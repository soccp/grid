// Copyright 2015 Tigera Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/projectcalico/cni-plugin/types"
	"github.com/projectcalico/cni-plugin/utils"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	k8sconversion "github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	calicoclient "github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// CmdAddK8s performs the "ADD" operation on a kubernetes pod
// Having kubernetes code in its own file avoids polluting the mainline code. It's expected that the kubernetes case will
// more special casing than the mainline code.
func CmdAddK8s(ctx context.Context, args *skel.CmdArgs, conf types.NetConf, epIDs utils.WEPIdentifiers, calicoClient calicoclient.Interface, endpoint *api.WorkloadEndpoint, nodename string) (*current.Result, error) {
	var err error
	var getip bool = false
	var needkeep bool = false
	var podip string = ""
	var result *current.Result

	utils.ConfigureLogging(conf.LogLevel)

	logger := logrus.WithFields(logrus.Fields{
		"WorkloadEndpoint": epIDs.WEPName,
		"ContainerID":      epIDs.ContainerID,
		"Pod":              epIDs.Pod,
		"Namespace":        epIDs.Namespace,
	})

	logger.Info("Extracted identifiers for CmdAddK8s")

	// Allocate the IP and update/create the endpoint. Do this even if the endpoint already exists and has an IP
	// allocation. The kubelet will send a DEL call for any old containers and we'll clean up the old IPs then.
	client, err := newK8sClient(conf, logger)
	if err != nil {
		return nil, err
	}
	logger.WithField("client", client).Debug("Created Kubernetes client")

	var routes []*net.IPNet
	if conf.IPAM.Type == "host-local" {
		// We're using the host-local IPAM plugin.  We implement some special-case support for that
		// plugin.  Namely:
		//
		// - We support a special value for its subnet config field, "usePodCIDR".  If that is specified,
		//   we swap the string "usePodCIDR" for the actual PodCIDR (looked up via the k8s API) before we pass the
		//   configuration to the plugin.
		// - We have partial support for its "routes" setting, which allows the routes that we install into
		//   the pod to be varied from our default (which is to insert /0 routes via the host).  If any routes
		//   are specified in the routes section then only the specified routes are programmed.  Since Calico
		//   uses a point-to-point link, the gateway parameter of the route is ignored and the host side IP
		//   of the veth is used instead.
		//
		// We unpack the JSON data as an untyped map rather than using a typed struct because we want to
		// round-trip any fields that we don't know about.
		var stdinData map[string]interface{}
		if err := json.Unmarshal(args.StdinData, &stdinData); err != nil {
			return nil, err
		}

		// Defer to ReplaceHostLocalIPAMPodCIDRs to swap the "usePodCidr" value out.
		var cachedPodCidr string
		getRealPodCIDR := func() (string, error) {
			if cachedPodCidr == "" {
				var err error
				cachedPodCidr, err = getPodCidr(client, conf, epIDs.Node)
				if err != nil {
					return "", err
				}
			}
			return cachedPodCidr, nil
		}
		err = utils.ReplaceHostLocalIPAMPodCIDRs(logger, stdinData, getRealPodCIDR)
		if err != nil {
			return nil, err
		}

		// Write any changes we made back to the input data so that it'll be passed on to the IPAM plugin.
		args.StdinData, err = json.Marshal(stdinData)
		if err != nil {
			return nil, err
		}
		logger.Debug("Updated stdin data")

		// Extract any custom routes from the IPAM configuration.
		ipamData := stdinData["ipam"].(map[string]interface{})
		untypedRoutes := ipamData["routes"]
		hlRoutes, ok := untypedRoutes.([]interface{})
		if untypedRoutes != nil && !ok {
			return nil, fmt.Errorf(
				"failed to parse host-local IPAM routes section; expecting list, not: %v", stdinData["ipam"])
		}
		for _, route := range hlRoutes {
			route := route.(map[string]interface{})
			untypedDst, ok := route["dst"]
			if !ok {
				logger.Debug("Ignoring host-ipam route with no dst")
				continue
			}
			dst, ok := untypedDst.(string)
			if !ok {
				return nil, fmt.Errorf(
					"invalid IPAM routes section; expecting 'dst' to be a string, not: %v", untypedDst)
			}
			_, cidr, err := net.ParseCIDR(dst)
			if err != nil {
				logger.WithError(err).WithField("routeDest", dst).Error(
					"Failed to parse destination of host-local IPAM route in CNI configuration.")
				return nil, err
			}
			routes = append(routes, cidr)
		}
	}

	// Determine which routes to program within the container. If no routes were provided in the CNI config,
	// then use the Calico default routes. If routes were provided then program those instead.
	if len(routes) == 0 {
		logger.Debug("No routes specified in CNI configuration, using defaults.")
		routes = utils.DefaultRoutes
	} else {
		if conf.IncludeDefaultRoutes {
			// We're configured to also include our own default route, so do that here.
			logger.Debug("Including Calico default routes in addition to routes from CNI config")
			routes = append(utils.DefaultRoutes, routes...)
		}
		logger.WithField("routes", routes).Info("Using custom routes from CNI configuration.")
	}

	labels := make(map[string]string)
	annot := make(map[string]string)
	var ports []api.EndpointPort
	var profiles []string
	var generateName, podowner, podownername string

	// Only attempt to fetch the labels and annotations from Kubernetes
	// if the policy type has been set to "k8s". This allows users to
	// run the plugin under Kubernetes without needing it to access the
	// Kubernetes API
	if conf.Policy.PolicyType == "k8s" {
		var err error

		labels, annot, ports, profiles, generateName, podowner, podownername, err = getK8sPodInfo(client, epIDs.Pod, epIDs.Namespace)
		if err != nil {
			return nil, err
		}
		logger.WithField("labels", labels).Debug("Fetched K8s labels")
		logger.WithField("annotations", annot).Debug("Fetched K8s annotations")
		logger.WithField("ports", ports).Debug("Fetched K8s ports")
		logger.WithField("profiles", profiles).Debug("Generated profiles")

		// Check for calico IPAM specific annotations and set them if needed.
		if conf.IPAM.Type == "grid-ipam" {

			v4pools := annot["cni.projectcalico.org/ipv4pools"]
			v6pools := annot["cni.projectcalico.org/ipv6pools"]

			if len(v4pools) != 0 || len(v6pools) != 0 {
				var stdinData map[string]interface{}
				if err := json.Unmarshal(args.StdinData, &stdinData); err != nil {
					return nil, err
				}
				var v4PoolSlice, v6PoolSlice []string

				if len(v4pools) > 0 {
					if err := json.Unmarshal([]byte(v4pools), &v4PoolSlice); err != nil {
						logger.WithField("IPv4Pool", v4pools).Error("Error parsing IPv4 IPPools")
						return nil, err
					}

					if _, ok := stdinData["ipam"].(map[string]interface{}); !ok {
						logger.Fatal("Error asserting stdinData type")
						os.Exit(0)
					}
					stdinData["ipam"].(map[string]interface{})["ipv4_pools"] = v4PoolSlice
					logger.WithField("ipv4_pools", v4pools).Debug("Setting IPv4 Pools")
				}
				if len(v6pools) > 0 {
					if err := json.Unmarshal([]byte(v6pools), &v6PoolSlice); err != nil {
						logger.WithField("IPv6Pool", v6pools).Error("Error parsing IPv6 IPPools")
						return nil, err
					}

					if _, ok := stdinData["ipam"].(map[string]interface{}); !ok {
						logger.Fatal("Error asserting stdinData type")
						os.Exit(0)
					}
					stdinData["ipam"].(map[string]interface{})["ipv6_pools"] = v6PoolSlice
					logger.WithField("ipv6_pools", v6pools).Debug("Setting IPv6 Pools")
				}

				newData, err := json.Marshal(stdinData)
				if err != nil {
					logger.WithField("stdinData", stdinData).Error("Error Marshaling data")
					return nil, err
				}
				args.StdinData = newData
				logger.Debug("Updated stdin data")
			}
		}
	}

	ipAddrsNoIpam := annot["cni.projectcalico.org/ipAddrsNoIpam"]
	ipAddrs := annot["cni.projectcalico.org/ipAddrs"]
	var etcdpath string
	// Switch based on which annotations are passed or not passed.
	switch {
	case ipAddrs == "" && ipAddrsNoIpam == "":

		if annot["keepip"] == "true" {
			logger.Debugf("THIS POD NEED KEEP IP")
			labels["podownertype"] = podowner
			labels["podownername"] = podownername
			needkeep = true

			tlsInfo := &transport.TLSInfo{
				CAFile:   conf.EtcdCaCertFile,
				CertFile: conf.EtcdCertFile,
				KeyFile:  conf.EtcdKeyFile,
			}

			tls, err := tlsInfo.ClientConfig()
			if err != nil {
				return nil, fmt.Errorf("could not initialize etcdv3 client: %+v", err)
			}

			cli, err := clientv3.New(clientv3.Config{
				Endpoints:   strings.Split(conf.EtcdEndpoints, ","),
				TLS:         tls,
				DialTimeout: 10 * time.Second,
			})
			if err != nil {
				return nil, fmt.Errorf("could not initialize etcdv3 client: %+v", err)
			}
			logger.Debugf("Init etcd client OK")
			defer cli.Close()
			if podowner != "statefulset" {
				etcdpath = fmt.Sprintf("/grid/bindips/%s/%s/%s/%s", epIDs.Namespace, podowner, nodename, podownername)
			} else {
				etcdpath = fmt.Sprintf("/grid/bindips/%s/%s/%s", epIDs.Namespace, podowner, epIDs.Pod)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			resp, err := cli.Get(ctx, etcdpath)
			cancel()
			if err != nil {
				return nil, err
			}
			logger.Debugf("etcd resp ip %v", resp)
			for _, ev := range resp.Kvs {
				if ev.Value != nil {
					var ips []string
					logger.Debugf("%s : %s\n", ev.Key, ev.Value)
					ips = append(ips, string(ev.Value))
					value, err := json.Marshal(ips)
					logger.Debugf("Marshal value %s", string(value))
					if err != nil {
						return nil, err
					}
					overriddenResult, err := overrideIPAMResult(string(value), logger)
					if err != nil {
						return nil, err
					}
					logger.Debugf("Bypassing IPAM to set the result to: %+v", overriddenResult)

					// Convert overridden IPAM result into current Result.
					// This method fill in all the empty fields necessory for CNI output according to spec.
					result, err = current.NewResultFromResult(overriddenResult)
					if err != nil {
						return nil, err
					}

					if len(result.IPs) == 0 {
						return nil, errors.New("failed to build result")
					}
					getip = true
					break
				}
			}
		}
		if !getip {
			// Call IPAM plugin if ipAddrsNoIpam or ipAddrs annotation is not present.
			logger.Debugf("Calling IPAM plugin %s", conf.IPAM.Type)
			ipamResult, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
			if err != nil {
				return nil, err
			}
			logger.Debugf("IPAM plugin returned: %+v", ipamResult)

			// Convert IPAM result into current Result.
			// IPAM result has a bunch of fields that are optional for an IPAM plugin
			// but required for a CNI plugin, so this is to populate those fields.
			// See CNI Spec doc for more details.
			result, err = current.NewResultFromResult(ipamResult)
			if err != nil {
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return nil, err
			}

			if len(result.IPs) == 0 {
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return nil, errors.New("IPAM plugin returned missing IP config")
			}
			podip = result.IPs[0].Address.IP.To4().String()
		}

	case ipAddrs != "" && ipAddrsNoIpam != "":
		// Can't have both ipAddrs and ipAddrsNoIpam annotations at the same time.
		e := fmt.Errorf("can't have both annotations: 'ipAddrs' and 'ipAddrsNoIpam' in use at the same time")
		logger.Error(e)
		return nil, e

	case ipAddrsNoIpam != "":
		if !conf.FeatureControl.IPAddrsNoIpam {
			e := fmt.Errorf("requested feature is not enabled: ip_addrs_no_ipam")
			logger.Error(e)
			return nil, e
		}

		// ipAddrsNoIpam annotation is set so bypass IPAM, and set the IPs manually.
		overriddenResult, err := overrideIPAMResult(ipAddrsNoIpam, logger)
		if err != nil {
			return nil, err
		}
		logger.Debugf("Bypassing IPAM to set the result to: %+v", overriddenResult)

		// Convert overridden IPAM result into current Result.
		// This method fill in all the empty fields necessory for CNI output according to spec.
		result, err = current.NewResultFromResult(overriddenResult)
		if err != nil {
			return nil, err
		}

		if len(result.IPs) == 0 {
			return nil, errors.New("failed to build result")
		}

	case ipAddrs != "":
		// If the endpoint already exists, we need to attempt to release the previous IP addresses here
		// since the ADD call will fail when it tries to reallocate the same IPs. releaseIPAddrs assumes
		// that Calico IPAM is in use, which is OK here since only Calico IPAM supports the ipAddrs
		// annotation.
		if endpoint != nil {
			logger.Info("Endpoint already exists and ipAddrs is set. Release any old IPs")
			if err := releaseIPAddrs(endpoint.Spec.IPNetworks, calicoClient, logger); err != nil {
				return nil, fmt.Errorf("failed to release ipAddrs: %s", err)
			}
		}

		// When ipAddrs annotation is set, we call out to the configured IPAM plugin
		// requesting the specific IP addresses included in the annotation.
		result, err = ipAddrsResult(ipAddrs, conf, args, logger)
		if err != nil {
			return nil, err
		}
		logger.Debugf("IPAM result set to: %+v", result)
	}

	// Configure the endpoint (creating if required).
	if endpoint == nil {
		logger.Debug("Initializing new WorkloadEndpoint resource")
		endpoint = api.NewWorkloadEndpoint()
	}
	endpoint.Name = epIDs.WEPName
	endpoint.Namespace = epIDs.Namespace
	endpoint.Labels = labels
	endpoint.GenerateName = generateName
	endpoint.Spec.Endpoint = epIDs.Endpoint
	endpoint.Spec.Node = epIDs.Node
	endpoint.Spec.Orchestrator = epIDs.Orchestrator
	endpoint.Spec.Pod = epIDs.Pod
	endpoint.Spec.Ports = ports
	endpoint.Spec.IPNetworks = []string{}

	// Set the profileID according to whether Kubernetes policy is required.
	// If it's not, then just use the network name (which is the normal behavior)
	// otherwise use one based on the Kubernetes pod's profile(s).
	if conf.Policy.PolicyType == "k8s" {
		endpoint.Spec.Profiles = profiles
	} else {
		endpoint.Spec.Profiles = []string{conf.Name}
	}

	// Populate the endpoint with the output from the IPAM plugin.
	if err = utils.PopulateEndpointNets(endpoint, result); err != nil {
		// Cleanup IP allocation and return the error.
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
		return nil, err
	}
	logger.WithField("endpoint", endpoint).Info("Populated endpoint")
	fmt.Fprintf(os.Stderr, "Calico CNI using IPs: %s\n", endpoint.Spec.IPNetworks)

	// releaseIPAM cleans up any IPAM allocations on failure.
	releaseIPAM := func() {
		logger.WithField("endpointIPs", endpoint.Spec.IPNetworks).Info("Releasing IPAM allocation(s) after failure")
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
	}

	// Whether the endpoint existed or not, the veth needs (re)creating.
	hostVethName := k8sconversion.VethNameForWorkload(epIDs.Namespace, epIDs.Pod)
	_, contVethMac, err := utils.DoNetworking(args, conf, result, logger, hostVethName, routes)
	if err != nil {
		logger.WithError(err).Error("Error setting up networking")
		releaseIPAM()
		return nil, err
	}

	mac, err := net.ParseMAC(contVethMac)
	if err != nil {
		logger.WithError(err).WithField("mac", mac).Error("Error parsing container MAC")
		releaseIPAM()
		return nil, err
	}
	endpoint.Spec.MAC = mac.String()
	endpoint.Spec.InterfaceName = hostVethName
	endpoint.Spec.ContainerID = epIDs.ContainerID
	logger.WithField("endpoint", endpoint).Info("Added Mac, interface name, and active container ID to endpoint")

	// Write the endpoint object (either the newly created one, or the updated one)
	if _, err := utils.CreateOrUpdate(ctx, calicoClient, endpoint); err != nil {
		logger.WithError(err).Error("Error creating/updating endpoint in datastore.")
		releaseIPAM()
		return nil, err
	}
	logger.Info("Wrote updated endpoint to datastore")

	// Add the interface created above to the CNI result.
	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name: endpoint.Spec.InterfaceName, Sandbox: endpoint.Spec.Endpoint},
	)
	//zk
	if !getip && needkeep {

		tlsInfo := &transport.TLSInfo{
			CAFile:   conf.EtcdCaCertFile,
			CertFile: conf.EtcdCertFile,
			KeyFile:  conf.EtcdKeyFile,
		}

		tls, err := tlsInfo.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("could not initialize etcdv3 client: %+v", err)
		}

		cli, err := clientv3.New(clientv3.Config{
			Endpoints:   strings.Split(conf.EtcdEndpoints, ","),
			TLS:         tls,
			DialTimeout: 10 * time.Second,
		})

		if err != nil {
			logger.Errorln(err)
		}
		defer cli.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		//_, err = cli.Put(ctx, "/calico/bindips/"+podowner+"/"+nodename+"/"+podownername, podip)
		_, err = cli.Put(ctx, etcdpath, podip)
		cancel()
		if err != nil {
			logger.Errorf("Put bindip to etcd failed for %s:%s Release it %s", endpoint.Namespace, endpoint.Name, podip)
			releaseIPAM()
			return nil, fmt.Errorf("Put bindip to etcd failed for %s:%s Release it %s", endpoint.Namespace, endpoint.Name, podip)
		}
	}
	return result, nil
}

// CmdDelK8s performs CNI DEL processing when running under Kubernetes. In Kubernetes, we identify workload endpoints based on their
// pod name and namespace rather than container ID, so we may receive multiple DEL calls for the same pod, but with different container IDs.
// As such, we must only delete the workload endpoint when the provided CNI_CONATAINERID matches the value on the WorkloadEndpoint. If they do not match,
// it means the DEL is for an old sandbox and the pod is still running. We should still clean up IPAM allocations, since they are identified by the
// container ID rather than the pod name and namespace. If they do match, then we can delete the workload endpoint.
func CmdDelK8s(ctx context.Context, c calicoclient.Interface, epIDs utils.WEPIdentifiers, args *skel.CmdArgs, conf types.NetConf, nodename string, logger *logrus.Entry) error {
	wep, err := c.WorkloadEndpoints().Get(ctx, epIDs.Namespace, epIDs.WEPName, options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			// Could not connect to datastore (connection refused, unauthorized, etc.)
			// so we have no way of knowing/checking ContainerID. To protect the endpoint
			// from false DEL, we return the error without deleting/cleaning up.
			return err
		}

		// The WorkloadEndpoint doesn't exist for some reason. We should still try to clean up any IPAM allocations
		// if they exist, so continue DEL processing.
		logger.WithField("WorkloadEndpoint", epIDs.WEPName).Warning("WorkloadEndpoint does not exist in the datastore, moving forward with the clean up")
	} else if wep.Spec.ContainerID != "" && args.ContainerID != wep.Spec.ContainerID {
		// If the ContainerID is populated and doesn't match the CNI_CONATINERID provided for this execution, then
		// we shouldn't delete the workload endpoint. We identify workload endpoints based on pod name and namespace, which means
		// we can receive DEL commands for an old sandbox for a currently running pod. However, we key IPAM allocations based on the
		// CNI_CONTAINERID, so we should still do that below for this case.
		logger.WithField("WorkloadEndpoint", wep).Warning("CNI_CONTAINERID does not match WorkloadEndpoint ConainerID, don't delete WEP.")
	} else if _, err = c.WorkloadEndpoints().Delete(ctx, wep.Namespace, wep.Name, options.DeleteOptions{}); err != nil {
		// Delete the WorkloadEndpoint object from the datastore, passing revision information from the
		// queried resource above in order to prevent conflicts.
		switch err := err.(type) {
		case cerrors.ErrorResourceDoesNotExist:
			// Log and proceed with the clean up if WEP doesn't exist.
			logger.WithField("endpoint", wep).Info("Endpoint object does not exist, no need to clean up.")
		case cerrors.ErrorResourceUpdateConflict:
			// This case means the WEP object was modified between the time we did the Get and now,
			// so it's not a safe Compare-and-Delete operation, so log and abort with the error.
			// Returning an error here is with the assumption that k8s (kubelet) retries deleting again.
			logger.WithField("endpoint", wep).Warning("Error deleting endpoint: endpoint was modified before it could be deleted.")
			return fmt.Errorf("error deleting endpoint: endpoint was modified before it could be deleted: %v", err)
		case cerrors.ErrorOperationNotSupported:
			// KDD does not support WorkloadEndpoint deletion, the WEP is backed by the Pod and the
			// deletion will be handled by Kubernetes. This error can be ignored.
			logger.WithField("endpoint", wep).Info("Endpoint deletion will be handled by Kubernetes deletion of the Pod.")
		default:
			return err
		}
	}
	//zk
	var podowner, podownername string
	var podip []string
	var ipamErr error
	if wep != nil {
		podowner = wep.ObjectMeta.Labels["podownertype"]
		podownername = wep.ObjectMeta.Labels["podownername"]
		podip = wep.Spec.IPNetworks
		logger.Debugf("pod ipcidr %s", podip)
	}
	if podownername != "" {
		client, err := newK8sClient(conf, logger)
		if err != nil {
			return err
		}
		logger.WithField("client", client).Debug("Created Kubernetes client")

		/*d := strings.Split(podownername, "-")
		deployname := strings.Join(d[:(len(d)-1)], "-")*/
		var exist bool
		if podowner == "deployment" {
			logger.Debugf("Deploy name is %s", podownername)
			exist, err = getK8sDeploymentInfo(client, podownername, epIDs.Namespace)
			if err != nil {
				return err
			}
		} else if podowner == "statefulset" {
			logger.Debugf("StatefulSet name is %s", podownername)
			exist, err = getK8sStatefulSetInfo(client, podownername, epIDs.Namespace)
			if err != nil {
				return err
			}
		} else {
			logger.Debugf("Daemonset name is %s", podownername)
			exist, err = getK8sDaemonSetInfo(client, podownername, epIDs.Namespace)
			if err != nil {
				return err
			}
		}
		if exist {
			ipamErr = nil
		} else {
			// Release the IP address for this container by calling the configured IPAM plugin.
			logger.Info("Releasing IP Bind relation")

			tlsInfo := &transport.TLSInfo{
				CAFile:   conf.EtcdCaCertFile,
				CertFile: conf.EtcdCertFile,
				KeyFile:  conf.EtcdKeyFile,
			}

			tls, err := tlsInfo.ClientConfig()
			if err != nil {
				return fmt.Errorf("could not initialize etcdv3 client: %+v", err)
			}

			cli, err := clientv3.New(clientv3.Config{
				Endpoints:   strings.Split(conf.EtcdEndpoints, ","),
				TLS:         tls,
				DialTimeout: 10 * time.Second,
			})
			if err != nil {
				return err
			}
			defer cli.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			var etcdpath string
			if podowner != "statefulset" {
				etcdpath = fmt.Sprintf("/grid/bindips/%s/%s/%s/%s", epIDs.Namespace, podowner, nodename, podownername)
			} else {
				etcdpath = fmt.Sprintf("/grid/bindips/%s/%s/%s", epIDs.Namespace, podowner, epIDs.Pod)
			}
			resp, err := cli.Delete(ctx, etcdpath)
			cancel()
			if err != nil {
				ipamErr = err
			}
			if resp.Deleted != 1 {
				ipamErr = err
			} else {
				logger.Debugf("Put the ip back into ippool %v", podip)
				//ipamErr = utils.CleanUpIPAM(conf, args, logger)
				ipamErr = releaseIPAddrs(podip, c, logger)
			}
		}
	} else {
		// Release the IP address for this container by calling the configured IPAM plugin.
		logger.Info("Releasing IP address(es)")

		ipamErr = utils.CleanUpIPAM(conf, args, logger)
	}

	// Clean up namespace by removing the interfaces.
	logger.Info("Cleaning up netns")
	//zk add brctl del
	err = utils.CleanUpNamespace(args, logger)
	if err != nil {
		return err
	}

	// Return the IPAM error if there was one. The IPAM error will be lost if there was also an error in cleaning up
	// the device or endpoint, but crucially, the user will know the overall operation failed.
	if ipamErr != nil {
		return ipamErr
	}

	logger.Info("Teardown processing complete.")
	return nil
}

// releaseIPAddrs calls directly into Calico IPAM to release the specified IP addresses.
// NOTE: This function assumes Calico IPAM is in use, and calls into it directly rather than calling the IPAM plugin.
func releaseIPAddrs(ipAddrs []string, calico calicoclient.Interface, logger *logrus.Entry) error {
	// For each IP, call out to Calico IPAM to release it.
	for _, ip := range ipAddrs {
		log := logger.WithField("IP", ip)
		log.Info("Releasing explicitly requested address")
		cip, _, err := cnet.ParseCIDR(ip)
		if err != nil {
			return err
		}

		unallocated, err := calico.IPAM().ReleaseIPs(context.Background(), []cnet.IP{*cip})
		if err != nil {
			log.WithError(err).Error("Failed to release explicit IP")
			return err
		}
		if len(unallocated) > 0 {
			log.Warn("Asked to release address but it doesn't exist.")
		} else {
			log.Infof("Released explicit address: %s", ip)
		}
	}
	return nil
}

// ipAddrsResult parses the ipAddrs annotation and calls the configured IPAM plugin for
// each IP passed to it by setting the IP field in CNI_ARGS, and returns the result of calling the IPAM plugin.
// Example annotation value string: "[\"10.0.0.1\", \"2001:db8::1\"]"
func ipAddrsResult(ipAddrs string, conf types.NetConf, args *skel.CmdArgs, logger *logrus.Entry) (*current.Result, error) {
	logger.Infof("Parsing annotation \"cni.projectcalico.org/ipAddrs\":%s", ipAddrs)

	// We need to make sure there is only one IPv4 and/or one IPv6
	// passed in, since CNI spec only supports one of each right now.
	ipList, err := validateAndExtractIPs(ipAddrs, "cni.projectcalico.org/ipAddrs", logger)
	if err != nil {
		return nil, err
	}

	result := current.Result{}

	// Go through all the IPs passed in as annotation value and call IPAM plugin
	// for each, and populate the result variable with IP4 and/or IP6 IPs returned
	// from the IPAM plugin.
	for _, ip := range ipList {
		// Call callIPAMWithIP with the ip address.
		r, err := callIPAMWithIP(ip, conf, args, logger)
		if err != nil {
			return nil, fmt.Errorf("error getting IP from IPAM: %s", err)
		}

		result.IPs = append(result.IPs, r.IPs[0])
		logger.Debugf("Adding IPv%s: %s to result", r.IPs[0].Version, ip.String())
	}

	return &result, nil
}

// callIPAMWithIP sets CNI_ARGS with the IP and calls the IPAM plugin with it
// to get current.Result and then it unsets the IP field from CNI_ARGS ENV var,
// so it doesn't pollute the subsequent requests.
func callIPAMWithIP(ip net.IP, conf types.NetConf, args *skel.CmdArgs, logger *logrus.Entry) (*current.Result, error) {

	// Save the original value of the CNI_ARGS ENV var for backup.
	originalArgs := os.Getenv("CNI_ARGS")
	logger.Debugf("Original CNI_ARGS=%s", originalArgs)

	ipamArgs := struct {
		cnitypes.CommonArgs
		IP net.IP `json:"ip,omitempty"`
	}{}

	if err := cnitypes.LoadArgs(args.Args, &ipamArgs); err != nil {
		return nil, err
	}

	if ipamArgs.IP != nil {
		logger.Errorf("'IP' variable already set in CNI_ARGS environment variable.")
	}

	// Request the provided IP address using the IP CNI_ARG.
	// See: https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md#cni_args for more info.
	newArgs := originalArgs + ";IP=" + ip.String()
	logger.Debugf("New CNI_ARGS=%s", newArgs)

	// Set CNI_ARGS to the new value.
	err := os.Setenv("CNI_ARGS", newArgs)
	if err != nil {
		return nil, fmt.Errorf("error setting CNI_ARGS environment variable: %v", err)
	}

	// Run the IPAM plugin.
	logger.Debugf("Calling IPAM plugin %s", conf.IPAM.Type)
	r, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
	if err != nil {
		// Restore the CNI_ARGS ENV var to it's original value,
		// so the subsequent calls don't get polluted by the old IP value.
		if err := os.Setenv("CNI_ARGS", originalArgs); err != nil {
			logger.Errorf("Error setting CNI_ARGS environment variable: %v", err)
		}
		return nil, err
	}
	logger.Debugf("IPAM plugin returned: %+v", r)

	// Restore the CNI_ARGS ENV var to it's original value,
	// so the subsequent calls don't get polluted by the old IP value.
	if err := os.Setenv("CNI_ARGS", originalArgs); err != nil {
		// Need to clean up IP allocation if this step doesn't succeed.
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
		logger.Errorf("Error setting CNI_ARGS environment variable: %v", err)
		return nil, err
	}

	// Convert IPAM result into current Result.
	// IPAM result has a bunch of fields that are optional for an IPAM plugin
	// but required for a CNI plugin, so this is to populate those fields.
	// See CNI Spec doc for more details.
	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return nil, err
	}

	if len(ipamResult.IPs) == 0 {
		return nil, errors.New("IPAM plugin returned missing IP config")
	}

	return ipamResult, nil
}

// overrideIPAMResult generates current.Result like the one produced by IPAM plugin,
// but sets IP field manually since IPAM is bypassed with this annotation.
// Example annotation value string: "[\"10.0.0.1\", \"2001:db8::1\"]"
func overrideIPAMResult(ipAddrsNoIpam string, logger *logrus.Entry) (*current.Result, error) {
	logger.Infof("Parsing annotation \"cni.projectcalico.org/ipAddrsNoIpam\":%s", ipAddrsNoIpam)

	// We need to make sure there is only one IPv4 and/or one IPv6
	// passed in, since CNI spec only supports one of each right now.
	ipList, err := validateAndExtractIPs(ipAddrsNoIpam, "cni.projectcalico.org/ipAddrsNoIpam", logger)
	if err != nil {
		return nil, err
	}

	result := current.Result{}

	// Go through all the IPs passed in as annotation value and populate
	// the result variable with IP4 and/or IP6 IPs.
	for _, ip := range ipList {
		var version string
		var mask net.IPMask

		if ip.To4() != nil {
			version = "4"
			mask = net.CIDRMask(32, 32)

		} else {
			version = "6"
			mask = net.CIDRMask(128, 128)
		}

		ipConf := &current.IPConfig{
			Version: version,
			Address: net.IPNet{
				IP:   ip,
				Mask: mask,
			},
		}
		result.IPs = append(result.IPs, ipConf)
		logger.Debugf("Adding IPv%s: %s to result", ipConf.Version, ip.String())
	}

	return &result, nil
}

// validateAndExtractIPs is a utility function that validates the passed IP list to make sure
// there is one IPv4 and/or one IPv6 and then returns the slice of IPs.
func validateAndExtractIPs(ipAddrs string, annotation string, logger *logrus.Entry) ([]net.IP, error) {
	// Parse IPs from JSON.
	ips, err := parseIPAddrs(ipAddrs, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPs %s for annotation \"%s\": %s", ipAddrs, annotation, err)
	}

	// annotation value can't be empty.
	if len(ips) == 0 {
		return nil, fmt.Errorf("annotation \"%s\" specified but empty", annotation)
	}

	var hasIPv4, hasIPv6 bool
	var ipList []net.IP

	// We need to make sure there is only one IPv4 and/or one IPv6
	// passed in, since CNI spec only supports one of each right now.
	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			logger.WithField("IP", ip).Error("Invalid IP format")
			return nil, fmt.Errorf("invalid IP format: %s", ip)
		}

		if ipAddr.To4() != nil {
			if hasIPv4 {
				// Check if there is already has been an IPv4 in the list, as we only support one IPv4 and/or one IPv6 per interface for now.
				return nil, fmt.Errorf("cannot have more than one IPv4 address for \"%s\" annotation", annotation)
			}
			hasIPv4 = true
		} else {
			if hasIPv6 {
				// Check if there is already has been an IPv6 in the list, as we only support one IPv4 and/or one IPv6 per interface for now.
				return nil, fmt.Errorf("cannot have more than one IPv6 address for \"%s\" annotation", annotation)
			}
			hasIPv6 = true
		}

		// Append the IP to ipList slice.
		ipList = append(ipList, ipAddr)
	}

	return ipList, nil
}

// parseIPAddrs is a utility function that parses string of IPs in json format that are
// passed in as a string and returns a slice of string with IPs.
// It also makes sure the slice isn't empty.
func parseIPAddrs(ipAddrsStr string, logger *logrus.Entry) ([]string, error) {
	var ips []string

	err := json.Unmarshal([]byte(ipAddrsStr), &ips)
	if err != nil {
		return nil, fmt.Errorf("failed to parse '%s' as JSON: %s", ipAddrsStr, err)
	}

	logger.Debugf("IPs parsed: %v", ips)

	return ips, nil
}

func newK8sClient(conf types.NetConf, logger *logrus.Entry) (*kubernetes.Clientset, error) {
	// Some config can be passed in a kubeconfig file
	kubeconfig := conf.Kubernetes.Kubeconfig

	// Config can be overridden by config passed in explicitly in the network config.
	configOverrides := &clientcmd.ConfigOverrides{}

	// If an API root is given, make sure we're using using the name / port rather than
	// the full URL. Earlier versions of the config required the full `/api/v1/` extension,
	// so split that off to ensure compatibility.
	conf.Policy.K8sAPIRoot = strings.Split(conf.Policy.K8sAPIRoot, "/api/")[0]

	var overridesMap = []struct {
		variable *string
		value    string
	}{
		{&configOverrides.ClusterInfo.Server, conf.Policy.K8sAPIRoot},
		{&configOverrides.AuthInfo.ClientCertificate, conf.Policy.K8sClientCertificate},
		{&configOverrides.AuthInfo.ClientKey, conf.Policy.K8sClientKey},
		{&configOverrides.ClusterInfo.CertificateAuthority, conf.Policy.K8sCertificateAuthority},
		{&configOverrides.AuthInfo.Token, conf.Policy.K8sAuthToken},
	}

	// Using the override map above, populate any non-empty values.
	for _, override := range overridesMap {
		if override.value != "" {
			*override.variable = override.value
		}
	}

	// Also allow the K8sAPIRoot to appear under the "kubernetes" block in the network config.
	if conf.Kubernetes.K8sAPIRoot != "" {
		configOverrides.ClusterInfo.Server = conf.Kubernetes.K8sAPIRoot
	}

	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		configOverrides).ClientConfig()
	if err != nil {
		return nil, err
	}

	// Create the clientset
	return kubernetes.NewForConfig(config)
}

func getK8sPodInfo(client *kubernetes.Clientset, podName, podNamespace string) (labels map[string]string, annotations map[string]string, ports []api.EndpointPort, profiles []string, generateName, podowner, podownername string, err error) {
	pod, err := client.CoreV1().Pods(string(podNamespace)).Get(podName, metav1.GetOptions{})
	logrus.Infof("pod info %+v", pod)
	if err != nil {
		return labels, annotations, ports, profiles, "", "", "", err
	}

	var c k8sconversion.Converter
	kvp, err := c.PodToWorkloadEndpoint(pod)
	if err != nil {
		return labels, annotations, ports, profiles, "", "", "", err
	}

	ports = kvp.Value.(*api.WorkloadEndpoint).Spec.Ports
	labels = kvp.Value.(*api.WorkloadEndpoint).Labels
	profiles = kvp.Value.(*api.WorkloadEndpoint).Spec.Profiles
	generateName = kvp.Value.(*api.WorkloadEndpoint).GenerateName
	// zk
	if pod.Annotations["keepip"] == "true" {
		//podowner = "deployment"
			p := strings.Split(generateName, "-")
			//logrus.Debugf("PODINFO %v", kvp.Value.(*api.WorkloadEndpoint).OwnerReferences)
			//podownerinfo := kvp.Value.(*api.WorkloadEndpoint).OwnerReferences[0].Kind
			podownerinfo := pod.OwnerReferences[0].Kind
			if podownerinfo == "ReplicaSet" {
				podowner = "deployment"
				podownername = strings.Join(p[:(len(p)-2)], "-")
			} else {
				podowner = strings.ToLower(podownerinfo)
				podownername = strings.Join(p[:(len(p)-1)], "-")
			}
		}

	return labels, pod.Annotations, ports, profiles, generateName, podowner, podownername, nil
}

//zk
func getK8sDeploymentInfo(client *kubernetes.Clientset, name, namespace string) (exist bool, err error) {
	deploy, err := client.AppsV1().Deployments(string(namespace)).Get(name, metav1.GetOptions{})
	//logrus.Debugf("deployment info %+v", deploy)
	if err != nil {
		if kerrors.IsNotFound(err) {
			logrus.Debugln(err)
			return false, nil
		}
		logrus.Debugf("Get Deploy for %s:%s error %v", namespace, name, err)
		return true, err
	}
	logrus.Debugf("deployment info %+v", deploy)
	/*if deploy.Status.Replicas != 0 {
		return true, nil
	}*/
	return true, nil
}

func getK8sStatefulSetInfo(client *kubernetes.Clientset, name, namespace string) (exist bool, err error) {
	sts, err := client.AppsV1().StatefulSets(string(namespace)).Get(name, metav1.GetOptions{})
	//logrus.Debugf("statefulset info %+v", sts)
	if err != nil {
		if kerrors.IsNotFound(err) {
			logrus.Debugln(err)
			return false, nil
		}
		logrus.Debugf("Get StatefulSet for %s:%s error %v", namespace, name, err)
		return true, err
	}
	logrus.Debugf("statefulset info %+v", sts)
	/*if *sts.Spec.Replicas != 0 {
		return true, nil
	}*/
	return true, nil
}

func getK8sDaemonSetInfo(client *kubernetes.Clientset, name, namespace string) (exist bool, err error) {
	ds, err := client.AppsV1().DaemonSets(string(namespace)).Get(name, metav1.GetOptions{})
	//logrus.Debugf("daemonset info %+v", ds)
	if err != nil {
		if kerrors.IsNotFound(err) {
			logrus.Debugln(err)
			return false, nil
		}
		logrus.Debugf("Get DaemonSet for %s:%s error %v", namespace, name, err)
		return true, err
	}
	logrus.Debugf("daemonset info %+v", ds)
	/*if ds.Status.CurrentNumberScheduled != 0 {
		return true, nil
	}*/
	return true, nil
}

func getPodCidr(client *kubernetes.Clientset, conf types.NetConf, nodename string) (string, error) {
	// Pull the node name out of the config if it's set. Defaults to nodename
	if conf.Kubernetes.NodeName != "" {
		nodename = conf.Kubernetes.NodeName
	}

	node, err := client.CoreV1().Nodes().Get(nodename, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	if node.Spec.PodCIDR == "" {
		return "", fmt.Errorf("no podCidr for node %s", nodename)
	}
	return node.Spec.PodCIDR, nil
}

func parseetcdips(ips string) (ip []string) {
	s := strings.Split(ips, ",")
	for i := 0; i < len(s); i++ {
		ip = append(ip, s[i])
	}
	return ip
}
