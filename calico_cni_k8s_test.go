package main_test

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"regexp"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/projectcalico/cni-plugin/testutils"
	"github.com/projectcalico/cni-plugin/utils"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	k8sconversion "github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/names"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func ensureNamespace(clientset *kubernetes.Clientset, name string) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	_, err := clientset.CoreV1().Namespaces().Create(ns)
	if errors.IsAlreadyExists(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred())
}

var _ = Describe("CalicoCni", func() {
	// Create a random seed
	rand.Seed(time.Now().UTC().UnixNano())
	log.SetFormatter(&logutils.Formatter{})
	log.AddHook(&logutils.ContextHook{})
	log.SetOutput(GinkgoWriter)
	log.SetLevel(log.DebugLevel)
	hostname, _ := names.Hostname()
	ctx := context.Background()
	calicoClient, err := client.NewFromEnv()
	if err != nil {
		panic(err)
	}

	BeforeEach(func() {
		testutils.WipeK8sPods()
		testutils.WipeEtcd()
	})

	Describe("Run Calico CNI plugin in K8s mode", func() {
		utils.ConfigureLogging("info")
		cniVersion := os.Getenv("CNI_SPEC_VERSION")

		Context("using host-local IPAM", func() {

			netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "datastore_type": "%s",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  },
			  "kubernetes": {
			    "k8s_api_root": "http://127.0.0.1:8080"
			  },
			  "policy": {"type": "k8s"},
			  "nodename_file_optional": true,
			  "log_level":"info"
			}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

			It("successfully networks the namespace", func() {
				config, err := clientcmd.DefaultClientConfig.ClientConfig()
				if err != nil {
					panic(err)
				}
				clientset, err := kubernetes.NewForConfig(config)

				if err != nil {
					panic(err)
				}

				name := fmt.Sprintf("run%d", rand.Uint32())

				// Create a K8s pod w/o any special params
				ensureNamespace(clientset, testutils.K8S_TEST_NS)
				_, err = clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{
							Name:  name,
							Image: "ignore",
						}},
						NodeName: hostname,
					},
				})
				if err != nil {
					panic(err)
				}
				containerID, session, contVeth, contAddresses, contRoutes, contNs, err := testutils.CreateContainer(netconf, name, testutils.K8S_TEST_NS, "")

				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				result, err := testutils.GetResultForCurrent(session, cniVersion)
				if err != nil {
					log.Fatalf("Error getting result from the session: %v\n", err)
				}

				mac := contVeth.Attrs().HardwareAddr

				Expect(len(result.IPs)).Should(Equal(1))
				ip := result.IPs[0].Address.IP.String()
				result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
				Expect(result.IPs[0].Address.Mask.String()).Should(Equal("ffffffff"))

				// datastore things:
				// TODO Make sure the profile doesn't exist

				ids := names.WorkloadEndpointIdentifiers{
					Node:         hostname,
					Orchestrator: api.OrchestratorKubernetes,
					Endpoint:     "eth0",
					Pod:          name,
					ContainerID:  containerID,
				}

				wrkload, err := ids.CalculateWorkloadEndpointName(false)
				Expect(err).NotTo(HaveOccurred())

				interfaceName := k8sconversion.VethNameForWorkload(testutils.K8S_TEST_NS, name)

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
				Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
				Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
					"projectcalico.org/namespace":      "test",
					"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
					"projectcalico.org/serviceaccount": "default",
				}))

				Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
					Pod:           name,
					InterfaceName: interfaceName,
					IPNetworks:    []string{result.IPs[0].Address.String()},
					MAC:           mac.String(),
					Profiles:      []string{"kns.test", "ksa.test.default"},
					Node:          hostname,
					Endpoint:      "eth0",
					Workload:      "",
					ContainerID:   containerID,
					Orchestrator:  api.OrchestratorKubernetes,
				}))

				// Routes and interface on host - there's is nothing to assert on the routes since felix adds those.
				// fmt.Println(Cmd("ip link show")) // Useful for debugging
				hostVeth, err := netlink.LinkByName(interfaceName)
				Expect(err).ToNot(HaveOccurred())
				Expect(hostVeth.Attrs().Flags.String()).Should(ContainSubstring("up"))
				Expect(hostVeth.Attrs().MTU).Should(Equal(1500))

				// Assert hostVeth sysctl values are set to what we expect for IPv4.
				err = testutils.CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", interfaceName), "1")
				Expect(err).ShouldNot(HaveOccurred())
				err = testutils.CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", interfaceName), "0")
				Expect(err).ShouldNot(HaveOccurred())
				err = testutils.CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", interfaceName), "1")
				Expect(err).ShouldNot(HaveOccurred())

				// Assert if the host side route is programmed correctly.
				hostRoutes, err := netlink.RouteList(hostVeth, syscall.AF_INET)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostRoutes[0]).Should(Equal(netlink.Route{
					LinkIndex: hostVeth.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst:       &result.IPs[0].Address,
					Protocol:  syscall.RTPROT_BOOT,
					Table:     syscall.RT_TABLE_MAIN,
					Type:      syscall.RTN_UNICAST,
				}))

				// Routes and interface in netns
				Expect(contVeth.Attrs().Flags.String()).Should(ContainSubstring("up"))

				// Assume the first IP is the IPv4 address
				Expect(contAddresses[0].IP.String()).Should(Equal(ip))
				Expect(contRoutes).Should(SatisfyAll(
					ContainElement(netlink.Route{
						LinkIndex: contVeth.Attrs().Index,
						Gw:        net.IPv4(169, 254, 1, 1).To4(),
						Protocol:  syscall.RTPROT_BOOT,
						Table:     syscall.RT_TABLE_MAIN,
						Type:      syscall.RTN_UNICAST,
					}),
					ContainElement(netlink.Route{
						LinkIndex: contVeth.Attrs().Index,
						Scope:     netlink.SCOPE_LINK,
						Dst:       &net.IPNet{IP: net.IPv4(169, 254, 1, 1).To4(), Mask: net.CIDRMask(32, 32)},
						Protocol:  syscall.RTPROT_BOOT,
						Table:     syscall.RT_TABLE_MAIN,
						Type:      syscall.RTN_UNICAST,
					})))

				_, err = testutils.DeleteContainer(netconf, contNs.Path(), name, testutils.K8S_TEST_NS)
				Expect(err).ShouldNot(HaveOccurred())

				// Make sure there are no endpoints anymore
				endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(0))

				// Make sure the interface has been removed from the namespace
				targetNs, _ := ns.GetNS(contNs.Path())
				err = targetNs.Do(func(_ ns.NetNS) error {
					_, err = netlink.LinkByName("eth0")
					return err
				})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Equal("Link not found"))

				// Make sure the interface has been removed from the host
				_, err = netlink.LinkByName("cali" + containerID)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Equal("Link not found"))
			})

			Context("when a named port is set", func() {
				It("it is added to the workload endpoint", func() {
					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					if err != nil {
						panic(err)
					}
					clientset, err := kubernetes.NewForConfig(config)

					if err != nil {
						panic(err)
					}

					name := fmt.Sprintf("run%d", rand.Uint32())

					// Create a K8s pod w/o any special params
					_, err = clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{Name: name},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  fmt.Sprintf("container-%s", name),
								Image: "ignore",
								Ports: []v1.ContainerPort{{
									Name:          "anamedport",
									ContainerPort: 555,
								}},
							}},
							NodeName: hostname,
						},
					})
					if err != nil {
						panic(err)
					}
					containerID, session, contVeth, _, _, contNs, err := testutils.CreateContainer(netconf, name, testutils.K8S_TEST_NS, "")

					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err := testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					mac := contVeth.Attrs().HardwareAddr

					Expect(len(result.IPs)).Should(Equal(1))
					result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
					Expect(result.IPs[0].Address.Mask.String()).Should(Equal("ffffffff"))

					// datastore things:
					// TODO Make sure the profile doesn't exist

					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					wrkload, err := ids.CalculateWorkloadEndpointName(false)
					interfaceName := k8sconversion.VethNameForWorkload(testutils.K8S_TEST_NS, name)
					Expect(err).NotTo(HaveOccurred())

					// The endpoint is created
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))
					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						Pod:           name,
						InterfaceName: interfaceName,
						IPNetworks:    []string{result.IPs[0].Address.String()},
						MAC:           mac.String(),
						Profiles:      []string{"kns.test", "ksa.test.default"},
						Node:          hostname,
						Endpoint:      "eth0",
						Workload:      "",
						ContainerID:   containerID,
						Orchestrator:  api.OrchestratorKubernetes,
						Ports: []api.EndpointPort{{
							Name:     "anamedport",
							Protocol: numorstring.ProtocolFromString("TCP"),
							Port:     555,
						}},
					}))

					_, err = testutils.DeleteContainer(netconf, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())

					// Make sure there are no endpoints anymore
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))

					// Make sure the interface has been removed from the namespace
					targetNs, _ := ns.GetNS(contNs.Path())
					err = targetNs.Do(func(_ ns.NetNS) error {
						_, err = netlink.LinkByName("eth0")
						return err
					})
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(Equal("Link not found"))

					// Make sure the interface has been removed from the host
					_, err = netlink.LinkByName("cali" + containerID)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(Equal("Link not found"))
				})
			})

			Context("when the same hostVeth exists", func() {
				It("successfully networks the namespace", func() {
					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					name := fmt.Sprintf("run%d", rand.Uint32())

					// Create a K8s pod w/o any special params
					_, err = clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{Name: name},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					if err := testutils.CreateHostVeth("", name, testutils.K8S_TEST_NS, hostname); err != nil {
						panic(err)
					}
					_, session, _, _, _, contNs, err := testutils.CreateContainer(netconf, name, testutils.K8S_TEST_NS, "")
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					_, err = testutils.DeleteContainer(netconf, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("using calico-ipam with ipPools annotation", func() {
				It("successfully assigns an IP address from the annotated ipPool", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net2",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
			          "nodename_file_optional": true,
				  "datastore_type": "%s",
			 	  "ipam": {
			    	 "type": "calico-ipam"
			         },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

					// Create a new ipPool.
					ipPool := "172.16.0.0/16"

					testutils.MustCreateNewIPPool(calicoClient, ipPool, false, false, true)
					_, ipPoolCIDR, err := net.ParseCIDR(ipPool)
					Expect(err).NotTo(HaveOccurred())

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP pool.
					name := fmt.Sprintf("run%d", rand.Uint32())
					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipv4pools": "[\"172.16.0.0/16\"]",
							},
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					_, _, _, contAddresses, _, contNs, err := testutils.CreateContainer(netconfCalicoIPAM, name, testutils.K8S_TEST_NS, "")
					Expect(err).NotTo(HaveOccurred())

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					log.Infof("Container got IP address: %s", podIP)
					Expect(ipPoolCIDR.Contains(podIP)).To(BeTrue())

					// Delete the container.
					_, err = testutils.DeleteContainer(netconfCalicoIPAM, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("using ipAddrsNoIpam annotation to assign IP address to a pod, bypassing IPAM", func() {
				It("should successfully assigns the annotated IP address", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net3",
				  "type": "calico",
				  "feature_control": {
					"ip_addrs_no_ipam": true
				  },
				  "etcd_endpoints": "http://%s:2379",
				  "datastore_type": "%s",
			          "nodename_file_optional": true,
			 	  "ipam": {},
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

					assignIP := net.IPv4(10, 0, 0, 1).To4()

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP address.
					name := fmt.Sprintf("run%d", rand.Uint32())
					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrsNoIpam": "[\"10.0.0.1\"]",
							},
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					containerID, _, contVeth, contAddresses, _, contNs, err := testutils.CreateContainer(netconfCalicoIPAM, name, testutils.K8S_TEST_NS, "")
					Expect(err).NotTo(HaveOccurred())
					mac := contVeth.Attrs().HardwareAddr

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					log.Infof("Container got IP address: %s", podIP)
					Expect(podIP).Should(Equal(assignIP))

					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					wrkload, err := ids.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					interfaceName := k8sconversion.VethNameForWorkload(testutils.K8S_TEST_NS, name)

					// The endpoint is created
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						Pod:           name,
						InterfaceName: interfaceName,
						IPNetworks:    []string{assignIP.String() + "/32"},
						MAC:           mac.String(),
						Profiles:      []string{"kns.test", "ksa.test.default"},
						Node:          hostname,
						Endpoint:      "eth0",
						Workload:      "",
						ContainerID:   containerID,
						Orchestrator:  api.OrchestratorKubernetes,
					}))

					// Delete the container.
					_, err = testutils.DeleteContainer(netconfCalicoIPAM, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("using ipAddrsNoIpam annotation to assign IP address to a pod, bypassing IPAM", func() {
				It("should fail if ipAddrsNoIpam is not enabled", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net3",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "datastore_type": "%s",
			          "nodename_file_optional": true,
			 	  "ipam": {},
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP address.
					name := fmt.Sprintf("run%d", rand.Uint32())
					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrsNoIpam": "[\"10.0.0.1\"]",
							},
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					_, session, _, _, _, contNs, err := testutils.CreateContainer(netconfCalicoIPAM, name, testutils.K8S_TEST_NS, "")
					Eventually(session).Should(gexec.Exit())
					Expect(session.Out).Should(gbytes.Say("requested feature is not enabled: ip_addrs_no_ipam"))

					_, err = testutils.DeleteContainer(netconfCalicoIPAM, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("should successfully assigns the annotated IP address", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
				  "cniVersion": "%s",
				  "name": "net4",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "datastore_type": "%s",
			          "nodename_file_optional": true,
				  "ipam": {
					   "type": "calico-ipam",
					   "assign_ipv4": "true",
					   "assign_ipv6": "true"
				   },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"debug"
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

					assignIP := net.IPv4(20, 0, 0, 111).To4()

					// Create a new ipPool.
					ipPool := "20.0.0.0/24"
					testutils.MustCreateNewIPPool(calicoClient, ipPool, false, false, true)
					_, _, err := net.ParseCIDR(ipPool)
					Expect(err).NotTo(HaveOccurred())

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP address.
					name := fmt.Sprintf("run%d", rand.Uint32())
					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrs": "[\"20.0.0.111\"]",
							},
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					containerID, _, contVeth, contAddresses, _, netNS, err := testutils.CreateContainer(netconfCalicoIPAM, name, testutils.K8S_TEST_NS, "")
					Expect(err).NotTo(HaveOccurred())
					mac := contVeth.Attrs().HardwareAddr

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					log.Infof("Container got IP address: %s", podIP)
					Expect(podIP).Should(Equal(assignIP))

					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					wrkload, err := ids.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					interfaceName := k8sconversion.VethNameForWorkload(testutils.K8S_TEST_NS, name)

					// Make sure WorkloadEndpoint is created and has the requested IP in the datastore.
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						Pod:           name,
						InterfaceName: interfaceName,
						IPNetworks:    []string{assignIP.String() + "/32"},
						MAC:           mac.String(),
						Profiles:      []string{"kns.test", "ksa.test.default"},
						Node:          hostname,
						Endpoint:      "eth0",
						Workload:      "",
						ContainerID:   containerID,
						Orchestrator:  api.OrchestratorKubernetes,
					}))

					// Delete the container.
					_, err = testutils.DeleteContainer(netconfCalicoIPAM, netNS.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("using ipAddrs annotation to assign IP address to a pod, through Calico IPAM, without specifying cniVersion in CNI config", func() {
				It("should successfully assigns the annotated IP address", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
				  "name": "net5",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "datastore_type": "%s",
			          "nodename_file_optional": true,
				  "ipam": {
					   "type": "calico-ipam",
					   "assign_ipv4": "true",
					   "assign_ipv6": "true"
				   },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

					assignIP := net.IPv4(20, 0, 0, 111).To4()

					// Create a new ipPool.
					ipPool := "20.0.0.0/24"
					testutils.MustCreateNewIPPool(calicoClient, ipPool, false, false, true)
					_, _, err := net.ParseCIDR(ipPool)
					Expect(err).NotTo(HaveOccurred())

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP address.
					name := fmt.Sprintf("run%d", rand.Uint32())
					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrs": "[\"20.0.0.111\"]",
							},
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					containerID, _, contVeth, contAddresses, _, contNs, err := testutils.CreateContainer(netconfCalicoIPAM, name, testutils.K8S_TEST_NS, "")
					Expect(err).NotTo(HaveOccurred())
					mac := contVeth.Attrs().HardwareAddr

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					log.Infof("Container got IP address: %s", podIP)
					Expect(podIP).Should(Equal(assignIP))

					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					wrkload, err := ids.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					interfaceName := k8sconversion.VethNameForWorkload(testutils.K8S_TEST_NS, name)

					// Make sure WorkloadEndpoint is created and has the requested IP in the datastore.
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						Pod:           name,
						InterfaceName: interfaceName,
						IPNetworks:    []string{assignIP.String() + "/32"},
						MAC:           mac.String(),
						Profiles:      []string{"kns.test", "ksa.test.default"},
						Node:          hostname,
						Endpoint:      "eth0",
						Workload:      "",
						ContainerID:   containerID,
						Orchestrator:  api.OrchestratorKubernetes,
					}))

					// Delete the container.
					_, err = testutils.DeleteContainer(netconfCalicoIPAM, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			hostLocalIPAMConfigs := []struct {
				description, config, unexpectedRoute string
				expectedV4Routes, expectedV6Routes   []string
				numIPv4IPs, numIPv6IPs               int
			}{
				{
					description: "old-style inline subnet",
					config: `
					{
					  "cniVersion": "%s",
					  "name": "net6",
					  "nodename_file_optional": true,
					  "type": "calico",
					  "etcd_endpoints": "http://%s:2379",
					  "datastore_type": "%s",
					  "ipam": {
					    "type": "host-local",
					    "subnet": "usePodCidr"
					  },
					  "kubernetes": {
					   "k8s_api_root": "http://127.0.0.1:8080"
					  },
					  "policy": {"type": "k8s"},
					  "log_level":"debug"
					}`,
					expectedV4Routes: []string{
						regexp.QuoteMeta("default via 169.254.1.1 dev eth0"),
						regexp.QuoteMeta("169.254.1.1 dev eth0 scope link"),
					},
					unexpectedRoute: regexp.QuoteMeta("10."),
					numIPv4IPs:      1,
					numIPv6IPs:      0,
				},
				{
					// This scenario tests IPv4+IPv6 without specifying any routes.
					description: "new-style with IPv4 and IPv6 ranges, no routes",
					config: `
					{
					  "cniVersion": "%s",
					  "name": "net6",
					  "nodename_file_optional": true,
					  "type": "calico",
					  "etcd_endpoints": "http://%s:2379",
					  "datastore_type": "%s",
					  "ipam": {
					    "type": "host-local",
					    "ranges": [
					       [
					          {
					            "subnet": "usePodCidr"
					          }
					       ],
					       [
					          {
					            "subnet": "dead:beef::/96"
					          }
					       ]
					    ]
					  },
					  "kubernetes": {
					   "k8s_api_root": "http://127.0.0.1:8080"
					  },
					  "policy": {"type": "k8s"},
					  "log_level":"debug"
					}`,
					expectedV4Routes: []string{
						regexp.QuoteMeta("default via 169.254.1.1 dev eth0"),
						regexp.QuoteMeta("169.254.1.1 dev eth0 scope link"),
					},
					expectedV6Routes: []string{
						"dead:beef::[0-9a-f]* dev eth0  metric 256",
						"fe80::/64 dev eth0  metric 256",
						"default via fe80::ecee:eeff:feee:eeee dev eth0  metric 1024",
						"ff00::/8 dev eth0  metric 256",
					},
					unexpectedRoute: regexp.QuoteMeta("10."),
					numIPv4IPs:      1,
					numIPv6IPs:      1,
				},
				{
					// In this scenario, we use a lot more of the host-local IPAM plugin.  Namely:
					// - we use multiple ranges, one of which is IPv6, the other uses the podCIDR
					// - we add custom routes, which override our default 0/0 and ::/0 routes.
					description: "new-style with IPv4 and IPv6 ranges and routes",
					config: `
					{
					  "cniVersion": "%s",
					  "name": "net6",
					  "nodename_file_optional": true,
					  "type": "calico",
					  "etcd_endpoints": "http://%s:2379",
					  "datastore_type": "%s",
					  "ipam": {
					    "type": "host-local",
					    "ranges": [
					       [
					          {
					            "subnet": "usePodCidr"
					          }
					       ],
					       [
					           { 
					               "subnet": "10.100.0.0/24" 
					           }
					       ],
					       [
					          {
					            "subnet": "dead:beef::/96"
					          }
					       ]
					    ],
					    "routes": [
					      {"dst": "10.123.0.0/16", "gw": "10.123.0.1"},
					      {"dst": "10.124.0.0/16"},
					      {"dst": "dead:beef::/96"}
					    ]
					  },
					  "kubernetes": {
					   "k8s_api_root": "http://127.0.0.1:8080"
					  },
					  "policy": {"type": "k8s"},
					  "log_level":"debug"
					}`,
					expectedV4Routes: []string{
						regexp.QuoteMeta("10.123.0.0/16 via 169.254.1.1 dev eth0"),
						regexp.QuoteMeta("10.124.0.0/16 via 169.254.1.1 dev eth0"),
						regexp.QuoteMeta("169.254.1.1 dev eth0 scope link"),
					},
					expectedV6Routes: []string{
						"dead:beef::. dev eth0  metric 256",
						"dead:beef::/96 via fe80::ecee:eeff:feee:eeee dev eth0  metric 1024",
						"fe80::/64 dev eth0  metric 256",
						"ff00::/8 dev eth0  metric 256",
					},
					unexpectedRoute: "default",
					numIPv4IPs:      2,
					numIPv6IPs:      1,
				},
				{
					// In this scenario, we use a lot more of the host-local IPAM plugin.  Namely:
					// - we use multiple ranges, one of which is IPv6, the other uses the podCIDR
					// - we add custom routes, but configure the plugin to also include our default routes.
					description: "new-style with IPv4 and IPv6 ranges and routes and Calico default routes",
					config: `
					{
					  "cniVersion": "%s",
					  "name": "net6",
					  "nodename_file_optional": true,
					  "type": "calico",
					  "etcd_endpoints": "http://%s:2379",
					  "include_default_routes": true,
					  "datastore_type": "%s",
					  "ipam": {
					    "type": "host-local",
					    "ranges": [
					       [
					          {
					            "subnet": "usePodCidr"
					          }
					       ],
					       [
					           { 
					               "subnet": "10.100.0.0/24" 
					           }
					       ],
					       [
					          {
					            "subnet": "dead:beef::/96"
					          }
					       ]
					    ],
					    "routes": [
					      {"dst": "10.123.0.0/16", "gw": "10.123.0.1"},
					      {"dst": "10.124.0.0/16"},
					      {"dst": "dead:beef::/96"}
					    ]
					  },
					  "kubernetes": {
					   "k8s_api_root": "http://127.0.0.1:8080"
					  },
					  "policy": {"type": "k8s"},
					  "log_level":"debug"
					}`,
					expectedV4Routes: []string{
						regexp.QuoteMeta("default via 169.254.1.1 dev eth0"),
						regexp.QuoteMeta("10.123.0.0/16 via 169.254.1.1 dev eth0"),
						regexp.QuoteMeta("10.124.0.0/16 via 169.254.1.1 dev eth0"),
						regexp.QuoteMeta("169.254.1.1 dev eth0 scope link"),
					},
					expectedV6Routes: []string{
						"dead:beef::. dev eth0  metric 256",
						"dead:beef::/96 via fe80::ecee:eeff:feee:eeee dev eth0  metric 1024",
						"fe80::/64 dev eth0  metric 256",
						"ff00::/8 dev eth0  metric 256",
					},
					numIPv4IPs: 2,
					numIPv6IPs: 1,
				},
			}

			for _, c := range hostLocalIPAMConfigs {
				c := c // Make sure we get a fresh variable on each loop.
				Context("Using host-local IPAM ("+c.description+"): request an IP then release it, and then request it again", func() {
					It("should successfully assign IP both times and successfully release it in the middle", func() {
						netconfHostLocalIPAM := fmt.Sprintf(c.config, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

						config, err := clientcmd.DefaultClientConfig.ClientConfig()
						Expect(err).NotTo(HaveOccurred())

						clientset, err := kubernetes.NewForConfig(config)
						Expect(err).NotTo(HaveOccurred())

						ensureNamespace(clientset, testutils.K8S_TEST_NS)

						// Create a K8s Node object with PodCIDR and name equal to hostname.
						_, err = clientset.CoreV1().Nodes().Create(&v1.Node{
							ObjectMeta: metav1.ObjectMeta{Name: hostname},
							Spec: v1.NodeSpec{
								PodCIDR: "10.0.0.0/24",
							},
						})
						Expect(err).NotTo(HaveOccurred())
						defer clientset.CoreV1().Nodes().Delete(hostname, &metav1.DeleteOptions{})

						By("Creating a pod with a specific IP address")
						name := fmt.Sprintf("run%d", rand.Uint32())
						_, err = clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{Name: name},
							Spec: v1.PodSpec{
								Containers: []v1.Container{{
									Name:  name,
									Image: "ignore",
								}},
								NodeName: hostname,
							},
						})
						Expect(err).NotTo(HaveOccurred())

						requestedIP := "10.0.0.42"
						expectedIP := net.IPv4(10, 0, 0, 42).To4()

						_, _, _, contAddresses, _, contNs, err := testutils.CreateContainer(netconfHostLocalIPAM, name, testutils.K8S_TEST_NS, requestedIP)
						Expect(err).NotTo(HaveOccurred())

						podIP := contAddresses[0].IP
						log.Infof("All container IPs: %v", contAddresses)
						Expect(podIP).Should(Equal(expectedIP))

						By("Deleting the pod we created earlier")
						_, err = testutils.DeleteContainer(netconfHostLocalIPAM, contNs.Path(), name, testutils.K8S_TEST_NS)
						Expect(err).ShouldNot(HaveOccurred())

						By("Creating a second pod with the same IP address as the first pod")
						name2 := fmt.Sprintf("run2%d", rand.Uint32())
						_, err = clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{Name: name2},
							Spec: v1.PodSpec{
								Containers: []v1.Container{{
									Name:  fmt.Sprintf("container-%s", name2),
									Image: "ignore",
								}},
								NodeName: hostname,
							},
						})
						Expect(err).NotTo(HaveOccurred())

						_, _, _, contAddresses, _, contNs, err = testutils.CreateContainer(netconfHostLocalIPAM, name2, testutils.K8S_TEST_NS, requestedIP)
						Expect(err).NotTo(HaveOccurred())

						pod2IP := contAddresses[0].IP
						log.Infof("All container IPs: %v", contAddresses)
						Expect(pod2IP).Should(Equal(expectedIP))

						contNs.Do(func(_ ns.NetNS) error {
							defer GinkgoRecover()
							out, err := exec.Command("ip", "route", "show").Output()
							Expect(err).NotTo(HaveOccurred())
							for _, r := range c.expectedV4Routes {
								Expect(string(out)).To(MatchRegexp(r))
							}

							if c.unexpectedRoute != "" {
								Expect(string(out)).NotTo(ContainSubstring(c.unexpectedRoute))
							}

							out, err = exec.Command("ip", "-6", "route", "show").Output()
							Expect(err).NotTo(HaveOccurred())
							for _, r := range c.expectedV6Routes {
								Expect(string(out)).To(MatchRegexp(r))
							}

							out, err = exec.Command("ip", "addr", "show").Output()
							Expect(err).NotTo(HaveOccurred())
							inet := regexp.MustCompile(` {4}inet .*scope global`)
							Expect(inet.FindAll(out, -1)).To(HaveLen(c.numIPv4IPs))
							inetv6 := regexp.MustCompile(` {4}inet6 .*scope global`)
							Expect(inetv6.FindAll(out, -1)).To(HaveLen(c.numIPv6IPs))

							return nil
						})

						_, err = testutils.DeleteContainer(netconfHostLocalIPAM, contNs.Path(), name2, testutils.K8S_TEST_NS)
						Expect(err).ShouldNot(HaveOccurred())
					})
				})
			}

			// This specific test case is for an issue where k8s would send extra DELs being "aggressive". See: https://github.com/kubernetes/kubernetes/issues/44100
			Context("ADD a container with a ContainerID and DEL it with the same ContainerID then ADD a new container with a different ContainerID, and send a DEL for the old ContainerID", func() {
				It("Use different CNI_ContainerIDs to ADD and DEL the container", func() {
					netconf := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net7",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "datastore_type": "%s",
           			  "nodename_file_optional": true,
			 	  "ipam": {
			    	 "type": "calico-ipam"
			         },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

					// Create a new ipPool.
					ipPool := "10.0.0.0/24"
					testutils.MustCreateNewIPPool(calicoClient, ipPool, false, false, true)

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod.
					name := fmt.Sprintf("run%d", rand.Uint32())

					cniContainerIDX := "container-id-00x"
					cniContainerIDY := "container-id-00y"

					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(
						&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name: name,
							},
							Spec: v1.PodSpec{
								Containers: []v1.Container{{
									Name:  name,
									Image: "ignore",
								}},
								NodeName: hostname,
							},
						})

					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					// ADD the container with passing a CNI_ContainerID "X".
					_, session, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf, name, testutils.K8S_TEST_NS, "", cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err := testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					log.Printf("Unmarshaled result: %v\n", result)

					// Assert that the endpoint is created in the backend datastore with ContainerID "X".
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					idsX := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  cniContainerIDX,
					}

					wrkloadX, err := idsX.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					Expect(endpoints.Items[0].Name).Should(Equal(wrkloadX))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(cniContainerIDX))

					// Delete the container with the CNI_ContainerID "X".
					exitCode, err := testutils.DeleteContainerWithId(netconf, contNs.Path(), name, testutils.K8S_TEST_NS, cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

					// The endpoint for ContainerID "X" should not exist in the backend datastore.
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))

					// ADD a new container with passing a CNI_ContainerID "Y".
					_, session, _, _, _, contNs, err = testutils.CreateContainerWithId(netconf, name, testutils.K8S_TEST_NS, "", cniContainerIDY)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err = testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					log.Printf("Unmarshaled result: %v\n", result)

					// Assert that the endpoint is created in the backend datastore with ContainerID "Y".
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					idsY := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  cniContainerIDY,
					}

					wrkloadY, err := idsY.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					Expect(endpoints.Items[0].Name).Should(Equal(wrkloadY))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(cniContainerIDY))

					// Delete the container with the CNI_ContainerID "X" again.
					exitCode, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), name, testutils.K8S_TEST_NS, cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

					// Assert that the endpoint with ContainerID "Y" is still in the datastore.
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkloadY))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(cniContainerIDY))

					// Finally, delete the container with the CNI_ContainerID "Y".
					exitCode, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), name, testutils.K8S_TEST_NS, cniContainerIDY)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

				})
			})

			// This specific test case is for an issue where k8s would send two ADDs with different container IDs for the same Pod.
			Context("Multiple ADD calls with different container IDs followed by DEL calls for stale container IDs", func() {
				It("Use different CNI_ContainerIDs to ADD and DEL the container", func() {
					netconf := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net7",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "datastore_type": "%s",
           			  "nodename_file_optional": true,
			 	  "ipam": {
			    	 "type": "calico-ipam"
			         },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

					// Create a new ipPool.
					ipPool := "10.0.0.0/24"
					testutils.MustCreateNewIPPool(calicoClient, ipPool, false, false, true)

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod.
					name := fmt.Sprintf("run%d", rand.Uint32())

					cniContainerIDX := "container-id-00x"
					cniContainerIDY := "container-id-00y"

					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(
						&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name: name,
							},
							Spec: v1.PodSpec{
								Containers: []v1.Container{{
									Name:  name,
									Image: "ignore",
								}},
								NodeName: hostname,
							},
						})

					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					// ADD the container with passing a CNI_CONTAINERID of "X".
					_, session, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf, name, testutils.K8S_TEST_NS, "", cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err := testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}
					log.Printf("Unmarshaled result: %v\n", result)

					// Assert that the endpoint is created in the backend datastore with ContainerID "X".
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					idsX := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  cniContainerIDX,
					}

					wrkloadX, err := idsX.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					Expect(endpoints.Items[0].Name).Should(Equal(wrkloadX))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(cniContainerIDX))

					// ADD the container with passing a CNI_CONTAINERID of "Y"
					_, session, _, _, _, contNs, err = testutils.CreateContainerWithId(netconf, name, testutils.K8S_TEST_NS, "", cniContainerIDY)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err = testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}
					log.Printf("Unmarshaled result: %v\n", result)

					// Assert that the endpoint is created in the backend datastore with ContainerID "Y".
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					idsY := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  cniContainerIDY,
					}

					wrkloadY, err := idsY.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					Expect(endpoints.Items[0].Name).Should(Equal(wrkloadY))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(cniContainerIDY))

					// Delete the container with the CNI_CONTAINERID "X".
					exitCode, err := testutils.DeleteContainerWithId(netconf, contNs.Path(), name, testutils.K8S_TEST_NS, cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

					// Assert that the endpoint in the backend datastore still has ContainerID "Y".
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkloadY))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(cniContainerIDY))

					// Delete the container with the CNI_CONTAINERID "Y".
					exitCode, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), name, testutils.K8S_TEST_NS, cniContainerIDY)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

					// Assert that the endpoint in the backend datastore is now gone.
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))

				})
			})

			Context("after creating a pod", func() {

				netconf := fmt.Sprintf(
					`
							{
							"cniVersion": "%s",
							"name": "net8",
							"type": "calico",
							"etcd_endpoints": "http://%s:2379",
							"datastore_type": "%s",
           			                        "nodename_file_optional": true,
							"ipam": {
									"type": "calico-ipam"
									},
							"kubernetes": {
								  "k8s_api_root": "http://127.0.0.1:8080"
								 },
							"policy": {"type": "k8s"},
							"log_level":"debug"
							}`,
					cniVersion,
					os.Getenv("ETCD_IP"),
					os.Getenv("DATASTORE_TYPE"),
				)

				var workloadName, containerID, name string
				var endpointSpec api.WorkloadEndpointSpec
				var contNs ns.NetNS
				var result *current.Result

				checkIPAMReservation := func() {
					// IPAM reservation should still be in place.
					handleID, _ := utils.GetHandleID("net8", containerID, workloadName)
					ipamIPs, err := calicoClient.IPAM().IPsByHandle(context.Background(), handleID)
					ExpectWithOffset(1, err).NotTo(HaveOccurred(), "error getting IPs")
					ExpectWithOffset(1, ipamIPs).To(HaveLen(1),
						"There should be an IPAM handle for endpoint")
					ExpectWithOffset(1, ipamIPs[0].String()+"/32").To(Equal(endpointSpec.IPNetworks[0]))
				}

				BeforeEach(func() {
					// Create a new ipPool.
					testutils.MustCreateNewIPPool(calicoClient, "10.0.0.0/24", false, false, true)

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod.
					name = fmt.Sprintf("run%d", rand.Uint32())

					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(
						&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name: name,
							},
							Spec: v1.PodSpec{
								Containers: []v1.Container{{
									Name:  name,
									Image: "ignore",
								}},
								NodeName: hostname,
							},
						})

					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)
					var session *gexec.Session
					containerID, session, _, _, _, contNs, err = testutils.CreateContainer(netconf, name, testutils.K8S_TEST_NS, "")
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					result, err = testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					log.Printf("Unmarshalled result from first ADD: %v\n", result)

					// The endpoint is created in etcd
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					workloadName, err = ids.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					Expect(endpoints.Items[0].Name).Should(Equal(workloadName))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					endpointSpec = endpoints.Items[0].Spec
					Expect(endpointSpec.ContainerID).Should(Equal(containerID))

					checkIPAMReservation()
				})

				AfterEach(func() {
					_, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), name, testutils.K8S_TEST_NS, containerID)
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("a second ADD for the same container should work, assigning a new IP", func() {
					// Try to create the same pod with a different container (so CNI receives the ADD for the same endpoint again)
					session, _, _, _, err := testutils.RunCNIPluginWithId(netconf, name, testutils.K8S_TEST_NS, "", "new-container-id", "eth0", contNs)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					resultSecondAdd, err := testutils.GetResultForCurrent(session, cniVersion)
					Expect(err).NotTo(HaveOccurred())
					log.Printf("Unmarshalled result from second ADD: %v\n", resultSecondAdd)

					// The IP addresses shouldn't be the same, since we'll reassign one.
					Expect(resultSecondAdd.IPs).ShouldNot(Equal(result.IPs))

					// Otherwise, they should be the same.
					resultSecondAdd.IPs = nil
					result.IPs = nil
					Expect(resultSecondAdd).Should(Equal(result))

					// IPAM reservation should still be in place.
					checkIPAMReservation()
				})

				Context("with networking rigged to fail", func() {
					renameVeth := func(from, to string) {
						output, err := exec.Command("ip", "link", "set", from, "down").CombinedOutput()
						Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
						output, err = exec.Command("ip", "link", "set", from, "name", to).CombinedOutput()
						Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
						output, err = exec.Command("ip", "link", "set", to, "up").CombinedOutput()
						Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
					}

					var realVethName, tweakedVethName string

					BeforeEach(func() {
						// To prevent the networking attempt from succeeding, rename the old veth.
						// This leaves a route and an eth0 in place that the plugin will struggle with.
						realVethName = endpointSpec.InterfaceName
						tweakedVethName = strings.Replace(realVethName, "cali", "sali", 1)
						renameVeth(realVethName, tweakedVethName)
					})

					It("a second ADD should fail, but not clean up the original IPAM allocation", func() {
						// Try to create the same container (so CNI receives the ADD for the same endpoint again)
						// Use a different container ID but the same Pod Name/Namespace
						session, _, _, _, err := testutils.RunCNIPluginWithId(netconf, name, testutils.K8S_TEST_NS, "", "new-container-id", "eth0", contNs)
						Expect(err).ShouldNot(HaveOccurred())
						Eventually(session).Should(gexec.Exit(1))

						// IPAM reservation should still be in place.
						checkIPAMReservation()
					})

					AfterEach(func() {
						// So the tear-down succeeds, put the veth back.
						renameVeth(tweakedVethName, realVethName)
					})
				})
			})

			Context("ask for more than 1 IPv4 addrs using ipAddrsNoIpam annotation to assign IP address to a pod, bypassing IPAM", func() {
				It("should return an error", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net9",
				  "type": "calico",
				  "feature_control": {
					  "ip_addrs_no_ipam": true
				  },
				  "etcd_endpoints": "http://%s:2379",
				  "datastore_type": "%s",
           			  "nodename_file_optional": true,
			 	  "ipam": {},
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in more than one IPv4 address.
					name := fmt.Sprintf("run%d", rand.Uint32())
					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrsNoIpam": "[\"10.0.0.1\", \"10.0.0.2\"]",
							},
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					_, _, _, _, _, contNs, err := testutils.CreateContainer(netconfCalicoIPAM, name, testutils.K8S_TEST_NS, "")
					Expect(err).To(HaveOccurred())

					// Make sure the WorkloadEndpoint is not created in the datastore.
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))

					// Delete the container.
					_, err = testutils.DeleteContainer(netconfCalicoIPAM, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("Create a container then send another ADD for the same container but with a different interface", func() {
				netconf := fmt.Sprintf(`
				{
				  "cniVersion": "%s",
				  "name": "net10",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "datastore_type": "%s",
           			  "nodename_file_optional": true,
				  "log_level": "debug",
			 	  "ipam": {
				    "type": "calico-ipam"
				  },
				  "kubernetes": {
				    "k8s_api_root": "http://127.0.0.1:8080"
				  },
				  "policy": {"type": "k8s"}
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

				It("should successfully execute both ADDs but for second ADD will return the same result as the first time but it won't network the container", func() {
					// Create a new ipPool.
					testutils.MustCreateNewIPPool(calicoClient, "10.0.0.0/24", false, false, true)

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod.
					name := "mypod-1"

					pod, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(
						&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name: name,
							},
							Spec: v1.PodSpec{
								Containers: []v1.Container{{
									Name:  name,
									Image: "ignore",
								}},
								NodeName: hostname,
							},
						})

					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					// Create the container, which will call CNI and by default it will create the container with interface name 'eth0'.
					containerID, session, _, _, _, contNs, err := testutils.CreateContainer(netconf, name, testutils.K8S_TEST_NS, "")
					Expect(err).ShouldNot(HaveOccurred())
					// Make sure the pod gets cleaned up, whether we fail or not.
					expectedIfaceName := "eth0"
					defer func() {
						_, err := testutils.DeleteContainerWithIdAndIfaceName(
							netconf, contNs.Path(), name, testutils.K8S_TEST_NS, containerID, expectedIfaceName)
						Expect(err).ShouldNot(HaveOccurred())
					}()
					Eventually(session).Should(gexec.Exit())

					result, err := testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					log.Printf("First container, unmarshalled result: %v\n", result)

					// The endpoint is created in etcd
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					wepName, err := ids.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					Expect(endpoints.Items[0].Name).Should(Equal(wepName))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))

					// Try to create the same container but with a different endpoint (container interface name 'eth1'),
					// so CNI receives the ADD for the same containerID but different endpoint.
					session, _, _, _, err = testutils.RunCNIPluginWithId(
						netconf, name, testutils.K8S_TEST_NS, "", containerID, "eth1", contNs)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					// If the above command succeeds, the CNI plugin will have renamed the container side of the
					// veth to "eth1".  We need to clean it up under the correct name, or we'll leak it.
					expectedIfaceName = "eth1"

					// The endpoint is created in etcd
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Returned endpoint should still have the same fields even after calling the CNI plugin with a different interface name.
					// Calico CNI currently only supports one endpoint (interface) per pod.
					Expect(endpoints.Items[0].Name).Should(Equal(wepName))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					// Explicitly assert that endpoint name is still 'eth0' (which was the case from the first ADD)
					Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))

					// Now we create another pod with a very similar name.
					name2 := "mypod"

					pod2, err := clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(
						&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name: name2,
							},
							Spec: v1.PodSpec{
								Containers: []v1.Container{{
									Name:  name2,
									Image: "ignore",
								}},
								NodeName: hostname,
							},
						})

					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod2)

					// Now since we can't use the same container namespace for the second container, we need to create a new one.
					contNs2, err := ns.NewNS()
					Expect(err).NotTo(HaveOccurred())
					containerID2 := "random-cid"
					defer func() {
						_, err := testutils.DeleteContainerWithId(netconf, contNs2.Path(), name2, testutils.K8S_TEST_NS, containerID2)
						Expect(err).ShouldNot(HaveOccurred())
					}()

					err = contNs2.Do(func(_ ns.NetNS) error {
						lo, err := netlink.LinkByName("lo")
						if err != nil {
							return err
						}
						return netlink.LinkSetUp(lo)
					})
					Expect(err).NotTo(HaveOccurred())

					// Create the container, which will call CNI and by default it will create the container with interface name 'eth0'.
					session2, _, _, _, err := testutils.RunCNIPluginWithId(
						netconf, name2, testutils.K8S_TEST_NS, "", containerID2, "eth0", contNs2)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session2).Should(gexec.Exit())

					result, err = testutils.GetResultForCurrent(session2, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					log.Printf("Second container: unmarshalled result: %v\n", result)

					// Make sure BOTH of the endpoints are there in etcd
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(2))

					// Construct the workloadendpoint name for the second pod.
					ids2 := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name2,
						ContainerID:  containerID2,
					}

					wrkload2, err := ids2.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					// Explicitly Get the second workloadendpoint and make sure it exists and has all the right fields.
					ep, err := calicoClient.WorkloadEndpoints().Get(ctx, testutils.K8S_TEST_NS, wrkload2, options.GetOptions{})
					Expect(err).ShouldNot(HaveOccurred())

					// Returned endpoint should still have the same fields even after calling the CNI plugin with a different interface name.
					// Calico CNI currently only supports one endpoint (interface) per pod.
					Expect(ep.Name).Should(Equal(wrkload2))
					Expect(ep.Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(ep.Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))

					// Assert this WEP has the new containerID for the second pod.
					Expect(ep.Spec.ContainerID).Should(Equal(containerID2))
				})
			})

			Context("when pod has a service account", func() {
				It("should add a service account profile to the workload endpoint", func() {
					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					if err != nil {
						panic(err)
					}
					clientset, err := kubernetes.NewForConfig(config)
					if err != nil {
						panic(err)
					}

					name := fmt.Sprintf("run%d", rand.Uint32())

					// Create a K8s service account
					saName := "testserviceaccount"
					_, err = clientset.CoreV1().ServiceAccounts(testutils.K8S_TEST_NS).Create(&v1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{Name: saName},
					})
					if err != nil {
						panic(err)
					}

					// Create a K8s pod with the service account
					_, err = clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{Name: name},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  fmt.Sprintf("container-%s", name),
								Image: "ignore",
								Ports: []v1.ContainerPort{{
									Name:          "anamedport",
									ContainerPort: 555,
								}},
							}},
							ServiceAccountName: saName,
							NodeName:           hostname,
						},
					})
					if err != nil {
						panic(err)
					}
					containerID, session, contVeth, _, _, contNs, err := testutils.CreateContainer(netconf, name, testutils.K8S_TEST_NS, "")

					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err := testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					mac := contVeth.Attrs().HardwareAddr

					Expect(len(result.IPs)).Should(Equal(1))

					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					wrkload, err := ids.CalculateWorkloadEndpointName(false)
					interfaceName := k8sconversion.VethNameForWorkload(testutils.K8S_TEST_NS, name)
					Expect(err).NotTo(HaveOccurred())

					// The endpoint is created
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/serviceaccount": saName,
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
					}))
					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						Pod:           name,
						InterfaceName: interfaceName,
						IPNetworks:    []string{result.IPs[0].Address.String()},
						MAC:           mac.String(),
						Profiles:      []string{"kns.test", "ksa.test." + saName},
						Node:          hostname,
						Endpoint:      "eth0",
						Workload:      "",
						ContainerID:   containerID,
						Orchestrator:  api.OrchestratorKubernetes,
						Ports: []api.EndpointPort{{
							Name:     "anamedport",
							Protocol: numorstring.ProtocolFromString("TCP"),
							Port:     555,
						}},
					}))

					_, err = testutils.DeleteContainer(netconf, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())

					// Make sure there are no endpoints anymore
					endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))

					// Make sure the interface has been removed from the namespace
					targetNs, _ := ns.GetNS(contNs.Path())
					err = targetNs.Do(func(_ ns.NetNS) error {
						_, err = netlink.LinkByName("eth0")
						return err
					})
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(Equal("Link not found"))

					// Make sure the interface has been removed from the host
					_, err = netlink.LinkByName("cali" + containerID)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(Equal("Link not found"))
				})
			})

			Context("when pod has a GenerateName", func() {
				It("should add a workload endpoint with the GenerateName", func() {
					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					if err != nil {
						panic(err)
					}
					clientset, err := kubernetes.NewForConfig(config)
					if err != nil {
						panic(err)
					}

					name := fmt.Sprintf("run%d", rand.Uint32())

					// Create a K8s pod with GenerateName
					generateName := "test-gen-name"
					_, err = clientset.CoreV1().Pods(testutils.K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{Name: name,
							GenerateName: generateName},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  fmt.Sprintf("container-%s", name),
								Image: "ignore",
								Ports: []v1.ContainerPort{{
									Name:          "anamedport",
									ContainerPort: 555,
								}},
							}},
							NodeName: hostname,
						},
					})
					if err != nil {
						panic(err)
					}
					containerID, session, contVeth, _, _, contNs, err := testutils.CreateContainer(netconf, name, testutils.K8S_TEST_NS, "")

					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err := testutils.GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					wrkload, err := ids.CalculateWorkloadEndpointName(false)
					Expect(err).NotTo(HaveOccurred())

					mac := contVeth.Attrs().HardwareAddr
					interfaceName := k8sconversion.VethNameForWorkload(testutils.K8S_TEST_NS, name)

					// The endpoint is created
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
					Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.K8S_TEST_NS))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      "test",
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))
					// Make sure that the GenerateName is there.
					Expect(endpoints.Items[0].GenerateName).Should(Equal(generateName))

					// Let's just check that the Spec is good too.
					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						Pod:           name,
						InterfaceName: interfaceName,
						IPNetworks:    []string{result.IPs[0].Address.String()},
						MAC:           mac.String(),
						Profiles:      []string{"kns.test", "ksa.test.default"},
						Node:          hostname,
						Endpoint:      "eth0",
						Workload:      "",
						ContainerID:   containerID,
						Orchestrator:  api.OrchestratorKubernetes,
						Ports: []api.EndpointPort{{
							Name:     "anamedport",
							Protocol: numorstring.ProtocolFromString("TCP"),
							Port:     555,
						}},
					}))

					_, err = testutils.DeleteContainer(netconf, contNs.Path(), name, testutils.K8S_TEST_NS)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})
		})
	})
})
