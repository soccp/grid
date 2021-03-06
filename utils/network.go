// Copyright 2018 Tigera Inc
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
package utils

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	//"regexp"
	//"strings"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/projectcalico/cni-plugin/types"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var (
	// IPv4AllNet represents the IPv4 all-addresses CIDR 0.0.0.0/0.
	IPv4AllNet *net.IPNet
	// IPv6AllNet represents the IPv6 all-addresses CIDR ::/0.
	IPv6AllNet    *net.IPNet
	DefaultRoutes []*net.IPNet
)

func init() {
	var err error
	_, IPv4AllNet, err = net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		panic(err)
	}
	_, IPv6AllNet, err = net.ParseCIDR("::/0")
	if err != nil {
		panic(err)
	}
	DefaultRoutes = []*net.IPNet{
		IPv4AllNet,
		IPv6AllNet, // Only used if we end up adding a v6 address.
	}
}

//zk
func NewRandomMac() net.HardwareAddr {
	m := make(net.HardwareAddr, 6)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 6; i++ {
		mac_byte := rand.Intn(256)
		m[i] = byte(mac_byte)

		rand.Seed(int64(mac_byte))
	}

	return m
}

// DoNetworking performs the networking for the given config and IPAM result
func DoNetworking(
	args *skel.CmdArgs,
	conf types.NetConf,
	result *current.Result,
	logger *logrus.Entry,
	desiredVethName string,
	routes []*net.IPNet,
) (hostVethName, contVethMAC string, err error) {
	// Select the first 11 characters of the containerID for the host veth.
	hostVethName = "grid" + args.ContainerID[:Min(11, len(args.ContainerID))]
	contVethName := args.IfName
	var hasIPv4, hasIPv6 bool

	// If a desired veth name was passed in, use that instead.
	if desiredVethName != "" {
		hostVethName = desiredVethName
	}

	logger.Infof("Setting the host side veth name to %s", hostVethName)

	// Clean up if hostVeth exists.
	if oldHostVeth, err := netlink.LinkByName(hostVethName); err == nil {
		if err = netlink.LinkDel(oldHostVeth); err != nil {
			return "", "", fmt.Errorf("failed to delete old hostVeth %v: %v", hostVethName, err)
		}
		logger.Infof("Cleaning old hostVeth: %v", hostVethName)
	}
	/*mask, err := GetLocalNetInfo()
	if err != nil {
		return "", "", err
	}*/
	gw, err := GetGateway()
	localinfo, err := GetLocalNetInfo()
	if err != nil {
		return "", "", fmt.Errorf("failed to get local netinfo for k8s service cidr")
	}
	if err != nil {
		return "", "", err
	}
	logger.Debugf("local gateway is %v", gw)
	err = ns.WithNetNSPath(args.Netns, func(hostNS ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  contVethName,
				Flags: net.FlagUp,
				MTU:   conf.MTU,
			},
			PeerName: hostVethName,
		}

		if err := netlink.LinkAdd(veth); err != nil {
			logger.Errorf("Error adding veth %+v: %s", veth, err)
			return err
		}

		hostVeth, err := netlink.LinkByName(hostVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
			return err
		}

		/*if mac, err := net.ParseMAC("EE:EE:EE:EE:EE:EE"); err != nil {
			logger.Infof("failed to parse MAC Address: %v. Using kernel generated MAC.", err)
		} else {
			// Set the MAC address on the host side interface so the kernel does not
			// have to generate a persistent address which fails some times.
			if err = netlink.LinkSetHardwareAddr(hostVeth, mac); err != nil {
				logger.Warnf("failed to Set MAC of %q: %v. Using kernel generated MAC.", hostVethName, err)
			}
		}*/
		//zk  Modify the logic to get the MAC for hostVeth

		mac := NewRandomMac()
		if err = netlink.LinkSetHardwareAddr(hostVeth, mac); err != nil {
			logger.Warnf("failed to Set MAC of %q: %v. Using kernel generated MAC.", hostVethName, err)
		}

		// Explicitly set the veth to UP state, because netlink doesn't always do that on all the platforms with net.FlagUp.
		// veth won't get a link local address unless it's set to UP state.
		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %v", hostVethName, err)
		}

		contVeth, err := netlink.LinkByName(contVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", contVethName, err)
			return err
		}

		// Fetch the MAC from the container Veth. This is needed by Calico.
		contVethMAC = contVeth.Attrs().HardwareAddr.String()
		logger.WithField("MAC", contVethMAC).Debug("Found MAC for container veth")

		// At this point, the virtual ethernet pair has been created, and both ends have the right names.
		// Both ends of the veth are still in the container's network namespace.

		// Figure out whether we have IPv4 and/or IPv6 addresses.
		for _, addr := range result.IPs {
			if addr.Version == "4" {
				hasIPv4 = true
			} else if addr.Version == "6" {
				hasIPv6 = true
			}
		}

		// Do the per-IP version set-up.  Add gateway routes etc.
		/*if hasIPv4 {
			//zk
			// Add a connected route to a dummy next hop so that a default route can be set
			//gateway := GetGateway()
			//g := strings.Split(gateway, ".")
			//first, _ := strconv.Atoi(g[0])
			//second, _ := strconv.Atoi(g[1])
			//third, _ := strconv.Atoi(g[2])
			//four, _ := strconv.Atoi(g[3])
			gw := net.IPv4(172, 16, 30, 1)
			//gw := net.IPv4(byte(first), byte(second), byte(third), byte(four))
			gwNet := &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)}
			err := netlink.RouteAdd(
				&netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst:       gwNet,
				},
			)

			if err != nil {
				return fmt.Errorf("failed to add route inside the container: %v", err)
			}

			for _, r := range routes {
				if r.IP.To4() == nil {
					logger.WithField("route", r).Debug("Skipping non-IPv4 route")
					continue
				}
				logger.WithField("route", r).Debug("Adding IPv4 route")
				if err = ip.AddRoute(r, gw, contVeth); err != nil {
					return fmt.Errorf("failed to add IPv4 route for %v via %v: %v", r, gw, err)
				}
			}
		}*/

		// Now add the IPs to the container side of the veth.
		for _, addr := range result.IPs {
			/*mask, err := GetLocalNetInfo()
			if err != nil {
				return err
			}*/
			//IpNet := &net.IPNet{IP: addr.Address.IP, Mask: net.CIDRMask(23, 32)}
			//addr.Address.Mask = mask.Mask
			IpNet := &net.IPNet{IP: addr.Address.IP, Mask: addr.Address.Mask}
			//IpNet := &net.IPNet{IP: addr.Address.IP, Mask: mask.Mask}
			//if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: &addr.Address}); err != nil {
			if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: IpNet}); err != nil {
				return fmt.Errorf("failed to add IP addr to %q: %v", contVeth, err)
			}
			for _, r := range routes {
				if r.IP.To4() == nil {
					logger.WithField("route", r).Debug("Skipping non-IPv4 route")
					continue
				}

				//gw := net.IPv4(192, 168, 12, 1)
				/*gw, err := GetGateway()
				if err != nil {
					return err
				}*/
				if err = ip.AddRoute(r, gw, contVeth); err != nil {
					return fmt.Errorf("failed to add IPv4 route for %v via %v: %v", r, gw, err)
				}
				// add k8s service cidr route to localhost
				ds := net.IPv4(10, 96, 0, 0)
				dsNet := &net.IPNet{IP: ds, Mask: net.CIDRMask(12, 32)}
				local := *localinfo
				route := netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Dst:       dsNet,
					Gw:        local.IP,
				}
				err = netlink.RouteAdd(&route)
				if err != nil {
					return fmt.Errorf("failed to add IPv4 route for k8s service cidr")
				}
				logger.WithField("route", r).Debug("Adding IPv4 route")
			}
		}

		/*if err = configureContainerSysctls(logger, conf.ContainerSettings, hasIPv4, hasIPv6); err != nil {
			return fmt.Errorf("error configuring sysctls for the container netns, error: %s", err)
		}*/

		// Now that the everything has been successfully set up in the container, move the "host" end of the
		// veth into the host namespace.
		if err = netlink.LinkSetNsFd(hostVeth, int(hostNS.Fd())); err != nil {
			return fmt.Errorf("failed to move veth to host netns: %v", err)
		}

		return nil
	})

	if err != nil {
		logger.Errorf("Error creating veth: %s", err)
		return "", "", err
	}

	/*err = configureSysctls(hostVethName, hasIPv4, hasIPv6)
	if err != nil {
		return "", "", fmt.Errorf("error configuring sysctls for interface: %s, error: %s", hostVethName, err)
	}*/

	// Moving a veth between namespaces always leaves it in the "DOWN" state. Set it back to "UP" now that we're
	// back in the host namespace.
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return "", "", fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
	}

	if err = netlink.LinkSetUp(hostVeth); err != nil {
		return "", "", fmt.Errorf("failed to set %q up: %v", hostVethName, err)
	}

	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	/*err = SetupRoutes(hostVeth, result)
	if err != nil {
		return "", "", fmt.Errorf("error adding host side routes for interface: %s, error: %s", hostVeth.Attrs().Name, err)
	}*/
	//zk
	br0link, err := netlink.LinkByName("br0")
	if err != nil {
		return "", "", fmt.Errorf("failed to lookup %s: %v", "br0", err)
	}
	err = netlink.LinkSetMasterByIndex(hostVeth, br0link.Attrs().Index)
	//err = Brctl(hostVethName)
	if err != nil {
		return "", "", fmt.Errorf("ERROR add hostveth %s to br0, err: %s", hostVethName, err)
	}

	return hostVethName, contVethMAC, err
}

// SetupRoutes sets up the routes for the host side of the veth pair.
func SetupRoutes(hostVeth netlink.Link, result *current.Result) error {

	// Go through all the IPs and add routes for each IP in the result.
	for _, ipAddr := range result.IPs {
		route := netlink.Route{
			LinkIndex: hostVeth.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &ipAddr.Address,
		}
		err := netlink.RouteAdd(&route)

		if err != nil {
			switch err {

			// Route already exists, but not necessarily pointing to the same interface.
			case syscall.EEXIST:
				// List all the routes for the interface.
				routes, err := netlink.RouteList(hostVeth, netlink.FAMILY_ALL)
				if err != nil {
					return fmt.Errorf("error listing routes")
				}

				// Go through all the routes pointing to the interface, and see if any of them is
				// exactly what we are intending to program.
				// If the route we want is already there then most likely it's programmed by Felix, so we ignore it,
				// and we return an error if none of the routes match the route we're trying to program.
				logrus.WithFields(logrus.Fields{"route": route, "scope": route.Scope}).Debug("Constructed route")
				for _, r := range routes {
					logrus.WithFields(logrus.Fields{"interface": hostVeth.Attrs().Name, "route": r, "scope": r.Scope}).Debug("Routes for the interface")
					if r.LinkIndex == route.LinkIndex && r.Dst.IP.Equal(route.Dst.IP) && r.Scope == route.Scope {
						// Route was already present on the host.
						logrus.WithFields(logrus.Fields{"interface": hostVeth.Attrs().Name}).Infof("CNI skipping add route. Route already exists")
						return nil
					}
				}
				return fmt.Errorf("route (Ifindex: %d, Dst: %s, Scope: %v) already exists for an interface other than '%s'",
					route.LinkIndex, route.Dst.String(), route.Scope, hostVeth.Attrs().Name)
			default:
				return fmt.Errorf("failed to add route (Ifindex: %d, Dst: %s, Scope: %v, Iface: %s): %v",
					route.LinkIndex, route.Dst.String(), route.Scope, hostVeth.Attrs().Name, err)
			}
		}

		logrus.WithFields(logrus.Fields{"interface": hostVeth, "IP": ipAddr.Address}).Debugf("CNI adding route")
	}
	return nil
}

// configureSysctls configures necessary sysctls required for the host side of the veth pair for IPv4 and/or IPv6.
func configureSysctls(hostVethName string, hasIPv4, hasIPv6 bool) error {
	var err error

	if hasIPv4 {
		// Enable proxy ARP, this makes the host respond to all ARP requests with its own
		// MAC. We install explicit routes into the containers network
		// namespace and we use a link-local address for the gateway.  Turing on proxy ARP
		// means that we don't need to assign the link local address explicitly to each
		// host side of the veth, which is one fewer thing to maintain and one fewer
		// thing we may clash over.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv4.conf.%s.proxy_arp=1: %s", hostVethName, err)
		}

		// Normally, the kernel has a delay before responding to proxy ARP but we know
		// that's not needed in a Calico network so we disable it.
		/*if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostVethName), "0"); err != nil {
			return fmt.Errorf("failed to set net.ipv4.neigh.%s.proxy_delay=0: %s", hostVethName, err)
		}*/

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv4.conf.%s.forwarding=1: %s", hostVethName, err)
		}
	}

	if hasIPv6 {
		// Make sure ipv6 is enabled on the hostVeth interface in the host network namespace.
		// Interfaces won't get a link local address without this sysctl set to 0.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", hostVethName), "0"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.disable_ipv6=0: %s", hostVethName, err)
		}

		// Enable proxy NDP, similarly to proxy ARP, described above in IPv4 section.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.proxy_ndp=1: %s", hostVethName, err)
		}

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/forwarding", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.forwarding=1: %s", hostVethName, err)
		}
	}

	return nil
}

// configureContainerSysctls configures necessary sysctls required inside the container netns.
func configureContainerSysctls(logger *logrus.Entry, settings types.ContainerSettings, hasIPv4, hasIPv6 bool) error {
	// If an IPv4 address is assigned, then configure IPv4 sysctls.
	if hasIPv4 {
		if settings.AllowIPForwarding {
			logger.Info("Enabling IPv4 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
				return err
			}
		} else {
			logger.Info("Disabling IPv4 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", "0"); err != nil {
				return err
			}
		}
	}

	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasIPv6 {
		if settings.AllowIPForwarding {
			logger.Info("Enabling IPv6 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
				return err
			}
		} else {
			logger.Info("Disabling IPv6 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", "0"); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeProcSys takes the sysctl path and a string value to set i.e. "0" or "1" and sets the sysctl.
func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

//zk use brctl shell command bring hostveth connect to bridge

func Brctl(hostvethName string) error {
	cmd := exec.Command("brctl", "addif", "br0", hostvethName)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

// zk get br0 ip
func GetLocalNetInfo() (ipnet *net.IPNet, err error) {
	addrs, err := net.InterfaceByName("br0")

	if err != nil {
		return nil, fmt.Errorf("get br0 addrs failed %s", err)
	}

	address, err := addrs.Addrs()
	if err != nil {
		return nil, fmt.Errorf("get br0 address failed %s", err)
	}
	add := address[0]
	// 检查ip地址判断是否回环地址
	if ipnet, ok := add.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
		if ipnet.IP.To4() != nil {
			return ipnet, err
		}

	}
	return nil, fmt.Errorf("get %s netinfo failed %s", "br0")
}

/*func GetLocalGateway() (gateway net.IP, err error) {
	command := "ip route |grep \"default via\" | grep \"br0\" |awk '{print $3}'"
	cmd := exec.Command("/bin/sh", "-c", command)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("run command %s err", command)
	}
	v := strings.TrimSpace(out.String())
	matched, err := regexp.MatchString(`((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)`, "")
	if err != nil {
		return nil, fmt.Errorf("regexp run command output failed errinfo is %s", err)
	}
	if !matched {
		return nil, fmt.Errorf("regexp result is %s", v)
	}
	gateway = net.ParseIP(v)
	return gateway.To4(), nil
}*/

func GetGateway() (gateway net.IP, err error) {
	hostveth, _ := netlink.LinkByName("br0")
	routes, err := netlink.RouteList(hostveth, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("error listing routes")
	}
	if routes[0].LinkIndex == hostveth.Attrs().Index {
		return routes[0].Gw, nil
	}
	return nil, fmt.Errorf("error get br0 default gateway")
}
