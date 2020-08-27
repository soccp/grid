// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/sirupsen/logrus"
)

// Create a new flag set.
var flagSet = flag.NewFlagSet("Grid-import", flag.ContinueOnError)

// Build the set of supported flags.
var version = flagSet.Bool("v", false, "Display version")
var cidr = flagSet.String("cidr", "", "Import available IP pools,such as 192.168.13.0/24")

func main() {
	// Set up logging formatting.
	logrus.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	logrus.AddHook(&logutils.ContextHook{})

	// Parse the provided flags.
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Decide which action to take based on the given flags.
	if *version {
		fmt.Println(startup.VERSION)
		os.Exit(0)
	} else if *runStartup {
		startup.Run()
	} else {
		fmt.Println("No valid options provided. Usage:")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
}

func configureIPPools(ctx context.Context, client client.Interface) {
	// Read in environment variables for use here and later.
	ipv4Pool := os.Getenv("CALICO_IPV4POOL_CIDR")
	ipv6Pool := os.Getenv("CALICO_IPV6POOL_CIDR")

	if strings.ToLower(os.Getenv("NO_DEFAULT_POOLS")) == "true" {
		if len(ipv4Pool) > 0 || len(ipv6Pool) > 0 {
			log.Error("Invalid configuration with NO_DEFAULT_POOLS defined and CALICO_IPV4POOL_CIDR or CALICO_IPV6POOL_CIDR defined.")
			terminate()
		}

		log.Info("Skipping IP pool configuration")
		return
	}

	ipv4IpipModeEnvVar := strings.ToLower(os.Getenv("CALICO_IPV4POOL_IPIP"))

	// Get a list of all IP Pools
	poolList, err := client.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Error("Unable to fetch IP pool list")
		terminate()
		return // not really needed but allows testing to function
	}

	// Check for IPv4 and IPv6 pools.
	ipv4Present := false
	ipv6Present := false
	for _, p := range poolList.Items {
		ip, _, err := cnet.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			log.Warnf("Error parsing CIDR '%s'. Skipping the IPPool.", p.Spec.CIDR)
		}
		version := ip.Version()
		ipv4Present = ipv4Present || (version == 4)
		ipv6Present = ipv6Present || (version == 6)
		if ipv4Present && ipv6Present {
			break
		}
	}

	// Read IPV4 CIDR from env if set and parse then check it for errors
	if ipv4Pool == "" {
		ipv4Pool = DEFAULT_IPV4_POOL_CIDR
	}
	_, ipv4Cidr, err := cnet.ParseCIDR(ipv4Pool)
	if err != nil || ipv4Cidr.Version() != 4 {
		log.Errorf("Invalid CIDR specified in CALICO_IPV4POOL_CIDR '%s'", ipv4Pool)
		terminate()
		return // not really needed but allows testing to function
	}

	// If no IPv6 pool is specified, generate one.
	if ipv6Pool == "" {
		ipv6Pool, err = GenerateIPv6ULAPrefix()
		if err != nil {
			log.Errorf("Failed to generate an IPv6 default pool")
			terminate()
		}
	}
	_, ipv6Cidr, err := cnet.ParseCIDR(ipv6Pool)
	if err != nil || ipv6Cidr.Version() != 6 {
		log.Errorf("Invalid CIDR specified in CALICO_IPV6POOL_CIDR '%s'", ipv6Pool)
		terminate()
		return // not really needed but allows testing to function
	}

	// Ensure there are pools created for each IP version.
	if !ipv4Present {
		log.Debug("Create default IPv4 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV4POOL_NAT_OUTGOING", true)
		createIPPool(ctx, client, ipv4Cidr, DEFAULT_IPV4_POOL_NAME, ipv4IpipModeEnvVar, outgoingNATEnabled)
	}
	if !ipv6Present && ipv6Supported() {
		log.Debug("Create default IPv6 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV6POOL_NAT_OUTGOING", false)

		createIPPool(ctx, client, ipv6Cidr, DEFAULT_IPV6_POOL_NAME, string(api.IPIPModeNever), outgoingNATEnabled)
	}
}

// createIPPool creates an IP pool using the specified CIDR.  This
// method is a no-op if the pool already exists.
func createIPPool(ctx context.Context, client client.Interface, cidr *cnet.IPNet, poolName, ipipModeName string, isNATOutgoingEnabled bool) {
	version := cidr.Version()
	var ipipMode api.IPIPMode

	switch strings.ToLower(ipipModeName) {
	case "", "off", "never":
		ipipMode = api.IPIPModeNever
	case "crosssubnet", "cross-subnet":
		ipipMode = api.IPIPModeCrossSubnet
	case "always":
		ipipMode = api.IPIPModeAlways
	default:
		log.Errorf("Unrecognized IPIP mode specified in CALICO_IPV4POOL_IPIP '%s'", ipipModeName)
		terminate()
	}

	pool := &api.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: poolName,
		},
		Spec: api.IPPoolSpec{
			CIDR:        cidr.String(),
			NATOutgoing: isNATOutgoingEnabled,
			IPIPMode:    ipipMode,
		},
	}

	log.Infof("Ensure default IPv%d pool is created. IPIP mode: %s", version, ipipModeName)

	// Create the pool.  There is a small chance that another node may
	// beat us to it, so handle the fact that the pool already exists.
	if _, err := client.IPPools().Create(ctx, pool, options.SetOptions{}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
			log.WithError(err).Errorf("Failed to create default IPv%d IP pool: %s", version)
			terminate()
		}
	} else {
		log.Infof("Created default IPv%d pool (%s) with NAT outgoing %t. IPIP mode: %s",
			version, cidr, isNATOutgoingEnabled, ipipModeName)
	}
}
