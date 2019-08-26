// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package ipam

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

const (
	blockSize = 64
)

type ipVersion struct {
	Number            int
	TotalBits         int
	BlockPrefixLength int
	BlockPrefixMask   net.IPMask
}

var ipv4 ipVersion = ipVersion{
	Number:            4,
	TotalBits:         32,
	BlockPrefixLength: 24,
	BlockPrefixMask:   net.CIDRMask(24, 32),
}

var ipv6 ipVersion = ipVersion{
	Number:            6,
	TotalBits:         128,
	BlockPrefixLength: 122,
	BlockPrefixMask:   net.CIDRMask(122, 128),
}

// Wrap the backend AllocationBlock struct so that we can
// attach methods to it.
type allocationBlock struct {
	*model.AllocationBlock
}

//zk
func newBlock(cidr cnet.IPNet) (allocationBlock, error) {
	b := model.AllocationBlock{}
	//zk Gets the last bit of IP
	k := strings.Split(cidr.String(), "/")[0]
	/*suffix, err := getsuffix()
	if err == nil {
		return allocationBlock{&b}, err
	}*/
	s, err := strconv.Atoi(strings.Split(k, ".")[3])
	if err != nil {
		return allocationBlock{&b}, fmt.Errorf("parse string to int err in function newBlock")
	}
	/*suff, err := strconv.Atoi(suffix)
	if err != nil {
		return allocationBlock{&b}, fmt.Errorf("parse suffix string to int err in function newBlock")
	}*/
	//zk Get the available length
	//blocksize := (suff - s + 1)
	blocksize := (250 - s + 1)
	b.Allocations = make([]*int, blocksize)
	b.Unallocated = make([]int, blocksize)
	b.StrictAffinity = false
	b.CIDR = cidr

	// Initialize unallocated ordinals.
	for i := 0; i < blocksize; i++ {
		b.Unallocated[i] = i
	}

	return allocationBlock{&b}, nil
}

func (b *allocationBlock) autoAssign(
	num int, handleID *string, host string, attrs map[string]string, affinityCheck bool) ([]cnet.IP, error) {

	// Determine if we need to check for affinity.
	checkAffinity := b.StrictAffinity || affinityCheck
	if checkAffinity && b.Affinity != nil && !hostAffinityMatches(host, b.AllocationBlock) {
		// Affinity check is enabled but the host does not match - error.
		s := fmt.Sprintf("Block affinity (%s) does not match provided (%s)", *b.Affinity, host)
		return nil, errors.New(s)
	} else if b.Affinity == nil {
		log.Warn("Attempting to assign IPs from block with no affinity: %v", b)
		if checkAffinity {
			// If we're checking strict affinity, we can't assign from a block with no affinity.
			return nil, fmt.Errorf("Attempt to assign from block %v with no affinity", b.CIDR)
		}
	}

	// Walk the allocations until we find enough addresses.
	ordinals := []int{}
	for len(b.Unallocated) > 0 && len(ordinals) < num {
		ordinals = append(ordinals, b.Unallocated[0])
		b.Unallocated = b.Unallocated[1:]
	}

	// Create slice of IPs and perform the allocations.
	ips := []cnet.IP{}
	for _, o := range ordinals {
		attrIndex := b.findOrAddAttribute(handleID, attrs)
		b.Allocations[o] = &attrIndex
		ips = append(ips, incrementIP(cnet.IP{b.CIDR.IP}, big.NewInt(int64(o))))
	}

	log.Debugf("Block %s returned ips: %v", b.CIDR.String(), ips)
	return ips, nil
}

func (b *allocationBlock) assign(address cnet.IP, handleID *string, attrs map[string]string, host string) error {
	if b.StrictAffinity && b.Affinity != nil && !hostAffinityMatches(host, b.AllocationBlock) {
		// Affinity check is enabled but the host does not match - error.
		return errors.New("Block host affinity does not match")
	} else if b.Affinity == nil {
		log.Warn("Attempting to assign IP from block with no affinity: %v", b)
		if b.StrictAffinity {
			// If we're checking strict affinity, we can't assign from a block with no affinity.
			return fmt.Errorf("Attempt to assign from block %v with no affinity", b.CIDR)
		}
	}

	// Convert to an ordinal.
	ordinal, err := ipToOrdinal(address, *b)
	if err != nil {
		return err
	}

	// Check if already allocated.
	if b.Allocations[ordinal] != nil {
		return errors.New("Address already assigned in block")
	}

	// Set up attributes.
	attrIndex := b.findOrAddAttribute(handleID, attrs)
	b.Allocations[ordinal] = &attrIndex

	// Remove from unallocated.
	for i, unallocated := range b.Unallocated {
		if unallocated == ordinal {
			b.Unallocated = append(b.Unallocated[:i], b.Unallocated[i+1:]...)
			break
		}
	}
	return nil
}

// hostAffinityMatches checks if the provided host matches the provided affinity.
func hostAffinityMatches(host string, block *model.AllocationBlock) bool {
	return *block.Affinity == "host:"+host
}

func (b allocationBlock) numFreeAddresses() int {
	return len(b.Unallocated)
}

func (b allocationBlock) empty() bool {
	//zk
	//return b.numFreeAddresses() == blockSize
	return b.numFreeAddresses() == len(b.Allocations)
}

func (b *allocationBlock) release(addresses []cnet.IP) ([]cnet.IP, map[string]int, error) {
	// Store return values.
	unallocated := []cnet.IP{}
	countByHandle := map[string]int{}

	// Used internally.
	var ordinals []int
	delRefCounts := map[int]int{}
	attrsToDelete := []int{}

	// Determine the ordinals that need to be released and the
	// attributes that need to be cleaned up.
	for _, ip := range addresses {
		// Convert to an ordinal.
		ordinal, err := ipToOrdinal(ip, *b)
		if err != nil {
			return nil, nil, err
		}

		// Check if allocated.
		attrIdx := b.Allocations[ordinal]
		if attrIdx == nil {
			log.Debugf("Asked to release address that was not allocated")
			unallocated = append(unallocated, ip)
			continue
		}
		ordinals = append(ordinals, ordinal)

		// Increment referece counting for attributes.
		cnt := 1
		if cur, exists := delRefCounts[*attrIdx]; exists {
			cnt = cur + 1
		}
		delRefCounts[*attrIdx] = cnt

		// Increment count of addresses by handle if a handle
		// exists.
		handleID := b.Attributes[*attrIdx].AttrPrimary
		if handleID != nil {
			handleCount := 0
			if count, ok := countByHandle[*handleID]; !ok {
				handleCount = count
			}
			handleCount += 1
			countByHandle[*handleID] = handleCount
		}
	}

	// Handle cleaning up of attributes.  We do this by
	// reference counting.  If we're deleting the last reference to
	// a given attribute, then it needs to be cleaned up.
	refCounts := b.attributeRefCounts()
	for idx, refs := range delRefCounts {
		if refCounts[idx] == refs {
			attrsToDelete = append(attrsToDelete, idx)
		}
	}
	if len(attrsToDelete) != 0 {
		log.Debugf("Deleting attributes: %v", attrsToDelete)
		b.deleteAttributes(attrsToDelete, ordinals)
	}

	// Release requested addresses.
	for _, ordinal := range ordinals {
		b.Allocations[ordinal] = nil
		b.Unallocated = append(b.Unallocated, ordinal)
	}
	return unallocated, countByHandle, nil
}

func (b *allocationBlock) deleteAttributes(delIndexes, ordinals []int) {
	newIndexes := make([]*int, len(b.Attributes))
	newAttrs := []model.AllocationAttribute{}
	y := 0 // Next free slot in the new attributes list.
	for x := range b.Attributes {
		if !intInSlice(x, delIndexes) {
			// Attribute at x is not being deleted.  Build a mapping
			// of old attribute index (x) to new attribute index (y).
			log.Debugf("%d in %s", x, delIndexes)
			newIndex := y
			newIndexes[x] = &newIndex
			y += 1
			newAttrs = append(newAttrs, b.Attributes[x])
		}
	}
	b.Attributes = newAttrs
	//zk
	// Update attribute indexes for all allocations in this block.
	//for i := 0; i < blockSize; i++ {
	for i := 0; i < len(b.Allocations); i++ {
		if b.Allocations[i] != nil {
			// Get the new index that corresponds to the old index
			// and update the allocation.
			newIndex := newIndexes[*b.Allocations[i]]
			b.Allocations[i] = newIndex
		}
	}
}

func (b allocationBlock) attributeRefCounts() map[int]int {
	refCounts := map[int]int{}
	for _, a := range b.Allocations {
		if a == nil {
			continue
		}

		if count, ok := refCounts[*a]; !ok {
			// No entry for given attribute index.
			refCounts[*a] = 1
		} else {
			refCounts[*a] = count + 1
		}
	}
	return refCounts
}

func (b allocationBlock) attributeIndexesByHandle(handleID string) []int {
	indexes := []int{}
	for i, attr := range b.Attributes {
		if attr.AttrPrimary != nil && *attr.AttrPrimary == handleID {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

func (b *allocationBlock) releaseByHandle(handleID string) int {
	attrIndexes := b.attributeIndexesByHandle(handleID)
	log.Debugf("Attribute indexes to release: %v", attrIndexes)
	if len(attrIndexes) == 0 {
		// Nothing to release.
		log.Debugf("No addresses assigned to handle '%s'", handleID)
		return 0
	}

	// There are addresses to release.
	ordinals := []int{}
	var o int
	//for o = 0; o < blockSize; o++ {
	for o = 0; o < len(b.Allocations); o++ {
		// Only check allocated ordinals.
		if b.Allocations[o] != nil && intInSlice(*b.Allocations[o], attrIndexes) {
			// Release this ordinal.
			ordinals = append(ordinals, o)
		}
	}

	// Clean and reorder attributes.
	b.deleteAttributes(attrIndexes, ordinals)

	// Release the addresses.
	for _, o := range ordinals {
		b.Allocations[o] = nil
		b.Unallocated = append(b.Unallocated, o)
	}
	return len(ordinals)
}

func (b allocationBlock) ipsByHandle(handleID string) []cnet.IP {
	ips := []cnet.IP{}
	attrIndexes := b.attributeIndexesByHandle(handleID)
	var o int
	//zk
	//for o = 0; o < blockSize; o++ {
	for o = 0; o < len(b.Allocations); o++ {
		if b.Allocations[o] != nil && intInSlice(*b.Allocations[o], attrIndexes) {
			ip := ordinalToIP(o, b)
			ips = append(ips, ip)
		}
	}
	return ips
}

func (b allocationBlock) attributesForIP(ip cnet.IP) (map[string]string, error) {
	// Convert to an ordinal.
	ordinal, err := ipToOrdinal(ip, b)
	if err != nil {
		return nil, err
	}

	// Check if allocated.
	attrIndex := b.Allocations[ordinal]
	if attrIndex == nil {
		return nil, errors.New(fmt.Sprintf("IP %s is not currently assigned in block", ip))
	}
	return b.Attributes[*attrIndex].AttrSecondary, nil
}

func (b *allocationBlock) findOrAddAttribute(handleID *string, attrs map[string]string) int {
	logCtx := log.WithField("attrs", attrs)
	if handleID != nil {
		logCtx = log.WithField("handle", *handleID)
	}
	attr := model.AllocationAttribute{handleID, attrs}
	for idx, existing := range b.Attributes {
		if reflect.DeepEqual(attr, existing) {
			log.Debugf("Attribute '%+v' already exists", attr)
			return idx
		}
	}

	// Does not exist - add it.
	logCtx.Debugf("New allocation attribute: %#v", attr)
	attrIndex := len(b.Attributes)
	b.Attributes = append(b.Attributes, attr)
	return attrIndex
}

func getlocalmask() (net.IPMask, error) {
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
			//fmt.Println(ipnet.IP.String())
			//fmt.Println(ipnet.Mask.String())
			//_, cidr, err := n.ParseCIDR(ipnet.String())
			//if err != nil {
			//		return "", fmt.Errorf("get br0 cidr failed %s", err)
			//}
			return ipnet.Mask, nil
		}

	}
	return nil, fmt.Errorf("get %s localmask failed %s", "br0")
}

func getsuffix() (suffix string, err error) {
	data, err := ioutil.ReadFile("/var/lib/grid/suffix")
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return empty string.
			log.Info("File /var/lib/grid/suffix does not exist")
			return "", fmt.Errorf("%s", "File /var/lib/grid/suffix does not exist")
		}
		log.WithError(err).Error("Failed to read /var/lib/grid/suffix")
		return "", err
	}
	return strings.TrimSpace(string(data)), fmt.Errorf("%s", "Failed to read /var/lib/grid/suffix")
}

func getBlockCIDRForAddress(addr cnet.IP) cnet.IPNet {
	var mask net.IPMask
	var err error
	if addr.Version() == 6 {
		// This is an IPv6 address.
		mask = ipv6.BlockPrefixMask
	} else {
		mask, err = getlocalmask()
		if err != nil {
			mask = ipv4.BlockPrefixMask
		}
		// This is an IPv4 address.
		//mask = ipv4.BlockPrefixMask
	}
	masked := addr.Mask(mask)
	return cnet.IPNet{net.IPNet{IP: masked, Mask: mask}}
}

func getIPVersion(ip cnet.IP) ipVersion {
	if ip.To4() == nil {
		return ipv6
	}
	return ipv4
}

func largerThanOrEqualToBlock(blockCIDR cnet.IPNet) bool {
	ones, _ := blockCIDR.Mask.Size()
	ipVersion := getIPVersion(cnet.IP{blockCIDR.IP})
	return ones <= ipVersion.BlockPrefixLength
}

func intInSlice(searchInt int, slice []int) bool {
	for _, v := range slice {
		if v == searchInt {
			return true
		}
	}
	return false
}

func ipToInt(ip cnet.IP) *big.Int {
	if ip.To4() != nil {
		return big.NewInt(0).SetBytes(ip.To4())
	} else {
		return big.NewInt(0).SetBytes(ip.To16())
	}
}

func intToIP(ipInt *big.Int) cnet.IP {
	ip := cnet.IP{net.IP(ipInt.Bytes())}
	return ip
}

func incrementIP(ip cnet.IP, increment *big.Int) cnet.IP {
	sum := big.NewInt(0).Add(ipToInt(ip), increment)
	return intToIP(sum)
}

func ipToOrdinal(ip cnet.IP, b allocationBlock) (int, error) {
	ip_int := ipToInt(ip)
	base_int := ipToInt(cnet.IP{b.CIDR.IP})
	ord := big.NewInt(0).Sub(ip_int, base_int).Int64()
	//zk
	//if ord < 0 || ord >= blockSize {
	if ord < 0 || ord >= int64(len(b.Allocations)) {
		return 0, fmt.Errorf("IP %s not in block %s", ip, b.CIDR)
	}
	return int(ord), nil
}

func ordinalToIP(ord int, b allocationBlock) cnet.IP {
	sum := big.NewInt(0).Add(ipToInt(cnet.IP{b.CIDR.IP}), big.NewInt(int64(ord)))
	return intToIP(sum)
}
