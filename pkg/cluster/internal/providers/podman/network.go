/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package podman

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"sigs.k8s.io/kind/pkg/errors"
	"sigs.k8s.io/kind/pkg/exec"
)

// By default podman creates one network per cluster, this allows to use
// DNS to resolve container names and use the corresponding IP family, since
// podman does not support dual stack containers yet in the `podman network`
// However, podman uses CNI, and it is possible to creates a CNI config file
// manually for podman to provide dual-stack if necessary.
//
// For now this also makes it easier for apps to join the same network, and
// leaves users with complex networking desires to create and manage their own
// networks.
const fixedNetworkPrefix = "kind"

// ensureNetwork creates a new network with the prefix + cluster name
func ensureNetwork(name string, isIPv6 bool) error {
	networkName := fmt.Sprintf("%s-%s", fixedNetworkPrefix, name)
	// TODO: revisit for dual stack
	subnet := ""
	if isIPv6 {
		// generate unique subnet per network based on the name
		// obtained from the ULA fc00::/8 range
		// Make N attempts with "probing" in case we happen to collide
		subnet = generateULASubnetFromName(networkName, 0)
	}
	err := createNetwork(networkName, subnet)
	if err == nil {
		// Success!
		return nil
	}

	// Only continue if the error is because of the subnet range
	// is already allocated
	if !isPoolOverlapError(err) {
		return err
	}

	// keep trying for ipv6 subnets
	const maxAttempts = 5
	for attempt := int32(1); attempt < maxAttempts; attempt++ {
		subnet := generateULASubnetFromName(networkName, attempt)
		err = createNetwork(networkName, subnet)
		if err == nil {
			// success!
			return nil
		} else if !isPoolOverlapError(err) {
			// unknown error ...
			return err
		}
	}
	return errors.New("exhausted attempts trying to find a non-overlapping subnet")

}

func createNetwork(name, subnet string) error {
	if subnet != "" {
		return exec.Command("podman", "network", "create", "-d=bridge",
			"--subnet", subnet, name).Run()
	}
	return exec.Command("podman", "network", "create", "-d=bridge",
		name).Run()
}

// delete network if exists, otherwise do nothing
func deleteNetwork(name string) error {
	networkName := fmt.Sprintf("%s-%s", fixedNetworkPrefix, name)
	if err := exec.Command("podman", "network", "inspect", networkName).Run(); err != nil {
		return nil
	}
	return exec.Command("podman", "network", "rm", networkName).Run()
}

func isPoolOverlapError(err error) bool {
	rerr := exec.RunErrorForError(err)
	return rerr != nil &&
		(strings.Contains(string(rerr.Output), "is being used by a network interface") ||
			strings.Contains(string(rerr.Output), "is already being used by a cni configuration"))
}

// generateULASubnetFromName generate an IPv6 subnet based on the
// name and Nth probing attempt
func generateULASubnetFromName(name string, attempt int32) string {
	ip := make([]byte, 16)
	ip[0] = 0xfc
	ip[1] = 0x00
	h := sha1.New()
	_, _ = h.Write([]byte(name))
	_ = binary.Write(h, binary.LittleEndian, attempt)
	bs := h.Sum(nil)
	for i := 2; i < 8; i++ {
		ip[i] = bs[i]
	}
	subnet := &net.IPNet{
		IP:   net.IP(ip),
		Mask: net.CIDRMask(64, 128),
	}
	return subnet.String()
}
