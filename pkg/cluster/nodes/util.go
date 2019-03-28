/*
Copyright 2019 The Kubernetes Authors.

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

package nodes

import (
	"fmt"

	"github.com/pkg/errors"
	"sigs.k8s.io/kind/pkg/cluster/internal/loadbalancer"
)

// GetControlPlaneEndpoint returns two stings with the control plane endpoint per ip family
// in case the cluster has an external load balancer in front of the control-plane nodes,
// otherwise return an empty string.
func GetControlPlaneEndpoint(allNodes []Node) (string, string, error) {
	node, err := ExternalLoadBalancerNode(allNodes)
	if err != nil {
		return "", "", err
	}
	// if there is no external load balancer return the empty string
	if node == nil {
		return "", "", nil
	}
<<<<<<< HEAD

	// get the IP and port for the load balancer
	loadBalancerIP, err := node.IP()
=======
	// gets the IP of the load balancer
	loadBalancerIPv4, loadBalancerIPv6, err := node.IP()
>>>>>>> 3f8f3e1... Add IPv6 support
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to get IPs for node: %s", node.Name())
	}
<<<<<<< HEAD

	return fmt.Sprintf("%s:%d", loadBalancerIP, loadbalancer.ControlPlanePort), nil
=======
	return fmt.Sprintf("%s:%d", loadBalancerIPv4, haproxy.ControlPlanePort), fmt.Sprintf("[%s]:%d", loadBalancerIPv6, haproxy.ControlPlanePort), nil
>>>>>>> 3f8f3e1... Add IPv6 support
}
