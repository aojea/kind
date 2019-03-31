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

package cni

import (
	"github.com/pkg/errors"
	"sigs.k8s.io/kind/pkg/build/cni/sources"
)

// Plugin contains the CNI installation manifest, the images needed
// and the CNI capabilities (IPv4, IPv6, ...)
type Plugin struct {
	Manifest     string
	Images       []string
	Capabilities string
}

// cniManifests contains the cni plugin reference name and the path to the installation manifest
var cniManifests = map[string]Plugin{
	"weave": {
		Manifest:     "cniplugins/weave-daemonset-k8s-1.8.yaml",
		Images:       []string{"weaveworks/weave-kube:2.5.1", "weaveworks/weave-npc:2.5.1"},
		Capabilities: "ipv4",
	},
	"calico": {
		Manifest:     "cniplugins/calico.yaml",
		Images:       []string{"calico/cni:v3.6.1", "calico/node:v3.6.1", "calico/kube-controllers:v3.6.1", "calico/ctl:v3.6.1"},
		Capabilities: "ipv4",
	},
	"calico-ipv6": {
		Manifest:     "cniplugins/calico-ipv6.yaml",
		Images:       []string{"calico/cni:v3.6.1", "calico/node:v3.6.1", "calico/kube-controllers:v3.6.1", "calico/ctl:v3.6.1"},
		Capabilities: "ipv6",
	},
}

// GetPlugin returns the manifest and images used by the CNI selected
func GetPlugin(cni string) (cniPlugin Plugin, err error) {
	cniPlugin, ok := cniManifests[cni]
	if !ok {
		return cniPlugin, errors.Errorf("no CNI plugin available with name: %s", cni)
	}
	data, err := sources.Asset(cniPlugin.Manifest)
	if err != nil {
		return cniPlugin, errors.Errorf("no CNI plugin manifest available for: %s", cni)
	}
	cniPlugin.Manifest = string(data)
	return cniPlugin, nil
}
