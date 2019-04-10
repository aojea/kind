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

package node

// these are well known paths within the node image
const (
	// TODO: refactor kubernetesVersionLocation to a common internal package
	kubernetesVersionLocation      = "/kind/version"
	defaultCNIManifestLocation     = "/kind/manifests/default-cni.yaml"
	defaultCNIManifestLocationIPv6 = "/kind/manifests/default-cni-ipv6.yaml"
	// TODO: add dual stack location
)

/*
The default CNI manifest and images are from calico currently.

To update these:
 - find the latest stable release at https://github.com/projectcalico/calico
 - copy the manifest from https://docs.projectcalico.org/v3.6/getting-started/kubernetes/installation/calico
 to the folder ./cni/ and modify and rename it accordenly
 *Important* Kind uses predefined subnet ranges, see pkg/cluster/internal/kubeadm/config.go
 (TODO) calico-ipv4-ipv6.yaml for dual stack deployements.
 - update the defaultCNIManifests map to include the manifests files
 - update the defaultCNIImages array to include the images in the manifest
 - update the comment below with the release URL

Current version: https://github.com/projectcalico/calico/releases/tag/v3.6.1

*/

var defaultCNIImages = []string{"calico/cni:v3.6.1", "calico/node:v3.6.1", "calico/kube-controllers:v3.6.1", "calico/ctl:v3.6.1"}
var defaultCNIManifests = map[string]string{
	defaultCNIManifestLocation:     "calico.yaml",
	defaultCNIManifestLocationIPv6: "calico-ipv6.yaml",
	// TODO: add dual stack manifest
}

// We pull in the sources with go-bindata
//go:generate go-bindata -nometadata -mode=0666 -pkg=$GOPACKAGE -o=cni_sources.go -prefix=cni cni
