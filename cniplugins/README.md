## cniplugins/node

Roughly this image is [the base image](./../base), with the addition of:
 - installing the Kubernetes packages / binaries
 - placing the Kubernetes and CNI docker images in `/kind/images/*.tar`
 - placing a file in `/kind/version` containing the Kubernetes semver
 - placing a CNI installation manifest in  `/kind/manifests/default-cni.yaml`

See [`node-image`][node-image.md] for more design details.

[pkg/build/node_image.go]: ./../../pkg/build/node/node.go
[node-image.md]: https://kind.sigs.k8s.io/docs/design/node-image
