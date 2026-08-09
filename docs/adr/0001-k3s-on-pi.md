# ADR 0001: K3s on the Raspberry Pi

- Status: Superseded by [ADR 0011](0011-kubeadm-on-pi.md)
- Date: 2026-08-08

## Context

The production target is one Raspberry Pi 5 whose usable capacity and
persistent storage must be reviewed before installation. A multi-node
environment is deferred. We need Kubernetes primitives and GitOps without
maintaining a larger distribution.

## Decision

Run one K3s server on the Pi, with K3s state on the SSD. Use Flannel VXLAN and
K3s's network-policy controller. Disable packaged Traefik and ServiceLB. Enable
secrets encryption at rest. Do not create an environment nesting directory.

## Consequences

The system has no node-level high availability. Two replicas protect rolling
updates and process failure only. A future environment is built separately and
reconciled from Git; this node is not converted in place.

## Supersession

This record preserves the original decision. Before K3s was installed, the
operator chose upstream Kubernetes through kubeadm in order to own the complete
control-plane and node configuration. ADR 0011 is authoritative.
