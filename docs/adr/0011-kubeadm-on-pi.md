# ADR 0011: Upstream Kubernetes with kubeadm on the Raspberry Pi

- Status: Accepted, implementation and Pi discovery pending
- Date: 2026-08-08
- Supersedes: [ADR 0001](0001-k3s-on-pi.md), [ADR 0002](0002-embedded-etcd.md)

## Context

The production target is one Raspberry Pi 5 whose usable capacity and
persistent storage must be reviewed before installation. The operator chose
full upstream Kubernetes and wants explicit ownership of the runtime, control
plane, networking, security configuration, backups, and upgrades. The host may
also contain protected services, VPN/tunnel interfaces, kill-switch behavior,
firewall rules, and policy routing, which make an assumed network
implementation unsafe.

## Decision

Bootstrap one upstream Kubernetes control-plane node with kubeadm. Use
containerd as the CRI runtime and kubeadm's stacked, single-member etcd static
Pod, with Kubernetes and etcd state proven to reside on the reviewed SSD.
Install and pin kubeadm, kubelet, kubectl, containerd, CRI tooling, and recovery
tools independently. Configure API audit logging, Pod Security admission, and
API encryption at rest explicitly. Register the only node without the default
control-plane `NoSchedule` taint, then verify that exact scheduling contract
before any workload or Flux reconciliation is authorized.

CNI selection and kube-proxy mode are separate discovery gates. kube-proxy
remains installed; eBPF replacement is outside this single-node contract. The
selected CNI must operate with that standard dataplane. Before `kubeadm init`,
inventory the actual kernel, routes, Pod/Service CIDR conflicts,
nftables/iptables behavior, VPN/tunnel interfaces, kill-switch behavior,
firewall, and policy-routing rules. Commit a follow-up decision and stage a
reviewed, immutable CNI artifact locally only after
negative recovery and connectivity tests are defined. No default CNI or
kube-proxy mode is implied here.

Keep Traefik, Ingress/Gateway controllers, NodePort, LoadBalancer, host ports,
host networking, and router forwarding absent. Kind may exercise manifests and
policies on a workstation, but it is local-only: it is not the Pi runtime,
production parity, backup evidence, or a substitute for kubeadm acceptance.

## Consequences

There is no node or control-plane high availability. Two website replicas
protect only process and rolling-update failure. The repository must own
component version skew, containerd configuration, PKI/certificate lifecycle,
etcd snapshot/restore, control-plane static Pod configuration, kubelet
configuration, networking, security flags, and upgrade sequencing.

`kubeadm reset` is destructive, does not fully clean CNI or host networking,
and is not rollback. Recovery uses compatible pinned components, protected PKI
and encryption material, a verified etcd snapshot, Git desired state, and a
tested procedure. A future multi-node environment is built separately and
reconciled from Git rather than converting this node in place.
