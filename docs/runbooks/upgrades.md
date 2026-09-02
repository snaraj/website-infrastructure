# Upgrade procedure — Draft / unverified

Use one component/credential boundary at a time. Read current upstream release
and security notes, verify checksums/digests/action commits/provider schema and
Free entitlement, update pins in a feature branch, render/test/scan, and retain a
compatible rollback artifact.

For a website image change, increment only that site's committed VERSION in the
same PR. Use a v0 PATCH for a compatible fix and a v0 MINOR for a compatible
feature while its production gate remains `no`. Shared publication/verification
tooling changes require both versions to increase. Production graduation is a
separate reviewed change that atomically switches the selected gate in
`release-policy.env` to `yes` and moves its VERSION to `1.0.0` or later; never
reuse or manually move an existing OCI version tag.

Before a Kubernetes upgrade, create and verify a fresh snapshot and its
off-device copy exactly as [disaster recovery](disaster-recovery.md)
prescribes; that runbook owns the commands, timer, retention, and the external
step the timer does not perform. Protect the current PKI/API-encryption material;
record containerd, kubeadm, kubelet, kubectl, control-plane image, CNI, and kube-proxy
versions/configuration; and test recovery access. Follow upstream kubeadm's
one-minor-at-a-time order and version-skew policy. Revalidate CNI/kube-proxy
compatibility with the actual VPN/tunnel interfaces, firewall, and
policy-routing state before changing either dataplane component. Before
Flux/provider/Helm or static policy changes, render the exact
CRDs/controllers/manifests and test deny fixtures. Before base/runtime image
changes, rebuild both platforms
and repeat signature/SBOM/provenance checks.

Before any future media-storage, kernel, runtime, kubelet, filesystem, or mount
change, verify the separate encrypted originals/metadata backup and its checksum,
keep public media disabled, and prove the preserved data filesystem remains the
expected device and read-only serving boundary after reboot. An etcd snapshot
does not provide this rollback.

Observe one rollout and failure domain before the next. `kubeadm reset` is not
rollback; use the documented compatible package/image/configuration and snapshot
recovery path.
