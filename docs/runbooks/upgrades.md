# Upgrade procedure — Draft / unverified

Use one component/credential boundary at a time. Read current upstream release
and security notes, verify checksums/digests/action commits/provider schema and
Free entitlement, update pins in a feature branch, render/test/scan, and retain a
compatible rollback artifact.

Before a Kubernetes upgrade, create a fresh local snapshot with
`sudo env CONFIRM_ETCD_SNAPSHOT=create-reviewed-stacked-etcd-snapshot /usr/local/sbin/website-infrastructure-etcd-snapshot --apply`, then run
`sudo /usr/local/sbin/website-infrastructure-etcd-snapshot --check`. Copy that
snapshot encrypted off-device and verify the external copy; the timer does not
perform this external step. Protect the current PKI/API-encryption material;
record containerd, kubeadm, kubelet, kubectl, control-plane image, CNI, and kube-proxy
versions/configuration; and test recovery access. Follow upstream kubeadm's
one-minor-at-a-time order and version-skew policy. Revalidate CNI/kube-proxy
compatibility with the actual VPN/tunnel interfaces, firewall, and
policy-routing state before changing either dataplane component. Before
Flux/provider/Helm/Kyverno changes, render the exact CRDs/controllers/policies
and test deny fixtures. Before base/runtime image changes, rebuild both platforms
and repeat signature/SBOM/provenance checks.

Before any future media-storage, kernel, runtime, kubelet, filesystem, or mount
change, verify the separate encrypted originals/metadata backup and its checksum,
keep public media disabled, and prove the preserved data filesystem remains the
expected device and read-only serving boundary after reboot. An etcd snapshot
does not provide this rollback.

Observe one rollout and failure domain before the next. `kubeadm reset` is not
rollback; use the documented compatible package/image/configuration and snapshot
recovery path.
