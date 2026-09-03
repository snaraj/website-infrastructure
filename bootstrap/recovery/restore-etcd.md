# Stacked-etcd restore — Draft / unverified

Upstream Kubernetes and etcd restore semantics are version-sensitive. Retrieve
the official guidance for the pinned Kubernetes/etcd releases at execution time
and rehearse the exact single-member, stacked-etcd procedure offline. Required
inputs include a hash-verified snapshot, compatible containerd/Kubernetes/etcd
tools, protected `/etc/kubernetes` PKI and configuration, and the API encryption
configuration/key material. Protect these independently from the snapshot.

An etcd snapshot never contains bytes from the proposed local media filesystem.
Do not infer media recovery from a healthy API restore. Keep the data volume
offline or read-only, restore originals/publication metadata from their separate
encrypted backup when needed, verify checksums, and re-establish the reviewed
PV/PVC binding only after API object identity and the physical mount agree.

The local producer writes root-owned mode-`0600` snapshots to
`/var/backups/kubernetes/etcd`; verify the selected file with the exact installed
`etcdutl --write-out=json snapshot status <reviewed-snapshot-path>` before and
after copying it into the isolated restore workspace. Never restore directly
from the live retention directory.

Keep the public Tunnel and Flux releases suspended. Stop kubelet and the static
control-plane Pods through the reviewed procedure, restore with the pinned etcd
restore tool to the reviewed SSD path, update only the exact static-Pod data path
required by that procedure, and restart/verify. Prove member, API, node, CoreDNS,
Pod Security, audit, and API encryption health; prove authorized Secret reads and
unauthorized denial; then create and verify a new snapshot. Restore Flux and
reconcile prerequisites before any application release.

After member/API health is restored, create the new acceptance snapshot with
`sudo env CONFIRM_ETCD_SNAPSHOT=create-reviewed-stacked-etcd-snapshot /usr/local/sbin/website-infrastructure-etcd-snapshot --apply` and confirm all local
snapshots plus the local TLS endpoint with
`sudo /usr/local/sbin/website-infrastructure-etcd-snapshot --check`. Copy the
accepted snapshot encrypted off-device and verify the copy manually; no unit in
this repository transmits backup data.

Never improvise from a different Kubernetes/etcd release or use `kubeadm reset`
as restore. Never paste PKI, encryption keys, snapshot content, kubeconfig, age
identity, or decrypted Secrets into commands that are logged, Git, CI,
documentation, or chat.
