# Full Pi rebuild — Draft / unverified

Follow `docs/runbooks/disaster-recovery.md`. Inventory/revalidate hardware first,
keep Cloudflare public routing disabled, reinstall the exact compatible
containerd and upstream Kubernetes components from verified artifacts, then
restore rather than improvising state. Reconcile desired state only after
etcd/PKI/API-encryption/age recovery and policy checks. Preserve old media
read-only until the restore is accepted.

The fresh cluster does not recover media merely because Git and etcd are
healthy. Verify the separate data filesystem/device and its checksums, recover
originals and metadata from the encrypted off-device backup if necessary,
recreate only the reviewed static volume binding, and prove the serving mount is
derivative-only/read-only before any naranjo release is resumed. Regenerate
delivery derivatives rather than treating an etcd snapshot as their backup.

Do not use `kubeadm reset` as preparation or rollback. If old media contains a
stale K3s installation, do not run its uninstall script during migration.
Destruction of the failed disk/cluster requires a separate explicit decision
after backup and restore evidence.
