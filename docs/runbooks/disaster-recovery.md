# Disaster recovery — Draft / unverified

Initial targets are six-hour Kubernetes-state RPO and four-hour RTO. They are
aspirational until a timed restore drill succeeds.

## Required protected material

- exact compatible upstream Kubernetes, containerd, CRI, etcd-recovery, and
  control-plane image artifacts/configuration with verified provenance;
- encrypted etcd snapshot copied off-device at least daily;
- Kubernetes PKI and API-encryption configuration/key material stored encrypted
  and separately from the snapshot;
- Git desired state and immutable image evidence;
- encrypted, checksum-verified off-device media originals and publication
  metadata, stored independently from the Pi data filesystem;
- separately encrypted protected legacy wallet/signing or anonymity identity
  material when locally present, plus a content-neutral archive manifest and
  tested restore result that disclose no values;
- Cloudflare/GitHub recovery factors stored separately;
- future application/database backups (etcd is not an application-data backup).

The etcd snapshot contains Kubernetes API state only. It does **not** contain
media originals, delivery derivatives, publication manifests, or checksums.
Originals and metadata require their own encrypted off-device backup and timed
restore; delivery derivatives are regenerated unless explicitly classified for
backup. The installed six-hour timer is
`website-infrastructure-etcd-snapshot.timer`. Confirm it with
`sudo systemctl status website-infrastructure-etcd-snapshot.timer`, and run the
read-only integrity/endpoint check with
`sudo /usr/local/sbin/website-infrastructure-etcd-snapshot --check`. To create a
snapshot immediately, use
`sudo env CONFIRM_ETCD_SNAPSHOT=create-reviewed-stacked-etcd-snapshot /usr/local/sbin/website-infrastructure-etcd-snapshot --apply`.
Local snapshots are root-owned mode `0600` files in
`/var/backups/kubernetes/etcd`; fourteen are retained. The timer does not
encrypt, transmit, or verify an off-device copy. An operator must perform that
external step separately and record the snapshot hash, destination, encryption
method, copy verification, and time without exposing snapshot content or keys.

## Restore order

1. Keep public DNS/Tunnel routing disabled and verify replacement hardware/SSD.
2. Install exact compatible containerd/Kubernetes components; restore protected
   PKI, API-encryption configuration, and the stacked-etcd snapshot with the
   pinned etcd tool. Restore the reviewed CNI/kube-proxy dataplane, then prove
   Secret encryption, member/API/node/CoreDNS health, PSA, audit, and policy
   enforcement.
3. Restore controllers and anonymous Flux sync. Restore or recreate the exact
   runtime Secrets through the owner custody procedure before reconciling their
   consumers; no Git decryption identity is required.
4. Reconcile prerequisites with releases suspended. Verify RBAC, default deny,
   quotas, signatures, and digests. Before any media binding, verify the
   preserved/restored data filesystem identity and checksums, recreate the exact
   reviewed static binding, and prove the workload can see delivery derivatives
   read-only but not originals/staging/metadata.
5. Exercise internal Service/tunnel isolation, then enable the public release and
   route only after all negative tests pass.

Record start/end, versions, snapshot age/hash, non-sensitive evidence, failures,
and achieved RPO/RTO. Record the media restore and derivative-regeneration drill
separately; success in one stream is not evidence for the other. A backup is not
accepted until both applicable drills complete.

The protected legacy archive is a third, independent recovery stream. An etcd
or media restore does not restore it, and a cluster rebuild must not mount,
repair, upgrade, or start it. Preserve its verified storage binding in place or
restore a tested copy only onto isolated storage. Follow
[the protected legacy archive runbook](protected-legacy-archive.md); runtime
reactivation requires a new decision and is never an automatic disaster-
recovery step.
