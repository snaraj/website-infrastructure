# Destructive uninstall safeguards

`kubeadm reset` removes local cluster state, does not fully clean CNI state or
host networking, and is never an upgrade or rollback. No repository script may
invoke it as routine recovery. Before any separately approved decommission:

- identify the exact node/data directory and prove it is not a broader mount;
- capture a fresh verified stacked-etcd snapshot off-device;
- preserve Kubernetes PKI/API-encryption material, age/tunnel credentials, and
  application-aware data backups separately;
- complete a restore drill on replacement media;
- disable public routing and revoke runtime credentials deliberately;
- obtain explicit approval naming the target and irrecoverable effects.

Prefer powering down or moving the old SSD to protected read-only storage while
the replacement is validated. Never paste or casually suggest the upstream
reset command as troubleshooting. If discovery finds a stale K3s installation,
do not run its uninstall script; first establish whether this is a migration,
capture its compatible snapshot/token/configuration, and approve the exact
destructive boundary separately.
