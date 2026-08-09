# ADR 0002: Single-member embedded etcd

- Status: Superseded by [ADR 0011](0011-kubeadm-on-pi.md)
- Date: 2026-08-08

## Decision

Initialize K3s with `cluster-init: true` so it uses embedded etcd. Store K3s data
on the SSD, compress snapshots every six hours, retain fourteen locally, and
copy snapshots encrypted off-device at least daily. Preserve the matching K3s
version and server token for restore.

## Rationale and consequences

Starting with etcd avoids a later SQLite-to-etcd transition and supports a
future three-server topology. One member is not HA and etcd is write-intensive;
unhealthy, non-SSD, or incorrectly mounted storage is a hard preflight failure.
K3s uninstall is destructive and is not a rollback.

## Supersession

The single-member etcd and SSD requirements remain, but kubeadm now owns a
stacked etcd static Pod instead of K3s embedded etcd. Snapshot and restore
procedures must follow the pinned upstream Kubernetes/etcd versions in ADR 0011.
