# Static storage policy and future local-volume posture

## Present-state truth

This is a repository-side Conftest control, not runtime admission. Kyverno is
retired and no webhook evaluates these rules in the cluster. The committed
Rego and hostile fixtures still fail closed before merge: unknown volume
sources, network storage, `hostPath`, unenumerated classes or provisioners,
path traversal, missing node affinity, data-source imports, CSI drivers, and
degenerate/null shapes are rejected.

The sanitized live inventory currently contains only an older, unbound
`hostPath` PersistentVolume and no PVC or StorageClass. That object is
historical runtime residue, not evidence that the reviewed local-volume design
is active. This repository must not claim storage activation until the
discovery, binding, restore, and live-validation evidence in ADR 0012 exists.

## Reviewed target posture

Future usage-export storage has one closed design:

- upstream static `local` PersistentVolume type, never `hostPath`;
- root `/mnt/local-pie-ssd`;
- StorageClass `local-pie-ssd` with
  `kubernetes.io/no-provisioner`;
- `ReadWriteOnce` access and `Retain` reclaim behavior;
- exact node affinity, a local block-device mount, no remote or nested mount,
  and no textual path traversal;
- no CSI driver, dynamic provisioner, volume-attributes class, data-source
  import, mount options, or alternate storage root.

The Naranjo Helm reconciler may receive PVC lifecycle authority only. It never
gets PV, StorageClass, node, or host authority. Permanent PV/StorageClass and
host preparation stay bootstrap/operator owned; tenant reconciliation cannot
create, retarget, delete, or widen them.

## Static control

`policies/conftest/kubernetes.rego` is the only executable policy source for
this boundary. Its owner-selected enumeration is:

| Field | Exact value |
| --- | --- |
| StorageClass | `local-pie-ssd` |
| Provisioner | `kubernetes.io/no-provisioner` |
| Local root | `/mnt/local-pie-ssd` |
| CSI drivers | empty |
| VolumeAttributesClass names | empty |
| PersistentVolume source types | `local`, with `csi` syntactically recognized but denied while the driver set is empty |

PersistentVolume source fields are derived by subtracting the exact known
non-source fields. A source Kubernetes adds later is therefore denied until it
is reviewed. All nested object reads are type checked so null, scalar, list,
or otherwise malformed values cannot make a Rego deny body disappear.

The workload-volume control is separate and broader: every Pod template may
use only `emptyDir`, `configMap`, `secret`, `projected`, or
`downwardAPI`. Claims, CSI, cloud disks, network filesystems, multi-source
entries, and unknown future fields fail closed.

## Verification

Run:

```sh
scripts/test-policy-fixtures.sh
python3 -B -m unittest tests.security.test_storage_exposure_policy_contract
python3 -B scripts/validate_repository.py kubernetes
```

The negative corpus includes NFS, iSCSI, cloud CSI, hostPath, traversal,
multiple/absent sources, unbounded or malformed node affinity, unknown class
and provisioner, data-source imports, VolumeAttributesClass references, null
objects, and unknown Pod volume sources. Each fixture has an exact expected
Conftest attribution; a generic rejection by an unrelated rule does not count.

## Runtime closure still required

Manifest checks cannot prove what a node path really mounts. Activation still
requires the ADR 0012 evidence: a local physical block device; reviewed
filesystem and capacity; UUID-bound mount with `nodev,nosuid,noexec`; no
symlink, bind, nested, network, loop, iSCSI, or NBD escape; backup and restore
drills; preserved SSH/control-plane headroom; exact PV/PVC binding; and live
cross-namespace denial tests. Missing evidence remains a NO-GO.

If live storage diverges, suspend the dependent release and preserve the
volume. Never format, delete, dynamically reprovision, or broaden reconciler
authority as a rollback shortcut.
