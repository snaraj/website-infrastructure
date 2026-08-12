# Storage admission: the enumerated-local-means gate

## The invariant

**Storage is allowed. Externally reachable storage is not, except by the
owner's enumerated means.**

That sentence replaces the earlier stance, which denied `PersistentVolume`,
`PersistentVolumeClaim`, `StorageClass`, and `CSIDriver` by kind and treated the
denial as permanent until a discovery-and-restore review lifted it. The owner
retired that stance by directive on 2026-08-12: the storage kinds are now
admitted, and what the gate withholds is *reachability from outside the
cluster by a means the owner has not named*.

Nothing about the storage rollout itself changed. This gate decides what the
cluster would accept; it does not create a single StorageClass, PersistentVolume,
or claim, and the repository's inventory gates still refuse committed storage
manifests (see "What this gate does not cover" below).

## The enumeration is the allowlist

There are five lists, and together they are the complete set of means by which
storage may exist. They live twice — once as CEL `variables` in
`policies/kyverno/disallow-undiscovered-storage.yaml` (admission) and once as
Rego constants in `policies/conftest/kubernetes.rego` (CI) — and
`tests/security/test_storage_exposure_policy_contract.py` fails if the two
copies ever disagree.

| Enumeration | Today | What adding to it means |
| --- | --- | --- |
| StorageClass identities | `local-pie-ssd` | a second class may exist |
| Provisioners | `kubernetes.io/no-provisioner` | something other than static local provisioning may place bytes |
| CSI drivers | *(empty)* | a driver may be installed, and `csi` volume sources and `VolumeAttributesClass` objects naming it become admissible |
| Local roots | `/mnt/local-pie-ssd` | local volumes may be anchored somewhere else on the node |
| PersistentVolume non-source fields | the nine upstream `PersistentVolumeSpec` fields that are not volume sources | **nothing** — this list exists so that unknown sources are denied by subtraction; adding a real source name here would silently admit it, and the test battery refuses that edit |

Adding a means is a one-line reviewed diff in two files. It is never a policy
rewrite, and it is never a decision an agent takes: the lists are the owner's.

The CSI-driver list being empty is deliberate, not an oversight. Every `csi`
volume source, every `CSIDriver` object, and every `VolumeAttributesClass` is
denied today — the observable behaviour for CSI is exactly what the old
deny-by-kind produced. What changed is the mechanism: admitting a local CSI
provisioner later is an entry in a list rather than a redesign of the gate.

## Two names that now read as history

The policy is still called `disallow-undiscovered-storage` and its storage rule
is still called `disallow-persistent-storage-resources`. Both names describe the
stance this change retires, and both are deliberately retained: five
scripts/validators, the release-readiness policy, and the staged Kyverno install
transaction all key on those identities, and renaming them from this lane would
edit files outside it and collide with pull requests in flight. Read
"undiscovered" as *not in the owner's enumeration*, which is what the gate now
means. Renaming both is queued as a follow-up once the in-flight admission work
has landed.

## The rule set, and why each rule exists

All fourteen checks live in that one Kyverno rule and are mirrored one-for-one
in Rego. Each is proven by its own single-object fixture under
`tests/kubernetes/fixtures/deny/storage-*.yaml`.

| # | Rule | Why |
| --- | --- | --- |
| SR-0 | a `spec` that is present but not a mapping is denied | a rule that goes undefined on a malformed object is an allow |
| SR-1 | a PersistentVolume declares exactly one volume source | zero sources means nothing can be reasoned about; two means a local decoy can sit beside a remote source |
| SR-2 | the source is `local` or `csi` | sources are derived by subtracting the known non-source fields, so `nfs`, `iscsi`, `cephfs`, `glusterfs`, `fc`, `rbd`, `portworxVolume`, `flexVolume`, `azureFile`, `azureDisk`, `awsElasticBlockStore`, `gcePersistentDisk`, `vsphereVolume`, `cinder`, `hostPath` **and every source upstream has not invented yet** fail here with no blocklist to maintain |
| SR-3 | a `csi` source names an enumerated driver | a driver reaches wherever it is written to reach |
| SR-4 | a `local` path is the enumerated root or beneath it | a path elsewhere on the node — control-plane state, an operator home, a mounted share — is a different means |
| SR-5 | a `local` path contains no `..` segment | SR-4 is a prefix test, and `<root>/../../var/lib/etcd` passes a prefix test |
| SR-6 | a `local` volume declares `nodeAffinity.required` | without it one reviewed directory is satisfiable on every node that ever joins |
| SR-7 | a PersistentVolume names an enumerated `storageClassName` | the class is part of the means |
| SR-8 | a StorageClass uses an enumerated provisioner | the provisioner is what actually decides where bytes land |
| SR-9 | a StorageClass is an enumerated identity | the class inventory is reviewed, so a second class cannot appear beside the first |
| SR-10 | a StorageClass declares no `parameters` and no `mountOptions` | that is where a server, export, share, endpoint, or bucket would be named; a static local class needs neither |
| SR-11 | a PersistentVolumeClaim names an enumerated `storageClassName` | an absent class binds through whatever is marked default, so installation order would choose the means |
| SR-12 | a PersistentVolumeClaim declares no `dataSource`/`dataSourceRef` | both import bytes from elsewhere, and `dataSourceRef` can cross namespaces |
| SR-13 | a `CSIDriver` is an enumerated driver | installing a driver installs a whole means at once, before any volume exists |
| SR-14 | a `VolumeAttributesClass` names an enumerated driver | it is the newest object that can point storage at a backend: a driver name plus a free-form parameter map |

`hostPath` is denied outright as a PersistentVolume source rather than
root-checked. Unlike `local` it carries no node-affinity requirement, so the
same path is satisfied on every node, and it can name any directory the kubelet
can see.

## Why it fails closed

Three properties, in order of importance:

1. **Sources are derived, not listed.** The policy enumerates the nine
   `PersistentVolumeSpec` fields that are *not* volume sources and treats
   everything else as a source. An upstream source this repository has never
   heard of is a source by construction and is denied by SR-2. There is no
   blocklist to fall behind.
2. **Every expression denies on absence.** Missing `spec`, missing `path`,
   missing `provisioner`, missing `metadata`, a non-string path, an empty
   enumeration — each evaluates false, and false denies. No input reaches an
   implicit allow.
3. **The empty list denies.** An enumeration with no entries admits nothing.
   The CSI-driver list is empty today and every driver-shaped object is refused
   because of it.

## Coverage is checked separately from behaviour

`kyverno test` reports a resource that falls *outside* a rule's `match` block as
`Pass`, reason `Excluded`. Deleting `PersistentVolume` from the storage rule's
matched kinds leaves the whole Kyverno suite green while an `nfs`
PersistentVolume is admitted — reproduced on this policy before this runbook was
written. Behavioural fixtures cannot see that failure at all.

`tests/security/test_storage_exposure_policy_contract.py` is the structural half.
It derives the covered kinds from the rule's own CEL expressions and requires the
`match` block to equal them, requires the Conftest mirror to key a deny rule on
each of those kinds, and requires the five enumerations to be identical across
both engines. Narrow either half and it goes red while every behavioural row
stays green.

## What this gate does not cover — stated, not papered over

- **A manifest cannot say what a node path really is.** `/mnt/local-pie-ssd`
  could be a bind mount of an NFS client mount, a Samba share, an iSCSI-backed
  filesystem, or a symlink to any of those, and no admission rule can tell.
  The gate proves the *declared* means; that the enumerated root is a local
  block device on a data partition separate from the control-plane filesystem
  is a mount-time and node-level fact, and it belongs to the live evidence that
  ADR 0012 already requires before storage is enabled.
- **Symlinks and bind mounts inside the enumerated root** are equally invisible.
  SR-5 denies textual traversal; it cannot deny a symlink placed on the node.
- **Kinds outside the match block are not evaluated.** `VolumeSnapshot` and its
  CRDs, `CSIStorageCapacity`, and `VolumeAttachment` are not covered — the same
  surface the previous deny-by-kind policy left uncovered. SR-12 removes the
  main reason a snapshot would matter by denying claims that import from one.
- **Pod-level mounting is a different gate.** Admitting the storage objects did
  not admit mounting them: tenant Pods remain bound to the exact ephemeral and
  credential volume allowlist, and workload-level `persistentVolumeClaim`,
  `ephemeral`, `csi`, and network volume sources are still denied. That gate is
  deliberately unchanged here.
- **The repository inventory gate is unchanged.** `scripts/release-gate.sh`
  (`assert_storage_disabled`) and `scripts/validate_repository.py` still refuse
  a committed `PersistentVolume`, `PersistentVolumeClaim`, `StorageClass`,
  `hostPath`, or `local:` under the live Kubernetes roots. This change moves the
  admission gate only; the storage rollout is a separate reviewed change and is
  still blocked on hardware.
- **Nothing is enforced live today.** Kyverno is not installed, so no admission
  webhook evaluates any of this yet. The staged install transaction brings it up
  in Audit first; this policy must be the shape that is promoted, not the
  deny-by-kind it replaced.

## Related decisions

ADR 0012 (heavy-media storage) still describes the storage design and its
evidence requirements, and its "no `hostPath`, local PersistentVolume,
PersistentVolumeClaim, or storage controller is created by this scaffold"
sentence remains true — nothing is created here. Its framing of persistent
storage as *disabled pending discovery* is what the owner's 2026-08-12 directive
supersedes, and amending that ADR is a platform-lane action: this runbook cites
it and does not reword it. The exact device names, filesystem identifiers, node
identity, and capacity that ADR 0012 keeps out of this repository stay out of it
— the enumerated root above is a declared mount contract, carrying none of them.
