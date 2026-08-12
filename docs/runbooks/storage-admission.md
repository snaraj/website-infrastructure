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

There are six lists, and together they are the complete set of means by which
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
| VolumeAttributesClass identities | *(empty)* | a PersistentVolume or claim may reference a class that retargets it at a backend |
| PersistentVolume non-source fields | the nine upstream `PersistentVolumeSpec` fields that are not volume sources | **a field stops being treated as a volume source.** Adding a real source name here makes that source invisible to the derivation. SR-1 backstops the case where the poisoned field is the object's ONLY source, and does NOT backstop a poisoned source sitting beside a legitimate `local:` one — so `tests/security/test_storage_exposure_policy_contract.py` pins this list to its exact nine names, and any addition fails regardless of what it is called |

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

Every check below lives in that one Kyverno rule and is mirrored one-for-one in
Rego. Each is proven by at least one single-object fixture under
`tests/kubernetes/fixtures/deny/storage-*.yaml`, and
`tests/security/test_storage_exposure_policy_contract.py` fails if this table
and the rule set ever diverge — the count is derived, never asserted in prose.

| # | Rule | Why |
| --- | --- | --- |
| SR-0 | a `spec` that is present but not a mapping is denied | a rule that goes undefined on a malformed object is an allow |
| SR-1 | a PersistentVolume declares exactly one volume source | zero sources means nothing can be reasoned about; two means a local decoy can sit beside a remote source |
| SR-2 | the source is `local` or `csi` | sources are derived by subtracting the known non-source fields, so `nfs`, `iscsi`, `cephfs`, `glusterfs`, `fc`, `rbd`, `portworxVolume`, `flexVolume`, `azureFile`, `azureDisk`, `awsElasticBlockStore`, `gcePersistentDisk`, `vsphereVolume`, `cinder`, `hostPath` **and every source upstream has not invented yet** fail here with no blocklist to maintain |
| SR-3 | a `csi` source names an enumerated driver | a driver reaches wherever it is written to reach |
| SR-4 | a `local` path is the enumerated root or beneath it | a path elsewhere on the node — control-plane state, an operator home, a mounted share — is a different means |
| SR-5 | a `local` path contains no `..` segment | SR-4 is a prefix test, and `<root>/../../var/lib/etcd` passes a prefix test |
| SR-6 | a `local` volume's `nodeAffinity.required` names the nodes it accepts — at least one selector term, and every term bounded by an `In` match with a non-empty value list | presence alone is not a pin: `operator: Exists` on `kubernetes.io/hostname` matches every node that ever joins, and `required: {}` asserts nothing, so one reviewed directory would still be a directory on any machine |
| SR-7 | a PersistentVolume names an enumerated `storageClassName` | the class is part of the means |
| SR-8 | a StorageClass uses an enumerated provisioner | the provisioner is what actually decides where bytes land |
| SR-9 | a StorageClass is an enumerated identity | the class inventory is reviewed, so a second class cannot appear beside the first |
| SR-10 | a StorageClass declares no `parameters` and no `mountOptions` | that is where a server, export, share, endpoint, or bucket would be named; a static local class needs neither |
| SR-11 | a PersistentVolumeClaim names an enumerated `storageClassName` | an absent class binds through whatever is marked default, so installation order would choose the means |
| SR-12 | a PersistentVolumeClaim declares no `dataSource`/`dataSourceRef` | both import bytes from elsewhere, and `dataSourceRef` can cross namespaces |
| SR-13 | a `CSIDriver` is an enumerated driver | installing a driver installs a whole means at once, before any volume exists |
| SR-14 | a `VolumeAttributesClass` names an enumerated driver | it is the newest object that can point storage at a backend: a driver name plus a free-form parameter map |
| SR-15 | a PersistentVolume or claim referencing a `volumeAttributesClassName` names an enumerated one | SR-14 gates the object; this gates the reference, exactly as SR-9 gates the class object and SR-7/SR-11 gate references to it. Without it the reference was un-gated in both engines |
| SR-16 | a PersistentVolume declares no `mountOptions` | SR-10's rationale where it equally holds: `["addr=storage.invalid", "vers=4.1"]` is an NFS mount by another spelling, and a statically provisioned local volume needs no mount options |

`hostPath` is denied outright as a PersistentVolume source rather than
root-checked. Unlike `local` it carries no node-affinity requirement, so the
same path is satisfied on every node, and it can name any directory the kubelet
can see.

## Why it fails closed

Four properties, in order of importance:

1. **Sources are derived, not listed.** The policy enumerates the nine
   `PersistentVolumeSpec` fields that are *not* volume sources and treats
   everything else as a source. An upstream source this repository has never
   heard of is a source by construction and is denied by SR-2. There is no
   blocklist to fall behind. The derivation's own soft spot — a real source
   name added to the non-source list — is pinned name-for-name by the test
   battery, because SR-1's arity backstop only holds when the poisoned field is
   the object's *only* source.
2. **Absent and unusable both deny.** Missing `spec`, missing `path`, missing
   `provisioner`, missing `metadata`, a non-string path, an empty enumeration —
   each evaluates false, and false denies. So does a field that is *present but
   structurally unusable*: `local:` with a null value, a `csi:` that is a
   string, a `nodeAffinity:` that is a list.
   **This was not true of the Conftest mirror until 2026-08-12.** Rego's
   `object.get` raises a builtin type error on such a value, and under OPA's
   default non-strict handling the surrounding expression becomes UNDEFINED —
   the deny body simply fails and the rule silently does not fire, while
   Kyverno's CEL raises and `failurePolicy: Fail` denies. Nine shapes diverged,
   eight of them fail-open in the engine that is the only gate running while
   Kyverno is uninstalled; the sharpest pair differed by ONE YAML TOKEN
   (`nodeAffinity:` present-but-null versus the key omitted) and the suite could
   not tell them apart. Every accessor now reads through a type-checked helper
   that denies on failure, and `scripts/test-storage-engine-parity.sh` feeds
   both engines the same corpus and fails on any disagreement.
3. **The empty list denies.** An enumeration with no entries admits nothing.
   The CSI-driver and VolumeAttributesClass lists are both empty today and every
   driver-shaped object, and every reference to an attributes class, is refused
   because of it.
4. **Rules must mean what they say.** SR-6 claimed to bound a local volume to
   its node while only checking that `nodeAffinity.required` was present, which
   `operator: Exists` on `kubernetes.io/hostname` satisfies on every node in the
   cluster — the allow fixture itself taught that shape. A rule whose stated
   purpose exceeds its behaviour is a claim, not a control, so SR-6 now requires
   the selector to name the nodes it accepts.

## Coverage is checked separately from behaviour

`kyverno test` reports a resource that falls *outside* a rule's `match` block as
`Pass`, reason `Excluded`. Deleting `PersistentVolume` from the storage rule's
matched kinds leaves the whole Kyverno suite green while an `nfs`
PersistentVolume is admitted — reproduced on this policy before this runbook was
written. Behavioural fixtures cannot see that failure at all.

**`kyverno test` also counts `Skip` as a PASS, not only `Pass`/`Excluded`.** That
is a second, quieter blind spot, and two one-word edits exploit it (both measured
on this exact policy, 2026-08-12):

- `spec.admission: true → false` stops every rule in the policy running at
  admission — the policy degrades to background scanning and refuses nothing —
  with the structural battery and the Kyverno suite both fully green.
- adding a userInfo narrowing to the match block (`clusterRoles`, `roles`, or
  `subjects`) makes the rule match only principals bound to a role nobody
  holds. `kyverno apply` prints "Policies Skipped (as required variables are not
  provided by the user)", every row reports `Skip`, and the suite reports
  74 passed / 0 failed.

Read any all-green Kyverno run as *behaviour on matched objects*, never as
coverage.

`tests/security/test_storage_exposure_policy_contract.py` is the structural half.
It derives the covered kinds from the rule's own CEL expressions and requires the
`match` block to equal them, requires the Conftest mirror to key a deny rule on
each of those kinds, requires the six enumerations to be identical across both
engines, forbids every narrowing field above (including the userInfo three), and
pins `admission: true` beside `validationFailureAction: Enforce` and
`failurePolicy: Fail`. Narrow either half and it goes red while every behavioural
row stays green.

`scripts/test-storage-engine-parity.sh` is the differential half, and it exists
because the structural battery compares TEXT. It runs every storage deny fixture
and the allow fixture through **both** engines, requires each engine's verdict to
equal the verdict the fixture's directory declares, and fails if Kyverno ever
reports `skip` or never evaluates an object at all — which is the same narrowing
above, caught behaviourally. It runs in `scripts/render-manifests.sh`, beside the
fixture runner, so `make check-kubernetes` and CI both execute it.

It proves its own comparison on every run. Neutering that comparison — one
`if` — was the single mutant that survived the whole matrix, because every other
guard around the harness reads its text rather than its behaviour. The harness
now runs the real comparison against a deliberately wrong expectation first and
aborts unless exactly one divergence comes back, so a harness that compares
nothing fails instead of passing.

It also enforces ATTRIBUTION. Both fixture runners assert only that a file is
rejected, so neutralizing one rule stays green whenever any other rule denies the
same object — measured on the Rego SR-0 arm, whose fixture also fails SR-1 and
SR-7. Every deny fixture therefore declares the message fragment its rule emits
in a `# rego-message:` header, the harness requires that fragment in the Conftest
output, and the test battery requires the fragment to be a real message some
Conftest rule can emit. Every rule in the mirror is pinned behaviourally, not by
the presence of its comment.

## What this gate does not cover — stated, not papered over

- **A manifest cannot say what a node path really is.** `/mnt/local-pie-ssd`
  could be a bind mount of an NFS client mount, a Samba share, an iSCSI-backed
  filesystem, or a symlink to any of those, and no admission rule can tell. A
  `mount --bind` of a network-backed filesystem produces a manifest
  byte-identical to the allow fixture. The gate proves the *declared* means.

  **The required host-side closure**, recorded here so it is not rediscovered
  later, is: the enumerated root proven to be a mount of a LOCAL BLOCK DEVICE
  (`findmnt -no FSTYPE,SOURCE` restricted to ext4/xfs/btrfs over a `/dev/*`
  source, never `nfs*`/`cifs`/`smb3`/`fuse.*`/iscsi); that mount pinned by device
  UUID in `/etc/fstab` with `nodev,nosuid,noexec` and no `x-systemd.automount`
  onto a network unit; a boot-time and periodic attestation that no nested mount
  and no symlink escapes the root; and the block device confirmed physically
  attached rather than an iSCSI, NBD, or loopback import. That work is
  **platform-lane** and belongs with the live evidence ADR 0012 already
  requires. It is **not** closed by this change, and nothing in this gate is
  relaxed to compensate.
- **Symlinks and bind mounts inside the enumerated root** are equally invisible.
  SR-5 denies textual traversal; it cannot deny a symlink placed on the node.
- **Kinds outside the match block are not evaluated.** `VolumeSnapshot`,
  `VolumeSnapshotClass`, `VolumeSnapshotContent`, `CSIStorageCapacity`, and
  `VolumeAttachment` are not covered — the same surface the previous
  deny-by-kind policy left uncovered. SR-12 removes the main reason a snapshot
  would matter by denying claims that import from one.

  `VolumeSnapshotClass` deserves its own sentence, because it carries the same
  `driver` + `parameters` shape that SR-10 and SR-14 exist to gate, and it is
  admitted today. The asymmetry with `VolumeAttributesClass` — which this change
  DID add — is deliberate: `VolumeAttributesClass` is a built-in Kubernetes kind
  present in the pinned server version without installing anything, so it can be
  created today, while every snapshot kind is an external-snapshotter CRD that
  does not exist in this cluster and cannot be created until an operator installs
  it. Naming an absent CRD in a `match` block is at best inert and at worst a
  policy-load problem in the cluster the staged install (#91) is still bringing
  up, so the snapshot kinds are added the day their CRDs are — and installing
  them is itself a means the enumeration would have to admit first.
- **Pod-level mounting is a different gate, and its two halves have different
  reach.** Admitting the storage objects did not admit mounting them.
  - In **CI**, `policies/conftest/kubernetes.rego` now derives a Pod volume's
    source by the same subtraction the PersistentVolume rules use: a volume
    entry is a name plus exactly one source, and only `emptyDir`, `configMap`,
    `secret`, `projected`, and `downwardAPI` — sources whose bytes come from the
    cluster's own API server or the node's ephemeral storage — are admitted.
    Everything else, including every source upstream has not invented yet, is
    denied by construction, for every workload kind in every namespace. It was
    previously a ten-name blocklist, under which an otherwise fully compliant
    Pod outside the tenant namespaces could mount `azureFile` or
    `awsElasticBlockStore` and be admitted.
  - At **admission**, the Kyverno rules that bound Pod volumes are scoped to the
    tenant namespaces (`naranjo-online`, `lidersea-com`, `cloudflare-public`) and
    are exact allowlists there. A Pod created directly in another namespace is
    not reached by them. Closing that would add a rule to this policy, and the
    policy's rule count, names, and order are a cross-PR contract with the
    staged install (#91), which patches `/spec/rules/<index>` by index — so it
    is a separate change, deliberately not folded in here.
- **The repository inventory gate is unchanged.** `scripts/release-gate.sh`
  (`assert_storage_disabled`) and `scripts/validate_repository.py` still refuse
  a committed `PersistentVolume`, `PersistentVolumeClaim`, `StorageClass`,
  `hostPath`, or `local:` under the live Kubernetes roots. This change moves the
  admission gate only; the storage rollout is a separate reviewed change and is
  still blocked on hardware.
- **Two CEL expressions deny by ERRORING, not by evaluating false**, and an
  erroring expression is a denial only because the webhook is
  `failurePolicy: Fail`. `local:` as a list and a StorageClass `parameters:` of
  null are the two measured shapes. The failure policy is committed and pinned by
  a test; the error→deny mapping itself is pinned behaviourally by the deny
  fixtures for those shapes and by the differential harness, which requires the
  Kyverno verdict to be `deny` for both.
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
