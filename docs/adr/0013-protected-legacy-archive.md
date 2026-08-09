# ADR 0013: Inactive protected legacy archive

- Status: Accepted / host evidence pending
- Date: 2026-08-09

## Context

The target host may contain a privacy-sensitive workload and a large retained
dataset from an earlier purpose. The new Kubernetes/web platform does not need
that workload, and running both roles on one host would expand the attack,
capacity, and failure boundaries. Deleting or migrating the retained state is
also unnecessary and could make later recovery impossible.

Bitcoin Core, Tor, and Sparrow are named in this decision only to classify the
kind of legacy material that needs protection. **This classification is not an
inventory.** Their presence, versions, units, users, paths, mounts, wallet
state, network configuration, identities, and archive contents are facts that
remain in an ignored local contract and protected operator evidence, never in
this public repository.

## Decision

The legacy workload is an **inactive protected archive**, not a co-hosted
service. It receives no Kubernetes object, container image, volume, Flux
resource, Cloudflare route, public listener, CI artifact, installer, updater,
or automatic restoration path.

The local protected-host contract has two non-interchangeable classes:

- `PROTECTED_SYSTEMD_UNIT` identifies a reviewed host service that must remain
  active through platform work.
- `PROTECTED_LEGACY_SYSTEMD_UNIT` identifies a reviewed legacy activation unit
  in the system manager that must be exactly inactive, have no remaining
  control group, and be persistently disabled or masked. A missing, failed,
  transitional, runtime-only-masked, static, linked, or user-manager unit never
  passes this check. Service, socket, timer, and path units are separate
  activation edges and must be classified individually.
- `PROTECTED_LEGACY_ARCHIVES_PRESENT` is an explicit `yes`/`no` decision. A
  reviewed empty list is never allowed to stand in for an unknown inventory;
  `yes` requires a protected root, while `no` forbids legacy declarations.
- `PROTECTED_LEGACY_ACTIVATION_CLASS_REVIEWED` must cover the committed generic
  set of system-manager units, user-manager units, containers, package
  activation, schedulers/autostart, and runtime exposure. Exact private
  evidence stays local; the system-manager unit key is not a proxy for the
  other classes.
- `PROTECTED_LEGACY_ARCHIVE_ROOT` identifies a dedicated local directory whose
  existence, canonical path, restrictive access, and mount binding must remain
  stable. It cannot be a broad system, home, configuration, or mount root.
  It may equal a dedicated reviewed data mount such as a child below `/mnt`,
  or be a directory inside a reviewed filesystem; the binding records which
  relationship was approved. The broad `/mnt` hierarchy itself is forbidden.
- `PROTECTED_LEGACY_ARCHIVE_BINDING_SHA256` binds each root, in order, to a
  versioned canonical metadata-only digest. Binding v3 covers root inode,
  ownership, mode, hard-link count, modification/change times, containing
  Linux mount identity, and a nonempty manifest of at most 256 immediate
  retained entries. The manifest
  hashes entry-name digests, type, inode, ownership, mode, link count, size,
  and modification/change times; it never opens or reads entry content. Live
  validation separately requires the root device to match mountinfo, rejects
  volatile/pseudo/overlay filesystems, descendant or stacked mounts, and every
  visible same-filesystem bind alias whose internal root overlaps the archive.
  It takes a second root and mount-topology snapshot before accepting the
  digest. This detects a missing archive disk, replaced archive disk, empty
  fallback directory, exposed alias, or bounded top-level drift without
  recursively enumerating or reading retained content. It is not a deep
  content-integrity proof, a backup, or a defense against a malicious root
  user.

Exact values exist only in the ignored mode-`0600` local contract. Validators
and shareable diagnostics may emit an index, count, state, or digest, but never
the value. An active/legacy overlap, duplicate value, symlink, traversal,
missing root, permissive root, active legacy unit, or enabled legacy unit is a
hard stop.

### Fresh presence-bound protected-host attestation

The generic activation-class declarations prove review scope, not current
runtime state or the archive-presence decision. For both `yes` and `no`, the
local contract must therefore contain exactly one
`PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256` binding to the fixed adjacent,
ignored `protected-legacy-runtime-evidence.local` file. The attestation records
the same `LEGACY_ARCHIVES_PRESENT=yes|no` decision and the live gate rejects a
mismatch. This prevents changing a reviewed `yes` contract to `no` and deleting
its archive declarations from bypassing every live archive/runtime check.

The evidence file is canonical, bounded ASCII; a regular non-symlink with one
hard link, mode `0600`, and the same owner as the contract. It contains no
units, paths, ports, process names, user names, container names, or raw boot
identifier. It contains only the schema, a SHA-256 of the current Linux boot
identifier, a creation epoch, the matching archive-presence decision, and exact
`PASS` statuses for private archive/storage inventory, system-manager units,
user-manager units, containers, package activation, schedulers and autostart,
processes, cgroups, open files, listeners, and non-execution of protected
product binaries during collection.

This file is a boot-bound, bounded operator attestation to separately reviewed
private evidence; it is not itself a live machine observation. The live gate
independently machine-probes the declared system-manager units, archive roots,
and archive bindings. For every other status, unless that gate later implements
an equivalent namespace-complete live machine probe, validation proves only
the attestation's schema, custody controls, binding, boot, and freshness—not
the underlying absence claim.

Both the declared creation time and file modification time must be no more than
600 seconds old and must not be in the future. A reboot, stale file, presence
mismatch, non-PASS or missing field, ownership/mode/link drift, boot mismatch,
or content-hash mismatch fails closed. Each `PASS` may be written only after its private,
identity-bearing evidence has been reviewed; copying the public example is not
discovery. The validator runs no discovery command and no product binary. Its
standalone digest emitter securely validates the adjacent contract and refuses
a mismatched presence decision before emitting binding material. That output is
derivation only, not mutation authorization. The content binding prevents a
different summary from satisfying the local
contract, but does not replace operator custody or defend against a malicious
root user.

The large retained dataset stays in place on its verified storage boundary. It
must not be copied into a convenience directory, recursively hashed, tarred,
reindexed, renamed, reformatted, rebound, recursively changed, or counted as
free Kubernetes/media capacity. Discovery records only bounded metadata and a
mount-binding fingerprint. The filesystem may remain mounted read-write,
or become read-only under the current live contract. A `noauto`/unmounted or
powered-off archive cannot satisfy the current root-and-mount live gate; that
posture requires a separately reviewed contract/schema and tested mount or
recovery procedure before the platform gate changes. No storage posture is
inferred from this decision.

An operator-facing consolidation directory is a recovery catalog, not a new
authoritative configuration root. Live SSH, firewall, VPN, and system service
configuration remains in its root-controlled system location. The catalog may
hold a human README, sanitized templates, manifests, hashes, rollback steps,
and permission-preserving offline copies. Wallet/signing material, VPN keys,
Tor identity material, RPC credentials, and other bearer secrets require a
separate encrypted off-device backup and tested restore; they are not copied
into a shareable catalog.

## Retirement transaction

Retirement is a staged, hash-bound operator transaction:

1. retain physical/LAN recovery and two independent SSH sessions;
2. collect local-only evidence without DNS, HTTP, TCP probes, package changes,
   firewall changes, service changes, reboot, or product-binary execution;
3. classify every service, trigger, consumer, listener, firewall rule, mount,
   and protected artifact as `KEEP`, `RETIRE`, or `UNKNOWN`; an `UNKNOWN`
   blocks mutation of that boundary. If an already-inactive workload lacks
   pre-existing clean-shutdown proof, leave that fact unknown, never start it,
   and permit only disabling inactive triggers plus write-free preservation;
4. preserve control state and separately prove protected-secret backup and
   restore without exposing values;
5. review the service manager's exact stop behavior, stop activation triggers,
   request a graceful manager-controlled stop only if the workload is already
   active, wait boundedly, then disable it; never start an inactive workload to
   improve evidence;
6. remove only uniquely attributable network authority in a separate
   transaction after proving there is no listener; shared Tor, VPN, DNS,
   firewall, and SSH behavior remains untouched;
7. soak, reboot through the tested recovery path, and prove the legacy units
   remain exactly inactive, persistently disabled/masked, and without a control
   group; the archive binding did not drift; no listener
   reappeared, and administration still works.

The first rollback window retains packages, binaries, configuration, units,
and data. There is no mask, purge, uninstall, forced process kill, lock-file
deletion, repair, or automatic start. Later removal is a separate exact-target
decision after archive and restore evidence passes.

## Network and platform boundary

Cloudflare Tunnel is an application/administration transport, not a replacement
for host-wide VPN privacy or a generic egress proxy. Existing VPN, WireGuard,
kill-switch, DNS, firewall, IPv4/IPv6, policy-routing, and MTU behavior must be
proven before kubeadm/CNI selection. A legacy rule is removed only when its
ownership is unique; ambiguous or shared rules stop the transaction. The
archived workload receives no inbound or outbound exception.

## Future restoration and updating

Restoration is a new deployment on an isolated, explicitly approved boundary;
it is not part of web-platform recovery. Before any first start, authenticate
the archive, consult the then-current official Bitcoin Core and Sparrow release
and verification documentation, review every skipped release and migration,
verify the selected artifact through its authenticated manifest/signature, and
reconcile wallet and configuration compatibility. Merely making an inert
archive “current” is not a reason to install or execute software on this host.
Once a newer binary has opened a data directory, an older binary must not be
used unless the upstream compatibility documentation explicitly permits it.

Current upstream entry points, to be revalidated at execution time:

- <https://bitcoincore.org/en/download/>
- <https://bitcoincore.org/en/releases/>
- <https://github.com/bitcoin-core/guix.sigs>
- <https://www.sparrowwallet.com/download/>
- <https://www.sparrowwallet.com/docs/quick-start.html#verifying-the-release>

## Consequences

Kubernetes capacity planning excludes the preserved archive. Platform
installation remains blocked while any legacy unit or root is unclassified,
active contrary to policy, enabled, missing, permissive, or drifted. The public
repository can prove the policy shape without publishing the host inventory,
while future restoration retains an explicit, independently reviewed path.

## Rollback

Rollback restores only exact archived configuration and network artifacts whose
current hashes still match the transaction, while preserving the last proven
inactive and persistently-disabled/masked activation state. Rollback never
re-enables or starts the legacy workload. Re-enablement or a start against
retained data always requires a fresh isolated recovery decision, current
release verification, and explicit operator authorization.
