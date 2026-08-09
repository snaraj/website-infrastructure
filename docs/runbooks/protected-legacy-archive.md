# Protected legacy archive — Draft / live evidence required

This runbook retires a privacy-sensitive host workload while preserving its
future recovery path. It never authorizes running, upgrading, deleting, or
restoring that workload. Product names in this document are policy classes,
not evidence that any component exists on the target host; exact names, paths,
mounts, versions, identities, rules, and manifests stay in protected local
files.

## Stop conditions

Stop immediately if physical/LAN recovery is unavailable, fewer than two
independent SSH sessions remain, the target/boot identity changes, a secret is
printed, the evidence directory or contract is a symlink, a protected file has
permissive access, storage ownership is uncertain, a wallet or Tor identity is
unclassified, a rule is shared, the service manager's stop behavior is
unknown, or any required result is `UNKNOWN`.

One narrow exception prevents unsafe evidence-gathering: if the workload is
already inactive and no pre-existing clean-shutdown proof exists, record
`CLEAN_SHUTDOWN=UNKNOWN` and do not start it. That uncertainty permits only
disabling already-inactive activation edges and preserving data without writes;
it blocks binary replacement, data migration, repair, backup-by-live-copy,
mount-policy changes, and restoration/start.

Do not use `kill -9`, delete a lock, run repair/reindex, recursively copy/hash
or chmod the retained dataset, combine disable with stop, mask/purge/uninstall,
change firewall/VPN/routing, reboot, or launch Bitcoin Core, Sparrow, Tor, or a
helper merely to discover a version. Use package metadata, unit metadata,
filesystem metadata, and hashes of bounded control artifacts. An unverifiable
manual binary version is recorded as `UNKNOWN`.

## Phase 1 — local-only inventory

1. The operator initiates SSH and retains custody of every passphrase and
   private key. Open a second session and keep physical/LAN recovery ready.
2. In a protected shell use `umask 077`. Keep raw evidence in a dedicated,
   regular, non-symlink local directory; do not save it in Git or paste it into
   chat.
3. Run `scripts/discover-pi.sh --local-only`. Manually inspect even its redacted
   output. The local-only marker must say external egress probes were skipped.
4. Privately inventory system and user service units, sockets, timers, paths,
   dependency/trigger edges, restart policy, package/container ownership,
   cron/desktop autostart, cgroups, processes, listeners, mounts, consumers,
   and firewall/routing layers. Never capture process environments, full
   command lines, raw configuration, logs, wallet filenames, or key material in
   shareable evidence.
5. Classify every item `KEEP`, `RETIRE`, or `UNKNOWN`. Prove whether Tor or a
   VPN is shared; whether Sparrow exists on this host or another workstation;
   whether RPC, ZMQ, Lightning, an indexer, monitoring, SSH forwarding, or
   router state depends on the legacy workload; and whether protected wallet or
   identity material exists. `UNKNOWN` blocks the next phase.

No external DNS/HTTP/TCP probe, package action, service change, firewall
change, mount change, or reboot belongs to this phase.

## Phase 2 — protected contract and archive plan

Copy the committed protected-service template to the ignored local contract,
set mode `0600`, explicitly choose whether legacy archives are present, and
record exact active services, legacy system-manager activation units, and
dedicated archive roots only there. Review every committed generic activation
class separately; a system-manager query cannot prove anything about a user
manager, container, package generator/preset, scheduler/autostart source, or
runtime exposure. Confirm each root is an absolute canonical directory, not a
symlink, home directory, volatile/pseudo-filesystem descendant, or broad root,
and is inaccessible to group/other.
An archive root may be the exact target of a dedicated reviewed data mount or a
directory within a reviewed filesystem; record that choice in protected
evidence. Never substitute the broad `/mnt` hierarchy for a dedicated target.
Bind the plan to the host and boot identity hashes, bounded control-file/unit
hashes, activation state, route/firewall fingerprints, the recovery catalog and
small control-state digest (never retained dataset content), mount identity,
and owner-reported backup/restore evidence. Before approval, remove any old
binding lines, run
`python3 scripts/validate_protected_host_contract.py CONTRACT --emit-bindings`,
append its metadata-only SHA-256 lines in root order, then run `--check-live`.
Binding v3 covers root inode/ownership/mode/link count/change times, stable
containing-mount identity, and a nonempty metadata-only manifest of no more
than 256 immediate entries. It includes entry-name digests plus bounded type,
inode, ownership, mode, link-count, size, and time metadata, but never opens
entry content or walks below the first level. Validation also rejects
volatile, pseudo, or overlay filesystems;
stacked or descendant mounts; overlapping same-filesystem bind aliases; and a
root device that disagrees with mountinfo. It rechecks root and topology state
before accepting the digest. Any empty, over-limit, unavailable, aliased,
changed, or ambiguous binding is a stop. This sentinel detects bounded
top-level replacement or drift; it is not recursive content authentication,
backup proof, or protection from a malicious root user.
Diagnostics leaving the host use indexes and statuses only.

The archive catalog has these logical roles; its actual path stays local:

```text
README.md                 sanitized operator recovery/update guide
manifest/                 content-neutral inventory, hashes, package provenance
control-state/            permission-preserving inactive configuration copies
rollback/                 exact inverse operations and precondition hashes
evidence/                 local PASS/FAIL/UNKNOWN and reboot/soak results
private-reference/        references to encrypted off-device material, not secrets
```

This catalog does not become a live configuration directory. Authoritative SSH,
UFW/nftables, VPN/WireGuard, Tor, and systemd files stay in their protected
system locations. Do not duplicate VPN private keys, wallet/signing material,
Tor identity keys, RPC credentials, cookies, or tokens into the catalog.
Preserve those separately using operator-controlled encryption and perform a
byte-for-byte restore test; record only `PASS`/`FAIL` and a non-sensitive
reference.

Preserve the large dataset in place. Record a bounded top-level structure
count, filesystem/mount identity, ownership/mode, symlink/bind-mount findings,
and free-space result without listing sensitive names or reading every data
block. Do not move it into the catalog.

### Fresh presence-bound protected-host gate

The activation-class lines and `yes|no` presence value in the protected-host
contract are review-scope declarations; they cannot by themselves authorize a
mutation or platform install. For either presence decision, immediately before
a live gate:

1. Privately re-check storage and mounts sufficiently to support the archive
   presence decision, then every known system-manager and user-manager activation
   edge, every container runtime, package preset/generator/upgrade activation
   path, scheduler and desktop autostart source, process, cgroup, open file, and
   IPv4/IPv6/Unix listener. A missing tool, inaccessible manager/session, probe
   error, incomplete namespace, `UNKNOWN`, or unexpected result is a stop.
2. Copy `bootstrap/pi/protected-legacy-runtime-evidence.example` to the fixed
   adjacent `protected-legacy-runtime-evidence.local` path beside
   `protected-services.env.local`, using a non-symlink regular file with one
   hard link, the same owner as the contract, and exact mode `0600`. Never put
   identities or raw probe output in this summary.
3. Only after reviewing the private raw evidence, replace its boot-hash and
   creation-time placeholders, set `LEGACY_ARCHIVES_PRESENT=yes|no` to exactly
   match the contract, and replace each status placeholder with `PASS` only
   when that class is complete. `ARCHIVE_INVENTORY_STATUS=PASS` means the
   private storage inventory supports that decision. `PRODUCT_EXECUTION_STATUS=PASS` means
   collection did not launch Bitcoin Core, Sparrow, Tor, or another protected
   workload or helper. `BOOT_ID_SHA256` is the lowercase SHA-256 of the current
   `/proc/sys/kernel/random/boot_id` ASCII value after stripping its surrounding
   whitespace (do not include the file's newline); `CREATED_UNIX` is the current
   Unix epoch collected after the checks. The boot hash and resulting evidence
   hash stay local and must not be pasted into chat, an issue, or a CI log.
4. From the repository root, run
   `python3 scripts/validate_protected_runtime_evidence.py bootstrap/pi/protected-services.env.local --emit-sha256`.
   This securely reads the adjacent contract and refuses to emit a digest when
   its presence decision differs. Digest emission is derivation only, never
   authorization to mutate the host.
   Replace any prior contract binding with the single emitted
   `PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256` line, then immediately run
   `python3 scripts/validate_protected_host_contract.py bootstrap/pi/protected-services.env.local --check-live`.

The summary expires after 600 seconds and is invalid after every reboot, even
when its age is shorter. Refresh the private checks, recreate the summary, and
replace its contract hash before each install/init gate and after a reboot;
never merely edit the timestamp or copy old `PASS` values. Both Kubernetes
apply paths run the gate once during validation and again at their final safe
boundary: after installer staging/collision checks or kubeadm dry-run, but
before the first host-target mutation. The validator checks the canonical
summary, boot binding, freshness, file controls, and contract hash without
executing discovery or product binaries. It does not manufacture the underlying
evidence. Treat the file as a boot-bound, bounded operator attestation: a
validated `PASS` does not mean that the validator observed the claimed absence.
Only a status covered by an equivalent, namespace-complete live machine probe
in the gate has that additional machine-observed evidence; currently the gate
separately probes declared system-manager units and, when present, archive
root/binding state. The mandatory matching presence value prevents the simple
`yes`-to-`no` deletion bypass, but `ARCHIVE_INVENTORY_STATUS=PASS` remains an
operator attestation to the private inventory rather than machine-created proof
that no archive exists anywhere.

## Phase 3 — no-change retirement review

Before a mutation, independently review an exact transaction containing:

- every activation edge to stop and later disable, in order;
- the main service manager and its `ExecStop`, signal, timeout, kill, and
  restart behavior without exposing secret-bearing arguments;
- proof that the archive and protected-material restore tests passed;
- unique ownership for every later network rule change;
- expected before/after hashes and bounded wait conditions;
- an inverse operation for each configuration or network artifact change, with
  drift refusal;
- a statement that rollback preserves the last proven inactive and
  persistently-disabled/masked state, and never re-enables or starts the
  workload.

If the main service is already inactive, never start it. If it is active, a
graceful manager-controlled stop is a distinct operator-approved step after
the stop path is reviewed. If that path invokes an unapproved product binary,
or a clean stop cannot be proven within the reviewed bound, stop the procedure.
For an active workload, clean-stop evidence is the manager job's successful
completion plus an empty unit cgroup, no remaining process/file use/listener,
and an already-available application shutdown marker when one exists. An absent
lock file alone is not proof. For an already-inactive workload, use only
pre-existing bounded evidence and the `CLEAN_SHUTDOWN=UNKNOWN` rule above.

## Phase 4 — quiesce and disable

Work one boundary at a time. Prevent independently activating sockets, timers,
paths, cron, and desktop/container triggers from launching new work; then use
the reviewed manager-controlled graceful stop for an already-active main
service. Wait until its unit, cgroup, process, files-in-use state, and IPv4/IPv6
listeners are inactive. Only then disable each exact activation edge. Do not
use `disable --now`. Do not mask, purge, uninstall, delete, repair, reindex, or
change the preserved mount during the initial rollback window.

Package presets, upgrades, generators, containers, cron, desktop autostart, and
dependencies can recreate activation. Record their ownership before the change
and repeat inactive/not-enabled checks after package maintenance and reboot.

Retire Tor only after proving no `KEEP` component uses it. Retire Sparrow only
in its proven scope; do not inspect or alter unrelated users or workstations.

## Phase 5 — network cleanup as a separate transaction

First leave stale allows in place while proving the retired workload has no
listener. Then snapshot exact UFW, nftables, IPv4/IPv6, policy-routing, VPN
kill-switch, DNS, and router state in private evidence. Remove only an exact
rule whose ownership is unique to a retired component. Ambiguous numbering,
shared ports, generated rules, or a route controlled by VPN software are stop
conditions.

Prove ownership as a chain of local evidence: activation unit to cgroup/process,
process to bound socket, socket to the exact firewall/router rule, and rule to
no `KEEP` consumer. A matching port number or comment alone is insufficient.
After local removal passes, perform an authorized negative reachability test
from an operator-controlled external network; do not treat a local listener
check as proof of Internet closure.

After every bounded change, prove both retained SSH sessions, a fresh SSH
session, required VPN/WireGuard privacy and kill-switch behavior, DNS, IPv4 and
IPv6 behavior, and unrelated `KEEP` services. Cloudflare Tunnel does not
replace the VPN and does not justify broader host egress.

## Phase 6 — soak, reboot, and accept

After an observation window, reboot only with physical/LAN recovery available.
Accept retirement only when all declared legacy units/triggers remain exactly
inactive, persistently disabled/masked, and without a control group; no related
process/listener reappears; archive roots and
mount fingerprints match, no protected data metadata drifted, required
administration/network behavior passes, and the result is recorded without
identities or secrets.

Choose the long-term storage posture explicitly: mounted read-write is needed
only for a proven local reason; read-only reduces accidental mutation;
`noauto`/unmounted reduces online exposure but needs a tested mount procedure;
powered-off/removable storage gives the smallest online surface but needs
physical custody and periodic health/backup checks. Do not change posture by
assumption. The current protected-host live gate requires each declared archive
root and its reviewed mount to be present. Unmounted or powered-off storage
therefore fails `--check-live` and cannot be adopted by editing the current
declaration into a misleading `archives absent` state; first approve and
implement a separate offline-archive contract/schema and recovery gate.

## Future restoration/update

Restoration is a new isolated deployment, not rollback of this transaction.
Authenticate the archive first; re-read every skipped upstream release and
migration note; obtain the then-current ARM64 artifact only from official
release channels; authenticate the signed manifest and verify the exact
artifact checksum; reconcile wallet/configuration compatibility; retain the old
artifact; and prove no unintended listener or automatic mapping before the
first explicitly authorized start. Never launch Sparrow on this server merely
to update it; prefer a separately secured operator workstation unless an
explicit headless-server requirement is reviewed.

Use the official entry points in ADR 0013 and revalidate them at execution time.
Never trust a version number, checksum, or signing key copied from an old
runbook without independent authentication.
