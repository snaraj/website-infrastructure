# Phase E — recovery, upgrade, and disaster validation

The recovery case matrix. Every case declares the handoff's nine
properties: safe preconditions, exact mutation boundary, evidence captured
before mutation, timeout/kill grace, automatic rollback scope,
non-rollbackable state, manual stop condition, retry rule, and
post-recovery proof. Proof levels stay honest: **contract** (text/structure
pinned by tests), **drill** (executable offline rehearsal), **live** (Phase
G, owner-authorized). A deliberate scoping rule shapes this phase:
`bootstrap/pi/**` is in the integrator's post-stable overlap set, so
behavioral drills that would modify those scripts wait for the
reconciliation window — the case matrix records exactly which drills those
are, and hardened scripts gain no test-injection surfaces (the Coinkite law
outranks testability).

## Case matrix

### E1 — etcd snapshot creation, retention collision, checksum, restore

- Preconditions: approved decisions file (0600, SSD identity resolved),
  pinned root-owned etcd tools at exact versions, TLS healthcheck files,
  RW reviewed-SSD mount, exact acknowledgement string for `--apply`.
- Mutation boundary: one staged partial file promoted to one named
  snapshot inside `/var/backups/kubernetes/etcd`; retention deletes at
  most the oldest beyond 14, refusing symlinks and unexpected names.
- Evidence before mutation: `--check` mode proves every precondition
  read-only; `etcdutl snapshot status` validates the partial BEFORE
  promotion and the promoted file after.
- Timeout/kill: trap-cleaned partial on any exit; interrupted runs leave
  no promoted artifact.
- Auto-rollback scope: partial removal only. Non-rollbackable: a deleted
  retention victim (accepted: it was beyond the reviewed retention cap).
- Manual stop: any status failure, unexpected filename, or mount drift.
- Retry: idempotent — a rerun creates a new named snapshot; no resume.
- Post-recovery proof: status on the promoted file + retention recount.
- Proof level today: **contract** (`test_etcd_snapshot_contract.py` pins
  the staging/verification/retention text). Restore rehearsal on an
  isolated environment: **drill deferred to the reconciliation window**
  (script edits are overlap-gated), then **live** in Phase G.

### E2 — bad website digest → previously proven signed digest

- Preconditions: v0.1.5 rollback digests cosign-verified (recorded in the
  onboarding bundles); promotion ceremony available.
- Mutation boundary: one HelmRelease digest value via the closed
  promotion path; never a re-tag (immutability law).
- Evidence before: current digest + its Release evidence; rollback digest
  signature re-verified at promotion time.
- Timeout/kill: Flux reconciliation interval bounds exposure; suspension
  remains the hard stop.
- Auto-rollback: none needed — the rollback IS the action; the failed
  digest stays published and signed for forensics, never deleted.
- Non-rollbackable: user-visible downtime already incurred.
- Manual stop: rollback digest fails verification (fail closed, keep the
  suspension).
- Retry: idempotent (same digest, same result).
- Post-recovery proof: runtime inventory validator sees the rollback
  digest; edge probes serve the previous content.
- Proof level: **contract** (image-rollback runbook retrained 2026-08-10;
  promotion validators executable) → **live** rehearsal in Phase G.

### E3 — interrupted stage upload / APT / containerd-kubelet / kubeadm

Integrator-lane transactions (private launchers, receipted immutable
stage, PREINSTALL classification, no-blind-reset rule). My lane holds the
boundary only: no repair, no rerun, no package mutation; read-only
sentinel observation; their receipts and 829-test suite are the evidence.
Recorded here so the matrix is complete without duplicating authority.

### E4 — Calico/NetworkManager apply-verify-restore; NetworkPolicy proof failure

Split: static policy shape is a platform **contract** (Conftest hostile
fixtures, Phase C); live apply/restore and packet-direction proof are
integrator-lane until stable, then Phase G canaries (**live**). A failed
NetworkPolicy proof invalidates the decision that depended on it — the
decisions file's approved status is the gate that flips.

### E5 — certificate expiration and version-skew upgrades

- Preconditions: kubeadm-managed PKI; pinned versions in `versions.env`.
- Contract today: `validate_kubeadm_config.py` pins SANs and versions;
  the upgrades runbook orders the skew-compatible steps.
- Gap (PLAT-REC-001, S2): no expiry ALERTING exists pre-launch — an
  expired cert discovered at reboot is the disaster case. Disposition:
  the scheduled-security workflow gains a cert-horizon check in the
  post-stable window (needs live PKI paths; listed for reconciliation).
- Proof level: **contract** now, **drill** post-stable, **live** Phase G.

### E6 — power loss, full disk, corrupted state, stale locks, hung children

Host-level cases are integrator-lane during bootstrap. Platform-side
standing controls: fail-closed validators refuse corrupted/partial inputs
everywhere (canonical-YAML law, mode/owner/symlink checks on every
consumed file — E1's preconditions are one instance); the render/ledger
determinism proofs make truncated evidence detectable. Full-disk behavior
on the single node: **live** Phase G canary (bounded write test), never
simulated destructively on the real host.

### E7 — instructions that cannot be executed as written (doc rot)

The quiet disaster: a runbook step referencing a script that moved. New
executable control **`tests/security/test_runbook_references.py`**: every
repository path referenced in `docs/runbooks/**` and `docs/assurance/**`
must exist in the tracked tree (illustrative placeholders explicitly
annotated). This turns documentation drift into a red gate forever.
Proof level: **drill** (runs in the suite, this PR).

## Findings register

| ID | Severity | Finding | Disposition |
| --- | --- | --- | --- |
| PLAT-REC-001 | S2 | No certificate-expiry alerting before launch | post-stable scheduled check (live PKI paths needed) |
| PLAT-REC-002 | S3 | Off-device snapshot custody ceremony undesigned (T12 residual) | owner decision required: destination + encryption + cadence, zero-cost constraint |
| PLAT-REC-003 | S3 | Runbook references could rot silently | **CLOSED** — executable reference check added |

## Overlap declaration (per the integrator's sync request)

Phase E names, but does not touch, these overlap-set paths:
`bootstrap/pi/etcd-snapshot.sh`, `bootstrap/pi/install-recovery-tools.sh`,
`bootstrap/pi/init-control-plane.sh`, `bootstrap/pi/configure-host.sh`.
Any Phase E drill requiring their modification is deferred to the
post-stable reconciliation window and will be preceded by a published path
list in the observations channel.
