# Phase A — threat model

Adversary-first review of the platform contract. Each threat lists the
attack, the standing control (with its executable checker where one exists —
IDs from [phase-a-invariants.md](phase-a-invariants.md)), and the residual
that later phases must close. Threats against Codex's private live loop are
in scope only at the boundary this repository can check.

## T1 — Credential theft and owner-token misuse

Attack: exfiltrated owner PAT/browser session mints releases, edits rulesets,
or pushes to `main`.
Controls: no long-lived credential exists in either repo or CI (OIDC keyless
publishing, secretless PRs — PLAT-SUP-004/PLAT-SEC-001); `main` requires the
owner through rulesets; commits carry noreply identities only (PLAT-SEC-002).
Residual: the owner's own account custody (hardware-key 2FA is owner-side;
Phase D extends phishing-resistant WebAuthn to Cloudflare Access). Detection
of a hostile merge is a Phase B ledger check (base-commit continuity).

## T2 — Branch/review bypass

Attack: an agent or attacker lands unreviewed content in `main` or rewrites
history.
Controls: rulesets (deletion, non-fast-forward, linear history, signature
requirements on `main`); both agent lanes are contractually PR-only; pre-push
gate validates the exact outgoing range (PLAT-SEC-002).
Residual: rulesets are owner-mutable by design; the assurance ledger records
the observed base commit per record so tampering shows as discontinuity.

## T3 — Compromised GitHub Actions

Attack: a hijacked third-party action exfiltrates tokens or poisons builds.
Controls: full-SHA pins with version comments (PLAT-SUP-004); top-level
`permissions: {}`; `persist-credentials: false`; PR CI holds no secrets; site
publishers expose only per-repo GHCR scope + OIDC.
Residual: a malicious pinned SHA itself — mitigated by review at bump time
(dependabot PRs are reviewed, never auto-merged); Phase B adds an
action-inventory diff check to the terminal gate.

## T4 — Poisoned or substituted OCI artifacts

Attack: attacker publishes a rogue image/chart, reuses a version, or swaps a
tag to point at different bytes.
Controls: the committed chart sources and signature policies require cosign
keyless signatures from exactly the two protected-`main` publisher identities
(PLAT-SUP-002 — re-pointed from the tag form 2026-08-22, ADR 0016 amendment;
note that admission is not among the LIVE controls here, because Kyverno is not
installed and not authorized to be, so the operating check is Flux's own
`spec.verify` at reconcile time); deployment is digest-pinned (PLAT-SUP-001);
publishers refuse tag reuse, and their manual dispatch is bound by their own
`authorize` job to a commit that already landed on protected `main` through the
full gate, so a dispatcher cannot choose arbitrary source bytes (PLAT-REL-002);
`verify-existing-oci-release.sh` re-proves any existing release read-only.
Residual: GHCR account compromise could delete-and-recreate a package; the
digest pins in Git still refuse the swap (different digest), and unsigned
0.1.5 chart versions await owner deletion (flagged). Rekor transparency
lookups land in Phase B as a scheduled check.

## T5 — Malicious render inputs (Helm/Kustomize/YAML decoys)

Attack: crafted chart values, duplicate YAML keys, or decoy documents change
what renders versus what review saw.
Controls: canonical-YAML law in `validate_release_state.py` (duplicate-key,
decoy, drift rejection); rendered-object conftest suite runs on the exact
render CI produces; kubeconform schema strictness; negative fixtures for
every bypass class found to date.
Residual: renderer version drift — pinned by `install-tools.sh` hashes; a
reproducibility hash for rendered output joins the Phase B gate.

## T6 — Lateral movement and host escape

Attack: a compromised site pod reaches the host, the other tenant, or the
admin plane.
Controls: restricted PSA + kyverno confinement (PLAT-EXP-003), default-deny
plus the nine closed NetworkPolicies (PLAT-EXP-002), no storage surfaces
(PLAT-EXP-004), no host namespaces/ports, ServiceAccount token minimization.
Residual: kernel/CNI zero-days on a single node — accepted single-node risk,
bounded by outbound-only exposure and the Phase E recovery drills; the
private admin plane's non-overlap is proven in Phase G canaries.

## T7 — Tunnel bypass, DNS takeover, stale routes

Attack: traffic reaches the origin outside the tunnel, or DNS points away
from it.
Controls: no inbound WAN ports (design + owner router); origin never a DNS
target; plan-only IaC pins the two zones' records; `verify-exposure.sh`
probes public posture without printing residential addresses.
Residual: registrar/Cloudflare account custody (owner-side; Phase D adds
Access hardening and the seven-point verification checklist + rollback
ladder that never touches LAN recovery).

## T8 — Secret leakage paths

Attack: secrets/private identity leak via commits, CI logs, evidence files,
error text, or swap.
Controls: PLAT-SEC-001/002/003 (gitleaks tree+history, metadata law, privacy
validators, redaction helpers); observations/evidence contracts strip
addresses and identities; capacity evidence must be untracked mode-0600.
Residual: host-side swap/log hygiene is Codex-lane; the assurance ledger's
forbidden-pattern CI check (Phase B) guards the new evidence surface.

## T9 — Rollback and recovery failure

Attack: a bad release cannot be rolled back, or recovery tooling itself
breaks the cluster (interrupted stage, expired certs, corrupted snapshot).
Controls: immutable digest history + verified v0.1.5 rollback images; bump-
never-retag law; suspended-state sentinels; runbooks retrained 2026-08-10.
Residual: rollback is proven only statically today — Phase E builds the
fake-host drills (snapshot restore rehearsal, interrupted-transaction
classification, cert-expiry alerts), Phase G rehearses live under owner
authorization.

## T10 — Guardian/automation races (two-agent hazard)

Attack: the two AI lanes mutate shared surfaces concurrently or act on stale
state (the PR #22 close race is the archetype).
Controls: ownership division with hot-spot pre-notice; observations channel
with custody contract; sentinel is read-only at a sanctioned cadence;
API-verified state before destructive git actions (rule hardened after #22).
Residual: contract compliance is behavioral, not mechanical; the sync tokens
(STARTED/READY/SEEN…) make each lane's position explicit and auditable.

## T11 — Spend injection

Attack: a change quietly enables a metered feature (Cloudflare product, paid
Action, GHCR overage) — cost as a denial-of-owner attack.
Controls: PLAT-COST-001/002; plan-only IaC with phase contracts; public
repos/packages only; the performance directive explicitly subordinates to
zero-cost, and Phase D verifies every proposed feature against current
free-plan documentation via the Cloudflare skills before design acceptance.
Residual: provider repricing — owner billing audit (PLAT-GAP-003).

## T12 — Backup exfiltration

Attack: etcd snapshots or recovery archives leak secrets at rest.
Controls: API-server encryption-at-rest config validated
(`validate_encryption_config.py`); snapshots stay host-local root-only;
nothing recovery-related is tracked.
Residual: off-device snapshot custody ceremony is undesigned — explicit
Phase E deliverable with an owner decision on storage location (zero-cost
constraint applies).
