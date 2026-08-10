# Platform assurance program

Charter for the parallel platform security and acceptance program executed by
the Fable lane while the platform integrator runs the live Pi bootstrap.
Authoritative program text lives in the owner's private handoff; this public
charter carries only its repository-safe contract so CI, reviewers, and
successors can hold the work to it.

## Ground rules (binding)

1. Security, privacy, encryption, integrity, and zero recurring cost are
   first-order. **Performance is the explicit third-order goal (owner
   directive, 2026-08-10): maximize it wherever it does not trade off the
   first two — which always win.**
2. Offline/GitHub work only until the stable-base signal: no mutation of the
   live host, its network, Cloudflare, DNS, `main`, tags, releases, packages,
   services, firewall, VPN, or secrets. Feature-branch + PR only; the owner
   merges everything.
3. Audits and fixes are separate review units. Audit evidence is preserved
   verbatim; corrections land on follow-up branches with regression tests
   that fail on the original behavior.
4. No test, policy, scan, signature check, privacy gate, or fail-closed
   behavior is ever weakened to obtain green CI.
5. Stop on ambiguity: transport failure, missing evidence, partial mutation,
   divergent branch, or unknown live state is never permission to retry.
6. No private value — secret, key, token, identity, path, route, peer, IP,
   inventory — enters source, fixtures, PR text, logs, or evidence. Private
   resources are described by type and ordinal only.

## Phases

| Phase | Scope | Gate |
| --- | --- | --- |
| A | Platform surface + trust-boundary audit: component map, authority matrix, data-flow, threat model, invariant catalog, stale-surface report | none — active |
| B | Deterministic fail-closed CI/supply-chain terminal gate | none — active |
| C | Kubernetes adversarial validation (static/rendered first) | none — active |
| D | Cloudflare Zero Trust + YubiKey design, **plan-only**, zero-cost-verified, performance-maximized within the non-negotiables | none — active |
| E | Recovery/upgrade/disaster validation on fake hosts | none — active |
| F | Post-stable reconciliation | `CODEX_PLATFORM_STABLE` signal, exact 4-field form |
| G | Approved live acceptance (read-only default) | stable signal + explicit owner authorization per mutation |

The stable-base signal is accepted only in its exact sanitized form
(`commit=` 40-hex, `contract=platform.snaraj.dev/v1alpha1`, `stage_sha256=`
and `cluster_proof_sha256=` 64-hex). Any missing field, placeholder,
shortened hash, or conflicting message is NOT STABLE.

## Branch program

`fable/platform-assurance-contracts` (this branch) → `fable/platform-security-ci`
→ `fable/platform-kubernetes-policy-audit` →
`fable/platform-cloudflare-zero-trust-design` →
`fable/platform-recovery-upgrade-audit` →
`fable/platform-audit-remediations-<area>` →
`fable/platform-post-stable-acceptance` (blocked until the signal).

Every PR states its exact base, predecessor if stacked, files owned, files
excluded, evidence commands and results, residual risks, rollback, and
whether it merges independently.

## Evidence ledger

Machine-readable JSON Lines at `docs/assurance/evidence-ledger.jsonl`, one
record per command/gate, schema `platform-assurance/v1`
([evidence-ledger.schema.json](evidence-ledger.schema.json)). `PASS` requires
an executable check; `BLOCKED` names the missing public prerequisite, never a
private value; evidence hashes bind only sanitized artifacts whose bytes are
preserved. CI validates schema, ordering, unique IDs, and forbidden-pattern
absence.

## Finding discipline

Findings carry stable IDs (`PLAT-<AREA>-NNN`), severity, exploit/failure
scenario, exact public location, reproduction or missing-proof statement,
violated property, smallest safe correction, required tests, rollback
consequences, owning remediation PR, and closure evidence. Corrections map
every change to finding IDs.

## Synchronization tokens

Sent through the shared observations channel at fixed points:
`FABLE_PLATFORM_ASSURANCE_STARTED`, `FABLE_PLATFORM_AUDIT_READY`,
`FABLE_PLATFORM_FIX_STACK_READY`, `FABLE_PLATFORM_STABLE_BASE_SEEN`,
`FABLE_PLATFORM_RECONCILIATION_READY`,
`FABLE_PLATFORM_LIVE_ACCEPTANCE_REQUESTED`,
`FABLE_PLATFORM_ASSURANCE_COMPLETE`. Owner-blocking questions are also
surfaced in the active session, never only in the channel.
