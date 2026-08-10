# Phase A — stale-surface report

Inventory of unreachable code, obsolete routes, dead configuration, legacy
coupling, stale documentation, duplicated policy, implementation-pinned
tests, and non-executable instructions. Point-in-time at the Phase A base
commit; the two dated dead-code audits are the evidence trail.

## Already corrected (evidence preserved)

The extraction-era sweep and the post-extraction reachability survey found
and corrected the large stale surfaces; findings and their executable
detections are preserved in:

- [2026-08-10-dead-code.md](../audits/2026-08-10-dead-code.md) — pre-split
  audit (D1–D6): planned-dead inventory, bytecode trap, hook
  discoverability, doc residue.
- [2026-08-10-post-extraction-dead-code.md](../audits/2026-08-10-post-extraction-dead-code.md)
  — post-split audit (PD1–PD5): the 82.5%-dead release gate (validators
  extracted, shell collapsed), orphaned publication lane, structurally
  broken Dependabot terraform ecosystem, retired-lane documentation drift,
  small residue. Corrections rode in the reviewed dead-weight PR.

## Standing stale-by-design surfaces (deliberate, not findings)

- Both release-gate runtime lanes fail closed PENDING the post-cutover
  successor; tests pin the exact dies (PLAT-REL-003).
- `kubernetes/websites/*` HelmReleases/Kustomizations stay suspended with
  sentinel values until promotion ceremonies (PLAT-REL-001).
- Kyverno signature policies stay `Audit` until the enforce gate; the
  zero-capacity staging policy stays active until reviewed capacity lands.
- ADR bodies are dated records and are never retrained; corrections arrive
  as dated amendments only (ADRs 0010/0014 carry them).

## Open items (tracked forward)

| ID | Surface | Class | Disposition |
| --- | --- | --- | --- |
| PLAT-STALE-001 | Platform-scoped Kind harness successor (the two-site harness retired with the extraction) | missing capability | Phase C/E design; successor consumes the standalone evidence validators |
| PLAT-STALE-002 | `docs/audits/2026-08-10-github-ux.md` and `-repo-split-coupling.md` describe pre-split CI truthfully but read as current to a casual reader | historical doc | headers already date them; no rewrite (audit law); index note lands with the audit-index follow-up |
| PLAT-STALE-003 | Site-source guidance in `skills/build-website-infrastructure` references machinery now living in the site repos | scoped doc | scope note added in the dead-weight PR; full pointer-rewrite deferred until the skill's next substantive revision |
| PLAT-STALE-004 | Provider-currency signal for the seven OpenTofu roots is manual after the Dependabot terraform removal | accepted residual | PD3 documents the reason; revisit if Dependabot ships OpenTofu lockfile support |
| PLAT-STALE-005 | Tests asserting shell text where behavior tests are possible (`function_body` adjacency pattern in the release-gate contract suite) | test smell | acceptable while the shell is a thin static gate; successor gate must ship behavior tests first (Phase B property) |

## Method

Reachability was proven by call-graph tracing from every CLI dispatch and
CI entry point, not text search alone; each corrected surface names the
test that now fails if it regresses. This report is regenerated whenever a
phase retires or introduces a surface.
