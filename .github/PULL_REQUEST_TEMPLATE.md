<!-- Every PR states these fields (docs/assurance/README.md, "Every PR
states its exact base, predecessor if stacked, files owned, files excluded,
evidence commands and results, residual risks, rollback, and whether it
merges independently."). Delete nothing; write "none" where empty. -->

## Summary

<!-- What changes and why, in terms of the invariant or gap it serves. -->

## Base and stacking

- Exact base: `main` @ <!-- sha -->
- Exact head: <!-- 40-hex sha; update after every author push -->
- Predecessor PR (if stacked): none
- Merges independently: yes/no

## Issue and release consequence

Closes #<!-- same-repository issue number -->

- Platform source release: tag-derived after protected-main merge; no patch is pre-allocated by this PR
- Adds exactly one new `changelog.d/<issue>-<lowercase-slug>.md`: yes/no
- `VERSION` and `CHANGELOG.md` remain unchanged: yes/no
- Derived patch is exactly one after the immutable predecessor tag: yes/no
- Predecessor tag and immutable Release GET receipt pass before Ready: pending/yes
- Publication is source-only and performs no deployment/promotion: confirm

## Files owned / files excluded

- Files owned by this PR:
- Files deliberately excluded (other lane, e.g. Codex-owned
  `bootstrap/pi/**`, `versions.env`, platform ADRs, `capacity.md`):

## Lane crossings declared

<!-- Any path this PR touches that the Delivery lane section's rulings do
not assign to this lane. AGENTS.md: a path in neither list is NOT
implicitly delivery. One row per path; write "none" where empty. -->

| Path | Why this PR touches it | Authorization | Ruling sought / recorded |
| --- | --- | --- | --- |
| none | | | |

- Rulings above amended back into AGENTS.md's Delivery lane section (same
  PR or the next one opened): yes/no/n/a

## Evidence

<!-- Exact commands run and their results, e.g.:
make check-fast / make check / make coverage / make pre-push-security -->

| Command | Result |
| --- | --- |
| `make check-fast` | |

## Exact-head review

- `requires-review` applied only after author completion: pending/yes
- Independent normal-comment verdict bound to exact head: pending
- Main Worker receipt (`HEAD`, `ROLE: MAIN-WORKER`, `VERDICT: PASS`, closed
  scope) from a context distinct from author/reviewer: pending
- Base freshness and successful required checks re-verified before Ready: pending

## Security

- New/changed fail-closed behavior and the test that pins its rejection path:
- No security behavior was weakened or made toggleable (AGENTS.md
  invariant; `validate_no_security_toggles.py` passes): confirm

## Residual risks

## Rollback

<!-- How to revert safely; call out anything a plain `git revert` misses. -->

## Merge order and collision paths

- Predecessors: none
- Successors that must refresh their current base and dependent evidence: none
- Collision paths: none
