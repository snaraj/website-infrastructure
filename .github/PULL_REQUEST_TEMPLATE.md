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

- Platform source release: `vX.Y.Z`
- `VERSION` is exactly one patch after the protected base: yes/no
- `CHANGELOG.md` records this exact release: yes/no
- Publication is source-only and performs no deployment/promotion: confirm

## Files owned / files excluded

- Files owned by this PR:
- Files deliberately excluded (other lane, e.g. Codex-owned
  `bootstrap/pi/**`, `versions.env`, platform ADRs, `capacity.md`):

## Evidence

<!-- Exact commands run and their results, e.g.:
make check-fast / make check / make coverage / make pre-push-security -->

| Command | Result |
| --- | --- |
| `make check-fast` | |

## Exact-head review

- `requires-review` applied only after author completion: pending/yes
- Independent normal-comment verdict bound to exact head: pending
- Main Worker bounded architecture sanity review: pending
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
- Successors that must resync their base and platform patch: none
- Collision paths: none
