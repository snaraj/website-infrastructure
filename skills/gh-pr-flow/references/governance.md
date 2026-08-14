# Governance and metadata contract

## Issue first

Create or claim an issue before substantive work. Record problem, acceptance,
constraints, threats, tests/mutations, exclusions, rollout/rollback, owner, and
dependencies. The repository issue form must require that minimum schema plus
labels, assignee, milestone, and the linked PR's standalone `Closes #N`. Apply:

- scope labels that describe the actual diff;
- one umbrella agent-authored label and the acting model/context label;
- owner assignee;
- one milestone representing the delivery/release arc.

For release-bearing work, make the issue and PR milestone exactly match the
proposed `VERSION` as `vX.Y.Z`; do not park a patch release in a generic future
major or upkeep milestone. The post-merge audit verifies the immutable Release
before closing a completed milestone and moves every unresolved issue first.
Audit acceptance evidence before closing or reclassifying stale issues; never
infer completion from a title, age, or closed milestone alone.

A PR body contains an exact standalone `Closes #N` for a same-repository issue.
Do not use closing syntax for a record that should remain open or an issue in a
different repository. The owner merge—not PR creation—closes the issue.

## Draft and requires-review

All agent PRs open Draft. `requires-review` is PR-head-only: it means the exact
current head is author-complete and asks an independent reviewer to act.
Absence means the PR is in flight. A reviewer removes it when posting either
verdict; after repairs, the author reapplies it only for the complete
replacement head. Never apply or interpret it on an issue; an issue has no head
and cannot satisfy a PR receipt or Ready gate. Use an explicit normal comment
for issue-spec review until a separately approved cross-repository issue-review
label exists. Treat legacy issue uses as coordinator cleanup residue. Neither
label state nor a review receipt alone makes a PR Ready.

## Role separation on a shared account

- **Author:** owns one branch, implementation, repairs, evidence, metadata.
- **Reviewer:** independent context, read-only experiments, exact-head receipt.
- **Coordinator/Main Worker:** re-queries mutable state, performs the bounded
  exact-head architecture/order/authority/settings sanity gate, and may flip
  Ready only after its separate `PASS` receipt.
- **Owner:** sole merge authority and policy exception authority.

Do not imply separate GitHub users when agents operate through the owner's
account. Signatures and exact-head receipts carry role provenance.

## Checks, coverage, and quality

Infrastructure/tool outages are reported as infrastructure failures, never as
product defects and never as a reason to waive a genuine product failure.

Read every job/check conclusion and logs. A neutral aggregate, skipped job,
missing matrix member, or infrastructure failure is not product evidence.
Classify runner/network/registry/tool failure honestly and rerun only through
normal controls; never churn reviewed history to clear a check. Real test,
security, coverage, or quality failures remain blockers.

Coverage floors are repository-specific and ratchet according to that
repository's contract. Never invent a universal percentage, lower a floor to
make a PR pass, or call an unmeasured path covered.

## Protected history

Validate branch/refspec with repository tooling. Push only the current
same-name work branch. Never force, delete, wildcard, tag, push protected main,
or write another author's branch. If base moves, create a fresh branch and
replacement PR; do not rewrite the published one.

Rulesets are defense in depth. Audit required checks, approvals, signatures,
linear history, bypass actors, and merge methods. Require checks to be bound to
their authoritative app/integration identity with strict current-base testing;
name-only checks, stale branches, or bypass actors fail the Ready gate. Do not
mutate repository settings without explicit owner authorization. Document gaps
rather than claiming repository prose is server enforcement.

Prove the active ruleset condition includes exactly the intended protected ref
such as `refs/heads/main`, with no exclusion or empty/mis-scoped include. A
ruleset name or active state that targets no branch protects nothing and hard
blocks Ready.

Inventory Actions policy, default workflow-token permissions, SHA-pinning
enforcement, secret scanning, and push protection in the owner-observed Ready
receipt. Require read-only defaults, no PR-review approval, full-SHA action
pinning, and signed protected-main commits. Record broader action allowlisting
and optional secret-pattern/validity scanning honestly when they remain
owner-applied hardening decisions.
