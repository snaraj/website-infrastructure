# Governance and metadata contract

## Issue first

Create or claim an issue before substantive work. Record problem, acceptance,
constraints, owner, and dependencies. Apply:

- scope labels that describe the actual diff;
- one umbrella agent-authored label and the acting model/context label;
- owner assignee;
- one milestone representing the delivery/release arc.

A PR body contains an exact standalone `Closes #N` for a same-repository issue.
Do not use closing syntax for a record that should remain open or an issue in a
different repository. The owner merge—not PR creation—closes the issue.

## Draft and requires-review

All agent PRs open Draft. `requires-review` means author-complete at the current
head and asks a reviewer to act. Absence means in-flight. A reviewer removes it
when posting either verdict; after repairs, the author reapplies it. Neither
label state nor a review receipt alone makes a PR Ready.

## Role separation on a shared account

- **Author:** owns one branch, implementation, repairs, evidence, metadata.
- **Reviewer:** independent context, read-only experiments, exact-head receipt.
- **Coordinator:** re-queries mutable state, resolves ordering, may flip Ready.
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
linear history, bypass actors, and merge methods, but do not mutate repository
settings without explicit owner authorization. Document gaps rather than
claiming repository prose is server enforcement.
