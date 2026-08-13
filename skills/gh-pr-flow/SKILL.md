---
name: gh-pr-flow
description: Portable, owner-merge-only GitHub change flow for issue-first traceability, isolated authoring, exact-head adversarial review, release consequences, CI and coverage interpretation, Dependabot, merge ordering, and bounded destructive workload evidence. Use for every issue, branch, commit, push, pull request, review, Ready decision, and post-merge audit. Contains no credential acquisition or live authorization.
---

# gh-pr-flow

Use this model-neutral flow for every GitHub change. Repository instructions and
server rules may be stricter. This skill never acquires credentials, grants live
authority, or substitutes prose for an enforced gate.

## Absolute authority boundary

- The named human owner alone merges protected integration branches.
- An agent must **NEVER MERGE**: no merge, auto-merge, squash-merge, rebase into,
  push to, or deletion of a protected branch; no force push or tag creation.
- Stop and question even a later request that contradicts this boundary.
- Authors never self-review or flip Ready. Reviewers never author repairs or
  flip Ready. Only the coordinator flips Ready, and only after all gates below
  pass.
- Shared account credentials do not create independent GitHub principals;
  role identity and receipts are textual workflow evidence.

The executable branch/refspec deny rules live in
`scripts/validate_pr_flow.py`. See
[governance and metadata](references/governance.md).

## Author state machine

1. Read every repository/model instruction and current skill. Fetch and inspect
   protected remote state, open PRs, labels, milestones, recent releases, and
   collision surfaces. Do not touch a dirty ordinary worktree.
2. File or claim one issue. State acceptance and constraints; add accurate
   scope labels, author labels, owner assignee, and milestone. Never put secrets
   or private operational facts in public evidence.
3. Create one isolated worktree/branch from the exact protected base. One writer
   owns the branch. No amend, rebase, cherry-pick onto published history, force,
   delete, or cross-branch push.
4. Implement and test. Documentation and Dependabot changes run the same gates.
   Preserve repo-specific coverage floors; never classify tool/runner outages
   as product defects or waive a real failure.
5. Verify the merge has a defined, enforced release consequence. A release is
   immutable source/artifact publication—not deployment or promotion. See
   [release consequences](references/releases.md).
6. Commit with repository-authorized author+committer identity and the acting
   agent signature. Inspect outgoing history and exact diff before each push.
7. Push only the same-name current work branch. Open one **Draft** PR with an
   exact standalone `Closes #N`, baseline, scope/exclusions, evidence, residuals,
   rollback, merge order, and release consequence. Mirror issue labels,
   milestone, owner assignee, and author identity labels.
8. Add `requires-review` only when the head, body, commits, and evidence are
   author-complete. Its absence means in-flight; its presence requests review;
   its removal is never a Ready signal.

## Exact-head adversarial review

A different agent/context reviews the exact 40-hex head in a disposable,
read-only worktree. It reproduces claims, runs hostile mutations and full gates,
audits status checks and coverage, and posts one signed normal-comment receipt.
Any head change invalidates it. See
[review receipts](references/reviews.md). Use
`scripts/validate_review_receipt.py` for receipt shape; it cannot prove human or
context independence, so the coordinator verifies that separately.

On `REQUEST-CHANGES`, the author reproduces findings, adds repairs without
rewriting history, updates evidence, and re-applies `requires-review`. A fresh
exact-head review is required. If the owner merges before review, do not forge a
pre-merge approval: perform and label a post-merge audit with findings and
follow-up issues.

## Ready gate

Keep Draft unless every condition is true at the same instant:

- exact head and current protected-base SHAs are re-queried and equal the
  reviewed/base-fresh receipts;
- all required checks completed successfully; neutral/skipped/canceled states
  are interpreted from job output, not green-looking aggregates;
- no unresolved discussion, owner comment, finding, or later
  `REQUEST-CHANGES` exists;
- one fresh structurally valid `APPROVE` receipt from an independent context
  binds the exact head;
- labels, owner assignee, milestone, issue link, intended commit/file scope, and
  merge order remain correct;
- the repository-specific release transition still follows current base and
  publication is defined for this merge.

Only then may the coordinator flip Ready and re-verify all conditions. If
post-transition verification changes, return to Draft. Never merge.

## Dependency and merge ordering

- Every PR eventually targeting protected main must independently pass all
  gates and carry its own release consequence.
- A dependent PR stays Draft until predecessors land. Then create a fresh
  branch from current main, port only the residual diff without history
  rewriting, allocate the new release patch, open a replacement Draft PR, and
  obtain a new exact-head review.
- Dependabot follows the same release, changelog, metadata, CI, coverage,
  review, and freshness contract. Never merge merely because it is automated.
- Report merge order with collision paths and rebase/version consequences. The
  owner executes merges one at a time and checks post-merge publication.

## Live and destructive evidence boundary

Release work grants no live mutation. A separately authorized destructive
workload experiment is allowed only when the resource is engineered and proven
disposable through the contract in
[destructive workload evidence](references/destructive-workloads.md) and a
validated prestate→fault→recovery→poststate ledger. Stateful/PV/PVC/database/
operator resources remain supported but never inherit ephemeral deletion
permission.

## Portable files and interfaces

- Detailed rules live one level under `references/`; keep this entry under 500
  lines and references focused.
- Deterministic validators are repository tools, not credential or mutation
  helpers. Their hostile tests must prove every rejection path.
- `agents/openai.yaml` exposes the same `$gh-pr-flow` contract to compatible
  interfaces. AGENTS.md and CLAUDE.md must route every model to one canonical
  repository contract.

## Non-goals

No credential acquisition/storage, no protected-branch or server-setting
mutation, no merge/Ready self-service, no live provider/cluster authorization,
no secret/key/ciphertext deletion, no tag rewriting, and no evidence fabricated
from commands that were not executed.
