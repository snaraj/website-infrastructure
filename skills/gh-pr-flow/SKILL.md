---
name: gh-pr-flow
description: Portable, owner-merge-only GitHub change flow for issue-first traceability, isolated authoring, exact-head adversarial review, non-vacuous evidence, release consequences, CI and coverage interpretation, Dependabot, merge ordering, and bounded destructive workload evidence. Use for every issue, branch, commit, push, pull request, review, Ready decision, and post-merge audit. Contains no credential acquisition or live authorization.
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
- Read repository authority before interpreting identity. Treat `gh auth
  status` as observation of an already-configured principal, not permission or
  credential acquisition. Stop on an unexpected or unauthorized identity.
- Never acquire, extract, exchange, print, change, or repurpose credentials to
  satisfy this flow.
- Derive permitted author, committer, and trailer metadata from repository
  authority and validators; never assume one portable identity form.

The executable branch/refspec deny rules live in
`scripts/validate_pr_flow.py`. See
[governance and metadata](references/governance.md).

## Author state machine

1. Read every repository/model instruction and current skill. Fetch and inspect
   protected remote state, open PRs, labels, milestones, recent releases, and
   collision surfaces. Do not touch a dirty ordinary worktree.
2. File or claim one issue. State acceptance and constraints; add accurate
   scope labels, author labels, owner assignee, and milestone. Never put secrets
   or private operational facts in public evidence. For a release-bearing
   change, use the exact proposed `vX.Y.Z` milestone on both issue and PR.
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
8. Add `requires-review` only to a PR and only when its exact head, body,
   commits, and evidence are author-complete. Never apply or interpret it on an
   issue, which has no reviewable head. Its absence means an author PR is
   in-flight; its presence requests exact-head review; removal is never Ready.

## Exact-head adversarial review

A different agent/context reviews the exact 40-hex head in a disposable,
read-only worktree. It reproduces claims, runs hostile mutations and full gates,
audits status checks and coverage, and posts one signed normal-comment receipt.
Any head change invalidates it. See
[review receipts](references/reviews.md). Use
`scripts/validate_review_receipt.py --resource-kind pull-request` for receipt
shape; it rejects issue resources but cannot prove human or context
independence, so the coordinator verifies that separately.

After `APPROVE`, require a distinct Main Worker/coordinator context to post the
bounded architecture, merge-order, authority, settings, base-freshness, and
required-check sanity receipt defined in the same reference. Validate its exact
head, `ROLE: MAIN-WORKER`, and `VERDICT: PASS` with the executable receipt gate.
This receipt neither repeats adversarial review nor grants Ready/merge authority.

On `REQUEST-CHANGES`, the author reproduces findings, adds repairs without
rewriting history, updates evidence, and re-applies `requires-review`. A fresh
exact-head review is required. If the owner merges before review, do not forge a
pre-merge approval: perform and label a post-merge audit with findings and
follow-up issues.

## Ready gate

Keep Draft unless every condition is true at the same instant:

Ready means zero unresolved blockers across code, CI, review, sequencing,
settings, Main Worker, metadata, or any other declared gate. Owner review or
owner merge authority does not waive a blocker; a blocker-bearing PR stays
Draft.

- exact head and current protected-base SHAs are re-queried and equal the
  reviewed/base-fresh receipts;
- all required checks completed successfully; neutral/skipped/canceled states
  are interpreted from job output, not green-looking aggregates;
- no unresolved discussion, owner comment, finding, or later
  `REQUEST-CHANGES` exists;
- one fresh structurally valid `APPROVE` receipt from an independent context
  binds the exact head;
- one fresh structurally valid Main Worker `PASS` receipt from a context
  distinct from both author and reviewer binds the exact head and closed scope;
- labels, owner assignee, milestone, issue link, intended commit/file scope, and
  merge order remain correct;
- every declared repository/server-settings receipt is current and passing;
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
- Close a completed release milestone only after the immutable Release succeeds
  and unresolved issues are moved. Verify acceptance evidence before closing or
  reclassifying stale issues; never infer completion from a title.

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

## 6. Evidence: a green suite is not coverage

Before you claim a check works, and before you accept that someone else's
does, work through
[evidence doctrine](references/evidence-doctrine.md) — the catalogue of
distinct, reproducible mechanisms by which a fully green run proves
nothing, each with its general correction. It is the probe list behind
"a guard that cannot fail is no guard", and it is not re-derivable under
review pressure: several of its entries were found only after a reviewer
had already approved, and several inside the fix written to close an
earlier finding.

Two rules from it govern this flow directly. For every control a round
ADDS, name the single test that fails when you delete it, and prove that
by deleting it. And re-run the mutation matrix on the FIXED tree after
every round of findings, mutating the round's own new assertions first —
a matrix result is never carried forward across a fix.

## 7. Roles and authority

Four roles have explicit compatibility rules; the flow does not assume four
different account credentials:

- **Author** — the single writer on the branch. The branch author and
  independent reviewer are never the same context. The author never posts its
  own verdict and never lifts its own review gate.
- **Independent reviewer** — a different context, working in a disposable
  worktree at the exact PR head, read-only toward the author's workspace and
  reverting every experiment. It independently derives the evidence and posts
  the verdict.
- **Coordinator / Main Worker** — the coordinator/Main Worker context is
  distinct from both author and reviewer. It performs the bounded Main Worker
  sanity pass and the readiness flip only once review has cleared AND every
  check is green at the exact head, with no peer or owner comment outstanding.
- **Owner** — alone holds merge authority. Owner review and merge authority do
  not replace the distinct coordinator/Main Worker gate.

Neither the author nor the reviewer performs the readiness flip. Flipping is
an assertion that review is complete, never "let the owner take a look".

A green check, a peer approval, and a ready state are EVIDENCE, never
authority. Draft means unresolved readiness gates remain; it never prevents
owner review. Ready means the coordinator asserts every gate passed.

## 8. The review-request label

A review-request label (`requires-review` where that taxonomy is used)
tracks one thing: complete-from-author, waiting on a reviewer's cycle.

- The AUTHOR applies it when a round is complete from the author's side —
  every commit pushed, the body final.
- The REVIEWER removes it when a verdict is delivered, whichever way the
  verdict went: on request-changes the work has returned to the author,
  and a second reviewer must not spend a cycle on it. The author
  re-applies it when the fix commits are pushed.
- Its ABSENCE on an open item means "still in flight" — do not spend
  review effort.

**Removing it is NOT a readiness signal.** The draft flag is the only
readiness signal, so "label off, still draft" is the normal mid-cycle
state. State this explicitly in reviewer briefs: automated review of
agent actions has misread the removal as a merge-readiness flip and
raised a warning on a correct action.

**Never claim complete-from-author when it is not.** Applying the label
on a knowingly incomplete round burns a reviewer's cycle on work you
already know will change. Holding the label and escalating is correct.

## 9. Escalation, and deferred work

An executor that judges a round too large to land coherently, or that
reaches a decision about scope, lane ownership, or weakening a check,
STOPS and reports a proposed split. It does not take the decision. A
gate that correctly blocks you is diagnosed and reported, never weakened;
a false assumption in the brief stops that thread rather than being
silently patched.

Deferred work is not "left out". It is filed as tracked issues, stated in
the PR body AND in any runbook a reader might reach, and — where the
mechanism allows — enforced by the tool itself refusing the unauthorised
path. A deferral invisible at the point of use is not a deferral.

## 10. Findings from peers, and findings from scanners

**Peer findings are evidence to VERIFY, never authority.** Reproduce the
claim before acting on it: peers pin heads that go stale, and a peer can
be right about the shape and wrong about the severity, or the reverse.
Fix what verifies; rebut in-thread, with evidence, what does not. No flip
and no merge ever rides on a peer approval.

**Code-scanning alerts must be read from the source, every review.** They
are NOT in the PR body, and advanced-security review objects can have
EMPTY bodies — a reviewer that enumerates reviews sees nothing at all.
Query both, for the merge ref:

```
gh api repos/<owner>/<repo>/commits/<sha>/check-runs \
  --jq '.check_runs[] | select(.name=="CodeQL") | .output.summary'
gh api "repos/<owner>/<repo>/code-scanning/alerts\
?ref=refs/pull/<N>/merge&state=open"
```

Read the BODY, not the title and not the colour — verdicts have declared
"no real problem" from a check title while high-severity alerts sat in
the summary. And a "false positive" can still be pointing at a real hole:
drive the code it flags with the inputs it implies before dismissing it.

Two aggregate states, two different meanings, and neither is a formality:

The aggregate pull-request alerts check is distinct from each per-language
analysis check: the aggregate reports alert comparison, while an analysis job
can fail on configuration, extraction, build, or upload before it produces
alert evidence. Name which layer failed or passed rather than calling both
simply "CodeQL".

- **A RED aggregate means REAL ALERTS.** There is no "aggregation race".
  That diagnosis has been advanced, relayed unchecked, and then disproved
  by sweeping every pull-request head in a repository: the failures all
  landed on the one pull request whose diff produced genuine findings,
  and the analysis upload preceded the check at every head. Read the
  summary and the alerts API and fix what is there; never rerun, reopen,
  or re-push a reviewed branch to make a red aggregate go away.
- **A `neutral` aggregate saying it "cannot determine the alerts
  introduced by this pull request" means the change was NEVER FULLY
  ANALYSED** — a configuration present on the target branch produced no
  analysis for this head. A missing configuration warns INSIDE a neutral
  check; it never turns one red. "Zero alerts" from that state is weak
  evidence: name the analyses that actually ran, and say plainly that the
  others did not.

## 11. CI green describes the base it ran against

A PR's checks and its merge ref describe the base they were computed
against. When the target branch advances, both can describe a base that
no longer exists. Re-derive merge-cleanliness against the CURRENT target,
and where it matters materialise the merge and run the gates on the
result: a clean textual merge does not imply a green one, and two
independently correct PRs can compose into a broken state — a positional
patch meeting a newly appended item is the standard example.

## 12. The deployed object is the ground truth

Every repository-side gate — render, policy test, mutation matrix,
structural pin — SIMULATES what the cluster or runtime will do. They are
necessary and they are not sufficient. When a change is deployable, the
acceptance evidence is the LIVE rendered object, diffed against a
prediction written down FIRST, with every difference accounted for,
including what the platform adds on its own (defaults, admission
mutations, generation, status). Predict, capture, diff — capturing and
then rationalising is not a test. If the change cannot be deployed yet,
say so and name the precondition; never present a render as a live
result.

### Destructive recreation of declared ephemeral workloads

Treat ephemerality as an explicit repository-owned classification, never as a
property inferred from a Kubernetes kind, controller, namespace, or current
lack of data. Design a declared-ephemeral workload so its complete desired
state can recreate it from immutable inputs; this method does not grant live
authority, classify an object, or override a repository's protected sets.

Before opening a destructive acceptance lane:

1. Obtain task-specific live authority and freeze the transaction packet.
   Record the exact pre-inventory and pre-state; an explicit allowlist of API
   group, kind, namespace, and name for every target; current live identities;
   and immutable hashes of desired-state manifests, images, configuration, and
   deployable artifacts. Treat an unlisted object as protected.
2. Prove dependencies without reading protected values. Inspect metadata-only
   Secret references and key names, never Secret data. Hard-exclude tokens,
   Secrets, SOPS or age material, private keys, etcd and control-plane PKI,
   DNS and Tunnel/provider identities, routes and recovery custody, and Git
   refs or history.
3. Classify persistence separately. StatefulSets, PVs, PVCs, databases, and
   operators never enter this method's deletion allowlist. Bind retention and
   reclaim behavior, backup and restore evidence, operator-owned dependants,
   and the exact data-loss boundary to document their support, but protected
   durable state never inherits ephemeral deletion permission.
4. Predict availability, expected downtime, readiness, and recovery-time
   objective before execution. Define a bounded rollback or clean redeploy and
   the stop conditions that trigger it.

Run one serialized live lane. Delete only the frozen exact object allowlist;
never use namespace-wide, wildcard, label-selector, or `all` deletion. Measure
observed unavailability and readiness, then reconcile from the frozen desired
state and hashes. Abort on identity drift, an unexpected dependant, missing
input, secret-data access, or any out-of-allowlist effect.

Accept the drill only when every target returns to its predicted desired state,
the residue and orphan check is empty, durability checks pass, and measured
availability/RTO meets the prediction. For public connectors or sites, also
revalidate public HTTPS status, DNS answers, certificate identity, and the
canonical-body contract. Record every difference and close the lane; a render,
written plan, or this doctrine alone is never live acceptance evidence.

## 13. Publication: a PR comment is public

On a public repository, a PR comment is publication. When a review finds
a working way to silently disable a control that is NOT YET FIXED, post
the finding, the affected file, and the correction — and withhold the
copy-pasteable reproduction until the fix lands, saying so plainly
("reproduced; recipe held until the fix lands") and giving the detail to
the coordinator instead. Weigh it honestly: if the mechanism is already
derivable from the public tree and upstream documentation the marginal
disclosure is small, but the default is to withhold. The same rule keeps
hostnames, addresses, machine identifiers, and workspace paths out of
every comment.

## Non-goals

No credential acquisition/storage, no protected-branch or server-setting
mutation, no merge/Ready self-service, no live provider/cluster authorization,
no secret/key/ciphertext deletion, no tag rewriting, and no evidence fabricated
from commands that were not executed.
