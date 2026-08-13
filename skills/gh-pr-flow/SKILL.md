---
name: gh-pr-flow
description: Reusable GitHub PR flow for agents and humans in any repository owned here — clean-worktree branching from origin/main, allow/deny rules for branch names and push refspecs, pre-push validation, single detailed PR, and evidence collection, plus the adversarial-review flow around it - author/reviewer/coordinator/owner authority, the review-request label, escalation, code-scanning alerts, base drift, live acceptance evidence, and the catalogue of ways a green suite lies. Contains no credential logic. Use for every branch/commit/push/PR cycle and every review of one.
---

# gh-pr-flow

A repository-agnostic PR flow. Enforceable rules live in
`scripts/validate_pr_flow.py` with allow/deny contract tests in
`tests/security/test_pr_flow_contract.py`; this skill is the procedure
around them. It never acquires, prints, or stores credentials, and it is
not a substitute for server-side rulesets.

## 0. Identity and credential preconditions (hard stops)

- Read the target repository's authority file before interpreting identity.
  `gh auth status` observes the already-configured principal; it neither
  supplies permission nor chooses which account ought to exist. A repository
  may deliberately authorize its owner account or may provision a dedicated
  least-privilege machine principal. This portable flow does not override that
  choice.
- Continue only when the configured principal and the requested operation are
  both authorized for the current task. An unexpected or unauthorized identity
  is a hard stop. Never acquire, extract, exchange, print, change, or repurpose
  credentials to satisfy this flow; a dedicated principal is a requirement only
  where the repository owner has already provisioned and required one.
- Commit author/committer emails and every trailer email must satisfy the
  target repository's publication-history metadata rule. Derive the accepted
  identity from that repository's authority and validators rather than assuming
  one portable email form.

## 1. Start clean, from current main

```
git fetch origin main
git status --porcelain            # must be empty
git switch -c <namespace>/<concern> origin/main
python3 -B scripts/validate_pr_flow.py branch "<namespace>/<concern>"
```

Branch names must pass the rule module (reviewed namespaces only; `main`
and malformed names are denied). For stacked work, base the sub-branch on
the integration branch instead of `origin/main` — everything else is
identical.

## 2. Author with inspection before every commit

- Review the exact diff (`git diff`), then the staged diff
  (`git diff --cached`) before each commit; commits are atomic with
  human-readable subjects.
- Run the repository's own validation for the change class plus
  `git diff --check`.

## 3. Gate before push

```
make pre-push-security            # binds the exact origin/main..HEAD range
python3 -B scripts/validate_pr_flow.py refspec "<branch>:<branch>" "<branch>"
```

Push ONLY the current work branch, same-name, never forced:

```
git push origin <branch>:<branch>
```

The rule module denies: force pushes, deletions, wildcards, tag creation,
pushing any protected branch, pushing a branch other than the one checked
out, and cross-branch refspecs. Tags and releases are never created from
this flow.

## 4. One detailed PR

Open exactly one PR for the branch with: purpose, baseline commit, scope
and changed files, threats/failure modes addressed, tests with exact
results, explicit exclusions, rollback path, residual risks, and the
review caveat — branch author and reviewer are distinct contexts, with the
reviewer independently reproducing evidence at the exact head in a disposable
worktree. A distinct GitHub principal is stronger when the owner has already
provisioned one, but it is not fabricated as a prerequisite. Agent review is
machine technical review, not an independent human. The owner alone merges to
`main`; import PRs merge via merge commit, everything else follows the target
repository's merge convention.

## 5. Evidence to record per cycle

Base SHA, branch, commit SHAs, validation outputs (exact), push refspec
used, PR URL, check conclusions, and anything skipped with the reason.
"Done" claims separate executed-and-verified from written-but-not-run.

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
- **Coordinator** — performs the readiness flip when this separate role is
  present, and only once review has cleared AND every check is green at the
  exact head, with no peer or owner comment outstanding. If no separate
  coordinator exists, the owner may perform that coordination action.
- **Owner** — alone holds merge authority. Acting as the coordinator fallback
  neither transfers that authority nor makes author and reviewer compatible.

Neither the author nor the reviewer performs the readiness flip. Flipping is
an assertion that review is complete, never "let the owner take a look".

A green check, a peer approval, and a ready state are EVIDENCE, never
authority. Draft means "not ready for the owner's eyes"; ready means the
coordinator asserts review is complete and every check passed.

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

No credential acquisition or storage; no provider mutations; no
force-recovery procedures (rollback is: close PR, delete own branch after
owner approval, or revert-PR for merged changes); no bypass of any
server-side protection.
