---
name: gh-pr-flow
description: Reusable GitHub PR flow for agents and humans in any repository owned here — clean-worktree branching from origin/main, allow/deny rules for branch names and push refspecs, pre-push validation, single detailed PR, and evidence collection. Contains no credential logic. Use for every branch/commit/push/PR cycle.
---

# gh-pr-flow

A repository-agnostic PR flow. Enforceable rules live in
`scripts/validate_pr_flow.py` with allow/deny contract tests in
`tests/security/test_pr_flow_contract.py`; this skill is the procedure
around them. It never acquires, prints, or stores credentials, and it is
not a substitute for server-side rulesets.

## 0. Identity preconditions (hard stops)

- `gh auth status` must show the dedicated non-admin machine identity.
  The repository owner's identity in an agent context is a hard stop.
- Commit author/committer emails and every trailer email must satisfy the
  publication-history metadata rule (`.invalid` or GitHub noreply forms
  only) — see the repository's validators; a real-domain address anywhere
  in metadata will fail the pre-push gate.

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
review caveat — author and any reviewing agent are distinct dedicated
non-admin principals, and agent review is machine technical review, not an
independent human. The owner alone merges to `main`; import PRs merge via
merge commit, everything else squashes per repository convention.

## 5. Evidence to record per cycle

Base SHA, branch, commit SHAs, validation outputs (exact), push refspec
used, PR URL, check conclusions, and anything skipped with the reason.
"Done" claims separate executed-and-verified from written-but-not-run.

## Non-goals

No credential acquisition or storage; no provider mutations; no
force-recovery procedures (rollback is: close PR, delete own branch after
owner approval, or revert-PR for merged changes); no bypass of any
server-side protection.
