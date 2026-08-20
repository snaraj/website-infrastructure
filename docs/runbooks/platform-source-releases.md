# Platform source releases and dependency queue

## Scope and authority

This runbook implements issue #164. It changes source-release bookkeeping only:
it grants no merge, tag, live-system, provider, cluster, deployment, or settings
authority. The owner alone merges. GitHub Actions may create only the annotated
platform source tag and immutable zero-asset Release after the exact protected-
main checks and settings proofs pass.

## One fragment per pull request

Every pull request adds exactly one path shaped
`changelog.d/<issue>-<lowercase-slug>.md`. The file is immutable after addition
and contains exactly one `### Added`, `### Changed`, `### Fixed`, or
`### Security` heading, a blank line, and one or more non-empty Markdown bullets.
The gate rejects an absent or second fragment, edits/deletions/renames of an
existing fragment, malformed names or bytes, workflow-expression openers, and
any change to root `VERSION` or `CHANGELOG.md`.

`VERSION` and `CHANGELOG.md` remain frozen historical records through `v0.1.9`.
They are not current release inputs and are not publisher-maintained outputs.
The one remaining code read of those paths is the exact frozen `v0.1.0`
recovery proof; it cannot select or describe a post-migration release.

The same exact-base transition runs on pull requests and protected-main pushes.
A squash commit and a merge-free rebase range are both valid when their complete
range adds exactly one fragment. The fragment may be committed anywhere in a
multi-commit range; the final main SHA is always the release identity.

## Tag-derived transaction

The immutable `v0.1.9` tag and its exact source SHA are the migration floor.
Legacy gaps before that floor remain historical and cannot influence new patch
allocation. From the floor forward, the contract requires every platform tag to
be canonical `vX.Y.Z`, annotated with the exact embedded name, source-bound
message, GitHub Actions bot identity, and source-commit date, exactly one patch
after its predecessor, and on one merge-free ancestral sequence. Every adjacent
post-floor tag boundary must also add exactly one valid fragment; a misplaced
tag can never consume two release intents or hide an earlier one.

For an untagged successful main SHA, the publisher:

1. fetches public tags without persisted checkout credentials;
2. validates the complete post-floor ledger;
3. requires the latest tag and its zero-asset immutable Release to be exact;
4. requires exactly one newly added fragment since that predecessor;
5. derives `next = latest patch + 1` without reading `VERSION`;
6. renders deterministic notes containing the source SHA, fragment path,
   fragment SHA-256, and exact fragment Markdown; and
7. reuses, resumes, or creates only the exact annotated tag and immutable
   zero-asset Release through the existing closed REST transaction.

The bounded GET-only predecessor wait finishes before the short-lived
Administration-read token is minted. The immutable-release setting is therefore
proved after ordering and immediately before the write job. That job rebinds the
window once and revalidates the exact predecessor tag and Release before every
mutation boundary; renewed pending, absent, mutable, or foreign state fails.

An exact existing tag at the source is an idempotent replay. A lightweight,
skipped, reversed, moved, foreign, or non-ancestral tag; a missing earlier tag;
or a tag/Release metadata mismatch is burned/conflicting state and fails.

## Rapid merges

Publisher workflows keep exact-SHA concurrency identities. If main SHAs A, B,
and C arrive before A is published, A sees one fragment and may publish; B sees two
and returns the distinct pending status; C sees three and does the same. Each
later workflow fetches tags and retries only that pending status. Once A's exact
tag and immutable Release both exist, B derives the next patch; once B is exact,
C does. A tag without its exact Release remains pending and cannot allocate the
next patch. Unsafe ledger states are never
retried as contention. A bounded timeout fails the workflow without allocating
or moving a tag; the exact SHA can be rerun normally.

## Dependency queue contract

Parallel work is a directed queue, not a shared patch-slot reservation:

- every dependent Draft PR states exact `Depends on PR #N` lines and its issue
  carries the matching native relationship;
- independent branches target `main`, use distinct issue-namespaced fragments,
  and publish their intended merge order;
- a predecessor merge triggers current-base and composed-merge checks plus
  refreshed review evidence where claims changed, but never a replacement PR
  solely because release metadata advanced; and
- a fresh branch/replacement PR is required only for a real semantic dependency,
  code conflict, or current-main repair. Port only the residual diff and keep
  published history immutable.

This is the queue expected for security issues blocked by #164: they may be
authored and reviewed in parallel, stay Draft while predecessors remain open,
and move one at a time under owner merge authority.

## Rollout and recovery

Issue #164 is the migration release and supplies its own fragment. Existing
Draft PRs that still edit `VERSION` or `CHANGELOG.md` must receive an additive
replacement/recut that removes those edits and adds one fragment before the new
gate can accept them. Their security implementation is otherwise independent.

A blind Git revert is deliberately insufficient: restoring the legacy gate
without its own valid legacy release transition must fail. Recovery is a
reviewed forward PR that restores the old code and simultaneously supplies the
release consequence required by the resulting head. Never move/delete a tag or
edit an immutable release to simulate rollback.
