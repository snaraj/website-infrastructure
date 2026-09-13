# Platform source releases and dependency queue

## Scope and authority

This runbook implements issue #164. It changes source-release bookkeeping only:
it grants no merge, tag, live-system, provider, cluster, deployment, or settings
authority. The owner alone merges. GitHub Actions may create only the annotated
platform source tag and immutable Release with its exact signed identity asset
pair after the protected-main checks and settings proofs pass. `v0.1.40` is the
sole zero-asset transition predecessor; it is never the format for a new
release.

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
The validator refuses more than 1024 platform tag refs before performing the
adjacent-edge walk, so a corrupt or unbounded inventory cannot consume the
entire 30-minute publication window.

For an untagged successful main SHA, the publisher:

1. fetches public tags without persisted checkout credentials;
2. validates the complete post-floor ledger;
3. requires the latest tag and immutable Release to be exact, consuming the
   canonical identity asset pair after the one-time `v0.1.40` bridge, except
   for the exact burned `v0.1.42` to `v0.1.43` recovery described below;
4. requires exactly one newly added fragment since that predecessor;
5. derives `next = latest patch + 1` without reading `VERSION`;
6. renders deterministic notes containing the source SHA, fragment path,
   fragment SHA-256, and exact fragment Markdown; and
7. reuses, resumes, or creates only the exact annotated tag, canonical identity
   JSON, detached Sigstore bundle, and immutable Release through the existing
   closed REST transaction.

The bounded GET-only predecessor wait finishes before the short-lived
Administration-read token is minted. The immutable-release setting is therefore
proved after ordering and immediately before the write job. That job rebinds the
window once and revalidates the exact predecessor tag and Release before every
mutation boundary; renewed pending, absent, mutable, or foreign state fails.

`v0.1.41` and `v0.1.42` are closed pre-Flux publication incidents. Their exact
annotated tags remain immutable ledger boundaries. The sole `v0.1.42` to `v0.1.43` edge may
observe the predecessor Release as absent. In the write job only, the publisher
enumerates the complete authenticated Release inventory, accepts either the
exact known signed two-asset `v0.1.42` draft or its clean absence, validates its
source, tag object, tree, workflow attempts, asset IDs, bytes, digests, signature,
and shared staged download token, then deletes only that exact draft Release ID.
It proves both draft absence and the unchanged annotated tag before creating
`v0.1.43`. The successor still requires fresh protected-main CI, a new exact
annotated tag, two signed identity assets, and an immutable published Release.
Every later edge returns to the ordinary complete-predecessor rule.

Historical v1, v2 and v3 identity assets remain immutable and are verified under
their original schemas and publisher subjects. `v0.1.77` is the terminal v2
release. Its exact successor begins v3, whose signed identity records only the
platform source, repository object, predecessor, tag, immutable Release and
successful workflow attempts. Application selections live in
`snaraj/platform-k8s-infra`; v3 therefore carries no selector or site payload.

An exact existing tag at the source is an idempotent replay. A lightweight,
skipped, reversed, moved, foreign, or non-ancestral tag; a missing earlier tag;
or a tag/Release metadata mismatch is burned/conflicting state and fails.

## Rapid merges

Publisher workflows keep exact-SHA concurrency identities. If main SHAs A, B,
and C arrive before A is published, A sees one fragment and may publish; B sees two
and returns the distinct pending status; C sees three and does the same. Each
later workflow fetches tags and retries only that pending status. Once A's exact
tag and immutable Release both exist, B derives the next patch; once B is exact,
C does. Outside the exact burned `v0.1.42` recovery edge, a tag without its
exact Release remains pending and cannot allocate the next patch. Unsafe ledger
states are never retried as contention. A bounded timeout fails the workflow
without allocating or moving a tag. For historical v1/v2/v3 execution, the exact
SHA can be rerun normally. Ordinary v4 additionally requires the workflow SHA,
execution SHA and released source SHA to agree. A later main merge can make
the `workflow_run` context differ from the earlier source; that publication
fails closed even if its source CI succeeded. Keep main at the intended
executor while completing the recovery below and its ordinary successor.
This repair does not authorize a general replay of later sources. If main
advances and equality cannot be restored without changing immutable history,
stop delivery for a separately reviewed forward repair.

Within that bounded wait, the expensive ledger result is cached only while the
complete `refs/tags/v*` ref name, tag-object ID, and peeled target snapshot is
byte-identical. A created, retargeted, or replaced tag changes the key and forces
full validation before the next REST read. A Release-only state change leaves
the validated Git ledger unchanged and repeats only the exact GET classifiers.

## Finite historical-source recovery

Issue #369 admits exactly three consecutive protected-main sources after the
immutable `v0.1.80` checkpoint. The ledger derives their next patches; the table
does not allocate tags. Both original workflow attempts must still be completed
and successful, and every original workflow file, tree, parent and fragment
must match the frozen policy in `platform_release_epoch.py`.

| Source | Original main CI / CodeQL (attempt 1) | Fragment |
| --- | --- | --- |
| `060c9678e130487b27cdaec395b0f1c5d74b9240` | `34283118915` / `34283118636` | `362-obsync-private-boundary.md` |
| `9cd79f1e69cfa00eb5467822831056101629c8f8` | `34305321734` / `34305321809` | `365-obsync-staged-readiness.md` |
| `3b7a0532ba5fe2f10037023f3e26ec5876f8d191` | `34638257426` / `34638258315` | `367-reserved-file-storage.md` |

The current protected checkout executes the repair; the historical trees are
data. A no-input `platform-release-recovery.yml` dispatch selects the oldest
incomplete edge once and binds its source, tag, predecessor, executor, repository
object, run ID, attempt and executor CI in a canonical receipt. Every later job
rechecks that receipt, original source CI, successful current-executor main CI
and CodeQL, the current main ref, and the complete immutable predecessor. A
fresh dispatch cannot overtake a still-running original publisher. Only attempt
1 is admitted; rerunning jobs cannot borrow an earlier settings attestation or
selection. Dispatches share one non-canceling concurrency group.

New v4 identity assets keep original source/main-CI fields separate from
`execution.source_sha`, `execution.tree_sha`, `execution.main_ci` and the actual
publisher run. The external tag policy selects the recovery signing subject
only for those three exact edges. Later ordinary releases use the ordinary
subject and require source/executor equality; downloaded identity fields cannot
select another trust root. The v1/v2/v3 schemas and existing immutable bytes are
unchanged. Source CI and publisher attempts are verified through exact
attempt-specific API records, including the original attempts named by the
terminal checkpoint.

After owner preparation of the exact annotated tag, recovery creates a draft with only
`tag_name`, `name`, `body`, `draft:true` and `prerelease:false`. It omits
`target_commitish` and requires GitHub's returned default-target hint to be
exactly `main`; the tag object and peeled commit bind the historical source.
The notes PATCH contains only `body`; the publish PATCH contains only the
selected `tag_name` and `draft:false`, with no `target_commitish`. A staged
record may expose the canonical tag or GitHub's temporary `untagged-<20 hex>`
tag matching both staged asset URL tokens. The signed intended tag and exact
annotated object remain fixed; final immutable validation accepts only that
canonical tag and its final asset URLs. Before and after each Release or asset write, the publisher
rechecks the unchanged tag object, source, predecessor and selected executor.
An exact zero-asset draft may resume on a fresh dispatch. Partial assets,
foreign custody, a moved tag, a missing settings proof or permission refusal
stop delivery. No token-scope expansion or automatic tag fallback is permitted.

### Owner-prepared historical tags

Only the owner may prepare the next exact annotated tag for this closed window:

| Tag | Historical source |
|---|---|
| `v0.1.81` | `060c9678e130487b27cdaec395b0f1c5d74b9240` |
| `v0.1.82` | `9cd79f1e69cfa00eb5467822831056101629c8f8` |
| `v0.1.83` | `3b7a0532ba5fe2f10037023f3e26ec5876f8d191` |

This exception becomes operative only after owner merge of its reviewed source
and successful exact-executor main CI and CodeQL. Before each owner action,
independently verify a single-edge packet against the existing frozen source,
parent, tree, fragment, original main/CodeQL attempts and current executor.
Require the exact immutable predecessor and current tag protections, no active
publisher for the edge, and an absent ref and Release. Use the canonical
`prove_trees`, `prove_ci`, `prove_release` and `validate_tag_record` checks;
tag existence and a successful job alone are insufficient evidence.

The packet fixes the annotation object hash, exact source, message
`Platform release <tag> from <source>`, existing release-tagger constants and
source committer instant. The owner may reuse a verified exact dangling object
or prepare that exact object, then create only the single absent tag reference.
The owner remains the API actor; annotation metadata does not claim a bot action
or a signed tag. Agents never create tag objects or refs. No temporary branch,
lightweight tag, force update, deletion, credential or protection change is
permitted. The owner must not create the Release or its assets. A permission
refusal or ambiguous response stops for authoritative readback, never a retry.

Read back the exact annotation/ref, compare the packet's object hash and peeled
source, require Release still absent, and fetch the exact tag for local/API
object equality. An already prepared exact tag is verified without another
write. Prepare and verify refuse a missing or inexact tag before privileged
jobs; the publisher independently refuses before either tag-creation POST.
An unreferenced annotation object alone does not meet the prerequisite.
Recovery retains all original-source/executor CI, first-attempt, settings,
OIDC, immutable two-asset and original-publisher proofs. Only after a completed
immutable release may the owner prepare the next edge. This is not a general
tag-creation exception and does not extend to later ordinary releases.

After owner merge and successful exact-executor main CI and CodeQL:

1. Keep main at that executor. Confirm the prior dispatch is terminal and there
   is no incomplete publisher proof. Do not rerun any of the frozen old
   workflows: their source cannot acquire this repair. Complete the exact
   owner-prepared tag prerequisite above for the oldest incomplete edge.
2. Dispatch the no-input recovery workflow at `main` once. The Actions REST
   dispatch endpoint, using API version `2026-03-10` and body `{"ref":"main"}`,
   returns the new `workflow_run_id`; bind the returned ID, attempt 1, main
   SHA and workflow path before following its jobs. A lost response requires
   readback of matching dispatch runs, never an immediate duplicate POST.
3. Require all jobs to succeed, then independently read back the selected
   annotated tag, immutable non-draft/non-prerelease Release and exact two
   assets. Verify downloaded size/digest/canonical identity, Sigstore subject,
   issuer and actual executor SHA/event, plus all signed original run attempts.
   Only completed success makes this edge a predecessor. Repeat steps 1–3 for
   the next edge, at most three dispatches with actual publications.
4. When the three predecessors are complete, let the ordinary publisher for
   the repair's own source finish. If its bounded predecessor wait already
   timed out, rerun that whole repaired-source workflow so every proof job
   executes again. Do not use a failed-jobs-only rerun. Require the same final
   tag, identity, original-attempt and immutable-Release readback.

An immutable asset may become visible before its original publisher finishes.
A reader waits for that exact attempt; a failed, cancelled, missing or unknown
original attempt is a terminal delivery hold. A later successful dispatch or
rerun cannot replace the signed attempt or rewrite immutable bytes. This scope
has no settlement-proof extension. Local modeled pass/deny checks and review
permit source Ready; the first protected execution proves actual ordinary-token
provider capability. No source release implies storage qualification, live
deployment, application promotion or device acceptance.

## Dependency queue contract

Parallel work is a directed queue, not a shared patch-slot reservation:

- every dependent Draft PR states exact `Depends on PR #N` lines and its issue
  carries the matching native relationship;
- independent branches target `main`, use distinct issue-namespaced fragments,
  and publish their intended merge order;
- a predecessor merge triggers current-base and composed-merge checks plus
  refreshed review evidence where claims changed, but never a replacement PR
  solely because release metadata advanced. The owner may select GitHub's
  [**Update branch → Update with rebase** control](https://github.blog/changelog/2022-02-03-more-ways-to-keep-your-pull-request-branch-up-to-date/)
  to refresh the published branch; that creates a new head and invalidates all
  prior checks and receipts. Agents never invoke this owner action, rebase the
  published branch, or force-push; and
- a fresh branch/replacement PR is required only for a real semantic dependency,
  code conflict, current-main repair, unavailable/conflicting rebase update, or
  owner decision not to rewrite the PR head. Port only the residual diff.

When the supplied base is no longer an ancestor, the release gate denies with
`release head does not descend from the exact current base; request an
owner-operated GitHub rebase update or create a fresh branch` rather than a raw
Git subprocess error.

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
