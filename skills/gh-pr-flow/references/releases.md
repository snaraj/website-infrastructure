# Release consequence for every protected-main merge

## Contract

Every merge has a repository-defined immutable consequence. Application repos
usually advance one SemVer patch across committed version/chart/image/changelog
locks and publish signed artifacts. Platform repos may publish a versioned
source tag and GitHub Release. Neither consequence implies live deployment.

Plain tags are `vX.Y.Z`. A runtime reference such as
`image:vX.Y.Z@sha256:<digest>` contains a plain tag plus immutable digest; the
combined reference is never itself a tag.

One packaging ecosystem may require a narrower representation. For Helm OCI,
the chart `version` and registry tag stay numeric `X.Y.Z` because Helm requires
the tag to equal valid chart SemVer and rejects a leading `v` as SemVerV2.
This exception must be explicit, source-locked, workflow-enforced, and tested;
it never permits numeric Git/image tags or calling `tag@digest` a tag.

## Per-PR transition

Each PR—including docs and dependency automation—moves exactly one patch from
its current protected base, or uses an equally strong repository automation
that keeps committed source truthful. When rebase integration is enabled, the
entire reviewed base..head chain must be merge-free and every intermediate
`VERSION` state must either retain the prior value or advance exactly one patch;
there must be exactly one boundary in the range. Reject skips, reversions,
transient future values, and merge-bearing topics whose rebase outcome cannot
obey the same state machine. Squash remains valid because its installed single
commit preserves the exact final boundary. A base move invalidates the
transition. Concurrent PRs may propose the same next patch only while Draft;
after one lands, every survivor resyncs on a fresh branch and takes the new
patch.

## Success-only exact-SHA publication

Publish only after the repository's main CI succeeds for the exact merged SHA.
GitHub documents that token-created refs do not recursively trigger ordinary
push workflows; use an explicit supported dispatch when chaining is required.
`workflow_run` fires regardless of conclusion and carries default-branch
context, so verify conclusion/event/branch/repository/workflow and explicitly
checkout payload `head_sha`.

Use the same complete-history monotonic state machine for main validation and
publisher recovery. Discover the latest retained patch boundary only after
proving every earlier state; never infer an expected version from transient
endpoints alone. Test no-version initialization, the bump at every position in
a multi-commit rebase, squash, skips, reversions, transient future versions,
and post-boundary commits. Any main SHA that passes must map to exactly one
publisher-recoverable release intent.

Do not use generic concurrency ordering as a release ledger. Distinct main SHAs
must have independent paths and unique immutable versions. Deduplicate only the
same SHA/tag. Test two and three rapid merges, out-of-order completion, duplicate
same-SHA events, stale events, wrong head/base, and event/permission identities.

Give every required audit workflow an explicit concurrency identity whose
protected-main component is the exact source SHA. PR-number cancellation may
collapse superseded review runs, but a branch/ref-only key must never let one
main SHA cancel another; deduplicate only the same SHA. Give every workflow job
an explicit, reviewed, positive `timeout-minutes` bound. Treat a timeout as a
failed attempt under the same exact retry and burned/conflicting-state rules,
not permission to skip verification or allocate a second identity silently.

## Immutable and partial state

Before creating anything, classify each tag/artifact/release as:

- **absent:** authoritative absence proven; safe to create;
- **complete:** exact target/source, signatures, provenance, SBOM/attestations,
  chart/source, notes and metadata match; safe to reuse;
- **resumable:** exact immutable prefix exists and the only missing suffix can
  be completed without rewriting;
- **burned/conflicting:** any foreign target, ambiguous lookup, partial evidence,
  mismatched notes/digests, or unprovable state; fail closed.

Never overwrite or reassign an immutable tag. Record a recovery issue and use a
new patch when safe completion is impossible. Validate permissions and exact
identity; preserve existing signer/provenance policies.

A GitHub Release is called immutable only when the repository's authoritative
immutable-release control is enabled before publication and the exact Release
REST record reports immutable state. Bind that server control into the Ready
receipt, recheck it before mutation, and reject mutable, draft, prerelease,
or foreign-author records. Enforce the repository's exact closed asset
inventory; unexpected or partially verified assets fail closed. Repository
code and prose cannot substitute for the server control.

Immutable Releases still permit title and notes edits, so treat human notes as
informational, never as the immutable identity of an external artifact. A
source-only platform Release that claims no external artifacts may require an
exactly empty asset inventory. If a Release identifies images, charts, packages,
or binaries, instead create one deterministic machine-readable manifest under
mode 0600 containing source SHA, version/tag, exact artifact refs and digests,
signer/workflow identity, and SBOM/provenance expectations. Checksum its exact
bytes, upload it to a draft, then publish. Verify exact asset name, count, size,
digest, content, and no extras; test absent/partial/create-race/retry/burned
states. Never rely on mutable notes to bind external artifact digests.

Official references:

- <https://docs.github.com/en/actions/concepts/security/github_token>
- <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run>
- <https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency>

## Deployable artifact vulnerability and alias contract

For a repository that publishes a deployable image, chart, package, or binary,
install the scanner at a checksum-verified immutable version. Scan source,
filesystem dependencies, and configuration in PR CI; scan the final artifact
by its exact digest before classifying publication complete. Gate reviewed
HIGH/CRITICAL policy, make every ignore explicit and bounded, and schedule a
full re-scan (or an equivalently enforced recurring audit). Mutation tests must
delete/bypass the scan, weaken severity, and retarget the digest. If an artifact
was already pushed when scanning fails, classify the version burned/conflicting;
never overwrite, delete, or adopt it.

Treat a registry digest as the immutable trust anchor and a registry tag as a
verified mutable alias. Never call a registry tag immutable without an
authoritative registry control. Deploy `tag@digest` only after trusting the
digest, and run a recurring alias/signature/attestation/chart-digest audit
against the immutable Release record. Alias drift is a hard stop and recovery
issue/new patch, never permission to retarget or adopt the tag.
