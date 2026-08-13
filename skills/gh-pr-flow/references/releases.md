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
that keeps committed source truthful. A base move invalidates the transition.
Concurrent PRs may propose the same next patch only while Draft; after one
lands, every survivor resyncs on a fresh branch and takes the new patch.

## Success-only exact-SHA publication

Publish only after the repository's main CI succeeds for the exact merged SHA.
GitHub documents that token-created refs do not recursively trigger ordinary
push workflows; use an explicit supported dispatch when chaining is required.
`workflow_run` fires regardless of conclusion and carries default-branch
context, so verify conclusion/event/branch/repository/workflow and explicitly
checkout payload `head_sha`.

Do not use generic concurrency ordering as a release ledger. Distinct main SHAs
must have independent paths and unique immutable versions. Deduplicate only the
same SHA/tag. Test two and three rapid merges, out-of-order completion, duplicate
same-SHA events, stale events, wrong head/base, and event/permission identities.

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

Official references:

- <https://docs.github.com/en/actions/concepts/security/github_token>
- <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run>
- <https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency>
