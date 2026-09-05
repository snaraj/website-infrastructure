# ADR 0014: Immutable container release versioning

- Status: Accepted
- Date: 2026-08-09

## Context

A full Git commit and an OCI digest are precise machine identities, but neither
is a useful human release name. The two Go services embed their independently
built Svelte frontends, so the versioned product is each final multi-platform
container graph rather than a standalone JavaScript package. A release layer
must add understandable `v0.x.x` names without weakening digest-only
deployment, allowing a mutable alias, or granting CI permission to write Git.

## Decision

Each site owns one committed stable SemVer file:

- `websites/naranjo.online/VERSION`
- `websites/lidersea.com/VERSION`

The file contains `MAJOR.MINOR.PATCH` without a `v` prefix. Prerelease/build
metadata, leading zeros, ranges, partial versions, and floating aliases are
rejected. The publication tag adds the conventional prefix, for example the
file `0.2.1` produces `v0.2.1`. The sites do not share a release counter.

`release-policy.env` holds an independent, reviewed production-graduation gate
for each site. While a gate is `no`, that site's committed version must remain
major zero. Graduation is one deliberate PR that changes the selected gate to
`yes` and moves its version to `1.0.0` or later. A graduated site's current
VERSION cannot return to major zero, although a verified historical v0 digest
may still be selected during rollback.

A pull request that changes a site's Docker build inputs or release lane must
strictly increase only that site's version. Changes to shared image verification
or publication tooling require both versions to increase. CI compares with the
exact pull-request base commit using read-only history; it never uses
`pull_request_target`, a write token, or untrusted shell interpolation.

Protected-main publication builds the amd64/arm64 OCI graph once, verifies and
scans that exact digest, and then exposes two immutable names for that same
graph:

- `sha-<full-40-character-Git-commit>` for source-level traceability;
- exact `vMAJOR.MINOR.PATCH` for human release history.

Repository tag listings are advisory only. Immediately before every full-SHA
write, the publisher directly resolves that exact destination: the same digest
is an idempotent retry, a different digest is a stop, and only the
checksum-pinned ORAS client's byte-exact not-found line for that same canonical
reference, exit status 1, and empty stdout prove absence. The stable tag uses
the same direct resolve-before-create rule. Every other registry,
authentication, transport,
proxy, partial-output, or differently scoped response stops the release. The
full-SHA name uploads the graph so its digest can be signed and attested; only
after those checks pass is the stable SemVer name added. Both names are then
resolved and must equal the
scanned digest. No `latest`, major-only, minor-only, branch, or environment
alias is produced.

Manual dispatch selects a separate read-only job with only `contents: read` and
`packages: read`. It does not build, publish, tag, sign, attest, or upload
evidence. It requires the full-SHA and stable names to already exist at the same
digest and verifies the existing keyless signature identity. A deleted name is
an incident and cannot be recreated by manual verification.

The image config records `org.opencontainers.image.source`,
`org.opencontainers.image.version`, and `org.opencontainers.image.revision`.
Uploaded non-secret release evidence binds site, image, unprefixed version,
exact version tag, full Git SHA, and digest alongside the per-platform SBOMs.
Signature and provenance verification continue to address the digest.

Kubernetes values remain digest-only. `promote-image.sh` requires an explicit
site, stable version tag, and digest, resolves the version tag to that digest
before and after signature/provenance checks, requires both platform configs to
bind that version and one full Git revision, then edits only the selected
Flux HelmRelease's digest and readiness override in an ignored candidate. The
transaction directory is mode-restricted on POSIX; on Git Bash/NTFS it inherits
the operator's ACL. It contains no credentials. Runtime tunnel Secrets are
created on the cluster by an owner ceremony and are not part of the transaction
or repository. The candidate still requires the checkout's access protection.
It emits a bounded patch plus a hash-bound evidence record, proves that patch
applies cleanly, and leaves the worktree unchanged. The operator reviews and
applies that patch explicitly; the verifier never races an editor by replacing
the live file and never stages, commits, pushes, or deploys. Chart defaults stay
at their fail-closed sentinels, and both the HelmRelease and parent
Kustomization remain suspended. A registry tag is therefore an operator index,
never the deployment or admission identity.

Rollback uses the same verifier with an explicit `--rollback` mode only after a
separate reviewed change has suspended both Flux layers. That mode requires an
already-promoted readiness gate, a nonzero current digest, and a retained tag
strictly older than the tracked current `VERSION`; its candidate changes only
the digest and preserves both suspensions. Resuming reconciliation is a later,
separately reviewed transaction after release and runtime evidence pass.

## Release procedure

For a pre-production site, choose the next version according to impact:

- increment PATCH for a compatible fix or rebuild-worthy release-policy change;
- increment MINOR for a compatible feature;
- keep major zero until the production decision is reviewed.

Edit only that site's VERSION in the same PR as its changed release inputs.
Shared release-tool changes require both VERSION files to move. After protected
main publishes and verifies the mapping, promote with:

```text
scripts/promote-image.sh <naranjo-online|lidersea-com> v0.MINOR.PATCH sha256:<digest>
```

The command prints an ignored `.artifacts/promotion.*` directory containing the
original snapshot, candidate, effective values, `promotion.patch`, and
`evidence.env`. Review their hashes and patch, run `git apply --check` again,
then apply the printed patch explicitly and rerun repository/transition checks.
Remove the ignored review directory after the PR evidence is no longer needed.
The shell wrapper is supported on Linux or Git Bash with GNU `sed` and
`sha256sum`; default macOS/BSD userland is not an accepted verification
environment.

To graduate one site, review its production readiness, change only its gate in
`release-policy.env` from `no` to `yes`, set its VERSION to `1.0.0` (or a later
reviewed stable version), and merge through the same protected-main path. Never
create or move the OCI tag manually.

## Consequences

This repository provides the release behavior that a language-specific
releaser would normally supply, while keeping the combined Svelte/Go image and
its existing scan/provenance pipeline authoritative. It deliberately does not
create Git tags or GitHub Releases: doing so would require `contents: write` and
introduce a second release authority. Those features may be proposed later in a
separate ADR if their benefit justifies that permission.

Registry administrators can still mutate package metadata outside this
workflow, and the OCI Distribution tag API provides no client-side atomic
create-if-absent guarantee against a concurrent administrator. Per-site
workflow concurrency serializes cooperating publishers; direct resolution
narrows the remaining creation race but cannot eliminate that external trust
boundary. Registry-side immutable-tag enforcement is required wherever the
provider offers it; its verified availability or absence is a registry control,
never an assumption made by this client. Promotion therefore distrusts the tag,
resolves it at each evidence
and finalization boundary, verifies
digest-bound version/revision labels, and deploys only the signed/attested
digest. Any deletion or reassignment is an incident; the remedy is
investigation and a new version, never recreating or overwriting the old name.

References:

- <https://semver.org/>
- <https://github.com/opencontainers/image-spec/blob/main/annotations.md>
- <https://oras.land/docs/commands/oras_repo_tags/>
- <https://oras.land/docs/commands/oras_tag/>

## Amendment (2026-08-10)

With the website extraction complete, the `websites/*/VERSION` authority files
named above moved to the standalone site repositories, whose tag-triggered
publishers now enforce this ADR's three-way tag/VERSION/chart lock in their
own CI. The promotion command shape and every immutability rule here remain
authoritative for this platform's digest-promotion path.
