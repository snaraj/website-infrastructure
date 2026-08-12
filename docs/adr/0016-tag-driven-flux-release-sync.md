# ADR 0016: Tag-driven Flux release sync

- Status: Accepted
- Date: 2026-08-12

## Context

Two things about releases were true at once and could not both stay true.

The owner names releases with version tags — `v0.1.9` is what appears in
release notes, in an incident conversation, and in a rollback decision. But the
identity the cluster actually consumed was a raw content address: each site's
`HelmRelease` resolved its chart from a `GitRepository` tracking that site's
`main` branch, and the running image came from an `sha256` digest pinned by hand
into `kubernetes/websites/<site>/release.yaml` by `scripts/promote-image.sh`.

That produced three concrete problems:

1. **The official release identity was not the release name.** The chart the
   cluster ran was whatever `main` happened to point at, which is a moving
   commit, not a release. Nothing in desired state named `v0.1.9`.
2. **Publishing a release did nothing.** A tagged, signed, scanned release could
   sit in GHCR indefinitely; reaching the cluster required a human to run the
   promotion verifier and land a reviewed digest edit. GitOps described the
   desired state but did not follow the releases.
3. **The chart leg was unverified.** Images were verified twice over — cosign
   keyless signature, embedded SLSA provenance, Kyverno admission — but the
   chart arrived over anonymous Git with no signature check at all. The
   strongest link in the chain was guarding the wrong door.

The obvious fix — Flux image automation writing new digests back to Git — is
refused: it requires giving the cluster a Git write credential, which safety
invariant 5 and ADR 0003 forbid outright.

## Decision

**The official release identity is the version tag**, and the cluster follows
published releases automatically, without the cluster ever holding a credential
that can write to a repository.

### 1. The chart version IS the release

Each site's release publisher pushes a Helm chart to
`oci://ghcr.io/snaraj/charts/<site>` at the same `vMAJOR.MINOR.PATCH` version as
the image it built, signed by the same keyless workflow identity. The platform
tracks that chart repository with a bounded SemVer range, so publishing a
release is what deploys it. `kubernetes/websites/<site>/source.yaml` is now an
`OCIRepository` (`source.toolkit.fluxcd.io/v1`), and the site's `HelmRelease`
(`helm.toolkit.fluxcd.io/v2`) consumes it through `chartRef` rather than an
inline `chart` block. No site `GitRepository` remains; the connector chart,
which lives in this repository and has no release identity of its own, keeps
its Git source.

### 2. Digest integrity survives inside the chart

Tag-driven does not mean tag-trusted. The digest-only deploy invariant (safety
invariant 6) is preserved on both legs:

- **Publish time.** Each site's publisher embeds the exact image digest it just
  built, signed, and scanned into the chart it publishes under that version. The
  workload therefore still names `repository@sha256:...`, and the chart version
  and the image digest are produced by one run of one workflow and can never
  drift apart.
- **Reconcile time.** `spec.verify` is mandatory on every site chart source:
  `provider: cosign` with a single `matchOIDCIdentity` entry anchored to that
  site's exact publisher — `https://github.com/snaraj/<site-repo>/.github/
  workflows/release-publisher.yml@refs/tags/v*`, issuer
  `https://token.actions.githubusercontent.com`. source-controller refuses to
  produce an artifact from a chart that is unsigned, signed by the sibling
  site, signed by a different workflow in the same repository, signed under a
  branch ref, or signed under a different issuer. Flux then records the
  resolved artifact as `<tag>@<digest>`, so what ran is content-addressed even
  though a tag selected it.
- **Admission time.** The existing `require-signed-<site>` Kyverno policies are
  unchanged and still verify the image signature and SLSA provenance against
  the identical identity tuple. A chart and the image it names can never be
  accepted from different authorities.

The two site tuples never couple. Chart repository, SemVer range, certificate
subject, image repository, namespace, release name, and reconciler identity are
per site, and the shared validators compare each against its own tuple only
(safety invariant 14).

### 3. The SemVer range is a policy, not a convenience

`>=0.1.9 <1.0.0` for both sites today. Both bounds are load-bearing:

- The **lower bound is a ratchet**: it denies resolution to any release older
  than the last reviewed one. A deleted or administratively re-pointed newer
  tag cannot silently roll a site backwards, and a downgrade is a reviewed PR,
  not an accident. It moves forward only by review; it never moves down.
- The **upper bound is ADR 0014's production-graduation gate expressed as a
  Flux policy.** While a site's `release-policy.env` gate reads `no`, its range
  must exclude major 1 and later. `validate_repository.py` re-derives that
  binding from the tracked gate on every run, so the range and the gate cannot
  disagree silently.

`ref.tag` and `ref.digest` are forbidden on these sources: a fixed tag freezes
the site off the release train, and a mutable name would let the registry
decide what runs.

### 4. No git write-back, ever

Flux image-automation controllers (`image-reflector-controller`,
`image-automation-controller`) are NOT installed and are not part of this
design. The cluster holds no Git credential and no registry credential: chart
pulls are anonymous, `secretRef`, `serviceAccountName`, `certSecretRef`,
`proxySecretRef`, `insecure`, and non-`generic` provider are all denied on site
chart sources by policy. Automation flows one way — the publisher signs, the
cluster verifies and pulls. If a future need appears to make the cluster write
to a repository, it is an owner decision and a new ADR, not an implementation
detail.

### 5. Fail-closed transition plan

Nothing in this ADR activates anything. Every gate that was closed stays
closed, and each step below is separately authorized:

| # | Step | Repository | Authorized by |
| --- | --- | --- | --- |
| 0 | Desired state moves to tag-driven chart sync; `suspend: true` everywhere; sentinels retained | this repository | reviewed PR (this change) |
| 1 | Site publishers embed the built image digest into the published chart | site repositories | reviewed PR per site |
| 2 | Flux controllers installed on the cluster; `flux-system` egress to GHCR/GitHub opened inside the default-deny posture | platform lane | platform-stable signal, then owner |
| 3 | `spec.suspend` flipped to `false` on the parent `Kustomization` and the `HelmRelease` | this repository | reviewed PR, after step 2 |
| 4 | `values.deploymentReady` / `values.image.digest` sentinel removed from the platform once the chart carries the digest | this repository | reviewed PR, after step 1 |
| 5 | `promote-image.sh` demoted to a rollback/emergency-pin tool | this repository | reviewed PR, after step 4 |

The order matters and is not negotiable: the digest must exist inside the chart
(step 1) before the platform's own digest override may be removed (step 4), so
there is never a moment when no artifact carries the digest.

Until step 4, `spec.values.deploymentReady: false` and the all-zeros
`sha256:000...0` digest remain in each site's `release.yaml` exactly as before.
They are the state `validate_release_state.py` classifies as `initial`, the
state `policies/release-conftest` rejects, and the state `promote-image.sh`
advances under review. This ADR deletes no fail-closed guard: it adds the
chart-source contract beside the existing sentinel and re-points every
validator that described the old chart binding to the new one, with negative
coverage that is equal or stronger at each re-point.

### 6. The promotion path's future role

`scripts/promote-image.sh` and the `release.yaml` digest pin remain fully
operative and are unchanged by this ADR. They stay the mechanism for the
in-flight `v0.1.9` deployment. Afterwards their role narrows, deliberately
rather than by neglect:

- **Rollback and emergency pin.** When a published release must be overridden
  out of band — a bad release, a compromised tag, an incident — an operator
  verifies a specific historical digest and lands a reviewed override. That is
  a slower, louder, reviewed path than the sync loop, which is exactly right
  for the case where the sync loop is what you distrust.
- **Not the routine deployment path.** Routine releases flow through the
  publisher and the SemVer range. A digest edit stops being ordinary traffic
  and becomes a signal that something is wrong.

The registry-side immutability caveats recorded in ADR 0014 still apply and are
what the reconcile-time signature verification and the artifact digest defend
against.

### 7. Release notes

Site release notes lead with the version tag as the release identity and carry
the image digest as supporting metadata, matching what desired state now means.
This is recorded here so the cross-repository change is reviewable as one
decision; it is implemented in the site repositories.

## Relationship to prior decisions

- **ADR 0003 (Flux pull-based reconciliation)** is extended, not superseded.
  Its rules stand — no Git credential, no write capability, least-privilege
  reconcilers, cross-namespace references and remote bases disabled. It
  excluded image automation; this ADR keeps that exclusion and states why
  tag-driven sync does not need it. The controller set it names
  (source/kustomize/helm) is unchanged: `OCIRepository` is a source-controller
  kind already present in the pinned Flux export.
- **ADR 0014 (Immutable container release versioning)** is extended, not
  superseded. Its versioning, tag-immutability, and promotion rules remain
  authoritative. This ADR changes which of its outputs desired state consumes:
  the version tag becomes the deployment identity instead of an operator index,
  while the digest it binds remains the only thing that ever runs. Its
  production-graduation gate gains a second enforcement point in the SemVer
  range. The promotion command shape it documents is unchanged; only its role
  narrows, per section 6.
- **ADR 0010 (Go/Svelte/Helm)** is unaffected: the chart contents and their
  fail-closed defaults remain the site repositories' business.

## Consequences

**Gained.** Publishing a release deploys it. The name the owner uses is the
name desired state carries. The chart leg gains signature verification bound to
the same identity as the image leg. A downgrade, an unsigned chart, a
wrong-identity chart, and an ungraduated major are each denied by a specific,
tested rule rather than by nobody having tried.

**Given up.** A release now reaches the cluster without a per-release human
edit. That is the point, and it moves the review boundary: what is reviewed is
the publisher, the signing identity, and the range — not each deployment. The
compensating controls are the mandatory cosign verification, the ratchet floor,
the graduation ceiling, the unchanged Kyverno image admission, and the fact
that everything stays suspended until an owner-authorized PR says otherwise.

**Costs.** A published chart is a new artifact class the site repositories must
keep signed and correct. A site can no longer be deployed from a branch, by
design. The `flux-system` namespace needs egress to GHCR within the default-deny
posture, which is platform-lane work and a prerequisite for step 2.

**Not proven here.** No Flux controller runs in this repository's CI. The tests
that accompany this decision model the sync contract and pin the manifests'
semantics; they do not observe source-controller resolving a range or verifying
a signature. That distinction is stated in the tests themselves and is why
steps 2 and 3 above are separate, separately authorized events.

References:

- <https://fluxcd.io/flux/components/source/ocirepositories/>
- <https://fluxcd.io/flux/components/helm/helmreleases/>
- <https://fluxcd.io/flux/cheatsheets/oci-artifacts/>
- <https://helm.sh/docs/topics/registries/>
