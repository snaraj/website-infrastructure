# ADR 0016: Immutable release-driven Flux synchronization

- Status: Accepted
- Date: 2026-08-12
- Last amended: 2026-08-26

## Context

The platform must turn an owner-approved protected-main merge into a live
cluster change without trusting a floating branch, a movable registry tag, a
cluster-held Git credential, or a manual `kubectl apply`. The repository also
must not claim protection from software that is absent on the cluster.

Two release identities are involved and must remain distinct:

1. a **platform release** selects the exact repository tree Flux may read; and
2. a **site release** selects the exact signed OCI chart and workload image a
   site's HelmRelease may deploy.

The previous design used a branch or SemVer range as a runtime selector and
kept dormant Kyverno policy as a CI dependency even though Kyverno was not
installed. Those were not enforceable live controls.

## Decision

### 1. Platform releases are one closed identity chain

A platform release is accepted only when all of these identify the same
protected-main merge:

- the protected-main merge commit and tree;
- the successful required-CI head and workflow attempts;
- an immutable annotated `vMAJOR.MINOR.PATCH` tag and its peeled commit;
- the GitHub Release target;
- the canonical signed release-identity asset and detached Sigstore bundle;
- the digest-pinned selector image and its build-source provenance; and
- the GitRepository artifact revision plus both Kustomizations'
  `lastAppliedRevision` values.

The Release contains exactly two security assets:
`platform-release-identity.v1.json` and
`platform-release-identity.v1.json.sigstore.json`. Release prose is not a
security input. Moved, partial, skipped, reused, conflicting, or arbitrary tags
are rejected. The exact annotated `v0.1.41` and `v0.1.42` tags are documented
burned pre-Flux publication attempts: they remain immutable, have no Release,
and are never selected. Only the exact `v0.1.43` successor may cross the
`v0.1.42` missing-Release edge after the known signed mutable draft is validated
and retired. `v0.1.43` and every later selected version must carry the complete
two-asset immutable Release identity.
A release or rendered manifest by itself is not convergence.

### 2. The cluster reads public Git without credentials

There is exactly one public HTTPS GitRepository. It has no `secretRef`, proxy
credential, write-back controller, deploy key, or registry credential. Its
artifact is independently bounded by sparse checkout and ignore rules to only:

- `kubernetes/websites/naranjo-online`; and
- `kubernetes/websites/lidersea-com`.

Flux controllers, controller RBAC, admission/bootstrap objects, Cloudflare,
platform prerequisites, and every unrelated path stay outside this loop. Flux
does not reconcile its own installation or authority boundary.

### 3. Release selection is verified outside the self-loop

An owner-attended bootstrap installs a digest-pinned, credentialless selector
CronJob outside the GitRepository artifact. The selector may patch only the
named GitRepository's exact tag and reserved evidence annotations. It accepts
only the exact next patch release after independently verifying the protected
merge, required CI, annotated tag, Release, both signed assets, selector image,
and build provenance.

Namespaced RBAC restricts that patch to one object. A native
ValidatingAdmissionPolicy and binding independently restrict the selector
ServiceAccount to the same exact forward transition. The selector cannot
change the repository URL, ref type, credentials, artifact boundary,
finalizers, status, or unrelated annotations. Trusted-root and selector-image
rotation is a separate owner-attended, fail-closed transaction tracked by
issue #222; the selector never self-updates.

### 4. Two direct site reconcilers preserve tenant boundaries

There are exactly two Kustomizations, never an aggregate:

- `naranjo-online-reconciler` uses `naranjo-online-reconciler` and the Naranjo
  path; and
- `lidersea-com-reconciler` uses `lidersea-com-reconciler` and the Lidersea
  path.

Both declare `prune: false`, `force: false`, `deletionPolicy: Orphan`,
`wait: true`, and no dependency graph. Missing `serviceAccountName` fails
closed because the controller may impersonate only the two exact site
accounts, while each site account is authorized only in its own namespace.
The site's HelmRelease then uses a second namespace-local `helm-reconciler`
identity. This two-stage chain is mandatory.

Initial bootstrap accepts only an empty live source/consumer inventory or an
exact phase-consistent partial rerun of these objects. A legacy, foreign, or
extra source consumer is a read-only stop. Bootstrap never applies all of
`access.yaml`, takes over foreign objects, or deletes legacy inventory.

### 5. Site releases are immutable signed OCI artifacts

Each site's OCIRepository selects one nonzero chart manifest digest. The
`platform.snaraj.dev/chart-release` annotation records the reviewed human
version, but the registry tag cannot choose bytes. The source is
credentialless and requires Cosign verification against only that site's
`release-publisher.yml@refs/heads/main` GitHub Actions identity and issuer.

The chart is the sole carrier of workload repository, tag, and image digest.
Platform HelmRelease values contain exactly `deploymentReady: true`; image
overrides are forbidden because they would split chart and workload identity.
A new site version therefore arrives through an ordinary reviewed platform
pin change, not a mutable SemVer range or manual cluster edit.

### 6. Kyverno is retired, not simulated

Kyverno is absent live and is not desired state. Its policy tree, installer,
controller sentinel, overlays, CLI pin, parity-only CI legs, and dedicated
fixtures are removed. No admission credit is claimed for them.

The retained defence chain is protected main and required CI, immutable signed
release identity, exact chart and image digests, Flux OCI signature
verification, two-stage tenant impersonation, default-deny networking,
least-privilege RBAC, and the narrowly scoped selector admission policy.
Conftest remains a pre-merge static control for public exposure, mutable or
foreign images, cross-tenant references, unenumerated storage, unsafe workload
shapes, NetworkPolicy drift, and widened RBAC.

A material trust-boundary expansion, including another independent tenant or
untrusted/third-party workload, triggers reconsideration of runtime admission.
That requires a fresh threat model and owner decision; it is not standing
authorization to reinstall Kyverno.

### 7. Activation and rollback are evidence-bound

The one-time #141 controller/RBAC migration completes first and remains outside
self-reconciliation. Initial #189 activation then:

1. verifies the exact platform release and cluster target;
2. captures a redacted semantic pre-inventory;
3. creates only absent-or-exact bootstrap authority and suspended reconcilers;
4. proves there is no legacy or foreign source consumer;
5. creates the exact tagged credentialless source;
6. proves source readiness at that revision;
7. activates each site reconciler independently; and
8. captures the post-inventory, controller health, site health, and public
   HTTP result.

Every changed object must be expected from the tagged YAML, every expected
change must occur, UIDs stay stable unless replacement was reviewed, and
unowned resources remain semantically unchanged. Failure contains the two
parents and selector without pruning. Rollback is a separately reviewed exact
release transition; it never falls back to a branch, range, or arbitrary tag.

Pruning remains disabled until the owner approves a separate reviewed
ownership inventory. The steady-state no-`kubectl` proof rides the first
routine site-pin release after activation rather than a dedicated release.

## Consequences

- Ordinary platform and site-pin changes use normal reviewed GitOps; heavy
  transaction ceremony is reserved for authority-boundary changes.
- Platform publication has a small additional signed identity asset and
  selector-image verification cost.
- A broken or unavailable release fails closed and can delay updates, but
  cannot silently select floating main or another site's artifact.
- Controller installation/RBAC and selector-root rotation remain explicit
  owner-attended operations outside the site reconciliation loop.
- The cluster stores no Git or GHCR write credential.

## Historical corrections

- **2026-08-22:** publisher identity moved from tag refs to the exact protected
  `refs/heads/main` workflow identity because tag creation is not the protected
  authority boundary.
- **2026-08-24:** mutable site SemVer selection and platform image overrides
  were replaced by exact chart digests with the chart as sole workload-image
  authority.
- **2026-08-26:** the absent Kyverno posture was retired, and platform source
  selection was bound to signed immutable platform releases through the
  external selector and native narrow admission guard.
- **2026-09-01 (owner ruling, issue #270):** site desired-state consumption
  was decoupled from platform releases. The measured incident: the live
  cluster served naranjo.online four releases behind its own published
  artifacts while every component truthfully reported healthy, because a
  site deploy required a promotion merge PLUS a platform release PLUS a
  selector advance, and only the first was alarmed by anything. The
  `flux-system` GitRepository now follows protected `refs/heads/main` — the
  one ref a no-bypass ruleset gates, the identical anchor every cosign
  publisher identity in this repository already trusts — bounded by the
  unchanged two-directory sparse checkout. Everything this ADR says about
  exact-digest chart selection, the mandatory verify block, and receipted
  promotion is UNCHANGED; the selector's runtime role ends with the
  owner-attended ceremony in `docs/runbooks/site-sync-branch-flip.md`, and
  platform releases continue as the platform's own versioned audit artifact
  that nothing consumes for site delivery.
