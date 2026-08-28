# Website chart rollback — reviewed immutable pair

Status: `REVIEW REQUIRED`. This runbook authorizes no registry, GitHub, Flux,
Kubernetes, or production mutation. `scripts/promote-image.sh` is retired and
always exits nonzero before consulting Git, registry tools, or the network.

The signed chart is the sole workload-image authority. A rollback therefore
changes the selected chart artifact, not HelmRelease image values:

- `kubernetes/websites/<site>/source.yaml` carries one audit-only
  `platform.snaraj.dev/chart-release` annotation and exactly one `spec.ref.digest`;
- `kubernetes/websites/<site>/release.yaml` keeps exactly
  `values: {deploymentReady: true}` and no image repository, tag, or digest
  override; and
- a registry tag is evidence used during review, never a Flux selector.

## Required rollback receipt

Acquire the intended older canonical release as a new, separately reviewed
exact chart-manifest digest pair with a credential-free receipt. It must bind
the exact site chart repository, stable tag, nonzero OCI manifest digest, sole
Helm chart layer and media type, exact
protected-main publisher identity, Chart.yaml name/version/appVersion, embedded
workload index reference, and Linux ARM64 child digest. Repeat resolution after
signature and content inspection and require both reads to agree.

If the older tag or exact manifest digest is deleted, moved, unavailable,
unsigned, signed by another identity, malformed, or inconsistent with any
receipt field, stop. Do not select another available tag or digest, restore a
SemVer range, add `ref.tag`, reuse a prior receipt, or add a HelmRelease image
override.

## Reviewed Git change

In one review, change only that site's release annotation and
`spec.ref.digest` to the newly receipted older pair. Keep the sibling tuple
unchanged. Validate the exact source contract, repository contract, transition
classification, render contract, and acquisition receipt with the affected
offline test modules.

These bytes become eligible only through the permanent immutable-release
selector and direct site reconcilers installed by the owner-attended #189
bootstrap. Before that terminal bootstrap they are not live. Afterward, a
reviewed rollback pair reaches the source only in an exact next immutable
platform Release; the selector performs a resourceVersion-bound update and the
site reconciler remains `prune: false`. A reviewed Git rollback pair is not live
rollback evidence: prove the Deployment, Pod, and runtime identities, and keep
Helm remediation a separate owner-authorized decision.
