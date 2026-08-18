# Kyverno admission policy

Core workload, image, exposure, network, readiness, discovery-gated storage,
and tenant etcd-payload rules run in `Enforce` with webhook failure policy
`Fail`. Tenant Pods may use only the bounded in-memory site scratch volume or
the tunnel's one exact Secret key; wildcard tolerations, legacy ServiceAccount
token Secrets, and every other volume source remain denied. The scaffold's
zero-Pod quota can be replaced only by a reviewed `namespace-budget` whose
annotation is bound to the local discovery-evidence hash. Flux reconciles them
only after the pinned admission controller reports Ready; site and tunnel
reconciliation remain suspended while capacity, image, token, and runtime
evidence are unresolved.

Signature and provenance rules are the same: `require-signed-naranjo-online`
and `require-signed-lidersea-com` declare `validationFailureAction: Enforce`
with webhook failure policy `Fail` in these sources, exactly like the rules
above. `policies/release-conftest/deployment-readiness.rego` denies a release
whose rendered signature policy reads anything but `Enforce`, so a downgrade
committed HERE fails the release gate rather than passing it.

Staging is a property of the INSTALL OVERLAY, never of this directory.
`kubernetes/platform/admission-install/enforce` composes these files unchanged;
`kubernetes/platform/admission-install/report-only` is the sole downgrade, and
it rewrites every `ClusterPolicy`'s `spec.validationFailureAction` to `Audit`
and `spec.webhookConfiguration.failurePolicy` to `Ignore` so the first install
stage reports instead of blocking. Both signature policies carry `verifyImages`
rules and no `validate` block, so that spec-level pair is their entire
downgrade — the per-rule `validate.failureAction` patches the other policies
need do not apply to them.

Promotion out of report-only is therefore a change of installed STAGE, gated by
`scripts/install-kyverno-admission.sh --stage enforce` and the authorization
recorded in `kubernetes/platform/admission-install/render.lock` — never an edit
to the files in this directory. The final public GHCR artifacts and an
actual-cluster verification soak remain prerequisites of that promotion.
