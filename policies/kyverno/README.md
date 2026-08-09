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

Signature and provenance rules remain explicitly staged in `Audit`. They need
the final public GHCR artifacts and an actual-cluster verification soak before a
reviewed promotion changes them to `Enforce`. The release gate treats either
signature policy remaining in Audit as a hard stop, so this staging state cannot
be mistaken for production readiness.
