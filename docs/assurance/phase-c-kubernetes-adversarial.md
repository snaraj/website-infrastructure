# Phase C — Kubernetes adversarial validation

## Evidence split

Repository rendering proves desired-state syntax and static policy behavior. It
does not prove a cluster applied the objects, a controller converged them, or a
runtime request was denied. Kyverno is retired and absent; no admission credit
is taken. Runtime claims require separately dated live evidence.

## Static controls

`scripts/render-manifests.sh` builds every retained Helm/Kustomize root,
validates schemas, runs Conftest, executes the complete allow/deny fixture
corpus, and applies the stricter release-state policy for the selected
transition mode. `scripts/validate_repository.py kubernetes activation`
independently checks exact inventories, Flux source/sync shape, immutable chart
digests, cosign publisher identity, default deny, and least-privilege RBAC.
Bootstrap-token hygiene remains explicit: `--skip-token-print` pinned by two suites
and allowlisted in the security-toggle detector as a security-positive flag.

The hostile battery must keep these mutants red:

| Mutant | Required rejection |
| --- | --- |
| NodePort, LoadBalancer, externalIPs, Ingress, Gateway, hostNetwork or hostPort | no direct public origin |
| mutable or foreign workload image | approved registry and full digest required |
| sibling-site or cross-namespace chart/source reference | exact tenant tuple required |
| changed OIDC issuer, publisher subject, tag selector, missing verify block | exact Flux cosign source contract required |
| prune enabled, wrong service account, aggregate dependency, or unsafe release values | fail-closed release activation |
| network/cloud/hostPath/unknown storage, traversal, missing affinity, null structures | enumerated static-local means only |
| wildcard RBAC, cluster-admin, foreign subject, direct tenant authority | two-stage namespace impersonation and least privilege |

Every deny fixture carries an exact expected reason, either in a sidecar or in
per-document inline declarations. Rejection by an unrelated rule does not
count as proof of the intended control.

## Runtime controls retained

The live defence chain is protected main plus required CI, annotated immutable
platform release, signed release identity, digest-only site artifacts, Flux OCI
verification, two-stage namespace impersonation, namespace default deny and
least-privilege RBAC, and bootstrap-owned ValidatingAdmissionPolicy confinement
of release-selector fields.

Live acceptance must demonstrate:

- exact `SourceVerified=True` at the selected OCI digest;
- exact Kustomization/HelmRelease generations and revisions;
- Deployment/Pod image references and runtime ARM64 image IDs matching the
  acquisition receipt;
- no NodePort/LoadBalancer/externalIPs/Ingress/Gateway;
- exact tenant NetworkPolicy and RBAC inventories;
- cross-tenant access denied and control-plane reachability denied; and
- an unsafe selector/release activation refused without partial mutation.

## Storage truth

The sanitized live cluster currently has an older unbound hostPath PV and no
PVC or StorageClass. That is not reviewed local-PV activation. The future
usage-export target remains static `local`, root `/mnt/local-pie-ssd`,
StorageClass `local-pie-ssd`, `ReadWriteOnce`, `Retain`, exact node
affinity and local-device proof. The Naranjo Helm reconciler may own PVC
lifecycle only, never PV, StorageClass, node, or host authority. See the
[static storage runbook](../runbooks/storage-admission.md).

## Revisit trigger

A material trust-boundary expansion, including another independent tenant or
untrusted/third-party workload, reopens the runtime-admission decision. It
requires a new threat model and ADR and does not authorize reinstalling
Kyverno.
