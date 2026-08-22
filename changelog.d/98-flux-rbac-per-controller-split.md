### Security

- Split Flux custom-resource authority into three install-root ClusterRoles, each bound to exactly one controller ServiceAccount, while removing every Flux API-group grant from the shared controller role, deriving exact read-only secondary informers, disabling Kustomize's broad config watchers, and preserving exact cross-controller denial, reviewed rollback design, and bounded live-oracle evidence.
- Preserve measured runtime sufficiency with only Helm's cluster-scoped Secret `get`/`list`/`watch` startup cache and tenant-local Pod/ReplicaSet `get`/`list`/`watch` readiness read-back; Secret writes, workload writes, and cross-tenant reads remain denied.
- Add a fail-closed isolated-kind acceptance harness for real pinned Flux controllers, a final-RBAC zero-restart Kustomize cold start, exact authorization transitions, both issue-186 failure modes, successful install/upgrade, acceptance-only Helm remediation, and deterministic recovery of harness-owned host resources.
