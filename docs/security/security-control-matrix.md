# Security control matrix

| Objective | Preventive control | Repository evidence | Runtime evidence required |
| --- | --- | --- | --- |
| No public origin/admin | ClusterIP only, no forwarding, split Tunnels | Conftest/Kyverno deny fixtures | external scan, WARP on/off tests, DNS audit |
| Pod containment | restricted PSA/context, no token, default deny | manifests and policy tests | rejected insecure pod, denied egress/cross-namespace probes |
| GitOps least privilege | anonymous source, explicit SAs, scoped paths | Flux manifests/RBAC tests | `kubectl auth can-i`, Flux status |
| Secret confidentiality | SOPS/age + API-server encryption at rest | structure scanner, `.sops.yaml`, encryption-config validation | canary decrypt/fail/recover plus raw-etcd at-rest verification without exposing values |
| Host-network safety | discovery-gated CNI/kube-proxy and conflict-free CIDRs | ADR, preflight, immutable local artifact contract | VPN/tunnel-interface, kill-switch, firewall, route, DNS, and recovery tests on the Pi |
| Media data isolation | repository-wide per-file/magic/aggregate ceilings, narrow Flux artifacts, capped OCI app layer, disabled storage profile, future derivative-only read-only local PV, no hostPath | ADR 0012, `.sourceignore`/sparse sources, chart sentinel, OCI and path-security tests | dedicated mount identity/boundary, denied writes/links, checksum, rollout/reboot/rebuild and separate restore drill |
| Administration survival | measured host/platform reserves, bounded media concurrency, host-level admin Tunnel | capacity and acceptance contracts | SSH/API over WARP during CPU, memory, disk and network load; `pi-admin` with Kubernetes/containerd stopped |
| Artifact integrity | digest, signed provenance/SBOM | workflows and immutable-reference checks | admission audit then enforce/negative test |
| Cloudflare $0 | product/resource denylist and no billing authority | Rego fixtures/token matrix | current subscription audit, plan hash, post-audit |
| Recoverability | stacked-etcd snapshots, separate PKI/encryption/key backups, independent media originals/metadata backup | runbooks and verify scripts | timed compatible-version cluster restore plus separate media restore/regeneration drill |
| Change accountability | protected main, pinned Actions, no external CI credentials | workflow policy/static tests | GitHub rules/audit reviewed manually |

Documentation or configuration alone does not close a control. The runtime
evidence column must be demonstrated before public exposure.
