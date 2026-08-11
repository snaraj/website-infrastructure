# Security control matrix

| Objective | Preventive control | Repository evidence | Runtime evidence required |
| --- | --- | --- | --- |
| No public origin/admin | ClusterIP only, no forwarding, split Tunnels | Conftest/Kyverno deny fixtures | external scan, WARP on/off tests, DNS audit |
| Pod containment | restricted PSA/context, no token, default deny | manifests and policy tests | rejected insecure pod, denied egress/cross-namespace probes |
| GitOps least privilege | anonymous source, explicit SAs, scoped paths, one flattened plugin-free kubeconfig and digest-pinned kubectl snapshot | Flux manifests/RBAC and protected-target tests | exact-target `kubectl auth can-i`, anonymous source and controller status |
| Secret confidentiality | separate hybrid-PQ cluster/operator age identities, SOPS + API-server encryption at rest, encrypted operator volume | strict SOPS grammar/recipient scanners, protected snapshot validators, classification and ceremony contracts | offline MAC/plaintext-identity proof, no-output decrypt/fail/recover, two backup restores, server-returned age-key equality, and raw-etcd at-rest verification without exposing values |
| Host-network safety | discovery-gated CNI/kube-proxy and conflict-free CIDRs | ADR, preflight, immutable local artifact contract | VPN/tunnel-interface, kill-switch, firewall, route, DNS, and recovery tests on the Pi |
| Legacy archive inactivity | explicit archive presence and activation-class reviews, exact system-manager states, private bound roots, no runtime/route/Kubernetes-or-container-mount/automatic-update path | ADR 0013, ignored-contract validator, local-only-by-default discovery and negative tests | indexed exact-inactive/disabled-or-masked/no-cgroup checks, stable mount fingerprint, no listener, secret-backup restore result, soak/reboot proof |
| Media data isolation | repository-wide per-file/magic/aggregate ceilings, narrow Flux artifacts, capped OCI app layer, disabled storage profile, future derivative-only read-only local PV, no hostPath | ADR 0012, `.sourceignore`/sparse sources, chart sentinel, OCI and path-security tests | dedicated mount identity/boundary, denied writes/links, checksum, rollout/reboot/rebuild and separate restore drill |
| Administration survival | measured host/platform reserves, bounded media concurrency, host-level admin Tunnel | capacity, token-custody, and active-credential canary contracts | SSH-only admin access during CPU, memory, disk and network load (PLAT-DEC-001: the API is administered on-host over SSH, never exposed to the admin path); active systemd credential equality/redaction; `pi-admin` with Kubernetes/containerd stopped |
| Artifact integrity | digest, signed provenance/SBOM | workflows and immutable-reference checks | admission audit then enforce/negative test |
| Cloudflare $0 and bounded authority | phase-separated state, product/resource denylist, JIT audit/apply tokens, no billing or Git/cluster authority | Rego fixtures, token matrix, protected-state ceremony | current subscription audit, scope/expiry/revocation receipts, plan/state bindings, post-audit |
| Recoverability | stacked-etcd snapshots, separate PKI/encryption/key backups, independent media originals/metadata backup | runbooks and verify scripts | timed compatible-version cluster restore plus separate media restore/regeneration drill |
| Change accountability | protected main, pinned Actions, no external CI credentials | workflow policy/static tests | GitHub rules/audit reviewed manually |

Documentation or configuration alone does not close a control. The runtime
evidence column must be demonstrated before public exposure.
