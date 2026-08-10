# Repository instructions

These rules apply to every human and automated contributor.

## Safety invariants

1. Never commit plaintext secrets, base64-only Kubernetes secrets, private age
   identities, tunnel tokens, API tokens, kubeconfigs, Kubernetes PKI/bootstrap
   material, API-encryption keys, recovery codes, private keys, authenticated
   plans, or state.
2. Never create `apps/`, `clusters/`, or `kubernetes/homelab/`.
3. Never add a Kubernetes `NodePort`, `LoadBalancer`, `externalIPs`, host port,
   host network, public Ingress, Gateway, or origin A/AAAA record.
4. Never add a Cloudflare resource outside the committed allowlist. A new or
   unknown product requires a reviewed ADR proving zero infrastructure cost.
5. Never give Flux a Git credential or write capability. The source is public
   anonymous HTTPS and reconciliation is pull-only.
6. Never deploy a mutable image tag. Workloads use a full `sha256` digest.
7. Every committed Kubernetes Secret must be a valid SOPS document whose
   `data` and `stringData` values are ciphertext.
8. Direct `kubectl apply` is limited to documented bootstrap or recovery. Once
   Flux owns a resource, normal changes flow through a reviewed Git commit.
9. Dashboard mutations are break-glass only and must be recorded and reconciled
   into OpenTofu immediately afterward.
10. Every new public route, API, database, authentication system, persistent
    volume, or cross-namespace flow requires a threat-model update.
11. Production website code lives in the standalone site repositories
    (Svelte frontend, Go service, Helm packaging); this platform consumes
    only their signed digests. Python is limited to dependency-free local
    policy/redaction tooling and must never enter a production image.
12. Treat the Git index as public. Real host/service inventory, account or zone
   IDs, emails, IPs, machine IDs, user/workspace paths, plans, state, and local
   evidence remain ignored/local unless an explicitly designed SOPS/age Secret
   flow requires ciphertext in Git.
13. Keep heavyweight media out of Git, OCI images, Flux, ConfigMaps,
    Secrets, and etcd. Before Pi discovery, reject every
    hostPath/PV/PVC/storage-profile activation; current zero-spend Cloudflare
    terms keep deliberate public large-media delivery disabled independently
    from application-code readiness.
14. Keep each website's domain, source/module/package, image, chart, namespace,
    Flux release, workflow signature, promotion, DNS zone variable, and Tunnel
    origin as one exact identity tuple. Shared tooling must not couple digests,
    readiness, rollback, or release authority.
15. Treat every declared protected legacy archive as inert. Never add an
    installer, updater, automatic start/restore, public route, listener,
    container/Kubernetes mount, CI artifact, or broad storage operation for it;
    exact units, roots, identities, contents, and recovery evidence stay in the
    ignored local contract. Reactivation requires a new ADR and threat-model
    review.

## Change workflow

- Read the relevant ADRs and runbooks before editing.
- Keep GitHub workflows secretless on pull requests, pin every action to a full
  commit SHA, and keep default permissions read-only.
- Run `make check` and add an allow and deny fixture for policy changes.
- Preserve fail-closed sentinels until an explicitly approved user-run step can
  replace them with verified non-secret values.
- Add GoDoc to exported Go declarations and contextual comments to non-obvious
  modules, structs, fields, variables, constants, functions, and safety checks.
  Explain why they exist in this system instead of narrating syntax.
- Before every push, review the exact staged index, run the repository privacy
  gate and Gitleaks, and leave any ambiguous operational value unstaged.
- Do not install tools, authenticate, plan, apply, deploy, commit, push, or
  mutate the Pi/router/GitHub/Cloudflare without explicit authorization.
- Use official upstream documentation to revalidate versions, schemas,
  entitlements, and billing immediately before any external change.

`kubeadm reset` is destructive, performs incomplete cleanup, and is never an
upgrade or rollback procedure. If discovery finds stale K3s state, do not run
its uninstall script; stop for a reviewed backup and migration decision.
