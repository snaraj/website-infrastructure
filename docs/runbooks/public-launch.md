# Public launch gate — currently NO-GO

Public launch is blocked until every item is evidenced:

- real frontend/provider locks and generated digest-pinned Flux manifest;
- independent naranjo.online and lidersea.com Go/Svelte tests,
  dual-architecture builds, scans, per-platform SBOMs, provenance, keyless
  signatures and verification, plus an immutable stable-version/full-SHA/digest
  evidence mapping for each selected image;
- public GHCR visibility for anonymous Pi pulls;
- final chart digest, no suspended releases, real SOPS tunnel Secret;
- restricted PSA/RBAC/default-deny negative tests and workload API denial;
- Kyverno audit soak followed by enforced registry/digest **and verified signing
  identity/attestation admission**; all policies are staged in `Audit` and are
  deliberately not installed, so this remains an explicit blocker;
- CNI/kube-proxy discovery decision plus Pi VPN/tunnel-interface, firewall,
  route, policy, DNS, and negative recovery tests;
- Pi stacked-etcd snapshot/off-device PKI and API-encryption recovery
  material/reboot and administration recovery tests;
- Cloudflare Free/subscription audit, policy-clean exact plan hash, approval,
  apply, and immediate post-audit;
- external HTTPS/header/DNS/port/WARP/identity/tunnel-failure tests.

The final `release-gate.sh --live` result is valid only for the clean local
commit named by the capacity evidence. Every authoritative Flux Kustomization
and Git source must report that exact `main@sha1:<commit>` as both observed and
successfully applied/attempted state, and its server-normalized live `spec` must
equal the canonical render. The global inventory is exactly six Kustomizations,
four GitRepositories, three HelmReleases, and their three generated HelmCharts;
Bucket, ExternalArtifact, HelmRepository, and OCIRepository inventories must be
empty. Each HelmRelease must trace through its current Revision-strategy
HelmChart to that same source artifact. The gate also
server-normalizes every required desired Kyverno ClusterPolicy and rendered
tenant NetworkPolicy with explicit non-persistent dry-runs, then requires every
live policy spec to be exactly equal. Missing generations, revisions, history,
source links, policy identities, or policy fields are a NO-GO, even when a
controller still reports `Ready=True`.

The same before/after capture rejects unknown Namespaces, workload controllers,
Pods, Services, source objects, ClusterPolicies, and admission webhooks. Only the
two reviewed kubeadm CNI controller variants may use the narrowly classified
system privilege boundary; all other controller-owned Pods reject host
namespaces, host paths, privilege escalation, added capabilities (apart from
CoreDNS `NET_BIND_SERVICE`), and every `hostPort`. Every live Service is both in
the exact release inventory and `ClusterIP`-only with no `externalIPs`,
`nodePort`, or load-balancer field. Generated ReplicaSets and Pods must retain
the exact controller UID chain and stable replica counts.

The public Tunnel must contain exactly the ordered `naranjo.online` and
`lidersea.com` Service routes followed by the final 404, with one matching
proxied automatic-TTL CNAME in each audited Free zone. One site's readiness does
not authorize the other; both HelmReleases and the Tunnel stay suspended until
their combined dependency and runtime admission evidence is complete.

Heavy-media launch is a separate blocked gate. The storage profile must remain
disabled, no media volume may render, and `/media/...` must remain unreachable
through the production chart while current Cloudflare self-serve terms are
incompatible with deliberate large-media delivery under the zero-spend policy.
Local streaming tests, a 512 MB cacheability limit, Range support, or cache
BYPASS are not entitlement evidence.

No checklist item can be waived by site urgency. If any dependency fails, keep
the HelmReleases suspended and accept downtime rather than origin exposure or a
paid fallback.
