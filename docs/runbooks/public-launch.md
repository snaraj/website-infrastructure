# Public launch gate — currently NO-GO

Public launch is blocked until every item is evidenced:

- real frontend/provider locks and generated digest-pinned Flux manifest;
- independent naranjo.online and lidersea.com Go/Svelte tests,
  dual-architecture builds, scans, per-platform SBOMs, provenance, keyless
  signatures and verification;
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
