# Public launch gate — currently NO-GO

Public launch is blocked until every item is evidenced:

- a generated digest-pinned Flux manifest for each site;
- release evidence supplied by each standalone site repository's release
  publisher, dispatched from that repository's protected `main` branch:
  independent Go/Svelte tests, dual-architecture builds, scans,
  SBOMs, provenance, keyless signatures and verification, plus an immutable
  stable-version/digest evidence mapping for each selected image;
- public GHCR visibility for anonymous Pi pulls;
- final chart digest, no suspended releases, the cluster-side tunnel Secret;
- restricted PSA/RBAC/default-deny negative tests and workload API denial;
- exact Conftest rejection of public Services, mutable images, cross-tenant
  references, and overbroad RBAC; signed digest-only site artifacts verified by
  Flux; and bootstrap-owned selector field confinement by the reviewed VAP;
- CNI/kube-proxy discovery decision plus Pi VPN/tunnel-interface, firewall,
  route, policy, DNS, and negative recovery tests;
- Pi stacked-etcd snapshot/off-device PKI and API-encryption recovery
  material/reboot and administration recovery tests;
- Cloudflare Free/subscription audit, policy-clean exact plan hash, approval,
  apply, and immediate post-audit;
- external HTTPS/header/DNS/port/WARP/identity/tunnel-failure tests.

`release-gate.sh --live` remains fail closed PENDING; #195 does not close it.
The protected `v0.1.40` merge/tag/Release publishes #141's terminal transaction source,
but does not prove live execution or convergence; a separately validated #141
terminal result remains the serialization gate. #189 must bind the immutable
annotated platform tag and peeled commit to the Flux artifact and both site
Kustomizations' `lastAppliedRevision` values, compare server-normalized desired
and live specs, and prove a complete pre/post inventory with only declared
mutations, no unexpected creates or deletes, site health, and a harmless
follow-up convergence. Historical fixed object counts are not evidence: derive
GitRepository, OCIRepository, Kustomization, HelmRelease, and generated-object
expectations from the exact reviewed render. Initial site reconcilers must use
`prune: false` and cannot depend on an absent prerequisite. The captured
evidence validators remain in `scripts/validate_flux_release_evidence.py` and
`scripts/validate_runtime_inventory_evidence.py`; missing generations,
revisions, histories, source links, artifact identities, or selector fields remain
a NO-GO even when a controller reports `Ready=True`.

The same before/after capture rejects unknown Namespaces, workload controllers,
Pods, Services, source objects, and unexpected admission webhooks. Only the
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
not authorize the other. Unsuspended desired-state bytes do not establish
runtime readiness or activation; the Tunnel and platform-services remain
separately blocked.

Heavy-media launch is a separate blocked gate. The storage profile must remain
disabled, no media volume may render, and `/media/...` must remain unreachable
through the production chart while current Cloudflare self-serve terms are
incompatible with deliberate large-media delivery under the zero-spend policy.
Local streaming tests, a 512 MB cacheability limit, Range support, or cache
BYPASS are not entitlement evidence.

No checklist item can be waived by site urgency. If a site's own verified
source, digest, namespace isolation, or scoped reconciliation boundary fails,
an owner-authorized future run must suspend that site through the reviewed
inner-then-outer rollback sequence;
never trade origin exposure or a paid fallback for availability.
