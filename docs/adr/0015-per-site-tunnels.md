# ADR 0015: Two per-site public Cloudflare Tunnels

- Status: Accepted (owner decision, 2026-08-11)
- Date: 2026-08-12
- Supersedes: the shared `pi-websites` public Tunnel in
  [ADR 0007](0007-split-tunnels.md); revises the shared three-rule ingress in
  [ADR 0008](0008-no-ingress.md)

## Decision

Each website runs behind its own remotely managed Cloudflare Tunnel. The two
Tunnels are named after their site identity tuples — `naranjo-online` and
`lidersea-com` — and are identical in shape while sharing no object, token,
or failure domain:

1. exactly one public hostname rule per Tunnel — the site's apex routed to
   its own ClusterIP service DNS name on TCP 8080
   (`naranjo.online` to `http://naranjo-online.naranjo-online.svc.cluster.local:8080`;
   `lidersea.com` to `http://lidersea-com.lidersea-com.svc.cluster.local:8080`);
2. a terminal `http_status:404` rule;
3. no private/WARP routing, no wildcard hostname, and no SSH or API hostname.

Each apex has exactly one proxied CNAME with automatic TTL targeting its own
Tunnel's `cfargotunnel.com` name. Runtime credentials are per-site: each
Tunnel has its own token, held only as a Kubernetes Secret and consumed by
its connector through `secretKeyRef` (`TUNNEL_TOKEN`), never as a literal
manifest value, and rotated independently, one Tunnel at a time.

The connector-to-origin leg (connector Pod to site ClusterIP on TCP 8080) is
plain HTTP inside the cluster's default-deny NetworkPolicy boundary. That is
an accepted decision, not an oversight: the public leg and the
connector-to-edge leg are both encrypted and authenticated, and internal
TLS/mTLS per origin remains a future defense-in-depth option to be adopted
only if its certificate lifecycle and failure modes justify it.

## Rationale

- Blast-radius isolation: compromise, misconfiguration, rate limiting, or
  deletion affecting one site's Tunnel or token cannot touch the other site.
- Independent rotation: token rotation and compromise response
  (force-disconnect) are per-site operations with per-site downtime.
- Per-site DNS targets: each apex CNAME binds to its own Tunnel, so DNS,
  Tunnel, token, namespace, and release stay one exact identity tuple per
  site (safety invariant 14) instead of coupling both zones to one shared
  object.

## HSTS ownership

The application owns `Strict-Transport-Security` and emits exactly
`max-age=31536000`. Cloudflare-managed HSTS stays off so two writers can
never publish contradictory policies. `includeSubDomains` and `preload` are
deferred until a complete subdomain inventory exists and a rollback has been
proven; preload is deliberately hard to reverse and is not enabled in this
phase. HSTS received over plain HTTP is ignored by browsers, so the edge
HTTP-to-HTTPS redirect (Always Use HTTPS) is a separate, required control —
Automatic HTTPS Rewrites is not a redirect and must never be described as
one.

## Recorded proposal — connector availability (implementation: platform lane)

Owner-verified observation (2026-08-11 evening, `kubectl`; to be revalidated
read-only): the two per-site connector Deployments run in `cloudflare-public`
with one Pod each and a `maxSurge: 0` / `maxUnavailable: 1` rollout, which can
briefly interrupt a site during connector replacement. The superseded shared
chart in Git specifies `replicaCount` 2 with `maxSurge: 1` /
`maxUnavailable: 0`, so Git and the live objects disagree. The per-site
connectors are not yet reconciled into Git; the recorded proposal is to carry
the surge-first shape (`maxSurge: 1` / `maxUnavailable: 0`) into the two
per-site connector Deployments during platform-lane reconciliation. That
shape, and a measured second connector Pod per Tunnel, are
process-availability only: two Pods on one Pi are not node, power, ISP, or
home-network high availability, and must never be described as such.

## Open decision — www behavior (owner)

Per site, exactly one of:

- terminal 404 for `www.<apex>` — no route exists and the terminal rule
  answers (behavior recorded at the 2026-08-11 handoff; to be revalidated
  read-only); or
- one exact `www.<apex>`-to-apex redirect — an explicit exact-hostname
  route or edge redirect, never a wildcard route.

Recommendation: keep the terminal 404. It is the simplest zero-cost shape
and adds no hostname surface. Choose the redirect only if real `www` traffic
is expected. Wildcard routes remain forbidden either way.

## Consequences

ADR 0007's shared `pi-websites` Tunnel and ADR 0008's original three-rule
shared ingress no longer describe the platform. The delivery lane reconciles
Git to this decision (issues #59, #61, #62): architecture documents, the
Cloudflare OpenTofu roots, plan policy, fixtures, audits, and runbooks.
Reconciliation adopts the live objects by import only — live Tunnels and DNS
records are never deleted or recreated to match stale IaC. The Kubernetes
desired state (one `cloudflare-public` connector chart and one
`pi-websites-tunnel-token` Secret) still models the superseded shared shape;
reconciling it into two per-site connector Deployments and Secrets belongs
to the platform-lane GitOps work and is tracked there, not here.

## Amendment (2026-08-29)

The paragraph above described the Kubernetes desired state as still modelling
the superseded shared shape — "one `cloudflare-public` connector chart and one
`pi-websites-tunnel-token` Secret" — and deferred the split to platform-lane
GitOps work. That reconciliation has since landed in this repository, so the
sentence no longer describes the tree it names. Prior lines are left byte for
byte intact; this section is the correction.

`kubernetes/platform/cloudflare-public/chart` now runs one connector per
website: two Deployments (`naranjo-online-tunnel`, `lidersea-com-tunnel`), each
labelled with its own site-scoped `app.kubernetes.io/instance`, each mounting
only its own runtime token Secret by name (`naranjo-online-tunnel-token`,
`lidersea-com-tunnel-token`), sharing no object or failure domain. Connector
egress is double-pinned so a site's own connector is the only one that can open
its origin leg.

Runtime token Secrets are created on the cluster by an owner ceremony; they do
not enter Git or the release Kustomization as ciphertext. Release readiness is
established from reviewed desired state and current convergence evidence, not
this amendment's historical suspension status. The authenticated Cloudflare
apply ceremony's separate vocabulary reconciliation remains tracked in issue
#82.
