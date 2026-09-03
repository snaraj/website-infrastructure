# Phase D — Cloudflare Zero Trust and performance design (plan-only)

Design document only: nothing here creates or changes an external resource.
Every feature is admitted under the order **security > zero cost >
performance** — a performance feature that weakens isolation or could ever
bill is rejected regardless of benefit. Feature availability below was
retrieved from current Cloudflare documentation via the Cloudflare skills on
2026-08-10; anything marked VERIFY-AT-CEREMONY is re-checked against live
docs during the owner's apply ceremony, because plans change and this
document must never be the authority Cloudflare's own docs are.

## Performance layer (owner directive, 2026-08-10)

Maximum edge performance strictly inside the two non-negotiables. The two
sites are fully static Go-served Svelte bundles — the best possible cache
customer — so nearly all performance comes free from aggressive caching.

### Admitted features (free-plan-verified, security-neutral or -positive)

| Feature | Availability (verified) | Why admitted | Order |
| --- | --- | --- | --- |
| HTTP/3 (QUIC) visitor-side | zone setting, Speed > Protocol Optimization | transport speedup; no isolation change | enable |
| Post-quantum tunnel transport | cloudflared→edge is TLS 1.3 with X25519MLKEM768 hybrid by default | security-POSITIVE performance path: QUIC transport + PQ key agreement in one | verify `protocol: quic` in connector config |
| Smart Tiered Cache | all plans, no additional cost (2026-04 changelog) | fewer origin fetches through one upper tier; tunnel-masked origin falls back to Generic topology automatically — still free | enable |
| Cache Rules: cache-everything for hashed static assets | free plan includes cache rules (bounded count) | static immutable assets by content hash; origin (the Pi + home uplink) shielded from nearly all traffic — performance AND availability | plan in IaC |
| Compression (Brotli/Zstandard) | default zone behavior | smaller payloads; no trade-off | verify-on |
| Automatic origin key exchange | default-on for all zones (2026-07 changelog) | avoids HelloRetryRequest round trip; prefers PQ hybrid | verify-on |
| Early Hints | cache feature; VERIFY-AT-CEREMONY for free-plan availability | static sites benefit from preload hints during server think time; no isolation change | enable if verified free |

### Rejected or constrained features (the order applied)

| Feature | Verdict | Reason |
| --- | --- | --- |
| Argo Smart Routing | REJECTED | metered/paid by name; zero-cost is non-negotiable |
| APO / paid image resizing / Zaraz beyond free | REJECTED | paid or metered surfaces |
| Speed Brain | CONSTRAINED: accept silent no-op | free and default-on, but documented as incompatible with strict CSP (`strict-dynamic`/nonce). The sites ship strict CSPs as a security control; **CSP stays, Speed Brain simply won't fire**. Security wins without spending anything. Revisit only if Cloudflare ships CSP-compatible speculation rules |
| 0-RTT session resumption | CONSTRAINED: allowed only with proof | replay-risk feature. Admissible here because both sites are static GET-only origins (no state mutation on GET, enforced by the site contract); enable only after the site repos' tests pin "GET never mutates" as an executable contract |
| Rocket Loader / JS rewriting | REJECTED | mutates served content; violates the review-what-runs principle for zero measured benefit on pre-optimized static bundles |

### Origin-side contract (site repositories, tracked separately)

Edge caching is only as good as origin headers. The site repos must serve:
content-hashed assets with `Cache-Control: public, max-age=31536000,
immutable`; HTML with a short TTL + `stale-while-revalidate`; correct
`ETag`/`Last-Modified`. This is a site-lane deliverable referenced here so
the platform cache rules and the origin agree on one story.

### Measurement (closes PLAT-GAP-004)

Zero-cost baseline: Cloudflare Observatory (available on all plans) plus
free Web Analytics/RUM after launch — both read-only, no origin exposure,
nothing metered. Synthetic checks run only against the public edge, never
the origin, and only post-launch with owner awareness.

## Zero Trust layer

### Principles

- No public origin listener, no router port-forward, ever. The tunnel is
  the only public path and it is outbound-only (PQ key agreement verified
  above). LAN/console recovery is never behind Cloudflare.
- Public site traffic and human administrative access are separate
  identities, separate policies, separate failure domains. A service token
  can never satisfy a human policy; a human identity can never satisfy a
  service endpoint.
- Human administrative access (when the owner chooses to enable any)
  requires Cloudflare Access with phishing-resistant WebAuthn — hardware
  keys, two enrolled for redundancy, documented loss/revocation and
  break-glass ceremonies. No email-domain-only bypass exists in any policy.
- Every credential is scoped and short-lived: per-purpose API tokens with
  exact permission lists (documented as types, never values), no
  account-global token in any workload, JIT ceremonies validated by the
  existing receipt validators.
- Origin binding stays pinned: SSL mode full with hostname ownership pinned
  in IaC; the connector-to-origin leg is plain HTTP inside the default-deny
  boundary (ADR 0015), so "Full (strict)" is not claimed. DNSSEC posture
  reviewed at the zone, log minimization on (no visitor identity retention
  beyond defaults).

### Attack tree (summary)

Root: serve attacker content or reach the origin.
1. DNS takeover → registrar/Cloudflare custody + DNSSEC review + IaC-pinned
   records (drift visible in plan).
2. Tunnel credential theft → each site's token lives only in the cluster
   Secret an owner ceremony creates; rotation ceremony documented; compromise of
   one token yields only the ability to serve that one site's hostname
   (per-site Tunnels, ADR 0015) — which signature-gated workloads limit.
3. Access policy bypass → no such policies exist for public sites (nothing
   to bypass); admin apps (if enabled) require WebAuthn hardware presence.
4. Cache poisoning → cache keys default-safe; no user-generated content;
   static-only origins; rules never cache by arbitrary query/header.
5. Replay via 0-RTT → constrained as above.

### Seven-point verification checklist (apply ceremony)

1. DNS: exactly the planned records in each zone, proxied, nothing extra.
2. Tunnel identity: two per-site tunnels (ADR 0015), each ID matching its
   own IaC root, no stray connectors on either.
3. Access policy: absent for public sites; admin apps (if any) enforce
   WebAuthn-backed policies with no bypass rule.
4. Origin bind: each connector serves only its own site's ClusterIP origin;
   no wildcard, no catch-all beyond the terminal 404.
5. Firewall: no new inbound rule appeared anywhere.
6. Route policy: host routing tables unchanged outside the connector's own
   egress (the private admin plane's non-overlap is re-verified).
7. External denial: direct-to-origin probes fail from outside; only the
   two hostnames answer, only via the edge.

### Rollback ladder

Each step reversible alone, none touches LAN/console recovery:
disable Access app → disable tunnel route → delete DNS record → stop
connector (cluster-side suspend) → remove tunnel. IaC plan shows each as an
isolated diff; the ladder never removes local access paths.

### Cost guard

Everything admitted above is free-plan per the retrieved documentation;
anything VERIFY-AT-CEREMONY is re-verified before enablement, and any
ambiguity is a NO-GO (PLAT-COST-001, threat T11). No Workers, no paid
add-ons, no metered analytics enter this design.

## IaC shape (plan-only)

The credential-free Cloudflare roots — being reconciled to ADR 0015's
per-site shape (issue #61) — gain performance/Zero-Trust settings as
reviewed additions to the relevant roots (zone settings with the admitted
features; cache rules, one per site), following the same fixture-tested
policy gating as every other root.
Policy tests (allow/deny fixtures for each admitted/rejected feature state)
land with the IaC change, not this document.
