# ADR 0008: No Ingress or Gateway controller initially

- Status: Accepted; ingress table revised 2026-08-12 per
  [ADR 0015](0015-per-site-tunnels.md)
- Date: 2026-08-08

## Decision

Public routing uses Cloudflare Tunnel ingress rules only. Per
[ADR 0015](0015-per-site-tunnels.md) each site's own Tunnel carries exactly
two ordered entries:

1. the site's apex hostname routes directly to its own service —
   `naranjo.online` to
   `http://naranjo-online.naranjo-online.svc.cluster.local:8080` on the
   `naranjo-online` Tunnel, and `lidersea.com` to
   `http://lidersea-com.lidersea-com.svc.cluster.local:8080` on the
   `lidersea-com` Tunnel;
2. every other hostname terminates at `http_status:404`.

There is no Ingress, Gateway API controller, NodePort, LoadBalancer, host port,
host network, origin A/AAAA record, wildcard route, or additional public
Tunnel beyond the two per-site Tunnels.

## Consequences

This removes a routing layer and public-listener risk while keeping the two
independent sites fully decoupled: each outbound connector serves exactly one
site, so neither shares a token, Tunnel, or failure domain with the other.
Revisit only when several real services make shared internal routing
materially simpler.

The original 2026-08-08 revision of this ADR routed both hostnames through
one shared public Tunnel with a three-rule ingress; that shape is superseded
by ADR 0015. The no-Ingress/no-Gateway decision itself is unchanged.
