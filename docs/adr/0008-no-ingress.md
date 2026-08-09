# ADR 0008: No Ingress or Gateway controller initially

- Status: Accepted
- Date: 2026-08-08

## Decision

The one public Tunnel uses three ordered ingress entries:

1. `naranjo.online` routes directly to
   `http://naranjo-online.naranjo-online.svc.cluster.local:8080`;
2. `lidersea.com` routes directly to
   `http://lidersea-com.lidersea-com.svc.cluster.local:8080`;
3. every other hostname terminates at `http_status:404`.

There is no Ingress, Gateway API controller, NodePort, LoadBalancer, host port,
host network, origin A/AAAA record, or second public Tunnel.

## Consequences

This removes a routing layer and public-listener risk while two independent
sites share only the outbound connector. Revisit only when several real
services make shared internal routing materially simpler.
