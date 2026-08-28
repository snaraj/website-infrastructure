# Public Tunnel chart — Draft / suspended

This chart runs one connector per website — two per-site Cloudflare Tunnel
connectors (`naranjo-online-tunnel`, `lidersea-com-tunnel`), one Deployment
each, without a Service, HPA, private route, host access, or Kubernetes API
token. Each connector is labelled `app.kubernetes.io/name=cloudflare-public`
plus its own site-scoped `app.kubernetes.io/instance=<site>-tunnel`, and mounts
only its own runtime token Secret by name (`naranjo-online-tunnel-token`,
`lidersea-com-tunnel-token`) — the token value lives only in a cluster Secret,
never in this chart. Per ADR 0015, each website is its own remotely managed
Tunnel with its own token, sharing no object or failure domain with the other.

Connector egress is double-pinned: the shared name-only `cloudflared-dns` and
`cloudflared-edge` policies reach cluster DNS and the Cloudflare edge for every
connector, while each per-site `cloudflared-<site>` policy pins its own
`<site>-tunnel` instance and reaches only that site's workload identity on TCP
8080. Each site chart owns the reciprocal tunnel-only ingress rule, whose peer
pins the same `<site>-tunnel` instance, and denies site egress — so only a
site's own connector can open its origin leg, and connector A can never reach
site B. The structural example is excluded from reconciliation and unusable.

Keep the HelmRelease suspended until:

1. every configured site Service is Ready and its signed OCI chart source,
   publisher identity, and exact digest have been verified;
2. the per-site encrypted token Secrets exist and are included in the release Kustomization;
3. Cloudflare Free plan/subscriptions and the exact OpenTofu plan hash pass;
4. external recovery/origin tests are ready.

At token rotation, update the encrypted Secret and `tokenRevision` in one
reviewed PR — one Tunnel at a time (ADR 0015). Roll back only if the old token
is not compromised; otherwise complete rotation forward. The admin tunnel is
never changed in the same step.
