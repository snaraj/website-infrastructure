# Data flows

## Public request

1. A visitor resolves the site's proxied apex CNAME, which targets that
   site's own Tunnel; no home A/AAAA record exists.
2. Cloudflare terminates public TLS under the existing Free zone. The
   application owns HSTS (exactly `max-age=31536000`); Cloudflare-managed
   HSTS stays off (ADR 0015).
3. The site's own outbound connector (`naranjo-online` or `lidersea-com`
   Tunnel, per ADR 0015) receives the request in `cloudflare-public`.
4. The Tunnel's single exact hostname rule maps the apex to its own service —
   `naranjo.online` to `naranjo-online.naranjo-online.svc.cluster.local:8080`,
   or `lidersea.com` to `lidersea-com.lidersea-com.svc.cluster.local:8080`.
   This connector-to-origin leg is plain HTTP inside the default-deny policy
   boundary by accepted decision; internal TLS/mTLS is a future option.
5. NetworkPolicy permits only that namespace/Pod/port pair. Unknown hostnames
   reach the Tunnel's terminal `http_status:404`; neither site receives
   workload egress, and neither Tunnel can reach the other site's service.

## Heavy-media publication and request — disabled

1. The operator transfers an original through the protected administration
   path into a non-served staging boundary on the dedicated data filesystem.
2. Offline tooling verifies size/checksum and creates browser-compatible
   derivatives; the Pi is not expected to transcode high-resolution source
   video during a visitor request.
3. A verified single-link regular file is atomically renamed into either a
   content-addressed immutable delivery path or a mutable no-store path.
   Originals, staging, metadata, internal files, links, and nested mounts remain
   outside the serving boundary.
4. After every storage and delivery gate is accepted, the Go origin would open
   the derivative through a traversal-resistant root and stream it with
   `HEAD`, Range, content length, and immutable validator/`Last-Modified`
   semantics; mutable aliases deliberately have no metadata-only validator.
5. Today this flow stops before step 3 reaches Kubernetes: no volume is
   rendered, `MEDIA_ENABLED=false`, and current Cloudflare self-serve terms make
   deliberate large-media delivery a zero-spend `NO-GO`.

Cloudflare cache hits are never assumed. Oversized files and cold/evicted edge
locations can reach the origin, and standard edge cache is neither global nor
durable storage.

## GitOps and secrets

1. A reviewed commit reaches protected `main` after secretless CI.
2. Flux fetches the public repository anonymously.
3. Kustomize controller decrypts only SOPS-encrypted Secret fields using an age
   identity mounted out-of-band in `flux-system`.
4. Explicit reconciliation ServiceAccounts apply the desired state.
5. The API server encrypts Secret values in etcd with the reviewed encryption
   configuration; the workload receives only its Secret.

## Image promotion

CI reads each site's independently committed stable SemVer, builds amd64/arm64
once, scans the exact graph, emits SBOM/provenance, and publishes immutable
`sha-<full-commit>` and `vMAJOR.MINOR.PATCH` names to GHCR that must resolve to
the same digest. Anonymous package visibility is a separate launch gate; only
after that gate is proven may documentation or deployment treat the package as
public. CI records source/version/SHA/digest evidence and signs/attests the
digest keylessly. A human supplies the selected version and digest to the
exact-site promotion command; it verifies their mapping and creates a
digest-only diff. Flux does not write Git and never deploys a tag.

## Sensitive flows excluded from CI

Kubeconfig, Kubernetes PKI/bootstrap material, API-encryption keys, age identity,
Tunnel tokens, Cloudflare apply/audit tokens, SSH credentials, state, and
authenticated plans stay on trusted operator systems.

## Media backup and restore

Originals and publication metadata are encrypted and copied off-device through
an operator-controlled process. Delivery derivatives are classified as
regenerable unless explicitly promoted to the protected backup class. A
stacked-etcd snapshot contains Kubernetes API objects only: it does **not**
contain originals, derivatives, checksums, or any bytes from a local media
filesystem. Cluster-state restore and media-data restore are separate,
independently verified flows.
