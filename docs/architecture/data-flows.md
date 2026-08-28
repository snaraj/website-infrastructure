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

## Immutable chart selection

Each site's protected-main publisher builds and signs its multi-architecture
image, embeds that exact index identity in the signed Helm chart, and publishes
the chart under a stable human version. This repository records that version
only as an audit annotation and makes Flux select the chart by its exact OCI
manifest digest. The tag-to-digest mapping, signature, sole chart layer, chart
metadata, embedded workload index, and Linux ARM64 child are bound by a
credential-free acquisition receipt before review.

Moving or deleting a tag cannot change the selected bytes. Forward changes and
rollbacks update the annotation and digest atomically after a separate receipt;
an unavailable digest fails closed. Site HelmRelease values contain only
`deploymentReady: true`, so the signed chart remains the sole image authority.
Flux never writes Git and never selects a tag or SemVer range.

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
