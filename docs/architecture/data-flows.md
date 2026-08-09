# Data flows

## Public request

1. A visitor resolves a proxied tunnel CNAME; no home A/AAAA record exists.
2. Cloudflare terminates public TLS under the existing Free zone.
3. The outbound `pi-websites` connector receives the request.
4. The first exact hostname rule maps `naranjo.online` to
   `naranjo-online.naranjo-online.svc.cluster.local:8080`.
5. The second exact hostname rule maps `lidersea.com` to
   `lidersea-com.lidersea-com.svc.cluster.local:8080`.
6. NetworkPolicy permits only those namespace/Pod/port pairs. Unknown hostnames
   reach the final `http_status:404`; neither site receives workload egress.

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

CI builds amd64/arm64, scans, emits SBOM/provenance, publishes to public GHCR,
and signs/attests keylessly for each site independently. A human uses the exact
site promotion command to create a digest-only diff and opens a PR. Flux does
not write Git.

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
