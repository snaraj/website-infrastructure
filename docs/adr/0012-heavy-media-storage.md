# ADR 0012: Discovery-gated heavy-media storage

- Status: Proposed / disabled pending Pi discovery and restore evidence
- Date: 2026-08-08

## Context

`naranjo.online` must eventually deliver large images, lossless audio, and
pre-generated browser-compatible video derivatives while preserving
irreplaceable source media. Those bytes are too large and too operationally
important to share the lifecycle of Git, the Svelte build, the Go embedded
filesystem, an OCI image, Flux, a ConfigMap, a Secret, or etcd. Persistent
storage also adds a new trust boundary: a compromised read-only website must
not discover originals, alter media, fill the control-plane filesystem, or turn
the Pi into an anonymous upload or transcoding service.

The actual Pi SSD, filesystem, mount topology, capacity, throughput, node
identity, backup destination, and recovery behavior have not been discovered.
Committing a host path, capacity, threshold, PersistentVolume, or claim now
would therefore be invented production configuration.

## Decision

Heavy media will use a dedicated data filesystem that is independent from the
OS and Kubernetes/control-plane filesystem. The storage implementation remains
disabled until read-only Pi discovery and a restore drill provide reviewable,
non-sensitive evidence. The current Helm contract must reject an attempt to
enable media; no `hostPath`, local PersistentVolume, PersistentVolumeClaim, or
storage controller is created by this scaffold.

After discovery, the preferred candidate is a statically provisioned upstream
local PersistentVolume with explicit node affinity and a pre-bound claim,
mounted read-only by the website workload. That candidate is not yet accepted.
The follow-up review must compare it with any other upstream mechanism, prove
reclaim and rebuild behavior, and avoid adding a privileged dynamic provisioner.
Exact device names, host paths, filesystem identifiers, node identity, capacity,
and performance evidence remain local rather than entering this public Git
repository.

## Media classes and logical layout

The future data filesystem has four logical roles; these names describe
security boundaries, not undiscovered host paths:

- **Originals** are irreplaceable source files. They are operator-readable,
  never mounted into the website, and backed up encrypted off-device.
- **Delivery derivatives** are browser-compatible files generated ahead of
  publication. They are regenerable from originals and are the only large
  files the website may read.
- **Staging** holds incomplete operator transfers and checksum work. It is not
  mounted or publicly addressable.
- **Metadata** holds manifests, checksums, publication evidence, and derivative
  recipes. It is backed up with the originals but is not served.

Immutable delivery URLs use a content-addressed segment such as
`/media/immutable/<sha256>/<safe-name>`. Mutable editorial URLs, if later
needed, use `/media/mutable/<safe-name>` with `Cache-Control: no-store` and no
metadata-only validator: an atomic same-size replacement can preserve a coarse
timestamp, so size/time alone cannot safely produce a 304. Neither class may be
implemented with a symlink or multi-link inode. The workload receives only the delivery
boundary as a read-only mount; originals, staging, metadata, and the parent
filesystem remain outside its mount namespace.

## Publication and serving

Publication is an operator action over the protected administration path, not
an HTTP upload API. A future reviewed tool must copy into a non-served staging
area on the data filesystem, verify the expected size and SHA-256 checksum,
generate delivery derivatives offline, set reviewed ownership and permissions,
flush file and directory metadata, and atomically rename each completed file
within the same filesystem. A mutable alias is published as a new regular file
with an atomic rename; symlinks, hard links, and in-place rewrites are forbidden.
Mount acceptance must also prove that nested bind mounts cannot cross the
derivative boundary because a rooted path API alone does not enforce filesystem
boundaries. Failed or partial transfers remain unreachable.

The Go service streams an already-open regular file through Go's standard HTTP
implementation. It preserves `GET`, `HEAD`, byte ranges, immutable conditional
requests, content length, and seeking without loading the file into memory;
mutable aliases intentionally omit ETag/`Last-Modified`. It rejects traversal,
dot-prefixed or reserved internal segments, directories, non-regular files,
symbolic links, and multi-link files; a directory-limited file handle prevents a
path race from escaping the reviewed media root. Known media
extensions receive an explicit safe MIME type. Unknown extensions are
`application/octet-stream`, use `nosniff`, and download as attachments.
Content-addressed paths may be cached immutably; mutable paths are never cached.

Repository validation applies per-file, content-signature, and aggregate asset
ceilings across the whole public tree. Generated frontend output remains ignored
by Git and is rechecked after building. Flux sources use sparse checkout plus
narrow ignore rules, with a root `.sourceignore` fallback, so application/media
history never enters source-controller artifacts. The final OCI verifier also
caps each architecture's application layer; source, GitOps, and image checks are
independent defenses rather than one extension-based promise.

No runtime transcoder, anonymous upload, upload API, authentication system,
database, or content-management service is authorized by this decision. Source
material such as high-frame-rate 4K video is preserved, but browser delivery
depends on pre-generated derivatives rather than real-time Pi transcoding.

## Capacity and failure posture

The media filesystem may eventually use nearly all of its reviewed data
capacity, but it must not share the filesystem required by Linux, SSH,
host-level `pi-admin`, containerd, kubelet, static control-plane Pods, stacked
etcd, DNS, Flux, or admission. Warning and critical free-space thresholds remain
unresolved until filesystem and workload measurements exist. At warning state,
new staging/publication stops. At critical state or any unexpected root/control-
plane `DiskPressure`, publication remains blocked, public workload capacity is
reduced or suspended through the reviewed runbook, and recovery access wins;
the system never deletes originals or buys storage automatically.

CPU and memory budgets are derived from measured Kubernetes Allocatable after
hard host, Kubernetes, and recovery reservations. An operator may later assign
the websites roughly 90% of the remaining safe workload budget, not 90% of raw
hardware. Static serving remains bounded-memory under concurrent transfers, and
load acceptance must prove that public traffic cannot starve SSH, the private
API path, or the independent host-level Tunnel.

## Backup, restore, and survival

| Event | Originals | Delivery derivatives | Kubernetes objects |
| --- | --- | --- | --- |
| Website image rollout | unchanged outside the container | unchanged on the read-only data volume | Deployment rolls by digest |
| Cluster rebuild | retained only if the data filesystem is preserved and verified | retained or regenerated | restored from Git and reviewed local storage binding |
| Stacked-etcd restore | **not restored** | **not restored** | restored only to snapshot time |
| Data-volume loss | restored from encrypted, checksum-verified off-device backup | regenerated or restored by classification | does not recover media bytes |

An etcd snapshot is never a media backup. Acceptance requires separate
encrypted off-device originals/metadata copies, checksum verification, a timed
restore onto isolated storage, derivative regeneration evidence, and a test
that reconciliation cannot format, delete, or silently rebind the preserved
volume.

## Evidence required to enable storage

- reviewed SSD health, filesystem, separate mount boundary, stable local
  identity, capacity, throughput, ownership, and read-only mount behavior;
- exact static-volume/claim design, node affinity, reclaim/retention behavior,
  rollout behavior, cluster rebuild sequence, and negative cross-namespace
  access tests;
- measured host and Kubernetes reservations, warning/critical thresholds,
  kubelet eviction settings, and CPU/memory/disk/network saturation tests that
  preserve SSH, private API access, and `pi-admin` with Kubernetes stopped;
- operator staging, atomic rename, corruption detection, encrypted backup,
  restore, and derivative-regeneration drills;
- current Cloudflare Free-plan, proxy, caching, Range, response-size,
  bandwidth, and acceptable-use review proving that origin streaming works
  without cache dependence.

Any missing or incompatible evidence keeps the chart storage profile disabled
and public media a `NO-GO`.

Current upstream references used for this proposal:

- <https://kubernetes.io/docs/concepts/storage/volumes/#local>
- <https://kubernetes.io/docs/concepts/storage/volumes/#hostpath>
- <https://kubernetes.io/docs/concepts/storage/persistent-volumes/#node-affinity>
- <https://kubernetes.io/docs/concepts/storage/storage-classes/#local>
- <https://kubernetes.io/docs/concepts/storage/persistent-volumes/#reclaiming>
- <https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/>
- <https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/>
- <https://go.dev/blog/osroot>
- <https://pkg.go.dev/net/http#ServeContent>
- <https://developers.cloudflare.com/cache/concepts/default-cache-behavior/>
- <https://www.cloudflare.com/service-specific-terms-application-services/>

## Rollback

Suspend the public Tunnel and website release, keep the data filesystem mounted
read-only or offline, and roll back only the application digest and Git desired
state. Never format, delete, or reuse the media volume as an application
rollback. If storage binding is uncertain after a rebuild, leave the claim and
workload disabled until the operator re-verifies the preserved filesystem and
checksums.
