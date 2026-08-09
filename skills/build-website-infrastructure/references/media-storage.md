# Heavy media storage and delivery

Use this reference for large image/audio/video work, persistent media, static
file serving, capacity, disk pressure, media backup, or edge delivery.

## Start with boundaries

1. Read the target repository's existing data ADRs and threat model before
   adding a persistent object, bucket, volume, mount, or public route.
2. Classify irreplaceable originals, protected publication metadata,
   regenerable browser derivatives, and unreachable staging separately.
3. Keep heavy bytes out of source history, frontend bundles, server embeds,
   container images, GitOps artifacts, and control-plane data unless the
   repository explicitly defines and tests a small bounded exception.
4. Give the public workload only the derivative/object prefix it needs, read
   only where possible. Never expose originals, staging, metadata, parent
   storage, listings, uploads, transcoding, authentication, a database, or a CMS
   implicitly.

## Select, do not assume, the storage model

For a new or unresolved storage profile, keep the feature disabled and reject
enablement. Do not invent a path, device, filesystem, bucket, class, node,
capacity, quota, concurrency, throughput, region, lifecycle, or billing value.
For an established repository, preserve and validate its selected CSI, object
storage, NFS, local-volume, or other model rather than replacing it with this
skill's examples.

When the discovered design deliberately selects a Kubernetes local volume,
evaluate static provisioning, retained reclaim behavior, explicit node affinity,
deterministic binding, and read-only workload mounts. Avoid `hostPath`; treat PV
capacity as metadata rather than a filesystem quota, keep bytes out of the
cluster datastore, and verify the dedicated mount before node/workload startup.
These local-volume rules do not apply to a repository that selected a different
backend.

## Publish and serve safely

For filesystem publication, stage on the same data filesystem outside the
serving boundary, verify expected size and digest, generate derivatives offline,
apply reviewed ownership/mode, flush data and metadata, then atomically rename a
regular file into place. Do not use symlinks, unsafe hard links, or in-place
rewrites. For object storage, derive equivalent integrity, atomic visibility,
versioning, lifecycle, and least-privilege controls from that provider.

Any serving implementation must reject traversal, links/escapes, reserved
segments, non-regular objects, directories, and listings; stream from a bounded
handle rather than loading whole media; define approved MIME behavior; protect
unknown formats with attachment and `nosniff`; distinguish immutable from
mutable cache policy; bound Range parsing, concurrency, open resources, and idle
writes without imposing a total deadline on valid large transfers. Test full,
HEAD, partial, conditional, If-Range, missing, malformed, traversal, link,
content-type, disabled, and overload paths. In Go, `os.Root`/`os.OpenRoot` plus
`http.ServeContent` is one implementation variant, not a universal mandate.

## Protect capacity and recovery

Derive operating-system, administrative, control-plane, and platform reserves,
workload budgets, eviction/low-space thresholds, transfer concurrency, and
traffic policy from the actual target. Separate media from root/control-plane
storage where the selected architecture permits it; monitor bytes and inodes;
stop publication at warning; suspend public load at critical pressure; never
delete originals automatically. Prove administrative access under CPU, memory,
storage, and network load, including any independent recovery path with the
orchestration layer unavailable.

Back up originals and protected metadata encrypted off-device or cross-provider
with checksum and timed restore evidence. Regenerate derivatives by default.
Test rollout, restart, rebinding/failover, control-plane rollback versus data
state, and storage loss as separate cases appropriate to the selected backend.

## Revalidate delivery terms

Retrieve current official edge, cache, Range, response-size, bandwidth, billing,
and service-specific terms every time. Cache is optional acceleration: cold,
evicted, or uncacheable requests can reach the origin. Record dated limits and
the go/no-go decision in the target repository, not this reusable skill. If
terms, entitlement, cost policy, durability, or origin capacity are incompatible
or unclear, keep production media disabled. Never treat cache bypass, Range,
object splitting, or origin capacity as a terms workaround.

Conditional implementation references:

- Kubernetes local storage: <https://kubernetes.io/docs/concepts/storage/volumes/#local>
- Kubernetes node pressure: <https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/>
- Go rooted filesystems: <https://go.dev/blog/osroot>
- Go static serving: <https://pkg.go.dev/net/http#ServeContent>
- Cloudflare cache behavior: <https://developers.cloudflare.com/cache/concepts/default-cache-behavior/>
- Cloudflare service terms: <https://www.cloudflare.com/service-specific-terms-application-services/>
