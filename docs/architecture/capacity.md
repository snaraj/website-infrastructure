# Discovery-gated capacity envelope

The Pi's usable compute, root/control-plane storage, dedicated media storage,
network path, and protected host workload must be measured before installation.
No committed CPU, memory, byte, inode, throughput, or concurrency value is a
production capacity claim. The default site releases, public Tunnel, and media
profile remain suspended or otherwise fail closed while those facts are
unknown.

## Budget model

Kubelet reservations must be derived from observed idle, peak, and recovery
behavior, then verified through the effective kubelet configuration and the
Node's reported `status.allocatable`. The budget is calculated in this order:

1. Reserve a hard minimum from raw host capacity for the Linux kernel, login
   sessions and SSH, the independent host-level `pi-admin` connector,
   containerd, kubelet, API server, scheduler, controller manager, stacked etcd,
   and emergency recovery.
2. Account for Kubernetes platform Pods such as DNS, Flux, desired-state
   admission, and the public connector with explicit requests/limits and
   operational headroom.
3. Define the remaining **safe website workload pool** from measured
   Allocatable rather than current utilization.
4. When the operator explicitly chooses, the two sites and public connector may be
   assigned roughly 90% of that safely discovered pool. The remaining margin
   is mandatory; “90%” never means 90% of raw hardware or permission to starve
   control-plane/administration services.

The small chart defaults are local scaffold values, not a 1 CPU/1 GiB product
ceiling. Until discovery produces a reviewed aggregate budget, each website
namespace uses a capacity-not-ready quota that admits zero Pods. Enabling a
release requires replacing that gate with quantities calculated from evidence,
not simply deleting isolation.

Two replicas on one node protect only against one process and some rollout
failures. They do not provide node, disk, ISP, Tunnel, or control-plane high
availability. No HPA or PodDisruptionBudget is installed initially.

## Storage isolation

The root/control-plane filesystem and future media-data filesystem are separate
failure domains. Media may eventually consume nearly all of the reviewed data
filesystem, but must never be able to consume the filesystem that carries SSH,
host logs, container images, kubelet state, static Pods, or etcd. A directory on
the root filesystem is not separation, and a PersistentVolume capacity field is
not a filesystem quota.

Final warning and critical thresholds remain unresolved. Discovery must measure
bytes and inodes, prove the expected device is actually mounted before kubelet
or reconciliation starts, and establish both root-filesystem kubelet eviction
signals and separate data-filesystem monitoring. The required response is:

- **warning:** reject new staging/publication, preserve current reads, and ask
  the operator to review capacity and checksums;
- **critical or unexpected root DiskPressure:** keep all publication blocked,
  reduce or suspend public workloads through the reviewed runbook, preserve the
  data volume and originals, and prioritize host administration/recovery;
- **missing/wrong data mount:** do not start a media consumer, because silently
  writing to a same-named root directory would defeat the isolation boundary.

The website never deletes originals or enables a paid storage fallback. Etcd
snapshots do not back up the media filesystem.

## Bounded media serving

The Go media path opens a regular file inside a directory-limited root and lets
the standard HTTP server seek/copy it; it does not allocate a buffer the size of
the object. A discovery-derived concurrent-transfer limit is mandatory whenever
media is enabled, stalled writes receive a per-write idle deadline rather than
an overall download deadline, and multipart Range work is bounded. No default
concurrency value exists because the upstream link, connector behavior, SSD,
and protected administration traffic have not been measured.

Cloudflare cache is never included as capacity. Free/Pro/Business objects above
the documented 512 MB cacheability ceiling bypass cache, cache entries can be
evicted, and cold locations reach the origin. More importantly, the current
self-serve terms make deliberate large-media delivery a zero-spend `NO-GO`, so
the disabled path cannot be activated merely because local load tests pass.

## Administration survival acceptance

These are live Pi acceptance tests, not Kind or workstation tests. Record only
redacted measurements and never intentionally fill the production root disk.

| Load case | Required evidence before a public release |
| --- | --- |
| CPU saturation | SSH and Kubernetes API remain responsive over the approved WARP identity/device path; system/control-plane processes receive their reserved capacity; public work is throttled or suspended first. |
| Memory pressure | Website Pods reach their limits or are evicted without OOM-killing sshd, `pi-admin`, kubelet, or control-plane processes; recovery login still works. |
| Data-volume warning/critical | New publication stops at warning; critical state cannot fill root/control-plane storage; originals remain intact and the site can be suspended safely. |
| Root/image filesystem pressure | Kubelet pressure/eviction behavior matches the complete reviewed threshold map; website Pods have no disk-pressure toleration and do not immediately reschedule into pressure. |
| Network saturation | Sustained public responses cannot prevent an interactive SSH session and API health check over WARP; a reviewed traffic-control or application concurrency limit protects the administration path. |
| Kubernetes/containerd stopped | Host-level `pi-admin` remains active and carries SSH independently; no public admin hostname or router forwarding appears. |
| Public Tunnel failure | Public sites go offline without affecting private SSH/API recovery and without exposing the origin or enabling a paid fallback. |

The final CNI, kube-proxy mode, cgroup hierarchy, kubelet reservation fields,
eviction threshold map, namespace quotas, priority behavior, and traffic policy
all remain discovery gates. Verify the effective runtime configuration rather
than assuming a checked-in file won precedence.

Official upstream references used for this model:

- <https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/>
- <https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/>
- <https://kubernetes.io/docs/concepts/storage/ephemeral-storage/>
- <https://kubernetes.io/docs/concepts/storage/volumes/#local>
- <https://kubernetes.io/docs/concepts/storage/volumes/#hostpath>
- <https://developers.cloudflare.com/cache/concepts/default-cache-behavior/>
- <https://www.cloudflare.com/service-specific-terms-application-services/>
