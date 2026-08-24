# Site capacity evidence — 2026-08-22

Measured evidence supporting the reviewed `namespace-budget` ResourceQuota for
`naranjo-online` and `lidersea-com`, replacing the `capacity-not-ready` gate that
admitted zero Pods. `docs/architecture/capacity.md` requires that the gate be
replaced with quantities calculated from evidence rather than simply deleted;
this document is that calculation, and each site quota is bound to these exact
bytes by its `platform.snaraj.dev/capacity-evidence-sha256` annotation.

Tracking issue: #201. The deadlock that prompted the review: #198.

## 1. Node allocatable

Read from the single-node cluster, read-only:

| Quantity | Capacity | Allocatable |
| --- | --- | --- |
| CPU | 4 | 3250m |
| Memory | 8127688Ki | 5506248Ki (~5377Mi) |
| Pods | — | 110 |

## 2. Platform reservation

Cluster-wide scheduled totals at the time of measurement:

| Quantity | Requests | Limits |
| --- | --- | --- |
| CPU | 1550m (47% of allocatable) | 4800m (147%) |
| Memory | 688Mi (12%) | 4436Mi (82%) |

Of those requests the two sites accounted for 100m CPU and 128Mi memory
(2 namespaces x 2 replicas x 25m/32Mi). Everything else in the measured
aggregate is treated conservatively as the platform reservation. This
subtraction is intentionally aggregate: it does not claim that any particular
desired-state component, including Kyverno, was installed at measurement time:

- CPU: 1550m - 100m = **1450m**
- Memory: 688Mi - 128Mi = **560Mi**

CPU limits already exceed allocatable at 147%. That is expected: limits are
ceilings, not reservations, and only requests participate in scheduling.

## 3. Safe website workload pool

Following the method in `docs/architecture/capacity.md` — allocatable, less the
platform reservation, less a mandatory margin, with at most roughly 90% of the
remainder available to the two sites and the public connector:

- CPU: (3250m - 1450m) x 0.9 = **1620m**
- Memory: (5377Mi - 560Mi) x 0.9 = **4335Mi**

## 4. Measured workload shape

Both site namespaces are identical:

| Fact | Value |
| --- | --- |
| Replicas | 2 |
| Rollout strategy | `maxSurge=0`, `maxUnavailable=1` |
| Per-Pod requests | `cpu=25m`, `memory=32Mi` |
| Per-Pod limits | `cpu=200m`, `memory=128Mi` |

Two constraints follow, and both are load-bearing for the numbers chosen below.

**Raising `pods` alone would have been cosmetic.** The out-of-band quota in
force before this review held `limits.memory` at `256Mi`, exactly two Pods'
worth. A third Pod could not have scheduled whatever `pods` said, so the CPU and
memory ceilings must scale with the Pod ceiling or the budget does not actually
expand.

**A ceiling equal to `replicas` reproduces the failure class of #198.** It
survives today only because `maxSurge=0` keeps the rollout from ever needing a
third Pod. A future zero-downtime rolling update would need a surge slot that
does not exist, and would fail closed against quota exactly as Helm's release
history did. The reviewed ceiling therefore carries deliberate headroom rather
than tracking the current replica count.

## 5. Reviewed budget

Per site namespace, a Pod ceiling of 6 — two replicas, a surge slot, and room to
grow — with every other quantity scaled from the measured per-Pod figures:

| Key | Value | Derivation |
| --- | --- | --- |
| `pods` | `6` | 2 replicas + surge + growth |
| `requests.cpu` | `150m` | 6 x 25m |
| `requests.memory` | `192Mi` | 6 x 32Mi |
| `limits.cpu` | `1200m` | 6 x 200m |
| `limits.memory` | `768Mi` | 6 x 128Mi |

## 6. Check against the safe pool

Both site namespaces' combined quota ceilings — not their current scheduled
totals — against section 3:

| Quantity | Combined quota ceiling | Safe pool | Utilisation |
| --- | --- | --- | --- |
| `requests.cpu` | 300m | 1620m | 19% |
| `requests.memory` | 384Mi | 4335Mi | 9% |

At measurement time the four scheduled site Pods requested 100m CPU and 128Mi
memory, as section 2 records. The 300m and 384Mi rows above instead represent
the full two-namespace quota ceiling if both namespaces used all six Pod slots.
Scheduling is governed by requests, and on that ceiling basis the budgets consume
under a fifth of the reviewed pool while leaving the public connector its share.

Limits are the deliberately looser half. The measured current scheduled totals
were 4800m CPU and 4436Mi memory, already including four site Pods at 200m and
128Mi each. Replacing only those current site totals with both namespace quota
ceilings gives the projection, not a current scheduled total:

- CPU: 4800m - (4 x 200m) + (2 x 1200m) = **6400m** (~197% of 3250m)
- Memory: 4436Mi - (4 x 128Mi) + (2 x 768Mi) = **5460Mi**;
  5460 / (5506248Ki / 1024) = **101.54%** (~102%)

Limits above allocatable are a normal overcommit posture and not a reservation;
the requests rows above are what must stay inside the pool, and they do by a
wide margin.

## 7. What this evidence does not establish

- **No high availability.** Two replicas on one node protect against a single
  process failure and some rollout failures. They do not provide node, disk,
  ISP, Tunnel, or control-plane redundancy, and this budget does not change that.
- **No storage claim.** Nothing here reviews filesystem capacity, inodes, or
  eviction thresholds; the storage sections of the capacity document remain open.
- **Not a production-graduation decision.** `release-policy.env` is untouched.
  Graduating a site under ADR 0014 is a separate owner decision.
- **A point-in-time measurement.** These figures were read once. They are
  evidence for a reviewed ceiling, not a continuous guarantee, and a material
  change in platform workloads warrants re-measuring.

- Opus5
