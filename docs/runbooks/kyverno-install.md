# Kyverno admission install — Draft / unverified

Current status is `NO-GO`. Nothing in this runbook authorizes a live
installation. It exists so that when installation *is* authorized, it is an
apply of reviewed bytes from an exact reviewed commit rather than an ad-hoc
command — and so that the review of those bytes, and of the ordering, can happen
now, in a pull request, instead of at the terminal at the moment of highest
consequence.

## STAGE 2 IS **NOT AUTHORIZED**

Read this before anything else in this document.

The pull request that introduced this runbook landed the install **transaction**
and **stage 1 only**. Stage 1 is `Audit` and `failurePolicy: Ignore` — fail-open,
enforcing nothing, degrading at worst to the cluster's state today. **Promoting
to stage 2 (`--stage enforce`) is not authorized by it**, and three independently
reproduced findings block the promotion:

| Blocker | What is wrong | Status |
| --- | --- | --- |
| **#99** | Both `require-signed-*` policies render `validationFailureAction: Audit` with **no rule-level `failureAction`** in the `enforce` root, so stage 2 **does not enforce image signatures** — an unsigned or wrong-identity image is reported and admitted while the installer announces admission is fail-closed. | CONFIRMED against the rendered `enforce` root |
| **#100** | The engine configuration filters `[ReplicaSet,*,*]` and `[ReplicaSet/?*,*,*]`, so `require-release-readiness`'s exact-Deployment-owner rule is **inert at admission**. Unfiltering it widens the enforcing webhook's blast radius on a one-node cluster and is an owner decision. | CONFIRMED against `enforce/config.yaml` |
| **#102** | The promotion has **no admission canary** on either side of the flip, and its evidence is not bound to the exact installation. | CONFIRMED as a gap |

**#87** (connector identity) and **#96** (the storage-gate pivot) must also land
first. #101 tracks two further defects on the same execution path.

This is not only written down. `render.lock` records
`stage.enforce.authorized=no`, and
[`scripts/install-kyverno-admission.sh`](../../scripts/install-kyverno-admission.sh)
reads it **before it binds a single tool**:

```
$ ./scripts/install-kyverno-admission.sh --stage enforce --apply --journal /tmp/j
install-kyverno-admission: stage enforce is NOT AUTHORIZED: promotion is blocked
on #99, #100, #102 (and #87, #96 must land first); see
docs/runbooks/kyverno-install.md. Authorization is a reviewed change to
render.lock, never an edit made during a ceremony
$ echo $?
1
```

`--stage enforce --plan` still runs — it mutates nothing and is how the promotion
gate is rehearsed and tested — and prints the same refusal as a warning.
Authorizing stage 2 means a reviewed pull request that flips
`stage.enforce.authorized`, with peer/platform validation recorded on it. It is
never an edit made during a ceremony.

## Why this is the most dangerous install in this repository

Every other component here fails by not working. An admission controller fails
by making the API server refuse writes.

A `ValidatingWebhookConfiguration` with `failurePolicy: Fail` tells the API
server to reject any request it cannot get an answer for. Registered against a
backend that is not answering — wrong Service, unissued certificate, denied
egress, unscheduled Pod — every matching write in the cluster becomes a 500,
including the writes needed to fix it. This cluster is one node, with one
operator, and no second control plane. That state is reached by a single
successful `kubectl apply`, and it is the state this entire design exists to
make unreachable.

## What is true today

Measured read-only on 2026-08-12 (a dated observation, not a constant —
revalidate read-only before the ceremony):

- Kyverno is **not installed**: zero `kyverno` CRDs, no `kyverno` namespace, and
  **zero `ValidatingWebhookConfiguration` objects cluster-wide**.
- Every `ClusterPolicy` under [`policies/kyverno/`](../../policies/kyverno) is
  therefore an inert marker. Nothing validates what enters the app namespaces.
- The Flux controllers are pinned and reviewable but hold no custom resource,
  so nothing is reconciling either.
- [`kubernetes/platform/admission/kyverno/controllers.yaml`](../../kubernetes/platform/admission/kyverno/controllers.yaml)
  is a deliberate fail-closed sentinel: an all-zero image digest, an unreachable
  Service, `failurePolicy: Fail`. It documents the shape and cannot be applied.

## The hard gate

**This install is a precondition for un-suspending any Flux object.**

Flux reconciles with `prune: true`. The moment a `suspend` flips, whatever Flux
applies is admitted by whatever admission control exists at that instant — and
today that is none. The image-signature, restricted-workload, tenant-networking,
storage, and release-readiness policies would be bypassed not because anything
disabled them but because nothing was ever listening.

So the order is: admission installed and enforcing, *then* a suspend flip is
even discussable. That ordering is the peer platform lane's requirement and this
runbook does not soften it.

## What is missing before any apply is possible

`versions.env` carries `KYVERNO_CLI_VERSION` — the CLI that runs the policy
fixtures in CI — and **no controller pins at all**. The installer requires five,
and refuses every apply path until they exist:

| Pin | What it binds |
| --- | --- |
| `KYVERNO_VERSION` | the controller release, expected to match the reviewed CLI version |
| `KYVERNO_CHART_VERSION` | the chart the component export is rendered from |
| `KYVERNO_ADMISSION_CONTROLLER_IMAGE` | `reg.kyverno.io/kyverno/kyverno` at a full digest |
| `KYVERNO_REPORTS_CONTROLLER_IMAGE` | `reg.kyverno.io/kyverno/reports-controller` at a full digest |
| `KYVERNO_KYVERNOPRE_IMAGE` | `reg.kyverno.io/kyverno/kyvernopre` at a full digest |

Those are platform-lane values. This lane requests them and does not invent
them; `versions.env` is not edited from here. Until they land, and until the
sentinel controller manifest is replaced by the reviewed component export
described in
[`render.lock`](../../kubernetes/platform/admission-install/render.lock), the
installer stops at its pin guard. Reproduce that refusal at any time:

```sh
./scripts/install-kyverno-admission.sh --stage report-only --plan
```

It renders, proves the render matches the lock, and then refuses. That refusal
is the intended state of this work.

## The two stages, and why they are not one

| | Stage 1 — `report-only` | Stage 2 — `enforce` |
| --- | --- | --- |
| webhook `failurePolicy` | `Ignore` | `Fail` |
| policy action | `Audit` | `Enforce` |
| a broken install means | no admission control — today's state | **no writes** |
| everything else | identical | identical |

[`kubernetes/platform/admission-install/report-only`](../../kubernetes/platform/admission-install/report-only)
is an overlay of
[`.../enforce`](../../kubernetes/platform/admission-install/enforce), so the two
stages cannot describe different controllers, bounds, or network — the suite
asserts their renders differ only in `failureAction`, `validationFailureAction`,
and `failurePolicy`. Promotion changes those fields and nothing else.

Stage 2 cannot be reached from an empty cluster. `--stage enforce` refuses
unless the live cluster proves stage 1 ran: every Kyverno Deployment Available,
every reviewed `ClusterPolicy` present **and reporting `Audit`**, and at least
one `PolicyReport` or `ClusterPolicyReport` object in existence. A promotion
without report evidence would be enforcement promoted on unmeasured blast
radius.

## Blast radius of stage 2, stated before it is taken

Once `failurePolicy: Fail` is registered, these become hard failures rather than
findings. Read this list as "what stops working if Kyverno stops answering":

- **Cluster-wide, in every namespace except `kube-system`, `flux-system`, and
  `kyverno`:** no non-`ClusterIP` Service, no `Ingress`, no Gateway API object,
  and no storage object outside the enumerated allowlist — `PersistentVolume`,
  `PersistentVolumeClaim`, `StorageClass`, `CSIDriver`,
  `VolumeAttributesClass`, and `StatefulSet` claim templates are all matched.
  `disallow-public-services` and the non-namespaced rules of
  `disallow-undiscovered-storage` reach every namespace.
- **The storage stance is an allowlist, not a kind denial.** The owner's ruling
  of 2026-08-12 permits StorageClasses, PersistentVolumes, and
  PersistentVolumeClaims; what is refused is storage reachable from outside the
  cluster by any means that has not been enumerated. Pull request #96 implements
  that pivot: the admitted volume sources are derived BY SUBTRACTION (only
  `local` and `csi` survive), against enumerated classes, provisioners, CSI
  drivers, and local roots. The CSI driver list is currently empty, so the
  practical stage-2 posture for CSI is unchanged from the previous
  deny-by-kind — a driver install is still refused, but now because it is not on
  the allowlist rather than because the kind is forbidden, and admitting one is
  an allowlist entry in a reviewed change rather than a policy rewrite. Read
  `policies/kyverno/disallow-undiscovered-storage.yaml` for the exact rules
  rather than a summary here; a runbook that restates a policy drifts from it.
  (Known-stale names: the policy `disallow-undiscovered-storage` and its rule
  `disallow-persistent-storage-resources` still describe the retired
  deny-by-kind stance. A rename is queued as a follow-up — it would collide with
  two other in-flight branches today.)
- **In `cloudflare-public`, `naranjo-online`, `lidersea-com`:** the full
  restricted-workload, approved-image, exact-networking, media-payload,
  release-readiness, and zero-capacity contracts. A site Deployment whose
  readiness annotation is not `true`, or whose image is not the canonical
  digest, stops being admitted.
- **Nothing in `kube-system`, `flux-system`, or `kyverno`**, by explicit
  exclusion — see below.

### The namespaces that are never intercepted, and why

Three exclusions, in two independent layers (engine `resourceFilters`, which is
evaluated before any policy runs, and the webhook `namespaceSelector`, which
stops the API server calling out at all). Both live in
[`admission-install/enforce/config.yaml`](../../kubernetes/platform/admission-install/enforce/config.yaml):

- `kube-system` — intercepting the control plane means a webhook outage can stop
  CoreDNS, the CNI, or a static Pod mirror from being written.
- `flux-system` — admission must never be able to block the reconciler that
  would repair admission.
- `kyverno` — self-exclusion. A controller that must pass its own webhook to
  start cannot restart.

The kubelet identity (`system:nodes`) is excluded for the same reason: without
it, a webhook outage becomes a node outage.

### The selector defect this replaced

The committed sentinel's webhook scoped interception with
`namespaceSelector: In [cloudflare-public, naranjo-online, lidersea-com]` —
three hard-coded namespace **names**. An inclusion list is fail-open by
construction: a namespace created tomorrow matches nothing, so nothing about it
is ever validated, and the gap is silent.

The install path therefore does not apply that object at all (registration is
the controller's act — see below), and the reviewed interception scope is an
**exclusion**: `NotIn [kube-system, flux-system, kyverno]`. A new namespace is
intercepted by default; only the three lockout-critical namespaces are exempt.

**Residual gap, stated rather than papered over.** The webhook will now *reach*
a new namespace, but most policies still *match* by namespace name
(`match.resources.namespaces: [cloudflare-public, naranjo-online, lidersea-com]`).
A new namespace therefore inherits only the cluster-wide rules listed under
blast radius — the Service, Ingress, Gateway, storage, and StatefulSet denials —
and not the workload, image, or signature contracts. Closing that fully means
changing what the committed policies match, which changes what they enforce in
the existing namespaces too. That is a separate reviewed change, not something
to slip into an install transaction.

## Ordering, and the deadlock it avoids

[`kubernetes/platform/prerequisites/network-policies.yaml`](../../kubernetes/platform/prerequisites/network-policies.yaml)
declares a bare ingress+egress `default-deny` for the `kyverno` namespace and no
allows, and
[`kubernetes/reconciliation/admission.yaml`](../../kubernetes/reconciliation/admission.yaml)
`dependsOn` `platform-prerequisites` with `wait: true`. Reconciled in that order
against a cluster where the allows are absent, the controller can never reach
the API server, never becomes Available, and the admission Kustomization waits
forever on a readiness its own predecessor made impossible.

The installer's phase order exists to make that unreachable:

1. `namespace`
2. `bounds` — the ResourceQuota and LimitRange, before anything can schedule
3. `network` — the deny **and its four allows in one apply**, so there is never
   a window in which the namespace is closed and unreachable, nor one in which
   it is open
4. `controller` — CRDs, RBAC, config, Service, Deployments; then **wait** for
   the policy CRD to be Established and every Deployment to be Available
5. `policies` — only now, when the backend is proven, do the objects exist that
   cause Kyverno to register webhooks

There is deliberately **no webhook phase**. Kyverno writes its own webhook
configurations, through its own RBAC, after it is running. A render that
declares one is refused: applying a webhook by hand points the API server at a
backend whose health nothing proved, which is the entire failure mode.

The four allows, and what each is for:

| Policy | Direction | Destination | Why |
| --- | --- | --- | --- |
| `kyverno-admission-webhook` | ingress | API server `/32`, TCP 9443 | the API server must reach the webhook, or `Fail` means "refuse everything" |
| `kyverno-dns` | egress | `kube-system` / `kube-dns`, 53 TCP+UDP | resolution for the API server and the Sigstore endpoints |
| `kyverno-kube-apiserver` | egress | API server `/32`, TCP 6443 | watches, reports, and the controller's own webhook registration |
| `kyverno-public-https` | egress | public addresses, TCP 443 | `verifyImages` — keyless verification is not an offline operation |

The API-server destination is committed as `192.0.2.0/32` (RFC 5737 TEST-NET-1),
an address that can never match anything real: safety invariant 12 keeps the
real one out of this public index permanently. The installer substitutes it from
the bound kubeconfig context's `server` value — the same value the binding guard
already proved — and refuses to apply anything in which the sentinel survives.
Nothing is typed by hand and nothing reaches shell history.

## Resource envelope

Node figures recorded 2026-08-12; revalidate read-only before the ceremony.

```
node allocatable                      3250m CPU   5502Mi memory
requested after the Flux install      1500m CPU    624Mi memory
headroom                              1750m CPU   4878Mi memory

Kyverno steady state
  2 controllers x 1 replica x (100m / 192Mi)
                                       200m CPU    384Mi memory
                                     = 11.4% of CPU headroom
                                     =  7.9% of memory headroom
remaining for sites and connectors    1550m CPU   4494Mi memory
```

The `namespace-budget` ResourceQuota (`pods: 4`, `requests.cpu: 400m`,
`requests.memory: 768Mi`, `limits.cpu: 2`, `limits.memory: 1536Mi`) is the part
that holds: it is enforced by the API server, so the bound survives a future
render that adds a controller, a replica-count mistake, or a values change
nobody re-derived. Steady state uses half the request quota; the other half is
the rolling-update surge.

`replicas: 1` because this is one node — a second replica has nowhere to be
scheduled that adds availability. `priorityClassName: system-cluster-critical`
deliberately **above** the sites: an evicted admission controller with an
enforcing webhook registered turns every matching write into a failure.
Consumption is bounded by the quota; not being the first thing killed is what
the priority class is for. The Flux controllers already ship at this class.

## Preconditions for the apply — every one of them, and none of them local

This runbook performs none of these and asserts none of them:

1. The controller pins above exist in `versions.env` and the sentinel component
   manifest has been replaced by the reviewed export, in a merged pull request.
2. The peer platform lane's recovery window is **closed**, with `sudo -n` proven
   unavailable on the host.
3. That lane's Service-CIDR repair, controlled reboot, post-reboot acceptance,
   and canaries have completed.
4. `CODEX_PLATFORM_STABLE` has been signalled.
5. The owner has authorized the install.

**No reboot originates from this ceremony.** Nothing here restarts, reboots, or
power-cycles the host, and an install that appears to need one has failed a
precondition instead.

Until all five hold, stop here. Reading the manifests and reproducing the render
digests below requires none of them and is the intended use of this document
today.

## Step 0 — bind the target, from private custody

```sh
export KUBECONFIG="$PROTECTED_KUBECONFIG"
export KYVERNO_INSTALL_CONTEXT="$REVIEWED_CONTEXT"
export KYVERNO_INSTALL_SERVER="$REVIEWED_SERVER"
```

All three are required for every mode that contacts the cluster. The installer
proves the context exists in that kubeconfig, that the context's cluster names
exactly `KYVERNO_INSTALL_SERVER`, and that the server is an IPv4 address — a
name cannot be turned into a NetworkPolicy destination, and guessing one would
be the deadlock above. Every `kubectl` call then passes `--kubeconfig`,
`--context`, and `--server` explicitly; nothing is inferred from ambient state.

## Step 1 — plan stage 1

```sh
./scripts/install-kyverno-admission.sh --stage report-only --plan
```

This renders the stage, proves the digest and object inventory against
`render.lock`, proves the tools are the `versions.env` versions and are not
resolved from inside the checkout, proves every image is one of the pinned
digests, proves the lockout exclusions are in the bytes, proves the stage's
action fields match the stage that was asked for, substitutes the API-server
destination, client-validates every object with `--validate=strict`, and proves
nothing it would create already exists. It mutates nothing.

Record the printed digest with the commit SHA. A digest that does not reproduce
means the tree, the tool, or the commit is not the reviewed one, and the
ceremony stops.

## Step 2 — apply stage 1

```sh
./scripts/install-kyverno-admission.sh --stage report-only --apply \
  --journal "$PROTECTED_ROOT/kyverno-stage1.journal"
```

The journal is required, and its path must be outside the checkout: it is the
only record of what this attempt created, and it has to survive the process so
an apply that dies between phases is still undoable by hand. That is enforced,
not merely asked for — `--apply` refuses a journal path inside the checkout, a
symlinked path, and a path that already records an earlier attempt, and it
creates the file under `umask 077`.

If any phase fails, the installer rolls the journal back in reverse order,
sweeps the webhook configurations Kyverno may already have registered for
itself, and proves zero residue before exiting non-zero.

## Step 3 — verify stage 1, and verify it is fail-open

```sh
kubectl -n kyverno get deploy,pods
kubectl get clusterpolicy
kubectl get validatingwebhookconfiguration -o yaml | grep -A2 failurePolicy
kubectl get policyreports -A
kubectl get clusterpolicyreports
```

Expected: Deployments Available, Pods `Running` and not restarting, every
reviewed policy present, **every registered webhook reporting
`failurePolicy: Ignore`**, and reports being produced. A webhook reporting
`Fail` at this point means the report-only overlay did not reach the cluster —
demote immediately (step 6) and investigate before going further.

Then leave it alone and let it observe real traffic. The reports are the
evidence stage 2's gate demands, and they are also the only honest measurement
of what enforcement will refuse.

## Step 4 — the promotion gate

Do not run step 5 until all of these hold:

1. Stage 1 has been running long enough to have seen a real reconcile, a real
   site deploy, and a real connector restart.
2. Every violation in the accumulated reports has been read and is either
   intended (the policy is right, the workload is wrong) or has produced a
   reviewed policy change. **An unexplained violation is a stop.**
3. The break-glass path below has been rehearsed by the operator who will run
   step 5, on this cluster, so it is muscle memory rather than a document.
4. The owner has authorized the promotion as a separate decision from step 2.

## Step 5 — promote to stage 2

> **STAGE 2 IS NOT AUTHORIZED.** The blocker table at the top of this document
> is the gate, not the four conditions in step 4: promotion is blocked on #99,
> #100 and #102, and #87 and #96 must land first. This step is written down so
> the procedure is reviewable, not because it is available. `render.lock`
> carries `stage.enforce.authorized=no` and the installer refuses `--stage
> enforce --apply` before it binds a tool, so a reader who arrives at this
> anchor without reading the top of the document is stopped by the script
> rather than by this paragraph.

```sh
./scripts/install-kyverno-admission.sh --stage enforce --plan
./scripts/install-kyverno-admission.sh --stage enforce --apply \
  --journal "$PROTECTED_ROOT/kyverno-stage2.journal"
```

The plan re-proves every guard and additionally proves stage 1's evidence. The
apply re-applies the same objects with the two action fields changed; it creates
nothing. If it fails, the installer **demotes** back to the report-only bytes
rather than deleting anything — deleting an installation to revert a
policy-action change would be a far larger act than the change being reverted.

Verify immediately, and have step 6 ready in another shell:

```sh
kubectl get validatingwebhookconfiguration -o yaml | grep -A2 failurePolicy
kubectl -n kyverno logs deploy/kyverno-admission-controller --tail=100
kubectl -n naranjo-online get events --sort-by=.lastTimestamp | tail
```

## Step 6 — break-glass

**If the cluster starts refusing writes, do this first and diagnose second.**

```sh
./scripts/install-kyverno-admission.sh --break-glass
```

It deletes the Kyverno webhook configurations — by the reviewed names and by the
`webhook.kyverno.io/managed-by=kyverno` label — and nothing else. The API server
stops calling admission immediately; writes resume; the controllers, policies,
and namespace all stay in place so the state is still diagnosable.

If the script itself is unavailable, the two commands it runs are:

```sh
kubectl delete validatingwebhookconfiguration -l webhook.kyverno.io/managed-by=kyverno
kubectl delete mutatingwebhookconfiguration -l webhook.kyverno.io/managed-by=kyverno
```

Deleting a webhook configuration is safe in a way that deleting the controller is
not: it is the single object that makes the API server wait for an answer, and
removing it cannot itself require an answer.

## Rollback

- **Undo the promotion only** — back to fail-open, one apply:

  ```sh
  ./scripts/install-kyverno-admission.sh --demote
  ```

- **Undo the installation** — remove exactly what an attempt created:

  ```sh
  ./scripts/install-kyverno-admission.sh --rollback \
    --journal "$PROTECTED_ROOT/kyverno-stage1.journal"
  ```

  It sweeps the runtime-registered webhook configurations first, deletes every
  journaled identity in reverse order, and then **proves** no Kyverno webhook
  configuration, `kyverno.io` CRD, or `kyverno` namespace remains. A rollback
  that does not prove the cluster is clean is a hope, not a rollback.

Neither path touches the websites. They are served by their tunnels
independently of whether admission exists — which is also why the whole
ceremony can be attempted, abandoned, and reattempted without a maintenance
window.

## What stays suspended

Nothing in this ceremony changes any `suspend` field, and it never applies an
object that carries one. `kubernetes/reconciliation/*.yaml` and the site
releases remain `suspend: true` afterwards.

Flipping any of them is a separate reviewed pull request whose preconditions
include this install being complete **at stage 2** — a controller in stage 1
reports violations and admits them, which is not admission control. Installing
admission and un-suspending Flux are two decisions, taken in that order, by the
owner.
