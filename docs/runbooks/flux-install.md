# Flux controller install — reviewed Git contract, live install already drifted

Current repository status is `NO-GO` for reconciliation. This runbook defines
an inert, authenticated installation and a bounded live-validation package; it
does not authorize an operator to use either one. Every live mode reads the
protected flattened kubeconfig and uses its client credential through kubectl.
The protected coordinator must record separate authorization, exact reviewed
inputs, prestate, commands, results, and poststate before a live run.

A stock upstream Flux install is ALREADY on the cluster and does not match the
desired state below. Read "Live prestate" next; every "fresh" precondition in
this document is a precondition, not a description of the cluster.

The install surface is
[`kubernetes/flux-system/controllers`](../../kubernetes/flux-system/controllers).
It contains the three pinned Flux controllers, their CRDs, Services, and
least-privilege RBAC. It contains no `GitRepository`, `Kustomization`,
`HelmRelease`, Secret, SOPS material, Tunnel route, or website release. The
controller install therefore creates no Flux-managed workload and changes no
public route.

The root sync objects remain separate. Nothing here creates a Flux custom
resource, changes a `suspend` field, handles a Secret, or touches Cloudflare.
Those operations require a separate reviewed pull request and owner approval.

## Live prestate — the cluster is NOT a green field

Read this before anything else in this document. **Flux is already installed on
the cluster.** It was applied on 2026-08-12 from a STOCK upstream v2.9.3 render
— not from this repository's reviewed overlay, and not through the installer
described below. Everything after this section describes the DESIRED state this
repository reviews and the ceremony that would create it on a cluster that does
not already have one. It does not describe the cluster.

The differences are security-relevant, not cosmetic. Against the reviewed
desired state, the live install carries at least:

| Live (stock upstream render) | Reviewed desired state |
| --- | --- |
| `cluster-reconciler-flux-system` ClusterRoleBinding grants `cluster-admin` to the kustomize and helm controllers | that binding is deleted by the overlay; the only ClusterRoleBinding is `crd-controller-flux-system` |
| that binding's subject list names four ServiceAccounts that do not exist | subjects are exactly the three ServiceAccounts the install creates |
| the `allow-egress` NetworkPolicy keeps upstream's blanket `egress: [{}]` — every `flux-system` Pod may egress anywhere | the blanket rule is patched away and only enumerated flows are allowed |
| the `flux-system` Namespace carries Pod Security `warn` only | `enforce`/`audit`/`warn` restricted at a pinned version |

What is NOT drifted, and is worth stating because it bounds the urgency: the
live install has ZERO Flux custom resources — no `Kustomization`,
`GitRepository`, `HelmRelease`, `OCIRepository`, `HelmRepository`, `HelmChart`,
`Bucket`, or `ExternalArtifact`. Nothing is reconciling, so the excess authority
above is standing privilege rather than an active reconciliation path.

**Reviewing and merging this desired state converges nothing.** The repository
ships the reviewed manifests, the executable installer, and this runbook.
Bringing the cluster to that state is a separate, separately owner-authorized
operational step, and the two
available options are set out in "Converging the existing install" below. The
installer's `--apply` mode is fresh-install-only and will REFUSE this cluster;
that refusal is correct and is not a defect to work around.

## Why the install is inert

The install root renders exactly 24 objects:

- one Namespace;
- eight Flux CRDs;
- three ClusterRoles and one ClusterRoleBinding after the overlay deletes the
  generated `cluster-reconciler-flux-system` binding;
- one ResourceQuota, three ServiceAccounts, one Service, three generated
  NetworkPolicies, and three Deployments in `flux-system`.

The overlay never restores `cluster-admin`. The only rendered
ClusterRoleBinding is `crd-controller-flux-system`, and its subjects are the
three ServiceAccounts that this install actually creates. Reconciliation later
uses the namespaced impersonation/RBAC contract from the current main branch;
this PR does not replace it with generated broad authority.

The root sync objects live in
[`kubernetes/flux-system/gotk-sync.yaml`](../../kubernetes/flux-system/gotk-sync.yaml).
They are not part of the 24-object render. With no Flux custom resource to
watch, the controllers elect leaders, establish watches, and idle. Both public
sites continue through their independent outbound Cloudflare Tunnels whether
Flux exists or not.

## Why the apply is ordered

The generated `allow-egress` policy is patched so that its blanket
`egress: [{}]` rule is removed. What remains selects the whole namespace for
Ingress and Egress with no allow rule: on an enforcing CNI it is a namespace
default deny. Starting controller Pods before DNS and Kubernetes API reachability
exists would deadlock leader election and cache startup.

The installer owns this order:

| Phase | Exact mutation | Invariant |
| --- | --- | --- |
| 1 | the 21 non-Deployment objects from the controller render | no controller Pod exists |
| 2 | `default-deny`, `flux-controllers-dns`, `flux-controllers-artifacts`, and `flux-controllers-kube-apiserver` | only reviewed startup flows exist |
| 2b | one `flux-api-reachability-canary` Pod | the selected-CNI in-Pod Service/API path must succeed; the Pod is then deleted and proved absent |
| 3 | the three controller Deployments | Pods start only after the executable API-path proof |
| 4 | `flux-controllers-public-https`, in a separate absent-only transaction | permitted only after scalable readiness, idleness, and exact startup-policy checks |

The canary runs as `source-controller`, carries the same `app:
source-controller` and `app.kubernetes.io/part-of: flux` labels selected by the
controller policies, uses the `source-controller` ServiceAccount, and calls
`https://kubernetes.default.svc:443/api` with the mounted ServiceAccount token
and cluster CA. It does not call the operator `--server` from inside the Pod.

## Selected-CNI API destination contract

This revision supports one reviewed dataplane contract: `--cni-provider
calico`. Before any mutation, the installer proves the live DaemonSet is exactly
`kube-system/calico-node`, has `k8s-app=calico-node`, and selects
`k8s-app=calico-node`. An API, RBAC, timeout, diagnostic, identity, or selector
failure stops the run.

Calico evaluates this workload egress after Service translation. The Pod calls
the Kubernetes Service on TCP 443, while the NetworkPolicy must name every
actual API backend as an explicit `/32` on TCP 6443. Those private backends are
provided with one or more repeated `--api-endpoint` options. Before mutation,
the sorted supplied set must equal the complete authenticated, explicitly-ready
IPv4 address set from every `kubernetes.default` EndpointSlice, with exactly the
reviewed `https`/TCP/6443 port. The bound snapshot includes each slice name,
UID, resourceVersion, address type, port, readiness, and address, and is checked
again across every mutation boundary. A missing, extra, duplicate, stale,
malformed, unready, or concurrently changed member fails closed. The endpoints
are never inferred from the operator-facing `--server`, because a local proxy,
VIP, DNS name, or future HA endpoint set can make the two surfaces different.

The committed policy keeps `192.0.2.0/32` as a non-routable sentinel. In a
mode-0700 temporary directory the installer replaces the one reviewed sentinel
block with a sorted, unique set of at most 16 canonical IPv4 `/32` peers. It
then collapses that private set back to the sentinel and requires byte identity
with the reviewed render. No other byte may change, and the private endpoint
set is neither written to Git nor printed as evidence.

A CNI other than Calico, an unproved Calico identity, IPv6, a subnet, a
duplicate, loopback, multicast, noncanonical IPv4 text, an endpoint set that is
not the complete authenticated live EndpointSlice set, or a set that does not
make the in-Pod canary succeed is a stop condition. EndpointSlice membership
proves every allowed `/32`; the canary separately proves one authenticated
Service/dataplane path. Supporting another CNI requires its own reviewed
destination and canary contract; changing the flag is not sufficient.

## Preconditions and absolute boundary

Before any cluster-touching mode:

1. use a clean checkout of the exact reviewed commit;
2. use the protected flattened kubeconfig and reviewed context/server tuple;
3. obtain the selected Calico API backend set from protected platform evidence,
   not Git or PR comments;
4. verify recovery access and a second protected operator session;
5. keep all output containing connection errors in protected custody; and
6. stop if the CNI identity, controller prestate, Flux custom-resource prestate,
   or policy prestate differs from the reviewed plan.

**Never apply `kubernetes/flux-system` — the parent root.** It carries
`gotk-sync.yaml`, whose root reconciliation object has no `suspend`, enables
pruning, and points at live desired state. Applying it can start reconciliation.
The installer target is a constant and cannot be redirected to that root.

No step in this runbook authorizes a Flux custom resource, unsuspend, SOPS/age
ceremony, Secret, public route, website rollout, NodePort, LoadBalancer,
Ingress, Gateway, host port, or host network. Stop rather than expand the scope.

## Bindings shared by every live mode

`--plan`, `--apply`, and `--open-public-egress` require all of these inputs:

- `--kubeconfig`, `--context`, and `--server`: every API operation carries the
  exact tuple, and the named context must resolve to the named server;
- `--cni-provider calico` and one repeated `--api-endpoint` per private API
  backend: the policy contract is independent from the operator endpoint;
- `--expect-render-sha256`, `--expect-egress-sha256`, and
  `--expect-canary-sha256`: controller, policy-template, and executable-canary
  bytes must all reproduce review evidence;
- `--expect-commit`: binds the installer and every guard, not just its output;
- the `versions.env` Kustomize version and Linux AMD64 executable SHA-256,
  Kubernetes client version, platform kubectl binary SHA-256, and exact tagged-and-digested
  `FLUX_API_CANARY_IMAGE`.

The installer first resolves each executable, copies it into its mode-0700 work
directory, removes write permission, hashes that private copy, and only then
invokes the copy. A matching self-reported version is not provenance. The
current Kustomize executable pin deliberately admits only the reviewed official
Linux AMD64 v5.8.1 bytes for a live ceremony.

An OCI identity such as `image:vX.Y.Z@sha256:...` is both readable and
immutable; the digest remains part of the identity. Release tags remain exactly
`vX.Y.Z`.

Prepare arguments without printing the private endpoint set:

```sh
API_ENDPOINT_ARGS=(--api-endpoint "$REVIEWED_API_ENDPOINT_1")
# Append one pair per additional reviewed backend, for example:
# API_ENDPOINT_ARGS+=(--api-endpoint "$REVIEWED_API_ENDPOINT_2")

COMMON_ARGS=(
  --kubeconfig "$PROTECTED_KUBECONFIG"
  --context "$REVIEWED_CONTEXT"
  --server "$REVIEWED_SERVER"
  --cni-provider calico
  "${API_ENDPOINT_ARGS[@]}"
  --expect-render-sha256 "$REVIEWED_RENDER_SHA256"
  --expect-egress-sha256 "$REVIEWED_EGRESS_SHA256"
  --expect-canary-sha256 "$REVIEWED_CANARY_SHA256"
  --expect-commit "$REVIEWED_COMMIT"
)
```

## Step 0 — reproduce all three renders offline

```sh
./scripts/install-flux-controllers.sh --render
```

This contacts no cluster. It validates the pinned tools, immutable images,
exact 24-object controller inventory, 21 + 3 controller split, 4 + 1 policy
split, restricted Pod Security labels, deleted blanket egress, absence of Flux
custom resources and Secrets, least-privilege effective RBAC inventory, and the
one-Pod canary shape. It prints three render SHA-256 values and the source
commit. Compare them with independently reviewed evidence; do not bless values
from the execution checkout merely because they are reproducible.

## Step 1 — plan against the exact target

```sh
./scripts/install-flux-controllers.sh --plan "${COMMON_ARGS[@]}"
```

The plan renders and validates all three surfaces, proves the selected Calico
identity, authenticates the supplied private endpoint set against the complete
live `kubernetes.default` EndpointSlice set, expands and round-trips it,
performs **client-side strict validation**, and runs read-only existence,
ownership, and server-dry-run checks. It does not create the canary or any other
object.

Where no `flux-system` Namespace exists, server dry-run cannot persist the
dry-run Namespace before validating its children
([kubernetes/kubernetes#83562](https://github.com/kubernetes/kubernetes/issues/83562)).
The expected, healthy result is exactly 13 independently creatable objects
(Namespace, eight CRDs, three ClusterRoles, one ClusterRoleBinding) and 11
namespaced children reporting `namespaces "flux-system" not found`. Any other
error, object, namespace, status, or diagnostic fails closed. Client-side strict
validation still covers all 24 objects and the policy/canary renders.

**That is not what this cluster will report.** `flux-system` already exists
here, so the plan takes the existing-installation path below and the
`namespaces "flux-system" not found` lines will be absent. Their absence is
expected on this cluster; seeing them would mean the Namespace had gone away
since the prestate capture, which is itself a stop condition.

On an existing installation — which is the current cluster — `--plan` may
classify the surface and verify ownership read-only, and it is the only mode
this cluster is eligible for today. `--apply` remains fresh-install-only: it
refuses an existing `flux-system` because a creation ledger cannot restore
unknown prestate after an in-place rewrite. Expect and require that refusal
here; a run that proceeds is a defect in the installer, not progress.

## Step 2 — apply, in phases

```sh
./scripts/install-flux-controllers.sh --apply "${COMMON_ARGS[@]}"
```

Run only when the plan proves the complete fresh state. **The current cluster
does not satisfy that precondition** and this step is unreachable on it until
one of the convergence options below has been separately authorized and
executed. The installer gives
every object an unpredictable 256-bit per-attempt annotation and uses
`kubectl create --save-config`, never a reconciling mutation. It creates phase
1, phase 2, creates the exact canary absent-only, waits up to 60 seconds for
`Succeeded`, reads that terminal phase independently, conditionally deletes the
Pod, and proves its exact UID gone and its name absent before creating any
controller Deployment. A concurrent same-name object can produce
`AlreadyExists` or a lost response, but cannot be adopted, rewritten, or
attributed to this attempt.

Every attempted manifest enters the transaction before its request. On failure
or `INT`, `TERM`, or `HUP`, the installer rebuilds its ledger from live objects
whose attempt annotation exactly matches. It deletes those objects newest-first
with both UID and resourceVersion in Kubernetes `DeleteOptions` preconditions,
then proves each captured UID gone. A foreign collision or concurrent
replacement is reported and left untouched; an uncertain namespaced collision
also prevents cascading Namespace deletion. A lost successful DELETE response
is accepted only after the captured UID is independently proved gone. The
installer reports `ROLLBACK INCOMPLETE` and exact residue rather than claiming
success when cleanup cannot be proved. A signal before mutation leaves the
cluster unchanged; a second signal cannot re-enter rollback.

## Step 3 — verify the controllers

Use the exact kubeconfig/context/server tuple on every command. Record only
redacted counts, names, image identities, and status fields.

```sh
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system get deployment \
  source-controller kustomize-controller helm-controller
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system get pod,networkpolicy
```

For each Deployment, require a **positive desired replica count**,
`status.observedGeneration == metadata.generation`, and current, updated,
available, and ready replicas all equal to the positive desired count, with
**zero unavailable replicas**. This is N/N rollout evidence, not a literal
replica constant. Zero desired, generation lag, a partial rollout, missing or
malformed fields, diagnostic output, RBAC denial, timeout, or API failure is not
ready. The contract remains valid for future reviewed multi-replica/HA capacity.

Require exactly the three pinned controller images and no fourth controller.
Require the canary Pod absent. Before public egress, seven NetworkPolicies are
expected: the three hardened generated policies plus the four startup policies.

Prove idleness by listing every installed Flux CRD kind across all namespaces.
Every query must exit zero, emit no stderr, and emit zero object names. A failed
or malformed query is unknown, never empty. The installer performs this exact
fail-closed check again before phase 4.

## Step 4 — open public HTTPS, last

```sh
./scripts/install-flux-controllers.sh --open-public-egress "${COMMON_ARGS[@]}"
```

This mode refuses unless:

- all three Deployments satisfy the scalable current-generation N/N invariant;
- every Flux CRD query succeeds cleanly and returns zero objects;
- all four startup NetworkPolicies carry one canonical install-attempt identity
  and server dry-run reports each exact private endpoint-bound object
  `unchanged`;
- `flux-controllers-public-https` is absent.

The public policy is an **absent-only transaction**. It receives a fresh,
unpredictable attempt annotation and uses `create --save-config`, never a
reconciling `apply`; it never adopts, rewrites, or deletes pre-existing state.
The manifest enters the response-loss-safe transaction before creation. After a
successful response, server dry-run must report the exact attempt-bound object
`unchanged`. A lost response, signal, diagnostic, unexpected line, or poststate
drift invokes rollback, but deletion is permitted only for the matching attempt
annotation and captured UID/resourceVersion. A concurrent foreign winner is
reported and left untouched. Only exact poststate and an unchanged authoritative
EndpointSlice snapshot commit the transaction.

The rule permits public destinations on TCP 443 while excluding private,
loopback, link-local, carrier-grade-NAT, multicast, and reserved ranges. Its
intended consumers include public Git/OCI endpoints and, when separately
authorized, `fulcio.sigstore.dev`, `rekor.sigstore.dev`, and the Sigstore TUF
service. Kubernetes image pulls occur from the node network and are not granted
by this Pod NetworkPolicy.

## Step 5 — verify the closure

Require eight NetworkPolicies after phase 4, no `egress` rule on generated
`allow-egress`, the exact private API endpoint set on TCP 6443, and the public
policy exact poststate. Re-run the N/N readiness and zero-Flux-custom-resource
checks. Do not disclose private endpoints in Git, PR text, CI logs, or shared
evidence.

## Coordinator-only bounded live-validation package

This package is deliberately separate from author testing. The author of this
Git change does not execute it. One coordinator holds the only live lane, uses
protected custody, and stops at the first mismatch.

### A. Capture read-only prestate

1. Record the exact reviewed commit and three render digests.
2. Run `--plan` with `COMMON_ARGS` and retain protected output.
3. Read `flux-system` Namespace existence; the exact three Deployment names,
   desired/current/updated/available/ready/unavailable/generation fields and
   image identities; all eight Flux CRD object counts; the eight expected
   ClusterRole/ClusterRoleBinding/CRD identities; all NetworkPolicy names; and
   absence of `flux-api-reachability-canary`.
4. Prove the selected CNI identity with this exact read-only query:

   ```sh
   kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
     --server "$REVIEWED_SERVER" -n kube-system get daemonset calico-node \
     -o jsonpath='{.metadata.name}{"|"}{.metadata.labels.k8s-app}{"|"}{.spec.selector.matchLabels.k8s-app}{"\n"}'
   ```

   The only accepted value is `calico-node|calico-node|calico-node`.
5. Stop if any Flux custom resource exists, any query fails or emits a
   diagnostic, an image differs, a private endpoint is not protected evidence,
   the canary already exists, or a policy/object has foreign or unknown state.

On the current cluster this capture is EXPECTED to record the live stock
install: an existing Namespace, three running controllers, the extra
`cluster-reconciler-flux-system` binding, an `allow-egress` policy that still
carries its blanket rule, warn-only Pod Security, and zero Flux custom
resources. That is prestate for the convergence decision, not a fault to be
cleared in place before continuing. Record it and stop; do not "fix" a live
object to make a later step pass.

### B. Prove negative and positive selected-CNI reachability

Use a freshly named, temporary validation Namespace that was proved absent.
The validation bundle must be rendered from the reviewed canary and policy
documents, with only these mechanical changes: replace `flux-system` with the
temporary Namespace and expand the API sentinel with the same reviewed private
endpoint-set routine. It creates only:

- a restricted-labeled temporary Namespace;
- a ServiceAccount named `source-controller`;
- the exact `default-deny` and `flux-controllers-dns` policies;
- later, the exact endpoint-bound `flux-controllers-kube-apiserver` policy; and
- one Pod at a time with the exact reviewed canary image, name, ServiceAccount,
  labels, command, token mount, and security context.

Run the negative probe first, before the API policy exists. Require the canary
not to reach `Succeeded`; delete it and prove it absent. Do not accept the
negative result by itself: it can also represent a broken image, DNS, token, or
API. Then create the exact API policy, recreate the byte-identical canary, and
require `Succeeded`. The only intended difference between the two probes is the
one API NetworkPolicy, so the negative/positive pair attributes reachability to
that selected-CNI endpoint contract.

Delete the validation Namespace and prove it absent. Prove that it created no
cluster-scoped object and that `flux-system` Deployments, Pods, policies, Flux
custom-resource counts, and public egress policy equal the captured prestate.
If cleanup or equality cannot be proved, stop and report residue; do not proceed
to the installer.

On an existing controller installation, do not remove or rewrite a live
`flux-system` policy to manufacture a negative result. The temporary Namespace
is the only approved negative probe. An additional positive probe in
`flux-system` may use the exact committed canary only after all four startup
policies compare exact, the canary is absent, and the coordinator records an
absent-only create/delete/absence transaction. It must not change a controller,
Flux custom resource, or policy.

### C. Exercise installer behavior only when the prestate makes it safe

- If `flux-system` or any controller object already exists, run `--plan` only
  and require `--apply` to refuse without mutation. Do not reconcile an
  existing install through this fresh-only path. **This is the current
  cluster's branch**: the only installer behaviour to exercise against it today
  is that `--plan` classifies and that `--apply` refuses.
- If every one of the 24 controller objects, five policy objects, and canary is
  absent and the owner separately authorizes a fresh installation, run Step 2.
  This branch becomes reachable on this cluster only after Option B in
  "Converging the existing install" has been separately authorized and
  completed.
  Require the positive pre-controller canary, its exact cleanup, and then the
  three Deployments. Do not create a Flux custom resource.
- Demonstrate scalable readiness using the live desired count, whatever
  positive N the reviewed Deployment specifies; never patch replicas merely to
  exercise the check.

### D. Exercise public-policy safety without opening public egress

The default acceptance package is non-mutating: run the offline behavioural
tests for collision/no-adoption, response loss, signal rollback, and poststate
drift, and read-only prove the live public policy prestate. Do not create
`flux-controllers-public-https` merely as a test.

If the policy already exists, `--open-public-egress` must refuse it and leave
its bytes unchanged. If it is absent, leave it absent unless the owner
separately authorizes the actual phase-4 network opening after readiness,
idleness, and exact startup-policy evidence. Response-loss and poststate-drift
fault injection remain offline only; injecting them against the cluster would
not be a bounded validation.

### E. Capture poststate equality

After any authorized live step, repeat section A. The final evidence must show:

- no validation Namespace or canary Pod;
- no Flux custom resource and no changed `suspend` field;
- no Secret/SOPS/Tunnel/public-route/website change;
- no unexpected cluster-scoped object or RBAC widening;
- exact controller images and scalable rollout status;
- exact expected policies, with the public policy still at its authorized
  prestate; and
- zero cleanup residue.

Any unknown result is a blocker, not a pass.

## Successful-install removal

A failed `--apply` already runs its own ledger-backed rollback. For a separately
authorized removal of a successful inert install,
`kubectl delete namespace flux-system` is **not sufficient**. It leaves these
12 non-namespaced objects:

```sh
kubectl delete clusterrolebinding crd-controller-flux-system
kubectl delete clusterrole crd-controller-flux-system \
  flux-edit-flux-system flux-view-flux-system
kubectl delete crd buckets.source.toolkit.fluxcd.io \
  externalartifacts.source.toolkit.fluxcd.io \
  gitrepositories.source.toolkit.fluxcd.io \
  helmcharts.source.toolkit.fluxcd.io \
  helmreleases.helm.toolkit.fluxcd.io \
  helmrepositories.source.toolkit.fluxcd.io \
  kustomizations.kustomize.toolkit.fluxcd.io \
  ocirepositories.source.toolkit.fluxcd.io
```

Delete the Namespace only after proving zero Flux custom resources, then remove
the exact binding, roles, and CRDs above with the same explicit target tuple.
These commands are not live authorization; they document complete inventory so a
future reviewed rollback cannot mistake Namespace deletion for full removal.

The reviewed render contains no `cluster-reconciler-flux-system` binding, so the
list above is complete **for an install this repository created**. It is NOT
complete for the cluster as it stands: the live stock install still carries
`cluster-reconciler-flux-system`, and removing the live install therefore also
requires

```sh
kubectl delete clusterrolebinding cluster-reconciler-flux-system
```

Read that as inventory, not as authorization. Deleting that binding is exactly
the privilege reduction the desired state encodes, and it is also the single
change most likely to break an in-flight reconciliation, so it belongs to the
owner-authorized convergence decision below rather than to an ad-hoc cleanup.

## Converging the existing install

The cluster runs the stock render; this repository reviews a different one. The
owner has NOT chosen how to close that gap, and this pull request does not
choose for them. Both options are recorded here so the decision is made against
stated blast radius rather than in a terminal.

**Option A — remediate in place.** Apply only the differences: delete
`cluster-reconciler-flux-system`, replace the blanket `allow-egress` rule with
the reviewed fail-closed egress set, and add the enforced restricted Pod
Security labels to the Namespace. Nothing is recreated and no CRD or custom
resource is touched.

- Blast radius: the three controllers keep running throughout. The window
  between removing `cluster-admin` and applying correct RBAC — and the window
  between closing egress and admitting the reviewed flows — are both windows in
  which a controller that IS reconciling would fail. Today nothing reconciles
  (zero Flux custom resources), which is what makes this option cheap right
  now and expensive later.
- Risk it does not remove: an in-place remediation produces a cluster whose
  provenance is "stock render plus hand-applied deltas". It is not the reviewed
  render, and no digest binds it. Any later drift audit compares against the
  reviewed bytes and must account for that difference forever.
- Not covered by `install-flux-controllers.sh`: this installer is
  fresh-install-only by an explicit, reviewed decision (a creation ledger
  cannot restore unknown prestate). Option A needs its own reviewed change with
  its own prestate capture, ordering, and rollback; do not reach for `--apply`.

**Option B — tear down and reinstall from the reviewed render.** Remove the
live install completely — the Namespace plus every cluster-scoped object listed
in "Successful-install removal", including `cluster-reconciler-flux-system` —
prove absence, then run this runbook from Step 0 on the resulting green field.

- Blast radius: strictly larger. Deleting the eight CRDs deletes every Flux
  custom resource of those kinds cluster-wide; that is currently zero objects,
  which is the only reason this option is bounded today. Controllers are absent
  for the duration. If anything has begun reconciling by the time this runs,
  reassess before deleting a single CRD.
- What it buys: the poststate IS the reviewed render, bound by
  `--expect-render-sha256`, `--expect-egress-sha256`, `--expect-canary-sha256`,
  and `--expect-commit`, created by the ordered transaction with a working
  rollback. Provenance is exact instead of reconstructed.
- Precondition it inherits: the selected-CNI API-destination contract and the
  canary must actually pass on this cluster. That has never been executed
  anywhere. Option B is therefore gated on the coordinator-only bounded
  live-validation package above, run first in its own temporary Namespace.

Neither option is authorized by this document, this pull request, or a green
gate. Both are owner decisions, and whichever is chosen lands as its own
reviewed change with its own prestate, evidence, and rollback.

## What remains blocked

This PR can prove Git bytes and an inert fresh-install transaction. It cannot
authorize or evidence the current cluster's selected-CNI/service-CIDR behavior,
reboot persistence, protected recovery, or live poststate. Until the coordinator
executes the bounded package and the owner accepts its evidence, activation is
blocked.

The live drift stated at the top of this document is blocked on the same
authority. Merging this change removes no `cluster-admin` binding, closes no
egress, and enforces no Pod Security label anywhere except in reviewed Git.
Anyone reading a green pipeline here as "the cluster is hardened" has read it
wrong: the gap between the reviewed desired state and the live install stays
exactly as wide the minute after this merges as the minute before, and it
closes only when the owner picks Option A or Option B and a separate reviewed
change executes it.

Kyverno is not installed, so repository policies are CI assertions rather than
live admission. The per-site SOPS/age token ceremonies and any reconciliation
unsuspend also remain blocked. A green render, green CI, or healthy idle
controller is evidence, never authorization.
