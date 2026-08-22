# Flux controller RBAC narrowing — DEFERRED, gated

Status: `DO NOT APPLY`. The desired state in this repository is narrowed; the
cluster is not. Applying it is an owner-authorized operation with the
preconditions in "Gate" below, and nothing in this document is a step to run
today.

## What changed, and the delta this creates

The generated Flux export binds the built-in `cluster-admin` ClusterRole to the
`kustomize-controller` and `helm-controller` ServiceAccounts, and shares one
wildcard ClusterRole across seven named subjects of which three exist. This
repository now:

1. deletes the `cluster-reconciler-flux-system` binding
   (`kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml`);
2. replaces the shared `crd-controller-flux-system` rules with an enumerated set
   that carries no wildcard, no cluster-wide Secret read, no
   `serviceaccounts/token` creation, and — since the per-controller split
   (issue #98) — **no Flux API group at all**: what remains is common read-only
   cluster metadata, event reporting, and the `/livez/ping` probe
   (`.../patches/crd-controller-role.yaml`);
3. pins that binding's subjects to the three installed controllers
   (`.../patches/crd-controller-binding.yaml`);
4. adds one ClusterRole and ClusterRoleBinding per controller, each bound to
   exactly one ServiceAccount and carrying only that controller's own
   custom-resource authority — `crd-controller-source-flux-system`,
   `crd-controller-kustomize-flux-system`, and
   `crd-controller-helm-flux-system`
   (`kubernetes/flux-system/controllers/per-controller-rbac.yaml`, a resource
   of the controller install root rather than `access.yaml`);
5. adds the namespaced authority the controllers still need — leader election,
   controller-owned ConfigMaps, the SOPS age key read, and one name-restricted
   impersonation Role per namespace holding reconciler accounts
   (`kubernetes/flux-system/access.yaml`);
6. corrects both site release reconcilers from `gitrepositories` to
   `ocirepositories`, the kind their own source objects declare.

**The live cluster still carries the broad binding.** The Flux controllers were
installed from the pre-narrowing render, so from the moment this change merges
until the gated apply below, Git and the cluster disagree about flux-system
authorization. That delta is deliberate and is the only known drift this change
introduces. It closes when step 4 of the procedure completes, and
`bootstrap/flux/bootstrap.sh --verify` is what proves it closed: the reviewed
model no longer contains `cluster-reconciler-flux-system`, so a cluster that
still has it fails verification.

## Why the order is apply-then-delete

`roleRef` is immutable. The broad binding cannot be repointed at the narrowed
role in place — an apply against the live object is rejected by the API server —
so the migration adds the replacement authority first and deletes the broad
binding last. That order is also the fail-safe one: at every intermediate point
the controllers hold at least the authority they need, and the last step only
ever removes authority.

## Offline proof, before touching anything

Run in a clean checkout of the merged commit:

    make check-fast
    python3 -B -m unittest tests.security.test_flux_rbac_contract -v
    make check-kubernetes

`tests/security/test_flux_rbac_contract.py` is the sufficiency proof: it
enumerates every object the reviewed Kustomizations and HelmReleases would
apply, derives the `(subject, verb, apiGroup, resource, namespace)` request each
one implies, and evaluates them against the committed Roles with a model of the
RBAC authorizer. A permission the narrowing forgot fails there. It also asserts
the denials — no cluster-admin, no wildcard reaching a Flux account, no
unrestricted impersonation, no token minting, no Secret writes — and that the
model's composition of the patches equals what `kustomize build` renders.

It also proves the other direction. `test_every_granted_request_is_derived_or_declared_slack`
expands every rule the committed RBAC binds to a Flux account into atomic
`(subject, verb, apiGroup, resource, scope)` requests and requires each one to be
either derived above or listed in `DECLARED_SLACK` with the reason it is granted
anyway — exactly, in both directions, so an undeclared grant and a stale
justification fail identically. Without it "narrow" meant only "passes a
deny-list", and a `batch/jobs` write or a cluster-wide `pods/exec` read could be
added with every gate green.

That inventory used to be dominated by one residual:
`crd-controller-flux-system` was a single ClusterRole bound to all three
controllers, so each held the other two's write authority over Kustomizations,
HelmReleases, and source objects. Impersonation did not contain it — the victim
controller performs the reconciliation. **That residual is retired by issue
#98.** Of its 135 declared-slack request atoms, 134 no longer exist; the one
legitimate overlap, helm-controller watching the HelmChart it creates, is
re-attributed to that owning controller. The retired reason remains pinned at
zero so reintroducing even one deputy grant cannot hide as declared slack.

The replacement proof is deliberately redundant:

- the shared role names no Flux API group;
- each split binding names exactly one canonical controller ServiceAccount and
  the same-named ClusterRole;
- the exact cross-controller write matrix, including status and finalizer
  subresources, is denied while owned positive controls remain allowed; and
- the install root alone authorizes every registered informer before
  `access.yaml` can be reconciled.

The fast validator, RBAC model, bootstrap live-state mirror, and Conftest rules
all enforce these properties. Conftest is additive defence in depth over the
rendered output; it does not replace the independent structural, behavioral,
or live comparison gates.

### The declared gaps, and what they block

The proof tolerates exactly two classes of gap, both declared in
`DECLARED_INSUFFICIENCIES`, and each tied by test to its object staying
suspended.

**1. The Kyverno staging stop.** The `admission` reconciler is namespaced on
purpose, so it can own the inert controller shell but cannot create the
ClusterPolicies or the `ValidatingWebhookConfiguration` its own path declares.
This is the stop already recorded in `access.yaml`.

**2. Readiness read-back — PRE-EXISTING, and a genuine unsuspend blocker.** A
`wait: true` Kustomization and a HelmRelease that has not disabled Helm's wait
both evaluate readiness by walking a workload down to the Pods it creates, under
the impersonated identity. So `admission` (waits on a Deployment in `kyverno`)
and all three `helm-reconciler` accounts need `get`/`list` on `replicasets` and
`pods` in their target namespace, and none of them has it.

These Roles are unchanged by this narrowing — the gap exists on `main` today —
but it means "this narrowing will not break unsuspend" is NOT established, and
saying so plainly is the point of declaring it.

It cannot simply be granted. `policies/conftest/kubernetes.rego` denies any Role
in `cloudflare-public`, `naranjo-online`, `lidersea-com`, or `kyverno` that names
`pods` or `replicasets` **at all** — the rule is verb-agnostic, so even a read
grant is refused as "direct workload control". Closing the gap is therefore a
reviewed decision between two options, and this change deliberately picks
neither:

- narrow that Conftest rule to write verbs, so read-back is permitted while
  direct workload control stays denied; or
- turn the waits off — `wait: false` on the Kustomization, `disableWait` on the
  HelmRelease actions — and accept that readiness is no longer gated there.

Until one is chosen and reviewed, every affected object stays suspended, which
the suite enforces.

## Live proof, before the deletion

Use the protected kubeconfig ceremony; never a bare `kubectl` against a mutable
default context. Every command here is a read. The command inventory below uses
`auth can-i` to keep each reviewed request legible, but a raw `no` is **not** a
denial receipt: kubectl can produce the same text and exit status before the
authorizer is reached.

### Closed discovery + authorization oracle

**LIVE USE IS BLOCKED.** `scripts/flux_rbac_denial_oracle.py` contains and
hermetically tests the closed protocol below, but a mutable checkout script
cannot establish its own stage-zero trust before receiving a protected
kubeconfig. Current main has no trusted reviewed-blob launcher for this entry
point, so its direct CLI returns `UNRESOLVED` before opening kubectl or the
kubeconfig. Do not invoke it directly, do not classify raw `auth can-i` output,
and do not use either as promotion evidence.

Once the owner supplies and separately reviews the missing launcher, it must
copy this exact script blob from the reviewed commit through a held descriptor,
bind the interpreter/tool and protected kubeconfig without reopening mutable
sources, and preserve the oracle's closed output. Only that reviewed launcher
may enable the following three ordered, separately recorded operations:

1. uncached raw discovery for the requested resource and verb, the built-in
   Lease positive control, the exact reviewed Flux Kustomization positive
   control, and the built-in kube-system Secret used by the inert denial
   control; each APIResource verb inventory must be well formed and advertise
   the exact ordinary verb that its following review will ask about. Kubernetes
   does not advertise the RBAC-only `impersonate` verb there, so that one
   exception is closed to the core `serviceaccounts` identity and is labeled
   `AUTHORIZATION_ONLY` in the discovery receipt;
2. for a Flux resource, a live CRD read proving exact group, plural, kind,
   namespaced scope, the sole served/storage version reviewed here, and both
   `NamesAccepted=True` and `Established=True`;
3. only after every discovery result is `RESOLVED`, the real pinned kubectl
   path POSTs one exact JSON SelfSubjectAccessReview to the raw authorization
   endpoint. This is the same non-persistent review API used by `auth can-i`,
   not a persisted object create, and avoids that command's unavoidable
   cluster-scope warning text.

### Rejected evidence designs

Four tempting substitutes are explicitly non-evidence for this migration:

1. **Constant-allow or constant-deny behavior.** An all-allowed or all-denied
   matrix is vacuous. Two owned positive controls and one inert denied control
   must all resolve in opposite directions before any requested row counts;
   `test_constant_allow_is_non_evidence`,
   `test_constant_deny_is_non_evidence`, and the portable constant-answer
   mutation prove both constant shapes fail closed.
2. **Incorrect ServiceAccount identity bracketing.** A near-match principal
   proves the wrong subject. The user must be exactly
   `system:serviceaccount:<namespace>:<name>` and the impersonation groups must
   be exactly `system:serviceaccounts`,
   `system:serviceaccounts:<namespace>`, and `system:authenticated`. Boundary
   prefixes, suffixes, fixture envelopes, missing groups, and foreign groups
   are rejected by the portable identity and protocol tests.
3. **Non-faithful protocol stubbing.** Invented kubectl or API output is not a
   protocol receipt. The hermetic lane drives the real pinned kubectl client
   and validates its captured discovery and raw SelfSubjectAccessReview
   request/response contract; the final issue-98 matrix also runs against a
   disposable real Kubernetes API server after installing all reviewed Flux
   CRDs. Hand-written loopback responses alone never satisfy that final lane.
4. **Custody bypass.** No caller-selected executable, kubeconfig, environment,
   exec plugin, external credential path, mutable source path, or alternate
   entry point may evade reviewed kubectl/kubeconfig custody. Descriptor
   replacement, link, mode, owner, digest, context/server, external-reference,
   and direct-checkout bypass attempts all fail closed without printing or
   reading Secret values. Native Windows keeps the portable protocol and
   identity suite; it does not pretend to supply POSIX descriptor custody.

Discovery and authorization have closed values. Discovery is `RESOLVED` or
`UNRESOLVED`; authorization is `ALLOWED`, `DENIED`, or `UNRESOLVED`. Missing,
stale, wrong-version/foreign, malformed, missing-requested-verb,
warning-bearing, unparseable, or transport-failed discovery is always
`UNRESOLVED`, and the authorizer is not called. A warning, malformed answer,
or transport/exit mismatch from
authorization is also `UNRESOLVED`. The response must exactly echo
apiVersion, kind, and every requested ResourceAttribute; `status.allowed` must
be a boolean, `denied` must be a boolean if present and cannot contradict an
allow, and `evaluationError` may only be absent/empty. Only then do true and
false become `ALLOWED` and `DENIED`.
This occurs after resolved discovery, two exact allowed controls, and one exact
denied control. The mixed controls make both a
constant-deny and a constant-allow authorizer non-evidence.

The denied control impersonates the exact canonical but deliberately inert
identity
`system:serviceaccount:flux-system:rbac-oracle-denial-control` for `get` on
`secrets` in `kube-system`. Only that exact denied request is load-bearing; the
oracle does not require a cluster-wide binding inventory. If it ever becomes
allowed, the control fails closed. Unlike either controller identity, this
request stays denied while the current broad controller binding exists, so
pre-deletion protected rows may faithfully report `ALLOWED` while a
constant-allow authorizer still fails the control.

The 2026-08-21 bounded read-only Pi probe established the pre-deletion baseline:
the exact Kustomization v1 discovery and live CRD conditions above resolved,
and warning-free raw reviews with the exact ServiceAccount groups returned
`allowed:true` for an allowed cluster-scoped row and `allowed:false` for the
inert Secret denial. Direct probes also confirmed that the current broad
binding still allows the protected controller row. These results confirm the
phase assumptions but are not promotion receipts while the trusted-launcher
boundary remains blocked.

The ServiceAccount subject is not a label or substring. It must be the exact
protocol identity `system:serviceaccount:<namespace>:<name>`; prefixes,
suffixes, envelopes, or malformed boundary characters stop unresolved. Each
request also impersonates exactly `system:serviceaccounts`,
`system:serviceaccounts:<subject-namespace>`, and `system:authenticated`; a
missing, extra, or foreign group is non-evidence. The request binds that full
identity plus verb, API group/version, resource, subresource, namespace, and
optional name. Wildcards are deliberately outside the oracle's reviewed
identity set; the final `'*' '*'` row below remains a coarse diagnostic, never
denial evidence.

The future owner-run Pi plan for the first protected denial row is recorded
below as an argument manifest, **not an executable command**. Repeat the exact
tuple and expected state for each non-wildcard row only after the trusted
launcher exists:

```text
REVIEWED_BLOB=scripts/flux_rbac_denial_oracle.py@<exact-owner-reviewed-commit>
KUBECTL=<reviewed absolute Linux ARM64 path supplied through held custody>
KUBECONFIG=<owner-generated mode-0600 flattened embedded-credential JSON snapshot>
CONTEXT=<exact owner-reviewed Pi context>
SERVER=<exact owner-reviewed Pi API server URL>
SUBJECT=system:serviceaccount:flux-system:kustomize-controller
VERB=create
API_GROUP=apps
RESOURCE=deployments
NAMESPACE=kube-system
NAME=<absent>
ALL_NAMESPACES=false
EXPECT=ALLOWED  # required pre-deletion baseline; DENIED only after the reviewed deletion
```

The single JSON receipt must bind the exact requested discovery identity, verb,
and closed `verbEvidence` (`DISCOVERY` or the exact ServiceAccount
`AUTHORIZATION_ONLY` exception) with `"state":"RESOLVED"`, report the
phase-appropriate expected authorization state, both positive controls as
`ALLOWED`, the inert denial control as `DENIED`, and
`"result":"PASS"`; any other output or nonzero exit stops the sweep. Record
only the bounded receipt, never `--list` authorization inventory.

The verified non-root source is mode 0600 and one link, but it is YAML and is
therefore deliberately rejected by the oracle's closed JSON snapshot parser.
It is not a ready oracle input. Through the protected ceremony, the owner must
explicitly authorize generation of a separate flattened JSON snapshot
containing only embedded credentials, with the exact context/server supplied
privately to the launcher, and deliver that snapshot through held custody. Do
not copy credentials during review, substitute the root kubeconfig, use sudo,
or record private host identity here. The launcher must also enforce the
v1.36.3 ARM64 `kubectl` SHA-256 already recorded as
`KUBECTL_ARM64_SHA256`.

Executable and kubeconfig custody remains part of the future result. The
oracle requires one independently supplied lowercase SHA-256 pin for every
executable and refuses links, non-regular sources, foreign owners, unsafe
modes, a missing/malformed/mismatched kubectl pin, and source replacement
during binding. It copies from the held source
descriptor into private custody and revalidates descriptor identity, mode, and
digest before every invocation; replacing the original path cannot change the
bytes used. Live custody runs only on Linux/WSL with the platform pins. Native
Windows retains portable request/response parsing, discovery-verb, SSAR-echo,
identity, and constant-answer decision tests without pretending to provide
POSIX descriptor custody or a live receipt. macOS runs those portable checks
and, when local kubectl and OpenSSL are available, the descriptor-custody and
hand-written TLS loopback protocol tests. That locally self-hashed client lane
does not substitute for Linux CI's repository-pinned kubectl or produce a live
receipt.

`tests/security/test_flux_rbac_denial_oracle.py` drives the production kubectl
adapter against an authenticated TLS loopback API surface. It observes the
real v1.36 kubectl client's raw discovery and exact JSON
SelfSubjectAccessReview requests, including the complete ServiceAccount
impersonation groups, serialization, warnings, and exit status; the loopback
discovery and authorizer responses remain deliberately hand-written and keyed
on every request dimension. This is hermetic client-protocol parity, not a
real API-server/authorizer substitute. The issue-closing evidence therefore
also requires the final matrix against a disposable real Kubernetes API
server; never use the Raspberry Pi for that experiment.

After the trusted launcher lands, repeat every non-wildcard row through the
oracle at each migration boundary. Until then the migration stays blocked. The
expected states are predicted before any apply:

- before step 3, owned rows and all 18 issue-98 crossing rows are `ALLOWED`;
- after step 3 but before step 4, every owned row remains `ALLOWED`; the three
  source-controller controller-to-controller categories (seven literal rows)
  become `DENIED`, while all 11 kustomize-controller and helm-controller rows
  remain `ALLOWED` only because the still-live
  `cluster-reconciler-flux-system` binding grants those two `cluster-admin`;
- after step 4, every owned row remains `ALLOWED` and every crossing/general
  forbidden row is `DENIED`.

A single `UNRESOLVED` or unexpected state invalidates the entire boundary; do
not infer the remaining rows. This mixed phase prediction also prevents a
constant-output tool from masquerading as migration evidence.

    # must be yes
    auth can-i impersonate serviceaccounts/root-reconciler -n flux-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i impersonate serviceaccounts/helm-reconciler -n naranjo-online \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i impersonate serviceaccounts/helm-reconciler -n lidersea-com \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i impersonate serviceaccounts/helm-reconciler -n cloudflare-public \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i list kustomizations.kustomize.toolkit.fluxcd.io -n flux-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i list helmreleases.helm.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:helm-controller
    # Startup authority: without these a controller crashloops before it
    # reconciles anything, so they are asked of all three, not just one.
    auth can-i create leases.coordination.k8s.io -n flux-system \
      --as=system:serviceaccount:flux-system:source-controller
    auth can-i create leases.coordination.k8s.io -n flux-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i create leases.coordination.k8s.io -n flux-system \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i create configmaps -n flux-system \
      --as=system:serviceaccount:flux-system:helm-controller
    # A registered informer for a kind this repository declares no object of.
    # The controller still lists and watches it at startup.
    auth can-i list buckets.source.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:source-controller
    auth can-i get secrets -n flux-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i create ocirepositories.source.toolkit.fluxcd.io -n naranjo-online \
      --as=system:serviceaccount:flux-system:naranjo-online-reconciler
    auth can-i create ocirepositories.source.toolkit.fluxcd.io -n lidersea-com \
      --as=system:serviceaccount:flux-system:lidersea-com-reconciler
    # The source read every reconciliation begins with. It happens under the
    # CONTROLLER's identity, before impersonation is configured, so it is asked
    # as the controller and not as the reconciler account.
    auth can-i get gitrepositories.source.toolkit.fluxcd.io -n flux-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i get ocirepositories.source.toolkit.fluxcd.io -n naranjo-online \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i patch gitrepositories.source.toolkit.fluxcd.io -n flux-system \
      --as=system:serviceaccount:flux-system:source-controller
    auth can-i create helmcharts.source.toolkit.fluxcd.io -n cloudflare-public \
      --as=system:serviceaccount:flux-system:helm-controller

    # DECLARED GAPS — these answer `no` today, and that is recorded rather than
    # fixed (see "The declared gaps" above). Run them so the answer is observed
    # rather than assumed, and do NOT unsuspend the objects that need them until
    # the reviewed decision is made.
    auth can-i list pods -n kyverno \
      --as=system:serviceaccount:flux-system:admission-reconciler
    auth can-i list replicasets -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i list pods -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i list pods -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler

    # must be no
    auth can-i create deployments -n kube-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i get secrets -n kube-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i create clusterrolebindings \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i create namespaces \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i create serviceaccounts/token -n kube-system \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i get secrets -n flux-system \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i impersonate serviceaccounts/root-reconciler -n flux-system \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i '*' '*' -A \
      --as=system:serviceaccount:flux-system:kustomize-controller

The issue-98 crossing sweep is the following literal 18-request matrix, not a
representative sample. Every request is cluster-wide (`allNamespaces=true`) and
has no object name. The portable RBAC model expands the same ownership property
exhaustively to 1,365 verb/resource/subresource/scope requests and also pins 88
owned grant atoms, 98 exclusive comparisons, and the six exact HelmChart
handoff exemptions.

| Subject ServiceAccount | Verb | API group and resource | After step 3 | After step 4 |
|---|---|---|---|---|
| source-controller | patch | `kustomize.toolkit.fluxcd.io` / `kustomizations` | DENIED | DENIED |
| source-controller | update | `kustomize.toolkit.fluxcd.io` / `kustomizations/status` | DENIED | DENIED |
| source-controller | update | `kustomize.toolkit.fluxcd.io` / `kustomizations/finalizers` | DENIED | DENIED |
| source-controller | patch | `helm.toolkit.fluxcd.io` / `helmreleases` | DENIED | DENIED |
| source-controller | update | `helm.toolkit.fluxcd.io` / `helmreleases/status` | DENIED | DENIED |
| source-controller | create | `source.toolkit.fluxcd.io` / `helmcharts` | DENIED | DENIED |
| source-controller | delete | `source.toolkit.fluxcd.io` / `helmcharts` | DENIED | DENIED |
| kustomize-controller | patch | `helm.toolkit.fluxcd.io` / `helmreleases` | ALLOWED | DENIED |
| kustomize-controller | update | `helm.toolkit.fluxcd.io` / `helmreleases/status` | ALLOWED | DENIED |
| kustomize-controller | patch | `source.toolkit.fluxcd.io` / `ocirepositories` | ALLOWED | DENIED |
| kustomize-controller | patch | `source.toolkit.fluxcd.io` / `gitrepositories` | ALLOWED | DENIED |
| kustomize-controller | create | `source.toolkit.fluxcd.io` / `helmcharts` | ALLOWED | DENIED |
| helm-controller | patch | `kustomize.toolkit.fluxcd.io` / `kustomizations` | ALLOWED | DENIED |
| helm-controller | update | `kustomize.toolkit.fluxcd.io` / `kustomizations/status` | ALLOWED | DENIED |
| helm-controller | update | `kustomize.toolkit.fluxcd.io` / `kustomizations/finalizers` | ALLOWED | DENIED |
| helm-controller | patch | `source.toolkit.fluxcd.io` / `gitrepositories` | ALLOWED | DENIED |
| helm-controller | patch | `source.toolkit.fluxcd.io` / `ocirepositories` | ALLOWED | DENIED |
| helm-controller | update | `source.toolkit.fluxcd.io` / `buckets/status` | ALLOWED | DENIED |

All 18 are required in the disposable real-API sweep as well as in the future
owner-run protected sweep. The `status` identities must resolve through the
API server's advertised subresources. Kubernetes does not advertise the
RBAC-only `finalizers` identity as an ordinary API subresource, so those two
rows are labeled `AUTHORIZATION_ONLY`: the oracle still resolves the exact base
resource, live CRD, version, scope, and `update` verb before it submits the
exact `subresource=finalizers` SelfSubjectAccessReview. This is the same narrow
exception shape as ServiceAccount `impersonate`; it is never permission to
skip discovery for the resource itself.

### Disposable real-API receipt (2026-08-21)

This issue's local destructive authority was limited to a disposable kind
cluster; it did not authorize a protected-cluster apply. A clean-from-zero
kind v0.32.0 cluster running Kubernetes v1.36.1 established all eight reviewed
Flux CRDs before the resolved local v1.36.4 kubectl client submitted any
authorization review. The merged oracle ran through held executable and
mode-0600 flattened-kubeconfig custody, with the exact ServiceAccount user and
all three Kubernetes groups on every raw SelfSubjectAccessReview.

The prediction and observation matched exactly:

- before narrowing, all 18 literal issue-98 crossings were `ALLOWED`;
- after the per-controller roles and narrowed shared role were applied, all 18
  crossings were `DENIED`, producing 18 exact yes-to-no flips;
- nine owned controls remained `ALLOWED`: source main-resource patch and status
  update; kustomize main-resource patch, status update, and finalizer update;
  helm main-resource patch, status update, and HelmChart create/delete;
- each requested row ran only after the oracle's two allowed controls and inert
  denied control returned `ALLOWED`, `ALLOWED`, and `DENIED` respectively;
- the applied shared role contained zero Flux API groups, its binding named the
  exact three installed controllers, and every CRD remained `Established`.

The first disposable attempt is not counted. It proved all 18 pre-change
allows, then stopped closed because the evidence harness incorrectly tried to
apply the binding's strategic-merge patch as a standalone object without its
base `roleRef`. That cluster was deleted before the harness was corrected; the
accepted receipt came from a new cluster created from zero. After the accepted
run, the cluster node, empty kind network, temporary kubeconfigs, discovery
cache, and harness were deleted and their absence was verified.

This mixed real-authorizer result rejects the constant-answer design; the raw
request receipts bind the correct ServiceAccount brackets and groups; the real
kubectl and API server reject protocol stubbing; and held descriptors plus the
hostile custody suite reject caller-controlled executable, kubeconfig,
environment, and alternate-path bypasses. It is local implementation evidence,
not a promotion receipt and not permission to mutate the protected cluster.

## What each step removes — read this before the procedure

Only one step in this migration is a deletion, but TWO of them remove
authority, and the difference decides what a rollback has to restore.

`crd-controller-flux-system` is patched with a strategic-merge patch that
REPLACES `rules` and `subjects` wholesale. So the moment step 3 applies it, the
live shared ClusterRole loses its wildcard rules, its cluster-wide Secret read,
and `serviceaccounts/token` creation, and the live binding loses four of its
seven subjects. That is a removal, not an addition, and it happens before the
"destructive" step.

Issue #98 makes that replacement narrower again: the shared role loses every
Flux API group, while six new install-root objects carry the replacement —
three ClusterRoles and their three exactly-one-ServiceAccount bindings. The six
must exist before the shared-role replacement lands. Applying the replacement
without them removes all fourteen registered-informer list/watch grants from
the controller install and cannot reach readiness.

That transaction boundary is why the six live in
`kubernetes/flux-system/controllers/per-controller-rbac.yaml`, a resource of
the controller install root, and never in later-reconciled `access.yaml`.

For **kustomize-controller and helm-controller** the loss is masked: they still
hold `cluster-admin` through `cluster-reconciler-flux-system` until step 4.
For **source-controller it is not masked at all** — that binding never covered
it — so from step 3 onward source-controller runs on the narrowed authority
alone. It is therefore the controller to canary first, and the reason step 3
carries its own verification and its own rollback boundary.

The four subjects removed from the binding name ServiceAccounts this install
does not create, so removing them takes away no live authority; they are
restored on rollback anyway, because rollback restores the whole pre-change
object rather than the parts someone judged load-bearing.

## Procedure

Nine cluster-scoped objects change across this migration, at two boundaries:
three existing objects are replaced or deleted and six issue-98 objects are
created. Each boundary has its own verification and rollback. Existing-object
bytes are frozen before mutation; the six create-only objects are recorded by
exact UID and resourceVersion so rollback cannot delete a concurrent foreign
replacement.

1. **Confirm the gate below is fully satisfied and the owner has said go.**
   Confirm the controllers are the reviewed digests and the reconciliation is
   still inert: every Flux object suspended, and the ones that are not
   (`flux-system`, `platform-prerequisites`) reconciling only objects this
   change has already proven authorized.
2. **Freeze the pre-change authorization.** Capture all three EXISTING objects as they
   exist live, with a digest, into operator-held storage — not into this
   repository, which describes the target state and therefore cannot describe
   what to roll back to:

       kubectl get clusterrole crd-controller-flux-system -o yaml
       kubectl get clusterrolebinding crd-controller-flux-system -o yaml
       kubectl get clusterrolebinding cluster-reconciler-flux-system -o yaml

   Record the SHA-256 of the captured file and confirm it re-reads identically.
   **If this capture is missing or unverified, stop.** The generated export is
   the source for the deleted binding only; the pre-change ClusterRole rules
   exist nowhere else once step 3 has run, so without this file the migration is
   one-way.

   Confirm the six per-controller objects are absent before create. Any existing
   name is foreign or an unresolved earlier attempt and is a stop, never an
   object to adopt or overwrite. The expected absent set is the three
   `crd-controller-{source,kustomize,helm}-flux-system` ClusterRoles and the
   same three ClusterRoleBindings.
3. **Apply the narrowed authority — additive first, replacement second.** The
   reviewed transaction first creates the six objects from
   `controllers/per-controller-rbac.yaml` and records their exact identities,
   then applies the namespaced Roles/RoleBindings from `access.yaml`, and only
   then replaces the shared `crd-controller-flux-system` ClusterRole and its
   subject-pinned binding. A fresh install obtains the same order from the
   controller install root; do not split its root into a later Flux
   reconciliation. At this boundary:
   - run every owned row and require `ALLOWED`;
   - require all seven literal source-controller crossing rows to be `DENIED`;
   - require all 11 literal kustomize/helm crossing rows to remain `ALLOWED` only
     because the broad cluster-admin binding still exists; any other phase
     shape is unresolved or wrong;
   - confirm all three controller Pods are Ready and have not restarted —
     `kubectl -n flux-system get pods` — because a controller that lost leader
     election or its own ConfigMap authority crashloops at startup rather than
     failing a reconciliation;
   - confirm source-controller specifically is still reconciling: the
     `flux-system` GitRepository must stay `Ready=True` with its
     `status.observedGeneration` current and its artifact revision advancing.

   **Rollback at this boundary:** re-apply the frozen ClusterRole and
   ClusterRoleBinding from step 2, then delete only the six transaction-created
   objects whose UID, resourceVersion, exact two ownership labels, roleRef, and
   single subject still match the recorded create receipt. A missing or replaced
   identity is residue requiring review, not permission to delete by name.
4. **Delete the broad binding.** Remove the `cluster-reconciler-flux-system`
   ClusterRoleBinding. It removes no object the controllers own and interrupts
   no workload: the connectors, both sites, and every Pod on the cluster are
   untouched, because no running workload authenticates as a Flux controller.
5. **Prove the removal.** Require every owned row to remain `ALLOWED` and every
   general forbidden and issue-98 crossing row to be `DENIED`. Then run
   `bootstrap/flux/bootstrap.sh --verify`, which compares live
   ServiceAccounts, Roles, RoleBindings, ClusterRoles, and ClusterRoleBindings
   against the reviewed model and fails on any drift — including a
   `cluster-reconciler-flux-system` that is still present, or any other binding
   that reaches a protected account.
6. **Prove reconciliation still works, without unsuspending anything.** Force a
   reconcile of the already-unsuspended `platform-prerequisites` Kustomization
   and require it to reach Ready with no RBAC condition. Its objects are the
   NetworkPolicies, ResourceQuotas, and LimitRanges the sufficiency proof
   covered, so a green result exercises the impersonation path end to end. Leave
   every suspended object suspended: unsuspending is a separate, separately
   gated decision.

## Rollback

Rollback is per boundary, and it restores **objects**, not just the deletion.
RBAC is evaluated per request, so every direction below takes effect
immediately: no restart, no drain, no workload impact.

| Failed at | Restore |
|---|---|
| step 3 (narrowed authority applied) | re-apply the frozen `crd-controller-flux-system` ClusterRole **and** its ClusterRoleBinding from step 2; then remove only the six new objects whose UID, resourceVersion, labels, roleRef, and single subject still exactly match the create receipt |
| step 4 or later (broad binding deleted) | re-create `cluster-reconciler-flux-system` from the frozen capture, **then** re-apply the frozen ClusterRole and its binding; remove the six new objects only under the same exact receipt match |
| interrupted anywhere, state unknown | re-apply all three frozen objects; then inventory the six new names and remove only exact transaction-owned matches — a missing or changed identity is residue for review, never permission to delete by name |

Re-creating the deleted binding alone is **not** a full rollback: it restores
`cluster-admin` for kustomize-controller and helm-controller, and nothing at all
for source-controller, whose pre-change authority lived only in the shared
ClusterRole this migration replaced. Roll back all three objects, then re-run
the "must be yes" block plus the source-controller check from step 3 to confirm
the cluster is back where it started.

Leave the narrowed namespaced Roles from `access.yaml` in place while rolling
back — they grant a subset of what the broad binding grants, so their presence
changes nothing, and removing them would make a second attempt start from
scratch.

If step 6 fails, the cause is a missing grant, and the failing Kustomization
names the exact resource and verb in its status condition. Add it to
`access.yaml` only when it belongs to an impersonated namespaced reconciler, or
to the owning controller's ClusterRole in
`controllers/per-controller-rbac.yaml` when it is controller-owned custom-
resource authority. Common non-Flux read authority alone belongs in the shared
role patch. Make the choice through a reviewed change, not a live `kubectl`
edit: a grant that exists only on the cluster is invisible to the sufficiency
proof and will be reverted by the next verify.

**What is not proven here.** Rollback is written from the objects' semantics —
`roleRef` immutability, replace-not-merge patch behaviour, per-request RBAC
evaluation — and from the offline proof above. It has not been exercised against
a failure injected at each boundary, because that requires the cluster this
change is deferred from touching. Exercising it is part of the owner-run apply,
in the order above: each boundary is verified before the next begins, and the
frozen capture from step 2 is what makes any of them reversible.

## Gate

This apply is deferred and stays deferred until ALL of the following hold:

- an owner-approved trusted reviewed-blob launcher exists for the denial
  oracle, binds the exact reviewed script/tool/kubeconfig bytes through held
  custody, and the read-only Pi matrix produces only bounded resolved receipts;
- the recovery window is closed — the temporary passwordless sudo installed for
  the Service-CIDR repair is removed and `sudo -n` is proven unavailable;
- the route install, controlled reboot, post-reboot acceptance, and behavioural
  canaries are complete (the reboot is performed by the platform lane; this lane
  never reboots the host);
- `CODEX_PLATFORM_STABLE` has been signalled rather than withheld;
- the admission controller is installed and enforcing, closing the audit's
  no-admission-control finding;
- the owner has given an explicit go for this specific apply.

Unsuspending any Flux object is a further, separate decision that this
narrowing is a precondition for — not a consequence of.
