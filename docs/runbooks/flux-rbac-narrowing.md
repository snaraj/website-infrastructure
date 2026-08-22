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
   that carries no wildcard, no Secret access, no
   `serviceaccounts/token` creation, and — since the per-controller split
   (issue #98) — **no Flux API group at all**: what remains is common read-only
   cluster metadata, event reporting, and the `/livez/ping` probe
   (`.../patches/crd-controller-role.yaml`);
3. pins that binding's subjects to the three installed controllers
   (`.../patches/crd-controller-binding.yaml`);
4. adds one ClusterRole and ClusterRoleBinding per controller, each bound to
   exactly one ServiceAccount and carrying only that controller's primary
   custom-resource authority plus its pinned read-only secondary informers —
   `crd-controller-source-flux-system`,
   `crd-controller-kustomize-flux-system`, and
   `crd-controller-helm-flux-system`
   (`kubernetes/flux-system/controllers/per-controller-rbac.yaml`, a resource
   of the controller install root rather than `access.yaml`). Kustomize watches
   Bucket, GitRepository, and OCIRepository read-only; Helm watches HelmChart
   and OCIRepository. The Helm role alone also carries the exact cluster-scoped
   Secret `get`/`list`/`watch` required by its all-namespaces release-storage
   informer;
5. adds the namespaced authority the controllers still need — leader election,
   controller-owned ConfigMaps, an exact `get` of the named SOPS age key, and one name-restricted
   impersonation Role per namespace holding reconciler accounts
   (`kubernetes/flux-system/access.yaml`);
6. corrects both site release reconcilers from `gitrepositories` to
   `ocirepositories`, the kind their own source objects declare.

The Helm Secret read is a deliberate residual, not an assertion that Secrets
are harmless. Kubernetes cannot express `list`/`watch` through
`resourceNames`, and the pinned controller builds one all-namespaces informer
before it becomes ready. The result is cluster-wide read-only Secret visibility
for `helm-controller`; every Secret write remains denied. That is materially
narrower than `cluster-admin`, but it must remain visible in review and in the
live authorization receipt.

Kustomize's optional ConfigMap/Secret event watchers are disabled with the
exact `--feature-gates=DisableConfigWatchers=true` argument. Kubernetes cannot
grant metadata-only Secret watch authority, so the alternative would expose
every namespace's Secret names and metadata plus any data returned by `get`.
Referenced inputs are still fetched by exact name during reconciliation; a
change is observed on the next interval, retry, source event, or manual
reconciliation instead of by an immediate ConfigMap/Secret event.

**The live cluster still carries the broad binding.** The Flux controllers were
installed from the pre-narrowing render, so from the moment this change merges
until the gated apply below, Git and the cluster disagree about flux-system
authorization. That delta is deliberate and is the only known drift this change
introduces. It closes when step 5 of the procedure completes. The protected
launcher must compare the live graph with the same reviewed model embedded in
`bootstrap/flux/bootstrap.sh`; that model no longer contains
`cluster-reconciler-flux-system`, so a cluster that still has it fails
verification.

## Why the order is apply-then-delete

`roleRef` is immutable. The broad binding cannot be repointed at the narrowed
role in place — an apply against the live object is rejected by the API server —
so the migration adds the replacement authority first and deletes the broad
binding as the last RBAC authority-removal step. That order is also the fail-safe
one: at every intermediate point the controllers hold at least the authority
they need, and that RBAC step only removes authority. The disposable
initial-creation cold-start and the later protected Helm upgrade are runtime
proofs, not part of the authority handoff.

## Offline proof, before touching anything

Run in a clean checkout of the merged commit:

    make check-fast
    python3 -B -m unittest tests.security.test_flux_rbac_contract -v
    release_mode="$(python3 -B scripts/validate_release_transition.py select-mode)"
    ./scripts/render-kubernetes.sh "--${release_mode}"
    ./scripts/validate-security.sh

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
#98.** All 135 declared-slack request atoms are retired. Helm's legitimate
HelmChart watch remains, but is now derived explicitly as a read-only secondary
informer rather than hidden in slack. The retired reason remains pinned at zero
so reintroducing even one deputy grant cannot hide as declared slack.

The replacement proof is deliberately redundant:

- the shared role names no Flux API group;
- each split binding names exactly one canonical controller ServiceAccount and
  the same-named ClusterRole;
- the exact cross-controller write matrix, including status and finalizer
  subresources, is denied while owned positive controls remain allowed; and
- the install root alone authorizes all 24 primary/secondary list/watch probes before
  `access.yaml` can be reconciled.

The fast validator, RBAC model, bootstrap live-state mirror, and Conftest rules
all enforce these properties. Conftest is additive defence in depth over the
rendered output; it does not replace the independent structural, behavioral,
or live comparison gates.

### The declared gaps, and what they block

The proof tolerates exactly two remaining gaps, both declared in
`DECLARED_INSUFFICIENCIES` and both tied by test to the `admission`
Kustomization staying suspended.

**1. The Kyverno staging stop.** The `admission` reconciler is namespaced on
purpose, so it can own the inert controller shell but cannot create the
ClusterPolicies or the `ValidatingWebhookConfiguration` its own path declares.
This is the stop already recorded in `access.yaml`.

**2. Admission readiness read-back.** The `admission` Kustomization uses
`wait: true`, so its impersonated reconciler must walk the Deployment down to
its ReplicaSets and Pods. It still has no `get`/`list`/`watch` for those objects
in `kyverno`; that is an independent unsuspend blocker even after the
cluster-scoped policy authority above is resolved.

Issue #186 closes the corresponding HelmRelease gap. Each tenant
`helm-reconciler` now has exactly `get`/`list`/`watch` for core Pods and apps
ReplicaSets in its own namespace. The Conftest exception matches the complete
tuple — tenant namespace, Role name, API group, resource, and exact read-only
verbs. A lookalike Role, foreign namespace, extra resource, write verb, or
cross-tenant request remains denied. Helm waits stay enabled; this RBAC proof no
longer relies on suspending a HelmRelease to hide missing readiness authority.
It does not by itself authorize any unsuspend.

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
4. **Custody bypass.** The hermetic portable lane exercises isolated imports,
   bytecode refusal, interpreter/tool identities, and the protocol's descriptor,
   link, mode, owner, digest, context/server, external-reference, and
   direct-checkout rejection paths without printing or reading Secret values.
   Those tests show that the held-custody implementation rejects its hostile
   fixtures; they do not establish stage-zero trust for a mutable checkout or
   enable the blocked live oracle. Native Windows keeps the portable protocol
   and identity suite; it does not pretend to supply POSIX descriptor custody.

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

- before step 4, owned rows and all 18 issue-98 crossing rows are `ALLOWED`;
- after step 4 but before step 5, every owned row remains `ALLOWED`; the three
  source-controller controller-to-controller categories (seven literal rows)
  become `DENIED`, while all 11 kustomize-controller and helm-controller rows
  remain `ALLOWED` only because the still-live
  `cluster-reconciler-flux-system` binding grants those two `cluster-admin`;
- after step 5, every owned row remains `ALLOWED` and every crossing/general
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
    auth can-i get secrets -A \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i list secrets -A \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i watch secrets -A \
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
    # Primary and secondary informers exist even for kinds with no object.
    auth can-i list buckets.source.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:source-controller
    auth can-i list buckets.source.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i watch ocirepositories.source.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i get secret/sops-age -n flux-system \
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

    # Helm readiness read-back: all six requests in each tenant must be yes.
    auth can-i get pods -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i list pods -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i watch pods -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i get replicasets.apps -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i list replicasets.apps -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i watch replicasets.apps -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i get pods -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i list pods -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i watch pods -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i get replicasets.apps -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i list replicasets.apps -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i watch replicasets.apps -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i get pods -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i list pods -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i watch pods -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i get replicasets.apps -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i list replicasets.apps -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i watch replicasets.apps -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler

    # DECLARED GAPS — these answer `no` today, and that is recorded rather than
    # fixed (see "The declared gaps" above). Run them so the answer is observed
    # rather than assumed, and do NOT unsuspend the objects that need them until
    # the reviewed decision is made.
    auth can-i list pods -n kyverno \
      --as=system:serviceaccount:flux-system:admission-reconciler
    auth can-i list replicasets.apps -n kyverno \
      --as=system:serviceaccount:flux-system:admission-reconciler

    # must be no
    auth can-i create deployments -n kube-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i get secrets -n kube-system \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i list secrets -A \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i watch secrets -A \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i create clusterrolebindings \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i create namespaces \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i create serviceaccounts/token -n kube-system \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i update secrets -n flux-system \
      --as=system:serviceaccount:flux-system:helm-controller
    # Tenant Helm identities may read readiness state only. Prove both the
    # same-namespace write boundary and the cross-tenant read boundary for
    # every tenant; a representative sample is not sufficient.
    auth can-i update pods -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i delete replicasets.apps -n naranjo-online \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i get pods -n lidersea-com \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i list replicasets.apps -n lidersea-com \
      --as=system:serviceaccount:naranjo-online:helm-reconciler
    auth can-i update pods -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i delete replicasets.apps -n lidersea-com \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i get pods -n cloudflare-public \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i list replicasets.apps -n cloudflare-public \
      --as=system:serviceaccount:lidersea-com:helm-reconciler
    auth can-i update pods -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i delete replicasets.apps -n cloudflare-public \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i get pods -n naranjo-online \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i list replicasets.apps -n naranjo-online \
      --as=system:serviceaccount:cloudflare-public:helm-reconciler
    auth can-i impersonate serviceaccounts/root-reconciler -n flux-system \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i '*' '*' -A \
      --as=system:serviceaccount:flux-system:kustomize-controller

The issue-98 crossing sweep is the following literal 18-request matrix, not a
representative sample. Every request is cluster-wide (`allNamespaces=true`) and
has no object name. The portable RBAC model expands the same ownership property
exhaustively to 1,365 verb/resource/subresource/scope requests and also pins 94
per-controller grant atoms, 98 exclusive comparisons, and the six exact HelmChart
handoff exemptions.

| Subject ServiceAccount | Verb | API group and resource | After step 4 | After step 5 |
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

Only one RBAC object is deleted, but TWO RBAC boundaries remove authority, and
the difference decides what a rollback has to restore. Step 6 later observes
controller health without mutating the operator and temporarily mutates one
HelmRelease solely as runtime proof; the release change is a separate journaled
workload boundary.

`crd-controller-flux-system` is patched with a strategic-merge patch that
REPLACES `rules` and `subjects` wholesale. So the moment step 4 applies it, the
live shared ClusterRole loses its wildcard rules, its cluster-wide Secret read,
and `serviceaccounts/token` creation, and the live binding loses four of its
seven subjects. The dedicated Helm ClusterRole must already preserve the exact
Secret `get`/`list`/`watch` needed for startup. This is a removal, not an
addition, and it happens before the "destructive" step.

Issue #98 makes that replacement narrower again: the shared role loses every
Flux API group, while six new install-root objects carry the replacement —
three ClusterRoles and their three exactly-one-ServiceAccount bindings. The six
must exist before the shared-role replacement lands. Applying the replacement
without them removes all 24 primary/secondary informer list/watch grants plus
Helm's three Secret startup-cache grants from the controller install and cannot
reach readiness.

That transaction boundary is why the six live in
`kubernetes/flux-system/controllers/per-controller-rbac.yaml`, a resource of
the controller install root, and never in later-reconciled `access.yaml`.

For **kustomize-controller and helm-controller** the loss is masked: they still
hold `cluster-admin` through `cluster-reconciler-flux-system` until step 5.
For **source-controller it is not masked at all** — that binding never covered
it — so from step 4 onward source-controller runs on the narrowed authority
alone. It is therefore the controller to canary first, and the reason step 4
carries its own verification and its own rollback boundary.

The four subjects removed from the binding name ServiceAccounts this install
does not create, so removing them takes away no live authority; they are
restored on rollback anyway, because rollback restores the whole pre-change
object rather than the parts someone judged load-bearing.

## Procedure

**LIVE USE IS BLOCKED until the gate below is satisfied.** Neither current
script is an eligible mutation entry point: the installer is fresh-only and the
bootstrap script intentionally refuses live modes. The migration needs a new,
separately reviewed protected-host launcher with `--plan`, `--apply`,
`--rollback`, and `--verify`, bound to the merged commit, explicit target tuple,
reviewed tool bytes, and a reviewed plan hash.

Nine cluster-scoped objects are in the RBAC boundary: three existing objects are
replaced or deleted and six split objects are created. The live active path also
needs a deliberately selected namespaced subset; applying all of `access.yaml`
would create dormant identities and is not an acceptable shortcut.

1. **Freeze the live prestate without Secret data.** The journal is a mode-0600,
   fsynced operator artifact. Bind the exact controller images, Deployment
   generations and N/N status, Pod UIDs/restarts, and the complete Flux object
   inventory. The last read-only observation was zero GitRepositories, zero
   Kustomizations, two site OCIRepositories, and two site HelmReleases; re-read
   rather than assume those counts. Capture each live object's UID,
   resourceVersion, generation, suspension, conditions, artifact revision or
   digest, Helm history, and workload readiness. Capture canonical semantic
   bytes plus UID/resourceVersion for every touched RBAC object. Confirm the six
   split ClusterRoles/Bindings are absent and record the broad binding's exact
   identity. Never journal Secret content.
2. **Close the mutation inventory.** It contains the six split
   ClusterRoles/Bindings; the shared `crd-controller-flux-system` ClusterRole and
   Binding; the legacy broad Binding deletion; the `flux-controller-runtime`
   Role/Binding; and, in each of the two namespaces with an active HelmRelease,
   the `flux-controller-impersonation` Role/Binding plus the
   `helm-reconciler` ServiceAccount/Role/Binding. The equivalent five
   `cloudflare-public` objects are excluded unless a separately reviewed plan
   establishes that dormant connector readiness belongs in this transaction.
3. **Create replacement authority first.** Create the six split objects,
   including Helm's cluster Secret `get`/`list`/`watch`, then create or replace
   the closed namespaced subset, including tenant-local Pod and ReplicaSet
   `get`/`list`/`watch`. Record every created UID/resourceVersion and require the
   exact target semantic bytes. Before removing anything, require all owned
   controls `ALLOWED`, all tenant read-back writes and cross-tenant reads
   `DENIED`, Helm Secret writes `DENIED`, and the existing controllers and four
   Flux objects unchanged from prestate.
4. **Replace the shared objects.** Replace the shared ClusterRole and
   subject-pinned Binding under captured resourceVersion preconditions. Run the
   mixed-phase authorization matrix. The seven source-controller crossings must
   now be `DENIED`; the 11 kustomize/helm crossings remain temporarily
   `ALLOWED` only through the still-present broad binding. Require both live
   OCIRepositories current and `Ready=True`; this is the source-controller
   canary on the actual live path.
5. **Delete the broad binding last.** Delete only the captured
   `cluster-reconciler-flux-system` UID/resourceVersion. Require every owned row
   `ALLOWED`, all 18 cross-controller rows and every general forbidden row
   `DENIED`, the exact expected binding graph, and no unexpected binding that
   reaches a controller account.
6. **Prove both issue-186 findings without terminating an operator.** The
   disposable kind lane initially creates both Kustomize and Helm at zero.
   Kustomize's sole zero-to-one creation occurs only after final RBAC and must
   reach current-generation readiness with one zero-restart Pod while Helm
   remains absent. Helm's later sole zero-to-one creation observes the missing
   Secret-read failure, and the same Pod's ordinary kubelet retry becomes ready
   after the reviewed rule is restored; Kustomize's exact Pod must remain
   unchanged and ready throughout.
   The protected transaction performs no controller restart, Pod deletion,
   eviction, or scale-down. Observe the existing helm-controller Deployment at
   its current generation and fully ready without `cluster-admin`, then perform
   the separately plan-bound controlled upgrade of one existing HelmRelease
   using only a collision-free
   `spec.commonMetadata.annotations` change. Require current observed generation,
   exactly one `Ready=True` with `reason=UpgradeSucceeded`, a later deployed Helm
   revision, and a ready workload. Restore the captured spec under
   resourceVersion preconditions and prove the final Flux/workload state matches
   the accepted plan. Any concurrent change is `recovery-required`, never an
   overwrite opportunity.

## Rollback

Rollback is per boundary, and it restores **objects**, not just the deletion.
RBAC restoration is evaluated per request and takes effect immediately without
a restart or drain. Runtime-proof rollback separately restores the captured
HelmRelease spec and verifies its workload; it does have workload impact.

| Failed at | Restore |
|---|---|
| after additive objects, before shared replacement | restore every modified namespaced object from the journal, then remove only transaction-created objects whose UID, resourceVersion, semantic hash, labels, roleRef, and subjects still match |
| after shared replacement, before broad deletion | restore the captured shared ClusterRole and Binding first, restore namespaced prestate, then remove exact transaction-created matches |
| after broad deletion or during runtime proof | re-create the captured broad Binding first, restore the shared ClusterRole/Binding and namespaced prestate, then remove exact transaction-created matches; if the HelmRelease proof mutation began, restore its captured spec only under the journaled UID/resourceVersion transition and verify release plus workload poststate |
| interrupted anywhere, state unknown | recover in the same reverse order, including the captured HelmRelease spec when its proof boundary began; any missing or changed identity is `recovery-required`, never permission to delete or overwrite by name |

Re-creating the deleted binding alone is **not** a full rollback: it restores
`cluster-admin` for kustomize-controller and helm-controller, and nothing at all
for source-controller, whose pre-change authority lived only in the shared
ClusterRole this migration replaced. Roll back all three objects, then re-run
the "must be yes" block plus the source-controller check from step 4 to confirm
the cluster is back where it started. Namespaced objects created by this
transaction are part of the rollback boundary; leaving them behind is residue,
not a harmless shortcut.

If runtime proof fails, do not infer a permission from controller logs and do
not hand-patch the cluster. Restore the journaled prestate, reproduce the exact
failure in the disposable kind acceptance environment, and change reviewed Git.

**What is not proven here.** Protected-cluster rollback is written from the
objects' semantics — `roleRef` immutability, replace-not-merge patch behaviour,
per-request RBAC evaluation — and from the offline proof above. The disposable
kind harness exercises only acceptance-owned Helm remediation rollback; its
receipt explicitly records that protected convergence rollback was not tested.
A failure has not been injected at each protected transaction boundary, because
that requires the cluster this change is deferred from touching. Exercising
those boundaries is part of the separately reviewed owner-run apply, in the
order above: each boundary is verified before the next begins, and the frozen
capture from step 1 is what makes any of them reversible.

## Gate

After the owner establishes that the workstation, checkout, and Make entrypoint
are under their control, select the exact clean, pushed non-main candidate head.
With kind/kubectl/Helm/Go matching `versions.env`, the target binds the isolated
Python plus Git, Docker, kind, kubectl, Helm, and Go executable identities into
the journal and receipt. Its committed-blob execution, raw tracked-tree check,
and private phase handoff are defence in depth inside that local assumption;
they are not an independently trusted stage-zero launcher. The receipt parent
must already exist outside the checkout, and the receipt path itself must not
exist:

```bash
EXPECTED_COMMIT="$(git rev-parse HEAD)"
FLUX_RBAC_KIND_RECEIPT=/absolute/existing-parent/new-flux-rbac-kind-receipt.json
make flux-rbac-kind-acceptance \
  EXPECTED_COMMIT="$EXPECTED_COMMIT" \
  FLUX_RBAC_KIND_RECEIPT="$FLUX_RBAC_KIND_RECEIPT"
```

A PASS receipt is owner-controlled local disposable-acceptance evidence only.
It claims neither adversarial stage-zero provenance nor promotion authority. It
is not permission to reuse a protected kubeconfig, run the protected
convergence transaction, or unsuspend a Flux object.

This apply is deferred and stays deferred until ALL of the following hold:

- the issue-186 repair and issue-98 split are both present on protected `main`,
  all required checks are green, and independent review binds the exact head;
- the disposable real-API acceptance uses the real pinned Flux controllers and
  cold-starts Kustomize under final RBAC with one zero-restart Pod while Helm
  remains at zero, preserves that exact Pod through the Helm proof, proves the
  Helm cache failure without Secret read, one install failure and one upgrade
  failure, each with a healthy workload, across the two missing readiness
  rules, successful install plus
  upgrade with all rules, acceptance-only Helm remediation rollback, and zero
  harness-owned kind/kubeconfig/network residue; it grants no protected-cluster
  mutation authority;
- an owner-reviewed protected-host launcher implements the closed plan,
  prestate journal, UID/resourceVersion mutations, rollback, and verification
  described above without trusting mutable checkout paths;
- a fresh read-only inventory matches the reviewed active-object plan, and any
  drift produces a new plan rather than an operator edit;
- the authorization applies to the exact merged commit and reviewed plan.

The paused route/reboot/admission-controller security queue is outside this
reduced RBAC scope and is not a hidden prerequisite. Kyverno remains absent, so
repository policy is CI defence in depth rather than a live admission claim.

Unsuspending any Flux object is a further, separate decision that this
narrowing is a precondition for — not a consequence of.
