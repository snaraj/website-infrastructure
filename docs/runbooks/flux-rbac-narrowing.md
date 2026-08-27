# Flux controller RBAC narrowing — protected transaction, gated

Status: `DO NOT APPLY`. Checkout execution is permanently `BLOCKED`. The
desired state in this repository is narrowed; live convergence is allowed only
after the gate below is satisfied and only through the exact released,
root-custodied transaction in
[`bootstrap/flux/rbac-convergence/README.md`](../../bootstrap/flux/rbac-convergence/README.md).
The owner must attend its `sudo`, plan-review, apply, and recovery boundaries.

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
   and OCIRepository. Neither role can read Secrets at cluster scope;
5. adds the namespaced authority the controllers still need — leader election,
   controller-owned ConfigMaps, an exact `get` of the named SOPS age key, and one name-restricted
   impersonation Role per namespace holding reconciler accounts
   (`kubernetes/flux-system/access.yaml`);
6. corrects both site release reconcilers from `gitrepositories` to
   `ocirepositories`, the kind their own source objects declare.

Kustomize and Helm optional ConfigMap/Secret event watchers are disabled with
the exact `--feature-gates=DisableConfigWatchers=true` argument. Kubernetes
cannot grant metadata-only Secret watch authority, so the alternative would
expose every namespace's Secret names and metadata plus any data returned by
`get`. Kustomize referenced inputs are fetched by exact name during
reconciliation; a change is observed on the next interval, retry, source event,
or manual reconciliation instead of by an immediate ConfigMap/Secret event.
The closed Helm contract allows only inline values and the local release
namespace: `valuesFrom`, `kubeConfig`, `storageNamespace`, and `targetNamespace`
are rejected. Helm release storage remains available through each impersonated
tenant reconciler's namespaced Role.

The transaction's required starting prestate contains the broad
`cluster-reconciler-flux-system` binding, and the last bounded observation
found it. Do not treat that observation as current: `--plan` must re-read the
entire graph, require exactly that broad cluster-admin binding for the tracked
controllers, and reject every tracked binding outside its closed inventory.
The intended Git/live authorization delta closes only when the transaction
deletes that exact captured UID/resourceVersion at step 5. Final verification
requires no cluster-admin binding to reach a tracked controller and compares
the whole resulting graph with the plan-derived expected graph.

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

### Naranjo claim lifecycle boundary

Issue #211 adds `persistentvolumeclaims` lifecycle only to the
`naranjo-online/helm-reconciler` Role because the reviewed usage-export chart
owns two claims. Kubernetes cannot restrict PVC `create` by resource name, so
the compensating boundary is the reviewed render plus the existing storage
policy: claims must explicitly select the owner-enumerated `local-pie-ssd`
StorageClass, declare no data source or remote storage mechanism, and remain
local to the Pi. The Role grants no PersistentVolume, StorageClass, node,
provisioner, snapshot, host-path, cross-namespace, or cluster-wide authority.
The same exact rule is carried in `desired-active.json`; therefore the protected
#141 transaction preserves it rather than replacing the live Role with an older
shape before #189 begins reconciliation.

## Live proof, before the deletion

Use the protected kubeconfig ceremony; never a bare `kubectl` against a mutable
default context. Every command here is a read. The command inventory below uses
`auth can-i` to keep each reviewed request legible, but a raw `no` is **not** a
denial receipt: kubectl can produce the same text and exit status before the
authorizer is reached.

### Closed discovery + authorization oracle

**LIVE USE IS GATED THROUGH THE PROTECTED TRANSACTION.**
`scripts/flux_rbac_denial_oracle.py` contains and hermetically tests the closed
protocol below, but a mutable checkout script cannot establish its own
stage-zero trust before receiving a protected kubeconfig. Its direct CLI
therefore remains non-evidence. Do not invoke it directly, classify raw
`auth can-i` output, or use either as promotion evidence.

The exact released transaction copies this oracle blob from the reviewed
commit through root custody, binds the interpreter, pinned kubectl, protected
kubeconfig, exact release, target tuple, and reviewed plan without reopening
mutable sources, and preserves the oracle's closed output in its journaled
phase evidence. Only that root-owned launcher may perform the following three
ordered, separately recorded operations:

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
   authorize direct live-oracle execution. Native Windows keeps the portable
   protocol and identity suite; it does not pretend to supply POSIX descriptor
   custody.

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
phase assumptions but are not promotion receipts; the protected transaction
must recapture them against its exact plan and target.

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

The first protected denial row is recorded below as an argument manifest,
**not an executable command**. The protected transaction supplies the private
tuple from root custody and repeats every non-wildcard row at its reviewed
phase boundary:

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
not copy credentials during review, substitute a different kubeconfig, invoke
the oracle with `sudo` outside the transaction, or record private host identity
here. The launcher must also enforce the v1.36.3 ARM64 `kubectl` SHA-256 already
recorded as `KUBECTL_ARM64_SHA256`.

Executable and kubeconfig custody is part of the protected result. The oracle
requires one independently supplied lowercase SHA-256 pin for every
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

The protected transaction repeats the closed rows through the oracle at each
migration boundary. The phase names, contents, and counts are executable
invariants:

| Evidence label | Exact expected matrix | Receipts |
|---|---|---:|
| `pre-shared` | after split and namespaced convergence, before watcher/shared changes: 42 startup/informer allows, nine owned allows, all 18 issue-98 crossings allowed, and 32 tenant local-read allows plus foreign/read-write denials | 101 |
| `mixed` | after watcher handling and shared replacement, before broad deletion: 42 startup/informer and nine owned rows allowed; the seven source-controller crossings denied; the remaining 11 kustomize/helm crossings still allowed through the broad binding | 69 |
| `final` | after broad deletion: 42 startup/informer and nine owned rows allowed; all 18 crossings denied; 40 tenant impersonation/local-read/isolation checks and 16 cluster-Secret/general forbidden denials | 125 |
| `post-proof-final` | after the Helm proof is restored and transaction annotations are removed: the exact `final` matrix again | 125 |
| `rollback-terminal` | after rollback: all nine owned and all 18 crossing rows allowed, matching the captured broad-authority prestate | 27 |

Committed verification reruns the 125-row final matrix; rolled-back
verification reruns the 27-row rollback matrix. The fresh receipt-set digest
must equal the applicable journaled terminal digest. Each receipt also carries
its exact request echo, resolved discovery, expected result, two allowed
controls, inert denied control, and `PASS`. A missing, extra, duplicate,
oversized, unresolved, or differently classified receipt invalidates the
entire phase.

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

All 18 are required in the disposable real-API sweep as well as in the
owner-run protected transaction. The `status` identities must resolve through
the API server's advertised subresources. Kubernetes does not advertise the
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

The repository render uses strategic-merge patches whose `rules` and `subjects`
REPLACE those fields wholesale. The protected live transaction does not apply
those patch files: at step 4 it sends the exact fully rendered shared objects as
resourceVersion- and UID-fenced replacements. At that boundary the live shared
ClusterRole loses its wildcard rules, cluster-wide Secret read, and
`serviceaccounts/token` creation, and the live binding loses four of its seven
subjects. The dedicated per-controller ClusterRoles must already preserve the
own-resource and secondary-informer authority needed for startup. This is a
removal, not an addition, and it happens before the broad-binding deletion.

Issue #98 makes that replacement narrower again: the shared role loses every
Flux API group, while six new install-root objects carry the replacement —
three ClusterRoles and their three exactly-one-ServiceAccount bindings. The six
must exist before the shared-role replacement lands. Applying the replacement
without them removes all 24 primary/secondary informer list/watch grants from
the controller install and cannot reach readiness.

That transaction boundary is why the six live in
`kubernetes/flux-system/controllers/per-controller-rbac.yaml`, a resource of
the controller install root, and never in later-reconciled `access.yaml`.

For **kustomize-controller and helm-controller** the loss is masked: they still
hold `cluster-admin` through `cluster-reconciler-flux-system` until step 5.
For **source-controller it is not masked at all** — that binding never covered
it — so from step 4 onward source-controller runs on the narrowed authority
alone. It is therefore the controller to canary first, and the reason step 4
carries its own verification and its own rollback boundary.

The narrowed binding removes four legacy subjects, but the transaction does
not rely on an assumption about whether those ServiceAccounts currently exist.
It captures the entire pre-change object and restores all captured subjects on
rollback rather than restoring only the parts judged load-bearing.

## Procedure

**LIVE USE IS GATED.** Neither the fresh-only installer, the bootstrap script,
the denial oracle, nor `access.yaml` is an eligible mutation entry point. The
only entry point is the exact released, root-owned transaction documented in
[`bootstrap/flux/rbac-convergence/README.md`](../../bootstrap/flux/rbac-convergence/README.md).
`access.yaml` is not in its custody manifest: the transaction never reads or
applies it.
Its `--stage`, `--plan`, `--apply`, `--rollback`, `--verify`, and single-incident
`--recover-v030` modes bind the
protected merge and platform Release, explicit target tuple, reviewed tool
bytes, captured UID/resourceVersion prestate, and owner-reviewed plan hash.
Use only the literal mode commands in that README. Every invocation must be
`sudo /usr/bin/env -i LC_ALL=C`, followed by only the exact variables allowed
for that mode, `/usr/bin/python3 -I -B`, and the fixed installed launcher. A
bare `sudo`, ambient environment, direct shebang execution, different Python,
or checkout path is outside the process boundary and is rejected.

**Freeze before custody and keep the freeze through terminal verification.**
From the held-descriptor custody ceremony until `--verify` succeeds for either
the committed or rolled-back state, make no out-of-band change to the installed
launcher, `/usr/bin/python3`, selected kubectl, kubeconfig or credentials,
Kubernetes CA, private target identities, or `target.json`. Do not run apt or
another package/OS upgrade. Do not reboot the operator or target host. Do not
publish either site or move an OCI tag. Outside the exact transaction modes, do
not change controller, RBAC, or Flux state or host WireGuard state. That is an
owner-controlled maintenance freeze, not a claim that the launcher can observe
every registry or host-side violation. On a violation or doubt, stop, preserve
all state, and use owner-reviewed recovery. Never compensate with `access.yaml`,
manual kubectl, a forward retry, or a replan.

The v0.1.36 release carries one owner-attended recovery for the authenticated
v0.1.30 sequence-47 stop caused solely by Naranjo moving from 0.1.42 through
exactly four sequential protected releases ending at 0.1.46. That mode must
terminalize the old journal and publish its rolled-back receipt before a fresh
v0.1.36 plan is captured. It does not broaden the normal rollback classifier,
accept another release movement, or perform forward work.
For the three static Helm-owned objects it admits only the chart-version label
movement: their UIDs and exact live safe shapes are closed, and projecting that
single label back to 0.1.42 must reproduce the captured semantic hashes. The
active ReplicaSet must carry exactly the already-validated Deployment
annotations plus the controller's desired/max replica annotations; its selector
is the Deployment selector plus `pod-template-hash`, while its object and Pod
template labels remain the full reviewed template-label set plus that hash. The
immutable platform release remains valid after later protected-main merges only
while its commit is still verified as an ancestor; tag, Release, CI, tree, and
custody identity remain exact.

The reviewed release tree must stay unchanged until the held-descriptor stage
prints `STAGED` and validates the root custody receipt. Only then may the source
checkout change. After that boundary, checkout bytes are neither input nor
authority: the root-owned custody tree and receipt are authoritative for every
later mode, and the checkout must never be reopened or restaged into this
transaction.

The canonical `plan.json` is immutable once published. Drift, expiry, a wrong
target, or a changed review conclusion is a stop. Do not delete, overwrite,
regenerate, or rerun `--plan`; there is no supported same-transaction replan.
Forward work after such a stop requires a new owner-reviewed transaction
release and custody ceremony.

Nine cluster-scoped objects are in the RBAC boundary: three existing objects are
replaced or deleted and six split objects are created. The live active path also
needs a deliberately selected namespaced subset; applying all of `access.yaml`
would create dormant identities and is not an acceptable shortcut.

All 23 rows stay in the recorded operation order. The six split rows are
always creates from proven absence, and the broad binding is always a delete
from captured presence. The 12 namespaced `converge` rows create when absent,
replace when present and semantically different, or become semantic no-ops
when already exact. The two controller argument rows similarly become `args`
or `noop`, and the shared pair become `replace` or `noop`. A no-op is still
journaled and must reread the exact captured UID, resourceVersion, prestate
semantic hash, and desired hash without issuing an API mutation. Never omit it
or change effective action by editing the plan.

1. **Freeze the live prestate without Secret data.** The journal is a mode-0600,
   fsynced operator artifact. Bind the exact controller images, Deployment
   generations and N/N status, Pod UIDs/restarts, and the complete Flux object
   inventory. The executable inventory requires zero Bucket,
   ExternalArtifact, GitRepository, HelmChart, HelmRepository, and
   Kustomization objects, plus exactly the two site OCIRepositories and two
   same-site HelmReleases; re-read rather than assume those counts. For both
   allowlisted pairs — `naranjo-online/naranjo-online-chart` to
   `naranjo-online/naranjo-online` and `lidersea-com/lidersea-com-chart` to
   `lidersea-com/lidersea-com` — derive `chartVersion` only during `--plan`
   from the exact current Cosign-verified OCI artifact `revision`. Require a
   canonical stable release SemVer inside the exact `>=0.1.9 <1.0.0` source
   range, then bind that `revision`, its derived `chartVersion`, its nonzero
   upstream `sha256:` `upstreamDigest`, and the separately captured OCI
   stored-artifact digest into the pair's immutable plan baseline. The local
   HelmRelease must use `helm-reconciler` and only inline
   `values={"deploymentReady":true}`. Bind its baseline to the exact Helm tuple:
   `attemptedRevision=<chartVersion>+<first-12-upstreamDigest-hex>`,
   `attemptedRevisionDigest=<upstreamDigest>`, the positive numeric
   `historyRevision`, `historyChartVersion=<attemptedRevision>`,
   `historyStatus=deployed`, and `historyOciDigest` either absent or exactly
   `<upstreamDigest>`; also capture the history release/config digests. Its
   status inventory must equal exactly one live Helm-owned Deployment, Service,
   ServiceAccount, and NetworkPolicy in the same namespace. Capture each live
   object's UID, resourceVersion, generation, suspension, conditions, complete
   Helm history, and workload readiness. After plan publication, every current
   source and Helm identity field must remain exactly equal to its recorded
   immutable plan baseline. A later chart version, even when canonical, stable,
   and in range, is drift; do not recapture or replan it into this transaction.
   Capture canonical semantic bytes plus UID/resourceVersion for every touched
   RBAC object. Confirm the six split ClusterRoles/Bindings are absent and
   record the broad binding's exact identity. Never journal Secret content.
2. **Close the mutation inventory.** It contains the six split
   ClusterRoles/Bindings; the shared `crd-controller-flux-system` ClusterRole and
   Binding; the legacy broad Binding deletion; the `flux-controller-runtime`
   Role/Binding; and, in each of the two namespaces with an active HelmRelease,
   the `flux-controller-impersonation` Role/Binding plus the
   `helm-reconciler` ServiceAccount/Role/Binding; and the exact reconciler
   Deployment argument updates needed wherever live prestate lacks the reviewed
   config-watcher gate.
   The equivalent five `cloudflare-public` objects are unconditionally outside
   this closed transaction. Adding them would require a different reviewed
   implementation and release, never a plan edit or replan.
3. **Create replacement authority first.** Create the six split objects, which
   grant no cluster-wide Secret access, then create or replace the closed
   namespaced subset, including tenant-local Pod and ReplicaSet
   `get`/`list`/`watch`. Record every created UID/resourceVersion and require the
   exact target semantic bytes. Before removing anything, require all owned
   controls `ALLOWED`, all tenant read-back writes and cross-tenant reads
   `DENIED`, and the existing controllers and four Flux objects unchanged from
   prestate. The still-present broad binding temporarily keeps controller
   Secret probes allowed; do not misreport them as final denials yet.
   **Before step 4, disable optional config watchers while broad authority still
   exists.** For each of `kustomize-controller` and `helm-controller`, first
   compare live arguments with the reviewed set. If the exact
   `--feature-gates=DisableConfigWatchers=true` flag is absent, update only that
   Deployment's reviewed arguments under its captured UID/resourceVersion, one
   controller at a time. Require a new current generation with exactly one
   Ready, zero-restart manager Pod and the exact reviewed argument set before
   moving to the next controller. If either rollout fails, restore captured
   Deployment prestate before changing RBAC. This ordering prevents an old
   process from retaining a Secret informer after its permission is removed.
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
   reaches a controller account. Helm controller cluster-wide Secret
   `get`/`list`/`watch` and writes must now all be `DENIED`.
6. **Prove both issue-186 findings.** The
   disposable kind lane initially creates both Kustomize and Helm at zero.
   Kustomize's sole zero-to-one creation occurs only after final RBAC and must
   reach current-generation readiness with one zero-restart Pod while Helm
   remains absent. Helm's later sole zero-to-one creation must reach
   current-generation readiness with one zero-restart Pod while all three
   cluster-wide Secret read probes deny; Kustomize's exact Pod must remain
   unchanged and ready throughout.
   The protected transaction uses only the reviewed step-3 reconciler rollouts; it
   performs no ad-hoc Pod deletion, eviction, or scale-down. Reconfirm that
   rolled-out Deployment is fully ready without `cluster-admin`, then perform
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
RBAC restoration is evaluated per request and takes effect immediately. The
Deployment argument change is a separate rollout boundary and must be restored
from captured prestate if its step fails. Runtime-proof rollback separately
restores the captured HelmRelease spec and verifies its workload; it does have
workload impact.

Route recovery from classified durable state only:

| Journal/live classification | Only valid next action |
|---|---|
| `committed`, even if PASS receipt publication was interrupted | `--verify`; never `--rollback` or `--apply` |
| `rolled-back`, even if rollback receipt publication was interrupted | `--verify`; never `--apply` |
| safely attributable `prepared` or `recovery-required` nonterminal journal | owner reviews, then runs the exact `--rollback` command from the transaction README once |
| ambiguous pending effect, journal, target identity, UID/resourceVersion, semantics, transaction marker, or live state | stop, preserve everything, and use owner-reviewed recovery; do not invoke a mutating mode |

`--verify` does not classify a nonterminal journal and returns
`RECOVERY_REQUIRED`. `--rollback` rejects committed state. Repeating rollback
against an already rolled-back journal can reproduce its receipt, but the
required next evidence step is still terminal `--verify`.

| Failed at | Restore |
|---|---|
| during a step-3 watcher-disable rollout | restore each changed reconciler Deployment under its journaled identity, prove its rollout, restore modified namespaced objects, then remove exact transaction-created matches |
| after additive objects and reconciler rollouts, before shared replacement | restore each changed reconciler Deployment and every modified namespaced object from the journal, then remove only transaction-created objects whose UID, resourceVersion, semantic hash, labels, roleRef, and subjects still match |
| after shared replacement, before broad deletion | restore the captured shared ClusterRole and Binding first, then restore changed reconciler Deployments and namespaced prestate before removing exact transaction-created matches |
| after broad deletion or during runtime proof | re-create the captured broad Binding first, restore the shared ClusterRole/Binding, changed reconciler Deployments, and namespaced prestate, then remove exact transaction-created matches; if the HelmRelease proof mutation began, restore its captured spec only under the journaled UID/resourceVersion transition and verify release plus workload poststate |
| interrupted with a safely attributable nonterminal journal | recover in the same reverse order, including the captured HelmRelease spec when its proof boundary began; any missing or changed identity changes the classification to ambiguous and requires an owner-reviewed stop, never deletion or overwrite by name |

Both terminal paths carry an exact 23-row target inventory in operation order.
Committed evidence has 22 present rows with desired semantics and one absent
broad-binding row. Rolled-back evidence has every originally absent target
absent and every originally present target restored semantically; unchanged
objects retain their captured UID, while a safely recreated broad binding is
bound to the journaled restored UID. Present rows record ID, UID, current
resourceVersion, and semantic SHA-256. Terminal evidence also binds the exact
binding graph and the applicable 125-row `post-proof-final` or 27-row
`rollback-terminal` evidence record. The journal commits that evidence and its
digest before publishing the terminal receipt; terminal `--verify` rereads all
of it and writes a numbered, hash-chained verification record. The fresh
inventory must keep IDs, presence, UIDs, and semantic hashes exact;
resourceVersions are recaptured and may advance, so verification does not
claim they equal the earlier terminal snapshot.

Re-creating the deleted binding alone is **not** a full rollback: it restores
`cluster-admin` for kustomize-controller and helm-controller, and nothing at all
for source-controller, whose pre-change authority lived only in the shared
ClusterRole this migration replaced. Roll back all three objects, then let the
protected launcher run the exact 27-row `rollback-terminal` matrix and complete
prestate verification. Raw `auth can-i` output and the illustrative blocks
above remain non-evidence. Namespaced objects created by this transaction are
part of the rollback boundary; leaving them behind is residue, not a harmless
shortcut.

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

This apply remains gated until ALL of the following hold:

- the issue-186 repair and issue-98 split are both present on protected `main`,
  all required checks are green, and independent review binds the exact head;
- the disposable real-API acceptance uses the real pinned Flux controllers and
  cold-starts Kustomize under final RBAC with one zero-restart Pod while Helm
  remains at zero, then cold-starts Helm with one zero-restart Pod while
  preserving that exact Kustomize Pod and denying Helm cluster-wide Secret
  reads, proves the tenant-local Pod and ReplicaSet readiness reads through
  exact authorization reviews, completes install plus upgrade under the final
  tenant Role, rolls back an acceptance-only synthetic workload failure, and
  leaves zero harness-owned kind/kubeconfig/network residue; it grants no
  protected-cluster mutation authority;
- the exact signed protected-main source and immutable platform Release include
  the reviewed transaction, source manifest, closed desired inventory, prestate
  journal, UID/resourceVersion mutations, rollback, and verification described
  above, and the owner stages those bytes through held root custody without
  trusting mutable checkout execution;
- a fresh read-only inventory matches the reviewed active-object plan; any
  later drift stops this immutable plan, and no replan or operator edit is
  permitted within the transaction;
- the authorization applies to the exact merged commit and reviewed plan.

The paused route/reboot/admission-controller security queue is outside this
reduced RBAC scope and is not a hidden prerequisite. Kyverno remains absent, so
repository policy is CI defence in depth rather than a live admission claim.

Unsuspending any Flux object is a further, separate decision that this
narrowing is a precondition for — not a consequence of.
