# Flux controller install — Draft / unverified

Current status is `NO-GO`. Nothing in this runbook authorizes a live
installation. It exists so that when installation *is* authorized, it is an
apply of reviewed bytes from an exact reviewed commit rather than an ad-hoc
command — and so that the review of those bytes can happen now, in a pull
request, instead of at the terminal.

**Scope.** Installing the three pinned Flux controllers as an *inert* control
plane, in an order that closes `flux-system` egress *around* them rather than
underneath them. Out of scope, deliberately and by separate authorization: the
`sops-age` ceremony, the root sync objects, and every `suspend` flip. Those are
[`docs/runbooks/flux-recovery.md`](flux-recovery.md) and the separate reviewed
pull request described under "What stays suspended" below.

## Why the install is inert

The install root
[`kubernetes/flux-system/controllers`](../../kubernetes/flux-system/controllers)
contains only the generated component export plus this repository's hardening
patches: namespaces, CRDs, RBAC, Services, and three Deployments. It contains
**no Flux custom resource** — no `GitRepository`, no `Kustomization`, no
`HelmRelease`. Controllers with nothing to reconcile do nothing: they elect a
leader, watch for custom resources that do not exist, and idle. The root sync
objects live in a different file
([`kubernetes/flux-system/gotk-sync.yaml`](../../kubernetes/flux-system/gotk-sync.yaml))
which this ceremony never applies.

That is what makes the install safe to perform, and safe to undo, independently
of any decision about what Flux should eventually manage. Both websites are
served through their tunnels regardless: no site delivery path passes through
Flux at any point in this runbook.

## Why the apply is ordered, and what happens if it is not

The reviewed bundle applies `allow-egress` with its blanket `egress: [{}]`
removed by
[`patches/allow-egress.yaml`](../../kubernetes/flux-system/controllers/patches/allow-egress.yaml).
What survives is `podSelector: {}` with `policyTypes: [Ingress, Egress]` and no
rules — on a NetworkPolicy-enforcing CNI, a **namespace-wide deny**. That is the
intended posture, and it is also a trap: create the three controller Deployments
in the same apply and their Pods start egress-isolated. No DNS, no API server,
so no leader election and no cache sync — the Pods never reach `1/1`, the
readiness step below can never pass, and the install **deadlocks** in a state
that looks like a broken controller rather than a missing allow.

`scripts/install-flux-controllers.sh` therefore applies in phases, and the
phases are the script's, not this document's:

| Phase | What | Why here |
| --- | --- | --- |
| 1 | the 22 non-workload objects: Namespace, 8 CRDs, RBAC, ResourceQuota, ServiceAccounts, Service, and the three generated NetworkPolicies including the deny-all | no Pod exists yet, so nothing is isolated yet |
| 2 | `default-deny`, `flux-controllers-dns`, `flux-controllers-artifacts`, `flux-controllers-kube-apiserver` — the API-server allow bound to the very `--server` this run targets | the flows a controller needs to *become* healthy |
| 3 | the three controller Deployments | Pods start into a namespace where those flows already exist |
| 4 | `flux-controllers-public-https`, via `--open-public-egress` | only after the controllers are observed healthy **and** idle |

Public HTTPS is last on purpose. Nothing in phases 1–3 needs it — the
controllers are inert, so they fetch nothing — and deferring it means the
namespace never has a path off the cluster while the install is still being
verified.

## Preconditions

Platform-lane preconditions, none of which this runbook performs or asserts:

1. The cluster is initialized and its API server is reachable from the
   protected operator workstation.
2. A CNI that **enforces `NetworkPolicy`** is installed. The deployment-state
   table in [`README.md`](../../README.md) records the current decision and its
   install state; a CNI without policy enforcement makes the closure desired
   state with no effect, which must not be mistaken for a closed namespace. It
   also means the ordering above is invisible in practice on a non-enforcing
   CNI: the install appears to work, and the same bytes deadlock the day the
   CNI lands. Order it correctly regardless.
3. The protected-custody preconditions in
   [`bootstrap/flux/README.md`](../../bootstrap/flux/README.md) hold: the
   reviewed-blob launcher exists, the trusted Linux operator platform and its
   pinned `kubectl` are staged, the protected flattened kubeconfig validates,
   and the recovery and two-session gates have actually been proven rather than
   claimed.

Until those hold, stop here. Reading the manifests and reproducing the render
digests below requires none of them and is the intended use of this document
today.

## The one thing never to do

**Never apply `kubernetes/flux-system` — the parent root.** It is the
bootstrap-era full-desired-state root, and it carries
[`gotk-sync.yaml`](../../kubernetes/flux-system/gotk-sync.yaml). The root
`Kustomization` in that file has **no `suspend`**, `prune: true`, and
`path: ./kubernetes/reconciliation`; the `platform-prerequisites` Kustomization
it would then reconcile is **also not suspended**. Applying the parent root
therefore does not install Flux — it starts Flux, immediately, with pruning
enabled, against live objects.

Two more reasons that apply is unsafe today, both worth fixing before the root
is ever used: `access.yaml` creates ServiceAccounts and RoleBindings in the
`kyverno` namespace, which the controller install does not create, so the apply
partially fails; and a namespace that is missing the
`kustomize.toolkit.fluxcd.io/prune: disabled` annotation the manifests declare
becomes prune-eligible the moment a root Kustomization reconciles. Verify that
annotation on every namespace *before* any reconciliation, not after.

The installer below cannot be pointed at that root: its target is a constant,
and `scripts/validate_repository.py` refuses a tree in which the egress overlay
is reachable from it.

## What every step is bound to

Three bindings are required by every mode that touches a cluster, and the
installer refuses to run without them. They are not conveniences: an install
that trusts `PATH` and the ambient kubeconfig can be pointed at the wrong
binary and the wrong cluster without anybody noticing.

- **Tools.** `kustomize` must report the `versions.env` `KUSTOMIZE_VERSION`
  pin, and `kubectl` must report the `KUBERNETES_VERSION` pin **and** hash to
  one of the committed `KUBECTL_*_SHA256` digests. A shim earlier on `PATH`
  fails the digest check before any cluster is contacted.
- **Bytes.** The checkout must be a Git checkout with no uncommitted change to
  the install roots, `versions.env`, or the installer, and the render must hash
  to the value passed as `--expect-render-sha256`. Take that value from the
  reviewed pull request, not from the run you are about to perform.
- **Target.** `--kubeconfig`, `--context`, and `--server` are all required and
  are passed on **every** API call. The installer proves the named context
  resolves to the named server before it does anything, and refuses a `--server`
  whose port is not the one the reviewed API-server allow names.

`--server` is also where the API-server egress destination comes from: the
committed policy carries `192.0.2.0/32` (RFC 5737 TEST-NET-1) as a fail-closed
sentinel, and the installer substitutes the address out of `--server` in a
mode-0700 temporary directory that it deletes on exit. The address is never
written into the checkout and never printed. Keep the installer's own output on
the operator terminal: `kubectl` connection errors quote the endpoint, so that
output is operator-private like everything else in this ceremony.

## Step 0 — reproduce the render offline

From a clean checkout of the exact reviewed commit, with the `versions.env` pin
of `kustomize`:

```sh
./scripts/install-flux-controllers.sh --render
```

This contacts no cluster and needs no kubeconfig. It renders both roots, refuses
the controller render if it contains any Flux custom resource, any Secret, or
any NetworkPolicy egress rule, refuses it unless `flux-system` enforces
restricted Pod Security, requires exactly 25 objects, cross-checks the rendered
CRD/ClusterRole/ClusterRoleBinding/Deployment names against the reviewed
inventory, proves the 22 + 3 and 4 + 1 phase splits, and prints both render
digests with the commit they came from.

Record the printed digests with the commit SHA, and compare them against the
reviewed pull request. A digest that does not reproduce means the tree, the
tool, or the commit is not the reviewed one, and the ceremony stops.
`scripts/ci/verify-render-determinism.sh` already proves in CI that renders are
byte-identical, so a mismatch is a fact about the operator's inputs, never about
the renderer.

## Step 1 — plan against the named cluster

```sh
./scripts/install-flux-controllers.sh --plan \
  --kubeconfig "$PROTECTED_KUBECONFIG" \
  --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" \
  --expect-render-sha256 "$REVIEWED_RENDER_SHA256"
```

Same offline guards, then a read-only **pre-apply gate**: a **client-side strict
validation** of all 25 objects and of the five egress policies, an existence and
ownership probe of every cluster-scoped object the install creates, and a
**server-side dry run**. Nothing mutates. The gate refuses if any reported name
falls outside the reviewed controller inventory, and it refuses outright if an
object it would create already exists under foreign ownership.

### Why the server dry run reports "namespace not found" on a fresh cluster

The install creates its own `flux-system` Namespace and 24 objects under it. A
`kubectl apply --dry-run=server` does **not** persist the dry-run Namespace
([kubernetes/kubernetes#83562](https://github.com/kubernetes/kubernetes/issues/83562)),
so on a **fresh** cluster the server has nowhere to place the 11 namespaced
children: each reports `namespaces "flux-system" not found` and `kubectl` exits
non-zero. That is the **expected, healthy** shape of a clean fresh install, not a
failure. The gate accepts exactly the 14 cluster-scoped objects (the Namespace,
8 CRDs, 3 ClusterRoles, 2 ClusterRoleBindings) reporting `created` alongside the
11 namespaced children (1 ResourceQuota, 3 ServiceAccounts, 1 Service, 3
Deployments, 3 NetworkPolicies) reporting that one namespace-not-found error. It
proves the create is clean two further ways that do not depend on the server dry
run persisting the namespace: a client-side strict validation of all 25 objects,
and a check that none of them already exists (`flux-system` absent, no fluxcd
CRDs, the reviewed ClusterRoles and ClusterRoleBindings absent). An earlier gate
that demanded all 25 report `created` could never pass a fresh cluster and would
have blocked the very install this script performs.

On a cluster where `flux-system` **already exists** — a re-run, or a
reconcile-to-reviewed-bytes check — the server dry run instead reports all 25
objects cleanly, and the gate accepts that shape too. Any other line — a foreign
object, a different namespace, a `configured`/`unchanged` where a fresh `created`
was expected, or any other error — fails the gate closed, and nothing is
applied.

## Step 2 — apply, in phases

```sh
./scripts/install-flux-controllers.sh --apply \
  --kubeconfig "$PROTECTED_KUBECONFIG" \
  --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" \
  --expect-render-sha256 "$REVIEWED_RENDER_SHA256"
```

Same guards and the same gate, then the three ordered phases from the table
above. Note what the script does *not* do: it never runs `kubectl apply -k`,
because `kubectl`'s embedded Kustomize is a different build than the pinned one,
so `-k` would apply bytes nobody rendered and nobody hashed.

**The apply is a transaction.** Every phase's output is parsed into a ledger of
the objects *this attempt* created. If any phase fails — including a partial
apply that created a prefix before erroring — the ledger is rolled back
newest-first and the absence of every one of those objects is then re-probed and
reported. Objects that already existed report `configured` and never enter the
ledger, so a failed re-run cannot delete a working install. If a delete does not
take, the script says `ROLLBACK INCOMPLETE` and names what is left rather than
claiming a clean undo.

## Step 3 — verify the controllers, and verify they are idle

```sh
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system get deploy \
  source-controller kustomize-controller helm-controller
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system get pods,networkpolicies
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" get gitrepositories,kustomizations,helmreleases,ocirepositories -A
```

Expected: three Deployments `1/1`, three Pods `Running`, seven NetworkPolicies
(`allow-egress`, `allow-scraping`, `allow-webhooks` from the export; plus
`default-deny` and the three startup allows), and the **last command returns no
resources in any namespace**. A Flux custom resource at this point means
something outside this ceremony created it; stop and investigate before
continuing.

Pods that come up but never reach `1/1`, with logs full of API-server or DNS
timeouts, mean the startup allows do not match the real dataplane — the
substituted address is wrong, or the installed CNI evaluates the policy against
a destination other than the API server's own address. That is the failure the
phase ordering makes *diagnosable*: the allows are already there, so a stuck
controller is a policy-matching problem and not a missing policy.

Confirm the running images are the three digests pinned in `versions.env` and
that no fourth controller exists — `image-reflector-controller` and
`image-automation-controller` are absent by decision, not by omission.

Record, do not be surprised by, the authority the generated export grants:
`cluster-reconciler-flux-system` is a ClusterRoleBinding to **cluster-admin**
for `kustomize-controller` and `helm-controller`. It ships that way upstream.
What keeps it from being the cluster's weakest point here is that both
controllers are patched with `--default-service-account=default` and every
Kustomization in this repository names an explicit least-privilege
`serviceAccountName`, so reconciliation impersonates a namespaced ServiceAccount
rather than using the controller's own identity. Removing the binding outright
is a separate reviewed change: `bootstrap/flux/bootstrap.sh` verifies live
cluster role bindings against a reviewed set that currently includes it, so the
manifest and the verifier must move together.

## Step 4 — open public HTTPS, last

```sh
./scripts/install-flux-controllers.sh --open-public-egress \
  --kubeconfig "$PROTECTED_KUBECONFIG" \
  --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" \
  --expect-render-sha256 "$REVIEWED_RENDER_SHA256"
```

This refuses unless all three controllers report `1/1` and all four startup
allows are present, then applies the one remaining policy from
[`kubernetes/flux-system/egress/network-policies.yaml`](../../kubernetes/flux-system/egress/network-policies.yaml).
After it, nothing else is reachable from a `flux-system` Pod: not the LAN, not
the node, not another namespace, not plain HTTP.

### What the public-HTTPS allow is for

A Kubernetes `NetworkPolicy` selects destinations by address, never by name, so
the reviewed rule is "public addresses, TCP 443, nothing else" rather than a
hostname allowlist. The destinations it exists to permit, recorded here so the
intent is reviewable even though the enforcement is coarser than the intent:

| Destination | Needed by | Since |
| --- | --- | --- |
| `github.com`, `codeload.github.com`, `objects.githubusercontent.com` | source-controller, for the anonymous public Git source | today |
| `ghcr.io`, `pkg-containers.githubusercontent.com` | source-controller, for OCI chart artifacts | only if the tag-driven release sync lands |
| `fulcio.sigstore.dev`, `rekor.sigstore.dev`, `tuf-repo-cdn.sigstore.dev` | source-controller, for keyless signature verification and its TUF root | only if the tag-driven release sync lands |

The Sigstore row is the one that is easy to miss: keyless verification is not
an offline operation, and a chart source configured with `verify` fails closed
— correctly, but confusingly — if those endpoints are unreachable. Container
**image** pulls are not in this table at all: the kubelet pulls images from the
node's network namespace, where a Pod NetworkPolicy has no effect.

## Step 5 — verify the closure

```sh
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system get networkpolicies
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system get networkpolicy allow-egress -o yaml
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system logs deploy/source-controller --tail=50
```

Expected: eight policies (`allow-egress`, `allow-scraping`, `allow-webhooks`
from the export; `default-deny` and the four `flux-controllers-*` allows from
this ceremony), `allow-egress` carrying no `egress` key, three Pods still
`Running` and not restarting, and controller logs free of API-server connection
errors.

## Rollback

Safe at every step, because nothing is reconciling.

**A failed `--apply` has already rolled itself back.** The installer removes
exactly what that attempt created and proves the removal; the procedures below
are for undoing a *successful* install.

- **Undo the closure only:**

  ```sh
  kubectl -n flux-system delete networkpolicy default-deny \
    flux-controllers-dns flux-controllers-artifacts \
    flux-controllers-public-https flux-controllers-kube-apiserver
  ```

  The controllers regain egress immediately; `allow-egress` still carries no
  blanket rule, so re-apply the export if unrestricted egress is genuinely
  needed for diagnosis, and treat that as a temporary, recorded exception.

- **Undo everything.** `kubectl delete namespace flux-system` is **not
  sufficient**: 13 of this bundle's objects are cluster-scoped and survive it.
  Remove them explicitly, and in this order:

  ```sh
  kubectl delete namespace flux-system
  kubectl delete clusterrolebinding cluster-reconciler-flux-system \
    crd-controller-flux-system
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

  (Each of those carries the same `--kubeconfig`/`--context`/`--server` binding
  as every other command in this runbook; it is elided above only so the object
  lists stay readable.) Deleting the namespace while Flux owns no resource
  destroys nothing else — there are no Flux custom resources, no finalizers on
  foreign objects, and no workload under Flux management. Deleting the CRDs
  would delete any Flux custom resource of those kinds; there are none, which is
  exactly what step 3 verified. Re-running steps 0–4 restores the same state
  from the same reviewed commit.

Neither rollback touches the websites. They are served by their tunnels
independently of whether Flux exists.

## What stays suspended, and what a suspend flip requires

Nothing in this ceremony changes any `suspend` field, and this ceremony never
applies an object that carries one. After it completes, the repository's
reconciliation objects are still exactly as committed:
`kubernetes/reconciliation/*.yaml` and the site releases under
`kubernetes/websites/` remain `suspend: true`, and the site releases still
carry their all-zero digest and `deploymentReady` sentinels.

Flipping any of them is a **separate reviewed pull request**, and it has
prerequisites this runbook does not satisfy:

1. The controllers are installed and healthy — steps 2–3 above, evidenced.
2. `flux-system` egress is closed and verified — steps 2, 4, and 5 above,
   evidenced, on a CNI that actually enforces policy.
3. **The admission decision is made explicitly.** Kyverno is not installed:
   [`kubernetes/reconciliation/admission.yaml`](../../kubernetes/reconciliation/admission.yaml)
   is `suspend: true` and annotated
   `suspended-until-reviewed-kyverno-artifact-digests-rbac-and-runtime-evidence`,
   and the controller manifest still carries an all-zero image digest. So the
   image-signature, restricted-workload, and tenant-networking policies under
   `policies/kyverno/` are **not enforced at admission** — they are proven only
   by `kyverno test` in CI against fixtures. Whatever Flux applies after a
   suspend flip is therefore admitted without those webhooks. That is a
   decision to take on the record — install admission first, or flip with the
   gap named and accepted — and it is not a blocker for the inert install,
   which admits nothing because it reconciles nothing.
4. The `sops-age` ceremony in [`bootstrap/flux/README.md`](../../bootstrap/flux/README.md),
   for any layer that consumes a SOPS-encrypted Secret.

A green render, a healthy controller, and a closed namespace are all evidence.
None of them is authorization: the owner alone decides that a suspend flip
happens, and the owner alone merges the pull request that performs it.
