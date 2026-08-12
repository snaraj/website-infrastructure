# Flux controller install — Draft / unverified

Current status is `NO-GO`. Nothing in this runbook authorizes a live
installation. It exists so that when installation *is* authorized, it is an
apply of reviewed bytes from an exact reviewed commit rather than an ad-hoc
command — and so that the review of those bytes can happen now, in a pull
request, instead of at the terminal.

**Scope.** Installing the three pinned Flux controllers as an *inert* control
plane, then closing `flux-system` egress. Out of scope, deliberately and by
separate authorization: the `sops-age` ceremony, the root sync objects, and
every `suspend` flip. Those are
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

## Preconditions

Platform-lane preconditions, none of which this runbook performs or asserts:

1. The cluster is initialized and its API server is reachable from the
   protected operator workstation.
2. A CNI that **enforces `NetworkPolicy`** is installed. The deployment-state
   table in [`README.md`](../../README.md) records the current decision and its
   install state; a CNI without policy enforcement makes step 4 desired state
   with no effect, which must not be mistaken for a closed namespace.
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

## Step 0 — plan

From a clean checkout of the exact reviewed `main` commit, on the operator
workstation, with the `versions.env` pins of `kustomize` and `kubectl`:

```sh
./scripts/install-flux-controllers.sh --plan
```

This renders the install root, refuses it if it contains any Flux custom
resource, any Secret, or any NetworkPolicy egress rule, refuses it unless
`flux-system` enforces restricted Pod Security, and requires exactly 25 objects.
It then runs a read-only **pre-apply gate** — a client-side strict validation of
all 25 objects, an existence probe of the objects the install creates, and a
**server-side dry run** — and refuses if any of them names anything outside the
reviewed controller inventory. It prints the render's SHA-256 and mutates
nothing.

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
was expected, or any genuine error — fails the gate closed, and nothing is
applied.

Record the printed digest with the commit SHA. A digest that does not reproduce
means the tree, the tool, or the commit is not the reviewed one, and the
ceremony stops. `scripts/ci/verify-render-determinism.sh` already proves in CI
that renders are byte-identical, so a mismatch is a fact about the operator's
inputs, never about the renderer.

## Step 1 — apply the controllers

```sh
./scripts/install-flux-controllers.sh --apply
```

Same guards, then the apply. Note what the script does *not* do: it never runs
`kubectl apply -k`, because `kubectl`'s embedded Kustomize is a different build
than the pinned one, so `-k` would apply bytes nobody rendered and nobody
hashed.

## Step 2 — verify the controllers, and verify they are idle

```sh
kubectl -n flux-system get deploy source-controller kustomize-controller helm-controller
kubectl -n flux-system get pods
kubectl get crd | grep toolkit.fluxcd.io
kubectl get gitrepositories,kustomizations,helmreleases,ocirepositories -A
```

Expected: three Deployments `1/1`, three Pods `Running`, the CRDs present, and
the **last command returns no resources in any namespace**. A Flux custom
resource at this point means something outside this ceremony created it; stop
and investigate before continuing.

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

## Step 3 — the API-server allow, from private custody

The controllers reach the API server at the control-plane node's own address.
That address is host inventory: safety invariant 12 keeps it out of this public
index permanently, so the committed policy
[`kubernetes/flux-system/egress/network-policies.yaml`](../../kubernetes/flux-system/egress/network-policies.yaml)
carries the reviewed *shape* — these Pods, TCP 6443, one exact `/32` — with
`192.0.2.0/32` (RFC 5737 TEST-NET-1) as its fail-closed sentinel destination.
An address that can never match anything real is the point: applied as
committed, the policy grants nothing.

Before step 4, produce the substituted copy **inside the protected root** —
never in the checkout, never in shell history:

```sh
umask 077
kustomize build kubernetes/flux-system/egress \
  | sed "s#192\.0\.2\.0/32#${CONTROL_PLANE_ADDRESS}/32#" \
  >"$PROTECTED_ROOT/flux-egress.yaml"
grep -c '192\.0\.2\.0/32' "$PROTECTED_ROOT/flux-egress.yaml"   # must print 0
```

`CONTROL_PLANE_ADDRESS` comes from the protected kubeconfig's reviewed server
value, not from a lookup. The substituted file is applied in step 4 and then
deleted; it never enters Git, CI, chat, or a shared clipboard.

If the substitution is skipped, step 4 still closes the namespace and the
controllers lose the API server. That failure is safe — nothing is reconciling
— and it is recovered by the rollback below, but it is not a state to leave
behind.

## Step 4 — close the namespace

```sh
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" apply -f "$PROTECTED_ROOT/flux-egress.yaml"
shred -u "$PROTECTED_ROOT/flux-egress.yaml"
```

This applies, in one document: `default-deny` for the namespace, then the four
enumerated allows — cluster DNS, the intra-namespace artifact fetch, public
HTTPS on TCP 443, and the API server on TCP 6443. Nothing else is reachable
from a `flux-system` Pod afterward: not the LAN, not the node, not another
namespace, not plain HTTP.

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

The blanket allow that upstream ships is already gone at this point. Step 1
applied `allow-egress` with its `egress: [{}]` rule removed by
[`kubernetes/flux-system/controllers/patches/allow-egress.yaml`](../../kubernetes/flux-system/controllers/patches/allow-egress.yaml),
so the namespace never has a window in which every Pod can reach everything.

## Step 5 — verify the closure

```sh
kubectl -n flux-system get networkpolicies
kubectl -n flux-system get networkpolicy allow-egress -o yaml   # no `egress:` key
kubectl -n flux-system get pods
kubectl -n flux-system logs deploy/source-controller --tail=50
```

Expected: eight policies (`allow-egress`, `allow-scraping`, `allow-webhooks`
from the export; `default-deny` and the four `flux-controllers-*` allows from
this step), `allow-egress` carrying no `egress` key, three Pods still `Running`
and not restarting, and controller logs free of API-server connection errors.

Pods that begin restarting here mean the API-server allow does not match the
real endpoint — step 3 was skipped, or the address was wrong, or the installed
CNI evaluates the policy against a destination other than the one substituted.
Roll back, correct, reapply.

## Rollback

Safe at every step, because nothing is reconciling.

- Undo the closure only: `kubectl -n flux-system delete networkpolicy
  default-deny flux-controllers-dns flux-controllers-artifacts
  flux-controllers-public-https flux-controllers-kube-apiserver`. The
  controllers regain egress immediately; `allow-egress` still carries no
  blanket rule, so re-apply the export if unrestricted egress is genuinely
  needed for diagnosis, and treat that as a temporary, recorded exception.
- Undo everything: `kubectl delete namespace flux-system`. Deleting the
  namespace while Flux owns no resource destroys nothing else — there are no
  Flux custom resources, no finalizers on foreign objects, and no workload
  under Flux management. Re-running steps 1–4 restores the exact same state
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

1. The controllers are installed and healthy — steps 1–2 above, evidenced.
2. `flux-system` egress is closed and verified — steps 3–5 above, evidenced,
   on a CNI that actually enforces policy.
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
