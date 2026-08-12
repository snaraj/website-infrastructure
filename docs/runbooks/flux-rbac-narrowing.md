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
   that carries no wildcard, no cluster-wide Secret read, and no
   `serviceaccounts/token` creation
   (`.../patches/crd-controller-role.yaml`);
3. pins that binding's subjects to the three installed controllers
   (`.../patches/crd-controller-binding.yaml`);
4. adds the namespaced authority the controllers still need — leader election,
   controller-owned ConfigMaps, the SOPS age key read, and one name-restricted
   impersonation Role per namespace holding reconciler accounts
   (`kubernetes/flux-system/access.yaml`);
5. corrects both site release reconcilers from `gitrepositories` to
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
default context. Every command here is a read: `auth can-i` issues a
SubjectAccessReview and changes nothing.

After applying the narrowed authority (step 2 below) and before deleting the
broad binding (step 3), confirm each row. The first block must all answer `yes`,
the second block must all answer `no`. While the broad binding is still present
the second block will answer `yes` — that is the point of running the sweep
again after the deletion.

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
    auth can-i create leases.coordination.k8s.io -n flux-system \
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

## Procedure

1. **Confirm the gate below is fully satisfied and the owner has said go.**
   Confirm the controllers are the reviewed digests and the reconciliation is
   still inert: every Flux object suspended, and the ones that are not
   (`flux-system`, `platform-prerequisites`) reconciling only objects this
   change has already proven authorized.
2. **Apply the narrowed authority, additively.** Apply `access.yaml` and the
   narrowed `crd-controller-flux-system` ClusterRole and its subject-pinned
   binding. Nothing is removed in this step, so the controllers gain authority
   and lose none. Run the "must be yes" block above; every row must answer
   `yes`.
3. **Delete the broad binding.** Remove the `cluster-reconciler-flux-system`
   ClusterRoleBinding — the deletion is the whole migration, and it is the only
   destructive action in this runbook. It removes no object the controllers own
   and interrupts no workload: the connectors, both sites, and every Pod on the
   cluster are untouched, because no running workload authenticates as a Flux
   controller.
4. **Prove the removal.** Run the "must be no" block; every row must now answer
   `no`. Then run `bootstrap/flux/bootstrap.sh --verify`, which compares live
   ServiceAccounts, Roles, RoleBindings, ClusterRoles, and ClusterRoleBindings
   against the reviewed model and fails on any drift — including a
   `cluster-reconciler-flux-system` that is still present, or any other binding
   that reaches a protected account.
5. **Prove reconciliation still works, without unsuspending anything.** Force a
   reconcile of the already-unsuspended `platform-prerequisites` Kustomization
   and require it to reach Ready with no RBAC condition. Its objects are the
   NetworkPolicies, ResourceQuotas, and LimitRanges the sufficiency proof
   covered, so a green result exercises the impersonation path end to end. Leave
   every suspended object suspended: unsuspending is a separate, separately
   gated decision.

## Rollback

Re-create the deleted binding from the pre-change generated export and the
controllers are back to their previous authority immediately; RBAC is evaluated
per request, so there is no restart, no drain, and no workload impact in either
direction. Keep the narrowed Roles in place while rolling back — they grant a
subset of what the broad binding grants, so their presence changes nothing, and
removing them would make a second attempt start from scratch.

If step 5 fails, the cause is a missing grant, and the failing Kustomization
names the exact resource and verb in its status condition. Add it to
`access.yaml` or to the narrowed ClusterRole through a reviewed change, not with
a live `kubectl` edit: a grant that exists only on the cluster is invisible to
the sufficiency proof and will be reverted by the next verify.

## Gate

This apply is deferred and stays deferred until ALL of the following hold:

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
