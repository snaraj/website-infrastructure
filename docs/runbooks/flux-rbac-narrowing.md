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
   (issue #98) — **no Flux API group at all**: what remains is the cluster
   metadata reads, event reporting, and the `/livez/ping` probe that are
   identical for all three controllers
   (`.../patches/crd-controller-role.yaml`);
3. pins that binding's subjects to the three installed controllers
   (`.../patches/crd-controller-binding.yaml`);
4. adds one ClusterRole and ClusterRoleBinding PER CONTROLLER, each bound to a
   single ServiceAccount, carrying that controller's own custom-resource
   authority — `crd-controller-source-flux-system`,
   `crd-controller-kustomize-flux-system`, `crd-controller-helm-flux-system`
   (`kubernetes/flux-system/access.yaml`);
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

That inventory used to be dominated by one residual: `crd-controller-flux-system`
was a single ClusterRole bound to all three controllers, so each held the other
two's write authority over Kustomizations, HelmReleases, and source objects, and
impersonation did not contain it — the victim controller performs the
reconciliation. **That residual is gone (issue #98).** 135 declared-slack rows
described it; 134 of those grants no longer exist, and the one that remains —
helm-controller's `watch` on the HelmChart it creates itself — is re-attributed
to the controller that owns the object rather than to a shared role.
`test_the_declared_slack_is_bounded_and_attributed` now asserts that count is
ZERO and keeps the retired reason string alive precisely so a re-broadened
shared role has to declare itself and fail.

Three properties replace it, each independently enforced:

- the shared role names no Flux API group — checked by
  `scripts/validate_repository.py`, by the Conftest rule over the rendered
  output, and by `test_the_shared_controller_role_grants_no_flux_api_group`;
- each per-controller ClusterRoleBinding names exactly one ServiceAccount and
  binds the role it is named for — same three places;
- every write one controller could make to another's object, including
  `/status` and `/finalizers`, is asserted DENIED, exhaustively from the
  registered-kind matrix rather than by example.

The one kind two controllers legitimately touch is HelmChart, from opposite ends
of one handoff: helm-controller creates and deletes the intermediate chart,
source-controller reconciles it into an artifact. That exemption is declared in
exactly one place in the suite and its size is asserted, so it cannot quietly
grow into a second shared role.

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

After applying the narrowed authority (step 3 below) and before deleting the
broad binding (step 4), confirm each row. The first block must all answer `yes`,
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

    # THE CONFUSED DEPUTY (issue #98), live. Each row is authority one
    # controller held over another controller's execution objects until the
    # per-controller split. Unlike the rows above, these turn `no` at step 3
    # rather than step 4 — the shared role is where they lived, and step 3 is
    # what replaces it — so run this block at BOTH boundaries: every row answers
    # `yes` before step 3 and `no` after it.
    auth can-i patch kustomizations.kustomize.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:source-controller
    auth can-i patch helmreleases.helm.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:source-controller
    auth can-i create helmcharts.source.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:source-controller
    auth can-i patch helmreleases.helm.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i patch ocirepositories.source.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:kustomize-controller
    auth can-i patch kustomizations.kustomize.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:helm-controller
    auth can-i patch gitrepositories.source.toolkit.fluxcd.io -A \
      --as=system:serviceaccount:flux-system:helm-controller

## What each step removes — read this before the procedure

Only one step in this migration is a deletion, but TWO of them remove
authority, and the difference decides what a rollback has to restore.

`crd-controller-flux-system` is patched with a strategic-merge patch that
REPLACES `rules` and `subjects` wholesale. So the moment step 3 applies it, the
live shared ClusterRole loses its wildcard rules, its cluster-wide Secret read,
and `serviceaccounts/token` creation, and the live binding loses four of its
seven subjects. That is a removal, not an addition, and it happens before the
"destructive" step.

Since the per-controller split (issue #98) that replacement patch removes MORE:
the shared role loses every Flux API group as well, and the authority it used to
carry arrives instead as six NEW objects — three ClusterRoles and three
ClusterRoleBindings — that must be applied in the same boundary. Applying the
shared-role patch without them leaves all three controllers unable to reconcile
anything, so the order inside step 3 is not optional: `access.yaml` first, the
shared role and its binding second.

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

NINE objects change across this migration, at two boundaries: three that exist
today and are modified or deleted, and six the split creates (issue #98). Each
boundary has its own verification and its own rollback, and the rollback payload
is frozen before anything is applied.

The asymmetry matters for rollback. The three EXISTING objects are restored from
the frozen capture; the six NEW ones did not exist before the migration, so
rolling back means DELETING them, not restoring them. A rollback that only
re-applies the frozen file leaves six live ClusterRoles and ClusterRoleBindings
granting authority nobody reviewed at that point in the sequence.

1. **Confirm the gate below is fully satisfied and the owner has said go.**
   Confirm the controllers are the reviewed digests and the reconciliation is
   still inert: every Flux object suspended, and the ones that are not
   (`flux-system`, `platform-prerequisites`) reconciling only objects this
   change has already proven authorized.
2. **Freeze the pre-change authorization.** Capture all three EXISTING objects
   as they exist live, with a digest, into operator-held storage — not into this
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

   Then confirm the six objects the split CREATES are absent, so that a later
   rollback deleting them cannot destroy something that was already there:

       kubectl get clusterrole crd-controller-source-flux-system \
         crd-controller-kustomize-flux-system crd-controller-helm-flux-system
       kubectl get clusterrolebinding crd-controller-source-flux-system \
         crd-controller-kustomize-flux-system crd-controller-helm-flux-system

   Every one must report `NotFound`. If any exists, stop: something else owns
   the name, and creating it here would adopt or overwrite it.
3. **Apply the narrowed authority — additive for the Roles and the three
   per-controller ClusterRoles, REPLACING for the shared ClusterRole and its
   binding.** Apply `access.yaml` first: it is purely additive, it creates the
   namespaced Roles and RoleBindings and the three per-controller ClusterRoles
   and ClusterRoleBindings that carry the replacement authority, and applying it
   alone changes no controller's effective permissions downward. Then apply the
   narrowed `crd-controller-flux-system` ClusterRole and its subject-pinned
   binding, which is where authority is removed (see the section above).

   **The order within this step is load-bearing now.** The shared role no longer
   carries any Flux API group, so applying its patch before the per-controller
   roles exist leaves all three controllers unable to list their own custom
   resources — every reconciliation stops, and source-controller has nothing
   masking the loss. Then, at this boundary:
   - run the "must be yes" block; every row must answer `yes`;
   - confirm all three controller Pods are Ready and have not restarted —
     `kubectl -n flux-system get pods` — because a controller that lost leader
     election or its own ConfigMap authority crashloops at startup rather than
     failing a reconciliation;
   - confirm source-controller specifically is still reconciling: the
     `flux-system` GitRepository must stay `Ready=True` with its
     `status.observedGeneration` current and its artifact revision advancing.

   **Rollback at this boundary:** re-apply the frozen ClusterRole and
   ClusterRoleBinding from step 2, AND delete the six objects the split created
   (`clusterrole` and `clusterrolebinding`
   `crd-controller-{source,kustomize,helm}-flux-system`). Nothing else has
   changed yet. Restoring the frozen pair without deleting the six leaves the
   pre-change shared authority and the new per-controller authority live at the
   same time — a superset of both, which is not the state anyone reviewed.
4. **Delete the broad binding.** Remove the `cluster-reconciler-flux-system`
   ClusterRoleBinding. It removes no object the controllers own and interrupts
   no workload: the connectors, both sites, and every Pod on the cluster are
   untouched, because no running workload authenticates as a Flux controller.
5. **Prove the removal.** Run the "must be no" block; every row must now answer
   `no`. Then run `bootstrap/flux/bootstrap.sh --verify`, which compares live
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

Every row restores the three frozen objects **and** deletes the six the split
created. `SPLIT` below is shorthand for those six:
`clusterrole` and `clusterrolebinding`
`crd-controller-source-flux-system`, `crd-controller-kustomize-flux-system`,
`crd-controller-helm-flux-system`.

| Failed at | Restore |
|---|---|
| step 3 (narrowed authority applied) | re-apply the frozen `crd-controller-flux-system` ClusterRole **and** its ClusterRoleBinding from step 2, **then** delete SPLIT |
| step 4 or later (broad binding deleted) | re-create `cluster-reconciler-flux-system` from the frozen capture, **then** re-apply the frozen ClusterRole and its binding, **then** delete SPLIT |
| interrupted anywhere, state unknown | re-apply all three frozen objects and delete SPLIT; together they are the complete pre-change authorization, and both halves are idempotent |

Re-creating the deleted binding alone is **not** a full rollback: it restores
`cluster-admin` for kustomize-controller and helm-controller, and nothing at all
for source-controller, whose pre-change authority lived only in the shared
ClusterRole this migration replaced. Nor is restoring the three frozen objects
without deleting SPLIT: that leaves the pre-change authority and the
per-controller authority live together, a superset of both. Roll back all three
objects and remove all six, then re-run the "must be yes" block plus the
source-controller check from step 3 to confirm the cluster is back where it
started.

Leave the narrowed namespaced Roles from `access.yaml` in place while rolling
back — they grant a subset of what the broad binding grants, so their presence
changes nothing, and removing them would make a second attempt start from
scratch.

If step 6 fails, the cause is a missing grant, and the failing Kustomization
names the exact resource and verb in its status condition. Add it to
`access.yaml` or to the narrowed ClusterRole through a reviewed change, not with
a live `kubectl` edit: a grant that exists only on the cluster is invisible to
the sufficiency proof and will be reverted by the next verify.

**What is not proven here.** Rollback is written from the objects' semantics —
`roleRef` immutability, replace-not-merge patch behaviour, per-request RBAC
evaluation — and from the offline proof above. It has not been exercised against
a failure injected at each boundary, because that requires the cluster this
change is deferred from touching. Exercising it is part of the owner-run apply,
in the order above: each boundary is verified before the next begins, and the
frozen capture from step 2 is what makes any of them reversible.

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
