# Protected Flux RBAC convergence transaction

This directory contains the closed, one-time rescue transaction for converging
an existing Flux installation to the reviewed RBAC model. It is operator
tooling, not a generic installer, a Kubernetes workload, or a Flux-reconciled
path. After its terminal state is proved, this directory is historical evidence
only: never reuse, generalize, or treat it as a template for later migrations.

Never execute `transaction.py` from a checkout. The program rejects that use.
The only live program is the exact released blob installed as the root-owned
launcher:

```text
/usr/local/sbin/website-infrastructure-flux-rbac-convergence
```

Every mode invocation in this runbook deliberately spells out the complete
process boundary: `sudo /usr/bin/env -i`, `LC_ALL=C`, only that mode's allowed
environment variables, `/usr/bin/python3 -I -B`, and the fixed launcher path.
Do not shorten that boundary, execute the launcher through its shebang, add
`PATH`, `HOME`, or another variable, or substitute a shell alias or checkout
path. The program rejects any different executable, interpreter, flags, or
environment.

The owner must attend every `sudo` boundary. Do not give the launcher a shell
alias, a mutable default kubeconfig, GitHub credentials, or a Kubernetes Secret.
It uses public GitHub API reads and a separately prepared, root-only,
credential-bearing kubeconfig held by descriptor. Do not print, commit, or copy
that kubeconfig during review.

## Closed scope

The plan has exactly 23 ordered target operations:

- six per-controller ClusterRoles and ClusterRoleBindings;
- the shared `crd-controller-flux-system` ClusterRole and ClusterRoleBinding;
- deletion of the captured legacy `cluster-reconciler-flux-system` binding;
- the `flux-controller-runtime` Role and RoleBinding;
- five active-path objects in each of `naranjo-online` and `lidersea-com`;
- the reviewed argument sets for `kustomize-controller` and
  `helm-controller`, including
  `--feature-gates=DisableConfigWatchers=true`.

The deleted broad binding is one of those 23 targets, so a committed terminal
inventory has 22 present rows and that one absent row. A rolled-back terminal
inventory has the original present/absent shape.

Controller runtime readiness binds image identity through the reviewed
tag-at-digest Deployment image, the byte-equal Pod spec image, and the
repository/digest-checked `imageID`. The runtime-reported
`containerStatuses[].image` remains required as a nonempty string of at most
4096 characters, but its runtime-selected representation is not parsed as or
equated to image identity.

Raw Kubernetes collection items may omit per-item `apiVersion` and `kind`.
For the four Helm-owned workload kinds, the transaction restores that TypeMeta
on copies from each already closed kind/path mapping before semantic hashing.
It does the same for the fixed ClusterRoleBinding and RoleBinding collection
paths using only `rbac.authorization.k8s.io/v1`. Present conflicting TypeMeta,
an unknown site kind, or a missing/extra owned object still fails closed.

It also makes and restores one collision-free `commonMetadata` annotation on
the existing naranjo HelmRelease as a journaled runtime proof. The final state
must match the captured HelmRelease semantics and the accepted workload
baseline.

The transaction never reads or applies
`kubernetes/flux-system/access.yaml`. It does not install Flux, reconcile its
own controller or RBAC path, create dormant identities, read Secret contents,
bootstrap website GitOps objects, or touch Cloudflare. Do not substitute
`kubectl apply`, a render, or all of `access.yaml` for any phase.

## Closed OCI-to-Helm chain

The live Flux inventory is closed, not sampled. Bucket, ExternalArtifact,
GitRepository, HelmChart, HelmRepository, and Kustomization inventories must
each be empty. Exactly these two source/release identity pairs may exist:

- `naranjo-online/naranjo-online-chart` OCIRepository to
  `naranjo-online/naranjo-online` HelmRelease;
- `lidersea-com/lidersea-com-chart` OCIRepository to
  `lidersea-com/lidersea-com` HelmRelease.

For each pair, the OCIRepository must have the exact credentialless,
same-site, Cosign-verified spec in the custodied transaction implementation.
Its current generation must be `Ready=True` and `SourceVerified=True`, both with
`reason=Succeeded`. At plan time, the artifact revision supplies the exact
canonical release SemVer and nonzero upstream `sha256:` digest. The version
must satisfy the source's exact `>=0.1.9 <1.0.0` range; prerelease, build,
noncanonical, and out-of-range versions fail closed. The stored artifact digest
is captured separately. The HelmRelease must use only
`chartRef.kind=OCIRepository` and the same namespace's `<site>-chart`, with the
exact release name,
`helm-reconciler` ServiceAccount, and inline
`values={"deploymentReady":true}`. Its attempted
revision digest must equal the OCI upstream digest, and its attempted revision
must be `<version>+<first-12-upstream-digest-hex>`. The latest Helm history
entry must be deployed for that revision. Its status inventory must contain
exactly one same-namespace Deployment, Service, ServiceAccount, and
NetworkPolicy, and those four identities must equal the live Helm-owned
workload inventory. Any missing, extra, cross-site, stale, suspended,
terminating, unverified, or digest-disconnected object stops the transaction.
The immutable plan records each derived version, source revision, upstream
digest, stored digest, and matching Helm status. Any chart movement after plan
creation changes that baseline and stops apply or verification; it cannot be
reinterpreted through the existing plan.

## Immutable bindings

The protected plan fails closed unless all of these agree:

- the signed protected-`main` merge commit and its single associated PR;
- the signed PR head and owner merge identity;
- the exact successful required main CI and CodeQL job receipt;
- the later successful platform-release workflow;
- an annotated immutable platform tag and its peeled commit;
- the GitHub Release tag, target commit, title, body, and publication order;
- every custodied file's SHA-256 and Git blob in the protected source tree;
- the root-owned Python interpreter and architecture-pinned `kubectl` bytes;
- the held kubeconfig bytes, context, API server, CA, `kube-system` UID, and
  single node name/UID tuple;
- every touched object's captured UID, resourceVersion, and semantic prestate;
- the exact canonical plan bytes and the owner-reviewed plan SHA-256.

This one-time executable authorizes exactly platform tag `v0.1.31`, the next
release after its reviewed `v0.1.30` protected base. `target.json` cannot select
another otherwise-valid SemVer tag. If protected `main` advances before this
candidate merges, stop and regenerate the candidate, tag binding, source
manifest, tests, and review receipts together; do not reinterpret this blob for
the later release.

`--plan` and `--apply` require the selected release commit to remain the tip of
protected `main`. A later `--verify` accepts only a protected-main descendant of
that immutable commit; it does not reinterpret a newer release as this
transaction's source. A moved, lightweight, partial, conflicting, unpublished,
or arbitrary tag is rejected.

## Private target input

[`target.example.json`](target.example.json) documents the exact field set. Its
placeholders intentionally fail target validation and must never be installed
unchanged. Prepare a new local `target.json` through the owner-controlled
read-only ceremony, then install it as:

```text
/var/lib/website-infrastructure/flux-rbac-convergence-v0.1.31/input/target.json
owner: root:root
mode: 0600
```

Keep the real file and its values out of Git, issues, pull requests, receipts,
and terminal transcripts. Its fields mean:

- `releaseTag`: exactly `v0.1.31`, whose immutable platform Release targets the
  same source revision staged into custody;
- `kubectl`: an absolute path to the reviewed Linux executable whose
  architecture-specific digest is pinned by the custodied `versions.env`;
- `kubeconfig`: an absolute path to one flattened JSON kubeconfig with one
  cluster/context, embedded CA and credentials, no external file or exec
  references, root ownership, and mode 0600;
- `context` and `server`: the exact private tuple independently reviewed by the
  owner;
- `kubernetesCaSha256`: SHA-256 of the decoded DER CA certificate;
- `kubeSystemNamespaceUidSha256`: SHA-256 of the ASCII namespace UID followed
  by one newline;
- `nodeIdentitySha256`: SHA-256 of the single node name, newline, node UID, and
  final newline.

The raw server, context, UIDs, node name, kubeconfig digest, and target hashes
are private operational evidence. The transaction records hashes rather than
publishing the tuple. Derive them with the separately reviewed read-only target
ceremony; do not query or expose Secret data to populate this file.

## Root custody and stage zero

Protected state lives under
`/var/lib/website-infrastructure/flux-rbac-convergence-v0.1.31`, with root ownership and
mode 0700 directories. Plans, journals, receipts, the private target, and
custodied source files are mode 0600 except for both the mode-0700 custodied
transaction blob and its mode-0700 installed launcher copy.

### Maintenance freeze

The owner starts a maintenance freeze before taking held-descriptor custody
and keeps it in force until one terminal state has been proved by `--verify`:
either committed or rolled back. Throughout that interval, make no out-of-band
change to the installed launcher, `/usr/bin/python3`, the selected `kubectl`,
the flattened kubeconfig or its credentials, the Kubernetes CA, any private
target identity, or `target.json`. Do not run apt or another package/OS upgrade.
Do not reboot the operator or target host. Do not publish either site or
move/repoint either site's OCI tag. Outside the exact transaction modes below,
do not mutate a controller, RBAC object, or Flux object, change host WireGuard
configuration, trigger a routine Flux reconcile, or attempt a manual `kubectl`
repair.

The launcher detects many resulting identity or baseline changes, but this is
an operator freeze, not a claim that every prohibited host or registry change
is observable. If any prohibited change occurs or its absence cannot be
established, stop. Do not apply, replan, retry forward, edit the journal, or
repair with `access.yaml`. Preserve custody, plan, journal, receipts, and live
state and use an owner-reviewed recovery decision. If a safely attributable
nonterminal journal exists, that decision may authorize the exact rollback
mode below; ambiguity remains a stop.

### Exact v0.1.30 recovery

The sole exception is `--recover-v030`, which exists only for the authenticated
v0.1.30 plan stopped at journal sequence 47 after Naranjo moved from chart
0.1.42 through exactly three sequential protected releases ending at 0.1.45.
It accepts no other plan, incident, release movement, site, controller change,
or unrelated drift. It reuses the v0.1.30 journal's existing crash-safe
rollback and terminal receipt machinery, restores the original verifier even
on failure, and stops after publishing both the old rolled-back receipt and a
root-only v0.1.31 receipt binding the recovery release, terminal journal, exact
chart/image movement, and custody hashes.
Run it once through the same isolated root process boundary with only `LC_ALL=C`
and `CONFIRM_FLUX_RBAC_RECOVERY=recover-v030-<reviewed-old-plan-sha256>-with-<v0.1.31-peeled-commit>`.
Only after `RECOVERED_V030` may the owner prepare and review a fresh v0.1.31
plan; the recovery mode never plans or applies forward state.

The transaction deliberately cannot establish trust in the first copy of
itself. Before `--stage`, the owner must:

1. independently verify the exact protected-main source revision, annotated
   tag, GitHub Release, required CI, and registered signature;
2. open the released `transaction.py` blob through a held, no-follow descriptor,
   verify its digest against both `source-manifest.v1` and the reviewed release,
   and install those held bytes at the fixed launcher path as root:root 0700;
3. resolve and review the root-owned Python executable digest without changing
   interpreters between staging and execution;
4. keep the exact released source tree unchanged and available at one absolute,
   non-symlink path until held-descriptor staging completes.

Do not install by reopening a mutable checkout path after review. Do not run the
checkout copy with `sudo`. The stage ceremony copies each manifest-listed blob
through a stable descriptor, checks its declared digest and mode, fsyncs the
private tree, and records the source revision, manifest, launcher, Python, and
complete custody-tree digests. `--plan` then binds those bytes to Git blobs in
the protected commit using credential-free public GitHub reads.

Do not change the source checkout while the held-descriptor stage is in
progress. Only after the command prints `STAGED` and the root custody receipt
has been validated may the checkout change. From that point onward the checkout
is neither input nor authority: the root-owned custody tree and its receipt are
the only local source authority, and no later mode may reopen, refresh, or
restage from the checkout.

From an interactive owner-attended root boundary, stage exactly once. Values
below are metavariables, not values to paste literally:

```sh
sudo /usr/bin/env -i LC_ALL=C \
  FLUX_RBAC_SOURCE_ROOT='<absolute-reviewed-release-tree-path>' \
  FLUX_RBAC_SOURCE_REVISION='<40-lowercase-hex-protected-merge-commit>' \
  FLUX_RBAC_MANIFEST_SHA256='<64-lowercase-hex-manifest-digest>' \
  FLUX_RBAC_LAUNCHER_SHA256='<64-lowercase-hex-launcher-digest>' \
  FLUX_RBAC_PYTHON_SHA256='<64-lowercase-hex-interpreter-digest>' \
  CONFIRM_FLUX_RBAC_CUSTODY='stage-reviewed-flux-rbac-<source-revision>-<manifest-digest>' \
  /usr/bin/python3 -I -B \
  /usr/local/sbin/website-infrastructure-flux-rbac-convergence --stage
```

The launcher requires a TTY and prints only `STAGED` on success. Repeating
`--stage` accepts an existing custody tree only when those root-owned bytes
validate against the exact supplied source, manifest, launcher, and Python
bindings; it can durably republish the matching receipt after an interrupted
post-rename stage. Any partial, foreign, mutable, or conflicting custody stops
the ceremony.

## Plan and owner review

Install the privately prepared `target.json` only after successful staging.
Then run the fixed launcher, with no checkout environment:

```sh
sudo /usr/bin/env -i LC_ALL=C \
  /usr/bin/python3 -I -B \
  /usr/local/sbin/website-infrastructure-flux-rbac-convergence --plan
```

`--plan` is read-only against Kubernetes. It revalidates public release
identity and root custody, binds the exact tools and target, captures a
redacted semantic inventory, and writes a mode-0600 `plan.json`. It refuses an
existing journal and prints one `PLAN_SHA256=<64-lowercase-hex>` line. The plan
expires after 24 hours for apply; expiry never removes rollback authority.

The owner and reviewers must inspect the root-only plan without copying private
tuple or UID evidence into GitHub. Review at least:

- the one release/source identity and source-bundle digest;
- tool, kubeconfig, and hashed target bindings;
- exactly 23 operations in the recorded order;
- all captured UID/resourceVersion and semantic prestate;
- the six split objects initially absent and the broad binding present;
- only the two active site namespaces in the namespaced inventory;
- exact desired semantic hashes and controller argument sets;
- controller images, arguments, readiness, Pod UIDs, and restart baselines;
- the closed zero inventories plus exactly two site OCIRepositories and two
  HelmReleases, including the complete OCI-to-Helm digest/revision/history/
  inventory chain above, their workloads, and public HTTP health;
- no unexpected binding reaching a tracked controller or site reconciler.

Do not edit `plan.json`. Drift, a wrong target, an expired plan, or a changed
review conclusion is a stop, not permission to replan. The canonical plan is
immutable once published: do not delete, replace, regenerate, or overwrite it,
and do not rerun `--plan` to reinterpret drift. The implementation provides no
plan-delete, plan-overwrite, or same-transaction replan path. Recovery requires
an owner-reviewed decision and, when forward work remains appropriate, a new
reviewed transaction release and custody ceremony rather than reuse of this
plan.

### Declared actions and semantic no-ops

All 23 target rows remain in the immutable operation order. The six split
objects are required absent and retain `action=create`; the broad binding is
required present and retains `action=delete`. Each of the 12 namespaced rows is
declared `converge`: an absent object is created, a present differing object is
replaced under its captured identity, and an exact semantic match is planned as
`action=noop`. Each controller argument row is `args` or `noop`, and each
shared RBAC row is `replace` or `noop`, using the same semantic comparison.

A no-op is not omitted. Apply journals its intent, rereads the exact captured
UID, resourceVersion, prestate semantic hash, and desired semantic hash, and
commits the journal record without an API mutation. Review `declaredAction`,
effective `action`, prestate presence, and desired hash for every row; never
turn a no-op into an ad-hoc apply or turn a planned action into a no-op by
editing the plan.

## Apply, one verified phase at a time

Only the owner supplies the exact plan acknowledgment after review:

```sh
sudo /usr/bin/env -i LC_ALL=C \
  FLUX_RBAC_EXPECTED_PLAN_SHA256='<plan-sha256>' \
  CONFIRM_FLUX_RBAC_APPLY='apply-reviewed-flux-rbac-<plan-sha256>' \
  /usr/bin/python3 -I -B \
  /usr/local/sbin/website-infrastructure-flux-rbac-convergence --apply
```

Before the first mutation, `--apply` rechecks the plan digest and freshness,
source Release, protected-main tip, CI receipts, custody, tools, target tuple,
every live prestate, and stable controller/Flux/workload baselines. It then
creates a durable, fsynced journal before executing these boundaries:

1. create the six split RBAC objects;
2. converge only the 12 closed active-path namespaced objects;
3. prove controller health, unchanged Flux/workloads, owned positive controls,
   and tenant isolation before authority removal;
4. update and roll out kustomize-controller, then helm-controller, only when
   their exact reviewed argument sets differ;
5. replace the shared ClusterRole and binding, then prove the mixed
   cross-controller authorization matrix and source canary;
6. delete only the captured broad binding UID/resourceVersion, then prove the
   final binding graph, owned controls, cross-controller denials, and
   cluster-wide Secret read denials;
7. perform and restore the one plan-bound HelmRelease annotation proof;
8. remove transaction annotations, prove exact final semantics and health, and
   write the PASS receipt.

The authorization evidence is an exact phase matrix, not an illustrative
sample:

| Recorded evidence | Boundary and required matrix | Exact receipts |
|---|---|---:|
| `pre-shared` | after split and namespaced convergence, before watcher/shared changes: 42 startup/informer allows, nine owned allows, all 18 crossing allows, and 32 tenant local-read allows plus foreign/read-write denials | 101 |
| `mixed` | after watcher handling and shared replacement, before broad deletion: the same 42 startup/informer and nine owned allows; seven source-controller crossings deny while the remaining 11 crossings still allow | 69 |
| `final` | after broad deletion: 42 startup/informer and nine owned allows; all 18 crossings deny; 40 tenant impersonation/local-read/isolation checks and 16 cluster-Secret/general forbidden denials | 125 |
| `post-proof-final` | after the Helm proof is restored and transaction annotations are removed: rerun the exact `final` matrix | 125 |
| `rollback-terminal` | after rollback: the nine owned rows and all 18 crossing rows return to `ALLOWED` | 27 |

Each row is retained only after its exact request echo, resolved discovery,
phase-expected authorization result, two allowed controls, inert denied
control, and `PASS` result validate. A missing, extra, duplicate, oversized,
unresolved, or differently classified receipt invalidates the whole phase.
The committed `--verify` reruns 125 final receipts; rolled-back `--verify`
reruns 27 rollback receipts. Each fresh receipt-set digest must equal the
corresponding journaled terminal digest.

Every mutation has a journaled intent and uses captured UID/resourceVersion
preconditions. Creates are attributed by the transaction marker and returned
UID. Semantic no-ops remain no-ops. A warning, concurrent change, unexpected
object, failed rollout, unresolved authorization result, restart, release or
workload drift, or public-health failure stops the forward path.

Success prints `PASS`. That token is not enough by itself. Before the journal
becomes committed, the transaction captures terminal evidence consisting of
the exact final binding graph, the `post-proof-final` authorization evidence
record, and a 23-row target inventory in immutable operation order. For each
present row the inventory binds target ID, UID, current resourceVersion, and
semantic SHA-256; the deleted broad-binding row is exactly `{id, present:
false}`. The terminal evidence and its digest are journaled before the PASS
receipt is published. Retain the root-only PASS receipt, journal, plan, oracle
evidence files, and later `--verify` record for the issue. Publish only redacted
hashes and conclusions.

## Interruption recovery and rollback

SIGINT, SIGTERM, SIGHUP, or a normal phase failure triggers automatic rollback
after the journal exists. Abrupt process or host loss leaves the fsynced intent
and operation records for the owner to classify. Never rerun `--apply`, delete
the journal, hand-edit an object, or guess whether the pending operation landed.

Use this state-routing matrix; the journal state and safe attribution decide the
mode, not the last terminal token seen:

| Classified state | Only valid next action |
|---|---|
| `committed`, including a missing/incomplete PASS publication | run `--verify`; never roll back or apply |
| `rolled-back`, including a missing/incomplete rollback publication | run `--verify`; never apply |
| safely attributable `prepared` or `recovery-required` nonterminal journal | after owner review, run the exact `--rollback` command once |
| ambiguous journal, pending effect, identity, UID/resourceVersion, semantics, marker, or live state | stop; preserve everything and use owner-reviewed recovery; do not invoke a mutating mode |

Do not use `--verify` to classify a nonterminal journal: it returns
`RECOVERY_REQUIRED`. Do not use `--rollback` against a committed journal: the
launcher directs that state to verification. A rolled-back `--rollback` can
only reproduce its terminal receipt; terminal evidence still requires
`--verify`.

Run explicit recovery with the original plan hash and an owner-reviewed
rollback acknowledgment:

```sh
sudo /usr/bin/env -i LC_ALL=C \
  FLUX_RBAC_EXPECTED_PLAN_SHA256='<plan-sha256>' \
  CONFIRM_FLUX_RBAC_ROLLBACK='rollback-reviewed-flux-rbac-<plan-sha256>' \
  /usr/bin/python3 -I -B \
  /usr/local/sbin/website-infrastructure-flux-rbac-convergence --rollback
```

Rollback remains available after plan expiry and does not depend on GitHub
availability. It rebinds local custody, tools, target, plan, and journal. If the
broad binding deletion began, rollback restores its captured semantics first;
it then restores the shared objects and controller Deployments before reversing
remaining namespaced and split operations. A started Helm proof is restored
under its journaled UID/resourceVersion boundary. It removes only attributable,
exact transaction-created objects and verifies the complete prestate and
authorization graph.

If live identity or semantics cannot be attributed safely, the launcher prints
`RECOVERY_REQUIRED` and does not overwrite or delete the ambiguous object.
Automatic apply recovery also attempts to journal that state and publish a
recovery-required receipt; do not assume an explicit rollback failure could
publish one. Preserve all state and escalate to review; do not use
`access.yaml` or manual `kubectl apply` as recovery.

A successful rollback journals terminal evidence before publishing its
receipt: the exact restored binding graph, the 27-receipt `rollback-terminal`
record, and a 23-row target inventory. Every originally absent target is
recorded absent. Every originally present target is recorded with restored
semantics and current resourceVersion; unchanged objects retain their captured
UID, while a safely recreated broad binding is bound to its journaled restored
UID. This terminal inventory is not optional cleanup evidence.

## Verify a terminal result

Verification always uses the original plan hash:

```sh
sudo /usr/bin/env -i LC_ALL=C \
  FLUX_RBAC_EXPECTED_PLAN_SHA256='<plan-sha256>' \
  /usr/bin/python3 -I -B \
  /usr/local/sbin/website-infrastructure-flux-rbac-convergence --verify
```

For a committed journal, `--verify` rechecks the immutable release ancestry and
all local bindings, reruns the 125-receipt final authorization, semantic,
controller, Flux/workload, binding-graph, public-health, and 23-target inventory
proofs, and reproduces the bound PASS receipt. For a rolled-back journal, it
reruns the 27-receipt rollback matrix, proves the original semantic and UID
prestate plus authorization graph and terminal inventory, and reproduces the
rollback receipt. It writes a new immutable, monotonically numbered,
hash-chained verification record bound to the terminal receipt and fresh
evidence. The fresh 23-row inventory must preserve IDs, presence, UIDs, and
semantic hashes; resourceVersions are recaptured and may advance, so they are
not used as a false equality claim against the terminal snapshot. A
nonterminal or ambiguous journal returns `RECOVERY_REQUIRED`.

Keep the maintenance freeze in force until this command succeeds for the
classified terminal state. A `PASS` printed for a committed or rolled-back
verification is interpreted through its record's `result` and `journalState`,
not as permission for any new mutation.

`--verify` is evidence, not permission to start the issue #189 Flux loop,
unsuspend an unrelated object, enable pruning, or delete these protected
records. Retention and eventual cleanup require a separate owner decision after
the durable issue evidence is accepted.
