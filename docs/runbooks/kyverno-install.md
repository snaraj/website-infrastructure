# Kyverno admission install — NO-GO / unverified

This runbook describes a future, bounded validation ceremony. It does not
authorize one. Kyverno is not installed, Flux remains suspended and inert, and
no step here changes a site, tunnel, secret, Cloudflare configuration, route,
host, or Flux suspension.

## STAGE 1 IS **NOT AUTHORIZED**

`render.lock` records `stage.report-only.authorized=no`. The installer reads
that value before resolving a tool, binding a target, reading private network
data, or creating a journal. Therefore `--stage report-only --apply` is
unreachable while either blocker remains:

| Blocker | Required closure |
| --- | --- |
| `#101` | Land and review the real Kyverno CRD/controller export, release and image pins, fresh-CRD ordering, and immutable tool identities. The committed all-zero controller sentinel is not installable. |
| `runtime-network-canary` | Build and review the private selected-CNI contract, cross-check every live Service, endpoint, and control-plane source, then pass the exact pre-controller ServiceAccount/label canary. |

The owner must authorize a later pull request which changes the lock. Editing
the lock at a terminal is not authorization.

## STAGE 2 IS **NOT AUTHORIZED**

`render.lock` independently records `stage.enforce.authorized=no`. Stage 2
inherits every stage-1 prerequisite and remains blocked on:

| Blocker | Required closure |
| --- | --- |
| `#100` | In report-only mode, prove the actual ReplicaSet admission username and the exact live Deployment UID lookup for controller-created and spoofed ReplicaSets. |
| `#101` | Complete the stage-1 component, CRD, tool, and runtime-network prerequisites. |
| `#102` | Bind a full observation window, exact controller rollout state, fresh reviewed-policy reports, webhook inspection, positive and negative admission canaries, interrupt recovery, rollback, and residue evidence to one transaction. |
| `runtime-network-canary` | Transitive from stage 1; the in-cluster API path and every webhook source must be proven before fail-closed admission is considered. |

Finding `#99` is repaired in the committed artifacts: both
`require-signed-*` policies are `Enforce` in stage 2, and the generic
report-only overlay is their only `Audit` downgrade. That repair does not
authorize enforcement.

An enforce apply is prohibited unless all blockers are closed, a fresh
independent review covers the exact head, and the owner separately authorizes
the transition. This document never supplies that authorization.

## Safety model

Admission is unusually hazardous because a registered webhook with
`failurePolicy: Fail` can refuse the writes needed to repair it. Stage 1 is
therefore `Audit` plus `Ignore`; stage 2 is `Enforce` plus `Fail`. Both roots
render the same objects and differ only in action fields.

The install path never applies a webhook configuration. Kyverno registers its
own webhooks only after its CRD, prerequisites, controller network, and
controller readiness gates pass. `kube-system`, `flux-system`, and `kyverno`
remain excluded from interception so admission cannot lock out the control
plane, its reconciler, or itself. `system:nodes` remains filtered too.

Replica count is a capacity and availability choice, never a security
invariant. A dated one-node plan may choose one replica; a future HA plan uses
multiple replicas and failure domains. Promotion instead proves the exact
controller inventory, positive desired replicas, current observed generation,
and `updated == available == desired`, with separately reviewed quota, surge,
and disruption capacity.

The storage policy is not a deny-by-kind boundary. `PersistentVolume`,
`PersistentVolumeClaim`, `StorageClass`, `StatefulSet`, database, CSI, and
operator designs remain extensible when a reviewed change explicitly binds
driver and storage provenance, topology, capacity, exposure, RBAC, network,
backup/restore, and threat controls. Unknown sources remain fail closed.

Git and release tags are exactly `vX.Y.Z`. An OCI reference such as
`image:vX.Y.Z@sha256:<digest>` is valid and must retain its digest.

## Transaction and ordering

The installer classifies every rendered object into exactly one phase:

1. `namespace`
2. `bounds`
3. `network`
4. `crds`
5. `controller-prerequisites`
6. `controller`
7. `policies`

The deny and all required network allows are one phase. Built-in objects receive
strict client validation before any mutation. Kyverno policies cannot be
strictly validated on a fresh cluster until the `clusterpolicies.kyverno.io`
CRD exists, so the apply waits for that CRD to be `Established`, starts a fresh
kubectl discovery process, and strictly dry-runs the policy phase immediately
before applying it. The controller must become Available before policies can
cause runtime webhook registration.

Between controller prerequisites and the controller Deployment, a disposable
Pod uses exactly:

- ServiceAccount `kyverno-admission-controller`;
- the admission-controller `name`, `component`, and `part-of` labels selected by
  the committed NetworkPolicies;
- the digest-pinned `KYVERNO_NETWORK_CANARY_IMAGE`;
- no automounted service-account token; and
- `/agnhost connect --timeout=10s kubernetes.default.svc:443`.

It must succeed, delete, and be proven absent before the controller phase.

## Immutable inputs

The operator target and the controller runtime path are separate contracts.
Never derive a Pod NetworkPolicy peer from the operator kubeconfig endpoint.

The operator exports an exact kubeconfig, context, and API URL:

```sh
export KUBECONFIG="$PROTECTED_KUBECONFIG"
export KYVERNO_INSTALL_CONTEXT="$REVIEWED_CONTEXT"
export KYVERNO_INSTALL_SERVER="$REVIEWED_OPERATOR_API_URL"
```

Every kubectl call names all three, and the installer cross-checks the
kubeconfig. The value is hashed into the transaction journal; it is not copied
into a NetworkPolicy.

The controller reaches `kubernetes.default.svc`. Its contract is a private,
regular, non-symlink mode-0600 file outside the checkout with exactly these
sorted `KEY=value` records and no comments, whitespace, blank values, or extra
keys:

```text
CNI_IDENTITY=<reviewed-selected-cni>
DNS_NAME=kubernetes.default.svc
KUBERNETES_ENDPOINT_CIDRS=<all-current-api-endpoints-as-sorted-/32-set>
KUBERNETES_ENDPOINT_PORT=6443
KUBERNETES_SERVICE_CIDR=<current-kubernetes-service-vip-/32>
KUBERNETES_SERVICE_PORT=443
KUBE_PROXY_MODE=<iptables|ipvs|nftables|ebpf-replacement>
POLICY_DATAPLANE=<service-vip|endpoint>
SCHEMA=website-infrastructure-kyverno-network-v1
WEBHOOK_SOURCE_CIDRS=<all-current-control-plane-internal-ips-as-sorted-/32-set>
```

Set only the path:

```sh
export KYVERNO_RUNTIME_NETWORK_CONTRACT="$PROTECTED_ROOT/kyverno-network.env"
```

The installer parses this as data; it never sources it. It cross-checks the
Service VIP/port, the complete endpoint set/port, and every current control-plane
InternalIP, including HA peers. `POLICY_DATAPLANE` selects either Service VIP
port 443 or the entire endpoint set port 6443 for Pod egress. The separate
webhook ingress rule expands to every control-plane source. Both committed
TEST-NET sentinels and the sentinel port must disappear or the transaction
stops.

Any CNI, kube-proxy mode, API endpoint, Service CIDR, or control-plane membership
change invalidates this contract. Rebind and rerun the canaries before an
install, promotion, or rollback; never widen a CIDR to make a test pass.

Every live mode requires both `kustomize` and `kubectl` to resolve to absolute
paths outside the checkout. The offline `--render` lock-regeneration mode
resolves only `kustomize`: it does not resolve or execute `kubectl`, and it does
not read `KUBECONFIG`, context, server, runtime-network, journal, or cluster
paths. Run the installer directly or as
`/bin/bash -p scripts/install-kyverno-admission.sh`.
The fixed `/bin/bash -p` entry point does not elevate privilege: it prevents
`BASH_ENV`, `ENV`, and exported shell functions from running before the guards.
The installer then removes those startup hooks and closes helper lookup to
`/usr/bin:/bin`; ambient `PATH` is retained only as data for Bash's non-executing
lookup of the two candidate tools.

Each candidate must be a single-link regular executable, owned by root or the
effective operator, with no special bits or group/other write permission. The
installer opens it once, verifies its SHA-256 pin from `versions.env`, and copies
the reviewed bytes into an operator-owned mode-0700 directory as a mode-0500
image. Linux opens and unlinks that image, then rechecks and executes
`/proc/self/fd/<fd>` for every call. Darwin's `/dev/fd` is non-executable, so the
offline harness retains the mode-0500 image inside the revalidated private
directory and binds its inode, held descriptor, and digest before every call.
The only accepted script form is the synthetic harness's exact
`#!/bin/bash -p`; production pins name native Linux tools. Replacing the source
path cannot change the bytes that receive cluster authority, and a changed held
image is refused before its next invocation. Self-reported versions remain a
separate compatibility check, never executable identity. This binds external
pathname races, not a compromised process running as the effective operator.

The live/install contract remains Linux AMD64 and continues to require the
existing `KUSTOMIZE_LINUX_AMD64_SHA256` and
`KUBECTL_LINUX_AMD64_SHA256` executable pins. Render-only provenance is a
closed host tuple: Linux/x86_64 uses that same kustomize executable pin;
Darwin/arm64 requires both the official v5.8.1 release-archive SHA-256 and the
independently pinned SHA-256 of its extracted `kustomize` binary from
`versions.env`. Any other kernel/architecture pair stops. The archive pin
identifies the official asset a reviewer downloads and verifies before
extraction; every invocation is then rebound to the extracted-binary pin.
Render-only support grants no kubectl pin, target identity, or live authority.
Controller, helper, and canary images require full non-zero digests and must
equal the reviewed pins.

Native Windows does not simulate POSIX owner/mode or file-descriptor semantics.
Its portable structure and policy tests still run, while this custody proof runs
under WSL, a Linux container, or Linux CI. Windows credential-workspace and other
Windows-specific checks remain separate and are not skipped by this contract.

## Journal and recovery contract

Stage 1 requires a new private journal path outside the checkout. It refuses a
symlink or non-empty earlier record and creates the file under `umask 077`. Its
header is:

```text
@transaction-v3|report-only|<render-sha256>|<operator-target-sha256>|<runtime-network-sha256>|<attempt-id>
```

Every following row is one rendered `kind|namespace|name` identity, written
before application. Rollback validates the entire file before its first delete:
schema, stage, render lock, hashed target, hashed private network contract,
canonical attempt ID, exact cluster-scoped lock inventory, allowed kind, and
`kyverno` as the only namespaced scope. It dispatches scope by kind, not by a
journal field.

Successful rollback appends `@rolled-back|<attempt-id>` and replay is refused.
An enforce journal is never a deletion program; promotion rollback is demotion
to report-only.

`INT`, `TERM`, and `HUP` are transaction failures. During stage 1 the handler
cleans the canary, rolls back the bound journal in reverse order, sweeps runtime
webhooks, and proves no residue. During stage 2 it demotes; it never deletes the
installation. An unproved recovery exits non-zero with `RECOVERY REQUIRED` and
preserves the journal path.

## Coordinator-only report-only live acceptance

This section is a prepared acceptance plan, not permission to run it. The
coordinator owns the only live lane. Do not begin until the stage-1 blockers are
closed, `render.lock` has a separately reviewed `authorized=yes`, the exact head
has independent static review, and the owner opens the bounded window. No step
unsuspends Flux, handles SOPS/tunnel tokens, changes Cloudflare, deploys a site,
or promotes enforcement.

### 1. Read-only absence and collision preflight

Record the exact commit and render receipts, then prove the expected empty
starting state:

```sh
git rev-parse HEAD
./scripts/install-kyverno-admission.sh --stage report-only --render
kubectl get namespace kyverno
kubectl get crd -o name | grep '\.kyverno\.io$'
kubectl get clusterpolicy,policy -A
kubectl get validatingwebhookconfiguration,mutatingwebhookconfiguration -o name | grep -i kyverno
```

Expected before the first accepted install: namespace, Kyverno CRDs, policies,
and every reviewed/extraneous Kyverno webhook are absent. A forbidden read is
not absence. A collision is a stop; the installer never adopts foreign state.

Also record, without publishing private inventory, the selected CNI identity,
kube-proxy mode, `kubernetes.default` Service, complete API endpoint set, and
all current control-plane InternalIPs. Build the private mode-0600 contract and
compare its SHA-256 in the protected evidence record.

### 2. Rehearse, then install report-only only

```sh
./scripts/install-kyverno-admission.sh --stage report-only --plan
./scripts/install-kyverno-admission.sh --stage report-only --apply \
  --journal "$PROTECTED_ROOT/kyverno-stage1.journal"
```

The recorded log must show all seven phases in order, strict built-in
validation before mutation, CRD Established before policy validation, the exact
pre-controller canary succeeding and disappearing, exact controller readiness,
and the namespace annotations binding render, network contract, journal,
attempt, and start time. Every applied ClusterPolicy must carry
`validationFailureAction: Audit`, every rule's `validate.failureAction` must be
`Audit`, and every `spec.webhookConfiguration.failurePolicy` must be `Ignore`;
any `Enforce` or `Fail` in the applied bytes is a stop.

### 3. Prove actual webhook and API paths

Inspect every runtime webhook by exact name and by the managed label. Record its
Service reference, CA bundle presence, namespace selector, rules, and timeout.

**The achievable `failurePolicy` contract is not universal `Ignore`.** The
report-only overlay patches ClusterPolicy fields, and Kyverno derives only its
RESOURCE webhooks from those fields. Every other configuration in the reviewed
inventory is one the controller constructs for its own API groups, with its own
failure policy, through its own RBAC; no ClusterPolicy overlay can reach it, so
demanding `Ignore` across the whole inventory demands a state stage 1 cannot
produce. The exact per-webhook expectation:

| Configuration | Expected `failurePolicy` | Why |
| --- | --- | --- |
| `kyverno-resource-validating-webhook-cfg` | `Ignore` | Built from the reviewed ClusterPolicies' `spec.webhookConfiguration.failurePolicy`, which the report-only overlay rewrites. This is the tenant-facing path, and the only one whose failure could refuse an unrelated write. |
| `kyverno-resource-mutating-webhook-cfg` | `Ignore` | Same derivation, mutating half. The reviewed policy set is validate-only, so this may also be absent. |
| `kyverno-policy-validating-webhook-cfg` | `Fail` | Kyverno's own admission control over `kyverno.io` policy objects, constructed by the controller at the pinned v1.18.2. Fail-open here would admit an unparseable policy. |
| `kyverno-policy-mutating-webhook-cfg` | `Fail` | Same family: policy defaulting/autogen over `kyverno.io` objects. |
| `kyverno-exception-validating-webhook-cfg` | `Fail` | Validates `PolicyException` objects — the objects that EXEMPT workloads from admission. |
| `kyverno-cel-exception-validating-webhook-cfg` | `Fail` | Same, for the CEL exception type. |
| `kyverno-global-context-validating-webhook-cfg` | `Fail` | Validates `GlobalContextEntry` objects. |
| `kyverno-verify-mutating-webhook-cfg` | `Fail` | Kyverno's self-check on its own Deployment in the `kyverno` namespace. |
| `kyverno-cleanup-validating-webhook-cfg` | absent | `cleanupController.enabled=false` in the recorded render parameters. |
| `kyverno-ttl-validating-webhook-cfg` | absent | Same disabled controller. |

Record the observed value for every configuration and compare it to this table.
The stop conditions, in order of severity:

1. A Kyverno webhook configuration present under any name NOT in
   `render.lock`'s `runtime.webhooks.validating` / `runtime.webhooks.mutating`
   is a stop — the break-glass sweep would not delete it by name.
2. Either `kyverno-resource-*` configuration reading anything but `Ignore` is a
   stop, and the response is break-glass: stage 1 is fail-open by definition
   and a fail-closed tenant webhook is the blast radius this staging exists to
   prevent.
3. A `Fail` row whose `rules` reach any group outside `kyverno.io` and
   `wgpolicyk8s.io` — other than the verify webhook's own pinned
   `kyverno`-namespace Deployment target — is a stop regardless of its failure
   policy. That scope bound, not the failure policy, is what keeps a `Fail` row
   from being able to refuse a tenant or platform write.
4. Any row whose observed value differs from the table is a stop for review:
   record the observed value, do not proceed, and amend this table in the same
   change that explains the difference. The table is the reviewed expectation
   for pinned v1.18.2, not a value read back from the cluster.

Then trigger a harmless admission request in the
dedicated `kyverno-validation` namespace and require a fresh PolicyReport result.
That result proves an actual API-server-to-webhook round trip from the effective
control-plane source; controller logs must show no network timeout or TLS error.

The pre-controller canary already proves the Pod-to-API DNS/TCP path with the
exact admission ServiceAccount and labels. Together, these two tests cover the
opposite network directions. On HA, trigger admissions through every API-server
endpoint or load-balancer backend and retain per-source evidence; any untested
control-plane source is a stop.

### 4. Known-allow, known-deny, and ReplicaSet identity canaries

Create only disposable objects in `kyverno-validation`, with an evidence label
and no secret, host access, public exposure, persistent storage, or external
network dependency. Because stage 1 is report-only, both known-allow and
known-deny requests must be admitted; their fresh report results must differ as
expected.

For ReplicaSets:

1. create a bounded Deployment named `kyverno-validation` and record its UID;
2. observe the built-in Deployment controller create its ReplicaSet;
3. require the exact-owner rule and
   `require-replicaset-controller-and-live-owner-uid` to pass for that
   controller-created ReplicaSet;
4. manually submit a raw ReplicaSet with a spoofed owner name/UID and require a
   fresh failure result; and
5. submit the same shape as an ordinary ServiceAccount and require the actor
   check to fail.

Do not infer the controller username. Record the admission identity actually
seen in Kyverno evidence and close `#100` only if it is exactly the reviewed
value. Delete the canary namespace and prove all canary resources and reports
are gone.

### 5. Interrupt, rollback, break-glass, and residue proof

Run one failure-injection attempt at a time from the known-empty starting state.
Interrupt after each phase boundary in separate attempts and require the handler
to roll back with a matching `@rolled-back|<attempt-id>` marker. A failure to
prove rollback is a stop; preserve the journal and run:

```sh
./scripts/install-kyverno-admission.sh --stage report-only --rollback \
  --journal "$PROTECTED_ROOT/kyverno-stage1.journal"
```

For a successfully installed report-only instance, rehearse break-glass:

```sh
./scripts/install-kyverno-admission.sh --break-glass
```

The script tries every reviewed exact name, then the label backstop, accumulates
delete errors, and succeeds only after exact-name and broad residue reads prove
clear. It leaves controllers and policies for diagnosis. After recording that
proof, use the bound stage-1 journal to remove the installation.

Final state must equal the preflight: no `kyverno` namespace, no `*.kyverno.io`
CRD, no ClusterPolicy/Policy, no reviewed or label-discovered Kyverno webhook,
no canary namespace/object, and no changed Flux suspension. Record failures and
their raw stderr; never translate a denied read into absence.

### 5a. Optional ephemeral workload recreation

The owner permits a coordinator-run acceptance to stop, delete, and recreate
Pods and workload controllers, including the two Cloudflare connector
Deployments, with downtime. This is optional and may not begin merely because
report-only is installed. Before any delete, the live-lane record must contain:

- an exact namespace/kind/name/UID inventory of every target and its Pods;
- an exact desired-state render and SHA-256 from the repository which owns that
  workload at a pinned commit;
- a machine-checked deletion allowlist containing only ephemeral workload kinds
  and proving that no `Secret`, SOPS/age file or key, PVC/PV, etcd/PKI object,
  provider object, or private-key-bearing object can match;
- the ordered redeploy and rollback commands, executed by one coordinator lane;
- a measured delete-to-ready recovery-time objective, readiness threshold, and
  timestamped residue ledger for every removed and recreated identity; and
- pre-test and post-test acceptance for both public HTTPS sites.

This repository owns the connector chart, not the two website application
charts. Connector recreation may use the exact rendered chart from this head.
Deleting a website workload requires an independently pinned render from its
owning `naranjo.online` or `lidersea.com` repository; #91 evidence alone cannot
authorize or reconstruct it. Missing ownership, hash, or rollback evidence is a
stop, and the dedicated `kyverno-validation` canaries remain sufficient.

Never delete or rewrite Cloudflare Tunnel/API tokens or the Kubernetes Secrets
which hold them. Preserve SOPS/age ciphertext and keys, all private keys,
domains, DNS zones, Tunnel/provider identities and state, routes, and recovery
custody. A test which does not recover both HTTPS sites to their pre-test
acceptance state has failed even if admission reports are correct.

`StatefulSet`, `PersistentVolume`, `PersistentVolumeClaim`, database, and
operator resources are not ephemeral by implication and never enter this
deletion allowlist. A test targeting one requires a separate exact durability,
backup/restore, recovery-time, data-integrity, and residue plan authorized for
that object; otherwise it is preserved.

### 6. Evidence and stop condition

Evidence contains commit/render digests, tool versions and executable hashes,
the private contract digest (not its private contents), transaction/journal
digests and attempt ID, phase timestamps, exact object/controller inventories,
webhook summaries without private addresses, canary results, and final residue
inventory. It contains no kubeconfig, token, secret, private route, or raw
network inventory.

Stop after report-only cleanup. Enforcement remains prohibited even if every
report-only check passes; its authorization is a later exact-head decision.

## Break-glass reference

If admission begins refusing writes, run the bound script first:

```sh
./scripts/install-kyverno-admission.sh --break-glass
```

If the checkout is unavailable, delete every exact runtime name while
continuing after individual errors, then use the label backstop and prove the
objects are absent. The reviewed exact inventory is:

```text
validating:
  kyverno-policy-validating-webhook-cfg
  kyverno-resource-validating-webhook-cfg
  kyverno-exception-validating-webhook-cfg
  kyverno-cel-exception-validating-webhook-cfg
  kyverno-global-context-validating-webhook-cfg
  kyverno-cleanup-validating-webhook-cfg
  kyverno-ttl-validating-webhook-cfg
mutating:
  kyverno-policy-mutating-webhook-cfg
  kyverno-resource-mutating-webhook-cfg
  kyverno-verify-mutating-webhook-cfg
```

The final broad fallback commands are:

```sh
kubectl delete validatingwebhookconfiguration -l webhook.kyverno.io/managed-by=kyverno
kubectl delete mutatingwebhookconfiguration -l webhook.kyverno.io/managed-by=kyverno
```

Do not delete controller objects until webhook deletion is proven. Removing a
controller first can leave a fail-closed webhook pointing at nothing.

## Step 5 — promote to stage 2

**NOT AUTHORIZED.** The future rehearsal command is shown only so its gate is
reviewable. `#100`, `#101`, `#102`, and the `runtime-network-canary` must all be
closed before a later exact-head decision can authorize promotion:

```sh
export KYVERNO_REPORT_ONLY_JOURNAL="$PROTECTED_ROOT/kyverno-stage1.journal"
./scripts/install-kyverno-admission.sh --stage enforce --plan
```

It validates the journal and exact live binding, requires the lock's minimum
observation interval, exact controller names, current generations, positive and
fully available desired replicas, Audit at policy and rule level, and fresh
timestamped PolicyReport/ClusterPolicyReport results naming a reviewed policy.
Those checks are necessary but not sufficient: `#100`, `#101`, `#102`, the
`runtime-network-canary`, fresh independent review, and explicit owner
authorization all remain gates. No `--stage enforce --apply` is authorized by
this runbook.

## What stays untouched

- Flux controllers and all reconciliation objects stay suspended.
- SOPS/age and tunnel-token ceremonies stay deferred.
- No Cloudflare, router, tunnel, route, DNS, SSH, host, reboot, or site action is
  part of this transaction.
- No live inventory or credential enters Git or pull-request evidence.
- A report-only installation never establishes the precondition for a Flux
  unsuspend; enforcement itself would need separate authorization first.
