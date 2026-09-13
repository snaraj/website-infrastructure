# Isolated private Obsync connector activation

This operator procedure prepares a create-only first activation of one private
connector. It is not live authorization or native-device acceptance. Follow the
[private TLS boundary](obsync-private-tls.md) and
[application activation](obsync-application-sync.md) first. Keep the shared
`cloudflare-public` HelmRelease suspended; never apply its full chart to install
this connector. Application composition remains in its existing lane.

## Exact artifact and prerequisites

`scripts/render_obsync_private_connector.py` invokes the pinned Helm version on
the existing dependency-free chart, checks its entire known object inventory,
and selects exactly two objects in `cloudflare-public`, in this order:

1. NetworkPolicy `cloudflared-obsidian`.
2. Deployment `obsync-tunnel`.

The only change to those chart-rendered objects is their `managed-by` label,
including the Pod label, becoming `obsync-private-operator`. The resolved token
revision is a non-secret operator identifier. The chart's image, token-file
mount, security context, resource requests/limits, probes, selectors and
TLS-proxy-only origin egress stay unchanged. The renderer has no cluster or
provider command, token reader, arbitrary chart path or value override.

No Secret, ServiceAccount, shared policy, peer Deployment, Service, Flux object
or provider route is emitted. The two fixed `--part` outputs compose byte-exactly
to the whole artifact and allow policy creation to finish before a Deployment
creation is dispatched. Canonical static gates render a synthetic revision;
that artifact never establishes token custody or deployment readiness.

Before requesting owner approval, record these checks in the private operator
journal. Missing, stale, ambiguous or conflicting evidence is a stop:

- The clean source commit is protected-main, owner-merged and independently
  approved, with successful exact-head source gates and current release
  evidence. Bind the source commit, tool pins, non-secret revision and each
  artifact SHA-256 to the proposed operation. Re-rendering different bytes
  requires renewed review; publication alone never installs the artifact.
- The intended cluster context and namespace are verified privately. The
  namespace retains restricted Pod Security, its admitted ResourceQuota and
  LimitRange, and sufficient capacity for the chart's one replica.
- Existing ServiceAccount `cloudflared` has token automount disabled. Existing
  NetworkPolicies `default-deny`, `cloudflared-dns` and `cloudflared-edge` match
  their reviewed source and the effective policy union remains confined. Record
  UID and resourceVersion for these named shared prerequisites and verify them
  unchanged afterward. Do not read Secret values or enumerate unrelated objects.
- Neither selected object exists. Any existing object, even one with the same
  name, labels or apparent specification, stops this first-install ceremony:
  never adopt it, add Helm ownership annotations, replace it or silently repair
  shared prerequisites. Check that no reconciler or other operator owns or can
  concurrently create these targets; preserve the shared release's suspension.
- The reviewed application/storage activation is complete. The proxy's
  backend-dependent HTTPS readiness, effective reciprocal NetworkPolicies,
  leaf validity/SAN/chain and intended devices' trust satisfy the TLS runbook.
  A connector `/ready` response proves edge connection health, not these gates.
- The owner separately admits the exact remotely managed Tunnel and private-network
  route for this service. Its provider UUID is verified from the approved
  resource, never derived from the Kubernetes Deployment name. Confirm the
  destination and virtual network, intended device admission and client routing,
  plus effective non-inspection or narrowly scoped `Do Not Inspect` treatment.
  No public hostname, DNS record, Access application or wider network route is
  a prerequisite. Missing provider identifiers or policy evidence remain open.
- The owner has separately supplied `obsync-tunnel-token` in this namespace,
  key `token`, through a reviewed credential ceremony bound to that exact
  account/Tunnel. This runbook does not install, obtain, rotate or validate a
  token. No token value enters an argument, render, log, source or review.
  Check only the authorized Secret metadata and custody receipt. A missing or
  mismatched receipt stops activation; a resolved revision string is not proof.
- Independent recovery remains available. No peer rollout, shared reconciliation
  or concurrent operator change may overlap this one-connector transaction.

Cloudflare documents private routing as a separate connector, route and enrolled
client configuration in its [private-network guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/).
The [IP/CIDR guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/cloudflared/connect-cidr/)
also requires the intended traffic to route through the client. These are
provider prerequisites, not resources this renderer creates or changes.

## Reviewable render and create-only order

In a clean checkout of the approved source commit, using the repository-pinned
tools, create an owner-only temporary directory outside Git. Set `revision` to
the reviewed non-secret revision and `artifact_dir` to that directory. Render
both parts without reading credentials:

```sh
python3 -B scripts/render_obsync_private_connector.py --token-revision "$revision" --part policy >"$artifact_dir/policy.yaml"
python3 -B scripts/render_obsync_private_connector.py --token-revision "$revision" --part deployment >"$artifact_dir/deployment.yaml"
kubeconform -strict -summary "$artifact_dir/policy.yaml" "$artifact_dir/deployment.yaml"
conftest test --policy policies/conftest "$artifact_dir/policy.yaml" "$artifact_dir/deployment.yaml"
```

Run the required source gates, inspect both full non-secret artifacts and record
their hashes privately. Review the concrete token/trust/route prerequisites and
rollback checkpoint with the owner. Do not proceed before owner approval of
the exact live operation. Do not change trust, provider state or a Secret as an
incidental step. The artifact alone cannot clear those separate ceremonies.

Inside the approved window, recheck source/hash equality, prerequisites, exact
target absence and exclusive ownership. Run this read-only preflight in the
same shell transaction before any dry-run or creation. It requires both selected
objects absent and all four named shared prerequisites present. A failed read
is a refusal, not absence. This checks existence and account automount only;
the preceding reviewed-policy, ownership, capacity and trust checks still apply.

```bash
set -euo pipefail
for target in deployment/obsync-tunnel networkpolicy/cloudflared-obsidian; do
  if ! observed="$(kubectl get "$target" --namespace cloudflare-public --ignore-not-found -o name)"; then
    printf 'Private connector preflight refused: target read failed.\n' >&2
    exit 1
  fi
  if [[ -n "$observed" ]]; then
    printf 'Private connector preflight refused: selected object already exists.\n' >&2
    exit 1
  fi
done
for target in serviceaccount/cloudflared networkpolicy/default-deny networkpolicy/cloudflared-dns networkpolicy/cloudflared-edge; do
  if ! observed="$(kubectl get "$target" --namespace cloudflare-public --ignore-not-found -o name)" || [[ -z "$observed" ]]; then
    printf 'Private connector preflight refused: shared prerequisite is unavailable.\n' >&2
    exit 1
  fi
done
if ! automount="$(kubectl get serviceaccount/cloudflared --namespace cloudflare-public -o 'jsonpath={.automountServiceAccountToken}')" || [[ "$automount" != false ]]; then
  printf 'Private connector preflight refused: shared account must remain tokenless.\n' >&2
  exit 1
fi
```

Do not continue in another shell after a preflight refusal. Do not create or
adopt a missing shared prerequisite here. Server-side dry-run each file using
the intended verified context; any refusal stops before either real creation:

```sh
kubectl create --dry-run=server -f "$artifact_dir/policy.yaml"
kubectl create --dry-run=server -f "$artifact_dir/deployment.yaml"
```

Then create only the policy. Capture its returned UID/resourceVersion in the
private journal and verify the resulting policy before issuing the separate
Deployment creation. Treat each command as a checkpoint, not a batch to paste:

```sh
kubectl create -f "$artifact_dir/policy.yaml" -o jsonpath='{.metadata.uid}{" "}{.metadata.resourceVersion}{"\n"}'
```

If and only if that checkpoint succeeds with the exact reviewed policy, create
the Deployment and capture its returned identity:

```sh
kubectl create -f "$artifact_dir/deployment.yaml" -o jsonpath='{.metadata.uid}{" "}{.metadata.resourceVersion}{"\n"}'
```

Capture output only in the private journal. `AlreadyExists`, lost responses or
partial outcomes are reconciliation stops, never reasons to retry creation or
use apply/replace. Read only the exact target metadata to establish the result;
do not infer ownership from its name or label. Without the recorded successful
creation identity, leave the object for a reviewed recovery decision.

Verify the exact Deployment generation/image, one ready replica, its own token
Secret reference and unchanged shared prerequisite identities. Then verify the
approved Tunnel connection and end-to-end trusted HTTPS from each intended
device, with the actual origin certificate. Keep metadata-only receipts; do not
enable request logging. The TLS runbook's real-client sync acceptance still
follows. Successful source or connector readiness is not native-device acceptance.

## Stop, rollback and later ownership

On a failure after creation, stop the campaign and preserve the partial receipt.
Do not delete storage, credentials, the policy or any shared object. If rollback
was approved and this Deployment's current UID matches the creation receipt,
read its current replica count and resourceVersion immediately before a
conditional scale to zero. Pass both recorded current values to `kubectl scale`
(`--current-replicas` and `--resource-version`); any precondition failure stops
for new assessment. Verify zero desired/ready replicas and peer/shared
prerequisites unchanged. This does not revoke a token or remove a provider route;
those remain separate owner actions. Never scale a replacement UID.

A policy created without a Deployment can remain as an inert, exact-selector
partial result pending review. Do not automatically remove an object after a
lost response. Do not restore an old token as rollback. Repeat activation,
updates, deletion, provider repair and transfer to a future Helm release each
need their own reviewed identity-bound operation. Never unsuspend the shared
release to take ownership of these objects or adopt the shared ServiceAccount.
