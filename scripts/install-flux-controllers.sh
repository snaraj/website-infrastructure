#!/usr/bin/env bash
# Install the reviewed Flux controllers, and nothing else.
#
# Why this exists as its own entry point: bootstrap/flux/bootstrap.sh owns the
# secret-bearing and sync-applying ceremonies and stays code-blocked until the
# reviewed-blob launcher exists. The controllers-only install needs none of
# that machinery — no age identity, no Secret, no Flux custom resource, no
# credential of any kind — and it was authorized as a separate,
# inert-by-construction step. Encoding that step here, with its guardrails
# executable and reviewable, is strictly better than performing it as an ad-hoc
# command outside the repository.
#
# The offline guards refuse BEFORE contacting the cluster. The pre-apply gate
# then makes only read-only, non-mutating calls -- an existence probe of the
# objects the install creates, a client-side strict validation, and a
# server-side dry run -- and classifies their output fail-closed for both a
# fresh cluster (flux-system absent) and a reconcile of an existing one. See the
# gate below and docs/runbooks/flux-install.md. Nothing mutates until --apply.
#
#   --plan    render, verify, and report the pre-apply gate outcome; no mutation
#   --apply   the same checks, then apply the identical verified bytes
#
# See docs/runbooks/flux-install.md for the surrounding ceremony.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
# The install target is a constant, never an argument. Applying the parent root
# would create the root GitRepository and Kustomization from gotk-sync.yaml;
# neither is suspended, so reconciliation of ./kubernetes/reconciliation would
# begin immediately with prune enabled. Making that unreachable is the single
# most important thing this script does.
INSTALL_TARGET='kubernetes/flux-system/controllers'
# The reviewed inventory: 1 Namespace, 8 CRDs, 3 ClusterRoles,
# 2 ClusterRoleBindings, 3 NetworkPolicies, 1 ResourceQuota, 3 ServiceAccounts,
# 1 Service, 3 Deployments. A render of a different size is not the reviewed
# install no matter what its digest says.
EXPECTED_OBJECTS=25
# The inventory splits by scope, which is what the fresh-cluster dry run below
# turns on: 14 cluster-scoped objects (the Namespace, 8 CRDs, 3 ClusterRoles,
# 2 ClusterRoleBindings) plus 11 objects that live IN flux-system (1
# ResourceQuota, 3 ServiceAccounts, 1 Service, 3 Deployments, 3 NetworkPolicies).
EXPECTED_CLUSTER_SCOPED=14
EXPECTED_NAMESPACED=11
# The cluster-scoped names, needed to prove nothing the install creates already
# exists on a fresh cluster. The CRDs are proven absent by group (every reviewed
# CRD is in the fluxcd toolkit group), so only the RBAC names are enumerated.
FLUX_CLUSTER_ROLES=(crd-controller-flux-system flux-edit-flux-system flux-view-flux-system)
FLUX_CLUSTER_ROLE_BINDINGS=(cluster-reconciler-flux-system crd-controller-flux-system)

# Recognized dry-run report lines. kubectl prints "<kind>/<name> <verb>" per
# object, optionally suffixed " (dry run)" (client) or " (server dry run)"
# (server). CRDs are bounded to the fluxcd toolkit group; every other kind to
# the reviewed controller inventory; verbs to the three non-mutating outcomes.
_dry_suffix='( \((server )?dry run\))?'
_apply_verb='(created|configured|unchanged)'
_cluster_scoped_kind='(namespace/flux-system|customresourcedefinition\.apiextensions\.k8s\.io/[a-z0-9.-]+\.fluxcd\.io|clusterrole\.rbac\.authorization\.k8s\.io/[a-z0-9-]+|clusterrolebinding\.rbac\.authorization\.k8s\.io/[a-z0-9-]+)'
_namespaced_kind='(networkpolicy\.networking\.k8s\.io/[a-z0-9-]+|resourcequota/[a-z0-9-]+|serviceaccount/[a-z0-9-]+|service/[a-z0-9-]+|deployment\.apps/[a-z0-9-]+)'
# A fresh cluster's cluster-scoped objects must report exactly "created": a
# "configured"/"unchanged" there means something already exists, which the
# absence probe should already have refused.
CLUSTER_SCOPED_CREATED_LINE="^${_cluster_scoped_kind} created${_dry_suffix}\$"
# Any reviewed object reporting any non-mutating verb: the shape of a clean
# client validation and of an existing-cluster server dry run.
INVENTORY_MUTATION_LINE="^(${_cluster_scoped_kind}|${_namespaced_kind}) ${_apply_verb}${_dry_suffix}\$"
# The EXPECTED fresh-cluster error on each of the 11 namespaced children: the
# server dry run does not persist the dry-run Namespace (k8s #83562), so it has
# nowhere to place them. Bounded to flux-system -- any other namespace, or any
# other error, is a genuine failure.
NS_NOT_FOUND_LINE='^Error from server \(NotFound\): error when creating "[^"]*": namespaces "flux-system" not found$'

die() {
  printf 'install-flux-controllers: %s\n' "$*" >&2
  exit 1
}

MODE="${1:---plan}"
case "$MODE" in
  --plan|--apply) ;;
  -h|--help)
    printf '%s\n' \
      'Usage: scripts/install-flux-controllers.sh [--plan|--apply]' \
      '  --plan   render + verify + read-only pre-apply gate (default; no mutation)' \
      '  --apply  the same checks, then apply the verified bytes'
    exit 0
    ;;
  *) die "unknown mode: ${MODE}" ;;
esac
(($# <= 1)) || die 'only one mode argument is accepted'

for tool in kustomize kubectl; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

digest_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum <"$1" | cut -d' ' -f1
  else
    shasum -a 256 <"$1" | cut -d' ' -f1
  fi
}

[[ -f "${REPO_ROOT}/${INSTALL_TARGET}/kustomization.yaml" ]] || \
  die "missing install root: ${INSTALL_TARGET}"

work="$(mktemp -d "${TMPDIR:-/tmp}/flux-controllers.XXXXXX")"
cleanup() {
  local status=$?
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT

rendered="${work}/controllers.yaml"
kustomize build "${REPO_ROOT}/${INSTALL_TARGET}" >"$rendered"
[[ -s "$rendered" ]] || die 'render produced no bytes'

# An inert install contains no Flux custom resource. A GitRepository,
# Kustomization, HelmRelease, OCIRepository, or image-automation object in this
# render would mean applying it starts reconciling something.
if grep -Eq '^kind:[[:space:]]*(GitRepository|Kustomization|HelmRelease|HelmChart|HelmRepository|OCIRepository|Bucket|ImageRepository|ImagePolicy|ImageUpdateAutomation|Receiver|Alert|Provider)[[:space:]]*$' "$rendered"; then
  die 'render contains a Flux custom resource; this install must reconcile nothing'
fi
if grep -Eq '^kind:[[:space:]]*Secret[[:space:]]*$' "$rendered"; then
  die 'render contains a Secret; the controller install carries no credential'
fi
# The blanket egress the Flux CLI generates must already be gone: a render that
# still carries an egress rule would open every flux-system Pod to every
# destination the moment it is applied.
if grep -Eq '^[[:space:]]+egress:[[:space:]]*$' "$rendered"; then
  die 'render still carries an egress rule; the allow-egress patch is not applied'
fi
# Pod Security must be enforced, not merely warned about.
if ! grep -Eq '^[[:space:]]+pod-security\.kubernetes\.io/enforce:[[:space:]]*restricted[[:space:]]*$' "$rendered"; then
  die 'render does not enforce restricted Pod Security on flux-system'
fi

object_count="$(grep -cE '^kind:[[:space:]]' "$rendered")"
[[ "$object_count" -eq "$EXPECTED_OBJECTS" ]] || \
  die "render has ${object_count} objects; the reviewed install has ${EXPECTED_OBJECTS}"

printf 'install-flux-controllers: render sha256 %s (%s objects)\n' \
  "$(digest_of "$rendered")" "$object_count"

# --- Fail-closed pre-apply gate ---------------------------------------------
#
# The install creates its OWN flux-system Namespace, so a naive "every object
# must report created" server dry run can never pass a fresh cluster: k8s #83562
# means the dry run does not persist that Namespace, and the 11 namespaced
# children then fail admission with `namespaces "flux-system" not found` while
# kubectl exits non-zero. The old gate died there -- refusing the very
# fresh-cluster install this script exists to perform. The gate instead proves a
# clean creation without leaning on the dry run persisting the namespace, and
# fails closed on anything else.

# (1) The bytes are valid to apply at all, independent of any namespace.
# Client-side strict validation rejects unknown/duplicated fields and needs no
# flux-system to exist, so it validates all 25 objects even on a fresh cluster.
client_dry_run="${work}/dry-run-client.txt"
if ! kubectl apply -f "$rendered" --dry-run=client --validate=strict \
    >"$client_dry_run" 2>&1; then
  cat -- "$client_dry_run" >&2
  die 'client-side strict validation failed; the render is not valid to apply'
fi
client_objects="$(grep -cE "$INVENTORY_MUTATION_LINE" "$client_dry_run" || true)"
[[ "$client_objects" -eq "$EXPECTED_OBJECTS" ]] || {
  cat -- "$client_dry_run" >&2
  die "client validation reported ${client_objects} reviewed objects; expected ${EXPECTED_OBJECTS}"
}

# (2) Is flux-system already present? That forks the two legitimate dry-run
# shapes below. A get that neither finds it nor cleanly reports it missing -- an
# unreachable API server -- is fatal, never silently treated as "fresh".
ns_state="${work}/namespace-state.txt"
if kubectl get namespace flux-system -o name >"$ns_state" 2>&1; then
  cluster_state='existing'
elif grep -q 'not found' "$ns_state"; then
  cluster_state='fresh'
else
  cat -- "$ns_state" >&2
  die 'could not determine flux-system state; the API server did not answer NotFound'
fi

# (3) On a fresh cluster nothing the install creates may already exist. The
# Namespace absence just proven covers every namespaced child; prove the
# cluster-scoped names too, so a "created" below is a real create and never a
# silent adopt of a foreign object. The render is grepped first so a drift
# between this list and the reviewed inventory fails loudly, not silently.
if [[ "$cluster_state" == 'fresh' ]]; then
  fluxcd_crds="$(kubectl get customresourcedefinition -o name 2>/dev/null \
    | grep -c '\.fluxcd\.io$' || true)"
  [[ "$fluxcd_crds" -eq 0 ]] || \
    die "flux-system is absent but ${fluxcd_crds} fluxcd CRD(s) already exist"
  for name in "${FLUX_CLUSTER_ROLES[@]}"; do
    grep -qE "name: ${name}\$" "$rendered" || \
      die "reviewed ClusterRole ${name} is not in the render; the inventory drifted"
    ! kubectl get clusterrole "$name" -o name >/dev/null 2>&1 || \
      die "flux-system is absent but ClusterRole ${name} already exists"
  done
  for name in "${FLUX_CLUSTER_ROLE_BINDINGS[@]}"; do
    grep -qE "name: ${name}\$" "$rendered" || \
      die "reviewed ClusterRoleBinding ${name} is not in the render; the inventory drifted"
    ! kubectl get clusterrolebinding "$name" -o name >/dev/null 2>&1 || \
      die "flux-system is absent but ClusterRoleBinding ${name} already exists"
  done
fi

# (4) The server dry run, classified by cluster state. It contacts the API
# server but mutates nothing. On a fresh cluster kubectl exits non-zero by
# design (the 11 children cannot be placed); that is not a failure here.
dry_run="${work}/dry-run-server.txt"
if kubectl apply -f "$rendered" --dry-run=server >"$dry_run" 2>&1; then
  server_rc=0
else
  server_rc=$?
fi
total_lines="$(grep -cE '.' "$dry_run" || true)"

if [[ "$cluster_state" == 'fresh' ]]; then
  # Exactly EXPECTED_CLUSTER_SCOPED objects report "created" and exactly
  # EXPECTED_NAMESPACED children report the flux-system namespace-not-found;
  # every line must be one of those two. A "configured"/"unchanged", a foreign
  # object, a different namespace, or any other error breaks the count and dies.
  [[ "$server_rc" -ne 0 ]] || \
    die 'fresh cluster but the server dry run reported no error; the namespace state is inconsistent'
  created="$(grep -cE "$CLUSTER_SCOPED_CREATED_LINE" "$dry_run" || true)"
  not_found="$(grep -cE "$NS_NOT_FOUND_LINE" "$dry_run" || true)"
  if [[ "$created" -ne "$EXPECTED_CLUSTER_SCOPED" || "$not_found" -ne "$EXPECTED_NAMESPACED" \
        || $((created + not_found)) -ne "$total_lines" ]]; then
    cat -- "$dry_run" >&2
    die "fresh dry-run shape wrong: ${created} cluster-scoped created (want ${EXPECTED_CLUSTER_SCOPED}), ${not_found} namespace-not-found children (want ${EXPECTED_NAMESPACED}), ${total_lines} total lines"
  fi
  printf 'install-flux-controllers: fresh-cluster dry run clean (%s created + %s expected namespace-not-found)\n' \
    "$created" "$not_found"
else
  # flux-system already exists: every reviewed object dry-runs cleanly against
  # it (the reconcile-to-reviewed-bytes path). A genuine error breaks the shape.
  [[ "$server_rc" -eq 0 ]] || {
    cat -- "$dry_run" >&2
    die 'server dry run failed against the existing flux-system namespace'
  }
  clean="$(grep -cE "$INVENTORY_MUTATION_LINE" "$dry_run" || true)"
  if [[ "$clean" -ne "$total_lines" || "$total_lines" -ne "$EXPECTED_OBJECTS" ]]; then
    cat -- "$dry_run" >&2
    die "existing dry-run shape wrong: ${clean} reviewed objects (want ${EXPECTED_OBJECTS}), ${total_lines} total lines"
  fi
  printf 'install-flux-controllers: existing-cluster dry run clean (%s objects)\n' "$clean"
fi

if [[ "$MODE" == '--plan' ]]; then
  printf 'install-flux-controllers: PLAN only; no mutation attempted\n'
  exit 0
fi

kubectl apply -f "$rendered"
printf 'install-flux-controllers: applied; Flux is installed and inert\n'
printf 'install-flux-controllers: apply the egress overlay next (docs/runbooks/flux-install.md)\n'
