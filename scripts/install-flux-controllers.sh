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
# Every guard refuses BEFORE contacting the cluster, except the explicit
# server-side dry run, which by definition mutates nothing.
#
#   --plan    render, verify, and report the dry-run outcome; no mutation
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
      '  --plan   render + verify + server-side dry run (default; no mutation)' \
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

dry_run="${work}/dry-run.txt"
if ! kubectl apply -f "$rendered" --dry-run=server >"$dry_run" 2>&1; then
  cat -- "$dry_run" >&2
  die 'server-side dry run failed; nothing was applied'
fi

# The dry run reports one line per object. Any line naming something outside
# the reviewed controller inventory — another namespace, a workload, a site
# object — means the render or the target cluster is not what it claims to be.
if grep -Ev '^(namespace/flux-system|customresourcedefinition\.apiextensions\.k8s\.io/[a-z0-9.-]+|clusterrole\.rbac\.authorization\.k8s\.io/[a-z0-9-]+|clusterrolebinding\.rbac\.authorization\.k8s\.io/[a-z0-9-]+|networkpolicy\.networking\.k8s\.io/[a-z0-9-]+|resourcequota/[a-z0-9-]+|serviceaccount/[a-z0-9-]+|service/[a-z0-9-]+|deployment\.apps/[a-z0-9-]+) [a-z ()]+$' "$dry_run"; then
  die 'dry run reported an object outside the reviewed controller inventory'
fi
dry_run_lines="$(wc -l <"$dry_run" | tr -d ' ')"
[[ "$dry_run_lines" -eq "$EXPECTED_OBJECTS" ]] || \
  die "dry run reported ${dry_run_lines} objects; the reviewed install has ${EXPECTED_OBJECTS}"
printf 'install-flux-controllers: dry run clean (%s objects)\n' "$dry_run_lines"

if [[ "$MODE" == '--plan' ]]; then
  printf 'install-flux-controllers: PLAN only; no mutation attempted\n'
  exit 0
fi

kubectl apply -f "$rendered"
printf 'install-flux-controllers: applied; Flux is installed and inert\n'
printf 'install-flux-controllers: apply the egress overlay next (docs/runbooks/flux-install.md)\n'
