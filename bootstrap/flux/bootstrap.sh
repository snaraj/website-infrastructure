#!/usr/bin/env bash
# Generate reviewed Flux controller desired state without credentials, then keep
# the two cluster mutations behind separate target proofs and acknowledgements.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# versions.env is resolved from this checkout rather than the caller's working
# directory; ShellCheck cannot follow the dynamic but trusted path in CI.
# shellcheck disable=SC1091
source "${repo_root}/versions.env"
mode="${1:---generate}"
controllers="${repo_root}/kubernetes/flux-system/controllers"
components="${controllers}/gotk-components.yaml"

require() { command -v "$1" >/dev/null 2>&1 || { printf '%s is required\n' "$1" >&2; exit 2; }; }
verify_cluster_target() {
  : "${EXPECTED_KUBECONFIG_CONTEXT:?Set the exact reviewed kubectl context}"
  : "${EXPECTED_KUBERNETES_SERVER:?Set the exact reviewed Kubernetes API URL}"
  : "${EXPECTED_PI_NODE_NAME:?Set the exact reviewed single Pi node name}"
  local actual_context actual_server node_names
  actual_context="$(kubectl config current-context)"
  actual_server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  node_names="$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
  [[ "${actual_context}" == "${EXPECTED_KUBECONFIG_CONTEXT}" ]] || {
    printf 'kubectl context mismatch; expected %s, got %s\n' "${EXPECTED_KUBECONFIG_CONTEXT}" "${actual_context}" >&2
    exit 2
  }
  [[ "${actual_server}" == "${EXPECTED_KUBERNETES_SERVER}" ]] || {
    printf 'Kubernetes API target mismatch.\n' >&2
    exit 2
  }
  [[ "${node_names}" == "${EXPECTED_PI_NODE_NAME}" ]] || {
    printf 'single-node target mismatch; expected only %s.\n' "${EXPECTED_PI_NODE_NAME}" >&2
    exit 2
  }
  printf 'Verified target context=%s node=%s.\n' "${actual_context}" "${EXPECTED_PI_NODE_NAME}"
}
require flux
# Python performs only a deterministic text substitution in generated YAML; the
# production controller and website stacks remain Kubernetes and Go.
if [[ -n "${PYTHON_BIN:-}" ]]; then
  python_command="${PYTHON_BIN}"
elif python3 --version >/dev/null 2>&1; then
  python_command=python3
elif python --version >/dev/null 2>&1; then
  python_command=python
else
  printf 'Python 3 is required to pin generated controller images\n' >&2
  exit 2
fi

if [[ "$(flux version --client 2>/dev/null | awk '/flux:/ {print $2}')" != "${FLUX_VERSION}" ]]; then
  printf 'Flux CLI does not match %s.\n' "${FLUX_VERSION}" >&2
  exit 1
fi

if [[ "${mode}" == "--generate" ]]; then
  temporary="$(mktemp)"
  trap 'rm -f "${temporary}"' EXIT
  flux install --version="${FLUX_VERSION}" --namespace=flux-system \
    --components=source-controller,kustomize-controller,helm-controller \
    --network-policy=true --export > "${temporary}"
  COMPONENTS_PATH="${temporary}" \
  SOURCE_IMAGE="${FLUX_SOURCE_CONTROLLER_IMAGE}" \
  KUSTOMIZE_IMAGE="${FLUX_KUSTOMIZE_CONTROLLER_IMAGE}" \
  HELM_IMAGE="${FLUX_HELM_CONTROLLER_IMAGE}" \
    "${python_command}" - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["COMPONENTS_PATH"])
text = path.read_text(encoding="utf-8")
replacements = {
    "ghcr.io/fluxcd/source-controller:v1.9.3": os.environ["SOURCE_IMAGE"],
    "ghcr.io/fluxcd/kustomize-controller:v1.9.4": os.environ["KUSTOMIZE_IMAGE"],
    "ghcr.io/fluxcd/helm-controller:v1.6.3": os.environ["HELM_IMAGE"],
}
for old, new in replacements.items():
    if text.count(old) != 1:
        raise SystemExit("expected exactly one generated image reference: " + old)
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
PY
  install -m 0644 "${temporary}" "${components}"
  printf 'Generated %s. Review the entire diff; no cluster or Git state changed.\n' "${components}"
  exit 0
fi

require kubectl
[[ -f "${components}" ]] || { printf 'Generate and review gotk-components.yaml first.\n' >&2; exit 1; }
verify_cluster_target
if [[ "${mode}" == "--apply-controllers" ]]; then
  [[ "${CONFIRM_FLUX_CONTROLLERS:-}" == "apply-reviewed-${FLUX_VERSION}" ]] || { printf 'Controller apply acknowledgement missing.\n' >&2; exit 2; }
  # Apply the rendered overlay so no controller Pod ever starts without the
  # reviewed multitenancy/default-identity flags.
  kubectl apply -k "${controllers}"
  kubectl -n flux-system rollout status deployment/source-controller --timeout=5m
  kubectl -n flux-system rollout status deployment/kustomize-controller --timeout=5m
  kubectl -n flux-system rollout status deployment/helm-controller --timeout=5m
  printf 'Controllers are available. Stop for age backup/install checkpoint.\n'
  exit 0
fi
if [[ "${mode}" == "--apply-sync" ]]; then
  [[ "${CONFIRM_FLUX_SYNC:-}" == "apply-reviewed-anonymous-sync" ]] || { printf 'Sync apply acknowledgement missing.\n' >&2; exit 2; }
  kubectl -n flux-system get secret sops-age >/dev/null
  kubectl apply -f "${repo_root}/kubernetes/platform/prerequisites/namespaces.yaml"
  kubectl apply -f "${repo_root}/kubernetes/flux-system/access.yaml"
  kubectl apply -f "${repo_root}/kubernetes/flux-system/gotk-sync.yaml"
  printf 'Bootstrap-owned access and anonymous sync applied after confirming the age Secret exists.\n'
  exit 0
fi
printf 'Usage: %s [--generate|--apply-controllers|--apply-sync]\n' "$0" >&2
exit 2
