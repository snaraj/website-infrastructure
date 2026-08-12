#!/bin/bash
# Generate reviewed Flux desired state, or apply/verify it through one exact
# protected kubeconfig and a checksum-pinned kubectl snapshot.
builtin set -Eeuo pipefail
builtin set +x
PATH=/usr/sbin:/usr/bin:/sbin:/bin
builtin export PATH
builtin umask 077

mutation_attempted=0
fail() {
  if [[ "${mutation_attempted}" -eq 0 ]]; then
    builtin printf 'FAIL Flux operation made no cluster mutation.\n' >&2
  else
    builtin printf 'FAIL Flux operation may have committed; stop and inspect the exact target.\n' >&2
  fi
  builtin exit 1
}

# Parse the requested operation before any external command or repository read.
# Offline desired-state generation remains available. Every secret-aware or
# live-cluster mode is a code-level safety stop until a separately installed
# reviewed-blob launcher establishes stage-zero trust outside this checkout.
mode="${1:---generate}"
[[ "$#" -le 1 ]] || fail
case "${mode}" in
  --generate) ;;
  --apply-controllers|--apply-sync|--verify)
    builtin printf 'BLOCKED Flux live mode requires the trusted reviewed-blob launcher; no protected file was read and no cluster mutation or request was attempted.\n' >&2
    builtin exit 1
    ;;
  *) fail ;;
esac

# Nothing inherited may make Bash execute caller-controlled startup code,
# import a function, or interpose a dynamic loader before we establish the
# reviewed toolchain. These checks and the core limits use Bash builtins only.
while read -r function_declaration function_flag inherited_function_name; do
  [[ "${function_declaration}" == declare && "${function_flag}" == -f ]] || fail
  [[ "${inherited_function_name}" == fail ]] || fail
done < <(builtin declare -F)
for bootstrap_environment_name in $(builtin compgen -e); do
  case "${bootstrap_environment_name}" in
    BASH_ENV|ENV|BASH_FUNC_*|LD_*) fail ;;
  esac
done
builtin ulimit -S -c 0 || fail
builtin ulimit -H -c 0 || fail

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
versions_file="${repo_root}/versions.env"
kubeconfig_validator="${repo_root}/scripts/validate_kubeconfig_snapshot.py"
controllers="${repo_root}/kubernetes/flux-system/controllers"
components="${controllers}/gotk-components.yaml"
[[ -f "${versions_file}" && ! -L "${versions_file}" ]] || fail

pin() {
  local name="$1"
  awk -F= -v key="${name}" '
    $1 == key && $2 ~ /^[A-Za-z0-9._:+@/-]+$/ { count += 1; value = $2 }
    END { if (count == 1) print value }
  ' "${versions_file}"
}
FLUX_VERSION="$(pin FLUX_VERSION)"
FLUX_LINUX_AMD64_SHA256="$(pin FLUX_LINUX_AMD64_SHA256)"
FLUX_SOURCE_CONTROLLER_IMAGE="$(pin FLUX_SOURCE_CONTROLLER_IMAGE)"
FLUX_KUSTOMIZE_CONTROLLER_IMAGE="$(pin FLUX_KUSTOMIZE_CONTROLLER_IMAGE)"
FLUX_HELM_CONTROLLER_IMAGE="$(pin FLUX_HELM_CONTROLLER_IMAGE)"
KUBERNETES_VERSION="$(pin KUBERNETES_VERSION)"
KUBECTL_LINUX_AMD64_SHA256="$(pin KUBECTL_LINUX_AMD64_SHA256)"
[[ "${FLUX_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail
[[ "${KUBERNETES_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail
[[ "${FLUX_LINUX_AMD64_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "${KUBECTL_LINUX_AMD64_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
for image in "${FLUX_SOURCE_CONTROLLER_IMAGE}" \
  "${FLUX_KUSTOMIZE_CONTROLLER_IMAGE}" "${FLUX_HELM_CONTROLLER_IMAGE}"; do
  [[ "${image}" =~ ^ghcr\.io/fluxcd/[a-z-]+:v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]] || fail
done

python3_binary="$(readlink -e -- /usr/bin/python3)" || fail
[[ "${python3_binary}" =~ ^/usr/bin/python3(\.[0-9]+)?$ ]] || fail
[[ -f "${python3_binary}" && ! -L "${python3_binary}" && -x "${python3_binary}" ]] || fail
[[ "$(stat -c '%u:%h' -- "${python3_binary}")" == 0:1 ]] || fail
python3_mode="$(stat -c %a -- "${python3_binary}")" || fail
(( (8#${python3_mode} & 0022) == 0 )) || fail
"${python3_binary}" -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' || fail

# Preserve the future live-mode recovery contract behind the unconditional
# launcher stop above. These attestations are additional gates, never a way to
# reopen the current release.
if [[ "${mode}" == --apply-controllers || "${mode}" == --apply-sync ]]; then
  [[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || fail
  [[ "${TWO_WORKING_SESSIONS_PROVEN:-}" == yes ]] || fail
fi

canonical_existing_path() {
  local candidate="$1" resolved current
  [[ "${candidate}" == /* ]] || return 1
  resolved="$(readlink -e -- "${candidate}")" || return 1
  [[ "${candidate}" == "${resolved}" ]] || return 1
  current="${candidate}"
  while [[ "${current}" != / ]]; do
    [[ ! -L "${current}" ]] || return 1
    current="$(dirname -- "${current}")"
  done
}

copy_stable_file() {
  local source="$1" destination="$2" state descriptor
  canonical_existing_path "${source}" || return 1
  [[ -f "${source}" && "$(stat -c %h -- "${source}")" == 1 ]] || return 1
  state="$(stat -c '%d:%i:%f:%h:%s:%Y' -- "${source}")" || return 1
  exec {descriptor}<"${source}" || return 1
  [[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y' -- "/proc/$$/fd/${descriptor}")" == "${state}" ]] || return 1
  command cat <&"${descriptor}" > "${destination}" || return 1
  [[ "$(stat -c '%d:%i:%f:%h:%s:%Y' -- "${source}")" == "${state}" ]] || return 1
  [[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y' -- "/proc/$$/fd/${descriptor}")" == "${state}" ]] || return 1
  exec {descriptor}<&-
}

temporary=''
cleanup() {
  if [[ -n "${temporary}" && -d "${temporary}" && ! -L "${temporary}" ]]; then
    if [[ "${mode}" == --generate ]]; then
      case "${temporary}" in
        /tmp/flux-generate.*) rm -rf -- "${temporary}" ;;
        *) printf 'Refusing ambiguous Flux generation cleanup target.\n' >&2; return 1 ;;
      esac
    else
      case "${temporary}" in
        "${workspace}"/flux-target.*) rm -rf -- "${temporary}" ;;
        *) printf 'Refusing ambiguous Flux target cleanup path.\n' >&2; return 1 ;;
      esac
    fi
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "${mode}" == --generate ]]; then
  : "${FLUX_BINARY:?Set the absolute verified Flux Linux AMD64 executable}"
  flux_source="${FLUX_BINARY}"
  canonical_existing_path "${flux_source}" || fail
  [[ -x "${flux_source}" && ! -L "${flux_source}" ]] || fail
  flux_mode="$(stat -c %a -- "${flux_source}")" || fail
  (( (8#${flux_mode} & 0022) == 0 )) || fail
  temporary="$(mktemp -d /tmp/flux-generate.XXXXXX)" || fail
  chmod 700 "${temporary}"
  flux="${temporary}/flux"
  generated="${temporary}/gotk-components.yaml"
  copy_stable_file "${flux_source}" "${flux}" || fail
  chmod 700 "${flux}"
  [[ "$(sha256sum -- "${flux}" | awk '{print $1}')" == "${FLUX_LINUX_AMD64_SHA256}" ]] || fail
  [[ "$("${flux}" version --client 2>/dev/null | awk '/flux:/ {print $2}')" == "${FLUX_VERSION}" ]] || fail
  "${flux}" install --version="${FLUX_VERSION}" --namespace=flux-system \
    --components=source-controller,kustomize-controller,helm-controller \
    --network-policy=true --export > "${generated}" || fail
  COMPONENTS_PATH="${generated}" \
  SOURCE_IMAGE="${FLUX_SOURCE_CONTROLLER_IMAGE}" \
  KUSTOMIZE_IMAGE="${FLUX_KUSTOMIZE_CONTROLLER_IMAGE}" \
  HELM_IMAGE="${FLUX_HELM_CONTROLLER_IMAGE}" \
    "${python3_binary}" -I - <<'PY' || fail
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
        raise SystemExit(1)
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
PY
  [[ "$(sha256sum -- "${flux}" | awk '{print $1}')" == "${FLUX_LINUX_AMD64_SHA256}" ]] || fail
  install -m 0644 "${generated}" "${components}" || fail
  printf 'PASS generated reviewed Flux controller desired state; no cluster or Git state changed.\n'
  exit 0
fi

for ambient_name in KUBECONFIG HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy KUBECTL_PLUGINS_PATH KUBECTL_EXTERNAL_DIFF; do
  [[ -z "${!ambient_name+x}" ]] || fail
done
unset KUBECONFIG HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy KUBECTL_PLUGINS_PATH KUBECTL_EXTERNAL_DIFF
while IFS= read -r authority_name; do
  case "${authority_name}" in
    SOPS_AGE_IDENTITY_FILE|SOPS_AGE_SECONDARY_IDENTITY_FILE|SOPS_AGE_TWO_BACKUPS_RESTORE_TESTED) ;;
    AWS_*|AZURE_*|GOOGLE_*|GCP_*|HCLOUD_*|VAULT_*|TF_*|TOFU_*|\
    GH_*|GITHUB_*|GIT_*|GCM_*|SSH_*|CF_*|CLOUDFLARE_*|SOPS_*) fail ;;
  esac
done < <(builtin compgen -e)

git_binary="$(readlink -e -- /usr/bin/git)" || fail
[[ "${git_binary}" == /usr/bin/git ]] || fail
[[ -f "${git_binary}" && ! -L "${git_binary}" && -x "${git_binary}" ]] || fail
[[ "$(stat -c '%u:%h' -- "${git_binary}")" == 0:1 ]] || fail
git_mode="$(stat -c %a -- "${git_binary}")" || fail
(( (8#${git_mode} & 0022) == 0 )) || fail

git_repo() {
  env -i PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 "${git_binary}" --no-replace-objects \
    -c credential.helper= -c core.askPass= -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null -C "${repo_root}" "$@"
}
: "${CREDENTIAL_WORKSPACE:?Set the protected POSIX credential workspace root}"
: "${KUBECONFIG_FILE:?Set the protected flattened JSON kubeconfig file}"
: "${KUBECTL_BINARY:?Set the protected pinned kubectl executable}"
: "${EXPECTED_KUBECONFIG_CONTEXT:?Set the exact reviewed kubectl context}"
: "${EXPECTED_KUBERNETES_SERVER:?Set the exact reviewed Kubernetes API URL}"
: "${EXPECTED_PI_NODE_NAME:?Set the exact reviewed single Pi node name}"
: "${EXPECTED_REPOSITORY_HEAD:?Set the exact reviewed main commit}"
: "${EXPECTED_KUBERNETES_CA_SHA256:?Set the reviewed embedded Kubernetes CA DER hash}"
: "${EXPECTED_KUBE_SYSTEM_NAMESPACE_UID_SHA256:?Set the reviewed kube-system UID hash}"
[[ "${EXPECTED_REPOSITORY_HEAD}" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "${EXPECTED_KUBERNETES_CA_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "${EXPECTED_KUBE_SYSTEM_NAMESPACE_UID_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
workspace="${CREDENTIAL_WORKSPACE}"
kubeconfig_source="${KUBECONFIG_FILE}"
kubectl_source="${KUBECTL_BINARY}"
canonical_existing_path "${workspace}" || fail
[[ -d "${workspace}" ]] || fail
operator_uid="$(id -u)" || fail
workspace_gid="$(stat -c %g -- "${workspace}")" || fail
[[ "$(stat -c '%u:%a' -- "${workspace}")" == "${operator_uid}:700" ]] || fail

temporary="$(mktemp -d "${workspace%/}/flux-target.XXXXXX")" || fail
chmod 700 "${temporary}"
kubeconfig="${temporary}/kubeconfig.json"
kubectl="${temporary}/kubectl"
kube_system_uid="${temporary}/kube-system-uid"
staged_repo="${temporary}/repository"
mkdir -m 700 "${staged_repo}"

bootstrap_source="$(readlink -e -- "${BASH_SOURCE[0]}")" || fail
[[ "${bootstrap_source}" == "${repo_root}/bootstrap/flux/bootstrap.sh" ]] || fail
[[ -d "${repo_root}/.git" && ! -L "${repo_root}/.git" ]] || fail
[[ ! -e "${repo_root}/.git/info/grafts" ]] || fail
[[ "$(git_repo rev-parse --show-toplevel)" == "${repo_root}" ]] || fail
[[ "$(git_repo rev-parse --verify 'HEAD^{commit}')" == "${EXPECTED_REPOSITORY_HEAD}" ]] || fail
[[ "$(git_repo symbolic-ref -q HEAD)" == refs/heads/main ]] || fail
[[ -z "$(git_repo for-each-ref --format='%(refname)' refs/replace)" ]] || fail
git_repo diff --quiet --no-ext-diff || fail
git_repo diff --cached --quiet --no-ext-diff || fail

critical_inventory='100755 bootstrap/flux/bootstrap.sh
100755 bootstrap/flux/verify-sops-age-secret.sh
100644 scripts/validate_kubeconfig_snapshot.py
100644 versions.env'
actual_critical_inventory="$(git_repo ls-tree "${EXPECTED_REPOSITORY_HEAD}" -- \
  bootstrap/flux/bootstrap.sh \
  bootstrap/flux/verify-sops-age-secret.sh \
  scripts/validate_kubeconfig_snapshot.py \
  versions.env | awk '{ mode=$1; sub(/^[^\t]*\t/, ""); print mode " " $0 }')" || fail
[[ "${actual_critical_inventory}" == "${critical_inventory}" ]] || fail
critical_snapshots="${temporary}/critical-snapshots"
mkdir -m 700 "${critical_snapshots}"
while IFS=' ' read -r critical_mode critical_path; do
  [[ "${critical_mode}" == 100644 || "${critical_mode}" == 100755 ]] || fail
  critical_source="${repo_root}/${critical_path}"
  [[ -f "${critical_source}" && ! -L "${critical_source}" ]] || fail
  critical_name="${critical_path//\//_}"
  critical_worktree_copy="${critical_snapshots}/${critical_name}.worktree"
  critical_blob_copy="${critical_snapshots}/${critical_name}.blob"
  copy_stable_file "${critical_source}" "${critical_worktree_copy}" || fail
  git_repo cat-file blob "${EXPECTED_REPOSITORY_HEAD}:${critical_path}" \
    > "${critical_blob_copy}" || fail
  chmod 600 "${critical_worktree_copy}" "${critical_blob_copy}"
  cmp -s -- "${critical_worktree_copy}" "${critical_blob_copy}" || fail
done <<< "${critical_inventory}"

snapshot_protected_file() {
  local source="$1" destination="$2" class="$3" mode_bits
  canonical_existing_path "${source}" || return 1
  case "${source}" in "${workspace}"/*) ;; *) return 1 ;; esac
  mode_bits="$(stat -c %a -- "${source}")" || return 1
  if [[ "${class}" == data ]]; then
    [[ "${mode_bits}" == 400 || "${mode_bits}" == 600 ]] || return 1
  else
    [[ "${mode_bits}" == 500 || "${mode_bits}" == 700 ]] || return 1
  fi
  [[ "$(stat -c '%u:%g:%h' -- "${source}")" == "${operator_uid}:${workspace_gid}:1" ]] || return 1
  copy_stable_file "${source}" "${destination}" || return 1
  if [[ "${class}" == data ]]; then chmod 600 "${destination}"; else chmod 700 "${destination}"; fi
}

snapshot_protected_file "${kubeconfig_source}" "${kubeconfig}" data || fail
snapshot_protected_file "${kubectl_source}" "${kubectl}" executable || fail
kubeconfig_digest="$(sha256sum -- "${kubeconfig}" | awk '{print $1}')" || fail
[[ "$(sha256sum -- "${kubectl}" | awk '{print $1}')" == "${KUBECTL_LINUX_AMD64_SHA256}" ]] || fail
[[ -f "${kubeconfig_validator}" && ! -L "${kubeconfig_validator}" ]] || fail
KUBECONFIG_SNAPSHOT_FILE="${kubeconfig}" \
  "${python3_binary}" -I "${kubeconfig_validator}" >/dev/null || fail
KUBECONFIG_SNAPSHOT_FILE="${kubeconfig}" \
EXPECTED_KUBERNETES_CA_SHA256="${EXPECTED_KUBERNETES_CA_SHA256}" \
  "${python3_binary}" -I - <<'PY_KUBERNETES_CA' || fail
import base64
import binascii
import hashlib
import hmac
import json
import os
import re


try:
    with open(os.environ["KUBECONFIG_SNAPSHOT_FILE"], "rb") as stream:
        document = json.load(stream)
    encoded_pem = document["clusters"][0]["cluster"]["certificate-authority-data"]
    pem = base64.b64decode(encoded_pem, validate=True).decode("ascii")
    match = re.fullmatch(
        r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n",
        pem,
    )
    if match is None:
        raise ValueError()
    der_text = match.group(1).replace("\n", "")
    der = base64.b64decode(der_text, validate=True)
    expected = os.environ["EXPECTED_KUBERNETES_CA_SHA256"]
    if not der or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), expected):
        raise ValueError()
except (OSError, KeyError, IndexError, TypeError, UnicodeError, ValueError, json.JSONDecodeError, binascii.Error):
    raise SystemExit(1)
PY_KUBERNETES_CA
kubectl_client="$("${kubectl}" version --client -o yaml 2>/dev/null)" || fail
[[ "$(printf '%s\n' "${kubectl_client}" | grep -c "^[[:space:]]*gitVersion: ${KUBERNETES_VERSION}$")" -eq 1 ]] || fail
kubectl_config_args=(--kubeconfig="${kubeconfig}" --context="${EXPECTED_KUBECONFIG_CONTEXT}")
kubectl_target_args=("${kubectl_config_args[@]}" --server="${EXPECTED_KUBERNETES_SERVER}" --request-timeout=15s)

verify_cluster_target() {
  local actual_context actual_server node_names
  actual_context="$("${kubectl}" --kubeconfig="${kubeconfig}" config current-context 2>/dev/null)" || return 1
  actual_server="$("${kubectl}" "${kubectl_config_args[@]}" config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)" || return 1
  node_names="$("${kubectl}" "${kubectl_target_args[@]}" get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)" || return 1
  : > "${kube_system_uid}"
  "${kubectl}" "${kubectl_target_args[@]}" get namespace kube-system \
    -o go-template='{{.metadata.uid}}{{"\n"}}' > "${kube_system_uid}" 2>/dev/null || return 1
  [[ "${actual_context}" == "${EXPECTED_KUBECONFIG_CONTEXT}" ]] || return 1
  [[ "${actual_server}" == "${EXPECTED_KUBERNETES_SERVER}" ]] || return 1
  [[ "${node_names}" == "${EXPECTED_PI_NODE_NAME}" ]] || return 1
  [[ "$(stat -c '%u:%g:%a:%h:%s' -- "${kube_system_uid}")" == "${operator_uid}:${workspace_gid}:600:1:37" ]] || return 1
  grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "${kube_system_uid}" || return 1
  [[ "$(sha256sum -- "${kube_system_uid}" | awk '{print $1}')" == "${EXPECTED_KUBE_SYSTEM_NAMESPACE_UID_SHA256}" ]] || return 1
  [[ "$(sha256sum -- "${kubeconfig}" | awk '{print $1}')" == "${kubeconfig_digest}" ]] || return 1
  [[ "$(sha256sum -- "${kubectl}" | awk '{print $1}')" == "${KUBECTL_LINUX_AMD64_SHA256}" ]] || return 1
}

verify_cluster_target || fail

if [[ "${mode}" == --apply-controllers || "${mode}" == --apply-sync || "${mode}" == --verify ]]; then
  expected_inventory='100644 kubernetes/flux-system/access.yaml
100644 kubernetes/flux-system/controllers/gotk-components.yaml
100644 kubernetes/flux-system/controllers/kustomization.yaml
100644 kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml
100644 kubernetes/flux-system/controllers/patches/crd-controller-binding.yaml
100644 kubernetes/flux-system/controllers/patches/crd-controller-role.yaml
100644 kubernetes/flux-system/controllers/patches/helm-controller.yaml
100644 kubernetes/flux-system/controllers/patches/kustomize-controller.yaml
100644 kubernetes/flux-system/controllers/patches/source-controller.yaml
100644 kubernetes/flux-system/gotk-sync.yaml
100644 kubernetes/platform/prerequisites/namespaces.yaml'
  actual_inventory="$(git_repo ls-tree -r "${EXPECTED_REPOSITORY_HEAD}" -- \
    kubernetes/flux-system/access.yaml \
    kubernetes/flux-system/controllers \
    kubernetes/flux-system/gotk-sync.yaml \
    kubernetes/platform/prerequisites/namespaces.yaml | \
    awk '{ mode=$1; sub(/^[^\t]*\t/, ""); print mode " " $0 }')" || fail
  [[ "${actual_inventory}" == "${expected_inventory}" ]] || fail
  manifest_archive="${temporary}/manifests.tar"
  git_repo archive --format=tar --output="${manifest_archive}" \
    "${EXPECTED_REPOSITORY_HEAD}" -- \
    kubernetes/flux-system/access.yaml \
    kubernetes/flux-system/controllers \
    kubernetes/flux-system/gotk-sync.yaml \
    kubernetes/platform/prerequisites/namespaces.yaml || fail
  chmod 600 "${manifest_archive}"
  manifest_digest="$(sha256sum -- "${manifest_archive}" | awk '{print $1}')" || fail
  tar --no-same-owner --no-same-permissions -xf "${manifest_archive}" -C "${staged_repo}" || fail
  [[ "$(sha256sum -- "${manifest_archive}" | awk '{print $1}')" == "${manifest_digest}" ]] || fail
fi

verify_remote_main() {
  local remote_result="${temporary}/remote-main.ref"
  local remote_stderr="${temporary}/remote-main.stderr"
  : > "${remote_result}"
  : > "${remote_stderr}"
  env -i PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 GIT_CEILING_DIRECTORIES="${temporary}" \
    "${git_binary}" --no-replace-objects -c credential.helper= -c core.askPass= \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null -C "${temporary}" \
    ls-remote --refs --exit-code \
    https://github.com/snaraj/website-infrastructure.git refs/heads/main \
    > "${remote_result}" 2> "${remote_stderr}" || return 1
  chmod 600 "${remote_result}" "${remote_stderr}"
  [[ "$(stat -c '%u:%g:%a:%h:%s' -- "${remote_result}")" == \
    "${operator_uid}:${workspace_gid}:600:1:57" ]] || return 1
  [[ "$(stat -c '%u:%g:%a:%h:%s' -- "${remote_stderr}")" == \
    "${operator_uid}:${workspace_gid}:600:1:0" ]] || return 1
  REMOTE_MAIN_RESULT="${remote_result}" \
  EXPECTED_REPOSITORY_HEAD="${EXPECTED_REPOSITORY_HEAD}" \
    "${python3_binary}" -I - <<'PY_REMOTE_MAIN' || return 1
import hmac
import os
import re


try:
    with open(os.environ["REMOTE_MAIN_RESULT"], "rb") as stream:
        value = stream.read()
    match = re.fullmatch(rb"([0-9a-f]{40})\trefs/heads/main\n", value)
    if match is None or not hmac.compare_digest(
        match.group(1).decode("ascii"), os.environ["EXPECTED_REPOSITORY_HEAD"]
    ):
        raise ValueError()
except (OSError, UnicodeError, ValueError):
    raise SystemExit(1)
PY_REMOTE_MAIN
}

if [[ "${mode}" == --apply-sync || "${mode}" == --verify ]]; then
  verify_remote_main || fail
fi

verify_reviewed_live_state() {
  local scope="$1" live="${temporary}/live-state-${1}"
  local diff_output diff_stderr live_stderr
  [[ "${scope}" == controllers || "${scope}" == full ]] || return 1
  [[ ! -e "${live}" ]] || return 1
  mkdir -m 700 "${live}" || return 1
  diff_output="${live}/desired-state.diff"
  diff_stderr="${live}/desired-state.stderr"
  live_stderr="${live}/kubectl.stderr"
  : > "${diff_output}"
  : > "${diff_stderr}"
  : > "${live_stderr}"
  chmod 600 "${diff_output}" "${diff_stderr}" "${live_stderr}"

  [[ -f /usr/bin/diff && ! -L /usr/bin/diff && -x /usr/bin/diff ]] || return 1
  [[ "$(stat -c '%u:%h' -- /usr/bin/diff)" == 0:1 ]] || return 1
  local diff_mode
  diff_mode="$(stat -c %a -- /usr/bin/diff)" || return 1
  (( (8#${diff_mode} & 0022) == 0 )) || return 1

  TMPDIR="${live}" KUBECTL_EXTERNAL_DIFF='/usr/bin/diff -u -N' \
    "${kubectl}" "${kubectl_target_args[@]}" diff \
      --field-manager=kubectl-client-side-apply \
      -k "${staged_repo}/kubernetes/flux-system/controllers" \
      >> "${diff_output}" 2>> "${diff_stderr}" || return 1
  if [[ "${scope}" == full ]]; then
    local manifest
    for manifest in \
      kubernetes/platform/prerequisites/namespaces.yaml \
      kubernetes/flux-system/access.yaml \
      kubernetes/flux-system/gotk-sync.yaml; do
      TMPDIR="${live}" KUBECTL_EXTERNAL_DIFF='/usr/bin/diff -u -N' \
        "${kubectl}" "${kubectl_target_args[@]}" diff \
          --field-manager=kubectl-client-side-apply \
          -f "${staged_repo}/${manifest}" \
          >> "${diff_output}" 2>> "${diff_stderr}" || return 1
    done
  fi
  [[ ! -s "${diff_output}" ]] || return 1

  capture_live_json() {
    local destination="$1"
    shift
    : > "${destination}"
    "${kubectl}" "${kubectl_target_args[@]}" "$@" -o json \
      > "${destination}" 2>> "${live_stderr}" || return 1
    chmod 600 "${destination}"
    [[ -s "${destination}" ]] || return 1
    [[ "$(stat -c '%u:%g:%a:%h' -- "${destination}")" == \
      "${operator_uid}:${workspace_gid}:600:1" ]] || return 1
  }

  local live_deployments="${live}/deployments.json"
  local live_service_accounts="${live}/service-accounts.json"
  local live_roles="${live}/roles.json"
  local live_role_bindings="${live}/role-bindings.json"
  local live_cluster_roles="${live}/cluster-roles.json"
  local live_cluster_role_bindings="${live}/cluster-role-bindings.json"
  local live_namespaces="${live}/namespaces.json"
  local live_git_repository="${live}/git-repository.json"
  local live_kustomization="${live}/kustomization.json"
  capture_live_json "${live_deployments}" -n flux-system get deployments || return 1
  capture_live_json "${live_service_accounts}" get serviceaccounts --all-namespaces || return 1
  capture_live_json "${live_roles}" get roles --all-namespaces || return 1
  capture_live_json "${live_role_bindings}" get rolebindings --all-namespaces || return 1
  capture_live_json "${live_cluster_roles}" get clusterroles || return 1
  capture_live_json "${live_cluster_role_bindings}" get clusterrolebindings || return 1
  if [[ "${scope}" == full ]]; then
    capture_live_json "${live_namespaces}" get namespaces flux-system \
      cloudflare-public naranjo-online lidersea-com kyverno || return 1
    capture_live_json "${live_git_repository}" -n flux-system get \
      gitrepository flux-system || return 1
    capture_live_json "${live_kustomization}" -n flux-system get \
      kustomization flux-system || return 1
  else
    capture_live_json "${live_namespaces}" get namespace flux-system || return 1
  fi

  FLUX_LIVE_SCOPE="${scope}" \
  FLUX_LIVE_DEPLOYMENTS="${live_deployments}" \
  FLUX_LIVE_SERVICE_ACCOUNTS="${live_service_accounts}" \
  FLUX_LIVE_ROLES="${live_roles}" \
  FLUX_LIVE_ROLE_BINDINGS="${live_role_bindings}" \
  FLUX_LIVE_CLUSTER_ROLES="${live_cluster_roles}" \
  FLUX_LIVE_CLUSTER_ROLE_BINDINGS="${live_cluster_role_bindings}" \
  FLUX_LIVE_NAMESPACES="${live_namespaces}" \
  FLUX_LIVE_GIT_REPOSITORY="${live_git_repository}" \
  FLUX_LIVE_KUSTOMIZATION="${live_kustomization}" \
  FLUX_EXPECTED_VERSION="${FLUX_VERSION}" \
  FLUX_EXPECTED_SOURCE_IMAGE="${FLUX_SOURCE_CONTROLLER_IMAGE}" \
  FLUX_EXPECTED_KUSTOMIZE_IMAGE="${FLUX_KUSTOMIZE_CONTROLLER_IMAGE}" \
  FLUX_EXPECTED_HELM_IMAGE="${FLUX_HELM_CONTROLLER_IMAGE}" \
    "${python3_binary}" -I - <<'PY_FLUX_LIVE_STATE' 2>> "${live_stderr}" || return 1
import copy
import json
import os
import re


class ContractError(Exception):
    pass


def require(condition):
    if not condition:
        raise ContractError()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(isinstance(key, str) and key not in result)
        result[key] = value
    return result


def load(name):
    with open(os.environ[name], "rb") as stream:
        raw = stream.read()
    require(raw and len(raw) <= 16 * 1024 * 1024)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)


def items(document):
    require(isinstance(document, dict))
    if document.get("kind", "").endswith("List"):
        result = document.get("items")
        require(isinstance(result, list))
        return result
    return [document]


def index(document, kind, namespaced=True):
    result = {}
    for value in items(document):
        require(isinstance(value, dict) and value.get("kind") == kind)
        metadata = value.get("metadata")
        require(isinstance(metadata, dict))
        name = metadata.get("name")
        namespace = metadata.get("namespace") if namespaced else None
        require(isinstance(name, str) and name)
        if namespaced:
            require(isinstance(namespace, str) and namespace)
        key = (namespace, name) if namespaced else name
        require(key not in result)
        result[key] = value
    return result


LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"
FLUX_FINALIZER = "finalizers.fluxcd.io"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def check_metadata(
    value,
    name,
    namespace,
    labels,
    annotations=None,
    allow_deployment_revision=False,
    allow_flux_finalizer=False,
    require_last_applied=True,
):
    require(isinstance(value, dict))
    allowed = {
        "name", "namespace", "uid", "resourceVersion", "generation",
        "creationTimestamp", "managedFields", "labels", "annotations", "finalizers",
    }
    require(set(value) <= allowed)
    require(value.get("name") == name and value.get("namespace") == namespace)
    require(value.get("labels", {}) == labels)
    actual_annotations = copy.deepcopy(value.get("annotations", {}))
    require(isinstance(actual_annotations, dict))
    last_applied = actual_annotations.pop(LAST_APPLIED, None)
    if require_last_applied:
        require(isinstance(last_applied, str) and last_applied)
    else:
        require(last_applied is None)
    if allow_deployment_revision:
        revision = actual_annotations.pop("deployment.kubernetes.io/revision", None)
        require(isinstance(revision, str) and re.fullmatch(r"[1-9][0-9]*", revision))
    require(actual_annotations == (annotations or {}))
    finalizers = value.get("finalizers", [])
    require(isinstance(finalizers, list))
    if allow_flux_finalizer:
        require(finalizers in ([], [FLUX_FINALIZER]))
    else:
        require(finalizers == [])
    uid = value.get("uid")
    require(isinstance(uid, str) and UUID.fullmatch(uid))
    resource_version = value.get("resourceVersion")
    require(isinstance(resource_version, str) and re.fullmatch(r"[1-9][0-9]*", resource_version))
    require(isinstance(value.get("creationTimestamp"), str))
    if "generation" in value:
        require(type(value["generation"]) is int and value["generation"] >= 1)
    if "managedFields" in value:
        require(isinstance(value["managedFields"], list))


def flux_labels(component=None, control_plane=False):
    result = {
        "app.kubernetes.io/instance": "flux-system",
        "app.kubernetes.io/part-of": "flux",
        "app.kubernetes.io/version": os.environ["FLUX_EXPECTED_VERSION"],
    }
    if component is not None:
        result["app.kubernetes.io/component"] = component
    if control_plane:
        result["control-plane"] = "controller"
    return result


def normalize_probe(probe):
    result = copy.deepcopy(probe)
    for key, expected in {
        "failureThreshold": 3,
        "periodSeconds": 10,
        "successThreshold": 1,
        "timeoutSeconds": 1,
    }.items():
        if result.get(key) == expected:
            result.pop(key)
    http_get = result.get("httpGet")
    if isinstance(http_get, dict) and http_get.get("scheme") == "HTTP":
        http_get.pop("scheme")
    return result


def normalize_container(container):
    result = copy.deepcopy(container)
    if result.get("terminationMessagePath") == "/dev/termination-log":
        result.pop("terminationMessagePath")
    if result.get("terminationMessagePolicy") == "File":
        result.pop("terminationMessagePolicy")
    for probe_name in ("livenessProbe", "readinessProbe"):
        if probe_name in result:
            result[probe_name] = normalize_probe(result[probe_name])
    for variable in result.get("env", []):
        require(isinstance(variable, dict))
        value_from = variable.get("valueFrom")
        if isinstance(value_from, dict):
            field_ref = value_from.get("fieldRef")
            if isinstance(field_ref, dict) and field_ref.get("apiVersion") == "v1":
                field_ref.pop("apiVersion")
            resource_ref = value_from.get("resourceFieldRef")
            if isinstance(resource_ref, dict) and resource_ref.get("divisor") in ("0", "1"):
                resource_ref.pop("divisor")
    resources = result.get("resources")
    if isinstance(resources, dict):
        limits = resources.get("limits")
        if isinstance(limits, dict) and limits.get("cpu") == "1":
            limits["cpu"] = "1000m"
    return result


def normalize_pod_spec(pod_spec):
    result = copy.deepcopy(pod_spec)
    for key, expected in {
        "dnsPolicy": "ClusterFirst",
        "restartPolicy": "Always",
        "schedulerName": "default-scheduler",
        "enableServiceLinks": True,
    }.items():
        if result.get(key) == expected:
            result.pop(key)
    if result.get("serviceAccount") == result.get("serviceAccountName"):
        result.pop("serviceAccount")
    containers = result.get("containers")
    require(isinstance(containers, list))
    result["containers"] = [normalize_container(value) for value in containers]
    return result


def controller_container(name, image, extra_args, source=False):
    arguments = [
        "--events-addr=",
        "--watch-all-namespaces=true",
        "--log-level=info",
        "--log-encoding=json",
        "--enable-leader-election",
    ]
    if source:
        arguments += [
            "--storage-path=/data",
            "--storage-adv-addr=source-controller.$(RUNTIME_NAMESPACE).svc.cluster.local.",
        ]
    arguments += extra_args
    environment = [
        {
            "name": "RUNTIME_NAMESPACE",
            "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}},
        }
    ]
    if source:
        environment.append({"name": "TUF_ROOT", "value": "/tmp/.sigstore"})
    environment.append(
        {
            "name": "GOMEMLIMIT",
            "valueFrom": {
                "resourceFieldRef": {
                    "containerName": "manager",
                    "resource": "limits.memory",
                }
            },
        }
    )
    ports = [{"containerPort": 8080, "name": "http-prom", "protocol": "TCP"}]
    if source:
        ports.insert(0, {"containerPort": 9090, "name": "http", "protocol": "TCP"})
    ports.append({"containerPort": 9440, "name": "healthz", "protocol": "TCP"})
    resources = {
        "limits": {"cpu": "1000m", "memory": "1Gi"},
        "requests": {"cpu": "50m" if source else "100m", "memory": "64Mi"},
    }
    if source:
        resources["limits"]["ephemeral-storage"] = "1Gi"
        resources["requests"]["ephemeral-storage"] = "128Mi"
    return {
        "args": arguments,
        "env": environment,
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "livenessProbe": {"httpGet": {"path": "/healthz", "port": "healthz"}},
        "name": "manager",
        "ports": ports,
        "readinessProbe": {
            "httpGet": {"path": "/" if source else "/readyz", "port": "http" if source else "healthz"}
        },
        "resources": resources,
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "volumeMounts": (
            [{"mountPath": "/data", "name": "data"}, {"mountPath": "/tmp", "name": "tmp"}]
            if source else [{"mountPath": "/tmp", "name": "temp"}]
        ),
    }


def expected_pod(name, image, extra_args, source, grace):
    return {
        "containers": [controller_container(name, image, extra_args, source)],
        "nodeSelector": {"kubernetes.io/os": "linux"},
        "priorityClassName": "system-cluster-critical",
        "securityContext": {
            "fsGroup": 1337,
            "runAsNonRoot": True,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "serviceAccountName": name,
        "terminationGracePeriodSeconds": grace,
        "volumes": (
            [
                {"emptyDir": {"sizeLimit": "768Mi"}, "name": "data"},
                {"emptyDir": {"sizeLimit": "128Mi"}, "name": "tmp"},
            ]
            if source else [{"emptyDir": {}, "name": "temp"}]
        ),
    }


def check_deployments(document):
    actual = index(document, "Deployment")
    expected = {
        "source-controller": (
            os.environ["FLUX_EXPECTED_SOURCE_IMAGE"],
            ["--no-cross-namespace-refs=true"],
            True,
            10,
        ),
        "kustomize-controller": (
            os.environ["FLUX_EXPECTED_KUSTOMIZE_IMAGE"],
            [
                "--no-cross-namespace-refs=true",
                "--no-remote-bases=true",
                "--default-service-account=default",
            ],
            False,
            60,
        ),
        "helm-controller": (
            os.environ["FLUX_EXPECTED_HELM_IMAGE"],
            ["--no-cross-namespace-refs=true", "--default-service-account=default"],
            False,
            600,
        ),
    }
    require(set(actual) == {("flux-system", name) for name in expected})
    for name, (image, extra_args, source, grace) in expected.items():
        value = actual[("flux-system", name)]
        require(value.get("apiVersion") == "apps/v1")
        require(set(value) <= {"apiVersion", "kind", "metadata", "spec", "status"})
        check_metadata(
            value.get("metadata"),
            name,
            "flux-system",
            flux_labels(name, True),
            allow_deployment_revision=True,
        )
        spec = copy.deepcopy(value.get("spec"))
        require(isinstance(spec, dict))
        for key, expected_default in {
            "progressDeadlineSeconds": 600,
            "revisionHistoryLimit": 10,
            "paused": False,
        }.items():
            if spec.get(key) == expected_default:
                spec.pop(key)
        if not source and spec.get("strategy") == {
            "rollingUpdate": {"maxSurge": "25%", "maxUnavailable": "25%"},
            "type": "RollingUpdate",
        }:
            spec.pop("strategy")
        template = spec.get("template")
        require(isinstance(template, dict) and set(template) == {"metadata", "spec"})
        template_metadata = copy.deepcopy(template["metadata"])
        if template_metadata.get("creationTimestamp") is None:
            template_metadata.pop("creationTimestamp", None)
        template["metadata"] = template_metadata
        require(
            template_metadata
            == {
                "annotations": {"prometheus.io/port": "8080", "prometheus.io/scrape": "true"},
                "labels": {"app": name, **flux_labels(name)},
            }
        )
        template["spec"] = normalize_pod_spec(template["spec"])
        expected_spec = {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": template_metadata,
                "spec": expected_pod(name, image, extra_args, source, grace),
            },
        }
        if source:
            expected_spec["strategy"] = {"type": "Recreate"}
        require(spec == expected_spec)


CONTROLLER_NAMES = {"source-controller", "kustomize-controller", "helm-controller"}
FLUX_ACCESS_NAMES = {
    "default",
    "root-reconciler",
    "platform-prerequisites-reconciler",
    "admission-reconciler",
    "platform-services-reconciler",
    "naranjo-online-reconciler",
    "lidersea-com-reconciler",
}
ACCESS_SERVICE_ACCOUNTS = {
    ("flux-system", name) for name in FLUX_ACCESS_NAMES
} | {
    ("cloudflare-public", "default"),
    ("cloudflare-public", "helm-reconciler"),
    ("naranjo-online", "default"),
    ("naranjo-online", "helm-reconciler"),
    ("lidersea-com", "default"),
    ("lidersea-com", "helm-reconciler"),
    ("kyverno", "default"),
}
CONTROLLER_SERVICE_ACCOUNTS = {("flux-system", name) for name in CONTROLLER_NAMES}
PROTECTED_SERVICE_ACCOUNTS = ACCESS_SERVICE_ACCOUNTS | CONTROLLER_SERVICE_ACCOUNTS


def check_service_account(value, namespace, name, controller=False):
    require(value.get("apiVersion") == "v1")
    require(set(value) <= {"apiVersion", "kind", "metadata", "automountServiceAccountToken"})
    check_metadata(
        value.get("metadata"),
        name,
        namespace,
        flux_labels(name) if controller else {},
    )
    if controller:
        require("automountServiceAccountToken" not in value)
    else:
        require(value.get("automountServiceAccountToken") is False)


def check_pristine_namespace_default_service_account(value):
    require(value.get("apiVersion") == "v1")
    require(set(value) == {"apiVersion", "kind", "metadata"})
    check_metadata(
        value.get("metadata"),
        "default",
        "flux-system",
        {},
        require_last_applied=False,
    )


def check_service_accounts(document, scope):
    actual = index(document, "ServiceAccount")
    for key in CONTROLLER_SERVICE_ACCOUNTS:
        require(key in actual)
        check_service_account(actual[key], key[0], key[1], controller=True)
    if scope == "full":
        for key in ACCESS_SERVICE_ACCOUNTS:
            require(key in actual)
            check_service_account(actual[key], key[0], key[1])
    else:
        for key in ACCESS_SERVICE_ACCOUNTS & set(actual):
            if key == ("flux-system", "default") and actual[key].get(
                "automountServiceAccountToken"
            ) is not False:
                check_pristine_namespace_default_service_account(actual[key])
            else:
                check_service_account(actual[key], key[0], key[1])


def rule(api_groups=None, resources=None, verbs=None, non_resource_urls=None, resource_names=None):
    result = {"verbs": verbs or []}
    if api_groups is not None:
        result["apiGroups"] = api_groups
    if resources is not None:
        result["resources"] = resources
    if non_resource_urls is not None:
        result["nonResourceURLs"] = non_resource_urls
    if resource_names is not None:
        result["resourceNames"] = resource_names
    return result


def normalize_rules(rules):
    require(isinstance(rules, list))
    result = []
    allowed = {"apiGroups", "resources", "resourceNames", "verbs", "nonResourceURLs"}
    for value in rules:
        require(isinstance(value, dict) and set(value) <= allowed)
        normalized = {}
        for key, member in value.items():
            require(isinstance(member, list) and all(isinstance(item, str) for item in member))
            normalized[key] = sorted(member)
        result.append(json.dumps(normalized, sort_keys=True, separators=(",", ":")))
    return sorted(result)


def cluster_role_rules():
    # The narrowed shared ClusterRole (AUDIT S12). This mirrors
    # kubernetes/flux-system/controllers/patches/crd-controller-role.yaml rule
    # for rule: the generated wildcards, the cluster-wide Secret read, and
    # `serviceaccounts/token` creation are gone, and what remains is the
    # authority the three controllers exercise under their own identity. A live
    # cluster still carrying the generated rules fails this verifier.
    source_kinds = [
        "buckets",
        "externalartifacts",
        "gitrepositories",
        "helmrepositories",
        "ocirepositories",
    ]
    all_source_kinds = sorted(source_kinds + ["helmcharts"])
    crd = [
        rule(["source.toolkit.fluxcd.io"], source_kinds, ["get", "list", "watch", "update", "patch"]),
        rule(
            ["source.toolkit.fluxcd.io"],
            ["helmcharts"],
            ["get", "list", "watch", "create", "update", "patch", "delete"],
        ),
        rule(
            ["source.toolkit.fluxcd.io"],
            [name + "/status" for name in all_source_kinds],
            ["get", "patch", "update"],
        ),
        rule(
            ["source.toolkit.fluxcd.io"],
            [name + "/finalizers" for name in all_source_kinds],
            ["update"],
        ),
        rule(["kustomize.toolkit.fluxcd.io"], ["kustomizations"], ["get", "list", "watch", "update", "patch"]),
        rule(["kustomize.toolkit.fluxcd.io"], ["kustomizations/status"], ["get", "patch", "update"]),
        rule(["kustomize.toolkit.fluxcd.io"], ["kustomizations/finalizers"], ["update"]),
        rule(["helm.toolkit.fluxcd.io"], ["helmreleases"], ["get", "list", "watch", "update", "patch"]),
        rule(["helm.toolkit.fluxcd.io"], ["helmreleases/status"], ["get", "patch", "update"]),
        rule(["helm.toolkit.fluxcd.io"], ["helmreleases/finalizers"], ["update"]),
        rule([""], ["namespaces", "serviceaccounts", "configmaps"], ["get", "list", "watch"]),
        rule([""], ["events"], ["create", "patch"]),
        rule(verbs=["head"], non_resource_urls=["/livez/ping"]),
    ]
    aggregate_groups = [
        "notification.toolkit.fluxcd.io",
        "source.toolkit.fluxcd.io",
        "source.extensions.fluxcd.io",
        "helm.toolkit.fluxcd.io",
        "image.toolkit.fluxcd.io",
        "kustomize.toolkit.fluxcd.io",
    ]
    return {
        "crd-controller-flux-system": crd,
        "flux-edit-flux-system": [
            rule(aggregate_groups, ["*"], ["create", "delete", "deletecollection", "patch", "update"])
        ],
        "flux-view-flux-system": [rule(aggregate_groups, ["*"], ["get", "list", "watch"])],
    }


def expected_cluster_role_labels(name):
    labels = flux_labels()
    if name in {"flux-edit-flux-system", "flux-view-flux-system"}:
        labels["rbac.authorization.k8s.io/aggregate-to-admin"] = "true"
        labels["rbac.authorization.k8s.io/aggregate-to-edit"] = "true"
    if name == "flux-view-flux-system":
        labels["rbac.authorization.k8s.io/aggregate-to-view"] = "true"
    return labels


def access_role_rules():
    mutate = ["get", "list", "watch", "create", "update", "patch", "delete"]
    prerequisite = [
        rule([""], ["serviceaccounts", "resourcequotas", "limitranges"], mutate),
        rule(["networking.k8s.io"], ["networkpolicies"], mutate),
    ]
    # The connector release still resolves its chart from a Git source; both
    # sites resolve theirs from a signed OCI artifact, so their reconcilers
    # apply an OCIRepository and never a GitRepository.
    git_release = [
        rule(["source.toolkit.fluxcd.io"], ["gitrepositories"], mutate),
        rule(["helm.toolkit.fluxcd.io"], ["helmreleases"], mutate),
    ]
    oci_release = [
        rule(["source.toolkit.fluxcd.io"], ["ocirepositories"], mutate),
        rule(["helm.toolkit.fluxcd.io"], ["helmreleases"], mutate),
    ]
    helm = [
        rule([""], ["configmaps", "secrets", "services", "serviceaccounts"], mutate),
        rule(["apps"], ["deployments"], mutate),
        rule(["networking.k8s.io"], ["networkpolicies"], mutate),
    ]
    # Controller identity. These are the namespaced Roles that replace the
    # deleted cluster-admin binding: leader election and controller-owned
    # ConfigMaps, the SOPS key read, and the name-restricted impersonation
    # grants through which every applied object actually reaches the API.
    controller_runtime = [
        rule(["coordination.k8s.io"], ["leases"], mutate),
        rule([""], ["configmaps"], mutate),
        rule([""], ["configmaps/status"], ["get", "update", "patch"]),
    ]
    return {
        ("flux-system", "flux-controller-runtime"): controller_runtime,
        ("flux-system", "flux-controller-decryption"): [
            rule([""], ["secrets"], ["get", "list", "watch"])
        ],
        ("flux-system", "flux-controller-impersonation"): [
            rule(
                [""],
                ["serviceaccounts"],
                ["impersonate"],
                resource_names=[
                    "root-reconciler",
                    "platform-prerequisites-reconciler",
                    "admission-reconciler",
                    "platform-services-reconciler",
                    "naranjo-online-reconciler",
                    "lidersea-com-reconciler",
                ],
            )
        ],
        ("cloudflare-public", "flux-controller-impersonation"): [
            rule([""], ["serviceaccounts"], ["impersonate"], resource_names=["helm-reconciler"])
        ],
        ("naranjo-online", "flux-controller-impersonation"): [
            rule([""], ["serviceaccounts"], ["impersonate"], resource_names=["helm-reconciler"])
        ],
        ("lidersea-com", "flux-controller-impersonation"): [
            rule([""], ["serviceaccounts"], ["impersonate"], resource_names=["helm-reconciler"])
        ],
        ("flux-system", "root-reconciler"): [
            rule(["kustomize.toolkit.fluxcd.io"], ["kustomizations"], mutate)
        ],
        ("cloudflare-public", "platform-prerequisites-reconciler"): prerequisite,
        ("naranjo-online", "platform-prerequisites-reconciler"): prerequisite,
        ("lidersea-com", "platform-prerequisites-reconciler"): prerequisite,
        ("kyverno", "platform-prerequisites-reconciler"): [
            rule(["networking.k8s.io"], ["networkpolicies"], mutate)
        ],
        ("kyverno", "admission-reconciler"): [
            rule([""], ["configmaps", "services", "serviceaccounts"], mutate),
            rule(["apps"], ["deployments"], mutate),
        ],
        ("cloudflare-public", "flux-release-reconciler"): git_release + [
            rule([""], ["secrets"], mutate)
        ],
        ("naranjo-online", "flux-release-reconciler"): oci_release,
        ("lidersea-com", "flux-release-reconciler"): oci_release,
        ("cloudflare-public", "helm-reconciler"): helm,
        ("naranjo-online", "helm-reconciler"): helm,
        ("lidersea-com", "helm-reconciler"): helm,
    }


def check_role(value, key, expected_rules, cluster=False):
    expected_api = "rbac.authorization.k8s.io/v1"
    require(value.get("apiVersion") == expected_api)
    require(set(value) == {"apiVersion", "kind", "metadata", "rules"})
    namespace, name = (None, key) if cluster else key
    check_metadata(
        value.get("metadata"),
        name,
        namespace,
        expected_cluster_role_labels(name) if cluster else {},
    )
    require(normalize_rules(value.get("rules")) == normalize_rules(expected_rules))


def sa_subject(namespace, name):
    return {"kind": "ServiceAccount", "name": name, "namespace": namespace}


def expected_bindings():
    role = lambda name: {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name}
    controllers = [sa_subject("flux-system", name) for name in sorted(CONTROLLER_NAMES)]
    result = {
        ("flux-system", "flux-controller-runtime"): (role("flux-controller-runtime"), controllers),
        ("flux-system", "flux-controller-decryption"): (
            role("flux-controller-decryption"), [sa_subject("flux-system", "kustomize-controller")]
        ),
        ("flux-system", "flux-controller-impersonation"): (
            role("flux-controller-impersonation"),
            [sa_subject("flux-system", "kustomize-controller")],
        ),
        ("cloudflare-public", "flux-controller-impersonation"): (
            role("flux-controller-impersonation"), [sa_subject("flux-system", "helm-controller")]
        ),
        ("naranjo-online", "flux-controller-impersonation"): (
            role("flux-controller-impersonation"), [sa_subject("flux-system", "helm-controller")]
        ),
        ("lidersea-com", "flux-controller-impersonation"): (
            role("flux-controller-impersonation"), [sa_subject("flux-system", "helm-controller")]
        ),
        ("flux-system", "root-reconciler"): (role("root-reconciler"), [sa_subject("flux-system", "root-reconciler")]),
        ("cloudflare-public", "platform-prerequisites-reconciler"): (role("platform-prerequisites-reconciler"), [sa_subject("flux-system", "platform-prerequisites-reconciler")]),
        ("naranjo-online", "platform-prerequisites-reconciler"): (role("platform-prerequisites-reconciler"), [sa_subject("flux-system", "platform-prerequisites-reconciler")]),
        ("lidersea-com", "platform-prerequisites-reconciler"): (role("platform-prerequisites-reconciler"), [sa_subject("flux-system", "platform-prerequisites-reconciler")]),
        ("kyverno", "platform-prerequisites-reconciler"): (role("platform-prerequisites-reconciler"), [sa_subject("flux-system", "platform-prerequisites-reconciler")]),
        ("kyverno", "admission-reconciler"): (role("admission-reconciler"), [sa_subject("flux-system", "admission-reconciler")]),
        ("cloudflare-public", "platform-services-reconciler"): (role("flux-release-reconciler"), [sa_subject("flux-system", "platform-services-reconciler")]),
        ("naranjo-online", "naranjo-online-reconciler"): (role("flux-release-reconciler"), [sa_subject("flux-system", "naranjo-online-reconciler")]),
        ("lidersea-com", "lidersea-com-reconciler"): (role("flux-release-reconciler"), [sa_subject("flux-system", "lidersea-com-reconciler")]),
        ("cloudflare-public", "helm-reconciler"): (role("helm-reconciler"), [sa_subject("cloudflare-public", "helm-reconciler")]),
        ("naranjo-online", "helm-reconciler"): (role("helm-reconciler"), [sa_subject("naranjo-online", "helm-reconciler")]),
        ("lidersea-com", "helm-reconciler"): (role("helm-reconciler"), [sa_subject("lidersea-com", "helm-reconciler")]),
    }
    return result


def expected_cluster_bindings():
    cluster_role = lambda name: {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "ClusterRole",
        "name": name,
    }
    # `cluster-reconciler-flux-system` is deliberately absent: the reviewed
    # desired state deletes it. A live cluster that still carries it binds
    # cluster-admin to two protected accounts, so it is caught by
    # binding_reaches_protected_account and this verifier fails — which is what
    # makes `--verify` the proof that the narrowing actually landed, not just
    # that the new authority was added beside the old.
    return {
        "crd-controller-flux-system": (
            cluster_role("crd-controller-flux-system"),
            [sa_subject("flux-system", name) for name in sorted(CONTROLLER_NAMES)],
        ),
    }


def normalized_subjects(subjects):
    require(isinstance(subjects, list))
    result = []
    for subject in subjects:
        require(isinstance(subject, dict))
        kind = subject.get("kind")
        if kind == "ServiceAccount":
            require(set(subject) == {"kind", "name", "namespace"})
        elif kind in {"Group", "User"}:
            require(set(subject) == {"apiGroup", "kind", "name"})
            require(subject.get("apiGroup") == "rbac.authorization.k8s.io")
        else:
            raise ContractError()
        result.append(json.dumps(subject, sort_keys=True, separators=(",", ":")))
    return sorted(result)


def check_binding(value, key, expected, cluster=False):
    require(value.get("apiVersion") == "rbac.authorization.k8s.io/v1")
    require(set(value) == {"apiVersion", "kind", "metadata", "roleRef", "subjects"})
    namespace, name = (None, key) if cluster else key
    check_metadata(
        value.get("metadata"),
        name,
        namespace,
        flux_labels() if cluster else {},
    )
    require(value.get("roleRef") == expected[0])
    require(normalized_subjects(value.get("subjects")) == normalized_subjects(expected[1]))


def binding_reaches_protected_account(value):
    subjects = value.get("subjects")
    require(isinstance(subjects, list))
    protected_groups = {"system:serviceaccounts"} | {
        "system:serviceaccounts:" + namespace for namespace, _ in PROTECTED_SERVICE_ACCOUNTS
    }
    for subject in subjects:
        require(isinstance(subject, dict))
        if subject.get("kind") == "ServiceAccount" and (
            subject.get("namespace"), subject.get("name")
        ) in PROTECTED_SERVICE_ACCOUNTS:
            return True
        if subject.get("kind") == "Group" and subject.get("name") in protected_groups:
            return True
    return False


def check_rbac(role_doc, binding_doc, cluster_role_doc, cluster_binding_doc, scope):
    roles = index(role_doc, "Role")
    access_roles = access_role_rules()
    if scope == "full":
        for key, expected in access_roles.items():
            require(key in roles)
            check_role(roles[key], key, expected)
    else:
        for key in set(roles) & set(access_roles):
            check_role(roles[key], key, access_roles[key])

    cluster_roles = index(cluster_role_doc, "ClusterRole", namespaced=False)
    for name, expected in cluster_role_rules().items():
        require(name in cluster_roles)
        check_role(cluster_roles[name], name, expected, cluster=True)

    expected_roles = expected_bindings()
    bindings = index(binding_doc, "RoleBinding")
    for key, value in bindings.items():
        if key in expected_roles:
            check_binding(value, key, expected_roles[key])
        elif binding_reaches_protected_account(value):
            raise ContractError()
    if scope == "full":
        require(set(expected_roles) <= set(bindings))

    expected_clusters = expected_cluster_bindings()
    cluster_bindings = index(cluster_binding_doc, "ClusterRoleBinding", namespaced=False)
    for key, value in cluster_bindings.items():
        if key in expected_clusters:
            check_binding(value, key, expected_clusters[key], cluster=True)
        elif binding_reaches_protected_account(value):
            raise ContractError()
    require(set(expected_clusters) <= set(cluster_bindings))


PSA_LABELS = {
    "pod-security.kubernetes.io/audit": "restricted",
    "pod-security.kubernetes.io/audit-version": "v1.36",
    "pod-security.kubernetes.io/enforce": "restricted",
    "pod-security.kubernetes.io/enforce-version": "v1.36",
    "pod-security.kubernetes.io/warn": "restricted",
    "pod-security.kubernetes.io/warn-version": "v1.36",
}


def check_namespaces(document, scope):
    actual = index(document, "Namespace", namespaced=False)
    expected_names = {"flux-system"}
    if scope == "full":
        expected_names |= {"cloudflare-public", "naranjo-online", "lidersea-com", "kyverno"}
    require(set(actual) == expected_names)
    for name, value in actual.items():
        require(value.get("apiVersion") == "v1")
        require(set(value) <= {"apiVersion", "kind", "metadata", "spec", "status"})
        if name == "flux-system":
            labels = {**flux_labels(), "kubernetes.io/metadata.name": name}
            annotations = {}
        else:
            labels = {**PSA_LABELS, "kubernetes.io/metadata.name": name}
            annotations = {"kustomize.toolkit.fluxcd.io/prune": "disabled"}
            if name == "kyverno":
                annotations["platform.snaraj.dev/readiness"] = (
                    "blocked-until-reviewed-controller-digests-and-runtime-evidence"
                )
        check_metadata(value.get("metadata"), name, None, labels, annotations)
        require(value.get("spec", {"finalizers": ["kubernetes"]}) == {"finalizers": ["kubernetes"]})


def check_flux_source(git_document, kustomization_document):
    git_values = index(git_document, "GitRepository")
    require(set(git_values) == {("flux-system", "flux-system")})
    git_value = git_values[("flux-system", "flux-system")]
    require(git_value.get("apiVersion") == "source.toolkit.fluxcd.io/v1")
    require(set(git_value) <= {"apiVersion", "kind", "metadata", "spec", "status"})
    check_metadata(
        git_value.get("metadata"),
        "flux-system",
        "flux-system",
        {},
        allow_flux_finalizer=True,
    )
    require(
        git_value.get("spec")
        == {
            "ignore": "/*\n!/kubernetes\n!/policies\n",
            "interval": "1m0s",
            "ref": {"branch": "main"},
            "sparseCheckout": ["kubernetes", "policies"],
            "timeout": "60s",
            "url": "https://github.com/snaraj/website-infrastructure.git",
        }
    )

    kustomization_values = index(kustomization_document, "Kustomization")
    require(set(kustomization_values) == {("flux-system", "flux-system")})
    kustomization = kustomization_values[("flux-system", "flux-system")]
    require(kustomization.get("apiVersion") == "kustomize.toolkit.fluxcd.io/v1")
    require(set(kustomization) <= {"apiVersion", "kind", "metadata", "spec", "status"})
    check_metadata(
        kustomization.get("metadata"),
        "flux-system",
        "flux-system",
        {},
        allow_flux_finalizer=True,
    )
    spec = copy.deepcopy(kustomization.get("spec"))
    require(isinstance(spec, dict))
    if spec.get("force") is False:
        spec.pop("force")
    require(
        spec
        == {
            "interval": "10m0s",
            "path": "./kubernetes/reconciliation",
            "prune": True,
            "retryInterval": "1m0s",
            "serviceAccountName": "root-reconciler",
            "sourceRef": {"kind": "GitRepository", "name": "flux-system"},
            "timeout": "5m0s",
            "wait": True,
        }
    )


def main():
    scope = os.environ["FLUX_LIVE_SCOPE"]
    require(scope in {"controllers", "full"})
    check_deployments(load("FLUX_LIVE_DEPLOYMENTS"))
    check_service_accounts(load("FLUX_LIVE_SERVICE_ACCOUNTS"), scope)
    check_rbac(
        load("FLUX_LIVE_ROLES"),
        load("FLUX_LIVE_ROLE_BINDINGS"),
        load("FLUX_LIVE_CLUSTER_ROLES"),
        load("FLUX_LIVE_CLUSTER_ROLE_BINDINGS"),
        scope,
    )
    check_namespaces(load("FLUX_LIVE_NAMESPACES"), scope)
    if scope == "full":
        check_flux_source(
            load("FLUX_LIVE_GIT_REPOSITORY"),
            load("FLUX_LIVE_KUSTOMIZATION"),
        )


try:
    main()
except Exception:
    raise SystemExit(1)
PY_FLUX_LIVE_STATE
  [[ "$(stat -c '%u:%g:%a:%h' -- "${diff_output}" "${diff_stderr}" "${live_stderr}")" == \
    "${operator_uid}:${workspace_gid}:600:1
${operator_uid}:${workspace_gid}:600:1
${operator_uid}:${workspace_gid}:600:1" ]] || return 1
  verify_cluster_target || return 1
}

if [[ "${mode}" == --apply-controllers ]]; then
  [[ "${CONFIRM_FLUX_CONTROLLERS:-}" == "apply-reviewed-${FLUX_VERSION}" ]] || fail
  verify_cluster_target || fail
  mutation_attempted=1
  "${kubectl}" "${kubectl_target_args[@]}" apply -k \
    "${staged_repo}/kubernetes/flux-system/controllers" >/dev/null || fail
  for deployment in source-controller kustomize-controller helm-controller; do
    "${kubectl}" "${kubectl_target_args[@]}" -n flux-system rollout status \
      "deployment/${deployment}" --timeout=5m >/dev/null || fail
  done
  verify_reviewed_live_state controllers || fail
  verify_cluster_target || fail
  printf 'PASS Flux controllers are available; stop for the age backup/install checkpoint.\n'
  exit 0
fi

if [[ "${mode}" == --apply-sync ]]; then
  [[ "${CONFIRM_FLUX_SYNC:-}" == apply-reviewed-anonymous-sync ]] || fail
  : "${EXPECTED_SOPS_AGE_RECIPIENT:?Set the reviewed public hybrid-PQ recipient}"
  KUBECONFIG_FILE="${kubeconfig}" KUBECTL_BINARY="${kubectl}" \
    /bin/bash "${repo_root}/bootstrap/flux/verify-sops-age-secret.sh" \
      1 "${EXPECTED_SOPS_AGE_RECIPIENT}" || fail
  verify_cluster_target || fail
  mutation_attempted=1
  for manifest in \
    kubernetes/platform/prerequisites/namespaces.yaml \
    kubernetes/flux-system/access.yaml \
    kubernetes/flux-system/gotk-sync.yaml; do
    "${kubectl}" "${kubectl_target_args[@]}" apply -f \
      "${staged_repo}/${manifest}" >/dev/null || fail
  done
  verify_reviewed_live_state full || fail
  verify_cluster_target || fail
  printf 'PASS bootstrap-owned access and anonymous sync were applied after exact age Secret verification.\n'
  exit 0
fi

for deployment in source-controller kustomize-controller helm-controller; do
  "${kubectl}" "${kubectl_target_args[@]}" -n flux-system rollout status \
    "deployment/${deployment}" --timeout=30s >/dev/null 2>&1 || fail
done
git_repository="$("${kubectl}" "${kubectl_target_args[@]}" -n flux-system get \
  gitrepository flux-system -o go-template='{{.spec.url}} {{if .spec.secretRef}}{{.spec.secretRef.name}}{{else}}none{{end}}' 2>/dev/null)" || fail
[[ "${git_repository}" == 'https://github.com/snaraj/website-infrastructure.git none' ]] || fail
"${kubectl}" "${kubectl_target_args[@]}" -n flux-system wait --for=condition=Ready \
  gitrepository/flux-system kustomization/flux-system --timeout=30s >/dev/null 2>&1 || fail
git_secret_count="$("${kubectl}" "${kubectl_target_args[@]}" -n flux-system get secret \
  -o jsonpath='{range .items[?(@.type=="kubernetes.io/basic-auth")]}x{end}{range .items[?(@.type=="kubernetes.io/ssh-auth")]}x{end}' | wc -c)" || fail
[[ "${git_secret_count}" -eq 0 ]] || fail
: "${EXPECTED_SOPS_AGE_RECIPIENT:?Set the reviewed public hybrid-PQ recipient}"
KUBECONFIG_FILE="${kubeconfig}" KUBECTL_BINARY="${kubectl}" \
  /bin/bash "${repo_root}/bootstrap/flux/verify-sops-age-secret.sh" \
    1 "${EXPECTED_SOPS_AGE_RECIPIENT}" || fail
verify_reviewed_live_state full || fail

source_args="$("${kubectl}" "${kubectl_target_args[@]}" -n flux-system get deployment source-controller -o jsonpath='{.spec.template.spec.containers[0].args}')" || fail
grep -q -- '--no-cross-namespace-refs=true' <<<"${source_args}" || fail
kustomize_args="$("${kubectl}" "${kubectl_target_args[@]}" -n flux-system get deployment kustomize-controller -o jsonpath='{.spec.template.spec.containers[0].args}')" || fail
grep -q -- '--no-cross-namespace-refs=true' <<<"${kustomize_args}" || fail
grep -q -- '--no-remote-bases=true' <<<"${kustomize_args}" || fail
grep -q -- '--default-service-account=default' <<<"${kustomize_args}" || fail
helm_args="$("${kubectl}" "${kubectl_target_args[@]}" -n flux-system get deployment helm-controller -o jsonpath='{.spec.template.spec.containers[0].args}')" || fail
grep -q -- '--no-cross-namespace-refs=true' <<<"${helm_args}" || fail
grep -q -- '--default-service-account=default' <<<"${helm_args}" || fail
for namespace in flux-system cloudflare-public naranjo-online; do
  "${kubectl}" "${kubectl_target_args[@]}" auth can-i create deployments \
    --as="system:serviceaccount:${namespace}:default" -n "${namespace}" | \
    grep -qx no || fail
done
verify_cluster_target || fail
printf 'PASS Flux target, exact reviewed live state, anonymous source, and exact SOPS Secret verification.\n'
