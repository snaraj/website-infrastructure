#!/bin/bash
# Create or resourceVersion-replace flux-system/sops-age from immutable
# protected snapshots. This Linux AMD64 ceremony never prints a private key.
set -Eeuo pipefail
set +x
set +o history

# Release safety stop. Create and replace both consume protected identity bytes
# and therefore require a separately installed stage-zero reviewed-blob
# launcher. No caller-supplied variable can reopen this path.
readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE}" != yes ]]; then
  builtin printf 'BLOCKED sops-age installation requires the trusted reviewed-blob launcher; no private file was read and no cluster mutation was attempted.\n' >&2
  builtin exit 1
fi

if [[ -n "${BASH_ENV+x}" || -n "${ENV+x}" || -n "${CDPATH+x}" ||
      -n "${GLOBIGNORE+x}" || -n "${LD_PRELOAD+x}" ||
      -n "${LD_LIBRARY_PATH+x}" || -n "${LD_AUDIT+x}" ||
      -n "${LD_DEBUG+x}" || -n "${LD_PROFILE+x}" ||
      -n "$(declare -Fx)" ]]; then
  printf 'FAIL sops-age installation made no cluster mutation.\n' >&2
  exit 1
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT \
  LD_DEBUG LD_PROFILE
umask 077
ulimit -S -c 0
ulimit -H -c 0
[[ "$(ulimit -S -c)" == 0 && "$(ulimit -H -c)" == 0 ]] || {
  printf 'FAIL sops-age installation made no cluster mutation.\n' >&2
  exit 1
}

mutation_attempted=0
fail() {
  if [[ "${mutation_attempted}" -eq 0 ]]; then
    printf 'FAIL sops-age installation made no cluster mutation.\n' >&2
  else
    printf 'FAIL sops-age installation may have committed; stop and inspect the exact target.\n' >&2
  fi
  exit 1
}

for ambient_name in KUBECONFIG HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy KUBECTL_PLUGINS_PATH; do
  [[ -z "${!ambient_name+x}" ]] || fail
done
unset KUBECONFIG HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy KUBECTL_PLUGINS_PATH
while IFS= read -r authority_name; do
  case "${authority_name}" in
    SOPS_AGE_TWO_BACKUPS_RESTORE_TESTED) ;;
    AWS_*|AZURE_*|GOOGLE_*|GCP_*|HCLOUD_*|VAULT_*|TF_*|TOFU_*|\
    GH_*|GITHUB_*|GIT_*|GCM_*|SSH_*|CF_*|CLOUDFLARE_*|SOPS_*) fail ;;
  esac
done < <(compgen -e)
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

mode="${1:-}"
shift || true
resource_version=''
if [[ "${mode}" == replace ]]; then
  resource_version="${1:-}"
  shift || true
  [[ "${resource_version}" =~ ^[1-9][0-9]*$ ]] || fail
elif [[ "${mode}" != create ]]; then
  fail
fi
[[ "$#" -eq 2 || "$#" -eq 4 ]] || fail
[[ "${mode}" != create || "$#" -eq 2 ]] || fail
[[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || fail
[[ "${TWO_WORKING_SESSIONS_PROVEN:-}" == yes ]] || fail
[[ "${SOPS_AGE_TWO_BACKUPS_RESTORE_TESTED:-}" == yes ]] || fail

for command_name in awk cat chmod cmp compgen dirname env findmnt git grep id \
  lsblk mktemp readlink rm sha256sum stat swapon uname; do
  command -v "${command_name}" >/dev/null 2>&1 || fail
done
python3_binary="$(readlink -e -- /usr/bin/python3)" || fail
[[ "${python3_binary}" =~ ^/usr/bin/python3(\.[0-9]+)?$ ]] || fail
[[ -f "${python3_binary}" && ! -L "${python3_binary}" && -x "${python3_binary}" ]] || fail
[[ "$(stat -c '%u:%h' -- "${python3_binary}")" == 0:1 ]] || fail
python3_mode="$(stat -c %a -- "${python3_binary}")" || fail
(( (8#${python3_mode} & 0022) == 0 )) || fail
"${python3_binary}" -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' || fail

: "${CREDENTIAL_WORKSPACE:?Set the protected POSIX credential workspace root}"
: "${KUBECONFIG_FILE:?Set the protected flattened JSON kubeconfig file}"
: "${KUBECTL_BINARY:?Set the protected pinned kubectl executable}"
: "${AGE_KEYGEN_BINARY:?Set the protected pinned age-keygen executable}"
: "${EXPECTED_KUBECONFIG_CONTEXT:?Set the exact reviewed kubectl context}"
: "${EXPECTED_KUBERNETES_SERVER:?Set the exact reviewed Kubernetes API URL}"
: "${EXPECTED_PI_NODE_NAME:?Set the exact reviewed single Pi node name}"
: "${EXPECTED_KUBERNETES_CA_SHA256:?Set the reviewed Kubernetes CA DER digest}"
: "${EXPECTED_KUBE_SYSTEM_NAMESPACE_UID_SHA256:?Set the reviewed kube-system UID digest}"
: "${EXPECTED_REPOSITORY_HEAD:?Set the exact reviewed main commit}"
: "${EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256:?Set the reviewed encrypted-filesystem UUID digest}"
: "${PROTECTED_LINUX_CUSTODY_ATTESTED:?Acknowledge the dedicated Linux custody controls}"
[[ "${EXPECTED_REPOSITORY_HEAD}" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "${EXPECTED_KUBERNETES_CA_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "${EXPECTED_KUBE_SYSTEM_NAMESPACE_UID_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "${EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "${PROTECTED_LINUX_CUSTODY_ATTESTED}" == \
  encrypted-storage-no-swap-no-coredump-no-cloud-sync-no-session-recording ]] || fail
workspace="${CREDENTIAL_WORKSPACE}"
kubeconfig_source="${KUBECONFIG_FILE}"
kubectl_source="${KUBECTL_BINARY}"
age_keygen_source="${AGE_KEYGEN_BINARY}"

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

canonical_existing_path "${workspace}" || fail
[[ -d "${workspace}" ]] || fail
operator_uid="$(id -u)" || fail
workspace_gid="$(stat -c %g -- "${workspace}")" || fail
[[ "$(stat -c '%u:%a' -- "${workspace}")" == "${operator_uid}:700" ]] || fail
workspace_device="$(stat -c %d -- "${workspace}")" || fail
mount_record="$(findmnt --noheadings --raw --output SOURCE,UUID --target "${workspace}")" || fail
[[ "$(printf '%s\n' "${mount_record}" | grep -c .)" -eq 1 ]] || fail
read -r mount_source mount_uuid mount_extra <<<"${mount_record}"
[[ -n "${mount_source}" && -n "${mount_uuid}" && -z "${mount_extra:-}" ]] || fail
mount_source="${mount_source%%\[*}"
[[ "${mount_source}" == /dev/* && "${mount_uuid}" =~ ^[A-Za-z0-9._:-]+$ ]] || fail
findmnt --noheadings --raw --output OPTIONS --target "${workspace}" | \
  grep -Eq '(^|,)rw(,|$)' || fail
lsblk --inverse --noheadings --raw --output TYPE "${mount_source}" | \
  grep -Fxq crypt || fail
[[ -z "$(swapon --show=NAME --noheadings --raw)" ]] || fail
[[ -r /proc/sys/kernel/yama/ptrace_scope ]] || fail
ptrace_scope="$(</proc/sys/kernel/yama/ptrace_scope)"
[[ "${ptrace_scope}" =~ ^[1-3]$ ]] || fail
mount_uuid_sha256="$(printf '%s\n' "${mount_uuid}" | sha256sum | awk '{print $1}')" || fail
[[ "${mount_uuid_sha256}" == "${EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256}" ]] || fail

temporary="$(mktemp -d "${workspace%/}/sops-age-install.XXXXXX")" || fail
combined="${temporary}/age.agekey"
kubeconfig="${temporary}/kubeconfig.json"
kubectl="${temporary}/kubectl"
age_keygen="${temporary}/age-keygen"
candidate="${temporary}/candidate.json"
annotated="${temporary}/annotated.json"
final="${temporary}/final.json"
mutation_result="${temporary}/mutation-result.json"
live_result="${temporary}/live-result.json"
existing_result="${temporary}/existing-result.json"
versions_file="${temporary}/versions.env"
kubeconfig_validator="${temporary}/validate_kubeconfig_snapshot.py"
age_version_output="${temporary}/age-version.txt"
cleanup() {
  if [[ -d "${temporary}" && ! -L "${temporary}" ]]; then
    case "${temporary}" in
      "${workspace}"/sops-age-install.*) rm -rf -- "${temporary}" ;;
      *) printf 'Refusing ambiguous sops-age cleanup target.\n' >&2 ;;
    esac
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "${temporary}"

trusted_git() {
  env -i PATH="${PATH}" HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    git --no-replace-objects -c credential.helper= -c core.askPass= \
      -c core.fsmonitor=false -c core.untrackedCache=false "$@"
}

[[ "$(trusted_git -C "${repo_root}" rev-parse --show-toplevel)" == "${repo_root}" ]] || fail
git_dir="$(trusted_git -C "${repo_root}" rev-parse --absolute-git-dir)" || fail
[[ "${git_dir}" == "${repo_root}/.git" && -d "${git_dir}" && ! -L "${git_dir}" ]] || fail
[[ "$(stat -c %u -- "${repo_root}")" == "${operator_uid}" ]] || fail
[[ "$(stat -c %u -- "${git_dir}")" == "${operator_uid}" ]] || fail
repo_mode="$(stat -c %a -- "${repo_root}")" || fail
git_mode="$(stat -c %a -- "${git_dir}")" || fail
(( (8#${repo_mode} & 0022) == 0 && (8#${git_mode} & 0022) == 0 )) || fail
[[ ! -e "${git_dir}/info/grafts" ]] || fail
[[ -z "$(trusted_git -C "${repo_root}" for-each-ref --format='%(refname)' refs/replace)" ]] || fail
[[ "$(trusted_git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}')" == "${EXPECTED_REPOSITORY_HEAD}" ]] || fail
[[ "$(trusted_git -C "${repo_root}" symbolic-ref -q HEAD)" == refs/heads/main ]] || fail
[[ "$(trusted_git -C "${repo_root}" rev-parse --is-shallow-repository)" == false ]] || fail
self_blob="$(trusted_git -C "${repo_root}" rev-parse \
  "${EXPECTED_REPOSITORY_HEAD}:bootstrap/flux/install-sops-age-secret.sh")" || fail
[[ "$(trusted_git -C "${repo_root}" hash-object --no-filters \
  "${repo_root}/bootstrap/flux/install-sops-age-secret.sh")" == "${self_blob}" ]] || fail
trusted_git -C "${repo_root}" cat-file blob \
  "${EXPECTED_REPOSITORY_HEAD}:versions.env" > "${versions_file}" || fail
trusted_git -C "${repo_root}" cat-file blob \
  "${EXPECTED_REPOSITORY_HEAD}:scripts/validate_kubeconfig_snapshot.py" \
  > "${kubeconfig_validator}" || fail
chmod 600 "${versions_file}" "${kubeconfig_validator}"
[[ "$(trusted_git -C "${repo_root}" hash-object --no-filters "${versions_file}")" == \
  "$(trusted_git -C "${repo_root}" rev-parse "${EXPECTED_REPOSITORY_HEAD}:versions.env")" ]] || fail
[[ "$(trusted_git -C "${repo_root}" hash-object --no-filters "${kubeconfig_validator}")" == \
  "$(trusted_git -C "${repo_root}" rev-parse "${EXPECTED_REPOSITORY_HEAD}:scripts/validate_kubeconfig_snapshot.py")" ]] || fail

pin() {
  local name="$1"
  awk -F= -v key="${name}" '
    $1 == key && $2 ~ /^[A-Za-z0-9._:+@/-]+$/ { count += 1; value = $2 }
    END { if (count == 1) print value }
  ' "${versions_file}"
}
age_version="$(pin AGE_VERSION)"
age_keygen_sha256="$(pin AGE_KEYGEN_LINUX_AMD64_SHA256)"
kubectl_version="$(pin KUBERNETES_VERSION)"
kubectl_sha256="$(pin KUBECTL_LINUX_AMD64_SHA256)"
[[ "${age_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail
[[ "${kubectl_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail
[[ "${age_keygen_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "${kubectl_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail

snapshot_protected_file() {
  local source="$1" destination="$2" class="$3" mode_bits state descriptor
  canonical_existing_path "${source}" || return 1
  case "${source}" in "${workspace}"/*) ;; *) return 1 ;; esac
  [[ -f "${source}" ]] || return 1
  mode_bits="$(stat -c %a -- "${source}")" || return 1
  if [[ "${class}" == data ]]; then
    [[ "${mode_bits}" == 400 || "${mode_bits}" == 600 ]] || return 1
  else
    [[ "${mode_bits}" == 500 || "${mode_bits}" == 700 ]] || return 1
  fi
  [[ "$(stat -c '%u:%g:%h' -- "${source}")" == "${operator_uid}:${workspace_gid}:1" ]] || return 1
  [[ "$(stat -c %d -- "${source}")" == "${workspace_device}" ]] || return 1
  state="$(stat -c '%d:%i:%f:%h:%s:%Y' -- "${source}")" || return 1
  exec {descriptor}<"${source}" || return 1
  [[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y' -- "/proc/$$/fd/${descriptor}")" == "${state}" ]] || return 1
  command cat <&"${descriptor}" > "${destination}" || return 1
  [[ "$(stat -c '%d:%i:%f:%h:%s:%Y' -- "${source}")" == "${state}" ]] || return 1
  [[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y' -- "/proc/$$/fd/${descriptor}")" == "${state}" ]] || return 1
  exec {descriptor}<&-
  if [[ "${class}" == data ]]; then chmod 600 "${destination}"; else chmod 700 "${destination}"; fi
  [[ "$(stat -c '%u:%h' -- "${destination}")" == "${operator_uid}:1" ]] || return 1
}

snapshot_protected_file "${kubeconfig_source}" "${kubeconfig}" data || fail
snapshot_protected_file "${kubectl_source}" "${kubectl}" executable || fail
snapshot_protected_file "${age_keygen_source}" "${age_keygen}" executable || fail
kubeconfig_digest="$(sha256sum -- "${kubeconfig}" | awk '{print $1}')" || fail
[[ "$(sha256sum -- "${kubectl}" | awk '{print $1}')" == "${kubectl_sha256}" ]] || fail
[[ "$(sha256sum -- "${age_keygen}" | awk '{print $1}')" == "${age_keygen_sha256}" ]] || fail
KUBECONFIG_SNAPSHOT_FILE="${kubeconfig}" \
  "${python3_binary}" -I "${kubeconfig_validator}" >/dev/null || fail
KUBECONFIG_SNAPSHOT_FILE="${kubeconfig}" \
EXPECTED_KUBERNETES_CA_SHA256="${EXPECTED_KUBERNETES_CA_SHA256}" \
  "${python3_binary}" -I - <<'PY' || fail
import base64
import hashlib
import hmac
import json
import os
import re
from pathlib import Path

try:
    document = json.loads(Path(os.environ["KUBECONFIG_SNAPSHOT_FILE"]).read_text("utf-8"))
    pem = base64.b64decode(
        document["clusters"][0]["cluster"]["certificate-authority-data"],
        validate=True,
    ).decode("ascii")
    match = re.fullmatch(
        r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n",
        pem,
    )
    if match is None:
        raise ValueError()
    der = base64.b64decode(match.group(1).replace("\n", ""), validate=True)
    actual = hashlib.sha256(der).hexdigest()
    if not hmac.compare_digest(actual, os.environ["EXPECTED_KUBERNETES_CA_SHA256"]):
        raise ValueError()
except (OSError, UnicodeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
PY

"${age_keygen}" --version > "${age_version_output}" 2>/dev/null || fail
mapfile -t age_version_lines < "${age_version_output}"
[[ "${#age_version_lines[@]}" -eq 1 ]] || fail
actual_age_version="${age_version_lines[0]}"
[[ "$(stat -c %s -- "${age_version_output}")" -eq $(( ${#actual_age_version} + 1 )) ]] || fail
[[ "${actual_age_version}" == "${age_version#v}" || "${actual_age_version}" == "age-keygen ${age_version#v}" ]] || fail
kubectl_client="$("${kubectl}" version --client -o yaml 2>/dev/null)" || fail
[[ "$(printf '%s\n' "${kubectl_client}" | grep -c "^[[:space:]]*gitVersion: ${kubectl_version}$")" -eq 1 ]] || fail

identity_files=()
recipients=()
identity_index=0
while [[ "$#" -gt 0 ]]; do
  identity_source="$1"
  expected_recipient="$2"
  shift 2
  [[ "${expected_recipient}" =~ ^age1pq1[0-9a-z]+$ ]] || fail
  identity_snapshot="${temporary}/identity-${identity_index}.agekey"
  derived_output="${temporary}/recipient-${identity_index}.txt"
  expected_output="${temporary}/expected-recipient-${identity_index}.txt"
  snapshot_protected_file "${identity_source}" "${identity_snapshot}" data || fail
  "${age_keygen}" -y "${identity_snapshot}" > "${derived_output}" 2>/dev/null || fail
  printf '%s\n' "${expected_recipient}" > "${expected_output}"
  cmp -s -- "${derived_output}" "${expected_output}" || fail
  for prior in "${recipients[@]:-}"; do
    [[ -z "${prior}" || "${prior}" != "${expected_recipient}" ]] || fail
  done
  identity_files+=("${identity_snapshot}")
  recipients+=("${expected_recipient}")
  identity_index=$((identity_index + 1))
done

: > "${combined}"
for identity_file in "${identity_files[@]}"; do
  command cat -- "${identity_file}" >> "${combined}" || fail
  printf '\n' >> "${combined}"
done
chmod 600 "${combined}"
combined_digest="$(sha256sum -- "${combined}" | awk '{print $1}')" || fail
[[ "${combined_digest}" =~ ^[0-9a-f]{64}$ ]] || fail

recipient_payload=''
for recipient in "${recipients[@]}"; do
  recipient_payload+="${recipient}"$'\n'
done
recipient_digest="$(printf '%s' "${recipient_payload}" | sha256sum | awk '{print $1}')"
identity_count="${#identity_files[@]}"
[[ "${identity_count}" -eq 1 || "${identity_count}" -eq 2 ]] || fail
[[ "${recipient_digest}" =~ ^[0-9a-f]{64}$ ]] || fail

kubectl_config_args=(--kubeconfig="${kubeconfig}" --context="${EXPECTED_KUBECONFIG_CONTEXT}")
kubectl_target_args=("${kubectl_config_args[@]}" --server="${EXPECTED_KUBERNETES_SERVER}" --request-timeout=15s)
verify_cluster_target() {
  local actual_context actual_server node_names namespace_uid namespace_uid_sha256
  actual_context="$("${kubectl}" --kubeconfig="${kubeconfig}" config current-context 2>/dev/null)" || return 1
  actual_server="$("${kubectl}" "${kubectl_config_args[@]}" config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)" || return 1
  node_names="$("${kubectl}" "${kubectl_target_args[@]}" get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)" || return 1
  namespace_uid="$("${kubectl}" "${kubectl_target_args[@]}" get namespace kube-system \
    -o jsonpath='{.metadata.uid}' 2>/dev/null)" || return 1
  [[ "${namespace_uid}" =~ ^[0-9a-f-]{20,64}$ ]] || return 1
  namespace_uid_sha256="$(printf '%s\n' "${namespace_uid}" | sha256sum | awk '{print $1}')" || return 1
  [[ "${actual_context}" == "${EXPECTED_KUBECONFIG_CONTEXT}" ]] || return 1
  [[ "${actual_server}" == "${EXPECTED_KUBERNETES_SERVER}" ]] || return 1
  [[ "${node_names}" == "${EXPECTED_PI_NODE_NAME}" ]] || return 1
  [[ "${namespace_uid_sha256}" == "${EXPECTED_KUBE_SYSTEM_NAMESPACE_UID_SHA256}" ]] || return 1
  [[ "$(sha256sum -- "${kubeconfig}" | awk '{print $1}')" == "${kubeconfig_digest}" ]] || return 1
  [[ "$(sha256sum -- "${kubectl}" | awk '{print $1}')" == "${kubectl_sha256}" ]] || return 1
  [[ "$(sha256sum -- "${age_keygen}" | awk '{print $1}')" == "${age_keygen_sha256}" ]] || return 1
  [[ "$(sha256sum -- "${combined}" | awk '{print $1}')" == "${combined_digest}" ]] || return 1
}
verify_cluster_target || fail

if [[ "${mode}" == create ]]; then
  [[ "${CONFIRM_SOPS_AGE_INSTALL:-}" == create-flux-system-sops-age ]] || fail
else
  [[ "${CONFIRM_SOPS_AGE_INSTALL:-}" == "replace-flux-system-sops-age-${resource_version}" ]] || fail
  : "${EXPECTED_PREDECESSOR_SOPS_AGE_SECRET_SHA256:?Set the protected predecessor Secret-data digest}"
  : "${EXPECTED_PREDECESSOR_RECIPIENT_SET_SHA256:?Set the protected predecessor recipient-set digest}"
  : "${EXPECTED_PREDECESSOR_IDENTITY_COUNT:?Set the predecessor identity count}"
  [[ "${EXPECTED_PREDECESSOR_SOPS_AGE_SECRET_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
  [[ "${EXPECTED_PREDECESSOR_RECIPIENT_SET_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
  [[ "${EXPECTED_PREDECESSOR_IDENTITY_COUNT}" =~ ^[12]$ ]] || fail
  "${kubectl}" "${kubectl_target_args[@]}" -n flux-system get secret sops-age \
    -o json > "${existing_result}" 2>/dev/null || fail
  chmod 600 "${existing_result}"
  "${python3_binary}" -I - "${existing_result}" "${resource_version}" \
    "${EXPECTED_PREDECESSOR_IDENTITY_COUNT}" \
    "${EXPECTED_PREDECESSOR_RECIPIENT_SET_SHA256}" \
    "${EXPECTED_PREDECESSOR_SOPS_AGE_SECRET_SHA256}" <<'PY' || fail
import base64
import binascii
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path


class InvalidPredecessor(Exception):
    pass


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InvalidPredecessor()
        value[key] = item
    return value


if len(sys.argv) != 6:
    raise SystemExit(1)
try:
    raw = Path(sys.argv[1]).read_bytes()
    if not raw or len(raw) > 1_048_576:
        raise InvalidPredecessor()
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    metadata = obj.get("metadata")
    data = obj.get("data")
    if not isinstance(metadata, dict) or not isinstance(data, dict):
        raise InvalidPredecessor()
    if obj.get("apiVersion") != "v1" or obj.get("kind") != "Secret" or obj.get("type") != "Opaque":
        raise InvalidPredecessor()
    if "immutable" in obj or metadata.get("name") != "sops-age" or metadata.get("namespace") != "flux-system":
        raise InvalidPredecessor()
    if metadata.get("resourceVersion") != sys.argv[2] or re.fullmatch(
        r"[0-9a-f-]{20,64}", metadata.get("uid", "")
    ) is None:
        raise InvalidPredecessor()
    if any(key in metadata for key in (
        "deletionGracePeriodSeconds", "deletionTimestamp", "finalizers",
        "generateName", "labels", "ownerReferences",
    )):
        raise InvalidPredecessor()
    expected_annotations = {
        "security.website-infrastructure/identity-count": sys.argv[3],
        "security.website-infrastructure/recipient-set-sha256": sys.argv[4],
        "security.website-infrastructure/managed-by": "website-infrastructure-sops-age-installer-v1",
    }
    if metadata.get("annotations") != expected_annotations or set(data) != {"age.agekey"}:
        raise InvalidPredecessor()
    encoded = data["age.agekey"]
    if not isinstance(encoded, str):
        raise InvalidPredecessor()
    decoded = base64.b64decode(encoded, validate=True)
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise InvalidPredecessor()
    actual_digest = hashlib.sha256(decoded).hexdigest()
    if not hmac.compare_digest(actual_digest, sys.argv[5]):
        raise InvalidPredecessor()
except (OSError, UnicodeError, json.JSONDecodeError, binascii.Error,
        InvalidPredecessor, TypeError, ValueError):
    raise SystemExit(1)
PY
fi

"${kubectl}" "${kubectl_target_args[@]}" -n flux-system create secret generic sops-age \
  --type=Opaque --from-file="age.agekey=${combined}" --dry-run=client -o json \
  > "${candidate}" 2>/dev/null || fail
"${kubectl}" "${kubectl_target_args[@]}" annotate --local -f "${candidate}" --overwrite -o json \
  "security.website-infrastructure/identity-count=${identity_count}" \
  "security.website-infrastructure/recipient-set-sha256=${recipient_digest}" \
  "security.website-infrastructure/managed-by=website-infrastructure-sops-age-installer-v1" \
  > "${annotated}" 2>/dev/null || fail

if [[ "${mode}" == replace ]]; then
  patch='[{"op":"add","path":"/metadata/resourceVersion","value":"'"${resource_version}"'"}]'
  "${kubectl}" "${kubectl_target_args[@]}" patch --local -f "${annotated}" --type=json \
    -p "${patch}" -o json > "${final}" 2>/dev/null || fail
else
  command cp -- "${annotated}" "${final}" || fail
  chmod 600 "${final}"
fi

verify_cluster_target || fail
mutation_attempted=1
if [[ "${mode}" == replace ]]; then
  "${kubectl}" "${kubectl_target_args[@]}" replace -f "${final}" -o json \
    > "${mutation_result}" 2>/dev/null || fail
else
  "${kubectl}" "${kubectl_target_args[@]}" create -f "${final}" -o json \
    > "${mutation_result}" 2>/dev/null || fail
fi
chmod 600 "${mutation_result}"

# Compare both the mutation response and a fresh live read with the protected
# candidate. UID/resourceVersion equality makes a concurrent replacement fail.
verify_cluster_target || fail
"${kubectl}" "${kubectl_target_args[@]}" -n flux-system get secret sops-age \
  -o json > "${live_result}" 2>/dev/null || fail
chmod 600 "${live_result}"
"${python3_binary}" -I - "${mutation_result}" "${live_result}" "${combined}" \
  "${identity_count}" "${recipient_digest}" <<'PY' || fail
import base64
import binascii
import hmac
import json
import re
import sys
from pathlib import Path


class InvalidResult(Exception):
    pass


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InvalidResult()
        value[key] = item
    return value


if len(sys.argv) != 6:
    raise SystemExit(1)
mutation_path = Path(sys.argv[1])
live_path = Path(sys.argv[2])
identity_path = Path(sys.argv[3])
expected_count = sys.argv[4]
expected_digest = sys.argv[5]


def validate_result(path, identity):
    raw = path.read_bytes()
    if not raw or len(raw) > 1_048_576:
        raise InvalidResult()
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    metadata = obj.get("metadata")
    data = obj.get("data")
    if not isinstance(metadata, dict) or not isinstance(data, dict):
        raise InvalidResult()
    if obj.get("apiVersion") != "v1" or obj.get("kind") != "Secret" or obj.get("type") != "Opaque":
        raise InvalidResult()
    if "immutable" in obj or metadata.get("name") != "sops-age" or metadata.get("namespace") != "flux-system":
        raise InvalidResult()
    if re.fullmatch(r"[1-9][0-9]*", metadata.get("resourceVersion", "")) is None:
        raise InvalidResult()
    uid = metadata.get("uid", "")
    if re.fullmatch(r"[0-9a-f-]{20,64}", uid) is None:
        raise InvalidResult()
    if any(key in metadata for key in (
        "deletionGracePeriodSeconds", "deletionTimestamp", "finalizers",
        "generateName", "labels", "ownerReferences",
    )):
        raise InvalidResult()
    expected_annotations = {
        "security.website-infrastructure/identity-count": expected_count,
        "security.website-infrastructure/recipient-set-sha256": expected_digest,
        "security.website-infrastructure/managed-by": "website-infrastructure-sops-age-installer-v1",
    }
    if metadata.get("annotations") != expected_annotations or set(data) != {"age.agekey"}:
        raise InvalidResult()
    encoded = data["age.agekey"]
    if not isinstance(encoded, str):
        raise InvalidResult()
    decoded = base64.b64decode(encoded, validate=True)
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise InvalidResult()
    if not hmac.compare_digest(decoded, identity):
        raise InvalidResult()
    return uid, metadata["resourceVersion"]


try:
    identity = identity_path.read_bytes()
    if not identity or len(identity) > 65_536:
        raise InvalidResult()
    mutation_identity = validate_result(mutation_path, identity)
    live_identity = validate_result(live_path, identity)
    if mutation_identity != live_identity:
        raise InvalidResult()
except (OSError, UnicodeError, json.JSONDecodeError, binascii.Error, InvalidResult, TypeError, ValueError):
    raise SystemExit(1)
PY

verify_cluster_target || fail
printf 'PASS sops-age %s completed through immutable protected inputs.\n' "${mode}"
