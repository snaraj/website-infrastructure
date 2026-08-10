#!/bin/bash
# Authenticate the committed SOPS MAC and decrypted Tunnel-token identity in one
# protected, network-isolated Linux AMD64 transaction. No plaintext is printed.
set -Eeuo pipefail
set +x
set +o history

# Release safety stop. MAC verification decrypts with the protected cluster
# identity and must be entered only through the future immutable stage-zero
# launcher. No caller-supplied variable can reopen this path.
readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE}" != yes ]]; then
  builtin printf 'BLOCKED protected SOPS verification requires the trusted reviewed-blob launcher; no private file was read and no ciphertext was decrypted.\n' >&2
  builtin exit 1
fi

if [[ -n "${BASH_ENV+x}" || -n "${ENV+x}" || -n "${CDPATH+x}" ||
      -n "${GLOBIGNORE+x}" || -n "${LD_PRELOAD+x}" ||
      -n "${LD_LIBRARY_PATH+x}" || -n "${LD_AUDIT+x}" ||
      -n "${LD_DEBUG+x}" || -n "${LD_PROFILE+x}" ||
      -n "$(declare -Fx)" ]]; then
  printf 'FAIL protected SOPS ciphertext verification.\n' >&2
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
  printf 'FAIL protected SOPS ciphertext verification.\n' >&2
  exit 1
}

fail() {
  printf 'FAIL protected SOPS ciphertext verification.\n' >&2
  exit 1
}

[[ "$#" -eq 0 ]] || fail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail
for ambient_name in KUBECONFIG HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy KUBECTL_PLUGINS_PATH; do
  [[ -z "${!ambient_name+x}" ]] || fail
done
while IFS= read -r authority_name; do
  case "${authority_name}" in
    SOPS_CONFIG_FILE|SOPS_CIPHERTEXT_FILE|SOPS_AGE_IDENTITY_FILE|SOPS_BINARY|\
    SOPS_AGE_TWO_BACKUPS_RESTORE_TESTED) ;;
    AWS_*|AZURE_*|GOOGLE_*|GCP_*|HCLOUD_*|VAULT_*|TF_*|TOFU_*|\
    GH_*|GITHUB_*|GIT_*|GCM_*|SSH_*|CF_*|CLOUDFLARE_*|SOPS_*) fail ;;
  esac
done < <(compgen -e)

for command_name in awk cat chmod compgen dirname env findmnt git grep id \
  lsblk mktemp readlink rm sha256sum stat swapon timeout tr uname unshare; do
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
: "${SOPS_CONFIG_FILE:?Set the protected .sops.yaml snapshot}"
: "${SOPS_CIPHERTEXT_FILE:?Set the protected Tunnel Secret ciphertext candidate}"
: "${SOPS_AGE_IDENTITY_FILE:?Set the protected cluster age identity}"
: "${SOPS_BINARY:?Set the protected pinned SOPS executable}"
: "${AGE_KEYGEN_BINARY:?Set the protected pinned age-keygen executable}"
: "${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256:?Set the protected account-ID digest}"
: "${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256:?Set the protected pi-websites Tunnel-ID digest}"
: "${EXPECTED_REPOSITORY_HEAD:?Set the exact reviewed main commit}"
: "${EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256:?Set the reviewed encrypted-filesystem UUID digest}"
: "${PROTECTED_LINUX_CUSTODY_ATTESTED:?Acknowledge the dedicated Linux custody controls}"
[[ "${SOPS_AGE_TWO_BACKUPS_RESTORE_TESTED:-}" == yes ]] || fail
for expected_sha256 in "${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256}" \
  "${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256}" \
  "${EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256}"; do
  [[ "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail
done
[[ "${EXPECTED_REPOSITORY_HEAD}" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "${PROTECTED_LINUX_CUSTODY_ATTESTED}" == \
  encrypted-storage-no-swap-no-coredump-no-cloud-sync-no-session-recording ]] || fail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
workspace="${CREDENTIAL_WORKSPACE}"
config_source="${SOPS_CONFIG_FILE}"
ciphertext_source="${SOPS_CIPHERTEXT_FILE}"
identity_source="${SOPS_AGE_IDENTITY_FILE}"
sops_source="${SOPS_BINARY}"
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

temporary="$(mktemp -d "${workspace%/}/sops-ciphertext-verify.XXXXXX")" || fail
config="${temporary}/sops-config.yaml"
ciphertext="${temporary}/tunnel-token.sops.yaml"
identity="${temporary}/cluster.agekey"
sops="${temporary}/sops"
age_keygen="${temporary}/age-keygen"
token="${temporary}/token"
sops_stderr="${temporary}/sops.stderr"
versions_file="${temporary}/versions.env"
age_version_output="${temporary}/age-version.txt"
recipient_output="${temporary}/recipient.txt"
validator_directory="${temporary}/validators"
mkdir -m 700 "${validator_directory}"
cleanup() {
  if [[ -d "${temporary}" && ! -L "${temporary}" ]]; then
    case "${temporary}" in
      "${workspace}"/sops-ciphertext-verify.*) rm -rf -- "${temporary}" ;;
      *) printf 'Refusing ambiguous SOPS verifier cleanup target.\n' >&2; return 1 ;;
    esac
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "${temporary}"

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

snapshot_protected_file() {
  local source="$1" destination="$2" class="$3" mode_bits size
  canonical_existing_path "${source}" || return 1
  case "${source}" in "${workspace}"/*) ;; *) return 1 ;; esac
  mode_bits="$(stat -c %a -- "${source}")" || return 1
  size="$(stat -c %s -- "${source}")" || return 1
  if [[ "${class}" == data ]]; then
    [[ "${mode_bits}" == 400 || "${mode_bits}" == 600 ]] || return 1
    [[ "${size}" -gt 0 && "${size}" -le 262144 ]] || return 1
  else
    [[ "${mode_bits}" == 500 || "${mode_bits}" == 700 ]] || return 1
  fi
  [[ "$(stat -c '%u:%g:%h' -- "${source}")" == "${operator_uid}:${workspace_gid}:1" ]] || return 1
  [[ "$(stat -c %d -- "${source}")" == "${workspace_device}" ]] || return 1
  copy_stable_file "${source}" "${destination}" || return 1
  if [[ "${class}" == data ]]; then chmod 600 "${destination}"; else chmod 700 "${destination}"; fi
}

trusted_git() {
  env -i PATH="${PATH}" HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    git --no-replace-objects -c credential.helper= -c core.askPass= \
      -c core.fsmonitor=false -c core.untrackedCache=false "$@"
}

# Establish repository trust before the first private-identity read.
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
  "${EXPECTED_REPOSITORY_HEAD}:bootstrap/flux/verify-sops-ciphertext.sh")" || fail
[[ "$(trusted_git -C "${repo_root}" hash-object --no-filters \
  "${repo_root}/bootstrap/flux/verify-sops-ciphertext.sh")" == "${self_blob}" ]] || fail
trusted_git -C "${repo_root}" cat-file blob \
  "${EXPECTED_REPOSITORY_HEAD}:versions.env" > "${versions_file}" || fail
chmod 600 "${versions_file}"

expected_validators=(
  scripts/validate_cloudflared_tunnel_token.py
  scripts/validate_release_state.py
  scripts/validate_release_transition.py
  scripts/validate_sops_ciphertext_snapshot.py
)
for validator_path in "${expected_validators[@]}"; do
  validator_name="${validator_path##*/}"
  trusted_git -C "${repo_root}" cat-file blob \
    "${EXPECTED_REPOSITORY_HEAD}:${validator_path}" \
    > "${validator_directory}/${validator_name}" || fail
  chmod 600 "${validator_directory}/${validator_name}"
  [[ "$(trusted_git -C "${repo_root}" hash-object --no-filters \
    "${validator_directory}/${validator_name}")" == \
    "$(trusted_git -C "${repo_root}" rev-parse \
      "${EXPECTED_REPOSITORY_HEAD}:${validator_path}")" ]] || fail
done

pin() {
  local name="$1"
  awk -F= -v key="${name}" '
    $1 == key && $2 ~ /^[A-Za-z0-9._:+@/-]+$/ { count += 1; value = $2 }
    END { if (count == 1) print value }
  ' "${versions_file}"
}
sops_version="$(pin SOPS_VERSION)"
sops_sha256="$(pin SOPS_LINUX_AMD64_SHA256)"
age_version="$(pin AGE_VERSION)"
age_keygen_sha256="$(pin AGE_KEYGEN_LINUX_AMD64_SHA256)"
[[ "${sops_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail
[[ "${age_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail
[[ "${sops_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "${age_keygen_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail

snapshot_protected_file "${config_source}" "${config}" data || fail
snapshot_protected_file "${ciphertext_source}" "${ciphertext}" data || fail
for public_binding in \
  ".sops.yaml:${config}" \
  "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml:${ciphertext}"; do
  public_path="${public_binding%%:*}"
  snapshot_path="${public_binding#*:}"
  [[ "$(trusted_git -C "${repo_root}" hash-object --no-filters "${snapshot_path}")" == \
    "$(trusted_git -C "${repo_root}" rev-parse \
      "${EXPECTED_REPOSITORY_HEAD}:${public_path}")" ]] || fail
done

# Only after all repository blobs are bound may private identities or readers
# enter the transaction.
snapshot_protected_file "${identity_source}" "${identity}" data || fail
snapshot_protected_file "${sops_source}" "${sops}" executable || fail
snapshot_protected_file "${age_keygen_source}" "${age_keygen}" executable || fail
[[ "$(sha256sum -- "${sops}" | awk '{print $1}')" == "${sops_sha256}" ]] || fail
[[ "$(sha256sum -- "${age_keygen}" | awk '{print $1}')" == "${age_keygen_sha256}" ]] || fail
"${age_keygen}" --version > "${age_version_output}" 2>/dev/null || fail
mapfile -t age_version_lines < "${age_version_output}"
[[ "${#age_version_lines[@]}" -eq 1 ]] || fail
actual_age_version="${age_version_lines[0]}"
[[ "$(stat -c %s -- "${age_version_output}")" -eq $(( ${#actual_age_version} + 1 )) ]] || fail
[[ "${actual_age_version}" == "${age_version#v}" || \
  "${actual_age_version}" == "age-keygen ${age_version#v}" ]] || fail
"${age_keygen}" -y "${identity}" > "${recipient_output}" 2>/dev/null || fail
mapfile -t recipient_lines < "${recipient_output}"
[[ "${#recipient_lines[@]}" -eq 1 ]] || fail
recipient="${recipient_lines[0]}"
[[ "${recipient}" =~ ^age1pq1[0-9a-z]+$ ]] || fail
[[ "$(stat -c %s -- "${recipient_output}")" -eq $(( ${#recipient} + 1 )) ]] || fail
[[ "$(grep -Fxc -- "      - ${recipient}" "${config}")" -eq 1 ]] || fail

SOPS_CONFIG_SNAPSHOT_FILE="${config}" \
SOPS_CIPHERTEXT_SNAPSHOT_FILE="${ciphertext}" \
  "${python3_binary}" -I "${validator_directory}/validate_sops_ciphertext_snapshot.py" \
  >/dev/null || fail
ciphertext_digest="$(sha256sum -- "${ciphertext}" | awk '{print $1}')" || fail
[[ "${ciphertext_digest}" =~ ^[0-9a-f]{64}$ ]] || fail

# Static grammar permits only one age stanza; a fresh network namespace makes
# any accidental remote key-service or version-check path unavailable as well.
set +e
env -i PATH="${PATH}" SOPS_AGE_KEY_FILE="${identity}" \
  timeout --signal=KILL 30s unshare --user --map-current-user --net -- \
  "${sops}" --disable-version-check --decrypt \
  --extract '["stringData"]["token"]' "${ciphertext}" \
  > "${token}" 2> "${sops_stderr}"
sops_status=$?
set -e
[[ "${sops_status}" -eq 0 ]] || fail
chmod 600 "${token}" "${sops_stderr}"
[[ ! -s "${sops_stderr}" ]] || fail
CLOUDFLARED_TUNNEL_TOKEN_FILE="${token}" \
EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256="${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256}" \
EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256="${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256}" \
  "${python3_binary}" -I "${validator_directory}/validate_cloudflared_tunnel_token.py" \
  >/dev/null || fail

[[ "$(sha256sum -- "${ciphertext}" | awk '{print $1}')" == "${ciphertext_digest}" ]] || fail
[[ "$(sha256sum -- "${sops}" | awk '{print $1}')" == "${sops_sha256}" ]] || fail
[[ "$(sha256sum -- "${age_keygen}" | awk '{print $1}')" == "${age_keygen_sha256}" ]] || fail
printf 'PASS committed SOPS MAC and Tunnel-token identity; ciphertext_sha256=%s\n' \
  "${ciphertext_digest}"
