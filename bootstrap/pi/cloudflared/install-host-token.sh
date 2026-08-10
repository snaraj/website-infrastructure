#!/bin/bash
# Validate the pi-admin Tunnel token against an exact reviewed-main validator.
# Root apply remains closed until a root-owned immutable launcher exists.
builtin set -Eeuo pipefail
builtin set +x
builtin set +o history

# Release safety stop. Both check and apply receive a protected bearer path in
# the latent implementation. Neither may run from mutable checkout bytes before
# a separately installed reviewed-blob launcher establishes stage-zero trust.
readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE}" != yes ]]; then
  builtin printf 'BLOCKED pi-admin token validation and installation require the trusted reviewed-blob launcher; no token was read and no host change was attempted.\n' >&2
  builtin exit 1
fi

PATH=/usr/sbin:/usr/bin:/sbin:/bin
builtin export PATH
builtin umask 077

die() {
  builtin printf 'FAIL pi-admin token validation made no host change.\n' >&2
  builtin exit 1
}

# Reject startup/runtime injection before any repository path or credential is
# opened. A minimal `env -i ... /bin/bash` invocation is still required because
# BASH_ENV and the dynamic loader act before the first script instruction.
while builtin read -r function_declaration function_flag inherited_function_name; do
  [[ "${function_declaration}" == declare && "${function_flag}" == -f ]] || die
  [[ "${inherited_function_name}" == die ]] || die
done < <(builtin declare -F)
for bootstrap_environment_name in $(builtin compgen -e); do
  case "${bootstrap_environment_name}" in
    BASH_ENV|ENV|BASHOPTS|SHELLOPTS|BASH_XTRACEFD|PS4|POSIXLY_CORRECT|\
      CDPATH|GLOBIGNORE|BASH_FUNC_*|LD_*) die ;;
  esac
done
builtin ulimit -S -c 0 || die
builtin ulimit -H -c 0 || die
[[ "$(builtin ulimit -S -c)" == 0 && "$(builtin ulimit -H -c)" == 0 ]] || die
[[ "${BASH}" == /bin/bash ]] || die

mode="${1:---check}"
(( $# <= 1 )) || die
case "${mode}" in --check|--apply) ;; *) die ;; esac
# Executing mutable checkout bytes as root and asking those same bytes to attest
# themselves is not a root of trust. Apply must remain unavailable until a
# separately reviewed root-owned launcher extracts the exact commit blobs into
# a private directory and invokes the extracted installer with /bin/bash.
[[ "${mode}" == --check ]] || die

for command_name in awk cat chmod cmp dirname env git id mktemp readlink rm \
  sha256sum stat uname; do
  builtin command -v "${command_name}" >/dev/null 2>&1 || die
done
[[ "$(uname -s)" == Linux ]] || die

git_binary="$(readlink -e -- /usr/bin/git)" || die
[[ "${git_binary}" == /usr/bin/git && -f "${git_binary}" && ! -L "${git_binary}" && -x "${git_binary}" ]] || die
[[ "$(stat -c '%u:%h' -- "${git_binary}")" == 0:1 ]] || die
git_mode="$(stat -c %a -- "${git_binary}")" || die
(( (8#${git_mode} & 0022) == 0 )) || die

python3_binary="$(readlink -e -- /usr/bin/python3)" || die
[[ "${python3_binary}" =~ ^/usr/bin/python3(\.[0-9]+)?$ ]] || die
[[ -f "${python3_binary}" && ! -L "${python3_binary}" && -x "${python3_binary}" ]] || die
[[ "$(stat -c '%u:%h' -- "${python3_binary}")" == 0:1 ]] || die
python3_mode="$(stat -c %a -- "${python3_binary}")" || die
(( (8#${python3_mode} & 0022) == 0 )) || die
"${python3_binary}" -I -B -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' || die

: "${CLOUDFLARED_TOKEN_WORKSPACE:?Set the protected token workspace root}"
: "${CLOUDFLARED_TUNNEL_TOKEN_FILE:?Set the protected token file path}"
: "${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256:?Set the protected account-ID digest}"
: "${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256:?Set the protected pi-admin Tunnel-ID digest}"
: "${EXPECTED_REPOSITORY_HEAD:?Set the exact reviewed main commit}"
: "${EXPECTED_REPOSITORY_OWNER_UID:?Set the reviewed checkout owner UID}"
[[ "${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die
[[ "${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die
[[ "${EXPECTED_REPOSITORY_HEAD}" =~ ^[0-9a-f]{40}$ ]] || die
[[ "${EXPECTED_REPOSITORY_OWNER_UID}" =~ ^[1-9][0-9]*$ ]] || die
[[ "${EUID}" -eq "${EXPECTED_REPOSITORY_OWNER_UID}" ]] || die

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

self_source="$(readlink -e -- "${BASH_SOURCE[0]}")" || die
repo_root="$(cd "$(dirname -- "${self_source}")/../../.." && pwd -P)" || die
[[ "${self_source}" == "${repo_root}/bootstrap/pi/cloudflared/install-host-token.sh" ]] || die
canonical_existing_path "${self_source}" || die
[[ -f "${self_source}" && ! -L "${self_source}" ]] || die

trusted_git() {
  env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    "${git_binary}" --no-replace-objects -c safe.directory="${repo_root}" \
      -c credential.helper= -c core.askPass= -c core.fsmonitor=false \
      -c core.hooksPath=/dev/null -C "${repo_root}" "$@"
}

[[ "$(trusted_git rev-parse --show-toplevel)" == "${repo_root}" ]] || die
git_dir="$(trusted_git rev-parse --absolute-git-dir)" || die
[[ "${git_dir}" == "${repo_root}/.git" && -d "${git_dir}" && ! -L "${git_dir}" ]] || die
[[ "$(stat -c %u -- "${repo_root}")" == "${EXPECTED_REPOSITORY_OWNER_UID}" ]] || die
[[ "$(stat -c %u -- "${git_dir}")" == "${EXPECTED_REPOSITORY_OWNER_UID}" ]] || die
repo_mode="$(stat -c %a -- "${repo_root}")" || die
git_dir_mode="$(stat -c %a -- "${git_dir}")" || die
(( (8#${repo_mode} & 0022) == 0 && (8#${git_dir_mode} & 0022) == 0 )) || die
[[ ! -e "${git_dir}/info/grafts" ]] || die
[[ ! -e "${git_dir}/objects/info/alternates" ]] || die
[[ -z "$(trusted_git for-each-ref --format='%(refname)' refs/replace)" ]] || die
[[ "$(trusted_git rev-parse --verify 'HEAD^{commit}')" == "${EXPECTED_REPOSITORY_HEAD}" ]] || die
[[ "$(trusted_git symbolic-ref -q HEAD)" == refs/heads/main ]] || die
[[ "$(trusted_git rev-parse --is-shallow-repository)" == false ]] || die

workspace="${CLOUDFLARED_TOKEN_WORKSPACE}"
source_file="${CLOUDFLARED_TUNNEL_TOKEN_FILE}"
canonical_existing_path "${workspace}" || die
canonical_existing_path "${source_file}" || die
[[ -d "${workspace}" && -f "${source_file}" && ! -L "${source_file}" ]] || die
case "${source_file}" in "${workspace}"/*) ;; *) die ;; esac
[[ "$(stat -c '%u:%a' -- "${workspace}")" == "${EXPECTED_REPOSITORY_OWNER_UID}:700" ]] || die
workspace_gid="$(stat -c %g -- "${workspace}")" || die
source_mode="$(stat -c %a -- "${source_file}")" || die
[[ "${source_mode}" == 400 || "${source_mode}" == 600 ]] || die
[[ "$(stat -c '%u:%g:%h' -- "${source_file}")" == \
  "${EXPECTED_REPOSITORY_OWNER_UID}:${workspace_gid}:1" ]] || die

temporary="$(mktemp -d "${workspace%/}/pi-admin-token-check.XXXXXX")" || die
cleanup() {
  [[ -n "${temporary:-}" ]] || return 0
  [[ -d "${temporary}" && ! -L "${temporary}" ]] || {
    builtin printf 'Refusing ambiguous token-workspace cleanup target.\n' >&2
    return 1
  }
  case "${temporary}" in
    "${workspace}"/pi-admin-token-check.*) rm -rf -- "${temporary}" ;;
    *) builtin printf 'Refusing ambiguous token-workspace cleanup target.\n' >&2; return 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "${temporary}"
effective_gid="$(id -g)" || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${temporary}")" == \
  "${EUID}:${effective_gid}:700:2" ]] || die

snapshot_regular_file() {
  local source="$1" destination="$2" expected_uid="$3"
  local source_mode source_state descriptor opened_state after_state
  canonical_existing_path "${source}" || return 1
  [[ -f "${source}" && ! -L "${source}" ]] || return 1
  [[ "$(stat -c '%u:%h' -- "${source}")" == "${expected_uid}:1" ]] || return 1
  source_mode="$(stat -c %a -- "${source}")" || return 1
  (( (8#${source_mode} & 0022) == 0 )) || return 1
  source_state="$(stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "${source}")" || return 1
  exec {descriptor}<"${source}" || return 1
  opened_state="$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- \
    "/proc/$$/fd/${descriptor}")" || {
    exec {descriptor}<&-
    return 1
  }
  if [[ "${opened_state}" != "${source_state}" ]] || \
    ! command cat <&"${descriptor}" > "${destination}"; then
    exec {descriptor}<&-
    return 1
  fi
  after_state="$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- \
    "/proc/$$/fd/${descriptor}")" || {
    exec {descriptor}<&-
    return 1
  }
  exec {descriptor}<&-
  [[ "${after_state}" == "${source_state}" ]] || return 1
  [[ "$(stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "${source}")" == \
    "${source_state}" ]] || return 1
  chmod 600 "${destination}"
  [[ "$(stat -c '%u:%g:%a:%h' -- "${destination}")" == \
    "${EUID}:${effective_gid}:600:1" ]] || return 1
}

validator_source="${repo_root}/scripts/validate_cloudflared_tunnel_token.py"
self_worktree="${temporary}/install-host-token.worktree"
self_blob="${temporary}/install-host-token.blob"
validator_worktree="${temporary}/validate-token.worktree"
token_validator="${temporary}/validate-token.blob"
snapshot_regular_file "${self_source}" "${self_worktree}" \
  "${EXPECTED_REPOSITORY_OWNER_UID}" || die
snapshot_regular_file "${validator_source}" "${validator_worktree}" \
  "${EXPECTED_REPOSITORY_OWNER_UID}" || die

critical_inventory='100755 bootstrap/pi/cloudflared/install-host-token.sh
100644 scripts/validate_cloudflared_tunnel_token.py'
actual_critical_inventory="$(trusted_git ls-tree "${EXPECTED_REPOSITORY_HEAD}" -- \
  bootstrap/pi/cloudflared/install-host-token.sh \
  scripts/validate_cloudflared_tunnel_token.py | \
  awk '{ mode=$1; sub(/^[^\t]*\t/, ""); print mode " " $0 }')" || die
[[ "${actual_critical_inventory}" == "${critical_inventory}" ]] || die
trusted_git cat-file blob \
  "${EXPECTED_REPOSITORY_HEAD}:bootstrap/pi/cloudflared/install-host-token.sh" \
  > "${self_blob}" || die
trusted_git cat-file blob \
  "${EXPECTED_REPOSITORY_HEAD}:scripts/validate_cloudflared_tunnel_token.py" \
  > "${token_validator}" || die
chmod 600 "${self_blob}" "${token_validator}"
[[ "$(trusted_git hash-object --no-filters "${self_blob}")" == \
  "$(trusted_git rev-parse "${EXPECTED_REPOSITORY_HEAD}:bootstrap/pi/cloudflared/install-host-token.sh")" ]] || die
[[ "$(trusted_git hash-object --no-filters "${token_validator}")" == \
  "$(trusted_git rev-parse "${EXPECTED_REPOSITORY_HEAD}:scripts/validate_cloudflared_tunnel_token.py")" ]] || die
cmp -s -- "${self_worktree}" "${self_blob}" || die
cmp -s -- "${validator_worktree}" "${token_validator}" || die

env -i PATH=/usr/bin:/bin \
  CLOUDFLARED_TUNNEL_TOKEN_FILE="${source_file}" \
  EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256="${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256}" \
  EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256="${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256}" \
  "${python3_binary}" -I -B "${token_validator}" >/dev/null || die

cleanup || die
temporary=''
trap - EXIT HUP INT TERM
builtin printf 'PASS reviewed-main pi-admin Tunnel token shape; no host state changed.\n'
