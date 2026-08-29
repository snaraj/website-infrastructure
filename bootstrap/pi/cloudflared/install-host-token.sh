#!/bin/bash
# Validate and atomically install one pi-admin Tunnel runtime token.
builtin set -Eeuo pipefail
builtin set +x
builtin set +o history

mode="${1:---check}"
expected_operation=token-check
[[ "${mode}" == --apply ]] && expected_operation=token-apply
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE:-}" != yes ||
      "${REVIEWED_BLOB_OPERATION:-}" != "${expected_operation}" ||
      ! "${REVIEWED_BLOB_ROOT:-}" =~ ^/run/website-infrastructure/reviewed-op\.[A-Za-z0-9]+$ ||
      "${EUID}" -ne 0 || "${BASH}" != /usr/bin/bash ]]; then
  builtin printf 'BLOCKED pi-admin token validation and installation require the trusted reviewed-blob launcher; no token was read and no host change was attempted.\n' >&2
  builtin exit 1
fi

PATH=/usr/sbin:/usr/bin:/sbin:/bin
builtin export PATH
builtin umask 077

die() {
  builtin printf 'FAIL pi-admin token transaction.\n' >&2
  builtin exit 1
}

while builtin read -r declaration flag inherited_name; do
  [[ "${declaration}" == declare && "${flag}" == -f ]] || die
  [[ "${inherited_name}" == die ]] || die
done < <(builtin declare -F)
for inherited_name in $(builtin compgen -e); do
  case "${inherited_name}" in
    BASH_ENV|ENV|BASHOPTS|SHELLOPTS|BASH_XTRACEFD|PS4|POSIXLY_CORRECT|\
      CDPATH|GLOBIGNORE|BASH_FUNC_*|LD_*|PYTHON*|GIT_*|\
      DBUS_*|SYSTEMD_*|SYSTEMCTL_*|JOURNAL_*|PAGER|LESS) die ;;
  esac
done
builtin ulimit -S -c 0 || die
builtin ulimit -H -c 0 || die
[[ "$(builtin ulimit -S -c)" == 0 && "$(builtin ulimit -H -c)" == 0 ]] || die
(( $# == 1 )) || die
case "${mode}" in --check|--apply) ;; *) die ;; esac

for command_name in mawk cat chmod chown cmp cp dirname env flock id install \
  mktemp mv readlink rm rmdir sha256sum stat uname; do
  builtin command -v "${command_name}" >/dev/null 2>&1 || die
done
[[ "$(uname -s)" == Linux ]] || die

: "${CLOUDFLARED_TOKEN_WORKSPACE:?}"
: "${CLOUDFLARED_TUNNEL_TOKEN_FILE:?}"
: "${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256:?}"
: "${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256:?}"
: "${EXPECTED_REPOSITORY_HEAD:?}"
: "${EXPECTED_REPOSITORY_OWNER_UID:?}"
[[ "${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die
[[ "${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die
[[ "${EXPECTED_REPOSITORY_HEAD}" =~ ^[0-9a-f]{40}$ ]] || die
[[ "${EXPECTED_REPOSITORY_OWNER_UID}" =~ ^[1-9][0-9]*$ ]] || die

canonical_existing_path() {
  local candidate="$1" resolved current
  [[ "${candidate}" == /* ]] || return 1
  resolved="$(readlink -e -- "${candidate}")" || return 1
  [[ "${candidate}" == "${resolved}" ]] || return 1
  current="${candidate}"
  while [[ "${current}" != / ]]; do
    [[ ! -L "${current}" ]] || return 1
    current="$(dirname -- "${current}")" || return 1
  done
}

repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)" || die
[[ "${repo_root}" == "${REVIEWED_BLOB_ROOT}" ]] || die
self_source="$(readlink -e -- "${BASH_SOURCE[0]}")" || die
validator="${repo_root}/scripts/validate_cloudflared_tunnel_token.py"
[[ "${self_source}" == "${repo_root}/bootstrap/pi/cloudflared/install-host-token.sh" ]] || die
canonical_existing_path "${self_source}" || die
canonical_existing_path "${validator}" || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${self_source}")" == 0:0:500:1 ]] || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${validator}")" == 0:0:400:1 ]] || die

python3_binary=/usr/bin/python3.12
canonical_existing_path "${python3_binary}" || die
[[ -f "${python3_binary}" && -x "${python3_binary}" ]] || die
[[ "$(stat -c '%u:%g:%h' -- "${python3_binary}")" == 0:0:1 ]] || die
python_mode="$(stat -c %a -- "${python3_binary}")" || die
(( (8#${python_mode} & 0022) == 0 )) || die
"${python3_binary}" -I -B -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' || die

workspace="${CLOUDFLARED_TOKEN_WORKSPACE}"
source_file="${CLOUDFLARED_TUNNEL_TOKEN_FILE}"
canonical_existing_path "${workspace}" || die
canonical_existing_path "${source_file}" || die
[[ -d "${workspace}" && ! -L "${workspace}" ]] || die
case "${source_file}" in "${workspace}"/*) ;; *) die ;; esac
[[ "$(stat -c '%u:%a' -- "${workspace}")" == \
  "${EXPECTED_REPOSITORY_OWNER_UID}:700" ]] || die
workspace_gid="$(stat -c %g -- "${workspace}")" || die
source_mode="$(stat -c %a -- "${source_file}")" || die
[[ "${source_mode}" == 400 || "${source_mode}" == 600 ]] || die
[[ "$(stat -c '%u:%g:%h' -- "${source_file}")" == \
  "${EXPECTED_REPOSITORY_OWNER_UID}:${workspace_gid}:1" ]] || die

runtime_parent=/run/website-infrastructure
canonical_existing_path "${runtime_parent}" || die
[[ "$(stat -c '%u:%g:%a' -- "${runtime_parent}")" == 0:0:700 ]] || die
temporary="$(mktemp -d "${runtime_parent}/pi-admin-token.XXXXXXXX")" || die
chmod 0700 "${temporary}" || die
candidate="${temporary}/candidate"
backup="${temporary}/previous"
lock_path="${runtime_parent}/pi-admin-token.lock"
destination_directory=/etc/cloudflared
destination="${destination_directory}/pi-admin.token"
destination_directory_created=no
mutation_started=no
committed=no
previous_state=absent
previous_digest=''

safe_cleanup() {
  [[ -n "${temporary:-}" && -d "${temporary}" && ! -L "${temporary}" ]] || return 1
  case "${temporary}" in
    "${runtime_parent}"/pi-admin-token.*) rm -rf -- "${temporary}" ;;
    *) return 1 ;;
  esac
}

file_digest() {
  sha256sum -- "$1" | /usr/bin/mawk '{print $1}'
}

destination_state() {
  if [[ -L "${destination}" || ( -e "${destination}" && ! -f "${destination}" ) ]]; then
    builtin printf 'unsafe'
  elif [[ -f "${destination}" ]]; then
    builtin printf 'present:%s:%s' \
      "$(stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g:%a' -- "${destination}")" \
      "$(file_digest "${destination}")"
  else
    builtin printf 'absent'
  fi
}

rollback() {
  local current
  [[ "${mutation_started}" == yes && "${committed}" == no ]] || return 0
  current="$(destination_state)" || return 1
  [[ "${current}" != unsafe ]] || return 1
  if [[ "${previous_state}" == absent ]]; then
    if [[ "${current}" != absent ]]; then rm -f -- "${destination}" || return 1; fi
  else
    [[ -f "${backup}" && ! -L "${backup}" ]] || return 1
    install -o root -g root -m 0600 -- "${backup}" "${candidate}.rollback" || return 1
    [[ "$(file_digest "${candidate}.rollback")" == "${previous_digest}" ]] || return 1
    mv -fT -- "${candidate}.rollback" "${destination}" || return 1
  fi
  if [[ "${previous_state}" == absent ]]; then
    [[ "$(destination_state)" == absent ]] || return 1
  else
    [[ "$(stat -c '%u:%g:%a:%h' -- "${destination}")" == 0:0:600:1 ]] || return 1
    [[ "$(file_digest "${destination}")" == "${previous_digest}" ]] || return 1
  fi
  if [[ "${destination_directory_created}" == yes ]]; then
    if [[ -e "${destination_directory}" || -L "${destination_directory}" ]]; then
      rmdir -- "${destination_directory}" || return 1
    fi
    destination_directory_created=no
  fi
  mutation_started=no
}

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( status != 0 )); then rollback || builtin printf 'ROLLBACK=INCOMPLETE\n' >&2; fi
  safe_cleanup >/dev/null 2>&1 || true
  exit "${status}"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "${mode}" == --apply ]]; then
  [[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || die
  [[ "${TWO_WORKING_SESSIONS_PROVEN:-}" == yes ]] || die
  [[ "${CONFIRM_PI_ADMIN_TOKEN_INSTALL:-}" == install-reviewed-pi-admin-token ]] || die
fi

# Copy the owner-held token through one stable descriptor into root-private
# custody. The validator never opens the owner path and never prints a field.
source_state="$(stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "${source_file}")" || die
exec {source_fd}<"${source_file}" || die
[[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "/proc/$$/fd/${source_fd}")" == \
  "${source_state}" ]] || die
cat <&"${source_fd}" >"${candidate}" || die
[[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "/proc/$$/fd/${source_fd}")" == \
  "${source_state}" ]] || die
exec {source_fd}<&-
[[ "$(stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "${source_file}")" == \
  "${source_state}" ]] || die
chmod 0400 "${candidate}" || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${candidate}")" == 0:0:400:1 ]] || die

/usr/bin/env -i PATH=/usr/bin HOME=/nonexistent LC_ALL=C \
  "CLOUDFLARED_TUNNEL_TOKEN_FILE=${candidate}" \
  "EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256=${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256}" \
  "EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256=${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256}" \
  "${python3_binary}" -I -B "${validator}" >/dev/null || die

if [[ "${mode}" == --check ]]; then
  safe_cleanup || die
  temporary=''
  trap - EXIT HUP INT TERM
  builtin printf 'PI_ADMIN_TOKEN_CHECK=PASS\n'
  builtin exit 0
fi

if [[ ! -e "${destination_directory}" ]]; then
  destination_directory_created=yes
  mutation_started=yes
  install -d -o root -g root -m 0700 -- "${destination_directory}" || die
fi
canonical_existing_path "${destination_directory}" || die
[[ "$(stat -c '%u:%g:%a' -- "${destination_directory}")" == 0:0:700 ]] || die
if [[ ! -e "${lock_path}" ]]; then
  install -o root -g root -m 0600 -- /dev/null "${lock_path}" || die
fi
[[ "$(stat -c '%u:%g:%a:%h' -- "${lock_path}")" == 0:0:600:1 ]] || die
exec 9<>"${lock_path}" || die
flock -n 9 || die

previous_state="$(destination_state)" || die
[[ "${previous_state}" != unsafe ]] || die
if [[ "${previous_state}" != absent ]]; then
  previous_digest="${previous_state##*:}"
  [[ "$(stat -c '%u:%g:%a:%h' -- "${destination}")" == 0:0:600:1 ]] || die
  cp --preserve=mode,ownership,timestamps -- "${destination}" "${backup}" || die
  chmod 0400 "${backup}" || die
  [[ "$(file_digest "${backup}")" == "${previous_digest}" ]] || die
fi

# Revalidate immediately before the atomic same-filesystem commit.
/usr/bin/env -i PATH=/usr/bin HOME=/nonexistent LC_ALL=C \
  "CLOUDFLARED_TUNNEL_TOKEN_FILE=${candidate}" \
  "EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256=${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256}" \
  "EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256=${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256}" \
  "${python3_binary}" -I -B "${validator}" >/dev/null || die
[[ "$(destination_state)" == "${previous_state}" ]] || die
chmod 0600 "${candidate}" || die
mutation_started=yes
mv -fT -- "${candidate}" "${destination}" || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${destination}")" == 0:0:600:1 ]] || die

/usr/bin/env -i PATH=/usr/bin HOME=/nonexistent LC_ALL=C \
  "CLOUDFLARED_TUNNEL_TOKEN_FILE=${destination}" \
  "EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256=${EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256}" \
  "EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256=${EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256}" \
  "${python3_binary}" -I -B "${validator}" >/dev/null || die
committed=yes
safe_cleanup || die
temporary=''
trap - EXIT HUP INT TERM
builtin printf 'PI_ADMIN_TOKEN_INSTALL=PASS\n'
