#!/bin/bash
# Prove one pinned active connector did not copy its bearer token into process
# metadata or any complete journal field associated with the unit.
builtin set -Eeuo pipefail
builtin set +x
builtin set +o history

# The canary opens the installed bearer and privileged runtime metadata. It
# accepts only a root-private exact-blob extraction created by the installed
# stage-zero launcher.
if [[ "${1:-}" != --verify || $# -ne 1 ||
      "${REVIEWED_BLOB_LAUNCHER_AVAILABLE:-}" != yes ||
      "${REVIEWED_BLOB_OPERATION:-}" != runtime-verify ||
      ! "${REVIEWED_BLOB_ROOT:-}" =~ ^/run/website-infrastructure/reviewed-op\.[A-Za-z0-9]+$ ||
      "${EUID}" -ne 0 || "${BASH}" != /usr/bin/bash ]]; then
  builtin printf 'BLOCKED pi-admin runtime token verification requires the trusted reviewed-blob launcher; no token or runtime metadata was read.\n' >&2
  builtin exit 1
fi

PATH=/usr/sbin:/usr/bin:/sbin:/bin
builtin export PATH
builtin umask 077

fail() {
  builtin printf 'FAIL pi-admin runtime token-redaction canary.\n' >&2
  builtin exit 1
}

# A minimal `env -i ... /usr/bin/bash` invocation prevents pre-script BASH_ENV or
# loader execution; these builtin-only checks then fail closed on any residue.
while builtin read -r function_declaration function_flag inherited_function_name; do
  [[ "${function_declaration}" == declare && "${function_flag}" == -f ]] || fail
  [[ "${inherited_function_name}" == fail ]] || fail
done < <(builtin declare -F)
for bootstrap_environment_name in $(builtin compgen -e); do
  case "${bootstrap_environment_name}" in
    BASH_ENV|ENV|BASHOPTS|SHELLOPTS|BASH_XTRACEFD|PS4|POSIXLY_CORRECT|\
      CDPATH|GLOBIGNORE|BASH_FUNC_*|LD_*|\
      DBUS_*|SYSTEMD_*|SYSTEMCTL_*|JOURNAL_*|PAGER|LESS) fail ;;
  esac
done
builtin ulimit -S -c 0 || fail
builtin ulimit -H -c 0 || fail
[[ "$(builtin ulimit -S -c)" == 0 && "$(builtin ulimit -H -c)" == 0 ]] || fail
[[ "${BASH}" == /usr/bin/bash ]] || fail
[[ "${EUID}" -eq 0 ]] || fail

: "${EXPECTED_REPOSITORY_HEAD:?Set the exact reviewed main commit}"
: "${EXPECTED_REPOSITORY_OWNER_UID:?Set the reviewed checkout owner UID}"
[[ "${EXPECTED_REPOSITORY_HEAD}" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "${EXPECTED_REPOSITORY_OWNER_UID}" =~ ^[1-9][0-9]*$ ]] || fail

for command_name in mawk cat chmod cmp dirname env findmnt grep id \
  getent journalctl mktemp passwd readlink rm sha256sum stat swapon systemctl uname; do
  builtin command -v "${command_name}" >/dev/null 2>&1 || fail
done
[[ "$(uname -s)" == Linux ]] || fail

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

self_source="$(readlink -e -- "${BASH_SOURCE[0]}")" || fail
repo_root="$(cd "$(dirname -- "${self_source}")/../../.." && pwd -P)" || fail
reviewed_unit_source="${repo_root}/bootstrap/pi/cloudflared/pi-admin.service"
installed_unit=/etc/systemd/system/pi-admin.service
[[ "${self_source}" == "${repo_root}/bootstrap/pi/cloudflared/verify-host-token-redaction.sh" ]] || fail
[[ "${repo_root}" == "${REVIEWED_BLOB_ROOT}" ]] || fail
canonical_existing_path "${self_source}" || fail
canonical_existing_path "${reviewed_unit_source}" || fail
canonical_existing_path "${installed_unit}" || fail
[[ "$(stat -c '%u:%g:%a:%h' -- "${self_source}")" == 0:0:500:1 ]] || fail
[[ "$(stat -c '%u:%g:%a:%h' -- "${reviewed_unit_source}")" == 0:0:400:1 ]] || fail
[[ "$(stat -c '%u:%g:%a:%h' -- "${installed_unit}")" == 0:0:644:1 ]] || fail

trusted_systemctl() {
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C systemctl "$@"
}

trusted_journalctl() {
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C journalctl "$@"
}

token_file=/etc/cloudflared/pi-admin.token
credential_directory=/run/credentials/pi-admin.service
expected_credential_file=${credential_directory}/tunnel-token

canonical_existing_path /run/website-infrastructure || fail
[[ -d /run/website-infrastructure && ! -L /run/website-infrastructure ]] || fail
[[ "$(stat -c '%u:%g:%a' /run/website-infrastructure)" == 0:0:700 ]] || fail
temporary_directory="$(mktemp -d /run/website-infrastructure/pi-admin-canary.XXXXXXXX)" || fail
cleanup() {
  [[ -n "${temporary_directory:-}" ]] || return 0
  [[ -d "${temporary_directory}" && ! -L "${temporary_directory}" ]] || {
    builtin printf 'Refusing ambiguous pi-admin canary cleanup target.\n' >&2
    return 1
  }
  case "${temporary_directory}" in
    /run/website-infrastructure/pi-admin-canary.*) rm -rf -- "${temporary_directory}" ;;
    *) builtin printf 'Refusing ambiguous pi-admin canary cleanup target.\n' >&2; return 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "${temporary_directory}"
effective_gid="$(id -g)" || fail
[[ "$(stat -c '%u:%g:%a:%h' -- "${temporary_directory}")" == \
  "0:${effective_gid}:700:2" ]] || fail

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
    "0:${effective_gid}:600:1" ]] || return 1
}

versions_source="${repo_root}/versions.env"
self_snapshot="${temporary_directory}/verify-token-redaction.snapshot"
reviewed_unit_snapshot="${temporary_directory}/pi-admin.reviewed.service"
installed_unit_snapshot="${temporary_directory}/pi-admin.installed.service"
versions_file="${temporary_directory}/versions.blob"
canonical_existing_path "${versions_source}" || fail
[[ "$(stat -c '%u:%g:%a:%h' -- "${versions_source}")" == 0:0:400:1 ]] || fail
snapshot_regular_file "${self_source}" "${self_snapshot}" 0 || fail
snapshot_regular_file "${reviewed_unit_source}" "${reviewed_unit_snapshot}" 0 || fail
snapshot_regular_file "${installed_unit}" "${installed_unit_snapshot}" 0 || fail
snapshot_regular_file "${versions_source}" "${versions_file}" 0 || fail
cmp -s -- "${self_source}" "${self_snapshot}" || fail
cmp -s -- "${reviewed_unit_snapshot}" "${installed_unit_snapshot}" || fail
cmp -s -- "${versions_source}" "${versions_file}" || fail

unit_properties="$(trusted_systemctl show --property=LoadState --property=FragmentPath \
  --property=DropInPaths --property=NeedDaemonReload --property=UnitFileState \
  pi-admin.service)" || fail
property_value() {
  local key="$1" count value
  count="$(builtin printf '%s\n' "${unit_properties}" | \
    /usr/bin/mawk -F= -v expected="${key}" '$1 == expected {count++} END {print count + 0}')" || return 1
  [[ "${count}" == 1 ]] || return 1
  value="$(builtin printf '%s\n' "${unit_properties}" | \
    /usr/bin/mawk -F= -v expected="${key}" '$1 == expected {sub(/^[^=]*=/, ""); print}')" || return 1
  builtin printf '%s' "${value}"
}
[[ "$(property_value LoadState)" == loaded ]] || fail
[[ "$(property_value FragmentPath)" == "${installed_unit}" ]] || fail
[[ -z "$(property_value DropInPaths)" ]] || fail
[[ "$(property_value NeedDaemonReload)" == no ]] || fail
[[ "$(property_value UnitFileState)" == enabled ]] || fail

service_account_owner() {
  local record name uid gid home shell group_record group_name group_gid members
  record="$(getent passwd cloudflared)" || return 1
  IFS=: read -r name _ uid gid _ home shell <<<"${record}"
  [[ "${name}" == cloudflared && "${uid}" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "${gid}" =~ ^[1-9][0-9]*$ && "${home}" == /nonexistent ]] || return 1
  [[ "${shell}" == /usr/sbin/nologin || "${shell}" == /usr/bin/false ]] || return 1
  group_record="$(getent group cloudflared)" || return 1
  IFS=: read -r group_name _ group_gid members <<<"${group_record}"
  [[ "${group_name}" == cloudflared && "${group_gid}" == "${gid}" && -z "${members}" ]] || \
    return 1
  [[ "$(id -G cloudflared)" == "${gid}" ]] || return 1
  [[ "$(passwd -S cloudflared)" == 'cloudflared L '* ]] || return 1
  builtin printf '%s:%s' "${uid}" "${gid}"
}
service_account="$(service_account_owner)" || fail

load_version_value() {
  local key="$1"
  /usr/bin/mawk -F= -v expected="${key}" '
    $1 == expected && $2 ~ /^[A-Za-z0-9._:+@/-]+$/ { count += 1; value = $2 }
    END { if (count == 1) print value }
  ' "${versions_file}"
}
CLOUDFLARED_HOST_ARM64_SHA256="$(load_version_value CLOUDFLARED_HOST_ARM64_SHA256)"
[[ "${CLOUDFLARED_HOST_ARM64_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail

canonical_existing_path "${token_file}" || fail
[[ -f "${token_file}" && ! -L "${token_file}" ]] || fail
[[ "$(stat -c '%u:%g:%a:%h' -- "${token_file}")" == 0:0:600:1 ]] || fail

runtime_identity() {
  local properties pid invocation start_time executable executable_state
  local executable_state_after executable_digest
  properties="$(trusted_systemctl show --property=MainPID --property=InvocationID pi-admin.service)" || return 1
  pid="$(printf '%s\n' "${properties}" | /usr/bin/mawk -F= '$1 == "MainPID" {print $2}')"
  invocation="$(printf '%s\n' "${properties}" | /usr/bin/mawk -F= '$1 == "InvocationID" {print $2}')"
  [[ "${pid}" =~ ^[1-9][0-9]*$ && "${invocation}" =~ ^[0-9a-f]{32}$ ]] || return 1
  [[ -r "/proc/${pid}/stat" && -r "/proc/${pid}/status" ]] || return 1
  [[ -r "/proc/${pid}/cmdline" && -r "/proc/${pid}/environ" ]] || return 1
  start_time="$(/usr/bin/mawk '{print $22}' "/proc/${pid}/stat")" || return 1
  [[ "${start_time}" =~ ^[1-9][0-9]*$ ]] || return 1
  executable="$(readlink -e -- "/proc/${pid}/exe")" || return 1
  [[ "${executable}" == /usr/local/bin/cloudflared ]] || return 1
  [[ "$(stat -Lc '%u:%g:%a:%h' -- "/proc/${pid}/exe")" == 0:0:755:1 ]] || return 1
  executable_state="$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g:%a' -- "/proc/${pid}/exe")" || return 1
  [[ "${executable_state##*:}" == 755 ]] || return 1
  [[ "${executable_state%:*}" == *:0:0 ]] || return 1
  executable_digest="$(sha256sum -- "/proc/${pid}/exe" 2>/dev/null | /usr/bin/mawk '{print $1}')" || return 1
  [[ "${executable_digest}" == "${CLOUDFLARED_HOST_ARM64_SHA256}" ]] || return 1
  executable_state_after="$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g:%a' -- "/proc/${pid}/exe")" || return 1
  [[ "${executable_state_after}" == "${executable_state}" ]] || return 1
  printf '%s:%s:%s' "${pid}" "${invocation}" "${start_time}"
}

runtime_process_owner() {
  local process_id="$1" uid_values gid_values
  local uid_real uid_effective uid_saved uid_filesystem
  local gid_real gid_effective gid_saved gid_filesystem
  uid_values="$(/usr/bin/mawk '$1 == "Uid:" {print $2, $3, $4, $5}' "/proc/${process_id}/status")" || return 1
  gid_values="$(/usr/bin/mawk '$1 == "Gid:" {print $2, $3, $4, $5}' "/proc/${process_id}/status")" || return 1
  read -r uid_real uid_effective uid_saved uid_filesystem <<<"${uid_values}"
  read -r gid_real gid_effective gid_saved gid_filesystem <<<"${gid_values}"
  [[ "${uid_real}" =~ ^[1-9][0-9]*$ && "${gid_real}" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "${uid_real}" == "${uid_effective}" && "${uid_real}" == "${uid_saved}" ]] || return 1
  [[ "${uid_real}" == "${uid_filesystem}" ]] || return 1
  [[ "${gid_real}" == "${gid_effective}" && "${gid_real}" == "${gid_saved}" ]] || return 1
  [[ "${gid_real}" == "${gid_filesystem}" ]] || return 1
  printf '%s:%s' "${uid_real}" "${gid_real}"
}

runtime_credential_file() {
  local process_id="$1"
  local -a arguments=()
  mapfile -d '' -t arguments < "/proc/${process_id}/cmdline" || return 1
  [[ "${#arguments[@]}" -eq 6 ]] || return 1
  [[ "${arguments[0]}" == /usr/local/bin/cloudflared ]] || return 1
  [[ "${arguments[1]}" == --no-autoupdate ]] || return 1
  [[ "${arguments[2]}" == tunnel && "${arguments[3]}" == run ]] || return 1
  [[ "${arguments[4]}" == --token-file ]] || return 1
  [[ "${arguments[5]}" == "${expected_credential_file}" ]] || return 1
  printf '%s' "${arguments[5]}"
}

mount_has_option() {
  local options="$1" expected="$2"
  case ",${options}," in
    *",${expected},"*) return 0 ;;
    *) return 1 ;;
  esac
}

assert_runtime_credential_custody() {
  local process_owner="$1" process_uid process_gid
  local directory_state file_state mount_record mount_target mount_type mount_options extra
  process_uid="${process_owner%%:*}"
  process_gid="${process_owner##*:}"
  [[ "$(readlink -e -- "${credential_directory}")" == "${credential_directory}" ]] || return 1
  [[ "$(readlink -e -- "${expected_credential_file}")" == "${expected_credential_file}" ]] || return 1
  [[ -d "${credential_directory}" && ! -L "${credential_directory}" ]] || return 1
  [[ -f "${expected_credential_file}" && ! -L "${expected_credential_file}" ]] || return 1
  directory_state="$(stat -c '%u:%g:%a:%h' -- "${credential_directory}")" || return 1
  file_state="$(stat -c '%u:%g:%a:%h' -- "${expected_credential_file}")" || return 1
  case "${directory_state}" in
    "${process_uid}:${process_gid}:500:2"|"${process_uid}:${process_gid}:700:2"|0:0:500:2|0:0:700:2) ;;
    *) return 1 ;;
  esac
  case "${file_state}" in
    "${process_uid}:${process_gid}:400:1"|"${process_uid}:${process_gid}:600:1"|\
      0:0:400:1|0:0:600:1) ;;
    *) return 1 ;;
  esac
  mount_record="$(findmnt -rn -T "${expected_credential_file}" -o TARGET,FSTYPE,OPTIONS 2>/dev/null)" || return 1
  read -r mount_target mount_type mount_options extra <<<"${mount_record}"
  [[ -z "${extra:-}" && "${mount_target}" == "${credential_directory}" ]] || return 1
  [[ "${mount_type}" == ramfs || "${mount_type}" == tmpfs ]] || return 1
  for expected_option in ro nosuid nodev noexec; do
    mount_has_option "${mount_options}" "${expected_option}" || return 1
  done
  if [[ "${mount_type}" == tmpfs ]]; then
    [[ -z "$(swapon --show=NAME --noheadings --raw 2>/dev/null)" ]] || return 1
  fi
}

identity_before="$(runtime_identity)" || fail
pid="${identity_before%%:*}"
trusted_systemctl is-active --quiet pi-admin.service || fail
process_owner="$(runtime_process_owner "${pid}")" || fail
[[ "${process_owner}" == "${service_account}" ]] || fail
credential_file="$(runtime_credential_file "${pid}")" || fail
[[ "${credential_file}" == "${expected_credential_file}" ]] || fail
assert_runtime_credential_custody "${process_owner}" || fail

pattern_file="${temporary_directory}/token.pattern"
token_state="$(stat -c '%d:%i:%f:%h:%s:%Y:%Z' -- "${token_file}")" || fail
exec {token_fd}<"${token_file}" || fail
[[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z' -- "/proc/$$/fd/${token_fd}")" == "${token_state}" ]] || fail
command cat <&"${token_fd}" > "${pattern_file}" || fail
[[ "$(stat -c '%d:%i:%f:%h:%s:%Y:%Z' -- "${token_file}")" == "${token_state}" ]] || fail
[[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z' -- "/proc/$$/fd/${token_fd}")" == "${token_state}" ]] || fail
exec {token_fd}<&-
chmod 600 "${pattern_file}"
[[ -s "${pattern_file}" && "$(stat -c '%u:%g:%a:%h' -- "${pattern_file}")" == \
  "0:${effective_gid}:600:1" ]] || fail
pattern_path_state="$(stat -c '%d:%i:%f:%h:%s:%Y:%Z' -- "${pattern_file}")" || fail
pattern_identity_state="$(stat -c '%d:%i:%f:%s:%Y' -- "${pattern_file}")" || fail
exec {pattern_fd}<"${pattern_file}" || fail
[[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z' -- "/proc/$$/fd/${pattern_fd}")" == \
  "${pattern_path_state}" ]] || fail
rm -f -- "${pattern_file}" || fail
[[ ! -e "${pattern_file}" && ! -L "${pattern_file}" ]] || fail
pattern_descriptor="/proc/$$/fd/${pattern_fd}"
[[ "$(stat -Lc '%d:%i:%f:%s:%Y' -- "${pattern_descriptor}")" == \
  "${pattern_identity_state}" ]] || fail
pattern_descriptor_state="$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z' -- \
  "${pattern_descriptor}")" || fail
IFS=: read -r _ _ _ pattern_links _ _ _ pattern_extra \
  <<<"${pattern_descriptor_state}"
[[ -z "${pattern_extra:-}" && "${pattern_links}" == 0 ]] || fail

# A token rotation does not affect a running LoadCredential snapshot until the
# service restarts. Compare through a stable descriptor and close that active-
# credential descriptor before process or journal scanning. The unlinked
# root-private pattern descriptor remains open only until every comparison ends.
credential_state="$(stat -c '%d:%i:%f:%h:%s:%Y:%Z' -- "${credential_file}")" || fail
compare_active_credential() {
  local expected_state="$1" descriptor opened_state after_state compare_status
  exec {descriptor}<"${credential_file}" || return 1
  opened_state="$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z' -- "/proc/$$/fd/${descriptor}")" || {
    exec {descriptor}<&-
    return 1
  }
  if [[ "${opened_state}" != "${expected_state}" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  set +e
  cmp -s -- "${pattern_descriptor}" "/proc/$$/fd/${descriptor}"
  compare_status=$?
  set -e
  after_state="$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z' -- "/proc/$$/fd/${descriptor}")" || {
    exec {descriptor}<&-
    return 1
  }
  exec {descriptor}<&-
  [[ "${compare_status}" -eq 0 && "${after_state}" == "${expected_state}" ]]
}
compare_active_credential "${credential_state}" || fail

assert_pattern_absent() {
  local target="$1" status
  set +e
  grep -aFq -f "${pattern_descriptor}" "${target}"
  status=$?
  set -e
  [[ "${status}" -eq 1 ]] || fail
}
assert_pattern_absent "/proc/${pid}/cmdline"
assert_pattern_absent "/proc/${pid}/environ"

# Export format and --all preserve every journal field and unabridged binary
# value while grep receives the token only through its root-private pattern file.
set +e
trusted_journalctl --quiet --no-pager --all --output=export --unit=pi-admin.service 2>/dev/null |
  grep -aFq -f "${pattern_descriptor}"
journal_status=("${PIPESTATUS[@]}")
set -e
[[ "${journal_status[0]}" -eq 0 && "${journal_status[1]}" -eq 1 ]] || fail

# Any retained coredump for this service may contain the bearer token even when
# journald stored the dump externally, so absence—not substring scanning—is the
# only safe result.
set +e
trusted_journalctl --quiet --no-pager --all --output=export --lines=1 \
  COREDUMP_UNIT=pi-admin.service 2>/dev/null | grep -aq .
coredump_status=("${PIPESTATUS[@]}")
set -e
[[ "${coredump_status[0]}" -eq 0 && "${coredump_status[1]}" -eq 1 ]] || fail

[[ "$(runtime_identity)" == "${identity_before}" ]] || fail
[[ "$(runtime_process_owner "${pid}")" == "${process_owner}" ]] || fail
[[ "$(service_account_owner)" == "${service_account}" ]] || fail
[[ "$(runtime_credential_file "${pid}")" == "${credential_file}" ]] || fail
assert_runtime_credential_custody "${process_owner}" || fail
[[ "$(stat -c '%d:%i:%f:%h:%s:%Y:%Z' -- "${credential_file}")" == "${credential_state}" ]] || fail
compare_active_credential "${credential_state}" || fail
[[ "$(stat -c '%d:%i:%f:%h:%s:%Y:%Z' -- "${token_file}")" == "${token_state}" ]] || fail
trusted_systemctl is-active --quiet pi-admin.service || fail

[[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z' -- "${pattern_descriptor}")" == \
  "${pattern_descriptor_state}" ]] || fail
exec {pattern_fd}<&-
[[ ! -e "${pattern_descriptor}" ]] || fail
cleanup || fail
temporary_directory=''
trap - EXIT HUP INT TERM

builtin printf 'PASS pinned active pi-admin token is absent from process metadata and complete journal records.\n'
