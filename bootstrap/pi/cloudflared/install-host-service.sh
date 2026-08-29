#!/bin/bash
# Transactionally install and start the host-level pi-admin systemd unit.
builtin set -Eeuo pipefail
builtin set +x
builtin set +o history

mode="${1:---check}"
expected_operation=service-check
[[ "${mode}" == --apply ]] && expected_operation=service-apply
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE:-}" != yes ||
      "${REVIEWED_BLOB_OPERATION:-}" != "${expected_operation}" ||
      ! "${REVIEWED_BLOB_ROOT:-}" =~ ^/run/website-infrastructure/reviewed-op\.[A-Za-z0-9]+$ ||
      "${EUID}" -ne 0 || "${BASH}" != /usr/bin/bash ]]; then
  builtin printf 'BLOCKED pi-admin service installation requires the trusted reviewed-blob launcher; no host change was attempted.\n' >&2
  builtin exit 1
fi

PATH=/usr/sbin:/usr/bin:/sbin:/bin
builtin export PATH
builtin umask 077

die() {
  builtin printf 'FAIL pi-admin service transaction.\n' >&2
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
for command_name in mawk chmod cmp cp dirname env flock getent groupadd groupdel \
  id install ln mktemp mv passwd readlink rm rmdir sha256sum stat systemctl \
  systemd-analyze uname useradd userdel; do
  builtin command -v "${command_name}" >/dev/null 2>&1 || die
done
[[ "$(uname -s)" == Linux ]] || die

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

load_version_value() {
  local key="$1" count value
  count="$(/usr/bin/mawk -F= -v expected="${key}" '$1 == expected {count++} END {print count + 0}' \
    "${versions_file}")" || die
  [[ "${count}" == 1 ]] || die
  value="$(/usr/bin/mawk -F= -v expected="${key}" '$1 == expected {sub(/^[^=]*=/, ""); print}' \
    "${versions_file}")" || die
  [[ "${value}" =~ ^[0-9a-f]{64}$ ]] || die
  builtin printf '%s' "${value}"
}

trusted_systemctl() {
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/nonexistent LC_ALL=C \
    systemctl "$@"
}

repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)" || die
[[ "${repo_root}" == "${REVIEWED_BLOB_ROOT}" ]] || die
self_source="$(readlink -e -- "${BASH_SOURCE[0]}")" || die
unit_source="${repo_root}/bootstrap/pi/cloudflared/pi-admin.service"
versions_file="${repo_root}/versions.env"
[[ "${self_source}" == "${repo_root}/bootstrap/pi/cloudflared/install-host-service.sh" ]] || die
canonical_existing_path "${self_source}" || die
canonical_existing_path "${unit_source}" || die
canonical_existing_path "${versions_file}" || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${self_source}")" == 0:0:500:1 ]] || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${unit_source}")" == 0:0:400:1 ]] || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${versions_file}")" == 0:0:400:1 ]] || die

binary=/usr/local/bin/cloudflared
token=/etc/cloudflared/pi-admin.token
destination=/etc/systemd/system/pi-admin.service
destination_directory=/etc/systemd/system
runtime_parent=/run/website-infrastructure
lock_path="${runtime_parent}/pi-admin-service.lock"

canonical_existing_path "${binary}" || die
canonical_existing_path "${token}" || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${binary}")" == 0:0:755:1 ]] || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${token}")" == 0:0:600:1 ]] || die
expected_binary_digest="$(load_version_value CLOUDFLARED_HOST_ARM64_SHA256)"
actual_binary_digest="$(sha256sum -- "${binary}")" || die
[[ "${actual_binary_digest%% *}" == "${expected_binary_digest}" ]] || die
systemd-analyze verify "${unit_source}" >/dev/null || die

account_preexisting=no
group_preexisting=no
if getent group cloudflared >/dev/null 2>&1; then group_preexisting=yes; fi
if getent passwd cloudflared >/dev/null 2>&1; then account_preexisting=yes; fi
if [[ "${account_preexisting}" == yes ]]; then
  passwd_record="$(getent passwd cloudflared)" || die
  IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell \
    <<<"${passwd_record}"
  [[ "${account_name}" == cloudflared && "${account_uid}" =~ ^[1-9][0-9]*$ ]] || die
  [[ "${account_gid}" =~ ^[1-9][0-9]*$ && "${account_home}" == /nonexistent ]] || die
  [[ "${account_shell}" == /usr/sbin/nologin || "${account_shell}" == /usr/bin/false ]] || die
  group_record="$(getent group cloudflared)" || die
  IFS=: read -r group_name _ group_gid group_members <<<"${group_record}"
  [[ "${group_name}" == cloudflared && "${group_gid}" == "${account_gid}" && \
    -z "${group_members}" ]] || die
  password_status="$(passwd -S cloudflared)" || die
  [[ "${password_status}" == 'cloudflared L '* ]] || die
  [[ "$(id -G cloudflared)" == "${account_gid}" ]] || die
elif [[ "${group_preexisting}" == yes ]]; then
  die
fi

if [[ "${mode}" == --check ]]; then
  builtin printf 'PI_ADMIN_SERVICE_CHECK=PASS\n'
  builtin exit 0
fi

[[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || die
[[ "${TWO_WORKING_SESSIONS_PROVEN:-}" == yes ]] || die
[[ "${CONFIRM_PI_ADMIN_SERVICE_INSTALL:-}" == install-and-start-reviewed-pi-admin ]] || die
canonical_existing_path "${destination_directory}" || die
[[ "$(stat -c '%u:%g' -- "${destination_directory}")" == 0:0 ]] || die
directory_mode="$(stat -c %a -- "${destination_directory}")" || die
(( (8#${directory_mode} & 0022) == 0 )) || die
canonical_existing_path "${runtime_parent}" || die
[[ "$(stat -c '%u:%g:%a' -- "${runtime_parent}")" == 0:0:700 ]] || die
if [[ ! -e "${lock_path}" ]]; then
  install -o root -g root -m 0600 -- /dev/null "${lock_path}" || die
fi
[[ "$(stat -c '%u:%g:%a:%h' -- "${lock_path}")" == 0:0:600:1 ]] || die
exec 9<>"${lock_path}" || die
flock -n 9 || die

temporary="$(mktemp -d "${destination_directory}/.pi-admin-service.XXXXXXXX")" || die
chmod 0700 "${temporary}" || die
candidate="${temporary}/pi-admin.service"
backup="${temporary}/previous.service"
install -o root -g root -m 0644 -- "${unit_source}" "${candidate}" || die
cmp -s -- "${unit_source}" "${candidate}" || die
[[ "$(stat -c '%u:%g:%a:%h' -- "${candidate}")" == 0:0:644:1 ]] || die
previous_state=absent
previous_enabled=disabled
previous_active=inactive
mutation_started=no
committed=no
account_created=no
group_created=no

if [[ -L "${destination}" || ( -e "${destination}" && ! -f "${destination}" ) ]]; then
  die
elif [[ -f "${destination}" ]]; then
  [[ "$(stat -c '%u:%g:%a:%h' -- "${destination}")" == 0:0:644:1 ]] || die
  previous_state="$(sha256sum -- "${destination}")" || die
  previous_state="${previous_state%% *}"
  cp --preserve=mode,ownership,timestamps -- "${destination}" "${backup}" || die
  [[ "$(sha256sum -- "${backup}")" == "${previous_state}  ${backup}" ]] || die
  if trusted_systemctl is-enabled --quiet pi-admin.service; then previous_enabled=enabled; fi
  if trusted_systemctl is-active --quiet pi-admin.service; then previous_active=active; fi
fi

cleanup() {
  [[ -n "${temporary:-}" && -d "${temporary}" && ! -L "${temporary}" ]] || return 1
  case "${temporary}" in
    "${destination_directory}"/.pi-admin-service.*) rm -rf -- "${temporary}" ;;
    *) return 1 ;;
  esac
}

rollback() {
  if [[ "${mutation_started}" == yes && "${committed}" == no ]]; then
    trusted_systemctl disable --now pi-admin.service >/dev/null 2>&1 || true
    if [[ "${previous_state}" == absent ]]; then
      rm -f -- "${destination}" || return 1
    else
      [[ -f "${backup}" && ! -L "${backup}" ]] || return 1
      install -o root -g root -m 0644 -- "${backup}" "${candidate}.rollback" || return 1
      mv -fT -- "${candidate}.rollback" "${destination}" || return 1
    fi
    trusted_systemctl daemon-reload || return 1
    if [[ "${previous_enabled}" == enabled ]]; then
      trusted_systemctl enable pi-admin.service >/dev/null || return 1
    fi
    if [[ "${previous_active}" == active ]]; then
      trusted_systemctl start pi-admin.service || return 1
    fi
  fi
  if [[ "${account_created}" == yes ]]; then
    userdel cloudflared || return 1
  fi
  if [[ "${group_created}" == yes ]]; then
    groupdel cloudflared || return 1
  fi
  return 0
}

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( status != 0 )); then rollback || builtin printf 'ROLLBACK=INCOMPLETE\n' >&2; fi
  cleanup >/dev/null 2>&1 || true
  exit "${status}"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "${account_preexisting}" == no ]]; then
  groupadd --system cloudflared || die
  group_created=yes
  useradd --system --gid cloudflared --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin cloudflared || die
  account_created=yes
  passwd --lock cloudflared >/dev/null || die
  passwd_record="$(getent passwd cloudflared)" || die
  IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell \
    <<<"${passwd_record}"
  [[ "${account_name}" == cloudflared && "${account_uid}" =~ ^[1-9][0-9]*$ ]] || die
  [[ "${account_gid}" =~ ^[1-9][0-9]*$ && "${account_home}" == /nonexistent && \
    "${account_shell}" == /usr/sbin/nologin ]] || die
  group_record="$(getent group cloudflared)" || die
  IFS=: read -r group_name _ group_gid group_members <<<"${group_record}"
  [[ "${group_name}" == cloudflared && "${group_gid}" == "${account_gid}" && \
    -z "${group_members}" ]] || die
  [[ "$(id -G cloudflared)" == "${account_gid}" ]] || die
  password_status="$(passwd -S cloudflared)" || die
  [[ "${password_status}" == 'cloudflared L '* ]] || die
fi

# Recheck the destination after the lock and immediately before commit.
if [[ "${previous_state}" == absent ]]; then
  [[ ! -e "${destination}" && ! -L "${destination}" ]] || die
  mutation_started=yes
  ln -- "${candidate}" "${destination}" || die
  rm -f -- "${candidate}" || die
else
  current_digest="$(sha256sum -- "${destination}")" || die
  [[ "${current_digest%% *}" == "${previous_state}" ]] || die
  mutation_started=yes
  mv -fT -- "${candidate}" "${destination}" || die
fi
[[ "$(stat -c '%u:%g:%a:%h' -- "${destination}")" == 0:0:644:1 ]] || die
cmp -s -- "${unit_source}" "${destination}" || die
trusted_systemctl daemon-reload || die
trusted_systemctl enable pi-admin.service >/dev/null || die
trusted_systemctl restart pi-admin.service || die
trusted_systemctl is-enabled --quiet pi-admin.service || die
trusted_systemctl is-active --quiet pi-admin.service || die
main_pid="$(trusted_systemctl show --property=MainPID --value pi-admin.service)" || die
[[ "${main_pid}" =~ ^[1-9][0-9]*$ ]] || die
process_uid="$(/usr/bin/mawk '$1 == "Uid:" {print $2, $3, $4, $5}' "/proc/${main_pid}/status")" || die
read -r uid_real uid_effective uid_saved uid_filesystem <<<"${process_uid}"
[[ "${uid_real}" =~ ^[1-9][0-9]*$ && "${uid_real}" == "${uid_effective}" && \
  "${uid_real}" == "${uid_saved}" && "${uid_real}" == "${uid_filesystem}" ]] || die
[[ "${uid_real}" == "${account_uid}" ]] || die
committed=yes
cleanup || die
temporary=''
trap - EXIT HUP INT TERM
builtin printf 'PI_ADMIN_SERVICE_INSTALL=PASS\n'
