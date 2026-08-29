#!/bin/bash
builtin set -Eeuo pipefail
builtin set +x
builtin set +o history

# Validation executes caller-staged bytes and apply mutates a privileged host
# path. Accept only the root-private extraction created by the installed
# reviewed-blob launcher; a mutable checkout invocation fails before the staged
# path is read.
mode="${1:---check}"
expected_operation='binary-check'
[[ "${mode}" == --apply ]] && expected_operation='binary-apply'
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE:-}" != yes ||
      "${REVIEWED_BLOB_OPERATION:-}" != "${expected_operation}" ||
      ! "${REVIEWED_BLOB_ROOT:-}" =~ ^/run/website-infrastructure/reviewed-op\.[A-Za-z0-9]+$ ||
      "${EUID}" -ne 0 || "${BASH}" != /usr/bin/bash ]]; then
  builtin printf 'BLOCKED cloudflared host-binary validation and installation require the trusted reviewed-blob launcher; no staged binary was executed and no host change was attempted.\n' >&2
  builtin exit 1
fi

# Root apply must not inherit a workstation or caller-controlled command path.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
builtin export PATH
builtin umask 077

die() {
  builtin printf 'ERROR %s\n' "$*" >&2
  builtin exit 1
}

while builtin read -r declaration flag inherited_name; do
  [[ "${declaration}" == declare && "${flag}" == -f ]] || die 'unsafe shell function state'
  [[ "${inherited_name}" == die ]] || die 'unsafe inherited shell function'
done < <(builtin declare -F)
for inherited_name in $(builtin compgen -e); do
  case "${inherited_name}" in
    BASH_ENV|ENV|BASHOPTS|SHELLOPTS|BASH_XTRACEFD|PS4|POSIXLY_CORRECT|\
      CDPATH|GLOBIGNORE|BASH_FUNC_*|LD_*|PYTHON*|GIT_*|\
      DBUS_*|SYSTEMD_*|SYSTEMCTL_*|JOURNAL_*|PAGER|LESS) \
      die 'unsafe inherited environment' ;;
  esac
done
builtin ulimit -S -c 0 || die 'could not disable soft core limit'
builtin ulimit -H -c 0 || die 'could not disable hard core limit'
[[ "$(builtin ulimit -S -c)" == 0 && "$(builtin ulimit -H -c)" == 0 ]] || \
  die 'core dumps remain enabled'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
[[ "${repo_root}" == "${REVIEWED_BLOB_ROOT}" ]] || die 'reviewed extraction root mismatch'
[[ "$(readlink -e -- "${BASH_SOURCE[0]}")" == \
  "${repo_root}/bootstrap/pi/cloudflared/install-host-binary.sh" ]] || die 'reviewed entry path mismatch'
[[ "$(stat -c '%u:%g:%a:%h' -- "${BASH_SOURCE[0]}")" == 0:0:500:1 ]] || die 'reviewed entry custody mismatch'
versions_file="${repo_root}/versions.env"

staged_binary="${CLOUDFLARED_HOST_BINARY_PATH:-${repo_root}/.artifacts/cloudflared-linux-arm64}"
destination=/usr/local/bin/cloudflared
destination_directory=/usr/local/bin
backup_parent=/var/backups/website-infrastructure
lock_directory=/run/website-infrastructure
lock_path="${lock_directory}/cloudflared-host-binary.lock"

candidate_directory=''
candidate_binary=''
backup_directory=''
previous_state=''
previous_identity=''
previous_metadata=''
candidate_identity=''
mutation_started=no
installation_committed=no
rollback_in_progress=no

load_version_value() {
  local key="$1" count value
  count="$(/usr/bin/mawk -F= -v expected="${key}" '$1 == expected { count += 1 } END { print count + 0 }' "${versions_file}")"
  [[ "${count}" == 1 ]] || die "versions.env must define ${key} exactly once"
  value="$(/usr/bin/mawk -F= -v expected="${key}" '$1 == expected { sub(/^[^=]*=/, ""); print }' "${versions_file}")"
  [[ -n "${value}" ]] || die "versions.env value is empty: ${key}"
  printf '%s\n' "${value}"
}

require_commands() {
  local command_name
  for command_name in mawk chmod chown cp date env flock getcap getfacl getfattr grep id install ln mktemp mv readlink rm rmdir setpriv sha256sum stat timeout unshare; do
    command -v "${command_name}" >/dev/null 2>&1 || die "required command is absent: ${command_name}"
  done
}

sha256_file() {
  sha256sum -- "$1" | /usr/bin/mawk '{print $1}'
}

file_state() {
  local path="$1"
  if [[ -L "${path}" ]]; then
    printf 'unsupported-symlink\n'
  elif [[ -e "${path}" && ! -f "${path}" ]]; then
    printf 'unsupported-nonregular\n'
  elif [[ -f "${path}" ]]; then
    printf 'sha256:%s\n' "$(sha256_file "${path}")"
  else
    printf 'absent\n'
  fi
}

assert_safe_root_directory() {
  local path="$1"
  local mode_value
  [[ -d "${path}" && ! -L "${path}" ]] || die "required directory is absent, non-directory, or symlinked: ${path}"
  [[ "$(readlink -f -- "${path}")" == "${path}" ]] || die "directory does not resolve to its exact path: ${path}"
  [[ "$(stat -c %u -- "${path}")" == 0 ]] || die "directory is not root-owned: ${path}"
  mode_value="$(stat -c %a -- "${path}")"
  (( (8#${mode_value} & 0022) == 0 )) || die "directory is group/world writable: ${path}"
}

ensure_private_root_directory() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    [[ -d "${path}" && ! -L "${path}" ]] || die "private path is not an exact directory: ${path}"
    [[ "$(stat -c %u -- "${path}")" == 0 ]] || die "private directory is not root-owned: ${path}"
    [[ "$(stat -c %a -- "${path}")" == 700 ]] || die "private directory mode must be 0700: ${path}"
  else
    install -d -o root -g root -m 0700 -- "${path}"
  fi
}

ensure_private_root_file() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    [[ -f "${path}" && ! -L "${path}" ]] || die "private path is not an exact regular file: ${path}"
    [[ "$(stat -c %u -- "${path}")" == 0 && "$(stat -c %g -- "${path}")" == 0 ]] || die "private file is not root-owned: ${path}"
    [[ "$(stat -c %a -- "${path}")" == 600 ]] || die "private file mode must be 0600: ${path}"
  else
    install -o root -g root -m 0600 -- /dev/null "${path}"
  fi
}

verify_binary() {
  local binary="$1"
  local digest version_output help_output escaped_version digest_after nobody_uid nobody_gid
  local -a isolated_runner

  [[ -f "${binary}" && ! -L "${binary}" ]] || return 1
  [[ "$(stat -c %h -- "${binary}")" == 1 ]] || return 1
  digest="$(sha256_file "${binary}")"
  [[ "${digest}" == "${CLOUDFLARED_HOST_ARM64_SHA256}" ]] || {
    printf 'cloudflared ARM64 binary checksum mismatch.\n' >&2
    return 1
  }

  if [[ "${EUID}" -eq 0 ]]; then
    nobody_uid="$(id -u nobody 2>/dev/null)" || return 1
    nobody_gid="$(id -g nobody 2>/dev/null)" || return 1
    [[ "${nobody_uid}" != 0 && "${nobody_gid}" =~ ^[0-9]+$ ]] || return 1
    isolated_runner=(timeout --signal=KILL 10s unshare --net -- setpriv
      --reuid="${nobody_uid}" --regid="${nobody_gid}" --clear-groups
      --no-new-privs env -i PATH="${PATH}")
  else
    isolated_runner=(timeout --signal=KILL 10s unshare --user --map-current-user
      --net -- env -i PATH="${PATH}")
  fi

  version_output="$("${isolated_runner[@]}" "${binary}" --version 2>&1)" || return 1
  digest_after="$(sha256_file "${binary}")"
  [[ "${digest_after}" == "${digest}" ]] || return 1
  escaped_version="${CLOUDFLARED_HOST_VERSION//./\\.}"
  grep -Eq "^cloudflared version ${escaped_version}([[:space:]]|$)" <<<"${version_output}" || {
    printf 'cloudflared binary does not report exact version %s.\n' "${CLOUDFLARED_HOST_VERSION}" >&2
    return 1
  }

  help_output="$("${isolated_runner[@]}" "${binary}" tunnel run --help 2>&1)" || return 1
  digest_after="$(sha256_file "${binary}")"
  [[ "${digest_after}" == "${digest}" ]] || return 1
  grep -Fq -- '--token-file' <<<"${help_output}" || {
    printf 'cloudflared binary does not expose the required --token-file behavior.\n' >&2
    return 1
  }
}

assert_no_extended_file_authority() {
  local path="$1" acl
  [[ "$(stat -c %h -- "${path}")" == 1 ]] || die 'file has multiple hard links'
  [[ -z "$(getcap -n -- "${path}" 2>/dev/null)" ]] || die 'file capabilities are unsupported'
  if getfattr -d -m- -- "${path}" 2>/dev/null | grep -Eq '^[^#[:space:]][^=]*='; then
    die 'extended file attributes are unsupported'
  fi
  acl="$(getfacl -cp -- "${path}" 2>/dev/null | /usr/bin/mawk 'NF {print}')" || die 'file ACL inventory is unavailable'
  [[ "$(printf '%s\n' "${acl}" | grep -Ec '^(user::|group::|other::)')" == 3 ]] || die 'extended file ACL entries are unsupported'
  [[ "$(printf '%s\n' "${acl}" | /usr/bin/mawk 'END {print NR + 0}')" == 3 ]] || die 'extended file ACL entries are unsupported'
}

prepare_candidate() {
  local owner group mode_value

  [[ -f "${staged_binary}" && ! -L "${staged_binary}" ]] || die 'staged cloudflared ARM64 binary must be a regular, non-symlink file'
  [[ "$(stat -c %h -- "${staged_binary}")" == 1 ]] || die 'staged cloudflared binary must have one link'

  if [[ "${mode}" == --apply ]]; then
    candidate_directory="$(mktemp -d "${destination_directory}/.cloudflared-install.XXXXXXXX")"
    chmod 0700 "${candidate_directory}"
    chown root:root "${candidate_directory}"
    candidate_binary="${candidate_directory}/cloudflared"
    install -o root -g root -m 0755 -- "${staged_binary}" "${candidate_binary}"
    owner="$(stat -c %u -- "${candidate_binary}")"
    group="$(stat -c %g -- "${candidate_binary}")"
    mode_value="$(stat -c %a -- "${candidate_binary}")"
    [[ "${owner}" == 0 && "${group}" == 0 && "${mode_value}" == 755 ]] || die 'private candidate ownership/mode is unsafe'
  else
    candidate_directory="$(mktemp -d)"
    chmod 0700 "${candidate_directory}"
    candidate_binary="${candidate_directory}/cloudflared"
    install -m 0700 -- "${staged_binary}" "${candidate_binary}"
  fi

  verify_binary "${candidate_binary}" || die 'private cloudflared candidate verification failed'
}

destination_identity() {
  stat -c '%d:%i:%f:%u:%g:%h' -- "${destination}"
}

destination_metadata() {
  stat -c '%f:%u:%g:%s:%Y' -- "$1"
}

validate_existing_destination() {
  local mode_value
  previous_state="$(file_state "${destination}")"
  case "${previous_state}" in
    absent)
      previous_identity=absent
      previous_metadata=absent
      ;;
    sha256:*)
      [[ "$(stat -c %u -- "${destination}")" == 0 ]] || die 'existing cloudflared binary is not root-owned'
      mode_value="$(stat -c %a -- "${destination}")"
      (( (8#${mode_value} & 0022) == 0 )) || die 'existing cloudflared binary is group/world writable'
      assert_no_extended_file_authority "${destination}"
      previous_identity="$(destination_identity)"
      previous_metadata="$(destination_metadata "${destination}")"
      ;;
    *)
      die 'existing cloudflared destination is a symlink or non-regular file'
      ;;
  esac
}

destination_is_unchanged() {
  [[ "$(file_state "${destination}")" == "${previous_state}" ]] || return 1
  if [[ "${previous_state}" == absent ]]; then
    [[ ! -e "${destination}" && ! -L "${destination}" ]]
  else
    [[ "$(destination_identity)" == "${previous_identity}" ]]
  fi
}

rollback_installation() {
  local current_state rollback_candidate backup_state

  [[ "${mutation_started}" == yes ]] || return 0
  [[ "${rollback_in_progress}" == no ]] || return 1
  rollback_in_progress=yes
  current_state="$(file_state "${destination}")"

  if [[ "${previous_state}" == absent && "${current_state}" == absent ]]; then
    mutation_started=no
    printf 'PASS cloudflared commit did not change the absent destination\n' >&2
    return 0
  fi
  if [[ "${previous_state}" != absent && "${current_state}" == "${previous_state}" ]] && \
    [[ "$(destination_identity)" == "${previous_identity}" ]]; then
    mutation_started=no
    printf 'PASS cloudflared commit did not replace the previous destination\n' >&2
    return 0
  fi
  if [[ "${current_state}" != "sha256:${CLOUDFLARED_HOST_ARM64_SHA256}" ]] || \
    [[ "$(destination_identity)" != "${candidate_identity}" ]]; then
    printf 'ERROR installed destination drifted; refusing rollback overwrite\n' >&2
    return 1
  fi

  if [[ "${previous_state}" == absent ]]; then
    rm -f -- "${destination}" || return 1
    [[ ! -e "${destination}" && ! -L "${destination}" ]] || return 1
  else
    [[ -f "${backup_directory}/cloudflared.pre" && ! -L "${backup_directory}/cloudflared.pre" ]] || return 1
    backup_state="$(file_state "${backup_directory}/cloudflared.pre")"
    [[ "${backup_state}" == "${previous_state}" ]] || return 1
    rollback_candidate="${candidate_directory}/cloudflared.rollback"
    cp -a -- "${backup_directory}/cloudflared.pre" "${rollback_candidate}" || return 1
    [[ "$(file_state "${rollback_candidate}")" == "${previous_state}" ]] || return 1
    [[ "$(destination_metadata "${rollback_candidate}")" == "${previous_metadata}" ]] || return 1
    mv -fT -- "${rollback_candidate}" "${destination}" || return 1
    [[ "$(file_state "${destination}")" == "${previous_state}" ]] || return 1
    [[ "$(destination_metadata "${destination}")" == "${previous_metadata}" ]] || return 1
  fi

  mutation_started=no
    printf 'PASS checked previous cloudflared binary state restored\n' >&2
}

cleanup() {
  if [[ -n "${candidate_binary}" && -f "${candidate_binary}" && ! -L "${candidate_binary}" ]]; then
    rm -f -- "${candidate_binary}"
  fi
  if [[ -n "${candidate_directory}" && -d "${candidate_directory}" && ! -L "${candidate_directory}" ]]; then
    rmdir -- "${candidate_directory}" 2>/dev/null || true
  fi
}

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( status != 0 )) && [[ "${mutation_started}" == yes && "${installation_committed}" != yes ]]; then
    printf 'ERROR cloudflared installation failed; attempting exact rollback\n' >&2
    if ! rollback_installation; then
      printf 'ERROR rollback incomplete; preserve %s and use physical/LAN recovery\n' "${backup_directory:-the private transaction evidence}" >&2
    fi
  fi
  cleanup
  exit "${status}"
}

trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_commands
[[ -f "${versions_file}" && ! -L "${versions_file}" ]] || die 'versions.env must be a regular, non-symlink file'
[[ "$(stat -c '%u:%g:%a:%h' -- "${versions_file}")" == 0:0:400:1 ]] || die 'versions.env reviewed custody mismatch'
CLOUDFLARED_HOST_VERSION="$(load_version_value CLOUDFLARED_HOST_VERSION)"
CLOUDFLARED_HOST_ARM64_SHA256="$(load_version_value CLOUDFLARED_HOST_ARM64_SHA256)"
[[ "${CLOUDFLARED_HOST_ARM64_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die 'CLOUDFLARED_HOST_ARM64_SHA256 is unresolved or malformed'
[[ "${CLOUDFLARED_HOST_VERSION}" =~ ^[0-9]{4}\.[0-9]+\.[0-9]+$ ]] || die 'CLOUDFLARED_HOST_VERSION is unresolved or malformed'
(( $# <= 1 )) || { printf 'Usage: %s [--check|--apply]\n' "$0" >&2; exit 2; }

case "${mode}" in
  --check) ;;
  --apply)
    [[ "${EUID}" -eq 0 ]] || { printf 'Apply mode requires root.\n' >&2; exit 2; }
    [[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || { printf 'Recovery acknowledgement missing.\n' >&2; exit 2; }
    [[ "${TWO_WORKING_SESSIONS_PROVEN:-}" == yes ]] || { printf 'Two-session acknowledgement missing.\n' >&2; exit 2; }
    [[ "${CONFIRM_CLOUDFLARED_INSTALL:-}" == "install-reviewed-cloudflared-${CLOUDFLARED_HOST_VERSION}" ]] || {
      printf 'Exact cloudflared install acknowledgement missing.\n' >&2
      exit 2
    }
    ;;
  *)
    printf 'Usage: %s [--check|--apply]\n' "$0" >&2
    exit 2
    ;;
esac

if [[ "${mode}" == --check ]]; then
  prepare_candidate
  printf 'Pinned cloudflared host binary and --token-file support are verified from a private copy. No change made.\n'
  exit 0
fi

assert_safe_root_directory "${destination_directory}"
assert_safe_root_directory /run
ensure_private_root_directory "${lock_directory}"
ensure_private_root_file "${lock_path}"
exec 9<>"${lock_path}"
flock -n 9 || die 'another cloudflared host-binary operation holds the lock'

# Every destination check happens after acquiring the mutation lock.
validate_existing_destination
assert_safe_root_directory /var/backups
ensure_private_root_directory /var/backups/website-infrastructure
backup_directory="$(mktemp -d "${backup_parent}/$(date -u +%Y%m%dT%H%M%SZ)-cloudflared.XXXXXXXX")"
chmod 0700 "${backup_directory}"
chown root:root "${backup_directory}"
if [[ "${previous_state}" != absent ]]; then
  cp -a -- "${destination}" "${backup_directory}/cloudflared.pre"
  [[ "$(file_state "${backup_directory}/cloudflared.pre")" == "${previous_state}" ]] || die 'cloudflared backup verification failed'
  assert_no_extended_file_authority "${backup_directory}/cloudflared.pre"
fi

# Copy and verify only after the destination and private backup transaction exist.
prepare_candidate
destination_is_unchanged || die 'cloudflared destination changed before atomic commit'
candidate_identity="$(stat -c '%d:%i:%f:%u:%g:%h' -- "${candidate_binary}")"
mutation_started=yes

if [[ "${previous_state}" == absent ]]; then
  # A same-filesystem hard link is an atomic no-replace commit for first install.
  ln -- "${candidate_binary}" "${destination}" || die 'cloudflared destination appeared before first install commit'
  rm -f -- "${candidate_binary}"
else
  # /usr/local/bin was proven root-owned and non-writable to unprivileged users;
  # the private candidate is on the same filesystem, so rename is atomic.
  mv -fT -- "${candidate_binary}" "${destination}"
fi

[[ -f "${destination}" && ! -L "${destination}" ]] || die 'installed cloudflared destination is unsafe'
[[ "$(stat -c %u -- "${destination}")" == 0 && "$(stat -c %g -- "${destination}")" == 0 ]] || die 'installed cloudflared ownership is unsafe'
[[ "$(stat -c %a -- "${destination}")" == 755 ]] || die 'installed cloudflared mode is unsafe'
assert_no_extended_file_authority "${destination}"
verify_binary "${destination}" || die 'installed cloudflared verification failed'

installation_committed=yes
printf 'Installed the verified cloudflared host binary only. No unit, user, token, or firewall changed.\n'
printf 'Recovery backup: %s\n' "${backup_directory}"
