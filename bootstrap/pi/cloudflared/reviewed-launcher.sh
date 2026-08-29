#!/usr/bin/bash
# Root-owned stage-zero launcher for the host-level pi-admin connector.
#
# Bootstrap is deliberately owner-attended: install this exact reviewed blob at
# /usr/local/sbin/website-infrastructure-reviewed-launcher, install a root-only
# hash manifest for the closed absolute-tool set below, then promote one exact
# protected-main Git bundle. The launcher never executes a mutable checkout.
builtin set -Eeuo pipefail
builtin set +x
builtin set +o history
builtin umask 077

readonly installed_launcher=/usr/local/sbin/website-infrastructure-reviewed-launcher
readonly tool_manifest=/etc/website-infrastructure/reviewed-tools.sha256
readonly state_parent=/var/lib/website-infrastructure
readonly source_repository=/var/lib/website-infrastructure/reviewed-source.git
readonly approved_commit_file=/var/lib/website-infrastructure/approved-main
readonly runtime_parent=/run/website-infrastructure
readonly lock_file=${runtime_parent}/reviewed-launcher.lock
cleanup_targets=()

fail() {
  builtin printf 'REVIEWED_LAUNCH=FAIL\n' >&2
  builtin exit 1
}

register_cleanup() {
  cleanup_targets+=("$1")
}

cleanup_on_exit() {
  local target
  set +e
  for target in "${cleanup_targets[@]}"; do
    case "${target}" in
      "${runtime_parent}"/reviewed-source.*.bundle|\
      "${runtime_parent}"/launcher-blob.*|\
      "${state_parent}"/approved-main.*|\
      /run/reviewed-tool-manifest.*|\
      /etc/website-infrastructure/reviewed-tools.sha256.*)
        [[ ! -e "${target}" && ! -L "${target}" ]] || /usr/bin/rm -f -- "${target}"
        ;;
      "${runtime_parent}"/reviewed-op.*)
        if [[ -d "${target}" && ! -L "${target}" ]]; then
          /usr/bin/rm -rf -- "${target}"
        fi
        ;;
    esac
  done
}

# Reject shell and loader injection before invoking an external command. The
# owner-installed path check below is the stage-zero boundary; this source-tree
# copy is never an authorized entrypoint.
while builtin read -r declaration flag inherited_name; do
  [[ "${declaration}" == declare && "${flag}" == -f ]] || fail
  [[ "${inherited_name}" == fail ]] || fail
done < <(builtin declare -F)
for inherited_name in $(builtin compgen -e); do
  case "${inherited_name}" in
    BASH_ENV|ENV|BASHOPTS|SHELLOPTS|BASH_XTRACEFD|PS4|POSIXLY_CORRECT|\
      CDPATH|GLOBIGNORE|BASH_FUNC_*|LD_*|GIT_*|PYTHON*|PERL*|RUBY*|\
      DBUS_*|SYSTEMD_*|SYSTEMCTL_*|JOURNAL_*|PAGER|LESS) fail ;;
  esac
done
builtin ulimit -S -c 0 || fail
builtin ulimit -H -c 0 || fail
[[ "$(builtin ulimit -S -c)" == 0 && "$(builtin ulimit -H -c)" == 0 ]] || fail
[[ "${EUID}" -eq 0 && "${BASH}" == /usr/bin/bash ]] || fail
[[ "${SUDO_UID:-}" =~ ^[1-9][0-9]*$ && "${SUDO_GID:-}" =~ ^[0-9]+$ ]] || fail

readonly -a required_tools=(
  /usr/bin/bash
  /usr/bin/cat
  /usr/bin/chmod
  /usr/bin/chown
  /usr/bin/cmp
  /usr/bin/cp
  /usr/bin/date
  /usr/bin/dirname
  /usr/bin/env
  /usr/bin/findmnt
  /usr/bin/flock
  /usr/bin/getfacl
  /usr/bin/getfattr
  /usr/bin/getent
  /usr/bin/git
  /usr/bin/grep
  /usr/bin/id
  /usr/bin/install
  /usr/bin/journalctl
  /usr/bin/ln
  /usr/bin/mkdir
  /usr/bin/mktemp
  /usr/bin/mawk
  /usr/bin/mv
  /usr/bin/passwd
  /usr/bin/python3.12
  /usr/bin/readlink
  /usr/bin/rm
  /usr/bin/rmdir
  /usr/bin/setpriv
  /usr/bin/sha256sum
  /usr/bin/stat
  /usr/bin/systemctl
  /usr/bin/systemd-analyze
  /usr/bin/timeout
  /usr/bin/uname
  /usr/bin/unshare
  /usr/sbin/getcap
  /usr/sbin/groupadd
  /usr/sbin/groupdel
  /usr/sbin/swapon
  /usr/sbin/useradd
  /usr/sbin/userdel
)

canonical_exact_path() {
  local candidate="$1" resolved current
  [[ "${candidate}" == /* ]] || return 1
  resolved="$(/usr/bin/readlink -e -- "${candidate}")" || return 1
  [[ "${resolved}" == "${candidate}" ]] || return 1
  current="${candidate}"
  while [[ "${current}" != / ]]; do
    [[ ! -L "${current}" ]] || return 1
    current="$(/usr/bin/dirname -- "${current}")" || return 1
  done
}

safe_root_directory() {
  local path="$1" mode
  canonical_exact_path "${path}" || return 1
  [[ -d "${path}" && ! -L "${path}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u:%g' -- "${path}")" == 0:0 ]] || return 1
  mode="$(/usr/bin/stat -c %a -- "${path}")" || return 1
  (( (8#${mode} & 0022) == 0 )) || return 1
}

safe_root_file() {
  local path="$1" expected_mode="$2"
  canonical_exact_path "${path}" || return 1
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "${path}")" == \
    "0:0:${expected_mode}:1" ]]
}

validate_installed_launcher_boundary() {
  local self
  self="$(/usr/bin/readlink -e -- "${BASH_SOURCE[0]}")" || fail
  [[ "${self}" == "${installed_launcher}" ]] || fail
  safe_root_file "${installed_launcher}" 755 || fail
  safe_root_directory /usr/local || fail
  safe_root_directory /usr/local/sbin || fail
}

validate_tool_manifest_boundary() {
  safe_root_directory /etc || fail
  safe_root_directory /etc/website-infrastructure || fail
  [[ "$(/usr/bin/stat -c %a -- /etc/website-infrastructure)" == 700 ]] || fail
  safe_root_file "${tool_manifest}" 600 || fail
}

validate_required_tool() {
  local path="$1" mode
  canonical_exact_path "${path}" || return 1
  [[ -f "${path}" && ! -L "${path}" && -x "${path}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u:%g:%h' -- "${path}")" == 0:0:1 ]] || return 1
  mode="$(/usr/bin/stat -c %a -- "${path}")" || return 1
  (( (8#${mode} & 0022) == 0 ))
}

render_tool_manifest() {
  local destination="$1" path observed
  /usr/bin/install -o root -g root -m 0600 -- /dev/null "${destination}" || return 1
  for path in "${required_tools[@]}"; do
    validate_required_tool "${path}" || return 1
    observed="$(/usr/bin/sha256sum -- "${path}")" || return 1
    observed="${observed%% *}"
    [[ "${observed}" =~ ^[0-9a-f]{64}$ ]] || return 1
    builtin printf '%s  %s\n' "${observed}" "${path}" >>"${destination}" || return 1
  done
  safe_root_file "${destination}" 600
}

tool_manifest_proposal() {
  local candidate digest
  safe_root_directory /run || fail
  candidate="$(/usr/bin/mktemp /run/reviewed-tool-manifest.XXXXXXXX)" || fail
  register_cleanup "${candidate}"
  render_tool_manifest "${candidate}" || fail
  digest="$(/usr/bin/sha256sum -- "${candidate}")" || fail
  digest="${digest%% *}"
  /usr/bin/rm -f -- "${candidate}" || fail
  builtin printf 'REVIEWED_TOOL_MANIFEST_PROPOSAL_SHA256=%s\n' "${digest}"
}

commit_tool_manifest() {
  local expected_digest="$1" confirmation="$2" candidate observed
  [[ "${expected_digest}" =~ ^[0-9a-f]{64}$ ]] || fail
  [[ "${confirmation}" == "commit-reviewed-tool-manifest-${expected_digest}" ]] || fail
  safe_root_directory /etc || fail
  if [[ ! -e /etc/website-infrastructure ]]; then
    /usr/bin/install -d -o root -g root -m 0700 -- /etc/website-infrastructure || fail
  fi
  safe_root_directory /etc/website-infrastructure || fail
  [[ "$(/usr/bin/stat -c %a -- /etc/website-infrastructure)" == 700 ]] || fail
  if [[ -e "${tool_manifest}" || -L "${tool_manifest}" ]]; then
    safe_root_file "${tool_manifest}" 600 || fail
  fi
  candidate="$(/usr/bin/mktemp \
    /etc/website-infrastructure/reviewed-tools.sha256.XXXXXXXX)" || fail
  register_cleanup "${candidate}"
  render_tool_manifest "${candidate}" || fail
  observed="$(/usr/bin/sha256sum -- "${candidate}")" || fail
  observed="${observed%% *}"
  [[ "${observed}" == "${expected_digest}" ]] || fail
  /usr/bin/mv -fT -- "${candidate}" "${tool_manifest}" || fail
  validate_tool_manifest_boundary
  validate_tool_manifest
  builtin printf 'REVIEWED_TOOL_MANIFEST_COMMIT=PASS\n'
}

validate_tool_manifest() {
  local expected_path line digest observed index=0
  exec 8<"${tool_manifest}" || fail
  while (( index < ${#required_tools[@]} )); do
    IFS= builtin read -r line <&8 || fail
    [[ "${line}" =~ ^([0-9a-f]{64})\ \ (/usr/(sbin|bin)/[A-Za-z0-9._+-]+)$ ]] || fail
    digest="${BASH_REMATCH[1]}"
    expected_path="${BASH_REMATCH[2]}"
    [[ "${expected_path}" == "${required_tools[index]}" ]] || fail
    validate_required_tool "${expected_path}" || fail
    observed="$(/usr/bin/sha256sum -- "${expected_path}")" || fail
    observed="${observed%% *}"
    [[ "${observed}" == "${digest}" ]] || fail
    (( index += 1 ))
  done
  if IFS= builtin read -r _ <&8; then fail; fi
  exec 8<&-
}

ensure_runtime_state() {
  safe_root_directory /run || fail
  if [[ ! -e "${runtime_parent}" ]]; then
    /usr/bin/install -d -o root -g root -m 0700 -- "${runtime_parent}" || fail
  fi
  safe_root_directory "${runtime_parent}" || fail
  [[ "$(/usr/bin/stat -c %a -- "${runtime_parent}")" == 700 ]] || fail
  if [[ ! -e "${lock_file}" ]]; then
    /usr/bin/install -o root -g root -m 0600 -- /dev/null "${lock_file}" || fail
  fi
  safe_root_file "${lock_file}" 600 || fail
  exec 9<>"${lock_file}" || fail
  /usr/bin/flock -n 9 || fail
}

safe_owner_input_file() {
  local path="$1" mode
  canonical_exact_path "${path}" || return 1
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  mode="$(/usr/bin/stat -c %a -- "${path}")" || return 1
  [[ "${mode}" == 400 || "${mode}" == 600 ]] || return 1
  [[ "$(/usr/bin/stat -c '%u:%g:%h' -- "${path}")" == \
    "${SUDO_UID}:${SUDO_GID}:1" ]] || return 1
}

copy_stable_owner_file() {
  local source="$1" destination="$2" before opened after descriptor
  safe_owner_input_file "${source}" || return 1
  before="$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "${source}")" || return 1
  exec {descriptor}<"${source}" || return 1
  opened="$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- \
    "/proc/$$/fd/${descriptor}")" || { exec {descriptor}<&-; return 1; }
  [[ "${opened}" == "${before}" ]] || { exec {descriptor}<&-; return 1; }
  /usr/bin/cat <&"${descriptor}" >"${destination}" || { exec {descriptor}<&-; return 1; }
  after="$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- \
    "/proc/$$/fd/${descriptor}")" || { exec {descriptor}<&-; return 1; }
  exec {descriptor}<&-
  [[ "${after}" == "${before}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "${source}")" == \
    "${before}" ]] || return 1
  /usr/bin/chmod 0400 "${destination}" || return 1
  safe_root_file "${destination}" 400
}

trusted_git() {
  /usr/bin/env -i PATH=/usr/bin HOME=/nonexistent LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 /usr/bin/git --no-replace-objects \
    -c credential.helper= -c core.askPass= -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null "$@"
}

read_approved_commit() {
  local value descriptor
  safe_root_file "${approved_commit_file}" 600 || return 1
  exec {descriptor}<"${approved_commit_file}" || return 1
  IFS= builtin read -r value <&"${descriptor}" || { exec {descriptor}<&-; return 1; }
  [[ "${value}" =~ ^[0-9a-f]{40}$ ]] || return 1
  if IFS= builtin read -r _ <&"${descriptor}"; then exec {descriptor}<&-; return 1; fi
  exec {descriptor}<&-
  builtin printf '%s' "${value}"
}

verify_installed_launcher_blob() {
  local commit="$1" mode expected observed temporary
  mode="$(trusted_git --git-dir="${source_repository}" ls-tree "${commit}" -- \
    bootstrap/pi/cloudflared/reviewed-launcher.sh | /usr/bin/mawk '{print $1}')" || return 1
  [[ "${mode}" == 100755 ]] || return 1
  temporary="$(/usr/bin/mktemp "${runtime_parent}/launcher-blob.XXXXXXXX")" || return 1
  register_cleanup "${temporary}"
  /usr/bin/chmod 0600 "${temporary}" || return 1
  trusted_git --git-dir="${source_repository}" cat-file blob \
    "${commit}:bootstrap/pi/cloudflared/reviewed-launcher.sh" >"${temporary}" || {
      /usr/bin/rm -f -- "${temporary}"; return 1;
    }
  expected="$(/usr/bin/sha256sum -- "${temporary}")" || {
    /usr/bin/rm -f -- "${temporary}"; return 1;
  }
  observed="$(/usr/bin/sha256sum -- "${installed_launcher}")" || {
    /usr/bin/rm -f -- "${temporary}"; return 1;
  }
  /usr/bin/rm -f -- "${temporary}" || return 1
  [[ "${expected%% *}" == "${observed%% *}" ]]
}

promote_source() {
  local bundle="$1" commit="$2" confirmation="$3"
  local private_bundle old_commit='' current_ref='' candidate bundle_size
  [[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || fail
  [[ "${confirmation}" == "promote-reviewed-protected-main-${commit}" ]] || fail
  safe_owner_input_file "${bundle}" || fail
  bundle_size="$(/usr/bin/stat -c %s -- "${bundle}")" || fail
  [[ "${bundle_size}" =~ ^[0-9]+$ ]] || fail
  (( bundle_size > 0 && bundle_size <= 134217728 )) || fail

  if [[ ! -e "${state_parent}" ]]; then
    /usr/bin/install -d -o root -g root -m 0700 -- "${state_parent}" || fail
  fi
  safe_root_directory "${state_parent}" || fail
  [[ "$(/usr/bin/stat -c %a -- "${state_parent}")" == 700 ]] || fail

  private_bundle="$(/usr/bin/mktemp "${runtime_parent}/reviewed-source.XXXXXXXX.bundle")" || fail
  register_cleanup "${private_bundle}"
  copy_stable_owner_file "${bundle}" "${private_bundle}" || {
    /usr/bin/rm -f -- "${private_bundle}" 2>/dev/null || true
    fail
  }

  if [[ ! -e "${source_repository}" ]]; then
    /usr/bin/mkdir -m 0700 -- "${source_repository}" || fail
    trusted_git init --bare "${source_repository}" >/dev/null || fail
  fi
  safe_root_directory "${source_repository}" || fail
  [[ "$(/usr/bin/stat -c %a -- "${source_repository}")" == 700 ]] || fail
  trusted_git --git-dir="${source_repository}" bundle verify "${private_bundle}" \
    >/dev/null || fail

  if [[ -e "${approved_commit_file}" ]]; then
    old_commit="$(read_approved_commit)" || fail
  fi
  current_ref="$(trusted_git --git-dir="${source_repository}" rev-parse \
    --verify refs/heads/main 2>/dev/null || true)"
  if [[ -n "${old_commit}" ]]; then
    [[ "${current_ref}" == "${old_commit}" || "${current_ref}" == "${commit}" ]] || fail
  else
    [[ -z "${current_ref}" || "${current_ref}" == "${commit}" ]] || fail
  fi

  trusted_git --git-dir="${source_repository}" fetch --no-tags --no-write-fetch-head \
    "${private_bundle}" "${commit}" >/dev/null || fail
  /usr/bin/rm -f -- "${private_bundle}" || fail
  trusted_git --git-dir="${source_repository}" cat-file -e "${commit}^{commit}" || fail
  trusted_git --git-dir="${source_repository}" fsck --full --strict --no-dangling >/dev/null || fail
  if [[ -n "${old_commit}" ]]; then
    trusted_git --git-dir="${source_repository}" merge-base --is-ancestor \
      "${old_commit}" "${commit}" || fail
  fi
  verify_installed_launcher_blob "${commit}" || fail

  if [[ "${current_ref}" != "${commit}" ]]; then
    if [[ -n "${current_ref}" ]]; then
      trusted_git --git-dir="${source_repository}" update-ref refs/heads/main \
        "${commit}" "${current_ref}" || fail
    else
      trusted_git --git-dir="${source_repository}" update-ref refs/heads/main \
        "${commit}" 0000000000000000000000000000000000000000 || fail
    fi
  fi

  candidate="$(/usr/bin/mktemp "${state_parent}/approved-main.XXXXXXXX")" || fail
  register_cleanup "${candidate}"
  builtin printf '%s\n' "${commit}" >"${candidate}" || fail
  /usr/bin/chmod 0600 "${candidate}" || fail
  safe_root_file "${candidate}" 600 || fail
  /usr/bin/mv -fT -- "${candidate}" "${approved_commit_file}" || fail
  safe_root_file "${approved_commit_file}" 600 || fail
  [[ "$(read_approved_commit)" == "${commit}" ]] || fail
  builtin printf 'REVIEWED_SOURCE_PROMOTION=PASS\n'
}

read_request() {
  local request="$1"; shift
  local expected_key line key value descriptor before opened after
  safe_owner_input_file "${request}" || fail
  before="$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "${request}")" || fail
  exec {descriptor}<"${request}" || fail
  opened="$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "/proc/$$/fd/${descriptor}")" || fail
  [[ "${opened}" == "${before}" ]] || fail
  for expected_key in "$@"; do
    IFS= builtin read -r line <&"${descriptor}" || fail
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${key}" == "${expected_key}" && "${line}" == *=* ]] || fail
    [[ "${value}" != *$'\r'* && "${value}" != *$'\n'* ]] || fail
    builtin printf -v "${expected_key}" '%s' "${value}" || fail
    builtin export "${expected_key?}"
  done
  if IFS= builtin read -r _ <&"${descriptor}"; then fail; fi
  after="$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "/proc/$$/fd/${descriptor}")" || fail
  exec {descriptor}<&-
  [[ "${after}" == "${before}" ]] || fail
  [[ "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%Y:%Z:%u:%g' -- "${request}")" == \
    "${before}" ]] || fail
}

extract_blob() {
  local commit="$1" root="$2" path="$3" expected_mode="$4"
  local actual_mode destination object_from_tree object_from_file
  actual_mode="$(trusted_git --git-dir="${source_repository}" ls-tree "${commit}" -- \
    "${path}" | /usr/bin/mawk '{print $1}')" || return 1
  [[ "${actual_mode}" == "${expected_mode}" ]] || return 1
  object_from_tree="$(trusted_git --git-dir="${source_repository}" rev-parse \
    "${commit}:${path}")" || return 1
  destination="${root}/${path}"
  /usr/bin/install -d -o root -g root -m 0700 -- \
    "$(/usr/bin/dirname -- "${destination}")" || return 1
  trusted_git --git-dir="${source_repository}" cat-file blob \
    "${commit}:${path}" >"${destination}" || return 1
  if [[ "${expected_mode}" == 100755 ]]; then
    /usr/bin/chmod 0500 "${destination}" || return 1
    safe_root_file "${destination}" 500 || return 1
  else
    /usr/bin/chmod 0400 "${destination}" || return 1
    safe_root_file "${destination}" 400 || return 1
  fi
  object_from_file="$(trusted_git hash-object --no-filters "${destination}")" || return 1
  [[ "${object_from_file}" == "${object_from_tree}" ]]
}

cleanup_extraction() {
  local root="$1"
  [[ -n "${root}" && -d "${root}" && ! -L "${root}" ]] || return 1
  case "${root}" in
    "${runtime_parent}"/reviewed-op.*) /usr/bin/rm -rf -- "${root}" ;;
    *) return 1 ;;
  esac
}

run_operation() {
  local operation="$1" request="${2:-}" commit root entry entry_mode
  local -a paths=() modes=() launch_environment=()
  commit="$(read_approved_commit)" || fail
  [[ "$(trusted_git --git-dir="${source_repository}" rev-parse --verify refs/heads/main)" == \
    "${commit}" ]] || fail
  verify_installed_launcher_blob "${commit}" || fail

  case "${operation}" in
    binary-check)
      [[ -n "${request}" ]] || fail
      read_request "${request}" CLOUDFLARED_HOST_BINARY_PATH
      entry=bootstrap/pi/cloudflared/install-host-binary.sh
      entry_mode=--check
      paths=("${entry}" versions.env)
      modes=(100755 100644)
      ;;
    binary-apply)
      [[ -n "${request}" ]] || fail
      read_request "${request}" CLOUDFLARED_HOST_BINARY_PATH \
        PHYSICAL_OR_LAN_RECOVERY_TESTED TWO_WORKING_SESSIONS_PROVEN \
        CONFIRM_CLOUDFLARED_INSTALL
      entry=bootstrap/pi/cloudflared/install-host-binary.sh
      entry_mode=--apply
      paths=("${entry}" versions.env)
      modes=(100755 100644)
      ;;
    token-check|token-apply)
      [[ -n "${request}" ]] || fail
      if [[ "${operation}" == token-check ]]; then
        read_request "${request}" CLOUDFLARED_TOKEN_WORKSPACE \
          CLOUDFLARED_TUNNEL_TOKEN_FILE EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256 \
          EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256
      else
        read_request "${request}" CLOUDFLARED_TOKEN_WORKSPACE \
          CLOUDFLARED_TUNNEL_TOKEN_FILE EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256 \
          EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256 PHYSICAL_OR_LAN_RECOVERY_TESTED \
          TWO_WORKING_SESSIONS_PROVEN CONFIRM_PI_ADMIN_TOKEN_INSTALL
      fi
      entry=bootstrap/pi/cloudflared/install-host-token.sh
      [[ "${operation}" == token-check ]] && entry_mode=--check || entry_mode=--apply
      paths=("${entry}" scripts/validate_cloudflared_tunnel_token.py)
      modes=(100755 100644)
      ;;
    service-check|service-apply)
      if [[ "${operation}" == service-check ]]; then
        [[ -z "${request}" ]] || fail
      else
        [[ -n "${request}" ]] || fail
        read_request "${request}" PHYSICAL_OR_LAN_RECOVERY_TESTED \
          TWO_WORKING_SESSIONS_PROVEN CONFIRM_PI_ADMIN_SERVICE_INSTALL
      fi
      entry=bootstrap/pi/cloudflared/install-host-service.sh
      [[ "${operation}" == service-check ]] && entry_mode=--check || entry_mode=--apply
      paths=("${entry}" bootstrap/pi/cloudflared/pi-admin.service versions.env)
      modes=(100755 100644 100644)
      ;;
    runtime-verify)
      [[ -z "${request}" ]] || fail
      entry=bootstrap/pi/cloudflared/verify-host-token-redaction.sh
      entry_mode=--verify
      paths=("${entry}" bootstrap/pi/cloudflared/pi-admin.service versions.env)
      modes=(100755 100644 100644)
      ;;
    *) fail ;;
  esac

  root="$(/usr/bin/mktemp -d "${runtime_parent}/reviewed-op.XXXXXXXX")" || fail
  register_cleanup "${root}"
  /usr/bin/chmod 0700 "${root}" || fail
  safe_root_directory "${root}" || fail
  local index=0
  while (( index < ${#paths[@]} )); do
    extract_blob "${commit}" "${root}" "${paths[index]}" "${modes[index]}" || {
      cleanup_extraction "${root}" 2>/dev/null || true
      fail
    }
    (( index += 1 ))
  done

  launch_environment=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/nonexistent LC_ALL=C REVIEWED_BLOB_LAUNCHER_AVAILABLE=yes \
    "REVIEWED_BLOB_ROOT=${root}" "REVIEWED_BLOB_OPERATION=${operation}" \
    "EXPECTED_REPOSITORY_HEAD=${commit}" \
    "EXPECTED_REPOSITORY_OWNER_UID=${SUDO_UID}")
  for inherited_name in CLOUDFLARED_HOST_BINARY_PATH PHYSICAL_OR_LAN_RECOVERY_TESTED \
    TWO_WORKING_SESSIONS_PROVEN CONFIRM_CLOUDFLARED_INSTALL \
    CLOUDFLARED_TOKEN_WORKSPACE CLOUDFLARED_TUNNEL_TOKEN_FILE \
    EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256 EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256 \
    CONFIRM_PI_ADMIN_TOKEN_INSTALL CONFIRM_PI_ADMIN_SERVICE_INSTALL; do
    if builtin declare -p "${inherited_name}" >/dev/null 2>&1; then
      launch_environment+=("${inherited_name}=${!inherited_name}")
    fi
  done

  set +e
  "${launch_environment[@]}" /usr/bin/bash "${root}/${entry}" "${entry_mode}"
  local status=$?
  set -e
  cleanup_extraction "${root}" || fail
  (( status == 0 )) || fail
  builtin printf 'REVIEWED_OPERATION=PASS\n'
}

validate_installed_launcher_boundary
trap cleanup_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

readonly command_name="${1:-}"
case "${command_name}" in
  tool-manifest-proposal)
    (( $# == 1 )) || fail
    tool_manifest_proposal
    builtin exit 0
    ;;
  tool-manifest-commit)
    (( $# == 3 )) || fail
    commit_tool_manifest "$2" "$3"
    builtin exit 0
    ;;
esac

validate_tool_manifest_boundary
validate_tool_manifest
ensure_runtime_state
case "${command_name}" in
  promote)
    (( $# == 4 )) || fail
    promote_source "$2" "$3" "$4"
    ;;
  binary-check|binary-apply|token-check|token-apply|service-apply)
    (( $# == 2 )) || fail
    run_operation "${command_name}" "$2"
    ;;
  service-check|runtime-verify)
    (( $# == 1 )) || fail
    run_operation "${command_name}"
    ;;
  *) fail ;;
esac
