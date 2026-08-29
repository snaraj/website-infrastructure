#!/bin/bash
# Fixed root-owned macOS launcher for the owner-only pie5 Cloudflare admin path.
# It executes only exact blobs extracted from a monotonic protected-main bundle.
set -Eeuo pipefail
set +x
set +o history
umask 077

# Imported functions are rejected before this launcher defines any of its own.
if [[ -n "$(declare -F)" ]]; then
  printf 'CLOUDFLARE_REVIEWED_LAUNCH=FAIL\n' >&2
  exit 1
fi

readonly installed_launcher=/usr/local/sbin/website-infrastructure-cloudflare-launcher
readonly custody_parent=/private/var/db/website-infrastructure
readonly launcher_state=${custody_parent}/cloudflare-launcher
readonly runtime_parent=${custody_parent}/runtime
readonly lock_directory=${runtime_parent}/cloudflare-launcher.lock
readonly source_repository=${launcher_state}/reviewed-source.git
readonly approved_commit_file=${launcher_state}/approved-main
readonly source_remote=https://github.com/snaraj/website-infrastructure.git
readonly source_main_ref=refs/heads/main
readonly tool_manifest=/private/etc/website-infrastructure/cloudflare-tools.sha256
readonly tool_parent=/usr/local/libexec/website-infrastructure
readonly tool_bin=${tool_parent}/cloudflare-bin

readonly tofu_archive_sha256=2ae38150a667f5c0bd57b318d18ad8091d08f93fcca40345f3d88998661de5a9
readonly tofu_binary_sha256=96557429623614140cf41afeb147b8a7e1fbe53e55923b63e7b581bc608d60ca
readonly conftest_archive_sha256=78302d045f0ec52e9786a06c6c621ac4516b4c5dd1e54efc8050c86c29b964d9
readonly conftest_binary_sha256=0534d8d2636d2ab5bb8284cf9a13c8a534108ce976e983ab4f5e2d9cf400b1a1
readonly jq_binary_sha256=2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e

cleanup_targets=()
lock_acquired=false

fail() {
  printf 'CLOUDFLARE_REVIEWED_LAUNCH=FAIL\n' >&2
  exit 1
}

register_cleanup() {
  cleanup_targets+=("$1")
}

cleanup_on_exit() {
  local target
  set +e
  for target in "${cleanup_targets[@]}"; do
    case "${target}" in
      "${runtime_parent}"/cloudflare-reviewed-op.*)
        [[ ! -d "${target}" || -L "${target}" ]] || /bin/rm -rf -- "${target}"
        ;;
      "${runtime_parent}"/source.*.bundle|\
      "${runtime_parent}"/launcher-blob.*|\
      "${runtime_parent}"/tofu-archive.*|\
      "${runtime_parent}"/conftest-archive.*|\
      "${runtime_parent}"/jq-binary.*|\
      "${launcher_state}"/approved-main.*|\
      "${runtime_parent}"/tool-manifest.*|\
      /private/etc/website-infrastructure/cloudflare-tools.sha256.*)
        [[ ! -e "${target}" && ! -L "${target}" ]] || /bin/rm -f -- "${target}"
        ;;
      "${tool_parent}"/cloudflare-bin.stage.*)
        [[ ! -d "${target}" || -L "${target}" ]] || /bin/rm -rf -- "${target}"
        ;;
    esac
  done
  if [[ "${lock_acquired}" == true && -d "${lock_directory}" && ! -L "${lock_directory}" ]]; then
    /bin/rm -f -- "${lock_directory}/pid"
    /bin/rmdir -- "${lock_directory}" 2>/dev/null || true
  fi
}

# No inherited loader/config injection reaches stage zero.
for inherited_name in $(compgen -e); do
  case "${inherited_name}" in
    BASH_ENV|ENV|BASHOPTS|SHELLOPTS|BASH_XTRACEFD|PS4|POSIXLY_CORRECT|\
      CDPATH|GLOBIGNORE|BASH_FUNC_*|DYLD_*|LD_*|GIT_*|PYTHON*|PERL*|RUBY*|\
      PAGER|LESS) fail ;;
  esac
done
ulimit -S -c 0 || fail
ulimit -H -c 0 || fail
[[ "$(ulimit -S -c)" == 0 && "$(ulimit -H -c)" == 0 ]] || fail
[[ "${EUID}" -eq 0 && "${BASH}" == /bin/bash ]] || fail
[[ "${SUDO_UID:-}" =~ ^[1-9][0-9]*$ && "${SUDO_GID:-}" =~ ^[0-9]+$ ]] || fail

readonly -a required_tools=(
  /bin/bash
  /bin/cat
  /bin/chmod
  /usr/sbin/chown
  /bin/cp
  /bin/date
  /usr/bin/dirname
  /usr/bin/env
  /usr/bin/git
  /usr/bin/install
  /bin/mkdir
  /usr/bin/mktemp
  /bin/mv
  /usr/bin/python3
  /bin/rm
  /bin/rmdir
  /usr/bin/shasum
  /usr/bin/stat
  /usr/bin/bsdtar
  /usr/bin/codesign
  /usr/bin/csrutil
  /usr/sbin/spctl
  /usr/bin/fdesetup
  /usr/bin/xattr
  /usr/bin/uname
  /usr/bin/curl
  /usr/bin/awk
  /usr/local/libexec/website-infrastructure/cloudflare-bin/tofu
  /usr/local/libexec/website-infrastructure/cloudflare-bin/conftest
  /usr/local/libexec/website-infrastructure/cloudflare-bin/jq
)

safe_root_directory() {
  local path="$1" expected_mode="${2:-}" observed
  [[ -d "${path}" && ! -L "${path}" ]] || return 1
  observed="$(/usr/bin/stat -f '%u:%g:%Lp' -- "${path}")" || return 1
  [[ "${observed%%:*}" == 0 && "${observed#*:}" == 0:* ]] || return 1
  observed="${observed##*:}"
  if [[ -n "${expected_mode}" ]]; then
    [[ "${observed}" == "${expected_mode}" ]] || return 1
  else
    (( (8#${observed} & 0022) == 0 )) || return 1
  fi
}

safe_root_file() {
  local path="$1" expected_mode="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  [[ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' -- "${path}")" == \
    "0:0:${expected_mode}:1" ]]
}

safe_owner_input_file() {
  local path="$1" maximum="$2" mode size
  [[ "${path}" == /* && "${path}" != *$'\n'* && "${path}" != *$'\r'* ]] || return 1
  [[ "${path}" != *'/../'* && "${path}" != *'/./'* && -f "${path}" && ! -L "${path}" ]] || return 1
  mode="$(/usr/bin/stat -f '%Lp' -- "${path}")" || return 1
  [[ "${mode}" == 400 || "${mode}" == 600 ]] || return 1
  [[ "$(/usr/bin/stat -f '%u:%g:%l' -- "${path}")" == \
    "${SUDO_UID}:${SUDO_GID}:1" ]] || return 1
  size="$(/usr/bin/stat -f '%z' -- "${path}")" || return 1
  [[ "${size}" =~ ^[0-9]+$ ]] || return 1
  (( size > 0 && size <= maximum ))
}

copy_stable_owner_file() {
  local source="$1" destination="$2" maximum="$3" before opened after
  safe_owner_input_file "${source}" "${maximum}" || return 1
  before="$(/usr/bin/stat -f '%d:%i:%p:%l:%z:%m:%c:%u:%g' -- "${source}")" || return 1
  exec 7<"${source}" || return 1
  opened="$(/usr/bin/stat -f '%d:%i:%p:%l:%z:%m:%c:%u:%g' -- /dev/fd/7)" || {
    exec 7<&-; return 1;
  }
  [[ "${opened}" == "${before}" ]] || { exec 7<&-; return 1; }
  /bin/cat <&7 >"${destination}" || { exec 7<&-; return 1; }
  after="$(/usr/bin/stat -f '%d:%i:%p:%l:%z:%m:%c:%u:%g' -- /dev/fd/7)" || {
    exec 7<&-; return 1;
  }
  exec 7<&-
  [[ "${after}" == "${before}" ]] || return 1
  [[ "$(/usr/bin/stat -f '%d:%i:%p:%l:%z:%m:%c:%u:%g' -- "${source}")" == \
    "${before}" ]] || return 1
  /bin/chmod 0400 "${destination}" || return 1
  /usr/sbin/chown 0:0 "${destination}" || return 1
  safe_root_file "${destination}" 400
}

sha256_file() {
  local output
  output="$(/usr/bin/shasum -a 256 -- "$1")" || return 1
  output="${output%% *}"
  [[ "${output}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "${output}"
}

validate_platform_boundary() {
  [[ "${BASH_SOURCE[0]}" == "${installed_launcher}" ]] || fail
  safe_root_directory /private || fail
  safe_root_directory /private/etc || fail
  safe_root_directory /private/var || fail
  safe_root_directory /private/var/db || fail
  safe_root_directory /usr || fail
  safe_root_directory /usr/local || fail
  safe_root_directory /usr/local/sbin || fail
  safe_root_file "${installed_launcher}" 755 || fail
  [[ "$(/usr/bin/uname -s)" == Darwin && "$(/usr/bin/uname -m)" == arm64 ]] || fail
  [[ "$(/usr/bin/fdesetup status)" == 'FileVault is On.' ]] || fail
  [[ "$(/usr/bin/csrutil status)" == 'System Integrity Protection status: enabled.' ]] || fail
  [[ "$(/usr/sbin/spctl --status 2>&1)" == 'assessments enabled' ]] || fail
}

ensure_directory() {
  local path="$1" mode="$2"
  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    /usr/bin/install -d -o root -g wheel -m "${mode}" -- "${path}" || fail
  fi
  safe_root_directory "${path}" "${mode#0}" || fail
}

ensure_state_directories() {
  ensure_directory "${custody_parent}" 0700
  ensure_directory "${launcher_state}" 0700
  ensure_directory "${runtime_parent}" 0700
}

acquire_lock() {
  ensure_state_directories
  /bin/mkdir -m 0700 -- "${lock_directory}" 2>/dev/null || fail
  lock_acquired=true
  printf '%s\n' "$$" >"${lock_directory}/pid" || fail
  /bin/chmod 0600 "${lock_directory}/pid" || fail
  /usr/sbin/chown 0:0 "${lock_directory}/pid" || fail
  safe_root_file "${lock_directory}/pid" 600 || fail
}

recover_stale_lock() {
  local confirmation="$1" pid
  ensure_state_directories
  safe_root_directory "${lock_directory}" 700 || fail
  safe_root_file "${lock_directory}/pid" 600 || fail
  exec 7<"${lock_directory}/pid" || fail
  IFS= read -r pid <&7 || fail
  if IFS= read -r _ <&7; then fail; fi
  exec 7<&-
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || fail
  if kill -0 "${pid}" 2>/dev/null; then fail; fi
  [[ "${confirmation}" == "recover-stale-cloudflare-launcher-lock-${pid}" ]] || fail
  /bin/rm -f -- "${lock_directory}/pid" || fail
  /bin/rmdir -- "${lock_directory}" || fail
  printf 'CLOUDFLARE_LAUNCHER_LOCK_RECOVERY=PASS\n'
}

validate_required_tool() {
  local path="$1" mode
  [[ -f "${path}" && ! -L "${path}" && -x "${path}" ]] || return 1
  [[ "$(/usr/bin/stat -f '%u:%g:%l' -- "${path}")" == 0:0:1 ]] || return 1
  mode="$(/usr/bin/stat -f '%Lp' -- "${path}")" || return 1
  (( (8#${mode} & 0022) == 0 ))
}

render_tool_manifest() {
  local destination="$1" path digest
  /usr/bin/install -o root -g wheel -m 0600 -- /dev/null "${destination}" || return 1
  for path in "${required_tools[@]}"; do
    validate_required_tool "${path}" || return 1
    digest="$(sha256_file "${path}")" || return 1
    printf '%s  %s\n' "${digest}" "${path}" >>"${destination}" || return 1
  done
  safe_root_file "${destination}" 600
}

validate_tool_manifest_boundary() {
  safe_root_directory /private/etc || fail
  safe_root_directory /private/etc/website-infrastructure 700 || fail
  safe_root_file "${tool_manifest}" 600 || fail
  safe_root_directory "${tool_parent}" 700 || fail
  safe_root_directory "${tool_bin}" 700 || fail
}

validate_tool_manifest() {
  local line digest path expected index=0 observed
  exec 7<"${tool_manifest}" || fail
  while (( index < ${#required_tools[@]} )); do
    IFS= read -r line <&7 || fail
    digest="${line%%  *}"
    path="${line#*  }"
    expected="${required_tools[index]}"
    [[ "${digest}" =~ ^[0-9a-f]{64}$ && "${path}" == "${expected}" ]] || fail
    validate_required_tool "${path}" || fail
    observed="$(sha256_file "${path}")" || fail
    [[ "${observed}" == "${digest}" ]] || fail
    (( index += 1 ))
  done
  if IFS= read -r line <&7; then fail; fi
  exec 7<&-
}

tool_manifest_proposal() {
  local candidate digest
  candidate="$(/usr/bin/mktemp "${runtime_parent}/tool-manifest.XXXXXXXX")" || fail
  register_cleanup "${candidate}"
  render_tool_manifest "${candidate}" || fail
  digest="$(sha256_file "${candidate}")" || fail
  /bin/rm -f -- "${candidate}" || fail
  printf 'CLOUDFLARE_TOOL_MANIFEST_PROPOSAL_SHA256=%s\n' "${digest}"
}

commit_tool_manifest() {
  local expected_digest="$1" confirmation="$2" candidate observed
  [[ "${expected_digest}" =~ ^[0-9a-f]{64}$ ]] || fail
  [[ "${confirmation}" == "commit-cloudflare-tool-manifest-${expected_digest}" ]] || fail
  ensure_directory /private/etc/website-infrastructure 0700
  if [[ -e "${tool_manifest}" || -L "${tool_manifest}" ]]; then
    safe_root_file "${tool_manifest}" 600 || fail
  fi
  candidate="$(/usr/bin/mktemp "/private/etc/website-infrastructure/cloudflare-tools.sha256.XXXXXXXX")" || fail
  register_cleanup "${candidate}"
  render_tool_manifest "${candidate}" || fail
  observed="$(sha256_file "${candidate}")" || fail
  [[ "${observed}" == "${expected_digest}" ]] || fail
  /bin/mv -f -- "${candidate}" "${tool_manifest}" || fail
  validate_tool_manifest_boundary
  validate_tool_manifest
  printf 'CLOUDFLARE_TOOL_MANIFEST_COMMIT=PASS\n'
}

validate_installed_tools() {
  safe_root_directory "${tool_bin}" 700 || return 1
  safe_root_file "${tool_bin}/tofu" 500 || return 1
  safe_root_file "${tool_bin}/conftest" 500 || return 1
  safe_root_file "${tool_bin}/jq" 500 || return 1
  [[ "$(sha256_file "${tool_bin}/tofu")" == "${tofu_binary_sha256}" ]] || return 1
  [[ "$(sha256_file "${tool_bin}/conftest")" == "${conftest_binary_sha256}" ]] || return 1
  [[ "$(sha256_file "${tool_bin}/jq")" == "${jq_binary_sha256}" ]] || return 1
}

read_request() {
  local request="$1"; shift
  local expected_key line key value before opened after
  safe_owner_input_file "${request}" 65536 || fail
  before="$(/usr/bin/stat -f '%d:%i:%p:%l:%z:%m:%c:%u:%g' -- "${request}")" || fail
  exec 7<"${request}" || fail
  opened="$(/usr/bin/stat -f '%d:%i:%p:%l:%z:%m:%c:%u:%g' -- /dev/fd/7)" || fail
  [[ "${opened}" == "${before}" ]] || fail
  for expected_key in "$@"; do
    IFS= read -r line <&7 || fail
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${key}" == "${expected_key}" && "${line}" == *=* ]] || fail
    [[ "${value}" != *$'\r'* && "${value}" != *$'\n'* ]] || fail
    printf -v "${expected_key}" '%s' "${value}" || fail
  done
  if IFS= read -r line <&7; then fail; fi
  after="$(/usr/bin/stat -f '%d:%i:%p:%l:%z:%m:%c:%u:%g' -- /dev/fd/7)" || fail
  exec 7<&-
  [[ "${after}" == "${before}" ]] || fail
  [[ "$(/usr/bin/stat -f '%d:%i:%p:%l:%z:%m:%c:%u:%g' -- "${request}")" == \
    "${before}" ]] || fail
}

install_tools() {
  local request="$1" stage tofu_inventory conftest_inventory
  local private_tofu private_conftest private_jq
  read_request "${request}" OPENTOFU_ARCHIVE_PATH CONFTEST_ARCHIVE_PATH JQ_BINARY_PATH CONFIRM_CLOUDFLARE_TOOL_INSTALL
  [[ "${CONFIRM_CLOUDFLARE_TOOL_INSTALL}" == \
    install-reviewed-cloudflare-tools-1.12.5-0.69.0-1.8.2 ]] || fail
  private_tofu="$(/usr/bin/mktemp "${runtime_parent}/tofu-archive.XXXXXXXX")" || fail
  private_conftest="$(/usr/bin/mktemp "${runtime_parent}/conftest-archive.XXXXXXXX")" || fail
  private_jq="$(/usr/bin/mktemp "${runtime_parent}/jq-binary.XXXXXXXX")" || fail
  register_cleanup "${private_tofu}"
  register_cleanup "${private_conftest}"
  register_cleanup "${private_jq}"
  copy_stable_owner_file "${OPENTOFU_ARCHIVE_PATH}" "${private_tofu}" 268435456 || fail
  copy_stable_owner_file "${CONFTEST_ARCHIVE_PATH}" "${private_conftest}" 268435456 || fail
  copy_stable_owner_file "${JQ_BINARY_PATH}" "${private_jq}" 16777216 || fail
  [[ "$(sha256_file "${private_tofu}")" == "${tofu_archive_sha256}" ]] || fail
  [[ "$(sha256_file "${private_conftest}")" == "${conftest_archive_sha256}" ]] || fail
  [[ "$(sha256_file "${private_jq}")" == "${jq_binary_sha256}" ]] || fail
  tofu_inventory="$(/usr/bin/bsdtar -tzf "${private_tofu}")" || fail
  conftest_inventory="$(/usr/bin/bsdtar -tzf "${private_conftest}")" || fail
  [[ "${tofu_inventory}" == $'CHANGELOG.md\nLICENSE\nREADME.md\ntofu' ]] || fail
  [[ "${conftest_inventory}" == $'LICENSE\nREADME.md\nconftest' ]] || fail
  if [[ -e "${tool_bin}" || -L "${tool_bin}" ]]; then
    validate_installed_tools || fail
    printf 'CLOUDFLARE_TOOL_INSTALL=ALREADY_EXACT\n'
    return
  fi
  ensure_directory /usr/local/libexec 0755
  ensure_directory "${tool_parent}" 0700
  stage="$(/usr/bin/mktemp -d "${tool_parent}/cloudflare-bin.stage.XXXXXXXX")" || fail
  register_cleanup "${stage}"
  /bin/chmod 0700 "${stage}" || fail
  /usr/bin/bsdtar -xzf "${private_tofu}" -C "${stage}" tofu || fail
  /usr/bin/bsdtar -xzf "${private_conftest}" -C "${stage}" conftest || fail
  /bin/cp -- "${private_jq}" "${stage}/jq" || fail
  /usr/bin/xattr -c "${stage}/tofu" "${stage}/conftest" "${stage}/jq" || fail
  /bin/chmod 0500 "${stage}/tofu" "${stage}/conftest" "${stage}/jq" || fail
  /usr/sbin/chown 0:0 "${stage}/tofu" "${stage}/conftest" "${stage}/jq" || fail
  /usr/bin/codesign --verify --strict "${stage}/tofu" || fail
  /usr/bin/codesign --verify --strict "${stage}/conftest" || fail
  /usr/bin/codesign --verify --strict "${stage}/jq" || fail
  [[ "$(sha256_file "${stage}/tofu")" == "${tofu_binary_sha256}" ]] || fail
  [[ "$(sha256_file "${stage}/conftest")" == "${conftest_binary_sha256}" ]] || fail
  [[ "$(sha256_file "${stage}/jq")" == "${jq_binary_sha256}" ]] || fail
  /bin/mv -- "${stage}" "${tool_bin}" || fail
  validate_installed_tools || fail
  printf 'CLOUDFLARE_TOOL_INSTALL=PASS\n'
}

trusted_git() {
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/var/empty LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    /usr/bin/git --no-replace-objects -c credential.helper= -c core.askPass= \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null "$@"
}

trusted_remote_git() {
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/var/empty LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    GIT_ALLOW_PROTOCOL=https \
    /usr/bin/git --no-replace-objects -c credential.helper= -c core.askPass= \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null \
    -c protocol.file.allow=never -c protocol.ext.allow=never \
    -c protocol.ssh.allow=never -c http.sslVerify=true \
    -c http.followRedirects=false "$@"
}

verify_live_main_tip() {
  local commit="$1" observed
  observed="$(trusted_remote_git ls-remote --refs --exit-code \
    "${source_remote}" "${source_main_ref}")" || return 1
  [[ "${observed}" == "${commit}"$'\t'"${source_main_ref}" ]]
}

read_approved_commit() {
  local value
  safe_root_file "${approved_commit_file}" 600 || return 1
  exec 7<"${approved_commit_file}" || return 1
  IFS= read -r value <&7 || { exec 7<&-; return 1; }
  if IFS= read -r _ <&7; then exec 7<&-; return 1; fi
  exec 7<&-
  [[ "${value}" =~ ^[0-9a-f]{40}$ ]] || return 1
  printf '%s' "${value}"
}

verify_installed_launcher_blob() {
  local commit="$1" mode expected observed temporary
  mode="$(trusted_git --git-dir="${source_repository}" ls-tree "${commit}" -- \
    scripts/cloudflare-reviewed-launcher.sh | /usr/bin/awk '{print $1}')" || return 1
  [[ "${mode}" == 100755 ]] || return 1
  temporary="$(/usr/bin/mktemp "${runtime_parent}/launcher-blob.XXXXXXXX")" || return 1
  register_cleanup "${temporary}"
  trusted_git --git-dir="${source_repository}" cat-file blob \
    "${commit}:scripts/cloudflare-reviewed-launcher.sh" >"${temporary}" || return 1
  expected="$(sha256_file "${temporary}")" || return 1
  observed="$(sha256_file "${installed_launcher}")" || return 1
  /bin/rm -f -- "${temporary}" || return 1
  [[ "${expected}" == "${observed}" ]]
}

pending_phase_exists() {
  local candidate
  for candidate in "${custody_parent}/cloudflare/pending/"*.json; do
    [[ -e "${candidate}" || -L "${candidate}" ]] || continue
    return 0
  done
  return 1
}

promote_source() {
  local bundle="$1" commit="$2" confirmation="$3"
  local private_bundle old_commit='' current_ref='' candidate bundle_size bundle_main
  [[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || fail
  [[ "${confirmation}" == "promote-reviewed-protected-main-${commit}" ]] || fail
  pending_phase_exists && fail
  safe_owner_input_file "${bundle}" 134217728 || fail
  bundle_size="$(/usr/bin/stat -f '%z' -- "${bundle}")" || fail
  (( bundle_size > 0 && bundle_size <= 134217728 )) || fail
  private_bundle="$(/usr/bin/mktemp "${runtime_parent}/source.XXXXXXXX.bundle")" || fail
  register_cleanup "${private_bundle}"
  copy_stable_owner_file "${bundle}" "${private_bundle}" 134217728 || fail
  bundle_main="$(trusted_git bundle list-heads "${private_bundle}" \
    "${source_main_ref}")" || fail
  [[ "${bundle_main}" == "${commit} ${source_main_ref}" ]] || fail
  verify_live_main_tip "${commit}" || fail
  if [[ ! -e "${source_repository}" && ! -L "${source_repository}" ]]; then
    /bin/mkdir -m 0700 -- "${source_repository}" || fail
    trusted_git init --bare "${source_repository}" >/dev/null || fail
  fi
  safe_root_directory "${source_repository}" 700 || fail
  trusted_git --git-dir="${source_repository}" bundle verify "${private_bundle}" >/dev/null || fail
  if [[ -e "${approved_commit_file}" ]]; then old_commit="$(read_approved_commit)" || fail; fi
  current_ref="$(trusted_git --git-dir="${source_repository}" rev-parse --verify refs/heads/main 2>/dev/null || true)"
  if [[ -n "${old_commit}" ]]; then
    [[ "${current_ref}" == "${old_commit}" || "${current_ref}" == "${commit}" ]] || fail
  else
    [[ -z "${current_ref}" || "${current_ref}" == "${commit}" ]] || fail
  fi
  trusted_git --git-dir="${source_repository}" fetch --no-tags --no-write-fetch-head \
    "${private_bundle}" "${commit}" >/dev/null || fail
  /bin/rm -f -- "${private_bundle}" || fail
  trusted_git --git-dir="${source_repository}" cat-file -e "${commit}^{commit}" || fail
  trusted_git --git-dir="${source_repository}" fsck --full --strict --no-dangling >/dev/null || fail
  if [[ -n "${old_commit}" ]]; then
    trusted_git --git-dir="${source_repository}" merge-base --is-ancestor "${old_commit}" "${commit}" || fail
  fi
  verify_installed_launcher_blob "${commit}" || fail
  if [[ "${current_ref}" != "${commit}" ]]; then
    if [[ -n "${current_ref}" ]]; then
      trusted_git --git-dir="${source_repository}" update-ref refs/heads/main "${commit}" "${current_ref}" || fail
    else
      trusted_git --git-dir="${source_repository}" update-ref refs/heads/main "${commit}" \
        0000000000000000000000000000000000000000 || fail
    fi
  fi
  candidate="$(/usr/bin/mktemp "${launcher_state}/approved-main.XXXXXXXX")" || fail
  register_cleanup "${candidate}"
  printf '%s\n' "${commit}" >"${candidate}" || fail
  /bin/chmod 0600 "${candidate}" || fail
  /usr/sbin/chown 0:0 "${candidate}" || fail
  safe_root_file "${candidate}" 600 || fail
  /bin/mv -f -- "${candidate}" "${approved_commit_file}" || fail
  [[ "$(read_approved_commit)" == "${commit}" ]] || fail
  printf 'CLOUDFLARE_REVIEWED_SOURCE_PROMOTION=PASS\n'
}

extract_blob() {
  local commit="$1" root="$2" path="$3" expected_mode="$4"
  local actual_mode destination object_from_tree object_from_file
  actual_mode="$(trusted_git --git-dir="${source_repository}" ls-tree "${commit}" -- \
    "${path}" | /usr/bin/awk '{print $1}')" || return 1
  [[ "${actual_mode}" == "${expected_mode}" ]] || return 1
  object_from_tree="$(trusted_git --git-dir="${source_repository}" rev-parse \
    "${commit}:${path}")" || return 1
  destination="${root}/${path}"
  /usr/bin/install -d -o root -g wheel -m 0700 -- \
    "$(/usr/bin/dirname -- "${destination}")" || return 1
  trusted_git --git-dir="${source_repository}" cat-file blob \
    "${commit}:${path}" >"${destination}" || return 1
  /bin/chmod 0400 "${destination}" || return 1
  /usr/sbin/chown 0:0 "${destination}" || return 1
  safe_root_file "${destination}" 400 || return 1
  object_from_file="$(trusted_git hash-object --no-filters "${destination}")" || return 1
  [[ "${object_from_file}" == "${object_from_tree}" ]]
}

copy_operation_input() {
  local source="$1" root="$2" name="$3" maximum="$4" destination
  destination="${root}/protected-input/${name}"
  /usr/bin/install -d -o root -g wheel -m 0700 -- "${root}/protected-input" || return 1
  copy_stable_owner_file "${source}" "${destination}" "${maximum}" || return 1
  printf '%s' "${destination}"
}

append_phase_paths() {
  local phase="$1" prefix
  prefix="infrastructure/cloudflare/phases/${phase}"
  operation_paths+=(
    "${prefix}/.terraform.lock.hcl"
    "${prefix}/main.tf"
    "${prefix}/variables.tf"
    "${prefix}/versions.tf"
  )
  operation_modes+=(100644 100644 100644 100644)
  if [[ "${phase}" != admin-policies ]]; then
    operation_paths+=("${prefix}/outputs.tf")
    operation_modes+=(100644)
  fi
}

run_operation() {
  local operation="$1" phase="${2:-}" request="${3:-}" commit root index status
  local token_copy='' context_copy='' certificate_copy=''
  local -a operation_paths operation_modes python_arguments
  operation_paths=(scripts/cloudflare_root_transaction.py)
  operation_modes=(100644)
  python_arguments=()
  commit="$(read_approved_commit)" || fail
  [[ "$(trusted_git --git-dir="${source_repository}" rev-parse --verify refs/heads/main)" == \
    "${commit}" ]] || fail
  verify_installed_launcher_blob "${commit}" || fail
  root="$(/usr/bin/mktemp -d "${runtime_parent}/cloudflare-reviewed-op.XXXXXXXX")" || fail
  register_cleanup "${root}"
  /bin/chmod 0700 "${root}" || fail
  /usr/sbin/chown 0:0 "${root}" || fail
  safe_root_directory "${root}" 700 || fail

  case "${operation}" in
    audit-token-proposal)
      [[ -z "${phase}" && -n "${request}" ]] || fail
      read_request "${request}" AUDIT_TOKEN_PATH CONTEXT_PATH
      token_copy="$(copy_operation_input "${AUDIT_TOKEN_PATH}" "${root}" audit-token 256)" || fail
      context_copy="$(copy_operation_input "${CONTEXT_PATH}" "${root}" context.json 65536)" || fail
      python_arguments=(audit-token-proposal "${token_copy}" "${context_copy}")
      ;;
    configure)
      [[ -z "${phase}" && -n "${request}" ]] || fail
      read_request "${request}" CONTEXT_PATH AUDIT_TOKEN_PATH OWNER_DEVICE_CA_CERTIFICATE_PATH CONFIRM_CLOUDFLARE_CONFIGURATION
      [[ "${CONFIRM_CLOUDFLARE_CONFIGURATION}" == configure-owner-only-pie5-cloudflare-admin ]] || fail
      context_copy="$(copy_operation_input "${CONTEXT_PATH}" "${root}" context.json 65536)" || fail
      token_copy="$(copy_operation_input "${AUDIT_TOKEN_PATH}" "${root}" audit-token 256)" || fail
      certificate_copy="$(copy_operation_input "${OWNER_DEVICE_CA_CERTIFICATE_PATH}" "${root}" owner-device-ca.pem 16384)" || fail
      python_arguments=(configure "${context_copy}" "${token_copy}" "${certificate_copy}")
      ;;
    rotate-audit-token)
      [[ -z "${phase}" && -n "${request}" ]] || fail
      read_request "${request}" AUDIT_TOKEN_PATH
      token_copy="$(copy_operation_input "${AUDIT_TOKEN_PATH}" "${root}" audit-token 256)" || fail
      python_arguments=(rotate-audit-token "${token_copy}")
      ;;
    apply)
      case "${phase}" in
        admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route) ;;
        *) fail ;;
      esac
      [[ -n "${request}" ]] || fail
      read_request "${request}" JIT_TOKEN_PATH JIT_TOKEN_ID
      [[ "${JIT_TOKEN_ID}" =~ ^[0-9a-f]{32}$ ]] || fail
      token_copy="$(copy_operation_input "${JIT_TOKEN_PATH}" "${root}" jit-token 256)" || fail
      operation_paths+=(scripts/cloudflare-audit.sh infrastructure/cloudflare/policy/cloudflare-plan.rego infrastructure/cloudflare/policy/cloudflare-cost-policy.yaml)
      operation_modes+=(100755 100644 100644)
      append_phase_paths "${phase}"
      python_arguments=(apply "${phase}" "${token_copy}" "${JIT_TOKEN_ID}")
      ;;
    resume)
      case "${phase}" in
        admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route) ;;
        *) fail ;;
      esac
      [[ -z "${request}" ]] || fail
      operation_paths+=(scripts/cloudflare-audit.sh infrastructure/cloudflare/policy/cloudflare-plan.rego infrastructure/cloudflare/policy/cloudflare-cost-policy.yaml)
      operation_modes+=(100755 100644 100644)
      append_phase_paths "${phase}"
      python_arguments=(resume "${phase}")
      ;;
    status|emit-runtime-token)
      [[ -z "${phase}" && -z "${request}" ]] || fail
      python_arguments=("${operation}")
      ;;
    *) fail ;;
  esac

  index=0
  while (( index < ${#operation_paths[@]} )); do
    extract_blob "${commit}" "${root}" "${operation_paths[index]}" \
      "${operation_modes[index]}" || fail
    (( index += 1 ))
  done
  set +e
  /usr/bin/env -i PATH="${tool_bin}:/usr/bin:/bin:/usr/sbin:/sbin" \
    HOME=/var/empty LC_ALL=C REVIEWED_BLOB_LAUNCHER_AVAILABLE=yes \
    "REVIEWED_BLOB_ROOT=${root}" "EXPECTED_REPOSITORY_HEAD=${commit}" \
    /usr/bin/python3 -I -B "${root}/scripts/cloudflare_root_transaction.py" \
    "${python_arguments[@]}"
  status=$?
  set -e
  (( status == 0 )) || fail
  if [[ "${operation}" != emit-runtime-token ]]; then
    printf 'CLOUDFLARE_REVIEWED_OPERATION=PASS\n'
  fi
}

validate_platform_boundary
trap cleanup_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

readonly command_name="${1:-}"
case "${command_name}" in
  recover-lock)
    (( $# == 2 )) || fail
    recover_stale_lock "$2"
    exit 0
    ;;
esac

acquire_lock
case "${command_name}" in
  tools-install)
    (( $# == 2 )) || fail
    install_tools "$2"
    exit 0
    ;;
  tool-manifest-proposal)
    (( $# == 1 )) || fail
    validate_installed_tools || fail
    tool_manifest_proposal
    exit 0
    ;;
  tool-manifest-commit)
    (( $# == 3 )) || fail
    validate_installed_tools || fail
    commit_tool_manifest "$2" "$3"
    exit 0
    ;;
esac

validate_tool_manifest_boundary
validate_tool_manifest
case "${command_name}" in
  promote)
    (( $# == 4 )) || fail
    promote_source "$2" "$3" "$4"
    ;;
  audit-token-proposal|configure|rotate-audit-token)
    (( $# == 2 )) || fail
    run_operation "${command_name}" '' "$2"
    ;;
  apply)
    (( $# == 3 )) || fail
    run_operation apply "$2" "$3"
    ;;
  resume)
    (( $# == 2 )) || fail
    run_operation resume "$2"
    ;;
  status|emit-runtime-token)
    (( $# == 1 )) || fail
    run_operation "${command_name}"
    ;;
  *) fail ;;
esac
