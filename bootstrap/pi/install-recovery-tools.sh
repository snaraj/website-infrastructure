#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'FAIL %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
[[ -f "${repo_root}/versions.env" && ! -L "${repo_root}/versions.env" ]] || \
  die 'trusted repository versions file is unavailable'
[[ "$(stat -c %a "${repo_root}/versions.env" 2>/dev/null || true)" == 644 ]] || \
  die 'trusted repository versions file must have mode 0644'
if grep -Ev '^(#|$|[A-Z0-9_]+=[A-Za-z0-9._:/@+-]+)$' "${repo_root}/versions.env" >/dev/null; then
  die 'trusted repository versions file contains unsupported shell syntax'
fi
# shellcheck disable=SC1091
source "${repo_root}/versions.env"
mode="${1:---check}"
[[ "${mode}" == "--check" || "${mode}" == "--apply" ]] || \
  die "usage: $0 [--check|--apply]"
if [[ "${mode}" == "--apply" ]]; then
  [[ "${EUID}" -eq 0 ]] || die 'apply mode requires root'
  [[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || \
    die 'physical or LAN recovery acknowledgement is missing'
  [[ "${CONFIRM_ETCD_TOOLS_INSTALL:-}" == "install-reviewed-etcd-tools-${ETCD_VERSION}" ]] || \
    die 'exact etcd tools install acknowledgement is missing'
  [[ "${CONFIRM_ETCD_SNAPSHOT_TIMER:-}" == enable-reviewed-six-hour-etcd-snapshots ]] || \
    die 'exact snapshot timer acknowledgement is missing'
fi

artifact_dir="${KUBERNETES_ARTIFACT_DIR:-${repo_root}/.artifacts/bootstrap-arm64}"
archive_path="${ETCD_TOOLS_ARCHIVE_PATH:-${artifact_dir}/etcd-v${ETCD_VERSION}-linux-arm64.tar.gz}"
archive_root="etcd-v${ETCD_VERSION}-linux-arm64"
decisions_path="${PI_DECISIONS_PATH:-${repo_root}/bootstrap/pi/decisions.env.local}"
snapshot_dir=/var/backups/kubernetes/etcd
service_name=website-infrastructure-etcd-snapshot.service
timer_name=website-infrastructure-etcd-snapshot.timer

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"
}

decision() {
  awk -F= -v key="$1" '$1 == key {sub(/^[^=]*=/, ""); print}' "${decisions_path}"
}

validate_decisions() {
  local key count mode_bits
  [[ -f "${decisions_path}" && ! -L "${decisions_path}" ]] || \
    die "reviewed Pi decisions file is unavailable: ${decisions_path}"
  mode_bits="$(stat -c %a "${decisions_path}" 2>/dev/null || true)"
  [[ "${mode_bits}" == 600 ]] || die 'reviewed Pi decisions file must have mode 0600'
  for key in DECISION_STATUS EXPECTED_SSD_FILESYSTEM_UUID EXPECTED_SSD_MOUNT_SOURCE; do
    count="$(grep -Ec "^${key}=" "${decisions_path}" || true)"
    [[ "${count}" == 1 ]] || die "decision ${key} must occur exactly once"
  done
  [[ "$(decision DECISION_STATUS)" == approved-after-pi-discovery ]] || \
    die 'Pi decisions are not approved after discovery'
  if grep -E '^(EXPECTED_SSD_FILESYSTEM_UUID|EXPECTED_SSD_MOUNT_SOURCE)=(|REPLACE_|UNRESOLVED)' \
    "${decisions_path}" >/dev/null; then
    die 'reviewed SSD identity is unresolved'
  fi
  if grep -E '^(DECISION_STATUS|EXPECTED_SSD_FILESYSTEM_UUID|EXPECTED_SSD_MOUNT_SOURCE)=.*[[:space:]]' \
    "${decisions_path}" >/dev/null; then
    die 'reviewed SSD decisions contain whitespace'
  fi
}

validate_backing() {
  local target="$1" actual_uuid actual_source options
  [[ -d "${target}" && ! -L "${target}" ]] || die "SSD review target is absent or unsafe: ${target}"
  actual_uuid="$(findmnt -T "${target}" -n -o UUID 2>/dev/null || true)"
  actual_source="$(findmnt -T "${target}" -n -o SOURCE 2>/dev/null | sed 's/\[.*$//' || true)"
  options="$(findmnt -T "${target}" -n -o OPTIONS 2>/dev/null || true)"
  [[ -n "${actual_uuid}" && "${actual_uuid}" == "$(decision EXPECTED_SSD_FILESYSTEM_UUID)" ]] || \
    die "${target} filesystem UUID differs from the reviewed SSD"
  [[ -n "${actual_source}" && "${actual_source}" == "$(decision EXPECTED_SSD_MOUNT_SOURCE)" ]] || \
    die "${target} mount source differs from the reviewed SSD"
  [[ ",${options}," != *,ro,* ]] || die "${target} filesystem is read-only"
}

tool_version() {
  local tool_path="$1" label="$2"
  "${tool_path}" version 2>/dev/null | \
    awk -F': ' -v wanted="${label} version" '$1 == wanted {print $2; exit}'
}

safe_archive() {
  local listing verbose entry component type_line type_count=0
  local -a components
  listing="$(tar -tzf "${archive_path}")" || die 'staged etcd archive cannot be listed'
  [[ -n "${listing}" ]] || die 'staged etcd archive is empty'
  while IFS= read -r entry; do
    [[ -n "${entry}" ]] || die 'staged etcd archive contains an empty path'
    [[ "${entry}" == "${archive_root}" || "${entry}" == "${archive_root}/"* ]] || \
      die 'staged etcd archive contains an unexpected top-level path'
    [[ "${entry}" != /* && "${entry}" != *\\* && "${entry}" != *//* ]] || \
      die 'staged etcd archive contains an unsafe path'
    IFS='/' read -r -a components <<<"${entry}"
    for component in "${components[@]}"; do
      [[ -z "${component}" || ( "${component}" != . && "${component}" != .. ) ]] || \
        die 'staged etcd archive contains path traversal'
    done
  done <<<"${listing}"

  [[ "$(grep -Fxc "${archive_root}/etcdctl" <<<"${listing}")" == 1 ]] || \
    die 'staged etcd archive must contain etcdctl exactly once'
  [[ "$(grep -Fxc "${archive_root}/etcdutl" <<<"${listing}")" == 1 ]] || \
    die 'staged etcd archive must contain etcdutl exactly once'

  verbose="$(LC_ALL=C tar -tvzf "${archive_path}")" || die 'staged etcd archive types cannot be inspected'
  while IFS= read -r type_line; do
    [[ -n "${type_line}" ]] || continue
    case "${type_line:0:1}" in
      -|d) ;;
      *) die 'staged etcd archive contains a link, device, or unsupported member type' ;;
    esac
    type_count=$((type_count + 1))
  done <<<"${verbose}"
  [[ "${type_count}" == "$(wc -l <<<"${listing}" | tr -d ' ')" ]] || \
    die 'staged etcd archive name/type inventory is inconsistent'
}

for command_name in awk bash chmod cp date dirname findmnt grep install mktemp readlink rm rmdir sed sha256sum stat systemctl systemd-analyze tar tr uname wc; do
  require_command "${command_name}"
done
[[ "$(uname -s)" == Linux ]] || die 'recovery tools must be checked on the target Linux host'
[[ "$(uname -m)" =~ ^(aarch64|arm64)$ ]] || die 'recovery tools require the reviewed ARM64 target'
[[ "${ETCD_VERSION:-}" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] || \
  die 'ETCD_VERSION is unresolved or malformed'
[[ "${ETCD_TOOLS_ARM64_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || \
  die 'ETCD_TOOLS_ARM64_SHA256 is unresolved or malformed'
[[ -f "${archive_path}" && ! -L "${archive_path}" ]] || die "staged etcd archive is missing: ${archive_path}"
printf '%s  %s\n' "${ETCD_TOOLS_ARM64_SHA256}" "${archive_path}" | \
  sha256sum --check --status || die 'staged etcd archive checksum mismatch'
validate_decisions
backing_probe=/var/backups
if [[ -d /var/backups/kubernetes && ! -L /var/backups/kubernetes ]]; then
  backing_probe=/var/backups/kubernetes
fi
validate_backing "${backing_probe}"
safe_archive

temporary_parent="$(readlink -f "${TMPDIR:-/tmp}")"
[[ -d "${temporary_parent}" ]] || die 'temporary directory parent is unavailable'
temporary="$(mktemp -d "${temporary_parent%/}/website-infrastructure-etcd.XXXXXXXX")"
cleanup_temporary() {
  local resolved
  resolved="$(readlink -f "${temporary}" 2>/dev/null || true)"
  if [[ -n "${resolved}" && "${resolved}" == "${temporary_parent%/}/website-infrastructure-etcd."* ]]; then
    rm -rf -- "${resolved}"
  else
    printf 'Refusing to remove an unexpected temporary path.\n' >&2
  fi
}
trap cleanup_temporary EXIT
tar --extract --gzip --file="${archive_path}" --directory="${temporary}" \
  --no-same-owner --no-same-permissions \
  "${archive_root}/etcdctl" "${archive_root}/etcdutl"
staged_etcdctl="${temporary}/${archive_root}/etcdctl"
staged_etcdutl="${temporary}/${archive_root}/etcdutl"
[[ -f "${staged_etcdctl}" && ! -L "${staged_etcdctl}" ]] || die 'extracted etcdctl is not a regular file'
[[ -f "${staged_etcdutl}" && ! -L "${staged_etcdutl}" ]] || die 'extracted etcdutl is not a regular file'
chmod 0755 "${staged_etcdctl}" "${staged_etcdutl}"
[[ "$(tool_version "${staged_etcdctl}" etcdctl)" == "${ETCD_VERSION}" ]] || \
  die 'staged etcdctl version differs from versions.env'
[[ "$(tool_version "${staged_etcdutl}" etcdutl)" == "${ETCD_VERSION}" ]] || \
  die 'staged etcdutl version differs from versions.env'

for source_path in \
  "${repo_root}/bootstrap/pi/etcd-snapshot.sh" \
  "${repo_root}/bootstrap/pi/systemd/${service_name}" \
  "${repo_root}/bootstrap/pi/systemd/${timer_name}"; do
  [[ -f "${source_path}" && ! -L "${source_path}" ]] || die "managed recovery file is missing: ${source_path}"
done
bash -n "${repo_root}/bootstrap/pi/etcd-snapshot.sh" "${repo_root}/bootstrap/pi/install-recovery-tools.sh"
grep -Fqx 'ExecStart=/usr/local/sbin/website-infrastructure-etcd-snapshot --apply' \
  "${repo_root}/bootstrap/pi/systemd/${service_name}" || die 'snapshot service command contract is invalid'
grep -Fqx 'OnCalendar=*-*-* 00/6:00:00' \
  "${repo_root}/bootstrap/pi/systemd/${timer_name}" || die 'snapshot timer is not scheduled every six hours'

if [[ "${mode}" == "--check" ]]; then
  printf 'PASS official staged ARM64 etcd tools, exact versions, safe archive, and SSD backing verified. No change made.\n'
  exit 0
fi

backup_root="/var/backups/website-infrastructure/$(date -u +%Y%m%dT%H%M%SZ)-etcd-recovery-tools"
targets=(
  /usr/local/bin/etcdctl
  /usr/local/bin/etcdutl
  /usr/local/sbin/website-infrastructure-etcd-snapshot
  /etc/website-infrastructure/versions.env
  /etc/website-infrastructure/pi-decisions.env
  "/etc/systemd/system/${service_name}"
  "/etc/systemd/system/${timer_name}"
)
old_timer_enabled=no
old_timer_active=no
snapshot_parent_preexisting=no
snapshot_dir_preexisting=no
config_dir_preexisting=no
[[ -d /var/backups/kubernetes && ! -L /var/backups/kubernetes ]] && snapshot_parent_preexisting=yes
[[ -d "${snapshot_dir}" && ! -L "${snapshot_dir}" ]] && snapshot_dir_preexisting=yes
[[ -d /etc/website-infrastructure && ! -L /etc/website-infrastructure ]] && config_dir_preexisting=yes
systemctl is-enabled --quiet "${timer_name}" 2>/dev/null && old_timer_enabled=yes || true
systemctl is-active --quiet "${timer_name}" 2>/dev/null && old_timer_active=yes || true

for target in "${targets[@]}"; do
  if [[ -e "${target}" || -L "${target}" ]]; then
    [[ -f "${target}" && ! -L "${target}" ]] || \
      die "managed install target is not a regular file: ${target}"
  fi
done
if [[ "${snapshot_dir_preexisting}" == yes ]]; then
  [[ "$(stat -c %u "${snapshot_dir}" 2>/dev/null || true)" == 0 ]] || \
    die 'existing snapshot directory must be owned by root'
  [[ "$(stat -c %a "${snapshot_dir}" 2>/dev/null || true)" == 700 ]] || \
    die 'existing snapshot directory must have mode 0700'
  validate_backing "${snapshot_dir}"
fi

install -d -m 0700 "${backup_root}"
for target in "${targets[@]}"; do
  if [[ -e "${target}" || -L "${target}" ]]; then
    install -d -m 0700 "${backup_root}$(dirname "${target}")"
    cp -a -- "${target}" "${backup_root}${target}"
  fi
done

rollback_needed=yes
rollback() {
  local target
  [[ "${rollback_needed}" == yes ]] || return
  set +e
  systemctl disable --now "${timer_name}" >/dev/null 2>&1
  for target in "${targets[@]}"; do
    rm -f -- "${target}"
    if [[ -e "${backup_root}${target}" || -L "${backup_root}${target}" ]]; then
      install -d -m 0755 "$(dirname "${target}")"
      cp -a -- "${backup_root}${target}" "${target}"
    fi
  done
  if [[ "${snapshot_dir_preexisting}" != yes ]]; then
    rmdir -- "${snapshot_dir}" >/dev/null 2>&1 || true
  fi
  if [[ "${snapshot_parent_preexisting}" != yes ]]; then
    rmdir -- /var/backups/kubernetes >/dev/null 2>&1 || true
  fi
  if [[ "${config_dir_preexisting}" != yes ]]; then
    rmdir -- /etc/website-infrastructure >/dev/null 2>&1 || true
  fi
  systemctl daemon-reload >/dev/null 2>&1
  [[ "${old_timer_enabled}" != yes ]] || systemctl enable "${timer_name}" >/dev/null 2>&1
  [[ "${old_timer_active}" != yes ]] || systemctl start "${timer_name}" >/dev/null 2>&1
  printf 'Recovery-tools installation failed; managed files were restored from %s.\n' "${backup_root}" >&2
}
trap 'rollback; cleanup_temporary' EXIT

for standard_dir in /usr/local/bin /usr/local/sbin /etc/systemd/system; do
  [[ -d "${standard_dir}" && ! -L "${standard_dir}" ]] || \
    die "required system directory is absent or unsafe: ${standard_dir}"
done
if [[ -e /etc/website-infrastructure || -L /etc/website-infrastructure ]]; then
  [[ -d /etc/website-infrastructure && ! -L /etc/website-infrastructure ]] || \
    die '/etc/website-infrastructure is not a regular directory'
else
  install -d -m 0755 /etc/website-infrastructure
fi
if [[ "${snapshot_dir_preexisting}" != yes ]]; then
  install -d -m 0700 "${snapshot_dir}"
fi
validate_backing "${snapshot_dir}"
install -m 0755 "${staged_etcdctl}" /usr/local/bin/etcdctl
install -m 0755 "${staged_etcdutl}" /usr/local/bin/etcdutl
install -m 0755 "${repo_root}/bootstrap/pi/etcd-snapshot.sh" \
  /usr/local/sbin/website-infrastructure-etcd-snapshot
install -m 0644 "${repo_root}/versions.env" /etc/website-infrastructure/versions.env
install -m 0600 "${decisions_path}" /etc/website-infrastructure/pi-decisions.env
install -m 0644 "${repo_root}/bootstrap/pi/systemd/${service_name}" \
  "/etc/systemd/system/${service_name}"
install -m 0644 "${repo_root}/bootstrap/pi/systemd/${timer_name}" \
  "/etc/systemd/system/${timer_name}"

[[ "$(tool_version /usr/local/bin/etcdctl etcdctl)" == "${ETCD_VERSION}" ]] || \
  die 'installed etcdctl version verification failed'
[[ "$(tool_version /usr/local/bin/etcdutl etcdutl)" == "${ETCD_VERSION}" ]] || \
  die 'installed etcdutl version verification failed'
systemd-analyze verify "/etc/systemd/system/${service_name}" "/etc/systemd/system/${timer_name}" >/dev/null
systemctl daemon-reload
systemctl enable --now "${timer_name}"
systemctl is-enabled --quiet "${timer_name}" || die 'snapshot timer was not enabled'

rollback_needed=no
trap cleanup_temporary EXIT
printf 'PASS pinned etcdctl/etcdutl and the six-hour snapshot timer were installed.\n'
printf 'Recovery backup: %s\n' "${backup_root}"
printf 'The timer does not copy or encrypt snapshots off-device; that remains a manual external step.\n'
