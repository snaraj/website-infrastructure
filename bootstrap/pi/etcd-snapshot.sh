#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'FAIL %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../.." 2>/dev/null && pwd -P || true)"
if [[ -n "${WEBSITE_INFRA_VERSIONS_FILE:-}" ]]; then
  versions_path="${WEBSITE_INFRA_VERSIONS_FILE}"
elif [[ -r "${repo_root}/versions.env" ]]; then
  versions_path="${repo_root}/versions.env"
else
  versions_path=/etc/website-infrastructure/versions.env
fi
[[ -f "${versions_path}" && ! -L "${versions_path}" ]] || \
  die "trusted versions file is unavailable: ${versions_path}"
[[ "$(stat -c %a "${versions_path}" 2>/dev/null || true)" == 644 ]] || \
  die 'trusted versions file must have mode 0644'
if [[ "${versions_path}" == /etc/* ]]; then
  [[ "$(stat -c %u "${versions_path}" 2>/dev/null || true)" == 0 ]] || \
    die 'installed versions file must be owned by root'
fi
if grep -Ev '^(#|$|[A-Z0-9_]+=[A-Za-z0-9._:/@+-]+)$' "${versions_path}" >/dev/null; then
  die 'trusted versions file contains unsupported shell syntax'
fi
# shellcheck disable=SC1090
source "${versions_path}"

mode="${1:---check}"
[[ "${mode}" == "--check" || "${mode}" == "--apply" ]] || \
  die "usage: $0 [--check|--apply]"
if [[ "${mode}" == "--apply" ]]; then
  [[ "${EUID}" -eq 0 ]] || die 'apply mode requires root'
  [[ "${CONFIRM_ETCD_SNAPSHOT:-}" == "create-reviewed-stacked-etcd-snapshot" ]] || \
    die 'exact snapshot acknowledgement is missing'
fi

snapshot_dir=/var/backups/kubernetes/etcd
if [[ -n "${PI_DECISIONS_PATH:-}" ]]; then
  decisions_path="${PI_DECISIONS_PATH}"
elif [[ -f "${repo_root}/bootstrap/pi/decisions.env.local" ]]; then
  decisions_path="${repo_root}/bootstrap/pi/decisions.env.local"
else
  decisions_path=/etc/website-infrastructure/pi-decisions.env
fi
etcdctl_path=/usr/local/bin/etcdctl
etcdutl_path=/usr/local/bin/etcdutl
endpoint=https://127.0.0.1:2379
ca_path=/etc/kubernetes/pki/etcd/ca.crt
cert_path=/etc/kubernetes/pki/etcd/healthcheck-client.crt
key_path=/etc/kubernetes/pki/etcd/healthcheck-client.key

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
  if [[ "${decisions_path}" == /etc/* ]]; then
    [[ "$(stat -c %u "${decisions_path}" 2>/dev/null || true)" == 0 ]] || \
      die 'installed Pi decisions file must be owned by root'
  fi
  for key in DECISION_STATUS EXPECTED_SSD_FILESYSTEM_UUID EXPECTED_SSD_MOUNT_SOURCE; do
    count="$(grep -Ec "^${key}=" "${decisions_path}" || true)"
    [[ "${count}" == 1 ]] || die "decision ${key} must occur exactly once"
  done
  [[ "$(decision DECISION_STATUS)" == approved-after-pi-discovery ]] || \
    die 'Pi decisions are not approved after discovery'
  if grep -E '^(EXPECTED_SSD_FILESYSTEM_UUID|EXPECTED_SSD_MOUNT_SOURCE)=($|REPLACE_|UNRESOLVED)' \
    "${decisions_path}" >/dev/null; then
    die 'reviewed SSD identity is unresolved'
  fi
  if grep -E '^(DECISION_STATUS|EXPECTED_SSD_FILESYSTEM_UUID|EXPECTED_SSD_MOUNT_SOURCE)=.*[[:space:]]' \
    "${decisions_path}" >/dev/null; then
    die 'reviewed SSD decisions contain whitespace'
  fi
}

validate_ssd_backing() {
  local target="$1" actual_uuid actual_source mount_options
  [[ -d "${target}" && ! -L "${target}" ]] || die "snapshot directory is absent or unsafe: ${target}"
  actual_uuid="$(findmnt -T "${target}" -n -o UUID 2>/dev/null || true)"
  actual_source="$(findmnt -T "${target}" -n -o SOURCE 2>/dev/null | sed 's/\[.*$//' || true)"
  mount_options="$(findmnt -T "${target}" -n -o OPTIONS 2>/dev/null || true)"
  [[ -n "${actual_uuid}" && "${actual_uuid}" == "$(decision EXPECTED_SSD_FILESYSTEM_UUID)" ]] || \
    die 'snapshot filesystem UUID differs from the reviewed SSD'
  [[ -n "${actual_source}" && "${actual_source}" == "$(decision EXPECTED_SSD_MOUNT_SOURCE)" ]] || \
    die 'snapshot mount source differs from the reviewed SSD'
  [[ ",${mount_options}," != *,ro,* ]] || die 'snapshot filesystem is read-only'
}

tool_version() {
  local tool_path="$1" label="$2"
  "${tool_path}" version 2>/dev/null | \
    awk -F': ' -v wanted="${label} version" '$1 == wanted {print $2; exit}'
}

validate_tools() {
  local path
  [[ "${ETCD_VERSION:-}" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] || \
    die 'ETCD_VERSION is unresolved or malformed'
  [[ "${ETCD_TOOLS_ARM64_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || \
    die 'ETCD_TOOLS_ARM64_SHA256 is unresolved or malformed'
  [[ -x "${etcdctl_path}" && ! -L "${etcdctl_path}" ]] || die 'pinned etcdctl is not installed as a regular executable'
  [[ -x "${etcdutl_path}" && ! -L "${etcdutl_path}" ]] || die 'pinned etcdutl is not installed as a regular executable'
  for path in "${etcdctl_path}" "${etcdutl_path}"; do
    [[ "$(stat -c %u "${path}" 2>/dev/null || true)" == 0 ]] || \
      die "installed tool must be owned by root: ${path}"
    [[ "$(stat -c %a "${path}" 2>/dev/null || true)" == 755 ]] || \
      die "installed tool must have mode 0755: ${path}"
  done
  [[ "$(tool_version "${etcdctl_path}" etcdctl)" == "${ETCD_VERSION}" ]] || \
    die 'installed etcdctl version differs from versions.env'
  [[ "$(tool_version "${etcdutl_path}" etcdutl)" == "${ETCD_VERSION}" ]] || \
    die 'installed etcdutl version differs from versions.env'
}

validate_tls_files() {
  local path owner mode_bits
  for path in "${ca_path}" "${cert_path}" "${key_path}"; do
    [[ -f "${path}" && ! -L "${path}" && -r "${path}" ]] || \
      die "required local etcd TLS file is unavailable: ${path}"
    owner="$(stat -c %u "${path}" 2>/dev/null || true)"
    [[ "${owner}" == 0 ]] || die "local etcd TLS file must be owned by root: ${path}"
  done
  mode_bits="$(stat -c %a "${key_path}" 2>/dev/null || true)"
  [[ "${mode_bits}" == 600 ]] || die 'local etcd healthcheck private key must have mode 0600'
}

validate_snapshot_files() {
  local enforce_retention="$1" entry name owner mode_bits count=0
  shopt -s nullglob dotglob
  for entry in "${snapshot_dir}"/*; do
    name="$(basename -- "${entry}")"
    [[ "${name}" =~ ^snapshot-[0-9]{8}T[0-9]{6}Z[.]db$ ]] || \
      die "unexpected entry in snapshot directory: ${name}"
    [[ -f "${entry}" && ! -L "${entry}" ]] || die "snapshot entry is not a regular file: ${name}"
    owner="$(stat -c %u "${entry}" 2>/dev/null || true)"
    mode_bits="$(stat -c %a "${entry}" 2>/dev/null || true)"
    [[ "${owner}" == 0 ]] || die "snapshot is not owned by root: ${name}"
    [[ "${mode_bits}" == 600 ]] || die "snapshot mode is not 0600: ${name}"
    if ! "${etcdutl_path}" --write-out=json snapshot status "${entry}" >/dev/null 2>&1; then
      die "snapshot verification failed: ${name}"
    fi
    count=$((count + 1))
  done
  shopt -u nullglob dotglob
  if [[ "${enforce_retention}" == yes && "${count}" -gt 14 ]]; then
    die "snapshot retention exceeds 14 files: ${count}"
  fi
}

for command_name in awk basename chmod date find findmnt flock grep mv rm sed sort stat; do
  require_command "${command_name}"
done
validate_decisions
validate_tools
validate_tls_files
validate_ssd_backing "${snapshot_dir}"
[[ "$(stat -c %u "${snapshot_dir}" 2>/dev/null || true)" == 0 ]] || \
  die 'snapshot directory must be owned by root'
[[ "$(stat -c %a "${snapshot_dir}" 2>/dev/null || true)" == 700 ]] || \
  die 'snapshot directory must have mode 0700'

if ! ETCDCTL_API=3 "${etcdctl_path}" \
  --endpoints="${endpoint}" \
  --dial-timeout=5s \
  --command-timeout=15s \
  --cacert="${ca_path}" \
  --cert="${cert_path}" \
  --key="${key_path}" \
  endpoint health >/dev/null 2>&1; then
  die 'local stacked-etcd health check failed'
fi

if [[ "${mode}" == "--check" ]]; then
  validate_snapshot_files yes
  printf 'PASS pinned etcd tools, local TLS endpoint, SSD backing, and retained snapshots verified. No change made.\n'
  exit 0
fi

umask 077
exec 9>/run/lock/website-infrastructure-etcd-snapshot.lock
flock -n 9 || die 'another etcd snapshot operation is already running'
validate_snapshot_files no

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
snapshot_name="snapshot-${timestamp}.db"
snapshot_path="${snapshot_dir}/${snapshot_name}"
partial_path="${snapshot_dir}/.${snapshot_name}.partial.$$"
[[ ! -e "${snapshot_path}" && ! -L "${snapshot_path}" ]] || \
  die "snapshot target already exists: ${snapshot_name}"
cleanup() {
  rm -f -- "${partial_path}" "${partial_path}.part"
}
trap cleanup EXIT

if ! ETCDCTL_API=3 "${etcdctl_path}" \
  --endpoints="${endpoint}" \
  --dial-timeout=5s \
  --command-timeout=5m \
  --cacert="${ca_path}" \
  --cert="${cert_path}" \
  --key="${key_path}" \
  snapshot save "${partial_path}" >/dev/null 2>&1; then
  die 'etcd snapshot save failed'
fi
chmod 0600 "${partial_path}"
if ! "${etcdutl_path}" --write-out=json snapshot status "${partial_path}" >/dev/null 2>&1; then
  die 'new etcd snapshot failed verification'
fi
mv -T -- "${partial_path}" "${snapshot_path}"
if ! "${etcdutl_path}" --write-out=json snapshot status "${snapshot_path}" >/dev/null 2>&1; then
  rm -f -- "${snapshot_path}"
  die 'installed etcd snapshot failed final verification and was removed'
fi

mapfile -t retained_names < <(
  find "${snapshot_dir}" -mindepth 1 -maxdepth 1 -type f \
    -name 'snapshot-????????T??????Z.db' -printf '%f\n' | LC_ALL=C sort -r
)
for ((index = 14; index < ${#retained_names[@]}; index++)); do
  old_name="${retained_names[index]}"
  [[ "${old_name}" =~ ^snapshot-[0-9]{8}T[0-9]{6}Z[.]db$ ]] || \
    die 'retention selected an unsafe filename'
  old_path="${snapshot_dir}/${old_name}"
  [[ -f "${old_path}" && ! -L "${old_path}" ]] || die 'retention target changed unexpectedly'
  rm -f -- "${old_path}"
done
validate_snapshot_files yes
trap - EXIT
printf 'PASS stacked-etcd snapshot saved, verified, and retained locally: %s\n' "${snapshot_path}"
printf 'Manual external step still required: copy the snapshot encrypted off-device and verify that copy.\n'
