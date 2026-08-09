#!/usr/bin/env bash
# Collect read-only Pi evidence for the human bootstrap review without placing
# raw host identities, addresses, or firewall contents in a shareable report.
set -euo pipefail

# Exit status is part of the evidence contract: 0 means every selected probe
# completed, 2 is an invocation/prerequisite error, and 3 means the report is
# incomplete because at least one probe failed or remained unknown/skipped.
readonly probe_timeout_seconds=15
readonly max_private_probe_bytes=$((8 * 1024 * 1024))
probe_success_count=0
probe_failure_count=0
probe_unknown_count=0

# No-argument behavior is fail-closed and local-only. Egress is a separate,
# explicit phase after the operator has proved the intended VPN/routing path.
discovery_mode=local-only
usage() {
  printf 'Usage: %s [--local-only|--with-egress]\n' "$0" >&2
  exit 2
}

case "$#" in
  0)
    ;;
  1)
    case "$1" in
      --local-only) discovery_mode=local-only ;;
      --with-egress) discovery_mode=with-egress ;;
      *) usage ;;
    esac
    ;;
  *)
    usage
    ;;
esac

# Resolve the repository once so discovery always uses the reviewed redactor
# and fingerprint implementation from the same checkout.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
redactor="${repo_root}/scripts/redact_inventory.py"
# Private workload identities live only in this local mode-0600 contract. The
# report refers to entries by index so a shareable discovery run never names
# an operator's protected services.
protected_services_path="${PROTECTED_SERVICES_PATH:-${repo_root}/bootstrap/pi/protected-services.env.local}"

if [[ "$(uname -s)" != Linux ]]; then
  printf 'This read-only inventory must run on the target Linux Pi.\n' >&2
  exit 2
fi
for required_command in chmod grep head mktemp python3 rm sed sha256sum timeout wc; do
  command -v "${required_command}" >/dev/null 2>&1 || {
    printf '%s is required for bounded, private discovery.\n' "${required_command}" >&2
    exit 2
  }
done

# A single private scratch file bounds sensitive command output before it is
# reduced to counts and a digest. It is mode 0600 and removed on every exit.
private_probe_file="$(mktemp)"
chmod 0600 "${private_probe_file}"
# Invoked by the EXIT trap below; ShellCheck cannot follow trap callbacks.
# shellcheck disable=SC2329
cleanup_private_probe_file() {
  rm -f -- "${private_probe_file}" || true
}
trap cleanup_private_probe_file EXIT
trap 'exit 130' HUP INT TERM

# section keeps the report readable when a person compares discovery runs.
section() { printf '\n## %s\n' "$1"; }

record_success() { probe_success_count=$((probe_success_count + 1)); }
record_failure() { probe_failure_count=$((probe_failure_count + 1)); }
record_unknown() { probe_unknown_count=$((probe_unknown_count + 1)); }

# timeout is mandatory above, so every external probe has a hard wall-clock
# bound even when a utility, device, or privileged read becomes unresponsive.
run_bounded() {
  timeout --signal=TERM --kill-after=2s "${probe_timeout_seconds}s" "$@"
}

# Bound sensitive output as it is produced, rather than checking its size only
# after a broken or hostile probe has already consumed arbitrary disk space.
# Reached both directly and through the dynamic capture dispatcher.
# shellcheck disable=SC2329
capture_private_output() {
  local byte_count producer_status reducer_status
  local -a pipeline_status
  : >"${private_probe_file}"
  set +e
  run_capture_command "$@" 2>/dev/null \
    | head -c "$((max_private_probe_bytes + 1))" >"${private_probe_file}"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  producer_status="${pipeline_status[0]:-1}"
  reducer_status="${pipeline_status[1]:-1}"
  byte_count="$(wc -c <"${private_probe_file}")"
  if [[ ! "${byte_count}" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if ((byte_count > max_private_probe_bytes)); then
    return 75
  fi
  if ((producer_status == 4 && reducer_status == 0)); then
    return 4
  fi
  if ((producer_status != 0 || reducer_status != 0)); then
    return 1
  fi
  return 0
}

# The shared Python redactor handles general identity/credential shapes. This
# final streaming guard covers short filesystem identifiers and BIP38 material
# that are easy to confuse with ordinary tokens: MBR PARTUUID 1234abcd-02,
# FAT/NTFS volume ID ABCD-1234, and 58-character 6P private-key payloads.
sanitize_stream() {
  python3 "${redactor}" | sed -E \
    -e 's/(PARTUUID=?)[0-9A-Fa-f]{8}-[0-9]{2}/\1[REDACTED_UUID]/g' \
    -e 's/(^|[^[:xdigit:]])[[:xdigit:]]{4}-[[:xdigit:]]{4}([^[:xdigit:]]|$)/\1[REDACTED_UUID]\2/g' \
    -e 's/(^|[^1-9A-HJ-NP-Za-km-z])6P[1-9A-HJ-NP-Za-km-z]{56}([^1-9A-HJ-NP-Za-km-z]|$)/\1[REDACTED_PRIVATE_KEY]\2/g'
}

# Shell functions below own their internal timeout because GNU timeout cannot
# invoke a function directly. Ordinary probe commands are bounded here.
run_capture_command() {
  if [[ "$(type -t "$1" || true)" == function ]]; then
    "$@"
  else
    run_bounded "$@"
  fi
}

# Filter one bounded producer while treating grep's no-match status as a valid
# empty result. The producer and reducer statuses remain separate so a failed
# inventory command can never masquerade as an empty inventory.
# Passed by name to capture; ShellCheck cannot resolve that dispatch.
# shellcheck disable=SC2329
filter_allow_empty() {
  local filter_status pattern producer_status
  local -a pipeline_status
  pattern="$1"
  shift
  if ! command -v "$1" >/dev/null 2>&1; then
    return 4
  fi
  set +e
  run_bounded "$@" 2>/dev/null | grep -E -- "${pattern}"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  producer_status="${pipeline_status[0]:-1}"
  filter_status="${pipeline_status[1]:-1}"
  if ((producer_status != 0 || (filter_status != 0 && filter_status != 1))); then
    return 1
  fi
  return 0
}

# capture sends every command result through the redactor before it can reach
# stdout; a missing probe is recorded as uncertainty instead of aborting later
# independent evidence collection.
capture() {
  local command_status label sanitizer_status
  local -a pipeline_status
  label="$1"
  shift
  printf '\n### %s\n' "${label}"
  if [[ "$(type -t "$1" || true)" != function ]] && ! command -v "$1" >/dev/null 2>&1; then
    printf 'probe_status=UNKNOWN reason=command-unavailable\n'
    record_unknown
    return 0
  fi
  set +e
  run_capture_command "$@" 2>&1 | sanitize_stream
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  command_status="${pipeline_status[0]:-1}"
  sanitizer_status="${pipeline_status[1]:-1}"
  if ((sanitizer_status != 0)); then
    printf 'probe_status=FAIL reason=sanitizer\n'
    record_failure
  elif ((command_status == 0)); then
    record_success
  elif ((command_status == 4)); then
    printf 'probe_status=UNKNOWN reason=command-unavailable\n'
    record_unknown
  else
    printf 'probe_status=FAIL reason=nonzero-or-timeout\n'
    record_failure
  fi
  return 0
}

# fingerprint_stdout proves whether sensitive command output changed while
# disclosing only its status and SHA-256, which is enough to bind later review.
# Passed by name to capture; ShellCheck cannot resolve that dispatch.
# shellcheck disable=SC2329
fingerprint_stdout() {
  local byte_count capture_status line_count output_sha256
  if [[ "$(type -t "$1" || true)" != function ]] && ! command -v "$1" >/dev/null 2>&1; then
    printf 'status=UNKNOWN command=%s reason=command-unavailable\n' "$1"
    return 4
  fi
  if capture_private_output "$@"; then
    capture_status=0
  else
    capture_status=$?
  fi
  if ((capture_status == 75)); then
    printf 'status=FAIL command=%s reason=output-limit\n' "$1"
    return 1
  elif ((capture_status == 4)); then
    printf 'status=UNKNOWN command=%s reason=command-unavailable\n' "$1"
    return 4
  elif ((capture_status != 0)); then
    printf 'status=FAIL command=%s reason=nonzero-or-timeout\n' "$1"
    return 1
  fi
  byte_count="$(wc -c <"${private_probe_file}")"
  line_count="$(wc -l <"${private_probe_file}")"
  output_sha256="$(sha256sum "${private_probe_file}" | sed -E 's/[[:space:]].*$//')"
  if [[ ! "${output_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'status=FAIL command=%s reason=digest\n' "$1"
    return 1
  fi
  if ((byte_count == 0)); then
    printf 'status=OK_EMPTY command=%s\n' "$1"
  else
    printf 'status=OK command=%s\n' "$1"
  fi
  printf 'line_count=%s\nbyte_count=%s\nsha256=%s\n' \
    "${line_count}" "${byte_count}" "${output_sha256}"
}

# nft_structure emits only aggregate counts and a digest. Table/chain names and
# policy text remain exclusively in the private scratch file and never reach
# the shareable report, even before redaction.
# Passed by name to capture; ShellCheck cannot resolve that dispatch.
# shellcheck disable=SC2329
nft_structure() {
  local byte_count capture_status chain_count hook_count ruleset_sha256 table_count
  if ! command -v sudo >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1; then
    printf 'status=UNKNOWN command=nft-list-ruleset reason=command-unavailable\n'
    return 4
  fi
  if capture_private_output sudo -n nft list ruleset; then
    capture_status=0
  else
    capture_status=$?
  fi
  if ((capture_status == 75)); then
    printf 'status=FAIL command=nft-list-ruleset reason=output-limit\n'
    return 1
  elif ((capture_status != 0)); then
    printf 'status=FAIL command=nft-list-ruleset reason=nonzero-or-timeout\n'
    return 1
  fi
  byte_count="$(wc -c <"${private_probe_file}")"
  table_count="$(grep -Ec '^[[:space:]]*table[[:space:]]' "${private_probe_file}" || true)"
  chain_count="$(grep -Ec '^[[:space:]]*chain[[:space:]]' "${private_probe_file}" || true)"
  hook_count="$(grep -Ec '[[:space:]]hook[[:space:]]' "${private_probe_file}" || true)"
  ruleset_sha256="$(sha256sum "${private_probe_file}" | sed -E 's/[[:space:]].*$//')"
  if [[ ! "${ruleset_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'status=FAIL command=nft-list-ruleset reason=digest\n'
    return 1
  fi
  if ((byte_count == 0)); then
    printf 'status=OK_EMPTY command=nft-list-ruleset\n'
  else
    printf 'status=OK command=nft-list-ruleset\n'
  fi
  printf 'table_count=%s\nchain_count=%s\nhook_count=%s\nbyte_count=%s\nsha256=%s\n' \
    "${table_count}" "${chain_count}" "${hook_count}" "${byte_count}" "${ruleset_sha256}"
}

# A mount's filesystem type is useful and intentionally allowlisted. Source,
# target resolution, UUIDs, options, and paths are separately hashed.
# Passed by name to capture; ShellCheck cannot resolve that dispatch.
# shellcheck disable=SC2329
mount_type_summary() {
  local filesystem_type
  if ! command -v findmnt >/dev/null 2>&1; then
    printf 'status=UNKNOWN reason=findmnt-unavailable\n'
    return 4
  fi
  if ! filesystem_type="$(run_bounded findmnt -T "$1" -n -o FSTYPE 2>/dev/null)"; then
    printf 'status=FAIL reason=findmnt\n'
    return 1
  fi
  if [[ ! "${filesystem_type}" =~ ^[A-Za-z0-9_.+-]+$ ]]; then
    printf 'status=FAIL reason=unexpected-filesystem-type\n'
    return 1
  fi
  printf 'status=OK filesystem_type=%s\n' "${filesystem_type}"
}

# SMART device paths are private. Enumerate them into the scratch file and
# report only an index and the allowlisted health result for each disk.
# Passed by name to capture; ShellCheck cannot resolve that dispatch.
# shellcheck disable=SC2329
smart_health_summary() {
  local capture_status device health index=0
  for smart_command in grep lsblk smartctl sudo; do
    if ! command -v "${smart_command}" >/dev/null 2>&1; then
      printf 'status=UNKNOWN reason=command-unavailable\n'
      return 4
    fi
  done
  if capture_private_output lsblk -dpno NAME,TYPE; then
    capture_status=0
  else
    capture_status=$?
  fi
  if ((capture_status != 0)); then
    printf 'status=FAIL reason=disk-enumeration-or-output-limit\n'
    return 1
  fi
  while read -r device _type; do
    [[ -n "${device}" ]] || continue
    index=$((index + 1))
    if ! health="$(run_bounded sudo -n smartctl -H "${device}" 2>/dev/null \
        | grep -E 'SMART overall-health|SMART Health Status')"; then
      printf 'disk_index=%d health=UNKNOWN\n' "${index}"
      return 1
    fi
    if grep -Eqi 'PASSED|OK' <<<"${health}"; then
      printf 'disk_index=%d health=PASS\n' "${index}"
    else
      printf 'disk_index=%d health=FAIL\n' "${index}"
      return 1
    fi
  done < <(grep -E '[[:space:]]disk$' "${private_probe_file}")
  if ((index == 0)); then
    printf 'status=FAIL reason=no-disks-enumerated\n'
    return 1
  fi
  printf 'disk_count=%d\n' "${index}"
}

# run_external_egress_probes is called only by explicit --with-egress mode.
# Keeping every intentional network probe in one function makes the local-only
# boundary auditable and prevents a newly added probe from being partly gated.
run_external_egress_probes() {
  capture 'DNS resolution fingerprint' fingerprint_stdout getent ahosts region1.v2.argotunnel.com
  capture 'Cloudflare HTTPS egress fingerprint' fingerprint_stdout curl --fail --silent --show-error --head --max-time 10 https://www.cloudflare.com/cdn-cgi/trace
  if command -v nc >/dev/null 2>&1; then
    capture 'Cloudflare Tunnel TCP 7844 egress' fingerprint_stdout nc -vz -w 5 region1.v2.argotunnel.com 7844
  else
    printf '\n### Cloudflare Tunnel port 7844\nnc is unavailable; connector tests remain pending.\n'
    record_unknown
  fi
}

printf '# Pi read-only discovery (source-minimized and addresses redacted)\n'
printf 'generated_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'NOTICE: Manually review even this redacted output before saving or sharing it.\n'

section 'Operating system and capacity'
capture 'kernel' uname -srmo
capture 'architecture' uname -m
capture 'os-release' sh -c 'grep -E "^(NAME|VERSION|ID|VERSION_ID)=" /etc/os-release'
capture 'time synchronization' timedatectl show -p NTPSynchronized -p Timezone
capture 'CPU count' nproc
capture 'memory' free -h
capture 'swap (type and numeric usage only)' swapon --show=TYPE,SIZE,USED,PRIO --noheadings --bytes
capture 'relevant kernel command-line flags' sh -c 'tr " " "\n" </proc/cmdline | grep -E "^(cgroup|systemd[.]unified_cgroup_hierarchy|swapaccount|apparmor|selinux)" || true'

section 'Storage identity and health'
capture 'block topology count and fingerprint' fingerprint_stdout \
  lsblk -e7 -b -o NAME,SIZE,ROTA,TYPE,FSTYPE,TRAN
# Kubernetes state directories are checked individually because they can live
# on different media, and control-plane durability depends on the actual mount.
for target in / /var/lib/etcd /var/lib/containerd /var/lib/kubelet; do
  if [[ -e "${target}" ]]; then
    capture "reviewed target ${target} mount identity fingerprint" fingerprint_stdout \
      findmnt -T "${target}" -n -o TARGET,SOURCE,FSTYPE,UUID,PARTUUID,OPTIONS
    capture "reviewed target ${target} filesystem type" mount_type_summary "${target}"
    capture "capacity ${target} (bytes and percent only)" \
      df -B1 --output=size,used,avail,pcent "${target}"
  else
    printf '\n### reviewed target %s\nabsent\n' "${target}"
  fi
done
capture 'TRIM timer state' systemctl show --no-pager \
  --property=LoadState --property=ActiveState --property=UnitFileState -- fstrim.timer
if command -v smartctl >/dev/null 2>&1; then
  capture 'SMART health summary (device identities omitted)' smart_health_summary
else
  printf '\n### SMART health\nsmartctl is unavailable; health remains pending.\n'
  record_unknown
fi

section 'Kernel, cgroups, and runtime prerequisites'
capture 'cgroup filesystem' stat -fc %T /sys/fs/cgroup
capture 'cgroup controllers' cat /sys/fs/cgroup/cgroup.controllers
# This loop is a program for the child shell, which owns and expands $module.
# shellcheck disable=SC2016
capture 'reviewed kernel modules' sh -c 'for module in overlay br_netfilter vxlan wireguard; do if modinfo "$module" >/dev/null 2>&1; then echo "$module available"; else echo "$module unavailable"; fi; done'
capture 'loaded relevant modules' sh -c 'lsmod | grep -E "^(overlay|br_netfilter|vxlan|wireguard|nf_|ip_|xt_)" || true'
capture 'relevant sysctls' sysctl vm.overcommit_memory vm.panic_on_oom kernel.panic kernel.panic_on_oops kernel.keys.root_maxkeys kernel.keys.root_maxbytes net.ipv4.ip_forward net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables
if [[ -r /sys/kernel/btf/vmlinux ]]; then printf '\n### kernel BTF\navailable\n'; else printf '\n### kernel BTF\nunavailable\n'; fi
capture 'installed platform packages' filter_allow_empty \
  '^(containerd|runc|kubeadm|kubelet|kubectl|cri-tools|kubernetes-cni)[[:space:]]' \
  dpkg-query -W
# This loop is a program for the child shell, which owns and expands $binary.
# shellcheck disable=SC2016
capture 'relevant binary versions' sh -c 'for binary in containerd runc kubeadm kubelet kubectl crictl; do if command -v "$binary" >/dev/null 2>&1; then "$binary" --version 2>&1 | head -n1; else echo "$binary absent"; fi; done'
if command -v containerd >/dev/null 2>&1; then
  capture 'containerd configuration fingerprint' fingerprint_stdout containerd config dump
fi

section 'Interfaces, routing, listeners, and CNI decision inputs'
# Network identities never reach the report. Counts and hashes support local
# comparison while unredacted review remains a separate, private operator step.
capture 'interface inventory fingerprint' fingerprint_stdout ip -details link show
capture 'IPv4 address inventory fingerprint' fingerprint_stdout ip -4 address show
capture 'IPv4 route inventory fingerprint' fingerprint_stdout ip -4 route show table all
capture 'IPv4 policy-rule inventory fingerprint' fingerprint_stdout ip -4 rule show
capture 'VPN tunnel interface inventory fingerprint' fingerprint_stdout \
  wg show interfaces
capture 'TCP/UDP listener inventory fingerprint (no process identities)' \
  fingerprint_stdout ss -lntu
capture 'local CRI socket inventory fingerprint' fingerprint_stdout \
  filter_allow_empty 'containerd|crio|cri-dockerd' ss -lx
capture 'IPv4 iptables implementation' iptables --version
capture 'IPv6 iptables implementation' ip6tables --version
capture 'nftables implementation' nft --version
capture 'nft structure counts and fingerprint' nft_structure
capture 'nft ruleset fingerprint' fingerprint_stdout sudo -n nft list ruleset
capture 'IPv4 iptables rules fingerprint' fingerprint_stdout sudo -n iptables-save
capture 'IPv6 iptables rules fingerprint' fingerprint_stdout sudo -n ip6tables-save
capture 'review-binding route and firewall fingerprints' bash "${repo_root}/scripts/fingerprint_pi_state.sh"
if [[ "${discovery_mode}" == with-egress ]]; then
  run_external_egress_probes
else
  printf '\n### External egress probes\n'
  printf 'external_egress_probes=SKIPPED_LOCAL_ONLY\n'
fi
if [[ "${discovery_mode}" == local-only ]]; then
  record_unknown
fi

section 'Protected host contract and existing platform state'
# Complete service inventories are hashed instead of filtered by committed
# workload names. The hashes detect drift while local review and the ignored
# protected-host contract retains the private active/inactive/archive identities
# needed by preflight.
capture 'running service inventory fingerprint' fingerprint_stdout \
  systemctl --type=service --state=running --no-pager --no-legend
capture 'service unit-file inventory fingerprint' fingerprint_stdout \
  systemctl list-unit-files --no-pager --no-legend

# The shared validator owns file/type/mode/schema checks and the indexed live
# active/inactive/archive diagnostics. Counts are derived only after validation;
# no declared value or archive entry is printed, enumerated, or hashed here.
if [[ ! -e "${protected_services_path}" && ! -L "${protected_services_path}" ]]; then
  printf 'protected_host_contract=PENDING_LOCAL_REVIEW\n'
  printf 'NOTICE: bootstrap preflight remains blocked until the private protected-host contract is reviewed.\n'
  record_unknown
elif run_bounded python3 "${repo_root}/scripts/validate_protected_host_contract.py" \
    "${protected_services_path}" --check-live >/dev/null 2>&1; then
  protected_active_count="$(grep -Ec '^PROTECTED_SYSTEMD_UNIT=' "${protected_services_path}" || true)"
  protected_legacy_count="$(grep -Ec '^PROTECTED_LEGACY_SYSTEMD_UNIT=' "${protected_services_path}" || true)"
  protected_archive_count="$(grep -Ec '^PROTECTED_LEGACY_ARCHIVE_ROOT=' "${protected_services_path}" || true)"
  printf 'protected_host_contract=REVIEWED active_unit_count=%d inactive_legacy_unit_count=%d archive_root_count=%d\n' \
    "${protected_active_count}" "${protected_legacy_count}" "${protected_archive_count}"
  record_success
else
  printf 'protected_host_contract=INVALID\n'
  printf 'NOTICE: bootstrap preflight remains blocked until the private protected-host contract is valid.\n'
  record_failure
fi
for path in /etc/kubernetes /var/lib/etcd /var/lib/kubelet /etc/cni/net.d /etc/containerd /var/lib/containerd /etc/rancher/k3s /var/lib/rancher/k3s /etc/cloudflared /var/lib/docker; do
  if [[ -e "${path}" ]]; then
    printf 'present: %s\n' "${path}"
  else
    printf 'absent: %s\n' "${path}"
  fi
done

printf '\nDiscovery made no persistent intentional changes. Use unredacted local inspection to fill\n'
printf 'the ignored decision files; never infer CNI or kube-proxy compatibility from\n'
printf 'this shareable report alone. Preserve VPN, firewall, and the reviewed protected-host contract.\n'

printf '\n## Machine-readable completeness\n'
printf 'discovery_probe_success_count=%d\n' "${probe_success_count}"
printf 'discovery_probe_failure_count=%d\n' "${probe_failure_count}"
printf 'discovery_probe_unknown_count=%d\n' "${probe_unknown_count}"
if ((probe_failure_count == 0 && probe_unknown_count == 0)); then
  printf 'discovery_completeness=COMPLETE\n'
  printf 'discovery_exit_code=0\n'
  exit 0
fi
printf 'discovery_completeness=INCOMPLETE\n'
printf 'discovery_exit_code=3\n'
exit 3
