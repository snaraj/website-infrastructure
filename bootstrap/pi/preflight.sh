#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# versions.env is anchored to the resolved repository root; ShellCheck cannot
# follow that dynamic but trusted path when CI intentionally runs without -x.
# shellcheck disable=SC1091
source "${repo_root}/versions.env"
phase=inspect
if [[ "${1:-}" == "--phase" && -n "${2:-}" ]]; then
  phase="$2"
elif [[ $# -ne 0 ]]; then
  printf 'Usage: %s [--phase inspect|install|init]\n' "$0" >&2
  exit 2
fi
[[ "${phase}" =~ ^(inspect|install|init)$ ]] || { printf 'Unknown phase: %s\n' "${phase}" >&2; exit 2; }

config_path="${KUBEADM_CONFIG_PATH:-${repo_root}/bootstrap/pi/kubeadm-config.yaml.local}"
encryption_path="${ENCRYPTION_CONFIG_PATH:-${repo_root}/bootstrap/pi/encryption-config.yaml.local}"
decisions_path="${PI_DECISIONS_PATH:-${repo_root}/bootstrap/pi/decisions.env.local}"
cni_path="${CNI_MANIFEST_PATH:-${repo_root}/bootstrap/pi/cni-manifest.local.yaml}"
images_lock_path="${IMAGES_LOCK_PATH:-${repo_root}/bootstrap/pi/images.lock.local}"
protected_services_path="${PROTECTED_SERVICES_PATH:-${repo_root}/bootstrap/pi/protected-services.env.local}"
failures=0

pass() { printf 'PASS %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*" >&2; failures=$((failures + 1)); }

require_command() {
  if command -v "$1" >/dev/null 2>&1; then
    pass "$1 present"
  else
    fail "$1 missing"
  fi
}

require_sysctl() {
  local name="$1"
  local expected="$2"
  local actual
  actual="$(sysctl -n "${name}" 2>/dev/null || true)"
  if [[ "${actual}" == "${expected}" ]]; then
    pass "sysctl ${name}=${expected}"
  else
    fail "sysctl ${name} must be ${expected}, found ${actual:-unavailable}"
  fi
}

require_module_available() {
  local module="$1"
  if [[ -d "/sys/module/${module}" ]] || modinfo "${module}" >/dev/null 2>&1; then
    pass "${module} module is loaded or available"
  else
    fail "${module} module is unavailable"
  fi
}

decision() {
  awk -F= -v key="$1" '$1 == key {sub(/^[^=]*=/, ""); print}' "${decisions_path}"
}

check_mode_0600() {
  local path="$1"
  local mode
  mode="$(stat -c %a "${path}" 2>/dev/null || true)"
  if [[ "${mode}" == "600" ]]; then
    pass "${path} mode is 0600"
  else
    fail "${path} mode must be 0600, found ${mode:-unavailable}"
  fi
}

if [[ "$(uname -s)" == Linux ]]; then
  pass 'operating system is Linux'
else
  fail 'this preflight must run on the target Linux host'
fi
if [[ "$(uname -m)" =~ ^(aarch64|arm64)$ ]]; then
  pass 'architecture is ARM64'
else
  fail "architecture is $(uname -m), expected ARM64"
fi

for command_name in awk base64 conntrack df find findmnt grep ip lsblk modinfo sed sha256sum socat ss stat swapon sysctl systemctl tar tr wc python3; do
  require_command "${command_name}"
done

required_decisions=(
  DECISION_STATUS EXPECTED_OS_ID EXPECTED_OS_VERSION_ID EXPECTED_KERNEL_RELEASE
  EXPECTED_SSD_FILESYSTEM_UUID EXPECTED_SSD_MOUNT_SOURCE PI_LAN_INTERFACE
  CONTAINERD_SOURCE CONTAINERD_VERSION PI_STABLE_PRIVATE_IP POD_CIDR SERVICE_CIDR
  KUBE_PROXY_OPERATION KUBE_PROXY_MODE CNI_PROVIDER
  CNI_VERSION CNI_DATAPLANE CNI_TUNNEL_MODE CNI_MTU CNI_HOST_NETWORK_REQUIREMENTS
  CNI_MANIFEST_SHA256 CNI_NETWORK_POLICY_PROVEN VPN_FIREWALL_COMPATIBILITY_REVIEWED
  DISCOVERY_IP_RULES_SHA256 DISCOVERY_IP_ROUTES_SHA256 DISCOVERY_NFT_RULESET_SHA256
  DISCOVERY_IPTABLES4_SHA256 DISCOVERY_IPTABLES6_SHA256
  ENCRYPTION_KEY_BACKUP_PROVEN RECOVERY_TOOLS_PROVEN PERSISTENT_HOST_CONFIG_PROVEN
)
if [[ ! -f "${decisions_path}" ]]; then
  fail "reviewed decisions file is absent: ${decisions_path}"
else
  check_mode_0600 "${decisions_path}"
  if grep -Ev '^(#|$|[A-Z0-9_]+=[^[:space:]]+)$' "${decisions_path}" | grep -q .; then
    fail 'decisions file contains a malformed non-comment line'
  fi
  if grep -Ev '^(#|$)' "${decisions_path}" | grep -Eq 'REPLACE_|UNRESOLVED|[[:space:]]'; then
    fail 'decisions file contains a sentinel or whitespace'
  fi
  for key in "${required_decisions[@]}"; do
    count="$(grep -Ec "^${key}=" "${decisions_path}" || true)"
    [[ "${count}" == 1 ]] || fail "decision ${key} must occur exactly once"
  done
  decision_line_count="$(grep -Ec '^[A-Z0-9_]+=' "${decisions_path}" || true)"
  [[ "${decision_line_count}" == "${#required_decisions[@]}" ]] || \
    fail 'decisions file must contain exactly the reviewed keys and no extras'
fi

if [[ -f "${decisions_path}" ]]; then
  status="$(decision DECISION_STATUS)"
  os_id="$(decision EXPECTED_OS_ID)"
  os_version="$(decision EXPECTED_OS_VERSION_ID)"
  expected_kernel="$(decision EXPECTED_KERNEL_RELEASE)"
  expected_uuid="$(decision EXPECTED_SSD_FILESYSTEM_UUID)"
  expected_source="$(decision EXPECTED_SSD_MOUNT_SOURCE)"
  containerd_source="$(decision CONTAINERD_SOURCE)"
  containerd_version_decision="$(decision CONTAINERD_VERSION)"
  lan_interface="$(decision PI_LAN_INTERFACE)"
  stable_ip="$(decision PI_STABLE_PRIVATE_IP)"
  pod_cidr="$(decision POD_CIDR)"
  service_cidr="$(decision SERVICE_CIDR)"
  proxy_operation="$(decision KUBE_PROXY_OPERATION)"
  proxy_mode="$(decision KUBE_PROXY_MODE)"
  cni_provider="$(decision CNI_PROVIDER)"
  cni_version="$(decision CNI_VERSION)"
  cni_dataplane="$(decision CNI_DATAPLANE)"
  cni_tunnel="$(decision CNI_TUNNEL_MODE)"
  cni_mtu="$(decision CNI_MTU)"
  cni_host_requirements="$(decision CNI_HOST_NETWORK_REQUIREMENTS)"
  cni_sha="$(decision CNI_MANIFEST_SHA256)"
  [[ "${status}" == approved-after-pi-discovery ]] || fail 'DECISION_STATUS is not approved-after-pi-discovery'
  [[ "${containerd_source}" == upstream-static ]] || fail 'CONTAINERD_SOURCE must be upstream-static after an explicit Pi ownership review'
  [[ "${containerd_version_decision}" == "${CONTAINERD_VERSION}" ]] || fail 'reviewed containerd version differs from versions.env'
  [[ "${proxy_operation}" == installed ]] || fail 'KUBE_PROXY_OPERATION must be installed; replacement is outside this contract'
  [[ "${proxy_mode}" =~ ^(iptables|nftables)$ ]] || fail 'KUBE_PROXY_MODE must be iptables or nftables'
  if [[ "${proxy_mode}" == nftables ]]; then
    require_command nft
    nft_version="$(nft --version 2>/dev/null | sed -nE 's/.*v([0-9]+)[.]([0-9]+)[.]([0-9]+).*/\1 \2 \3/p' || true)"
    read -r nft_major nft_minor nft_patch <<<"${nft_version}"
    if [[ "${nft_major:-}" =~ ^[0-9]+$ && "${nft_minor:-}" =~ ^[0-9]+$ && "${nft_patch:-}" =~ ^[0-9]+$ ]] && \
       (( nft_major > 1 || (nft_major == 1 && (nft_minor > 0 || (nft_minor == 0 && nft_patch >= 1))) )); then
      pass 'nft CLI is at least 1.0.1'
    else
      fail 'nftables kube-proxy mode requires nft CLI version 1.0.1 or newer'
    fi
    kernel_version="$(uname -r | sed -nE 's/^([0-9]+)[.]([0-9]+).*/\1 \2/p')"
    read -r kernel_major kernel_minor <<<"${kernel_version}"
    if [[ "${kernel_major:-}" =~ ^[0-9]+$ && "${kernel_minor:-}" =~ ^[0-9]+$ ]] && \
       (( kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 13) )); then
      pass 'kernel is at least 5.13 for nftables kube-proxy mode'
    else
      fail 'nftables kube-proxy mode requires kernel 5.13 or newer'
    fi
  else
    require_command iptables
  fi
  [[ "${cni_provider}" =~ ^(cilium|calico)$ ]] || fail 'CNI_PROVIDER must be cilium or calico'
  [[ "${cni_version}" =~ ^v?[0-9]+[.][0-9]+[.][0-9]+$ ]] || fail 'CNI_VERSION is not an exact semantic version'
  [[ "${cni_dataplane}" == kube-proxy ]] || fail 'CNI_DATAPLANE must be kube-proxy; replacement is outside this contract'
  if [[ "${cni_mtu}" =~ ^[0-9]+$ ]] && (( cni_mtu >= 576 && cni_mtu <= 9000 )); then
    :
  else
    fail 'CNI_MTU must be an integer from 576 through 9000'
  fi
  expected_cni_host_requirements=invalid
  case "${cni_provider}/${cni_tunnel}" in
    cilium/vxlan) expected_cni_host_requirements=udp:8472 ;;
    cilium/geneve) expected_cni_host_requirements=udp:6081 ;;
    cilium/native) expected_cni_host_requirements=none ;;
    calico/vxlan) expected_cni_host_requirements=udp:4789 ;;
    calico/ipip) expected_cni_host_requirements=ip-proto:4 ;;
    calico/bgp) expected_cni_host_requirements=tcp:179 ;;
    *) fail 'CNI provider/tunnel combination is outside the reviewed matrix' ;;
  esac
  [[ "${cni_host_requirements}" == "${expected_cni_host_requirements}" ]] || \
    fail 'CNI_HOST_NETWORK_REQUIREMENTS does not match the exact provider/tunnel matrix'
  [[ "${cni_sha}" =~ ^[0-9a-f]{64}$ ]] || fail 'CNI_MANIFEST_SHA256 is malformed'
  [[ "$(decision CNI_NETWORK_POLICY_PROVEN)" == yes ]] || fail 'NetworkPolicy support has not been approved'
  [[ "$(decision VPN_FIREWALL_COMPATIBILITY_REVIEWED)" == yes ]] || fail 'VPN/firewall compatibility review is incomplete'
  [[ "$(decision ENCRYPTION_KEY_BACKUP_PROVEN)" == yes ]] || fail 'separate encrypted backup of the API encryption key is unproven'
  [[ "$(decision RECOVERY_TOOLS_PROVEN)" == yes ]] || fail 'stacked-etcd recovery tools and runbook are unproven'
  [[ "$(decision PERSISTENT_HOST_CONFIG_PROVEN)" == yes ]] || fail 'persistent modules, sysctls, and swap state are unproven'

  if current_fingerprints="$(bash "${repo_root}/scripts/fingerprint_pi_state.sh" 2>/dev/null)"; then
    for fingerprint_key in \
      DISCOVERY_IP_RULES_SHA256 DISCOVERY_IP_ROUTES_SHA256 DISCOVERY_NFT_RULESET_SHA256 \
      DISCOVERY_IPTABLES4_SHA256 DISCOVERY_IPTABLES6_SHA256; do
      current_fingerprint="$(printf '%s\n' "${current_fingerprints}" | awk -F= -v key="${fingerprint_key}" '$1 == key {print $2}')"
      [[ "${current_fingerprint}" =~ ^[0-9a-f]{64}$ ]] || fail "current ${fingerprint_key} is unavailable"
      [[ "${current_fingerprint}" == "$(decision "${fingerprint_key}")" ]] || fail "${fingerprint_key} changed since reviewed discovery"
    done
  else
    fail 'unable to re-read exact routing and firewall fingerprints'
  fi

  actual_os_id="$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' /etc/os-release 2>/dev/null || true)"
  actual_os_version="$(awk -F= '$1 == "VERSION_ID" {gsub(/"/, "", $2); print $2}' /etc/os-release 2>/dev/null || true)"
  if [[ "${actual_os_id}" == "${os_id}" ]]; then
    pass 'OS ID matches the reviewed host'
  else
    fail 'OS ID changed since discovery'
  fi
  if [[ "${actual_os_version}" == "${os_version}" ]]; then
    pass 'OS version matches the reviewed host'
  else
    fail 'OS version changed since discovery'
  fi
  if [[ "$(uname -r)" == "${expected_kernel}" ]]; then
    pass 'kernel matches the reviewed host'
  else
    fail 'kernel changed since discovery'
  fi
  if ip link show dev "${lan_interface}" >/dev/null 2>&1; then
    pass 'reviewed LAN interface exists'
  else
    fail 'reviewed LAN interface is absent'
  fi
  if ip -4 -o address show dev "${lan_interface}" 2>/dev/null | awk '{print $4}' | grep -Eq "^${stable_ip//./[.]}(/|$)"; then
    pass 'stable private API address is assigned to the reviewed interface'
  else
    fail 'stable private API address is not assigned to the reviewed interface'
  fi
fi

if [[ -f "${config_path}" ]]; then
  check_mode_0600 "${config_path}"
  if grep -Eq 'REPLACE_|UNRESOLVED' "${config_path}"; then
    fail 'kubeadm config contains an unresolved sentinel'
  elif python3 "${repo_root}/scripts/validate_kubeadm_config.py" "${config_path}"; then
    pass 'kubeadm config matches the reviewed contract'
  else
    fail 'kubeadm config violates the reviewed contract'
  fi
  if [[ -f "${decisions_path}" ]]; then
    grep -Fq "advertiseAddress: ${stable_ip}" "${config_path}" || fail 'config advertise address differs from decisions'
    grep -Fq "podSubnet: ${pod_cidr}" "${config_path}" || fail 'config pod CIDR differs from decisions'
    grep -Fq "serviceSubnet: ${service_cidr}" "${config_path}" || fail 'config service CIDR differs from decisions'
    grep -Fq "mode: ${proxy_mode}" "${config_path}" || fail 'config kube-proxy mode differs from decisions'
    python3 "${repo_root}/scripts/validate_pi_network.py" "${config_path}" || fail 'live network overlap validation failed'
  fi
else
  fail "local kubeadm config is absent: ${config_path}"
fi

if [[ -f "${encryption_path}" ]]; then
  check_mode_0600 "${encryption_path}"
  if python3 "${repo_root}/scripts/validate_encryption_config.py" "${encryption_path}"; then
    pass 'encryption config matches the exact provider-order contract'
  else
    fail 'encryption config violates the exact provider-order contract'
  fi
else
  fail "local encryption config is absent: ${encryption_path}"
fi

memory_kib="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
if (( memory_kib >= 12000000 )); then
  pass 'at least 12 GiB memory is visible'
else
  fail 'less than 12 GiB memory is visible'
fi
if [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" == cgroup2fs ]] && grep -qw memory /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
  pass 'cgroup v2 memory controller is available'
else
  fail 'cgroup v2 memory controller is unavailable'
fi
require_module_available overlay
require_module_available br_netfilter
if [[ -f "${decisions_path}" && "${cni_provider:-}" == cilium ]]; then
  if [[ -r /sys/kernel/btf/vmlinux ]]; then
    pass 'kernel BTF is available for Cilium'
  else
    fail 'kernel BTF is unavailable for Cilium'
  fi
fi
if [[ -f "${decisions_path}" ]]; then
  case "${cni_tunnel:-}" in
    vxlan) require_module_available vxlan ;;
    geneve) require_module_available geneve ;;
    ipip) require_module_available ipip ;;
  esac
fi

if [[ -z "$(swapon --noheadings --show 2>/dev/null)" ]]; then
  pass 'swap is inactive'
else
  fail 'active swap found; do not disable it automatically'
fi
require_sysctl vm.overcommit_memory 1
require_sysctl vm.panic_on_oom 0
require_sysctl kernel.panic 10
require_sysctl kernel.panic_on_oops 1
require_sysctl kernel.keys.root_maxkeys 1000000
require_sysctl kernel.keys.root_maxbytes 25000000
require_sysctl net.ipv4.ip_forward 1
require_sysctl net.bridge.bridge-nf-call-iptables 1
require_sysctl net.bridge.bridge-nf-call-ip6tables 1

if [[ -f "${decisions_path}" ]]; then
  for target in /var/lib/etcd /var/lib/containerd /var/lib/kubelet; do
    if [[ ! -d "${target}" ]]; then
      fail "required SSD-backed directory is absent: ${target}"
      continue
    fi
    actual_uuid="$(findmnt -T "${target}" -no UUID 2>/dev/null || true)"
    actual_source="$(findmnt -T "${target}" -no SOURCE 2>/dev/null | sed 's/\[.*$//' || true)"
    [[ "${actual_uuid}" == "${expected_uuid}" ]] || fail "${target} filesystem UUID differs from the reviewed SSD"
    [[ "${actual_source}" == "${expected_source}" ]] || fail "${target} mount source differs from the reviewed SSD"
    available="$(df --output=avail -B1 "${target}" 2>/dev/null | tail -n1 | tr -d ' ' || true)"
    if [[ "${available}" =~ ^[0-9]+$ ]] && (( available >= 107374182400 )); then
      pass "${target} has at least 100 GiB free"
    else
      fail "${target} has less than 100 GiB free or capacity is unknown"
    fi
  done
fi

for port in 2379 2380 6443 10250 10257 10259; do
  if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
    fail "TCP port ${port} already has a listener"
  else
    pass "TCP port ${port} is unused"
  fi
done
if [[ -f "${decisions_path}" && "${cni_host_requirements:-none}" =~ ^(tcp|udp):([0-9]+)$ ]]; then
  cni_protocol="${BASH_REMATCH[1]}"
  cni_port="${BASH_REMATCH[2]}"
  if (( cni_port < 1 || cni_port > 65535 )); then
    fail 'reviewed CNI host-network port is out of range'
  elif [[ "${cni_protocol}" == tcp ]] && ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${cni_port}$"; then
    fail "reviewed CNI TCP port ${cni_port} already has a listener"
  elif [[ "${cni_protocol}" == udp ]] && ss -H -lun 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${cni_port}$"; then
    fail "reviewed CNI UDP port ${cni_port} already has a listener"
  else
    pass "reviewed CNI ${cni_protocol^^} port ${cni_port} is unused"
  fi
fi

for stale in /etc/rancher/k3s /var/lib/rancher/k3s /usr/local/bin/k3s; do
  [[ ! -e "${stale}" ]] || fail "stale K3s state requires a reviewed migration: ${stale}"
done

if [[ "${phase}" == install ]]; then
  for path in /etc/kubernetes /etc/cni/net.d /etc/containerd; do
    [[ ! -d "${path}" || -z "$(find "${path}" -mindepth 1 -print -quit 2>/dev/null)" ]] || fail "existing platform configuration found: ${path}"
  done
  for path in /var/lib/etcd /var/lib/kubelet /var/lib/containerd; do
    [[ -z "$(find "${path}" -mindepth 1 -print -quit 2>/dev/null)" ]] || fail "existing platform state found: ${path}"
  done
  for binary in containerd kubeadm kubelet kubectl; do
    command -v "${binary}" >/dev/null 2>&1 && fail "existing ${binary} binary found; import/upgrade is a separate procedure" || true
  done
elif [[ "${phase}" == init ]]; then
  if bash "${repo_root}/bootstrap/pi/host-prerequisites/verify-host-prerequisites.sh" --post-reboot; then
    pass 'persistent host prerequisites survived a separately proven reboot'
  else
    fail 'persistent host-prerequisite reboot verification failed'
  fi
  for binary in containerd ctr crictl etcdctl etcdutl kubeadm kubelet kubectl; do require_command "${binary}"; done
  [[ -x /usr/local/sbin/website-infrastructure-etcd-snapshot && ! -L /usr/local/sbin/website-infrastructure-etcd-snapshot ]] || \
    fail 'installed stacked-etcd snapshot helper is absent or unsafe'
  [[ "${ETCD_TOOLS_ARM64_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail 'etcd recovery-tools checksum is unresolved'
  [[ "${CRICTL_ARM64_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail 'crictl checksum is unresolved'
  [[ "$(crictl --version 2>/dev/null || true)" == "crictl version v${CRICTL_VERSION}" ]] || fail 'crictl version differs from versions.env'
  etcdctl version 2>/dev/null | grep -Eq "^etcdctl version: ${ETCD_VERSION}([[:space:]]|$)" || fail 'etcdctl version differs from versions.env'
  etcdutl version 2>/dev/null | grep -Eq "^etcdutl version: ${ETCD_VERSION}([[:space:]]|$)" || fail 'etcdutl version differs from versions.env'
  [[ "$(kubeadm version -o short 2>/dev/null || true)" == "${KUBERNETES_VERSION}" ]] || fail 'kubeadm version differs from versions.env'
  [[ "$(kubelet --version 2>/dev/null || true)" == "Kubernetes ${KUBERNETES_VERSION}" ]] || fail 'kubelet version differs from versions.env'
  containerd --version 2>/dev/null | grep -Fq "v${CONTAINERD_VERSION}" || fail 'containerd version differs from versions.env'
  containerd config dump 2>/dev/null | grep -Eq 'SystemdCgroup[[:space:]]*=[[:space:]]*true' || fail 'containerd does not use systemd cgroups'
  # containerd 2.x splits CRI into io.containerd.cri.v1 images+runtime; both rows must be ok.
  ctr plugins ls 2>/dev/null | grep -Eq '^io[.]containerd[.]cri[.]v1[[:space:]]+images[[:space:]].*[[:space:]]ok[[:space:]]*$' || fail 'containerd CRI images plugin is not healthy'
  ctr plugins ls 2>/dev/null | grep -Eq '^io[.]containerd[.]cri[.]v1[[:space:]]+runtime[[:space:]].*[[:space:]]ok[[:space:]]*$' || fail 'containerd CRI runtime plugin is not healthy'
  if systemctl is-active --quiet containerd.service; then
    pass 'containerd is active'
  else
    fail 'containerd is not active'
  fi
  [[ ! -e /etc/kubernetes/manifests/kube-apiserver.yaml ]] || fail 'an initialized control plane already exists'
  [[ ! -e /var/lib/etcd/member ]] || fail 'existing stacked-etcd member state found'
  if [[ -f "${cni_path}" ]]; then
    if printf '%s  %s\n' "${cni_sha}" "${cni_path}" | sha256sum --check --status; then
      pass 'CNI manifest hash matches decisions'
    else
      fail 'CNI manifest hash mismatch'
    fi
    if python3 "${repo_root}/scripts/validate_cni_manifest.py" "${cni_path}" --decisions "${decisions_path}"; then
      pass 'rendered CNI manifest matches provider, proxy, CIDR, MTU, tunnel, and image decisions'
    else
      fail 'rendered CNI manifest violates the reviewed CNI contract'
    fi
    cni_image_count="$(grep -Ec '^[[:space:]]*image:' "${cni_path}" || true)"
    (( cni_image_count > 0 )) || fail 'CNI manifest contains no container images'
    if grep -E '^[[:space:]]*image:' "${cni_path}" | grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]|$)' >/dev/null; then
      fail 'CNI manifest contains a non-digest image'
    else
      pass 'CNI manifest images are digest-only'
    fi
    grep -Eq '^kind:[[:space:]]*DaemonSet$' "${cni_path}" || fail 'CNI manifest contains no DaemonSet'
  else
    fail "rendered CNI manifest is absent: ${cni_path}"
  fi
  if [[ -f "${images_lock_path}" ]]; then
    check_mode_0600 "${images_lock_path}"
    if grep -Ev '^(#|$|[^[:space:]]+[[:space:]]sha256:[0-9a-f]{64})$' "${images_lock_path}" >/dev/null; then
      fail 'image lock has malformed entries'
    else
      pass 'image lock entries are syntactically pinned'
    fi
    grep -Eq 'REPLACE_|UNRESOLVED' "${images_lock_path}" && fail 'image lock contains unresolved sentinels'
    required_images=(
      "registry.k8s.io/kube-apiserver:${KUBERNETES_VERSION}"
      "registry.k8s.io/kube-controller-manager:${KUBERNETES_VERSION}"
      "registry.k8s.io/kube-scheduler:${KUBERNETES_VERSION}"
      "registry.k8s.io/kube-proxy:${KUBERNETES_VERSION}"
      "${COREDNS_IMAGE}" "${PAUSE_IMAGE}" "${ETCD_IMAGE}"
    )
    for image in "${required_images[@]}"; do
      [[ "$(awk -v ref="${image}" '$1 == ref {count++} END {print count + 0}' "${images_lock_path}")" == 1 ]] || \
        fail "image lock must contain ${image} exactly once"
    done
  else
    fail "reviewed image lock is absent: ${images_lock_path}"
  fi
fi

# Private identities belong in this ignored mode-0600 contract. The shared
# validator emits indexed diagnostics only and keeps static parsing separate
# from the live active/inactive, enablement, and archive-root checks used here.
if [[ -e "${protected_services_path}" || -L "${protected_services_path}" ]]; then
  if python3 "${repo_root}/scripts/validate_protected_host_contract.py" \
      "${protected_services_path}" --check-live; then
    pass 'protected-host live checks and mandatory presence-bound boot attestation passed'
  else
    fail 'protected-host live checks or presence-bound boot attestation is invalid'
  fi
elif [[ "${phase}" == install || "${phase}" == init ]]; then
  fail 'protected-host contract is required before an install or init phase'
else
  warn 'protected-host contract is absent; install and init will fail closed until it is reviewed'
fi

if (( failures > 0 )); then
  printf '%d preflight failure(s); no mutation is authorized.\n' "${failures}" >&2
  exit 1
fi
printf 'PASS %s preflight completed without intentional changes.\n' "${phase}"
