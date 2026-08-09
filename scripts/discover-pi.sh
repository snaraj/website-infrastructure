#!/usr/bin/env bash
# Collect read-only Pi evidence for the human bootstrap review without placing
# raw host identities, addresses, or firewall contents in a shareable report.
set -euo pipefail

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
command -v python3 >/dev/null 2>&1 || { printf 'python3 is required for redaction.\n' >&2; exit 2; }

# section keeps the report readable when a person compares discovery runs.
section() { printf '\n## %s\n' "$1"; }

# capture sends every command result through the redactor before it can reach
# stdout; a missing probe is recorded as uncertainty instead of aborting later
# independent evidence collection.
capture() {
  local label="$1"
  shift
  printf '\n### %s\n' "${label}"
  if ! "$@" 2>&1 | python3 "${redactor}"; then
    printf '[command unavailable or returned nonzero]\n'
  fi
}

# fingerprint_stdout proves whether sensitive command output changed while
# disclosing only its status and SHA-256, which is enough to bind later review.
fingerprint_stdout() {
  local output
  if ! output="$("$@" 2>/dev/null)"; then
    printf 'status=FAIL command=%s\n' "$1"
    return 1
  fi
  if [[ -z "${output}" ]]; then
    printf 'status=OK_EMPTY command=%s\n' "$1"
  else
    printf 'status=OK command=%s\n' "$1"
  fi
  printf '%s' "${output}" | sha256sum | awk '{print "sha256=" $1}'
}

# nft_structure exposes table/chain topology needed for CNI planning but omits
# individual firewall rules that could reveal protected host details.
nft_structure() {
  local ruleset
  if ! ruleset="$(sudo -n nft list ruleset 2>/dev/null)"; then
    printf 'status=FAIL command=nft-list-ruleset\n'
    return 1
  fi
  if [[ -z "${ruleset}" ]]; then
    printf 'status=OK_EMPTY command=nft-list-ruleset\n'
    return 0
  fi
  printf 'status=OK command=nft-list-ruleset\n'
  printf '%s\n' "${ruleset}" | grep -E '^(table|[[:space:]]*chain|[[:space:]]*type .* hook .* policy)'
}

# protected_unit_state intentionally discards systemctl output because error
# text can echo a private unit name. Only the indexed active-state result is
# safe to include in the shareable report.
protected_unit_state() {
  local unit="$1"
  if systemctl is-active --quiet -- "${unit}" >/dev/null 2>&1; then
    printf 'state=active\n'
  else
    printf 'state=inactive-or-unavailable\n'
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
capture 'swap' swapon --show --noheadings --bytes
capture 'relevant kernel command-line flags' sh -c 'tr " " "\n" </proc/cmdline | grep -E "^(cgroup|systemd[.]unified_cgroup_hierarchy|swapaccount|apparmor|selinux)" || true'

section 'Storage identity and health'
capture 'block topology (no model, serial, or mount paths)' lsblk -e7 -o NAME,SIZE,ROTA,TYPE,FSTYPE,TRAN
# Kubernetes state directories are checked individually because they can live
# on different media, and control-plane durability depends on the actual mount.
for target in / /var/lib/etcd /var/lib/containerd /var/lib/kubelet; do
  if [[ -e "${target}" ]]; then
    capture "reviewed target ${target}" findmnt -T "${target}" -o TARGET,SOURCE,FSTYPE,UUID,OPTIONS
    capture "capacity ${target}" df -hT "${target}"
  else
    printf '\n### reviewed target %s\nabsent\n' "${target}"
  fi
done
capture 'TRIM timer state' systemctl is-enabled fstrim.timer
if command -v smartctl >/dev/null 2>&1; then
  while IFS= read -r device; do
    # The child shell expands $1; keeping the program single-quoted prevents
    # the discovery shell from consuming that positional parameter first.
    # shellcheck disable=SC2016
    capture "SMART health ${device}" sh -c 'sudo -n smartctl -H "$1" | grep -E "SMART overall-health|SMART Health Status"' sh "${device}"
  done < <(lsblk -dpno NAME,TYPE | awk '$2 == "disk" {print $1}')
else
  printf '\n### SMART health\nsmartctl is unavailable; health remains pending.\n'
fi

section 'Kernel, cgroups, and runtime prerequisites'
capture 'cgroup filesystem' stat -fc %T /sys/fs/cgroup
capture 'cgroup controllers' sh -c 'cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true'
# This loop is a program for the child shell, which owns and expands $module.
# shellcheck disable=SC2016
capture 'reviewed kernel modules' sh -c 'for module in overlay br_netfilter vxlan wireguard; do if modinfo "$module" >/dev/null 2>&1; then echo "$module available"; else echo "$module unavailable"; fi; done'
capture 'loaded relevant modules' sh -c 'lsmod | grep -E "^(overlay|br_netfilter|vxlan|wireguard|nf_|ip_|xt_)" || true'
capture 'relevant sysctls' sysctl vm.overcommit_memory vm.panic_on_oom kernel.panic kernel.panic_on_oops kernel.keys.root_maxkeys kernel.keys.root_maxbytes net.ipv4.ip_forward net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables
if [[ -r /sys/kernel/btf/vmlinux ]]; then printf '\n### kernel BTF\navailable\n'; else printf '\n### kernel BTF\nunavailable\n'; fi
capture 'installed platform packages' sh -c 'dpkg-query -W 2>/dev/null | grep -E "^(containerd|runc|kubeadm|kubelet|kubectl|cri-tools|kubernetes-cni)[[:space:]]" || true'
# This loop is a program for the child shell, which owns and expands $binary.
# shellcheck disable=SC2016
capture 'relevant binary versions' sh -c 'for binary in containerd runc kubeadm kubelet kubectl crictl; do if command -v "$binary" >/dev/null 2>&1; then "$binary" --version 2>&1 | head -n1; else echo "$binary absent"; fi; done'
if command -v containerd >/dev/null 2>&1; then
  capture 'safe-selected containerd config' sh -c 'containerd config dump 2>/dev/null | grep -E "^(version|root|state|disabled_plugins)|SystemdCgroup|sandbox|pinned_images|io[.]containerd[.]cri" || true'
fi

section 'Interfaces, routing, listeners, and CNI decision inputs'
# Route/firewall evidence is deliberately both redacted and fingerprinted: the
# former supports human review, while the latter detects drift before mutation.
capture 'interface names, state, MTU, and redacted link addresses' ip -br link
capture 'redacted IPv4 addresses' ip -br -4 address
capture 'redacted routes' ip -4 route show table all
capture 'redacted policy rules' ip -4 rule show
capture 'VPN tunnel interface inventory fingerprint' fingerprint_stdout \
  sh -c 'command -v wg >/dev/null 2>&1 && wg show interfaces || true'
capture 'TCP/UDP listeners (addresses redacted)' ss -lntup
capture 'local CRI sockets' sh -c 'ss -lx | grep -E "containerd|crio|cri-dockerd" || true'
capture 'iptables implementation' sh -c 'iptables --version 2>/dev/null || true; ip6tables --version 2>/dev/null || true; nft --version 2>/dev/null || true'
capture 'nft table and chain names only' nft_structure
capture 'nft ruleset fingerprint' fingerprint_stdout sudo -n nft list ruleset
capture 'IPv4 iptables rules fingerprint' fingerprint_stdout sudo -n iptables-save
capture 'IPv6 iptables rules fingerprint' fingerprint_stdout sudo -n ip6tables-save
capture 'review-binding route and firewall fingerprints' bash "${repo_root}/scripts/fingerprint_pi_state.sh"
capture 'DNS resolution' getent ahosts region1.v2.argotunnel.com
capture 'Cloudflare HTTPS egress' curl --fail --silent --show-error --head --max-time 10 https://www.cloudflare.com/cdn-cgi/trace
if command -v nc >/dev/null 2>&1; then
  capture 'Cloudflare Tunnel TCP 7844 egress' nc -vz -w 5 region1.v2.argotunnel.com 7844
else
  printf '\n### Cloudflare Tunnel port 7844\nnc is unavailable; connector tests remain pending.\n'
fi

section 'Protected services and existing platform state'
# Complete service inventories are hashed instead of filtered by committed
# workload names. The hashes detect drift while local review and the ignored
# exact-unit contract retain the private identities needed by preflight.
capture 'running service inventory fingerprint' fingerprint_stdout \
  systemctl --type=service --state=running --no-pager --no-legend
capture 'service unit-file inventory fingerprint' fingerprint_stdout \
  systemctl list-unit-files --no-pager --no-legend

protected_contract_ready=true
if [[ -L "${protected_services_path}" ]]; then
  printf 'protected_service_contract=INVALID_SYMLINK\n'
  protected_contract_ready=false
elif [[ ! -f "${protected_services_path}" ]]; then
  printf 'protected_service_contract=PENDING_LOCAL_REVIEW\n'
  protected_contract_ready=false
elif [[ "$(stat -c %a "${protected_services_path}" 2>/dev/null || true)" != 600 ]]; then
  printf 'protected_service_contract=INVALID_MODE\n'
  protected_contract_ready=false
elif grep -Eqv '^(#|$|PROTECTED_SERVICES_REVIEWED=yes|PROTECTED_SYSTEMD_UNIT=[A-Za-z0-9_][A-Za-z0-9_.:@-]*[.]service)$' \
    "${protected_services_path}"; then
  printf 'protected_service_contract=INVALID_FORMAT\n'
  protected_contract_ready=false
elif [[ "$(grep -Ec '^PROTECTED_SERVICES_REVIEWED=yes$' "${protected_services_path}" || true)" != 1 ]]; then
  printf 'protected_service_contract=REVIEW_NOT_CONFIRMED\n'
  protected_contract_ready=false
elif awk -F= '$1 == "PROTECTED_SYSTEMD_UNIT" { if (seen[$2]++) duplicate=1 } END { exit duplicate ? 0 : 1 }' \
    "${protected_services_path}"; then
  printf 'protected_service_contract=DUPLICATE_UNIT\n'
  protected_contract_ready=false
fi

if [[ "${protected_contract_ready}" == true ]]; then
  protected_service_index=0
  while IFS= read -r protected_service_line; do
    [[ "${protected_service_line}" == PROTECTED_SYSTEMD_UNIT=* ]] || continue
    protected_service_index=$((protected_service_index + 1))
    protected_unit_state "${protected_service_line#*=}" | python3 "${redactor}" \
      | sed "1s/^/protected_service_${protected_service_index}_/"
  done < "${protected_services_path}"
  printf 'protected_service_contract=REVIEWED count=%d\n' "${protected_service_index}"
else
  printf 'NOTICE: bootstrap preflight remains blocked until the private protected-service contract is reviewed.\n'
fi
for path in /etc/kubernetes /var/lib/etcd /var/lib/kubelet /etc/cni/net.d /etc/containerd /var/lib/containerd /etc/rancher/k3s /var/lib/rancher/k3s /etc/cloudflared /var/lib/docker; do
  if [[ -e "${path}" ]]; then
    printf 'present: %s\n' "${path}"
  else
    printf 'absent: %s\n' "${path}"
  fi
done

printf '\nDiscovery made no intentional changes. Use unredacted local inspection to fill\n'
printf 'the ignored decision files; never infer CNI or kube-proxy compatibility from\n'
printf 'this shareable report alone. Preserve VPN, firewall, and every locally declared protected service.\n'
