#!/usr/bin/env bash

# Shared, repository-controlled helpers. Review plans and state files are parsed
# as inert KEY=VALUE data and are never sourced or evaluated.

host_prereq_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${host_prereq_dir}/../../.." && pwd -P)"

readonly modules_source="${host_prereq_dir}/90-website-infrastructure-kubeadm.modules.conf"
readonly sysctl_source="${host_prereq_dir}/90-website-infrastructure-kubeadm.sysctl.conf"
readonly modules_target="/etc/modules-load.d/90-website-infrastructure-kubeadm.conf"
readonly sysctl_target="/etc/sysctl.d/90-website-infrastructure-kubeadm.conf"
readonly fstab_target="/etc/fstab"
readonly backup_root="/var/backups/website-infrastructure/host-prerequisites"
readonly state_root="/var/lib/website-infrastructure/host-prerequisites"
readonly active_state="${state_root}/active.state"
readonly pending_state="${state_root}/pending-transaction"
# This shared lock is intentionally consumed by the apply and rollback entry
# points rather than by a function in this library.
# shellcheck disable=SC2034
readonly lock_path="/run/lock/website-infrastructure-host-prerequisites.lock"

readonly -a required_modules=(overlay br_netfilter)
readonly -a sysctl_keys=(
  vm.overcommit_memory
  vm.panic_on_oom
  kernel.panic
  kernel.panic_on_oops
  kernel.keys.root_maxkeys
  kernel.keys.root_maxbytes
  net.ipv4.ip_forward
  net.bridge.bridge-nf-call-iptables
  net.bridge.bridge-nf-call-ip6tables
)
readonly -a current_plan_keys=(
  CURRENT_VM_OVERCOMMIT_MEMORY
  CURRENT_VM_PANIC_ON_OOM
  CURRENT_KERNEL_PANIC
  CURRENT_KERNEL_PANIC_ON_OOPS
  CURRENT_KERNEL_KEYS_ROOT_MAXKEYS
  CURRENT_KERNEL_KEYS_ROOT_MAXBYTES
  CURRENT_NET_IPV4_IP_FORWARD
  CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES
  CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES
)
readonly -a desired_values=(1 0 10 1 1000000 25000000 1 1 1)

host_prereq_die() {
  printf 'ERROR %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == 0 ]] || host_prereq_die 'this host-prerequisites operation requires root'
}

require_commands() {
  local command_name
  for command_name in awk chmod chown cp cut date find findfs findmnt flock grep id install lsmod mkdir mktemp modinfo modprobe mv python3 readlink rm sed sha256sum sort stat swapoff swapon sysctl systemctl uname; do
    command -v "${command_name}" >/dev/null 2>&1 || host_prereq_die "required command is absent: ${command_name}"
  done
}

sha256_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

sha256_stdin() {
  sha256sum | awk '{print $1}'
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

plan_value() {
  local key="$1"
  local plan_path="$2"
  awk -F= -v key="${key}" '$1 == key {sub(/^[^=]*=/, ""); print}' "${plan_path}"
}

data_value() {
  local key="$1"
  local data_path="$2"
  awk -F= -v key="${key}" '$1 == key {sub(/^[^=]*=/, ""); print}' "${data_path}"
}

host_machine_id_sha256() {
  [[ -f /etc/machine-id && ! -L /etc/machine-id ]] || host_prereq_die '/etc/machine-id must be a regular file'
  sha256_file /etc/machine-id
}

host_boot_id_sha256() {
  [[ -f /proc/sys/kernel/random/boot_id ]] || host_prereq_die 'kernel boot ID is unavailable'
  sha256_file /proc/sys/kernel/random/boot_id
}

host_os_release_sha256() {
  local resolved
  [[ -f /etc/os-release ]] || host_prereq_die '/etc/os-release must resolve to a regular file'
  resolved="$(readlink -f -- /etc/os-release)"
  [[ "${resolved}" == /etc/os-release || "${resolved}" == /usr/lib/os-release || "${resolved}" == /lib/os-release ]] || host_prereq_die '/etc/os-release resolves outside its approved system locations'
  sha256_file /etc/os-release
}

module_available() {
  local module="$1"
  modinfo "${module}" >/dev/null 2>&1 || [[ -d "/sys/module/${module}" ]]
}

module_loaded() {
  local module="$1"
  [[ -d "/sys/module/${module}" ]] || lsmod | awk '{print $1}' | grep -Fxq "${module}"
}

module_gated_sysctl() {
  case "$1" in
    net.bridge.bridge-nf-call-iptables|net.bridge.bridge-nf-call-ip6tables) return 0 ;;
    *) return 1 ;;
  esac
}

observed_sysctl_value() {
  local key="$1"
  local value
  if value="$(sysctl -n "${key}" 2>/dev/null)"; then
    [[ "${value}" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "${value}"
    return 0
  fi
  if module_gated_sysctl "${key}" && ! module_loaded br_netfilter; then
    printf 'unavailable-until-module-load\n'
    return 0
  fi
  return 1
}

active_swap_sources() {
  local source raw_sources
  if ! raw_sources="$(swapon --show --noheadings --raw --output NAME)"; then
    printf 'swapon inventory failed\n' >&2
    return 1
  fi
  while IFS= read -r source; do
    [[ -z "${source}" ]] && continue
    if [[ "${source}" != /* || "${source}" =~ [[:space:]] ]]; then
      printf 'unknown active swap source cannot be represented safely: %q\n' "${source}" >&2
      return 1
    fi
    readlink -f -- "${source}"
  done <<<"${raw_sources}"
}

active_swap_sha256() {
  active_swap_sources | LC_ALL=C sort -u | sha256_stdin
}

fstab_swap_specs() {
  awk '$0 !~ /^[[:space:]]*#/ && NF >= 3 && $3 == "swap" {print $1}' "${fstab_target}"
}

resolve_swap_spec() {
  local spec="$1"
  local resolved
  case "${spec}" in
    UUID=*|LABEL=*|PARTUUID=*|PARTLABEL=*)
      resolved="$(findfs "${spec}" 2>/dev/null || true)"
      ;;
    /*)
      [[ "${spec}" != *\\* ]] || return 1
      resolved="${spec}"
      ;;
    *)
      return 1
      ;;
  esac
  [[ -n "${resolved}" && "${resolved}" != /dev/zram* && "${resolved}" != /dev/mapper/* && "${resolved}" != /dev/dm-* && ! "${resolved}" =~ [[:space:]] ]] || return 1
  resolved="$(readlink -f -- "${resolved}")"
  [[ -b "${resolved}" || -f "${resolved}" ]] || return 1
  printf '%s\n' "${resolved}"
}

unknown_swap_signals() {
  local path inventory matches grep_status find_status
  for path in \
    /etc/default/dphys-swapfile \
    /etc/dphys-swapfile \
    /etc/systemd/zram-generator.conf \
    /etc/systemd/zram-generator.conf.d \
    /usr/lib/systemd/zram-generator.conf \
    /usr/lib/systemd/zram-generator.conf.d \
    /usr/local/lib/systemd/zram-generator.conf \
    /usr/local/lib/systemd/zram-generator.conf.d \
    /etc/systemd/swap.conf \
    /etc/systemd/swap.conf.d \
    /etc/default/zramswap \
    /etc/default/zram-config; do
    [[ ! -e "${path}" ]] || printf 'configuration:%s\n' "${path}"
  done

  for path in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    [[ -d "${path}" ]] || continue
    matches=''
    find_status=0
    matches="$(find "${path}" -maxdepth 3 \( -type f -o -type l \) -name '*.swap' -print 2>/dev/null)" || find_status=$?
    if (( find_status != 0 )); then
      printf 'native-swap-unit-inventory-unavailable:%s\n' "${path}"
    elif [[ -n "${matches}" ]]; then
      awk '{ print "native-unit:" $0 }' <<<"${matches}"
    fi
  done

  if inventory="$(systemctl list-unit-files --no-legend --no-pager 2>/dev/null)"; then
    awk '$1 ~ /^(dphys-swapfile|zramswap|systemd-swap|zram-swap|systemd-zram-setup@).*\.(service|swap)$/ {print "unit:" $1}' <<<"${inventory}"
  else
    printf 'systemd-unit-inventory-unavailable\n'
  fi

  for path in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/init.d /etc/cron.d; do
    [[ -d "${path}" ]] || continue
    matches=''
    grep_status=0
    matches="$(grep -IlEr --include='*.service' --include='*.timer' --include='*swap*' '(^|[[:space:]/])(swapon|mkswap)([[:space:]]|$)|/dev/zram|zram-generator|dphys-swapfile' "${path}" 2>/dev/null)" || grep_status=$?
    if (( grep_status > 1 )); then
      printf 'swap-command-inventory-unavailable:%s\n' "${path}"
    elif [[ -n "${matches}" ]]; then
      awk '{ print "swap-command-file:" $0 }' <<<"${matches}"
    fi
  done
  for path in /etc/rc.local /etc/crontab; do
    [[ -f "${path}" ]] || continue
    grep_status=0
    if grep -IqE '(^|[[:space:]/])(swapon|mkswap)([[:space:]]|$)|/dev/zram|zram-generator|dphys-swapfile' "${path}"; then
      printf 'swap-command-file:%s\n' "${path}"
    else
      grep_status=$?
      (( grep_status <= 1 )) || printf 'swap-command-inventory-unavailable:%s\n' "${path}"
    fi
  done
}

detect_swap_mechanism() {
  local signals
  local active_output
  local -a active=()
  local -a fstab_resolved=()
  local spec resolved source candidate found

  signals="$(unknown_swap_signals)"
  if [[ -n "${signals}" ]]; then
    printf '%s\n' "${signals}" >&2
    printf 'unknown\n'
    return 0
  fi

  if ! active_output="$(active_swap_sources)"; then
    printf 'unknown\n'
    return 0
  fi
  if [[ -n "${active_output}" ]]; then
    mapfile -t active <<<"${active_output}"
  fi
  while IFS= read -r spec; do
    [[ -z "${spec}" ]] && continue
    if ! resolved="$(resolve_swap_spec "${spec}")"; then
      printf 'unresolvable fstab swap specification: %q\n' "${spec}" >&2
      printf 'unknown\n'
      return 0
    fi
    fstab_resolved+=("${resolved}")
  done < <(fstab_swap_specs)

  if (( ${#active[@]} == 0 && ${#fstab_resolved[@]} == 0 )); then
    printf 'none\n'
    return 0
  fi
  if (( ${#fstab_resolved[@]} == 0 )); then
    printf 'active swap is not represented by /etc/fstab\n' >&2
    printf 'unknown\n'
    return 0
  fi

  for source in "${active[@]}"; do
    found=no
    for candidate in "${fstab_resolved[@]}"; do
      if [[ "${source}" == "${candidate}" ]]; then
        found=yes
        break
      fi
    done
    if [[ "${found}" != yes ]]; then
      printf 'active swap is not an exact /etc/fstab source: %q\n' "${source}" >&2
      printf 'unknown\n'
      return 0
    fi
  done
  printf 'fstab-only\n'
}

assert_safe_existing_directory() {
  local path="$1"
  local mode owner resolved
  [[ -d "${path}" && ! -L "${path}" ]] || host_prereq_die "required directory is absent, non-directory, or symlinked: ${path}"
  resolved="$(readlink -f -- "${path}")"
  [[ "${resolved}" == "${path}" ]] || host_prereq_die "directory does not resolve to its exact path: ${path}"
  owner="$(stat -c %u -- "${path}")"
  mode="$(stat -c %a -- "${path}")"
  [[ "${owner}" == 0 ]] || host_prereq_die "directory is not root-owned: ${path}"
  (( (8#${mode} & 0022) == 0 )) || host_prereq_die "directory is group/world writable: ${path}"
}

assert_plan_file() {
  local plan_path="$1"
  [[ -f "${plan_path}" && ! -L "${plan_path}" ]] || host_prereq_die 'plan must be a regular, non-symlink file'
  [[ "$(stat -c %u -- "${plan_path}")" == 0 ]] || host_prereq_die 'plan must be root-owned'
  [[ "$(stat -c %a -- "${plan_path}")" == 600 ]] || host_prereq_die 'plan mode must be exactly 0600'
  python3 "${repo_root}/scripts/validate_host_prerequisites_plan.py" "${plan_path}"
}

validate_desired_sources() {
  local line key value index expected found
  local -a modules=()
  local -A seen_sysctls=()
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"${line}")"
    [[ -z "${line}" ]] && continue
    [[ "${line}" =~ ^[a-z0-9_]+$ ]] || host_prereq_die 'modules source contains a malformed entry'
    modules+=("${line}")
  done < "${modules_source}"
  (( ${#modules[@]} == ${#required_modules[@]} )) || host_prereq_die 'modules source has an unexpected entry count'
  for index in "${!required_modules[@]}"; do
    [[ "${modules[${index}]}" == "${required_modules[${index}]}" ]] || host_prereq_die 'modules source differs from the exact ordered allowlist'
  done

  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"${line}")"
    [[ -z "${line}" ]] && continue
    [[ "${line}" =~ ^([a-z0-9._-]+)[[:space:]]*=[[:space:]]*([0-9]+)$ ]] || host_prereq_die 'sysctl source contains a malformed entry'
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    [[ -z "${seen_sysctls[${key}]:-}" ]] || host_prereq_die "sysctl source repeats ${key}"
    found=no
    for index in "${!sysctl_keys[@]}"; do
      if [[ "${key}" == "${sysctl_keys[${index}]}" ]]; then
        [[ "${value}" == "${desired_values[${index}]}" ]] || host_prereq_die "sysctl source has an unauthorized value for ${key}"
        found=yes
        break
      fi
    done
    [[ "${found}" == yes ]] || host_prereq_die "sysctl source contains an unauthorized key: ${key}"
    seen_sysctls["${key}"]="${value}"
  done < "${sysctl_source}"
  (( ${#seen_sysctls[@]} == ${#sysctl_keys[@]} )) || host_prereq_die 'sysctl source does not contain the exact allowlist'
}

check_host_against_plan() {
  local plan_path="$1"
  local index key actual expected module mechanism expected_action

  assert_plan_file "${plan_path}"
  [[ -f "${modules_source}" && ! -L "${modules_source}" ]] || host_prereq_die 'reviewed modules source is not a regular file'
  [[ -f "${sysctl_source}" && ! -L "${sysctl_source}" ]] || host_prereq_die 'reviewed sysctl source is not a regular file'
  validate_desired_sources
  [[ "$(sha256_file "${modules_source}")" == "$(plan_value DESIRED_MODULES_SHA256 "${plan_path}")" ]] || host_prereq_die 'reviewed modules source hash differs from the plan'
  [[ "$(sha256_file "${sysctl_source}")" == "$(plan_value DESIRED_SYSCTL_SHA256 "${plan_path}")" ]] || host_prereq_die 'reviewed sysctl source hash differs from the plan'

  [[ "$(uname -m)" == "$(plan_value EXPECTED_ARCHITECTURE "${plan_path}")" ]] || host_prereq_die 'architecture changed since discovery'
  [[ "$(uname -r)" == "$(plan_value EXPECTED_KERNEL_RELEASE "${plan_path}")" ]] || host_prereq_die 'kernel changed since discovery'
  [[ "$(host_machine_id_sha256)" == "$(plan_value EXPECTED_MACHINE_ID_SHA256 "${plan_path}")" ]] || host_prereq_die 'machine identity changed since discovery'
  [[ "$(host_boot_id_sha256)" == "$(plan_value EXPECTED_BOOT_ID_SHA256 "${plan_path}")" ]] || host_prereq_die 'boot changed since discovery; generate and review a fresh plan'
  [[ "$(host_os_release_sha256)" == "$(plan_value EXPECTED_OS_RELEASE_SHA256 "${plan_path}")" ]] || host_prereq_die 'OS release changed since discovery'

  assert_safe_existing_directory /etc/modules-load.d
  assert_safe_existing_directory /etc/sysctl.d
  [[ -f "${fstab_target}" && ! -L "${fstab_target}" ]] || host_prereq_die '/etc/fstab must be a regular, non-symlink file'
  [[ "$(file_state "${modules_target}")" == "$(plan_value EXPECTED_MODULES_TARGET_STATE "${plan_path}")" ]] || host_prereq_die 'modules-load target changed since discovery'
  [[ "$(file_state "${sysctl_target}")" == "$(plan_value EXPECTED_SYSCTL_TARGET_STATE "${plan_path}")" ]] || host_prereq_die 'sysctl target changed since discovery'
  [[ "$(sha256_file "${fstab_target}")" == "$(plan_value EXPECTED_FSTAB_SHA256 "${plan_path}")" ]] || host_prereq_die '/etc/fstab changed since discovery'

  for module in "${required_modules[@]}"; do
    module_available "${module}" || host_prereq_die "required module is unavailable: ${module}"
  done
  for index in "${!sysctl_keys[@]}"; do
    key="${sysctl_keys[${index}]}"
    actual="$(observed_sysctl_value "${key}" || true)"
    [[ -n "${actual}" ]] || host_prereq_die "sysctl ${key} cannot be observed safely"
    expected="$(plan_value "${current_plan_keys[${index}]}" "${plan_path}")"
    [[ "${actual}" == "${expected}" ]] || host_prereq_die "sysctl ${key} changed since discovery"
  done

  mechanism="$(detect_swap_mechanism)"
  [[ "${mechanism}" != unknown ]] || host_prereq_die 'swap mechanism is unknown or mixed; no change is permitted'
  [[ "${mechanism}" == "$(plan_value SWAP_MECHANISM "${plan_path}")" ]] || host_prereq_die 'swap mechanism changed since discovery'
  expected_action="none"
  [[ "${mechanism}" != fstab-only ]] || expected_action="disable-fstab"
  [[ "${expected_action}" == "$(plan_value SWAP_ACTION "${plan_path}")" ]] || host_prereq_die 'swap action is inconsistent with live discovery'
  [[ "$(active_swap_sha256)" == "$(plan_value EXPECTED_ACTIVE_SWAP_SHA256 "${plan_path}")" ]] || host_prereq_die 'active swap set changed since discovery'
  if [[ "${mechanism}" == fstab-only ]]; then
    fstab_swap_specs | grep -q . || host_prereq_die 'fstab-only swap classification contains no fstab swap entries'
  fi

  printf 'PASS live host still matches the approved discovery plan\n'
}

verify_desired_host_contract() {
  local index key actual module mechanism
  [[ "$(file_state "${modules_target}")" == "sha256:$(sha256_file "${modules_source}")" ]] || return 1
  [[ "$(file_state "${sysctl_target}")" == "sha256:$(sha256_file "${sysctl_source}")" ]] || return 1
  for module in "${required_modules[@]}"; do
    module_loaded "${module}" || return 1
  done
  for index in "${!sysctl_keys[@]}"; do
    key="${sysctl_keys[${index}]}"
    actual="$(sysctl -n "${key}" 2>/dev/null || true)"
    [[ "${actual}" == "${desired_values[${index}]}" ]] || return 1
  done
  [[ -z "$(swapon --show --noheadings --raw --output NAME)" ]] || return 1
  mechanism="$(detect_swap_mechanism)"
  [[ "${mechanism}" == none ]] || return 1
}

atomic_install_root_file() {
  local source="$1"
  local target="$2"
  local temporary
  temporary="$(mktemp "$(dirname "${target}")/.website-infrastructure.XXXXXX")"
  if ! install -o root -g root -m 0644 -- "${source}" "${temporary}"; then
    rm -f -- "${temporary}"
    return 1
  fi
  if ! mv -fT -- "${temporary}" "${target}"; then
    rm -f -- "${temporary}"
    return 1
  fi
}

atomic_install_matching_target() {
  local source="$1"
  local target="$2"
  local temporary
  temporary="$(mktemp "$(dirname "${target}")/.website-infrastructure.XXXXXX")"
  rm -f -- "${temporary}"
  if ! cp -a -- "${target}" "${temporary}"; then
    rm -f -- "${temporary}"
    return 1
  fi
  if ! cp --no-preserve=mode,ownership,timestamps -- "${source}" "${temporary}"; then
    rm -f -- "${temporary}"
    return 1
  fi
  if ! mv -fT -- "${temporary}" "${target}"; then
    rm -f -- "${temporary}"
    return 1
  fi
}

ensure_private_directory() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    [[ -d "${path}" && ! -L "${path}" ]] || host_prereq_die "private path is not an exact directory: ${path}"
    [[ "$(stat -c %u -- "${path}")" == 0 ]] || host_prereq_die "private directory is not root-owned: ${path}"
    [[ "$(stat -c %a -- "${path}")" == 700 ]] || host_prereq_die "private directory mode must be 0700: ${path}"
  else
    install -d -o root -g root -m 0700 -- "${path}"
  fi
}

atomic_restore_backup() {
  local backup="$1"
  local target="$2"
  local temporary
  temporary="$(mktemp "$(dirname "${target}")/.website-infrastructure-restore.XXXXXX")"
  rm -f -- "${temporary}"
  if ! cp -a -- "${backup}" "${temporary}"; then
    rm -f -- "${temporary}"
    return 1
  fi
  if ! mv -fT -- "${temporary}" "${target}"; then
    rm -f -- "${temporary}"
    return 1
  fi
}

manifest_key_allowed() {
  case "$1" in
    MANIFEST_VERSION|TRANSACTION_ID|PLAN_SHA256|MACHINE_ID_SHA256|APPLIED_BOOT_ID_SHA256|MODULES_PRESTATE|SYSCTL_PRESTATE|FSTAB_PRE_SHA256|FSTAB_POST_SHA256|ACTIVE_SWAP_PRE_SHA256|DESIRED_MODULES_SHA256|DESIRED_SYSCTL_SHA256|SWAP_ACTION|LATE_SYSCTLS_STATE|OLD_VM_OVERCOMMIT_MEMORY|OLD_VM_PANIC_ON_OOM|OLD_KERNEL_PANIC|OLD_KERNEL_PANIC_ON_OOPS|OLD_KERNEL_KEYS_ROOT_MAXKEYS|OLD_KERNEL_KEYS_ROOT_MAXBYTES|OLD_NET_IPV4_IP_FORWARD|OLD_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES|OLD_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

old_sysctl_value_allowed() {
  local key="$1"
  local value="$2"
  local number
  if [[ "${value}" == unavailable-until-module-load ]]; then
    [[ "${key}" == OLD_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES || "${key}" == OLD_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES ]]
    return
  fi
  [[ "${value}" =~ ^[0-9]{1,10}$ ]] || return 1
  number=$((10#${value}))
  case "${key}" in
    OLD_VM_OVERCOMMIT_MEMORY) (( number <= 2 )) ;;
    OLD_VM_PANIC_ON_OOM|OLD_KERNEL_PANIC_ON_OOPS|OLD_NET_IPV4_IP_FORWARD|OLD_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES|OLD_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES) (( number <= 1 )) ;;
    OLD_KERNEL_PANIC) (( number <= 3600 )) ;;
    OLD_KERNEL_KEYS_ROOT_MAXKEYS|OLD_KERNEL_KEYS_ROOT_MAXBYTES) (( number >= 1 && number <= 2000000000 )) ;;
    *) return 1 ;;
  esac
}

validate_late_sysctls() {
  local manifest="$1"
  local transaction_dir="$2"
  local late_file="${transaction_dir}/module-load-sysctls.pre"
  local state key value count expected_count=0
  local -a late_keys=()
  state="$(data_value LATE_SYSCTLS_STATE "${manifest}")"
  [[ "${state}" == absent || "${state}" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  for key in OLD_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES OLD_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES; do
    if [[ "$(data_value "${key}" "${manifest}")" == unavailable-until-module-load ]]; then
      expected_count=$((expected_count + 1))
      late_keys+=("${key}")
    fi
  done
  if (( expected_count == 0 )); then
    [[ "${state}" == absent && ! -e "${late_file}" && ! -L "${late_file}" ]]
    return
  fi
  if [[ "${state}" == absent && ! -e "${late_file}" && ! -L "${late_file}" ]]; then
    return 0
  fi
  [[ -f "${late_file}" && ! -L "${late_file}" ]] || return 1
  [[ "$(stat -c %u -- "${late_file}")" == 0 && "$(stat -c %a -- "${late_file}")" == 600 ]] || return 1
  if [[ "${state}" != absent ]]; then
    [[ "sha256:$(sha256_file "${late_file}")" == "${state}" ]] || return 1
  fi
  while IFS= read -r line; do
    [[ "${line}" == *=* ]] || return 1
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${key}" == OLD_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES || "${key}" == OLD_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES ]] || return 1
    [[ "$(data_value "${key}" "${manifest}")" == unavailable-until-module-load ]] || return 1
    [[ "${value}" != unavailable-until-module-load ]] || return 1
    old_sysctl_value_allowed "${key}" "${value}" || return 1
  done < "${late_file}"
  for key in "${late_keys[@]}"; do
    count="$(grep -Ec "^${key}=" "${late_file}" || true)"
    [[ "${count}" == 1 ]] || return 1
  done
  [[ "$(grep -Ec '^[A-Z][A-Z0-9_]*=' "${late_file}" || true)" == "${expected_count}" ]]
}

validate_transaction() {
  local transaction_id="$1"
  local transaction_dir="${backup_root}/${transaction_id}"
  local manifest="${transaction_dir}/manifest"
  local key value count prestate
  local -a required_manifest_keys=(
    MANIFEST_VERSION TRANSACTION_ID PLAN_SHA256 MACHINE_ID_SHA256 APPLIED_BOOT_ID_SHA256
    MODULES_PRESTATE SYSCTL_PRESTATE FSTAB_PRE_SHA256 FSTAB_POST_SHA256
    ACTIVE_SWAP_PRE_SHA256 DESIRED_MODULES_SHA256 DESIRED_SYSCTL_SHA256 SWAP_ACTION
    LATE_SYSCTLS_STATE
    OLD_VM_OVERCOMMIT_MEMORY OLD_VM_PANIC_ON_OOM OLD_KERNEL_PANIC
    OLD_KERNEL_PANIC_ON_OOPS OLD_KERNEL_KEYS_ROOT_MAXKEYS OLD_KERNEL_KEYS_ROOT_MAXBYTES
    OLD_NET_IPV4_IP_FORWARD OLD_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES
    OLD_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES
  )

  [[ "${transaction_id}" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}-[0-9]+$ ]] || { printf 'ERROR malformed transaction ID\n' >&2; return 1; }
  [[ -d "${transaction_dir}" && ! -L "${transaction_dir}" ]] || { printf 'ERROR transaction directory is absent or unsafe\n' >&2; return 1; }
  [[ "$(stat -c %u -- "${transaction_dir}")" == 0 && "$(stat -c %a -- "${transaction_dir}")" == 700 ]] || { printf 'ERROR transaction directory ownership/mode is unsafe\n' >&2; return 1; }
  [[ -f "${manifest}" && ! -L "${manifest}" ]] || { printf 'ERROR transaction manifest is absent or unsafe\n' >&2; return 1; }
  [[ "$(stat -c %u -- "${manifest}")" == 0 && "$(stat -c %a -- "${manifest}")" == 600 ]] || { printf 'ERROR transaction manifest ownership/mode is unsafe\n' >&2; return 1; }

  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    [[ "${line}" == *=* ]] || { printf 'ERROR malformed transaction manifest line\n' >&2; return 1; }
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${key}" =~ ^[A-Z][A-Z0-9_]*$ && -n "${value}" && ! "${value}" =~ [[:space:]] ]] || { printf 'ERROR unsafe transaction manifest value\n' >&2; return 1; }
    manifest_key_allowed "${key}" || { printf 'ERROR unknown transaction manifest key: %s\n' "${key}" >&2; return 1; }
  done < "${manifest}"
  for key in "${required_manifest_keys[@]}"; do
    count="$(grep -Ec "^${key}=" "${manifest}" || true)"
    [[ "${count}" == 1 ]] || { printf 'ERROR transaction key %s must occur exactly once\n' "${key}" >&2; return 1; }
  done

  [[ "$(data_value MANIFEST_VERSION "${manifest}")" == 1 ]] || return 1
  [[ "$(data_value TRANSACTION_ID "${manifest}")" == "${transaction_id}" ]] || return 1
  for key in PLAN_SHA256 MACHINE_ID_SHA256 APPLIED_BOOT_ID_SHA256 FSTAB_PRE_SHA256 FSTAB_POST_SHA256 ACTIVE_SWAP_PRE_SHA256 DESIRED_MODULES_SHA256 DESIRED_SYSCTL_SHA256; do
    [[ "$(data_value "${key}" "${manifest}")" =~ ^[0-9a-f]{64}$ ]] || { printf 'ERROR malformed transaction hash: %s\n' "${key}" >&2; return 1; }
  done
  for key in MODULES_PRESTATE SYSCTL_PRESTATE; do
    prestate="$(data_value "${key}" "${manifest}")"
    [[ "${prestate}" == absent || "${prestate}" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  done
  [[ "$(data_value SWAP_ACTION "${manifest}")" =~ ^(none|disable-fstab)$ ]] || return 1
  for key in OLD_VM_OVERCOMMIT_MEMORY OLD_VM_PANIC_ON_OOM OLD_KERNEL_PANIC OLD_KERNEL_PANIC_ON_OOPS OLD_KERNEL_KEYS_ROOT_MAXKEYS OLD_KERNEL_KEYS_ROOT_MAXBYTES OLD_NET_IPV4_IP_FORWARD OLD_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES OLD_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES; do
    old_sysctl_value_allowed "${key}" "$(data_value "${key}" "${manifest}")" || return 1
  done
  validate_late_sysctls "${manifest}" "${transaction_dir}" || return 1

  [[ -f "${transaction_dir}/fstab.pre" && ! -L "${transaction_dir}/fstab.pre" ]] || return 1
  [[ "$(sha256_file "${transaction_dir}/fstab.pre")" == "$(data_value FSTAB_PRE_SHA256 "${manifest}")" ]] || return 1
  [[ -f "${transaction_dir}/active-swaps.pre" && ! -L "${transaction_dir}/active-swaps.pre" ]] || return 1
  [[ "$(sha256_file "${transaction_dir}/active-swaps.pre")" == "$(data_value ACTIVE_SWAP_PRE_SHA256 "${manifest}")" ]] || return 1
  for key in MODULES SYSCTL; do
    prestate="$(data_value "${key}_PRESTATE" "${manifest}")"
    if [[ "${prestate}" == absent ]]; then
      [[ ! -e "${transaction_dir}/${key,,}.pre" ]] || return 1
    else
      [[ -f "${transaction_dir}/${key,,}.pre" && ! -L "${transaction_dir}/${key,,}.pre" ]] || return 1
      [[ "sha256:$(sha256_file "${transaction_dir}/${key,,}.pre")" == "${prestate}" ]] || return 1
    fi
  done
}

source_is_in_saved_swaps() {
  local source="$1"
  local saved_file="$2"
  grep -Fxq -- "${source}" "${saved_file}"
}

current_swaps_are_saved_subset() {
  local saved_file="$1"
  local source current_output
  if ! current_output="$(active_swap_sources)"; then
    return 1
  fi
  while IFS= read -r source; do
    [[ -z "${source}" ]] && continue
    source_is_in_saved_swaps "${source}" "${saved_file}" || return 1
  done <<<"${current_output}"
}

validate_active_state() {
  local allow_pending="${1:-no}"
  local key value count transaction_id manifest
  local -a state_keys=(
    STATE_VERSION STATUS TRANSACTION_ID PLAN_SHA256 MACHINE_ID_SHA256
    APPLIED_BOOT_ID_SHA256 DESIRED_MODULES_SHA256 DESIRED_SYSCTL_SHA256 SWAP_ACTION
  )
  [[ -f "${active_state}" && ! -L "${active_state}" ]] || { printf 'ERROR active state is absent or unsafe\n' >&2; return 1; }
  [[ "$(stat -c %u -- "${active_state}")" == 0 && "$(stat -c %a -- "${active_state}")" == 600 ]] || { printf 'ERROR active state ownership/mode is unsafe\n' >&2; return 1; }
  if [[ "${allow_pending}" != yes ]]; then
    [[ ! -e "${pending_state}" && ! -L "${pending_state}" ]] || { printf 'ERROR a pending transaction exists; recover before verification\n' >&2; return 1; }
  fi
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    [[ "${line}" == *=* ]] || return 1
    key="${line%%=*}"
    value="${line#*=}"
    case "${key}" in
      STATE_VERSION|STATUS|TRANSACTION_ID|PLAN_SHA256|MACHINE_ID_SHA256|APPLIED_BOOT_ID_SHA256|DESIRED_MODULES_SHA256|DESIRED_SYSCTL_SHA256|SWAP_ACTION) ;;
      *) printf 'ERROR unknown active-state key: %s\n' "${key}" >&2; return 1 ;;
    esac
    [[ -n "${value}" && ! "${value}" =~ [[:space:]] ]] || return 1
  done < "${active_state}"
  for key in "${state_keys[@]}"; do
    count="$(grep -Ec "^${key}=" "${active_state}" || true)"
    [[ "${count}" == 1 ]] || return 1
  done
  [[ "$(data_value STATE_VERSION "${active_state}")" == 1 ]] || return 1
  [[ "$(data_value STATUS "${active_state}")" == active ]] || return 1
  for key in PLAN_SHA256 MACHINE_ID_SHA256 APPLIED_BOOT_ID_SHA256 DESIRED_MODULES_SHA256 DESIRED_SYSCTL_SHA256; do
    [[ "$(data_value "${key}" "${active_state}")" =~ ^[0-9a-f]{64}$ ]] || return 1
  done
  [[ "$(data_value SWAP_ACTION "${active_state}")" =~ ^(none|disable-fstab)$ ]] || return 1
  [[ "$(data_value MACHINE_ID_SHA256 "${active_state}")" == "$(host_machine_id_sha256)" ]] || return 1
  transaction_id="$(data_value TRANSACTION_ID "${active_state}")"
  validate_transaction "${transaction_id}" || return 1
  manifest="${backup_root}/${transaction_id}/manifest"
  for key in PLAN_SHA256 MACHINE_ID_SHA256 APPLIED_BOOT_ID_SHA256 DESIRED_MODULES_SHA256 DESIRED_SYSCTL_SHA256 SWAP_ACTION; do
    [[ "$(data_value "${key}" "${active_state}")" == "$(data_value "${key}" "${manifest}")" ]] || return 1
  done
  for key in OLD_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES OLD_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES; do
    if [[ "$(data_value "${key}" "${manifest}")" == unavailable-until-module-load ]]; then
      [[ "$(data_value LATE_SYSCTLS_STATE "${manifest}")" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    fi
  done
}

check_transaction_rollback_ready() {
  local transaction_id="$1"
  local transaction_dir="${backup_root}/${transaction_id}"
  local manifest="${transaction_dir}/manifest"
  local modules_pre sysctl_pre fstab_pre fstab_post desired_modules desired_sysctl current_state

  validate_transaction "${transaction_id}" || return 1
  [[ "$(data_value MACHINE_ID_SHA256 "${manifest}")" == "$(host_machine_id_sha256)" ]] || { printf 'ERROR transaction belongs to a different machine identity\n' >&2; return 1; }
  modules_pre="$(data_value MODULES_PRESTATE "${manifest}")"
  sysctl_pre="$(data_value SYSCTL_PRESTATE "${manifest}")"
  fstab_pre="$(data_value FSTAB_PRE_SHA256 "${manifest}")"
  fstab_post="$(data_value FSTAB_POST_SHA256 "${manifest}")"
  desired_modules="sha256:$(data_value DESIRED_MODULES_SHA256 "${manifest}")"
  desired_sysctl="sha256:$(data_value DESIRED_SYSCTL_SHA256 "${manifest}")"
  current_state="$(file_state "${modules_target}")"
  [[ "${current_state}" == "${modules_pre}" || "${current_state}" == "${desired_modules}" ]] || { printf 'ERROR modules target drifted after apply; refusing rollback overwrite\n' >&2; return 1; }
  current_state="$(file_state "${sysctl_target}")"
  [[ "${current_state}" == "${sysctl_pre}" || "${current_state}" == "${desired_sysctl}" ]] || { printf 'ERROR sysctl target drifted after apply; refusing rollback overwrite\n' >&2; return 1; }
  [[ -f "${fstab_target}" && ! -L "${fstab_target}" ]] || return 1
  current_state="$(sha256_file "${fstab_target}")"
  [[ "${current_state}" == "${fstab_pre}" || "${current_state}" == "${fstab_post}" ]] || { printf 'ERROR /etc/fstab drifted after apply; refusing rollback overwrite\n' >&2; return 1; }
  current_swaps_are_saved_subset "${transaction_dir}/active-swaps.pre" || { printf 'ERROR active swap contains a source outside the transaction\n' >&2; return 1; }
}

transaction_old_sysctl_value() {
  local old_key="$1"
  local manifest="$2"
  local transaction_dir="$3"
  local value
  value="$(data_value "${old_key}" "${manifest}")"
  if [[ "${value}" != unavailable-until-module-load ]]; then
    printf '%s\n' "${value}"
    return 0
  fi
  if [[ ! -f "${transaction_dir}/module-load-sysctls.pre" ]]; then
    return 2
  fi
  value="$(data_value "${old_key}" "${transaction_dir}/module-load-sysctls.pre")"
  old_sysctl_value_allowed "${old_key}" "${value}" || return 1
  printf '%s\n' "${value}"
}

restore_transaction() {
  local transaction_id="$1"
  local transaction_dir="${backup_root}/${transaction_id}"
  local manifest="${transaction_dir}/manifest"
  local modules_pre sysctl_pre fstab_pre fstab_post desired_modules desired_sysctl
  local current_state index key old_key old_value old_status source current_sources failures=0 skipped_module_gated=0

  check_transaction_rollback_ready "${transaction_id}" || return 1
  modules_pre="$(data_value MODULES_PRESTATE "${manifest}")"
  sysctl_pre="$(data_value SYSCTL_PRESTATE "${manifest}")"
  fstab_pre="$(data_value FSTAB_PRE_SHA256 "${manifest}")"
  fstab_post="$(data_value FSTAB_POST_SHA256 "${manifest}")"
  desired_modules="sha256:$(data_value DESIRED_MODULES_SHA256 "${manifest}")"
  desired_sysctl="sha256:$(data_value DESIRED_SYSCTL_SHA256 "${manifest}")"

  if [[ "${modules_pre}" == absent ]]; then
    rm -f -- "${modules_target}" || failures=$((failures + 1))
  else
    atomic_restore_backup "${transaction_dir}/modules.pre" "${modules_target}" || failures=$((failures + 1))
  fi
  if [[ "${sysctl_pre}" == absent ]]; then
    rm -f -- "${sysctl_target}" || failures=$((failures + 1))
  else
    atomic_restore_backup "${transaction_dir}/sysctl.pre" "${sysctl_target}" || failures=$((failures + 1))
  fi
  atomic_restore_backup "${transaction_dir}/fstab.pre" "${fstab_target}" || failures=$((failures + 1))

  for index in "${!sysctl_keys[@]}"; do
    key="${sysctl_keys[${index}]}"
    old_key="OLD_${current_plan_keys[${index}]#CURRENT_}"
    old_status=0
    old_value="$(transaction_old_sysctl_value "${old_key}" "${manifest}" "${transaction_dir}")" || old_status=$?
    if (( old_status == 2 )); then
      skipped_module_gated=$((skipped_module_gated + 1))
      continue
    elif (( old_status != 0 )); then
      failures=$((failures + 1))
      continue
    fi
    sysctl -q -w "${key}=${old_value}" || failures=$((failures + 1))
  done

  current_sources="$(active_swap_sources 2>/dev/null || true)"
  while IFS= read -r source; do
    [[ -z "${source}" ]] && continue
    if ! grep -Fxq -- "${source}" <<<"${current_sources}"; then
      swapon -- "${source}" || failures=$((failures + 1))
    fi
  done < "${transaction_dir}/active-swaps.pre"

  [[ "$(file_state "${modules_target}")" == "${modules_pre}" ]] || failures=$((failures + 1))
  [[ "$(file_state "${sysctl_target}")" == "${sysctl_pre}" ]] || failures=$((failures + 1))
  [[ "$(sha256_file "${fstab_target}")" == "${fstab_pre}" ]] || failures=$((failures + 1))
  [[ "$(active_swap_sha256)" == "$(data_value ACTIVE_SWAP_PRE_SHA256 "${manifest}")" ]] || failures=$((failures + 1))
  for index in "${!sysctl_keys[@]}"; do
    key="${sysctl_keys[${index}]}"
    old_key="OLD_${current_plan_keys[${index}]#CURRENT_}"
    old_status=0
    old_value="$(transaction_old_sysctl_value "${old_key}" "${manifest}" "${transaction_dir}")" || old_status=$?
    if (( old_status == 2 )); then
      continue
    elif (( old_status != 0 )); then
      failures=$((failures + 1))
      continue
    fi
    [[ "$(sysctl -n "${key}" 2>/dev/null || true)" == "${old_value}" ]] || failures=$((failures + 1))
  done

  if (( failures > 0 )); then
    printf 'ERROR rollback is incomplete; use physical/LAN recovery and preserve %s\n' "${transaction_dir}" >&2
    return 1
  fi
  [[ ! -f "${active_state}" || "$(data_value TRANSACTION_ID "${active_state}")" != "${transaction_id}" ]] || rm -f -- "${active_state}"
  [[ ! -f "${pending_state}" || "$(<"${pending_state}")" != "${transaction_id}" ]] || rm -f -- "${pending_state}"
  printf 'ROLLED_BACK_UTC=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${transaction_dir}/ROLLED_BACK"
  chown root:root "${transaction_dir}/ROLLED_BACK"
  chmod 0600 "${transaction_dir}/ROLLED_BACK"
  printf 'PASS exact persistent files and recorded prior runtime sysctls/swap were restored\n'
  if (( skipped_module_gated > 0 )); then
    printf 'NOTICE %d module-gated sysctl(s) had no pre-load value; their natural loaded values remain until reboot\n' "${skipped_module_gated}"
  fi
  printf 'NOTICE modules loaded during apply remain loaded until a reviewed reboot\n'
}
