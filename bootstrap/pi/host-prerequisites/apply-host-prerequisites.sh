#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# Keep runtime resolution anchored to this reviewed script while giving static
# analysis the exact repository-controlled library that defines shared state.
# shellcheck source=bootstrap/pi/host-prerequisites/lib.sh
source "${script_dir}/lib.sh"

mode=check
plan_path=''
while (( $# > 0 )); do
  case "$1" in
    --check)
      mode=check
      shift
      ;;
    --apply)
      mode=apply
      shift
      ;;
    --plan)
      (( $# >= 2 )) || { printf 'ERROR --plan requires a path\n' >&2; exit 2; }
      plan_path="$2"
      shift 2
      ;;
    *)
      printf 'Usage: %s [--check|--apply] --plan ROOT_OWNED_PLAN\n' "$0" >&2
      exit 2
      ;;
  esac
done
[[ -n "${plan_path}" ]] || { printf 'ERROR --plan is required\n' >&2; exit 2; }
[[ "$(uname -s)" == Linux ]] || host_prereq_die 'host prerequisites must run on the target Linux host'
require_root
require_commands

check_host_against_plan "${plan_path}"
plan_sha256="$(sha256_file "${plan_path}")"
swap_action="$(plan_value SWAP_ACTION "${plan_path}")"

printf 'PLAN_SHA256=%s\n' "${plan_sha256}"
printf 'APPLY_ACK=apply-reviewed-host-prerequisites-%s\n' "${plan_sha256}"
if [[ "${swap_action}" == disable-fstab ]]; then
  printf 'SWAP_ACK=disable-reviewed-fstab-swap-%s\n' "$(plan_value EXPECTED_ACTIVE_SWAP_SHA256 "${plan_path}")"
fi
printf 'REBOOT_ACK=verify-host-prerequisites-after-reboot\n'

if [[ "${mode}" == check ]]; then
  printf 'PASS check completed without intentional changes\n'
  exit 0
fi

[[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || host_prereq_die 'PHYSICAL_OR_LAN_RECOVERY_TESTED=yes is required'
[[ "${CONFIRM_HOST_PREREQUISITES:-}" == "apply-reviewed-host-prerequisites-${plan_sha256}" ]] || host_prereq_die 'CONFIRM_HOST_PREREQUISITES does not match this exact plan hash'
[[ "${CONFIRM_REBOOT_VERIFICATION:-}" == verify-host-prerequisites-after-reboot ]] || host_prereq_die 'CONFIRM_REBOOT_VERIFICATION=verify-host-prerequisites-after-reboot is required'
if [[ "${swap_action}" == disable-fstab ]]; then
  expected_swap_ack="disable-reviewed-fstab-swap-$(plan_value EXPECTED_ACTIVE_SWAP_SHA256 "${plan_path}")"
  [[ "${CONFIRM_SWAP_CHANGE:-}" == "${expected_swap_ack}" ]] || host_prereq_die 'CONFIRM_SWAP_CHANGE does not match the exact reviewed swap set'
else
  [[ -z "${CONFIRM_SWAP_CHANGE:-}" ]] || host_prereq_die 'CONFIRM_SWAP_CHANGE must be unset when the plan makes no swap change'
fi

exec 9>"${lock_path}"
flock -n 9 || host_prereq_die 'another host-prerequisites operation holds the lock'

# Repeat every live gate after acquiring the mutation lock.
check_host_against_plan "${plan_path}"
[[ ! -e "${active_state}" && ! -L "${active_state}" ]] || host_prereq_die 'an active host-prerequisites state already exists; verify or roll it back first'
[[ ! -e "${pending_state}" && ! -L "${pending_state}" ]] || host_prereq_die 'a pending transaction exists; recover it before applying again'

assert_safe_existing_directory /var/backups
assert_safe_existing_directory /var/lib
ensure_private_directory /var/backups/website-infrastructure
ensure_private_directory "${backup_root}"
ensure_private_directory /var/lib/website-infrastructure
ensure_private_directory "${state_root}"

umask 077
transaction_id="$(date -u +%Y%m%dT%H%M%SZ)-$(host_boot_id_sha256 | cut -c1-12)-$$"
transaction_dir="${backup_root}/${transaction_id}"
mkdir -m 0700 -- "${transaction_dir}"
chown root:root "${transaction_dir}"

modules_prestate="$(file_state "${modules_target}")"
sysctl_prestate="$(file_state "${sysctl_target}")"
fstab_pre_sha256="$(sha256_file "${fstab_target}")"
active_swap_sources | LC_ALL=C sort -u > "${transaction_dir}/active-swaps.pre"
chmod 0600 "${transaction_dir}/active-swaps.pre"
chown root:root "${transaction_dir}/active-swaps.pre"
active_swap_pre_sha256="$(sha256_file "${transaction_dir}/active-swaps.pre")"

cp -a -- "${fstab_target}" "${transaction_dir}/fstab.pre"
if [[ "${modules_prestate}" != absent ]]; then
  cp -a -- "${modules_target}" "${transaction_dir}/modules.pre"
fi
if [[ "${sysctl_prestate}" != absent ]]; then
  cp -a -- "${sysctl_target}" "${transaction_dir}/sysctl.pre"
fi

if [[ "${swap_action}" == disable-fstab ]]; then
  awk '
    $0 !~ /^[[:space:]]*#/ && NF >= 3 && $3 == "swap" {
      print "# website-infrastructure-disabled-swap " $0
      next
    }
    { print }
  ' "${fstab_target}" > "${transaction_dir}/fstab.post"
  if awk '$0 !~ /^[[:space:]]*#/ && NF >= 3 && $3 == "swap" {found=1} END {exit found ? 0 : 1}' "${transaction_dir}/fstab.post"; then
    host_prereq_die 'candidate /etc/fstab still contains an active swap declaration'
  fi
  findmnt --verify --tab-file "${transaction_dir}/fstab.post" >/dev/null
else
  cp -- "${fstab_target}" "${transaction_dir}/fstab.post"
fi
chmod 0600 "${transaction_dir}/fstab.post"
chown root:root "${transaction_dir}/fstab.post"
fstab_post_sha256="$(sha256_file "${transaction_dir}/fstab.post")"

manifest="${transaction_dir}/manifest"
{
  printf 'MANIFEST_VERSION=1\n'
  printf 'TRANSACTION_ID=%s\n' "${transaction_id}"
  printf 'PLAN_SHA256=%s\n' "${plan_sha256}"
  printf 'MACHINE_ID_SHA256=%s\n' "$(host_machine_id_sha256)"
  printf 'APPLIED_BOOT_ID_SHA256=%s\n' "$(host_boot_id_sha256)"
  printf 'MODULES_PRESTATE=%s\n' "${modules_prestate}"
  printf 'SYSCTL_PRESTATE=%s\n' "${sysctl_prestate}"
  printf 'FSTAB_PRE_SHA256=%s\n' "${fstab_pre_sha256}"
  printf 'FSTAB_POST_SHA256=%s\n' "${fstab_post_sha256}"
  printf 'ACTIVE_SWAP_PRE_SHA256=%s\n' "${active_swap_pre_sha256}"
  printf 'DESIRED_MODULES_SHA256=%s\n' "$(sha256_file "${modules_source}")"
  printf 'DESIRED_SYSCTL_SHA256=%s\n' "$(sha256_file "${sysctl_source}")"
  printf 'SWAP_ACTION=%s\n' "${swap_action}"
  printf 'LATE_SYSCTLS_STATE=absent\n'
  for index in "${!sysctl_keys[@]}"; do
    printf 'OLD_%s=%s\n' "${current_plan_keys[${index}]#CURRENT_}" "$(plan_value "${current_plan_keys[${index}]}" "${plan_path}")"
  done
} > "${manifest}"
chmod 0600 "${manifest}"
chown root:root "${manifest}"
validate_transaction "${transaction_id}" || host_prereq_die 'prepared rollback transaction did not validate'

printf '%s\n' "${transaction_id}" > "${pending_state}"
chmod 0600 "${pending_state}"
chown root:root "${pending_state}"

state_temporary=''
late_sysctls_temporary=''
manifest_temporary=''
on_apply_error() {
  local original_status=$?
  trap - ERR
  set +e
  if [[ -n "${state_temporary}" && "${state_temporary}" == "${state_root}/.active."* ]]; then
    rm -f -- "${state_temporary}"
  fi
  if [[ -n "${late_sysctls_temporary}" && "${late_sysctls_temporary}" == "${transaction_dir}/.module-load-sysctls."* ]]; then
    rm -f -- "${late_sysctls_temporary}"
  fi
  if [[ -n "${manifest_temporary}" && "${manifest_temporary}" == "${transaction_dir}/.manifest."* ]]; then
    rm -f -- "${manifest_temporary}"
  fi
  printf 'ERROR apply failed; attempting the exact prepared rollback %s\n' "${transaction_id}" >&2
  if ! restore_transaction "${transaction_id}"; then
    printf 'ERROR automatic rollback failed; preserve %s and use physical/LAN recovery\n' "${transaction_dir}" >&2
  fi
  exit "${original_status}"
}
trap on_apply_error ERR

atomic_install_root_file "${modules_source}" "${modules_target}"
atomic_install_root_file "${sysctl_source}" "${sysctl_target}"
for module in "${required_modules[@]}"; do
  modprobe "${module}"
done

late_sysctls_temporary="$(mktemp "${transaction_dir}/.module-load-sysctls.XXXXXX")"
late_sysctl_count=0
for index in "${!sysctl_keys[@]}"; do
  old_key="OLD_${current_plan_keys[${index}]#CURRENT_}"
  if [[ "$(data_value "${old_key}" "${manifest}")" == unavailable-until-module-load ]]; then
    late_value="$(sysctl -n "${sysctl_keys[${index}]}")"
    if ! old_sysctl_value_allowed "${old_key}" "${late_value}"; then
      printf 'ERROR module-loaded default for %s is unsafe\n' "${sysctl_keys[${index}]}" >&2
      false
    fi
    printf '%s=%s\n' "${old_key}" "${late_value}" >> "${late_sysctls_temporary}"
    late_sysctl_count=$((late_sysctl_count + 1))
  fi
done
if (( late_sysctl_count > 0 )); then
  chmod 0600 "${late_sysctls_temporary}"
  chown root:root "${late_sysctls_temporary}"
  mv -fT -- "${late_sysctls_temporary}" "${transaction_dir}/module-load-sysctls.pre"
  late_sysctls_sha256="$(sha256_file "${transaction_dir}/module-load-sysctls.pre")"
  manifest_temporary="$(mktemp "${transaction_dir}/.manifest.XXXXXX")"
  awk -v state="sha256:${late_sysctls_sha256}" '
    /^LATE_SYSCTLS_STATE=/ { print "LATE_SYSCTLS_STATE=" state; next }
    { print }
  ' "${manifest}" > "${manifest_temporary}"
  chmod 0600 "${manifest_temporary}"
  chown root:root "${manifest_temporary}"
  mv -fT -- "${manifest_temporary}" "${manifest}"
else
  rm -f -- "${late_sysctls_temporary}"
fi
if ! validate_transaction "${transaction_id}"; then
  printf 'ERROR module-loaded rollback values did not validate\n' >&2
  false
fi
sysctl -q -p "${sysctl_target}"

if [[ "${swap_action}" == disable-fstab ]]; then
  atomic_install_matching_target "${transaction_dir}/fstab.post" "${fstab_target}"
  while IFS= read -r source; do
    [[ -z "${source}" ]] && continue
    swapoff -- "${source}"
  done < "${transaction_dir}/active-swaps.pre"
fi

verify_desired_host_contract

state_temporary="$(mktemp "${state_root}/.active.XXXXXX")"
{
  printf 'STATE_VERSION=1\n'
  printf 'STATUS=active\n'
  printf 'TRANSACTION_ID=%s\n' "${transaction_id}"
  printf 'PLAN_SHA256=%s\n' "${plan_sha256}"
  printf 'MACHINE_ID_SHA256=%s\n' "$(host_machine_id_sha256)"
  printf 'APPLIED_BOOT_ID_SHA256=%s\n' "$(host_boot_id_sha256)"
  printf 'DESIRED_MODULES_SHA256=%s\n' "$(sha256_file "${modules_source}")"
  printf 'DESIRED_SYSCTL_SHA256=%s\n' "$(sha256_file "${sysctl_source}")"
  printf 'SWAP_ACTION=%s\n' "${swap_action}"
} > "${state_temporary}"
chmod 0600 "${state_temporary}"
chown root:root "${state_temporary}"
mv -fT -- "${state_temporary}" "${active_state}"
rm -f -- "${pending_state}"

bash "${script_dir}/verify-host-prerequisites.sh" --post-apply
trap - ERR
printf 'PASS host prerequisites applied with rollback transaction %s\n' "${transaction_id}"
printf 'NEXT reboot, then run: sudo bash %s/verify-host-prerequisites.sh --post-reboot\n' "${script_dir}"
