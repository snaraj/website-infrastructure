#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# Keep runtime resolution anchored to this reviewed script while giving static
# analysis the exact repository-controlled library that defines shared state.
# shellcheck source=bootstrap/pi/host-prerequisites/lib.sh
source "${script_dir}/lib.sh"

if [[ $# -ne 0 ]]; then
  printf 'Usage: %s\n' "$0" >&2
  exit 2
fi
[[ "$(uname -s)" == Linux ]] || host_prereq_die 'discovery must run on the target Linux host'
require_root
require_commands
validate_desired_sources

assert_safe_existing_directory /etc/modules-load.d
assert_safe_existing_directory /etc/sysctl.d
[[ -f "${fstab_target}" && ! -L "${fstab_target}" ]] || host_prereq_die '/etc/fstab must be a regular, non-symlink file'

mechanism="$(detect_swap_mechanism)"
case "${mechanism}" in
  none)
    swap_action=none
    ;;
  fstab-only)
    swap_action=disable-fstab
    ;;
  *)
    mechanism=UNRESOLVED_UNKNOWN
    swap_action=UNRESOLVED_REFUSE
    ;;
esac

printf '# Root-only host-prerequisites plan generated read-only at %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '# Review every value locally. Change only PLAN_STATUS after approval.\n'
printf '# Unknown/mixed swap remains intentionally invalid and requires a new reviewed implementation.\n'
printf 'PLAN_VERSION=1\n'
printf 'PLAN_STATUS=review-required\n'
printf 'MODULES_TARGET=%s\n' "${modules_target}"
printf 'SYSCTL_TARGET=%s\n' "${sysctl_target}"
printf 'FSTAB_TARGET=%s\n' "${fstab_target}"
printf 'BACKUP_ROOT=%s\n' "${backup_root}"
printf 'STATE_ROOT=%s\n' "${state_root}"
printf 'DESIRED_MODULES=overlay,br_netfilter\n'
printf 'EXPECTED_ARCHITECTURE=%s\n' "$(uname -m)"
printf 'EXPECTED_KERNEL_RELEASE=%s\n' "$(uname -r)"
printf 'EXPECTED_MACHINE_ID_SHA256=%s\n' "$(host_machine_id_sha256)"
printf 'EXPECTED_BOOT_ID_SHA256=%s\n' "$(host_boot_id_sha256)"
printf 'EXPECTED_OS_RELEASE_SHA256=%s\n' "$(host_os_release_sha256)"
printf 'EXPECTED_MODULES_TARGET_STATE=%s\n' "$(file_state "${modules_target}")"
printf 'EXPECTED_SYSCTL_TARGET_STATE=%s\n' "$(file_state "${sysctl_target}")"
printf 'EXPECTED_FSTAB_SHA256=%s\n' "$(sha256_file "${fstab_target}")"
printf 'EXPECTED_ACTIVE_SWAP_SHA256=%s\n' "$(active_swap_sha256)"
printf 'DESIRED_MODULES_SHA256=%s\n' "$(sha256_file "${modules_source}")"
printf 'DESIRED_SYSCTL_SHA256=%s\n' "$(sha256_file "${sysctl_source}")"
printf 'SWAP_MECHANISM=%s\n' "${mechanism}"
printf 'SWAP_ACTION=%s\n' "${swap_action}"

for index in "${!sysctl_keys[@]}"; do
  value="$(observed_sysctl_value "${sysctl_keys[${index}]}" || true)"
  [[ -n "${value}" ]] || value=UNRESOLVED_UNAVAILABLE
  printf '%s=%s\n' "${current_plan_keys[${index}]}" "${value}"
done
for index in "${!sysctl_keys[@]}"; do
  desired_key="${current_plan_keys[${index}]#CURRENT_}"
  printf 'DESIRED_%s=%s\n' "${desired_key}" "${desired_values[${index}]}"
done

printf '# Discovery made no intentional changes. This output is not approval.\n'
