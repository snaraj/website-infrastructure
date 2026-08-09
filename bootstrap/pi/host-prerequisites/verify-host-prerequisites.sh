#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# Keep runtime resolution anchored to this reviewed script while giving static
# analysis the exact repository-controlled library that defines shared state.
# shellcheck source=bootstrap/pi/host-prerequisites/lib.sh
source "${script_dir}/lib.sh"

if [[ $# -ne 1 || ! "${1}" =~ ^--post-(apply|reboot)$ ]]; then
  printf 'Usage: %s --post-apply|--post-reboot\n' "$0" >&2
  exit 2
fi
phase="${1#--post-}"
[[ "$(uname -s)" == Linux ]] || host_prereq_die 'verification must run on the target Linux host'
require_root
require_commands
validate_active_state || host_prereq_die 'active host-prerequisites state failed validation'

applied_boot_id="$(data_value APPLIED_BOOT_ID_SHA256 "${active_state}")"
current_boot_id="$(host_boot_id_sha256)"
if [[ "${phase}" == apply ]]; then
  [[ "${current_boot_id}" == "${applied_boot_id}" ]] || host_prereq_die 'post-apply verification must run in the original apply boot'
else
  [[ "${current_boot_id}" != "${applied_boot_id}" ]] || host_prereq_die 'post-reboot verification requires evidence of a different boot ID'
fi

[[ "$(sha256_file "${modules_source}")" == "$(data_value DESIRED_MODULES_SHA256 "${active_state}")" ]] || host_prereq_die 'repository modules source changed after apply'
[[ "$(sha256_file "${sysctl_source}")" == "$(data_value DESIRED_SYSCTL_SHA256 "${active_state}")" ]] || host_prereq_die 'repository sysctl source changed after apply'
verify_desired_host_contract || host_prereq_die "${phase} host-prerequisites persistence verification failed"

transaction_id="$(data_value TRANSACTION_ID "${active_state}")"
printf 'PASS %s verification proved exact files, loaded modules, runtime sysctls, and no swap\n' "${phase}"
printf 'ROLLBACK_TRANSACTION=%s\n' "${transaction_id}"
if [[ "${phase}" == reboot ]]; then
  printf 'PASS boot ID changed, so persistence was exercised by a real reboot\n'
fi
