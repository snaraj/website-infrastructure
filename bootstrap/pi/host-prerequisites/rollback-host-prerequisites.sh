#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# Keep runtime resolution anchored to this reviewed script while giving static
# analysis the exact repository-controlled library that defines shared state.
# shellcheck source=bootstrap/pi/host-prerequisites/lib.sh
source "${script_dir}/lib.sh"

mode=check
transaction_id=''
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
    --transaction)
      (( $# >= 2 )) || { printf 'ERROR --transaction requires an ID\n' >&2; exit 2; }
      transaction_id="$2"
      shift 2
      ;;
    *)
      printf 'Usage: %s [--check|--apply] --transaction TRANSACTION_ID\n' "$0" >&2
      exit 2
      ;;
  esac
done
[[ -n "${transaction_id}" ]] || { printf 'ERROR --transaction is required\n' >&2; exit 2; }
[[ "$(uname -s)" == Linux ]] || host_prereq_die 'rollback must run on the target Linux host'
require_root
require_commands

transaction_is_referenced=no
if [[ -f "${pending_state}" && ! -L "${pending_state}" ]]; then
  [[ "$(stat -c %u -- "${pending_state}")" == 0 && "$(stat -c %a -- "${pending_state}")" == 600 ]] || host_prereq_die 'pending transaction ownership/mode is unsafe'
  [[ "$(<"${pending_state}")" == "${transaction_id}" ]] || host_prereq_die 'pending state references a different transaction'
  if [[ -e "${active_state}" || -L "${active_state}" ]]; then
    validate_active_state yes || host_prereq_die 'active state beside pending transaction failed validation'
    [[ "$(data_value TRANSACTION_ID "${active_state}")" == "${transaction_id}" ]] || host_prereq_die 'active and pending states reference different transactions'
  fi
  transaction_is_referenced=yes
elif [[ -f "${active_state}" && ! -L "${active_state}" ]]; then
  validate_active_state || host_prereq_die 'active state failed validation'
  [[ "$(data_value TRANSACTION_ID "${active_state}")" == "${transaction_id}" ]] || host_prereq_die 'active state references a different transaction'
  transaction_is_referenced=yes
fi
[[ "${transaction_is_referenced}" == yes ]] || host_prereq_die 'transaction is not the active or pending host-prerequisites state'
check_transaction_rollback_ready "${transaction_id}" || host_prereq_die 'transaction is not safe to roll back'

printf 'ROLLBACK_ACK=rollback-host-prerequisites-%s\n' "${transaction_id}"
printf 'NOTICE rollback restores persistent files and prior runtime sysctls/swap; loaded modules remain until reboot\n'
if [[ "${mode}" == check ]]; then
  printf 'PASS rollback check completed without intentional changes\n'
  exit 0
fi

[[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || host_prereq_die 'PHYSICAL_OR_LAN_RECOVERY_TESTED=yes is required'
[[ "${CONFIRM_HOST_PREREQUISITES_ROLLBACK:-}" == "rollback-host-prerequisites-${transaction_id}" ]] || host_prereq_die 'CONFIRM_HOST_PREREQUISITES_ROLLBACK does not match this transaction'

exec 9>"${lock_path}"
flock -n 9 || host_prereq_die 'another host-prerequisites operation holds the lock'
check_transaction_rollback_ready "${transaction_id}" || host_prereq_die 'transaction changed while waiting for the lock'
restore_transaction "${transaction_id}"
printf 'NEXT perform a reviewed reboot if unloading the two prerequisite modules is required\n'
