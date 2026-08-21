#!/usr/bin/env bash
# Offline/pre-kubeadm installer for the SSH-only ingress guard (PLAT-DEC-001).
# Active clusters must use the distinct retrofit transaction. This entrypoint
# deliberately keeps the KUBELET_ALREADY_ACTIVE refusal.

set -Eeuo pipefail
set +x
set +o history
umask 077

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

launch_revision="${INGRESS_GUARD_SOURCE_REVISION:-}"
launch_manifest="${INGRESS_GUARD_MANIFEST_SHA256:-}"
custody_dir="${INGRESS_GUARD_LAUNCH_CUSTODY_DIR:-}"
transaction_library="${INGRESS_GUARD_TRANSACTION_LIBRARY:-}"
[[ "${INGRESS_GUARD_LAUNCH_VERIFIED:-}" == "${launch_revision}:${launch_manifest}" && \
  "${custody_dir}" == "/var/lib/website-infrastructure/ingress-guard/custody/${launch_manifest}" && \
  "${transaction_library}" =~ ^/proc/self/fd/[0-9]+$ ]] || {
  printf 'INGRESS-GUARD INSTALL FAIL TRUSTED_LAUNCH_REQUIRED\n' >&2
  exit 1
}
# shellcheck source=bootstrap/pi/ingress-guard/transaction-lib.sh
source "${transaction_library}"

readonly etc_dir=/etc/website-infrastructure
readonly library_parent=/usr/local/lib/website-infrastructure
readonly library_dir="${library_parent}/ingress-guard"
readonly contract_target="${etc_dir}/admin-ingress.env"
readonly contract_validator_target="${library_dir}/validate_admin_ingress_contract.py"
readonly model_validator_target="${library_dir}/validate_ingress_guard.py"
readonly transaction_lib_target="${library_dir}/transaction-lib.sh"
readonly loader_target=/usr/local/sbin/website-infrastructure-ingress-guard-load
readonly verify_target=/usr/local/sbin/website-infrastructure-ingress-guard-verify
readonly recover_target=/usr/local/sbin/website-infrastructure-ingress-guard-recover
readonly retrofit_target=/usr/local/sbin/website-infrastructure-ingress-guard-retrofit
readonly unit_target=/etc/systemd/system/website-infrastructure-ingress-guard.service
readonly dropin_dir=/etc/systemd/system/kubelet.service.d
readonly dropin_target="${dropin_dir}/50-website-infrastructure-ingress-guard.conf"

contract_source="${IG_CONTRACT_INPUT}"
contract_validator_source="${custody_dir}/scripts/validate_admin_ingress_contract.py"
model_validator_source="${custody_dir}/scripts/validate_ingress_guard.py"
transaction_lib_source="${custody_dir}/bootstrap/pi/ingress-guard/transaction-lib.sh"
loader_source="${custody_dir}/bootstrap/pi/ingress-guard/load-ingress-guard.sh"
verify_source="${custody_dir}/bootstrap/pi/ingress-guard/verify-ingress-guard.sh"
recover_source="${custody_dir}/bootstrap/pi/ingress-guard/recover-ingress-guard.sh"
retrofit_source="${custody_dir}/bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh"
unit_source="${custody_dir}/bootstrap/pi/ingress-guard/systemd/website-infrastructure-ingress-guard.service"
dropin_source="${custody_dir}/bootstrap/pi/ingress-guard/systemd/kubelet.service.d/50-website-infrastructure-ingress-guard.conf"

mutation_started=no
lock_held=no
capture=''

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [[ "${lock_held}" == yes ]]; then
    flock -u 9 >/dev/null 2>&1 || true
    exec 9>&-
    lock_held=no
  fi
  if (( status != 0 )) && [[ "${mutation_started}" == yes ]]; then
    INGRESS_GUARD_AUTOMATIC_RECOVERY=journal-bound \
      INGRESS_GUARD_TRANSACTION_LIBRARY="${INGRESS_GUARD_RECOVERY_LIBRARY:-}" \
      /bin/bash "${INGRESS_GUARD_RECOVERY_ENTRY:-/nonexistent}" --automatic >/dev/null 2>&1
    recovery_status=$?
    case "${recovery_status}" in
      0) printf 'INGRESS-GUARD INSTALL FAIL ROLLED_BACK_VERIFIED\n' >&2 ;;
      20) printf 'INGRESS-GUARD INSTALL FAIL REBOOT_PENDING_RECONCILED\n' >&2 ;;
      21) printf 'INGRESS-GUARD INSTALL FAIL COMMIT_RECONCILED\n' >&2 ;;
      *) printf 'INGRESS-GUARD INSTALL FAIL RECOVERY_REQUIRED\n' >&2 ;;
    esac
  fi
  [[ -z "${capture}" ]] || rm -f -- "${capture}" >/dev/null 2>&1 || true
  exit "${status}"
}

trap on_exit EXIT
trap 'trap "" HUP INT TERM; exit 129' HUP
trap 'trap "" HUP INT TERM; exit 130' INT
trap 'trap "" HUP INT TERM; exit 143' TERM

[[ "${EUID}" -eq 0 ]] || ig_die NOT_ROOT
[[ -t 0 && -t 1 && -t 2 ]] || ig_die DIRECT_TTY_REQUIRED
if [[ -n "${SSH_CONNECTION:-}" && \
  ( -z "${SUDO_USER:-}" || "${SUDO_USER}" == root ) ]]; then
  ig_die ROOT_SSH_FORBIDDEN
fi
IG_SOURCE_REVISION="${launch_revision}"
IG_MANIFEST_SHA256="${launch_manifest}"
IG_CUSTODY_RECEIPT_SHA256="${INGRESS_GUARD_CUSTODY_RECEIPT_SHA256:-}"
IG_CUSTODY_DIR="${custody_dir}"
requested_source_revision="${IG_SOURCE_REVISION}"
requested_manifest_sha256="${IG_MANIFEST_SHA256}"
requested_custody_receipt_sha256="${IG_CUSTODY_RECEIPT_SHA256}"
[[ "${CONFIRM_INGRESS_GUARD_INSTALL:-}" == \
  "install-reviewed-ssh-only-ingress-guard-${IG_SOURCE_REVISION}-${IG_MANIFEST_SHA256}" ]] \
  || ig_die EXACT_CONFIRMATION_MISSING

ig_require_commands
ig_bootstrap_state_roots
ig_validate_public_binding
ig_verify_bundle
ig_verify_custody_receipt
ig_verify_custody_contract

kubelet_state="$(ig_systemctl_state kubelet.service ActiveState)" \
  || ig_die KUBELET_STATE_INVALID
if [[ "${kubelet_state}" == active ]]; then
  ig_die KUBELET_ALREADY_ACTIVE
fi
[[ "${kubelet_state}" == inactive ]] || ig_die KUBELET_STATE_INVALID

# The reviewed private file is created directly under the root-owned input
# directory; no private inventory is staged in or reopened from the checkout.
ig_assert_root_file "${contract_source}" 600 || ig_die PRIVATE_CONTRACT_CUSTODY_INVALID
ig_run_bounded python3 -I -B "${contract_validator_source}" CONTRACT "${contract_source}" >/dev/null \
  || ig_die STAGED_CONTRACT_INVALID

ig_acquire_lock
lock_held=yes
if [[ -e "${IG_JOURNAL_PATH}" || -L "${IG_JOURNAL_PATH}" ]]; then
  ig_load_journal
  [[ "${IG_PHASE}" == rolled-back ]] || ig_die TRANSACTION_RECORD_EXISTS
  prior_receipt="$(ig_journal_receipt_path)" || ig_die CLOSED_RECEIPT_INVALID
  ig_assert_root_file "${prior_receipt}" 600 || ig_die CLOSED_RECEIPT_INVALID
  [[ "$(ig_secure_root_file_sha256 "${prior_receipt}" 0600 16384)" == \
    "${IG_RECEIPT_SHA256}" ]] \
    || ig_die CLOSED_RECEIPT_INVALID
  IG_SOURCE_REVISION="${requested_source_revision}"
  IG_MANIFEST_SHA256="${requested_manifest_sha256}"
  IG_CUSTODY_RECEIPT_SHA256="${requested_custody_receipt_sha256}"
  IG_CUSTODY_DIR="${custody_dir}"
  ig_verify_custody_receipt
fi

kubelet_state="$(ig_systemctl_state kubelet.service ActiveState)" \
  || ig_die KUBELET_STATE_INVALID
[[ "${kubelet_state}" == inactive ]] || ig_die KUBELET_STATE_CHANGED

ig_assert_directory /etc/systemd/system 755 || ig_die SYSTEM_DIRECTORY_INVALID
ig_assert_directory /usr/local/sbin 755 || ig_die SYSTEM_DIRECTORY_INVALID
ig_assert_directory /usr/local/lib 755 || ig_die SYSTEM_DIRECTORY_INVALID

capture="$(mktemp "${IG_TRANSACTION_ROOT}/.prestate.XXXXXXXX")"
chmod 0600 -- "${capture}"
IG_TABLE_PRESTATE="$(ig_table_prestate "${capture}" "${model_validator_source}" "${contract_source}")"
[[ "${IG_TABLE_PRESTATE}" == absent ]] || ig_die PREEXISTING_STATE
IG_GUARD_ENABLED_PRESTATE="$(ig_unit_enabled_state)" || ig_die UNIT_STATE_INVALID
IG_KUBELET_PRESTATE=inactive

IG_PRE_ETC_DIR="$(ig_directory_prestate "${etc_dir}" 700)"
IG_PRE_VENDOR_DIR="$(ig_directory_prestate "${library_parent}" 755)"
IG_PRE_LIBRARY_DIR="$(ig_directory_prestate "${library_dir}" 755)"
IG_PRE_DROPIN_DIR="$(ig_directory_prestate "${dropin_dir}" 755)"
IG_PRE_CONTRACT="$(ig_file_prestate "${contract_target}" "${contract_source}" 600)"
IG_PRE_CONTRACT_VALIDATOR="$(ig_file_prestate "${contract_validator_target}" "${contract_validator_source}" 600)"
IG_PRE_MODEL_VALIDATOR="$(ig_file_prestate "${model_validator_target}" "${model_validator_source}" 600)"
IG_PRE_TRANSACTION_LIB="$(ig_file_prestate "${transaction_lib_target}" "${transaction_lib_source}" 600)"
IG_PRE_LOADER="$(ig_file_prestate "${loader_target}" "${loader_source}" 700)"
IG_PRE_VERIFY="$(ig_file_prestate "${verify_target}" "${verify_source}" 700)"
IG_PRE_RECOVER="$(ig_file_prestate "${recover_target}" "${recover_source}" 700)"
IG_PRE_RETROFIT="$(ig_file_prestate "${retrofit_target}" "${retrofit_source}" 700)"
IG_PRE_UNIT="$(ig_file_prestate "${unit_target}" "${unit_source}" 644)"
IG_PRE_DROPIN="$(ig_file_prestate "${dropin_target}" "${dropin_source}" 644)"
ig_verify_guard_unit_prestate "${unit_target}" "${IG_PRE_UNIT}" \
  || ig_die GUARD_UNIT_PRESTATE_INVALID
if [[ "${IG_PRE_DROPIN}" == absent ]]; then
  ig_verify_kubelet_dependency_absent || ig_die KUBELET_DEPENDENCY_PRESTATE_INVALID
fi

# The complete prestate is durable before the first system destination changes.
IG_ATTEMPT_ID="$(ig_secure_uuid)" || ig_die BOOT_BINDING_INVALID
IG_BOOT_BINDING="$(ig_secure_boot_sha256)" || ig_die BOOT_BINDING_INVALID
IG_CLOSURE_BOOT_BINDING=not-applicable
IG_CLUSTER_BINDING=not-applicable
IG_ATTESTATION_SHA256=not-applicable
IG_CLUSTER_HEALTH_SCOPE=not-applicable
IG_MODE=offline
IG_PHASE=prepared
IG_RECEIPT_SHA256=none
ig_journal_write
mutation_started=yes

ig_ensure_directory "${etc_dir}" 0700
ig_ensure_directory "${library_parent}" 0755
ig_ensure_directory "${library_dir}" 0755
ig_ensure_directory "${dropin_dir}" 0755
ig_install_exact "${contract_source}" "${contract_target}" 600
ig_install_exact "${contract_validator_source}" "${contract_validator_target}" 600
ig_install_exact "${model_validator_source}" "${model_validator_target}" 600
ig_install_exact "${transaction_lib_source}" "${transaction_lib_target}" 600
ig_install_exact "${loader_source}" "${loader_target}" 700
ig_install_exact "${verify_source}" "${verify_target}" 700
ig_install_exact "${recover_source}" "${recover_target}" 700
ig_install_exact "${retrofit_source}" "${retrofit_target}" 700
ig_install_exact "${unit_source}" "${unit_target}" 644
ig_install_exact "${dropin_source}" "${dropin_target}" 644

IG_PHASE=artifacts-installed
ig_journal_write
ig_run_bounded systemctl daemon-reload >/dev/null 2>&1 || ig_die DAEMON_RELOAD_FAILED
if [[ "${IG_GUARD_ENABLED_PRESTATE}" == disabled ]]; then
  ig_run_bounded systemctl enable "${IG_GUARD_UNIT}" >/dev/null 2>&1 || ig_die ENABLE_FAILED
fi

IG_PHASE=guard-start-intent
ig_journal_write
# Queue the service while holding the global lock, then release so the loader
# can acquire the same lock. The prepared journal blocks any second transaction.
ig_run_bounded systemctl start --no-block "${IG_GUARD_UNIT}" >/dev/null 2>&1 || ig_die GUARD_START_FAILED
ig_release_lock
lock_held=no
if ! ig_run_bounded systemctl start "${IG_GUARD_UNIT}" >/dev/null 2>&1; then
  ig_acquire_lock_wait
  lock_held=yes
  ig_die GUARD_START_FAILED
fi
ig_acquire_lock_wait
lock_held=yes

IG_PHASE=guard-active
ig_journal_write
"${verify_target}" >/dev/null || ig_die POST_INSTALL_VERIFICATION_FAILED

# The value-free receipt is durable before the journal records success.
trap '' HUP INT TERM
IG_PHASE=commit-intent
ig_journal_write
ig_write_receipt pass verified verified verified not-needed
IG_PHASE=committed
ig_journal_write
mutation_started=no
ig_release_lock
lock_held=no
trap - EXIT HUP INT TERM
rm -f -- "${capture}"
printf 'INGRESS-GUARD INSTALL PASS ssh-only-admin-ingress-guard-installed\n'
