#!/usr/bin/env bash
# Deterministic recovery/rollback for an interrupted ingress-guard transaction.

set -Eeuo pipefail
set +x
set +o history
umask 077

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

launch_revision="${INGRESS_GUARD_SOURCE_REVISION:-}"
launch_manifest="${INGRESS_GUARD_MANIFEST_SHA256:-}"
launch_custody="${INGRESS_GUARD_LAUNCH_CUSTODY_DIR:-}"
launch_custody_receipt="${INGRESS_GUARD_CUSTODY_RECEIPT_SHA256:-}"
if [[ "${INGRESS_GUARD_LAUNCH_VERIFIED:-}" == "${launch_revision}:${launch_manifest}" && \
  "${launch_custody}" == "/var/lib/website-infrastructure/ingress-guard/custody/${launch_manifest}" && \
  "${launch_custody_receipt}" =~ ^[0-9a-f]{64}$ && \
  "${INGRESS_GUARD_TRANSACTION_LIBRARY:-}" =~ ^/proc/self/fd/[0-9]+$ && \
  -r "${INGRESS_GUARD_TRANSACTION_LIBRARY}" ]]; then
  transaction_library="${INGRESS_GUARD_TRANSACTION_LIBRARY}"
else
  printf 'INGRESS-GUARD RECOVERY FAIL TRUSTED_LAUNCH_REQUIRED\n' >&2
  exit 1
fi
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

recovery_complete=no
recovery_reporting=no
recovery_state_publication_armed=no
capture=''

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( status != 0 )) && [[ "${recovery_complete}" == no && \
    "${recovery_reporting}" == no && \
    "${recovery_state_publication_armed}" == yes ]]; then
    recovery_reporting=yes
    if [[ -n "${IG_MODE:-}" && -d "${IG_RECEIPT_ROOT:-/nonexistent}" ]]; then
      IG_PHASE=recovery-required
      ig_write_receipt recovery-required unverified unverified unverified required \
        >/dev/null 2>&1 || true
      ig_journal_write >/dev/null 2>&1 || true
    fi
    printf 'INGRESS-GUARD RECOVERY FAIL MANUAL_RECOVERY_REQUIRED\n' >&2
  fi
  [[ -z "${capture}" ]] || rm -f -- "${capture}" >/dev/null 2>&1 || true
  exit "${status}"
}

trap on_exit EXIT
trap 'trap "" HUP INT TERM; exit 129' HUP
trap 'trap "" HUP INT TERM; exit 130' INT
trap 'trap "" HUP INT TERM; exit 143' TERM

[[ "${EUID}" -eq 0 ]] || ig_die NOT_ROOT
case "${1:-}" in
  --automatic)
    recovery_invocation=automatic
    [[ "${INGRESS_GUARD_AUTOMATIC_RECOVERY:-}" == journal-bound ]] \
      || ig_die AUTOMATIC_RECOVERY_REFUSED
    ;;
  --recover)
    recovery_invocation=manual
    [[ -t 0 && -t 1 && -t 2 ]] || ig_die DIRECT_TTY_REQUIRED
    if [[ -n "${SSH_CONNECTION:-}" && \
      ( -z "${SUDO_USER:-}" || "${SUDO_USER}" == root ) ]]; then
      ig_die ROOT_SSH_FORBIDDEN
    fi
    [[ "${CONFIRM_INGRESS_GUARD_RECOVERY:-}" == recover-reviewed-ingress-guard ]] \
      || ig_die EXACT_CONFIRMATION_MISSING
    ;;
  *)
    ig_die RECOVERY_MODE_INVALID
    ;;
esac

ig_require_commands
ig_bootstrap_state_roots
ig_acquire_lock
ig_load_journal
[[ "${IG_SOURCE_REVISION}" == "${launch_revision}" && \
  "${IG_MANIFEST_SHA256}" == "${launch_manifest}" && \
  "${IG_CUSTODY_DIR}" == "${launch_custody}" && \
  "${IG_CUSTODY_RECEIPT_SHA256}" == "${launch_custody_receipt}" ]] \
  || ig_die RECOVERY_BUNDLE_JOURNAL_MISMATCH
ig_validate_public_binding
ig_verify_bundle
ig_verify_custody_receipt

contract_source="${IG_CONTRACT_INPUT}"
contract_validator_source="${IG_CUSTODY_DIR}/scripts/validate_admin_ingress_contract.py"
model_validator_source="${IG_CUSTODY_DIR}/scripts/validate_ingress_guard.py"
transaction_lib_source="${IG_CUSTODY_DIR}/bootstrap/pi/ingress-guard/transaction-lib.sh"
loader_source="${IG_CUSTODY_DIR}/bootstrap/pi/ingress-guard/load-ingress-guard.sh"
verify_source="${IG_CUSTODY_DIR}/bootstrap/pi/ingress-guard/verify-ingress-guard.sh"
recover_source="${IG_CUSTODY_DIR}/bootstrap/pi/ingress-guard/recover-ingress-guard.sh"
retrofit_source="${IG_CUSTODY_DIR}/bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh"
unit_source="${IG_CUSTODY_DIR}/bootstrap/pi/ingress-guard/systemd/website-infrastructure-ingress-guard.service"
dropin_source="${IG_CUSTODY_DIR}/bootstrap/pi/ingress-guard/systemd/kubelet.service.d/50-website-infrastructure-ingress-guard.conf"

# Close a loader PASS split before main rollback. An unpublished/open loader
# intent is closed as rolled back only after the owned table is proven absent.
ig_reconcile_published_load_commit

# A success receipt is published only after an intent journal is durable. If a
# kill splits the receipt from the final journal update, verify the immutable
# exact receipt and finish that already-proven state; never roll back beneath a
# durable PASS claim. Pending-reboot uses the same reconciliation rule.
case "${IG_PHASE}" in
  commit-intent)
    intent_receipt="$(ig_receipt_path pass)" || ig_die INTENT_RECEIPT_INVALID
    intent_ready=no
    if [[ -e "${intent_receipt}" || -L "${intent_receipt}" ]]; then
      ig_assert_root_file "${intent_receipt}" 600 || ig_die INTENT_RECEIPT_INVALID
      intent_ready=yes
    else
      intent_temp_state="$(ig_unpublished_document_temp_state "${intent_receipt}")"
    fi
    if [[ "${intent_ready}" == no && "${intent_temp_state:-absent}" == present ]]; then
      ig_discard_unpublished_document_temp "${intent_receipt}"
    fi
    if [[ "${intent_ready}" == yes ]]; then
      ig_write_receipt pass verified verified verified not-needed
      IG_PHASE=committed
      ig_journal_write
      recovery_complete=yes
      trap - EXIT HUP INT TERM
      printf 'INGRESS-GUARD RECOVERY PASS interrupted-commit-reconciled\n'
      [[ "${recovery_invocation}" == manual ]] && exit 0
      exit 21
    fi
    ;;
  awaiting-reboot-intent)
    intent_receipt="$(ig_receipt_path pending-reboot)" \
      || ig_die INTENT_RECEIPT_INVALID
    intent_ready=no
    if [[ -e "${intent_receipt}" || -L "${intent_receipt}" ]]; then
      ig_assert_root_file "${intent_receipt}" 600 || ig_die INTENT_RECEIPT_INVALID
      intent_ready=yes
    else
      intent_temp_state="$(ig_unpublished_document_temp_state "${intent_receipt}")"
    fi
    if [[ "${intent_ready}" == no && "${intent_temp_state:-absent}" == present ]]; then
      ig_discard_unpublished_document_temp "${intent_receipt}"
    fi
    if [[ "${intent_ready}" == yes ]]; then
      ig_write_receipt pending-reboot verified pending pending not-needed
      IG_PHASE=awaiting-reboot
      ig_journal_write
      recovery_complete=yes
      trap - EXIT HUP INT TERM
      printf 'INGRESS-GUARD RECOVERY PASS interrupted-pending-state-reconciled\n'
      [[ "${recovery_invocation}" == manual ]] && exit 0
      exit 20
    fi
    ;;
esac

if [[ "${IG_PHASE}" == committed || "${IG_PHASE}" == rolled-back ]]; then
  receipt_path="$(ig_journal_receipt_path)" || ig_die CLOSED_RECEIPT_INVALID
  ig_assert_root_file "${receipt_path}" 600 || ig_die CLOSED_RECEIPT_INVALID
  [[ "$(ig_secure_root_file_sha256 "${receipt_path}" 0600 16384)" == \
    "${IG_RECEIPT_SHA256}" ]] \
    || ig_die CLOSED_RECEIPT_INVALID
  recovery_complete=yes
  trap - EXIT HUP INT TERM
  printf 'INGRESS-GUARD RECOVERY PASS transaction-already-closed\n'
  exit 0
fi

IG_PHASE=rollback-intent
IG_RECEIPT_SHA256=none
ig_journal_write
recovery_state_publication_armed=yes

# Remove a drop-in created by this attempt before touching service state. For a
# retrofit this lets an interrupted kubelet restart be restored while the
# verified guard still protects the listeners.
ig_remove_if_created "${IG_PRE_DROPIN}" "${dropin_source}" "${dropin_target}" 644 \
  || ig_die DROPIN_ROLLBACK_AMBIGUOUS
ig_run_bounded systemctl daemon-reload >/dev/null 2>&1 || ig_die DAEMON_RELOAD_FAILED

kubelet_now="$(ig_systemctl_state kubelet.service ActiveState)" \
  || ig_die KUBELET_STATE_INVALID
if [[ "${IG_KUBELET_PRESTATE}" == active && "${kubelet_now}" != active ]]; then
  ig_run_bounded systemctl start kubelet.service >/dev/null 2>&1 || ig_die KUBELET_RESTORE_FAILED
  [[ "$(ig_systemctl_state kubelet.service ActiveState)" == active ]] \
    || ig_die KUBELET_RESTORE_FAILED
elif [[ "${IG_KUBELET_PRESTATE}" == inactive && "${kubelet_now}" == active ]]; then
  ig_die KUBELET_ROLLBACK_AMBIGUOUS
fi

if [[ "${IG_CLUSTER_HEALTH_SCOPE}" != not-applicable ]]; then
  ig_require_cluster_commands
  ig_verify_cluster_health "${IG_CLUSTER_HEALTH_SCOPE}" \
    || ig_die CLUSTER_ROLLBACK_HEALTH_INVALID
fi

unit_load_state="$(ig_systemctl_state "${IG_GUARD_UNIT}" LoadState)" \
  || ig_die UNIT_STATE_INVALID
if [[ "${unit_load_state}" == loaded ]]; then
  ig_run_bounded systemctl stop "${IG_GUARD_UNIT}" >/dev/null 2>&1 || ig_die GUARD_STOP_FAILED
fi
if [[ "${IG_KUBELET_PRESTATE}" == active ]]; then
  [[ "$(ig_systemctl_state kubelet.service ActiveState)" == active ]] \
    || ig_die KUBELET_ROLLBACK_AMBIGUOUS
fi

capture="$(mktemp "${IG_TRANSACTION_ROOT}/.recovery.XXXXXXXX")"
chmod 0600 -- "${capture}"
ig_assert_root_file "${contract_source}" 600 || ig_die PRIVATE_CONTRACT_CUSTODY_INVALID
ig_run_bounded python3 -I -B "${contract_validator_source}" CONTRACT "${contract_source}" >/dev/null \
  || ig_die PRIVATE_CONTRACT_CUSTODY_INVALID
ig_capture_ruleset "${capture}" || ig_die RULESET_CAPTURE_FAILED
if ! ig_verify_absent_capture "${capture}" "${model_validator_source}" "${contract_source}"; then
  if ig_verify_live_capture "${capture}" "${model_validator_source}" "${contract_source}"; then
    [[ "${IG_TABLE_PRESTATE}" == absent ]] || ig_die TABLE_ROLLBACK_AMBIGUOUS
    ig_delete_owned_table_and_prove_absent \
      "${capture}" "${model_validator_source}" "${contract_source}" \
      || ig_die TABLE_ROLLBACK_AMBIGUOUS
  else
    ig_die TABLE_ROLLBACK_AMBIGUOUS
  fi
fi
ig_close_load_journal_after_absence

if [[ "${IG_GUARD_ENABLED_PRESTATE}" == disabled ]]; then
  ig_run_bounded systemctl disable "${IG_GUARD_UNIT}" >/dev/null 2>&1 \
    || ig_die GUARD_DISABLE_FAILED
fi

ig_remove_if_created "${IG_PRE_UNIT}" "${unit_source}" "${unit_target}" 644 \
  || ig_die UNIT_ROLLBACK_AMBIGUOUS
ig_remove_if_created "${IG_PRE_RETROFIT}" "${retrofit_source}" "${retrofit_target}" 700 \
  || ig_die ARTIFACT_ROLLBACK_AMBIGUOUS
ig_remove_if_created "${IG_PRE_RECOVER}" "${recover_source}" "${recover_target}" 700 \
  || ig_die ARTIFACT_ROLLBACK_AMBIGUOUS
ig_remove_if_created "${IG_PRE_VERIFY}" "${verify_source}" "${verify_target}" 700 \
  || ig_die ARTIFACT_ROLLBACK_AMBIGUOUS
ig_remove_if_created "${IG_PRE_LOADER}" "${loader_source}" "${loader_target}" 700 \
  || ig_die ARTIFACT_ROLLBACK_AMBIGUOUS
ig_remove_if_created "${IG_PRE_TRANSACTION_LIB}" "${transaction_lib_source}" "${transaction_lib_target}" 600 \
  || ig_die ARTIFACT_ROLLBACK_AMBIGUOUS
ig_remove_if_created "${IG_PRE_MODEL_VALIDATOR}" "${model_validator_source}" "${model_validator_target}" 600 \
  || ig_die ARTIFACT_ROLLBACK_AMBIGUOUS
ig_remove_if_created "${IG_PRE_CONTRACT_VALIDATOR}" "${contract_validator_source}" "${contract_validator_target}" 600 \
  || ig_die ARTIFACT_ROLLBACK_AMBIGUOUS
ig_remove_if_created "${IG_PRE_CONTRACT}" "${contract_source}" "${contract_target}" 600 \
  || ig_die CONTRACT_ROLLBACK_AMBIGUOUS
ig_run_bounded systemctl daemon-reload >/dev/null 2>&1 || ig_die DAEMON_RELOAD_FAILED

ig_remove_directory_if_created "${IG_PRE_DROPIN_DIR}" "${dropin_dir}" 755 \
  || ig_die DIRECTORY_ROLLBACK_AMBIGUOUS
ig_remove_directory_if_created "${IG_PRE_LIBRARY_DIR}" "${library_dir}" 755 \
  || ig_die DIRECTORY_ROLLBACK_AMBIGUOUS
ig_remove_directory_if_created "${IG_PRE_VENDOR_DIR}" "${library_parent}" 755 \
  || ig_die DIRECTORY_ROLLBACK_AMBIGUOUS
ig_remove_directory_if_created "${IG_PRE_ETC_DIR}" "${etc_dir}" 700 \
  || ig_die DIRECTORY_ROLLBACK_AMBIGUOUS

[[ "$(ig_systemctl_state kubelet.service ActiveState)" == "${IG_KUBELET_PRESTATE}" ]] \
  || ig_die KUBELET_ROLLBACK_AMBIGUOUS
[[ "$(ig_unit_enabled_state)" == "${IG_GUARD_ENABLED_PRESTATE}" ]] \
  || ig_die GUARD_ENABLEMENT_ROLLBACK_AMBIGUOUS
ig_verify_guard_unit_prestate "${unit_target}" "${IG_PRE_UNIT}" \
  || ig_die GUARD_UNIT_ROLLBACK_AMBIGUOUS
if [[ "${IG_PRE_DROPIN}" == absent ]]; then
  ig_verify_kubelet_dependency_absent \
    || ig_die KUBELET_DEPENDENCY_ROLLBACK_AMBIGUOUS
fi
if [[ "${IG_CLUSTER_HEALTH_SCOPE}" != not-applicable ]]; then
  ig_verify_cluster_health "${IG_CLUSTER_HEALTH_SCOPE}" \
    || ig_die CLUSTER_ROLLBACK_HEALTH_INVALID
fi
ig_write_receipt rollback-verified absent restored restored verified
IG_PHASE=rolled-back
ig_journal_write
recovery_complete=yes
trap - EXIT HUP INT TERM
rm -f -- "${capture}"
printf 'INGRESS-GUARD RECOVERY PASS exact-prestate-restored\n'
