#!/usr/bin/env bash
# Crash-recoverable loader for the SSH-only admin-ingress guard (PLAT-DEC-001).
# Installed and executed only from root-owned, hash-verified custody.

set -Eeuo pipefail
set +x
set +o history
umask 077

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly contract_path=/etc/website-infrastructure/admin-ingress.env
readonly library_dir=/usr/local/lib/website-infrastructure/ingress-guard
readonly transaction_library="${library_dir}/transaction-lib.sh"
readonly verifier="${library_dir}/validate_ingress_guard.py"
readonly contract_validator="${library_dir}/validate_admin_ingress_contract.py"
readonly runtime_dir=/run/website-infrastructure-ingress-guard

[[ -f "${transaction_library}" && ! -L "${transaction_library}" ]] || {
  printf 'INGRESS-GUARD LOAD FAIL LIBRARY_MISSING\n' >&2
  exit 1
}
# shellcheck source=bootstrap/pi/ingress-guard/transaction-lib.sh
source "${transaction_library}"

load_phase=none
load_attempt_id=none
load_boot_binding=none
table_created_in_memory=no
rollback_running=no
capture="${runtime_dir}/ruleset.json"
rendered="${runtime_dir}/guard.nft"

load_journal_write() {
  local phase="$1" prestate="$2" receipt_hash="$3"
  ig_write_load_journal_record "${phase}" "${prestate}" \
    "${load_attempt_id}" "${load_boot_binding}" "${receipt_hash}"
  load_phase="${phase}"
}

load_receipt_write() {
  local result="$1" table_state="$2" rollback="$3"
  ig_write_load_receipt "${load_attempt_id}" "${load_boot_binding}" \
    "${result}" "${table_state}" "${rollback}"
}

load_receipt_path() {
  ig_load_receipt_path "$1" "$2"
}

cleanup_runtime() {
  rm -f -- "${capture}" "${rendered}" >/dev/null 2>&1 || true
}

rollback_load() {
  local receipt_hash
  [[ "${rollback_running}" == no ]] || return 1
  rollback_running=yes
  set +e
  load_journal_write rollback-intent absent none
  if [[ "${table_created_in_memory}" == yes ]]; then
    if ig_delete_owned_table_and_prove_absent \
      "${capture}" "${verifier}" "${contract_path}"; then
      receipt_hash="$(load_receipt_write rollback-verified absent verified)" || return 1
      load_journal_write rolled-back absent "${receipt_hash}" || return 1
      return 0
    fi
  else
    if ig_capture_ruleset "${capture}"; then
      if ig_verify_absent_capture "${capture}" "${verifier}" "${contract_path}"; then
        receipt_hash="$(load_receipt_write rollback-verified absent verified)" \
          || return 1
        load_journal_write rolled-back absent "${receipt_hash}" || return 1
        return 0
      fi
      if ig_verify_live_capture "${capture}" "${verifier}" "${contract_path}" && \
        ig_delete_owned_table_and_prove_absent \
          "${capture}" "${verifier}" "${contract_path}"; then
        receipt_hash="$(load_receipt_write rollback-verified absent verified)" \
          || return 1
        load_journal_write rolled-back absent "${receipt_hash}" || return 1
        return 0
      fi
    fi
  fi
  receipt_hash="$(load_receipt_write recovery-required unverified required)" || return 1
  load_journal_write recovery-required absent "${receipt_hash}" || return 1
  return 1
}

on_exit() {
  local status=$? published_commit=no published_path receipt_hash temp_state
  trap - EXIT HUP INT TERM
  set +e
  if (( status != 0 )) && [[ "${load_phase}" == commit-intent ]]; then
    published_path="$(load_receipt_path "${load_attempt_id}" pass)"
    if [[ -e "${published_path}" || -L "${published_path}" ]]; then
      # Never roll back beneath a published immutable PASS record. Reconcile
      # its exact bytes to the journal, or preserve commit-intent for retry.
      published_commit=yes
      if ig_assert_root_file "${published_path}" 600; then
        if receipt_hash="$(load_receipt_write pass verified not-needed)" && \
          load_journal_write committed absent "${receipt_hash}" >/dev/null 2>&1; then
          status=0
        fi
      fi
      table_created_in_memory=no
    else
      temp_state="$(ig_unpublished_document_temp_state "${published_path}")"
      [[ "${temp_state}" == absent ]] || \
        ig_discard_unpublished_document_temp "${published_path}" >/dev/null 2>&1 \
        || true
    fi
  fi
  if (( status != 0 )) && [[ "${published_commit}" == no ]] && \
    [[ "${table_created_in_memory}" == yes || \
      "${load_phase}" =~ ^(prepared|apply-intent|applied|commit-intent|rollback-intent)$ ]]; then
    rollback_load >/dev/null 2>&1 || true
  fi
  cleanup_runtime
  exit "${status}"
}

trap on_exit EXIT
trap 'trap "" HUP INT TERM; exit 129' HUP
trap 'trap "" HUP INT TERM; exit 130' INT
trap 'trap "" HUP INT TERM; exit 143' TERM

[[ "${EUID}" -eq 0 ]] || ig_die NOT_ROOT
ig_require_commands
ig_bootstrap_state_roots
ig_acquire_lock_wait
[[ -z "${RUNTIME_DIRECTORY:-}" || "${RUNTIME_DIRECTORY}" == "${runtime_dir}" ]] \
  || ig_die RUNTIME_DIRECTORY_INVALID
[[ -d "${runtime_dir}" && ! -L "${runtime_dir}" ]] || ig_die RUNTIME_DIRECTORY_MISSING
[[ -f "${verifier}" && ! -L "${verifier}" ]] || ig_die LIBRARY_MISSING
[[ -f "${contract_validator}" && ! -L "${contract_validator}" ]] || ig_die LIBRARY_MISSING
ig_assert_root_file "${contract_path}" 600 || ig_die CONTRACT_INVALID
ig_run_bounded python3 -I -B "${contract_validator}" CONTRACT "${contract_path}" >/dev/null \
  || ig_die CONTRACT_INVALID

# Complete or refuse an interrupted prior load before starting a new one. An
# apply-intent journal plus an exact owned model is safe to delete because the
# durable prestate was absent; any foreign/ambiguous model is left untouched.
if [[ -e "${IG_LOAD_JOURNAL_PATH}" || -L "${IG_LOAD_JOURNAL_PATH}" ]]; then
  ig_assert_root_file "${IG_LOAD_JOURNAL_PATH}" 600 || ig_die LOAD_JOURNAL_INVALID
  [[ "$(awk 'END {print NR + 0}' "${IG_LOAD_JOURNAL_PATH}")" == 6 ]] \
    || ig_die LOAD_JOURNAL_INVALID
  [[ "$(ig_read_value schema "${IG_LOAD_JOURNAL_PATH}")" == ingress-guard-load-journal-v2 ]] \
    || ig_die LOAD_JOURNAL_INVALID
  previous_phase="$(ig_read_value phase "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  previous_prestate="$(ig_read_value prestate "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  previous_attempt="$(ig_read_value attempt_id "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  previous_boot="$(ig_read_value boot_binding_sha256 "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  previous_receipt="$(ig_read_value receipt_sha256 "${IG_LOAD_JOURNAL_PATH}")" \
    || ig_die LOAD_JOURNAL_INVALID
  [[ "${previous_attempt}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || ig_die LOAD_JOURNAL_INVALID
  [[ "${previous_boot}" =~ ^[0-9a-f]{64}$ ]] || ig_die LOAD_JOURNAL_INVALID
  load_attempt_id="${previous_attempt}"
  load_boot_binding="${previous_boot}"
  case "${previous_phase}" in
    committed|rolled-back)
      [[ "${previous_receipt}" =~ ^[0-9a-f]{64}$ ]] || ig_die LOAD_JOURNAL_INVALID
      if [[ "${previous_phase}" == committed ]]; then
        previous_result=pass
      else
        previous_result=rollback-verified
      fi
      previous_receipt_path="$(load_receipt_path "${previous_attempt}" "${previous_result}")" \
        || ig_die LOAD_RECEIPT_INVALID
      ig_assert_root_file "${previous_receipt_path}" 600 \
        || ig_die LOAD_RECEIPT_INVALID
      [[ "$(ig_secure_root_file_sha256 "${previous_receipt_path}" 0600 16384)" == \
        "${previous_receipt}" ]] \
        || ig_die LOAD_RECEIPT_INVALID
      ;;
    prepared)
      [[ "${previous_prestate}" == absent ]] || ig_die LOAD_JOURNAL_INVALID
      ;;
    commit-intent)
      [[ "${previous_prestate}" == absent && "${previous_receipt}" == none ]] \
        || ig_die LOAD_JOURNAL_INVALID
      previous_receipt_path="$(load_receipt_path "${previous_attempt}" pass)" \
        || ig_die LOAD_RECEIPT_INVALID
      if [[ -e "${previous_receipt_path}" || -L "${previous_receipt_path}" ]]; then
        ig_assert_root_file "${previous_receipt_path}" 600 \
          || ig_die LOAD_RECEIPT_INVALID
        receipt_hash="$(load_receipt_write pass verified not-needed)" \
          || ig_die LOAD_RECEIPT_INVALID
        load_journal_write committed absent "${receipt_hash}"
      else
        intent_temp_state="$(ig_unpublished_document_temp_state "${previous_receipt_path}")"
        [[ "${intent_temp_state}" == absent ]] || \
          ig_discard_unpublished_document_temp "${previous_receipt_path}"
        ig_capture_ruleset "${capture}" || ig_die INTERRUPTED_RECOVERY_REQUIRED
        if ig_verify_absent_capture "${capture}" "${verifier}" "${contract_path}"; then
          receipt_hash="$(load_receipt_write rollback-verified absent verified)"
          load_journal_write rolled-back absent "${receipt_hash}"
        elif ig_verify_live_capture "${capture}" "${verifier}" "${contract_path}"; then
          table_created_in_memory=yes
          rollback_load || ig_die INTERRUPTED_RECOVERY_REQUIRED
          table_created_in_memory=no
        else
          ig_die INTERRUPTED_RECOVERY_REQUIRED
        fi
      fi
      ;;
    apply-intent|applied|rollback-intent|recovery-required)
      [[ "${previous_prestate}" == absent ]] || ig_die LOAD_JOURNAL_INVALID
      ig_capture_ruleset "${capture}" || ig_die INTERRUPTED_RECOVERY_REQUIRED
      if ig_verify_absent_capture "${capture}" "${verifier}" "${contract_path}"; then
        receipt_hash="$(load_receipt_write rollback-verified absent verified)"
        load_journal_write rolled-back absent "${receipt_hash}"
      elif ig_verify_live_capture "${capture}" "${verifier}" "${contract_path}"; then
        table_created_in_memory=yes
        rollback_load || ig_die INTERRUPTED_RECOVERY_REQUIRED
        table_created_in_memory=no
      else
        ig_die INTERRUPTED_RECOVERY_REQUIRED
      fi
      ;;
    *)
      ig_die LOAD_JOURNAL_INVALID
      ;;
  esac
fi

ig_capture_ruleset "${capture}" || ig_die RULESET_CAPTURE_FAILED
if ! ig_verify_absent_capture "${capture}" "${verifier}" "${contract_path}"; then
  if ig_verify_live_capture "${capture}" "${verifier}" "${contract_path}"; then
    trap - EXIT HUP INT TERM
    cleanup_runtime
    printf 'INGRESS-GUARD LOAD PASS already-active-model-verified\n'
    exit 0
  fi
  ig_die PREEXISTING_STATE
fi

load_attempt_id="$(ig_secure_uuid)" || ig_die BOOT_BINDING_INVALID
load_boot_binding="$(ig_secure_boot_sha256)" || ig_die BOOT_BINDING_INVALID
load_journal_write prepared absent none
rm -f -- "${rendered}"
ig_run_bounded python3 -I -B "${verifier}" render --contract "${contract_path}" \
  --output "${rendered}" >/dev/null || ig_die RENDER_FAILED
ig_run_bounded nft -c -f "${rendered}" >/dev/null 2>&1 || ig_die RENDER_REJECTED

# Persist intent before the atomic apply. A kill/power loss after this write is
# recovered on the next invocation by classifying the exact owned identity.
load_journal_write apply-intent absent none
ig_run_bounded nft -f "${rendered}" >/dev/null 2>&1 || ig_die APPLY_FAILED
table_created_in_memory=yes
load_journal_write applied absent none

# Any failure from here, including this capture itself, reaches the EXIT trap
# with table_created_in_memory=yes and therefore deletes the exact owned table.
ig_capture_ruleset "${capture}" || ig_die POST_APPLY_CAPTURE_FAILED
ig_verify_live_capture "${capture}" "${verifier}" "${contract_path}" \
  || ig_die POST_APPLY_VERIFICATION_FAILED

# Do not let a catchable signal split the durable receipt/journal commit.
trap '' HUP INT TERM
load_journal_write commit-intent absent none
receipt_hash="$(load_receipt_write pass verified not-needed)"
load_journal_write committed absent "${receipt_hash}"
table_created_in_memory=no
trap - EXIT HUP INT TERM
cleanup_runtime
printf 'INGRESS-GUARD LOAD PASS ssh-only-admin-ingress-guard-active\n'
