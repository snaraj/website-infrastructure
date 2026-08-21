#!/usr/bin/env bash
# Running-cluster retrofit transaction for the SSH-only ingress guard.
# This is intentionally separate from install-ingress-guard.sh: the offline
# installer continues to refuse an active kubelet.

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
  printf 'INGRESS-GUARD RETROFIT FAIL TRUSTED_LAUNCH_REQUIRED\n' >&2
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
readonly cluster_ca=/etc/kubernetes/pki/ca.crt

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

load_secure_bindings() {
  local expected_attested_boot="${1:-}" output
  local -a bindings
  local -a command=(
    python3 -I -B "${model_validator_source}" retrofit-binding
    --attestation "${IG_RETROFIT_INPUT}"
    --boot-id-file /proc/sys/kernel/random/boot_id
    --cluster-ca "${cluster_ca}"
    --source-revision "${IG_SOURCE_REVISION}"
    --manifest-sha256 "${IG_MANIFEST_SHA256}"
  )
  if [[ -n "${expected_attested_boot}" ]]; then
    command+=(--attested-boot-id-sha256 "${expected_attested_boot}")
  fi
  output="$(ig_run_bounded "${command[@]}")" || ig_die RETROFIT_BINDING_INVALID
  mapfile -t bindings <<<"${output}"
  [[ "${#bindings[@]}" -eq 3 ]] || ig_die RETROFIT_BINDING_INVALID
  [[ "${bindings[0]}" =~ ^attestation_sha256=([0-9a-f]{64})$ ]] \
    || ig_die RETROFIT_BINDING_INVALID
  ATTESTATION_SHA256="${BASH_REMATCH[1]}"
  [[ "${bindings[1]}" =~ ^current_boot_sha256=([0-9a-f]{64})$ ]] \
    || ig_die RETROFIT_BINDING_INVALID
  CURRENT_BOOT_SHA256="${BASH_REMATCH[1]}"
  [[ "${bindings[2]}" =~ ^cluster_ca_sha256=([0-9a-f]{64})$ ]] \
    || ig_die RETROFIT_BINDING_INVALID
  CURRENT_CLUSTER_SHA256="${BASH_REMATCH[1]}"
}

guard_only_verify() {
  [[ "$(ig_systemctl_state "${IG_GUARD_UNIT}" ActiveState)" == active ]] || return 1
  [[ "$(ig_unit_enabled_state)" == enabled ]] || return 1
  ig_capture_ruleset "${capture}" || return 1
  ig_verify_live_capture "${capture}" "${model_validator_target}" "${contract_target}"
}

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
      0) printf 'INGRESS-GUARD RETROFIT FAIL ROLLED_BACK_VERIFIED\n' >&2 ;;
      20) printf 'INGRESS-GUARD RETROFIT FAIL REBOOT_PENDING_RECONCILED\n' >&2 ;;
      21) printf 'INGRESS-GUARD RETROFIT FAIL COMMIT_RECONCILED\n' >&2 ;;
      *) printf 'INGRESS-GUARD RETROFIT FAIL RECOVERY_REQUIRED\n' >&2 ;;
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
mode="${1:-}"
[[ "${mode}" == --activate || "${mode}" == --close-after-reboot ]] \
  || ig_die RETROFIT_MODE_INVALID

IG_SOURCE_REVISION="${launch_revision}"
IG_MANIFEST_SHA256="${launch_manifest}"
IG_CUSTODY_RECEIPT_SHA256="${INGRESS_GUARD_CUSTODY_RECEIPT_SHA256:-}"
IG_CUSTODY_DIR="${custody_dir}"
ig_require_commands
ig_require_cluster_commands
ig_bootstrap_state_roots
ig_validate_public_binding
ig_verify_bundle
ig_verify_custody_receipt
ig_verify_custody_contract
ig_assert_root_file "${contract_source}" 600 || ig_die PRIVATE_CONTRACT_CUSTODY_INVALID
ig_run_bounded python3 -I -B "${contract_validator_source}" CONTRACT "${contract_source}" >/dev/null \
  || ig_die PRIVATE_CONTRACT_CUSTODY_INVALID

if [[ "${mode}" == --close-after-reboot ]]; then
  [[ "${CONFIRM_INGRESS_GUARD_RETROFIT_CLOSE:-}" == \
    "close-reviewed-ingress-guard-retrofit-${IG_SOURCE_REVISION}-${IG_MANIFEST_SHA256}" ]] \
    || ig_die EXACT_CONFIRMATION_MISSING
  ig_acquire_lock
  lock_held=yes
  requested_source_revision="${IG_SOURCE_REVISION}"
  requested_manifest_sha256="${IG_MANIFEST_SHA256}"
  requested_custody_receipt_sha256="${IG_CUSTODY_RECEIPT_SHA256}"
  ig_load_journal
  [[ "${IG_MODE}:${IG_PHASE}" == retrofit:awaiting-reboot ]] \
    || ig_die REBOOT_CLOSURE_STATE_INVALID
  [[ "${IG_SOURCE_REVISION}:${IG_MANIFEST_SHA256}" == \
    "${requested_source_revision}:${requested_manifest_sha256}" ]] \
    || ig_die REBOOT_CLOSURE_BINDING_MISMATCH
  [[ "${IG_CUSTODY_RECEIPT_SHA256}" == "${requested_custody_receipt_sha256}" ]] \
    || ig_die REBOOT_CLOSURE_BINDING_MISMATCH
  ig_verify_custody_receipt
  pending_receipt="$(ig_journal_receipt_path)" || ig_die PENDING_RECEIPT_INVALID
  ig_assert_root_file "${pending_receipt}" 600 || ig_die PENDING_RECEIPT_INVALID
  [[ "$(ig_secure_root_file_sha256 "${pending_receipt}" 0600 16384)" == \
    "${IG_RECEIPT_SHA256}" ]] \
    || ig_die PENDING_RECEIPT_INVALID
  load_secure_bindings "${IG_BOOT_BINDING}"
  [[ "${ATTESTATION_SHA256}" == "${IG_ATTESTATION_SHA256}" ]] \
    || ig_die RETROFIT_ATTESTATION_CHANGED
  [[ "${CURRENT_BOOT_SHA256}" != "${IG_BOOT_BINDING}" ]] || ig_die REBOOT_NOT_OBSERVED
  [[ "${CURRENT_CLUSTER_SHA256}" == "${IG_CLUSTER_BINDING}" ]] \
    || ig_die CLUSTER_BINDING_INVALID
  [[ "$(ig_file_prestate "${contract_target}" "${contract_source}" 600)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${contract_validator_target}" "${contract_validator_source}" 600)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${model_validator_target}" "${model_validator_source}" 600)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${transaction_lib_target}" "${transaction_lib_source}" 600)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${loader_target}" "${loader_source}" 700)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${verify_target}" "${verify_source}" 700)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${recover_target}" "${recover_source}" 700)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${retrofit_target}" "${retrofit_source}" 700)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${unit_target}" "${unit_source}" 644)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_file_prestate "${dropin_target}" "${dropin_source}" 644)" == exact ]] \
    || ig_die INSTALLED_ARTIFACT_DRIFT
  [[ "$(ig_systemctl_state kubelet.service ActiveState)" == active ]] \
    || ig_die KUBELET_STATE_INVALID
  "${verify_target}" >/dev/null || ig_die POST_REBOOT_VERIFICATION_FAILED
  ig_verify_cluster_health "${IG_CLUSTER_HEALTH_SCOPE}" \
    || ig_die POST_REBOOT_CLUSTER_HEALTH_FAILED
  # The canary suite is deliberately followed by one last descriptor-bound
  # attestation/boot/CA read so those bindings are adjacent to commit intent.
  load_secure_bindings "${IG_BOOT_BINDING}"
  [[ "${ATTESTATION_SHA256}" == "${IG_ATTESTATION_SHA256}" ]] \
    || ig_die RETROFIT_ATTESTATION_CHANGED
  [[ "${CURRENT_BOOT_SHA256}" != "${IG_BOOT_BINDING}" ]] || ig_die REBOOT_NOT_OBSERVED
  [[ "${CURRENT_CLUSTER_SHA256}" == "${IG_CLUSTER_BINDING}" ]] \
    || ig_die CLUSTER_BINDING_INVALID
  trap '' HUP INT TERM
  IG_CLOSURE_BOOT_BINDING="${CURRENT_BOOT_SHA256}"
  mutation_started=yes
  IG_PHASE=commit-intent
  ig_journal_write
  ig_write_receipt pass verified verified verified not-needed
  IG_PHASE=committed
  ig_journal_write
  mutation_started=no
  ig_release_lock
  lock_held=no
  trap - EXIT HUP INT TERM
  printf 'INGRESS-GUARD RETROFIT PASS reboot-persistent-transaction-closed\n'
  exit 0
fi

[[ "${CONFIRM_INGRESS_GUARD_RETROFIT:-}" == \
  "retrofit-reviewed-running-cluster-${IG_SOURCE_REVISION}-${IG_MANIFEST_SHA256}" ]] \
  || ig_die EXACT_CONFIRMATION_MISSING
[[ "$(ig_systemctl_state kubelet.service ActiveState)" == active ]] \
  || ig_die KUBELET_NOT_ACTIVE

ig_acquire_lock
lock_held=yes
if [[ -e "${IG_JOURNAL_PATH}" || -L "${IG_JOURNAL_PATH}" ]]; then
  requested_source_revision="${IG_SOURCE_REVISION}"
  requested_manifest_sha256="${IG_MANIFEST_SHA256}"
  requested_custody_receipt_sha256="${IG_CUSTODY_RECEIPT_SHA256}"
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
[[ "${kubelet_state}" == active ]] || ig_die KUBELET_STATE_CHANGED
ig_assert_directory /etc/systemd/system 755 || ig_die SYSTEM_DIRECTORY_INVALID
ig_assert_directory /usr/local/sbin 755 || ig_die SYSTEM_DIRECTORY_INVALID
ig_assert_directory /usr/local/lib 755 || ig_die SYSTEM_DIRECTORY_INVALID

capture="$(mktemp "${IG_TRANSACTION_ROOT}/.prestate.XXXXXXXX")"
chmod 0600 -- "${capture}"
IG_TABLE_PRESTATE="$(ig_table_prestate "${capture}" "${model_validator_source}" "${contract_source}")"
[[ "${IG_TABLE_PRESTATE}" == absent ]] || ig_die PREEXISTING_STATE
IG_GUARD_ENABLED_PRESTATE="$(ig_unit_enabled_state)" || ig_die UNIT_STATE_INVALID
[[ "${IG_GUARD_ENABLED_PRESTATE}" == disabled ]] || ig_die GUARD_UNIT_PRESTATE_INVALID
IG_KUBELET_PRESTATE=active

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
[[ "${IG_PRE_UNIT}:${IG_PRE_DROPIN}" == absent:absent ]] \
  || ig_die RETROFIT_PRESTATE_MISMATCH
ig_verify_guard_unit_prestate "${unit_target}" "${IG_PRE_UNIT}" \
  || ig_die GUARD_UNIT_PRESTATE_INVALID
ig_verify_kubelet_dependency_absent || ig_die KUBELET_DEPENDENCY_PRESTATE_INVALID

# Re-open every private/boot binding by descriptor and prove cluster health
# while the transaction lock is held, immediately before the durable journal.
  IG_CLUSTER_HEALTH_SCOPE="$(ig_cluster_health_scope)" || ig_die CLUSTER_PRESTATE_UNHEALTHY
  load_secure_bindings
  IG_ATTEMPT_ID="$(ig_secure_uuid)" || ig_die BOOT_BINDING_INVALID
IG_BOOT_BINDING="${CURRENT_BOOT_SHA256}"
IG_CLOSURE_BOOT_BINDING=none
IG_CLUSTER_BINDING="${CURRENT_CLUSTER_SHA256}"
IG_ATTESTATION_SHA256="${ATTESTATION_SHA256}"
IG_MODE=retrofit
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
IG_PHASE=artifacts-installed
ig_journal_write
ig_run_bounded systemctl daemon-reload >/dev/null 2>&1 || ig_die DAEMON_RELOAD_FAILED
ig_run_bounded systemctl enable "${IG_GUARD_UNIT}" >/dev/null 2>&1 || ig_die ENABLE_FAILED

IG_PHASE=guard-start-intent
ig_journal_write
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
guard_only_verify || ig_die GUARD_SEMANTIC_VERIFICATION_FAILED
IG_PHASE=guard-active
ig_journal_write

# Persistence becomes a kubelet dependency only after the active guard model
# is proven. The currently running kubelet is never stopped behind an absent or
# unverified table.
ig_install_exact "${dropin_source}" "${dropin_target}" 644
ig_run_bounded systemctl daemon-reload >/dev/null 2>&1 || ig_die DAEMON_RELOAD_FAILED
grep -qw -- "${IG_GUARD_UNIT}" \
  <<<"$(ig_run_bounded systemctl show -p After --value kubelet.service 2>/dev/null)" \
  || ig_die KUBELET_ORDERING_MISSING
grep -qw -- "${IG_GUARD_UNIT}" \
  <<<"$(ig_run_bounded systemctl show -p Requires --value kubelet.service 2>/dev/null)" \
  || ig_die KUBELET_REQUIRES_MISSING
IG_PHASE=dropin-installed
ig_journal_write

IG_PHASE=kubelet-restart-intent
ig_journal_write
ig_run_bounded systemctl restart kubelet.service >/dev/null 2>&1 || ig_die KUBELET_RESTART_FAILED
[[ "$(ig_systemctl_state kubelet.service ActiveState)" == active ]] \
  || ig_die KUBELET_RESTART_FAILED
"${verify_target}" >/dev/null || ig_die POST_RETROFIT_VERIFICATION_FAILED
ig_verify_cluster_health "${IG_CLUSTER_HEALTH_SCOPE}" \
  || ig_die POST_RETROFIT_CLUSTER_HEALTH_FAILED

# Activation is not final success until a new boot repeats the proof. Persist a
# bounded pending receipt and phase so power loss simply resumes at closure.
  trap '' HUP INT TERM
  IG_PHASE=awaiting-reboot-intent
  ig_journal_write
  ig_write_receipt pending-reboot verified pending pending not-needed
  IG_PHASE=awaiting-reboot
ig_journal_write
mutation_started=no
ig_release_lock
lock_held=no
trap - EXIT HUP INT TERM
rm -f -- "${capture}"
printf 'INGRESS-GUARD RETROFIT PENDING reboot-proof-required\n'
