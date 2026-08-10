#!/usr/bin/env bash
set -euo pipefail
set +x

# This gate is deliberately offline. Refuse management and legacy Cloudflare
# credentials before the first external process can inherit them.
for forbidden_name in CLOUDFLARE_API_TOKEN CLOUDFLARE_API_KEY CLOUDFLARE_EMAIL CLOUDFLARE_API_USER_SERVICE_KEY; do
  if [[ -n "${!forbidden_name+x}" ]]; then
    unset "${forbidden_name}"
    printf '%s must be absent while running the offline plan gate\n' "${forbidden_name}" >&2
    exit 2
  fi
done

# Usage requires one caller-selected protected workspace. Plan, redacted audit,
# pre-state receipt, TMPDIR, and every temporary JSON byte must stay beneath it.
# The current phase state path, initialized local-backend metadata, and reviewed
# manual pre-apply attestation are mandatory protected inputs. The state leaf may
# be absent only for the initial-create proof.
# Route/API phases additionally require one protected recovery/session
# attestation. The final DNS phase instead requires one fixed-schema protected
# Naranjo transaction directory; this gate reruns its receipt validator.
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
phase="${1:-}"
plan_input="${2:-}"
audit_input="${3:-}"
protected_input="${4:-}"
receipt_input="${5:-}"
state_input="${6:-}"
backend_input="${7:-}"
manual_attestation_input="${8:-}"
phase_evidence_input="${9:-}"
unexpected_input="${10:-}"

case "${phase}" in
  admin-tunnel|admin-policies|admin-route|admin-api|public-edge|public-dns-naranjo|public-dns-lidersea) ;;
  *)
    printf 'Usage: %s PHASE /protected/plan.tfplan /protected/audit.txt /protected/root /protected/pre-state.receipt /protected/state-path /protected/backend-metadata /protected/manual-attestation.json [/protected/phase-evidence]\n' "$0" >&2
    exit 2
    ;;
esac
[[ -z "${unexpected_input}" ]] || { printf 'The plan gate accepts at most nine positional arguments\n' >&2; exit 2; }
[[ -n "${state_input}" && -n "${backend_input}" && -n "${manual_attestation_input}" ]] || {
  printf 'State path, backend metadata, and manual pre-apply attestation are required\n' >&2
  exit 2
}
case "${phase}" in
  admin-route|admin-api)
    [[ -n "${phase_evidence_input}" ]] || {
      printf '%s requires a protected recovery/session attestation\n' "${phase}" >&2
      exit 2
    }
    ;;
  public-dns-lidersea)
    [[ -n "${phase_evidence_input}" ]] || {
      printf 'Lidersea activation requires the protected Naranjo transaction directory\n' >&2
      exit 2
    }
    ;;
  *)
    [[ -z "${phase_evidence_input}" ]] || {
      printf 'Phase evidence is not accepted for this phase\n' >&2
      exit 2
    }
    ;;
esac

for command_name in awk chmod conftest cp cygpath date find git jq mkdir mktemp powershell.exe rm sha256sum sort stat tee tofu; do
  command -v "${command_name}" >/dev/null 2>&1 || { printf '%s is required\n' "${command_name}" >&2; exit 2; }
done
if command -v python3 >/dev/null 2>&1; then
  python_command=python3
elif command -v python >/dev/null 2>&1; then
  python_command=python
else
  printf 'Python 3 is required for strict protected-evidence validation\n' >&2
  exit 2
fi

for forbidden_context in TF_WORKSPACE TF_CLI_ARGS TF_CLI_ARGS_plan TF_CLI_ARGS_show; do
  if [[ -n "${!forbidden_context+x}" ]]; then
    printf '%s must be absent while running the offline plan gate\n' "${forbidden_context}" >&2
    exit 2
  fi
done

[[ -n "${protected_input}" && -d "${protected_input}" && ! -L "${protected_input}" ]] || {
  printf 'A real, non-symlink protected workspace root is required\n' >&2
  exit 2
}
protected_logical="$(cd "${protected_input}" && pwd -L)"
protected_root="$(cd "${protected_input}" && pwd -P)"
[[ "${protected_logical}" == "${protected_root}" ]] || {
  printf 'Protected workspace has a symlinked parent boundary\n' >&2
  exit 2
}
if [[ -n "$(find "${protected_root}" -type l -print -quit 2>/dev/null)" ]]; then
  printf 'Protected workspace must not contain symlinks\n' >&2
  exit 2
fi

canonical_file() {
  local input="$1"
  [[ -f "${input}" && ! -L "${input}" ]] || return 1
  local directory
  directory="$(cd "$(dirname "${input}")" && pwd -P)" || return 1
  printf '%s/%s\n' "${directory}" "$(basename "${input}")"
}

canonical_directory() {
  local input="$1"
  [[ -d "${input}" && ! -L "${input}" ]] || return 1
  (cd "${input}" && pwd -P)
}

assert_within_protected() {
  local label="$1"
  local path="$2"
  case "${path}" in
    "${protected_root}"/*) ;;
    *) printf '%s must resolve beneath the protected workspace\n' "${label}" >&2; exit 2 ;;
  esac
}

plan_path="$(canonical_file "${plan_input}")" || { printf 'A real, non-symlink plan file is required\n' >&2; exit 2; }
audit_path="$(canonical_file "${audit_input}")" || { printf 'A real, non-symlink audit file is required\n' >&2; exit 2; }
receipt_path="$(canonical_file "${receipt_input}")" || { printf 'A real, non-symlink pre-state receipt is required\n' >&2; exit 2; }
backend_path="$(canonical_file "${backend_input}")" || { printf 'A real, non-symlink backend-metadata file is required\n' >&2; exit 2; }
manual_attestation_path="$(canonical_file "${manual_attestation_input}")" || { printf 'A real, non-symlink manual pre-apply attestation is required\n' >&2; exit 2; }
assert_within_protected plan "${plan_path}"
assert_within_protected audit "${audit_path}"
assert_within_protected receipt "${receipt_path}"
assert_within_protected backend-metadata "${backend_path}"
assert_within_protected manual-attestation "${manual_attestation_path}"

state_parent="$(canonical_directory "$(dirname "${state_input}")")" || {
  printf 'The phase state parent must be a real, non-symlink directory\n' >&2
  exit 2
}
expected_phase_storage="${protected_root}/cloudflare/${phase}"
[[ "${state_parent}" == "${expected_phase_storage}" && "$(basename "${state_input}")" == terraform.tfstate ]] || {
  printf 'State path is not the exact protected current-phase state path\n' >&2
  exit 2
}
state_path="${state_parent}/terraform.tfstate"
expected_backend_path="${expected_phase_storage}/tofu-data/terraform.tfstate"
[[ "${backend_path}" == "${expected_backend_path}" ]] || {
  printf 'Backend metadata is not in the exact protected current-phase TF_DATA_DIR\n' >&2
  exit 2
}
if [[ -e "${state_path}" || -L "${state_path}" ]]; then
  state_path="$(canonical_file "${state_path}")" || {
    printf 'Present phase state must be one real, non-symlink regular file\n' >&2
    exit 2
  }
  state_mode=present
else
  state_mode=absent
fi
case "${phase}" in
  admin-route|admin-api)
    recovery_evidence_path="$(canonical_file "${phase_evidence_input}")" || { printf 'A real, non-symlink recovery/session evidence file is required\n' >&2; exit 2; }
    assert_within_protected recovery-evidence "${recovery_evidence_path}"
    ;;
  public-dns-lidersea)
    naranjo_transaction_root="$(canonical_directory "${phase_evidence_input}")" || { printf 'A real, non-symlink Naranjo transaction directory is required\n' >&2; exit 2; }
    assert_within_protected naranjo-transaction "${naranjo_transaction_root}/sentinel"
    expected_naranjo_absent_inventory=$'postflight-token-evidence.txt\npre-apply-state-evidence.txt\npre-operation-audit.txt\npre-state-receipt.txt\npreflight-token-evidence.txt\nsaved-plan.tfplan\nsource-ip-policy.txt\ntarget-binding.txt\ntoken-id.txt\ntoken-receipt.json'
    expected_naranjo_present_inventory="$(printf '%s\npre-apply-state.tfstate\n' "${expected_naranjo_absent_inventory}" | LC_ALL=C sort)"
    actual_naranjo_inventory="$(find "${naranjo_transaction_root}" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" || exit 2
    if [[ "${actual_naranjo_inventory}" == "${expected_naranjo_absent_inventory}" ]]; then
      naranjo_state_mode_hint=absent
    elif [[ "${actual_naranjo_inventory}" == "${expected_naranjo_present_inventory}" ]]; then
      naranjo_state_mode_hint=present
    else
      printf 'Naranjo transaction directory inventory is not an exact absent/present schema\n' >&2
      exit 2
    fi
    naranjo_target_path="$(canonical_file "${naranjo_transaction_root}/target-binding.txt")" || exit 2
    naranjo_plan_path="$(canonical_file "${naranjo_transaction_root}/saved-plan.tfplan")" || exit 2
    naranjo_state_evidence_path="$(canonical_file "${naranjo_transaction_root}/pre-apply-state-evidence.txt")" || exit 2
    naranjo_pre_state_receipt_path="$(canonical_file "${naranjo_transaction_root}/pre-state-receipt.txt")" || exit 2
    if [[ "${naranjo_state_mode_hint}" == present ]]; then
      naranjo_state_path="$(canonical_file "${naranjo_transaction_root}/pre-apply-state.tfstate")" || exit 2
    fi
    naranjo_pre_audit_path="$(canonical_file "${naranjo_transaction_root}/pre-operation-audit.txt")" || exit 2
    naranjo_source_ip_path="$(canonical_file "${naranjo_transaction_root}/source-ip-policy.txt")" || exit 2
    naranjo_token_id_path="$(canonical_file "${naranjo_transaction_root}/token-id.txt")" || exit 2
    naranjo_preflight_path="$(canonical_file "${naranjo_transaction_root}/preflight-token-evidence.txt")" || exit 2
    naranjo_postflight_path="$(canonical_file "${naranjo_transaction_root}/postflight-token-evidence.txt")" || exit 2
    naranjo_token_receipt_path="$(canonical_file "${naranjo_transaction_root}/token-receipt.json")" || exit 2
    ;;
esac

: "${TMPDIR:?Set TMPDIR to a private directory beneath the protected workspace}"
[[ -d "${TMPDIR}" && ! -L "${TMPDIR}" ]] || { printf 'TMPDIR must be a real, non-symlink directory\n' >&2; exit 2; }
tmp_logical="$(cd "${TMPDIR}" && pwd -L)"
tmp_root="$(cd "${TMPDIR}" && pwd -P)"
[[ "${tmp_logical}" == "${tmp_root}" ]] || { printf 'TMPDIR has a symlinked parent boundary\n' >&2; exit 2; }
assert_within_protected TMPDIR "${tmp_root}/sentinel"

phase_relative="infrastructure/cloudflare/phases/${phase}"
phase_root="${repo_root}/${phase_relative}"
lock_path="${phase_root}/.terraform.lock.hcl"
[[ -f "${lock_path}" && ! -L "${lock_path}" ]] || { printf 'Committed phase provider lock file is required\n' >&2; exit 1; }

assert_root_inventory() {
  local inventory_phase="$1"
  local inventory_root="$2"
  local expected actual
  if [[ "${inventory_phase}" == admin-policies ]]; then
    expected=$'.terraform.lock.hcl\nmain.tf\nterraform.tfvars.example\nvariables.tf\nversions.tf'
  else
    expected=$'.terraform.lock.hcl\nmain.tf\noutputs.tf\nterraform.tfvars.example\nvariables.tf\nversions.tf'
  fi
  actual="$(find "${inventory_root}" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" || return 1
  [[ "${actual}" == "${expected}" ]] || {
    printf '%s phase root on-disk inventory is not exact; overrides, local tfvars, caches, and extra files are forbidden\n' "${inventory_phase}" >&2
    return 1
  }
}

assert_phase_inventory() {
  assert_root_inventory "${phase}" "${phase_root}"
  if [[ "${phase}" == public-dns-lidersea ]]; then
    assert_root_inventory public-dns-naranjo "${repo_root}/infrastructure/cloudflare/phases/public-dns-naranjo"
  fi
}

assert_policy_inventory() {
  local expected actual
  expected=$'cloudflare-cost-policy.yaml\ncloudflare-plan.rego'
  actual="$(find "${repo_root}/infrastructure/cloudflare/policy" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" || return 1
  [[ "${actual}" == "${expected}" ]] || {
    printf 'Cloudflare policy on-disk inventory is not exact\n' >&2
    return 1
  }
}

assert_sources_equal_head() {
  local -a source_paths=(
    "${phase_relative}"
    infrastructure/cloudflare/policy
    scripts/cloudflare-plan-gate.sh
    scripts/cloudflare-audit.sh
    scripts/validate_cloudflare_preapply_evidence.py
    scripts/validate_cloudflare_token_receipt.py
    scripts/validate-windows-credential-workspace.ps1
  )
  if [[ "${phase}" == public-dns-lidersea ]]; then
    source_paths+=(infrastructure/cloudflare/phases/public-dns-naranjo)
  fi
  git -C "${repo_root}" diff --quiet -- "${source_paths[@]}" || return 1
  git -C "${repo_root}" diff --cached --quiet -- "${source_paths[@]}" || return 1
  [[ -z "$(git -C "${repo_root}" ls-files --others -- "${source_paths[@]}")" ]] || return 1
}

repo_commit="$(git -C "${repo_root}" rev-parse HEAD)"
[[ "${repo_commit}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || { printf 'Repository commit is not canonical\n' >&2; exit 1; }
assert_phase_inventory || exit 1
assert_policy_inventory || exit 1
assert_sources_equal_head || { printf 'Cloudflare plan sources differ from the bound repository commit\n' >&2; exit 1; }

digest_file() {
  sha256sum "$1" | awk '{print $1}'
}

digest_stream() {
  sha256sum | awk '{print $1}'
}

stable_snapshot() {
  local source="$1"
  local label="$2"
  local before after snapshot snapshot_hash
  [[ "$(find "${source}" -maxdepth 0 -type f -links 1 -printf '%n')" == 1 ]] || {
    printf '%s source must be a regular file with exactly one hard link\n' "${label}" >&2
    return 1
  }
  before="$(digest_file "${source}")" || return 1
  snapshot="$(mktemp "${tmp_root}/${label}.XXXXXX")" || return 1
  cp -- "${source}" "${snapshot}" || { rm -f -- "${snapshot}"; return 1; }
  chmod 400 "${snapshot}" || { rm -f -- "${snapshot}"; return 1; }
  after="$(digest_file "${source}")" || { rm -f -- "${snapshot}"; return 1; }
  snapshot_hash="$(digest_file "${snapshot}")" || { rm -f -- "${snapshot}"; return 1; }
  [[ "$(find "${snapshot}" -maxdepth 0 -type f -links 1 -printf '%n')" == 1 ]] || { rm -f -- "${snapshot}"; return 1; }
  [[ "${before}" == "${after}" && "${before}" == "${snapshot_hash}" ]] || {
    printf '%s changed while creating the protected immutable snapshot\n' "${label}" >&2
    rm -f -- "${snapshot}"
    return 1
  }
  printf '%s\n' "${snapshot}"
}

stable_handle_snapshot() {
  local source="$1"
  local label="$2"
  local before_identity before_hash opened_identity after_identity after_hash
  local snapshot snapshot_hash stable_fd
  [[ "$(find "${source}" -maxdepth 0 -type f -links 1 -printf '%n')" == 1 ]] || {
    printf '%s source must be a regular file with exactly one hard link\n' "${label}" >&2
    return 1
  }
  before_identity="$(stat -Lc '%d:%i:%f:%h:%s' -- "${source}")" || return 1
  before_hash="$(digest_file "${source}")" || return 1
  exec {stable_fd}<"${source}" || return 1
  opened_identity="$(stat -Lc '%d:%i:%f:%h:%s' -- "${source}")" || {
    exec {stable_fd}<&-
    return 1
  }
  snapshot="$(mktemp "${tmp_root}/${label}.XXXXXX")" || {
    exec {stable_fd}<&-
    return 1
  }
  tee "${snapshot}" <&${stable_fd} >/dev/null || {
    exec {stable_fd}<&-
    rm -f -- "${snapshot}"
    return 1
  }
  exec {stable_fd}<&-
  chmod 400 "${snapshot}" || { rm -f -- "${snapshot}"; return 1; }
  after_identity="$(stat -Lc '%d:%i:%f:%h:%s' -- "${source}")" || { rm -f -- "${snapshot}"; return 1; }
  after_hash="$(digest_file "${source}")" || { rm -f -- "${snapshot}"; return 1; }
  snapshot_hash="$(digest_file "${snapshot}")" || { rm -f -- "${snapshot}"; return 1; }
  [[ "$(find "${snapshot}" -maxdepth 0 -type f -links 1 -printf '%n')" == 1 ]] || { rm -f -- "${snapshot}"; return 1; }
  [[ "${before_identity}" == "${opened_identity}" && "${before_identity}" == "${after_identity}" && \
      "${before_hash}" == "${after_hash}" && "${before_hash}" == "${snapshot_hash}" ]] || {
    printf '%s identity or bytes changed while reading its stable handle\n' "${label}" >&2
    rm -f -- "${snapshot}"
    return 1
  }
  printf '%s\n' "${snapshot}"
}

stable_copy_to() {
  local source="$1"
  local target="$2"
  local label="$3"
  local before after target_hash
  [[ "$(find "${source}" -maxdepth 0 -type f -links 1 -printf '%n')" == 1 ]] || return 1
  before="$(digest_file "${source}")" || return 1
  cp -- "${source}" "${target}" || return 1
  chmod 400 "${target}" || return 1
  after="$(digest_file "${source}")" || return 1
  target_hash="$(digest_file "${target}")" || return 1
  [[ "$(find "${target}" -maxdepth 0 -type f -links 1 -printf '%n')" == 1 ]] || return 1
  [[ "${before}" == "${after}" && "${before}" == "${target_hash}" ]] || {
    printf '%s changed while creating the protected source snapshot\n' "${label}" >&2
    return 1
  }
}

assert_snapshot_still_matches() {
  local label="$1"
  local source="$2"
  local snapshot="$3"
  local source_hash snapshot_hash
  source_hash="$(digest_file "${source}")" || return 1
  snapshot_hash="$(digest_file "${snapshot}")" || return 1
  [[ "${source_hash}" == "${snapshot_hash}" ]] || {
    printf '%s changed after its protected snapshot was created\n' "${label}" >&2
    return 1
  }
}

assert_handle_snapshot_still_matches() {
  local label="$1"
  local source="$2"
  local snapshot="$3"
  local before_identity after_identity source_hash snapshot_hash stable_fd
  [[ "$(find "${source}" -maxdepth 0 -type f -links 1 -printf '%n')" == 1 ]] || return 1
  before_identity="$(stat -Lc '%d:%i:%f:%h:%s' -- "${source}")" || return 1
  exec {stable_fd}<"${source}" || return 1
  source_hash="$(sha256sum <&${stable_fd} | awk '{print $1}')" || {
    exec {stable_fd}<&-
    return 1
  }
  exec {stable_fd}<&-
  after_identity="$(stat -Lc '%d:%i:%f:%h:%s' -- "${source}")" || return 1
  snapshot_hash="$(digest_file "${snapshot}")" || return 1
  [[ "${before_identity}" == "${after_identity}" && "${source_hash}" == "${snapshot_hash}" ]] || {
    printf '%s identity or bytes changed after its stable-handle snapshot\n' "${label}" >&2
    return 1
  }
}

plan_source_path="${plan_path}"
audit_source_path="${audit_path}"
receipt_source_path="${receipt_path}"
gate_source_hash="$(digest_file "${repo_root}/scripts/cloudflare-plan-gate.sh")"
audit_script_source_hash="$(digest_file "${repo_root}/scripts/cloudflare-audit.sh")"
preapply_validator_source_hash="$(digest_file "${repo_root}/scripts/validate_cloudflare_preapply_evidence.py")"
state_parent_identity="$(stat -Lc '%d:%i:%f:%h' -- "${state_parent}")" || exit 1

raw_json="$(mktemp "${tmp_root}/cloudflare-plan-raw.XXXXXX")" || exit 1
policy_json="$(mktemp "${tmp_root}/cloudflare-plan-policy.XXXXXX")" || exit 1
workspace_attestation_output="$(mktemp "${tmp_root}/cloudflare-workspace-attestation.XXXXXX")" || exit 1
state_validation_output="$(mktemp "${tmp_root}/cloudflare-state-validation.XXXXXX")" || exit 1
manual_validation_output="$(mktemp "${tmp_root}/cloudflare-manual-validation.XXXXXX")" || exit 1
policy_snapshot_dir="$(mktemp -d "${tmp_root}/cloudflare-policy.XXXXXX")" || exit 1
validator_mirror="$(mktemp -d "${tmp_root}/cloudflare-validator-repo.XXXXXX")" || exit 1
mkdir -p "${validator_mirror}/scripts" || exit 1
chmod 700 "${policy_snapshot_dir}" "${validator_mirror}" "${validator_mirror}/scripts" || exit 1
policy_snapshot="${policy_snapshot_dir}/cloudflare-plan.rego"
windows_validator_snapshot="${validator_mirror}/scripts/validate-windows-credential-workspace.ps1"
token_validator_snapshot="${validator_mirror}/scripts/validate_cloudflare_token_receipt.py"
preapply_validator_snapshot="${validator_mirror}/scripts/validate_cloudflare_preapply_evidence.py"

cleanup() {
  rm -f -- "${raw_json}" "${policy_json}" "${workspace_attestation_output}" \
    "${state_validation_output}" "${manual_validation_output}" \
    "${plan_snapshot:-}" "${audit_snapshot:-}" "${receipt_snapshot:-}" \
    "${lock_snapshot:-}" "${state_snapshot:-}" "${backend_snapshot:-}" \
    "${manual_attestation_snapshot:-}" "${recovery_evidence_snapshot:-}" \
    "${naranjo_target_snapshot:-}" "${naranjo_plan_snapshot:-}" \
    "${naranjo_state_snapshot:-}" "${naranjo_state_evidence_snapshot:-}" \
    "${naranjo_pre_state_receipt_snapshot:-}" "${naranjo_pre_audit_snapshot:-}" \
    "${naranjo_source_ip_snapshot:-}" "${naranjo_token_id_snapshot:-}" \
    "${naranjo_preflight_snapshot:-}" "${naranjo_postflight_snapshot:-}" \
    "${naranjo_token_receipt_snapshot:-}" "${naranjo_lock_snapshot:-}" \
    "${naranjo_token_validation_output:-}" "${naranjo_prestate_validation_output:-}" \
    "${predecessor_raw_json:-}" \
    "${predecessor_policy_json:-}"
  rm -rf -- "${policy_snapshot_dir}" "${validator_mirror}"
}
trap cleanup EXIT

stable_copy_to "${repo_root}/infrastructure/cloudflare/policy/cloudflare-plan.rego" "${policy_snapshot}" cloudflare-policy || exit 1
stable_copy_to "${repo_root}/scripts/validate-windows-credential-workspace.ps1" "${windows_validator_snapshot}" windows-workspace-validator || exit 1
stable_copy_to "${repo_root}/scripts/validate_cloudflare_preapply_evidence.py" "${preapply_validator_snapshot}" cloudflare-preapply-validator || exit 1
if [[ "${phase}" == public-dns-lidersea ]]; then
  stable_copy_to "${repo_root}/scripts/validate_cloudflare_token_receipt.py" "${token_validator_snapshot}" cloudflare-token-validator || exit 1
fi

plan_snapshot="$(stable_snapshot "${plan_path}" cloudflare-plan)" || exit 1
audit_snapshot="$(stable_snapshot "${audit_path}" cloudflare-audit)" || exit 1
receipt_snapshot="$(stable_snapshot "${receipt_path}" cloudflare-pre-state-receipt)" || exit 1
lock_snapshot="$(stable_snapshot "${lock_path}" cloudflare-provider-lock)" || exit 1
backend_snapshot="$(stable_handle_snapshot "${backend_path}" cloudflare-backend-metadata)" || exit 1
manual_attestation_snapshot="$(stable_handle_snapshot "${manual_attestation_path}" cloudflare-manual-attestation)" || exit 1
if [[ "${state_mode}" == present ]]; then
  state_snapshot="$(stable_handle_snapshot "${state_path}" cloudflare-current-state)" || exit 1
fi
if [[ "${phase}" == admin-route || "${phase}" == admin-api ]]; then
  recovery_evidence_snapshot="$(stable_snapshot "${recovery_evidence_path}" cloudflare-recovery-evidence)" || exit 1
fi
if [[ "${phase}" == public-dns-lidersea ]]; then
  naranjo_phase_root="${repo_root}/infrastructure/cloudflare/phases/public-dns-naranjo"
  naranjo_lock_path="${naranjo_phase_root}/.terraform.lock.hcl"
  naranjo_target_snapshot="$(stable_snapshot "${naranjo_target_path}" naranjo-target-binding)" || exit 1
  naranjo_plan_snapshot="$(stable_snapshot "${naranjo_plan_path}" naranjo-saved-plan)" || exit 1
  naranjo_state_evidence_snapshot="$(stable_snapshot "${naranjo_state_evidence_path}" naranjo-pre-apply-state-evidence)" || exit 1
  naranjo_pre_state_receipt_snapshot="$(stable_snapshot "${naranjo_pre_state_receipt_path}" naranjo-pre-state-receipt)" || exit 1
  if [[ "${naranjo_state_mode_hint}" == present ]]; then
    naranjo_state_snapshot="$(stable_snapshot "${naranjo_state_path}" naranjo-pre-apply-state)" || exit 1
  fi
  naranjo_pre_audit_snapshot="$(stable_snapshot "${naranjo_pre_audit_path}" naranjo-pre-operation-audit)" || exit 1
  naranjo_source_ip_snapshot="$(stable_snapshot "${naranjo_source_ip_path}" naranjo-source-ip-policy)" || exit 1
  naranjo_token_id_snapshot="$(stable_snapshot "${naranjo_token_id_path}" naranjo-token-id)" || exit 1
  naranjo_preflight_snapshot="$(stable_snapshot "${naranjo_preflight_path}" naranjo-preflight-token-evidence)" || exit 1
  naranjo_postflight_snapshot="$(stable_snapshot "${naranjo_postflight_path}" naranjo-postflight-token-evidence)" || exit 1
  naranjo_token_receipt_snapshot="$(stable_snapshot "${naranjo_token_receipt_path}" naranjo-token-receipt)" || exit 1
  naranjo_lock_snapshot="$(stable_snapshot "${naranjo_lock_path}" naranjo-provider-lock)" || exit 1
  predecessor_raw_json="$(mktemp "${tmp_root}/naranjo-plan-raw.XXXXXX")" || exit 1
  predecessor_policy_json="$(mktemp "${tmp_root}/naranjo-plan-policy.XXXXXX")" || exit 1
  naranjo_token_validation_output="$(mktemp "${tmp_root}/naranjo-token-validation.XXXXXX")" || exit 1
  naranjo_prestate_validation_output="$(mktemp "${tmp_root}/naranjo-prestate-validation.XXXXXX")" || exit 1
fi

state_validator_arguments=(
  state
  --phase "${phase}"
  --backend-metadata "$(cygpath -w "${backend_snapshot}")"
  --expected-state-path "$(cygpath -w "${state_path}")"
)
if [[ "${state_mode}" == present ]]; then
  state_validator_arguments+=(--state-file "$(cygpath -w "${state_snapshot}")")
else
  [[ ! -e "${state_path}" && ! -L "${state_path}" ]] || {
    printf 'Current-phase state appeared before absent-state validation\n' >&2
    exit 1
  }
  state_validator_arguments+=(--state-absent)
fi
"${python_command}" "$(cygpath -w "${preapply_validator_snapshot}")" \
  "${state_validator_arguments[@]}" > "${state_validation_output}" || {
  printf 'Current-phase backend/state evidence is invalid\n' >&2
  exit 1
}
chmod 400 "${state_validation_output}" || exit 1
state_validation_hash="$(digest_file "${state_validation_output}")"
if [[ "${state_mode}" == absent ]]; then
  [[ ! -e "${state_path}" && ! -L "${state_path}" && \
      "$(stat -Lc '%d:%i:%f:%h' -- "${state_parent}")" == "${state_parent_identity}" ]] || {
    printf 'Current-phase state or parent changed during absent-state validation\n' >&2
    exit 1
  }
fi

protected_file_arguments=(
  "${plan_source_path}" "${audit_source_path}" "${receipt_source_path}"
  "${plan_snapshot}" "${audit_snapshot}" "${receipt_snapshot}"
  "${backend_path}" "${backend_snapshot}"
  "${manual_attestation_path}" "${manual_attestation_snapshot}"
  "${lock_snapshot}" "${policy_snapshot}" "${preapply_validator_snapshot}"
  "${state_validation_output}"
)
if [[ "${state_mode}" == present ]]; then
  protected_file_arguments+=("${state_path}" "${state_snapshot}")
fi
if [[ "${phase}" == admin-route || "${phase}" == admin-api ]]; then
  protected_file_arguments+=("${recovery_evidence_path}" "${recovery_evidence_snapshot}")
fi
if [[ "${phase}" == public-dns-lidersea ]]; then
  protected_file_arguments+=(
    "${naranjo_target_path}" "${naranjo_plan_path}"
    "${naranjo_state_evidence_path}" "${naranjo_pre_state_receipt_path}"
    "${naranjo_pre_audit_path}" "${naranjo_source_ip_path}" "${naranjo_token_id_path}"
    "${naranjo_preflight_path}" "${naranjo_postflight_path}" "${naranjo_token_receipt_path}"
    "${naranjo_target_snapshot}" "${naranjo_plan_snapshot}"
    "${naranjo_state_evidence_snapshot}" "${naranjo_pre_state_receipt_snapshot}"
    "${naranjo_pre_audit_snapshot}" "${naranjo_source_ip_snapshot}" "${naranjo_token_id_snapshot}"
    "${naranjo_preflight_snapshot}" "${naranjo_postflight_snapshot}" "${naranjo_token_receipt_snapshot}"
    "${naranjo_lock_snapshot}" "${token_validator_snapshot}"
  )
  if [[ "${naranjo_state_mode_hint}" == present ]]; then
    protected_file_arguments+=("${naranjo_state_path}" "${naranjo_state_snapshot}")
  fi
fi
protected_file_windows=()
for protected_file_path in "${protected_file_arguments[@]}"; do
  protected_file_windows+=("$(cygpath -w "${protected_file_path}")")
done
# PowerShell, not Bash, expands the fixed script block's $args values.
# shellcheck disable=SC2016
powershell.exe -NoProfile -NonInteractive -Command '
  & {
    if ($args.Count -lt 4) { exit 2 }
    $validator = [string]$args[0]
    $repositoryRoot = [string]$args[1]
    $protectedRoot = [string]$args[2]
    [string[]]$protectedFiles = $args[3..($args.Count - 1)]
    & $validator -RepositoryRoot $repositoryRoot -Root $protectedRoot `
      -Session -ProtectedFile $protectedFiles
  }
' "$(cygpath -w "${windows_validator_snapshot}")" \
  "$(cygpath -w "${repo_root}")" "$(cygpath -w "${protected_root}")" \
  "${protected_file_windows[@]}" > "${workspace_attestation_output}"

plan_path="${plan_snapshot}"
audit_path="${audit_snapshot}"
receipt_path="${receipt_snapshot}"

tofu -chdir="${phase_root}" show -json "${plan_path}" > "${raw_json}"
jq --arg phase "${phase}" '. + {codex_contract: {phase: $phase}}' "${raw_json}" > "${policy_json}"
conftest test --policy "${policy_snapshot}" "${policy_json}"

plan_hash="$(digest_file "${plan_path}")"
audit_file_hash="$(digest_file "${audit_path}")"
receipt_file_hash="$(digest_file "${receipt_path}")"
lock_hash="$(digest_file "${lock_snapshot}")"
repo_commit_hash="$(printf '%s\n' "${repo_commit}" | digest_stream)"

unique_value() {
  local file="$1"
  local label="$2"
  local -a matches=()
  mapfile -t matches < <(awk -F= -v label="${label}" '$1 == label {sub(/^[^=]*=/, ""); sub(/\r$/, ""); print}' "${file}")
  [[ "${#matches[@]}" -eq 1 ]] || { printf '%s must appear exactly once in protected evidence\n' "${label}" >&2; exit 1; }
  printf '%s\n' "${matches[0]}"
}

require_sha256() {
  local name="$1"
  local value="$2"
  [[ "${value}" =~ ^[0-9a-f]{64}$ && "${value}" =~ [1-9a-f] ]] || {
    printf '%s is not a nonzero lowercase SHA-256\n' "${name}" >&2
    exit 1
  }
}

assert_exact_kv_schema() {
  local file="$1"
  local expected_keys="$2"
  local observed_keys
  if ! observed_keys="$(LC_ALL=C awk '
    index($0, "\r") != 0 {exit 2}
    $0 !~ /^[a-z0-9_]+=[A-Za-z0-9_.:+\/-]+$/ {exit 2}
    {
      key = $0
      sub(/=.*/, "", key)
      print key
    }
  ' "${file}" | LC_ALL=C sort)"; then
    printf 'Protected receipt is not canonical key=value ASCII\n' >&2
    exit 1
  fi
  [[ "${observed_keys}" == "${expected_keys}" ]] || {
    printf 'Protected receipt fields are missing, duplicated, or extra\n' >&2
    exit 1
  }
}

canonical_utc_epoch() {
  local label="$1"
  local value="$2"
  [[ "${value}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
    printf '%s must use canonical UTC seconds\n' "${label}" >&2
    return 1
  }
  date -u -d "${value}" +%s 2>/dev/null || {
    printf '%s is not a real UTC timestamp\n' "${label}" >&2
    return 1
  }
}

state_validation_line_count="$(awk '{sub(/\r$/, "")} END {print NR}' "${state_validation_output}")"
state_validation_pass_count="$(awk '{sub(/\r$/, "")} $0 == "PASS Cloudflare pre-apply state evidence" {count++} END {print count + 0}' "${state_validation_output}")"
[[ "${state_validation_line_count}" -eq 9 && "${state_validation_pass_count}" -eq 1 ]] || {
  printf 'Current-phase state validation did not produce bounded PASS evidence\n' >&2
  exit 1
}
state_backend="$(unique_value "${state_validation_output}" state_backend)"
backend_metadata_hash="$(unique_value "${state_validation_output}" backend_metadata_sha256)"
state_path_hash="$(unique_value "${state_validation_output}" state_path_sha256)"
state_file_hash="$(unique_value "${state_validation_output}" state_sha256)"
state_lineage_hash="$(unique_value "${state_validation_output}" state_lineage_sha256)"
state_serial="$(unique_value "${state_validation_output}" state_serial)"
state_binding_hash="$(unique_value "${state_validation_output}" state_binding_sha256)"
validated_state_mode="$(unique_value "${state_validation_output}" state_mode)"
[[ "${state_backend}" == local-protected-file && "${validated_state_mode}" == "${state_mode}" ]] || {
  printf 'Current-phase backend/state mode does not match the protected input\n' >&2
  exit 1
}
require_sha256 backend_metadata_sha256 "${backend_metadata_hash}"
require_sha256 state_path_sha256 "${state_path_hash}"
require_sha256 state_binding_sha256 "${state_binding_hash}"
[[ "${backend_metadata_hash}" == "$(digest_file "${backend_snapshot}")" ]] || {
  printf 'Parsed backend metadata hash mismatch\n' >&2
  exit 1
}
if [[ "${state_mode}" == present ]]; then
  require_sha256 state_sha256 "${state_file_hash}"
  require_sha256 state_lineage_sha256 "${state_lineage_hash}"
  [[ "${state_serial}" =~ ^[0-9]+$ && "${state_file_hash}" == "$(digest_file "${state_snapshot}")" ]] || {
    printf 'Parsed current-phase state facts mismatch\n' >&2
    exit 1
  }
else
  [[ "${state_file_hash}" == absent && "${state_lineage_hash}" == absent && "${state_serial}" == absent ]] || {
    printf 'Absent-state proof contains fabricated state facts\n' >&2
    exit 1
  }
fi
manual_attestation_hash="$(digest_file "${manual_attestation_snapshot}")"
require_sha256 manual_attestation_sha256 "${manual_attestation_hash}"

expected_receipt_keys=$'backend_metadata_sha256\nmanual_attestation_sha256\nphase_lock_sha256\nphase_root\nplan_sha256\nplanned_utc\nrepo_commit\nstate_binding_sha256\nstate_evidence_sha256\nstate_mode\nstate_sha256\nworkspace_attestation_sha256'
case "${phase}" in
  admin-route|admin-api)
    expected_receipt_keys="$(printf '%s\nrecovery_evidence_sha256\n' "${expected_receipt_keys}" | LC_ALL=C sort)"
    ;;
  public-dns-lidersea)
    expected_receipt_keys="$(printf '%s\npredecessor_post_audit_sha256\npredecessor_pre_state_receipt_sha256\npredecessor_state_evidence_sha256\npredecessor_token_receipt_sha256\npredecessor_token_validation_sha256\n' "${expected_receipt_keys}" | LC_ALL=C sort)"
    ;;
esac
assert_exact_kv_schema "${receipt_path}" "${expected_receipt_keys}"

receipt_phase="$(unique_value "${receipt_path}" phase_root)"
receipt_commit="$(unique_value "${receipt_path}" repo_commit)"
receipt_lock_hash="$(unique_value "${receipt_path}" phase_lock_sha256)"
receipt_plan_hash="$(unique_value "${receipt_path}" plan_sha256)"
receipt_workspace_attestation="$(unique_value "${receipt_path}" workspace_attestation_sha256)"
receipt_backend_hash="$(unique_value "${receipt_path}" backend_metadata_sha256)"
receipt_state_binding_hash="$(unique_value "${receipt_path}" state_binding_sha256)"
receipt_state_evidence_hash="$(unique_value "${receipt_path}" state_evidence_sha256)"
receipt_state_mode="$(unique_value "${receipt_path}" state_mode)"
receipt_state_hash="$(unique_value "${receipt_path}" state_sha256)"
receipt_manual_attestation_hash="$(unique_value "${receipt_path}" manual_attestation_sha256)"
planned_utc="$(unique_value "${receipt_path}" planned_utc)"
[[ "${receipt_phase}" == "${phase_relative}" ]] || { printf 'Receipt phase root mismatch\n' >&2; exit 1; }
[[ "${receipt_commit}" == "${repo_commit}" && "${receipt_commit}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || { printf 'Receipt repository commit mismatch\n' >&2; exit 1; }
require_sha256 phase_lock_sha256 "${receipt_lock_hash}"
require_sha256 plan_sha256 "${receipt_plan_hash}"
require_sha256 workspace_attestation_sha256 "${receipt_workspace_attestation}"
require_sha256 backend_metadata_sha256 "${receipt_backend_hash}"
require_sha256 state_binding_sha256 "${receipt_state_binding_hash}"
require_sha256 state_evidence_sha256 "${receipt_state_evidence_hash}"
require_sha256 manual_attestation_sha256 "${receipt_manual_attestation_hash}"
[[ "${receipt_state_mode}" == "${state_mode}" && "${receipt_state_hash}" == "${state_file_hash}" ]] || {
  printf 'Receipt state mode/hash mismatch\n' >&2
  exit 1
}
: "${CLOUDFLARE_WORKSPACE_ATTESTATION_SHA256:?Run the protected Windows workspace validator in this session and export its attestation hash}"
require_sha256 CLOUDFLARE_WORKSPACE_ATTESTATION_SHA256 "${CLOUDFLARE_WORKSPACE_ATTESTATION_SHA256}"
attestation_line_count="$(awk '{sub(/\r$/, "")} END {print NR}' "${workspace_attestation_output}")"
attestation_pass_count="$(awk '{sub(/\r$/, "")} $0 == "PASS protected Windows credential workspace" {count++} END {print count + 0}' "${workspace_attestation_output}")"
[[ "${attestation_line_count}" -eq 5 && "${attestation_pass_count}" -eq 1 ]] || { printf 'Current-session Windows workspace/file validation did not produce bounded PASS evidence\n' >&2; exit 1; }
fresh_workspace_attestation="$(unique_value "${workspace_attestation_output}" workspace_attestation_sha256)"
protected_file_set_attestation="$(unique_value "${workspace_attestation_output}" protected_file_set_sha256)"
workspace_validation_utc="$(unique_value "${workspace_attestation_output}" validation_utc)"
workspace_validation_attestation="$(unique_value "${workspace_attestation_output}" validation_attestation_sha256)"
require_sha256 fresh_workspace_attestation_sha256 "${fresh_workspace_attestation}"
require_sha256 protected_file_set_sha256 "${protected_file_set_attestation}"
require_sha256 validation_attestation_sha256 "${workspace_validation_attestation}"
workspace_validation_epoch="$(canonical_utc_epoch 'Windows protected-file validation_utc' "${workspace_validation_utc}")" || exit 1
workspace_validation_now_epoch="$(date -u +%s)"
workspace_validation_age=$((workspace_validation_now_epoch - workspace_validation_epoch))
(( workspace_validation_age >= 0 && workspace_validation_age <= 300 )) || {
  printf 'Windows protected-file validation is stale or future-dated\n' >&2
  exit 1
}
[[ "${receipt_lock_hash}" == "${lock_hash}" ]] || { printf 'Receipt provider-lock hash mismatch\n' >&2; exit 1; }
[[ "${receipt_plan_hash}" == "${plan_hash}" ]] || { printf 'Receipt saved-plan hash mismatch\n' >&2; exit 1; }
[[ "${receipt_backend_hash}" == "${backend_metadata_hash}" ]] || { printf 'Receipt backend-metadata hash mismatch\n' >&2; exit 1; }
[[ "${receipt_state_binding_hash}" == "${state_binding_hash}" ]] || { printf 'Receipt derived-state binding mismatch\n' >&2; exit 1; }
[[ "${receipt_state_evidence_hash}" == "${state_validation_hash}" ]] || { printf 'Receipt canonical state-evidence hash mismatch\n' >&2; exit 1; }
[[ "${receipt_manual_attestation_hash}" == "${manual_attestation_hash}" ]] || { printf 'Receipt manual-attestation hash mismatch\n' >&2; exit 1; }
[[ "${receipt_workspace_attestation}" == "${CLOUDFLARE_WORKSPACE_ATTESTATION_SHA256}" ]] || { printf 'Receipt protected-workspace attestation mismatch\n' >&2; exit 1; }
[[ "${receipt_workspace_attestation}" == "${fresh_workspace_attestation}" ]] || { printf 'Receipt does not match the current-session protected-workspace validation\n' >&2; exit 1; }
if [[ "${phase}" == admin-route || "${phase}" == admin-api ]]; then
  receipt_recovery_hash="$(unique_value "${receipt_path}" recovery_evidence_sha256)"
  recovery_evidence_hash="$(digest_file "${recovery_evidence_snapshot}")"
  require_sha256 recovery_evidence_sha256 "${receipt_recovery_hash}"
  [[ "${receipt_recovery_hash}" == "${recovery_evidence_hash}" ]] || {
    printf 'Receipt recovery/session evidence hash mismatch\n' >&2
    exit 1
  }

  "${python_command}" -c '
import json
import pathlib
import sys

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

raw = pathlib.Path(sys.argv[1]).read_bytes()
if not raw or len(raw) > 32768 or raw.startswith(b"\xef\xbb\xbf"):
    raise SystemExit(1)
try:
    text = raw.decode("utf-8", errors="strict")
    value = json.loads(text, object_pairs_hook=reject_duplicates)
except (UnicodeError, ValueError):
    raise SystemExit(1)
if not isinstance(value, dict):
    raise SystemExit(1)
' "$(cygpath -w "${recovery_evidence_snapshot}")" || {
    printf 'Recovery/session evidence is not bounded strict UTF-8 JSON\n' >&2
    exit 1
  }

  jq -e \
    --arg phase "${phase}" \
    --arg repository "${repo_commit_hash}" \
    --arg workspace "${fresh_workspace_attestation}" \
    --arg plan "${plan_hash}" \
    --arg audit "${audit_file_hash}" \
    --arg host_identity "$(jq -er '.bindings.host_identity_sha256' "${recovery_evidence_snapshot}")" '
      def nonzero_sha256:
        type == "string" and test("^[0-9a-f]{64}$") and test("[1-9a-f]");
      (keys | sort) == [
        "bindings", "evidence_role", "expires_utc", "fresh_login",
        "generated_utc", "phase", "physical_recovery", "schema", "ssh_sessions"
      ] and
      .schema == "admin-recovery-session-v1" and
      .phase == $phase and
      .evidence_role == "operator-attestation-plus-independent-challenges" and
      (.bindings | keys | sort) == [
        "host_identity_sha256", "predecessor_audit_sha256",
        "repository_commit_sha256", "saved_plan_sha256",
        "workspace_attestation_sha256"
      ] and
      .bindings.repository_commit_sha256 == $repository and
      .bindings.workspace_attestation_sha256 == $workspace and
      .bindings.saved_plan_sha256 == $plan and
      .bindings.predecessor_audit_sha256 == $audit and
      (.bindings.host_identity_sha256 | nonzero_sha256) and
      (.physical_recovery | keys | sort) == [
        "challenge_sha256", "evidence_sha256", "host_identity_sha256",
        "method", "operator_attested", "verified_at"
      ] and
      .physical_recovery.method == "physical-console" and
      .physical_recovery.operator_attested == true and
      .physical_recovery.host_identity_sha256 == .bindings.host_identity_sha256 and
      (.physical_recovery.challenge_sha256 | nonzero_sha256) and
      (.physical_recovery.evidence_sha256 | nonzero_sha256) and
      (.ssh_sessions | type) == "array" and (.ssh_sessions | length) == 2 and
      all(.ssh_sessions[];
        (keys | sort) == [
          "challenge_result_sha256", "challenge_sha256", "evidence_sha256",
          "host_identity_sha256", "kind", "read_only", "session_sha256", "verified_at"
        ] and
        .kind == "retained-session" and .read_only == true and
        .host_identity_sha256 == $host_identity and
        (.session_sha256 | nonzero_sha256) and
        (.challenge_sha256 | nonzero_sha256) and
        (.challenge_result_sha256 | nonzero_sha256) and
        (.evidence_sha256 | nonzero_sha256)
      ) and
      (.fresh_login | keys | sort) == [
        "challenge_result_sha256", "challenge_sha256", "evidence_sha256",
        "host_identity_sha256", "kind", "read_only", "session_sha256", "verified_at"
      ] and
      .fresh_login.kind == "fresh-login" and .fresh_login.read_only == true and
      .fresh_login.host_identity_sha256 == .bindings.host_identity_sha256 and
      (.fresh_login.session_sha256 | nonzero_sha256) and
      (.fresh_login.challenge_sha256 | nonzero_sha256) and
      (.fresh_login.challenge_result_sha256 | nonzero_sha256) and
      (.fresh_login.evidence_sha256 | nonzero_sha256) and
      ([
        .physical_recovery.challenge_sha256,
        .physical_recovery.evidence_sha256,
        .ssh_sessions[0].session_sha256,
        .ssh_sessions[0].challenge_sha256,
        .ssh_sessions[0].challenge_result_sha256,
        .ssh_sessions[0].evidence_sha256,
        .ssh_sessions[1].session_sha256,
        .ssh_sessions[1].challenge_sha256,
        .ssh_sessions[1].challenge_result_sha256,
        .ssh_sessions[1].evidence_sha256,
        .fresh_login.session_sha256,
        .fresh_login.challenge_sha256,
        .fresh_login.challenge_result_sha256,
        .fresh_login.evidence_sha256
      ] as $proof_hashes | ($proof_hashes | unique | length) == ($proof_hashes | length))
    ' "${recovery_evidence_snapshot}" >/dev/null || {
      printf 'Recovery/session evidence schema or binding mismatch\n' >&2
      exit 1
    }

  recovery_generated_utc="$(jq -er '.generated_utc' "${recovery_evidence_snapshot}")"
  recovery_expires_utc="$(jq -er '.expires_utc' "${recovery_evidence_snapshot}")"
  recovery_physical_utc="$(jq -er '.physical_recovery.verified_at' "${recovery_evidence_snapshot}")"
  recovery_fresh_login_utc="$(jq -er '.fresh_login.verified_at' "${recovery_evidence_snapshot}")"
  mapfile -t recovery_session_times < <(jq -er '.ssh_sessions[].verified_at' "${recovery_evidence_snapshot}")
  [[ "${#recovery_session_times[@]}" -eq 2 ]] || exit 1
  recovery_generated_epoch="$(canonical_utc_epoch 'Recovery generated_utc' "${recovery_generated_utc}")" || exit 1
  recovery_expires_epoch="$(canonical_utc_epoch 'Recovery expires_utc' "${recovery_expires_utc}")" || exit 1
  recovery_physical_epoch="$(canonical_utc_epoch 'Physical recovery verified_at' "${recovery_physical_utc}")" || exit 1
  recovery_session_one_epoch="$(canonical_utc_epoch 'Retained session one verified_at' "${recovery_session_times[0]}")" || exit 1
  recovery_session_two_epoch="$(canonical_utc_epoch 'Retained session two verified_at' "${recovery_session_times[1]}")" || exit 1
  recovery_fresh_login_epoch="$(canonical_utc_epoch 'Fresh login verified_at' "${recovery_fresh_login_utc}")" || exit 1
  recovery_now_epoch="$(date -u +%s)"
  (( recovery_expires_epoch > recovery_generated_epoch &&
     recovery_expires_epoch - recovery_generated_epoch <= 300 &&
     recovery_now_epoch >= recovery_generated_epoch &&
     recovery_now_epoch <= recovery_expires_epoch )) || {
    printf 'Recovery/session evidence is stale, future-dated, or has a TTL above five minutes\n' >&2
    exit 1
  }
  for proof_epoch in \
    "${recovery_physical_epoch}" "${recovery_session_one_epoch}" \
    "${recovery_session_two_epoch}" "${recovery_fresh_login_epoch}"; do
    (( proof_epoch <= recovery_generated_epoch && recovery_generated_epoch - proof_epoch <= 300 )) || {
      printf 'One recovery/session challenge is outside the fresh evidence window\n' >&2
      exit 1
    }
  done
  session_delta=$((recovery_session_one_epoch - recovery_session_two_epoch))
  (( session_delta < 0 )) && session_delta=$((-session_delta))
  (( session_delta <= 60 &&
     recovery_fresh_login_epoch >= recovery_session_one_epoch &&
     recovery_fresh_login_epoch >= recovery_session_two_epoch )) || {
    printf 'Two retained sessions were not shown concurrently before the fresh login challenge\n' >&2
    exit 1
  }
fi
if [[ "${phase}" == public-dns-lidersea ]]; then
  jq -eRs 'test("^[A-Za-z0-9_-]{8,128}\\n?$") and (contains("\r") | not)' \
    "${naranjo_token_id_snapshot}" >/dev/null || {
      printf 'Naranjo token-ID record is not one bounded non-secret identifier\n' >&2
      exit 1
    }
  naranjo_target_hash="$(digest_file "${naranjo_target_snapshot}")"
  naranjo_plan_hash="$(digest_file "${naranjo_plan_snapshot}")"
  naranjo_state_evidence_hash="$(digest_file "${naranjo_state_evidence_snapshot}")"
  naranjo_pre_state_receipt_hash="$(digest_file "${naranjo_pre_state_receipt_snapshot}")"
  naranjo_pre_audit_hash="$(digest_file "${naranjo_pre_audit_snapshot}")"
  naranjo_source_ip_hash="$(digest_file "${naranjo_source_ip_snapshot}")"
  naranjo_token_id_hash="$(digest_file "${naranjo_token_id_snapshot}")"
  naranjo_preflight_hash="$(digest_file "${naranjo_preflight_snapshot}")"
  naranjo_postflight_hash="$(digest_file "${naranjo_postflight_snapshot}")"
  naranjo_token_receipt_hash="$(digest_file "${naranjo_token_receipt_snapshot}")"
  naranjo_lock_hash="$(digest_file "${naranjo_lock_snapshot}")"
  naranjo_prestate_arguments=(
    predecessor
    --receipt "$(cygpath -w "${naranjo_pre_state_receipt_snapshot}")"
    --state-evidence "$(cygpath -w "${naranjo_state_evidence_snapshot}")"
    --phase public-dns-naranjo
    --repository-commit "${repo_commit}"
    --saved-plan-sha256 "${naranjo_plan_hash}"
    --provider-lock-sha256 "${naranjo_lock_hash}"
  )
  if [[ "${naranjo_state_mode_hint}" == present ]]; then
    naranjo_prestate_arguments+=(--state-file "$(cygpath -w "${naranjo_state_snapshot}")")
  else
    naranjo_prestate_arguments+=(--state-absent)
  fi
  "${python_command}" "$(cygpath -w "${preapply_validator_snapshot}")" \
    "${naranjo_prestate_arguments[@]}" > "${naranjo_prestate_validation_output}" || {
    printf 'Naranjo predecessor pre-state receipt/evidence is invalid\n' >&2
    exit 1
  }
  chmod 400 "${naranjo_prestate_validation_output}" || exit 1
  naranjo_prestate_line_count="$(awk '{sub(/\r$/, "")} END {print NR}' "${naranjo_prestate_validation_output}")"
  naranjo_prestate_pass_count="$(awk '{sub(/\r$/, "")} $0 == "PASS Cloudflare predecessor pre-state evidence" {count++} END {print count + 0}' "${naranjo_prestate_validation_output}")"
  [[ "${naranjo_prestate_line_count}" -eq 9 && "${naranjo_prestate_pass_count}" -eq 1 ]] || {
    printf 'Naranjo predecessor state validation is not the bounded PASS form\n' >&2
    exit 1
  }
  naranjo_state_mode="$(unique_value "${naranjo_prestate_validation_output}" state_mode)"
  naranjo_state_hash="$(unique_value "${naranjo_prestate_validation_output}" state_sha256)"
  naranjo_state_binding_hash="$(unique_value "${naranjo_prestate_validation_output}" state_binding_sha256)"
  naranjo_prestate_workspace_hash="$(unique_value "${naranjo_prestate_validation_output}" workspace_attestation_sha256)"
  naranjo_prestate_planned_utc="$(unique_value "${naranjo_prestate_validation_output}" planned_utc)"
  [[ "${naranjo_state_mode}" == "${naranjo_state_mode_hint}" ]] || {
    printf 'Naranjo state mode does not match the exact transaction inventory\n' >&2
    exit 1
  }
  [[ "$(unique_value "${naranjo_prestate_validation_output}" pre_state_receipt_sha256)" == "${naranjo_pre_state_receipt_hash}" && \
      "$(unique_value "${naranjo_prestate_validation_output}" state_evidence_sha256)" == "${naranjo_state_evidence_hash}" ]] || {
    printf 'Naranjo predecessor validation does not bind its preserved inputs\n' >&2
    exit 1
  }
  if [[ "${naranjo_state_mode}" == present ]]; then
    require_sha256 "Naranjo state" "${naranjo_state_hash}"
    [[ "${naranjo_state_hash}" == "$(digest_file "${naranjo_state_snapshot}")" ]] || {
      printf 'Naranjo present state hash does not match its snapshot\n' >&2
      exit 1
    }
  else
    [[ "${naranjo_state_hash}" == absent && -z "${naranjo_state_snapshot:-}" ]] || {
      printf 'Naranjo absent state transaction contains state bytes\n' >&2
      exit 1
    }
  fi
  for binding_pair in \
    "target:${naranjo_target_hash}" \
    "plan:${naranjo_plan_hash}" \
    "state-evidence:${naranjo_state_evidence_hash}" \
    "pre-state-receipt:${naranjo_pre_state_receipt_hash}" \
    "state-binding:${naranjo_state_binding_hash}" \
    "pre-state-workspace:${naranjo_prestate_workspace_hash}" \
    "pre-audit:${naranjo_pre_audit_hash}" \
    "source-IP:${naranjo_source_ip_hash}" \
    "token-ID:${naranjo_token_id_hash}" \
    "preflight:${naranjo_preflight_hash}" \
    "postflight:${naranjo_postflight_hash}" \
    "token-receipt:${naranjo_token_receipt_hash}" \
    "provider-lock:${naranjo_lock_hash}"; do
    require_sha256 "Naranjo ${binding_pair%%:*}" "${binding_pair#*:}"
  done

  tofu -chdir="${naranjo_phase_root}" show -json "${naranjo_plan_snapshot}" > "${predecessor_raw_json}"
  jq --arg phase public-dns-naranjo '. + {codex_contract: {phase: $phase}}' \
    "${predecessor_raw_json}" > "${predecessor_policy_json}"
  conftest test --policy "${policy_snapshot}" "${predecessor_policy_json}"

  [[ "$(unique_value "${naranjo_pre_audit_snapshot}" audit_result)" == pass ]] || {
    printf 'Naranjo pre-operation audit evidence is not a completed pass\n' >&2
    exit 1
  }
  [[ "$(unique_value "${naranjo_pre_audit_snapshot}" audit_phase)" == public-edge ]] || {
    printf 'Naranjo pre-operation audit is not from public-edge\n' >&2
    exit 1
  }
  naranjo_pre_audit_generated="$(unique_value "${naranjo_pre_audit_snapshot}" generated_utc)"
  naranjo_pre_audit_epoch="$(canonical_utc_epoch 'Naranjo pre-operation audit generated_utc' "${naranjo_pre_audit_generated}")" || exit 1

  for inherited_name in \
    CLOUDFLARE_PHASE_TOKEN_RECEIPT WEBSITE_INFRA_CREDENTIAL_ROOT CLOUDFLARE_RECEIPT_PHASE \
    CLOUDFLARE_EXPECTED_TARGET_SHA256 CLOUDFLARE_EXPECTED_WORKSPACE_ATTESTATION_SHA256 \
    CLOUDFLARE_EXPECTED_SAVED_PLAN_SHA256 CLOUDFLARE_EXPECTED_STATE_MODE \
    CLOUDFLARE_EXPECTED_STATE_BINDING_SHA256 CLOUDFLARE_EXPECTED_STATE_SHA256 \
    CLOUDFLARE_EXPECTED_PROVIDER_LOCK_SHA256 CLOUDFLARE_EXPECTED_REPOSITORY_COMMIT_SHA256 \
    CLOUDFLARE_EXPECTED_AUDIT_SHA256 CLOUDFLARE_EXPECTED_POST_AUDIT_SHA256 \
    CLOUDFLARE_EXPECTED_TOKEN_ID_SHA256 \
    CLOUDFLARE_EXPECTED_SOURCE_IP_POLICY_SHA256 CLOUDFLARE_EXPECTED_PREFLIGHT_EVIDENCE_SHA256 \
    CLOUDFLARE_EXPECTED_POSTFLIGHT_EVIDENCE_SHA256; do
    unset "${inherited_name}"
  done
  naranjo_token_validator_arguments=(
    --receipt "$(cygpath -w "${naranjo_token_receipt_snapshot}")" \
    --credential-root "$(cygpath -w "${protected_root}")" \
    --phase public-dns-naranjo \
    --target-sha256 "${naranjo_target_hash}" \
    --workspace-attestation-sha256 "${naranjo_prestate_workspace_hash}" \
    --saved-plan-sha256 "${naranjo_plan_hash}" \
    --state-mode "${naranjo_state_mode}" \
    --state-binding-sha256 "${naranjo_state_binding_hash}" \
    --provider-lock-sha256 "${naranjo_lock_hash}" \
    --repository-commit-sha256 "${repo_commit_hash}" \
    --audit-sha256 "${naranjo_pre_audit_hash}" \
    --post-audit-sha256 "${audit_file_hash}" \
    --token-id-sha256 "${naranjo_token_id_hash}" \
    --source-ip-policy-sha256 "${naranjo_source_ip_hash}" \
    --preflight-evidence-sha256 "${naranjo_preflight_hash}" \
    --postflight-evidence-sha256 "${naranjo_postflight_hash}"
  )
  if [[ "${naranjo_state_mode}" == present ]]; then
    naranjo_token_validator_arguments+=(--state-sha256 "${naranjo_state_hash}")
  fi
  "${python_command}" "$(cygpath -w "${token_validator_snapshot}")" \
    "${naranjo_token_validator_arguments[@]}" > "${naranjo_token_validation_output}"
  chmod 400 "${naranjo_token_validation_output}" || exit 1
  naranjo_token_validation_hash="$(digest_file "${naranjo_token_validation_output}")"
  require_sha256 predecessor_token_validation_sha256 "${naranjo_token_validation_hash}"

  receipt_predecessor_audit_hash="$(unique_value "${receipt_path}" predecessor_post_audit_sha256)"
  receipt_predecessor_pre_state_hash="$(unique_value "${receipt_path}" predecessor_pre_state_receipt_sha256)"
  receipt_predecessor_state_evidence_hash="$(unique_value "${receipt_path}" predecessor_state_evidence_sha256)"
  receipt_predecessor_token_hash="$(unique_value "${receipt_path}" predecessor_token_receipt_sha256)"
  receipt_predecessor_validation_hash="$(unique_value "${receipt_path}" predecessor_token_validation_sha256)"
  require_sha256 predecessor_post_audit_sha256 "${receipt_predecessor_audit_hash}"
  require_sha256 predecessor_pre_state_receipt_sha256 "${receipt_predecessor_pre_state_hash}"
  require_sha256 predecessor_state_evidence_sha256 "${receipt_predecessor_state_evidence_hash}"
  require_sha256 predecessor_token_receipt_sha256 "${receipt_predecessor_token_hash}"
  require_sha256 predecessor_token_validation_sha256 "${receipt_predecessor_validation_hash}"
  [[ "${receipt_predecessor_audit_hash}" == "${audit_file_hash}" ]] || { printf 'Receipt Naranjo post-audit hash mismatch\n' >&2; exit 1; }
  [[ "${receipt_predecessor_pre_state_hash}" == "${naranjo_pre_state_receipt_hash}" ]] || { printf 'Receipt Naranjo pre-state-receipt hash mismatch\n' >&2; exit 1; }
  [[ "${receipt_predecessor_state_evidence_hash}" == "${naranjo_state_evidence_hash}" ]] || { printf 'Receipt Naranjo state-evidence hash mismatch\n' >&2; exit 1; }
  [[ "${receipt_predecessor_token_hash}" == "${naranjo_token_receipt_hash}" ]] || { printf 'Receipt Naranjo token-receipt hash mismatch\n' >&2; exit 1; }
  [[ "${receipt_predecessor_validation_hash}" == "${naranjo_token_validation_hash}" ]] || { printf 'Receipt Naranjo token-validation hash mismatch\n' >&2; exit 1; }

  validation_line_count="$(awk '{sub(/\r$/, "")} END {print NR}' "${naranjo_token_validation_output}")"
  validation_pass_count="$(awk '{sub(/\r$/, "")} $0 == "PASS Cloudflare phase-token receipt" {count++} END {print count + 0}' "${naranjo_token_validation_output}")"
  [[ "${validation_line_count}" -eq 4 && "${validation_pass_count}" -eq 1 ]] || { printf 'Naranjo token validation evidence is not the bounded PASS form\n' >&2; exit 1; }
  [[ "$(unique_value "${naranjo_token_validation_output}" phase)" == public-dns-naranjo ]] || { printf 'Naranjo token validation phase mismatch\n' >&2; exit 1; }
  [[ "$(unique_value "${naranjo_token_validation_output}" receipt_sha256)" == "${naranjo_token_receipt_hash}" ]] || { printf 'Naranjo validator evidence does not bind the token receipt\n' >&2; exit 1; }
  [[ "$(unique_value "${naranjo_token_validation_output}" evidence_role)" == operator-attestation-plus-live-verification-record ]] || { printf 'Naranjo token validation evidence role mismatch\n' >&2; exit 1; }
  jq -e \
    --arg workspace "${naranjo_prestate_workspace_hash}" \
    --arg repository "${repo_commit_hash}" \
    --arg provider_lock "${naranjo_lock_hash}" \
    --arg state_mode "${naranjo_state_mode}" \
    --arg state_binding "${naranjo_state_binding_hash}" \
    --arg state_sha "${naranjo_state_hash}" \
    --arg pre_audit "${naranjo_pre_audit_hash}" \
    --arg post_audit "${audit_file_hash}" '
      .schema == "cloudflare-phase-token-receipt-v2" and
      .phase == "public-dns-naranjo" and .operation == "apply" and
      .verification.postflight.revocation_status == "verified" and
      .bindings.workspace_attestation_sha256 == $workspace and
      .bindings.repository_commit_sha256 == $repository and
      .bindings.provider_lock_sha256 == $provider_lock and
      .bindings.state_mode == $state_mode and
      .bindings.state_binding_sha256 == $state_binding and
      (($state_mode == "present" and .bindings.state_sha256 == $state_sha) or
       ($state_mode == "absent" and .bindings.state_sha256 == null)) and
      .bindings.audit_sha256 == $pre_audit and
      .bindings.post_audit_sha256 == $post_audit
    ' >/dev/null "${naranjo_token_receipt_snapshot}" || { printf 'Naranjo token receipt does not bind the current protected transaction\n' >&2; exit 1; }
  naranjo_token_issued_utc="$(jq -er '.token_policy.issued_at' "${naranjo_token_receipt_snapshot}")" || exit 1
  naranjo_token_issued_epoch="$(canonical_utc_epoch 'Naranjo token issued_at' "${naranjo_token_issued_utc}")" || exit 1
  naranjo_prestate_planned_epoch="$(canonical_utc_epoch 'Naranjo pre-state planned_utc' "${naranjo_prestate_planned_utc}")" || exit 1
  (( naranjo_prestate_planned_epoch <= naranjo_token_issued_epoch && naranjo_token_issued_epoch - naranjo_prestate_planned_epoch <= 900 )) || {
    printf 'Naranjo token was not issued within 900 seconds after its bound saved plan\n' >&2
    exit 1
  }
  (( naranjo_pre_audit_epoch <= naranjo_token_issued_epoch && naranjo_token_issued_epoch - naranjo_pre_audit_epoch <= 900 )) || {
    printf 'Naranjo token was not issued within 900 seconds after its pre-operation audit\n' >&2
    exit 1
  }
  naranjo_revocation_verified_utc="$(jq -er '.verification.postflight.verified_at' "${naranjo_token_receipt_snapshot}")" || { printf 'Naranjo token receipt lacks a revocation-verification time\n' >&2; exit 1; }
fi
planned_epoch="$(canonical_utc_epoch 'Receipt planned_utc' "${planned_utc}")" || exit 1
now_epoch="$(date -u +%s)"
plan_age=$((now_epoch - planned_epoch))
plan_max_age="${CLOUDFLARE_PLAN_MAX_AGE_SECONDS:-900}"
if ! [[ "${plan_max_age}" =~ ^[0-9]+$ ]] || (( plan_max_age < 60 || plan_max_age > 3600 )); then
  printf 'CLOUDFLARE_PLAN_MAX_AGE_SECONDS must be 60-3600\n' >&2
  exit 2
fi
(( plan_age >= 0 && plan_age <= plan_max_age )) || { printf 'Saved plan receipt is stale or future-dated\n' >&2; exit 1; }

audit_result="$(unique_value "${audit_path}" audit_result)"
[[ "${audit_result}" == pass ]] || { printf 'Audit evidence is not a completed pass\n' >&2; exit 1; }
audit_phase="$(unique_value "${audit_path}" audit_phase)"
case "${phase}" in
  admin-tunnel) expected_audit_phase=preflight ;;
  admin-policies) expected_audit_phase=admin-tunnel ;;
  admin-route) expected_audit_phase=admin-policies ;;
  admin-api) expected_audit_phase=admin-route ;;
  public-edge) expected_audit_phase=public-edge-preflight ;;
  public-dns-naranjo) expected_audit_phase=public-edge ;;
  public-dns-lidersea) expected_audit_phase=public-dns-naranjo ;;
esac
[[ "${audit_phase}" == "${expected_audit_phase}" ]] || { printf 'Audit evidence is from the wrong predecessor phase\n' >&2; exit 1; }
audit_generated="$(unique_value "${audit_path}" generated_utc)"
audit_epoch="$(canonical_utc_epoch 'Audit generated_utc' "${audit_generated}")" || exit 1
audit_age=$((now_epoch - audit_epoch))
if [[ "${phase}" == public-dns-lidersea ]]; then
  naranjo_revocation_epoch="$(canonical_utc_epoch 'Naranjo revocation-verification timestamp' "${naranjo_revocation_verified_utc}")" || exit 1
  naranjo_chronology_result="$(
    "${python_command}" "$(cygpath -w "${preapply_validator_snapshot}")" chronology \
      --revocation-verified-utc "${naranjo_revocation_verified_utc}" \
      --post-audit-utc "${audit_generated}"
  )" || { printf 'Naranjo post-audit must follow revocation/rejection verification\n' >&2; exit 1; }
  [[ "${naranjo_chronology_result}" == "PASS Cloudflare post-audit chronology" && \
      "${audit_epoch}" -ge "${naranjo_revocation_epoch}" && "${audit_epoch}" -le "${now_epoch}" ]] || {
    printf 'Naranjo post-audit must follow revocation/rejection verification\n' >&2
    exit 1
  }
fi
audit_max_age="${CLOUDFLARE_AUDIT_MAX_AGE_SECONDS:-900}"
if ! [[ "${audit_max_age}" =~ ^[0-9]+$ ]] || (( audit_max_age < 60 || audit_max_age > 3600 )); then
  printf 'CLOUDFLARE_AUDIT_MAX_AGE_SECONDS must be 60-3600\n' >&2
  exit 2
fi
(( audit_age >= 0 && audit_age <= audit_max_age )) || { printf 'Audit evidence is stale or future-dated\n' >&2; exit 1; }

plan_variable() {
  jq -er --arg name "$1" '.variables[$name].value' "${policy_json}"
}

require_hex32() {
  [[ "$2" =~ ^[0-9a-f]{32}$ && "$2" =~ [1-9a-f] ]] || { printf '%s is not a resolved nonzero 32-hex target\n' "$1" >&2; exit 1; }
}

require_uuid() {
  [[ "$2" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || { printf '%s is not a resolved real Tunnel UUID\n' "$1" >&2; exit 1; }
}

account_binding_fingerprint() {
  printf 'phase=account\naccount=%s\n' "$1" | digest_stream
}

admin_contract_fingerprint() {
  printf 'phase=%s\naccount=%s\ntunnel=%s\nnetwork=%s\n' "$1" "$2" "$3" "$4" | digest_stream
}

admin_policy_fingerprint() {
  printf 'phase=%s\naccount=%s\ntunnel=%s\nnetwork=%s\nidentity=%s\nposture_id=%s\nposture_sha256=%s\nsession=%s\nssh_precedence=%s\nblock_precedence=%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" | digest_stream
}

admin_api_inputs_fingerprint() {
  printf 'phase=admin-api-inputs\naccount=%s\ntunnel=%s\nnetwork=%s\nidentity=%s\nposture_id=%s\nposture_sha256=%s\nsession=%s\nssh_precedence=%s\napi_precedence=%s\nblock_precedence=%s\npolicies_sha256=%s\nroute_sha256=%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "${12}" | digest_stream
}

admin_tunnel_fingerprint() {
  printf 'phase=admin-tunnel\naccount=%s\ntunnel=%s\n' "$1" "$2" | digest_stream
}

public_edge_fingerprint() {
  printf 'phase=public-edge\naccount=%s\ntunnel=%s\n' "$1" "$2" | digest_stream
}

public_dns_binding_fingerprint() {
  printf 'phase=%s\naccount=%s\ntunnel=%s\nzone=%s\nhostname=%s\n' "$1" "$2" "$3" "$4" "$5" | digest_stream
}

jit_account_scope_fingerprint() {
  printf 'resource_scope=exact-account\ncloudflare_account_id=%s\n' "$1" | digest_stream
}

jit_zone_scope_fingerprint() {
  printf 'resource_scope=exact-zone\ncloudflare_account_id=%s\ncloudflare_zone_id=%s\n' "$1" "$2" | digest_stream
}

assert_audit_hash() {
  local label="$1"
  local expected="$2"
  local audited
  audited="$(unique_value "${audit_path}" "${label}")"
  require_sha256 "${label}" "${audited}"
  [[ "${audited}" == "${expected}" ]] || { printf 'Plan does not match redacted audit contract %s\n' "${label}" >&2; exit 1; }
}

require_audit_hash() {
  local label="$1"
  local audited
  audited="$(unique_value "${audit_path}" "${label}")"
  require_sha256 "${label}" "${audited}"
}

assert_audit_value() {
  local label="$1"
  local expected="$2"
  local audited
  audited="$(unique_value "${audit_path}" "${label}")"
  [[ "${audited}" == "${expected}" ]] || { printf 'Audit predecessor state mismatch for %s\n' "${label}" >&2; exit 1; }
}

assert_public_admin_path() {
  local gateway_count api_state
  require_audit_hash admin_tunnel_contract_sha256
  require_audit_hash admin_posture_contract_sha256
  require_audit_hash admin_policies_contract_sha256
  require_audit_hash admin_route_contract_sha256
  assert_audit_value private_route_inventory_count 1
  gateway_count="$(unique_value "${audit_path}" gateway_policy_inventory_count)"
  api_state="$(unique_value "${audit_path}" pi_admin_api_policy_activation_state)"
  if [[ "${api_state}" == absent ]]; then
    [[ "${gateway_count}" == 2 ]] || {
      printf 'Public predecessor audit does not close the two-rule admin policy inventory\n' >&2
      exit 1
    }
  elif [[ "${api_state}" == exact ]]; then
    [[ "${gateway_count}" == 3 ]] || {
      printf 'Public predecessor audit does not close the three-rule admin policy inventory\n' >&2
      exit 1
    }
  else
    printf 'Public predecessor audit has a conflicting admin API policy state\n' >&2
    exit 1
  fi
}

account_id="$(plan_variable cloudflare_account_id)"
require_hex32 cloudflare_account_id "${account_id}"
case "${phase}" in
  admin-tunnel)
    assert_audit_hash account_binding_sha256 "$(account_binding_fingerprint "${account_id}")"
    assert_audit_value pi_admin_tunnel_activation_state absent
    assert_audit_value cloudflare_tunnel_inventory_count 0
    assert_audit_value gateway_l4_inventory_count 0
    assert_audit_value gateway_policy_inventory_count 0
    assert_audit_value private_route_inventory_count 0
    ;;
  public-edge)
    assert_audit_hash account_binding_sha256 "$(account_binding_fingerprint "${account_id}")"
    assert_public_admin_path
    assert_audit_value cloudflare_tunnel_inventory_count 1
    assert_audit_value pi_websites_tunnel_activation_state absent
    assert_audit_value public_dns_naranjo_activation_state absent
    assert_audit_value public_dns_lidersea_activation_state absent
    ;;
  admin-policies)
    tunnel_id="$(plan_variable pi_admin_tunnel_id)"
    network="$(plan_variable pi_admin_cidr)"
    admin_email="$(plan_variable admin_email)"
    posture_id="$(plan_variable admin_device_posture_check_id)"
    plan_contract="$(plan_variable verified_admin_tunnel_contract_sha256)"
    posture_contract="$(plan_variable verified_admin_posture_contract_sha256)"
    policy_inputs_contract="$(plan_variable verified_admin_policy_inputs_contract_sha256)"
    session_freshness="$(plan_variable admin_session_freshness)"
    ssh_precedence="$(plan_variable pi_admin_ssh_allow_precedence)"
    block_precedence="$(plan_variable pi_admin_block_precedence)"
    require_uuid pi_admin_tunnel_id "${tunnel_id}"
    require_uuid admin_device_posture_check_id "${posture_id}"
    require_sha256 verified_admin_tunnel_contract_sha256 "${plan_contract}"
    require_sha256 verified_admin_posture_contract_sha256 "${posture_contract}"
    require_sha256 verified_admin_policy_inputs_contract_sha256 "${policy_inputs_contract}"
    expected_contract="$(admin_tunnel_fingerprint "${account_id}" "${tunnel_id}")"
    [[ "${plan_contract}" == "${expected_contract}" ]] || { printf 'Plan-carried admin-tunnel contract does not bind its targets\n' >&2; exit 1; }
    assert_audit_hash admin_tunnel_contract_sha256 "${expected_contract}"
    assert_audit_hash admin_posture_contract_sha256 "${posture_contract}"
    expected_policy_inputs="$(admin_policy_fingerprint admin-policy-inputs "${account_id}" "${tunnel_id}" "${network}" "${admin_email}" "${posture_id}" "${posture_contract}" "${session_freshness}" "${ssh_precedence}" "${block_precedence}")"
    [[ "${policy_inputs_contract}" == "${expected_policy_inputs}" ]] || { printf 'Plan-carried admin policy-input contract does not bind identity, posture, session, and precedence\n' >&2; exit 1; }
    assert_audit_hash admin_policy_inputs_contract_sha256 "${expected_policy_inputs}"
    assert_audit_value gateway_policy_inventory_count 0
    ;;
  admin-route)
    tunnel_id="$(plan_variable pi_admin_tunnel_id)"
    network="$(plan_variable pi_admin_cidr)"
    admin_email="$(plan_variable admin_email)"
    posture_id="$(plan_variable admin_device_posture_check_id)"
    posture_contract="$(plan_variable verified_admin_posture_contract_sha256)"
    session_freshness="$(plan_variable admin_session_freshness)"
    ssh_precedence="$(plan_variable pi_admin_ssh_allow_precedence)"
    block_precedence="$(plan_variable pi_admin_block_precedence)"
    plan_contract="$(plan_variable verified_admin_policies_contract_sha256)"
    require_uuid pi_admin_tunnel_id "${tunnel_id}"
    require_uuid admin_device_posture_check_id "${posture_id}"
    require_sha256 verified_admin_posture_contract_sha256 "${posture_contract}"
    require_sha256 verified_admin_policies_contract_sha256 "${plan_contract}"
    expected_contract="$(admin_policy_fingerprint admin-policies "${account_id}" "${tunnel_id}" "${network}" "${admin_email}" "${posture_id}" "${posture_contract}" "${session_freshness}" "${ssh_precedence}" "${block_precedence}")"
    [[ "${plan_contract}" == "${expected_contract}" ]] || { printf 'Plan-carried admin-policies contract does not bind its targets\n' >&2; exit 1; }
    assert_audit_hash admin_posture_contract_sha256 "${posture_contract}"
    assert_audit_hash admin_policies_contract_sha256 "${expected_contract}"
    assert_audit_value gateway_policy_inventory_count 2
    assert_audit_value pi_admin_api_policy_activation_state absent
    ;;
  admin-api)
    tunnel_id="$(plan_variable pi_admin_tunnel_id)"
    network="$(plan_variable pi_admin_cidr)"
    admin_email="$(plan_variable admin_email)"
    posture_id="$(plan_variable admin_device_posture_check_id)"
    posture_contract="$(plan_variable verified_admin_posture_contract_sha256)"
    policies_contract="$(plan_variable verified_admin_policies_contract_sha256)"
    session_freshness="$(plan_variable admin_session_freshness)"
    ssh_precedence="$(plan_variable pi_admin_ssh_allow_precedence)"
    api_precedence="$(plan_variable pi_admin_api_allow_precedence)"
    block_precedence="$(plan_variable pi_admin_block_precedence)"
    plan_contract="$(plan_variable verified_admin_route_contract_sha256)"
    api_inputs_contract="$(plan_variable verified_admin_api_inputs_contract_sha256)"
    require_uuid pi_admin_tunnel_id "${tunnel_id}"
    require_uuid admin_device_posture_check_id "${posture_id}"
    require_sha256 verified_admin_posture_contract_sha256 "${posture_contract}"
    require_sha256 verified_admin_policies_contract_sha256 "${policies_contract}"
    require_sha256 verified_admin_route_contract_sha256 "${plan_contract}"
    require_sha256 verified_admin_api_inputs_contract_sha256 "${api_inputs_contract}"
    expected_policies_contract="$(admin_policy_fingerprint admin-policies "${account_id}" "${tunnel_id}" "${network}" "${admin_email}" "${posture_id}" "${posture_contract}" "${session_freshness}" "${ssh_precedence}" "${block_precedence}")"
    [[ "${policies_contract}" == "${expected_policies_contract}" ]] || { printf 'Plan-carried admin-policies contract does not bind API identity, posture, session, and precedence\n' >&2; exit 1; }
    assert_audit_hash admin_posture_contract_sha256 "${posture_contract}"
    assert_audit_hash admin_policies_contract_sha256 "${expected_policies_contract}"
    expected_contract="$(admin_contract_fingerprint admin-route "${account_id}" "${tunnel_id}" "${network}")"
    [[ "${plan_contract}" == "${expected_contract}" ]] || { printf 'Plan-carried admin-route contract does not bind its targets\n' >&2; exit 1; }
    assert_audit_hash admin_route_contract_sha256 "${expected_contract}"
    expected_api_inputs="$(admin_api_inputs_fingerprint "${account_id}" "${tunnel_id}" "${network}" "${admin_email}" "${posture_id}" "${posture_contract}" "${session_freshness}" "${ssh_precedence}" "${api_precedence}" "${block_precedence}" "${policies_contract}" "${plan_contract}")"
    [[ "${api_inputs_contract}" == "${expected_api_inputs}" ]] || { printf 'Plan-carried API-input contract does not bind API precedence and predecessor security contracts\n' >&2; exit 1; }
    assert_audit_hash admin_api_inputs_contract_sha256 "${expected_api_inputs}"
    assert_audit_value gateway_policy_inventory_count 2
    assert_audit_value pi_admin_api_policy_activation_state absent
    ;;
  public-dns-naranjo)
    tunnel_id="$(plan_variable pi_websites_tunnel_id)"
    zone_id="$(plan_variable cloudflare_naranjo_online_zone_id)"
    plan_contract="$(plan_variable verified_public_edge_contract_sha256)"
    require_uuid pi_websites_tunnel_id "${tunnel_id}"
    require_hex32 cloudflare_naranjo_online_zone_id "${zone_id}"
    require_sha256 verified_public_edge_contract_sha256 "${plan_contract}"
    expected_contract="$(public_edge_fingerprint "${account_id}" "${tunnel_id}")"
    [[ "${plan_contract}" == "${expected_contract}" ]] || { printf 'Plan-carried public-edge contract does not bind its targets\n' >&2; exit 1; }
    assert_public_admin_path
    assert_audit_hash public_edge_contract_sha256 "${expected_contract}"
    assert_audit_value public_dns_naranjo_activation_state absent
    assert_audit_value public_dns_lidersea_activation_state absent
    assert_audit_hash public_dns_naranjo_binding_sha256 "$(public_dns_binding_fingerprint public-dns-naranjo "${account_id}" "${tunnel_id}" "${zone_id}" naranjo.online)"
    ;;
  public-dns-lidersea)
    tunnel_id="$(plan_variable pi_websites_tunnel_id)"
    zone_id="$(plan_variable cloudflare_lidersea_com_zone_id)"
    plan_contract="$(plan_variable verified_public_edge_contract_sha256)"
    require_uuid pi_websites_tunnel_id "${tunnel_id}"
    require_hex32 cloudflare_lidersea_com_zone_id "${zone_id}"
    require_sha256 verified_public_edge_contract_sha256 "${plan_contract}"
    expected_contract="$(public_edge_fingerprint "${account_id}" "${tunnel_id}")"
    [[ "${plan_contract}" == "${expected_contract}" ]] || { printf 'Plan-carried public-edge contract does not bind its targets\n' >&2; exit 1; }
    assert_public_admin_path
    assert_audit_hash public_edge_contract_sha256 "${expected_contract}"
    assert_audit_value public_dns_naranjo_activation_state exact
    assert_audit_value public_dns_lidersea_activation_state absent
    assert_audit_hash public_dns_lidersea_binding_sha256 "$(public_dns_binding_fingerprint public-dns-lidersea "${account_id}" "${tunnel_id}" "${zone_id}" lidersea.com)"
    ;;
esac

case "${phase}" in
  public-dns-naranjo|public-dns-lidersea)
    manual_scope_binding="$(jit_zone_scope_fingerprint "${account_id}" "${zone_id}")"
    ;;
  *)
    manual_scope_binding="$(jit_account_scope_fingerprint "${account_id}")"
    ;;
esac
require_sha256 manual_scope_binding_sha256 "${manual_scope_binding}"
manual_validator_arguments=(
  manual
  --attestation "$(cygpath -w "${manual_attestation_snapshot}")"
  --phase "${phase}"
  --repository-commit-sha256 "${repo_commit_hash}"
  --workspace-attestation-sha256 "${receipt_workspace_attestation}"
  --saved-plan-sha256 "${plan_hash}"
  --predecessor-audit-sha256 "${audit_file_hash}"
  --provider-lock-sha256 "${lock_hash}"
  --state-binding-sha256 "${state_binding_hash}"
  --scope-binding-sha256 "${manual_scope_binding}"
)
if [[ "${phase}" == admin-route || "${phase}" == admin-api ]]; then
  manual_validator_arguments+=(--recovery-evidence-sha256 "${recovery_evidence_hash}")
fi
"${python_command}" "$(cygpath -w "${preapply_validator_snapshot}")" \
  "${manual_validator_arguments[@]}" > "${manual_validation_output}" || {
  printf 'Reviewed manual pre-apply attestation is invalid\n' >&2
  exit 1
}
chmod 400 "${manual_validation_output}" || exit 1
manual_validation_line_count="$(awk '{sub(/\r$/, "")} END {print NR}' "${manual_validation_output}")"
manual_validation_pass_count="$(awk '{sub(/\r$/, "")} $0 == "PASS Cloudflare pre-apply manual attestation" {count++} END {print count + 0}' "${manual_validation_output}")"
[[ "${manual_validation_line_count}" -eq 4 && "${manual_validation_pass_count}" -eq 1 ]] || {
  printf 'Manual pre-apply validation did not produce bounded PASS evidence\n' >&2
  exit 1
}
[[ "$(unique_value "${manual_validation_output}" phase)" == "${phase}" ]] || {
  printf 'Manual pre-apply validation phase mismatch\n' >&2
  exit 1
}
[[ "$(unique_value "${manual_validation_output}" attestation_sha256)" == "${manual_attestation_hash}" ]] || {
  printf 'Manual pre-apply validation does not bind the protected attestation\n' >&2
  exit 1
}
[[ "$(unique_value "${manual_validation_output}" evidence_role)" == reviewed-manual-preapply-authorization ]] || {
  printf 'Manual pre-apply validation evidence role mismatch\n' >&2
  exit 1
}

[[ "$(git -C "${repo_root}" rev-parse HEAD)" == "${repo_commit}" ]] || {
  printf 'Repository HEAD changed while evaluating the saved plan\n' >&2
  exit 1
}
assert_phase_inventory || exit 1
assert_policy_inventory || exit 1
assert_sources_equal_head || {
  printf 'Cloudflare plan sources changed or differ from the bound repository commit\n' >&2
  exit 1
}
[[ "$(digest_file "${repo_root}/scripts/cloudflare-plan-gate.sh")" == "${gate_source_hash}" ]] || {
  printf 'Cloudflare plan gate source changed while evaluating the plan\n' >&2
  exit 1
}
[[ "$(digest_file "${repo_root}/scripts/cloudflare-audit.sh")" == "${audit_script_source_hash}" ]] || {
  printf 'Cloudflare audit source changed while evaluating the plan\n' >&2
  exit 1
}
[[ "$(digest_file "${repo_root}/scripts/validate_cloudflare_preapply_evidence.py")" == "${preapply_validator_source_hash}" ]] || {
  printf 'Cloudflare pre-apply validator source changed while evaluating the plan\n' >&2
  exit 1
}
assert_snapshot_still_matches cloudflare-policy \
  "${repo_root}/infrastructure/cloudflare/policy/cloudflare-plan.rego" "${policy_snapshot}" || exit 1
assert_snapshot_still_matches windows-workspace-validator \
  "${repo_root}/scripts/validate-windows-credential-workspace.ps1" "${windows_validator_snapshot}" || exit 1
assert_snapshot_still_matches cloudflare-preapply-validator \
  "${repo_root}/scripts/validate_cloudflare_preapply_evidence.py" "${preapply_validator_snapshot}" || exit 1
assert_snapshot_still_matches phase-provider-lock "${lock_path}" "${lock_snapshot}" || exit 1
assert_snapshot_still_matches saved-plan "${plan_source_path}" "${plan_snapshot}" || exit 1
assert_snapshot_still_matches predecessor-audit "${audit_source_path}" "${audit_snapshot}" || exit 1
assert_snapshot_still_matches pre-state-receipt "${receipt_source_path}" "${receipt_snapshot}" || exit 1
assert_handle_snapshot_still_matches backend-metadata "${backend_path}" "${backend_snapshot}" || exit 1
assert_handle_snapshot_still_matches manual-preapply-attestation \
  "${manual_attestation_path}" "${manual_attestation_snapshot}" || exit 1
[[ "$(digest_file "${state_validation_output}")" == "${state_validation_hash}" ]] || {
  printf 'State-validation evidence changed after protected-file validation\n' >&2
  exit 1
}
if [[ "${state_mode}" == present ]]; then
  assert_handle_snapshot_still_matches current-phase-state "${state_path}" "${state_snapshot}" || exit 1
else
  [[ ! -e "${state_path}" && ! -L "${state_path}" && \
      "$(stat -Lc '%d:%i:%f:%h' -- "${state_parent}")" == "${state_parent_identity}" ]] || {
    printf 'Current-phase absent-state proof changed while evaluating the plan\n' >&2
    exit 1
  }
fi
if [[ "${phase}" == admin-route || "${phase}" == admin-api ]]; then
  assert_snapshot_still_matches recovery-session-evidence \
    "${recovery_evidence_path}" "${recovery_evidence_snapshot}" || exit 1
fi
if [[ "${phase}" == public-dns-lidersea ]]; then
  actual_naranjo_inventory="$(find "${naranjo_transaction_root}" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" || exit 1
  if [[ "${naranjo_state_mode_hint}" == present ]]; then
    expected_naranjo_inventory="${expected_naranjo_present_inventory}"
  else
    expected_naranjo_inventory="${expected_naranjo_absent_inventory}"
  fi
  [[ "${actual_naranjo_inventory}" == "${expected_naranjo_inventory}" ]] || {
    printf 'Naranjo transaction inventory changed while evaluating Lidersea\n' >&2
    exit 1
  }
  assert_snapshot_still_matches cloudflare-token-validator \
    "${repo_root}/scripts/validate_cloudflare_token_receipt.py" "${token_validator_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-provider-lock "${naranjo_lock_path}" "${naranjo_lock_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-target-binding "${naranjo_target_path}" "${naranjo_target_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-saved-plan "${naranjo_plan_path}" "${naranjo_plan_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-pre-apply-state-evidence "${naranjo_state_evidence_path}" "${naranjo_state_evidence_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-pre-state-receipt "${naranjo_pre_state_receipt_path}" "${naranjo_pre_state_receipt_snapshot}" || exit 1
  if [[ "${naranjo_state_mode_hint}" == present ]]; then
    assert_snapshot_still_matches naranjo-pre-apply-state "${naranjo_state_path}" "${naranjo_state_snapshot}" || exit 1
  else
    [[ ! -e "${naranjo_transaction_root}/pre-apply-state.tfstate" && ! -L "${naranjo_transaction_root}/pre-apply-state.tfstate" ]] || {
      printf 'Naranjo absent-state transaction gained a state file\n' >&2
      exit 1
    }
  fi
  assert_snapshot_still_matches naranjo-pre-operation-audit "${naranjo_pre_audit_path}" "${naranjo_pre_audit_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-source-IP-policy "${naranjo_source_ip_path}" "${naranjo_source_ip_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-token-ID "${naranjo_token_id_path}" "${naranjo_token_id_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-preflight-evidence "${naranjo_preflight_path}" "${naranjo_preflight_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-postflight-evidence "${naranjo_postflight_path}" "${naranjo_postflight_snapshot}" || exit 1
  assert_snapshot_still_matches naranjo-token-receipt "${naranjo_token_receipt_path}" "${naranjo_token_receipt_snapshot}" || exit 1
fi

printf 'phase=%s\n' "${phase}"
printf 'phase_root=%s\n' "${phase_relative}"
printf 'repo_commit=%s\n' "${repo_commit}"
printf 'phase_lock_sha256=%s\n' "${lock_hash}"
printf 'state_backend=%s\n' "${state_backend}"
printf 'backend_metadata_sha256=%s\n' "${backend_metadata_hash}"
printf 'state_path_sha256=%s\n' "${state_path_hash}"
printf 'state_mode=%s\n' "${state_mode}"
printf 'state_sha256=%s\n' "${state_file_hash}"
printf 'state_lineage_sha256=%s\n' "${state_lineage_hash}"
printf 'state_serial=%s\n' "${state_serial}"
printf 'state_binding_sha256=%s\n' "${state_binding_hash}"
printf 'state_evidence_sha256=%s\n' "${state_validation_hash}"
printf 'plan_sha256=%s\n' "${plan_hash}"
printf 'manual_attestation_sha256=%s\n' "${manual_attestation_hash}"
printf 'manual_attestation_role=reviewed-manual-preapply-authorization\n'
printf 'workspace_attestation_sha256=%s\n' "${receipt_workspace_attestation}"
printf 'protected_file_set_sha256=%s\n' "${protected_file_set_attestation}"
printf 'workspace_validation_attestation_sha256=%s\n' "${workspace_validation_attestation}"
printf 'workspace_validation_age_seconds=%s\n' "${workspace_validation_age}"
printf 'plan_age_seconds=%s\n' "${plan_age}"
printf 'audit_sha256=%s\n' "${audit_file_hash}"
printf 'audit_age_seconds=%s\n' "${audit_age}"
printf 'pre_state_receipt_sha256=%s\n' "${receipt_file_hash}"
if [[ "${phase}" == admin-route || "${phase}" == admin-api ]]; then
  printf 'recovery_evidence_sha256=%s\n' "${recovery_evidence_hash}"
  printf 'recovery_evidence_role=operator-attestation-not-connectivity-proof\n'
fi
if [[ "${phase}" == public-dns-lidersea ]]; then
  printf 'predecessor_post_audit_sha256=%s\n' "${audit_file_hash}"
  printf 'predecessor_pre_state_receipt_sha256=%s\n' "${naranjo_pre_state_receipt_hash}"
  printf 'predecessor_state_evidence_sha256=%s\n' "${naranjo_state_evidence_hash}"
  printf 'predecessor_token_receipt_sha256=%s\n' "${naranjo_token_receipt_hash}"
  printf 'predecessor_token_validation_sha256=%s\n' "${naranjo_token_validation_hash}"
fi
jq -r '[.resource_changes[]? | select(.mode == "managed") | .type] | group_by(.)[] | "resource_count " + .[0] + "=" + (length|tostring)' "${policy_json}"
printf "POLICY PASS ONLY. Expected infrastructure cost remains \$0 subject to current\n"
printf 'The protected manual review and current-state binding passed, but live token\n'
printf 'preflight, child-only launch, post-audit, and revocation remain mandatory.\n'
printf 'This offline result is not apply authorization.\n'
