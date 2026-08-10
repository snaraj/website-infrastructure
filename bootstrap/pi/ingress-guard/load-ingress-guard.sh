#!/usr/bin/env bash
# Transactional loader for the SSH-only admin-ingress guard (PLAT-DEC-001).
# Installed as /usr/local/sbin/website-infrastructure-ingress-guard-load and
# executed only by website-infrastructure-ingress-guard.service.
#
# Every failure path leaves the host either exactly as found or with the
# owned table removed (bounded rollback of one exact identity, never a broad
# flush), and always exits non-zero so the kubelet Requires= dependency stays
# unsatisfied — the guard fails CLOSED. Output is a fixed value-free token
# vocabulary; nft stderr is discarded because it can echo rule text, and no
# interface name is ever printed.
set -euo pipefail
umask 077

contract_path=/etc/website-infrastructure/admin-ingress.env
library_dir=/usr/local/lib/website-infrastructure/ingress-guard
runtime_dir="${RUNTIME_DIRECTORY:-/run/website-infrastructure-ingress-guard}"
owned_table=website_infrastructure_ingress_guard

die() { printf 'INGRESS-GUARD LOAD FAIL %s\n' "$1" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die NOT_ROOT
command -v nft >/dev/null 2>&1 || die NFT_MISSING
command -v python3 >/dev/null 2>&1 || die PYTHON_MISSING
[[ -d "${runtime_dir}" ]] || die RUNTIME_DIRECTORY_MISSING
verifier="${library_dir}/validate_ingress_guard.py"
contract_validator="${library_dir}/validate_admin_ingress_contract.py"
[[ -f "${verifier}" && -f "${contract_validator}" ]] || die LIBRARY_MISSING

capture="${runtime_dir}/ruleset.json"
rendered="${runtime_dir}/guard.nft"
cleanup() { rm -f -- "${capture}" "${rendered}"; }
trap cleanup EXIT

# A missing, unreviewed, or malformed private contract is a hard stop before
# any firewall interaction; its diagnostics are value-free tokens.
python3 -I -B "${contract_validator}" CONTRACT "${contract_path}" >/dev/null \
  || die CONTRACT_INVALID

capture_ruleset() {
  rm -f -- "${capture}"
  nft -j list ruleset >"${capture}" 2>/dev/null || die RULESET_CAPTURE_FAILED
}

verify_live() {
  python3 -I -B "${verifier}" live \
    --ruleset "${capture}" --contract "${contract_path}" >/dev/null
}

verify_absent() {
  python3 -I -B "${verifier}" live \
    --ruleset "${capture}" --contract "${contract_path}" --expect-absent \
    >/dev/null 2>&1
}

capture_ruleset
if ! verify_absent; then
  # The owned identity (or a same-named decoy) already exists. Accept only a
  # byte-for-model exact healthy guard as idempotent success; every other
  # pre-existing state is ambiguous and is never repaired or deleted here.
  if verify_live; then
    printf 'INGRESS-GUARD LOAD PASS already-active-model-verified\n'
    exit 0
  fi
  die PREEXISTING_STATE
fi

# Fresh install: render deterministically from the validated contract, prove
# nft accepts it, then apply in one atomic nft transaction.
python3 -I -B "${verifier}" render \
  --contract "${contract_path}" --output "${rendered}" >/dev/null \
  || die RENDER_FAILED
nft -c -f "${rendered}" 2>/dev/null || die RENDER_REJECTED
nft -f "${rendered}" 2>/dev/null || die APPLY_FAILED

capture_ruleset
if ! verify_live; then
  # Bounded rollback: delete exactly the owned table, then prove the host is
  # back to the owned-identity-absent state. Ambiguity stays fatal.
  nft delete table inet "${owned_table}" 2>/dev/null || die ROLLBACK_FAILED
  capture_ruleset
  verify_absent || die ROLLBACK_AMBIGUOUS
  die ROLLED_BACK_VERIFICATION_FAILED
fi

printf 'INGRESS-GUARD LOAD PASS ssh-only-admin-ingress-guard-active\n'
