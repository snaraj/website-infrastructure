#!/usr/bin/env bash
# Read-only semantic verification of the SSH-only admin-ingress guard
# (PLAT-DEC-001). Installed as
# /usr/local/sbin/website-infrastructure-ingress-guard-verify.
#
# Intended callers: the integrator's init preflight immediately before
# `systemctl start kubelet.service`, the post-listener/post-CNI recheck, and
# a human operator. It mutates nothing, prints only fixed value-free tokens,
# and exits non-zero on ANY doubt so callers fail closed. Guard drift is a
# hard stop for review — this script never repairs anything.
set -euo pipefail
umask 077

contract_path=/etc/website-infrastructure/admin-ingress.env
library_dir=/usr/local/lib/website-infrastructure/ingress-guard
guard_unit=website-infrastructure-ingress-guard.service

die() { printf 'INGRESS-GUARD VERIFY FAIL %s\n' "$1" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die NOT_ROOT
command -v nft >/dev/null 2>&1 || die NFT_MISSING
command -v python3 >/dev/null 2>&1 || die PYTHON_MISSING
command -v systemctl >/dev/null 2>&1 || die SYSTEMCTL_MISSING
verifier="${library_dir}/validate_ingress_guard.py"
[[ -f "${verifier}" ]] || die LIBRARY_MISSING

# Persistence proof: the loader must be enabled (reboot coverage) and have
# completed successfully in this boot.
systemctl is-enabled --quiet "${guard_unit}" 2>/dev/null || die UNIT_NOT_ENABLED
[[ "$(systemctl show -p ActiveState --value "${guard_unit}" 2>/dev/null)" == active ]] \
  || die UNIT_NOT_ACTIVE

# Ordering proof: the kubelet drop-in must be loaded so kubelet cannot start
# (and cannot stay started) without this guard.
ordering_after="$(systemctl show -p After --value kubelet.service 2>/dev/null)"
grep -qw -- "${guard_unit}" <<<"${ordering_after}" || die KUBELET_ORDERING_MISSING
ordering_requires="$(systemctl show -p Requires --value kubelet.service 2>/dev/null)"
grep -qw -- "${guard_unit}" <<<"${ordering_requires}" || die KUBELET_REQUIRES_MISSING

# Semantic proof: normalize the live structured ruleset against the closed
# expected model for the securely loaded private contract. The capture lives
# only in a private mode-0700 temporary directory.
capture_dir="$(mktemp -d)"
chmod 0700 "${capture_dir}"
capture="${capture_dir}/ruleset.json"
cleanup() { rm -f -- "${capture}"; rmdir -- "${capture_dir}"; }
trap cleanup EXIT
nft -j list ruleset >"${capture}" 2>/dev/null || die RULESET_CAPTURE_FAILED
python3 -I -B "${verifier}" live \
  --ruleset "${capture}" --contract "${contract_path}" >/dev/null \
  || die MODEL_VERIFICATION_FAILED

printf 'INGRESS-GUARD VERIFY PASS ssh-only-admin-ingress-guard-active\n'
