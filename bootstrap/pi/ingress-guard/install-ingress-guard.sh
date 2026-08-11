#!/usr/bin/env bash
# Operator-run installer for the SSH-only admin-ingress guard (PLAT-DEC-001).
#
# Run ON the Pi from a normal SSH session with sudo, after staging the private
# contract at bootstrap/pi/ingress-guard/admin-ingress.env.local (root-owned,
# mode 0600). It installs the contract, the python validators, the loader and
# verifier, the systemd unit, and the additive kubelet drop-in; enables and
# starts ONLY the guard unit; and then proves the model. It never starts,
# stops, or restarts kubelet, containerd, sshd, NetworkManager, WireGuard, or
# the host firewall, and it refuses to run while kubelet is active — a
# retrofit on a running cluster is a separately authorized live operation.
#
# Failure rolls back exactly the artifacts THIS run created (a bounded list,
# never a directory sweep), leaving pre-existing state untouched, and exits
# non-zero: the guard is absent and kubelet remains blocked — fail closed.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
source_dir="${repo_root}/bootstrap/pi/ingress-guard"
staged_contract="${source_dir}/admin-ingress.env.local"

etc_dir=/etc/website-infrastructure
library_dir=/usr/local/lib/website-infrastructure/ingress-guard
contract_target="${etc_dir}/admin-ingress.env"
loader_target=/usr/local/sbin/website-infrastructure-ingress-guard-load
verify_target=/usr/local/sbin/website-infrastructure-ingress-guard-verify
unit_target=/etc/systemd/system/website-infrastructure-ingress-guard.service
dropin_dir=/etc/systemd/system/kubelet.service.d
dropin_target="${dropin_dir}/50-website-infrastructure-ingress-guard.conf"
guard_unit=website-infrastructure-ingress-guard.service

die() { printf 'INGRESS-GUARD INSTALL FAIL %s\n' "$1" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die NOT_ROOT
# Root SSH is forbidden for this lane: an interactive install must arrive as
# a named operator and elevate with sudo, keeping accountability intact.
if [[ -n "${SSH_CONNECTION:-}" && -z "${SUDO_USER:-}" ]]; then
  die ROOT_SSH_FORBIDDEN
fi
[[ "${CONFIRM_INGRESS_GUARD_INSTALL:-}" == install-reviewed-ssh-only-ingress-guard ]] \
  || die EXACT_CONFIRMATION_MISSING
command -v nft >/dev/null 2>&1 || die NFT_MISSING
command -v python3 >/dev/null 2>&1 || die PYTHON_MISSING
command -v systemctl >/dev/null 2>&1 || die SYSTEMCTL_MISSING
if [[ "$(systemctl show -p ActiveState --value kubelet.service 2>/dev/null)" == active ]]; then
  die KUBELET_ALREADY_ACTIVE
fi

# The staged private contract must already be fully valid (root-owned 0600,
# reviewed, well-formed) before anything is copied anywhere.
python3 -I -B "${repo_root}/scripts/validate_admin_ingress_contract.py" \
  CONTRACT "${staged_contract}" >/dev/null || die STAGED_CONTRACT_INVALID

created_paths=()
enabled_by_this_run=no
rollback() {
  status=$?
  trap - EXIT
  if (( status != 0 )); then
    if [[ "${enabled_by_this_run}" == yes ]]; then
      systemctl disable "${guard_unit}" >/dev/null 2>&1 || true
    fi
    local created
    for created in "${created_paths[@]:-}"; do
      [[ -n "${created}" ]] && rm -f -- "${created}"
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
    printf 'INGRESS-GUARD INSTALL FAIL ROLLED_BACK_THIS_RUN_ONLY\n' >&2
  fi
  exit "${status}"
}
trap rollback EXIT

# install_exact places one file with exact ownership/mode. An existing
# byte-identical destination is idempotent success; an existing divergent
# destination is a hard stop — this installer never overwrites foreign
# content, so a conflicting artifact must be reviewed and removed by hand.
install_exact() {
  local source_path="$1" target_path="$2" mode="$3"
  [[ -f "${source_path}" && ! -L "${source_path}" ]] || die SOURCE_MISSING
  if [[ -e "${target_path}" || -L "${target_path}" ]]; then
    [[ -f "${target_path}" && ! -L "${target_path}" ]] || die TARGET_CONFLICT
    cmp -s -- "${source_path}" "${target_path}" || die TARGET_CONFLICT
    chown root:root -- "${target_path}"
    chmod "${mode}" -- "${target_path}"
    return 0
  fi
  install -o root -g root -m "${mode}" -- "${source_path}" "${target_path}" \
    || die INSTALL_FAILED
  created_paths+=("${target_path}")
}

install -d -o root -g root -m 0700 "${etc_dir}"
install -d -o root -g root -m 0755 /usr/local/lib/website-infrastructure "${library_dir}"
install -d -o root -g root -m 0755 "${dropin_dir}"

install_exact "${staged_contract}" "${contract_target}" 0600
install_exact "${repo_root}/scripts/validate_admin_ingress_contract.py" \
  "${library_dir}/validate_admin_ingress_contract.py" 0644
install_exact "${repo_root}/scripts/validate_ingress_guard.py" \
  "${library_dir}/validate_ingress_guard.py" 0644
install_exact "${source_dir}/load-ingress-guard.sh" "${loader_target}" 0755
install_exact "${source_dir}/verify-ingress-guard.sh" "${verify_target}" 0755
install_exact "${source_dir}/systemd/website-infrastructure-ingress-guard.service" \
  "${unit_target}" 0644
install_exact \
  "${source_dir}/systemd/kubelet.service.d/50-website-infrastructure-ingress-guard.conf" \
  "${dropin_target}" 0644

systemctl daemon-reload || die DAEMON_RELOAD_FAILED
if ! systemctl is-enabled --quiet "${guard_unit}" 2>/dev/null; then
  systemctl enable "${guard_unit}" >/dev/null 2>&1 || die ENABLE_FAILED
  enabled_by_this_run=yes
fi
# Activation runs the transactional loader; its own bounded rollback removes
# the owned table if post-load verification fails.
systemctl start "${guard_unit}" || die GUARD_START_FAILED
"${verify_target}" || die POST_INSTALL_VERIFICATION_FAILED

trap - EXIT
printf 'INGRESS-GUARD INSTALL PASS ssh-only-admin-ingress-guard-installed\n'
printf 'NOTE firewall fingerprints changed by design: rerun reviewed discovery\n'
printf 'NOTE and refresh decisions.env.local fingerprints before init preflight.\n'
