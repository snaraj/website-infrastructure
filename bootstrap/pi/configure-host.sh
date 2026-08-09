#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
mode="${1:---check}"

if [[ "${mode}" == "--check" ]]; then
  printf 'Host configuration check only; no changes will be made.\n'
  systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || true
  sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|allowtcpforwarding|x11forwarding) ' || true
  timedatectl show -p NTPSynchronized --value 2>/dev/null || true
  systemctl is-enabled fstrim.timer 2>/dev/null || true
  printf 'Firewall/VPN rules are intentionally not changed by this script.\n'
  exit 0
fi

if [[ "${mode}" != "--apply-ssh-and-journald" ]]; then
  printf 'Usage: %s [--check|--apply-ssh-and-journald]\n' "$0" >&2
  exit 2
fi

[[ "${EUID}" -eq 0 ]] || { printf 'Apply mode requires root.\n' >&2; exit 2; }
: "${ADMIN_USER:?Set ADMIN_USER to the tested non-root administrator}"
[[ "${ADMIN_USER}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { printf 'ADMIN_USER is not a safe Linux account name.\n' >&2; exit 2; }
[[ "${RECOVERY_SESSION_TESTED:-}" == "yes" ]] || { printf 'Set RECOVERY_SESSION_TESTED=yes only after a second session and physical/LAN recovery are proven.\n' >&2; exit 2; }
[[ "${CONFIRM_HOST_MUTATION:-}" == "apply-reviewed-ssh-journald" ]] || { printf 'Explicit host mutation acknowledgement missing.\n' >&2; exit 2; }
id "${ADMIN_USER}" >/dev/null 2>&1 || { printf 'ADMIN_USER does not exist.\n' >&2; exit 2; }

backup_root="/var/backups/website-infrastructure/$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "${backup_root}"
cp -a /etc/ssh/sshd_config "${backup_root}/sshd_config"
[[ ! -d /etc/ssh/sshd_config.d ]] || cp -a /etc/ssh/sshd_config.d "${backup_root}/sshd_config.d"
[[ ! -d /etc/systemd/journald.conf.d ]] || cp -a /etc/systemd/journald.conf.d "${backup_root}/journald.conf.d"

restore_managed_dropins() {
  if [[ -f "${backup_root}/sshd_config.d/60-platform-hardening.conf" ]]; then
    install -m 0644 "${backup_root}/sshd_config.d/60-platform-hardening.conf" \
      /etc/ssh/sshd_config.d/60-platform-hardening.conf
  else
    rm -f /etc/ssh/sshd_config.d/60-platform-hardening.conf
  fi
  if [[ -f "${backup_root}/journald.conf.d/60-platform-limits.conf" ]]; then
    install -m 0644 "${backup_root}/journald.conf.d/60-platform-limits.conf" \
      /etc/systemd/journald.conf.d/60-platform-limits.conf
  else
    rm -f /etc/systemd/journald.conf.d/60-platform-limits.conf
  fi
}

verify_effective_sshd() {
  local effective
  local host_name
  host_name="$(hostname -f 2>/dev/null || hostname)"
  effective="$(sshd -T -C "user=${ADMIN_USER},host=${host_name},addr=127.0.0.1")" || return 1
  local expected
  for expected in \
    'permitrootlogin no' \
    'passwordauthentication no' \
    'kbdinteractiveauthentication no' \
    'authenticationmethods publickey' \
    'pubkeyauthentication yes' \
    'allowagentforwarding no' \
    'allowtcpforwarding no' \
    'x11forwarding no' \
    'permittunnel no' \
    'gatewayports no' \
    "allowusers ${ADMIN_USER}"; do
    grep -Fqx -- "${expected}" <<<"${effective}" || {
      printf 'effective sshd setting is missing: %s\n' "${expected}" >&2
      return 1
    }
  done
}

install -d -m 0755 /etc/ssh/sshd_config.d /etc/systemd/journald.conf.d
sed "s/REPLACE_ADMIN_USER/${ADMIN_USER}/g" "${repo_root}/bootstrap/pi/sshd/60-platform-hardening.conf" \
  > /etc/ssh/sshd_config.d/60-platform-hardening.conf
chmod 0644 /etc/ssh/sshd_config.d/60-platform-hardening.conf
install -m 0644 "${repo_root}/bootstrap/pi/journald/60-platform-limits.conf" \
  /etc/systemd/journald.conf.d/60-platform-limits.conf

if ! sshd -t || ! verify_effective_sshd; then
  cp -a "${backup_root}/sshd_config" /etc/ssh/sshd_config
  restore_managed_dropins
  printf 'sshd validation failed; restored the exact previous configuration. Review %s locally.\n' "${backup_root}" >&2
  exit 1
fi
if ! systemctl reload ssh 2>/dev/null && ! systemctl reload sshd; then
  cp -a "${backup_root}/sshd_config" /etc/ssh/sshd_config
  restore_managed_dropins
  sshd -t
  systemctl reload ssh 2>/dev/null || systemctl reload sshd || true
  printf 'SSH reload failed; restored the exact previous configuration. Review %s locally.\n' "${backup_root}" >&2
  exit 1
fi
if ! systemctl restart systemd-journald; then
  cp -a "${backup_root}/sshd_config" /etc/ssh/sshd_config
  restore_managed_dropins
  sshd -t
  systemctl reload ssh 2>/dev/null || systemctl reload sshd || true
  systemctl restart systemd-journald || true
  printf 'journald restart failed; restored the exact previous configuration. Review %s locally.\n' "${backup_root}" >&2
  exit 1
fi
printf 'Applied SSH/journald configuration. Keep both existing sessions open and test a third before logout.\n'
printf 'Recovery backup: %s\n' "${backup_root}"
