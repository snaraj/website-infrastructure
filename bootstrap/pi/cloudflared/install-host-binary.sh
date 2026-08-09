#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
# shellcheck disable=SC1091
source "${repo_root}/versions.env"
mode="${1:---check}"
staged_binary="${CLOUDFLARED_HOST_BINARY_PATH:-${repo_root}/.artifacts/cloudflared-linux-arm64}"

[[ -f "${staged_binary}" ]] || { printf 'staged cloudflared ARM64 binary is missing: %s\n' "${staged_binary}" >&2; exit 1; }
[[ "${CLOUDFLARED_HOST_ARM64_SHA256}" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'CLOUDFLARED_HOST_ARM64_SHA256 is unresolved or malformed.\n' >&2
  exit 1
}
printf '%s  %s\n' "${CLOUDFLARED_HOST_ARM64_SHA256}" "${staged_binary}" | sha256sum --check --status || {
  printf 'cloudflared ARM64 binary checksum mismatch.\n' >&2
  exit 1
}
version_output="$("${staged_binary}" --version)"
grep -Fq "cloudflared version ${CLOUDFLARED_HOST_VERSION}" <<<"${version_output}" || {
  printf 'cloudflared binary does not report version %s.\n' "${CLOUDFLARED_HOST_VERSION}" >&2
  exit 1
}

if [[ "${mode}" == "--check" ]]; then
  printf 'Pinned cloudflared host binary is staged and verified. No change made.\n'
  exit 0
fi
[[ "${mode}" == "--apply" ]] || { printf 'Usage: %s [--check|--apply]\n' "$0" >&2; exit 2; }
[[ "${EUID}" -eq 0 ]] || { printf 'Apply mode requires root.\n' >&2; exit 2; }
[[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == "yes" ]] || { printf 'Recovery acknowledgement missing.\n' >&2; exit 2; }
[[ "${CONFIRM_CLOUDFLARED_INSTALL:-}" == "install-reviewed-cloudflared-${CLOUDFLARED_HOST_VERSION}" ]] || {
  printf 'Exact cloudflared install acknowledgement missing.\n' >&2
  exit 2
}

backup_root="/var/backups/website-infrastructure/$(date -u +%Y%m%dT%H%M%SZ)-cloudflared"
install -d -m 0700 "${backup_root}"
if [[ -e /usr/local/bin/cloudflared ]]; then
  cp -a /usr/local/bin/cloudflared "${backup_root}/cloudflared"
fi
install -m 0755 "${staged_binary}" /usr/local/bin/cloudflared
if ! /usr/local/bin/cloudflared --version | grep -Fq "cloudflared version ${CLOUDFLARED_HOST_VERSION}"; then
  if [[ -f "${backup_root}/cloudflared" ]]; then
    install -m 0755 "${backup_root}/cloudflared" /usr/local/bin/cloudflared
  else
    rm -f /usr/local/bin/cloudflared
  fi
  printf 'installed binary verification failed; restored the previous binary.\n' >&2
  exit 1
fi
printf 'Installed the verified cloudflared host binary only. No unit, user, token, or firewall changed.\n'
printf 'Recovery backup: %s\n' "${backup_root}"
