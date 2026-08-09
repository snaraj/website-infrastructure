#!/usr/bin/env bash
# Produce stable hashes of the Pi route and firewall state so a reviewed host
# plan cannot be applied after silent network drift.
set -euo pipefail

[[ "$(uname -s)" == Linux ]] || { printf 'FAIL fingerprints require Linux\n' >&2; exit 2; }
for command_name in awk id ip iptables-save ip6tables-save mktemp nft sed sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'FAIL required command is absent: %s\n' "${command_name}" >&2
    exit 2
  }
done
if [[ "$(id -u)" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || { printf 'FAIL sudo is required for firewall evidence\n' >&2; exit 2; }
  sudo -n true >/dev/null 2>&1 || { printf 'FAIL non-interactive privileged firewall read is unavailable\n' >&2; exit 2; }
fi

# Raw firewall state is sensitive, so it lives only in a private temporary
# directory and is removed on every exit path.
temporary_directory="$(mktemp -d)"
chmod 0700 "${temporary_directory}"
# cleanup enumerates owned files instead of recursively deleting a broad path.
cleanup() {
  rm -f -- \
    "${temporary_directory}/rules.raw" "${temporary_directory}/routes.raw" \
    "${temporary_directory}/nft.raw" "${temporary_directory}/nft.normalized" \
    "${temporary_directory}/iptables4.raw" "${temporary_directory}/iptables4.normalized" \
    "${temporary_directory}/iptables6.raw" "${temporary_directory}/iptables6.normalized"
  rmdir -- "${temporary_directory}"
}
trap cleanup EXIT

# privileged reads kernel firewall state directly when already root and uses
# non-interactive sudo otherwise; it must never pause an automated review.
privileged() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

ip -4 rule show >"${temporary_directory}/rules.raw"
ip -4 route show table all >"${temporary_directory}/routes.raw"
privileged nft list ruleset >"${temporary_directory}/nft.raw"
privileged iptables-save >"${temporary_directory}/iptables4.raw"
privileged ip6tables-save >"${temporary_directory}/iptables6.raw"

# Packet and byte counters are evidence noise; rule structure remains intact.
sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets # bytes #/g' \
  "${temporary_directory}/nft.raw" >"${temporary_directory}/nft.normalized"
sed -E 's/\[[0-9]+:[0-9]+\]/[#:#]/g' \
  "${temporary_directory}/iptables4.raw" >"${temporary_directory}/iptables4.normalized"
sed -E 's/\[[0-9]+:[0-9]+\]/[#:#]/g' \
  "${temporary_directory}/iptables6.raw" >"${temporary_directory}/iptables6.normalized"

# hash_file emits the KEY=digest contract consumed by later decision files and
# rejects malformed hashing output rather than recording weak evidence.
hash_file() {
  local key="$1"
  local path="$2"
  local digest
  digest="$(sha256sum "${path}" | awk '{print $1}')"
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || { printf 'FAIL unable to hash %s\n' "${key}" >&2; exit 1; }
  printf '%s=%s\n' "${key}" "${digest}"
}

hash_file DISCOVERY_IP_RULES_SHA256 "${temporary_directory}/rules.raw"
hash_file DISCOVERY_IP_ROUTES_SHA256 "${temporary_directory}/routes.raw"
hash_file DISCOVERY_NFT_RULESET_SHA256 "${temporary_directory}/nft.normalized"
hash_file DISCOVERY_IPTABLES4_SHA256 "${temporary_directory}/iptables4.normalized"
hash_file DISCOVERY_IPTABLES6_SHA256 "${temporary_directory}/iptables6.normalized"
