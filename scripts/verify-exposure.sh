#!/usr/bin/env bash
# Live, external proof that exactly the two approved hostnames reach their own
# applications while an unconfigured hostname and the residential origin do not.
set -euo pipefail

readonly LIVE_ACK='I_ACKNOWLEDGE_THIS_WILL_PROBE_PUBLIC_DNS_CLOUDFLARE_AND_MY_HOME_IP'
readonly NARANJO_HOSTNAME='naranjo.online'
readonly LIDERSEA_HOSTNAME='lidersea.com'
PYTHON_BIN=''

die() {
  printf 'verify-exposure: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<EOF
Usage:
  scripts/verify-exposure.sh --check
  scripts/verify-exposure.sh --live ${LIVE_ACK}

Required shell-only inputs for --live:
  HOME_PUBLIC_IP             residential IPv4 or IPv6 address (never printed)
  UNEXPECTED_PUBLIC_HOSTNAME an unconfigured subdomain of naranjo.online or lidersea.com

Optional:
  HOME_PUBLIC_IPV6           second residential address to check (never printed)

The fixed approved identities are naranjo.online and lidersea.com. This command
does not accept alternate expected hostnames.
EOF
}

require_tools() {
  local tool
  for tool in curl dig nc; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required; this script never installs tools"
  done
  local candidate
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import ipaddress' >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
  [[ -n "$PYTHON_BIN" ]] || die 'Python 3 with ipaddress support is required'
}

validate_inputs() {
  : "${HOME_PUBLIC_IP:?Set HOME_PUBLIC_IP only in the invoking local shell}"
  : "${UNEXPECTED_PUBLIC_HOSTNAME:?Set UNEXPECTED_PUBLIC_HOSTNAME only in the invoking local shell}"
  [[ "$HOME_PUBLIC_IP" != *[[:space:]]* ]] || die 'HOME_PUBLIC_IP must be one address without whitespace'
  "$PYTHON_BIN" -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$HOME_PUBLIC_IP" >/dev/null 2>&1 || \
    die 'HOME_PUBLIC_IP must be one valid IPv4 or IPv6 address'
  if [[ -n "${HOME_PUBLIC_IPV6:-}" ]]; then
    [[ "$HOME_PUBLIC_IPV6" != *[[:space:]]* ]] || die 'HOME_PUBLIC_IPV6 must be one address without whitespace'
    "$PYTHON_BIN" -c 'import ipaddress,sys; value=ipaddress.ip_address(sys.argv[1]); assert value.version == 6' "$HOME_PUBLIC_IPV6" >/dev/null 2>&1 || \
      die 'HOME_PUBLIC_IPV6 must be one valid IPv6 address'
  fi
  [[ "$UNEXPECTED_PUBLIC_HOSTNAME" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?\.(naranjo\.online|lidersea\.com)$ ]] || \
    die 'UNEXPECTED_PUBLIC_HOSTNAME must be a single unconfigured subdomain of an approved zone'
  [[ "$UNEXPECTED_PUBLIC_HOSTNAME" != "$NARANJO_HOSTNAME" && "$UNEXPECTED_PUBLIC_HOSTNAME" != "$LIDERSEA_HOSTNAME" ]] || \
    die 'the unexpected hostname must differ from both approved hostnames'
}

resolved_contains_address() {
  local address="$1"
  "$PYTHON_BIN" -c '
import ipaddress
import sys
target = ipaddress.ip_address(sys.argv[1])
for raw in sys.stdin:
    try:
        if ipaddress.ip_address(raw.strip()) == target:
            raise SystemExit(0)
    except ValueError:
        pass
raise SystemExit(1)
' "$address"
}

assert_site_identity() {
  local hostname="$1"
  local other_hostname="$2"
  local body headers ready_body status

  status="$(curl --silent --show-error --max-time 15 --output /dev/null --write-out '%{http_code}' "https://${hostname}/")" || \
    die "${hostname} root request failed"
  [[ "$status" == '200' ]] || die "${hostname} returned HTTP ${status}, expected 200"
  body="$(curl --fail --silent --show-error --max-time 15 "https://${hostname}/")" || \
    die "${hostname} body request failed"
  grep -Fq 'data-static-fallback' <<<"$body" || die "${hostname} lacks the built application fallback"
  grep -Fq 'Hello World!' <<<"$body" || die "${hostname} lacks the expected application content"
  grep -Fq "<title>${hostname}</title>" <<<"$body" || die "${hostname} did not return its exact tenant identity"
  if grep -Fq "<title>${other_hostname}</title>" <<<"$body"; then
    die "${hostname} returned the other tenant's identity"
  fi

  ready_body="$(curl --fail --silent --show-error --max-time 15 "https://${hostname}/readyz")" || \
    die "${hostname} public readiness endpoint failed"
  [[ -n "$ready_body" ]] || die "${hostname} public readiness endpoint returned an empty body"

  headers="$(curl --fail --silent --show-error --head --max-time 15 "https://${hostname}/")" || \
    die "${hostname} header request failed"
  local header
  # Cloudflare documents cf-ray as present on every response served through its
  # network, so this distinguishes a tunnel/edge path from a different HTTPS
  # endpoint that merely returns the same application body.
  for header in cf-ray content-security-policy strict-transport-security x-content-type-options; do
    grep -Eqi "^${header}:" <<<"$headers" || die "${hostname} is missing response header ${header}"
  done
  printf 'PASS %s exact content identity, Cloudflare edge, readiness, and browser headers\n' "$hostname"
}

assert_dns_hides_origin() {
  local hostname="$1"
  local resolved
  resolved="$(dig +short A "$hostname"; dig +short AAAA "$hostname")"
  [[ -n "$resolved" ]] || die "${hostname} has no public A or AAAA answer"
  if resolved_contains_address "$HOME_PUBLIC_IP" <<<"$resolved"; then
    die "${hostname} DNS reveals HOME_PUBLIC_IP"
  fi
  if [[ -n "${HOME_PUBLIC_IPV6:-}" ]] && resolved_contains_address "$HOME_PUBLIC_IPV6" <<<"$resolved"; then
    die "${hostname} DNS reveals HOME_PUBLIC_IPV6"
  fi
  printf 'PASS %s DNS resolves without disclosing supplied residential addresses\n' "$hostname"
}

assert_unexpected_hostname_denied() {
  local edge_hostname="$1"
  local body status
  # --connect-to reaches the already-approved Cloudflare edge while preserving
  # the unexpected Host and TLS identity. No DNS record for the negative name is
  # required, and the residential address is never used for this request.
  body="$(curl --silent --show-error --max-time 15 \
    --connect-to "${UNEXPECTED_PUBLIC_HOSTNAME}:443:${edge_hostname}:443" \
    --write-out $'\n%{http_code}' "https://${UNEXPECTED_PUBLIC_HOSTNAME}/")" || \
    die 'unexpected-hostname edge probe could not complete'
  status="${body##*$'\n'}"
  body="${body%$'\n'*}"
  [[ "$status" =~ ^4[0-9][0-9]$ ]] || die "unexpected hostname was not denied with a 4xx response (HTTP ${status})"
  if grep -Eq '<title>(naranjo\.online|lidersea\.com)</title>|data-static-fallback|Hello World!' <<<"$body"; then
    die 'unexpected hostname received approved tenant content'
  fi
  printf 'PASS unexpected hostname denied at the edge without tenant content (HTTP %s)\n' "$status"
}

assert_origin_ports_closed() {
  local address="$1"
  local label="$2"
  local port
  for port in 22 80 443 6443; do
    if nc -z -w 3 "$address" "$port" >/dev/null 2>&1; then
      die "${label} accepts residential TCP ${port}"
    fi
    printf 'PASS %s TCP %s closed/unreachable\n' "$label" "$port"
  done
}

run_live_probes() {
  assert_site_identity "$NARANJO_HOSTNAME" "$LIDERSEA_HOSTNAME"
  assert_site_identity "$LIDERSEA_HOSTNAME" "$NARANJO_HOSTNAME"
  assert_dns_hides_origin "$NARANJO_HOSTNAME"
  assert_dns_hides_origin "$LIDERSEA_HOSTNAME"
  assert_unexpected_hostname_denied "$NARANJO_HOSTNAME"
  assert_origin_ports_closed "$HOME_PUBLIC_IP" HOME_PUBLIC_IP
  if [[ -n "${HOME_PUBLIC_IPV6:-}" ]]; then
    assert_origin_ports_closed "$HOME_PUBLIC_IPV6" HOME_PUBLIC_IPV6
  fi
  printf 'PASS live exposure gate: two exact tenants, unexpected-host denial, origin hiding, and tested TCP closure\n'
  printf 'NOTE this remains one point-in-time external observation; release-gate.sh also requires live cluster readiness/admission evidence\n'
}

case "${1:---check}" in
  --check)
    (($# == 1)) || { usage >&2; exit 2; }
    require_tools
    printf 'verify-exposure: tools present; no DNS, network, or residential address was accessed\n'
    ;;
  --live)
    (($# == 2)) || { usage >&2; exit 2; }
    [[ "$2" == "$LIVE_ACK" ]] || die "exact acknowledgement is required: ${LIVE_ACK}"
    require_tools
    validate_inputs
    run_live_probes
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
