#!/usr/bin/env bash
# OWNER-RUN, read-only Cloudflare account/zone audit for the facts that the
# token-free edge probe cannot observe.
#
# WHY THIS EXISTS. scripts/edge-probe.sh proves behaviour from outside with no
# credential. Behaviour cannot say which setting produced it, and it cannot see
# anything with no externally observable effect: plan and subscription state,
# the Tunnel and connector inventory, the DNS record set, managed-HSTS
# ownership, or whether a Zero Trust private-network surface exists. This
# script reads exactly those facts through authenticated GET requests and
# nothing else.
#
# WHAT IT IS NOT. It is not the phased apply gate: scripts/cloudflare-audit.sh
# is the pre-apply/post-apply ceremony reader bound to the plan gate, and it
# stays authoritative for that flow. This is the steady-state acceptance audit
# for the two per-site Tunnel target state, and it never writes, plans, or
# applies anything.
#
# CREDENTIAL HANDLING. The token is read from CF_API_TOKEN in the environment
# only. It is never accepted as an argument, never echoed, never written to a
# file, never placed in a URL, and never passed through argv: it reaches curl
# through a configuration document on stdin, so it cannot appear in the process
# table. Shell tracing and history are disabled at the top of this file, and
# the variable is un-exported before any subprocess runs, so no child process
# inherits it.
#
# OUTPUT IS REDACTED BY DEFAULT. Account, zone, Tunnel and connector
# identifiers are replaced with stable short pseudonyms so two runs diff
# cleanly without publishing an inventory of identifiers. The mapping is a
# domain-separated SHA-256 prefix: the same input gives the same pseudonym
# across runs and hosts, which is what makes a diff meaningful, and the inputs
# are 128-bit random identifiers, so a pseudonym discloses nothing. --raw
# prints real identifiers for the owner's eyes only and says so loudly.
#
# FAIL CLOSED. Any transport failure, non-2xx status, unsuccessful API
# envelope, truncated collection, or unexpected schema is a finding that fails
# the run. An unknown answer is never a pass.
set -Eeuo pipefail
set +x
set +o history

# The API version is pinned here deliberately. Cloudflare versions its REST API
# in the path; a floating base would let a schema change silently alter what
# these assertions mean.
readonly API_BASE='https://api.cloudflare.com/client/v4'
readonly SCHEMA='cloudflare-account-audit/1'
readonly REDACTION_DOMAIN='website-infrastructure/cloudflare-account-audit/v1'

# The audited target state, per ADR 0015 (two per-site Tunnels) and the
# 2026-08-12 edge attestation. Zone names are the site identities; Tunnel names
# are the site identity tuples.
readonly ZONE_A='naranjo.online'
readonly ZONE_B='lidersea.com'
readonly TUNNEL_A='naranjo-online'
readonly TUNNEL_B='lidersea-com'
readonly ORIGIN_A='http://naranjo-online.naranjo-online.svc.cluster.local:8080'
readonly ORIGIN_B='http://lidersea-com.lidersea-com.svc.cluster.local:8080'
# naranjo.online is signed; lidersea.com stays unsigned until the owner's
# signing ceremony, so "disabled" is its expected DNSSEC state today. If the
# ceremony happens, this expectation moves in the same reviewed change.
readonly DNSSEC_A='active'
readonly DNSSEC_B='disabled'

# grep is resolved absolutely and every pattern is passed with -e: an
# interactive shell that shims grep to ugrep parses a dash-leading pattern as
# an option and silently returns nothing.
resolve_grep() {
  local candidate
  for candidate in /usr/bin/grep /bin/grep; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  command -v grep
}
GREP="$(resolve_grep)"
readonly GREP

RAW=no
FINDINGS=0
CHECKS=0
DIGEST_TOOL=''
WORKDIR=''
TOKEN_READ=no

usage() {
  cat <<'USAGE'
Usage:
  CF_API_TOKEN=... scripts/cloudflare-account-audit.sh [--raw]
  scripts/cloudflare-account-audit.sh --self-test
  scripts/cloudflare-account-audit.sh --help

Read-only Cloudflare account/zone audit. Owner-run only. Issues GET requests
exclusively; it never creates, updates, deletes, plans, or applies anything.

Input:
  CF_API_TOKEN   A short-lived READ-ONLY API token, supplied in the
                 environment only. Never pass a token as an argument.

Options:
  --raw        Print real identifiers instead of stable pseudonyms. For the
               owner's eyes only: the output then contains account, zone,
               Tunnel and connector identifiers and must never be committed,
               pasted into an issue, pull request, comment or ticket, or
               shared.
  --self-test  Offline invariant check: tooling, redaction determinism, and
               proof that every request this script can issue is a GET against
               the pinned API base. Needs no token and contacts no host.
  --help       This text.

What is audited (all read-only):
  * account subscriptions and per-zone plan/subscription: zero spend
  * zone settings: always_use_https, min_tls_version, tls_1_3, 0rtt, ssl, and
    that Cloudflare-managed HSTS stays off because the application owns it
  * DNSSEC status against the per-zone expectation
  * Tunnel inventory: exactly the two expected per-site Tunnels, one public
    hostname rule plus a terminal 404 each, and no idle connector
  * no Zero Trust private-network surface: no private routes, no WARP profile
  * DNS inventory: exactly one proxied apex CNAME per zone targeting its own
    Tunnel, no origin A/AAAA anywhere, and no unexpected record
  * the supplied token: active, expiring, and read-only as far as it can prove

Exit codes: 0 all checks passed, 1 one or more findings, 2 usage or tooling
error. A check that could not be completed counts as a finding.
USAGE
}

die() {
  printf 'cloudflare-account-audit: %s\n' "$*" >&2
  exit 2
}

cleanup() {
  if [[ -n "${WORKDIR}" && -d "${WORKDIR}" ]]; then
    rm -rf -- "${WORKDIR}"
  fi
}

finding() {
  printf 'FINDING %s\n' "$*"
  FINDINGS=$(( FINDINGS + 1 ))
}

ok() {
  printf 'OK %s\n' "$*"
}

check() {
  CHECKS=$(( CHECKS + 1 ))
}

resolve_tools() {
  command -v curl >/dev/null 2>&1 || die 'curl is required; this script never installs tools'
  command -v jq >/dev/null 2>&1 || die 'jq is required; this script never installs tools'
  if command -v sha256sum >/dev/null 2>&1; then
    DIGEST_TOOL='sha256sum'
  elif command -v shasum >/dev/null 2>&1; then
    DIGEST_TOOL='shasum -a 256'
  else
    die 'a SHA-256 tool (sha256sum or shasum) is required'
  fi
}

# Stable pseudonym for one identifier. Domain-separated so a value hashed here
# can never collide with the same value hashed for another purpose, and
# unsalted so two audits of the same account diff cleanly.
redact() {
  local value="$1" digest
  if [[ "${RAW}" == yes ]]; then
    printf '%s\n' "${value}"
    return 0
  fi
  if [[ -z "${value}" ]]; then
    printf 'none\n'
    return 0
  fi
  # Fail closed rather than emit an empty pseudonym: a run where every
  # identifier collapsed to the same token would look like a clean diff.
  [[ -n "${DIGEST_TOOL}" ]] || die 'the digest tool was never resolved; redaction cannot be trusted'
  # shellcheck disable=SC2086 # DIGEST_TOOL is a fixed one- or two-word command
  digest="$(printf '%s|%s' "${REDACTION_DOMAIN}" "${value}" | ${DIGEST_TOOL} | cut -c1-12)"
  printf 'id:%s\n' "${digest}"
}

# One GET, fail-closed. The method is fixed inside the configuration document;
# the path is validated against a conservative character set so no caller can
# smuggle a second URL, a header, or a curl option into it.
api_get() {
  local path="$1"
  [[ "${path}" =~ ^/[A-Za-z0-9._~/?\&=%:,+-]+$ ]] || return 1
  printf 'silent\nshow-error\nfail\nrequest = "GET"\nproto = "=https"\ntlsv1.2\nconnect-timeout = 10\nmax-time = 30\nmax-filesize = 5242880\nheader = "Authorization: Bearer %s"\nheader = "Accept: application/json"\nurl = "%s%s"\n' \
    "${CF_API_TOKEN}" "${API_BASE}" "${path}" | curl --disable --config -
}

# GET one endpoint and require a successful envelope. Prints the body on
# success; prints nothing and returns 1 on any transport, status, or envelope
# failure, so every caller has to decide explicitly what an absent answer
# means.
api_object() {
  local path="$1" response
  response="$(api_get "${path}" 2>/dev/null)" || return 1
  jq -e '.success == true and has("result")' >/dev/null 2>&1 <<<"${response}" || return 1
  printf '%s\n' "${response}"
}

# GET a collection and prove it was not truncated. Cloudflare returns
# result_info for paginated collections; more than one page means this script
# saw part of an inventory, and a partial inventory can never support an
# "exactly N and nothing else" assertion.
api_collection() {
  local path="$1" separator='?' response
  [[ "${path}" != *'?'* ]] || separator='&'
  response="$(api_get "${path}${separator}per_page=100&page=1" 2>/dev/null)" || return 1
  jq -e '
    .success == true and (.result | type == "array") and
    ((.result_info // null) as $info |
      ($info == null or (
        (($info | has("total_pages") | not) or $info.total_pages <= 1) and
        (($info | has("count") | not) or $info.count == (.result | length))
      )))
  ' >/dev/null 2>&1 <<<"${response}" || return 1
  printf '%s\n' "${response}"
}

require_token() {
  if [[ -z "${CF_API_TOKEN:-}" ]]; then
    die 'set a short-lived READ-ONLY token in CF_API_TOKEN; never pass a token as an argument'
  fi
  # Reject control characters and curl-config injection before the value is
  # interpolated into the configuration document.
  if ! [[ "${CF_API_TOKEN}" =~ ^[A-Za-z0-9_-]{40}$ ||
          "${CF_API_TOKEN}" =~ ^(cfk_|cfut_|cfat_)[A-Za-z0-9]{40}[0-9A-Fa-f]{8}$ ]]; then
    die 'CF_API_TOKEN has an unsupported or unsafe format'
  fi
  # Keep the bearer in this shell only: no child process inherits it.
  export -n CF_API_TOKEN
  TOKEN_READ=yes
}

audit_token() {
  local verify status token_id detail non_read expiry
  check
  verify="$(api_object '/user/tokens/verify' || true)"
  if [[ -z "${verify}" ]]; then
    finding 'token-verify the supplied token could not be verified; an audit never proceeds on an unproven credential'
    return 1
  fi
  status="$(jq -r '.result.status // "unknown"' <<<"${verify}")"
  if [[ "${status}" == active ]]; then
    ok "token-verify status=active id=$(redact "$(jq -r '.result.id // ""' <<<"${verify}")")"
  else
    finding "token-verify status=${status} expected=active"
  fi

  check
  token_id="$(jq -r '.result.id // ""' <<<"${verify}")"
  if [[ ! "${token_id}" =~ ^[0-9a-f]{32}$ ]]; then
    finding 'token-scope the verify response carried no usable token id, so the permissions were NOT machine-verified; review them in the dashboard'
    return 0
  fi
  detail="$(api_object "/user/tokens/${token_id}" || true)"
  if [[ -z "${detail}" ]]; then
    # A minimal read-only token normally cannot read the token API. That is the
    # healthy answer, and it is still reported as a limitation, not a pass.
    finding 'token-scope the token cannot read its own definition (expected for a minimal read-only token), so its permissions were NOT machine-verified; confirm read-only scope and the expiry in the dashboard'
    return 0
  fi
  non_read="$(jq -r '
    [ .result.policies[]? |
      (.effect // "allow") as $effect |
      .permission_groups[]? |
      select(($effect != "allow") or ((.name // "") | test("Read$") | not)) |
      (.name // "unnamed")
    ] | unique | join(",")
  ' <<<"${detail}")"
  if [[ -z "${non_read}" ]]; then
    ok 'token-scope every permission group is an allow of a Read permission'
  else
    finding "token-scope the token carries non-read permission groups: ${non_read}; an audit token must be read-only"
  fi

  check
  expiry="$(jq -r '.result.expires_on // ""' <<<"${detail}")"
  if [[ -n "${expiry}" ]]; then
    ok "token-expiry expires_on=${expiry}"
  else
    finding 'token-expiry the token has no expiry; the audit ceremony issues a just-in-time token of at most 60 minutes'
  fi
}

# Resolve one zone by name. Echoes "<zone_id> <account_id>" and prints nothing
# else, so it is safe to call from a command substitution.
zone_identity() {
  local name="$1" zones
  zones="$(api_collection "/zones?name=${name}" || true)"
  [[ -n "${zones}" ]] || return 1
  [[ "$(jq -r '.result | length' <<<"${zones}")" == 1 ]] || return 1
  jq -r '.result[0] | (.id // "") + " " + (.account.id // "")' <<<"${zones}"
}

audit_account_subscriptions() {
  local account_id="$1" response paid total
  check
  response="$(api_collection "/accounts/${account_id}/subscriptions" || true)"
  if [[ -z "${response}" ]]; then
    finding 'account-subscriptions the subscription inventory could not be read completely'
    return 0
  fi
  total="$(jq -r '.result | length' <<<"${response}")"
  paid="$(jq -r '
    [.result[]? | select(
      ((.price // 0) != 0) or
      (((.rate_plan.public_name // .rate_plan.name // "") | test("free"; "i")) | not) or
      ((.trial // false) == true)
    )] | length' <<<"${response}")"
  if [[ "${paid}" == 0 ]]; then
    ok "account-subscriptions all ${total} subscription(s) are named Free, zero-priced, and not trials"
  else
    finding "account-subscriptions ${paid} of ${total} subscription(s) are not zero-priced non-trial Free plans; this is a zero-spend finding"
  fi
}

audit_zone_plan() {
  local name="$1" zone_id="$2" zones subscription plan
  check
  zones="$(api_collection "/zones?name=${name}" || true)"
  if [[ -z "${zones}" ]]; then
    finding "zone-plan[${name}] the zone record could not be read"
    return 0
  fi
  plan="$(jq -r '.result[0].plan.name // "unknown"' <<<"${zones}")"
  if [[ "${plan}" =~ ^Free ]]; then
    ok "zone-plan[${name}] plan=${plan} status=$(jq -r '.result[0].status // "unknown"' <<<"${zones}")"
  else
    finding "zone-plan[${name}] plan=${plan} expected=Free; this is a zero-spend finding"
  fi

  check
  subscription="$(api_object "/zones/${zone_id}/subscription" || true)"
  if [[ -z "${subscription}" ]]; then
    finding "zone-subscription[${name}] the zone subscription could not be read"
    return 0
  fi
  if jq -e '
    (.result.rate_plan.id // "") == "free" and
    (.result.price | type) == "number" and .result.price == 0
  ' >/dev/null <<<"${subscription}"; then
    ok "zone-subscription[${name}] rate_plan=free price=0"
  else
    finding "zone-subscription[${name}] the subscription is not exactly the zero-priced Free rate plan"
  fi
}

audit_setting() {
  local name="$1" zone_id="$2" setting="$3" expected="$4" why="$5"
  local response value
  check
  response="$(api_object "/zones/${zone_id}/settings/${setting}" || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-setting[${name}/${setting}] could not be read; an unknown setting is not a pass"
    return 0
  fi
  value="$(jq -r '.result.value | if type == "object" then tojson else tostring end' <<<"${response}")"
  if [[ "${value}" == "${expected}" ]]; then
    ok "zone-setting[${name}/${setting}] value=${value}"
  else
    finding "zone-setting[${name}/${setting}] value=${value} expected=${expected}; ${why}"
  fi
}

audit_ssl_mode() {
  local name="$1" zone_id="$2" response value
  check
  response="$(api_object "/zones/${zone_id}/settings/ssl" || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-setting[${name}/ssl] could not be read; an unknown setting is not a pass"
    return 0
  fi
  value="$(jq -r '.result.value | tostring' <<<"${response}")"
  case "${value}" in
    full|strict)
      ok "zone-setting[${name}/ssl] value=${value}" ;;
    *)
      finding "zone-setting[${name}/ssl] value=${value} expected=full or strict; off and flexible put cleartext on the edge-to-origin leg" ;;
  esac
}

audit_managed_hsts() {
  local name="$1" zone_id="$2" response enabled
  check
  response="$(api_object "/zones/${zone_id}/settings/security_header" || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-setting[${name}/security_header] could not be read; an unknown setting is not a pass"
    return 0
  fi
  enabled="$(jq -r '.result.value.strict_transport_security.enabled // false | tostring' <<<"${response}")"
  if [[ "${enabled}" == false ]]; then
    ok "zone-setting[${name}/managed-hsts] enabled=false (the application owns Strict-Transport-Security)"
  else
    finding "zone-setting[${name}/managed-hsts] enabled=${enabled}; two writers would publish contradictory HSTS policies"
  fi
}

audit_zone_settings() {
  local name="$1" zone_id="$2"
  audit_setting "${name}" "${zone_id}" always_use_https on \
    'plaintext HTTP must be redirected to HTTPS at the edge'
  audit_setting "${name}" "${zone_id}" min_tls_version 1.2 \
    'TLS 1.0 and 1.1 must be refused'
  audit_setting "${name}" "${zone_id}" tls_1_3 on \
    'TLS 1.3 must remain enabled'
  audit_setting "${name}" "${zone_id}" 0rtt off \
    'early data is replayable and stays disabled'
  audit_ssl_mode "${name}" "${zone_id}"
  audit_managed_hsts "${name}" "${zone_id}"
}

audit_dnssec() {
  local name="$1" zone_id="$2" expected="$3" response status
  check
  response="$(api_object "/zones/${zone_id}/dnssec" || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-dnssec[${name}] status could not be read"
    return 0
  fi
  status="$(jq -r '.result.status // "unknown"' <<<"${response}")"
  if [[ "${status}" == "${expected}" ]]; then
    ok "zone-dnssec[${name}] status=${status}"
  else
    finding "zone-dnssec[${name}] status=${status} expected=${expected}; if the owner ran the signing ceremony, move the recorded expectation in the same reviewed change"
  fi
}

audit_tunnels() {
  local account_id="$1" response count names
  check
  response="$(api_collection "/accounts/${account_id}/cfd_tunnel?is_deleted=false" || true)"
  if [[ -z "${response}" ]]; then
    finding 'tunnel-inventory the Tunnel inventory could not be read completely'
    printf '%s\n' '{"result":[]}' >"${WORKDIR}/tunnels.json"
    return 1
  fi
  printf '%s\n' "${response}" >"${WORKDIR}/tunnels.json"
  count="$(jq -r '.result | length' <<<"${response}")"
  names="$(jq -r '[.result[].name] | sort | join(",")' <<<"${response}")"
  if [[ "${count}" == 2 && "${names}" == "${TUNNEL_B},${TUNNEL_A}" ]]; then
    ok "tunnel-inventory exactly the two expected per-site Tunnels exist (${names})"
  else
    finding "tunnel-inventory count=${count} names=${names} expected exactly ${TUNNEL_A} and ${TUNNEL_B}"
  fi
}

tunnel_id_for() {
  local tunnel_name="$1"
  jq -r --arg name "${tunnel_name}" \
    '[.result[]? | select(.name == $name)] | if length == 1 then (.[0].id // "") else "" end' \
    "${WORKDIR}/tunnels.json"
}

audit_tunnel_detail() {
  local account_id="$1" tunnel_name="$2" hostname="$3" origin="$4"
  local tunnel_id status config connections idle total pseudonyms connector
  check
  tunnel_id="$(tunnel_id_for "${tunnel_name}")"
  if [[ ! "${tunnel_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    finding "tunnel[${tunnel_name}] is not uniquely present with a well-formed identifier"
    return 0
  fi
  status="$(jq -r --arg name "${tunnel_name}" '.result[] | select(.name == $name) | .status // "unknown"' "${WORKDIR}/tunnels.json")"
  ok "tunnel[${tunnel_name}] id=$(redact "${tunnel_id}") status=${status}"

  check
  config="$(api_object "/accounts/${account_id}/cfd_tunnel/${tunnel_id}/configurations" || true)"
  if [[ -z "${config}" ]]; then
    finding "tunnel[${tunnel_name}] the ingress configuration could not be read"
  elif jq -e --arg hostname "${hostname}" --arg origin "${origin}" '
    (.result.config.ingress | type) == "array" and
    (.result.config.ingress | length) == 2 and
    .result.config.ingress[0].hostname == $hostname and
    .result.config.ingress[0].service == $origin and
    (.result.config.ingress[1] | has("hostname") | not) and
    .result.config.ingress[1].service == "http_status:404"
  ' >/dev/null <<<"${config}"; then
    ok "tunnel[${tunnel_name}] ingress is exactly one ${hostname} rule to its own origin plus the terminal 404"
  else
    finding "tunnel[${tunnel_name}] ingress is not exactly one ${hostname} rule to its own origin plus a terminal 404 rule"
  fi

  check
  connections="$(api_object "/accounts/${account_id}/cfd_tunnel/${tunnel_id}/connections" || true)"
  if [[ -z "${connections}" ]]; then
    finding "tunnel[${tunnel_name}] the connector inventory could not be read"
    return 0
  fi
  total="$(jq -r '.result | length' <<<"${connections}")"
  idle="$(jq -r '[.result[]? | select(((.conns // []) | length) == 0)] | length' <<<"${connections}")"
  pseudonyms=''
  while IFS= read -r connector; do
    [[ -n "${connector}" ]] || continue
    pseudonyms="${pseudonyms} $(redact "${connector}")"
  done <<<"$(jq -r '.result[]?.id // empty' <<<"${connections}")"
  printf 'RECORD tunnel[%s] connectors=%s idle=%s ids=%s\n' \
    "${tunnel_name}" "${total}" "${idle}" "${pseudonyms# }"
  if [[ "${idle}" == 0 ]]; then
    ok "tunnel[${tunnel_name}] every listed connector holds live connections"
  else
    finding "tunnel[${tunnel_name}] ${idle} connector(s) hold no live connection; check whether an old-token connector is lingering"
  fi
}

audit_no_private_network() {
  local account_id="$1" routes profiles count
  check
  routes="$(api_collection "/accounts/${account_id}/teamnet/routes?is_deleted=false" || true)"
  if [[ -z "${routes}" ]]; then
    finding 'private-routes the private-route inventory could not be read completely'
  else
    count="$(jq -r '.result | length' <<<"${routes}")"
    if [[ "${count}" == 0 ]]; then
      ok 'private-routes none exist; the two site Tunnels carry no private network surface'
    else
      finding "private-routes ${count} route(s) exist; ADR 0015 gives the site Tunnels no private or WARP routing"
    fi
  fi

  check
  profiles="$(api_collection "/accounts/${account_id}/devices/policies" || true)"
  if [[ -z "${profiles}" ]]; then
    # A token scoped to exactly the audited surface may legitimately lack Zero
    # Trust read permission. That is a limitation, not a pass.
    finding 'warp-profiles the device-profile inventory could not be read; confirm by hand that no WARP profile exists, or widen the audit token read scope'
  else
    count="$(jq -r '[.result[]? | select((.default // false) == false)] | length' <<<"${profiles}")"
    if [[ "${count}" == 0 ]]; then
      ok 'warp-profiles no non-default WARP device profile exists'
    else
      finding "warp-profiles ${count} non-default WARP device profile(s) exist"
    fi
  fi
}

audit_dns_records() {
  local name="$1" zone_id="$2" tunnel_id="$3"
  local response apex_count address_count unexpected
  check
  response="$(api_collection "/zones/${zone_id}/dns_records" || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-dns[${name}] the DNS inventory could not be read completely; a partial inventory cannot support an exactness claim"
    return 0
  fi
  address_count="$(jq -r '[.result[] | select(.type == "A" or .type == "AAAA")] | length' <<<"${response}")"
  if [[ "${address_count}" == 0 ]]; then
    ok "zone-dns[${name}] no origin A/AAAA record exists"
  else
    finding "zone-dns[${name}] ${address_count} address record(s) exist; an origin address record would publish the residential origin"
  fi

  check
  if [[ -z "${tunnel_id}" ]]; then
    finding "zone-dns[${name}] this site's Tunnel identifier is unknown, so the apex CNAME target could not be checked"
  else
    apex_count="$(jq -r --arg apex "${name}" --arg target "${tunnel_id}.cfargotunnel.com" '
      [.result[] | select(
        .name == $apex and .type == "CNAME" and .content == $target and
        .proxied == true and .ttl == 1
      )] | length' <<<"${response}")"
    if [[ "${apex_count}" == 1 ]]; then
      ok "zone-dns[${name}] exactly one proxied apex CNAME with automatic TTL targets this site's own Tunnel"
    else
      finding "zone-dns[${name}] exact_apex_cname_count=${apex_count} expected=1 (proxied, automatic TTL, this site's own Tunnel)"
    fi
  fi

  check
  unexpected="$(jq -r --arg apex "${name}" '
    [.result[] | select((.name == $apex and .type == "CNAME") | not) | .type] | sort | unique | join(",")
  ' <<<"${response}")"
  if [[ -z "${unexpected}" ]]; then
    ok "zone-dns[${name}] no record beyond the apex CNAME exists"
  else
    finding "zone-dns[${name}] record types beyond the apex CNAME are present: ${unexpected}; every additional name is public surface"
  fi
}

self_test() {
  local failures first second repeated call_sites
  local method_declarations egress_points method_literal egress_literal verb
  failures=0
  resolve_tools
  printf 'cloudflare-account-audit self-test (offline; no credential is read, no host is contacted)\n'
  printf 'schema=%s api_base=%s digest=%s grep=%s\n' \
    "${SCHEMA}" "${API_BASE}" "${DIGEST_TOOL}" "${GREP}"

  first="$(redact 'sample-identifier-one')"
  second="$(redact 'sample-identifier-one')"
  repeated="$(redact 'sample-identifier-two')"
  printf 'redaction-stable       -> %s == %s\n' "${first}" "${second}"
  [[ "${first}" == "${second}" && "${first}" == id:* ]] || failures=$(( failures + 1 ))
  printf 'redaction-distinct     -> %s != %s\n' "${first}" "${repeated}"
  [[ "${first}" != "${repeated}" ]] || failures=$(( failures + 1 ))
  printf 'redaction-hides-input  -> %s\n' "$([[ "${first}" == *sample-identifier* ]] && printf FAIL || printf ok)"
  [[ "${first}" != *sample-identifier* ]] || failures=$(( failures + 1 ))

  # Every request this script can issue goes through one helper, that helper
  # invokes curl exactly once, and it declares exactly one method. A write verb
  # anywhere in the file is a self-test failure, not a review comment.
  #
  # The two literals below are assembled from fragments on purpose: written out
  # whole they would appear in this file and each check would count itself.
  verb='GET'
  method_literal="request = \"${verb}\""
  egress_literal='curl --disable'' --config'
  call_sites="$("${GREP}" -c -E -e '\bapi_(get|object|collection)[[:space:]]' "$0" || true)"
  method_declarations="$("${GREP}" -c -F -e "${method_literal}" "$0" || true)"
  egress_points="$("${GREP}" -c -F -e "${egress_literal}" "$0" || true)"
  printf 'single-method-surface  -> api helper references=%s method declarations=%s curl invocations=%s\n' \
    "${call_sites}" "${method_declarations}" "${egress_points}"
  [[ "${method_declarations}" == 1 ]] || failures=$(( failures + 1 ))
  [[ "${egress_points}" == 1 ]] || failures=$(( failures + 1 ))
  if "${GREP}" -q -E -e '--request[[:space:]]+(POST|PUT|PATCH|DELETE)' -e '[[:space:]]-X[[:space:]]+(POST|PUT|PATCH|DELETE)' "$0"; then
    printf 'write-method-absent    -> FAIL\n'
    failures=$(( failures + 1 ))
  else
    printf 'write-method-absent    -> ok\n'
  fi
  printf 'credential-untouched   -> %s\n' "$([[ "${TOKEN_READ}" == no ]] && printf ok || printf FAIL)"
  [[ "${TOKEN_READ}" == no ]] || failures=$(( failures + 1 ))

  if (( failures > 0 )); then
    printf '\nRESULT schema=%s mode=self-test failures=%s exit=1\n' "${SCHEMA}" "${failures}"
    return 1
  fi
  printf '\nRESULT schema=%s mode=self-test failures=0 exit=0\n' "${SCHEMA}"
  return 0
}

run_audit() {
  local identity_a identity_b zone_a_id zone_b_id account_id account_b
  resolve_tools
  require_token
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/cloudflare-account-audit.XXXXXX")"
  trap cleanup EXIT

  printf '# Cloudflare read-only account audit\n'
  printf 'schema=%s\n' "${SCHEMA}"
  printf 'generated_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'api_base=%s\n' "${API_BASE}"
  printf 'mode=%s\n' "$([[ "${RAW}" == yes ]] && printf raw || printf redacted)"
  if [[ "${RAW}" == yes ]]; then
    printf '\n!! RAW MODE: the output below contains real Cloudflare identifiers.\n'
    printf '!! It is for the owner eyes only. Never commit it, never paste it into an\n'
    printf '!! issue, pull request, comment, chat, or ticket, and delete the capture\n'
    printf '!! as soon as the review is finished.\n'
  fi
  printf '\nEvery request below is a GET. Nothing is created, updated, or deleted.\n\n'

  printf '## token\n'
  if ! audit_token; then
    printf '\nRESULT schema=%s checks=%s findings=%s exit=1\n' "${SCHEMA}" "${CHECKS}" "${FINDINGS}"
    return 1
  fi

  printf '\n## zones\n'
  identity_a="$(zone_identity "${ZONE_A}" || true)"
  identity_b="$(zone_identity "${ZONE_B}" || true)"
  check
  if [[ -z "${identity_a}" || -z "${identity_b}" ]]; then
    finding 'zone-identity one or both zones did not resolve to exactly one zone; the remaining checks would be unsound'
    printf '\nRESULT schema=%s checks=%s findings=%s exit=1\n' "${SCHEMA}" "${CHECKS}" "${FINDINGS}"
    return 1
  fi
  zone_a_id="${identity_a%% *}"
  account_id="${identity_a##* }"
  zone_b_id="${identity_b%% *}"
  account_b="${identity_b##* }"
  if [[ "${account_id}" == "${account_b}" ]]; then
    ok "zone-identity account=$(redact "${account_id}") zones=$(redact "${zone_a_id}"),$(redact "${zone_b_id}")"
  else
    finding 'zone-identity the two zones live in different accounts; the account-level checks below cover only the first'
  fi

  printf '\n## zero spend\n'
  audit_account_subscriptions "${account_id}"
  audit_zone_plan "${ZONE_A}" "${zone_a_id}"
  audit_zone_plan "${ZONE_B}" "${zone_b_id}"

  printf '\n## zone settings\n'
  audit_zone_settings "${ZONE_A}" "${zone_a_id}"
  audit_zone_settings "${ZONE_B}" "${zone_b_id}"
  audit_dnssec "${ZONE_A}" "${zone_a_id}" "${DNSSEC_A}"
  audit_dnssec "${ZONE_B}" "${zone_b_id}" "${DNSSEC_B}"

  printf '\n## tunnels\n'
  audit_tunnels "${account_id}" || true
  audit_tunnel_detail "${account_id}" "${TUNNEL_A}" "${ZONE_A}" "${ORIGIN_A}"
  audit_tunnel_detail "${account_id}" "${TUNNEL_B}" "${ZONE_B}" "${ORIGIN_B}"
  audit_no_private_network "${account_id}"

  printf '\n## dns\n'
  audit_dns_records "${ZONE_A}" "${zone_a_id}" "$(tunnel_id_for "${TUNNEL_A}")"
  audit_dns_records "${ZONE_B}" "${zone_b_id}" "$(tunnel_id_for "${TUNNEL_B}")"

  printf '\n## still needs the owner eyes (not machine-checkable here)\n'
  printf '%s\n' \
    '- the billing page: no trial, add-on, usage-based product, or paid certificate' \
    '- the two Registrar renewals, identified separately from infrastructure' \
    '- account members and their passkey/MFA posture' \
    '- the API token inventory: nothing long-lived, nothing broader than its purpose'

  printf '\nRESULT schema=%s checks=%s findings=%s exit=%s\n' \
    "${SCHEMA}" "${CHECKS}" "${FINDINGS}" "$(( FINDINGS > 0 ? 1 : 0 ))"
  (( FINDINGS == 0 ))
}

main() {
  local mode status
  mode=audit
  status=0
  while (( $# > 0 )); do
    case "$1" in
      --raw) RAW=yes ;;
      --self-test) mode=self-test ;;
      -h|--help) usage; return 0 ;;
      *) usage >&2; die "unknown argument: $1" ;;
    esac
    shift
  done
  if [[ "${mode}" == self-test ]]; then
    self_test || status=$?
    return "${status}"
  fi
  run_audit || status=$?
  return "${status}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
