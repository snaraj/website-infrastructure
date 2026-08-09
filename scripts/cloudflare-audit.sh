#!/usr/bin/env bash
set -euo pipefail

# This script reads Cloudflare's live control plane without changing it. Its
# output is deliberately aggregate-only so audit evidence can be shared without
# also turning logs into an inventory of account, zone, route, or token IDs.
required=(curl jq sha256sum)
for command_name in "${required[@]}"; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf '%s is required\n' "${command_name}" >&2
    exit 2
  }
done
: "${CLOUDFLARE_API_TOKEN:?Set a read-only audit token in the environment}"
: "${CLOUDFLARE_ACCOUNT_ID:?Set the account ID in the environment}"
: "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID:?Set the naranjo.online zone ID in the environment}"
: "${CLOUDFLARE_LIDERSEA_COM_ZONE_ID:?Set the lidersea.com zone ID in the environment}"

# A syntactically valid target is necessary before it can participate in the
# non-secret binding fingerprint shared with cloudflare-plan-gate.sh.
for variable_name in \
  CLOUDFLARE_ACCOUNT_ID \
  CLOUDFLARE_NARANJO_ONLINE_ZONE_ID \
  CLOUDFLARE_LIDERSEA_COM_ZONE_ID; do
  if [[ ! "${!variable_name}" =~ ^[0-9a-f]{32}$ ]]; then
    printf '%s must be a 32-character lowercase hexadecimal ID\n' "${variable_name}" >&2
    exit 2
  fi
done

if [[ "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}" == "${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}" ||
      "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}" == "${CLOUDFLARE_ACCOUNT_ID}" ||
      "${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}" == "${CLOUDFLARE_ACCOUNT_ID}" ]]; then
  printf 'Account and public-zone targets must be three distinct identifiers\n' >&2
  exit 2
fi

# Keep this labelled byte sequence identical to cloudflare-plan-gate.sh. The
# domain labels are lexicographically sorted so swapping two valid IDs changes
# the digest and cannot be hidden by an unlabelled set.
binding_fingerprint() {
  local account_id="$1"
  local naranjo_online_zone_id="$2"
  local lidersea_com_zone_id="$3"
  printf 'account=%s\npublic_domain[lidersea.com]=%s\npublic_domain[naranjo.online]=%s\n' \
    "${account_id}" "${lidersea_com_zone_id}" "${naranjo_online_zone_id}" | sha256sum
}

target_binding_hash="$(binding_fingerprint \
  "${CLOUDFLARE_ACCOUNT_ID}" \
  "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}" \
  "${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}")"
readonly target_binding_hash="${target_binding_hash%% *}"

readonly expected_zone_count=2
failures=0

api_get() {
  local api_path="$1"
  # Feed the credential through curl config stdin so it does not appear in argv.
  printf 'silent\nshow-error\nfail\nheader = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\nurl = "https://api.cloudflare.com/client/v4%s"\n' \
    "${CLOUDFLARE_API_TOKEN}" "${api_path}" | curl --config -
}

api_get_complete() {
  local api_path="$1"
  local separator='?'
  local first total_pages page response combined next_result
  [[ "${api_path}" != *'?'* ]] || separator='&'
  first="$(api_get "${api_path}${separator}per_page=100&page=1")" || return 1
  jq -e '.success == true' >/dev/null 2>&1 <<<"${first}" || return 1
  total_pages="$(jq -r '.result_info.total_pages // 1' <<<"${first}")"
  [[ "${total_pages}" =~ ^[0-9]+$ ]] && (( total_pages >= 1 && total_pages <= 100 )) || return 1
  # A partial first page is never acceptable audit evidence. Reassemble every
  # advertised page before any caller counts products, users, routes, or zones.
  if (( total_pages == 1 )); then
    printf '%s\n' "${first}"
    return 0
  fi
  jq -e '.result | type == "array"' >/dev/null 2>&1 <<<"${first}" || return 1
  combined="$(jq -c '.result' <<<"${first}")"
  for ((page = 2; page <= total_pages; page++)); do
    response="$(api_get "${api_path}${separator}per_page=100&page=${page}")" || return 1
    jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${response}" || return 1
    next_result="$(jq -c '.result' <<<"${response}")"
    combined="$(jq -cn --argjson left "${combined}" --argjson right "${next_result}" '$left + $right')"
  done
  jq -cn --argjson result "${combined}" '{success: true, result: $result, result_info: {complete: true}}'
}

mark_unavailable() {
  printf 'UNAVAILABLE: %s\n' "$1"
  failures=$((failures + 1))
}

safe_query() {
  local label="$1"
  local path="$2"
  local filter="$3"
  local response output
  printf '\n## %s\n' "${label}"
  if ! response="$(api_get_complete "${path}" 2>/dev/null)"; then
    mark_unavailable 'API request, entitlement, schema, or complete pagination could not be proven.'
    return 0
  fi
  if ! output="$(jq -er "${filter}" <<<"${response}" 2>/dev/null)"; then
    mark_unavailable 'response schema changed.'
    return 0
  fi
  printf '%s\n' "${output}"
}

printf '# Cloudflare read-only zero-spend audit\n'
printf 'generated_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'contract=two Free zones for ordinary sites; large-media delivery is NO-GO; Registrar renewals only\n'
printf 'target_binding_sha256=%s\n' "${target_binding_hash}"
printf 'Account, zone, record, route, policy, member, and token identifiers are not printed.\n'

token_response="$(api_get_complete '/user/tokens/verify' 2>/dev/null || true)"
printf '\n## Token validity\n'
token_status="$(jq -r 'if .success then (.result.status // "unknown") else "unknown" end' <<<"${token_response:-{}}" 2>/dev/null || printf unknown)"
printf 'status=%s\n' "${token_status}"
if [[ "${token_status}" != "active" ]]; then
  mark_unavailable 'the read-only audit token is not proven active.'
fi

printf '\n## Account subscriptions\n'
subscriptions="$(api_get_complete "/accounts/${CLOUDFLARE_ACCOUNT_ID}/subscriptions" 2>/dev/null || true)"
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${subscriptions:-{}}"; then
  mark_unavailable 'account subscriptions could not be completely audited.'
else
  jq -r '.result as $r | "count=" + (($r | length) | tostring), ($r[]? | {name: (.rate_plan.public_name // .rate_plan.name // "unknown"), currency: (.currency // "unknown"), price: (.price // null), frequency: (.frequency // "unknown")} | @json)' <<<"${subscriptions}"
  if ! jq -e 'all(.result[]?; (((.rate_plan.public_name // .rate_plan.name // "") | length) > 0 and (.price | type) == "number" and .price == 0 and (.state == "Provisioned" or .state == "Paid")))' >/dev/null <<<"${subscriptions}"; then
    mark_unavailable 'a subscription has an unknown or nonzero price; this is a zero-spend NO-GO.'
  fi
fi

zones="$(api_get_complete "/zones?account.id=${CLOUDFLARE_ACCOUNT_ID}" 2>/dev/null || true)"
printf '\n## Zones and DNS\n'
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${zones:-{}}"; then
  mark_unavailable 'zones could not be completely audited.'
else
  zone_count="$(jq -r '.result | length' <<<"${zones}")"
  printf 'zone_count=%s expected=%s\n' "${zone_count}" "${expected_zone_count}"
  if [[ "${zone_count}" -ne "${expected_zone_count}" ]]; then
    mark_unavailable 'the account does not contain exactly the two expected zones.'
  fi

  # The filter on the API request is not trusted as proof by itself. Require
  # the complete response to contain only the two canonical names, and require
  # every returned zone to repeat the one intended account binding.
  if ! jq -e '
    (.result | map(.name) | sort) == ["lidersea.com", "naranjo.online"] and
    all(.result[]; .account.id == env.CLOUDFLARE_ACCOUNT_ID) and
    all(.result[]; .status == "active") and
    all(.result[]; ((.plan.name // "") | test("^Free(?: Website)?$"; "i")))
  ' >/dev/null <<<"${zones}"; then
    mark_unavailable 'the complete zone inventory is not exactly the two named active Free zones in this account.'
  fi

  zone_names=("lidersea.com" "naranjo.online")
  zone_ids=("${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}" "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}")
  for index in "${!zone_names[@]}"; do
    zone_name="${zone_names[$index]}"
    zone_id="${zone_ids[$index]}"
    zone_match_count="$(CLOUDFLARE_AUDIT_CURRENT_ZONE_ID="${zone_id}" jq -r \
      --arg zone_name "${zone_name}" \
      '[.result[] | select(.id == env.CLOUDFLARE_AUDIT_CURRENT_ZONE_ID and .name == $zone_name and .account.id == env.CLOUDFLARE_ACCOUNT_ID and .status == "active" and ((.plan.name // "") | test("^Free(?: Website)?$"; "i")))] | length' \
      <<<"${zones}")"
    if [[ "${zone_match_count}" -ne 1 ]]; then
      printf 'zone[%s] id_name_account_binding=unverified\n' "${zone_name}"
      failures=$((failures + 1))
    else
      printf 'zone[%s] id_name_account_binding=verified plan=Free status=active\n' "${zone_name}"
    fi

    # Each canonical ID is used only in request paths and the fingerprint. Raw
    # IDs and arbitrary API response bodies never enter the audit output.
    zone_subscription="$(api_get "/zones/${zone_id}/subscription" 2>/dev/null || true)"
    if ! jq -e '.success == true and .result.rate_plan.id == "free" and (.result.price | type) == "number" and .result.price == 0 and .result.rate_plan.is_contract == false and (.result.state == "Provisioned" or .result.state == "Paid")' >/dev/null 2>&1 <<<"${zone_subscription:-{}}"; then
      printf 'zone[%s] subscription=unavailable-or-not-exact-free\n' "${zone_name}"
      failures=$((failures + 1))
    else
      jq -r --arg zone_name "${zone_name}" '"zone[" + $zone_name + "] subscription_plan=" + .result.rate_plan.id + " price=" + (.result.price|tostring) + " state=" + .result.state' <<<"${zone_subscription}"
    fi

    records="$(api_get_complete "/zones/${zone_id}/dns_records" 2>/dev/null || true)"
    printf 'zone[%s] dns=' "${zone_name}"
    if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${records:-{}}"; then
      printf '{"unavailable":true}\n'
      failures=$((failures + 1))
    else
      jq -c '{count: (.result|length), by_type: ([.result[].type] | group_by(.) | map({(.[0]): length}) | add // {}), proxied: ([.result[] | select(.proxied == true)] | length)}' <<<"${records}"
    fi

    dnssec="$(api_get_complete "/zones/${zone_id}/dnssec" 2>/dev/null || true)"
    dnssec_status="$(jq -r 'if .success then (.result.status // "unknown") else "unknown" end' <<<"${dnssec:-{}}" 2>/dev/null || printf unknown)"
    printf 'zone[%s] dnssec_status=%s\n' "${zone_name}" "${dnssec_status}"
    if [[ "${dnssec_status}" == "unknown" ]]; then
      failures=$((failures + 1))
    fi
  done
fi

safe_query 'Cloudflare Tunnels' "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel?is_deleted=false" \
  '"count=" + ((.result | length) | tostring), ([.result[]? | (.status // "unknown")] | group_by(.) | map({(.[0]): length}) | add // {} | @json)'
safe_query 'Private routes' "/accounts/${CLOUDFLARE_ACCOUNT_ID}/teamnet/routes?is_deleted=false" \
  '"count=" + ((.result | length) | tostring)'
safe_query 'Gateway policies' "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/rules" \
  '"count=" + ((.result | length) | tostring), ([.result[]? | {action: .action, enabled: .enabled}] | @json)'
safe_query 'Access applications' "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps" \
  '"count=" + ((.result | length) | tostring)'
safe_query 'Zero Trust users and consumed seats' "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/users" \
  '"users=" + ((.result | length) | tostring) + " access_seats=" + ([.result[]? | select(.access_seat == true)] | length | tostring) + " gateway_seats=" + ([.result[]? | select(.gateway_seat == true)] | length | tostring)'

printf '\n## Manual dashboard checks (required)\n'
printf '%s\n' \
  "- Both domain zones show Free (\$0/month); neither is Pro." \
  '- Zero Trust is Free, seat/user count is within the current Free entitlement.' \
  '- No trial, paid add-on, usage-based product, paid certificate, or subscription is active.' \
  '- Video and deliberate large-file delivery remain disabled; Free Tunnel/CDN delivery is a NO-GO.' \
  '- The two Registrar renewals are identified separately from infrastructure.' \
  '- Account members/admins use passkeys/MFA; member and API-token inventories were reviewed.' \
  '- Audit/apply token permissions, account/zone scopes, IP conditions, and expirations exactly match the documented matrix.' \
  '- Budget alert is enabled only as secondary detection.'
printf '\nThis script issued GET requests only and printed no raw response. Unknown or\n'
printf 'unavailable evidence is a NO-GO, not a pass.\n'

if (( failures > 0 )); then
  printf '%d audit uncertainty/failure condition(s); zero-spend approval is blocked.\n' "${failures}" >&2
  exit 1
fi
printf 'Machine-checkable audit evidence passed; manual dashboard review is still required.\n'
