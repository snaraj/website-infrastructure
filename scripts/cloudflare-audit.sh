#!/bin/bash
builtin set -Eeuo pipefail
builtin set +x
builtin set +o history

# Release safety stop. This authenticated reader receives a broad account token
# and cannot establish stage-zero trust from mutable checkout bytes. Keep the
# aggregate-only audit implementation reviewable, but do not read a bearer or
# contact Cloudflare until the separately installed reviewed-blob launcher
# exists.
readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE}" != yes ]]; then
  builtin printf 'BLOCKED authenticated Cloudflare audit requires the trusted reviewed-blob launcher; no API token was read and no network request was attempted.\n' >&2
  builtin exit 1
fi

# This script reads Cloudflare's live control plane without changing it. Its
# output is deliberately aggregate-only so audit evidence can be shared without
# also turning logs into an inventory of account, zone, route, or token IDs.
required=(awk curl jq sha256sum)
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

# Reject control characters and curl-config injection before the token is ever
# interpolated into config stdin. Support the documented legacy opaque token
# and the repository's current Cloudflare prefixed-token family only.
if ! [[ "${CLOUDFLARE_API_TOKEN}" =~ ^[A-Za-z0-9_-]{40}$ ||
        "${CLOUDFLARE_API_TOKEN}" =~ ^(cfk_|cfut_|cfat_)[A-Za-z0-9]{40}[0-9A-Fa-f]{8}$ ]]; then
  printf 'CLOUDFLARE_API_TOKEN has an unsupported or unsafe format\n' >&2
  exit 2
fi
# Keep the bearer value in this shell only. It reaches curl through config
# stdin, not through argv or the inherited environment of every subprocess.
export -n CLOUDFLARE_API_TOKEN

audit_phase="${CLOUDFLARE_AUDIT_PHASE:-preflight}"
case "${audit_phase}" in
  preflight|public-edge-preflight|admin-tunnel|admin-policies|admin-route|admin-api|public-edge|public-dns-naranjo|public-dns-lidersea|all) ;;
  *)
    printf 'CLOUDFLARE_AUDIT_PHASE must be preflight, public-edge-preflight, one of the seven apply phases, or all\n' >&2
    exit 2
    ;;
esac
audit_token_owner="${CLOUDFLARE_AUDIT_TOKEN_OWNER:-user}"
case "${audit_token_owner}" in
  user) token_verify_path='/user/tokens/verify' ;;
  account) token_verify_path="/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/verify" ;;
  *) printf 'CLOUDFLARE_AUDIT_TOKEN_OWNER must be user or account\n' >&2; exit 2 ;;
esac

# A syntactically valid target is necessary before it can participate in the
# non-secret binding fingerprint shared with cloudflare-plan-gate.sh.
for variable_name in \
  CLOUDFLARE_ACCOUNT_ID \
  CLOUDFLARE_NARANJO_ONLINE_ZONE_ID \
  CLOUDFLARE_LIDERSEA_COM_ZONE_ID; do
  if [[ ! "${!variable_name}" =~ ^[0-9a-f]{32}$ || ! "${!variable_name}" =~ [1-9a-f] ]]; then
    printf '%s must be a nonzero 32-character lowercase hexadecimal ID\n' "${variable_name}" >&2
    exit 2
  fi
done

if [[ "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}" == "${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}" ||
      "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}" == "${CLOUDFLARE_ACCOUNT_ID}" ||
      "${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}" == "${CLOUDFLARE_ACCOUNT_ID}" ]]; then
  printf 'Account and public-zone targets must be three distinct identifiers\n' >&2
  exit 2
fi

admin_device_contract_requested=false
admin_policy_contract_requested=false
case "${audit_phase}" in
  admin-tunnel|admin-policies|admin-route|admin-api|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) admin_device_contract_requested=true ;;
esac
case "${audit_phase}" in
  admin-policies|admin-route|admin-api|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) admin_policy_contract_requested=true ;;
esac

if [[ "${admin_device_contract_requested}" == true ]]; then
  for variable_name in \
    CLOUDFLARE_PI_ADMIN_CIDR \
    CLOUDFLARE_ADMIN_EMAIL \
    CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID \
    CLOUDFLARE_ADMIN_POSTURE_CERTIFICATE_ID \
    CLOUDFLARE_ADMIN_POSTURE_PLATFORM \
    CLOUDFLARE_EXPECTED_ADMIN_POSTURE_CONTRACT_SHA256 \
    CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE \
    CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE \
    CLOUDFLARE_ADMIN_SESSION_FRESHNESS \
    CLOUDFLARE_WARP_DEVICE_POLICY_ID; do
    [[ -n "${!variable_name:-}" ]] || { printf '%s is required for the selected admin audit phase\n' "${variable_name}" >&2; exit 2; }
  done
  if ! jq -en --arg cidr "${CLOUDFLARE_PI_ADMIN_CIDR}" '
    try (
      ($cidr | split("/")) as $parts |
      ($parts | length) == 2 and $parts[1] == "32" and
      ($parts[0] | split(".") | map(tonumber)) as $octets |
      ($octets | length) == 4 and
      all($octets[]; . >= 0 and . <= 255) and
      (
        $octets[0] == 10 or
        ($octets[0] == 172 and $octets[1] >= 16 and $octets[1] <= 31) or
        ($octets[0] == 192 and $octets[1] == 168)
      )
    ) catch false
  ' >/dev/null; then
    printf 'CLOUDFLARE_PI_ADMIN_CIDR must be one private IPv4 /32\n' >&2
    exit 2
  fi
  [[ "${CLOUDFLARE_ADMIN_EMAIL}" =~ ^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$ ]] || {
    printf 'CLOUDFLARE_ADMIN_EMAIL must be one exact email identity\n' >&2
    exit 2
  }
  [[ "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
    printf 'CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID must be one lowercase rule UUID\n' >&2
    exit 2
  }
  [[ "${CLOUDFLARE_ADMIN_POSTURE_CERTIFICATE_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
    printf 'CLOUDFLARE_ADMIN_POSTURE_CERTIFICATE_ID must be one lowercase managed-certificate UUID\n' >&2
    exit 2
  }
  [[ "${CLOUDFLARE_ADMIN_POSTURE_PLATFORM}" =~ ^(windows|mac|linux)$ ]] || {
    printf 'CLOUDFLARE_ADMIN_POSTURE_PLATFORM must be windows, mac, or linux\n' >&2
    exit 2
  }
  [[ "${CLOUDFLARE_EXPECTED_ADMIN_POSTURE_CONTRACT_SHA256}" =~ ^[0-9a-f]{64}$ &&
      "${CLOUDFLARE_EXPECTED_ADMIN_POSTURE_CONTRACT_SHA256}" =~ [1-9a-f] ]] || {
    printf 'CLOUDFLARE_EXPECTED_ADMIN_POSTURE_CONTRACT_SHA256 must be an independently approved nonzero lowercase SHA-256\n' >&2
    exit 2
  }
  [[ "${CLOUDFLARE_WARP_DEVICE_POLICY_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
    printf 'CLOUDFLARE_WARP_DEVICE_POLICY_ID must be one lowercase profile UUID\n' >&2
    exit 2
  }
  [[ "${CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE}" =~ ^[0-9]+$ &&
      "${CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE}" =~ ^[0-9]+$ &&
      "${CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE}" -lt "${CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE}" ]] || {
    printf 'Admin SSH precedence must be numeric and lower than block precedence\n' >&2
    exit 2
  }
  [[ "${CLOUDFLARE_ADMIN_SESSION_FRESHNESS}" =~ ^[1-9][0-9]{0,2}s$ ]] || {
    printf 'CLOUDFLARE_ADMIN_SESSION_FRESHNESS must be 1-900 seconds\n' >&2
    exit 2
  }
  freshness_seconds="${CLOUDFLARE_ADMIN_SESSION_FRESHNESS%s}"
  (( freshness_seconds <= 900 )) || { printf 'Admin session freshness exceeds 900 seconds\n' >&2; exit 2; }
fi

if [[ "${audit_phase}" == admin-route || "${audit_phase}" == admin-api ||
      "${audit_phase}" == public-edge-preflight || "${audit_phase}" == public-edge ||
      "${audit_phase}" == public-dns-naranjo || "${audit_phase}" == public-dns-lidersea ||
      "${audit_phase}" == all ]]; then
  : "${CLOUDFLARE_PI_ADMIN_API_ALLOW_PRECEDENCE:?Required for API precedence binding in the selected audit phase}"
  [[ "${CLOUDFLARE_PI_ADMIN_API_ALLOW_PRECEDENCE}" =~ ^[0-9]+$ &&
      "${CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE}" -lt "${CLOUDFLARE_PI_ADMIN_API_ALLOW_PRECEDENCE}" &&
      "${CLOUDFLARE_PI_ADMIN_API_ALLOW_PRECEDENCE}" -lt "${CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE}" ]] || {
    printf 'Admin API precedence must be numeric, after SSH, and before block\n' >&2
    exit 2
  }
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

digest() {
  sha256sum | awk '{print $1}'
}

account_binding_fingerprint() {
  printf 'phase=account\naccount=%s\n' "$1" | digest
}

admin_contract_fingerprint() {
  local contract_phase="$1"
  local account_id="$2"
  local tunnel_id="$3"
  local network="$4"
  printf 'phase=%s\naccount=%s\ntunnel=%s\nnetwork=%s\n' \
    "${contract_phase}" "${account_id}" "${tunnel_id}" "${network}" | digest
}

admin_policy_fingerprint() {
  local contract_phase="$1"
  local account_id="$2"
  local tunnel_id="$3"
  local network="$4"
  local email="$5"
  local posture_id="$6"
  local posture_hash="$7"
  local session_freshness="$8"
  local ssh_precedence="$9"
  local block_precedence="${10}"
  printf 'phase=%s\naccount=%s\ntunnel=%s\nnetwork=%s\nidentity=%s\nposture_id=%s\nposture_sha256=%s\nsession=%s\nssh_precedence=%s\nblock_precedence=%s\n' \
    "${contract_phase}" "${account_id}" "${tunnel_id}" "${network}" "${email}" \
    "${posture_id}" "${posture_hash}" "${session_freshness}" "${ssh_precedence}" \
    "${block_precedence}" | digest
}

admin_api_inputs_fingerprint() {
  printf 'phase=admin-api-inputs\naccount=%s\ntunnel=%s\nnetwork=%s\nidentity=%s\nposture_id=%s\nposture_sha256=%s\nsession=%s\nssh_precedence=%s\napi_precedence=%s\nblock_precedence=%s\npolicies_sha256=%s\nroute_sha256=%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "${12}" | digest
}

admin_tunnel_fingerprint() {
  printf 'phase=admin-tunnel\naccount=%s\ntunnel=%s\n' "$1" "$2" | digest
}

public_edge_fingerprint() {
  printf 'phase=public-edge\naccount=%s\ntunnel=%s\n' "$1" "$2" | digest
}

public_dns_binding_fingerprint() {
  printf 'phase=%s\naccount=%s\ntunnel=%s\nzone=%s\nhostname=%s\n' "$1" "$2" "$3" "$4" "$5" | digest
}

target_binding_hash="$(binding_fingerprint \
  "${CLOUDFLARE_ACCOUNT_ID}" \
  "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}" \
  "${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}")"
readonly target_binding_hash="${target_binding_hash%% *}"
account_binding_hash="$(account_binding_fingerprint "${CLOUDFLARE_ACCOUNT_ID}")"
readonly account_binding_hash

readonly expected_zone_count=2
failures=0

api_get() {
  local api_path="$1"
  [[ "${api_path}" =~ ^/[A-Za-z0-9._~/?\&=%:+,-]+$ ]] || return 1
  # Feed the credential through curl config stdin so it does not appear in argv.
  printf 'silent\nshow-error\nfail\nrequest = "GET"\nproto = "=https"\ntlsv1.2\nconnect-timeout = 10\nmax-time = 30\nmax-filesize = 5242880\nheader = "Authorization: Bearer %s"\nheader = "Accept: application/json"\nurl = "https://api.cloudflare.com/client/v4%s"\n' \
    "${CLOUDFLARE_API_TOKEN}" "${api_path}" | curl --disable --config -
}

# These endpoints are explicitly SinglePage in Cloudflare's current SDK/API
# contract. Accept absent pagination metadata, but if the API supplies it,
# reject any count or page value that could indicate a truncated collection.
api_get_single_page() {
  local api_path="$1"
  local response
  response="$(api_get "${api_path}")" || return 1
  jq -e '
    .success == true and (.result | type == "array") and
    ((.result | length) as $length |
      (.result_info // null) as $info |
      ($info == null or (
        ($info | type) == "object" and
        (($info | has("count") | not) or (($info.count | type) == "number" and $info.count == $length)) and
        (($info | has("total_count") | not) or (($info.total_count | type) == "number" and $info.total_count == $length)) and
        (($info | has("page") | not) or (($info.page | type) == "number" and $info.page == 1)) and
        (($info | has("total_pages") | not) or (($info.total_pages | type) == "number" and $info.total_pages == 1))
      )))
  ' >/dev/null 2>&1 <<<"${response}" || return 1
  printf '%s\n' "${response}"
}

api_get_complete() {
  local api_path="$1"
  local separator='?'
  local first total_pages total_count page response combined next_result
  local verification_combined first_canonical verification_canonical
  [[ "${api_path}" != *'?'* ]] || separator='&'
  first="$(api_get "${api_path}${separator}per_page=100&page=1")" || return 1
  jq -e '
    .success == true and (.result | type == "array") and
    (.result_info | type == "object") and
    (.result_info.page | type == "number") and .result_info.page == 1 and
    (.result_info.per_page | type == "number") and .result_info.per_page > 0 and .result_info.per_page <= 100 and
    (.result_info.total_pages | type == "number") and .result_info.total_pages >= 1 and .result_info.total_pages <= 100 and
    (.result_info.total_count | type == "number") and .result_info.total_count >= 0 and
    (.result_info.count | type == "number") and .result_info.count == (.result | length)
  ' >/dev/null 2>&1 <<<"${first}" || return 1
  total_pages="$(jq -r '.result_info.total_pages' <<<"${first}")"
  total_count="$(jq -r '.result_info.total_count' <<<"${first}")"
  [[ "${total_pages}" =~ ^[0-9]+$ ]] && (( total_pages >= 1 && total_pages <= 100 )) || return 1
  combined="$(jq -c '.result' <<<"${first}")"
  for ((page = 2; page <= total_pages; page++)); do
    response="$(api_get "${api_path}${separator}per_page=100&page=${page}")" || return 1
    jq -e --argjson expected_page "${page}" --argjson expected_pages "${total_pages}" --argjson expected_total "${total_count}" '
      .success == true and (.result | type == "array") and
      (.result_info | type == "object") and
      .result_info.page == $expected_page and
      .result_info.total_pages == $expected_pages and
      .result_info.total_count == $expected_total and
      (.result_info.per_page | type == "number") and .result_info.per_page > 0 and .result_info.per_page <= 100 and
      (.result_info.count | type == "number") and .result_info.count == (.result | length)
    ' >/dev/null 2>&1 <<<"${response}" || return 1
    next_result="$(jq -c '.result' <<<"${response}")"
    combined="$(jq -cn --argjson left "${combined}" --argjson right "${next_result}" '$left + $right')"
  done
  [[ "$(jq -r 'length' <<<"${combined}")" -eq "${total_count}" ]] || return 1
  jq -e '
    all(.[]; (.id | type) == "string" and (.id | length) > 0) and
    ((map(.id) | unique | length) == length)
  ' >/dev/null 2>&1 <<<"${combined}" || return 1

  # Repeat every page and require the same canonical objects, not merely the
  # same count. This rejects page-shift races that can otherwise produce a
  # unique but incomplete inventory while resources are changing concurrently.
  verification_combined='[]'
  for ((page = 1; page <= total_pages; page++)); do
    response="$(api_get "${api_path}${separator}per_page=100&page=${page}")" || return 1
    jq -e --argjson expected_page "${page}" --argjson expected_pages "${total_pages}" --argjson expected_total "${total_count}" '
      .success == true and (.result | type == "array") and
      (.result_info | type == "object") and
      .result_info.page == $expected_page and
      .result_info.total_pages == $expected_pages and
      .result_info.total_count == $expected_total and
      (.result_info.per_page | type == "number") and .result_info.per_page > 0 and .result_info.per_page <= 100 and
      (.result_info.count | type == "number") and .result_info.count == (.result | length)
    ' >/dev/null 2>&1 <<<"${response}" || return 1
    next_result="$(jq -c '.result' <<<"${response}")"
    verification_combined="$(jq -cn --argjson left "${verification_combined}" --argjson right "${next_result}" '$left + $right')"
  done
  [[ "$(jq -r 'length' <<<"${verification_combined}")" -eq "${total_count}" ]] || return 1
  jq -e '
    all(.[]; (.id | type) == "string" and (.id | length) > 0) and
    ((map(.id) | unique | length) == length)
  ' >/dev/null 2>&1 <<<"${verification_combined}" || return 1
  first_canonical="$(jq -cS 'sort_by(.id)' <<<"${combined}")" || return 1
  verification_canonical="$(jq -cS 'sort_by(.id)' <<<"${verification_combined}")" || return 1
  [[ "${first_canonical}" == "${verification_canonical}" ]] || return 1
  jq -cn --argjson result "${combined}" --argjson total_count "${total_count}" \
    '{success: true, result: $result, result_info: {complete: true, total_count: $total_count}}'
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
printf 'audit_phase=%s\n' "${audit_phase}"
printf 'account_binding_sha256=%s\n' "${account_binding_hash}"
printf 'target_binding_sha256=%s\n' "${target_binding_hash}"
printf 'Account, zone, record, route, policy, member, and token identifiers are not printed.\n'

token_response="$(api_get "${token_verify_path}" 2>/dev/null || true)"
printf '\n## Token validity\n'
printf 'owner=%s\n' "${audit_token_owner}"
token_status="$(jq -r 'if .success then (.result.status // "unknown") else "unknown" end' <<<"${token_response:-{}}" 2>/dev/null || printf unknown)"
printf 'status=%s\n' "${token_status}"
if [[ "${token_status}" != "active" ]]; then
  mark_unavailable 'the read-only audit token is not proven active.'
fi

printf '\n## Account subscriptions\n'
subscriptions="$(api_get_single_page "/accounts/${CLOUDFLARE_ACCOUNT_ID}/subscriptions" 2>/dev/null || true)"
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${subscriptions:-{}}"; then
  mark_unavailable 'account subscriptions could not be completely audited.'
else
  jq -r '.result as $r | "count=" + (($r | length) | tostring), ($r[]? | {name: (.rate_plan.public_name // .rate_plan.name // "unknown"), currency: (.currency // "unknown"), price: (.price // null), frequency: (.frequency // "unknown")} | @json)' <<<"${subscriptions}"
  if ! jq -e '
    all(.result[]?;
      ((.rate_plan.public_name // .rate_plan.name // "") | test("free"; "i")) and
      (.price | type) == "number" and .price == 0 and
      (.state == "Provisioned" or .state == "Paid") and
      ((.trial // false) == false) and
      (((.rate_plan.id // "") | test("trial"; "i")) | not)
    )
  ' >/dev/null <<<"${subscriptions}"; then
    mark_unavailable 'a subscription is not explicitly Free, zero-priced, non-trial, and active; this is a zero-spend NO-GO.'
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

    dnssec="$(api_get "/zones/${zone_id}/dnssec" 2>/dev/null || true)"
    dnssec_status="$(jq -r 'if .success then (.result.status // "unknown") else "unknown" end' <<<"${dnssec:-{}}" 2>/dev/null || printf unknown)"
    printf 'zone[%s] dnssec_status=%s\n' "${zone_name}" "${dnssec_status}"
    if [[ "${dnssec_status}" == "unknown" ]]; then
      failures=$((failures + 1))
    fi
  done
fi

printf '\n## Cloudflare Tunnels\n'
tunnels="$(api_get_complete "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel?is_deleted=false" 2>/dev/null || true)"
pi_admin_tunnel_id=''
pi_websites_tunnel_id=''
pi_admin_tunnel_healthy=false
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${tunnels:-{}}"; then
  mark_unavailable 'Tunnel inventory could not be completely audited.'
else
  jq -r '"count=" + ((.result | length) | tostring), ([.result[]? | (.status // "unknown")] | group_by(.) | map({(.[0]): length}) | add // {} | @json)' <<<"${tunnels}"
  if ! jq -e '([.result | group_by(.name)[] | select(length > 1)] | length) == 0' >/dev/null <<<"${tunnels}"; then
    mark_unavailable 'duplicate active Tunnel names exist.'
  fi
  admin_tunnel_count="$(jq -r '[.result[] | select(.name == "pi-admin")] | length' <<<"${tunnels}")"
  public_tunnel_count="$(jq -r '[.result[] | select(.name == "pi-websites")] | length' <<<"${tunnels}")"
  tunnel_inventory_count="$(jq -r '.result | length' <<<"${tunnels}")"
  printf 'cloudflare_tunnel_inventory_count=%s\n' "${tunnel_inventory_count}"
  printf 'pi-admin exact_name_count=%s\n' "${admin_tunnel_count}"
  printf 'pi-websites exact_name_count=%s\n' "${public_tunnel_count}"
  [[ "${admin_tunnel_count}" -eq 0 ]] && printf 'pi_admin_tunnel_activation_state=absent\n' || printf 'pi_admin_tunnel_activation_state=present-or-conflict\n'
  [[ "${public_tunnel_count}" -eq 0 ]] && printf 'pi_websites_tunnel_activation_state=absent\n' || printf 'pi_websites_tunnel_activation_state=present-or-conflict\n'
  if [[ "${admin_tunnel_count}" -eq 1 ]]; then
    pi_admin_tunnel_id="$(jq -er '.result[] | select(.name == "pi-admin") | .id' <<<"${tunnels}")"
    if ! [[ "${pi_admin_tunnel_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
      mark_unavailable 'pi-admin Tunnel ID is missing or malformed.'
      pi_admin_tunnel_id=''
    elif [[ "$(jq -r '.result[] | select(.name == "pi-admin") | (.status // "unknown")' <<<"${tunnels}")" == healthy ]]; then
      pi_admin_tunnel_healthy=true
    fi
  fi
  if [[ "${public_tunnel_count}" -eq 1 ]]; then
    pi_websites_tunnel_id="$(jq -er '.result[] | select(.name == "pi-websites") | .id' <<<"${tunnels}")"
    if ! [[ "${pi_websites_tunnel_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
      mark_unavailable 'pi-websites Tunnel ID is missing or malformed.'
      pi_websites_tunnel_id=''
    fi
  fi
  if [[ -n "${pi_admin_tunnel_id}" && "${pi_admin_tunnel_id}" == "${pi_websites_tunnel_id}" ]]; then
    mark_unavailable 'admin and public Tunnel identities are not separate.'
  fi
  case "${audit_phase}" in
    admin-tunnel|admin-policies|admin-route|admin-api|public-edge-preflight)
      if [[ "${tunnel_inventory_count}" -ne 1 || "${admin_tunnel_count}" -ne 1 || "${public_tunnel_count}" -ne 0 ]]; then
        mark_unavailable 'admin staging requires the complete active Tunnel inventory to contain pi-admin only.'
      fi
      ;;
    public-edge|public-dns-naranjo|public-dns-lidersea|all)
      if [[ "${tunnel_inventory_count}" -ne 2 || "${admin_tunnel_count}" -ne 1 || "${public_tunnel_count}" -ne 1 ]]; then
        mark_unavailable 'public staging requires the complete active Tunnel inventory to contain only pi-admin and pi-websites.'
      fi
      ;;
  esac
fi

if [[ "${pi_admin_tunnel_healthy}" == true ]]; then
  admin_tunnel_hash="$(admin_tunnel_fingerprint "${CLOUDFLARE_ACCOUNT_ID}" "${pi_admin_tunnel_id}")"
  printf 'admin_tunnel_contract_sha256=%s\n' "${admin_tunnel_hash}"
elif [[ "${audit_phase}" == admin-tunnel || "${audit_phase}" == admin-policies ||
        "${audit_phase}" == admin-route || "${audit_phase}" == admin-api ||
        "${audit_phase}" == public-edge-preflight || "${audit_phase}" == public-edge ||
        "${audit_phase}" == public-dns-naranjo || "${audit_phase}" == public-dns-lidersea ||
        "${audit_phase}" == all ]]; then
  mark_unavailable 'the exact pi-admin Tunnel is not uniquely present and healthy.'
fi

printf '\n## Gateway policies\n'
gateway_rules="$(api_get_single_page "/accounts/${CLOUDFLARE_ACCOUNT_ID}/gateway/rules" 2>/dev/null || true)"
admin_policy_verified=false
admin_l4_inventory_closed=false
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${gateway_rules:-{}}"; then
  mark_unavailable 'Gateway policy inventory could not be completely audited.'
else
  jq -r '"count=" + ((.result | length) | tostring), ([.result[]? | {action: .action, enabled: .enabled}] | @json)' <<<"${gateway_rules}"
  gateway_l4_inventory_count="$(jq -r '[.result[] | select(((.filters // []) | index("l4")) != null)] | length' <<<"${gateway_rules}")"
  gateway_policy_inventory_count="$(jq -r '.result | length' <<<"${gateway_rules}")"
  printf 'gateway_l4_inventory_count=%s\n' "${gateway_l4_inventory_count}"
  printf 'gateway_policy_inventory_count=%s\n' "${gateway_policy_inventory_count}"
  if ! jq -e '
    ([.result | group_by(.name)[] | select(length > 1)] | length) == 0 and
    ([.result | group_by(.precedence)[] | select(length > 1)] | length) == 0
  ' >/dev/null <<<"${gateway_rules}"; then
    mark_unavailable 'duplicate Gateway policy name or precedence exists.'
  fi

  if [[ "${audit_phase}" == admin-tunnel && "${gateway_policy_inventory_count}" -ne 0 ]]; then
    mark_unavailable 'admin-tunnel post-audit requires no Gateway policy before the isolated admin-policies phase.'
  fi

  if [[ "${admin_policy_contract_requested}" == true && -n "${pi_admin_tunnel_id}" ]]; then
    api_named_count="$(jq -r '[.result[] | select(.name == "pi-admin-api-allow")] | length' <<<"${gateway_rules}")"
    if [[ "${audit_phase}" == admin-policies || "${audit_phase}" == admin-route ]]; then
      if [[ "${api_named_count}" -eq 0 ]]; then
        printf 'pi_admin_api_policy_activation_state=absent\n'
      else
        printf 'pi_admin_api_policy_activation_state=conflict\n'
      fi
    fi
    if [[ "${audit_phase}" == admin-api || "${audit_phase}" == all ]]; then
      expected_gateway_count=3
    elif [[ "${audit_phase}" == public-edge-preflight || "${audit_phase}" == public-edge ||
            "${audit_phase}" == public-dns-naranjo || "${audit_phase}" == public-dns-lidersea ]]; then
      if [[ "${api_named_count}" -eq 0 ]]; then
        expected_gateway_count=2
      elif [[ "${api_named_count}" -eq 1 ]]; then
        expected_gateway_count=3
      else
        expected_gateway_count=-1
      fi
    else
      expected_gateway_count=2
    fi
    unreviewed_gateway_count="$(jq -r '[.result[] | select(
      .name != "pi-admin-ssh-allow" and .name != "pi-admin-api-allow" and .name != "pi-admin-block"
    )] | length' <<<"${gateway_rules}")"
    reviewed_gateway_count="$(jq -r '[.result[] | select(
      .name == "pi-admin-ssh-allow" or .name == "pi-admin-api-allow" or .name == "pi-admin-block"
    )] | length' <<<"${gateway_rules}")"
    if [[ "${unreviewed_gateway_count}" -eq 0 && "${reviewed_gateway_count}" -eq "${expected_gateway_count}" &&
          "${gateway_policy_inventory_count}" -eq "${expected_gateway_count}" ]]; then
      admin_l4_inventory_closed=true
    fi
    printf 'Gateway complete inventory closed=%s unreviewed_count=%s\n' "${admin_l4_inventory_closed}" "${unreviewed_gateway_count}"

    ssh_match_count="$(jq -r '
      def compact_settings:
        walk(if type == "object" then with_entries(select(.value != null and .value != false and .value != "" and .value != [] and .value != {})) else . end);
      [.result[] | select(
      .name == "pi-admin-ssh-allow" and .action == "allow" and .enabled == true and
      .filters == ["l4"] and .precedence == (env.CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE | tonumber) and
      .traffic == ("net.dst.ip in {" + env.CLOUDFLARE_PI_ADMIN_CIDR + "} and net.protocol == \"tcp\" and net.dst.port in {22}") and
      .identity == ("identity.email == \"" + env.CLOUDFLARE_ADMIN_EMAIL + "\"") and
      .device_posture == ("any(device_posture.checks.passed[*] in {\"" + env.CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID + "\"})") and
      ((.expiration // "") == "") and ((.schedule // "") == "") and
      ((.rule_settings // {}) | compact_settings) == {check_session: {enforce: true, duration: env.CLOUDFLARE_ADMIN_SESSION_FRESHNESS}}
    )] | length' <<<"${gateway_rules}")"
    block_match_count="$(jq -r '
      def compact_settings:
        walk(if type == "object" then with_entries(select(.value != null and .value != false and .value != "" and .value != [] and .value != {})) else . end);
      [.result[] | select(
      .name == "pi-admin-block" and .action == "block" and .enabled == true and
      .filters == ["l4"] and .precedence == (env.CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE | tonumber) and
      .traffic == ("net.dst.ip in {" + env.CLOUDFLARE_PI_ADMIN_CIDR + "}") and
      ((.identity // "") == "") and ((.device_posture // "") == "") and
      ((.expiration // "") == "") and ((.schedule // "") == "") and
      ((.rule_settings // {}) | compact_settings) == {}
    )] | length' <<<"${gateway_rules}")"
    printf 'pi-admin SSH-only policy exact_match_count=%s\n' "${ssh_match_count}"
    printf 'pi-admin final-block policy exact_match_count=%s\n' "${block_match_count}"
    if [[ "${ssh_match_count}" -eq 1 && "${block_match_count}" -eq 1 && "${admin_l4_inventory_closed}" == true ]]; then
      admin_policy_verified=true
    fi
  fi

  if [[ "${audit_phase}" == admin-api || "${audit_phase}" == public-edge-preflight ||
        "${audit_phase}" == public-edge || "${audit_phase}" == public-dns-naranjo ||
        "${audit_phase}" == public-dns-lidersea || "${audit_phase}" == all ]]; then
    api_match_count="$(jq -r '
      def compact_settings:
        walk(if type == "object" then with_entries(select(.value != null and .value != false and .value != "" and .value != [] and .value != {})) else . end);
      [.result[] | select(
      .name == "pi-admin-api-allow" and .action == "allow" and .enabled == true and
      .filters == ["l4"] and .precedence == (env.CLOUDFLARE_PI_ADMIN_API_ALLOW_PRECEDENCE | tonumber) and
      .traffic == ("net.dst.ip in {" + env.CLOUDFLARE_PI_ADMIN_CIDR + "} and net.protocol == \"tcp\" and net.dst.port in {6443}") and
      .identity == ("identity.email == \"" + env.CLOUDFLARE_ADMIN_EMAIL + "\"") and
      .device_posture == ("any(device_posture.checks.passed[*] in {\"" + env.CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID + "\"})") and
      ((.expiration // "") == "") and ((.schedule // "") == "") and
      ((.rule_settings // {}) | compact_settings) == {check_session: {enforce: true, duration: env.CLOUDFLARE_ADMIN_SESSION_FRESHNESS}}
    )] | length' <<<"${gateway_rules}")"
    printf 'pi-admin API-6443 policy exact_match_count=%s\n' "${api_match_count}"
    if [[ "${audit_phase}" == admin-api || "${audit_phase}" == all || "${api_named_count}" -eq 1 ]]; then
      [[ "${api_match_count}" -eq 1 ]] || mark_unavailable 'the later API policy is not exactly TCP 6443 with the required identity, posture, session, and precedence.'
    else
      [[ "${api_match_count}" -eq 0 ]] || mark_unavailable 'the optional API policy is neither absent nor exact.'
    fi
    [[ "${api_named_count}" -eq 0 ]] && printf 'pi_admin_api_policy_activation_state=absent\n' || true
    [[ "${api_named_count}" -eq 1 && "${api_match_count}" -eq 1 ]] && printf 'pi_admin_api_policy_activation_state=exact\n' || true
    [[ "${api_named_count}" -gt 1 || ("${api_named_count}" -eq 1 && "${api_match_count}" -ne 1) ]] && printf 'pi_admin_api_policy_activation_state=conflict\n' || true
  fi
fi

admin_policies_verified=false
admin_device_verified=false

if [[ "${admin_device_contract_requested}" == true ]]; then
  printf '\n## WARP enrollment, device policy, and posture\n'
  posture_rules="$(api_get_single_page "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/posture" 2>/dev/null || true)"
  posture_match_count=0
  posture_contract_hash=''
  posture_contract_verified=false
  if jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${posture_rules:-{}}"; then
    posture_match_count="$(jq -r '[.result[] | . as $rule | select(
      .id == env.CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID and .enabled == true and
      $rule.type == "client_certificate_v2" and
      (.input | type) == "object" and
      (.input | keys | sort) == ["certificate_id", "check_private_key", "cn", "extended_key_usage", "operating_system"] and
      .input.certificate_id == env.CLOUDFLARE_ADMIN_POSTURE_CERTIFICATE_ID and
      .input.check_private_key == true and
      .input.operating_system == env.CLOUDFLARE_ADMIN_POSTURE_PLATFORM and
      .input.cn == "${serial_number}" and
      .input.extended_key_usage == ["clientAuth"] and
      .match == [{"platform": env.CLOUDFLARE_ADMIN_POSTURE_PLATFORM}] and
      .expiration == "5m" and .schedule == "5m"
    )] | length' <<<"${posture_rules}")"
    if [[ "${posture_match_count}" -eq 1 ]]; then
      posture_canonical="$(jq -cS '.result[] | . as $rule | select(.id == env.CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID) | {id, enabled, type, input, match, expiration, schedule}' <<<"${posture_rules}")"
      posture_contract_hash="$(printf 'phase=admin-posture\nrule=%s\n' "${posture_canonical}" | digest)"
      printf 'observed_admin_posture_contract_sha256=%s\n' "${posture_contract_hash}"
      if [[ "${posture_contract_hash}" == "${CLOUDFLARE_EXPECTED_ADMIN_POSTURE_CONTRACT_SHA256}" ]]; then
        posture_contract_verified=true
        printf 'admin_posture_contract_sha256=%s\n' "${posture_contract_hash}"
      fi
    fi
  fi
  printf 'required_posture certificate_v2_exact_match_count=%s approved_hash_match=%s\n' "${posture_match_count}" "${posture_contract_verified}"

  device_policies="$(api_get_single_page "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/policies" 2>/dev/null || true)"
  warp_policy_match_count=0
  if jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${device_policies:-{}}"; then
    warp_policy_match_count="$(jq -r '[.result[] | select(
      .policy_id == env.CLOUDFLARE_WARP_DEVICE_POLICY_ID and
      .enabled == true and .service_mode_v2.mode == "warp" and
      .switch_locked == true and .allowed_to_leave == false and .allow_mode_switch == false and
      ([.include[]? | .address?] | sort) == [env.CLOUDFLARE_PI_ADMIN_CIDR] and
      ([.include[]? | select(has("host"))] | length) == 0 and
      ([.exclude[]?] | length) == 0
    )] | length' <<<"${device_policies}")"
  fi
  printf 'required_WARP_profile exact_match_count=%s\n' "${warp_policy_match_count}"

  enrolled_devices="$(api_get "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/physical-devices?active_registrations=only&include=last_seen_registration.policy&per_page=100" 2>/dev/null || true)"
  enrolled_match_count=0
  device_inventory_complete=false
  if jq -e '
    .success == true and (.result | type == "array") and
    (.result_info | type == "object") and
    ((.result_info.cursor // "") == "") and
    ((.result_info | has("total_count") | not) or
      ((.result_info.total_count | type) == "number" and .result_info.total_count == (.result | length))) and
    (.result_info.count | type == "number") and
    .result_info.count == (.result | length) and
    (.result_info.per_page | type == "number") and
    .result_info.per_page >= (.result | length)
  ' >/dev/null 2>&1 <<<"${enrolled_devices:-{}}"; then
    device_inventory_complete=true
    enrolled_match_count="$(jq -r '[.result[] | select(
      .last_seen_user.email == env.CLOUDFLARE_ADMIN_EMAIL and
      (.active_registrations // 0) > 0 and
      .last_seen_registration.policy.id == env.CLOUDFLARE_WARP_DEVICE_POLICY_ID and
      .last_seen_registration.policy.deleted == false
    )] | length' <<<"${enrolled_devices}")"
  fi
  printf 'required_admin_WARP_enrollment active_match_count=%s inventory_complete=%s\n' "${enrolled_match_count}" "${device_inventory_complete}"

  if [[ "${posture_match_count}" -eq 1 && "${posture_contract_verified}" == true && "${warp_policy_match_count}" -eq 1 &&
        "${device_inventory_complete}" == true && "${enrolled_match_count}" -ge 1 ]]; then
    admin_device_verified=true
  else
    mark_unavailable 'admin device contract requires a strong bound posture rule, locked WARP include-/32 with no exclusions, and active enrolled admin device.'
  fi

  if [[ "${pi_admin_tunnel_healthy}" == true && "${admin_device_verified}" == true ]]; then
    admin_policy_inputs_hash="$(admin_policy_fingerprint admin-policy-inputs \
      "${CLOUDFLARE_ACCOUNT_ID}" "${pi_admin_tunnel_id}" "${CLOUDFLARE_PI_ADMIN_CIDR}" \
      "${CLOUDFLARE_ADMIN_EMAIL}" "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}" \
      "${posture_contract_hash}" "${CLOUDFLARE_ADMIN_SESSION_FRESHNESS}" \
      "${CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE}" "${CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE}")"
    printf 'admin_policy_inputs_contract_sha256=%s\n' "${admin_policy_inputs_hash}"
  fi

  if [[ "${admin_policy_contract_requested}" == true ]]; then
    if [[ "${pi_admin_tunnel_healthy}" == true && "${admin_policy_verified}" == true && "${admin_device_verified}" == true ]]; then
      admin_policies_verified=true
      admin_policies_hash="$(admin_policy_fingerprint admin-policies \
        "${CLOUDFLARE_ACCOUNT_ID}" "${pi_admin_tunnel_id}" "${CLOUDFLARE_PI_ADMIN_CIDR}" \
        "${CLOUDFLARE_ADMIN_EMAIL}" "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}" \
        "${posture_contract_hash}" "${CLOUDFLARE_ADMIN_SESSION_FRESHNESS}" \
        "${CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE}" "${CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE}")"
      printf 'admin_policies_contract_sha256=%s\n' "${admin_policies_hash}"
    else
      mark_unavailable 'admin-policies contract requires the healthy Tunnel, closed exact L4 policy inventory, and verified device contract.'
    fi
  fi
fi

printf '\n## Private routes\n'
routes="$(api_get_complete "/accounts/${CLOUDFLARE_ACCOUNT_ID}/teamnet/routes?is_deleted=false" 2>/dev/null || true)"
admin_route_verified=false
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${routes:-{}}"; then
  mark_unavailable 'private-route inventory could not be completely audited.'
else
  route_inventory_count="$(jq -r '.result | length' <<<"${routes}")"
  printf 'count=%s\n' "${route_inventory_count}"
  printf 'private_route_inventory_count=%s\n' "${route_inventory_count}"
  if ! jq -e '([.result | group_by(.network)[] | select(length > 1)] | length) == 0' >/dev/null <<<"${routes}"; then
    mark_unavailable 'duplicate or conflicting private route networks exist.'
  fi
  if [[ "${admin_policies_verified}" == true ]]; then
    route_match_count="$(CLOUDFLARE_AUDIT_PI_ADMIN_TUNNEL_ID="${pi_admin_tunnel_id}" jq -r '[.result[] | select(
      .network == env.CLOUDFLARE_PI_ADMIN_CIDR and
      .tunnel_id == env.CLOUDFLARE_AUDIT_PI_ADMIN_TUNNEL_ID and
      .comment == "Pi host only; verified block and SSH-only allow required"
    )] | length' <<<"${routes}")"
    printf 'pi-admin /32 route exact_match_count=%s\n' "${route_match_count}"
    if [[ "${route_match_count}" -eq 1 && "${route_inventory_count}" -eq 1 ]]; then
      admin_route_verified=true
      admin_route_hash="$(admin_contract_fingerprint admin-route "${CLOUDFLARE_ACCOUNT_ID}" "${pi_admin_tunnel_id}" "${CLOUDFLARE_PI_ADMIN_CIDR}")"
      printf 'admin_route_contract_sha256=%s\n' "${admin_route_hash}"
    fi
  fi
  case "${audit_phase}" in
    admin-tunnel|admin-policies)
      [[ "${route_inventory_count}" -eq 0 ]] || mark_unavailable 'private routes must remain absent before the isolated admin-route phase.'
      ;;
    admin-route|admin-api|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
      [[ "${route_inventory_count}" -eq 1 ]] || mark_unavailable 'the complete private-route inventory must contain the exact Pi /32 only.'
      ;;
  esac
fi

case "${audit_phase}" in
  admin-route|admin-api|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
    [[ "${admin_route_verified}" == true ]] || mark_unavailable 'admin-route contract is not exactly one /32 bound to the verified admin Tunnel.'
    ;;
esac

if [[ "${audit_phase}" == admin-route && "${admin_route_verified}" == true ]]; then
  admin_api_inputs_hash="$(admin_api_inputs_fingerprint \
    "${CLOUDFLARE_ACCOUNT_ID}" "${pi_admin_tunnel_id}" "${CLOUDFLARE_PI_ADMIN_CIDR}" \
    "${CLOUDFLARE_ADMIN_EMAIL}" "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}" \
    "${posture_contract_hash}" "${CLOUDFLARE_ADMIN_SESSION_FRESHNESS}" \
    "${CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE}" "${CLOUDFLARE_PI_ADMIN_API_ALLOW_PRECEDENCE}" \
    "${CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE}" "${admin_policies_hash}" "${admin_route_hash}")"
  printf 'admin_api_inputs_contract_sha256=%s\n' "${admin_api_inputs_hash}"
fi

printf '\n## Public edge contract\n'
public_edge_verified=false
if [[ -n "${pi_websites_tunnel_id}" ]]; then
  public_tunnel_status="$(jq -r '.result[] | select(.name == "pi-websites") | (.status // "unknown")' <<<"${tunnels}")"
  public_config="$(api_get "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${pi_websites_tunnel_id}/configurations" 2>/dev/null || true)"
  if [[ "${public_tunnel_status}" == healthy ]] && jq -e '
    .success == true and
    (.result.config | keys | sort) == ["ingress"] and
    .result.config.ingress == [
      {"hostname": "naranjo.online", "service": "http://naranjo-online.naranjo-online.svc.cluster.local:8080"},
      {"hostname": "lidersea.com", "service": "http://lidersea-com.lidersea-com.svc.cluster.local:8080"},
      {"service": "http_status:404"}
    ]
  ' >/dev/null 2>&1 <<<"${public_config:-{}}"; then
    public_edge_verified=true
    public_edge_hash="$(public_edge_fingerprint "${CLOUDFLARE_ACCOUNT_ID}" "${pi_websites_tunnel_id}")"
    printf 'pi-websites tunnel_status=healthy ingress=exact terminal_404=verified\n'
    printf 'public_edge_contract_sha256=%s\n' "${public_edge_hash}"
  else
    printf 'pi-websites tunnel/config=unverified\n'
  fi
else
  printf 'pi-websites tunnel/config=absent\n'
fi

case "${audit_phase}" in
  public-edge|public-dns-naranjo|public-dns-lidersea|all)
    [[ "${public_edge_verified}" == true ]] || mark_unavailable 'public-edge contract is not one healthy separate Tunnel with two exact origins and terminal 404.'
    ;;
esac

printf '\n## Public apex activation state\n'
zone_names=("lidersea.com" "naranjo.online")
zone_ids=("${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}" "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}")
for index in "${!zone_names[@]}"; do
  zone_name="${zone_names[$index]}"
  zone_id="${zone_ids[$index]}"
  apex_state=unavailable
  apex_records="$(api_get_complete "/zones/${zone_id}/dns_records?name=${zone_name}" 2>/dev/null || true)"
  if jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${apex_records:-{}}"; then
    address_record_count="$(jq -r --arg hostname "${zone_name}" '[.result[] | select(.name == $hostname and (.type == "A" or .type == "AAAA" or .type == "CNAME"))] | length' <<<"${apex_records}")"
    if [[ "${address_record_count}" -eq 0 ]]; then
      apex_state=absent
    elif [[ "${public_edge_verified}" == true ]] &&
      CLOUDFLARE_AUDIT_PUBLIC_TUNNEL_ID="${pi_websites_tunnel_id}" jq -e --arg hostname "${zone_name}" '
        [.result[] | select(.name == $hostname and (.type == "A" or .type == "AAAA" or .type == "CNAME"))] as $address_records |
        ($address_records | length) == 1 and
        $address_records[0].type == "CNAME" and
        $address_records[0].content == (env.CLOUDFLARE_AUDIT_PUBLIC_TUNNEL_ID + ".cfargotunnel.com") and
        $address_records[0].proxied == true and
        $address_records[0].ttl == 1
      ' >/dev/null 2>&1 <<<"${apex_records}"; then
      apex_state=exact
    else
      apex_state=conflict
    fi
  fi

  if [[ "${zone_name}" == naranjo.online ]]; then
    apex_label=public_dns_naranjo_activation_state
    binding_label=public_dns_naranjo_binding_sha256
    binding_phase=public-dns-naranjo
  else
    apex_label=public_dns_lidersea_activation_state
    binding_label=public_dns_lidersea_binding_sha256
    binding_phase=public-dns-lidersea
  fi
  printf '%s=%s\n' "${apex_label}" "${apex_state}"

  if [[ "${public_edge_verified}" == true && ("${apex_state}" == absent || "${apex_state}" == exact) ]]; then
    printf '%s=%s\n' "${binding_label}" "$(public_dns_binding_fingerprint "${binding_phase}" "${CLOUDFLARE_ACCOUNT_ID}" "${pi_websites_tunnel_id}" "${zone_id}" "${zone_name}")"
  fi

  expected_apex_state=''
  case "${audit_phase}:${zone_name}" in
    public-edge-preflight:*|public-edge:*) expected_apex_state=absent ;;
    public-dns-naranjo:naranjo.online) expected_apex_state=exact ;;
    public-dns-naranjo:lidersea.com) expected_apex_state=absent ;;
    public-dns-lidersea:*|all:*) expected_apex_state=exact ;;
  esac
  if [[ -n "${expected_apex_state}" && "${apex_state}" != "${expected_apex_state}" ]]; then
    mark_unavailable "the ${zone_name} apex state is not ${expected_apex_state} for ${audit_phase}."
  fi
done
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
printf 'audit_result=pass\n'
printf 'Machine-checkable audit evidence passed; manual dashboard review is still required.\n'
