#!/bin/bash
builtin set -Eeuo pipefail
builtin set +x
builtin set +o history

# This authenticated reader is admitted only from the fixed root-owned
# workstation launcher. The launcher extracts exact reviewed protected-main
# blobs into a root-owned runtime directory and starts this file with a clean
# environment; a mutable-checkout invocation stops before reading the bearer.
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE:-}" != yes ||
      "${REVIEWED_BLOB_OPERATION:-}" != cloudflare-audit ||
      ! "${REVIEWED_BLOB_ROOT:-}" =~ ^/private/var/db/website-infrastructure/runtime/cloudflare-reviewed-op\.[A-Za-z0-9]+$ ]]; then
  builtin printf 'BLOCKED authenticated Cloudflare audit requires the trusted reviewed-blob launcher; no API token was read and no network request was attempted.\n' >&2
  builtin exit 1
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly repo_root
if [[ "${repo_root}" != "${REVIEWED_BLOB_ROOT}" ]]; then
  builtin printf 'BLOCKED reviewed Cloudflare audit extraction root mismatch; no API token was read and no network request was attempted.\n' >&2
  builtin exit 1
fi

# This script reads Cloudflare's live control plane without changing it. Its
# output is deliberately aggregate-only so audit evidence can be shared without
# also turning logs into an inventory of account, zone, route, or token IDs.
required=(awk curl jq)
for command_name in "${required[@]}"; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf '%s is required\n' "${command_name}" >&2
    exit 2
  }
done
if command -v sha256sum >/dev/null 2>&1; then
  readonly sha256_program=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  readonly sha256_program=shasum
else
  printf 'sha256sum or shasum is required\n' >&2
  exit 2
fi
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
  preflight|admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) ;;
  *)
    printf 'CLOUDFLARE_AUDIT_PHASE is not one of the closed reviewed audit phases\n' >&2
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

certificate_contract_requested=false
enrollment_policy_contract_requested=false
enrollment_contract_requested=false
admin_device_contract_requested=false
admin_policy_contract_requested=false
case "${audit_phase}" in
  admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) certificate_contract_requested=true ;;
esac
case "${audit_phase}" in
  admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) enrollment_policy_contract_requested=true ;;
esac
case "${audit_phase}" in
  admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) enrollment_contract_requested=true ;;
esac
case "${audit_phase}" in
  admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) admin_device_contract_requested=true ;;
esac
case "${audit_phase}" in
  admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) admin_policy_contract_requested=true ;;
esac

require_uuid_value() {
  local label="$1"
  local value="$2"
  [[ "${value}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || {
    printf '%s must be one real lowercase UUID\n' "${label}" >&2
    exit 2
  }
}

require_sha256_value() {
  local label="$1"
  local value="$2"
  [[ "${value}" =~ ^[0-9a-f]{64}$ && "${value}" =~ [1-9a-f] ]] || {
    printf '%s must be one nonzero lowercase SHA-256\n' "${label}" >&2
    exit 2
  }
}

if [[ "${certificate_contract_requested}" == true ]]; then
  : "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_ID:?Required for the selected certificate audit phase}"
  : "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_SHA256:?Required for the selected certificate audit phase}"
  require_uuid_value CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_ID "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_ID}"
  require_sha256_value CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_SHA256 "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_SHA256}"
fi

if [[ "${enrollment_policy_contract_requested}" == true ]]; then
  : "${CLOUDFLARE_OWNER_ENROLLMENT_POLICY_ID:?Required for the selected enrollment audit phase}"
  : "${CLOUDFLARE_ADMIN_IDENTITY_PROVIDER_ID:?Required for the selected enrollment audit phase}"
  : "${CLOUDFLARE_ADMIN_EMAIL:?Required for the selected enrollment audit phase}"
  require_uuid_value CLOUDFLARE_OWNER_ENROLLMENT_POLICY_ID "${CLOUDFLARE_OWNER_ENROLLMENT_POLICY_ID}"
  require_uuid_value CLOUDFLARE_ADMIN_IDENTITY_PROVIDER_ID "${CLOUDFLARE_ADMIN_IDENTITY_PROVIDER_ID}"
  [[ "${CLOUDFLARE_ADMIN_EMAIL}" =~ ^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$ ]] || {
    printf 'CLOUDFLARE_ADMIN_EMAIL must be one exact email identity\n' >&2
    exit 2
  }
fi

if [[ "${enrollment_contract_requested}" == true ]]; then
  : "${CLOUDFLARE_OWNER_ENROLLMENT_APPLICATION_ID:?Required for the selected enrollment audit phase}"
  require_uuid_value CLOUDFLARE_OWNER_ENROLLMENT_APPLICATION_ID "${CLOUDFLARE_OWNER_ENROLLMENT_APPLICATION_ID}"
fi

if [[ "${admin_device_contract_requested}" == true ]]; then
  for variable_name in \
    CLOUDFLARE_PI_ADMIN_CIDR \
    CLOUDFLARE_ADMIN_EMAIL \
    CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID \
    CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID \
    CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE \
    CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE \
    CLOUDFLARE_ADMIN_SESSION_FRESHNESS; do
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
  require_uuid_value CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}"
  require_uuid_value CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID "${CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID}"
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

# Keep this labelled byte sequence identical to cloudflare-plan-gate.sh. The
# domain labels are lexicographically sorted so swapping two valid IDs changes
# the digest and cannot be hidden by an unlabelled set.
binding_fingerprint() {
  local account_id="$1"
  local naranjo_online_zone_id="$2"
  local lidersea_com_zone_id="$3"
  printf 'account=%s\npublic_domain[lidersea.com]=%s\npublic_domain[naranjo.online]=%s\n' \
    "${account_id}" "${lidersea_com_zone_id}" "${naranjo_online_zone_id}" | digest
}

digest() {
  if [[ "${sha256_program}" == sha256sum ]]; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
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

admin_certificate_fingerprint() {
  printf 'phase=admin-certificate\naccount=%s\ncertificate_id=%s\ncertificate_sha256=%s\n' \
    "$1" "$2" "$3" | digest
}

admin_enrollment_policy_fingerprint() {
  printf 'phase=admin-enrollment-policy\naccount=%s\npolicy_id=%s\nidentity=%s\n' \
    "$1" "$2" "$3" | digest
}

admin_enrollment_fingerprint() {
  printf 'phase=admin-enrollment\naccount=%s\npolicy_id=%s\napplication_id=%s\nidentity_provider_id=%s\nidentity=%s\n' \
    "$1" "$2" "$3" "$4" "$5" | digest
}

admin_device_fingerprint() {
  printf 'phase=admin-device\naccount=%s\nnetwork=%s\nidentity=%s\nposture_id=%s\nprofile_id=%s\ncertificate_sha256=%s\nenrollment_sha256=%s\nplatform_routes_sha256=%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" | digest
}

admin_policy_fingerprint() {
  printf 'phase=%s\naccount=%s\ntunnel=%s\nnetwork=%s\nidentity=%s\nposture_id=%s\nprofile_id=%s\ndevice_sha256=%s\nenrollment_sha256=%s\nsession=%s\nssh_precedence=%s\nblock_precedence=%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "${12}" | digest
}

admin_tunnel_fingerprint() {
  printf 'phase=admin-tunnel\naccount=%s\ntunnel=%s\nenrollment_sha256=%s\ndevice_sha256=%s\n' \
    "$1" "$2" "$3" "$4" | digest
}

public_edge_fingerprint() {
  printf 'phase=public-edge\naccount=%s\npublic_domain[lidersea.com]=%s\npublic_domain[naranjo.online]=%s\n' \
    "$1" "$3" "$2" | digest
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

# The physical-device API is cursor-paginated rather than page-paginated. The
# reviewed admin contract permits exactly one active device, so a complete
# response must fit in one 100-item page, advertise no next cursor, and remain
# byte-for-byte identical (after canonical ID ordering) when fetched again.
# This rejects both truncation and an enrollment/revocation race at the audit
# boundary without ever printing device identifiers or attributes.
api_get_cursor_complete_one_page() {
  local api_path="$1"
  local first verification first_canonical verification_canonical
  first="$(api_get "${api_path}")" || return 1
  jq -e '
    .success == true and (.result | type == "array") and
    (.result_info | type == "object") and
    (.result_info.count | type) == "number" and
    .result_info.count == (.result | length) and
    (.result_info.total_count | type) == "number" and
    .result_info.total_count == (.result | length) and
    (.result_info.per_page | type) == "number" and
    .result_info.per_page >= (.result | length) and
    ((.result_info.cursor // "") == "") and
    all(.result[]; (.id | type) == "string" and (.id | length) > 0) and
    ((.result | map(.id) | unique | length) == (.result | length))
  ' >/dev/null 2>&1 <<<"${first}" || return 1
  verification="$(api_get "${api_path}")" || return 1
  jq -e '
    .success == true and (.result | type == "array") and
    (.result_info | type == "object") and
    (.result_info.count | type) == "number" and
    .result_info.count == (.result | length) and
    (.result_info.total_count | type) == "number" and
    .result_info.total_count == (.result | length) and
    (.result_info.per_page | type) == "number" and
    .result_info.per_page >= (.result | length) and
    ((.result_info.cursor // "") == "") and
    all(.result[]; (.id | type) == "string" and (.id | length) > 0) and
    ((.result | map(.id) | unique | length) == (.result | length))
  ' >/dev/null 2>&1 <<<"${verification}" || return 1
  first_canonical="$(jq -cS '{result: (.result | sort_by(.id)), result_info: {count: .result_info.count, total_count: .result_info.total_count}}' <<<"${first}")" || return 1
  verification_canonical="$(jq -cS '{result: (.result | sort_by(.id)), result_info: {count: .result_info.count, total_count: .result_info.total_count}}' <<<"${verification}")" || return 1
  [[ "${first_canonical}" == "${verification_canonical}" ]] || return 1
  printf '%s\n' "${first}"
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

printf '\n## Owner device certificate\n'
mtls_certificates="$(api_get_complete "/accounts/${CLOUDFLARE_ACCOUNT_ID}/mtls_certificates" 2>/dev/null || true)"
admin_certificate_verified=false
admin_certificate_contract_hash=''
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${mtls_certificates:-{}}"; then
  mark_unavailable 'mTLS certificate inventory could not be completely audited.'
else
  mtls_inventory_count="$(jq -r '.result | length' <<<"${mtls_certificates}")"
  admin_certificate_named_count="$(jq -r '[.result[] | select(.name == "pi-admin-owner-device-ca")] | length' <<<"${mtls_certificates}")"
  unrelated_mtls_hash="$(jq -cS '[.result[] | select(.name != "pi-admin-owner-device-ca")] | sort_by(.id)' <<<"${mtls_certificates}" | digest)"
  printf 'mtls_certificate_inventory_count=%s\n' "${mtls_inventory_count}"
  printf 'unrelated_mtls_inventory_sha256=%s\n' "${unrelated_mtls_hash}"
  if [[ "${admin_certificate_named_count}" -eq 0 ]]; then
    printf 'pi_admin_certificate_activation_state=absent\n'
  elif [[ "${admin_certificate_named_count}" -eq 1 && "${certificate_contract_requested}" == true ]]; then
    certificate_shape_match="$(jq -r --arg id "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_ID}" '[.result[] | select(
      .id == $id and .name == "pi-admin-owner-device-ca" and .ca == true and
      (.certificates | type) == "string" and (.certificates | contains("PRIVATE KEY") | not)
    )] | length' <<<"${mtls_certificates}")"
    observed_certificate_sha256="$(jq -j --arg id "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_ID}" '.result[] | select(.id == $id and .name == "pi-admin-owner-device-ca") | .certificates' <<<"${mtls_certificates}" | digest)"
    if [[ "${certificate_shape_match}" -eq 1 && "${observed_certificate_sha256}" == "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_SHA256}" ]]; then
      admin_certificate_verified=true
      admin_certificate_contract_hash="$(admin_certificate_fingerprint \
        "${CLOUDFLARE_ACCOUNT_ID}" "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_ID}" \
        "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_SHA256}")"
      printf 'pi_admin_certificate_activation_state=exact\n'
      printf 'admin_certificate_contract_sha256=%s\n' "${admin_certificate_contract_hash}"
    else
      printf 'pi_admin_certificate_activation_state=conflict\n'
    fi
  else
    printf 'pi_admin_certificate_activation_state=conflict\n'
  fi
fi
case "${audit_phase}" in
  preflight)
    [[ "${admin_certificate_named_count:-0}" -eq 0 ]] || mark_unavailable 'the owner-device CA must be absent before its isolated phase.'
    ;;
  admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
    [[ "${admin_certificate_verified}" == true ]] || mark_unavailable 'the exact public owner-device CA is not uniquely present.'
    ;;
esac

printf '\n## Owner WARP enrollment\n'
access_policies="$(api_get_complete "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/policies" 2>/dev/null || true)"
enrollment_policy_verified=false
admin_enrollment_policy_contract_hash=''
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${access_policies:-{}}"; then
  mark_unavailable 'Access reusable-policy inventory could not be completely audited; Access must be enabled on the Free plan.'
else
  enrollment_policy_named_count="$(jq -r '[.result[] | select(.name == "pi-admin-owner-device-enrollment")] | length' <<<"${access_policies}")"
  printf 'access_policy_inventory_count=%s\n' "$(jq -r '.result | length' <<<"${access_policies}")"
  printf 'unrelated_access_policy_inventory_sha256=%s\n' "$(jq -cS '[.result[] | select(.name != "pi-admin-owner-device-enrollment")] | sort_by(.id)' <<<"${access_policies}" | digest)"
  if [[ "${enrollment_policy_named_count}" -eq 0 ]]; then
    printf 'pi_admin_enrollment_policy_activation_state=absent\n'
  elif [[ "${enrollment_policy_named_count}" -eq 1 && "${enrollment_policy_contract_requested}" == true ]]; then
    enrollment_policy_match_count="$(jq -r --arg id "${CLOUDFLARE_OWNER_ENROLLMENT_POLICY_ID}" --arg email "${CLOUDFLARE_ADMIN_EMAIL}" '[.result[] | select(
      .id == $id and .name == "pi-admin-owner-device-enrollment" and
      .decision == "allow" and .session_duration == "15m" and
      .include == [{email: {email: $email}}] and
      ((.exclude // []) | length) == 0 and ((.require // []) | length) == 0 and
      .mfa_config == {allowed_authenticators: ["biometrics", "security_key"], mfa_disabled: false, session_duration: "5m"}
    )] | length' <<<"${access_policies}")"
    if [[ "${enrollment_policy_match_count}" -eq 1 ]]; then
      enrollment_policy_verified=true
      admin_enrollment_policy_contract_hash="$(admin_enrollment_policy_fingerprint \
        "${CLOUDFLARE_ACCOUNT_ID}" "${CLOUDFLARE_OWNER_ENROLLMENT_POLICY_ID}" "${CLOUDFLARE_ADMIN_EMAIL}")"
      printf 'pi_admin_enrollment_policy_activation_state=exact\n'
      printf 'admin_enrollment_policy_contract_sha256=%s\n' "${admin_enrollment_policy_contract_hash}"
    else
      printf 'pi_admin_enrollment_policy_activation_state=conflict\n'
    fi
  else
    printf 'pi_admin_enrollment_policy_activation_state=conflict\n'
  fi
fi

access_apps="$(api_get_complete "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/apps" 2>/dev/null || true)"
enrollment_app_verified=false
admin_enrollment_contract_hash=''
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${access_apps:-{}}"; then
  mark_unavailable 'Access application inventory could not be completely audited; Access must be enabled on the Free plan.'
else
  enrollment_app_named_count="$(jq -r '[.result[] | select(.name == "pi-admin-owner-device-enrollment")] | length' <<<"${access_apps}")"
  printf 'access_application_inventory_count=%s\n' "$(jq -r '.result | length' <<<"${access_apps}")"
  printf 'unrelated_access_application_inventory_sha256=%s\n' "$(jq -cS '[.result[] | select(.name != "pi-admin-owner-device-enrollment")] | sort_by(.id)' <<<"${access_apps}" | digest)"
  if [[ "${enrollment_app_named_count}" -eq 0 ]]; then
    printf 'pi_admin_enrollment_app_activation_state=absent\n'
  elif [[ "${enrollment_app_named_count}" -eq 1 && "${enrollment_contract_requested}" == true ]]; then
    enrollment_app_match_count="$(jq -r \
      --arg app_id "${CLOUDFLARE_OWNER_ENROLLMENT_APPLICATION_ID}" \
      --arg policy_id "${CLOUDFLARE_OWNER_ENROLLMENT_POLICY_ID}" \
      --arg idp_id "${CLOUDFLARE_ADMIN_IDENTITY_PROVIDER_ID}" '[.result[] | select(
        .id == $app_id and .name == "pi-admin-owner-device-enrollment" and .type == "warp" and
        .allowed_idps == [$idp_id] and .auto_redirect_to_identity == true and
        .session_duration == "15m" and
        .policies == [{id: $policy_id, precedence: 1}]
      )] | length' <<<"${access_apps}")"
    if [[ "${enrollment_app_match_count}" -eq 1 && "${enrollment_policy_verified}" == true ]]; then
      enrollment_app_verified=true
      admin_enrollment_contract_hash="$(admin_enrollment_fingerprint \
        "${CLOUDFLARE_ACCOUNT_ID}" "${CLOUDFLARE_OWNER_ENROLLMENT_POLICY_ID}" \
        "${CLOUDFLARE_OWNER_ENROLLMENT_APPLICATION_ID}" "${CLOUDFLARE_ADMIN_IDENTITY_PROVIDER_ID}" \
        "${CLOUDFLARE_ADMIN_EMAIL}")"
      printf 'pi_admin_enrollment_app_activation_state=exact\n'
      printf 'admin_enrollment_contract_sha256=%s\n' "${admin_enrollment_contract_hash}"
    else
      printf 'pi_admin_enrollment_app_activation_state=conflict\n'
    fi
  else
    printf 'pi_admin_enrollment_app_activation_state=conflict\n'
  fi
fi

identity_providers="$(api_get_complete "/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers" 2>/dev/null || true)"
admin_identity_provider_match_count=0
if jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${identity_providers:-{}}"; then
  if [[ "${enrollment_policy_contract_requested}" == true ]]; then
    admin_identity_provider_match_count="$(jq -r --arg id "${CLOUDFLARE_ADMIN_IDENTITY_PROVIDER_ID:-}" '[.result[] | select(.id == $id)] | length' <<<"${identity_providers}")"
  fi
  identity_provider_inventory_count="$(jq -r '.result | length' <<<"${identity_providers}")"
  printf 'identity_provider_inventory_count=%s\n' "${identity_provider_inventory_count}"
  printf 'admin_identity_provider_match_count=%s\n' "${admin_identity_provider_match_count}"
  printf 'identity_provider_inventory_sha256=%s\n' "$(jq -cS '.result | sort_by(.id)' <<<"${identity_providers}" | digest)"
  if [[ "${enrollment_policy_contract_requested}" == true && ("${identity_provider_inventory_count}" -ne 1 || "${admin_identity_provider_match_count}" -ne 1) ]]; then
    mark_unavailable 'the WARP enrollment application must bind the account sole identity provider.'
  fi
else
  mark_unavailable 'Access identity-provider inventory could not be completely audited.'
fi

case "${audit_phase}" in
  preflight|admin-certificate)
    [[ "${enrollment_policy_named_count:-0}" -eq 0 && "${enrollment_app_named_count:-0}" -eq 0 ]] || mark_unavailable 'owner enrollment objects must be absent before their isolated phases.'
    ;;
  admin-enrollment-policy)
    [[ "${enrollment_policy_verified}" == true && "${enrollment_app_named_count:-0}" -eq 0 ]] || mark_unavailable 'only the exact owner enrollment policy may exist at this phase.'
    ;;
  admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
    [[ "${enrollment_policy_verified}" == true && "${enrollment_app_verified}" == true ]] || mark_unavailable 'the exact owner-only MFA WARP enrollment application and policy are not uniquely present.'
    ;;
esac

printf '\n## Cloudflare Tunnels\n'
tunnels="$(api_get_complete "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel?is_deleted=false" 2>/dev/null || true)"
pi_admin_tunnel_id=''
naranjo_online_tunnel_id=''
lidersea_com_tunnel_id=''
pi_admin_tunnel_healthy=false
naranjo_online_tunnel_healthy=false
lidersea_com_tunnel_healthy=false
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${tunnels:-{}}"; then
  mark_unavailable 'Tunnel inventory could not be completely audited.'
else
  jq -r '"count=" + ((.result | length) | tostring), ([.result[]? | (.status // "unknown")] | group_by(.) | map({(.[0]): length}) | add // {} | @json)' <<<"${tunnels}"
  if ! jq -e '([.result | group_by(.name)[] | select(length > 1)] | length) == 0' >/dev/null <<<"${tunnels}"; then
    mark_unavailable 'duplicate active Tunnel names exist.'
  fi
  admin_tunnel_count="$(jq -r '[.result[] | select(.name == "pi-admin")] | length' <<<"${tunnels}")"
  naranjo_online_tunnel_count="$(jq -r '[.result[] | select(.name == "naranjo-online")] | length' <<<"${tunnels}")"
  lidersea_com_tunnel_count="$(jq -r '[.result[] | select(.name == "lidersea-com")] | length' <<<"${tunnels}")"
  tunnel_inventory_count="$(jq -r '.result | length' <<<"${tunnels}")"
  printf 'cloudflare_tunnel_inventory_count=%s\n' "${tunnel_inventory_count}"
  printf 'pi-admin exact_name_count=%s\n' "${admin_tunnel_count}"
  printf 'naranjo-online exact_name_count=%s\n' "${naranjo_online_tunnel_count}"
  printf 'lidersea-com exact_name_count=%s\n' "${lidersea_com_tunnel_count}"
  printf 'stable_tunnel_inventory_sha256=%s\n' "$(jq -cS '[.result[] | {id, name, config_src, tun_type, deleted_at}] | sort_by(.name)' <<<"${tunnels}" | digest)"
  printf 'unrelated_tunnel_inventory_sha256=%s\n' "$(jq -cS '[.result[] | select(.name != "pi-admin") | {id, name, config_src, tun_type, deleted_at}] | sort_by(.name)' <<<"${tunnels}" | digest)"
  [[ "${admin_tunnel_count}" -eq 0 ]] && printf 'pi_admin_tunnel_activation_state=absent\n' || printf 'pi_admin_tunnel_activation_state=present-or-conflict\n'
  [[ "${naranjo_online_tunnel_count}" -eq 1 ]] && printf 'naranjo_online_tunnel_activation_state=present\n' || printf 'naranjo_online_tunnel_activation_state=absent-or-conflict\n'
  [[ "${lidersea_com_tunnel_count}" -eq 1 ]] && printf 'lidersea_com_tunnel_activation_state=present\n' || printf 'lidersea_com_tunnel_activation_state=absent-or-conflict\n'
  if [[ "${admin_tunnel_count}" -eq 1 ]]; then
    pi_admin_tunnel_id="$(jq -er '.result[] | select(.name == "pi-admin") | .id' <<<"${tunnels}")"
    if ! [[ "${pi_admin_tunnel_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
      mark_unavailable 'pi-admin Tunnel ID is missing or malformed.'
      pi_admin_tunnel_id=''
    elif [[ "$(jq -r '.result[] | select(.name == "pi-admin") | (.status // "unknown")' <<<"${tunnels}")" == healthy ]]; then
      pi_admin_tunnel_healthy=true
    fi
  fi
  if [[ "${naranjo_online_tunnel_count}" -eq 1 ]]; then
    naranjo_online_tunnel_id="$(jq -er '.result[] | select(.name == "naranjo-online") | .id' <<<"${tunnels}")"
    if ! [[ "${naranjo_online_tunnel_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
      mark_unavailable 'naranjo-online Tunnel ID is missing or malformed.'
      naranjo_online_tunnel_id=''
    elif [[ "$(jq -r '.result[] | select(.name == "naranjo-online") | (.status // "unknown")' <<<"${tunnels}")" == healthy ]]; then
      naranjo_online_tunnel_healthy=true
    fi
  fi
  if [[ "${lidersea_com_tunnel_count}" -eq 1 ]]; then
    lidersea_com_tunnel_id="$(jq -er '.result[] | select(.name == "lidersea-com") | .id' <<<"${tunnels}")"
    if ! [[ "${lidersea_com_tunnel_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
      mark_unavailable 'lidersea-com Tunnel ID is missing or malformed.'
      lidersea_com_tunnel_id=''
    elif [[ "$(jq -r '.result[] | select(.name == "lidersea-com") | (.status // "unknown")' <<<"${tunnels}")" == healthy ]]; then
      lidersea_com_tunnel_healthy=true
    fi
  fi
  distinct_tunnel_id_count="$(jq -nr \
    --arg admin "${pi_admin_tunnel_id}" \
    --arg naranjo "${naranjo_online_tunnel_id}" \
    --arg lidersea "${lidersea_com_tunnel_id}" \
    '[$admin, $naranjo, $lidersea] | map(select(length > 0)) | unique | length')"
  expected_distinct_tunnel_id_count=2
  [[ -n "${pi_admin_tunnel_id}" ]] && expected_distinct_tunnel_id_count=3
  if [[ "${distinct_tunnel_id_count}" -ne "${expected_distinct_tunnel_id_count}" ]]; then
    mark_unavailable 'admin and per-site public Tunnel identities are not all separate.'
  fi
  case "${audit_phase}" in
    preflight|admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device)
      if [[ "${tunnel_inventory_count}" -ne 2 || "${admin_tunnel_count}" -ne 0 || "${naranjo_online_tunnel_count}" -ne 1 || "${lidersea_com_tunnel_count}" -ne 1 ]]; then
        mark_unavailable 'pre-admin staging requires exactly the two separate public site Tunnels and no pi-admin Tunnel.'
      fi
      ;;
    admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
      if [[ "${tunnel_inventory_count}" -ne 3 || "${admin_tunnel_count}" -ne 1 || "${naranjo_online_tunnel_count}" -ne 1 || "${lidersea_com_tunnel_count}" -ne 1 ]]; then
        mark_unavailable 'admin staging requires exactly pi-admin plus the two separate public site Tunnels.'
      elif [[ "${pi_admin_tunnel_healthy}" != true ]]; then
        mark_unavailable 'pi-admin Tunnel is not healthy after its isolated creation and connector-install phase.'
      fi
      ;;
  esac
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

  unrelated_gateway_hash="$(jq -cS '[.result[] | select(.name != "pi-admin-ssh-allow" and .name != "pi-admin-block")] | sort_by(.id)' <<<"${gateway_rules}" | digest)"
  printf 'unrelated_gateway_policy_inventory_sha256=%s\n' "${unrelated_gateway_hash}"
  case "${audit_phase}" in
    preflight|admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel)
      [[ "${gateway_policy_inventory_count}" -eq 0 ]] || mark_unavailable 'Gateway policies must remain absent before the isolated admin-policies phase.'
      ;;
    admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
      [[ "${gateway_policy_inventory_count}" -eq 2 ]] || mark_unavailable 'the complete Gateway inventory must contain the exact SSH allow and final Pi block only.'
      ;;
  esac

  if [[ "${admin_policy_contract_requested}" == true && -n "${pi_admin_tunnel_id}" ]]; then
    unreviewed_gateway_count="$(jq -r '[.result[] | select(
      .name != "pi-admin-ssh-allow" and .name != "pi-admin-block"
    )] | length' <<<"${gateway_rules}")"
    reviewed_gateway_count="$(jq -r '[.result[] | select(
      .name == "pi-admin-ssh-allow" or .name == "pi-admin-block"
    )] | length' <<<"${gateway_rules}")"
    if [[ "${unreviewed_gateway_count}" -eq 0 && "${reviewed_gateway_count}" -eq 2 &&
          "${gateway_policy_inventory_count}" -eq 2 ]]; then
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
fi

admin_policies_verified=false
admin_device_verified=false

printf '\n## WARP enrollment, device policy, and posture\n'
posture_rules="$(api_get_single_page "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/posture" 2>/dev/null || true)"
posture_named_count=0
posture_match_count=0
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${posture_rules:-{}}"; then
  mark_unavailable 'device-posture inventory could not be completely audited.'
else
  posture_named_count="$(jq -r '[.result[] | select(.name == "pi-admin-owner-device-certificate")] | length' <<<"${posture_rules}")"
  printf 'device_posture_inventory_count=%s\n' "$(jq -r '.result | length' <<<"${posture_rules}")"
  printf 'unrelated_device_posture_inventory_sha256=%s\n' "$(jq -cS '[.result[] | select(.name != "pi-admin-owner-device-certificate")] | sort_by(.id)' <<<"${posture_rules}" | digest)"
  if [[ "${posture_named_count}" -eq 0 ]]; then
    printf 'pi_admin_device_posture_activation_state=absent\n'
  elif [[ "${posture_named_count}" -eq 1 && "${admin_device_contract_requested}" == true ]]; then
    posture_match_count="$(jq -r --arg id "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}" \
      --arg certificate_id "${CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_ID}" '[.result[] | select(
        .id == $id and .name == "pi-admin-owner-device-certificate" and .enabled == true and
        .description == "Require the one owner laptop certificate and its matching private key." and
        .type == "client_certificate_v2" and
        ((.input // {}) | with_entries(select(.value != null))) == {
          certificate_id: $certificate_id,
          check_private_key: true,
          cn: "${serial_number}",
          extended_key_usage: ["clientAuth"],
          locations: {trust_stores: ["system"]},
          operating_system: "mac"
        } and
        .match == [{platform: "mac"}] and .expiration == "10m" and .schedule == "5m"
      )] | length' <<<"${posture_rules}")"
    if [[ "${posture_match_count}" -eq 1 ]]; then
      printf 'pi_admin_device_posture_activation_state=exact\n'
    else
      printf 'pi_admin_device_posture_activation_state=conflict\n'
    fi
  else
    printf 'pi_admin_device_posture_activation_state=conflict\n'
  fi
fi
printf 'required_posture_certificate_v2_exact_match_count=%s\n' "${posture_match_count}"

device_policies="$(api_get_single_page "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/policies" 2>/dev/null || true)"
profile_named_count=0
warp_policy_match_count=0
device_platform_routes_hash=''
if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${device_policies:-{}}"; then
  mark_unavailable 'device-profile inventory could not be completely audited.'
else
  profile_named_count="$(jq -r '[.result[] | select(.name == "pi-admin-owner-device")] | length' <<<"${device_policies}")"
  printf 'device_profile_inventory_count=%s\n' "$(jq -r '.result | length' <<<"${device_policies}")"
  printf 'unrelated_device_profile_inventory_sha256=%s\n' "$(jq -cS '[.result[] | select(.name != "pi-admin-owner-device")] | sort_by(.policy_id)' <<<"${device_policies}" | digest)"
  if [[ "${profile_named_count}" -eq 0 ]]; then
    printf 'pi_admin_device_profile_activation_state=absent\n'
  elif [[ "${profile_named_count}" -eq 1 && "${admin_device_contract_requested}" == true ]]; then
    warp_policy_match_count="$(jq -r --arg id "${CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID}" \
      --arg cidr "${CLOUDFLARE_PI_ADMIN_CIDR}" --arg email "${CLOUDFLARE_ADMIN_EMAIL}" '[.result[] | select(
        .policy_id == $id and .name == "pi-admin-owner-device" and .default == false and
        .description == "Locked owner profile; only the single Pi host route enters Cloudflare." and
        .enabled == true and .precedence == 100 and
        .match == ("identity.email == " + ($email | @json)) and
        .allow_mode_switch == false and .allow_updates == true and .allowed_to_leave == false and
        .auto_connect == 0 and .captive_portal == 180 and .disable_auto_fallback == true and
        .register_interface_ip_with_dns == false and .sccm_vpn_boundary_support == false and
        (.support_url // "") == "" and .switch_locked == true and .exclude_office_ips == false and
        .tunnel_protocol == "masque" and
        ((.service_mode_v2 // {}) | with_entries(select(.value != null))) == {mode: "warp"} and
        (.include // []) == [{address: $cidr, description: "Pi admin host only"}] and
        ((.exclude // []) | length) == 0 and
        ((.lan_allow_minutes // null) == null) and ((.lan_allow_subnet_size // null) == null)
      )] | length' <<<"${device_policies}")"
    device_platform_routes_hash="$(jq -cS --arg id "${CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID}" \
      '.result[] | select(.policy_id == $id) | {always_include: (.always_include // []), always_exclude: (.always_exclude // [])}' \
      <<<"${device_policies}" | digest)"
    printf 'device_platform_managed_routes_sha256=%s\n' "${device_platform_routes_hash}"
    if [[ "${warp_policy_match_count}" -eq 1 ]]; then
      printf 'pi_admin_device_profile_activation_state=exact\n'
    else
      printf 'pi_admin_device_profile_activation_state=conflict\n'
    fi
  else
    printf 'pi_admin_device_profile_activation_state=conflict\n'
  fi
fi
printf 'required_WARP_profile_exact_match_count=%s\n' "${warp_policy_match_count}"

device_inventory_required=false
case "${audit_phase}" in
  admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all) device_inventory_required=true ;;
esac
active_device_inventory_count=0
enrolled_match_count=0
device_inventory_complete=false
if [[ "${device_inventory_required}" == true ]]; then
  enrolled_devices="$(api_get_cursor_complete_one_page "/accounts/${CLOUDFLARE_ACCOUNT_ID}/devices/physical-devices?active_registrations=only&include=last_seen_registration.policy&per_page=100" 2>/dev/null || true)"
  if jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${enrolled_devices:-{}}"; then
    device_inventory_complete=true
    active_device_inventory_count="$(jq -r '.result | length' <<<"${enrolled_devices}")"
    if [[ "${admin_device_contract_requested}" == true ]]; then
      enrolled_match_count="$(jq -r --arg email "${CLOUDFLARE_ADMIN_EMAIL}" --arg profile_id "${CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID}" '[.result[] | select(
        .last_seen_user.email == $email and .active_registrations == 1 and
        .last_seen_registration.policy.id == $profile_id and
        .last_seen_registration.policy.name == "pi-admin-owner-device" and
        .last_seen_registration.policy.default == false and
        .last_seen_registration.policy.deleted == false
      )] | length' <<<"${enrolled_devices}")"
    fi
    printf 'active_device_inventory_sha256=%s\n' "$(jq -cS '.result | sort_by(.id)' <<<"${enrolled_devices}" | digest)"
  else
    mark_unavailable 'active WARP device inventory was not one stable complete cursor page.'
  fi
fi
printf 'active_device_inventory_count=%s\n' "${active_device_inventory_count}"
printf 'required_admin_WARP_enrollment_active_match_count=%s\n' "${enrolled_match_count}"
printf 'active_device_inventory_complete=%s\n' "${device_inventory_complete}"

case "${audit_phase}" in
  preflight|admin-certificate|admin-enrollment-policy|admin-enrollment-app)
    [[ "${posture_named_count}" -eq 0 && "${profile_named_count}" -eq 0 ]] || mark_unavailable 'owner posture and device profile must remain absent before the isolated admin-device phase.'
    if [[ "${audit_phase}" == admin-enrollment-app ]]; then
      [[ "${device_inventory_complete}" == true && "${active_device_inventory_count}" -eq 0 ]] || mark_unavailable 'no WARP device may be enrolled before the one-device phase.'
    fi
    ;;
  admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
    if [[ "${posture_match_count}" -eq 1 && "${warp_policy_match_count}" -eq 1 &&
          "${device_inventory_complete}" == true && "${active_device_inventory_count}" -eq 1 &&
          "${enrolled_match_count}" -eq 1 && "${admin_certificate_verified}" == true &&
          "${enrollment_app_verified}" == true ]]; then
      admin_device_verified=true
      admin_device_contract_hash="$(admin_device_fingerprint \
        "${CLOUDFLARE_ACCOUNT_ID}" "${CLOUDFLARE_PI_ADMIN_CIDR}" "${CLOUDFLARE_ADMIN_EMAIL}" \
        "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}" "${CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID}" \
        "${admin_certificate_contract_hash}" "${admin_enrollment_contract_hash}" \
        "${device_platform_routes_hash}")"
      printf 'admin_device_contract_sha256=%s\n' "${admin_device_contract_hash}"
    else
      mark_unavailable 'admin device contract requires one exact certificate posture rule, one locked include-/32 profile, and exactly one active owner device assigned to it.'
    fi
    ;;
esac

if [[ "${pi_admin_tunnel_healthy}" == true && "${admin_device_verified}" == true ]]; then
  admin_tunnel_hash="$(admin_tunnel_fingerprint \
    "${CLOUDFLARE_ACCOUNT_ID}" "${pi_admin_tunnel_id}" \
    "${admin_enrollment_contract_hash}" "${admin_device_contract_hash}")"
  printf 'admin_tunnel_contract_sha256=%s\n' "${admin_tunnel_hash}"
  admin_policy_inputs_hash="$(admin_policy_fingerprint admin-policy-inputs \
    "${CLOUDFLARE_ACCOUNT_ID}" "${pi_admin_tunnel_id}" "${CLOUDFLARE_PI_ADMIN_CIDR}" \
    "${CLOUDFLARE_ADMIN_EMAIL}" "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}" \
    "${CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID}" "${admin_device_contract_hash}" \
    "${admin_enrollment_contract_hash}" "${CLOUDFLARE_ADMIN_SESSION_FRESHNESS}" \
    "${CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE}" "${CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE}")"
  printf 'admin_policy_inputs_contract_sha256=%s\n' "${admin_policy_inputs_hash}"
fi

if [[ "${admin_policy_contract_requested}" == true ]]; then
  if [[ "${pi_admin_tunnel_healthy}" == true && "${admin_policy_verified}" == true && "${admin_device_verified}" == true ]]; then
    admin_policies_verified=true
    admin_policies_hash="$(admin_policy_fingerprint admin-policies \
      "${CLOUDFLARE_ACCOUNT_ID}" "${pi_admin_tunnel_id}" "${CLOUDFLARE_PI_ADMIN_CIDR}" \
      "${CLOUDFLARE_ADMIN_EMAIL}" "${CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID}" \
      "${CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID}" "${admin_device_contract_hash}" \
      "${admin_enrollment_contract_hash}" "${CLOUDFLARE_ADMIN_SESSION_FRESHNESS}" \
      "${CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE}" "${CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE}")"
    printf 'admin_policies_contract_sha256=%s\n' "${admin_policies_hash}"
  else
    mark_unavailable 'admin-policies contract requires the healthy Tunnel, closed exact two-rule L4 inventory, and verified one-device contract.'
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
  printf 'unrelated_private_route_inventory_sha256=%s\n' "$(jq -cS --arg network "${CLOUDFLARE_PI_ADMIN_CIDR:-}" '[.result[] | select(.network != $network)] | sort_by(.id)' <<<"${routes}" | digest)"
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
    preflight|admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel|admin-policies)
      [[ "${route_inventory_count}" -eq 0 ]] || mark_unavailable 'private routes must remain absent before the isolated admin-route phase.'
      ;;
    admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
      [[ "${route_inventory_count}" -eq 1 ]] || mark_unavailable 'the complete private-route inventory must contain the exact Pi /32 only.'
      ;;
  esac
fi

case "${audit_phase}" in
  admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
    [[ "${admin_route_verified}" == true ]] || mark_unavailable 'admin-route contract is not exactly one /32 bound to the verified admin Tunnel.'
    ;;
esac

printf '\n## Public edge contract\n'
public_edge_verified=false
naranjo_online_config=''
lidersea_com_config=''
if [[ -n "${naranjo_online_tunnel_id}" && -n "${lidersea_com_tunnel_id}" ]]; then
  naranjo_online_config="$(api_get "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${naranjo_online_tunnel_id}/configurations" 2>/dev/null || true)"
  lidersea_com_config="$(api_get "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${lidersea_com_tunnel_id}/configurations" 2>/dev/null || true)"
  if [[ "${naranjo_online_tunnel_healthy}" == true && "${lidersea_com_tunnel_healthy}" == true ]] &&
    CLOUDFLARE_AUDIT_EXPECTED_TUNNEL_ID="${naranjo_online_tunnel_id}" jq -e '
      .success == true and .result.account_id == env.CLOUDFLARE_ACCOUNT_ID and
      .result.tunnel_id == env.CLOUDFLARE_AUDIT_EXPECTED_TUNNEL_ID and .result.source == "cloudflare" and
      (.result.config | keys | sort) == ["ingress"] and
      .result.config.ingress == [
        {"hostname": "naranjo.online", "service": "http://naranjo-online.naranjo-online.svc.cluster.local:8080"},
        {"service": "http_status:404"}
      ]
    ' >/dev/null 2>&1 <<<"${naranjo_online_config:-{}}" &&
    CLOUDFLARE_AUDIT_EXPECTED_TUNNEL_ID="${lidersea_com_tunnel_id}" jq -e '
      .success == true and .result.account_id == env.CLOUDFLARE_ACCOUNT_ID and
      .result.tunnel_id == env.CLOUDFLARE_AUDIT_EXPECTED_TUNNEL_ID and .result.source == "cloudflare" and
      (.result.config | keys | sort) == ["ingress"] and
      .result.config.ingress == [
        {"hostname": "lidersea.com", "service": "http://lidersea-com.lidersea-com.svc.cluster.local:8080"},
        {"service": "http_status:404"}
      ]
    ' >/dev/null 2>&1 <<<"${lidersea_com_config:-{}}"; then
    public_edge_verified=true
    public_edge_hash="$(public_edge_fingerprint "${CLOUDFLARE_ACCOUNT_ID}" "${naranjo_online_tunnel_id}" "${lidersea_com_tunnel_id}")"
    printf 'public_site_tunnels=two-separate-healthy ingress=one-exact-origin-each terminal_404=verified\n'
    printf 'unrelated_tunnel_configuration_sha256=%s\n' "$(jq -cnS \
      --argjson naranjo "$(jq -cS '.result.config' <<<"${naranjo_online_config}")" \
      --argjson lidersea "$(jq -cS '.result.config' <<<"${lidersea_com_config}")" \
      '{"lidersea.com": $lidersea, "naranjo.online": $naranjo}' | digest)"
    printf 'public_edge_contract_sha256=%s\n' "${public_edge_hash}"
  else
    printf 'public_site_tunnels/config=unverified\n'
  fi
else
  printf 'public_site_tunnels/config=absent-or-conflict\n'
fi

case "${audit_phase}" in
  preflight|admin-certificate|admin-enrollment-policy|admin-enrollment-app|admin-device|admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
    [[ "${public_edge_verified}" == true ]] || mark_unavailable 'public-edge contract is not two healthy separate per-site Tunnels with one exact origin and terminal 404 each.'
    ;;
esac

printf '\n## Admin Tunnel public-exposure negative\n'
admin_tunnel_public_exposure_verified=false
if [[ -z "${pi_admin_tunnel_id}" ]]; then
  printf 'pi_admin_remote_config=absent-with-tunnel\n'
  admin_tunnel_public_exposure_verified=true
else
  pi_admin_config="$(api_get "/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${pi_admin_tunnel_id}/configurations" 2>/dev/null || true)"
  admin_public_dns_reference_count=0
  admin_dns_inventory_complete=true
  for zone_id in "${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}" "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}"; do
    admin_dns_records="$(api_get_complete "/zones/${zone_id}/dns_records" 2>/dev/null || true)"
    if ! jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${admin_dns_records:-{}}"; then
      admin_dns_inventory_complete=false
      continue
    fi
    current_admin_dns_reference_count="$(CLOUDFLARE_AUDIT_ADMIN_TUNNEL_ID="${pi_admin_tunnel_id}" jq -r \
      '[.result[] | select(.type == "CNAME" and .content == (env.CLOUDFLARE_AUDIT_ADMIN_TUNNEL_ID + ".cfargotunnel.com"))] | length' \
      <<<"${admin_dns_records}")"
    admin_public_dns_reference_count=$((admin_public_dns_reference_count + current_admin_dns_reference_count))
  done
  if [[ "${admin_dns_inventory_complete}" == true && "${admin_public_dns_reference_count}" -eq 0 ]] &&
    CLOUDFLARE_AUDIT_EXPECTED_TUNNEL_ID="${pi_admin_tunnel_id}" jq -e '
      .success == true and .result.account_id == env.CLOUDFLARE_ACCOUNT_ID and
      .result.tunnel_id == env.CLOUDFLARE_AUDIT_EXPECTED_TUNNEL_ID and .result.source == "cloudflare" and
      ((.result.config // null) == null or .result.config == {})
    ' >/dev/null 2>&1 <<<"${pi_admin_config:-{}}"; then
    admin_tunnel_public_exposure_verified=true
    printf 'pi_admin_remote_config=no-public-ingress dns_references=0\n'
  else
    printf 'pi_admin_remote_config_or_dns_negative=unverified\n'
  fi
fi
case "${audit_phase}" in
  admin-tunnel|admin-policies|admin-route|public-edge-preflight|public-edge|public-dns-naranjo|public-dns-lidersea|all)
    [[ "${admin_tunnel_public_exposure_verified}" == true ]] || mark_unavailable 'pi-admin has a public ingress configuration, public DNS reference, or an incomplete negative audit.'
    ;;
esac

printf '\n## Public apex activation state\n'
zone_names=("lidersea.com" "naranjo.online")
zone_ids=("${CLOUDFLARE_LIDERSEA_COM_ZONE_ID}" "${CLOUDFLARE_NARANJO_ONLINE_ZONE_ID}")
for index in "${!zone_names[@]}"; do
  zone_name="${zone_names[$index]}"
  zone_id="${zone_ids[$index]}"
  if [[ "${zone_name}" == naranjo.online ]]; then
    public_tunnel_id="${naranjo_online_tunnel_id}"
  else
    public_tunnel_id="${lidersea_com_tunnel_id}"
  fi
  apex_state=unavailable
  apex_records="$(api_get_complete "/zones/${zone_id}/dns_records?name=${zone_name}" 2>/dev/null || true)"
  if jq -e '.success == true and (.result | type == "array")' >/dev/null 2>&1 <<<"${apex_records:-{}}"; then
    address_record_count="$(jq -r --arg hostname "${zone_name}" '[.result[] | select(.name == $hostname and (.type == "A" or .type == "AAAA" or .type == "CNAME"))] | length' <<<"${apex_records}")"
    if [[ "${address_record_count}" -eq 0 ]]; then
      apex_state=absent
    elif [[ "${public_edge_verified}" == true ]] &&
      CLOUDFLARE_AUDIT_PUBLIC_TUNNEL_ID="${public_tunnel_id}" jq -e --arg hostname "${zone_name}" '
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
    printf '%s=%s\n' "${binding_label}" "$(public_dns_binding_fingerprint "${binding_phase}" "${CLOUDFLARE_ACCOUNT_ID}" "${public_tunnel_id}" "${zone_id}" "${zone_name}")"
  fi

  expected_apex_state=''
  case "${audit_phase}:${zone_name}" in
    preflight:*|admin-certificate:*|admin-enrollment-policy:*|admin-enrollment-app:*|admin-device:*|admin-tunnel:*|admin-policies:*|admin-route:*) expected_apex_state=exact ;;
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
