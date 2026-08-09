#!/usr/bin/env bash
set -euo pipefail

# OpenTofu plans contain sensitive values even when terminal output marks them
# sensitive. Keep the derived JSON owner-readable and destroy it on every exit.
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
plan_path="${1:-}"
[[ -n "${plan_path}" && -f "${plan_path}" ]] || { printf 'Usage: %s /protected/path/to/plan.tfplan\n' "$0" >&2; exit 2; }
for command_name in tofu conftest jq sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 || { printf '%s is required\n' "${command_name}" >&2; exit 2; }
done

json_path="$(mktemp)"
trap 'rm -f "${json_path}"' EXIT
tofu -chdir="${repo_root}/infrastructure/cloudflare" show -json "${plan_path}" > "${json_path}"
conftest test --policy "${repo_root}/infrastructure/cloudflare/policy" "${json_path}"

# Conftest proves the reference graph; this extraction independently binds the
# three resolved opaque targets to the two canonical public labels. Any missing,
# duplicate, malformed, swapped-address, or account-as-zone value fails closed.
if ! binding_json="$(jq -ce '
  def valid_target_id: type == "string" and test("^[0-9a-f]{32}$");
  . as $plan
  | ([
    $plan.resource_changes[]?
    | select(.mode == "managed")
    | select(
        .type == "cloudflare_zero_trust_gateway_policy" or
        .type == "cloudflare_zero_trust_tunnel_cloudflared" or
        .type == "cloudflare_zero_trust_tunnel_cloudflared_config" or
        .type == "cloudflare_zero_trust_tunnel_cloudflared_route"
      )
    | .change.after.account_id
  ] | unique) as $accounts
  | [
      $plan.resource_changes[]?
      | select(.mode == "managed")
      | select(.address == "cloudflare_dns_record.naranjo_online[0]")
      | select(.change.after.name == "naranjo.online")
      | .change.after.zone_id
    ] as $naranjo_online_zones
  | [
      $plan.resource_changes[]?
      | select(.mode == "managed")
      | select(.address == "cloudflare_dns_record.lidersea_com[0]")
      | select(.change.after.name == "lidersea.com")
      | .change.after.zone_id
    ] as $lidersea_com_zones
  | if
      ($accounts | length) == 1 and
      ($naranjo_online_zones | length) == 1 and
      ($lidersea_com_zones | length) == 1 and
      ($accounts[0] | valid_target_id) and
      ($naranjo_online_zones[0] | valid_target_id) and
      ($lidersea_com_zones[0] | valid_target_id) and
      $accounts[0] != $naranjo_online_zones[0] and
      $accounts[0] != $lidersea_com_zones[0] and
      $naranjo_online_zones[0] != $lidersea_com_zones[0]
    then {
      account_id: $accounts[0],
      naranjo_online_zone_id: $naranjo_online_zones[0],
      lidersea_com_zone_id: $lidersea_com_zones[0]
    }
    else error("plan does not resolve to one account and two labelled distinct zones")
    end
' "${json_path}" 2>/dev/null)"; then
  printf 'Cloudflare plan target binding could not be proven\n' >&2
  exit 1
fi

account_id="$(jq -r '.account_id' <<<"${binding_json}")"
naranjo_online_zone_id="$(jq -r '.naranjo_online_zone_id' <<<"${binding_json}")"
lidersea_com_zone_id="$(jq -r '.lidersea_com_zone_id' <<<"${binding_json}")"

# Keep this labelled byte sequence identical to cloudflare-audit.sh. Public
# domain labels are sorted; raw account and zone IDs never reach output.
binding_fingerprint() {
  local bound_account_id="$1"
  local bound_naranjo_online_zone_id="$2"
  local bound_lidersea_com_zone_id="$3"
  printf 'account=%s\npublic_domain[lidersea.com]=%s\npublic_domain[naranjo.online]=%s\n' \
    "${bound_account_id}" "${bound_lidersea_com_zone_id}" "${bound_naranjo_online_zone_id}" | sha256sum
}

target_binding_hash="$(binding_fingerprint \
  "${account_id}" "${naranjo_online_zone_id}" "${lidersea_com_zone_id}")"
target_binding_hash="${target_binding_hash%% *}"
plan_hash="$(sha256sum "${plan_path}")"
plan_hash="${plan_hash%% *}"
printf 'plan_sha256=%s\n' "${plan_hash}"
printf 'target_binding_sha256=%s\n' "${target_binding_hash}"
jq -r '[.resource_changes[]? | select(.mode == "managed") | .type] | group_by(.)[] | "resource_count " + .[0] + "=" + (length|tostring)' "${json_path}"
printf "POLICY PASS ONLY. Expected infrastructure cost remains \$0 subject to a current\n"
printf 'read-only subscription/Free-entitlement audit and dashboard checks. This is\n'
printf 'not apply authorization. Large-media delivery remains a Free-plan NO-GO.\n'
printf 'Record the hash and obtain explicit approval for the ordinary sites only.\n'
