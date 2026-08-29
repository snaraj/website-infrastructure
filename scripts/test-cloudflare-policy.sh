#!/usr/bin/env bash
# Prove each isolated Cloudflare phase accepts one exact graph and rejects
# topology, sequencing, target-binding, widening, and deletion mutations.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
policy="${repo_root}/infrastructure/cloudflare/policy"
fixtures="${repo_root}/infrastructure/cloudflare/tests/fixtures"
command -v conftest >/dev/null 2>&1 || { printf 'conftest is required\n' >&2; exit 2; }

if [[ -n "${PYTHON_BIN:-}" ]]; then
  python_command="${PYTHON_BIN}"
elif python3 --version >/dev/null 2>&1; then
  python_command=python3
elif python --version >/dev/null 2>&1; then
  python_command=python
else
  printf 'Python 3 is required for deterministic JSON fixture mutations\n' >&2
  exit 2
fi

for fixture in "${fixtures}"/allow-*.json; do
  conftest test --policy "${policy}" "${fixture}"
done

temporary="$(mktemp -d)"
trap 'rm -rf -- "${temporary}"' EXIT

assert_mutation_denied() {
  local phase="$1"
  local name="$2"
  local source="${fixtures}/allow-${phase}.json"
  local output="${temporary}/${phase}-${name}.json"
  "${python_command}" "${repo_root}/scripts/mutate_cloudflare_fixture.py" \
    "${name}" "${source}" "${output}"
  if conftest test --policy "${policy}" "${output}" >/dev/null 2>&1; then
    printf 'mutated Cloudflare plan unexpectedly passed: %s/%s\n' "${phase}" "${name}" >&2
    exit 1
  fi
  printf 'PASS rejected mutation %s/%s\n' "${phase}" "${name}"
}

for phase in admin-certificate admin-enrollment-policy admin-enrollment-app admin-device admin-tunnel admin-policies admin-route site-naranjo-online site-lidersea-com; do
  assert_mutation_denied "${phase}" false-approval
  assert_mutation_denied "${phase}" delete-resource
  assert_mutation_denied "${phase}" cloudflare-data-source
  assert_mutation_denied "${phase}" external-data-source
  assert_mutation_denied "${phase}" local-exec-provisioner
  assert_mutation_denied "${phase}" module-call
  assert_mutation_denied "${phase}" provider-override
  assert_mutation_denied "${phase}" missing-provider-config
  assert_mutation_denied "${phase}" unexpected-mode
  assert_mutation_denied "${phase}" extra-resource
  assert_mutation_denied "${phase}" extra-configured-field
  assert_mutation_denied "${phase}" unknown-critical
done

# Administrative onboarding stays create-only: a plan carrying a prior object
# is a stale or already-applied plan and must never re-run.
for phase in admin-certificate admin-enrollment-policy admin-enrollment-app admin-device admin-tunnel admin-policies admin-route; do
  assert_mutation_denied "${phase}" stale-update
done

assert_mutation_denied admin-certificate certificate-is-not-ca
assert_mutation_denied admin-certificate certificate-private-key
assert_mutation_denied admin-certificate certificate-hash-mismatch
assert_mutation_denied admin-certificate wrong-certificate-variable
assert_mutation_denied admin-certificate wrong-account-variable

assert_mutation_denied admin-enrollment-policy enrollment-everyone
assert_mutation_denied admin-enrollment-policy enrollment-email-widened
assert_mutation_denied admin-enrollment-policy enrollment-mfa-disabled
assert_mutation_denied admin-enrollment-policy enrollment-weak-mfa
assert_mutation_denied admin-enrollment-policy enrollment-session-long
assert_mutation_denied admin-enrollment-policy wrong-enrollment-email-variable
assert_mutation_denied admin-enrollment-policy wrong-account-variable

assert_mutation_denied admin-enrollment-app extra-identity-provider
assert_mutation_denied admin-enrollment-app enrollment-app-wrong-type
assert_mutation_denied admin-enrollment-app enrollment-auto-redirect-off
assert_mutation_denied admin-enrollment-app enrollment-policy-precedence
assert_mutation_denied admin-enrollment-app missing-enrollment-policy-contract
assert_mutation_denied admin-enrollment-app wrong-enrollment-policy-variable
assert_mutation_denied admin-enrollment-app wrong-account-variable

assert_mutation_denied admin-device device-match-widened
assert_mutation_denied admin-device device-route-widened
assert_mutation_denied admin-device device-fallback-enabled
assert_mutation_denied admin-device device-dns-registration-enabled
assert_mutation_denied admin-device device-wireguard-protocol
assert_mutation_denied admin-device device-can-leave
assert_mutation_denied admin-device device-can-switch-mode
assert_mutation_denied admin-device device-private-key-check-off
assert_mutation_denied admin-device device-certificate-cn-wildcard
assert_mutation_denied admin-device device-posture-expiration-long
assert_mutation_denied admin-device missing-certificate-contract
assert_mutation_denied admin-device missing-enrollment-contract
assert_mutation_denied admin-device wrong-account-variable

assert_mutation_denied admin-tunnel missing-device-contract
assert_mutation_denied admin-tunnel missing-enrollment-contract
assert_mutation_denied admin-tunnel wrong-account-variable

assert_mutation_denied admin-policies disabled-block
assert_mutation_denied admin-policies widened-ssh-traffic
assert_mutation_denied admin-policies api-in-ssh-phase
assert_mutation_denied admin-policies widened-filters
assert_mutation_denied admin-policies wrong-identity-variable
assert_mutation_denied admin-policies missing-block
assert_mutation_denied admin-policies swapped-precedence
assert_mutation_denied admin-policies no-session-enforcement
assert_mutation_denied admin-policies extra-session-setting
assert_mutation_denied admin-policies wrong-account-variable
assert_mutation_denied admin-policies missing-tunnel-contract
assert_mutation_denied admin-policies zero-tunnel-contract
assert_mutation_denied admin-policies missing-device-contract
assert_mutation_denied admin-policies zero-device-contract
assert_mutation_denied admin-policies missing-enrollment-contract
assert_mutation_denied admin-policies opaque-device-profile-id
assert_mutation_denied admin-policies missing-policy-inputs-contract
assert_mutation_denied admin-policies zero-policy-inputs-contract
assert_mutation_denied admin-policies opaque-posture-id
assert_mutation_denied admin-policies identity-scoped-block
assert_mutation_denied admin-policies expiring-block

assert_mutation_denied admin-route widened-route
assert_mutation_denied admin-route public-route
assert_mutation_denied admin-route wrong-route-tunnel-variable
assert_mutation_denied admin-route missing-policies-contract
assert_mutation_denied admin-route zero-policies-contract
assert_mutation_denied admin-route zero-device-contract
assert_mutation_denied admin-route missing-enrollment-contract
assert_mutation_denied admin-route opaque-device-profile-id
assert_mutation_denied admin-route opaque-posture-id
assert_mutation_denied admin-route wrong-route-comment
assert_mutation_denied admin-route wrong-account-variable

# The two site roots adopt live objects. Every mutation below is a way the
# adoption could damage a running site, reach the other site, widen the public
# surface, or walk the zone security target state backwards.
for phase in site-naranjo-online site-lidersea-com; do
  assert_mutation_denied "${phase}" fabricated-create
  assert_mutation_denied "${phase}" create-with-prior-object
  assert_mutation_denied "${phase}" apex-foreign-tunnel-uuid
  assert_mutation_denied "${phase}" config-foreign-tunnel-uuid
  assert_mutation_denied "${phase}" cross-site-plan-value
  assert_mutation_denied "${phase}" cross-site-ingress-value
  assert_mutation_denied "${phase}" cross-site-config-reference
  assert_mutation_denied "${phase}" recreate-adopted-tunnel
  assert_mutation_denied "${phase}" tunnel-config-update
  assert_mutation_denied "${phase}" renamed-tunnel
  assert_mutation_denied "${phase}" extra-public-tunnel
  assert_mutation_denied "${phase}" wrong-account-variable
  assert_mutation_denied "${phase}" cross-site-hostname
  assert_mutation_denied "${phase}" cross-site-origin
  assert_mutation_denied "${phase}" cross-site-tunnel-reference
  assert_mutation_denied "${phase}" wildcard-hostname
  assert_mutation_denied "${phase}" wildcard-dns-name
  assert_mutation_denied "${phase}" extra-ingress-rule
  assert_mutation_denied "${phase}" nonterminal-catchall
  assert_mutation_denied "${phase}" wrong-site-origin
  assert_mutation_denied "${phase}" public-warp-routing
  assert_mutation_denied "${phase}" private-route-in-site-root
  assert_mutation_denied "${phase}" wrong-public-hostname
  assert_mutation_denied "${phase}" wrong-zone-variable
  assert_mutation_denied "${phase}" account-as-zone-target
  assert_mutation_denied "${phase}" unproxied-dns
  assert_mutation_denied "${phase}" a-record
  assert_mutation_denied "${phase}" aaaa-record
  assert_mutation_denied "${phase}" always-use-https-off
  assert_mutation_denied "${phase}" min-tls-downgrade
  assert_mutation_denied "${phase}" tls13-off
  assert_mutation_denied "${phase}" zero-rtt-on
  assert_mutation_denied "${phase}" http3-off
  assert_mutation_denied "${phase}" ssl-strict
  assert_mutation_denied "${phase}" ssl-flexible
  assert_mutation_denied "${phase}" rebound-zone-setting
  assert_mutation_denied "${phase}" missing-zone-setting
  assert_mutation_denied "${phase}" extra-zone-setting
  assert_mutation_denied "${phase}" duplicate-setting-owner
  assert_mutation_denied "${phase}" wrong-https-prestate
  assert_mutation_denied "${phase}" wrong-min-tls-prestate
  assert_mutation_denied "${phase}" unrelated-zone-setting-update
  assert_mutation_denied "${phase}" lying-no-op-setting
  assert_mutation_denied "${phase}" missing-adoption-audit
  assert_mutation_denied "${phase}" zero-adoption-audit
done

printf 'All isolated Cloudflare phase policy fixtures passed.\n'
