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

for phase in admin-tunnel admin-policies admin-route admin-api public-edge public-dns-naranjo public-dns-lidersea; do
  assert_mutation_denied "${phase}" false-approval
  assert_mutation_denied "${phase}" delete-resource
  assert_mutation_denied "${phase}" cloudflare-data-source
  assert_mutation_denied "${phase}" external-data-source
  assert_mutation_denied "${phase}" local-exec-provisioner
  assert_mutation_denied "${phase}" module-call
  assert_mutation_denied "${phase}" provider-override
  assert_mutation_denied "${phase}" missing-provider-config
  assert_mutation_denied "${phase}" stale-update
  assert_mutation_denied "${phase}" unexpected-mode
  assert_mutation_denied "${phase}" extra-resource
  assert_mutation_denied "${phase}" extra-configured-field
  assert_mutation_denied "${phase}" unknown-critical
done

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
assert_mutation_denied admin-policies missing-posture-contract
assert_mutation_denied admin-policies zero-posture-contract
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
assert_mutation_denied admin-route zero-posture-contract
assert_mutation_denied admin-route opaque-posture-id
assert_mutation_denied admin-route wrong-route-comment
assert_mutation_denied admin-route wrong-account-variable

assert_mutation_denied admin-api wrong-api-port
assert_mutation_denied admin-api missing-route-contract
assert_mutation_denied admin-api zero-route-contract
assert_mutation_denied admin-api missing-api-inputs-contract
assert_mutation_denied admin-api zero-api-inputs-contract
assert_mutation_denied admin-api zero-policies-contract
assert_mutation_denied admin-api zero-posture-contract
assert_mutation_denied admin-api opaque-posture-id
assert_mutation_denied admin-api api-after-block
assert_mutation_denied admin-api api-precedence-offset
assert_mutation_denied admin-api no-session-enforcement
assert_mutation_denied admin-api extra-session-setting
assert_mutation_denied admin-api wrong-account-variable

assert_mutation_denied public-edge swapped-public-ingress
assert_mutation_denied public-edge wrong-lidersea-origin
assert_mutation_denied public-edge nonterminal-catchall
assert_mutation_denied public-edge duplicate-ingress-hostname
assert_mutation_denied public-edge extra-public-tunnel
assert_mutation_denied public-edge public-warp-routing
assert_mutation_denied public-edge dns-too-early
assert_mutation_denied public-edge wrong-account-variable

for phase in public-dns-naranjo public-dns-lidersea; do
  assert_mutation_denied "${phase}" wrong-public-hostname
  assert_mutation_denied "${phase}" wrong-zone-variable
  assert_mutation_denied "${phase}" wrong-cname-tunnel-variable
  assert_mutation_denied "${phase}" unproxied-dns
  assert_mutation_denied "${phase}" a-record
  assert_mutation_denied "${phase}" account-as-zone-target
  assert_mutation_denied "${phase}" missing-edge-contract
  assert_mutation_denied "${phase}" zero-edge-contract
done

printf 'All isolated Cloudflare phase policy fixtures passed.\n'
