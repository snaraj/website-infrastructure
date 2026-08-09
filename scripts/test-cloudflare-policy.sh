#!/usr/bin/env bash
# Prove the Cloudflare zero-spend plan policy accepts one reviewed topology and
# rejects both curated and mechanically mutated ways to exceed its boundaries.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
policy="${repo_root}/infrastructure/cloudflare/policy"
fixtures="${repo_root}/infrastructure/cloudflare/tests/fixtures"
command -v conftest >/dev/null 2>&1 || { printf 'conftest is required\n' >&2; exit 2; }
# Python is used only to mutate JSON fixtures deterministically; production and
# cluster code remain Go/Kubernetes, and callers may pin the interpreter in CI.
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

# The allow fixture prevents an accidentally impossible policy, while every deny
# fixture must fail or the test suite stops immediately.
conftest test --policy "${policy}" "${fixtures}/allow-plan.json"
for fixture in "${fixtures}"/deny-*.json; do
  if conftest test --policy "${policy}" "${fixture}" >/dev/null 2>&1; then
    printf 'forbidden Cloudflare plan unexpectedly passed: %s\n' "${fixture}" >&2
    exit 1
  fi
  printf 'PASS rejected %s\n' "${fixture}"
done

# Mutations derive one forbidden change at a time from the known-good plan, which
# catches policy gaps without maintaining many nearly identical JSON files.
temporary="$(mktemp -d)"
trap 'rm -rf -- "${temporary}"' EXIT
# assert_mutation_denied makes rejection—not merely tool execution—the contract.
assert_mutation_denied() {
  local name="$1"
  local output="${temporary}/${name}.json"
  "${python_command}" "${repo_root}/scripts/mutate_cloudflare_fixture.py" \
    "${name}" "${fixtures}/allow-plan.json" "${output}"
  if conftest test --policy "${policy}" "${output}" >/dev/null 2>&1; then
    printf 'mutated Cloudflare plan unexpectedly passed: %s\n' "${name}" >&2
    exit 1
  fi
  printf 'PASS rejected mutation %s\n' "${name}"
}

assert_mutation_denied disabled-block
assert_mutation_denied widened-traffic
assert_mutation_denied public-admin-cidr
assert_mutation_denied unknown-block-state
assert_mutation_denied wrong-route-tunnel
assert_mutation_denied extra-route-reference
assert_mutation_denied wrong-identity-variable
assert_mutation_denied duplicate-tunnel-name
assert_mutation_denied mismatched-public-hostname
assert_mutation_denied mismatched-lidersea-hostname
assert_mutation_denied swapped-public-ingress
assert_mutation_denied wrong-lidersea-origin
assert_mutation_denied nonterminal-catchall
assert_mutation_denied duplicate-ingress-hostname
assert_mutation_denied widened-filters
assert_mutation_denied cloudflare-data-source
assert_mutation_denied cross-account-target
assert_mutation_denied wrong-account-variable
assert_mutation_denied literal-account-target
assert_mutation_denied missing-account-target
assert_mutation_denied unknown-account-target
assert_mutation_denied wrong-zone-variable
assert_mutation_denied wrong-lidersea-zone-variable
assert_mutation_denied swapped-zone-variables
assert_mutation_denied literal-zone-target
assert_mutation_denied missing-zone-target
assert_mutation_denied unknown-zone-target
assert_mutation_denied duplicate-zone-target
assert_mutation_denied malformed-zone-target
assert_mutation_denied zone-equals-account-target
assert_mutation_denied wrong-lidersea-cname-tunnel
assert_mutation_denied wrong-lidersea-cname-attribute
assert_mutation_denied missing-dns-record
assert_mutation_denied duplicate-dns-record
assert_mutation_denied extra-dns-record
assert_mutation_denied extra-public-tunnel
