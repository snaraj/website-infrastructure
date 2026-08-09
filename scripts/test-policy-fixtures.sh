#!/usr/bin/env bash
# Exercise Kubernetes admission policy with explicit positive and negative
# controls before those rules become part of the Flux reconciliation boundary.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
policy="${repo_root}/policies/conftest"

command -v conftest >/dev/null 2>&1 || { printf 'conftest is required\n' >&2; exit 2; }

# Allow fixtures detect over-broad rules; deny fixtures prove unsafe resources
# still stop the build instead of being accepted as ordinary test output.
for fixture in "${repo_root}"/tests/kubernetes/fixtures/allow/*.yaml; do
  conftest test --policy "${policy}" "${fixture}"
done
for fixture in "${repo_root}"/tests/kubernetes/fixtures/deny/*.yaml; do
  if conftest test --policy "${policy}" "${fixture}" >/dev/null 2>&1; then
    printf 'deny fixture unexpectedly passed: %s\n' "${fixture}" >&2
    exit 1
  fi
  printf 'PASS rejected %s\n' "${fixture}"
done
