#!/usr/bin/env bash
# Exercise Kubernetes admission policy with explicit positive and negative
# controls before those rules become part of the Flux reconciliation boundary.
#
# WHY A DENY FIXTURE IS ASSERTED PER DOCUMENT, NOT PER FILE
#
# A deny fixture is a multi-document file: several plausible widenings of the
# same reviewed contract, each of which must be refused. Asserting only that
# CONFTEST REJECTED THE FILE hides the weakening of any single deny arm — with
# five bypass documents in one file, a rego arm can be widened so that its
# document is now ACCEPTED and the other four denials still fail the file. The
# fixture still "rejects", the suite is still green, and the real manifest the
# same widening was applied to sails through. That was reproduced on this
# repository (two separate arms), which is why file-level rejection is no longer
# the assertion.
#
# So every deny fixture carries a reviewed `.expected` sidecar naming EXACTLY
# the denial messages it must produce, and this runner compares the whole set.
# A message that disappears is a weakened rule; a message that appears is a
# denial nobody reviewed. Both are failures, and both name the arm — because the
# message names the rule and the object that tripped it.
#
# `expect_release_rejection` in scripts/render-manifests.sh is the same pattern
# on the release policy set; this is that discipline applied to deny fixtures.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
policy="${repo_root}/policies/conftest"

command -v conftest >/dev/null 2>&1 || { printf 'conftest is required\n' >&2; exit 2; }

# Allow fixtures detect over-broad rules; deny fixtures prove unsafe resources
# still stop the build instead of being accepted as ordinary test output.
for fixture in "${repo_root}"/tests/kubernetes/fixtures/allow/*.yaml; do
  conftest test --policy "${policy}" "${fixture}"
done

# Conftest colours its output on a terminal; the escape sequences are stripped
# so the comparison is over messages rather than over presentation.
strip_ansi() {
  sed -E $'s/\x1b\\[[0-9;]*m//g'
}

expect_fixture_denials() {
  local fixture="$1"
  local expected_file="${fixture%.yaml}.expected"
  local result='' actual='' expected=''

  [[ -f "$expected_file" ]] || {
    printf 'deny fixture has no reviewed denial list: %s\n' "$expected_file" >&2
    printf 'every deny fixture states the exact message each document must produce\n' >&2
    exit 1
  }

  if result="$(conftest test --policy "${policy}" "${fixture}" 2>&1)"; then
    printf 'deny fixture unexpectedly passed: %s\n' "${fixture}" >&2
    exit 1
  fi

  actual="$(printf '%s\n' "$result" | strip_ansi |
    sed -n 's/^FAIL - .* - main - //p' | LC_ALL=C sort)"
  expected="$(grep -vE '^[[:space:]]*(#|$)' "$expected_file" | LC_ALL=C sort)"

  if [[ "$actual" != "$expected" ]]; then
    printf 'deny fixture produced a different denial set than reviewed: %s\n' \
      "${fixture}" >&2
    printf -- '--- missing (a rule stopped denying) ---\n' >&2
    comm -13 <(printf '%s\n' "$actual") <(printf '%s\n' "$expected") >&2
    printf -- '--- unreviewed (a rule started denying) ---\n' >&2
    comm -23 <(printf '%s\n' "$actual") <(printf '%s\n' "$expected") >&2
    exit 1
  fi

  printf 'PASS rejected %s (%s reviewed denial(s))\n' "${fixture}" \
    "$(printf '%s\n' "$expected" | grep -cE '.')"
}

for fixture in "${repo_root}"/tests/kubernetes/fixtures/deny/*.yaml; do
  expect_fixture_denials "$fixture"
done
