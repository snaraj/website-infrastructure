#!/usr/bin/env bash
# Exercise Kubernetes admission policy with explicit positive and negative
# controls before those rules become part of the Flux reconciliation boundary.
#
# ATTRIBUTION. "This file was rejected" is a weak assertion: whenever any OTHER
# rule also denies the same object, a rule can be neutralized and the runner
# stays green. Measured twice on wi #96 (2026-08-12) — the Rego SR-0 arm, and
# then both pod-volume arms, each neutralized with every committed gate green.
# So a deny fixture may declare, in a `# rego-message:` header, the exact
# message fragment the rule it exists to kill emits, and this runner then
# requires that fragment in the Conftest output. Fixtures with no header keep
# the older file-level assertion; the header is required for the single-object
# storage and pod-volume corpora by
# tests/security/test_storage_exposure_policy_contract.py, which pins the
# fixture names and the fragments as literals held outside these files.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
policy="${repo_root}/policies/conftest"

command -v conftest >/dev/null 2>&1 || { printf 'conftest is required\n' >&2; exit 2; }

# Set ONLY by the self-test below, so the attribution grep can be exercised
# against a message no rule emits without editing a committed fixture.
expected_message_override=''

# Reject one deny fixture, and — when it declares one — require the denial to
# carry the message its own rule emits. The two failure modes return DIFFERENT
# codes on purpose: the self-test has to tell "the attribution check stopped
# checking" from "the rule this probe pins was weakened", and both are red.
#   0  rejected, by the rule it claims
#   1  not rejected at all
#   2  rejected, but by some other rule
expect_rejection() {
  local fixture="$1" output expected_message
  if output="$(conftest test --policy "${policy}" "${fixture}" 2>&1)"; then
    printf '%s\n' "${output}" >&2
    printf 'deny fixture unexpectedly passed: %s\n' "${fixture}" >&2
    return 1
  fi

  if [[ -n "${expected_message_override}" ]]; then
    expected_message="${expected_message_override}"
  else
    expected_message="$(sed -n 's/^# rego-message: //p' "${fixture}" | head -n 1)"
  fi
  if [[ -n "${expected_message}" ]] && ! grep -Fq -- "${expected_message}" <<<"${output}"; then
    printf '%s\n' "${output}" >&2
    printf 'deny fixture was rejected by some OTHER rule, not the one it claims: %s (expected message: %s)\n' \
      "${fixture}" "${expected_message}" >&2
    return 2
  fi
  return 0
}

# SELF-TEST, run before the corpus. The attribution grep is the whole point of
# the block above, and a grep replaced by a constant that never fires leaves
# this runner reporting the same "PASS rejected" lines forever. So it is
# exercised here against a deliberately WRONG expectation — a fixture both this
# runner and the policy reject, told to expect a message no rule emits — and the
# run aborts unless the attribution check is what refused it.
self_test_probe="${repo_root}/tests/kubernetes/fixtures/deny/pod-volume-undiscovered-source.yaml"
[[ -s "${self_test_probe}" ]] || { printf 'fixture-runner self-test probe is missing\n' >&2; exit 1; }
expected_message_override='no rule in this repository ever emits this sentence'
self_test_rc=0
expect_rejection "${self_test_probe}" >/dev/null 2>&1 || self_test_rc=$?
expected_message_override=''
if (( self_test_rc == 1 )); then
  printf 'FIXTURE RUNNER SELF-TEST FAILED: the probe %s is no longer rejected at all — the rule it pins has been weakened\n' \
    "$(basename -- "${self_test_probe}")" >&2
  exit 1
fi
if (( self_test_rc != 2 )); then
  printf 'FIXTURE RUNNER SELF-TEST FAILED: a wrong expected message was accepted — the attribution check is not checking\n' >&2
  exit 1
fi

# Allow fixtures detect over-broad rules; deny fixtures prove unsafe resources
# still stop the build instead of being accepted as ordinary test output.
for fixture in "${repo_root}"/tests/kubernetes/fixtures/allow/*.yaml; do
  conftest test --policy "${policy}" "${fixture}"
done
for fixture in "${repo_root}"/tests/kubernetes/fixtures/deny/*.yaml; do
  expect_rejection "${fixture}"
  printf 'PASS rejected %s\n' "${fixture}"
done
