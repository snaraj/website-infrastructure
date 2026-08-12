#!/usr/bin/env bash
# Differential harness for the two engines that express the storage-exposure
# gate: the Kyverno ClusterPolicy (admission) and its Conftest/Rego mirror (CI).
#
# WHY THIS EXISTS. The structural battery in
# tests/security/test_storage_exposure_policy_contract.py proves the two files
# AGREE IN TEXT — same enumerations, same rule identifiers, same covered kinds.
# Text agreement is not behaviour agreement. Rego's object.get raises a builtin
# type error on a degenerate value (null, a scalar, a list), and under OPA's
# default non-strict handling the surrounding expression is UNDEFINED, so the
# deny rule silently does not fire; CEL raises on the same shapes and the
# webhook's failurePolicy: Fail turns that into a denial. On this policy that
# produced nine divergences, eight of them fail-open in the engine that is the
# only gate running today (wi #96 adversarial review, 2026-08-12) — with every
# committed check green, because nothing ever fed the same object to both
# engines and compared the answers.
#
# WHAT IT CHECKS, per object file:
#   1. the Conftest verdict matches the EXPECTED verdict, which is the fixture's
#      directory (allow/ admits, deny/ denies) — so the harness cannot go green
#      by both engines drifting together;
#   2. the Kyverno verdict matches the expected verdict;
#   3. therefore the two engines match each other;
#   4. Kyverno actually EVALUATED the object — a storage object that yields no
#      pass, fail or error row was never reached by the policy, and a `skip` row
#      is worse: `kyverno test` counts Skip as a PASS, so a match block narrowed
#      by namespace, name, or a userInfo field (clusterRoles/roles/subjects)
#      leaves the behavioural suite entirely green while the policy matches
#      nobody;
#   5. the denial came from the RULE THE FIXTURE CLAIMS. Each deny fixture
#      declares the message fragment its rule emits, in a `# rego-message:`
#      header, and this harness requires that fragment in the Conftest output.
#      Without it a per-rule mutation is invisible whenever any OTHER rule also
#      denies the object: neutralizing the SR-0 arm left every gate green,
#      because its fixture also fails SR-1 and SR-7 and the runners only assert
#      that the FILE is rejected.
#
# SCOPE. Storage kinds only. The Kyverno policy's Pod rules are deliberately
# namespace-scoped while the Conftest mirror's pod-volume rules are repo-wide, so
# Pods are not a parity surface and are not claimed as one.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
policy_dir="${repo_root}/policies/conftest"
kyverno_policy="${repo_root}/policies/kyverno/disallow-undiscovered-storage.yaml"

# A corpus that shrinks is a harness that proves less while still reporting
# success, so the floor is pinned here and the count is printed as evidence.
# tests/security/test_storage_exposure_policy_contract.py holds the same floor
# and the required degenerate shapes, so neither the corpus nor this number can
# be trimmed quietly.
minimum_deny_objects=30

for tool in conftest kyverno; do
  command -v "${tool}" >/dev/null 2>&1 || { printf '%s is required\n' "${tool}" >&2; exit 2; }
done

failures=0
checked=0

# Every divergence reason is recorded as well as counted, because the self-test
# below has to prove WHICH comparison fired, not merely that something did.
divergence_reasons=''

# The three reasons the self-test asserts on, held as constants so the self-test
# cannot pass by matching a reason string that has since been reworded.
reason_conftest='the Conftest mirror disagreed with the fixture directory'
reason_kyverno='the Kyverno policy disagreed with the fixture directory'
reason_attribution='the Conftest mirror never emitted the claimed denial'

# Set ONLY by the self-test below, so the attribution grep can be exercised
# against a message no rule emits without editing a committed fixture.
expected_message_override=''

report_divergence() {
  printf 'PARITY FAILURE %s: expected=%s conftest=%s kyverno=%s (%s)\n' \
    "$1" "$2" "$3" "$4" "$5" >&2
  failures=$((failures + 1))
  divergence_reasons="${divergence_reasons}$5"$'\n'
}

check_object() {
  local fixture="$1" expected="$2" name conftest_verdict conftest_output kyverno_output kyverno_verdict
  local pass fail error skip expected_message
  name="$(basename -- "${fixture}")"

  if conftest_output="$(conftest test --policy "${policy_dir}" "${fixture}" 2>&1)"; then
    conftest_verdict='allow'
  else
    conftest_verdict='deny'
  fi

  # The claimed rule must be the rule that fired. A fixture with no declared
  # message is a fixture whose rule cannot be mutation-tested, so its absence is
  # a failure rather than a skip.
  if [[ "${expected}" == 'deny' ]]; then
    if [[ -n "${expected_message_override}" ]]; then
      expected_message="${expected_message_override}"
    else
      expected_message="$(sed -n 's/^# rego-message: //p' "${fixture}" | head -n 1)"
    fi
    if [[ -z "${expected_message}" ]]; then
      printf 'PARITY FAILURE %s: deny fixture declares no rego-message header to attribute its denial to\n' \
        "${name}" >&2
      failures=$((failures + 1))
      return
    fi
    if ! grep -Fq -- "${expected_message}" <<<"${conftest_output}"; then
      printf '%s\n' "${conftest_output}" >&2
      report_divergence "${name}" "${expected}" "${conftest_verdict}" 'n/a' \
        "${reason_attribution}: ${expected_message}"
      return
    fi
  fi

  # kyverno apply exits non-zero whenever a resource fails a rule, which is the
  # expected outcome for most of this corpus; the verdict is read from the
  # summary line instead, and a missing summary is itself a hard failure below.
  kyverno_output="$(kyverno apply "${kyverno_policy}" --resource "${fixture}" 2>&1 || true)"
  # kyverno apply's summary line is "pass: N, fail: N, warn: N, error: N, skip: N".
  pass="$(sed -n 's/.*pass: \([0-9][0-9]*\).*/\1/p' <<<"${kyverno_output}" | tail -n 1)"
  fail="$(sed -n 's/.*fail: \([0-9][0-9]*\).*/\1/p' <<<"${kyverno_output}" | tail -n 1)"
  error="$(sed -n 's/.*error: \([0-9][0-9]*\).*/\1/p' <<<"${kyverno_output}" | tail -n 1)"
  skip="$(sed -n 's/.*skip: \([0-9][0-9]*\).*/\1/p' <<<"${kyverno_output}" | tail -n 1)"
  if [[ -z "${pass}" || -z "${fail}" || -z "${error}" || -z "${skip}" ]]; then
    printf '%s\n' "${kyverno_output}" >&2
    printf 'PARITY FAILURE %s: kyverno apply produced no verdict summary\n' "${name}" >&2
    failures=$((failures + 1))
    return
  fi

  if (( skip > 0 )); then
    report_divergence "${name}" "${expected}" "${conftest_verdict}" 'skip' \
      'the policy SKIPPED a storage object: match-block or userInfo narrowing'
    return
  fi
  if (( pass + fail + error == 0 )); then
    report_divergence "${name}" "${expected}" "${conftest_verdict}" 'unevaluated' \
      'the policy never reached this storage object'
    return
  fi

  if (( fail > 0 || error > 0 )); then
    kyverno_verdict='deny'
  else
    kyverno_verdict='allow'
  fi

  checked=$((checked + 1))
  # ONE comparison PER ENGINE, deliberately not a single disjunction. A single
  # `if A || B` is satisfied by either half, so a self-test probe that makes both
  # halves true cannot tell a working comparison from one that lost a half:
  # dropping either disjunct left the harness PASSING and the self-test green
  # (measured, wi #96 delta review). Two statements with distinct reasons make
  # each half separately observable, and the self-test below requires BOTH.
  if [[ "${conftest_verdict}" != "${expected}" ]]; then
    report_divergence "${name}" "${expected}" "${conftest_verdict}" "${kyverno_verdict}" \
      "${reason_conftest}"
  fi
  if [[ "${kyverno_verdict}" != "${expected}" ]]; then
    report_divergence "${name}" "${expected}" "${conftest_verdict}" "${kyverno_verdict}" \
      "${reason_kyverno}"
  fi
}

# SELF-TEST, run before the corpus. The verdict comparison and the message
# attribution ARE this harness, and a harness that compares nothing reports
# success forever: neutering the comparison left it green on a corpus containing
# a real engine divergence (mutant M19, measured on this file), and the
# attribution grep had no killer at all until this round. Both are therefore
# exercised here against deliberately WRONG expectations, and the run aborts
# unless each one is what refused the probe. The counters are restored afterwards
# so the probes cannot colour the real result either way.
self_test_probe="${repo_root}/tests/kubernetes/fixtures/deny/storage-nfs-persistent-volume.yaml"
[[ -s "${self_test_probe}" ]] || { printf 'parity self-test probe is missing\n' >&2; exit 1; }

self_test() {
  # Runs one probe and leaves the reported reasons in `self_test_reasons` and
  # the divergence count in `self_test_delta`, with every counter restored.
  local expected="$1" checked_before="${checked}" failures_before="${failures}"
  divergence_reasons=''
  check_object "${self_test_probe}" "${expected}" 2>/dev/null
  self_test_delta=$((failures - failures_before))
  self_test_reasons="${divergence_reasons}"
  failures="${failures_before}"
  checked="${checked_before}"
  divergence_reasons=''
}

self_test_requires() {
  grep -Fq -- "$1" <<<"${self_test_reasons}" || {
    printf 'PARITY HARNESS SELF-TEST FAILED: a deliberately wrong expectation never produced "%s" — that half of the harness is not checking\n' \
      "$1" >&2
    exit 1
  }
}

# Probe 1 — the verdict comparison, one half at a time. The probe is an object
# both engines deny, declared `allow`, so BOTH per-engine comparisons must fire.
self_test 'allow'
if (( self_test_delta != 2 )); then
  printf 'PARITY HARNESS SELF-TEST FAILED: a wrong expected verdict produced %d divergences, not 2 — a per-engine comparison is missing\n' \
    "${self_test_delta}" >&2
  exit 1
fi
self_test_requires "${reason_conftest}"
self_test_requires "${reason_kyverno}"

# Probe 2 — the message attribution. The same object, correctly declared `deny`,
# told to expect a message no rule in this repository emits: the attribution
# check must be the thing that refuses it, and nothing else may.
expected_message_override='no rule in this repository ever emits this sentence'
self_test 'deny'
expected_message_override=''
if (( self_test_delta != 1 )); then
  printf 'PARITY HARNESS SELF-TEST FAILED: a wrong expected message produced %d divergences, not 1 — the attribution check is not checking\n' \
    "${self_test_delta}" >&2
  exit 1
fi
self_test_requires "${reason_attribution}"

deny_objects=0
for fixture in "${repo_root}"/tests/kubernetes/fixtures/deny/storage-*.yaml; do
  deny_objects=$((deny_objects + 1))
  check_object "${fixture}" 'deny'
done

allow_objects=0
for fixture in "${repo_root}"/tests/kubernetes/fixtures/allow/storage-*.yaml; do
  allow_objects=$((allow_objects + 1))
  check_object "${fixture}" 'allow'
done

if (( deny_objects < minimum_deny_objects )); then
  printf 'storage parity corpus shrank: %d deny fixtures, floor is %d\n' \
    "${deny_objects}" "${minimum_deny_objects}" >&2
  exit 1
fi
if (( allow_objects < 1 )); then
  printf 'storage parity corpus carries no admissible shape, so "deny" proves nothing\n' >&2
  exit 1
fi
if (( checked != deny_objects + allow_objects )); then
  printf 'storage parity harness compared %d of %d objects\n' \
    "${checked}" "$((deny_objects + allow_objects))" >&2
  exit 1
fi
if (( failures > 0 )); then
  printf '%d storage engine-parity failure(s)\n' "${failures}" >&2
  exit 1
fi

printf 'PASS storage engine parity: %d deny + %d allow object(s), both engines agreed with the expected verdict on every one\n' \
  "${deny_objects}" "${allow_objects}"
