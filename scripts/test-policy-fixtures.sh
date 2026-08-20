#!/usr/bin/env bash
# Exercise Kubernetes admission policy with explicit positive and negative
# controls before those rules become part of the Flux reconciliation boundary.
#
# WHY A DENY FIXTURE IS ASSERTED BY REASON, NOT MERELY BY REJECTION
#
# A deny fixture is a multi-document file: several plausible widenings of the
# same reviewed contract, each of which must be refused. A file-level "conftest
# exited non-zero" assertion cannot tell a working deny arm from a neutered
# one: with several bypass documents in one file, deleting, disabling, or
# widening one rule still leaves the other documents failing the file, so the
# runner keeps printing PASS while a reviewed control is gone. That is not
# hypothetical -- it was reproduced on this repository twice. A one-token edit
# to the flux-system egress rule (`count(...) > 0` -> `> 999`) left every gate
# green while `allow-egress: egress: [{}]`, the cluster-wide allow-all posture
# the rule exists to forbid, was accepted again.
#
# A deny fixture therefore declares what it must be rejected FOR, in one of two
# reviewed forms, and this runner picks the stronger one the fixture supplies:
#
# 1. An `.expected` SIDECAR naming exactly the denial messages the file must
#    produce. The runner compares the whole set: a message that disappears is a
#    weakened rule, a message that appears is a denial nobody reviewed, and both
#    are failures that name the arm -- because the message names the rule and
#    the object that tripped it. This is the strongest form and the default for
#    new fixtures.
#
# 2. Inline `# expect-deny:` declarations, one per YAML document:
#
#        # expect-deny: NetworkPolicy flux-system/allow-egress must carry no egress rule
#
#    The runner requires the rejection to quote each declared reason, so a rule
#    that stops firing is a failure even when some other rule still rejects the
#    same bytes. The count must equal the document count, so a document cannot
#    quietly go unasserted.
#
# A fixture that declares NEITHER is refused. Until v0.1.5 it kept the older
# file-level assertion and said so in its PASS line: that was a MIGRATION
# affordance, not a tier -- fixtures predating the discipline kept passing while
# the incomplete migration stayed visible instead of assumed. The migration is
# finished (every deny fixture in the tree declares one of the two forms above),
# so the only thing the affordance can still do is admit the NEXT undeclared
# fixture, silently, as one PASS line among a hundred. The declaration is
# therefore a precondition, checked BEFORE conftest runs: an undeclared fixture
# fails for what it did not declare rather than for whatever the engine happened
# to print, and no engine verdict can route around the check.
#
# `expect_release_rejection` in scripts/render-manifests.sh is the same pattern
# on the release policy set; this is that discipline applied to deny fixtures.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
policy="${repo_root}/policies/conftest"

command -v conftest >/dev/null 2>&1 || { printf 'conftest is required\n' >&2; exit 2; }

# Every fixture is read by REDIRECTION rather than passed as a filename. `--`
# is not a portable option terminator: BSD `sed` treats it as a file, printing
# "sed: --: No such file or directory" and exiting non-zero -- and inside a
# process substitution that exit status is invisible, so the loop it feeds would
# silently iterate over nothing on one platform while working on another. A
# redirect has no such ambiguity and is hyphen-proof by construction.
#
# `---` at column 0 is a YAML document separator; kustomize and every fixture
# here use that form. Counting them bounds how many reasons a file must declare.
count_documents() {
  local separators=0
  separators="$(grep -cE '^---[[:space:]]*$' <"$1" || true)"
  printf '%s' "$((separators + 1))"
}

# Conftest is invoked with `--no-color`, but its output is stripped as well so
# the comparison is over messages rather than over presentation even if a future
# release colours a stream the flag does not cover.
strip_ansi() {
  sed -E $'s/\x1b\\[[0-9;]*m//g'
}

# The exact-set form: the fixture's reviewed `.expected` sidecar must name every
# denial the file produces, and no other.
assert_reviewed_denial_set() {
  local fixture="$1" expected_file="$2" output="$3"
  local actual='' expected=''

  actual="$(printf '%s\n' "$output" | strip_ansi |
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

# The per-document form: every declared reason must appear in the rejection, and
# exactly one reason must be declared per document.
assert_declared_denial_reasons() {
  local fixture="$1" expected_count="$2" output="$3"
  local documents='' expected=''

  documents="$(count_documents "${fixture}")"
  if ((expected_count != documents)); then
    printf 'deny fixture %s declares %s expect-deny reason(s) for %s document(s); declare exactly one per document\n' \
      "${fixture}" "${expected_count}" "${documents}" >&2
    exit 1
  fi
  while IFS= read -r expected; do
    [[ -n "${expected}" ]] || continue
    if ! grep -Fq -- "${expected}" <<<"${output}"; then
      printf '%s\n' "${output}" >&2
      printf 'deny fixture %s was rejected, but not for the declared reason: %s\n' \
        "${fixture}" "${expected}" >&2
      exit 1
    fi
  done < <(sed -n 's/^#[[:space:]]*expect-deny:[[:space:]]*//p' <"${fixture}")
  printf 'PASS rejected %s (%s declared reason(s) proven)\n' "${fixture}" "${expected_count}"
}

expect_fixture_denials() {
  local fixture="$1"
  local expected_file="${fixture%.yaml}.expected"
  local output='' expected_count=0

  # The precondition, established before the engine is consulted: a fixture
  # that names no reviewed denial cannot be asserted by reason at all, so it is
  # refused here rather than downgraded to a file-level PASS.
  expected_count="$(grep -cE '^#[[:space:]]*expect-deny:' <"${fixture}" || true)"
  if [[ ! -f "$expected_file" ]] && ((expected_count == 0)); then
    printf 'deny fixture declares no reviewed denial mechanism: %s\n' "${fixture}" >&2
    printf 'add a reviewed %s naming every denial message the file must produce, or one "# expect-deny:" line per YAML document\n' \
      "${expected_file##*/}" >&2
    exit 1
  fi

  if output="$(conftest test --no-color --policy "${policy}" "${fixture}" 2>&1)"; then
    printf 'deny fixture unexpectedly passed: %s\n' "${fixture}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi

  if [[ -f "$expected_file" ]]; then
    assert_reviewed_denial_set "${fixture}" "${expected_file}" "${output}"
    return 0
  fi

  assert_declared_denial_reasons "${fixture}" "${expected_count}" "${output}"
}

# Allow fixtures detect over-broad rules; deny fixtures prove unsafe resources
# still stop the build instead of being accepted as ordinary test output.
for fixture in "${repo_root}"/tests/kubernetes/fixtures/allow/*.yaml; do
  conftest test --policy "${policy}" "${fixture}"
done
for fixture in "${repo_root}"/tests/kubernetes/fixtures/deny/*.yaml; do
  expect_fixture_denials "$fixture"
done
