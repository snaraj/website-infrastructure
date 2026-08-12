#!/usr/bin/env bash
# Exercise Kubernetes admission policy with explicit positive and negative
# controls before those rules become part of the Flux reconciliation boundary.
#
# Deny fixtures are asserted by REASON, not merely by rejection. A file-level
# "conftest exited non-zero" assertion cannot tell a working deny arm from a
# neutered one: with several bypass documents in one file, deleting or
# disabling one rule still leaves the other documents failing the file, so the
# runner keeps printing PASS while a reviewed control is gone. That is not
# hypothetical -- on this repository a one-token edit to the flux-system
# egress rule (`count(...) > 0` -> `> 999`) left every gate green while
# `allow-egress: egress: [{}]`, the cluster-wide allow-all posture the rule
# exists to forbid, was accepted again.
#
# So a deny fixture declares what it must be rejected FOR:
#
#     # expect-deny: NetworkPolicy flux-system/allow-egress must carry no egress rule
#
# One such line per YAML document in the file. The runner then requires the
# rejection to quote each declared reason, so a rule that stops firing is a
# failure even when some other rule still rejects the same bytes. Fixtures that
# declare nothing keep the older file-level assertion and say so in their PASS
# line, which is what makes the weaker mode visible rather than assumed.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
policy="${repo_root}/policies/conftest"

command -v conftest >/dev/null 2>&1 || { printf 'conftest is required\n' >&2; exit 2; }

# `---` at column 0 is a YAML document separator; kustomize and every fixture
# here use that form. Counting them bounds how many reasons a file must declare.
count_documents() {
  local separators=0
  separators="$(grep -cE '^---[[:space:]]*$' -- "$1" || true)"
  printf '%s' "$((separators + 1))"
}

# Allow fixtures detect over-broad rules; deny fixtures prove unsafe resources
# still stop the build instead of being accepted as ordinary test output.
for fixture in "${repo_root}"/tests/kubernetes/fixtures/allow/*.yaml; do
  conftest test --policy "${policy}" "${fixture}"
done
for fixture in "${repo_root}"/tests/kubernetes/fixtures/deny/*.yaml; do
  output=''
  if output="$(conftest test --no-color --policy "${policy}" "${fixture}" 2>&1)"; then
    printf 'deny fixture unexpectedly passed: %s\n' "${fixture}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  expected_count=0
  expected_count="$(grep -cE '^#[[:space:]]*expect-deny:' -- "${fixture}" || true)"
  if ((expected_count == 0)); then
    printf 'PASS rejected (file-level only, no expect-deny declared) %s\n' "${fixture}"
    continue
  fi
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
  done < <(sed -n 's/^#[[:space:]]*expect-deny:[[:space:]]*//p' -- "${fixture}")
  printf 'PASS rejected %s (%s declared reason(s) proven)\n' "${fixture}" "${expected_count}"
done
