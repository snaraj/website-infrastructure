#!/usr/bin/env bash
# Prove the canonical render is deterministic: two independent scaffold
# renders must produce byte-identical artifacts. Nondeterminism in rendered
# manifests would make every hash-bound review and the assurance ledger's
# evidence hashes unreproducible, so a mismatch fails closed with the exact
# differing files (never their contents, which could be lengthy).
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
artifact_root="${repo_root}/.artifacts/rendered"

die() {
  printf 'render-determinism: NO-GO: %s\n' "$*" >&2
  exit 1
}

snapshot() {
  local destination="$1"
  rm -rf -- "$destination"
  mkdir -p -- "$destination"
  cp -R -- "${artifact_root}/." "$destination/"
}

first_pass="$(mktemp -d "${TMPDIR:-/tmp}/render-determinism-a.XXXXXX")"
second_pass="$(mktemp -d "${TMPDIR:-/tmp}/render-determinism-b.XXXXXX")"
cleanup() {
  rm -rf -- "$first_pass" "$second_pass"
}
trap cleanup EXIT

bash "${repo_root}/scripts/render-manifests.sh" --scaffold >/dev/null
snapshot "$first_pass"
bash "${repo_root}/scripts/render-manifests.sh" --scaffold >/dev/null
snapshot "$second_pass"

if ! diff -qr -- "$first_pass" "$second_pass" >/dev/null; then
  diff -qr -- "$first_pass" "$second_pass" | sed 's|/tmp/[^ ]*/||g' >&2 || true
  die 'two scaffold renders differ; rendered evidence is not reproducible'
fi
printf 'render-determinism: PASS two independent scaffold renders are byte-identical\n'
