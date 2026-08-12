#!/usr/bin/env bash
# Prove the canonical render is deterministic: two independent renders must
# produce byte-identical artifacts. Nondeterminism in rendered manifests would
# make every hash-bound review and the assurance ledger's evidence hashes
# unreproducible, so a mismatch fails closed with the exact differing files
# (never their contents, which could be lengthy).
#
# The render mode is read from the authoritative release state rather than
# pinned. Scaffold is only the authoritative mode while every release is still
# inert; once one site is promoted the renderer refuses --scaffold by design,
# so a hardcoded flag would report a release-state refusal as a determinism
# failure on every later pull request. Selecting the mode keeps this a
# determinism proof in every state and keeps it fail-closed: an unavailable or
# unrecognized mode stops the gate instead of silently falling back.
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

mode=''
mode="$(python3 -B "${repo_root}/scripts/validate_release_transition.py" select-mode)" ||
  die 'authoritative release transition mode is unavailable'
case "$mode" in
  scaffold|transition|release) ;;
  *) die "unsafe release transition mode: ${mode}" ;;
esac

first_pass="$(mktemp -d "${TMPDIR:-/tmp}/render-determinism-a.XXXXXX")"
second_pass="$(mktemp -d "${TMPDIR:-/tmp}/render-determinism-b.XXXXXX")"
cleanup() {
  rm -rf -- "$first_pass" "$second_pass"
}
trap cleanup EXIT

bash "${repo_root}/scripts/render-manifests.sh" "--${mode}" >/dev/null
snapshot "$first_pass"
bash "${repo_root}/scripts/render-manifests.sh" "--${mode}" >/dev/null
snapshot "$second_pass"

if ! diff -qr -- "$first_pass" "$second_pass" >/dev/null; then
  diff -qr -- "$first_pass" "$second_pass" | sed 's|/tmp/[^ ]*/||g' >&2 || true
  die "two ${mode} renders differ; rendered evidence is not reproducible"
fi
printf 'render-determinism: PASS two independent %s renders are byte-identical\n' "$mode"
