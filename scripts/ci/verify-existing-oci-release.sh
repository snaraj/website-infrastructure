#!/usr/bin/env bash
# Read-only manual verification for one already-published immutable release.
set -euo pipefail
umask 077

: "${IMAGE:?Set IMAGE to the canonical GHCR repository}"
: "${RELEASE_TAG:?Set RELEASE_TAG to the exact stable SemVer tag}"
: "${GITHUB_SHA:?GITHUB_SHA must identify the selected main commit}"
: "${WORKFLOW_IDENTITY:?Set the exact keyless workflow identity}"
: "${VERIFY_ERROR_ROOT:?Set VERIFY_ERROR_ROOT to a new private temporary directory}"

[[ "${IMAGE}" =~ ^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$ ]] || {
  printf 'IMAGE is not one canonical lowercase GHCR repository\n' >&2
  exit 2
}
[[ "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  printf 'RELEASE_TAG is not one stable SemVer tag\n' >&2
  exit 2
}
[[ "${GITHUB_SHA}" =~ ^[0-9a-f]{40}$ ]] || {
  printf 'GITHUB_SHA is not one full Git commit\n' >&2
  exit 2
}
# Site releases are published by each standalone repository under immutable
# version tags, but the SIGNING identity is the publisher run itself, which is
# a workflow_dispatch selected from that repository's protected `main` branch.
# The trust boundary is therefore that exact branch-ref publisher: a run at a
# ref executes the definition at that ref, and `main` is the only ref those
# repositories gate on creation and update with no bypass actors, whereas tag
# creation there is unrestricted (ADR 0016 amendment 2026-08-22). RELEASE_TAG
# above still pins WHICH release is being verified.
[[ "${WORKFLOW_IDENTITY}" =~ ^https://github\.com/snaraj/(naranjo\.online|lidersea\.com)/\.github/workflows/release-publisher\.yml@refs/heads/main$ ]] || {
  printf 'WORKFLOW_IDENTITY is outside the protected-main publisher trust boundary\n' >&2
  exit 2
}
for command_name in cosign oras; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf '%s is required\n' "${command_name}" >&2
    exit 2
  }
done
[[ ! -e "${VERIFY_ERROR_ROOT}" ]] || {
  printf 'VERIFY_ERROR_ROOT must not already exist\n' >&2
  exit 2
}
mkdir -- "${VERIFY_ERROR_ROOT}"

resolve_required() {
  local reference="$1"
  local label="$2"
  local error_path="${VERIFY_ERROR_ROOT}/${label}.error"
  local digest
  if ! digest="$(oras resolve "${reference}" 2>"${error_path}")"; then
    sed -n '1,20p' "${error_path}" >&2
    printf 'required immutable reference is unavailable: %s\n' "${label}" >&2
    return 1
  fi
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf 'required immutable reference returned a malformed digest: %s\n' \
      "${label}" >&2
    return 1
  }
  printf '%s\n' "${digest}"
}

sha_digest="$(resolve_required "${IMAGE}:sha-${GITHUB_SHA}" sha-tag)"
version_digest="$(resolve_required "${IMAGE}:${RELEASE_TAG}" version-tag)"
[[ "${sha_digest}" == "${version_digest}" ]] || {
  printf 'full-SHA and stable release tags do not identify the same digest\n' >&2
  exit 1
}

cosign verify \
  --certificate-identity "${WORKFLOW_IDENTITY}" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${IMAGE}@${sha_digest}" >/dev/null

printf 'Read-only verification passed for %s at %s (%s).\n' \
  "${RELEASE_TAG}" "${sha_digest}" "${GITHUB_SHA}"
