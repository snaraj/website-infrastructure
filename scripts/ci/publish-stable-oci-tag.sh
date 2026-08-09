#!/usr/bin/env bash
# Publish the human-readable SemVer tag only after the immutable digest has
# been signed and attested. OCI Distribution has no client-side compare-and-
# swap for tags, so registry-enforced tag immutability remains the final race
# boundary; every observable resolution error here otherwise fails closed.
set -euo pipefail

: "${EXPECTED_DIGEST:?Set EXPECTED_DIGEST to the signed sha256 image digest}"
: "${IMAGE:?Set IMAGE to the canonical ghcr.io owner/repository name}"
: "${GITHUB_SHA:?GITHUB_SHA must identify the release commit}"
: "${RELEASE_TAG:?Set RELEASE_TAG to the validated stable SemVer tag}"
: "${STABLE_TAG_VERIFY_ROOT:?Set STABLE_TAG_VERIFY_ROOT to a new temporary directory}"

[[ "${EXPECTED_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  printf 'EXPECTED_DIGEST is malformed\n' >&2
  exit 2
}
[[ "${IMAGE}" =~ ^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$ ]] || {
  printf 'IMAGE must be one canonical lowercase GHCR repository\n' >&2
  exit 2
}
[[ "${GITHUB_SHA}" =~ ^[0-9a-f]{40}$ ]] || {
  printf 'GITHUB_SHA is malformed\n' >&2
  exit 2
}
[[ "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  printf 'RELEASE_TAG is not a canonical stable SemVer tag\n' >&2
  exit 2
}
command -v oras >/dev/null 2>&1 || {
  printf 'oras is required\n' >&2
  exit 2
}
[[ ! -e "${STABLE_TAG_VERIFY_ROOT}" ]] || {
  printf 'STABLE_TAG_VERIFY_ROOT must not already exist\n' >&2
  exit 2
}
mkdir -- "${STABLE_TAG_VERIFY_ROOT}"

stable_reference="${IMAGE}:${RELEASE_TAG}"
resolve_error="${STABLE_TAG_VERIFY_ROOT}/stable-resolve.error"
: >"${resolve_error}"
if resolved_digest="$(oras resolve "${stable_reference}" 2>"${resolve_error}")"; then
  [[ "${resolved_digest}" == "${EXPECTED_DIGEST}" ]] || {
    printf 'refusing to reassign immutable tag %s\n' "${RELEASE_TAG}" >&2
    exit 1
  }
elif grep -Eqi \
  'MANIFEST_UNKNOWN|manifest unknown|NAME_UNKNOWN|name unknown' \
  "${resolve_error}"; then
  oras tag "${IMAGE}@${EXPECTED_DIGEST}" "${RELEASE_TAG}"
else
  sed -n '1,20p' "${resolve_error}" >&2
  printf 'could not prove stable tag absence for %s\n' "${RELEASE_TAG}" >&2
  exit 1
fi

[[ "$(oras resolve "${IMAGE}:sha-${GITHUB_SHA}")" == "${EXPECTED_DIGEST}" ]] || {
  printf 'immutable commit tag no longer resolves to the signed digest\n' >&2
  exit 1
}
[[ "$(oras resolve "${stable_reference}")" == "${EXPECTED_DIGEST}" ]] || {
  printf 'stable release tag does not resolve to the signed digest\n' >&2
  exit 1
}
printf 'Verified immutable stable tag %s at %s.\n' \
  "${RELEASE_TAG}" "${EXPECTED_DIGEST}"
