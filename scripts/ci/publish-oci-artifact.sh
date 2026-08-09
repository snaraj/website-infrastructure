#!/usr/bin/env bash
# Publish one already-verified OCI layout without rebuilding or changing its
# digest. Content-addressed retries are safe: incomplete attempts can leave
# untagged blobs in GHCR, while the reviewed tag is accepted only after its
# complete graph resolves to the exact digest produced and scanned by Buildx.
set -euo pipefail

: "${OCI_ARCHIVE:?Set OCI_ARCHIVE to the verified multi-platform OCI layout archive}"
: "${EXPECTED_DIGEST:?Set EXPECTED_DIGEST to the verified sha256 index digest}"
: "${IMAGE:?Set IMAGE to the canonical ghcr.io owner/repository name}"
: "${GITHUB_SHA:?GITHUB_SHA must identify the release commit}"
: "${PUBLISH_VERIFY_ROOT:?Set PUBLISH_VERIFY_ROOT to a new temporary verification directory}"

[[ -f "${OCI_ARCHIVE}" ]] || { printf 'OCI archive is missing: %s\n' "${OCI_ARCHIVE}" >&2; exit 2; }
[[ "${EXPECTED_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'EXPECTED_DIGEST is malformed\n' >&2; exit 2; }
[[ "${IMAGE}" =~ ^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$ ]] || {
  printf 'IMAGE must be one canonical lowercase GHCR repository\n' >&2
  exit 2
}
[[ "${GITHUB_SHA}" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || {
  printf 'GITHUB_SHA is malformed\n' >&2
  exit 2
}
for command_name in jq oras; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf '%s is required\n' "${command_name}" >&2
    exit 2
  }
done
[[ ! -e "${PUBLISH_VERIFY_ROOT}" ]] || {
  printf 'PUBLISH_VERIFY_ROOT must not already exist\n' >&2
  exit 2
}
mkdir -- "${PUBLISH_VERIFY_ROOT}"

# Re-resolving the local source immediately before publication prevents a bad
# path or stale environment value from turning the retry loop into a different
# release than the artifact that passed scanning.
source_reference="${OCI_ARCHIVE}@${EXPECTED_DIGEST}"
source_digest="$(oras resolve --oci-layout "${source_reference}")"
[[ "${source_digest}" == "${EXPECTED_DIGEST}" ]] || {
  printf 'OCI archive does not resolve to the expected index digest\n' >&2
  exit 1
}
readonly image_index_media_type="application/vnd.oci.image.index.v1+json"
source_media_type="$(
  oras manifest fetch --oci-layout "${source_reference}" |
    jq -er '.mediaType'
)"
[[ "${source_media_type}" == "${image_index_media_type}" ]] || {
  printf 'OCI archive root is %s, not an OCI image index\n' \
    "${source_media_type:-unknown}" >&2
  exit 1
}

destination_reference="${IMAGE}:sha-${GITHUB_SHA}"
readonly max_attempts=4
readonly base_delay_seconds="${PUBLISH_RETRY_DELAY_SECONDS:-5}"
[[ "${base_delay_seconds}" =~ ^[0-9]+$ ]] || {
  printf 'PUBLISH_RETRY_DELAY_SECONDS must be a non-negative integer\n' >&2
  exit 2
}

# GHCR can briefly report a just-uploaded child manifest as missing when ORAS
# publishes a nested multi-platform graph with provenance and SBOM manifests.
# Serial copy reduces that visibility race; bounded whole-graph retries finish
# safely because every blob and manifest is addressed by its immutable digest.
for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  if oras cp --no-tty --concurrency 1 --from-oci-layout \
    "${source_reference}" "${destination_reference}"; then
    resolved=""
    if resolved="$(oras resolve "${destination_reference}")" &&
      [[ "${resolved}" == "${EXPECTED_DIGEST}" ]]; then
      # A fresh layout per attempt prevents a partial earlier download from
      # masking a still-missing child manifest in the remote registry graph.
      roundtrip_layout="${PUBLISH_VERIFY_ROOT}/attempt-${attempt}.oci"
      if oras cp --no-tty --concurrency 1 --to-oci-layout \
        "${IMAGE}@${EXPECTED_DIGEST}" "${roundtrip_layout}:verified"; then
        roundtrip_digest=""
        if roundtrip_digest="$(oras resolve --oci-layout "${roundtrip_layout}:verified")" &&
          roundtrip_media_type="$(
            oras manifest fetch --oci-layout "${roundtrip_layout}:verified" |
              jq -er '.mediaType'
          )" &&
          [[ "${roundtrip_digest}" == "${EXPECTED_DIGEST}" ]] &&
          [[ "${roundtrip_media_type}" == "${image_index_media_type}" ]]; then
          printf 'Published and round-trip verified %s at %s.\n' \
            "${destination_reference}" "${EXPECTED_DIGEST}"
          exit 0
        fi
        printf 'Publish attempt %d round trip returned digest %s and media type %s.\n' \
          "${attempt}" "${roundtrip_digest:-unavailable}" \
          "${roundtrip_media_type:-unavailable}" >&2
      else
        printf 'Publish attempt %d could not fetch the complete remote OCI graph.\n' \
          "${attempt}" >&2
      fi
    else
      printf 'Publish attempt %d resolved to %s instead of %s.\n' \
        "${attempt}" "${resolved:-unavailable}" "${EXPECTED_DIGEST}" >&2
    fi
  else
    printf 'Publish attempt %d could not copy the complete OCI graph.\n' \
      "${attempt}" >&2
  fi

  if (( attempt < max_attempts )); then
    delay_seconds=$((attempt * base_delay_seconds))
    printf 'Retrying the same content-addressed graph in %d seconds.\n' \
      "${delay_seconds}" >&2
    sleep "${delay_seconds}"
  fi
done

printf 'OCI graph did not publish and resolve exactly after %d attempts.\n' \
  "${max_attempts}" >&2
exit 1
