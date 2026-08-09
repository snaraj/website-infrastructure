#!/usr/bin/env bash
# Prove that one site's multi-platform OCI graph contains two distinct
# production images, then scan and inventory those exact views before push.
set -euo pipefail
umask 077

: "${OCI_ARCHIVE:?Set OCI_ARCHIVE to the final multi-platform OCI layout archive}"
: "${EXPECTED_DIGEST:?Set EXPECTED_DIGEST to the final sha256 index digest}"
: "${EVIDENCE_DIR:?Set EVIDENCE_DIR to a private temporary output directory}"
: "${ARTIFACT_NAME:?Set ARTIFACT_NAME to the canonical site slug}"
: "${MAX_APPLICATION_LAYER_BYTES:?Set the reviewed final application-layer ceiling}"

[[ -f "${OCI_ARCHIVE}" ]] || { printf 'OCI archive is missing: %s\n' "${OCI_ARCHIVE}" >&2; exit 2; }
[[ "${EXPECTED_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'EXPECTED_DIGEST is malformed\n' >&2; exit 2; }
[[ "${ARTIFACT_NAME}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || {
  printf 'ARTIFACT_NAME must be one safe lowercase release slug\n' >&2
  exit 2
}
[[ "${MAX_APPLICATION_LAYER_BYTES}" =~ ^[1-9][0-9]*$ ]] || {
  printf 'MAX_APPLICATION_LAYER_BYTES must be one positive integer\n' >&2
  exit 2
}
for command_name in oras trivy syft jq; do
  command -v "${command_name}" >/dev/null 2>&1 || { printf '%s is required\n' "${command_name}" >&2; exit 2; }
done

mkdir -p -- "${EVIDENCE_DIR}"
# Separate OCI layouts prevent a scanner's default-platform behavior from
# making both commands inspect the same child manifest while appearing distinct.
amd64_layout="${EVIDENCE_DIR}/${ARTIFACT_NAME}-amd64.oci"
arm64_layout="${EVIDENCE_DIR}/${ARTIFACT_NAME}-arm64.oci"
for target in "${amd64_layout}" "${arm64_layout}"; do
  [[ ! -e "${target}" ]] || { printf 'refusing to reuse OCI evidence target: %s\n' "${target}" >&2; exit 2; }
done

resolved="$(oras resolve --oci-layout "${OCI_ARCHIVE}@${EXPECTED_DIGEST}")"
[[ "${resolved}" == "${EXPECTED_DIGEST}" ]] || {
  printf 'OCI archive does not resolve to the expected index digest\n' >&2
  exit 1
}

oras cp --no-tty --from-oci-layout --to-oci-layout --platform linux/amd64 \
  "${OCI_ARCHIVE}@${EXPECTED_DIGEST}" "${amd64_layout}:scan"
oras cp --no-tty --from-oci-layout --to-oci-layout --platform linux/arm64 \
  "${OCI_ARCHIVE}@${EXPECTED_DIGEST}" "${arm64_layout}:scan"

# The copied configs are independent evidence that ORAS selected the requested
# children; scanning begins only after both declared platforms are exact.
amd64_platform="$(
  oras manifest fetch-config --oci-layout "${amd64_layout}:scan" |
    jq -er '.os + "/" + .architecture'
)"
arm64_platform="$(
  oras manifest fetch-config --oci-layout "${arm64_layout}:scan" |
    jq -er '.os + "/" + .architecture'
)"
[[ "${amd64_platform}" == linux/amd64 ]] || { printf 'amd64 view resolved to %s\n' "${amd64_platform}" >&2; exit 1; }
[[ "${arm64_platform}" == linux/arm64 ]] || { printf 'arm64 view resolved to %s\n' "${arm64_platform}" >&2; exit 1; }
[[ "${amd64_platform}" != "${arm64_platform}" ]] || { printf 'platform views are not distinct\n' >&2; exit 1; }

# The runtime Dockerfiles add only one site binary above the reviewed base. A
# tight last-layer ceiling therefore catches split or renamed embedded media
# even when file extensions and source-level checks are evaded.
read -r amd64_app_digest amd64_app_size < <(
  oras manifest fetch --oci-layout "${amd64_layout}:scan" |
    jq -er '[.layers[-1].digest, (.layers[-1].size | tostring)] | @tsv'
)
read -r arm64_app_digest arm64_app_size < <(
  oras manifest fetch --oci-layout "${arm64_layout}:scan" |
    jq -er '[.layers[-1].digest, (.layers[-1].size | tostring)] | @tsv'
)
for value in "${amd64_app_size}" "${arm64_app_size}"; do
  [[ "${value}" =~ ^[1-9][0-9]*$ ]] || { printf 'application layer size is malformed\n' >&2; exit 1; }
  (( value <= MAX_APPLICATION_LAYER_BYTES )) || {
    printf 'application layer exceeds the reviewed byte ceiling\n' >&2
    exit 1
  }
done
[[ "${amd64_app_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'amd64 application layer digest is malformed\n' >&2; exit 1; }
[[ "${arm64_app_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'arm64 application layer digest is malformed\n' >&2; exit 1; }
[[ "${amd64_app_digest}" != "${arm64_app_digest}" ]] || { printf 'platform application layers are not distinct\n' >&2; exit 1; }

trivy image --input "${amd64_layout}:scan" \
  --exit-code 1 --ignore-unfixed --severity HIGH,CRITICAL
trivy image --input "${arm64_layout}:scan" \
  --exit-code 1 --ignore-unfixed --severity HIGH,CRITICAL

# Syft receives the same single-platform layouts already selected and proven
# above. Re-discovering a platform from the original BuildKit archive is
# ambiguous once its image index also carries SBOM/provenance descriptors.
# Keeping one evidence source per platform binds the inventory to the exact
# child that Trivy scanned and that the application-layer checks inspected.
syft "oci-dir:${amd64_layout}" \
  -o "spdx-json=${EVIDENCE_DIR}/${ARTIFACT_NAME}-amd64.spdx.json"
syft "oci-dir:${arm64_layout}" \
  -o "spdx-json=${EVIDENCE_DIR}/${ARTIFACT_NAME}-arm64.spdx.json"

printf 'Verified and scanned distinct linux/amd64 and linux/arm64 views of %s.\n' \
  "${EXPECTED_DIGEST}"
