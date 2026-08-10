#!/usr/bin/env bash
# Verify one site's published multi-architecture image and create a bounded
# review patch for its immutable Flux override. The live worktree is never
# changed, staged, committed, pushed, or deployed by this command.
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# The exact site selector expands to one closed identity tuple. Sharing the
# verifier removes drift, while each tuple retains its own image, workflow,
# values file, Helm release, namespace, and rollback decision.
usage() {
  printf 'Usage: %s {naranjo-online|lidersea-com} vMAJOR.MINOR.PATCH sha256:<64 lowercase hex> [--rollback]\n' "$0" >&2
}

site="${1:-}"
release_tag="${2:-}"
digest="${3:-}"
operation='promotion'
case "$#" in
  3) ;;
  4)
    [[ "${4}" == '--rollback' ]] || { usage; exit 2; }
    operation='rollback'
    ;;
  *) usage; exit 2 ;;
esac
case "${site}" in
  naranjo-online)
    image='ghcr.io/snaraj/naranjo-online'
    values_relative='kubernetes/websites/naranjo-online/release.yaml'
    parent_relative='kubernetes/reconciliation/naranjo-online.yaml'
    values="${repo_root}/kubernetes/websites/naranjo-online/release.yaml"
    parent="${repo_root}/kubernetes/reconciliation/naranjo-online.yaml"
    identity="https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/tags/${2:-}"
    chart_oci='oci://ghcr.io/snaraj/charts/naranjo-online'
    release='naranjo-online'
    namespace='naranjo-online'
    ;;
  lidersea-com)
    image='ghcr.io/snaraj/lidersea-com'
    values_relative='kubernetes/websites/lidersea-com/release.yaml'
    parent_relative='kubernetes/reconciliation/lidersea-com.yaml'
    values="${repo_root}/kubernetes/websites/lidersea-com/release.yaml"
    parent="${repo_root}/kubernetes/reconciliation/lidersea-com.yaml"
    identity="https://github.com/snaraj/lidersea.com/.github/workflows/release-publisher.yml@refs/tags/${2:-}"
    chart_oci='oci://ghcr.io/snaraj/charts/lidersea-com'
    release='lidersea-com'
    namespace='lidersea-com'
    ;;
  *)
    usage
    exit 2
    ;;
esac
# Resolve the manifest relative to this script so ShellCheck follows the same
# file that Bash loads after repo_root has been canonicalized above.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../versions.env
# CI intentionally runs ShellCheck without -x; suppress only its refusal to
# follow this already-declared runtime source while retaining all other checks.
# shellcheck disable=SC1091
source "${repo_root}/versions.env"

[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  usage
  exit 2
}
[[ "${digest}" != "sha256:$(printf '0%.0s' {1..64})" ]] || { printf 'all-zero digest is forbidden\n' >&2; exit 2; }
# Exact ORAS and Cosign versions keep local verification aligned with CI's
# interpretation of manifests, signatures, and attestations.
for command_name in git cosign oras jq sed python3 sha256sum mktemp cmp rm mkdir dirname; do
  command -v "${command_name}" >/dev/null 2>&1 || { printf '%s is required\n' "${command_name}" >&2; exit 2; }
done
tag_validation=(
  "${repo_root}/scripts/validate_image_release.py" validate-tag
  --site "${site}" --tag "${release_tag}"
)
if [[ "${operation}" == 'promotion' ]]; then
  # Forward promotion always consumes the selected site's current tracked
  # release. Historical signed tags are accepted only by explicit rollback.
  tag_validation+=(--current)
else
  # Rollback must select an actually older retained release. The tracked
  # current tag and any future tag remain forward-promotion operations.
  tag_validation+=(--rollback)
fi
python3 -B "${tag_validation[@]}"
release_version="${release_tag#v}"
oras_actual="$(oras version | sed -n 's/^[[:space:]]*Version:[[:space:]]*//p')"
cosign_actual="$(cosign version | sed -n 's/^[[:space:]]*GitVersion:[[:space:]]*//p')"
[[ "${oras_actual}" == "${ORAS_VERSION#v}" ]] || {
  printf 'oras version must be exactly %s; got %s\n' "${ORAS_VERSION#v}" "${oras_actual:-unknown}" >&2
  exit 2
}
[[ "${cosign_actual}" == "${COSIGN_VERSION}" ]] || {
  printf 'cosign version must be exactly %s; got %s\n' "${COSIGN_VERSION}" "${cosign_actual:-unknown}" >&2
  exit 2
}

# Either operation creates a review artifact for one values file, so it requires
# an isolated feature branch and a clean tree before network evidence is used.
if ! branch="$(git -C "${repo_root}" branch --show-current)"; then
  printf 'release branch could not be read\n' >&2
  exit 2
fi
[[ -n "${branch}" && "${branch}" != "main" ]] || { printf 'release change requires a non-main feature branch\n' >&2; exit 2; }
if ! initial_head="$(git -C "${repo_root}" rev-parse --verify HEAD)"; then
  printf 'release HEAD could not be read\n' >&2
  exit 2
fi
[[ "${initial_head}" =~ ^[0-9a-f]{40}$ ]] || { printf 'release HEAD is not one full Git SHA\n' >&2; exit 2; }
if ! initial_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"; then
  printf 'working tree status could not be read\n' >&2
  exit 2
fi
[[ -z "${initial_status}" ]] || { printf 'working tree must be clean before a release change\n' >&2; exit 2; }

file_sha256() {
  local output
  if ! output="$(sha256sum -- "$1")"; then
    return 1
  fi
  output="${output%% *}"
  [[ "${output}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${output}"
}

require_original_clean_state() {
  local current_branch current_head current_status
  if ! current_branch="$(git -C "${repo_root}" branch --show-current)"; then
    printf 'release branch could not be re-read\n' >&2
    return 1
  fi
  [[ "${current_branch}" == "${branch}" ]] || {
    printf 'release branch changed during verification\n' >&2
    return 1
  }
  if ! current_head="$(git -C "${repo_root}" rev-parse --verify HEAD)"; then
    printf 'release HEAD could not be re-read\n' >&2
    return 1
  fi
  [[ "${current_head}" == "${initial_head}" ]] || {
    printf 'release HEAD changed during verification\n' >&2
    return 1
  }
  if ! current_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"; then
    printf 'working tree status could not be re-read\n' >&2
    return 1
  fi
  [[ -z "${current_status}" ]] || {
    printf 'working tree changed during release verification\n' >&2
    return 1
  }
  python3 -B "${tag_validation[@]}"
}

# The narrow parser proves exact YAML ancestry, both suspension gates, and the
# readiness/digest phase. Forward promotion may initialize a site or advance an
# already-promoted site; rollback is meaningful only from promoted state.
site_phase() {
  local expected_digest="${1:-}"
  local -a arguments=(site-phase --site "${site}")
  if [[ -n "${expected_digest}" ]]; then
    arguments+=(--expect-digest "${expected_digest}")
  fi
  python3 -B "${repo_root}/scripts/validate_release_state.py" "${arguments[@]}"
}
if ! initial_phase="$(site_phase)"; then
  printf '%s\n' \
    'HelmRelease must be explicitly suspended before a digest change; parent Kustomization must be explicitly suspended before a digest change' >&2
  exit 1
fi
case "${operation}:${initial_phase}" in
  promotion:initial|promotion:promoted|rollback:promoted) ;;
  rollback:initial)
    printf 'rollback requires an already-promoted deployment readiness gate and nonzero digest\n' >&2
    exit 1
    ;;
  *)
    printf 'release state is not valid for the requested operation\n' >&2
    exit 1
    ;;
esac

# Retain independent content fingerprints across the long registry verification
# window. A same-phase edit is still a state change and invalidates the review.
if ! initial_release_fingerprint="$(file_sha256 "${values}")"; then
  printf 'HelmRelease fingerprint could not be computed\n' >&2
  exit 1
fi
if ! initial_parent_fingerprint="$(file_sha256 "${parent}")"; then
  printf 'parent Kustomization fingerprint could not be computed\n' >&2
  exit 1
fi

# Keyless verification is scoped to the main-branch publisher workflow; a valid
# signature from another repository or workflow is intentionally insufficient.
reference="${image}@${digest}"
issuer='https://token.actions.githubusercontent.com'
if ! tagged_digest="$(oras resolve "${image}:${release_tag}")"; then
  printf 'release tag could not be resolved\n' >&2
  exit 1
fi
[[ "${tagged_digest}" == "${digest}" ]] || {
  printf 'release tag does not resolve to the supplied digest\n' >&2
  exit 1
}
index_manifest="$(oras manifest fetch "${reference}")"
jq -e '
  ([.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64")] | length) == 1 and
  ([.manifests[] | select(.platform.os == "linux" and .platform.architecture == "arm64")] | length) == 1
' >/dev/null <<<"${index_manifest}" || {
  printf 'image index does not contain exactly one linux/amd64 and one linux/arm64 manifest\n' >&2
  exit 1
}
release_revision=''
for platform in linux/amd64 linux/arm64; do
  config="$(oras manifest fetch-config --platform "${platform}" "${reference}")"
  if ! image_labels="$(
    jq -er '[
      .config.Labels["org.opencontainers.image.source"],
      .config.Labels["org.opencontainers.image.version"],
      .config.Labels["org.opencontainers.image.revision"]
    ] | @tsv' <<<"${config}"
  )"; then
    printf '%s image labels could not be read exactly\n' "${platform}" >&2
    exit 1
  fi
  [[ "${image_labels}" != *$'\n'* && "${image_labels}" != *$'\r'* ]] || {
    printf '%s image labels contain more than one record\n' "${platform}" >&2
    exit 1
  }
  IFS=$'\t' read -r image_source image_version image_revision extra_label <<<"${image_labels}"
  [[ -z "${extra_label}" ]] || {
    printf '%s image labels contain extra fields\n' "${platform}" >&2
    exit 1
  }
  [[ "${image_source}" == 'https://github.com/snaraj/website-infrastructure' ]] || {
    printf '%s image source label is not the reviewed repository\n' "${platform}" >&2
    exit 1
  }
  [[ "${image_version}" == "${release_version}" ]] || {
    printf '%s image version label does not match the requested release tag\n' "${platform}" >&2
    exit 1
  }
  [[ "${image_revision}" =~ ^[0-9a-f]{40}$ ]] || {
    printf '%s image revision label is not one full Git SHA\n' "${platform}" >&2
    exit 1
  }
  if [[ -z "${release_revision}" ]]; then
    release_revision="${image_revision}"
  else
    [[ "${image_revision}" == "${release_revision}" ]] || {
      printf 'platform image revision labels disagree\n' >&2
      exit 1
    }
  fi
done
cosign verify --certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}" "${reference}" >/dev/null
cosign verify-attestation --type slsaprovenance1 --certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}" "${reference}" >/dev/null
# Resolve the human tag again immediately before candidate construction. The review
# refuses a concurrent or administrative tag reassignment between provenance
# verification and the digest-addressed patch.
if ! rebound_tagged_digest="$(oras resolve "${image}:${release_tag}")"; then
  printf 'release tag could not be re-resolved after provenance verification\n' >&2
  exit 1
fi
[[ "${rebound_tagged_digest}" == "${digest}" ]] || {
  printf 'release tag mapping changed during verification\n' >&2
  exit 1
}

optional_secret_relative='kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml'
optional_secret_source="${repo_root}/${optional_secret_relative}"
if [[ -L "${optional_secret_source}" ]]; then
  printf 'optional tunnel Secret input must not be a symlink\n' >&2
  exit 1
elif [[ -e "${optional_secret_source}" ]]; then
  optional_secret_presence='present'
else
  optional_secret_presence='absent'
fi

# Build and validate the candidate away from the live release path. The ignored
# transaction is the only written state; the repository remains untouched so
# an editor or another process can never be overwritten by this verifier.
umask 077
artifact_root="${repo_root}/.artifacts"
if [[ -e "${artifact_root}" ]]; then
  [[ -d "${artifact_root}" && ! -L "${artifact_root}" ]] || {
    printf '.artifacts must be a real directory for a release review transaction\n' >&2
    exit 1
  }
else
  # On POSIX the umask below restricts files; Git Bash on NTFS inherits the
  # operator's directory ACL because chmod-style mode creation is not reliably
  # supported. A configured tunnel Secret is copied only as tracked ciphertext
  # and is never decrypted by this transaction.
  mkdir -- "${artifact_root}"
fi
transaction_root="$(mktemp -d "${artifact_root}/promotion.${site}.XXXXXX")"
case "${transaction_root}" in
  "${artifact_root}"/promotion."${site}".*) ;;
  *) printf 'unsafe promotion transaction path\n' >&2; exit 1 ;;
esac
candidate_root="${transaction_root}/root"
candidate_values="${candidate_root}/${values_relative}"
candidate_parent="${candidate_root}/${parent_relative}"
original_backup="${transaction_root}/original.release.yaml"
effective_values="${transaction_root}/effective-values.yaml"
review_patch="${transaction_root}/promotion.patch"
review_patch_recheck="${transaction_root}/promotion.recheck.patch"
evidence_file="${transaction_root}/evidence.env"
declare -a release_state_paths=(
  'kubernetes/websites/naranjo-online/release.yaml'
  'kubernetes/reconciliation/naranjo-online.yaml'
  'kubernetes/websites/lidersea-com/release.yaml'
  'kubernetes/reconciliation/lidersea-com.yaml'
  'kubernetes/platform/cloudflare-public/release/release.yaml'
  'kubernetes/platform/cloudflare-public/release/kustomization.yaml'
  'kubernetes/reconciliation/platform-services.yaml'
  'kubernetes/reconciliation/admission.yaml'
  '.sops.yaml'
  'infrastructure/cloudflare/phases/admin-api/.terraform.lock.hcl'
  'infrastructure/cloudflare/phases/admin-api/main.tf'
  'infrastructure/cloudflare/phases/admin-api/outputs.tf'
  'infrastructure/cloudflare/phases/admin-api/terraform.tfvars.example'
  'infrastructure/cloudflare/phases/admin-api/variables.tf'
  'infrastructure/cloudflare/phases/admin-api/versions.tf'
  'infrastructure/cloudflare/phases/admin-policies/.terraform.lock.hcl'
  'infrastructure/cloudflare/phases/admin-policies/main.tf'
  'infrastructure/cloudflare/phases/admin-policies/terraform.tfvars.example'
  'infrastructure/cloudflare/phases/admin-policies/variables.tf'
  'infrastructure/cloudflare/phases/admin-policies/versions.tf'
  'infrastructure/cloudflare/phases/admin-route/.terraform.lock.hcl'
  'infrastructure/cloudflare/phases/admin-route/main.tf'
  'infrastructure/cloudflare/phases/admin-route/outputs.tf'
  'infrastructure/cloudflare/phases/admin-route/terraform.tfvars.example'
  'infrastructure/cloudflare/phases/admin-route/variables.tf'
  'infrastructure/cloudflare/phases/admin-route/versions.tf'
  'infrastructure/cloudflare/phases/admin-tunnel/.terraform.lock.hcl'
  'infrastructure/cloudflare/phases/admin-tunnel/main.tf'
  'infrastructure/cloudflare/phases/admin-tunnel/outputs.tf'
  'infrastructure/cloudflare/phases/admin-tunnel/terraform.tfvars.example'
  'infrastructure/cloudflare/phases/admin-tunnel/variables.tf'
  'infrastructure/cloudflare/phases/admin-tunnel/versions.tf'
  'infrastructure/cloudflare/phases/public-dns-lidersea/.terraform.lock.hcl'
  'infrastructure/cloudflare/phases/public-dns-lidersea/main.tf'
  'infrastructure/cloudflare/phases/public-dns-lidersea/outputs.tf'
  'infrastructure/cloudflare/phases/public-dns-lidersea/terraform.tfvars.example'
  'infrastructure/cloudflare/phases/public-dns-lidersea/variables.tf'
  'infrastructure/cloudflare/phases/public-dns-lidersea/versions.tf'
  'infrastructure/cloudflare/phases/public-dns-naranjo/.terraform.lock.hcl'
  'infrastructure/cloudflare/phases/public-dns-naranjo/main.tf'
  'infrastructure/cloudflare/phases/public-dns-naranjo/outputs.tf'
  'infrastructure/cloudflare/phases/public-dns-naranjo/terraform.tfvars.example'
  'infrastructure/cloudflare/phases/public-dns-naranjo/variables.tf'
  'infrastructure/cloudflare/phases/public-dns-naranjo/versions.tf'
  'infrastructure/cloudflare/phases/public-edge/.terraform.lock.hcl'
  'infrastructure/cloudflare/phases/public-edge/main.tf'
  'infrastructure/cloudflare/phases/public-edge/outputs.tf'
  'infrastructure/cloudflare/phases/public-edge/terraform.tfvars.example'
  'infrastructure/cloudflare/phases/public-edge/variables.tf'
  'infrastructure/cloudflare/phases/public-edge/versions.tf'
)
if [[ "${optional_secret_presence}" == 'present' ]]; then
  release_state_paths+=("${optional_secret_relative}")
fi
declare -A initial_state_fingerprints=()

require_transition_snapshots_unchanged() {
  local state_relative state_source state_destination
  local current_state_fingerprint expected_state_fingerprint
  local expected_destination_fingerprint
  for state_relative in "${release_state_paths[@]}"; do
    expected_state_fingerprint="${initial_state_fingerprints[$state_relative]-}"
    [[ "${expected_state_fingerprint}" =~ ^[0-9a-f]{64}$ ]] || {
      printf 'transition source fingerprint is unavailable: %s\n' "${state_relative}" >&2
      return 1
    }
    state_source="${repo_root}/${state_relative}"
    state_destination="${candidate_root}/${state_relative}"
    if ! current_state_fingerprint="$(file_sha256 "${state_source}")"; then
      printf 'transition source fingerprint could not be finalized: %s\n' "${state_relative}" >&2
      return 1
    fi
    [[ "${current_state_fingerprint}" == "${expected_state_fingerprint}" ]] || {
      printf 'transition source changed during local validation: %s\n' "${state_relative}" >&2
      return 1
    }
    if [[ "${state_relative}" == "${values_relative}" ]]; then
      expected_destination_fingerprint="${candidate_fingerprint}"
    else
      expected_destination_fingerprint="${expected_state_fingerprint}"
    fi
    if ! current_state_fingerprint="$(file_sha256 "${state_destination}")"; then
      printf 'transition snapshot fingerprint could not be finalized: %s\n' "${state_relative}" >&2
      return 1
    fi
    [[ "${current_state_fingerprint}" == "${expected_destination_fingerprint}" ]] || {
      printf 'transition snapshot changed during local validation: %s\n' "${state_relative}" >&2
      return 1
    }
  done
  if [[ "${optional_secret_presence}" == 'absent' ]]; then
    [[ ! -e "${optional_secret_source}" && ! -L "${optional_secret_source}" ]] || {
      printf 'optional tunnel Secret appeared during local validation\n' >&2
      return 1
    }
    [[ ! -e "${candidate_root}/${optional_secret_relative}" && \
       ! -L "${candidate_root}/${optional_secret_relative}" ]] || {
      printf 'optional tunnel Secret appeared in the candidate snapshot\n' >&2
      return 1
    }
  fi
}

cleanup_transaction() {
  python3 -B "${repo_root}/scripts/remove_review_transaction.py" \
    --artifact-root "${artifact_root}" \
    --transaction-root "${transaction_root}" \
    --site "${site}"
}
on_failure() {
  local status=$?
  trap - ERR INT TERM HUP EXIT
  set +e
  [[ "${status}" -ne 0 ]] || status=1
  cleanup_transaction || printf 'WARNING: partial review artifacts could not be removed: %s\n' "${transaction_root}" >&2
  exit "${status}"
}
trap on_failure ERR INT TERM HUP EXIT

# Snapshot the selected release once, authenticate it, and derive the candidate
# with exclusive no-follow writers. The complete transition state is captured
# alongside it so dependency validation never sees a partial synthetic root.
require_original_clean_state
if [[ "${optional_secret_presence}" == 'absent' ]]; then
  [[ ! -e "${optional_secret_source}" && ! -L "${optional_secret_source}" ]] || {
    printf 'optional tunnel Secret appeared before transition snapshotting\n' >&2
    exit 1
  }
fi
mkdir -p -- "$(dirname -- "${candidate_values}")"
python3 -B "${repo_root}/scripts/write_review_artifact.py" \
  --input "${values}" --output "${original_backup}"
if ! backup_fingerprint="$(file_sha256 "${original_backup}")"; then
  printf 'HelmRelease snapshot fingerprint could not be computed\n' >&2
  exit 1
fi
[[ "${backup_fingerprint}" == "${initial_release_fingerprint}" ]] || {
  printf 'HelmRelease changed while creating the review snapshot\n' >&2
  exit 1
}
for state_relative in "${release_state_paths[@]}"; do
  state_source="${repo_root}/${state_relative}"
  state_destination="${candidate_root}/${state_relative}"
  if ! state_source_before="$(file_sha256 "${state_source}")"; then
    printf 'transition source fingerprint could not be computed: %s\n' "${state_relative}" >&2
    exit 1
  fi
  mkdir -p -- "$(dirname -- "${state_destination}")"
  if [[ "${state_relative}" == "${values_relative}" ]]; then
    python3 -B "${repo_root}/scripts/create_release_candidate.py" \
      --original "${original_backup}" \
      --output "${state_destination}" \
      --digest "${digest}" \
      --initial-phase "${initial_phase}"
  else
    python3 -B "${repo_root}/scripts/write_review_artifact.py" \
      --input "${state_source}" --output "${state_destination}"
  fi
  if ! state_source_after="$(file_sha256 "${state_source}")"; then
    printf 'transition source fingerprint could not be re-read: %s\n' "${state_relative}" >&2
    exit 1
  fi
  if ! state_destination_fingerprint="$(file_sha256 "${state_destination}")"; then
    printf 'transition snapshot fingerprint could not be computed: %s\n' "${state_relative}" >&2
    exit 1
  fi
  [[ "${state_source_before}" == "${state_source_after}" ]] || {
    printf 'transition input changed while snapshotting: %s\n' "${state_relative}" >&2
    exit 1
  }
  if [[ "${state_relative}" != "${values_relative}" && \
        "${state_destination_fingerprint}" != "${state_source_before}" ]]; then
    printf 'transition snapshot differs from its source: %s\n' "${state_relative}" >&2
    exit 1
  fi
  initial_state_fingerprints["${state_relative}"]="${state_source_before}"
done
if ! candidate_parent_fingerprint="$(file_sha256 "${candidate_parent}")"; then
  printf 'candidate parent fingerprint could not be computed\n' >&2
  exit 1
fi
[[ "${candidate_parent_fingerprint}" == "${initial_parent_fingerprint}" ]] || {
  printf 'candidate parent differs from the authenticated Kustomization\n' >&2
  exit 1
}
candidate_phase="$(
  python3 -B "${repo_root}/scripts/validate_release_state.py" \
    --root "${candidate_root}" site-phase --site "${site}" --expect-digest "${digest}"
)"
[[ "${candidate_phase}" == 'promoted' ]] || {
  printf 'candidate release did not produce the exact promoted digest state\n' >&2
  exit 1
}
python3 -B "${repo_root}/scripts/validate_release_transition.py" \
  --root "${candidate_root}" plan --expect-mode transition >/dev/null
python3 -B "${repo_root}/scripts/validate_release_state.py" \
  --root "${candidate_root}" emit-values --release "${site}" | \
  python3 -B "${repo_root}/scripts/write_review_artifact.py" \
    --normalize-crlf --output "${effective_values}"
[[ -s "${effective_values}" ]] || { printf 'candidate effective values are empty\n' >&2; exit 1; }
if command -v helm >/dev/null 2>&1; then
  # The chart ships from the site repository as a signed OCI artifact at the
  # same version as the image; pull that exact release and render with the
  # candidate effective values.
  chart_pull_dir="$(mktemp -d)"
  helm pull "${chart_oci}" --version "${release_version}" \
    --destination "${chart_pull_dir}"
  chart_archive="${chart_pull_dir}/${release}-${release_version}.tgz"
  [[ -f "${chart_archive}" ]] || {
    printf 'released chart %s@%s could not be pulled\n' "${chart_oci}" "${release_version}" >&2
    exit 1
  }
  helm lint "${chart_archive}" --values "${effective_values}"
  helm template "${release}" "${chart_archive}" --namespace "${namespace}" \
    --values "${effective_values}" >/dev/null
  rm -rf -- "${chart_pull_dir}"
else
  printf 'PENDING Helm render: helm is unavailable. Do not apply the patch until CI passes.\n'
fi

if ! candidate_fingerprint="$(file_sha256 "${candidate_values}")"; then
  printf 'candidate HelmRelease fingerprint could not be computed\n' >&2
  exit 1
fi
[[ "${candidate_fingerprint}" != "${initial_release_fingerprint}" ]] || {
  printf 'release operation would be a no-op\n' >&2
  exit 1
}
python3 -B "${repo_root}/scripts/create_release_patch.py" \
  --original "${original_backup}" \
  --candidate "${candidate_values}" \
  --relative "${values_relative}" \
  --output "${review_patch}"
if ! canonical_patch_fingerprint="$(file_sha256 "${review_patch}")"; then
  printf 'canonical review patch fingerprint could not be computed\n' >&2
  exit 1
fi
git -C "${repo_root}" apply --check -- "${review_patch}"

# Repeat every local and remote mutable input after candidate validation. No
# compare/check sequence writes the live worktree: applying the review patch is
# an explicit later operator action.
require_original_clean_state
require_transition_snapshots_unchanged
if ! current_release_fingerprint="$(file_sha256 "${values}")"; then
  printf 'HelmRelease fingerprint could not be re-read\n' >&2
  exit 1
fi
[[ "${current_release_fingerprint}" == "${initial_release_fingerprint}" ]] || {
  printf 'HelmRelease changed during registry or candidate verification\n' >&2
  exit 1
}
if ! current_parent_fingerprint="$(file_sha256 "${parent}")"; then
  printf 'parent Kustomization fingerprint could not be re-read\n' >&2
  exit 1
fi
[[ "${current_parent_fingerprint}" == "${initial_parent_fingerprint}" ]] || {
  printf 'parent Kustomization changed during registry or candidate verification\n' >&2
  exit 1
}
revalidated_phase="$(site_phase)"
[[ "${revalidated_phase}" == "${initial_phase}" ]] || {
  printf 'release phase changed during registry or candidate verification\n' >&2
  exit 1
}
if ! finalized_tagged_digest="$(oras resolve "${image}:${release_tag}")"; then
  printf 'release tag could not be resolved before review artifact finalization\n' >&2
  exit 1
fi
[[ "${finalized_tagged_digest}" == "${digest}" ]] || {
  printf 'release tag mapping changed before review artifact finalization\n' >&2
  exit 1
}

python3 -B "${repo_root}/scripts/validate_repository.py" all
python3 -B "${repo_root}/scripts/validate_release_transition.py" \
  --root "${candidate_root}" plan --expect-mode transition >/dev/null
git -C "${repo_root}" diff --check

# A final just-in-time pass prevents a long local validation from producing a
# stale success record after a tag, branch, HEAD, parent, release, or policy edit.
if ! final_tagged_digest="$(oras resolve "${image}:${release_tag}")"; then
  printf 'release tag could not be resolved during local validation\n' >&2
  exit 1
fi
[[ "${final_tagged_digest}" == "${digest}" ]] || {
  printf 'release tag mapping changed during local validation\n' >&2
  exit 1
}
require_original_clean_state
require_transition_snapshots_unchanged
if ! current_release_fingerprint="$(file_sha256 "${values}")"; then
  printf 'HelmRelease fingerprint could not be read during local validation\n' >&2
  exit 1
fi
[[ "${current_release_fingerprint}" == "${initial_release_fingerprint}" ]] || {
  printf 'HelmRelease changed during local validation\n' >&2
  exit 1
}
if ! current_parent_fingerprint="$(file_sha256 "${parent}")"; then
  printf 'parent Kustomization fingerprint could not be read during local validation\n' >&2
  exit 1
fi
[[ "${current_parent_fingerprint}" == "${initial_parent_fingerprint}" ]] || {
  printf 'parent Kustomization changed during local validation\n' >&2
  exit 1
}
if ! current_candidate_fingerprint="$(file_sha256 "${candidate_values}")"; then
  printf 'candidate HelmRelease fingerprint could not be read during local validation\n' >&2
  exit 1
fi
[[ "${current_candidate_fingerprint}" == "${candidate_fingerprint}" ]] || {
  printf 'candidate HelmRelease changed during local validation\n' >&2
  exit 1
}
candidate_phase="$(
  python3 -B "${repo_root}/scripts/validate_release_state.py" \
    --root "${candidate_root}" site-phase --site "${site}" --expect-digest "${digest}"
)"
[[ "${candidate_phase}" == 'promoted' ]] || {
  printf 'candidate release state changed during local validation\n' >&2
  exit 1
}
python3 -B "${repo_root}/scripts/validate_release_transition.py" \
  --root "${candidate_root}" plan --expect-mode transition >/dev/null
if ! current_patch_fingerprint="$(file_sha256 "${review_patch}")"; then
  printf 'review patch fingerprint could not be read during local validation\n' >&2
  exit 1
fi
[[ "${current_patch_fingerprint}" == "${canonical_patch_fingerprint}" ]] || {
  printf 'review patch changed during local validation\n' >&2
  exit 1
}
python3 -B "${repo_root}/scripts/create_release_patch.py" \
  --original "${original_backup}" \
  --candidate "${candidate_values}" \
  --relative "${values_relative}" \
  --output "${review_patch_recheck}"
if ! regenerated_patch_fingerprint="$(file_sha256 "${review_patch_recheck}")"; then
  printf 'regenerated review patch fingerprint could not be computed\n' >&2
  exit 1
fi
[[ "${regenerated_patch_fingerprint}" == "${canonical_patch_fingerprint}" ]] || {
  printf 'regenerated review patch differs from the validated candidate\n' >&2
  exit 1
}
cmp -s -- "${review_patch}" "${review_patch_recheck}" || {
  printf 'review patch bytes differ from the validated candidate\n' >&2
  exit 1
}
rm -f -- "${review_patch_recheck}"
git -C "${repo_root}" apply --check -- "${review_patch}"
git -C "${repo_root}" diff --check

if ! patch_fingerprint="$(file_sha256 "${review_patch}")"; then
  printf 'review patch fingerprint could not be computed\n' >&2
  exit 1
fi
[[ "${patch_fingerprint}" == "${canonical_patch_fingerprint}" ]] || {
  printf 'review patch changed during evidence finalization\n' >&2
  exit 1
}
printf '%s\n' \
  'SCHEMA=website-infrastructure-promotion-review-v1' \
  "SITE=${site}" \
  "OPERATION=${operation}" \
  "RELEASE_TAG=${release_tag}" \
  "DIGEST=${digest}" \
  "IMAGE_REVISION=${release_revision}" \
  "REVIEWED_HEAD=${initial_head}" \
  "ORIGINAL_RELEASE_SHA256=${initial_release_fingerprint}" \
  "CANDIDATE_RELEASE_SHA256=${candidate_fingerprint}" \
  "PATCH_SHA256=${patch_fingerprint}" | \
  python3 -B "${repo_root}/scripts/write_review_artifact.py" --output "${evidence_file}"

trap - ERR INT TERM HUP EXIT
printf 'Verified %s candidate for %s release %s digest %s from revision %s on branch %s.\n' \
  "${operation}" "${site}" "${release_tag}" "${digest}" "${release_revision}" "${branch}"
printf 'The worktree is unchanged. Review %s and its evidence, then apply it explicitly with git apply. Both suspension gates remain true. This script did not stage, commit, push, or deploy.\n' \
  "${review_patch}"
printf 'Review artifacts: %s\n' "${transaction_root}"
