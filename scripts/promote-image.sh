#!/usr/bin/env bash
# Verify one site's published multi-architecture image and prepare its immutable
# digest in Helm values; promotion remains an unstaged review and never deploys.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# The exact site selector expands to one closed identity tuple. Sharing the
# verifier removes drift, while each tuple retains its own image, workflow,
# values file, Helm release, namespace, and rollback decision.
site="${1:-}"
digest="${2:-}"
case "${site}" in
  naranjo-online)
    image='ghcr.io/snaraj/naranjo-online'
    values="${repo_root}/websites/naranjo.online/chart/values.yaml"
    identity='https://github.com/snaraj/website-infrastructure/.github/workflows/publish-naranjo-online-image.yml@refs/heads/main'
    chart="${repo_root}/websites/naranjo.online/chart"
    release='naranjo-online'
    namespace='naranjo-online'
    ;;
  lidersea-com)
    image='ghcr.io/snaraj/lidersea-com'
    values="${repo_root}/websites/lidersea.com/chart/values.yaml"
    identity='https://github.com/snaraj/website-infrastructure/.github/workflows/publish-lidersea-com-image.yml@refs/heads/main'
    chart="${repo_root}/websites/lidersea.com/chart"
    release='lidersea-com'
    namespace='lidersea-com'
    ;;
  *)
    printf 'Usage: %s {naranjo-online|lidersea-com} sha256:<64 lowercase hex>\n' "$0" >&2
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
  printf 'Usage: %s {naranjo-online|lidersea-com} sha256:<64 lowercase hex>\n' "$0" >&2
  exit 2
}
[[ "${digest}" != "sha256:$(printf '0%.0s' {1..64})" ]] || { printf 'all-zero digest is forbidden\n' >&2; exit 2; }
# Exact ORAS and Cosign versions keep local verification aligned with CI's
# interpretation of manifests, signatures, and attestations.
for command_name in git cosign oras jq sed grep; do
  command -v "${command_name}" >/dev/null 2>&1 || { printf '%s is required\n' "${command_name}" >&2; exit 2; }
done
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

# Promotion mutates one reviewed values file, so it requires an isolated feature
# branch and a clean tree before any network-derived digest is written.
branch="$(git -C "${repo_root}" branch --show-current)"
[[ -n "${branch}" && "${branch}" != "main" ]] || { printf 'promotion requires a non-main feature branch\n' >&2; exit 2; }
[[ -z "$(git -C "${repo_root}" status --porcelain)" ]] || { printf 'working tree must be clean before promotion\n' >&2; exit 2; }

# Keyless verification is scoped to the main-branch publisher workflow; a valid
# signature from another repository or workflow is intentionally insufficient.
reference="${image}@${digest}"
issuer='https://token.actions.githubusercontent.com'
index_manifest="$(oras manifest fetch "${reference}")"
jq -e '
  ([.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64")] | length) == 1 and
  ([.manifests[] | select(.platform.os == "linux" and .platform.architecture == "arm64")] | length) == 1
' >/dev/null <<<"${index_manifest}" || {
  printf 'image index does not contain exactly one linux/amd64 and one linux/arm64 manifest\n' >&2
  exit 1
}
cosign verify --certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}" "${reference}" >/dev/null
cosign verify-attestation --type slsaprovenance1 --certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}" "${reference}" >/dev/null

# Keep a rollback copy until repository and Helm validation complete so an
# interrupted or failed promotion cannot leave a half-edited release contract.
digest_count="$(grep -Ec '^  digest: sha256:[0-9a-f]{64}$' "${values}")"
[[ "${digest_count}" -eq 1 ]] || { printf 'expected exactly one image digest field\n' >&2; exit 1; }
backup="$(mktemp)"
cp "${values}" "${backup}"
restore() { cp "${backup}" "${values}"; rm -f "${backup}"; }
trap restore ERR INT TERM
sed -E -i "s|^  digest: sha256:[0-9a-f]{64}$|  digest: ${digest}|" "${values}"
sed -E -i 's/^deploymentReady: false$/deploymentReady: true/' "${values}"

# Re-run the same structural gates used by CI before presenting the diff for
# review; Helm absence remains visible and must be resolved by CI before a PR.
python3 "${repo_root}/scripts/validate_repository.py" layout privacy secrets media kubernetes
if command -v helm >/dev/null 2>&1; then
  helm lint "${chart}"
  helm template "${release}" "${chart}" --namespace "${namespace}" >/dev/null
else
  printf 'PENDING Helm render: helm is unavailable. Do not open the PR until CI passes.\n'
fi
git -C "${repo_root}" diff --check
rm -f "${backup}"
trap - ERR INT TERM

printf 'Verified and updated %s digest %s on branch %s.\n' "${site}" "${digest}" "${branch}"
printf 'Review the diff and create a PR manually. This script did not commit, push, or deploy.\n'
git -C "${repo_root}" diff -- "${values}"
