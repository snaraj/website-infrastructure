#!/usr/bin/env bash
# Install the exact ephemeral validators used by GitHub Actions, with every
# network download authenticated by SHA-256. CI binaries stay outside the
# checkout so subsequent whole-tree secret and vulnerability scans cannot scan
# the downloaded scanners themselves.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# Every caller receives a fresh private tool directory outside the checkout.
# This prevents later whole-tree scanners from treating downloaded scanner
# binaries as repository content. GitHub Actions supplies RUNNER_TEMP; local
# callers use an already-existing absolute TMPDIR (or /tmp).
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  : "${RUNNER_TEMP:?GitHub Actions must provide RUNNER_TEMP}"
  tool_parent_input="${RUNNER_TEMP}"
else
  tool_parent_input="${TMPDIR:-/tmp}"
fi
[[ "${tool_parent_input}" == /* && -d "${tool_parent_input}" && ! -L "${tool_parent_input}" ]] || {
  printf 'tool temporary root is not a safe absolute directory.\n' >&2
  exit 1
}
tool_parent="$(cd "${tool_parent_input}" && pwd -P)"
case "${tool_parent}/" in
  "${repo_root}/"*)
    printf 'tool custody must remain outside the checkout.\n' >&2
    exit 1
    ;;
esac
install_root="$(mktemp -d "${tool_parent%/}/website-infrastructure-tools.XXXXXX")"

# Downloads use a separate private temporary directory that is removed even
# when verification fails.
download_root="$(mktemp -d "${tool_parent%/}/website-infrastructure-downloads.XXXXXX")"
trap 'rm -rf -- "${download_root}"' EXIT

# fetch refuses redirects away from HTTPS/TLS 1.2+ and verifies bytes before any
# archive is extracted or executable is installed.
fetch() {
  local url="$1"
  local sha256="$2"
  local output="$3"
  # The basename is public release metadata and makes a failed pin actionable
  # without printing query strings, credentials, or a caller's local paths.
  printf 'Fetching checksum-pinned asset %s.\n' "${url##*/}"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --retry 3 --retry-all-errors --retry-delay 1 \
    --output "${output}" "${url}"
  printf '%s  %s\n' "${sha256}" "${output}" | sha256sum --check --status || {
    printf 'checksum mismatch: %s\n' "${url}" >&2
    exit 1
  }
}

# safe_extract rejects absolute and parent-traversal members so a compromised
# release archive cannot write outside its dedicated extraction directory.
safe_extract() {
  local archive="$1"
  local destination="$2"
  local members member_modes
  # Capture the complete listing before grep. With pipefail, a quiet grep could
  # otherwise close early, SIGPIPE tar, and turn a detected bad path into false.
  members="$(tar -tf "${archive}")" || {
    printf 'unable to list archive: %s\n' "${archive}" >&2
    exit 1
  }
  if grep -Eq '(^/|(^|/)\.\.(/|$))' <<<"${members}"; then
    printf 'unsafe archive path: %s\n' "${archive}" >&2
    exit 1
  fi
  # CI validators need only regular files and directories. Reject links and
  # device-like entries so extraction cannot redirect a later member outside
  # the fresh tool directory even when the archive hash itself is authentic.
  member_modes="$(LC_ALL=C tar -tvf "${archive}")" || {
    printf 'unable to inspect archive member types: %s\n' "${archive}" >&2
    exit 1
  }
  if grep -Eqv '^[d-]' <<<"${member_modes}"; then
    printf 'unsafe archive member type: %s\n' "${archive}" >&2
    exit 1
  fi
  mkdir -p "${destination}"
  tar -xf "${archive}" -C "${destination}"
}

# install_archive_binary centralizes the URL, checksum, exact archive member,
# output name, and temporary key contract for each pinned CI utility.
install_archive_binary() {
  local url="$1"
  local sha256="$2"
  local member="$3"
  local destination_name="$4"
  local key="$5"
  local archive="${download_root}/${key}.archive"
  local extracted="${download_root}/${key}"
  fetch "${url}" "${sha256}" "${archive}"
  safe_extract "${archive}" "${extracted}"
  [[ -f "${extracted}/${member}" ]] || { printf 'archive member missing: %s\n' "${member}" >&2; exit 1; }
  install -m 0755 "${extracted}/${member}" "${install_root}/${destination_name}"
}

install_archive_binary \
  'https://github.com/aquasecurity/trivy/releases/download/v0.73.0/trivy_0.73.0_Linux-64bit.tar.gz' \
  '2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b' \
  'trivy' 'trivy' 'trivy'
install_archive_binary \
  'https://github.com/anchore/syft/releases/download/v1.50.0/syft_1.50.0_linux_amd64.tar.gz' \
  'bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788' \
  'syft' 'syft' 'syft'
install_archive_binary \
  'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz' \
  '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb' \
  'gitleaks' 'gitleaks' 'gitleaks'
install_archive_binary \
  'https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz' \
  '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8' \
  'actionlint' 'actionlint' 'actionlint'
install_archive_binary \
  'https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz' \
  '9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883' \
  'kubeconform' 'kubeconform' 'kubeconform'
install_archive_binary \
  'https://github.com/open-policy-agent/conftest/releases/download/v0.69.0/conftest_0.69.0_Linux_x86_64.tar.gz' \
  '96fc2fbf11f0afde51256647127e6f00a64ce839a4d9a0a1aef2426c0e6f4b3f' \
  'conftest' 'conftest' 'conftest'
install_archive_binary \
  'https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v5.8.1/kustomize_v5.8.1_linux_amd64.tar.gz' \
  '029a7f0f4e1932c52a0476cf02a0fd855c0bb85694b82c338fc648dcb53a819d' \
  'kustomize' 'kustomize' 'kustomize'
install_archive_binary \
  'https://github.com/opentofu/opentofu/releases/download/v1.12.5/tofu_1.12.5_linux_amd64.tar.gz' \
  'a6894d45ae7a17ce83189cce8fe04b5a65f68cefceb62455b5a6a89fa53ab38f' \
  'tofu' 'tofu' 'tofu'
install_archive_binary \
  'https://get.helm.sh/helm-v4.2.3-linux-amd64.tar.gz' \
  'e9b88b4ee95b18c706839c28d3a0220e5bc470e9cd9262410c90793c45ff8b7c' \
  'linux-amd64/helm' 'helm' 'helm'
install_archive_binary \
  'https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz' \
  '8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198' \
  'shellcheck-v0.11.0/shellcheck' 'shellcheck' 'shellcheck'

# The denial-oracle protocol test must exercise the same reviewed kubectl bytes
# as protected operator scripts, never whichever client happens to be on the
# GitHub runner PATH.
kubectl_file="${download_root}/kubectl"
fetch \
  'https://dl.k8s.io/release/v1.36.3/bin/linux/amd64/kubectl' \
  'ebbd080e7c2e275093b55915722043257eb24004363e20acb3c4d71919f88336' \
  "${kubectl_file}"
install -m 0755 "${kubectl_file}" "${install_root}/kubectl"

# ORAS publishes archive hashes inside a signed-release checksum asset. Pin the
# checksum asset itself before trusting the archive entry selected from it.
oras_checksums="${download_root}/oras-checksums.txt"
fetch \
  'https://github.com/oras-project/oras/releases/download/v1.3.3/oras_1.3.3_checksums.txt' \
  '5cf7ff102a941bdb35e8eabfc8cbe937c5387d20e7a2ee75dc4be90410e462cd' \
  "${oras_checksums}"
oras_filename='oras_1.3.3_linux_amd64.tar.gz'
oras_sha256="$(awk -v filename="${oras_filename}" '$2 == filename {print $1}' "${oras_checksums}")"
[[ "${oras_sha256}" =~ ^[0-9a-f]{64}$ ]] || { printf 'ORAS archive checksum entry is missing.\n' >&2; exit 1; }
install_archive_binary \
  "https://github.com/oras-project/oras/releases/download/v1.3.3/${oras_filename}" \
  "${oras_sha256}" \
  'oras' 'oras' 'oras'

# Hadolint ships as one executable rather than an archive, but it crosses the
# same checksum boundary before installation.
hadolint_file="${download_root}/hadolint"
fetch \
  'https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-linux-x86_64' \
  'c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507' \
  "${hadolint_file}"
install -m 0755 "${hadolint_file}" "${install_root}/hadolint"

# GitHub Actions receives the external path through its command file; local
# callers get an explicit instruction instead of this script mutating their
# parent shell.
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "${install_root}" >> "${GITHUB_PATH}"
else
  printf 'Add %s to PATH for this shell.\n' "${install_root}"
fi
printf 'Installed checksum-verified ephemeral tools into %s.\n' "${install_root}"
