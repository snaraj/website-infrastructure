#!/usr/bin/env bash
# Validate every isolated Cloudflare phase without planning, applying, or
# allowing an ambient Cloudflare credential to reach a child process.
set -euo pipefail
set +x

credential_names=(
  CLOUDFLARE_API_TOKEN
  CLOUDFLARE_API_KEY
  CLOUDFLARE_EMAIL
  CLOUDFLARE_API_USER_SERVICE_KEY
)
for credential_name in "${credential_names[@]}"; do
  if [[ -n "${!credential_name+x}" ]]; then
    printf 'Cloudflare validation requires a credential-free environment.\n' >&2
    exit 2
  fi
done
unset CLOUDFLARE_API_TOKEN CLOUDFLARE_API_KEY CLOUDFLARE_EMAIL \
  CLOUDFLARE_API_USER_SERVICE_KEY

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cloudflare_root="${repo_root}/infrastructure/cloudflare"
phases=(
  admin-tunnel
  admin-policies
  admin-route
  admin-api
  public-edge
  public-dns-naranjo
  public-dns-lidersea
)

command -v tofu >/dev/null 2>&1 || {
  printf 'OpenTofu is required.\n' >&2
  exit 2
}
command -v sha256sum >/dev/null 2>&1 || {
  printf 'sha256sum is required.\n' >&2
  exit 2
}

if [[ -n "${PYTHON_BIN:-}" ]]; then
  python_command="${PYTHON_BIN}"
elif python3 --version >/dev/null 2>&1; then
  python_command=python3
elif python --version >/dev/null 2>&1; then
  python_command=python
else
  printf 'Python 3 is required.\n' >&2
  exit 2
fi

temporary=''
cleanup() {
  if [[ -n "${temporary}" && -d "${temporary}" && ! -L "${temporary}" ]]; then
    case "$(basename -- "${temporary}")" in
      website-cloudflare-validate.*) rm -rf -- "${temporary}" ;;
      *) printf 'Refusing ambiguous validation cleanup target.\n' >&2 ;;
    esac
  fi
}
trap cleanup EXIT
temporary="$(mktemp -d -t website-cloudflare-validate.XXXXXXXX)"
[[ -d "${temporary}" && ! -L "${temporary}" ]] || {
  printf 'Could not create a private validation directory.\n' >&2
  exit 1
}
chmod 700 "${temporary}"

file_sha256() {
  local output digest
  output="$(sha256sum -- "$1")"
  digest="${output%% *}"
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "${digest}"
}

"${python_command}" -B "${repo_root}/scripts/validate_repository.py" cloudflare
tofu -chdir="${cloudflare_root}" fmt -check -recursive

for phase in "${phases[@]}"; do
  phase_root="${cloudflare_root}/phases/${phase}"
  lock_file="${phase_root}/.terraform.lock.hcl"
  data_dir="${temporary}/${phase}"
  [[ -d "${phase_root}" && -f "${lock_file}" && ! -L "${lock_file}" ]] || {
    printf 'A required Cloudflare phase or lock is unavailable.\n' >&2
    exit 1
  }
  mkdir -m 700 -- "${data_dir}"
  lock_before="$(file_sha256 "${lock_file}")"
  TF_DATA_DIR="${data_dir}" tofu -chdir="${phase_root}" init \
    -backend=false -input=false -lockfile=readonly -no-color
  TF_DATA_DIR="${data_dir}" tofu -chdir="${phase_root}" validate -no-color
  lock_after="$(file_sha256 "${lock_file}")"
  [[ "${lock_after}" == "${lock_before}" ]] || {
    printf 'A Cloudflare provider lock changed during validation.\n' >&2
    exit 1
  }
done

"${repo_root}/scripts/test-cloudflare-policy.sh"
printf 'All isolated Cloudflare phase roots validated without credentials.\n'
