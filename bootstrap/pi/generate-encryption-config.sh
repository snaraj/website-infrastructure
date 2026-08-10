#!/bin/bash
# Generate one Kubernetes API-server secretbox key directly into a protected
# LUKS-backed file. Key material is never accepted through arguments or the
# environment and is never written to stdout or stderr.
set -Eeuo pipefail
set +x
set +o history

# Release safety stop. This is intentionally not an environment-controlled
# feature flag: a mutable checkout cannot establish the stage-zero trust needed
# before generating key material. Keep the latent ceremony reviewable, but do
# not enter it until a separately installed reviewed-blob launcher exists.
readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE}" != yes ]]; then
  builtin printf 'BLOCKED API encryption generation requires the trusted reviewed-blob launcher; no key was generated.\n' >&2
  builtin exit 1
fi

if [[ -n "${BASH_ENV+x}" || -n "${ENV+x}" || -n "${CDPATH+x}" ||
      -n "${GLOBIGNORE+x}" || -n "${LD_PRELOAD+x}" ||
      -n "${LD_LIBRARY_PATH+x}" || -n "${LD_AUDIT+x}" ||
      -n "${LD_DEBUG+x}" || -n "${LD_PROFILE+x}" ||
      -n "$(declare -Fx)" ]]; then
  printf 'FAIL API encryption config generation made no intentional output.\n' >&2
  exit 1
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT \
  LD_DEBUG LD_PROFILE
umask 077
ulimit -S -c 0
ulimit -H -c 0
[[ "$(ulimit -S -c)" == 0 && "$(ulimit -H -c)" == 0 ]] || {
  printf 'FAIL API encryption config generation made no intentional output.\n' >&2
  exit 1
}

output_created=no
fail() {
  if [[ "${output_created}" == yes ]]; then
    printf 'FAIL API encryption config output may exist; retain the protected volume and inspect locally.\n' >&2
  else
    printf 'FAIL API encryption config generation made no intentional output.\n' >&2
  fi
  exit 1
}

[[ "$#" -eq 0 ]] || fail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail
for command_name in awk chmod compgen dirname env findmnt git grep id lsblk \
  mktemp readlink rm sha256sum stat swapon uname; do
  command -v "${command_name}" >/dev/null 2>&1 || fail
done

for ambient_name in PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; do
  [[ -z "${!ambient_name+x}" ]] || fail
done
while IFS= read -r authority_name; do
  case "${authority_name}" in
    API_ENCRYPTION_KEY_NAME|CONFIRM_API_ENCRYPTION_KEY_GENERATION|CREDENTIAL_WORKSPACE|\
    EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256|EXPECTED_REPOSITORY_HEAD|\
    PROTECTED_LINUX_CUSTODY_ATTESTED) ;;
    AWS_*|AZURE_*|GOOGLE_*|GCP_*|HCLOUD_*|VAULT_*|TF_*|TOFU_*|\
    GH_*|GITHUB_*|GIT_*|GCM_*|SSH_*|CF_*|CLOUDFLARE_*|SOPS_*) fail ;;
  esac
done < <(compgen -e)

: "${CREDENTIAL_WORKSPACE:?Set the protected POSIX credential workspace root}"
: "${EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256:?Set the encrypted-filesystem UUID digest}"
: "${EXPECTED_REPOSITORY_HEAD:?Set the exact reviewed main commit}"
: "${API_ENCRYPTION_KEY_NAME:?Set the reviewed key-YYYY-MM name}"
: "${CONFIRM_API_ENCRYPTION_KEY_GENERATION:?Set the exact generation acknowledgement}"
: "${PROTECTED_LINUX_CUSTODY_ATTESTED:?Acknowledge the dedicated Linux custody controls}"
[[ "${EXPECTED_REPOSITORY_HEAD}" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "${EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "${API_ENCRYPTION_KEY_NAME}" =~ ^key-[0-9]{4}-[0-9]{2}$ ]] || fail
[[ "${CONFIRM_API_ENCRYPTION_KEY_GENERATION}" == \
  "generate-reviewed-api-encryption-${API_ENCRYPTION_KEY_NAME}" ]] || fail
[[ "${PROTECTED_LINUX_CUSTODY_ATTESTED}" == \
  encrypted-storage-no-swap-no-coredump-no-cloud-sync-no-session-recording ]] || fail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)" || fail
repo_root="$(cd "${script_dir}/../.." && pwd -P)" || fail
workspace="${CREDENTIAL_WORKSPACE}"
[[ "${workspace}" == /* ]] || fail
workspace="$(readlink -e -- "${workspace}")" || fail
[[ -d "${workspace}" && ! -L "${workspace}" ]] || fail
operator_uid="$(id -u)" || fail
(( operator_uid != 0 )) || fail
workspace_gid="$(stat -c %g -- "${workspace}")" || fail
[[ "$(stat -c '%u:%a' -- "${workspace}")" == "${operator_uid}:700" ]] || fail
current="${workspace}"
while [[ "${current}" != / ]]; do
  [[ ! -L "${current}" ]] || fail
  current="$(dirname -- "${current}")"
done
case "${workspace}/" in "${repo_root}/"*) fail ;; esac

workspace_device="$(stat -c %d -- "${workspace}")" || fail
mount_record="$(findmnt --noheadings --raw --output SOURCE,UUID --target "${workspace}")" || fail
[[ "$(printf '%s\n' "${mount_record}" | grep -c .)" -eq 1 ]] || fail
read -r mount_source mount_uuid mount_extra <<<"${mount_record}"
[[ -n "${mount_source}" && -n "${mount_uuid}" && -z "${mount_extra:-}" ]] || fail
mount_source="${mount_source%%\[*}"
[[ "${mount_source}" == /dev/* && "${mount_uuid}" =~ ^[A-Za-z0-9._:-]+$ ]] || fail
findmnt --noheadings --raw --output OPTIONS --target "${workspace}" | \
  grep -Eq '(^|,)rw(,|$)' || fail
lsblk --inverse --noheadings --raw --output TYPE "${mount_source}" | grep -Fxq crypt || fail
[[ -z "$(swapon --show=NAME --noheadings --raw)" ]] || fail
[[ -r /proc/sys/kernel/yama/ptrace_scope ]] || fail
ptrace_scope="$(</proc/sys/kernel/yama/ptrace_scope)"
[[ "${ptrace_scope}" =~ ^[1-3]$ ]] || fail
mount_uuid_sha256="$(printf '%s\n' "${mount_uuid}" | sha256sum | awk '{print $1}')" || fail
[[ "${mount_uuid_sha256}" == "${EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256}" ]] || fail

python3_binary="$(readlink -e -- /usr/bin/python3)" || fail
[[ "${python3_binary}" =~ ^/usr/bin/python3([.][0-9]+)?$ ]] || fail
[[ -f "${python3_binary}" && ! -L "${python3_binary}" && -x "${python3_binary}" ]] || fail
[[ "$(stat -c '%u:%h' -- "${python3_binary}")" == 0:1 ]] || fail
python3_mode="$(stat -c %a -- "${python3_binary}")" || fail
(( (8#${python3_mode} & 0022) == 0 )) || fail
"${python3_binary}" -I -B -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' || fail

trusted_git() {
  env -i PATH="${PATH}" HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    git --no-replace-objects -c credential.helper= -c core.askPass= \
      -c core.fsmonitor=false -c core.untrackedCache=false "$@"
}

[[ "$(trusted_git -C "${repo_root}" rev-parse --show-toplevel)" == "${repo_root}" ]] || fail
git_dir="$(trusted_git -C "${repo_root}" rev-parse --absolute-git-dir)" || fail
[[ "${git_dir}" == "${repo_root}/.git" && -d "${git_dir}" && ! -L "${git_dir}" ]] || fail
[[ "$(stat -c %u -- "${repo_root}")" == "${operator_uid}" ]] || fail
[[ "$(stat -c %u -- "${git_dir}")" == "${operator_uid}" ]] || fail
repo_mode="$(stat -c %a -- "${repo_root}")" || fail
git_mode="$(stat -c %a -- "${git_dir}")" || fail
(( (8#${repo_mode} & 0022) == 0 && (8#${git_mode} & 0022) == 0 )) || fail
[[ ! -e "${git_dir}/info/grafts" ]] || fail
[[ -z "$(trusted_git -C "${repo_root}" for-each-ref --format='%(refname)' refs/replace)" ]] || fail
[[ "$(trusted_git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}')" == \
  "${EXPECTED_REPOSITORY_HEAD}" ]] || fail
[[ "$(trusted_git -C "${repo_root}" rev-parse --verify 'refs/remotes/origin/main^{commit}')" == \
  "${EXPECTED_REPOSITORY_HEAD}" ]] || fail
[[ "$(trusted_git -C "${repo_root}" symbolic-ref -q HEAD)" == refs/heads/main ]] || fail
[[ "$(trusted_git -C "${repo_root}" rev-parse --is-shallow-repository)" == false ]] || fail
self_blob="$(trusted_git -C "${repo_root}" rev-parse \
  "${EXPECTED_REPOSITORY_HEAD}:bootstrap/pi/generate-encryption-config.sh")" || fail
[[ "$(trusted_git -C "${repo_root}" hash-object --no-filters \
  "${repo_root}/bootstrap/pi/generate-encryption-config.sh")" == "${self_blob}" ]] || fail

temporary="$(mktemp -d "${workspace%/}/api-encryption-generation.XXXXXX")" || fail
generator="${temporary}/generate_encryption_config.py"
validator="${temporary}/validate_encryption_config.py"
parser="${temporary}/validate_kubeadm_config.py"
template="${temporary}/encryption-config.yaml.example"
output="${workspace%/}/api-encryption-config.yaml"
cleanup() {
  if [[ -d "${temporary}" && ! -L "${temporary}" ]]; then
    case "${temporary}" in
      "${workspace}"/api-encryption-generation.*) rm -rf -- "${temporary}" ;;
      *) printf 'Refusing ambiguous API encryption ceremony cleanup target.\n' >&2 ;;
    esac
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "${temporary}"
[[ "$(stat -c '%u:%g:%a:%d' -- "${temporary}")" == \
  "${operator_uid}:${workspace_gid}:700:${workspace_device}" ]] || fail
[[ ! -e "${output}" && ! -L "${output}" ]] || fail

for source_path in scripts/generate_encryption_config.py \
  scripts/validate_encryption_config.py scripts/validate_kubeadm_config.py \
  bootstrap/pi/encryption-config.yaml.example; do
  case "${source_path}" in
    scripts/generate_encryption_config.py) destination="${generator}" ;;
    scripts/validate_encryption_config.py) destination="${validator}" ;;
    scripts/validate_kubeadm_config.py) destination="${parser}" ;;
    bootstrap/pi/encryption-config.yaml.example) destination="${template}" ;;
    *) fail ;;
  esac
  trusted_git -C "${repo_root}" cat-file blob \
    "${EXPECTED_REPOSITORY_HEAD}:${source_path}" > "${destination}" || fail
  chmod 600 "${destination}"
  [[ "$(trusted_git -C "${repo_root}" hash-object --no-filters "${destination}")" == \
    "$(trusted_git -C "${repo_root}" rev-parse "${EXPECTED_REPOSITORY_HEAD}:${source_path}")" ]] || fail
done

if ! PYTHONDONTWRITEBYTECODE=1 "${python3_binary}" -I -B "${generator}" \
  "${validator}" "${template}" "${output}" "${API_ENCRYPTION_KEY_NAME}" \
  >/dev/null 2>/dev/null; then
  [[ ! -e "${output}" && ! -L "${output}" ]] || output_created=yes
  fail
fi
output_created=yes
[[ -f "${output}" && ! -L "${output}" ]] || fail
[[ "$(stat -c '%u:%g:%a:%h:%d' -- "${output}")" == \
  "${operator_uid}:${workspace_gid}:600:1:${workspace_device}" ]] || fail
output_state="$(stat -c '%d:%i:%f:%h:%s:%Y' -- "${output}")" || fail
exec {output_fd}<"${output}" || fail
[[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y' -- "/proc/$$/fd/${output_fd}")" == \
  "${output_state}" ]] || fail
"${python3_binary}" -I -B "${validator}" "/proc/$$/fd/${output_fd}" >/dev/null 2>/dev/null || fail
[[ "$(stat -c '%d:%i:%f:%h:%s:%Y' -- "${output}")" == "${output_state}" ]] || fail
exec {output_fd}<&-

printf 'PASS one protected API encryption configuration was generated without displaying key material.\n'
printf 'GATE create and restore-test two independent encrypted backups before Kubernetes bootstrap.\n'
