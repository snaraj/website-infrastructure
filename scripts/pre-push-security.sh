#!/usr/bin/env bash
# Scan one immutable outgoing range before Git uploads it.
set -euo pipefail

fail() {
  printf 'FAIL pre-push security gate did not authorize publication.\n' >&2
  exit 1
}

[[ "$#" -eq 2 ]] || fail
baseline="$1"
candidate="$2"
[[ "${baseline}" =~ ^[0-9a-f]{40,64}$ ]] || fail
[[ "${candidate}" =~ ^[0-9a-f]{40,64}$ ]] || fail
[[ "${baseline}" != "${candidate}" ]] || fail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail
current_head="$(git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || fail
[[ "${candidate}" == "${current_head}" ]] || fail
resolved_baseline="$(git -C "${repo_root}" rev-parse --verify "${baseline}^{commit}" 2>/dev/null)" || fail
[[ "${resolved_baseline}" == "${baseline}" ]] || fail
git -C "${repo_root}" merge-base --is-ancestor "${baseline}" "${candidate}" || fail
[[ "$(git -C "${repo_root}" rev-parse --is-shallow-repository 2>/dev/null)" == "false" ]] || fail

# The index and worktree must still be the exact reviewed commit. Ignored
# custody paths are intentionally irrelevant; every unignored path is blocked.
git -C "${repo_root}" diff --quiet --no-ext-diff --ignore-submodules -- || fail
git -C "${repo_root}" diff --cached --quiet --no-ext-diff --ignore-submodules "${candidate}" -- || fail
[[ -z "$(git -C "${repo_root}" ls-files --others --exclude-standard)" ]] || fail

python_command=""
for candidate_command in python3 python; do
  candidate_path="$(command -v "${candidate_command}" 2>/dev/null || true)"
  if [[ -n "${candidate_path}" ]] && "${candidate_path}" -I -B -c \
    'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' \
    >/dev/null 2>&1; then
    python_command="${candidate_path}"
    break
  fi
done
[[ -n "${python_command}" ]] || fail

# Isolated Python must not find an ignored bytecode or extension-module shadow
# beside the reviewed validators. Cached bytecode is forbidden before and after
# execution; -B additionally prevents the gate itself from creating it.
reject_ambient_python() {
  local path
  local candidates=()
  shopt -s nullglob
  candidates=(
    "${repo_root}/scripts/__pycache__"
    "${repo_root}/scripts/"*.pyc
    "${repo_root}/scripts/"*.pyo
    "${repo_root}/scripts/"*.pyd
    "${repo_root}/scripts/"*.so
    "${repo_root}/scripts/sitecustomize.py"
    "${repo_root}/scripts/usercustomize.py"
  )
  shopt -u nullglob
  for path in "${candidates[@]}"; do
    [[ ! -e "${path}" && ! -L "${path}" ]] || fail
  done
}
reject_ambient_python

# Isolated mode blocks PYTHONPATH, user site packages, and sitecustomize. Load
# each repository-validator dependency from its exact reviewed source before
# validate_repository.py adds its sibling directory to sys.path.
isolated_repository_loader='import pathlib, sys, types
root = pathlib.Path(sys.argv[1]).resolve()
scripts = root / "scripts"
for name in ("workload_registry", "validate_image_release", "validate_release_state", "validate_release_transition", "validate_signature_policy"):
    path = scripts / (name + ".py")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
target = scripts / "validate_repository.py"
sys.argv = [str(target), *sys.argv[2:]]
namespace = {"__name__": "__main__", "__file__": str(target), "__package__": None, "__cached__": None}
exec(compile(target.read_bytes(), str(target), "exec", dont_inherit=True), namespace)'
"${python_command}" -I -B -c "${isolated_repository_loader}" \
  "${repo_root}" all || fail
"${python_command}" -I -B "${repo_root}/scripts/validate_publication_history.py" \
  "${baseline}" "${candidate}" || fail
reject_ambient_python

command -v gitleaks >/dev/null 2>&1 || fail
expected_version="$(awk -F= '
  $1 == "GITLEAKS_VERSION" && $2 ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/ {
    count += 1; value = $2
  }
  END { if (count == 1) print value }
' "${repo_root}/versions.env")"
[[ -n "${expected_version}" ]] || fail
actual_version="$(gitleaks version 2>/dev/null | tr -d '\r\n')" || fail
[[ "${actual_version}" == "${expected_version}" || "v${actual_version}" == "${expected_version}" ]] || fail

# Bind Gitleaks to an empty, owner-only one-use ignore file. This prevents an
# ignored local .gitleaksignore from suppressing a finding without entering the
# reviewed Git boundary. The file remains empty and is removed on every exit.
git_directory="$(git -C "${repo_root}" rev-parse --absolute-git-dir 2>/dev/null)" || fail
[[ -d "${git_directory}" ]] || fail
old_umask="$(umask)"
umask 077
empty_ignore="$(mktemp "${git_directory}/pre-push-gitleaks-ignore.XXXXXX")" || fail
umask "${old_umask}"
cleanup() {
  rm -f -- "${empty_ignore}"
}
abort() {
  trap - EXIT HUP INT TERM
  cleanup
  exit 1
}
trap cleanup EXIT
trap abort HUP INT TERM
[[ -f "${empty_ignore}" && ! -L "${empty_ignore}" && ! -s "${empty_ignore}" ]] || fail

# Both scanners use the same immutable baseline..candidate range. Archives and
# decoded payloads are traversed only to explicit depths, and the Python gate
# rejects every blob larger than the Gitleaks target ceiling before this scan.
gitleaks git \
  --no-banner \
  --no-color \
  --redact \
  --ignore-gitleaks-allow \
  --gitleaks-ignore-path="${empty_ignore}" \
  --max-archive-depth=1 \
  --max-decode-depth=1 \
  --max-target-megabytes=2 \
  --timeout=120 \
  --config "${repo_root}/policies/gitleaks.toml" \
  --log-opts="${baseline}..${candidate}" \
  "${repo_root}" || fail

[[ -f "${empty_ignore}" && ! -L "${empty_ignore}" && ! -s "${empty_ignore}" ]] || fail

[[ "$(git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" == "${candidate}" ]] || fail
git -C "${repo_root}" diff --quiet --no-ext-diff --ignore-submodules -- || fail
git -C "${repo_root}" diff --cached --quiet --no-ext-diff --ignore-submodules "${candidate}" -- || fail
[[ -z "$(git -C "${repo_root}" ls-files --others --exclude-standard)" ]] || fail

printf 'PASS pre-push exact outgoing range: %s..%s\n' "${baseline}" "${candidate}"
