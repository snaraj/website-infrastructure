#!/usr/bin/env bash
# Run the repository's layered security contract: structural invariants first,
# then executable static policy controls.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# Python remains limited to dependency-free policy checks; allow callers and
# Windows Git Bash to select the real interpreter instead of a store shim.
if [[ -n "${PYTHON_BIN:-}" ]]; then
  python_command="${PYTHON_BIN}"
elif python3 --version >/dev/null 2>&1; then
  python_command=python3
elif python --version >/dev/null 2>&1; then
  python_command=python
else
  printf 'Python 3 is required for repository policy validation\n' >&2
  exit 2
fi
# Every repository mode except the deliberate release gate runs here; the
# short entry point previously omitted media and activation, so it could pass
# while the terminal CI gate ('all') still failed.
"${python_command}" -B "${repo_root}/scripts/validate_repository.py" layout privacy media secrets workflows dependabot kubernetes cloudflare activation
bash "${repo_root}/scripts/test-policy-fixtures.sh"
"${python_command}" -B "${repo_root}/scripts/validate_assurance_ledger.py" "${repo_root}/docs/assurance/evidence-ledger.jsonl"
"${python_command}" -B "${repo_root}/scripts/validate_no_security_toggles.py" "${repo_root}"
"${python_command}" -B "${repo_root}/scripts/validate_attack_surface_manifest.py" "${repo_root}/docs/assurance/attack-surface-manifest.json"
