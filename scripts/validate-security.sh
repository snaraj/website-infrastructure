#!/usr/bin/env bash
# Run the repository's layered security contract: structural invariants first,
# policy controls second, and executable admission behavior when available.
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
"${python_command}" -B "${repo_root}/scripts/validate_repository.py" layout privacy secrets workflows kubernetes cloudflare
bash "${repo_root}/scripts/test-policy-fixtures.sh"

# Kyverno CLI fixtures verify runtime admission semantics beyond static YAML;
# missing tooling is surfaced as pending so it cannot be mistaken for a pass.
if command -v kyverno >/dev/null 2>&1 && [[ -d "${repo_root}/tests/kubernetes/kyverno" ]]; then
  kyverno test "${repo_root}/tests/kubernetes/kyverno"
else
  printf 'PENDING Kyverno CLI tests: tool or fixtures unavailable.\n'
fi
