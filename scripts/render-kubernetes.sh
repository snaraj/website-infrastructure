#!/usr/bin/env bash
# Compatibility entry point retained for Make/CI callers. The canonical renderer
# owns the target list so a legacy invocation cannot omit either site or the
# Flux reconciliation root.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec bash "${repo_root}/scripts/render-manifests.sh" "$@"
