#!/bin/bash
# Preserve the documented entry point while sharing the exact protected target
# implementation with bootstrap apply operations.
set -Eeuo pipefail
set +x
set +o history

# Release safety stop. This wrapper must not resolve or execute mutable worktree
# paths before a separately installed reviewed-blob launcher exists.
readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE}" != yes ]]; then
  builtin printf 'BLOCKED Flux verification requires the trusted reviewed-blob launcher; no protected file was read and no cluster request was attempted.\n' >&2
  builtin exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
exec bash "${repo_root}/bootstrap/flux/bootstrap.sh" --verify
