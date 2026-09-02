#!/usr/bin/env bash
# Report whether this checkout can run its validation and release gates; this
# script never installs software or weakens a gate to accommodate a workstation.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${repo_root}/versions.env"

# Required tools cover the repository's always-on static policy checks. Optional
# tools unlock lifecycle-specific checks such as cluster, secret, or image work.
required=(git python3 curl jq shellcheck gitleaks kustomize kubeconform conftest tofu)
optional=(kubectl flux age cosign syft trivy actionlint hadolint docker)
missing=0

for command_name in "${required[@]}"; do
  if command -v "${command_name}" >/dev/null 2>&1; then
    printf 'required %-14s present\n' "${command_name}"
  else
    printf 'required %-14s MISSING\n' "${command_name}" >&2
    missing=1
  fi
done

for command_name in "${optional[@]}"; do
  if command -v "${command_name}" >/dev/null 2>&1; then
    printf 'optional %-14s present\n' "${command_name}"
  else
    printf 'optional %-14s absent\n' "${command_name}"
  fi
done

# An unresolved pin means reproducibility has not been established, regardless
# of whether a similarly named executable happens to be installed locally.
if grep -q '=UNRESOLVED$' "${repo_root}/versions.env"; then
  printf 'versions.env contains unresolved pins; release/deployment is blocked\n' >&2
  missing=1
fi

exit "${missing}"
