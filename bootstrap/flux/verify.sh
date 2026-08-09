#!/usr/bin/env bash
set -euo pipefail

for command_name in kubectl flux git; do
  command -v "${command_name}" >/dev/null 2>&1 || { printf '%s is required\n' "${command_name}" >&2; exit 2; }
done

git ls-remote --exit-code https://github.com/snaraj/website-infrastructure.git refs/heads/main >/dev/null
flux check
flux get sources git -A
flux get kustomizations -A

secret_ref="$(kubectl -n flux-system get gitrepository flux-system -o jsonpath='{.spec.secretRef.name}' 2>/dev/null || true)"
[[ -z "${secret_ref}" ]] || { printf 'FAIL GitRepository has an authentication secretRef.\n' >&2; exit 1; }

git_secret_count="$(kubectl -n flux-system get secret -o jsonpath='{range .items[?(@.type=="kubernetes.io/basic-auth")]}x{end}{range .items[?(@.type=="kubernetes.io/ssh-auth")]}x{end}' | wc -c)"
[[ "${git_secret_count}" -eq 0 ]] || { printf 'FAIL Git authentication Secret exists in flux-system.\n' >&2; exit 1; }
kubectl -n flux-system get secret sops-age >/dev/null

source_args="$(kubectl -n flux-system get deployment source-controller -o jsonpath='{.spec.template.spec.containers[0].args}')"
grep -q -- '--no-cross-namespace-refs=true' <<<"${source_args}" || { printf 'FAIL source cross-namespace refs are not disabled.\n' >&2; exit 1; }
args="$(kubectl -n flux-system get deployment kustomize-controller -o jsonpath='{.spec.template.spec.containers[0].args}')"
grep -q -- '--no-cross-namespace-refs=true' <<<"${args}" || { printf 'FAIL cross-namespace refs are not disabled.\n' >&2; exit 1; }
grep -q -- '--no-remote-bases=true' <<<"${args}" || { printf 'FAIL remote bases are not disabled.\n' >&2; exit 1; }
grep -q -- '--default-service-account=default' <<<"${args}" || { printf 'FAIL Kustomize fallback identity is not denied.\n' >&2; exit 1; }
helm_args="$(kubectl -n flux-system get deployment helm-controller -o jsonpath='{.spec.template.spec.containers[0].args}')"
grep -q -- '--no-cross-namespace-refs=true' <<<"${helm_args}" || { printf 'FAIL Helm cross-namespace refs are not disabled.\n' >&2; exit 1; }
grep -q -- '--default-service-account=default' <<<"${helm_args}" || { printf 'FAIL Helm fallback identity is not denied.\n' >&2; exit 1; }

for namespace in flux-system cloudflare-public naranjo-online; do
  kubectl auth can-i create deployments --as="system:serviceaccount:${namespace}:default" -n "${namespace}" | grep -qx no || {
    printf 'FAIL default fallback identity has workload authority in %s.\n' "${namespace}" >&2
    exit 1
  }
done

printf 'Flux verification passed without printing Secret content. Runtime canary/decrypt/recovery tests remain required.\n'
