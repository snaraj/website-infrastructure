#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck disable=SC1091
source "${repo_root}/versions.env"
mode="${1:---check}"
config_path="${KUBEADM_CONFIG_PATH:-${repo_root}/bootstrap/pi/kubeadm-config.yaml.local}"
encryption_path="${ENCRYPTION_CONFIG_PATH:-${repo_root}/bootstrap/pi/encryption-config.yaml.local}"
cni_path="${CNI_MANIFEST_PATH:-${repo_root}/bootstrap/pi/cni-manifest.local.yaml}"
images_lock_path="${IMAGES_LOCK_PATH:-${repo_root}/bootstrap/pi/images.lock.local}"

die() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

locked_digest() {
  local reference="$1"
  awk -v ref="${reference}" '$1 == ref {print $2}' "${images_lock_path}"
}

verify_local_image() {
  local reference="$1"
  local expected="$2"
  local actual
  [[ "${expected}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "missing reviewed digest for ${reference}"
  actual="$(ctr -n k8s.io images list 2>/dev/null | awk -v ref="${reference}" '$1 == ref {print $3}')"
  [[ "${actual}" == "${expected}" ]] || die "local image target mismatch for ${reference}: ${actual:-absent}"
  printf 'PASS local image target matches lock: %s\n' "${reference}"
}

delete_bootstrap_tokens() {
  local list_output first_field delete_failed=0
  local -a tokens=()

  if ! list_output="$(kubeadm token list 2>/dev/null)"; then
    printf 'FAIL kubeadm bootstrap-token inventory failed.\n' >&2
    return 1
  fi

  while IFS=$' \t' read -r first_field _; do
    if [[ "${first_field}" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]]; then
      tokens+=("${first_field}")
    fi
  done <<<"${list_output}"
  unset list_output first_field

  for token in "${tokens[@]}"; do
    if ! kubeadm token delete "${token}" >/dev/null 2>&1; then
      # Do not echo the bearer token. Continue so every inventoried token gets
      # a deletion attempt, then fail the initialization as a whole.
      printf 'FAIL kubeadm bootstrap-token deletion failed.\n' >&2
      delete_failed=1
    fi
  done
  unset token tokens

  (( delete_failed == 0 ))
}

assert_no_bootstrap_token_secrets() {
  local secret_output secret_name

  if ! secret_output="$(
    kubectl -n kube-system get secrets \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null
  )"; then
    printf 'FAIL Kubernetes bootstrap-token Secret inventory failed.\n' >&2
    return 1
  fi

  while IFS= read -r secret_name; do
    if [[ "${secret_name}" == bootstrap-token-* ]]; then
      printf 'FAIL a Kubernetes bootstrap-token Secret remains.\n' >&2
      return 1
    fi
  done <<<"${secret_output}"
  unset secret_output secret_name
}

best_effort_delete_bootstrap_tokens() {
  local secret_output resource

  # Prefer kubeadm so the normal token lifecycle is used. If its inventory is
  # unavailable during partial initialization, fall back to deleting only the
  # narrowly named bootstrap-token Secrets through the API.
  delete_bootstrap_tokens || true
  if assert_no_bootstrap_token_secrets; then
    return 0
  fi

  if ! secret_output="$(kubectl -n kube-system get secrets -o name 2>/dev/null)"; then
    return 1
  fi
  while IFS= read -r resource; do
    if [[ "${resource}" == secret/bootstrap-token-* ]]; then
      kubectl -n kube-system delete "${resource}" --wait=true >/dev/null 2>&1 || true
    fi
  done <<<"${secret_output}"
  unset secret_output resource
  assert_no_bootstrap_token_secrets
}

# Sourcing exposes only the narrowly testable helpers above. Operational work
# occurs only when this file is executed.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

bash "${repo_root}/bootstrap/pi/preflight.sh" --phase init
kubeadm config validate --config "${config_path}"

mapfile -t kubeadm_images < <(kubeadm config images list --config "${config_path}")
[[ "${#kubeadm_images[@]}" -eq 7 ]] || die "expected seven kubeadm bootstrap images, found ${#kubeadm_images[@]}"
for image in "${kubeadm_images[@]}"; do
  digest="$(locked_digest "${image}")"
  [[ "$(grep -Ec "^${image//./[.]}[[:space:]]" "${images_lock_path}")" == 1 ]] || \
    die "image lock must contain ${image} exactly once"
  verify_local_image "${image}" "${digest}"
done

mapfile -t cni_images < <(awk '$1 == "image:" {print $2}' "${cni_path}" | sort -u)
(( ${#cni_images[@]} > 0 )) || die 'rendered CNI manifest contains no images'
for image in "${cni_images[@]}"; do
  digest="$(locked_digest "${image}")"
  verify_local_image "${image}" "${digest}"
done

dry_run_log="$(mktemp)"
trap 'rm -f -- "${dry_run_log}"' EXIT
if ! kubeadm init --dry-run --skip-token-print --config "${config_path}" >"${dry_run_log}" 2>&1; then
  printf 'FAIL kubeadm dry-run failed; inspect locally without sharing tokens or addresses.\n' >&2
  exit 1
fi
rm -f -- "${dry_run_log}"
trap - EXIT

if [[ "${mode}" == "--check" ]]; then
  printf 'PASS kubeadm validation, image lock, runtime images, and dry-run succeeded. No cluster was created.\n'
  exit 0
fi
[[ "${mode}" == "--apply" ]] || die "usage: $0 [--check|--apply]"
[[ "${EUID}" -eq 0 ]] || die 'apply mode requires root'
[[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || die 'recovery acknowledgement missing'
[[ "${CONFIRM_KUBEADM_INIT:-}" == "initialize-reviewed-${KUBERNETES_VERSION}" ]] || \
  die 'exact kubeadm initialization acknowledgement missing'

# Image verification and kubeadm dry-run can consume most of the runtime
# evidence freshness window. Re-run the complete protected-host gate at the
# last safe boundary before creating any control-plane path.
bash "${repo_root}/bootstrap/pi/preflight.sh" --phase init

install -d -m 0700 /etc/kubernetes/admission /etc/kubernetes/audit /etc/kubernetes/encryption
install -d -m 0700 /var/log/kubernetes/audit
install -m 0600 "${repo_root}/bootstrap/pi/psa.yaml" /etc/kubernetes/admission/psa.yaml
install -m 0600 "${repo_root}/bootstrap/pi/audit.yaml" /etc/kubernetes/audit/audit-policy.yaml
install -m 0600 "${encryption_path}" /etc/kubernetes/encryption/encryption-config.yaml
install -m 0600 "${config_path}" /etc/kubernetes/kubeadm-config.yaml
install -m 0600 "${cni_path}" /etc/kubernetes/cni-bootstrap.yaml
install -m 0600 "${images_lock_path}" /etc/kubernetes/images.lock

systemctl start kubelet.service
init_log="$(mktemp)"
init_attempted=no
cleanup_failure() {
  status=$?
  trap - EXIT
  set +e
  rm -f -- "${init_log}"
  if (( status != 0 )); then
    if [[ "${init_attempted}" == yes && -r /etc/kubernetes/admin.conf ]]; then
      export KUBECONFIG=/etc/kubernetes/admin.conf
      if ! best_effort_delete_bootstrap_tokens; then
        printf 'WARN best-effort bootstrap-token cleanup could not prove zero remaining Secrets.\n' >&2
      fi
    fi
    printf 'FAIL initialization stopped with partial state. Do not run kubeadm reset; inspect locally and use the recovery runbook.\n' >&2
  fi
  exit "${status}"
}
trap cleanup_failure EXIT
init_attempted=yes
kubeadm init --skip-token-print --config /etc/kubernetes/kubeadm-config.yaml >"${init_log}" 2>&1
rm -f -- "${init_log}"

export KUBECONFIG=/etc/kubernetes/admin.conf
delete_bootstrap_tokens
assert_no_bootstrap_token_secrets
printf 'PASS all kubeadm bootstrap tokens were deleted immediately after initialization.\n'

CONFIRM_ETCD_SNAPSHOT=create-reviewed-stacked-etcd-snapshot \
  /usr/local/sbin/website-infrastructure-etcd-snapshot --apply
printf 'PASS first verified local stacked-etcd snapshot completed before CNI installation.\n'

kubectl apply --server-side --field-manager=kubeadm-cni-bootstrap -f /etc/kubernetes/cni-bootstrap.yaml
kubectl wait --for=condition=Ready node --all --timeout=10m
kubectl -n kube-system rollout status deployment/coredns --timeout=5m

# Recheck at the final success boundary so a later step cannot accidentally
# report success while a bootstrap bearer token exists.
assert_no_bootstrap_token_secrets

trap - EXIT
printf 'PASS upstream Kubernetes control plane initialized and the reviewed CNI applied.\n'
printf 'Run bootstrap/pi/verify.sh, reboot verification, policy canaries, and snapshot acceptance before Flux.\n'
