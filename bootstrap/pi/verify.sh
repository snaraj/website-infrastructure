#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck disable=SC1091
source "${repo_root}/versions.env"
[[ "${EUID}" -eq 0 ]] || { printf 'Read-only control-plane verification requires root.\n' >&2; exit 2; }
export KUBECONFIG=/etc/kubernetes/admin.conf

for command_name in containerd ctr kubeadm kubelet kubectl; do
  command -v "${command_name}" >/dev/null 2>&1 || { printf 'FAIL %s is missing.\n' "${command_name}" >&2; exit 1; }
done

python3 "${repo_root}/scripts/validate_kubeadm_config.py" /etc/kubernetes/kubeadm-config.yaml
kubeadm config validate --config /etc/kubernetes/kubeadm-config.yaml
[[ "$(kubeadm version -o short)" == "${KUBERNETES_VERSION}" ]]
[[ "$(kubelet --version)" == "Kubernetes ${KUBERNETES_VERSION}" ]]
containerd --version | grep -Fq "v${CONTAINERD_VERSION}"
containerd config dump | grep -Eq 'SystemdCgroup[[:space:]]*=[[:space:]]*true'
# containerd 2.x splits CRI into io.containerd.cri.v1 images+runtime; both rows must be ok.
ctr plugins ls | grep -Eq '^io[.]containerd[.]cri[.]v1[[:space:]]+images[[:space:]].*[[:space:]]ok[[:space:]]*$'
ctr plugins ls | grep -Eq '^io[.]containerd[.]cri[.]v1[[:space:]]+runtime[[:space:]].*[[:space:]]ok[[:space:]]*$'

[[ "$(kubectl get node -o name | wc -l | tr -d ' ')" == 1 ]] || { printf 'FAIL expected exactly one node.\n' >&2; exit 1; }
kubectl wait --for=condition=Ready node --all --timeout=2m
kubectl -n kube-system get pod -l component=kube-apiserver
kubectl -n kube-system get pod -l component=kube-controller-manager
kubectl -n kube-system get pod -l component=kube-scheduler
kubectl -n kube-system get pod -l component=etcd
kubectl -n kube-system rollout status deployment/coredns --timeout=2m

taints="$(kubectl get node -o jsonpath='{range .items[*].spec.taints[*]}{.key}{"="}{.effect}{"\n"}{end}')"
if grep -Eq 'node-role[.]kubernetes[.]io/control-plane=.*NoSchedule' <<<"${taints}"; then
  printf 'FAIL the single control-plane node is unschedulable.\n' >&2
  exit 1
fi

bad_services="$(kubectl get service -A -o jsonpath='{range .items[?(@.spec.type!="ClusterIP")]}{.metadata.namespace}/{.metadata.name}:{.spec.type}{"\n"}{end}')"
[[ -z "${bad_services}" ]] || { printf 'FAIL non-ClusterIP Services:\n%s\n' "${bad_services}" >&2; exit 1; }
bootstrap_tokens="$(kubectl -n kube-system get secret -o name | grep '^secret/bootstrap-token-' || true)"
[[ -z "${bootstrap_tokens}" ]] || { printf 'FAIL bootstrap tokens remain:\n%s\n' "${bootstrap_tokens}" >&2; exit 1; }

grep -Fq -- '--encryption-provider-config=/etc/kubernetes/encryption/encryption-config.yaml' /etc/kubernetes/manifests/kube-apiserver.yaml
grep -Fq -- '--audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml' /etc/kubernetes/manifests/kube-apiserver.yaml
grep -Fq -- '--admission-control-config-file=/etc/kubernetes/admission/psa.yaml' /etc/kubernetes/manifests/kube-apiserver.yaml
test -s /var/log/kubernetes/audit/audit.log
kubeadm certs check-expiration
kubectl get pods -A -o wide
kubectl get events -A --sort-by=.lastTimestamp
printf 'PASS read-only kubeadm control-plane verification succeeded.\n'
printf 'Still required: encryption/PSA/NetworkPolicy canaries, snapshot+restore, reboot, VPN/firewall regression, and remote-access tests.\n'
