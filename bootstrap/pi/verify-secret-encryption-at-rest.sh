#!/bin/bash
# Prove that one disposable Kubernetes Secret is stored as secretbox ciphertext
# in the local stacked-etcd member. Secret material and raw etcd bytes remain in
# a root-private runtime directory and are never printed or placed in arguments.
set -Eeuo pipefail
set +x
set +o history

# Release safety stop. Even check mode opens cluster and etcd credentials in the
# latent implementation below. A mutable root-run checkout is not a stage-zero
# trust boundary, and the installed etcdctl binary does not yet have its own
# reviewed executable digest pin. No caller-supplied variable can reopen this
# path.
readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no
if [[ "${REVIEWED_BLOB_LAUNCHER_AVAILABLE}" != yes ]]; then
  builtin printf 'BLOCKED Secret encryption-at-rest canary requires the trusted reviewed-blob launcher and an installed etcdctl digest pin; no protected file was read and no cluster or etcd request was attempted.\n' >&2
  builtin exit 1
fi

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

die() {
  printf 'FAIL Secret encryption-at-rest canary phase=%s.\n' "${phase:-preflight}" >&2
  exit 1
}

phase=preflight
mode="${1:---check}"
[[ "$#" -le 1 ]] || die
case "${mode}" in
  --check|--dry-run|--apply) ;;
  *) die ;;
esac
[[ "${EUID}" -eq 0 ]] || die

# Ambient client configuration must not redirect either trusted local client.
for ambient_name in KUBECONFIG KUBECTL_PLUGINS_PATH HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy ETCDCTL_ENDPOINTS ETCDCTL_CACERT \
  ETCDCTL_CERT ETCDCTL_KEY ETCDCTL_USER ETCDCTL_PASSWORD; do
  [[ -z "${!ambient_name+x}" ]] || die
done
unset KUBECONFIG KUBECTL_PLUGINS_PATH HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy ETCDCTL_ENDPOINTS ETCDCTL_CACERT \
  ETCDCTL_CERT ETCDCTL_KEY ETCDCTL_USER ETCDCTL_PASSWORD

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
if [[ -n "${WEBSITE_INFRA_VERSIONS_FILE:-}" ]]; then
  versions_file="${WEBSITE_INFRA_VERSIONS_FILE}"
elif [[ -r "${repo_root}/versions.env" ]]; then
  versions_file="${repo_root}/versions.env"
else
  versions_file=/etc/website-infrastructure/versions.env
fi

kubectl=/usr/local/bin/kubectl
etcdctl=/usr/local/bin/etcdctl
default_kubeconfig=/etc/kubernetes/admin.conf
kubeconfig_path="${KUBECONFIG_FILE:-${default_kubeconfig}}"
endpoint=https://127.0.0.1:2379
ca_path=/etc/kubernetes/pki/etcd/ca.crt
cert_path=/etc/kubernetes/pki/etcd/healthcheck-client.crt
key_path=/etc/kubernetes/pki/etcd/healthcheck-client.key
encryption_config=/etc/kubernetes/encryption/encryption-config.yaml
apiserver_manifest=/etc/kubernetes/manifests/kube-apiserver.yaml
audit_policy=/etc/kubernetes/audit/audit-policy.yaml
audit_log=/var/log/kubernetes/audit/audit.log
expected_audit_policy_sha256=1ad3d8a3456afd638c279c4593a0defe2b0f3f7e3f4719a7952a5cbd586ab453

# The namespace is deliberately pre-existing and dedicated. This canary never
# creates or deletes a namespace, so even failure cleanup cannot cascade.
canary_namespace=website-infrastructure-encryption-canary
canary_name=secret-at-rest-canary
canary_manager=secret-encryption-at-rest-canary-v1
etcd_key="/registry/secrets/${canary_namespace}/${canary_name}"
encrypted_prefix='k8s:enc:secretbox:v1:'

require_command() {
  command -v "$1" >/dev/null 2>&1 || die
}

canonical_public_file() {
  local candidate="$1" current resolved
  [[ "${candidate}" == /* ]] || return 1
  resolved="$(readlink -e -- "${candidate}")" || return 1
  [[ "${resolved}" == "${candidate}" ]] || return 1
  current="${candidate}"
  while [[ "${current}" != / ]]; do
    [[ ! -L "${current}" ]] || return 1
    current="$(dirname -- "${current}")"
  done
  [[ -f "${candidate}" && ! -L "${candidate}" ]] || return 1
  [[ "$(stat -c '%a:%h' -- "${candidate}")" == 644:1 ]]
}

canonical_regular_file() {
  local candidate="$1" expected_modes="$2" current resolved mode_bits
  [[ "${candidate}" == /* ]] || return 1
  resolved="$(readlink -e -- "${candidate}")" || return 1
  [[ "${resolved}" == "${candidate}" ]] || return 1
  current="${candidate}"
  while [[ "${current}" != / ]]; do
    [[ ! -L "${current}" ]] || return 1
    current="$(dirname -- "${current}")"
  done
  [[ -f "${candidate}" && ! -L "${candidate}" ]] || return 1
  [[ "$(stat -c '%u:%g:%h' -- "${candidate}")" == 0:0:1 ]] || return 1
  mode_bits="$(stat -c %a -- "${candidate}")" || return 1
  case " ${expected_modes} " in *" ${mode_bits} "*) ;; *) return 1 ;; esac
}

pin() {
  local name="$1"
  awk -F= -v key="${name}" '
    $1 == key && $2 ~ /^[A-Za-z0-9._:+@\/-]+$/ { count += 1; value = $2 }
    END { if (count == 1) print value }
  ' "${versions_file}"
}

tool_state() {
  local path="$1"
  stat -c '%d:%i:%f:%h:%s:%Y:%Z' -- "${path}"
}

verify_bound_file() {
  local path="$1" descriptor="$2" expected_state="$3"
  [[ "$(tool_state "${path}")" == "${expected_state}" ]] || return 1
  [[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y:%Z' -- "/proc/$$/fd/${descriptor}")" == "${expected_state}" ]]
}

validate_fixed_tool() {
  local path="$1"
  canonical_regular_file "${path}" '755' || return 1
  [[ -x "${path}" ]]
}

for command_name in awk base64 chmod cmp dirname flock grep head id kill mapfile mktemp \
  readlink rm rmdir sed sha256sum sleep stat tail tr wc; do
  require_command "${command_name}"
done

canonical_public_file "${versions_file}" || die
kubernetes_version="$(pin KUBERNETES_VERSION)"
kubectl_sha256="$(pin KUBECTL_ARM64_SHA256)"
etcd_version="$(pin ETCD_VERSION)"
etcd_tools_arm64_sha256="$(pin ETCD_TOOLS_ARM64_SHA256)"
[[ "${kubernetes_version}" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]] || die
[[ "${kubectl_sha256}" =~ ^[0-9a-f]{64}$ ]] || die
[[ "${etcd_version}" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] || die
[[ "${etcd_tools_arm64_sha256}" =~ ^[0-9a-f]{64}$ ]] || die

validate_fixed_tool "${kubectl}" || die
validate_fixed_tool "${etcdctl}" || die
kubectl_state="$(tool_state "${kubectl}")" || die
etcdctl_state="$(tool_state "${etcdctl}")" || die
[[ "$(sha256sum -- "${kubectl}" | awk '{print $1}')" == "${kubectl_sha256}" ]] || die
kubectl_client="$("${kubectl}" version --client -o yaml 2>/dev/null)" || die
[[ "$(printf '%s\n' "${kubectl_client}" | grep -c "^[[:space:]]*gitVersion: ${kubernetes_version}$")" -eq 1 ]] || die
actual_etcd_version="$("${etcdctl}" version 2>/dev/null | awk -F': ' '$1 == "etcdctl version" {print $2; exit}')" || die
[[ "${actual_etcd_version}" == "${etcd_version}" ]] || die
[[ "$(tool_state "${kubectl}")" == "${kubectl_state}" ]] || die
[[ "$(tool_state "${etcdctl}")" == "${etcdctl_state}" ]] || die

python3_binary="$(readlink -e -- /usr/bin/python3)" || die
[[ "${python3_binary}" =~ ^/usr/bin/python3([.][0-9]+)?$ ]] || die
canonical_regular_file "${python3_binary}" '555 755' || die
python3_mode="$(stat -c %a -- "${python3_binary}")" || die
(( (8#${python3_mode} & 0022) == 0 )) || die
"${python3_binary}" -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' || die

: "${EXPECTED_KUBECONFIG_CONTEXT:?Set the exact reviewed Kubernetes context}"
: "${EXPECTED_KUBERNETES_SERVER:?Set the exact reviewed Kubernetes API URL}"
: "${EXPECTED_PI_NODE_NAME:?Set the exact reviewed single Pi node name}"
[[ "${EXPECTED_KUBECONFIG_CONTEXT}" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,126}$ ]] || die
[[ "${EXPECTED_KUBERNETES_SERVER}" =~ ^https://[^/@[:space:]]+:[0-9]{1,5}$ ]] || die
[[ "${EXPECTED_PI_NODE_NAME}" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] || die
canonical_regular_file "${kubeconfig_path}" '400 600' || die
if [[ -z "${KUBECONFIG_FILE:-}" ]]; then
  [[ "${kubeconfig_path}" == "${default_kubeconfig}" ]] || die
fi
kubeconfig_state="$(tool_state "${kubeconfig_path}")" || die
exec {kubeconfig_fd}<"${kubeconfig_path}" || die
verify_bound_file "${kubeconfig_path}" "${kubeconfig_fd}" "${kubeconfig_state}" || die
kubeconfig="/proc/$$/fd/${kubeconfig_fd}"
kubectl_config_args=(--kubeconfig="${kubeconfig}" --context="${EXPECTED_KUBECONFIG_CONTEXT}")
kubectl_target_args=("${kubectl_config_args[@]}" --server="${EXPECTED_KUBERNETES_SERVER}" --request-timeout=15s)

# Inspect only the redacted kubeconfig view. Exact embedded-data field names
# forbid credential plugins, path-based credentials, bearer tokens and proxies.
if ! "${kubectl}" "${kubectl_config_args[@]}" config view --minify -o json 2>/dev/null | \
  "${python3_binary}" -I -c '
import json
import sys
try:
    document = json.load(sys.stdin)
    context_name, server = sys.argv[1:]
    if set(document) != {"apiVersion", "clusters", "contexts", "current-context", "kind", "preferences", "users"}:
        raise ValueError()
    if document["apiVersion"] != "v1" or document["kind"] != "Config" or document["current-context"] != context_name:
        raise ValueError()
    if len(document["clusters"]) != 1 or len(document["contexts"]) != 1 or len(document["users"]) != 1:
        raise ValueError()
    cluster = document["clusters"][0]["cluster"]
    user = document["users"][0]["user"]
    context = document["contexts"][0]
    if set(cluster) not in ({"certificate-authority-data", "server"}, {"certificate-authority-data", "server", "tls-server-name"}):
        raise ValueError()
    if cluster["server"] != server:
        raise ValueError()
    if set(user) != {"client-certificate-data", "client-key-data"}:
        raise ValueError()
    if context["name"] != context_name or set(context["context"]) not in ({"cluster", "user"}, {"cluster", "namespace", "user"}):
        raise ValueError()
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
' "${EXPECTED_KUBECONFIG_CONTEXT}" "${EXPECTED_KUBERNETES_SERVER}"
then
  die
fi
verify_bound_file "${kubeconfig_path}" "${kubeconfig_fd}" "${kubeconfig_state}" || die

for tls_path in "${ca_path}" "${cert_path}" "${key_path}"; do
  canonical_regular_file "${tls_path}" '400 600 644' || die
done
[[ "$(stat -c %a -- "${key_path}")" =~ ^(400|600)$ ]] || die
ca_state="$(tool_state "${ca_path}")" || die
cert_state="$(tool_state "${cert_path}")" || die
key_state="$(tool_state "${key_path}")" || die
exec {ca_fd}<"${ca_path}" || die
exec {cert_fd}<"${cert_path}" || die
exec {key_fd}<"${key_path}" || die
verify_bound_file "${ca_path}" "${ca_fd}" "${ca_state}" || die
verify_bound_file "${cert_path}" "${cert_fd}" "${cert_state}" || die
verify_bound_file "${key_path}" "${key_fd}" "${key_state}" || die
etcd_tls_args=(
  --endpoints="${endpoint}"
  --dial-timeout=5s
  --command-timeout=15s
  --cacert="/proc/$$/fd/${ca_fd}"
  --cert="/proc/$$/fd/${cert_fd}"
  --key="/proc/$$/fd/${key_fd}"
)

canonical_regular_file "${encryption_config}" '400 600' || die
[[ -f "${repo_root}/scripts/validate_encryption_config.py" && ! -L "${repo_root}/scripts/validate_encryption_config.py" ]] || die
"${python3_binary}" -I "${repo_root}/scripts/validate_encryption_config.py" "${encryption_config}" >/dev/null 2>&1 || die
canonical_regular_file "${audit_policy}" '400 600 644' || die
[[ "$(sha256sum -- "${audit_policy}" | awk '{print $1}')" == "${expected_audit_policy_sha256}" ]] || die
canonical_regular_file "${audit_log}" '600 640' || die
canonical_regular_file "${apiserver_manifest}" '600 644' || die
grep -Fq -- '--encryption-provider-config=/etc/kubernetes/encryption/encryption-config.yaml' "${apiserver_manifest}" || die
grep -Fq -- '--audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml' "${apiserver_manifest}" || die
grep -Fq -- '--audit-log-path=/var/log/kubernetes/audit/audit.log' "${apiserver_manifest}" || die

verify_cluster_target() {
  local actual_context actual_server node_names namespace_shape target_name
  verify_bound_file "${kubeconfig_path}" "${kubeconfig_fd}" "${kubeconfig_state}" || return 1
  [[ "$(tool_state "${kubectl}")" == "${kubectl_state}" ]] || return 1
  [[ "$(sha256sum -- "${kubectl}" | awk '{print $1}')" == "${kubectl_sha256}" ]] || return 1
  actual_context="$("${kubectl}" --kubeconfig="${kubeconfig}" config current-context 2>/dev/null)" || return 1
  actual_server="$("${kubectl}" "${kubectl_config_args[@]}" config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)" || return 1
  node_names="$("${kubectl}" "${kubectl_target_args[@]}" get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)" || return 1
  namespace_shape="$("${kubectl}" "${kubectl_target_args[@]}" get namespace "${canary_namespace}" -o go-template='{{.metadata.name}} {{.status.phase}} {{index .metadata.labels "security.website-infrastructure/canary-purpose"}} {{if .metadata.deletionTimestamp}}deleting{{else}}stable{{end}}' 2>/dev/null)" || return 1
  target_name="$("${kubectl}" "${kubectl_target_args[@]}" -n "${canary_namespace}" get secret "${canary_name}" --ignore-not-found -o name 2>/dev/null)" || return 1
  [[ "${actual_context}" == "${EXPECTED_KUBECONFIG_CONTEXT}" ]] || return 1
  [[ "${actual_server}" == "${EXPECTED_KUBERNETES_SERVER}" ]] || return 1
  [[ "${node_names}" == "${EXPECTED_PI_NODE_NAME}" ]] || return 1
  [[ "${namespace_shape}" == "${canary_namespace} Active secret-encryption-at-rest-v1 stable" ]] || return 1
  [[ -z "${target_name}" ]]
}

if ! ETCDCTL_API=3 "${etcdctl}" "${etcd_tls_args[@]}" endpoint health >/dev/null 2>&1; then
  die
fi
verify_bound_file "${ca_path}" "${ca_fd}" "${ca_state}" || die
verify_bound_file "${cert_path}" "${cert_fd}" "${cert_state}" || die
verify_bound_file "${key_path}" "${key_fd}" "${key_state}" || die
[[ "$(tool_state "${etcdctl}")" == "${etcdctl_state}" ]] || die
verify_cluster_target || die

if [[ "${mode}" == --check || "${mode}" == --dry-run ]]; then
  printf 'PASS Secret encryption-at-rest canary preflight verified; no Kubernetes object, firewall, VPN, SSH, or service change made.\n'
  printf 'GATE the fixed canary namespace must remain dedicated and carry the reviewed purpose label before --apply.\n'
  exit 0
fi

# These acknowledgements are checked at the final safe boundary, before even a
# runtime directory or lock file is created.
[[ "${PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes ]] || die
[[ "${TWO_WORKING_SESSIONS_PROVEN:-}" == yes ]] || die
[[ "${CONFIRM_SECRET_ENCRYPTION_AT_REST_CANARY:-}" == run-reviewed-secret-encryption-at-rest-canary ]] || die

phase='runtime-staging'
temporary="$(mktemp -d /run/website-infrastructure-secret-encryption-at-rest.XXXXXXXX)" || die
[[ -d "${temporary}" && ! -L "${temporary}" ]] || die
chmod 0700 "${temporary}"
[[ "$(stat -c '%u:%g:%a' -- "${temporary}")" == 0:0:700 ]] || die
marker="${temporary}/marker"
expected_encoded="${temporary}/expected-encoded"
candidate="${temporary}/candidate.json"
annotated="${temporary}/annotated.json"
manifest="${temporary}/manifest.json"
create_error="${temporary}/create.stderr"
identity_file="${temporary}/identity"
observed_encoded="${temporary}/observed-encoded"
etcd_record="${temporary}/etcd-record.json"
raw_value="${temporary}/raw-etcd-value"
etcd_error="${temporary}/etcd.stderr"
delete_options="${temporary}/delete-options.json"
delete_response="${temporary}/delete-response.json"
proxy_log="${temporary}/proxy.log"
proxy_socket="${temporary}/kubectl-proxy.sock"
proxy_client_error="${temporary}/proxy-client.stderr"
absence_file="${temporary}/absence"
audit_slice="${temporary}/audit-slice.jsonl"
audit_parser_error="${temporary}/audit-parser.stderr"
runtime_files=(
  "${marker}" "${expected_encoded}" "${candidate}" "${annotated}" "${manifest}"
  "${create_error}" "${identity_file}" "${observed_encoded}" "${etcd_record}"
  "${raw_value}" "${etcd_error}" "${delete_options}" "${delete_response}"
  "${proxy_log}" "${proxy_socket}" "${proxy_client_error}" "${absence_file}" "${audit_slice}"
  "${audit_parser_error}"
)
mutation_attempted=no
cleanup_complete=no
cleanup_uncertain=no
proxy_pid=''
target_uid=''
target_resource_version=''

cleanup_runtime() {
  local path
  [[ -n "${temporary:-}" ]] || return 0
  case "${temporary}" in /run/website-infrastructure-secret-encryption-at-rest.*) ;; *) return 1 ;; esac
  [[ -d "${temporary}" && ! -L "${temporary}" ]] || return 1
  [[ "$(stat -c '%u:%g:%a' -- "${temporary}" 2>/dev/null)" == 0:0:700 ]] || return 1
  for path in "${runtime_files[@]}"; do
    [[ "${path}" == "${temporary}/"* ]] || return 1
    rm -f -- "${path}" || return 1
  done
  rmdir -- "${temporary}"
}

stop_proxy() {
  if [[ -n "${proxy_pid}" ]]; then
    kill "${proxy_pid}" >/dev/null 2>&1 || true
    wait "${proxy_pid}" >/dev/null 2>&1 || true
    proxy_pid=''
  fi
}

secret_absent() {
  : > "${absence_file}"
  "${kubectl}" "${kubectl_target_args[@]}" -n "${canary_namespace}" get secret "${canary_name}" \
    --ignore-not-found -o name >"${absence_file}" 2>/dev/null || return 1
  [[ ! -s "${absence_file}" ]]
}

capture_owned_identity() {
  local -a lines=()
  : > "${identity_file}"
  : > "${observed_encoded}"
  "${kubectl}" "${kubectl_target_args[@]}" -n "${canary_namespace}" get secret "${canary_name}" \
    -o go-template='{{.metadata.uid}}{{"\n"}}{{.metadata.resourceVersion}}{{"\n"}}{{.type}}{{"\n"}}{{len .data}}{{"\n"}}{{index .metadata.annotations "security.website-infrastructure/managed-by"}}{{"\n"}}{{.immutable}}{{"\n"}}' \
    >"${identity_file}" 2>/dev/null || return 1
  "${kubectl}" "${kubectl_target_args[@]}" -n "${canary_namespace}" get secret "${canary_name}" \
    -o go-template='{{index .data "canary-marker"}}' >"${observed_encoded}" 2>/dev/null || return 1
  cmp -s -- "${expected_encoded}" "${observed_encoded}" || return 1
  mapfile -t lines < "${identity_file}"
  [[ "${#lines[@]}" -eq 6 ]] || return 1
  [[ "${lines[0]}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  [[ "${lines[1]}" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "${lines[2]}" == Opaque && "${lines[3]}" == 1 ]] || return 1
  [[ "${lines[4]}" == "${canary_manager}" && "${lines[5]}" == true ]] || return 1
  captured_uid="${lines[0]}"
  captured_resource_version="${lines[1]}"
}

precondition_delete() {
  local api_path _attempt
  api_path="/api/v1/namespaces/${canary_namespace}/secrets/${canary_name}"
  rm -f -- "${delete_response}"
  printf '{"apiVersion":"v1","kind":"DeleteOptions","gracePeriodSeconds":0,"propagationPolicy":"Background","preconditions":{"uid":"%s","resourceVersion":"%s"}}\n' \
    "${target_uid}" "${target_resource_version}" > "${delete_options}" || return 1

  : > "${proxy_log}"
  "${kubectl}" "${kubectl_config_args[@]}" --server="${EXPECTED_KUBERNETES_SERVER}" proxy \
    --unix-socket="${proxy_socket}" \
    --accept-hosts='^localhost$' \
    --accept-paths="^${api_path}$" \
    --reject-methods='^(GET|POST|PUT|PATCH|CONNECT|HEAD|OPTIONS|TRACE)$' \
    >"${proxy_log}" 2>&1 &
  proxy_pid=$!
  for _attempt in {1..50}; do
    kill -0 "${proxy_pid}" >/dev/null 2>&1 || break
    [[ -S "${proxy_socket}" ]] && break
    sleep 0.1
  done
  [[ -S "${proxy_socket}" && ! -L "${proxy_socket}" ]] || { stop_proxy; return 1; }
  [[ "$(stat -c '%u:%g' -- "${proxy_socket}")" == 0:0 ]] || { stop_proxy; return 1; }

  if ! "${python3_binary}" -I - "${proxy_socket}" "${api_path}" "${delete_options}" "${delete_response}" \
    2>"${proxy_client_error}" <<'PY'
import http.client
import os
import socket
import sys


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path):
        super().__init__("localhost", timeout=10)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


try:
    socket_path, path, request_path, response_path = sys.argv[1:]
    payload = open(request_path, "rb").read(4097)
    if not payload or len(payload) > 4096:
        raise ValueError()
    connection = UnixHTTPConnection(socket_path)
    connection.request("DELETE", path, body=payload, headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    body = response.read(1_048_577)
    connection.close()
    if response.status not in (200, 202) or len(body) > 1_048_576:
        raise ValueError()
    descriptor = os.open(response_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, body)
    finally:
        os.close(descriptor)
except (OSError, ValueError, http.client.HTTPException):
    raise SystemExit(1)
PY
  then
    stop_proxy
    return 1
  fi
  stop_proxy
  for _attempt in {1..50}; do
    secret_absent && return 0
    sleep 0.1
  done
  return 1
}

cleanup_secret() {
  if secret_absent; then
    cleanup_complete=yes
    return 0
  fi
  capture_owned_identity || return 1
  if [[ -z "${target_uid}" ]]; then
    target_uid="${captured_uid}"
    target_resource_version="${captured_resource_version}"
  else
    [[ "${captured_uid}" == "${target_uid}" ]] || return 1
    [[ "${captured_resource_version}" == "${target_resource_version}" ]] || return 1
  fi
  precondition_delete || return 1
  cleanup_complete=yes
}

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  stop_proxy
  if [[ "${mutation_attempted:-no}" == yes && "${cleanup_complete:-no}" != yes ]]; then
    if ! cleanup_secret; then
      cleanup_uncertain=yes
      status=1
      printf 'RECOVERY exact canary Secret cleanup is uncertain; no broad deletion was attempted.\n' >&2
      printf 'RECOVERY retain and inspect the single root-private canary runtime directory locally.\n' >&2
    fi
  fi
  if [[ "${cleanup_uncertain:-no}" != yes ]]; then
    cleanup_runtime || {
      status=1
      printf 'RECOVERY root-private canary runtime cleanup is incomplete; inspect it locally.\n' >&2
    }
  fi
  exit "${status}"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

exec 9>/run/lock/website-infrastructure-secret-encryption-at-rest.lock
chmod 0600 /run/lock/website-infrastructure-secret-encryption-at-rest.lock
flock -n 9 || die

phase='marker-generation'
/usr/bin/head -c 48 /dev/urandom | /usr/bin/base64 -w 0 > "${marker}" || die
[[ "$(stat -c '%u:%g:%a:%h:%s' -- "${marker}")" == 0:0:600:1:64 ]] || die
grep -Eq '^[A-Za-z0-9+/]{64}$' "${marker}" || die
/usr/bin/base64 -w 0 < "${marker}" > "${expected_encoded}" || die
[[ -s "${expected_encoded}" ]] || die

phase='manifest-staging'
"${kubectl}" "${kubectl_config_args[@]}" -n "${canary_namespace}" create secret generic "${canary_name}" \
  --type=Opaque --from-file="canary-marker=${marker}" --dry-run=client -o json \
  >"${candidate}" 2>"${create_error}" || die
"${kubectl}" "${kubectl_config_args[@]}" annotate --local -f "${candidate}" --overwrite -o json \
  "security.website-infrastructure/managed-by=${canary_manager}" \
  >"${annotated}" 2>"${create_error}" || die
"${kubectl}" "${kubectl_config_args[@]}" patch --local -f "${annotated}" --type=json \
  -p='[{"op":"add","path":"/immutable","value":true}]' -o json \
  >"${manifest}" 2>"${create_error}" || die

verify_cluster_target || die
verify_bound_file "${ca_path}" "${ca_fd}" "${ca_state}" || die
verify_bound_file "${cert_path}" "${cert_fd}" "${cert_state}" || die
verify_bound_file "${key_path}" "${key_fd}" "${key_state}" || die
[[ "$(tool_state "${etcdctl}")" == "${etcdctl_state}" ]] || die
audit_inode="$(stat -c '%d:%i' -- "${audit_log}")" || die
audit_size="$(stat -c %s -- "${audit_log}")" || die

phase='secret-create'
mutation_attempted=yes
"${kubectl}" "${kubectl_target_args[@]}" create -f "${manifest}" -o name \
  >/dev/null 2>"${create_error}" || die
capture_owned_identity || die
target_uid="${captured_uid}"
target_resource_version="${captured_resource_version}"

phase='raw-etcd-proof'
if ! ETCDCTL_API=3 "${etcdctl}" "${etcd_tls_args[@]}" --write-out=json \
  get "${etcd_key}" --limit=1 >"${etcd_record}" 2>"${etcd_error}"; then
  die
fi
"${python3_binary}" -I - "${etcd_record}" "${raw_value}" "${etcd_key}" "${target_resource_version}" \
  2>"${etcd_error}" <<'PY' || die
import base64
import binascii
import json
import os
import sys

try:
    record_path, raw_path, expected_key, expected_revision = sys.argv[1:]
    with open(record_path, "rb") as stream:
        document = json.load(stream)
    kvs = document.get("kvs")
    count = document.get("count", len(kvs) if isinstance(kvs, list) else -1)
    if not isinstance(kvs, list) or len(kvs) != 1 or str(count) != "1":
        raise ValueError()
    item = kvs[0]
    key = base64.b64decode(item["key"], validate=True).decode("utf-8")
    value = base64.b64decode(item["value"], validate=True)
    if key != expected_key or str(item["mod_revision"]) != expected_revision or not value:
        raise ValueError()
    descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value)
    finally:
        os.close(descriptor)
except (OSError, UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError, binascii.Error):
    raise SystemExit(1)
PY
[[ "$(stat -c '%u:%g:%a:%h' -- "${raw_value}")" == 0:0:600:1 ]] || die
[[ "$(head -c "${#encrypted_prefix}" "${raw_value}")" == "${encrypted_prefix}" ]] || die
if LC_ALL=C grep -aFq -f "${marker}" "${raw_value}"; then
  die
fi

phase='precondition-cleanup'
cleanup_secret || die

phase='audit-metadata-proof'
audit_verified=no
for _attempt in {1..15}; do
  if [[ "$(stat -c '%d:%i' -- "${audit_log}" 2>/dev/null)" == "${audit_inode}" ]] \
    && [[ "$(stat -c %s -- "${audit_log}" 2>/dev/null)" -ge "${audit_size}" ]]; then
    tail -c "+$((audit_size + 1))" -- "${audit_log}" > "${audit_slice}" 2>/dev/null || true
    if "${python3_binary}" -I - "${audit_slice}" "${canary_namespace}" "${canary_name}" \
      2>"${audit_parser_error}" <<'PY'
import json
import sys

seen = set()
try:
    with open(sys.argv[1], "rb") as stream:
        for raw_line in stream:
            if not raw_line.strip():
                continue
            event = json.loads(raw_line)
            reference = event.get("objectRef", {})
            if (
                reference.get("apiVersion") == "v1"
                and reference.get("resource") == "secrets"
                and reference.get("namespace") == sys.argv[2]
                and reference.get("name") == sys.argv[3]
                and event.get("stage") == "ResponseComplete"
            ):
                if "requestObject" in event or "responseObject" in event:
                    raise ValueError()
                code = event.get("responseStatus", {}).get("code")
                if not isinstance(code, int) or not 200 <= code < 300:
                    raise ValueError()
                seen.add(event.get("verb"))
except (OSError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if {"create", "get", "delete"}.issubset(seen) else 1)
PY
    then
      audit_verified=yes
      break
    fi
  fi
  sleep 1
done
if [[ "${audit_verified}" != yes ]]; then
  printf 'GATE audit metadata-only records could not be proven from the unchanged local log; inspect locally before acceptance.\n' >&2
  die
fi

phase=complete
printf 'PASS raw stacked-etcd value used the expected secretbox prefix and contained no plaintext marker bytes.\n'
printf 'PASS exact UID/resourceVersion-preconditioned canary cleanup completed and metadata-only audit events were verified.\n'
printf 'No firewall, VPN, SSH, Kubernetes service, or host service setting was changed.\n'
