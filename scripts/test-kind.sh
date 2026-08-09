#!/usr/bin/env bash
# Exercise rendered policy and RBAC against a disposable, loopback-only Kind
# control plane; this is a local integration check, not the production kubeadm
# topology or a substitute for the Pi's reviewed CNI decision.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${repo_root}/versions.env"

# These identifiers establish ownership of the only cluster this harness may
# create or delete. The explicit acknowledgement makes mutation opt-in.
readonly cluster_name="website-infra-local-test"
readonly cluster_context="kind-${cluster_name}"
readonly apply_ack="I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test"
readonly local_only_label="platform.snaraj.dev/local-kind-test"

# Mutable ownership state starts empty and becomes cleanup-authoritative only
# after the newly created Docker container has been uniquely identified.
temp_root=""
kubeconfig_file=""
cluster_cleanup_authorized=0
owned_container_id=""
new_temp_path=""
naranjo_render_path=""
lidersea_render_path=""
cloudflare_render_path=""
runtime_mode=0
repository_release_mode='scaffold'
declare -a temp_files=()

# log keeps expected progress on stdout while failures use die and stderr.
log() {
  printf '%s\n' "$*"
}

# die gives all fail-closed branches one consistent non-success exit.
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

# remember_temp_file records individually owned paths so cleanup never relies on
# a recursive delete of an ambiguous directory.
remember_temp_file() {
  temp_files+=("$1")
}

# cluster_exists checks the local Docker-backed Kind inventory without matching
# substrings, preventing accidental reuse of somebody else's test cluster.
cluster_exists() {
  local candidate
  local clusters
  clusters="$(env KIND_EXPERIMENTAL_PROVIDER=docker kind get clusters)" || \
    die "could not enumerate local Kind clusters"
  while IFS= read -r candidate; do
    [[ "${candidate}" == "${cluster_name}" ]] && return 0
  done <<<"${clusters}"
  return 1
}

# cleanup deletes the cluster only when its current container identity still
# matches the one created by this run, then removes only registered temp files.
cleanup() {
  local original_status="$1"
  local cleanup_status=0
  local current_container_id
  local temp_file
  trap - EXIT INT TERM
  set +e

  if (( cluster_cleanup_authorized == 1 )); then
    # Re-read Docker state at deletion time so a replaced or expanded cluster is
    # never treated as the disposable object this process originally created.
    current_container_id="$(docker ps -aq \
      --filter "label=io.x-k8s.kind.cluster=${cluster_name}")"
    if [[ -z "${owned_container_id}" || "${current_container_id}" != "${owned_container_id}" ]]; then
      printf 'ERROR: refusing cleanup because Kind container ownership changed for %s\n' \
        "${cluster_name}" >&2
      cleanup_status=1
    else
      log "Cleaning only disposable Kind cluster ${cluster_name}."
      env \
        KIND_EXPERIMENTAL_PROVIDER=docker \
        KUBECONFIG="${kubeconfig_file}" \
        kind delete cluster --name "${cluster_name}" || cleanup_status=1
    fi
  fi

  for temp_file in "${temp_files[@]}"; do
    if [[ -n "${temp_root}" && "${temp_file}" == "${temp_root}/"* ]]; then
      rm -f -- "${temp_file}" || cleanup_status=1
    fi
  done
  if [[ -n "${temp_root}" && -d "${temp_root}" ]]; then
    rmdir -- "${temp_root}" || cleanup_status=1
  fi

  if (( original_status == 0 && cleanup_status != 0 )); then
    original_status=1
  fi
  exit "${original_status}"
}

# require_command refuses implicit installation, keeping this harness offline
# and leaving workstation changes under human control.
require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required; this harness never installs tools"
}

# require_exact_version binds parsing and rendering behavior to versions.env.
require_exact_version() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  [[ "${actual}" == "${expected}" ]] || die "${label} version ${actual:-unknown} does not match ${expected}"
  log "PASS ${label} ${actual}"
}

# extract_semver normalizes the different version output shapes used by pinned
# Kubernetes utilities without accepting an unversioned executable.
extract_semver() {
  local value="$1"
  if [[ "${value}" =~ v?([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    printf 'v%s\n' "${BASH_REMATCH[1]}"
  else
    return 1
  fi
}

# check_local_docker rejects TCP and SSH Docker endpoints because cleanup and
# cluster mutation are authorized only on the operator's local engine.
check_local_docker() {
  local docker_context
  local docker_endpoint
  local docker_host="${DOCKER_HOST:-}"

  docker_context="$(docker context show)"
  docker_endpoint="$(docker context inspect --format '{{ .Endpoints.docker.Host }}' "${docker_context}")"

  case "${docker_endpoint}" in
    unix:///*|npipe://*) ;;
    *) die "Docker context ${docker_context} is not a local Unix socket or Windows named pipe (${docker_endpoint:-unknown})" ;;
  esac
  if [[ -n "${docker_host}" ]]; then
    case "${docker_host}" in
      unix:///*|npipe://*) ;;
      *) die "DOCKER_HOST is not local (${docker_host}); refusing remote Docker access" ;;
    esac
  fi

  docker info --format '{{ .ServerVersion }}' >/dev/null
  log "PASS Docker context ${docker_context} uses local endpoint ${docker_endpoint}"
}

# check_optional_tool runs extra policy layers when present but still requires
# their exact pinned version, so an optional check cannot silently change meaning.
check_optional_tool() {
  local command_name="$1"
  local expected="$2"
  local version_output
  local actual

  if ! command -v "${command_name}" >/dev/null 2>&1; then
    log "SKIP ${command_name}: optional pinned validator is not installed"
    return 0
  fi

  case "${command_name}" in
    kubeconform) version_output="$(kubeconform -v)" ;;
    conftest) version_output="$(conftest --version)" ;;
    kyverno) version_output="$(kyverno version)" ;;
    *) die "unsupported optional validator ${command_name}" ;;
  esac
  actual="$(extract_semver "${version_output}")" || die "could not parse ${command_name} version"
  require_exact_version "${command_name}" "${actual}" "${expected}"
}

# check_prerequisites proves the complete no-download execution boundary before
# --apply is allowed to create any Docker or Kubernetes object.
check_prerequisites() {
  local kind_output
  local kind_actual
  local kubectl_output
  local kubectl_actual
  local helm_actual
  local kustomize_actual

  : "${KIND_VERSION:?KIND_VERSION is required in versions.env}"
  : "${KIND_NODE_IMAGE:?KIND_NODE_IMAGE is required in versions.env}"
  : "${KUBERNETES_VERSION:?KUBERNETES_VERSION is required in versions.env}"
  : "${HELM_VERSION:?HELM_VERSION is required in versions.env}"
  : "${KUSTOMIZE_VERSION:?KUSTOMIZE_VERSION is required in versions.env}"
  [[ "${KIND_NODE_IMAGE}" =~ ^kindest/node:v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]] || \
    die "KIND_NODE_IMAGE must be a full kindest/node tag and sha256 digest"

  for command_name in kind kubectl helm kustomize docker; do
    require_command "${command_name}"
  done

  kind_output="$(kind version)"
  kind_actual="$(extract_semver "${kind_output}")" || die "could not parse kind version"
  require_exact_version "kind" "${kind_actual}" "${KIND_VERSION}"

  kubectl_output="$(kubectl version --client=true --output=yaml)"
  kubectl_actual="$(extract_semver "${kubectl_output}")" || die "could not parse kubectl client version"
  require_exact_version "kubectl" "${kubectl_actual}" "${KUBERNETES_VERSION}"

  helm_actual="$(helm version --template '{{ .Version }}')"
  require_exact_version "helm" "${helm_actual}" "v${HELM_VERSION#v}"

  kustomize_actual="$(extract_semver "$(kustomize version)")" || die "could not parse kustomize version"
  require_exact_version "kustomize" "${kustomize_actual}" "${KUSTOMIZE_VERSION}"

  check_local_docker
  # The node image must already exist by digest; Kind is not allowed to pull
  # mutable or network-derived input during this integration test.
  docker image inspect "${KIND_NODE_IMAGE}" >/dev/null 2>&1 || \
    die "pinned node image is not present locally: ${KIND_NODE_IMAGE}; preload it outside this harness"
  log "PASS pinned Kind node image is already local"

  if cluster_exists; then
    die "Kind cluster ${cluster_name} already exists; it will not be reused or deleted"
  fi
  log "PASS disposable cluster name ${cluster_name} is unused"

  check_optional_tool conftest "${CONFTEST_VERSION}"
  check_optional_tool kyverno "${KYVERNO_CLI_VERSION}"
}

# new_temp_file allocates a path inside the proven temp root and registers it
# before a caller writes data, preserving deterministic cleanup after failure.
new_temp_file() {
  local name="$1"
  new_temp_path="${temp_root}/${name}"
  remember_temp_file "${new_temp_path}"
}

# reject_remote_kustomize_sources keeps every rendered byte attributable to the
# checked-out repository rather than fetching a moving base during the test.
reject_remote_kustomize_sources() {
  local manifest
  while IFS= read -r manifest; do
    if grep -Eq '(https?://|ssh://|git::|github\.com/|gitlab\.com/|bitbucket\.org/|\.git//)' \
      "${manifest}"; then
      die "remote Kustomize source is forbidden in the offline Kind harness: ${manifest}"
    fi
  done < <(find "${repo_root}/kubernetes" -type f -name 'kustomization.yaml' -print)
}

# render_local_artifacts produces the same Helm/Kustomize desired state Flux will
# reconcile, then applies available policy validators without starting workloads.
render_local_artifacts() {
  local naranjo_render
  local lidersea_render
  local cloudflare_render
  local target
  local output
  local output_name
  local rendered
  local -a kustomize_targets=(
    kubernetes/reconciliation
    kubernetes/platform/prerequisites
    kubernetes/platform/admission
    kubernetes/platform/cloudflare-public/release
    kubernetes/websites/naranjo-online
    kubernetes/websites/lidersea-com
  )
  local -a rendered_files=()

  reject_remote_kustomize_sources
  # Helm dependencies would create another network and provenance path, so this
  # offline harness accepts only self-contained repository charts.
  if grep -Eq '^[[:space:]]*dependencies:' "${repo_root}/websites/naranjo.online/chart/Chart.yaml" \
    || grep -Eq '^[[:space:]]*dependencies:' "${repo_root}/websites/lidersea.com/chart/Chart.yaml" \
    || grep -Eq '^[[:space:]]*dependencies:' "${repo_root}/kubernetes/platform/cloudflare-public/chart/Chart.yaml"; then
    die "Helm chart dependencies are forbidden in this offline harness"
  fi

  helm lint "${repo_root}/websites/naranjo.online/chart"
  new_temp_file naranjo-online.yaml
  naranjo_render="${new_temp_path}"
  helm template naranjo-online "${repo_root}/websites/naranjo.online/chart" \
    --namespace naranjo-online > "${naranjo_render}"
  rendered_files+=("${naranjo_render}")

  helm lint "${repo_root}/websites/lidersea.com/chart"
  new_temp_file lidersea-com.yaml
  lidersea_render="${new_temp_path}"
  helm template lidersea-com "${repo_root}/websites/lidersea.com/chart" \
    --namespace lidersea-com > "${lidersea_render}"
  rendered_files+=("${lidersea_render}")

  helm lint "${repo_root}/kubernetes/platform/cloudflare-public/chart"
  new_temp_file cloudflare-public.yaml
  cloudflare_render="${new_temp_path}"
  helm template cloudflare-public "${repo_root}/kubernetes/platform/cloudflare-public/chart" \
    --namespace cloudflare-public > "${cloudflare_render}"
  rendered_files+=("${cloudflare_render}")

  for target in "${kustomize_targets[@]}"; do
    # Flatten either POSIX or Windows separators into a portable temp name.
    output_name="${target//\//-}"
    output_name="${output_name//\\\\/-}"
    new_temp_file "${output_name}.yaml"
    output="${new_temp_path}"
    kustomize build "${repo_root}/${target}" > "${output}"
    rendered_files+=("${output}")
  done

  for rendered in "${rendered_files[@]}"; do
    if command -v conftest >/dev/null 2>&1; then
      conftest test --policy "${repo_root}/policies/conftest" "${rendered}"
    fi
  done

  if command -v conftest >/dev/null 2>&1; then
    bash "${repo_root}/scripts/test-policy-fixtures.sh"
    if [[ "$repository_release_mode" == 'scaffold' ]]; then
      if conftest test --policy "${repo_root}/policies/release-conftest" \
        "${naranjo_render}" >/dev/null 2>&1; then
        die "naranjo.online release gate unexpectedly accepted the sentinel chart"
      fi
      log "PASS release policy rejects the intentionally inactive naranjo.online chart"
      if conftest test --policy "${repo_root}/policies/release-conftest" \
        "${lidersea_render}" >/dev/null 2>&1; then
        die "lidersea.com release gate unexpectedly accepted the sentinel chart"
      fi
      log "PASS release policy rejects the intentionally inactive lidersea.com chart"
    else
      conftest test --policy "${repo_root}/policies/release-conftest" \
        "$naranjo_render" "$lidersea_render"
      log 'PASS release policy accepts both active site charts'
    fi
  else
    log "SKIP Conftest policy fixtures and release-policy negative test: conftest is unavailable"
  fi

  if command -v kyverno >/dev/null 2>&1; then
    kyverno test "${repo_root}/tests/kubernetes/kyverno"
  else
    log "SKIP Kyverno CLI fixtures: kyverno is unavailable"
  fi

  log "SKIP Kubeconform: no offline schema bundle is committed; the local API server validates core workload output"

  naranjo_render_path="${naranjo_render}"
  lidersea_render_path="${lidersea_render}"
  cloudflare_render_path="${cloudflare_render}"
}

# assert_release_sentinels proves the repository is still intentionally inert;
# if promotion gates change, this harness must be extended before applying YAML.
assert_release_sentinels() {
  grep -Eq '^deploymentReady:[[:space:]]+false$' \
    "${repo_root}/websites/naranjo.online/chart/values.yaml" || \
    die "naranjo.online deploymentReady sentinel is no longer false; extend this harness before running workloads"
  grep -Eq '^  digest:[[:space:]]+sha256:0{64}$' \
    "${repo_root}/websites/naranjo.online/chart/values.yaml" || \
    die "naranjo.online all-zero digest sentinel changed; extend this harness before running workloads"
  grep -Eq '^deploymentReady:[[:space:]]+false$' \
    "${repo_root}/websites/lidersea.com/chart/values.yaml" || \
    die "lidersea.com deploymentReady sentinel is no longer false; extend this harness before running workloads"
  grep -Eq '^  digest:[[:space:]]+sha256:0{64}$' \
    "${repo_root}/websites/lidersea.com/chart/values.yaml" || \
    die "lidersea.com all-zero digest sentinel changed; extend this harness before running workloads"
  grep -Eq '^  suspend:[[:space:]]+true$' \
    "${repo_root}/kubernetes/websites/naranjo-online/release.yaml" || \
    die "naranjo.online HelmRelease is no longer suspended; extend this harness before running workloads"
  grep -Eq '^  suspend:[[:space:]]+true$' \
    "${repo_root}/kubernetes/websites/lidersea-com/release.yaml" || \
    die "lidersea.com HelmRelease is no longer suspended; extend this harness before running workloads"
  grep -Eq '^  suspend:[[:space:]]+true$' \
    "${repo_root}/kubernetes/platform/cloudflare-public/release/release.yaml" || \
    die "cloudflare-public HelmRelease is no longer suspended; extend this harness before running workloads"
  grep -Eq '^    tokenRevision:[[:space:]]+not-configured$' \
    "${repo_root}/kubernetes/platform/cloudflare-public/release/release.yaml" || \
    die "tunnel token sentinel changed; extend this harness before running workloads"
  for file in \
    "${repo_root}/kubernetes/reconciliation/admission.yaml" \
    "${repo_root}/kubernetes/reconciliation/platform-services.yaml" \
    "${repo_root}/kubernetes/reconciliation/naranjo-online.yaml" \
    "${repo_root}/kubernetes/reconciliation/lidersea-com.yaml"; do
    grep -Eq '^  suspend:[[:space:]]+true$' "$file" || \
      die "outer reconciliation is no longer suspended in ${file}"
  done
  grep -Eq 'platform\.snaraj\.dev/deployment-ready:[[:space:]]+"false"$' \
    "${repo_root}/kubernetes/platform/admission/kyverno/controllers.yaml" || \
    die 'admission controller readiness sentinel changed'
  grep -Eq 'image:.*@sha256:0{64}$' \
    "${repo_root}/kubernetes/platform/admission/kyverno/controllers.yaml" || \
    die 'admission controller all-zero digest sentinel changed'
}

detect_repository_release_mode() {
  local suspended=0 active=0 file
  for file in \
    "${repo_root}/kubernetes/websites/naranjo-online/release.yaml" \
    "${repo_root}/kubernetes/websites/lidersea-com/release.yaml" \
    "${repo_root}/kubernetes/platform/cloudflare-public/release/release.yaml" \
    "${repo_root}/kubernetes/reconciliation/admission.yaml" \
    "${repo_root}/kubernetes/reconciliation/platform-services.yaml" \
    "${repo_root}/kubernetes/reconciliation/naranjo-online.yaml" \
    "${repo_root}/kubernetes/reconciliation/lidersea-com.yaml"; do
    if grep -Eq '^  suspend:[[:space:]]+true$' "$file"; then
      suspended=$((suspended + 1))
    elif grep -Eq '^  suspend:[[:space:]]+false$' "$file"; then
      active=$((active + 1))
    else
      die "release suspension is not explicit in ${file}"
    fi
  done
  if (( suspended == 7 && active == 0 )); then
    repository_release_mode='scaffold'
    assert_release_sentinels
  elif (( active == 7 && suspended == 0 )); then
    repository_release_mode='release'
    grep -Eq '^deploymentReady:[[:space:]]+true$' "${repo_root}/websites/naranjo.online/chart/values.yaml" || \
      die 'active naranjo.online release lacks deploymentReady=true'
    grep -Eq '^deploymentReady:[[:space:]]+true$' "${repo_root}/websites/lidersea.com/chart/values.yaml" || \
      die 'active lidersea.com release lacks deploymentReady=true'
    if grep -Eq '^  digest:[[:space:]]+sha256:0{64}$' \
      "${repo_root}/websites/naranjo.online/chart/values.yaml" \
      "${repo_root}/websites/lidersea.com/chart/values.yaml"; then
      die 'active site release still contains an all-zero digest'
    fi
  else
    die 'mixed admission/site/tunnel suspension is forbidden; all seven release gates must transition together'
  fi
  log "PASS repository release mode is internally consistent: ${repository_release_mode}"
}

# write_kind_config pins the test API to loopback and labels the sole node with
# the ownership marker checked again after creation.
write_kind_config() {
  local config_file="$1"
  cat > "${config_file}" <<EOF
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
networking:
  apiServerAddress: "127.0.0.1"
nodes:
  - role: control-plane
    labels:
      ${local_only_label}: "true"
EOF
}

# write_bootstrap_namespace creates only the Flux namespace primitive needed to
# test repository RBAC, with the production Pod Security posture already active.
write_bootstrap_namespace() {
  local namespace_file="$1"
  cat > "${namespace_file}" <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: flux-system
  labels:
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.36
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.36
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.36
EOF
}

# write_psa_negative_fixture supplies a deliberately privileged Pod so the test
# proves admission rejection instead of merely inspecting namespace labels.
write_psa_negative_fixture() {
  local fixture_file="$1"
  cat > "${fixture_file}" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: must-be-rejected-by-psa
  namespace: naranjo-online
spec:
  restartPolicy: Never
  containers:
    - name: insecure
      image: registry.k8s.io/pause:3.10.2
      securityContext:
        privileged: true
EOF
}

# kubectl_local forces every command through the generated kubeconfig and exact
# Kind context, avoiding whichever cluster the operator normally uses.
kubectl_local() {
  kubectl --kubeconfig "${kubeconfig_file}" --context "${cluster_context}" "$@"
}

# assert_can_i turns each intended Flux/Helm permission boundary into executable
# API-server evidence, including important negative permissions.
assert_can_i() {
  local expected="$1"
  shift
  local actual
  actual="$(kubectl_local auth can-i "$@")"
  [[ "${actual}" == "${expected}" ]] || die "RBAC expected ${expected} for kubectl auth can-i $*, got ${actual}"
  log "PASS RBAC ${expected}: $*"
}

# require_runtime_image accepts only the canonical repository plus an immutable,
# non-zero digest already present in the local Docker content store. Runtime mode
# never builds, pulls, signs, or substitutes an image.
require_runtime_image() {
  local label="$1"
  local image="$2"
  local expected_repository="$3"
  local repo_digests
  [[ "$image" =~ ^${expected_repository}@sha256:[0-9a-f]{64}$ ]] || \
    die "${label} must be ${expected_repository}@sha256:<64 lowercase hex>"
  [[ "$image" != *'@sha256:0000000000000000000000000000000000000000000000000000000000000000' ]] || \
    die "${label} must not use the all-zero digest"
  docker image inspect "$image" >/dev/null 2>&1 || \
    die "${label} is not present locally by exact digest; preload it outside this harness"
  repo_digests="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image")"
  grep -Fxq -- "$image" <<<"$repo_digests" || \
    die "${label} local image metadata does not contain the exact requested RepoDigest"
  log "PASS ${label} exact digest is already present locally"
}

check_runtime_inputs() {
  : "${NARANJO_RUNTIME_IMAGE:?Set NARANJO_RUNTIME_IMAGE to the locally preloaded candidate digest}"
  : "${LIDERSEA_RUNTIME_IMAGE:?Set LIDERSEA_RUNTIME_IMAGE to the locally preloaded candidate digest}"
  require_runtime_image NARANJO_RUNTIME_IMAGE "$NARANJO_RUNTIME_IMAGE" 'ghcr\.io/snaraj/naranjo-online'
  require_runtime_image LIDERSEA_RUNTIME_IMAGE "$LIDERSEA_RUNTIME_IMAGE" 'ghcr\.io/snaraj/lidersea-com'
}

write_capacity_probe() {
  local fixture_file="$1"
  cat >"$fixture_file" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: must-be-rejected-by-zero-capacity
  namespace: naranjo-online
spec:
  automountServiceAccountToken: false
  serviceAccountName: naranjo-online
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: ${NARANJO_RUNTIME_IMAGE}
      imagePullPolicy: Never
      resources:
        requests: {cpu: 1m, memory: 1Mi}
        limits: {cpu: 10m, memory: 16Mi}
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
        readOnlyRootFilesystem: true
EOF
}

render_runtime_sites() {
  local naranjo_digest="${NARANJO_RUNTIME_IMAGE#*@}"
  local lidersea_digest="${LIDERSEA_RUNTIME_IMAGE#*@}"
  local desired_naranjo desired_lidersea

  if [[ "$repository_release_mode" == 'release' ]]; then
    desired_naranjo="$(awk '$1 == "image:" {gsub(/"/, "", $2); print $2}' "$naranjo_render_path")"
    desired_lidersea="$(awk '$1 == "image:" {gsub(/"/, "", $2); print $2}' "$lidersea_render_path")"
    [[ "$desired_naranjo" == "$NARANJO_RUNTIME_IMAGE" ]] || \
      die 'NARANJO_RUNTIME_IMAGE differs from the active desired Deployment image'
    [[ "$desired_lidersea" == "$LIDERSEA_RUNTIME_IMAGE" ]] || \
      die 'LIDERSEA_RUNTIME_IMAGE differs from the active desired Deployment image'
    log 'PASS runtime candidate digests exactly match active desired state'
  fi

  new_temp_file naranjo-online-runtime.yaml
  naranjo_render_path="$new_temp_path"
  helm template naranjo-online "${repo_root}/websites/naranjo.online/chart" \
    --namespace naranjo-online \
    --set deploymentReady=true \
    --set image.pullPolicy=Never \
    --set-string "image.digest=${naranjo_digest}" >"$naranjo_render_path"

  new_temp_file lidersea-com-runtime.yaml
  lidersea_render_path="$new_temp_path"
  helm template lidersea-com "${repo_root}/websites/lidersea.com/chart" \
    --namespace lidersea-com \
    --set deploymentReady=true \
    --set image.pullPolicy=Never \
    --set-string "image.digest=${lidersea_digest}" >"$lidersea_render_path"

  if command -v conftest >/dev/null 2>&1; then
    conftest test --policy "${repo_root}/policies/conftest" "$naranjo_render_path" "$lidersea_render_path"
    conftest test --policy "${repo_root}/policies/release-conftest" "$naranjo_render_path" "$lidersea_render_path"
  fi
  log 'PASS candidate two-site render is accepted by static and release-state policy'
}

assert_service_ready() {
  local namespace="$1"
  local name="$2"
  local body
  kubectl_local -n "$namespace" rollout status "deployment/${name}" --timeout=180s
  kubectl_local -n "$namespace" wait --for=condition=Ready pod \
    -l "app.kubernetes.io/name=${name},app.kubernetes.io/instance=${name}" --timeout=180s
  body="$(kubectl_local get --raw "/api/v1/namespaces/${namespace}/services/http:${name}:http/proxy/readyz")"
  [[ "$body" == 'ok' ]] || die "${namespace}/${name} Service proxy readiness returned an unexpected body"
  [[ "$(kubectl_local -n "$namespace" get deployment "$name" -o jsonpath='{.status.observedGeneration}')" == \
     "$(kubectl_local -n "$namespace" get deployment "$name" -o jsonpath='{.metadata.generation}')" ]] || \
    die "${namespace}/${name} Deployment has not observed its current generation"
  [[ "$(kubectl_local -n "$namespace" get deployment "$name" -o jsonpath='{.status.readyReplicas}')" == '2' ]] || \
    die "${namespace}/${name} does not have both replicas ready"
  log "PASS ${namespace}/${name} has two Ready replicas and a live /readyz Service response"
}

exercise_runtime_sites() {
  local capacity_probe quota_output node_name disk_pressure
  render_runtime_sites

  env KIND_EXPERIMENTAL_PROVIDER=docker kind load docker-image \
    --name "$cluster_name" "$NARANJO_RUNTIME_IMAGE"
  env KIND_EXPERIMENTAL_PROVIDER=docker kind load docker-image \
    --name "$cluster_name" "$LIDERSEA_RUNTIME_IMAGE"
  log 'PASS exact candidate digests loaded from local Docker into the disposable cluster'

  new_temp_file capacity-probe.yaml
  capacity_probe="$new_temp_path"
  write_capacity_probe "$capacity_probe"
  if quota_output="$(kubectl_local apply --dry-run=server -f "$capacity_probe" 2>&1)"; then
    die 'zero-Pod capacity gate admitted a conforming Pod'
  fi
  if ! grep -Eq 'capacity-not-ready|exceeded quota' <<<"$quota_output"; then
    printf '%s\n' "$quota_output" >&2
    die 'capacity probe was rejected without evidence from the zero-Pod quota'
  fi
  log 'PASS runtime ResourceQuota admission rejects a conforming site Pod while capacity is unresolved'

  # This mutation is confined to the uniquely owned disposable Kind cluster.
  # Production desired state and manifests retain the exact zero-Pod gate.
  kubectl_local -n naranjo-online delete resourcequota capacity-not-ready
  kubectl_local -n lidersea-com delete resourcequota capacity-not-ready
  log 'PASS removed only disposable-cluster capacity sentinels for readiness exercise'

  kubectl_local apply -f "$naranjo_render_path"
  kubectl_local apply -f "$lidersea_render_path"
  assert_service_ready naranjo-online naranjo-online
  assert_service_ready lidersea-com lidersea-com

  node_name="$(kubectl_local get nodes -l "${local_only_label}=true" -o jsonpath='{.items[0].metadata.name}')"
  disk_pressure="$(kubectl_local get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="DiskPressure")].status}')"
  [[ "$disk_pressure" == 'False' ]] || die "disposable Kind node reports DiskPressure=${disk_pressure:-unknown}"
  log 'PASS disposable Kind node reports DiskPressure=False during two-site readiness'
  log 'RUNTIME EVIDENCE PASS: API admission enforced zero capacity, then both exact-digest site Deployments became Ready'
  log 'NOTE Kind readiness is not Raspberry Pi capacity, storage, CNI, tunnel, or production evidence'
}

# exercise_cluster owns the mutation lifecycle: allocate isolated files, render
# first, create one cluster, prove ownership, apply primitives, and dry-run apps.
exercise_cluster() {
  local kind_config
  local flux_namespace
  local psa_negative
  local prerequisites_render
  local naranjo_render
  local lidersea_render
  local cloudflare_render
  local api_server
  local node_label
  local service_account_value
  local namespace

  # Prove the generated path cannot name a broad or repository directory before
  # any cleanup trap is armed.
  temp_root="$(mktemp -d "${TMPDIR:-/tmp}/website-infra-kind.XXXXXX")"
  [[ -d "${temp_root}" && "${temp_root}" != "/" && "${temp_root}" != "${repo_root}" ]] || \
    die "unsafe temporary directory ${temp_root}"
  trap 'cleanup $?' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  new_temp_file kind-config.yaml
  kind_config="${new_temp_path}"
  new_temp_file kubeconfig
  kubeconfig_file="${new_temp_path}"
  new_temp_file flux-system-namespace.yaml
  flux_namespace="${new_temp_path}"
  new_temp_file psa-negative.yaml
  psa_negative="${new_temp_path}"
  new_temp_file prerequisites.yaml
  prerequisites_render="${new_temp_path}"
  write_kind_config "${kind_config}"
  write_bootstrap_namespace "${flux_namespace}"
  write_psa_negative_fixture "${psa_negative}"

  detect_repository_release_mode
  render_local_artifacts
  naranjo_render="${naranjo_render_path}"
  lidersea_render="${lidersea_render_path}"
  cloudflare_render="${cloudflare_render_path}"
  kustomize build "${repo_root}/kubernetes/platform/prerequisites" > "${prerequisites_render}"

  if cluster_exists; then
    die "Kind cluster ${cluster_name} appeared after preflight; refusing to reuse or delete it"
  fi

  env \
    KIND_EXPERIMENTAL_PROVIDER=docker \
    KUBECONFIG="${kubeconfig_file}" \
    kind create cluster \
      --name "${cluster_name}" \
      --config "${kind_config}" \
      --image "${KIND_NODE_IMAGE}" \
      --kubeconfig "${kubeconfig_file}" \
      --wait 120s

  # Cleanup authority begins only after Docker reports one concrete container
  # carrying Kind's exact cluster label.
  owned_container_id="$(docker ps -aq \
    --filter "label=io.x-k8s.kind.cluster=${cluster_name}")"
  [[ "${owned_container_id}" =~ ^[0-9a-f]+$ ]] || \
    die "could not prove ownership of exactly one Kind control-plane container"
  cluster_cleanup_authorized=1

  # The generated kubeconfig and node label independently prove this harness did
  # not attach to a non-local or pre-existing control plane.
  api_server="$(kubectl_local config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
  [[ "${api_server}" =~ ^https://127\.0\.0\.1:[0-9]+$ ]] || \
    die "Kind API server is not loopback-only: ${api_server}"
  node_label="$(kubectl_local get nodes -l "${local_only_label}=true" -o name)"
  [[ "${node_label}" == "node/${cluster_name}-control-plane" ]] || \
    die "Kind node is missing the local-only ownership label"
  log "PASS isolated kubeconfig uses loopback API ${api_server}"

  kubectl_local apply -f "${flux_namespace}"
  kubectl_local apply -f "${repo_root}/kubernetes/platform/prerequisites/namespaces.yaml"
  kubectl_local apply -f "${repo_root}/kubernetes/flux-system/access.yaml"
  kubectl_local apply -f "${prerequisites_render}"

  for namespace in flux-system cloudflare-public naranjo-online lidersea-com; do
    service_account_value="$(kubectl_local -n "${namespace}" get serviceaccount default \
      -o jsonpath='{.automountServiceAccountToken}')"
    [[ "${service_account_value}" == "false" ]] || \
      die "default ServiceAccount in ${namespace} does not disable token automount"
  done
  log "PASS bootstrap namespaces, restricted PSA labels, RBAC, quotas, and default-deny resources applied"

  if kubectl_local apply --dry-run=server -f "${psa_negative}" >/dev/null 2>&1; then
    die "restricted Pod Security admission accepted the privileged negative fixture"
  fi
  log "PASS restricted Pod Security admission rejects a privileged Pod"

  assert_can_i yes \
    --as system:serviceaccount:flux-system:platform-prerequisites-reconciler \
    create networkpolicies.networking.k8s.io -n naranjo-online
  assert_can_i no \
    --as system:serviceaccount:flux-system:platform-prerequisites-reconciler \
    create deployments.apps -n naranjo-online
  assert_can_i yes \
    --as system:serviceaccount:naranjo-online:helm-reconciler \
    create deployments.apps -n naranjo-online
  assert_can_i no \
    --as system:serviceaccount:naranjo-online:helm-reconciler \
    create secrets -n flux-system
  assert_can_i yes \
    --as system:serviceaccount:flux-system:platform-prerequisites-reconciler \
    create networkpolicies.networking.k8s.io -n lidersea-com
  assert_can_i no \
    --as system:serviceaccount:flux-system:platform-prerequisites-reconciler \
    create deployments.apps -n lidersea-com
  assert_can_i yes \
    --as system:serviceaccount:lidersea-com:helm-reconciler \
    create deployments.apps -n lidersea-com
  assert_can_i no \
    --as system:serviceaccount:lidersea-com:helm-reconciler \
    create secrets -n flux-system

  # Server-side dry-run exercises admission and API validation while the digest,
  # token, and HelmRelease gates intentionally prevent workload execution.
  kubectl_local apply --dry-run=server -f "${naranjo_render}"
  kubectl_local apply --dry-run=server -f "${lidersea_render}"
  kubectl_local apply --dry-run=server -f "${cloudflare_render}"
  log "PASS both site and tunnel Helm outputs pass local API server validation without creating workloads"
  if (( runtime_mode == 1 )); then
    exercise_runtime_sites
  elif [[ "$repository_release_mode" == 'scaffold' ]]; then
    log "SKIP workload execution: both site digest/readiness gates and all three HelmRelease suspensions are intentional"
  else
    log 'SKIP workload execution: use explicitly gated --runtime with the two exact local desired image digests'
  fi
  log "SKIP tunnel execution: no credential or plaintext Secret is accepted by this harness"
  log "SKIP Flux controllers and CRDs: generated bootstrap artifacts are not required for primitive RBAC validation"
  log "SKIP behavioral NetworkPolicy test: Kind networking is not the production CNI decision"
  log "Disposable Kind checks completed; trap cleanup will now delete only ${cluster_name}."
}

# usage documents the read-only default and the exact acknowledgement required
# for the disposable cluster lifecycle.
usage() {
  printf '%s\n' \
    'Usage:' \
    '  scripts/test-kind.sh [--check]' \
    "  scripts/test-kind.sh --apply ${apply_ack}" \
    "  scripts/test-kind.sh --runtime ${apply_ack}" \
    '' \
    'Runtime mode additionally requires locally preloaded NARANJO_RUNTIME_IMAGE' \
    'and LIDERSEA_RUNTIME_IMAGE canonical sha256 references. It removes the two' \
    'zero-Pod quotas only inside the owned disposable cluster, runs both sites,' \
    'proves their readiness, and still never starts a tunnel or accepts a secret.'
}

case "${1:---check}" in
  --check)
    (( $# <= 1 )) || { usage >&2; exit 2; }
    check_prerequisites
    log 'Kind local harness prerequisites are ready; no cluster was created.'
    ;;
  --apply)
    (( $# == 2 )) || { usage >&2; exit 2; }
    [[ "$2" == "${apply_ack}" ]] || die "exact acknowledgement is required: ${apply_ack}"
    check_prerequisites
    exercise_cluster
    ;;
  --runtime)
    (( $# == 2 )) || { usage >&2; exit 2; }
    [[ "$2" == "${apply_ack}" ]] || die "exact acknowledgement is required: ${apply_ack}"
    runtime_mode=1
    check_prerequisites
    check_runtime_inputs
    exercise_cluster
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
