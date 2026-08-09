#!/usr/bin/env bash
# Exercise rendered policy and RBAC against a disposable, loopback-only Kind
# control plane; this is a local integration check, not the production kubeadm
# topology or a substitute for the Pi's reviewed CNI decision.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${repo_root}/versions.env"

# These identifiers establish ownership of the only cluster and Docker network
# this harness may create or delete. The explicit acknowledgement makes both
# mutations opt-in.
readonly cluster_name="website-infra-local-test"
readonly cluster_context="kind-${cluster_name}"
readonly docker_network_name="${cluster_name}-internal"
readonly docker_network_owner_label="platform.snaraj.dev/kind-network-owner"
readonly apply_ack="I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test_AND_ITS_INTERNAL_DOCKER_NETWORK"
readonly local_only_label="platform.snaraj.dev/local-kind-test"

# Mutable ownership state starts empty and becomes cleanup-authoritative only
# after each newly created Docker object has been uniquely identified.
temp_root=""
kubeconfig_file=""
cluster_creation_started=0
cluster_cleanup_authorized=0
owned_container_id=""
network_cleanup_authorized=0
owned_network_id=""
new_temp_path=""
naranjo_render_path=""
lidersea_render_path=""
cloudflare_render_path=""
naranjo_release_values_path=""
lidersea_release_values_path=""
cloudflare_release_values_path=""
runtime_mode=0
repository_release_mode='scaffold'
transition_runtime_site=""
transition_runtime_image=""
transition_release_values_path=""
transition_render_path=""
transition_namespace_baseline=""
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

# docker_network_exists enumerates exact local names instead of relying on
# Docker's substring-oriented name filter. No existing network is ever reused.
docker_network_exists() {
  local candidate
  local networks
  networks="$(docker network ls --format '{{.Name}}')" || \
    die "could not enumerate local Docker networks"
  while IFS= read -r candidate; do
    [[ "${candidate}" == "${docker_network_name}" ]] && return 0
  done <<<"${networks}"
  return 1
}

# docker_network_identity emits every immutable or security-relevant property
# used to authorize this run's cleanup. The owner label value is the fixed
# cluster name, not caller-controlled input.
docker_network_identity() {
  docker network inspect --format \
    '{{.Id}}|{{.Name}}|{{.Driver}}|{{.Internal}}|{{.Attachable}}|{{.Ingress}}|{{.Scope}}|{{json .Labels}}' \
    "${docker_network_name}"
}

assert_owned_docker_network() {
  local actual_identity
  local expected_identity
  expected_identity="${owned_network_id}|${docker_network_name}|bridge|true|false|false|local|{\"${docker_network_owner_label}\":\"${cluster_name}\"}"
  actual_identity="$(docker_network_identity)" || \
    die "could not inspect owned Docker network ${docker_network_name}"
  [[ "${actual_identity}" == "${expected_identity}" ]] || \
    die "Docker network ${docker_network_name} is not the exact owned internal bridge"
  log "PASS owned Docker network ${docker_network_name} is an internal local bridge"
}

create_owned_docker_network() {
  local created_id
  if docker_network_exists; then
    die "Docker network ${docker_network_name} appeared after preflight; refusing to reuse or delete it"
  fi
  created_id="$(docker network create \
    --driver bridge \
    --internal \
    --label "${docker_network_owner_label}=${cluster_name}" \
    "${docker_network_name}")" || die "could not create owned internal Docker network"
  [[ "${created_id}" =~ ^[0-9a-f]{64}$ ]] || \
    die "Docker did not return one full network ID for ${docker_network_name}"
  owned_network_id="${created_id}"
  network_cleanup_authorized=1
  assert_owned_docker_network
}

assert_owned_node_network() {
  local attached_containers
  local node_networks
  node_networks="$(docker inspect --format \
    '{{range $network_name, $_ := .NetworkSettings.Networks}}{{println $network_name}}{{end}}' \
    "${owned_container_id}")" || die "could not inspect the owned Kind node networks"
  [[ "${node_networks}" == "${docker_network_name}" ]] || \
    die "owned Kind node is not attached only to ${docker_network_name}"
  attached_containers="$(docker network inspect --format \
    '{{range $container_id, $_ := .Containers}}{{println $container_id}}{{end}}' \
    "${docker_network_name}")" || die "could not inspect internal Docker network endpoints"
  [[ "${attached_containers}" == "${owned_container_id}" ]] || \
    die "internal Docker network contains an endpoint other than the one owned Kind node"
  log "PASS owned Kind node is the sole endpoint on ${docker_network_name}"
}

# cleanup deletes the cluster only when its current container identity still
# matches the one created by this run, removes the exact owned network only
# while its full identity still matches, then removes registered temp files.
cleanup() {
  local original_status="$1"
  local cleanup_status=0
  local candidate_container_id
  local candidate_container_name
  local candidate_cluster_label
  local candidate_role_label
  local candidate_image
  local candidate_networks
  local attached_containers
  local current_container_id
  local current_network_identity
  local expected_network_identity
  local temp_file
  trap - EXIT INT TERM
  set +e

  # Kind can fail or receive a signal after Docker has created the node but
  # before the successful-return ownership capture below. Recover cleanup
  # authority only for the single exact container created inside this run's
  # already-proven internal network. Ambiguous or changed state is never deleted.
  if (( cluster_creation_started == 1 && cluster_cleanup_authorized == 0 )); then
    if ! candidate_container_id="$(docker ps -aq --no-trunc \
      --filter "label=io.x-k8s.kind.cluster=${cluster_name}")"; then
      printf 'ERROR: could not enumerate a partial Kind container for %s\n' \
        "${cluster_name}" >&2
      cleanup_status=1
    elif [[ -z "${candidate_container_id}" ]]; then
      log "No partial Kind container exists for ${cluster_name}; continuing network-only cleanup."
    elif [[ ! "${candidate_container_id}" =~ ^[0-9a-f]{64}$ ]]; then
      printf 'ERROR: refusing cleanup because partial Kind container ownership is ambiguous for %s\n' \
        "${cluster_name}" >&2
      cleanup_status=1
    elif ! candidate_container_name="$(docker inspect --format '{{.Name}}' \
      "${candidate_container_id}")" ||
      ! candidate_cluster_label="$(docker inspect --format \
        '{{index .Config.Labels "io.x-k8s.kind.cluster"}}' "${candidate_container_id}")" ||
      ! candidate_role_label="$(docker inspect --format \
        '{{index .Config.Labels "io.x-k8s.kind.role"}}' "${candidate_container_id}")" ||
      ! candidate_image="$(docker inspect --format '{{.Config.Image}}' \
        "${candidate_container_id}")" ||
      ! candidate_networks="$(docker inspect --format \
        '{{range $network_name, $_ := .NetworkSettings.Networks}}{{println $network_name}}{{end}}' \
        "${candidate_container_id}")" ||
      ! attached_containers="$(docker network inspect --format \
        '{{range $container_id, $_ := .Containers}}{{println $container_id}}{{end}}' \
        "${docker_network_name}")" ||
      ! current_network_identity="$(docker_network_identity)"; then
      printf 'ERROR: refusing cleanup because partial Kind ownership could not be inspected for %s\n' \
        "${cluster_name}" >&2
      cleanup_status=1
    else
      expected_network_identity="${owned_network_id}|${docker_network_name}|bridge|true|false|false|local|{\"${docker_network_owner_label}\":\"${cluster_name}\"}"
      if [[ "${candidate_container_name}" != "/${cluster_name}-control-plane" ||
        "${candidate_cluster_label}" != "${cluster_name}" ||
        "${candidate_role_label}" != "control-plane" ||
        "${candidate_image}" != "${KIND_NODE_IMAGE}" ||
        "${candidate_networks}" != "${docker_network_name}" ||
        "${attached_containers}" != "${candidate_container_id}" ||
        "${current_network_identity}" != "${expected_network_identity}" ]]; then
        printf 'ERROR: refusing cleanup because partial Kind ownership changed for %s\n' \
          "${cluster_name}" >&2
        cleanup_status=1
      else
        owned_container_id="${candidate_container_id}"
        cluster_cleanup_authorized=1
        log "Recovered exact cleanup ownership for partial Kind cluster ${cluster_name}."
      fi
    fi
  fi

  if (( cluster_cleanup_authorized == 1 )); then
    # Re-read Docker state at deletion time so a replaced or expanded cluster is
    # never treated as the disposable object this process originally created.
    current_container_id="$(docker ps -aq --no-trunc \
      --filter "label=io.x-k8s.kind.cluster=${cluster_name}")"
    if [[ -z "${owned_container_id}" || "${current_container_id}" != "${owned_container_id}" ]]; then
      printf 'ERROR: refusing cleanup because Kind container ownership changed for %s\n' \
        "${cluster_name}" >&2
      cleanup_status=1
    else
      log "Cleaning only disposable Kind cluster ${cluster_name}."
      env \
        KIND_EXPERIMENTAL_PROVIDER=docker \
        KIND_EXPERIMENTAL_DOCKER_NETWORK="${docker_network_name}" \
        KUBECONFIG="${kubeconfig_file}" \
        kind delete cluster --name "${cluster_name}" || cleanup_status=1
    fi
  fi

  if (( network_cleanup_authorized == 1 )); then
    expected_network_identity="${owned_network_id}|${docker_network_name}|bridge|true|false|false|local|{\"${docker_network_owner_label}\":\"${cluster_name}\"}"
    if ! current_network_identity="$(docker_network_identity 2>/dev/null)"; then
      printf 'ERROR: refusing cleanup because Docker network identity could not be read for %s\n' \
        "${docker_network_name}" >&2
      cleanup_status=1
    elif [[ "${current_network_identity}" != "${expected_network_identity}" ]]; then
      printf 'ERROR: refusing cleanup because Docker network ownership changed for %s\n' \
        "${docker_network_name}" >&2
      cleanup_status=1
    else
      log "Cleaning only owned internal Docker network ${docker_network_name}."
      docker network rm "${owned_network_id}" >/dev/null || cleanup_status=1
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

  for command_name in kind kubectl helm kustomize docker python3; do
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
  if docker_network_exists; then
    die "Docker network ${docker_network_name} already exists; it will not be reused or deleted"
  fi
  log "PASS disposable Docker network name ${docker_network_name} is unused"

  check_optional_tool conftest "${CONFTEST_VERSION}"
  check_optional_tool kyverno "${KYVERNO_CLI_VERSION}"
}

# Direct transition runtime remains usable, but it cannot bypass the exact
# canonical repository/static-render gate owned by release-gate.sh.
run_canonical_transition_static_gate() {
  bash "${repo_root}/scripts/release-gate.sh" --transition-check
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
  local -a naranjo_helm_values_args=()
  local -a lidersea_helm_values_args=()
  local -a cloudflare_helm_values_args=()
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

  if [[ "$repository_release_mode" == 'release' ]]; then
    # Flux merges these exact spec.values mappings over the inert chart defaults.
    # Reuse the strict release-state parser so Kind cannot test a different
    # readiness/digest path from CI, release-gate, or the production controller.
    new_temp_file naranjo-online-release-values.yaml
    naranjo_release_values_path="${new_temp_path}"
    python3 "${repo_root}/scripts/validate_release_state.py" emit-values \
      --release naranjo-online >"${naranjo_release_values_path}"
    [[ -s "${naranjo_release_values_path}" ]] || die 'naranjo.online effective release values are empty'
    naranjo_helm_values_args=(--values "${naranjo_release_values_path}")

    new_temp_file lidersea-com-release-values.yaml
    lidersea_release_values_path="${new_temp_path}"
    python3 "${repo_root}/scripts/validate_release_state.py" emit-values \
      --release lidersea-com >"${lidersea_release_values_path}"
    [[ -s "${lidersea_release_values_path}" ]] || die 'lidersea.com effective release values are empty'
    lidersea_helm_values_args=(--values "${lidersea_release_values_path}")

    new_temp_file cloudflare-public-release-values.yaml
    cloudflare_release_values_path="${new_temp_path}"
    python3 "${repo_root}/scripts/validate_release_state.py" emit-values \
      --release cloudflare-public >"${cloudflare_release_values_path}"
    [[ -s "${cloudflare_release_values_path}" ]] || die 'cloudflare-public effective release values are empty'
    cloudflare_helm_values_args=(--values "${cloudflare_release_values_path}")
  fi

  helm lint "${repo_root}/websites/naranjo.online/chart" "${naranjo_helm_values_args[@]}"
  new_temp_file naranjo-online.yaml
  naranjo_render="${new_temp_path}"
  helm template naranjo-online "${repo_root}/websites/naranjo.online/chart" \
    --namespace naranjo-online "${naranjo_helm_values_args[@]}" > "${naranjo_render}"
  rendered_files+=("${naranjo_render}")

  helm lint "${repo_root}/websites/lidersea.com/chart" "${lidersea_helm_values_args[@]}"
  new_temp_file lidersea-com.yaml
  lidersea_render="${new_temp_path}"
  helm template lidersea-com "${repo_root}/websites/lidersea.com/chart" \
    --namespace lidersea-com "${lidersea_helm_values_args[@]}" > "${lidersea_render}"
  rendered_files+=("${lidersea_render}")

  helm lint "${repo_root}/kubernetes/platform/cloudflare-public/chart" "${cloudflare_helm_values_args[@]}"
  new_temp_file cloudflare-public.yaml
  cloudflare_render="${new_temp_path}"
  helm template cloudflare-public "${repo_root}/kubernetes/platform/cloudflare-public/chart" \
    --namespace cloudflare-public "${cloudflare_helm_values_args[@]}" > "${cloudflare_render}"
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
  local suspended=0 active=0 file transition_plan
  local -a transition_plan_lines=()

  if [[ -n "$transition_runtime_site" ]]; then
    if ! transition_plan="$(
      python3 "${repo_root}/scripts/validate_release_transition.py" plan \
        --expect-mode transition
    )"; then
      die 'authoritative release state does not permit transition runtime evidence'
    fi
    mapfile -t transition_plan_lines <<<"$transition_plan"
    ((${#transition_plan_lines[@]} == 6)) || \
      die 'authoritative transition plan has an invalid shape'
    [[ "${transition_plan_lines[0]}" == 'mode=transition' ]] || \
      die 'authoritative release mode is not transition'
    [[ "${transition_plan_lines[1]}" =~ ^naranjo-online=(initial|staged|active)$ ]] || \
      die 'naranjo-online transition phase is invalid'
    [[ "${transition_plan_lines[2]}" =~ ^lidersea-com=(initial|staged|active)$ ]] || \
      die 'lidersea-com transition phase is invalid'
    [[ "${transition_plan_lines[3]}" =~ ^cloudflare-public=(initial|staged|active)$ ]] || \
      die 'cloudflare-public transition phase is invalid'
    [[ "${transition_plan_lines[4]}" =~ ^any-website-active=(true|false)$ ]] || \
      die 'website activation summary is invalid'
    [[ "${transition_plan_lines[5]}" =~ ^any-workload-active=(true|false)$ ]] || \
      die 'workload activation summary is invalid'
    if [[ "$transition_runtime_site" == 'naranjo-online' ]]; then
      [[ "${transition_plan_lines[1]}" == 'naranjo-online=staged' ]] || \
        die 'naranjo-online must be exactly staged for transition runtime evidence'
    else
      [[ "${transition_plan_lines[2]}" == 'lidersea-com=staged' ]] || \
        die 'lidersea-com must be exactly staged for transition runtime evidence'
    fi
    repository_release_mode='transition'
    log "PASS authoritative transition plan selects staged ${transition_runtime_site}"
    return
  fi

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
    # Chart defaults intentionally stay false/all-zero in every phase. The
    # strict emit-values render below validates the active HelmRelease override.
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

check_transition_runtime_input() {
  case "$transition_runtime_site" in
    naranjo-online)
      : "${NARANJO_RUNTIME_IMAGE:?Set NARANJO_RUNTIME_IMAGE to the locally preloaded staged digest}"
      transition_runtime_image="$NARANJO_RUNTIME_IMAGE"
      require_runtime_image NARANJO_RUNTIME_IMAGE "$transition_runtime_image" \
        'ghcr\.io/snaraj/naranjo-online'
      ;;
    lidersea-com)
      : "${LIDERSEA_RUNTIME_IMAGE:?Set LIDERSEA_RUNTIME_IMAGE to the locally preloaded staged digest}"
      transition_runtime_image="$LIDERSEA_RUNTIME_IMAGE"
      require_runtime_image LIDERSEA_RUNTIME_IMAGE "$transition_runtime_image" \
        'ghcr\.io/snaraj/lidersea-com'
      ;;
    *) die 'transition runtime site must be naranjo-online or lidersea-com' ;;
  esac
}

write_transition_namespace() {
  local fixture_file="$1"
  cat >"$fixture_file" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${transition_runtime_site}
  labels:
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.36
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.36
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.36
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: ${transition_runtime_site}
automountServiceAccountToken: false
EOF
}

write_selected_capacity_gate() {
  local fixture_file="$1"
  cat >"$fixture_file" <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: capacity-not-ready
  namespace: ${transition_runtime_site}
  annotations:
    platform.snaraj.dev/readiness: blocked-until-pi-capacity-evidence
spec:
  hard:
    pods: "0"
EOF
}

write_selected_capacity_probe() {
  local fixture_file="$1"
  cat >"$fixture_file" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: must-be-rejected-by-zero-capacity
  namespace: ${transition_runtime_site}
spec:
  automountServiceAccountToken: false
  serviceAccountName: default
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: ${transition_runtime_image}
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

render_transition_runtime_site() {
  local chart_path desired_render desired_image vendored_entry
  local -a desired_images=()
  local -a runtime_images=()

  case "$transition_runtime_site" in
    naranjo-online) chart_path="${repo_root}/websites/naranjo.online/chart" ;;
    lidersea-com) chart_path="${repo_root}/websites/lidersea.com/chart" ;;
    *) die 'transition runtime site escaped its closed allowlist' ;;
  esac
  [[ ! -f "${chart_path}/Chart.lock" ]] || \
    die 'chart dependencies are forbidden in transition runtime mode'
  if [[ -d "${chart_path}/charts" ]]; then
    if ! vendored_entry="$(find "${chart_path}/charts" -mindepth 1 -print -quit)"; then
      die 'could not inspect vendored chart dependencies in transition runtime mode'
    fi
    [[ -z "$vendored_entry" ]] || \
      die 'vendored chart dependencies are forbidden in transition runtime mode'
  fi

  new_temp_file "${transition_runtime_site}-transition-release-values.yaml"
  transition_release_values_path="$new_temp_path"
  python3 "${repo_root}/scripts/validate_release_state.py" emit-values \
    --release "$transition_runtime_site" >"$transition_release_values_path"
  [[ -s "$transition_release_values_path" ]] || \
    die "${transition_runtime_site} effective transition values are empty"

  helm lint "$chart_path" --values "$transition_release_values_path"
  new_temp_file "${transition_runtime_site}-transition-desired.yaml"
  desired_render="$new_temp_path"
  helm template "$transition_runtime_site" "$chart_path" \
    --namespace "$transition_runtime_site" \
    --values "$transition_release_values_path" >"$desired_render"

  mapfile -t desired_images < <(
    awk '$1 == "image:" {gsub(/"/, "", $2); print $2}' "$desired_render"
  )
  ((${#desired_images[@]} == 1)) || \
    die "${transition_runtime_site} desired render must contain exactly one image"
  desired_image="${desired_images[0]}"
  [[ "$desired_image" == "$transition_runtime_image" ]] || \
    die "selected runtime image differs from the staged ${transition_runtime_site} HelmRelease image"
  validate_transition_render_inventory "$desired_render"

  new_temp_file "${transition_runtime_site}-transition-runtime.yaml"
  transition_render_path="$new_temp_path"
  helm template "$transition_runtime_site" "$chart_path" \
    --namespace "$transition_runtime_site" \
    --values "$transition_release_values_path" \
    --set image.pullPolicy=Never >"$transition_render_path"
  mapfile -t runtime_images < <(
    awk '$1 == "image:" {gsub(/"/, "", $2); print $2}' "$transition_render_path"
  )
  ((${#runtime_images[@]} == 1)) || \
    die "${transition_runtime_site} runtime render must contain exactly one image"
  [[ "${runtime_images[0]}" == "$transition_runtime_image" ]] || \
    die "${transition_runtime_site} runtime render changed the selected staged image"
  validate_transition_render_inventory "$transition_render_path"

  if command -v conftest >/dev/null 2>&1; then
    conftest test --policy "${repo_root}/policies/conftest" "$transition_render_path"
    conftest test --policy "${repo_root}/policies/release-conftest" "$transition_render_path"
  fi
  log "PASS staged ${transition_runtime_site} render is bound to its one exact local digest"
}

# validate_transition_render_inventory accepts only Helm's canonical block-map
# grammar for the selected site's four exact objects. The strict key grammar,
# unique top-level/direct-metadata keys, and closed key inventories reject YAML
# aliases, merge keys, quoted/flow-form duplicate identity keys, extra documents,
# and cluster-scoped objects without adding a runtime YAML dependency.
validate_transition_render_inventory() {
  local render_path="$1"
  python3 -B - "$render_path" "$transition_runtime_site" <<'PY'
from pathlib import Path
import re
import sys

render_path = Path(sys.argv[1])
site = sys.argv[2]
network_policy = {
    "naranjo-online": "cloudflared-to-naranjo-online",
    "lidersea-com": "cloudflared-to-lidersea-com",
}.get(site)
if network_policy is None:
    raise SystemExit("transition render site escaped its closed allowlist")

raw = render_path.read_bytes()
if (
    not raw
    or len(raw) > 1024 * 1024
    or b"\r" in raw
    or b"\t" in raw
    or not raw.endswith(b"\n")
    or any(byte < 0x20 and byte != 0x0A for byte in raw)
):
    raise SystemExit("transition render must be bounded LF-terminated YAML")
text = raw.decode("utf-8", errors="strict")
documents = []
for fragment in re.split(r"(?m)^---\n", text):
    if not fragment.strip():
        continue
    lines = fragment.splitlines()
    top_level = [line for line in lines if line and not line.startswith((" ", "#"))]
    entries = []
    for line in top_level:
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*):(.*)", line)
        if match is None:
            raise SystemExit("transition render has non-canonical top-level YAML")
        entries.append((match.group(1), match.group(2)))
    keys = [key for key, _ in entries]
    if len(keys) != len(set(keys)):
        raise SystemExit("transition render has a duplicate top-level key")
    values = dict(entries)
    api_version = values.get("apiVersion", "")
    kind = values.get("kind", "")
    kind_value = kind[1:] if kind.startswith(" ") else kind
    expected_keys = {
        "Deployment": ["apiVersion", "kind", "metadata", "spec"],
        "Service": ["apiVersion", "kind", "metadata", "spec"],
        "ServiceAccount": [
            "apiVersion",
            "kind",
            "metadata",
            "automountServiceAccountToken",
        ],
        "NetworkPolicy": ["apiVersion", "kind", "metadata", "spec"],
    }.get(kind_value)
    if expected_keys is None or keys != expected_keys:
        raise SystemExit("transition render has a non-canonical top-level key inventory")
    if values["metadata"] != "":
        raise SystemExit("transition render metadata must use one canonical block map")
    if kind_value == "ServiceAccount":
        if values["automountServiceAccountToken"] != " false":
            raise SystemExit("transition ServiceAccount must disable token automount")
    elif values["spec"] != "":
        raise SystemExit("transition resource spec must use one canonical block map")

    metadata_index = lines.index("metadata:")
    metadata_lines = []
    for line in lines[metadata_index + 1 :]:
        if line and not line.startswith((" ", "#")):
            break
        metadata_lines.append(line)
    metadata_entries = []
    for line in metadata_lines:
        if not line or line.lstrip().startswith("#") or not line.startswith("  "):
            continue
        if line.startswith("   "):
            continue
        match = re.fullmatch(r"  ([A-Za-z][A-Za-z0-9./_-]*):(.*)", line)
        if match is None:
            raise SystemExit("transition metadata has non-canonical direct YAML")
        metadata_entries.append((match.group(1), match.group(2)))
    metadata_keys = [key for key, _ in metadata_entries]
    if len(metadata_keys) != len(set(metadata_keys)):
        raise SystemExit("transition metadata has a duplicate direct key")
    if not set(metadata_keys).issubset(
        {"name", "namespace", "labels", "annotations"}
    ):
        raise SystemExit("transition metadata contains a key outside the closed allowlist")
    metadata = dict(metadata_entries)
    expected_name = network_policy if kind_value == "NetworkPolicy" else site
    name = metadata.get("name", "")
    namespace = metadata.get("namespace", "")
    if name != " " + expected_name:
        raise SystemExit("transition render object name is not exact")
    if namespace != " " + site:
        raise SystemExit("transition render document lacks one exact namespaced identity")
    documents.append(
        (
            api_version[1:] if api_version.startswith(" ") else api_version,
            kind_value,
            site,
            name[1:] if name.startswith(" ") else name,
        )
    )

expected = {
    ("apps/v1", "Deployment", site, site),
    ("v1", "Service", site, site),
    ("v1", "ServiceAccount", site, site),
    ("networking.k8s.io/v1", "NetworkPolicy", site, network_policy),
}
if len(documents) != 4 or set(documents) != expected:
    raise SystemExit("transition render is not the exact four-resource selected-site inventory")
PY
}

# Namespace comparison is set-based and deterministic. The only permitted
# change from the freshly created cluster baseline is the selected namespace.
normalize_namespace_inventory() {
  python3 -B -c '
import re
import sys

names = [line for line in sys.stdin.read().splitlines() if line]
if not names or len(names) != len(set(names)):
    raise SystemExit("namespace inventory is empty or duplicated")
if any(
    len(name) > 63
    or re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", name) is None
    for name in names
):
    raise SystemExit("namespace inventory contains a non-canonical name")
sys.stdout.write("\n".join(sorted(names)))
'
}

read_transition_namespace_inventory() {
  local namespace_names
  namespace_names="$(kubectl_local get namespaces \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')" || return 1
  normalize_namespace_inventory <<<"${namespace_names}"
}

capture_transition_namespace_baseline() {
  local forbidden_namespace
  local namespace_name
  if ! transition_namespace_baseline="$(read_transition_namespace_inventory)"; then
    die 'could not capture the owned transition cluster namespace baseline'
  fi
  for forbidden_namespace in flux-system cloudflare-public naranjo-online lidersea-com; do
    while IFS= read -r namespace_name; do
      [[ "${namespace_name}" != "${forbidden_namespace}" ]] || \
        die "fresh transition cluster unexpectedly contains namespace ${forbidden_namespace}"
    done <<<"${transition_namespace_baseline}"
  done
  log 'PASS captured fresh owned-cluster namespace baseline before tenant mutation'
}

assert_transition_namespace_boundary() {
  local current_namespaces
  local expected_namespaces
  local expected_source
  [[ -n "${transition_namespace_baseline}" ]] || \
    die 'transition namespace baseline is unavailable'
  if ! current_namespaces="$(read_transition_namespace_inventory)"; then
    die 'could not enumerate namespaces in the owned transition cluster'
  fi
  expected_source="${transition_namespace_baseline}"$'\n'"${transition_runtime_site}"
  if ! expected_namespaces="$(normalize_namespace_inventory <<<"${expected_source}")"; then
    die 'could not construct the exact selected transition namespace inventory'
  fi
  [[ "${current_namespaces}" == "${expected_namespaces}" ]] || \
    die 'transition namespace inventory differs from baseline plus the selected tenant'
}

revalidate_transition_runtime_state() {
  local chart_path current_render expected_render rendered_values current_values

  case "$transition_runtime_site" in
    naranjo-online) chart_path="${repo_root}/websites/naranjo.online/chart" ;;
    lidersea-com) chart_path="${repo_root}/websites/lidersea.com/chart" ;;
    *) die 'transition runtime site escaped its closed allowlist during revalidation' ;;
  esac

  detect_repository_release_mode
  if ! current_values="$(
    python3 "${repo_root}/scripts/validate_release_state.py" emit-values \
      --release "$transition_runtime_site"
  )"; then
    die "could not re-read ${transition_runtime_site} effective values"
  fi
  if ! rendered_values="$(<"$transition_release_values_path")"; then
    die "could not re-read ${transition_runtime_site} rendered values"
  fi
  [[ "$current_values" == "$rendered_values" ]] || \
    die "${transition_runtime_site} effective values changed during transition runtime validation"
  if ! current_render="$(
    helm template "$transition_runtime_site" "$chart_path" \
      --namespace "$transition_runtime_site" \
      --values "$transition_release_values_path" \
      --set image.pullPolicy=Never
  )"; then
    die "could not re-render ${transition_runtime_site} during transition validation"
  fi
  if ! expected_render="$(<"$transition_render_path")"; then
    die "could not re-read ${transition_runtime_site} runtime render"
  fi
  [[ "$current_render" == "$expected_render" ]] || \
    die "${transition_runtime_site} chart render changed during transition runtime validation"
  # Sandwich the values read between two full topology classifications so a
  # suspension-only edit cannot reuse a stale staged render.
  detect_repository_release_mode
}

write_disposable_capacity_gates() {
  local fixture_file="$1"
  cat >"$fixture_file" <<'EOF'
apiVersion: v1
kind: ResourceQuota
metadata:
  name: capacity-not-ready
  namespace: naranjo-online
  annotations:
    platform.snaraj.dev/readiness: blocked-until-pi-capacity-evidence
spec:
  hard:
    pods: "0"
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: capacity-not-ready
  namespace: lidersea-com
  annotations:
    platform.snaraj.dev/readiness: blocked-until-pi-capacity-evidence
spec:
  hard:
    pods: "0"
EOF
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
  local -a naranjo_runtime_values_args=()
  local -a lidersea_runtime_values_args=()

  if [[ "$repository_release_mode" == 'release' ]]; then
    [[ -n "$naranjo_release_values_path" && -s "$naranjo_release_values_path" ]] || \
      die 'active naranjo.online effective values are unavailable'
    [[ -n "$lidersea_release_values_path" && -s "$lidersea_release_values_path" ]] || \
      die 'active lidersea.com effective values are unavailable'
    desired_naranjo="$(awk '$1 == "image:" {gsub(/"/, "", $2); print $2}' "$naranjo_render_path")"
    desired_lidersea="$(awk '$1 == "image:" {gsub(/"/, "", $2); print $2}' "$lidersea_render_path")"
    [[ "$desired_naranjo" == "$NARANJO_RUNTIME_IMAGE" ]] || \
      die 'NARANJO_RUNTIME_IMAGE differs from the active desired Deployment image'
    [[ "$desired_lidersea" == "$LIDERSEA_RUNTIME_IMAGE" ]] || \
      die 'LIDERSEA_RUNTIME_IMAGE differs from the active desired Deployment image'
    naranjo_runtime_values_args=(--values "$naranjo_release_values_path")
    lidersea_runtime_values_args=(--values "$lidersea_release_values_path")
    log 'PASS runtime candidate digests exactly match active desired state'
  else
    # Scaffold runtime mode is an explicit candidate exercise, so it overlays
    # only the supplied immutable digest/readiness onto inert chart defaults.
    naranjo_runtime_values_args=(
      --set deploymentReady=true
      --set-string "image.digest=${naranjo_digest}"
    )
    lidersea_runtime_values_args=(
      --set deploymentReady=true
      --set-string "image.digest=${lidersea_digest}"
    )
  fi

  new_temp_file naranjo-online-runtime.yaml
  naranjo_render_path="$new_temp_path"
  helm template naranjo-online "${repo_root}/websites/naranjo.online/chart" \
    --namespace naranjo-online \
    --set image.pullPolicy=Never \
    "${naranjo_runtime_values_args[@]}" >"$naranjo_render_path"

  new_temp_file lidersea-com-runtime.yaml
  lidersea_render_path="$new_temp_path"
  helm template lidersea-com "${repo_root}/websites/lidersea.com/chart" \
    --namespace lidersea-com \
    --set image.pullPolicy=Never \
    "${lidersea_runtime_values_args[@]}" >"$lidersea_render_path"

  if command -v conftest >/dev/null 2>&1; then
    conftest test --policy "${repo_root}/policies/conftest" "$naranjo_render_path" "$lidersea_render_path"
    conftest test --policy "${repo_root}/policies/release-conftest" "$naranjo_render_path" "$lidersea_render_path"
  fi
  log 'PASS candidate two-site render is accepted by static and release-state policy'
}

assert_service_ready() {
  local namespace="$1"
  local name="$2"
  local body observed_generation desired_generation ready_replicas
  kubectl_local -n "$namespace" rollout status "deployment/${name}" --timeout=180s
  kubectl_local -n "$namespace" wait --for=condition=Ready pod \
    -l "app.kubernetes.io/name=${name},app.kubernetes.io/instance=${name}" --timeout=180s
  body="$(kubectl_local get --raw "/api/v1/namespaces/${namespace}/services/http:${name}:http/proxy/readyz")"
  [[ "$body" == 'ok' ]] || die "${namespace}/${name} Service proxy readiness returned an unexpected body"
  if ! observed_generation="$(kubectl_local -n "$namespace" get deployment "$name" \
    -o jsonpath='{.status.observedGeneration}')"; then
    die "could not read ${namespace}/${name} observed generation"
  fi
  if ! desired_generation="$(kubectl_local -n "$namespace" get deployment "$name" \
    -o jsonpath='{.metadata.generation}')"; then
    die "could not read ${namespace}/${name} desired generation"
  fi
  [[ -n "$observed_generation" && "$observed_generation" == "$desired_generation" ]] || \
    die "${namespace}/${name} Deployment has not observed its current generation"
  if ! ready_replicas="$(kubectl_local -n "$namespace" get deployment "$name" \
    -o jsonpath='{.status.readyReplicas}')"; then
    die "could not read ${namespace}/${name} ready replica count"
  fi
  [[ "$ready_replicas" == '2' ]] || \
    die "${namespace}/${name} does not have both replicas ready"
  log "PASS ${namespace}/${name} has two Ready replicas and a live /readyz Service response"
}

exercise_runtime_sites() {
  local capacity_gate capacity_probe quota_output node_name disk_pressure
  render_runtime_sites

  env KIND_EXPERIMENTAL_PROVIDER=docker \
    KIND_EXPERIMENTAL_DOCKER_NETWORK="${docker_network_name}" kind load docker-image \
    --name "$cluster_name" "$NARANJO_RUNTIME_IMAGE"
  env KIND_EXPERIMENTAL_PROVIDER=docker \
    KIND_EXPERIMENTAL_DOCKER_NETWORK="${docker_network_name}" kind load docker-image \
    --name "$cluster_name" "$LIDERSEA_RUNTIME_IMAGE"
  log 'PASS exact candidate digests loaded from local Docker into the disposable cluster'

  if [[ "$repository_release_mode" == 'release' ]]; then
    # Reviewed production quotas intentionally admit the two replicas. Add the
    # old zero-Pod boundary only inside this owned Kind cluster so runtime mode
    # still proves the negative transition before exercising readiness.
    new_temp_file disposable-capacity-gates.yaml
    capacity_gate="$new_temp_path"
    write_disposable_capacity_gates "$capacity_gate"
    kubectl_local apply -f "$capacity_gate"
    log 'PASS installed disposable zero-Pod release negative controls in Kind only'
  fi

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
  # In scaffold mode it removes the rendered sentinel; in release mode it
  # removes only the disposable negative control and leaves reviewed quotas.
  kubectl_local -n naranjo-online delete resourcequota capacity-not-ready
  kubectl_local -n lidersea-com delete resourcequota capacity-not-ready
  log 'PASS removed only zero-Pod Kind controls for readiness exercise'

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

exercise_transition_runtime_site() {
  local namespace_fixture capacity_gate capacity_probe quota_output
  local quota_names quota_pods quota_readiness remaining_quotas
  local node_name disk_pressure

  capture_transition_namespace_baseline
  env KIND_EXPERIMENTAL_PROVIDER=docker \
    KIND_EXPERIMENTAL_DOCKER_NETWORK="${docker_network_name}" kind load docker-image \
    --name "$cluster_name" "$transition_runtime_image"
  log "PASS loaded only staged ${transition_runtime_site} digest into disposable Kind"

  new_temp_file "${transition_runtime_site}-namespace.yaml"
  namespace_fixture="$new_temp_path"
  write_transition_namespace "$namespace_fixture"
  kubectl_local apply -f "$namespace_fixture"
  assert_transition_namespace_boundary
  log "PASS transition runtime created only selected tenant namespace ${transition_runtime_site}"

  new_temp_file "${transition_runtime_site}-capacity-not-ready.yaml"
  capacity_gate="$new_temp_path"
  write_selected_capacity_gate "$capacity_gate"
  kubectl_local apply -f "$capacity_gate"
  if ! quota_names="$(kubectl_local -n "$transition_runtime_site" get resourcequota -o name)"; then
    die 'could not enumerate the selected transition quota inventory'
  fi
  [[ "$quota_names" == 'resourcequota/capacity-not-ready' ]] || \
    die 'transition runtime quota inventory is not the one synthetic zero-Pod gate'
  if ! quota_pods="$(kubectl_local -n "$transition_runtime_site" get resourcequota capacity-not-ready \
    -o jsonpath='{.spec.hard.pods}')"; then
    die 'could not read the selected transition Pod quota'
  fi
  if ! quota_readiness="$(kubectl_local -n "$transition_runtime_site" get resourcequota capacity-not-ready \
    -o jsonpath='{.metadata.annotations.platform\.snaraj\.dev/readiness}')"; then
    die 'could not read the selected transition quota readiness annotation'
  fi
  [[ "$quota_pods" == '0' ]] || die 'transition runtime capacity gate is not zero Pods'
  [[ "$quota_readiness" == 'blocked-until-pi-capacity-evidence' ]] || \
    die 'transition runtime capacity gate readiness annotation is not exact'

  new_temp_file "${transition_runtime_site}-capacity-probe.yaml"
  capacity_probe="$new_temp_path"
  write_selected_capacity_probe "$capacity_probe"
  if quota_output="$(kubectl_local apply --dry-run=server -f "$capacity_probe" 2>&1)"; then
    die 'selected-site zero-Pod capacity gate admitted a conforming Pod'
  fi
  if ! grep -Eq 'capacity-not-ready|exceeded quota' <<<"$quota_output"; then
    printf '%s\n' "$quota_output" >&2
    die 'selected-site probe was rejected without evidence from the zero-Pod quota'
  fi
  log "PASS ${transition_runtime_site} synthetic quota rejected the conforming Pod"

  kubectl_local -n "$transition_runtime_site" delete resourcequota capacity-not-ready
  if ! remaining_quotas="$(kubectl_local -n "$transition_runtime_site" get resourcequota -o name)"; then
    die 'could not verify the selected transition quota deletion'
  fi
  [[ -z "$remaining_quotas" ]] || \
    die 'transition runtime changed or retained an unexpected quota'

  kubectl_local apply -f "$transition_render_path"
  assert_transition_namespace_boundary
  assert_service_ready "$transition_runtime_site" "$transition_runtime_site"

  if ! node_name="$(kubectl_local get nodes -l "${local_only_label}=true" -o jsonpath='{.items[0].metadata.name}')"; then
    die 'could not read the owned transition Kind node identity'
  fi
  [[ -n "$node_name" ]] || die 'owned transition Kind node identity is empty'
  if ! disk_pressure="$(kubectl_local get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="DiskPressure")].status}')"; then
    die 'could not read DiskPressure from the owned transition Kind node'
  fi
  [[ "$disk_pressure" == 'False' ]] || \
    die "disposable Kind node reports DiskPressure=${disk_pressure:-unknown}"
  assert_owned_docker_network
  assert_owned_node_network
  revalidate_transition_runtime_state
  # Kind can run for long enough that an unrelated release, policy, capacity,
  # or repository-contract edit lands after the preflight render. Re-run the
  # complete canonical transition gate at the final evidence boundary so the
  # PASS below can never be attached to stale static proof.
  run_canonical_transition_static_gate
  log "TRANSITION RUNTIME EVIDENCE PASS: staged ${transition_runtime_site} exact-digest Deployment became Ready"
  log 'NOTE this isolated result is not Raspberry Pi, Flux, tunnel, CNI, capacity, or production evidence'
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
  write_kind_config "${kind_config}"

  detect_repository_release_mode
  if [[ "$repository_release_mode" == 'transition' ]]; then
    render_transition_runtime_site
    revalidate_transition_runtime_state
  else
    new_temp_file flux-system-namespace.yaml
    flux_namespace="${new_temp_path}"
    new_temp_file psa-negative.yaml
    psa_negative="${new_temp_path}"
    new_temp_file prerequisites.yaml
    prerequisites_render="${new_temp_path}"
    write_bootstrap_namespace "${flux_namespace}"
    write_psa_negative_fixture "${psa_negative}"
    render_local_artifacts
    naranjo_render="${naranjo_render_path}"
    lidersea_render="${lidersea_render_path}"
    cloudflare_render="${cloudflare_render_path}"
    kustomize build "${repo_root}/kubernetes/platform/prerequisites" > "${prerequisites_render}"
  fi

  if cluster_exists; then
    die "Kind cluster ${cluster_name} appeared after preflight; refusing to reuse or delete it"
  fi
  create_owned_docker_network

  cluster_creation_started=1
  env \
    KIND_EXPERIMENTAL_PROVIDER=docker \
    KIND_EXPERIMENTAL_DOCKER_NETWORK="${docker_network_name}" \
    KUBECONFIG="${kubeconfig_file}" \
    kind create cluster \
      --name "${cluster_name}" \
      --config "${kind_config}" \
      --image "${KIND_NODE_IMAGE}" \
      --kubeconfig "${kubeconfig_file}" \
      --wait 120s

  # Cleanup authority begins only after Docker reports one concrete container
  # carrying Kind's exact cluster label.
  owned_container_id="$(docker ps -aq --no-trunc \
    --filter "label=io.x-k8s.kind.cluster=${cluster_name}")"
  [[ "${owned_container_id}" =~ ^[0-9a-f]{64}$ ]] || \
    die "could not prove ownership of exactly one Kind control-plane container"
  cluster_cleanup_authorized=1
  cluster_creation_started=0
  assert_owned_docker_network
  assert_owned_node_network

  # The generated kubeconfig and node label independently prove this harness did
  # not attach to a non-local or pre-existing control plane.
  api_server="$(kubectl_local config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
  [[ "${api_server}" =~ ^https://127\.0\.0\.1:[0-9]+$ ]] || \
    die "Kind API server is not loopback-only: ${api_server}"
  node_label="$(kubectl_local get nodes -l "${local_only_label}=true" -o name)"
  [[ "${node_label}" == "node/${cluster_name}-control-plane" ]] || \
    die "Kind node is missing the local-only ownership label"
  log "PASS isolated kubeconfig uses loopback API ${api_server}"

  if [[ "$repository_release_mode" == 'transition' ]]; then
    exercise_transition_runtime_site
    log "Disposable one-site transition check completed; trap cleanup will now delete only ${cluster_name} and ${docker_network_name}."
    return
  fi

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
  assert_owned_docker_network
  assert_owned_node_network
  log "Disposable Kind checks completed; trap cleanup will now delete only ${cluster_name} and ${docker_network_name}."
}

# usage documents the read-only default and the exact acknowledgement required
# for the disposable cluster and internal Docker-network lifecycle.
usage() {
  printf '%s\n' \
    'Usage:' \
    '  scripts/test-kind.sh [--check]' \
    "  scripts/test-kind.sh --apply ${apply_ack}" \
    "  scripts/test-kind.sh --runtime ${apply_ack}" \
    "  scripts/test-kind.sh --transition-runtime {naranjo-online|lidersea-com} ${apply_ack}" \
    '' \
    'Runtime mode additionally requires locally preloaded NARANJO_RUNTIME_IMAGE' \
    'and LIDERSEA_RUNTIME_IMAGE canonical sha256 references. It removes the two' \
    'zero-Pod quotas only inside the owned disposable cluster, runs both sites,' \
    'proves their readiness, and still never starts a tunnel or accepts a secret.' \
    'Transition runtime requires only the selected site image, requires that site' \
    'to be exactly staged in the authoritative transition plan, creates no Flux,' \
    'tunnel, other-site, or production resources, and proves only local readiness.' \
    'Every mutating mode creates and deletes the exact owned internal Docker bridge.'
}

case "${1:---check}" in
  --check)
    (( $# <= 1 )) || { usage >&2; exit 2; }
    check_prerequisites
    log 'Kind local harness prerequisites are ready; no cluster or network was created.'
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
  --transition-runtime)
    (( $# == 3 )) || { usage >&2; exit 2; }
    case "$2" in
      naranjo-online|lidersea-com) ;;
      *) die 'transition runtime site must be naranjo-online or lidersea-com' ;;
    esac
    transition_runtime_site="$2"
    [[ "$3" == "${apply_ack}" ]] || die "exact acknowledgement is required: ${apply_ack}"
    runtime_mode=1
    run_canonical_transition_static_gate
    check_prerequisites
    check_transition_runtime_input
    exercise_cluster
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
