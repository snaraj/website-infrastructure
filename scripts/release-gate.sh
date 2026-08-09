#!/usr/bin/env bash
set -euo pipefail

# Final release evidence gate. Static rendering is necessary but never counted
# as runtime proof: --live also runs disposable Kind readiness, reads an explicit
# production context, exercises real admission with negative dry-runs, and probes
# the public edge from this machine.

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${REPO_ROOT}/versions.env"
readonly LIVE_ACK='I_ACKNOWLEDGE_RELEASE_GATE_WILL_MUTATE_LOCAL_KIND_AND_PROBE_PRODUCTION_AND_PUBLIC_EDGE'
readonly KIND_ACK='I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test_AND_ITS_INTERNAL_DOCKER_NETWORK'
TEMP_ROOT=''
PROD_KUBECONFIG=''
PROD_CONTEXT=''
PYTHON_BIN=''
CAPACITY_EVIDENCE_SHA256=''
RELEASE_GIT_COMMIT=''

die() {
  printf 'release-gate: NO-GO: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'release-gate: %s\n' "$*"
}

usage() {
  cat <<EOF
Usage:
  scripts/release-gate.sh --check
  scripts/release-gate.sh --scaffold
  scripts/release-gate.sh --transition-check
  scripts/release-gate.sh --transition-runtime {naranjo-online|lidersea-com} ${KIND_ACK}
  scripts/release-gate.sh --release-check
  scripts/release-gate.sh --live ${LIVE_ACK} KUBECONFIG CONTEXT

--check         checks required local tools only; reads no cluster/network state.
--scaffold      proves the checked-in desired state remains fail-closed.
--transition-check
                proves the complete canonical transition gate without Docker,
                Kind, production, registry, or public-network access.
--transition-runtime
                statically proves one safe transition, then runs only the
                selected staged site in owned loopback Kind on an exactly owned
                internal Docker bridge; no production, Flux, Tunnel, registry,
                LAN, or public network is accessed.
--release-check requires promoted static desired state and local capacity review.
--live          additionally creates/deletes owned local Kind, reads the exact
                production context, sends server-side dry-run admission probes,
                and runs the external Cloudflare/origin checks.

--release-check and --live require CAPACITY_EVIDENCE_FILE pointing to an
untracked, non-symlink, mode-0600 file with exactly these key/value records:
  SCHEMA=website-infrastructure-capacity-v1
  REVIEWED_GIT_COMMIT=<current 40-hex commit>
  REVIEWED_UTC=<UTC RFC3339 timestamp no older than seven days>
  DISCOVERY_REPORT_SHA256=<64 lowercase hex>
  CPU_SATURATION=PASS
  MEMORY_PRESSURE=PASS
  ROOT_PRESSURE=PASS
  NETWORK_SATURATION=PASS
  ADMIN_SURVIVAL=PASS
  KUBELET_RESERVATIONS=PASS
  SITE_QUOTAS=PASS
  CNI_NETWORKPOLICY=PASS
  TUNNEL_FAILURE_RECOVERY=PASS
  STORAGE_PROFILE=DISABLED

Live exposure inputs HOME_PUBLIC_IP, optional HOME_PUBLIC_IPV6, and
UNEXPECTED_PUBLIC_HOSTNAME remain shell-only and are handled by
verify-exposure.sh without printing residential addresses.
EOF
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$TEMP_ROOT" ]]; then
    case "$TEMP_ROOT" in
      "${TMPDIR:-/tmp}"/website-infra-release.*) rm -rf -- "$TEMP_ROOT" ;;
      *) printf 'release-gate: refusing unsafe temporary cleanup path\n' >&2; status=1 ;;
    esac
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require_static_tools() {
  local tool
  for tool in git rg helm kustomize kubeconform conftest kyverno; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required; this gate never installs tools"
  done
  local candidate
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
  [[ -n "$PYTHON_BIN" ]] || die 'Python 3.8 or newer is required'
}

require_live_tools() {
  require_static_tools
  local tool
  for tool in kubectl kind docker curl dig nc; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required; this gate never installs tools"
  done
}

assert_clean_commit() {
  local before_commit after_commit status_output
  before_commit="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" || \
    die 'release requires an existing Git commit'
  [[ "$before_commit" =~ ^[0-9a-f]{40}$ ]] || \
    die 'release HEAD is not one canonical 40-hex Git commit'
  status_output="$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" || \
    die 'release worktree status could not be read'
  [[ -z "$status_output" ]] || \
    die 'release requires a clean worktree, including no untracked release inputs'
  after_commit="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" || \
    die 'release HEAD became unavailable while checking the worktree'
  [[ "$after_commit" == "$before_commit" ]] || \
    die 'release HEAD changed while checking the worktree'
  if [[ -n "$RELEASE_GIT_COMMIT" ]]; then
    [[ "$after_commit" == "$RELEASE_GIT_COMMIT" ]] || \
      die 'release HEAD changed after static evidence was captured'
  else
    RELEASE_GIT_COMMIT="$after_commit"
  fi
}

assert_storage_disabled() {
  grep -Eq '^  enabled:[[:space:]]+false$' "${REPO_ROOT}/websites/naranjo.online/chart/values.yaml" || \
    die 'naranjo media storage must remain disabled'
  grep -Eq '^  profile:[[:space:]]+UNRESOLVED_PI_MEDIA_STORAGE$' \
    "${REPO_ROOT}/websites/naranjo.online/chart/values.yaml" || \
    die 'naranjo media storage profile is no longer the unresolved disabled sentinel'

  local -a storage_roots=(
    "${REPO_ROOT}/websites/naranjo.online/chart/templates"
    "${REPO_ROOT}/websites/lidersea.com/chart/templates"
    "${REPO_ROOT}/kubernetes/platform/prerequisites"
    "${REPO_ROOT}/kubernetes/platform/cloudflare-public/chart"
    "${REPO_ROOT}/kubernetes/websites"
  )
  local root
  for root in "${storage_roots[@]}"; do
    [[ -d "$root" ]] || die "required storage-proof root is missing: ${root}"
  done
  local forbidden='^[[:space:]]*(kind:[[:space:]]+(PersistentVolume|PersistentVolumeClaim|StorageClass|CSIDriver)|hostPath:|persistentVolumeClaim:|ephemeral:|csi:|nfs:|local:|key:[[:space:]]+node\.kubernetes\.io/disk-pressure)'
  local rg_status=0
  rg -n --glob '*.yaml' --glob '*.yml' "$forbidden" "${storage_roots[@]}" >/dev/null || rg_status=$?
  if (( rg_status == 0 )); then
    die 'host/local/persistent storage or DiskPressure tolerance exists before approved discovery'
  elif (( rg_status != 1 )); then
    die 'storage proof search failed'
  fi
  log 'PASS static storage profile is disabled with no hostPath/local PV/PVC/disk-pressure bypass'
}

assert_capacity_evidence() {
  : "${CAPACITY_EVIDENCE_FILE:?Set CAPACITY_EVIDENCE_FILE to the ignored mode-0600 review contract}"
  local commit
  commit="$RELEASE_GIT_COMMIT"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || \
    die 'capacity evidence cannot bind to an unavailable release commit'
  "$PYTHON_BIN" - "$CAPACITY_EVIDENCE_FILE" "$commit" "$REPO_ROOT" \
    "${REPO_ROOT}/.artifacts/rendered/kubernetes-platform-prerequisites.yaml" <<'PY'
import datetime as dt
import os
import pathlib
import re
import stat
import subprocess
import sys

path = pathlib.Path(sys.argv[1])
commit = sys.argv[2]
repo = pathlib.Path(sys.argv[3]).resolve()
rendered_prerequisites = pathlib.Path(sys.argv[4])
if path.is_symlink() or not path.is_file():
    raise SystemExit("capacity evidence must be a regular non-symlink file")
mode = stat.S_IMODE(path.stat().st_mode)
if mode != 0o600:
    raise SystemExit(f"capacity evidence mode must be 0600, got {mode:04o}")
resolved = path.resolve()
try:
    relative = resolved.relative_to(repo)
except ValueError:
    relative = None
if relative is not None:
    tracked = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--error-unmatch", "--", str(relative)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if tracked.returncode == 0:
        raise SystemExit("capacity evidence must never be tracked by Git")

required = {
    "SCHEMA": "website-infrastructure-capacity-v1",
    "REVIEWED_GIT_COMMIT": commit,
    "CPU_SATURATION": "PASS",
    "MEMORY_PRESSURE": "PASS",
    "ROOT_PRESSURE": "PASS",
    "NETWORK_SATURATION": "PASS",
    "ADMIN_SURVIVAL": "PASS",
    "KUBELET_RESERVATIONS": "PASS",
    "SITE_QUOTAS": "PASS",
    "CNI_NETWORKPOLICY": "PASS",
    "TUNNEL_FAILURE_RECOVERY": "PASS",
    "STORAGE_PROFILE": "DISABLED",
}
values = {}
for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    if not raw or raw.startswith("#"):
        continue
    if "=" not in raw:
        raise SystemExit(f"capacity evidence line {number} is not KEY=VALUE")
    key, value = raw.split("=", 1)
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
        raise SystemExit(f"capacity evidence line {number} has an invalid or duplicate key")
    values[key] = value
allowed = set(required) | {"REVIEWED_UTC", "DISCOVERY_REPORT_SHA256"}
if set(values) != allowed:
    missing = sorted(allowed - set(values))
    extra = sorted(set(values) - allowed)
    raise SystemExit(f"capacity evidence keys mismatch; missing={missing}, extra={extra}")
for key, expected in required.items():
    if values[key] != expected:
        raise SystemExit(f"capacity evidence {key} does not match the required reviewed value")
if not re.fullmatch(r"[0-9a-f]{64}", values["DISCOVERY_REPORT_SHA256"]):
    raise SystemExit("DISCOVERY_REPORT_SHA256 must be 64 lowercase hex")

if not rendered_prerequisites.is_file() or rendered_prerequisites.is_symlink():
    raise SystemExit("rendered current prerequisite artifact is missing or is a symlink")

def plain_scalar(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value

def document_metadata(lines):
    metadata = {}
    annotations = {}
    in_metadata = False
    in_annotations = False
    for raw in lines:
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            in_metadata = stripped == "metadata:"
            in_annotations = False
            continue
        if not in_metadata:
            continue
        if indent == 2:
            in_annotations = stripped == "annotations:"
            if not in_annotations and ":" in stripped:
                key, value = stripped.split(":", 1)
                metadata[key] = plain_scalar(value)
            continue
        if indent == 4 and in_annotations and ":" in stripped:
            key, value = stripped.split(":", 1)
            annotations[key] = plain_scalar(value)
    return metadata, annotations

documents = []
current = []
for raw in rendered_prerequisites.read_text(encoding="utf-8").splitlines():
    if raw.strip() == "---":
        if current:
            documents.append(current)
        current = []
    else:
        current.append(raw)
if current:
    documents.append(current)

site_namespaces = {"naranjo-online", "lidersea-com"}
site_quotas = []
for document in documents:
    kinds = [plain_scalar(line.split(":", 1)[1]) for line in document if line.startswith("kind:")]
    if kinds != ["ResourceQuota"]:
        continue
    metadata, annotations = document_metadata(document)
    if metadata.get("namespace") in site_namespaces:
        site_quotas.append((metadata, annotations))

expected_identities = {(namespace, "namespace-budget") for namespace in site_namespaces}
actual_identities = {(metadata.get("namespace"), metadata.get("name")) for metadata, _ in site_quotas}
if len(site_quotas) != 2 or actual_identities != expected_identities:
    raise SystemExit("rendered prerequisites must contain exactly two promoted site namespace-budget quotas")
for metadata, annotations in site_quotas:
    identity = f"{metadata['namespace']}/{metadata['name']}"
    if annotations.get("platform.snaraj.dev/readiness") != "reviewed-pi-capacity":
        raise SystemExit(f"rendered quota {identity} lacks reviewed-pi-capacity readiness")
    if annotations.get("platform.snaraj.dev/capacity-evidence-sha256") != values["DISCOVERY_REPORT_SHA256"]:
        raise SystemExit(f"rendered quota {identity} is not bound to the reviewed discovery evidence hash")

try:
    reviewed = dt.datetime.strptime(values["REVIEWED_UTC"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
except ValueError as exc:
    raise SystemExit("REVIEWED_UTC must be UTC RFC3339 (YYYY-MM-DDTHH:MM:SSZ)") from exc
age = dt.datetime.now(dt.timezone.utc) - reviewed
if age.total_seconds() < -300 or age > dt.timedelta(days=7):
    raise SystemExit("capacity review is future-dated or older than seven days")
print("release-gate: PASS local capacity contract is current, commit-bound, and matches both rendered site quotas")
PY
  CAPACITY_EVIDENCE_SHA256="$(awk -F= '$1 == "DISCOVERY_REPORT_SHA256" {print $2}' "$CAPACITY_EVIDENCE_FILE")"
  [[ "$CAPACITY_EVIDENCE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die 'validated capacity evidence hash could not be reloaded'
}

assert_signature_policies_enforced() {
  local name file
  for name in require-signed-naranjo-online require-signed-lidersea-com; do
    file="${REPO_ROOT}/policies/kyverno/${name}.yaml"
    grep -Eq '^  validationFailureAction:[[:space:]]+Enforce$' "$file" || \
      die "${name} remains staged Audit rather than Enforce"
  done
  if grep -Eq '^[[:space:]]*-[[:space:]]+require-zero-site-capacity\.yaml$' \
    "${REPO_ROOT}/policies/kyverno/kustomization.yaml"; then
    die 'zero-site-capacity policy remains active; reviewed capacity promotion is incomplete'
  fi
  log 'PASS both image-signature policies are Enforce and the zero-capacity staging policy is inactive'
}

run_static_gate() {
  local mode="$1"
  if [[ "$mode" == '--release' ]]; then
    assert_clean_commit
  fi
  "$PYTHON_BIN" "${REPO_ROOT}/scripts/validate_repository.py" all
  bash "${REPO_ROOT}/scripts/render-manifests.sh" "$mode"
  assert_storage_disabled
  if [[ "$mode" == '--release' ]]; then
    assert_clean_commit
    assert_capacity_evidence
    assert_signature_policies_enforced
  fi
}

desired_deployment_image() {
  local artifact="$1"
  local repository="$2"
  local deployment_name="$3"
  local container_name="$4"
  local image
  image="$(awk -v target="$deployment_name" -v wanted_container="$container_name" '
    function flush_container() {
      if (current_name == wanted_container && current_image != "") print current_image
      current_name = ""
      current_image = ""
    }
    function finish_containers() {
      flush_container()
      in_containers = 0
      item_indent = -1
    }
    function reset_document() {
      kind = ""
      resource = ""
      in_containers = 0
      item_indent = -1
      current_name = ""
      current_image = ""
    }
    function indentation(line) {
      match(line, /[^ ]/)
      return RSTART == 0 ? length(line) : RSTART - 1
    }
    BEGIN {reset_document()}
    /^---/ {
      if (in_containers) finish_containers()
      reset_document()
      next
    }
    {indent = indentation($0)}
    $1 == "kind:" {kind = $2}
    kind == "Deployment" && resource == "" && $1 == "name:" {resource = $2}
    kind == "Deployment" && resource == target && $1 == "containers:" {
      in_containers = 1
      containers_indent = indent
      item_indent = -1
      next
    }
    in_containers {
      if ($1 != "-" && indent <= containers_indent) {
        finish_containers()
      } else if ($1 == "-" && ($2 == "name:" || $2 == "image:")) {
        if (item_indent == -1) item_indent = indent
        if (indent == item_indent) {
          flush_container()
          if ($2 == "name:") current_name = $3
          if ($2 == "image:") current_image = $3
          next
        }
      }
      if (item_indent >= 0 && indent == item_indent + 2) {
        if ($1 == "name:") current_name = $2
        if ($1 == "image:") current_image = $2
      }
    }
    END {
      if (in_containers) finish_containers()
    }
  ' "$artifact")"
  image="${image//\"/}"
  [[ "$image" =~ ^${repository}@sha256:[0-9a-f]{64}$ ]] || \
    die "rendered Deployment does not contain one canonical immutable image for ${repository}"
  [[ "$image" != *'@sha256:0000000000000000000000000000000000000000000000000000000000000000' ]] || \
    die "rendered Deployment for ${repository} still has the all-zero digest"
  printf '%s\n' "$image"
}

kubectl_prod() {
  kubectl --kubeconfig "$PROD_KUBECONFIG" --context "$PROD_CONTEXT" "$@"
}

validate_production_context() {
  [[ -f "$PROD_KUBECONFIG" && ! -L "$PROD_KUBECONFIG" ]] || die 'KUBECONFIG must be an explicit regular non-symlink file'
  [[ -n "$PROD_CONTEXT" && "$PROD_CONTEXT" != kind-* ]] || die 'an explicit non-Kind production context is required'
  [[ "$(kubectl --kubeconfig "$PROD_KUBECONFIG" config get-contexts "$PROD_CONTEXT" -o name)" == "$PROD_CONTEXT" ]] || \
    die 'the explicit production context is not present in the supplied kubeconfig'
  local server
  server="$(kubectl_prod config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
  [[ "$server" == https://* ]] || die 'production API endpoint must use HTTPS'
  log 'PASS explicit production kubeconfig/context resolved to an HTTPS API (address withheld)'
}

new_temp_root() {
  TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/website-infra-release.XXXXXX")"
  case "$TEMP_ROOT" in
    "${TMPDIR:-/tmp}"/website-infra-release.*) ;;
    *) die 'mktemp returned an unsafe release-gate path' ;;
  esac
}

capture_production_state() {
  capture_prod_json namespaces.json Namespaces get namespaces -o json
  capture_prod_json nodes.json nodes get nodes -o json
  capture_prod_json deployments.json deployments get deployments -A -o json
  capture_prod_json daemonsets.json DaemonSets get daemonsets.apps -A -o json
  capture_prod_json statefulsets.json StatefulSets get statefulsets.apps -A -o json
  capture_prod_json replicasets.json replicasets get replicasets.apps -A -o json
  capture_prod_json replicationcontrollers.json ReplicationControllers get replicationcontrollers -A -o json
  capture_prod_json jobs.json Jobs get jobs.batch -A -o json
  capture_prod_json cronjobs.json CronJobs get cronjobs.batch -A -o json
  capture_prod_json horizontalpodautoscalers.json HorizontalPodAutoscalers get horizontalpodautoscalers.autoscaling -A -o json
  capture_prod_json pods.json pods get pods -A -o json
  capture_prod_json services.json services get services -A -o json
  capture_prod_json networkpolicies.json networkpolicies get networkpolicies.networking.k8s.io -A -o json
  capture_prod_json pvcs.json pvcs get persistentvolumeclaims -A -o json
  capture_prod_json quotas.json quotas get resourcequotas -A -o json
  capture_prod_json webhooks.json webhooks get validatingwebhookconfigurations -o json
  capture_prod_json mutatingwebhooks.json MutatingWebhooks get mutatingwebhookconfigurations -o json
  capture_prod_json policies.json policies get clusterpolicies.kyverno.io -o json
  capture_prod_json gitrepositories.json GitRepositories get gitrepositories.source.toolkit.fluxcd.io -A -o json
  capture_prod_json buckets.json Buckets get buckets.source.toolkit.fluxcd.io -A -o json
  capture_prod_json externalartifacts.json ExternalArtifacts get externalartifacts.source.toolkit.fluxcd.io -A -o json
  capture_prod_json helmrepositories.json HelmRepositories get helmrepositories.source.toolkit.fluxcd.io -A -o json
  capture_prod_json ocirepositories.json OCIRepositories get ocirepositories.source.toolkit.fluxcd.io -A -o json
  capture_prod_json helmcharts.json HelmCharts get helmcharts.source.toolkit.fluxcd.io -A -o json
  capture_prod_json kustomizations.json Kustomizations get kustomizations.kustomize.toolkit.fluxcd.io -A -o json
  capture_prod_json helmreleases.json helmreleases get helmreleases.helm.toolkit.fluxcd.io -A -o json
}

capture_prod_json() {
  local output_name="$1"
  local label="$2"
  shift 2
  local error_file="${TEMP_ROOT}/kubectl-error.txt"
  if ! kubectl_prod "$@" >"${TEMP_ROOT}/${output_name}" 2>"$error_file"; then
    die "production ${label} query failed (details withheld in temporary local evidence)"
  fi
  : >"$error_file"
}

capture_desired_security_policy_state() {
  local error_file="${TEMP_ROOT}/kubectl-error.txt"
  local kind name namespace source

  # Extract the complete expected Flux authority chain from canonical rendered
  # output, then ask the real API server to apply CRD defaults without writing.
  # The live validator compares each resulting spec exactly. This closes fields
  # such as Kustomization patches/postBuild and GitRepository include/proxy/auth
  # that a revision-only check cannot see.
  "$PYTHON_BIN" - "$REPO_ROOT" "$TEMP_ROOT" <<'PY'
import pathlib
import re
import sys

repo = pathlib.Path(sys.argv[1]).resolve()
output_root = pathlib.Path(sys.argv[2]).resolve()
expected = {
    ("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "flux-system"),
    ("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "platform-prerequisites"),
    ("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "admission"),
    ("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "platform-services"),
    ("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "naranjo-online"),
    ("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "lidersea-com"),
    ("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "flux-system"),
    ("source.toolkit.fluxcd.io/v1", "GitRepository", "naranjo-online", "naranjo-online-source"),
    ("source.toolkit.fluxcd.io/v1", "GitRepository", "lidersea-com", "lidersea-com-source"),
    ("source.toolkit.fluxcd.io/v1", "GitRepository", "cloudflare-public", "cloudflare-public-source"),
    ("helm.toolkit.fluxcd.io/v2", "HelmRelease", "naranjo-online", "naranjo-online"),
    ("helm.toolkit.fluxcd.io/v2", "HelmRelease", "lidersea-com", "lidersea-com"),
    ("helm.toolkit.fluxcd.io/v2", "HelmRelease", "cloudflare-public", "cloudflare-public"),
}
relevant_types = {(identity[0], identity[1]) for identity in expected}
artifacts = (
    repo / ".artifacts/rendered/kubernetes-flux-system.yaml",
    repo / ".artifacts/rendered/kubernetes-reconciliation.yaml",
    repo / ".artifacts/rendered/kubernetes-websites-naranjo-online.yaml",
    repo / ".artifacts/rendered/kubernetes-websites-lidersea-com.yaml",
    repo / ".artifacts/rendered/kubernetes-platform-cloudflare-public-release.yaml",
)


def one_top_level(lines, key):
    prefix = key + ": "
    values = [line[len(prefix):] for line in lines if line.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        return None
    return values[0]


def metadata_identity(lines):
    indexes = [index for index, line in enumerate(lines) if line == "metadata:"]
    if len(indexes) != 1:
        return None
    values = {}
    for line in lines[indexes[0] + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if indent != 2:
            continue
        match = re.fullmatch(
            r"  (name|namespace): ([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)",
            line,
        )
        if match is not None:
            key, value = match.groups()
            if key in values:
                return None
            values[key] = value
    if set(values) != {"name", "namespace"}:
        return None
    return values["namespace"], values["name"]


selected = {}
for artifact in artifacts:
    if artifact.is_symlink() or not artifact.is_file():
        raise SystemExit("rendered Flux artifact is unavailable or unsafe")
    text = artifact.read_text(encoding="utf-8")
    for document in re.split(r"(?m)^---[ \t]*$", text):
        lines = document.splitlines()
        api_version = one_top_level(lines, "apiVersion")
        kind = one_top_level(lines, "kind")
        if (api_version, kind) not in relevant_types:
            continue
        identity = metadata_identity(lines)
        if identity is None:
            raise SystemExit("rendered Flux object identity is non-canonical")
        complete = (api_version, kind, identity[0], identity[1])
        if complete not in expected or complete in selected:
            raise SystemExit("rendered Flux object inventory is outside the closed contract")
        selected[complete] = document.strip() + "\n"
if set(selected) != expected:
    raise SystemExit("rendered Flux object inventory is incomplete")
for (_api_version, kind, namespace, name), document in selected.items():
    destination = output_root / (
        "desired-flux-{}-{}-{}.yaml".format(kind.lower(), namespace, name)
    )
    destination.write_text(document, encoding="utf-8")
PY

  while IFS='|' read -r kind namespace name; do
    source="${TEMP_ROOT}/desired-flux-${kind,,}-${namespace}-${name}.yaml"
    [[ -f "$source" && ! -L "$source" ]] || \
      die "desired Flux object source is unavailable or unsafe: ${kind} ${namespace}/${name}"
    if ! kubectl_prod apply \
      --server-side \
      --dry-run=server \
      --force-conflicts \
      --field-manager=website-infrastructure-release-gate \
      -f "$source" \
      -o json >"${TEMP_ROOT}/desired-flux-${kind,,}-${namespace}-${name}.json" 2>"$error_file"; then
      die "production server could not normalize desired ${kind} ${namespace}/${name} (details withheld)"
    fi
    : >"$error_file"
  done <<'EOF'
kustomization|flux-system|flux-system
kustomization|flux-system|platform-prerequisites
kustomization|flux-system|admission
kustomization|flux-system|platform-services
kustomization|flux-system|naranjo-online
kustomization|flux-system|lidersea-com
gitrepository|flux-system|flux-system
gitrepository|naranjo-online|naranjo-online-source
gitrepository|lidersea-com|lidersea-com-source
gitrepository|cloudflare-public|cloudflare-public-source
helmrelease|naranjo-online|naranjo-online
helmrelease|lidersea-com|lidersea-com
helmrelease|cloudflare-public|cloudflare-public
EOF

  for name in \
    disallow-public-services \
    disallow-tenant-media-payloads \
    disallow-undiscovered-storage \
    require-approved-images \
    require-exact-tenant-networking \
    require-release-readiness \
    require-restricted-workloads \
    require-signed-naranjo-online \
    require-signed-lidersea-com; do
    source="${REPO_ROOT}/policies/kyverno/${name}.yaml"
    [[ -f "$source" && ! -L "$source" ]] || \
      die "desired ClusterPolicy source is unavailable or unsafe: ${name}"
    # Ask the real API server to apply CRD defaults without persisting anything.
    # --force-conflicts only affects this dry-run representation; it can never
    # take ownership of a live field because the request is explicitly dry-run.
    if ! kubectl_prod apply \
      --server-side \
      --dry-run=server \
      --force-conflicts \
      --field-manager=website-infrastructure-release-gate \
      -f "$source" \
      -o json >"${TEMP_ROOT}/desired-policy-${name}.json" 2>"$error_file"; then
      die "production server could not normalize desired ClusterPolicy ${name} (details withheld)"
    fi
    : >"$error_file"
  done

  # Extract only the nine closed tenant NetworkPolicy identities from the
  # canonical rendered artifacts. This parser does not interpret YAML; it
  # accepts one exact block-form identity shape and refuses missing, duplicate,
  # or extra tenant policies before any production dry-run request is made.
  "$PYTHON_BIN" - "$REPO_ROOT" "$TEMP_ROOT" <<'PY'
import pathlib
import re
import sys

repo = pathlib.Path(sys.argv[1]).resolve()
output_root = pathlib.Path(sys.argv[2]).resolve()
expected = {
    ("cloudflare-public", "default-deny"),
    ("cloudflare-public", "cloudflared-dns"),
    ("cloudflare-public", "cloudflared-edge"),
    ("cloudflare-public", "cloudflared-naranjo-online"),
    ("cloudflare-public", "cloudflared-lidersea-com"),
    ("naranjo-online", "default-deny"),
    ("naranjo-online", "cloudflared-to-naranjo-online"),
    ("lidersea-com", "default-deny"),
    ("lidersea-com", "cloudflared-to-lidersea-com"),
}
tenant_namespaces = {identity[0] for identity in expected}
artifacts = (
    repo / ".artifacts/rendered/kubernetes-platform-prerequisites.yaml",
    repo / ".artifacts/rendered/helm-naranjo-online.yaml",
    repo / ".artifacts/rendered/helm-lidersea-com.yaml",
    repo / ".artifacts/rendered/helm-cloudflare-public.yaml",
)
selected = {}
for artifact in artifacts:
    if artifact.is_symlink() or not artifact.is_file():
        raise SystemExit("rendered NetworkPolicy artifact is unavailable or unsafe")
    text = artifact.read_text(encoding="utf-8")
    for document in re.split(r"(?m)^---[ \t]*$", text):
        lines = document.splitlines()
        kinds = [line[6:] for line in lines if line.startswith("kind: ")]
        if kinds != ["NetworkPolicy"]:
            continue
        metadata_indexes = [
            index for index, line in enumerate(lines) if line == "metadata:"
        ]
        if len(metadata_indexes) != 1:
            raise SystemExit("rendered NetworkPolicy metadata is non-canonical")
        direct = []
        for line in lines[metadata_indexes[0] + 1 :]:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent == 0:
                break
            if indent != 2:
                continue
            match = re.fullmatch(r"  (name|namespace): ([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)", line)
            if match is not None:
                direct.append(match.groups())
        if [key for key, _ in direct] != ["name", "namespace"]:
            raise SystemExit("rendered NetworkPolicy identity is non-canonical")
        values = dict(direct)
        identity = (values["namespace"], values["name"])
        if identity[0] not in tenant_namespaces:
            continue
        if identity not in expected or identity in selected:
            raise SystemExit("rendered tenant NetworkPolicy inventory is outside the closed contract")
        selected[identity] = document.strip() + "\n"
if set(selected) != expected:
    raise SystemExit("rendered tenant NetworkPolicy inventory is incomplete")
for (namespace, name), document in selected.items():
    destination = output_root / f"desired-networkpolicy-{namespace}-{name}.yaml"
    destination.write_text(document, encoding="utf-8")
PY

  local identity namespace name
  for identity in \
    cloudflare-public/default-deny \
    cloudflare-public/cloudflared-dns \
    cloudflare-public/cloudflared-edge \
    cloudflare-public/cloudflared-naranjo-online \
    cloudflare-public/cloudflared-lidersea-com \
    naranjo-online/default-deny \
    naranjo-online/cloudflared-to-naranjo-online \
    lidersea-com/default-deny \
    lidersea-com/cloudflared-to-lidersea-com; do
    namespace="${identity%%/*}"
    name="${identity#*/}"
    source="${TEMP_ROOT}/desired-networkpolicy-${namespace}-${name}.yaml"
    [[ -f "$source" && ! -L "$source" ]] || \
      die "desired NetworkPolicy source is unavailable or unsafe: ${identity}"
    if ! kubectl_prod apply \
      --server-side \
      --dry-run=server \
      --force-conflicts \
      --field-manager=website-infrastructure-release-gate \
      -f "$source" \
      -o json >"${TEMP_ROOT}/desired-networkpolicy-${namespace}-${name}.json" 2>"$error_file"; then
      die "production server could not normalize desired NetworkPolicy ${identity} (details withheld)"
    fi
    : >"$error_file"
  done
}

assert_flux_revision_and_security_policy_state() {
  "$PYTHON_BIN" - "$TEMP_ROOT" "$RELEASE_GIT_COMMIT" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
commit = sys.argv[2]
if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("release Git commit is unavailable or non-canonical")
expected_git_revision = "main@sha1:" + commit


def load_items(name):
    document = json.loads((root / name).read_text(encoding="utf-8"))
    items = document.get("items")
    if not isinstance(items, list):
        raise SystemExit(f"{name} does not contain one Kubernetes item list")
    return items


def metadata(item):
    value = item.get("metadata", {})
    return value if isinstance(value, dict) else {}


def status(item):
    value = item.get("status", {})
    return value if isinstance(value, dict) else {}


def one_ready(item, kind, identity):
    conditions = status(item).get("conditions", [])
    ready = [
        condition
        for condition in conditions
        if isinstance(condition, dict) and condition.get("type") == "Ready"
    ]
    if len(ready) != 1 or ready[0].get("status") != "True":
        raise SystemExit(f"{kind} {identity} does not have exactly one Ready=True condition")


def exact_generation(item, kind, identity):
    generation = metadata(item).get("generation")
    observed = status(item).get("observedGeneration")
    if (
        type(generation) is not int
        or generation < 1
        or type(observed) is not int
        or observed != generation
    ):
        raise SystemExit(f"{kind} {identity} has not observed its exact current generation")
    return generation


def by_identity(items, namespace, name, kind):
    matches = [
        item
        for item in items
        if metadata(item).get("namespace") == namespace
        and metadata(item).get("name") == name
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one {kind} {namespace}/{name}, found {len(matches)}"
        )
    return matches[0]


def exact_namespaced_inventory(items, expected, kind):
    identities = []
    for item in items:
        if not isinstance(item, dict):
            raise SystemExit(f"{kind} inventory contains a non-object item")
        identities.append(
            (metadata(item).get("namespace"), metadata(item).get("name"))
        )
    if len(identities) != len(expected) or set(identities) != expected:
        raise SystemExit(f"live {kind} inventory differs from the exact release set")


def desired_flux_object(kind, api_version, namespace, name):
    path = root / "desired-flux-{}-{}-{}.json".format(
        kind.lower(), namespace, name
    )
    desired = json.loads(path.read_text(encoding="utf-8"))
    if (
        desired.get("apiVersion") != api_version
        or desired.get("kind") != kind
        or metadata(desired).get("namespace") != namespace
        or metadata(desired).get("name") != name
        or not isinstance(desired.get("spec"), dict)
    ):
        raise SystemExit(f"desired {kind} normalization is invalid: {namespace}/{name}")
    return desired


kustomization_identities = {
    ("flux-system", "flux-system"),
    ("flux-system", "platform-prerequisites"),
    ("flux-system", "admission"),
    ("flux-system", "platform-services"),
    ("flux-system", "naranjo-online"),
    ("flux-system", "lidersea-com"),
}
kustomizations = load_items("kustomizations.json")
exact_namespaced_inventory(
    kustomizations, kustomization_identities, "Kustomization"
)
for name in (
    "flux-system",
    "platform-prerequisites",
    "admission",
    "platform-services",
    "naranjo-online",
    "lidersea-com",
):
    identity = "flux-system/" + name
    item = by_identity(kustomizations, "flux-system", name, "Kustomization")
    desired = desired_flux_object(
        "Kustomization",
        "kustomize.toolkit.fluxcd.io/v1",
        "flux-system",
        name,
    )
    exact_generation(item, "Kustomization", identity)
    one_ready(item, "Kustomization", identity)
    current_status = status(item)
    if (
        current_status.get("lastAppliedRevision") != expected_git_revision
        or current_status.get("lastAttemptedRevision") != expected_git_revision
    ):
        raise SystemExit(
            f"Kustomization {identity} is not applied and attempted at exact local HEAD"
        )
    if item.get("spec") != desired.get("spec"):
        raise SystemExit(f"Kustomization {identity} spec differs from exact desired state")


source_identities = {
    ("flux-system", "flux-system"),
    ("naranjo-online", "naranjo-online-source"),
    ("lidersea-com", "lidersea-com-source"),
    ("cloudflare-public", "cloudflare-public-source"),
}
gitrepositories = load_items("gitrepositories.json")
exact_namespaced_inventory(gitrepositories, source_identities, "GitRepository")
for namespace, name in sorted(source_identities):
    identity = f"{namespace}/{name}"
    item = by_identity(gitrepositories, namespace, name, "GitRepository")
    desired = desired_flux_object(
        "GitRepository", "source.toolkit.fluxcd.io/v1", namespace, name
    )
    exact_generation(item, "GitRepository", identity)
    one_ready(item, "GitRepository", identity)
    spec = item.get("spec", {})
    artifact = status(item).get("artifact", {})
    if (
        spec.get("url") != "https://github.com/snaraj/website-infrastructure.git"
        or spec.get("ref") != {"branch": "main"}
        or not isinstance(artifact, dict)
        or artifact.get("revision") != expected_git_revision
    ):
        raise SystemExit(f"GitRepository {identity} is not the exact current main artifact")
    if spec != desired.get("spec"):
        raise SystemExit(f"GitRepository {identity} spec differs from exact desired state")


for filename, kind in (
    ("buckets.json", "Bucket"),
    ("externalartifacts.json", "ExternalArtifact"),
    ("helmrepositories.json", "HelmRepository"),
    ("ocirepositories.json", "OCIRepository"),
):
    if load_items(filename):
        raise SystemExit(f"live {kind} inventory must be empty")


helmreleases = load_items("helmreleases.json")
helmcharts = load_items("helmcharts.json")
release_sources = {
    ("naranjo-online", "naranjo-online"): "naranjo-online-source",
    ("lidersea-com", "lidersea-com"): "lidersea-com-source",
    ("cloudflare-public", "cloudflare-public"): "cloudflare-public-source",
}
expected_chart_identities = {
    (namespace, f"{namespace}-{name}")
    for namespace, name in release_sources
}
exact_namespaced_inventory(helmreleases, set(release_sources), "HelmRelease")
exact_namespaced_inventory(helmcharts, expected_chart_identities, "HelmChart")
for (namespace, name), source_name in release_sources.items():
    identity = f"{namespace}/{name}"
    release = by_identity(helmreleases, namespace, name, "HelmRelease")
    desired_release = desired_flux_object(
        "HelmRelease", "helm.toolkit.fluxcd.io/v2", namespace, name
    )
    if release.get("spec") != desired_release.get("spec"):
        raise SystemExit(f"HelmRelease {identity} spec differs from exact desired state")
    generation = exact_generation(release, "HelmRelease", identity)
    one_ready(release, "HelmRelease", identity)
    release_status = status(release)
    attempted_generation = release_status.get("lastAttemptedGeneration")
    attempted_revision = release_status.get("lastAttemptedRevision")
    if type(attempted_generation) is not int or attempted_generation != generation:
        raise SystemExit(f"HelmRelease {identity} did not attempt its exact current generation")
    if not isinstance(attempted_revision, str) or not attempted_revision:
        raise SystemExit(f"HelmRelease {identity} has no attempted source revision")
    history = release_status.get("history")
    if not isinstance(history, list) or not history or not isinstance(history[0], dict):
        raise SystemExit(f"HelmRelease {identity} has no successful release history")
    latest = history[0]
    if (
        latest.get("name") != name
        or latest.get("namespace") != namespace
        or latest.get("status") != "deployed"
        or latest.get("chartVersion") != attempted_revision
    ):
        raise SystemExit(
            f"HelmRelease {identity} attempted revision is not its latest deployed revision"
        )
    chart_reference = release_status.get("helmChart")
    if not isinstance(chart_reference, str) or chart_reference.count("/") != 1:
        raise SystemExit(f"HelmRelease {identity} has no canonical HelmChart reference")
    chart_namespace, chart_name = chart_reference.split("/", 1)
    expected_chart_name = f"{namespace}-{name}"
    if chart_namespace != namespace or chart_name != expected_chart_name:
        raise SystemExit(f"HelmRelease {identity} references an unexpected HelmChart")
    chart_identity = f"{chart_namespace}/{chart_name}"
    chart = by_identity(helmcharts, chart_namespace, chart_name, "HelmChart")
    exact_generation(chart, "HelmChart", chart_identity)
    one_ready(chart, "HelmChart", chart_identity)
    chart_spec = chart.get("spec", {})
    desired_chart_spec = desired_release.get("spec", {}).get("chart", {}).get("spec")
    chart_status = status(chart)
    chart_artifact = chart_status.get("artifact", {})
    if (
        chart_spec.get("reconcileStrategy") != "Revision"
        or chart_spec.get("sourceRef")
        != {"kind": "GitRepository", "name": source_name}
        or chart_spec != desired_chart_spec
        or chart_status.get("observedSourceArtifactRevision")
        != expected_git_revision
        or not isinstance(chart_artifact, dict)
        or chart_artifact.get("revision") != attempted_revision
    ):
        raise SystemExit(
            f"HelmRelease {identity} is not applied from its exact current Git artifact"
        )


required_policies = {
    "disallow-public-services",
    "disallow-tenant-media-payloads",
    "disallow-undiscovered-storage",
    "require-approved-images",
    "require-exact-tenant-networking",
    "require-release-readiness",
    "require-restricted-workloads",
    "require-signed-naranjo-online",
    "require-signed-lidersea-com",
}
live_policies = {
    metadata(policy).get("name"): policy for policy in load_items("policies.json")
}
if len(live_policies) != len(required_policies) or set(live_policies) != required_policies:
    raise SystemExit("live ClusterPolicy inventory differs from the exact desired state")
for name in sorted(required_policies):
    live = live_policies.get(name)
    if live is None:
        raise SystemExit(f"required live ClusterPolicy is missing: {name}")
    desired_path = root / f"desired-policy-{name}.json"
    desired = json.loads(desired_path.read_text(encoding="utf-8"))
    if (
        desired.get("apiVersion") != "kyverno.io/v1"
        or desired.get("kind") != "ClusterPolicy"
        or metadata(desired).get("name") != name
        or not isinstance(desired.get("spec"), dict)
    ):
        raise SystemExit(f"desired ClusterPolicy normalization is invalid: {name}")
    if live.get("spec") != desired.get("spec"):
        raise SystemExit(f"live ClusterPolicy spec differs from exact desired state: {name}")


expected_network_policies = {
    ("cloudflare-public", "default-deny"),
    ("cloudflare-public", "cloudflared-dns"),
    ("cloudflare-public", "cloudflared-edge"),
    ("cloudflare-public", "cloudflared-naranjo-online"),
    ("cloudflare-public", "cloudflared-lidersea-com"),
    ("naranjo-online", "default-deny"),
    ("naranjo-online", "cloudflared-to-naranjo-online"),
    ("lidersea-com", "default-deny"),
    ("lidersea-com", "cloudflared-to-lidersea-com"),
}
tenant_namespaces = {identity[0] for identity in expected_network_policies}
tenant_network_policies = [
    policy
    for policy in load_items("networkpolicies.json")
    if metadata(policy).get("namespace") in tenant_namespaces
]
live_network_policies = {
    (metadata(policy).get("namespace"), metadata(policy).get("name")): policy
    for policy in tenant_network_policies
}
if (
    len(tenant_network_policies) != len(expected_network_policies)
    or set(live_network_policies) != expected_network_policies
):
    raise SystemExit("live tenant NetworkPolicy inventory differs from exact desired state")
for namespace, name in sorted(expected_network_policies):
    desired_path = root / f"desired-networkpolicy-{namespace}-{name}.json"
    desired = json.loads(desired_path.read_text(encoding="utf-8"))
    if (
        desired.get("apiVersion") != "networking.k8s.io/v1"
        or desired.get("kind") != "NetworkPolicy"
        or metadata(desired).get("namespace") != namespace
        or metadata(desired).get("name") != name
        or not isinstance(desired.get("spec"), dict)
    ):
        raise SystemExit(
            f"desired NetworkPolicy normalization is invalid: {namespace}/{name}"
        )
    if live_network_policies[(namespace, name)].get("spec") != desired.get("spec"):
        raise SystemExit(
            f"live NetworkPolicy spec differs from exact desired state: {namespace}/{name}"
        )

print(
    "release-gate: PASS Flux sources, Helm revisions, and live security-policy specs are bound to exact local HEAD"
)
PY
}

assert_global_runtime_inventory() {
  "$PYTHON_BIN" - \
    "$TEMP_ROOT" \
    "$NARANJO_RUNTIME_IMAGE" \
    "$LIDERSEA_RUNTIME_IMAGE" \
    "$CLOUDFLARED_RUNTIME_IMAGE" \
    "$ADMISSION_RUNTIME_IMAGE" \
    "$FLUX_SOURCE_CONTROLLER_IMAGE" \
    "$FLUX_KUSTOMIZE_CONTROLLER_IMAGE" \
    "$FLUX_HELM_CONTROLLER_IMAGE" \
    "$KUBERNETES_VERSION" \
    "$COREDNS_IMAGE" \
    "$ETCD_IMAGE" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
naranjo_image = sys.argv[2]
lidersea_image = sys.argv[3]
cloudflared_image = sys.argv[4]
admission_image = sys.argv[5]
flux_source_image = sys.argv[6]
flux_kustomize_image = sys.argv[7]
flux_helm_image = sys.argv[8]
kubernetes_version = sys.argv[9]
coredns_image = sys.argv[10]
etcd_image = sys.argv[11]


def load_items(name):
    document = json.loads((root / name).read_text(encoding="utf-8"))
    items = document.get("items")
    if not isinstance(items, list):
        raise SystemExit(f"{name} does not contain one Kubernetes item list")
    if any(not isinstance(item, dict) for item in items):
        raise SystemExit(f"{name} contains a non-object item")
    return items


def metadata(item):
    value = item.get("metadata", {})
    return value if isinstance(value, dict) else {}


def namespaced_identity(item):
    return metadata(item).get("namespace"), metadata(item).get("name")


def exact_namespaced_map(items, expected, kind):
    identities = [namespaced_identity(item) for item in items]
    if len(identities) != len(expected) or set(identities) != expected:
        raise SystemExit(f"live {kind} inventory differs from the exact release set")
    result = {}
    for item in items:
        identity = namespaced_identity(item)
        uid = metadata(item).get("uid")
        if not isinstance(uid, str) or not uid:
            raise SystemExit(f"{kind} {identity[0]}/{identity[1]} has no stable UID")
        result[identity] = item
    return result


def dynamic_namespaced_map(items, kind):
    result = {}
    uids = set()
    for item in items:
        identity = namespaced_identity(item)
        uid = metadata(item).get("uid")
        if (
            not all(isinstance(value, str) and value for value in identity)
            or identity in result
            or not isinstance(uid, str)
            or not uid
            or uid in uids
        ):
            raise SystemExit(f"live {kind} inventory has an invalid or duplicate identity")
        result[identity] = item
        uids.add(uid)
    return result


def one_controller_owner(item, kind, identity):
    owners = metadata(item).get("ownerReferences", [])
    if not isinstance(owners, list):
        raise SystemExit(f"{kind} {identity[0]}/{identity[1]} has invalid owner references")
    controllers = [
        owner
        for owner in owners
        if isinstance(owner, dict) and owner.get("controller") is True
    ]
    if len(owners) != 1 or len(controllers) != 1:
        raise SystemExit(f"{kind} {identity[0]}/{identity[1]} lacks one exact controller owner")
    return controllers[0]


def pod_spec(item):
    value = item.get("spec", {})
    return value if isinstance(value, dict) else {}


def container_images(spec):
    regular = spec.get("containers", [])
    init = spec.get("initContainers", [])
    if (
        not isinstance(regular, list)
        or not regular
        or not isinstance(init, list)
        or any(not isinstance(container, dict) for container in regular + init)
    ):
        return None
    images = [container.get("image") for container in regular + init]
    if any(not isinstance(image, str) or not image for image in images):
        return None
    return images


def assert_no_host_port(spec, label):
    containers = (
        spec.get("containers", [])
        + spec.get("initContainers", [])
        + spec.get("ephemeralContainers", [])
    )
    for container in containers:
        for port in container.get("ports", []):
            if port.get("hostPort") not in {None, 0}:
                raise SystemExit(f"{label} declares a hostPort")


def assert_restricted_spec(spec, label, allowed_capabilities=()):
    if any(spec.get(field) is True for field in ("hostNetwork", "hostPID", "hostIPC")):
        raise SystemExit(f"{label} enters a host namespace")
    if any("hostPath" in volume for volume in spec.get("volumes", [])):
        raise SystemExit(f"{label} mounts a hostPath")
    containers = (
        spec.get("containers", [])
        + spec.get("initContainers", [])
        + spec.get("ephemeralContainers", [])
    )
    for container in containers:
        security = container.get("securityContext", {})
        capabilities = security.get("capabilities", {})
        added = capabilities.get("add", [])
        if (
            security.get("privileged") is True
            or security.get("allowPrivilegeEscalation") is True
            or security.get("procMount") == "Unmasked"
            or not isinstance(added, list)
            or any(value not in allowed_capabilities for value in added)
        ):
            raise SystemExit(f"{label} contains a privileged container capability")
    assert_no_host_port(spec, label)


def stable_deployment(item, identity):
    meta = metadata(item)
    spec = item.get("spec", {})
    status = item.get("status", {})
    replicas = spec.get("replicas")
    generation = meta.get("generation")
    if (
        type(replicas) is not int
        or replicas < 1
        or type(generation) is not int
        or generation < 1
        or status.get("observedGeneration") != generation
        or status.get("replicas") != replicas
        or status.get("updatedReplicas") != replicas
        or status.get("readyReplicas") != replicas
        or status.get("availableReplicas") != replicas
        or status.get("unavailableReplicas") not in {None, 0}
    ):
        raise SystemExit(f"Deployment {identity[0]}/{identity[1]} is not exactly stable")
    return replicas


def stable_daemonset(item, identity):
    meta = metadata(item)
    status = item.get("status", {})
    generation = meta.get("generation")
    desired = status.get("desiredNumberScheduled")
    if (
        type(generation) is not int
        or generation < 1
        or status.get("observedGeneration") != generation
        or type(desired) is not int
        or desired != 1
        or status.get("currentNumberScheduled") != desired
        or status.get("updatedNumberScheduled") != desired
        or status.get("numberReady") != desired
        or status.get("numberAvailable") != desired
        or status.get("numberMisscheduled") not in {None, 0}
        or status.get("numberUnavailable") not in {None, 0}
    ):
        raise SystemExit(f"DaemonSet {identity[0]}/{identity[1]} is not exactly stable")
    return desired


namespace_items = load_items("namespaces.json")
expected_namespaces = {
    "default",
    "kube-node-lease",
    "kube-public",
    "kube-system",
    "flux-system",
    "kyverno",
    "cloudflare-public",
    "naranjo-online",
    "lidersea-com",
}
namespace_names = [metadata(item).get("name") for item in namespace_items]
if len(namespace_names) != len(expected_namespaces) or set(namespace_names) != expected_namespaces:
    raise SystemExit("live Namespace inventory differs from the exact release set")
for item in namespace_items:
    if item.get("status", {}).get("phase") != "Active" or metadata(item).get("deletionTimestamp") is not None:
        raise SystemExit("an expected Namespace is not exactly Active")

nodes = load_items("nodes.json")
if len(nodes) != 1:
    raise SystemExit("global inventory requires exactly one production node")
node_name = metadata(nodes[0]).get("name")
node_uid = metadata(nodes[0]).get("uid")
if (
    not isinstance(node_name, str)
    or not node_name
    or not isinstance(node_uid, str)
    or not node_uid
):
    raise SystemExit("production node identity is unavailable")

base_deployments = {
    ("naranjo-online", "naranjo-online"),
    ("lidersea-com", "lidersea-com"),
    ("cloudflare-public", "cloudflared"),
    ("kyverno", "kyverno-admission-controller"),
    ("flux-system", "source-controller"),
    ("flux-system", "kustomize-controller"),
    ("flux-system", "helm-controller"),
    ("kube-system", "coredns"),
}
provider_variants = {
    "cilium": (
        ("kube-system", "cilium-operator"),
        ("kube-system", "cilium"),
    ),
    "calico": (
        ("kube-system", "calico-kube-controllers"),
        ("kube-system", "calico-node"),
    ),
}
deployment_items = load_items("deployments.json")
daemonset_items = load_items("daemonsets.json")
deployment_identities = set(namespaced_identity(item) for item in deployment_items)
daemonset_identities = set(namespaced_identity(item) for item in daemonset_items)
provider = None
for candidate, (provider_deployment, provider_daemonset) in provider_variants.items():
    if (
        deployment_identities == base_deployments | {provider_deployment}
        and daemonset_identities
        == {("kube-system", "kube-proxy"), provider_daemonset}
    ):
        provider = candidate
        break
if provider is None:
    raise SystemExit("live Deployment/DaemonSet inventory is outside the exact kubeadm/CNI release variants")
provider_deployment, provider_daemonset = provider_variants[provider]
deployments = exact_namespaced_map(
    deployment_items, base_deployments | {provider_deployment}, "Deployment"
)
daemonsets = exact_namespaced_map(
    daemonset_items,
    {("kube-system", "kube-proxy"), provider_daemonset},
    "DaemonSet",
)

for filename, kind in (
    ("statefulsets.json", "StatefulSet"),
    ("replicationcontrollers.json", "ReplicationController"),
    ("jobs.json", "Job"),
    ("cronjobs.json", "CronJob"),
    ("horizontalpodautoscalers.json", "HorizontalPodAutoscaler"),
):
    if load_items(filename):
        raise SystemExit(f"live {kind} inventory must be empty")

expected_deployment_images = {
    ("naranjo-online", "naranjo-online"): naranjo_image,
    ("lidersea-com", "lidersea-com"): lidersea_image,
    ("cloudflare-public", "cloudflared"): cloudflared_image,
    ("kyverno", "kyverno-admission-controller"): admission_image,
    ("flux-system", "source-controller"): flux_source_image,
    ("flux-system", "kustomize-controller"): flux_kustomize_image,
    ("flux-system", "helm-controller"): flux_helm_image,
    ("kube-system", "coredns"): coredns_image,
}
provider_image = {
    "cilium": re.compile(r"quay[.]io/cilium/[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}\Z"),
    "calico": re.compile(r"docker[.]io/calico/[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}\Z"),
}[provider]
deployment_replicas = {}
for identity, deployment in deployments.items():
    deployment_replicas[identity] = stable_deployment(deployment, identity)
    template = deployment.get("spec", {}).get("template", {}).get("spec", {})
    images = container_images(template)
    if images is None:
        raise SystemExit(f"Deployment {identity[0]}/{identity[1]} has invalid container images")
    if identity == provider_deployment:
        if any(provider_image.fullmatch(image) is None or image.endswith("@sha256:" + "0" * 64) for image in images):
            raise SystemExit("CNI controller Deployment image is outside the reviewed provider registry/digest contract")
    elif images != [expected_deployment_images[identity]]:
        raise SystemExit(f"Deployment {identity[0]}/{identity[1]} image inventory differs from exact desired state")
    allowed_capabilities = {"NET_BIND_SERVICE"} if identity == ("kube-system", "coredns") else set()
    assert_restricted_spec(
        template,
        f"Deployment {identity[0]}/{identity[1]} template",
        allowed_capabilities,
    )

daemonset_desired = {}
for identity, daemonset in daemonsets.items():
    daemonset_desired[identity] = stable_daemonset(daemonset, identity)
    template = daemonset.get("spec", {}).get("template", {}).get("spec", {})
    images = container_images(template)
    if images is None:
        raise SystemExit(f"DaemonSet {identity[0]}/{identity[1]} has invalid container images")
    if identity == ("kube-system", "kube-proxy"):
        if images != [f"registry.k8s.io/kube-proxy:{kubernetes_version}"]:
            raise SystemExit("kube-proxy image differs from the exact reviewed Kubernetes version")
    elif any(provider_image.fullmatch(image) is None or image.endswith("@sha256:" + "0" * 64) for image in images):
        raise SystemExit("CNI DaemonSet image is outside the reviewed provider registry/digest contract")
    assert_no_host_port(template, f"DaemonSet {identity[0]}/{identity[1]} template")

replicasets = dynamic_namespaced_map(load_items("replicasets.json"), "ReplicaSet")
deployment_uids = {
    metadata(item)["uid"]: identity for identity, item in deployments.items()
}
active_replicasets = {}
replicaset_parent = {}
replicaset_identity_by_uid = {}
for identity, replicaset in replicasets.items():
    owner = one_controller_owner(replicaset, "ReplicaSet", identity)
    parent = deployment_uids.get(owner.get("uid"))
    if (
        owner.get("apiVersion") != "apps/v1"
        or owner.get("kind") != "Deployment"
        or parent is None
        or owner.get("name") != parent[1]
        or identity[0] != parent[0]
        or not identity[1].startswith(parent[1] + "-")
    ):
        raise SystemExit(f"ReplicaSet {identity[0]}/{identity[1]} is outside the exact Deployment UID chain")
    replicas = replicaset.get("spec", {}).get("replicas")
    if type(replicas) is not int or replicas < 0:
        raise SystemExit(f"ReplicaSet {identity[0]}/{identity[1]} has an invalid replica count")
    replicaset_parent[metadata(replicaset)["uid"]] = parent
    replicaset_identity_by_uid[metadata(replicaset)["uid"]] = identity
    if replicas:
        deployment = deployments[parent]
        deployment_selector = json.loads(
            json.dumps(deployment.get("spec", {}).get("selector", {}))
        )
        replicaset_selector = json.loads(
            json.dumps(replicaset.get("spec", {}).get("selector", {}))
        )
        deployment_template = json.loads(
            json.dumps(deployment.get("spec", {}).get("template", {}))
        )
        replicaset_template = json.loads(
            json.dumps(replicaset.get("spec", {}).get("template", {}))
        )
        selector_hash = replicaset_selector.get("matchLabels", {}).pop(
            "pod-template-hash", None
        )
        template_hash = replicaset_template.get("metadata", {}).get(
            "labels", {}
        ).pop("pod-template-hash", None)
        if (
            not isinstance(selector_hash, str)
            or not selector_hash
            or template_hash != selector_hash
            or replicaset_selector != deployment_selector
            or replicaset_template != deployment_template
            or replicas != deployment_replicas[parent]
            or replicaset.get("status", {}).get("readyReplicas") != replicas
            or replicaset.get("status", {}).get("availableReplicas") != replicas
        ):
            raise SystemExit(f"active ReplicaSet {identity[0]}/{identity[1]} differs from its exact stable Deployment")
        if parent in active_replicasets:
            raise SystemExit(f"Deployment {parent[0]}/{parent[1]} has more than one active ReplicaSet")
        active_replicasets[parent] = metadata(replicaset)["uid"]
    elif any(replicaset.get("status", {}).get(field, 0) not in {None, 0} for field in ("replicas", "readyReplicas", "availableReplicas")):
        raise SystemExit(f"inactive ReplicaSet {identity[0]}/{identity[1]} still has live replicas")
if set(active_replicasets) != set(deployments):
    raise SystemExit("each exact Deployment must have one and only one active ReplicaSet")

daemonset_uids = {
    metadata(item)["uid"]: identity for identity, item in daemonsets.items()
}
pod_counts = {identity: 0 for identity in deployments}
pod_counts.update({identity: 0 for identity in daemonsets})
static_expected = {
    ("kube-system", f"etcd-{node_name}"),
    ("kube-system", f"kube-apiserver-{node_name}"),
    ("kube-system", f"kube-controller-manager-{node_name}"),
    ("kube-system", f"kube-scheduler-{node_name}"),
}
static_seen = set()
pod_uids = set()
for pod in load_items("pods.json"):
    identity = namespaced_identity(pod)
    uid = metadata(pod).get("uid")
    if (
        identity[0] not in expected_namespaces
        or not isinstance(identity[1], str)
        or not identity[1]
        or not isinstance(uid, str)
        or not uid
        or uid in pod_uids
        or metadata(pod).get("deletionTimestamp") is not None
    ):
        raise SystemExit("live Pod inventory has an invalid, duplicate, or deleting identity")
    pod_uids.add(uid)
    spec = pod_spec(pod)
    images = container_images(spec)
    if images is None:
        raise SystemExit(f"Pod {identity[0]}/{identity[1]} has invalid container images")
    owners = metadata(pod).get("ownerReferences", [])
    elevated = False
    expected_images = None
    restricted_allowed_capabilities = set()
    mirror_annotation = metadata(pod).get("annotations", {}).get(
        "kubernetes.io/config.mirror"
    )
    if identity in static_expected and mirror_annotation not in {None, ""}:
        if owners:
            owner = one_controller_owner(pod, "mirror Pod", identity)
            if (
                owner.get("apiVersion") != "v1"
                or owner.get("kind") != "Node"
                or owner.get("name") != node_name
                or owner.get("uid") != node_uid
            ):
                raise SystemExit(
                    f"mirror Pod {identity[0]}/{identity[1]} has an unexpected Node owner"
                )
        if (
            identity in static_seen
            or spec.get("nodeName") != node_name
            or spec.get("initContainers")
            or spec.get("ephemeralContainers")
        ):
            raise SystemExit(f"unowned Pod {identity[0]}/{identity[1]} is not one exact kubeadm mirror Pod")
        static_seen.add(identity)
        elevated = True
        component = identity[1][:-len(node_name) - 1]
        expected_images = {
            "etcd": [etcd_image],
            "kube-apiserver": [f"registry.k8s.io/kube-apiserver:{kubernetes_version}"],
            "kube-controller-manager": [f"registry.k8s.io/kube-controller-manager:{kubernetes_version}"],
            "kube-scheduler": [f"registry.k8s.io/kube-scheduler:{kubernetes_version}"],
        }.get(component)
    else:
        if not owners:
            raise SystemExit(
                f"unowned Pod {identity[0]}/{identity[1]} is not one exact kubeadm mirror Pod"
            )
        owner = one_controller_owner(pod, "Pod", identity)
        owner_uid = owner.get("uid")
        if owner.get("apiVersion") != "apps/v1" or owner.get("kind") not in {"ReplicaSet", "DaemonSet"}:
            raise SystemExit(f"Pod {identity[0]}/{identity[1]} has an unapproved controller kind")
        if owner.get("kind") == "ReplicaSet":
            parent = replicaset_parent.get(owner_uid)
            if (
                parent is None
                or active_replicasets.get(parent) != owner_uid
                or owner.get("name") != replicaset_identity_by_uid.get(owner_uid, (None, None))[1]
                or identity[0] != parent[0]
                or not identity[1].startswith(owner.get("name", "") + "-")
            ):
                raise SystemExit(f"Pod {identity[0]}/{identity[1]} is outside the active Deployment UID chain")
            pod_counts[parent] += 1
            expected_images = container_images(
                deployments[parent].get("spec", {}).get("template", {}).get("spec", {})
            )
            if parent == ("kube-system", "coredns"):
                restricted_allowed_capabilities = {"NET_BIND_SERVICE"}
        else:
            parent = daemonset_uids.get(owner_uid)
            if (
                parent is None
                or owner.get("name") != parent[1]
                or identity[0] != parent[0]
                or not identity[1].startswith(parent[1] + "-")
            ):
                raise SystemExit(f"Pod {identity[0]}/{identity[1]} is outside the exact DaemonSet UID chain")
            pod_counts[parent] += 1
            elevated = True
            expected_images = container_images(
                daemonsets[parent].get("spec", {}).get("template", {}).get("spec", {})
            )
    if images != expected_images:
        raise SystemExit(f"Pod {identity[0]}/{identity[1]} image inventory differs from its exact controller")
    if pod.get("status", {}).get("phase") != "Running":
        raise SystemExit(f"Pod {identity[0]}/{identity[1]} is not Running")
    ready = [
        condition
        for condition in pod.get("status", {}).get("conditions", [])
        if isinstance(condition, dict) and condition.get("type") == "Ready"
    ]
    if len(ready) != 1 or ready[0].get("status") != "True":
        raise SystemExit(f"Pod {identity[0]}/{identity[1]} is not exactly Ready")
    assert_no_host_port(spec, f"Pod {identity[0]}/{identity[1]}")
    if not elevated:
        assert_restricted_spec(
            spec,
            f"Pod {identity[0]}/{identity[1]}",
            restricted_allowed_capabilities,
        )
if static_seen != static_expected:
    raise SystemExit("live kubeadm mirror Pod inventory is incomplete")
expected_pod_counts = dict(deployment_replicas)
expected_pod_counts.update(daemonset_desired)
if pod_counts != expected_pod_counts:
    raise SystemExit("live controller-owned Pod counts differ from exact stable controller replicas")

expected_services = {
    ("default", "kubernetes"),
    ("kube-system", "kube-dns"),
    ("flux-system", "source-controller"),
    ("kyverno", "kyverno-svc"),
    ("naranjo-online", "naranjo-online"),
    ("lidersea-com", "lidersea-com"),
}
services = exact_namespaced_map(load_items("services.json"), expected_services, "Service")
for identity, service in services.items():
    spec = service.get("spec", {})
    if (
        spec.get("type", "ClusterIP") != "ClusterIP"
        or spec.get("externalIPs")
        or spec.get("externalName")
        or spec.get("healthCheckNodePort") not in {None, 0}
        or any(port.get("nodePort") not in {None, 0} for port in spec.get("ports", []))
    ):
        raise SystemExit(f"Service {identity[0]}/{identity[1]} has a direct-origin exposure field")

if load_items("mutatingwebhooks.json"):
    raise SystemExit("live MutatingWebhookConfiguration inventory must be empty")
validating = load_items("webhooks.json")
if len(validating) != 1 or metadata(validating[0]).get("name") != "kyverno-resource-validating-webhook-cfg":
    raise SystemExit("live ValidatingWebhookConfiguration inventory differs from the exact Kyverno boundary")
tenant_namespaces = {"cloudflare-public", "naranjo-online", "lidersea-com"}
webhooks = validating[0].get("webhooks", [])
if not isinstance(webhooks, list) or not webhooks:
    raise SystemExit("exact Kyverno validating webhook set is unavailable")
for webhook in webhooks:
    service = webhook.get("clientConfig", {}).get("service", {})
    selector = webhook.get("namespaceSelector", {})
    expressions = selector.get("matchExpressions", [])
    if (
        webhook.get("failurePolicy") != "Fail"
        or service.get("namespace") != "kyverno"
        or service.get("name") != "kyverno-svc"
        or selector.get("matchLabels")
        or not isinstance(expressions, list)
        or len(expressions) != 1
        or expressions[0].get("key") != "kubernetes.io/metadata.name"
        or expressions[0].get("operator") != "In"
        or set(expressions[0].get("values", [])) != tenant_namespaces
        or len(expressions[0].get("values", [])) != len(tenant_namespaces)
    ):
        raise SystemExit("live Kyverno validating webhook does not fail closed over the exact tenant set")

print(
    "release-gate: PASS exact global namespace, controller, Pod, Service, and admission inventories are closed"
)
PY
}

assert_production_state() {
  "$PYTHON_BIN" - "$TEMP_ROOT" "$NARANJO_RUNTIME_IMAGE" "$LIDERSEA_RUNTIME_IMAGE" "$CLOUDFLARED_RUNTIME_IMAGE" "$ADMISSION_RUNTIME_IMAGE" "$CAPACITY_EVIDENCE_SHA256" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
naranjo_image = sys.argv[2]
lidersea_image = sys.argv[3]
cloudflared_image = sys.argv[4]
admission_image = sys.argv[5]
capacity_evidence_sha256 = sys.argv[6]

def load(name):
    return json.loads((root / name).read_text(encoding="utf-8"))["items"]

def meta(item):
    return item.get("metadata", {})

def condition(item, name):
    matches = [c for c in item.get("status", {}).get("conditions", []) if c.get("type") == name]
    return matches[-1].get("status") if matches else None

def by_identity(items, namespace, name, kind):
    matches = [x for x in items if meta(x).get("namespace") == namespace and meta(x).get("name") == name]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {kind} {namespace}/{name}, found {len(matches)}")
    return matches[0]

nodes = load("nodes.json")
if len(nodes) != 1:
    raise SystemExit(f"expected the reviewed single-node Pi topology, found {len(nodes)} nodes")
node = nodes[0]
for name, expected in (("Ready", "True"), ("DiskPressure", "False"), ("MemoryPressure", "False"), ("PIDPressure", "False")):
    if condition(node, name) != expected:
        raise SystemExit(f"production node condition {name} is not {expected}")

deployments = load("deployments.json")
expected_deployments = {
    ("naranjo-online", "naranjo-online"): ("naranjo-online", naranjo_image),
    ("lidersea-com", "lidersea-com"): ("lidersea-com", lidersea_image),
    ("cloudflare-public", "cloudflared"): ("cloudflared", cloudflared_image),
    ("kyverno", "kyverno-admission-controller"): ("kyverno", admission_image),
}
tenant_namespaces = {"cloudflare-public", "naranjo-online", "lidersea-com"}
expected_tenant_deployments = {
    identity for identity in expected_deployments if identity[0] in tenant_namespaces
}
actual_tenant_deployments = {
    (meta(item).get("namespace"), meta(item).get("name"))
    for item in deployments
    if meta(item).get("namespace") in tenant_namespaces
}
if actual_tenant_deployments != expected_tenant_deployments:
    raise SystemExit(
        "tenant Deployment inventory differs from the exact naranjo/lidersea/cloudflared release set"
    )
for (namespace, name), (expected_container, expected_image) in expected_deployments.items():
    deployment = by_identity(deployments, namespace, name, "Deployment")
    spec = deployment.get("spec", {})
    status = deployment.get("status", {})
    desired = spec.get("replicas", 0)
    if namespace in {"naranjo-online", "lidersea-com"} and desired != 2:
        raise SystemExit(f"Deployment {namespace}/{name} must retain exactly two reviewed replicas")
    if desired < 1 or status.get("readyReplicas", 0) < desired or status.get("availableReplicas", 0) < desired:
        raise SystemExit(f"Deployment {namespace}/{name} is not fully ready/available")
    if status.get("observedGeneration") != meta(deployment).get("generation"):
        raise SystemExit(f"Deployment {namespace}/{name} has not observed its current generation")
    containers = spec.get("template", {}).get("spec", {}).get("containers", [])
    images = [c.get("image", "") for c in containers]
    matched = [c for c in containers if c.get("name") == expected_container and c.get("image") == expected_image]
    if len(matched) != 1:
        raise SystemExit(f"Deployment {namespace}/{name} image differs from exact desired digest")
    all_images = images + [c.get("image", "") for c in spec.get("template", {}).get("spec", {}).get("initContainers", [])]
    if not images or any(not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image) or image.endswith("@sha256:" + "0" * 64) for image in all_images):
        raise SystemExit(f"Deployment {namespace}/{name} has a mutable or sentinel image")
    if namespace != "kyverno" and images != [expected_image]:
        raise SystemExit(f"Deployment {namespace}/{name} has an unexpected sidecar")
    if namespace in {"naranjo-online", "lidersea-com"}:
        if meta(deployment).get("annotations", {}).get("platform.snaraj.dev/deployment-ready") != "true":
            raise SystemExit(f"Deployment {namespace}/{name} lacks active readiness annotation")
    if namespace == "cloudflare-public":
        revision = spec.get("template", {}).get("metadata", {}).get("annotations", {}).get("platform.snaraj.dev/tunnel-token-revision")
        if revision in {None, "", "not-configured", "UNRESOLVED"}:
            raise SystemExit("cloudflared token revision remains unresolved")

replicasets = [item for item in load("replicasets.json") if meta(item).get("namespace") in tenant_namespaces]
expected_owner_name = {
    "cloudflare-public": "cloudflared",
    "naranjo-online": "naranjo-online",
    "lidersea-com": "lidersea-com",
}
replicaset_identities = set()
for replicaset in replicasets:
    namespace = meta(replicaset).get("namespace")
    name = meta(replicaset).get("name")
    owners = [owner for owner in meta(replicaset).get("ownerReferences", []) if owner.get("controller") is True]
    if len(owners) != 1 or owners[0].get("apiVersion") != "apps/v1" or owners[0].get("kind") != "Deployment":
        raise SystemExit(f"tenant ReplicaSet {namespace}/{name} lacks one Deployment controller owner")
    if owners[0].get("name") != expected_owner_name[namespace]:
        raise SystemExit(f"tenant ReplicaSet {namespace}/{name} is not owned by the exact reviewed Deployment")
    replicaset_identities.add((namespace, name))

services = [x for x in load("services.json") if meta(x).get("namespace") in tenant_namespaces]
expected_services = {
    ("naranjo-online", "naranjo-online"),
    ("lidersea-com", "lidersea-com"),
}
actual_services = {(meta(item).get("namespace"), meta(item).get("name")) for item in services}
if actual_services != expected_services:
    raise SystemExit("tenant Service inventory differs from the exact two internal site Services")
for namespace, name in expected_services:
    by_identity(services, namespace, name, "Service")
for service in services:
    spec = service.get("spec", {})
    if spec.get("type", "ClusterIP") != "ClusterIP" or spec.get("externalIPs"):
        raise SystemExit(f"tenant Service {meta(service).get('namespace')}/{meta(service).get('name')} is externally exposed")
    if any(port.get("nodePort", 0) for port in spec.get("ports", [])):
        raise SystemExit(f"tenant Service {meta(service).get('namespace')}/{meta(service).get('name')} has a nodePort")

pvcs = [x for x in load("pvcs.json") if meta(x).get("namespace") in {"cloudflare-public", "naranjo-online", "lidersea-com"}]
if pvcs:
    raise SystemExit("tenant namespaces contain persistent volume claims while storage is disabled")

for pod in load("pods.json"):
    if meta(pod).get("namespace") not in {"cloudflare-public", "naranjo-online", "lidersea-com"}:
        continue
    spec = pod.get("spec", {})
    namespace = meta(pod).get("namespace")
    expected_account = {"cloudflare-public": "cloudflared", "naranjo-online": "naranjo-online", "lidersea-com": "lidersea-com"}[namespace]
    if spec.get("serviceAccountName") != expected_account or spec.get("automountServiceAccountToken") is not False:
        raise SystemExit(f"tenant Pod {namespace}/{meta(pod).get('name')} has an unexpected identity or token automount")
    if spec.get("hostNetwork") is True or spec.get("hostPID") is True or spec.get("hostIPC") is True:
        raise SystemExit(f"tenant Pod {namespace}/{meta(pod).get('name')} uses a host namespace")
    owners = [owner for owner in meta(pod).get("ownerReferences", []) if owner.get("controller") is True]
    if len(owners) != 1 or owners[0].get("apiVersion") != "apps/v1" or owners[0].get("kind") != "ReplicaSet":
        raise SystemExit(f"tenant Pod {namespace}/{meta(pod).get('name')} lacks one ReplicaSet controller owner")
    if (namespace, owners[0].get("name")) not in replicaset_identities:
        raise SystemExit(f"tenant Pod {namespace}/{meta(pod).get('name')} is outside the exact Deployment owner chain")
    for toleration in spec.get("tolerations", []):
        key = toleration.get("key", "")
        operator = toleration.get("operator", "Equal")
        if key == "node.kubernetes.io/disk-pressure" or (operator == "Exists" and not key):
            raise SystemExit(
                f"tenant Pod {meta(pod).get('namespace')}/{meta(pod).get('name')} can tolerate DiskPressure"
            )
    expected_volume = {
        "naranjo-online": {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
        "lidersea-com": {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
        "cloudflare-public": {
            "name": "tunnel-token",
            "secret": {
                "secretName": "pi-websites-tunnel-token",
                "defaultMode": 288,
                "items": [{"key": "token", "path": "token"}],
            },
        },
    }[namespace]
    if spec.get("volumes", []) != [expected_volume]:
        raise SystemExit(f"tenant Pod {namespace}/{meta(pod).get('name')} differs from its exact reviewed volume contract")
    all_containers = spec.get("initContainers", []) + spec.get("containers", []) + spec.get("ephemeralContainers", [])
    for container in all_containers:
        image = container.get("image", "")
        expected_image = {"cloudflare-public": cloudflared_image, "naranjo-online": naranjo_image, "lidersea-com": lidersea_image}[namespace]
        if image != expected_image:
            raise SystemExit(f"tenant Pod {namespace}/{meta(pod).get('name')} does not use the exact desired digest")
        if any(port.get("hostPort", 0) for port in container.get("ports", [])):
            raise SystemExit(f"tenant Pod {namespace}/{meta(pod).get('name')} declares hostPort")

networkpolicies = load("networkpolicies.json")
expected_names = {
    "naranjo-online": {"default-deny", "cloudflared-to-naranjo-online"},
    "lidersea-com": {"default-deny", "cloudflared-to-lidersea-com"},
    "cloudflare-public": {"default-deny", "cloudflared-dns", "cloudflared-edge", "cloudflared-naranjo-online", "cloudflared-lidersea-com"},
}
for namespace, names in expected_names.items():
    actual = {meta(p).get("name") for p in networkpolicies if meta(p).get("namespace") == namespace}
    if actual != names:
        raise SystemExit(f"NetworkPolicy inventory drift in {namespace}: expected {sorted(names)}, got {sorted(actual)}")
allowed_pairs = {
    "naranjo-online": {"cloudflare-public"},
    "lidersea-com": {"cloudflare-public"},
    "cloudflare-public": {"kube-system", "naranjo-online", "lidersea-com"},
}
for policy in networkpolicies:
    namespace = meta(policy).get("namespace")
    if namespace not in expected_names:
        continue
    spec = policy.get("spec", {})
    peers = []
    for rule in spec.get("ingress", []):
        peers.extend(rule.get("from", []))
    for rule in spec.get("egress", []):
        peers.extend(rule.get("to", []))
    for peer in peers:
        if "namespaceSelector" not in peer:
            continue
        labels = peer.get("namespaceSelector", {}).get("matchLabels", {})
        selected = labels.get("kubernetes.io/metadata.name")
        pod_labels = peer.get("podSelector", {}).get("matchLabels", {})
        if set(labels) != {"kubernetes.io/metadata.name"} or selected not in allowed_pairs[namespace] or not pod_labels:
            raise SystemExit(f"NetworkPolicy {namespace}/{meta(policy).get('name')} widens a cross-namespace peer")

quotas = load("quotas.json")
for namespace in ("naranjo-online", "lidersea-com"):
    namespace_quotas = [q for q in quotas if meta(q).get("namespace") == namespace]
    if len(namespace_quotas) != 1 or meta(namespace_quotas[0]).get("name") != "namespace-budget":
        raise SystemExit(f"{namespace} must contain exactly one reviewed namespace-budget quota")
    quota_annotations = meta(namespace_quotas[0]).get("annotations", {})
    if quota_annotations.get("platform.snaraj.dev/readiness") != "reviewed-pi-capacity":
        raise SystemExit(f"{namespace} quota lacks reviewed-pi-capacity readiness")
    if quota_annotations.get("platform.snaraj.dev/capacity-evidence-sha256") != capacity_evidence_sha256:
        raise SystemExit(f"{namespace} quota is not bound to this release's reviewed discovery evidence hash")
    required = {"pods", "requests.cpu", "requests.memory", "limits.cpu", "limits.memory"}
    approved = []
    for quota in namespace_quotas:
        hard = quota.get("spec", {}).get("hard", {})
        if "pods" in hard:
            try:
                if int(hard["pods"]) < 2:
                    raise SystemExit(f"{namespace} contains a Pod quota below the two-replica floor")
            except (TypeError, ValueError) as exc:
                raise SystemExit(f"{namespace} contains a non-integer Pod quota") from exc
        if required.issubset(set(hard)):
            approved.append(quota)
    if not approved:
        raise SystemExit(f"{namespace} quota lacks the reviewed CPU/memory/Pod envelope")

kustomizations = load("kustomizations.json")
for name in ("platform-prerequisites", "admission", "platform-services", "naranjo-online", "lidersea-com"):
    item = by_identity(kustomizations, "flux-system", name, "Kustomization")
    if item.get("spec", {}).get("suspend", False) or condition(item, "Ready") != "True":
        raise SystemExit(f"Flux Kustomization {name} is suspended or not Ready")
    if name == "admission" and item.get("spec", {}).get("wait") is not True:
        raise SystemExit("admission Kustomization must keep wait=true as its runtime readiness boundary")
    observed = item.get("status", {}).get("observedGeneration")
    if observed != meta(item).get("generation"):
        raise SystemExit(f"Flux Kustomization {name} has not observed its current generation")

releases = load("helmreleases.json")
for namespace, name in (("naranjo-online", "naranjo-online"), ("lidersea-com", "lidersea-com"), ("cloudflare-public", "cloudflare-public")):
    item = by_identity(releases, namespace, name, "HelmRelease")
    if item.get("spec", {}).get("suspend", False) or condition(item, "Ready") != "True":
        raise SystemExit(f"HelmRelease {namespace}/{name} is suspended or not Ready")
    observed = item.get("status", {}).get("observedGeneration")
    if observed != meta(item).get("generation"):
        raise SystemExit(f"HelmRelease {namespace}/{name} has not observed its current generation")

required_policies = {
    "disallow-public-services",
    "disallow-tenant-media-payloads",
    "disallow-undiscovered-storage",
    "require-approved-images",
    "require-exact-tenant-networking",
    "require-release-readiness",
    "require-restricted-workloads",
    "require-signed-naranjo-online",
    "require-signed-lidersea-com",
}
policies = {meta(p).get("name"): p for p in load("policies.json")}
missing = sorted(required_policies - set(policies))
if missing:
    raise SystemExit(f"required live ClusterPolicies are missing: {missing}")
if "require-zero-site-capacity" in policies:
    raise SystemExit("live zero-site-capacity policy still blocks reviewed release capacity")
for name in required_policies:
    policy = policies[name]
    spec = policy.get("spec", {})
    if spec.get("validationFailureAction") != "Enforce" or spec.get("admission") is not True:
        raise SystemExit(f"ClusterPolicy {name} is not active Enforce admission")
    if spec.get("webhookConfiguration", {}).get("failurePolicy") != "Fail":
        raise SystemExit(f"ClusterPolicy {name} is not fail-closed")
    if condition(policy, "Ready") != "True":
        raise SystemExit(f"ClusterPolicy {name} is missing Ready=True status")

webhooks = load("webhooks.json")
kyverno_webhooks = []
for config in webhooks:
    for webhook in config.get("webhooks", []):
        service = webhook.get("clientConfig", {}).get("service", {})
        if service.get("namespace") == "kyverno":
            kyverno_webhooks.append(webhook)
if not kyverno_webhooks or any(w.get("failurePolicy") != "Fail" for w in kyverno_webhooks):
    raise SystemExit("no fail-closed live Kyverno validating webhook set was found")

print("release-gate: PASS production runtime state: node, admission, Flux, tunnel, sites, quotas, and storage boundaries")
PY
}

write_admission_fixtures() {
  cat >"${TEMP_ROOT}/deny-ingress.yaml" <<'EOF'
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: release-gate-deny, namespace: naranjo-online}
spec:
  rules:
    - host: unexpected.naranjo.online
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: {name: naranjo-online, port: {name: http}}
EOF
  cat >"${TEMP_ROOT}/deny-gateway.yaml" <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: release-gate-deny, namespace: naranjo-online}
spec: {gatewayClassName: forbidden, listeners: [{name: http, protocol: HTTP, port: 80}]}
EOF
  cat >"${TEMP_ROOT}/deny-nodeport.yaml" <<'EOF'
apiVersion: v1
kind: Service
metadata: {name: release-gate-nodeport, namespace: naranjo-online}
spec: {type: NodePort, selector: {app: none}, ports: [{port: 80}]}
EOF
  cat >"${TEMP_ROOT}/deny-loadbalancer.yaml" <<'EOF'
apiVersion: v1
kind: Service
metadata: {name: release-gate-loadbalancer, namespace: naranjo-online}
spec: {type: LoadBalancer, selector: {app: none}, ports: [{port: 80}]}
EOF
  cat >"${TEMP_ROOT}/deny-externalips.yaml" <<'EOF'
apiVersion: v1
kind: Service
metadata: {name: release-gate-externalips, namespace: naranjo-online}
spec: {externalIPs: [192.0.2.10], selector: {app: none}, ports: [{port: 80}]}
EOF
  cat >"${TEMP_ROOT}/deny-network-widening.yaml" <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: release-gate-wide, namespace: naranjo-online}
spec: {podSelector: {}, ingress: [{from: [{namespaceSelector: {}}]}]}
EOF
  cat >"${TEMP_ROOT}/deny-network-endport.yaml" <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: cloudflared-to-naranjo-online, namespace: naranjo-online}
spec:
  podSelector:
    matchLabels: {app.kubernetes.io/name: naranjo-online}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: cloudflare-public}
          podSelector:
            matchLabels: {app.kubernetes.io/name: cloudflare-public}
      ports: [{port: 8080, endPort: 9000, protocol: TCP}]
  egress: []
EOF
  cat >"${TEMP_ROOT}/deny-pvc.yaml" <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: release-gate-deny, namespace: naranjo-online}
spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}
EOF
  cat >"${TEMP_ROOT}/deny-media-configmap.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata: {name: release-gate-media, namespace: naranjo-online}
binaryData: {video.mp4: AA==}
EOF
  cat >"${TEMP_ROOT}/deny-media-secret.yaml" <<'EOF'
apiVersion: v1
kind: Secret
metadata: {name: release-gate-media, namespace: naranjo-online}
type: Opaque
data: {inline.svg: PHN2Zz48L3N2Zz4=}
EOF
  cat >"${TEMP_ROOT}/deny-encoded-media-configmap.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata: {name: release-gate-encoded-media, namespace: naranjo-online}
data: {blob: iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB}
EOF
  cat >"${TEMP_ROOT}/deny-legacy-token-secret.yaml" <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: release-gate-legacy-token
  namespace: naranjo-online
  annotations: {kubernetes.io/service-account.name: helm-reconciler}
type: kubernetes.io/service-account-token
EOF
  cat >"${TEMP_ROOT}/deny-wildcard-toleration.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: release-gate-wildcard-toleration, namespace: naranjo-online}
spec:
  automountServiceAccountToken: false
  serviceAccountName: naranjo-online
  restartPolicy: Never
  tolerations: [{operator: Exists}]
  securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: naranjo-online
      image: ${NARANJO_RUNTIME_IMAGE}
      resources: {requests: {cpu: 1m, memory: 1Mi}, limits: {cpu: 10m, memory: 16Mi}}
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
EOF
  cat >"${TEMP_ROOT}/deny-unlisted-volume.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: release-gate-unlisted-volume, namespace: naranjo-online}
spec:
  automountServiceAccountToken: false
  serviceAccountName: naranjo-online
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: naranjo-online
      image: ${NARANJO_RUNTIME_IMAGE}
      resources: {requests: {cpu: 1m, memory: 1Mi}, limits: {cpu: 10m, memory: 16Mi}}
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
  volumes:
    - name: tmp
      azureFile: {secretName: invented-storage, shareName: media}
EOF
  cat >"${TEMP_ROOT}/deny-raw-replicaset.yaml" <<EOF
apiVersion: apps/v1
kind: ReplicaSet
metadata: {name: release-gate-raw-replicaset, namespace: naranjo-online}
spec:
  replicas: 0
  selector: {matchLabels: {app: release-gate-raw-replicaset}}
  template:
    metadata: {labels: {app: release-gate-raw-replicaset}}
    spec:
      automountServiceAccountToken: false
      serviceAccountName: naranjo-online
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: naranjo-online
          image: ${NARANJO_RUNTIME_IMAGE}
          resources: {requests: {cpu: 1m, memory: 1Mi}, limits: {cpu: 10m, memory: 16Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
EOF
  cat >"${TEMP_ROOT}/deny-false-ready.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: release-gate-false-ready
  namespace: naranjo-online
  annotations: {platform.snaraj.dev/deployment-ready: "false"}
spec:
  replicas: 0
  selector: {matchLabels: {app: release-gate-false-ready}}
  template:
    metadata: {labels: {app: release-gate-false-ready}}
    spec:
      automountServiceAccountToken: false
      serviceAccountName: naranjo-online
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: app
          image: ${NARANJO_RUNTIME_IMAGE}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
EOF
  cat >"${TEMP_ROOT}/deny-workload.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: release-gate-host-access, namespace: naranjo-online}
spec:
  automountServiceAccountToken: false
  serviceAccountName: naranjo-online
  hostNetwork: true
  tolerations: [{key: node.kubernetes.io/disk-pressure, operator: Exists}]
  securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: app
      image: ghcr.io/snaraj/naranjo-online:latest
      ports: [{containerPort: 8080, hostPort: 18080}]
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
  volumes: [{name: host, hostPath: {path: /var/lib/release-gate}}]
EOF
}

expect_prod_denied() {
  local label="$1"
  local file="$2"
  local expected_regex="$3"
  local output
  if output="$(kubectl_prod apply --dry-run=server -f "$file" 2>&1)"; then
    die "production admission accepted negative fixture ${label}"
  fi
  if ! grep -Eqi "$expected_regex" <<<"$output"; then
    die "${label} was rejected without evidence from the expected API/admission control"
  fi
  log "PASS live admission denied ${label}"
}

exercise_production_admission() {
  write_admission_fixtures
  expect_prod_denied ingress "${TEMP_ROOT}/deny-ingress.yaml" 'disallow-public-services|Ingress is forbidden'
  expect_prod_denied gateway "${TEMP_ROOT}/deny-gateway.yaml" 'disallow-public-services|Gateway API|no matches for kind|resource mapping not found'
  expect_prod_denied NodePort "${TEMP_ROOT}/deny-nodeport.yaml" 'disallow-public-services|ClusterIP'
  expect_prod_denied LoadBalancer "${TEMP_ROOT}/deny-loadbalancer.yaml" 'disallow-public-services|ClusterIP'
  expect_prod_denied externalIPs "${TEMP_ROOT}/deny-externalips.yaml" 'disallow-public-services|externalIPs|ClusterIP'
  expect_prod_denied cross-namespace-widening "${TEMP_ROOT}/deny-network-widening.yaml" 'require-exact-tenant-networking|exact cloudflare|widens'
  expect_prod_denied network-endPort-widening "${TEMP_ROOT}/deny-network-endport.yaml" 'require-exact-tenant-networking|exact cloudflare|TCP 8080|endPort'
  expect_prod_denied PVC "${TEMP_ROOT}/deny-pvc.yaml" 'disallow-undiscovered-storage|Persistent storage'
  expect_prod_denied tenant-media-configmap "${TEMP_ROOT}/deny-media-configmap.yaml" 'disallow-tenant-media-payloads|media|binaryData'
  expect_prod_denied tenant-media-secret "${TEMP_ROOT}/deny-media-secret.yaml" 'disallow-tenant-media-payloads|media|Secret'
  expect_prod_denied encoded-media-configmap "${TEMP_ROOT}/deny-encoded-media-configmap.yaml" 'disallow-tenant-media-payloads|media|encoded'
  expect_prod_denied legacy-serviceaccount-token "${TEMP_ROOT}/deny-legacy-token-secret.yaml" 'disallow-undiscovered-storage|legacy|ServiceAccount token'
  expect_prod_denied wildcard-diskpressure-toleration "${TEMP_ROOT}/deny-wildcard-toleration.yaml" 'disallow-undiscovered-storage|wildcard|DiskPressure'
  expect_prod_denied unlisted-volume-source "${TEMP_ROOT}/deny-unlisted-volume.yaml" 'disallow-undiscovered-storage|volume|scratch'
  expect_prod_denied raw-replicaset "${TEMP_ROOT}/deny-raw-replicaset.yaml" 'require-release-readiness|ReplicaSet|exact reviewed Deployment'
  expect_prod_denied false-readiness "${TEMP_ROOT}/deny-false-ready.yaml" 'require-release-readiness|readiness must be explicitly true'
  expect_prod_denied host-access-mutable-image-disk-pressure "${TEMP_ROOT}/deny-workload.yaml" \
    'require-restricted-workloads|require-approved-images|disallow-undiscovered-storage|PodSecurity|hostNetwork|hostPort|DiskPressure'
  log 'PASS production allow path is the observed Ready desired state; deny paths were real server-side admission requests'
}

assert_no_live_routes() {
  local output api_resources
  output="$(kubectl_prod get ingresses.networking.k8s.io -A -o name 2>"${TEMP_ROOT}/kubectl-error.txt")" || \
    die 'production Ingress inventory query failed (details withheld)'
  [[ -z "$output" ]] || die 'production cluster contains Ingress objects'
  # Gateway APIs may intentionally be absent. If installed, every route-family
  # inventory must still be empty.
  api_resources="$(kubectl_prod api-resources --api-group=gateway.networking.k8s.io -o name 2>"${TEMP_ROOT}/kubectl-error.txt")" || \
    die 'production Gateway API discovery failed (details withheld)'
  local resource
  for resource in gateways.gateway.networking.k8s.io httproutes.gateway.networking.k8s.io grpcroutes.gateway.networking.k8s.io \
    tlsroutes.gateway.networking.k8s.io tcproutes.gateway.networking.k8s.io udproutes.gateway.networking.k8s.io referencegrants.gateway.networking.k8s.io; do
    if grep -Fxq "$resource" <<<"$api_resources"; then
      output="$(kubectl_prod get "$resource" -A -o name 2>"${TEMP_ROOT}/kubectl-error.txt")" || \
        die "production ${resource} inventory query failed (details withheld)"
      [[ -z "$output" ]] || die "production cluster contains forbidden ${resource} objects"
    fi
  done
  log 'PASS production has no Ingress or Gateway API route objects'
}

run_live_gate() {
  require_live_tools
  run_static_gate --release
  new_temp_root

  export NARANJO_RUNTIME_IMAGE
  export LIDERSEA_RUNTIME_IMAGE
  export CLOUDFLARED_RUNTIME_IMAGE
  export ADMISSION_RUNTIME_IMAGE
  NARANJO_RUNTIME_IMAGE="$(desired_deployment_image "${REPO_ROOT}/.artifacts/rendered/helm-naranjo-online.yaml" 'ghcr\.io/snaraj/naranjo-online' naranjo-online naranjo-online)"
  LIDERSEA_RUNTIME_IMAGE="$(desired_deployment_image "${REPO_ROOT}/.artifacts/rendered/helm-lidersea-com.yaml" 'ghcr\.io/snaraj/lidersea-com' lidersea-com lidersea-com)"
  CLOUDFLARED_RUNTIME_IMAGE="$(desired_deployment_image "${REPO_ROOT}/.artifacts/rendered/helm-cloudflare-public.yaml" 'cloudflare/cloudflared:[A-Za-z0-9._-]+' cloudflared cloudflared)"
  ADMISSION_RUNTIME_IMAGE="$(desired_deployment_image "${REPO_ROOT}/.artifacts/rendered/kubernetes-platform-admission.yaml" 'reg\.kyverno\.io/kyverno/[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+' kyverno-admission-controller kyverno)"

  validate_production_context
  bash "${REPO_ROOT}/scripts/test-kind.sh" --runtime "$KIND_ACK"
  assert_clean_commit
  capture_desired_security_policy_state
  capture_production_state
  assert_flux_revision_and_security_policy_state
  assert_global_runtime_inventory
  assert_production_state
  assert_no_live_routes
  exercise_production_admission
  bash "${REPO_ROOT}/scripts/verify-exposure.sh" --live \
    'I_ACKNOWLEDGE_THIS_WILL_PROBE_PUBLIC_DNS_CLOUDFLARE_AND_MY_HOME_IP'
  assert_clean_commit
  capture_desired_security_policy_state
  capture_production_state
  assert_flux_revision_and_security_policy_state
  assert_global_runtime_inventory
  assert_production_state
  assert_no_live_routes
  assert_clean_commit
  log 'GO: static, reviewed capacity, Kind, production admission/readiness, storage, and public exposure evidence all passed'
}

case "${1:---check}" in
  --check)
    (($# == 1)) || { usage >&2; exit 2; }
    require_live_tools
    log 'PASS required tools are present; no cluster, Docker object, DNS, or network state was accessed'
    ;;
  --scaffold)
    (($# == 1)) || { usage >&2; exit 2; }
    require_static_tools
    run_static_gate --scaffold
    log 'PASS scaffold remains fail-closed; this is intentionally not release evidence'
    ;;
  --release-check)
    (($# == 1)) || { usage >&2; exit 2; }
    require_static_tools
    run_static_gate --release
    log 'PASS promoted static state and capacity review; runtime evidence is still required for GO'
    ;;
  --transition-check)
    (($# == 1)) || { usage >&2; exit 2; }
    require_static_tools
    run_static_gate --transition
    log 'PASS canonical static transition gate; no Docker or cluster object was created'
    ;;
  --transition-runtime)
    (($# == 3)) || { usage >&2; exit 2; }
    case "$2" in
      naranjo-online|lidersea-com) ;;
      *) die 'transition runtime site must be naranjo-online or lidersea-com' ;;
    esac
    [[ "$3" == "$KIND_ACK" ]] || die "exact acknowledgement is required: ${KIND_ACK}"
    require_static_tools
    bash "${REPO_ROOT}/scripts/test-kind.sh" --transition-runtime "$2" "$KIND_ACK"
    log "PASS bounded local transition runtime evidence for staged $2; production remains untouched"
    ;;
  --live)
    (($# == 4)) || { usage >&2; exit 2; }
    [[ "$2" == "$LIVE_ACK" ]] || die "exact acknowledgement is required: ${LIVE_ACK}"
    PROD_KUBECONFIG="$3"
    PROD_CONTEXT="$4"
    run_live_gate
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
