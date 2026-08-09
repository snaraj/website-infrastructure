#!/usr/bin/env bash
set -euo pipefail

# Final release evidence gate. Static rendering is necessary but never counted
# as runtime proof: --live also runs disposable Kind readiness, reads an explicit
# production context, exercises real admission with negative dry-runs, and probes
# the public edge from this machine.

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly LIVE_ACK='I_ACKNOWLEDGE_RELEASE_GATE_WILL_MUTATE_LOCAL_KIND_AND_PROBE_PRODUCTION_AND_PUBLIC_EDGE'
readonly KIND_ACK='I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test'
TEMP_ROOT=''
PROD_KUBECONFIG=''
PROD_CONTEXT=''
PYTHON_BIN=''
CAPACITY_EVIDENCE_SHA256=''

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
  scripts/release-gate.sh --release-check
  scripts/release-gate.sh --live ${LIVE_ACK} KUBECONFIG CONTEXT

--check         checks required local tools only; reads no cluster/network state.
--scaffold      proves the checked-in desired state remains fail-closed.
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
  git -C "$REPO_ROOT" rev-parse --verify HEAD >/dev/null 2>&1 || die 'release requires an existing Git commit'
  [[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" ]] || \
    die 'release requires a clean worktree, including no untracked release inputs'
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
  commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
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
  capture_prod_json nodes.json nodes get nodes -o json
  capture_prod_json deployments.json deployments get deployments -A -o json
  capture_prod_json replicasets.json replicasets get replicasets.apps -A -o json
  capture_prod_json pods.json pods get pods -A -o json
  capture_prod_json services.json services get services -A -o json
  capture_prod_json networkpolicies.json networkpolicies get networkpolicies.networking.k8s.io -A -o json
  capture_prod_json pvcs.json pvcs get persistentvolumeclaims -A -o json
  capture_prod_json quotas.json quotas get resourcequotas -A -o json
  capture_prod_json webhooks.json webhooks get validatingwebhookconfigurations -o json
  capture_prod_json policies.json policies get clusterpolicies.kyverno.io -o json
  capture_prod_json kustomizations.json kustomizations -n flux-system get kustomizations.kustomize.toolkit.fluxcd.io -o json
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
    if observed is not None and observed != meta(item).get("generation"):
        raise SystemExit(f"Flux Kustomization {name} has not observed its current generation")

releases = load("helmreleases.json")
for namespace, name in (("naranjo-online", "naranjo-online"), ("lidersea-com", "lidersea-com"), ("cloudflare-public", "cloudflare-public")):
    item = by_identity(releases, namespace, name, "HelmRelease")
    if item.get("spec", {}).get("suspend", False) or condition(item, "Ready") != "True":
        raise SystemExit(f"HelmRelease {namespace}/{name} is suspended or not Ready")
    observed = item.get("status", {}).get("observedGeneration")
    if observed is not None and observed != meta(item).get("generation"):
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
  capture_production_state
  assert_production_state
  assert_no_live_routes
  exercise_production_admission
  bash "${REPO_ROOT}/scripts/verify-exposure.sh" --live \
    'I_ACKNOWLEDGE_THIS_WILL_PROBE_PUBLIC_DNS_CLOUDFLARE_AND_MY_HOME_IP'
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
