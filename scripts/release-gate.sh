#!/usr/bin/env bash
set -euo pipefail

# Release evidence gate. Static rendering is necessary but never counted as
# runtime proof. The runtime lanes (--transition-runtime, --live) fail closed
# PENDING their post-cutover successor: site runtime evidence moved to the
# standalone site repositories with the embedded sources.

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${REPO_ROOT}/versions.env"
readonly LIVE_ACK='I_ACKNOWLEDGE_RELEASE_GATE_WILL_MUTATE_LOCAL_KIND_AND_PROBE_PRODUCTION_AND_PUBLIC_EDGE'
readonly KIND_ACK='I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test_AND_ITS_INTERNAL_DOCKER_NETWORK'
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
                validates its arguments, then fails closed: the local Kind
                runtime stage was retired with the embedded site sources and
                is PENDING its post-cutover successor.
--release-check requires promoted static desired state and local capacity review.
--live          validates its arguments, then fails closed PENDING the
                post-cutover live gate (platform + remote-chart evidence).

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

require_static_tools() {
  local tool
  for tool in git rg helm kustomize kubeconform conftest; do
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
  # Site chart values now live (and prove media stays disabled) in each
  # standalone site repository; the platform-side proof is the media flag
  # check on kubernetes/websites/*/release.yaml in validate_repository.py.
  local -a storage_roots=(
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

run_static_gate() {
  local mode="$1"
  if [[ "$mode" == '--release' ]]; then
    assert_clean_commit
  fi
  "$PYTHON_BIN" -B "${REPO_ROOT}/scripts/validate_repository.py" all
  bash "${REPO_ROOT}/scripts/render-manifests.sh" "$mode"
  assert_storage_disabled
  if [[ "$mode" == '--release' ]]; then
    assert_clean_commit
    assert_capacity_evidence
  fi
}

run_live_gate() {
  # PENDING SUCCESSOR: the site charts and their runtime evidence moved to
  # the standalone site repositories; the local Kind runtime stage was
  # retired with the embedded sources. This lane fails closed until the
  # post-cutover live gate (platform + remote-chart evidence) replaces it.
  # Its two captured-evidence validators survive as executable programs —
  # scripts/validate_flux_release_evidence.py and
  # scripts/validate_runtime_inventory_evidence.py — which the successor
  # must invoke against real captured state and the suite keeps testing.
  die 'live gate is PENDING its post-cutover successor: site runtime evidence no longer renders locally'
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
    die 'transition runtime evidence is PENDING its post-cutover successor: the local Kind stage was retired with the embedded site sources'
    ;;
  --live)
    (($# == 4)) || { usage >&2; exit 2; }
    [[ "$2" == "$LIVE_ACK" ]] || die "exact acknowledgement is required: ${LIVE_ACK}"
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
