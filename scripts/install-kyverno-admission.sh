#!/usr/bin/env bash
# Install Kyverno admission as a staged, bound, reversible transaction.
#
# WHY THIS IS NOT A `kubectl apply`
#
# An admission controller is the only component here that can make the API
# server refuse writes it would otherwise accept. A ValidatingWebhookConfiguration
# with `failurePolicy: Fail` pointing at a backend that is not answering turns
# every matching request in the cluster into a 500 — including the requests
# needed to fix it. On a one-node cluster with one operator that is the worst
# reachable state, and a single successful apply reaches it.
#
# So this script exists to make three properties executable instead of
# remembered:
#
#   ORDERING          Phases run namespace, bounds, network, CRDs, controller
#                     prerequisites, controller, then policies. The exact
#                     egress/ingress allows are in place and a disposable
#                     in-cluster API canary passes BEFORE a controller starts.
#                     The policy CRD is Established and the controllers are
#                     Available BEFORE policy validation/application can trigger
#                     webhook registration. The deny and allows are one apply.
#                     There is no operator-owned webhook phase: registration
#                     belongs to the controller.
#
#   BINDING           The tools are the versions versions.env pins and are not
#                     resolved out of the checkout; the render's SHA-256 and
#                     object inventory match the committed
#                     kubernetes/platform/admission-install/render.lock; every
#                     image in the render is one of the pinned digests; and the
#                     target is an explicitly named kubeconfig, context, and
#                     server that the kubeconfig itself confirms. Nothing is
#                     inferred from ambient state.
#
#   TRANSACTIONALITY  Every object is proven absent before anything is applied,
#                     each phase's identities are journaled before that phase
#                     runs, and any failure rolls back exactly the journal —
#                     including the cluster-scoped objects and the webhook
#                     configurations Kyverno registers for itself, which are not
#                     in the render at all. The journal is UNTRUSTED input on
#                     the way back in: every identity in it is proven to be one
#                     this install could have created, over the whole file,
#                     before the first delete. Rollback then proves zero residue.
#
# STAGES — the rollout is two reviewed steps and cannot be collapsed into one.
#
#   --stage report-only   Fail-OPEN. failurePolicy Ignore, every policy Audit.
#                         A broken install degrades to "no admission control",
#                         which is the cluster's state today, never to "no
#                         writes". This is always the first apply.
#   --stage enforce       Fail-CLOSED. The committed Enforce/Fail bytes. Refused
#                         unless the live cluster proves report-only ran:
#                         controllers Available, every policy present and in
#                         Audit, and at least one policy report produced.
#
# MODES
#   --render        render, hash, and print the inventory; no cluster contact,
#                   no pins required. This is how render.lock is regenerated.
#   --plan          every guard, plus the read-only pre-apply gate. No mutation.
#   --apply         the same guards, then the ordered transactional apply.
#   --rollback      remove exactly what a journal says an attempt created.
#                   This is the undo for stage 1, which CREATES objects.
#   --demote        re-apply the report-only bytes over a live install. This is
#                   the undo for stage 2, which creates nothing and only changes
#                   policy actions: deleting would be a far larger act than the
#                   promotion it is reverting.
#   --break-glass   delete ONLY the Kyverno webhook configurations, at once,
#                   for the case where the cluster has started refusing writes.
#
# TARGET BINDING — all three are required for every mode that contacts the
# cluster, and a mismatch is fatal:
#   KUBECONFIG                 path to the reviewed kubeconfig
#   KYVERNO_INSTALL_CONTEXT    the exact context name within it
#   KYVERNO_INSTALL_SERVER     the exact API server URL that context must name
#   KYVERNO_RUNTIME_NETWORK_CONTRACT
#                              private mode-0600 selected-CNI/HA endpoint data;
#                              never the operator kubeconfig endpoint
#   KYVERNO_REPORT_ONLY_JOURNAL stage-1 transaction record, required only for a
#                              stage-2 rehearsal/promotion
#
# See docs/runbooks/kyverno-install.md for the surrounding ceremony, the
# stage-1 to stage-2 promotion gate, and the break-glass procedure.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
INSTALL_ROOT='kubernetes/platform/admission-install'
LOCK_FILE="${REPO_ROOT}/${INSTALL_ROOT}/render.lock"
VERSIONS_FILE="${REPO_ROOT}/versions.env"
# The one namespace this transaction is allowed to create anything in. Rollback
# validates every namespaced journal entry against it, so a journal cannot name
# an object in kube-system and have it deleted.
INSTALL_NAMESPACE='kyverno'

# The pins this install is bound to. They are platform-lane values and this
# script never invents them: their absence is the reason an apply is refused
# today, and stating them by name is how the ask is made unambiguous.
REQUIRED_PINS=(
  KYVERNO_VERSION
  KYVERNO_CHART_VERSION
  KYVERNO_ADMISSION_CONTROLLER_IMAGE
  KYVERNO_REPORTS_CONTROLLER_IMAGE
  KYVERNO_KYVERNOPRE_IMAGE
  KYVERNO_NETWORK_CANARY_IMAGE
)
PIN_IMAGE_KEYS=(
  KYVERNO_ADMISSION_CONTROLLER_IMAGE
  KYVERNO_REPORTS_CONTROLLER_IMAGE
  KYVERNO_KYVERNOPRE_IMAGE
  KYVERNO_NETWORK_CANARY_IMAGE
)
# Controller images stay in Kyverno's official registry. The disposable
# network canary is a separately reviewed Kubernetes test image. Every image is
# tag+digest bound, and the all-zero sentinel is always refused.
KYVERNO_IMAGE_PATTERN='^reg\.kyverno\.io/kyverno/[a-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$'
CANARY_IMAGE_PATTERN='^registry\.k8s\.io/e2e-test-images/agnhost:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$'
ZERO_DIGEST='sha256:0000000000000000000000000000000000000000000000000000000000000000'

# Separate fail-closed sentinels for separate trust directions. The operator
# target is never substituted into either. A private runtime contract expands
# the first to every control-plane webhook source and the second to the exact
# peer set the selected CNI observes for `kubernetes.default.svc`.
WEBHOOK_SOURCE_SENTINEL_CIDR='192.0.2.10/32'
RUNTIME_API_SENTINEL_CIDR='192.0.2.20/32'
RUNTIME_API_SENTINEL_PORT='65535'
RUNTIME_NETWORK_SCHEMA='website-infrastructure-kyverno-network-v1'

# Ordered install phases, by kind. A kind that appears in the render and in no
# phase stops the install: an unclassified object is an object whose ordering
# nobody decided, and ordering is the whole point of this script.
PHASE_NAMES=(namespace bounds network crds controller-prerequisites controller policies)
declare -A PHASE_KINDS=(
  [namespace]='Namespace'
  [bounds]='ResourceQuota|LimitRange'
  [network]='NetworkPolicy'
  [crds]='CustomResourceDefinition'
  [controller-prerequisites]='ConfigMap|ServiceAccount|ClusterRole|ClusterRoleBinding|Role|RoleBinding|Service|PodDisruptionBudget|PriorityClass'
  [controller]='Deployment'
  [policies]='ClusterPolicy|Policy'
)

# There is deliberately no webhook phase. Registering a ValidatingWebhookConfiguration
# by `kubectl apply` points the API server at a backend whose health nothing has
# proven — the exact misregistration this transaction exists to prevent. Kyverno
# writes its own webhook configurations, through its own RBAC, after the ordered
# health wait, and only then. A render that declares one is refused outright.
FORBIDDEN_KINDS='ValidatingWebhookConfiguration|MutatingWebhookConfiguration'

# Kinds whose objects live outside a namespace. Rollback must name these
# explicitly: deleting the namespace does not remove them, and a leftover
# webhook configuration is the specific piece of residue that keeps refusing
# writes after the controller behind it is gone.
CLUSTER_SCOPED_KINDS='CustomResourceDefinition|ClusterRole|ClusterRoleBinding|ValidatingWebhookConfiguration|MutatingWebhookConfiguration|ClusterPolicy|PriorityClass|Namespace'

die() {
  printf 'install-kyverno-admission: %s\n' "$*" >&2
  exit 1
}

note() {
  printf 'install-kyverno-admission: %s\n' "$*"
}

usage() {
  printf '%s\n' \
    'Usage: scripts/install-kyverno-admission.sh --stage <report-only|enforce> <mode>' \
    '  --render        render + digest + inventory; no cluster contact' \
    '  --plan          all guards + read-only pre-apply gate; no mutation' \
    '  --apply         all guards, then the ordered transactional apply' \
    '  --rollback      undo one attempt; requires --journal <file>' \
    '  --break-glass   delete only the Kyverno webhook configurations'
}

# --- argument parsing --------------------------------------------------------

STAGE=''
MODE=''
JOURNAL=''
while (($# > 0)); do
  case "$1" in
    --stage)
      (($# >= 2)) || die '--stage requires a value'
      STAGE="$2"
      shift 2
      ;;
    --journal)
      (($# >= 2)) || die '--journal requires a value'
      JOURNAL="$2"
      shift 2
      ;;
    --render|--plan|--apply|--rollback|--demote|--break-glass)
      [[ -z "$MODE" ]] || die 'only one mode may be given'
      MODE="$1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$MODE" ]] || die 'a mode is required; see --help'
case "$MODE" in
  --break-glass|--demote) : ;;
  --rollback)
    [[ -n "$JOURNAL" ]] || die '--rollback requires --journal <file>'
    ;;
  --apply)
    [[ -n "$JOURNAL" ]] || die '--apply requires --journal <file> so the transaction record survives the process'
    ;;&
  *)
    case "$STAGE" in
      report-only|enforce) ;;
      '') die '--stage is required; see --help' ;;
      *) die "unknown stage: ${STAGE}" ;;
    esac
    ;;
esac

# --- lock file ---------------------------------------------------------------

# Read one key from the lock. The file is parsed as data and never sourced: a
# record that describes what may be applied must not be able to execute.
lock_value() {
  local key="$1" line=''
  [[ -f "$LOCK_FILE" ]] || die "missing render lock: ${INSTALL_ROOT}/render.lock"
  line="$(grep -E "^${key}=" "$LOCK_FILE" || true)"
  [[ -n "$line" ]] || die "render lock has no ${key}"
  printf '%s' "${line#*=}"
}

# --- stage authorization -----------------------------------------------------

# BOTH mutating stages are reviewed decisions and neither is authorized today.
# This check runs before tool resolution, target binding, runtime-contract
# reads, journal path inspection, or journal creation. A dependent prerequisite
# cannot accidentally become reachable just because an earlier guard changed.
#
# `--plan` stays reachable: it mutates nothing, it is how the promotion gate is
# rehearsed, and refusing it would delete the only way to exercise that gate.
# It prints the refusal as a warning instead.
require_stage_authorization() {
  local stage="$1" authorized='' blockers=''
  authorized="$(lock_value "stage.${stage}.authorized")"
  [[ "$authorized" != 'yes' ]] || return 0
  blockers="$(lock_value "stage.${stage}.blocked-by")"
  case "$MODE" in
    --apply)
      die "stage ${stage} is NOT AUTHORIZED: activation is blocked on ${blockers}; see docs/runbooks/kyverno-install.md. Authorization is a reviewed change to render.lock, never an edit made during a ceremony"
      ;;
    *)
      note "WARNING: stage ${stage} is NOT AUTHORIZED; this is a rehearsal and nothing may be applied"
      note "activation is blocked on ${blockers}"
      ;;
  esac
}

validate_apply_journal_path() {
  # The journal is the only record of what this attempt created, and it must
  # outlive the process. Authorization is checked BEFORE this path is touched.
  [[ ! -L "$JOURNAL" ]] || die "journal path is a symlink and will not be written through: ${JOURNAL}"
  [[ ! -s "$JOURNAL" ]] || die "journal already records an attempt: ${JOURNAL}"
  local journal_directory=''
  journal_directory="$(cd -- "$(dirname -- "$JOURNAL")" 2>/dev/null && pwd -P)" || \
    die "journal directory does not exist: $(dirname -- "$JOURNAL")"
  case "${journal_directory}/" in
    "${REPO_ROOT}"/*)
      die "journal path is inside the checkout: ${JOURNAL}; the transaction record must outlive any working-tree operation (see docs/runbooks/kyverno-install.md)"
      ;;
  esac
}

case "$MODE" in
  --render|--plan|--apply)
    require_stage_authorization "$STAGE"
    [[ "$MODE" != '--apply' ]] || validate_apply_journal_path
    ;;
esac

digest_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum <"$1" | cut -d' ' -f1
  else
    shasum -a 256 <"$1" | cut -d' ' -f1
  fi
}

digest_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | cut -d' ' -f1
  else
    printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
  fi
}

# --- tool binding ------------------------------------------------------------

# A tool that satisfies `command -v` is not a bound tool. Two things are proven
# here: the binary is not being resolved out of the checkout (a repository that
# can supply its own kubectl can supply one that reports whatever the gate wants
# to hear), and its version is exactly the one versions.env pins.
resolved_tool() {
  local tool="$1" path=''
  path="$(command -v "$tool" 2>/dev/null)" || die "${tool} is required"
  case "$path" in
    /*) ;;
    *) die "${tool} did not resolve to an absolute path" ;;
  esac
  # Compare PHYSICAL paths. REPO_ROOT is already symlink-resolved, and a PATH
  # entry rarely is (macOS TMPDIR alone is a symlink), so a textual comparison
  # would miss exactly the case this guard exists for.
  local directory=''
  directory="$(cd -- "$(dirname -- "$path")" 2>/dev/null && pwd -P)" || \
    die "${tool} resolves to an unreadable directory"
  path="${directory}/$(basename -- "$path")"
  case "$path" in
    "${REPO_ROOT}"/*) die "${tool} resolves inside the checkout: ${path}" ;;
  esac
  printf '%s' "$path"
}

pinned_version() {
  local key="$1" line=''
  [[ -f "$VERSIONS_FILE" ]] || die 'versions.env is missing'
  line="$(grep -E "^${key}=" "$VERSIONS_FILE" || true)"
  [[ -n "$line" ]] || die "versions.env has no ${key}"
  printf '%s' "${line#*=}"
}

verify_tool_digest() {
  local tool="$1" path="$2" pin_key="$3" expected='' actual=''
  expected="$(pinned_version "$pin_key")"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "versions.env has no valid ${pin_key}"
  actual="$(digest_of "$path")"
  [[ "$actual" == "$expected" ]] || \
    die "${tool} executable sha256 ${actual} does not match versions.env ${pin_key}"
}

bind_tools() {
  local expected='' actual=''
  KUSTOMIZE_BIN="$(resolved_tool kustomize)"
  expected="$(pinned_version KUSTOMIZE_VERSION)"
  actual="$("$KUSTOMIZE_BIN" version 2>/dev/null | head -n1 | tr -d '[:space:]')"
  [[ "$actual" == "$expected" ]] || \
    die "kustomize is ${actual}; versions.env pins ${expected}"
  # The lock records which renderer produced its digests; a different one may
  # legitimately produce different bytes, so the mismatch must be named here
  # rather than surfacing later as an unexplained digest failure.
  local lock_tool_version=''
  lock_tool_version="$(lock_value render.tool.version)"
  [[ "$actual" == "$lock_tool_version" ]] || \
    die "kustomize is ${actual}; render.lock digests were produced by ${lock_tool_version}"
  verify_tool_digest kustomize "$KUSTOMIZE_BIN" KUSTOMIZE_LINUX_AMD64_SHA256

  KUBECTL_BIN="$(resolved_tool kubectl)"
  expected="$(pinned_version KUBERNETES_VERSION)"
  actual="$("$KUBECTL_BIN" version --client --output=json 2>/dev/null |
    sed -n 's/.*"gitVersion": *"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$actual" ]] || die 'kubectl did not report a client version'
  [[ "$actual" == "$expected" ]] || \
    die "kubectl is ${actual}; versions.env pins ${expected}"
  verify_tool_digest kubectl "$KUBECTL_BIN" KUBECTL_LINUX_AMD64_SHA256
}

# --- pin binding -------------------------------------------------------------

# The platform-lane values this install is bound to. Their absence is the
# current, intended state of this branch: the transaction is reviewable and the
# apply is impossible.
bind_pins() {
  local key='' value=''
  PIN_IMAGES=()
  for key in "${REQUIRED_PINS[@]}"; do
    value="$(grep -E "^${key}=" "$VERSIONS_FILE" 2>/dev/null || true)"
    value="${value#*=}"
    if [[ -z "$value" || "$value" == 'UNRESOLVED' ]]; then
      die "versions.env has no reviewed ${key}; the Kyverno controller pins are a platform-lane decision and this installer will not invent them (see docs/runbooks/kyverno-install.md)"
    fi
  done
  for key in "${PIN_IMAGE_KEYS[@]}"; do
    value="$(grep -E "^${key}=" "$VERSIONS_FILE" || true)"
    value="${value#*=}"
    case "$key" in
      KYVERNO_NETWORK_CANARY_IMAGE)
        [[ "$value" =~ $CANARY_IMAGE_PATTERN ]] || \
          die "${key} is not the reviewed Kubernetes canary image at a full digest: ${value}"
        ;;
      *)
        [[ "$value" =~ $KYVERNO_IMAGE_PATTERN ]] || \
          die "${key} is not an official Kyverno image at a full digest: ${value}"
        ;;
    esac
    case "$value" in
      *"@${ZERO_DIGEST}") die "${key} still carries the all-zero sentinel digest" ;;
    esac
    [[ "$key" == 'KYVERNO_NETWORK_CANARY_IMAGE' ]] || PIN_IMAGES+=("$value")
  done
}

# --- render + lock binding ---------------------------------------------------

render_stage() {
  local stage="$1" destination="$2"
  "$KUSTOMIZE_BIN" build "${REPO_ROOT}/${INSTALL_ROOT}/${stage}" >"$destination"
  [[ -s "$destination" ]] || die "render produced no bytes for stage ${stage}"
}

object_count() {
  grep -cE '^kind:[[:space:]]' "$1" || true
}

verify_lock() {
  local stage="$1" rendered="$2" actual_digest='' actual_objects=''
  actual_digest="$(digest_of "$rendered")"
  actual_objects="$(object_count "$rendered")"
  local expected_digest='' expected_objects=''
  expected_digest="$(lock_value "${stage}.sha256")"
  expected_objects="$(lock_value "${stage}.objects")"
  [[ "$actual_digest" == "$expected_digest" ]] || \
    die "stage ${stage} render sha256 ${actual_digest} does not match render.lock ${expected_digest}"
  [[ "$actual_objects" == "$expected_objects" ]] || \
    die "stage ${stage} render has ${actual_objects} objects; render.lock records ${expected_objects}"
  note "stage ${stage} render sha256 ${actual_digest} (${actual_objects} objects) matches render.lock"
}

# Every image in the bytes about to be applied must be one of the pinned
# digests. This is what makes the pins load-bearing rather than decorative: a
# render that names any other image, including the staged all-zero sentinel, is
# refused here even though it hashed correctly.
verify_images() {
  local rendered="$1" image='' pinned='' matched=''
  while IFS= read -r image; do
    [[ -n "$image" ]] || continue
    matched=''
    for pinned in "${PIN_IMAGES[@]}"; do
      [[ "$image" != "$pinned" ]] || matched='yes'
    done
    [[ -n "$matched" ]] || die "render names an unpinned image: ${image}"
  done < <(sed -n 's/^[[:space:]]*image:[[:space:]]*//p' "$rendered" | tr -d '"' | sort -u)
}

# The exclusions that prevent lockout, proven in the bytes rather than trusted
# from the comment above them.
verify_exclusions() {
  local rendered="$1" namespace=''
  for namespace in kube-system flux-system kyverno; do
    grep -Fq "[*/*,${namespace},*]" "$rendered" || \
      die "the engine configuration does not filter the ${namespace} namespace"
    grep -Fq "\"${namespace}\"" "$rendered" || \
      die "the webhook namespaceSelector does not exclude ${namespace}"
  done
  grep -Fq '"operator":"NotIn"' "$rendered" || \
    die 'the webhook namespaceSelector is not a NotIn exclusion'
  grep -Fq 'excludeGroups: system:nodes' "$rendered" || \
    die 'the engine configuration does not exclude the kubelet identity'
}

# The stage is a property of the bytes, not of the flag. A render that claims to
# be report-only while carrying an enforcing rule would be the exact failure the
# staging exists to prevent, so the flag is verified against the content.
verify_stage_actions() {
  local stage="$1" rendered="$2"
  case "$stage" in
    report-only)
      ! grep -qE '^[[:space:]]+failureAction:[[:space:]]+Enforce$' "$rendered" || \
        die 'stage report-only render still contains an Enforce rule action'
      ! grep -qE '^[[:space:]]+validationFailureAction:[[:space:]]+Enforce$' "$rendered" || \
        die 'stage report-only render still contains an Enforce policy action'
      ! grep -qE '^[[:space:]]+failurePolicy:[[:space:]]+Fail$' "$rendered" || \
        die 'stage report-only render still registers a fail-closed webhook'
      grep -qE '^[[:space:]]+failurePolicy:[[:space:]]+Ignore$' "$rendered" || \
        die 'stage report-only render declares no fail-open webhook policy'
      ;;
    enforce)
      grep -qE '^[[:space:]]+failurePolicy:[[:space:]]+Fail$' "$rendered" || \
        die 'stage enforce render declares no fail-closed webhook policy'
      ! grep -qE '^[[:space:]]+failurePolicy:[[:space:]]+Ignore$' "$rendered" || \
        die 'stage enforce render still contains a fail-open webhook policy'
      ;;
  esac
}

# --- target binding ----------------------------------------------------------

# Three explicit values, cross-checked against each other. An unset context, a
# context the kubeconfig does not define, or a server the context does not name
# all stop here: an admission install that mutates "whatever kubectl was
# pointing at" is not a reviewed change.
#
# This is OPERATOR TARGET IDENTITY and nothing else. It is never reused as a
# Pod NetworkPolicy peer: controllers reach `kubernetes.default.svc`, not the
# operator's kubeconfig URL.
bind_target_identity() {
  [[ -n "${KUBECONFIG:-}" ]] || die 'KUBECONFIG must name the reviewed kubeconfig'
  [[ -f "${KUBECONFIG}" ]] || die "KUBECONFIG does not exist: ${KUBECONFIG}"
  [[ -n "${KYVERNO_INSTALL_CONTEXT:-}" ]] || die 'KYVERNO_INSTALL_CONTEXT must name the exact context'
  [[ -n "${KYVERNO_INSTALL_SERVER:-}" ]] || die 'KYVERNO_INSTALL_SERVER must name the exact API server URL'

  local cluster='' server=''
  cluster="$("$KUBECTL_BIN" config view -o "jsonpath={.contexts[?(@.name=='${KYVERNO_INSTALL_CONTEXT}')].context.cluster}" 2>/dev/null || true)"
  [[ -n "$cluster" ]] || die "the kubeconfig defines no context named ${KYVERNO_INSTALL_CONTEXT}"
  server="$("$KUBECTL_BIN" config view -o "jsonpath={.clusters[?(@.name=='${cluster}')].cluster.server}" 2>/dev/null || true)"
  [[ -n "$server" ]] || die "the kubeconfig context ${KYVERNO_INSTALL_CONTEXT} names no server"
  [[ "$server" == "${KYVERNO_INSTALL_SERVER}" ]] || \
    die "context ${KYVERNO_INSTALL_CONTEXT} targets a different server than KYVERNO_INSTALL_SERVER"
}

bind_target() {
  bind_target_identity
}

KUBECTL() {
  "$KUBECTL_BIN" --kubeconfig "${KUBECONFIG}" --context "${KYVERNO_INSTALL_CONTEXT}" \
    --server "${KYVERNO_INSTALL_SERVER}" "$@"
}

# --- private runtime network contract ----------------------------------------

contract_value() {
  local key="$1" line=''
  line="$(grep -E "^${key}=" "$RUNTIME_NETWORK_CONTRACT" || true)"
  [[ -n "$line" ]] || die "runtime network contract has no ${key}"
  [[ "$(grep -cE "^${key}=" "$RUNTIME_NETWORK_CONTRACT" || true)" -eq 1 ]] || \
    die "runtime network contract repeats ${key}"
  printf '%s' "${line#*=}"
}

canonical_cidr_list() {
  local label="$1" list="$2" item='' sorted=''
  local octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
  local cidr="^${octet}\\.${octet}\\.${octet}\\.${octet}/32\$"
  [[ -n "$list" && "$list" != *' '* && "$list" != ,* && "$list" != *, && "$list" != *,,* ]] || \
    die "runtime network contract ${label} is not a canonical comma-separated /32 set"
  local IFS=','
  for item in $list; do
    [[ "$item" =~ $cidr ]] || die "runtime network contract ${label} contains a non-IPv4-/32 peer"
    case "$item" in
      "$WEBHOOK_SOURCE_SENTINEL_CIDR"|"$RUNTIME_API_SENTINEL_CIDR")
        die "runtime network contract ${label} contains a fail-closed sentinel"
        ;;
    esac
  done
  unset IFS
  sorted="$(printf '%s' "$list" | tr ',' '\n' | LC_ALL=C sort -u | paste -sd, -)"
  [[ "$sorted" == "$list" ]] || \
    die "runtime network contract ${label} must be sorted and duplicate-free"
  printf '%s' "$list"
}

bind_runtime_network_contract() {
  local expected_keys='' actual_keys='' invalid_lines=''
  [[ -n "${KYVERNO_RUNTIME_NETWORK_CONTRACT:-}" ]] || \
    die 'KYVERNO_RUNTIME_NETWORK_CONTRACT must name the reviewed private selected-CNI/HA contract'
  [[ -f "$KYVERNO_RUNTIME_NETWORK_CONTRACT" && ! -L "$KYVERNO_RUNTIME_NETWORK_CONTRACT" ]] || \
    die 'runtime network contract must be a regular non-symlink file'
  RUNTIME_NETWORK_CONTRACT="$(cd -- "$(dirname -- "$KYVERNO_RUNTIME_NETWORK_CONTRACT")" && pwd -P)/$(basename -- "$KYVERNO_RUNTIME_NETWORK_CONTRACT")"
  case "$RUNTIME_NETWORK_CONTRACT" in
    "${REPO_ROOT}"/*) die 'runtime network contract must remain outside the checkout' ;;
  esac
  [[ "$(stat -c '%a' "$RUNTIME_NETWORK_CONTRACT" 2>/dev/null)" == '600' ]] || \
    die 'runtime network contract mode must be 0600'
  invalid_lines="$(awk 'NF && $0 !~ /^[A-Z][A-Z0-9_]*=[^[:space:]]+$/ { print NR }' "$RUNTIME_NETWORK_CONTRACT")"
  [[ -z "$invalid_lines" ]] || \
    die 'runtime network contract contains blank values, whitespace, comments, or malformed records'
  expected_keys="$(printf '%s\n' \
    CNI_IDENTITY \
    DNS_NAME \
    KUBERNETES_ENDPOINT_CIDRS \
    KUBERNETES_ENDPOINT_PORT \
    KUBERNETES_SERVICE_CIDR \
    KUBERNETES_SERVICE_PORT \
    KUBE_PROXY_MODE \
    POLICY_DATAPLANE \
    SCHEMA \
    WEBHOOK_SOURCE_CIDRS)"
  actual_keys="$(sed '/^$/d;s/=.*//' "$RUNTIME_NETWORK_CONTRACT" | LC_ALL=C sort)"
  [[ "$actual_keys" == "$expected_keys" ]] || \
    die 'runtime network contract key inventory is not exact'
  [[ "$(contract_value SCHEMA)" == "$RUNTIME_NETWORK_SCHEMA" ]] || \
    die 'runtime network contract schema is not reviewed'
  RUNTIME_CNI_IDENTITY="$(contract_value CNI_IDENTITY)"
  [[ "$RUNTIME_CNI_IDENTITY" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || \
    die 'runtime network contract CNI_IDENTITY is not canonical'
  RUNTIME_KUBE_PROXY_MODE="$(contract_value KUBE_PROXY_MODE)"
  [[ "$RUNTIME_KUBE_PROXY_MODE" =~ ^(iptables|ipvs|nftables|ebpf-replacement)$ ]] || \
    die 'runtime network contract KUBE_PROXY_MODE is not reviewed'
  RUNTIME_DATAPLANE_MODE="$(contract_value POLICY_DATAPLANE)"
  [[ "$RUNTIME_DATAPLANE_MODE" =~ ^(service-vip|endpoint)$ ]] || \
    die 'runtime network contract POLICY_DATAPLANE must be service-vip or endpoint'
  RUNTIME_SERVICE_CIDR="$(canonical_cidr_list KUBERNETES_SERVICE_CIDR "$(contract_value KUBERNETES_SERVICE_CIDR)")"
  [[ "$RUNTIME_SERVICE_CIDR" != *,* ]] || die 'KUBERNETES_SERVICE_CIDR must contain exactly one /32'
  RUNTIME_SERVICE_PORT="$(contract_value KUBERNETES_SERVICE_PORT)"
  [[ "$RUNTIME_SERVICE_PORT" == '443' ]] || die 'KUBERNETES_SERVICE_PORT must be 443'
  RUNTIME_ENDPOINT_CIDRS="$(canonical_cidr_list KUBERNETES_ENDPOINT_CIDRS "$(contract_value KUBERNETES_ENDPOINT_CIDRS)")"
  RUNTIME_ENDPOINT_PORT="$(contract_value KUBERNETES_ENDPOINT_PORT)"
  [[ "$RUNTIME_ENDPOINT_PORT" == '6443' ]] || die 'KUBERNETES_ENDPOINT_PORT must be 6443'
  RUNTIME_WEBHOOK_SOURCE_CIDRS="$(canonical_cidr_list WEBHOOK_SOURCE_CIDRS "$(contract_value WEBHOOK_SOURCE_CIDRS)")"
  [[ "$(contract_value DNS_NAME)" == 'kubernetes.default.svc' ]] || \
    die 'runtime network contract DNS_NAME must be kubernetes.default.svc'
  RUNTIME_NETWORK_DIGEST="$(digest_of "$RUNTIME_NETWORK_CONTRACT")"
}

cross_check_runtime_network_contract() {
  local service='' endpoint_addresses='' endpoint_ports='' control_plane_addresses=''
  if ! service="$(KUBECTL -n default get service kubernetes \
      -o 'jsonpath={.spec.clusterIP}{"|"}{.spec.ports[?(@.name=="https")].port}' 2>&1)"; then
    die 'cannot cross-check the in-cluster kubernetes.default Service'
  fi
  [[ "$service" == "${RUNTIME_SERVICE_CIDR%/32}|${RUNTIME_SERVICE_PORT}" ]] || \
    die 'runtime network contract does not match the live kubernetes.default Service VIP/port'
  if ! endpoint_addresses="$(KUBECTL -n default get endpoints kubernetes \
      -o 'jsonpath={range .subsets[*].addresses[*]}{.ip}{"\n"}{end}' 2>&1)"; then
    die 'cannot cross-check the Kubernetes API endpoint addresses'
  fi
  endpoint_addresses="$(printf '%s\n' "$endpoint_addresses" | sed '/^$/d;s#$#/32#' | LC_ALL=C sort -u | paste -sd, -)"
  [[ "$endpoint_addresses" == "$RUNTIME_ENDPOINT_CIDRS" ]] || \
    die 'runtime network contract does not match the complete live Kubernetes API endpoint set'
  if ! endpoint_ports="$(KUBECTL -n default get endpoints kubernetes \
      -o 'jsonpath={range .subsets[*].ports[*]}{.port}{"\n"}{end}' 2>&1)"; then
    die 'cannot cross-check the Kubernetes API endpoint ports'
  fi
  [[ "$(printf '%s\n' "$endpoint_ports" | sed '/^$/d' | LC_ALL=C sort -u | paste -sd, -)" == "$RUNTIME_ENDPOINT_PORT" ]] || \
    die 'runtime network contract does not match the live Kubernetes API endpoint port'
  if ! control_plane_addresses="$(KUBECTL get nodes -l node-role.kubernetes.io/control-plane \
      -o 'jsonpath={range .items[*].status.addresses[?(@.type=="InternalIP")]}{.address}{"\n"}{end}' 2>&1)"; then
    die 'cannot cross-check the control-plane webhook source set'
  fi
  control_plane_addresses="$(printf '%s\n' "$control_plane_addresses" | sed '/^$/d;s#$#/32#' | LC_ALL=C sort -u | paste -sd, -)"
  [[ -n "$control_plane_addresses" && "$control_plane_addresses" == "$RUNTIME_WEBHOOK_SOURCE_CIDRS" ]] || \
    die 'runtime network contract does not match every live control-plane InternalIP (including HA peers)'
  note 'runtime network contract matches the selected CNI mode and complete live Service/endpoint/control-plane sets'
}

expand_cidr_sentinel() {
  local source="$1" destination="$2" sentinel="$3" peers="$4" found=''
  found="$(grep -cF "cidr: ${sentinel}" "$source" || true)"
  [[ "$found" -eq 1 ]] || die "render carries ${found} occurrences of network sentinel ${sentinel}; expected one"
  awk -v sentinel="$sentinel" -v peers="$peers" '
    $0 == "            cidr: " sentinel {
      count = split(peers, peer, ",")
      print "            cidr: " peer[1]
      for (i = 2; i <= count; i++) {
        print "        - ipBlock:"
        print "            cidr: " peer[i]
      }
      next
    }
    { print }
  ' "$source" >"$destination"
}

substitute_runtime_network() {
  local source="$1" destination="$2" first="${WORK}/network-webhook.yaml" second="${WORK}/network-api.yaml"
  local api_peers='' api_port=''
  case "$RUNTIME_DATAPLANE_MODE" in
    service-vip) api_peers="$RUNTIME_SERVICE_CIDR"; api_port="$RUNTIME_SERVICE_PORT" ;;
    endpoint) api_peers="$RUNTIME_ENDPOINT_CIDRS"; api_port="$RUNTIME_ENDPOINT_PORT" ;;
  esac
  expand_cidr_sentinel "$source" "$first" "$WEBHOOK_SOURCE_SENTINEL_CIDR" "$RUNTIME_WEBHOOK_SOURCE_CIDRS"
  expand_cidr_sentinel "$first" "$second" "$RUNTIME_API_SENTINEL_CIDR" "$api_peers"
  [[ "$(grep -cF "port: ${RUNTIME_API_SENTINEL_PORT}" "$second" || true)" -eq 1 ]] || \
    die 'render does not carry exactly one runtime API port sentinel'
  sed "s/port: ${RUNTIME_API_SENTINEL_PORT}/port: ${api_port}/" "$second" >"$destination"
  ! grep -qE '192\.0\.2\.(10|20)/32|port: 65535' "$destination" || \
    die 'a fail-closed runtime network sentinel survived substitution'
}

# --- inventory ---------------------------------------------------------------

# Split the render into one file per document and record each document's
# identity. Only top-level `kind:`, `  name:` and `  namespace:` are read, which
# is exactly the metadata a reviewed, machine-generated render states at the
# document root; the per-phase counts are then checked against render.lock, so a
# mis-split cannot pass silently.
split_render() {
  local rendered="$1" directory="$2"
  mkdir -p -- "$directory"
  awk -v out="$directory" '
    BEGIN { n = 0; file = sprintf("%s/%04d.yaml", out, n) }
    /^---[[:space:]]*$/ { n++; file = sprintf("%s/%04d.yaml", out, n); next }
    { print >file }
  ' "$rendered"
  # Drop any empty leading document the separator produced.
  local candidate=''
  for candidate in "$directory"/*.yaml; do
    grep -qE '^kind:[[:space:]]' "$candidate" || rm -f -- "$candidate"
  done
}

document_field() {
  local file="$1" field="$2"
  sed -n "s/^${field}:[[:space:]]*//p" "$file" | head -n1 | tr -d '"'
}

document_metadata() {
  local file="$1" field="$2"
  awk -v field="$field" '
    /^metadata:[[:space:]]*$/ { inside = 1; next }
    /^[^[:space:]]/ { inside = 0 }
    inside && $1 == field":" { print $2; exit }
  ' "$file" | tr -d '"'
}

phase_kinds() {
  local phase="$1"
  printf '%s' "${PHASE_KINDS[$phase]}"
}

# Every kind this transaction is able to journal, DERIVED from the phase table
# rather than restated beside it. The journal writer classifies each rendered
# document through PHASE_KINDS and refuses anything it cannot place, so a kind
# absent from that table is a kind no attempt of this installer ever recorded —
# and a journal line naming one can only have been authored by something else.
# Deriving it is what keeps the writer and the rollback reader from drifting
# apart the way a second hard-coded list would.
journalable_kinds() {
  local phase='' pattern=''
  for phase in "${PHASE_NAMES[@]}"; do
    pattern="${pattern}${pattern:+|}${PHASE_KINDS[$phase]}"
  done
  printf '%s' "$pattern"
}

# --- pre-apply gate ----------------------------------------------------------

# Nothing this install creates may already exist. The namespace being absent
# covers every namespaced child, so only the cluster-scoped names need naming —
# and they are read from render.lock rather than from the render, so a drift
# between the reviewed inventory and the bytes fails loudly instead of shrinking
# the probe.
probe_absence() {
  local entry='' kind='' name='' state=''
  state="$(KUBECTL get namespace kyverno -o name 2>&1 || true)"
  if [[ "$state" != *'not found'* ]]; then
    [[ -n "$state" ]] || die 'could not determine the kyverno namespace state'
    die 'the kyverno namespace already exists; this install refuses to adopt an object it did not create'
  fi
  local names=''
  names="$(lock_value inventory.cluster-scoped.names)"
  local IFS=','
  for entry in $names; do
    kind="${entry%%/*}"
    name="${entry#*/}"
    [[ "$kind" != 'Namespace' ]] || continue
    grep -qE "^[[:space:]]*name:[[:space:]]+${name}[[:space:]]*$" "$RENDERED" || \
      die "reviewed inventory names ${kind}/${name} but the render does not contain it"
    # Same class as the residue proof: a read that FAILED is not a read that
    # returned "absent". Discarding the status here would let a denied or timing
    # -out API answer be recorded as "nothing exists", and the transaction would
    # then create objects over state it never actually observed. Only an
    # explicit not-found is absence; anything else stops the install.
    if state="$(KUBECTL get "$kind" "$name" -o name 2>&1)"; then
      die "${kind}/${name} already exists; refusing to adopt a foreign object"
    fi
    [[ "$state" == *'not found'* || "$state" == *'NotFound'* ]] || \
      die "could not determine whether ${kind}/${name} exists: ${state}"
  done
  note 'pre-apply absence probe clean: nothing this install creates already exists'
}

# --- stage gate --------------------------------------------------------------

# Stage 2 is not reachable from an empty cluster. The evidence demanded here is
# the evidence stage 1 exists to produce: controllers that came up, policies
# that loaded, and reports that prove the engine actually evaluated traffic.
require_report_only_evidence() {
  local available='' entry='' name='' action='' reports='' inventory='' binding=''
  local rule_actions='' rule_action='' report_policy='' report_timestamp=''
  local reviewed_reports=0 installed_at='' now='' minimum_age='' age=''
  local live_render='' live_network='' live_journal='' live_attempt='' extra=''
  local expected_controllers='' actual_controllers='' generation=''
  local observed_generation='' desired='' updated='' ready=''
  [[ -n "${KYVERNO_REPORT_ONLY_JOURNAL:-}" ]] || \
    die 'KYVERNO_REPORT_ONLY_JOURNAL must name the exact stage-1 transaction record'
  [[ -f "$KYVERNO_REPORT_ONLY_JOURNAL" && ! -L "$KYVERNO_REPORT_ONLY_JOURNAL" ]] || \
    die 'stage-1 evidence journal must be a regular non-symlink file'
  validate_journal "$KYVERNO_REPORT_ONLY_JOURNAL"
  [[ "$(sed -n '1{s/^[^|]*|\([^|]*\).*/\1/p;}' "$KYVERNO_REPORT_ONLY_JOURNAL")" == 'report-only' ]] || \
    die 'stage-1 evidence journal does not describe report-only'
  if ! binding="$(KUBECTL get namespace kyverno \
      -o 'jsonpath={.metadata.annotations.platform\.snaraj\.dev/install-render-sha256}{"|"}{.metadata.annotations.platform\.snaraj\.dev/install-network-sha256}{"|"}{.metadata.annotations.platform\.snaraj\.dev/install-journal-sha256}{"|"}{.metadata.annotations.platform\.snaraj\.dev/install-attempt-id}{"|"}{.metadata.annotations.platform\.snaraj\.dev/install-started-unix}' 2>&1)"; then
    die 'cannot read the live stage-1 transaction binding'
  fi
  IFS='|' read -r live_render live_network live_journal live_attempt installed_at extra <<<"$binding"
  [[ -z "${extra:-}" && "${live_render}|${live_network}|${live_journal}" == "$(lock_value report-only.sha256)|${RUNTIME_NETWORK_DIGEST}|$(digest_of "$KYVERNO_REPORT_ONLY_JOURNAL")" ]] || \
    die 'live stage 1 is not bound to this render, runtime-network contract, and transaction journal'
  [[ "$live_attempt" == "$(sed -n '1{s/^[^|]*|[^|]*|[^|]*|[^|]*|[^|]*|\([^|]*\).*/\1/p;}' "$KYVERNO_REPORT_ONLY_JOURNAL")" ]] || \
    die 'live stage 1 attempt identity does not match the private transaction journal'
  [[ "$installed_at" =~ ^[0-9]{10}$ ]] || \
    die 'live stage 1 carries no canonical install-started timestamp'
  minimum_age="$(lock_value stage.enforce.minimum-observation-seconds)"
  [[ "$minimum_age" =~ ^[0-9]+$ ]] || die 'render.lock carries no canonical stage-1 observation interval'
  now="$(date -u +%s)"
  age=$((now - installed_at))
  ((age >= minimum_age)) || \
    die "stage report-only has observed only ${age}s; the reviewed minimum is ${minimum_age}s"
  if ! available="$(KUBECTL -n kyverno get deployment \
      -l app.kubernetes.io/part-of=kyverno \
      -o 'jsonpath={range .items[*]}{.metadata.name}{"|"}{.metadata.generation}{"|"}{.status.observedGeneration}{"|"}{.spec.replicas}{"|"}{.status.updatedReplicas}{"|"}{.status.availableReplicas}{"\n"}{end}' 2>&1)"; then
    die 'cannot read the exact stage-1 controller rollout state'
  fi
  [[ -n "$available" ]] || \
    die 'stage report-only has not been applied: no Kyverno Deployment is present'
  expected_controllers="$(lock_value runtime.controllers.names)"
  actual_controllers="$(printf '%s\n' "$available" | sed '/^$/d;s/|.*//' | LC_ALL=C sort -u | paste -sd, -)"
  [[ "$actual_controllers" == "$expected_controllers" ]] || \
    die "stage report-only controller inventory is ${actual_controllers}; reviewed exact inventory is ${expected_controllers}"
  while IFS='|' read -r name generation observed_generation desired updated ready extra; do
    [[ -n "$name" ]] || continue
    [[ -z "${extra:-}" && "$generation" =~ ^[1-9][0-9]*$ && "$observed_generation" == "$generation" ]] || \
      die "stage report-only is not current: ${name} has generation ${generation}, observed ${observed_generation}"
    [[ "$desired" =~ ^[1-9][0-9]*$ && "$updated" == "$desired" && "$ready" == "$desired" ]] || \
      die "stage report-only is not ready: ${name} desired=${desired}, updated=${updated}, available=${ready}"
  done <<<"$available"

  local names=''
  names="$(lock_value inventory.cluster-scoped.names)"
  inventory=",${names},"
  local IFS=','
  for entry in $names; do
    [[ "${entry%%/*}" == 'ClusterPolicy' ]] || continue
    name="${entry#*/}"
    unset IFS
    # `.spec.validationFailureAction` is the DEPRECATED spec-level field, and
    # report-only/kustomization.yaml documents it as non-authoritative in as
    # many words: Kyverno prefers the rule's own `validate.failureAction`, so a
    # policy can read `Audit` at the spec level while every rule enforces.
    # Proving "the cluster is in report-only" from the deprecated field alone
    # would accept exactly that cluster. BOTH are read, and the rule-level one
    # is the one that decides.
    action="$(KUBECTL get clusterpolicy "$name" -o 'jsonpath={.spec.validationFailureAction}' 2>/dev/null || true)"
    [[ -n "$action" ]] || die "stage report-only did not install ClusterPolicy ${name}"
    [[ "$action" == 'Audit' ]] || \
      die "ClusterPolicy ${name} is already ${action}; the cluster is not in the report-only stage"
    # The third instance of the same class, and the one that mattered most: an
    # EMPTY answer here is legitimate (verifyImages rules carry no validate
    # block), so emptiness cannot be the refusal the way it is for the
    # spec-level read four lines above — which means a discarded status leaves
    # a timed-out or denied read indistinguishable from "every rule reports
    # Audit", and the gate would announce "evidence accepted" and promote to
    # fail-closed admission on a cluster it never actually read.
    if ! rule_actions="$(KUBECTL get clusterpolicy "$name" \
      -o 'jsonpath={range .spec.rules[*]}{.validate.failureAction}{"\n"}{end}' 2>&1)"; then
      die "cannot read ClusterPolicy ${name}'s authoritative rule actions (${rule_actions}); stage 1 is NOT proven to be what is running and enforcement must not be promoted on an unread cluster"
    fi
    while IFS= read -r rule_action; do
      # verifyImages rules carry no validate block at all, so an empty value is
      # the expected shape for them rather than a missing answer.
      [[ -n "$rule_action" ]] || continue
      [[ "$rule_action" == 'Audit' ]] || \
        die "ClusterPolicy ${name} has a rule whose authoritative validate.failureAction is ${rule_action}; the cluster is not in the report-only stage"
    done <<<"$rule_actions"
    IFS=','
  done
  unset IFS

  # A report is evidence only if it is a report ABOUT A POLICY THIS INSTALL
  # REVIEWED. Counting every report object in every namespace would accept a
  # stale artifact of something else entirely as proof that stage 1 evaluated
  # this policy set.
  if ! reports="$(KUBECTL get policyreports.wgpolicyk8s.io,clusterpolicyreports.wgpolicyk8s.io \
      --all-namespaces -o 'jsonpath={range .items[*]}{range .results[*]}{.policy}{"|"}{.timestamp.seconds}{"\n"}{end}{end}' 2>&1)"; then
    die 'cannot read timestamped report-only evidence'
  fi
  while IFS='|' read -r report_policy report_timestamp; do
    [[ -n "$report_policy" ]] || continue
    [[ "$inventory" == *",ClusterPolicy/${report_policy},"* ]] || continue
    [[ "$report_timestamp" =~ ^[0-9]+$ ]] || continue
    ((report_timestamp >= installed_at && report_timestamp <= now + 300)) || continue
    reviewed_reports=$((reviewed_reports + 1))
  done <<<"$reports"
  [[ "$reviewed_reports" -gt 0 ]] || \
    die 'stage report-only produced no fresh timestamped report naming a reviewed policy; enforcement would be promoted on stale or unmeasured blast radius'
  note "stage report-only evidence accepted (${reviewed_reports} fresh reviewed-policy result(s), ${age}s observation)"
}

# --- rollback ----------------------------------------------------------------

# Count the entries in one comma-separated reviewed name list.
#
# The two lists ARE the reviewed identity set, and their declared cardinalities
# are what make "the journal has N entries" equivalent to "the journal is the
# whole inventory". A lock whose list and count disagreed would let a SUBSET of
# the inventory satisfy the count check, so the lock is proven against itself
# before any journal is measured against it.
lock_name_count() {
  printf '%s' "$1" | tr ',' '\n' | grep -cE '.' || true
}

# Prove every identity in a journal is one this install DID create, BEFORE any
# delete runs.
#
# The journal is a plain text file that deliberately outlives the process, which
# makes it the one input to a privileged `kubectl delete` that something other
# than an apply can author. Reading it verbatim would turn `--rollback` into
# "delete whatever this file names on the bound cluster". Provenance is
# therefore proven rather than assumed, against the reviewed render inventory in
# BOTH scopes.
#
# THE NAMESPACE IS NOT AN IDENTITY. Binding cluster-scoped entries to
# `inventory.cluster-scoped.names` while accepting a namespaced entry on nothing
# but a phase-known kind plus `namespace == kyverno` is the substitution this
# check exists to refuse: `ServiceAccount|kyverno|default` and
# `ConfigMap|kyverno|kube-root-ca.crt` are a journalable kind in the admission
# namespace and are objects this transaction never created — the first is the
# namespace's own default identity and the second is the cluster's CA
# distribution point. Both were accepted, and `rollback_journal` deleted them.
# The membership test is therefore the exact `Kind/namespace/name` triple in
# `inventory.namespaced.names`, the same shape the journal itself records.
#
# CARDINALITY AND UNIQUENESS COMPLETE THE BINDING. Membership alone accepts a
# journal that names one reviewed identity, or the same one fifteen times: a
# short journal is a delete program someone truncated, and a repeated line is
# not a record this installer wrote (the writer emits each rendered document
# exactly once). Each entry must be distinct, and the total must equal the
# reviewed inventory — which, with membership, is exactly "the journal is a
# permutation of the reviewed inventory".
#
# The WHOLE journal is validated before the FIRST delete. Validating as we go
# would delete a valid prefix and only then discover the foreign entry — the
# rollback would be half-done and the refusal would arrive too late to matter.
#
# SCOPE IS A PROPERTY OF THE KIND, NEVER OF THE NAMESPACE FIELD.
#
# `kubectl` IGNORES `--namespace` for a root-scoped resource: `kubectl -n
# kyverno delete ClusterRole cluster-admin` issues the CLUSTER-SCOPED request
# and returns 0 with a warning. So a validator that concludes "this entry has a
# namespace, therefore it is bounded to the install namespace" is bypassed by
# writing a namespace beside a cluster-scoped kind — the entry takes the
# namespaced branch, the only check applied is `namespace == kyverno`, and the
# delete then reaches any cluster-scoped object of that kind, anywhere, outside
# the reviewed inventory entirely. The scope is therefore DERIVED from the kind
# and the journal is required to AGREE with it in both directions: a
# cluster-scoped kind must carry no namespace, and every other kind must carry
# one. `rollback_journal` dispatches on the same derivation, so the check and
# the delete cannot disagree.
validate_journal() {
  local journal="$1" line='' kind='' namespace='' name='' rest='' inventory=''
  local schema='' stage='' render_digest='' target_digest='' network_digest='' attempt_id=''
  local journalable='' namespaced_inventory='' identity='' seen=','
  local cluster_names='' namespaced_names='' expected_cluster='' expected_namespaced=''
  local expected_total=0
  cluster_names="$(lock_value inventory.cluster-scoped.names)"
  namespaced_names="$(lock_value inventory.namespaced.names)"
  expected_cluster="$(lock_value inventory.cluster-scoped)"
  expected_namespaced="$(lock_value inventory.namespaced)"
  [[ "$expected_cluster" =~ ^[0-9]+$ && "$expected_namespaced" =~ ^[0-9]+$ ]] || \
    die 'render.lock records no canonical inventory cardinality; no journal can be proven against it'
  [[ "$(lock_name_count "$cluster_names")" == "$expected_cluster" ]] || \
    die "render.lock's cluster-scoped inventory list and count disagree; the reviewed identity set is not readable and no journal can be proven against it"
  [[ "$(lock_name_count "$namespaced_names")" == "$expected_namespaced" ]] || \
    die "render.lock's namespaced inventory list and count disagree; the reviewed identity set is not readable and no journal can be proven against it"
  expected_total=$((expected_cluster + expected_namespaced))
  inventory=",${cluster_names},"
  namespaced_inventory=",${namespaced_names},"
  journalable="$(journalable_kinds)"
  local -a lines=()
  mapfile -t lines <"$journal"
  ((${#lines[@]} > 1)) || die "journal records no transaction: ${journal}"
  IFS='|' read -r schema stage render_digest target_digest network_digest attempt_id rest <<<"${lines[0]}"
  [[ -z "$rest" && "$schema" == '@transaction-v3' ]] || \
    die 'journal is not a bound transaction-v3 record; refusing without deleting anything'
  [[ "$attempt_id" =~ ^[0-9a-f]{64}$ ]] || \
    die 'journal carries no canonical attempt identity'
  ! grep -qE "^@rolled-back\|${attempt_id}$" "$journal" || \
    die 'journal attempt was already rolled back; replay is refused without deleting anything'
  [[ "$stage" =~ ^(report-only|enforce)$ ]] || die 'journal names no reviewed stage'
  [[ "$render_digest" == "$(lock_value "${stage}.sha256")" ]] || \
    die 'journal render digest does not match the current reviewed lock; refusing without deleting anything'
  [[ "$target_digest" == "$(digest_text "$KYVERNO_INSTALL_SERVER")" ]] || \
    die 'journal target digest does not match the explicitly bound operator target; refusing without deleting anything'
  [[ "$network_digest" == "$RUNTIME_NETWORK_DIGEST" ]] || \
    die 'journal runtime-network digest does not match the bound private contract'
  local index=0 entries=0
  for ((index = 1; index < ${#lines[@]}; index++)); do
    line="${lines[index]}"
    [[ -n "$line" ]] || continue
    IFS='|' read -r kind namespace name rest <<<"$line"
    [[ -z "$rest" ]] || \
      die "journal line $((index + 1)) is not kind|namespace|name: ${line}"
    [[ "$kind" =~ ^[A-Za-z][A-Za-z0-9]*$ ]] || \
      die "journal line $((index + 1)) names no kind: ${line}"
    [[ "$name" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || \
      die "journal line $((index + 1)) names no object: ${line}"
    # A kind no phase of this install applies is a kind no attempt of this
    # installer could have journaled, so it can only have been written by
    # something else. Derived from the phase table rather than restated, so the
    # writer and this reader cannot drift apart.
    [[ "$kind" =~ ^(${journalable})$ ]] || \
      die "journal line $((index + 1)) names ${kind}, which no phase of this install applies; refusing the entire rollback without deleting anything"
    if [[ "$kind" =~ ^(${CLUSTER_SCOPED_KINDS})$ ]]; then
      [[ -z "$namespace" ]] || \
        die "journal line $((index + 1)) gives cluster-scoped ${kind}/${name} the namespace ${namespace}; scope follows the KIND and kubectl ignores --namespace for a root-scoped object, so this entry would delete cluster-wide; refusing the entire rollback without deleting anything"
      [[ "$inventory" == *",${kind}/${name},"* ]] || \
        die "journal names cluster-scoped ${kind}/${name}, which render.lock's reviewed inventory does not contain; refusing the entire rollback without deleting anything"
      identity="${kind}/${name}"
    else
      [[ -n "$namespace" ]] || \
        die "journal line $((index + 1)) names namespaced ${kind} ${name} with no namespace; refusing the entire rollback without deleting anything"
      [[ "$namespace" == "$INSTALL_NAMESPACE" ]] || \
        die "journal names ${kind} ${namespace}/${name} outside the ${INSTALL_NAMESPACE} namespace; refusing the entire rollback without deleting anything"
      # The namespace is a bound, never an identity: every object this
      # transaction creates lives here, and so does everything the namespace and
      # the control plane created for themselves.
      [[ "$namespaced_inventory" == *",${kind}/${namespace}/${name},"* ]] || \
        die "journal names namespaced ${kind} ${namespace}/${name}, which render.lock's reviewed inventory does not contain; a same-namespace identity this install never created is not a rollback target; refusing the entire rollback without deleting anything"
      identity="${kind}/${namespace}/${name}"
    fi
    [[ "$seen" != *",${identity},"* ]] || \
      die "journal line $((index + 1)) repeats ${identity}; the writer records each rendered object exactly once, so a repeated identity is not a record this installer wrote; refusing the entire rollback without deleting anything"
    seen="${seen}${identity},"
    entries=$((entries + 1))
  done
  ((entries > 0)) || die "journal records no object: ${journal}"
  # Membership plus uniqueness plus this equality is exactly "the journal is a
  # permutation of the reviewed inventory". Without it a journal naming one
  # reviewed identity is a valid delete program, and a truncated journal would
  # leave the rest of the install standing while reporting a complete rollback.
  ((entries == expected_total)) || \
    die "journal records ${entries} identity(ies); render.lock's reviewed inventory is ${expected_total} (${expected_cluster} cluster-scoped, ${expected_namespaced} namespaced); a journal that is not the COMPLETE reviewed inventory is not the record of an attempt of this transaction; refusing the entire rollback without deleting anything"
  note "journal validated: ${entries} identity(ies), the complete reviewed inventory exactly once each and at the scope its kind declares"
}

# Remove exactly what an attempt created, in reverse order, and nothing else.
# Every identity is checked against render.lock's reviewed inventory (and, for
# namespaced objects, against the admission namespace) by validate_journal
# above before a single delete is issued — the journal is untrusted input, not a
# trusted record, because the file can be edited by anything that can write to
# its path. Kyverno's self-registered webhook configurations are not in the
# journal (the controller writes them at runtime), so they are swept separately
# by the reviewed names and by label — after the journal has been proven.
rollback_journal() {
  local journal="$1" line='' kind='' namespace='' name='' journal_stage='' attempt_id=''
  [[ -f "$journal" ]] || die "journal does not exist: ${journal}"
  validate_journal "$journal"
  journal_stage="$(sed -n '1{s/^[^|]*|\([^|]*\).*/\1/p;}' "$journal")"
  attempt_id="$(sed -n '1{s/^[^|]*|[^|]*|[^|]*|[^|]*|[^|]*|\([^|]*\).*/\1/p;}' "$journal")"
  [[ "$journal_stage" == 'report-only' ]] || \
    die 'an enforce journal records a promotion over existing objects and must never be used as a delete program; use --demote'
  remove_runtime_webhooks || \
    die 'rollback could not remove every reviewed runtime webhook; controller objects were left in place and admission is NOT proven clear'
  local -a entries=()
  mapfile -t entries <"$journal"
  local index=0
  for ((index = ${#entries[@]} - 1; index >= 0; index--)); do
    line="${entries[index]}"
    [[ -n "$line" && "$line" != @transaction-v3\|* ]] || continue
    IFS='|' read -r kind namespace name <<<"$line"
    # Dispatch on the KIND, exactly as validate_journal derived the scope it
    # accepted. Dispatching on the namespace FIELD instead would let the two
    # disagree, and `kubectl` resolves that disagreement in the dangerous
    # direction: it ignores --namespace for a root-scoped object.
    if [[ "$kind" =~ ^(${CLUSTER_SCOPED_KINDS})$ ]]; then
      KUBECTL delete "$kind" "$name" --ignore-not-found --wait=false >/dev/null || \
        die "rollback could not remove ${kind}/${name}"
    else
      KUBECTL -n "$namespace" delete "$kind" "$name" --ignore-not-found --wait=false >/dev/null || \
        die "rollback could not remove ${kind} ${namespace}/${name}"
    fi
  done
  prove_no_residue
  printf '@rolled-back|%s\n' "$attempt_id" >>"$journal" || \
    die 'rollback completed but the private journal could not be marked consumed; preserve it and do not replay'
  note "rollback complete: $((${#entries[@]} - 1)) journaled object(s) removed"
}

remove_runtime_webhooks() {
  local kind='' names='' name='' failures=0
  for kind in validating mutating; do
    names="$(lock_value "runtime.webhooks.${kind}")"
    local IFS=','
    for name in $names; do
      if ! KUBECTL delete "${kind}webhookconfiguration" "$name" --ignore-not-found --wait=false >/dev/null; then
        printf 'install-kyverno-admission: failed to delete reviewed %swebhookconfiguration/%s\n' "$kind" "$name" >&2
        failures=$((failures + 1))
      fi
    done
    unset IFS
    if ! KUBECTL delete "${kind}webhookconfiguration" -l "$(lock_value runtime.webhooks.label)" \
        --ignore-not-found --wait=false >/dev/null; then
      printf 'install-kyverno-admission: failed to delete %swebhookconfiguration label backstop\n' "$kind" >&2
      failures=$((failures + 1))
    fi
  done
  ((failures == 0))
}

# The webhook configurations are the piece of residue that keeps REFUSING WRITES
# after the controller behind them is gone, so their absence is proven for every
# path that claims to have removed them — including break-glass, whose whole
# promise is that the API server has stopped calling admission. A best-effort
# sweep that reports success without checking is an unproven emergency action.
#
# AN UNREADABLE CLUSTER IS NOT A CLEAN CLUSTER. Reading with `2>/dev/null` and
# `|| true` discards kubectl's exit status twice, so a FAILED read — a denied
# RBAC rule, an API timeout, a torn-down kubeconfig, which are exactly the
# conditions break-glass runs under — produced an empty stream, `grep -c`
# printed 0, and the proof concluded "clean" while fail-closed webhooks stayed
# registered. The read's own status is captured and a failure REFUSES, with a
# message that says "not proven" rather than "clean". The namespace probe below
# has always had this shape; these two now match it.
prove_no_webhook_residue() {
  local remedy="$1" kind='' short_kind='' names='' name='' state='' remaining='' listing=''
  for short_kind in validating mutating; do
    kind="${short_kind}webhookconfiguration"
    names="$(lock_value "runtime.webhooks.${short_kind}")"
    local IFS=','
    for name in $names; do
      if state="$(KUBECTL get "$kind" "$name" -o name 2>&1)"; then
        die "residue: reviewed ${kind}/${name} remains; ${remedy}"
      fi
      [[ "$state" == *'not found'* || "$state" == *'NotFound'* ]] || \
        die "cannot prove reviewed ${kind}/${name} absent; admission is NOT proven clear; ${remedy}"
    done
    unset IFS
    if ! listing="$(KUBECTL get "$kind" -o name 2>&1)"; then
      die "cannot prove ${kind} residue: reading them failed (${listing}); admission is NOT proven clear; ${remedy}"
    fi
    remaining="$(printf '%s\n' "$listing" | grep -c 'kyverno' || true)"
    [[ "$remaining" -eq 0 ]] || \
      die "residue: ${remaining} Kyverno ${kind} object(s) remain; ${remedy}"
  done
}

# A rollback that does not prove the cluster is clean is a hope, not a rollback.
prove_no_residue() {
  local remaining='' listing=''
  prove_no_webhook_residue 'run --break-glass'
  if ! listing="$(KUBECTL get customresourcedefinition -o name 2>&1)"; then
    die "cannot prove CRD residue: reading the custom resource definitions failed (${listing}); the rollback is NOT proven complete"
  fi
  remaining="$(printf '%s\n' "$listing" | grep -c '\.kyverno\.io$' || true)"
  [[ "$remaining" -eq 0 ]] || die "residue: ${remaining} kyverno.io CRD(s) remain"
  remaining="$(KUBECTL get namespace kyverno -o name 2>&1 || true)"
  [[ "$remaining" == *'not found'* ]] || die 'residue: the kyverno namespace remains'
  note 'residue probe clean: no Kyverno webhook configuration, CRD, or namespace remains'
}

# A controller Deployment is not allowed to start until a disposable Pod with
# the exact admission-controller ServiceAccount and selector labels has proven
# DNS plus TCP connectivity to `kubernetes.default.svc:443` under the effective
# NetworkPolicies. The image is an independently reviewed digest pin; the Pod
# carries no credential and is deleted with a proven absence before the
# controller phase proceeds.
#
# THE NUMERIC USER IS NOT DECORATION. `runAsNonRoot: true` is not a request to
# pick a non-root user; it is a REFUSAL to start a container that resolves to
# UID 0. The effective UID comes from the container's `runAsUser`, then the
# Pod's, then the image's own OCI `User` — and `CANARY_IMAGE_PATTERN` above
# constrains this image to `registry.k8s.io/e2e-test-images/agnhost`, whose
# config declares no non-root user. With `runAsNonRoot` alone the kubelet
# therefore resolves root and refuses the container AFTER the API server
# admitted the Pod, so the failure arrives as a canary that never reaches
# Succeeded — reported as "the network path is broken" by the wait below, on a
# cluster whose network path is fine. The transaction then rolls back a healthy
# install for a reason nothing in its output names. The explicit non-zero
# `runAsUser`/`runAsGroup` are what make the canary's own result readable:
# 10001 matches the reviewed admission-controller security context in
# kubernetes/platform/admission/kyverno/controllers.yaml, and `/agnhost` is a
# world-executable static binary that needs no particular identity to dial TCP.
run_pre_controller_network_canary() {
  local canary_image='' manifest="${WORK}/network-canary.yaml" phase=''
  canary_image="$(pinned_version KYVERNO_NETWORK_CANARY_IMAGE)"
  cat >"$manifest" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kyverno-network-canary
  namespace: kyverno
  labels:
    app.kubernetes.io/name: kyverno
    app.kubernetes.io/component: admission-controller
    app.kubernetes.io/part-of: kyverno
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  serviceAccountName: kyverno-admission-controller
  dnsPolicy: ClusterFirst
  containers:
    - name: network-canary
      image: ${canary_image}
      imagePullPolicy: IfNotPresent
      command: [/agnhost, connect, --timeout=10s, kubernetes.default.svc:443]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        seccompProfile: {type: RuntimeDefault}
      resources:
        requests: {cpu: 5m, memory: 16Mi}
        limits: {cpu: 25m, memory: 32Mi}
EOF
  CANARY_ACTIVE='yes'
  KUBECTL create -f "$manifest" >/dev/null || transaction_failed 'pre-controller network canary create'
  KUBECTL -n kyverno wait --for=jsonpath='{.status.phase}'=Succeeded \
    pod/kyverno-network-canary --timeout=60s >/dev/null || \
    transaction_failed 'pre-controller network canary DNS/API path'
  KUBECTL -n kyverno delete pod kyverno-network-canary --wait=true --timeout=60s >/dev/null || \
    transaction_failed 'pre-controller network canary cleanup'
  if phase="$(KUBECTL -n kyverno get pod kyverno-network-canary -o name 2>&1)"; then
    transaction_failed 'pre-controller network canary residue'
  fi
  [[ "$phase" == *'not found'* || "$phase" == *'NotFound'* ]] || \
    transaction_failed 'pre-controller network canary cleanup could not be proven'
  CANARY_ACTIVE=''
  note 'pre-controller canary passed: exact ServiceAccount/labels resolved DNS and reached kubernetes.default.svc:443 under the effective NetworkPolicies'
}

# --- modes -------------------------------------------------------------------

WORK=''
cleanup() {
  local status=$?
  [[ -z "$WORK" ]] || rm -rf -- "$WORK"
  exit "$status"
}
trap cleanup EXIT

if [[ "$MODE" == '--break-glass' ]]; then
  # The fastest correct action when the cluster has started refusing writes:
  # remove the webhook configurations and nothing else. The controllers, the
  # policies, and the namespace all stay, so the state is diagnosable afterwards
  # — but the API server stops calling out, and writes resume immediately.
  bind_tools
  # IDENTITY only: break-glass applies no NetworkPolicy, so demanding an IPv4
  # server here would let a substitution constraint it does not use refuse the
  # emergency path at exactly the moment the cluster is refusing writes.
  bind_target_identity
  remove_runtime_webhooks || \
    die 'break-glass could not delete every reviewed runtime webhook; admission is NOT proven clear'
  # The deletions above are best-effort by design (a partial sweep must not stop
  # the rest), so success is a PROVEN absence, never an assumed one.
  prove_no_webhook_residue 'break-glass did NOT clear admission; the API server may still be refusing writes — see the raw commands in docs/runbooks/kyverno-install.md'
  note 'break-glass complete: Kyverno webhook configurations removed; the API server no longer calls admission'
  note 'the controllers and policies remain installed and inert; diagnose before re-registering'
  exit 0
fi

if [[ "$MODE" == '--rollback' ]]; then
  bind_tools
  bind_target
  bind_runtime_network_contract
  cross_check_runtime_network_contract
  rollback_journal "$JOURNAL"
  exit 0
fi

# Stage 2 creates nothing: it re-applies the same objects with two fields
# changed. Its undo is therefore the reverse promotion, not a deletion — the
# report-only bytes go back over the live install and the webhook is fail-open
# again within one apply. Deleting the installation to revert a policy-action
# change would be a far larger act than the change being reverted.
demote_to_report_only() {
  local rendered="${WORK}/report-only.demote.yaml"
  local bound="${WORK}/report-only.demote.bound.yaml"
  render_stage report-only "$rendered"
  verify_lock report-only "$rendered"
  verify_stage_actions report-only "$rendered"
  # The substitution replaces a CIDR and nothing else, so re-verifying the
  # bound file here would be a guard no input can trip — deliberately not added.
  # What proves this path applies the FAIL-OPEN bytes is behavioural: the suite
  # reads the policy-action lines of the file the demotion actually sent.
  substitute_runtime_network "$rendered" "$bound"
  KUBECTL apply -f "$bound" >/dev/null || \
    die 'demotion to report-only failed; run --break-glass to stop the API server calling admission'
  note 'demoted to stage report-only: the webhook is fail-open and the policies report again'
}

if [[ "$MODE" == '--demote' ]]; then
  bind_tools
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/kyverno-admission.XXXXXX")"
  bind_target
  bind_runtime_network_contract
  cross_check_runtime_network_contract
  demote_to_report_only
  exit 0
fi

bind_tools
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kyverno-admission.XXXXXX")"
RENDERED="${WORK}/${STAGE}.yaml"
render_stage "$STAGE" "$RENDERED"

if [[ "$MODE" == '--render' ]]; then
  # The lock-regeneration path. It deliberately requires no pins and no cluster:
  # its whole job is to report what the working tree renders to, so a reviewer
  # can commit those values.
  printf 'render.tool.version=%s\n' "$("$KUSTOMIZE_BIN" version | head -n1 | tr -d '[:space:]')"
  printf '%s.sha256=%s\n' "$STAGE" "$(digest_of "$RENDERED")"
  printf '%s.objects=%s\n' "$STAGE" "$(object_count "$RENDERED")"
  exit 0
fi

verify_lock "$STAGE" "$RENDERED"
verify_stage_actions "$STAGE" "$RENDERED"
verify_exclusions "$RENDERED"
bind_pins
verify_images "$RENDERED"
bind_target
bind_runtime_network_contract
cross_check_runtime_network_contract

SUBSTITUTED="${WORK}/${STAGE}.bound.yaml"
substitute_runtime_network "$RENDERED" "$SUBSTITUTED"

DOCUMENTS="${WORK}/documents"
split_render "$SUBSTITUTED" "$DOCUMENTS"

# Classify every document into exactly one phase and journal its identity. An
# unclassified kind stops here rather than being applied in whatever order the
# renderer happened to emit it.
# Only --apply may write the operator's record. A --plan mutates nothing on the
# cluster and must not truncate the journal of an earlier attempt either: a plan
# that silently rewrote that file would hand the next --rollback a delete
# program the operator never authored.
[[ "$MODE" == '--apply' ]] || JOURNAL="${WORK}/journal"
# Created narrow: the record of what a privileged apply touched is not
# world-writable, and the next --rollback reads it as its delete program.
ATTEMPT_ID="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$ATTEMPT_ID" =~ ^[0-9a-f]{64}$ ]] || die 'could not create a canonical transaction attempt identity'
(umask 077; printf '@transaction-v3|%s|%s|%s|%s|%s\n' \
  "$STAGE" "$(lock_value "${STAGE}.sha256")" \
  "$(digest_text "$KYVERNO_INSTALL_SERVER")" "$RUNTIME_NETWORK_DIGEST" \
  "$ATTEMPT_ID" >"$JOURNAL")
for phase in "${PHASE_NAMES[@]}"; do
  : >"${WORK}/phase-${phase}.yaml"
done
for document in "$DOCUMENTS"/*.yaml; do
  kind="$(document_field "$document" kind)"
  [[ -n "$kind" ]] || die "a rendered document declares no kind"
  name="$(document_metadata "$document" name)"
  namespace="$(document_metadata "$document" namespace)"
  [[ -n "$name" ]] || die "a rendered ${kind} declares no name"
  case "$kind" in
    Secret) die 'the render contains a Secret; this install carries no credential' ;;
  esac
  if [[ "$kind" =~ ^(${FORBIDDEN_KINDS})$ ]]; then
    die "the render declares ${kind} ${name}; webhook registration is the controller's act after the health wait, never an operator apply"
  fi
  matched=''
  for phase in "${PHASE_NAMES[@]}"; do
    if [[ "$kind" =~ ^($(phase_kinds "$phase"))$ ]]; then
      matched="$phase"
      break
    fi
  done
  [[ -n "$matched" ]] || die "render contains an unclassified kind: ${kind}; its install ordering is undecided"
  if [[ "$kind" =~ ^(${CLUSTER_SCOPED_KINDS})$ ]]; then
    printf '%s|%s|%s\n' "$kind" '' "$name" >>"$JOURNAL"
  else
    [[ -n "$namespace" ]] || die "namespaced ${kind} ${name} declares no namespace"
    printf '%s|%s|%s\n' "$kind" "$namespace" "$name" >>"$JOURNAL"
  fi
  printf -- '---\n' >>"${WORK}/phase-${matched}.yaml"
  cat -- "$document" >>"${WORK}/phase-${matched}.yaml"
done

journaled="$(grep -cE '^[A-Za-z][A-Za-z0-9]*\|' "$JOURNAL" || true)"
[[ "$journaled" -eq "$(object_count "$RENDERED")" ]] || \
  die "journaled ${journaled} identities for $(object_count "$RENDERED") rendered objects"
cluster_scoped="$(grep -cE "^(${CLUSTER_SCOPED_KINDS})\|\|" "$JOURNAL" || true)"
[[ "$cluster_scoped" -eq "$(lock_value inventory.cluster-scoped)" ]] || \
  die "render has ${cluster_scoped} cluster-scoped objects; render.lock records $(lock_value inventory.cluster-scoped)"

# The built-in bytes are validatable before a fresh cluster knows the Kyverno
# GVKs. ClusterPolicy documents are deliberately excluded here: kubectl maps a
# custom kind through discovery even for client dry-run, so validating them now
# would make the zero-CRD starting state fail before the transaction could
# install the CRD that teaches discovery about them (#101/C3).
BUILTIN_VALIDATION="${WORK}/builtins.yaml"
: >"$BUILTIN_VALIDATION"
for phase in "${PHASE_NAMES[@]}"; do
  [[ "$phase" == 'policies' ]] && continue
  cat -- "${WORK}/phase-${phase}.yaml" >>"$BUILTIN_VALIDATION"
done
client_validation="${WORK}/dry-run-client-builtins.txt"
if ! KUBECTL apply -f "$BUILTIN_VALIDATION" --dry-run=client --validate=strict \
    >"$client_validation" 2>&1; then
  cat -- "$client_validation" >&2
  die 'client-side strict validation failed for built-in install objects'
fi
note "client-side strict validation clean for built-in install objects ($(grep -cE '.' "$client_validation" || true) objects)"

# The two stages ask opposite questions of the cluster, and asking the wrong one
# would refuse the very promotion this design requires. Stage 1 CREATES: nothing
# it installs may already exist. Stage 2 PROMOTES: everything it touches must
# already exist, in the report-only shape, healthy, and reporting.
if [[ "$STAGE" == 'enforce' ]]; then
  require_report_only_evidence
else
  probe_absence
fi

if [[ "$MODE" == '--plan' ]]; then
  note 'PLAN only; no mutation attempted'
  note "phases in order: ${PHASE_NAMES[*]}"
  exit 0
fi

# --- the transaction ---------------------------------------------------------

APPLIED=''
CANARY_ACTIVE=''
INSTALL_STARTED_UNIX="$(date -u +%s)"
# A transaction that only handles its own failures is not interrupt-safe: Ctrl-C,
# a TERM from a supervisor, or a closed SSH session between two phases leaves a
# half-installed cluster with nothing that knows to undo it. The EXIT trap above
# only sweeps the work directory. These handlers roll the attempt back, and when
# the rollback cannot PROVE it finished they say RECOVERY REQUIRED and name the
# journal rather than exiting quietly on an unproven state.
on_interrupt() {
  local signal="$1"
  trap - INT TERM HUP
  printf 'install-kyverno-admission: received SIG%s during the transaction\n' "$signal" >&2
  if [[ -n "$CANARY_ACTIVE" ]]; then
    KUBECTL -n kyverno delete pod kyverno-network-canary --ignore-not-found --wait=false >/dev/null || true
  fi
  # Stage 1 created objects, so reverse its bound journal. Stage 2 only
  # re-applied existing objects, so deleting that same inventory would turn an
  # interrupted promotion into a platform uninstall. Its only valid undo is a
  # demotion to the report-only bytes. Each runs in a subshell with the EXIT
  # trap detached so a `die` remains observable here.
  if [[ "$STAGE" == 'enforce' ]]; then
    if (trap - EXIT; demote_to_report_only); then
      printf 'install-kyverno-admission: interrupted promotion demoted to report-only; no installed object was deleted\n' >&2
      exit 1
    fi
  elif (trap - EXIT; rollback_journal "$JOURNAL"); then
    printf 'install-kyverno-admission: interrupted attempt rolled back; the cluster is as it was\n' >&2
    exit 1
  fi
  printf 'install-kyverno-admission: RECOVERY REQUIRED: the interrupted attempt could not be proven rolled back; the journal at %s is the record — re-run --rollback --journal %s, then --break-glass if writes are failing\n' \
    "$JOURNAL" "$JOURNAL" >&2
  exit 1
}

transaction_failed() {
  printf 'install-kyverno-admission: phase %s failed; rolling back\n' "$1" >&2
  if [[ -n "$CANARY_ACTIVE" ]]; then
    KUBECTL -n kyverno delete pod kyverno-network-canary --ignore-not-found --wait=false >/dev/null || true
  fi
  if [[ "$STAGE" == 'enforce' ]]; then
    if (trap - EXIT; demote_to_report_only); then
      exit 1
    fi
    printf 'install-kyverno-admission: RECOVERY REQUIRED: promotion failed and report-only demotion could not be proven; run --break-glass if writes are failing\n' >&2
    exit 1
  fi
  if (trap - EXIT; rollback_journal "$JOURNAL"); then
    exit 1
  fi
  printf 'install-kyverno-admission: RECOVERY REQUIRED: failed attempt could not be proven rolled back; re-run --rollback --journal %s, then --break-glass if writes are failing\n' "$JOURNAL" >&2
  exit 1
}

trap 'on_interrupt INT' INT
trap 'on_interrupt TERM' TERM
trap 'on_interrupt HUP' HUP

for phase in "${PHASE_NAMES[@]}"; do
  file="${WORK}/phase-${phase}.yaml"
  grep -qE '^kind:[[:space:]]' "$file" || continue
  if [[ "$phase" == 'policies' ]]; then
    # Every kubectl invocation is a fresh process, so discovery is refreshed
    # after the CRD Established wait above. Only now can strict validation map
    # ClusterPolicy on a genuinely fresh cluster. A plan cannot mutate the
    # cluster to reach this state and therefore validates the built-in prefix;
    # policy schema/engine validation remains an independent repository gate.
    policy_validation="${WORK}/dry-run-client-policies.txt"
    if ! KUBECTL apply -f "$file" --dry-run=client --validate=strict \
        >"$policy_validation" 2>&1; then
      cat -- "$policy_validation" >&2
      transaction_failed 'policies (strict validation after CRD establishment)'
    fi
    note "policy validation clean after refreshed CRD discovery ($(grep -cE '.' "$policy_validation" || true) objects)"
  fi
  note "applying phase ${phase}"
  KUBECTL apply -f "$file" >/dev/null || transaction_failed "$phase"
  APPLIED="${APPLIED}${phase} "
  if [[ "$phase" == 'crds' ]]; then
    # A fresh cluster cannot server-validate Kyverno policies until their CRDs
    # exist and are Established. This phase contains CRDs only; every dependent
    # object is applied later.
    KUBECTL wait --for=condition=Established crd/clusterpolicies.kyverno.io --timeout=120s >/dev/null || \
      transaction_failed 'crds (policy CRD never established)'
    note 'Kyverno policy CRD is Established before any dependent object'
  fi
  if [[ "$phase" == 'controller-prerequisites' && "$STAGE" == 'report-only' ]]; then
    run_pre_controller_network_canary
  fi
  if [[ "$phase" == 'controller' ]]; then
    # The ordering guarantee, made executable: the controllers are Available and
    # the policy CRD is Established BEFORE any policy exists to trigger webhook
    # registration. The namespace already has its allows, so this wait can
    # actually complete — a wait placed before the network phase could not.
    KUBECTL -n kyverno wait --for=condition=Available deployment \
      -l app.kubernetes.io/part-of=kyverno --timeout=300s >/dev/null || \
      transaction_failed 'controller (no Deployment became Available)'
    note 'controllers Available after the CRD and network-canary gates'
  fi
done

if [[ "$STAGE" == 'report-only' ]]; then
  KUBECTL annotate namespace kyverno --overwrite \
    "platform.snaraj.dev/install-render-sha256=$(lock_value report-only.sha256)" \
    "platform.snaraj.dev/install-network-sha256=${RUNTIME_NETWORK_DIGEST}" \
    "platform.snaraj.dev/install-journal-sha256=$(digest_of "$JOURNAL")" \
    "platform.snaraj.dev/install-attempt-id=${ATTEMPT_ID}" \
    "platform.snaraj.dev/install-started-unix=${INSTALL_STARTED_UNIX}" >/dev/null || \
    transaction_failed 'stage-1 evidence binding'
  note 'stage-1 evidence bound to the exact render, runtime-network contract, and private transaction journal'
fi

note "applied phases: ${APPLIED% }"
note "journal: ${JOURNAL}"
case "$STAGE" in
  report-only)
    note 'stage report-only installed: policies report, the webhook cannot block'
    note 'collect report evidence, then promote with --stage enforce (see the runbook)'
    ;;
  enforce)
    note 'stage enforce installed: the admission webhook is now fail-closed'
    note 'break-glass if writes start failing: --break-glass'
    ;;
esac
