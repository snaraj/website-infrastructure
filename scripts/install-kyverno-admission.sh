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
#   ORDERING          Phases run namespace, bounds, network, controller, then
#                     policies. The exact egress/ingress allows are in place and
#                     the controllers are Available BEFORE any policy exists to
#                     trigger webhook registration. No step waits on health that
#                     an earlier step made impossible — specifically, the
#                     namespace is never closed without its allows, because the
#                     deny and the allows are one apply. There is no webhook
#                     phase at all: registration belongs to the controller.
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
#                     in the render at all. Rollback then proves zero residue.
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
#
# See docs/runbooks/kyverno-install.md for the surrounding ceremony, the
# stage-1 to stage-2 promotion gate, and the break-glass procedure.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
INSTALL_ROOT='kubernetes/platform/admission-install'
LOCK_FILE="${REPO_ROOT}/${INSTALL_ROOT}/render.lock"
VERSIONS_FILE="${REPO_ROOT}/versions.env"

# The pins this install is bound to. They are platform-lane values and this
# script never invents them: their absence is the reason an apply is refused
# today, and stating them by name is how the ask is made unambiguous.
REQUIRED_PINS=(
  KYVERNO_VERSION
  KYVERNO_CHART_VERSION
  KYVERNO_ADMISSION_CONTROLLER_IMAGE
  KYVERNO_REPORTS_CONTROLLER_IMAGE
  KYVERNO_KYVERNOPRE_IMAGE
)
PIN_IMAGE_KEYS=(
  KYVERNO_ADMISSION_CONTROLLER_IMAGE
  KYVERNO_REPORTS_CONTROLLER_IMAGE
  KYVERNO_KYVERNOPRE_IMAGE
)
# Only the official Kyverno registry, only a full digest, and never the all-zero
# sentinel that the staged controller manifest deliberately carries.
PIN_IMAGE_PATTERN='^reg\.kyverno\.io/kyverno/[a-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$'
ZERO_DIGEST='sha256:0000000000000000000000000000000000000000000000000000000000000000'

# The fail-closed destination the committed NetworkPolicies carry: RFC 5737
# TEST-NET-1 can never match anything real, so the bytes in Git grant nothing.
SENTINEL_CIDR='192.0.2.0/32'
# Each occurrence is one reviewed flow: API-server ingress to the webhook port,
# and controller egress to the API server. A different count means the reviewed
# network shape changed and this substitution was not re-derived.
SENTINEL_OCCURRENCES=2

# Ordered install phases, by kind. A kind that appears in the render and in no
# phase stops the install: an unclassified object is an object whose ordering
# nobody decided, and ordering is the whole point of this script.
PHASE_NAMES=(namespace bounds network controller policies)
declare -A PHASE_KINDS=(
  [namespace]='Namespace'
  [bounds]='ResourceQuota|LimitRange'
  [network]='NetworkPolicy'
  [controller]='CustomResourceDefinition|ConfigMap|ServiceAccount|ClusterRole|ClusterRoleBinding|Role|RoleBinding|Service|Deployment|PodDisruptionBudget|PriorityClass'
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
    # The journal is the only record of what this attempt created, and it has to
    # outlive the process: an apply that dies between phases must still be
    # undoable by hand. A temporary path would be swept by the exit trap exactly
    # when it is needed most.
    [[ -n "$JOURNAL" ]] || die '--apply requires --journal <file> so the transaction record survives the process'
    [[ ! -s "$JOURNAL" ]] || die "journal already records an attempt: ${JOURNAL}"
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

digest_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum <"$1" | cut -d' ' -f1
  else
    shasum -a 256 <"$1" | cut -d' ' -f1
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

  KUBECTL_BIN="$(resolved_tool kubectl)"
  expected="$(pinned_version KUBERNETES_VERSION)"
  actual="$("$KUBECTL_BIN" version --client --output=json 2>/dev/null |
    sed -n 's/.*"gitVersion": *"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$actual" ]] || die 'kubectl did not report a client version'
  [[ "$actual" == "$expected" ]] || \
    die "kubectl is ${actual}; versions.env pins ${expected}"
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
    [[ "$value" =~ $PIN_IMAGE_PATTERN ]] || \
      die "${key} is not an official Kyverno image at a full digest: ${value}"
    case "$value" in
      *"@${ZERO_DIGEST}") die "${key} still carries the all-zero sentinel digest" ;;
    esac
    PIN_IMAGES+=("$value")
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
bind_target() {
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

  # The reviewed server value is also the only source for the NetworkPolicy
  # destination, so the address is never typed, never guessed, and never
  # diverges from the cluster actually being installed into.
  local host=''
  host="${server#*://}"
  host="${host%%:*}"
  host="${host#[}"
  host="${host%]}"
  [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || \
    die "the reviewed server must name an IPv4 address, not ${host}; a name cannot be turned into a NetworkPolicy destination"
  APISERVER_CIDR="${host}/32"
}

KUBECTL() {
  "$KUBECTL_BIN" --kubeconfig "${KUBECONFIG}" --context "${KYVERNO_INSTALL_CONTEXT}" \
    --server "${KYVERNO_INSTALL_SERVER}" "$@"
}

# Replace the fail-closed sentinel with the bound API server. Applying a render
# in which the sentinel survives would close the namespace against an address
# that matches nothing, which is the ordering deadlock this design exists to
# prevent — so its survival is fatal, not a warning.
substitute_endpoint() {
  local source="$1" destination="$2" found=''
  found="$(grep -cF "$SENTINEL_CIDR" "$source" || true)"
  [[ "$found" -eq "$SENTINEL_OCCURRENCES" ]] || \
    die "render carries ${found} sentinel destinations; the reviewed network shape has ${SENTINEL_OCCURRENCES}"
  sed "s#${SENTINEL_CIDR}#${APISERVER_CIDR}#g" "$source" >"$destination"
  ! grep -qF "$SENTINEL_CIDR" "$destination" || \
    die 'the fail-closed sentinel destination survived substitution'
  found="$(grep -cF "$APISERVER_CIDR" "$destination" || true)"
  [[ "$found" -eq "$SENTINEL_OCCURRENCES" ]] || \
    die "substituted render carries ${found} API-server destinations; expected ${SENTINEL_OCCURRENCES}"
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
    if KUBECTL get "$kind" "$name" -o name >/dev/null 2>&1; then
      die "${kind}/${name} already exists; refusing to adopt a foreign object"
    fi
  done
  note 'pre-apply absence probe clean: nothing this install creates already exists'
}

# --- stage gate --------------------------------------------------------------

# Stage 2 is not reachable from an empty cluster. The evidence demanded here is
# the evidence stage 1 exists to produce: controllers that came up, policies
# that loaded, and reports that prove the engine actually evaluated traffic.
require_report_only_evidence() {
  local available='' entry='' name='' action='' reports=''
  available="$(KUBECTL -n kyverno get deployment -l app.kubernetes.io/part-of=kyverno \
    -o 'jsonpath={range .items[*]}{.metadata.name}={.status.availableReplicas}{"\n"}{end}' 2>/dev/null || true)"
  [[ -n "$available" ]] || \
    die 'stage report-only has not been applied: no Kyverno Deployment is present'
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    [[ "${entry#*=}" =~ ^[1-9][0-9]*$ ]] || \
      die "stage report-only is not healthy: ${entry%%=*} has no available replica"
  done <<<"$available"

  local names=''
  names="$(lock_value inventory.cluster-scoped.names)"
  local IFS=','
  for entry in $names; do
    [[ "${entry%%/*}" == 'ClusterPolicy' ]] || continue
    name="${entry#*/}"
    action="$(KUBECTL get clusterpolicy "$name" -o 'jsonpath={.spec.validationFailureAction}' 2>/dev/null || true)"
    [[ -n "$action" ]] || die "stage report-only did not install ClusterPolicy ${name}"
    [[ "$action" == 'Audit' ]] || \
      die "ClusterPolicy ${name} is already ${action}; the cluster is not in the report-only stage"
  done
  unset IFS

  reports="$(KUBECTL get policyreports.wgpolicyk8s.io,clusterpolicyreports.wgpolicyk8s.io \
    --all-namespaces -o name 2>/dev/null | grep -c . || true)"
  [[ "$reports" -gt 0 ]] || \
    die 'stage report-only produced no policy report; enforcement would be promoted on unmeasured blast radius'
  note "stage report-only evidence accepted (${reports} policy report object(s))"
}

# --- rollback ----------------------------------------------------------------

# Remove exactly what an attempt created, in reverse order, and nothing else.
# Every identity comes from the journal, which was written from the render's own
# metadata after the absence probe proved none of it pre-existed — so a delete
# here can never reach a foreign object. Kyverno's self-registered webhook
# configurations are not in the journal (the controller writes them at runtime),
# so they are swept separately by the reviewed names and by label.
rollback_journal() {
  local journal="$1" line='' kind='' namespace='' name=''
  [[ -f "$journal" ]] || die "journal does not exist: ${journal}"
  remove_runtime_webhooks
  local -a entries=()
  mapfile -t entries <"$journal"
  local index=0
  for ((index = ${#entries[@]} - 1; index >= 0; index--)); do
    line="${entries[index]}"
    [[ -n "$line" ]] || continue
    IFS='|' read -r kind namespace name <<<"$line"
    if [[ -n "$namespace" ]]; then
      KUBECTL -n "$namespace" delete "$kind" "$name" --ignore-not-found --wait=false >/dev/null || \
        die "rollback could not remove ${kind} ${namespace}/${name}"
    else
      KUBECTL delete "$kind" "$name" --ignore-not-found --wait=false >/dev/null || \
        die "rollback could not remove ${kind}/${name}"
    fi
  done
  prove_no_residue
  note "rollback complete: ${#entries[@]} journaled object(s) removed"
}

remove_runtime_webhooks() {
  local kind='' names='' name=''
  for kind in validating mutating; do
    names="$(lock_value "runtime.webhooks.${kind}")"
    local IFS=','
    for name in $names; do
      KUBECTL delete "${kind}webhookconfiguration" "$name" --ignore-not-found --wait=false >/dev/null || true
    done
    unset IFS
    KUBECTL delete "${kind}webhookconfiguration" -l "$(lock_value runtime.webhooks.label)" \
      --ignore-not-found --wait=false >/dev/null || true
  done
}

# A rollback that does not prove the cluster is clean is a hope, not a rollback.
prove_no_residue() {
  local kind='' remaining=''
  for kind in validatingwebhookconfiguration mutatingwebhookconfiguration; do
    remaining="$(KUBECTL get "$kind" -o name 2>/dev/null | grep -c 'kyverno' || true)"
    [[ "$remaining" -eq 0 ]] || \
      die "residue: ${remaining} Kyverno ${kind} object(s) remain; run --break-glass"
  done
  remaining="$(KUBECTL get customresourcedefinition -o name 2>/dev/null | grep -c '\.kyverno\.io$' || true)"
  [[ "$remaining" -eq 0 ]] || die "residue: ${remaining} kyverno.io CRD(s) remain"
  remaining="$(KUBECTL get namespace kyverno -o name 2>&1 || true)"
  [[ "$remaining" == *'not found'* ]] || die 'residue: the kyverno namespace remains'
  note 'residue probe clean: no Kyverno webhook configuration, CRD, or namespace remains'
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
  bind_target
  remove_runtime_webhooks
  note 'break-glass complete: Kyverno webhook configurations removed; the API server no longer calls admission'
  note 'the controllers and policies remain installed and inert; diagnose before re-registering'
  exit 0
fi

if [[ "$MODE" == '--rollback' ]]; then
  bind_tools
  bind_target
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
  substitute_endpoint "$rendered" "$bound"
  KUBECTL apply -f "$bound" >/dev/null || \
    die 'demotion to report-only failed; run --break-glass to stop the API server calling admission'
  note 'demoted to stage report-only: the webhook is fail-open and the policies report again'
}

if [[ "$MODE" == '--demote' ]]; then
  bind_tools
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/kyverno-admission.XXXXXX")"
  bind_target
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

SUBSTITUTED="${WORK}/${STAGE}.bound.yaml"
substitute_endpoint "$RENDERED" "$SUBSTITUTED"

DOCUMENTS="${WORK}/documents"
split_render "$SUBSTITUTED" "$DOCUMENTS"

# Classify every document into exactly one phase and journal its identity. An
# unclassified kind stops here rather than being applied in whatever order the
# renderer happened to emit it.
JOURNAL="${JOURNAL:-${WORK}/journal}"
: >"$JOURNAL"
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

journaled="$(grep -cE '.' "$JOURNAL" || true)"
[[ "$journaled" -eq "$(object_count "$RENDERED")" ]] || \
  die "journaled ${journaled} identities for $(object_count "$RENDERED") rendered objects"
cluster_scoped="$(grep -cE "^(${CLUSTER_SCOPED_KINDS})\|\|" "$JOURNAL" || true)"
[[ "$cluster_scoped" -eq "$(lock_value inventory.cluster-scoped)" ]] || \
  die "render has ${cluster_scoped} cluster-scoped objects; render.lock records $(lock_value inventory.cluster-scoped)"

# The bytes must be valid to apply at all, independently of any namespace.
# Client-side strict validation rejects unknown and duplicated fields and needs
# nothing to exist on the cluster, so it covers every object on a fresh install.
client_validation="${WORK}/dry-run-client.txt"
if ! KUBECTL apply -f "$SUBSTITUTED" --dry-run=client --validate=strict \
    >"$client_validation" 2>&1; then
  cat -- "$client_validation" >&2
  die 'client-side strict validation failed; the render is not valid to apply'
fi
note "client-side strict validation clean ($(grep -cE '.' "$client_validation" || true) objects)"

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
transaction_failed() {
  printf 'install-kyverno-admission: phase %s failed; rolling back\n' "$1" >&2
  if [[ "$STAGE" == 'enforce' ]]; then
    demote_to_report_only || true
  else
    rollback_journal "$JOURNAL" || true
  fi
  exit 1
}

for phase in "${PHASE_NAMES[@]}"; do
  file="${WORK}/phase-${phase}.yaml"
  grep -qE '^kind:[[:space:]]' "$file" || continue
  note "applying phase ${phase}"
  KUBECTL apply -f "$file" >/dev/null || transaction_failed "$phase"
  APPLIED="${APPLIED}${phase} "
  if [[ "$phase" == 'controller' ]]; then
    # The ordering guarantee, made executable: the controllers are Available and
    # the policy CRD is Established BEFORE any policy exists to trigger webhook
    # registration. The namespace already has its allows, so this wait can
    # actually complete — a wait placed before the network phase could not.
    KUBECTL wait --for=condition=Established crd/clusterpolicies.kyverno.io --timeout=120s >/dev/null || \
      transaction_failed 'controller (policy CRD never established)'
    KUBECTL -n kyverno wait --for=condition=Available deployment \
      -l app.kubernetes.io/part-of=kyverno --timeout=300s >/dev/null || \
      transaction_failed 'controller (no Deployment became Available)'
    note 'controllers Available and the policy CRD is Established'
  fi
done

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
