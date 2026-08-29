#!/usr/bin/env bash
# Install the reviewed Flux controllers, and nothing else.
#
# Why this exists as its own entry point: bootstrap/flux/bootstrap.sh owns the
# secret-bearing and sync-applying ceremonies and stays code-blocked until the
# reviewed-blob launcher exists. The controllers-only install needs none of
# that machinery — no age identity, no Secret, and no Flux custom resource —
# but every live mode necessarily reads the protected client credential in its
# explicit kubeconfig. It was authorized as a separate,
# inert-by-construction step. Encoding that step here, with its guardrails
# executable and reviewable, is strictly better than performing it as an ad-hoc
# command outside the repository.
#
# Three properties this script owns, each of which a runbook sentence alone
# could not deliver:
#
#   ORDERING. The reviewed controller bundle carries `allow-egress` patched to
#   podSelector {} + policyTypes [Ingress, Egress] with no rules, which on a
#   NetworkPolicy-enforcing CNI is a namespace-wide deny-all. Creating that
#   together with the three controller Deployments isolates the controllers at
#   the instant they are created: no DNS, no API server, no leader election, no
#   cache sync, so they can never become ready and the install deadlocks. The
#   creation transaction is therefore ORDERED — the namespace, CRDs, RBAC and Services first, then
#   the startup egress allows (default-deny, DNS, the intra-namespace artifact
#   fetch, and the API server bound to the very endpoint this run targets), and
#   an ephemeral, digest-pinned Pod using source-controller's labels and Service
#   Account proves DNS plus an authenticated request through
#   kubernetes.default.svc, is deleted and absence-proven, and only then are the
#   Deployments created. Public HTTPS stays shut until every positive desired
#   replica is current, updated, available and ready with none unavailable;
#   --open-public-egress is that separate step.
#
#   BINDING. Nothing here runs against "whatever is on PATH" or "whatever the
#   ambient kubeconfig points at". kustomize and kubectl are copied into the
#   private work directory and checked against the versions.env executable
#   SHA-256 pins BEFORE either copy is invoked; the render must come from a Git
#   checkout at an ASSERTED commit with no uncommitted modification to any
#   install input; all three rendered artifacts -- controller, egress, and
#   canary -- must hash to the sha256s the reviewer signed off; and
#   every single API operation carries an explicit --kubeconfig/--context/
#   --server whose context is proven to resolve to exactly that server first.
#   Binding only the controller render was not enough: the egress bundle is the
#   SECURITY half of what this script creates, and an unasserted digest over it
#   meant a commit could widen an allow while reproducing the reviewed
#   controller digest exactly.
#
#   TRANSACTION. A multi-object `kubectl create -f` is not atomic: a failure part-way leaves a
#   created prefix, and 18 of this bundle's objects are non-namespaced (8 CRDs,
#   6 ClusterRoles, 4 ClusterRoleBindings) which no `delete namespace` can
#   remove. --apply therefore installs onto a FRESH cluster only. That is the
#   scope in which the transaction is honest. Every object is created with an
#   unpredictable per-attempt annotation and create-only semantics, so a
#   same-name race can never be overwritten or mistaken for this attempt. Undo
#   captures the matching UID/resourceVersion and sends a DeleteOptions request
#   carrying both preconditions; a response-loss lookup or delete can therefore
#   never remove a concurrent replacement.
#   An apply over an EXISTING install would instead rewrite objects as
#   `configured` -- a mutation with no recorded prestate, which no ledger of
#   creations can undo and which would make the rollback report "the cluster is
#   unchanged" after rewriting 27 objects. Rather than claim a restore this
#   script cannot perform, the existing-install path is refused for --apply and
#   stays available read-only through --plan. A signal (INT/TERM/HUP) takes the
#   same rollback path a failed phase takes, because a Ctrl-C between phases
#   would otherwise leave exactly the cluster-scoped residue the ledger exists
#   to prevent.
#
# The offline guards refuse BEFORE contacting the cluster. The pre-apply gate
# then makes only read-only, non-mutating calls -- an existence and ownership
# probe of the objects the install creates, a client-side strict validation, and
# a server-side dry run -- and classifies their output fail-closed for both a
# fresh cluster (flux-system absent) and a reconcile of an existing one. See the
# gate below and docs/runbooks/flux-install.md. Nothing mutates until --apply.
#
#   --render  render, verify, and print all three render sha256s; no cluster contact
#   --plan    the same, plus the read-only pre-apply gate; no mutation
#   --apply   the same checks, then the ordered, attempt-bound create transaction (fresh only)
#   --open-public-egress  the deferred public-HTTPS allow, once every controller
#                         replica is current/updated/available/ready and the
#                         namespace still reconciles nothing
#
# --plan, --apply and --open-public-egress ALL require every binding:
#   --kubeconfig PATH --context NAME --server https://ADDRESS:6443
#   --cni-provider calico --api-endpoint ADDRESS [--api-endpoint ADDRESS ...]
#   --expect-render-sha256 HEX --expect-egress-sha256 HEX
#   --expect-canary-sha256 HEX --expect-commit HEX
#
# PRESTATE, stated here because a reader who opens only this file would
# otherwise infer a green field from the word "install": a STOCK upstream Flux
# v2.9.3 render is ALREADY live on the cluster, applied outside this ceremony,
# still carrying the cluster-admin cluster-reconciler binding, the blanket
# allow-egress rule, and warn-only Pod Security. --apply is fresh-install-only
# and WILL refuse that cluster; that refusal is the designed behaviour, not an
# obstacle. Converging the live install is an owner decision documented in the
# runbook's "Converging the existing install"; this script performs neither
# option.
#
# See docs/runbooks/flux-install.md for the surrounding ceremony.
set -euo pipefail
# Every byte this script writes -- the render, the address-substituted egress
# bundle, the attempt ledger -- is operator-private, so the work directory and
# everything in it is created unreadable to anyone else from the first syscall.
umask 077

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
# The install target is a constant, never an argument. Applying the parent root
# would create the GitRepository and both per-site Kustomizations from
# gotk-sync.yaml; none is suspended, so reconciliation of
# ./kubernetes/websites/naranjo-online and ./kubernetes/websites/lidersea-com
# would begin immediately. Making that unreachable is the single most important
# thing this script does.
INSTALL_TARGET='kubernetes/flux-system/controllers'
# The fail-closed egress overlay. Split by this script into the startup allows
# the controllers need in order to start at all, and the public-HTTPS allow that
# stays shut until they are observed healthy.
EGRESS_TARGET='kubernetes/flux-system/egress'
CANARY_TARGET='kubernetes/flux-system/canary'
VERSIONS_FILE="${REPO_ROOT}/versions.env"
INSTALL_NAMESPACE='flux-system'
# The reviewed inventory after the least-privilege RBAC patches: 1 Namespace,
# 8 CRDs, 6 ClusterRoles, 4 ClusterRoleBindings, 3 NetworkPolicies,
# 1 ResourceQuota, 3 ServiceAccounts,
# 1 Service, 3 Deployments. A render of a different size is not the reviewed
# install no matter what its digest says.
#
# The ClusterRole count went 3 -> 6 and the binding count 1 -> 4 with issue #98:
# the shared crd-controller ClusterRole no longer carries any Flux API group,
# and the three per-controller replacements are created HERE, by this
# transaction, because this transaction is what removes the authority they
# replace. Rendering them from kubernetes/flux-system/access.yaml instead would
# install three controllers that cannot watch their own custom resources.
EXPECTED_OBJECTS=30
# The inventory splits by scope, which is what the fresh-cluster dry run below
# turns on: 19 cluster-scoped objects (the Namespace, 8 CRDs, 6 ClusterRoles,
# 4 ClusterRoleBindings) plus 11 objects that live IN flux-system (1
# ResourceQuota, 3 ServiceAccounts, 1 Service, 3 Deployments, 3 NetworkPolicies).
EXPECTED_CLUSTER_SCOPED=19
EXPECTED_NAMESPACED=11
# ... and it splits again by creation phase: the 3 controller Deployments are held
# back until their egress allows and canary proof exist, so 27 objects go first.
EXPECTED_WORKLOADS=3
EXPECTED_PREREQUISITES=27
# The egress overlay: 5 policies, of which 4 must be in force before any
# controller Pod is created and 1 (public HTTPS) is deliberately deferred.
EXPECTED_EGRESS_POLICIES=5
EXPECTED_STARTUP_POLICIES=4
STARTUP_EGRESS_POLICIES=(
  default-deny
  flux-controllers-dns
  flux-controllers-artifacts
  flux-controllers-kube-apiserver
)
PUBLIC_EGRESS_POLICY='flux-controllers-public-https'
# The cluster-scoped names, needed to prove nothing the install creates already
# exists on a fresh cluster and that nothing it would touch on an existing one
# belongs to somebody else. Declared here as the REVIEWED set and cross-checked
# against the render below, so a drift between the two is a hard failure rather
# than a silently narrower probe.
FLUX_CRDS=(
  buckets.source.toolkit.fluxcd.io
  externalartifacts.source.toolkit.fluxcd.io
  gitrepositories.source.toolkit.fluxcd.io
  helmcharts.source.toolkit.fluxcd.io
  helmreleases.helm.toolkit.fluxcd.io
  helmrepositories.source.toolkit.fluxcd.io
  kustomizations.kustomize.toolkit.fluxcd.io
  ocirepositories.source.toolkit.fluxcd.io
)
# The three per-controller entries are authored (issue #98), not generated: they
# replace the Flux-group authority the crd-controller-role patch removes, and
# they are listed here so the absence probe, the ownership check and the
# rollback contract all cover them exactly like the generated three.
FLUX_CLUSTER_ROLES=(
  crd-controller-flux-system
  crd-controller-helm-flux-system
  crd-controller-kustomize-flux-system
  crd-controller-source-flux-system
  flux-edit-flux-system
  flux-view-flux-system
)
FLUX_CLUSTER_ROLE_BINDINGS=(
  crd-controller-flux-system
  crd-controller-helm-flux-system
  crd-controller-kustomize-flux-system
  crd-controller-source-flux-system
)
CONTROLLER_DEPLOYMENTS=(source-controller kustomize-controller helm-controller)
# The least-privilege render labels every one of its 30 objects with both of these.
# They are this install's ownership marker: an object that already exists and
# carries them is a previous run of THIS install; one that exists without them
# belongs to something else and is never adopted, reconfigured, or deleted.
OWNERSHIP_PART_OF='"app.kubernetes.io/part-of":"flux"'
OWNERSHIP_INSTANCE='"app.kubernetes.io/instance":"flux-system"'
# RFC 5737 TEST-NET-1: the committed API-server destination, which can never
# match a real endpoint. The real endpoint SET is never committed and is not
# inferred from the operator's kubeconfig. Repeated --api-endpoint inputs bind
# the selected Calico post-DNAT destinations, and the in-Pod Service canary is
# the proof that those destinations actually reach this cluster's API.
APISERVER_SENTINEL_CIDR='192.0.2.0/32'
APISERVER_PORT=6443
SUPPORTED_CNI_PROVIDER='calico'
MAX_API_ENDPOINTS=16
CANARY_NAME='flux-api-reachability-canary'
ATTEMPT_ANNOTATION='platform.snaraj.dev/install-attempt-id'

# Recognized dry-run report lines. kubectl prints "<kind>/<name> <verb>" per
# object, optionally suffixed " (dry run)" (client) or " (server dry run)"
# (server). CRDs are bounded to the fluxcd toolkit group; every other kind to
# the reviewed controller inventory; verbs to the three non-mutating outcomes.
_dry_suffix='( \((server )?dry run\))?'
_apply_verb='(created|configured|unchanged)'
_cluster_scoped_kind='(namespace/flux-system|customresourcedefinition\.apiextensions\.k8s\.io/[a-z0-9.-]+\.fluxcd\.io|clusterrole\.rbac\.authorization\.k8s\.io/[a-z0-9-]+|clusterrolebinding\.rbac\.authorization\.k8s\.io/[a-z0-9-]+)'
_namespaced_kind='(networkpolicy\.networking\.k8s\.io/[a-z0-9-]+|resourcequota/[a-z0-9-]+|serviceaccount/[a-z0-9-]+|service/[a-z0-9-]+|deployment\.apps/[a-z0-9-]+)'
# A fresh cluster's cluster-scoped objects must report exactly "created": a
# "configured"/"unchanged" there means something already exists, which the
# absence probe should already have refused.
CLUSTER_SCOPED_CREATED_LINE="^${_cluster_scoped_kind} created${_dry_suffix}\$"
# Any reviewed object reporting any non-mutating verb: the shape of a clean
# client validation and of an existing-cluster server dry run.
INVENTORY_MUTATION_LINE="^(${_cluster_scoped_kind}|${_namespaced_kind}) ${_apply_verb}${_dry_suffix}\$"
# The EXPECTED fresh-cluster error on each of the 11 namespaced children: the
# server dry run does not persist the dry-run Namespace (k8s #83562), so it has
# nowhere to place them. Bounded to flux-system -- any other namespace, or any
# other error, is a genuine failure.
NS_NOT_FOUND_LINE='^Error from server \(NotFound\): error when creating "[^"]*": namespaces "flux-system" not found$'

die() {
  printf 'install-flux-controllers: %s\n' "$*" >&2
  exit 1
}

note() {
  printf 'install-flux-controllers: %s\n' "$*"
}

warn() {
  printf 'install-flux-controllers: %s\n' "$*" >&2
}

usage() {
  printf '%s\n' \
    'Usage: scripts/install-flux-controllers.sh MODE [binding options]' \
    '' \
    'Modes:' \
    '  --render  render + verify + print all three render sha256s; contacts no cluster' \
    '  --plan    the same, plus the read-only pre-apply gate; no mutation' \
    '  --apply   the same checks, then the ordered, attempt-bound create transaction (fresh only)' \
    '  --open-public-egress  the deferred public-HTTPS allow, once every desired replica is ready' \
    '' \
    'Binding options -- ALL are required by --plan, --apply, and' \
    '--open-public-egress alike, and all are optional for --render, which' \
    'asserts whichever of the three digests it is given:' \
    '  --kubeconfig PATH   the protected kubeconfig; never the ambient default' \
    '  --context NAME      the reviewed context; proven to resolve to --server' \
    '  --server URL        https://ADDRESS:6443 for operator API calls only' \
    '  --cni-provider NAME must be calico; binds the selected post-DNAT contract' \
    '  --api-endpoint IP   actual API backend; repeat for an HA endpoint set' \
    '  --expect-render-sha256 HEX   the reviewed controller render digest' \
    '  --expect-egress-sha256 HEX   the reviewed egress overlay render digest' \
    '  --expect-canary-sha256 HEX   the reviewed ephemeral Pod render digest' \
    '  --expect-commit HEX          the reviewed commit this must run from'
}

MODE=''
KUBECONFIG_PATH=''
KUBE_CONTEXT=''
KUBE_SERVER=''
EXPECT_RENDER_SHA256=''
EXPECT_EGRESS_SHA256=''
EXPECT_CANARY_SHA256=''
EXPECT_COMMIT=''
CNI_PROVIDER=''
API_ENDPOINTS=()

require_value() {
  # "$1" is the option name, "$2" the count of remaining arguments.
  (($2 >= 2)) || die "${1} requires a value"
}

while (($#)); do
  case "$1" in
    --render|--plan|--apply|--open-public-egress)
      [[ -z "$MODE" ]] || die 'only one mode argument is accepted'
      MODE="$1"
      shift
      ;;
    --kubeconfig)
      require_value "$1" "$#"
      KUBECONFIG_PATH="$2"
      shift 2
      ;;
    --context)
      require_value "$1" "$#"
      KUBE_CONTEXT="$2"
      shift 2
      ;;
    --server)
      require_value "$1" "$#"
      KUBE_SERVER="$2"
      shift 2
      ;;
    --cni-provider)
      require_value "$1" "$#"
      CNI_PROVIDER="$2"
      shift 2
      ;;
    --api-endpoint)
      require_value "$1" "$#"
      API_ENDPOINTS+=("$2")
      shift 2
      ;;
    --expect-render-sha256)
      require_value "$1" "$#"
      EXPECT_RENDER_SHA256="$2"
      shift 2
      ;;
    --expect-egress-sha256)
      require_value "$1" "$#"
      EXPECT_EGRESS_SHA256="$2"
      shift 2
      ;;
    --expect-canary-sha256)
      require_value "$1" "$#"
      EXPECT_CANARY_SHA256="$2"
      shift 2
      ;;
    --expect-commit)
      require_value "$1" "$#"
      EXPECT_COMMIT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done
[[ -n "$MODE" ]] || die 'a mode is required: --render, --plan, --apply, or --open-public-egress'

needs_cluster='yes'
if [[ "$MODE" == '--render' ]]; then
  needs_cluster='no'
fi

# Every binding a cluster-touching mode needs is demanded here, before a single
# byte is rendered: an operator who forgot one learns it immediately, and no
# mode can reach an API call with a binding still unset.
if [[ "$needs_cluster" == 'yes' ]]; then
  [[ -n "$KUBECONFIG_PATH" ]] || die '--kubeconfig is required; the install never uses the ambient default kubeconfig'
  [[ -n "$KUBE_CONTEXT" ]] || die '--context is required; the install never uses the ambient current context'
  [[ -n "$KUBE_SERVER" ]] || die '--server is required; the install never uses the context default server'
  [[ -n "$CNI_PROVIDER" ]] || die '--cni-provider is required; the API destination semantics must name the selected CNI'
  [[ "$CNI_PROVIDER" == "$SUPPORTED_CNI_PROVIDER" ]] || \
    die "--cni-provider ${CNI_PROVIDER} has no reviewed API-destination contract; only ${SUPPORTED_CNI_PROVIDER} is supported"
  ((${#API_ENDPOINTS[@]} > 0)) || die '--api-endpoint is required; the API backend set is never inferred from the operator kubeconfig'
  ((${#API_ENDPOINTS[@]} <= MAX_API_ENDPOINTS)) || \
    die "the API backend set has ${#API_ENDPOINTS[@]} entries; the reviewed maximum is ${MAX_API_ENDPOINTS}"
  [[ -n "$EXPECT_RENDER_SHA256" ]] || die '--expect-render-sha256 is required; an unasserted render digest binds nothing'
  # The egress overlay is the security half of what this script applies, and
  # --open-public-egress applies nothing else. A digest that covered only the
  # controller bundle left those bytes unbound: a commit could reproduce the
  # reviewed controller digest exactly while widening an allow.
  [[ -n "$EXPECT_EGRESS_SHA256" ]] || die '--expect-egress-sha256 is required; the egress bytes this applies would otherwise be unasserted'
  [[ -n "$EXPECT_CANARY_SHA256" ]] || die '--expect-canary-sha256 is required; the pre-controller executable probe would otherwise be unreviewed'
  # ... and a digest binds OUTPUT, not the program that produced it. The commit
  # is what binds this script, its constants, and its guards to the reviewed
  # ones.
  [[ -n "$EXPECT_COMMIT" ]] || die '--expect-commit is required; a render digest binds the bytes rendered, not the installer that rendered them'
fi

normalize_ipv4() {
  local candidate="$1"
  local -a octets=()
  local octet=''
  local value=0
  IFS='.' read -r -a octets <<<"$candidate"
  ((${#octets[@]} == 4)) || return 1
  local -a normalized_octets=()
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    value=$((10#$octet))
    ((value <= 255)) || return 1
    normalized_octets+=("$value")
  done
  ((normalized_octets[0] > 0 && normalized_octets[0] < 224 \
     && normalized_octets[0] != 127)) || return 1
  printf '%s.%s.%s.%s' "${normalized_octets[@]}"
}

if [[ "$needs_cluster" == 'yes' ]]; then
  normalized_endpoints=()
  for endpoint in "${API_ENDPOINTS[@]}"; do
    canonical_endpoint=''
    canonical_endpoint="$(normalize_ipv4 "$endpoint")" || \
      die "--api-endpoint ${endpoint} is not one canonical unicast IPv4 address"
    normalized_endpoints+=("$canonical_endpoint")
  done
  mapfile -t API_ENDPOINTS < <(printf '%s\n' "${normalized_endpoints[@]}" | LC_ALL=C sort -u)
  ((${#API_ENDPOINTS[@]} == ${#normalized_endpoints[@]})) || \
    die '--api-endpoint values must be unique; duplicate backends do not define a set'
fi

# --- Tool identity -----------------------------------------------------------
#
# Codex demonstrated the gap this closes: a fake `kubectl` earlier on PATH
# produced a full accepted dry-run inventory, an accepted apply, and a clean exit --
# "Flux is installed and inert" -- with no cluster involved at all. `command -v`
# proves a name resolves to something; it proves nothing about what that
# something is. The pins in versions.env are the repository's answer to "which
# tool", so they are the answer used here.

digest_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum <"$1" | cut -d' ' -f1
  else
    shasum -a 256 <"$1" | cut -d' ' -f1
  fi
}

# Create the private directory before resolving a downloaded executable. The
# selected binary is copied once, the copy is hashed, and only that copy is ever
# invoked. Hashing one pathname and later executing the mutable source pathname
# would leave a replacement race between the proof and the execution.
work="$(mktemp -d "${TMPDIR:-/tmp}/flux-controllers.XXXXXX")"
cleanup() {
  local status=$?
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT

# versions.env is parsed as DATA, never sourced: sourcing a file to learn a
# version string would execute whatever else it contained.
pin_value() {
  local key="$1"
  local line=''
  line="$(grep -E "^${key}=" -- "$VERSIONS_FILE" | tail -n 1 || true)"
  [[ -n "$line" ]] || die "versions.env carries no ${key} pin"
  printf '%s' "${line#*=}"
}

resolve_tool() {
  local tool="$1"
  local path=''
  path="$(command -v -- "$tool" 2>/dev/null)" || die "${tool} is required"
  [[ -n "$path" && -f "$path" && -x "$path" ]] || \
    die "${tool} does not resolve to an executable regular file"
  printf '%s' "$path"
}

stage_tool() {
  local tool="$1"
  local source="$2"
  local directory="${work}/tools/${tool}"
  local destination=''
  mkdir -p -- "$directory"
  destination="${directory}/$(basename -- "$source")"
  cp -- "$source" "$destination"
  chmod 0500 -- "$destination"
  [[ -f "$destination" && ! -L "$destination" && -x "$destination" ]] || \
    die "the private ${tool} copy is not an executable regular file"
  printf '%s' "$destination"
}

[[ -f "$VERSIONS_FILE" ]] || die 'versions.env is missing; the tool pins cannot be read'

KUSTOMIZE_BIN="$(stage_tool kustomize "$(resolve_tool kustomize)")"
kustomize_digest_pin="$(pin_value KUSTOMIZE_LINUX_AMD64_SHA256)"
[[ "$kustomize_digest_pin" =~ ^[0-9a-f]{64}$ ]] || \
  die 'versions.env carries no valid KUSTOMIZE_LINUX_AMD64_SHA256 pin'
kustomize_digest="$(digest_of "$KUSTOMIZE_BIN")"
[[ "$kustomize_digest" == "$kustomize_digest_pin" ]] || \
  die 'the kustomize executable sha256 does not match versions.env KUSTOMIZE_LINUX_AMD64_SHA256; refusing to execute unidentified bytes beside a protected kubeconfig'
kustomize_pin="$(pin_value KUSTOMIZE_VERSION)"
kustomize_reported="$("$KUSTOMIZE_BIN" version 2>/dev/null | head -n 1 | tr -d '[:space:]' || true)"
[[ "$kustomize_reported" == "$kustomize_pin" ]] || \
  die "the kustomize resolved from PATH reports '${kustomize_reported}'; versions.env pins ${kustomize_pin}"

if [[ "$needs_cluster" == 'yes' ]]; then
  KUBECTL_BIN="$(stage_tool kubectl "$(resolve_tool kubectl)")"
  kubectl_digest="$(digest_of "$KUBECTL_BIN")"
  kubectl_digest_matched='no'
  for pin_key in KUBECTL_LINUX_AMD64_SHA256 KUBECTL_ARM64_SHA256; do
    if [[ "$kubectl_digest" == "$(pin_value "$pin_key")" ]]; then
      kubectl_digest_matched='yes'
    fi
  done
  [[ "$kubectl_digest_matched" == 'yes' ]] || \
    die 'the kubectl resolved from PATH matches no versions.env kubectl digest pin; refusing to run an unidentified binary against a cluster'
  kubectl_pin="$(pin_value KUBERNETES_VERSION)"
  kubectl_reported="$("$KUBECTL_BIN" version --client -o yaml 2>/dev/null \
    | grep -E '^[[:space:]]*gitVersion:' | head -n 1 | tr -d '[:space:]' || true)"
  kubectl_reported="${kubectl_reported#gitVersion:}"
  [[ "$kubectl_reported" == "$kubectl_pin" ]] || \
    die "the kubectl resolved from PATH reports '${kubectl_reported}'; versions.env pins ${kubectl_pin}"
fi

# --- Repository bytes --------------------------------------------------------
#
# "The reviewed commit" has to mean something executable. A checkout that is not
# a Git checkout, or one whose install inputs carry uncommitted edits, cannot be
# the reviewed bytes no matter what the render hashes to.

GIT_BIN="$(resolve_tool git)"
source_commit=''
source_commit="$("$GIT_BIN" -C "$REPO_ROOT" rev-parse --verify HEAD 2>/dev/null)" || \
  die 'the install must run from a Git checkout of the reviewed commit'
# Printing the commit told the operator which commit ran; it did not stop the
# wrong one from running. Asserting it does, and it is the only binding that
# covers this script itself -- the render digests bind the manifests, not the
# guards that read them.
if [[ -n "$EXPECT_COMMIT" && "$source_commit" != "$EXPECT_COMMIT" ]]; then
  die "the checkout is at commit ${source_commit}, not the reviewed ${EXPECT_COMMIT}; the installer and its guards are not the reviewed ones"
fi
dirty_inputs=''
dirty_inputs="$("$GIT_BIN" -C "$REPO_ROOT" status --porcelain -- \
  "$INSTALL_TARGET" "$EGRESS_TARGET" "$CANARY_TARGET" versions.env scripts/install-flux-controllers.sh)"
if [[ -n "$dirty_inputs" ]]; then
  printf '%s\n' "$dirty_inputs" >&2
  die 'the install inputs carry uncommitted modifications; the render would not be the reviewed bytes'
fi

[[ -f "${REPO_ROOT}/${INSTALL_TARGET}/kustomization.yaml" ]] || \
  die "missing install root: ${INSTALL_TARGET}"
[[ -f "${REPO_ROOT}/${EGRESS_TARGET}/kustomization.yaml" ]] || \
  die "missing egress overlay root: ${EGRESS_TARGET}"
[[ -f "${REPO_ROOT}/${CANARY_TARGET}/kustomization.yaml" ]] || \
  die "missing API canary root: ${CANARY_TARGET}"

# An INTERRUPT is not a clean stop. A Ctrl-C, a terminal hangup, or a `kill`
# during the transaction leaves everything the completed phases created -- including
# the Namespace and all 18 non-namespaced RBAC/CRD objects -- with
# nothing to remove them and no list of what to remove by hand. That is exactly
# the residue the ledger exists to prevent, so the signal runs the SAME rollback
# path a failed phase runs. Two hazards it must survive: arriving before any
# mutation (the transaction is not open, so there is nothing to undo and saying so
# is the whole job), and arriving twice (the second must not restart a rollback
# that is already in flight).
TRANSACTION_OPEN='no'
TRANSACTION_COMMITTED='no'
INTERRUPT_HANDLED='no'
# A stable duplicate of the real stderr. Bash defers a trap until the running
# foreground command finishes, and the creates run through the kube() SHELL
# FUNCTION with `>"$output" 2>&1` on the call -- so a handler that fires there
# inherits that redirection and writes its rollback report into a file inside
# $work, which the EXIT trap then deletes. The operator would see an interrupt,
# no report, and full residue. Reporting through this saved descriptor is what
# makes the rollback report reach the terminal from anywhere in the script.
exec 9>&2
on_signal() {
  local signal="$1"
  if [[ "$INTERRUPT_HANDLED" == 'yes' ]]; then
    warn "SIG${signal} arrived while the first interrupt was still being handled; ignoring it" 2>&9
    return 0
  fi
  INTERRUPT_HANDLED='yes'
  # Disarm before doing anything slow, so a repeat signal cannot re-enter.
  trap - INT TERM HUP
  {
    warn "interrupted by SIG${signal}; an in-flight create may already have persisted objects"
    if [[ "$TRANSACTION_OPEN" == 'yes' ]]; then
      rollback || true
    elif [[ "$TRANSACTION_COMMITTED" == 'yes' ]]; then
      warn 'rollback: the mutation was already committed; no transaction remains open'
    else
      warn 'rollback: the interrupt arrived before any mutation; the cluster is unchanged'
    fi
  } 2>&9
  exit 1
}
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP' HUP

rendered="${work}/controllers.yaml"
"$KUSTOMIZE_BIN" build "${REPO_ROOT}/${INSTALL_TARGET}" >"$rendered"
[[ -s "$rendered" ]] || die 'render produced no bytes'

# An inert install contains no Flux custom resource. A GitRepository,
# Kustomization, HelmRelease, OCIRepository, or image-automation object in this
# render would mean applying it starts reconciling something.
if grep -Eq '^kind:[[:space:]]*(GitRepository|Kustomization|HelmRelease|HelmChart|HelmRepository|OCIRepository|Bucket|ImageRepository|ImagePolicy|ImageUpdateAutomation|Receiver|Alert|Provider)[[:space:]]*$' "$rendered"; then
  die 'render contains a Flux custom resource; this install must reconcile nothing'
fi
if grep -Eq '^kind:[[:space:]]*Secret[[:space:]]*$' "$rendered"; then
  die 'render contains a Secret; the controller install carries no credential'
fi
# The blanket egress the Flux CLI generates must already be gone: a render that
# still carries an egress rule would open every flux-system Pod to every
# destination the moment it is applied.
if grep -Eq '^[[:space:]]+egress:[[:space:]]*$' "$rendered"; then
  die 'render still carries an egress rule; the allow-egress patch is not applied'
fi
# Pod Security must be enforced, not merely warned about.
if ! grep -Eq '^[[:space:]]+pod-security\.kubernetes\.io/enforce:[[:space:]]*restricted[[:space:]]*$' "$rendered"; then
  die 'render does not enforce restricted Pod Security on flux-system'
fi

object_count="$(grep -cE '^kind:[[:space:]]' "$rendered")"
[[ "$object_count" -eq "$EXPECTED_OBJECTS" ]] || \
  die "render has ${object_count} objects; the reviewed install has ${EXPECTED_OBJECTS}"

render_digest="$(digest_of "$rendered")"
if [[ -n "$EXPECT_RENDER_SHA256" && "$render_digest" != "$EXPECT_RENDER_SHA256" ]]; then
  die "render sha256 ${render_digest} is not the reviewed ${EXPECT_RENDER_SHA256}; the tree, the tool, or the commit is not the reviewed one"
fi
note "render sha256 ${render_digest} (${object_count} objects) from commit ${source_commit}"

# --- The reviewed inventory, derived and cross-checked ------------------------
#
# The cluster-scoped names are what the rollback below must be able to remove
# and what a foreign-ownership refusal must cover, so they are read out of the
# render itself and then required to equal the reviewed constants above. A
# regenerated export that adds, drops, or renames one fails here rather than
# quietly shrinking every probe that follows.

inventory_names() {
  awk -v want="$2" '
    function flush() { if (kind == want && name != "") { print name } kind = ""; name = "" }
    /^---[[:space:]]*$/ { flush(); next }
    /^kind:[[:space:]]/ { if (kind == "") { kind = $2 } ; next }
    /^  name:[[:space:]]/ { if (name == "") { name = $2 } ; next }
    END { flush() }
  ' "$1" | LC_ALL=C sort
}

assert_inventory() {
  local kind="$1"
  shift
  local reviewed=''
  local derived=''
  reviewed="$(printf '%s\n' "$@" | LC_ALL=C sort)"
  derived="$(inventory_names "$rendered" "$kind")"
  [[ "$reviewed" == "$derived" ]] || \
    die "the rendered ${kind} inventory is not the reviewed one; the export drifted and every absence, ownership, and rollback probe below would be narrower than the install"
}

assert_inventory CustomResourceDefinition "${FLUX_CRDS[@]}"
assert_inventory ClusterRole "${FLUX_CLUSTER_ROLES[@]}"
assert_inventory ClusterRoleBinding "${FLUX_CLUSTER_ROLE_BINDINGS[@]}"
assert_inventory Deployment "${CONTROLLER_DEPLOYMENTS[@]}"

# --- Ordered phases ----------------------------------------------------------
#
# kustomize emits documents separated by a bare `---` at column 0 and indents
# every line inside a document, so a column-0 `---` is unambiguously a document
# boundary in its output. Both halves of every split are counted afterwards and
# the two counts must sum to the whole, so a mis-split fails closed instead of
# silently dropping an object out of a phase.

split_documents() {
  local source="$1"
  local pattern="$2"
  local matched="$3"
  local rest="$4"
  : >"$matched"
  : >"$rest"
  awk -v pattern="$pattern" -v matched="$matched" -v rest="$rest" '
    function flush(   out) {
      if (buffer == "") { return }
      out = (selected ? matched : rest)
      printf "---\n%s", buffer >>out
      buffer = ""
      selected = 0
    }
    /^---[[:space:]]*$/ { flush(); next }
    {
      buffer = buffer $0 "\n"
      if ($0 ~ pattern) { selected = 1 }
    }
    END { flush() }
  ' "$source"
}

count_objects() {
  grep -cE '^kind:[[:space:]]' "$1" || true
}

workloads="${work}/phase-3-workloads.yaml"
prerequisites="${work}/phase-1-prerequisites.yaml"
# The splitter's pattern and the guard's pattern below are deliberately NOT the
# same. A guard that asks the same question the splitter asked can only ever
# agree with it, which is how it survives being disabled: nothing can reach it.
# The guard's pattern is strictly BROADER -- it also recognizes a quoted or
# oddly spaced `kind` -- so a Deployment the splitter failed to recognize lands
# in phase 1 and the guard is the thing that catches it.
DEPLOYMENT_SPLIT_PATTERN='^kind: Deployment[[:space:]]*$'
DEPLOYMENT_ANY_PATTERN='^kind:[[:space:]]*['"'"'"]?Deployment['"'"'"]?[[:space:]]*$'
split_documents "$rendered" "$DEPLOYMENT_SPLIT_PATTERN" "$workloads" "$prerequisites"
# The whole point of the split is that no controller Pod exists before its
# egress allows do; a Deployment left in phase 1 would silently restore the
# deadlock this ordering exists to remove. Checked BEFORE the counts, so the
# operator is told which invariant broke rather than being told an arithmetic
# result that happens to follow from it.
! grep -Eq "$DEPLOYMENT_ANY_PATTERN" "$prerequisites" || \
  die 'a controller Deployment is still in the phase-1 bundle; the ordering that prevents the egress deadlock is broken'
workload_count="$(count_objects "$workloads")"
prerequisite_count="$(count_objects "$prerequisites")"
[[ "$workload_count" -eq "$EXPECTED_WORKLOADS" && "$prerequisite_count" -eq "$EXPECTED_PREREQUISITES" \
   && $((workload_count + prerequisite_count)) -eq "$EXPECTED_OBJECTS" ]] || \
  die "phase split wrong: ${prerequisite_count} prerequisite object(s) + ${workload_count} workload(s) is not ${EXPECTED_PREREQUISITES} + ${EXPECTED_WORKLOADS}"
[[ "$(grep -cE "$DEPLOYMENT_ANY_PATTERN" "$workloads" || true)" -eq "$EXPECTED_WORKLOADS" ]] || \
  die 'the phase-3 bundle is not exactly the controller Deployments'

# The 11 objects that live INSIDE flux-system. The ownership probe used to stop
# at the cluster-scoped ones, which made the script's own claim -- that an
# object under foreign ownership stops the install before anything is applied --
# false of every namespaced object it applies. Derived from the render rather than
# hand-listed, and then counted, so an export that adds or renames one is a hard
# failure instead of a silently narrower probe.
FLUX_NAMESPACED_OBJECTS=()
for kind in ResourceQuota ServiceAccount Service Deployment NetworkPolicy; do
  while IFS= read -r derived_name; do
    [[ -n "$derived_name" ]] || continue
    FLUX_NAMESPACED_OBJECTS+=("${kind,,}/${derived_name}")
  done < <(inventory_names "$rendered" "$kind")
done
[[ "${#FLUX_NAMESPACED_OBJECTS[@]}" -eq "$EXPECTED_NAMESPACED" ]] || \
  die "the render carries ${#FLUX_NAMESPACED_OBJECTS[@]} namespaced object(s); the reviewed install has ${EXPECTED_NAMESPACED} and the ownership probe would be narrower than the apply"
# ... and the deny-all that makes the ordering necessary must be in phase 1,
# where the controllers can be created into an already-isolated namespace.
grep -Eq '^  name: allow-egress[[:space:]]*$' "$prerequisites" || \
  die 'the patched allow-egress policy is not in the phase-1 bundle'

# --- The egress overlay, verified before any address is bound to it ----------

egress_rendered="${work}/egress.yaml"
"$KUSTOMIZE_BIN" build "${REPO_ROOT}/${EGRESS_TARGET}" >"$egress_rendered"
[[ -s "$egress_rendered" ]] || die 'egress render produced no bytes'
egress_count="$(count_objects "$egress_rendered")"
[[ "$egress_count" -eq "$EXPECTED_EGRESS_POLICIES" ]] || \
  die "egress overlay has ${egress_count} objects; the reviewed overlay has ${EXPECTED_EGRESS_POLICIES}"
for policy in "${STARTUP_EGRESS_POLICIES[@]}" "$PUBLIC_EGRESS_POLICY"; do
  [[ "$(grep -cE "^  name: ${policy}\$" "$egress_rendered" || true)" -eq 1 ]] || \
    die "the reviewed egress policy ${policy} is not in the overlay render exactly once"
done
[[ "$(grep -cF -- "$APISERVER_SENTINEL_CIDR" "$egress_rendered" || true)" -eq 1 ]] || \
  die 'the committed API-server allow does not carry exactly one unresolved sentinel destination'
egress_digest="$(digest_of "$egress_rendered")"
# The digest is taken over the COMMITTED bytes, before the API-server address is
# substituted in: the substituted file carries host inventory, so it is not a
# value a reviewer could ever have signed off. What the substitution then does
# to those reviewed bytes is bounded separately below -- exactly one line may
# differ.
if [[ -n "$EXPECT_EGRESS_SHA256" && "$egress_digest" != "$EXPECT_EGRESS_SHA256" ]]; then
  die "egress overlay sha256 ${egress_digest} is not the reviewed ${EXPECT_EGRESS_SHA256}; the egress bytes this would apply are not the reviewed ones"
fi
note "egress overlay sha256 ${egress_digest} (${egress_count} policies, API-server destination unresolved)"

# The canary is a third reviewed artifact, not shell-generated YAML. It carries
# the same selector and ServiceAccount as source-controller and runs exactly one
# immutable kubectl command against the in-cluster Service DNS identity.
canary_rendered="${work}/api-canary.yaml"
"$KUSTOMIZE_BIN" build "${REPO_ROOT}/${CANARY_TARGET}" >"$canary_rendered"
[[ -s "$canary_rendered" ]] || die 'API canary render produced no bytes'
[[ "$(count_objects "$canary_rendered")" -eq 1 ]] || \
  die 'API canary render must contain exactly one object'
for fragment in \
  'kind: Pod' \
  "  name: ${CANARY_NAME}" \
  '  namespace: flux-system' \
  '    app: source-controller' \
  '    app.kubernetes.io/part-of: flux' \
  '  serviceAccountName: source-controller' \
  'value: kubernetes.default.svc' \
  '- --raw=/api'; do
  [[ "$(grep -cF -- "$fragment" "$canary_rendered" || true)" -eq 1 ]] || \
    die "API canary render does not carry the reviewed boundary exactly once: ${fragment}"
done
canary_image="$(pin_value FLUX_API_CANARY_IMAGE)"
[[ "$canary_image" =~ ^registry\.k8s\.io/kubectl:v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]] || \
  die 'FLUX_API_CANARY_IMAGE must be one tagged, digest-pinned official kubectl image'
[[ "$(grep -cF -- "image: ${canary_image}" "$canary_rendered" || true)" -eq 1 ]] || \
  die 'API canary image does not exactly match the versions.env identity'
canary_digest="$(digest_of "$canary_rendered")"
if [[ -n "$EXPECT_CANARY_SHA256" && "$canary_digest" != "$EXPECT_CANARY_SHA256" ]]; then
  die "API canary sha256 ${canary_digest} is not the reviewed ${EXPECT_CANARY_SHA256}; the executable in-Pod proof is not the reviewed one"
fi
note "API canary sha256 ${canary_digest} (one ephemeral Pod)"

if [[ "$MODE" == '--render' ]]; then
  note 'RENDER only; no cluster was contacted and nothing was mutated'
  exit 0
fi

# --- Explicit target ---------------------------------------------------------
#
# The ambient default kubeconfig, context, and server are never used. Naming all
# three and proving the named context resolves to the named server is what makes
# "the cluster I meant" a checked fact rather than an assumption. That operator
# endpoint is deliberately NOT reused as workload policy evidence: the selected
# CNI's post-DNAT backends are separate, explicit --api-endpoint inputs.

[[ -f "$KUBECONFIG_PATH" ]] || die 'the --kubeconfig path is not a regular file'
[[ "$KUBE_SERVER" =~ ^https://([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]+)$ ]] || \
  die '--server must be https://<IPv4 address>:<port>; a NetworkPolicy selects destinations by address and can express nothing else'
server_port="${BASH_REMATCH[3]}"
[[ "$server_port" == "$APISERVER_PORT" ]] || \
  die "--server names port ${server_port} but the reviewed API-server egress allow names ${APISERVER_PORT}; the controllers would be denied the endpoint this run targets"

configured_server=''
configured_server="$("$KUBECTL_BIN" config view --kubeconfig "$KUBECONFIG_PATH" \
  --context "$KUBE_CONTEXT" --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)" || \
  die 'the --context is not present in the --kubeconfig'
[[ "$configured_server" == "$KUBE_SERVER" ]] || \
  die 'the --context resolves to a different API server than --server; refusing to act on a cluster nobody named'

# Every API operation goes through here. There is deliberately no other call
# site: an operation that forgot one of the three bindings would silently fall
# back to the ambient default, which is exactly the failure being closed.
kube() {
  "$KUBECTL_BIN" --kubeconfig "$KUBECONFIG_PATH" --context "$KUBE_CONTEXT" \
    --server "$KUBE_SERVER" "$@"
}

# The endpoint-set rule below is valid only for the selected Calico dataplane.
# Bind that assumption to the cluster before any mutation. The succeeding
# in-Pod canary later proves the dataplane behavior, rather than treating this
# identity probe as reachability evidence.
cni_probe_error="${work}/cni-probe.err"
cni_identity=''
if ! cni_identity="$(kube -n kube-system get daemonset calico-node \
    -o jsonpath='{.metadata.name}{"|"}{.metadata.labels.k8s-app}{"|"}{.spec.selector.matchLabels.k8s-app}' \
    2>"$cni_probe_error")"; then
  cat -- "$cni_probe_error" >&2
  die 'could not prove the selected Calico CNI identity; no API destination semantics may be assumed'
fi
[[ ! -s "$cni_probe_error" ]] || {
  cat -- "$cni_probe_error" >&2
  die 'the selected-CNI identity probe produced unexpected diagnostic output'
}
[[ "$cni_identity" == 'calico-node|calico-node|calico-node' ]] || \
  die "the selected-CNI identity is '${cni_identity}', not the reviewed Calico daemonset/selector contract"

# A Service canary proves one request traversed the dataplane; it cannot prove
# that every /32 granted by the policy belongs to that Service. Bind the private
# input to the complete authenticated EndpointSlice set before expanding the
# policy. The snapshot includes slice UID/resourceVersion, address type, named
# port, readiness, and every address, so a same-address replacement or a
# concurrent endpoint-set change is visible as drift rather than silently
# becoming a durable egress peer.
expected_api_endpoints="${work}/expected-api-endpoints.txt"
printf '%s\n' "${API_ENDPOINTS[@]}" >"$expected_api_endpoints"
endpoint_probe_index=0
capture_api_endpoint_snapshot() {
  local destination="$1"
  local raw="${destination}.raw"
  local errors="${destination}.err"
  local observed="${destination}.addresses"
  local record='' first='' second='' third='' fourth='' extra=''
  local canonical='' current_slice=''
  local slice_count=0 port_count=0 endpoint_count=0 total_endpoints=0
  local -a addresses=()

  # `$ready` is a Go-template variable, not shell expansion.
  # shellcheck disable=SC2016
  if ! kube -n default get endpointslice \
      -l kubernetes.io/service-name=kubernetes \
      -o go-template='{{range .items}}SLICE|{{.metadata.name}}|{{.metadata.uid}}|{{.metadata.resourceVersion}}|{{.addressType}}{{"\n"}}{{range .ports}}PORT|{{.name}}|{{.protocol}}|{{.port}}{{"\n"}}{{end}}{{range .endpoints}}{{$ready := .conditions.ready}}{{range .addresses}}ENDPOINT|{{.}}|{{$ready}}{{"\n"}}{{end}}{{end}}{{end}}' \
      >"$raw" 2>"$errors"; then
    cat -- "$errors" >&2
    warn 'could not read the authoritative kubernetes.default EndpointSlice set'
    return 1
  fi
  if [[ -s "$errors" || ! -s "$raw" ]]; then
    cat -- "$errors" >&2
    warn 'the kubernetes.default EndpointSlice probe was empty or produced diagnostics'
    return 1
  fi

  while IFS='|' read -r record first second third fourth extra; do
    [[ -z "$extra" ]] || {
      warn 'the kubernetes.default EndpointSlice probe returned a malformed record'
      return 1
    }
    case "$record" in
      SLICE)
        if [[ -n "$current_slice" && ("$port_count" -ne 1 || "$endpoint_count" -eq 0) ]]; then
          warn 'a kubernetes.default EndpointSlice did not carry exactly one reviewed port and at least one ready endpoint'
          return 1
        fi
        [[ -n "$first" && "$first" =~ ^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$ \
           && "$second" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ \
           && "$third" =~ ^[1-9][0-9]*$ && "$fourth" == 'IPv4' ]] || {
          warn 'the kubernetes.default EndpointSlice identity/addressType record is not canonical IPv4 state'
          return 1
        }
        current_slice="$first"
        port_count=0
        endpoint_count=0
        ((slice_count += 1))
        ;;
      PORT)
        [[ -n "$current_slice" && "$first" == 'https' && "$second" == 'TCP' \
           && "$third" == "$APISERVER_PORT" && -z "$fourth" ]] || {
          warn 'a kubernetes.default EndpointSlice does not expose exactly the reviewed https/TCP/6443 backend port'
          return 1
        }
        ((port_count += 1))
        ;;
      ENDPOINT)
        [[ -n "$current_slice" && "$second" == 'true' && -z "$third" && -z "$fourth" ]] || {
          warn 'a kubernetes.default EndpointSlice address is not explicitly ready'
          return 1
        }
        canonical="$(normalize_ipv4 "$first")" || {
          warn 'a kubernetes.default EndpointSlice returned a noncanonical/non-unicast IPv4 address'
          return 1
        }
        [[ "$canonical" == "$first" ]] || {
          warn 'a kubernetes.default EndpointSlice returned a noncanonical IPv4 spelling'
          return 1
        }
        addresses+=("$canonical")
        ((endpoint_count += 1))
        ((total_endpoints += 1))
        ;;
      *)
        warn 'the kubernetes.default EndpointSlice probe returned an unknown record type'
        return 1
        ;;
    esac
  done <"$raw"
  [[ "$slice_count" -gt 0 && "$port_count" -eq 1 && "$endpoint_count" -gt 0 ]] || {
    warn 'the kubernetes.default EndpointSlice set has no complete ready IPv4 backend slice'
    return 1
  }
  printf '%s\n' "${addresses[@]}" | LC_ALL=C sort >"$observed"
  [[ "$(LC_ALL=C sort -u "$observed" | grep -cE '.' || true)" -eq "$total_endpoints" ]] || {
    warn 'the kubernetes.default EndpointSlice set contains a duplicate backend address'
    return 1
  }
  cmp -s -- "$expected_api_endpoints" "$observed" || {
    warn 'the supplied API endpoint set does not exactly match the complete live kubernetes.default EndpointSlice set'
    return 1
  }
  LC_ALL=C sort -- "$raw" >"$destination"
}

endpoint_snapshot="${work}/api-endpoints.initial"
capture_api_endpoint_snapshot "$endpoint_snapshot" || \
  die 'the supplied API endpoint set is not authoritative live Kubernetes endpoint state'
note "selected-CNI API backend set authenticated against ${#API_ENDPOINTS[@]} live EndpointSlice address(es)"

endpoint_snapshot_unchanged() {
  local label="$1"
  local current=''
  ((endpoint_probe_index += 1))
  current="${work}/api-endpoints.${endpoint_probe_index}"
  capture_api_endpoint_snapshot "$current" || return 1
  cmp -s -- "$endpoint_snapshot" "$current" || {
    warn "the authoritative Kubernetes endpoint set drifted during ${label}"
    return 1
  }
}

# --- The egress bundle, bound to the Calico post-DNAT API endpoint set -------
#
# Calico enforces workload egress after kube-proxy DNAT, so the standard
# Kubernetes NetworkPolicy must name every API backend /32 on 6443 even though
# the Pod calls the kubernetes Service on 443. The private set lands only in the
# 0700 work directory and is never printed.

endpoint_cidrs="${work}/api-endpoint-cidrs.txt"
: >"$endpoint_cidrs"
for endpoint in "${API_ENDPOINTS[@]}"; do
  printf '%s/32\n' "$endpoint" >>"$endpoint_cidrs"
done

egress_bound="${work}/egress-bound.yaml"
awk -v sentinel="$APISERVER_SENTINEL_CIDR" -v endpoints="$endpoint_cidrs" '
  $0 == "        - ipBlock:" {
    header = $0
    if ((getline following) > 0 && following == "            cidr: " sentinel) {
      while ((getline cidr < endpoints) > 0) {
        print header
        print "            cidr: " cidr
      }
      close(endpoints)
      replaced++
      next
    }
    print header
    print following
    next
  }
  { print }
  END { if (replaced != 1) { exit 42 } }
' "$egress_rendered" >"$egress_bound" || \
  die 'the reviewed API-server sentinel block could not be expanded exactly once'
[[ "$(grep -cF -- "$APISERVER_SENTINEL_CIDR" "$egress_bound" || true)" -eq 0 ]] || \
  die 'the API-server sentinel survived substitution; the applied policy would grant nothing'
for endpoint in "${API_ENDPOINTS[@]}"; do
  [[ "$(grep -cF -- "            cidr: ${endpoint}/32" "$egress_bound" || true)" -eq 1 ]] || \
    die 'the bound API endpoint set is not an exact one-to-one expansion of the private input'
done

# Reconstruct the reviewed sentinel form from the private expansion and demand
# byte identity. This is stronger than counting diff lines and remains exact
# when an HA cluster supplies more than one backend.
egress_roundtrip="${work}/egress-roundtrip.yaml"
awk -v sentinel="$APISERVER_SENTINEL_CIDR" -v endpoints="$endpoint_cidrs" '
  BEGIN { while ((getline cidr < endpoints) > 0) { selected[cidr] = 1 } close(endpoints) }
  $0 == "        - ipBlock:" {
    header = $0
    if ((getline following) <= 0) { print header; next }
    cidr = following
    sub(/^            cidr: /, "", cidr)
    if (cidr in selected) {
      if (!collapsed) {
        print header
        print "            cidr: " sentinel
        collapsed = 1
      }
      next
    }
    print header
    print following
    next
  }
  { print }
' "$egress_bound" >"$egress_roundtrip"
cmp -s -- "$egress_rendered" "$egress_roundtrip" || \
  die 'the API endpoint-set substitution changed bytes outside the one reviewed sentinel block'

startup_egress="${work}/phase-2-startup-egress.yaml"
public_egress="${work}/phase-4-public-egress.yaml"
split_documents "$egress_bound" "^  name: ${PUBLIC_EGRESS_POLICY}[[:space:]]*\$" \
  "$public_egress" "$startup_egress"
startup_count="$(count_objects "$startup_egress")"
public_count="$(count_objects "$public_egress")"
[[ "$startup_count" -eq "$EXPECTED_STARTUP_POLICIES" && "$public_count" -eq 1 \
   && $((startup_count + public_count)) -eq "$EXPECTED_EGRESS_POLICIES" ]] || \
  die "egress phase split wrong: ${startup_count} startup + ${public_count} public is not ${EXPECTED_STARTUP_POLICIES} + 1"
for policy in "${STARTUP_EGRESS_POLICIES[@]}"; do
  grep -Eq "^  name: ${policy}\$" "$startup_egress" || \
    die "the startup egress bundle is missing ${policy}; the controllers would start without a flow they need"
done
! grep -Eq "^  name: ${PUBLIC_EGRESS_POLICY}\$" "$startup_egress" || \
  die 'the public-HTTPS allow is in the startup bundle; it stays shut until the controllers are observed healthy'

# The egress bundle is namespace-scoped, so a server dry run cannot validate it
# before flux-system exists (k8s #83562, the same defect the controller gate
# works around). Client-side strict validation needs no namespace and rejects
# unknown or duplicated fields on all five policies.
egress_client_dry_run="${work}/egress-dry-run-client.txt"
if ! kube apply -f "$egress_bound" --dry-run=client --validate=strict \
    >"$egress_client_dry_run" 2>&1; then
  cat -- "$egress_client_dry_run" >&2
  die 'client-side strict validation failed on the egress overlay'
fi

canary_client_dry_run="${work}/canary-dry-run-client.txt"
if ! kube apply -f "$canary_rendered" --dry-run=client --validate=strict \
    >"$canary_client_dry_run" 2>&1; then
  cat -- "$canary_client_dry_run" >&2
  die 'client-side strict validation failed on the API canary'
fi
[[ "$(grep -cE "^pod/${CANARY_NAME} created( \(dry run\))?$" "$canary_client_dry_run" || true)" -eq 1 \
   && "$(grep -cE '.' "$canary_client_dry_run" || true)" -eq 1 ]] || {
  cat -- "$canary_client_dry_run" >&2
  die 'client validation did not report exactly the reviewed API canary Pod'
}

# --- Fail-closed pre-apply gate ---------------------------------------------
#
# The install creates its OWN flux-system Namespace, so a naive "every object
# must report created" server dry run can never pass a fresh cluster: k8s #83562
# means the dry run does not persist that Namespace, and the 11 namespaced
# children then fail admission with `namespaces "flux-system" not found` while
# kubectl exits non-zero. The old gate died there -- refusing the very
# fresh-cluster install this script exists to perform. The gate instead proves a
# clean creation without leaning on the dry run persisting the namespace, and
# fails closed on anything else.

# (1) The bytes are valid to apply at all, independent of any namespace.
# Client-side strict validation rejects unknown/duplicated fields and needs no
# flux-system to exist, so it validates all 30 objects even on a fresh cluster.
client_dry_run="${work}/dry-run-client.txt"
if ! kube apply -f "$rendered" --dry-run=client --validate=strict \
    >"$client_dry_run" 2>&1; then
  cat -- "$client_dry_run" >&2
  die 'client-side strict validation failed; the render is not valid to apply'
fi
client_objects="$(grep -cE "$INVENTORY_MUTATION_LINE" "$client_dry_run" || true)"
[[ "$client_objects" -eq "$EXPECTED_OBJECTS" ]] || {
  cat -- "$client_dry_run" >&2
  die "client validation reported ${client_objects} reviewed objects; expected ${EXPECTED_OBJECTS}"
}

# (2) Is flux-system already present? That forks the two legitimate dry-run
# shapes below. A get that neither finds it nor cleanly reports it missing -- an
# unreachable API server -- is fatal, never silently treated as "fresh".
ns_state="${work}/namespace-state.txt"
if kube get namespace "$INSTALL_NAMESPACE" -o name >"$ns_state" 2>&1; then
  cluster_state='existing'
elif grep -Eq '^Error from server \(NotFound\): (namespaces "flux-system"|namespace/flux-system) not found$' "$ns_state"; then
  cluster_state='fresh'
else
  cat -- "$ns_state" >&2
  die 'could not determine flux-system state; the API server did not answer NotFound'
fi

# (2b) --apply installs onto a FRESH cluster only.
#
# Not a convenience limit -- a scope limit on what the transaction below can
# honestly undo. On an existing install every one of the 27 phase-1 objects
# reports `configured`: bytes rewritten in place, with no prestate recorded
# anywhere. A ledger of CREATIONS cannot restore them, so a phase-2 or phase-3
# failure would roll back nothing and print "this attempt created nothing; the
# cluster is unchanged" over a namespace whose RBAC, CRDs and NetworkPolicies
# had just been rewritten. Refusing is the only answer that is true. Reconciling
# an existing install to reviewed bytes is a real need and a separate reviewed
# ceremony; --plan still classifies that cluster read-only, which is how the
# operator sees what it would take.
if [[ "$MODE" == '--apply' && "$cluster_state" == 'existing' ]]; then
  die 'flux-system already exists; --apply installs only onto a fresh cluster, because an apply over an existing install rewrites objects this transaction has no prestate to restore (use --plan to inspect it; see docs/runbooks/flux-install.md)'
fi

# (3) Nothing the install creates may be adopted from somebody else. Every
# cluster-scoped object is probed: absent is fine; present carrying THIS
# install's ownership labels is a previous run of it; present without them
# belongs to something else and is never reconfigured, never deleted, and never
# counted as this attempt's to roll back. On a fresh cluster the bar is higher
# still -- flux-system is absent, so a leftover cluster-scoped object is residue
# from a failed install and the operator is told rather than silently adopted.
probe_labels() {
  local kind="$1"
  local name="$2"
  local namespaced="${3:-}"
  local probe_err="${work}/probe.err"
  local labels=''
  if [[ -n "$namespaced" ]]; then
    if labels="$(kube -n "$INSTALL_NAMESPACE" get "$kind" "$name" \
        -o jsonpath='{.metadata.labels}' 2>"$probe_err")"; then
      printf '%s' "$labels"
      return 0
    fi
  elif labels="$(kube get "$kind" "$name" -o jsonpath='{.metadata.labels}' 2>"$probe_err")"; then
    printf '%s' "$labels"
    return 0
  fi
  if grep -Eq '^Error from server \(NotFound\): .+ not found$' "$probe_err"; then
    printf 'ABSENT'
    return 0
  fi
  cat -- "$probe_err" >&2
  die "could not determine whether ${kind}/${name} exists; the API server did not answer NotFound"
}

assert_not_foreign() {
  local kind="$1"
  local name="$2"
  local namespaced="${3:-}"
  local labels=''
  labels="$(probe_labels "$kind" "$name" "$namespaced")"
  if [[ "$labels" == 'ABSENT' ]]; then
    return 0
  fi
  if [[ "$cluster_state" == 'fresh' ]]; then
    die "flux-system is absent but ${kind} ${name} already exists; clean up the residue of the earlier attempt before reinstalling"
  fi
  [[ "$labels" == *"$OWNERSHIP_PART_OF"* && "$labels" == *"$OWNERSHIP_INSTANCE"* ]] || \
    die "${kind} ${name} already exists and is not owned by this install; refusing to adopt, reconfigure, or roll back a foreign object"
}

canary_prestate="$(probe_labels pod "$CANARY_NAME" namespaced)"
[[ "$canary_prestate" == 'ABSENT' ]] || \
  die "Pod ${CANARY_NAME} already exists; the ephemeral proof is absent-only and never adopts or deletes pre-existing state"

if [[ "$cluster_state" == 'fresh' ]]; then
  crd_inventory="${work}/crd-inventory.txt"
  crd_inventory_error="${work}/crd-inventory.err"
  if ! kube get customresourcedefinition -o name >"$crd_inventory" 2>"$crd_inventory_error"; then
    cat -- "$crd_inventory_error" >&2
    die 'could not prove the fresh cluster has no Flux CRD; an API/RBAC failure is not absence'
  fi
  [[ ! -s "$crd_inventory_error" ]] || {
    cat -- "$crd_inventory_error" >&2
    die 'the CRD absence probe produced unexpected diagnostic output'
  }
  while IFS= read -r crd_entry; do
    [[ -n "$crd_entry" ]] || continue
    [[ "$crd_entry" =~ ^customresourcedefinition\.apiextensions\.k8s\.io/[a-z0-9]([-.a-z0-9]*[a-z0-9])?$ ]] || \
      die 'the CRD absence probe returned malformed output; absence was not proven'
  done <"$crd_inventory"
  fluxcd_crds="$(grep -c '\.fluxcd\.io$' "$crd_inventory" || true)"
  [[ "$fluxcd_crds" -eq 0 ]] || \
    die "flux-system is absent but ${fluxcd_crds} fluxcd CRD(s) already exist"
  # The 11 namespaced objects need no probe on this path and cannot get one: a
  # namespaced object cannot exist without its namespace, and the namespace was
  # just proven absent. Their absence is a consequence of that proof, not an
  # assumption -- which is the other half of why --apply is fresh-only.
else
  assert_not_foreign namespace "$INSTALL_NAMESPACE"
  for name in "${FLUX_CRDS[@]}"; do
    assert_not_foreign customresourcedefinition "$name"
  done
  for entry in "${FLUX_NAMESPACED_OBJECTS[@]}"; do
    assert_not_foreign "${entry%%/*}" "${entry#*/}" namespaced
  done
fi
for name in "${FLUX_CLUSTER_ROLES[@]}"; do
  assert_not_foreign clusterrole "$name"
done
for name in "${FLUX_CLUSTER_ROLE_BINDINGS[@]}"; do
  assert_not_foreign clusterrolebinding "$name"
done

# (4) The server dry run, classified by cluster state. It contacts the API
# server but mutates nothing. On a fresh cluster kubectl exits non-zero by
# design (the 11 children cannot be placed); that is not a failure here.
dry_run="${work}/dry-run-server.txt"
if kube apply -f "$rendered" --dry-run=server >"$dry_run" 2>&1; then
  server_rc=0
else
  server_rc=$?
fi
total_lines="$(grep -cE '.' "$dry_run" || true)"

if [[ "$cluster_state" == 'fresh' ]]; then
  # Exactly EXPECTED_CLUSTER_SCOPED objects report "created" and exactly
  # EXPECTED_NAMESPACED children report the flux-system namespace-not-found;
  # every line must be one of those two. A "configured"/"unchanged", a foreign
  # object, a different namespace, or any other error breaks the count and dies.
  [[ "$server_rc" -ne 0 ]] || \
    die 'fresh cluster but the server dry run reported no error; the namespace state is inconsistent'
  created="$(grep -cE "$CLUSTER_SCOPED_CREATED_LINE" "$dry_run" || true)"
  not_found="$(grep -cE "$NS_NOT_FOUND_LINE" "$dry_run" || true)"
  if [[ "$created" -ne "$EXPECTED_CLUSTER_SCOPED" || "$not_found" -ne "$EXPECTED_NAMESPACED" \
        || $((created + not_found)) -ne "$total_lines" ]]; then
    cat -- "$dry_run" >&2
    die "fresh dry-run shape wrong: ${created} cluster-scoped created (want ${EXPECTED_CLUSTER_SCOPED}), ${not_found} namespace-not-found children (want ${EXPECTED_NAMESPACED}), ${total_lines} total lines"
  fi
  note "fresh-cluster dry run clean (${created} created + ${not_found} expected namespace-not-found)"
else
  # flux-system already exists: every reviewed object dry-runs cleanly against
  # it (the reconcile-to-reviewed-bytes path). A genuine error breaks the shape.
  [[ "$server_rc" -eq 0 ]] || {
    cat -- "$dry_run" >&2
    die 'server dry run failed against the existing flux-system namespace'
  }
  clean="$(grep -cE "$INVENTORY_MUTATION_LINE" "$dry_run" || true)"
  if [[ "$clean" -ne "$total_lines" || "$total_lines" -ne "$EXPECTED_OBJECTS" ]]; then
    cat -- "$dry_run" >&2
    die "existing dry-run shape wrong: ${clean} reviewed objects (want ${EXPECTED_OBJECTS}), ${total_lines} total lines"
  fi
  note "existing-cluster dry run clean (${clean} objects)"
fi

endpoint_snapshot_unchanged 'the read-only pre-mutation gate' || \
  die 'the authoritative Kubernetes endpoint set changed while the install was being planned'

if [[ "$MODE" == '--plan' ]]; then
  note 'PLAN only; no mutation attempted'
  note "create order would be: ${EXPECTED_PREREQUISITES} prerequisites, ${EXPECTED_STARTUP_POLICIES} startup egress allows, one create/prove/conditional-delete API canary, then ${EXPECTED_WORKLOADS} controller Deployments"
  exit 0
fi

# --- The ordered, inventory-bound transaction --------------------------------

LEDGER="${work}/created-by-this-attempt.txt"
: >"$LEDGER"
# Candidate manifests whose create requests were attempted, in request order.
# The ledger is rebuilt from their live per-attempt identities on demand rather
# than trusting kubectl output or same-name existence.
ATTEMPTED_MANIFESTS=()
FOREIGN_COLLISIONS="${work}/foreign-collisions.txt"
UNCERTAIN_OBJECTS="${work}/uncertain-objects.txt"
: >"$FOREIGN_COLLISIONS"
: >"$UNCERTAIN_OBJECTS"

attempt_random="${work}/attempt-random.bin"
if ! dd if=/dev/urandom of="$attempt_random" bs=32 count=1 status=none; then
  die 'could not obtain kernel randomness for the install-attempt identity'
fi
[[ "$(wc -c <"$attempt_random")" -eq 32 ]] || \
  die 'the install-attempt entropy read was incomplete'
ATTEMPT_ID="$(digest_of "$attempt_random")"
rm -f -- "$attempt_random"
[[ "$ATTEMPT_ID" =~ ^[0-9a-f]{64}$ ]] || \
  die 'the install-attempt identity is not a canonical 256-bit value'

# Add the unpredictable identity to top-level metadata only. The inverse pass
# then removes it and must reproduce the reviewed manifest byte for byte: that
# is what proves this runtime derivation added no second field while making
# every create response independently attributable.
annotate_manifest_for_attempt() {
  local source="$1"
  local destination="$2"
  local attempt="$3"
  local roundtrip="${destination}.roundtrip"
  local expected=''
  expected="$(count_objects "$source")"
  awk -v key="$ATTEMPT_ANNOTATION" -v attempt="$attempt" '
    function flush_metadata() {
      if (!has_annotations) {
        print "  annotations:"
        print "    " key ": " attempt
      }
      printf "%s", metadata
      metadata = ""
      in_metadata = 0
      has_annotations = 0
    }
    $0 == "metadata:" {
      print
      in_metadata = 1
      documents++
      next
    }
    in_metadata {
      if ($0 !~ /^ /) {
        flush_metadata()
      } else {
        if ($0 == "  annotations:") {
          metadata = metadata $0 "\n" "    " key ": " attempt "\n"
          has_annotations = 1
          next
        }
        if (index($0, "    " key ":") == 1) { exit 41 }
        metadata = metadata $0 "\n"
        next
      }
    }
    { print }
    END {
      if (in_metadata) { flush_metadata() }
      if (documents == 0) { exit 42 }
    }
  ' "$source" >"$destination" || \
    die 'the attempt annotation could not be added exactly once per object'
  [[ "$(grep -cF -- "    ${ATTEMPT_ANNOTATION}: ${attempt}" "$destination" || true)" -eq "$expected" ]] || \
    die 'the attempt annotation count does not equal the manifest object count'

  awk -v key="$ATTEMPT_ANNOTATION" -v attempt="$attempt" '
    function flush_annotations() {
      if (body != "") {
        print "  annotations:"
        printf "%s", body
      }
      body = ""
      in_annotations = 0
    }
    $0 == "  annotations:" {
      in_annotations = 1
      next
    }
    in_annotations {
      if ($0 !~ /^    /) {
        flush_annotations()
      } else {
        if ($0 == "    " key ": " attempt) { removed++; next }
        body = body $0 "\n"
        next
      }
    }
    { print }
    END {
      if (in_annotations) { flush_annotations() }
      if (removed == 0) { exit 43 }
    }
  ' "$destination" >"$roundtrip" || \
    die 'the attempt annotation could not be removed from the derived manifest'
  cmp -s -- "$source" "$roundtrip" || \
    die 'the attempt-bound manifest changed bytes outside its provenance annotation'
}

entry_is_cluster_scoped() {
  [[ "$1" =~ ^(namespace|customresourcedefinition\.apiextensions\.k8s\.io|clusterrole\.rbac\.authorization\.k8s\.io|clusterrolebinding\.rbac\.authorization\.k8s\.io)/[^/]+$ ]]
}

# The objects a manifest declares, as the `<resource>/<name>` identifiers kubectl
# prints and accepts, in the order the manifest declares them. That order is what
# makes the rollback's reverse walk remove children before the Namespace.
manifest_entries() {
  awk '
    function resource(k) {
      if (k == "Namespace") { return "namespace" }
      if (k == "CustomResourceDefinition") { return "customresourcedefinition.apiextensions.k8s.io" }
      if (k == "ClusterRole") { return "clusterrole.rbac.authorization.k8s.io" }
      if (k == "ClusterRoleBinding") { return "clusterrolebinding.rbac.authorization.k8s.io" }
      if (k == "NetworkPolicy") { return "networkpolicy.networking.k8s.io" }
      if (k == "ResourceQuota") { return "resourcequota" }
      if (k == "ServiceAccount") { return "serviceaccount" }
      if (k == "Service") { return "service" }
      if (k == "Deployment") { return "deployment.apps" }
      return tolower(k)
    }
    function flush() {
      if (kind != "" && name != "") { printf "%s/%s\n", resource(kind), name }
      kind = ""; name = ""
    }
    /^---[[:space:]]*$/ { flush(); next }
    /^kind:[[:space:]]/ { if (kind == "") { kind = $2; gsub(/["'"'"']/, "", kind) } ; next }
    /^  name:[[:space:]]/ { if (name == "") { name = $2 } ; next }
    END { flush() }
  ' "$1"
}

# One atomic metadata read supplies the attempt marker and the two server
# preconditions used for rollback. Missing/foreign/malformed/error are distinct:
# only an exact attempt match may ever enter the deletion ledger.
CAPTURE_STATE=''
CAPTURE_ATTEMPT=''
CAPTURE_UID=''
CAPTURE_RESOURCE_VERSION=''
capture_entry_metadata() {
  local entry="$1"
  local key="${entry//[\/.]/_}"
  local output="${work}/identity-${key}.txt"
  local errors="${work}/identity-${key}.err"
  local marker='' extra=''
  CAPTURE_STATE='error'
  CAPTURE_ATTEMPT=''
  CAPTURE_UID=''
  CAPTURE_RESOURCE_VERSION=''
  : >"$output"
  : >"$errors"
  if entry_is_cluster_scoped "$entry"; then
    if ! kube get "$entry" \
        -o go-template='{{index .metadata.annotations "platform.snaraj.dev/install-attempt-id"}}{{"|"}}{{.metadata.uid}}{{"|"}}{{.metadata.resourceVersion}}{{"|END"}}' \
        >"$output" 2>"$errors"; then
      if grep -Eq '^Error from server \(NotFound\): .+ not found$' "$errors"; then
        CAPTURE_STATE='absent'
        return 0
      fi
      return 1
    fi
  else
    if ! kube -n "$INSTALL_NAMESPACE" get "$entry" \
        -o go-template='{{index .metadata.annotations "platform.snaraj.dev/install-attempt-id"}}{{"|"}}{{.metadata.uid}}{{"|"}}{{.metadata.resourceVersion}}{{"|END"}}' \
        >"$output" 2>"$errors"; then
      if grep -Eq '^Error from server \(NotFound\): .+ not found$' "$errors"; then
        CAPTURE_STATE='absent'
        return 0
      fi
      return 1
    fi
  fi
  [[ ! -s "$errors" ]] || return 1
  IFS='|' read -r CAPTURE_ATTEMPT CAPTURE_UID CAPTURE_RESOURCE_VERSION marker extra <"$output"
  [[ -z "$extra" && "$marker" == 'END' \
     && "$CAPTURE_UID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ \
     && "$CAPTURE_RESOURCE_VERSION" =~ ^[1-9][0-9]*$ ]] || return 1
  CAPTURE_STATE='present'
  return 0
}

# Convert only the closed reviewed resource inventory to REST collection paths.
# `kubectl delete --raw PATH -f DeleteOptions.json` is the kubectl interface that
# can actually send UID/resourceVersion preconditions; ordinary `kubectl delete`
# explicitly performs no resourceVersion check.
entry_api_path() {
  local entry="$1"
  local name="${entry#*/}"
  [[ "$name" != "$entry" && "$name" =~ ^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$ ]] || return 1
  case "$entry" in
    namespace/*) printf '/api/v1/namespaces/%s' "$name" ;;
    customresourcedefinition.apiextensions.k8s.io/*) printf '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/%s' "$name" ;;
    clusterrole.rbac.authorization.k8s.io/*) printf '/apis/rbac.authorization.k8s.io/v1/clusterroles/%s' "$name" ;;
    clusterrolebinding.rbac.authorization.k8s.io/*) printf '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/%s' "$name" ;;
    networkpolicy.networking.k8s.io/*) printf '/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies/%s' "$INSTALL_NAMESPACE" "$name" ;;
    deployment.apps/*) printf '/apis/apps/v1/namespaces/%s/deployments/%s' "$INSTALL_NAMESPACE" "$name" ;;
    resourcequota/*) printf '/api/v1/namespaces/%s/resourcequotas/%s' "$INSTALL_NAMESPACE" "$name" ;;
    serviceaccount/*) printf '/api/v1/namespaces/%s/serviceaccounts/%s' "$INSTALL_NAMESPACE" "$name" ;;
    service/*) printf '/api/v1/namespaces/%s/services/%s' "$INSTALL_NAMESPACE" "$name" ;;
    pod/*) printf '/api/v1/namespaces/%s/pods/%s' "$INSTALL_NAMESPACE" "$name" ;;
    *) return 1 ;;
  esac
}

conditional_delete_entry() {
  local entry="$1"
  local uid="$2"
  local resource_version="$3"
  local key="${entry//[\/.]/_}"
  local options="${work}/delete-${key}.json"
  local response="${work}/delete-${key}.response"
  local api_path=''
  api_path="$(entry_api_path "$entry")" || return 1
  printf '{"apiVersion":"v1","kind":"DeleteOptions","propagationPolicy":"Background","preconditions":{"uid":"%s","resourceVersion":"%s"}}\n' \
    "$uid" "$resource_version" >"$options"
  kube delete --raw "$api_path" -f "$options" >"$response" 2>&1
}

# Rebuild the ledger from exact attempt identities. An AlreadyExists response or
# a lost response after a concurrent actor won the name is not evidence of our
# ownership; that live object is recorded as a collision and left untouched.
harvest_ledger() {
  local manifest=''
  local entry=''
  : >"$LEDGER"
  : >"$FOREIGN_COLLISIONS"
  : >"$UNCERTAIN_OBJECTS"
  for manifest in ${ATTEMPTED_MANIFESTS[@]+"${ATTEMPTED_MANIFESTS[@]}"}; do
    while IFS= read -r entry; do
      [[ -n "$entry" ]] || continue
      if ! capture_entry_metadata "$entry"; then
        printf '%s\n' "$entry" >>"$UNCERTAIN_OBJECTS"
      elif [[ "$CAPTURE_STATE" == 'present' && "$CAPTURE_ATTEMPT" == "$ATTEMPT_ID" ]]; then
        printf '%s|%s|%s\n' "$entry" "$CAPTURE_UID" "$CAPTURE_RESOURCE_VERSION" >>"$LEDGER"
      elif [[ "$CAPTURE_STATE" == 'present' ]]; then
        printf '%s\n' "$entry" >>"$FOREIGN_COLLISIONS"
      fi
    done < <(manifest_entries "$manifest")
  done
}

UID_GONE_STATE=''
attempt_uid_is_gone() {
  local entry="$1"
  local uid="$2"
  UID_GONE_STATE='error'
  if ! capture_entry_metadata "$entry"; then
    return 1
  fi
  if [[ "$CAPTURE_STATE" == 'absent' ]]; then
    UID_GONE_STATE='absent'
    return 0
  fi
  if [[ "$CAPTURE_STATE" == 'present' && "$CAPTURE_UID" != "$uid" ]]; then
    UID_GONE_STATE='replaced'
    warn "rollback: ${entry} was concurrently replaced; the foreign UID remains untouched"
    return 0
  fi
  UID_GONE_STATE='residue'
  return 1
}

# Roll back exactly matching attempt objects newest-first. Identity is captured
# immediately before each DELETE and supplied as UID+resourceVersion server
# preconditions, so neither a concurrent update nor delete/recreate can be lost.
rollback() {
  local -a created=() residue=() collisions=() uncertain=()
  local record='' entry='' uid='' resource_version=''
  local index=0
  local namespace_record='' preserve_namespace='no'
  harvest_ledger
  mapfile -t created <"$LEDGER"
  mapfile -t collisions <"$FOREIGN_COLLISIONS"
  mapfile -t uncertain <"$UNCERTAIN_OBJECTS"
  if ((${#collisions[@]} > 0)); then
    warn "rollback: ${#collisions[@]} concurrent/foreign same-name object(s) were identified and left untouched: ${collisions[*]}"
    for entry in "${collisions[@]}"; do
      if ! entry_is_cluster_scoped "$entry"; then
        preserve_namespace='yes'
      fi
    done
  fi
  for entry in "${uncertain[@]}"; do
    if ! entry_is_cluster_scoped "$entry"; then
      preserve_namespace='yes'
    fi
  done
  if ((${#created[@]} == 0)); then
    if ((${#uncertain[@]} > 0)); then
      warn "ROLLBACK INCOMPLETE: could not classify ${#uncertain[@]} candidate object(s) by attempt identity: ${uncertain[*]}"
      return 1
    fi
    if ((${#collisions[@]} > 0)); then
      warn 'rollback: this attempt created nothing; foreign collisions remain untouched'
    else
      warn 'rollback: this attempt created nothing; the cluster is unchanged'
    fi
    return 0
  fi
  warn "rollback: removing the ${#created[@]} object(s) this attempt created, newest first"
  for ((index = ${#created[@]} - 1; index >= 0; index--)); do
    record="${created[index]}"
    IFS='|' read -r entry uid resource_version <<<"$record"
    if [[ "$entry" == "namespace/${INSTALL_NAMESPACE}" ]]; then
      namespace_record="$record"
      continue
    fi
    conditional_delete_entry "$entry" "$uid" "$resource_version" || \
      warn "rollback: the preconditioned delete response for ${entry} was unsuccessful or lost"
  done
  for record in "${created[@]}"; do
    IFS='|' read -r entry uid resource_version <<<"$record"
    [[ "$entry" != "namespace/${INSTALL_NAMESPACE}" ]] || continue
    if ! attempt_uid_is_gone "$entry" "$uid"; then
      residue+=("$entry")
      if ! entry_is_cluster_scoped "$entry"; then
        preserve_namespace='yes'
      fi
    elif [[ "$UID_GONE_STATE" == 'replaced' ]] && ! entry_is_cluster_scoped "$entry"; then
      preserve_namespace='yes'
    fi
  done
  if [[ -n "$namespace_record" ]]; then
    IFS='|' read -r entry uid resource_version <<<"$namespace_record"
    if [[ "$preserve_namespace" == 'yes' ]]; then
      residue+=("$entry")
      warn 'rollback: preserving the attempt-created Namespace because deleting it would cascade a concurrent/uncertain foreign namespaced object'
    else
      conditional_delete_entry "$entry" "$uid" "$resource_version" || \
        warn "rollback: the preconditioned delete response for ${entry} was unsuccessful or lost"
      attempt_uid_is_gone "$entry" "$uid" || residue+=("$entry")
    fi
  fi
  if ((${#uncertain[@]} > 0)); then
    residue+=("${uncertain[@]}")
  fi
  if ((${#residue[@]} > 0)); then
    warn "ROLLBACK INCOMPLETE: ${#residue[@]} attempt object(s) remain or could not be classified; manual protected review required: ${residue[*]}"
    return 1
  fi
  warn "rollback complete: all ${#created[@]} object(s) this attempt created are absent, cluster-scoped objects included"
  return 0
}

transaction_failed() {
  warn "$1"
  rollback || true
  exit 1
}

create_phase() {
  local label="$1"
  local manifest="$2"
  local expected="$3"
  local output=''
  output="${work}/create-$(basename -- "$manifest" .yaml).txt"
  local rc=0 reported=0 total='' entry=''
  note "phase ${label}: creating ${expected} attempt-bound object(s)"
  # Recorded BEFORE the call, not after: an interrupt delivered during create
  # must still find this manifest in the list, or its objects are invisible to
  # the rollback.
  ATTEMPTED_MANIFESTS+=("$manifest")
  kube create --save-config -f "$manifest" >"$output" 2>&1 || rc=$?
  if ((rc != 0)); then
    cat -- "$output" >&2
    transaction_failed "phase ${label} create failed (kubectl exit ${rc}); a partial create or a foreign collision may exist"
  fi
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    if grep -Fxq -- "${entry} created" "$output"; then
      ((reported += 1))
    fi
  done < <(manifest_entries "$manifest")
  total="$(grep -cE '.' "$output" || true)"
  if [[ "$reported" -ne "$expected" || "$total" -ne "$expected" ]]; then
    cat -- "$output" >&2
    transaction_failed "phase ${label} reported ${reported} exact creations across ${total} line(s); expected exactly ${expected}"
  fi
}

# Create one absent-only object under the same response-loss-safe ledger used
# by the install. The manifest enters the ledger before the request: if the API
# server persists it but the response is lost, rollback rediscovers it live.
create_exact_object() {
  local label="$1"
  local manifest="$2"
  local expected_entry="$3"
  local failure_prefix="${4:-${label} create failed}"
  local output=''
  output="${work}/create-$(basename -- "$manifest" .yaml).txt"
  local rc=0
  ATTEMPTED_MANIFESTS+=("$manifest")
  kube create --save-config -f "$manifest" >"$output" 2>&1 || rc=$?
  if ((rc != 0)); then
    cat -- "$output" >&2
    transaction_failed "${failure_prefix} (kubectl exit ${rc}); the response may have been lost after persistence"
  fi
  if [[ "$(grep -cE '.' "$output" || true)" -ne 1 ]] || \
      ! grep -Fxq -- "${expected_entry} created" "$output"; then
    cat -- "$output" >&2
    transaction_failed "${label} create did not report exactly ${expected_entry} created"
  fi
}

prove_api_path_then_remove_canary() {
  local canary_entry="pod/${CANARY_NAME}"
  local wait_output="${work}/canary-wait.txt"
  local phase_error="${work}/canary-phase.err"
  local canary_uid='' canary_resource_version=''
  local phase=''
  local after=''

  note 'phase api-canary: proving DNS, TLS, Service routing, ServiceAccount authentication and API discovery'
  create_exact_object 'API canary' "$canary_attempt" "$canary_entry" \
    'the in-Pod Kubernetes Service/API canary did not succeed; API canary create failed'
  if ! kube -n "$INSTALL_NAMESPACE" wait --for=jsonpath='{.status.phase}'=Succeeded \
      "$canary_entry" --timeout=60s >"$wait_output" 2>&1; then
    cat -- "$wait_output" >&2
    transaction_failed 'the in-Pod Kubernetes Service/API canary did not succeed; no controller Deployment was created'
  fi
  if ! phase="$(kube -n "$INSTALL_NAMESPACE" get "$canary_entry" \
      -o jsonpath='{.status.phase}' 2>"$phase_error")"; then
    cat -- "$phase_error" >&2
    transaction_failed 'the API canary completed but its exact terminal state could not be proven'
  fi
  [[ ! -s "$phase_error" && "$phase" == 'Succeeded' ]] || {
    cat -- "$phase_error" >&2
    transaction_failed "the API canary terminal phase is '${phase}', not Succeeded"
  }

  if ! capture_entry_metadata "$canary_entry" \
      || [[ "$CAPTURE_STATE" != 'present' || "$CAPTURE_ATTEMPT" != "$ATTEMPT_ID" ]]; then
    transaction_failed 'the API canary terminal object is not bound to this install attempt; it will not be deleted by name'
  fi
  canary_uid="$CAPTURE_UID"
  canary_resource_version="$CAPTURE_RESOURCE_VERSION"
  conditional_delete_entry "$canary_entry" "$canary_uid" "$canary_resource_version" || \
    warn 'API canary conditional-delete response was unsuccessful or lost; proving the exact UID is gone'
  attempt_uid_is_gone "$canary_entry" "$canary_uid" || \
    transaction_failed 'the API canary UID could not be proven gone after its preconditioned delete'
  after="$(probe_labels pod "$CANARY_NAME" namespaced)"
  if [[ "$after" != 'ABSENT' ]]; then
    transaction_failed 'the API canary name is no longer absent; a concurrent foreign replacement remains untouched and controller creation is blocked'
  fi
  note 'phase api-canary: authenticated in-cluster API path proved; ephemeral Pod is absent'
}

deployment_is_fully_ready() {
  local deployment="$1"
  local status_error="${work}/readiness-${deployment}.err"
  local status=''
  local generation='' desired='' observed='' current='' updated=''
  local available='' ready='' unavailable='' marker='' extra=''
  if ! status="$(kube -n "$INSTALL_NAMESPACE" get deployment "$deployment" \
      -o jsonpath='{.metadata.generation}{"|"}{.spec.replicas}{"|"}{.status.observedGeneration}{"|"}{.status.replicas}{"|"}{.status.updatedReplicas}{"|"}{.status.availableReplicas}{"|"}{.status.readyReplicas}{"|"}{.status.unavailableReplicas}{"|END"}' \
      2>"$status_error")"; then
    cat -- "$status_error" >&2
    die "could not read Deployment ${deployment}; the controllers are not installed"
  fi
  [[ ! -s "$status_error" ]] || {
    cat -- "$status_error" >&2
    die "Deployment ${deployment} readiness probe produced unexpected diagnostic output"
  }
  IFS='|' read -r generation desired observed current updated available ready unavailable marker extra <<<"$status"
  [[ -z "$extra" && "$marker" == 'END' ]] || \
    die "Deployment ${deployment} returned malformed readiness output; public egress stays shut"
  for value in "$generation" "$desired" "$observed" "$current" "$updated" "$available" "$ready"; do
    [[ "$value" =~ ^[0-9]+$ ]] || \
      die "Deployment ${deployment} returned malformed readiness output; public egress stays shut"
  done
  [[ -z "$unavailable" || "$unavailable" =~ ^[0-9]+$ ]] || \
    die "Deployment ${deployment} returned malformed unavailable-replica state; public egress stays shut"
  unavailable="${unavailable:-0}"
  [[ "$desired" -gt 0 && "$generation" -eq "$observed" \
     && "$current" -eq "$desired" && "$updated" -eq "$desired" \
     && "$available" -eq "$desired" && "$ready" -eq "$desired" \
     && "$unavailable" -eq 0 ]] || \
     die "Deployment ${deployment} is not fully current (${status}); public egress stays shut until every positive desired replica is observed, current, updated, available and ready with none unavailable"
}

attempt_manifests="${work}/attempt"
mkdir -p -- "$attempt_manifests"
prerequisites_attempt="${attempt_manifests}/phase-1-prerequisites.yaml"
startup_egress_attempt="${attempt_manifests}/phase-2-startup-egress.yaml"
canary_attempt="${attempt_manifests}/api-canary.yaml"
workloads_attempt="${attempt_manifests}/phase-3-workloads.yaml"
public_egress_attempt="${attempt_manifests}/phase-4-public-egress.yaml"
if [[ "$MODE" == '--apply' ]]; then
  annotate_manifest_for_attempt "$prerequisites" "$prerequisites_attempt" "$ATTEMPT_ID"
  annotate_manifest_for_attempt "$startup_egress" "$startup_egress_attempt" "$ATTEMPT_ID"
  annotate_manifest_for_attempt "$canary_rendered" "$canary_attempt" "$ATTEMPT_ID"
  annotate_manifest_for_attempt "$workloads" "$workloads_attempt" "$ATTEMPT_ID"
else
  annotate_manifest_for_attempt "$public_egress" "$public_egress_attempt" "$ATTEMPT_ID"
fi

if [[ "$MODE" == '--open-public-egress' ]]; then
  [[ "$cluster_state" == 'existing' ]] || \
    die 'flux-system is absent; public egress cannot be opened before the controller install exists'

  # HEALTHY: replica count is capacity, not a security constant. Accept N/N for
  # any positive N only when the controller has observed the current generation
  # and every desired replica is current, updated, available and ready.
  for deployment in "${CONTROLLER_DEPLOYMENTS[@]}"; do
    deployment_is_fully_ready "$deployment"
  done

  # IDLE: preserve kubectl's status separately from its bytes. An API, TLS,
  # timeout or RBAC failure is never converted into a zero-resource result.
  for crd_name in "${FLUX_CRDS[@]}"; do
    idle_key="${crd_name//./_}"
    idle_output="${work}/idle-${idle_key}.txt"
    idle_error="${work}/idle-${idle_key}.err"
    if ! kube get "$crd_name" --all-namespaces -o name >"$idle_output" 2>"$idle_error"; then
      cat -- "$idle_error" >&2
      die "could not prove ${crd_name} is empty; API/RBAC/timeout failure keeps public egress shut"
    fi
    [[ ! -s "$idle_error" ]] || {
      cat -- "$idle_error" >&2
      die "the ${crd_name} idle probe produced unexpected diagnostic output; public egress stays shut"
    }
    live_custom_resources=0
    while IFS= read -r resource_line; do
      [[ -n "$resource_line" ]] || continue
      resource_type="${resource_line%%/*}"
      resource_name="${resource_line#*/}"
      [[ "$resource_type" == "$crd_name" && "$resource_name" != "$resource_line" \
         && "$resource_name" =~ ^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$ ]] || \
        die "the ${crd_name} idle probe returned malformed output; public egress stays shut"
      ((live_custom_resources += 1))
    done <"$idle_output"
    [[ "$live_custom_resources" -eq 0 ]] || \
      die "the cluster carries ${live_custom_resources} ${crd_name} object(s); the controllers are reconciling, not idle, and public egress stays shut"
  done

  # Compare the live startup closure with the exact private endpoint-set render
  # and the one attempt identity that created it. A fresh attempt is used only
  # for the new public policy; it must not make the installed startup policies
  # appear drifted merely because their provenance marker is intentionally old.
  startup_install_attempt=''
  for policy in "${STARTUP_EGRESS_POLICIES[@]}"; do
    startup_entry="networkpolicy.networking.k8s.io/${policy}"
    if ! capture_entry_metadata "$startup_entry" || [[ "$CAPTURE_STATE" != 'present' ]]; then
      die "the startup egress policy ${policy} is not in the cluster; the namespace closure is not in the state this step extends"
    fi
    [[ "$CAPTURE_ATTEMPT" =~ ^[0-9a-f]{64}$ ]] || \
      die "the startup egress policy ${policy} carries no canonical install-attempt provenance"
    if [[ -z "$startup_install_attempt" ]]; then
      startup_install_attempt="$CAPTURE_ATTEMPT"
    elif [[ "$startup_install_attempt" != "$CAPTURE_ATTEMPT" ]]; then
      die 'the startup egress policies were not created by one atomic install attempt'
    fi
  done
  startup_expected="${work}/startup-egress-live-attempt.yaml"
  annotate_manifest_for_attempt "$startup_egress" "$startup_expected" "$startup_install_attempt"
  startup_shape="${work}/startup-shape.txt"
  if ! kube apply -f "$startup_expected" --dry-run=server >"$startup_shape" 2>&1; then
    cat -- "$startup_shape" >&2
    die 'could not compare the live startup egress policies with the reviewed render'
  fi
  live_unchanged="$(grep -cE '^networkpolicy\.networking\.k8s\.io/[a-z0-9-]+ unchanged( \((server )?dry run\))?$' "$startup_shape" || true)"
  live_lines="$(grep -cE '.' "$startup_shape" || true)"
  if [[ "$live_unchanged" -ne "$EXPECTED_STARTUP_POLICIES" || "$live_lines" -ne "$EXPECTED_STARTUP_POLICIES" ]]; then
    cat -- "$startup_shape" >&2
    die "the live startup egress policies are not the reviewed shape (${live_unchanged} of ${EXPECTED_STARTUP_POLICIES} unchanged across ${live_lines} line(s)); public egress stays shut over a closure nobody reviewed"
  fi

  public_prestate="$(probe_labels networkpolicy "$PUBLIC_EGRESS_POLICY" namespaced)"
  [[ "$public_prestate" == 'ABSENT' ]] || \
    die "NetworkPolicy ${PUBLIC_EGRESS_POLICY} already exists; this absent-only transaction never adopts, reconciles, or deletes pre-existing state"

  endpoint_snapshot_unchanged 'the public-policy prestate gate' || \
    die 'the authoritative Kubernetes endpoint set drifted before the public-policy mutation'
  TRANSACTION_OPEN='yes'
  create_exact_object 'public-HTTPS NetworkPolicy' "$public_egress_attempt" \
    "networkpolicy.networking.k8s.io/${PUBLIC_EGRESS_POLICY}"
  public_poststate="${work}/public-poststate.txt"
  if ! kube apply -f "$public_egress_attempt" --dry-run=server >"$public_poststate" 2>&1; then
    cat -- "$public_poststate" >&2
    transaction_failed 'the public-HTTPS policy was created but its exact poststate could not be proven'
  fi
  [[ "$(grep -cE '.' "$public_poststate" || true)" -eq 1 \
     && "$(grep -cE "^networkpolicy\.networking\.k8s\.io/${PUBLIC_EGRESS_POLICY} unchanged( \((server )?dry run\))?$" "$public_poststate" || true)" -eq 1 ]] || {
    cat -- "$public_poststate" >&2
    transaction_failed 'the public-HTTPS policy poststate differs from the exact reviewed object'
  }
  endpoint_snapshot_unchanged 'the public-policy poststate gate' || \
    transaction_failed 'the authoritative Kubernetes endpoint set drifted across the public-policy mutation'
  TRANSACTION_COMMITTED='yes'
  TRANSACTION_OPEN='no'
  note 'public HTTPS allowed; the absent-only transaction committed the exact reviewed policy'
  exit 0
fi

# From here an interrupt has something to undo, and every function the rollback
# path needs is defined. Set as late as possible and as one statement, so a
# signal can never call into a half-built transaction.
TRANSACTION_OPEN='yes'

# 1 — the namespace, its deny-all, the CRDs, the RBAC, the quota, the accounts,
#     and the Service. No Pod exists yet, so nothing is isolated yet either.
create_phase prerequisites "$prerequisites_attempt" "$EXPECTED_PREREQUISITES"
# 2 — the startup allows, bound to this run's API server. From here the
#     namespace denies by default and permits exactly DNS, the intra-namespace
#     artifact fetch, and the API server.
endpoint_snapshot_unchanged 'startup-policy creation' || \
  transaction_failed 'the authoritative Kubernetes endpoint set drifted before startup-policy creation'
create_phase startup-egress "$startup_egress_attempt" "$EXPECTED_STARTUP_POLICIES"
endpoint_snapshot_unchanged 'startup-policy poststate' || \
  transaction_failed 'the authoritative Kubernetes endpoint set drifted across startup-policy creation'
# 2b — prove the selected-CNI Service/API path from the controller boundary,
#      then remove and absence-prove the canary before any controller exists.
prove_api_path_then_remove_canary
endpoint_snapshot_unchanged 'the API canary boundary' || \
  transaction_failed 'the authoritative Kubernetes endpoint set drifted across the API canary proof'
# 3 — only now the controllers, which come up into a namespace where the flows
#     they need to elect a leader and sync a cache already exist.
create_phase workloads "$workloads_attempt" "$EXPECTED_WORKLOADS"
endpoint_snapshot_unchanged 'controller creation' || \
  transaction_failed 'the authoritative Kubernetes endpoint set drifted across controller creation'
TRANSACTION_COMMITTED='yes'
TRANSACTION_OPEN='no'

note 'created; Flux is installed and inert'
note 'the controllers start with DNS, the intra-namespace artifact fetch, and the API server allowed; public HTTPS is still denied'
note 'verify every positive desired controller replica is current/updated/available/ready with none unavailable and no Flux custom resource, then run --open-public-egress (docs/runbooks/flux-install.md)'
