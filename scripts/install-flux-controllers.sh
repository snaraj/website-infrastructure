#!/usr/bin/env bash
# Install the reviewed Flux controllers, and nothing else.
#
# Why this exists as its own entry point: bootstrap/flux/bootstrap.sh owns the
# secret-bearing and sync-applying ceremonies and stays code-blocked until the
# reviewed-blob launcher exists. The controllers-only install needs none of
# that machinery — no age identity, no Secret, no Flux custom resource, no
# credential of any kind — and it was authorized as a separate,
# inert-by-construction step. Encoding that step here, with its guardrails
# executable and reviewable, is strictly better than performing it as an ad-hoc
# command outside the repository.
#
# Three properties this script owns, each of which a runbook sentence alone
# could not deliver:
#
#   ORDERING. The reviewed controller bundle carries `allow-egress` patched to
#   podSelector {} + policyTypes [Ingress, Egress] with no rules, which on a
#   NetworkPolicy-enforcing CNI is a namespace-wide deny-all. Applying that
#   together with the three controller Deployments isolates the controllers at
#   the instant they are created: no DNS, no API server, no leader election, no
#   cache sync, so they can never reach 1/1 and the install deadlocks. The apply
#   is therefore ORDERED — the namespace, CRDs, RBAC and Services first, then
#   the startup egress allows (default-deny, DNS, the intra-namespace artifact
#   fetch, and the API server bound to the very endpoint this run targets), and
#   only then the Deployments. Public HTTPS stays shut until the controllers are
#   observed healthy and idle; --open-public-egress is that separate step and it
#   refuses to run while any controller is not 1/1.
#
#   BINDING. Nothing here runs against "whatever is on PATH" or "whatever the
#   ambient kubeconfig points at". kustomize and kubectl are checked against the
#   versions.env pins (kubectl by version AND by binary sha256, so a hostile
#   earlier-on-PATH shim cannot impersonate it); the render must come from a Git
#   checkout with no uncommitted modification to any install input and must hash
#   to the sha256 the reviewer signed off; and every single API operation
#   carries an explicit --kubeconfig/--context/--server whose context is proven
#   to resolve to exactly that server first.
#
#   TRANSACTION. `kubectl apply -f` is not atomic: a failure part-way leaves an
#   applied prefix, and 13 of this bundle's objects are CLUSTER-SCOPED (8 CRDs,
#   3 ClusterRoles, 2 ClusterRoleBindings) which no `delete namespace` can
#   remove. Every phase's apply output is parsed into an inventory ledger of the
#   objects THIS attempt created; on any failure the ledger is rolled back
#   newest-first and the absence of every one of them — cluster-scoped included
#   — is then proven. Objects that already existed are never adopted and never
#   deleted, and an object that exists under foreign ownership stops the install
#   before anything is applied.
#
# The offline guards refuse BEFORE contacting the cluster. The pre-apply gate
# then makes only read-only, non-mutating calls -- an existence and ownership
# probe of the objects the install creates, a client-side strict validation, and
# a server-side dry run -- and classifies their output fail-closed for both a
# fresh cluster (flux-system absent) and a reconcile of an existing one. See the
# gate below and docs/runbooks/flux-install.md. Nothing mutates until --apply.
#
#   --render  render, verify, and print the render sha256; no cluster contact
#   --plan    the same, plus the read-only pre-apply gate; no mutation
#   --apply   the same checks, then the ordered, ledger-backed apply
#   --open-public-egress  the deferred public-HTTPS allow, once 3/3 are 1/1
#
# --plan, --apply and --open-public-egress additionally require:
#   --kubeconfig PATH --context NAME --server https://ADDRESS:6443
#   --expect-render-sha256 HEX   (--plan and --apply)
#
# See docs/runbooks/flux-install.md for the surrounding ceremony.
set -euo pipefail
# Every byte this script writes -- the render, the address-substituted egress
# bundle, the apply ledger -- is operator-private, so the work directory and
# everything in it is created unreadable to anyone else from the first syscall.
umask 077

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
# The install target is a constant, never an argument. Applying the parent root
# would create the root GitRepository and Kustomization from gotk-sync.yaml;
# neither is suspended, so reconciliation of ./kubernetes/reconciliation would
# begin immediately with prune enabled. Making that unreachable is the single
# most important thing this script does.
INSTALL_TARGET='kubernetes/flux-system/controllers'
# The fail-closed egress overlay. Split by this script into the startup allows
# the controllers need in order to start at all, and the public-HTTPS allow that
# stays shut until they are observed healthy.
EGRESS_TARGET='kubernetes/flux-system/egress'
VERSIONS_FILE="${REPO_ROOT}/versions.env"
INSTALL_NAMESPACE='flux-system'
# The reviewed inventory: 1 Namespace, 8 CRDs, 3 ClusterRoles,
# 2 ClusterRoleBindings, 3 NetworkPolicies, 1 ResourceQuota, 3 ServiceAccounts,
# 1 Service, 3 Deployments. A render of a different size is not the reviewed
# install no matter what its digest says.
EXPECTED_OBJECTS=25
# The inventory splits by scope, which is what the fresh-cluster dry run below
# turns on: 14 cluster-scoped objects (the Namespace, 8 CRDs, 3 ClusterRoles,
# 2 ClusterRoleBindings) plus 11 objects that live IN flux-system (1
# ResourceQuota, 3 ServiceAccounts, 1 Service, 3 Deployments, 3 NetworkPolicies).
EXPECTED_CLUSTER_SCOPED=14
EXPECTED_NAMESPACED=11
# ... and it splits again by apply phase: the 3 controller Deployments are held
# back until their egress allows exist, so 22 objects go first.
EXPECTED_WORKLOADS=3
EXPECTED_PREREQUISITES=22
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
FLUX_CLUSTER_ROLES=(crd-controller-flux-system flux-edit-flux-system flux-view-flux-system)
FLUX_CLUSTER_ROLE_BINDINGS=(cluster-reconciler-flux-system crd-controller-flux-system)
CONTROLLER_DEPLOYMENTS=(source-controller kustomize-controller helm-controller)
# The generated export labels every one of its 25 objects with both of these.
# They are this install's ownership marker: an object that already exists and
# carries them is a previous run of THIS install; one that exists without them
# belongs to something else and is never adopted, reconfigured, or deleted.
OWNERSHIP_PART_OF='"app.kubernetes.io/part-of":"flux"'
OWNERSHIP_INSTANCE='"app.kubernetes.io/instance":"flux-system"'
# RFC 5737 TEST-NET-1: the committed API-server destination, which can never
# match a real endpoint. The real address is never committed; it is derived at
# apply time from the --server this run is explicitly bound to, which is also
# what makes the allow and the target provably the same cluster.
APISERVER_SENTINEL_CIDR='192.0.2.0/32'
APISERVER_PORT=6443

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
# The one line shape that puts an object into the rollback ledger. Only a real
# apply prints an unsuffixed "created"; a dry run never does, so a dry run can
# never enter anything into the ledger.
LEDGER_CREATED_LINE="^(${_cluster_scoped_kind}|${_namespaced_kind}) created\$"
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
    '  --render  render + verify + print the render sha256; contacts no cluster' \
    '  --plan    the same, plus the read-only pre-apply gate; no mutation' \
    '  --apply   the same checks, then the ordered, ledger-backed apply' \
    '  --open-public-egress  the deferred public-HTTPS allow, once 3/3 are 1/1' \
    '' \
    'Binding options (required by --plan, --apply, --open-public-egress):' \
    '  --kubeconfig PATH   the protected kubeconfig; never the ambient default' \
    '  --context NAME      the reviewed context; proven to resolve to --server' \
    '  --server URL        https://ADDRESS:6443 -- also the API-server allow' \
    '  --expect-render-sha256 HEX   the reviewed render digest (--plan/--apply)'
}

MODE=''
KUBECONFIG_PATH=''
KUBE_CONTEXT=''
KUBE_SERVER=''
EXPECT_RENDER_SHA256=''
APISERVER_ADDRESS=''

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
    --expect-render-sha256)
      require_value "$1" "$#"
      EXPECT_RENDER_SHA256="$2"
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
  [[ -n "$EXPECT_RENDER_SHA256" ]] || die '--expect-render-sha256 is required; an unasserted render digest binds nothing'
fi

# --- Tool identity -----------------------------------------------------------
#
# Codex demonstrated the gap this closes: a fake `kubectl` earlier on PATH
# produced 25 accepted dry-run lines, an accepted apply, and a clean exit --
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

[[ -f "$VERSIONS_FILE" ]] || die 'versions.env is missing; the tool pins cannot be read'

KUSTOMIZE_BIN="$(resolve_tool kustomize)"
kustomize_pin="$(pin_value KUSTOMIZE_VERSION)"
kustomize_reported="$("$KUSTOMIZE_BIN" version 2>/dev/null | head -n 1 | tr -d '[:space:]' || true)"
[[ "$kustomize_reported" == "$kustomize_pin" ]] || \
  die "the kustomize resolved from PATH reports '${kustomize_reported}'; versions.env pins ${kustomize_pin}"
# versions.env pins kubectl by digest but carries no kustomize checksum, so the
# strongest available kustomize binding is its self-reported version. That gap
# is a declared platform-lane ask (versions.env is not editable from this lane);
# until a KUSTOMIZE_*_SHA256 pin exists, the render digest below is what
# actually binds kustomize's OUTPUT, which is the property the install needs.

if [[ "$needs_cluster" == 'yes' ]]; then
  KUBECTL_BIN="$(resolve_tool kubectl)"
  kubectl_pin="$(pin_value KUBERNETES_VERSION)"
  kubectl_reported="$("$KUBECTL_BIN" version --client -o yaml 2>/dev/null \
    | grep -E '^[[:space:]]*gitVersion:' | head -n 1 | tr -d '[:space:]' || true)"
  kubectl_reported="${kubectl_reported#gitVersion:}"
  [[ "$kubectl_reported" == "$kubectl_pin" ]] || \
    die "the kubectl resolved from PATH reports '${kubectl_reported}'; versions.env pins ${kubectl_pin}"
  kubectl_digest="$(digest_of "$KUBECTL_BIN")"
  kubectl_digest_matched='no'
  for pin_key in KUBECTL_LINUX_AMD64_SHA256 KUBECTL_ARM64_SHA256; do
    if [[ "$kubectl_digest" == "$(pin_value "$pin_key")" ]]; then
      kubectl_digest_matched='yes'
    fi
  done
  [[ "$kubectl_digest_matched" == 'yes' ]] || \
    die 'the kubectl resolved from PATH matches no versions.env kubectl digest pin; refusing to run an unidentified binary against a cluster'
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
dirty_inputs=''
dirty_inputs="$("$GIT_BIN" -C "$REPO_ROOT" status --porcelain -- \
  "$INSTALL_TARGET" "$EGRESS_TARGET" versions.env scripts/install-flux-controllers.sh)"
if [[ -n "$dirty_inputs" ]]; then
  printf '%s\n' "$dirty_inputs" >&2
  die 'the install inputs carry uncommitted modifications; the render would not be the reviewed bytes'
fi

[[ -f "${REPO_ROOT}/${INSTALL_TARGET}/kustomization.yaml" ]] || \
  die "missing install root: ${INSTALL_TARGET}"
[[ -f "${REPO_ROOT}/${EGRESS_TARGET}/kustomization.yaml" ]] || \
  die "missing egress overlay root: ${EGRESS_TARGET}"

work="$(mktemp -d "${TMPDIR:-/tmp}/flux-controllers.XXXXXX")"
cleanup() {
  local status=$?
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT

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
split_documents "$rendered" '^kind: Deployment[[:space:]]*$' "$workloads" "$prerequisites"
workload_count="$(count_objects "$workloads")"
prerequisite_count="$(count_objects "$prerequisites")"
[[ "$workload_count" -eq "$EXPECTED_WORKLOADS" && "$prerequisite_count" -eq "$EXPECTED_PREREQUISITES" \
   && $((workload_count + prerequisite_count)) -eq "$EXPECTED_OBJECTS" ]] || \
  die "phase split wrong: ${prerequisite_count} prerequisite object(s) + ${workload_count} workload(s) is not ${EXPECTED_PREREQUISITES} + ${EXPECTED_WORKLOADS}"
# The whole point of the split is that no controller Pod exists before its
# egress allows do; a Deployment left in phase 1 would silently restore the
# deadlock this ordering exists to remove.
! grep -Eq '^kind: Deployment[[:space:]]*$' "$prerequisites" || \
  die 'a controller Deployment is still in the phase-1 bundle; the ordering that prevents the egress deadlock is broken'
[[ "$(grep -cE '^kind: Deployment[[:space:]]*$' "$workloads" || true)" -eq "$EXPECTED_WORKLOADS" ]] || \
  die 'the phase-3 bundle is not exactly the controller Deployments'
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
note "egress overlay sha256 $(digest_of "$egress_rendered") (${egress_count} policies, API-server destination unresolved)"

if [[ "$MODE" == '--render' ]]; then
  note 'RENDER only; no cluster was contacted and nothing was mutated'
  exit 0
fi

# --- Explicit target ---------------------------------------------------------
#
# The ambient default kubeconfig, context, and server are never used. Naming all
# three and proving the named context resolves to the named server is what makes
# "the cluster I meant" a checked fact rather than an assumption -- and the
# server address is then the same address the API-server egress allow is bound
# to, so the policy and the target cannot disagree.

[[ -f "$KUBECONFIG_PATH" ]] || die 'the --kubeconfig path is not a regular file'
[[ "$KUBE_SERVER" =~ ^https://([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]+)$ ]] || \
  die '--server must be https://<IPv4 address>:<port>; a NetworkPolicy selects destinations by address and can express nothing else'
APISERVER_ADDRESS="${BASH_REMATCH[1]}"
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

# --- The egress bundle, bound to this run's API server -----------------------
#
# The substitution lands only in the 0700 work directory: the address is host
# inventory, it never enters the checkout, and the file is removed by the exit
# trap. Nothing below ever prints this file. The replacement is index-based
# rather than a regex substitution so the sentinel is matched literally.

egress_bound="${work}/egress-bound.yaml"
apiserver_cidr="${APISERVER_ADDRESS}/32"
awk -v sentinel="$APISERVER_SENTINEL_CIDR" -v replacement="$apiserver_cidr" '
  {
    out = ""
    rest = $0
    while ((pos = index(rest, sentinel)) > 0) {
      out = out substr(rest, 1, pos - 1) replacement
      rest = substr(rest, pos + length(sentinel))
    }
    print out rest
  }
' "$egress_rendered" >"$egress_bound"
[[ "$(grep -cF -- "$APISERVER_SENTINEL_CIDR" "$egress_bound" || true)" -eq 0 ]] || \
  die 'the API-server sentinel survived substitution; the applied policy would grant nothing'
[[ "$(grep -cF -- "$apiserver_cidr" "$egress_bound" || true)" -eq 1 ]] || \
  die 'the substituted API-server destination does not appear exactly once'

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

if [[ "$MODE" == '--open-public-egress' ]]; then
  # The deferred step. It exists as a mode rather than a runbook paste so that
  # "only after the controllers are healthy" is a check, not an instruction.
  for deployment in "${CONTROLLER_DEPLOYMENTS[@]}"; do
    readiness=''
    readiness="$(kube -n "$INSTALL_NAMESPACE" get deployment "$deployment" \
      -o jsonpath='{.status.readyReplicas}/{.status.replicas}' 2>/dev/null)" || \
      die "could not read Deployment ${deployment}; the controllers are not installed"
    [[ "$readiness" == '1/1' ]] || \
      die "Deployment ${deployment} reports ${readiness}, not 1/1; public egress stays shut until every controller is healthy and idle"
  done
  for policy in "${STARTUP_EGRESS_POLICIES[@]}"; do
    kube -n "$INSTALL_NAMESPACE" get networkpolicy "$policy" -o name >/dev/null 2>&1 || \
      die "the startup egress policy ${policy} is not in the cluster; the namespace closure is not in the state this step extends"
  done
  kube apply -f "$public_egress" >"${work}/apply-public.txt" 2>&1 || {
    cat -- "${work}/apply-public.txt" >&2
    die 'the public-HTTPS allow failed to apply'
  }
  note 'public HTTPS allowed; the flux-system closure is now complete'
  exit 0
fi

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
# flux-system to exist, so it validates all 25 objects even on a fresh cluster.
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
elif grep -q 'not found' "$ns_state"; then
  cluster_state='fresh'
else
  cat -- "$ns_state" >&2
  die 'could not determine flux-system state; the API server did not answer NotFound'
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
  local probe_err="${work}/probe.err"
  local labels=''
  if labels="$(kube get "$kind" "$name" -o jsonpath='{.metadata.labels}' 2>"$probe_err")"; then
    printf '%s' "$labels"
    return 0
  fi
  if grep -q 'NotFound\|not found' "$probe_err"; then
    printf 'ABSENT'
    return 0
  fi
  cat -- "$probe_err" >&2
  die "could not determine whether ${kind}/${name} exists; the API server did not answer NotFound"
}

assert_not_foreign() {
  local kind="$1"
  local name="$2"
  local labels=''
  labels="$(probe_labels "$kind" "$name")"
  if [[ "$labels" == 'ABSENT' ]]; then
    return 0
  fi
  if [[ "$cluster_state" == 'fresh' ]]; then
    die "flux-system is absent but ${kind} ${name} already exists; clean up the residue of the earlier attempt before reinstalling"
  fi
  [[ "$labels" == *"$OWNERSHIP_PART_OF"* && "$labels" == *"$OWNERSHIP_INSTANCE"* ]] || \
    die "${kind} ${name} already exists and is not owned by this install; refusing to adopt, reconfigure, or roll back a foreign object"
}

if [[ "$cluster_state" == 'fresh' ]]; then
  fluxcd_crds="$(kube get customresourcedefinition -o name 2>/dev/null \
    | grep -c '\.fluxcd\.io$' || true)"
  [[ "$fluxcd_crds" -eq 0 ]] || \
    die "flux-system is absent but ${fluxcd_crds} fluxcd CRD(s) already exist"
else
  assert_not_foreign namespace "$INSTALL_NAMESPACE"
  for name in "${FLUX_CRDS[@]}"; do
    assert_not_foreign customresourcedefinition "$name"
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

if [[ "$MODE" == '--plan' ]]; then
  note 'PLAN only; no mutation attempted'
  note "apply order would be: ${EXPECTED_PREREQUISITES} prerequisites, then ${EXPECTED_STARTUP_POLICIES} startup egress allows, then ${EXPECTED_WORKLOADS} controller Deployments"
  exit 0
fi

# --- The ordered, inventory-bound transaction --------------------------------

LEDGER="${work}/created-by-this-attempt.txt"
: >"$LEDGER"

record_created() {
  local output="$1"
  local line=''
  while IFS= read -r line; do
    if [[ "$line" =~ ${LEDGER_CREATED_LINE} ]]; then
      printf '%s\n' "${line%% created}" >>"$LEDGER"
    fi
  done <"$output"
}

entry_is_cluster_scoped() {
  [[ "$1" =~ ^(namespace|customresourcedefinition\.apiextensions\.k8s\.io|clusterrole\.rbac\.authorization\.k8s\.io|clusterrolebinding\.rbac\.authorization\.k8s\.io)/ ]]
}

delete_entry() {
  local entry="$1"
  if entry_is_cluster_scoped "$entry"; then
    kube delete "$entry" --ignore-not-found --wait >/dev/null 2>&1 || true
  else
    kube delete "$entry" -n "$INSTALL_NAMESPACE" --ignore-not-found --wait >/dev/null 2>&1 || true
  fi
}

entry_exists() {
  local entry="$1"
  if entry_is_cluster_scoped "$entry"; then
    kube get "$entry" -o name >/dev/null 2>&1
  else
    kube get "$entry" -n "$INSTALL_NAMESPACE" -o name >/dev/null 2>&1
  fi
}

# Roll back exactly what this attempt created, newest first, and then PROVE the
# absence rather than trusting the delete's exit status. `kubectl delete
# namespace flux-system` -- the runbook's old whole-install undo -- cannot touch
# the 13 cluster-scoped objects, so the ledger is the only thing that makes the
# undo complete.
rollback() {
  local -a created=()
  local entry=''
  local index=0
  local -a residue=()
  mapfile -t created <"$LEDGER"
  if ((${#created[@]} == 0)); then
    warn 'rollback: this attempt created nothing; the cluster is unchanged'
    return 0
  fi
  warn "rollback: removing the ${#created[@]} object(s) this attempt created, newest first"
  for ((index = ${#created[@]} - 1; index >= 0; index--)); do
    delete_entry "${created[index]}"
  done
  for entry in "${created[@]}"; do
    if entry_exists "$entry"; then
      residue+=("$entry")
    fi
  done
  if ((${#residue[@]} > 0)); then
    warn "ROLLBACK INCOMPLETE: ${#residue[@]} object(s) still exist and need manual removal: ${residue[*]}"
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

apply_phase() {
  local label="$1"
  local manifest="$2"
  local expected="$3"
  local output="${work}/apply-${label}.txt"
  local rc=0
  local reported=''
  local total=''
  note "phase ${label}: applying ${expected} object(s)"
  kube apply -f "$manifest" >"$output" 2>&1 || rc=$?
  # The ledger is written BEFORE the failure is acted on: a partial apply still
  # created a prefix, and only a ledger that includes it can undo it.
  record_created "$output"
  if ((rc != 0)); then
    cat -- "$output" >&2
    transaction_failed "phase ${label} apply failed (kubectl exit ${rc}); a partial apply may have created objects"
  fi
  reported="$(grep -cE "$INVENTORY_MUTATION_LINE" "$output" || true)"
  total="$(grep -cE '.' "$output" || true)"
  if [[ "$reported" -ne "$expected" || "$total" -ne "$expected" ]]; then
    cat -- "$output" >&2
    transaction_failed "phase ${label} reported ${reported} reviewed object(s) across ${total} line(s); expected exactly ${expected}"
  fi
}

# 1 — the namespace, its deny-all, the CRDs, the RBAC, the quota, the accounts,
#     and the Service. No Pod exists yet, so nothing is isolated yet either.
apply_phase prerequisites "$prerequisites" "$EXPECTED_PREREQUISITES"
# 2 — the startup allows, bound to this run's API server. From here the
#     namespace denies by default and permits exactly DNS, the intra-namespace
#     artifact fetch, and the API server.
apply_phase startup-egress "$startup_egress" "$EXPECTED_STARTUP_POLICIES"
# 3 — only now the controllers, which come up into a namespace where the flows
#     they need to elect a leader and sync a cache already exist.
apply_phase workloads "$workloads" "$EXPECTED_WORKLOADS"

note 'applied; Flux is installed and inert'
note 'the controllers start with DNS, the intra-namespace artifact fetch, and the API server allowed; public HTTPS is still denied'
note 'verify 3/3 controllers 1/1 and no Flux custom resource, then run --open-public-egress (docs/runbooks/flux-install.md)'
