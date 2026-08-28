#!/usr/bin/env bash
# Owner-attended, create-or-exact bootstrap for the permanent #189 boundary.
set -Eeuo pipefail

usage() {
  echo "usage: $0 KUBECONFIG CONTEXT https://API_BACKEND:6443 SELECTOR_SHA256 API_BACKEND/32 [...]" >&2
  exit 2
}

(( $# >= 5 )) || usage
kubeconfig=$1
context=$2
server=$3
selector_digest=$4
shift 4
root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd -P)"
validator="${root}/scripts/validate_platform_bootstrap.py"
cidr_args=()
for cidr in "$@"; do cidr_args+=(--api-cidr "$cidr"); done
common=(--selector-digest "$selector_digest" "${cidr_args[@]}")
kube=(kubectl --kubeconfig "$kubeconfig" --context "$context" --server "$server")
[[ -f "$kubeconfig" && ! -L "$kubeconfig" ]] || { echo "kubeconfig must be one explicit regular file" >&2; exit 2; }
for tool in cosign curl git jq kubectl mktemp python3; do command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }; done
preflight="$(python3 -I -B "$validator" preflight "${common[@]}" --server "$server")"
tag="$(jq -er .tag <<<"$preflight")"
sha="$(jq -er .sha <<<"$preflight")"
work="$(mktemp -d)"
chmod 700 "$work"
api='https://api.github.com/repos/snaraj/website-infrastructure'
asset='platform-release-identity.v1.json'; bundle='platform-release-identity.v1.json.sigstore.json'
trusted_root="${root}/cmd/platform-release-selector/trusted_root.json"
[[ -f "$trusted_root" && ! -L "$trusted_root" ]] || { echo "pinned Sigstore trusted root is unavailable" >&2; exit 2; }

public_get() { curl --fail --silent --show-error --location --max-filesize 4194304 --max-time 60 --proto '=https' --proto-redir '=https' --tlsv1.2 --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2026-03-10' --output "$2" "$1"; }
public_asset() { local record=$1 name=$2 output=$3 count=$4 id expected; [[ $count == 2 ]]; expected="[\"$asset\",\"$bundle\"]"; jq -e --argjson count "$count" --argjson expected "$expected" '(.assets|type=="array") and (.assets|length==$count) and (([.assets[].name]|sort)==($expected|sort))' "$record" >/dev/null; id="$(jq -er --arg name "$name" '[.assets[]|select(.name==$name)]|select(length==1)|.[0].id|select(type=="number" and .>0)' "$record")"; curl --fail --silent --show-error --location --max-filesize 4194304 --max-time 60 --proto '=https' --proto-redir '=https' --tlsv1.2 --header 'Accept: application/octet-stream' --header 'X-GitHub-Api-Version: 2026-03-10' --output "$output" "$api/releases/assets/$id"; }
get_live() { local namespace=${4:-flux-system}; "${kube[@]}" -n "$namespace" get "$1/$2" --ignore-not-found -o json >"$3"; }
render() { local state=${2:-target}; python3 -I -B "$validator" render --component "$1" "${common[@]}" --source-state "$state" --target-annotations "$work/target-annotations.json"; }
check_live() { local state=${5:-target}; python3 -I -B "$validator" check --component "$1" "${common[@]}" --live "$4" --suspend "$3" --source-state "$state" --target-annotations "$work/target-annotations.json"; }
verify_endpoints() { "${kube[@]}" -n default get endpointslice.discovery.k8s.io -l kubernetes.io/service-name=kubernetes -o json >"$work/endpoints.json"; python3 -I -B "$validator" api-endpoints "${cidr_args[@]}" --live "$work/endpoints.json"; }
capture_consumers() { local phase=$1 stem=$2; "${kube[@]}" get kustomizations.kustomize.toolkit.fluxcd.io --all-namespaces --request-timeout=15s -o json >"$work/$stem.kustomizations.json"; "${kube[@]}" get helmcharts.source.toolkit.fluxcd.io --all-namespaces --request-timeout=15s -o json >"$work/$stem.helmcharts.json"; "${kube[@]}" get helmreleases.helm.toolkit.fluxcd.io --all-namespaces --request-timeout=15s -o json >"$work/$stem.helmreleases.json"; "${kube[@]}" get externalartifacts.source.toolkit.fluxcd.io --all-namespaces --request-timeout=15s -o json >"$work/$stem.externalartifacts.json"; python3 -I -B "$validator" consumers "${common[@]}" --phase "$phase" --target-annotations "$work/target-annotations.json" --kustomizations-live "$work/$stem.kustomizations.json" --helmcharts-live "$work/$stem.helmcharts.json" --helmreleases-live "$work/$stem.helmreleases.json" --externalartifacts-live "$work/$stem.externalartifacts.json"; }
check_site_chain() { local restore_site=${1:-} key resource name namespace live; local -a args=(); for row in 'naranjo-online|Role|flux-controller-impersonation role.rbac.authorization.k8s.io flux-controller-impersonation naranjo-online' 'naranjo-online|RoleBinding|flux-controller-impersonation rolebinding.rbac.authorization.k8s.io flux-controller-impersonation naranjo-online' 'naranjo-online|ServiceAccount|helm-reconciler serviceaccount helm-reconciler naranjo-online' 'naranjo-online|Role|helm-reconciler role.rbac.authorization.k8s.io helm-reconciler naranjo-online' 'naranjo-online|RoleBinding|helm-reconciler rolebinding.rbac.authorization.k8s.io helm-reconciler naranjo-online' 'lidersea-com|Role|flux-controller-impersonation role.rbac.authorization.k8s.io flux-controller-impersonation lidersea-com' 'lidersea-com|RoleBinding|flux-controller-impersonation rolebinding.rbac.authorization.k8s.io flux-controller-impersonation lidersea-com' 'lidersea-com|ServiceAccount|helm-reconciler serviceaccount helm-reconciler lidersea-com' 'lidersea-com|Role|helm-reconciler role.rbac.authorization.k8s.io helm-reconciler lidersea-com' 'lidersea-com|RoleBinding|helm-reconciler rolebinding.rbac.authorization.k8s.io helm-reconciler lidersea-com'; do read -r key resource name namespace <<<"$row"; live="$work/site-chain-${namespace}-${resource%%.*}-${name}.json"; get_live "$resource" "$name" "$live" "$namespace"; [[ -s "$live" ]]; args+=(--site-chain-live "$key=$live"); done; [[ -z $restore_site ]] || args+=(--site "$restore_site"); python3 -I -B "$validator" site-chain "${args[@]}"; }
capture_site_children() { local site=$1 stem=$2; get_live networkpolicy.networking.k8s.io default-deny "$work/$stem.networkpolicy.json" "$site"; get_live ocirepository.source.toolkit.fluxcd.io "$site-chart" "$work/$stem.oci.json" "$site"; get_live helmrelease.helm.toolkit.fluxcd.io "$site" "$work/$stem.helmrelease.json" "$site"; [[ -s "$work/$stem.networkpolicy.json" && -s "$work/$stem.oci.json" && -s "$work/$stem.helmrelease.json" ]]; }
prove_site_children() { local site=$1 stem=$2; capture_site_children "$site" "$stem"; python3 -I -B "$validator" site-children "${common[@]}" --site "$site" --target-annotations "$work/target-annotations.json" --networkpolicy-live "$work/$stem.networkpolicy.json" --oci-live "$work/$stem.oci.json" --helmrelease-live "$work/$stem.helmrelease.json"; }
prove_site_ready() { local site=$1 stem=$2; prove_site_children "$site" "$stem"; python3 -I -B "$validator" oci-ready "${common[@]}" --site "$site" --target-annotations "$work/target-annotations.json" --oci-live "$work/$stem.oci.json"; python3 -I -B "$validator" helmrelease-ready "${common[@]}" --site "$site" --target-annotations "$work/target-annotations.json" --helmrelease-live "$work/$stem.helmrelease.json"; }
ensure() { local component=$1 resource=$2 name=$3 namespace=${4:-flux-system} desired="$work/$1.desired.json" live="$work/$1.live.json"; render "$component" >"$desired"; get_live "$resource" "$name" "$live" "$namespace"; if [[ ! -s "$live" ]]; then verify_endpoints; "${kube[@]}" -n "$namespace" create -f "$desired" >/dev/null; get_live "$resource" "$name" "$live" "$namespace"; fi; check_live "$component" "$resource" any "$live"; }
prove_revoked() { local answer; answer="$("${kube[@]}" auth can-i patch gitrepositories.source.toolkit.fluxcd.io --resource-name=flux-system --namespace=flux-system --as=system:serviceaccount:flux-system:platform-release-selector)"; [[ $answer == no ]]; }
quarantine_authority() { local live="$work/selector-rolebinding.live.json" request="$work/selector-rolebinding.quarantine.json"; get_live rolebinding.rbac.authorization.k8s.io platform-release-selector "$live"; if [[ ! -s "$live" ]]; then prove_revoked; return; fi; if python3 -I -B "$validator" check-rolebinding-quarantine "${common[@]}" --live "$live" 2>/dev/null; then prove_revoked; return; fi; python3 -I -B "$validator" quarantine-rolebinding "${common[@]}" --live "$live" >"$request"; "${kube[@]}" -n flux-system replace -f "$request" >/dev/null; get_live rolebinding.rbac.authorization.k8s.io platform-release-selector "$live"; python3 -I -B "$validator" check-rolebinding-quarantine "${common[@]}" --live "$live"; prove_revoked; }
prove_helm_revoked() { local site=$1 answer verb resource; for row in 'patch deployments.apps' 'create secrets' 'patch networkpolicies.networking.k8s.io'; do read -r verb resource <<<"$row"; answer="$("${kube[@]}" auth can-i "$verb" "$resource" --namespace "$site" --as "system:serviceaccount:$site:helm-reconciler")"; [[ $answer == no ]]; done; }
transition_helm_binding() { local site=$1 state=$2; local before="$work/$site.helm-binding.before.json" request="$work/$site.helm-binding.replace.json" after="$work/$site.helm-binding.after.json"; get_live rolebinding.rbac.authorization.k8s.io helm-reconciler "$before" "$site"; [[ -s "$before" ]]; if python3 -I -B "$validator" helm-binding-check --site "$site" --quarantined "$state" --live "$before"; then [[ $state == false ]] || prove_helm_revoked "$site"; return; fi; python3 -I -B "$validator" helm-binding-transition --site "$site" --quarantined "$state" --live "$before" >"$request"; [[ $state == true ]] || verify_endpoints; "${kube[@]}" -n "$site" replace -f "$request" >/dev/null; get_live rolebinding.rbac.authorization.k8s.io helm-reconciler "$after" "$site"; python3 -I -B "$validator" helm-binding-result --site "$site" --quarantined "$state" --before "$before" --after "$after"; [[ $state == false ]] || prove_helm_revoked "$site"; }
prove_both_helm_quarantined() { local n="$work/naranjo-online.helm-binding.live.json" l="$work/lidersea-com.helm-binding.live.json"; get_live rolebinding.rbac.authorization.k8s.io helm-reconciler "$n" naranjo-online; get_live rolebinding.rbac.authorization.k8s.io helm-reconciler "$l" lidersea-com; python3 -I -B "$validator" helm-bindings-quarantined --naranjo-live "$n" --lidersea-live "$l"; prove_helm_revoked naranjo-online; prove_helm_revoked lidersea-com; }
quarantine_helm_bindings() { transition_helm_binding naranjo-online true; transition_helm_binding lidersea-com true; prove_both_helm_quarantined; }
migrate_oci() { local site=$1; local before="$work/$site.oci.before.json" patch="$work/$site.oci.patch.json" after="$work/$site.oci.after.json"; get_live ocirepository.source.toolkit.fluxcd.io "$site-chart" "$before" "$site"; [[ -s "$before" ]]; if python3 -I -B "$validator" oci-check --site "$site" --target-annotations "$work/target-annotations.json" --live "$before" 2>/dev/null; then return; fi; prove_both_helm_quarantined; [[ $(check_site_chain) == quarantined ]]; python3 -I -B "$validator" oci-migration-patch --site "$site" --target-annotations "$work/target-annotations.json" --live "$before" >"$patch"; verify_endpoints; "${kube[@]}" -n "$site" patch ocirepository.source.toolkit.fluxcd.io "$site-chart" --type=json --patch-file "$patch" >/dev/null; get_live ocirepository.source.toolkit.fluxcd.io "$site-chart" "$after" "$site"; python3 -I -B "$validator" oci-migration-result --site "$site" --target-annotations "$work/target-annotations.json" --live "$before" --after "$after"; }
restore_authority() {
  local live="$work/selector-rolebinding.live.json" request="$work/selector-rolebinding.restore.json"
  # Site activation and quiescence can each take minutes. Wait out every old
  # selector token first, then re-read the complete selector authority and
  # network dependency chain at the actual restore boundary; an early proof is
  # insufficient against drift.
  wait_quiescent
  exact_existing selector-admission-policy validatingadmissionpolicy.admissionregistration.k8s.io platform-release-selector
  exact_existing selector-admission-binding validatingadmissionpolicybinding.admissionregistration.k8s.io platform-release-selector
  exact_existing selector-serviceaccount serviceaccount platform-release-selector
  exact_existing selector-role role.rbac.authorization.k8s.io platform-release-selector
  exact_existing selector-network-dns networkpolicy.networking.k8s.io platform-release-selector-dns
  exact_existing selector-network-public networkpolicy.networking.k8s.io platform-release-selector-public-https
  exact_existing selector-network-api networkpolicy.networking.k8s.io platform-release-selector-kube-apiserver
  exact_existing selector-cronjob cronjob.batch platform-release-selector flux-system true
  exact_existing parent-impersonation-role role.rbac.authorization.k8s.io flux-controller-impersonation
  exact_existing parent-impersonation-rolebinding rolebinding.rbac.authorization.k8s.io flux-controller-impersonation
  get_live rolebinding.rbac.authorization.k8s.io platform-release-selector "$live"
  if [[ ! -s "$live" ]]; then
    ensure selector-rolebinding rolebinding.rbac.authorization.k8s.io platform-release-selector
    return
  fi
  check_live selector-rolebinding rolebinding.rbac.authorization.k8s.io any "$live" 2>/dev/null && return
  python3 -I -B "$validator" restore-rolebinding "${common[@]}" --live "$live" >"$request"
  verify_endpoints
  "${kube[@]}" -n flux-system replace -f "$request" >/dev/null
  get_live rolebinding.rbac.authorization.k8s.io platform-release-selector "$live"
  check_live selector-rolebinding rolebinding.rbac.authorization.k8s.io any "$live"
}
wait_quiescent() { local cron="$work/selector-cronjob.live.json" jobs="$work/selector-jobs.live.json" pods="$work/selector-pods.live.json"; get_live cronjob.batch platform-release-selector "$cron"; check_live selector-cronjob cronjob.batch true "$cron"; for (( poll=0; poll<120; poll++ )); do "${kube[@]}" -n flux-system get jobs.batch -o json >"$jobs"; "${kube[@]}" -n flux-system get pods -o json >"$pods"; python3 -I -B "$validator" selector-quiescence --cronjob-live "$cron" --jobs-live "$jobs" --pods-live "$pods" && return; sleep 5; done; python3 -I -B "$validator" selector-quiescence --cronjob-live "$cron" --jobs-live "$jobs" --pods-live "$pods"; }
replace_suspend() { local component=$1 resource=$2 name=$3 state=$4 live="$work/$1.live.json" request="$work/$1.replace.json"; get_live "$resource" "$name" "$live"; check_live "$component" "$resource" "$state" "$live" && return 0; verify_endpoints; python3 -I -B "$validator" replace --component "$component" "${common[@]}" --live "$live" --suspend "$state" >"$request"; "${kube[@]}" -n flux-system replace -f "$request" >/dev/null; get_live "$resource" "$name" "$live"; check_live "$component" "$resource" "$state" "$live"; }
contain() { local result=0 component resource name live request; set +e; for row in 'selector-cronjob cronjob.batch platform-release-selector' 'naranjo-kustomization kustomization.kustomize.toolkit.fluxcd.io naranjo-online-reconciler' 'lidersea-kustomization kustomization.kustomize.toolkit.fluxcd.io lidersea-com-reconciler'; do read -r component resource name <<<"$row"; live="$work/$component.live.json"; request="$work/$component.contain.json"; get_live "$resource" "$name" "$live" || { result=1; continue; }; [[ -s "$live" ]] || continue; check_live "$component" "$resource" true "$live" && continue; python3 -I -B "$validator" replace --component "$component" "${common[@]}" --live "$live" --suspend true >"$request" && "${kube[@]}" -n flux-system replace -f "$request" >/dev/null && get_live "$resource" "$name" "$live" && check_live "$component" "$resource" true "$live" || result=1; done; set -e; return "$result"; }
# Invoked indirectly by ERR and signal traps.
# shellcheck disable=SC2329
on_failure() { local status=$?; (( status != 0 )) || status=1; trap - ERR INT TERM HUP; if [[ $mutations_armed == true ]]; then quarantine_helm_bindings || echo 'RECOVERY_REQUIRED: site Helm authority could not be revoked' >&2; quarantine_authority || echo 'RECOVERY_REQUIRED: selector authority could not be revoked' >&2; contain || echo 'RECOVERY_REQUIRED: one exact active object could not be suspended' >&2; fi; rm -rf -- "$work"; exit "$status"; }
is_ready() { local live="$work/$1.ready.json"; get_live "$2" "$3" "$live" && python3 -I -B "$validator" ready --component "$1" "${common[@]}" --live "$live" --tag "$4" --sha "$5" --source-state "${6:-target}" --target-annotations "$work/target-annotations.json"; }
wait_ready() { for (( poll=0; poll<480; poll++ )); do is_ready "$@" 2>/dev/null && return 0; sleep 5; done; is_ready "$@"; }
parent_attempted() { local site=$1 component=$2 name=$3; local live="$work/$site.parent.attempted.json"; get_live kustomization.kustomize.toolkit.fluxcd.io "$name" "$live"; python3 -I -B "$validator" parent-attempted "${common[@]}" --site "$site" --component "$component" --target-annotations "$work/target-annotations.json" --parent-live "$live" --tag "$tag" --sha "$sha"; }
wait_site_applied() { local site=$1 component=$2 name=$3 stem; for (( poll=0; poll<480; poll++ )); do stem="$site.applied.$poll"; if parent_attempted "$site" "$component" "$name" 2>/dev/null && prove_site_children "$site" "$stem" 2>/dev/null && python3 -I -B "$validator" oci-ready "${common[@]}" --site "$site" --target-annotations "$work/target-annotations.json" --oci-live "$work/$stem.oci.json" 2>/dev/null; then return; fi; sleep 5; done; parent_attempted "$site" "$component" "$name"; prove_site_children "$site" "$site.applied.final"; python3 -I -B "$validator" oci-ready "${common[@]}" --site "$site" --target-annotations "$work/target-annotations.json" --oci-live "$work/$site.applied.final.oci.json"; }
prove_parent_chain_exact() { local site=$1 prefix; case $site in naranjo-online) prefix=naranjo ;; lidersea-com) prefix=lidersea ;; *) return 1 ;; esac; exact_existing "$prefix-site-serviceaccount" serviceaccount "$site-reconciler"; exact_existing "$prefix-site-role" role.rbac.authorization.k8s.io flux-release-reconciler "$site"; exact_existing "$prefix-site-rolebinding" rolebinding.rbac.authorization.k8s.io "$site-reconciler" "$site"; }
prove_parent_activation_chain_exact() { local site=$1; exact_existing parent-impersonation-role role.rbac.authorization.k8s.io flux-controller-impersonation; exact_existing parent-impersonation-rolebinding rolebinding.rbac.authorization.k8s.io flux-controller-impersonation; prove_parent_chain_exact "$site"; }
activate_site() { local site=$1 component=$2 name=$3; prove_helm_revoked "$site"; prove_parent_activation_chain_exact "$site"; replace_suspend "$component" kustomization.kustomize.toolkit.fluxcd.io "$name" false; wait_site_applied "$site" "$component" "$name"; [[ $(check_site_chain "$site") == restore-ready ]]; prove_parent_activation_chain_exact "$site"; prove_helm_revoked "$site"; transition_helm_binding "$site" false; wait_ready "$component" kustomization.kustomize.toolkit.fluxcd.io "$name" "$tag" "$sha"; for (( poll=0; poll<480; poll++ )); do prove_site_ready "$site" "$site.ready.$poll" 2>/dev/null && return; sleep 5; done; prove_site_ready "$site" "$site.ready.final"; }
exact_existing() { local component=$1 resource=$2 name=$3 namespace=${4:-flux-system} suspend=${5:-any}; local live="$work/healthy.$component.json"; get_live "$resource" "$name" "$live" "$namespace"; [[ -s "$live" ]] && check_live "$component" "$resource" "$suspend" "$live"; }
healthy_no_write() { [[ $(check_site_chain) == active ]] && capture_consumers post healthy && exact_existing selector-admission-policy validatingadmissionpolicy.admissionregistration.k8s.io platform-release-selector && exact_existing selector-admission-binding validatingadmissionpolicybinding.admissionregistration.k8s.io platform-release-selector && exact_existing selector-serviceaccount serviceaccount platform-release-selector && exact_existing selector-role role.rbac.authorization.k8s.io platform-release-selector && exact_existing selector-rolebinding rolebinding.rbac.authorization.k8s.io platform-release-selector && exact_existing parent-impersonation-role role.rbac.authorization.k8s.io flux-controller-impersonation && exact_existing parent-impersonation-rolebinding rolebinding.rbac.authorization.k8s.io flux-controller-impersonation && exact_existing selector-network-dns networkpolicy.networking.k8s.io platform-release-selector-dns && exact_existing selector-network-public networkpolicy.networking.k8s.io platform-release-selector-public-https && exact_existing selector-network-api networkpolicy.networking.k8s.io platform-release-selector-kube-apiserver && exact_existing selector-cronjob cronjob.batch platform-release-selector flux-system false && exact_existing naranjo-site-serviceaccount serviceaccount naranjo-online-reconciler && exact_existing naranjo-site-role role.rbac.authorization.k8s.io flux-release-reconciler naranjo-online && exact_existing naranjo-site-rolebinding rolebinding.rbac.authorization.k8s.io naranjo-online-reconciler naranjo-online && exact_existing lidersea-site-serviceaccount serviceaccount lidersea-com-reconciler && exact_existing lidersea-site-role role.rbac.authorization.k8s.io flux-release-reconciler lidersea-com && exact_existing lidersea-site-rolebinding rolebinding.rbac.authorization.k8s.io lidersea-com-reconciler lidersea-com && is_ready source gitrepository.source.toolkit.fluxcd.io flux-system "$tag" "$sha" target && is_ready naranjo-kustomization kustomization.kustomize.toolkit.fluxcd.io naranjo-online-reconciler "$tag" "$sha" && is_ready lidersea-kustomization kustomization.kustomize.toolkit.fluxcd.io lidersea-com-reconciler "$tag" "$sha" && prove_site_ready naranjo-online healthy.naranjo && prove_site_ready lidersea-com healthy.lidersea && verify_endpoints; }
success() { mutations_armed=false; trap - ERR INT TERM HUP; rm -rf -- "$work"; echo "PASS: $tag selector and both direct site reconcilers are active at $sha"; exit 0; }
mutations_armed=false
trap on_failure ERR INT TERM HUP

# Prove the fully signed canonical target anonymously before any cluster write.
public_get "$api/releases/tags/$tag" "$work/release.json"
public_asset "$work/release.json" "$asset" "$work/$asset" 2
public_asset "$work/release.json" "$bundle" "$work/$bundle" 2
public_get "$api/git/ref/tags/$tag" "$work/ref.json"
tag_object="$(jq -er '.object.sha | select(type == "string")' "$work/ref.json")"; [[ $tag_object =~ ^[0-9a-f]{40}$ ]]
public_get "$api/git/tags/$tag_object" "$work/tag.json"
main_id="$(jq -er '.main_ci.run_id | select(type == "number")' "$work/$asset")"; main_attempt="$(jq -er '.main_ci.run_attempt | select(type == "number")' "$work/$asset")"
platform_id="$(jq -er '.platform_release.run_id | select(type == "number")' "$work/$asset")"; platform_attempt="$(jq -er '.platform_release.run_attempt | select(type == "number")' "$work/$asset")"
[[ $main_id =~ ^[1-9][0-9]*$ && $main_attempt =~ ^[1-9][0-9]*$ && $platform_id =~ ^[1-9][0-9]*$ && $platform_attempt =~ ^[1-9][0-9]*$ ]]
public_get "$api/actions/runs/$main_id/attempts/$main_attempt" "$work/main.json"
public_get "$api/actions/runs/$platform_id/attempts/$platform_attempt" "$work/platform.json"
mkdir "$work/anonymous-docker"
identity='https://github.com/snaraj/website-infrastructure/.github/workflows/platform-release.yml@refs/heads/main'; issuer='https://token.actions.githubusercontent.com'; image="ghcr.io/snaraj/website-infrastructure/platform-release-selector@$selector_digest"
env -u COSIGN_REPOSITORY cosign verify-blob --bundle "$work/$bundle" --trusted-root "$trusted_root" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$work/$asset" >/dev/null
python3 -I -B "$validator" remote --selector-digest "$selector_digest" --identity "$work/$asset" --bundle "$work/$bundle" --release-json "$work/release.json" --ref-json "$work/ref.json" --tag-json "$work/tag.json" --main-run-json "$work/main.json" --platform-run-json "$work/platform.json" >"$work/target-annotations.json"
selector_build_sha="$(jq -er '."selector-build-sha" | select(type == "string" and test("^[0-9a-f]{40}$") and . != "0000000000000000000000000000000000000000")' "$work/target-annotations.json")"
common+=(--selector-build-sha "$selector_build_sha")
env -u COSIGN_REPOSITORY DOCKER_CONFIG="$work/anonymous-docker" cosign verify --trusted-root "$trusted_root" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$image" >/dev/null
env -u COSIGN_REPOSITORY DOCKER_CONFIG="$work/anonymous-docker" cosign verify-attestation --trusted-root "$trusted_root" --type slsaprovenance1 --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$image" >"$work/attestations.jsonl"
python3 -I -B "$validator" attestation "${common[@]}" --live "$work/attestations.jsonl"
verify_endpoints
source_preflight="$work/source.preflight.json"
get_live gitrepository.source.toolkit.fluxcd.io flux-system "$source_preflight"
if [[ -s "$source_preflight" ]]; then
  check_live source gitrepository.source.toolkit.fluxcd.io any "$source_preflight" target
  capture_consumers post preflight
else
  [[ $tag == v0.1.41 ]]
  capture_consumers initial preflight
fi
site_chain_state="$(check_site_chain)"
[[ $site_chain_state == active || $site_chain_state == quarantined || $site_chain_state == mixed ]]
if [[ -s "$source_preflight" ]] && healthy_no_write 2>/dev/null; then success; fi
read -r -p "Type $tag to create/resume the suspended bootstrap boundary: " confirmation
[[ $confirmation == "$tag" ]]
mutations_armed=true

# Revoke selector authority and contain every exact suspendable object before
# repairing or proving admission and runtime components.
quarantine_helm_bindings
quarantine_authority
contain
ensure selector-cronjob cronjob.batch platform-release-selector
wait_quiescent
ensure selector-admission-policy validatingadmissionpolicy.admissionregistration.k8s.io platform-release-selector
ensure selector-admission-binding validatingadmissionpolicybinding.admissionregistration.k8s.io platform-release-selector
ensure selector-serviceaccount serviceaccount platform-release-selector
ensure selector-role role.rbac.authorization.k8s.io platform-release-selector
ensure parent-impersonation-role role.rbac.authorization.k8s.io flux-controller-impersonation
ensure parent-impersonation-rolebinding rolebinding.rbac.authorization.k8s.io flux-controller-impersonation
ensure selector-network-dns networkpolicy.networking.k8s.io platform-release-selector-dns
ensure selector-network-public networkpolicy.networking.k8s.io platform-release-selector-public-https
ensure selector-network-api networkpolicy.networking.k8s.io platform-release-selector-kube-apiserver
ensure naranjo-site-serviceaccount serviceaccount naranjo-online-reconciler; ensure naranjo-site-role role.rbac.authorization.k8s.io flux-release-reconciler naranjo-online; ensure naranjo-site-rolebinding rolebinding.rbac.authorization.k8s.io naranjo-online-reconciler naranjo-online
ensure lidersea-site-serviceaccount serviceaccount lidersea-com-reconciler; ensure lidersea-site-role role.rbac.authorization.k8s.io flux-release-reconciler lidersea-com; ensure lidersea-site-rolebinding rolebinding.rbac.authorization.k8s.io lidersea-com-reconciler lidersea-com
ensure naranjo-kustomization kustomization.kustomize.toolkit.fluxcd.io naranjo-online-reconciler
ensure lidersea-kustomization kustomization.kustomize.toolkit.fluxcd.io lidersea-com-reconciler
[[ $(check_site_chain) == quarantined ]]
capture_consumers contained before-source
migrate_oci naranjo-online
migrate_oci lidersea-com
# The OCI migrations can take time. Re-list the complete four-API consumer
# boundary immediately before the root source commit point so a newly appeared
# foreign consumer cannot ride the source creation race.
capture_consumers contained source-commit
source_live="$work/source.live.json"; get_live gitrepository.source.toolkit.fluxcd.io flux-system "$source_live"
if [[ ! -s "$source_live" ]]; then [[ $tag == v0.1.41 ]]; render source target >"$work/source.desired.json"; verify_endpoints; "${kube[@]}" -n flux-system create -f "$work/source.desired.json" >/dev/null; get_live gitrepository.source.toolkit.fluxcd.io flux-system "$source_live"; fi
check_live source gitrepository.source.toolkit.fluxcd.io any "$source_live" target
contain
wait_ready source gitrepository.source.toolkit.fluxcd.io flux-system "$tag" "$sha" target
replace_suspend selector-cronjob cronjob.batch platform-release-selector true
activate_site naranjo-online naranjo-kustomization naranjo-online-reconciler
activate_site lidersea-com lidersea-kustomization lidersea-com-reconciler
restore_authority
replace_suspend selector-cronjob cronjob.batch platform-release-selector false
healthy_no_write
success
