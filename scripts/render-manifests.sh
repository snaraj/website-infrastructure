#!/usr/bin/env bash
set -euo pipefail

# Canonical offline render gate for every desired-state root. This proves
# source/schema/policy properties only; runtime convergence/readiness is supplied
# separately by release-gate.sh.

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
ARTIFACT_ROOT="${REPO_ROOT}/.artifacts/rendered"
MODE="${1:---scaffold}"

die() {
  printf 'render-manifests: %s\n' "$*" >&2
  exit 1
}

case "$MODE" in
  --scaffold|--transition|--release) ;;
  -h|--help)
    printf '%s\n' \
      'Usage: scripts/render-manifests.sh [--scaffold|--transition|--release]' \
      '  --scaffold  require all three releases and both sites to remain inert (default)' \
      '  --transition require the exact safe phase of each independently staged release' \
      '  --release   require release-state policy to accept every rendered artifact'
    exit 0
    ;;
  *) die "unknown mode: ${MODE}" ;;
esac
(($# <= 1)) || die 'only one mode argument is accepted'

case "$ARTIFACT_ROOT" in
  "${REPO_ROOT}"/.artifacts/rendered) ;;
  *) die "refusing unsafe artifact path: ${ARTIFACT_ROOT}" ;;
esac
rm -rf -- "$ARTIFACT_ROOT"
mkdir -p -- "$ARTIFACT_ROOT"

temporary_values=()
cleanup_temporary_values() {
  local status=$?
  local temporary_value
  trap - EXIT
  for temporary_value in "${temporary_values[@]}"; do
    case "$temporary_value" in
      "${TMPDIR:-/tmp}"/website-infra-release-values.*) rm -f -- "$temporary_value" ;;
      *)
        printf 'render-manifests: refusing unsafe temporary values cleanup path\n' >&2
        status=1
        ;;
    esac
  done
  exit "$status"
}
trap cleanup_temporary_values EXIT

for tool in helm kustomize kubeconform conftest python3 mktemp; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# The workflow selects a mode once. Reclassifying here and requiring that exact
# mode closes both direct-invocation mistakes and a state change between the CI
# selector and renderer. The seven-line record is parsed as data, never sourced.
mode_name="${MODE#--}"
release_plan=''
if ! release_plan="$(
  python3 -B "${REPO_ROOT}/scripts/validate_release_transition.py" plan \
    --expect-mode "$mode_name"
)"; then
  die "authoritative release state does not permit ${MODE}"
fi
mapfile -t release_plan_lines <<<"$release_plan"
((${#release_plan_lines[@]} == 7)) || die 'release transition plan has an invalid shape'
[[ "${release_plan_lines[0]}" == "mode=${mode_name}" ]] || die 'release transition mode does not match'
[[ "${release_plan_lines[1]}" =~ ^naranjo-online=(staged|active)$ ]] || \
  die 'naranjo-online transition phase is invalid'
naranjo_phase="${BASH_REMATCH[1]}"
[[ "${release_plan_lines[2]}" =~ ^lidersea-com=(staged|active)$ ]] || \
  die 'lidersea-com transition phase is invalid'
lidersea_phase="${BASH_REMATCH[1]}"
[[ "${release_plan_lines[3]}" =~ ^cloudflare-public=(initial|staged|active)$ ]] || \
  die 'cloudflare-public transition phase is invalid'
cloudflare_phase="${BASH_REMATCH[1]}"
[[ "${release_plan_lines[4]}" =~ ^platform-services-suspended=(true|false)$ ]] || \
  die 'platform-services suspension summary is invalid'
[[ "${release_plan_lines[5]}" =~ ^any-website-active=(true|false)$ ]] || \
  die 'website safety-envelope summary is invalid'
any_website_active="${BASH_REMATCH[1]}"
[[ "${release_plan_lines[6]}" =~ ^any-workload-active=(true|false)$ ]] || \
  die 'workload activation summary is invalid'
any_workload_active="${BASH_REMATCH[1]}"

# The site charts (and their schema negative controls) live in the
# standalone site repositories and are validated by their own CI; this
# renderer covers the platform chart and the platform's Flux objects.

python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" flux-system-kustomization \
  --file "${REPO_ROOT}/kubernetes/flux-system/kustomization.yaml"
python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" flux-sync \
  --file "${REPO_ROOT}/kubernetes/flux-system/gotk-sync.yaml.in"
declare -a SIGNED_CHART_SITES=(
  naranjo-online
  lidersea-com
)
signature_site=''
for signature_site in "${SIGNED_CHART_SITES[@]}"; do
  # Reconcile-time half of the same identity tuple: the site's published chart
  # source must demand a cosign signature from exactly this site's publisher,
  # run at that repository's protected `main` branch, before source-controller
  # will produce an artifact from it.
  python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" chart-source \
    --file "${REPO_ROOT}/kubernetes/websites/${signature_site}/source.yaml" \
    --site "$signature_site"
done

declare -a CHART_ROWS=(
  "cloudflare-public|cloudflare-public|kubernetes/platform/cloudflare-public/chart"
)
declare -a KUSTOMIZE_TARGETS=(
  kubernetes/flux-system/canary
  kubernetes/flux-system/egress
  kubernetes/platform/prerequisites
  kubernetes/platform/cloudflare-public/release
  kubernetes/websites/naranjo-online
  kubernetes/websites/lidersea-com
)

rendered_files=()
row='' release_name='' namespace='' relative_chart='' chart_path='' output=''
release_values=''
for row in "${CHART_ROWS[@]}"; do
  IFS='|' read -r release_name namespace relative_chart <<<"$row"
  chart_path="${REPO_ROOT}/${relative_chart}"
  [[ -f "${chart_path}/Chart.yaml" ]] || die "missing required chart: ${relative_chart}"
  # Packaged/subchart dependencies are deliberately absent so this gate never
  # fetches mutable remote content while rendering a reviewed checkout.
  [[ ! -f "${chart_path}/Chart.lock" ]] || die "chart dependencies are not permitted: ${relative_chart}/Chart.lock"
  if [[ -d "${chart_path}/charts" ]] && find "${chart_path}/charts" -mindepth 1 -print -quit | grep -q .; then
    die "vendored chart dependencies are not permitted: ${relative_chart}/charts"
  fi
  helm_values_args=()
  if [[ "$MODE" != '--scaffold' ]]; then
    release_values="$(mktemp "${TMPDIR:-/tmp}/website-infra-release-values.${release_name}.XXXXXX")"
    temporary_values+=("$release_values")
    python3 -B "${REPO_ROOT}/scripts/validate_release_state.py" emit-values \
      --release "$release_name" >"$release_values"
    [[ -s "$release_values" ]] || die "effective HelmRelease values are empty for ${release_name}"
    helm_values_args=(--values "$release_values")
  fi
  helm lint "$chart_path" "${helm_values_args[@]}"
  output="${ARTIFACT_ROOT}/helm-${release_name}.yaml"
  helm template "$release_name" "$chart_path" --namespace "$namespace" \
    "${helm_values_args[@]}" >"$output"
  [[ -s "$output" ]] || die "Helm produced an empty render for ${release_name}"
  rendered_files+=("$output")
done

target='' output_name=''
for target in "${KUSTOMIZE_TARGETS[@]}"; do
  [[ -f "${REPO_ROOT}/${target}/kustomization.yaml" ]] || die "missing required Kustomize root: ${target}"
  output_name="${target//\//-}"
  output_name="${output_name//\\/-}"
  output="${ARTIFACT_ROOT}/${output_name}.yaml"
  kustomize build "${REPO_ROOT}/${target}" >"$output"
  [[ -s "$output" ]] || die "Kustomize produced an empty render for ${target}"
  rendered_files+=("$output")
done

# Flux bootstrap output is generated rather than handwritten. A scaffold can be
# statically checked without it, but release-gate.sh refuses release readiness
# until the generated controller artifact exists and is rendered here.
if [[ -f "${REPO_ROOT}/kubernetes/flux-system/controllers/gotk-components.yaml" ]]; then
  output="${ARTIFACT_ROOT}/kubernetes-flux-system.yaml"
  kustomize build "${REPO_ROOT}/kubernetes/flux-system" >"$output"
  [[ -s "$output" ]] || die 'Flux Kustomize render was empty'
  rendered_files+=("$output")
else
  [[ "$MODE" == '--scaffold' || "$any_workload_active" == 'false' ]] || \
    die 'Flux controller artifact is required whenever a workload is active'
  printf 'render-manifests: PENDING Flux controller render (gotk-components.yaml is absent)\n'
fi

rendered=''
for rendered in "${rendered_files[@]}"; do
  kubeconform -strict -summary -ignore-missing-schemas "$rendered"
  conftest test --policy "${REPO_ROOT}/policies/conftest" "$rendered"
done

bash "${REPO_ROOT}/scripts/test-policy-fixtures.sh"

expect_release_rejection() {
  local manifest="$1"
  local expected_fragment="$2"
  local result
  # An absent artifact makes Conftest exit non-zero for a reason that is not a
  # policy denial at all, which would otherwise be read as evidence of a
  # fail-closed property this gate never actually proved.
  [[ -s "$manifest" ]] || die "missing artifact for release proof: $(basename -- "$manifest")"
  if result="$(conftest test --policy "${REPO_ROOT}/policies/release-conftest" "$manifest" 2>&1)"; then
    die "release policy unexpectedly accepted fail-closed artifact $(basename -- "$manifest")"
  fi
  if ! grep -Fq -- "$expected_fragment" <<<"$result"; then
    printf '%s\n' "$result" >&2
    die "release policy rejected $(basename -- "$manifest") without proving: ${expected_fragment}"
  fi
}

# Prove staged versus active site state against the exact values-only contract
# and the independent exact-site chart-source verification denials.
assert_site_release_phase() {
  local manifest="$1"
  local website="$2"
  local phase="$3"
  local suspended="HelmRelease ${website} remains suspended"
  local invalid_values="HelmRelease ${website} values must contain exactly deploymentReady: true"
  local unverified="chart source ${website}/${website}-chart does not require cosign verification"
  local unbound="chart source ${website}/${website}-chart does not bind exactly one keyless publisher identity"
  local result='' fragment=''
  local -a required=() forbidden=()

  [[ -s "$manifest" ]] || die "missing rendered site artifact: $(basename -- "$manifest")"
  case "$phase" in
    staged)
      required=("$suspended")
      forbidden=("$invalid_values" "$unverified" "$unbound")
      ;;
    active)
      conftest test --policy "${REPO_ROOT}/policies/release-conftest" "$manifest"
      return 0
      ;;
    *) die "website ${website} carries an unclassifiable phase: ${phase}" ;;
  esac

  if result="$(conftest test --policy "${REPO_ROOT}/policies/release-conftest" "$manifest" 2>&1)"; then
    die "release policy unexpectedly accepted ${phase} site artifact $(basename -- "$manifest")"
  fi
  for fragment in "${required[@]}"; do
    if ! grep -Fq -- "$fragment" <<<"$result"; then
      printf '%s\n' "$result" >&2
      die "release policy rejected $(basename -- "$manifest") without proving: ${fragment}"
    fi
  done
  for fragment in "${forbidden[@]}"; do
    if grep -Fq -- "$fragment" <<<"$result"; then
      printf '%s\n' "$result" >&2
      die "${phase} website ${website} still denies: ${fragment}"
    fi
  done
}

if [[ "$MODE" == '--scaffold' ]]; then
  # These are negative controls, not readiness evidence. They prove the checked-in
  # desired state remains inert until the separately reviewed GitOps cutover
  # and its capacity/runtime evidence.
  expect_release_rejection "${REPO_ROOT}/tests/kubernetes/fixtures/release-deny/missing-readiness.yaml" \
    'Deployment readiness-missing is not marked ready'
  expect_release_rejection "${ARTIFACT_ROOT}/helm-cloudflare-public.yaml" 'cloudflared tunnel token revision remains unresolved'
  assert_site_release_phase "${ARTIFACT_ROOT}/kubernetes-websites-naranjo-online.yaml" \
    naranjo-online "$naranjo_phase"
  assert_site_release_phase "${ARTIFACT_ROOT}/kubernetes-websites-lidersea-com.yaml" \
    lidersea-com "$lidersea_phase"
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-platform-cloudflare-public-release.yaml" 'HelmRelease cloudflare-public remains suspended'
elif [[ "$MODE" == '--release' ]]; then
  for rendered in "${rendered_files[@]}"; do
    conftest test --policy "${REPO_ROOT}/policies/release-conftest" "$rendered"
  done
else
  # Transition mode validates each authoritative site at its classified phase.
  # Suspended parent/HelmRelease objects are accepted only because the strict
  # classifier already proved their exact identity and relationship. The proof
  # runs over the site's rendered Flux root, which is the desired state this
  # repository still renders now that each site chart lives in its own
  # repository and is gated by that repository's own CI.
  declare -A WEBSITE_PHASES=(
    [naranjo-online]="$naranjo_phase"
    [lidersea-com]="$lidersea_phase"
  )
  website=''
  for website in naranjo-online lidersea-com; do
    assert_site_release_phase "${ARTIFACT_ROOT}/kubernetes-websites-${website}.yaml" \
      "$website" "${WEBSITE_PHASES[$website]}"
  done

  if [[ "$cloudflare_phase" == 'initial' ]]; then
    expect_release_rejection "${ARTIFACT_ROOT}/helm-cloudflare-public.yaml" \
      'cloudflared tunnel token revision remains unresolved'
  else
    conftest test --policy "${REPO_ROOT}/policies/release-conftest" \
      "${ARTIFACT_ROOT}/helm-cloudflare-public.yaml"
  fi

  if [[ "$any_workload_active" == 'true' ]]; then
    # Every active workload still depends on the reviewed Flux controller
    # artifact. This validates source; live controller convergence is separate.
    conftest test --policy "${REPO_ROOT}/policies/release-conftest" \
      "${ARTIFACT_ROOT}/kubernetes-flux-system.yaml"
  fi

  if [[ "$any_website_active" == 'true' ]]; then
    # A live child or active website parent additionally requires reviewed
    # capacity. During ordered rollback/resume, desired child suspension is not
    # proof that Flux has observed it yet.
    conftest test --policy "${REPO_ROOT}/policies/release-conftest" \
      "${ARTIFACT_ROOT}/kubernetes-platform-prerequisites.yaml"
  fi
fi

printf 'render-manifests: %s static artifact(s) passed schema/exposure/policy gates in %s\n' \
  "${#rendered_files[@]}" "$ARTIFACT_ROOT"
printf 'render-manifests: runtime convergence/readiness remains unproven by design\n'
