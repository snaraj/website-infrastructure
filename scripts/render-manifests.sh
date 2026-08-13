#!/usr/bin/env bash
set -euo pipefail

# Canonical offline render gate for every desired-state root. This proves
# source/schema/policy properties only; runtime admission/readiness is supplied
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

for tool in helm kustomize kubeconform conftest kyverno python3 mktemp; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# The workflow selects a mode once. Reclassifying here and requiring that exact
# mode closes both direct-invocation mistakes and a state change between the CI
# selector and renderer. The six-line record is parsed as data, never sourced.
mode_name="${MODE#--}"
release_plan=''
if ! release_plan="$(
  python3 -B "${REPO_ROOT}/scripts/validate_release_transition.py" plan \
    --expect-mode "$mode_name"
)"; then
  die "authoritative release state does not permit ${MODE}"
fi
mapfile -t release_plan_lines <<<"$release_plan"
((${#release_plan_lines[@]} == 6)) || die 'release transition plan has an invalid shape'
[[ "${release_plan_lines[0]}" == "mode=${mode_name}" ]] || die 'release transition mode does not match'
[[ "${release_plan_lines[1]}" =~ ^naranjo-online=(initial|staged|active)$ ]] || \
  die 'naranjo-online transition phase is invalid'
naranjo_phase="${BASH_REMATCH[1]}"
[[ "${release_plan_lines[2]}" =~ ^lidersea-com=(initial|staged|active)$ ]] || \
  die 'lidersea-com transition phase is invalid'
lidersea_phase="${BASH_REMATCH[1]}"
[[ "${release_plan_lines[3]}" =~ ^cloudflare-public=(initial|staged|active)$ ]] || \
  die 'cloudflare-public transition phase is invalid'
cloudflare_phase="${BASH_REMATCH[1]}"
[[ "${release_plan_lines[4]}" =~ ^any-website-active=(true|false)$ ]] || \
  die 'website safety-envelope summary is invalid'
any_website_active="${BASH_REMATCH[1]}"
[[ "${release_plan_lines[5]}" =~ ^any-workload-active=(true|false)$ ]] || \
  die 'workload activation summary is invalid'
any_workload_active="${BASH_REMATCH[1]}"

# The site charts (and their schema negative controls) live in the
# standalone site repositories and are validated by their own CI; this
# renderer covers the platform chart and the platform's Flux objects.

POLICY_KUSTOMIZATION="${REPO_ROOT}/policies/kyverno/kustomization.yaml"
[[ -f "$POLICY_KUSTOMIZATION" ]] || die "missing Kyverno policy kustomization: ${POLICY_KUSTOMIZATION}"

policy_resource_is_active() {
  local expected_file="$1"
  awk -v expected="$expected_file" '
    /^[[:space:]]*#/ {next}
    /^[^[:space:]]/ {
      in_resources = ($0 ~ /^resources:[[:space:]]*$/)
      next
    }
    in_resources && /^[[:space:]]*-[[:space:]]+/ {
      resource = $0
      sub(/^[[:space:]]*-[[:space:]]+/, "", resource)
      sub(/[[:space:]]+$/, "", resource)
      if (resource == expected) matches++
    }
    END {exit(matches == 1 ? 0 : 1)}
  ' "$POLICY_KUSTOMIZATION"
}

declare -a CORE_POLICY_FILES=(
  disallow-public-services
  disallow-tenant-media-payloads
  disallow-undiscovered-storage
  require-approved-images
  require-exact-tenant-networking
  require-release-readiness
  require-restricted-workloads
)
declare -a SIGNATURE_POLICY_INVENTORY_ARGS=()
if [[ "$MODE" == '--scaffold' ]]; then
  CORE_POLICY_FILES+=(require-zero-site-capacity)
  SIGNATURE_POLICY_INVENTORY_ARGS+=(--inventory staging)
elif [[ "$any_website_active" == 'true' ]]; then
  if policy_resource_is_active require-zero-site-capacity.yaml; then
    die 'a live or outer-reconcilable website refuses the still-active zero-site-capacity admission policy'
  fi
  SIGNATURE_POLICY_INVENTORY_ARGS+=(--inventory promoted)
elif policy_resource_is_active require-zero-site-capacity.yaml; then
  # A staged transition may retain the closed capacity gate. If present it is
  # still a core fail-closed policy and receives the same structural checks.
  CORE_POLICY_FILES+=(require-zero-site-capacity)
  SIGNATURE_POLICY_INVENTORY_ARGS+=(--inventory staging --inventory promoted)
else
  # The sentinel may be removed in the same reviewed transition that prepares
  # activation, but no third inventory or Kustomize transform is permitted.
  SIGNATURE_POLICY_INVENTORY_ARGS+=(--inventory staging --inventory promoted)
fi
policy_name=''
for policy_name in "${CORE_POLICY_FILES[@]}"; do
  policy_file="${REPO_ROOT}/policies/kyverno/${policy_name}.yaml"
  [[ -f "$policy_file" ]] || die "missing required Kyverno policy ${policy_name}"
  policy_resource_is_active "${policy_name}.yaml" || \
    die "required Kyverno policy ${policy_name}.yaml is not listed exactly once under kustomization resources"
  grep -Eq "^  name:[[:space:]]+${policy_name}$" "$policy_file" || die "Kyverno policy identity mismatch in ${policy_name}.yaml"
  grep -Eq '^  validationFailureAction:[[:space:]]+Enforce$' "$policy_file" || die "core Kyverno policy ${policy_name} is not Enforce"
  grep -Eq '^    failurePolicy:[[:space:]]+Fail$' "$policy_file" || die "core Kyverno policy ${policy_name} is not fail-closed"
done
python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" kustomization \
  --file "$POLICY_KUSTOMIZATION" \
  "${SIGNATURE_POLICY_INVENTORY_ARGS[@]}"
python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" admission-kustomization \
  --file "${REPO_ROOT}/kubernetes/platform/admission/kustomization.yaml"
python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" reconciliation-kustomization \
  --file "${REPO_ROOT}/kubernetes/reconciliation/kustomization.yaml"
python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" flux-system-kustomization \
  --file "${REPO_ROOT}/kubernetes/flux-system/kustomization.yaml"
python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" flux-sync \
  --file "${REPO_ROOT}/kubernetes/flux-system/gotk-sync.yaml"
declare -a SIGNATURE_POLICY_ROWS=(
  'naranjo-online|release-publisher.yml'
  'lidersea-com|release-publisher.yml'
)
signature_row='' signature_site='' signature_workflow=''
for signature_row in "${SIGNATURE_POLICY_ROWS[@]}"; do
  IFS='|' read -r signature_site signature_workflow <<<"$signature_row"
  # Reconcile-time half of the same identity tuple: the site's published chart
  # source must demand a cosign signature from exactly this site's tag-triggered
  # publisher before source-controller will produce an artifact from it.
  python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" chart-source \
    --file "${REPO_ROOT}/kubernetes/websites/${signature_site}/source.yaml" \
    --site "$signature_site"
  policy_name="require-signed-${signature_site}"
  policy_file="${REPO_ROOT}/policies/kyverno/${policy_name}.yaml"
  [[ -f "$policy_file" ]] || die "missing staged signature policy ${policy_name}"
  policy_resource_is_active "${policy_name}.yaml" || \
    die "signature policy ${policy_name}.yaml is not listed exactly once under kustomization resources"
  python3 -B "${REPO_ROOT}/scripts/validate_signature_policy.py" policy \
    --file "$policy_file" \
    --site "$signature_site" \
    --workflow "$signature_workflow" \
    --action Audit \
    --action Enforce
done

declare -a CHART_ROWS=(
  "cloudflare-public|cloudflare-public|kubernetes/platform/cloudflare-public/chart"
)
declare -a KUSTOMIZE_TARGETS=(
  kubernetes/reconciliation
  kubernetes/platform/prerequisites
  kubernetes/platform/admission
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

output="${ARTIFACT_ROOT}/policies-kyverno.yaml"
kustomize build "${REPO_ROOT}/policies/kyverno" >"$output"
[[ -s "$output" ]] || die 'Kyverno policy render was empty'
rendered_files+=("$output")

rendered=''
for rendered in "${rendered_files[@]}"; do
  kubeconform -strict -summary -ignore-missing-schemas "$rendered"
  conftest test --policy "${REPO_ROOT}/policies/conftest" "$rendered"
done

bash "${REPO_ROOT}/scripts/test-policy-fixtures.sh"
# The storage gate is expressed twice — Kyverno CEL at admission, Rego in CI —
# and the two engines evaluate degenerate shapes differently, so agreeing on
# text is not agreeing on behaviour. This feeds the same objects to both and
# fails on any disagreement.
bash "${REPO_ROOT}/scripts/test-storage-engine-parity.sh"
kyverno test "${REPO_ROOT}/tests/kubernetes/kyverno"

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

# Prove one site's rendered desired state denies exactly the fail-closed
# reasons its classified phase predicts, over that site's closed denial
# vocabulary. Required fragments alone cannot separate `initial` from `staged`
# — both remain suspended — so the fragments a phase forbids are asserted
# absent too. That absence is what proves a staged site's reviewed digest and
# readiness actually reached the rendered artifact, which before the site
# charts moved to their own repositories was proven by rendering the chart.
assert_site_release_phase() {
  local manifest="$1"
  local website="$2"
  local phase="$3"
  local suspended="HelmRelease ${website} remains suspended"
  local not_ready="HelmRelease ${website} is not marked ready"
  local zero_digest="HelmRelease ${website} still names the all-zero image digest"
  local uncanonical="HelmRelease ${website} does not name a canonical image digest"
  # A site root also renders that site's chart source, so the closed
  # vocabulary below is only exhaustive if it names that object's denials too.
  # A correct chart source produces neither fragment in ANY phase, so both are
  # forbidden everywhere rather than required anywhere: an unverified or
  # misattributed chart source can never be an expected reason for this
  # artifact to be denied.
  local unverified="chart source ${website}/${website}-chart does not require cosign verification"
  local unbound="chart source ${website}/${website}-chart does not bind exactly one keyless publisher identity"
  local result='' fragment=''
  local -a required=() forbidden=()

  [[ -s "$manifest" ]] || die "missing rendered site artifact: $(basename -- "$manifest")"
  case "$phase" in
    initial)
      # The forbidden entry here is closed-vocabulary documentation rather
      # than a live check: the required all-zero denial already dominates it,
      # because the all-zero sentinel is canonical in shape. Listing the full
      # vocabulary in every arm is what makes the staged arm's forbidden set —
      # where these checks are load-bearing — obviously exhaustive.
      required=("$suspended" "$not_ready" "$zero_digest")
      forbidden=("$uncanonical" "$unverified" "$unbound")
      ;;
    staged)
      required=("$suspended")
      forbidden=("$not_ready" "$zero_digest" "$uncanonical" "$unverified" "$unbound")
      ;;
    active)
      # An active site must satisfy the release policy outright; that single
      # accepting pass already proves every forbidden fragment is absent.
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
  # desired state remains inert until promotion and capacity/runtime evidence.
  expect_release_rejection "${REPO_ROOT}/tests/kubernetes/fixtures/release-deny/missing-readiness.yaml" \
    'Deployment readiness-missing is not marked ready'
  expect_release_rejection "${ARTIFACT_ROOT}/helm-cloudflare-public.yaml" 'cloudflared tunnel token revision remains unresolved'
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-platform-admission.yaml" 'Deployment kyverno-admission-controller is not marked ready'
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-platform-admission.yaml" 'container kyverno still uses the all-zero digest'
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-platform-prerequisites.yaml" \
    'site capacity gate remains closed or lacks a hash-bound reviewed budget in namespace naranjo-online'
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-platform-prerequisites.yaml" \
    'site capacity gate remains closed or lacks a hash-bound reviewed budget in namespace lidersea-com'
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-reconciliation.yaml" 'Kustomization admission remains suspended'
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-reconciliation.yaml" 'Kustomization platform-services remains suspended'
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-reconciliation.yaml" 'Kustomization naranjo-online remains suspended'
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-reconciliation.yaml" 'Kustomization lidersea-com remains suspended'
  assert_site_release_phase "${ARTIFACT_ROOT}/kubernetes-websites-naranjo-online.yaml" \
    naranjo-online "$naranjo_phase"
  assert_site_release_phase "${ARTIFACT_ROOT}/kubernetes-websites-lidersea-com.yaml" \
    lidersea-com "$lidersea_phase"
  expect_release_rejection "${ARTIFACT_ROOT}/kubernetes-platform-cloudflare-public-release.yaml" 'HelmRelease cloudflare-public remains suspended'
  expect_release_rejection "${ARTIFACT_ROOT}/policies-kyverno.yaml" 'signature admission policy require-signed-naranjo-online is not enforced'
  expect_release_rejection "${ARTIFACT_ROOT}/policies-kyverno.yaml" 'signature admission policy require-signed-lidersea-com is not enforced'
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
    # Any active workload requires reviewed controller/admission artifacts and
    # release-grade core policies, even if the connector is activated first.
    for output in \
      "${ARTIFACT_ROOT}/kubernetes-flux-system.yaml" \
      "${REPO_ROOT}/kubernetes/platform/admission/kyverno/controllers.yaml"; do
      conftest test --policy "${REPO_ROOT}/policies/release-conftest" "$output"
    done
    for policy_name in "${CORE_POLICY_FILES[@]}"; do
      conftest test --policy "${REPO_ROOT}/policies/release-conftest" \
        "${REPO_ROOT}/policies/kyverno/${policy_name}.yaml"
    done
  fi

  if [[ "$any_website_active" == 'true' ]]; then
    # A live child or active website parent additionally requires reviewed
    # capacity and enforced signatures. During ordered rollback/resume, desired
    # child suspension is not proof that Flux has observed it yet.
    for output in \
      "${ARTIFACT_ROOT}/kubernetes-platform-prerequisites.yaml" \
      "${ARTIFACT_ROOT}/policies-kyverno.yaml"; do
      conftest test --policy "${REPO_ROOT}/policies/release-conftest" "$output"
    done
  fi
fi

printf 'render-manifests: %s static artifact(s) passed schema/exposure/policy gates in %s\n' \
  "${#rendered_files[@]}" "$ARTIFACT_ROOT"
printf 'render-manifests: runtime admission/readiness remains unproven by design\n'
