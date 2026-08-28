#!/usr/bin/env bash
# Complete the exact next platform Release while retaining the frozen v0.1.0
# recovery edge. This transaction receives only the workflow write token; a
# separate prerequisite job proves the immutable-release server setting.
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${TAG:?TAG is required}"
: "${BASE_SHA:?BASE_SHA is required}"
: "${BASE_TAG:?BASE_TAG is required}"
: "${MAIN_RUN_ID:?MAIN_RUN_ID is required}"
: "${MAIN_RUN_ATTEMPT:?MAIN_RUN_ATTEMPT is required}"
: "${SELECTOR_IMAGE_DIGEST:?SELECTOR_IMAGE_DIGEST is required}"
: "${SELECTOR_BUILD_SHA:?SELECTOR_BUILD_SHA is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
test -z "${IMMUTABLE_SETTINGS_TOKEN-}"
test -z "${ACTIONS_READ_TOKEN-}"
test -z "${CONTENTS_READ_TOKEN-}"
test -z "${GITHUB_TOKEN-}"
test -z "${GH_ENTERPRISE_TOKEN-}"
test -z "${GITHUB_ENTERPRISE_TOKEN-}"

# Keep the credential in a non-exported shell variable. Every external write
# child receives only the ordinary per-job GITHUB_TOKEN.
write_token="${GH_TOKEN}"
unset GH_TOKEN

contract='scripts/ci/platform_release_contract.py'
api_version='2026-03-10'
api="${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}"
ref_json="${RUNNER_TEMP}/platform-ref.json"
tag_json="${RUNNER_TEMP}/platform-tag.json"
release_json="${RUNNER_TEMP}/platform-release.json"
notes="${RUNNER_TEMP}/platform-notes.md"
identity_asset="${RUNNER_TEMP}/platform-release-identity.v1.json"
identity_bundle="${RUNNER_TEMP}/platform-release-identity.v1.json.sigstore.json"
identity_download="${RUNNER_TEMP}/platform-release-identity.download.json"
bundle_download="${RUNNER_TEMP}/platform-release-identity.sigstore.download.json"
asset_upload_json="${RUNNER_TEMP}/platform-release-asset-upload.json"
draft_marker="${RUNNER_TEMP}/platform-release-draft-marker.json"
draft_request="${RUNNER_TEMP}/platform-release-draft-request.json"
body_patch="${RUNNER_TEMP}/platform-release-body-patch.json"
publish_patch="${RUNNER_TEMP}/platform-release-publish-patch.json"
release_pages_json="${RUNNER_TEMP}/platform-release-pages.json"
burned_notes="${RUNNER_TEMP}/platform-burned-release-notes.md"
legacy_main_run_json="${RUNNER_TEMP}/platform-legacy-main-run.json"
legacy_platform_run_json="${RUNNER_TEMP}/platform-legacy-platform-run.json"
legacy_main_runs_json="${RUNNER_TEMP}/platform-legacy-main-runs.json"
legacy_platform_runs_json="${RUNNER_TEMP}/platform-legacy-platform-runs.json"
legacy_predecessor_json="${RUNNER_TEMP}/platform-legacy-predecessor.json"
tagger_name='github-actions[bot]'
tagger_email='41898282+github-actions[bot]@users.noreply.github.com'
recovery_source_sha='51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e'
recovery_tag='v0.1.0'
burned_base_sha='77f32682b45f7bed845b245e6477c11539b67bcd'
burned_base_tag='v0.1.41'
burned_source_sha='6d85c2b01dd4bd66add4192372b26bcdf1b0a951'
burned_tag='v0.1.42'
burned_draft_id='378336604'
burned_main_run_id='33152936164'
burned_platform_run_id='33153400419'
burned_run_attempt='1'
burned_selector_digest='sha256:c9f8d59013bc5ca9431e3ccd22227e4e05920746829318cacf1ccb70b17d2e61'
identity_asset_name='platform-release-identity.v1.json'
identity_bundle_name='platform-release-identity.v1.json.sigstore.json'
identity_subject='https://github.com/snaraj/website-infrastructure/.github/workflows/platform-release.yml@refs/heads/main'
identity_issuer='https://token.actions.githubusercontent.com'

get_json() {
  local token="$1" url="$2" output="$3"
  curl --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --output "${output}" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --header "Authorization: Bearer ${token}" \
    "${url}"
}

get_public_json() {
  local url="$1" output="$2"
  curl --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --output "${output}" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    "${url}"
}

download_identity_asset() {
  local token="$1" release_record="$2" name="$3" output="$4" count="$5"
  local asset_id status expected
  if [ "${count}" = 1 ]; then
    expected="[\"${identity_asset_name}\"]"
  else
    test "${count}" = 2
    expected="[\"${identity_asset_name}\",\"${identity_bundle_name}\"]"
  fi
  jq -e --argjson count "${count}" --argjson expected "${expected}" '
    (.assets | type == "array") and (.assets | length == $count) and
    (([.assets[].name] | sort) == ($expected | sort))' \
    "${release_record}" >/dev/null
  asset_id="$(jq -er --arg name "${name}" '
    [.assets[] | select(.name == $name)] | select(length == 1) |
    .[0].id | select(type == "number" and . > 0)' "${release_record}")"
  status="$(curl --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --output "${output}" --write-out '%{http_code}' \
    --header 'Accept: application/octet-stream' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --header "Authorization: Bearer ${token}" \
    "${api}/releases/assets/${asset_id}")"
  test "${status}" = 200
}

verify_identity_signature() {
  local identity="$1" bundle="$2"
  env -u COSIGN_REPOSITORY cosign verify-blob \
    --bundle "${bundle}" \
    --certificate-identity "${identity_subject}" \
    --certificate-oidc-issuer "${identity_issuer}" \
    "${identity}" >/dev/null
}

download_identity_pair() {
  local release_record="$1"
  download_identity_asset "${write_token}" "${release_record}" \
    "${identity_asset_name}" "${identity_download}" 2
  download_identity_asset "${write_token}" "${release_record}" \
    "${identity_bundle_name}" "${bundle_download}" 2
  verify_identity_signature "${identity_download}" "${bundle_download}"
}

upload_identity_asset() {
  local release_id="$1" name="$2" path="$3" status
  status="$(curl --silent --show-error \
    --proto '=https' --tlsv1.2 --request POST \
    --output "${asset_upload_json}" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header 'Content-Type: application/json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --header "Authorization: Bearer ${write_token}" \
    --data-binary "@${path}" \
    "https://uploads.github.com/repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets?name=${name}")"
  test "${status}" = 201
}

validate_identity_runs() {
  local identity="$1" main_id main_attempt platform_id platform_attempt
  main_id="$(jq -er '.main_ci.run_id | select(type == "number" and . > 0)' \
    "${identity}")"
  main_attempt="$(jq -er '.main_ci.run_attempt | select(type == "number" and . > 0)' \
    "${identity}")"
  platform_id="$(jq -er '.platform_release.run_id | select(type == "number" and . > 0)' \
    "${identity}")"
  platform_attempt="$(jq -er '.platform_release.run_attempt | select(type == "number" and . > 0)' \
    "${identity}")"
  test "$(get_public_json \
    "${api}/actions/runs/${main_id}/attempts/${main_attempt}" \
    "${legacy_main_run_json}")" = 200
  test "$(get_public_json \
    "${api}/actions/runs/${platform_id}/attempts/${platform_attempt}" \
    "${legacy_platform_run_json}")" = 200
  python3 -I -B "${contract}" identity-run-records \
    --identity "${identity}" \
    --main-run-json "${legacy_main_run_json}" \
    --platform-run-json "${legacy_platform_run_json}" >/dev/null
}

validate_selector_transition() {
  local predecessor_digest="$1" predecessor_build_sha="$2"
  [[ "${predecessor_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
  [[ "${predecessor_build_sha}" =~ ^[0-9a-f]{40}$ ]]
  [[ "${SELECTOR_IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]
  [[ "${SELECTOR_BUILD_SHA}" =~ ^[0-9a-f]{40}$ ]]

  if git diff --quiet "${BASE_SHA}" "${SOURCE_SHA}" -- \
    cmd/platform-release-selector internal/releaseselector go.mod; then
    test "${SELECTOR_IMAGE_DIGEST}" = "${predecessor_digest}"
    test "${SELECTOR_BUILD_SHA}" = "${predecessor_build_sha}"
  else
    test "${SELECTOR_IMAGE_DIGEST}" != "${predecessor_digest}"
    test "${SELECTOR_BUILD_SHA}" = "${SOURCE_SHA}"
    test "${SELECTOR_BUILD_SHA}" != "${predecessor_build_sha}"
  fi
}

run_write_gh() {
  GH_TOKEN="${write_token}" gh "$@"
}

classify_tag() {
  local required="$1" source_sha="$2" tag="$3" message="$4" tagger_date="$5"
  local status tag_object object_status
  local -a record_args=()
  status="$(get_json "${write_token}" \
    "${api}/git/ref/tags/${tag}" "${ref_json}")"
  if [ "${status}" = 200 ]; then
    tag_object="$(jq -er '.object.sha' "${ref_json}")"
    object_status="$(get_json "${write_token}" \
      "${api}/git/tags/${tag_object}" "${tag_json}")"
    test "${object_status}" = 200
    record_args=(--ref-json "${ref_json}" --tag-json "${tag_json}")
  fi
  python3 -I -B "${contract}" tag-state \
    --http-status "${status}" --require "${required}" "${record_args[@]}" \
    --tag "${tag}" --source-sha "${source_sha}" \
    --message "${message}" --tagger-name "${tagger_name}" \
    --tagger-email "${tagger_email}" --tagger-date "${tagger_date}"
}

write_recovery_notes() {
  local source_sha="$1" tag="$2"
  {
    printf '## Platform %s\n\n' "${tag}"
    printf "Immutable repository source: \`%s\`\n\n" "${source_sha}"
    printf 'This release names platform source only. It does not deploy, promote, mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n'
    printf "See \`CHANGELOG.md\` at this tag for the human-readable change record.\n"
  } > "${notes}"
}

write_current_identity() {
  local release_id="$1" tag_object_sha="$2"
  local main_run_id="${3:-${MAIN_RUN_ID}}"
  local main_run_attempt="${4:-${MAIN_RUN_ATTEMPT}}"
  local platform_run_id="${5:-${GITHUB_RUN_ID}}"
  local platform_run_attempt="${6:-${GITHUB_RUN_ATTEMPT}}"
  local selector_digest="${7:-${SELECTOR_IMAGE_DIGEST}}"
  python3 -I -B "${contract}" release-identity \
    --repository . --head "${SOURCE_SHA}" --tag "${TAG}" \
    --base-sha "${BASE_SHA}" --base-tag "${BASE_TAG}" \
    --tag-object-sha "${tag_object_sha}" --release-id "${release_id}" \
    --main-run-id "${main_run_id}" \
    --main-run-attempt "${main_run_attempt}" \
    --platform-run-id "${platform_run_id}" \
    --platform-run-attempt "${platform_run_attempt}" \
    --selector-image-digest "${selector_digest}" \
    --selector-build-sha "${SELECTOR_BUILD_SHA}" > "${identity_asset}"
}

write_current_notes() {
  python3 -I -B "${contract}" release-notes \
    --repository . --head "${SOURCE_SHA}" --tag "${TAG}" \
    --base-sha "${BASE_SHA}" --base-tag "${BASE_TAG}" > "${notes}"
}

write_current_draft_marker() {
  printf '{"schema":"https://snaraj.dev/schemas/platform-release-draft/v1","source_sha":"%s","tag":"%s"}\n' \
    "${SOURCE_SHA}" "${TAG}" > "${draft_marker}"
}

write_burned_notes() {
  python3 -I -B "${contract}" release-notes \
    --repository . --head "${burned_source_sha}" --tag "${burned_tag}" \
    --base-sha "${burned_base_sha}" --base-tag "${burned_base_tag}" \
    > "${burned_notes}"
}

list_release_pages() {
  run_write_gh api --paginate --slurp \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    "repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
    > "${release_pages_json}"
}

classify_current_draft() {
  local required="$1"
  write_current_draft_marker
  write_current_notes
  list_release_pages
  python3 -I -B "${contract}" release-draft-state \
    --releases-json "${release_pages_json}" --tag "${TAG}" \
    --source-sha "${SOURCE_SHA}" --title "Platform ${TAG}" \
    --body "${draft_marker}" --body "${notes}" --require "${required}"
}

classify_burned_draft() {
  local required="$1"
  write_burned_notes
  list_release_pages
  python3 -I -B "${contract}" release-draft-state \
    --releases-json "${release_pages_json}" --tag "${burned_tag}" \
    --source-sha "${burned_source_sha}" --title "Platform ${burned_tag}" \
    --body "${burned_notes}" --expected-release-id "${burned_draft_id}" \
    --expected-asset-count 2 --require "${required}"
}

validate_burned_partial() {
  local status digest
  status="$(get_json "${write_token}" \
    "${api}/releases/${burned_draft_id}" "${release_json}")"
  test "${status}" = 200
  write_burned_notes
  download_identity_pair "${release_json}"
  test "$(get_public_json \
    "${api}/actions/runs/${burned_main_run_id}/attempts/${burned_run_attempt}" \
    "${legacy_main_run_json}")" = 200
  test "$(get_public_json \
    "${api}/actions/runs/${burned_platform_run_id}/attempts/${burned_run_attempt}" \
    "${legacy_platform_run_json}")" = 200
  digest="$(python3 -I -B "${contract}" burned-partial-release-record \
    --release-json "${release_json}" --identity "${identity_download}" \
    --bundle "${bundle_download}" --body "${burned_notes}" \
    --main-run-json "${legacy_main_run_json}" \
    --platform-run-json "${legacy_platform_run_json}")"
  test "${digest}" = "${burned_selector_digest}"
  test "${digest}" = "${SELECTOR_IMAGE_DIGEST}"
  test "${SELECTOR_BUILD_SHA}" = "${burned_source_sha}"
}

classify_release() {
  local required="$1" tag="$2" source_sha="$3" status
  local -a record_args=()
  status="$(get_json "${write_token}" \
    "${api}/releases/tags/${tag}" "${release_json}")"
  if [ "${status}" = 200 ]; then
    record_args=(--release-json "${release_json}")
  fi
  python3 -I -B "${contract}" release-state \
    --http-status "${status}" --require "${required}" \
    "${record_args[@]}" --tag "${tag}" \
    --allow-grandfathered-main-target \
    --source-sha "${source_sha}" \
    --title "Platform ${tag}" --body "${notes}"
}

classify_current_release() {
  local required="$1" status tag_object tree_sha evidence_selector_digest
  local -a record_args=()
  status="$(get_json "${write_token}" \
    "${api}/releases/tags/${TAG}" "${release_json}")"
  if [ "${status}" = 200 ]; then
    tag_object="$(jq -er '.object.sha' "${ref_json}")"
    tree_sha="$(git rev-parse "${SOURCE_SHA}^{tree}")"
    download_identity_pair "${release_json}"
    evidence_selector_digest="$(python3 -I -B "${contract}" \
      selector-image-from-release --release-json "${release_json}" \
      --identity "${identity_download}" --bundle "${bundle_download}" \
      --tag "${TAG}" --source-sha "${SOURCE_SHA}" \
      --tag-object-sha "${tag_object}" --source-tree-sha "${tree_sha}" \
      --selector-build-sha "${SELECTOR_BUILD_SHA}")"
    test "${evidence_selector_digest}" = "${SELECTOR_IMAGE_DIGEST}"
    record_args=(--release-json "${release_json}" \
      --identity "${identity_download}" --bundle "${bundle_download}" \
      --tag-object-sha "${tag_object}" --source-tree-sha "${tree_sha}" \
      --selector-build-sha "${SELECTOR_BUILD_SHA}")
  fi
  python3 -I -B "${contract}" identity-release-state \
    --http-status "${status}" --require "${required}" \
    "${record_args[@]}" --tag "${TAG}" --source-sha "${SOURCE_SHA}" \
    --selector-build-sha "${SELECTOR_BUILD_SHA}"
}

classify_predecessor_release() {
  local status tag_object tree_sha legacy_main_run_id legacy_main_run_attempt
  local legacy_platform_run_id legacy_platform_run_attempt
  local predecessor_build_sha predecessor_selector_digest
  status="$(get_json "${write_token}" \
    "${api}/releases/tags/${BASE_TAG}" "${release_json}")"
  if [ "${BASE_SHA}" = "${burned_source_sha}" ] && \
     [ "${BASE_TAG}" = "${burned_tag}" ] && [ "${TAG}" = v0.1.43 ]; then
    test "${status}" = 404
    if classify_burned_draft exact >/dev/null 2>&1; then
      :
    else
      classify_burned_draft absent >/dev/null
    fi
    return
  fi
  test "${status}" = 200
  tag_object="$(jq -er '.object.sha' "${ref_json}")"
  if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then
    tree_sha="$(git rev-parse "${BASE_SHA}^{tree}")"
    download_identity_pair "${release_json}"
    predecessor_build_sha="$(jq -er '.selector.provenance.source_sha |
      select(type == "string" and test("^[0-9a-f]{40}$"))' \
      "${identity_download}")"
    predecessor_selector_digest="$(python3 -I -B "${contract}" \
      selector-image-from-release \
      --release-json "${release_json}" --identity "${identity_download}" \
      --bundle "${bundle_download}" --tag "${BASE_TAG}" \
      --source-sha "${BASE_SHA}" --tag-object-sha "${tag_object}" \
      --source-tree-sha "${tree_sha}" \
      --selector-build-sha "${predecessor_build_sha}")"
    validate_selector_transition \
      "${predecessor_selector_digest}" "${predecessor_build_sha}"
    validate_identity_runs "${identity_download}"
  else
    # v0.1.40 is the sole immutable zero-asset predecessor. Derive its exact
    # historical workflow attempts from filtered REST listings; v0.1.41 builds
    # the first selector and establishes the signed canonical asset format.
    test "${BASE_TAG}" = v0.1.40
    test "${TAG}" = v0.1.41
    tag_object="$(jq -er '.object.sha' "${ref_json}")"
    test "$(get_public_json \
      "${api}/actions/workflows/pull-request.yml/runs?branch=main&event=push&head_sha=${BASE_SHA}&status=success&per_page=100" \
      "${legacy_main_runs_json}")" = 200
    test "$(get_public_json \
      "${api}/actions/workflows/platform-release.yml/runs?branch=main&event=workflow_run&head_sha=${BASE_SHA}&status=success&per_page=100" \
      "${legacy_platform_runs_json}")" = 200
    python3 -I -B scripts/ci/validate_platform_predecessor.py \
      --repository . \
      --base-tag "${BASE_TAG}" --target-tag "${TAG}" \
      --release-json "${release_json}" \
      --ref-json "${ref_json}" --tag-json "${tag_json}" \
      --main-runs-json "${legacy_main_runs_json}" \
      --platform-runs-json "${legacy_platform_runs_json}" \
      --emit > "${legacy_predecessor_json}"
    test "$(jq -er '.source.merge_sha' "${legacy_predecessor_json}")" = \
      "${BASE_SHA}"
    test "$(jq -er '.tag.object_sha' "${legacy_predecessor_json}")" = \
      "${tag_object}"
    legacy_main_run_id="$(jq -er '.main_ci.run_id' \
      "${legacy_predecessor_json}")"
    legacy_main_run_attempt="$(jq -er '.main_ci.run_attempt' \
      "${legacy_predecessor_json}")"
    legacy_platform_run_id="$(jq -er '.platform_release.run_id' \
      "${legacy_predecessor_json}")"
    legacy_platform_run_attempt="$(jq -er '.platform_release.run_attempt' \
      "${legacy_predecessor_json}")"
    test "$(get_public_json \
      "${api}/actions/runs/${legacy_main_run_id}/attempts/${legacy_main_run_attempt}" \
      "${legacy_main_run_json}")" = 200
    test "$(get_public_json \
      "${api}/actions/runs/${legacy_platform_run_id}/attempts/${legacy_platform_run_attempt}" \
      "${legacy_platform_run_json}")" = 200
    python3 -I -B scripts/ci/validate_platform_predecessor.py \
      --repository . \
      --base-tag "${BASE_TAG}" --target-tag "${TAG}" \
      --release-json "${release_json}" \
      --ref-json "${ref_json}" --tag-json "${tag_json}" \
      --main-runs-json "${legacy_main_runs_json}" \
      --platform-runs-json "${legacy_platform_runs_json}" \
      --main-run-json "${legacy_main_run_json}" \
      --platform-run-json "${legacy_platform_run_json}"
  fi
}

preflight_publication_state() {
  local predecessor_tagger_date predecessor_message
  local recovery_tagger_date recovery_message recovery_release_state
  local current_tagger_date current_message current_tag_state current_release_state
  local current_draft_state

  predecessor_tagger_date="$(git show -s --format=%cI "${BASE_SHA}")"
  predecessor_message="Platform release ${BASE_TAG} from ${BASE_SHA}"
  recovery_tagger_date="$(git show -s --format=%cI "${recovery_source_sha}")"
  recovery_message="Platform release ${recovery_tag} from ${recovery_source_sha}"
  current_tagger_date="$(git show -s --format=%cI "${SOURCE_SHA}")"
  current_message="Platform release ${TAG} from ${SOURCE_SHA}"

  # Close all six remote objects before any mutation. The predecessor tag and
  # immutable Release are hard prerequisites for allocating the next patch.
  # The recovery tag must already be the exact owner-prepared annotated tag.
  # Both recovery/current Releases and the current tag may be reused only when
  # exact; every other present record is foreign, and a current Release without
  # its exact tag is impossible state.
  classify_tag exact \
    "${BASE_SHA}" "${BASE_TAG}" "${predecessor_message}" \
    "${predecessor_tagger_date}" >/dev/null
  classify_predecessor_release >/dev/null

  write_recovery_notes "${recovery_source_sha}" "${recovery_tag}"
  classify_tag exact \
    "${recovery_source_sha}" "${recovery_tag}" "${recovery_message}" \
    "${recovery_tagger_date}" >/dev/null
  if classify_release exact "${recovery_tag}" "${recovery_source_sha}" >/dev/null 2>&1; then
    recovery_release_state=exact
  else
    classify_release absent "${recovery_tag}" "${recovery_source_sha}" >/dev/null
    recovery_release_state=absent
  fi

  if classify_tag exact \
    "${SOURCE_SHA}" "${TAG}" "${current_message}" \
    "${current_tagger_date}" >/dev/null 2>&1; then
    current_tag_state=exact
  else
    classify_tag absent \
      "${SOURCE_SHA}" "${TAG}" "${current_message}" \
      "${current_tagger_date}" >/dev/null
    current_tag_state=absent
  fi
  if classify_current_release exact >/dev/null 2>&1; then
    current_release_state=exact
  else
    classify_current_release absent >/dev/null
    current_release_state=absent
  fi
  if classify_current_draft exact >/dev/null 2>&1; then
    current_draft_state=exact
  else
    classify_current_draft absent >/dev/null
    current_draft_state=absent
  fi
  if [ "${current_tag_state}" = absent ]; then
    test "${current_release_state}" = absent
    test "${current_draft_state}" = absent
  fi
  if [ "${current_release_state}" = exact ]; then
    test "${current_draft_state}" = absent
  fi
  if [ "${current_draft_state}" = exact ]; then
    test "${current_tag_state}" = exact
    test "${current_release_state}" = absent
  fi

  # Repeat the same closed classification after the complete first pass. A
  # tag or Release that changes while its sibling is inspected cannot cross a
  # later mutation boundary on the strength of a stale observation.
  classify_tag exact \
    "${BASE_SHA}" "${BASE_TAG}" "${predecessor_message}" \
    "${predecessor_tagger_date}" >/dev/null
  classify_predecessor_release >/dev/null
  write_recovery_notes "${recovery_source_sha}" "${recovery_tag}"
  classify_tag exact \
    "${recovery_source_sha}" "${recovery_tag}" "${recovery_message}" \
    "${recovery_tagger_date}" >/dev/null
  classify_release "${recovery_release_state}" "${recovery_tag}" \
    "${recovery_source_sha}" >/dev/null
  classify_tag "${current_tag_state}" \
    "${SOURCE_SHA}" "${TAG}" "${current_message}" \
    "${current_tagger_date}" >/dev/null
  classify_current_release "${current_release_state}" >/dev/null
  classify_current_draft "${current_draft_state}" >/dev/null
}

retire_burned_partial_draft() {
  local release_id status removed attempt tagger_date message
  if [ "${BASE_SHA}" != "${burned_source_sha}" ] || \
     [ "${BASE_TAG}" != "${burned_tag}" ] || [ "${TAG}" != v0.1.43 ]; then
    return
  fi
  tagger_date="$(git show -s --format=%cI "${burned_source_sha}")"
  message="Platform release ${burned_tag} from ${burned_source_sha}"
  classify_tag exact \
    "${burned_source_sha}" "${burned_tag}" "${message}" \
    "${tagger_date}" >/dev/null
  if release_id="$(classify_burned_draft exact 2>/dev/null)"; then
    test "${release_id}" = "${burned_draft_id}"
    validate_burned_partial
    test "$(classify_burned_draft exact)" = "${release_id}"
    classify_tag exact \
      "${burned_source_sha}" "${burned_tag}" "${message}" \
      "${tagger_date}" >/dev/null
    if ! run_write_gh api --method DELETE \
      --header 'Accept: application/vnd.github+json' \
      --header "X-GitHub-Api-Version: ${api_version}" \
      "repos/${GITHUB_REPOSITORY}/releases/${release_id}" >/dev/null; then
      printf 'draft Release delete did not succeed; checking the exact postcondition\n' >&2
    fi
    removed=false
    for attempt in 1 2 3 4 5; do
      status="$(get_json "${write_token}" \
        "${api}/releases/${release_id}" "${release_json}")"
      if [ "${status}" = 404 ] && classify_burned_draft absent >/dev/null; then
        removed=true
        break
      fi
      test "${status}" = 200
      validate_burned_partial
      sleep "${attempt}"
    done
    test "${removed}" = true
  else
    classify_burned_draft absent >/dev/null
  fi
  classify_tag exact \
    "${burned_source_sha}" "${burned_tag}" "${message}" \
    "${tagger_date}" >/dev/null
  classify_predecessor_release >/dev/null
}

complete_recovery_release() {
  local tagger_date message release_race_verified attempt
  tagger_date="$(git show -s --format=%cI "${recovery_source_sha}")"
  message="Platform release ${recovery_tag} from ${recovery_source_sha}"

  python3 -I -B "${contract}" recovery-release \
    --repository . --source-sha "${recovery_source_sha}" \
    --tag "${recovery_tag}" >/dev/null
  write_recovery_notes "${recovery_source_sha}" "${recovery_tag}"

  # The owner-prepared annotated tag is a hard prerequisite. This function has
  # no tag-create path: absence or foreign state fails before any remote write.
  classify_tag exact \
    "${recovery_source_sha}" "${recovery_tag}" "${message}" \
    "${tagger_date}" >/dev/null

  if classify_release exact "${recovery_tag}" "${recovery_source_sha}" >/dev/null 2>&1; then
    printf 'verified complete existing recovery Release %s\n' "${recovery_tag}"
  else
    classify_release absent "${recovery_tag}" "${recovery_source_sha}" >/dev/null
    classify_tag exact \
      "${recovery_source_sha}" "${recovery_tag}" "${message}" \
      "${tagger_date}" >/dev/null
    preflight_publication_state
    write_recovery_notes "${recovery_source_sha}" "${recovery_tag}"
    classify_tag exact \
      "${recovery_source_sha}" "${recovery_tag}" "${message}" \
      "${tagger_date}" >/dev/null
    classify_release absent "${recovery_tag}" "${recovery_source_sha}" >/dev/null
    if ! run_write_gh release create "${recovery_tag}" --verify-tag \
      --target "${recovery_source_sha}" \
      --title "Platform ${recovery_tag}" --notes-file "${notes}"; then
      printf 'recovery Release create did not succeed; checking for an exact concurrent winner\n' >&2
    fi
    release_race_verified=false
    for attempt in 1 2 3 4 5; do
      if classify_release exact "${recovery_tag}" "${recovery_source_sha}" >/dev/null 2>&1; then
        release_race_verified=true
        break
      fi
      sleep "${attempt}"
    done
    test "${release_race_verified}" = true
  fi
  classify_release exact "${recovery_tag}" "${recovery_source_sha}" >/dev/null
  classify_tag exact \
    "${recovery_source_sha}" "${recovery_tag}" "${message}" \
    "${tagger_date}" >/dev/null
}

publish_current_release() {
  local tagger_date message tag_object release_id tree_sha
  local tag_race_verified release_race_verified attempt
  tagger_date="$(git show -s --format=%cI "${SOURCE_SHA}")"
  message="Platform release ${TAG} from ${SOURCE_SHA}"

  if classify_tag exact \
    "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null 2>&1; then
    printf 'verified existing %s at %s\n' "${TAG}" "${SOURCE_SHA}"
  else
    classify_tag absent \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    classify_current_release absent >/dev/null
    preflight_publication_state
    classify_tag absent \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    classify_current_release absent >/dev/null
    tag_object="$(run_write_gh api --method POST \
      --header 'Accept: application/vnd.github+json' \
      --header "X-GitHub-Api-Version: ${api_version}" \
      "repos/${GITHUB_REPOSITORY}/git/tags" \
      -f tag="${TAG}" -f message="${message}" \
      -f object="${SOURCE_SHA}" -f type=commit \
      -f "tagger[name]=${tagger_name}" \
      -f "tagger[email]=${tagger_email}" \
      -f "tagger[date]=${tagger_date}" --jq '.sha')"
    preflight_publication_state
    classify_tag absent \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    classify_current_release absent >/dev/null
    if ! run_write_gh api --method POST \
      --header 'Accept: application/vnd.github+json' \
      --header "X-GitHub-Api-Version: ${api_version}" \
      "repos/${GITHUB_REPOSITORY}/git/refs" \
      -f ref="refs/tags/${TAG}" -f sha="${tag_object}" >/dev/null; then
      printf 'tag ref create did not succeed; checking for an exact concurrent winner\n' >&2
    fi
    tag_race_verified=false
    for attempt in 1 2 3 4 5; do
      if classify_tag exact \
        "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null 2>&1; then
        tag_race_verified=true
        break
      fi
      sleep "${attempt}"
    done
    test "${tag_race_verified}" = true
  fi
  classify_tag exact \
    "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
  write_current_draft_marker
  write_current_notes

  if classify_current_release exact >/dev/null 2>&1; then
    printf 'verified complete existing GitHub Release %s\n' "${TAG}"
  else
    classify_current_release absent >/dev/null
    classify_tag exact \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    preflight_publication_state
    classify_tag exact \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    classify_current_release absent >/dev/null

    # Reuse only one exact zero-asset draft for this source. GitHub may expose
    # its mutable tag as `untagged-<20 hex>` until the final publish PATCH.
    if release_id="$(classify_current_draft exact 2>/dev/null)"; then
      printf 'resuming exact zero-asset draft Release %s\n' "${release_id}"
    else
      classify_current_draft absent >/dev/null
      jq -n --arg tag "${TAG}" --arg target "${SOURCE_SHA}" \
        --arg name "Platform ${TAG}" --rawfile body "${draft_marker}" \
        '{body:$body,draft:true,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}' \
        > "${draft_request}"
      release_id="$(run_write_gh api --method POST \
        --header 'Accept: application/vnd.github+json' \
        --header "X-GitHub-Api-Version: ${api_version}" \
        "repos/${GITHUB_REPOSITORY}/releases" \
        --input "${draft_request}" --jq '.id')"
    fi
    [[ "${release_id}" =~ ^[1-9][0-9]*$ ]]
    test "$(get_json "${write_token}" "${api}/releases/${release_id}" \
      "${release_json}")" = 200
    test "$(python3 -I -B "${contract}" release-draft-state \
      --releases-json "${release_json}" --tag "${TAG}" \
      --source-sha "${SOURCE_SHA}" --title "Platform ${TAG}" \
      --body "${draft_marker}" --body "${notes}" \
      --expected-release-id "${release_id}" --require exact)" = "${release_id}"

    jq -n --arg tag "${TAG}" --arg target "${SOURCE_SHA}" \
      --arg name "Platform ${TAG}" --rawfile body "${notes}" \
      '{body:$body,draft:true,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}' \
      > "${body_patch}"
    run_write_gh api --method PATCH \
      --header 'Accept: application/vnd.github+json' \
      --header "X-GitHub-Api-Version: ${api_version}" \
      "repos/${GITHUB_REPOSITORY}/releases/${release_id}" \
      --input "${body_patch}" >/dev/null
    test "$(get_json "${write_token}" "${api}/releases/${release_id}" \
      "${release_json}")" = 200
    python3 -I -B "${contract}" release-draft-record \
      --release-json "${release_json}" --tag "${TAG}" \
      --source-sha "${SOURCE_SHA}" --title "Platform ${TAG}" \
      --body "${notes}" >/dev/null
    test "$(classify_current_draft exact)" = "${release_id}"

    tag_object="$(jq -er '.object.sha' "${ref_json}")"
    write_current_identity "${release_id}" "${tag_object}"
    env -u COSIGN_REPOSITORY cosign sign-blob --yes \
      --bundle "${identity_bundle}" "${identity_asset}" >/dev/null
    verify_identity_signature "${identity_asset}" "${identity_bundle}"
    upload_identity_asset "${release_id}" "${identity_asset_name}" \
      "${identity_asset}"
    upload_identity_asset "${release_id}" "${identity_bundle_name}" \
      "${identity_bundle}"
    test "$(get_json "${write_token}" "${api}/releases/${release_id}" \
      "${release_json}")" = 200
    download_identity_pair "${release_json}"
    cmp -s "${identity_asset}" "${identity_download}"
    cmp -s "${identity_bundle}" "${bundle_download}"
    tree_sha="$(git rev-parse "${SOURCE_SHA}^{tree}")"
    python3 -I -B "${contract}" staged-identity-release-record \
      --release-json "${release_json}" --identity "${identity_download}" \
      --bundle "${bundle_download}" \
      --tag "${TAG}" --source-sha "${SOURCE_SHA}" \
      --tag-object-sha "${tag_object}" \
      --source-tree-sha "${tree_sha}" \
      --selector-build-sha "${SELECTOR_BUILD_SHA}" >/dev/null

    jq -n --arg tag "${TAG}" --arg target "${SOURCE_SHA}" \
      --arg name "Platform ${TAG}" --rawfile body "${notes}" \
      '{body:$body,draft:false,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}' \
      > "${publish_patch}"
    run_write_gh api --method PATCH \
      --header 'Accept: application/vnd.github+json' \
      --header "X-GitHub-Api-Version: ${api_version}" \
      "repos/${GITHUB_REPOSITORY}/releases/${release_id}" \
      --input "${publish_patch}" >/dev/null
    release_race_verified=false
    for attempt in 1 2 3 4 5; do
      if classify_current_release exact >/dev/null 2>&1; then
        release_race_verified=true
        break
      fi
      sleep "${attempt}"
    done
    test "${release_race_verified}" = true
  fi
  classify_current_release exact >/dev/null
  classify_tag exact \
    "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
}

test "${SOURCE_SHA}" != "${recovery_source_sha}"
test "${TAG}" != "${recovery_tag}"
test "${SOURCE_SHA}" != "${BASE_SHA}"
test "${TAG}" != "${BASE_TAG}"
# Re-derive the tag binding from the checked-out source and fetched
# immutable tag ledger before the first REST observation. Every later mutation
# boundary reaches the same derivation through the complete-state preflight.
preflight_publication_state
complete_recovery_release
retire_burned_partial_draft
publish_current_release

unset write_token
