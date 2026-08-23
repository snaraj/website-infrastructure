#!/usr/bin/env bash
# Complete the Release for the frozen owner-prepared v0.1.0 tag, then converge
# this exact main SHA. This transaction receives only the workflow write token;
# a separate prerequisite job proves the immutable-release server setting.
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${TAG:?TAG is required}"
: "${BASE_SHA:?BASE_SHA is required}"
: "${BASE_TAG:?BASE_TAG is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
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
tagger_name='github-actions[bot]'
tagger_email='41898282+github-actions[bot]@users.noreply.github.com'
recovery_source_sha='51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e'
recovery_tag='v0.1.0'

get_json() {
  local token="$1" url="$2" output="$3"
  curl --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --output "${output}" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --header "Authorization: Bearer ${token}" \
    "${url}"
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

write_current_notes() {
  python3 -I -B "${contract}" release-notes \
    --repository . --head "${SOURCE_SHA}" --tag "${TAG}" \
    --base-sha "${BASE_SHA}" --base-tag "${BASE_TAG}" > "${notes}"
}

write_predecessor_notes() {
  python3 -I -B "${contract}" release-notes \
    --repository . --head "${BASE_SHA}" --tag "${BASE_TAG}" > "${notes}"
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

preflight_publication_state() {
  local predecessor_tagger_date predecessor_message
  local recovery_tagger_date recovery_message recovery_release_state
  local current_tagger_date current_message current_tag_state current_release_state

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
  write_predecessor_notes
  classify_tag exact \
    "${BASE_SHA}" "${BASE_TAG}" "${predecessor_message}" \
    "${predecessor_tagger_date}" >/dev/null
  classify_release exact "${BASE_TAG}" "${BASE_SHA}" >/dev/null

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

  write_current_notes
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
  if classify_release exact "${TAG}" "${SOURCE_SHA}" >/dev/null 2>&1; then
    current_release_state=exact
  else
    classify_release absent "${TAG}" "${SOURCE_SHA}" >/dev/null
    current_release_state=absent
  fi
  if [ "${current_tag_state}" = absent ]; then
    test "${current_release_state}" = absent
  fi

  # Repeat the same closed classification after the complete first pass. A
  # tag or Release that changes while its sibling is inspected cannot cross a
  # later mutation boundary on the strength of a stale observation.
  write_predecessor_notes
  classify_tag exact \
    "${BASE_SHA}" "${BASE_TAG}" "${predecessor_message}" \
    "${predecessor_tagger_date}" >/dev/null
  classify_release exact "${BASE_TAG}" "${BASE_SHA}" >/dev/null
  write_recovery_notes "${recovery_source_sha}" "${recovery_tag}"
  classify_tag exact \
    "${recovery_source_sha}" "${recovery_tag}" "${recovery_message}" \
    "${recovery_tagger_date}" >/dev/null
  classify_release "${recovery_release_state}" "${recovery_tag}" \
    "${recovery_source_sha}" >/dev/null
  write_current_notes
  classify_tag "${current_tag_state}" \
    "${SOURCE_SHA}" "${TAG}" "${current_message}" \
    "${current_tagger_date}" >/dev/null
  classify_release "${current_release_state}" "${TAG}" "${SOURCE_SHA}" >/dev/null
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
  local tagger_date message tag_object
  local tag_race_verified release_race_verified attempt
  tagger_date="$(git show -s --format=%cI "${SOURCE_SHA}")"
  message="Platform release ${TAG} from ${SOURCE_SHA}"

  if classify_tag exact \
    "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null 2>&1; then
    printf 'verified existing %s at %s\n' "${TAG}" "${SOURCE_SHA}"
  else
    classify_tag absent \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    classify_release absent "${TAG}" "${SOURCE_SHA}" >/dev/null
    preflight_publication_state
    classify_tag absent \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    classify_release absent "${TAG}" "${SOURCE_SHA}" >/dev/null
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
    classify_release absent "${TAG}" "${SOURCE_SHA}" >/dev/null
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

  write_current_notes
  if classify_release exact "${TAG}" "${SOURCE_SHA}" >/dev/null 2>&1; then
    printf 'verified complete existing GitHub Release %s\n' "${TAG}"
  else
    classify_release absent "${TAG}" "${SOURCE_SHA}" >/dev/null
    classify_tag exact \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    preflight_publication_state
    write_current_notes
    classify_tag exact \
      "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
    classify_release absent "${TAG}" "${SOURCE_SHA}" >/dev/null
    if ! run_write_gh release create "${TAG}" --verify-tag \
      --target "${SOURCE_SHA}" \
      --title "Platform ${TAG}" --notes-file "${notes}"; then
      printf 'Release create did not succeed; checking for an exact concurrent winner\n' >&2
    fi
    release_race_verified=false
    for attempt in 1 2 3 4 5; do
      if classify_release exact "${TAG}" "${SOURCE_SHA}" >/dev/null 2>&1; then
        release_race_verified=true
        break
      fi
      sleep "${attempt}"
    done
    test "${release_race_verified}" = true
  fi
  classify_release exact "${TAG}" "${SOURCE_SHA}" >/dev/null
  classify_tag exact \
    "${SOURCE_SHA}" "${TAG}" "${message}" "${tagger_date}" >/dev/null
}

test "${SOURCE_SHA}" != "${recovery_source_sha}"
test "${TAG}" != "${recovery_tag}"
test "${SOURCE_SHA}" != "${BASE_SHA}"
test "${TAG}" != "${BASE_TAG}"
# Re-derive notes and the tag binding from the checked-out source and fetched
# immutable tag ledger before the first REST observation. Every later mutation
# boundary reaches the same derivation through the complete-state preflight.
write_current_notes
preflight_publication_state
complete_recovery_release
publish_current_release

unset write_token
