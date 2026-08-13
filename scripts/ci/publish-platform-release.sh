#!/usr/bin/env bash
# Converge one exact source SHA to its immutable annotated tag and GitHub Release.
# The workflow invokes this file directly so the same transaction, including
# every API-construction choice and retry path, runs in hostile tests.
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${TAG:?TAG is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

contract='scripts/ci/platform_release_contract.py'
api_version='2026-03-10'
api="${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}"
ref_json="${RUNNER_TEMP}/platform-ref.json"
tag_json="${RUNNER_TEMP}/platform-tag.json"
release_json="${RUNNER_TEMP}/platform-release.json"
immutable_json="${RUNNER_TEMP}/platform-immutable.json"
notes="${RUNNER_TEMP}/platform-notes.md"
tagger_name='github-actions[bot]'
tagger_email='41898282+github-actions[bot]@users.noreply.github.com'
tagger_date="$(git show -s --format=%cI "${SOURCE_SHA}")"
message="Platform release ${TAG} from ${SOURCE_SHA}"

get_json() {
  local url="$1"
  local output="$2"
  curl --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --output "${output}" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --header "Authorization: Bearer ${GH_TOKEN}" \
    "${url}"
}

# Refuse to create even the immutable-prefix tag if the server control has
# drifted. The Ready receipt checks the same authoritative endpoint before
# merge; this in-transaction GET closes the time between that receipt and use.
immutable_status="$(get_json "${api}/immutable-releases" "${immutable_json}")"
test "${immutable_status}" = 200
python3 -I -B "${contract}" immutable-settings \
  --settings-json "${immutable_json}" >/dev/null

classify_tag() {
  local required="$1" status tag_object object_status
  local -a record_args=()
  status="$(get_json "${api}/git/ref/tags/${TAG}" "${ref_json}")"
  if [ "${status}" = 200 ]; then
    tag_object="$(jq -er '.object.sha' "${ref_json}")"
    object_status="$(get_json "${api}/git/tags/${tag_object}" "${tag_json}")"
    test "${object_status}" = 200
    record_args=(--ref-json "${ref_json}" --tag-json "${tag_json}")
  fi
  python3 -I -B "${contract}" tag-state \
    --http-status "${status}" --require "${required}" "${record_args[@]}" \
    --tag "${TAG}" --source-sha "${SOURCE_SHA}" \
    --message "${message}" --tagger-name "${tagger_name}" \
    --tagger-email "${tagger_email}" --tagger-date "${tagger_date}"
}

if classify_tag exact >/dev/null 2>&1; then
  printf 'verified existing %s at %s\n' "${TAG}" "${SOURCE_SHA}"
else
  classify_tag absent >/dev/null
  tag_object="$(gh api --method POST \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    "repos/${GITHUB_REPOSITORY}/git/tags" \
    -f tag="${TAG}" \
    -f message="${message}" \
    -f object="${SOURCE_SHA}" \
    -f type=commit \
    -f "tagger[name]=${tagger_name}" \
    -f "tagger[email]=${tagger_email}" \
    -f "tagger[date]=${tagger_date}" \
    --jq '.sha')"
  if ! gh api --method POST \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    "repos/${GITHUB_REPOSITORY}/git/refs" \
    -f ref="refs/tags/${TAG}" -f sha="${tag_object}" >/dev/null; then
    printf 'tag ref create did not succeed; checking for an exact concurrent winner\n' >&2
  fi
  tag_race_verified=false
  for attempt in 1 2 3 4 5; do
    if classify_tag exact >/dev/null 2>&1; then
      tag_race_verified=true
      break
    fi
    sleep "${attempt}"
  done
  test "${tag_race_verified}" = true
  classify_tag exact >/dev/null
fi

{
  printf '## Platform %s\n\n' "${TAG}"
  printf "Immutable repository source: \`%s\`\n\n" "${SOURCE_SHA}"
  printf 'This release names platform source only. It does not deploy, promote, mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n'
  printf "See \`CHANGELOG.md\` at this tag for the human-readable change record.\n"
} > "${notes}"

classify_release() {
  local required="$1" status
  local -a record_args=()
  status="$(get_json "${api}/releases/tags/${TAG}" "${release_json}")"
  if [ "${status}" = 200 ]; then
    record_args=(--release-json "${release_json}")
  fi
  python3 -I -B "${contract}" release-state \
    --http-status "${status}" --require "${required}" \
    "${record_args[@]}" --tag "${TAG}" \
    --title "Platform ${TAG}" --body "${notes}"
}

if classify_release exact >/dev/null 2>&1; then
  printf 'verified complete existing GitHub Release %s\n' "${TAG}"
else
  classify_release absent >/dev/null
  # The tag is not locked until the Release exists. Close the last observable
  # pre-publication window after proving Release absence and before creating it.
  classify_tag exact >/dev/null
  if ! gh release create "${TAG}" --verify-tag \
    --title "Platform ${TAG}" --notes-file "${notes}"; then
    printf 'release create did not succeed; checking for an exact concurrent winner\n' >&2
  fi
  release_race_verified=false
  for attempt in 1 2 3 4 5; do
    if classify_release exact >/dev/null 2>&1; then
      release_race_verified=true
      break
    fi
    sleep "${attempt}"
  done
  test "${release_race_verified}" = true
  classify_release exact >/dev/null
fi

# Re-query both halves after create/reuse. An immutable Release locks its tag,
# but a foreign pre-lock race must never be accepted as a successful release.
classify_release exact >/dev/null
classify_tag exact >/dev/null
