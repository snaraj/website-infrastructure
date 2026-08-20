#!/usr/bin/env bash
# Resolve the exact tag-derived predecessor before the immutable-settings proof.
# This step is GET-only and carries a contents-read token, never publication or
# Administration authority.
set -euo pipefail

: "${CONTENTS_READ_TOKEN:?CONTENTS_READ_TOKEN is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
test -z "${GH_TOKEN-}"
test -z "${GITHUB_TOKEN-}"
test -z "${GH_ENTERPRISE_TOKEN-}"
test -z "${GITHUB_ENTERPRISE_TOKEN-}"
test -z "${IMMUTABLE_SETTINGS_TOKEN-}"
test -z "${ACTIONS_READ_TOKEN-}"

read_token="${CONTENTS_READ_TOKEN}"
unset CONTENTS_READ_TOKEN

contract='scripts/ci/platform_release_contract.py'
api_version='2026-03-10'
api="${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}"
ref_json="${RUNNER_TEMP}/platform-predecessor-ref.json"
tag_json="${RUNNER_TEMP}/platform-predecessor-tag.json"
release_json="${RUNNER_TEMP}/platform-predecessor-release.json"
notes="${RUNNER_TEMP}/platform-predecessor-notes.md"
tagger_name='github-actions[bot]'
tagger_email='41898282+github-actions[bot]@users.noreply.github.com'

get_json() {
  local url="$1" output="$2"
  curl --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --request GET \
    --output "${output}" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --header "Authorization: Bearer ${read_token}" \
    "${url}"
}

classify_predecessor_tag() {
  local source_sha="$1" tag="$2" message="$3" tagger_date="$4"
  local status tag_object object_status
  local -a record_args=()
  status="$(get_json "${api}/git/ref/tags/${tag}" "${ref_json}")"
  if [ "${status}" = 200 ]; then
    tag_object="$(jq -er '.object.sha' "${ref_json}")"
    object_status="$(get_json "${api}/git/tags/${tag_object}" "${tag_json}")"
    test "${object_status}" = 200
    record_args=(--ref-json "${ref_json}" --tag-json "${tag_json}")
  fi
  python3 -I -B "${contract}" tag-state \
    --http-status "${status}" --require exact "${record_args[@]}" \
    --tag "${tag}" --source-sha "${source_sha}" \
    --message "${message}" --tagger-name "${tagger_name}" \
    --tagger-email "${tagger_email}" --tagger-date "${tagger_date}" >/dev/null
}

classify_predecessor_release() {
  local required="$1" tag="$2" status
  local -a record_args=()
  status="$(get_json "${api}/releases/tags/${tag}" "${release_json}")"
  if [ "${status}" = 200 ]; then
    record_args=(--release-json "${release_json}")
  fi
  python3 -I -B "${contract}" release-state \
    --http-status "${status}" --require "${required}" \
    "${record_args[@]}" --tag "${tag}" \
    --title "Platform ${tag}" --body "${notes}" >/dev/null
}

for _attempt in {1..30}; do
  # Public tag refresh has no checkout credential. Only the REST reads below
  # receive the step-scoped contents-read token.
  git fetch --quiet --tags origin
  intent=''
  if intent="$(python3 -I -B "${contract}" release-window \
    --repository . --head "${SOURCE_SHA}")"; then
    :
  else
    status=$?
    test "${status}" -eq 3 || exit "${status}"
    sleep 10
    continue
  fi

  base_sha="$(jq -er '.base_sha' <<<"${intent}")"
  base_tag="$(jq -er '.base_tag' <<<"${intent}")"
  source_sha="$(jq -er '.source_sha' <<<"${intent}")"
  test "${source_sha}" = "${SOURCE_SHA}"
  test "${base_sha}" != "${SOURCE_SHA}"
  test -n "${base_tag}"
  python3 -I -B "${contract}" release-notes \
    --repository . --head "${base_sha}" --tag "${base_tag}" > "${notes}"
  tagger_date="$(git show -s --format=%cI "${base_sha}")"
  message="Platform release ${base_tag} from ${base_sha}"
  classify_predecessor_tag \
    "${base_sha}" "${base_tag}" "${message}" "${tagger_date}"
  if classify_predecessor_release exact "${base_tag}"; then
    :
  elif classify_predecessor_release absent "${base_tag}"; then
    # Only clean absence is contention.
    sleep 10
    continue
  else
    # The record may have changed from absent to exact between the closed
    # observations. Accept only that exact concurrent winner; a present
    # foreign, mutable, partial, draft, prerelease, wrong-author,
    # asset-bearing, or mismatched Release dies here.
    classify_predecessor_release exact "${base_tag}"
  fi
  printf 'attestation=PASS:%s:%s\n' \
    "${GITHUB_REPOSITORY}" "${SOURCE_SHA}" >> "${GITHUB_OUTPUT}"
  unset read_token
  exit 0
done

unset read_token
printf 'predecessor release did not become exact within the bounded wait\n' >&2
exit 1
