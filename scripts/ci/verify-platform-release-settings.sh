#!/usr/bin/env bash
# Verify immutable releases in a read-only job. The no-bypass release-tag
# ruleset is an owner-observed external Ready prerequisite because GitHub
# redacts bypass actors from read-only ruleset callers. This process never
# receives publication authority and emits only a sanitized value receipt.
set -euo pipefail

: "${IMMUTABLE_SETTINGS_TOKEN:?IMMUTABLE_SETTINGS_TOKEN is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"

# Never leave a write token ambient. Each read-only child receives the App token
# only for its bounded GET operation.
settings_token="${IMMUTABLE_SETTINGS_TOKEN}"
unset IMMUTABLE_SETTINGS_TOKEN
test -z "${GH_TOKEN-}"
test -z "${GITHUB_TOKEN-}"
test -z "${GH_ENTERPRISE_TOKEN-}"
test -z "${GITHUB_ENTERPRISE_TOKEN-}"

contract='scripts/ci/platform_release_contract.py'
api_version='2026-03-10'
immutable_json="${RUNNER_TEMP}/platform-immutable-settings.json"
receipt_json="${RUNNER_TEMP}/platform-immutable-settings-receipt.json"

immutable_status="$(curl --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  --request GET \
  --output "${immutable_json}" --write-out '%{http_code}' \
  --header 'Accept: application/vnd.github+json' \
  --header "X-GitHub-Api-Version: ${api_version}" \
  --header "Authorization: Bearer ${settings_token}" \
  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/immutable-releases")"
if [ "${immutable_status}" != 200 ]; then
  printf 'immutable-release settings query failed with HTTP %s\n' \
    "${immutable_status}" >&2
  exit 1
fi

unset settings_token

python3 -I -B "${contract}" immutable-settings-receipt \
  --settings-json "${immutable_json}" \
  --repository "${GITHUB_REPOSITORY}" \
  --source-sha "${SOURCE_SHA}" \
  --run-id "${GITHUB_RUN_ID}" \
  --run-attempt "${GITHUB_RUN_ATTEMPT}" > "${receipt_json}"

printf 'attestation=PASS:%s:%s:%s:%s\n' \
  "${GITHUB_REPOSITORY}" "${GITHUB_RUN_ID}" \
  "${GITHUB_RUN_ATTEMPT}" "${SOURCE_SHA}" >> "${GITHUB_OUTPUT}"
{
  printf '### Immutable-release current-settings proof\n\n'
  printf '```json\n'
  tr -d '\r\n' < "${receipt_json}"
  printf '\n```\n'
} >> "${GITHUB_STEP_SUMMARY}"
