#!/usr/bin/env bash
# Verify the exact completed protected-main job and step inventory. This job
# receives only Actions/Contents read and emits no credential or job identifier.
set -euo pipefail

: "${ACTIONS_READ_TOKEN:?ACTIONS_READ_TOKEN is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${COMPLETED_RUN_ID:?COMPLETED_RUN_ID is required}"
: "${COMPLETED_RUN_ATTEMPT:?COMPLETED_RUN_ATTEMPT is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"

actions_token="${ACTIONS_READ_TOKEN}"
unset ACTIONS_READ_TOKEN
test -z "${IMMUTABLE_SETTINGS_TOKEN-}"
test -z "${GH_TOKEN-}"
test -z "${GITHUB_TOKEN-}"
test -z "${GH_ENTERPRISE_TOKEN-}"
test -z "${GITHUB_ENTERPRISE_TOKEN-}"

contract='scripts/ci/platform_release_contract.py'
api_version='2026-03-10'
jobs_json="${RUNNER_TEMP}/platform-main-ci-jobs.json"
codeql_runs_json="${RUNNER_TEMP}/platform-codeql-runs.json"
codeql_jobs_json="${RUNNER_TEMP}/platform-codeql-jobs.json"
receipt_json="${RUNNER_TEMP}/platform-main-ci-jobs-receipt.json"

api_get() {
  local url="$1" output="$2"
  curl --silent --show-error \
    --proto '=https' --tlsv1.2 \
    --request GET \
    --output "${output}" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --header "Authorization: Bearer ${actions_token}" \
    "${url}"
}

jobs_status="$(api_get \
  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/runs/${COMPLETED_RUN_ID}/jobs?filter=latest&per_page=100" \
  "${jobs_json}")"
if [ "${jobs_status}" != 200 ]; then
  printf 'completed-main job inventory query failed with HTTP %s\n' \
    "${jobs_status}" >&2
  exit 1
fi

codeql_ready=false
for poll_attempt in {1..30}; do
  codeql_runs_status="$(api_get \
    "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml/runs?branch=main&event=push&head_sha=${SOURCE_SHA}&per_page=100" \
    "${codeql_runs_json}")"
  if [ "${codeql_runs_status}" != 200 ]; then
    printf 'exact-SHA CodeQL run query failed with HTTP %s\n' \
      "${codeql_runs_status}" >&2
    exit 1
  fi
  codeql_run_state="$(python3 -I -B "${contract}" codeql-run-state \
    --runs-json "${codeql_runs_json}" --source-sha "${SOURCE_SHA}")"
  if [ "${codeql_run_state}" = pending ]; then
    if [ "${poll_attempt}" -lt 30 ]; then sleep 10; fi
    continue
  fi
  if [[ ! "${codeql_run_state}" =~ ^ready:([1-9][0-9]*):([1-9][0-9]*)$ ]]; then
    printf 'exact-SHA CodeQL run state is malformed\n' >&2
    exit 1
  fi
  codeql_run_id="${BASH_REMATCH[1]}"
  codeql_run_attempt="${BASH_REMATCH[2]}"
  codeql_jobs_status="$(api_get \
    "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/runs/${codeql_run_id}/jobs?filter=latest&per_page=100" \
    "${codeql_jobs_json}")"
  if [ "${codeql_jobs_status}" != 200 ]; then
    printf 'exact-SHA CodeQL jobs query failed with HTTP %s\n' \
      "${codeql_jobs_status}" >&2
    exit 1
  fi
  codeql_jobs_state="$(python3 -I -B "${contract}" codeql-jobs-state \
    --jobs-json "${codeql_jobs_json}" --run-id "${codeql_run_id}" \
    --run-attempt "${codeql_run_attempt}" --source-sha "${SOURCE_SHA}")"
  if [ "${codeql_jobs_state}" = ready ]; then
    codeql_ready=true
    break
  fi
  test "${codeql_jobs_state}" = pending
  if [ "${poll_attempt}" -lt 30 ]; then sleep 10; fi
done
test "${codeql_ready}" = true
unset actions_token

python3 -I -B "${contract}" main-ci-jobs-receipt \
  --jobs-json "${jobs_json}" \
  --codeql-runs-json "${codeql_runs_json}" \
  --codeql-jobs-json "${codeql_jobs_json}" \
  --repository "${GITHUB_REPOSITORY}" \
  --source-sha "${SOURCE_SHA}" \
  --run-id "${COMPLETED_RUN_ID}" \
  --run-attempt "${COMPLETED_RUN_ATTEMPT}" > "${receipt_json}"

printf 'attestation=PASS:%s:%s:%s:%s\n' \
  "${GITHUB_REPOSITORY}" "${COMPLETED_RUN_ID}" \
  "${COMPLETED_RUN_ATTEMPT}" "${SOURCE_SHA}" >> "${GITHUB_OUTPUT}"
{
  printf '### Protected-main required-jobs proof\n\n'
  printf '```json\n'
  tr -d '\r\n' < "${receipt_json}"
  printf '\n```\n'
} >> "${GITHUB_STEP_SUMMARY}"
