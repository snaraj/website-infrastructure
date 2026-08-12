#!/usr/bin/env bash
# Prove the checked-out pull-request merge commit is the exact two-parent join
# of the live base branch tip and the pull request's head, then print that
# verified base tip on stdout so one value drives every range-scanning gate in
# the same step (publication history, secret scanning). Diagnostics go to
# stderr; stdout carries the object ID and nothing else.
#
# Why the base tip is resolved rather than taken from the event payload:
# github.event.pull_request.base.sha is a snapshot from when the pull request
# was opened and GitHub never refreshes it as the base branch advances, while
# refs/pull/<n>/merge is always recomputed against the CURRENT base tip.
# Comparing the merge commit's first parent against that stale snapshot fails
# every open pull request the moment the base branch moves — a liveness defect,
# not a security property. The property worth asserting is the stronger one:
# the first parent must be the live tip this pull request actually merges into,
# and the payload's snapshot must still be an ancestor of that tip, so a
# rewritten or unrelated base fails closed instead of being read as ordinary
# staleness.
set -euo pipefail

fail() {
  printf 'FAIL immutable pull-request history validation: %s\n' "$*" >&2
  exit 1
}

readonly oid_pattern='^([0-9a-f]{40}|[0-9a-f]{64})$'

event_name="${GITHUB_EVENT_NAME:-}"
repository="${GITHUB_REPOSITORY:-}"
git_ref="${GITHUB_REF:-}"
git_sha="${GITHUB_SHA:-}"
base_ref="${PR_BASE_REF:-}"
base_repository="${PR_BASE_REPOSITORY:-}"
base_sha="${PR_BASE_SHA:-}"
head_sha="${PR_HEAD_SHA:-}"
number="${PR_NUMBER:-}"

# Server-authenticated event identity. Every one of these was asserted before
# this logic became a script and none is relaxed here.
[[ "$event_name" == pull_request ]] || fail 'event is not a pull request'
[[ "$repository" == "$base_repository" ]] || fail 'pull request is not same-repository'
[[ "$base_ref" == main ]] || fail 'base branch is not the protected integration branch'
[[ "$number" =~ ^[1-9][0-9]*$ ]] || fail 'pull-request number is malformed'
[[ "$git_ref" == "refs/pull/${number}/merge" ]] || fail 'checked-out ref is not the pull-request merge ref'
[[ "$base_sha" =~ $oid_pattern ]] || fail 'event base object ID is malformed'
[[ "$head_sha" =~ $oid_pattern ]] || fail 'event head object ID is malformed'
[[ "$git_sha" =~ $oid_pattern ]] || fail 'event merge object ID is malformed'
[[ "$(git rev-parse --is-shallow-repository)" == false ]] || fail 'repository history is shallow'

checked_out_sha="$(git rev-parse --verify 'HEAD^{commit}')" || fail 'HEAD is not a commit'
[[ "$checked_out_sha" == "$git_sha" ]] || fail 'checked-out commit is not the event merge commit'

merge_record_text="$(git rev-list --parents -n 1 "$checked_out_sha")" || fail 'merge record is unreadable'
read -r -a merge_record <<<"$merge_record_text"
[[ "${#merge_record[@]}" -eq 3 ]] || fail 'merge commit does not have exactly two parents'
[[ "${merge_record[0]}" == "$checked_out_sha" ]] || fail 'merge record does not name the checked-out commit'
[[ "${merge_record[2]}" == "$head_sha" ]] || fail 'merge second parent is not the pull-request head'
[[ "$(git rev-parse --verify "${base_sha}^{commit}")" == "$base_sha" ]] || fail 'event base is not a commit'
[[ "$(git rev-parse --verify "${head_sha}^{commit}")" == "$head_sha" ]] || fail 'event head is not a commit'

# The remote-tracking ref is preferred over a fresh fetch because it arrived in
# the same fetch that delivered the merge commit now checked out, so the two
# are consistent by construction; re-fetching would reintroduce a race between
# the merge ref GitHub computed and a base branch that moved afterwards. The
# explicit fetch exists only for a checkout that did not populate the ref, and
# an unresolvable tip stops the gate rather than falling back to the payload.
base_tip=''
base_tip="$(git rev-parse --verify --quiet "refs/remotes/origin/${base_ref}^{commit}")" || base_tip=''
if [[ -z "$base_tip" ]]; then
  git fetch --no-tags --no-recurse-submodules --quiet origin \
    "+refs/heads/${base_ref}:refs/remotes/origin/${base_ref}" ||
    fail 'live base branch tip could not be fetched'
  base_tip="$(git rev-parse --verify --quiet "refs/remotes/origin/${base_ref}^{commit}")" ||
    fail 'live base branch tip could not be resolved'
fi
[[ -n "$base_tip" ]] || fail 'live base branch tip could not be resolved'
[[ "$base_tip" =~ $oid_pattern ]] || fail 'live base branch tip is malformed'
[[ "$(git rev-parse --verify "${base_tip}^{commit}")" == "$base_tip" ]] || fail 'live base branch tip is not a commit'

if [[ "${merge_record[1]}" != "$base_tip" ]]; then
  printf 'merge first parent %s, live base tip %s\n' "${merge_record[1]}" "$base_tip" >&2
  fail 'merge first parent is not the live base branch tip'
fi

# The payload snapshot is still held to account: on a protected, linear base
# branch every historical tip remains an ancestor of the current one, so a
# base.sha that is not an ancestor means the base was rewritten or the payload
# does not belong to this history at all.
git merge-base --is-ancestor "$base_sha" "$base_tip" ||
  fail 'event base is not an ancestor of the live base branch tip'

printf '%s\n' "$base_tip"
