# GitHub control-plane checklist — Draft / dashboard verification required

For protected `main`, require pull requests, current branches, all repository/
application/container/dependency checks, signed commits after merge-method
testing, and block force pushes/deletion. Apply rules to administrators where
practical. With one trusted operator, do not create an impossible second-reviewer
requirement.

Keep default workflow token permissions read-only and Actions restricted to
GitHub-hosted runners. Platform publication uses three jobs that never share a
credential: one non-environment job receives Actions/Contents read and proves
the exact completed-main job and step inventory; the `platform-release`
environment job receives `contents: read` plus a short-lived GitHub App token
with repository Administration read; and the dependent publish job receives
only `contents: write` through its ordinary per-job `GITHUB_TOKEN`. No
repository/environment secret may contain kubeconfig,
Cloudflare, SSH, age, Kubernetes PKI/bootstrap, API-encryption, or tunnel
credentials. The sole exception in this release lane is the dedicated
`PLATFORM_RELEASE_APP_PRIVATE_KEY`, held only by the selected-main
`platform-release` environment and usable only to mint that read-only settings
token.

Posting source to GitHub remains a workstation responsibility. Authenticate Git
with the dedicated passphrase-protected SSH agent or the OS credential manager/
passkey; never copy that GitHub authority to the Pi, Flux, or a Cloudflare
credential store. Before every push, review the exact index rather
than the whole working directory, run the repository secret/privacy gates over
the index and full Git history, and push only the reviewed commit. Ignored files
are not a confidentiality boundary, and a force-added local artifact/state path
must fail validation.

Use the repository-owned pre-push hook for the publication command itself:

```bash
git -c core.hooksPath=.githooks push --porcelain origin <reviewed-branch>
```

The hook accepts exactly one non-delete, fast-forward branch update to the exact
`snaraj/website-infrastructure` GitHub origin, requires its immutable
object ID to equal a clean `HEAD`, rejects untracked public candidates and
shallow history, reruns the exact-index privacy/secret validator, requires the
pinned Gitleaks release, and scans every commit, tree, blob, path, mode, and
metadata record in the exact outgoing advertised-baseline..candidate range.
Reachable history already contained in the advertised baseline is trusted as
published history and is not re-certified by this gate; the known baseline
identity-metadata residual therefore remains a separate owner decision.
After fetching the reviewed `origin/main`, `make pre-push-security` rehearses
the exact local `origin/main..HEAD` publication range. That local tracking ref
is useful for rehearsal only: the hook binds an existing branch to the old
object ID supplied by Git during the push, or a new branch to `main` advertised
by the exact approved remote. Never use `--no-verify`; only the hook-bound push
authorizes publication, and a failed gate authorizes no push.

The hook, validators, secret policy, and PR workflow are themselves candidate
repository code. A pull request could weaken its own implementation while still
producing a status with the same job name unless GitHub rules outside the branch
protect that control plane. Configure the `main` ruleset/required workflow in
the GitHub UI, restrict workflow-file changes as the platform permits, and
manually review every change beneath `.github/`, `.githooks/`, `policies/`, and
the publication validators before merge. A candidate-generated PASS is not a
substitute for that out-of-band rule and review.

## Platform release readiness receipt

The platform publisher supports both merge methods enabled for this repository:
one-commit squash and merge-free multi-commit rebase. Merge commits stay
disabled. Each range adds one immutable `changelog.d/` fragment and leaves the
frozen legacy `VERSION` and `CHANGELOG.md` untouched. The publisher derives the
next patch from the protected tag ledger anchored at `v0.1.9`; see
[`platform-source-releases.md`](./platform-source-releases.md) for the exact
fragment, rapid-merge, and dependency-queue state machine. That code cannot
prevent an owner from merging a failing or stale PR
when server-side checks are optional, and repository code cannot make a GitHub
Release immutable. The automatic-release policy must not become Ready until the
repository owner configures and then observes this exact server state:

- GitHub immutable releases enabled before the first affected Release is
  published; enabling the control later does not retrofit an existing Release;
- GitHub Private Vulnerability Reporting enabled so `SECURITY.md` names a
  private intake that the repository actually provides;
- pull request, linear history, and signed commits required, with no bypass
  actors;
- strict required checks `dependency-review` and
  `repository-and-infrastructure`, each bound to GitHub Actions integration
  `15368`, with the branch current before merge;
- force pushes and branch deletion disabled;
- exactly `squash` and `rebase` enabled as merge methods, with no update rule
  that would require a bypass merely to merge an otherwise passing PR;
- Actions enabled with server-side full-SHA pinning required, default workflow
  token permissions read-only, and workflow tokens unable to approve pull
  requests; and
- secret scanning and push protection enabled;
- exactly one active tag ruleset across repository and inherited sources,
  repository-owned as `immutable-platform-release-tags`, targeting only
  `refs/tags/v*.*.*`, with no bypass actors or creation restriction and exact
  update, deletion, and non-fast-forward restrictions. Initial release-tag
  creation therefore remains possible, while every later move, force-move, or
  deletion is denied before immutable Release publication. GitHub documents
  the independent [ruleset rule semantics](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
  and [`fnmatch` ref syntax](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository#using-fnmatch-syntax);
  the stars are conservative wildcards, not a numeric SemVer grammar, so the
  source-release validator separately enforces exact `vX.Y.Z` arithmetic;
- environment `platform-release` using selected branch policies with exactly
  one branch rule named `main`, no tag/wildcard policy, no required reviewer,
  no wait timer, and `deployment: false` in the workflow;
- environment variable `PLATFORM_RELEASE_APP_ID` and environment secret
  `PLATFORM_RELEASE_APP_PRIVATE_KEY`, with no copy at repository scope; and
- one active GitHub App installation selected to exactly this repository, no
  subscribed events, and permissions exactly Administration read plus implicit
  Metadata read—never Contents write.

The original 2026-08-13 observation returned `DENY`; the later exact-main
settings receipt passed after the owner closed immutable releases, Private
Vulnerability Reporting, SHA pinning, required-check, bypass, and update-rule
gaps. Actions still allow all publishers even though every checked-in reference
is pinned; selected-action allowlisting is a separate owner-applied hardening
decision. Non-provider-pattern and validity secret-scanning checks remain
disabled residuals. Record those values rather than misrepresenting them as
enforced. None of this grants an agent permission to change settings.

Record only those value-level observations, never actor or ruleset identifiers,
in an untracked JSON receipt with this closed shape:

```json
{
  "repository": "snaraj/website-infrastructure",
  "branch": "main",
  "actions_enabled": true,
  "actions_allowed_actions": "all",
  "actions_sha_pinning_required": true,
  "default_workflow_permissions": "read",
  "actions_can_approve_pull_request_reviews": false,
  "immutable_releases": true,
  "private_vulnerability_reporting": true,
  "merge_methods": ["rebase", "squash"],
  "required_status_checks": [
    {"context": "dependency-review", "integration_id": 15368},
    {"context": "repository-and-infrastructure", "integration_id": 15368}
  ],
  "strict_status_checks": true,
  "require_pull_request": true,
  "require_linear_history": true,
  "require_signed_commits": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "restrict_updates": false,
  "active_main_branch_ruleset_count": 2,
  "owner_update_ruleset": "Owner-PR-Updates",
  "owner_update_ref": "~DEFAULT_BRANCH",
  "owner_update_fetch_and_merge": false,
  "owner_update_bypass": "owner-user-pull-request",
  "bypass_actors": [],
  "active_release_tag_ruleset_count": 1,
  "release_tag_ruleset": "immutable-platform-release-tags",
  "release_tag_ruleset_active": true,
  "release_tag_ruleset_repository_owned": true,
  "release_tag_ruleset_target": "tag",
  "release_tag_pattern": "refs/tags/v*.*.*",
  "release_tag_includes": ["refs/tags/v*.*.*"],
  "release_tag_excludes": [],
  "release_tag_creation_restricted": false,
  "release_tag_updates_allowed": false,
  "release_tag_deletions_allowed": false,
  "release_tag_non_fast_forward_allowed": false,
  "release_tag_bypass_actors": [],
  "release_tag_rule_types": ["deletion", "non_fast_forward", "update"],
  "secret_scanning": true,
  "secret_scanning_push_protection": true,
  "secret_scanning_non_provider_patterns": false,
  "secret_scanning_validity_checks": false
}
```

After the repository owner has made the settings changes, generate the receipt
through the authoritative GET-only preflight and revalidate its closed schema
offline. Keep the value-only file untracked and remove it after recording the
canonical receipt and its digest on the pull request:

```bash
receipt="$(mktemp)"
trap 'rm -f -- "${receipt}"' EXIT
python3 -I -B scripts/ci/platform_release_contract.py settings-preflight \
  --repository snaraj/website-infrastructure > "${receipt}"
python3 -I -B scripts/ci/platform_release_contract.py settings-receipt \
  --receipt "${receipt}" \
  --repository snaraj/website-infrastructure
sha256sum "${receipt}"
```

The JSON and digest prove exact observed values, not when or by whom the GETs
were performed. Never replay them as freshness evidence. Bind the command
transcript to the exact current main SHA and authenticated owner session, and
rerun the authoritative GETs immediately before the one-time recovery writes.

The preflight uses `gh api --method GET` only with REST API version
`2026-03-10`; it exhaustively reads the ruleset inventory plus the repository,
`/immutable-releases`, `/private-vulnerability-reporting`, Actions policy,
workflow-token policy, security-analysis, and exact active repository-owned
`only-me-merge` and `Owner-PR-Updates` records. The same exhaustive inventory includes all active tag
rulesets, including inherited rules, before reading the exact release-tag rule.
GitHub's [2026-03-10 repository-ruleset REST schema](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10)
describes `update_allows_fetch_and_merge` as branch behavior. For a tag-targeted
ruleset, GitHub accepts a write payload that sets it false but canonicalizes the
authoritative GET to the exact type-only object `{"type":"update"}`. The
preflight accepts only that safe tag normalization: any `parameters` object,
top-level update escape, or foreign update-rule field denies. The exact tag
target, closed update/deletion/non-fast-forward inventory, and empty bypass set
remain independently load-bearing.
The owner
credential is load-bearing here: GitHub omits `bypass_actors` for ruleset
callers without write access, so the runtime Administration-read App must not
claim to prove the empty-bypass state.
An authentication, pagination, schema, missing, extra, duplicated,
foreign-integration, inverted, update-restricted, or bypass-bearing result emits
no receipt. A successful receipt is necessary but not sufficient for Ready:
exact-head CI, current base, resolved findings, and a fresh independent approval
remain required. The receipt grants no settings-write or merge authority; only
the coordinator changes Draft/Ready and only the repository owner merges.

## Release App provisioning and job separation

The workflow `GITHUB_TOKEN` cannot read `/immutable-releases`: GitHub requires
repository Administration read, which is not an available workflow permission.
Do not remove the pre-write proof and do not broaden the publisher token. Pin
`actions/create-github-app-token` to
`bcd2ba49218906704ab6c1aa796996da409d3eb1` (`v3.2.0`), request only
`permission-administration: read`, scope it explicitly to owner `snaraj` and
repository `website-infrastructure`, and leave token revocation enabled.

Workflow-level `success` is not publication authority: GitHub can report a
successful workflow even when a job or step is intentionally skipped. The
separate `main-ci-jobs` job uses only `actions: read` plus `contents: read` to
GET the exact latest-attempt job inventory for the completed run. It requires
exactly `repository-and-infrastructure: success`, exactly
`dependency-review: skipped` for a protected-main push, and every declared
repository gate step successful except the one PR-only history scan, which must
be exactly skipped. Missing, duplicate, foreign, failed, cancelled, or newly
skipped jobs/steps emit no attestation. The same bounded read-only job waits up
to five minutes for exactly one `CodeQL` push run at the same main SHA, then
requires exactly `analyze (python, none)` and `analyze (go, autobuild)`, with
each job's checkout, initialization, and analysis steps succeeding. PR CodeQL
is never reused as evidence for a
squash/rebase-created main SHA. Its run-bound value receipt is required
alongside the settings receipt; neither read token crosses into the publisher.

The environment's selected-`main` policy governs access to its credential but
does not independently authenticate `workflow_run.head_branch`, because the
called workflow runs in default-branch context. The trigger's explicit
`branches: [main]`, all three job `if` conditions, and exact event/source
validators remain separate load-bearing checks.

The `immutable-settings` job is the only job attached to environment
`platform-release`. It has `contents: read`, checks out and binds the exact
successful main SHA, then uses the ordinary contents-read token in a bounded
GET-only step to wait for the derived predecessor's exact tag and immutable
Release. Only after ordering completes does it mint the App token and perform
one GET-only immutable-setting probe, so the proof is fresh immediately before
the write job. It exports only two sanitized attestations: the predecessor
source binding and the settings receipt bound to repository, workflow run ID,
run attempt, and source SHA. A partial job rerun cannot replay an older
settings result; only a rerun of the settings job can produce the current
attempt's exact value. Its step summary contains this closed value-only receipt:

```json
{
  "immutable_releases_enabled": true,
  "repository": "snaraj/website-infrastructure",
  "run_attempt": 1,
  "run_id": 123456789,
  "schema": "platform-release-immutable-settings-v1",
  "source_sha": "<lowercase 40-hex successful-main SHA>",
  "status": "PASS"
}
```

The dependent `publish` job independently checks out and rebinds the same event
SHA. It has `contents: write`, no environment, no App variable, no App secret,
and no App token. The settings shell rejects `GH_TOKEN`; the publisher rejects
`IMMUTABLE_SETTINGS_TOKEN`, the Actions-read token, and the predecessor
contents-read token. It rebinds the release window once, then requires the exact
predecessor tag and immutable Release again at every preflight before mutation,
apart from the exact burned `v0.1.42` to `v0.1.43` edge. On that edge the
annotated predecessor tag remains exact while the predecessor Release must be
absent; the write job may retire only the exact known, validated signed
two-asset draft before creating the fully canonical successor.
Never combine the jobs,
export either read token as a job output, or pass any read credential to the
publication transaction.

Before Ready, produce a separate untracked provisioning receipt with the closed
schema enforced by `app-provisioning-receipt`. It must combine owner-authenticated
GETs for the environment, selected-main policy, variable name, and secret name
with App-authenticated GETs for installation account, selected repository
inventory, permissions, events, suspension, identity equality, and a successful
immutable-setting probe. The ordinary owner OAuth token cannot read the App
installation endpoints, so it cannot truthfully produce the whole receipt by
itself. Keep raw App/installation IDs, tokens, and the private key local; emit
only `app_identity_binding_exact: true`, the closed value fields, and the
receipt digest. Validate it with:

```bash
python3 -I -B scripts/ci/platform_release_contract.py app-provisioning-receipt \
  --receipt "${untracked_receipt}" \
  --repository snaraj/website-infrastructure
```

## Immutable publication and one-time v0.1.0 recovery

The publication transaction accepts a GitHub Release only when authoritative
REST reports `immutable:true`, exact published/non-prerelease metadata, the
GitHub Actions bot author identity, and an exactly empty asset inventory.
[GitHub's immutable-release contract](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases)
locks the associated tag while the Release exists and prevents reuse after
deletion. Before that lock exists, this transaction verifies the exact
annotated-tag object, source, message, tagger, and instant immediately around a
bounded Release create/re-query; a drifted tag is never accepted or moved.
The external release-tag ruleset is a Ready prerequisite for that interval. It
contains no `creation` rule, but independently forbids update, deletion, and
non-fast-forward changes with no bypass. The non-fast-forward rule is retained
in addition to the update restriction so force-move semantics remain explicit
and fail closed if GitHub evolves the update-rule parameter surface. This
closes the race against Contents writers; an administrator who can edit the
ruleset remains outside the publication threat model, so a fresh owner settings
receipt is still required before Ready and before the one-time recovery window.
GitHub still permits editing an immutable Release's human title and notes, so
those fields are revalidated but are not an external-artifact identity. This
platform Release intentionally claims source only and therefore requires zero
assets. Any future external image/chart/package claim must move its digest and
identity tuple into one byte-exact manifest asset uploaded before publication.

The stranded first release has one deliberately narrow recovery. After the
v0.1.1 recovery change reaches `main`, the owner may execute only an independently
audited tag-preparation packet: create the exact annotated `v0.1.0` tag at frozen
source `51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e` with the contract's exact bot
tagger metadata. The owner must not create the Release. Until that tag is exact,
the automatic transaction performs no write. The workflow's own `GITHUB_TOKEN`
then creates or verifies the immutable zero-asset v0.1.0 Release as
`github-actions[bot]` before it begins the current tag-derived release. Missing,
lightweight, moved, foreign, partial, or raced states fail closed; exact
completion is idempotent.
The Release call uses `--verify-tag` and deliberately omits `--target`: GitHub
documents `target_commitish` as unused when the tag already exists. Supplying
the historical workflow-bearing target would require Workflows write, an
authority unavailable to `GITHUB_TOKEN`. A disposable-repository canary must
still prove this exact existing-tag path before Ready; documentation is not a
substitute for observed API behavior.

The failed `v0.1.41` and `v0.1.42` publications are not repaired in place.
Their annotated tags are immutable and remain burned ledger boundaries. The
only successor exception accepts an absent `v0.1.42` Release on the exact
`v0.1.42` to `v0.1.43` edge. It deletes only the exact authenticated signed
two-asset draft allocated by the failed v0.1.42 run after revalidating its full
incident identity, and proves the tag unchanged and the draft absent. `v0.1.43`
then follows the normal full two-asset immutable publication path; no later
release inherits the exception.

PR jobs remain read-only with checkout credential persistence disabled. Neither
release job receives Cloudflare, cluster, deployment, package, OIDC, or
attestation authority.

Make each exact GHCR package public independently after verifying its source
linkage, digest, attestations, and repository ownership. Package publication is
not deployment promotion; CI never writes either chart digest or pushes to
`main`.

## Owner-account merge restriction

The current threat model is public source for a privately operated, single-owner
homelab. Review this boundary before granting another collaborator, administrator,
automation principal, or tenant access. An agent holding the owner's credentials
has the owner's GitHub identity; these rules cannot distinguish that agent from
an interactive owner. Agents still have no delegated merge authority.

Two active repository-owned branch rulesets compose the protection:

- `only-me-merge` keeps every security check and signature requirement, with
  an empty bypass list.
- `Owner-PR-Updates` targets only `~DEFAULT_BRANCH`, has no exclusions, and
  contains only `update` with `update_allows_fetch_and_merge: false`. Its sole
  bypass is the repository owner's numeric `User` ID in `pull_request` mode.

GitHub omits the false update parameters from its GET response. The validator
accepts either that exact no-exception rule or the explicit false form; null,
empty parameters, foreign fields and a true fetch/merge exception are refused.

The owner exception belongs only to the second ruleset. Adding it to the core
ruleset would bypass security checks. Immutable tag protection and its empty
bypass list remain separate. The receipt's existing `restrict_updates: false`
describes the core ruleset; the combined policy does restrict updates.

The release settings receipt requires these additional observable facts:

```json
{
  "active_main_branch_ruleset_count": 2,
  "owner_update_ruleset": "Owner-PR-Updates",
  "owner_update_ref": "~DEFAULT_BRANCH",
  "owner_update_fetch_and_merge": false
}
```

Administration-read callers cannot observe bypass actors. Their structural
receipt must not claim owner-only authority. With the existing authorized
ruleset-write credential, run this GET-only check alongside the existing
core/tag zero-bypass checks; missing actor evidence fails, rather than becoming
an empty list:

```bash
set -euo pipefail
repository=snaraj/website-infrastructure
owner_id="$(gh api "users/${repository%%/*}" --jq '.id')"
ruleset_id="$(gh api "repos/${repository}/rulesets" --paginate --slurp | jq -er '
  add | map(select(.name == "Owner-PR-Updates" and .target == "branch"
    and .enforcement == "active"))
  | if length == 1 then .[0].id else error("ambiguous owner restriction") end')"
gh api "repos/${repository}/rulesets/${ruleset_id}" | jq -e --argjson owner "$owner_id" '
  .bypass_actors == [{actor_id:$owner, actor_type:"User", bypass_mode:"pull_request"}]
  and .conditions == {ref_name:{include:["~DEFAULT_BRANCH"], exclude:[]}}
  and (.rules == [{type:"update"}]
    or .rules == [{type:"update", parameters:{update_allows_fetch_and_merge:false}}])
' >/dev/null
printf 'OWNER_PR_UPDATES=PASS\n'
```

Prepare and validate the release-validator compatibility change before adding
the restriction. Read back both rulesets after applying it; preserve the
existing zero-bypass security rules. No step in this procedure merges a PR.

The platform preflight uses owner-visible evidence and additionally requires
`owner_update_bypass: owner-user-pull-request` after validating the exact actor
array. This field must never be inferred by an Administration-read caller.
