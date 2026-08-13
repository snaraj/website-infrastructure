# GitHub control-plane checklist — Draft / dashboard verification required

For protected `main`, require pull requests, current branches, all repository/
application/container/dependency checks, signed commits after merge-method
testing, and block force pushes/deletion. Apply rules to administrators where
practical. With one trusted operator, do not create an impossible second-reviewer
requirement.

Keep default workflow token permissions read-only and Actions restricted to
GitHub-hosted runners. The publish job alone receives package/OIDC/attestation
permissions on `snaraj/website-infrastructure` `main`. No repository/environment
secret may contain kubeconfig, Cloudflare, SSH, age, Kubernetes PKI/bootstrap,
API-encryption, or tunnel credentials.

Posting source to GitHub remains a workstation responsibility. Authenticate Git
with the dedicated passphrase-protected SSH agent or the OS credential manager/
passkey; never copy that GitHub authority to the Pi, Flux, SOPS documents, or a
Cloudflare credential store. Before every push, review the exact index rather
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
disabled. That code cannot prevent an owner from merging a failing or stale PR
when server-side checks are optional, and repository code cannot make a GitHub
Release immutable. The automatic-release policy must not become Ready until the
repository owner configures and then observes this exact server state:

- GitHub immutable releases enabled before the first affected Release is
  published; enabling the control later does not retrofit an existing Release;
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
- secret scanning and push protection enabled.

Read-only observation on 2026-08-13 found immutable releases disabled, no
required-status-check rule, an update restriction, and an always-on
repository-role bypass. It also found Actions SHA pinning disabled. The
authoritative preflight therefore returns `DENY`. Actions currently allow all
publishers even though every checked-in reference is pinned; selected-action
allowlisting is a separate owner-applied hardening decision. Secret scanning
and push protection are enabled, while non-provider-pattern and validity checks
remain disabled residuals. Those optional residuals are recorded rather than
misrepresented as enforced. None of this grants an agent permission to change
settings.

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
  "bypass_actors": [],
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

The preflight uses `gh api --method GET` only with REST API version
`2026-03-10`; it exhaustively reads the ruleset inventory plus the repository,
immutable-release, Actions policy, workflow-token policy, security-analysis,
and exact active repository-owned `only-me-merge` records.
An authentication, pagination, schema, missing, extra, duplicated,
foreign-integration, inverted, update-restricted, or bypass-bearing result emits
no receipt. A successful receipt is necessary but not sufficient for Ready:
exact-head CI, current base, resolved findings, and a fresh independent approval
remain required. The receipt grants no settings-write or merge authority; only
the coordinator changes Draft/Ready and only the repository owner merges.

The publication transaction rechecks the same immutable-release endpoint before
creating a tag. It then accepts a GitHub Release only when authoritative REST
reports `immutable:true`, exact published/non-prerelease metadata, the GitHub
Actions bot author identity, and an exactly empty asset inventory.
[GitHub's immutable-release contract](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases)
locks the associated tag while the Release exists and prevents reuse after
deletion. Before that lock exists, this transaction verifies the exact
annotated-tag object, source, message, tagger, and instant immediately around a
bounded Release create/re-query; a drifted tag is never accepted or moved.
GitHub still permits editing an immutable Release's human title and notes, so
those fields are revalidated but are not an external-artifact identity. This
platform Release intentionally claims source only and therefore requires zero
assets. Any future external image/chart/package claim must move its digest and
identity tuple into one byte-exact manifest asset uploaded before publication.

GitHub Actions uses the per-job ephemeral `GITHUB_TOKEN`. PR jobs remain
read-only with checkout credential persistence disabled. Only the trusted
publisher job on protected `main` receives the minimum package/OIDC/attestation
permissions; it never receives Cloudflare or deployment authority.

Make each exact GHCR package public independently after verifying its source
linkage, digest, attestations, and repository ownership. Package publication is
not deployment promotion; CI never writes either chart digest or pushes to
`main`.
