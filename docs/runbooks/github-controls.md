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

GitHub Actions uses the per-job ephemeral `GITHUB_TOKEN`. PR jobs remain
read-only with checkout credential persistence disabled. Only the trusted
publisher job on protected `main` receives the minimum package/OIDC/attestation
permissions; it never receives Cloudflare or deployment authority.

Make each exact GHCR package public independently after verifying its source
linkage, digest, attestations, and repository ownership. Package publication is
not deployment promotion; CI never writes either chart digest or pushes to
`main`.
