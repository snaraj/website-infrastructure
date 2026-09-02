# Actions-hosted promoter trust assessment

**Verdict: NOT-YET.** Moving the release-promotion tick to GitHub Actions is
not identity-neutral. The proposed GitHub App introduces a persistent
write-capable principal and a private-key secret, while its required
`contents:write` permission also authorizes pull-request merges and release
writes. The workstation promoter shipped by #292 (issue #286) remains the
supported path until every condition below is enforced and the owner
explicitly accepts the residual blast radius.

This assessment covers hosting only. It does not authorize a workflow, App,
credential, ruleset, version-pin, release, promotion, or infrastructure change.

## Why the current lift is unsafe

- **Owner-only merge is not enforced against the new App.** The current
  GET-only settings preflight reports `restrict_updates: false` for protected
  `main`. Required pull requests, current-base checks, signatures, and green
  required checks constrain *what* can merge; they do not restrict *which
  write-capable principal* invokes the merge. GitHub documents
  `contents:write` as sufficient for the merge endpoint. The same permission
  covers commits, branches, tags, and Releases. A stolen promoter token could
  therefore merge any otherwise-passing PR and could burn a new immutable
  platform tag/Release, in addition to branch spam, PR spam, label/Ready
  manipulation, or poisoned promotion PRs.
- **An App token requires a CI credential.** An installation token is minted
  from an App private key. GitHub calls that key the App's most valuable
  secret; storing it in an Actions secret is a new long-lived CI credential.
  GitHub-signed commits remove the need for the owner's *commit-signing* key,
  but do not remove the App-authentication key.
- **The identity gates do not yet have an App profile.** GraphQL
  `createCommitOnBranch` fixes the author to the credential owner, fixes the
  committer to GitHub's web-flow identity, and automatically signs the commit
  when supported. A resulting `verified` commit can satisfy the main
  `required_signatures` rule, but it intentionally cannot satisfy the current
  owner author/committer profile in `verify-commit-signatures`. Its local mode
  also verifies only the owner's pinned SSH signer, not GitHub's GPG signer.
  GitHub also documents that, on a signature-required branch, a pull request
  can be squash-merged only by its author; the owner is not the author of an
  App-authored PR. Rebase-merge behavior and the resulting identities must be
  proven rather than assumed.
  Separately, `validate_publication_history.py` currently accepts any GitHub
  noreply address; despite the stronger repository prose, that executable
  check does not prove exact owner identity. Adding an App before closing that
  mismatch would make identity acceptance implicit.
- **The built-in token is not a zero-touch substitute.** `GITHUB_TOKEN` avoids
  a custom App key, but GitHub places workflow runs from automation-created or
  updated pull requests into an approval-required state. That restores a human
  action before CI and does not meet the hands-off requirement.

## Conditions before reconsideration

1. **Enforce owner-only updates on the server.** Add an independent ruleset
   that restricts updates to `main` to the owner role while leaving the current
   no-bypass checks/signatures ruleset layered underneath it. Extend the
   GET-only settings preflight and hostile fixtures to require that exact
   composition and prove the promoter App cannot merge. A ruleset name is not
   evidence.
2. **Close tag and Release authority.** Prove a server-enforced construction
   that lets the source publisher create its next tag/Release but prevents the
   promoter App from doing so. `contents:write` has no branch-only mode, and
   the current release-tag rule permits creation. If this cannot be enforced,
   the hosted design remains NOT-YET; detection after an immutable version is
   burned is not prevention.
3. **Use two registrations and two custody domains.** The promoter and
   `snaraj-agent-reviews[bot]` must have different immutable App IDs,
   installations, private keys, environments, and token-minting paths. Ready
   evaluation must bind a comment to the review App's immutable ID and exact
   bot login, not merely to a signature line. A hostile promoter-authored
   comment containing two plausible APPROVE bodies must count as zero receipts.
   The review App must retain no Contents write.
4. **Make commit identity an explicit closed profile.** Use only
   `createCommitOnBranch`; never provision a signing key or perform `git push`
   from the runner. In a disposable test repository, capture the exact App
   author, GitHub committer, signature type, REST verification fields, and
   required-signature result. Then make the repository history gate and
   `verify-commit-signatures` accept exactly either the owner SSH profile or
   that one App/GitHub-GPG profile, and reject an unknown noreply actor,
   unsigned push, alternate App, or merely textual `- Promoter` claim.
   The canary must also prove the owner-operated merge method and the exact
   post-merge commit; losing squash as an option is an explicit process change.
5. **Keep hostile network input away from write authority.** A tokenless
   acquisition job may read public GitHub and GHCR endpoints, install the
   checksum-verified cosign version already pinned by `versions.env`, and run
   the unchanged double-resolution, digest, cosign, SLSA, Release-asset, and
   annotated-tag checks. A separate minimal write job may consume only a
   bounded canonical result and must revalidate its closed schema, base SHA,
   target paths, and counts before minting a repository-scoped token. No job
   receives `id-token`, Actions write, Checks write, Workflows write, or
   Administration write.
6. **Pin and mutation-test the workflow.** Keep root permissions empty, use
   `ubuntu-24.04`, pin every action to a full commit SHA, install tools through
   the repository checksum verifier, and fail closed on network, registry,
   rate-limit, tool-version, artifact, or identity ambiguity. Mutations must
   prove red for job co-location, widened permissions/repository scope,
   alternate actors, removed second resolution, unpinned tools, stale base,
   and surviving tag/merge authority.

## Residual risk requiring owner acceptance

Even after those conditions, the App private key is readable by the hosted
write job and does not expire automatically; compromise permits short-lived
installation tokens until the key is revoked. GitHub-hosted runners have
general outbound network access, so the design can bind every fetched byte and
keep credentials out of the verification job, but it cannot claim network
confinement. Pull-request write also permits PR comments and lifecycle changes;
actor-bound receipt validation makes those writes non-authoritative, not
impossible. Availability remains dependent on GitHub Actions, GHCR, GitHub API,
and Sigstore services, with every outage required to stop rather than promote.
The existing Administration-read platform-release App and its environment
secret must not be reused or broadened for promotion.

## Primary platform semantics

- [GraphQL `createCommitOnBranch`](https://docs.github.com/en/graphql/reference/commits#createcommitonbranch)
- [GitHub App authentication in Actions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow)
- [GitHub App permission scope](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [Pull-request merge permission](https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request)
- [Required signed-commit rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-signed-commits)
- [`GITHUB_TOKEN` event behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)
- [Secure use of Actions](https://docs.github.com/en/actions/reference/security/secure-use)
