# GitHub Actions and release

## Discover the release contract

Repository instructions and scripts remain the source of truth. Identify the
protected release event/ref, registry, runner trust model, required token scopes,
artifact and attestation systems, GitOps promotion policy, and rollback owner.
Perform tests, clean build, audit, digest/attestation, and real-artifact
verification as distinct phases; leave missing evidence pending and do not
publish without authorization.

## Workflow security contract

- Pin every third-party action to a complete commit SHA and keep the readable
  release tag in a comment. Revalidate pins from the action's official release
  and immutable commit pages when updating.
- Set the top-level token permission to the least capability that all jobs need,
  preferably no permission or read-only content. Elevate only the protected
  publication job with the exact registry, OIDC, or attestation scopes required
  by the repository-selected services.
- Give untrusted change validation no secrets, registry write, OIDC, deploy key,
  cluster credential, remote-host credential, decryptor, PKI/bootstrap material,
  or provider credential. Use a trusted disposable runner model appropriate to
  the repository; never expose a persistent privileged runner to untrusted code.
- Never execute untrusted pull-request code in `pull_request_target` with a
  privileged token. Prefer `pull_request` and immutable tools/actions.
- Split validation from publication. Change requests build without pushing; the
  protected release event builds the final artifact once, scans that digest,
  generates the required inventory, publishes, signs/attests, verifies, and
  emits the digest as evidence.
- Follow the discovered GitOps promotion policy. Do not introduce CI writes to
  deployment state when review is required, and do not require manual promotion
  when the repository deliberately authorizes a separately secured automation.
- Treat artifacts and caches as untrusted inputs across privilege boundaries.
  Minimize retention and never upload state, plans, credentials, or inventories.
- Give every independently released site its own workflow identity, registry
  subject, digest, inventory names, signature subject, promotion key, and
  rollback. A validation matrix may share setup and verification machinery, but
  one site's evidence must never promote another.

## Resolve versions in the target repository

Do not freeze dated action SHAs or tool releases in this reusable skill. Read the
target repository's version lock and workflows, then revalidate each third-party
action against its official release and immutable commit page. Pin the complete
commit SHA and retain the human-readable release tag in a comment. Select and
pin the repository's attestation and signing tools explicitly rather than
accepting changing installer defaults.

Official starting points:

- <https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- <https://docs.github.com/actions/security-guides/automatic-token-authentication>
- <https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations>
- each action repository's official Releases and immutable commit page
