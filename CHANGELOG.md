# Changelog

All notable platform-source releases are recorded here. Versions follow
Semantic Versioning and name the repository state only; publication never
implies deployment or promotion.

## [Unreleased]

## [0.1.0] - 2026-08-13

### Added

- The first platform source release unit. After the immutable-release readiness
  receipt passes, every protected-main merge, including documentation and
  dependency changes, must carry exactly the next patch from its protected
  base. Successful main CI then publishes an annotated plain `vX.Y.Z` tag and
  matching immutable GitHub Release at that exact source SHA.
- Portable, model-neutral collaboration doctrine for issue-first traceability,
  exact-head adversarial review receipts, owner-only merge authority, release
  consequences, and rigorously classified destructive workload experiments.

### Security

- Platform release publication is independent per source SHA, exact-state
  idempotent, fail-closed on conflicting tags/releases, and has no deployment,
  cluster, Cloudflare, DNS, Tunnel, secret, or protected-custody permission.
- Squash and merge-free multi-commit rebase integrations now share one exact
  base-to-final-SHA patch contract, so an allowed merge shape cannot suppress a
  release or split one merge intent across tags.
- Annotated tag type, object, source target, message, policy tagger, and instant
  are verified through authoritative REST state. A GET-only readiness receipt
  must prove the server immutable-release and protected-main controls before
  Ready. GitHub Releases require authoritative `immutable:true`, exact
  GitHub-Actions author, title/body/state, and an empty asset inventory;
  concurrent create races converge only after the exact state is re-queried.
