# Changelog

All notable platform-source releases are recorded here. Versions follow
Semantic Versioning and name the repository state only; publication never
implies deployment or promotion.

## [Unreleased]

## [0.1.7] - 2026-08-19

### Changed

- The two site-owned Cloudflare roots now complete the minimum-TLS update and
  its provider readback before the plaintext-redirect update, so a zone never
  accepts a redirect ahead of its own TLS floor.

### Security

- The Cloudflare plan policy binds the edge-hardening transaction to its
  measured prestate: only the two existing HTTPS-redirect and minimum-TLS
  owners may update, only from `off` and `1.0`, and every other resource in a
  site plan — Tunnel, Tunnel configuration, apex record, and the four remaining
  zone settings — must plan as a no-op.
- Six hostile plan mutations now prove those denials on both site phases: a
  duplicate setting owner, a Tunnel-configuration update, a falsified
  pre-change value on each of the two target settings, an unrelated
  zone-setting update, and a plan that claims `no-op` on the redirect owner
  while its own recorded before value contradicts that target.

## [0.1.6] - 2026-08-18

### Added

- A staged, bound, reversible Kyverno admission-install transaction as dormant
  desired state: seven classified phases, a render/target/network/attempt-bound
  rollback journal, an exact-identity pre-controller in-cluster API canary, and
  a promotion gate bound to exact controller rollout and fresh reviewed reports.
  Neither mutating stage is authorized, so nothing is installed or enforced.
- An admission-only ReplicaSet identity policy requiring the built-in Deployment
  controller and the exact live same-namespace owner UID, with positive,
  spoofed-UID, and wrong-actor fixtures.

### Changed

- Role-specific admission NetworkPolicies now select the admission controller by
  component rather than by the shared `part-of` label, so the reports controller
  no longer inherits webhook ingress or public egress.
- The Kyverno policy README and the report-only acceptance runbook now describe
  the committed policy actions and the achievable per-webhook `failurePolicy`
  matrix instead of a state the install cannot reach.

### Security

- The rollback journal binds the complete exact `kind|namespace|name` render
  inventory, with cardinality and uniqueness, before any delete or webhook
  sweep; a same-namespace identity outside the reviewed inventory is refused.
- The pre-controller canary declares numeric `runAsUser`/`runAsGroup` so its
  restricted `runAsNonRoot` identity is startable rather than admitted and
  then rejected by the kubelet.
- The installer binds its Kustomize executable to the official Linux AMD64
  SHA-256 digest rather than to a self-reported version string.

## [0.1.5] - 2026-08-18

### Added

- A reproducible, reviewed Flux controller install surface: a controllers-only
  Kustomize root whose build is exactly the bytes to apply, an ordered and
  digest-bound installer, an ephemeral pre-controller Kubernetes Service/API
  reachability canary, and an install/removal runbook that documents the
  complete cluster-scoped inventory a namespace deletion cannot remove.
- A fail-closed `flux-system` egress set: an explicit ingress+egress
  `default-deny` plus enumerated DNS, intra-namespace artifact, Kubernetes
  API-server, and separately deferred public-HTTPS allows, each with its own
  single-document deny fixture whose expected rejection message is asserted.

### Changed

- The Flux install documentation now states the live prestate honestly: a stock
  upstream v2.9.3 render is already installed on the cluster, so this reviewed
  desired state is a convergence target rather than a description of the
  cluster, and the runbook presents remediate-in-place and
  teardown/reinstall as the two owner-authorized convergence options with
  their blast radius.

### Fixed

- `source-controller` no longer receives `--no-cross-namespace-refs`; the
  pinned v1.9.3 binary does not register that flag and exits non-zero on it,
  so the reviewed desired state was an unstartable Deployment.

### Security

- `flux-system` carries enforced restricted Pod Security in the reviewed
  overlay instead of the generated export's warn-only label, and the
  generated blanket `egress: [{}]` allow is removed by a reviewed patch that
  the repository validator refuses to let drift.

## [0.1.4] - 2026-08-18

### Fixed

- The platform source publisher again publishes every patch. Its tag guard was
  frozen to one literal release from the recovery era, so the first version
  advance past that era stranded publication: the guard exited non-zero with no
  output and the tag and Release were never created. The guard now derives the
  expected tag from the `VERSION` the checked-out source declares, which is the
  same identity the release window already binds, so it can never go stale
  against a later patch.

### Security

- A repository gate now refuses any current-version tag literal in the
  publisher. Only the frozen recovery tag may name a version; the tag the
  publisher accepts must be derived from source. The gate is proven by
  execution as well as by inspection — a publisher pinned to a single patch is
  shown refusing the tag its own source declares.

## [0.1.3] - 2026-08-18

### Changed

- Bumped `github/codeql-action/init` and `github/codeql-action/analyze` from
  4.37.6 to 4.37.7 together in `.github/workflows/codeql.yml`, superseding
  Dependabot PRs #124 and #125 with one commit so both steps stay on the
  same released version.

### Fixed

- Added a `groups` stanza to the `github-actions` ecosystem entry in
  `.github/dependabot.yml` scoping `github/codeql-action*`, the root cause of
  #124/#125 landing as two mutually-blocking PRs instead of one: future
  coordinated codeql-action releases now arrive grouped.

## [0.1.2] - 2026-08-14

### Added

- A portable catalogue of vacuous-green review failures, with exact-head
  author/reviewer/coordinator authority, strict visible-resource discovery,
  and forward-testable skill packaging rules.
- A bounded destructive-recreation method for explicitly classified ephemeral
  Kubernetes workloads; protected durable state never inherits its deletion
  permission.

### Changed

- Ready now means zero unresolved code, CI, review, sequencing, settings, Main
  Worker, metadata, or other declared blockers. Author, reviewer, and Main
  Worker contexts remain distinct, and `requires-review` remains a PR-head-only
  request rather than a readiness signal.

### Security

- Review evidence now rejects inert GitHub Markdown links, escaped delimiters,
  nested container fences, symlink escapes, repository identity leakage, and
  untested or vacuous guard claims without granting credential, live-system,
  durable-state deletion, settings, Ready, or merge authority.

## [0.1.1] - 2026-08-14

### Fixed

- Restored unattended per-main source publication after the built-in workflow
  token proved unable to read the immutable-release repository setting. A
  short-lived, repository-selected GitHub App token now performs only that
  Administration-read check; the built-in token remains the sole tag and
  Release writer.
- Added a one-time fail-closed recovery for the stranded `v0.1.0` publication.
  The owner prepares only its exact annotated tag; the workflow refuses every
  write until that tag is exact, creates the immutable zero-asset Release as
  `github-actions[bot]`, and completes it before beginning `v0.1.1`.
- Required an exact GET-only inventory of the completed protected-main jobs and
  all declared gate steps. A workflow-level `success` with a skipped, missing,
  cancelled, duplicate, or foreign critical job/step no longer authorizes
  publication; the push-only dependency-review skip remains explicit. The same
  read-only gate boundedly waits for the exact main-SHA CodeQL run and requires
  its sole Python analysis job and declared analysis steps to succeed.

### Security

- Bound the release App to the `platform-release` environment, exact selected
  branch `main`, one repository, Administration read plus implicit Metadata
  read, no events, and no Contents write. The environment suppresses deployment
  objects and keeps its private key unavailable to pull-request jobs.
- Separated the App and write credentials into different jobs. The read-only
  job exports only a sanitized `PASS` receipt; the write job has no environment,
  App variable, App secret, or App token. Hostile coverage rejects merged jobs,
  token outputs/crossover, broadened authority, foreign state, races, and
  partial recovery.
- Added an owner-observed, no-bypass release-tag ruleset prerequisite that
  permits initial `vX.Y.Z` tag creation but denies update, deletion, and
  non-fast-forward movement during the interval before GitHub locks the tag to
  its immutable Release. The least-authority runtime App does not overclaim the
  bypass field that GitHub redacts from read-only ruleset callers.

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
