---
name: build-website-infrastructure
description: Build, secure, test, and evolve self-hosted website infrastructure. Use for Kubernetes and Helm, Flux GitOps, encrypted secrets, Cloudflare Tunnel/DNS/Zero Trust infrastructure as code, edge-host bootstrap and recovery, supply-chain release policy, persistent media, or cross-cutting architecture and security changes — and, where site source lives alongside the platform, for website source, Go or frontend services, containers, and GitHub Actions publication.
---

# Build Website Infrastructure

Build a coherent slice from source through deployment policy while preserving
the target repository's cost, privacy, origin, and GitOps contracts.

## Discover before editing

1. Locate the repository root, then read its `AGENTS.md`, `README.md`, status,
   and relevant ADRs/runbooks. A vendored copy of this skill may sit below that
   root, so do not assume a fixed relative path. Preserve unrelated work.
2. Read [repository contract discovery](references/project-contract.md), then
   derive identities and invariants from the target repository itself.
3. Identify the requested layer: website, container, orchestrator/GitOps,
   encrypted secrets, provider infrastructure as code, host bootstrap/recovery,
   CI/release, or architecture.
4. Inspect every producer and consumer of a changed name, port, image, Secret,
   namespace, route, or output. Keep source, manifests, policy, tests, docs, and
   runbooks synchronized.
5. Retrieve current primary documentation before choosing provider schemas,
   versions, image digests, action SHAs, permissions, pricing, or entitlements.
   Never fill an unknown with a plausible value.

## Choose the relevant workflow

In a split layout (platform repository consuming standalone site
repositories), the source/build/publication workflows below apply inside each
site repository; the platform side's role is admitting and promoting their
signed artifacts by digest.

- For website or container changes, preserve the repository's public response,
  runtime, isolation, image immutability, architecture, and test contracts.
- For a new website, build one exact identity tuple across source/module,
  package, image, deployment unit, namespace/environment, GitOps object,
  workflow, signature, promotion, DNS, and origin where those layers exist.
  Share validation machinery when useful, but never share release digests or
  readiness.
- For large media, read [media storage and delivery](references/media-storage.md)
  before changing code, storage, capacity, or edge routing. Keep heavy bytes out
  of source, build artifacts, and control-plane state unless the repository
  explicitly defines a bounded exception; keep a new storage profile impossible
  to enable until live evidence and current delivery terms both pass.
- For orchestrator or GitOps changes, render the complete target, validate
  schema and policy, scope authorization and reconciliation, preserve the
  repository's isolation defaults, and add a negative fixture for every new
  prohibition.
- For host or Kubernetes bootstrap changes, preserve the distribution, runtime,
  datastore, network, and recovery choices recorded by the repository. Do not
  infer CNI, proxy, firewall, VPN, tunnel, route, or CIDR behavior without live
  evidence. Treat Kind as disposable integration testing, never target-host
  acceptance evidence.
- For secrets, preserve the repository's own secret contract and its stable
  consumer names/keys. Never create, read, print, or request private credential
  material; carrying no secrets at all is one conditional variant, and an
  in-repository encrypted-secret format is another.
- For Cloudflare work, load `$cloudflare:cloudflare` when that skill is
  available; otherwise retrieve current official Cloudflare and provider
  documentation directly. Treat unknown price, entitlement, or terms
  compatibility as `NO-GO` under the target repository's cost policy.
- For GitHub Actions or publication, read
  [GitHub Actions and release](references/github-actions.md). Keep pull requests
  secretless/read-only and separate tests, build, scan, publish, attest, promote,
  and deployment evidence.
- Before any external mutation or user-run procedure, read
  [external gates](references/external-gates.md) and stop at the applicable
  authorization checkpoint.

## Implement a complete local slice

1. Update architecture/threat model first when adding a public route, API,
   database, auth system, persistent volume, privilege, or cross-namespace flow.
2. Make the smallest internally complete change using repository-native files
   and `apply_patch`.
3. Add allow and deny tests close to the enforced boundary. A policy without a
   rejected fixture is incomplete.
4. Keep sentinels obviously invalid and fail closed. Do not make an unfinished
   scaffold look deployable.
5. Document the system reason for non-obvious modules, structs, fields,
   constants, variables, functions, and safety branches. Exported APIs follow
   their language's documentation convention, including GoDoc for Go. Prefer
   concise context and invariants over comments that merely restate syntax;
   synchronize the repository's script index when one is part of its contract.
6. Run the narrow tests, then the repository-discovered aggregate check. If a
   pinned validator is unavailable, run every available local check and report
   the exact unexecuted gates.
7. Review the diff adversarially for secret leakage, mutable references, public
   exposure, excess privilege, billing paths, inconsistent names, and rollback
   gaps.

## Preserve public-repository privacy

- Treat the full Git index as public. Before every push, inspect staged content
  and run the repository's privacy and secret scanners against exactly what will
  leave the workstation.
- Commit only deliberate public identities such as the domain and repository
  owner, unmistakably synthetic fixtures, or the approved encrypted-secret
  format. Keep real account
  and zone IDs, emails, private/public host addresses, machine IDs, filesystem
  paths, inventory, plans/state, protected unit names, and local evidence out of
  Git whether or not a conventional secret scanner recognizes them.
- Store protected service names only in the ignored local contract defined by
  the target repository, protected by mode `0600` or a platform-equivalent ACL.
  Share hashes and indexed status, never names or raw service inventory.
- If a value is ambiguous, do not stage or push it. Encryption is not permission
  to commit arbitrary operational evidence; use only the repository-selected
  encrypted-secret flow for explicitly classified values.

## Preserve evidence integrity

- Do not equate syntax validation with runtime acceptance.
- Mark live-dependent procedures `Draft / unverified` until the exact target
  check or restore drill succeeds.
- Record command, version, target, result, and non-sensitive evidence for a
  completed gate. Never copy stale test totals or claim an architecture/build
  that was not exercised.
- Keep release evidence as distinct phases: test, build, audit, hash/attest,
  then manually verify the real artifact. Repository scripts and `AGENTS.md`
  remain authoritative; preparation is not publication permission.

## Maintain this skill

After a verified workflow exposes a reusable method-level lesson, update
the smallest relevant reference. Keep `SKILL.md` concise and move detailed
procedures into one-level references. Do not promote an untested hypothesis into
an operational rule. Regenerate `agents/openai.yaml` if triggering or scope
changes, run the skill validator, and forward-test non-mutating tasks when useful.

## Report precisely

Lead with the achieved local outcome. Include changed files, checks passed,
checks unavailable/pending, assumptions, unresolved external values, security
findings, the next exact checkpoint, commands that would run only after approval,
and rollback. State explicitly whether any external system changed or secret was
accessed.
