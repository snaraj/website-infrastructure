# Repository instructions

These rules apply to every human and automated contributor.

## Safety invariants

1. Never commit plaintext secrets, base64-only Kubernetes secrets, private age
   identities, tunnel tokens, API tokens, kubeconfigs, Kubernetes PKI/bootstrap
   material, API-encryption keys, recovery codes, private keys, authenticated
   plans, or state.
2. Never create `apps/`, `clusters/`, or `kubernetes/homelab/`.
3. Never add a Kubernetes `NodePort`, `LoadBalancer`, `externalIPs`, host port,
   host network, public Ingress, Gateway, or origin A/AAAA record.
4. Never add a Cloudflare resource outside the committed allowlist. A new or
   unknown product requires a reviewed ADR proving zero infrastructure cost.
5. Never give Flux a Git credential or write capability. The source is public
   anonymous HTTPS and reconciliation is pull-only.
6. Never deploy a mutable image tag. Workloads use a full `sha256` digest.
7. Every committed Kubernetes Secret must be a valid SOPS document whose
   `data` and `stringData` values are ciphertext.
8. Direct `kubectl apply` is limited to documented bootstrap or recovery. Once
   Flux owns a resource, normal changes flow through a reviewed Git commit.
9. Dashboard mutations are break-glass only and must be recorded and reconciled
   into OpenTofu immediately afterward.
10. Every new public route, API, database, authentication system, persistent
    volume, or cross-namespace flow requires a threat-model update.
11. Production website code lives in the standalone site repositories
    (Svelte frontend, Go service, Helm packaging); this platform consumes
    only their signed digests. Python is limited to dependency-free local
    policy/redaction tooling and must never enter a production image.
12. Treat the Git index as public. Real host/service inventory, account or zone
   IDs, emails, IPs, machine IDs, user/workspace paths, plans, state, and local
   evidence remain ignored/local unless an explicitly designed SOPS/age Secret
   flow requires ciphertext in Git.
13. Keep heavyweight media out of Git, OCI images, Flux, ConfigMaps,
    Secrets, and etcd. Before Pi discovery, reject every
    hostPath/PV/PVC/storage-profile activation; current zero-spend Cloudflare
    terms keep deliberate public large-media delivery disabled independently
    from application-code readiness.
14. Keep each website's domain, source/module/package, image, chart, namespace,
    Flux release, workflow signature, promotion, DNS zone variable, and Tunnel
    origin as one exact identity tuple. Shared tooling must not couple digests,
    readiness, rollback, or release authority.
15. Treat every declared protected legacy archive as inert. Never add an
    installer, updater, automatic start/restore, public route, listener,
    container/Kubernetes mount, CI artifact, or broad storage operation for it;
    exact units, roots, identities, contents, and recovery evidence stay in the
    ignored local contract. Reactivation requires a new ADR and threat-model
    review.
16. Keep the admin plane SSH-only (PLAT-DEC-001). Never widen admin-VPN
    ingress toward 2379, 2380, 6443, or 10250, weaken the host-ingress guard
    artifacts, or reintroduce kubectl-over-VPN paths in code, policy, or
    docs; `make check-ingress-guard` and the terminal PR gate enforce the
    denial and any change to it requires an owner decision superseding
    PLAT-DEC-001.

## Change workflow

- Read the relevant ADRs and runbooks before editing.
- Keep GitHub workflows secretless on pull requests, pin every action to a full
  commit SHA, and keep default permissions read-only.
- Run `make check` and add an allow and deny fixture for policy changes.
- Preserve fail-closed sentinels until an explicitly approved user-run step can
  replace them with verified non-secret values.
- Add GoDoc to exported Go declarations and contextual comments to non-obvious
  modules, structs, fields, variables, constants, functions, and safety checks.
  Explain why they exist in this system instead of narrating syntax.
- Before every push, review the exact staged index, run the repository privacy
  gate and Gitleaks (`make pre-push-security` rehearses the full
  origin/main..HEAD publication gate; `git config core.hooksPath .githooks`
  makes it automatic), and leave any ambiguous operational value unstaged.
- `make check-fast` needs only Python and Git; the full `make check` also
  needs the pinned gitleaks/shellcheck/actionlint/helm/kubeconform/conftest
  and OpenTofu toolchain from `versions.env`, and `make coverage` needs the
  one hash-pinned `coverage` wheel from
  `scripts/ci/requirements-coverage.txt`.
- Do not install tools, authenticate, plan, apply, deploy, commit, push, or
  mutate the Pi/router/GitHub/Cloudflare without explicit authorization.
- Use official upstream documentation to revalidate versions, schemas,
  entitlements, and billing immediately before any external change.

`kubeadm reset` is destructive, performs incomplete cleanup, and is never an
upgrade or rollback procedure. If discovery finds stale K3s state, do not run
its uninstall script; stop for a reviewed backup and migration decision.

## Delivery lane

This repository must be operable cold by any major frontier model: AGENTS.md
is the canonical, vendor-agnostic agent contract, and no requirement may live
only in a vendor-specific file or an agent's private memory. The delivery
lane is the verification and documentation surface — `tests/**`, `scripts/**`,
`.github/workflows/**`, `Makefile`, `README.md`, and `docs/**`. The platform
lane — `bootstrap/pi/**`, `versions.env`, the ADRs, and the capacity
documents — is owned separately: delivery-lane changes never edit
platform-lane files, and platform decisions (the safety invariants above,
including PLAT-DEC-001) are referenced from here, never restated or reworded.

Delivery-lane requirements, explicit and numbered:

1. Zero spend, no external processors: checks run with pinned local tools
   and the GitHub-hosted runner only, and no third-party service ever
   receives repository content, tokens, or measurements — the coverage gate
   is self-hosted for exactly this reason.
2. Owner-only merges, and no force-push: history published to origin is
   immutable; corrections land as new commits on a branch behind a reviewed
   pull request.
3. Commit-metadata privacy: the GitHub noreply address appears in both the
   author and the committer fields of every outgoing commit; the
   immutable-history gate (`scripts/validate_publication_history.py`)
   enforces this closure over the whole outgoing range.
4. No co-author trailers: agent work is signed in the open, per lane —
   delivery-lane commit bodies end with "- Fable5", and Codex-lane pull
   request titles end with " - Codex 5.6 Sol Ultra".
5. Fail-closed, never weaken: a delivery-lane change strengthens or
   documents a check, never relaxes one, and every deliberate exception is
   an explicit, load-bearing justification that the suite re-verifies (the
   security-toggle allowlist and the validator-parity CI-only allowlist are
   the models), so a stale justification fails exactly like a missing check.
6. Ratchet-only coverage floor: `docs/badges/coverage.json` records the
   enforced floor, which may rise and never falls; coverage moves by adding
   tests, never by trimming the measured surface.
7. Provider neutrality: Cloudflare is the current provider binding, chosen
   and bounded by the platform lane (safety invariant 4 and its ADRs);
   shared code and checks keep capability names generic so the binding
   could change without rewriting this lane.

## Adversarial review protocol

Every substantive PR receives an independent adversarial review BEFORE it
leaves draft. The mechanism is vendor-agnostic: any capable agent — or a
human — runs it with git, a shell, and this repository's own gates; no
step assumes a particular AI tool. (Claude sessions load this contract
automatically through CLAUDE.md; other agents read AGENTS.md directly.
Neither gets a different protocol.)

**Reviewer independence.** The reviewer is a different agent or context
than the author — a fresh session of the same vendor qualifies; a
different lane is better. The reviewer works in a disposable worktree at
the PR head, stays read-only toward the author's workspace, reverts every
experiment, and removes the worktree afterward.

**The review must:**

1. Audit every claim in the PR body and commit messages against the
   actual diffs. Overstatement is a finding even when the code is right.
2. Build a mutation kill matrix: for each guard or test the PR adds or
   changes, apply the exact regression it claims to prevent — the suite
   must go red. Revert between mutations. A surviving mutant is a
   finding.
3. Probe for flakes: the full suite at least three times, plus the race
   detector where the language has one. Any nondeterminism is a finding
   naming the test.
4. Check hygiene: commit identity (owner noreply in BOTH author and
   committer), signature conventions, no co-author trailers, secret scan
   clean, out-of-lane paths untouched.
5. Check doctrine: nothing weakened — every gate, validator, or test
   change is additive or strengthening; exceptions are narrow, named,
   and justified where the owner will read them.
6. For CI-invisible paths (jobs that run only on pushes to main), demand
   simulated evidence of both directions in the PR and treat the first
   post-merge run as part of the change under review.

**Verdict format** — posted as a PR comment, so every vendor and the
owner see the identical record: APPROVE or REQUEST-CHANGES; numbered
findings with severity and file:line; the mutation kill matrix; flake
results; a claim-audit table (SUPPORTED / OVERSTATED per claim); explicit
"no finding — checked X, Y, Z" statements so silence is never ambiguous;
confirmation the scratch workspace was removed; the reviewing lane's
signature. A PR flips from draft to ready only after an APPROVE verdict
(or after findings are fixed and re-verified), and the evidence comment
remains on the PR as the permanent record.

A green check, a peer approval, or a ready state is evidence, never
authority: the owner alone merges.

## GitHub conventions

- **Issues first.** Substantive work is tracked as a labeled issue before or
  alongside its PR; PRs declare `Closes #N` so merges close the record.
  Feature intake lands as a `features`-labeled issue with the architectural
  constraints stated, even when implementation waits.
- **Labels.** One taxonomy, identical names/colors/meanings across all
  three repositories: `production-readiness`, `conventions`, `security`,
  `tests`, `ci`, `docs`, `release`, `fix`, `provider-neutrality`,
  `delivery-lane`, `features`. New labels are added to all three at once.
- **Milestones.** Every PR and issue carries one. Release milestones close
  when the release ships; completed arcs close their milestone.
- **Assignee.** The owner is assignee on every PR and issue (authorship is
  already the owner's account by token identity).
- **Linear history.** Merge commits are disabled in repository settings;
  the owner merges by squash (or rebase). Branches auto-delete on merge;
  stale local branches are pruned as work lands. History is append-only
  and never rewritten.
- **Commits.** Detailed bodies to the review protocol's evidence standard —
  problem, mechanism, enumerated changes, evidence — signed per lane.
