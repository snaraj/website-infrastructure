# Repository instructions

These rules apply to every human and automated contributor.

## Cold start — first-session checklist

A new agent operates from this repository alone; nothing is relayed by
the owner. In order:

1. Read this file end to end — the safety invariants and the lane split
   before anything else; CLAUDE.md only imports it. Then read
   `skills/gh-pr-flow/SKILL.md` and all of its linked references before any
   GitHub issue/branch/PR/review action.
2. `git fetch origin` and work from `origin/main`. Never trust a local
   `main`, a stale worktree, or another agent's summary of remote state —
   verify remote facts directly (`gh pr view`, `git ls-remote`).
3. Verify identity and tooling: `gh auth status` shows the owner's
   account; commits carry the noreply identity per "Commit identity
   mechanics"; `make check-fast` needs only Python and Git, and the full
   `make check` needs the pinned toolchain from `versions.env`.
4. Survey the live state yourself: `gh issue list`, `gh pr list` — map every
   open PR's dependency edges, collision paths, writer ownership, and available
   review capacity before choosing or publishing work.
5. Establish which lane your task lives in (Delivery lane section) and
   confirm every path you intend to touch belongs to it.
6. Claim work through an issue, branch from `origin/main`, and follow
   "Working a change end to end".

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
- A claim that a Kubernetes workload is ephemeral is load-bearing only after
  `skills/gh-pr-flow/references/destructive-workloads.md` is satisfied and
  `scripts/validate_destructive_test_ledger.py` accepts the exact evidence.
  The ledger uses the closed namespaced workload allowlist, exact cardinalities,
  and one fault target; unknown or cluster-scoped API/kinds fail closed. Its
  disposable fixture must prove a mode-0600 pre-mutation recovery journal,
  repeated/mixed-signal-safe single rollback, bounded receipt, and zero residue.
  Stateful/PV/PVC/database/operator resources remain supported but never
  inherit deletion permission. Protected tokens, Secrets, SOPS/age material,
  private keys, etcd/PKI, DNS/domain/Tunnel/provider identities, custody, and
  Git history are excluded from destructive tests.
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
`.github/workflows/**`, `Makefile`, `README.md`, and `docs/**` — plus, per
the owner's lane re-cut of 2026-08-12, the Cloudflare/edge surface:
`infrastructure/cloudflare/**` and the Cloudflare ADRs (0006–0008, 0015,
and successors). The platform lane — `bootstrap/pi/**`, `versions.env`, the
remaining ADRs, and the capacity documents — is owned separately:
delivery-lane changes never edit platform-lane files, and platform
decisions (the safety invariants above, including PLAT-DEC-001) are
referenced from here, never restated or reworded.

**Lane-surface rulings (owner, 2026-08-12; later rulings identify their
source).** Load-bearing surfaces the two lists above never named, each assigned
once so the question stops being re-adjudicated per pull request:

The owner's 2026-08-20 ruling for release fragments, GitHub intake templates,
and dependency-governed Draft capacity is recorded durably in
[issue #164 comment 5360347849](https://github.com/snaraj/website-infrastructure/issues/164#issuecomment-5360347849).

- `skills/**` — SHARED AGENT GOVERNANCE (peer/platform ruling, 2026-08-13),
  not the exclusive property of either implementation lane. Either lane may
  author there under one-writer-per-branch, but review comes from a different
  context and, where a skill touches a lane-specific security boundary, from
  the other lane. A skill never supersedes AGENTS.md and never grants
  credential, live-mutation, or merge authority; any change that expands
  permission requires an owner ruling.
- `changelog.d/**` — SHARED RELEASE INPUT (owner ruling, 2026-08-20, source
  above). Every implementation lane adds its own exactly one issue-namespaced
  fragment under delivery-lane requirement 8. This mandatory shared write does
  not transfer either lane's implementation paths or permit edits to another
  fragment.
- `.github/ISSUE_TEMPLATE/**` and `.github/PULL_REQUEST_TEMPLATE.md` — DELIVERY
  GOVERNANCE (owner ruling, 2026-08-20, source above). These exact intake files
  implement the issue-first and pull-request evidence contracts. The ruling is
  not shorthand for any other path under `.github/**`.

- `bootstrap/flux/**` — DELIVERY for its reviewed-state model, README, and
  docs. `bootstrap.sh` embeds the inventory and desired-state assertions
  covering the delivery-owned `kubernetes/flux-system/**` manifests, and
  that model is the mechanism that proves the cluster matches them. Its
  live-apply custody surface stays PLATFORM-owned and stays blocked: the
  `--apply-controllers` / `--apply-sync` / `--verify` stop, the four
  sibling entry points `install-sops-age-secret.sh`,
  `verify-sops-age-secret.sh`, `verify-sops-ciphertext.sh`, and
  `verify.sh` in their entirety — each blocked by the same reviewed-blob
  stop — the trusted reviewed-blob launcher requirement, and the
  credential-custody preconditions. The split is by responsibility, not
  by line range — a delivery-lane change may correct what the model
  asserts about reviewed state, never what the custody surface above
  permits or requires.
- `policies/conftest/**`, `policies/kyverno/**`, and
  `policies/release-conftest/**` — DELIVERY. The enumeration is exact,
  not shorthand for `policies/**`: these three subtrees are the
  executable expression of the gates this lane already owns. Every other
  file under `policies/` — the pinned secret-scan policy
  `policies/gitleaks.toml` among them — is unchanged by this ruling and
  reached only through the rule below. One caveat: a change to ADMISSION
  policy semantics needs independent validation by the platform (peer)
  lane, recorded on the pull request, before enforcement is enabled
  anywhere.
- `.githooks/**` — DELIVERY: the pre-push hook implements delivery-lane
  requirements 2 and 3. Changing what it PERMITS is a security-control
  change and needs an owner decision, not a lane call (issue #83).
- `kubernetes/flux-system/**` — DELIVERY: the GitOps desired state this
  lane authors, and what the reviewed-state model above pins.
- `kubernetes/websites/*/release.yaml` — DELIVERY when the change is
  produced by `scripts/promote-image.sh` and the pull request carries its
  evidence, under the owner's standing deploy grant. Outside
  `kubernetes/flux-system/**`, that promotion surface and the
  `cloudflare-public` row below are the only parts of `kubernetes/**`
  this ruling assigns to the delivery lane; `kubernetes/reconciliation/**`,
  the rest of `kubernetes/platform/**`, and the remaining
  `kubernetes/websites/**` files are unchanged by this ruling and stay
  unruled — reach them only through the rule below.
  A RETENTION field is not a promotion. The delivery lane set
  `spec.maxHistory` on both site releases under issue #198, and that edit is
  outside this row: it is not `scripts/promote-image.sh` output and moves no
  digest, tag, or readiness scalar. It is a DECLARED CROSSING under the rule
  below, not a lane transfer, and it grants no standing claim on the tree.
  The field is load-bearing for reliability rather than release identity —
  helm-controller's unset five-revision default exceeded the measured
  namespace Secret budget, which wedged a site release permanently and
  blocked every subsequent deploy. Record the owner or platform (peer) ruling
  in this row when it arrives, including whether release-retention fields
  belong to this lane given that they gate whether a promotion can land at
  all.
- `kubernetes/platform/cloudflare-public/**` — DELIVERY, DERIVED from the
  Cloudflare/edge re-cut recorded in the paragraph above, not granted
  here: that re-cut names only `infrastructure/cloudflare/**` and the
  Cloudflare ADRs, and this tree is the same edge surface's in-cluster
  half — the public Tunnel connector chart and its suspended release, the
  cluster end of the tunnel whose provider-side configuration this lane
  already owns, serving the sites this lane promotes through the row
  above. PR #87 already writes it under this reading. Amend this row if
  the owner or the platform (peer) lane rules otherwise.
- `kubernetes/platform/admission-install/**` — NOT transferred. It is
  platform-shaped admission-control install machinery and the platform
  (peer) lane remains its ruling authority. The delivery lane is
  authoring it under the owner's 2026-08-12 authorization to install
  Kyverno (issue #88): that is a DECLARED CROSSING under the rule below,
  not a lane transfer, and it grants no standing claim on the tree.
  Promotion to enforcement still needs independent validation by the
  platform (peer) lane, recorded on the pull request. Amend this row if
  the owner or the platform (peer) lane rules otherwise.
- `kubernetes/websites/*/source.yaml` — NOT transferred, ruling PENDING.
  The row above assigns `kubernetes/websites/*/release.yaml` to delivery
  through the promotion surface and leaves the remaining
  `kubernetes/websites/**` files unruled; these per-site chart
  `OCIRepository` objects are among them. Each one carries a cosign
  `matchOIDCIdentity` that the delivery-lane validators
  (`scripts/validate_signature_policy.py`,
  `policies/conftest/kubernetes.rego`) already assert byte for byte, so
  the manifest and the gate that pins it cannot be changed from different
  lanes without one of them going stale. The delivery lane touched these
  two files under issue #185 to re-point that identity: a DECLARED
  CROSSING under the rule below, not a lane transfer, and it grants no
  standing claim on the tree. Record the owner or platform (peer) ruling
  in this row when it arrives.
- `docs/adr/0016-tag-driven-flux-release-sync.md` — NOT transferred,
  ruling PENDING. The lane split above assigns "the remaining ADRs" to
  the platform lane, and "Lane discipline in docs" says the delivery lane
  cites them by number rather than editing them. ADR 0016 is nonetheless
  the decision record for surfaces this lane owns outright (the
  signature-policy validators, the conftest and Kyverno policies, the
  promotion script), and it was authored from this lane in commit
  `c0911d7` without a recorded ruling. Issue #185 amended it, because
  leaving it asserting a signing identity the platform no longer trusts
  would have been a silent contradiction. The amendment is append-only:
  it adds one `## Amendment` section in the convention ADRs 0010 and
  0014 already use and leaves every pre-existing line byte for byte
  intact, so what it corrects it corrects on the record rather than by
  rewriting history. That is a DECLARED CROSSING under the rule below,
  not a lane transfer. Record the owner or platform (peer) ruling in
  this row when it arrives, including whether ADR 0016 belongs to this
  lane outright given what it governs.
- `kubernetes/platform/prerequisites/resource-controls.yaml`,
  `docs/architecture/capacity.md`, and `versions.env` — NOT transferred,
  ruling PENDING. The lane split assigns capacity documents and
  `versions.env` to the platform lane, while leaving the rest of
  `kubernetes/platform/**` unruled. The delivery lane touched these paths
  under issue #201 on the owner's explicit 2026-08-22 capacity-graduation
  instruction: replace both zero-Pod sentinels with the exact reviewed
  namespace budgets, bind them to the sanitized audit bytes, document the
  measurement, and add a closed Darwin/arm64 renderer pin without changing
  the Linux live-install tuple. That is a DECLARED CROSSING under the rule
  below, not a lane transfer, and grants no standing claim on these paths.
  The same change deactivates `require-zero-site-capacity.yaml` in the
  delivery-owned `policies/kyverno/kustomization.yaml`, because that policy
  admits only the sentinel shape being replaced. Its source remains
  unmodified as historical material and as a possible input to a separately
  reviewed restoration; restoration requires a coordinated policy-inventory,
  report-only-overlay, render-lock, and validator recut, not merely re-listing
  the source. Removing it from the rendered set also orphans its report-only
  patch under
  `kubernetes/platform/admission-install/report-only/`, which remains under
  platform (peer) ruling authority; deleting that patch and enumeration is
  the same declared crossing. Under the `policies/**` caveat, the admission
  semantic change still needs independent platform (peer) validation on the
  eventual pull request. Record the owner or platform ruling here when it
  arrives, including whether the measured budget and its evidence document
  belong to this lane because delivery validators enforce them.

**A path in neither list is not implicitly delivery.** Silence is not
permission. Declare the crossing in the pull request body before touching
the path, obtain an owner or peer ruling (a scope adjudication only —
never a merge approval, and the owner alone merges), and then — this part
is an obligation, not a courtesy — amend the rulings above with the
answer, in the same pull request or the next one you open. A ruling left
in a review thread is a question the next agent has to ask again.

Delivery-lane requirements, explicit and numbered:

1. Zero spend, no external processors: checks run with pinned local tools
   and the GitHub-hosted runner only, and no third-party service ever
   receives repository content, tokens, or measurements — the coverage gate
   is self-hosted for exactly this reason.
2. Owner-only merges and immutable history: the repository owner alone merges. An agent must
   NEVER merge, auto-merge, squash, rebase into, or push `main`; must never
   force-push, delete refs, or create tags; and must stop and question even a
   later request to do so. Corrections are additive commits or a fresh branch.
3. Commit-metadata privacy: the GitHub noreply address appears in both the
   author and the committer fields of every outgoing commit; the
   immutable-history gate (`scripts/validate_publication_history.py`)
   enforces this closure over the whole outgoing range.
4. No co-author trailers: agent work is signed in the open with the acting
   identity. This authoring lane signs commit and PR bodies `- 5.6 Sol` and
   carries the matching `5.6-sol` label.
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
8. Every protected-main merge has a platform release consequence. Every PR,
   including docs and Dependabot, adds exactly one new immutable
   `changelog.d/<issue>-<lowercase-slug>.md` fragment and never edits another
   fragment, the frozen legacy `VERSION`, or the frozen legacy `CHANGELOG.md`.
   The PR and protected-main gate enforce the same exact-base diff for both
   one-commit squash and merge-free multi-commit rebase integrations. After
   successful main CI, the publisher validates the immutable tag ledger anchored
   at `v0.1.9`, requires one fragment across every adjacent ledger edge, waits
   until an earlier main SHA has both its exact tag and exact immutable Release,
   derives exactly one next patch, and publishes an annotated plain `vX.Y.Z` tag
   plus exact zero-asset GitHub Release at the complete final SHA. Release notes bind the
   fragment path, SHA-256, and bytes; fragments and immutable Releases are the
   permanent post-migration changelog. This source release never deploys or
   promotes platform or site workloads. The authoritative GET-only protected-main settings
   receipt in the GitHub controls runbook must prove immutable releases,
   Private Vulnerability Reporting,
   strict current-base required checks bound to GitHub Actions, required signed
   commits, read-only token defaults, enforced action SHA pinning, and no bypass
   or update restriction before this release policy is Ready.

## Adversarial review protocol

Every substantive PR receives an independent adversarial review BEFORE it
leaves draft. The mechanism is vendor-agnostic: any capable agent — or a
human — runs it with git, a shell, and this repository's own gates; no
step assumes a particular AI tool. (Claude sessions load this contract
automatically through CLAUDE.md; other agents read AGENTS.md directly.
Neither gets a different protocol.)

**Reviewer independence.** The reviewer is a different agent or context
than the author — a fresh session of the same vendor qualifies; a
different lane is better. Both contexts use this repository's already
configured, task-authorized owner account: the GitHub principal is transport,
not the independence boundary. Never acquire, extract, exchange, or change
credentials to manufacture reviewer separation, and never print or repurpose
them. The reviewer works in a disposable worktree at the PR head, stays
read-only toward the author's workspace, reverts every experiment, and removes
the worktree afterward.

**Exact-head receipt.** Agents share the owner's GitHub principal, so identity
is textual workflow evidence. A normal PR comment contains exactly one
`HEAD: <40-lowercase-hex>` line, exactly one `VERDICT: APPROVE` or
`VERDICT: REQUEST-CHANGES`, and ends `- <Agent> (adversarial reviewer)`.
Any head change invalidates it and requires a fresh independent review. Validate
the shape with `scripts/validate_review_receipt.py --resource-kind pull-request`;
the validator rejects issue resources, and context independence still requires
coordinator verification. If the owner merged first, record a post-merge audit
rather than retroactive approval.

**Main Worker Ready receipt.** After an exact-head `APPROVE`, a coordinator
context distinct from both author and reviewer performs one bounded sanity pass
over architecture, merge order, authority, owner-observed settings, base
freshness, and required checks. Its normal comment contains exactly one `HEAD:
<40-lowercase-hex>`, exactly `ROLE: MAIN-WORKER`, exactly `VERDICT: PASS`, the
closed scope line defined in `skills/gh-pr-flow/references/reviews.md`, and a
final `- <context> (Main Worker)` signature. Validate it with
`scripts/validate_review_receipt.py --receipt-kind main-worker
--resource-kind pull-request --required-verdict PASS`; `BLOCK`, a broadened
scope, shared author/reviewer context, or any head change cannot satisfy Ready.
This gate is architecture/order coordination, not a second code review, a
settings mutation, Ready authority, or merge authority.

**The review must:**

1. Audit every claim in the PR body and commit messages against the
   actual diffs, reproducing every number the body cites. Overstatement
   is a finding even when the code is right.
2. Build a mutation kill matrix: for each guard or test the PR adds or
   changes, apply the exact regression it claims to prevent — the suite
   must go red. Revert between mutations. A surviving mutant is a
   finding.
3. Probe for vacuity: a guard that cannot fail is no guard. For each new
   or changed assertion, demonstrate at least one input that turns it
   red (the kill matrix usually supplies it); an assertion no input can
   fail is decorative, and decorative checks are findings. Work through
   `skills/gh-pr-flow/references/evidence-doctrine.md` rather than
   re-deriving it: it catalogues the distinct, reproducible mechanisms
   by which a fully green run proves nothing — coverage that a policy
   suite cannot see, fixtures and gates that disable themselves, and the
   ways a fix written to close a finding is itself vacuous — each with
   its general correction.
4. Probe for flakes: the full suite at least three times, plus the race
   detector where the language has one. Any nondeterminism is a finding
   naming the test.
5. Check hygiene: commit identity (owner noreply in BOTH author and
   committer), signature conventions and agent labels, no co-author
   trailers, secret scan clean, out-of-lane paths untouched.
6. Check doctrine: nothing weakened — every gate, validator, or test
   change is additive or strengthening; exceptions are narrow, named,
   and justified where the owner will read them.
7. For CI-invisible paths (jobs that run only on pushes to main), demand
   simulated evidence of both directions in the PR and treat the first
   post-merge run as part of the change under review.

**Verdict format** — posted as a normal PR comment, so every vendor and the
owner see the identical record: exact head, APPROVE or REQUEST-CHANGES; numbered
findings with severity and file:line; the mutation kill matrix; flake
results; a claim-audit table (SUPPORTED / OVERSTATED per claim); explicit
"no finding — checked X, Y, Z" statements so silence is never ambiguous;
confirmation the scratch workspace was removed; the reviewing agent's
signature in the form `- <Agent> (adversarial reviewer)`, matching its
agent label. Posting the verdict also removes the `requires-review`
label, whichever way the verdict went — the item is no longer waiting on
review attention. That removal is NOT a readiness signal: the draft flag
is the only readiness signal, so label-off while still draft is the
normal mid-cycle state. A REQUEST-CHANGES verdict returns the work to
the same branch owner — fixes land on the same branch and receive a
delta re-review of the changed scope. Role compatibility is fixed: the
branch author and independent reviewer are never the same context, and
neither the author nor the reviewer performs the readiness flip. The
coordinator/Main Worker context is distinct from both author and reviewer and
performs that flip. The flip happens only once the verdict is APPROVE
(or its findings are fixed and re-verified), no owner or peer comment is
outstanding, and every check is green at the exact head. A coordination
action never confers merge authority; the owner alone merges. The evidence
comment remains on the PR as the permanent record.

A green check, a peer approval, or a ready state is evidence, never
authority: the owner alone merges.

## GitHub conventions

- **Issues first.** Substantive work is tracked as a labeled issue before or
  alongside its PR; a standalone exact `Closes #N` targets a same-repository
  issue so only the owner merge closes it.
  Use the governed issue form: problem/invariant, acceptance, threats, tests and
  mutations, exclusions, rollout/rollback, labels, owner assignee, exact
  release milestone, and linked PR are required evidence.
  Feature intake lands as a `features`-labeled issue with the architectural
  constraints stated, even when implementation waits.
- **Labels.** One taxonomy, identical names/colors/meanings across all
  three repositories: `production-readiness`, `conventions`, `security`,
  `tests`, `ci`, `docs`, `release`, `fix`, `provider-neutrality`,
  `delivery-lane`, `features`, `requires-review`. New labels are added to
  all three at once. This repository additionally retains two repo-local
  legacy labels from the separation era (`platform`, `extraction`); the
  shared taxonomy governs new work.
- **`requires-review` — exact-PR-head review signal.** The author lane applies
  `requires-review` only when a PR's exact head, commits, body, and evidence are
  complete-from-author. Its absence on an open agent-authored PR means the PR is
  still in flight; its presence asks an independent reviewer to inspect that
  exact head. The reviewer removes it when posting either verdict; after
  REQUEST-CHANGES the author reapplies it only after the replacement head is
  complete. Never apply or interpret `requires-review` on an issue: an issue has
  no reviewable head and cannot satisfy a PR receipt or Ready gate. Issue-spec
  review uses an explicit normal comment until a separately approved,
  cross-repository issue-review label exists. Existing issue uses of
  `requires-review` are migration residue for coordinator cleanup, not review
  readiness. The label is never a substitute for Draft/Ready state, a fresh
  APPROVE receipt, or owner merge authority.
  The APPROVE verdict and the flip by the coordinator are necessary but not
  sufficient. Ready means zero unresolved blockers across code, CI, review,
  sequencing, settings, Main Worker, metadata, or any other declared gate.
  Owner review or owner merge authority does not waive a blocker; a
  blocker-bearing PR stays Draft.
- **Agent labels.** Every agent-created PR and issue carries TWO further
  labels: the umbrella `agent-authored` AND the acting agent's own label —
  `fable5` (Claude Fable 5), `5.6-sol` (ChatGPT 5.6 SOL ULTRA), `opus5`
  (Claude Opus 5), `opus4.8` (Claude Opus 4.8). The signature must match
  the label (delivery-lane bodies ending `- Fable5` ↔ `fable5`;
  Codex-lane titles ending " - Codex 5.6 Sol Ultra" ↔ `5.6-sol`).
  The umbrella description is model-neutral: `Authored by an AI agent on the
  repository owner's behalf`. Treat older model-specific umbrella descriptions
  as coordinator/server-metadata cleanup across all repositories; keep the
  per-model label as provenance.
  Adversarial-review verdicts carry the same identity as
  `- <Agent> (adversarial reviewer)`. These repositories are worked by
  several frontier models in parallel lanes; labels plus signatures keep
  authorship auditable with no owner relay. When a new model joins, its
  label — description "Authored by <model>" — is created in ALL THREE
  repositories before its first PR, per the one-taxonomy rule.
- **Concurrent PR capacity.** Per the owner's 2026-08-20 ruling recorded in
  [issue #164 comment 5360347849](https://github.com/snaraj/website-infrastructure/issues/164#issuecomment-5360347849),
  there is no fixed count ceiling. Publish independent and dependent work as
  Draft PRs when dependency edges, collision paths, one-writer-per-branch
  ownership, and reviewer capacity are explicit. Open work never broadens
  authority: the owner alone merges, and unresolved sequencing or collision
  risk keeps each affected PR Draft.
- **Merge authority.** THE OWNER ALONE MERGES. Never merge, never
  self-approve, never treat a peer approval or a green check as
  authority, and never force-push a shared ref. Every PR opens as a
  draft.
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
- **Dependabot.** Dependency PRs obey the same issue/milestone/assignee,
  one-fragment release consequence, exact-head review, CI/coverage, and base freshness
  controls. Tool or runner outages are reported as infrastructure failures;
  they never waive a real product failure.
- **Merge readiness.** Keep Draft until the exact head has a fresh independent
  APPROVE receipt and a fresh bounded Main Worker `PASS` receipt, all exact-head
  checks succeed, protected base is current, all discussions/findings are
  resolved, metadata/scope/order remain exact, and the platform patch-release
  consequence is proven. Only the coordinator flips Ready and re-verifies;
  author and reviewer never do. Nobody but the repository owner merges.

## Working a change end to end

The complete delivery loop, each step gated by the sections around it:

1. **Check the lane.** Confirm every path you intend to touch belongs
   to the delivery lane exactly as the Delivery lane section above
   defines it — that definition is the sole authority on lane scope,
   and this checklist deliberately does not restate it. This contract
   file itself is editable from the delivery lane. Never edit the other
   lane's files; reference platform decisions, never restate or reword
   them.
2. **Claim the work.** File (or take) the issue; state intent and
   constraints. Label it — including both agent labels — assign the
   owner, set a milestone. Do not put the PR-head-only `requires-review` label
   on an issue; request issue-spec review through an explicit normal comment.
3. **Branch from `origin/main`** after `git fetch origin`; branch names
   are lane-prefixed (`fable5/<topic>`). One writer per branch, always —
   a branch that is not yours is a branch you never push to. Add one unique
   issue-namespaced changelog fragment; never reserve a patch number or edit
   generated release files. Never rewrite a published branch.
4. **Build the change** inside the invariants, the Change workflow, and
   the delivery-lane requirements above. Docs-only diffs still run the
   gates.
5. **Run the gates** ("Quality gates" below), review the exact staged
   index, run `make pre-push-security`, and commit under the pinned
   identity with a body to the evidence standard, ending with your
   signature.
6. **Push and open a DRAFT PR**: `Closes #N`, the same labels, owner as
   assignee, a milestone, body signed. Every number in the body must be
   reproducible — the adversarial review will reproduce it. Apply
   `requires-review` once the PR is complete-from-author — every commit
   pushed, the body final; until it carries that label, nobody reviews
   it.
7. **Adversarial review** per the protocol above; findings are fixed on
   the same branch by the same writer and delta re-reviewed before the
   flip to ready.
8. **Main Worker gate** per the protocol above; its exact-head `PASS` receipt
   is required after approval and before coordinator Ready evaluation.
9. **Owner comments** are handled per the owner review protocol below.
10. **The owner merges.** Nothing you can do — approval, green checks,
   ready state — substitutes for that.

## Commit identity mechanics

Delivery-lane requirement 3, made operational. The identity — BOTH
author and committer, on every outgoing commit — is the owner's GitHub
noreply identity: exactly the author identity already carried by every
published commit on `origin/main`. This file cannot spell it out,
deliberately: the repository privacy gate bans literal email addresses
from tracked text (only commit METADATA may carry the noreply address —
`validate_publication_history.py` accepts it there and nowhere else).
Read it from published history and pin it per command:

    identity_name="$(git log -1 --format='%an' origin/main)"
    identity_email="$(git log -1 --format='%ae' origin/main)"

- Pin it per command with environment variables, never with `git config`
  (repository or global): configuration outlives the session, leaks into
  unrelated work, and hides identity decisions from review.

      GIT_AUTHOR_NAME="$identity_name" \
      GIT_AUTHOR_EMAIL="$identity_email" \
      GIT_COMMITTER_NAME="$identity_name" \
      GIT_COMMITTER_EMAIL="$identity_email" \
      git commit ...

- Every authorized commit runs under the pinned environment. Agents never
  amend, rebase, cherry-pick onto published history, force, or delete; use
  additive commits or a fresh branch. The publication-history validator checks
  both author and committer over the complete outgoing range.
- No `Co-Authored-By` trailers, ever. Signatures per lane (delivery-lane
  requirement 4), matching the agent label.
- Treat the Git index as public (safety invariant 12): no hostname, IP
  address, machine or account identifier, username, workspace path,
  token, or private operational fact enters any commit, message,
  fixture, or doc — what reaches history cannot be unpublished.

## Owner review protocol

Comments the owner leaves on PRs ARE code reviews — address each
promptly, reply IN-THREAD per comment describing the resolution, then
notify the owner the PR is ready to re-check; never mark a PR ready
with unaddressed owner comments.

## Dependent pull requests

Keep dependent work Draft and publish a directed merge order using exact
`Depends on PR #N` lines plus the corresponding issue relationships. Independent
parallel PRs target `main` and add distinct fragments; a predecessor merge never
forces a replacement merely because a shared version or changelog slot moved.
Re-query the current base and composed merge, rerun the gates, and refresh review
evidence whose claims changed. The only in-place refresh after a base move is
owner-operated: in GitHub's **Update branch** menu the owner selects **Update
with rebase**. That server rewrite creates a new head and invalidates every old
check and exact-head receipt; agents never invoke it, rebase the published branch,
or force-push. If that owner action is unavailable, conflicts, or is declined,
re-cut onto a fresh branch and replacement PR. A fresh branch is otherwise
required only for a real code or semantic dependency, conflict, or current-main
repair; port only the residual diff. Every PR that eventually targets main
independently adds one fragment and passes the release gate.

## Quality gates — exact commands and patterns

The Change workflow above is canonical for the pre-push ceremony; this
is the consolidated command view:

    make check-fast          # Python + Git only: validators + full unittest battery
    make check               # adds gitleaks/shellcheck/actionlint/helm/
                             #   kubeconform/conftest/OpenTofu (versions.env pins)
    make coverage            # floor + drift + byte-exact badge (hash-pinned wheel)
    make pre-push-security   # rehearses the origin/main..HEAD publication gate
    git config core.hooksPath .githooks   # makes the real gate automatic on push

- **Coverage floor.** The committed contract in
  `docs/badges/coverage.json`: floor 76.0%, drift tolerance 2.5%,
  measured over `scripts/**` by the canonical suite recorded there. Its
  `total_percent` is the sole numeric source of truth; do not duplicate a
  measured snapshot in prose. Ratchet only (delivery-lane
  requirement 6): the floor may rise and never falls, and coverage moves
  by adding tests, never by trimming the measured surface.
  `make coverage-refresh` re-measures and rewrites the ledger/badge for
  committing after test changes.
- **Ratchet pairs.** When a stated requirement and shipped behavior
  disagree across lanes, record the gap loudly instead of greenwashing
  it: one green test pins current behavior, and a paired
  `unittest.expectedFailure` twin asserts the pending contract — the day
  a platform-lane change tightens the implementation, the xfail becomes
  an unexpected success, the suite goes hard red, and removing the
  marker converts the note into an enforced deny row. Canonical
  exemplar: `tests/security/test_containerd_cri_health_contract_matrix.py`.
- **Perf discipline.** The site repositories pin payload budgets as
  tests; the analogous discipline here is byte-exactness — render
  determinism (`make check-determinism`) and badge regeneration are
  enforced comparisons, never judgments.
- **Secret scan, both modes.** `make check-gitleaks` scans the working
  tree with the pinned policy (`policies/gitleaks.toml`), and the
  publication gate (`make pre-push-security` / the pre-push hook) scans
  the exact outgoing history range. PR CI re-scans base..head with
  `--ignore-gitleaks-allow` and a verified-empty ignore file, so NO
  allowlist entry is ever honored on the merge path — this repository
  keeps no `.gitleaksignore`; fix the content, never allowlist it.
- **Flake probe.** Before a PR leaves draft the full suite has run at
  least three times (author and reviewer independently); any
  nondeterminism is a finding naming the test.

## CI map

- **pull-request.yml** — pull requests, pushes to `main`, and manual dispatch.
  Pull requests run immutable-PR-history validation
  (`validate_publication_history.py` over base..head —
  noreply identity closure and linear, non-shallow history), gitleaks
  over the exact PR range with the empty ignore file, actionlint, a
  compile sweep of every tracked `scripts/**/*.py` with a count floor,
  the full unittest battery plus `validate_repository.py all`, the
  self-hosted coverage contract (hash-pinned wheel in a disposable
  venv; floor + drift + byte-exact badge), shellcheck, `gitleaks dir`
  plus the ambient-artifact check, Kubernetes render + validation in
  the release-transition mode the release-state policy selects, render
  determinism, the assurance-ledger / no-security-toggles /
  attack-surface-manifest / ingress-guard validators, Kyverno policy
  tests, and credential-free OpenTofu validation — plus a separate
  `dependency-review` job (pull requests only; fails on high severity). Main
  pushes run the same repository/infrastructure battery plus the exact
  base-to-final-SHA one-fragment release transition; manual dispatch runs the battery but
  deliberately skips event-bound transition/history checks.
- **codeql.yml** — pull requests, `main` pushes, weekly cron, and manual
  dispatch.
- **platform-release.yml** — `workflow_run` of the named Pull request workflow;
  its publish job is eligible only after that workflow completed successfully
  for a push to `main`, then binds and publishes the exact final SHA. A distinct
  main SHA has an independent non-canceling transaction.
- **scheduled-security.yml** — weekly cron full-history scan plus manual
  dispatch. Post-merge therefore consists of the full main-push battery and
  CodeQL, followed success-only by the source publisher; scheduled security is
  independent of merges.
- **Zero-spend guardrails on the merge path.** The `tests/security`
  battery IS the guard: `test_actions_zero_spend_exposure.py` pins the
  workflows' exposure (secretless PRs, read-only default permissions,
  GitHub-hosted runners, pinned actions), and
  `test_cloudflare_zero_spend_allowlist.py` pins the committed product
  allowlist (safety invariant 4). The coverage gate is self-hosted so
  no external processor ever receives repository content or
  measurements.
- **Pinning rules.** Every action at a full commit SHA with a version
  comment; every tool version in `versions.env`, checksum-verified by
  `scripts/ci/install-tools.sh`, and enforced by
  `tests/security/test_ci_tool_pins.py`; GitHub-hosted `ubuntu-24.04`
  runners only; PR workflows secretless with checkout credential
  persistence disabled.

## Docs conventions

- **Truthful README.** The deployment-state table is the honest source
  of truth — the repository is deliberately not deployable until the
  fail-closed sentinels are replaced with reviewed evidence, and prose
  never claims otherwise. Badge honesty is enforced: the coverage badge
  is regenerated byte-exact by the gate and cannot claim what CI did
  not measure.
- **Platform source changelog.** `VERSION` and `CHANGELOG.md` are frozen legacy
  history through `v0.1.9` and are not release inputs after issue #164. Each PR
  adds one `changelog.d/` fragment; the tag-derived publisher binds its exact
  bytes into immutable Release notes. Publishing source never claims the
  platform is deployed or promoted, and `make release-check` still rejects
  deployment sentinels independently.
- **Lane discipline in docs.** The platform ADRs and the capacity documents
  are platform-lane: cite them by number, never edit, restate, or reword
  them from the delivery lane. The Cloudflare ADRs (0006–0008, 0015, and
  successors) are delivery-lane per the owner's 2026-08-12 lane re-cut.
  Runbooks and assurance documents are
  delivery-lane and follow the same evidence standard as PR bodies —
  their cross-references are pinned by tests.
- **Attribution.** No third-party creative assets exist here. Any that
  ever arrive land with their reviewed license alongside the asset; the
  site repositories carry their own asset-policy notices.
