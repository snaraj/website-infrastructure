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
- `.github/dependabot.yml` — DELIVERY, recorded here as issue #129 discharging
  the amendment that PR #127's declared crossing assigned to it. The file
  configures ecosystems, schedules, and `groups:` stanzas for the workflow and
  module manifests this lane already owns, and a `groups:` stanza is the
  root-cause fix for a split version-locked pair; it is the same surface as its
  `.github/workflows/**` siblings and carries no platform-lane content. The
  file's last change before PR #127 predates the lane split entirely, so no
  post-split precedent or peer-lane claim conflicts with this assignment. Like
  the row above, this one is exact and not shorthand for any other path under
  `.github/**`.

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
- `cmd/platform-release-selector/**` and `internal/releaseselector/**` —
  PLATFORM (owner authorization 2026-08-28 for issue #242). These are the
  bootstrap-owned credentialless selector and its immutable image inputs.
  Delivery-owned CI may materialize and validate the final image, but a
  selector behavior or packaging change remains an authority-boundary change:
  it requires independent security review and the owner-attended live digest
  rotation tracked by issue #222; it never grants selector self-update.
- `policies/conftest/**` and `policies/release-conftest/**` — DELIVERY.
  The enumeration is exact, not shorthand for `policies/**`: these subtrees are the
  executable expression of the gates this lane already owns. Every other
  file under `policies/` — the pinned secret-scan policy
  `policies/gitleaks.toml` among them — is unchanged by this ruling and
  reached only through the rule below. Issue #195 retired Kyverno entirely;
  Conftest is a pre-merge static control and must never be described as live
  admission.
- `.githooks/**` — DELIVERY: the pre-push hook implements delivery-lane
  requirements 2 and 3. Changing what it PERMITS is a security-control
  change and needs an owner decision, not a lane call (issue #83).
- `kubernetes/flux-system/**` — DELIVERY: the GitOps desired state this
  lane authors, and what the reviewed-state model above pins.
- `kubernetes/websites/*/release.yaml` — the former DELIVERY grant applied
  only to output from `scripts/promote-image.sh`. Issue #195 retires that
  script fail-closed and removes the image override, so the grant has no
  remaining write shape and must not be read as authority to recreate one.
  Each site release now supplies exactly `deploymentReady: true`; its signed
  chart is the sole image authority. Outside `kubernetes/flux-system/**`, the
  `cloudflare-public` row below is the only current part of `kubernetes/**`
  assigned to delivery. `kubernetes/reconciliation/**`, the rest of
  `kubernetes/platform/**`, and the remaining `kubernetes/websites/**` files
  stay unruled — reach them only through the rule below.
  The delivery lane set `spec.maxHistory` on both site releases under issue
  #198 as a DECLARED CROSSING, not a lane transfer. Retention is load-bearing
  for reliability rather than release identity: helm-controller's unset
  five-revision default exceeded the measured namespace Secret budget, wedged
  a site release permanently, and blocked every subsequent deploy. Record the
  owner or platform (peer) ruling here when it arrives, including whether
  release-retention fields belong to this lane.
  **Owner ruling 2026-08-28:** the exact version-neutral
  `app.kubernetes.io/managed-by: fluxcd` label on both site HelmRelease
  objects is DELIVERY-owned for issue #240. It supplies the ordinary
  post-bootstrap #189 reconciliation witness and a stable offline inventory
  marker without changing either release spec. This ruling grants no standing
  ownership of other metadata or fields in these manifests.
- `kubernetes/platform/cloudflare-public/**` — DELIVERY, DERIVED from the
  Cloudflare/edge re-cut recorded in the paragraph above, not granted
  here: that re-cut names only `infrastructure/cloudflare/**` and the
  Cloudflare ADRs, and this tree is the same edge surface's in-cluster
  half — the public Tunnel connector chart and its suspended release, the
  cluster end of the tunnel whose provider-side configuration this lane
  already owns, serving the sites this lane promotes through the row
  above. PR #87 already writes it under this reading. Amend this row if
  the owner or the platform (peer) lane rules otherwise.
- `kubernetes/platform/admission/**` and
  `kubernetes/platform/admission-install/**` — RETIRED and absent under the
  owner's issue #195 decision. No lane may recreate a Kyverno controller,
  policy, installer, or report-only/enforce overlay from the old issue #88
  authorization. A material trust-boundary expansion, including another
  independent tenant or untrusted/third-party workload, triggers a new
  threat model and ADR; it is not standing install authority.
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
  standing claim on the tree. Issue #195 is a second DECLARED CROSSING: it
  replaces mutable SemVer selection with one separately receipted audit-tag
  and exact OCI manifest-digest pair per site, while retiring the former
  HelmRelease promotion override. Future forward or rollback selection changes
  require a new exact acquisition receipt and remain crossings until the owner
  or platform (peer) records a lane ruling here. Issue #252 is the first such
  forward selection and is DECLARED as a crossing on exactly those terms: it
  recaptured the receipt and moved both sites to their published releases
  without touching a fail-closed property, a signature contract, or
  `release.yaml`. It is a worked precedent for the shape, not a ruling — the
  row above stays PENDING, and the next selection declares its crossing too.
- `docs/adr/0016-tag-driven-flux-release-sync.md` — NOT transferred,
  ruling PENDING. The lane split above assigns "the remaining ADRs" to
  the platform lane, and "Lane discipline in docs" says the delivery lane
  cites them by number rather than editing them. ADR 0016 is nonetheless
  the decision record for surfaces this lane owns outright (the
  OCI signature validators, Conftest policies, and release-transition
  controls), and it was authored from this lane in commit
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
  Issue #195 subsequently retired the Kyverno capacity policy and its install
  overlay rather than preserving them as restoration inputs. The reviewed
  quota and evidence binding remain enforced by Conftest and repository
  validators.

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
4. No co-author trailers: agent work is signed in the open with the ACTING
   agent's own identity — commit and PR bodies end with the signature that
   matches the agent label the same work carries, per the roster in "Agent
   labels" (`- Fable5` ↔ `fable5`, `- 5.6 Sol` ↔ `5.6-sol`, `- Opus5` ↔
   `opus5`, `- Sonnet5` ↔ `sonnet5`). A fixed lane signature is wrong on its
   face once several models work this repository: it would attribute one
   lane's work to another. Precedents: #123 signed `- 5.6 Sol`, #127 signed
   `- Sonnet5`, both owner-merged.
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
   plus an exact immutable GitHub Release at the complete final SHA. Starting
   with `v0.1.41`, that Release carries exactly the canonical identity JSON and
   its detached Sigstore bundle; `v0.1.40` is the sole zero-asset transition
   predecessor. Release notes bind the
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

**Review depth is risk-based** (owner reduction, 2026-08-22). Ceremony is
spent where a mistake reaches something real; spending security-grade
attention on a comment fix costs the attention a trust boundary needs.
Three tiers, and a change takes the highest tier any of its paths earns:

- **Security-surface changes** — credentials, authorization, public exposure,
  signing, digests, immutable artifacts, destructive operations, workflows,
  policies, validators, the safety invariants, and anything the delivery-lane
  requirements gate — take focused tests, one full CI cycle at the exact head,
  live validation where runtime behavior moves, ONE independent adversarial
  review, and owner merge.
- **Normal code changes** take focused tests and one full local gate; a live
  check only when runtime behavior changes; one review.
- **Documentation, comments, and formatting** run the relevant checks, and
  adversarial review is the coordinator's routing decision rather than a
  mandate. No tier ever skips the secret scans or the publication gate.

Nothing here relaxes a fail-closed control at a real trust boundary: the
safety invariants, owner-only merge, commit identity and signing, digest-only
deploys, SOPS-only secrets, protected-branch settings, and the release
transition gates are the same in every tier. Exact-head discipline is also
unchanged for whatever review DOES run — a verdict binds the head it names.

**Reviewer independence.** The reviewer is a different agent or context
than the author — a fresh session of the same vendor qualifies; a
different lane is better. Independence is established by the POSTING
ACTOR, never by signature wording: a verdict receipt is posted by the
`snaraj-agent-reviews[bot]` GitHub App, a principal separate from the
account that authors and pushes branches and one that holds repository
Contents write nowhere, so a compromised review lane cannot alter what
it reviews. The signature line is lane provenance — content rather than
identity — so any current or future model name is valid there and this
contract pins no model roster. No rule compares the reviewer's name to
the author's: a textual same-lane denial is satisfied by typing a
different word, which is evidence that the reviewer can type and
nothing else. Same-lane review is therefore permitted and stays legible,
and the actor is what a reader verifies. Authoring and reviewing both
reach git and the API through this repository's already configured,
task-authorized owner account; never acquire, extract, exchange, or
change credentials to manufacture reviewer separation, and never print
or repurpose them. The reviewer works in a disposable worktree at the PR
head, stays read-only toward the author's workspace, reverts every
experiment, and removes the worktree afterward.

**Exact-head receipt.** The receipt binds one exact head, and the bot actor
above is what makes it a second party rather than a self-approval. A normal PR
comment contains exactly one `HEAD: <40-lowercase-hex>` line, exactly one
`VERDICT: APPROVE` or `VERDICT: REQUEST-CHANGES`, and ends
`- <Agent> (adversarial reviewer)`. Any head change invalidates it and requires
a fresh independent review. Validate the shape with
`scripts/validate_review_receipt.py --head <head> --resource-kind
pull-request <receipt>`; the
validator rejects issue resources and proves receipt SHAPE only — it never
sees who posted the comment, so the coordinator reads the posting actor from
GitHub. If the owner merged first, record a post-merge audit rather than
retroactive approval.

**Main Worker Ready receipt — RETIRED** (owner reduction, 2026-08-22). There is
no separate Main Worker pass: after an exact-head `APPROVE` and green required
checks at that head, the coordinator flips Ready and the owner merges. No
`ROLE: MAIN-WORKER` receipt is required, none is a Ready input, and no lane may
reintroduce one as a local convention. Machinery for the retired receipt still
exists and is transitional rather than authority — the `main-worker` receipt
kind in `scripts/validate_review_receipt.py`, the Main Worker sections of
`skills/gh-pr-flow/**`, and the `ROLE: MAIN-WORKER` rows of
`.github/PULL_REQUEST_TEMPLATE.md` — and issue #188 owns removing it. Until
that lands this file governs, because a skill never supersedes AGENTS.md.

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
4. Probe for flakes: the author runs the complete local gate once on the
   final head; the reviewer runs the focused checks its findings need,
   plus the race detector where the language has one, and MAY re-run the
   full suite when it has specific cause. Any nondeterminism is a finding
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
coordinator context is distinct from both author and reviewer and
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
  sequencing, settings, metadata, or any other declared gate.
  Owner review or owner merge authority does not waive a blocker; a
  blocker-bearing PR stays Draft.
  Ordinary labels, body text, and process comments are coordination signals,
  never security invariants: they are written by the same lane that authored
  the change and carry no more authority than that. The control evidence is
  the App-posted exact-head verdict — its posting actor and the head it binds —
  alongside the signed-commit chain, the protected-branch settings, and the
  gates that run at that head.
- **Agent labels.** Every agent-created PR and issue carries TWO further
  labels: the umbrella `agent-authored` AND the acting agent's own label —
  `fable5` (Claude Fable 5), `5.6-sol` (ChatGPT 5.6 SOL ULTRA), `opus5`
  (Claude Opus 5), `opus4.8` (Claude Opus 4.8), `sonnet5` (Claude Sonnet 5,
  color `0EA5E9`, description "Authored by Claude Sonnet 5"). The signature
  must match the label (delivery-lane bodies ending `- Fable5` ↔ `fable5`,
  `- Opus5` ↔ `opus5`, `- Sonnet5` ↔ `sonnet5`;
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
  they never waive a real product failure. When Dependabot splits a
  version-locked pair into separate PRs — precedent: `github/codeql-action`
  `init` and `analyze` as #124 and #125 — one agent PR supersedes BOTH,
  applying the paired bump AND the root-cause fix in the same commit: a
  `groups:` stanza in `.github/dependabot.yml` scoped to that pair, so the
  split cannot recur. The superseded Dependabot PRs are left for Dependabot
  to close on its next rebase (merged precedent #127).
- **Merge readiness.** Keep Draft until the exact head has a fresh independent
  APPROVE receipt, all exact-head
  checks succeed, protected base is current, all discussions/findings are
  resolved, metadata/scope/order remain exact, and the platform patch-release
  consequence is proven. Only the coordinator flips Ready and re-verifies;
  author and reviewer never do. Nobody but the repository owner merges.

## Parallel agents in one checkout

Several agents — different models and vendors, executors and reviewers — work
this repository at once, sometimes on one machine. Git worktrees are the
isolation mechanism, and these rules are part of the contract: they bind every
lane whether or not any vendor-specific tooling is present. This section exists
because the cold-start invariant above is literal — an agent that clones this
repository must learn the isolation rules here, not from a machine-local
skills folder that a fresh clone does not carry.

- **The shared checkout is nobody's workspace.** It stays on `main`, clean, and
  is used only for coordination — `git fetch`, worktree creation and removal,
  ceremony reads. No agent builds, edits, or checks out a branch there. It may
  lag `origin/main` harmlessly: every actor works from `origin/main` after its
  own `git fetch origin`, never from a local `main`.
- **One worktree per acting context, named for its lane.** The preferred branch
  grammar is `<lane>-<effort>/<issue#>-<topic>` (e.g.
  `opus5-high/218-contracts-fold`), carrying the dispatched reasoning effort
  (`low | med | high | max`) and the tracking issue; `<lane>` is parsed by
  longest match against the repository-registered agent-label set, then the
  `-<effort>` suffix. Executors run `git worktree add
  .claude/worktrees/<lane>-<effort>-<issue#>-<topic> -b
  <lane>-<effort>/<issue#>-<topic> origin/main`. The legacy `<lane>/<topic>`
  form remains accepted during the transition. Either way the directory and
  the branch carry the SAME lane, because the cleanup rule below depends on
  ownership being legible to every other agent. A worktree whose name and
  branch disagree, or a branch with no lane prefix, is a contract violation.
- **Reviewers work disposably.** A detached-HEAD worktree at the exact pull
  request head (`git worktree add .claude/worktrees/<lane>-review-<PR#>
  <headSHA>`), removed once the receipt posts. A reviewer stays read-only
  toward every other workspace and reverts every experiment inside its own.
- **One writer per branch, one branch per worktree.** A worktree that is not
  yours is a worktree you never write to. Treat reads with care: a tree that
  advances under you mid-operation is a live executor, not stale state.
- **Some git state is shared — that is the trap.** HEAD, index, and working
  tree are per-worktree; refs, remotes, config, and stash are repository-wide.
  So `git fetch`, `git branch -d/-D`, and `git worktree prune` act on every
  lane at once: run them only from the main checkout during deliberate
  cleanup, never mid-task. Never `git config` anything — identity and signing
  are pinned per command per "Commit identity mechanics", and one lane's
  config write poisons all of them. A branch checked out in any worktree
  cannot be deleted or checked out elsewhere; that lock marks live ownership.
- **Clean only your own lane, and only after the owner merges.** Confirm the
  merge against the remote, then remove your worktree and delete your branch
  from the main checkout with `git worktree remove` and `git branch -d` — no
  `--force`, no `-D`. Those refusals are the safety net: a dirty tree or an
  unmerged branch is somebody's live work, very possibly another lane running
  right now. Another lane's leftovers are that lane's to remove, and deleting
  a remote ref is the owner's alone (delivery-lane requirement 2).
- **Shared machines contend.** Heavy suites in several worktrees compete for
  CPU and load-sensitive tests can flake under contention. Treat a contention
  flake as an environment finding — name it, rerun it, never weaken the test —
  and stagger the heaviest batteries when many lanes run at once.

Only process doctrine belongs here. Host and service baselines, admin-ingress
and tunnel design, and credential custody stay machine-local permanently:
safety invariant 12 treats the Git index as public.

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
   are lane-prefixed, in the grammar "Parallel agents in one checkout"
   defines (`opus5-high/218-contracts-fold`; legacy `fable5/<topic>` still
   accepted). One writer per branch, always —
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
7. **Adversarial review** per the protocol above, at the depth its risk
   tier earns; findings are fixed on the same branch by the same writer
   and delta re-reviewed. After an APPROVE at the exact final head with
   every required check green, the coordinator flips Ready — there is no
   second receipt between them.
8. **Owner comments** are handled per the owner review protocol below.
9. **The owner merges.** Nothing you can do — approval, green checks,
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
- **SSH-sign every agent commit, and select the key EXPLICITLY.** Signing is
  pinned per command with the owner-registered signing key, never through
  `git config`, for the same reason the identity is. The obvious selector is
  broken: `key::$(ssh-add -L | grep ssh-ed25519)` matches EVERY loaded ed25519
  line, so `key::` receives a multi-line value and signing fails on a
  malformed key — not an exotic setup, since any agent that also loads a
  deploy or push key hits it. Ask the forge which key is registered for
  SIGNING, intersect that with what the agent actually holds, and require
  exactly one match; the selection then names no key comment, no host, and no
  ordering, so it works unchanged from any machine the owner signs on:

      signing_key() {
        local account matched
        account="$(gh api /user --jq '.login')"
        matched="$(comm -12 \
          <(gh api "/users/${account}/ssh_signing_keys" --jq '.[].key' | sort) \
          <(ssh-add -L | awk '{print $1, $2}' | sort))"
        test "$(printf '%s' "${matched}" | grep -c '')" -eq 1 || {
          printf 'expected exactly one registered signing key in the agent\n' >&2
          return 1
        }
        printf '%s' "${matched}"
      }

      git -c gpg.format=ssh \
          -c user.signingkey="key::$(signing_key)" \
          commit -S ...

  Local verification needs a SPACE-FREE principal in the allowed-signers
  file — the bare identity email read from published history, never
  `Name <email>`, because ssh reads the space as a field break, reports
  `line 1: invalid key`, and matches nothing. That is the trap: a genuine
  WRONG-KEY negative control also reports `No principal matched.`, so a
  malformed file silently false-passes the negative control while proving
  nothing. Run BOTH controls and require them to DIFFER — the positive must
  print `G`, and the negative, holding only some other key, must print `U`.
  If the positive is not `G` the file is broken; repair it before believing
  the negative. Signature enforcement is a protected-branch setting on
  `main`, not a repository-wide one, so it never blocks the owner's own
  merges from a machine that lacks this key.
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

**Stale concurrent Drafts are re-cut, never rewritten.** A Draft that has
fallen far behind current protected `main`, or that has absorbed repeated
REQUEST-CHANGES rounds against a moving base until its published history no
longer resembles the change under review, is superseded rather than repaired
in place: branch fresh from current `origin/main`, port only the reviewed
residual diff, add the new fragment, rerun every gate, obtain a fresh
exact-head review, and close the stale PR as superseded — the branch stays,
because ref deletion is the owner's. That is the #109 → #123 precedent, and
it is a re-cut precisely because rebasing or force-pushing a published branch
is barred by delivery-lane requirement 2.

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
- **Flake probe.** The author runs the complete local gate ONCE on the
  final head; the reviewer runs the focused checks its findings need and
  MAY re-run the full suite when it has specific cause. Any
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
  attack-surface-manifest / ingress-guard validators, Conftest hostile-policy
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
  of truth — unresolved lanes remain blocked until fail-closed sentinels are
  replaced with reviewed evidence, and safe-active desired state never claims
  live reconciliation, readiness, or traffic without live proof. Badge honesty is enforced: the coverage badge
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
