# Repository instructions

These rules apply to every human and automated contributor.

## Cold start — first-session checklist

A new agent operates from this repository alone; nothing is relayed by
the owner. In order:

1. Read this file end to end — the safety invariants and the lane split
   before anything else; CLAUDE.md only imports it.
2. `git fetch origin` and work from `origin/main`. Never trust a local
   `main`, a stale worktree, or another agent's summary of remote state —
   verify remote facts directly (`gh pr view`, `git ls-remote`).
3. Verify identity and tooling: `gh auth status` shows the owner's
   account; commits carry the noreply identity per "Commit identity
   mechanics"; `make check-fast` needs only Python and Git, and the full
   `make check` needs the pinned toolchain from `versions.env`.
4. Survey the live state yourself: `gh issue list`, `gh pr list` —
   including the open-agent-PR count against the PR budget below.
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

**Lane-surface rulings (owner, 2026-08-12).** Load-bearing surfaces the two
lists above never named, each assigned once so the question stops being
re-adjudicated per pull request:

- `bootstrap/flux/**` — DELIVERY for its reviewed-state model, README, and
  docs. `bootstrap.sh` embeds the inventory and desired-state assertions
  covering the delivery-owned `kubernetes/flux-system/**` manifests, and
  that model is the mechanism that proves the cluster matches them. Its
  live-apply custody surface stays PLATFORM-owned and stays blocked: the
  `--apply-controllers` / `--apply-sync` / `--verify` stop, the trusted
  reviewed-blob launcher requirement, and the credential-custody
  preconditions. The split is by responsibility, not by line range — a
  delivery-lane change may correct what the model asserts about reviewed
  state, never what the stop permits.
- `policies/**` — DELIVERY, covering `policies/conftest/**`,
  `policies/kyverno/**`, and `policies/release-conftest/**`: these are the
  executable expression of the gates this lane already owns. One caveat:
  a change to ADMISSION policy semantics needs peer/platform validation
  before enforcement is enabled anywhere.
- `.githooks/**` — DELIVERY: the pre-push hook implements delivery-lane
  requirements 2 and 3. Changing what it PERMITS is a security-control
  change and needs an owner decision, not a lane call (issue #83).
- `kubernetes/flux-system/**` — DELIVERY: the GitOps desired state this
  lane authors, and what the reviewed-state model above pins.
- `kubernetes/websites/*/release.yaml` — DELIVERY when changed by a
  reviewed `scripts/promote-image.sh` pull request, under the owner's
  standing deploy grant. That promotion surface is the only part of
  `kubernetes/**` outside `kubernetes/flux-system/**` this lane writes;
  `kubernetes/platform/**`, `kubernetes/reconciliation/**`, and the
  remaining `kubernetes/websites/**` files are unchanged by this ruling
  and stay platform-adjacent — reach them only through the rule below.

**A path in neither list is not implicitly delivery.** Silence is not
permission. Declare the crossing in the pull request body before touching
the path, obtain an owner or peer ruling, and then — this part is an
obligation, not a courtesy — amend the rulings above with the answer, in
the same pull request or the next one you open. A ruling left in a review
thread is a question the next agent has to ask again.

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
   actual diffs, reproducing every number the body cites. Overstatement
   is a finding even when the code is right.
2. Build a mutation kill matrix: for each guard or test the PR adds or
   changes, apply the exact regression it claims to prevent — the suite
   must go red. Revert between mutations. A surviving mutant is a
   finding.
3. Probe for vacuity: a guard that cannot fail is no guard. For each new
   or changed assertion, demonstrate at least one input that turns it
   red (the kill matrix usually supplies it); an assertion no input can
   fail is decorative, and decorative checks are findings.
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

**Verdict format** — posted as a PR comment, so every vendor and the
owner see the identical record: APPROVE or REQUEST-CHANGES; numbered
findings with severity and file:line; the mutation kill matrix; flake
results; a claim-audit table (SUPPORTED / OVERSTATED per claim); explicit
"no finding — checked X, Y, Z" statements so silence is never ambiguous;
confirmation the scratch workspace was removed; the reviewing agent's
signature in the form `- <Agent> (adversarial reviewer)`, matching its
agent label. Posting the verdict also removes the `requires-review`
label, whichever way the verdict went — the item is no longer waiting on
review attention. A REQUEST-CHANGES verdict returns the work to the same
branch owner — fixes land on the same branch and receive a delta
re-review of the changed scope. A PR flips from draft to ready only
after an APPROVE verdict (or after findings are fixed and re-verified),
and the evidence comment remains on the PR as the permanent record.

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
  `delivery-lane`, `features`, `requires-review`. New labels are added to
  all three at once. This repository additionally retains two repo-local
  legacy labels from the separation era (`platform`, `extraction`); the
  shared taxonomy governs new work.
- **`requires-review` — the review-readiness signal.** The author lane
  applies `requires-review` the moment a PR or issue is
  complete-from-author — every commit pushed, body and evidence final —
  so review attention is productive. Its ABSENCE on an open
  agent-authored PR or issue means the item is still in flight:
  reviewers and other lanes must not spend review effort on it. The
  reviewer removes it when posting the verdict; on REQUEST-CHANGES the
  author re-applies it once the fix commits are pushed. On an issue it
  carries the same meaning — complete enough to act on or decide — and
  whoever then acts on it or records the decision removes the label;
  opening a PR that claims the issue counts as acting. It is
  a coordination signal only: never a substitute for draft/ready state,
  for the APPROVE verdict that flips a PR ready, or for owner merge
  authority.
- **Agent labels.** Every agent-created PR and issue carries TWO further
  labels: the umbrella `agent-authored` AND the acting agent's own label —
  `fable5` (Claude Fable 5), `5.6-sol` (ChatGPT 5.6 SOL ULTRA), `opus5`
  (Claude Opus 5), `opus4.8` (Claude Opus 4.8). The signature must match
  the label (delivery-lane bodies ending `- Fable5` ↔ `fable5`;
  Codex-lane titles ending " - Codex 5.6 Sol Ultra" ↔ `5.6-sol`), and
  adversarial-review verdicts carry the same identity as
  `- <Agent> (adversarial reviewer)`. These repositories are worked by
  several frontier models in parallel lanes; labels plus signatures keep
  authorship auditable with no owner relay. When a new model joins, its
  label — description "Authored by <model>" — is created in ALL THREE
  repositories before its first PR, per the one-taxonomy rule.
- **PR budget.** At most 3 agent PRs open in this repository by default;
  parallel pushes beyond that need explicit owner authorization first.
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
   owner, set a milestone. Apply `requires-review` once the issue is
   complete-from-author — the problem stated, the acceptance criteria
   final; until it carries that label, the issue is still being drafted.
3. **Branch from `origin/main`** after `git fetch origin`; branch names
   are lane-prefixed (`fable5/<topic>`). One writer per branch, always —
   a branch that is not yours is a branch you never push to.
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

- EVERY history-writing command runs under the same pinned environment —
  `commit`, `commit --amend`, `rebase`, `cherry-pick`. A rebase rewrites
  the COMMITTER of every replayed commit, and the privacy gate checks
  the committer field (`scripts/validate_publication_history.py`
  enforces the closure over the whole outgoing range, in the pre-push
  hook and again in PR CI), so an unpinned rebase silently reintroduces
  the machine identity into otherwise-clean commits.
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

## Stacked pull requests

Stacking is sanctioned for dependent work; these rules exist because a
squash-merge repository punishes careless stacks:

- The stacked PR's base is THE BRANCH IT STACKS ON, so its diff shows
  only the increment.
- A stacked PR STAYS DRAFT UNTIL ITS BASE MERGES. Squashing a stacked
  PR before its base would duplicate the base's entire content into
  `main`.
- When the base merges: `git fetch --prune`; rebase the stacked branch
  onto `main` under the pinned identity environment (the committer
  rewrite above); re-run the gates on the rebased head; then
  `git push --force-with-lease` to YOUR OWN single-writer branch — the
  sole force-push an agent ever performs in this repository. GitHub
  retargets the PR to `main` automatically; verify the retarget and the
  residual diff yourself.
- One writer per branch, always, and remote truth is checked directly —
  `gh pr view`, `git ls-remote` — never assumed from another agent's
  report.

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
  measured over `scripts/**` by the canonical suite recorded there
  (80.8% at the last refresh). Ratchet only (delivery-lane
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

- **pull-request.yml** — pull requests and manual dispatch ONLY; no job
  runs on pushes to `main`. The battery: immutable-PR-history
  validation (`validate_publication_history.py` over base..head —
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
  `dependency-review` job (pull requests only; fails on high severity).
- **codeql.yml** — pull requests, `main` pushes, weekly cron, and
  manual dispatch. **scheduled-security.yml** — weekly cron full-history
  scan, plus manual dispatch. Nothing else runs post-merge: what merges
  is what was gated.
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
- **No CHANGELOG yet.** Releases are deliberately suspended
  (`make release-check` rejects every deployment sentinel); release and
  versioning ceremony arrives with the release-state policy, per
  ADR 0014.
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
