# Repository-split and coupling audit — 2026-08-10

Author: Claude Fable 5 (drafted locally; published under the dedicated
machine identity). Scope: everything binding the two embedded websites to
`snaraj/website-infrastructure`, plus rehearsal evidence that the
history-preserving split works. Method: read-only inspection of `main` at
`1b31c89b285bbc3eaae90391c2826cc53ab601b1`, anonymous remote checks, and a
full extraction rehearsal in disposable local clones. Every claim is labeled
CONFIRMED (checked today, evidence cited), INFERRED (reasoned, not directly
executed), or UNKNOWN.

## 1. Baseline (CONFIRMED, anonymous `git ls-remote` + local clone)

- `website-infrastructure` `main` = `1b31c89`; total history is 6 squash
  commits (`397cf36` → `1b31c89`).
- `deploy/pi-live-readiness` exists at exactly `1b31c89` (zero commits
  ahead); stale branch `onboard-cloudflare-and-sops` at `4f70db2`.
- `snaraj/naranjo.online` `main` = `5ff145c` (single owner seed commit,
  README.md only). `snaraj/lidersea.com` `main` = `696d962` (same shape).
  Both destination repositories are seeded — the former import hard-stop is
  cleared.
- GHCR packages `ghcr.io/snaraj/naranjo-online` and
  `ghcr.io/snaraj/lidersea-com` are public (anonymous pull token works).

## 2. Coupling inventory (CONFIRMED at `1b31c89`, file:line)

1. **Flux sources pin the monorepo chart paths.**
   `kubernetes/websites/naranjo-online/source.yaml:14,19` (sparse-checkout
   ignore and include of `websites/naranjo.online/chart`) and
   `release.yaml:17` (`chart: ./websites/naranjo.online/chart`); mirrored for
   lidersea in `kubernetes/websites/lidersea-com/release.yaml:17`. The
   cutover PR must re-point both GitRepositories/HelmReleases at the new
   repositories (or their successor chart location).
2. **Cross-site version lock in release validation.**
   `scripts/validate_image_release.py:37` defines `SHARED_RELEASE_INPUTS`;
   changes there force BOTH site versions to bump, and
   `scripts/validate_image_release.py:715` requires both
   `websites/*/VERSION` files to exist. The monorepo validators must be
   retaught when the sites leave (cutover/removal PRs), or `check-fast`
   fails the moment a site directory disappears.
3. **Go module paths are monorepo-internal.**
   Both sites declare
   `module github.com/snaraj/website-infrastructure/websites/<domain>`
   (`websites/<domain>/go.mod:1`). Builds and tests pass standalone anyway
   (see §4) because the modules are self-contained; renaming to
   `github.com/snaraj/<domain>` is a post-import site-repo change, not an
   import blocker.
4. **Cosign identities pin the monorepo publisher workflows.**
   `policies/kyverno/require-signed-naranjo-online.yaml:33,55`,
   `policies/kyverno/require-signed-lidersea-com.yaml:33,55`, and
   `scripts/promote-image.sh:34,45` all pin
   `https://github.com/snaraj/website-infrastructure/.github/workflows/publish-<artifact>-image.yml@refs/heads/main`.
   The first release from a site repository changes the signing identity;
   Kyverno policies and `promote-image.sh` must be updated in the same
   cutover window (exact replacement strings are proposed in the
   coordination register, SYNC-7).
5. **GHCR package provenance and clutter.** Anonymous tag listing today:
   `naranjo-online` has 8 tags (`v0.1.2`, `v0.1.3`, three `sha-<commit>`,
   three `sha256-<digest>`); `lidersea-com` has 6 (same pattern, two
   generations). The `sha-*`/`sha256-*` entries come from the monorepo
   publishers and attestation plumbing (INFERRED from workflow inspection;
   the tag inventory itself is CONFIRMED). Keeping these packages and
   granting each site repository Actions write access (rather than new
   packages) preserves every existing digest pin (SYNC-4 recommendation).

Identity facts that do NOT change at split (CONFIRMED in chart values and
ADR 0014): image names, chart/Deployment/Service names, namespaces, port
8080, digest-only deployment, immutable version tags, SemVer contract.

## 3. Extraction rehearsal (CONFIRMED — executed 2026-08-10)

Performed in disposable clones under a local scratch directory with
`git filter-repo 2.47.0` (Homebrew), never inside the real clones; nothing
was pushed anywhere.

| Step | naranjo.online | lidersea.com |
| --- | --- | --- |
| Filter (`websites/<d>/` → root) | tip `5017c93`, **5 commits** | tip `c22b635`, **5 commits** |
| Foreign paths in filtered history | 0 | 0 |
| Authorship/dates preserved | yes (verified in log) | yes |
| Seed at destination `main` | `5ff145c` | `696d962` |
| Unrelated-root merge commit | `f7c7e4b` (parents `5ff145c`,`5017c93`) | `e8496a9` (parents `696d962`,`c22b635`) |
| Commits reachable after merge | 7 | 7 |
| Merge conflicts | README.md add/add only | README.md add/add only |
| Frontend `npm ci && npm test && npm run build` | pass (5/5 tests) | pass (2/2 tests) |
| `go vet ./... && go test ./...` at new root | pass (3/3 packages, embed test included) | pass (3/3 packages) |
| `docker build` | image `sha256:1d9cb0aa…` (Go tests re-run in-build) | image `sha256:6f37d08f…` |

The 5-commit-per-site count matches expectation: the monorepo's entire
history is 6 squash commits, and one of them never touched the sites
(SYNC-6). The README add/add conflict is inherent (owner seed and imported
history both add README.md); the rehearsed resolution takes the imported
site README. Import must merge into destination `main` via MERGE COMMIT —
squash or rebase-merge would flatten the imported history.

Environment caveats (CONFIRMED): rehearsal ran node v26.7.0 / npm 11.19.0
vs CI's pinned 24.19.0 / 11.17.0, and a single-architecture local docker
build vs CI's amd64+arm64; Go 1.26.5 and gitleaks 8.30.1 match the CI pins
exactly. The real import PRs will get authoritative results from CI.

## 4. What must change, where, when

| Change | Repo | Phase |
| --- | --- | --- |
| Re-point 2 Flux sources + HelmRelease chart paths | infrastructure | cutover (after platform base merges) |
| Replace 2 cosign identities + `promote-image.sh` | infrastructure | same cutover PR |
| Reteach `validate_image_release.py` / `validate_repository.py` site expectations | infrastructure | cutover + removal PRs |
| Go module path rename | site repos | post-import, pre-first-release |
| Per-site CI (PR gates, coverage), releases | site repos | after import PRs merge |
| Embedded `websites/**` removal | infrastructure | LAST, after both external images deploy and roll back |

## 5. Unknowns and risks

- Ruleset/branch-protection state on all three repos is not anonymously
  verifiable (UNKNOWN here; owner confirms during Gate 0).
- Merge-commit capability must be enabled on both site repos before the
  import PRs merge (owner setting; UNKNOWN until then).
- The pull-request workflow asserts the PR base is `main`
  (`.github/workflows/pull-request.yml:50`), so stacked sub-PRs targeting an
  integration branch fail that single step; validation for stacked work runs
  via `workflow_dispatch` until a small amendment is reviewed (CONFIRMED
  from workflow source).
- Coordination items SYNC-1..9 (chart import marking, GHCR continuity,
  required check names, signature strings, workload schema) await Codex's
  batched answers; none blocks the import PRs themselves.

## 6. Recommendation

Proceed with Phase D (naranjo first, priority site) as soon as Gate 0
passes: the rehearsal proves the exact import shape end-to-end against the
real seeded destinations, with zero foreign paths and green standalone
builds on both sites.
