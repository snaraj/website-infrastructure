# Roadmap to v1.0.0 — "Productionalized"

This document is the single source of truth for the cross-repo path to v1.0.0.
It binds the three repositories that make up the platform:

- [`website-infrastructure`](https://github.com/snaraj/website-infrastructure) — platform, validation, and operations
- [`naranjo.online`](https://github.com/snaraj/naranjo.online) — website
- [`lidersea.com`](https://github.com/snaraj/lidersea.com) — website

Day-to-day work is tracked in each repo's GitHub milestones ([linked below](#milestones));
this file defines what v1 means, the phases that reach it, and the invariants that
bound every step. There is no fixed date: v1 ships when the exit criteria are met.

## What v1.0.0 means

**v1.0.0 = "Productionalized":** both websites deployed live and serving on the
production cluster (home Raspberry Pi Kubernetes, fronted by Cloudflare), with
the platform stable and the admin plane hardened.

**Semver stance:** all three repos remain on 0.1.x pre-release versions until
go-live. v1.0.0 is tagged only when the definition above is met and verified —
no earlier bump to 0.2.x or 1.0.0-rc.

## Phases to v1

Phases 1–3 can proceed in parallel; Phase 4 requires all of 1–3; Phase 5 closes.

### Phase 1 — Platform live *(Codex lane)*

The Kubernetes cluster on the production hardware is installed and stable.

**Exit criteria:**
- Cluster stable under its recovery/validation runbooks.
- `CODEX_PLATFORM_STABLE` published.

### Phase 2 — Admin plane hardened

**Exit criteria:**
- SSH-only host-ingress guard live-proven on the host (triple-gated apply).
- Cloudflare Tunnel + Access admin plane provisioned and proven from an
  external vantage point.
- WireGuard retired.

### Phase 3 — Repo production-readiness *(all three repos)*

**Exit criteria:**
- Test coverage ≥85% via E2E-style lifecycle and fail-closed tests.
- Ratcheting coverage gates in CI (thresholds can rise, never fall).
- Documentation accurate — no drift between docs, decisions, and code.
- All badges green and self-hosted (no external coverage processors).

### Phase 4 — Deploy & cutover

**Exit criteria:**
- Both sites deployed to the production cluster.
- Cloudflare DNS cutover complete.
- Serving verified from an external vantage point.

### Phase 5 — Tag v1.0.0

**Exit criteria:**
- v1.0.0 tagged in all three repos.
- Both v1 milestones closed everywhere.

## Current status (as of 2026-08-10/11)

| Area | Phase | Status |
| --- | --- | --- |
| Platform runtime | 1 | Install failed and recovering; no stable signal yet |
| Ingress guard | 2 | Merged ([#30](https://github.com/snaraj/website-infrastructure/pull/30)); live apply held |
| Cloudflare admin plane | 2 | Decided ($0 design complete); provisioning pending, external proof outstanding |
| Repo production-readiness | 3 | PRs in flight; coverage ~71–77% → target ≥85% |
| Deploy & cutover | 4 | Not started (blocked on Phases 1–3) |
| Tag v1.0.0 | 5 | Blocked on all of the above |

## Invariants

These hold at every phase and are never traded away:

- **Zero spend** on any platform — free tiers only; nothing metered is ever enabled.
- **Security and privacy are never traded** for performance or convenience;
  controls fail closed with no runtime bypass.
- **The owner is the sole merge and live-mutation authority** — agents propose;
  only the owner merges to `main` or applies changes to live systems.

## Milestones

| Repo | Production readiness | v1.0.0 — Productionalized |
| --- | --- | --- |
| website-infrastructure | [milestone 3](https://github.com/snaraj/website-infrastructure/milestone/3) | [milestone 4](https://github.com/snaraj/website-infrastructure/milestone/4) |
| naranjo.online | [milestone 3](https://github.com/snaraj/naranjo.online/milestone/3) | [milestone 4](https://github.com/snaraj/naranjo.online/milestone/4) |
| lidersea.com | [milestone 3](https://github.com/snaraj/lidersea.com/milestone/3) | [milestone 4](https://github.com/snaraj/lidersea.com/milestone/4) |
