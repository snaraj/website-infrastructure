# Practical security model

Adopted 2026-08-10. This is the plain-language, owner-facing policy layer
above `threat-model.md` and `security-control-matrix.md`. Where an older
document demands more than this model at launch time, this model wins until
that document is corrected. It is application-stack-agnostic: it may
require an OCI image, an immutable digest, a non-root runtime, an internal
port, probes, resource bounds, secret references, and network policy; it
never requires a particular frontend framework, language, or site layout.

## Owner acceptance criteria this model serves

1. A fresh host plus the repository's install path yields a working
   platform that can deploy a simple web application — rebuild-from-repo is
   the recovery model.
2. Heavily security-leaning throughout, at zero provider spend of any kind
   on any platform.
3. Heavy media (high-bitrate video, lossless audio) eventually serves well
   to a genuinely public audience on a residential-gigabit-class uplink.
   All transcoding happens at ingest, never on the serving host, which has
   no hardware encoder; media stays fail-closed until its own activation
   phase.
4. A future per-site authenticated admin endpoint (small-CMS direction)
   must remain designable without re-architecting.

## Control classification

- **REQUIRED before first public deployment** — blocks launch.
- **FOLLOW-UP** — sensible hardening after launch, scheduled.
- **DEFERRED** — waits for a real requirement; recorded so it is not
  redesigned out.
- **REJECTED** — disproportionate for a single-owner system; do not
  reintroduce as a gate.

Standing REJECTED set (owner ruling): Cloudflare WARP as a launch or
recovery requirement; attended or full-disk-encrypted boot; TPM/HSM or
hardware-bound key custody; hybrid-post-quantum custody schemes as
baseline; bespoke launchers or custom trust daemons. Standard revocable
credentials, root-only files, pinned dependencies, immutable digests,
backups, and tested recovery are the baseline instead.

## Threats, practical controls, and response

For every threat: control now → remaining work → accepted risk → response
owner (always the repository owner; agents prepare, owner executes) →
escalation trigger.

### T1. Accidental secret publication
- Now (REQUIRED, largely in place): pinned-version gitleaks on every
  outgoing range with the committed policy; repository-wide privacy
  validators rejecting real emails, private hosts, paths, and identifiers
  in files and commit metadata; secretless PR CI.
- Remaining: wire the shipped pre-push hook visibly into onboarding.
- Accepted risk: a novel secret shape can evade patterns once.
- Escalation: any confirmed leak → revoke/rotate first, then history
  handling decided by the owner (no silent rewrites).

### T2. Malicious or unreviewed repository change
- Now (REQUIRED): PR-only main, owner-only merge; agents hold non-admin
  write with no bypass; required status checks named and enforced once the
  owner activates them (Gate 0).
- Remaining: owner activates rulesets on all three repositories; required
  checks list finalized.
- Accepted risk: single-owner review is one pair of eyes; machine review is
  labeled as machine review, never as an independent human.
- Escalation: any bypass-capable credential observed in an agent context →
  hard stop, revoke.

### T3. Compromised CI action or dependency
- Now (REQUIRED, in place): every third-party action pinned to a full
  commit SHA with a named version comment; dependabot on three ecosystems;
  CodeQL; dependency review failing on high severity; toolchain versions
  asserted byte-exact; checksum-verified tool installs.
- Remaining: keep pins current via dependabot cadence.
- Accepted risk: upstream compromise inside a pinned revision window.
- Escalation: advisory affecting a pinned revision → pin forward via PR.

### T4. Substituted or unsigned container image
- Now (REQUIRED, in place): digest-only deployment; chart keyless signatures
  bound to exact protected-main publisher identities; Flux refuses
  unsigned/unmatched charts; SBOM/provenance remain bound to verified OCI
  views and Conftest rejects mutable or foreign workload images.
- Remaining: identity strings rotate once at cutover to the site
  repositories (single reviewed PR; exact strings already proposed).
- Accepted risk: registry availability is external.
- Escalation: Flux verification failure → selection stays closed; rollback
  requires a separately reviewed exact prior digest with no fallback.

### T5. Stolen or leaked revocable credential
- Now (REQUIRED): short-lived fine-grained tokens for agents (24h target,
  7-day max), owner-injected, never in chat/files/argv/history; per-workflow
  GITHUB_TOKEN/OIDC for CI; no agent access to secrets stores.
- Remaining: provision the dedicated machine user; revocation drill once.
- Accepted risk: within a token's short life, its narrow scopes are usable.
- Escalation: suspected exposure → revoke in UI first, rotate, audit the
  security log before resuming.

### T6. Unnecessarily exposed administration surface
- Now (REQUIRED, in place by design): no public origin, no router
  port-forward, outbound-only tunnel, SSH on LAN only, loopback-only
  auxiliary services; UFW active.
- Remaining: optional exact-target remote access is a DEFERRED phase with
  its own constraints; nothing about it may weaken LAN/physical recovery.
- Accepted risk: LAN-resident attacker reaches SSH's authentication layer.
- Escalation: any listener appearing outside the recorded baseline →
  investigate before any other platform work.

### T7. Theft or loss of the host or its storage
- Now (REQUIRED): plainly stated residual risk — a stolen running host or
  disk may expose host-held credentials and data; the practical response is
  revoke, rotate, rebuild from repository, restore tested backups.
  Kubernetes API data is encrypted at rest; irreplaceable originals carry
  encrypted off-device backups.
- REJECTED as launch gates: disk encryption requiring attended boot,
  hardware-bound custody.
- Escalation: physical loss → immediate credential revocation sweep, then
  rebuild.

### T8. Provider account compromise (GitHub, Cloudflare)
- Now (REQUIRED): passkey/MFA on owner accounts (owner-attested), minimal
  token scopes, zero standing broad tokens, phase-scoped short-lived
  provider tokens only during authorized windows, spend-bearing products
  structurally excluded (zero-spend rule is absolute and now explicitly
  covers every platform).
- Remaining: periodic owner review of authorized applications/tokens.
- Accepted risk: provider-side compromise is externally driven.
- Escalation: unexpected token, ruleset, or billing artifact → freeze all
  agent activity, owner rotates account credentials.

### T9. Host or root compromise of the platform
- Now (REQUIRED): rebuild-from-repo as the recovery model; digest-pinned
  workloads; restricted pods without tokens or egress by default;
  containment boundaries tested by policy fixtures.
- Remaining: platform bootstrap and recovery drills are the platform
  lane's deliverables on its active branch.
- Accepted risk: a root-level compromise invalidates local evidence; the
  answer is reprovision, not forensics theater.
- Escalation: integrity doubt → stop mutations, rebuild, rotate everything
  the host could read.

### T10. Bad deployment or lost node (availability)
- Now (REQUIRED): recorded rollback digest per release; single-command
  redeploy of the previous digest; declarative desired state.
- FOLLOW-UP: post-cutover, per-site release/rollback rehearsal against the
  live platform with recorded digests.
- Honesty rule (always): this is a single-node system; resilience means
  fast rebuild, tested rollback, and monitoring — never claimed as high
  availability. Two replicas on one host are not availability.
- Escalation: failed rollback → restore from the platform recovery path;
  the embedded sources remain deployable until both external images have
  deployed and rolled back successfully.

## Boundaries this model refuses to cross

- No control may require spend on any platform (hosting, CI, registry,
  badges, monitoring — free tiers only, nothing metered).
- No control may remove LAN/physical recovery or make the host depend on a
  third party to boot, recover, or serve.
- No security ceremony may block the owner's stated product goals; when a
  control and the product conflict, the conflict is surfaced to the owner
  rather than silently resolved in either direction.
