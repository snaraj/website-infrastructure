# Practical security and threat-complexity audit — 2026-08-10

Author: Claude Fable 5. Scope: whether the repository's security machinery
matches the owner's practical goals (working infrastructure, standard
controls, revocable credentials, tested recovery — not ceremony), at `main`
= `1b31c89`. Labels: CONFIRMED / INFERRED / UNKNOWN. This audit reports; it
changes nothing. The companion practical security model (separate PR)
proposes the go-forward policy.

## 1. What is genuinely strong (CONFIRMED)

- Enforcement is executable, not aspirational: `validate_repository.py all`
  (8 sections), 697 discovered unit tests, a pre-push gate
  (`scripts/pre-push-security.sh`) that binds an immutable outgoing range,
  isolated-Python validator loading, a pinned gitleaks version, an
  owner-only empty ignore file, and worktree/index purity checks.
- Commit-metadata privacy is enforced: publication history rejects any
  email outside `*.invalid` / `*@users.noreply.github.com`, plus local
  workstation paths, non-public IPs, UUIDs, and opaque identifiers
  (`scripts/validate_publication_history.py`).
- CI is secretless on PRs, job-scoped elsewhere, fully SHA-pinned, version
  asserted, with CodeQL, dependency review, scheduled full-history secret
  scans, and dual trivy passes.
- Supply chain: digest-only deployment, keyless cosign signing, Kyverno
  admission pinned to exact workflow identities, SBOM/provenance bound to
  verified OCI views.

## 2. Findings

### F1 — Rejected-control residue in security docs (CONFIRMED)

`docs/security/security-control-matrix.md` and `docs/security/threat-model.md`
still require WARP-based runtime evidence ("SSH/API over WARP", "WARP on/off
tests") and present hybrid-PQ age custody as a standing control. Owner
direction (2026-08-10, recorded in the coordination plan) removes WARP,
attended/encrypted boot, hybrid-PQ custody, and bespoke launchers as launch
gates. The docs therefore overstate launch requirements. Correction (Phase
J, owner-accepted): re-scope those runtime-evidence rows to LAN/physical
recovery until the optional remote-access phase exists, and mark hybrid-PQ
as deferred hardening, not baseline.

### F2 — The strongest local gate is opt-in and currently unwired (CONFIRMED)

`.githooks/pre-push` exists, but `core.hooksPath` is unset in a fresh clone,
so nothing runs it. The gate executes only when a developer knows to run
`make pre-push-security`. Recommendation: a documented one-line setup step
(`git config core.hooksPath .githooks`) in README/onboarding, or a
bootstrap check; keep it advisory (server-side rulesets remain the real
enforcement).

### F3 — The security suite is Linux-bound; macOS runs are 15% red (CONFIRMED)

On a stock macOS workstation, `make check-fast` fails 103 of 697 tests for
two environmental reasons: (a) the symlinked `/var` temp root trips the
suite's own link-traversal/canonical-path guards (~90 tests); (b) 13 tests
exercise Linux-only semantics (procfs mount fingerprinting, symlink-race
defenses). CI on ubuntu-24.04 is green (verified via anonymous check-run
API). Risk: developers on macOS learn to ignore red, which erodes the
pre-push discipline the repo depends on. A minimal repair (realpathed
TMPDIR in the Makefile + explicit platform skip-guards with reasons) is
drafted as its own PR.

### F4 — Commit-trailer email convention is undefined under the metadata gate (CONFIRMED)

The gate (correctly) rejects real-domain emails in commit metadata, which
includes the conventional AI-attribution trailer address at the assistant
vendor's real domain. Interim convention adopted for drafts: a trailer
naming Claude Fable 5 at an address under the RFC-reserved `.invalid`
top-level domain (unresolvable, and no GitHub account-linkage risk). Owner
decision requested: either bless that convention in the contribution docs
or allowlist the vendor's specific noreply address in the validator via a
reviewed change. (No literal addresses appear in this file because the
repository privacy check forbids them here too — itself a sign the gates
compose correctly.)

### F5 — One legacy real email exists in public history (CONFIRMED, accepted)

The initial commit (`397cf36`) carries a personal Gmail address in its
author/committer fields, predating the gate. History rewriting is
prohibited and the address is already public; no action beyond awareness.
The gate prevents recurrence for all future pushes.

### F6 — Machine-identity emails must be real-account noreply at push time (INFERRED)

Draft commits currently use a placeholder bot identity in GitHub's noreply
address form before the machine user exists. GitHub links noreply-form
addresses to accounts by username; before anything pushes, draft branches
must be re-authored to the actually provisioned account's numeric-ID
noreply form so attribution cannot point at an unrelated account that
happens to hold a similar username.

### F7 — Single-node honesty (CONFIRMED, already mostly handled)

Public docs largely avoid HA claims; the standing rule (futures register
I-4) is that resilience is fast rebuild + tested rollback + monitoring,
never availability. Any doc language implying otherwise should be corrected
opportunistically in Phase J.

## 3. Practicality verdict

The machinery is unusually strong for a single-owner project and — after
F1's doc correction — aligned with the owner's "practical, not
ceremonial" ruling: nothing in the enforced path requires WARP, special
hardware, or attended boot; everything is revocable and rebuildable. The
main practical debts are developer-experience (F2, F3) and convention
clarity (F4, F6), all addressable in small reviewed PRs already drafted or
planned.
