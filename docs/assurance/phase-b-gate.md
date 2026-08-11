# Phase B — the deterministic terminal gate

Maps every Phase B requirement to its executable checker. The terminal gate
is the **`repository-and-infrastructure`** job in
`.github/workflows/pull-request.yml` — this name is the stable contract for
branch protection/rulesets and must not be renamed casually. Companion jobs:
`analyze` (CodeQL) and `dependency-review`. Local parity:
`make check` runs the credential-free layers (validators, tests, gitleaks
tree scan, shellcheck, actionlint, render/policy, ingress guard; plus opt-in
`make check-determinism` and `make coverage`). CI-only layers with no local
equivalent in `make check`: the Trivy vuln/secret and misconfig scans, the
immutable PR-history proof with history-ranged gitleaks, and the
hash-pinned coverage gate — rehearse the history gate with
`make pre-push-security`.

## Requirement → checker

| Requirement | Checker | Status |
| --- | --- | --- |
| Layout/privacy/media/secret/workflow/Kubernetes/Cloudflare/activation/release validators | `validate_repository.py` (9 modes; `all` runs 8 and `release` is the deliberate deployment gate) in CI + `validate-security.sh` | LIVE |
| Full unit/security test discovery | `unittest discover` under pinned Python (CI) / `make check-fast` | LIVE |
| Bash syntax + pinned ShellCheck | CI shellcheck step over `bootstrap scripts` (pinned via install-tools) | LIVE |
| Python compile + unit tests | compile smoke list + suite | LIVE |
| YAML/JSON/schema validation | kubeconform `-strict` on every rendered artifact; JSON schemas in fixtures | LIVE |
| Kubernetes OpenAPI validation (exact supported version) | kubeconform against the pinned schema set | LIVE |
| Kustomize/Helm rendering with deterministic output hashes | `render-manifests.sh` + **`ci/verify-render-determinism.sh`** (two renders byte-identical) | LIVE (this PR) |
| Kyverno allow **and** deny cases | `kyverno test tests/kubernetes/kyverno` (44 cases) + `test-policy-fixtures.sh` | LIVE |
| NetworkPolicy structural tests + behavioral-proof contract | conftest rendered-object rules + kyverno exact-networking suite; behavioral canaries are Phase G by design | LIVE / phased |
| GitHub Actions static validation + least-privilege `permissions:` | `validate_repository.py workflows` (pins, permissions, persist-credentials) | LIVE |
| Secret scanning with hostile fixtures proving redaction | pinned gitleaks (tree + full history at pre-push) + privacy validators + **ledger forbidden-pattern tests** (`test_assurance_ledger.py` hostile notes) | LIVE (extended) |
| Dependency and license review | `dependency-review` job (fails on high severity); exact-MIT license law in site repos | LIVE |
| SBOM generation | site publishers attach SBOM + provenance per release (platform consumes digests) | LIVE (site lane) |
| OCI manifest/index inspection proving linux/arm64 children | site publisher verification lane + `verify-existing-oci-release.sh` read-only re-proof | LIVE |
| Immutable digest/tag/repo/workflow-identity/release-subject checks | `validate_image_release.py`, `validate_signature_policy.py`, conftest signature policy, kyverno require-signed | LIVE |
| Sigstore verification + negative tests (wrong repo/ref/issuer/subject/digest/unsigned) | signature-policy allow/deny fixtures + `verify-existing-oci-release.sh` closed identity allowlist | LIVE |
| Reproducibility evidence for rendered manifests | `ci/verify-render-determinism.sh` in the terminal gate | LIVE (this PR) |
| Evidence-ledger validation (schema, order, unique IDs, forbidden patterns) | **`validate_assurance_ledger.py`** in the terminal gate + `validate-security.sh`; closes PLAT-GAP-002 | LIVE (this PR) |
| Security-toggle sweep (Coinkite law, Phase C) | **`validate_no_security_toggles.py`** over the tracked tree in the terminal gate + `validate-security.sh` | LIVE |
| Offensive-validation attack-surface contract (Phase H) | **`validate_attack_surface_manifest.py`** on `docs/assurance/attack-surface-manifest.json` in the terminal gate | LIVE |
| SSH-only host-ingress guard artifacts (PLAT-DEC-001) | **`validate_ingress_guard.py repo`** + **`validate_admin_ingress_contract.py EXAMPLE`** in the terminal gate and `make check-ingress-guard` | LIVE |
| Coverage floor, drift bound, and badge integrity | **`scripts/ci/coverage_gate.py gate`** after the instrumented suite (hash-pinned wheel, no external service) | LIVE (this PR) |

## Required CI properties

- **No network-dependent test masquerades as a unit test**: the suite runs
  hermetically; the only network steps are labeled CI steps (tool
  download via checksum-pinned `install-tools.sh`, trivy DB fetch).
- **Pinned tools**: every action full-SHA-pinned; every downloaded tool
  checksum-verified; renderer versions pinned (determinism check would
  expose drift).
- **Read-only default**: top-level `permissions: {}`; PR jobs hold no
  secrets; `persist-credentials: false` everywhere; forks get nothing.
- **Artifacts**: the repository publishes no CI artifacts from PR runs;
  rendered outputs live and die with the runner. The evidence ledger is
  the reviewed, committed artifact — validated fail-closed.
- **Windows/PowerShell lane**: no PowerShell launchers exist in this
  repository (they are private, Codex-side); the requirement is
  N/A here and recorded as such rather than silently skipped.

## Residuals

- Rekor transparency-log spot checks (T4) — scheduled-security candidate,
  needs a bounded network-labeled job; tracked, not yet wired.
- Behavioral NetworkPolicy canaries — Phase G under owner authorization.
- Action-inventory diff alerting (T3) — candidate for scheduled-security.
