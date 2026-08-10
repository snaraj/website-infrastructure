# Phase A — invariant catalog

Every invariant names its owner, its executable checker in this repository,
its evidence class, failure severity, and remediation owner. An invariant
without an executable checker is listed as a GAP finding, not silently
assumed. Checkers referenced here run in the terminal CI gate
(`.github/workflows/pull-request.yml` job `repository-and-infrastructure`)
or the pre-push gate (`scripts/pre-push-security.sh`) unless noted.

Severity: S1 = security/spend/privacy breach; S2 = integrity/availability of
the platform contract; S3 = drift that misleads operators.

## Cost (first-order)

| ID | Invariant | Checker | Evidence | Sev | Remediation |
| --- | --- | --- | --- | --- | --- |
| PLAT-COST-001 | No Cloudflare resource outside two Free-plan zones; no metered feature in IaC | `scripts/validate_repository.py cloudflare` + `policies/conftest` cloudflare fixtures + `scripts/validate-cloudflare-iac.sh` (credential-free init/validate of all seven phase roots) | CI PASS | S1 | Fable lane |
| PLAT-COST-002 | No paid GitHub feature: public repos, free runners, GHCR public pulls | repo settings are owner-controlled; CI asserts nothing pulls with credentials (`persist-credentials: false` and SHA pins enforced by `scripts/validate_repository.py` `check_workflows`) | CI PASS | S1 | owner |
| PLAT-COST-003 | Registrar renewals are the only authorized charges; unknown billing = NO-GO | documented law (`README.md`, `docs/runbooks/public-launch.md`); no executable probe can exist without credentials — GAP accepted, owner audits billing UI | owner attestation | S1 | owner |

## Supply chain and release identity

| ID | Invariant | Checker | Evidence | Sev | Remediation |
| --- | --- | --- | --- | --- | --- |
| PLAT-SUP-001 | Workloads deploy by immutable digest only; version tags never move | `scripts/validate_image_release.py` (SemVer + graduation gates), `policies/conftest/kubernetes.rego` digest rules, kyverno `require-approved-images` | CI PASS + 52 kyverno tests | S1 | Fable lane |
| PLAT-SUP-002 | Only the two site tag-form publisher identities are trusted (`…/release-publisher.yml@refs/tags/v*`) | `scripts/validate_signature_policy.py` (closed contract), `policies/conftest/signature-policy.rego`, `scripts/ci/verify-existing-oci-release.sh` trust boundary, kyverno `require-signed-*` | CI PASS + allow/deny fixtures | S1 | Fable lane |
| PLAT-SUP-003 | Flux pulls anonymously; site sources pin their standalone repos with chart-rooted sparse checkout; platform sources pin this repo | `approved_git_source_urls`/`approved_git_source_scopes` in `policies/conftest/kubernetes.rego` (deny rules on rendered objects) | conftest 532 tests | S1 | Fable lane |
| PLAT-SUP-004 | Third-party Actions pinned to full SHAs; tools installed checksum-verified | `scripts/validate_repository.py` `check_workflows` (full-SHA pin law) + `scripts/ci/install-tools.sh` pinned hashes | CI PASS | S1 | Fable lane |
| PLAT-SUP-005 | The retired live gate's evidence validators stay executable and tested for the successor | `tests/security/test_release_gate_contract.py` (25 executed tests over `validate_flux_release_evidence.py` / `validate_runtime_inventory_evidence.py`) | unittest PASS | S2 | Fable lane |

## Exposure and isolation

| ID | Invariant | Checker | Evidence | Sev | Remediation |
| --- | --- | --- | --- | --- | --- |
| PLAT-EXP-001 | No public inbound path: no NodePort/LoadBalancer/hostNetwork/Ingress/Gateway/externalIPs | kyverno `disallow-public-services` (+ deny fixtures), conftest service rules | CI PASS | S1 | Fable lane |
| PLAT-EXP-002 | Tenant namespaces: default-deny with exactly the nine closed NetworkPolicy identities | conftest rendered-object rules; kyverno `require-exact-tenant-networking` (endport-widening deny fixture) | CI PASS | S1 | Fable lane |
| PLAT-EXP-003 | Workloads restricted: non-root, no privilege escalation, dropped capabilities, no host namespaces/paths, exact ServiceAccounts | kyverno `require-restricted-workloads` + `disallow-undiscovered-storage` allow/deny suites | CI PASS | S1 | Fable lane |
| PLAT-EXP-004 | No storage activation before discovery: no PV/PVC/StorageClass/CSI/hostPath/disk-pressure tolerations | kyverno `disallow-undiscovered-storage`, release-gate `assert_storage_disabled` (platform roots), `validate_repository.py` media checks | CI PASS | S1 | Fable lane |

## Secrets and privacy

| ID | Invariant | Checker | Evidence | Sev | Remediation |
| --- | --- | --- | --- | --- | --- |
| PLAT-SEC-001 | No plaintext secret anywhere in tree or history; committed Secrets are SOPS ciphertext bound to the exact age recipient | pinned gitleaks (tree + full history via pre-push), `validate_sops_ciphertext_snapshot.py`, structural-example byte pin in `validate_publication_history.py` | gate PASS | S1 | Fable lane |
| PLAT-SEC-002 | Commit metadata carries no real email (only `.invalid` / `users.noreply`) | `validate_publication_history.py` metadata law (pre-push, full outgoing range) | gate PASS | S1 | Fable lane |
| PLAT-SEC-003 | No private host identity (IP, path, username, unit, route, inventory) in any tracked file | `validate_repository.py privacy` + file-level email/identifier validators | CI PASS | S1 | Fable lane |
| PLAT-SEC-004 | Heavy media never enters Git/OCI/ConfigMaps/etcd | `validate_repository.py` media contract + kyverno `disallow-tenant-media-payloads` (binary/encoded deny fixtures) | CI PASS | S2 | Fable lane |

## Fail-closed release state

| ID | Invariant | Checker | Evidence | Sev | Remediation |
| --- | --- | --- | --- | --- | --- |
| PLAT-REL-001 | Checked-in desired state stays inert: suspended Kustomizations/HelmReleases, Audit-staged policies, zero-capacity quotas | `render-manifests.sh --scaffold` negative controls (`expect_release_rejection` set) + `release-policy` conftest | CI PASS | S1 | Fable lane |
| PLAT-REL-002 | Release promotion is a closed ceremony: three-way version lock, no skip flags, no manual dispatch, no tag reuse | site repos' publisher CI (their tests); platform side `validate_release_transition.py` classify/plan + `promote-image.sh` bound evidence | CI PASS both sides | S1 | Fable lane |
| PLAT-REL-003 | Runtime lanes fail closed PENDING the successor; no silent bypass may resurrect them | `test_release_gate_contract.py` pins both PENDING dies, forbids retired machinery names, requires validators to refuse short argv | unittest PASS | S1 | Fable lane |
| PLAT-REL-004 | No boolean/env/config may disable a security behavior (Coinkite law) | enforced by review + tests that make dangerous states unrepresentable; sweep is a Phase C deliverable (GAP: no single automated toggle-detector yet) | partial | S1 | Fable lane (Phase C) |

## Host and platform (Codex-owned surface, checker-only view)

| ID | Invariant | Checker | Evidence | Sev | Remediation |
| --- | --- | --- | --- | --- | --- |
| PLAT-HOST-001 | Bootstrap inputs are validated fail-closed before any user-run procedure | `validate_host_prerequisites_plan.py`, `validate_kubeadm_config.py`, `validate_encryption_config.py`, `validate_pi_network.py`, `validate_cni_manifest.py` + their test files | unittest PASS | S1 | Codex lane |
| PLAT-HOST-002 | Protected legacy services stay untouched, inactive, operator-only | `validate_protected_host_contract.py` / `validate_protected_runtime_evidence.py` (indexed diagnostics only) | unittest PASS | S1 | Codex lane |
| PLAT-HOST-003 | Live mutations happen only inside Codex's immutable staged payload with manifest hashes | Codex's 829-test lane (their branch); this repo consumes only the sanitized hashes | Codex evidence | S1 | Codex lane |

## Identified gaps (Phase A findings)

- PLAT-GAP-001 (S2): no automated detector proves "no security toggle"
  repository-wide (PLAT-REL-004 relies on review); Phase C must add a
  negative-fixture sweep for flag-gated control paths.
- PLAT-GAP-002 (S2): ledger CI validation (schema/order/forbidden patterns)
  does not exist yet; lands with `fable/platform-security-ci`.
- PLAT-GAP-003 (S3): PLAT-COST-003 has no executable probe by design
  (credential-free CI); owner billing audit is the accepted control.
- PLAT-GAP-004 (S2): performance posture (owner third-order directive) has
  no measured baseline; Phase D must define zero-cost, security-neutral
  measurement (e.g., synthetic checks from CI against the public edge only
  after launch) and the free-plan feature plan.
