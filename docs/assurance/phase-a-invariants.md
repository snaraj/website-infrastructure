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
| PLAT-SUP-001 | Workloads deploy by immutable digest only; version tags never move | `scripts/validate_image_release.py` (SemVer + graduation gates), `policies/conftest/kubernetes.rego` digest rules, kyverno `require-approved-images` | CI PASS + 44 kyverno tests | S1 | Fable lane |
| PLAT-SUP-002 | Only the two site protected-`main` publisher identities are trusted (`…/release-publisher.yml@refs/heads/main`); re-pointed from the tag form 2026-08-22 because a run at a ref executes the definition at that ref and only `main` is gated on creation with no bypass actors (ADR 0016 amendment) | `scripts/validate_signature_policy.py` (closed contract), `policies/conftest/signature-policy.rego`, `scripts/ci/verify-existing-oci-release.sh` trust boundary, kyverno `require-signed-*` (CI assertion and future desired state only — Kyverno is not installed and not authorized to be, so it is not a live runtime control) | CI PASS + allow/deny fixtures | S1 | Fable lane |
| PLAT-SUP-003 | Flux pulls anonymously; site sources pin their standalone repos with chart-rooted sparse checkout; platform sources pin this repo | `approved_git_source_urls`/`approved_git_source_scopes` in `policies/conftest/kubernetes.rego` (deny rules on rendered objects) | conftest deny/warn rule sweep over every rendered object (76 rules) | S1 | Fable lane |
| PLAT-SUP-004 | Third-party Actions pinned to full SHAs; tools installed checksum-verified | `scripts/validate_repository.py` `check_workflows` (full-SHA pin law) + `scripts/ci/install-tools.sh` pinned hashes | CI PASS | S1 | Fable lane |
| PLAT-SUP-005 | The retired live gate's evidence validators stay executable and tested for the successor | `tests/security/test_release_gate_contract.py` (27 executed tests over `validate_flux_release_evidence.py` / `validate_runtime_inventory_evidence.py`) | unittest PASS | S2 | Fable lane |

## Exposure and isolation

| ID | Invariant | Checker | Evidence | Sev | Remediation |
| --- | --- | --- | --- | --- | --- |
| PLAT-EXP-001 | No public inbound path: no NodePort/LoadBalancer/hostNetwork/Ingress/Gateway/externalIPs | kyverno `disallow-public-services` (+ deny fixtures), conftest service rules | CI PASS | S1 | Fable lane |
| PLAT-EXP-002 | Tenant namespaces: default-deny with exactly the nine closed NetworkPolicy identities | conftest rendered-object rules; kyverno `require-exact-tenant-networking` (endport-widening deny fixture) | CI PASS | S1 | Fable lane |
| PLAT-EXP-003 | Workloads restricted: non-root, no privilege escalation, dropped capabilities, no host namespaces/paths, exact ServiceAccounts | kyverno `require-restricted-workloads` + `disallow-undiscovered-storage` allow/deny suites | CI PASS | S1 | Fable lane |
| PLAT-EXP-004 | Storage is allowed; externally reachable storage is not, except by the owner's enumerated means (owner directive 2026-08-12 retires the earlier permanent deny-by-kind). Admission enumerates the classes, provisioners, CSI drivers, and local roots that may exist; every unrecognized volume source, driver, provisioner, path, or structurally unusable object is denied. The repository INVENTORY gate is unchanged and still refuses committed storage manifests | kyverno `disallow-undiscovered-storage` rule `disallow-persistent-storage-resources` + its Conftest mirror (1 allow / 36 deny fixtures, counted by tests/security/test_storage_exposure_policy_contract.py), `tests/security/test_storage_exposure_policy_contract.py` (match-coverage + enumeration lockstep), release-gate `assert_storage_disabled` (platform roots), `validate_repository.py` media checks | CI PASS | S1 | Fable lane |
| PLAT-EXP-005 | WireGuard admin plane is the ONLY inbound-from-internet listener and is cryptographically gated (PSK per peer, scoped AllowedIPs, silent to non-handshake packets) | Pi-local config review + Phase H external-vantage scan (owner-scheduled); attack-surface manifest | design + live | S1 | Fable lane |
| PLAT-EXP-006 | Compromised pods cannot reach the control plane (API/etcd/kubelet) | conftest/kyverno network rules + Phase H live canary; attack-surface manifest `reachability` | policy + live | S1 | Fable lane |
| PLAT-EXP-007 | Admin plane is host-SSH-only, isolated from workloads and from the cluster API (PLAT-DEC-001) | Pi-local design + Phase H live canary; attack-surface manifest | design + live | S1 | Fable lane |
| PLAT-EGR-001 | Proton egress leaks nothing: no DNS/IPv6 leak, kill-switch fails closed, only designed exemptions; the WG reply-path exemption is not a general bypass | Pi-local config review + Phase H live leak tests (owner-authorized) | design + live | S1 | Fable lane |

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
| PLAT-REL-001 | Checked-in activation stays inert: both Kyverno install stages remain `authorized=no`; `admission`, `platform-services`, both site Kustomizations, and both contained HelmReleases remain suspended. Each site instead carries the exact bounded `namespace-budget` guardrail (`pods=6`, `requests.cpu=150m`, `requests.memory=192Mi`, `limits.cpu=1200m`, `limits.memory=768Mi`) bound to evidence SHA-256 `955a59cbf5ba0bd36f5e62349ed070a2b1eba6fb3ef072951435010edcceaf34` | `scripts/validate_repository.py kubernetes activation` + `policies/release-conftest/deployment-readiness.rego` + `tests/security/test_kyverno_install_contract.py` | CI PASS | S1 | Fable lane |
| PLAT-REL-002 | Release promotion is a closed ceremony: three-way version lock, no skip flags, no tag reuse, and dispatch bound to an already-merged protected-`main` commit (corrected 2026-08-22 — the publishers are now manual-dispatch-only, and the closure is the `authorize` job's main-run record, not the absence of dispatch) | site repos' publisher CI (their tests); platform side `validate_release_transition.py` classify/plan + `promote-image.sh` bound evidence | CI PASS both sides | S1 | Fable lane |
| PLAT-REL-003 | Runtime lanes fail closed PENDING the successor; no silent bypass may resurrect them | `test_release_gate_contract.py` pins both PENDING dies, forbids retired machinery names, requires validators to refuse short argv | unittest PASS | S1 | Fable lane |
| PLAT-REL-004 | No boolean/env/config may disable a security behavior (Coinkite law) | `scripts/validate_no_security_toggles.py` sweeps every tracked file for toggle idioms outside a justified allowlist; runs in the terminal PR gate and `validate-security.sh` (Phase C closed the former gap) | CI PASS + hostile-fixture CLI battery | S1 | Fable lane |

## Host and platform (Codex-owned surface, checker-only view)

| ID | Invariant | Checker | Evidence | Sev | Remediation |
| --- | --- | --- | --- | --- | --- |
| PLAT-HOST-001 | Bootstrap inputs are validated fail-closed before any user-run procedure | `validate_host_prerequisites_plan.py`, `validate_kubeadm_config.py`, `validate_encryption_config.py`, `validate_pi_network.py`, `validate_cni_manifest.py` + their test files | unittest PASS | S1 | Codex lane |
| PLAT-HOST-002 | Protected legacy services stay untouched, inactive, operator-only | `validate_protected_host_contract.py` / `validate_protected_runtime_evidence.py` (indexed diagnostics only) | unittest PASS | S1 | Codex lane |
| PLAT-HOST-003 | Live mutations happen only inside Codex's immutable staged payload with manifest hashes | Codex's 829-test lane (their branch); this repo consumes only the sanitized hashes | Codex evidence | S1 | Codex lane |

## Identified gaps (Phase A findings)

- PLAT-GAP-001 (S2): CLOSED by Phase C — `scripts/validate_no_security_toggles.py`
  sweeps every tracked file for toggle idioms with a justified allowlist and a
  stale-allowlist failure mode; it runs in the terminal PR gate and in
  `scripts/validate-security.sh`, with a hostile-fixture CLI battery in
  `tests/security/test_no_security_toggles_cli.py`.
- PLAT-GAP-002 (S2): CLOSED — `scripts/validate_assurance_ledger.py` validates
  the evidence ledger (schema/order/forbidden patterns) in the terminal PR
  gate (`.github/workflows/pull-request.yml`) and `validate-security.sh`.
- PLAT-GAP-003 (S3): PLAT-COST-003 has no executable probe by design
  (credential-free CI); owner billing audit is the accepted control.
- PLAT-GAP-004 (S2): performance posture (owner third-order directive) has
  no measured baseline; Phase D must define zero-cost, security-neutral
  measurement (e.g., synthetic checks from CI against the public edge only
  after launch) and the free-plan feature plan.
