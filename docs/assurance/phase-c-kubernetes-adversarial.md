# Phase C — Kubernetes adversarial validation (static-first)

Maps the handoff's seven adversarial areas to their positive AND negative
executable tests, with the proof level labeled honestly: **static** (parses
or renders the artifact), **policy** (admission/policy engine evaluates
rendered or fixture objects), **behavioral** (a real control plane proves
the runtime effect — Phase G only, owner-authorized). A parser-only check
is never presented as a behavioral proof. New in this phase: the
no-security-toggle detector (closes PLAT-GAP-001).

## 1. Kubeadm and host contract — proof level: static

Positive: `validate_kubeadm_config.py` accepts only the canonical config
(version pins, cgroup driver, sysctls/modules, encryption-provider order,
SAN set, audit-policy wiring, anonymous-auth off, authorization modes);
`validate_encryption_config.py` + `generate_encryption_config.py` (CSPRNG,
0600, no-display); `validate_host_prerequisites_plan.py`;
`validate_pi_network.py`; `validate_cni_manifest.py`.
Negative: 45+ rejection tests across their five suites (wrong skew, swap,
weak provider order, guessed inputs, SAN drift, token retention).
Bootstrap-token hygiene: `--skip-token-print` pinned by two suites and
allowlisted in the toggle detector as security-positive.
Residual → G: none statically reachable; live init evidence is Codex-lane.

## 2. API server and admission — proof level: static + policy

Positive: encryption-at-rest config validated; admission chain rendered and
schema-checked; Kyverno policies render from the canonical template
(`policies/kyverno`, regenerated never hand-edited).
Negative: conftest deny rules on rendered admission objects; kyverno test
deny matrix; `expect_release_rejection` proves the release policy REJECTS
the inert scaffold (admission not enforced yet is itself asserted).
Residual → G: webhook failure-policy behavior, audit-log emission, PSA
runtime decisions need a live control plane (fixed read-only canaries).

## 3. Workload confinement — proof level: policy

Positive: `fixtures/allow/hardened.yaml` + `lidersea-hardened.yaml` pass
`require-restricted-workloads` (non-root, dropped caps, seccomp, RO root,
resources, exact ServiceAccounts) and `require-approved-images` (digest
pins, canonical repos).
Negative: `fixtures/deny/insecure.yaml`, `token-bypass.yaml`, and the
`objective2-bypasses.yaml` matrix (host ports, capability re-add, digest
drift, cross-site image, SA token mounts) — 52 kyverno cases total.
Residual → G: kernel-level enforcement (seccomp actually applied) is
behavioral by nature.

## 4. Network isolation — proof level: policy

Positive: nine closed tenant NetworkPolicy identities in rendered state;
`require-exact-tenant-networking` passes the exact ingress/no-egress shape.
Negative: widened-ingress, endport-widening, namespace-selector and label
substitution denials; `disallow-public-services` denies Service/Ingress/
Gateway exposure paths.
Residual → G: default-deny/allow/restore packet-level canaries (both
directions) and coexistence with the operator's private admin plane are
behavioral; specified in the handoff's Phase G list.

## 5. Flux and artifact trust — proof level: static + policy

Positive: conftest `approved_git_source_urls`/`approved_git_source_scopes`
pin per-source URLs, chart-rooted sparse checkout, exact ignore rules;
signature policies pin the two tag-form publisher identities; suspended
sentinels assert inertness; the extracted evidence validators
(`validate_flux_release_evidence.py`, `validate_runtime_inventory_evidence.py`)
are executed by 25 unit tests over synthetic captured state — the successor
live gate's logic is proven today at policy level.
Negative: cross-site source-name substitution, wrong-identity signature
fixtures, canonical-URL denials, unsigned-artifact rejection paths.
Residual → G: real Rekor/registry round-trips (Phase B residual: scheduled
Rekor spot checks).

## 6. Single-node resilience — proof level: deferred by honesty

Static coverage exists only for configuration (quotas, eviction-relevant
requests/limits, zero-capacity staging quota denials). Pressure, eviction,
restart, reboot, certificate-expiry, and GC behavior cannot be proven from
fixtures; MISLABELING RISK is the finding here, not a missing YAML test.
Disposition: Phase E builds the fake-host drills; Phase G runs the fixed
read-only live canaries. Recorded as PLAT-K8S-001 (S2, accepted interim).

## 7. Tenant/workload contract — proof level: static

Positive: the sanitized onboarding bundles validate against the generic
`platform.snaraj.dev/v1alpha1` workload shape (digest, port, probes,
route hostname, resources, replicas, storage profile, rollback digest) —
zero PENDING fields since v0.1.6.
Negative: bundle-contract validation rejects missing/malformed fields
(integrator-side validator); platform-side, kyverno denies any workload
outside the closed identity set.
Residual: none new; contract evolution is a two-lane change by design.

## New executable control: the no-security-toggle detector

`scripts/validate_no_security_toggles.py` (closes **PLAT-GAP-001**, the
Coinkite law as a machine check): sweeps every tracked file for
skip/disable/bypass identifiers aimed at verification, signing, policy,
scanning, gates, or admission, plus no-verify/insecure/skip CLI flags and
`verification disabled` idioms. Occurrences are legal only through an
exact-match allowlist where every entry carries its justification and a
stale entry is itself an error; the detector and its test are whole-file
exempt behind tamper-checked identity markers. Five-test contract suite
proves detection of nine hostile idiom classes, benign-line silence, stale
-allowlist failure, and marker tampering. Wired into the terminal gate and
`validate-security.sh`.

## Phase C findings register

| ID | Severity | Finding | Disposition |
| --- | --- | --- | --- |
| PLAT-K8S-001 | S2 | Single-node resilience has configuration-only proof; runtime behavior unproven until E/G | accepted interim; Phase E drills next |
| PLAT-GAP-001 | S2 | (from Phase A) no automated toggle detector | **CLOSED this phase** |
