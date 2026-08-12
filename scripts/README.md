# Scripts: prove it before we touch it

Image and chart publication left this repository with the site sources: each standalone site repository owns its tag-triggered publisher, and this platform consumes only signed digests.
[`ci/verify-existing-oci-release.sh`](./ci/verify-existing-oci-release.sh) is the read-only manual lane: it requires the full-SHA and stable tags to agree and verifies the existing keyless identity without publishing, tagging, signing, or attesting. [`validate_signature_policy.py`](./validate_signature_policy.py) enforces the closed source/render contract for both site-specific Kyverno signature policies so expected trust strings cannot be hidden in comments or inert fields.
This folder is where we make “prove it first” real: none of these files is permission to touch the Pi, Cloudflare, GitHub, or production, and an unknown answer is always a stop. [`ci/install-tools.sh`](./ci/install-tools.sh) gives CI the exact checksum-pinned validators instead of trusting runner defaults. [`cloudflare-audit.sh`](./cloudflare-audit.sh) reads the live account, both named Free zones, subscriptions, Tunnel, DNS, Gateway, Access, and seat state without printing IDs; [`cloudflare-plan-gate.sh`](./cloudflare-plan-gate.sh) binds a protected OpenTofu plan to the audit fingerprint and the selected phase's exact address, type, count, and field contract; [`validate_cloudflare_token_receipt.py`](./validate_cloudflare_token_receipt.py) validates one bounded local JIT-token ceremony and its independently supplied hashes without reading a credential or contacting Cloudflare; [`validate_cloudflared_tunnel_token.py`](./validate_cloudflared_tunnel_token.py) validates an environment-only Connector token against independently supplied account and Tunnel hashes without printing the token; [`validate-cloudflare-iac.sh`](./validate-cloudflare-iac.sh) initializes and validates all seven isolated phase roots in disposable data directories without accepting a Cloudflare credential; [`mutate_cloudflare_fixture.py`](./mutate_cloudflare_fixture.py) creates precise bad plans; and [`test-cloudflare-policy.sh`](./test-cloudflare-policy.sh) proves every one is denied. [`validate_sops_ciphertext_snapshot.py`](./validate_sops_ciphertext_snapshot.py) binds a protected ciphertext snapshot to the exact age recipient and closed SOPS grammar before an offline MAC/decryption ceremony; [`validate_kubeconfig_snapshot.py`](./validate_kubeconfig_snapshot.py) admits only a single embedded-credential Kubernetes context with no plugin, proxy, token, external-path, or insecure escape hatch; [`validate-windows-credential-workspace.ps1`](./validate-windows-credential-workspace.ps1) is the user-run Windows preflight for that credential workspace, refusing to proceed unless the system volume is fully BitLocker-encrypted and the workspace root is a non-reparse directory owned by the current identity with protected ACLs, so protected snapshots are only handled on a disk-encrypted, access-controlled workstation. [`discover-pi.sh`](./discover-pi.sh) collects the first read-only host picture, [`fingerprint_pi_state.sh`](./fingerprint_pi_state.sh) hashes the network/firewall baseline without publishing it, and [`redact_inventory.py`](./redact_inventory.py) strips common identifiers from deliberately limited discovery output. [`validate_host_prerequisites_plan.py`](./validate_host_prerequisites_plan.py), [`validate_kubeadm_config.py`](./validate_kubeadm_config.py), [`validate_encryption_config.py`](./validate_encryption_config.py), [`validate_pi_network.py`](./validate_pi_network.py), and [`validate_cni_manifest.py`](./validate_cni_manifest.py) each reject one dangerous class of guessed host, cluster, secret-at-rest, routing, or CNI input before a user-run bootstrap can consume it. [`preflight-tools.sh`](./preflight-tools.sh) reports which pinned local tools are present without installing anything; [`render-manifests.sh`](./render-manifests.sh) is the canonical offline Helm/Kustomize/schema/Conftest/Kyverno renderer; [`render-kubernetes.sh`](./render-kubernetes.sh) keeps the familiar wrapper name; [`test-policy-fixtures.sh`](./test-policy-fixtures.sh) requires safe fixtures to pass and unsafe ones to fail; [`validate_repository.py`](./validate_repository.py) joins the cross-file layout, privacy, media, secret, workflow, Kubernetes, Cloudflare, activation, and release invariants; [`validate_publication_history.py`](./validate_publication_history.py) closes the outgoing commit/tree/blob and metadata history; [`pre-push-security.sh`](./pre-push-security.sh) binds those checks to one clean exact source commit and immutable outgoing range; [`validate-security.sh`](./validate-security.sh) is the short credential-free security entry point; [`release-gate.sh`](./release-gate.sh) separates inert scaffold proof from promoted static proof while its runtime lanes fail closed PENDING the post-cutover successor; [`validate_flux_release_evidence.py`](./validate_flux_release_evidence.py) and [`validate_runtime_inventory_evidence.py`](./validate_runtime_inventory_evidence.py) are that retired live lane's captured-evidence validators, kept executable and unit-tested for the successor gate; [`validate_assurance_ledger.py`](./validate_assurance_ledger.py) validates the platform-assurance evidence ledger fail-closed (canonical records, ordering, uniqueness, forbidden private patterns); [`ci/verify-pull-request-merge-base.sh`](./ci/verify-pull-request-merge-base.sh) proves a pull-request checkout is the exact two-parent join of the live base branch tip and the reviewed head, and prints that verified tip so the history and secret scans cannot scan a narrower range than the one that merges; [`ci/verify-render-determinism.sh`](./ci/verify-render-determinism.sh) proves two independent renders of the authoritative release-transition mode are byte-identical so hash-bound evidence stays reproducible in every release state; [`validate_no_security_toggles.py`](./validate_no_security_toggles.py) sweeps the whole tree for skip/disable/bypass security-toggle idioms outside a justified allowlist (the Coinkite law as a machine check); [`validate_attack_surface_manifest.py`](./validate_attack_surface_manifest.py) validates the Phase H offensive-validation attack-surface contract fail-closed (closed result vocabulary, full critical-surface coverage, no private values); and [`verify-exposure.sh`](./verify-exposure.sh) checks both public domains, security headers, DNS privacy, and closed residential-origin ports after deployment. [`edge-probe.sh`](./edge-probe.sh) is the credential-free acceptance probe for the same two public edges — redirect posture, TLS floor, 0-RTT, HSTS, DNSSEC, readiness, `www` absence, and site distinctness — measured twice per run and scored PASS/GAP/SKIP against the encoded target state; it proves the local TLS client can speak a legacy protocol against a loopback server before it will assert anything about the edge, so a client limitation can never be reported as a server verdict, and it is report-only until `--enforce`. [`cloudflare-account-audit.sh`](./cloudflare-account-audit.sh) is its owner-run authenticated counterpart: one read-only token in the environment, GET requests only, and the configuration facts no external probe can observe (plan and subscription, the six zone settings, DNSSEC, the two per-site Tunnels and their connectors, the absence of a private-network surface, and the DNS inventory), with account, zone, Tunnel and connector identifiers replaced by stable pseudonyms so two captures diff without publishing an identifier inventory. The small Python helpers are here because strict structured validation and streaming redaction need to work with the standard library on a workstation, CI runner, or fresh Ubuntu host; Python is never part of either production website, container, or cluster runtime.
[`validate_cloudflare_preapply_evidence.py`](./validate_cloudflare_preapply_evidence.py) validates the protected current-phase backend/state binding and reviewed manual pre-apply attestation without credentials or network access.
[`ci/coverage_gate.py`](./ci/coverage_gate.py) enforces the self-hosted coverage contract fail-closed — measured floor, bounded drift against the committed ledger, and byte-exact regeneration of the committed badge — so coverage claims never depend on an external upload service.
[`generate_encryption_config.py`](./generate_encryption_config.py) is the
no-display writer used by the protected Pi API-encryption ceremony. It accepts
no key through arguments or environment, uses the operating-system CSPRNG,
validates the complete rendered document, and creates its destination through
an exclusive mode-`0600` descriptor.
`release-gate.sh --live` fails closed PENDING its post-cutover successor. The
successor must capture live state and pass it through the two retained
evidence validators, which server-normalize and exact-match every
authoritative Flux spec and close the global runtime inventory.
`discover-pi.sh` is local-only when invoked with no argument; intentional DNS,
HTTPS, and TCP probes require explicit `--with-egress` after the privacy route
has been proven. [`validate_protected_host_contract.py`](./validate_protected_host_contract.py)
keeps exact active-service and inactive-archive identities in the ignored local
contract while emitting only indexed diagnostics, and
[`validate_protected_runtime_evidence.py`](./validate_protected_runtime_evidence.py)
validates the fresh presence-bound protected-host review attestation without
treating it as a complete live process or storage scan.
[`validate_image_release.py`](./validate_image_release.py) enforces each site's
stable SemVer, production gate, and pull-request version bump without registry
or Git write access; [`validate_release_state.py`](./validate_release_state.py)
extracts only the closed, canonical HelmRelease and parent-Kustomization state
used by CI, promotion, and release rendering, rejecting duplicate keys, YAML
decoys, mixed readiness/digest phases, and identity drift without a general
YAML dependency; [`validate_release_transition.py`](./validate_release_transition.py)
classifies exact scaffold, independently staged, rollback, and fully active
states while enforcing admission and platform-service dependencies;
[`create_release_patch.py`](./create_release_patch.py) creates one bounded,
exclusive review patch for a closed release path;
[`create_release_candidate.py`](./create_release_candidate.py) performs the
exact digest/readiness rewrite into a new no-follow file instead of editing any
path in place;
[`write_review_artifact.py`](./write_review_artifact.py) creates the associated
bounded evidence and effective-values files without following or replacing an
existing path; [`remove_review_transaction.py`](./remove_review_transaction.py)
removes only an exact failed transaction without traversing a symlink root;
[`validate_pr_flow.py`](./validate_pr_flow.py) holds the allow/deny
branch-name and push-refspec rules behind the gh-pr-flow skill — pure
policy with no Git execution, network, or credential logic;
[`promote-image.sh`](./promote-image.sh)
binds the selected human version tag to the signed digest and emits that patch
plus hash-bound evidence without changing the worktree. The candidate prepares
either an authoritative digest/readiness override or a suspended digest-only
rollback to a strictly older retained version without removing either
reconciliation suspension. The renderer's `--transition` mode provides
credential-free static proof of those exact effective values. The single-site
Kind transition-runtime stage retired with the embedded site sources; that
lane and the live gate both fail closed PENDING their post-cutover successor,
which must re-establish runtime evidence against the standalone site charts.
[`validate_admin_ingress_contract.py`](./validate_admin_ingress_contract.py)
holds the public schema for the ignored root-owned admin-ingress contract
(the reviewed administrative VPN ingress interfaces behind the SSH-only
decision PLAT-DEC-001), rejecting duplicates, whitespace ambiguity, symlinks,
hard links, non-root ownership, partial reads, and LAN/CNI interface classes
with fixed value-free tokens; and
[`validate_ingress_guard.py`](./validate_ingress_guard.py) is the semantic
verifier, deterministic renderer, and tracked-artifact gate for the SSH-only
host-ingress guard: it normalizes structured `nft -j` output against one
closed expected model (TCP 22 preserved; 2379/2380/6443/10250 terminally
denied per reviewed interface) and refuses sets, maps, inversions,
wildcards, alternate families, decoy chains, and unknown grammar, so the
guard's proof can never be widened or bypassed by rule indirection.

```mermaid
flowchart LR
    D["Read-only discovery"] --> V["Fail-closed validators"]
    C["Helm, policies, IaC"] --> R["Render and negative tests"]
    V --> R --> O["OCI and release evidence"]
    O --> P["Reviewed digest promotion"] --> G["Flux reconciliation"]
    G --> L["Explicit live acceptance"]
```

## Adding a validator

The invocation-parity suite (`tests/security/test_validator_invocation_parity.py`)
fails any `validate_*.py` that appears on one of its surfaces but not the
others — the drift class commit 3ad45c6 had to close by hand. A new
validator therefore lands as one reviewed change touching every surface:

1. the script itself under `scripts/`, with its battery in `tests/security/`
   (the compile sweep in the pull-request workflow enrolls every tracked
   `scripts/**/*.py` automatically — there is no compile list to forget);
2. `scripts/validate-security.sh`, the local credential-free entry point —
   or, when the validator cannot run there (event-scoped input, render-lane
   coupling), a justified entry in the parity suite's CI-only allowlist
   naming the tracked local surface that provides the equivalent run;
3. the inline invocations in `.github/workflows/pull-request.yml`;
4. the guide paragraph above — `tests/security/test_scripts_readme.py`
   requires exactly one link per script.

[`test-storage-engine-parity.sh`](./test-storage-engine-parity.sh) is the differential half of the storage gate: it feeds every storage fixture to BOTH engines that express that gate — Kyverno CEL at admission and its Conftest/Rego mirror in CI — and fails on any verdict disagreement, on any Kyverno `skip`, on an object the policy never evaluated, or on a denial the fixture's own rule did not produce, because two files agreeing in text is not two engines agreeing in behaviour; it proves its own comparison against a deliberately wrong expectation on every run, so a harness that compares nothing fails instead of passing.
