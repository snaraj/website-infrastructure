# Scripts: prove it before we touch it

[`validate_frontend_dist.py`](./validate_frontend_dist.py) checks each generated Vite tree without a browser or network, rejecting remote or missing resources, source and source-map output, unhashed immutable assets, symlinks, and explicit byte-budget overruns before Go embeds it.
[`ci/publish-oci-artifact.sh`](./ci/publish-oci-artifact.sh) publishes the exact scanned multi-platform graph with serial, bounded content-addressed retries, then downloads the complete remote graph into a fresh OCI layout so a short GHCR child-manifest visibility delay cannot make an otherwise proven release flaky or change its digest.
[`ci/publish-stable-oci-tag.sh`](./ci/publish-stable-oci-tag.sh) creates the human SemVer name only after signature and provenance verification; it resolves the destination immediately before the write, treats only explicit registry unknown-manifest/name responses as absence, and refuses every mismatch or indeterminate lookup.
[`ci/verify-existing-oci-release.sh`](./ci/verify-existing-oci-release.sh) is the read-only manual lane: it requires the full-SHA and stable tags to agree and verifies the existing keyless identity without publishing, tagging, signing, or attesting. [`validate_signature_policy.py`](./validate_signature_policy.py) enforces the closed source/render contract for both site-specific Kyverno signature policies so expected trust strings cannot be hidden in comments or inert fields.
This folder is where we make “prove it first” real: none of these files is permission to touch the Pi, Cloudflare, GitHub, or production, and an unknown answer is always a stop. [`ci/install-tools.sh`](./ci/install-tools.sh) gives CI the exact checksum-pinned validators instead of trusting runner defaults, while [`ci/verify-oci-artifact.sh`](./ci/verify-oci-artifact.sh) proves each site’s final amd64/arm64 OCI graph, distinct bounded application layers, vulnerability scan, and per-platform SBOM before publication. [`cloudflare-audit.sh`](./cloudflare-audit.sh) reads the live account, both named Free zones, subscriptions, Tunnel, DNS, Gateway, Access, and seat state without printing IDs; [`cloudflare-plan-gate.sh`](./cloudflare-plan-gate.sh) binds a protected OpenTofu plan to that audit fingerprint and the exact eight-resource allowlist; [`mutate_cloudflare_fixture.py`](./mutate_cloudflare_fixture.py) creates precise bad plans; and [`test-cloudflare-policy.sh`](./test-cloudflare-policy.sh) proves every one is denied. [`discover-pi.sh`](./discover-pi.sh) collects the first read-only host picture, [`fingerprint_pi_state.sh`](./fingerprint_pi_state.sh) hashes the network/firewall baseline without publishing it, and [`redact_inventory.py`](./redact_inventory.py) strips common identifiers from deliberately limited discovery output. [`validate_host_prerequisites_plan.py`](./validate_host_prerequisites_plan.py), [`validate_kubeadm_config.py`](./validate_kubeadm_config.py), [`validate_encryption_config.py`](./validate_encryption_config.py), [`validate_pi_network.py`](./validate_pi_network.py), and [`validate_cni_manifest.py`](./validate_cni_manifest.py) each reject one dangerous class of guessed host, cluster, secret-at-rest, routing, or CNI input before a user-run bootstrap can consume it. [`preflight-tools.sh`](./preflight-tools.sh) reports which pinned local tools are present without installing anything; [`render-manifests.sh`](./render-manifests.sh) is the canonical offline Helm/Kustomize/schema/Conftest/Kyverno renderer; [`render-kubernetes.sh`](./render-kubernetes.sh) keeps the familiar wrapper name; [`test-policy-fixtures.sh`](./test-policy-fixtures.sh) requires safe fixtures to pass and unsafe ones to fail; and [`test-kind.sh`](./test-kind.sh) optionally exercises those contracts against a disposable, owned local Kind cluster without pretending it is the Pi. [`validate_repository.py`](./validate_repository.py) joins the cross-file layout, privacy, media, secret, workflow, Kubernetes, Cloudflare, activation, and release invariants; [`validate-security.sh`](./validate-security.sh) is the short credential-free security entry point; [`release-gate.sh`](./release-gate.sh) separates inert scaffold proof, promoted static proof, and explicitly acknowledged live evidence; and [`verify-exposure.sh`](./verify-exposure.sh) checks both public domains, security headers, DNS privacy, and closed residential-origin ports after deployment. The small Python helpers are here because strict structured validation and streaming redaction need to work with the standard library on a workstation, CI runner, or fresh Ubuntu host; Python is never part of either production website, container, or cluster runtime.
`release-gate.sh --live` server-normalizes and exact-matches every authoritative
Flux spec, rejects alternate source kinds, and closes the global Namespace,
controller, controller-UID/Pod, Service, policy, and admission inventories both
before and after public probes.
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
[`promote-image.sh`](./promote-image.sh)
binds the selected human version tag to the signed digest and emits that patch
plus hash-bound evidence without changing the worktree. The candidate prepares
either an authoritative digest/readiness override or a suspended digest-only
rollback to a strictly older retained version without removing either
reconciliation suspension. The renderer's `--transition` mode provides
credential-free static proof of those exact effective values, and the explicit
single-site Kind transition-runtime gate supplies isolated pre-resume behavior
evidence without touching Flux, the tunnel, or production. It sandwiches Kind
between complete static transition gates so a checkout change during runtime
cannot inherit stale proof. The live release gate similarly binds the clean
local commit through Flux Git sources, Kustomization revisions, HelmChart and
HelmRelease status, and exact server-normalized Kyverno and tenant network
policy specs before GO.

```mermaid
flowchart LR
    D["Read-only discovery"] --> V["Fail-closed validators"]
    C["Go, Svelte, Helm, IaC"] --> R["Render and negative tests"]
    V --> R --> O["OCI and release evidence"]
    O --> P["Reviewed digest promotion"] --> G["Flux reconciliation"]
    G --> L["Explicit live acceptance"]
```
