### Security

- Activate both website releases from exact signed chart digests and replace the floating aggregate Flux graph with one credentialless exact-tag source, two non-pruning site reconcilers, and a permanent immutable-release selector.
- Publish the deterministic platform and site identity as exactly two immutable Release assets: canonical `platform-release-identity.v1.json` bytes plus their detached Sigstore bundle.
- Retire the absent Kyverno controller, installer, policy tree, CLI pin, and parity-only CI surfaces while preserving Conftest hostile controls, exact-digest OCI verification, tenant isolation, default deny, least-privilege impersonation, and the fail-closed release transition.
- Create each site's exact namespace-wide default deny before its signed chart supplies the sole application traffic allowance; first activation expects exactly those two policy creations.
- Enroll the release-selector Go runtime in CodeQL, make bootstrap containment immune to repeated signals, and keep public-file custody checks stable under unrelated directory churn without weakening path-replacement or hardlink rejection.
- Remove the unused standalone `release-record` CLI entry point while retaining the internal release validator used by fail-closed state classification.
- Scan the selector's canonical remote digest as ARM64, build its binary with Go 1.27.0, and consume a verified immutable upstream Cosign commit image; expire exact package-bound exceptions for the remaining upstream-only findings on 2026-09-15.
- Permit one failed, still-untagged release fragment to be repaired in place while keeping every tagged fragment immutable, so publication recovery does not create artificial platform versions.
