# Signed artifact verification (Kyverno retired)

Kyverno is not installed and is no longer desired state. This repository does
not claim image-signature admission. The live artifact boundary is the signed
site chart selected by an exact OCI manifest digest and verified by Flux
`OCIRepository.spec.verify`.

For each site, one closed identity tuple binds:

- its own GHCR chart repository;
- one nonzero `sha256` OCI manifest digest;
- the exact release-publisher workflow in that site's repository;
- terminal `@refs/heads/main$`, protected main only;
- GitHub Actions' exact OIDC issuer; and
- the site's namespace and HelmRelease.

The signed chart is the sole workload-image authority. Platform values contain
exactly `deploymentReady: true`; they cannot override image repository, tag,
or digest. Conftest independently rejects mutable workload images, an
unapproved registry, a sibling-site image identity, cross-namespace chart
references, and noncanonical Flux source verification.

## Safe change procedure

1. Acquire the intended chart without credentials and bind its human release
   label to the exact OCI manifest digest.
2. Verify its one Helm layer, chart identity, protected-main certificate
   subject and issuer, embedded workload index image, and Linux ARM64 child.
3. Repeat resolution after inspection and require the same digest.
4. Update the acquisition receipt and the site's annotation/digest pair
   atomically. Never use a bare tag or SemVer selector.
5. Run:

   ```sh
   python3 -B -m unittest \
     tests.security.test_signature_policy_contract \
     tests.security.test_signature_policy_cli
   python3 -B scripts/validate_repository.py kubernetes
   ```

Rollback repeats the same acquisition and verification against the older exact
digest. If those bytes or their expected signature are unavailable, rollback
fails closed.

A material trust-boundary expansion, including another independent tenant or
untrusted/third-party workload, triggers reconsideration of runtime
admission. That trigger requires a new threat model and ADR; it does not
authorize reinstalling Kyverno or weakening the current Flux/Conftest controls.
