# Signed artifact verification — Flux `spec.verify` and Conftest

This repository does not claim image-signature admission: no webhook evaluates
these rules in the cluster. The live artifact boundary is the signed site chart
selected by an exact OCI manifest digest and verified by Flux
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

The credential-free acquisition, the repeated resolution, and the atomic
annotation/digest update are the "Required rollback receipt" and "Reviewed Git
change" sections of [image-rollback.md](image-rollback.md); a forward change
follows the same ceremony against the intended newer digest, and both fail
closed when the bytes or their expected signature are unavailable. Then run:

```sh
python3 -B -m unittest \
  tests.security.test_signature_policy_contract \
  tests.security.test_signature_policy_cli
python3 -B scripts/validate_repository.py kubernetes
```

A material trust-boundary expansion, including another independent tenant or
untrusted/third-party workload, triggers reconsideration of runtime
admission. That trigger requires a new threat model and ADR; it does not
authorize weakening the current Flux/Conftest controls.
