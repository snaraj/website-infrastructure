# Image-signature admission contract

The two website `ClusterPolicy` objects have one closed verification shape. An
active release must not rely on the presence of reassuring YAML strings: both
the source policy and the post-Kustomize object are compared with the complete
approved contract.

The contract requires, independently for the image signature and SLSA
provenance:

- the exact `ghcr.io/snaraj/<site>@sha256:*` repository/digest reference;
- `required: true`, `verifyDigest: true`, and `mutateDigest: false`;
- one keyless attestor with count one, the site's exact protected-main workflow
  subject, GitHub Actions OIDC issuer, and the public Rekor URL;
- a `SigstoreBundle` attestation with predicate type
  `https://slsa.dev/provenance/v1`;
- one `Equals` condition binding `buildDefinition.buildType` to the GitHub
  Actions workflow build type.

The checked-in pre-production policy may use `Audit`; a production release
requires the otherwise identical `Enforce` variant. Neither action permits a
different rule, wildcard repository prefix, regular-expression identity,
transparency-log bypass, skip list, extra attestor, or alternate condition.
Kyverno documents why `required` and `verifyDigest` are admission checks and
distinguishes signature attestors from attestation attestors in its
[Verify Images overview](https://kyverno.io/docs/policy-types/cluster-policy/verify-images/overview/).
Its [Sigstore guide](https://kyverno.io/docs/policy-types/cluster-policy/verify-images/sigstore/)
documents the GitHub workflow keyless identity, Rekor, Sigstore bundle, and SLSA
condition structure used here.

The entire reconciliation chain is part of the contract: the Flux bootstrap
index, `gotk-sync.yaml` source/root reconciler, reconciliation index, admission
parent, and policy index all have exact inventories. `namePrefix`, `nameSuffix`,
patches, replacements, image rewrites, post-build substitutions, components,
and generators are rejected. Otherwise a locally valid policy or its Flux
parent could be renamed, removed, or weakened after its source-level check but
before reconciliation.

## Safe change procedure

1. Treat the site slug, GHCR repository, workflow filename, workflow identity,
   namespace, and policy name as one identity tuple. A rename changes all of
   them in one reviewed patch.
2. Update the pinned template in `scripts/validate_signature_policy.py`, both
   source policies, and the exact rendered-object model in
   `policies/conftest/signature-policy.rego`. Never weaken only one layer to
   make a render pass.
3. Add an allow control and a deny control for the proposed semantic change.
   Extend `tests/security/test_signature_policy_contract.py` with a mutation
   proving the former contract cannot be bypassed through comments, duplicate
   keys, alternate nesting, or extra fields.
4. Run:

   ```sh
   python3 -B -m unittest tests.security.test_signature_policy_contract
   python3 -B scripts/validate_repository.py all
   scripts/render-manifests.sh --scaffold
   ```

5. Before changing `Audit` to `Enforce`, verify the exact published digest with
   the expected keyless signature and provenance, complete an actual-cluster
   deny/recovery soak, and use the reviewed release-transition procedure. Do
   not edit the action as an isolated live hotfix.
