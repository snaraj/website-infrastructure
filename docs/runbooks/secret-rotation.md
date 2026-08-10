# SOPS/age and workload-secret rotation — Draft / unverified

Current status is `NO-GO`. The installer and both secret-aware verifiers are
code-blocked before protected-file access until a separately installed
reviewed-blob launcher establishes stage-zero trust. The commands below are a
future acceptance contract, not executable operator instructions; do not
generate production identities or bypass the guards in the meantime.

## Routine age rotation

Use the protected Linux AMD64 ceremony in `bootstrap/flux/README.md`. The
repository and each ciphertext have
exactly one public recipient throughout rotation. Only the private
`flux-system/sops-age` file temporarily contains two identities:

1. Generate a new hybrid post-quantum cluster identity, capture only its public
   recipient, create two operator-wrapped recovery copies, and restore-test both
   with disposable ciphertext. Keep the old identity protected and available.
2. Capture the current Secret `resourceVersion`, identity count, recipient-set
   digest, and SHA-256 of the decoded `age.agekey` bytes into protected ceremony
   evidence through the exact flattened JSON kubeconfig; never print the bytes.
   Stage the checksum-
   pinned kubectl and age-keygen binaries, kubeconfig, and both identities as
   single-link owner-only files in the protected Linux root. The Windows gate's
   local attestation hash is not portable authorization for this process. Use
   the installer’s compare-and-swap replacement with the exact reviewed
   context, API server, node, CA digest, `kube-system` namespace-UID digest,
   encrypted-filesystem UUID digest, and `main` commit already exported inside
   the private `env -i` shell. Set
   `EXPECTED_PREDECESSOR_IDENTITY_COUNT`,
   `EXPECTED_PREDECESSOR_RECIPIENT_SET_SHA256`, and
   `EXPECTED_PREDECESSOR_SOPS_AGE_SECRET_SHA256` from that separate evidence:

   ```bash
   CONFIRM_SOPS_AGE_INSTALL="replace-flux-system-sops-age-$RESOURCE_VERSION" \
     bootstrap/flux/install-sops-age-secret.sh replace "$RESOURCE_VERSION" \
     "$OLD_IDENTITY_FILE" "$OLD_PUBLIC_RECIPIENT" \
     "$NEW_IDENTITY_FILE" "$NEW_PUBLIC_RECIPIENT"
   ```

   The resourceVersion and predecessor digests make a concurrent or unexpected
   Secret change fail rather than get overwritten. The private snapshots of the digest-pinned `age-keygen` and
   kubectl binaries are rechecked before mutation. `age-keygen -y` derives and
   compares both recipients, and the installer compares the API server's
   mutation response plus a fresh live Secret with the intended combined
   identity, UID, resourceVersion, annotations, and security metadata before reporting
   success. Confirm current Flux reconciliation remains healthy; do not print
   or manually decode the installed key afterward.
3. In one reviewed Git change, replace `.sops.yaml` with the new public recipient
   and run `sops updatekeys` for every tracked SOPS document. Each document must
   contain exactly the new recipient, never an old+new public-recipient set.
   Structural validation is not a decrypt test. After the exact ciphertext is
   merged to protected `main`, the future procedure runs
   `verify-sops-ciphertext.sh`; it requires the
   protected public inputs to equal their committed blobs, authenticates the
   SOPS MAC, and validates the decrypted token's reviewed account/Tunnel identity
   entirely in protected scratch. Record only PASS and the ciphertext hash.
4. Merge and prove Flux reconciles the new revision. While both private identities
   remain installed, prove the reviewed previous revision is still decryptable
   for rollback. Do not perform another deployment during this bounded window.
5. After the rollback window, capture the then-current resourceVersion and use
   the same installer in `replace` mode with only the new identity/recipient.
   Require `verify-sops-age-secret.sh 1 "$NEW_PUBLIC_RECIPIENT"` with the new
   protected identity plus the same kubeconfig/kubectl/age-keygen snapshots,
   and re-verify reconciliation
   plus missing-key failure/recovery.
   Prove the old public recipient is absent from the current tree, then retire the
   old private identity according to its backup policy.

Two public recipients are rejected rather than treated as an indefinite
compatibility mode.

## Compromise

Re-encryption is insufficient because repository history remains decryptable by
the stolen key. Rotate every underlying credential whose historical ciphertext
could be decrypted, revoke the old credentials, create a new age identity, and
review access logs. Keep stable Secret names/keys so workloads do not bind to the
producer. Rotate one workload at a time and preserve a tested rollback producer
only while the old credential is known uncompromised.

Compromise of the operator-wrapping identity has a different blast radius:
replace it, re-encrypt every retained archive to the new operator recipient, and
rotate/revoke every still-valid bearer credential found in those archives.
OpenTofu state and private inventory cannot be revoked; treat their disclosure
as permanent and reassess all correlated controls.
