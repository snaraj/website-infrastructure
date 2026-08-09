# SOPS/age and workload-secret rotation — Draft / unverified

## Routine age rotation

1. Generate a new identity on the trusted workstation, capture only its public
   recipient, create two encrypted recovery copies, and test both with disposable
   ciphertext. Keep the old identity available but protected.
2. Add both public recipients temporarily and re-encrypt every SOPS document.
   Prove `data`/`stringData` are ciphertext and both identities decrypt a
   disposable copy; scan the diff/history for plaintext.
3. Install the new identity out of band from a protected file. Verify Flux can
   decrypt/reconcile, then remove the old identity from the cluster.
4. Remove the old public recipient and re-encrypt again. Verify and retire the
   old private identity according to its backup policy.

## Compromise

Re-encryption is insufficient because repository history remains decryptable by
the stolen key. Rotate every underlying credential whose historical ciphertext
could be decrypted, revoke the old credentials, create a new age identity, and
review access logs. Keep stable Secret names/keys so workloads do not bind to the
producer. Rotate one workload at a time and preserve a tested rollback producer
only while the old credential is known uncompromised.
