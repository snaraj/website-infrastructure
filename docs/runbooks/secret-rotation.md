# Workload-secret rotation — Draft / unverified

Current status is `NO-GO`. Every live path named here is code-blocked before
protected-file access until a separately installed reviewed-blob launcher
establishes stage-zero trust. The steps below are a future acceptance contract,
not executable operator instructions.

This repository carries no secrets (AGENTS.md safety invariant 7). There is no
in-Git ciphertext to re-encrypt and no repository key to rotate: every runtime
Secret is created on the cluster by an owner ceremony, so rotation is a
provider-side credential change followed by a re-run of that ceremony. The
public Tunnel token has its own procedure in
[`tunnel-token-rotation.md`](./tunnel-token-rotation.md).

## Routine rotation

1. Issue the new credential at its provider and capture it directly into a
   mode-0600 file inside the protected root, without printing it.
2. Re-run the cluster-side ceremony for that Secret through the exact flattened
   JSON kubeconfig and pinned kubectl, keeping the Secret name and keys stable
   so no workload binds to the producer. Capture the resourceVersion before and
   after; never print the bytes.
3. Confirm reconciliation stays healthy and the workload picked up the new
   revision, then revoke the old credential at the provider.
4. Rotate one workload at a time, and preserve a tested rollback producer only
   while the old credential is known uncompromised.

## Compromise

Rotate every credential the compromised principal could reach, revoke the old
ones, and review access logs. Compromise of the operator-wrapping identity has a
different blast radius: replace it, re-encrypt every retained archive to the new
operator recipient, and rotate/revoke every still-valid bearer credential found
in those archives. OpenTofu state and private inventory cannot be revoked; treat
their disclosure as permanent and reassess all correlated controls.
