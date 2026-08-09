# Flux recovery — Draft / unverified

1. Keep public routing disabled. Confirm the Kubernetes API, stacked etcd,
   CoreDNS, node readiness, Secret encryption, audit, and namespaces before
   touching Flux.
2. Compare installed controller images to the reviewed generated manifest and
   immutable digests. Apply only `gotk-components.yaml` with the recovery
   kubeconfig if controllers are absent/corrupt.
3. Wait for source, kustomize, and helm controllers. Confirm cross-namespace
   references and remote bases remain disabled.
4. Confirm the out-of-band `sops-age` Secret exists without reading it. Restore
   it only from a user-controlled tested backup using `--from-file`.
5. Apply `gotk-sync.yaml`. Prove the GitRepository has no `secretRef`, fetches
   public `main`, and tenant Kustomizations use explicit ServiceAccounts.
6. Inspect Flux events/status. Prefer a Git revert for bad desired state; do not
   patch Flux-owned resources as ordinary recovery.
7. Before re-enabling a suspended release, render/policy-check the exact revision
   and verify signatures/digests.

Removing the age Secret is a planned negative test only after backups: reconcile
must fail closed, and restoring the same Secret must recover. Never print Secret
YAML or create Git credentials to make recovery easier.
