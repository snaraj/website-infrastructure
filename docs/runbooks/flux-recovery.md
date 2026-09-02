# Flux recovery — Draft / unverified

Current status is `NO-GO`. Every live/secret-aware command named below is
code-blocked before protected-file access because the separately installed
reviewed-blob launcher does not exist. The raw-etcd canary also lacks a reviewed
installed-`etcdctl` executable digest pin. These steps are the future recovery
acceptance contract only; do not bypass a guard with ad-hoc `sudo`, a manual
copy, or environment changes.

1. Keep public routing disabled. Confirm the Kubernetes API, stacked etcd,
   CoreDNS, node readiness, Secret encryption, audit, and namespaces before
   touching Flux. A configured encryption-provider flag is insufficient: run
   the gated disposable raw-etcd canary and require the encrypted-storage prefix,
   plaintext absence, exact cleanup, and metadata-only audit evidence.
2. Compare installed controller images to the reviewed generated manifest and
   immutable digests. Use the protected Linux AMD64 tool/kubeconfig ceremony and
   `bootstrap/flux/bootstrap.sh --apply-controllers` at an exact reviewed `main`
   commit if controllers are absent/corrupt; do not invoke bare kubectl against
   a mutable default context.
3. Wait for source, kustomize, and helm controllers. Confirm cross-namespace
   references and remote bases remain disabled.
4. Never enable or invoke the retired `bootstrap/flux/bootstrap.sh --apply-sync`
   body. Restore site sync only through the release-bound
   `bootstrap/flux/release-selector/bootstrap.sh` transaction: prove the
   GitRepository is credentialless and selects one exact immutable tag, its
   consumer inventory is closed, and both tenant Kustomizations use their
   explicit ServiceAccounts with `prune: false`.
5. Inspect Flux events/status. Prefer a Git revert for bad desired state; do not
   patch Flux-owned resources as ordinary recovery.
6. Before re-enabling a suspended release, render/policy-check the exact revision
   and verify signatures/digests.

Never print Secret YAML or create Git credentials to make recovery easier.
