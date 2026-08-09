# Disposable local Kind validation

Kind is an optional workstation-only integration harness. Production remains
upstream Kubernetes bootstrapped with kubeadm on the Raspberry Pi. A Kind pass
does not validate the Pi runtime, CNI choice, networking, storage, backup,
upgrade, or recovery procedures.

The harness is credential-free and never installs or downloads anything. It
requires the exact `kind`, `kubectl`, Helm, and Kustomize versions in
`versions.env`, a local Docker Unix socket or Windows named pipe, and the exact
digest-pinned Kind node image already present in that local engine. Optional
Conftest and Kyverno CLI checks run only when their exact pinned versions are
available. Kubeconform is skipped because the repository has no offline schema
bundle; the local API server validates rendered core resources instead.

Run the non-mutating prerequisite check first:

```console
make kind-check
```

The apply mode uses the fixed cluster name `website-infra-local-test`, refuses
to reuse or delete a pre-existing cluster with that name, writes an isolated
temporary kubeconfig, and binds the test API to loopback. It records the exact
local control-plane container it created and its exit trap deletes the cluster
only while that ownership still matches. Invoke it directly with the complete
acknowledgement shown here:

```console
./scripts/test-kind.sh --apply I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test
```

The apply run creates only bootstrap namespaces, restricted Pod Security
labels, bootstrap RBAC, quotas, limit ranges, and NetworkPolicy objects. It
proves restricted Pod Security rejects a privileged Pod, exercises positive
and negative RBAC decisions, renders both Helm charts and local Kustomizations,
and submits chart output only as server-side dry runs. Conftest and Kyverno
fixtures run when their CLIs are present.

Website and tunnel workloads are deliberately not launched while the image
digest/readiness, SOPS token, token-revision, and suspended HelmRelease gates
remain unresolved. Flux controllers are not installed, and Kind's local
networking is not treated as evidence for the production CNI or NetworkPolicy
behavior.
