# Disposable local Kind validation

Kind is an optional workstation-only integration harness. Production remains
upstream Kubernetes bootstrapped with kubeadm on the Raspberry Pi. A Kind pass
does not validate the Pi runtime, CNI choice, networking, storage, backup,
upgrade, or recovery procedures.

The harness is credential-free and never installs or downloads anything. It
requires Python 3 plus the exact `kind`, `kubectl`, Helm, and Kustomize versions
in `versions.env`, a local Docker Unix socket or Windows named pipe, and the
exact digest-pinned Kind node image already present in that local engine.
Optional Conftest and Kyverno CLI checks run only when their exact pinned
versions are available. Kubeconform is skipped because the repository has no
offline schema bundle; the local API server validates rendered core resources
instead.

Run the non-mutating prerequisite check first:

```console
make kind-check
```

The apply mode uses the fixed cluster name `website-infra-local-test` and fixed
network name `website-infra-local-test-internal`. It refuses to reuse or delete
either pre-existing object, writes an isolated temporary kubeconfig, and binds
the test API to loopback. Before Kind starts, the harness creates that network
as a non-attachable, non-ingress, local `--internal` Docker bridge with one
exact owner label. It records the full network and control-plane container IDs,
proves the node is the network's sole endpoint and has no second Docker network,
and deletes each object only while its complete ownership identity still
matches. Invoke it directly with the complete acknowledgement shown here:

```console
./scripts/test-kind.sh --apply I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test_AND_ITS_INTERNAL_DOCKER_NETWORK
```

The apply run creates only bootstrap namespaces, restricted Pod Security
labels, bootstrap RBAC, quotas, limit ranges, and NetworkPolicy objects. It
proves restricted Pod Security rejects a privileged Pod, exercises positive
and negative RBAC decisions, renders both Helm charts and local Kustomizations,
and submits chart output only as server-side dry runs. Conftest and Kyverno
fixtures run when their CLIs are present.

Website and tunnel workloads are deliberately not launched while the image
digest/readiness, SOPS token, token-revision, and suspended HelmRelease gates
remain unresolved. Flux controllers are not installed. The owned internal
Docker bridge prevents the disposable node and its Pods from routing to the
LAN, public Internet, registry, or another Docker network; this host-level
containment is still not evidence for the production CNI or NetworkPolicy
behavior.

When every release gate is active, the harness uses the strict release-state
parser to extract the authoritative HelmRelease `spec.values` for both sites
and the public connector. Linting, local desired-state renders, release policy,
and runtime candidate comparison therefore use the same effective values Flux
will merge over the permanently inert chart defaults. The runtime-only
`image.pullPolicy=Never` override prevents a network pull inside disposable
Kind; it does not replace the reviewed digest or readiness values.
When the repository already contains reviewed capacity quotas, runtime mode
temporarily adds the exact zero-Pod `capacity-not-ready` negative control only
inside the owned Kind cluster, proves it rejects a conforming Pod, removes that
temporary control, and leaves the rendered reviewed quotas in place for the
two-replica readiness exercise.

For a single promoted or rollback digest that is still suspended, use the
explicit transition runtime mode. The strict transition classifier must accept
the checkout as `transition`, and the selected website must be exactly
`staged`; an initial or already-active selection is rejected before Kind is
created. The direct command invokes the same canonical offline transition gate
as `release-gate.sh` both before creating Kind and again after runtime checks,
immediately before reporting evidence. A repository, render, schema, policy,
capacity, or negative-fixture change during the Kind run therefore fails closed
instead of inheriting stale static proof. Preload only the selected canonical
image by its exact digest, then set only its existing site-specific environment
variable. For example:

```console
export NARANJO_RUNTIME_IMAGE='ghcr.io/snaraj/naranjo-online@sha256:REPLACE_WITH_64_LOWERCASE_HEX'
./scripts/test-kind.sh --transition-runtime naranjo-online I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test_AND_ITS_INTERNAL_DOCKER_NETWORK
```

To run only that canonical transition proof without reading Docker state or
creating either owned object:

```console
./scripts/release-gate.sh --transition-check
```

The release-gate wrapper invokes that same path, whose first action is the
complete canonical offline transition gate:

```console
./scripts/release-gate.sh --transition-runtime naranjo-online I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test_AND_ITS_INTERNAL_DOCKER_NETWORK
```

Substitute `lidersea-com` and `LIDERSEA_RUNTIME_IMAGE` together for the other
site. The harness extracts that one HelmRelease's authoritative `spec.values`,
requires its one rendered image to equal the locally present RepoDigest, and
overrides only `image.pullPolicy=Never`. Inside the owned loopback cluster it
creates only the selected tenant namespace, applies and proves one synthetic
selected-site zero-Pod quota, removes exactly that quota, loads and runs only
the selected site, and checks its two replicas and `/readyz`. It does not create
Flux or Cloudflare namespaces, render a runtime tunnel, read a production
kubeconfig, contact a registry, LAN, public endpoint, or other Docker network,
or establish Raspberry Pi capacity, CNI, storage, tunnel, or production
evidence. Namespace checks compare the live inventory to the freshly captured
system baseline plus exactly the selected tenant before and after workload
application.
