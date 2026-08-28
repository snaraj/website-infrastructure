# Bootstrap-owned platform release selector

This directory is the permanent #189 boundary. None of its objects is selected
by the `flux-system` GitRepository or either site Kustomization. Installation is
an owner-attended bootstrap operation from an exact immutable platform release.
Flux reconciles only the two website paths.

## Steady state

- one anonymous HTTPS GitRepository pinned to a canonical platform tag;
- exactly two direct website Kustomizations using their exact site service
  accounts, `prune: false`, `deletionPolicy: Orphan`, and no dependency graph;
- one credentialless, digest-pinned selector CronJob; and
- one namespaced Role limited to `get,patch` on the single GitRepository named
  `flux-system` and `get` on the two exact site Kustomizations; and
- one fail-closed native ValidatingAdmissionPolicy and Deny binding that match
  only the selector ServiceAccount's main-resource update of that source.

The selector performs two stable Kubernetes reads, two stable anonymous GitHub
observations, one RFC 6902 resourceVersion compare-and-swap that changes only
the tag and identity annotations, then a current-generation Flux readiness
proof for the source and both independently pinned site Kustomizations. It
selects only the exact next patch. An absent candidate is a successful no-op;
partial, mutable, skipped, moved, or conflicting remote state fails.

Each immutable GitHub Release carries exactly two assets:
`platform-release-identity.v1.json` and its detached Sigstore bundle
`platform-release-identity.v1.json.sigstore.json`. The identity is compact
recursively sorted UTF-8 JSON with one terminal LF and a 64 KiB limit. It binds
the annotated tag, protected merge and tree, exact workflow attempts, selector
image/signature/provenance, changelog fragment, and both sites' signed
chart/workload identities. Release notes are informational and never a trust
input. The selector anonymously downloads both exact assets twice through a
fixed HTTPS host allowlist, checks each GitHub metadata digest against its
bytes, and verifies the bundle with the digest-pinned cosign binary against the
exact platform workflow subject and GitHub Actions issuer.

## Explicit trust boundary

RBAC restricts the selector to patching one named GitRepository, and the native
admission pair independently limits that ServiceAccount to an exact one-patch
forward tag plus the closed reserved evidence-annotation transition. It denies
no-ops and changes to source identity, URL, ref type, credentials, ignore,
sparse checkout, status, finalizers, or non-reserved annotations. The policy
matches neither source-controller status/finalizer writes nor any other
principal. Sparse checkout, the exact public repository, direct site paths,
and site-scoped service accounts bound the consequence after that commit point.

## Bootstrap and recovery

`bootstrap.sh` is a bounded owner-attended orchestrator. Its released read-only
validator owns parsing, normalization, exact-object comparison, CAS rendering,
EndpointSlice equality, artifact semantics, provenance binding, and readiness
decisions. The shell performs exact creates/replaces, one UID/resourceVersion-
guarded JSON Patch per pre-existing site OCIRepository to remove its legacy
SemVer selector, and waits; it never uses apply or delete.
Every Kustomization is created suspended. No recovery mutation is armed until
all public evidence and the owner's exact confirmation succeed. When selector
admission or authority is incomplete, the exact RoleBinding is first placed in
a verified no-subject quarantine. Any later error keeps authority revoked and
best-effort suspends both Kustomizations and the selector CronJob; it never
deletes or takes over a foreign object. Before source creation it enumerates
all effective Git consumers across Kustomizations, HelmCharts, HelmReleases and
ExternalArtifacts twice and accepts only zero consumers or the two exact
suspended parents. It creates or proves the eight parent-chain RBAC objects,
read-only proves the ten pre-existing site execution-chain objects, and
temporarily revokes both exact site Helm RoleBindings while closing each child
spec. Reruns accept only absent or semantically exact normalized objects and
resume from the observed safe phase, including an exact singleton suspended
parent or either exact mixed Helm-binding state left by interruption. The
first armed action always re-quarantines both bindings. A fully complete rerun
proves the target state and performs no write. A partial active rerun first contains the exact
suspendable objects before continuing. Target-source readiness is mandatory
even when a prior attempt already created the source. After that proof the
selector stays suspended while the two sites become Ready in order, then its
authority and permanent schedule are restored.

The initial source-absent bootstrap runs only from a clean checkout of the exact
annotated `v0.1.42` Release. Burned `v0.1.41` is never selected. Recovery after
the source advances requires a clean checkout of the exact canonical annotated
Release already named by the live source; a stale, future, or mismatched
checkout stops before mutation. After reviewing the selector digest and private
API backend set, invoke:

```console
bootstrap/flux/release-selector/bootstrap.sh \
  /protected/path/kubeconfig exact-context https://PRIVATE_BACKEND:6443 \
  sha256:REVIEWED_SELECTOR_DIGEST PRIVATE_BACKEND/32
```

No ambient Kubernetes context is used. The script anonymously verifies the
current immutable two-asset Release, annotated tag, exact attempts, protected
source tree and detached identity signature, plus the selector's keyless
signature and SLSA v1 provenance before the first mutation. It then
requires the owner to type the exact tag. The supplied private `/32` set must
equal the current ready `kubernetes.default` EndpointSlice backends. Calico
enforces workload egress after Service DNAT, so the selector policy names those
backends on TCP 6443 even though the Pod calls the Kubernetes Service on 443.

The selector remains bootstrap-owned and never self-updates. Trusted-root or
selector-digest rotation is an explicit owner-attended migration tracked by
issue #222: quarantine the RoleBinding, suspend the CronJob, wait for zero
selector Jobs and Pods, replace the exact CronJob, re-prove admission, RBAC and
NetworkPolicy state, restore the RoleBinding, and observe the next scheduled
run. Evidence-to-image digest equality is never relaxed during rotation.
