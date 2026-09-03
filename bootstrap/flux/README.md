# Flux bootstrap — Draft / unverified

Flux reads public `main` anonymously. Never use `flux bootstrap github` or
`flux bootstrap git`, and never create a Git authentication Secret.

The sync objects remain blocked until independent physical/LAN recovery and two
simultaneously working admin sessions have been proven immediately before the
first mutation. Losing either session afterward is recoverable; claiming the
proof before it happened is not.

**The controllers-only install is the one exception, and it is not performed
from this directory.** Installing the three controllers creates no Secret and
applies no Flux custom resource. Its live modes are not credential-free: they
use the protected flattened kubeconfig and its client
credential through a pinned kubectl. Kustomize and kubectl are copied into a
private work directory and their exact executable bytes are SHA-256-bound
before either copy is invoked. The install was separated into its own reviewed entry point,
`scripts/install-flux-controllers.sh`, whose guardrails are executable rather
than documentary: a constant install target that cannot be pointed at the
unsuspended bootstrap root, refusal of any render containing a Flux custom
resource or a Secret or a NetworkPolicy egress rule, an exact object count, and
a server-side dry run whose reported inventory must stay inside `flux-system`.
The ordered ceremony around it is [`docs/runbooks/flux-install.md`](../../docs/runbooks/flux-install.md).
This section previously said no live installation was authorized at all; that
statement stopped being true when the controllers-only install was authorized
separately, and a control this repository asserts but does not hold is worse
than no assertion.

**The cluster already has Flux, and it is not this render.** A stock upstream
v2.9.3 install was applied on 2026-08-12 outside this ceremony: it still binds
`cluster-admin` through `cluster-reconciler-flux-system`, still ships the
blanket `allow-egress` rule, and labels `flux-system` warn-only. The reviewed
overlay and installer here are the desired state that install does not match.
The installer is fresh-install-only and will refuse that cluster by design; the
runbook's "Live prestate" and "Converging the existing install" sections carry
the honest prestate and record that no reviewed convergence design exists.
Nothing in this directory or that one converges the cluster.

`bootstrap.sh --apply-controllers` remains blocked and is **not** the sanctioned
path: it is the protected-custody variant, and it is code-blocked by the same
missing launcher as everything else here. The two are not alternatives — the
sanctioned installer performs an inert authenticated install with the explicit
protected kubeconfig/context/server tuple, while this script's controller mode
exists for the future protected ceremony that also verifies live state against
reviewed expectations.

The code-enforced blocker for everything else stands: no trusted stage-zero
reviewed-blob launcher exists yet. `bootstrap.sh --apply-controllers`,
`--apply-sync`, and `--verify`; `verify.sh`; and the raw-etcd canary all stop
before reading a protected file or making a cluster request. Do not invoke them
or supply secret-bearing environment variables. Their implementations remain
in-tree for review only. Reopening them requires a separately installed
immutable launcher that starts with a clean execution environment, extracts
exact reviewed commit blobs into private custody with trusted absolute tools,
and executes only those snapshots. The recovery and two-session gates are
additional requirements after that control exists. Offline
`bootstrap.sh --generate` remains available and does not consume protected
credentials.

## Trusted operator platform and tools

The secret-bearing and cluster-mutation scripts intentionally support only a
trusted Linux AMD64 host. Git Bash, Cygwin, WSL over an ordinary Windows profile,
and a generic temporary directory are not equivalent custody boundaries. A
separate Linux machine with a dm-crypt/LUKS ancestor beneath the owner-only
mode-0700 credential root, no active swap, hard and soft core limits fixed at
zero, Yama ptrace restriction, no cloud sync/indexing/session recording, and
two tested recovery copies is mandatory. Each secret-aware script verifies the
encrypted block-device ancestry, no-swap state, mount UUID hash, and process
limits; the operator explicitly attests the controls that software cannot
fully observe. The Windows credential gate remains useful for
Cloudflare/OpenTofu work performed on Windows, but its local hash output is not a
portable signature and is not accepted as proof for a later Linux process.

Stage these release artifacts inside the protected root as single-link
owner-only executables, without adding them to the repository:

- Flux v2.9.3 Linux AMD64 for controller generation; and
- kubectl v1.36.3 Linux AMD64 for target reads and mutations.

Verify the publishers' signature/provenance material and the archive/checksum
files independently. `versions.env` pins the resulting executable hashes. The
scripts copy each sensitive tool through one stable file handle, execute only
the private copy, and recheck its hash. A version string alone is not tool
provenance.

Every live command also requires a protected, flattened JSON kubeconfig. Create
it inside the protected root with the pinned kubectl using `config view --raw
--flatten --minify -o json`, with stdout redirected directly to a mode-0600
candidate rather than the terminal. The final file must contain exactly one
cluster, one user, one current context, embedded CA/client certificate/client
key data, and an empty standard `preferences` object. The offline validator
rejects external file paths, bearer tokens, `exec`/auth-provider plugins,
proxies, insecure TLS, duplicate keys, extra authority, links, unsafe modes,
and replacement races:

```bash
KUBECONFIG_SNAPSHOT_FILE="$PROTECTED_KUBECONFIG" \
  /usr/bin/python3 -I scripts/validate_kubeconfig_snapshot.py
```

The future launcher must start the protected process through an absolute
`/bin/bash` from an `env -i` environment before any mutable repository script
runs. In-script rejection of `BASH_ENV`, exported functions, or loader variables
is drift detection after interpreter startup and is not the stage-zero control.
The latent ceremony also rejects proxies, GitHub, SSH-agent, Cloudflare,
OpenTofu, and cloud-KMS authority before its first intentional private-file
read. Each future live operation requires the exact reviewed
`main` commit in `EXPECTED_REPOSITORY_HEAD`, rejects
replace refs, grafts, shallow history, and mutable critical blobs, and extracts
validators and pins from that commit. Bind the target with the reviewed
context/API URL/single Pi node, embedded Kubernetes CA DER SHA-256, and the
SHA-256 of the live `kube-system` namespace UID (canonical UID plus LF). Every
API call receives explicit `--kubeconfig`, `--context`, and `--server`
arguments from immutable snapshots.

## Generate controllers locally

Set `FLUX_BINARY` to the verified Linux AMD64 executable and run
`bootstrap.sh --generate`. The script exports only source-controller,
kustomize-controller, and helm-controller, replaces their tags with the three
reviewed multi-arch digests, and writes `gotk-components.yaml`. Review and
commit the complete diff before any apply. Image-reflector and image-automation
controllers remain absent.

The latent controller-apply implementation uses manifests archived from
`EXPECTED_REPOSITORY_HEAD`, verifies the exact target immediately before apply,
and waits for all three deployments. Its `--apply-controllers` mode remains
code-blocked by the missing launcher; this description is a future acceptance
contract, not an instruction to bypass the stop.

## Public Tunnel tokens

Each site has its own Cloudflare Tunnel bearer, not an API token; the two share
no credential. Neither enters this repository: the owner creates
`cloudflare-public/naranjo-online-tunnel-token` and
`cloudflare-public/lidersea-com-tunnel-token` directly on the cluster from
separate mode-0600 files, one site at a time per
`docs/runbooks/tunnel-token-rotation.md`, and the connector release stays
suspended until that ceremony has run. Never source a token from OpenTofu state.

`bootstrap.sh --apply-sync` remains blocked and is retired as a recovery path.
Its dormant implementation predates the exact-consumer, authority-quarantine,
and compare-and-swap requirements of ADR 0016; it must not be enabled or used to
apply all of `access.yaml` or `gotk-sync.yaml`. The only sanctioned initial site
sync is the owner-attended, release-bound
`bootstrap/flux/release-selector/bootstrap.sh` transaction. Controller install,
controller RBAC, and Cloudflare recovery remain separate out-of-band procedures
and never enter the two site Kustomizations.
