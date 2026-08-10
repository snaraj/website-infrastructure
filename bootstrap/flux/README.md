# Flux and SOPS bootstrap — Draft / unverified

Flux reads public `main` anonymously. Never use `flux bootstrap github` or
`flux bootstrap git`, and never create a Git authentication Secret.

Nothing in this directory authorizes a live installation. Controller apply,
the `sops-age` Secret, and sync are separate mutations. They remain blocked
until independent physical/LAN recovery and two simultaneously working admin
sessions have been proven immediately before the first mutation. Losing either
session afterward is recoverable; claiming the proof before it happened is not.

There is an earlier code-enforced blocker: no trusted stage-zero reviewed-blob
launcher exists yet. `bootstrap.sh --apply-controllers`, `--apply-sync`, and
`--verify`; `verify.sh`; both `install-sops-age-secret.sh` modes; both protected
SOPS verifiers; and the raw-etcd canary all stop before reading a protected file
or making a cluster request. Do not invoke them or supply secret-bearing
environment variables. Their implementations remain in-tree for review only.
Reopening them requires a separately installed immutable launcher that starts
with a clean execution environment, extracts exact reviewed commit blobs into
private custody with trusted absolute tools, and executes only those snapshots.
The recovery and two-session gates are additional requirements after that
control exists. Offline `bootstrap.sh --generate` remains available and does
not consume protected credentials.

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

- Flux v2.9.3 Linux AMD64 for controller generation;
- kubectl v1.36.3 Linux AMD64 for target reads and mutations;
- age/age-keygen v1.3.1 Linux AMD64; and
- SOPS v3.13.3 Linux AMD64.

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
OpenTofu, cloud-KMS, and unapproved SOPS authority before its first intentional
private-file read. Each future live operation requires the exact reviewed
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

## Cluster age identity ceremony

Do not generate the real identities merely because this branch is ready. Begin
only after the reviewed-blob launcher exists and the protected machine, two
independent backup destinations, restore test, raw-etcd Secret-encryption
canary, metadata-only audit evidence, recovery, and two-session gates are ready.

1. On the trusted offline Linux machine, generate a hybrid post-quantum cluster
   identity with the pinned `age-keygen -pq`. Capture only its public
   `age1pq1...` recipient. Never display or transmit the private identity.
2. Generate a different operator-wrapping identity. Create two independently
   stored operator-wrapped copies of the cluster identity. Restore each into
   protected scratch and prove it decrypts disposable ciphertext; a copy
   encrypted only to a key stored beside it is not independent recovery.
3. Verify a disposable SOPS encrypt/decrypt round trip with the pinned binaries.
   Commit only the cluster public recipient to `.sops.yaml`. The operator key,
   cluster identity, decrypted material, and backup locations never enter Git,
   CI, chat, email, clipboard sync, or the Pi at this stage.
4. After the launcher blocker is resolved, Flux controllers are healthy, and
   the raw-etcd canary proves the configured encrypted-storage prefix while the
   plaintext marker is absent, the future procedure runs
   `install-sops-age-secret.sh create`. Supply protected paths through the
   private process, not command-history literals. Required inputs include
   `CREDENTIAL_WORKSPACE`, `KUBECONFIG_FILE`, `KUBECTL_BINARY`,
   `AGE_KEYGEN_BINARY`, the exact context/server/node/CA/namespace-UID,
   encrypted-filesystem UUID hash, the exact custody acknowledgement,
   `SOPS_AGE_TWO_BACKUPS_RESTORE_TESTED=yes`, and the create acknowledgement.

The installer derives the public recipient from the protected private file,
creates candidates only inside the protected root, and uses create or
resourceVersion compare-and-swap replace. Replacement also requires the
independently retained predecessor identity-count, recipient-set, and private-
data digests, so a merely well-shaped but unexpected Secret cannot be silently
overwritten. It compares both the API server's mutation response and a fresh
live read with the intended `age.agekey` bytes, UID, resourceVersion, exact
annotations, and closed security metadata before reporting success. The
standalone verifier likewise requires the protected identity file(s) and pinned
age-keygen, then compares the exact live bytes; metadata and shape alone are
never proof.

## Public Tunnel-token ciphertext

The `pi-websites` runtime token is a Cloudflare Tunnel bearer, not an API token.
Retrieve it directly into a mode-0600 protected file without printing it. Build
the exact `cloudflare-public/pi-websites-tunnel-token` Secret plaintext only in
protected scratch, encrypt `stringData.token` with the one recipient selected by
`.sops.yaml`, and write SOPS output to a new candidate before any atomic rename.
Never source the token from OpenTofu state.

Only after the launcher blocker is resolved, and before copying ciphertext into
`kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml`, run the
static snapshot/repository validators. Review and merge only the ciphertext,
public recipient, and token revision. Then, from the exact merged protected
`main`, the future procedure runs `verify-sops-ciphertext.sh` on protected snapshots of the committed
`.sops.yaml` and ciphertext, the cluster identity, pinned SOPS/age-keygen
executables, and independently prepared SHA-256 digests of the reviewed
Cloudflare account and `pi-websites` Tunnel IDs. The script:

- checks the exact SOPS grammar and single hybrid-PQ recipient;
- decrypts under a network namespace, which authenticates the SOPS MAC;
- directs plaintext only to mode-0600 protected scratch;
- validates the decrypted bearer token's canonical standard-base64 JSON,
  account digest, Tunnel UUID digest, and secret length; and
- requires both public input snapshots to equal their exact committed Git blobs,
  with replace refs, grafts, local credential helpers, and mutable validator
  sources excluded; and
- emits only PASS plus the public ciphertext SHA-256 before deleting scratch.

CI repeats structure, path, recipient, and ciphertext-envelope checks, but CI
has no private identity and therefore cannot authenticate the MAC or plaintext
token identity. A CI PASS is not a decrypt proof.

After the launcher blocker is resolved, the ciphertext/revision change is
reviewed and merged, and its protected MAC proof succeeds, the future procedure
runs `bootstrap.sh --apply-sync`. Supply the protected age
identity file(s) and pinned age-keygen so it can compare the exact live Secret
bytes. It first verifies the installed age Secret, then
applies the namespaces, bootstrap-owned least-privilege access, and anonymous
sync manifests archived from the exact reviewed `main` commit. `verify.sh`
delegates to the same protected target implementation. Flux cannot modify its
own controller or reconciliation authorization.
