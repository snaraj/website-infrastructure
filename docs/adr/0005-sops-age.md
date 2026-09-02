# ADR 0005: SOPS with age

- Status: Superseded by the owner's 2026-09-02 decision that the repository
  carries no secrets (AGENTS.md safety invariant 7); the scaffolding below is
  removed and the Tunnel token is created on the cluster by an owner ceremony
- Date: 2026-08-08

Implementation status: deployment blocked. The architecture below is accepted,
but every repository entrypoint that generates or consumes protected key
material, verifies SOPS plaintext, reads cluster/etcd credentials, or mutates
Flux is code-blocked until a separately installed immutable reviewed-blob
launcher establishes stage-zero trust outside the mutable checkout.

## Decision

Flux-native SOPS decryption produces stable Kubernetes Secret names and keys.
Commit only SOPS ciphertext and the public cluster recipient. Use two independent
age trust domains:

1. A cluster identity decrypts only Git-tracked Kubernetes SOPS documents. Its
   private identity exists only in the `flux-system/sops-age` Secret and two
   operator-wrapped, restore-tested recovery copies. It never reaches CI, a
   GitHub secret, a workload namespace, or a Cloudflare operator file.
2. A separate operator-wrapping identity encrypts local Cloudflare state/plan
   archives, private inventory, and recovery copies. It never reaches Git, CI,
   the Pi, or the Kubernetes cluster.

New identities use age's hybrid post-quantum recipient form. The pinned age,
SOPS, and Flux controller versions must pass a disposable encrypt/decrypt and
controller canary before the invalid recipient sentinel is replaced. Tool
version output is insufficient: secret-aware operator commands use stable
private executable snapshots whose Linux AMD64 SHA-256 digests are pinned in
`versions.env`. Normal
and rotation repository states have exactly one cluster recipient. Rotation
temporarily installs the old and new private identities together in
`flux-system`, then atomically switches `.sops.yaml` and every ciphertext to the
new public recipient in one reviewed Git change. The old private identity stays
only through a bounded rollback window and is then removed.

Cloudflare API tokens are not cluster secrets. Audit/apply tokens are
just-in-time and revoked after their one bounded job. The distinct admin and
public Tunnel runtime tokens follow their own custody and rotation procedures.

CI authenticates repository location, canonical SOPS envelope grammar, the one
public recipient, and the Secret's closed shape. CI deliberately has no private
identity, so it cannot authenticate the SOPS MAC or prove the decrypted Tunnel
token belongs to the reviewed account/Tunnel. That separate proof is designed
to run only after merge in the protected offline Linux ceremony, but is
currently blocked by the missing launcher:
`verify-sops-ciphertext.sh` first requires the protected public inputs to equal
their exact blobs on reviewed `main`, then decrypts into private scratch inside
a network namespace and validates the plaintext through independently prepared
account/Tunnel-ID digests without printing it.

The latent installation and verification design for `flux-system/sops-age` uses a checksum-pinned kubectl
snapshot and a flattened, self-contained, one-context JSON kubeconfig. Every API
call carries the same explicit context and server. External credential files,
exec/auth-provider plugins, token files, proxies, mutable worktree manifests,
and mixed GitHub/Cloudflare/cloud-KMS authority are rejected. A dm-crypt/LUKS
ancestor, no active swap, zero hard/soft core limits, restricted ptrace, and a
reviewed mount-UUID hash are mandatory. The API server's mutation response and
a fresh live read must equal the intended private bytes and object identity;
public annotations alone are never installation or verification evidence.

## Consequences

Anyone with the identity and repository history can decrypt retained ciphertext,
so suspected theft requires credential rotation as well as re-encryption.
Kubernetes API encryption at rest remains necessary after decryption into the
API server. Before the cluster identity is installed, a disposable raw-etcd
canary must prove the configured encrypted-storage prefix is present and the
plaintext marker is absent, while audit evidence remains metadata-only. A
configured API-server flag alone is not that proof. Hybrid post-quantum age protects against future cryptanalytic
improvement but does not protect an unlocked workstation, a stolen running
process, a compromised controller, or careless plaintext handling. The
workstation ceremony and encrypted-volume controls remain mandatory. In-script
environment and self-hash checks occur after interpreter/loader startup and are
therefore defense-in-depth drift checks, not the missing trust root.
