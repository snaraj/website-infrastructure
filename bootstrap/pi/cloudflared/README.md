# Host-level `pi-admin` connector — Draft / uninstalled

The unit is independent of Kubernetes and accepts only a remotely managed tunnel token
through a root-owned systemd credential file. It contains no account API token,
`cert.pem`, Global API key, public hostname, or DNS record.

Before installation, verify the exact pinned cloudflared binary/checksum and its
`--token-file` behavior, create a locked `cloudflared` system user, confirm LAN/
physical recovery, and review existing firewall/VPN policy. Any eventual token
installation must avoid printing it; the dedicated account must be non-root,
password-locked,
have `/nonexistent` as home, and use `nologin`/`false` as its shell.

Both `install-host-token.sh --check` and `--apply` are intentionally
code-blocked before the token path is read. A mutable worktree script cannot
establish stage-zero trust: malicious startup code or a replaced script could
omit its self-check before reading or installing the bearer. Reopening either
mode requires a separate root-owned reviewed-blob launcher that uses trusted
absolute tools to extract the exact installer and validator blobs into a new
root-private directory, verifies their object IDs and modes, and invokes the
extracted installer with `/bin/bash` and a minimal environment. That transaction
must be independently reviewed and tested for interruption, race, rollback, and
cleanup. Until it exists, no manual copy, ad-hoc `sudo`, or permissions
workaround is authorized. The token apply is intentionally blocked; deployment
of the host token remains blocked.

The latent validator accepts Cloudflare's canonical standard-Base64 token
encoding, requires the exact `{a,s,t}` payload, canonical UUID/account fields,
and a minimum 32-byte Tunnel secret, and never prints a field. It is designed to
bind exact local `main`, reject replacement refs/config injection, compare
stable source snapshots with reviewed Git blobs, and execute only a private
validator copy. Those are future defense-in-depth controls, not a reason to
bypass the current guard.

`verify-host-token-redaction.sh` is likewise code-blocked before token or
runtime-metadata access. Only after the launcher blocker is resolved and a
separately approved unit start may the future procedure invoke it with the same exact
reviewed-main commit/owner binding, and a minimal environment. It compares
through an unlinked root-private pattern-file descriptor and emits only
PASS/FAIL. It binds `MainPID`, invocation ID, process start time, exact
`/usr/local/bin/cloudflared` executable, and exact non-bearer argv; opens the
active systemd credential through a stable handle; and proves those bytes equal
the unchanged installed token before checking the process argv, environment,
and complete unit journal. It also disables core dumps before opening any token,
uses reviewed Git blobs for itself and `versions.env`, and closes the credential
and pattern descriptors before success. A rotation without the required restart
cannot silently scan the wrong token. Do not inspect logs by printing them before this
canary passes.
Then prove the service survives kubelet/containerd and the control plane
stopping and restarting.

`LoadCredential=` copies the file into systemd’s protected runtime credential
directory, but it does **not** encrypt `/etc/cloudflared/pi-admin.token` at rest.
The current Pi design therefore makes an explicit, review-required
rotate-on-device-loss choice:
root compromise or offline storage theft can recover the bearer token, so force-
disconnect connectors and rotate it immediately. TPM2-backed
`LoadCredentialEncrypted=` or full-disk encryption requires a separately tested
hardware/recovery design and must not be inferred from this unit.
Production deployment must either accept this residual plaintext-at-rest risk
in the merge/deployment record or first implement and restore-test one of those
hardware-backed designs.

`install-host-binary.sh --check` and `--apply` are also code-blocked by the
missing reviewed-blob launcher. The latent design copies a locally staged ARM64
binary into private custody, verifies that copy against fail-closed
checksum/version pins, and proves `--token-file` support. It never executes the
mutable staging path. Its future root apply transaction acquires an exclusive
lock, performs re-verification and hardlink/capability/xattr/ACL rejection,
creates a drift-safe backup, and commits with an atomic same-filesystem
operation. Candidate execution is designed to be
time-bounded, network-namespaced, and privilege-dropped. Those controls remain
reviewable but non-actionable; no binary check or install is authorized until
the launcher exists.

Do not harden SSH or change firewall rules until external WARP SSH/kubectl works,
WARP-off/unauthorized tests fail, independent physical/LAN recovery works, and
at least two working sessions have been proven immediately before mutation.
Physical access is the independent recovery path if either session later drops.
The
Gateway L4 block is not a substitute for a host firewall and does not prove ICMP
denial. Token rotation changes only `pi-admin`; never rotate the public tunnel in
the same operation. Rotation prevents the old token from reconnecting but does
not evict an already connected old-token connector. A compromise response must
also force-disconnect every existing connection; physical/LAN access, never the
old token, is the admin rollback path.

The initial SSH design retains self-managed host-trusted keys over the private
WARP-to-Tunnel path. Do not add a public SSH hostname or make sshd trust a
provider-managed SSH CA without a separate decision. `cloudflared` proxies
client-initiated access; host-initiated DNS, updates, Git/registry access, and
other egress continue to use the host routing table. Existing VPN/WireGuard and
kill-switch behavior therefore remains an independent control. Route the
connector through that reviewed privacy boundary and prefer loss of remote
availability to an unreviewed direct-WAN bypass; retain physical/LAN recovery.
