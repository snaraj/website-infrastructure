# Host-level `pi-admin` connector

Status: the fail-closed deployment machinery is implemented and reviewable. It
is not evidence that the connector is installed or that remote access works;
only the live acceptance record may make either claim.

## Fixed security boundary

- The connector exposes one private host `/32` through Cloudflare Tunnel. It
  creates no public hostname, DNS record, router forwarding, or Kubernetes API
  (`6443`) allow.
- Gateway must allow TCP 22 only for the exact owner identity on the enrolled
  owner laptop, with the approved device-certificate posture check and a fresh
  session. A later unconditional destination block denies every other L4 flow.
- Cloudflare authorizes the transport. `sshd` independently requires the
  laptop's dedicated, passphrase-protected owner key. The host does not trust a
  Cloudflare SSH CA.
- LAN and the existing private WireGuard path remain recovery transports. The
  connector installers do not edit SSH, UFW, WireGuard, routing, or Kubernetes.
- The service runs as the locked, non-login `cloudflared` system account with
  no supplementary groups or Linux capabilities. systemd supplies the token as
  a runtime credential and applies the hardening in `pi-admin.service`.
- The Tunnel carries client-initiated private access only. Host DNS and egress
  still follow the host routing table, VPN/WireGuard policy, and kill switch.
  Loss of the reviewed privacy route must fail closed; physical/LAN recovery is
  the availability fallback.

## Why source-tree scripts cannot run as root

Every installer and the runtime canary refuses before reading a staged binary,
token, or privileged runtime state unless it was extracted by the installed
root-owned launcher. The launcher never executes a mutable checkout. It:

- admits only a root-owned, mode-`0755` launcher at the fixed installed path;
- validates a closed, ordered, root-only SHA-256 manifest for every absolute
  executable it and its children can use;
- accepts an owner-held Git bundle only through a stable descriptor, verifies
  the bundle and full object database, enforces monotonic protected-main
  ancestry, and requires the installed launcher blob to equal the approved
  commit;
- extracts only the exact operation's reviewed blobs into a fresh root-private
  directory, verifies Git object IDs and modes, and launches with `env -i` and
  `/usr/bin/bash`;
- accepts fixed-order, fixed-key owner request files; and
- serializes operations, disables core dumps, rejects shell/loader/tool
  injection, cleans temporary custody, and fails closed on drift.

Direct invocations are negative tests, not an alternate procedure.

## Owner-attended deployment order

Use an exact merged protected-main commit. Keep physical/LAN recovery and two
independently proven SSH sessions until all mutations and rollback checks are
complete. Use the short-lived sudo procedure; never put a password, token, or
private key in a command line, environment dump, log, repository, or chat.

1. Prove the current host/cluster baseline and the existing SSH/UFW/WireGuard
   controls. Install the signed OS package that provides `getfattr` if absent.
2. Obtain the pinned ARM64 `cloudflared` release out of band and verify the
   version and SHA-256 in `versions.env`. Do not execute caller-staged bytes.
3. From the exact merged commit, install
   `reviewed-launcher.sh` at
   `/usr/local/sbin/website-infrastructure-reviewed-launcher`, owned by root,
   mode `0755`, one link. This is the only manual stage-zero code install.
4. Run `tool-manifest-proposal`. Review the host package change context, then
   pass its exact SHA-256 to `tool-manifest-commit` with confirmation
   `commit-reviewed-tool-manifest-<SHA256>`. The commit is atomic and the
   launcher immediately revalidates every entry.
5. Create an owner-owned mode-`0600` Git bundle containing the exact merged
   commit. Run `promote <bundle> <commit>
   promote-reviewed-protected-main-<commit>`. Promotion is monotonic; a launcher
   change requires a new owner-attended stage-zero install before promotion.
6. Create owner-owned mode-`0600` request files with exactly the schemas below,
   in the shown order. No blank, duplicate, or extra line is accepted.

Binary check:

```text
CLOUDFLARED_HOST_BINARY_PATH=<absolute owner-staged path>
```

Binary apply adds:

```text
PHYSICAL_OR_LAN_RECOVERY_TESTED=yes
TWO_WORKING_SESSIONS_PROVEN=yes
CONFIRM_CLOUDFLARED_INSTALL=install-reviewed-cloudflared-<pinned version>
```

Invoke `binary-check <request>`, then `binary-apply <request>`. The installer
copies into private custody, verifies checksum/version/`--token-file` behavior
inside a network namespace as an unprivileged identity, rejects links,
capabilities, xattrs, and extended ACLs, acquires an exclusive lock, preserves
the prior state, and uses an atomic same-filesystem commit.

Token check:

```text
CLOUDFLARED_TOKEN_WORKSPACE=<absolute owner-only mode-0700 directory>
CLOUDFLARED_TUNNEL_TOKEN_FILE=<mode-0400-or-0600 file inside that directory>
EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256=<lowercase SHA-256>
EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256=<lowercase SHA-256>
```

Token apply adds:

```text
PHYSICAL_OR_LAN_RECOVERY_TESTED=yes
TWO_WORKING_SESSIONS_PROVEN=yes
CONFIRM_PI_ADMIN_TOKEN_INSTALL=install-reviewed-pi-admin-token
```

Invoke `token-check <request>`, then `token-apply <request>`. The validator
accepts only Cloudflare's canonical standard-Base64 `{a,s,t}` token, exact
independently supplied account/Tunnel hashes, and a minimum 32-byte secret. It
never prints a field. The apply revalidates immediately before and after the
atomic root-mode-`0600` install and rolls back exact prior bytes on failure.

7. Before the service starts, prove the destination `/32`, exact owner/device
   TCP-22 allow, and later unconditional destination block exist at safe
   precedence. Then run `service-check` and create this exact apply request:

```text
PHYSICAL_OR_LAN_RECOVERY_TESTED=yes
TWO_WORKING_SESSIONS_PROVEN=yes
CONFIRM_PI_ADMIN_SERVICE_INSTALL=install-and-start-reviewed-pi-admin
```

Invoke `service-apply <request>`. It validates the pinned binary and token,
creates or strictly validates the locked account/group, installs the exact unit
atomically, reloads systemd, enables/restarts it, and proves the live process
runs under the dedicated UID. Failure restores the prior unit enablement,
activity, bytes, and newly created account/group state.

8. Run `runtime-verify`. Success proves the exact installed unit has no
   drop-ins or pending reload, the exact reviewed binary and locked account own
   the live process, the active systemd credential equals the unchanged token,
   the token is absent from complete argv/environment/journal records, no unit
   coredump exists, and all identities remain stable throughout the scan.
9. Prove connector egress uses the reviewed privacy route and that loss of that
   route does not create direct-WAN fallback. Stop and restart Kubernetes host
   services and prove `pi-admin` remains healthy independently, then restore and
   prove the cluster baseline.
10. From an external network, prove enrolled-owner WARP-on SSH succeeds. Prove
    WARP-off, a different LAN device/key, an unenrolled device, wrong identity,
    expired/revoked session, every non-22 port, and direct residential-origin
    access fail. Re-prove LAN recovery and normal owner-key SSH last.

## Package upgrades and launcher changes

The executable manifest intentionally fails closed after a covered OS utility
changes. Recovery is implemented: run `tool-manifest-proposal`, confirm the
change came from an expected signed package transaction, then commit only the
exact proposed digest with `tool-manifest-commit`. This route does not require
the old tool hashes to match, so it requires fresh owner-authorized sudo and the
exact digest confirmation.

A change to `reviewed-launcher.sh` cannot self-promote. Review and merge it,
install that exact protected-main blob again through the owner-attended
stage-zero step, then promote the matching newer bundle. A non-descendant
bundle is refused.

## Recovery and residual risk

- Never replace a failed private route with a public SSH hostname, router port
  forward, broad source-CIDR rule, public `22`, or `6443` allow.
- Preserve old sessions during mutation. On failure, use physical/LAN access;
  never use an old or suspected token as rollback authority.
- Routine rotation proves the old token cannot reconnect. Suspected compromise
  additionally force-disconnects every existing Tunnel connection before the
  replacement is trusted.
- `LoadCredential=` protects runtime delivery but does not encrypt
  `/etc/cloudflared/pi-admin.token` at rest. Root compromise or offline storage
  theft can recover it. Rotate and force-disconnect on device loss. Full-disk or
  TPM-backed credential encryption requires a separately restore-tested design.
- Root and the owner laptop remain trust anchors. The manifest detects
  unexpected executable drift; it cannot defend a host after root compromise.
