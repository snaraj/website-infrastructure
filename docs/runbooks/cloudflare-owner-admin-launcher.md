# Cloudflare owner-admin launcher

This runbook is the only reviewed live path for the seven `pi-admin`
Cloudflare phases. It contains no live identifiers or credentials. Replace
placeholders only in absolute owner-owned mode-`0600` files outside Git. Never
put a token, email, account/zone/user ID, device ID, route, or private address
in shell arguments, history, logs, issues, pull requests, or this repository.

## Trust boundary

- Install `scripts/cloudflare-reviewed-launcher.sh` from the exact merged
  protected-main blob as
  `/usr/local/sbin/website-infrastructure-cloudflare-launcher`, root:wheel mode
  `0755`.
- The launcher requires arm64 macOS, FileVault on, SIP enabled, Gatekeeper
  enabled, root-owned non-writable parent directories, a root-owned executable
  manifest, and exact pinned OpenTofu, Conftest, and jq bytes.
- Every live operation executes exact blobs from the launcher's root-owned,
  monotonically advanced bare repository. A mutable checkout is never an
  execution source.
- Before promotion changes root custody, the launcher uses anonymous HTTPS with
  a fixed repository URL, disabled redirects and credentials, and an HTTPS-only
  Git transport to require both the bundle's advertised `refs/heads/main` and
  the live upstream `refs/heads/main` to equal the requested commit exactly.
- Invoke sudo as `/usr/bin/env -u TERMINFO /usr/bin/sudo ...`. The local sudo
  policy intentionally rejects inherited `TERMINFO`; unsetting it fixes the
  invocation without weakening that policy.
- The launcher serializes all work. Never delete its lock manually. Use the
  closed `recover-lock` operation only after the recorded process is absent and
  type the exact PID-bound confirmation.

## Owner input files

Every request file is an exact `KEY=value` grammar with no blank or extra line.
The request and every referenced input must be an absolute, non-symlink,
single-link regular file owned by the invoking owner, mode `0400` or `0600`.
The launcher copies each input to root custody from one stable open handle.

Tool installation request, four lines:

```text
OPENTOFU_ARCHIVE_PATH=/absolute/protected/path/tofu.tar.gz
CONFTEST_ARCHIVE_PATH=/absolute/protected/path/conftest.tar.gz
JQ_BINARY_PATH=/absolute/protected/path/jq
CONFIRM_CLOUDFLARE_TOOL_INSTALL=install-reviewed-cloudflare-tools-1.12.5-0.69.0-1.8.2
```

Audit-token proposal request, two lines:

```text
AUDIT_TOKEN_PATH=/absolute/protected/path/audit-token
CONTEXT_PATH=/absolute/protected/path/context.json
```

Configuration request, four lines:

```text
CONTEXT_PATH=/absolute/protected/path/context.json
AUDIT_TOKEN_PATH=/absolute/protected/path/audit-token
OWNER_DEVICE_CA_CERTIFICATE_PATH=/absolute/protected/path/owner-device-ca.pem
CONFIRM_CLOUDFLARE_CONFIGURATION=configure-owner-only-pie5-cloudflare-admin
```

JIT apply request, two lines:

```text
JIT_TOKEN_PATH=/absolute/protected/path/current-phase-token
JIT_TOKEN_ID=REPLACE_WITH_NONSECRET_32_HEX_TOKEN_ID
```

Audit-token rotation request, one line:

```text
AUDIT_TOKEN_PATH=/absolute/protected/path/replacement-audit-token
```

## Protected context

The context is strict JSON with exactly this shape. Every placeholder becomes a
real value only in the protected file. Permission-group IDs come from the live
Cloudflare permission catalog and are checked against both their exact names
and scopes on every operation.

```json
{
  "schema": "pie5-cloudflare-owner-admin-v1",
  "account_id": "REPLACE_WITH_32_HEX_ACCOUNT_ID",
  "owner_user_id": "REPLACE_WITH_32_HEX_OWNER_USER_ID",
  "zone_ids": {
    "naranjo.online": "REPLACE_WITH_32_HEX_ZONE_ID",
    "lidersea.com": "REPLACE_WITH_32_HEX_ZONE_ID"
  },
  "admin_email": "REPLACE_WITH_EXACT_OWNER_EMAIL",
  "identity_provider_id": "REPLACE_WITH_LOWERCASE_IDP_UUID",
  "pi_admin_cidr": "REPLACE_WITH_PRIVATE_IPV4_HOST_PREFIX",
  "gateway": {
    "ssh_allow_precedence": 100,
    "block_precedence": 1000,
    "session_freshness": "300s"
  },
  "jit_permission_group_ids": {
    "admin-certificate": "REPLACE_WITH_SSL_CERTIFICATES_WRITE_ID",
    "admin-enrollment-policy": "REPLACE_WITH_ACCESS_APPS_POLICIES_WRITE_ID",
    "admin-enrollment-app": "REPLACE_WITH_ACCESS_APPS_POLICIES_WRITE_ID",
    "admin-device": "REPLACE_WITH_ZERO_TRUST_WRITE_ID",
    "admin-tunnel": "REPLACE_WITH_CLOUDFLARED_CONNECTOR_WRITE_ID",
    "admin-policies": "REPLACE_WITH_ZERO_TRUST_WRITE_ID",
    "admin-route": "REPLACE_WITH_NETWORKS_WRITE_ID"
  },
  "audit_permission_group_ids": {
    "API Tokens Read": "REPLACE_WITH_ID",
    "Account Settings Read": "REPLACE_WITH_ID",
    "Billing Read": "REPLACE_WITH_ID",
    "Account: SSL and Certificates Read": "REPLACE_WITH_ID",
    "Cloudflare One Connector: cloudflared Read": "REPLACE_WITH_ID",
    "Cloudflare One Networks Read": "REPLACE_WITH_ID",
    "Zero Trust Read": "REPLACE_WITH_ID",
    "Access: Apps and Policies Read": "REPLACE_WITH_ID",
    "Access: Audit Logs Read": "REPLACE_WITH_ID",
    "Access: Organizations, Identity Providers, and Groups Read": "REPLACE_WITH_ID",
    "Zone Read": "REPLACE_WITH_ID",
    "DNS Read": "REPLACE_WITH_ID"
  },
  "owner_device_ca_certificate_sha256": "REPLACE_WITH_PUBLIC_CA_FILE_SHA256",
  "audit_token_contract_sha256": "REPLACE_WITH_PROPOSED_CONTRACT_SHA256"
}
```

For the proposal only, set `audit_token_contract_sha256` to 64 zeroes. Run the
proposal, copy only its printed contract SHA-256 into the protected context,
and run `configure`. Configuration rejects another user's token, another
account, a partial zone selector, any write permission, a non-host source
condition, a lifetime over 60 minutes, a private key, or a context/certificate
digest mismatch.

## Bootstrap and promotion

1. Download the three official pinned artifacts into protected owner files;
   independently verify the release checksums recorded in `versions.env`.
2. Run `tools-install <request>`. Then run `tool-manifest-proposal`, inspect its
   SHA-256, and run `tool-manifest-commit <sha256>
   commit-cloudflare-tool-manifest-<sha256>`. An OS/tool update deliberately
   blocks later work until a new proposal is reviewed and committed.
3. Fetch protected `main`, create a full Git bundle whose sole requested main
   tip is that exact commit, and run `promote <bundle> <commit>
   promote-reviewed-protected-main-<commit>`. Promotion refuses history
   rollback, a bundle/live-upstream main mismatch, a launcher-blob mismatch, or
   any pending Cloudflare phase. A network or upstream ambiguity fails closed.
4. Run `audit-token-proposal <request>`, update the protected context with the
   printed contract hash, then run `configure <request>`.
5. Import the sole leaf certificate and matching private key into the Mac system
   trust store. After the leaf is independently verified and the public CA is
   preserved, destroy the CA private key so another device certificate cannot
   be minted. Replacing or renewing the leaf later requires a reviewed full CA
   rotation before certificate expiry.
6. Run `status`. All seven phases must initially be `absent`.

## One phase

1. Create one user-owned JIT token named
   `website-infrastructure-<phase>-jit`. Give it exactly the phase permission,
   the exact account resource, one current global source host (`/32` or `/128`),
   and at most 30 minutes. Keep every other write token revoked.
2. Run `apply <phase> <request>`. Inspect the saved-plan SHA-256 and type the
   exact displayed confirmation. The command stops at
   `PHASE_RESULT=PENDING_REVOCATION`; this is not completion.
3. Revoke that exact JIT token in Cloudflare. Do not wait for expiry.
4. For `admin-device`, enroll only this Mac using the exact owner identity,
   phishing-resistant MFA, and the installed leaf certificate. For
   `admin-tunnel`, pipe `emit-runtime-token` directly into the reviewed Pi
   connector installer and prove the connector healthy. Do not display or save
   the runtime bearer.
5. Run `resume <phase>`. Type the phase's external confirmation only after it is
   independently true. Completion requires rejected-bearer proof, inactive
   token metadata, complete issuance-to-closure audit logs attributed to that
   token, the exact create set, unchanged unrelated resources, and the exact
   post-audit.
6. Run `status` and begin the next phase only when the current phase is
   `complete` and no previous phase is pending.

The fixed order is `admin-certificate`, `admin-enrollment-policy`,
`admin-enrollment-app`, `admin-device`, `admin-tunnel`, `admin-policies`, then
`admin-route`.

## Failure and recovery

- On any interruption, do not mint another token and do not delete protected
  state. Run `status`.
- If interruption occurred before the launcher printed the revoke instruction,
  run `resume <phase>` once so an exact completed provider state and a held
  Tunnel bearer can be recovered; follow its next instruction.
- Revoke the JIT token whenever the launcher requests it, then run
  `resume <phase>` again. A pre-apply failure clears only after the audit log
  proves zero mutations. An empty failed apply clears only after the same proof.
- `FAILED_PARTIAL_LOCKED` is an incident boundary. Preserve all root state and
  logs; do not import, edit state, retry, or broaden a token. Implement and
  independently review a phase-specific recovery before proceeding.
- `recover-lock recover-stale-cloudflare-launcher-lock-<pid>` is allowed only
  after independently proving that exact PID no longer exists. A live or
  malformed lock remains closed.
- Rotate the audit token with `rotate-audit-token <request>` before expiry. The
  replacement must have the identical policy contract; rotation never changes
  context, write authority, or phase state.

After `admin-route`, live acceptance still requires the local-console and
retained-LAN-session safety checks, owner-laptop LAN/hotspot/Proton positives,
unauthorized-device LAN/off-LAN negatives, public-TCP-22 negative, Pi reboot
proof, WARP reconnect proof, DNS-leak classification, and final complete audit.
