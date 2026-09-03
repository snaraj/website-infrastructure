# Tunnel token rotation — Draft / unverified

For the host-level `pi-admin` token, stage the new `eyJ...` value only in a
protected owner-only file only after the reviewed-blob launcher blocker is
resolved. Both modes of `bootstrap/pi/cloudflared/install-host-token.sh` and the
runtime redaction canary are currently code-blocked before bearer access. The
future procedure binds validation to the independently reviewed 40-hex `main`
commit and checkout-owner UID, and invokes absolute `/bin/bash` through a
minimal `/usr/bin/env -i` environment.
The file must be canonical standard Base64 (including `+`, `/`, and required
padding), not a guessed URL-safe-only shape. The installer parses the token's
closed `{a,s,t}` payload without disclosure and requires independently prepared
SHA-256 digests of the reviewed account ID and `pi-admin` Tunnel UUID, so a
well-formed token for the wrong Tunnel is rejected. It snapshots its own source,
executes the validator blob from that exact commit, rejects Git replacement/
configuration injection, disables core dumps, and emits no token field.

The token installer intentionally refuses both `--check` and `--apply` before
reading the token path. Running a mutable checkout script and letting it attest
itself is not a valid root of trust. A separately reviewed root-owned reviewed-blob
launcher/extraction transaction is required before host-token deployment or
rotation can proceed; it must copy exact commit blobs into root-private custody
with trusted absolute tools before `/bin/bash` executes them. Do not substitute
a manual copy, ad-hoc `sudo`, or a local permissions exception. The old bearer
remains never rollback authority. Starting/restarting the unit is a separate
checkpoint;
afterward require `verify-host-token-redaction.sh` before displaying any logs.
The canary requires the same reviewed-main source binding, opens the installed
token into an unlinked root-private descriptor, binds one stable systemd
invocation, proves the executable is the
pinned `/usr/local/bin/cloudflared`, requires its exact `--token-file` argv,
compares the installed file with that invocation's active `LoadCredential`
snapshot, and only then scans argv, environment, and the complete unit journal.
It therefore fails safely if a new token was installed but the service still
runs with the old credential.
The persistent root-only token is not encrypted at rest, so loss or offline
theft of the Pi triggers immediate force-disconnect and rotation.

Both public paths are also `NO-GO` until the same class of separately installed
reviewed-blob launcher exists. Public token rotation instructions below are a
future acceptance contract only; do not bypass the guards.

`pi-admin` and each public site hold separate Tunnel tokens. Never rotate more
than one in a single change. A remotely managed Tunnel token is a bearer
credential: anyone holding it can run a connector for that Tunnel.

Cloudflare rotation has two important semantics:

- after rotation, the old token cannot establish a new connection;
- connectors that were already connected with the old token remain connected
  until they restart or Cloudflare force-disconnects the Tunnel connections.

Therefore an old token is never a post-rotation rollback credential. Routine
rotation preserves service with existing connections while the new token is
installed. Compromise response rotates first, force-disconnects every existing
connection, and accepts downtime while trusted connectors receive the new
token. Physical or trusted-LAN recovery is the admin-path fallback.

Never place either Tunnel token or the API bearer used for rotation in a command
line, shell history, Git, chat, logs, OpenTofu state, or an unprotected plan.
Use a protected file or process-local environment, disable shell tracing, and
clear it immediately afterward.

## Public connectors — exactly one site per ceremony

`<site>` is one of the two independent connectors in the chart's `values.yaml`:
`naranjo-online` (Tunnel `naranjo-online-tunnel`, Secret
`naranjo-online-tunnel-token`) or `lidersea-com` (`lidersea-com-tunnel`,
`lidersea-com-tunnel-token`); the other is the PEER and shares no credential.
The superseded shared `pi-websites` Tunnel and Secret are denied by policy.

Routine rotation:

1. Keep `pi-admin` and physical/LAN recovery working and record the peer
   Secret's `resourceVersion` and `creationTimestamp`. In a reviewed window,
   have the owner rotate only `<site>-tunnel` into a protected mode-0600 file
   without printing it; replicas may stay connected, but the old token cannot
   reconnect them.
2. Create the `cloudflare-public/<site>-tunnel-token` Secret directly on the
   cluster from that file. The token never enters the repository in any
   encoding, the release Kustomization stays at its exact two resources, and
   the only committed half is that connector's own non-secret `tokenRevision`.
3. Render, policy-check, and secret-scan the exact diff. After merge, watch the
   `maxUnavailable=0` rollout and verify one healthy new-token `<site>`
   connector plus public, terminal-404, and origin-denial tests.
4. Prove the peer untouched: its Secret's `resourceVersion` and
   `creationTimestamp` still equal step 1's, its connector still healthy.
5. Confirm no old-token `<site>` connector remains, then delete the protected
   old-token file. Never restore it: preserve admin recovery, stop that one
   site's rollout, and issue a different new token through another rotation.

Compromise of one `<site>` token: do step 1, then force-disconnect that one
Tunnel's connections with the dashboard control or a short-lived API token
holding exactly the connector-write permission —
`DELETE /accounts/<ACCOUNT_ID>/cfd_tunnel/<TUNNEL_ID>/connections`, the UUID
being `<site>-tunnel`'s own. Never put either bearer in the URL or command
line. That one site takes downtime because every old-token connector, a
malicious one included, otherwise stays active; the peer keeps serving. Then do
steps 2 to 5, revoke the API token against non-secret revocation evidence, and
never restore the compromised token.

## Admin connector — routine rotation

1. Preserve physical/LAN recovery and at least two working sessions. Have the
   owner rotate only `pi-admin` and capture the new token in a protected file
   without printing it.
2. Stop: current `--apply` is closed. Implement and independently review the
   root-owned reviewed-blob launcher/extraction transaction described above;
   otherwise do not replace the credential or restart `pi-admin`.
3. After that missing control is implemented, atomically replace only the
   root-owned systemd credential, restart `pi-admin`, require the exact-main
   active-credential equality/redaction canary, and run WARP-on, WARP-off,
   unauthorized identity/device, and control-plane-stopped tests. Public
   connector health must remain unchanged.
4. Delete the protected old-token file after the new connector is healthy. If
   the new credential fails, stop the unit and recover over physical/LAN access;
   correct the new credential or perform another forward rotation. The old token
   cannot reconnect after rotation and is not a rollback path.

## Admin connector — suspected or confirmed compromise

1. Retain physical/LAN recovery, rotate only `pi-admin`, and immediately
   force-disconnect all of its existing connections using the same protected
   dashboard/API procedure. Accept loss of remote administration during repair.
2. The current apply path is closed until the root-owned reviewed-blob launcher
   is implemented. If compromise occurs before then, stop the unit and use
   physical/LAN recovery; do not bypass that control to regain remote access.
3. Once that transaction exists, atomically install the new root-owned
   credential, restart `pi-admin`, and run every WARP and
   control-plane-stopped test before relying on it.
4. Revoke the short-lived API token, remove protected copies of the compromised
   Tunnel token, and prove both public connectors are unchanged. Never restore
   a compromised token.

Revalidate the current behavior immediately before live rotation:

- <https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/>
