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

The public `pi-websites` SOPS path is also `NO-GO`: its protected ciphertext
verifier and the Flux age-secret/live-sync entrypoints are code-blocked until
the same class of separately installed reviewed-blob launcher exists. Public
token rotation instructions below are a future acceptance contract only. Do
not generate the production age identities or Tunnel ciphertext, and do not
bypass the guards.

The admin and public Tunnel tokens are separate. Never rotate both in one
change. A remotely managed Tunnel token is a bearer credential: anyone holding
it can run a connector for that Tunnel.

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

## Public connector — routine rotation

1. Keep `pi-admin` and physical/LAN recovery working. During a reviewed window,
   have the owner rotate `pi-websites` and capture the new runtime token directly
   into a protected mode-0600 file without printing it. Existing replicas may
   remain connected, but the old token can no longer reconnect them.
2. Generate the same Kubernetes Secret name/key, encrypt with the one public age
   recipient selected by `.sops.yaml`, list `tunnel-token.sops.yaml` exactly once
   in the public release Kustomization, and update the chart's non-secret
   `tokenRevision` in one feature-branch PR. The gate accepts this as staged only
   when the file, listing, ciphertext structure, Secret identity/key, recipient,
   and revision all agree. Before the file enters the repository, run the
   protected Linux `bootstrap/flux/verify-sops-ciphertext.sh` ceremony. A PASS
   authenticates the SOPS MAC and proves the decrypted bearer matches the
   independently reviewed account and `pi-websites` Tunnel-ID digests without
   printing it; CI structural validation cannot provide that proof. Initial
   state requires the Secret both absent and
   unlisted; never commit a latent listing or split these fields across PRs.
3. Render, policy-check, and secret-scan the exact diff. After merge, watch the
   `maxUnavailable=0` rollout and verify two healthy new-token connectors plus
   public, terminal-404, and origin-denial tests.
4. Audit the connector inventory and confirm no old-token connector remains.
   Delete the protected old-token file. Do not restore it if rollout fails;
   preserve admin recovery, stop the public rollout if necessary, and issue a
   different new token through another reviewed rotation.

## Public connector — suspected or confirmed compromise

1. Preserve `pi-admin` and physical/LAN recovery, then immediately rotate only
   `pi-websites`.
2. Using the dashboard control or a short-lived API token with the exact
   connector-write permission, force-disconnect all existing connections for
   that Tunnel. The API operation is
   `DELETE /accounts/<ACCOUNT_ID>/cfd_tunnel/<TUNNEL_ID>/connections`. Never put
   either bearer value in the URL or command line. Downtime is required because
   every old-token connector, including a malicious one, can otherwise remain
   active.
3. Install the new token through the same SOPS/age, review, merge, rollout, and
   verification path above. Revoke the short-lived API token after recording
   non-secret revocation evidence.
4. Prove the public connector recovered and `pi-admin` remained unchanged.
   Never restore the compromised token or skip the force-disconnect step.

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
   Tunnel token, and prove `pi-websites` remained unchanged. Never restore a
   compromised token.

Revalidate the current behavior immediately before live rotation:

- <https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/>
