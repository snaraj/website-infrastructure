# Tunnel token rotation — Draft / unverified

The admin and public tunnel tokens are separate. Never rotate both in one change.

## Public connector

1. Keep admin recovery working. Obtain a new `pi-websites` runtime token into a
   protected mode-0600 file without printing it; no account API token enters
   Kubernetes.
2. Generate the same Kubernetes Secret name/key, encrypt with the one public age
   recipient selected by `.sops.yaml`, list `tunnel-token.sops.yaml` exactly once
   in the public release Kustomization, and update the chart's non-secret
   `tokenRevision` in one feature-branch PR. The gate accepts this as staged only
   when the file, listing, ciphertext structure, Secret identity/key, recipient,
   and revision all agree. Initial state requires the Secret both absent and
   unlisted; never commit a latent listing or split these fields across PRs.
3. Render/policy/secret-scan the diff. After merge, watch maxUnavailable=0 rollout
   and verify two connectors plus public/404/origin-denial tests.
4. Revoke the old token only after both new connectors are healthy. If the old
   token is compromised, revoke first and accept downtime.

## Admin connector

Preserve LAN/physical recovery, replace only the root-owned systemd credential,
restart `pi-admin`, and run WARP on/off/unauthorized and control-plane-stopped
tests. Roll
back to the old token only when it is not compromised. Public connector health
must remain unchanged throughout.
