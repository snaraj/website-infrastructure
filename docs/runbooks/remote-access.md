# Remote administration — Draft / unverified, not the decided plane

The decided admin plane is WireGuard/SSH only (PLAT-DEC-001), and
[practical-security-model.md](../security/practical-security-model.md) keeps
Cloudflare WARP in its standing REJECTED set as a launch or recovery
requirement. What remains is the staged, unapplied design of ADR 0007; the WARP
enrolment and Gateway-policy procedure is removed rather than left runnable.

## Preconditions

- Physical or trusted LAN recovery works and two SSH sessions are open.
- `scripts/discover-pi.sh --local-only` was reviewed before any external probe;
  detected pre-existing VPN/tunnel, firewall, and routing state is backed up
  and unchanged.
- Cloudflare/Zero Trust is proven Free, the seat count is within entitlement,
  the Pi `/32` avoids reserved ranges, and safe Gateway precedences are known.
- The cloudflared binary/tag/checksum and systemd unit are reviewed.

## Traffic and credential decision

The design's remote path would use the administrator's self-managed, passphrase-
protected SSH key end-to-end over an enrolled Cloudflare One client and a
private WARP-to-Tunnel route. Cloudflare Gateway narrows which identity/device
may reach TCP 22, while sshd still authenticates the key. Do not add a public
hostname or configure the host to trust a Cloudflare SSH certificate authority
in this phase. Access for Infrastructure and encrypted SSH command logging are
possible later, but they add a new CA/proxy/logging trust boundary and require
a separate privacy and recovery decision.

Cloudflare Tunnel carries client-initiated private access only. Server-
initiated traffic from the Pi follows the host routing table, so Tunnel does not
replace ProtonVPN/WireGuard, DNS leak protection, or the host kill switch. Prove
that `cloudflared` reaches Cloudflare through the selected privacy route and
that VPN loss fails closed; physical/LAN recovery is the availability fallback,
not a direct-WAN exception.

## Saturation acceptance before public media

Run these only after capacity, storage, and rollback profiles are reviewed.
Generate bounded load that cannot intentionally fill the production root disk,
and retain physical/LAN recovery throughout.

1. While website Pods consume their allowed CPU, confirm an interactive SSH
   session and Kubernetes API health check remain responsive over the admin
   path.
2. Exercise application memory limits and eviction without OOM-killing sshd,
   `pi-admin`, kubelet, or the control plane.
3. Drive the dedicated data filesystem through reviewed warning behavior and
   prove new publication stops; verify the root/control-plane filesystem and
   SSH logs retain their required headroom. Do not test by filling root.
4. Sustain bounded public transfers and prove the administration path retains
   network capacity; lower the public concurrency/bandwidth budget if it does
   not.
5. Stop Kubernetes workloads, kubelet, and containerd through the reviewed
   recovery procedure and prove host-level `pi-admin` still carries SSH. Restart
   and verify without changing public DNS or adding router forwarding.
6. Record redacted latency, pressure state, effective reservations, failure,
   recovery time, and exact tested revision. A workstation or Kind pass cannot
   substitute for this Pi evidence.

## Rollback

If SSH hardening fails, restore the timestamped drop-in backup through the old
session and validate/reload sshd, retaining LAN access. Do not add a public
hostname or router forwarding as fallback. A compromised token is rotated
forward, never restored.

Current official behavior must be revalidated before the live step:

- <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-device-client/>
- <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/cloudflared/>
- <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/>
- <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-infrastructure-access/>
