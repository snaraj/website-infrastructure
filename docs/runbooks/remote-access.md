# Remote administration — Draft / unverified

## Preconditions

- Physical or trusted LAN recovery works and two SSH sessions are open.
- `scripts/discover-pi.sh` was reviewed; any detected pre-existing VPN/tunnel,
  firewall, and routing state is backed up and unchanged.
- Cloudflare/Zero Trust is proven Free, the seat count is within entitlement,
  the Pi `/32` avoids reserved ranges, and safe Gateway precedences are known.
- The cloudflared binary/tag/checksum and systemd unit are reviewed.

## Staged procedure

1. Create/import `pi-admin` with no public hostname, DNS, or tunnel config; add
   exactly the Pi private `/32` route.
2. Install its distinct token into the root-owned systemd credential source
   without printing it. Start the host service and prove it remains available
   while kubelet, containerd, and the Kubernetes control plane are stopped.
3. Enroll only the administrator device in WARP Traffic+DNS/Traffic mode, include
   the Pi `/32`, enable TCP proxying, and require exact identity, MFA, and device
   posture.
4. Apply the TCP 22/6443 allow followed by a lower-priority all-other-TCP/UDP
   block. Keep host firewall default deny because Gateway does not prove ICMP or
   all-protocol denial.
5. From an external network, prove WARP-on SSH/kubectl succeeds, WARP-off fails,
   unauthorized identity/device fails, and LAN recovery still works.
6. Only then run the recovery-gated SSH hardening script. Keep the old sessions
   open and prove a third login before logout.

## Saturation acceptance before public media

Run these only after capacity, storage, and rollback profiles are reviewed.
Generate bounded load that cannot intentionally fill the production root disk,
and retain physical/LAN recovery throughout.

1. While website Pods consume their allowed CPU, confirm an interactive SSH
   session and Kubernetes API health check remain responsive over the approved
   WARP identity/device path.
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
session and validate/reload sshd. If WARP/Tunnel fails, retain LAN access, stop
the new host service, and revert only the reviewed route/policies. Do not add a
public hostname or router forwarding as fallback. A compromised token is rotated
forward, never restored.
