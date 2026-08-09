# Host-level `pi-admin` connector — Draft / uninstalled

The unit is independent of Kubernetes and accepts only a remotely managed tunnel token
through a root-owned systemd credential file. It contains no account API token,
`cert.pem`, Global API key, public hostname, or DNS record.

Before installation, verify the exact pinned cloudflared binary/checksum and its
`--token-file` behavior, create a locked `cloudflared` system user, confirm LAN/
physical recovery, and review existing firewall/VPN policy. Install the token
without printing it, mode 0600 root-owned. Tail logs only after confirming token
redaction. Start the service and prove it survives kubelet/containerd and the
control plane stopping and restarting.

`install-host-binary.sh --check` verifies a locally staged ARM64 binary against
the fail-closed pins in `versions.env`; its separately acknowledged apply mode
installs only that binary and backs up an existing one. It does not download,
enable a unit, create a user, write a token, or touch networking.

Do not harden SSH or change firewall rules until external WARP SSH/kubectl works,
WARP-off/unauthorized tests fail, and a second LAN session remains open. The
Gateway L4 block is not a substitute for a host firewall and does not prove ICMP
denial. Token rotation changes only `pi-admin`; never rotate the public tunnel in
the same operation.

The initial SSH design retains self-managed host-trusted keys over the private
WARP-to-Tunnel path. Do not add a public SSH hostname or make sshd trust a
provider-managed SSH CA without a separate decision. `cloudflared` proxies
client-initiated access; host-initiated DNS, updates, Git/registry access, and
other egress continue to use the host routing table. Existing VPN/WireGuard and
kill-switch behavior therefore remains an independent control. Route the
connector through that reviewed privacy boundary and prefer loss of remote
availability to an unreviewed direct-WAN bypass; retain physical/LAN recovery.
