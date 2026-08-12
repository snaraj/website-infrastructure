# ADR 0007: Separate administration and public Tunnels

- Status: Superseded by [ADR 0015](0015-per-site-tunnels.md) for the public
  edge; the administrative-plane material below remains a staged, unapplied
  design subordinate to PLAT-DEC-001 (SSH-only admin plane)
- Date: 2026-08-08

## Decision

`pi-admin` runs as a host-level service independent of Kubernetes, has no public
hostname/DNS, and advertises exactly the Pi's private `/32` to enrolled WARP
devices. Gateway policy allows only approved identity/device traffic to TCP 22
and 6443 and blocks all other Pi traffic.

`pi-websites` runs inside Kubernetes, owns public website hostnames, has no private
route, and can reach only approved website Services. Tokens are distinct and
rotated independently.

## Supersession note (2026-08-12)

The owner selected a different live public topology: two independent
per-site Tunnels (`naranjo-online`, `lidersea-com`), one per website, with
distinct tokens, connectors, DNS targets, and blast radii. The shared
`pi-websites` Tunnel described above was never applied and is retired;
[ADR 0015](0015-per-site-tunnels.md) is the authoritative public-edge
decision. The admin/public separation principle itself — administrative
access and public traffic never share a Tunnel, token, or policy — carries
forward unchanged.
