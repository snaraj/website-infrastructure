# ADR 0007: Separate administration and public Tunnels

- Status: Accepted, Cloudflare entitlement audit pending
- Date: 2026-08-08

## Decision

`pi-admin` runs as a host-level service independent of Kubernetes, has no public
hostname/DNS, and advertises exactly the Pi's private `/32` to enrolled WARP
devices. Gateway policy allows only approved identity/device traffic to TCP 22
and 6443 and blocks all other Pi traffic.

`pi-websites` runs inside Kubernetes, owns public website hostnames, has no private
route, and can reach only approved website Services. Tokens are distinct and
rotated independently.
