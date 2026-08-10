# Phase H — offensive / adversarial validation (red-team the castle)

Owner-directed addition to the assurance program (2026-08-10): before any
production website holds real assets, attack the platform as an adversary
would — the cluster, the host, and above all the interfaces that face the
internet through the WireGuard admin plane and Proton egress. The goal is to
measure how well the castle is actually configured, not to demonstrate
exploits. Findings feed remediation PRs under the same discipline as every
other phase.

## Rules of engagement (binding — this is authorized testing of owner-owned infrastructure)

1. **Targets are exclusively the owner's own castle**: the Pi, its cluster,
   its interfaces, its Cloudflare zone configuration. No third-party host,
   no external service, no Cloudflare/Proton infrastructure itself, no
   network the owner does not own. No scanning of anything on the public
   internet beyond the owner's own WAN endpoint.
2. **Non-destructive only**. No denial of service, no resource exhaustion,
   no state mutation, no reboots. This is reachability and configuration
   validation, not stress or exploitation. A test that could degrade the
   live platform is redesigned or deferred, never run.
3. **No live execution until three conditions hold**: the platform is
   stable (`CODEX_PLATFORM_STABLE`), the owner has explicitly authorized the
   specific probe set, and it is coordinated with the integrator so it never
   runs during an active bootstrap/init window. Attacking the Pi is squarely
   the integrator's live-operation boundary.
4. **White-box and logged**. No detection evasion; every probe is
   pre-declared (the attack-surface manifest is the contract), bounded,
   and its evidence sanitized (no keys, IPs, routes, or peer identities in
   any artifact — finite PASS/FAIL categories and non-fingerprinting hashes
   only).
5. **Free tooling only** run from the owner's own machines: `nmap`,
   `wireguard-tools`, `kube-bench` (CIS), `kube-hunter` (read-only mode),
   `trivy` (already in use), and small purpose-built leak/reachability
   scripts. No exploit frameworks, no C2, no credential attacks — none are
   needed for configuration validation and none would be zero-cost-clean.
6. **Owner is the final authority**; the integrator coordinates on the Pi;
   nothing that touches the live host runs without the explicit go.

## Attack surface, prioritized by internet-reachability

### Surface 1 — the WireGuard admin plane (the ONLY inbound-from-internet listener)

This is the crown-jewel target: the single thing that accepts packets from
the internet. WireGuard is silent to any packet that does not complete a
valid Noise handshake, which is the first thing to verify holds true in
practice.

| Test | Expected result | Control probed | When |
| --- | --- | --- | --- |
| External port scan of the WAN endpoint (TCP + UDP, full range) | No service responds; the admin UDP port is silent to non-handshake packets; SSH(22)/API(6443)/etcd(2379)/kubelet(10250)/HTTP(80,443) all closed/filtered inbound | PLAT-EXP-001, PLAT-EXP-005 | live, **owner-scheduled** (needs the travel laptop on an external network — parked ~1 month by owner) |
| Handshake with wrong/absent key or PSK | Silent drop, no downgrade, no fingerprint leak | PLAT-EXP-005 | live + config review now |
| Peer `AllowedIPs` scope | Admin peer is scoped to the admin subnet only, never `0.0.0.0/0`; a compromised peer key cannot route arbitrary traffic | PLAT-EXP-005 | config review (Pi-local design doc) |
| What the admin peer can reach on the host | Host SSH admin only — **NOT** the cluster API/etcd/kubelet. See the admin-plane scope decision below | PLAT-EXP-007 | live canary + design |
| Reply-path exemption (FwMark + `ip rule`) | Scoped to wg-admin's own marked reply packets; cannot be abused as a general Proton bypass | PLAT-EGR-001 | config review + live leak test |
| UFW rule set | Additive-only: exactly one admin UDP port opened; LAN SSH unchanged; no inbound rule for any cluster port | PLAT-EXP-001 | config review + live |

### Surface 2 — Proton egress (leak resistance)

The origin's residential identity must never escape. Egress leaks are how it
would.

| Test | Expected result | Control | When |
| --- | --- | --- | --- |
| DNS leak | All resolution egresses through Proton (or the stub → Proton), never the ISP/router resolver | PLAT-EGR-001 | live |
| IPv6 leak | IPv6 is disabled or fully routed through Proton — no dual-stack bypass exposing the real address | PLAT-EGR-001 | live |
| Kill-switch / fail-closed | If Proton drops, egress fails closed (no traffic) rather than falling back to the ISP and exposing the origin | PLAT-EGR-001 | live, bounded (no destructive drop; simulate via interface-state read + policy inspection) |
| Egress exemption set | Only the designed exemptions (GitHub, apt, git, Cloudflare) and the reply-path exemptions (LAN SSH, wg-admin) exist; no general bypass | PLAT-EGR-001 | config review + live |

### Surface 3 — Cloudflare Tunnel / origin exposure

| Test | Expected result | Control | When |
| --- | --- | --- | --- |
| Site hostname resolution | Resolves to Cloudflare proxied IPs only; never an A/AAAA record pointing at the residential IP | PLAT-EXP-001 | live (public DNS, no origin contact) |
| Direct-to-origin connection attempt | Fails — no inbound port, no forward, nothing listening at the residential IP | PLAT-EXP-001 | live, owner-scheduled (external vantage) |
| Tunnel connector compromise blast radius | Serving the two hostnames only; signature admission + closed NetworkPolicies bound lateral damage | design + Phase C controls | design |

### Surface 4 — the cluster (assume-breach: a compromised site pod)

The realistic in-cluster adversary is a malicious or supply-chain-compromised
site image. Every path below already has a standing control (Phase C); Phase
H proves it adversarially with a canary "attacker" pod.

| Attack | Expected result | Control | When |
| --- | --- | --- | --- |
| Pod → other tenant's pod | Denied (default-deny NetworkPolicy) | PLAT-EXP-002 | live canary + kube-hunter |
| Pod → API server (6443) | Denied | PLAT-EXP-006 | live canary |
| Pod → etcd (2379) / kubelet (10250) | Denied | PLAT-EXP-006 | live canary |
| Pod → node host / escape | Blocked (restricted PSA, no privileged/hostPath/host namespaces, seccomp, dropped caps) | PLAT-EXP-003 | live canary + kube-bench |
| Deploy unsigned/mutated/privileged image | Rejected at admission | PLAT-SUP-001/002, PLAT-EXP-003 | live + Phase C fixtures |
| Pod egress (phone-home / exfil) | Denied (default-deny egress) | PLAT-EXP-002, PLAT-EGR-001 | live canary |
| Pod → admin plane / admin subnet | Isolated — a compromised workload cannot reach the WG admin interface | PLAT-EXP-007 | live canary |

### Surface 5 — the host

| Test | Expected result | Control | When |
| --- | --- | --- | --- |
| SSH posture | Key-only, no password, no root login, rate-limited | host review + live | live |
| Passwordless sudo scope | The automation's passwordless sudo is scoped/justified, not blanket root — **finding candidate** | design + live | live |
| Inactive-service surface | bitcoind inactive+disabled, electrs absent, tor/cups posture reviewed; nothing extra listening | PLAT-HOST-002 | live (sentinel already tracks the listener set) |
| CIS benchmark | kube-bench passes the applicable controls | PLAT-HOST-001 | live |

## The admin-plane scope decision (owner input requested — a real security tradeoff)

Should the WireGuard admin plane be able to reach the **cluster API (6443)**,
or only **host SSH**?

- **SSH-only (recommended, defense-in-depth):** the travel laptop reaches the
  Pi over WG, SSHes to the host, and runs `kubectl` locally on the Pi. The
  admin VPN never exposes the Kubernetes API. Smallest attack surface: a
  compromised admin peer key yields a host login attempt (still gated by SSH
  keys), not direct API access.
- **API-over-VPN (convenience):** exposes 6443 to the admin subnet so
  `kubectl` works directly from the laptop. Wider surface; a compromised peer
  key reaches the API's authn/authz boundary directly.

Recommendation: **SSH-only**, because it costs nothing in capability (kubectl
still works, one hop away) and removes an entire class of exposure. Recorded
as decision **PLAT-DEC-001** for the owner. The attack-surface manifest
encodes the SSH-only expectation until the owner rules otherwise.

## Executable artifact (now): the attack-surface manifest

`docs/assurance/attack-surface-manifest.json` is the declarative contract the
live harness asserts reality against: for each surface, the expected result
in a closed vocabulary (`no-response`, `wireguard-handshake-only`, `denied`,
`allowed-to-class`, `fail-closed`), bound to an invariant ID. It carries no
private value by construction — surfaces and endpoints are named by class and
ordinal only. `scripts/validate_attack_surface_manifest.py` (stdlib) validates
it fail-closed and cross-checks that every critical surface is covered, so the
contract cannot silently lose a probe. The live harness (post-stable,
owner-authorized) is the executor; this phase ships the contract and the
validator, matching the program's contract-now / live-later pattern.

## Timing and gating

- **Now (offline):** this design, the manifest contract + validator, and the
  interface threat model. Extends the Phase C adversarial fixtures where a
  rendered-object test can express the pivot denial.
- **Post-stable, owner-authorized, integrator-coordinated:** the live canary
  pods, kube-bench/kube-hunter (read-only), and the leak tests — non-
  destructive, bounded, never during an active bootstrap window.
- **Owner-scheduled external vantage:** the WAN port scan and direct-to-origin
  attempt need the travel laptop on an external network (the parked
  ~1-month hotspot test). Highest-value, so worth scheduling deliberately.

## Findings and decisions register

| ID | Type | Item | Disposition |
| --- | --- | --- | --- |
| PLAT-DEC-001 | decision | Admin plane: SSH-only vs API-over-VPN | owner decision; manifest encodes SSH-only pending |
| PLAT-OFF-001 | finding-candidate | Passwordless sudo scope for automation | confirm scoped/justified during live host review |
| PLAT-OFF-002 | gap | Kill-switch fail-closed behavior unproven until a bounded live leak test | post-stable, owner-authorized |
| PLAT-DEC-002 | decision | External-vantage test scheduling (hotspot) | owner-scheduled (~1 month parked) |

## Overlap declaration

Phase H's live portion targets integrator-owned live surfaces (host,
cluster, WG/Proton interfaces). No `bootstrap/pi/**` file is modified by
this phase; the live harness is a separate, owner-authorized, read-only
executor coordinated through the observations channel with a published
probe list before any run.
