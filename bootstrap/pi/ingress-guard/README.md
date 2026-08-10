# SSH-only admin-ingress guard (PLAT-DEC-001)

Owner decision: administration of the Pi is SSH-only. From every reviewed
administrative VPN ingress interface, the guard keeps TCP 22 reachable and
terminally denies the cluster control plane — TCP 2379 and 2380 (stacked
etcd), 6443 (Kubernetes API), and 10250 (kubelet) — for new and established
flows. A compromised admin-peer credential must yield at most a key-gated SSH
attempt, never direct control-plane reachability. Nothing in this directory
contacts the Pi from CI; every file here is inert until an operator runs the
installer on the host during an authorized window.

## Exact enforced model

One nftables table `inet website_infrastructure_ingress_guard` with one base
chain `admin_ingress` (`type filter hook input priority -10; policy accept`),
containing, per reviewed interface and in this order:

| Rule | Verdict |
| --- | --- |
| `iifname <admin-vpn> tcp dport 22 counter` | `accept` (chain-local; later base chains such as the reviewed UFW policy still evaluate) |
| `iifname <admin-vpn> tcp dport 2379 counter` | `drop` (terminal across all chains) |
| `iifname <admin-vpn> tcp dport 2380 counter` | `drop` |
| `iifname <admin-vpn> tcp dport 6443 counter` | `drop` |
| `iifname <admin-vpn> tcp dport 10250 counter` | `drop` |

The `inet` family covers IPv4 and IPv6 in one table; the verifier rejects
single-family variants. Matching by ingress interface (never destination
address) means every host address a tunnel peer can route to — tunnel-local
or LAN/control-plane — is covered, while loopback, LAN, and CNI paths that
local `kubectl` and the cluster itself use are untouched. Rules are
deliberately not conntrack-gated so established flows are dropped too, and
`drop` verdicts are final across every base chain, so no other table can
resurrect a denied packet. Counters exist so the later live proof can show
this guard, not some other rule, absorbed each blocked probe.

## Fail-closed properties

- No contract, unreviewed contract, malformed contract, missing library,
  failed render, failed apply, or failed post-load verification ⇒ the loader
  exits non-zero ⇒ `kubelet.service` cannot start (drop-in `Requires=`).
- With the guard absent no control-plane listener can exist (kubelet never
  started), so cluster ports are unreachable from the VPN — closed, not open.
- The unit has no `Condition*` line: a skipped condition would still satisfy
  `Requires=`, which is the one silent-open path systemd offers. Absence of
  the contract fails the unit instead.
- Pre-existing owned-name state that is not the exact healthy model is
  `PREEXISTING_STATE`: never repaired, never deleted, always a stop.
- Rollback deletes exactly `table inet website_infrastructure_ingress_guard`
  and re-proves absence; ambiguity is fatal and mutates nothing further.
- No flag, environment variable, or config file disables the guard or any
  check; diagnostics are fixed value-free tokens.

## Files

| File | Installed as | Purpose |
| --- | --- | --- |
| `admin-ingress.env.example` | `/etc/website-infrastructure/admin-ingress.env` (from the gitignored `.local` copy) | private-input contract: reviewed admin VPN ingress interfaces |
| `load-ingress-guard.sh` | `/usr/local/sbin/website-infrastructure-ingress-guard-load` | transactional render → check → atomic apply → verify → bounded rollback |
| `verify-ingress-guard.sh` | `/usr/local/sbin/website-infrastructure-ingress-guard-verify` | read-only semantic + persistence + ordering proof (preflight hook) |
| `systemd/website-infrastructure-ingress-guard.service` | `/etc/systemd/system/…` | boot persistence, ordered `Before=network-pre.target kubelet.service` |
| `systemd/kubelet.service.d/50-website-infrastructure-ingress-guard.conf` | `/etc/systemd/system/kubelet.service.d/…` | additive `Requires=`+`After=` so kubelet cannot start unguarded |
| `install-ingress-guard.sh` | run in place with sudo | conflict-refusing installer with bounded this-run-only rollback |

The semantic engine lives in `scripts/validate_ingress_guard.py` and the
contract schema in `scripts/validate_admin_ingress_contract.py`; the
installer copies both to `/usr/local/lib/website-infrastructure/ingress-guard/`
so root units never execute from a user-owned checkout.

## Operator flow (authorized window only)

1. Copy `admin-ingress.env.example` to `admin-ingress.env.local` in this
   directory ON THE PI; declare each reviewed admin VPN ingress interface;
   set `root:root` mode `0600`; flip `ADMIN_INGRESS_REVIEWED=yes` after human
   review. The `.local` file is gitignored and layout-gated; never commit it.
2. `sudo CONFIRM_INGRESS_GUARD_INSTALL=install-reviewed-ssh-only-ingress-guard \
   ./install-ingress-guard.sh`
3. `sudo /usr/local/sbin/website-infrastructure-ingress-guard-verify`
4. Re-run reviewed discovery so `decisions.env.local` firewall fingerprints
   are regenerated AFTER guard activation (see integration note 3).

## Integration note for the platform integrator (Codex) — additive only

No Codex-owned file is edited by this change. Systemd-level enforcement
(`Requires=` drop-in) already blocks an unguarded kubelet start regardless of
script flow. Three declared integration points remain for the integrator:

1. **Init preflight** (`bootstrap/pi/preflight.sh --phase init`): add a call
   to `/usr/local/sbin/website-infrastructure-ingress-guard-verify` alongside
   the protected-host live checks, so `--check` mode reports guard health
   before any apply attempt.
2. **Immediately before kubelet starts** (`bootstrap/pi/init-control-plane.sh`
   runs `systemctl start kubelet.service` after its second
   `preflight.sh --phase init` pass): the verifier must run at that boundary,
   and again after kubeadm's listeners exist and after CNI installation.
   Exact overlap declared per the handoff: the single line starting kubelet
   is the integration point; this change does not edit that file.
3. **Fingerprint ordering**: guard activation intentionally changes the
   `nft`/`iptables-save` state that `scripts/fingerprint_pi_state.sh` hashes.
   The reviewed live-input capture that feeds `decisions.env.local`
   fingerprints must therefore occur AFTER guard activation (fresh discovery
   → review → fingerprints → init), or preflight will correctly refuse to
   proceed. Guard drift after that capture is a hard stop, never auto-repair.
4. **One-shot local files**: this lane never reads or writes
   `decisions.env.local` or `kubeadm-config.yaml.local`; the installer
   refuses to run while kubelet is active and touches no Codex `.local`
   artifact.

The live reachability proof (bounded probes over the admin tunnel) is
designed in `docs/assurance/phase-h-ssh-only-ingress-guard.md` and is triple
gated: exact `CODEX_PLATFORM_STABLE` signal, explicit owner authorization of
the exact probe list, and integrator coordination. Nothing in this
repository executes it automatically.
