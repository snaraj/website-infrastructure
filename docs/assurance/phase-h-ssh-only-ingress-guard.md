# Phase H implementation: SSH-only host-ingress guard and its gated live proof

Status: repository implementation + live-proof DESIGN. Nothing here authorizes
a live probe, firewall mutation, deployment, reboot, or Pi access. Owner (final
authority): Samuel. This lane contains tracked custody, offline installation,
running-cluster retrofit, recovery, verification, and tests only.

## The decision this implements

PLAT-DEC-001 is decided: the administration plane is **SSH-only**. The admin
laptop reaches the Pi through the hardened WireGuard path and TCP 22;
`kubectl` runs locally on the Pi; reviewed administrative VPN ingress must
never reach TCP 2379, 2380, 6443, or 10250. Control-plane initialization
stays blocked until a persistent fail-closed host-ingress guard is installed
and proven, because kubeadm's API server, stacked etcd, and kubelet listeners
bind broadly, Kubernetes NetworkPolicy is not a host-firewall substitute, and
firewall fingerprint equality is not semantic proof of unreachability.

Components delivered offline (see `bootstrap/pi/ingress-guard/README.md` for
the exact model): private-input contract
(`scripts/validate_admin_ingress_contract.py`), semantic verifier and
renderer (`scripts/validate_ingress_guard.py`), transactional loader,
root-owned held-inode custody, crash journal/recovery, a distinct
running-cluster retrofit, read-only verify wrapper, boot-persistent unit ordered
`Before=network-pre.target kubelet.service`, and the additive kubelet
`Requires=` drop-in that makes an unguarded kubelet start unrepresentable at
the service-manager level.

## Design decisions and rejected alternatives

1. **Dedicated nftables owned table, not UFW rule adoption.** Existing
   UFW/iptables state could only be "adopted" by proving ownership,
   persistence, ordering, and reboot behavior of rules another tool believes
   it owns; UFW rewrites its chains wholesale on reload, which breaks the
   exact-owned-identity and no-broad-replacement requirements. A dedicated
   `inet website_infrastructure_ingress_guard` table is additive, survives
   UFW reloads, and is provable from the structured ruleset. Fingerprint
   equality alone was rejected as non-semantic.
2. **Separate private schema, not protected-host reuse** (handoff challenge
   point, answered). `PROTECTED_SYSTEMD_UNIT`/archive keys attest service and
   storage protection during bootstrap; their semantics are not "network
   ingress plane", so overloading them would prove the wrong property.
   `ADMIN_INGRESS_REVIEWED` + repeated `ADMIN_INGRESS_INTERFACE` is a
   deliberate minimal new schema stored only in the Pi's root-owned mode-0700
   input directory; no private value or private-content hash enters a checkout,
   receipt, CI log, issue, or PR.
3. **`policy accept` chain with terminal per-port drops, not `policy drop`.**
   The guard must not take over unrelated admin-plane traffic decisions
   (handoff: no change to routing, LAN, egress, CNI, or unrelated traffic).
   Deny-by-default for the host remains the reviewed firewall baseline's
   job; nftables `drop` is final across all base chains, so the guard's
   denials cannot be resurrected by any other table's accept, while its
   chain-local `dport 22 accept` cannot bypass the baseline (accept only
   ends evaluation of the guard's own chain).
4. **Ingress-interface match (`iifname`), not destination-address match.** A
   tunnel peer may route to the tunnel-local address or the LAN/control-plane
   address; matching the ingress interface covers both without recording any
   address, and leaves loopback/LAN/CNI paths untouched.
5. **Five explicit rules per interface, not an anonymous port set.** The
   verifier's closed grammar refuses every set/map/verdict-map indirection;
   explicit rules keep the proof a literal sequence equality and give each
   port its own live counter.
6. **Priority −10 in the filter band.** Deterministically ahead of
   conventional filter chains for counter attribution; correctness does not
   depend on winning a priority race because drops are terminal anyway.

## Transaction and rollback model

The public artifact inventory is transferred from no-follow held descriptors
into root-owned custody and bound to an operator-attested protected-main
revision plus the exact manifest and fixed-launcher hashes before any artifact
entrypoint executes. The fixed launcher reopens the selected entrypoint and
library with `O_NOFOLLOW`, hashes them, and executes write-sealed memfd snapshots;
no checkout or custody pathname byte is parsed first. Private input starts in a
separate root-owned directory. Neither installer reopens a reviewed checkout
path or mutates the metadata of a pre-existing directory. A custody commit
interrupted before its receipt is reconciled only by revalidating the complete
root-owned tree; it never falls back to the mutable source. Before host
mutation, the custodied verifier re-runs the closed artifact, unit-sandbox, and
drop-in contract against those same manifest-bound bytes.

Loader (`website-infrastructure-ingress-guard.service` → `…-load`): validate
contract → capture `nft -j` → require owned identity ABSENT (a same-named decoy
is `PREEXISTING_STATE`; an exact healthy model is boot-idempotent) → render →
`nft -c` → durably record `apply-intent` → single atomic `nft -f` → arm
in-memory rollback → durably record `applied` → re-capture → semantic verify →
durable `commit-intent` → immutable receipt → committed journal. Capture
failure after apply is inside the
armed rollback window. A normal failure deletes exactly the owned table and
re-proves absence; a kill/power loss is classified from the durable absent
prestate on the next run. Foreign or unclassifiable state is never deleted.

The offline installer still refuses an active kubelet. Its post-start verifier
failure, daemon-reload failure, signals, and interruption all re-enter the same
exact-prestate recovery. The distinct retrofit requires active kubelet and a
boot/cluster/prestate/recovery attestation. It proves the guard before adding
the drop-in, proves the effective dependency before one controlled kubelet
restart, and records `awaiting-reboot`. Repository code never reboots the host.
After a separately authorized reboot, a new-boot proof closes the transaction.
Closure must match the activation's source/manifest/cluster bindings and first
validate the durable pending receipt; it preserves that receipt and writes a
separate result-specific final receipt. Receipt or binding replay cannot close
a different attempt. Activation, restart, closure, and rollback also require
API readiness, all nodes Ready, Calico, the applicable three Flux controllers,
the Tunnel pair, and each present site workload to retain the exact closed
health scope observed before mutation. The original attestation bytes remain
unchanged across the reboot; closure proves the current boot differs.
If recovery finds kubelet inactive, it restores kubelet while the guard remains
active before it may remove the guard. No path restarts NetworkManager,
WireGuard, sshd, UFW, or containerd; root SSH is refused.

## Boot-order proof

Static: the tracked unit pins `Before=network-pre.target kubelet.service`,
`WantedBy=multi-user.target`, no `Condition*` (a skipped condition would
still satisfy `Requires=`); the tracked drop-in pins
`Requires=`+`After=website-infrastructure-ingress-guard.service`;
`validate_ingress_guard.py repo` and the unit suite enforce both. Live: the
verify wrapper proves `is-enabled`, `ActiveState=active`, and that kubelet's
effective `After=` and `Requires=` contain the guard unit before init may
start kubelet. Retrofit success is not emitted until the same proof succeeds on
a different boot; counter/reachability attribution remains item L3 below.
The active-cluster prestate also requires the exact owned unit/drop-in files,
unit identity, and effective kubelet dependency to be absent before the first
journaled mutation.

## Semantic verifier grammar (closed)

Input is `nft -j list ruleset` JSON (schema version 1) normalized against one
expected model; text substring matching is never used. Allowed object keys:
table `{family,name,handle}`, chain
`{family,table,name,handle,type,hook,prio,policy}`, rule
`{family,table,chain,handle,expr}`; rule expressions exactly
`[iifname ==, tcp dport ==, counter, accept|drop]`. Everything else —
inversions, sets, ranges, prefixes, wildcards, verdict maps, jumps, foreign
objects in the owned table, same-named decoy chains, duplicate tables,
single-family variants, unknown keys, boolean/null encodings — is a fixed
failure token. Diagnostics are value-free by construction
(`TOKENS`/token constants in the two validators are the complete
vocabulary); no interface name, count, address, rule text, hash of a private
value, or raw command output is ever emitted.

## Trust-boundary update

`docs/architecture/trust-boundaries.md` now records: admin laptop may
initiate TCP 22 only, and is explicitly denied 6443/2379/2380/10250; direct
API exposure to the admin plane is no longer an allowed boundary. The
attack-surface manifest already encodes `admin-peer → kubernetes-api =
denied` (PLAT-EXP-007); this phase turns it from expectation into enforced,
verifiable host state.

## Gated live proof (design only — independently gated, never automatic)

Live execution requires ALL of the following, independently:

1. the exact five-line `CODEX_PLATFORM_STABLE` signal (sanitized form per the
   assurance charter);
2. Samuel's direct authorization of the exact probe list below (verbatim);
3. explicit Codex/Fable coordination confirming no overlapping Pi mutation
   window;
4. two retained working sessions and a fresh-login canary;
5. separately tested physical/LAN recovery;
6. exact protected-main, custody-manifest, current-boot, and cluster-CA
   bindings in the root-private attestation; and
7. a separately reviewed mutation authorization for the exact phase. A read,
   merge, prior authorization, or pending receipt does not satisfy it.

Probe list (bounded, non-destructive, rate-limited ≤1 attempt/second,
timeout ≤5 s each, no credential guessing, no scanning beyond the owner's
own host):

- L1 fresh independent SSH over the admin WireGuard path succeeds on TCP 22
  (also proving the guard did not lock the operator out).
- L2 from EVERY reviewed admin ingress plane, bounded TCP connects to 2379,
  2380, 6443, 10250 fail AFTER the listeners exist — against both the
  tunnel-reachable host address and the private/LAN control-plane address.
- L3 guard rule counters increased by exactly the probe count (proving THIS
  guard absorbed them); repeated after a full reboot.
- L4 `…-verify` passes immediately before init, after kubeadm listeners
  exist, and after CNI installation.
- L5 Proton egress, LAN SSH, cloudflared publication, and local kubectl
  remain functional (no unrelated-traffic regression).
- L6 negative control: the same bounded probes from the LAN plane still
  reach 6443 per the cluster's intended local topology, proving the guard is
  interface-scoped, not host-wide.

Evidence rules: PASS/FAIL categories and counter deltas only; no address,
interface name, or route in any artifact. Any failure stops for review and
never mutates firewall state. Nothing in this repository can execute this
section automatically; there is no harness entry point, timer, or workflow
for it by construction.

## Owner decisions requested (carried from the integrator handoff)

The guard is transport-independent, but the surrounding authentication
design needs Samuel's answers before finalization: (1) which laptop/mobile
operating systems must administer the Pi; (2) whether two hardware security
keys are owned/acceptable; (3) laptop-only or phone/tablet access too;
(4) whether the router already exposes a WireGuard UDP endpoint and how its
address is discovered while traveling; (5) whether LAN/physical recovery is
confirmed available if every remote credential is revoked; (6) whether SSH
port forwarding is needed for any local-only workflow or stays disabled;
(7) desired session lifetime and revocation aggressiveness; (8) whether a
second emergency operator is ever required. A threat-model-based
recommendation (hardware-backed FIDO2 SSH key preferred, simpler fallback
documented, no CA without a concrete recovery story) will follow the
answers; ProtonVPN remains egress-only and is never the admin identity
mechanism.

## Declared gaps (honest limits of the offline proof)

- Kernel-level packet behavior, reboot persistence, sandbox viability of the
  hardened unit, and counter attribution are proven only by the gated live
  items above. Offline proof covers manifest closure, held-inode copy logic,
   state/receipt schemas, model grammar, ordering, and artifacts. A hermetic
   Linux namespace fixture runs the real shell across every forward phase with
   failure, TERM, and SIGKILL, plus receipt/journal splits, hostile filesystem
   states, rollback, and zero-temporary-residue proofs; it still does not claim
   those live outcomes.
- The verifier proves the guard's own model and refuses ambiguity; it does
  not audit the full reviewed firewall baseline (that remains the
  fingerprint + discovery lane's job).
- `preflight.sh`/`init-control-plane.sh` invocation of the verify wrapper is
  declared, not wired, to avoid editing integrator-owned files; until Codex
  lands it, enforcement rests on the systemd `Requires=` ordering alone
  (which already blocks an unguarded start).
- A merged retrofit procedure remains inert. Exact hashes, attestation, two
  retained sessions, physical/LAN recovery, fresh-login proof, exclusive
  mutation window, and direct owner authorization must all be refreshed before
  a live phase. A prior observation or green CI run grants none of them.

## Reconciliation hotspots

`bootstrap/pi/preflight.sh` and `bootstrap/pi/init-control-plane.sh` (verify
hook, declared above, not edited); `scripts/fingerprint_pi_state.sh`
interaction (fingerprints must be captured after guard activation);
`bootstrap/pi/systemd/kubelet.service` (never edited — drop-in only). The
four Phase E recovery/init files are untouched.
