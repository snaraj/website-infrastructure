# Runbook — adopting the two per-site Cloudflare roots

Scope: bringing the already-live `naranjo.online` and `lidersea.com` Cloudflare
objects under the two independent OpenTofu roots in
`infrastructure/cloudflare/phases/site-naranjo-online` and
`infrastructure/cloudflare/phases/site-lidersea-com`, and moving each zone to
the committed security target state.

This runbook is owner-run. No agent holds a Cloudflare credential, and nothing
in this repository performs an authenticated Cloudflare call. Read
`infrastructure/cloudflare/README.md` for the custody and token rules and
`infrastructure/cloudflare/imports/README.md` for the exact import addresses
before starting; this document is the plan-review procedure, not a substitute
for either.

## What is being adopted, and what is not

Both websites already serve traffic through their own Cloudflare Tunnel behind
their own proxied apex CNAME. Those objects, the two zones, and the Universal
SSL certificates all pre-exist. The roots are written to **adopt** them:

- every planned change must carry a prior object;
- create, delete, and replacement are refused by the committed plan policy;
- the adopted Tunnel and the adopted apex record must plan as `no-op`;
- only the Tunnel ingress configuration and the five zone settings may plan as
  an update, and only toward the exact committed value.

Not adopted, deliberately: the zones themselves, the plan/subscription, the
Registrar objects, DNSSEC, Universal SSL, Cloudflare-managed HSTS (the
application owns that header), and every paid product.

## Preconditions

1. The read-only audit token is separate from every write token and has no
   write permission.
2. A fresh read-only adoption audit has been taken for the site being worked,
   and its canonical SHA-256 is the value supplied as that root's
   `verified_<site>_adoption_audit_sha256`.
3. Exactly three Tunnels exist on the account — the administrative one and one
   per website. A fourth Tunnel is a stop.
4. Only one Cloudflare write token is live at any moment, minted just in time,
   restricted to the minimum permission group, one account plus one zone, a
   trusted source IP, and a lifetime no longer than 30 minutes.
5. `make check` is green on the commit being applied from, and the working tree
   is that exact commit.

## Order

Serial, never parallel, one site fully closed out before the next begins:

1. `site-naranjo-online` — import, plan, review, apply, revoke, re-audit.
2. `site-lidersea-com` — new token, same sequence, last.

The two roots share no state file, no variable file, no token, and no plan. A
failure in one site never touches the other; that separation is the point of
the two-root shape.

## Per-site sequence

1. Initialize only that one root, with its own protected state path passed via
   `-backend-config`, and its own `TF_DATA_DIR` under the protected volume.
   Never initialize live state beside the repository.
2. Supply the account ID, that zone's ID, and the adoption-audit hash from the
   ignored protected variable file beside that root. The tracked
   `terraform.tfvars.example` carries placeholders only.
3. Import the eight objects one at a time, in the order given in
   `imports/README.md`, running a refresh-only plan after each.
4. Produce the reviewed saved plan and walk the review checklist below.
5. Apply only that saved plan.
6. Revoke the write token immediately, prove that same bearer is now rejected
   using a separate credential, then re-audit the complete zone and the owning
   Tunnel with the read-only token.
7. Retain the redacted receipt: phase, token ID (never the value), permission
   groups, account/zone selector, source-IP restriction, issue and expiry
   times, plan hash, audit hashes, revocation time, and revocation-verification
   result.

## Plan review — what a correct plan looks like

Exactly eight resources, no more and no fewer:

| Resource | Expected action |
| --- | --- |
| the site's Tunnel | `no operation` |
| the site's Tunnel configuration | `no operation`, or an update only if live ingress differs from the committed single-origin plus terminal 404 |
| the site's apex CNAME | `no operation` |
| `always_use_https` | update to `on` (expected: the live zones do not redirect today) |
| `min_tls_version` | update to `1.2` (expected: TLS 1.0 and 1.1 are accepted today) |
| `tls_1_3` | `no operation` (expected: already on) |
| `0rtt` | `no operation` (expected: already off) |
| `ssl` | `no operation` if the zone is already `full`; an update to `full` otherwise |

The redirect gap, the TLS floor, the already-on TLS 1.3, and the already-off
0-RTT are dated external observations from a credential-free probe, not config
reads. Treat them as expectations to confirm in the plan, never as facts. The
current `ssl` mode was **not** observable externally and is genuinely unknown
until the plan prints it: read it, and if the plan proposes moving away from
`full`, stop.

## Hard stops

Abort the window, revoke the token, and record the observation rather than
improvising, if the plan shows any of:

- **any `destroy`, `replace`, or forced replacement.** A live Tunnel or apex
  record must never be deleted or recreated. `prevent_destroy` should already
  refuse it; a plan that reaches the point of proposing it means the
  configuration or the state binding is wrong, not that the object should go.
- **any `create`.** A create means the import did not happen or landed at the
  wrong address, and applying it would duplicate a live object.
- **a resource count other than eight**, an address outside the committed set,
  or a resource type outside the allowlist.
- **the other site's hostname, origin, zone, Tunnel, or variable** appearing
  anywhere in this root's plan.
- **an `A` or `AAAA` record, a wildcard hostname or record name, a private or
  WARP route, or a second public hostname** on the site's Tunnel.
- **an SSL mode other than `full`** — in particular any strict variant. The
  connector-to-origin leg is plain HTTP by accepted decision, so strict origin
  pull breaks the site instead of hardening it.
- **an unknown value on any security-critical field** at plan time.
- **any paid product, plan change, subscription mutation, or nonzero price.**

## Rollback

Rollback is a plan and apply of the previous setting values, never a delete and
never a recreate. Record the pre-change value of every setting the plan will
move before applying, so the reverse plan can be written from evidence rather
than memory. A failed or partial apply is repaired by re-planning the remaining
delta — never by removing a Tunnel or a DNS record.

Adoption itself is reversible without touching Cloudflare: `tofu state rm`
removes an object from state and leaves the live object untouched.

## Acceptance after each site

Re-run the external probes for that site only and confirm, over both HTTP and
HTTPS: the apex redirects to HTTPS with path and query preserved, TLS 1.0 and
1.1 are refused, TLS 1.2 and 1.3 still negotiate, the certificate still
verifies, `Strict-Transport-Security` is still exactly the application's value,
`/readyz` still answers, and the other site is unchanged. Only then mint the
second site's token.

## Zero spend

Every resource in these roots is a free-plan object: Tunnel, Tunnel
configuration, an authoritative DNS record, and free zone-level SSL/TLS
settings. Nothing here can bill. The committed allowlist and the merge-path
zero-spend battery both refuse any other Cloudflare resource type, and the cost
policy still pins authorized infrastructure cost at zero.

- Fable5
