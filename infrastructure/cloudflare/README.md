# Cloudflare OpenTofu — Draft / disabled / unapplied

This configuration pins OpenTofu `1.12.5` and Cloudflare provider `5.22.0` from
current official schemas verified on 2026-08-08. It defaults to zero resources;
the committed `enable_cloudflare_resources` default remains false. Keep every
idle operator configuration false through read-only discovery and Free
entitlement checks. Because the import addresses are count-indexed, set the
flag true only in an ignored, protected local variable file during each
explicitly approved import/refresh/plan window described below, then return it
to false when that window closes. A true local override is never permission to
apply.

## Managed scope

Exactly eight instances are allowed:

- two remotely managed Tunnels (`pi-admin`, `pi-websites`);
- one exact private `/32` route owned by `pi-admin`;
- one public tunnel config with two ordered site origins and final 404;
- one proxied tunnel CNAME with `ttl = 1` in each public zone;
- one identity/device/port-specific Gateway allow and one later final block.

The one public Tunnel serves exactly these ordered routes:

1. `naranjo.online` to
   `http://naranjo-online.naranjo-online.svc.cluster.local:8080`;
2. `lidersea.com` to
   `http://lidersea-com.lidersea-com.svc.cluster.local:8080`;
3. an unqualified final `http_status:404` catch-all.

Every account-scoped resource resolves only through
`var.cloudflare_account_id`. The `naranjo.online` and `lidersea.com` DNS
records resolve only through `var.cloudflare_naranjo_online_zone_id` and
`var.cloudflare_lidersea_com_zone_id`, respectively. Those three opaque IDs
must be distinct. Both CNAMEs reference the exact same `pi-websites` Tunnel;
there is no second public Tunnel. The plan policy rejects missing, extra,
duplicate, swapped, cross-wired, literal, unknown, malformed, or wrong-account
targets.

No zone, plan, subscription, Registrar, Worker, storage, AI, media, paid
certificate/security, usage-based, or trial resource exists. `pi-admin` has no
public config or DNS. Tunnel runtime tokens are retrieved out of band and never
through a provider data source/state.

## Subscription boundary for this account

The account contract is exactly two active domain zones on the **Free** website
plan. Registrar renewal for those two domains is an accepted, separately
classified ownership cost; it does not authorize infrastructure spend. Pro is
the known next website tier and is explicitly forbidden by this policy. The
Zero Trust account must independently remain on its Free tier and within its
current user entitlement. No limit exhaustion may trigger a paid fallback:
capacity beyond either Free tier is a `NO-GO` and requires a new decision.
As observed on 2026-08-08, Pro lists at $20 per domain/month on annual billing or
$25 month-to-month: two Pro zones would therefore be $40 or $50 monthly before
tax. Those amounts describe the forbidden boundary only; prices must be checked
again from Cloudflare before any future plan decision.

## Public-content boundary

The two ordinary sites remain technically in scope only after the current
account, named-zone, subscription, and Zero Trust Free-entitlement audit passes.
Cloudflare cache is optional acceleration, not origin capacity or availability:
standard cache is data-center-local, uses LRU eviction, and does not guarantee
retention for the configured TTL.

Large-media delivery is a fail-closed **NO-GO** on this Free-plan Tunnel design.
Cloudflare's current self-serve Application Services terms require Free, Pro,
and Business customers to use an appropriate paid service for video and other
large files delivered through the CDN, without publishing a safe file-size or
traffic threshold. Free, Pro, and Business also have a 512 MB maximum cacheable
file size; an oversized response bypasses cache and can repeatedly reach the
Pi. Byte ranges, `Cache-Control: no-store`, cache bypass, or object splitting do
not create contractual permission and must not be used to evade a limit. Keep
video and deliberate large-download routes disabled. Any future media feature
requires a new reviewed architecture and an authorized service, which conflicts
with the present zero-spend decision.

## Credential and state boundary

Use `CLOUDFLARE_API_TOKEN` only in a trusted local environment. Maintain two
different tokens; never add the audit permissions to the apply token.

The short-lived apply token is scoped to the one exact account and both exact
managed zones with:

- Account: Cloudflare One Connector cloudflared Write, Cloudflare One Networks
  Write, and Zero Trust Write;
- Zone: DNS Write;
- only matching Read permissions if the current token UI/provider requires them.

The read-only audit token is scoped to the one exact account. Set
`CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_NARANJO_ONLINE_ZONE_ID`, and
`CLOUDFLARE_LIDERSEA_COM_ZONE_ID` locally when running the audit; the script
proves each ID belongs to its exact named zone and that both zones belong to the
same account without printing any ID. Its Zone Read and
DNS Read scopes must cover **all zones in that account**, not only the two
expected zones; otherwise the exact-two count is false evidence. It has:

- Account: Billing Read, Cloudflare One Connector cloudflared Read, Cloudflare
  One Networks Read, Zero Trust Read, Access: Apps and Policies Read, and
  Access: Audit Logs Read;
- Zone: Zone Read and DNS Read for all zones in that exact account.

Set explicit token expiration and an operator egress-IP condition where stable.
Use the apply token for one reviewed plan/apply window, revoke it immediately
afterward, and rotate the audit token at least every 30 days. Record only token
IDs, permission names, scopes, conditions, issue/expiry times, and revocation
evidence—never token values.

Never grant Billing Write, Seats Write, Registrar, zone/plan/subscription write,
Workers, Load Balancing, certificates, or unrelated account settings. Use a
separate read-only audit token for `scripts/cloudflare-audit.sh`. The audit
token intentionally does not have Account Settings or Account API Tokens Read;
account membership, MFA, and token inventories remain explicit dashboard checks.

OpenTofu state and plans are sensitive (identity, topology, IDs, and possibly
provider values). Keep them encrypted outside Git. The checked-in provider lock
file was generated with pinned OpenTofu from the signed Cloudflare provider;
review changes to it, and never commit `.terraform/`, state, variables, or
plans.

## Exit-gated workflow

1. Run the read-only audit with the intended account and both named zone IDs,
   record its labelled `target_binding_sha256`, and complete the dashboard
   checklist. Any missing, duplicate, swapped, or mismatched target;
   unavailable/unknown evidence; non-Free plan; over-entitlement seat count;
   trial; or nonzero/unknown price is `NO-GO`.
2. Resolve variables in ignored `terraform.tfvars`, leaving
   `enable_cloudflare_resources=false` while idle. Confirm the hostname is the
   exact canonical apex for each corresponding discovered zone.
3. `tofu init -backend=false`, review the signed provider/lock, format, and
   validate without credentials.
4. At the explicit import checkpoint, temporarily set the ignored local
   `enable_cloudflare_resources=true`, import existing resources one at a time
   following `imports/README.md`, and run a refresh-only plan after each. Never
   recreate an existing zone/tunnel/rule; restore the local override to false
   when the import window closes.
5. Create an authenticated plan in protected storage with
   `enable_cloudflare_resources=true`; do not upload it.
6. Run `scripts/cloudflare-plan-gate.sh`, record the exact plan SHA-256 and safe
   resource counts, and require its `target_binding_sha256` to equal the audit
   fingerprint exactly. Repeat the read-only subscription audit immediately
   before approval.
7. Stop for explicit approval of that exact plan hash and matching target
   fingerprint. Apply manually from the saved plan only; immediately repeat the
   subscription audit and negative tests.

Budget alerts remain secondary detection. They neither cap nor authorize spend.

## Current caveats

Gateway network policy documents TCP/UDP; do not claim it blocks every protocol.
Enforce equivalent host firewall default-deny after recovery-gated review.
WARP must carry traffic (not DNS-only), proxy TCP, include the Pi `/32`, and pass
the exact posture check. Posture caching and existing sessions mean SSH keys and
host controls remain mandatory.

Official references:

- <https://registry.terraform.io/providers/cloudflare/cloudflare/5.22.0>
- <https://github.com/cloudflare/terraform-provider-cloudflare/releases/tag/v5.22.0>
- <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/>
- <https://developers.cloudflare.com/cloudflare-one/traffic-policies/network-policies/>
- <https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/limitations/>
- <https://developers.cloudflare.com/tunnel/>
- <https://developers.cloudflare.com/cache/concepts/default-cache-behavior/>
- <https://developers.cloudflare.com/cache/concepts/retention-vs-freshness/>
- <https://developers.cloudflare.com/fundamentals/reference/policies-compliances/delivering-videos-with-cloudflare/>
- <https://www.cloudflare.com/service-specific-terms-application-services/>
- <https://www.cloudflare.com/plans/>
- <https://developers.cloudflare.com/billing/understand/billing-policy/>
