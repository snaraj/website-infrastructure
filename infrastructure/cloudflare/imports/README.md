# Cloudflare provider v5 imports — external mutation checkpoints

Imports are authenticated state mutations. This document does not authorize
running them, and no import is part of repository-only validation. Use an
import only when read-only discovery proves the exact object already exists and
an explicit operator checkpoint approves adding it to the correct state.

The administrative imports below remain blocked: `scripts/cloudflare-plan-gate.sh`
is initial-onboarding create-only, requiring exact `actions = ["create"]` and an
absent prior object, so it cannot authorize import, refresh-only, no-op, update,
reconciliation, replacement, or rollback for those roots.

The two website roots are the adoption case and are governed by the committed
plan policy instead: `infrastructure/cloudflare/policy/cloudflare-plan.rego`
requires every website change to carry a prior object, forbids create, delete,
and replacement outright, and pins the adopted Tunnel and apex record to
`["no-op"]`. That policy is an offline review aid for the owner's own plan, not
an apply authorization, and the authenticated ceremony scripts do not yet speak
these phase names.

## Credential-reach warning

An exact OpenTofu import address is not an exact Cloudflare token boundary.
Account permissions used for Tunnels, Gateway policies, and private-network
routes can reach the applicable resource class across the selected account.
Zone DNS Write can reach every DNS record in its selected zone, and Zone
Settings Write can reach every setting in it; Cloudflare does not offer
API-token scope for one record or one setting. The two website roots therefore
use two different one-zone tokens, but each token still has unavoidable
record-wide and setting-wide reach inside its own zone.

For every import or refresh window:

- initialize only one phase root with its own protected encrypted state;
- mint one new phase-only JIT token, keep no other write token live, and never
  reuse it;
- use the minimum permission group on the one account or one zone, with a short
  explicit TTL and trusted source-IP restriction;
- authorize only the exact protected import address and a future dedicated
  import/reconciliation gate, never the token's broader technical reach;
- revoke the write token immediately afterward, prove that bearer is rejected,
  then audit the complete affected account resource class or DNS zone with the
  separate read-only audit token; and
- retain a redacted receipt with token ID—not value—phase, permissions,
  account/zone selector, source IP, issue/expiry, plan and contract hashes,
  revocation time, and revocation-verification result.

If a stable trusted source IP, protected plan/audit gate, or complete revocation
receipt is unavailable, stop. `prevent_destroy` and delete/replacement denial
remain mandatory but do not reduce token reach.

## Non-negotiable state and secret custody

- Initialize only one of the six directories under
  `infrastructure/cloudflare/phases/`.
- Give every phase its own state path on a protected encrypted volume.
- Keep the read-only audit token and both Tunnel runtime tokens separate from
  every import token.
- Put variables, state, plans, plan JSON, command transcripts containing IDs,
  and decrypted SOPS material outside Git.
- Import one object, then run a refresh-only plan and the future dedicated
  import/reconciliation gate before touching another object.
- Stop on any create, update, replacement, delete, unknown critical value,
  target mismatch, unrelated live change, or object not already verified by
  the audit.

Phase acknowledgements are lifecycle preconditions, not resource-count
switches. Supply approved phase values from protected local inputs during an
authorized window. Returning an acknowledgement to false must make planning
fail; it must never express deletion.

## Required order

The administrative dependency is strict:

```text
admin-tunnel import -> revoke write token -> exact account-wide Tunnel audit
  -> admin-policies imports -> revoke write token -> exact relevant-policy audit
  -> admin-route import (only if the exact /32 route already exists)
  -> revoke write token -> route audit
  -> independent recovery + two working SSH sessions
  -> optional admin-api import
```

The website dependency is strict and per site:

```text
site-naranjo-online: read-only adoption audit -> import 8 objects one at a time
  -> non-destructive refresh-only plan -> apply -> revoke write token
  -> complete naranjo.online zone + owning Tunnel audit
  -> site-lidersea-com (same sequence, different token, last)
```

Never import the route merely because the Tunnel exists. The audit must first
emit the admin-policies contract proving the final block and TCP 22
identity/device allow are enabled, correctly ordered, and bound to the selected
account and Pi `/32`. Never import one site's objects into the other site's
root: the objects are already distinct, and a crossed import would point one
zone's apex at the other site's Tunnel.

## Phase-owned import addresses

Run each command from the repository root only after replacing bracketed
identifiers through a protected mechanism. Avoid placing real identifiers in
interactive shell history. Addresses intentionally have no `[0]` index:
there is no global `count` gate.

### `admin-tunnel`

Owning root: `infrastructure/cloudflare/phases/admin-tunnel`

```powershell
tofu -chdir=infrastructure/cloudflare/phases/admin-tunnel import 'cloudflare_zero_trust_tunnel_cloudflared.pi_admin' '<account_id>/<tunnel_id>'
```

The refresh-only plan must contain this one Tunnel and nothing else. Revoke and
rejection-verify the account-scoped write token immediately after import. Then
use the separate read-only token to audit the selected account's complete
Tunnel inventory, prove that no unrelated Tunnel changed, emit the
tunnel-contract hash, and record the receipt before proceeding.

### `admin-policies`

Owning root: `infrastructure/cloudflare/phases/admin-policies`

```powershell
tofu -chdir=infrastructure/cloudflare/phases/admin-policies import 'cloudflare_zero_trust_gateway_policy.pi_admin_block' '<account_id>/<rule_id>'
tofu -chdir=infrastructure/cloudflare/phases/admin-policies import 'cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow' '<account_id>/<rule_id>'
```

This root requires the matching admin-tunnel contract. Import and verify the
final block before the SSH allow. The future gated refresh-only plan must show
exactly these two policies and no Tunnel or route. Revoke and rejection-verify
the write token before using the separate read-only token to audit the complete
relevant policy set, including exact TCP 22 traffic, identity, posture, session
freshness, enabled state, Pi `/32`, and lower allow precedence. Only an exact
post-revocation audit may emit the admin-policies contract.

### `admin-route`

Owning root: `infrastructure/cloudflare/phases/admin-route`

```powershell
tofu -chdir=infrastructure/cloudflare/phases/admin-route import 'cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin' '<account_id>/<route_id>'
```

This root requires the matching admin-policies contract. The imported network
must be exactly one audited RFC1918 IPv4 `/32` through the audited `pi-admin`
Tunnel. A broader prefix, different Tunnel, unrelated route change, or missing
contract is a `NO-GO`. Revoke and rejection-verify the write token first, then
audit every relevant account route with the separate read-only token.

### `admin-api`

Owning root: `infrastructure/cloudflare/phases/admin-api`

```powershell
tofu -chdir=infrastructure/cloudflare/phases/admin-api import 'cloudflare_zero_trust_gateway_policy.pi_admin_api_allow' '<account_id>/<rule_id>'
```

This phase stays default-off. Consider it only after exact route audit,
independent physical recovery, two working administrative sessions, and a
separate explicit approval. The policy must allow only TCP 6443 for the exact
identity and posture, evaluate after the SSH allow and before the final block,
and carry the matching route-contract hash. Its JIT token is new and distinct
from the earlier admin-policies token even though both require an
account-scoped policy permission.

### `site-naranjo-online`

Owning root: `infrastructure/cloudflare/phases/site-naranjo-online`

Eight objects, imported one at a time, each followed by a refresh-only plan
before the next. Replace every bracketed identifier through a protected
mechanism; no real identifier belongs in shell history or in Git.

```powershell
tofu -chdir=infrastructure/cloudflare/phases/site-naranjo-online import 'cloudflare_zero_trust_tunnel_cloudflared.naranjo_online' '<account_id>/<naranjo_online_tunnel_id>'
tofu -chdir=infrastructure/cloudflare/phases/site-naranjo-online import 'cloudflare_zero_trust_tunnel_cloudflared_config.naranjo_online' '<account_id>/<naranjo_online_tunnel_id>'
tofu -chdir=infrastructure/cloudflare/phases/site-naranjo-online import 'cloudflare_dns_record.naranjo_online_apex' '<naranjo_online_zone_id>/<apex_dns_record_id>'
tofu -chdir=infrastructure/cloudflare/phases/site-naranjo-online import 'cloudflare_zone_setting.naranjo_online_always_use_https' '<naranjo_online_zone_id>/always_use_https'
tofu -chdir=infrastructure/cloudflare/phases/site-naranjo-online import 'cloudflare_zone_setting.naranjo_online_min_tls_version' '<naranjo_online_zone_id>/min_tls_version'
tofu -chdir=infrastructure/cloudflare/phases/site-naranjo-online import 'cloudflare_zone_setting.naranjo_online_tls_1_3' '<naranjo_online_zone_id>/tls_1_3'
tofu -chdir=infrastructure/cloudflare/phases/site-naranjo-online import 'cloudflare_zone_setting.naranjo_online_zero_rtt' '<naranjo_online_zone_id>/0rtt'
tofu -chdir=infrastructure/cloudflare/phases/site-naranjo-online import 'cloudflare_zone_setting.naranjo_online_ssl' '<naranjo_online_zone_id>/ssl'
```

The Tunnel and its configuration share one import identifier: the configuration
resource is addressed by the Tunnel it configures, not by an identifier of its
own. The apex record identifier is the record's own opaque ID, read from the
zone through the read-only audit token. Each zone setting is addressed by its
Cloudflare setting name, which is the literal shown above and is not a secret.

After the eighth import the refresh-only plan must show exactly eight objects
and nothing else: the Tunnel and the apex record as no-op, the configuration as
no-op, and the five zone settings as no-op or as an update toward the exact
committed value. Any create, delete, or replacement is a hard stop — see the
runbook. Then revoke and rejection-verify the write token and use the separate
read-only token to audit the complete `naranjo.online` zone and the owning
Tunnel before the second site's token is minted.

### `site-lidersea-com`

Owning root: `infrastructure/cloudflare/phases/site-lidersea-com`

```powershell
tofu -chdir=infrastructure/cloudflare/phases/site-lidersea-com import 'cloudflare_zero_trust_tunnel_cloudflared.lidersea_com' '<account_id>/<lidersea_com_tunnel_id>'
tofu -chdir=infrastructure/cloudflare/phases/site-lidersea-com import 'cloudflare_zero_trust_tunnel_cloudflared_config.lidersea_com' '<account_id>/<lidersea_com_tunnel_id>'
tofu -chdir=infrastructure/cloudflare/phases/site-lidersea-com import 'cloudflare_dns_record.lidersea_com_apex' '<lidersea_com_zone_id>/<apex_dns_record_id>'
tofu -chdir=infrastructure/cloudflare/phases/site-lidersea-com import 'cloudflare_zone_setting.lidersea_com_always_use_https' '<lidersea_com_zone_id>/always_use_https'
tofu -chdir=infrastructure/cloudflare/phases/site-lidersea-com import 'cloudflare_zone_setting.lidersea_com_min_tls_version' '<lidersea_com_zone_id>/min_tls_version'
tofu -chdir=infrastructure/cloudflare/phases/site-lidersea-com import 'cloudflare_zone_setting.lidersea_com_tls_1_3' '<lidersea_com_zone_id>/tls_1_3'
tofu -chdir=infrastructure/cloudflare/phases/site-lidersea-com import 'cloudflare_zone_setting.lidersea_com_zero_rtt' '<lidersea_com_zone_id>/0rtt'
tofu -chdir=infrastructure/cloudflare/phases/site-lidersea-com import 'cloudflare_zone_setting.lidersea_com_ssl' '<lidersea_com_zone_id>/ssl'
```

This is the literal final activation. Its different JIT token carries DNS Write
and Zone Settings Write on the `lidersea.com` zone only — which still means
every record and every setting in that zone — plus the account connector
permission its Tunnel needs. Stop on a conflict or unexpected zone change,
revoke and rejection-verify the write token, audit the entire zone with the
separate read-only token, and retain the final receipt.

Import identifier formats are the pinned provider's own, documented at
<https://registry.terraform.io/providers/cloudflare/cloudflare/5.22.0>. Confirm
each one against that documentation immediately before the ceremony rather than
trusting this file.

## Existing infrastructure only

Do not import or manage zones, plans, subscriptions, Registrar objects, API
token objects, device enrollment, WARP settings, Workers, storage, media,
Cloudflare-managed HSTS, or any paid feature. The application owns
`Strict-Transport-Security`; adopting the zone HSTS setting would create a
second writer for one header. Do not use import to adopt an object that merely resembles
the target. Names, account/zone binding, Tunnel binding, route, policy
language, precedence, ingress order, DNS type/content/proxy/TTL, and
entitlement must all match exactly.

For provider-v4 state, stop and use the official v5 migration procedure. Do not
guess or rewrite state. A phase with no pre-existing exact object proceeds only
through a separately gated future create plan, never through a fabricated
import.
