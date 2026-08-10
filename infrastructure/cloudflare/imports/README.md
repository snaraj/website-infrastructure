# Cloudflare provider v5 imports — external mutation checkpoints

Imports are authenticated state mutations. This document does not authorize
running them, and no import is part of repository-only validation. Use an
import only when read-only discovery proves the exact object already exists and
an explicit operator checkpoint approves adding it to the correct state.

The current `scripts/cloudflare-plan-gate.sh` is initial-onboarding create-only:
it requires exact `actions = ["create"]` and an absent prior object. It cannot
authorize import, refresh-only, no-op, update, reconciliation, replacement, or
rollback. Every import below remains blocked until a separate import/
reconciliation policy and gate are implemented and independently validated.

## Credential-reach warning

An exact OpenTofu import address is not an exact Cloudflare token boundary.
Account permissions used for Tunnels, Gateway policies, and private-network
routes can reach the applicable resource class across the selected account.
Zone DNS Write can reach every DNS record in its selected zone; Cloudflare does
not offer API-token scope for one record. The two DNS phases therefore use two
different one-zone tokens, but each token still has unavoidable record-wide
reach inside its zone.

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

- Initialize only one of the seven directories under
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

The public dependency is strict:

```text
public-edge imports -> revoke write token -> exact account-wide Tunnel/config audit
  -> public-dns-naranjo import -> revoke Naranjo token -> complete-zone audit
  -> public-dns-lidersea import last -> revoke write token -> complete-zone audit
```

Never import the route merely because the Tunnel exists. The audit must first
emit the admin-policies contract proving the final block and TCP 22
identity/device allow are enabled, correctly ordered, and bound to the selected
account and Pi `/32`. Never import either DNS record before the exact
`pi-websites` ingress and terminal 404 produce the public-edge contract.

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

### `public-edge`

Owning root: `infrastructure/cloudflare/phases/public-edge`

```powershell
tofu -chdir=infrastructure/cloudflare/phases/public-edge import 'cloudflare_zero_trust_tunnel_cloudflared.pi_websites' '<account_id>/<tunnel_id>'
tofu -chdir=infrastructure/cloudflare/phases/public-edge import 'cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites' '<account_id>/<tunnel_id>'
```

The future gated refresh-only plan must contain one `pi-websites` Tunnel and one
config, exactly two ordered apex-to-cluster origins, and an unqualified terminal
`http_status:404`. It must contain no DNS record or private route. Revoke and
rejection-verify the write token, then use the separate read-only token to audit
the selected account's complete Tunnel/config inventory and prove no unrelated
change before emitting the public-edge contract.

### `public-dns-naranjo`

Owning root: `infrastructure/cloudflare/phases/public-dns-naranjo`

```powershell
tofu -chdir=infrastructure/cloudflare/phases/public-dns-naranjo import 'cloudflare_dns_record.naranjo_online' '<naranjo_online_zone_id>/<dns_record_id>'
```

This JIT token has DNS Write on the `naranjo.online` zone only, which still
means every record in that zone. The exact plan permits only the proxied apex
`ttl = 1` CNAME to the audited `pi-websites` Tunnel. Stop on any A, AAAA, or
CNAME conflict. Revoke and rejection-verify this token, then audit the entire
zone with the separate read-only token before the Lidersea token can be minted.

### `public-dns-lidersea`

Owning root: `infrastructure/cloudflare/phases/public-dns-lidersea`

```powershell
tofu -chdir=infrastructure/cloudflare/phases/public-dns-lidersea import 'cloudflare_dns_record.lidersea_com' '<lidersea_com_zone_id>/<dns_record_id>'
```

This is the literal final activation. Its different JIT token has DNS Write on
the `lidersea.com` zone only, which still means every record in that zone. The
exact plan permits only the proxied apex `ttl = 1` CNAME to the audited
`pi-websites` Tunnel. Stop on a conflict or unexpected zone change, revoke and
rejection-verify the write token, audit the entire zone with the separate
read-only token, and retain the final receipt.

## Existing infrastructure only

Do not import or manage zones, plans, subscriptions, Registrar objects, API
token objects, device enrollment, WARP settings, Workers, storage, media, or
any paid feature. Do not use import to adopt an object that merely resembles
the target. Names, account/zone binding, Tunnel binding, route, policy
language, precedence, ingress order, DNS type/content/proxy/TTL, and
entitlement must all match exactly.

For provider-v4 state, stop and use the official v5 migration procedure. Do not
guess or rewrite state. A phase with no pre-existing exact object proceeds only
through a separately gated future create plan, never through a fabricated
import.
