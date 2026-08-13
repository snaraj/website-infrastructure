# Cloudflare edge HTTPS and TLS hardening — Draft / unverified

This is the future owner-run transaction for `naranjo.online` and
`lidersea.com`. It does not report that either setting was changed. Repository
authoring, a green pull request, an OpenTofu validation, or a policy-fixture
PASS is not live evidence and grants no Cloudflare authority.

Current `main` already declares the desired values in the two independent site
roots: Always Use HTTPS is `on` and Minimum TLS Version is `1.2`. This runbook
makes the transition, provider readback, hostile-plan boundary, rollback, and
public acceptance evidence load-bearing. It never adds a second state owner.

## Authority and hard stops

The live transaction is `NO-GO` while
`docs/runbooks/cloudflare-token-receipt.md` says the trusted reviewed-blob
launcher and strict current-phase token-preflight authorization record are not
implemented. Do not substitute a mutable checkout, ambient token, dashboard
toggle, direct API request, unreviewed provider process, or an offline PASS.

This procedure does not authorize or require a DNS-record change, Tunnel or
connector change, provider-identity change, paid feature, Kubernetes action,
host action, route action, secret read, or recovery-custody action. A plan that
contains one is not this transaction. Stop before apply.

The transaction also stops unless all of these are true:

1. The exact repository commit, site-root state, provider lock, saved plan,
   protected workspace, fresh read-only audit, JIT token, source restriction,
   expiry, revocation, and post-audit satisfy
   `docs/runbooks/cloudflare-state-custody.md`,
   `docs/runbooks/cloudflare-website-adoption.md`, and
   `docs/runbooks/cloudflare-token-receipt.md`.
2. OpenTofu is exactly `1.12.5` and the Cloudflare provider is exactly
   `5.22.0`, as declared and locked independently in each site root. No
   `init -upgrade`, alternate provider mirror, override file, module, data
   source, or unlocked provider is allowed.
3. The read-only audit still reports both zones active on the Free plan, SSL
   mode `full`, Always Use HTTPS `off`, Minimum TLS Version `1.0`, TLS 1.3
   `on`, 0-RTT `off`, HTTP/3 `on`, and the recorded automatic HTTPS rewrite
   value unchanged. Any different prestate invalidates the reviewed forward
   transition; capture it and start a new review instead of coercing the plan.
4. Both site states already own exactly one resource for each of the six zone
   settings. The two target owners are the exact addresses below. Absence,
   duplication, a second root, or a create/import/replacement action is a stop.
5. No Tunnel rotation, connector rollout, DNS work, application deployment, or
   certificate maintenance is concurrent with this ceremony.
6. The same frozen Windows host, PowerShell `7.6.4`, .NET `10.0.10`, and exact
   `scripts/cloudflare-edge-sslstream-probe.ps1` bytes are available before and
   after each zone. A different runtime or script cannot inherit the legacy-
   capable claim from the pre-change receipt.

| Zone | Site root | Existing Minimum TLS owner | Existing HTTPS owner |
|---|---|---|---|
| `naranjo.online` | `infrastructure/cloudflare/phases/site-naranjo-online` | `cloudflare_zone_setting.naranjo_online_min_tls_version` | `cloudflare_zone_setting.naranjo_online_always_use_https` |
| `lidersea.com` | `infrastructure/cloudflare/phases/site-lidersea-com` | `cloudflare_zone_setting.lidersea_com_min_tls_version` | `cloudflare_zone_setting.lidersea_com_always_use_https` |

Keep every generated plan, state snapshot, audit, receipt, probe result, diff,
and rollback record outside Git in the protected workspace prescribed by the
custody runbooks. None is a repository artifact.

## 1. Freeze the before evidence

Do this for both zones before planning either zone.

1. Produce the bounded redacted account audit through the future trusted
   launcher. Capture the exact setting values above plus the zone status/plan,
   proxied apex binding, DNSSEC state, Tunnel name/status/configuration version,
   single-hostname ingress, terminal `http_status:404`, and connector count.
   Preserve the audit's stable pseudonyms and hashes; never copy raw IDs into
   the transaction record.
2. Run the existing token-free external probe in report-only mode:

   ```sh
   scripts/edge-probe.sh --rounds 2 --round-gap 20
   ```

   Before hardening, both zones must have only the expected redirect and
   TLS-1.0/1.1 gaps. HTTPS 200, the header contract, TLS 1.2/1.3, certificate
   headroom, DNS/DNSSEC expectations, readiness, `www` absence, site identity,
   and cross-site distinctness must pass. `SKIP`, `ERROR`, or `DIVERGENT` is a
   stop, never legacy-protocol evidence.
3. On the frozen Windows client, create one pre-change receipt per zone:

   ```powershell
   pwsh -NoLogo -NoProfile -NonInteractive -File scripts/cloudflare-edge-sslstream-probe.ps1 -Mode Prechange -Zone naranjo.online
   pwsh -NoLogo -NoProfile -NonInteractive -File scripts/cloudflare-edge-sslstream-probe.ps1 -Mode Prechange -Zone lidersea.com
   ```

   Each must end in a `pass` result. All four explicitly offered protocols
   must be `accepted` and report their exact negotiated protocol. Ordinary
   hostname/chain validation and online revocation checking remain enabled.
   HTTP must be direct 200, HTTPS must be direct 200, and the exact-three-
   script canonical body count/length/SHA-256 must match the embedded frozen
   baseline. Preserve the runtime record, script SHA-256, TLS 1.2/1.3 leaf
   certificate SHA-256 values, and result together.
4. Hash and bind all before evidence to the exact commit and protected
   transaction directory. If any expected observation is missing, stop.

## 2. Plan exactly one zone

The order is fixed: finish `naranjo.online`, including acceptance or rollback,
before planning `lidersea.com`. Never hold two approved write tokens or apply
two site roots concurrently.

For the selected root, follow the adoption and state-custody runbooks to refresh
state and produce one saved plan without applying it. The policy gate must
report exactly nine already-owned managed resources with this action set:

| Resource class | Required action |
|---|---|
| existing Minimum TLS owner | one `update`, exact `1.0` → `1.2`, or target-state `no-op` only when a separately reviewed retry already reached `1.2` |
| existing Always Use HTTPS owner | one `update`, exact `off` → `on`, or target-state `no-op` only when a separately reviewed retry already reached `on` |
| Tunnel, Tunnel configuration, proxied apex DNS | three `no-op` actions |
| TLS 1.3, 0-RTT, HTTP/3, SSL mode | four `no-op` actions at `on`, `off`, `on`, `full` respectively |

For the frozen starting state, the saved plan therefore has exactly two
updates and seven no-ops. It has no create, delete, replacement, import, data
source, module, provider override, unknown critical field, extra resource, or
paid capability. The configuration dependency makes the provider finish and
read back Minimum TLS Version before Always Use HTTPS can run.

Reject and destroy the saved plan if its derived prestate differs from the
read-only audit, if either target has the wrong before value, if any unrelated
resource updates, or if either setting has more than one owner. Do not use
`-target`, hand-edit plan JSON, refresh around the gate, or re-plan after
approval. Apply only the exact hash-bound saved plan through the future trusted
launcher.

## 3. Apply, reread, and accept that same zone

1. The owner applies the exact approved saved plan through the future trusted
   launcher and completes its JIT-token revocation/rejection receipt. No agent
   executes this step. A lifecycle postcondition failure is an apply failure,
   even if the dashboard appears correct.
2. With a separate read-only credential, immediately reread both exact target
   settings. Require `min_tls_version=1.2` and `always_use_https=on`.
3. Produce a fresh normal plan for the same root through the same custody path.
   It must refresh remote state and exit with no changes across all nine
   resources. This is the provider-side readback proof; do not treat the
   configured literals alone as evidence.
4. Run the fixed SslStream client for only the selected zone with
   `-Mode Postchange`. Require the `PowerShell`, `Framework`, `OS`, and
   `ScriptSha256` runtime fields to equal that zone's pre-change receipt
   exactly; the `Mode` field must be the expected `Prechange` → `Postchange`
   difference. Require TLS 1.0 and 1.1
   `rejected`, TLS 1.2 and 1.3 `accepted` with the exact negotiated values,
   direct HTTPS 200, both HTTP requests redirected in one edge response to the
   exact HTTPS path/query, and the same canonical body length/SHA-256. Require
   the normally validated TLS 1.2/1.3 certificate SHA-256 to match the before
   receipt; an intervening legitimate rotation still makes continuity
   unproved and stops this transaction for review.
5. Run the independent public probe for only the selected zone:

   ```sh
   scripts/edge-probe.sh --zone naranjo.online --enforce --rounds 2
   ```

   Substitute `lidersea.com` only during its later turn. Exit zero with no
   gap, skip, error, or divergence is required. Root and path/query redirects,
   HTTPS/header/HSTS behaviour, TLS floor, TLS 1.2/1.3, 0-RTT, readiness,
   certificate headroom, DNS/DNSSEC expectation, `www` absence, and site
   identity must all pass.
6. Produce the post-change redacted account audit. Compare every non-target
   field to the before audit. The plan/status, SSL mode, automatic rewrite,
   TLS 1.3, 0-RTT, HTTP/3, DNSSEC, exact single proxied apex binding, Tunnel
   pseudonym/status/configuration version/ingress/terminal rule, and connector
   count must be unchanged. Only the two selected setting values may differ.
   Also require the peer zone's complete redacted slice to be unchanged.
7. Record acceptance only after behaviour, provider refresh, independent
   setting reread, certificate/body continuity, DNS/Tunnel continuity, and
   token revocation all agree. Then—and only then—repeat sections 2 and 3 for
   `lidersea.com`.

## 4. Roll back the selected zone on any failure

Never begin the peer zone after a failed apply, postcondition, readback, probe,
diff, or receipt. Preserve the failed evidence and revoke any possibly live
write token first.

The committed desired state remains the secure target, so do not manufacture a
second OpenTofu owner, edit state, use an override file, weaken the policy, or
commit the known-worse values. Emergency restoration is a documented
break-glass exception performed by the owner for this one zone only:

1. From the protected pre-change audit, recover the exact captured setting
   values. This reviewed transaction permits restoration only to
   `always_use_https=off` and `min_tls_version=1.0`; if the capture says
   anything else, stop and obtain a new rollback review.
2. In the selected zone only, restore Always Use HTTPS first when reachability
   or a redirect loop is the symptom, then restore Minimum TLS Version. Change
   no other control. Record the break-glass action and the separately read-back
   setting values; never use a direct API command or expose a token to the
   shell.
3. Reread both settings with the independent read-only audit and require the
   captured values. Rerun the SslStream client in `Prechange` mode and the
   external probe in report-only mode. All four protocols must again negotiate,
   HTTP/HTTPS canonical bodies must agree, the original expected gaps must
   return, and HTTPS/certificate/DNS/Tunnel/peer-zone evidence must equal the
   before record.
4. Refresh through the existing site root and create—but do not apply—a new
   forward plan. It must again contain only the exact two reviewed forward
   updates and seven no-ops. That proves the one managed state owner observed
   the restoration and keeps the next retry explicit.

Rollback is incomplete until exact setting readback and every continuity check
passes. It restores a known-worse security posture, so open an incident record,
leave the peer zone untouched, and schedule a newly reviewed retry.

## 5. Repository and CI acceptance

These checks are offline and do not substitute for section 3:

```text
pwsh -NoLogo -NoProfile -NonInteractive -File scripts/cloudflare-edge-sslstream-probe.ps1 -SelfTest
make check-fast
make check
make coverage
make pre-push-security
```

The policy matrix must reject duplicate setting owners, wrong captured before
values, a Tunnel-configuration update, and any non-target setting update. The
source contract must prove exactly one setting owner per site root and exactly
two site-owned owners repository-wide for each target setting. CI stays
credential-free: no workflow receives Cloudflare state or a token, the existing
30-minute job timeout remains, pull-request concurrency still cancels stale
runs, provider/tool pins remain exact, and the repository secret/scanner gates
cover the new script, policy, fixtures, tests, and runbook.

While infrastructure-governance PR #117 is unmerged, this work remains Draft:
no `VERSION` edit, no `requires-review`, and no author-complete claim. After the
owner merges #117, integrate current `main` append-only, take the next
sequential platform patch, rerun the exact local gates and CI, and obtain fresh
Ultra and Main Worker gates before changing author status.

## Official semantics used by this contract

- [Cloudflare Always Use HTTPS](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/)
  documents the edge redirect and Free-plan availability.
- [Cloudflare Minimum TLS Version](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/)
  documents the zone floor and rejection of older client versions.
- [Cloudflare provider `cloudflare_zone_setting`](https://registry.terraform.io/providers/cloudflare/cloudflare/5.22.0/docs/resources/zone_setting)
  is the pinned managed resource used by the two site roots.
- [OpenTofu lifecycle checks](https://opentofu.org/docs/language/meta-arguments/lifecycle/)
  define the resource postconditions used for provider readback.
- [Microsoft `EnabledSslProtocols`](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslclientauthenticationoptions.enabledsslprotocols?view=net-10.0)
  and [`SslStream.SslProtocol`](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream.sslprotocol?view=net-10.0)
  define the explicitly offered and actually negotiated protocol evidence.
