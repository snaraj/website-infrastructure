# Cloudflare OpenTofu — staged, disabled, and unapplied

This directory defines six independent OpenTofu roots. It is a design and
verification artifact only: nothing here authorizes an authenticated plan,
import, apply, DNS change, or change to the Pi firewall, VPN, or SSH service.
OpenTofu is pinned to `1.12.5` and the Cloudflare provider to `5.22.0`.

Four administrative roots are create-only onboarding. The two website roots are
different in kind: their Tunnels, apex records, and zones already exist and
already serve traffic, so those roots ADOPT the live objects by import. Git is
reconciled to the live topology, never the reverse, and never by deleting or
recreating a live object.

## Phase graph

Each root owns one narrow resource graph and one independently protected state:

| Root | Exact IaC-managed scope | Activation condition |
| --- | --- | --- |
| `phases/admin-tunnel` | `pi-admin` Tunnel only | First administrative phase |
| `phases/admin-policies` | Final Pi block and TCP 22 identity/device allow only | Exact admin-tunnel and strong-posture audit contracts |
| `phases/admin-route` | One RFC1918 Pi `/32` route through `pi-admin` | Exact admin-policies audit contract |
| `phases/admin-api` | One identity/device allow for TCP 6443 | Later, separate approval after route verification |
| `phases/site-naranjo-online` | `naranjo-online` Tunnel, its single-origin configuration, the proxied `naranjo.online` apex CNAME, and that zone's five security settings | Adoption of the live naranjo.online objects; first website root |
| `phases/site-lidersea-com` | `lidersea-com` Tunnel, its single-origin configuration, the proxied `lidersea.com` apex CNAME, and that zone's five security settings | Adoption of the live lidersea.com objects; final activation |

The security dependencies are:

```text
admin-tunnel -> verified tunnel + posture contracts -> admin-policies
             -> verified block + SSH contract -> admin-route
             -> verified route + independent recovery + two working SSH sessions
             -> optional admin-api

per-site read-only adoption audit -> site-naranjo-online (import, then plan)
             -> zone audit + receipt revalidation
             -> site-lidersea-com (import, then plan; last)
```

`admin-tunnel` deliberately contains no Gateway policy or private route.
`admin-policies` deliberately contains no Tunnel or route. Its exact TCP 22
allow must have a lower Gateway precedence number than its catch-all Pi block.
The read-only audit must prove the Tunnel, both policies, their exact account
and Pi `/32` binding, their enabled state, and their precedence before
`admin-route` may advertise the `/32`. Cloudflare documents that lower policy
precedence numbers evaluate first; unmatched enrolled-device private-network
traffic otherwise requires an explicit catch-all block design.

The administrative posture contract is deliberately closed to one independently
approved `client_certificate_v2` rule. The audit requires an exact managed
certificate UUID, `check_private_key = true`, one exact Windows/macOS/Linux
platform, `${serial_number}` certificate CN binding, `clientAuth` extended-key
usage only, the same exact platform match, and five-minute evaluation and
expiration. The operator must independently review and supply the expected
canonical posture SHA-256; structural nonempty JSON is never treated as strong
posture. The policy-input contract additionally binds the exact administrator
email, posture-rule UUID and hash, session freshness, SSH/block precedence,
account, Tunnel, and Pi `/32`. Route and API plans must reproduce that full
contract, so a valid predecessor hash cannot be reused with another identity or
weaker device rule. The route post-audit also emits an API-input contract that
adds the proposed API precedence plus the exact policy- and route-contract
hashes; `admin-api` must reproduce that digest before its plan can pass.

`admin-api` is not part of initial SSH access. Its acknowledgement defaults to
false and it allows only TCP 6443, after the SSH allow and before the final
block. Both `admin-route` and `admin-api` remain unapplied unless independent
physical recovery is proven, two simultaneous retained administrative sessions
pass distinct challenges, and a separate fresh-login challenge succeeds while
they remain available. The gate validates a fresh protected attestation of
those facts; it does not make a network connection and must never be described
as proving connectivity by itself. None of these roots changes UFW, WireGuard,
WARP enrollment, Tor, `sshd`, host keys, or the operating system.

The audit closes each relevant inventory instead of proving only one matching
object. Administrative staging permits only `pi-admin`, zero Gateway policies
before `admin-policies`, then exactly the SSH allow plus unconditional final
block, and zero routes before `admin-route`, then exactly one Pi `/32`. The
website adoption audit permits exactly three Tunnels — `pi-admin`,
`naranjo-online`, and `lidersea-com` — and no fourth. Initial plan gates also
require the preflight Tunnel/Gateway-policy/route counts appropriate to the next
root. Any additional Tunnel, Gateway policy, or private route is a `NO-GO`; it
must be removed through a separate reviewed operation or explicitly
incorporated into a future closed architecture before deployment continues.

For website adoption, the audit must also reproduce the healthy `pi-admin`
Tunnel, exact posture, complete Gateway-policy, and exact private-route
contracts. The API policy may be absent with exactly two total Gateway rules or
exact with exactly three; every other state is a conflict.

Each website root owns exactly these ordered ingress rules on its own Tunnel:

1. that site's apex to that site's ClusterIP service DNS name on TCP 8080;
2. an unqualified terminal `http_status:404` catch-all.

There is no shared public Tunnel and no wildcard hostname. Each root also owns
exactly one proxied `ttl = 1` apex CNAME in its own zone, whose content is
derived from that root's own Tunnel resource attribute, so no Tunnel UUID ever
enters Git or a variable file.

Each website root additionally owns exactly five free zone-level settings that
carry the zone security target state:

| Setting | Committed value | Why |
| --- | --- | --- |
| `always_use_https` | `on` | Plain HTTP currently serves the live site; HSTS received over cleartext is ignored by browsers, so the edge redirect is the control that closes the first-visit gap |
| `min_tls_version` | `1.2` | TLS 1.0 and 1.1 are currently accepted, and the legacy handshakes are signed `ecdsa_sha1` |
| `tls_1_3` | `on` | Already on; committed so it cannot silently regress |
| `0rtt` | `off` | Already off; early data is replayable and the handshake saving does not justify it |
| `ssl` | `full` | The connector-to-origin leg is plain HTTP by accepted decision, so a strict variant would break the site rather than harden it. A strict value is a policy denial, not a judgement call |

`Strict-Transport-Security` is deliberately absent from this table: the
application owns that header and Cloudflare-managed HSTS stays off so two
writers can never publish contradictory policies.

The roots, state, and tokens remain separate. Run and audit them serially;
`site-lidersea-com` is the literal last activation. `pi-admin` never receives
public ingress or DNS, and neither website Tunnel owns a private route. One
website root never references the other site's zone, Tunnel, namespace,
hostname, or variables — the plan policy and the phase-contract validator both
reject a cross-site reference.

## Destruction-safe phase acknowledgements

Every phase acknowledgement defaults to false and is used as a lifecycle
precondition, not as `count` or `for_each`. Returning an acknowledgement to
false therefore makes planning fail; it does not turn the phase into a
destroy-all plan. Every managed Cloudflare resource has `prevent_destroy`, and
the phase plan gate must reject every delete or replacement, unexpected
address, cross-phase resource, unknown security-critical value, or
resource-count mismatch.

The two plan shapes are separate contracts and are never collapsed:

- **Administrative onboarding is create-only.** Each accepted change has exact
  action `["create"]` and no prior object.
- **Website adoption is adopt-only.** Every change must carry a prior object,
  no change may be a create, a delete, or a replacement, and the adopted Tunnel
  and apex record must plan as `["no-op"]`. Only the ingress configuration and
  the five zone settings may plan as `["update"]`, and only toward the exact
  committed value. A create in a website plan means the import did not happen
  and would duplicate a live object; a delete or replacement means an outage.

Rollback of an authenticated apply still requires a separate future gate and is
intentionally outside this one.

The plan policy also requires exactly one empty `cloudflare` provider
configuration, environment-only provider authentication, no module call, no
data source, no provisioner, and no non-managed mode. Each phase root and the
policy directory have an exact on-disk file inventory. Ignored override files,
local variable files, provider caches, and any other extra file are a `NO-GO`.

Do not combine roots, share a backend, add a global enable switch, or apply from
a directory above a phase root.

## Credential reach is broader than the IaC allowlist

The plan/state contract can name an exact Tunnel, route, policy, or DNS record;
a Cloudflare API token cannot be restricted that narrowly. Cloudflare API-token
policies select User, Account, or Zone resources:

- account permissions used for Tunnels, Gateway policies, and private-network
  routes reach the applicable resource class across the selected account, not
  one named Tunnel, rule, or route;
- Zone DNS Write can be limited to one selected zone, but it can create, read,
  update, delete, and list records across that zone; it cannot be limited to
  one apex CNAME.

This is unavoidable residual credential reach, not authorization to touch those
other objects. References to an “exact” object below describe the protected
plan and audit allowlist, never the provider token's enforcement boundary.
Cloudflare's separate Tunnel-specific runtime token is only for running its
Tunnel and is not an IaC management token.

Compensating controls are mandatory:

1. Mint a new just-in-time write token for exactly one phase. Keep only one
   Cloudflare write token live at a time and never reuse it.
2. Restrict it to the one account or one zone needed by that root, the minimum
   current permission group, a short explicit TTL covering only the approved
   window, and the trusted operator source IP. If a stable trusted source IP
   cannot be enforced, stop; do not silently weaken the ceremony.
3. Authenticate only after the read-only audit contract and exact saved-plan
   SHA-256 match the phase gate. Apply only that saved plan from protected
   storage.
4. Enforce the phase's exact address/type/count/field allowlist, no data source
   for runtime secrets, `prevent_destroy`, and denial of delete/replacement.
5. Immediately after apply, revoke the write token and prove that same bearer is
   rejected using a separate credential. Only then re-audit the entire affected
   account resource class or zone with the separate read-only audit token.
6. Retain a redacted receipt containing phase, token ID—not value—permission
   groups, account/zone selector, source-IP restriction, issue/expiry time,
   plan hash, input/output audit-contract hashes, revocation time, and
   revocation-verification result. Missing evidence is a fail-closed `NO-GO`.

## State, plan, and secret custody

Use six different state paths on a protected encrypted volume:

```text
<protected>/cloudflare/admin-tunnel/terraform.tfstate
<protected>/cloudflare/admin-policies/terraform.tfstate
<protected>/cloudflare/admin-route/terraform.tfstate
<protected>/cloudflare/admin-api/terraform.tfstate
<protected>/cloudflare/site-naranjo-online/terraform.tfstate
<protected>/cloudflare/site-lidersea-com/terraform.tfstate
```

Every value that is a private identifier — the account ID, each zone ID, and
the fresh adoption-audit hash — is supplied only from an ignored, protected
variable file beside that one root. The tracked `terraform.tfvars.example` in
each root carries obvious placeholders and never a real identifier, and
`.gitignore` covers `*.tfstate*`, `terraform.tfvars`, `*.auto.tfvars`, and
`.terraform/` so neither state nor inputs can be published.

Pass the phase-specific path with local-backend configuration when initializing
only that root. Use the phase's dedicated protected
`<protected>/cloudflare/PHASE/tofu-data` as `TF_DATA_DIR`; the offline gate
requires and parses its `terraform.tfstate` backend metadata and requires the
configured local-backend path to equal the phase path above. Never initialize live state beside the repository. Never commit
or upload `.terraform/`, state, state backups, variable files, saved plans,
plan JSON, provider environment, Tunnel runtime tokens, audit evidence
containing opaque IDs, or decrypted SOPS material. State and plans remain
outside Git even when the repository otherwise uses SOPS and age.

Write-token plaintext may enter only through `CLOUDFLARE_API_TOKEN` in the exact
OpenTofu provider child process. It must not be exported into the parent shell,
offline gate, parser, audit process, or another child. The distinct read-only
audit bearer may enter only the future isolated audit child through the same
trusted reviewed-blob launcher boundary; it is never shared with OpenTofu or an
offline validator. SOPS/age ciphertext may
protect approved credential source material, but decryption must be ephemeral
and must never feed a Terraform variable, provider data source, plan, state,
log, or repository plaintext. The required child-only launcher is not yet
implemented, so this rule currently blocks live plan/apply.

The six JIT write tokens have these maximum Cloudflare-enforced boundaries:

| Root | Cloudflare-enforced reach | Exact protected-plan intent |
| --- | --- | --- |
| `admin-tunnel` | Connector/Tunnel write across the selected account | `pi-admin` Tunnel only |
| `admin-policies` | Required Gateway-policy write across the selected account | Final Pi block and TCP 22 allow only |
| `admin-route` | Required private-network route write across the selected account | One Pi `/32` through `pi-admin` only |
| `admin-api` | Required Gateway-policy write across the selected account | TCP 6443 allow only |
| `site-naranjo-online` | Connector/Tunnel config write across the selected account, plus DNS Write and Zone Settings Write across the `naranjo.online` zone | One adopted Tunnel, its config, one adopted apex CNAME, and five zone settings |
| `site-lidersea-com` | Connector/Tunnel config write across the selected account, plus DNS Write and Zone Settings Write across the `lidersea.com` zone | One adopted Tunnel, its config, one adopted apex CNAME, and five zone settings |

Grant only matching read permission if the current provider requires it. The
read-only audit token is separate from all write tokens. Its Zone Read and DNS
Read coverage must include every zone in the selected account so the
exact-two-zone assertion is meaningful. It may also have the narrow Billing,
Tunnel, Networks, Zero Trust, Access policy, and audit-log reads needed by
`scripts/cloudflare-audit.sh`. It must not have write access.

The `pi-admin`, `naranjo-online`, and `lidersea-com` Tunnel runtime tokens are
separate from each other and from every API token, and are rotated one Tunnel
at a time. Retrieve them out of band without a provider data source
or management-token substitution.

Never grant Billing Write, Seats Write, Registrar, plan/subscription write,
Workers, storage, AI, media, Load Balancing, certificates, or unrelated account
settings.

## Exit-gated ceremony

All authenticated steps below are future manual checkpoints. This repository
work performs none of them.

There are two different gates and they must not be collapsed. The protected
saved-plan gate is a **pre-apply** check. It runs after the authenticated plan is
created, with every Cloudflare credential absent from its environment, and must
finish before any apply starts. A completed `cloudflare-phase-token-receipt-v2`
is a **post-apply closure** record because it includes revocation/rejected-token
evidence and the subsequent read-only post-audit; it cannot retroactively authorize the apply it
describes. Lidersea consumes only the already completed Naranjo receipt as a
predecessor dependency, never a completed receipt for the current Lidersea
operation.

A future live implementation still needs a separate strict machine-produced
current-phase token-preflight record and a launcher that gives the bearer only
to the exact OpenTofu plan/apply child process. The offline gate now requires a
protected reviewed manual pre-apply attestation of the zero-paid entitlement,
account MFA/inventory, phase-exact JIT scope/source-IP/TTL, and recovery gates;
that human record is not live API proof. The offline gate and every parser must
see no bearer value. After apply, the separate closure gate must bind the saved
plan, token ID, preflight evidence, post audit, revocation, and rejected-token
result. The live preflight/launcher and full broad-scope closure gate are not
implemented here; this remains an explicit deployment blocker, so policy PASS
cannot authorize apply.

The current worktree is not a trusted execution source. The audit script is
code-blocked before token or network access until a trusted launcher can execute
one exact reviewed immutable blob with a clean environment. The offline plan
gate remains executable for tests, but a PASS produced by mutable worktree code
is non-authoritative for live custody. Implementing and validating that common
reviewed-blob launcher is an explicit deployment blocker for both scripts.

1. Use read-only discovery to bind the selected account and the two exact named
   zones. Require exactly two active Free zones, a verified Free Zero Trust
   entitlement, no trial, and no nonzero or unknown price. Record only redacted
   labelled audit hashes.
2. Validate all six roots without credentials and review their pinned
   provider locks. Resolve values only in ignored, protected phase-specific
   variable files.
3. If an exact managed object already exists, import it only into its owning
   phase using `imports/README.md`. Import and refresh one object at a time
   within a separately approved JIT-token window.
4. Gate, approve, and apply `admin-tunnel` alone. Revoke and rejection-verify the
   write token with a separate credential, then use the read-only audit token to
   audit the selected account's complete Tunnel set and exact approved
   certificate-v2 posture/WARP-device contract, verify no unrelated change,
   emit both audit hashes, and retain the receipt.
5. Use both contracts to gate `admin-policies`. Apply the exact final block and
   TCP 22 allow alone; revoke and rejection-verify the write token, then
   re-audit all relevant policies with the read-only token, emit the matching
   policies-contract hash, and retain the receipt.
6. Only that policies contract can unlock `admin-route`. Before any route or
   host-network change, prove independent recovery and two working
   administrative sessions. Apply only the approved Pi `/32` saved plan, revoke
   and rejection-verify the write token, then re-audit all routes with the
   read-only token, emit the exact API-input contract, and retain the receipt.
7. Keep `admin-api` default-off until its own later approval, the verified-route
   and API-input contracts, and repeated recovery/session evidence. Its token is
   distinct from the earlier policy token despite using the same account
   permission class.
8. Adopt `site-naranjo-online` with its own JIT token: import each object with
   `imports/README.md`, confirm the refresh-only plan is non-destructive, apply
   only the reviewed saved plan, then revoke and rejection-verify the write
   token and re-audit that Tunnel and that complete DNS zone with the read-only
   token.
9. Only then mint the second, different JIT token and repeat for
   `site-lidersea-com` — the literal final activation. Retain both receipts.
   The two roots never share a token, a state file, or a plan.

Any mismatch, ambiguity, unknown value, missing evidence, overbroad token
selector, absent IP/TTL restriction, credential spill, unexpected account/zone
change, paid product, or session/recovery failure is a fail-closed `NO-GO`.
Budget alerts are secondary detection; they do not cap or authorize spend.

### Protected saved-plan gate

`scripts/cloudflare-plan-gate.sh` accepts eight baseline positional arguments:
the exact phase name, saved plan, completed redacted audit, protected workspace
root, pre-state receipt, exact current-phase state path, initialized protected
backend-metadata file, and reviewed manual pre-apply attestation. It accepts at
most one phase-specific ninth argument. `admin-route` and `admin-api` require
the protected recovery/session JSON described below. The final website
activation requires the fixed-schema protected predecessor transaction
directory. Every other
phase rejects a ninth argument. The plan, audit, receipts, backend/state,
manual attestation, validation evidence, caller-selected `TMPDIR`, and
every temporary JSON file must resolve inside that one non-symlink protected
root. The gate rejects an inherited Cloudflare API token before starting any
child process; it is offline and never authenticates to Cloudflare.

The gate requires the phase, policy, audit/gate, token-validator, and Windows
workspace-validator sources to equal one unchanged `HEAD` before and after the
evaluation. It snapshots the inputs, provider lock, exact Rego policy, and
validators into protected storage, reads backend/state/manual bytes through
open file descriptors into read-only snapshots, parses only snapshots, rejects ignored or
untracked source files, and rechecks every original hash and exact directory
inventory before returning. The snapshotted Windows validator receives the
actual checkout root plus every original and parsed protected artifact. It
checks each file's full reparse chain, exact ACL, single-link regular-file
identity, exclusive same-handle read, and SHA-256, then emits a bounded fresh
file-set attestation without printing a path.

The owner-readable pre-state receipt has exactly one value for each field:

```text
backend_metadata_sha256=BACKEND_METADATA_SHA256
manual_attestation_sha256=MANUAL_ATTESTATION_SHA256
phase_root=infrastructure/cloudflare/phases/PHASE
repo_commit=COMMIT_HEX
phase_lock_sha256=LOCK_SHA256
workspace_attestation_sha256=WINDOWS_WORKSPACE_ATTESTATION_SHA256
state_binding_sha256=DERIVED_STATE_BINDING_SHA256
state_evidence_sha256=CANONICAL_NINE_LINE_STATE_EVIDENCE_SHA256
state_mode=absent|present
state_sha256=absent|STATE_SHA256
plan_sha256=SAVED_PLAN_SHA256
planned_utc=RFC3339_UTC
```

`admin-route` and `admin-api` add exactly:

```text
recovery_evidence_sha256=RECOVERY_SESSION_JSON_SHA256
```

Only the Lidersea pre-state receipt adds these exact fields:

```text
predecessor_post_audit_sha256=NARANJO_POST_AUDIT_SHA256
predecessor_pre_state_receipt_sha256=NARANJO_PRE_STATE_RECEIPT_SHA256
predecessor_state_evidence_sha256=NARANJO_STATE_EVIDENCE_SHA256
predecessor_token_receipt_sha256=NARANJO_PHASE_TOKEN_RECEIPT_SHA256
predecessor_token_validation_sha256=NARANJO_TOKEN_VALIDATOR_PASS_SHA256
```

Never copy raw lineage or state bytes into the receipt or terminal output. The
gate derives backend type/path/hash, state hash, labelled lineage hash, and
serial from the exact parsed snapshots; callers cannot assert lineage or serial.
Write the receipt fields in exactly the order shown. Before constructing it,
preserve the state validator's exact nine LF-terminated output lines in protected
storage; the receipt binds that file's hash, and the plan gate independently
recreates the same bytes and rejects a mismatch.
For first create, the exact phase state leaf may be absent, in which case the
binding uses distinct literal `absent` facts and the gate verifies the unchanged
parent and continued absence before and after evaluation. Generate the receipt
in the same protected ceremony that creates the saved plan, then make it
read-only. Field names are an exact closed set: missing, duplicate, blank, or
extra fields fail. Every timestamp uses exactly `YYYY-MM-DDTHH:MM:SSZ`; GNU date
expressions, offsets, fractional seconds, and noncanonical variants fail. The
gate recomputes the repository commit, phase lock hash, and plan
hash, invokes `scripts/validate-windows-credential-workspace.ps1 -Session`
against the supplied protected root, and requires both its fresh output and
`CLOUDFLARE_WORKSPACE_ATTESTATION_SHA256` to match the receipt. It creates a
private read-only snapshot of every plan/evidence input and requires identical
hashes before and after copying before parsing any snapshot. It then requires a
fresh `audit_result=pass` from the exact predecessor phase, compares every phase
contract, and prints only hashes and non-secret metadata. Its default audit
freshness limit and saved-plan age limit are each 900 seconds and may only be
tightened or raised as far as 3600 seconds.

The gate compares the receipt with the actual protected backend/current-state
snapshot or explicit absent-state observation. A missing, stale, reused, or
unverifiable binding blocks deployment. This is still an offline custody check,
not proof of current Cloudflare API state and not apply authorization.

The manual file is strict duplicate-free UTF-8 JSON with schema
`cloudflare-preapply-manual-v1`, a maximum five-minute validity window, and
evidence role `reviewed-manual-preapply-authorization`. It binds the commit,
workspace attestation, saved plan, predecessor audit, provider lock, and derived
state binding. Its closed fields require exactly the two named active Free
zones, Free Zero Trust, no paid/trial/unknown entitlement, authorized
infrastructure cost exactly zero except separately classified registrar
renewals, reviewed member/token inventory and administrator MFA, the phase's
exact scope/permission/unavoidable-reach matrix, a distinct source-IP-policy
hash, a token lifetime no longer than 30 minutes, only one live write token, no
plaintext persistence/sharing, physical-or-trusted-LAN recovery, two retained
sessions, a fresh third login, and account-owner approval. Route/API records
also exact-match the separately validated recovery evidence hash. These are
reviewed operator assertions; a future machine-produced live token preflight
must independently prove active status, restriction, and scope before apply.

The route/API recovery file is strict duplicate-free UTF-8 JSON with schema
`admin-recovery-session-v1`, the exact phase, a maximum five-minute validity
window, and the evidence role
`operator-attestation-plus-independent-challenges`. It binds the current commit
hash, workspace attestation, saved-plan hash, predecessor-audit hash, and one
host-identity hash. It contains one fresh physical-console challenge, exactly
two distinct read-only retained-session challenge/result records verified
within 60 seconds of one another, and a third distinct fresh-login challenge
performed after both retained-session checks. Every challenge, result, session,
and evidence hash is nonzero and distinct. This is a bounded operator
attestation and evidence binding, not cryptographic or network proof; the
operator must actually perform the checks. The known current state has not yet
proved the two-session condition, so `admin-route` and `admin-api` remain
`NO-GO`.

For Lidersea, argument nine is a directory with one of two exact inventories.
Both contain `target-binding.txt`, `saved-plan.tfplan`,
`pre-apply-state-evidence.txt`, `pre-state-receipt.txt`,
`pre-operation-audit.txt`, `source-ip-policy.txt`, `token-id.txt`,
`preflight-token-evidence.txt`, `postflight-token-evidence.txt`, and
`token-receipt.json`, with no extra entry or link. The absent form contains no
`pre-apply-state.tfstate`; its state evidence and receipt must both say
`state_mode=absent` and `state_sha256=absent`, while the v2 JSON token receipt
uses `state_mode="absent"` and `state_sha256=null`. The present form adds exactly
`pre-apply-state.tfstate`; all three records must say present and the carried
bytes must match the nonzero state hash. Both forms require a nonzero derived
`state_binding_sha256`. Mixing either inventory or representation is a
`NO-GO`.

The gate snapshots the exact inventory and committed Naranjo lock, re-runs
OpenTofu JSON rendering and the Naranjo Rego policy, reparses the original
canonical nine-line state evidence, recomputes its derived binding, reparses the
original canonical pre-state receipt, and compares repository, plan, provider
lock, backend, workspace, state mode/hash/binding, and optional present-state
bytes. It then directly re-runs the strict v2 token-receipt validator from its
protected source snapshot. A caller-supplied PASS file is never accepted.

The current predecessor audit must prove the Naranjo apex is exact while the
Lidersea apex remains absent. The Lidersea pre-state receipt binds that post
audit, the exact Naranjo token receipt, and the newly generated bounded
four-line validator output. The receipt's postflight revocation verification
must occur at or before the read-only post audit, and its Naranjo pre-operation audit must have
preceded token issuance by no more than 900 seconds. This makes the second DNS
activation fail closed until the first zone's plan, audit, source-IP, token-ID,
revocation, workspace, repository, state, and provider-lock bindings all agree.

## Zero-spend and content boundary

The account contract is exactly two active domain zones on the Free website
plan plus separately classified Registrar renewal for domain ownership. Zero
Trust must independently remain on its verified Free entitlement. No limit
exhaustion may trigger a paid fallback. Pro, trials, usage-based features, and
unknown products are forbidden.

Cloudflare cache is optional acceleration, not Pi capacity or availability.
Large-media delivery remains `NO-GO` on this design. Byte ranges, cache bypass,
`no-store`, or object splitting do not create contractual permission. Any
future media feature or paid tier requires a new reviewed architecture and an
explicit cost decision.

## Current caveats

The authenticated apply ceremony in `scripts/cloudflare-plan-gate.sh`,
`scripts/cloudflare-audit.sh`, and the two evidence validators still speaks the
superseded shared-Tunnel phase names and its create-only onboarding contract.
It therefore cannot authorize a website adoption, and after this reconciliation
it names roots that no longer exist, so it fails closed rather than passing
something stale. Reconciling that ceremony to the two website roots is tracked
separately; until it lands, website plans and applies are owner-run with an
owner-held just-in-time token against the runbook, and no gate output may be
described as apply authorization.

Deployment is still blocked. The write-token permissions reach broader
Cloudflare resource classes than these plans, while the current audit does not
yet produce a canonical before/after digest for every object those permissions
can mutate. In particular, connector/config closure, all Zero Trust surfaces,
private virtual networks, and token-ID-attributed audit-log deltas are not yet
bound as one transaction. DNS pagination is complete and duplicate-ID checked,
and the complete Gateway-rule inventory is closed, but those narrower checks do
not prove that a broad account token made no unrelated change. Implement and
independently validate the full-class before/after and audit-log contract before
any apply.

The gate also relies on locally resolved OpenTofu, Conftest, jq, Git Bash,
PowerShell, Python, and checksum tools. Versions alone do not authenticate
binaries. A reviewed absolute-path SHA-256 tool manifest and protected
same-file verification are still required for a live ceremony. Until that is
complete, a policy PASS remains analysis evidence only and never apply
authorization.

Cloudflare response normalization and the selected read endpoints must be
confirmed through a separately approved read-only discovery run before the
first ceremony. No such live confirmation has occurred in this implementation
work.

Gateway network policy coverage must not be described as a replacement for the
host firewall. WARP must carry traffic rather than run DNS-only, proxy TCP,
include only the Pi `/32`, and pass the exact posture check. Cached posture and
existing sessions make SSH keys, host controls, independent recovery, and
multiple proven sessions mandatory.

Official references:

- <https://registry.terraform.io/providers/cloudflare/cloudflare/5.22.0>
- <https://github.com/cloudflare/terraform-provider-cloudflare/releases/tag/v5.22.0>
- <https://developers.cloudflare.com/fundamentals/api/reference/permissions/>
- <https://developers.cloudflare.com/fundamentals/api/get-started/create-token/>
- <https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/>
- <https://developers.cloudflare.com/cloudflare-one/traffic-policies/order-of-enforcement/>
- <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/cloudflared/connect-cidr/>
- <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/>
- <https://developers.cloudflare.com/tunnel/>
- <https://developers.cloudflare.com/cache/concepts/default-cache-behavior/>
- <https://developers.cloudflare.com/fundamentals/reference/policies-compliances/delivering-videos-with-cloudflare/>
- <https://www.cloudflare.com/service-specific-terms-application-services/>
- <https://www.cloudflare.com/plans/>
- <https://developers.cloudflare.com/billing/understand-billing-policy/>
