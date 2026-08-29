# Cloudflare OpenTofu — staged and fail-closed

This directory defines nine independent OpenTofu roots. Seven create the
private owner-administration plane; two adopt the already-live website edge.
Nothing in the files alone authorizes an authenticated plan, import, apply,
DNS change, or Pi host change. Live use additionally requires the installed
reviewed-source launcher, a protected saved plan, a fresh predecessor audit,
one phase-specific JIT token, immediate revocation, and a closing audit.
OpenTofu is pinned to `1.12.5` and the Cloudflare provider to `5.22.0`.

The two website roots are different in kind from the seven administrative
roots: their Tunnels, apex records, and zones already exist and already serve
traffic, so those roots ADOPT live objects by import. Git is reconciled to that
topology, never the reverse, and never by deleting or recreating a live object.

## Phase graph

Each root owns one narrow resource graph and one independently protected state:

| Root | Exact IaC-managed scope | Activation condition |
| --- | --- | --- |
| `phases/admin-certificate` | Public owner-device CA certificate only; never its private key | Initial account and zero-spend preflight |
| `phases/admin-enrollment-policy` | Exact owner email plus phishing-resistant MFA enrollment policy | Exact certificate audit contract |
| `phases/admin-enrollment-app` | WARP enrollment application with one policy and one identity provider | Exact enrollment-policy audit contract |
| `phases/admin-device` | One macOS client-certificate posture rule and one locked Pi-only WARP profile | Exact certificate and enrollment audit contracts; attended owner-device enrollment |
| `phases/admin-tunnel` | `pi-admin` Tunnel only | Exact one-device and enrollment audit contracts |
| `phases/admin-policies` | Final Pi block and TCP 22 identity/device allow only | Exact device and admin-tunnel audit contracts |
| `phases/admin-route` | One RFC1918 Pi `/32` route through `pi-admin` | Exact admin-policies audit contract |
| `phases/site-naranjo-online` | `naranjo-online` Tunnel, its single-origin configuration, the proxied `naranjo.online` apex CNAME, and that zone's six security settings | Adoption of the live naranjo.online objects; first website root |
| `phases/site-lidersea-com` | `lidersea-com` Tunnel, its single-origin configuration, the proxied `lidersea.com` apex CNAME, and that zone's six security settings | Adoption of the live lidersea.com objects; final activation |

The security dependencies are:

```text
public owner CA -> exact-owner MFA enrollment -> one WARP application
                -> one Mac certificate posture + locked /32 profile
                -> private pi-admin Tunnel -> TCP/22 allow + final Pi block
                -> exact Pi /32 route -> external and reboot verification

per-site read-only adoption audit -> site-naranjo-online (import, then plan)
             -> zone audit + receipt revalidation
             -> site-lidersea-com (import, then plan; last)
```

`admin-certificate` uploads public CA bytes only. The plan policy rejects a
private-key field or private-key material. `admin-enrollment-policy` admits one
exact email identity with only biometric or security-key MFA, a five-minute MFA
session, and a fifteen-minute enrollment session. `admin-enrollment-app` is a
WARP application that auto-redirects to the account's sole reviewed identity
provider and attaches only that policy.

`admin-device` requires `client_certificate_v2`, the exact uploaded CA,
`check_private_key = true`, a serial-number certificate binding, `clientAuth`
usage, macOS, and the system trust store. The profile matches the same exact
email, cannot be disabled, left, or mode-switched by the user, uses WARP over
MASQUE with fallback disabled, and sends only the Pi RFC1918 `/32` through
Cloudflare. Cloudflare-managed control routes are hashed separately so they
cannot conceal a widened owner route. The audit closes the active-device
inventory at exactly one device assigned to this profile; a second enrollment
is a deployment and maintenance failure.

`admin-tunnel` deliberately contains no Gateway policy or private route.
`admin-policies` deliberately contains no Tunnel or route. Its exact TCP 22
allow must have a lower Gateway precedence number than its catch-all Pi block.
The read-only audit must prove the Tunnel, both policies, their exact account
and Pi `/32` binding, their enabled state, and their precedence before
`admin-route` may advertise the `/32`. Cloudflare documents that lower policy
precedence numbers evaluate first; unmatched enrolled-device private-network
traffic otherwise requires an explicit catch-all block design. The policy-input
contract binds the exact email, posture and profile UUIDs, enrollment and device
contract hashes, session freshness, precedence values, account, Tunnel, and Pi
`/32`. A predecessor hash therefore cannot be replayed against another identity,
device, route, or weaker session rule.

No Cloudflare rule exposes the Kubernetes API or another Pi port. The final
block covers every destination port on that Pi except the earlier exact TCP/22
allow. `admin-route` remains blocked unless independent physical recovery is
proven, two retained administrative sessions pass distinct challenges, and a
separate fresh-login challenge succeeds while both sessions remain available.
The protected attestation binds those observations; it never substitutes for
the real connectivity checks. These roots do not edit UFW, WireGuard, `sshd`,
host keys, or the operating system; those changes use the separate reviewed Pi
launcher and retain the local console rollback path.

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
Tunnel, exact owner enrollment/device posture, the exact two-rule Gateway
inventory, and the exact private route. Any third Gateway rule is a conflict.

Each website root owns exactly these ordered ingress rules on its own Tunnel:

1. that site's apex to that site's ClusterIP service DNS name on TCP 8080;
2. an unqualified terminal `http_status:404` catch-all.

There is no shared public Tunnel and no wildcard hostname. Each root also owns
exactly one proxied `ttl = 1` apex CNAME in its own zone, whose content is
derived from that root's own Tunnel resource attribute, so no Tunnel UUID ever
enters Git or a variable file.

Each website root additionally owns exactly six free zone-level settings that
carry the zone security target state:

| Setting | Committed value | Why |
| --- | --- | --- |
| `always_use_https` | `on` | Plain HTTP currently serves the live site; HSTS received over cleartext is ignored by browsers, so the edge redirect is the control that closes the first-visit gap |
| `min_tls_version` | `1.2` | TLS 1.0 and 1.1 are currently accepted, and the legacy handshakes are signed `ecdsa_sha1` |
| `tls_1_3` | `on` | Already on; committed so it cannot silently regress |
| `0rtt` | `off` | Already off; early data is replayable and the handshake saving does not justify it |
| `http3` | `on` | Already advertised on every response; pinned so it cannot regress unnoticed |
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
  the six zone settings may plan as `["update"]`, and only toward the exact
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

Use nine different state paths on a protected encrypted volume:

```text
<protected>/cloudflare/admin-certificate/terraform.tfstate
<protected>/cloudflare/admin-enrollment-policy/terraform.tfstate
<protected>/cloudflare/admin-enrollment-app/terraform.tfstate
<protected>/cloudflare/admin-device/terraform.tfstate
<protected>/cloudflare/admin-tunnel/terraform.tfstate
<protected>/cloudflare/admin-policies/terraform.tfstate
<protected>/cloudflare/admin-route/terraform.tfstate
<protected>/cloudflare/site-naranjo-online/terraform.tfstate
<protected>/cloudflare/site-lidersea-com/terraform.tfstate
```

Every value that is a private identifier — the account ID, each zone ID, and
the fresh adoption-audit hash — is supplied from a variable file on the same
protected volume, outside the repository, passed with `-var-file`. A variable
file inside a phase root is rejected by the closed file inventory, so the
protected path is the only working location as well as the only safe one. The
tracked `terraform.tfvars.example` in each root carries obvious placeholders,
is never the file you fill in, and never holds a real identifier. `.gitignore`
additionally covers `*.tfstate*`, `terraform.tfvars`, `*.auto.tfvars`, and
`.terraform/` as defence in depth.

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
audit bearer may enter only the isolated audit child through the same trusted
reviewed-blob launcher boundary; it is never shared with OpenTofu or an offline
validator. SOPS/age ciphertext may
protect approved credential source material, but decryption must be ephemeral
and must never feed a Terraform variable, provider data source, plan, state,
log, or repository plaintext.

The nine JIT write tokens have these maximum Cloudflare-enforced boundaries:

| Root | Cloudflare-enforced reach | Exact protected-plan intent |
| --- | --- | --- |
| `admin-certificate` | mTLS-certificate write across the selected account | One public owner-device CA only |
| `admin-enrollment-policy` | Access app/policy write across the selected account | One exact-owner phishing-resistant-MFA policy |
| `admin-enrollment-app` | Access app/policy write across the selected account | One WARP enrollment application with one policy and IdP |
| `admin-device` | Zero Trust write across the selected account | One certificate posture rule and one locked Pi-only profile |
| `admin-tunnel` | Connector/Tunnel write across the selected account | `pi-admin` Tunnel only |
| `admin-policies` | Required Gateway-policy write across the selected account | Final Pi block and TCP 22 allow only |
| `admin-route` | Required private-network route write across the selected account | One Pi `/32` through `pi-admin` only |
| `site-naranjo-online` | Connector/Tunnel config write across the selected account, plus DNS Write and Zone Settings Write across the `naranjo.online` zone | One adopted Tunnel, its config, one adopted apex CNAME, and six zone settings |
| `site-lidersea-com` | Connector/Tunnel config write across the selected account, plus DNS Write and Zone Settings Write across the `lidersea.com` zone | One adopted Tunnel, its config, one adopted apex CNAME, and six zone settings |

Grant only matching read permission if the current provider requires it. The
user-owned read-only audit token is separate from all write tokens. Its exact
permission set is machine-checked by the root transaction: `API Tokens Read`,
`Account Settings Read`, `Billing Read`, `Account: SSL and Certificates Read`,
`Cloudflare One Connector: cloudflared Read`, `Cloudflare One Networks Read`,
`Zero Trust Read`, `Access: Apps and Policies Read`, `Access: Audit Logs Read`,
`Access: Organizations, Identity Providers, and Groups Read`, `Zone Read`, and
`DNS Read`. Its zone reads cover every zone in the selected account so the
exact-two-zone assertion cannot be made true by authorization filtering. It has
one global-host source condition, a maximum 60-minute lifetime, and no write
permission. Its user-scoped policy must name the exact protected
`owner_user_id`; a token owned by another account member is rejected even when
that member can read the same account.

The `pi-admin`, `naranjo-online`, and `lidersea-com` Tunnel runtime tokens are
separate from each other and from every API token, and are rotated one Tunnel
at a time. Retrieve them out of band without a provider data source
or management-token substitution.

Never grant Billing Write, Seats Write, Registrar, plan/subscription write,
Workers, storage, AI, media, Load Balancing, certificates, or unrelated account
settings.

## Exit-gated ceremony

The seven administrative phases have one live entrypoint:
`/usr/local/sbin/website-infrastructure-cloudflare-launcher`. Install that file
root-owned and mode `0755` from its exact protected-main blob. It accepts no
mutable-checkout execution. It uses a root-owned monotonic Git bundle, a
root-owned manifest of every executable dependency, exact pinned OpenTofu,
Conftest, and jq binaries, a clean environment, and the closed operations in
`scripts/cloudflare-reviewed-launcher.sh`. FileVault, SIP, and Gatekeeper must
all be enabled.

`scripts/cloudflare_root_transaction.py` then validates the user-owned audit
token's live permission catalog, exact owner user/account/all-account-zones
resources, one-host source condition, and maximum 60-minute lifetime. Each
write phase accepts one freshly issued maximum-30-minute token with exactly one
phase permission and the exact account resource. The transaction journals the
token and audit window before any authenticated plan, performs a complete live
pre-audit, creates one typed saved plan, verifies its exact create-only graph
and Conftest result, and gives the bearer only to that plan/apply child.

An apply remains pending until the owner revokes the JIT token. Resume proves
both that the bearer is rejected and that the audit credential sees the token
inactive, queries every V2 audit-log page from token issuance onward, requires
the exact JIT actor and exact create resource set with no update, delete, or
unknown action, then runs the complete post-audit. Interrupted preparation,
apply, external connector/device work, revocation, and cleanup are all
journaled. A no-mutation failure may be cleared only after revocation and an
empty mutation log; partial provider state remains locked for a new reviewed
incident-recovery implementation. No status or PASS line contains a token,
private identifier, email, or address.

The legacy `cloudflare-plan-gate.sh` and
`cloudflare-phase-token-receipt-v2` remain the credential-free review and
postflight contracts for the two website-adoption roots. They do not authorize
administrative execution and are not substitutes for the root transaction.
Authenticated website import/apply automation is still outside the admin
launcher's closed grammar; those two roots remain blocked until a separately
reviewed adoption transaction exists.

1. Enable the Free Zero Trust account, retain one reviewed identity provider,
   and use read-only discovery to bind the exact owner user, account, and all
   account zones. Stop on a trial, paid entitlement, unexpected zone, member,
   Tunnel, route, policy, or device.
2. Issue one Mac client certificate from a dedicated offline CA, import the
   leaf certificate and key into the Mac system trust store, preserve the
   public CA certificate, and destroy the CA private key after the leaf works.
   The transaction refuses any private key in its Cloudflare input.
3. Validate all nine roots credential-free. Install the reviewed launcher and
   exact pinned tools, commit the root tool manifest, promote the exact
   protected-main bundle, and configure its protected context and audit token.
4. Run `admin-certificate`, `admin-enrollment-policy`, and
   `admin-enrollment-app` separately. For each phase: create one exact JIT
   token, apply the typed plan, revoke that token, then resume to close its
   complete live inventory and audit-log receipt.
5. Run `admin-device`, revoke its JIT token, install/enroll Cloudflare One on
   this Mac with the exact identity and phishing-resistant MFA, and resume only
   when the audit proves exactly one active owner device, one certificate
   posture rule, and one locked `/32` profile.
6. Run `admin-tunnel`; its connector bearer remains root-only. Revoke the JIT
   token, pipe the connector bearer directly into the reviewed Pi installer,
   prove the connector healthy, and only then resume the phase. Never place the
   connector bearer in an argument, terminal, clipboard, shell history, or Git.
7. Run `admin-policies`, revoke, and resume. The closing audit must show exactly
   the TCP 22 owner/device allow followed by the unconditional all-port Pi
   block, with no third Gateway rule.
8. With local console recovery and two retained LAN SSH sessions, run
   `admin-route`, revoke, and resume. Then prove owner-laptop SSH from LAN and
   hotspot, repeat with Proton enabled, reject an unauthorized device from both
   LAN and off-LAN paths, prove no public TCP 22 exposure, reboot both sides of
   the path as applicable, and repeat the positives and negatives.
9. Keep both website-adoption roots blocked. Their imports and updates require
   a future reviewed adoption transaction; the admin launcher intentionally
   cannot execute them.

Any mismatch, ambiguity, unknown value, missing evidence, overbroad token
selector, absent IP/TTL restriction, credential spill, unexpected account/zone
change, paid product, or session/recovery failure is a fail-closed `NO-GO`.
Budget alerts are secondary detection; they do not cap or authorize spend.

### Protected saved-plan gate

`scripts/cloudflare-plan-gate.sh` accepts eight baseline positional arguments:
the exact phase name, saved plan, completed redacted audit, protected workspace
root, pre-state receipt, exact current-phase state path, initialized protected
backend-metadata file, and reviewed manual pre-apply attestation. It accepts at
most one phase-specific ninth argument. `admin-route` requires
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

`admin-route` adds exactly:

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
sessions, a fresh third login, and account-owner approval. Route records
also exact-match the separately validated recovery evidence hash. These are
reviewed operator assertions; a future machine-produced live token preflight
must independently prove active status, restriction, and scope before apply.

The route recovery file is strict duplicate-free UTF-8 JSON with schema
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
operator must actually perform the checks. Missing or stale two-session proof
keeps `admin-route` at `NO-GO`.

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
