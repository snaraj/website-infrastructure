# Cloudflare phase-token receipt — Draft / unverified

This ceremony records one short-lived Cloudflare API token transaction without
recording the token. The JSON receipt is an **operator attestation plus a
live-verification record**. Its hashes make independently reviewed local
artifacts disagree loudly; they are not cryptographic proof that Cloudflare
issued, scoped, or revoked a token. A validator PASS does not authorize a plan,
apply, import, Tunnel start, DNS change, firewall change, or any other live
mutation.

This receipt is a post-apply closure artifact, not a pre-apply authorization.
Its required postflight revocation fields cannot exist before apply. The
offline saved-plan gate must pass before apply with the bearer absent, while a
separate current-phase token-preflight record must validate scope, TTL,
source-IP restriction, token ID, and active status. After apply, revoke the
write token and prove that same bearer is rejected using a separate credential;
then run the post-apply audit with the separate read-only audit token before
completing this receipt and running this validator. A postflight
PASS never retroactively approves an operation. The offline plan gate now
requires a protected five-minute `cloudflare-preapply-manual-v1` record covering
the reviewed Free/zero-paid entitlement, account MFA/inventory, phase-exact JIT
scope, source-IP policy, maximum 30-minute lifetime, and recovery gates. Its
`active_status_verified` field is explicitly an operator assertion; it cannot
replace the separately machine-produced live preflight. That strict live
preflight gate and a child-process-only OpenTofu credential launcher are not
implemented yet, so live apply remains `NO-GO`.

The current checkout scripts are not a trusted launcher.
`scripts/cloudflare-audit.sh` is deliberately code-blocked before token or
network access until an exact reviewed blob can be launched from a trusted,
immutable source with a clean environment. `scripts/cloudflare-plan-gate.sh`
remains useful for credential-free offline tests, but executing it from a
mutable worktree cannot produce authoritative live-custody evidence. The same
trusted reviewed-blob launcher is a deployment prerequisite for both
ceremonies; a local PASS before it exists does not lift the `NO-GO`.

Run the ceremony only inside the protected workspace described in
`windows-credential-ceremony.md`. The receipt path must be absolute, outside the
repository, and a strict descendant of the explicit protected root supplied by
`--credential-root` or `WEBSITE_INFRA_CREDENTIAL_ROOT`, never both. Supply the
receipt itself with `--receipt` or `CLOUDFLARE_PHASE_TOKEN_RECEIPT`, never both.
The validator rejects symlink and Windows reparse-point traversal where the host
exposes those controls, rejects hard-linked or non-regular files, enforces
owner-private POSIX modes, reads at most 16 KiB, and performs no network request
or external command. On Windows, containment is not an ACL/BitLocker proof: the
current-session PowerShell workspace gate must separately validate the root and
include the receipt in its array-valued `-ProtectedFile` input. That verifies an
absolute contained regular file, exact owner/DACL, single-link identity, and the
bytes read from one stable handle. Preserve the resulting
`protected_file_set_sha256`, `validation_utc`, and
`validation_attestation_sha256` in separate protected gate evidence, not inside
the receipt being hashed. The receipt validator never prints the path or
receipt contents.

## Closed phase and authority matrix

| Phase | Token permission | Cloudflare resource selector | Unavoidable permission reach |
|---|---|---|---|
| `admin-tunnel` | `Cloudflare One Connector: cloudflared Write` | exact account | all Cloudflared connectors and Tunnels in the account |
| `admin-policies` | `Zero Trust Write` | exact account | all Zero Trust resources in the account |
| `admin-route` | `Cloudflare One Networks Write` | exact account | all private routes and virtual networks in the account |
| `admin-api` | `Zero Trust Write` | exact account | all Zero Trust resources in the account |
| `public-edge` | `Cloudflare One Connector: cloudflared Write` | exact account | all Cloudflared connectors and Tunnels in the account |
| `public-dns-naranjo` | `DNS Write` | that exact zone | all DNS records in that one zone |
| `public-dns-lidersea` | `DNS Write` | that exact zone | all DNS records in that one zone |
| `audit` | the exact read set below | exact account and all account zones | all listed read surfaces |

Cloudflare's token resource selectors do not narrow the write permissions above
to one Tunnel, route, Gateway rule, or DNS record. Separate roots and tokens
isolate state, time, intent, and revocation; they do not create object-level
Cloudflare authorization that the API does not offer. This unavoidable reach is
why every token is source-IP restricted, just in time, MFA reviewed, and revoked
immediately after one phase.

The audit token's exact ordered permission set is `Billing Read`, `Zone Read`,
`DNS Read`, `Cloudflare One Connector: cloudflared Read`, `Cloudflare One
Networks Read`, `Zero Trust Read`, `Access: Apps and Policies Read`, and `Access:
Audit Logs Read`. It has no write permission. Apply tokens live for no more than **30
minutes**; the audit token lives for no more than **60 minutes**. Both user-owned
and account-owned tokens are permitted, but the preflight endpoint kind must
match ownership: `user-token-verify` or `account-token-verify`.

No phase token may include Billing Write, Registrar Write, or API Tokens Write.
It has no Git write, cluster, or Tunnel-runtime connection authority. Connector
and Tunnel *management* reach is represented honestly by the permission matrix;
`tunnel_runtime_authority=false` means the API token is not a `cloudflared`
connector bearer token.

## Exact receipt schema

The validator accepts only `cloudflare-phase-token-receipt-v2`, strict UTF-8
JSON without a BOM, duplicate keys, missing keys, or extra keys. All SHA-256
values are 64 lowercase hexadecimal characters and may not be all zero. The
externally supplied digest for every semantically different artifact must also
be distinct; copying one digest into multiple fields is rejected. Give each
evidence file an exact labelled schema so even two otherwise empty observations
have different bytes rather than reusing a hash. The receipt never contains the
token, an account/zone/Tunnel identifier, an IP
address, an age identity, a private key, a GitHub token, raw state, a saved plan,
or raw Cloudflare responses.

The top-level object contains exactly:

- `schema`, `phase`, and `operation` (`apply` for the seven write phases,
  `audit` for the read phase);
- `token_policy` with owner and endpoint kinds, exact scope/permission/reach
  arrays, canonical UTC-second issue/expiry times, `token_id_sha256`,
  `source_ip_restricted=true`, and `source_ip_policy_sha256`;
- `bindings` with `target_sha256`, `workspace_attestation_sha256`,
  `saved_plan_sha256`, explicit `state_mode`, `state_binding_sha256`,
  `state_sha256`, `provider_lock_sha256`, `repository_commit_sha256`,
  pre-operation `audit_sha256`, and read-only `post_audit_sha256`;
- `controls` with `mfa_verified=true` and every persistence, sharing, prohibited
  write, Git, cluster, and Tunnel-runtime authority flag set to `false`; and
- `verification.preflight` plus `verification.postflight`.

Both verification objects contain the same `token_id_sha256` as token policy in
addition to their own distinct `evidence_sha256`.

Every apply receipt requires the saved-plan, derived-state-binding, provider
lock, pre-operation-audit, and post-operation-audit hashes. For a present
pre-apply state, `state_mode` is exactly `"present"` and `state_sha256` is the
nonzero hash of the carried state bytes. For first-create absence, `state_mode`
is exactly `"absent"`, `state_binding_sha256` still binds the backend, exact
state path, and literal absent lineage/serial facts, and `state_sha256` is JSON
`null`; a fabricated hash is rejected. These forms are mutually exclusive.
The audit-token receipt has `state_mode`, saved plan, state binding, state,
provider lock, and post-audit values exactly JSON `null`: it binds its produced
read-only audit in `audit_sha256` without recursively requiring an audit of the
audit token. Hash exact bytes, without copying protected artifacts out of the
workspace:

- the reviewed target-binding record;
- the protected-workspace validator's attestation record;
- the saved binary plan, canonical derived pre-state evidence, optional present
  pre-apply state, and provider lock file;
- the canonical ASCII repository object ID followed by one LF, yielding
  `repository_commit_sha256`; and
- the bounded, redacted pre-operation audit record; and
- for apply receipts, the distinct bounded read-only post-operation audit
  generated only after revocation and rejected-bearer verification.

Derive `token_id_sha256` from the exact non-secret Cloudflare token identifier,
never from the bearer value, and independently supply the expected hash to the
validator. Both bounded redacted verification records must carry that same
labelled hash. The validator exact-matches token policy, preflight, postflight,
and external expectation, preventing active-token evidence for one token from
being paired with revocation evidence for another.

The source-IP-policy hash binds a separate redacted restriction record. Hash
bindings are local attestations: validators can exact-match bytes and closed
schemas, but cannot independently prove that a human statement or redacted
Cloudflare response is truthful. That
record must attest exactly one currently observed egress address narrowed to a
host prefix (`/32` for IPv4 or `/128` for IPv6), its canonical UTC observation
time, and the exact token-condition response; a Boolean or hash alone is not
independent proof that Cloudflare enforced it. The
preflight evidence hash binds an active-token verification whose revocation
status is still `pending`. After the operation, revoke the same token before its
expiry, prove that the revoked token itself is rejected, and use a **separate
credential** to verify revoked status. Bind that distinct record as the
postflight evidence hash. The validator rejects identical preflight and
postflight hashes, a postflight timestamp in the future, or timestamps outside
the order issue, preflight, revocation, postflight. It also rejects reuse of the
pre-operation audit hash as the post-operation audit hash. The Lidersea
predecessor gate separately parses the post-audit `generated_utc` and requires
it to be at or after the Naranjo revocation/rejection-verification timestamp;
an audit generated before revocation is a `NO-GO`.

## Invocation contract

Supply the expected phase and every applicable hash independently through the
named CLI options or their `CLOUDFLARE_EXPECTED_*` environment equivalents.
Do not set both sources for one value. Apply phases use:

```text
python scripts/validate_cloudflare_token_receipt.py
  --receipt <protected-absolute-path>
  --credential-root <protected-volume-root>
  --phase <closed-phase-name>
  --target-sha256 <reviewed-hash>
  --workspace-attestation-sha256 <reviewed-hash>
  --saved-plan-sha256 <reviewed-hash>
  --state-mode <absent-or-present>
  --state-binding-sha256 <reviewed-hash>
  --state-sha256 <reviewed-hash-only-when-present>
  --provider-lock-sha256 <reviewed-hash>
  --repository-commit-sha256 <reviewed-hash>
  --audit-sha256 <reviewed-pre-operation-hash>
  --post-audit-sha256 <reviewed-post-operation-hash>
  --token-id-sha256 <reviewed-hash>
  --source-ip-policy-sha256 <reviewed-hash>
  --preflight-evidence-sha256 <reviewed-hash>
  --postflight-evidence-sha256 <reviewed-hash>
```

Keep command history disabled even though these arguments are hashes. A success
prints only PASS, the closed phase name, the receipt SHA-256, and the evidence
role. Any failure is a `NO-GO`; preserve the protected evidence, revoke any
possibly live token, and restart with a new token and new receipt. Never weaken
the receipt to make an old plan pass.
