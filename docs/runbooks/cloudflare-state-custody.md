# Cloudflare OpenTofu state custody — Draft / unverified

No import, plan, apply, or authenticated provider refresh may occur until this
runbook has been exercised with disposable state. `sensitive = true`, file mode
0600, `.gitignore`, and deletion after use do not encrypt OpenTofu state.

The current mutable checkout is not a trusted live-custody source.
`scripts/cloudflare-audit.sh` is code-blocked before token or network access,
and an offline `scripts/cloudflare-plan-gate.sh` PASS is non-authoritative for a
live operation, until a common trusted launcher executes an exact reviewed
immutable blob with a clean environment. That launcher is a deployment blocker,
not an optional hardening step.

## State boundaries

Admin policy, admin routing, public Tunnel configuration, and public DNS
activation use the repository's separate phase roots and separate state files.
Never combine them with `terraform_remote_state`, a shared apply token, or one
saved plan. Public DNS is the final activation phase. Kubernetes API access is a
later default-off admin policy, not part of initial SSH onboarding.

For each phase, create a dedicated directory under the protected Windows
credential workspace. Configure the local backend with an absolute state path in
that directory. Use exactly `<protected>/cloudflare/PHASE/terraform.tfstate`
for state and `<protected>/cloudflare/PHASE/tofu-data` for `TF_DATA_DIR`; the
initialized backend metadata is therefore
`<protected>/cloudflare/PHASE/tofu-data/terraform.tfstate`. Keep `.terraform`, provider/plugin cache, `TF_DATA_DIR`, `TEMP`,
`TMP`, private variables, saved plan, plan JSON, raw audit response, and import
inputs there too. Reject reparse points, repository-relative paths, weak ACLs,
unexpected owner, and a volume without active encryption.

Only one operator process may hold a phase's state. A stale lock, lineage change,
serial regression, or unreviewed state replacement is a `NO-GO`; do not use
force-unlock until the owning process and protected backup are independently
verified.

## Bound transaction

Every authenticated operation binds these non-secret facts in a protected local
receipt:

- phase name and exact repository commit;
- parsed local-backend metadata SHA-256 and exact configured state-path binding;
- actual state SHA-256, parsed lineage hash, and parsed pre-operation serial, or
  a distinct explicit absent-state binding for first create;
- provider lock-file SHA-256 and exact OpenTofu/provider versions;
- redacted audit receipt SHA-256 and freshness;
- saved binary-plan SHA-256 plus its sanitized machine-policy result;
- approved target-binding SHA-256; and
- token-policy issue/expiry/source-IP receipt without the token value.

The offline plan gate requires the exact state leaf and backend metadata as
arguments. It opens each present input, copies bytes from that descriptor into a
read-only protected snapshot, compares identity and SHA-256 before/after the
read, and includes both source and snapshot in the Windows stable-handle file
set. It parses the backend metadata and requires type `local`, default workspace
metadata, and the exact phase state path. It parses an empty present state's
format, pinned OpenTofu version, lineage, and serial. For a never-created state
it instead requires the exact leaf to remain absent and its parent identity to
remain unchanged throughout the gate; absence is never represented as a fake
lineage or serial zero. A present state containing any output or managed
resource is outside the initial-create contract and fails.

Before the original phase gate, preserve its exact nine-line state-validator
output and bind that file as `state_evidence_sha256` in the canonical pre-state
receipt. The gate independently regenerates the same output and rejects any
hash mismatch. When a completed phase becomes a predecessor, preserve that
owner-private pre-state receipt and exact state-validator output. The
next gate reparses both and recomputes the derived state binding. For absence,
the transaction directory must omit the state file and all three state facts
are the literal `absent`; for presence, it must contain exactly one carried
state file whose bytes, lineage hash, and serial match the evidence. The v2 JSON
token receipt represents those same forms as `state_mode="absent"` with
`state_sha256=null`, or `state_mode="present"` with a nonzero state hash. Both
require the same nonzero `state_binding_sha256`; mixed forms fail closed.

The receipt also binds a protected `cloudflare-preapply-manual-v1` review. That
closed, five-minute record covers the exact Free/zero-paid entitlement, account
MFA and authority inventories, phase-exact JIT token scope/permission/reach,
source-IP policy hash, maximum 30-minute token lifetime, and physical/LAN plus
two-session/fresh-login recovery gates. It is a human-reviewed assertion, not
live API proof and not authorization to apply; the machine token preflight and
child-only credential launcher remain separate blockers.

Use configuration-driven import blocks or a protected input wrapper so account,
zone, Tunnel, route, and rule IDs do not enter shell history. Import one exact
object, then run a normal protected plan and review configuration equivalence.
A refresh-only plan is not sufficient. Delete the import block or protected
input after the accepted state transition.

Apply only the exact saved binary plan whose hashes and state lineage still
match. If state serial, commit, lock file, audit receipt, target binding, token
policy, or plan changes, discard the plan and restart. Revoke the apply token and
verify revocation before the post-apply read-only audit.

Immediately before the gate consumes protected artifacts on Windows, run the
current-session credential-workspace validator with an array-valued
`-ProtectedFile` containing the plan, pre-operation state, provider-lock
snapshot, target binding, audit record, phase receipt, token receipt/evidence,
and any predecessor or recovery evidence required by that phase. The validator
binds each stable handle's identity, exact ACL, size, timestamp, and SHA-256 into
`protected_file_set_sha256`, then binds that set and the stable workspace hash
to `validation_utc` in `validation_attestation_sha256`. Preserve those three
fields as separate protected gate evidence and enforce immediate freshness.
They must not be added to a receipt included in the file set, which would create
an impossible self-hash. A file-set change after receipt construction is a
`NO-GO` even when the receipt's internal hashes still match.

## Backup and recovery

After every accepted state change, encrypt an opaque whole-file copy of the state
to the separate operator-wrapping age recipient. SOPS is appropriate for
structured local credential files, but it leaves document structure visible;
use whole-file age encryption for state and saved-plan archives. Write the
encrypted candidate on the protected volume, verify its ciphertext hash and a
no-output restore into protected scratch, then copy it to two independent
encrypted failure domains. Retain no plaintext archive.

Quarterly and before a live deployment, restore one backup into an isolated
protected directory, verify lineage/serial/hash without contacting Cloudflare,
and record only `PASS` plus non-sensitive hashes. Compromise of the wrapping
identity requires a new identity, re-encryption of every retained archive, and
rotation of every still-valid bearer credential present in those archives.
State/topology disclosure itself cannot be revoked.

## Failure and rollback

An interrupted apply is not repaired from memory. Preserve the protected state,
revoke the token, run a fresh read-only audit, compare Cloudflare with the last
accepted state and transaction receipt, and prepare a new saved plan. Never copy
state into the repository, chat, issue tracker, GitHub artifact, CI log, or an
ordinary temp directory for troubleshooting. Rollback uses a newly audited plan
and the same phase boundary; it never broadens permissions or activates public
DNS early.
