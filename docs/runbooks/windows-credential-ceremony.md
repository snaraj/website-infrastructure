# Windows credential ceremony — Draft / unverified

This ceremony covers the operator-wrapping age identity, Cloudflare API/Tunnel
tokens, OpenTofu private variables, state, plans, and raw audit responses. It is
an operator action, never CI automation. Do not begin while screen sharing,
recording, transcription, shell tracing, or support telemetry can capture the
session.

## Protected workspace

Use a dedicated BitLocker-protected NTFS volume or fixed VHDX outside the
repository, cloud-sync folders, indexed folders, and ordinary backup agents.
The workspace root must be that volume's drive root, and the volume must be
different from both the Windows system volume and the repository volume; a
restricted subdirectory on either existing volume is not sufficient.
The OS volume and every volume selected by configured or active pagefiles,
crash dumps, minidumps, or a dedicated dump file must also be fully BitLocker
protected because process residue may land there. Encryption must exist before
the first plaintext is created; deletion from an SSD is not a secrecy control.

Before each ceremony, verify without listing contents:

- the resolved root is absolute, outside the repository, and not a reparse point;
- its owner is the intended operator SID;
- ACL inheritance is disabled and only that operator and `SYSTEM` have access;
- the volume is mounted, BitLocker protection is active, and recovery material
  is stored in a different failure domain;
- the Windows system volume and every pagefile/crash-dump backing volume are
  fully encrypted before secrets can reach them;
- `TEMP`, `TMP`, `TF_DATA_DIR`, `TF_PLUGIN_CACHE_DIR`, `TF_CLI_CONFIG_FILE`,
  and all explicit output paths resolve inside this root and retain only the
  operator-and-`SYSTEM` ACL; and
- no OneDrive/cloud sync, Windows Search indexing, clipboard history/cloud sync,
  terminal capture, or editor backup is active for the root.

Set `WEBSITE_INFRA_CREDENTIAL_ROOT` only in the private process using an
interactive path selection. Run the repository copy of
`scripts/validate-windows-credential-workspace.ps1` with the checkout's absolute
root supplied through `-RepositoryRoot`. If a coordinating gate executes a
byte-for-byte validator snapshot from the protected volume, it must still pass
the actual checkout root explicitly; the validator binds its own bytes rather
than its copy-specific path or file identity.

After protected `TEMP`, `TMP`, `TF_DATA_DIR`, and `TF_PLUGIN_CACHE_DIR`
directories plus an explicit `TF_CLI_CONFIG_FILE` are configured, repeat the
gate with `-Session`. Before an authenticated operation, pass every input and
evidence artifact as an array-valued `-ProtectedFile` argument. Build that array
inside the private process from interactive selections; do not type sensitive
paths into saved command history.

```powershell
$protectedArtifacts = @($selectedPlan, $selectedState, $selectedReceipt)
& $validator -Root $env:WEBSITE_INFRA_CREDENTIAL_ROOT `
    -RepositoryRoot $checkoutRoot -Session `
    -ProtectedFile $protectedArtifacts
```

Each protected file must be an absolute strict descendant of the workspace, a
regular non-reparse file with exactly one hard-link name, the current operator
as owner, and exactly two full-control DACL entries: that operator and `SYSTEM`.
The validator takes an exclusive no-follow handle, checks identity and ACL
before and after hashing the bytes, and rejects duplicates or any change during
the read. `TF_CLI_CONFIG_FILE` receives the same validation even when it is not
listed separately.

The gate is read-only. It queries the registry and CIM for configured and active
pagefile locations plus crash, mini-, and dedicated-dump locations, resolves
only unambiguous local drive-letter paths, and requires every resulting volume
to report active, 100-percent, fully encrypted BitLocker protection. An
unavailable inventory, wildcard, device path, unresolved environment variable,
unknown dump mode, or unresolved destination is a `NO-GO`; do not elevate the
ceremony shell or weaken the check to make the query pass.

With no protected-file argument, success remains exactly `PASS` plus the stable
`workspace_attestation_sha256`. With protected files, success also emits only a
`protected_file_set_sha256`, canonical `validation_utc`, and
`validation_attestation_sha256`. The workspace hash binds root/session
configuration, exact ACLs, CLI configuration bytes, pagefile/dump inventory,
BitLocker results, repository root, validator bytes, and PowerShell host
provenance. The separate file-set hash binds artifact identities, sizes,
timestamps, ACLs, and byte hashes. The validation hash binds both hashes to the
current process start and UTC second. Keeping the file-set hash outside a
receipt that is itself in the set avoids a circular hash dependency.

The gate prints only bounded PASS fields or one fixed, path-free failure; it
does not make the directory safe or repair ACL/encryption settings. Preserve
`workspace_attestation_sha256` only inside the protected transaction receipt,
and preserve the file-set/freshness output only in the separate protected gate
evidence. Rerun the gate and discard saved plans if the stable workspace hash
changes. Treat a stale `validation_utc`, a changed file-set hash, or a changed
validation hash as a `NO-GO`.

Session validation also rejects ambient `TF_CLI_ARGS*`, OpenTofu debug/logging,
workspace, provider-reattachment, and lockfile-bypass settings, plus Cloudflare's
legacy global-key authentication variables. It rejects nonempty `GH_TOKEN`,
`GITHUB_TOKEN`, enterprise variants, `GIT_ASKPASS`, `SSH_ASKPASS`,
`SSH_AUTH_SOCK`, `SSH_AGENT_PID`, Git SSH/helper/prompt overrides, every
`GIT_CONFIG_*`, and every `GCM_*` variable. Use only the one phase's
`CLOUDFLARE_API_TOKEN`; do not enable provider tracing during a credential
ceremony.

An administrator can take ownership of NTFS data and malware in the operator's
session can read unlocked files. The ceremony reduces persistence and accidental
disclosure; it does not turn a compromised workstation into a trusted one.

## Private process

Use a fresh, non-elevated, no-profile shell. The gate rejects an administrator
token or high/system integrity; an inability to read the required security
inventory from that shell is a failure, not permission to run the token-bearing
process elevated. Disable PowerShell transcription,
debug tracing, and PSReadLine history for that process; do not use
`ExecutionPolicy Bypass`. Pin absolute paths to verified, checksummed age,
OpenTofu, Git, and Cloudflare tooling. Reject symlinks/reparse points at every
input and output boundary.

The environment checks do not prove that Windows Credential Manager contains no
GitHub entry, that a machine-wide SSH agent has no loaded Pi key, or that another
desktop process cannot access the unlocked operator profile. Before introducing
the Cloudflare token, use a separate OS/process trust domain in which GitHub
publishing credentials, Git credential helpers, and Pi private-key authority
are unavailable. Do not stop or alter an existing SSH process automatically;
an established transport can remain open, but it is not evidence that its
credential authority is isolated from the ceremony. Re-enable Git publication
authority only after the phase token is revoked and the private workspace is
closed.

The attestation is a local hash record, not a signature, TPM quote, malware
scan, or independent proof of operator statements. It binds the validator and
PowerShell host but does not replace separate checksum/signature verification
for age, OpenTofu, providers, or Cloudflare tooling.

Select secret file paths interactively or through protected file pickers. Never
put a token, identity, passphrase, account ID, tunnel ID, private address, or
recovery path in a command-line literal. Prefer supported credential files or
process-local environment variables. Clear each environment variable immediately
after its one command. Never print decrypted content; a successful check records
only `PASS`, a bounded object count, and/or a SHA-256 digest that is not itself
sensitive.

## Identity hierarchy

This Windows gate applies only when Windows is the ceremony host. Prefer a
separate, offline trusted machine for generating the operator-wrapping identity
and performing recovery-copy restore tests. That machine needs its own reviewed
encrypted-storage, access-control, residue, backup, and tool-provenance
ceremony; using it does not weaken any Windows requirement when Windows handles
other credentials. Private identities, decrypted recovery material, and restore
test plaintext must never transit Git, chat, email, cloud sync, a shared
clipboard, or an ordinary removable filesystem.

A `workspace_attestation_sha256` produced here is a local integrity summary,
not a signature that another machine can verify, and must not be exported as if
it authorized a process on another host. If Windows is used to prepare
Cloudflare/OpenTofu artifacts while Linux handles the archives, treat the
transfer as a separate encrypted, authenticated custody ceremony and validate
every destination file again.

Generate one hybrid post-quantum **operator-wrapping identity** with the pinned
`age-keygen -pq`. Its private identity never enters Git, CI, the Pi, Kubernetes,
or a backup encrypted only to itself. It wraps private recovery material and
opaque OpenTofu archives. Maintain two independently protected recovery copies
without a circular dependency.

Verify the exact pinned age version with disposable ciphertext before use. Also
verify publisher signature/provenance material and the Linux AMD64 executable
hashes pinned in `versions.env`; matching `--version` output alone does not
exclude a wrapper that can read an identity.

## Cloudflare credentials

Create a distinct, named, just-in-time token for the read-only audit and for each
approved phase root. Never let one apply token span two roots or both DNS zones.
Each account phase receives only its documented provider-required permission
group for the exact account; each DNS phase receives `DNS Write` for one exact
zone. Cloudflare tokens cannot be restricted to one Tunnel, route, Gateway rule,
or DNS record, so the receipt must state that unavoidable wider resource-class
or zone reach rather than claiming object-level authorization. Never grant
billing, subscription, registrar, member, API-token administration, GitHub, or
cluster authority. Use the shortest practical expiry and a proven source-IP
condition when the operator egress is stable. Record a bounded non-secret policy
receipt and revoke each token immediately after its one job; verify revocation
with a separate credential.

`pi-admin` and the two per-site public Tunnel tokens are distinct bearer
credentials. Never retrieve them through OpenTofu state. Keep them all out of
Git: each public token is installed as its own cluster Secret by its own
ceremony.
Follow the Tunnel rotation runbook after any suspected capture.

## Closeout

Complete the exact-index secret/privacy scan before Git operations. Remove
plaintext scratch, clear process-local secret variables and clipboard contents,
close the private process, unmount the protected volume when practical, and
confirm no plaintext appeared in the repository, generic temp directories,
shell history, transcripts, crash logs, editor backups, or cloud sync. Preserve
only encrypted archives and bounded non-secret receipts.
