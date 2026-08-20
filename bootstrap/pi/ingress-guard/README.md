# SSH-only admin-ingress guard (PLAT-DEC-001)

This directory defines one additive nftables guard. On every reviewed
administrative VPN ingress interface it preserves TCP 22 and terminally drops
TCP 2379, 2380, 6443, and 10250. It never owns UFW, Calico, kube-proxy,
WireGuard, routes, foreign nftables identities, or unrelated traffic.

Nothing here authorizes Pi access or a live mutation. A merged revision is a
procedure only. Live use still needs separately reviewed exact-main hashes,
two retained sessions, tested physical/LAN recovery, a fresh-login canary, an
exclusive mutation window, and direct owner authorization.

## Exact model

The sole owned identity is
`table inet website_infrastructure_ingress_guard`, containing one base chain
`admin_ingress` (`type filter hook input priority -10; policy accept`). For
each reviewed interface, rules occur in this literal order:

| Port | Verdict |
| --- | --- |
| 22 | `accept` with counter |
| 2379 | `drop` with counter |
| 2380 | `drop` with counter |
| 6443 | `drop` with counter |
| 10250 | `drop` with counter |

The `inet` family covers IPv4 and IPv6. Interface matching covers every host
address routed through the reviewed tunnel while leaving loopback, LAN, and
CNI traffic alone. The verifier rejects sets, maps, jumps, wildcard matches,
single-family variants, unknown grammar, extra objects, missing counters, and
same-name decoys. Diagnostics are fixed tokens and never contain an interface,
address, peer, ruleset, private count, or a hash of the private contract.

## Why custody is a separate stage

No privileged script executes or installs bytes by reopening a mutable
checkout path. `source-manifest.v1` is a closed SHA-256/mode inventory of all
public privileged artifacts. Stage zero is the only manual bridge:

1. the operator checks out one exact protected-main revision and proves it is
   clean;
2. the operator opens `custody-ingress-guard.sh` on a held file descriptor and
   checks that descriptor against the hash from the exact Git object;
3. `/usr/bin/install` copies that descriptor, not its pathname, to the fixed
   root-owned bootstrap path;
4. only after the root-owned copy is re-hashed may it execute;
5. its copier opens the source-root directory and every component with
   `O_NOFOLLOW`, hashes bytes read from each held descriptor, and writes those
   same bytes into a new mode-0700 root-owned custody directory;
6. each file and directory is fsynced before the custody directory is renamed
   into place and an immutable v2 custody receipt is made durable;
7. the receipt labels the revision as operator-attested (the script does not
   query Git), while binding that assertion to the exact manifest and fixed
   launcher hashes;
8. every later entrypoint and library is opened from custody with `O_NOFOLLOW`,
   re-hashed, copied into a write-sealed memfd, and only then parsed by Bash.

If power is lost after the directory rename but before its receipt commits, a
repeat invocation does not reopen the checkout: it no-follows and re-hashes the
closed root-owned tree, rejects every extra/type/mode/owner/link deviation, and
then recreates the deterministic receipt. It never overwrites an existing
custody directory or treats an unverified directory as success.

Replacement, symlink, hard-link, in-place edit, partial write, wrong mode,
missing file, foreign file, or manifest drift is a hard stop before a custody
artifact executes. The private contract is never part of this public manifest.

Use the following as a shape, not authorization. Substitute only exact values
reviewed for the merged protected-main revision. Keep the shell holding
`custody_fd` alive through `/usr/bin/install`.

```bash
revision=<40-lowercase-hex-protected-main>
test "$(git rev-parse HEAD)" = "${revision}"
test -z "$(git status --porcelain=v1)"

manifest_sha256="$({ git show "${revision}:bootstrap/pi/ingress-guard/source-manifest.v1"; } | sha256sum | awk '{print $1}')"
custody_sha256="$({ git show "${revision}:bootstrap/pi/ingress-guard/custody-ingress-guard.sh"; } | sha256sum | awk '{print $1}')"
exec {custody_fd}<bootstrap/pi/ingress-guard/custody-ingress-guard.sh
test "$(sha256sum "/proc/self/fd/${custody_fd}" | awk '{print $1}')" = "${custody_sha256}"
operator_pid="${BASHPID}"

sudo /usr/bin/test ! -e \
  /usr/local/sbin/website-infrastructure-ingress-guard-custody
sudo /usr/bin/install -o root -g root -m 0700 \
  "/proc/${operator_pid}/fd/${custody_fd}" \
  /usr/local/sbin/website-infrastructure-ingress-guard-custody
sudo /usr/bin/sha256sum \
  /usr/local/sbin/website-infrastructure-ingress-guard-custody
# Compare the public result locally with custody_sha256 before continuing.

INGRESS_GUARD_SOURCE_ROOT="${PWD}" \
INGRESS_GUARD_SOURCE_REVISION="${revision}" \
INGRESS_GUARD_MANIFEST_SHA256="${manifest_sha256}" \
INGRESS_GUARD_CUSTODY_SHA256="${custody_sha256}" \
CONFIRM_INGRESS_GUARD_CUSTODY="custody-reviewed-ingress-guard-${revision}-${manifest_sha256}" \
sudo --preserve-env=SSH_CONNECTION,INGRESS_GUARD_SOURCE_ROOT,INGRESS_GUARD_SOURCE_REVISION,INGRESS_GUARD_MANIFEST_SHA256,INGRESS_GUARD_CUSTODY_SHA256,CONFIRM_INGRESS_GUARD_CUSTODY \
  /usr/local/sbin/website-infrastructure-ingress-guard-custody --stage
```

The command must run from a direct TTY. Piping the bootstrap, invoking it from
the checkout as root, or allowing root SSH is refused.

## Private inputs

Private values exist only on the Pi under the root-owned mode-0700 input
directory. Create and review them locally; do not place them in the checkout,
Git, CI, issues, PRs, or command output.

- `input/admin-ingress.env`: root:root 0600, one link, exact contract described
  by `admin-ingress.env.example`. Its raw value, count, and content hash are
  never recorded.
- `input/retrofit-attestation.env`: root:root 0600, one link, at most 4096
  bytes, strict UTF-8. It contains only reviewed hashes and fixed acknowledgments:

```text
SCHEMA=ingress-guard-retrofit-attestation-v1
SOURCE_REVISION=<exact-protected-main-sha>
MANIFEST_SHA256=<exact-source-manifest-sha256>
BOOT_ID_SHA256=<current-boot-id-sha256>
CLUSTER_CA_SHA256=<current-cluster-ca-public-certificate-sha256>
OWNED_TABLE_PRESTATE=absent
GUARD_UNIT_PRESTATE=absent
DROPIN_PRESTATE=absent
KUBELET_PRESTATE=active
TWO_RETAINED_SESSIONS=yes
PHYSICAL_LAN_RECOVERY=yes
FRESH_LOGIN_CANARY=yes
MUTATION_WINDOW_AUTHORIZED=yes
```

The attestation validator rejects missing, duplicate, foreign, mismatched,
stale-boot, stale-cluster, symlink, hard-link, ownership, mode, encoding, and
metacharacter states. It emits only PASS/FAIL tokens. Do not rewrite this
attestation after activation: its descriptor hash and pre-reboot boot binding
are journaled. Closure reopens the same bytes, requires a different current
boot, and requires cluster CA custody to remain unchanged.

## Offline install (kubelet must be inactive)

`install-ingress-guard.sh` is the pre-kubeadm path. It intentionally exits
`KUBELET_ALREADY_ACTIVE`; there is no flag or environment bypass. Use only the
fixed root-owned launcher with a direct-TTY confirmation bound to the reviewed
revision and manifest. No checkout or custody-path entrypoint is parsed
directly. The transaction:

1. validates custody, tool identities, the exact closed systemd sandbox and
   drop-in contract from custodied bytes, private contract, inactive kubelet,
   owned-table absence, effective systemd state, destination files, and
   directory metadata;
2. durably writes the complete prestate journal before creating a directory or
   system artifact;
3. installs only exact root-owned files and never chmods/chowns a pre-existing
   directory;
4. reloads systemd, enables and starts only the guard unit;
5. proves the semantic table, persistence, and effective kubelet dependency;
6. fsyncs a closed receipt before committing the journal.

Any ordinary failure or catchable signal enters the same recovery transaction.
Power loss or `SIGKILL` leaves the prepared journal for
the fixed custody launcher's `--recover` action.

The direct-TTY invocation shape is:

```bash
INGRESS_GUARD_SOURCE_REVISION="${revision}" \
INGRESS_GUARD_MANIFEST_SHA256="${manifest_sha256}" \
INGRESS_GUARD_CUSTODY_SHA256="${custody_sha256}" \
CONFIRM_INGRESS_GUARD_INSTALL="install-reviewed-ssh-only-ingress-guard-${revision}-${manifest_sha256}" \
sudo --preserve-env=SSH_CONNECTION,INGRESS_GUARD_SOURCE_REVISION,INGRESS_GUARD_MANIFEST_SHA256,INGRESS_GUARD_CUSTODY_SHA256,CONFIRM_INGRESS_GUARD_INSTALL \
  /usr/local/sbin/website-infrastructure-ingress-guard-custody --install
```

## Running-cluster retrofit

`retrofit-ingress-guard.sh` is the only active-kubelet path. It requires the
strict attestation above and refuses an inactive kubelet. Its phase order is:

```text
prepared
  -> artifacts-installed
  -> guard-start-intent
  -> guard-active (semantic proof complete)
  -> dropin-installed (effective Requires/After proof complete)
  -> kubelet-restart-intent
  -> awaiting-reboot-intent
  -> awaiting-reboot
  -> commit-intent
  -> committed
```

The drop-in is not installed until the additive table has loaded and passed the
closed semantic model. Only then does the transaction restart kubelet once to
establish the effective dependency, prove both services and the live table,
and verify API readiness, every node Ready, Calico, the applicable three Flux
controllers, the Tunnel pair, and each present site workload. It then writes a
durable `pending-reboot` receipt. It prints `PENDING`, never `PASS`, at that
boundary.

Reboot is a separate owner-authorized action, not performed by repository
code. Keep both sessions and physical/LAN recovery until the new boot is
observed. Keep the original attestation bytes unchanged, repeat the fresh-login
and recovery checks, then use `--close-after-reboot`. Closure requires a
different current boot, the same original attestation/source/manifest and
cluster binding, active kubelet, enabled/active guard, effective dependency,
the exact live model, and the same applicable cluster-health canaries. Only
then is the final receipt fsynced and `PASS` emitted.
The pending receipt remains immutable at its result-specific path; closure
validates its journal-bound hash and writes a separate final receipt.

Activation and closure entrypoint shapes (still not live authorization) are:

```bash
INGRESS_GUARD_SOURCE_REVISION="${revision}" \
INGRESS_GUARD_MANIFEST_SHA256="${manifest_sha256}" \
INGRESS_GUARD_CUSTODY_SHA256="${custody_sha256}" \
CONFIRM_INGRESS_GUARD_RETROFIT="retrofit-reviewed-running-cluster-${revision}-${manifest_sha256}" \
sudo --preserve-env=SSH_CONNECTION,INGRESS_GUARD_SOURCE_REVISION,INGRESS_GUARD_MANIFEST_SHA256,INGRESS_GUARD_CUSTODY_SHA256,CONFIRM_INGRESS_GUARD_RETROFIT \
  /usr/local/sbin/website-infrastructure-ingress-guard-custody --retrofit-activate

# Only after a separately authorized reboot and refreshed attestation:
INGRESS_GUARD_SOURCE_REVISION="${revision}" \
INGRESS_GUARD_MANIFEST_SHA256="${manifest_sha256}" \
INGRESS_GUARD_CUSTODY_SHA256="${custody_sha256}" \
CONFIRM_INGRESS_GUARD_RETROFIT_CLOSE="close-reviewed-ingress-guard-retrofit-${revision}-${manifest_sha256}" \
sudo --preserve-env=SSH_CONNECTION,INGRESS_GUARD_SOURCE_REVISION,INGRESS_GUARD_MANIFEST_SHA256,INGRESS_GUARD_CUSTODY_SHA256,CONFIRM_INGRESS_GUARD_RETROFIT_CLOSE \
  /usr/local/sbin/website-infrastructure-ingress-guard-custody --retrofit-close
```

## Rollback and interruption recovery

All custody/install/load/retrofit operations share one root-only global lock.
The v2 journals and receipts use closed fixed schemas, mode 0600, exclusive
temp files, fsync, no-replace immutable result documents, and atomic journal
rename. A durable intent precedes every result receipt; recovery either rolls
back before publication or reconciles the exact immutable result before
claiming closure. Legacy v1 journal names are an explicit hard stop requiring
manual disposition. Records contain public source hashes and opaque
host bindings only—never raw inventory, private paths, interface counts,
addresses, peers, routes, rules, tokens, or a private-contract digest.

The loader writes `apply-intent` before `nft -f`. Once apply returns success it
arms rollback in memory before attempting the post-apply capture. Capture,
semantic verification, receipt, or journal failure therefore deletes exactly
`table inet website_infrastructure_ingress_guard` and re-proves absence. After
power loss, an exact model following absent prestate can be removed; a foreign
or unclassifiable identity is left untouched and becomes
`MANUAL_RECOVERY_REQUIRED`.

Transaction recovery removes the new drop-in before service rollback. If a
retrofit interruption left kubelet inactive, recovery restores active kubelet
while the verified guard remains active; only then may it stop the guard and
delete the exact owned table. Every created file is removed only when it still
matches its custody source; every pre-existing exact file and directory is
left untouched. Drift, failed absence proof, failed kubelet restore, or
unavailable capture preserves a fail-closed recovery journal instead of
guessing.

Manual recovery requires a direct TTY and exact fixed confirmation. It first
validates the journal-bound custody tree, then either proves the transaction
already closed or executes the same exact-prestate rollback used automatically:

```bash
CONFIRM_INGRESS_GUARD_RECOVERY=recover-reviewed-ingress-guard \
INGRESS_GUARD_SOURCE_REVISION="${revision}" \
INGRESS_GUARD_MANIFEST_SHA256="${manifest_sha256}" \
INGRESS_GUARD_CUSTODY_SHA256="${custody_sha256}" \
sudo --preserve-env=SSH_CONNECTION,INGRESS_GUARD_SOURCE_REVISION,INGRESS_GUARD_MANIFEST_SHA256,INGRESS_GUARD_CUSTODY_SHA256,CONFIRM_INGRESS_GUARD_RECOVERY \
  /usr/local/sbin/website-infrastructure-ingress-guard-custody --recover
```

## Receipts and declared limits

Successful custody, load, offline install, pending retrofit, reboot closure,
rollback, and recovery each have a distinct fixed receipt under
`/var/lib/website-infrastructure/ingress-guard/receipts`. Console output is a
single fixed token. Receipts are local protected evidence and are not copied to
GitHub.

Offline tests include a hermetic Linux namespace fixture that executes the real
shell transactions through ledgered synthetic nft/systemd/kubectl boundaries.
It covers every forward phase with failure, TERM, and SIGKILL; receipt/journal
splits; stale/tampered bindings; source symlink/hard-link/race attacks; exact
rollback; and zero temporary residue. It does not prove the Pi kernel,
nft/systemd versions, SSH survival, counters, reboot behavior, or application
reachability. Those remain separately
authorized live acceptance steps in
`docs/assurance/phase-h-ssh-only-ingress-guard.md`.
