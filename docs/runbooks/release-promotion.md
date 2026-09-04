# Release promotion — a published release opens its own reviewed pull request (issue #286)

Since the issue #275 decoupling, a merge to protected `main` deploys within
minutes. The step that advances the committed exact-digest selection is
`scripts/promote_releases.py`, run unattended on the owner's workstation:
it discovers every promotable workload from the annotated `OCIRepository`
manifests under `kubernetes/`, runs the issue-195 acquisition ceremony with
every judgment in code, rewrites every pinned copy of the selection by
counted substitution, opens the Draft promotion pull request with review
attention armed, and — on a later tick — earns that pull request its
exact-head verdict by re-deriving the whole promotion surface from the
registry and the site's immutable Release ("Receipts by proof" below). It
never flips Ready and never merges: the coordinator
flips under AGENTS.md's one rule and the owner merges. `scripts/ready_check.py`
evaluates that rule read-only, proving exactly that the pull request is open,
targets the default branch, is not behind it, carries an App-posted exact-head
APPROVE with no REQUEST-CHANGES at that head, and has green required checks and
intact labels. It prints the approving lanes beside the tier labels and judges
neither against the other: that match is the coordinator's.
The deploy-assurance watchdog stays the loud
backstop: a promotion the tool cannot open leaves the watchdog's drift issue
open, with one comment naming the failed step.

Authority: the tool runs under the owner's own keyring credential and SSH
signing key, so every promotion commit carries the owner's noreply identity
and a verified signature exactly like a hand-run promotion. No new
principal, no credential in CI. Every judgment lives in the tool, whose
battery is `tests/security/test_promote_releases_contract.py`; the command
blocks below are pinned byte for byte against `RUNBOOK_BLOCKS` there, so a
neutralized or smuggled invocation is a red test, never prose drift.

## Extending to a new workload

Commit the workload's `OCIRepository` with the
`platform.snaraj.dev/chart-release` annotation, an exact `ref.digest`, the
`oci://` chart URL and the cosign `matchOIDCIdentity` of its publisher. The
tool reads the identity tuple from that document and selects the
acquisition profile from the publisher identity; a publisher this tool has
no profile for is refused, never guessed, so a NAS, vault, mesh or GPU chart
from a different publisher lands as one new profile in `PROFILES`, not a
rewrite. The receipt contract in `scripts/ci/platform_release_contract.py`
still binds exactly the two site identities; extending that closure is a
separate reviewed change per workload.

## Install (once per workstation)

The tool works in its own clone so the coordination checkout stays clean.
Clone over HTTPS: `gh`'s credential helper supplies the push credential,
and the loaded SSH key signs:

```sh
repo="$HOME/Library/Application Support/release-promoter/website-infrastructure"
mkdir -p "$(dirname "$repo")"
git clone --quiet https://github.com/snaraj/website-infrastructure.git "$repo"
```

Prove the credentials and the toolchain from a login shell before anything
runs unattended — a dry run performs every read and every gate and prints
what it would push, without committing, pushing, opening or flipping:

```sh
python3 -I -B "$repo/scripts/promote_releases.py" tick --repo "$repo" --dry-run
```

Then install the user agent. The plist is emitted by the tool with the
paths as arguments — no machine path is ever committed. `--token-command`
names the machine-local helper that mints the reviewer App's
repository-scoped token; it reaches the tick as the environment variable
`PROMOTER_RECEIPT_TOKEN_COMMAND`, takes `owner/repository` as its only
argument, and prints one token on stdout (diagnostics on stderr, which is the
only stream a failure is ever quoted from). Omit the flag and the promoter
still runs every proof and posts nothing:

```sh
receipt_helper="$HOME/path/to/agent-reviews-token"
python3 -I -B "$repo/scripts/promote_releases.py" launchd-plist --repo "$repo" --log "$HOME/Library/Logs/release-promoter.log" --token-command "$receipt_helper" > "$HOME/Library/LaunchAgents/dev.snaraj.release-promoter.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.snaraj.release-promoter.plist"
```

The agent runs at load and every 5 minutes while the workstation is awake
and the owner is logged in (the keyring and the ssh-agent are unlocked by
that session). A tick that finds another live tick's lock skips: the lock
is held by the operating system and released when its holder exits, however
it exits, so no stale lock survives a crash and none is ever reaped by age.
Every command a tick runs is bounded (ten minutes; the gates sixty; cosign
two, with one retry), so a hung tick cannot hold the lock indefinitely and a
stalled signature check costs seconds rather than a silent ten minutes.

## Operate

Run a tick now and read the tail of the log:

```sh
launchctl kickstart -k "gui/$(id -u)/dev.snaraj.release-promoter"
tail -n 40 "$HOME/Library/Logs/release-promoter.log"
```

Each tick logs one line per workload (`committed X vs latest Y -> verdict`),
every gate it ran, and the Draft pull request it opened. After the signed commit the tick runs
`make pre-push-security` on the exact outgoing commit and pushes only when
it passes; a refusal pushes nothing. Only pull requests that satisfy the
owned-promoter identity tuple (owner-authored, promoter branch of this
repository against `main`; labels are authorization inputs, not identity,
so a stripped label never removes the pull request from the tool's view) are
ever planned or superseded; a failure comment on the drift issue is redacted of every path and
host detail, the raw text staying in the local log. A promotion pull request that falls behind `main` or
whose target release moves on is closed as superseded and re-cut on the
next tick; nothing is ever amended, rebased or force-pushed.

### Reading the log

Every line carries the UTC timestamp first. After it, five shapes:

- `<slug>: committed X vs latest Y -> verdict` — one per workload, per tick.
- `START <kind> <target> budget=<n>s` — a long external call is beginning.
  `<kind>` is one of `registry-token`, `registry-manifest`, `registry-blob`,
  `release-asset`, `cosign-verify-chart`, `cosign-verify-provenance`,
  `github-api`, `github-list`, `github-write`, `github-command`, `git-fetch`,
  `git-push`, `gate`, `receipt-token`, `receipt-post`. The target names the
  repository, reference or digest; it never carries a token, an
  `Authorization` value or a workstation path.
- `DONE <kind> <target> elapsed=<n>s OK` — or, on failure, `elapsed=<n>s
  FAILED decision=<retry|refuse|skip-this-tick> reason=<redacted>`. The
  decision is on the failing line itself: reading the log never means
  correlating two lines to learn what a stall cost. Cosign is bounded at 120
  seconds per attempt with exactly one retry, so its first failure reads
  `attempt=1/2 ... decision=retry`.
- `PROOF <novelty|confinement|re-derivation|subject> pull-request=<n>
  head=<sha7> <held|failed: what|skipped: why> elapsed=<n>s` — one per proof.
- `SUMMARY tick elapsed=<n>s dry-run=<bool> <key>=<value> …` — the last line
  of every tick, on every exit path, with one key per workload
  (`current`/`behind`/`ahead`) and one per pull request it touched
  (`cut=`, `pull-request-N=superseded`, `receipt-N=posted:APPROVE`,
  `receipt-N=skipped`, `receipt=unconfigured`). `SUMMARY receipt …` is the
  same line from a standalone `receipt` run.

A tick that ends without a `SUMMARY` line died in a way the tool did not
survive; that is the one shape worth escalating on sight.

## Disable

```sh
launchctl bootout "gui/$(id -u)/dev.snaraj.release-promoter"
```

The repository keeps working exactly as before: a hand-run promotion is
still a valid promotion.

## Manual use

From any checkout, `status` compares every committed selection with the
latest published release (exit 3 when any workload is not current — behind,
ahead or unpublished alike):

```sh
python3 -I -B scripts/promote_releases.py status
```

`verify` re-derives the committed receipt from the registry and requires it
to reproduce — the tool's own correctness proof against `main`, and a
standing custody check that the registry still serves what is committed:

```sh
python3 -I -B scripts/promote_releases.py verify
```

`receipt` runs the tick's receipt step alone, under the same lock and over
the same pull requests, so a manual run can never race the scheduled one or
post a verdict the tick would not. A dry run performs every proof, validates
the composed receipt and stops before posting:

```sh
PROMOTER_RECEIPT_TOKEN_COMMAND="$receipt_helper" python3 -I -B "$repo/scripts/promote_releases.py" receipt --repo "$repo" --dry-run
```

## Receipts by proof

A promotion pull request's verdict is EARNED, not requested. On every tick,
for each open promoter pull request the planner keeps — owner-authored, a
promoter branch of this repository against `main`, current with `main` — the
tool proves three things and reads nothing from the pull request itself:

1. **Novelty.** No `snaraj-agent-reviews[bot]` comment already binds this
   exact head, matched on the App's four-part actor identity, so a head is
   judged at most once.
2. **Confinement.** Every path the head changes against `main` is a path the
   promoter's own `apply_promotion` writes. The permitted set is that
   function's return value from the re-derivation below, never a list kept in
   the tool, so it cannot go stale as the promotion surface grows.
3. **Re-derivation.** In a detached read-only worktree at `main`, the
   issue-195 acquisition ceremony runs again — double tag resolution, the
   Helm config and sole chart layer at their own digests, the embedded
   workload pin bound to the exact index, one `linux/arm64` child, cosign on
   the chart AT ITS DIGEST and on the SLSA v1 provenance at the index digest,
   the immutable Release and its `release-manifest.json` bound by GitHub's own
   asset digest, and the annotated tag dereferenced to a commit reachable from
   the site's protected `main`. The whole promotion surface is then re-rendered
   from that record and every blob compared to the head's by Git object id.
   One mutated byte anywhere is a different id.

All three hold and the App posts `VERDICT: APPROVE` at that head, validated by
`scripts/validate_review_receipt.py` first and with the live head re-read
immediately before posting — a head that moved aborts the post. The
`requires-review` label comes off with an APPROVE. A definitive failure of
proof 2 or 3 posts `VERDICT: REQUEST-CHANGES` naming the proof and the
mismatch and does nothing else: the label stays armed, because the pull
request still needs a human to look, and a promotion pull request is never
repaired in place — the fix lands in the promoter's code and the promoter
re-cuts. A refusal it cannot attribute to the pull request — the registry,
the Release, cosign, the network — is neither verdict: it is logged and the
head is judged again on the next tick.

The capture date is the one value taken from the head, because the cut stamps
the day it ran and no registry can return it; it must be a plain ISO date
within a day of the head commit's own signed author timestamp, and anything
else is a mutation that fails proof 3.

The token never enters an argument list, a log line or a file: the helper
named by `PROMOTER_RECEIPT_TOKEN_COMMAND` mints it, and it is handed to
exactly one `gh pr comment` subprocess through its environment. With the
variable unset the step reports itself unconfigured and composes nothing.

**What is NOT automated.** Ready and merge. `scripts/ready_check.py` remains
the only expression of the Ready rule, the coordinator alone flips, and the
owner alone merges. A receipt is review evidence and nothing more.

## Loop timing

Three bounds decide how long a published site release waits for the cluster,
and none of them is a control:

- the promoter tick, `StartInterval` 300 — a read-only poll of the sites'
  latest releases and this repository's open pull requests;
- both sites' `OCIRepository` and `HelmRelease` `interval: 1m0s` — Flux
  polling references it has already signature-verified;
- the review and the owner's merge, which are the only human steps left.

There is deliberately no Flux `Receiver`: a webhook would add an inbound
path, a shared secret and a new object to buy the same minute that a poll of
already-verified state buys for nothing (AGENTS.md safety invariant 3, issue
#309). Every ceremony judgment, gate, scan, signature and identity pin is
unchanged by the shorter intervals.
