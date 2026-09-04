# Release promotion — a published release opens its own reviewed pull request (issue #286)

Since the issue #275 decoupling, a merge to protected `main` deploys within
minutes. The step that advances the committed exact-digest selection is
`scripts/promote_releases.py`, run unattended on the owner's workstation:
it discovers every promotable workload from the annotated `OCIRepository`
manifests under `kubernetes/`, runs the issue-195 acquisition ceremony with
every judgment in code, rewrites every pinned copy of the selection by
counted substitution, and opens the Draft promotion pull request with both
review lanes armed. It never flips Ready and never merges: the coordinator
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
paths as arguments — no machine path is ever committed:

```sh
python3 -I -B "$repo/scripts/promote_releases.py" launchd-plist --repo "$repo" --log "$HOME/Library/Logs/release-promoter.log" > "$HOME/Library/LaunchAgents/dev.snaraj.release-promoter.plist"
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

Every line carries the UTC timestamp first. After it, four shapes:

- `<slug>: committed X vs latest Y -> verdict` — one per workload, per tick.
- `START <kind> <target> budget=<n>s` — a long external call is beginning.
  `<kind>` is one of `registry-token`, `registry-manifest`, `registry-blob`,
  `release-asset`, `cosign-version`, `cosign-verify-chart`,
  `cosign-verify-provenance`, `github-api`, `github-list`, `github-write`,
  `github-command`, `git-fetch`, `git-push`, `gate`. The target names the
  repository, reference or digest; it never carries a token, an
  `Authorization` value or a workstation path.
- `DONE <kind> <target> elapsed=<n>s OK` — or, on failure, `elapsed=<n>s
  FAILED decision=<retry|refuse|skip-this-tick> reason=<redacted>`. The
  decision is on the failing line itself: reading the log never means
  correlating two lines to learn what a stall cost. Cosign is bounded at 120
  seconds per attempt with exactly one retry, so its first failure reads
  `attempt=1/2 ... decision=retry`.
- `SUMMARY tick elapsed=<n>s dry-run=<bool> <key>=<value> …` — the last line
  of every tick, on every exit path, with one key per workload
  (`current`/`behind`/`ahead`) and one per pull request it touched
  (`cut=`, `pull-request-N=superseded`).

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
