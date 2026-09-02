# Release promotion — a published release opens its own reviewed pull request (issue #286)

Since the issue #275 decoupling, a merge to protected `main` deploys within
minutes. The step that advances the committed exact-digest selection is
`scripts/promote_releases.py`, run unattended on the owner's workstation:
it discovers every promotable workload from the annotated `OCIRepository`
manifests under `kubernetes/`, runs the issue-195 acquisition ceremony with
every judgment in code, rewrites every pinned copy of the selection by
counted substitution, and opens the Draft promotion pull request with both
review lanes armed. It flips Ready only when the exact head carries two
distinct adversarial APPROVE receipts in the repository's canonical receipt
shape, both required checks green from GitHub Actions and a current base,
all read at the moment of the flip, read AGAIN after it, and read once more
after the security routing label leaves: each read must pass the same
judgment at the same head. A head, receipt, label, check or base that
changes across those reads is compensated: Draft is restored and both lanes
re-armed, and the restore is claimed only from a read that shows Draft with
both lanes. A restore that cannot be proven posts a
`promoter-alert unresolved-ready` comment stating exactly what was observed
and fails loudly for the operator. Every tick re-judges an open Ready
promotion pull request and withdraws it to Draft with both lanes re-armed
(`promoter-note ready-withdrawn`) when its head no longer carries the
authorization or any input of it can no longer be read; a promoter label
someone removed is a blocker, not an escape from the tool's view. That
bounds the time Ready can outlive a lapsed authorization to one tick
period (15 minutes); the receipts stay visible on the pull request for the
merge click, and only an authoritative status computed at the head (the
#289 lift) can make the bound zero. The owner alone merges. The deploy-assurance watchdog stays the loud
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

The agent runs at load and every 15 minutes while the workstation is awake
and the owner is logged in (the keyring and the ssh-agent are unlocked by
that session). A tick that finds another live tick's lock skips: the lock
is held by the operating system and released when its holder exits, however
it exits, so no stale lock survives a crash and none is ever reaped by age.
Every command a tick runs is bounded (ten minutes; the gates sixty), so a
hung tick cannot hold the lock indefinitely.

## Operate

Run a tick now and read the tail of the log:

```sh
launchctl kickstart -k "gui/$(id -u)/dev.snaraj.release-promoter"
tail -n 40 "$HOME/Library/Logs/release-promoter.log"
```

Each tick logs one line per workload (`committed X vs latest Y -> verdict`),
every gate it ran, the Draft pull request it opened or the Ready decision it
made with its reasons. After the signed commit the tick runs
`make pre-push-security` on the exact outgoing commit and pushes only when
it passes; a refusal pushes nothing. Only pull requests that satisfy the
owned-promoter identity tuple (owner-authored, promoter branch of this
repository against `main`, promoter labels) are ever planned, superseded or
flipped; a failure comment on the drift issue is redacted of every path and
host detail, the raw text staying in the local log. A promotion pull request that falls behind `main` or
whose target release moves on is closed as superseded and re-cut on the
next tick; nothing is ever amended, rebased or force-pushed.

## Disable

```sh
launchctl bootout "gui/$(id -u)/dev.snaraj.release-promoter"
```

The repository keeps working exactly as before: a hand-run promotion is
still a valid promotion.

## Manual use

From any checkout, `status` compares every committed selection with the
latest published release (exit 3 when any workload is behind):

```sh
python3 -I -B scripts/promote_releases.py status
```

`verify` re-derives the committed receipt from the registry and requires it
to reproduce — the tool's own correctness proof against `main`, and a
standing custody check that the registry still serves what is committed:

```sh
python3 -I -B scripts/promote_releases.py verify
```
