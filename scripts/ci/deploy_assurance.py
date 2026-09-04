"""Deploy assurance: own the promise that published site releases reach the
committed desired state and that the platform publish path is healthy.

Two independent GitHub-side conditions, each loud on failure (issue #273;
the 2026-09-01 incident this answers: the live cluster served naranjo.online
v0.1.63 while v0.1.67 was published, every component "green", nothing
alerted — the committed selection had silently fallen behind and a failed
platform-release run had died on a transient token-mint 422 with no retry):

1. SITE SELECTION DRIFT — for every ``kubernetes/websites/*/source.yaml``,
   the site repository of record is derived from the cosign
   ``matchOIDCIdentity`` subject (the identity that signs the chart names
   the repository), its latest published release is fetched, and a newer
   published release than the committed ``platform.snaraj.dev/chart-release``
   annotation is a condition. A committed annotation naming a release the
   site never published is a separate, worse condition.
2. PLATFORM PUBLISH INTEGRITY — the newest completed protected-main gate
   run whose conclusion is SUCCESS (a cancelled or failed gate authorized
   no release and never anchors the check; no successful anchor at all is
   itself the fail-closed condition, preserving any standing tracker) must
   have a ``Platform release`` run at the same head SHA that concluded
   successfully (a no-artifact merge still concludes success: it logs its
   verdict and publishes nothing, so this check needs no classification
   knowledge). A first-attempt conclusion of exactly ``failure`` is
   retried exactly once via ``rerun-failed-jobs`` — under ``--apply``
   only, and a failed dispatch still records the condition; every other
   completed conclusion is a fail-closed ``abnormal`` condition that never
   reruns; a run not completed past the two-hour runtime allowance is
   ``stuck``; absence after the grace window or a repeated failure is a
   condition.

Any active condition exits 1 (a red scheduled run) and, with ``--apply``,
maintains exactly one open tracking issue per condition key — opened when
the condition appears, closed with a resolution comment when it clears.
Without ``--apply`` the same decisions print but nothing mutates.

Standard library only. The one credential is ``GITHUB_TOKEN``; no cluster,
registry, or external service is contacted.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
SITES_DIR = Path("kubernetes/websites")
ISSUE_MARKER = "deploy-assurance["
ISSUE_LABELS = ["ci", "delivery-lane", "agent-authored", "fable5"]
SIGNATURE = "- Fable5"
ESTIMATE_HEADING = "## Estimate"
# ASCII only and bounded. `\d` also matches Unicode decimal digits — Arabic-Indic
# ٣ among them — which `int` then accepts, so a label could round-trip through a
# spelling no reader typed.
DIGITS = "[0-9]{1,6}"
# The one place a label is tied to a field. The set the parser requires is
# DERIVED from the dataclass below, so a field cannot be half-added.
ESTIMATE_LABELS = {"files": "files", "net lines": "net_lines", "review rounds": "review_rounds"}
GATE_WORKFLOW = "pull-request.yml"
PUBLISH_WORKFLOW = "platform-release.yml"
# A publish run that has not appeared this soon after its gate completed is
# still "pending", not yet a condition: workflow_run dispatch plus queue time
# is ordinarily seconds, and one scheduled interval later the verdict is real.
PENDING_GRACE_SECONDS = 20 * 60
# A publish run still queued/waiting/in progress past this allowance is STUCK,
# a condition in its own right — the publisher ordinarily finishes in minutes,
# and "pending forever" is exactly how a wedged run stays silent (round-2
# review finding: a seven-day-old in_progress run classified as pending).
STUCK_RUN_SECONDS = 2 * 60 * 60
# The one conclusion that authorizes the bounded rerun-failed-jobs dispatch.
# Every other completed conclusion (cancelled, skipped, neutral,
# action_required, timed_out, stale, startup_failure, anything future) is a
# fail-closed condition WITHOUT a rerun: the write authority reaches exactly
# the reviewed first-failed-attempt state and nothing else.
RETRYABLE_CONCLUSIONS = frozenset({"failure"})

ANNOTATION_PATTERN = re.compile(
    r'^\s*platform\.snaraj\.dev/chart-release:\s*"(\d+\.\d+\.\d+)"\s*$',
    re.MULTILINE,
)
SUBJECT_PATTERN = re.compile(
    r"^\s*subject:\s*\^https://github\\\.com/([^\s]+?)/\\\.github/",
    re.MULTILINE,
)


def parse_site_selection(text):
    """Return ``(committed_version, site_repository)`` from one source.yaml.

    The repository comes from the cosign subject, so the assurance target is
    exactly the repository whose publisher identity the cluster verifies —
    never a hand-maintained mapping that can drift on its own.
    """

    annotation = ANNOTATION_PATTERN.search(text)
    subject = SUBJECT_PATTERN.search(text)
    if annotation is None or subject is None:
        return None
    return annotation.group(1), subject.group(1).replace("\\.", ".")


def semver_tuple(version):
    return tuple(int(part) for part in version.split("."))


def drift_verdict(committed, latest_published):
    """Classify one site's committed selection against its latest release.

    ``latest_published`` arrives with its ``v`` prefix stripped. Returns one
    of ``"current"`` (equal), ``"behind"`` (a newer release is published),
    or ``"ahead"`` (the committed annotation names something newer than any
    published release — an integrity failure, not a race).
    """

    committed_t, latest_t = semver_tuple(committed), semver_tuple(latest_published)
    if committed_t == latest_t:
        return "current"
    return "behind" if committed_t < latest_t else "ahead"


def publish_verdict(gate_age_seconds, publish_run, run_age_seconds):
    """Classify the publish leg for the newest successful main gate SHA.

    ``publish_run`` is the matching Platform release run summary (or None):
    ``{"status": ..., "conclusion": ..., "run_attempt": int}``;
    ``run_age_seconds`` is that run's own age (None when there is no run).
    Returns one of ``"ok"``, ``"pending"``, ``"stuck"`` (not completed past
    the runtime allowance — a wedged run must go loud, never stay pending
    forever), ``"absent"``, ``"retry"`` (concluded exactly ``failure`` on
    its first attempt — rerun exactly once), ``"failing"`` (``failure``
    again after the bounded retry), or ``"abnormal"`` (any other completed
    conclusion — cancelled, skipped, neutral, action_required, timed_out,
    stale, or anything future/unknown — a fail-closed condition that never
    authorizes the rerun write).
    """

    if publish_run is None:
        return "pending" if gate_age_seconds < PENDING_GRACE_SECONDS else "absent"
    if publish_run.get("status") != "completed":
        if run_age_seconds is not None and run_age_seconds > STUCK_RUN_SECONDS:
            return "stuck"
        return "pending"
    if publish_run.get("conclusion") == "success":
        return "ok"
    if publish_run.get("conclusion") not in RETRYABLE_CONCLUSIONS:
        return "abnormal"
    return "retry" if publish_run.get("run_attempt") == 1 else "failing"


def condition_title(key):
    """One stable title per condition key — the idempotency anchor."""

    return "{}{}]".format(ISSUE_MARKER, key)


@dataclasses.dataclass(frozen=True)
class Estimate:
    """The estimate AGENTS.md requires of a commission, as integers.

    A tracking issue this tool opens IS the commission for the pull request
    answering it, and the hourly rewrite erased the estimate a coordinator added.
    Preserving it as TEXT failed twice, so it is parsed into this type and
    rendered back from it: nothing from the issue is on the output path, which
    closes "another spelling rides along" by construction rather than by
    enumerating spellings (PR #303; PR #305 rounds 1-3, design reset).
    """

    files: int
    net_lines: int
    review_rounds: int


# The sign is required on net lines and refused elsewhere; `fullmatch` below
# means a field carrying trailing text is not a field.
ESTIMATE_PATTERNS = {
    label: re.compile("- " + re.escape(label) + ": ("
                      + ("[+-]" if field == "net_lines" else "") + DIGITS + ")")
    for label, field in ESTIMATE_LABELS.items()
}


def parse_estimate(body):
    """One ``Estimate``, or ``None`` for every other body. Never raises.

    Exactly one whole-line heading, then one line per field — blank lines
    ignored, the trailing lane signature dropped, labels unique, the label set
    equal to the dataclass's own. Any deviation preserves nothing and the
    regenerated evidence wins: the fail-closed direction.
    """

    lines = body.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and lines[-1] == SIGNATURE:
        lines.pop()
    if [line for line in lines if line == ESTIMATE_HEADING] != [ESTIMATE_HEADING]:
        return None
    values = {}
    for line in lines[lines.index(ESTIMATE_HEADING) + 1:]:
        if not line.strip():
            continue
        hits = [(f, m) for label, f in ESTIMATE_LABELS.items()
                for m in [ESTIMATE_PATTERNS[label].fullmatch(line)] if m]
        if len(hits) != 1 or hits[0][0] in values:
            return None
        values[hits[0][0]] = int(hits[0][1].group(1))
    if values.keys() != {f.name for f in dataclasses.fields(Estimate)}:
        return None
    return Estimate(**values)


def render_estimate(estimate):
    """The canonical block, built from the integers — so leading zeros and any
    other spelling the writer used normalise away instead of being copied."""

    fields = "\n".join(
        "- {}: {}".format(label, format(getattr(estimate, field), "+d" if field == "net_lines" else "d"))
        for label, field in ESTIMATE_LABELS.items()
    )
    return "\n\n" + ESTIMATE_HEADING + "\n\n" + fields


def iso_age_seconds(stamp):
    """Seconds elapsed since an ISO-8601 GitHub timestamp."""

    return (
        datetime.now(timezone.utc)
        - datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    ).total_seconds()


class GitHub:
    """The thin REST layer; every decision above stays network-free."""

    def __init__(self, token, repository):
        self.token = token
        self.repository = repository

    def request(self, method, path, body=None):
        request = urllib.request.Request(
            API_ROOT + path,
            method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
        # An empty body (204 mutations) decodes to an empty mapping so read
        # paths fail loudly on a missing key instead of a None subscript.
        return json.loads(payload) if payload else {}

    def latest_release(self, repository):
        """Return ``(tag_name, published_at)`` or ``(None, None)`` on 404."""

        try:
            release = self.request("GET", "/repos/{}/releases/latest".format(repository))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None, None
            raise
        return release["tag_name"], release.get("published_at")

    def newest_main_gate_run(self):
        """The newest completed main gate run whose conclusion is success.

        ``status=completed`` is a STATUS, not a conclusion — it also covers
        cancelled, skipped, and timed-out runs, none of which authorized a
        release, so anchoring on one of those would demand a Platform
        release nothing dispatched. Only a successful gate is a valid
        publish anchor; a failed gate is main CI's own loud problem.
        """

        runs = self.request(
            "GET",
            "/repos/{}/actions/workflows/{}/runs"
            "?branch=main&event=push&status=completed&per_page=30".format(
                self.repository, GATE_WORKFLOW
            ),
        )["workflow_runs"]
        for run in runs:
            if run.get("conclusion") == "success":
                return run
        return None

    def publish_run_for(self, head_sha):
        runs = self.request(
            "GET",
            "/repos/{}/actions/workflows/{}/runs?per_page=30".format(
                self.repository, PUBLISH_WORKFLOW
            ),
        )["workflow_runs"]
        for run in runs:
            if run["head_sha"] == head_sha:
                return run
        return None

    def rerun_failed_jobs(self, run_id):
        self.request(
            "POST", "/repos/{}/actions/runs/{}/rerun-failed-jobs".format(
                self.repository, run_id
            ),
        )

    def open_assurance_issues(self):
        """Every open marker issue, paginated to exhaustion.

        Returns ``{title: {"numbers": [ascending], "body": body_of_lowest}}``
        so the reconciler can repair duplicates deterministically and detect
        a stale body. A single-page read would make any matching issue past
        page one invisible and mint a duplicate.
        """

        found = {}
        page = 1
        while True:
            issues = self.request(
                "GET",
                "/repos/{}/issues?state=open&labels=delivery-lane"
                "&per_page=100&page={}".format(self.repository, page),
            )
            for issue in issues:
                if "pull_request" in issue or not issue["title"].startswith(
                    ISSUE_MARKER
                ):
                    continue
                entry = found.setdefault(issue["title"], {})
                entry[issue["number"]] = issue.get("body") or ""
            if len(issues) < 100:
                break
            page += 1
        return {
            title: {
                "numbers": sorted(bodies),
                "body": bodies[min(bodies)],
            }
            for title, bodies in found.items()
        }

    def open_issue(self, title, body):
        self.request(
            "POST",
            "/repos/{}/issues".format(self.repository),
            {"title": title, "body": body, "labels": ISSUE_LABELS},
        )

    def update_issue_body(self, number, body):
        self.request(
            "PATCH",
            "/repos/{}/issues/{}".format(self.repository, number),
            {"body": body},
        )

    def close_issue(self, number, comment):
        self.request(
            "POST",
            "/repos/{}/issues/{}/comments".format(self.repository, number),
            {"body": comment},
        )
        self.request(
            "PATCH",
            "/repos/{}/issues/{}".format(self.repository, number),
            {"state": "closed"},
        )


def release_lag(published_at):
    """Days since the latest release published — the drift condition's age."""

    if not published_at:
        return None
    published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - published).days


def gather_conditions(github, root, apply=False):
    """Evaluate both checks; return ``{condition_title: body}`` plus log lines.

    ``apply`` gates the ONE mutation this function can reach — the bounded
    ``rerun-failed-jobs`` dispatch. Without it every decision still prints
    and exits red, but nothing on GitHub moves.
    """

    conditions, log = {}, []
    for source in sorted((root / SITES_DIR).glob("*/source.yaml")):
        site = source.parent.name
        relative = source.relative_to(root)
        parsed = parse_site_selection(source.read_text())
        if parsed is None:
            conditions[condition_title("unparseable/" + site)] = (
                "`{}` no longer carries a parseable chart-release annotation "
                "and cosign subject; deploy assurance is blind to this site "
                "until that is repaired.".format(relative)
            )
            continue
        committed, repository = parsed
        latest_tag, published_at = github.latest_release(repository)
        if latest_tag is None:
            conditions[condition_title("unpublished-selection/" + site)] = (
                "The committed selection in `{}` names `{}` but {} has NO "
                "published release at all — the desired state references an "
                "artifact whose repository publishes nothing. Fail closed: "
                "repair the selection or the release before anything "
                "else.".format(relative, committed, repository)
            )
            log.append(
                "{}: committed {} but {} has no published release -> "
                "unpublished-selection".format(site, committed, repository)
            )
            continue
        verdict = drift_verdict(committed, latest_tag.lstrip("v"))
        log.append(
            "{}: committed {} vs latest published {} -> {}".format(
                site, committed, latest_tag, verdict
            )
        )
        if verdict == "behind":
            lag = release_lag(published_at)
            conditions[condition_title("site-drift/" + site)] = (
                "{} has published release `{}` (published {}{}) but the "
                "committed selection in `{}` still names `{}`. A promotion PR "
                "is owed; until it merges the domain cannot receive the newer "
                "release.".format(
                    repository,
                    latest_tag,
                    published_at or "date unreported",
                    "" if lag is None else ", {} day(s) ago".format(lag),
                    relative,
                    committed,
                )
            )
        elif verdict == "ahead":
            conditions[condition_title("unpublished-selection/" + site)] = (
                "The committed selection in `{}` names `{}`, which is NEWER "
                "than {}'s latest published release `{}`. The desired state "
                "references an artifact the site never published — repair the "
                "selection or the release before anything else.".format(
                    relative, committed, repository, latest_tag
                )
            )

    gate = github.newest_main_gate_run()
    if gate is None:
        # Unknown never means clear: without a successful gate anchor the
        # publish path CANNOT be verified, and the shared condition key
        # keeps any previously opened publish tracker standing (updated in
        # place) instead of letting an unverifiable pass close it.
        log.append("no successful main gate run found -> publish-unverifiable")
        conditions[condition_title("publish-integrity")] = (
            "No completed successful main gate run is visible from the "
            "Actions API, so the publish path cannot be verified. This is a "
            "fail-closed condition, not a clear: any previously recorded "
            "publish failure must be treated as still standing until a "
            "successful gate anchor exists again."
        )
        return conditions, log
    gate_age = iso_age_seconds(gate["updated_at"])
    publish_run = github.publish_run_for(gate["head_sha"])
    run_age = None
    if publish_run is not None:
        started = publish_run.get("run_started_at") or publish_run.get("created_at")
        run_age = iso_age_seconds(started) if started else STUCK_RUN_SECONDS + 1
    verdict = publish_verdict(gate_age, publish_run, run_age)
    log.append(
        "publish integrity for gate {} ({}): {}".format(
            gate["head_sha"][:12], gate["conclusion"], verdict
        )
    )
    if verdict == "retry":
        rerun_note = ""
        if apply:
            try:
                github.rerun_failed_jobs(publish_run["id"])
                log.append(
                    "platform-release run {} failed on attempt 1; "
                    "rerun-failed-jobs dispatched (the one bounded retry)".format(
                        publish_run["id"]
                    )
                )
            except (urllib.error.URLError, OSError) as error:
                # The dispatch is best-effort; the CONDITION is not. A
                # transport failure here must still leave the tracker
                # recording the failed publish (round-2 review finding).
                log.append(
                    "rerun-failed-jobs dispatch FAILED: {}".format(error)
                )
                rerun_note = (
                    " The bounded rerun dispatch itself failed ({}); no "
                    "retry is in flight.".format(error)
                )
        else:
            log.append(
                "platform-release run {} failed on attempt 1; a bounded "
                "rerun WOULD be dispatched (dry run — no --apply)".format(
                    publish_run["id"]
                )
            )
        conditions[condition_title("publish-integrity")] = (
            "Platform release run {} for main SHA `{}` failed on its first "
            "attempt; one bounded rerun is dispatched under --apply. If the "
            "next assurance pass still finds it failing, no further "
            "automatic retry will happen.{}".format(
                publish_run["id"], gate["head_sha"], rerun_note
            )
        )
    elif verdict in {"absent", "failing", "stuck", "abnormal"}:
        described = {
            "absent": "no Platform release run at all",
            "failing": "a Platform release run that failed after its "
            "bounded retry",
            "stuck": "a Platform release run still not completed past the "
            "{}-minute runtime allowance — a wedged run, not a pending "
            "one".format(STUCK_RUN_SECONDS // 60),
            "abnormal": "a Platform release run with completed conclusion "
            "`{}` — outside the reviewed success/failure vocabulary, so it "
            "is refused fail-closed and never authorizes a rerun".format(
                None if publish_run is None else publish_run.get("conclusion")
            ),
        }[verdict]
        conditions[condition_title("publish-integrity")] = (
            "The newest successful main gate run (SHA `{}`) has {} — the "
            "publish path between a merged change and its platform release "
            "is broken and will not recover on its own.".format(
                gate["head_sha"], described
            )
        )
    return conditions, log


def reconcile_issues(github, conditions, apply):
    """Converge the tracking issues on the active conditions.

    One issue per condition title: created when the condition appears,
    its BODY updated in place when the evidence changes, duplicates
    (same title, higher numbers) closed toward the lowest survivor, and
    everything closed with a comment when the condition clears. The rewrite
    replaces the evidence and carries one appended `## Estimate` block
    forward, so the recomposed body is still byte-comparable and an unchanged
    condition stays "still-open" rather than churning every tick.
    """

    actions = []
    open_issues = github.open_assurance_issues()
    for title, body in conditions.items():
        entry = open_issues.get(title)
        estimate = parse_estimate(entry["body"] if entry else "")
        desired = body + (render_estimate(estimate) if estimate else "") + "\n\n" + SIGNATURE
        if entry is None:
            actions.append("open: " + title)
            if apply:
                github.open_issue(title, desired)
            continue
        keep = entry["numbers"][0]
        for duplicate in entry["numbers"][1:]:
            actions.append(
                "close-duplicate: {} (#{} duplicates #{})".format(
                    title, duplicate, keep
                )
            )
            if apply:
                github.close_issue(
                    duplicate,
                    "Duplicate deploy-assurance tracker; #{} is the "
                    "survivor.\n\n- Fable5".format(keep),
                )
        if entry["body"] != desired:
            actions.append("update: {} (#{})".format(title, keep))
            if apply:
                github.update_issue_body(keep, desired)
        else:
            actions.append("still-open: {} (#{})".format(title, keep))
    for title, entry in open_issues.items():
        if title not in conditions:
            for number in entry["numbers"]:
                actions.append("close: {} (#{})".format(title, number))
                if apply:
                    github.close_issue(
                        number,
                        "Deploy assurance no longer observes this condition; "
                        "closing.\n\n- Fable5",
                    )
    return actions


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform the mutations: the bounded publish rerun and the "
        "tracking-issue maintenance (without it, decisions print only "
        "and NOTHING on GitHub moves)",
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    arguments = parser.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN")
    if not token or not arguments.repository:
        print("GITHUB_TOKEN and a repository are required", file=sys.stderr)
        return 2
    github = GitHub(token, arguments.repository)
    conditions, log = gather_conditions(
        github, Path(__file__).resolve().parents[2], apply=arguments.apply
    )
    for line in log:
        print(line)
    for line in reconcile_issues(github, conditions, arguments.apply):
        print(line)
    if conditions:
        print(
            "DEPLOY ASSURANCE: {} active condition(s)".format(len(conditions)),
            file=sys.stderr,
        )
        return 1
    print("deploy assurance: all clear")
    return 0


if __name__ == "__main__":
    sys.exit(main())
