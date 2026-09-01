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
   run must have a ``Platform release`` run at the same head SHA that
   concluded successfully (a no-artifact merge still concludes success: it
   logs its verdict and publishes nothing, so this check needs no
   classification knowledge). A first-attempt failure is retried exactly
   once via ``rerun-failed-jobs``; absence after the grace window or a
   repeated failure is a condition.

Any active condition exits 1 (a red scheduled run) and, with ``--apply``,
maintains exactly one open tracking issue per condition key — opened when
the condition appears, closed with a resolution comment when it clears.
Without ``--apply`` the same decisions print but nothing mutates.

Standard library only. The one credential is ``GITHUB_TOKEN``; no cluster,
registry, or external service is contacted.
"""

from __future__ import annotations

import argparse
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
GATE_WORKFLOW = "pull-request.yml"
PUBLISH_WORKFLOW = "platform-release.yml"
# A publish run that has not appeared this soon after its gate completed is
# still "pending", not yet a condition: workflow_run dispatch plus queue time
# is ordinarily seconds, and one scheduled interval later the verdict is real.
PENDING_GRACE_SECONDS = 20 * 60

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


def publish_verdict(gate_age_seconds, publish_run):
    """Classify the publish leg for the newest completed main gate SHA.

    ``publish_run`` is the matching Platform release run summary (or None):
    ``{"status": ..., "conclusion": ..., "run_attempt": int}``. Returns one
    of ``"ok"``, ``"pending"``, ``"absent"``, ``"retry"`` (failed on its
    first attempt — rerun exactly once), or ``"failing"`` (failed again
    after the one bounded retry; never rerun further).
    """

    if publish_run is None:
        return "pending" if gate_age_seconds < PENDING_GRACE_SECONDS else "absent"
    if publish_run.get("status") != "completed":
        return "pending"
    if publish_run.get("conclusion") == "success":
        return "ok"
    return "retry" if publish_run.get("run_attempt") == 1 else "failing"


def condition_title(key):
    """One stable title per condition key — the idempotency anchor."""

    return "{}{}]".format(ISSUE_MARKER, key)


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

    def latest_release_tag(self, repository):
        try:
            release = self.request("GET", "/repos/{}/releases/latest".format(repository))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise
        return release["tag_name"]

    def newest_main_gate_run(self):
        runs = self.request(
            "GET",
            "/repos/{}/actions/workflows/{}/runs"
            "?branch=main&event=push&status=completed&per_page=1".format(
                self.repository, GATE_WORKFLOW
            ),
        )["workflow_runs"]
        return runs[0] if runs else None

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
        issues = self.request(
            "GET",
            "/repos/{}/issues?state=open&labels=delivery-lane&per_page=100".format(
                self.repository
            ),
        )
        return {
            issue["title"]: issue["number"]
            for issue in issues
            if issue["title"].startswith(ISSUE_MARKER) and "pull_request" not in issue
        }

    def open_issue(self, title, body):
        self.request(
            "POST",
            "/repos/{}/issues".format(self.repository),
            {"title": title, "body": body, "labels": ISSUE_LABELS},
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


def gather_conditions(github, root):
    """Evaluate both checks; return ``{condition_title: body}`` plus log lines."""

    conditions, log = {}, []
    for source in sorted((root / SITES_DIR).glob("*/source.yaml")):
        site = source.parent.name
        parsed = parse_site_selection(source.read_text())
        if parsed is None:
            conditions[condition_title("unparseable/" + site)] = (
                "`{}` no longer carries a parseable chart-release annotation "
                "and cosign subject; deploy assurance is blind to this site "
                "until that is repaired.".format(source)
            )
            continue
        committed, repository = parsed
        latest_tag = github.latest_release_tag(repository)
        if latest_tag is None:
            log.append("{}: {} has no published release; skipping".format(site, repository))
            continue
        verdict = drift_verdict(committed, latest_tag.lstrip("v"))
        log.append(
            "{}: committed {} vs latest published {} -> {}".format(
                site, committed, latest_tag, verdict
            )
        )
        if verdict == "behind":
            conditions[condition_title("site-drift/" + site)] = (
                "{} has published release `{}` but the committed selection in "
                "`{}` still names `{}`. A promotion PR is owed; until it "
                "merges the domain cannot receive the newer release.".format(
                    repository, latest_tag, SITES_DIR / site / "source.yaml", committed
                )
            )
        elif verdict == "ahead":
            conditions[condition_title("unpublished-selection/" + site)] = (
                "The committed selection in `{}` names `{}`, which is NEWER "
                "than {}'s latest published release `{}`. The desired state "
                "references an artifact the site never published — repair the "
                "selection or the release before anything else.".format(
                    SITES_DIR / site / "source.yaml", committed, repository, latest_tag
                )
            )

    gate = github.newest_main_gate_run()
    if gate is None:
        log.append("no completed main gate run found; publish check skipped")
        return conditions, log
    gate_age = (
        datetime.now(timezone.utc)
        - datetime.fromisoformat(gate["updated_at"].replace("Z", "+00:00"))
    ).total_seconds()
    publish_run = github.publish_run_for(gate["head_sha"])
    verdict = publish_verdict(gate_age, publish_run)
    log.append(
        "publish integrity for gate {} ({}): {}".format(
            gate["head_sha"][:12], gate["conclusion"], verdict
        )
    )
    if verdict == "retry":
        github.rerun_failed_jobs(publish_run["id"])
        log.append(
            "platform-release run {} failed on attempt 1; "
            "rerun-failed-jobs dispatched (the one bounded retry)".format(
                publish_run["id"]
            )
        )
        conditions[condition_title("publish-integrity")] = (
            "Platform release run {} for main SHA `{}` failed on its first "
            "attempt; one bounded rerun was dispatched. If the next "
            "assurance pass still finds it failing, no further automatic "
            "retry will happen.".format(publish_run["id"], gate["head_sha"])
        )
    elif verdict in {"absent", "failing"}:
        conditions[condition_title("publish-integrity")] = (
            "The newest completed main gate run (SHA `{}`) has {} — the "
            "publish path between a merged change and its platform release "
            "is broken and will not recover on its own.".format(
                gate["head_sha"],
                "no Platform release run at all"
                if verdict == "absent"
                else "a Platform release run that failed after its bounded retry",
            )
        )
    return conditions, log


def reconcile_issues(github, conditions, apply):
    """Open one issue per new condition; close issues whose condition cleared."""

    actions = []
    open_issues = github.open_assurance_issues()
    for title, body in conditions.items():
        if title in open_issues:
            actions.append("still-open: " + title)
        else:
            actions.append("open: " + title)
            if apply:
                github.open_issue(title, body + "\n\n- Fable5")
    for title, number in open_issues.items():
        if title not in conditions:
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
        help="maintain tracking issues (without it, decisions print only)",
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    arguments = parser.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN")
    if not token or not arguments.repository:
        print("GITHUB_TOKEN and a repository are required", file=sys.stderr)
        return 2
    github = GitHub(token, arguments.repository)
    conditions, log = gather_conditions(github, Path(__file__).resolve().parents[2])
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
