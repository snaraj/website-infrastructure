"""Deploy-assurance contract battery (issue #273).

Pins the network-free decisions of ``scripts/ci/deploy_assurance.py`` — the
watchdog that owns the release-to-domain promise — so the incident it
answers (a committed selection silently four releases behind, a
platform-release run dead on a transient 422 with no retry and no signal)
cannot quietly come back:

* the site repository of record is derived from each committed cosign
  subject, proven against the real ``kubernetes/websites`` tree, so the
  assurance target can never drift from what the cluster actually verifies;
* drift classification is three-valued — current, behind, ahead — and the
  "ahead" direction (a selection naming an unpublished release) is its own
  condition rather than a silent pass;
* the publish-integrity retry is bounded to exactly one rerun: a first
  failed attempt retries, every later attempt is terminal, and no verdict
  value other than ``retry`` may dispatch a rerun;
* the workflow file keeps its narrow, reviewed permission surface.
"""

from __future__ import annotations

import json
import re
import unittest
import urllib.error
from collections import deque
from contextlib import contextmanager
from unittest import mock

from .support import REPO_ROOT, load_script

assurance = load_script("ci/deploy_assurance.py")

SITES = REPO_ROOT / "kubernetes" / "websites"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy-assurance.yml"

# The workflow's byte-exact lockstep twin (round-3 review finding 1): every
# per-key assertion admitted SOME GitHub-valid key that changed execution
# while the asserted bytes stayed intact, so the reviewed file IS the
# contract, whole. Edit the workflow and this constant in the same commit.
EXPECTED_WORKFLOW = """\
name: Deploy assurance

# Owns the promise that published site releases reach the committed desired
# state and that the platform publish path is healthy (issue #273). Red run +
# one idempotent tracking issue per condition; closes them when clear. The
# checker's decisions are pinned by tests/security/test_deploy_assurance_contract.py.
on:
  schedule:
    - cron: '23 * * * *'
  workflow_dispatch:

permissions: {}

concurrency:
  group: deploy-assurance
  cancel-in-progress: false

jobs:
  assure:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      contents: read
      actions: write # read gate/publish runs; the one bounded rerun-failed-jobs
      issues: write # open/close the per-condition tracking issues
    steps:
      - name: Check out desired state
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 1
      - name: Evaluate drift and publish integrity
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: python3 -I -B scripts/ci/deploy_assurance.py --apply
"""


class SiteSelectionParsingTests(unittest.TestCase):
    maxDiff = None

    def test_every_committed_site_parses_to_its_signing_repository(self):
        """The cosign subject names the repo of record for every real site."""

        parsed = {
            source.parent.name: assurance.parse_site_selection(source.read_text())
            for source in sorted(SITES.glob("*/source.yaml"))
        }
        self.assertEqual(sorted(parsed), ["lidersea-com", "naranjo-online"])
        for site, selection in parsed.items():
            self.assertIsNotNone(selection, site)
            committed, repository = selection
            self.assertRegex(committed, r"^\d+\.\d+\.\d+$", site)
            self.assertRegex(repository, r"^snaraj/[a-z.]+$", site)
        self.assertEqual(parsed["naranjo-online"][1], "snaraj/naranjo.online")
        self.assertEqual(parsed["lidersea-com"][1], "snaraj/lidersea.com")

    def test_selection_without_annotation_or_subject_is_unparseable(self):
        source = (SITES / "naranjo-online" / "source.yaml").read_text()
        without_annotation = re.sub(
            r"(?m)^\s*platform\.snaraj\.dev/chart-release:.*\n", "", source
        )
        self.assertIsNone(assurance.parse_site_selection(without_annotation))
        without_subject = re.sub(r"(?m)^\s*subject:.*\n", "", source)
        self.assertIsNone(assurance.parse_site_selection(without_subject))

    def test_lookalike_subject_hosts_do_not_parse(self):
        """Only the escaped-dot github.com subject shape yields a repository."""

        source = (SITES / "naranjo-online" / "source.yaml").read_text()
        lookalike = source.replace(
            "^https://github\\.com/snaraj/naranjo\\.online/",
            "^https://github.evil.example/snaraj/naranjo\\.online/",
        )
        self.assertIsNone(assurance.parse_site_selection(lookalike))


class DriftVerdictTests(unittest.TestCase):
    def test_equal_versions_are_current(self):
        self.assertEqual(assurance.drift_verdict("0.1.66", "0.1.66"), "current")

    def test_newer_published_release_is_behind(self):
        self.assertEqual(assurance.drift_verdict("0.1.63", "0.1.67"), "behind")

    def test_numeric_not_lexicographic_comparison(self):
        """0.1.9 vs 0.1.10 must compare as numbers — the classic silent trap."""

        self.assertEqual(assurance.drift_verdict("0.1.9", "0.1.10"), "behind")
        self.assertEqual(assurance.drift_verdict("0.1.10", "0.1.9"), "ahead")

    def test_committed_selection_beyond_published_is_ahead(self):
        self.assertEqual(assurance.drift_verdict("0.2.0", "0.1.67"), "ahead")


class PublishVerdictTests(unittest.TestCase):
    def run_verdict(self, run_age=60, **run):
        return assurance.publish_verdict(
            assurance.PENDING_GRACE_SECONDS + 1, run, run_age
        )

    def test_absent_run_within_grace_is_pending_then_absent(self):
        self.assertEqual(assurance.publish_verdict(30, None, None), "pending")
        self.assertEqual(
            assurance.publish_verdict(
                assurance.PENDING_GRACE_SECONDS + 1, None, None
            ),
            "absent",
        )

    def test_incomplete_run_is_pending_only_inside_the_runtime_allowance(self):
        """A wedged run must never stay "pending" forever (round-2 review
        finding: a seven-day-old in_progress run classified as pending, no
        condition, no tracker). Past the allowance it is STUCK — loud."""

        for status in ("in_progress", "queued", "waiting"):
            self.assertEqual(
                self.run_verdict(status=status, conclusion=None, run_attempt=1),
                "pending",
                status,
            )
            self.assertEqual(
                self.run_verdict(
                    run_age=assurance.STUCK_RUN_SECONDS + 1,
                    status=status,
                    conclusion=None,
                    run_attempt=1,
                ),
                "stuck",
                status,
            )
        self.assertEqual(
            self.run_verdict(
                run_age=7 * 24 * 3600,
                status="in_progress",
                conclusion=None,
                run_attempt=1,
            ),
            "stuck",
        )

    def test_successful_run_is_ok(self):
        self.assertEqual(
            self.run_verdict(status="completed", conclusion="success", run_attempt=1),
            "ok",
        )

    def test_first_attempt_failure_earns_exactly_one_retry(self):
        self.assertEqual(
            self.run_verdict(status="completed", conclusion="failure", run_attempt=1),
            "retry",
        )

    def test_second_attempt_failure_is_terminal_never_retried(self):
        for attempt in (2, 3, 7):
            self.assertEqual(
                self.run_verdict(
                    status="completed", conclusion="failure", run_attempt=attempt
                ),
                "failing",
                attempt,
            )

    def test_every_other_completed_conclusion_is_abnormal_never_retry(self):
        """``status=completed`` is a STATUS spanning many conclusions
        (round-2 review finding): the rerun authority reaches exactly the
        reviewed attempt-1 ``failure`` and nothing else. Every other
        conclusion GitHub documents — and any future unknown one — maps to
        the fail-closed ``abnormal`` verdict at every attempt."""

        for conclusion in (
            "cancelled",
            "skipped",
            "neutral",
            "action_required",
            "timed_out",
            "stale",
            "startup_failure",
            None,
            "some-future-conclusion",
        ):
            for attempt in (1, 2):
                self.assertEqual(
                    self.run_verdict(
                        status="completed", conclusion=conclusion, run_attempt=attempt
                    ),
                    "abnormal",
                    (conclusion, attempt),
                )

    def test_retry_is_the_only_verdict_that_dispatches_a_rerun(self):
        """The rerun call sits behind the single ``retry`` branch: the verdict
        space is exactly these seven values, and only one of them reruns."""

        verdicts = {
            assurance.publish_verdict(30, None, None),
            assurance.publish_verdict(
                assurance.PENDING_GRACE_SECONDS + 1, None, None
            ),
            self.run_verdict(status="in_progress", conclusion=None, run_attempt=1),
            self.run_verdict(
                run_age=assurance.STUCK_RUN_SECONDS + 1,
                status="in_progress",
                conclusion=None,
                run_attempt=1,
            ),
            self.run_verdict(status="completed", conclusion="success", run_attempt=1),
            self.run_verdict(status="completed", conclusion="failure", run_attempt=1),
            self.run_verdict(status="completed", conclusion="failure", run_attempt=2),
            self.run_verdict(status="completed", conclusion="skipped", run_attempt=1),
        }
        self.assertEqual(
            verdicts,
            {"pending", "stuck", "absent", "ok", "retry", "failing", "abnormal"},
        )
        rerun_sites = re.findall(
            r"rerun_failed_jobs\(", (REPO_ROOT / "scripts/ci/deploy_assurance.py").read_text()
        )
        # One definition, one call site — the bounded retry has no second door.
        self.assertEqual(len(rerun_sites), 2)


class IssueReconciliationTests(unittest.TestCase):
    class RecordingGitHub:
        def __init__(self, open_entries):
            self.opened, self.closed, self.updated = [], [], []
            self._open = open_entries

        def open_assurance_issues(self):
            return {
                title: {"numbers": list(entry["numbers"]), "body": entry["body"]}
                for title, entry in self._open.items()
            }

        def open_issue(self, title, body):
            self.opened.append(title)

        def update_issue_body(self, number, body):
            self.updated.append((number, body))

        def close_issue(self, number, comment):
            self.closed.append(number)

    def test_new_condition_opens_existing_stays_cleared_closes(self):
        drift = assurance.condition_title("site-drift/naranjo-online")
        github = self.RecordingGitHub(
            {
                drift: {"numbers": [41], "body": "still behind\n\n- Fable5"},
                assurance.condition_title("publish-integrity"): {
                    "numbers": [42],
                    "body": "x",
                },
            }
        )
        conditions = {
            drift: "still behind",
            assurance.condition_title("site-drift/lidersea-com"): "now behind",
        }
        actions = assurance.reconcile_issues(github, conditions, apply=True)
        self.assertEqual(
            github.opened, [assurance.condition_title("site-drift/lidersea-com")]
        )
        self.assertEqual(github.closed, [42])
        self.assertEqual(github.updated, [])
        self.assertEqual(len(actions), 3)

    def test_changed_evidence_updates_the_surviving_issue_in_place(self):
        drift = assurance.condition_title("site-drift/naranjo-online")
        github = self.RecordingGitHub(
            {drift: {"numbers": [41], "body": "stale evidence\n\n- Fable5"}}
        )
        actions = assurance.reconcile_issues(
            github, {drift: "fresh evidence"}, apply=True
        )
        self.assertEqual(github.updated, [(41, "fresh evidence\n\n- Fable5")])
        self.assertEqual(github.opened, [])
        self.assertEqual(github.closed, [])
        self.assertTrue(any(action.startswith("update:") for action in actions))

    def test_duplicate_trackers_converge_on_the_lowest_number(self):
        drift = assurance.condition_title("site-drift/naranjo-online")
        github = self.RecordingGitHub(
            {drift: {"numbers": [41, 55, 90], "body": "behind\n\n- Fable5"}}
        )
        assurance.reconcile_issues(github, {drift: "behind"}, apply=True)
        self.assertEqual(github.closed, [55, 90])
        self.assertEqual(github.opened, [])
        self.assertEqual(github.updated, [])

    def test_without_apply_nothing_mutates(self):
        drift = assurance.condition_title("site-drift/naranjo-online")
        github = self.RecordingGitHub(
            {
                assurance.condition_title("publish-integrity"): {
                    "numbers": [42, 43],
                    "body": "x",
                }
            }
        )
        assurance.reconcile_issues(github, {drift: "behind"}, apply=False)
        self.assertEqual(github.opened, [])
        self.assertEqual(github.closed, [])
        self.assertEqual(github.updated, [])


class _CannedResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@contextmanager
def canned_api(routes):
    """Patch urlopen with a hand fake keyed on ``(method, path)``.

    Records every request so a battery can assert exactly which mutations
    happened — the same visibility a mock framework would fake, from ~15
    lines of stdlib.
    """

    calls = []

    def fake_urlopen(request, timeout=None):
        path = request.full_url.replace(assurance.API_ROOT, "")
        calls.append(
            (request.get_method(), path, request.data, dict(request.header_items()))
        )
        outcome = routes[(request.get_method(), path.split("?")[0])]
        if isinstance(outcome, deque):
            # A deque is a queue of per-call payloads (pagination fakes).
            outcome = outcome.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return _CannedResponse(json.dumps(outcome).encode() if outcome is not None else b"")

    with mock.patch.object(assurance.urllib.request, "urlopen", fake_urlopen):
        yield calls


def http_error(code):
    return urllib.error.HTTPError("u", code, "err", None, None)


class GitHubLayerTests(unittest.TestCase):
    def setUp(self):
        self.github = assurance.GitHub("t0ken", "snaraj/website-infrastructure")

    def test_every_request_carries_bearer_authorization(self):
        """Removing the Authorization header must turn this red — the REST
        layer is useless (rate-limited, permission-blind) without it."""

        with canned_api({("PATCH", "/repos/x"): None}) as calls:
            self.assertEqual(self.github.request("PATCH", "/repos/x", {"a": 1}), {})
        method, path, body, headers = calls[0]
        self.assertEqual((method, path), ("PATCH", "/repos/x"))
        self.assertEqual(json.loads(body), {"a": 1})
        self.assertEqual(headers.get("Authorization"), "Bearer t0ken")
        self.assertEqual(headers.get("X-github-api-version"), assurance.API_VERSION)

    def test_latest_release_returns_none_pair_only_for_404(self):
        route = ("GET", "/repos/snaraj/naranjo.online/releases/latest")
        with canned_api(
            {route: {"tag_name": "v0.1.67", "published_at": "2026-09-01T00:07:43Z"}}
        ):
            self.assertEqual(
                self.github.latest_release("snaraj/naranjo.online"),
                ("v0.1.67", "2026-09-01T00:07:43Z"),
            )
        with canned_api({route: http_error(404)}):
            self.assertEqual(
                self.github.latest_release("snaraj/naranjo.online"), (None, None)
            )
        with canned_api({route: http_error(500)}):
            with self.assertRaises(urllib.error.HTTPError):
                self.github.latest_release("snaraj/naranjo.online")

    def test_run_lookups_pin_protected_main_and_the_bounded_rerun_call(self):
        runs_path = (
            "/repos/snaraj/website-infrastructure/actions/workflows/{}/runs"
        )
        with canned_api(
            {
                ("GET", runs_path.format("pull-request.yml")): {
                    "workflow_runs": [
                        # completed-but-cancelled newest: NOT a valid anchor
                        # (status=completed spans many conclusions), so the
                        # gate lookup must skip it for the newest SUCCESS.
                        {"head_sha": "f" * 40, "conclusion": "cancelled"},
                        {"head_sha": "a" * 40, "conclusion": "success"},
                    ]
                },
                ("GET", runs_path.format("platform-release.yml")): {
                    "workflow_runs": [
                        {"head_sha": "b" * 40, "id": 1},
                        {"head_sha": "a" * 40, "id": 2},
                    ]
                },
                ("POST", "/repos/snaraj/website-infrastructure/actions/runs/2/rerun-failed-jobs"): None,
            }
        ) as calls:
            self.assertEqual(
                self.github.newest_main_gate_run(),
                {"head_sha": "a" * 40, "conclusion": "success"},
            )
            self.assertEqual(
                self.github.publish_run_for("a" * 40), {"head_sha": "a" * 40, "id": 2}
            )
            self.assertIsNone(self.github.publish_run_for("c" * 40))
            self.github.rerun_failed_jobs(2)
        # The gate question is only answerable about protected main pushes:
        # a query drifted to another branch or event answers about attacker
        # state, so the exact query string is contract, not implementation.
        gate_query = calls[0][1]
        self.assertIn("branch=main", gate_query)
        self.assertIn("event=push", gate_query)
        self.assertIn("status=completed", gate_query)
        self.assertEqual(calls[-1][0], "POST")

    def test_gate_page_without_any_successful_run_anchors_nothing(self):
        runs_path = (
            "/repos/snaraj/website-infrastructure/actions/workflows/"
            "pull-request.yml/runs"
        )
        with canned_api(
            {
                ("GET", runs_path): {
                    "workflow_runs": [
                        {"head_sha": "f" * 40, "conclusion": "failure"},
                        {"head_sha": "e" * 40, "conclusion": "timed_out"},
                    ]
                }
            }
        ):
            self.assertIsNone(self.github.newest_main_gate_run())

    def test_issue_listing_filters_paginates_and_repairs_duplicates(self):
        page_one = [
            {"title": "deploy-assurance[publish-integrity]", "number": 9, "body": "b9"},
            {"title": "unrelated issue", "number": 10, "body": "x"},
            {
                "title": "deploy-assurance[site-drift/x]",
                "number": 11,
                "body": "pr",
                "pull_request": {},
            },
        ]
        # Force real pagination: page one full at exactly 100 rows, the
        # duplicate marker title arriving only on page two.
        page_one += [
            {"title": "filler {}".format(i), "number": 100 + i, "body": ""}
            for i in range(100 - len(page_one))
        ]
        page_two = [
            {"title": "deploy-assurance[publish-integrity]", "number": 300, "body": "b300"},
        ]
        with canned_api(
            {
                ("GET", "/repos/snaraj/website-infrastructure/issues"): deque(
                    [page_one, page_two]
                )
            }
        ) as calls:
            listing = self.github.open_assurance_issues()
        self.assertEqual(len(calls), 2)
        self.assertIn("page=2", calls[1][1])
        self.assertEqual(
            listing,
            {
                "deploy-assurance[publish-integrity]": {
                    "numbers": [9, 300],
                    "body": "b9",
                }
            },
        )

    def test_issue_open_update_and_close_mutations(self):
        base = "/repos/snaraj/website-infrastructure/issues"
        with canned_api(
            {
                ("POST", base): {},
                ("POST", base + "/9/comments"): {},
                ("PATCH", base + "/9"): {},
            }
        ) as calls:
            self.github.open_issue("t", "b")
            self.github.update_issue_body(9, "fresher evidence")
            self.github.close_issue(9, "resolved")
        opened = json.loads(calls[0][2])
        self.assertEqual(opened["labels"], assurance.ISSUE_LABELS)
        self.assertEqual(
            [c[0] for c in calls], ["POST", "PATCH", "POST", "PATCH"]
        )
        self.assertEqual(json.loads(calls[1][2]), {"body": "fresher evidence"})
        self.assertEqual(json.loads(calls[-1][2]), {"state": "closed"})


class _ScriptedGitHub:
    """Hand fake for gather_conditions: canned answers, recorded reruns."""

    def __init__(self, tags, gate, publish):
        self._tags, self._gate, self._publish = tags, gate, publish
        self.reruns, self.opened, self.closed, self.updated = [], [], [], []

    def open_issue(self, title, body):
        self.opened.append(title)

    def update_issue_body(self, number, body):
        self.updated.append(number)

    def close_issue(self, number, comment):
        self.closed.append(number)

    def latest_release(self, repository):
        tag = self._tags[repository]
        if tag is None:
            return None, None
        return tag, "2026-08-30T00:00:00Z"

    def newest_main_gate_run(self):
        return self._gate

    def publish_run_for(self, head_sha):
        return self._publish

    def rerun_failed_jobs(self, run_id):
        self.reruns.append(run_id)

    def open_assurance_issues(self):
        return {}


def _fresh_gate():
    now = assurance.datetime.now(assurance.timezone.utc)
    return {
        "head_sha": "a" * 40,
        "conclusion": "success",
        "updated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


class GatherConditionsTests(unittest.TestCase):
    """End-to-end decision sweep over the REAL committed websites tree."""

    def current_tags(self):
        committed = {}
        for source in SITES.glob("*/source.yaml"):
            version, repository = assurance.parse_site_selection(source.read_text())
            committed[repository] = "v" + version
        return committed

    def test_all_clear_when_selections_are_current_and_publish_succeeded(self):
        github = _ScriptedGitHub(
            self.current_tags(),
            _fresh_gate(),
            {"status": "completed", "conclusion": "success", "run_attempt": 1, "id": 5},
        )
        conditions, log = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(conditions, {})
        self.assertEqual(github.reruns, [])
        self.assertTrue(any("-> current" in line for line in log))

    def test_newer_site_release_raises_the_drift_condition(self):
        tags = self.current_tags()
        tags["snaraj/naranjo.online"] = "v9.9.9"
        github = _ScriptedGitHub(
            tags,
            _fresh_gate(),
            {"status": "completed", "conclusion": "success", "run_attempt": 1, "id": 5},
        )
        conditions, _ = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(
            list(conditions), ["deploy-assurance[site-drift/naranjo-online]"]
        )
        self.assertIn("v9.9.9", conditions["deploy-assurance[site-drift/naranjo-online]"])

    def test_unpublished_selection_raises_its_own_condition(self):
        tags = self.current_tags()
        tags["snaraj/lidersea.com"] = "v0.0.1"
        github = _ScriptedGitHub(
            tags,
            _fresh_gate(),
            {"status": "completed", "conclusion": "success", "run_attempt": 1, "id": 5},
        )
        conditions, _ = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(
            list(conditions), ["deploy-assurance[unpublished-selection/lidersea-com]"]
        )

    def test_site_with_no_release_at_all_fails_closed(self):
        """A committed selection whose repository publishes nothing is the
        unpublished-selection condition, never a silent skip."""

        tags = self.current_tags()
        tags["snaraj/lidersea.com"] = None
        github = _ScriptedGitHub(
            tags,
            _fresh_gate(),
            {"status": "completed", "conclusion": "success", "run_attempt": 1, "id": 5},
        )
        conditions, log = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(
            list(conditions), ["deploy-assurance[unpublished-selection/lidersea-com]"]
        )
        self.assertIn(
            "NO published release",
            conditions["deploy-assurance[unpublished-selection/lidersea-com]"],
        )
        self.assertTrue(any("unpublished-selection" in line for line in log))

    def test_drift_condition_names_the_release_age(self):
        tags = self.current_tags()
        tags["snaraj/naranjo.online"] = "v9.9.9"
        github = _ScriptedGitHub(
            tags,
            _fresh_gate(),
            {"status": "completed", "conclusion": "success", "run_attempt": 1, "id": 5},
        )
        conditions, _ = assurance.gather_conditions(github, REPO_ROOT)
        body = conditions["deploy-assurance[site-drift/naranjo-online]"]
        self.assertIn("2026-08-30T00:00:00Z", body)
        self.assertIn("day(s) ago", body)
        self.assertIn("kubernetes/websites/naranjo-online/source.yaml", body)

    def test_first_publish_failure_reruns_only_under_apply(self):
        """The one mutation gather can reach obeys --apply: a dry run decides
        and reports identically but dispatches nothing."""

        publish = {"status": "completed", "conclusion": "failure", "run_attempt": 1, "id": 7}
        dry = _ScriptedGitHub(self.current_tags(), _fresh_gate(), dict(publish))
        conditions, log = assurance.gather_conditions(dry, REPO_ROOT, apply=False)
        self.assertEqual(dry.reruns, [])
        self.assertIn("deploy-assurance[publish-integrity]", conditions)
        self.assertTrue(any("WOULD be dispatched" in line for line in log))
        wet = _ScriptedGitHub(self.current_tags(), _fresh_gate(), dict(publish))
        conditions, _ = assurance.gather_conditions(wet, REPO_ROOT, apply=True)
        self.assertEqual(wet.reruns, [7])
        self.assertIn("deploy-assurance[publish-integrity]", conditions)

    def test_repeated_publish_failure_is_terminal_without_rerun(self):
        github = _ScriptedGitHub(
            self.current_tags(),
            _fresh_gate(),
            {"status": "completed", "conclusion": "failure", "run_attempt": 2, "id": 7},
        )
        conditions, _ = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(github.reruns, [])
        self.assertIn(
            "failed after its bounded retry",
            conditions["deploy-assurance[publish-integrity]"],
        )

    def test_no_successful_gate_is_a_condition_never_a_clear(self):
        """Unknown probe state must never mean clear (round-2 review
        finding: the old "skipped" path exited 0 and closed a standing
        publish tracker). The unverifiable state emits the SAME
        publish-integrity key, so an existing tracker is preserved by
        update-in-place instead of being closed as cleared."""

        github = _ScriptedGitHub(self.current_tags(), None, None)
        conditions, log = assurance.gather_conditions(github, REPO_ROOT)
        self.assertIn("deploy-assurance[publish-integrity]", conditions)
        self.assertIn(
            "cannot be verified", conditions["deploy-assurance[publish-integrity]"]
        )
        self.assertTrue(any("publish-unverifiable" in line for line in log))
        self.assertFalse(any("skipped" in line for line in log))

    def test_stuck_publish_run_is_a_condition_not_pending_forever(self):
        github = _ScriptedGitHub(
            self.current_tags(),
            _fresh_gate(),
            {
                "status": "in_progress",
                "conclusion": None,
                "run_attempt": 1,
                "id": 7,
                "run_started_at": "2026-08-20T00:00:00Z",
            },
        )
        conditions, _ = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(github.reruns, [])
        self.assertIn(
            "wedged run", conditions["deploy-assurance[publish-integrity]"]
        )

    def test_abnormal_conclusions_condition_without_ever_rerunning(self):
        """The write authority reaches exactly the reviewed attempt-1
        failure: every other completed conclusion raises the condition and
        dispatches nothing, at any attempt, even under --apply."""

        for conclusion in ("skipped", "cancelled", "neutral", "action_required",
                           "timed_out", "stale"):
            for attempt in (1, 2):
                github = _ScriptedGitHub(
                    self.current_tags(),
                    _fresh_gate(),
                    {
                        "status": "completed",
                        "conclusion": conclusion,
                        "run_attempt": attempt,
                        "id": 7,
                    },
                )
                conditions, _ = assurance.gather_conditions(
                    github, REPO_ROOT, apply=True
                )
                self.assertEqual(github.reruns, [], (conclusion, attempt))
                self.assertIn(
                    "`{}`".format(conclusion),
                    conditions["deploy-assurance[publish-integrity]"],
                    (conclusion, attempt),
                )

    def test_rerun_dispatch_failure_still_records_the_condition(self):
        """A transport failure on the one bounded mutation must not escape
        gather (round-2 review finding: the exception previously prevented
        reconcile_issues from recording the failed publish at all)."""

        class _DispatchBroken(_ScriptedGitHub):
            def rerun_failed_jobs(self, run_id):
                raise urllib.error.URLError("boom")

        github = _DispatchBroken(
            self.current_tags(),
            _fresh_gate(),
            {"status": "completed", "conclusion": "failure", "run_attempt": 1, "id": 7},
        )
        conditions, log = assurance.gather_conditions(github, REPO_ROOT, apply=True)
        body = conditions["deploy-assurance[publish-integrity]"]
        self.assertIn("dispatch itself failed", body)
        self.assertTrue(any("dispatch FAILED" in line for line in log))

    def test_malformed_source_is_a_condition_naming_the_relative_path(self):
        """A source.yaml the checker cannot parse is a blindness condition,
        and its public tracking body carries the repo-relative path — never
        a runner-local absolute one."""

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            site = root / "kubernetes" / "websites" / "broken-site"
            site.mkdir(parents=True)
            (site / "source.yaml").write_text("not: [the, expected, shape]\n")
            github = _ScriptedGitHub(
                {},
                _fresh_gate(),
                {
                    "status": "completed",
                    "conclusion": "success",
                    "run_attempt": 1,
                    "id": 5,
                },
            )
            conditions, _ = assurance.gather_conditions(github, root)
        self.assertEqual(list(conditions), ["deploy-assurance[unparseable/broken-site]"])
        body = conditions["deploy-assurance[unparseable/broken-site]"]
        self.assertIn("kubernetes/websites/broken-site/source.yaml", body)
        self.assertNotIn(scratch, body)


class MainWiringTests(unittest.TestCase):
    def test_missing_token_or_repository_is_a_hard_error(self):
        with mock.patch.dict(assurance.os.environ, {}, clear=True):
            self.assertEqual(assurance.main([]), 2)

    def current_fake(self, gate=None, publish=None, drifted=False):
        tags = {
            repository: "v" + version
            for source in SITES.glob("*/source.yaml")
            for version, repository in [
                assurance.parse_site_selection(source.read_text())
            ]
        }
        if drifted:
            tags["snaraj/naranjo.online"] = "v9.9.9"
        # Defaults model a HEALTHY publish leg: without a successful gate
        # anchor the checker now (correctly) raises publish-unverifiable,
        # so an all-clear fixture must supply one.
        if gate is None:
            gate = _fresh_gate()
        if publish is None:
            publish = {
                "status": "completed",
                "conclusion": "success",
                "run_attempt": 1,
                "id": 5,
            }
        return _ScriptedGitHub(tags, gate, publish)

    def run_main(self, fake, argv):
        environment = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "snaraj/x"}
        with mock.patch.dict(assurance.os.environ, environment, clear=True):
            with mock.patch.object(assurance, "GitHub", lambda token, repo: fake):
                return assurance.main(argv)

    FAILED_FIRST_ATTEMPT = {
        "status": "completed",
        "conclusion": "failure",
        "run_attempt": 1,
        "id": 7,
    }

    def test_conditions_exit_red_and_all_clear_exits_zero(self):
        self.assertEqual(self.run_main(self.current_fake(), []), 0)
        self.assertEqual(self.run_main(self.current_fake(drifted=True), []), 1)

    def test_cli_without_apply_performs_no_mutation_at_all(self):
        """The CLI-level negative control the round-1 review demanded: a
        first-attempt publish failure plus an active drift, run without
        --apply, must exit red having dispatched no rerun and written no
        issue."""

        fake = self.current_fake(
            gate=_fresh_gate(),
            publish=dict(self.FAILED_FIRST_ATTEMPT),
            drifted=True,
        )
        self.assertEqual(self.run_main(fake, []), 1)
        self.assertEqual(fake.reruns, [])
        self.assertEqual(fake.opened, [])
        self.assertEqual(fake.closed, [])
        self.assertEqual(fake.updated, [])

    def test_cli_with_apply_dispatches_the_bounded_rerun(self):
        fake = self.current_fake(
            gate=_fresh_gate(), publish=dict(self.FAILED_FIRST_ATTEMPT)
        )
        self.assertEqual(self.run_main(fake, ["--apply"]), 1)
        self.assertEqual(fake.reruns, [7])


class WorkflowSurfaceTests(unittest.TestCase):
    def test_workflow_keeps_the_reviewed_narrow_surface(self):
        text = WORKFLOW.read_text()
        self.assertIn("\npermissions: {}\n", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("runs-on: ubuntu-24.04", text)
        self.assertIn("timeout-minutes:", text)
        self.assertNotIn("pull_request_target", text)
        job_permissions = re.search(
            r"permissions:\n((?:      [a-z-]+: [a-z]+(?: #[^\n]*)?\n)+)", text
        )
        self.assertIsNotNone(job_permissions)
        assert job_permissions is not None
        grants = dict(
            line.split("#")[0].strip().split(": ")
            for line in job_permissions.group(1).strip().splitlines()
        )
        self.assertEqual(
            grants,
            {"contents": "read", "actions": "write", "issues": "write"},
        )

    def test_the_workflow_file_is_the_reviewed_bytes(self):
        """The COMPLETE file, byte for byte — the lockstep-twin pattern the
        repository already uses for the Flux sync template. Round-2's
        surviving mutant kept the asserted evaluator block intact while a
        key elsewhere changed execution (round 3 demonstrated `shell:`
        appended AFTER the run line: a GitHub-valid custom template that
        discards the generated script), which is why no per-block or
        per-key assertion closes this surface — only whole-file equality
        does. Changing the workflow therefore requires changing this twin
        in the same commit, which is the point: every workflow edit is a
        reviewed edit."""

        self.assertEqual(WORKFLOW.read_text(), EXPECTED_WORKFLOW)

    def test_the_shell_key_regression_stays_dead(self):
        """The round-3 survivor by name: a `shell:` key anywhere in this
        workflow selects a custom command template and can discard the
        runner-generated script while every block assertion stays green."""

        self.assertNotIn("shell:", WORKFLOW.read_text())

    def test_workflow_declares_no_suppression_and_exactly_two_steps(self):
        """No `if:` (the round-1 surviving mutant), no `continue-on-error`,
        no shell-level failure swallowing, and exactly the two reviewed
        steps with one `run:` between them — a third step or second run
        line is an unreviewed execution surface. Subsumed by the byte-exact
        twin above; kept for focused failure messages."""

        text = WORKFLOW.read_text()
        self.assertIsNone(re.search(r"(?m)^\s*if:", text))
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("|| true", text)
        self.assertNotIn("exit 0", text)
        self.assertEqual(text.count("      - name: "), 2)
        self.assertEqual(text.count("        run: "), 1)

    def test_a_nonzero_checker_exit_fails_the_workflow_command(self):
        """Behavioral proof that the checker's exit code IS the job result:
        execute the exact `run:` line from the workflow with a PATH-shimmed
        python3 that exits 7, and require the shell to propagate 7 with the
        exact reviewed arguments delivered. An inert body, a swallowed
        exit, or a rewritten invocation all fail here, not just in shape."""

        import subprocess
        import tempfile
        from pathlib import Path

        match = re.search(r"(?m)^        run: (.+)$", WORKFLOW.read_text())
        self.assertIsNotNone(match)
        assert match is not None
        command = match.group(1)
        with tempfile.TemporaryDirectory() as scratch:
            shim = Path(scratch) / "python3"
            shim.write_text(
                "#!/bin/sh\nprintf '%s' \"$*\" > \"{}/argv\"\nexit 7\n".format(
                    scratch
                )
            )
            shim.chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", "-e", "-c", command],
                env={"PATH": scratch, "GITHUB_TOKEN": "shim"},
                capture_output=True,
            )
            self.assertEqual(result.returncode, 7)
            self.assertEqual(
                (Path(scratch) / "argv").read_text(),
                "-I -B scripts/ci/deploy_assurance.py --apply",
            )


if __name__ == "__main__":
    unittest.main()
