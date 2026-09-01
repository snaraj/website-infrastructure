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
from contextlib import contextmanager
from unittest import mock

from .support import REPO_ROOT, load_script

assurance = load_script("ci/deploy_assurance.py")

SITES = REPO_ROOT / "kubernetes" / "websites"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy-assurance.yml"


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
    def run_verdict(self, **run):
        return assurance.publish_verdict(assurance.PENDING_GRACE_SECONDS + 1, run)

    def test_absent_run_within_grace_is_pending_then_absent(self):
        self.assertEqual(assurance.publish_verdict(30, None), "pending")
        self.assertEqual(
            assurance.publish_verdict(assurance.PENDING_GRACE_SECONDS + 1, None),
            "absent",
        )

    def test_incomplete_run_is_pending_regardless_of_age(self):
        self.assertEqual(
            self.run_verdict(status="in_progress", conclusion=None, run_attempt=1),
            "pending",
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

    def test_retry_is_the_only_verdict_that_dispatches_a_rerun(self):
        """The rerun call sits behind the single ``retry`` branch: the verdict
        space is exactly these five values, and only one of them reruns."""

        verdicts = {
            assurance.publish_verdict(30, None),
            assurance.publish_verdict(assurance.PENDING_GRACE_SECONDS + 1, None),
            self.run_verdict(status="in_progress", conclusion=None, run_attempt=1),
            self.run_verdict(status="completed", conclusion="success", run_attempt=1),
            self.run_verdict(status="completed", conclusion="failure", run_attempt=1),
            self.run_verdict(status="completed", conclusion="failure", run_attempt=2),
        }
        self.assertEqual(
            verdicts, {"pending", "absent", "ok", "retry", "failing"}
        )
        rerun_sites = re.findall(
            r"rerun_failed_jobs\(", (REPO_ROOT / "scripts/ci/deploy_assurance.py").read_text()
        )
        # One definition, one call site — the bounded retry has no second door.
        self.assertEqual(len(rerun_sites), 2)


class IssueReconciliationTests(unittest.TestCase):
    class RecordingGitHub:
        def __init__(self, open_titles):
            self.opened, self.closed = [], []
            self._open = open_titles

        def open_assurance_issues(self):
            return dict(self._open)

        def open_issue(self, title, body):
            self.opened.append(title)

        def close_issue(self, number, comment):
            self.closed.append(number)

    def test_new_condition_opens_existing_stays_cleared_closes(self):
        github = self.RecordingGitHub(
            {
                assurance.condition_title("site-drift/naranjo-online"): 41,
                assurance.condition_title("publish-integrity"): 42,
            }
        )
        conditions = {
            assurance.condition_title("site-drift/naranjo-online"): "still behind",
            assurance.condition_title("site-drift/lidersea-com"): "now behind",
        }
        actions = assurance.reconcile_issues(github, conditions, apply=True)
        self.assertEqual(
            github.opened, [assurance.condition_title("site-drift/lidersea-com")]
        )
        self.assertEqual(github.closed, [42])
        self.assertEqual(len(actions), 3)

    def test_without_apply_nothing_mutates(self):
        github = self.RecordingGitHub(
            {assurance.condition_title("publish-integrity"): 42}
        )
        assurance.reconcile_issues(
            github,
            {assurance.condition_title("site-drift/naranjo-online"): "behind"},
            apply=False,
        )
        self.assertEqual(github.opened, [])
        self.assertEqual(github.closed, [])


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
        calls.append((request.get_method(), path, request.data))
        outcome = routes[(request.get_method(), path.split("?")[0])]
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

    def test_request_sends_bearer_auth_and_decodes_empty_bodies(self):
        with canned_api({("PATCH", "/repos/x"): None}) as calls:
            self.assertEqual(self.github.request("PATCH", "/repos/x", {"a": 1}), {})
        method, path, body = calls[0]
        self.assertEqual((method, path), ("PATCH", "/repos/x"))
        self.assertEqual(json.loads(body), {"a": 1})

    def test_latest_release_tag_returns_none_only_for_404(self):
        route = ("GET", "/repos/snaraj/naranjo.online/releases/latest")
        with canned_api({route: {"tag_name": "v0.1.67"}}):
            self.assertEqual(
                self.github.latest_release_tag("snaraj/naranjo.online"), "v0.1.67"
            )
        with canned_api({route: http_error(404)}):
            self.assertIsNone(self.github.latest_release_tag("snaraj/naranjo.online"))
        with canned_api({route: http_error(500)}):
            with self.assertRaises(urllib.error.HTTPError):
                self.github.latest_release_tag("snaraj/naranjo.online")

    def test_run_lookups_and_the_bounded_rerun_call(self):
        runs_path = (
            "/repos/snaraj/website-infrastructure/actions/workflows/{}/runs"
        )
        with canned_api(
            {
                ("GET", runs_path.format("pull-request.yml")): {
                    "workflow_runs": [{"head_sha": "a" * 40}]
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
                self.github.newest_main_gate_run(), {"head_sha": "a" * 40}
            )
            self.assertEqual(
                self.github.publish_run_for("a" * 40), {"head_sha": "a" * 40, "id": 2}
            )
            self.assertIsNone(self.github.publish_run_for("c" * 40))
            self.github.rerun_failed_jobs(2)
        self.assertEqual(calls[-1][0], "POST")

    def test_issue_listing_filters_marker_titles_and_pull_requests(self):
        with canned_api(
            {
                ("GET", "/repos/snaraj/website-infrastructure/issues"): [
                    {"title": "deploy-assurance[publish-integrity]", "number": 9},
                    {"title": "unrelated issue", "number": 10},
                    {
                        "title": "deploy-assurance[site-drift/x]",
                        "number": 11,
                        "pull_request": {},
                    },
                ]
            }
        ):
            self.assertEqual(
                self.github.open_assurance_issues(),
                {"deploy-assurance[publish-integrity]": 9},
            )

    def test_issue_open_and_close_mutations(self):
        base = "/repos/snaraj/website-infrastructure/issues"
        with canned_api(
            {
                ("POST", base): {},
                ("POST", base + "/9/comments"): {},
                ("PATCH", base + "/9"): {},
            }
        ) as calls:
            self.github.open_issue("t", "b")
            self.github.close_issue(9, "resolved")
        opened = json.loads(calls[0][2])
        self.assertEqual(opened["labels"], assurance.ISSUE_LABELS)
        self.assertEqual([c[0] for c in calls], ["POST", "POST", "PATCH"])
        self.assertEqual(json.loads(calls[-1][2]), {"state": "closed"})


class _ScriptedGitHub:
    """Hand fake for gather_conditions: canned answers, recorded reruns."""

    def __init__(self, tags, gate, publish):
        self._tags, self._gate, self._publish = tags, gate, publish
        self.reruns = []

    def latest_release_tag(self, repository):
        return self._tags[repository]

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

    def test_site_with_no_release_yet_is_skipped_not_failed(self):
        tags = self.current_tags()
        tags["snaraj/lidersea.com"] = None
        github = _ScriptedGitHub(
            tags,
            _fresh_gate(),
            {"status": "completed", "conclusion": "success", "run_attempt": 1, "id": 5},
        )
        conditions, log = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(conditions, {})
        self.assertTrue(any("no published release" in line for line in log))

    def test_first_publish_failure_dispatches_the_single_rerun(self):
        github = _ScriptedGitHub(
            self.current_tags(),
            _fresh_gate(),
            {"status": "completed", "conclusion": "failure", "run_attempt": 1, "id": 7},
        )
        conditions, _ = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(github.reruns, [7])
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

    def test_no_gate_run_skips_the_publish_leg(self):
        github = _ScriptedGitHub(self.current_tags(), None, None)
        conditions, log = assurance.gather_conditions(github, REPO_ROOT)
        self.assertEqual(conditions, {})
        self.assertTrue(any("publish check skipped" in line for line in log))


class MainWiringTests(unittest.TestCase):
    def test_missing_token_or_repository_is_a_hard_error(self):
        with mock.patch.dict(assurance.os.environ, {}, clear=True):
            self.assertEqual(assurance.main([]), 2)

    def test_conditions_exit_red_and_all_clear_exits_zero(self):
        fake = _ScriptedGitHub(
            {
                repository: "v" + version
                for source in SITES.glob("*/source.yaml")
                for version, repository in [
                    assurance.parse_site_selection(source.read_text())
                ]
            },
            None,
            None,
        )
        environment = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "snaraj/x"}
        with mock.patch.dict(assurance.os.environ, environment, clear=True):
            with mock.patch.object(assurance, "GitHub", lambda token, repo: fake):
                self.assertEqual(assurance.main([]), 0)
        fake._tags["snaraj/naranjo.online"] = "v9.9.9"
        with mock.patch.dict(assurance.os.environ, environment, clear=True):
            with mock.patch.object(assurance, "GitHub", lambda token, repo: fake):
                self.assertEqual(assurance.main([]), 1)


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

    def test_workflow_runs_the_checker_with_apply(self):
        self.assertIn(
            "python3 -B scripts/ci/deploy_assurance.py --apply",
            WORKFLOW.read_text(),
        )


if __name__ == "__main__":
    unittest.main()
