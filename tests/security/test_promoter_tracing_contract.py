"""Pin the promoter's call tracing, budgets and cadence (issue #309): every long
call announces itself with its budget and reports what it cost, cosign is
bounded short with one retry, the tick interval and the runbook agree, and a
credential-bearing command never has its output recorded."""

import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from .support import REPO_ROOT
from .test_promote_releases_contract import MODULE, FakeFleet, quiet_git_environment, tracked_copy


class TracingFixture:
    """A real promoter clone with a bare origin, a scripted fleet, and log capture."""

    def __init__(self, case: unittest.TestCase):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.env = quiet_git_environment()
        source = tracked_copy(base / "source")
        self.origin = base / "origin.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(source), str(self.origin)], cwd=base, check=True, env=self.env)
        self.repo = base / "repo"
        subprocess.run(["git", "clone", "-q", str(self.origin), str(self.repo)], cwd=base, check=True, env=self.env)
        committed = MODULE.load_receipt(REPO_ROOT)["records"]["naranjo-online"]["chartTag"]
        major, minor, patch = committed.split(".")
        self.fleet = FakeFleet(version=f"{major}.{minor}.{int(patch) + 1}")
        self.log_lines = []
        self._log = MODULE.log
        MODULE.log = self.log_lines.append
        case.addCleanup(self.close)

    def close(self):
        MODULE.log = self._log
        self.tmp.cleanup()

    def run(self, argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
        if argv[0] == "git":
            merged = dict(self.env)
            merged.update(env or {})
            return MODULE.run_command(argv, cwd=cwd, input_text=input_text, env=merged)
        return self.fleet.run(argv, cwd=cwd, input_text=input_text, env=env, timeout=timeout)


class CallTracingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = TracingFixture(self)

    def test_cosign_is_bounded_short_and_retried_exactly_once(self):
        self.assertEqual((MODULE.COSIGN_TIMEOUT_SECONDS, MODULE.COSIGN_ATTEMPTS), (120, 2))
        self.assertLess(MODULE.COSIGN_TIMEOUT_SECONDS, MODULE.COMMAND_TIMEOUT_SECONDS)
        stalls = []

        def stalling(argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
            if argv[:2] == ["cosign", "verify"]:
                stalls.append(timeout)
                raise MODULE.Refusal(f"`cosign verify` exceeded {timeout}s and its process group was killed")
            return self.fixture.fleet.run(argv, cwd=cwd, input_text=input_text, env=env, timeout=timeout)

        cosign = MODULE.Cosign(run=stalling, pinned_version="v3.1.3")
        with self.assertRaisesRegex(MODULE.Refusal, "exceeded 120s"):
            cosign.verify_chart("ghcr.io/snaraj/charts/naranjo-online", "sha256:" + "a" * 64, "subject")
        self.assertEqual(stalls, [MODULE.COSIGN_TIMEOUT_SECONDS] * MODULE.COSIGN_ATTEMPTS,
                         "each attempt carries the short budget, and there are exactly two")
        lines = self.fixture.log_lines
        self.assertTrue(any("START cosign-verify-chart" in line and "attempt=1/2" in line and "budget=120s" in line for line in lines), lines)
        self.assertTrue(any("FAILED decision=retry" in line and "attempt=1/2" in line for line in lines), lines)
        self.assertTrue(any("FAILED decision=refuse" in line and "attempt=2/2" in line for line in lines), lines)
        self.fixture.log_lines.clear()
        attempts = []

        def flaky(argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
            if argv[:2] == ["cosign", "verify"]:
                attempts.append(argv)
                if len(attempts) == 1:
                    raise MODULE.Refusal("`cosign verify` exceeded 120s and its process group was killed")
            return self.fixture.fleet.run(argv, cwd=cwd, input_text=input_text, env=env, timeout=timeout)

        MODULE.Cosign(run=flaky, pinned_version="v3.1.3").verify_chart(
            self.fixture.fleet.chart_repo, self.fixture.fleet.manifest_digest, "subject"
        )
        self.assertEqual(len(attempts), 2)
        self.assertTrue(any("FAILED decision=retry" in line for line in self.fixture.log_lines))
        self.assertTrue(any("DONE cosign-verify-chart" in line and line.endswith("OK") for line in self.fixture.log_lines))

    def test_the_cosign_version_check_is_traced_on_the_short_budget(self):
        budgets = []

        def recording(argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
            if argv[:2] == ["cosign", "version"]:
                budgets.append(timeout)
            return self.fixture.fleet.run(argv, cwd=cwd, input_text=input_text, env=env, timeout=timeout)

        MODULE.Cosign(run=recording, pinned_version="v3.1.3").require_pinned_version()
        self.assertEqual(budgets, [MODULE.COSIGN_TIMEOUT_SECONDS])
        self.assertTrue(any(line.startswith("START cosign-version ") and line.endswith("budget=120s") for line in self.fixture.log_lines))
        self.assertTrue(any(line.startswith("DONE cosign-version ") and line.endswith("OK") for line in self.fixture.log_lines))

    def test_run_command_really_enforces_the_budget_it_is_given(self):
        with self.assertRaisesRegex(MODULE.Refusal, r"exceeded 1s and its process group was killed"):
            MODULE.run_command(["sh", "-c", "sleep 30"], timeout=1)

    def test_a_credential_bearing_command_never_has_its_output_recorded(self):
        with self.assertRaisesRegex(MODULE.Refusal, "deliberately not recorded"):
            MODULE.run_command(["sh", "-c", "echo super-secret-token-value; exit 3"], quiet_output=True)
        for line in self.fixture.log_lines:
            self.assertNotIn("super-secret-token-value", line)
        with self.assertRaises(MODULE.Refusal):
            MODULE.run_command(["sh", "-c", "echo ordinary-diagnostic; exit 3"])
        self.assertTrue(any("ordinary-diagnostic" in line for line in self.fixture.log_lines))

    def test_a_failed_call_names_the_decision_its_caller_would_take(self):
        with MODULE.failure_decision("skip-this-tick"), self.assertRaises(MODULE.Refusal):
            with MODULE.timed_call("registry-manifest", "example:1", 60):
                raise MODULE.Refusal("registry unreachable")
        self.assertTrue(any("decision=skip-this-tick" in line and "reason=registry unreachable" in line
                            for line in self.fixture.log_lines))
        self.fixture.log_lines.clear()
        with self.assertRaises(MODULE.Refusal):
            with MODULE.timed_call("registry-manifest", "example:1", 60):
                raise MODULE.Refusal("registry unreachable")
        self.assertTrue(any("decision=refuse" in line for line in self.fixture.log_lines),
                        "outside any declared block the default decision is the strict one")

    def test_a_tick_that_finds_the_lock_held_still_ends_in_one_summary(self):
        # PR #313 round 1, finding 1: an expected overlap must stay
        # distinguishable from a dead tick, so this exit reports too.
        held = MODULE.acquire_lock(self.fixture.repo / ".git" / "promoter.lock")
        self.assertIsNotNone(held)
        before = time.monotonic()
        try:
            code = MODULE.tick(self.fixture.repo, True, registry=self.fixture.fleet.registry(),
                               github=MODULE.GitHub(run=self.fixture.run, fetch=self.fixture.fleet.fetch),
                               cosign=self.fixture.fleet.cosign(), run=self.fixture.run)
        finally:
            wall = time.monotonic() - before
            MODULE.release_lock(held)
        self.assertEqual(code, 0)
        self.assertTrue(any("another tick holds the lock" in line for line in self.fixture.log_lines))
        summaries = [line for line in self.fixture.log_lines if line.startswith("SUMMARY tick elapsed=")]
        self.assertEqual(len(summaries), 1, self.fixture.log_lines)
        self.assertIn("dry-run=True lock=held-by-another-tick", summaries[0])
        # The elapsed field is measured, not a sentinel: it cannot exceed the
        # wall time this test observed around the call (round 2, finding 2).
        elapsed = float(re.search(r"elapsed=([0-9.]+)s", summaries[0]).group(1))
        self.assertLessEqual(elapsed, wall + 0.05, summaries[0])

    def test_the_initial_fetch_is_traced_and_a_refusal_leaves_start_and_done(self):
        MODULE.Workspace(self.fixture.repo, self.fixture.run).refresh()
        self.assertTrue(any(line.startswith("START git-fetch origin main budget=600s") for line in self.fixture.log_lines))
        self.assertTrue(any(line.startswith("DONE git-fetch origin main ") and line.endswith("OK") for line in self.fixture.log_lines))
        self.fixture.log_lines.clear()

        def refusing(argv, cwd=None, input_text=None, env=None, timeout=None, quiet_output=False):
            if argv[:2] == ["git", "fetch"]:
                raise MODULE.Refusal("`git fetch` exceeded 600s and its process group was killed")
            return self.fixture.run(argv, cwd=cwd, input_text=input_text, env=env, timeout=timeout, quiet_output=quiet_output)

        with self.assertRaisesRegex(MODULE.Refusal, "exceeded 600s"):
            MODULE.Workspace(self.fixture.repo, refusing).refresh()
        self.assertTrue(any(line.startswith("DONE git-fetch origin main ") and "FAILED decision=refuse" in line
                            for line in self.fixture.log_lines), self.fixture.log_lines)


class CadenceTests(unittest.TestCase):
    """The constant, the emitted plist and the runbook's sentence agree."""

    def test_the_tick_interval_is_five_minutes_everywhere_it_is_stated(self):
        self.assertEqual(MODULE.LAUNCHD_INTERVAL_SECONDS, 300)
        text = (REPO_ROOT / "docs" / "runbooks" / "release-promotion.md").read_text(encoding="utf-8")
        minutes = MODULE.LAUNCHD_INTERVAL_SECONDS // 60
        self.assertIn(f"runs at load and every {minutes} minutes", text)
        self.assertIn(f"the promoter tick, `StartInterval` {MODULE.LAUNCHD_INTERVAL_SECONDS}", text)
        self.assertIn(f"<key>StartInterval</key><integer>{MODULE.LAUNCHD_INTERVAL_SECONDS}</integer>",
                      MODULE.launchd_plist("/x/repo", "/x/log"))
        self.assertIn("### Reading the log", text)
        self.assertNotIn("PROOF", text)
