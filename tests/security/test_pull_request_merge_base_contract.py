"""Execute the pull-request merge-base gate against real Git history.

The motivating defect: the workflow step bound the merge commit's first
parent to ``github.event.pull_request.base.sha``. That payload field is a
snapshot taken when the pull request was opened and GitHub never refreshes
it as the base branch advances, while ``refs/pull/<n>/merge`` is always
recomputed against the current base tip. Every open pull request therefore
went red the moment ``main`` moved — a liveness defect, not a detection.

Every case below builds real commits with real ``git`` and runs the real
script, because a string pin over shell text cannot tell a working
assertion from a broken one. The green case is specifically the *advanced
base* scenario that used to fail; the red cases are genuine integrity
violations that must still fail.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import REPO_ROOT, hermetic_git_environment, required_tool


SCRIPT = REPO_ROOT / "scripts" / "ci" / "verify-pull-request-merge-base.sh"
BASH = shutil.which("bash")
GIT = shutil.which("git")

FAILURE_LABEL = "FAIL immutable pull-request history validation"


class PullRequestMergeBaseFixture(unittest.TestCase):
    """Build one repository whose base branch advanced after the fork."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "repository"
        self.root.mkdir(parents=True)
        self.environment = hermetic_git_environment(
            identity=("Fixture Author", "fixture@example.invalid")
        )
        self.git("init", "--quiet", "--initial-branch", "main")
        # `fork` is the base tip the pull request was opened against, and the
        # value a stale event payload keeps reporting.
        self.fork = self.commit("fork.txt", "fork")
        self.git("branch", "feature")
        # The base branch then advances, exactly as merging another pull
        # request does. `advanced` is what refs/pull/<n>/merge is recomputed
        # against, and what the payload snapshot no longer names.
        self.advanced = self.commit("advanced.txt", "advanced")
        self.git("checkout", "--quiet", "feature")
        self.head = self.commit("feature.txt", "feature")
        self.merge = self.merge_commit(self.advanced, self.head)
        self.git("checkout", "--quiet", "--detach", self.merge)
        self.set_remote_tracking_tip(self.advanced)

    def git(self, *argv, check=True):
        completed = subprocess.run(
            [required_tool(GIT, "git is required"), "-C", str(self.root), *argv],
            capture_output=True,
            text=True,
            env=self.environment,
            check=False,
        )
        if check and completed.returncode != 0:
            raise AssertionError(
                "git {} failed: {}{}".format(
                    " ".join(argv), completed.stdout, completed.stderr
                )
            )
        return completed.stdout.strip()

    def commit(self, name, message):
        (self.root / name).write_text(message + "\n", encoding="utf-8")
        self.git("add", "--", name)
        self.git("commit", "--quiet", "--message", message)
        return self.git("rev-parse", "HEAD^{commit}")

    def merge_commit(self, first_parent, second_parent):
        """Join two commits exactly as GitHub's merge ref does."""

        tree = self.git("rev-parse", "{}^{{tree}}".format(second_parent))
        return self.git(
            "commit-tree", tree, "-p", first_parent, "-p", second_parent,
            "-m", "merge",
        )

    def set_remote_tracking_tip(self, commit):
        self.git("update-ref", "refs/remotes/origin/main", commit)

    def run_script(self, **overrides):
        environment = dict(self.environment)
        environment.update(
            {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_REPOSITORY": "owner/repository",
                "GITHUB_REF": "refs/pull/7/merge",
                "GITHUB_SHA": self.merge,
                "PR_BASE_REF": "main",
                "PR_BASE_REPOSITORY": "owner/repository",
                # The stale snapshot: the fork point, not the advanced tip.
                "PR_BASE_SHA": self.fork,
                "PR_HEAD_SHA": self.head,
                "PR_NUMBER": "7",
            }
        )
        for key, value in overrides.items():
            if value is None:
                environment.pop(key, None)
            else:
                environment[key] = value
        return subprocess.run(
            [required_tool(BASH, "bash is required"), str(SCRIPT)],
            cwd=str(self.root),
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def assert_refused(self, completed, reason):
        self.assertNotEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn(FAILURE_LABEL, completed.stderr)
        self.assertIn(reason, completed.stderr)
        self.assertEqual(completed.stdout, "")


@unittest.skipUnless(BASH and GIT, "bash and git are required")
class AdvancedBaseBranchTests(PullRequestMergeBaseFixture):
    """The green direction: the scenario that used to fail every pull request."""

    def test_an_advanced_base_branch_is_accepted_and_the_live_tip_is_printed(self):
        completed = self.run_script()
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertEqual(completed.stdout.strip(), self.advanced)
        # The regression in one assertion: the payload snapshot is genuinely
        # stale here, and the gate no longer conflates that with an attack.
        self.assertNotEqual(self.fork, self.advanced)

    def test_a_base_branch_that_has_not_moved_is_still_accepted(self):
        """The pre-existing green case must not regress."""

        completed = self.run_script(PR_BASE_SHA=self.advanced)
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertEqual(completed.stdout.strip(), self.advanced)

    def test_the_printed_tip_is_the_range_that_actually_merges(self):
        """The scanned range must cover exactly the commits the merge adds."""

        completed = self.run_script()
        base = completed.stdout.strip()
        added = self.git("rev-list", "{}..{}".format(base, self.head)).split()
        self.assertEqual(added, [self.head])

    def test_the_remote_tracking_ref_is_preferred_over_a_fetch(self):
        """No network is touched when the checkout already populated the ref."""

        self.git("remote", "add", "origin", str(self.root / "nonexistent.git"))
        completed = self.run_script()
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertEqual(completed.stdout.strip(), self.advanced)


@unittest.skipUnless(BASH and GIT, "bash and git are required")
class MergeBaseRefusalTests(PullRequestMergeBaseFixture):
    """The red direction: every integrity property still fails closed."""

    def test_a_first_parent_other_than_the_live_tip_is_refused(self):
        """The core property: what merges must be what was proven."""

        self.set_remote_tracking_tip(self.fork)
        self.assert_refused(
            self.run_script(),
            "merge first parent is not the live base branch tip",
        )

    def test_a_base_snapshot_off_the_branch_history_is_refused(self):
        """A rewritten or unrelated base is no longer read as staleness."""

        # Built with plumbing so the checked-out merge commit is untouched:
        # a parentless commit is exactly a base that shares no history.
        empty_tree = self.git("hash-object", "-w", "-t", "tree", os.devnull)
        unrelated = self.git("commit-tree", empty_tree, "-m", "unrelated")
        self.assertNotEqual(unrelated, self.fork)
        self.assert_refused(
            self.run_script(PR_BASE_SHA=unrelated),
            "event base is not an ancestor of the live base branch tip",
        )

    def test_an_unresolvable_base_tip_stops_the_gate(self):
        """Fail closed rather than falling back to the payload snapshot."""

        self.git("update-ref", "-d", "refs/remotes/origin/main")
        self.git("remote", "add", "origin", str(self.root / "nonexistent.git"))
        self.assert_refused(
            self.run_script(), "live base branch tip could not be fetched"
        )

    def test_a_second_parent_other_than_the_head_is_refused(self):
        self.assert_refused(
            self.run_script(PR_HEAD_SHA=self.fork),
            "merge second parent is not the pull-request head",
        )

    def test_a_checkout_that_is_not_the_event_merge_commit_is_refused(self):
        self.git("checkout", "--quiet", "--detach", self.head)
        self.assert_refused(
            self.run_script(),
            "checked-out commit is not the event merge commit",
        )

    def test_a_single_parent_head_is_refused(self):
        single = self.git("rev-parse", "feature^{commit}")
        self.git("checkout", "--quiet", "--detach", single)
        self.assert_refused(
            self.run_script(GITHUB_SHA=single),
            "merge commit does not have exactly two parents",
        )

    def test_event_identity_violations_are_each_refused(self):
        for label, overrides, reason in (
            (
                "not a pull request",
                {"GITHUB_EVENT_NAME": "push"},
                "event is not a pull request",
            ),
            (
                "fork pull request",
                {"PR_BASE_REPOSITORY": "attacker/repository"},
                "pull request is not same-repository",
            ),
            (
                "unprotected base branch",
                {"PR_BASE_REF": "release"},
                "base branch is not the protected integration branch",
            ),
            (
                "malformed number",
                {"PR_NUMBER": "0"},
                "pull-request number is malformed",
            ),
            (
                "mismatched merge ref",
                {"GITHUB_REF": "refs/pull/8/merge"},
                "checked-out ref is not the pull-request merge ref",
            ),
            (
                "head ref instead of merge ref",
                {"GITHUB_REF": "refs/pull/7/head"},
                "checked-out ref is not the pull-request merge ref",
            ),
            (
                "malformed base object id",
                {"PR_BASE_SHA": "not-an-oid"},
                "event base object ID is malformed",
            ),
            (
                "malformed head object id",
                {"PR_HEAD_SHA": "0" * 39},
                "event head object ID is malformed",
            ),
            (
                "malformed merge object id",
                {"GITHUB_SHA": "zz" + "0" * 38},
                "event merge object ID is malformed",
            ),
        ):
            with self.subTest(label=label):
                self.assert_refused(self.run_script(**overrides), reason)

    def test_every_absent_event_variable_is_refused(self):
        """An unset variable must never read as a satisfied assertion."""

        for name in (
            "GITHUB_EVENT_NAME",
            "GITHUB_REPOSITORY",
            "GITHUB_REF",
            "GITHUB_SHA",
            "PR_BASE_REF",
            "PR_BASE_REPOSITORY",
            "PR_BASE_SHA",
            "PR_HEAD_SHA",
            "PR_NUMBER",
        ):
            with self.subTest(variable=name):
                completed = self.run_script(**{name: None})
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(FAILURE_LABEL, completed.stderr)
                self.assertEqual(completed.stdout, "")


class PullRequestHistoryStepContractTests(unittest.TestCase):
    """Keep the workflow step bound to the verified tip, never the payload."""

    @classmethod
    def setUpClass(cls):
        cls.workflow = (
            REPO_ROOT / ".github" / "workflows" / "pull-request.yml"
        ).read_text(encoding="utf-8")
        start = cls.workflow.index("- name: Scan immutable pull-request history")
        cls.step = cls.workflow[: cls.workflow.index("- name: Validate workflows", start)]

    def test_the_step_drives_both_range_scans_from_the_verified_tip(self):
        self.assertIn(
            'base_sha="$(./scripts/ci/verify-pull-request-merge-base.sh)" || fail',
            self.step,
        )
        for consumer in (
            '--pull-request "${base_sha}" "${PR_HEAD_SHA}"',
            '--log-opts="${base_sha}..${PR_HEAD_SHA}"',
        ):
            with self.subTest(consumer=consumer):
                self.assertIn(consumer, self.step)

    def test_the_stale_payload_snapshot_no_longer_bounds_any_scan(self):
        """The defect in one assertion: no scan range may come from base.sha."""

        for retired in (
            '--log-opts="${PR_BASE_SHA}',
            '--pull-request "${PR_BASE_SHA}"',
            '"${merge_record[1]}" == "${PR_BASE_SHA}"',
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, self.step)

    def test_the_captured_object_id_is_revalidated_after_the_boundary(self):
        shape_gate = self.step.index('[[ "${base_sha}" =~ ${oid_pattern} ]] || fail')
        self.assertLess(
            self.step.index('base_sha="$(./scripts'), shape_gate
        )
        self.assertLess(shape_gate, self.step.index("validate_publication_history.py"))

    def test_the_step_still_exports_every_identity_the_script_asserts(self):
        for variable in (
            "PR_BASE_REF:",
            "PR_BASE_REPOSITORY:",
            "PR_BASE_SHA:",
            "PR_HEAD_SHA:",
            "PR_NUMBER:",
        ):
            with self.subTest(variable=variable):
                self.assertIn(variable, self.step)

    def test_the_checkout_keeps_the_full_history_the_script_requires(self):
        self.assertIn("fetch-depth: 0", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)

    def test_the_verifier_is_executable_and_prints_only_an_object_id(self):
        self.assertTrue(SCRIPT.is_file())
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        body = SCRIPT.read_text(encoding="utf-8")
        # Exactly one stdout write, and it is the verified tip.
        self.assertEqual(body.count("printf '%s\\n' \"$base_tip\""), 1)
        self.assertIn("set -euo pipefail", body)


if __name__ == "__main__":
    unittest.main()
