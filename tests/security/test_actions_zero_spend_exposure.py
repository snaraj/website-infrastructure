"""Merge-path GitHub Actions spend-exposure audit (issue #45).

GitHub-side spend is clean today — every job runs on the free
``ubuntu-24.04`` runner, every action is commit-pinned, no artifact
retention is configured, and the two scheduled workflows fire weekly —
but nothing on the merge path would fail if a larger or macOS runner, an
unpinned third-party action, artifact retention, or a fast cron
appeared. This battery pins that exposure surface so the CI unittest
sweep rejects the drift in the pull request that introduces it.

The audit is a line-shape scan, not a YAML load: the repository's
policy tooling is dependency-free by contract, and a shape the scan
cannot classify is a failure, never a skip. The deny-path tests prove
every rejection fires on synthetic bad workflows instead of trusting
that the auditor would.
"""

import re
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"

# Allowlist of one: the standard GitHub-hosted free runner. Larger,
# macOS, Windows, GPU, and self-declared labels are all spend or trust
# exposure and must arrive with a reviewed edit to this pin.
ALLOWED_RUNNERS = frozenset({"ubuntu-24.04"})

# Every ``uses:`` must be an owner/repo(/path)@<40-hex-commit> reference.
# This is deliberately stricter than the minimum (unpinned *third-party*
# actions): AGENTS.md pins first-party actions to full commit SHAs too,
# so a tag- or branch-pinned ``actions/`` or ``github/`` reference fails
# the same way, and a look-alike owner cannot slip past a prefix check.
_PINNED_USES = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}(?:\s+#.*)?$"
)

# The complete scheduled-trigger inventory, keyed by workflow file name.
# A new scheduled workflow, an added cron, or a faster cadence changes
# this mapping and must arrive as a reviewed edit to the pin.
PINNED_CRON_INVENTORY = {
    "codeql.yml": ("37 9 * * 2",),
    "scheduled-security.yml": ("19 10 * * 6",),
}

_RUNS_ON_LINE = re.compile(r"^\s*runs-on:\s*(.*?)\s*$")
_USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(.*?)\s*$")
_SCHEDULE_LINE = re.compile(r"^\s*schedule:\s*$")
_CRON_LINE = re.compile(r"^\s*-\s*cron:\s*(.*?)\s*$")


def workflow_files(workflow_root):
    """Return every workflow file under one tree, failing closed on none."""

    root = Path(workflow_root)
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
    if not files:
        raise AssertionError(
            "fail closed: no workflow files found under " + str(root)
        )
    return files


def _unquoted(value):
    """Strip one layer of YAML scalar quoting from a matched value."""

    for quote in ('"', "'"):
        if len(value) >= 2 and value.startswith(quote) and value.endswith(quote):
            return value[1:-1]
    return value


def exposure_violations(files, allowed_runners, pinned_cron_inventory):
    """Audit workflow files against the pinned spend-exposure surface.

    Returns violation strings; raises ``AssertionError`` when a file is
    unreadable or the scan finds nothing to judge (zero ``runs-on``
    lines across the whole inventory means the scan itself is broken).
    """

    violations = []
    observed_crons = {}
    observed_schedule_lines = {}
    runner_lines = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise AssertionError(
                "fail closed: unreadable workflow file {}: {}".format(
                    path, error
                )
            )
        if "retention-days" in text:
            violations.append(
                "artifact retention is configured in " + str(path)
            )
        crons = []
        schedule_lines = 0
        for number, line in enumerate(text.splitlines(), start=1):
            runs_on = _RUNS_ON_LINE.match(line)
            if runs_on is not None:
                runner_lines += 1
                runner = _unquoted(runs_on.group(1))
                if runner not in allowed_runners:
                    violations.append(
                        "runs-on is outside the pinned free-runner "
                        "allowlist at {}:{}: {!r}".format(path, number, runner)
                    )
                continue
            uses = _USES_LINE.match(line)
            if uses is not None:
                reference = _unquoted(uses.group(1))
                if _PINNED_USES.match(reference) is None:
                    violations.append(
                        "uses is not pinned to a 40-hex commit SHA at "
                        "{}:{}: {!r}".format(path, number, reference)
                    )
                continue
            if _SCHEDULE_LINE.match(line) is not None:
                schedule_lines += 1
                continue
            cron = _CRON_LINE.match(line)
            if cron is not None:
                crons.append(_unquoted(cron.group(1)))
        observed_crons[path.name] = tuple(crons)
        observed_schedule_lines[path.name] = schedule_lines
    if runner_lines == 0:
        raise AssertionError(
            "fail closed: the workflow scan matched no runs-on lines at all"
        )
    expected_crons = {
        path.name: pinned_cron_inventory.get(path.name, ()) for path in files
    }
    if observed_crons != expected_crons:
        violations.append(
            "scheduled-trigger inventory drifted: expected {!r}, "
            "observed {!r}".format(expected_crons, observed_crons)
        )
    for name, count in sorted(observed_schedule_lines.items()):
        expected = 1 if pinned_cron_inventory.get(name) else 0
        if count != expected:
            violations.append(
                "schedule blocks drifted in {}: expected {}, found "
                "{}".format(name, expected, count)
            )
    unmatched_pins = sorted(
        set(pinned_cron_inventory) - {path.name for path in files}
    )
    if unmatched_pins:
        violations.append(
            "pinned scheduled workflows are missing from the tree: "
            + ", ".join(unmatched_pins)
        )
    return violations


class ActionsZeroSpendExposureTests(unittest.TestCase):
    """Keep the committed workflow inventory inside the pinned surface."""

    def test_runner_allowlist_is_exactly_the_free_standard_runner(self):
        """The allowlist of one is itself part of the guarded surface."""

        self.assertEqual(ALLOWED_RUNNERS, frozenset({"ubuntu-24.04"}))

    def test_committed_workflows_have_no_spend_exposure(self):
        """Runners, action pins, retention, and crons all hold at once."""

        files = workflow_files(WORKFLOW_ROOT)
        self.assertEqual(
            exposure_violations(files, ALLOWED_RUNNERS, PINNED_CRON_INVENTORY),
            [],
        )

    def test_cron_pin_covers_every_committed_scheduled_workflow(self):
        """The pin and the tree must describe the same two weekly crons."""

        names = {path.name for path in workflow_files(WORKFLOW_ROOT)}
        self.assertEqual(set(PINNED_CRON_INVENTORY), {
            "codeql.yml",
            "scheduled-security.yml",
        })
        self.assertLessEqual(set(PINNED_CRON_INVENTORY), names)


class ActionsZeroSpendDenyPathTests(unittest.TestCase):
    """Prove the auditor rejects each exposure class, hermetically."""

    def _audit_synthetic(self, contents, pins=None):
        """Run the auditor over a synthetic .github/workflows tree."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workflows"
            root.mkdir()
            for name, text in contents.items():
                if isinstance(text, bytes):
                    (root / name).write_bytes(text)
                else:
                    (root / name).write_text(text, encoding="utf-8")
            return exposure_violations(
                workflow_files(root),
                ALLOWED_RUNNERS,
                PINNED_CRON_INVENTORY if pins is None else pins,
            )

    @staticmethod
    def _job(runs_on="ubuntu-24.04", extra=""):
        return (
            "jobs:\n"
            "  scan:\n"
            "    runs-on: {}\n".format(runs_on)
            + extra
        )

    def test_macos_runner_is_a_violation(self):
        violations = self._audit_synthetic(
            {"bad.yml": self._job("macos-14")}, pins={}
        )
        self.assertTrue(
            any("runs-on" in item and "macos-14" in item for item in violations),
            violations,
        )

    def test_larger_ubuntu_runner_is_a_violation(self):
        violations = self._audit_synthetic(
            {"bad.yml": self._job("ubuntu-24.04-arm64-8core")}, pins={}
        )
        self.assertTrue(any("runs-on" in item for item in violations), violations)

    def test_expression_runner_is_a_violation(self):
        """A matrix/expression runner cannot be judged, so it is denied."""

        violations = self._audit_synthetic(
            {"bad.yml": self._job("${{ matrix.runner }}")}, pins={}
        )
        self.assertTrue(any("runs-on" in item for item in violations), violations)

    def test_tag_pinned_third_party_action_is_a_violation(self):
        violations = self._audit_synthetic(
            {
                "bad.yml": self._job(
                    extra="    steps:\n"
                    "      - uses: third-party/setup-anything@v4\n"
                )
            },
            pins={},
        )
        self.assertTrue(
            any("40-hex" in item and "third-party" in item for item in violations),
            violations,
        )

    def test_short_sha_pin_is_a_violation(self):
        violations = self._audit_synthetic(
            {
                "bad.yml": self._job(
                    extra="    steps:\n"
                    "      - uses: third-party/setup-anything@abc1234\n"
                )
            },
            pins={},
        )
        self.assertTrue(any("40-hex" in item for item in violations), violations)

    def test_local_and_docker_uses_are_violations(self):
        """Path and image references bypass commit pinning entirely."""

        violations = self._audit_synthetic(
            {
                "bad.yml": self._job(
                    extra="    steps:\n"
                    "      - uses: ./.github/actions/local\n"
                    "      - uses: docker://alpine:3.20\n"
                )
            },
            pins={},
        )
        self.assertEqual(
            len([item for item in violations if "40-hex" in item]), 2, violations
        )

    def test_artifact_retention_is_a_violation(self):
        violations = self._audit_synthetic(
            {
                "bad.yml": self._job(
                    extra="    steps:\n"
                    "      - uses: actions/upload-artifact@"
                    + "0" * 40
                    + "\n"
                    "        with:\n"
                    "          retention-days: 5\n"
                )
            },
            pins={},
        )
        self.assertTrue(
            any("artifact retention" in item for item in violations), violations
        )

    def test_new_scheduled_workflow_is_a_violation(self):
        """A cron the pin does not know about must fail the audit."""

        violations = self._audit_synthetic(
            {
                "miner.yml": "on:\n"
                "  schedule:\n"
                "    - cron: '*/5 * * * *'\n" + self._job()
            },
            pins={},
        )
        self.assertTrue(
            any("scheduled-trigger inventory" in item for item in violations),
            violations,
        )

    def test_faster_cron_on_a_pinned_workflow_is_a_violation(self):
        """Editing an existing weekly cron to a fast cadence must fail."""

        violations = self._audit_synthetic(
            {
                "codeql.yml": "on:\n"
                "  schedule:\n"
                "    - cron: '*/10 * * * *'\n" + self._job()
            },
            pins={"codeql.yml": ("37 9 * * 2",)},
        )
        self.assertTrue(
            any("scheduled-trigger inventory" in item for item in violations),
            violations,
        )

    def test_added_second_cron_on_a_pinned_workflow_is_a_violation(self):
        violations = self._audit_synthetic(
            {
                "codeql.yml": "on:\n"
                "  schedule:\n"
                "    - cron: '37 9 * * 2'\n"
                "    - cron: '0 * * * *'\n" + self._job()
            },
            pins={"codeql.yml": ("37 9 * * 2",)},
        )
        self.assertTrue(
            any("scheduled-trigger inventory" in item for item in violations),
            violations,
        )

    def test_missing_pinned_scheduled_workflow_is_a_violation(self):
        """Deleting a pinned workflow silently would also be drift."""

        violations = self._audit_synthetic(
            {"other.yml": self._job()},
            pins={"scheduled-security.yml": ("19 10 * * 6",)},
        )
        self.assertTrue(
            any("missing from the tree" in item for item in violations),
            violations,
        )

    def test_empty_workflow_tree_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(AssertionError, "no workflow files"):
                workflow_files(Path(directory))

    def test_undecodable_workflow_fails_closed(self):
        with self.assertRaisesRegex(AssertionError, "unreadable workflow"):
            self._audit_synthetic({"bad.yml": b"\xff\xfeon:"}, pins={})

    def test_scan_that_matches_no_runners_fails_closed(self):
        """A regex bitrot that stops matching runs-on must not pass."""

        with self.assertRaisesRegex(AssertionError, "no runs-on"):
            self._audit_synthetic({"bad.yml": "on: push\n"}, pins={})


if __name__ == "__main__":
    unittest.main()
