"""Merge-path GitHub Actions spend-exposure audit (issue #45).

GitHub-side spend is clean today — every job runs on the free
``ubuntu-24.04`` runner, every action is commit-pinned, every job has a
positive timeout, no artifact retention is configured, and the two scheduled
workflows fire weekly —
but nothing on the merge path would fail if a larger or macOS runner, an
unpinned third-party action, artifact retention, or a fast cron
appeared. This battery pins that exposure surface so the CI unittest
sweep rejects the drift in the pull request that introduces it.

The audit uses a dependency-free strict YAML structure parser. It follows
mapping indentation and block scalars, accepts any valid block indentation,
and identifies every direct child of ``jobs`` before judging its direct
``runs-on`` and ``timeout-minutes`` fields. Unsupported flow mappings that
could hide a job, runner, timeout, action, or schedule fail closed. Symlinks
anywhere under the scanned tree are failures too. The deny-path tests execute
four-space jobs, nested/matrix decoys, flow mappings, and block-scalar decoys so
timeout coverage cannot become vacuous through formatting.
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

_KEY_LINE = re.compile(
    r"^(?P<indent> *)(?P<sequence>-\s+)?"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?P<value>.*)$"
)
# The one scalar trigger form that cannot smuggle spend configuration
# (``on: push``). Anything else after ``on:`` — flow mappings, flow
# sequences, quoting tricks — must be rewritten in block style.
_BARE_TRIGGER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Fail-closed net for everything the anchored classifiers above did not
# match: a spend-relevant token anywhere else on a non-comment line is
# an unclassifiable shape (flow-style YAML, odd quoting) and is denied
# outright rather than silently passed.
_SPEND_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:runs-on|timeout-minutes|uses|cron|schedule|jobs)\s*:"
)


def _flow_violation(path, number, line):
    return (
        "spend-relevant token outside the strict block YAML structure "
        "(flow-style YAML is forbidden) at {}:{}: {!r}".format(
            path, number, line.strip()
        )
    )


def _parse_workflow(path, text):
    """Return a closed workflow shape plus structural violations.

    GitHub/actionlint remains the complete YAML grammar authority. This parser
    deliberately handles only the block mapping/sequence shapes needed to
    enumerate triggers and jobs; a flow value carrying a governed key is a
    denial rather than an input whose nested structure is guessed.
    """

    violations = []
    stack = []
    block_scalar_indent = None
    shape = {
        "events": set(),
        "jobs": {},
        "crons": [],
        "schedule_lines": 0,
        "trigger_values": {},
    }
    root_on_count = 0
    root_jobs_count = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            violations.append(
                "tabs are forbidden in workflow indentation at {}:{}".format(
                    path, number
                )
            )
            continue
        indent = len(line) - len(line.lstrip(" "))
        if block_scalar_indent is not None:
            if indent > block_scalar_indent:
                continue
            block_scalar_indent = None
        match = _KEY_LINE.match(line)
        if match is None:
            if _SPEND_TOKEN.search(line):
                violations.append(_flow_violation(path, number, line))
            continue
        key = match.group("key")
        value = match.group("value").strip()
        while stack and stack[-1]["indent"] >= indent:
            stack.pop()
        parent = stack[-1]["path"] if stack else ()
        current = parent + (key,)

        if key == "on" and not parent:
            root_on_count += 1
            if not value:
                pass
            elif _BARE_TRIGGER.fullmatch(value):
                shape["events"].add(value)
            else:
                violations.append(
                    "workflow trigger value must be one bare event or "
                    "block-style at {}:{}: {!r}".format(path, number, value)
                )
        elif len(current) == 2 and current[0] == "on":
            shape["events"].add(key)
            shape["trigger_values"][key] = value

        if key == "jobs" and not parent:
            root_jobs_count += 1
            if value:
                violations.append(_flow_violation(path, number, line))
        elif parent == ("jobs",):
            jobs = shape["jobs"]
            if key in jobs:
                violations.append(
                    "duplicate workflow job {!r} at {}:{}".format(key, path, number)
                )
            jobs.setdefault(key, {"runs-on": [], "timeout-minutes": []})
            if value:
                violations.append(_flow_violation(path, number, line))
        elif len(current) == 3 and current[0] == "jobs" and current[1] in shape["jobs"]:
            if key in {"runs-on", "timeout-minutes"}:
                shape["jobs"][current[1]][key].append((value, number))
        elif key in {"runs-on", "timeout-minutes"}:
            violations.append(
                "{} appears outside a direct job mapping at {}:{}".format(
                    key, path, number
                )
            )

        if key == "uses":
            reference = _unquoted(value)
            if _PINNED_USES.fullmatch(reference) is None:
                violations.append(
                    "uses is not pinned to a 40-hex commit SHA at "
                    "{}:{}: {!r}".format(path, number, reference)
                )
        if key == "retention-days":
            violations.append("artifact retention is configured in " + str(path))
        if current == ("on", "schedule"):
            shape["schedule_lines"] += 1
            if value:
                violations.append(_flow_violation(path, number, line))
        elif key == "schedule":
            violations.append(
                "schedule appears outside the workflow trigger mapping at {}:{}".format(
                    path, number
                )
            )
        if current == ("on", "schedule", "cron"):
            shape["crons"].append(_unquoted(value))
        elif key == "cron":
            violations.append(
                "cron appears outside on.schedule at {}:{}".format(path, number)
            )

        if key not in {"jobs", "runs-on", "timeout-minutes", "uses", "schedule", "cron"} and _SPEND_TOKEN.search(value):
            violations.append(_flow_violation(path, number, line))
        if re.fullmatch(r"[|>]([+-])?[1-9]?", value):
            block_scalar_indent = indent
        stack.append({"indent": indent, "path": current})

    if root_on_count != 1:
        violations.append(
            "workflow must contain exactly one root on mapping in {}".format(path)
        )
    if root_jobs_count != 1:
        violations.append(
            "workflow must contain exactly one root jobs mapping in {}".format(path)
        )
    return shape, violations


def workflow_files(workflow_root):
    """Return every workflow file under one tree, failing closed on none.

    Symlinks anywhere under the tree (or the tree itself) are failures:
    ``rglob`` does not traverse symlinked directories, so a symlink
    could point scanned content out of this audit's sight.
    """

    root = Path(workflow_root)
    symlinks = sorted(
        str(path) for path in [root, *root.rglob("*")] if path.is_symlink()
    )
    if symlinks:
        raise AssertionError(
            "fail closed: symlinks are forbidden under the scanned workflow "
            "tree (content behind a symlink escapes the audit): "
            + ", ".join(symlinks)
        )
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
    unreadable, or when the scan matched no ``runs-on`` line anywhere
    and found no violation either (a silent all-quiet result means the
    scan itself is broken). Spend-relevant tokens the anchored
    block-style classifiers cannot place — flow-style YAML above all —
    are violations, never silent passes.
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
        shape, structural = _parse_workflow(path, text)
        violations.extend(structural)
        for job, fields in sorted(shape["jobs"].items()):
            runners = fields["runs-on"]
            timeouts = fields["timeout-minutes"]
            if len(runners) != 1:
                violations.append(
                    "job {!r} must contain exactly one direct runs-on in {}".format(
                        job, path
                    )
                )
            else:
                runner_lines += 1
                raw_runner, number = runners[0]
                runner = _unquoted(raw_runner)
                if runner not in allowed_runners:
                    violations.append(
                        "runs-on is outside the pinned free-runner "
                        "allowlist at {}:{}: {!r}".format(path, number, runner)
                    )
            if len(timeouts) != 1:
                violations.append(
                    "job {!r} must contain exactly one direct positive "
                    "timeout-minutes in {}".format(job, path)
                )
            else:
                raw_timeout, number = timeouts[0]
                timeout = _unquoted(raw_timeout)
                if re.fullmatch(r"[1-9][0-9]*", timeout) is None:
                    violations.append(
                        "timeout-minutes must be one positive literal at "
                        "{}:{}: {!r}".format(path, number, timeout)
                    )
        observed_crons[path.name] = tuple(shape["crons"])
        observed_schedule_lines[path.name] = shape["schedule_lines"]
    if runner_lines == 0:
        raise AssertionError(
            "fail closed: the workflow scan matched no runs-on lines and "
            "reported no violations; the scan itself is broken"
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
            + "    timeout-minutes: 30\n"
            + extra
        )

    def test_missing_zero_expression_and_duplicate_timeouts_are_violations(self):
        base = self._job()
        mutations = (
            base.replace("    timeout-minutes: 30\n", ""),
            base.replace("timeout-minutes: 30", "timeout-minutes: 0"),
            base.replace("timeout-minutes: 30", "timeout-minutes: ${{ vars.TIMEOUT }}"),
            base.replace(
                "    timeout-minutes: 30\n",
                "    timeout-minutes: 30\n    timeout-minutes: 40\n",
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(timeout_mutation=index):
                violations = self._audit_synthetic({"bad.yml": workflow}, pins={})
                self.assertTrue(
                    any("timeout-minutes" in item for item in violations), violations
                )

    def test_four_space_job_indentation_is_parsed_and_missing_timeout_is_denied(self):
        valid = (
            "on: push\n"
            "jobs:\n"
            "    scan:\n"
            "        runs-on: ubuntu-24.04\n"
            "        timeout-minutes: 30\n"
            "        steps:\n"
            "          - run: echo ok\n"
        )
        self.assertEqual(self._audit_synthetic({"valid.yml": valid}, pins={}), [])
        violations = self._audit_synthetic(
            {"missing.yml": valid.replace("        timeout-minutes: 30\n", "")},
            pins={},
        )
        self.assertTrue(
            any("scan" in item and "timeout-minutes" in item for item in violations),
            violations,
        )

    def test_nested_matrix_timeout_cannot_satisfy_the_direct_job_timeout(self):
        workflow = (
            "on: push\n"
            "jobs:\n"
            "   matrix_job:\n"
            "      runs-on: ubuntu-24.04\n"
            "      strategy:\n"
            "         matrix:\n"
            "            timeout-minutes: 30\n"
            "            os: [ubuntu-24.04]\n"
            "      steps:\n"
            "        - run: echo ok\n"
        )
        violations = self._audit_synthetic({"nested.yml": workflow}, pins={})
        self.assertTrue(
            any("outside a direct job" in item for item in violations), violations
        )
        self.assertTrue(
            any("matrix_job" in item and "timeout-minutes" in item for item in violations),
            violations,
        )

    def test_block_scalar_job_decoy_is_ignored_but_real_job_stays_counted(self):
        workflow = (
            "on: push\n"
            "jobs:\n"
            "  scan:\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - run: |\n"
            "          jobs:\n"
            "            hidden:\n"
            "              runs-on: macos-14\n"
            "              timeout-minutes: 0\n"
        )
        self.assertEqual(self._audit_synthetic({"scalar.yml": workflow}, pins={}), [])

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

    def test_flow_style_jobs_mapping_is_rejected(self):
        """Reviewer evasion, verbatim: a flow-style job hiding a paid runner.

        The companion clean file reproduces the reviewed scenario where
        other workflows still contribute block-style runs-on lines, so
        the vacuity guard alone would never have caught this.
        """

        violations = self._audit_synthetic(
            {
                "bad.yml": "jobs: {m: {runs-on: macos-latest, "
                "steps: [{run: echo hi}]}}\n",
                "good.yml": self._job(),
            },
            pins={},
        )
        self.assertTrue(
            any(
                "flow-style YAML is forbidden" in item and "bad.yml" in item
                for item in violations
            ),
            violations,
        )

    def test_flow_style_schedule_is_rejected(self):
        """Reviewer evasion, verbatim: a five-minute cron in a flow trigger."""

        violations = self._audit_synthetic(
            {
                "bad.yml": 'on: {schedule: [{cron: "*/5 * * * *"}]}\n'
                + self._job()
            },
            pins={},
        )
        self.assertTrue(
            any("block-style" in item and "bad.yml" in item for item in violations),
            violations,
        )

    def test_flow_style_trigger_sequence_is_rejected(self):
        """Any non-scalar on: value must be rewritten in block style."""

        violations = self._audit_synthetic(
            {"bad.yml": "on: [push, schedule]\n" + self._job()}, pins={}
        )
        self.assertTrue(
            any("block-style" in item for item in violations), violations
        )

    def test_flow_style_step_uses_is_rejected(self):
        """A flow-mapping step hides its uses: from the anchored classifier."""

        violations = self._audit_synthetic(
            {
                "bad.yml": self._job(
                    extra="    steps: [{uses: third-party/setup-anything@v4}]\n"
                )
            },
            pins={},
        )
        self.assertTrue(
            any("flow-style YAML is forbidden" in item for item in violations),
            violations,
        )

    def test_symlinked_workflow_tree_fails_closed(self):
        """A symlink could point scanned content out of the audit's sight."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            outside = base / "outside.yml"
            outside.write_text(self._job("macos-14"), encoding="utf-8")
            root = base / "workflows"
            root.mkdir()
            (root / "good.yml").write_text(self._job(), encoding="utf-8")
            try:
                (root / "linked.yml").symlink_to(outside)
            except OSError as error:
                self.skipTest("cannot create symlinks here: " + str(error))
            with self.assertRaisesRegex(AssertionError, "symlink"):
                workflow_files(root)

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
