"""End-to-end battery for the Cloudflare fixture mutator CLI.

The mutator manufactures the DENY fixtures for the OpenTofu policy tests:
if it silently produced an unmutated plan, the policy suite would "verify"
a fixture that never attacked anything. Its ``main()`` had never executed
under test. The passing cases prove a mutation really changes the plan and
is deterministic; the hostile cases prove unknown mutations, wrong phases,
and unreadable sources fail with exit 1 on stderr instead of emitting a
fixture at all.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MUTATOR = REPO_ROOT / "scripts" / "mutate_cloudflare_fixture.py"
FIXTURES = REPO_ROOT / "infrastructure" / "cloudflare" / "tests" / "fixtures"
SOURCE = FIXTURES / "allow-admin-tunnel.json"
FAIL_PREFIX = b"FAIL unable to create Cloudflare fixture mutation: "


def run_mutator(mutation, source, output):
    return subprocess.run(
        [sys.executable, "-B", str(MUTATOR), mutation, str(source), str(output)],
        capture_output=True,
    )


class MutateCloudflareFixtureCliTests(unittest.TestCase):
    """Mutations must really mutate; anything unknown must not emit output."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()
        self.output = self.root / "deny.json"

    def assert_failed_without_output(self, completed, fragment):
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn(FAIL_PREFIX, completed.stderr)
        self.assertIn(fragment, completed.stderr)
        self.assertFalse(self.output.exists(), "a failed mutation must emit nothing")

    def test_valid_mutation_produces_a_changed_deterministic_plan(self):
        completed = run_mutator("false-approval", SOURCE, self.output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, b"")
        mutated = json.loads(self.output.read_text(encoding="utf-8"))
        original = json.loads(SOURCE.read_text(encoding="utf-8"))
        self.assertNotEqual(mutated, original, "mutation did not change the plan")
        # Same phase contract retained: the deny fixture must still target
        # the phase whose policy suite consumes it.
        self.assertEqual(
            mutated["codex_contract"]["phase"],
            original["codex_contract"]["phase"],
        )
        second = self.root / "second.json"
        again = run_mutator("false-approval", SOURCE, second)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(second.read_bytes(), self.output.read_bytes())

    def test_unknown_mutation_name_is_rejected(self):
        self.assert_failed_without_output(
            run_mutator("bogus-name", SOURCE, self.output),
            b"unknown mutation bogus-name for admin-tunnel",
        )

    def test_phase_mismatched_mutation_is_rejected(self):
        # 'wrong-public-hostname' only exists for the public DNS phases;
        # asking for it from the admin-tunnel fixture must fail closed.
        self.assert_failed_without_output(
            run_mutator("wrong-public-hostname", SOURCE, self.output),
            b"admin-tunnel",
        )

    def test_missing_and_non_json_sources_are_rejected(self):
        completed = run_mutator(
            "false-approval", self.root / "absent.json", self.output
        )
        self.assert_failed_without_output(completed, b"No such file")
        broken = self.root / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        completed = run_mutator("false-approval", broken, self.output)
        self.assertEqual(completed.returncode, 1)
        self.assertIn(FAIL_PREFIX, completed.stderr)
        self.assertFalse(self.output.exists())

    def test_source_without_contract_is_rejected(self):
        stripped = json.loads(SOURCE.read_text(encoding="utf-8"))
        del stripped["codex_contract"]
        source = self.root / "stripped.json"
        source.write_text(json.dumps(stripped), encoding="utf-8")
        self.assert_failed_without_output(
            run_mutator("false-approval", source, self.output),
            b"codex_contract",
        )

    def test_unwritable_output_directory_is_rejected(self):
        completed = run_mutator(
            "false-approval", SOURCE, self.root / "missing-dir" / "deny.json"
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(FAIL_PREFIX, completed.stderr)

    def test_missing_positionals_are_a_usage_error(self):
        completed = subprocess.run(
            [sys.executable, "-B", str(MUTATOR), "false-approval"],
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"usage", completed.stderr)


if __name__ == "__main__":
    unittest.main()
