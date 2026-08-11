"""End-to-end battery for the no-security-toggles scanner CLI.

The scanner is the tree-wide tripwire for disablement idioms (skip flags,
unsigned-artifact toggles, verification switches). Its ``main()`` and both
outcomes had never executed under test. The passing fixture is the real
tracked tree — the same invocation CI runs. Hostile fixtures are tree
copies keyed to the tracked file names (the scanner always enumerates the
repository's own ``git ls-files``, then reads those names under the ROOT
argument), each planted with a toggle idiom assembled from fragments at
runtime so this test file cannot itself trip the scanner.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_no_security_toggles.py"
PASS_LINE = "no-security-toggles: PASS no toggle idiom outside the justified allowlist"
# A tracked, non-allowlisted text file to plant hostile lines into.
PLANT_TARGET = "docs/assurance/README.md"


def run_scanner(root):
    return subprocess.run(
        [sys.executable, "-B", str(VALIDATOR), str(root)],
        capture_output=True,
        text=True,
    )


class NoSecurityTogglesCliTests(unittest.TestCase):
    """The real tree passes; a planted toggle idiom fails, loudly."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()

    def copy_tracked_tree(self):
        """Copy every tracked file (runtime-assembled hostile lines go on top)."""

        listed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
            capture_output=True,
            check=True,
        )
        for name in listed.stdout.decode().split("\0"):
            if not name:
                continue
            source = REPO_ROOT / name
            if not source.is_file() or source.is_symlink():
                continue
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        return self.root

    def test_the_tracked_tree_passes_end_to_end(self):
        completed = run_scanner(REPO_ROOT)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(PASS_LINE, completed.stdout)

    def test_planted_toggle_idioms_fail_the_copy(self):
        tree = self.copy_tracked_tree()
        target = tree / PLANT_TARGET
        original = target.read_text(encoding="utf-8")
        cases = (
            ("SK" + "IP_SIGNATURE_CHECK=1", "security-toggle identifier"),
            ("ALLOW_" + "UNSIGNED=1", "unsigned-artifact toggle"),
            ("git push --no-" + "verify", "no-verify flag"),
            ("curl --in" + "secure", "insecure flag"),
            ("--skip-" + "tls", "skip flag"),
            ("ver" + "ify=false", "verification disabled"),
        )
        for hostile_line, label in cases:
            with self.subTest(idiom=label):
                target.write_text(original + hostile_line + "\n", encoding="utf-8")
                completed = run_scanner(tree)
                self.assertEqual(completed.returncode, 1, completed.stdout)
                self.assertIn(PLANT_TARGET, completed.stderr)
                self.assertIn(label, completed.stderr)
                self.assertNotIn(PASS_LINE, completed.stdout)
        target.write_text(original, encoding="utf-8")

    def test_removed_allowlist_justification_fails_stale(self):
        # Deleting a justified line must fail the scan: an allowlist entry
        # matching nothing means the exemption has outlived its subject.
        tree = self.copy_tracked_tree()
        completed = run_scanner(tree)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        planted = tree / "bootstrap" / "pi" / "init-control-plane.sh"
        text = planted.read_text(encoding="utf-8")
        self.assertIn("--skip-token-print", text)
        planted.write_text(
            text.replace("--skip-token-print", "--show-token-print"),
            encoding="utf-8",
        )
        completed = run_scanner(tree)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("allowlist entry no longer matches anything", completed.stderr)

    def test_empty_root_fails_every_allowlist_expectation(self):
        # An empty ROOT means nothing matched any allowlist entry: the
        # scanner reports every stale exemption instead of passing quietly.
        completed = run_scanner(self.root)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("allowlist entry no longer matches anything", completed.stderr)
        self.assertNotIn(PASS_LINE, completed.stdout)

    def test_self_exempt_marker_removal_is_detected(self):
        tree = self.copy_tracked_tree()
        scanner_copy = tree / "scripts" / "validate_no_security_toggles.py"
        text = scanner_copy.read_text(encoding="utf-8")
        marker = "assembled from " + "fragments"
        self.assertIn(marker, text)
        scanner_copy.write_text(
            text.replace(marker, "assembled elsewhere"), encoding="utf-8"
        )
        completed = run_scanner(tree)
        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "scripts/validate_no_security_toggles.py: self-exempt marker is missing",
            completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
