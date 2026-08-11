"""End-to-end fail-closed battery for the review-artifact writer CLI.

``write_review_artifact.py`` is the promotion pipeline's only approved way
to persist review evidence: exclusive create, 0600, no symlink following
anywhere on the path, bounded canonical LF text. Its ``main()`` had never
run under test. The CLI deliberately collapses every failure into one
content-neutral stderr line, so these cases assert that line plus the
on-disk consequences (nothing created, nothing clobbered) rather than the
internal reason strings, which stay covered at module level.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WRITER = REPO_ROOT / "scripts" / "write_review_artifact.py"
ERROR_LINE = "ERROR review artifact could not be written safely"
PAYLOAD = b"SCHEMA=review-v1\nRESULT=PASS\n"


def run_writer(*argv, stdin=None):
    return subprocess.run(
        [sys.executable, "-B", str(WRITER), *argv],
        input=stdin,
        capture_output=True,
    )


class WriteReviewArtifactCliTests(unittest.TestCase):
    """One safe way to write evidence; every unsafe request changes nothing."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        # Resolve: macOS TMPDIR sits under the /var symlink, and the writer
        # rejects any symlinked path component by design.
        self.root = Path(self._directory.name).resolve()
        self.output = self.root / "evidence.env"

    def assert_failed_without_side_effects(self, completed):
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn(ERROR_LINE.encode(), completed.stderr)
        self.assertFalse(self.output.exists())

    def test_stdin_payload_is_written_exclusively_with_0600(self):
        completed = run_writer("--output", str(self.output), stdin=PAYLOAD)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(self.output.read_bytes(), PAYLOAD)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_input_file_payload_is_written(self):
        source = self.root / "input.env"
        source.write_bytes(PAYLOAD)
        completed = run_writer("--output", str(self.output), "--input", str(source))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.output.read_bytes(), PAYLOAD)

    def test_crlf_stdin_is_normalized_only_on_request(self):
        crlf = b"SCHEMA=review-v1\r\nRESULT=PASS\r\n"
        self.assert_failed_without_side_effects(
            run_writer("--output", str(self.output), stdin=crlf)
        )
        completed = run_writer(
            "--output", str(self.output), "--normalize-crlf", stdin=crlf
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.output.read_bytes(), PAYLOAD)

    def test_unterminated_empty_and_oversize_stdin_are_rejected(self):
        for label, payload in (
            ("empty", b""),
            ("unterminated", b"SCHEMA=review-v1"),
            ("oversize", b"x" * (1024 * 1024) + b"y\n"),
            ("lone-cr", b"a\rb\n"),
            ("nul-byte", b"a\x00b\n"),
            ("escape-byte", b"a\x1bb\n"),
            ("invalid-utf8", b"\xff\xfe\n"),
        ):
            with self.subTest(payload=label):
                self.assert_failed_without_side_effects(
                    run_writer("--output", str(self.output), stdin=payload)
                )

    def test_existing_output_file_is_never_clobbered(self):
        self.output.write_text("previous evidence\n")
        completed = run_writer("--output", str(self.output), stdin=PAYLOAD)
        self.assertEqual(completed.returncode, 1)
        self.assertIn(ERROR_LINE.encode(), completed.stderr)
        self.assertEqual(self.output.read_text(), "previous evidence\n")

    def test_symlink_output_is_refused_and_target_untouched(self):
        elsewhere = self.root / "elsewhere.env"
        self.output.symlink_to(elsewhere)
        completed = run_writer("--output", str(self.output), stdin=PAYLOAD)
        self.assertEqual(completed.returncode, 1)
        self.assertIn(ERROR_LINE.encode(), completed.stderr)
        self.assertFalse(elsewhere.exists())

    def test_symlinked_parent_directory_is_refused(self):
        real_dir = self.root / "real"
        real_dir.mkdir()
        linked_dir = self.root / "linked"
        linked_dir.symlink_to(real_dir)
        completed = run_writer(
            "--output", str(linked_dir / "evidence.env"), stdin=PAYLOAD
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(ERROR_LINE.encode(), completed.stderr)
        self.assertFalse((real_dir / "evidence.env").exists())

    def test_symlink_directory_and_empty_inputs_are_refused(self):
        source = self.root / "input.env"
        source.write_bytes(PAYLOAD)
        link = self.root / "input-link.env"
        link.symlink_to(source)
        empty = self.root / "empty.env"
        empty.write_bytes(b"")
        for label, path in (
            ("symlink", link),
            ("directory", self.root),
            ("empty", empty),
            ("missing", self.root / "absent.env"),
        ):
            with self.subTest(input=label):
                self.assert_failed_without_side_effects(
                    run_writer(
                        "--output", str(self.output), "--input", str(path)
                    )
                )

    def test_missing_output_argument_is_a_usage_error(self):
        completed = run_writer(stdin=PAYLOAD)
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"--output", completed.stderr)


if __name__ == "__main__":
    unittest.main()
