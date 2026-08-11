"""Exercise exclusive bounded writes for promotion review artifacts."""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = load_script("write_review_artifact.py")


class ReviewArtifactWriterTests(unittest.TestCase):
    def test_exclusive_regular_write(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "evidence.env"
            MODULE.write_exclusive(output, b"SCHEMA=review-v1\n")
            self.assertEqual(output.read_bytes(), b"SCHEMA=review-v1\n")
            self.assertTrue(stat.S_ISREG(output.stat().st_mode))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_rejects_existing_file_and_symlink_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "evidence.env"
            output.write_bytes(b"keep\n")
            with self.assertRaises(MODULE.ArtifactError):
                MODULE.write_exclusive(output, b"replace\n")
            self.assertEqual(output.read_bytes(), b"keep\n")

            if hasattr(os, "symlink"):
                link = root / "link.env"
                try:
                    link.symlink_to(output)
                except OSError:
                    self.skipTest("symlink creation is unavailable")
                with self.assertRaises(MODULE.ArtifactError):
                    MODULE.write_exclusive(link, b"replace\n")
                self.assertEqual(output.read_bytes(), b"keep\n")

    def test_bounded_file_copy_rejects_symlink_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.yaml"
            source.write_bytes(b"value: safe\n")
            self.assertEqual(MODULE.read_bounded_file(source), b"value: safe\n")
            if hasattr(os, "symlink"):
                link = root / "source-link.yaml"
                try:
                    link.symlink_to(source)
                except OSError:
                    self.skipTest("symlink creation is unavailable")
                with self.assertRaises(MODULE.ArtifactError):
                    MODULE.read_bounded_file(link)

    def test_stdin_contract_rejects_oversize_cr_and_controls(self):
        invalid = (
            b"x" * (MODULE.MAX_ARTIFACT_BYTES + 1),
            b"value\r\n",
            b"value=bad\x00\n",
        )
        for raw in invalid:
            with self.subTest(size=len(raw)):
                original = MODULE.sys.stdin

                class FakeStdin:
                    def __init__(self, value):
                        from io import BytesIO

                        self.buffer = BytesIO(value)

                MODULE.sys.stdin = FakeStdin(raw)
                try:
                    with self.assertRaises(MODULE.ArtifactError):
                        MODULE.read_bounded_stdin()
                finally:
                    MODULE.sys.stdin = original

    def test_explicit_windows_transport_normalization_keeps_lf_output(self):
        original = MODULE.sys.stdin

        class FakeStdin:
            def __init__(self):
                from io import BytesIO

                self.buffer = BytesIO(b"one\r\ntwo\r\n")

        MODULE.sys.stdin = FakeStdin()
        try:
            self.assertEqual(
                MODULE.read_bounded_stdin(normalize_crlf=True), b"one\ntwo\n"
            )
        finally:
            MODULE.sys.stdin = original


if __name__ == "__main__":
    unittest.main()
