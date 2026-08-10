"""Exercise exclusive construction of one release-state candidate."""

import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import create_release_candidate as MODULE  # noqa: E402


DIGEST = "sha256:" + ("a" * 64)
ZERO = "sha256:" + ("0" * 64)


def release_text(ready="false", digest=ZERO):
    return (
        "spec:\n"
        "  values:\n"
        "    deploymentReady: {}\n"
        "    image:\n"
        "      digest: {}\n".format(ready, digest)
    ).encode("utf-8")


class ReleaseCandidateTests(unittest.TestCase):
    def test_initial_candidate_changes_only_digest_and_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            output = root / "candidate.yaml"
            original.write_bytes(release_text())
            MODULE.create_candidate(original, output, DIGEST, "initial")
            self.assertEqual(output.read_bytes(), release_text("true", DIGEST))

    def test_promoted_candidate_preserves_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            output = root / "candidate.yaml"
            original.write_bytes(release_text("true", "sha256:" + ("b" * 64)))
            MODULE.create_candidate(original, output, DIGEST, "promoted")
            self.assertEqual(output.read_bytes(), release_text("true", DIGEST))

    def test_rejects_duplicate_targets_existing_output_and_symlink_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            output = root / "candidate.yaml"
            original.write_bytes(release_text() + release_text())
            with self.assertRaises(MODULE.CandidateError):
                MODULE.create_candidate(original, output, DIGEST, "initial")

            original.write_bytes(release_text())
            output.write_bytes(b"keep\n")
            with self.assertRaises(MODULE.CandidateError):
                MODULE.create_candidate(original, output, DIGEST, "initial")
            self.assertEqual(output.read_bytes(), b"keep\n")

            if hasattr(os, "symlink"):
                link = root / "link.yaml"
                try:
                    link.symlink_to(original)
                except OSError:
                    self.skipTest("symlink creation is unavailable")
                with self.assertRaises(MODULE.CandidateError):
                    MODULE.create_candidate(link, root / "link-output.yaml", DIGEST, "initial")


if __name__ == "__main__":
    unittest.main()
