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
TAG = "v1.2.3"
ZERO_TAG = "v0.0.0"


def release_text(ready="false", digest=ZERO, tag=ZERO_TAG):
    return (
        "spec:\n"
        "  values:\n"
        "    deploymentReady: {}\n"
        "    image:\n"
        "      tag: {}\n"
        "      digest: {}\n".format(ready, tag, digest)
    ).encode("utf-8")


class ReleaseCandidateTests(unittest.TestCase):
    def test_initial_candidate_changes_only_tag_digest_and_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            output = root / "candidate.yaml"
            original.write_bytes(release_text())
            MODULE.create_candidate(original, output, DIGEST, TAG, "initial")
            self.assertEqual(
                output.read_bytes(), release_text("true", DIGEST, TAG)
            )

    def test_promoted_candidate_preserves_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            output = root / "candidate.yaml"
            original.write_bytes(
                release_text("true", "sha256:" + ("b" * 64), "v1.2.2")
            )
            MODULE.create_candidate(original, output, DIGEST, TAG, "promoted")
            self.assertEqual(
                output.read_bytes(), release_text("true", DIGEST, TAG)
            )

    def test_the_release_name_and_the_release_bytes_advance_together(self):
        """One transaction writes both halves of the identity, or neither.

        promote-image.sh proves the registry maps the requested tag to the
        requested digest before this runs, so a candidate that moved only one
        of the pair would publish a release name the transaction never bound
        to the bytes beside it. The source must expose exactly one of each
        target, and the result must carry both new values.
        """

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            original.write_bytes(release_text("true", "sha256:" + ("b" * 64), "v1.2.2"))

            # A source with no tag line cannot receive one: the candidate is a
            # substitution, never an insertion, so a release.yaml that lost the
            # tag field fails closed instead of silently promoting without it.
            missing_tag = root / "missing-tag.yaml"
            missing_tag.write_bytes(
                b"spec:\n  values:\n    deploymentReady: true\n"
                b"    image:\n      digest: " + ("sha256:" + "b" * 64).encode() + b"\n"
            )
            with self.assertRaises(MODULE.CandidateError):
                MODULE.create_candidate(
                    missing_tag, root / "a.yaml", DIGEST, TAG, "promoted"
                )
            self.assertFalse((root / "a.yaml").exists())

            # Two tag lines are as ambiguous as two digest lines.
            duplicate_tag = root / "duplicate-tag.yaml"
            duplicate_tag.write_bytes(
                b"spec:\n  values:\n    deploymentReady: true\n    image:\n"
                b"      tag: v1.2.2\n      tag: v1.2.2\n"
                b"      digest: " + ("sha256:" + "b" * 64).encode() + b"\n"
            )
            with self.assertRaises(MODULE.CandidateError):
                MODULE.create_candidate(
                    duplicate_tag, root / "b.yaml", DIGEST, TAG, "promoted"
                )
            self.assertFalse((root / "b.yaml").exists())

    def test_a_tag_outside_the_release_grammar_is_refused(self):
        """A lying or floating release name never reaches a candidate.

        Every shape below would put a name on the workload that is not one
        exact published release, so the candidate is refused before any file is
        created — including the sentinel, which is the state promotion moves
        AWAY from and can never move toward.
        """

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            original.write_bytes(release_text())
            for index, bad in enumerate(
                (
                    ZERO_TAG,
                    "latest",
                    "1.2.3",
                    "v1.2",
                    "v1.2.3.rc",
                    "v01.2.3",
                    "vmain",
                    "v1.2.3 ",
                    "",
                    DIGEST,
                )
            ):
                output = root / "candidate-{}.yaml".format(index)
                with self.subTest(tag=bad):
                    with self.assertRaises(MODULE.CandidateError):
                        MODULE.create_candidate(
                            original, output, DIGEST, bad, "initial"
                        )
                    self.assertFalse(output.exists())

    def test_rejects_duplicate_targets_existing_output_and_symlink_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            output = root / "candidate.yaml"
            original.write_bytes(release_text() + release_text())
            with self.assertRaises(MODULE.CandidateError):
                MODULE.create_candidate(original, output, DIGEST, TAG, "initial")

            original.write_bytes(release_text())
            output.write_bytes(b"keep\n")
            with self.assertRaises(MODULE.CandidateError):
                MODULE.create_candidate(original, output, DIGEST, TAG, "initial")
            self.assertEqual(output.read_bytes(), b"keep\n")

            if hasattr(os, "symlink"):
                link = root / "link.yaml"
                try:
                    link.symlink_to(original)
                except OSError:
                    self.skipTest("symlink creation is unavailable")
                with self.assertRaises(MODULE.CandidateError):
                    MODULE.create_candidate(
                        link, root / "link-output.yaml", DIGEST, TAG, "initial"
                    )


if __name__ == "__main__":
    unittest.main()
