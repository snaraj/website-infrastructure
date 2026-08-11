"""Exercise the candidate-only release patch boundary."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = load_script("create_release_patch.py")
RELATIVE = "kubernetes/websites/naranjo-online/release.yaml"


class ReleasePatchTests(unittest.TestCase):
    def test_patch_applies_only_the_closed_release_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / RELATIVE
            target.parent.mkdir(parents=True)
            target.write_bytes(b"digest: old\n")
            candidate = root / "candidate.yaml"
            candidate.write_bytes(b"digest: new\n")
            patch = root / "review.patch"

            MODULE.create_patch(target, candidate, RELATIVE, patch)
            text = patch.read_text(encoding="utf-8")
            self.assertIn("--- a/" + RELATIVE, text)
            self.assertIn("+++ b/" + RELATIVE, text)
            self.assertNotIn(str(root), text)

            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "core.autocrlf", "false"], cwd=root, check=True
            )
            subprocess.run(["git", "add", "--", RELATIVE], cwd=root, check=True)
            subprocess.run(
                ["git", "apply", "--check", "--", str(patch)],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "apply", "--", str(patch)], cwd=root, check=True
            )
            self.assertEqual(target.read_bytes(), candidate.read_bytes())

    def test_rejects_noop_unsafe_path_and_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            candidate = root / "candidate.yaml"
            output = root / "review.patch"
            original.write_bytes(b"value: old\n")
            candidate.write_bytes(b"value: old\n")
            with self.assertRaises(MODULE.PatchError):
                MODULE.create_patch(original, candidate, RELATIVE, output)

            candidate.write_bytes(b"value: new\n")
            with self.assertRaises(MODULE.PatchError):
                MODULE.create_patch(original, candidate, "../release.yaml", output)

            output.write_bytes(b"keep\n")
            with self.assertRaises(MODULE.PatchError):
                MODULE.create_patch(original, candidate, RELATIVE, output)
            self.assertEqual(output.read_bytes(), b"keep\n")

    def test_rejects_non_lf_oversized_and_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original.yaml"
            candidate = root / "candidate.yaml"
            original.write_bytes(b"value: old\r\n")
            candidate.write_bytes(b"value: new\n")
            with self.assertRaises(MODULE.PatchError):
                MODULE.create_patch(original, candidate, RELATIVE, root / "one.patch")

            original.write_bytes(b"x" * (MODULE.MAX_RELEASE_BYTES + 1) + b"\n")
            with self.assertRaises(MODULE.PatchError):
                MODULE.create_patch(original, candidate, RELATIVE, root / "two.patch")

            if hasattr(os, "symlink"):
                original.write_bytes(b"value: old\n")
                link = root / "link.yaml"
                try:
                    link.symlink_to(original)
                except OSError:
                    self.skipTest("symlink creation is unavailable")
                with self.assertRaises(MODULE.PatchError):
                    MODULE.create_patch(link, candidate, RELATIVE, root / "three.patch")


if __name__ == "__main__":
    unittest.main()
