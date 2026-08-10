"""Exercise no-follow cleanup of failed promotion transactions."""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "remove_review_transaction.py"
SPEC = importlib.util.spec_from_file_location("remove_review_transaction", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReviewTransactionCleanupTests(unittest.TestCase):
    def test_removes_only_exact_owned_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory).resolve() / ".artifacts"
            transaction = artifact / "promotion.naranjo-online.A1b2C3"
            transaction.mkdir(parents=True)
            (transaction / "partial.env").write_bytes(b"partial\n")
            MODULE.remove_transaction(artifact, transaction, "naranjo-online")
            self.assertFalse(transaction.exists())
            self.assertTrue(artifact.is_dir())

    def test_rejects_wrong_name_and_symlink_root_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / ".artifacts"
            artifact.mkdir()
            wrong = artifact / "unrelated"
            wrong.mkdir()
            with self.assertRaises(MODULE.CleanupError):
                MODULE.remove_transaction(artifact, wrong, "naranjo-online")
            self.assertTrue(wrong.is_dir())

            if hasattr(os, "symlink"):
                target = Path(directory) / "target"
                target.mkdir()
                marker = target / "keep.txt"
                marker.write_bytes(b"keep\n")
                link = artifact / "promotion.naranjo-online.A1b2C3"
                try:
                    link.symlink_to(target, target_is_directory=True)
                except OSError:
                    self.skipTest("directory symlink creation is unavailable")
                with self.assertRaises(MODULE.CleanupError):
                    MODULE.remove_transaction(artifact, link, "naranjo-online")
                self.assertEqual(marker.read_bytes(), b"keep\n")


if __name__ == "__main__":
    unittest.main()
