"""Exercise every retained signature-contract CLI entry point."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_signature_policy.py"
SOURCE = ROOT / "kubernetes/websites/naranjo-online/source.yaml"


class SignaturePolicyCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            ["python3", "-B", str(SCRIPT), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def source_args(self, path):
        return ("chart-source", "--file", path, "--site", "naranjo-online")

    def assert_rejected(self, completed, fragment, code=1):
        self.assertEqual(completed.returncode, code, completed.stderr)
        self.assertIn(fragment, completed.stderr)
        self.assertNotIn("PASS", completed.stdout)

    def test_retained_entry_points_accept_reviewed_sources(self):
        cases = (
            (
                "chart-source",
                "--file",
                ROOT / "kubernetes/websites/naranjo-online/source.yaml",
                "--site",
                "naranjo-online",
            ),
            (
                "flux-system-kustomization",
                "--file",
                ROOT / "kubernetes/flux-system/kustomization.yaml",
            ),
            (
                "flux-sync",
                "--file",
                ROOT / "kubernetes/flux-system/gotk-sync.yaml.in",
            ),
        )
        for case in cases:
            with self.subTest(command=case[0]):
                completed = self.run_cli(*case)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("PASS", completed.stdout)

    def test_mutable_chart_selector_is_rejected(self):
        source = (
            ROOT / "kubernetes/websites/naranjo-online/source.yaml"
        ).read_text(encoding="utf-8")
        source = source.replace(
            "    digest: sha256:",
            "    tag: v0.1.46\n  # removed immutable digest: sha256:",
            1,
        )
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "source.yaml"
            path.write_text(source, encoding="utf-8")
            completed = self.run_cli(
                "chart-source",
                "--file",
                path,
                "--site",
                "naranjo-online",
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("ERROR", completed.stderr)

    def test_nonregular_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            completed = self.run_cli(
                "chart-source",
                "--file",
                scratch,
                "--site",
                "naranjo-online",
            )
        self.assertNotEqual(completed.returncode, 0)

    def test_noncanonical_encodings_are_rejected(self):
        text = SOURCE.read_text(encoding="utf-8")
        cases = (
            ("crlf.yaml", text.replace("\n", "\r\n", 1).encode(), "must use LF line endings"),
            ("tab.yaml", text.replace("  interval", "\tinterval", 1).encode(), "must not contain tabs"),
            ("bom.yaml", b"\xef\xbb\xbf" + text.encode(), "must not contain a UTF-8 BOM"),
            ("no-lf.yaml", text.rstrip("\n").encode(), "must end with one LF"),
            ("binary.yaml", text.encode() + b"\xff\xfe\n", "policy input is not valid UTF-8"),
        )
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for name, payload, fragment in cases:
                hostile = root / name
                hostile.write_bytes(payload)
                with self.subTest(case=name):
                    self.assert_rejected(
                        self.run_cli(*self.source_args(hostile)), fragment
                    )

    def test_symlink_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            link = Path(scratch) / "source.yaml"
            link.symlink_to(SOURCE)
            self.assert_rejected(
                self.run_cli(*self.source_args(link)),
                "policy input must be one regular non-symlink file",
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo is unavailable")
    def test_fifo_input_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as scratch:
            fifo = Path(scratch) / "source.yaml"
            os.mkfifo(fifo)
            self.assert_rejected(
                self.run_cli(*self.source_args(fifo)),
                "policy input must be one regular non-symlink file",
            )

    def test_oversize_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            oversize = Path(scratch) / "source.yaml"
            oversize.write_text("#" + "x" * (64 * 1024) + "\n", encoding="utf-8")
            self.assert_rejected(
                self.run_cli(*self.source_args(oversize)),
                "policy input exceeds the 64 KiB ceiling",
            )

    def test_missing_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            missing = Path(scratch) / "absent.yaml"
            completed = self.run_cli(*self.source_args(missing))
        self.assertEqual(completed.returncode, 1)
        self.assertIn("ERROR", completed.stderr)
        self.assertNotIn("PASS", completed.stdout)

    def test_missing_subcommand_is_a_usage_error(self):
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 2)
        self.assertIn("usage", completed.stderr)


if __name__ == "__main__":
    unittest.main()
