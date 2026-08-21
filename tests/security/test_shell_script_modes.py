#!/usr/bin/env python3
"""Protect Linux shell entrypoint modes from Windows working-tree defaults."""

import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
# These files are sourced by privileged entrypoints and deliberately have no
# standalone control path. Every other tracked shell file is user- or CI-run.
SOURCE_ONLY_SHELL_FILES = {
    "bootstrap/pi/host-prerequisites/lib.sh",
    "bootstrap/pi/ingress-guard/transaction-lib.sh",
}


def tracked_shell_modes():
    """Return Git index modes because NTFS cannot represent the Linux contract."""

    result = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), "ls-files", "--stage", "-z", "--", "*.sh"],
        check=True,
        capture_output=True,
        text=True,
    )
    modes = {}
    for record in result.stdout.split("\0"):
        if not record:
            continue
        metadata, separator, path = record.partition("\t")
        if not separator:
            raise AssertionError("git ls-files returned a malformed shell-script record")
        modes[path] = metadata.split()[0]
    return modes


class ShellScriptModeContractTests(unittest.TestCase):
    """Keep executable entrypoints runnable after a Linux or CI checkout."""

    def test_only_source_libraries_are_non_executable(self):
        modes = tracked_shell_modes()
        self.assertTrue(modes, "the tracked shell-script inventory must not be empty")
        self.assertTrue(
            SOURCE_ONLY_SHELL_FILES.issubset(modes),
            "every source-only allowlist entry must remain tracked",
        )

        mismatches = {
            path: {"actual": mode, "expected": expected}
            for path, mode in sorted(modes.items())
            for expected in (
                "100644" if path in SOURCE_ONLY_SHELL_FILES else "100755",
            )
            if mode != expected
        }
        self.assertEqual(
            mismatches,
            {},
            "shell entrypoints need 100755 in Git; source-only libraries need 100644",
        )


if __name__ == "__main__":
    unittest.main()
