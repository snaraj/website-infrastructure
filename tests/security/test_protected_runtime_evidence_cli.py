"""Portable end-to-end fail-closed battery for the runtime-evidence CLI.

The evidence reader attests that a fresh, presence-bound protected-host
review happened on the current boot. Most of its custody rejections are
plain POSIX (symlink, FIFO, mode, ownership pairing, directory custody)
yet had never been executed through the CLI; the previous tests covered
them only at the parse level or behind Linux-only skips. Every case here
runs on macOS and Linux alike. The genuine boot-probe pass path stays
Linux-gated because /proc does not exist elsewhere — asserted explicitly
so the platform boundary is a documented decision, not an accident.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.security.test_protected_runtime_contract_integration import contract_text

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_protected_runtime_evidence.py"
EVIDENCE_NAME = "protected-legacy-runtime-evidence.local"


def run_validator(contract, *extra):
    return subprocess.run(
        [sys.executable, "-B", str(VALIDATOR), str(contract), *extra],
        capture_output=True,
        text=True,
    )


class ProtectedRuntimeEvidenceCliTests(unittest.TestCase):
    """Custody violations must fail closed on every POSIX platform."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()
        self.contract = self.root / "protected-services.env"
        self.contract.write_text(contract_text())
        self.contract.chmod(0o600)
        self.evidence = self.root / EVIDENCE_NAME

    def assert_error(self, completed, fragment):
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("ERROR " + fragment, completed.stderr)
        self.assertNotIn("PASS", completed.stdout)

    def write_evidence(self, payload=b"RUNTIME_EVIDENCE_SCHEMA=stub\n", mode=0o600):
        self.evidence.write_bytes(payload)
        self.evidence.chmod(mode)

    def test_missing_contract_is_rejected(self):
        completed = run_validator(self.root / "absent.env", "--emit-sha256")
        self.assert_error(completed, "protected-host contract presence is invalid")

    def test_world_readable_contract_is_rejected(self):
        self.contract.chmod(0o644)
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(completed, "protected-host contract presence is invalid")

    def test_symlinked_contract_is_rejected(self):
        link = self.root / "link.env"
        link.symlink_to(self.contract)
        completed = run_validator(link, "--emit-sha256")
        self.assert_error(completed, "protected-host contract presence is invalid")

    def test_missing_evidence_is_unavailable(self):
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(completed, "runtime evidence is unavailable")

    def test_symlinked_evidence_is_rejected(self):
        target = self.root / "target.local"
        target.write_bytes(b"payload\n")
        target.chmod(0o600)
        self.evidence.symlink_to(target)
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(completed, "runtime evidence must not be a symbolic link")

    def test_fifo_evidence_is_rejected(self):
        os.mkfifo(self.evidence, 0o600)
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(completed, "runtime evidence must be a regular file")

    def test_group_readable_evidence_is_rejected(self):
        self.write_evidence(mode=0o640)
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(completed, "runtime evidence mode must be exactly 0600")

    def test_hard_linked_evidence_is_rejected(self):
        self.write_evidence()
        os.link(self.evidence, self.root / "alias.local")
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(
            completed, "runtime evidence must have exactly one hard link"
        )

    def test_oversize_evidence_is_rejected(self):
        # One byte over the 4096-byte ceiling: the bounded read consumes the
        # whole file, the same-handle stability check still matches, and the
        # explicit size rejection fires.
        self.write_evidence(payload=b"#" * 4096 + b"\n")
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(completed, "runtime evidence exceeds the size limit")

    def test_far_oversize_evidence_fails_the_bounded_read(self):
        # Well past the ceiling, the reader stops at its bound and refuses
        # the partial view as an instability rather than trusting it.
        self.write_evidence(payload=b"#" * 5000 + b"\n")
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(completed, "runtime evidence changed while reading")

    def test_stale_evidence_is_rejected(self):
        self.write_evidence()
        stale = 4_000  # far beyond the 600 second freshness ceiling
        os.utime(self.evidence, ns=(
            (int(os.stat(self.evidence).st_atime_ns)),
            int((os.stat(self.evidence).st_mtime - stale) * 1_000_000_000),
        ))
        completed = run_validator(self.contract, "--emit-sha256")
        self.assert_error(completed, "runtime evidence file is stale")

    def test_expected_sha256_must_be_lowercase_hex(self):
        # The malformed binding must never validate. On Linux the specific
        # digest-shape rejection is observable; elsewhere the boot probe
        # fails first — either way the CLI exits 1 and blesses nothing.
        self.write_evidence()
        completed = run_validator(
            self.contract, "--expected-sha256", "NOT-A-DIGEST"
        )
        if sys.platform.startswith("linux"):
            self.assert_error(
                completed,
                "expected runtime evidence binding is not a lowercase SHA-256",
            )
        else:
            self.assert_error(completed, "current boot identity is unavailable")

    def test_emit_and_expected_are_mutually_exclusive(self):
        completed = run_validator(
            self.contract, "--emit-sha256", "--expected-sha256", "a" * 64
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("usage", completed.stderr)

    def test_action_argument_is_required(self):
        completed = run_validator(self.contract)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("usage", completed.stderr)

    def test_boot_probe_is_the_only_nonportable_dependency(self):
        # Document the platform boundary: off Linux the CLI must fail with
        # the boot-identity error rather than pretending to attest.
        if sys.platform.startswith("linux"):
            self.skipTest("the boot probe exists on Linux")
        self.write_evidence()
        completed = run_validator(self.contract, "--emit-sha256")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("current boot identity is unavailable", completed.stderr)


if __name__ == "__main__":
    unittest.main()
