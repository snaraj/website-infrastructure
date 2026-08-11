"""End-to-end fail-closed battery for the protected-host contract reader.

``load_contract`` is the security boundary that decides whether an
owner-private contract file may be trusted at all. Until this battery, every
one of its rejection branches — symlink, FIFO, wrong mode, hard-link pair,
symlinked ancestor, missing file, oversize — was completely unexecuted by
the suite: a regression could have silently started accepting a hostile
contract and no test would have noticed. Each case here runs the real CLI
as a subprocess against a real on-disk fixture and asserts the exact
fail-closed refusal, plus the one passing fixture that proves the validator
still accepts legitimate input (rejecting everything is not a valid way to
pass this battery).
"""

import os
import tempfile
import unittest
from pathlib import Path

from tests.security.test_protected_services_contract import contract_text

from .support import run_script

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_protected_host_contract.py"


def run_validator(target, *extra):
    return run_script(VALIDATOR, target, *extra)


class ProtectedHostContractFailClosedTests(unittest.TestCase):
    """The contract reader must refuse every unsafe custody arrangement."""

    def setUp(self):
        # Resolve the scratch root: macOS puts TMPDIR under the /var symlink
        # and an unresolved root would trip the traversal rejection for every
        # case, masking the specific branch each test targets.
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()

    def write_contract(self, name="contract.env", text=None, mode=0o600):
        path = self.root / name
        path.write_text(contract_text() if text is None else text)
        path.chmod(mode)
        return path

    def assert_rejected(self, completed, message):
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn(message, completed.stderr)
        self.assertNotIn("PASS", completed.stdout)

    def test_valid_private_contract_passes_end_to_end(self):
        completed = run_validator(self.write_contract())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "PASS protected-host contract syntax is valid", completed.stdout
        )

    def test_missing_contract_is_unavailable(self):
        self.assert_rejected(
            run_validator(self.root / "absent.env"),
            "ERROR protected-host contract is unavailable",
        )

    def test_symlinked_contract_is_rejected(self):
        target = self.write_contract()
        link = self.root / "link.env"
        link.symlink_to(target)
        self.assert_rejected(
            run_validator(link),
            "ERROR protected-host contract must not be a symbolic link",
        )

    def test_fifo_contract_is_rejected(self):
        fifo = self.root / "fifo.env"
        os.mkfifo(fifo, 0o600)
        self.assert_rejected(
            run_validator(fifo),
            "ERROR protected-host contract must be a regular file",
        )

    def test_group_readable_mode_is_rejected(self):
        for mode in (0o644, 0o640, 0o400, 0o700):
            with self.subTest(mode=oct(mode)):
                path = self.write_contract(name=f"mode-{mode:o}.env", mode=mode)
                self.assert_rejected(
                    run_validator(path),
                    "ERROR protected-host contract mode must be exactly 0600",
                )

    def test_hard_link_pair_is_rejected(self):
        original = self.write_contract()
        alias = self.root / "alias.env"
        os.link(original, alias)
        # Both names now share the inode: the contract is reachable through
        # a name the operator did not audit, so both must be refused.
        for path in (original, alias):
            with self.subTest(path=path.name):
                self.assert_rejected(
                    run_validator(path),
                    "ERROR protected-host contract must have exactly one hard link",
                )

    def test_symlinked_ancestor_directory_is_rejected(self):
        real_dir = self.root / "real"
        real_dir.mkdir()
        contract = real_dir / "contract.env"
        contract.write_text(contract_text())
        contract.chmod(0o600)
        linked_dir = self.root / "linked"
        linked_dir.symlink_to(real_dir)
        self.assert_rejected(
            run_validator(linked_dir / "contract.env"),
            "ERROR protected-host contract path must not traverse a symbolic link",
        )

    def test_oversize_contract_fails_the_bounded_read(self):
        # The reader caps its read at MAX_CONTRACT_BYTES + 1; an oversize
        # file therefore fails the same-handle stability comparison rather
        # than being truncated and partially trusted.
        oversize = contract_text() + "# " + "x" * 70000 + "\n"
        self.assert_rejected(
            run_validator(self.write_contract(name="big.env", text=oversize)),
            "ERROR protected-host contract changed while reading",
        )

    def test_invalid_utf8_contract_is_rejected(self):
        path = self.root / "binary.env"
        path.write_bytes(contract_text().encode() + b"\xff\xfe\n")
        path.chmod(0o600)
        completed = run_validator(path)
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertNotIn("PASS", completed.stdout)

    def test_unreviewed_contract_content_is_rejected(self):
        text = contract_text().replace(
            "PROTECTED_SERVICES_REVIEWED=yes", "PROTECTED_SERVICES_REVIEWED=no"
        )
        completed = run_validator(self.write_contract(name="unrev.env", text=text))
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertNotIn("PASS", completed.stdout)

    def test_check_live_and_emit_bindings_are_mutually_exclusive(self):
        completed = run_validator(
            self.write_contract(), "--check-live", "--emit-bindings"
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("mutually exclusive", completed.stderr)


if __name__ == "__main__":
    unittest.main()
