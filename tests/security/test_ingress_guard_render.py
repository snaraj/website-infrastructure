"""End-to-end battery for the ingress-guard ``render`` subcommand.

``render`` writes the SSH-only admin-ingress nftables policy (PLAT-DEC-001)
to disk. It merged in the host-ingress guard change with zero test
executions: neither its exclusive-create discipline nor its argument
rejections had ever run under test, so a regression could have started
following symlinks or silently overwriting an existing policy file. Every
case here drives the real CLI. The rendered artifact is also checked for
the decision's substance — the control-plane ports that must be terminally
denied from the admin VPN — so the renderer cannot quietly drop the denial
while still exiting zero.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_ingress_guard.py"
PASS_LINE = "ingress-guard: PASS rendered-admin-ingress-policy"
DENIED_CONTROL_PLANE_PORTS = ("2379", "2380", "6443", "10250")


def run_guard(*argv):
    return subprocess.run(
        [sys.executable, "-B", str(VALIDATOR), *argv],
        capture_output=True,
        text=True,
    )


class IngressGuardRenderTests(unittest.TestCase):
    """Rendering must be exclusive, symlink-refusing, and deny-complete."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()
        self.output = self.root / "admin-ingress.nft"

    def assert_usage_error(self, completed):
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("usage:", completed.stderr)
        self.assertFalse(self.output.exists())

    def test_render_writes_the_ssh_only_policy_exclusively(self):
        completed = run_guard(
            "render", "--output", str(self.output), "--interface", "wg0"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(PASS_LINE, completed.stdout)
        self.assertTrue(self.output.is_file())
        # The artifact is written 0600: the rendered ruleset names the
        # owner's admin interface and must stay owner-private.
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        text = self.output.read_text(encoding="utf-8")
        for port in DENIED_CONTROL_PLANE_PORTS:
            self.assertIn(
                f'iifname "wg0" tcp dport {port} counter drop', text,
                f"rendered policy lost the terminal denial of port {port}",
            )
        self.assertIn(
            'iifname "wg0" tcp dport 22 counter accept', text,
            "rendered policy must keep SSH reachable from the admin VPN",
        )
        self.assertLess(
            text.index("dport 22 counter accept"),
            text.index("dport 2379 counter drop"),
            "SSH accept must precede the control-plane denials",
        )
        # Rendering must be deterministic: a second render of the same
        # interfaces produces byte-identical policy in a fresh location.
        second = self.root / "second.nft"
        again = run_guard("render", "--output", str(second), "--interface", "wg0")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(second.read_bytes(), self.output.read_bytes())

    def test_render_refuses_to_overwrite_an_existing_target(self):
        self.output.write_text("operator content, not ours\n")
        completed = run_guard(
            "render", "--output", str(self.output), "--interface", "wg0"
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("RENDER_TARGET_UNSAFE", completed.stderr)
        self.assertEqual(
            self.output.read_text(), "operator content, not ours\n",
            "render must never clobber an existing file",
        )

    def test_render_refuses_a_symlink_target(self):
        # Even a dangling symlink must not be followed into a write: the
        # exclusive no-follow create fails instead of creating the link's
        # destination somewhere the operator did not choose.
        elsewhere = self.root / "elsewhere.nft"
        self.output.symlink_to(elsewhere)
        completed = run_guard(
            "render", "--output", str(self.output), "--interface", "wg0"
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("RENDER_TARGET_UNSAFE", completed.stderr)
        self.assertFalse(elsewhere.exists())

    def test_render_refuses_an_unwritable_directory_target(self):
        completed = run_guard(
            "render",
            "--output",
            str(self.root / "missing-dir" / "out.nft"),
            "--interface",
            "wg0",
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("RENDER_TARGET_UNSAFE", completed.stderr)

    def test_render_without_output_is_a_usage_error(self):
        self.assert_usage_error(run_guard("render", "--interface", "wg0"))

    def test_render_with_expect_absent_is_a_usage_error(self):
        self.assert_usage_error(
            run_guard(
                "render",
                "--output",
                str(self.output),
                "--interface",
                "wg0",
                "--expect-absent",
            )
        )

    def test_render_with_contract_and_interfaces_is_a_usage_error(self):
        self.assert_usage_error(
            run_guard(
                "render",
                "--output",
                str(self.output),
                "--contract",
                str(self.root / "contract.env"),
                "--interface",
                "wg0",
            )
        )

    def test_render_without_any_interface_source_is_rejected(self):
        completed = run_guard("render", "--output", str(self.output))
        self.assertEqual(completed.returncode, 1)
        self.assertIn("INTERFACE_ARGUMENT_INVALID", completed.stderr)
        self.assertFalse(self.output.exists())

    def test_render_rejects_invalid_and_duplicate_interfaces(self):
        for label, interfaces in (
            ("shell-metacharacters", ("wg0;drop",)),
            ("uppercase", ("WG0",)),
            ("duplicate", ("wg0", "wg0")),
            ("empty", ("",)),
        ):
            arguments = []
            for interface in interfaces:
                arguments.extend(("--interface", interface))
            with self.subTest(case=label):
                completed = run_guard(
                    "render", "--output", str(self.output), *arguments
                )
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertIn("INTERFACE_ARGUMENT_INVALID", completed.stderr)
                self.assertFalse(self.output.exists())

    def test_render_rejects_an_unreviewed_contract_file(self):
        contract = self.root / "admin-ingress.env"
        contract.write_text("ADMIN_INGRESS_REVIEWED=no\n")
        contract.chmod(0o600)
        completed = run_guard(
            "render", "--output", str(self.output), "--contract", str(contract)
        )
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
