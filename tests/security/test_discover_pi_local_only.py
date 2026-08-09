"""Keep the first Pi discovery pass local until outbound routing is trusted."""

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISCOVERY = ROOT / "scripts" / "discover-pi.sh"


class DiscoverPiLocalOnlyContractTests(unittest.TestCase):
    """Prove the explicit local-only argument gates every intentional probe."""

    @classmethod
    def setUpClass(cls):
        cls.script = DISCOVERY.read_text(encoding="utf-8")

    def test_argument_contract_defaults_local_and_requires_explicit_egress(self):
        self.assertIn("discovery_mode=local-only", self.script)
        self.assertNotIn("discovery_mode=default", self.script)
        self.assertIn('Usage: %s [--local-only|--with-egress]', self.script)
        self.assertIn('--local-only) discovery_mode=local-only', self.script)
        self.assertIn('--with-egress) discovery_mode=with-egress', self.script)
        self.assertIn("discovery_mode=local-only", self.script)
        self.assertIn('case "$#" in', self.script)
        self.assertRegex(self.script, r"(?ms)^\s*\*\)\s+usage\s+;;")

    def test_unknown_argument_exits_two_when_bash_is_available(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is unavailable for the unknown-argument check")
        completed = subprocess.run(
            [bash, str(DISCOVERY), "--not-a-discovery-mode"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Usage:", completed.stderr)

    def test_local_only_branch_skips_the_single_egress_probe_function(self):
        self.assertEqual(self.script.count("run_external_egress_probes() {"), 1)
        self.assertEqual(self.script.count("\n  run_external_egress_probes\n"), 1)
        self.assertIn(
            'if [[ "${discovery_mode}" == with-egress ]]; then\n'
            "  run_external_egress_probes\n"
            "else\n"
            "  printf '\\n### External egress probes\\n'\n"
            "  printf 'external_egress_probes=SKIPPED_LOCAL_ONLY\\n'\n"
            "fi",
            self.script,
        )

        function_body = self.script.split("run_external_egress_probes() {", 1)[1].split(
            "\n}", 1
        )[0]
        for probe in (
            "getent ahosts",
            "curl --fail",
            "nc -vz",
        ):
            with self.subTest(probe=probe):
                self.assertIn(probe, function_body)

    def test_listener_inventory_never_requests_process_identities(self):
        """A shareable report must not include names/PIDs from ss -p."""

        self.assertIn("ss -lntu", self.script)
        self.assertNotRegex(self.script, r"\bss\s+-[^\n ]*p")

    def test_protected_host_validation_remains_local_and_count_only(self):
        """Expanded local validation must not move into the egress-only function."""

        function_body = self.script.split("run_external_egress_probes() {", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertNotIn("validate_protected_host_contract.py", function_body)
        self.assertIn("validate_protected_host_contract.py", self.script)
        self.assertIn("active_unit_count=%d", self.script)
        self.assertIn("inactive_legacy_unit_count=%d", self.script)
        self.assertIn("archive_root_count=%d", self.script)
        self.assertNotIn("protected_service_line#*=", self.script)

    def test_discovery_invokes_no_legacy_product_binary(self):
        # Split private product identities so the public test remains generic in
        # the same way as the protected-services contract test.
        for product in (
            "bit" + "coin",
            "bit" + "coind",
            "spar" + "row",
            "pro" + "ton",
            "t" + "or",
        ):
            with self.subTest(product=product):
                self.assertIsNone(
                    re.search(r"\b{}\b".format(re.escape(product)), self.script, re.I)
                )

    def test_script_has_valid_bash_syntax_when_bash_is_available(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is unavailable for syntax validation")
        subprocess.run([bash, "-n", str(DISCOVERY)], check=True)


if __name__ == "__main__":
    unittest.main()
