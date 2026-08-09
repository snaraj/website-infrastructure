"""Keep private host-service identities local while still proving continuity."""

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = REPO_ROOT / "bootstrap" / "pi" / "preflight.sh"
DISCOVERY = REPO_ROOT / "scripts" / "discover-pi.sh"
EXAMPLE = REPO_ROOT / "bootstrap" / "pi" / "protected-services.env.example"
GITIGNORE = REPO_ROOT / ".gitignore"


class ProtectedServicesContractTests(unittest.TestCase):
    """Protect service names from Git and from shareable discovery output."""

    @classmethod
    def setUpClass(cls):
        """Load the cross-file privacy contract once for static assertions."""

        cls.preflight = PREFLIGHT.read_text(encoding="utf-8")
        cls.discovery = DISCOVERY.read_text(encoding="utf-8")
        cls.example = EXAMPLE.read_text(encoding="utf-8")
        cls.gitignore = GITIGNORE.read_text(encoding="utf-8")

    def test_local_inventory_is_ignored_and_example_is_unapproved(self):
        """Copying the template must not create a committable or approved file."""

        self.assertIn("bootstrap/pi/protected-services.env.local", self.gitignore)
        self.assertIn("PROTECTED_SERVICES_REVIEWED=no", self.example)
        self.assertNotIn("PROTECTED_SERVICES_REVIEWED=yes", self.example)

    def test_preflight_requires_a_private_exact_contract(self):
        """Install/init may proceed only after a mode-0600 local review."""

        for fragment in (
            'PROTECTED_SERVICES_PATH:-${repo_root}/bootstrap/pi/protected-services.env.local',
            'check_mode_0600 "${protected_services_path}"',
            "PROTECTED_SERVICES_REVIEWED=yes exactly once",
            "protected_service_seen",
            'systemctl is-active --quiet -- "${protected_service}"',
            "protected-service contract is required before an install or init phase",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.preflight)

    def test_diagnostics_use_indexes_instead_of_unit_names(self):
        """Shared output may report status but must not interpolate identities."""

        self.assertIn('protected service ${protected_service_index} is active', self.preflight)
        self.assertIn("protected_service_${protected_service_index}_", self.discovery)
        self.assertNotIn('printf "%s" "${protected_service}"', self.preflight)
        self.assertNotIn('printf "%s" "${protected_service_line#*=}"', self.discovery)

    def test_discovery_hashes_complete_service_inventories(self):
        """Drift remains visible without committing or printing the inventory."""

        self.assertIn("running service inventory fingerprint", self.discovery)
        self.assertIn("service unit-file inventory fingerprint", self.discovery)
        self.assertIn("fingerprint_stdout", self.discovery)
        self.assertIn("protected_service_contract=DUPLICATE_UNIT", self.discovery)

    def test_committed_contract_contains_no_private_service_examples(self):
        """The public interface must stay generic even in comments and tests."""

        combined = "\n".join((self.preflight, self.discovery, self.example)).lower()
        for term in ("bit" + "coin", "pro" + "ton", "t" + "or"):
            with self.subTest(term=term):
                self.assertIsNone(re.search(r"\b{}\b".format(re.escape(term)), combined))


if __name__ == "__main__":
    unittest.main()
