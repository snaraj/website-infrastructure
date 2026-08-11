"""End-to-end fail-closed battery for the attack-surface manifest CLI.

The manifest is the offensive-validation contract (Phase H): it declares
what an internet-side attacker must observe, in a closed vocabulary, with
full coverage of the required surfaces. The validator ran in CI but its
``main()`` had no test executions, and none of its refusals were pinned.
The passing fixture is the committed manifest itself; every hostile case
mutates a copy and asserts the CLI refuses it — most importantly the
PLAT-DEC-001 regression where admin-peer-to-kubernetes-api flips away
from ``denied``.
"""

import json
import tempfile
import unittest
from pathlib import Path

from .support import run_script

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_attack_surface_manifest.py"
MANIFEST = REPO_ROOT / "docs" / "assurance" / "attack-surface-manifest.json"
PASS_LINE = "attack-surface-manifest: PASS well-formed, closed-vocabulary, full-coverage"


def run_validator(path):
    return run_script(VALIDATOR, path)


class AttackSurfaceManifestCliTests(unittest.TestCase):
    """The committed manifest passes; every loosened variant fails."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()
        self.document = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def write_document(self, document, name="manifest.json"):
        path = self.root / name
        path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
        return path

    def assert_rejected(self, document_or_path, fragment):
        path = (
            document_or_path
            if isinstance(document_or_path, Path)
            else self.write_document(document_or_path)
        )
        completed = run_validator(path)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn(fragment, completed.stderr)
        self.assertNotIn(PASS_LINE, completed.stdout)

    def test_committed_manifest_passes_end_to_end(self):
        completed = run_validator(MANIFEST)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(PASS_LINE, completed.stdout)

    def test_admin_api_reachability_must_stay_denied(self):
        # The heart of PLAT-DEC-001: if anyone edits the manifest to expect
        # kubectl-from-the-admin-VPN again, the validator must refuse.
        for entry in self.document["reachability"]:
            if entry["from"] == "admin-peer" and entry["to"] == "kubernetes-api":
                entry["expected"] = "allowed-to-class"
        self.assert_rejected(
            self.document,
            "admin peer to kubernetes-api must be denied (PLAT-DEC-001 SSH-only)",
        )

    def test_widened_vocabulary_is_rejected(self):
        self.document["expected_vocabulary"].append("maybe")
        self.assert_rejected(
            self.document, "expected_vocabulary drifted from the closed result set"
        )

    def test_dropped_required_surface_is_rejected(self):
        self.document["inbound_wan"] = [
            entry
            for entry in self.document["inbound_wan"]
            if entry["surface"] != "kubernetes-api"
        ]
        self.assert_rejected(
            self.document, "inbound_wan is missing required surfaces: ['kubernetes-api']"
        )

    def test_wireguard_port_must_expect_handshake_only(self):
        for entry in self.document["inbound_wan"]:
            if entry["surface"] == "wireguard-admin-udp":
                entry["expected"] = "no-response"
        self.assert_rejected(
            self.document,
            "the WireGuard admin port must expect wireguard-handshake-only",
        )

    def test_freeform_control_id_is_rejected(self):
        self.document["egress"][0]["control"] = "FINDING-1"
        self.assert_rejected(self.document, "control is not a PLAT-")

    def test_out_of_vocabulary_expectation_is_rejected(self):
        self.document["reachability"][0]["expected"] = "maybe"
        self.assert_rejected(
            self.document, "expected is outside the closed vocabulary"
        )

    def test_wrong_schema_tag_is_rejected(self):
        self.document["schema"] = "attack-surface/v2"
        self.assert_rejected(self.document, "schema tag is not attack-surface/v1")

    def test_empty_section_is_rejected(self):
        self.document["egress"] = []
        self.assert_rejected(self.document, "section egress is missing or empty")

    def test_truncated_json_is_rejected(self):
        path = self.root / "broken.json"
        path.write_text(MANIFEST.read_text(encoding="utf-8")[:-40], encoding="utf-8")
        self.assert_rejected(path, "manifest is not canonical JSON")

    def test_symlink_and_missing_manifest_are_rejected(self):
        link = self.root / "link.json"
        link.symlink_to(MANIFEST)
        self.assert_rejected(link, "manifest is missing or is a symlink")
        self.assert_rejected(
            self.root / "absent.json", "manifest is missing or is a symlink"
        )


if __name__ == "__main__":
    unittest.main()
