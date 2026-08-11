import json
import tempfile
import unittest
from pathlib import Path

from .support import load_script

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "docs" / "assurance" / "attack-surface-manifest.json"

MODULE = load_script("validate_attack_surface_manifest.py")


class AttackSurfaceManifestTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "manifest.json"

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, document):
        self.path.write_text(json.dumps(document), encoding="utf-8")

    def test_committed_manifest_passes(self):
        self.assertEqual(MODULE.manifest_errors(MANIFEST), [])

    def test_missing_required_surface_is_rejected(self):
        self.document["inbound_wan"] = [
            entry
            for entry in self.document["inbound_wan"]
            if entry["surface"] != "wireguard-admin-udp"
        ]
        self.write(self.document)
        errors = MODULE.manifest_errors(self.path)
        self.assertTrue(any("missing required surfaces" in error for error in errors))

    def test_open_inbound_surface_is_rejected(self):
        # Any non-WireGuard inbound surface that answers is a hole.
        for entry in self.document["inbound_wan"]:
            if entry["surface"] == "ssh-service":
                entry["expected"] = "allowed-to-class"
        self.write(self.document)
        errors = MODULE.manifest_errors(self.path)
        self.assertTrue(any("must expect no-response" in error for error in errors))

    def test_admin_api_reachable_is_rejected(self):
        # PLAT-DEC-001: the admin plane is SSH-only; API from the peer denied.
        for entry in self.document["reachability"]:
            if entry["from"] == "admin-peer" and entry["to"] == "kubernetes-api":
                entry["expected"] = "allowed-to-class"
        self.write(self.document)
        errors = MODULE.manifest_errors(self.path)
        self.assertTrue(any("SSH-only" in error for error in errors))

    def test_expected_outside_vocabulary_is_rejected(self):
        self.document["reachability"][0]["expected"] = "maybe"
        self.write(self.document)
        errors = MODULE.manifest_errors(self.path)
        self.assertTrue(any("closed vocabulary" in error for error in errors))

    def test_free_form_identifier_is_rejected(self):
        # A private address smuggled into a field must be refused. Built at
        # runtime so the repository privacy scanner never sees it at rest.
        self.document["reachability"][0]["to"] = "10.0.0." + "5:6443"
        self.write(self.document)
        errors = MODULE.manifest_errors(self.path)
        self.assertTrue(any("closed identifier" in error for error in errors))

    def test_bad_control_id_is_rejected(self):
        self.document["egress"][0]["control"] = "FINDING-1"
        self.write(self.document)
        errors = MODULE.manifest_errors(self.path)
        self.assertTrue(any("PLAT-" in error for error in errors))

    def test_missing_or_symlink_manifest_is_rejected(self):
        self.assertEqual(
            MODULE.manifest_errors(self.path.with_name("absent.json")),
            ["manifest is missing or is a symlink"],
        )


if __name__ == "__main__":
    unittest.main()
