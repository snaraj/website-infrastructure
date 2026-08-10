#!/usr/bin/env python3
import base64
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_encryption_config.py"
SPEC = importlib.util.spec_from_file_location("validate_encryption_config", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

VALID = (ROOT / "bootstrap" / "pi" / "encryption-config.yaml.example").read_text(encoding="utf-8")
VALID = VALID.replace("REPLACE_KEY_NAME", "key-2026-08")
VALID = VALID.replace("REPLACE_BASE64_32_BYTE_KEY", base64.b64encode(b"a" * 32).decode("ascii"))


class EncryptionConfigTests(unittest.TestCase):
    def assert_rejected(self, config, fragment):
        errors = MODULE.validate(config)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_accepts_exact_reviewed_configuration(self):
        self.assertEqual(MODULE.validate(VALID), [])

    def test_rejects_identity_first(self):
        identity_first = VALID.replace(
            "      - secretbox:\n          keys:\n            - name: key-2026-08\n"
            "              secret: " + base64.b64encode(b"a" * 32).decode("ascii") + "\n"
            "      - identity: {}",
            "      - identity: {}\n"
            "      - secretbox:\n          keys:\n            - name: key-2026-08\n"
            "              secret: " + base64.b64encode(b"a" * 32).decode("ascii"),
        )
        self.assert_rejected(identity_first, "secretbox first")

    def test_rejects_wrong_key_length_and_extra_provider(self):
        short = VALID.replace(
            base64.b64encode(b"a" * 32).decode("ascii"),
            base64.b64encode(b"a" * 31).decode("ascii"),
        )
        self.assert_rejected(short, "exactly 32 bytes")
        extra = VALID.replace("      - identity: {}", "      - aesgcm: {}\n      - identity: {}")
        self.assert_rejected(extra, "exactly secretbox first")

    def test_rejects_unknown_fields_and_non_secret_resources(self):
        self.assert_rejected(VALID.replace("kind: EncryptionConfiguration", "kind: EncryptionConfiguration\nfoo: bar"),
                             "must contain exactly")
        self.assert_rejected(VALID.replace("      - secrets", "      - configmaps"), "exactly [secrets]")


if __name__ == "__main__":
    unittest.main()
