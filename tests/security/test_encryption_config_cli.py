"""End-to-end fail-closed battery for the encryption-config CLI.

The validator guards the Kubernetes API encryption-at-rest configuration:
secretbox first, identity strictly as a read fallback. Its ``main()`` had
never been executed by the suite, so the exit-code contract the bootstrap
scripts rely on (0 pass / 1 fail with FAIL lines on stderr / 2 usage) was
unproven. Each hostile case asserts the CLI refuses a weakened
configuration — provider reordering, oversized or non-canonical keys,
foreign providers, sentinel leftovers — with the exact error line.
"""

import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_encryption_config.py"
PASS_LINE = (
    "PASS encryption config is exact: secretbox first, identity read fallback second"
)
VALID_KEY = base64.b64encode(b"a" * 32).decode()
# Assembled at runtime from the sentinel-bearing template: a literal
# EncryptionConfiguration document in this file would itself violate the
# repository's plaintext-encryption-config secret law.
VALID_CONFIG = (
    (REPO_ROOT / "bootstrap" / "pi" / "encryption-config.yaml.example")
    .read_text(encoding="utf-8")
    .replace("REPLACE_KEY_NAME", "key-2026-08")
    .replace("REPLACE_BASE64_32_BYTE_KEY", VALID_KEY)
)


def run_validator(*argv):
    return subprocess.run(
        [sys.executable, "-B", str(VALIDATOR), *argv],
        capture_output=True,
        text=True,
    )


class EncryptionConfigCliTests(unittest.TestCase):
    """The CLI must accept exactly one shape and reject every weakening."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()

    def write_config(self, text, name="config.yaml"):
        path = self.root / name
        path.write_text(text)
        return path

    def assert_rejected(self, text, fragment):
        completed = run_validator(str(self.write_config(text)))
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("FAIL " + fragment, completed.stderr)
        self.assertNotIn(PASS_LINE, completed.stdout)

    def test_canonical_config_passes_end_to_end(self):
        completed = run_validator(str(self.write_config(VALID_CONFIG)))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(PASS_LINE, completed.stdout)

    def test_identity_first_provider_order_is_rejected(self):
        # identity-first would mean new Secrets are written in PLAINTEXT
        # while the validator still sees both providers present.
        reordered = VALID_CONFIG.replace(
            "      - secretbox:\n"
            "          keys:\n"
            "            - name: key-2026-08\n"
            f"              secret: {VALID_KEY}\n"
            "      - identity: {}\n",
            "      - identity: {}\n"
            "      - secretbox:\n"
            "          keys:\n"
            "            - name: key-2026-08\n"
            f"              secret: {VALID_KEY}\n",
        )
        self.assertNotEqual(reordered, VALID_CONFIG)
        self.assert_rejected(
            reordered,
            "providers must contain exactly secretbox first and identity second",
        )

    def test_short_or_noncanonical_key_material_is_rejected(self):
        for label, key in (
            ("31-byte", base64.b64encode(b"a" * 31).decode()),
            ("33-byte", base64.b64encode(b"a" * 33).decode()),
            ("non-canonical-padding", VALID_KEY[:-2] + "a="),
            ("five-byte-key", base64.b64encode(b"hello").decode()),
        ):
            with self.subTest(key=label):
                self.assert_rejected(
                    VALID_CONFIG.replace(VALID_KEY, key),
                    "secretbox key must be canonical base64 encoding exactly 32 bytes",
                )

    def test_replacement_sentinel_is_rejected(self):
        self.assert_rejected(
            VALID_CONFIG.replace(VALID_KEY, "REPLACE_BASE64_32_BYTE_KEY"),
            "replacement sentinel remains",
        )

    def test_wrong_resource_scope_is_rejected(self):
        self.assert_rejected(
            VALID_CONFIG.replace("- secrets", "- configmaps"),
            "resources[0].resources must be exactly [secrets]",
        )

    def test_extra_root_field_is_rejected(self):
        self.assert_rejected(
            VALID_CONFIG + "unexpected: field\n",
            "EncryptionConfiguration must contain exactly",
        )

    def test_duplicate_document_is_rejected(self):
        self.assert_rejected(
            VALID_CONFIG + "---\n" + VALID_CONFIG,
            "duplicate EncryptionConfiguration document",
        )

    def test_tab_indentation_is_rejected(self):
        self.assert_rejected(
            VALID_CONFIG.replace("  - resources:", "\t- resources:", 1),
            "tabs are unsupported",
        )

    def test_unreadable_path_fails_closed(self):
        completed = run_validator(str(self.root / "absent.yaml"))
        self.assertEqual(completed.returncode, 1)
        self.assertIn("FAIL unable to read encryption config:", completed.stderr)

    def test_missing_argument_is_a_usage_error(self):
        completed = run_validator()
        self.assertEqual(completed.returncode, 2)
        self.assertIn("usage:", completed.stderr)


if __name__ == "__main__":
    unittest.main()
