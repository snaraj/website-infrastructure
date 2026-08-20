#!/usr/bin/env python3
import base64
import unittest
from pathlib import Path

from .support import load_script


ROOT = Path(__file__).resolve().parents[2]
MODULE = load_script("validate_encryption_config.py")

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

    def test_unreviewed_field_names_are_counted_and_never_echoed(self):
        """The inspected file is the one holding the API server's secretbox key.

        Its field names are bytes read out of that file, so a diagnostic that
        echoed them would copy content from the most sensitive file on the host
        into bootstrap output and CI logs. Unreviewed fields are reported as a
        count; only this validator's own literal vocabulary is ever named back.
        Both mappings below are exercised because the second one — the key entry
        itself — is the mapping that sits alongside the secret scalar.
        """

        marker = "zz" + "unreviewedfieldname" + "zz"
        for label, config in (
            (
                "EncryptionConfiguration",
                VALID.replace(
                    "kind: EncryptionConfiguration",
                    "kind: EncryptionConfiguration\n{}: bar".format(marker),
                ),
            ),
            (
                "secretbox.keys[0]",
                VALID.replace("              secret: ", "              {}: ".format(marker)),
            ),
        ):
            with self.subTest(mapping=label):
                errors = MODULE.validate(config)
                self.assertNotEqual(errors, [])
                self.assertFalse(
                    any(marker in error for error in errors),
                    "unreviewed field name echoed back: {}".format(errors),
                )
                self.assertTrue(
                    any("{} must contain exactly".format(label) in error for error in errors),
                    errors,
                )
                self.assertTrue(
                    any("unreviewed field count 1" in error for error in errors), errors
                )

    def test_missing_reviewed_fields_are_still_named(self):
        """Naming an ABSENT field is safe, and keeps the diagnostic actionable.

        An expected-but-missing name is one of this validator's own literals and
        never came from the configuration, so it stays in the message. Without
        this the non-echo rule above would be satisfied just as well by an empty
        diagnostic, which would tell an operator nothing.
        """

        errors = MODULE.validate(VALID.replace("              secret: ", "              zzz: "))
        self.assertTrue(any("missing secret" in error for error in errors), errors)

    def test_shared_parser_diagnostics_never_echo_file_derived_content(self):
        """All syntax failures retain an exact line without returning input bytes."""

        marker = "zz" + "parserdiagnosticmarker" + "zz"
        duplicate_key = VALID.replace(
            "kind: EncryptionConfiguration",
            "kind: EncryptionConfiguration\n{}: first\n{}: second".format(marker, marker),
        )
        missing_value = VALID.rstrip() + "\n{}:\n".format(marker)
        marker_document = VALID.replace(
            "kind: EncryptionConfiguration", "kind: {}".format(marker)
        ).rstrip()
        duplicate_document = (
            marker_document
            + "\n---\napiVersion: apiserver.config.k8s.io/v1\nkind: {}\nresources: []\n".format(marker)
        )

        cases = (
            (
                "duplicate-key",
                duplicate_key,
                "duplicate mapping key",
                max(
                    number
                    for number, line in enumerate(duplicate_key.splitlines(), 1)
                    if line == "{}: second".format(marker)
                ),
            ),
            (
                "missing-value",
                missing_value,
                "mapping key has no value",
                max(
                    number
                    for number, line in enumerate(missing_value.splitlines(), 1)
                    if line == "{}:".format(marker)
                ),
            ),
            (
                "duplicate-kind",
                duplicate_document,
                "duplicate document kind",
                max(
                    number
                    for number, line in enumerate(duplicate_document.splitlines(), 1)
                    if line == "apiVersion: apiserver.config.k8s.io/v1"
                ),
            ),
        )
        for label, config, structural_label, expected_line in cases:
            with self.subTest(shape=label):
                errors = MODULE.validate(config)
                self.assertNotEqual(errors, [])
                self.assertFalse(any(marker in error for error in errors), errors)
                self.assertIn(
                    "{} at line {}".format(structural_label, expected_line), errors
                )


if __name__ == "__main__":
    unittest.main()
