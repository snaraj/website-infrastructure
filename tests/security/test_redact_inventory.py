#!/usr/bin/env python3
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "redact_inventory.py"

# A redactor that can be stalled by the inventory it is redacting fails open in
# practice: the discovery pipeline hangs and the operator's escape hatch is to
# read the unredacted capture. This ceiling sits three orders of magnitude above
# a healthy run — microseconds of matching plus interpreter start-up — so it
# cannot flake on a loaded machine, while a pattern that has acquired a
# catastrophic-backtracking shape does not finish at all.
ADVERSARIAL_SECONDS = 15


class RedactionTests(unittest.TestCase):
    def redact(self, value, timeout=None):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=value,
            text=True,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
        return result.stdout

    def test_redacts_addresses_machine_ids_and_filesystem_uuids(self):
        output = self.redact(
            "Machine ID: 0123456789abcdef0123456789abcdef\n"
            "root=PARTUUID=" + "12345678" + "-1234-1234-1234-123456789abc "
            "192.168.1.10\n"
        )
        self.assertNotIn("0123456789abcdef", output)
        self.assertNotIn("12345678-1234", output)
        self.assertNotIn("192.168.1.10", output)
        self.assertIn("[REDACTED_MACHINE_ID]", output)
        self.assertIn("[REDACTED_UUID]", output)
        self.assertIn("[REDACTED_IPv4]", output)

    def test_redacts_age_identity_families_and_cloudflare_token_formats(self):
        """Redaction keeps pace with native PQ age and prefixed Cloudflare tokens."""

        secrets = (
            "AGE-" + "SECRET-KEY-1" + ("A" * 58),
            "AGE-" + "SECRET-KEY-PQ-1" + ("A" * 128),
            "cfk_" + ("A" * 40) + "deadbeef",
            "cfut_" + ("B" * 40) + "cafebabe",
            "cfat_" + ("C" * 40) + "0123abcd",
        )
        legacy = "L" * 40
        output = self.redact(
            "\n".join(secrets)
            + "\ncloudflare_api_token='"
            + legacy
            + "'\n"
        )
        for value in secrets + (legacy,):
            with self.subTest(prefix=value[:16]):
                self.assertNotIn(value, output)
        self.assertEqual(output.count("[REDACTED_AGE_IDENTITY]"), 2)
        self.assertEqual(output.count("[REDACTED_CLOUDFLARE_TOKEN]"), 3)
        self.assertIn("cloudflare_api_token='[REDACTED]'", output)

    def test_redacts_cloudflare_contexts_and_complete_private_key_blocks(self):
        legacy = "L" * 40
        bearer = "B" * 40
        tunnel = "eyJ" + ("T" * 96)
        private_body = "VERY-SENSITIVE-PRIVATE-MATERIAL"
        output = self.redact(
            "cloudflare_api_token: " + legacy + "\n"
            "Authorization: Bearer " + bearer + "\n"
            "tunnel_token=" + tunnel + "\n"
            "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----\n"
            + private_body + "\n"
            "-----END ENCRYPTED " + "PRIVATE KEY-----\n"
            "after=public\n"
        )
        for value in (legacy, bearer, tunnel, private_body):
            self.assertNotIn(value, output)
        self.assertIn("cloudflare_api_token: [REDACTED]", output)
        self.assertIn("Authorization: Bearer [REDACTED]", output)
        self.assertIn("tunnel_token=[REDACTED]", output)
        self.assertIn("[REDACTED_PRIVATE_KEY_BLOCK]", output)
        self.assertIn("after=public", output)

    def test_redactor_preserves_public_age_recipient_and_token_near_miss(self):
        """Public recipients and malformed token-like text remain useful evidence."""

        public_recipient = "age1pq1" + ("q" * 128)
        near_miss = "cfut_" + ("A" * 39) + "deadbeef"
        output = self.redact(public_recipient + "\n" + near_miss + "\n")
        self.assertIn(public_recipient, output)
        self.assertIn(near_miss, output)

    def test_redacts_legacy_wallet_anonymity_rpc_and_vpn_shapes(self):
        """Defense-in-depth strips common crown-jewel shapes if a probe regresses."""

        onion = "a" * 56 + ".onion"
        extended_key = "xprv" + "A" * 100
        slip132_key = "Zpub" + "B" * 100
        private_key = "K" + "A" * 51
        bech32_address = "bc1q" + "q" * 30
        base58_address = "1" + "A" * 33
        key_origin = "[deadbeef/84h/0h/0h]"
        output = self.redact(
            f"endpoint={onion}\n"
            f"descriptor={key_origin}{extended_key}\n"
            f"watch_only={slip132_key}\n"
            f"wif={private_key}\n"
            f"receive={bech32_address} change={base58_address}\n"
            "rpcuser=TEST_USER_NOT_A_CREDENTIAL\n"
            "rpcpassword=TEST_PASSWORD_NOT_A_CREDENTIAL\n"
            "rpcauth=TEST_AUTH_NOT_A_CREDENTIAL\n"
            "PrivateKey=TEST_PRIVATE_KEY_NOT_A_CREDENTIAL\n"
            "PresharedKey=TEST_PRESHARED_KEY_NOT_A_CREDENTIAL\n"
            "HashedControlPassword 16:TEST_CONTROL_VALUE_NOT_A_CREDENTIAL\n"
            'ControlPassword "TEST CONTROL VALUE WITH SPACES"\n'
        )
        for value in (
            onion,
            extended_key,
            slip132_key,
            private_key,
            bech32_address,
            base58_address,
            key_origin,
            "TEST_USER_NOT_A_CREDENTIAL",
            "TEST_PASSWORD_NOT_A_CREDENTIAL",
            "TEST_AUTH_NOT_A_CREDENTIAL",
            "TEST_PRIVATE_KEY_NOT_A_CREDENTIAL",
            "TEST_PRESHARED_KEY_NOT_A_CREDENTIAL",
            "TEST_CONTROL_VALUE_NOT_A_CREDENTIAL",
            "TEST CONTROL VALUE WITH SPACES",
        ):
            with self.subTest(value=value[:16]):
                self.assertNotIn(value, output)
        for marker in (
            "[REDACTED_ONION_IDENTITY]",
            "[REDACTED_EXTENDED_KEY]",
            "[REDACTED_PRIVATE_KEY]",
            "[REDACTED_WALLET_ADDRESS]",
            "[REDACTED_KEY_ORIGIN]",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, output)

    def test_every_hardened_derivation_marker_spelling_stays_redacted(self):
        """Pin the language the key-origin character class must accept.

        A descriptor's key origin marks a hardened derivation step with `h`,
        `H`, or `'`, and the path may be absent entirely. The pattern spells
        that marker as one case-insensitive character class, so this fixes what
        the class has to cover: a later edit cannot narrow the redaction to one
        spelling and quietly publish the others.
        """

        origins = (
            "[deadbeef/84h/0h/0h]",
            "[DEADBEEF/84H/0H/0H]",
            "[deadbeef/84'/0'/0']",
            "[deadbeef/84h/0'/0H]",
            "[deadbeef/0/1/2]",
            "[deadbeef]",
        )
        output = self.redact(
            "\n".join("descriptor={}".format(origin) for origin in origins) + "\n"
        )
        for origin in origins:
            with self.subTest(origin=origin):
                self.assertNotIn(origin, output)
        self.assertEqual(output.count("[REDACTED_KEY_ORIGIN]"), len(origins))

    def test_redactor_finishes_on_adversarial_key_origin_input(self):
        """Discovery output is host-shaped, untrusted, and can be pumped.

        Each line pumps one repetition axis of the key-origin pattern and then
        denies it the closing bracket, which is the input shape that forces a
        backtracking engine to explore every way of partitioning what it already
        consumed. The assertion is a wall-clock ceiling over the whole stream
        rather than any single match, so it stays meaningful for whatever the
        pattern table grows into.
        """

        pumps = (
            "descriptor=[deadbeef" + "/0h" * 40,
            "descriptor=[deadbeef" + "/00000000" * 40,
            "descriptor=[deadbeef" + "/0" * 200,
            "descriptor=[deadbeef" + "/0'" * 40 + "/",
        )
        output = self.redact("\n".join(pumps) + "\n", timeout=ADVERSARIAL_SECONDS)
        self.assertEqual(output.count("\n"), len(pumps))


if __name__ == "__main__":
    unittest.main()
