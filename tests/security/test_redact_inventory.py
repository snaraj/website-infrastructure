#!/usr/bin/env python3
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "redact_inventory.py"


class RedactionTests(unittest.TestCase):
    def redact(self, value):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=value,
            text=True,
            capture_output=True,
            check=True,
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


if __name__ == "__main__":
    unittest.main()
