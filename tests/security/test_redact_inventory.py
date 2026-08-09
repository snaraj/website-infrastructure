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


if __name__ == "__main__":
    unittest.main()
