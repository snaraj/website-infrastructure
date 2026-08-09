"""Keep private SSH transport separate from host egress privacy."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "runbooks" / "remote-access.md"
CONNECTOR = ROOT / "bootstrap" / "pi" / "cloudflared" / "README.md"


class RemoteAccessTrafficPlaneTests(unittest.TestCase):
    """Prevent Tunnel from being mistaken for a host-wide VPN or SSH authority."""

    @classmethod
    def setUpClass(cls):
        cls.runbook = " ".join(RUNBOOK.read_text(encoding="utf-8").split())
        cls.connector = " ".join(CONNECTOR.read_text(encoding="utf-8").split())

    def test_initial_path_keeps_self_managed_ssh_authentication(self):
        """The private route adds a gate without silently replacing operator keys."""

        for fragment in (
            "self-managed, passphrase- protected SSH key end-to-end",
            "sshd still authenticates the key",
            "Do not add a public hostname",
            "trust a Cloudflare SSH certificate authority in this phase",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.runbook)

    def test_tunnel_does_not_replace_vpn_or_kill_switch(self):
        """Server egress remains governed by the host route and privacy boundary."""

        for document in (self.runbook, self.connector):
            with self.subTest(document=document[:24]):
                self.assertIn("host routing table", document)
                self.assertIn("VPN/WireGuard", document)
                self.assertTrue(
                    "kill switch" in document or "kill-switch" in document
                )
                self.assertIn("physical/LAN recovery", document)

    def test_current_official_cloudflare_entry_points_are_recorded(self):
        """Live work must revalidate both private SSH and tunnel egress behavior."""

        for suffix in (
            "/ssh/ssh-device-client/",
            "/private-net/cloudflared/",
            "/configure-tunnels/tunnel-with-firewall/",
            "/ssh/ssh-infrastructure-access/",
        ):
            with self.subTest(suffix=suffix):
                self.assertIn("https://developers.cloudflare.com/", self.runbook)
                self.assertIn(suffix, self.runbook)


if __name__ == "__main__":
    unittest.main()
