#!/usr/bin/env python3
import contextlib
import copy
import importlib.util
import io
import ipaddress
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_pi_network.py"
SPEC = importlib.util.spec_from_file_location("validate_pi_network", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

FIXTURE = json.loads(
    (Path(__file__).with_name("fixtures_pi_network.json")).read_text(encoding="utf-8")
)
ADVERTISE = ipaddress.ip_address("192.168.50.10")


def query_responses(state):
    mapping = {
        ("address", "show"): state["address"],
        ("-details", "link", "show"): state["link"],
        ("rule", "show"): state["rule"],
        ("route", "show", "table", "all"): state["route"],
    }

    def response(*arguments):
        return copy.deepcopy(mapping[arguments])

    return response


class PiNetworkValidationTests(unittest.TestCase):
    def state(self):
        return copy.deepcopy(FIXTURE)

    def inspect(self, state):
        with mock.patch.object(MODULE, "ip_json", side_effect=query_responses(state)):
            return MODULE.live_networks(ADVERTISE)

    def assert_inspection_rejected(self, state, fragment):
        with self.assertRaisesRegex(ValueError, fragment):
            self.inspect(state)

    def test_accepts_only_the_proven_canonical_lan_model(self):
        networks = self.inspect(self.state())
        self.assertIn(("interface eth0", ipaddress.ip_network("192.168.50.0/24")), networks)
        self.assertNotIn(("route table main", ipaddress.ip_network("0.0.0.0/0")), networks)

    def test_rejects_any_additional_policy_rule(self):
        state = self.state()
        state["rule"].insert(
            1,
            {
                "priority": 10000,
                "src": "all",
                "fwmark": "0xca6c",
                "table": 51820,
            },
        )
        self.assert_inspection_rejected(state, "policy rule")

    def test_rejects_a_route_in_an_alternate_table_even_without_a_rule(self):
        state = self.state()
        state["route"].append(
            {"dst": "10.0.0.0/8", "dev": "eth0", "table": 51820, "flags": []}
        )
        self.assert_inspection_rejected(state, "unsupported route table 51820")

    def test_rejects_vpn_default_and_split_routes(self):
        default_state = self.state()
        default_state["link"].append(
            {"ifname": "corp0", "link_type": "none", "linkinfo": {"info_kind": "tun"}}
        )
        default_state["route"][0]["dev"] = "corp0"
        self.assert_inspection_rejected(default_state, "VPN/tunnel route")

        split_state = self.state()
        split_state["link"].append(
            {
                "ifname": "corp0",
                "link_type": "none",
                "linkinfo": {"info_kind": "wireguard"},
            }
        )
        split_state["route"].append(
            {"dst": "172.16.0.0/12", "dev": "corp0", "protocol": "static", "flags": []}
        )
        self.assert_inspection_rejected(split_state, "VPN/tunnel route")

    def test_rejects_a_default_route_without_exact_lan_gateway_proof(self):
        wrong_interface = self.state()
        wrong_interface["link"].append({"ifname": "wlan0", "link_type": "ether"})
        wrong_interface["route"][0]["dev"] = "wlan0"
        self.assert_inspection_rejected(wrong_interface, "advertise-address LAN interface")

        off_link_gateway = self.state()
        off_link_gateway["route"][0]["gateway"] = "192.168.60.1"
        self.assert_inspection_rejected(off_link_gateway, "advertise LAN")

    def test_broad_split_default_is_not_ignored_and_blocks_overlap(self):
        state = self.state()
        state["route"].append(
            {
                "dst": "0.0.0.0/1",
                "gateway": "192.168.50.1",
                "dev": "eth0",
                "protocol": "static",
                "flags": [],
            }
        )
        config = """\
localAPIEndpoint:
  advertiseAddress: 192.168.50.10
networking:
  podSubnet: 10.42.0.0/16
  serviceSubnet: 10.43.0.0/16
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "kubeadm.yaml"
            config_path.write_text(config, encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch.object(MODULE, "ip_json", side_effect=query_responses(state)):
                with contextlib.redirect_stderr(stderr):
                    result = MODULE.main([str(config_path)])
        self.assertEqual(result, 1)
        self.assertIn("overlaps route table main 0.0.0.0/1", stderr.getvalue())

    def test_malformed_or_incomplete_ip_query_fails_closed(self):
        malformed = self.state()
        malformed["route"] = {"dst": "default"}
        self.assert_inspection_rejected(malformed, "did not return a JSON list")

        no_advertise_binding = self.state()
        no_advertise_binding["address"][1]["addr_info"][0]["local"] = "192.168.50.11"
        self.assert_inspection_rejected(no_advertise_binding, "occur exactly once")

    def test_failed_ip_command_returns_a_fail_closed_result(self):
        config = """\
localAPIEndpoint:
  advertiseAddress: 192.168.50.10
networking:
  podSubnet: 10.42.0.0/16
  serviceSubnet: 10.43.0.0/16
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "kubeadm.yaml"
            config_path.write_text(config, encoding="utf-8")
            stderr = io.StringIO()
            error = subprocess.CalledProcessError(2, ["ip", "-j", "-4", "address", "show"])
            with mock.patch.object(MODULE, "ip_json", side_effect=error):
                with contextlib.redirect_stderr(stderr):
                    result = MODULE.main([str(config_path)])
        self.assertEqual(result, 1)
        self.assertIn("unable to prove live network separation", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
