"""Make dangerous admin-ingress contract states unrepresentable.

The private contract names the reviewed administrative VPN ingress
interfaces for the SSH-only guard (PLAT-DEC-001). These tests prove the
schema rejects every ambiguity the handoff enumerates — duplicates,
whitespace games, unexpected keys, symlinks, hard links, non-root
ownership, partial/oversized/undecodable files, and interface classes that
would aim the guard at loopback, the LAN recovery plane, or the pod
network — and that no diagnostic can ever carry a private value.
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_admin_ingress_contract.py"

spec = importlib.util.spec_from_file_location("validate_admin_ingress_contract", SCRIPT)
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)

REVIEWED = "ADMIN_INGRESS_REVIEWED=yes"
INTERFACE = "ADMIN_INGRESS_INTERFACE="


def parse(*lines):
    return MODULE.parse_contract_text("\n".join(lines) + "\n")


class ContractParsingTests(unittest.TestCase):
    """The KEY=value grammar refuses repair: ambiguity is always rejection."""

    def test_healthy_contract_preserves_declaration_order(self):
        interfaces, errors = parse(
            "# comment", REVIEWED, INTERFACE + "adminvpn0", INTERFACE + "adminvpn1"
        )
        self.assertEqual(errors, [])
        self.assertEqual(interfaces, ("adminvpn0", "adminvpn1"))

    def test_missing_interface_declaration_fails(self):
        interfaces, errors = parse(REVIEWED)
        self.assertIsNone(interfaces)
        self.assertIn("INTERFACE_MISSING", errors)

    def test_duplicate_interface_declaration_fails(self):
        _, errors = parse(REVIEWED, INTERFACE + "adminvpn0", INTERFACE + "adminvpn0")
        self.assertIn("INTERFACE_DUPLICATE line 3", errors)

    def test_whitespace_ambiguity_fails(self):
        for line in (
            " " + INTERFACE + "adminvpn0",
            INTERFACE + "adminvpn0 ",
            "ADMIN_INGRESS_REVIEWED =yes",
            "\t" + REVIEWED,
        ):
            with self.subTest(line=line):
                _, errors = parse(REVIEWED, line)
                self.assertTrue(
                    any(error.startswith("LINE_SHAPE_INVALID") for error in errors)
                )

    def test_unexpected_key_fails(self):
        _, errors = parse(REVIEWED, INTERFACE + "adminvpn0", "ADMIN_INGRESS_MODE=off")
        self.assertIn("KEY_UNSUPPORTED line 3", errors)

    def test_review_flag_is_mandatory_and_single_and_yes(self):
        cases = (
            ((INTERFACE + "adminvpn0",), "REVIEW_FLAG_MISSING"),
            ((REVIEWED, REVIEWED, INTERFACE + "adminvpn0"), "REVIEW_FLAG_DUPLICATE line 2"),
            (("ADMIN_INGRESS_REVIEWED=maybe", INTERFACE + "adminvpn0"), "REVIEW_FLAG_INVALID line 1"),
            (("ADMIN_INGRESS_REVIEWED=no", INTERFACE + "adminvpn0"), "REVIEW_INCOMPLETE"),
        )
        for lines, token in cases:
            with self.subTest(token=token):
                _, errors = parse(*lines)
                self.assertIn(token, errors)

    def test_loopback_lan_bridge_and_cni_classes_are_unrepresentable(self):
        # Universal Linux interface-class names, not host facts: declaring
        # any of these would break local kubectl, LAN recovery, or the CNI.
        for name in (
            "lo", "eth0", "enp1s0", "end0", "wlan0", "br-lan", "bond0",
            "docker0", "veth12ab", "cni0", "cali12ab", "flannel.1",
            "vxlan.calico", "tunl0", "kube-bridge", "virbr0", "tap0",
        ):
            with self.subTest(name=name):
                _, errors = parse(REVIEWED, INTERFACE + name)
                self.assertTrue(
                    any("INTERFACE_CLASS_FORBIDDEN" in error for error in errors)
                )

    def test_interface_shape_is_closed(self):
        for name in ("WG0", "wg admin", "wg*", "-admin", "9vpn", "a", "x" * 16, "wgé"):
            with self.subTest(name=repr(name)):
                _, errors = parse(REVIEWED, INTERFACE + name)
                self.assertTrue(
                    any(
                        error.startswith(
                            ("INTERFACE_SHAPE_INVALID", "VALUE_WHITESPACE_AMBIGUOUS")
                        )
                        for error in errors
                    )
                )

    def test_interface_count_is_bounded(self):
        lines = [REVIEWED] + [INTERFACE + f"adminvpn{i}" for i in range(17)]
        _, errors = parse(*lines)
        self.assertTrue(any("INTERFACE_LIMIT_EXCEEDED" in error for error in errors))

    def test_every_diagnostic_is_in_the_closed_vocabulary(self):
        hostile_documents = (
            (REVIEWED,),
            (REVIEWED, INTERFACE + "eth0"),
            (REVIEWED, "X=y"),
            ("ADMIN_INGRESS_REVIEWED=no",),
            (REVIEWED, INTERFACE + "adminvpn0", INTERFACE + "adminvpn0"),
        )
        for lines in hostile_documents:
            _, errors = parse(*lines)
            for error in errors:
                token = error.split(" line ")[0]
                with self.subTest(error=error):
                    self.assertIn(token, MODULE.TOKENS)


class ContractMetadataTests(unittest.TestCase):
    """File metadata policy: root-owned, 0600, one hard link, no symlink."""

    def test_metadata_policy_rejects_every_dangerous_state(self):
        base = dict(
            is_symlink=False, is_regular=True, mode=0o600, uid=0, gid=0, nlink=1
        )
        self.assertEqual(MODULE.metadata_errors(**base), [])
        cases = (
            (dict(base, is_symlink=True), "CONTRACT_SYMLINK"),
            (dict(base, is_regular=False), "CONTRACT_NOT_REGULAR"),
            (dict(base, mode=0o640), "CONTRACT_MODE_INVALID"),
            (dict(base, mode=0o400), "CONTRACT_MODE_INVALID"),
            (dict(base, uid=1000), "CONTRACT_OWNERSHIP_INVALID"),
            (dict(base, gid=1000), "CONTRACT_OWNERSHIP_INVALID"),
            (dict(base, nlink=2), "CONTRACT_LINK_COUNT_INVALID"),
        )
        for kwargs, token in cases:
            with self.subTest(token=token):
                self.assertIn(token, MODULE.metadata_errors(**kwargs))

    def test_symlinked_file_is_rejected_end_to_end(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = (Path(scratch).resolve()) / "real.env"
            target.write_text("ADMIN_INGRESS_REVIEWED=yes\n", encoding="utf-8")
            target.chmod(0o600)
            link = (Path(scratch).resolve()) / "contract.env"
            link.symlink_to(target)
            _, errors = MODULE.load_admin_ingress_contract(link)
            self.assertEqual(errors, ["CONTRACT_SYMLINK"])

    def test_hard_linked_file_is_rejected_end_to_end(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = (Path(scratch).resolve()) / "contract.env"
            target.write_text("ADMIN_INGRESS_REVIEWED=yes\n", encoding="utf-8")
            target.chmod(0o600)
            os.link(target, (Path(scratch).resolve()) / "second-name.env")
            _, errors = MODULE.load_admin_ingress_contract(target)
            self.assertIn("CONTRACT_LINK_COUNT_INVALID", errors)

    def test_wrong_mode_is_rejected_end_to_end(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = (Path(scratch).resolve()) / "contract.env"
            target.write_text("ADMIN_INGRESS_REVIEWED=yes\n", encoding="utf-8")
            target.chmod(0o644)
            _, errors = MODULE.load_admin_ingress_contract(target)
            self.assertIn("CONTRACT_MODE_INVALID", errors)

    @unittest.skipUnless(os.geteuid() != 0, "requires a non-root euid")
    def test_non_root_ownership_is_rejected_end_to_end(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = (Path(scratch).resolve()) / "contract.env"
            target.write_text(
                "ADMIN_INGRESS_REVIEWED=yes\nADMIN_INGRESS_INTERFACE=adminvpn0\n",
                encoding="utf-8",
            )
            target.chmod(0o600)
            _, errors = MODULE.load_admin_ingress_contract(target)
            self.assertIn("CONTRACT_OWNERSHIP_INVALID", errors)

    def test_missing_oversized_and_undecodable_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            missing = (Path(scratch).resolve()) / "absent.env"
            _, errors = MODULE.load_admin_ingress_contract(missing)
            self.assertEqual(errors, ["CONTRACT_UNAVAILABLE"])
            # Ownership rejection fires first for user-owned fixtures, so the
            # later bounds are exercised through a patched metadata seam; the
            # ownership rule itself is proven by the dedicated tests above.
            oversized = (Path(scratch).resolve()) / "oversized.env"
            oversized.write_bytes(b"#" + b"a" * MODULE.MAX_CONTRACT_BYTES)
            oversized.chmod(0o600)
            undecodable = (Path(scratch).resolve()) / "undecodable.env"
            undecodable.write_bytes(b"\xff\xfe" + b"ADMIN_INGRESS_REVIEWED=yes\n")
            undecodable.chmod(0o600)
            with mock.patch.object(MODULE, "_stat_errors", return_value=[]):
                raw, errors = MODULE.read_contract_bytes(oversized)
                self.assertIsNone(raw)
                self.assertIn("CONTRACT_TOO_LARGE", errors)
                _, errors = MODULE.load_admin_ingress_contract(undecodable)
                self.assertIn("CONTRACT_ENCODING_INVALID", errors)


class ContractPrivacyTests(unittest.TestCase):
    """No path, value, or interface name may reach any diagnostic stream."""

    def test_hostile_private_values_never_appear_in_output(self):
        # Assembled at runtime so no private-looking value exists at rest.
        hostile_interface = "wg" + "casa" + "lan" + "7"
        hostile_key_value = "ADMIN_" + "INGRESS_INTERFACE=" + hostile_interface
        _, errors = MODULE.parse_contract_text(
            "ADMIN_INGRESS_REVIEWED=yes\n"
            + hostile_key_value
            + "\n"
            + hostile_key_value
            + "\n"
        )
        for error in errors:
            self.assertNotIn(hostile_interface, error)
        with tempfile.TemporaryDirectory() as scratch:
            contract = (Path(scratch).resolve()) / "contract.env"
            contract.write_text(
                "ADMIN_INGRESS_REVIEWED=yes\n" + hostile_key_value + "\n",
                encoding="utf-8",
            )
            contract.chmod(0o600)
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(SCRIPT), "CONTRACT", str(contract)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn(hostile_interface, completed.stdout + completed.stderr)

    def test_tracked_example_stays_inert(self):
        example = (
            REPO_ROOT / "bootstrap/pi/ingress-guard/admin-ingress.env.example"
        ).read_text(encoding="utf-8")
        self.assertEqual(MODULE.example_errors(example), [])

    def test_example_gate_rejects_reviewed_or_valued_templates(self):
        self.assertIn(
            "EXAMPLE_MUST_STAY_UNREVIEWED",
            MODULE.example_errors("ADMIN_INGRESS_REVIEWED=yes\n"),
        )
        self.assertIn(
            "EXAMPLE_MUST_DECLARE_NO_VALUE",
            MODULE.example_errors(
                "ADMIN_INGRESS_REVIEWED=no\nADMIN_INGRESS_INTERFACE=adminvpn0\n"
            ),
        )


if __name__ == "__main__":
    unittest.main()
