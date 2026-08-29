from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/validate_host_prerequisites_plan.py"
HOST_DIR = ROOT / "bootstrap/pi/host-prerequisites"


def valid_plan() -> dict[str, str]:
    sha = "a" * 64
    values = {
        "PLAN_VERSION": "1",
        "PLAN_STATUS": "approved-after-host-discovery",
        "MODULES_TARGET": "/etc/modules-load.d/90-website-infrastructure-kubeadm.conf",
        "SYSCTL_TARGET": "/etc/sysctl.d/90-website-infrastructure-kubeadm.conf",
        "FSTAB_TARGET": "/etc/fstab",
        "BACKUP_ROOT": "/var/backups/website-infrastructure/host-prerequisites",
        "STATE_ROOT": "/var/lib/website-infrastructure/host-prerequisites",
        "DESIRED_MODULES": "overlay,br_netfilter",
        "EXPECTED_ARCHITECTURE": "aarch64",
        "EXPECTED_KERNEL_RELEASE": "6.12.34+rpt-rpi-2712",
        "EXPECTED_MODULES_TARGET_STATE": "absent",
        "EXPECTED_SYSCTL_TARGET_STATE": f"sha256:{sha}",
        "SWAP_MECHANISM": "none",
        "SWAP_ACTION": "none",
        "CURRENT_VM_OVERCOMMIT_MEMORY": "0",
        "CURRENT_VM_PANIC_ON_OOM": "0",
        "CURRENT_KERNEL_PANIC": "0",
        "CURRENT_KERNEL_PANIC_ON_OOPS": "1",
        "CURRENT_KERNEL_KEYS_ROOT_MAXKEYS": "1000000",
        "CURRENT_KERNEL_KEYS_ROOT_MAXBYTES": "25000000",
        "CURRENT_NET_IPV4_IP_FORWARD": "0",
        "CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES": "0",
        "CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES": "0",
        "DESIRED_VM_OVERCOMMIT_MEMORY": "1",
        "DESIRED_VM_PANIC_ON_OOM": "0",
        "DESIRED_KERNEL_PANIC": "10",
        "DESIRED_KERNEL_PANIC_ON_OOPS": "1",
        "DESIRED_KERNEL_KEYS_ROOT_MAXKEYS": "1000000",
        "DESIRED_KERNEL_KEYS_ROOT_MAXBYTES": "25000000",
        "DESIRED_NET_IPV4_IP_FORWARD": "1",
        "DESIRED_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES": "1",
        "DESIRED_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES": "1",
    }
    for key in (
        "EXPECTED_MACHINE_ID_SHA256",
        "EXPECTED_BOOT_ID_SHA256",
        "EXPECTED_OS_RELEASE_SHA256",
        "EXPECTED_FSTAB_SHA256",
        "EXPECTED_ACTIVE_SWAP_SHA256",
        "DESIRED_MODULES_SHA256",
        "DESIRED_SYSCTL_SHA256",
    ):
        values[key] = sha
    return values


class HostPrerequisitesPlanTests(unittest.TestCase):
    def run_validator(self, values: dict[str, str], extra: str = ""):
        content = "\n".join(f"{key}={value}" for key, value in values.items())
        if extra:
            content += "\n" + extra
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan"
            plan.write_text(content + "\n", encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(plan)],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_accepts_exact_none_and_fstab_only_plans(self):
        result = self.run_validator(valid_plan())
        self.assertEqual(result.returncode, 0, result.stderr)

        values = valid_plan()
        values["SWAP_MECHANISM"] = "fstab-only"
        values["SWAP_ACTION"] = "disable-fstab"
        result = self.run_validator(values)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_unknown_or_inconsistent_swap(self):
        for mechanism, action in (
            ("zram", "disable-zram"),
            ("unknown", "none"),
            ("fstab-only", "none"),
            ("none", "disable-fstab"),
        ):
            with self.subTest(mechanism=mechanism, action=action):
                values = valid_plan()
                values["SWAP_MECHANISM"] = mechanism
                values["SWAP_ACTION"] = action
                self.assertNotEqual(self.run_validator(values).returncode, 0)

    def test_rejects_unknown_duplicate_or_retargeted_fields(self):
        result = self.run_validator(valid_plan(), "EXTRA_COMMAND=modprobe-anything")
        self.assertNotEqual(result.returncode, 0)
        result = self.run_validator(valid_plan(), "PLAN_STATUS=approved-after-host-discovery")
        self.assertNotEqual(result.returncode, 0)
        values = valid_plan()
        values["SYSCTL_TARGET"] = "/etc/sysctl.conf"
        self.assertNotEqual(self.run_validator(values).returncode, 0)

    def test_plan_diagnostics_never_echo_a_key_read_from_the_plan(self):
        """Issue #175: an operator plan is file-derived input like any other.

        The duplicate-key and unknown-key diagnostics reproduced the plan's own
        key names into stderr, outside issue #112's encryption sink. Both now
        report a position (the line) or a count, so the refusal stays
        actionable without echoing what it read.
        """

        marker = "ZZ" + "PLANKEYMARKER" + "ZZ"

        unknown = self.run_validator(valid_plan(), "{}=value".format(marker))
        self.assertNotEqual(unknown.returncode, 0)
        self.assertNotIn(marker, unknown.stdout + unknown.stderr)
        self.assertIn("unknown keys: 1", unknown.stderr)

        duplicated = self.run_validator(valid_plan(), "PLAN_VERSION=1")
        self.assertNotEqual(duplicated.returncode, 0)
        self.assertNotIn("PLAN_VERSION", duplicated.stdout + duplicated.stderr)
        self.assertIn("duplicate key", duplicated.stderr)

    def test_the_plan_probe_would_see_an_echo(self):
        """Vacuity probe for the assertions above.

        A reviewed expectation IS still named — that is the deliberate half of
        the contract — so the same stream demonstrably can carry a key name.
        """

        values = valid_plan()
        del values["PLAN_VERSION"]
        result = self.run_validator(values)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PLAN_VERSION", result.stderr)

    def test_rejects_unbounded_current_sysctl(self):
        values = valid_plan()
        values["CURRENT_NET_IPV4_IP_FORWARD"] = "2"
        self.assertNotEqual(self.run_validator(values).returncode, 0)

    def test_allows_unavailable_only_for_br_netfilter_gated_sysctls(self):
        values = valid_plan()
        values[
            "CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES"
        ] = "unavailable-until-module-load"
        values[
            "CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES"
        ] = "unavailable-until-module-load"
        self.assertEqual(self.run_validator(values).returncode, 0)
        values["CURRENT_NET_IPV4_IP_FORWARD"] = "unavailable-until-module-load"
        self.assertNotEqual(self.run_validator(values).returncode, 0)

    def test_fail_closed_example_has_complete_schema(self):
        result = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(HOST_DIR / "host-prerequisites.plan.example"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("missing keys:", result.stderr)
        self.assertNotIn("unknown keys:", result.stderr)


class HostPrerequisitesScriptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = (HOST_DIR / "lib.sh").read_text(encoding="utf-8")
        cls.discovery = (HOST_DIR / "discover-host-prerequisites.sh").read_text(
            encoding="utf-8"
        )
        cls.apply = (HOST_DIR / "apply-host-prerequisites.sh").read_text(encoding="utf-8")
        cls.verify = (HOST_DIR / "verify-host-prerequisites.sh").read_text(encoding="utf-8")
        cls.rollback = (HOST_DIR / "rollback-host-prerequisites.sh").read_text(
            encoding="utf-8"
        )
        cls.all_scripts = "\n".join(
            (cls.library, cls.discovery, cls.apply, cls.verify, cls.rollback)
        )

    def test_targets_and_private_roots_are_exact(self):
        for fragment in (
            'readonly modules_target="/etc/modules-load.d/90-website-infrastructure-kubeadm.conf"',
            'readonly sysctl_target="/etc/sysctl.d/90-website-infrastructure-kubeadm.conf"',
            'readonly fstab_target="/etc/fstab"',
            'readonly backup_root="/var/backups/website-infrastructure/host-prerequisites"',
            'readonly state_root="/var/lib/website-infrastructure/host-prerequisites"',
        ):
            self.assertIn(fragment, self.library)

    def test_committed_desired_files_are_minimal_and_exact(self):
        modules = [
            line
            for line in (HOST_DIR / "90-website-infrastructure-kubeadm.modules.conf")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(modules, ["overlay", "br_netfilter"])
        sysctls = {
            key.strip(): value.strip()
            for key, value in (
                line.split("=", 1)
                for line in (
                    HOST_DIR / "90-website-infrastructure-kubeadm.sysctl.conf"
                )
                .read_text(encoding="utf-8")
                .splitlines()
                if line and not line.startswith("#")
            )
        }
        self.assertEqual(
            sysctls,
            {
                "vm.overcommit_memory": "1",
                "vm.panic_on_oom": "0",
                "kernel.panic": "10",
                "kernel.panic_on_oops": "1",
                "kernel.keys.root_maxkeys": "1000000",
                "kernel.keys.root_maxbytes": "25000000",
                "net.ipv4.ip_forward": "1",
                "net.bridge.bridge-nf-call-iptables": "1",
                "net.bridge.bridge-nf-call-ip6tables": "1",
            },
        )

    def test_review_plan_is_inert_and_unknown_swap_fails_closed(self):
        self.assertNotIn('source "${plan', self.all_scripts)
        self.assertNotIn("eval ", self.all_scripts)
        for fragment in (
            "swap mechanism is unknown or mixed; no change is permitted",
            "/etc/default/dphys-swapfile",
            "/etc/systemd/zram-generator.conf",
            "native-unit:",
            "active swap is not represented by /etc/fstab",
        ):
            self.assertIn(fragment, self.library)

    def test_apply_has_hash_bound_ack_backup_and_automatic_rollback(self):
        for fragment in (
            "apply-reviewed-host-prerequisites-${plan_sha256}",
            "disable-reviewed-fstab-swap-",
            "PHYSICAL_OR_LAN_RECOVERY_TESTED",
            "CONFIRM_REBOOT_VERIFICATION",
            'cp -a -- "${fstab_target}" "${transaction_dir}/fstab.pre"',
            "attempting the exact prepared rollback",
            'restore_transaction "${transaction_id}"',
        ):
            self.assertIn(fragment, self.apply)

    def test_module_gated_sysctls_are_captured_before_the_first_write(self):
        for fragment in (
            "unavailable-until-module-load",
            "LATE_SYSCTLS_STATE",
            "module-load-sysctls.pre",
            "transaction_old_sysctl_value",
        ):
            self.assertIn(fragment, self.library + self.apply)
        self.assertLess(
            self.apply.index('module-load-sysctls.pre"'),
            self.apply.index('sysctl -q -p "${sysctl_target}"'),
        )

    def test_verification_distinguishes_apply_from_real_reboot(self):
        self.assertIn('[[ "${current_boot_id}" != "${applied_boot_id}" ]]', self.verify)
        self.assertIn("verify_desired_host_contract", self.verify)
        self.assertIn("loaded modules, runtime sysctls, and no swap", self.verify)

    def test_rollback_refuses_drift_and_requires_exact_ack(self):
        for fragment in (
            "modules target drifted after apply; refusing rollback overwrite",
            "sysctl target drifted after apply; refusing rollback overwrite",
            "/etc/fstab drifted after apply; refusing rollback overwrite",
        ):
            self.assertIn(fragment, self.library)
        self.assertIn(
            "rollback-host-prerequisites-${transaction_id}", self.rollback
        )
        self.assertIn("CONFIRM_HOST_PREREQUISITES_ROLLBACK", self.rollback)

    def test_no_broad_swap_sysctl_module_or_network_actions(self):
        for forbidden in (
            "swapoff -a",
            "swapoff --all",
            "sysctl --system",
            "modprobe -r",
            "curl ",
            "wget ",
        ):
            self.assertNotIn(forbidden, self.all_scripts)


if __name__ == "__main__":
    unittest.main()
