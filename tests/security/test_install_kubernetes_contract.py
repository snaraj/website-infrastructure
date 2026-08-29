#!/usr/bin/env python3
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from .support import required_tool


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "bootstrap" / "pi" / "install-kubernetes.sh"
CONTAINERD_UNIT = ROOT / "bootstrap" / "pi" / "systemd" / "containerd.service"
KUBELET_UNIT = ROOT / "bootstrap" / "pi" / "systemd" / "kubelet.service"
RECOVERY_NOTE = ROOT / "bootstrap" / "pi" / "INSTALL-RECOVERY.md"
GUARD_DROPIN = (
    ROOT
    / "bootstrap"
    / "pi"
    / "ingress-guard"
    / "systemd"
    / "kubelet.service.d"
    / "50-website-infrastructure-ingress-guard.conf"
)
BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required for the archive contract tests"
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)


def bash_path(path):
    value = Path(path).as_posix()
    if os.name == "nt" and len(value) >= 3 and value[1:3] == ":/":
        return f"/{value[0].lower()}{value[2:]}"
    return value


@unittest.skipUnless(BASH, "bash and GNU tar are required for archive contract tests")
class InstallerArchiveTests(unittest.TestCase):
    def validate(self, archive):
        return subprocess.run(
            [
                required_tool(BASH, BASH_REQUIRED),
                "-c",
                "source \"$1\"\nsafe_archive \"$2\" '^[A-Za-z0-9._-]+/?$'",
                "installer-archive-test",
                bash_path(SCRIPT),
                bash_path(archive),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def make_archive(path, member_name="loopback", member_type=tarfile.REGTYPE):
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo(member_name)
            member.mode = 0o755
            member.type = member_type
            if member_type == tarfile.REGTYPE:
                payload = b"reviewed-binary"
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            else:
                member.linkname = "loopback" if member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                archive.addfile(member)

    def test_regular_safe_member_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "safe.tgz"
            self.make_archive(archive)
            result = self.validate(archive)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_links_devices_and_traversal_are_rejected(self):
        cases = (
            ("symlink", "loopback", tarfile.SYMTYPE),
            ("hardlink", "loopback", tarfile.LNKTYPE),
            ("character-device", "loopback", tarfile.CHRTYPE),
            ("block-device", "loopback", tarfile.BLKTYPE),
            ("traversal", "../escape", tarfile.REGTYPE),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for label, name, member_type in cases:
                with self.subTest(label=label):
                    archive = Path(temporary) / f"{label}.tgz"
                    self.make_archive(archive, name, member_type)
                    result = self.validate(archive)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


class InstallerTransactionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.containerd = CONTAINERD_UNIT.read_text(encoding="utf-8")
        cls.kubelet = KUBELET_UNIT.read_text(encoding="utf-8")
        cls.recovery = RECOVERY_NOTE.read_text(encoding="utf-8")

    def test_manifest_is_complete_and_targets_are_never_overwritten(self):
        for fragment in (
            "containerd|ctr|containerd-shim-*",
            'add_target "${path}" "/opt/cni/bin/$(basename "${path}")" 0755',
            "refusing to overwrite existing install target",
            "target appeared during installation; refusing overwrite",
            'ln -- "${pending_destination}" "${destination}"',
            "refusing to replace or alter existing systemd service state",
            "/usr/local/bin/kubeadm version -o short",
            "/usr/local/bin/containerd config dump",
        ):
            self.assertIn(fragment, self.script)
        self.assertNotIn('install -m 0755 "${binary}" "/opt/cni/bin/', self.script)

    def test_failure_handler_is_phase_aware_and_hash_guarded(self):
        for fragment in (
            "transaction_started='yes'",
            "rollback_installation",
            "installed_hashes",
            "refusing to remove changed installed target",
            "phase=%s rollback=complete",
            "phase=%s rollback=incomplete",
        ):
            self.assertIn(fragment, self.script)
        self.assertIn("SIGKILL", self.recovery)
        self.assertIn("never deletes a path it can no longer prove", self.recovery)

    def test_units_have_explicit_finite_limits_and_correct_start_limit_section(self):
        for unit in (self.containerd, self.kubelet):
            unit_section, service_section = unit.split("[Service]", 1)
            self.assertIn("StartLimitIntervalSec=0", unit_section)
            self.assertNotIn("StartLimitInterval", service_section)
            self.assertIn("LimitCORE=0", service_section)
            self.assertNotIn("=infinity", service_section)
        for unit in (self.containerd, self.kubelet):
            self.assertNotIn("LimitNOFILE=", unit)
            self.assertIn("LimitNPROC=65536", unit)
            self.assertIn("TasksMax=65536", unit)

    def test_collision_gate_tolerates_only_the_tracked_ingress_guard_dropin(self):
        # PLAT-DEC-001 installs the ingress guard before the runtime, so the
        # guard's one additive kubelet drop-in legitimately predates
        # kubelet.service itself. The collision gate may tolerate exactly that
        # byte-verified state and nothing else; each fragment below is a
        # load-bearing piece of that tolerance, so losing any of them either
        # re-breaks the sanctioned guard-then-runtime ordering or widens the
        # gate past the tracked drop-in.
        self.assertTrue(GUARD_DROPIN.is_file())
        for fragment in (
            "'/etc/systemd/system/kubelet.service.d/50-website-infrastructure-ingress-guard.conf'",
            "bootstrap/pi/ingress-guard/systemd/kubelet.service.d/50-website-infrastructure-ingress-guard.conf",
            "systemctl show -p FragmentPath --value kubelet.service",
            "systemctl show -p DropInPaths --value kubelet.service",
            '[[ -z "${fragment_path}" && "${dropin_paths}" == "${guard_dropin_target}" ]]',
            "unexpected content beside the tracked ingress-guard kubelet drop-in",
            "'0:0:644'",
            'check_sha "${guard_dropin_hash}" "${guard_dropin_target}"',
        ):
            self.assertIn(fragment, self.script)

    def test_collision_gate_still_refuses_foreign_service_state(self):
        # The drop-in tolerance must not relax the original refusals:
        # activation state dies first for both units, a unit-state probe that
        # finds anything for containerd.service falls through to the
        # unconditional refusal, and only kubelet.service reaches the
        # tracked-drop-in validation branch.
        for fragment in (
            'systemctl is-active --quiet "${name}" 2>/dev/null',
            'systemctl is-enabled --quiet "${name}" 2>/dev/null',
            'systemctl cat "${name}" >/dev/null 2>&1 || continue',
            '[[ "${name}" == kubelet.service ]] ||',
            "refusing to replace or alter existing systemd service state",
        ):
            self.assertIn(fragment, self.script)

    def test_kubelet_binds_kubeadm_managed_config_and_dynamic_runtime_flags(self):
        expected_bindings = [
            'Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig='
            '/etc/kubernetes/bootstrap-kubelet.conf '
            '--kubeconfig=/etc/kubernetes/kubelet.conf"',
            'Environment="KUBELET_CONFIG_ARGS='
            '--config=/var/lib/kubelet/config.yaml"',
            'Environment="KUBELET_KUBEADM_ARGS="',
            "EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env",
            "ExecStart=/usr/local/bin/kubelet $KUBELET_KUBECONFIG_ARGS "
            "$KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS",
        ]
        self.assertEqual(
            [
                line
                for line in self.kubelet.splitlines()
                if line.startswith(("Environment=", "EnvironmentFile=", "ExecStart="))
            ],
            expected_bindings,
        )
        self.assertNotIn("/etc/default/kubelet", self.kubelet)
        self.assertNotIn("KUBELET_EXTRA_ARGS", self.kubelet)


if __name__ == "__main__":
    unittest.main()
