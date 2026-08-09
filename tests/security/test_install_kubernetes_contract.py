#!/usr/bin/env python3
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "bootstrap" / "pi" / "install-kubernetes.sh"
CONTAINERD_UNIT = ROOT / "bootstrap" / "pi" / "systemd" / "containerd.service"
KUBELET_UNIT = ROOT / "bootstrap" / "pi" / "systemd" / "kubelet.service"
RECOVERY_NOTE = ROOT / "bootstrap" / "pi" / "INSTALL-RECOVERY.md"
BASH = shutil.which("bash")
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
                BASH,
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

    def test_kubelet_accepts_only_kubeadm_generated_runtime_flags(self):
        self.assertIn(
            "EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env", self.kubelet
        )
        self.assertIn(
            "ExecStart=/usr/local/bin/kubelet $KUBELET_KUBEADM_ARGS", self.kubelet
        )
        self.assertNotIn("/etc/default/kubelet", self.kubelet)
        self.assertNotIn("KUBELET_EXTRA_ARGS", self.kubelet)


if __name__ == "__main__":
    unittest.main()
