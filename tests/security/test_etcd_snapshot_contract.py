import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import required_tool


ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")
BASH_REQUIRED = "Bash is required to execute the snapshot script"
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)


def bash_path(path):
    value = Path(path).as_posix()
    if os.name == "nt" and len(value) >= 3 and value[1:3] == ":/":
        return f"/{value[0].lower()}{value[2:]}"
    return value


class EtcdSnapshotContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = (ROOT / "bootstrap/pi/etcd-snapshot.sh").read_text(encoding="utf-8")
        cls.installer = (ROOT / "bootstrap/pi/install-recovery-tools.sh").read_text(encoding="utf-8")
        cls.service = (
            ROOT / "bootstrap/pi/systemd/website-infrastructure-etcd-snapshot.service"
        ).read_text(encoding="utf-8")
        cls.timer = (
            ROOT / "bootstrap/pi/systemd/website-infrastructure-etcd-snapshot.timer"
        ).read_text(encoding="utf-8")

    def test_snapshot_is_local_pinned_verified_and_private(self):
        for fragment in (
            "snapshot_dir=/var/backups/kubernetes/etcd",
            "endpoint=https://127.0.0.1:2379",
            "/etc/kubernetes/pki/etcd/ca.crt",
            "/etc/kubernetes/pki/etcd/healthcheck-client.crt",
            "/etc/kubernetes/pki/etcd/healthcheck-client.key",
            "ETCD_TOOLS_ARM64_SHA256 is unresolved or malformed",
            "--write-out=json snapshot status",
            "chmod 0600",
            "index = 14",
            "create-reviewed-stacked-etcd-snapshot",
        ):
            self.assertIn(fragment, self.snapshot)
        self.assertIn("apply mode requires root", self.snapshot)
        self.assertNotIn("set -x", self.snapshot)

    def test_installer_is_offline_and_rejects_unsafe_archives(self):
        for fragment in (
            "ETCD_TOOLS_ARM64_SHA256 is unresolved or malformed",
            "sha256sum --check --status",
            "staged etcd archive contains path traversal",
            "unsupported member type",
            "etcdctl exactly once",
            "etcdutl exactly once",
            "install-reviewed-etcd-tools-${ETCD_VERSION}",
            "enable-reviewed-six-hour-etcd-snapshots",
        ):
            self.assertIn(fragment, self.installer)
        for downloader in ("curl ", "wget ", "Invoke-WebRequest"):
            self.assertNotIn(downloader, self.installer)

    def test_ssd_placeholder_predicate_has_source_parity_and_real_ere_behavior(self):
        expected_pattern = (
            r"^(EXPECTED_SSD_FILESYSTEM_UUID|EXPECTED_SSD_MOUNT_SOURCE)="
            r"($|REPLACE_|UNRESOLVED)"
        )
        predicates = []
        for label, source in (
            ("installer", self.installer),
            ("snapshot", self.snapshot),
        ):
            active_patterns = re.findall(
                r"(?m)^[ \t]*if grep -E '([^'\r\n]+)'[ \t]*\\[ \t]*$",
                source,
            )
            ssd_patterns = [
                pattern
                for pattern in active_patterns
                if pattern.startswith(
                    "^(EXPECTED_SSD_FILESYSTEM_UUID|"
                    "EXPECTED_SSD_MOUNT_SOURCE)="
                )
            ]
            with self.subTest(label=label, contract="exact predicate"):
                self.assertEqual(ssd_patterns, [expected_pattern])
                self.assertNotIn(
                    "(EXPECTED_SSD_FILESYSTEM_UUID|EXPECTED_SSD_MOUNT_SOURCE)="
                    "(|REPLACE_|UNRESOLVED)",
                    source,
                )
            predicates.append((label, ssd_patterns[0]))

        if not BASH:
            self.skipTest("Bash is unavailable")
        cases = (
            ("EXPECTED_SSD_FILESYSTEM_UUID=1234-ABCD\n", False),
            ("EXPECTED_SSD_MOUNT_SOURCE=/dev/reviewed-ssd\n", False),
            ("EXPECTED_SSD_FILESYSTEM_UUID=\n", True),
            ("EXPECTED_SSD_FILESYSTEM_UUID=REPLACE_UUID\n", True),
            ("EXPECTED_SSD_FILESYSTEM_UUID=UNRESOLVED\n", True),
            ("EXPECTED_SSD_MOUNT_SOURCE=\n", True),
            ("EXPECTED_SSD_MOUNT_SOURCE=REPLACE_DEVICE\n", True),
            ("EXPECTED_SSD_MOUNT_SOURCE=UNRESOLVED\n", True),
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "decisions.env.local"
            for label, pattern in predicates:
                for content, unresolved in cases:
                    with self.subTest(label=label, content=content.rstrip("\n")):
                        fixture.write_text(content, encoding="utf-8")
                        result = subprocess.run(
                            [
                                required_tool(BASH, BASH_REQUIRED),
                                "-c",
                                f"LC_ALL=C grep -Eq {shlex.quote(pattern)} \"$1\"",
                                "recovery-ssd-gate",
                                bash_path(fixture),
                            ],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        self.assertEqual(
                            result.returncode,
                            0 if unresolved else 1,
                            result.stderr,
                        )

    def test_systemd_schedule_and_sandbox_are_explicit(self):
        for fragment in (
            "Type=oneshot",
            "UMask=0077",
            "ExecStart=/usr/local/sbin/website-infrastructure-etcd-snapshot --apply",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/backups/kubernetes/etcd /run/lock",
            "IPAddressDeny=any",
            "IPAddressAllow=127.0.0.0/8",
            "CapabilityBoundingSet=",
        ):
            self.assertIn(fragment, self.service)
        self.assertIn("OnCalendar=*-*-* 00/6:00:00", self.timer)
        self.assertIn("Persistent=true", self.timer)


if __name__ == "__main__":
    unittest.main()
