import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


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
