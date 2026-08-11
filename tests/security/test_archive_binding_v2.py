"""Prove protected archive bindings use stable, unambiguous mount identity."""

import inspect
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = load_script(
    "validate_protected_host_contract.py", module_name="validate_archive_binding_v3"
)


def findmnt_output(
    *,
    source="/dev/sda2",
    filesystem_uuid="AABB-CCDD",
    partition_uuid="1234ABCD-02",
    target="/srv",
    filesystem_type="ext4",
    options="rw,noatime",
    major_minor="8:2",
):
    """Build the exact one-record JSON shape accepted from findmnt."""

    return json.dumps(
        {
            "filesystems": [
                {
                    "target": target,
                    "source": source,
                    "fstype": filesystem_type,
                    "options": options,
                    "uuid": filesystem_uuid,
                    "partuuid": partition_uuid,
                    "maj:min": major_minor,
                }
            ]
        }
    ).encode("utf-8")


class ArchiveBindingV3Tests(unittest.TestCase):
    """Keep mount bindings stable across reboot while failing closed on ambiguity."""

    def findmnt_identity(
        self,
        stdout,
        *,
        expected_filesystem_type="ext4",
        expected_major_minor="8:2",
    ):
        with mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/findmnt"):
            with mock.patch.object(
                MODULE,
                "_bounded_command_stdout",
                return_value=stdout,
            ):
                return MODULE._findmnt_identity(
                    "/srv/archive",
                    "/srv",
                    expected_filesystem_type,
                    expected_major_minor,
                )

    def root_metadata(self):
        return os.stat_result(
            (stat.S_IFDIR | 0o700, 4321, 999, 1, 1000, 1000, 0, 0, 0, 0)
        )

    def top_level_fingerprint(self, digest="a" * 64):
        return {
            "schema": "protected-legacy-top-level-v1",
            "entry_count": 3,
            "metadata_sha256": digest,
        }

    def mount_record(
        self,
        mount_id,
        *,
        major_minor="8:2",
        root="/",
        mount_point="/srv",
        filesystem_type="ext4",
    ):
        return MODULE.MountInfoRecord(
            mount_id,
            1,
            major_minor,
            PurePosixPath(root),
            PurePosixPath(mount_point),
            filesystem_type,
        )

    def contract_entries(self, archive_root):
        """Build a complete static contract around one synthetic root."""

        return {
            "PROTECTED_SERVICES_REVIEWED": ["yes"],
            "PROTECTED_LEGACY_ARCHIVES_REVIEWED": ["yes"],
            "PROTECTED_LEGACY_ARCHIVES_PRESENT": ["yes"],
            "PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256": ["a" * 64],
            "PROTECTED_LEGACY_ARCHIVE_ROOT": [archive_root],
            "PROTECTED_LEGACY_ARCHIVE_BINDING_SHA256": ["b" * 64],
            MODULE.ACTIVATION_CLASS_KEY: sorted(MODULE.REQUIRED_ACTIVATION_CLASSES),
        }

    def test_archive_roots_use_a_narrow_operator_data_allowlist(self):
        """Home data remains valid while critical and package paths are rejected."""

        for archive_root in (
            "/home/operator/.bitcoin",
            "/srv/archive",
            "/mnt/archive",
            "/media/archive",
            "/opt/archive",
        ):
            with self.subTest(allowed_archive_root=archive_root):
                contract, errors = MODULE.validate_entries(
                    self.contract_entries(archive_root)
                )
                self.assertIsNotNone(contract)
                self.assertEqual(errors, [])

        for archive_root in (
            "/root/archive",
            "/var/lib/archive",
            "/var/lib/systemd/archive",
            "/var/lib/dpkg/archive",
            "/etc/archive",
            "/usr/local/archive",
            "/home/operator",
        ):
            with self.subTest(rejected_archive_root=archive_root):
                contract, errors = MODULE.validate_entries(
                    self.contract_entries(archive_root)
                )
                self.assertIsNone(contract)
                self.assertTrue(any("archive root 1" in error for error in errors))
                self.assertNotIn(archive_root, "\n".join(errors))

    def test_stable_ids_ignore_device_rename_and_options_are_sorted(self):
        """UUID identity, not reboot-dependent /dev naming, determines the digest."""

        first = self.findmnt_identity(
            findmnt_output(source="/dev/sda2[/archive]", options="rw,noatime")
        )
        renamed = self.findmnt_identity(
            findmnt_output(source="/dev/nvme0n1p2[/archive]", options="noatime,rw")
        )
        self.assertEqual(first, renamed)
        self.assertEqual(first["options"], ["noatime", "rw"])
        self.assertEqual(
            first["stable_ids"],
            {"uuid": "aabb-ccdd", "partuuid": "1234abcd-02"},
        )
        self.assertEqual(first["source_subpath"], "/archive")
        self.assertNotIn("source_fallback", first)
        self.assertEqual(
            MODULE._archive_binding_digest(
                self.root_metadata(), first, self.top_level_fingerprint()
            ),
            MODULE._archive_binding_digest(
                self.root_metadata(), renamed, self.top_level_fingerprint()
            ),
        )

    def test_changed_stable_id_changes_binding(self):
        """A different filesystem UUID cannot satisfy a previously reviewed binding."""

        expected = self.findmnt_identity(findmnt_output(filesystem_uuid="AAAA-BBBB"))
        replacement = self.findmnt_identity(findmnt_output(filesystem_uuid="CCCC-DDDD"))
        self.assertNotEqual(expected, replacement)
        self.assertNotEqual(
            MODULE._archive_binding_digest(
                self.root_metadata(), expected, self.top_level_fingerprint()
            ),
            MODULE._archive_binding_digest(
                self.root_metadata(), replacement, self.top_level_fingerprint()
            ),
        )

    def test_v3_payload_binds_root_and_top_level_without_device_number(self):
        """The payload binds retained metadata but never a volatile device number."""

        identity = self.findmnt_identity(findmnt_output())
        top_level = self.top_level_fingerprint()
        payload = MODULE._archive_binding_payload(
            self.root_metadata(), identity, top_level
        )
        self.assertEqual(payload["schema"], "protected-legacy-archive-binding-v3")
        self.assertEqual(
            payload["root"],
            {
                "inode": 4321,
                "uid": 1000,
                "gid": 1000,
                "mode": 0o700,
                "nlink": 1,
                "mtime_ns": None,
                "ctime_ns": None,
            },
        )
        self.assertEqual(payload["top_level"], top_level)
        self.assertNotIn("device", json.dumps(payload))

    def test_source_is_an_explicit_fallback_only_without_stable_ids(self):
        """Device source participates only when findmnt exposes no stable ID."""

        identity = self.findmnt_identity(
            findmnt_output(
                source="crypt-archive",
                filesystem_uuid=None,
                partition_uuid=None,
            )
        )
        self.assertEqual(identity["source_fallback"], "crypt-archive")
        self.assertNotIn("stable_ids", identity)

    def test_findmnt_requires_one_strict_bounded_record_and_timeout(self):
        """Malformed, ambiguous, oversized, or stalled findmnt output fails closed."""

        two_records = json.loads(findmnt_output().decode("utf-8"))
        two_records["filesystems"].append(dict(two_records["filesystems"][0]))
        self.assertIsNone(
            self.findmnt_identity(json.dumps(two_records).encode("utf-8"))
        )
        self.assertIsNone(
            self.findmnt_identity(b"x" * (MODULE.MAX_FINDMNT_BYTES + 1))
        )

        with mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/findmnt"):
            with mock.patch.object(
                MODULE,
                "_bounded_command_stdout",
                return_value=None,
            ) as bounded:
                self.assertIsNone(MODULE._findmnt_identity("/srv/archive", "/srv"))
        self.assertEqual(bounded.call_args.args[1], MODULE.MAX_FINDMNT_BYTES)
        self.assertEqual(
            bounded.call_args.args[2], MODULE.FINDMNT_TIMEOUT_SECONDS
        )
        self.assertIn("MAJ:MIN", bounded.call_args.args[0][-1])

    @unittest.skipUnless(os.name == "posix", "bounded process capture is POSIX-only")
    def test_bounded_command_capture_enforces_cap_before_completion(self):
        """The producer cannot force an unbounded in-memory stdout buffer."""

        cap = 4096
        exact = MODULE._bounded_command_stdout(
            [
                sys.executable,
                "-c",
                "import os; os.write(1, b'x' * {})".format(cap),
            ],
            cap,
            5,
        )
        oversized = MODULE._bounded_command_stdout(
            [
                sys.executable,
                "-c",
                "import os; os.write(1, b'x' * {})".format(cap + 1),
            ],
            cap,
            5,
        )
        many_small_writes = MODULE._bounded_command_stdout(
            [
                sys.executable,
                "-c",
                "import os; [os.write(1, b'x') for _ in range({})]".format(
                    cap + 1
                ),
            ],
            cap,
            5,
        )
        stalled_after_cap = MODULE._bounded_command_stdout(
            [
                sys.executable,
                "-c",
                "import os,time; os.write(1, b'x' * {}); time.sleep(30)".format(
                    cap
                ),
            ],
            cap,
            0.1,
        )
        self.assertEqual(exact, b"x" * cap)
        self.assertIsNone(oversized)
        self.assertIsNone(many_small_writes)
        self.assertIsNone(stalled_after_cap)
        self.assertIsNone(
            MODULE._bounded_command_stdout(
                [sys.executable, "-c", "raise SystemExit(7)"],
                cap,
                5,
            )
        )
        self.assertIsNone(
            MODULE._bounded_command_stdout(
                ["/definitely/missing/archive-validator-helper"],
                cap,
                5,
            )
        )

    @unittest.skipUnless(os.name == "posix", "process-group cleanup is POSIX-only")
    def test_bounded_command_kills_descendant_after_parent_exits(self):
        """A descendant retaining stdout is killed after its parent exits."""

        import fcntl

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            descendant_script = root / "descendant.py"
            wrapper_script = root / "wrapper.py"
            lock_path = root / "descendant.lock"
            pid_path = root / "descendant.pid"
            descendant_script.write_text(
                "import fcntl\n"
                "import os\n"
                "import pathlib\n"
                "import sys\n"
                "import time\n"
                "lock_handle = open(sys.argv[1], 'w', encoding='utf-8')\n"
                "fcntl.flock(lock_handle, fcntl.LOCK_EX)\n"
                "pathlib.Path(sys.argv[2]).write_text(str(os.getpid()), "
                "encoding='ascii')\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            wrapper_script.write_text(
                "import os\n"
                "import pathlib\n"
                "import subprocess\n"
                "import sys\n"
                "import time\n"
                "child = subprocess.Popen(\n"
                "    [sys.executable, sys.argv[1], sys.argv[2], sys.argv[3]],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=sys.stdout,\n"
                "    stderr=subprocess.DEVNULL,\n"
                "    close_fds=True,\n"
                ")\n"
                "deadline = time.monotonic() + 5\n"
                "while not pathlib.Path(sys.argv[3]).exists():\n"
                "    if time.monotonic() >= deadline:\n"
                "        child.kill()\n"
                "        raise SystemExit(8)\n"
                "    time.sleep(0.01)\n"
                "os._exit(0)\n",
                encoding="utf-8",
            )

            descendant_pid = None
            lock_acquired = False
            try:
                self.assertIsNone(
                    MODULE._bounded_command_stdout(
                        [
                            sys.executable,
                            str(wrapper_script),
                            str(descendant_script),
                            str(lock_path),
                            str(pid_path),
                        ],
                        16,
                        2,
                    )
                )
                self.assertTrue(pid_path.is_file())
                descendant_pid = int(pid_path.read_text(encoding="ascii"))
                with lock_path.open("a+", encoding="utf-8") as lock_handle:
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            fcntl.flock(
                                lock_handle,
                                fcntl.LOCK_EX | fcntl.LOCK_NB,
                            )
                            lock_acquired = True
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                break
                            time.sleep(0.01)
                    if lock_acquired:
                        fcntl.flock(lock_handle, fcntl.LOCK_UN)
                self.assertTrue(
                    lock_acquired,
                    "descendant retained its lock after bounded cleanup",
                )
            finally:
                if descendant_pid is not None:
                    try:
                        os.kill(descendant_pid, MODULE.signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_process_group_cleanup_signals_group_after_parent_exit(self):
        """A reaped-looking parent cannot suppress descendant group cleanup."""

        process = mock.Mock()
        process.poll.return_value = 0
        process.wait.return_value = 0
        with mock.patch.object(
            MODULE.os,
            "getpgrp",
            return_value=4321,
            create=True,
        ):
            with mock.patch.object(MODULE.signal, "SIGKILL", 9, create=True):
                with mock.patch.object(
                    MODULE.os,
                    "killpg",
                    create=True,
                ) as kill_group:
                    MODULE._terminate_process_group(process, 4322)
        kill_group.assert_called_once_with(4322, 9)
        process.kill.assert_not_called()

    def test_process_group_cleanup_never_signals_callers_group(self):
        """The defensive group guard falls back to killing only the helper."""

        process = mock.Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        with mock.patch.object(
            MODULE.os,
            "getpgrp",
            return_value=4321,
            create=True,
        ):
            with mock.patch.object(
                MODULE.os,
                "killpg",
                create=True,
            ) as kill_group:
                MODULE._terminate_process_group(process, 4321)
        kill_group.assert_not_called()
        process.kill.assert_called_once_with()

    def test_bounded_capture_source_has_no_unbounded_convenience_reader(self):
        """The security cap is enforced while reading, not after buffering."""

        source = inspect.getsource(MODULE._bounded_command_stdout)
        self.assertNotIn("subprocess.run", source)
        self.assertNotIn(".communicate(", source)
        self.assertIn("max_bytes + 1 - len(captured)", source)

    def test_findmnt_rejects_unsafe_or_disagreeing_filesystem_type(self):
        """Mountinfo and findmnt must agree on a durable supported filesystem."""

        for filesystem_type in ("tmpfs", "nfs", "nfs4", "cifs", "fuse.sshfs"):
            with self.subTest(filesystem_type=filesystem_type):
                self.assertIsNone(
                    self.findmnt_identity(
                        findmnt_output(filesystem_type=filesystem_type),
                        expected_filesystem_type=filesystem_type,
                    )
                )
        self.assertIsNone(
            self.findmnt_identity(
                findmnt_output(),
                expected_filesystem_type="xfs",
            )
        )

    def test_findmnt_device_must_match_the_opened_archive_descriptor(self):
        """findmnt cannot describe a different device than the held archive FD."""

        self.assertIsNone(
            self.findmnt_identity(
                findmnt_output(major_minor="8:3"),
                expected_major_minor="8:2",
            )
        )
        identity = self.findmnt_identity(
            findmnt_output(major_minor="8:2"),
            expected_major_minor="8:2",
        )
        self.assertIsNotNone(identity)
        self.assertNotIn("major_minor", identity)

    def test_findmnt_rejects_duplicate_json_keys_and_target_mismatch(self):
        """Parser ambiguity and disagreement with mountinfo cannot enter a binding."""

        duplicate = (
            b'{"filesystems":[{"target":"/srv","target":"/",'
            b'"source":"/dev/sda2","fstype":"ext4","options":"rw",'
            b'"uuid":"aaaa","partuuid":null,"maj:min":"8:2"}]}'
        )
        self.assertIsNone(self.findmnt_identity(duplicate))
        self.assertIsNone(self.findmnt_identity(findmnt_output(target="/")))

    def test_descendant_and_stacked_mounts_are_rejected(self):
        """A hidden dataset or same-target overmount makes the root ambiguous."""

        descendant_target, descendant_errors = MODULE._mount_target_from_points(
            "/srv/archive",
            (PurePosixPath("/"), PurePosixPath("/srv/archive/data")),
        )
        self.assertIsNone(descendant_target)
        self.assertTrue(any("descendant" in item for item in descendant_errors))

        stacked_target, stacked_errors = MODULE._mount_target_from_points(
            "/srv/archive",
            (PurePosixPath("/"), PurePosixPath("/srv"), PurePosixPath("/srv")),
        )
        self.assertIsNone(stacked_target)
        self.assertTrue(any("stacked" in item for item in stacked_errors))

    def test_unambiguous_deepest_containing_mount_is_selected(self):
        """The archive binds to the one deepest mount that contains its root."""

        selected, errors = MODULE._mount_target_from_points(
            "/srv/archive",
            (PurePosixPath("/"), PurePosixPath("/srv"), PurePosixPath("/var")),
        )
        self.assertEqual(errors, ())
        self.assertEqual(selected, "/srv")

    def test_external_bind_aliases_of_archive_storage_are_rejected(self):
        """Exact, ancestor, and descendant aliases expose retained data elsewhere."""

        selected = self.mount_record(10)
        for root in ("/archive", "/", "/archive/blocks"):
            with self.subTest(root=root):
                alias = self.mount_record(
                    11,
                    root=root,
                    mount_point="/external-alias",
                )
                record, errors = MODULE._mount_record_from_records(
                    "/srv/archive",
                    (selected, alias),
                )
                self.assertIsNone(record)
                self.assertTrue(any("external mount alias" in item for item in errors))

        unrelated = self.mount_record(
            12,
            root="/different-tree",
            mount_point="/unrelated",
        )
        record, errors = MODULE._mount_record_from_records(
            "/srv/archive",
            (selected, unrelated),
        )
        self.assertEqual(record, selected)
        self.assertEqual(errors, ())

        other_device = self.mount_record(
            13,
            major_minor="9:1",
            root="/archive",
            mount_point="/different-device",
        )
        record, errors = MODULE._mount_record_from_records(
            "/srv/archive",
            (selected, other_device),
        )
        self.assertEqual(record, selected)
        self.assertEqual(errors, ())

    def test_only_explicitly_reviewed_local_filesystems_are_accepted(self):
        """Network, FUSE, volatile, and synthetic filesystems all fail closed."""

        for filesystem_type in (
            "tmpfs",
            "overlay",
            "proc",
            "nfs",
            "nfs4",
            "cifs",
            "fuse.sshfs",
        ):
            with self.subTest(filesystem_type=filesystem_type):
                record, errors = MODULE._mount_record_from_records(
                    "/srv/archive",
                    (
                        self.mount_record(
                            10,
                            filesystem_type=filesystem_type,
                        ),
                    ),
                )
                self.assertIsNone(record)
                self.assertTrue(any("unsupported" in item for item in errors))

        for filesystem_type in sorted(MODULE.ALLOWED_ARCHIVE_FILESYSTEM_TYPES):
            with self.subTest(allowed_filesystem_type=filesystem_type):
                selected = self.mount_record(
                    10,
                    filesystem_type=filesystem_type,
                )
                record, errors = MODULE._mount_record_from_records(
                    "/srv/archive",
                    (selected,),
                )
                self.assertEqual(record, selected)
                self.assertEqual(errors, ())

    def test_mountinfo_parser_preserves_roots_and_rejects_ambiguity(self):
        """Alias detection receives strict IDs, devices, roots, and mount targets."""

        raw = (
            b"36 25 8:2 / /srv rw,relatime - ext4 /dev/sda2 rw\n"
            b"37 25 8:2 /archive /backup rw,relatime - ext4 /dev/sda2 rw\n"
        )
        records = MODULE._parse_mountinfo_bytes(raw)
        self.assertIsNotNone(records)
        self.assertEqual(records[1].root, PurePosixPath("/archive"))
        self.assertEqual(records[1].mount_point, PurePosixPath("/backup"))
        self.assertEqual(records[1].major_minor, "8:2")
        self.assertIsNone(
            MODULE._parse_mountinfo_bytes(raw.replace(b"37 25", b"36 25"))
        )
        self.assertIsNone(
            MODULE._parse_mountinfo_bytes(
                raw.replace(b"/archive /backup", b"/archive\\999 /backup")
            )
        )
        self.assertIsNone(
            MODULE._parse_mountinfo_bytes(
                raw.replace(b"/archive /backup", b"/archive\\011child /backup")
            )
        )

    def test_non_host_mount_namespace_fails_before_mountinfo_read(self):
        """A container/private namespace cannot certify the host archive view."""

        with mock.patch.object(MODULE, "_host_mount_namespace_matches", return_value=False):
            with mock.patch.object(MODULE, "_read_mountinfo") as read_mountinfo:
                target, errors = MODULE._archive_mount_target("/srv/archive")
        self.assertIsNone(target)
        self.assertTrue(any("host mount namespace" in item for item in errors))
        read_mountinfo.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "directory-fd metadata is POSIX-only")
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_top_level_sentinel_is_bounded_nonempty_and_change_sensitive(self):
        """Immediate metadata proves retained data exists without reading contents."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory) / "archive"
            root.mkdir(mode=0o700)

            def fingerprint():
                opened = MODULE._open_archive_directory_no_follow(str(root))
                self.assertIsNotNone(opened)
                try:
                    return MODULE._archive_top_level_fingerprint(opened.descriptor)
                finally:
                    MODULE._close_opened_archive_directory(opened)

            self.assertIsNone(fingerprint())

            private_name = "private-retained-name"
            retained = root / private_name
            retained.write_bytes(b"contents-are-never-read")
            with mock.patch.object(MODULE.os, "open", wraps=os.open) as opened:
                first = fingerprint()
            self.assertIsNotNone(first)
            self.assertGreater(opened.call_count, 1)
            self.assertEqual(opened.call_args_list[0].args[0], "/")
            self.assertEqual(opened.call_args_list[-1].args[0], root.name)
            self.assertNotIn(
                str(root),
                [call.args[0] for call in opened.call_args_list],
            )
            self.assertEqual(first["entry_count"], 1)
            self.assertNotIn(private_name, json.dumps(first))

            renamed = root / "renamed-retained-entry"
            retained.rename(renamed)
            second = fingerprint()
            self.assertNotEqual(first, second)

            renamed.write_bytes(b"metadata-change")
            third = fingerprint()
            self.assertNotEqual(second, third)

            link = root / "external-link"
            link.symlink_to(Path(directory))
            self.assertIsNone(fingerprint())
            link.unlink()

            for index in range(MODULE.MAX_ARCHIVE_TOP_LEVEL_ENTRIES - 1):
                (root / "bounded-{:03d}".format(index)).touch()
            at_limit = fingerprint()
            self.assertIsNotNone(at_limit)
            self.assertEqual(
                at_limit["entry_count"], MODULE.MAX_ARCHIVE_TOP_LEVEL_ENTRIES
            )
            (root / "overflow").touch()
            self.assertIsNone(fingerprint())

    @unittest.skipUnless(os.name == "posix", "live binding metadata is POSIX-only")
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_binding_rechecks_mount_topology_and_root_device(self):
        """A mount replacement during fingerprinting cannot yield a binding."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory) / "archive"
            root.mkdir(mode=0o700)
            (root / "retained").mkdir()
            metadata = root.lstat()
            device = "{}:{}".format(os.major(metadata.st_dev), os.minor(metadata.st_dev))
            record = self.mount_record(
                10,
                major_minor=device,
                mount_point="/",
            )
            replacement = self.mount_record(
                11,
                major_minor=device,
                mount_point="/",
            )
            identity = {
                "filesystem_type": "ext4",
                "options": ["noatime", "rw"],
                "target": "/",
                "stable_ids": {"uuid": "aabb"},
            }
            with mock.patch.object(
                MODULE,
                "_archive_mount_record",
                side_effect=[(record, ()), (replacement, ())],
            ):
                with mock.patch.object(
                    MODULE,
                    "_findmnt_identity",
                    return_value=identity,
                ):
                    self.assertIsNone(MODULE.archive_binding_fingerprint(str(root)))

            with mock.patch.object(
                MODULE,
                "_archive_mount_record",
                side_effect=[(record, ()), (record, ())],
            ):
                with mock.patch.object(
                    MODULE,
                    "_findmnt_identity",
                    return_value=identity,
                ) as findmnt_identity:
                    binding = MODULE.archive_binding_fingerprint(str(root))
            self.assertRegex(binding or "", r"^[0-9a-f]{64}$")
            self.assertEqual(findmnt_identity.call_count, 2)
            self.assertEqual(
                [call.args[3] for call in findmnt_identity.call_args_list],
                [device, device],
            )

            wrong_device = record._replace(major_minor="999:999")
            with mock.patch.object(
                MODULE,
                "_archive_mount_record",
                return_value=(wrong_device, ()),
            ):
                issues = MODULE.archive_root_issues(str(root))
            self.assertTrue(any("mount device" in item for item in issues))

    @unittest.skipUnless(os.name == "posix", "path-swap proof is POSIX-only")
    def test_binding_rejects_parent_rename_to_same_inode_symlink_race(self):
        """A swapped parent cannot pass merely because it resolves to the held inode."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            container = Path(directory)
            parent = container / "parent"
            parent.mkdir(mode=0o700)
            root = parent / "archive"
            root.mkdir(mode=0o700)
            (root / "retained").touch()

            metadata = root.lstat()
            device = "{}:{}".format(os.major(metadata.st_dev), os.minor(metadata.st_dev))
            record = self.mount_record(
                10,
                major_minor=device,
                mount_point="/",
            )
            identity = {
                "filesystem_type": "ext4",
                "options": ["rw"],
                "target": "/",
                "stable_ids": {"uuid": "aabb"},
            }
            original_fingerprint = MODULE._archive_top_level_fingerprint
            displaced = container / "displaced-parent"

            def fingerprint_then_swap(descriptor):
                fingerprint = original_fingerprint(descriptor)
                parent.rename(displaced)
                parent.symlink_to(displaced, target_is_directory=True)
                return fingerprint

            with mock.patch.object(
                MODULE,
                "_archive_mount_record",
                return_value=(record, ()),
            ):
                with mock.patch.object(
                    MODULE,
                    "_findmnt_identity",
                    return_value=identity,
                ):
                    with mock.patch.object(
                        MODULE,
                        "_archive_top_level_fingerprint",
                        side_effect=fingerprint_then_swap,
                    ):
                        self.assertIsNone(
                            MODULE.archive_binding_fingerprint(str(root))
                        )

    def test_namespace_identity_compares_proc_self_with_proc_one(self):
        """Namespace proof uses the namespace inode and rejects any mismatch."""

        matching = [mock.Mock(st_dev=4, st_ino=99), mock.Mock(st_dev=4, st_ino=99)]
        with mock.patch.object(MODULE.os, "stat", side_effect=matching) as stat_probe:
            self.assertTrue(MODULE._host_mount_namespace_matches())
        self.assertEqual(
            [call.args[0] for call in stat_probe.call_args_list],
            ["/proc/self/ns/mnt", "/proc/1/ns/mnt"],
        )

        different = [mock.Mock(st_dev=4, st_ino=99), mock.Mock(st_dev=4, st_ino=100)]
        with mock.patch.object(MODULE.os, "stat", side_effect=different):
            self.assertFalse(MODULE._host_mount_namespace_matches())


if __name__ == "__main__":
    unittest.main()
