"""Behavioral hostile cases for the selector image rootfs validator."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/ci/validate_selector_rootfs.py"
SPEC = importlib.util.spec_from_file_location("selector_rootfs_validator", VALIDATOR)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load selector rootfs validator")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SelectorRootfsValidatorTests(unittest.TestCase):
    def make_archive(
        self,
        path: Path,
        *,
        duplicate: str | None = None,
        omit: str | None = None,
        mode_changes: dict[str, int] | None = None,
        share_type: bytes = tarfile.DIRTYPE,
        sigstore_type: bytes = tarfile.DIRTYPE,
        root_type: bytes = tarfile.REGTYPE,
        root_bytes: bytes | None = None,
    ) -> None:
        if root_bytes is None:
            root_bytes = (
                ROOT / "cmd/platform-release-selector/trusted_root.json"
            ).read_bytes()
        entries = [
            ("usr/local/share", 0o555, share_type, b""),
            ("usr/local/share/sigstore", 0o555, sigstore_type, b""),
            (
                "usr/local/share/sigstore/trusted_root.json",
                0o444,
                root_type,
                root_bytes,
            ),
        ]
        entries = [entry for entry in entries if entry[0] != omit]
        if mode_changes:
            entries = [
                (name, mode_changes.get(name, mode), member_type, data)
                for name, mode, member_type, data in entries
            ]
        if duplicate is not None:
            entries.append(next(entry for entry in entries if entry[0] == duplicate))
        with tarfile.open(path, mode="w") as archive:
            for name, mode, member_type, data in entries:
                member = tarfile.TarInfo(name)
                member.mode = mode
                member.type = member_type
                if member_type == tarfile.REGTYPE:
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                else:
                    archive.addfile(member)

    def validate_fixture(self, **changes) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "rootfs.tar"
            self.make_archive(archive, **changes)
            MODULE.validate_rootfs(archive)

    def test_exact_tree_passes(self):
        self.validate_fixture()

    def test_duplicate_target_member_fails_closed(self):
        with self.assertRaisesRegex(MODULE.RootfsValidationError, "duplicate"):
            self.validate_fixture(duplicate="usr/local/share/sigstore")

    def test_missing_target_member_fails_closed(self):
        with self.assertRaisesRegex(MODULE.RootfsValidationError, "incomplete"):
            self.validate_fixture(omit="usr/local/share/sigstore")

    def test_each_non_directory_parent_fails_closed(self):
        for changes in (
            {"share_type": tarfile.REGTYPE},
            {"sigstore_type": tarfile.REGTYPE},
        ):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(
                    MODULE.RootfsValidationError, "directories"
                ):
                    self.validate_fixture(**changes)

    def test_non_regular_trusted_root_fails_closed(self):
        with self.assertRaisesRegex(MODULE.RootfsValidationError, "regular file"):
            self.validate_fixture(root_type=tarfile.SYMTYPE)

    def test_each_wrong_mode_fails_closed(self):
        for name, mode in MODULE.EXPECTED_MODES.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(MODULE.RootfsValidationError, "mode"):
                    self.validate_fixture(mode_changes={name: mode ^ 0o100})

    def test_wrong_trusted_root_content_fails_closed(self):
        with self.assertRaisesRegex(MODULE.RootfsValidationError, "hash drifted"):
            self.validate_fixture(root_bytes=b"foreign trusted root")


if __name__ == "__main__":
    unittest.main()
