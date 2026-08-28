#!/usr/bin/env python3
"""Validate the trusted-root files in an exported selector image filesystem."""

from __future__ import annotations

import hashlib
import sys
import tarfile
from pathlib import Path


EXPECTED_MODES = {
    "usr/local/share": 0o555,
    "usr/local/share/sigstore": 0o555,
    "usr/local/share/sigstore/trusted_root.json": 0o444,
}
EXPECTED_TRUSTED_ROOT_SHA256 = (
    "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
)


class RootfsValidationError(ValueError):
    """The selector filesystem archive violates its trusted-root contract."""


def validate_rootfs(path: Path) -> None:
    """Fail closed unless one exact, traversable trusted-root tree is present."""
    try:
        with tarfile.open(path, mode="r:") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                name = member.name.removeprefix("./").rstrip("/")
                if name not in EXPECTED_MODES:
                    continue
                if name in members:
                    raise RootfsValidationError(
                        "duplicate selector rootfs member: " + name
                    )
                members[name] = member
            if set(members) != set(EXPECTED_MODES):
                raise RootfsValidationError(
                    "selector trusted-root inventory is incomplete"
                )
            for name, expected_mode in EXPECTED_MODES.items():
                if members[name].mode & 0o7777 != expected_mode:
                    raise RootfsValidationError(
                        "unexpected selector rootfs mode: " + name
                    )
            if not members["usr/local/share"].isdir() or not members[
                "usr/local/share/sigstore"
            ].isdir():
                raise RootfsValidationError(
                    "selector trusted-root parents must be directories"
                )
            root = members["usr/local/share/sigstore/trusted_root.json"]
            if not root.isfile():
                raise RootfsValidationError(
                    "selector trusted root must be a regular file"
                )
            stream = archive.extractfile(root)
            if stream is None or hashlib.sha256(stream.read()).hexdigest() != (
                EXPECTED_TRUSTED_ROOT_SHA256
            ):
                raise RootfsValidationError(
                    "selector trusted-root content hash drifted"
                )
    except (OSError, tarfile.TarError) as exc:
        raise RootfsValidationError(
            "cannot read selector rootfs archive: " + str(exc)
        ) from exc


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        raise RootfsValidationError("usage: validate_selector_rootfs.py ROOTFS_TAR")
    validate_rootfs(Path(arguments[0]))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except RootfsValidationError as exc:
        raise SystemExit(str(exc)) from exc
