#!/usr/bin/env python3
"""Validate protected SOPS configuration and ciphertext snapshots offline."""

from __future__ import annotations

import importlib.util
import os
import re
import stat
import sys
from pathlib import Path
from types import ModuleType


SOPS_CONFIG_SNAPSHOT_ENV = "SOPS_CONFIG_SNAPSHOT_FILE"
SOPS_CIPHERTEXT_SNAPSHOT_ENV = "SOPS_CIPHERTEXT_SNAPSHOT_FILE"
MAX_SNAPSHOT_BYTES = 256 * 1024


class SnapshotError(ValueError):
    """Represent every invalid snapshot without exposing protected details."""


# One domain failure type parameterizes the shared no-follow walk helpers.
# The four private-file validators carry byte-identical copies of the helper
# family (pinned by tests/security/test_nofollow_helper_drift.py); fix any
# defect in every copy in the same change.
_WALK_ERROR = SnapshotError


def _path_state(metadata: os.stat_result) -> tuple[int, ...]:
    """Bind a path entry and open descriptor to all stable custody metadata."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        getattr(metadata, "st_uid", -1),
        getattr(metadata, "st_gid", -1),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        getattr(metadata, "st_file_attributes", 0),
        getattr(metadata, "st_reparse_tag", 0),
    )


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    """Treat POSIX links and Windows reparse points as path indirection."""

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def _ancestor_state(metadata: os.stat_result) -> tuple[int, ...]:
    """Bind an ancestor DIRECTORY to the fields that identify that directory.

    A directory's st_nlink, st_size, st_mtime_ns and st_ctime_ns describe its
    CONTENTS, not this path: every one of them changes when an unrelated
    process creates or removes some other entry inside it. Snapshotting them
    made the walk refuse a completely stable path whenever a sibling process
    touched a shared ancestor -- and the per-user temporary root is a shared
    ancestor of every private file staged under it, so one concurrent
    ``mkdtemp`` anywhere on the machine turned a valid read into a fail-closed
    refusal. That is issue #158's transient class, measured on an untouched
    path as st_nlink 5372 -> 5373 with st_dev/st_ino/st_mode/st_uid/st_gid
    unchanged.

    Nothing a path-substitution attack must do is dropped. st_dev and st_ino
    identify the directory itself, so replacing it fails; st_mode carries the
    type bits, so swapping it for a file or a symlink fails (and
    ``_is_link_or_reparse`` refuses the symlink outright before this runs);
    st_uid/st_gid catch a concurrent chown; the Windows attribute and reparse
    fields keep the reparse-point decision intact. The FINAL component keeps
    the complete ``_path_state`` tuple, and the read window is separately
    bound to the open descriptor and to its own parent directory handle, so
    no field removed here was the only witness to anything.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        getattr(metadata, "st_uid", -1),
        getattr(metadata, "st_gid", -1),
        getattr(metadata, "st_file_attributes", 0),
        getattr(metadata, "st_reparse_tag", 0),
    )


def _path_chain(path: Path) -> tuple[tuple[str, tuple[int, ...]], ...]:
    """Snapshot every ancestor so directory replacement cannot pass silently."""

    result: list[tuple[str, tuple[int, ...]]] = []
    components = (*reversed(path.parents), path)
    for position, component in enumerate(components):
        metadata = component.lstat()
        if _is_link_or_reparse(metadata):
            raise _WALK_ERROR()
        state = (
            _path_state(metadata)
            if position == len(components) - 1
            else _ancestor_state(metadata)
        )
        result.append((os.path.normcase(str(component)), state))
    return tuple(result)


def _open_posix_no_follow(path: Path, flags: int) -> tuple[int, int, str]:
    """Traverse an absolute POSIX path through no-follow directory handles."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        os.name != "posix"
        or nofollow is None
        or directory is None
        or os.open not in os.supports_dir_fd
        or not path.is_absolute()
        or not path.name
    ):
        raise _WALK_ERROR()
    directory_flags = os.O_RDONLY | nofollow | directory
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    parent_descriptor = os.open("/", directory_flags)
    try:
        for component in path.parts[1:-1]:
            if component in {"", ".", ".."}:
                raise _WALK_ERROR()
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        descriptor = os.open(path.name, flags | nofollow, dir_fd=parent_descriptor)
    except BaseException:
        os.close(parent_descriptor)
        raise
    return descriptor, parent_descriptor, path.name


def _canonical_path(path_text: str) -> Path:
    """Accept only one absolute, normalized path with no linked component."""

    if (
        not path_text
        or "\x00" in path_text
        or any(ord(character) < 32 for character in path_text)
    ):
        raise SnapshotError()
    supplied = Path(path_text)
    if (
        not supplied.is_absolute()
        or any(part in {".", ".."} for part in supplied.parts)
        or os.path.normcase(path_text) != os.path.normcase(str(supplied))
    ):
        raise SnapshotError()
    if os.name == "nt":
        if re.match(r"^[A-Za-z]:[\\/]", path_text) is None:
            raise SnapshotError()
        if any(":" in part or part.endswith((" ", ".")) for part in supplied.parts[1:]):
            raise SnapshotError()
    absolute = Path(os.path.abspath(os.path.normpath(str(supplied))))
    if os.path.normcase(str(absolute)) != os.path.normcase(str(supplied)):
        raise SnapshotError()
    try:
        resolved = absolute.resolve(strict=True)
        _path_chain(absolute)
    except (OSError, RuntimeError, SnapshotError) as error:
        raise SnapshotError() from error
    if os.path.normcase(str(resolved)) != os.path.normcase(str(absolute)):
        raise SnapshotError()
    return absolute


def read_snapshot(path_text: str) -> bytes:
    """Read one private file while binding bytes to its stable directory entry."""

    path = _canonical_path(path_text)
    try:
        before_chain = _path_chain(path)
        before = path.lstat()
    except (OSError, SnapshotError) as error:
        raise SnapshotError() from error
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_link_or_reparse(before)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_SNAPSHOT_BYTES
    ):
        raise SnapshotError()
    if os.name == "posix" and (
        before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
    ):
        raise SnapshotError()

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor: int | None = None
    final_name: str | None = None
    try:
        if os.name == "posix":
            descriptor, parent_descriptor, final_name = _open_posix_no_follow(
                path, flags
            )
        else:
            descriptor = os.open(str(path), flags)
        try:
            opened_before = os.fstat(descriptor)
            parent_before = (
                os.fstat(parent_descriptor)
                if parent_descriptor is not None
                else None
            )
            if _path_state(opened_before) != _path_state(before):
                raise SnapshotError()
            chunks: list[bytes] = []
            remaining = MAX_SNAPSHOT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            opened_after = os.fstat(descriptor)
            if parent_descriptor is not None and final_name is not None:
                parent_after = os.fstat(parent_descriptor)
                directory_entry = os.stat(
                    final_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    parent_before is None
                    or _path_state(parent_before) != _path_state(parent_after)
                    or _path_state(directory_entry) != _path_state(opened_after)
                ):
                    raise SnapshotError()
        finally:
            os.close(descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)
    except SnapshotError:
        raise
    except OSError as error:
        raise SnapshotError() from error

    if (
        _path_state(opened_before) != _path_state(opened_after)
        or opened_after.st_size != len(raw)
        or len(raw) > MAX_SNAPSHOT_BYTES
    ):
        raise SnapshotError()
    try:
        after_chain = _path_chain(path)
        after = path.lstat()
        final_resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, SnapshotError) as error:
        raise SnapshotError() from error
    if (
        before_chain != after_chain
        or _path_state(after) != _path_state(opened_after)
        or os.path.normcase(str(final_resolved)) != os.path.normcase(str(path))
    ):
        raise SnapshotError()
    return raw


def _canonical_text(raw: bytes) -> str:
    """Decode canonical LF-terminated UTF-8 without normalizing protected bytes."""

    if not raw or len(raw) > MAX_SNAPSHOT_BYTES or not raw.endswith(b"\n"):
        raise SnapshotError()
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise SnapshotError() from error
    if text.startswith("\ufeff") or any(
        (ord(character) < 32 and character != "\n")
        or 127 <= ord(character) <= 159
        or ord(character) in {0x2028, 0x2029}
        for character in text
    ):
        raise SnapshotError()
    if any(
        re.fullmatch(r"[ ]*(?:---|[.][.][.])(?:[ ]+#.*)?", line)
        for line in text.split("\n")
    ):
        raise SnapshotError()
    return text


def _load_transition_module() -> ModuleType:
    """Load the reviewed sibling grammar by absolute path, never ambient import."""

    script = Path(__file__).resolve().with_name("validate_release_transition.py")
    specification = importlib.util.spec_from_file_location(
        "_website_infrastructure_sops_snapshot_grammar", script
    )
    if specification is None or specification.loader is None:
        raise SnapshotError()
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    recipient_parser = getattr(module, "sops_recipient_from_config", None)
    secret_validator = getattr(module, "tunnel_secret_errors", None)
    if not callable(recipient_parser) or not callable(secret_validator):
        raise SnapshotError()
    return module


def parse_snapshots(config_raw: bytes, ciphertext_raw: bytes) -> None:
    """Require one configured hybrid-PQ recipient and its exact Tunnel Secret."""

    grammar = _load_transition_module()
    try:
        recipient = grammar.sops_recipient_from_config(_canonical_text(config_raw))
        if recipient is None:
            raise SnapshotError()
        errors = grammar.tunnel_secret_errors(
            _canonical_text(ciphertext_raw), recipient
        )
    except SnapshotError:
        raise
    except Exception as error:
        raise SnapshotError() from error
    if errors:
        raise SnapshotError()


def validate() -> None:
    """Read both environment-selected snapshots and validate only in memory."""

    config_path = os.environ.get(SOPS_CONFIG_SNAPSHOT_ENV, "")
    ciphertext_path = os.environ.get(SOPS_CIPHERTEXT_SNAPSHOT_ENV, "")
    config_raw = read_snapshot(config_path)
    ciphertext_raw = read_snapshot(ciphertext_path)
    parse_snapshots(config_raw, ciphertext_raw)


def main(argv: list[str] | None = None) -> int:
    """Expose one content-neutral result and no argument-based input surface."""

    arguments = sys.argv[1:] if argv is None else argv
    try:
        if (
            arguments
            or sys.flags.isolated != 1
            or sys.flags.dont_write_bytecode != 1
        ):
            raise SnapshotError()
        validate()
    except Exception:
        print("FAIL SOPS ciphertext snapshot validation.", file=sys.stderr)
        return 1
    print("PASS SOPS ciphertext snapshot validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
