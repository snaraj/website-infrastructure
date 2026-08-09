#!/usr/bin/env python3
"""Validate the private protected-host contract without echoing identities."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import posixpath
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Callable, NamedTuple


# This public schema describes roles only. Exact paths and unit names remain in
# the ignored mode-0600 local file and are never included in diagnostics.
REVIEW_KEYS = {
    "PROTECTED_SERVICES_REVIEWED",
    "PROTECTED_LEGACY_ARCHIVES_REVIEWED",
}
PRESENCE_KEY = "PROTECTED_LEGACY_ARCHIVES_PRESENT"
ACTIVATION_CLASS_KEY = "PROTECTED_LEGACY_ACTIVATION_CLASS_REVIEWED"
RUNTIME_EVIDENCE_HASH_KEY = "PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256"
RUNTIME_EVIDENCE_SCHEMA = "protected-legacy-host-review-v2"
RUNTIME_EVIDENCE_PRESENCE_FIELD = "LEGACY_ARCHIVES_PRESENT"
RUNTIME_EVIDENCE_VALIDATOR_API_VERSION = "protected-legacy-runtime-evidence-api-v1"
REQUIRED_ACTIVATION_CLASSES = {
    "containers",
    "package-activation",
    "runtime-exposure",
    "scheduled-autostart",
    "system-manager-units",
    "user-manager-units",
}
REPEATED_KEYS = {
    "PROTECTED_SYSTEMD_UNIT",
    "PROTECTED_LEGACY_ARCHIVE_ROOT",
    "PROTECTED_LEGACY_ARCHIVE_BINDING_SHA256",
    "PROTECTED_LEGACY_SYSTEMD_UNIT",
    ACTIVATION_CLASS_KEY,
}
ALLOWED_KEYS = REVIEW_KEYS | {
    PRESENCE_KEY,
    RUNTIME_EVIDENCE_HASH_KEY,
} | REPEATED_KEYS
ACTIVE_UNIT_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@-]*[.]service\Z")
LEGACY_UNIT_RE = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_.:@-]*[.](?:service|socket|timer|path)\Z"
)
ARCHIVE_ROOT_RE = re.compile(r"/[A-Za-z0-9_@+~.-]+(?:/[A-Za-z0-9_@+~.-]+)*\Z")
BINDING_RE = re.compile(r"[0-9a-f]{64}\Z")

# A declared root must live under one of the deliberately narrow operator-data
# hierarchies below. The minimum part count includes the leading ``/`` part, so
# a home archive must be at least /home/<user>/<dedicated-root>, while the other
# hierarchies require one dedicated child. This allowlist keeps archives out of
# /root, package/service state below /var, and every executable/configuration
# hierarchy without trying to enumerate all dangerous descendants.
ALLOWED_ARCHIVE_ROOT_PREFIX_PARTS = {
    "home": 4,
    "media": 3,
    "mnt": 3,
    "opt": 3,
    "srv": 3,
}

# Only local filesystems with durable on-disk semantics and native Unix access
# controls may carry a protected archive. Unknown/new types fail closed until
# their storage and identity behavior receives explicit review. In particular,
# network filesystems and FUSE implementations are intentionally absent.
ALLOWED_ARCHIVE_FILESYSTEM_TYPES = {
    "btrfs",
    "ext4",
    "f2fs",
    "xfs",
    "zfs",
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAX_CONTRACT_BYTES = 65536
MAX_CONTRACT_ENTRIES = 256
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
MAX_MOUNTINFO_LINES = 8192
MAX_FINDMNT_BYTES = 64 * 1024
FINDMNT_TIMEOUT_SECONDS = 10
MAX_ARCHIVE_TOP_LEVEL_ENTRIES = 256
MAX_ARCHIVE_TOP_LEVEL_MANIFEST_BYTES = 2 * 1024 * 1024


class ProtectedHostContract(NamedTuple):
    """Statically validated identities grouped by their required host state."""

    active_units: tuple[str, ...]
    legacy_archives_present: bool
    runtime_evidence_sha256: str | None
    archive_roots: tuple[str, ...]
    archive_bindings: tuple[str, ...]
    legacy_units: tuple[str, ...]
    activation_classes: tuple[str, ...]


class UnitState(NamedTuple):
    """Exact system-manager state without collapsing errors into safe values."""

    load_state: str | None
    active_state: str | None
    unit_file_state: str | None
    control_group: str | None


class MountInfoRecord(NamedTuple):
    """Mount topology fields used only for current-host ambiguity checks."""

    mount_id: int
    parent_id: int
    major_minor: str
    root: PurePosixPath
    mount_point: PurePosixPath
    filesystem_type: str


class OpenedArchiveDirectory(NamedTuple):
    """Descriptors retaining an archive root and its immediate parent."""

    descriptor: int
    parent_descriptor: int
    basename: str


def _duplicates(values: tuple[str, ...], label: str) -> list[str]:
    """Return indexed duplicate errors without disclosing any repeated value."""

    errors: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(values, start=1):
        if value in seen:
            errors.append(f"{label} {index} duplicates an earlier declaration")
        seen.add(value)
    return errors


def _is_relative_to(path: Path, parent: Path) -> bool:
    """Backport Path.is_relative_to so the validator works on Python 3.8."""

    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_entries(
    entries: dict[str, list[str]],
    *,
    allow_missing_bindings: bool = False,
    allow_unreviewed: bool = False,
) -> tuple[ProtectedHostContract | None, list[str]]:
    """Validate the closed public schema independently from live host state."""

    errors: list[str] = []
    entry_count = sum(len(values) for values in entries.values())
    if entry_count > MAX_CONTRACT_ENTRIES:
        errors.append("protected-host contract has too many declarations")
    for key in sorted(REVIEW_KEYS):
        values = entries.get(key, [])
        allowed = {"yes", "no"} if allow_unreviewed else {"yes"}
        if len(values) != 1 or values[0] not in allowed:
            expectation = "equal yes or no" if allow_unreviewed else "equal yes"
            errors.append(f"{key} must occur exactly once and {expectation}")

    presence_values = entries.get(PRESENCE_KEY, [])
    if len(presence_values) != 1 or presence_values[0] not in {"yes", "no"}:
        errors.append(f"{PRESENCE_KEY} must occur exactly once and equal yes or no")
        legacy_archives_present = False
    else:
        legacy_archives_present = presence_values[0] == "yes"

    runtime_evidence_values = entries.get(RUNTIME_EVIDENCE_HASH_KEY, [])
    runtime_evidence_sha256 = (
        runtime_evidence_values[0] if len(runtime_evidence_values) == 1 else None
    )
    active_units = tuple(entries.get("PROTECTED_SYSTEMD_UNIT", []))
    archive_roots = tuple(entries.get("PROTECTED_LEGACY_ARCHIVE_ROOT", []))
    archive_bindings = tuple(
        entries.get("PROTECTED_LEGACY_ARCHIVE_BINDING_SHA256", [])
    )
    legacy_units = tuple(entries.get("PROTECTED_LEGACY_SYSTEMD_UNIT", []))
    activation_classes = tuple(entries.get(ACTIVATION_CLASS_KEY, []))

    errors.extend(_duplicates(active_units, "active unit"))
    errors.extend(_duplicates(archive_roots, "archive root"))
    errors.extend(_duplicates(archive_bindings, "archive binding"))
    errors.extend(_duplicates(legacy_units, "legacy unit"))
    errors.extend(_duplicates(activation_classes, "activation class review"))

    if set(activation_classes) != REQUIRED_ACTIVATION_CLASSES or len(
        activation_classes
    ) != len(REQUIRED_ACTIVATION_CLASSES):
        errors.append("activation class review declarations are incomplete or unsupported")

    for index, binding in enumerate(archive_bindings, start=1):
        if not BINDING_RE.fullmatch(binding):
            errors.append(f"archive binding {index} must be a lowercase SHA-256")

    for index, unit in enumerate(active_units, start=1):
        if not ACTIVE_UNIT_RE.fullmatch(unit) or ".." in unit or "@." in unit:
            errors.append(f"active unit {index} has an unsafe identifier")
    for index, unit in enumerate(legacy_units, start=1):
        if not LEGACY_UNIT_RE.fullmatch(unit) or ".." in unit or "@." in unit:
            errors.append(f"legacy unit {index} has an unsafe identifier")
        if unit in active_units:
            errors.append(f"legacy unit {index} overlaps an active unit")

    parsed_roots: list[PurePosixPath | None] = []
    for index, value in enumerate(archive_roots, start=1):
        parsed: PurePosixPath | None = None
        if (
            not ARCHIVE_ROOT_RE.fullmatch(value)
            or posixpath.normpath(value) != value
            or any(part in {"", ".", ".."} for part in value.split("/")[1:])
        ):
            errors.append(f"archive root {index} must be an absolute canonical path")
        else:
            parsed = PurePosixPath(value)
            minimum_parts = ALLOWED_ARCHIVE_ROOT_PREFIX_PARTS.get(
                parsed.parts[1] if len(parsed.parts) > 1 else ""
            )
            if minimum_parts is None or len(parsed.parts) < minimum_parts:
                errors.append(f"archive root {index} is too broad to be dedicated")
        parsed_roots.append(parsed)

    for index, root in enumerate(parsed_roots, start=1):
        if root is None:
            continue
        for earlier in parsed_roots[: index - 1]:
            if earlier is None:
                continue
            if root in earlier.parents or earlier in root.parents:
                errors.append(f"archive root {index} overlaps an earlier archive root")
                break

    if len(runtime_evidence_values) != 1:
        if not (allow_missing_bindings and not runtime_evidence_values):
            errors.append(
                f"{RUNTIME_EVIDENCE_HASH_KEY} must occur exactly once for "
                "either archive-presence decision"
            )
    elif not BINDING_RE.fullmatch(runtime_evidence_values[0]):
        errors.append(
            f"{RUNTIME_EVIDENCE_HASH_KEY} must be a lowercase SHA-256"
        )

    if legacy_archives_present:
        if not archive_roots:
            errors.append("archive presence is yes but no dedicated archive root is declared")
        if not allow_missing_bindings and len(archive_bindings) != len(archive_roots):
            errors.append("each declared archive root must have one binding SHA-256")
        if allow_missing_bindings and archive_bindings and len(archive_bindings) != len(archive_roots):
            errors.append("archive bindings must be absent or complete while deriving them")
    else:
        if archive_roots or archive_bindings or legacy_units:
            errors.append("archive presence is no but legacy archive declarations are not empty")

    if errors:
        return None, errors
    return ProtectedHostContract(
        active_units,
        legacy_archives_present,
        runtime_evidence_sha256,
        archive_roots,
        archive_bindings,
        legacy_units,
        activation_classes,
    ), []


def parse_contract_text(
    text: str,
    *,
    allow_missing_bindings: bool = False,
    allow_unreviewed: bool = False,
) -> tuple[ProtectedHostContract | None, list[str]]:
    """Parse strict KEY=VALUE input while keeping all values out of errors."""

    entries: dict[str, list[str]] = {}
    errors: list[str] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw or raw.startswith("#"):
            continue
        if raw != raw.strip() or "=" not in raw:
            errors.append(f"line {line_number}: expected unindented KEY=VALUE")
            continue
        key, value = raw.split("=", 1)
        if key not in ALLOWED_KEYS:
            errors.append(f"line {line_number}: unsupported key")
            continue
        if not value or any(character.isspace() or ord(character) < 32 for character in value):
            errors.append(f"line {line_number}: value is empty or contains whitespace/control data")
            continue
        entries.setdefault(key, []).append(value)

    if errors:
        return None, errors
    return validate_entries(
        entries,
        allow_missing_bindings=allow_missing_bindings,
        allow_unreviewed=allow_unreviewed,
    )


def _open_absolute_file_no_follow(path: Path, flags: int) -> tuple[int, int, str]:
    """Open an absolute POSIX file and retain its no-follow parent directory."""

    if os.name != "posix" or not path.is_absolute() or not path.name:
        raise OSError("secure component-wise path opens are unavailable")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None or os.open not in os.supports_dir_fd:
        raise OSError("secure component-wise path opens are unavailable")

    directory_flags = os.O_RDONLY | nofollow | directory
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open("/", directory_flags)
    try:
        for component in path.parts[1:-1]:
            if component in {"", ".", ".."}:
                raise OSError("unsafe path component")
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(path.name, flags | nofollow, dir_fd=descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return file_descriptor, descriptor, path.name


def load_contract(
    path: Path,
    *,
    allow_missing_bindings: bool = False,
    allow_unreviewed: bool = False,
) -> tuple[ProtectedHostContract | None, list[str]]:
    """Securely read and validate the private contract without path races."""

    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        absolute = path.absolute()
    except OSError:
        return None, ["protected-host contract is unavailable"]
    if stat.S_ISLNK(metadata.st_mode):
        return None, ["protected-host contract must not be a symbolic link"]
    if not stat.S_ISREG(metadata.st_mode):
        return None, ["protected-host contract must be a regular file"]
    if resolved != absolute:
        return None, ["protected-host contract path must not traverse a symbolic link"]
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        return None, ["protected-host contract mode must be exactly 0600"]
    if metadata.st_nlink != 1:
        return None, ["protected-host contract must have exactly one hard link"]

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        return None, ["secure no-follow contract reads are unavailable"]
    # O_NONBLOCK prevents a lookup/open race from hanging on a substituted FIFO
    # or device before the authoritative fstat can reject it.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        descriptor, parent_descriptor, final_name = _open_absolute_file_no_follow(
            absolute,
            flags,
        )
    except OSError:
        return None, ["protected-host contract cannot be opened safely"]
    try:
        opened_before = os.fstat(descriptor)
        parent_before = os.fstat(parent_descriptor)
        initial_identity = (metadata.st_dev, metadata.st_ino)
        opened_identity = (opened_before.st_dev, opened_before.st_ino)
        if initial_identity != opened_identity:
            return None, ["protected-host contract changed while opening"]
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or stat.S_IMODE(opened_before.st_mode) != 0o600
            or opened_before.st_nlink != 1
        ):
            return None, ["protected-host contract controls changed while opening"]

        chunks: list[bytes] = []
        remaining = MAX_CONTRACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        parent_after = os.fstat(parent_descriptor)
        before_state = (
            opened_before.st_dev,
            opened_before.st_ino,
            opened_before.st_mode,
            opened_before.st_uid,
            opened_before.st_gid,
            opened_before.st_nlink,
            opened_before.st_size,
            opened_before.st_mtime_ns,
            opened_before.st_ctime_ns,
        )
        after_state = (
            opened_after.st_dev,
            opened_after.st_ino,
            opened_after.st_mode,
            opened_after.st_uid,
            opened_after.st_gid,
            opened_after.st_nlink,
            opened_after.st_size,
            opened_after.st_mtime_ns,
            opened_after.st_ctime_ns,
        )
        parent_before_state = (
            parent_before.st_dev,
            parent_before.st_ino,
            parent_before.st_mode,
            parent_before.st_uid,
            parent_before.st_gid,
            parent_before.st_nlink,
            parent_before.st_size,
            parent_before.st_mtime_ns,
            parent_before.st_ctime_ns,
        )
        parent_after_state = (
            parent_after.st_dev,
            parent_after.st_ino,
            parent_after.st_mode,
            parent_after.st_uid,
            parent_after.st_gid,
            parent_after.st_nlink,
            parent_after.st_size,
            parent_after.st_mtime_ns,
            parent_after.st_ctime_ns,
        )
        if (
            before_state != after_state
            or opened_after.st_size != len(raw)
            or parent_before_state != parent_after_state
        ):
            return None, ["protected-host contract changed while reading"]

        directory_entry = os.stat(
            final_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        directory_entry_state = (
            directory_entry.st_dev,
            directory_entry.st_ino,
            directory_entry.st_mode,
            directory_entry.st_uid,
            directory_entry.st_gid,
            directory_entry.st_nlink,
            directory_entry.st_size,
            directory_entry.st_mtime_ns,
            directory_entry.st_ctime_ns,
        )
        if directory_entry_state != after_state:
            return None, ["protected-host contract directory entry changed while reading"]

        # Re-walk the absolute path with O_NOFOLLOW after the read. Retaining the
        # original parent descriptor proves the file stayed in that directory;
        # this second walk also rejects a parent renamed away and replaced by a
        # symlink back to the same inode, which a final path-based lstat alone
        # cannot distinguish.
        try:
            reopened, reopened_parent, reopened_name = _open_absolute_file_no_follow(
                absolute,
                flags,
            )
        except OSError:
            return None, ["protected-host contract path changed while reading"]
        try:
            reopened_state = os.fstat(reopened)
            reopened_parent_state = os.fstat(reopened_parent)
            if (
                reopened_name != final_name
                or (
                    reopened_state.st_dev,
                    reopened_state.st_ino,
                    reopened_state.st_mode,
                    reopened_state.st_uid,
                    reopened_state.st_gid,
                    reopened_state.st_nlink,
                    reopened_state.st_size,
                    reopened_state.st_mtime_ns,
                    reopened_state.st_ctime_ns,
                )
                != after_state
                or (
                    reopened_parent_state.st_dev,
                    reopened_parent_state.st_ino,
                    reopened_parent_state.st_mode,
                    reopened_parent_state.st_uid,
                    reopened_parent_state.st_gid,
                    reopened_parent_state.st_nlink,
                    reopened_parent_state.st_size,
                    reopened_parent_state.st_mtime_ns,
                    reopened_parent_state.st_ctime_ns,
                )
                != parent_after_state
            ):
                return None, ["protected-host contract path changed while reading"]
        finally:
            os.close(reopened)
            os.close(reopened_parent)
    except OSError:
        return None, ["protected-host contract cannot be read safely"]
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)

    try:
        final_metadata = path.lstat()
    except OSError:
        return None, ["protected-host contract changed after reading"]
    final_state = (
        final_metadata.st_dev,
        final_metadata.st_ino,
        final_metadata.st_mode,
        final_metadata.st_uid,
        final_metadata.st_gid,
        final_metadata.st_nlink,
        final_metadata.st_size,
        final_metadata.st_mtime_ns,
        final_metadata.st_ctime_ns,
    )
    if final_state != after_state:
        return None, ["protected-host contract changed after reading"]
    if len(raw) > MAX_CONTRACT_BYTES:
        return None, ["protected-host contract exceeds the size limit"]
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return None, ["protected-host contract cannot be read as UTF-8"]
    return parse_contract_text(
        text,
        allow_missing_bindings=allow_missing_bindings,
        allow_unreviewed=allow_unreviewed,
    )


def systemd_unit_state(unit: str) -> UnitState:
    """Read exact system-manager state quietly without exposing the unit."""

    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return UnitState(None, None, None, None)
    try:
        result = subprocess.run(
            [
                systemctl,
                "--system",
                "show",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=UnitFileState",
                "--property=ControlGroup",
                "--",
                unit,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return UnitState(None, None, None, None)
    if result.returncode != 0:
        return UnitState(None, None, None, None)
    properties: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            return UnitState(None, None, None, None)
        key, value = line.split("=", 1)
        if key not in {
            "LoadState",
            "ActiveState",
            "UnitFileState",
            "ControlGroup",
        } or key in properties:
            return UnitState(None, None, None, None)
        properties[key] = value
    if set(properties) != {
        "LoadState",
        "ActiveState",
        "UnitFileState",
        "ControlGroup",
    }:
        return UnitState(None, None, None, None)
    return UnitState(
        properties["LoadState"],
        properties["ActiveState"],
        properties["UnitFileState"],
        properties["ControlGroup"],
    )


def _mountinfo_unescape(value: str) -> str | None:
    """Decode only the four escapes emitted for Linux mountinfo paths."""

    if re.search(r"\\(?!040|011|012|134)", value):
        return None
    return re.sub(
        r"\\(040|011|012|134)",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys instead of accepting a last-value override."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _host_mount_namespace_matches() -> bool:
    """Require inspection from the host mount namespace, not a private view."""

    try:
        current = os.stat("/proc/self/ns/mnt")
        host = os.stat("/proc/1/ns/mnt")
    except OSError:
        return False
    # These identify the namespace objects only and never enter the archive
    # binding payload, where device numbers would be reboot-unstable.
    return (current.st_dev, current.st_ino) == (host.st_dev, host.st_ino)


def _parse_mountinfo_bytes(raw: bytes) -> tuple[MountInfoRecord, ...] | None:
    """Parse a bounded mountinfo snapshot without retaining mount sources."""

    if len(raw) > MAX_MOUNTINFO_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return None
    lines = text.splitlines()
    if not lines or len(lines) > MAX_MOUNTINFO_LINES:
        return None

    records: list[MountInfoRecord] = []
    mount_ids: set[int] = set()
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            return None
        before = left.split()
        after = right.split()
        if len(before) < 6 or len(after) < 3:
            return None
        if not before[0].isdigit() or not before[1].isdigit():
            return None
        mount_id = int(before[0])
        parent_id = int(before[1])
        if mount_id <= 0 or mount_id in mount_ids:
            return None
        if not re.fullmatch(r"[0-9]+:[0-9]+", before[2]):
            return None

        raw_root = _mountinfo_unescape(before[3])
        raw_mount_point = _mountinfo_unescape(before[4])
        filesystem_type = after[0]
        if (
            raw_root is None
            or raw_mount_point is None
            or not raw_root.startswith("/")
            or posixpath.normpath(raw_root) != raw_root
            or not raw_mount_point.startswith("/")
            or posixpath.normpath(raw_mount_point) != raw_mount_point
            or any(ord(character) < 32 or ord(character) == 127 for character in raw_root)
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in raw_mount_point
            )
            or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", filesystem_type)
        ):
            return None
        mount_ids.add(mount_id)
        records.append(
            MountInfoRecord(
                mount_id,
                parent_id,
                before[2],
                PurePosixPath(raw_root),
                PurePosixPath(raw_mount_point),
                filesystem_type.lower(),
            )
        )
    return tuple(records)


def _read_mountinfo() -> tuple[MountInfoRecord, ...] | None:
    """Read a bounded, structurally valid snapshot of visible mount records."""

    try:
        with Path("/proc/self/mountinfo").open("rb") as mountinfo_file:
            raw = mountinfo_file.read(MAX_MOUNTINFO_BYTES + 1)
    except OSError:
        return None
    return _parse_mountinfo_bytes(raw)


def _paths_overlap(first: PurePosixPath, second: PurePosixPath) -> bool:
    """Return whether either absolute filesystem-internal path contains the other."""

    return first == second or first in second.parents or second in first.parents


def _mount_record_from_records(
    value: str,
    records: tuple[MountInfoRecord, ...],
) -> tuple[MountInfoRecord | None, tuple[str, ...]]:
    """Select one containing mount and reject every visible archive alias."""

    target = PurePosixPath(value)
    record_ids = tuple(record.mount_id for record in records)
    if len(record_ids) != len(set(record_ids)):
        return None, ("mount topology has duplicate record identifiers",)
    relevant = tuple(
        record
        for record in records
        if (
            record.mount_point == target
            or record.mount_point in target.parents
            or target in record.mount_point.parents
        )
    )
    relevant_points = tuple(record.mount_point for record in relevant)
    if len(relevant_points) != len(set(relevant_points)):
        return None, ("has an ambiguous stacked mount topology",)
    if any(target in record.mount_point.parents for record in relevant):
        return None, ("contains an undeclared descendant mount",)
    candidates = tuple(
        record
        for record in relevant
        if record.mount_point == target or record.mount_point in target.parents
    )
    if not candidates:
        return None, ("containing mount is unavailable",)
    selected = max(candidates, key=lambda item: len(item.mount_point.parts))
    if selected.filesystem_type not in ALLOWED_ARCHIVE_FILESYSTEM_TYPES:
        return None, ("uses an unsupported non-local or non-durable filesystem",)

    try:
        relative = target.relative_to(selected.mount_point)
    except ValueError:
        return None, ("containing mount relationship is invalid",)
    archive_filesystem_root = (
        selected.root
        if relative == PurePosixPath(".")
        else selected.root.joinpath(relative)
    )
    for record in records:
        if record.mount_id == selected.mount_id:
            continue
        if record.major_minor != selected.major_minor:
            continue
        if _paths_overlap(record.root, archive_filesystem_root):
            return None, ("has an external mount alias",)
    return selected, ()


def _mount_target_from_points(
    value: str,
    mount_points: tuple[PurePosixPath, ...],
) -> tuple[str | None, tuple[str, ...]]:
    """Compatibility helper for pure descendant/stacked topology tests."""

    records = tuple(
        MountInfoRecord(
            index,
            0,
            "{}:0".format(index),
            PurePosixPath("/"),
            mount_point,
            "ext4",
        )
        for index, mount_point in enumerate(mount_points, start=1)
    )
    selected, errors = _mount_record_from_records(value, records)
    return (str(selected.mount_point) if selected is not None else None), errors


def _archive_mount_record(
    value: str,
) -> tuple[MountInfoRecord | None, tuple[str, ...]]:
    """Establish an unambiguous containing mount in the host namespace."""

    if not _host_mount_namespace_matches():
        return None, ("must be inspected from the host mount namespace",)
    records = _read_mountinfo()
    if records is None:
        return None, ("mount topology is unavailable",)
    return _mount_record_from_records(value, records)


def _archive_mount_target(value: str) -> tuple[str | None, tuple[str, ...]]:
    """Establish an unambiguous containing mount in the host namespace."""

    selected, errors = _archive_mount_record(value)
    return (str(selected.mount_point) if selected is not None else None), errors


def _safe_findmnt_string(value: object, *, optional: bool = False) -> str | None:
    """Accept only scalar, printable findmnt fields."""

    if optional and (value is None or value == "-"):
        return None
    if not isinstance(value, str) or not value or value == "-":
        raise ValueError("missing findmnt field")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("unsafe findmnt field")
    return value


def _isolated_process_group_id(
    process: subprocess.Popen[bytes],
) -> int | None:
    """Return the verified helper-only process group created by ``setsid``."""

    try:
        process_group_id = os.getpgid(process.pid)
        caller_process_group_id = os.getpgrp()
    except (AttributeError, OSError):
        return None
    if (
        process_group_id <= 1
        or process_group_id != process.pid
        or process_group_id == caller_process_group_id
    ):
        return None
    return process_group_id


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    process_group_id: int | None,
) -> None:
    """Kill an isolated helper group, then reap its direct child."""

    group_signaled = False
    try:
        caller_process_group_id = os.getpgrp()
    except (AttributeError, OSError):
        caller_process_group_id = None
    if (
        process_group_id is not None
        and process_group_id > 1
        and process_group_id != caller_process_group_id
    ):
        try:
            os.killpg(process_group_id, signal.SIGKILL)
            group_signaled = True
        except ProcessLookupError:
            group_signaled = True
        except (AttributeError, OSError):
            pass
    if not group_signaled and process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.SubprocessError):
            pass


def _bounded_command_stdout(
    command: list[str],
    max_bytes: int,
    timeout_seconds: float,
) -> bytes | None:
    """Capture a POSIX command with an in-flight byte cap and hard deadline."""

    if os.name != "posix" or max_bytes < 0 or timeout_seconds <= 0:
        return None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    process_group_id = _isolated_process_group_id(process)
    if process.stdout is None:
        _terminate_process_group(process, process_group_id)
        return None

    deadline = time.monotonic() + timeout_seconds
    captured = bytearray()
    group_cleanup_is_safe = True
    try:
        descriptor = process.stdout.fileno()
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                return None
            try:
                readable, _, _ = select.select(
                    [descriptor],
                    [],
                    [],
                    remaining_time,
                )
            except (OSError, ValueError):
                return None
            if not readable:
                return None
            try:
                chunk = os.read(
                    descriptor,
                    min(65536, max_bytes + 1 - len(captured)),
                )
            except OSError:
                return None
            if not chunk:
                break
            captured.extend(chunk)
            if len(captured) > max_bytes:
                return None

        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            return None
        try:
            return_code = process.wait(timeout=remaining_time)
        except subprocess.TimeoutExpired:
            return None
        except (OSError, subprocess.SubprocessError):
            # An unexpected wait failure does not prove that the child PID still
            # anchors the original group, so avoid signaling a possibly reused ID.
            group_cleanup_is_safe = False
            return None
        group_cleanup_is_safe = False
        if return_code != 0:
            return None
        return bytes(captured)
    finally:
        try:
            process.stdout.close()
        except OSError:
            pass
        _terminate_process_group(
            process,
            process_group_id if group_cleanup_is_safe else None,
        )


def _findmnt_identity(
    value: str,
    expected_target: str,
    expected_filesystem_type: str | None = None,
    expected_major_minor: str | None = None,
) -> dict[str, object] | None:
    """Return a strict, bounded stable-filesystem identity for one target."""

    findmnt = shutil.which("findmnt")
    if findmnt is None:
        return None
    stdout = _bounded_command_stdout(
        [
            findmnt,
            "--json",
            "--target",
            value,
            "--output",
            "TARGET,SOURCE,FSTYPE,OPTIONS,UUID,PARTUUID,MAJ:MIN",
        ],
        MAX_FINDMNT_BYTES,
        FINDMNT_TIMEOUT_SECONDS,
    )
    if stdout is None:
        return None
    try:
        document = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
        if not isinstance(document, dict) or set(document) != {"filesystems"}:
            return None
        filesystems = document["filesystems"]
        if not isinstance(filesystems, list) or len(filesystems) != 1:
            return None
        record = filesystems[0]
        required = {
            "target",
            "source",
            "fstype",
            "options",
            "uuid",
            "partuuid",
            "maj:min",
        }
        if not isinstance(record, dict) or set(record) != required:
            return None

        target = _safe_findmnt_string(record["target"])
        source = _safe_findmnt_string(record["source"])
        filesystem_type = _safe_findmnt_string(record["fstype"]).lower()
        options = _safe_findmnt_string(record["options"])
        filesystem_uuid = _safe_findmnt_string(record["uuid"], optional=True)
        partition_uuid = _safe_findmnt_string(record["partuuid"], optional=True)
        major_minor = _safe_findmnt_string(record["maj:min"])
        if (
            target != expected_target
            or not target.startswith("/")
            or posixpath.normpath(target) != target
        ):
            return None
        if (
            filesystem_type not in ALLOWED_ARCHIVE_FILESYSTEM_TYPES
            or (
                expected_filesystem_type is not None
                and filesystem_type != expected_filesystem_type.lower()
            )
        ):
            return None
        if (
            not re.fullmatch(r"[0-9]+:[0-9]+", major_minor)
            or (
                expected_major_minor is not None
                and major_minor != expected_major_minor
            )
        ):
            return None
        option_list = options.split(",")
        if any(not option for option in option_list):
            return None
    except (KeyError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        return None

    identity: dict[str, object] = {
        "filesystem_type": filesystem_type,
        "options": sorted(option_list),
        "target": target,
    }
    stable_ids: dict[str, str] = {}
    if filesystem_uuid is not None:
        stable_ids["uuid"] = filesystem_uuid.lower()
    if partition_uuid is not None:
        stable_ids["partuuid"] = partition_uuid.lower()
    if stable_ids:
        identity["stable_ids"] = stable_ids
    else:
        identity["source_fallback"] = source

    suffix = re.search(r"\[([^\[\]\x00-\x1f]+)\]\Z", source)
    if suffix is not None:
        identity["source_subpath"] = suffix.group(1)
    return identity


def _stat_stability_state(metadata: os.stat_result) -> tuple[int, ...]:
    """Return metadata that must remain unchanged during one binding pass."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _archive_device_identity(metadata: os.stat_result) -> str | None:
    """Render st_dev in the same major:minor form used by mountinfo."""

    try:
        return "{}:{}".format(os.major(metadata.st_dev), os.minor(metadata.st_dev))
    except (AttributeError, OSError, ValueError):
        return None


def _close_opened_archive_directory(opened: OpenedArchiveDirectory) -> None:
    """Close both descriptors retained for one archive path walk."""

    for descriptor in (opened.descriptor, opened.parent_descriptor):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_archive_directory_no_follow(value: str) -> OpenedArchiveDirectory | None:
    """Open every absolute path component without following symbolic links."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    noatime = getattr(os, "O_NOATIME", None)
    if os.name != "posix" or nofollow is None or directory is None or noatime is None:
        return None
    parsed = PurePosixPath(value)
    if (
        not value.startswith("/")
        or value == "/"
        or posixpath.normpath(value) != value
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        return None

    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    traversal_flags = (
        getattr(os, "O_PATH", os.O_RDONLY) | nofollow | directory | close_on_exec
    )
    root_flags = os.O_RDONLY | nofollow | directory | noatime | close_on_exec
    current_descriptor: int | None = None
    transferred = False
    try:
        current_descriptor = os.open("/", traversal_flags)
        components = parsed.parts[1:]
        for index, component in enumerate(components):
            final_component = index == len(components) - 1
            next_descriptor = os.open(
                component,
                root_flags if final_component else traversal_flags,
                dir_fd=current_descriptor,
            )
            try:
                if not stat.S_ISDIR(os.fstat(next_descriptor).st_mode):
                    os.close(next_descriptor)
                    return None
            except OSError:
                os.close(next_descriptor)
                return None
            if final_component:
                opened = OpenedArchiveDirectory(
                    next_descriptor,
                    current_descriptor,
                    component,
                )
                transferred = True
                return opened
            os.close(current_descriptor)
            current_descriptor = next_descriptor
    except OSError:
        return None
    finally:
        # A successful return transfers the immediate parent descriptor to the
        # result. Every failure retains it here for deterministic cleanup.
        if current_descriptor is not None and not transferred:
            try:
                os.close(current_descriptor)
            except OSError:
                pass
    return None


def _archive_top_level_fingerprint(descriptor: int) -> dict[str, object] | None:
    """Hash immediate retained-entry metadata through an already-held root FD."""

    try:
        root_before = os.fstat(descriptor)
        if not stat.S_ISDIR(root_before.st_mode):
            return None

        names: list[str] = []
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if len(names) >= MAX_ARCHIVE_TOP_LEVEL_ENTRIES:
                        return None
                    if (
                        not isinstance(entry.name, str)
                        or not entry.name
                        or entry.name in {".", ".."}
                        or "/" in entry.name
                        or "\x00" in entry.name
                    ):
                        return None
                    names.append(entry.name)
        except OSError:
            return None
        if not names:
            return None

        records: list[tuple[str, tuple[int, ...], bytes]] = []
        manifest_size = 0
        for name in names:
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError:
                return None
            if stat.S_ISLNK(metadata.st_mode):
                return None
            state = _stat_stability_state(metadata)
            record = {
                "name_sha256": hashlib.sha256(os.fsencode(name)).hexdigest(),
                "type": stat.S_IFMT(metadata.st_mode),
                "inode": metadata.st_ino,
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "nlink": metadata.st_nlink,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            }
            serialized = json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            manifest_size += len(serialized) + 4
            if manifest_size > MAX_ARCHIVE_TOP_LEVEL_MANIFEST_BYTES:
                return None
            records.append((record["name_sha256"], state, serialized))

        digest = hashlib.sha256()
        digest.update(b"protected-legacy-top-level-v1\x00")
        for _name_hash, _state, serialized in sorted(records):
            digest.update(len(serialized).to_bytes(4, "big"))
            digest.update(serialized)

        for name, expected in zip(names, [item[1] for item in records]):
            try:
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError:
                return None
            if _stat_stability_state(current) != expected:
                return None
        root_after = os.fstat(descriptor)
        if _stat_stability_state(root_before) != _stat_stability_state(root_after):
            return None
        return {
            "schema": "protected-legacy-top-level-v1",
            "entry_count": len(records),
            "metadata_sha256": digest.hexdigest(),
        }
    except OSError:
        return None


def _archive_binding_payload(
    metadata: os.stat_result,
    mount_identity: dict[str, object],
    top_level_fingerprint: dict[str, object],
) -> dict[str, object]:
    """Build the v3 payload without volatile root or mount device numbers."""

    return {
        "schema": "protected-legacy-archive-binding-v3",
        "root": {
            "inode": metadata.st_ino,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "nlink": metadata.st_nlink,
            "mtime_ns": metadata.st_mtime_ns,
            "ctime_ns": metadata.st_ctime_ns,
        },
        "mount": mount_identity,
        "top_level": top_level_fingerprint,
    }


def _archive_binding_digest(
    metadata: os.stat_result,
    mount_identity: dict[str, object],
    top_level_fingerprint: dict[str, object],
) -> str:
    """Hash the canonical v3 archive binding payload."""

    payload = _archive_binding_payload(
        metadata,
        mount_identity,
        top_level_fingerprint,
    )
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def archive_binding_fingerprint(value: str) -> str | None:
    """Hash stable root, mount, and bounded retained-entry metadata."""

    opened = _open_archive_directory_no_follow(value)
    if opened is None:
        return None
    try:
        try:
            metadata = os.fstat(opened.descriptor)
            parent_entry = os.stat(
                opened.basename,
                dir_fd=opened.parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            return None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(parent_entry.st_mode)
            or _stat_stability_state(metadata) != _stat_stability_state(parent_entry)
        ):
            return None

        mount_record, mount_errors = _archive_mount_record(value)
        if mount_errors or mount_record is None:
            return None
        opened_major_minor = _archive_device_identity(metadata)
        if opened_major_minor != mount_record.major_minor:
            return None
        mount_identity = _findmnt_identity(
            value,
            str(mount_record.mount_point),
            mount_record.filesystem_type,
            opened_major_minor,
        )
        if mount_identity is None:
            return None
        top_level_fingerprint = _archive_top_level_fingerprint(opened.descriptor)
        if top_level_fingerprint is None:
            return None

        final_mount_record, final_mount_errors = _archive_mount_record(value)
        if final_mount_errors or final_mount_record != mount_record:
            return None
        try:
            final_metadata = os.fstat(opened.descriptor)
            final_parent_entry = os.stat(
                opened.basename,
                dir_fd=opened.parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            return None
        if (
            _stat_stability_state(metadata) != _stat_stability_state(final_metadata)
            or _stat_stability_state(metadata)
            != _stat_stability_state(final_parent_entry)
            or _archive_device_identity(final_metadata)
            != final_mount_record.major_minor
        ):
            return None
        final_mount_identity = _findmnt_identity(
            value,
            str(final_mount_record.mount_point),
            final_mount_record.filesystem_type,
            _archive_device_identity(final_metadata),
        )
        if final_mount_identity != mount_identity:
            return None

        # Re-walk every absolute path component after the mount and manifest
        # probes. A renamed parent replaced by a symlink may still resolve to
        # the same inode through ordinary lstat(), but cannot pass this walk.
        reopened = _open_archive_directory_no_follow(value)
        if reopened is None:
            return None
        try:
            try:
                reopened_metadata = os.fstat(reopened.descriptor)
                reopened_parent_entry = os.stat(
                    reopened.basename,
                    dir_fd=reopened.parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError:
                return None
            if (
                _stat_stability_state(metadata)
                != _stat_stability_state(reopened_metadata)
                or _stat_stability_state(metadata)
                != _stat_stability_state(reopened_parent_entry)
            ):
                return None
        finally:
            _close_opened_archive_directory(reopened)
        return _archive_binding_digest(
            final_metadata,
            mount_identity,
            top_level_fingerprint,
        )
    finally:
        _close_opened_archive_directory(opened)


def archive_root_issues(value: str) -> tuple[str, ...]:
    """Inspect only root metadata; never enumerate or hash archive contents."""

    path = Path(value)
    try:
        metadata = path.lstat()
    except OSError:
        return ("is unavailable",)
    if stat.S_ISLNK(metadata.st_mode):
        return ("must not be a symbolic link",)
    if not stat.S_ISDIR(metadata.st_mode):
        return ("must be a directory",)

    errors: list[str] = []
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return ("cannot be resolved canonically",)
    if str(resolved) != value:
        errors.append("must not traverse a symbolic-link or noncanonical component")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        errors.append("must not grant group or world access")

    try:
        if (
            resolved == REPOSITORY_ROOT
            or _is_relative_to(resolved, REPOSITORY_ROOT)
            or _is_relative_to(REPOSITORY_ROOT, resolved)
        ):
            errors.append("must be isolated from the public repository")
    except ValueError:
        # Different Windows drives cannot overlap. Production validation runs on
        # Linux, while this branch keeps the pure static checks cross-platform.
        pass
    mount_record, mount_errors = _archive_mount_record(value)
    errors.extend(mount_errors)
    if (
        not mount_errors
        and mount_record is not None
        and _archive_device_identity(metadata) != mount_record.major_minor
    ):
        errors.append("does not match its containing mount device")
    return tuple(errors)


def check_live_state(
    contract: ProtectedHostContract,
    unit_probe: Callable[[str], UnitState] = systemd_unit_state,
    archive_probe: Callable[[str], tuple[str, ...]] = archive_root_issues,
    binding_probe: Callable[[str], str | None] = archive_binding_fingerprint,
) -> list[str]:
    """Optionally prove required live state without exposing contract values."""

    errors: list[str] = []
    for index, unit in enumerate(contract.active_units, start=1):
        state = unit_probe(unit)
        if None in state:
            errors.append(f"active unit {index} state is unavailable")
        elif state.load_state != "loaded":
            errors.append(f"active unit {index} is not loaded")
        elif state.active_state != "active":
            errors.append(f"active unit {index} is not exactly active")

    for index, unit in enumerate(contract.legacy_units, start=1):
        state = unit_probe(unit)
        if None in state:
            errors.append(f"legacy unit {index} state is unavailable")
            continue
        if state.active_state != "inactive":
            errors.append(f"legacy unit {index} must be exactly inactive")
        if state.load_state not in {"loaded", "masked"}:
            errors.append(f"legacy unit {index} load state is not safely classified")
        if state.unit_file_state not in {"disabled", "masked"}:
            errors.append(
                f"legacy unit {index} must be persistently disabled or masked"
            )
        if state.control_group:
            errors.append(f"legacy unit {index} still has a control group")

    for index, (root, expected_binding) in enumerate(
        zip(contract.archive_roots, contract.archive_bindings),
        start=1,
    ):
        try:
            problems = archive_probe(root)
        except OSError:
            problems = ("state is unavailable",)
        for problem in problems:
            errors.append(f"archive root {index} {problem}")
        try:
            actual_binding = binding_probe(root)
        except OSError:
            actual_binding = None
        if actual_binding is None:
            errors.append(f"archive root {index} binding is unavailable")
        elif actual_binding != expected_binding:
            errors.append(f"archive root {index} binding changed")
    return errors


def _load_runtime_evidence_validator() -> object | None:
    """Load only the fixed, non-symlink sibling validator without using sys.path."""

    script_directory = Path(__file__).resolve().parent
    validator_path = script_directory / "validate_protected_runtime_evidence.py"
    try:
        metadata = validator_path.lstat()
        resolved = validator_path.resolve(strict=True)
    except OSError:
        return None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or resolved != validator_path
        or resolved.parent != script_directory
    ):
        return None
    specification = importlib.util.spec_from_file_location(
        "_protected_runtime_evidence_validator",
        str(validator_path),
    )
    if specification is None or specification.loader is None:
        return None
    module = importlib.util.module_from_spec(specification)
    previous_bytecode_policy = sys.dont_write_bytecode
    try:
        # Preflight is a read-only gate. SourceFileLoader otherwise persists a
        # sibling __pycache__ entry as a side effect of this fixed import.
        sys.dont_write_bytecode = True
        specification.loader.exec_module(module)
    except (ImportError, OSError, SyntaxError):
        return None
    finally:
        sys.dont_write_bytecode = previous_bytecode_policy
    if (
        getattr(module, "EVIDENCE_HASH_KEY", None) != RUNTIME_EVIDENCE_HASH_KEY
        or getattr(module, "EVIDENCE_SCHEMA", None) != RUNTIME_EVIDENCE_SCHEMA
        or getattr(module, "PRESENCE_FIELD", None)
        != RUNTIME_EVIDENCE_PRESENCE_FIELD
        or getattr(module, "EVIDENCE_VALIDATOR_API_VERSION", None)
        != RUNTIME_EVIDENCE_VALIDATOR_API_VERSION
        or not callable(getattr(module, "validate_runtime_evidence", None))
    ):
        return None
    return module


def runtime_evidence_issues(
    contract_path: Path,
    expected_sha256: str | None,
    expected_archives_present: bool,
    loader: Callable[[], object | None] | None = None,
) -> tuple[str, ...]:
    """Validate fresh bound evidence while keeping all private values opaque."""

    if expected_sha256 is None or not BINDING_RE.fullmatch(expected_sha256):
        return ("fresh boot-bound runtime evidence binding is unavailable",)
    try:
        if loader is None:
            loader = _load_runtime_evidence_validator
        validator = loader()
        validate = getattr(validator, "validate_runtime_evidence", None)
        if not callable(validate):
            return ("fresh boot-bound runtime evidence validator is unavailable",)
        loaded, evidence_errors = validate(
            contract_path,
            expected_sha256,
            expected_archives_present=expected_archives_present,
        )
    except Exception:  # Trusted fixed sibling failed; never expose exception values.
        return ("fresh boot-bound runtime evidence validation is unavailable",)
    if evidence_errors or loaded is None:
        return ("fresh boot-bound runtime evidence is invalid",)
    if getattr(loaded, "sha256", None) != expected_sha256:
        return ("fresh boot-bound runtime evidence binding is invalid",)
    evidence = getattr(loaded, "evidence", None)
    if (
        not isinstance(getattr(evidence, "archives_present", None), bool)
        or evidence.archives_present != expected_archives_present
    ):
        return ("fresh boot-bound runtime evidence presence binding is invalid",)
    return ()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path, metavar="CONTRACT")
    parser.add_argument("--check-live", action="store_true")
    parser.add_argument("--emit-bindings", action="store_true")
    args = parser.parse_args(argv)

    if args.check_live and args.emit_bindings:
        parser.error("--check-live and --emit-bindings are mutually exclusive")

    contract, errors = load_contract(
        args.contract,
        allow_missing_bindings=args.emit_bindings,
        allow_unreviewed=args.emit_bindings,
    )
    if contract is not None and args.emit_bindings:
        generated_bindings: list[str] = []
        if contract.archive_bindings:
            errors.append("remove existing archive bindings before deriving replacements")
        else:
            for index, root in enumerate(contract.archive_roots, start=1):
                problems = archive_root_issues(root)
                binding = archive_binding_fingerprint(root)
                if problems or binding is None:
                    errors.append(f"archive root {index} binding cannot be derived safely")
                else:
                    generated_bindings.append(binding)
        if not errors:
            for binding in generated_bindings:
                print(f"PROTECTED_LEGACY_ARCHIVE_BINDING_SHA256={binding}")
    if contract is not None and args.check_live:
        errors.extend(check_live_state(contract))
        errors.extend(
            runtime_evidence_issues(
                args.contract,
                contract.runtime_evidence_sha256,
                contract.legacy_archives_present,
            )
        )
    if errors:
        for error in errors:
            print("ERROR " + error, file=sys.stderr)
        return 1
    if args.check_live:
        print(
            "PASS protected-host contract and live checks passed; the fresh "
            "presence-bound boot attestation is structurally valid"
        )
    elif args.emit_bindings:
        print(
            "PASS DERIVATION ONLY, NOT AUTHORIZATION: archive binding SHA-256 "
            "values were derived from bounded metadata",
            file=sys.stderr,
        )
    else:
        print("PASS protected-host contract syntax is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
