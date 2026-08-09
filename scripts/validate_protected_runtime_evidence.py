#!/usr/bin/env python3
"""Validate a fresh, content-neutral protected-host review attestation.

The validator deliberately performs no process discovery and executes no
external command. Private discovery is reviewed separately; this file binds
only its canonical PASS summary to one boot and a short time window.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Callable, NamedTuple


EVIDENCE_FILENAME = "protected-legacy-runtime-evidence.local"
EVIDENCE_HASH_KEY = "PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256"
EVIDENCE_SCHEMA = "protected-legacy-host-review-v2"
EVIDENCE_VALIDATOR_API_VERSION = "protected-legacy-runtime-evidence-api-v1"
HOST_VALIDATOR_FILENAME = "validate_protected_host_contract.py"
MAX_EVIDENCE_BYTES = 4096
MAX_EVIDENCE_LINES = 32
MAX_EVIDENCE_AGE_SECONDS = 600
MAX_BOOT_ID_BYTES = 128
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
UNIX_EPOCH_RE = re.compile(r"[1-9][0-9]{8,10}\Z")

# Order is part of the schema so two reviews cannot serialize equivalent
# claims differently and silently produce unrelated binding hashes.
PRESENCE_FIELD = "LEGACY_ARCHIVES_PRESENT"
STATUS_FIELDS = (
    "ARCHIVE_INVENTORY_STATUS",
    "SYSTEM_MANAGER_UNITS_STATUS",
    "USER_MANAGER_UNITS_STATUS",
    "CONTAINERS_STATUS",
    "PACKAGE_ACTIVATION_STATUS",
    "SCHEDULERS_AUTOSTART_STATUS",
    "PROCESSES_STATUS",
    "CGROUPS_STATUS",
    "OPEN_FILES_STATUS",
    "LISTENERS_STATUS",
    "PRODUCT_EXECUTION_STATUS",
)
REQUIRED_FIELDS = (
    "RUNTIME_EVIDENCE_SCHEMA",
    "BOOT_ID_SHA256",
    "CREATED_UNIX",
    PRESENCE_FIELD,
) + STATUS_FIELDS


class RuntimeEvidence(NamedTuple):
    """Canonical non-identifying evidence needed by the live gate."""

    boot_id_sha256: str
    created_unix: int
    archives_present: bool


class LoadedRuntimeEvidence(NamedTuple):
    """Validated evidence and its raw-content binding digest."""

    evidence: RuntimeEvidence
    sha256: str


def evidence_path_for_contract(contract_path: Path) -> Path:
    """Return the only accepted evidence location for a local contract."""

    return contract_path.parent / EVIDENCE_FILENAME


def _load_host_contract_validator() -> object | None:
    """Load the fixed sibling contract parser without trusting ``sys.path``."""

    # This reverse load runs only from the standalone CLI. When the host gate
    # imports this evidence module, function definitions remain inert, so the
    # two pinned validators do not recursively import one another.
    script_directory = Path(__file__).resolve().parent
    validator_path = script_directory / HOST_VALIDATOR_FILENAME
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
        "_protected_host_contract_validator_for_runtime_evidence",
        str(validator_path),
    )
    if specification is None or specification.loader is None:
        return None
    module = importlib.util.module_from_spec(specification)
    previous_bytecode_policy = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        specification.loader.exec_module(module)
    except (ImportError, OSError, SyntaxError):
        return None
    finally:
        sys.dont_write_bytecode = previous_bytecode_policy
    if (
        getattr(module, "RUNTIME_EVIDENCE_HASH_KEY", None) != EVIDENCE_HASH_KEY
        or getattr(module, "RUNTIME_EVIDENCE_SCHEMA", None) != EVIDENCE_SCHEMA
        or getattr(module, "RUNTIME_EVIDENCE_PRESENCE_FIELD", None)
        != PRESENCE_FIELD
        or getattr(module, "RUNTIME_EVIDENCE_VALIDATOR_API_VERSION", None)
        != EVIDENCE_VALIDATOR_API_VERSION
        or not callable(getattr(module, "load_contract", None))
    ):
        return None
    return module


def adjacent_contract_presence(
    contract_path: Path,
    loader: Callable[[], object | None] | None = None,
) -> tuple[bool | None, list[str]]:
    """Read the supplied contract's reviewed presence without exposing values."""

    try:
        validator = (loader or _load_host_contract_validator)()
        load_contract = getattr(validator, "load_contract", None)
        if not callable(load_contract):
            return None, ["protected-host contract validator is unavailable"]
        contract, contract_errors = load_contract(
            contract_path,
            allow_missing_bindings=True,
            allow_unreviewed=True,
        )
    except Exception:  # The fixed sibling failed; never expose exception values.
        return None, ["protected-host contract presence is unavailable"]
    if contract_errors or contract is None:
        return None, ["protected-host contract presence is invalid"]
    presence = getattr(contract, "legacy_archives_present", None)
    if not isinstance(presence, bool):
        return None, ["protected-host contract presence is invalid"]
    return presence, []


def current_boot_id_sha256(path: Path = BOOT_ID_PATH) -> str | None:
    """Hash the current Linux boot ID without returning its raw value."""

    try:
        with path.open("rb") as boot_id_file:
            raw = boot_id_file.read(MAX_BOOT_ID_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_BOOT_ID_BYTES:
        return None
    try:
        boot_id = raw.decode("ascii").strip()
    except UnicodeError:
        return None
    if not BOOT_ID_RE.fullmatch(boot_id):
        return None
    return hashlib.sha256(boot_id.encode("ascii")).hexdigest()


def parse_evidence_bytes(
    raw: bytes,
    *,
    current_boot_sha256: str,
    now_epoch: float,
) -> tuple[RuntimeEvidence | None, list[str]]:
    """Validate the bounded canonical document without exposing field values."""

    errors: list[str] = []
    if len(raw) > MAX_EVIDENCE_BYTES:
        return None, ["runtime evidence exceeds the size limit"]
    if not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        return None, ["runtime evidence must use canonical LF-terminated ASCII"]
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        return None, ["runtime evidence must be canonical ASCII"]

    lines = text.splitlines()
    if len(lines) > MAX_EVIDENCE_LINES:
        return None, ["runtime evidence exceeds the line limit"]
    if len(lines) != len(REQUIRED_FIELDS):
        return None, ["runtime evidence has missing or extra fields"]

    entries: dict[str, str] = {}
    ordered_keys: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        if not line or line != line.strip() or line.count("=") != 1:
            errors.append(
                f"runtime evidence line {line_number} is not canonical KEY=VALUE"
            )
            continue
        key, value = line.split("=", 1)
        if key not in REQUIRED_FIELDS:
            errors.append(f"runtime evidence line {line_number} has an unsupported key")
            continue
        if key in entries:
            errors.append(f"runtime evidence line {line_number} duplicates a field")
            continue
        if not value or any(ord(character) < 33 or ord(character) > 126 for character in value):
            errors.append(f"runtime evidence line {line_number} has an invalid value")
            continue
        entries[key] = value
        ordered_keys.append(key)

    if errors:
        return None, errors
    if tuple(ordered_keys) != REQUIRED_FIELDS:
        return None, ["runtime evidence fields are not in canonical order"]
    if entries["RUNTIME_EVIDENCE_SCHEMA"] != EVIDENCE_SCHEMA:
        errors.append("runtime evidence schema is unsupported")
    if not SHA256_RE.fullmatch(entries["BOOT_ID_SHA256"]):
        errors.append("runtime evidence boot binding is not a lowercase SHA-256")
    if not SHA256_RE.fullmatch(current_boot_sha256):
        errors.append("current boot identity is unavailable")
    elif not hmac.compare_digest(entries["BOOT_ID_SHA256"], current_boot_sha256):
        errors.append("runtime evidence belongs to a different boot")
    if not UNIX_EPOCH_RE.fullmatch(entries["CREATED_UNIX"]):
        errors.append("runtime evidence creation time is invalid")
        created_unix = 0
    else:
        created_unix = int(entries["CREATED_UNIX"])
        age = now_epoch - created_unix
        if age < 0:
            errors.append("runtime evidence creation time is in the future")
        elif age > MAX_EVIDENCE_AGE_SECONDS:
            errors.append("runtime evidence is stale")
    presence_value = entries[PRESENCE_FIELD]
    if presence_value not in {"yes", "no"}:
        errors.append("runtime evidence archive-presence decision is invalid")
    archives_present = presence_value == "yes"
    for field in STATUS_FIELDS:
        if entries[field] != "PASS":
            errors.append("runtime evidence contains a non-PASS status")
            break

    if errors:
        return None, errors
    return RuntimeEvidence(
        entries["BOOT_ID_SHA256"],
        created_unix,
        archives_present,
    ), []


def _stable_stat_state(metadata: os.stat_result) -> tuple[int, ...]:
    """Return the inode and mutable controls that must survive one secure read."""

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


def _read_evidence_file(path: Path) -> tuple[bytes | None, os.stat_result | None, list[str]]:
    """Securely open one regular evidence file and read only the public bound."""

    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        absolute = path.absolute()
    except OSError:
        return None, None, ["runtime evidence is unavailable"]
    if stat.S_ISLNK(before.st_mode):
        return None, None, ["runtime evidence must not be a symbolic link"]
    if not stat.S_ISREG(before.st_mode):
        return None, None, ["runtime evidence must be a regular file"]
    if resolved != absolute:
        return None, None, ["runtime evidence path must not traverse a symbolic link"]

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        return None, None, ["secure no-follow evidence reads are unavailable"]
    # O_NONBLOCK prevents a lookup/open race from hanging if a regular file is
    # replaced by a FIFO or device before the authoritative fstat below.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        descriptor, parent_descriptor, final_name = _open_absolute_file_no_follow(
            absolute,
            flags,
        )
    except OSError:
        return None, None, ["runtime evidence cannot be opened safely"]
    try:
        opened_before = os.fstat(descriptor)
        parent_before = os.fstat(parent_descriptor)
        if _stable_stat_state(opened_before) != _stable_stat_state(before):
            return None, None, ["runtime evidence changed while opening"]
        if not stat.S_ISREG(opened_before.st_mode):
            return None, None, ["runtime evidence controls changed while opening"]
        chunks: list[bytes] = []
        remaining = MAX_EVIDENCE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        parent_after = os.fstat(parent_descriptor)
        after_state = _stable_stat_state(opened_after)
        parent_after_state = _stable_stat_state(parent_after)
        if (
            _stable_stat_state(opened_before) != after_state
            or opened_after.st_size != len(raw)
            or _stable_stat_state(parent_before) != parent_after_state
        ):
            return None, None, ["runtime evidence changed while reading"]

        directory_entry = os.stat(
            final_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _stable_stat_state(directory_entry) != after_state:
            return None, None, ["runtime evidence directory entry changed while reading"]

        # Retaining the original parent proves the opened inode stayed in that
        # directory. Re-walking the absolute path proves the directory itself
        # was not renamed away and replaced by a symlink to the same inode.
        try:
            reopened, reopened_parent, reopened_name = _open_absolute_file_no_follow(
                absolute,
                flags,
            )
        except OSError:
            return None, None, ["runtime evidence path changed while reading"]
        try:
            if (
                reopened_name != final_name
                or _stable_stat_state(os.fstat(reopened)) != after_state
                or _stable_stat_state(os.fstat(reopened_parent)) != parent_after_state
            ):
                return None, None, ["runtime evidence path changed while reading"]
        finally:
            os.close(reopened)
            os.close(reopened_parent)
    except OSError:
        return None, None, ["runtime evidence cannot be read safely"]
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)

    try:
        final_metadata = path.lstat()
    except OSError:
        return None, None, ["runtime evidence changed after reading"]
    if _stable_stat_state(final_metadata) != after_state:
        return None, None, ["runtime evidence changed after reading"]
    if len(raw) > MAX_EVIDENCE_BYTES:
        return None, None, ["runtime evidence exceeds the size limit"]
    return raw, opened_after, []


def _metadata_errors(
    contract_metadata: os.stat_result,
    evidence_metadata: os.stat_result,
    *,
    now_epoch: float,
) -> list[str]:
    """Validate ownership, permissions, link count, and write freshness."""

    errors: list[str] = []
    if stat.S_IMODE(evidence_metadata.st_mode) != 0o600:
        errors.append("runtime evidence mode must be exactly 0600")
    if evidence_metadata.st_nlink != 1:
        errors.append("runtime evidence must have exactly one hard link")
    if (
        evidence_metadata.st_uid != contract_metadata.st_uid
        or evidence_metadata.st_gid != contract_metadata.st_gid
    ):
        errors.append("runtime evidence owner must match the protected-host contract")
    file_age = now_epoch - evidence_metadata.st_mtime
    if file_age < 0:
        errors.append("runtime evidence modification time is in the future")
    elif file_age > MAX_EVIDENCE_AGE_SECONDS:
        errors.append("runtime evidence file is stale")
    return errors


def validate_runtime_evidence(
    contract_path: Path,
    expected_sha256: str | None,
    *,
    expected_archives_present: bool | None = None,
    now_epoch: float | None = None,
    boot_id_probe: Callable[[], str | None] = current_boot_id_sha256,
) -> tuple[LoadedRuntimeEvidence | None, list[str]]:
    """Validate the fixed adjacent evidence file and optional contract digest."""

    now = time.time() if now_epoch is None else now_epoch
    try:
        contract_metadata = contract_path.lstat()
    except OSError:
        return None, ["protected-host contract is unavailable"]
    if stat.S_ISLNK(contract_metadata.st_mode):
        return None, ["protected-host contract must not be a symbolic link"]
    if not stat.S_ISREG(contract_metadata.st_mode):
        return None, ["protected-host contract must be a regular file"]
    if stat.S_IMODE(contract_metadata.st_mode) != 0o600:
        return None, ["protected-host contract mode must be exactly 0600"]

    evidence_path = evidence_path_for_contract(contract_path)
    try:
        parent_metadata = evidence_path.parent.lstat()
    except OSError:
        return None, ["runtime evidence directory is unavailable"]
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        return None, ["runtime evidence directory must be a non-symlink directory"]

    raw, evidence_metadata, errors = _read_evidence_file(evidence_path)
    if errors or raw is None or evidence_metadata is None:
        return None, errors or ["runtime evidence is unavailable"]
    errors.extend(
        _metadata_errors(contract_metadata, evidence_metadata, now_epoch=now)
    )
    boot_sha256 = boot_id_probe()
    if boot_sha256 is None:
        errors.append("current boot identity is unavailable")
    else:
        parsed, parse_errors = parse_evidence_bytes(
            raw,
            current_boot_sha256=boot_sha256,
            now_epoch=now,
        )
        errors.extend(parse_errors)
        if (
            parsed is not None
            and evidence_metadata.st_mtime + 1 < parsed.created_unix
        ):
            errors.append("runtime evidence modification predates its creation time")
        if (
            parsed is not None
            and expected_archives_present is not None
            and parsed.archives_present != expected_archives_present
        ):
            errors.append(
                "runtime evidence archive-presence decision does not match "
                "the protected-host contract"
            )
    if errors:
        return None, errors

    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None:
        if not SHA256_RE.fullmatch(expected_sha256):
            return None, ["expected runtime evidence binding is not a lowercase SHA-256"]
        if not hmac.compare_digest(digest, expected_sha256):
            return None, ["runtime evidence binding changed"]
    return LoadedRuntimeEvidence(parsed, digest), []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path, metavar="CONTRACT")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--emit-sha256", action="store_true")
    action.add_argument("--expected-sha256", metavar="SHA256")
    args = parser.parse_args(argv)

    expected_presence, presence_errors = adjacent_contract_presence(args.contract)
    if presence_errors or expected_presence is None:
        for error in presence_errors or [
            "protected-host contract presence is unavailable"
        ]:
            print("ERROR " + error, file=sys.stderr)
        return 1
    expected = None if args.emit_sha256 else args.expected_sha256
    loaded, errors = validate_runtime_evidence(
        args.contract,
        expected,
        expected_archives_present=expected_presence,
    )
    if errors or loaded is None:
        for error in errors or ["runtime evidence validation failed"]:
            print("ERROR " + error, file=sys.stderr)
        return 1
    # Presence is the authorization-sensitive field. Re-read it before any
    # output so a concurrent yes/no change cannot receive a stale binding.
    final_presence, final_presence_errors = adjacent_contract_presence(args.contract)
    if (
        final_presence_errors
        or final_presence is None
        or final_presence != expected_presence
    ):
        print(
            "ERROR protected-host contract presence changed during validation",
            file=sys.stderr,
        )
        return 1
    if args.emit_sha256:
        print(f"{EVIDENCE_HASH_KEY}={loaded.sha256}")
        print(
            "PASS fresh presence-bound protected-host review attestation matches "
            "the adjacent contract; DIGEST EMISSION ONLY, NOT AUTHORIZATION",
            file=sys.stderr,
        )
    else:
        print(
            "PASS fresh presence-bound protected-host review attestation matches "
            "the adjacent contract"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
