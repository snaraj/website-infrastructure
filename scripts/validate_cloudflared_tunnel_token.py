#!/usr/bin/env python3
"""Validate one private cloudflared Tunnel token without disclosing a field."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path


MAX_TOKEN_BYTES = 4097
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ACCOUNT_TAG = re.compile(r"[0-9a-f]{32}\Z")
TOKEN_SHAPE = re.compile(rb"eyJ[A-Za-z0-9+/]+={0,2}\Z")


class InvalidToken(Exception):
    """Collapse every invalid input into one content-neutral failure."""


def duplicate_safe_object(pairs):
    """Reject JSON objects whose duplicate fields could hide authority."""

    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidToken()
        result[key] = value
    return result


# One domain failure type parameterizes the shared no-follow walk helpers.
# The four private-file validators carry byte-identical copies of the helper
# family (pinned by tests/security/test_nofollow_helper_drift.py); fix any
# defect in every copy in the same change.
_WALK_ERROR = InvalidToken


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


def _canonical_file(path_text: str) -> Path:
    """Accept one absolute normalized existing path with no linked ancestor."""

    if (
        not path_text
        or "\x00" in path_text
        or any(ord(character) < 32 for character in path_text)
    ):
        raise InvalidToken()
    supplied = Path(path_text)
    if (
        not supplied.is_absolute()
        or any(part in {".", ".."} for part in supplied.parts)
        or os.path.normcase(path_text) != os.path.normcase(str(supplied))
    ):
        raise InvalidToken()
    if os.name == "nt":
        if re.match(r"^[A-Za-z]:[\\/]", path_text) is None:
            raise InvalidToken()
        if any(":" in part or part.endswith((" ", ".")) for part in supplied.parts[1:]):
            raise InvalidToken()
    absolute = Path(os.path.abspath(os.path.normpath(str(supplied))))
    if os.path.normcase(str(absolute)) != os.path.normcase(str(supplied)):
        raise InvalidToken()
    try:
        resolved = absolute.resolve(strict=True)
        _path_chain(absolute)
    except (OSError, RuntimeError, InvalidToken) as error:
        raise InvalidToken() from error
    if os.path.normcase(str(resolved)) != os.path.normcase(str(absolute)):
        raise InvalidToken()
    return absolute


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


def stable_private_read(path_text: str) -> bytes:
    """Read one owner-private token through a stable same-handle transaction."""

    path = _canonical_file(path_text)
    try:
        before_chain = _path_chain(path)
        before = path.lstat()
    except (OSError, InvalidToken) as error:
        raise InvalidToken() from error
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_link_or_reparse(before)
        or before.st_nlink != 1
        or before.st_size < 80
        or before.st_size > MAX_TOKEN_BYTES
    ):
        raise InvalidToken()
    if os.name == "posix" and (
        before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
    ):
        raise InvalidToken()

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
                raise InvalidToken()
            chunks: list[bytes] = []
            remaining = MAX_TOKEN_BYTES + 1
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
                    raise InvalidToken()
        finally:
            os.close(descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)
    except InvalidToken:
        raise
    except OSError as error:
        raise InvalidToken() from error

    if (
        _path_state(opened_before) != _path_state(opened_after)
        or opened_after.st_size != len(raw)
        or len(raw) > MAX_TOKEN_BYTES
    ):
        raise InvalidToken()
    try:
        after_chain = _path_chain(path)
        after = path.lstat()
        final_resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, InvalidToken) as error:
        raise InvalidToken() from error
    if (
        before_chain != after_chain
        or _path_state(after) != _path_state(opened_after)
        or os.path.normcase(str(final_resolved)) != os.path.normcase(str(path))
    ):
        raise InvalidToken()
    return raw


def canonical_base64(value: str) -> bytes:
    """Decode exactly canonical standard Base64 without normalizing input."""

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidToken() from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise InvalidToken()
    return decoded


def validate() -> None:
    """Validate custody, token grammar, and reviewed account/Tunnel identity."""

    path_text = os.environ.get("CLOUDFLARED_TUNNEL_TOKEN_FILE", "")
    account_digest = os.environ.get("EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256", "")
    tunnel_digest = os.environ.get("EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256", "")
    if SHA256.fullmatch(account_digest) is None or SHA256.fullmatch(tunnel_digest) is None:
        raise InvalidToken()
    raw = stable_private_read(path_text)
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if b"\n" in raw or b"\r" in raw or TOKEN_SHAPE.fullmatch(raw) is None:
        raise InvalidToken()
    decoded = canonical_base64(raw.decode("ascii"))
    try:
        token = json.loads(
            decoded.decode("utf-8"),
            object_pairs_hook=duplicate_safe_object,
            parse_constant=lambda _: (_ for _ in ()).throw(InvalidToken()),
        )
    except (InvalidToken, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidToken() from error
    if not isinstance(token, dict) or set(token) != {"a", "s", "t"}:
        raise InvalidToken()
    account = token.get("a")
    secret = token.get("s")
    tunnel = token.get("t")
    if not all(isinstance(value, str) for value in (account, secret, tunnel)):
        raise InvalidToken()
    if ACCOUNT_TAG.fullmatch(account) is None:
        raise InvalidToken()
    try:
        parsed_tunnel = uuid.UUID(tunnel)
        if parsed_tunnel.int == 0 or str(parsed_tunnel) != tunnel:
            raise InvalidToken()
    except (ValueError, AttributeError) as error:
        raise InvalidToken() from error
    if len(canonical_base64(secret)) < 32:
        raise InvalidToken()
    if hashlib.sha256(account.encode("ascii")).hexdigest() != account_digest:
        raise InvalidToken()
    if hashlib.sha256(tunnel.encode("ascii")).hexdigest() != tunnel_digest:
        raise InvalidToken()


def main(argv: list[str] | None = None) -> int:
    """Expose one generic result and no argument-selected credential surface."""

    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments or sys.flags.isolated != 1:
            raise InvalidToken()
        validate()
    except Exception:
        print("FAIL Cloudflare Tunnel token validation.", file=sys.stderr)
        return 1
    print("PASS Cloudflare Tunnel token identity and structure.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
