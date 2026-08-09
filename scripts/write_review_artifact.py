#!/usr/bin/env python3
"""Write one bounded review artifact without following or replacing a path."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


MAX_ARTIFACT_BYTES = 1024 * 1024


class ArtifactError(ValueError):
    """The requested review artifact cannot be created safely."""


def read_bounded_stdin(*, normalize_crlf: bool = False) -> bytes:
    """Read at most the closed artifact limit plus one byte."""

    raw = sys.stdin.buffer.read(MAX_ARTIFACT_BYTES + 1)
    if b"\r" in raw:
        if not normalize_crlf or b"\r" in raw.replace(b"\r\n", b""):
            raise ArtifactError("review artifact contains noncanonical carriage returns")
        raw = raw.replace(b"\r\n", b"\n")
    if (
        not raw
        or len(raw) > MAX_ARTIFACT_BYTES
        or not raw.endswith(b"\n")
    ):
        raise ArtifactError("review artifact must be bounded LF-terminated text")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise ArtifactError("review artifact must be UTF-8") from error
    if any(
        (ord(character) < 32 and character not in {"\n", "\t"})
        or 127 <= ord(character) <= 159
        or ord(character) in {0x2028, 0x2029}
        for character in text
    ):
        raise ArtifactError("review artifact contains forbidden control characters")
    return raw


def read_bounded_file(path: Path) -> bytes:
    """Read one stable regular input without following a symlink."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )
    try:
        before = absolute.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > MAX_ARTIFACT_BYTES
            or absolute.resolve(strict=True) != absolute
        ):
            raise ArtifactError("review artifact input must be one bounded regular file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(absolute, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(before):
                raise ArtifactError("review artifact input changed while opening")
            chunks = []
            remaining = MAX_ARTIFACT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            finished = os.fstat(descriptor)
            if identity(finished) != identity(opened) or len(raw) != opened.st_size:
                raise ArtifactError("review artifact input changed while reading")
        finally:
            os.close(descriptor)
        after = absolute.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or identity(after) != identity(opened)
            or absolute.resolve(strict=True) != absolute
        ):
            raise ArtifactError("review artifact input path changed while reading")
    except ArtifactError:
        raise
    except (OSError, RuntimeError) as error:
        raise ArtifactError("review artifact input cannot be read safely") from error
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise ArtifactError("review artifact input must be LF-terminated text")
    try:
        raw.decode("utf-8")
    except UnicodeError as error:
        raise ArtifactError("review artifact input must be UTF-8") from error
    return raw


def write_exclusive(output: Path, raw: bytes) -> None:
    """Create one mode-0600 regular file beneath one real parent directory."""

    absolute = Path(os.path.abspath(os.fspath(output)))
    parent = absolute.parent
    try:
        parent_before = parent.lstat()
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or parent.resolve(strict=True) != parent
        ):
            raise ArtifactError("review artifact parent must be a real directory")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(absolute, flags, 0o600)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ArtifactError("review artifact output is not a regular file")
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise ArtifactError("review artifact write made no progress")
                offset += written
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            finished = os.fstat(descriptor)
            if (
                finished.st_dev != opened.st_dev
                or finished.st_ino != opened.st_ino
                or finished.st_size != len(raw)
                or not stat.S_ISREG(finished.st_mode)
            ):
                raise ArtifactError("review artifact changed while writing")
        finally:
            os.close(descriptor)
        after = absolute.lstat()
        parent_after = parent.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_dev != finished.st_dev
            or after.st_ino != finished.st_ino
            or after.st_size != len(raw)
            or parent_before.st_dev != parent_after.st_dev
            or parent_before.st_ino != parent_after.st_ino
            or parent.resolve(strict=True) != parent
            or absolute.resolve(strict=True) != absolute
        ):
            raise ArtifactError("review artifact path changed while writing")
    except ArtifactError:
        raise
    except (OSError, RuntimeError) as error:
        raise ArtifactError("review artifact cannot be created exclusively") from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--input", type=Path)
    parser.add_argument(
        "--normalize-crlf",
        action="store_true",
        help="normalize a trusted Windows text producer before exclusive writing",
    )
    args = parser.parse_args(argv)
    try:
        raw = (
            read_bounded_file(args.input)
            if args.input is not None
            else read_bounded_stdin(normalize_crlf=args.normalize_crlf)
        )
        write_exclusive(
            args.output, raw
        )
    except ArtifactError:
        print("ERROR review artifact could not be written safely", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
