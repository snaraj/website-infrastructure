#!/usr/bin/env python3
"""Create one bounded review patch without mutating the repository."""

from __future__ import annotations

import argparse
import difflib
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath


MAX_RELEASE_BYTES = 65536
RELEASE_PATH_RE = re.compile(
    r"kubernetes/websites/(?:naranjo-online|lidersea-com)/release[.]yaml\Z"
)


class PatchError(ValueError):
    """The requested patch is not one safe canonical release edit."""


def read_regular_lf(path: Path) -> str:
    """Read one stable, bounded, non-symlink UTF-8/LF file."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )
    try:
        before = absolute.lstat()
        if not stat.S_ISREG(before.st_mode) or absolute.resolve(strict=True) != absolute:
            raise PatchError("release patch input must be a regular non-symlink file")
        if before.st_size <= 0 or before.st_size > MAX_RELEASE_BYTES:
            raise PatchError("release patch input size is outside the bounded contract")
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
                raise PatchError("release patch input changed while opening")
            chunks = []
            remaining = MAX_RELEASE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            opened_after = os.fstat(descriptor)
            if identity(opened_after) != identity(opened) or len(raw) != opened.st_size:
                raise PatchError("release patch input changed while reading")
        finally:
            os.close(descriptor)
        after = absolute.lstat()
    except PatchError:
        raise
    except (OSError, RuntimeError) as error:
        raise PatchError("release patch input cannot be read safely") from error
    if (
        not stat.S_ISREG(after.st_mode)
        or identity(before) != identity(after)
        or absolute.resolve(strict=True) != absolute
    ):
        raise PatchError("release patch input changed while reading")
    if not raw or len(raw) > MAX_RELEASE_BYTES or not raw.endswith(b"\n") or b"\r" in raw:
        raise PatchError("release patch input must be bounded UTF-8/LF text")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise PatchError("release patch input must be UTF-8") from error
    if any(
        (ord(character) < 32 and character != "\n")
        or 127 <= ord(character) <= 159
        or ord(character) in {0x2028, 0x2029}
        for character in text
    ):
        raise PatchError("release patch input contains forbidden control characters")
    return text


def validate_relative_path(value: str) -> str:
    """Accept only one of the two closed repository release paths."""

    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not RELEASE_PATH_RE.fullmatch(value):
        raise PatchError("release patch path is outside the closed allowlist")
    return value


def create_patch(original: Path, candidate: Path, relative: str, output: Path) -> None:
    """Write an exclusive mode-0600 unified patch for one exact path."""

    relative = validate_relative_path(relative)
    original_text = read_regular_lf(original)
    candidate_text = read_regular_lf(candidate)
    if original_text == candidate_text:
        raise PatchError("release patch candidate is unchanged")
    patch = "".join(
        difflib.unified_diff(
            original_text.splitlines(keepends=True),
            candidate_text.splitlines(keepends=True),
            fromfile="a/" + relative,
            tofile="b/" + relative,
            lineterm="\n",
        )
    ).encode("utf-8")
    if not patch or len(patch) > MAX_RELEASE_BYTES:
        raise PatchError("release patch output is empty or oversized")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(output), flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(patch)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise PatchError("release patch output cannot be created exclusively") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--relative", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        create_patch(args.original, args.candidate, args.relative, args.output)
    except PatchError:
        print("ERROR release review patch could not be created safely", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
