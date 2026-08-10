#!/usr/bin/env python3
"""Create one validated Kubernetes API encryption config without displaying its key."""

from __future__ import annotations

import argparse
import base64
import importlib.util
import os
import re
import stat
import sys
from pathlib import Path


KEY_NAME_RE = re.compile(r"key-[0-9]{4}-[0-9]{2}")
KEY_NAME_SENTINEL = "REPLACE_KEY_NAME"
KEY_SENTINEL = "REPLACE_BASE64_32_BYTE_KEY"
MAX_SOURCE_BYTES = 128 * 1024


class GenerationError(ValueError):
    """Represent a closed generation failure without secret-bearing detail."""


def _load_validator(path: Path):
    spec = importlib.util.spec_from_file_location("exact_encryption_config_validator", path)
    if spec is None or spec.loader is None:
        raise GenerationError()
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "validate", None)):
        raise GenerationError()
    return module


def render_config(template: str, key_name: str, key_bytes: bytes, validator) -> str:
    """Render and validate the exact template while keeping key bytes in memory only."""

    if KEY_NAME_RE.fullmatch(key_name) is None or len(key_bytes) != 32:
        raise GenerationError()
    if template.count(KEY_NAME_SENTINEL) != 1 or template.count(KEY_SENTINEL) != 1:
        raise GenerationError()
    encoded = base64.b64encode(key_bytes).decode("ascii")
    rendered = template.replace(KEY_NAME_SENTINEL, key_name).replace(KEY_SENTINEL, encoded)
    if validator.validate(rendered):
        raise GenerationError()
    return rendered


def _read_bounded_regular_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise GenerationError()
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(16384, MAX_SOURCE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise GenerationError()
        content = b"".join(chunks)
        if len(content) > MAX_SOURCE_BYTES:
            raise GenerationError()
        return content.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise GenerationError() from error
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    created_identity = None
    try:
        descriptor = os.open(path, flags, 0o600)
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise GenerationError()
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            # The protected ceremony is Linux-only. This branch keeps the
            # descriptor/exclusivity behavior testable on Windows workstations.
            os.chmod(path, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise GenerationError()
            view = view[written:]
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        if (final.st_dev, final.st_ino) != created_identity or final.st_nlink != 1:
            raise GenerationError()
    except (OSError, GenerationError) as error:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created_identity is not None:
            try:
                current = os.lstat(path)
                if (current.st_dev, current.st_ino) == created_identity:
                    os.unlink(path)
            except OSError:
                pass
        raise GenerationError() from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if os.name == "posix":
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("validator", type=Path)
    parser.add_argument("template", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("key_name")
    args = parser.parse_args(argv)

    try:
        if not all(path.is_absolute() for path in (args.validator, args.template, args.output)):
            raise GenerationError()
        validator = _load_validator(args.validator)
        template = _read_bounded_regular_file(args.template)
        rendered = render_config(template, args.key_name, os.urandom(32), validator)
        _write_exclusive(args.output, rendered.encode("utf-8"))
    except Exception:
        print("FAIL API encryption config generation.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
