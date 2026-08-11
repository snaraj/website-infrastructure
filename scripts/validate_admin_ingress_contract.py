#!/usr/bin/env python3
"""Validate the private admin-ingress contract without echoing identities.

The SSH-only host-ingress guard (owner decision PLAT-DEC-001) must know which
administrative VPN ingress interfaces it covers, but interface names are host
topology and never belong in Git, CI logs, or public evidence. This validator
holds the public SCHEMA — generic keys, closed shapes, fail-closed rules —
while the VALUES live only in an ignored root-owned mode-0600 singly linked
local file created on the Pi. Every diagnostic is a fixed value-free token
(plus a line number); no interface name, count-free wording is deliberate, and
no raw file content ever reaches stdout or stderr.

The existing protected-host contract identifies systemd units and archive
roots; its semantics are service protection during bootstrap, not network
ingress planes, so this is a deliberate separate schema instead of an
overloaded reuse (the handoff's challenge point, answered: reuse would prove
the wrong property).
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

# Public schema: generic capability keys only. The review flag is a human
# attestation that the declared interfaces are exactly the reviewed
# administrative VPN ingress planes and nothing else.
REVIEW_KEY = "ADMIN_INGRESS_REVIEWED"
INTERFACE_KEY = "ADMIN_INGRESS_INTERFACE"
ALLOWED_KEYS = frozenset({REVIEW_KEY, INTERFACE_KEY})

# Linux IFNAMSIZ bounds a name at 15 visible characters. The shape is strict
# lowercase so a copied placeholder, wildcard, glob, or shell fragment can
# never become a live match expression.
INTERFACE_MIN_LENGTH = 2
INTERFACE_MAX_LENGTH = 15
INTERFACE_FIRST_CHARSET = frozenset("abcdefghijklmnopqrstuvwxyz")
INTERFACE_CHARSET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")

# An administrative VPN ingress plane is always a dedicated tunnel-class
# interface. Loopback, physical LAN/WLAN, bridge, and container/CNI interface
# classes are structurally refused so a mistyped declaration can never aim the
# guard at the path local kubectl, the LAN recovery plane, or the pod network
# actually uses. The names are universal Linux conventions, not host facts.
FORBIDDEN_EXACT = frozenset({"lo"})
FORBIDDEN_PREFIXES = (
    "bond", "br", "cali", "cni", "docker", "dummy", "en", "eth", "flannel",
    "kube", "lxc", "tap", "team", "tunl", "veth", "virbr", "vxlan", "wl",
)

# Bounded input keeps a substituted giant or growing file from stalling the
# loader; the interface cap bounds render size without recording the real
# topology count anywhere public.
MAX_CONTRACT_BYTES = 8192
MAX_INTERFACES = 16

# Closed diagnostic vocabulary. Tokens never carry a value; line numbers are
# positions, not content. Anything outside this set is a bug.
TOKENS = frozenset({
    "CONTRACT_UNAVAILABLE",
    "CONTRACT_NOT_REGULAR",
    "CONTRACT_SYMLINK",
    "CONTRACT_MODE_INVALID",
    "CONTRACT_OWNERSHIP_INVALID",
    "CONTRACT_LINK_COUNT_INVALID",
    "CONTRACT_CHANGED_WHILE_READING",
    "CONTRACT_TOO_LARGE",
    "CONTRACT_ENCODING_INVALID",
    "LINE_SHAPE_INVALID",
    "KEY_UNSUPPORTED",
    "VALUE_WHITESPACE_AMBIGUOUS",
    "REVIEW_FLAG_MISSING",
    "REVIEW_FLAG_DUPLICATE",
    "REVIEW_FLAG_INVALID",
    "REVIEW_INCOMPLETE",
    "INTERFACE_MISSING",
    "INTERFACE_DUPLICATE",
    "INTERFACE_SHAPE_INVALID",
    "INTERFACE_CLASS_FORBIDDEN",
    "INTERFACE_LIMIT_EXCEEDED",
    "EXAMPLE_MUST_STAY_UNREVIEWED",
    "EXAMPLE_MUST_DECLARE_NO_VALUE",
})


def interface_errors(value: str, line_number: int) -> list[str]:
    """Return value-free shape/class tokens for one declared interface."""

    errors: list[str] = []
    if (
        not INTERFACE_MIN_LENGTH <= len(value) <= INTERFACE_MAX_LENGTH
        or value[0] not in INTERFACE_FIRST_CHARSET
        or any(character not in INTERFACE_CHARSET for character in value)
    ):
        errors.append(f"INTERFACE_SHAPE_INVALID line {line_number}")
        return errors
    if value in FORBIDDEN_EXACT or value.startswith(FORBIDDEN_PREFIXES):
        errors.append(f"INTERFACE_CLASS_FORBIDDEN line {line_number}")
    return errors


def parse_contract_text(text: str) -> tuple[tuple[str, ...] | None, list[str]]:
    """Parse the exact KEY=value grammar; ambiguity is rejection, not repair."""

    errors: list[str] = []
    review_values: list[str] = []
    interfaces: list[str] = []
    seen_interfaces: set[str] = set()
    for line_number, line in enumerate(text.split("\n"), start=1):
        if line == "" or line.startswith("#"):
            continue
        # Leading/trailing whitespace and control bytes make a value visually
        # ambiguous and are how lookalike declarations smuggle divergence, so
        # the raw line must be exactly KEY=value.
        if line != line.strip() or any(ord(char) < 32 for char in line):
            errors.append(f"LINE_SHAPE_INVALID line {line_number}")
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or not value:
            errors.append(f"LINE_SHAPE_INVALID line {line_number}")
            continue
        # A key is shape, not vocabulary: internal whitespace or a stray
        # character is a malformed line, reported before key lookup so a
        # lookalike key cannot masquerade as merely "unsupported".
        if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_" for character in key):
            errors.append(f"LINE_SHAPE_INVALID line {line_number}")
            continue
        if key not in ALLOWED_KEYS:
            errors.append(f"KEY_UNSUPPORTED line {line_number}")
            continue
        if any(character.isspace() for character in value):
            errors.append(f"VALUE_WHITESPACE_AMBIGUOUS line {line_number}")
            continue
        if key == REVIEW_KEY:
            if review_values:
                errors.append(f"REVIEW_FLAG_DUPLICATE line {line_number}")
                continue
            if value not in {"yes", "no"}:
                errors.append(f"REVIEW_FLAG_INVALID line {line_number}")
                continue
            review_values.append(value)
            continue
        shape_errors = interface_errors(value, line_number)
        if shape_errors:
            errors.extend(shape_errors)
            continue
        if value in seen_interfaces:
            errors.append(f"INTERFACE_DUPLICATE line {line_number}")
            continue
        if len(interfaces) >= MAX_INTERFACES:
            errors.append(f"INTERFACE_LIMIT_EXCEEDED line {line_number}")
            continue
        seen_interfaces.add(value)
        interfaces.append(value)

    if not review_values:
        errors.append("REVIEW_FLAG_MISSING")
    elif review_values[0] != "yes":
        errors.append("REVIEW_INCOMPLETE")
    if not interfaces:
        errors.append("INTERFACE_MISSING")
    if errors:
        return None, errors
    return tuple(interfaces), []


def metadata_errors(
    *,
    is_symlink: bool,
    is_regular: bool,
    mode: int,
    uid: int,
    gid: int,
    nlink: int,
) -> list[str]:
    """Pure fail-closed policy over file metadata, testable without root."""

    if is_symlink:
        return ["CONTRACT_SYMLINK"]
    if not is_regular:
        return ["CONTRACT_NOT_REGULAR"]
    errors: list[str] = []
    if mode != 0o600:
        errors.append("CONTRACT_MODE_INVALID")
    if uid != 0 or gid != 0:
        errors.append("CONTRACT_OWNERSHIP_INVALID")
    if nlink != 1:
        errors.append("CONTRACT_LINK_COUNT_INVALID")
    return errors


def _stat_errors(metadata: os.stat_result) -> list[str]:
    return metadata_errors(
        is_symlink=stat.S_ISLNK(metadata.st_mode),
        is_regular=stat.S_ISREG(metadata.st_mode),
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        nlink=metadata.st_nlink,
    )


def _state(metadata: os.stat_result) -> tuple:
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


def _open_no_follow(path: Path) -> int:
    """Open the absolute path component-wise with O_NOFOLLOW at every step."""

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
        raise OSError("secure component-wise opens are unavailable")
    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open("/", directory_flags)
    try:
        for component in path.parts[1:-1]:
            if component in {"", ".", ".."}:
                raise OSError("unsafe path component")
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        flags = os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        file_descriptor = os.open(path.name, flags, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    return file_descriptor


def read_contract_bytes(path: Path) -> tuple[bytes | None, list[str]]:
    """Read the contract with race detection; partial or swapped reads fail."""

    try:
        initial = path.lstat()
    except OSError:
        return None, ["CONTRACT_UNAVAILABLE"]
    errors = _stat_errors(initial)
    if errors:
        return None, errors
    try:
        descriptor = _open_no_follow(path)
    except OSError:
        return None, ["CONTRACT_UNAVAILABLE"]
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            return None, ["CONTRACT_CHANGED_WHILE_READING"]
        errors = _stat_errors(opened)
        if errors:
            return None, errors
        chunks: list[bytes] = []
        remaining = MAX_CONTRACT_BYTES + 1
        while remaining:
            try:
                chunk = os.read(descriptor, remaining)
            except OSError:
                return None, ["CONTRACT_UNAVAILABLE"]
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        # A single identical before/after descriptor state proves no rewrite,
        # truncation, relink, or ownership flip happened mid-read; a short or
        # grown read is a partial file and always fails closed.
        if _state(after) != _state(opened) or after.st_size != len(raw):
            return None, ["CONTRACT_CHANGED_WHILE_READING"]
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError:
        return None, ["CONTRACT_CHANGED_WHILE_READING"]
    if _state(final) != _state(after):
        return None, ["CONTRACT_CHANGED_WHILE_READING"]
    if len(raw) > MAX_CONTRACT_BYTES:
        return None, ["CONTRACT_TOO_LARGE"]
    return raw, []


def load_admin_ingress_contract(path: Path) -> tuple[tuple[str, ...] | None, list[str]]:
    """Securely load and fully validate the private contract file."""

    raw, errors = read_contract_bytes(path)
    if errors:
        return None, errors
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        return None, ["CONTRACT_ENCODING_INVALID"]
    return parse_contract_text(text)


def example_errors(text: str) -> list[str]:
    """Require the tracked template to stay inert: unreviewed and value-free."""

    errors: list[str] = []
    review_lines = [
        line for line in text.split("\n") if line == f"{REVIEW_KEY}=no"
    ]
    if len(review_lines) != 1 or f"{REVIEW_KEY}=yes" in text:
        errors.append("EXAMPLE_MUST_STAY_UNREVIEWED")
    for line in text.split("\n"):
        if line.startswith(f"{INTERFACE_KEY}="):
            errors.append("EXAMPLE_MUST_DECLARE_NO_VALUE")
            break
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"CONTRACT", "EXAMPLE"}:
        print(
            "usage: validate_admin_ingress_contract.py CONTRACT|EXAMPLE <path>",
            file=sys.stderr,
        )
        return 2
    path = Path(argv[2])
    if argv[1] == "EXAMPLE":
        try:
            errors = example_errors(path.read_text(encoding="utf-8"))
        except OSError:
            errors = ["CONTRACT_UNAVAILABLE"]
        subject = "example"
    else:
        interfaces, errors = load_admin_ingress_contract(path)
        subject = "contract"
        # The interface tuple is for library callers (the semantic verifier);
        # the CLI never prints it, by construction.
        del interfaces
    for error in errors:
        print(f"admin-ingress-contract: FAIL {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"admin-ingress-contract: PASS reviewed-admin-ingress-{subject}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
