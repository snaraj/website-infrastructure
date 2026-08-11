#!/usr/bin/env python3
"""Validate one protected, embedded-credential kubeconfig snapshot offline."""

from __future__ import annotations

import base64
import binascii
import hmac
import ipaddress
import json
import os
import re
import stat
import sys
import urllib.parse
from pathlib import Path
from typing import Any


KUBECONFIG_SNAPSHOT_ENV = "KUBECONFIG_SNAPSHOT_FILE"
MAX_KUBECONFIG_BYTES = 256 * 1024
MAX_EMBEDDED_BYTES = 128 * 1024

TOP_LEVEL_KEYS = {
    "apiVersion",
    "kind",
    "current-context",
    "clusters",
    "users",
    "contexts",
    "preferences",
}
NAMED_ENTRY_KEYS = {"name"}
CLUSTER_KEYS = {"server", "certificate-authority-data"}
CLUSTER_KEYS_WITH_TLS_NAME = CLUSTER_KEYS | {"tls-server-name"}
USER_KEYS = {"client-certificate-data", "client-key-data"}
CONTEXT_KEYS = {"cluster", "user"}
CONTEXT_KEYS_WITH_NAMESPACE = CONTEXT_KEYS | {"namespace"}

SAFE_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._@-]{0,126}[A-Za-z0-9])?\Z")
DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
NAMESPACE_RE = DNS_LABEL_RE


class SnapshotError(ValueError):
    """Represent every invalid input without exposing its protected values."""


class DuplicateKeyError(SnapshotError):
    """Reject JSON objects that would otherwise overwrite an earlier key."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError()
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise SnapshotError()


def _exact_object(value: Any, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise SnapshotError()
    return value


def _one_entry(value: Any) -> dict[str, Any]:
    if type(value) is not list or len(value) != 1 or type(value[0]) is not dict:
        raise SnapshotError()
    return value[0]


def _safe_name(value: Any) -> str:
    if type(value) is not str or SAFE_NAME_RE.fullmatch(value) is None:
        raise SnapshotError()
    return value


def _valid_dns_name(value: Any) -> str:
    if type(value) is not str or len(value) > 253 or not value:
        raise SnapshotError()
    labels = value.split(".")
    if any(DNS_LABEL_RE.fullmatch(label) is None for label in labels):
        raise SnapshotError()
    return value


def _canonical_base64(value: Any) -> bytes:
    if type(value) is not str or not value:
        raise SnapshotError()
    try:
        raw = value.encode("ascii")
        decoded = base64.b64decode(raw, validate=True)
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise SnapshotError() from error
    if not decoded or len(decoded) > MAX_EMBEDDED_BYTES:
        raise SnapshotError()
    if base64.b64encode(decoded).decode("ascii") != value:
        raise SnapshotError()
    return decoded


def _canonical_pem(
    encoded: Any,
    allowed_labels: tuple[str, ...],
    minimum_der_bytes: int,
) -> bytes:
    pem = _canonical_base64(encoded)
    try:
        text = pem.decode("ascii")
    except UnicodeError as error:
        raise SnapshotError() from error
    if "\r" in text or not text.endswith("\n"):
        raise SnapshotError()
    lines = text[:-1].split("\n")
    if len(lines) < 3:
        raise SnapshotError()

    selected_label = None
    for label in allowed_labels:
        if lines[0] == "-----BEGIN " + label + "-----":
            selected_label = label
            break
    if selected_label is None or lines[-1] != "-----END " + selected_label + "-----":
        raise SnapshotError()

    body = "".join(lines[1:-1])
    try:
        der = base64.b64decode(body.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise SnapshotError() from error
    if (
        len(der) < minimum_der_bytes
        or len(der) > MAX_EMBEDDED_BYTES
        or not der.startswith(b"\x30")
    ):
        raise SnapshotError()
    canonical_body = base64.b64encode(der).decode("ascii")
    canonical_lines = [
        canonical_body[offset : offset + 64]
        for offset in range(0, len(canonical_body), 64)
    ]
    expected = "\n".join(
        [
            "-----BEGIN " + selected_label + "-----",
            *canonical_lines,
            "-----END " + selected_label + "-----",
            "",
        ]
    )
    if text != expected:
        raise SnapshotError()
    return pem


def _validate_server(value: Any) -> bool:
    if type(value) is not str or not value or value != value.strip():
        raise SnapshotError()
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise SnapshotError() from error
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or port == 0
    ):
        raise SnapshotError()
    hostname = parsed.hostname
    if any(ord(character) > 127 for character in hostname):
        raise SnapshotError()
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
        if all(character in "0123456789." for character in hostname):
            raise SnapshotError()
        _valid_dns_name(hostname)
        canonical_host = hostname
    else:
        canonical_host = address.compressed
        if address.version == 6:
            canonical_host = "[" + canonical_host + "]"
    canonical_netloc = canonical_host
    if port is not None:
        canonical_netloc += ":" + str(port)
    if parsed.netloc != canonical_netloc or value != "https://" + canonical_netloc:
        raise SnapshotError()
    return address is not None


def _validate_tls_server_name(value: Any) -> None:
    name = _valid_dns_name(value)
    try:
        ipaddress.ip_address(name)
    except ValueError:
        if all(character in "0123456789." for character in name):
            raise SnapshotError()
    else:
        raise SnapshotError()


def parse_snapshot(raw: bytes) -> None:
    """Validate the complete closed JSON kubeconfig schema in memory."""

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except DuplicateKeyError:
        raise
    except (UnicodeError, json.JSONDecodeError, SnapshotError) as error:
        raise SnapshotError() from error

    root = _exact_object(document, TOP_LEVEL_KEYS)
    if root["apiVersion"] != "v1" or type(root["apiVersion"]) is not str:
        raise SnapshotError()
    if root["kind"] != "Config" or type(root["kind"]) is not str:
        raise SnapshotError()
    if type(root["preferences"]) is not dict or root["preferences"]:
        raise SnapshotError()

    cluster_entry = _one_entry(root["clusters"])
    user_entry = _one_entry(root["users"])
    context_entry = _one_entry(root["contexts"])
    _exact_object(cluster_entry, NAMED_ENTRY_KEYS | {"cluster"})
    _exact_object(user_entry, NAMED_ENTRY_KEYS | {"user"})
    _exact_object(context_entry, NAMED_ENTRY_KEYS | {"context"})

    cluster_name = _safe_name(cluster_entry["name"])
    user_name = _safe_name(user_entry["name"])
    context_name = _safe_name(context_entry["name"])
    current_context = _safe_name(root["current-context"])

    cluster = cluster_entry["cluster"]
    if type(cluster) is not dict or frozenset(cluster) not in {
        frozenset(CLUSTER_KEYS),
        frozenset(CLUSTER_KEYS_WITH_TLS_NAME),
    }:
        raise SnapshotError()
    server_uses_ip = _validate_server(cluster["server"])
    ca_pem = _canonical_pem(
        cluster["certificate-authority-data"],
        ("CERTIFICATE",),
        64,
    )
    if "tls-server-name" in cluster:
        if not server_uses_ip:
            raise SnapshotError()
        _validate_tls_server_name(cluster["tls-server-name"])

    user = _exact_object(user_entry["user"], USER_KEYS)
    client_pem = _canonical_pem(
        user["client-certificate-data"],
        ("CERTIFICATE",),
        64,
    )
    _canonical_pem(
        user["client-key-data"],
        ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"),
        32,
    )
    if hmac.compare_digest(ca_pem, client_pem):
        raise SnapshotError()

    context = context_entry["context"]
    if type(context) is not dict or frozenset(context) not in {
        frozenset(CONTEXT_KEYS),
        frozenset(CONTEXT_KEYS_WITH_NAMESPACE),
    }:
        raise SnapshotError()
    if (
        type(context["cluster"]) is not str
        or type(context["user"]) is not str
        or not hmac.compare_digest(context["cluster"], cluster_name)
        or not hmac.compare_digest(context["user"], user_name)
        or not hmac.compare_digest(current_context, context_name)
    ):
        raise SnapshotError()
    if "namespace" in context:
        namespace = context["namespace"]
        if type(namespace) is not str or NAMESPACE_RE.fullmatch(namespace) is None:
            raise SnapshotError()


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


def _path_chain(path: Path) -> tuple[tuple[str, tuple[int, ...]], ...]:
    """Snapshot every ancestor so directory replacement cannot pass silently."""

    result: list[tuple[str, tuple[int, ...]]] = []
    for component in reversed((path, *path.parents)):
        metadata = component.lstat()
        if _is_link_or_reparse(metadata):
            raise _WALK_ERROR()
        result.append((os.path.normcase(str(component)), _path_state(metadata)))
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
    if (
        not path_text
        or "\x00" in path_text
        or any(ord(character) < 32 for character in path_text)
    ):
        raise SnapshotError()
    supplied = Path(path_text)
    if not supplied.is_absolute() or any(part in {".", ".."} for part in supplied.parts):
        raise SnapshotError()
    if os.name == "nt":
        if not re.match(r"^[A-Za-z]:[\\/]", path_text):
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
    """Read a single-link private file and bind bytes to the stable path entry."""

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
        or before.st_size > MAX_KUBECONFIG_BYTES
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
            remaining = MAX_KUBECONFIG_BYTES + 1
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
        or len(raw) > MAX_KUBECONFIG_BYTES
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


def validate() -> None:
    path_text = os.environ.get(KUBECONFIG_SNAPSHOT_ENV, "")
    parse_snapshot(read_snapshot(path_text))


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments or sys.flags.isolated != 1:
            raise SnapshotError()
        validate()
    except Exception:
        print("FAIL Kubernetes kubeconfig snapshot validation.", file=sys.stderr)
        return 1
    print("PASS Kubernetes kubeconfig snapshot validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
