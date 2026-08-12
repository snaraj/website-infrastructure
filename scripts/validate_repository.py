#!/usr/bin/env python3
"""Dependency-free, credential-free repository policy checks."""

import argparse
import fnmatch
import hashlib
import ipaddress
import os
import re
import stat
import subprocess
import sys
from pathlib import Path


# Tests load this file directly from its path, so make the sibling release
# policy module importable without depending on a caller's working directory.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from validate_image_release import repository_errors as image_release_errors
from validate_release_state import (
    CanonicalYamlError,
    RELEASE_CONTRACTS,
    ZERO_DIGEST,
    _parse_simple_mapping,
    canonical_scalar,
    load_helm_release,
    load_parent_suspension,
    load_simple_mapping_file,
)
from validate_release_transition import (
    CLOUDFLARE_LOCK_FILES,
    CLOUDFLARE_TERRAFORM_REVIEW_FILES,
    CLOUDFLARE_TERRAFORM_SOURCE_FILES,
    STATE as TRANSITION_RELEASE_STATE,
    classify as classify_release_transition,
    cloudflare_phase_contract_errors,
    contains_secret_document,
    load_admission_suspension,
    sops_recipient_from_config,
    sops_secret_errors,
    tunnel_secret_errors,
)
from validate_signature_policy import (
    admission_kustomization_errors,
    flux_sync_errors,
    flux_system_kustomization_errors,
    reconciliation_kustomization_errors,
    signature_policy_action,
    signature_policy_errors,
    signature_policy_kustomization_errors,
)


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".conf", ".css", ".env", ".example", ".go", ".hcl", ".html", ".js",
    ".json", ".lock", ".md", ".mjs", ".rego", ".service", ".sh",
    ".svelte", ".tf", ".timer", ".toml", ".tpl", ".ts", ".txt",
    ".yaml", ".yml",
}
FORBIDDEN_LOCAL_ONLY_COMPONENTS = {
    ".artifacts", ".cache", ".idea", ".ssh", ".terraform", ".vscode",
    "__pycache__", "coverage", "local-evidence", "node_modules", "results",
}
FORBIDDEN_LOCAL_ONLY_FILE_PATTERNS = {
    ".ds_store", ".env", ".env.*", ".terraformrc", "*.7z", "*.age", "*.agekey",
    "*.asc", "*.auto.tfvars", "*.auto.tfvars.json", "*.backend.hcl", "*.bak",
    "*.bin", "*.blob", "*.bz2", "*.dec.*", "*.enc", "*.encrypted", "*.gpg", "*.key",
    "*.kubeconfig", "*.p12", "*.pem", "*.pfx", "*.pgp", "*.plaintext.*", "*.rar",
    "*.pyc", "*.pyd", "*.pyo", "*.sarif", "*.sbom.json", "*.sops.env",
    "*.sops.ini", "*.sops.json", "*.swo", "*.swp", "*.tar", "*.tar.*",
    "*.tfbackend", "*.tfplan", "*.tfplan.json", "*.tgz", "*.tmp", "*.token",
    "*.xz", "*.zip", "*.zst", "*~", "cloudflared-token*", "crash.*.log",
    "crash.log", "id_ed25519*", "id_rsa*", "keys.txt", "known_hosts*",
    "kubeconfig*", "api-encryption-config.yaml", "encryption-config.yaml.local",
    "powershell_transcript.*.txt", "*.transcript.txt", "thumbs.db", "terraform.rc",
    "terraform.tfvars", "terraform.tfvars.json",
}
FORBIDDEN_LOCAL_ONLY_EXACT_NAMES = {
    "bootstrap/pi/cni-manifest.local.yaml",
    "bootstrap/pi/decisions.env.local",
    "bootstrap/pi/encryption-config.yaml.local",
    "bootstrap/pi/images.lock.local",
    "bootstrap/pi/ingress-guard/admin-ingress.env.local",
    "bootstrap/pi/kubeadm-config.yaml.local",
    "bootstrap/pi/protected-legacy-runtime-evidence.local",
    "bootstrap/pi/protected-services.env.local",
}
# Website source now lives in the standalone site repositories; no generated
# frontend output (or placeholder for it) is permitted anywhere in this tree.
ALLOWED_DIST_PATHS = set()
ALLOWED_DIST_DIRECTORIES = {
    path.rsplit("/", 1)[0] for path in ALLOWED_DIST_PATHS
}
SKIP_PARTS = {".git", "dist", *FORBIDDEN_LOCAL_ONLY_COMPONENTS}
MEDIA_SCAN_SKIP_PARTS = {".git", "dist", *FORBIDDEN_LOCAL_ONLY_COMPONENTS}
MEDIA_SUFFIXES = {
    ".aac", ".avif", ".avi", ".bmp", ".flac", ".gif", ".heic", ".heif",
    ".ico", ".jpeg", ".jpg", ".m4a", ".mkv", ".mov", ".mp3", ".mp4",
    ".ogg", ".ogv", ".otf", ".png", ".svg", ".tif", ".tiff", ".ttf",
    ".wav", ".webm", ".webp", ".woff", ".woff2",
}
# Version-controlled UI assets must remain genuinely small. The wider ceiling
# catches a renamed/archive payload before it can bloat Git or a container build.
MAX_UI_ASSET_BYTES = 1 * 1024 * 1024
MAX_REPOSITORY_FILE_BYTES = 2 * 1024 * 1024
# The complete public working tree is also bounded so split, renamed, encrypted,
# or base64 chunks cannot grow without limit while each file remains small.
MAX_PUBLIC_REPOSITORY_BYTES = 16 * 1024 * 1024
# Source and generated UI trees also have an aggregate ceiling so many small
# files cannot bypass the per-file media boundary.
MAX_ASSET_TREE_BYTES = 2 * 1024 * 1024
# Kubernetes data objects are configuration, not a byte store. This repository
# ceiling sits far below the API limit and is backed by admission controls.
MAX_KUBERNETES_DATA_OBJECT_BYTES = 128 * 1024
MEDIA_MAGIC_PREFIXES = (
    b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"OggS",
    b"fLaC", b"ID3", b"\x1aE\xdf\xa3", b"\x00\x01\x00\x00", b"wOFF",
    b"wOF2", b"OTTO",
)
# The one deliberate exception to the no-media rule: the self-hosted coverage
# badge. It stays reviewable because it must satisfy the strict text contract
# below (ASCII only, tiny, fixed element set, no scripts/links/embedded data),
# and the pull-request coverage gate additionally proves the committed bytes
# equal a deterministic re-render of docs/badges/coverage.json. Anything that
# misses either bar is rejected exactly like any other media file.
APPROVED_TEXT_BADGE_PATHS = {"docs/badges/coverage.svg"}
MAX_TEXT_BADGE_BYTES = 2048
# The badge must open with this exact envelope; the namespace URI is the only
# URL-shaped byte sequence permitted anywhere in the file, so the forbidden
# fragment scan below runs on everything after this verbatim prefix.
BADGE_REQUIRED_PREFIX = '<svg xmlns="http://www.w3.org/2000/svg" '
BADGE_FORBIDDEN_FRAGMENTS = (
    "base64", "data:", "script", "href", "xlink", "import", "foreignobject",
    "<image", "<use", "url(", "&#", "http", "<!", "<?",
)
BADGE_ALLOWED_ELEMENTS = {"svg", "title", "g", "rect", "text"}
OPAQUE_ARTIFACT_MAGIC_PREFIXES = (
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd", b"BZh", b"Salted__",
    b"-----BEGIN AGE ENCRYPTED FILE-----", b"age-encryption.org/v1",
    b"-----BEGIN PGP MESSAGE-----", b"U2FsdGVkX1",
)
ALLOWED_CLOUDFLARE_RESOURCES = {
    "cloudflare_dns_record",
    "cloudflare_zero_trust_gateway_policy",
    "cloudflare_zero_trust_tunnel_cloudflared",
    "cloudflare_zero_trust_tunnel_cloudflared_config",
    "cloudflare_zero_trust_tunnel_cloudflared_route",
    "cloudflare_zone_setting",
}
APPROVED_SOPS_SECRET_PATHS = {
    "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml": (
        "pi-websites-tunnel-token"
    ),
}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST_IMAGE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
# One closed tuple drives every site-specific release check so adding a site
# cannot silently leave image publication, admission, or activation asymmetric.
# The third element is the publisher workflow inside each STANDALONE site
# repository (tag-triggered); it feeds the pinned signature identities.
SITE_RELEASE_CONTRACTS = (
    ("naranjo.online", "naranjo-online", "release-publisher.yml"),
    ("lidersea.com", "lidersea-com", "release-publisher.yml"),
)

# This literal digest couples Trivy's path-scoped AVD-KSV-0056 acceptance to
# every ServiceAccount, Role, RoleBinding, rule, and subject in access.yaml.
# Update it only after reviewing that complete authorization file.
FLUX_ACCESS_CONTRACT_SHA256 = (
    "0e6c9c7f1dac58f9a5be61108c4dca106fff07ebd9b02cbebd7dec5508b689b5"
)

EMAIL_ADDRESS = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
)
OPAQUE_32_HEX = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
UUID_IDENTIFIER = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}(?![0-9a-f])"
)
IPV4_LITERAL = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
IPV6_CANDIDATE = re.compile(
    r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])"
)
SYNTHETIC_32_HEX = {
    "1" * 32,
    "2" * 32,
    "3" * 32,
    "0123456789abcdef" * 2,
}
SECRET_SIGNATURES = {
    "age private identity": re.compile(
        r"AGE-SECRET-KEY-(?:PQ-)?1[A-Z0-9]+"
    ),
    "private key block": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "GitHub classic token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "GitHub fine-grained token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "prefixed Cloudflare API credential": re.compile(
        r"\b(?:cfk|cfut|cfat)_[A-Za-z0-9]{40}[0-9A-Fa-f]{8}\b"
    ),
    "literal Cloudflare API token": re.compile(
        r"(?i)\bcloudflare_api_token\b[\"']?\s*[:=]\s*"
        r"[\"']?[A-Za-z0-9_-]{20,}[\"']?"
    ),
    "Cloudflare bearer credential": re.compile(
        r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~-]{20,}"
    ),
    "Cloudflare Tunnel runtime token": re.compile(
        r"(?i)\b(?:cloudflared[_ -]?)?tunnel[_ -]?token\b[\"']?\s*[:=]\s*"
        r"[\"']?(?:eyJ[A-Za-z0-9+/_-]{20,}={0,2}|"
        r"[A-Za-z0-9+/_-]{80,}={0,2})[\"']?"
    ),
    "bare Cloudflare Tunnel runtime token": re.compile(
        r"(?<![A-Za-z0-9+/_-])eyJ[A-Za-z0-9+/_-]{77,}={0,2}"
        r"(?![A-Za-z0-9+/_=-])"
    ),
    "local Cloudflare token receipt": re.compile(
        r"(?i)[\"']schema[\"']\s*:\s*[\"']"
        r"cloudflare-phase-token-receipt-v(?:1|2)[\"']"
    ),
    "Gitleaks inline suppression": re.compile(r"(?i)gitleaks\s*:\s*allow"),
}
ENCRYPTION_CONFIGURATION_SENTINEL = "REPLACE_BASE64_32_BYTE_KEY"
ENCRYPTION_CONFIGURATION_KIND = re.compile(
    r'''(?m)^[ \t]*(?:"kind"|'kind'|kind)[ \t]*:[ \t]*'''
    r'''(?:"EncryptionConfiguration"|'EncryptionConfiguration'|'''
    r'''EncryptionConfiguration)[ \t]*(?:#.*)?$'''
)
SECRETBOX_PROVIDER = re.compile(
    r'''(?m)^[ \t]*(?:-[ \t]+)?(?:"secretbox"|'secretbox'|secretbox)[ \t]*:'''
)
SECRETBOX_SECRET_SCALAR = re.compile(
    r'''(?m)^[ \t]*(?:"secret"|'secret'|secret)[ \t]*:[ \t]*'''
    r'''(?P<value>[^#\r\n]*?)[ \t]*(?:#.*)?$'''
)
# These literals are network-policy boundaries, cluster test networks, or
# process bind addresses—not discovered host identities.
PUBLIC_NETWORK_IPV4 = {
    "0.0.0.0", "10.0.0.0", "10.42.0.0", "10.42.1.0", "10.43.0.0", "10.44.0.0",
    "10.99.0.0", "100.64.0.0", "127.0.0.0", "127.0.0.1",
    "169.254.0.0", "172.16.0.0", "192.168.0.0", "224.0.0.0",
    "240.0.0.0",
}
DOCUMENTATION_IPV4 = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
# Private/public host-shaped values used by validator tests are exact and may
# appear only beneath a test/fixture path; production documentation gets no
# blanket RFC1918 exception.
SYNTHETIC_TEST_IPV4_OCTETS = {
    (8, 8, 8, 8), (192, 168, 1, 10), (192, 168, 50, 0),
    (192, 168, 50, 1), (192, 168, 50, 10), (192, 168, 50, 11),
    (192, 168, 50, 20), (192, 168, 60, 1),
}


def _git_visible_paths(root):
    """Return tracked plus unignored paths without enumerating ignored custody files."""

    root = root.resolve()
    if not (root / ".git").exists():
        return ({
            relative(path, root)
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        }, [])
    try:
        result = subprocess.run(
            [
                "git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
                "--exclude-standard",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return set(), ["Git-visible repository inventory is unavailable"]
    if result.returncode != 0:
        return set(), ["Git-visible repository inventory is unavailable"]
    try:
        decoded = result.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return set(), ["Git-visible repository inventory is not UTF-8"]
    entries = decoded.split("\0")
    if entries[-1:] == [""]:
        entries.pop()
    for entry in entries:
        parts = Path(entry).parts
        if (
            not entry
            or Path(entry).is_absolute()
            or not parts
            or any(part in {"", ".", ".."} for part in parts)
        ):
            return set(), ["Git-visible repository inventory escaped its root"]
    return set(entries), []


def _public_candidate_paths(root, include_directories=False):
    """Return only content that could enter Git, never ignored owner-only files."""

    root = root.resolve()
    visible, errors = _git_visible_paths(root)
    if errors:
        raise OSError(errors[0])
    paths = [root.joinpath(*Path(entry).parts) for entry in sorted(visible)]
    if include_directories and not (root / ".git").exists():
        paths.extend(
            path for path in root.rglob("*")
            if path.is_dir() and not path.is_symlink()
        )
    return paths


def _git_index_text_documents(root):
    """Return exact stage-0 blobs without reading working-tree substitutes.

    Invalid UTF-8 and NUL bytes are preserved with surrogate escapes so an
    attacker cannot make an otherwise ASCII credential invisible by appending
    one binary byte. This repository does not permit symbolic index entries.
    """

    root = root.resolve()
    if not (root / ".git").exists():
        return [], []
    try:
        inventory = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--stage"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return [], ["exact Git index inventory is unavailable"]
    if inventory.returncode != 0:
        return [], ["exact Git index inventory is unavailable"]

    entries = []
    errors = []
    for raw_entry in inventory.stdout.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
            relative_path = raw_path.decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError):
            return [], ["exact Git index inventory is malformed"]
        parts = Path(relative_path).parts
        if (
            Path(relative_path).is_absolute()
            or not parts
            or any(part in {"", ".", ".."} for part in parts)
        ):
            return [], ["exact Git index inventory escaped its root"]
        if stage != "0":
            errors.append("unmerged Git index entry: " + relative_path)
            continue
        if mode == "120000":
            errors.append("symbolic Git index entry is forbidden: " + relative_path)
            continue
        if mode not in {"100644", "100755"}:
            errors.append("unsupported Git index mode: " + relative_path)
            continue
        if not re.fullmatch(r"[0-9a-f]{40,64}", object_id):
            return [], ["exact Git index object identity is malformed"]
        entries.append((relative_path, object_id))

    if not entries:
        return [], errors
    try:
        process = subprocess.Popen(
            ["git", "-C", str(root), "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return [], errors + ["exact Git index object reader is unavailable"]
    documents = []
    aggregate_size = 0
    aggregate_rejected = False
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        for relative_path, object_id in entries:
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii", "strict").strip()
            header_parts = header.split(" ")
            if (
                len(header_parts) != 3
                or header_parts[0] != object_id
                or header_parts[1] != "blob"
                or not header_parts[2].isdigit()
            ):
                raise ValueError("unexpected batch header")
            size = int(header_parts[2])
            aggregate_size += size
            too_large = size > MAX_REPOSITORY_FILE_BYTES
            aggregate_overflow = aggregate_size > MAX_PUBLIC_REPOSITORY_BYTES
            if too_large or aggregate_overflow:
                remaining = size
                while remaining:
                    chunk = process.stdout.read(min(remaining, 64 * 1024))
                    if not chunk:
                        raise ValueError("truncated oversized blob")
                    remaining -= len(chunk)
                if process.stdout.read(1) != b"\n":
                    raise ValueError("malformed batch delimiter")
                if too_large:
                    errors.append("oversized Git index blob: " + relative_path)
                if aggregate_overflow and not aggregate_rejected:
                    errors.append("Git index exceeds the aggregate byte ceiling")
                    aggregate_rejected = True
                continue
            data = process.stdout.read(size)
            if len(data) != size or process.stdout.read(1) != b"\n":
                raise ValueError("truncated index blob")
            text = data.decode("utf-8", "surrogateescape")
            documents.append((relative_path, text))
        process.stdin.close()
        if process.wait(timeout=10) != 0:
            raise ValueError("batch reader failed")
        process.stdout.close()
    except (OSError, UnicodeDecodeError, ValueError, subprocess.TimeoutExpired):
        if not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        return [], errors + ["exact Git index object scan failed"]
    return documents, errors


class UnsafePublicPathError(OSError):
    """A Git-visible worktree path crossed a link or changed while read."""


def _is_reparse_point(metadata):
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _path_snapshot(path, root):
    """Describe each component without following symbolic/reparse links."""

    root = root.resolve()
    parts = path.relative_to(root).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise UnsafePublicPathError("path escaped repository root")
    snapshot = []
    current = root
    for index, part in enumerate(parts):
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise UnsafePublicPathError("link or reparse point is forbidden")
        final = index == len(parts) - 1
        if final:
            if not stat.S_ISREG(metadata.st_mode):
                raise UnsafePublicPathError("public path is not a regular file")
            if metadata.st_nlink != 1:
                raise UnsafePublicPathError("hardlinked public file is forbidden")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise UnsafePublicPathError("public path ancestor is not a directory")
        snapshot.append((
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size if final else None,
            metadata.st_mtime_ns if final else None,
        ))
    return tuple(snapshot)


def _read_public_regular_file(path, root, byte_limit=None):
    """Read one stable single-link file using no-follow where available."""

    before = _path_snapshot(path, root)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened_before = os.fstat(descriptor)
        expected = before[-1]
        opened_identity = (
            opened_before.st_dev,
            opened_before.st_ino,
            opened_before.st_mode,
            opened_before.st_nlink,
            opened_before.st_size,
            opened_before.st_mtime_ns,
        )
        if opened_identity != expected or not stat.S_ISREG(opened_before.st_mode):
            raise UnsafePublicPathError("public file changed before open")
        if opened_before.st_nlink != 1:
            raise UnsafePublicPathError("hardlinked public file is forbidden")
        chunks = []
        remaining = (
            opened_before.st_size
            if byte_limit is None
            else min(opened_before.st_size, byte_limit)
        )
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise UnsafePublicPathError("public file was truncated while read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if byte_limit is None and os.read(descriptor, 1):
            raise UnsafePublicPathError("public file grew while read")
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = _path_snapshot(path, root)
    final_identity = (
        opened_after.st_dev,
        opened_after.st_ino,
        opened_after.st_mode,
        opened_after.st_nlink,
        opened_after.st_size,
        opened_after.st_mtime_ns,
    )
    if before != after or final_identity != before[-1]:
        raise UnsafePublicPathError("public path changed while read")
    return b"".join(chunks), opened_before


def files(root):
    """Yield stable Git-visible text snapshots without following links."""

    for path in _public_candidate_paths(root):
        relative_parts = path.relative_to(root).parts
        if any(part in SKIP_PARTS for part in relative_parts):
            continue
        try:
            if _path_snapshot(path, root)[-1][4] > MAX_REPOSITORY_FILE_BYTES:
                yield path, None
                continue
            data, _ = _read_public_regular_file(path, root)
        except FileNotFoundError:
            # A tracked deletion has no worktree bytes. The exact stage-0
            # scanner below remains authoritative for what Git would publish.
            continue
        except OSError:
            yield path, None
            continue
        # Preserve every byte for ASCII-oriented deny patterns; NUL or invalid
        # UTF-8 must not turn a public candidate into a scanner bypass.
        yield path, data.decode("utf-8", "surrogateescape").replace("\r\n", "\n")


def relative(path, root):
    return path.relative_to(root).as_posix()


def read(path):
    """Read one stable public file through an absolute no-link component chain."""

    absolute = Path(path).absolute()
    anchor = Path(absolute.anchor)
    metadata = _path_snapshot(absolute, anchor)[-1]
    if metadata[4] > MAX_REPOSITORY_FILE_BYTES:
        raise UnsafePublicPathError("public policy file exceeds scan ceiling")
    data, _ = _read_public_regular_file(absolute, anchor)
    return data.decode("utf-8", "strict").replace("\r\n", "\n")


def has_media_magic(prefix):
    """Recognize common media bytes even when a file has a harmless suffix."""

    stripped = prefix.lstrip()
    return (
        prefix.startswith(MEDIA_MAGIC_PREFIXES)
        or (prefix.startswith(b"RIFF") and prefix[8:12] in {b"WEBP", b"WAVE", b"AVI "})
        or (len(prefix) >= 12 and prefix[4:8] == b"ftyp")
        or stripped.lower().startswith(b"<svg")
    )


def is_fixture(path):
    parts = set(path.parts)
    return "fixtures" in parts or "examples" in parts


def contains_plaintext_encryption_configuration(text):
    """Detect a concrete API-server secretbox scalar independent of its path."""

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    documents = re.split(r"(?m)^[ \t]*---[ \t]*(?:#.*)?$", text)
    for document in documents:
        if ENCRYPTION_CONFIGURATION_KIND.search(document) is None:
            continue
        provider = SECRETBOX_PROVIDER.search(document)
        if provider is None:
            continue
        for match in SECRETBOX_SECRET_SCALAR.finditer(document, provider.end()):
            value = match.group("value").strip()
            if (
                len(value) >= 2
                and value[0] in {"'", '"'}
                and value[-1] == value[0]
            ):
                value = value[1:-1].strip()
            if value and value != ENCRYPTION_CONFIGURATION_SENTINEL:
                return True
    return False


def is_test_path(path, root):
    """Identify committed test sources without treating all private IPs as safe."""

    relative_parts = path.relative_to(root).parts
    return "tests" in relative_parts or path.name.startswith("test_")


def allowed_ipv4(value, path, root):
    """Allow only public documentation and explicitly synthetic network values."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    if not isinstance(address, ipaddress.IPv4Address):
        return False
    normalized = str(address)
    if normalized in PUBLIC_NETWORK_IPV4:
        return True
    if any(address in network for network in DOCUMENTATION_IPV4):
        return True
    octets = tuple(int(part) for part in normalized.split("."))
    return is_test_path(path, root) and octets in SYNTHETIC_TEST_IPV4_OCTETS


def forbidden_ipv6_values(text):
    """Return valid IPv6 candidates other than loopback and documentation space."""

    documentation = ipaddress.ip_network("2001:db8::/32")
    forbidden = []
    for candidate in IPV6_CANDIDATE.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv6Address) and not (
            address.is_unspecified or address.is_loopback or address in documentation
        ):
            forbidden.append(address)
    return forbidden


def active_kustomization_resource(text, name):
    return re.search(
        r"(?m)^\s*-\s+{}\s*(?:#.*)?$".format(re.escape(name)), text
    ) is not None


def flux_access_contract_errors(text):
    """Require review of every byte in the accepted Flux authorization file."""

    # read_text already normalizes platform newlines; the explicit replacement
    # also makes direct unit-test input behave identically on Windows and Linux.
    normalized = text.replace("\r\n", "\n")
    observed = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if observed != FLUX_ACCESS_CONTRACT_SHA256:
        return [
            "Flux access authorization changed; review every ServiceAccount, "
            "Role, RoleBinding, rule, and subject before updating its digest"
        ]
    return []


def check_layout(root):
    errors = []
    for path in _public_candidate_paths(root, include_directories=True):
        rel_parts = path.relative_to(root).parts
        lowered = tuple(part.lower() for part in rel_parts)
        rel = "/".join(lowered)
        forbidden_local_only = any(
            part in FORBIDDEN_LOCAL_ONLY_COMPONENTS for part in lowered
        )
        name = lowered[-1]
        if name != ".env.example" and any(
            fnmatch.fnmatchcase(name, pattern)
            for pattern in FORBIDDEN_LOCAL_ONLY_FILE_PATTERNS
        ):
            forbidden_local_only = True
        if (
            rel in FORBIDDEN_LOCAL_ONLY_EXACT_NAMES
            or ("cloudflare" in name and "receipt" in name and name.endswith(".json"))
            or name.endswith(".tfstate")
            or ".tfstate." in name
            or name.endswith("_override.tf")
            or name.endswith("_override.tf.json")
            or name in {"override.tf", "override.tf.json"}
        ):
            forbidden_local_only = True
        if "dist" in lowered:
            allowed_dist = rel in ALLOWED_DIST_PATHS or (
                path.is_dir() and rel in ALLOWED_DIST_DIRECTORIES
            )
            forbidden_local_only = forbidden_local_only or not allowed_dist
        if forbidden_local_only:
            errors.append(
                "local-only directory content is Git-visible: " + relative(path, root)
            )
        if any(part in SKIP_PARTS for part in lowered):
            continue
        if "apps" in lowered:
            errors.append("forbidden directory component 'apps': " + relative(path, root))
        if "clusters" in lowered:
            errors.append("forbidden directory component 'clusters': " + relative(path, root))
        if len(lowered) >= 2 and lowered[0:2] == ("kubernetes", "homelab"):
            errors.append("forbidden kubernetes/homelab layout: " + relative(path, root))
    required = [
        "AGENTS.md", "SECURITY.md", "versions.env", "release-policy.env",
        "kubernetes", "scripts/validate_image_release.py",
        "policies/gitleaks.toml",
    ]
    for name in required:
        if not (root / name).exists():
            errors.append("required path missing: " + name)
    return errors


def check_secrets(root):
    errors = []
    def inspect(text, path, rel):
        for label, pattern in SECRET_SIGNATURES.items():
            if pattern.search(text) or pattern.search(rel):
                problem = "{} found in {}".format(label, rel)
                if problem not in errors:
                    errors.append(problem)

        if rel.startswith("kubernetes/") and path.suffix in {".yaml", ".yml"}:
            if not re.search(r"\.sops\.ya?ml$", path.name):
                if contains_secret_document(text) and not is_fixture(path):
                    problem = "unencrypted Kubernetes Secret manifest: " + rel
                    if problem not in errors:
                        errors.append(problem)
        if contains_plaintext_encryption_configuration(text):
            problem = "plaintext Kubernetes API encryption configuration: " + rel
            if problem not in errors:
                errors.append(problem)

    def inspect_sops_snapshot(documents):
        sops_paths = {
            rel for rel in documents
            if rel != ".sops.yaml" and re.search(r"\.sops\.ya?ml$", rel)
        }
        for rel in sorted(sops_paths - set(APPROVED_SOPS_SECRET_PATHS)):
            errors.append("unapproved SOPS Secret path: " + rel)
        approved_present = sorted(sops_paths & set(APPROVED_SOPS_SECRET_PATHS))
        if not approved_present:
            return
        config = documents.get(".sops.yaml")
        if config is None:
            errors.append("SOPS configuration is unavailable for approved ciphertext")
            return
        try:
            recipient = sops_recipient_from_config(config)
        except TRANSITION_RELEASE_STATE.CanonicalYamlError:
            errors.append("SOPS configuration is unsafe for approved ciphertext")
            return
        if recipient is None:
            errors.append("approved SOPS ciphertext requires a configured recipient")
            return
        for rel in approved_present:
            for problem in tunnel_secret_errors(documents[rel], recipient):
                detail = "invalid approved SOPS Secret {}: {}".format(rel, problem)
                if detail not in errors:
                    errors.append(detail)

    worktree_documents = {}
    for path, text in files(root):
        rel = relative(path, root)
        if text is None:
            errors.append("unsafe or unstable public repository path: " + rel)
            continue
        worktree_documents[rel] = text
        inspect(text, path, rel)
    inspect_sops_snapshot(worktree_documents)
    index_documents, index_errors = _git_index_text_documents(root)
    errors.extend(index_errors)
    for rel, text in index_documents:
        inspect(text, root.joinpath(*Path(rel).parts), rel)
    inspect_sops_snapshot(dict(index_documents))
    return errors


def check_privacy(root):
    """Reject local identity and host facts that do not belong in public Git."""

    errors = []
    local_profile = re.compile(r"(?i)[A-Z]:[\\/]+Users[\\/]+[^\\/\s]+")
    workspace_path = re.compile(r"(?i)[A-Z]:[\\/]+dev(?:[\\/]|\b)")
    def inspect(text, path, rel):
        inspected = text + "\n" + rel
        if local_profile.search(inspected) or workspace_path.search(inspected):
            problem = "local workstation path found in " + rel
            if problem not in errors:
                errors.append(problem)
        if any(not allowed_ipv4(value, path, root) for value in IPV4_LITERAL.findall(inspected)):
            problem = "host IPv4 address outside the public allowlist found in " + rel
            if problem not in errors:
                errors.append(problem)
        if forbidden_ipv6_values(inspected):
            problem = "host IPv6 address outside the public allowlist found in " + rel
            if problem not in errors:
                errors.append(problem)
        if any(
            value != "00000000-0000-0000-0000-000000000000"
            for value in UUID_IDENTIFIER.findall(inspected)
        ):
            problem = "machine or tunnel UUID found in " + rel
            if problem not in errors:
                errors.append(problem)
        for address in EMAIL_ADDRESS.findall(inspected):
            if not address.lower().endswith(".invalid"):
                problem = "non-synthetic email address found in " + rel
                if problem not in errors:
                    errors.append(problem)
        for identifier in OPAQUE_32_HEX.findall(inspected):
            if identifier not in SYNTHETIC_32_HEX:
                problem = "non-synthetic 32-hex identifier found in " + rel
                if problem not in errors:
                    errors.append(problem)

    for path, text in files(root):
        rel = relative(path, root)
        if text is None:
            errors.append("unsafe or unstable public repository path: " + rel)
            continue
        inspect(text, path, rel)
    index_documents, index_errors = _git_index_text_documents(root)
    errors.extend(error for error in index_errors if error not in errors)
    for rel, text in index_documents:
        inspect(text, root.joinpath(*Path(rel).parts), rel)
    return errors


def approved_badge_errors(data, rel):
    """Hold the one approved generated badge to a strict reviewable-text law.

    Fail closed: any deviation reports the file as ordinary forbidden media
    plus the precise reason, so this exception can never widen into a
    general capability to commit SVG content.
    """

    def rejection(reason):
        return (
            "approved badge violates the strict text contract ({}): {}".format(
                reason, rel
            )
        )

    if len(data) > MAX_TEXT_BADGE_BYTES:
        return [rejection("exceeds the {} byte ceiling".format(MAX_TEXT_BADGE_BYTES))]
    try:
        text = data.decode("ascii", "strict")
    except UnicodeError:
        return [rejection("contains non-ASCII bytes")]
    problems = []
    if any(ord(character) < 32 and character != "\n" for character in text):
        problems.append(rejection("contains control characters"))
    if not text.startswith(BADGE_REQUIRED_PREFIX) or not text.endswith("</svg>\n"):
        problems.append(rejection("unexpected SVG envelope"))
        return problems
    remainder = text[len(BADGE_REQUIRED_PREFIX):].lower()
    for fragment in BADGE_FORBIDDEN_FRAGMENTS:
        if fragment in remainder:
            problems.append(rejection("forbidden fragment " + repr(fragment)))
    for element in re.findall(r"<\s*/?\s*([A-Za-z][A-Za-z0-9-]*)", text):
        if element.lower() not in BADGE_ALLOWED_ELEMENTS:
            problems.append(rejection("element outside the allowlist: " + element))
    return problems


def check_media(root):
    """Keep heavyweight media and unresolved storage out of public desired state."""

    errors = []
    asset_totals = {}
    repository_total = 0
    public_paths = _public_candidate_paths(root)
    for path in public_paths:
        relative_parts = path.relative_to(root).parts
        if any(part in MEDIA_SCAN_SKIP_PARTS for part in relative_parts):
            continue
        rel = relative(path, root)
        try:
            metadata = _path_snapshot(path, root)[-1]
        except FileNotFoundError:
            continue
        except OSError:
            errors.append("unsafe or unstable public repository path: " + rel)
            continue
        size = metadata[4]
        repository_total += size
        if size > MAX_REPOSITORY_FILE_BYTES:
            errors.append("file exceeds the public repository size ceiling: " + rel)
        try:
            data, _ = _read_public_regular_file(
                path,
                root,
                byte_limit=32 if size > MAX_REPOSITORY_FILE_BYTES else None,
            )
        except OSError:
            errors.append("unsafe or unstable public repository path: " + rel)
            continue

        # The platform repository carries no application asset trees at all;
        # any media content anywhere in it is a violation.
        asset_scope = None
        suffix = path.suffix.lower()
        prefix = data[:64]
        media_magic = has_media_magic(prefix)
        if any(prefix.startswith(marker) for marker in OPAQUE_ARTIFACT_MAGIC_PREFIXES):
            errors.append("opaque archive or encrypted artifact is forbidden: " + rel)
        is_media = suffix in MEDIA_SUFFIXES
        if is_media or media_magic:
            # The magic sniff intentionally recognizes the "<svg" text
            # signature, so the approved badge necessarily arrives here; its
            # strict text contract (exact envelope, ASCII-only, element
            # allowlist, no embedded data) is what excludes renamed binary
            # or active content, more precisely than the sniff could.
            if rel in APPROVED_TEXT_BADGE_PATHS:
                errors.extend(approved_badge_errors(data, rel))
            elif asset_scope is None:
                label = "media file" if is_media else "renamed media content"
                errors.append("{} is outside the small frontend asset tree: {}".format(label, rel))
            else:
                asset_totals[asset_scope] = asset_totals.get(asset_scope, 0) + size
                if size > MAX_UI_ASSET_BYTES:
                    errors.append("frontend UI asset exceeds the small-asset ceiling: " + rel)

        if path.suffix.lower() in TEXT_SUFFIXES and size <= MAX_REPOSITORY_FILE_BYTES:
            # Binary-magic detection runs first; tolerant decoding here only
            # looks for an explicit data URI without letting a renamed binary
            # crash the policy process before it can report the violation.
            text = data.decode("utf-8", "ignore")
            if re.search(r"(?i)data:(?:image|audio|video|font)/[^;,]+;base64,", text):
                errors.append("embedded media data URI is forbidden: " + rel)

    for (site, tree), total in sorted(asset_totals.items()):
        if total > MAX_ASSET_TREE_BYTES:
            errors.append("{} {} asset tree exceeds the aggregate media ceiling".format(site, tree))
    if repository_total > MAX_PUBLIC_REPOSITORY_BYTES:
        errors.append("public repository tree exceeds the aggregate byte ceiling")

    # Every GitRepository honors the root .sourceignore unless spec.ignore
    # overrides it. Keep the artifact allowlist explicit so source-controller
    # never stores application/media/history that reconciliation cannot use.
    sourceignore = root / ".sourceignore"
    source_required = (
        "/*",
        "!/kubernetes/",
        "!/policies/kyverno/",
    )
    if not sourceignore.is_file():
        errors.append("Flux source artifact boundary is missing: .sourceignore")
    else:
        source_text = read(sourceignore)
        for fragment in source_required:
            if fragment not in source_text:
                errors.append("Flux source artifact allowlist is missing: " + fragment)

    for path in live_kubernetes_files(root):
        text = read(path)
        rel = relative(path, root)
        forbidden = {
            "persistent storage object": re.compile(
                r"(?m)^kind:\s*(?:PersistentVolume|PersistentVolumeClaim|StorageClass)\s*$"
            ),
            "persistent volume claim": re.compile(r"(?m)^\s*persistentVolumeClaim:\s*$"),
            "local volume source": re.compile(r"(?m)^\s*local:\s*$"),
            "hostPath volume": re.compile(r"(?m)^\s*hostPath:\s*$"),
            "disk-pressure toleration": re.compile(r"(?m)^\s*key:\s*node\.kubernetes\.io/disk-pressure\s*$"),
        }
        for label, pattern in forbidden.items():
            if pattern.search(text):
                errors.append("{} before media discovery in {}".format(label, rel))
        for document in re.split(r"(?m)^---\s*$", text):
            if re.search(r"(?m)^kind:\s*GitRepository\s*$", document):
                # A per-source override is allowed only as a second, narrower
                # boundary paired with sparse checkout. Broad re-inclusion would
                # overrule the root .sourceignore and recreate whole-repo artifacts.
                has_ignore = re.search(r"(?m)^\s*ignore:\s*(?:\||>)?\s*$", document)
                if has_ignore and not re.search(r"(?m)^\s*sparseCheckout:\s*$", document):
                    errors.append("GitRepository ignore override lacks sparse checkout in " + rel)
                if has_ignore and re.search(r"(?m)^\s*!/\*\*?\s*$", document):
                    errors.append("GitRepository ignore override broadly re-includes the repository in " + rel)
            if not re.search(r"(?m)^kind:\s*(?:ConfigMap|Secret)\s*$", document):
                continue
            if len(document.encode("utf-8")) > MAX_KUBERNETES_DATA_OBJECT_BYTES:
                errors.append("Kubernetes data object exceeds the non-media ceiling in " + rel)
            if re.search(r"(?m)^binaryData:\s*$", document):
                errors.append("ConfigMap binaryData is forbidden in " + rel)
            if re.search(
                r"(?im)^\s+[A-Za-z0-9_.-]+\.(?:aac|avif|avi|bmp|flac|gif|heic|heif|jpeg|jpg|m4a|mkv|mov|mp3|mp4|ogg|ogv|png|tif|tiff|wav|webm|webp):",
                document,
            ):
                errors.append("media-shaped Kubernetes data key is forbidden in " + rel)

    # The media fail-closed chart contract (media.enabled=false behind the
    # UNRESOLVED_PI_MEDIA_STORAGE sentinel) moved with the charts into the
    # standalone site repositories; each site's own CI enforces it there,
    # and the platform's HelmRelease values must not re-enable it here.
    for release in sorted((root / "kubernetes" / "websites").glob("*/release.yaml")):
        text = read(release)
        if re.search(r"(?m)^\s*media:\s*$[\s\S]{0,120}?^\s*enabled:\s*true", text):
            errors.append(
                "platform values re-enable site media: " + relative(release, root)
            )
    return errors


def check_workflows(root):
    errors = []
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return ["workflow directory missing: .github/workflows"]
    for path in _public_candidate_paths(root):
        if path.parent != workflow_dir or path.suffix not in {".yaml", ".yml"}:
            continue
        text = read(path)
        rel = relative(path, root)
        for match in re.finditer(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", text):
            value = match.group(1).strip("'\"")
            if value.startswith("./") or value.startswith("docker://"):
                continue
            if "@" not in value or not FULL_SHA.match(value.rsplit("@", 1)[1]):
                errors.append("Action is not pinned to a full SHA in {}: {}".format(rel, value))
        if "pull_request_target:" in text:
            errors.append("pull_request_target is forbidden: " + rel)
        if re.search(r"(?m)^\s*persist-credentials:\s*true\s*$", text):
            errors.append("checkout credential persistence enabled: " + rel)
    errors.extend(image_release_errors(root))
    return errors


def live_kubernetes_files(root):
    base = root / "kubernetes"
    if not base.exists():
        return []
    result = []
    for path in _public_candidate_paths(root):
        try:
            path.relative_to(base)
        except ValueError:
            continue
        if path.suffix not in {".yaml", ".yml"}:
            continue
        if is_fixture(path) or "templates" in path.parts or path.name == "gotk-components.yaml":
            continue
        result.append(path)
    return result


def flux_components_errors(root):
    """Validate generated Flux provenance and images when the export exists."""

    components = root / "kubernetes/flux-system/controllers/gotk-components.yaml"
    if not components.is_file():
        return []
    versions_path = root / "versions.env"
    if not versions_path.is_file():
        return ["versions.env is missing for generated Flux validation"]
    versions_text = read(versions_path)
    values = dict(
        match.groups()
        for match in re.finditer(r"(?m)^([A-Z0-9_]+)=([^\s#]+)$", versions_text)
    )
    required_keys = (
        "FLUX_VERSION",
        "FLUX_SOURCE_CONTROLLER_IMAGE",
        "FLUX_KUSTOMIZE_CONTROLLER_IMAGE",
        "FLUX_HELM_CONTROLLER_IMAGE",
    )
    missing = [key for key in required_keys if key not in values]
    if missing:
        return ["generated Flux validation is missing pin(s): " + ", ".join(missing)]

    text = read(components)
    errors = []
    if "# Flux Version: {}".format(values["FLUX_VERSION"]) not in text:
        errors.append("generated Flux version does not match versions.env")
    if "# Components: source-controller,kustomize-controller,helm-controller" not in text:
        errors.append("generated Flux component set is not the reviewed three-controller set")
    if re.search(r"(?m)^kind:\s*Secret\s*$", text):
        errors.append("generated Flux components must not contain a Secret")
    actual_images = re.findall(r"(?m)^\s*image:\s*([^\s#]+)", text)
    expected_images = {
        values["FLUX_SOURCE_CONTROLLER_IMAGE"],
        values["FLUX_KUSTOMIZE_CONTROLLER_IMAGE"],
        values["FLUX_HELM_CONTROLLER_IMAGE"],
    }
    if len(actual_images) != 3 or set(actual_images) != expected_images:
        errors.append("generated Flux images must exactly match the three versions.env digests")
    return errors


def check_kubernetes(root):
    errors = []
    forbidden = {
        "public Service": re.compile(r"(?m)^\s*type:\s*(?:NodePort|LoadBalancer)\s*$"),
        "external IP": re.compile(r"(?m)^\s*externalIPs:\s*$"),
        "host network": re.compile(r"(?m)^\s*hostNetwork:\s*true\s*$"),
        "host PID": re.compile(r"(?m)^\s*hostPID:\s*true\s*$"),
        "host IPC": re.compile(r"(?m)^\s*hostIPC:\s*true\s*$"),
        "host port": re.compile(r"(?m)^\s*hostPort:\s*\d+\s*$"),
        "privileged container": re.compile(r"(?m)^\s*privileged:\s*true\s*$"),
        "privilege escalation": re.compile(r"(?m)^\s*allowPrivilegeEscalation:\s*true\s*$"),
        "ServiceAccount token mount": re.compile(r"(?m)^\s*automountServiceAccountToken:\s*true\s*$"),
        "hostPath volume": re.compile(r"(?m)^\s*hostPath:\s*$"),
    }
    for path in live_kubernetes_files(root):
        text = read(path)
        rel = relative(path, root)
        for label, pattern in forbidden.items():
            if pattern.search(text):
                errors.append("{} in {}".format(label, rel))
        for match in re.finditer(r"(?m)^[ \t]*image:[ \t]*([^\s#]+)", text):
            image = match.group(1).strip("'\"")
            if not DIGEST_IMAGE.match(image):
                errors.append("mutable or invalid image reference in {}: {}".format(rel, image))
    errors.extend(flux_components_errors(root))
    flux = root / "kubernetes" / "flux-system"
    if flux.exists():
        required_fragments = {
            "flux-system/controllers/patches/source-controller.yaml": [
                "--no-cross-namespace-refs=true", "runAsNonRoot", "RuntimeDefault",
                "requests/ephemeral-storage", "limits/ephemeral-storage", "sizeLimit",
            ],
            "flux-system/controllers/patches/kustomize-controller.yaml": [
                "--no-cross-namespace-refs=true", "--no-remote-bases=true",
                "--default-service-account=default", "runAsNonRoot", "RuntimeDefault",
            ],
            "flux-system/controllers/patches/helm-controller.yaml": [
                "--no-cross-namespace-refs=true", "--default-service-account=default",
                "runAsNonRoot", "RuntimeDefault",
            ],
            "flux-system/access.yaml": [
                "namespace: cloudflare-public", "namespace: naranjo-online",
                "namespace: lidersea-com",
            ],
            "reconciliation/platform-services.yaml": [
                "provider: sops", "name: sops-age",
            ],
        }
        for name, fragments in required_fragments.items():
            path = root / "kubernetes" / name
            if not path.is_file():
                errors.append("required Flux hardening file missing: " + name)
                continue
            text = read(path)
            for fragment in fragments:
                if fragment not in text:
                    errors.append("Flux hardening fragment missing from {}: {}".format(name, fragment))
        access = flux / "access.yaml"
        if access.is_file():
            errors.extend(flux_access_contract_errors(read(access)))
        default_denies = root / "kubernetes/platform/prerequisites/network-policies.yaml"
        if not default_denies.is_file():
            errors.append("bootstrap-owned default-deny NetworkPolicies are missing")
        else:
            documents = re.split(r"(?m)^---\s*$", read(default_denies))
            for namespace in (
                "cloudflare-public", "naranjo-online", "lidersea-com", "kyverno",
            ):
                matches = [doc for doc in documents if (
                    re.search(r"(?m)^\s*name:\s*default-deny\s*$", doc) and
                    re.search(r"(?m)^\s*namespace:\s*{}\s*$".format(namespace), doc) and
                    re.search(r"(?ms)^\s*policyTypes:\s*\n\s*-\s*Ingress\s*\n\s*-\s*Egress\s*$", doc)
                )]
                if len(matches) != 1:
                    errors.append("exact ingress+egress default-deny missing for " + namespace)
        # The per-site ingress policies (cloudflared-to-<site>) ship inside
        # the standalone site charts and arrive through the remote sources;
        # the platform keeps requiring its own egress side toward each site.
        required_network_templates = {
            "kubernetes/platform/cloudflare-public/chart/templates/network-policies.yaml": [
                "cloudflared-dns", "cloudflared-edge", "cloudflared-naranjo-online",
                "cloudflared-lidersea-com",
            ],
        }
        for name, policy_names in required_network_templates.items():
            path = root / name
            text = read(path) if path.is_file() else ""
            for policy_name in policy_names:
                if policy_name not in text:
                    errors.append("required scoped NetworkPolicy missing: " + policy_name)
    errors.extend(signature_policy_source_errors(root))
    return errors


def check_cloudflare(root):
    errors = []
    base = root / "infrastructure" / "cloudflare"
    if not base.exists():
        return ["Cloudflare OpenTofu directory missing"]
    errors.extend(cloudflare_phase_contract_errors(root))
    visible_paths, visibility_errors = _git_visible_cloudflare_paths(root)
    errors.extend(visibility_errors)
    expected_sources = {
        path.as_posix() for path in CLOUDFLARE_TERRAFORM_SOURCE_FILES
    }
    expected_phase_files = {
        path.as_posix() for path in CLOUDFLARE_TERRAFORM_REVIEW_FILES
    }
    visible_phase_files = {
        relative_path
        for relative_path in visible_paths
        if relative_path.startswith("infrastructure/cloudflare/phases/")
    }
    for missing in sorted(expected_phase_files - visible_phase_files):
        errors.append("required Cloudflare phase file is not Git-visible: " + missing)
    for unexpected in sorted(visible_phase_files - expected_phase_files):
        errors.append("unexpected Git-visible Cloudflare phase file: " + unexpected)
    visible_sources = {
        relative_path
        for relative_path in visible_paths
        if relative_path.endswith(".tf")
    }
    for missing in sorted(expected_sources - visible_sources):
        errors.append("required Cloudflare Terraform source is not Git-visible: " + missing)
    for unexpected in sorted(visible_sources - expected_sources):
        errors.append("unexpected Git-visible Cloudflare Terraform source: " + unexpected)
    for relative_path in sorted(visible_paths):
        name = Path(relative_path).name
        if name.endswith(".tf.json"):
            errors.append("Git-visible Terraform JSON configuration is forbidden: " + relative_path)
        if name.endswith(".tfvars") or name.endswith(".tfvars.json"):
            errors.append("Git-visible Terraform variable input is forbidden: " + relative_path)

    for relative_path in sorted(visible_sources):
        path = root / relative_path
        if path.is_symlink() or not path.is_file():
            errors.append("Cloudflare Terraform source is missing or symbolic: " + relative_path)
            continue
        text = read(path)
        for match in re.finditer(r'(?m)^\s*data\s+"(cloudflare_[^"]+)"', text):
            errors.append("Cloudflare data source is forbidden in {}: {}".format(
                relative(path, root), match.group(1)
            ))
        for match in re.finditer(r'(?m)^\s*resource\s+"([^"]+)"', text):
            resource_type = match.group(1)
            if resource_type not in ALLOWED_CLOUDFLARE_RESOURCES:
                errors.append("Cloudflare resource outside allowlist in {}: {}".format(
                    relative(path, root), resource_type
                ))
    return errors


def _git_visible_cloudflare_paths(root):
    """Return tracked plus unignored Cloudflare files; ignored local inputs stay local."""

    visible, errors = _git_visible_paths(root)
    if errors:
        return set(), [
            error.replace("repository inventory", "Cloudflare source inventory")
            for error in errors
        ]
    return {
        entry for entry in visible
        if entry.startswith("infrastructure/cloudflare/")
    }, []


def signature_policy_source_errors(root, allowed_inventories=None):
    """Validate policies and bind their exact inventory to classified release mode."""

    errors = []
    if allowed_inventories is None:
        try:
            plan = classify_release_transition(root)
        except (
            CanonicalYamlError,
            TRANSITION_RELEASE_STATE.CanonicalYamlError,
            OSError,
            RuntimeError,
            UnicodeError,
        ):
            # Continue source diagnostics against both closed inventories, but
            # the missing authoritative mode remains a fail-closed error.
            errors.append("signature policy inventory mode is unavailable or unsafe")
            allowed_inventories = ("staging", "promoted")
        else:
            if plan.mode == "scaffold":
                allowed_inventories = ("staging",)
            elif plan.any_website_active:
                allowed_inventories = ("promoted",)
            else:
                # A staged transition may remove the zero-capacity sentinel in
                # the same reviewed change that prepares website activation.
                allowed_inventories = ("staging", "promoted")
    policy_root = root / "policies/kyverno"
    # Small unit fixtures without a policy tree remain composable. In the real
    # repository, policies/gitleaks.toml is layout-required, so a missing
    # Kyverno subtree is still an unambiguous failure here.
    if not policy_root.exists() and not (root / "policies").exists():
        return []
    if policy_root.is_symlink() or not policy_root.is_dir():
        return ["signature policy directory is missing or symbolic"]
    index = policy_root / "kustomization.yaml"
    if index.is_symlink() or not index.is_file():
        return ["signature policy Kustomization is missing or symbolic"]
    try:
        index_text = read(index)
    except (OSError, UnicodeError):
        return ["signature policy Kustomization is unavailable"]
    if signature_policy_kustomization_errors(index_text, allowed_inventories):
        errors.append("signature policy Kustomization is non-canonical")
    for domain, slug, workflow in SITE_RELEASE_CONTRACTS:
        policy_name = "require-signed-{}.yaml".format(slug)
        policy = root / "policies/kyverno" / policy_name
        if policy.is_symlink() or not policy.is_file():
            errors.append("{} signature admission policy is missing".format(domain))
            continue
        try:
            policy_text = read(policy)
        except (OSError, UnicodeError):
            errors.append("{} signature admission policy is unavailable".format(domain))
            continue
        if signature_policy_errors(policy_text, slug, workflow):
            errors.append("{} signature admission policy is non-canonical".format(domain))
        if not active_kustomization_resource(index_text, policy_name):
            errors.append(
                "{} signature admission policy is not active in its Kustomization".format(
                    domain
                )
            )
    admission_index = root / "kubernetes/platform/admission/kustomization.yaml"
    if admission_index.is_symlink() or not admission_index.is_file():
        errors.append("admission parent Kustomization is missing or symbolic")
    else:
        try:
            admission_index_text = read(admission_index)
        except (OSError, UnicodeError):
            errors.append("admission parent Kustomization is unavailable")
        else:
            if admission_kustomization_errors(admission_index_text):
                errors.append("admission parent Kustomization is non-canonical")
    authoritative_files = (
        (
            "kubernetes/reconciliation/kustomization.yaml",
            reconciliation_kustomization_errors,
            "reconciliation root Kustomization",
        ),
        (
            "kubernetes/flux-system/kustomization.yaml",
            flux_system_kustomization_errors,
            "Flux bootstrap Kustomization",
        ),
        (
            "kubernetes/flux-system/gotk-sync.yaml",
            flux_sync_errors,
            "Flux root synchronization",
        ),
    )
    for relative_path, validator, label in authoritative_files:
        path = root / relative_path
        if path.is_symlink() or not path.is_file():
            errors.append(label + " is missing or symbolic")
            continue
        try:
            text = read(path)
        except (OSError, UnicodeError):
            errors.append(label + " is unavailable")
            continue
        if validator(text):
            errors.append(label + " is non-canonical")
    try:
        load_admission_suspension(root)
    except (
        CanonicalYamlError,
        TRANSITION_RELEASE_STATE.CanonicalYamlError,
        OSError,
        UnicodeError,
    ):
        errors.append("Flux admission reconciliation is non-canonical")
    return errors


def signature_admission_install_errors(root):
    """Prove the signature policy is part of reconciled Kyverno desired state."""
    errors = []
    reconciliation_index = root / "kubernetes/reconciliation/kustomization.yaml"
    if not reconciliation_index.is_file() or not active_kustomization_resource(
        read(reconciliation_index), "admission.yaml"
    ):
        errors.append("admission reconciliation is not active from the Flux root")

    admission_reconciliation = root / "kubernetes/reconciliation/admission.yaml"
    if admission_reconciliation.is_file():
        admission_text = read(admission_reconciliation)
        for fragment in [
            "path: ./kubernetes/platform/admission",
            "serviceAccountName: admission-reconciler",
            "wait: true",
        ]:
            if fragment not in admission_text:
                errors.append("admission reconciliation contract is missing: " + fragment)

    admission_index = root / "kubernetes/platform/admission/kustomization.yaml"
    if admission_index.is_file():
        admission_index_text = read(admission_index)
        for resource in ["kyverno/controllers.yaml", "../../../policies/kyverno"]:
            if not active_kustomization_resource(admission_index_text, resource):
                errors.append("admission desired state is missing active resource: " + resource)

    kyverno_controllers = root / "kubernetes/platform/admission/kyverno/controllers.yaml"
    if kyverno_controllers.is_file():
        controller_text = read(kyverno_controllers)
        for fragment in [
            "kind: Deployment",
            "kind: Service",
            "kind: ValidatingWebhookConfiguration",
            "app.kubernetes.io/part-of: kyverno",
        ]:
            if fragment not in controller_text:
                errors.append("Kyverno controller desired state is missing: " + fragment)
    return errors


def site_release_override_errors(domain, release_state):
    """Validate the authoritative production values of one HelmRelease."""

    errors = []
    release_digest = release_state.values.get(("image", "digest"))
    if release_digest == ZERO_DIGEST:
        errors.append(
            "{} HelmRelease override must contain one nonzero image digest".format(
                domain
            )
        )
    if release_state.values.get(("deploymentReady",)) != "true":
        errors.append("{} HelmRelease override is not deploymentReady".format(domain))
    return errors


def _plain_yaml_scalar(value):
    """Normalize the narrow quoted scalars used by capacity manifests."""

    if (
        isinstance(value, str)
        and len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {"'", '"'}
    ):
        return value[1:-1]
    return value


def _quota_documents(text):
    """Return canonical mapping-only ResourceQuota documents."""

    if "\r" in text or not text.endswith("\n"):
        raise CanonicalYamlError("capacity YAML must be UTF-8/LF terminated")
    documents = []
    current = []
    for line in text.split("\n"):
        if re.fullmatch(r"[ ]*---[ ]*", line):
            if current:
                documents.append("\n".join(current) + "\n")
                current = []
            continue
        if re.fullmatch(r"[ ]*[.][.][.][ ]*", line):
            raise CanonicalYamlError("capacity YAML document terminator is forbidden")
        current.append(line)
    if any(line.strip() for line in current):
        documents.append("\n".join(current).rstrip("\n") + "\n")

    quotas = []
    for document in documents:
        if canonical_scalar(document, ("kind",)) != "ResourceQuota":
            continue
        # The shared release parser intentionally limits ordinary mapping keys
        # to a small grammar. Translate only these two reviewed annotation keys
        # to internal aliases; every other slash-bearing key still fails closed.
        normalized = re.sub(
            r"(?m)^    platform[.]snaraj[.]dev/readiness:",
            "    capacity_readiness:",
            document,
        )
        normalized = re.sub(
            r"(?m)^    platform[.]snaraj[.]dev/capacity-evidence-sha256:",
            "    capacity_evidence_sha256:",
            normalized,
        )
        lines = []
        for line in normalized.split("\n"):
            quoted = re.fullmatch(
                r"(?P<prefix>[ ]*[A-Za-z0-9_.-]+): (?P<quote>['\"])(?P<value>[A-Za-z0-9./][A-Za-z0-9_./:@+-]*)(?P=quote)",
                line,
            )
            if quoted is not None:
                line = "{}: {}".format(
                    quoted.group("prefix"), quoted.group("value")
                )
            lines.append(line)
        quotas.append(_parse_simple_mapping(lines, 0, len(lines), 0))
    return quotas


def reviewed_capacity_errors(root):
    """Require one hash-bound reviewed namespace budget for each website."""

    errors = []
    prerequisites_index = root / "kubernetes/platform/prerequisites/kustomization.yaml"
    resource_controls = root / "kubernetes/platform/prerequisites/resource-controls.yaml"
    if not prerequisites_index.is_file() or not active_kustomization_resource(
        read(prerequisites_index), "resource-controls.yaml"
    ):
        errors.append("reviewed website capacity resource-controls are not reconciled")

    try:
        quotas = _quota_documents(read(resource_controls))
    except (CanonicalYamlError, OSError, UnicodeError):
        return errors + ["reviewed website capacity quota inventory is non-canonical"]

    expected_namespaces = {slug for _, slug, _ in SITE_RELEASE_CONTRACTS}
    for namespace in sorted(expected_namespaces):
        matches = [
            quota for quota in quotas
            if _plain_yaml_scalar(quota.get(("metadata", "namespace"))) == namespace
        ]
        if len(matches) != 1:
            errors.append(
                "reviewed website capacity quota missing or duplicated: " + namespace
            )
            continue
        quota = matches[0]
        if _plain_yaml_scalar(quota.get(("metadata", "name"))) != "namespace-budget":
            errors.append("reviewed website capacity quota identity is invalid: " + namespace)
        if _plain_yaml_scalar(quota.get(
            ("metadata", "annotations", "capacity_readiness")
        )) != "reviewed-pi-capacity":
            errors.append("reviewed website capacity readiness is invalid: " + namespace)
        evidence = _plain_yaml_scalar(quota.get(
            (
                "metadata", "annotations",
                "capacity_evidence_sha256",
            )
        ))
        if not isinstance(evidence, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence):
            errors.append("reviewed website capacity evidence hash is invalid: " + namespace)
        hard = {
            path[-1]: _plain_yaml_scalar(value)
            for path, value in quota.items()
            if len(path) == 3 and path[:2] == ("spec", "hard")
        }
        if set(hard) != {
            "pods", "requests.cpu", "requests.memory", "limits.cpu", "limits.memory"
        }:
            errors.append("reviewed website capacity limits are incomplete: " + namespace)
        else:
            if not re.fullmatch(r"[2-9]|[1-9][0-9]+", str(hard["pods"])):
                errors.append("reviewed website Pod capacity is invalid: " + namespace)
            for key in ("requests.cpu", "requests.memory", "limits.cpu", "limits.memory"):
                if not re.fullmatch(r"[1-9][0-9]*(?:m|Ki|Mi|Gi)?", str(hard[key])):
                    errors.append(
                        "reviewed website capacity quantity is invalid: {} {}".format(
                            namespace, key
                        )
                    )

    kyverno_index = root / "policies/kyverno/kustomization.yaml"
    if kyverno_index.is_file() and active_kustomization_resource(
        read(kyverno_index), "require-zero-site-capacity.yaml"
    ):
        errors.append("zero-site-capacity admission policy remains active")
    return errors


def check_release(root):
    errors = []
    versions = read(root / "versions.env")
    if re.search(r"(?m)^[A-Z0-9_]+=UNRESOLVED$", versions):
        errors.append("versions.env still contains UNRESOLVED pins")
    required_generated = [
        "kubernetes/flux-system/controllers/gotk-components.yaml",
        "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml",
        "kubernetes/platform/admission/kyverno/controllers.yaml",
        "kubernetes/platform/admission/kustomization.yaml",
        "kubernetes/reconciliation/admission.yaml",
    ] + [path.as_posix() for path in sorted(CLOUDFLARE_LOCK_FILES)]
    for name in required_generated:
        if not (root / name).is_file():
            errors.append("required reviewed/generated file missing: " + name)

    sops_config = read(root / ".sops.yaml")
    if "REPLACE_WITH_PUBLIC_RECIPIENT" in sops_config:
        errors.append(".sops.yaml still has the invalid public-recipient sentinel")
    configured_recipients = re.findall(
        r"(?m)^\s*-\s*(age1[0-9a-z]+)\s*$", sops_config
    )
    if len(configured_recipients) != 1:
        errors.append(".sops.yaml must contain exactly one valid age recipient")

    for domain, slug, _ in SITE_RELEASE_CONTRACTS:
        try:
            release_state = load_helm_release(slug, root)
        except (CanonicalYamlError, OSError, UnicodeError):
            errors.append("{} release state is unavailable or non-canonical".format(domain))
            continue
        errors.extend(site_release_override_errors(domain, release_state))
        if release_state.suspended:
            errors.append("HelmRelease remains suspended: " + slug)
        try:
            if load_parent_suspension(slug, root):
                errors.append("parent Kustomization remains suspended: " + slug)
        except (CanonicalYamlError, OSError, UnicodeError):
            errors.append("{} parent release state is unavailable or non-canonical".format(domain))

    try:
        public_release = load_helm_release("cloudflare-public", root)
        if public_release.suspended:
            errors.append("HelmRelease remains suspended: cloudflare-public")
        token_revision = public_release.values.get(("tunnel", "tokenRevision"))
        if token_revision in {None, "not-configured", "UNRESOLVED"}:
            errors.append("public tunnel tokenRevision is unresolved")
        if load_parent_suspension("cloudflare-public", root):
            errors.append("parent Kustomization remains suspended: platform-services")
    except (CanonicalYamlError, OSError, UnicodeError):
        errors.append("public tunnel release state is unavailable or non-canonical")

    tunnel_kustomization = read(
        root / "kubernetes/platform/cloudflare-public/release/kustomization.yaml"
    )
    if not active_kustomization_resource(tunnel_kustomization, "tunnel-token.sops.yaml"):
        errors.append("encrypted tunnel token is not active in the public release Kustomization")
    tunnel_secret = root / "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml"
    if tunnel_secret.is_file() and len(configured_recipients) == 1:
        for problem in tunnel_secret_errors(read(tunnel_secret), configured_recipients[0]):
            errors.append("invalid production tunnel Secret: " + problem)
    errors.extend(signature_policy_source_errors(root))
    for domain, slug, workflow in SITE_RELEASE_CONTRACTS:
        signature_policy = root / "policies/kyverno" / (
            "require-signed-{}.yaml".format(slug)
        )
        if signature_policy.is_symlink() or not signature_policy.is_file():
            continue
        try:
            signature_text = read(signature_policy)
        except (OSError, UnicodeError):
            continue
        if signature_policy_action(signature_text, slug, workflow) != "Enforce":
            errors.append("{} signature admission policy is not enforced".format(domain))

    errors.extend(signature_admission_install_errors(root))
    errors.extend(reviewed_capacity_errors(root))
    return errors


def cloudflare_visible_configuration_errors(root):
    """Return Git-visible Terraform inventory/input failures as activation signals."""

    base = root / "infrastructure" / "cloudflare"
    if not base.exists():
        return []
    visible_paths, errors = _git_visible_cloudflare_paths(root)
    errors.extend(cloudflare_phase_contract_errors(root))
    expected_sources = {
        path.as_posix() for path in CLOUDFLARE_TERRAFORM_SOURCE_FILES
    }
    visible_sources = {
        path for path in visible_paths if path.endswith(".tf")
    }
    if visible_sources != expected_sources:
        errors.append("Cloudflare Terraform source inventory is outside the closed contract")
    expected_phase_files = {
        path.as_posix() for path in CLOUDFLARE_TERRAFORM_REVIEW_FILES
    }
    visible_phase_files = {
        path for path in visible_paths
        if path.startswith("infrastructure/cloudflare/phases/")
    }
    if visible_phase_files != expected_phase_files:
        errors.append("Cloudflare phase file inventory is outside the closed contract")
    for relative_path in visible_paths:
        name = Path(relative_path).name
        if name.endswith(".tf.json") or name.endswith(".tfvars") or name.endswith(".tfvars.json"):
            errors.append("Cloudflare Terraform auto-loaded input is Git-visible")
            break
    return errors


def activation_requested(root):
    if cloudflare_visible_configuration_errors(root):
        return True
    for name, contract in RELEASE_CONTRACTS.items():
        release_path = root / str(contract["release"])
        if release_path.is_file():
            try:
                if not load_helm_release(name, root).suspended:
                    return True
            except (CanonicalYamlError, OSError, UnicodeError):
                # An ambiguous activation gate is itself an activation signal:
                # invoke the full fail-closed release check instead of treating
                # a parser failure as a safely suspended release.
                return True
        parent_path = root / str(contract["parent"])
        if parent_path.is_file():
            try:
                if not load_parent_suspension(name, root):
                    return True
            except (CanonicalYamlError, OSError, UnicodeError):
                return True
    tunnel_kustomization = root / "kubernetes/platform/cloudflare-public/release/kustomization.yaml"
    if tunnel_kustomization.is_file() and active_kustomization_resource(
        read(tunnel_kustomization), "tunnel-token.sops.yaml"
    ):
        return True
    for _, slug, _ in SITE_RELEASE_CONTRACTS:
        signature_policy = root / "policies" / "kyverno" / (
            "require-signed-{}.yaml".format(slug)
        )
        if signature_policy.is_file() and re.search(
            r"(?m)^\s*validationFailureAction:\s*Enforce\s*$", read(signature_policy)
        ):
            return True
    return False


def _allowed_transition_release_errors(plan):
    """Return only full-release failures made inert by the classified phase."""

    allowed = set()
    phases = {
        "naranjo-online": plan.naranjo_online,
        "lidersea-com": plan.lidersea_com,
    }
    for domain, slug, workflow in SITE_RELEASE_CONTRACTS:
        phase = phases[slug]
        if phase == "active":
            continue
        allowed.update({
            "HelmRelease remains suspended: " + slug,
            "parent Kustomization remains suspended: " + slug,
        })
        # A suspended child is not yet proven inert while its outer Flux
        # Kustomization remains active. Keep signature enforcement mandatory
        # through the child-first rollback and parent-first resume windows.
        if plan.website_parent_suspended(slug):
            allowed.update({
                "{} signature admission policy is missing".format(domain),
                "{} signature admission policy is not enforced".format(domain),
                "{} signature admission policy is non-canonical".format(domain),
                "{} signature admission policy is not active in its Kustomization".format(domain),
            })
        if phase == "initial":
            allowed.update({
                "{} HelmRelease override must contain one nonzero image digest".format(domain),
                "{} HelmRelease override is not deploymentReady".format(domain),
            })

    if plan.cloudflare_public != "active":
        allowed.update({
            "HelmRelease remains suspended: cloudflare-public",
            "parent Kustomization remains suspended: platform-services",
        })
    if plan.cloudflare_public == "initial":
        # Exact classification already proved the Secret absent and unlisted.
        # Only those expected pre-ceremony failures are inert; staged state must
        # never filter a missing, unlisted, or malformed encrypted Secret.
        allowed.update({
            "public tunnel tokenRevision is unresolved",
            "required reviewed/generated file missing: kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml",
            ".sops.yaml still has the invalid public-recipient sentinel",
            ".sops.yaml must contain exactly one valid age recipient",
            "encrypted tunnel token is not active in the public release Kustomization",
        })
    return allowed


def _transition_release_error_is_allowed(error, plan, allowed):
    if error in allowed:
        return True
    if not plan.any_website_active and error.startswith(
        (
            "reviewed website capacity ",
            "zero-site-capacity admission policy remains active",
        )
    ):
        return True
    return False


def check_activation(root):
    # The strict classifier is authoritative even when every gate looks inert:
    # ambiguous YAML, dependency drift, or a one-way suspension violation must
    # never be mistaken for scaffold state.
    try:
        plan = classify_release_transition(root)
    except (
        CanonicalYamlError,
        TRANSITION_RELEASE_STATE.CanonicalYamlError,
        OSError,
        RuntimeError,
        UnicodeError,
    ):
        return ["release transition state is unavailable or unsafe"]

    if plan.mode == "release":
        return check_release(root)

    errors = []
    try:
        activation_signal = activation_requested(root)
    except (CanonicalYamlError, OSError, RuntimeError, UnicodeError):
        return ["release transition state is unavailable or unsafe"]
    if plan.mode == "scaffold":
        if activation_signal:
            errors.append("scaffold desired state contains a release activation signal")
        return errors
    if not plan.any_workload_active and not activation_signal:
        return errors

    # Reuse the complete production contract whenever any controller or public
    # workload is active. Filter only failures whose exact release is proven
    # inert by the classifier; shared controller/install failures and every
    # active or outer-reconcilable workload's identity, SOPS, signature, and
    # capacity proof remain mandatory.
    allowed = _allowed_transition_release_errors(plan)
    errors.extend(
        error for error in check_release(root)
        if not _transition_release_error_is_allowed(error, plan, allowed)
    )
    return list(dict.fromkeys(errors))


CHECKS = {
    "layout": check_layout,
    "privacy": check_privacy,
    "media": check_media,
    "secrets": check_secrets,
    "workflows": check_workflows,
    "kubernetes": check_kubernetes,
    "cloudflare": check_cloudflare,
    "activation": check_activation,
    "release": check_release,
}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("checks", nargs="*", choices=sorted(CHECKS) + ["all"])
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    selected = args.checks or ["all"]
    if "all" in selected:
        selected = [name for name in CHECKS if name != "release"]
    elif "release" in selected:
        selected = [name for name in CHECKS if name != "release"] + ["release"]
    failures = []
    for name in selected:
        try:
            current = CHECKS[name](args.root.resolve())
        except (OSError, UnicodeError):
            current = ["safe public file snapshot is unavailable"]
        if current:
            failures.extend("{}: {}".format(name, item) for item in current)
        else:
            print("PASS {}".format(name))
    if failures:
        for item in failures:
            print("FAIL " + item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
