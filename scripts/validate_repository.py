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
from validate_image_release import (
    SITE_CONTRACTS as IMAGE_RELEASE_SITE_CONTRACTS,
    read_policy as read_release_policy,
    repository_errors as image_release_errors,
)
from validate_release_state import (
    CanonicalYamlError,
    PUBLIC_CONNECTOR_SITES,
    RELEASE_CONTRACTS,
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
    sops_recipient_from_config,
    sops_secret_errors,
    tunnel_secret_errors,
)
from validate_signature_policy import (
    CHART_REPOSITORIES,
    chart_source_errors,
    flux_sync_errors,
    flux_system_kustomization_errors,
)
# dependabot_contract intentionally is not validate_-prefixed: it runs only
# through the CHECKS registry below (issue #131), never as its own CLI
# invocation in validate-security.sh or pull-request.yml, so it stays outside
# tests/security/test_validator_invocation_parity.py's local/CI symmetry net
# by construction -- see that module's own docstring for the full rationale.
from dependabot_contract import file_errors as dependabot_contract_errors


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
# ceiling sits far below the API limit and is backed by the retained static
# policy controls.
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
# cannot silently leave signed chart publication, selection, or activation
# asymmetric.
# The third element is the publisher workflow inside each STANDALONE site
# repository, dispatched from that repository's protected `main` branch; it
# feeds the pinned signature identities.
SITE_RELEASE_CONTRACTS = (
    ("naranjo.online", "naranjo-online", "release-publisher.yml"),
    ("lidersea.com", "lidersea-com", "release-publisher.yml"),
)

# Owner-reviewed capacity is one closed decision, not merely a syntactically
# valid ResourceQuota.  Bind every site budget to the exact sanitized audit
# bytes and exact five-field quota map approved in issue #201.
REVIEWED_SITE_CAPACITY_EVIDENCE = Path(
    "docs/audits/2026-08-22-site-capacity-evidence.md"
)
REVIEWED_SITE_CAPACITY_HARD = {
    "pods": "6",
    "requests.cpu": "150m",
    "requests.memory": "192Mi",
    "limits.cpu": "1200m",
    "limits.memory": "768Mi",
}

# This literal digest couples Trivy's path-scoped AVD-KSV-0056 acceptance to
# every ServiceAccount, Role, RoleBinding, rule, and subject in access.yaml.
# Update it only after reviewing that complete authorization file.
FLUX_ACCESS_CONTRACT_SHA256 = (
    "9c755188823d4037211be496086376a11241c85f31829628dd6bacb77f513d27"
)

# The same coupling for the six cluster-scoped per-controller objects, which
# live in the install root rather than access.yaml (issue #98). Cluster-wide
# authority does not get a weaker review gate than namespaced authority.
FLUX_PER_CONTROLLER_CONTRACT_SHA256 = (
    "b9b7a1f0626a203967f7f874699303367dd77ac9aeb934aeb61d4abd7215dd5a"
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
            metadata.st_nlink if final else None,
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


def site_default_deny_contract_errors(root):
    """Pin default-deny ownership to the exact direct-site topology."""

    errors = []

    def exact_default_deny(path, namespace):
        if not path.is_file():
            return False
        documents = [
            document for document in re.split(r"(?m)^---\s*$", read(path))
            if document.strip()
        ]
        return len(documents) == 1 and bool(
            re.search(r"(?m)^apiVersion:\s*networking[.]k8s[.]io/v1\s*$", documents[0])
            and re.search(r"(?m)^kind:\s*NetworkPolicy\s*$", documents[0])
            and re.search(r"(?m)^\s*name:\s*default-deny\s*$", documents[0])
            and re.search(
                r"(?m)^\s*namespace:\s*{}\s*$".format(re.escape(namespace)),
                documents[0],
            )
            and re.search(r"(?m)^\s*podSelector:\s*{}\s*$", documents[0])
            and re.search(
                r"(?ms)^\s*policyTypes:\s*\n\s*-\s*Ingress\s*\n\s*-\s*Egress\s*$",
                documents[0],
            )
        )

    prerequisites = root / "kubernetes/platform/prerequisites"
    if not exact_default_deny(
        prerequisites / "network-policies.yaml", "cloudflare-public"
    ):
        errors.append(
            "platform prerequisites must retain exactly the cloudflare-public default-deny"
        )
    prerequisite_index = prerequisites / "kustomization.yaml"
    prerequisite_resources = re.findall(
        r"(?m)^\s*-\s+([A-Za-z0-9_.-]+)\s*$",
        read(prerequisite_index) if prerequisite_index.is_file() else "",
    )
    if set(prerequisite_resources) != {"network-policies.yaml", "resource-controls.yaml"} \
            or len(prerequisite_resources) != 2:
        errors.append("platform prerequisites Kustomization inventory is not exact")

    for namespace in ("naranjo-online", "lidersea-com"):
        site_root = root / "kubernetes/websites" / namespace
        if not exact_default_deny(site_root / "default-deny.yaml", namespace):
            errors.append("exact site-owned ingress+egress default-deny missing for " + namespace)
        site_index = site_root / "kustomization.yaml"
        site_resources = re.findall(
            r"(?m)^\s*-\s+([A-Za-z0-9_.-]+)\s*$",
            read(site_index) if site_index.is_file() else "",
        )
        if set(site_resources) != {"default-deny.yaml", "source.yaml", "release.yaml"} \
                or len(site_resources) != 3:
            errors.append(
                "direct site Kustomization inventory must be default-deny, source, release: "
                + namespace
            )
    return errors


def flux_access_contract_errors(text, expected=None, label="Flux access authorization"):
    """Require review of every byte in an accepted Flux authorization file.

    Parameterized over the digest because the authorization is now in TWO files
    (issue #98): the namespaced grants in access.yaml, and the six cluster-scoped
    per-controller objects that had to move into the install root so the
    transaction that removes the authority they replace also creates them.
    Moving them must not cost them their byte-level review coupling — an
    unpinned ClusterRole is a worse place to keep cluster-wide authority than a
    pinned Role.
    """

    # read_text already normalizes platform newlines; the explicit replacement
    # also makes direct unit-test input behave identically on Windows and Linux.
    normalized = text.replace("\r\n", "\n")
    observed = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if observed != (FLUX_ACCESS_CONTRACT_SHA256 if expected is None else expected):
        return [
            "{} changed; review every ServiceAccount, Role, RoleBinding, "
            "ClusterRole, ClusterRoleBinding, rule, and subject before updating "
            "its digest".format(label)
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
        "!/.sourceignore",
        "!/kubernetes/",
        "/kubernetes/*",
        "!/kubernetes/websites/",
        "/kubernetes/websites/*",
        "!/kubernetes/websites/naranjo-online/",
        "!/kubernetes/websites/naranjo-online/**",
        "!/kubernetes/websites/lidersea-com/",
        "!/kubernetes/websites/lidersea-com/**",
    )
    if not sourceignore.is_file():
        errors.append("Flux source artifact boundary is missing: .sourceignore")
    else:
        source_text = read(sourceignore)
        source_lines = tuple(
            line.strip() for line in source_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        if source_lines != source_required:
            errors.append("Flux source artifact allowlist is not the exact two-site boundary")

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
            if re.search(r"(?m)^kind:\s*HelmRelease\s*$", document) and re.search(
                r"(?m)^  (?:valuesFrom|kubeConfig|storageNamespace|targetNamespace):",
                document,
            ):
                errors.append(
                    "HelmRelease must not use controller-side external inputs or namespace redirects in "
                    + rel
                )
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


def check_dependabot(root):
    """Fail closed on any `.github/dependabot.yml` outside issue #131's contract.

    `check_workflows` above only globs `.github/workflows/*.yml`, and
    actionlint does not know the Dependabot config schema either, so this
    is the one gate that reads `.github/dependabot.yml` at all. Delegates
    to `dependabot_contract.file_errors`, a standard-library-only mini
    parser for the small block-YAML subset every real config in this
    repository family uses (see that module's docstring for the full
    grammar and the deliberate narrowings versus Dependabot's real schema).
    """

    return dependabot_contract_errors(root / ".github" / "dependabot.yml")


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
    # ``read`` returns text, so these are str keys and str values. The two
    # groups are named explicitly rather than splatted from ``match.groups()``:
    # that call is typed as a variable-length tuple, which reads as an
    # arbitrary-arity pair to a static checker and invites a bytes/str
    # confusion warning on a mapping that is unambiguously str-keyed here.
    values = {
        match.group(1): match.group(2)
        for match in re.finditer(r"(?m)^([A-Z0-9_]+)=([^\s#]+)$", versions_text)
    }
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


# The exact flux-system egress inventory. Conftest pins the shape of whichever
# policies a render contains; this pins that they are all present and reachable
# from the roots the install ceremony applies, because a policy file that no
# Kustomization references is desired state nobody ever applies.
FLUX_EGRESS_POLICIES = (
    "default-deny",
    "flux-controllers-dns",
    "flux-controllers-artifacts",
    "flux-controllers-public-https",
    "flux-controllers-kube-apiserver",
)
FLUX_CONTROL_PLANE_SENTINEL = "sentinel-until-private-calico-api-endpoint-set"
FLUX_API_CANARY_NAME = "flux-api-reachability-canary"


def flux_egress_contract_errors(root):
    """Require the fail-closed flux-system egress set and its wiring."""

    errors = []
    policies = root / "kubernetes/flux-system/egress/network-policies.yaml"
    if not policies.is_file():
        return ["fail-closed flux-system egress NetworkPolicies are missing"]
    text = read(policies)
    for name in FLUX_EGRESS_POLICIES:
        if not re.search(r"(?m)^\s*name:\s*{}\s*$".format(re.escape(name)), text):
            errors.append("required flux-system egress NetworkPolicy missing: " + name)
    documents = re.split(r"(?m)^---\s*$", text)
    exact_default_deny = [doc for doc in documents if (
        re.search(r"(?m)^\s*name:\s*default-deny\s*$", doc) and
        re.search(r"(?m)^\s*namespace:\s*flux-system\s*$", doc) and
        re.search(r"(?ms)^\s*policyTypes:\s*\n\s*-\s*Ingress\s*\n\s*-\s*Egress\s*$", doc)
    )]
    if len(exact_default_deny) != 1:
        errors.append("exact ingress+egress default-deny missing for flux-system")
    if FLUX_CONTROL_PLANE_SENTINEL not in text:
        errors.append("flux-system API-server egress must keep its unresolved control-plane sentinel")

    # The blanket `egress: [{}]` the Flux CLI generates is removed by patch;
    # an unreferenced patch file would leave the export unmodified while the
    # repository still looked hardened.
    patch = root / "kubernetes/flux-system/controllers/patches/allow-egress.yaml"
    if not patch.is_file():
        errors.append("generated allow-egress blanket rule is not patched away")
    elif not re.search(r"(?m)^-\s*op:\s*remove\s*$", read(patch)) or (
        "path: /spec/egress" not in read(patch)
    ):
        errors.append("allow-egress patch must remove /spec/egress and nothing else")
    # Pod Security on flux-system: the generated export only warns, so the
    # overlay's enforce labels are the control. A patch file that exists but is
    # not wired into the install root is the same failure as no patch at all,
    # which is why both halves are checked for both patches.
    namespace_patch = root / "kubernetes/flux-system/controllers/patches/namespace.yaml"
    if not namespace_patch.is_file():
        errors.append("flux-system Pod Security enforcement patch is missing")
    else:
        namespace_text = read(namespace_patch)
        for fragment in (
            "pod-security.kubernetes.io~1enforce",
            "value: restricted",
            "value: v1.36",
        ):
            if fragment not in namespace_text:
                errors.append(
                    "flux-system Pod Security patch must enforce restricted at a pinned "
                    "version: " + fragment
                )
    controllers_index = root / "kubernetes/flux-system/controllers/kustomization.yaml"
    if not controllers_index.is_file():
        errors.append("Flux controller install root is missing")
    else:
        controllers_text = read(controllers_index)
        for referenced in ("patches/allow-egress.yaml", "patches/namespace.yaml"):
            if referenced not in controllers_text:
                errors.append(
                    "Flux controller install root does not apply " + referenced
                )
    egress_index = root / "kubernetes/flux-system/egress/kustomization.yaml"
    if not egress_index.is_file():
        errors.append("Flux egress Kustomization root is missing")
    elif not active_kustomization_resource(read(egress_index), "network-policies.yaml"):
        errors.append("Flux egress resource is not reachable from its root")

    # The executable API-path proof is a separately rendered, one-Pod target.
    # Keeping it outside the bootstrap root makes it impossible for ordinary
    # GitOps reconciliation to create the probe, while the installer can still
    # bind and create its exact reviewed bytes immediately before controllers.
    canary_root = root / "kubernetes/flux-system/canary"
    canary_index = canary_root / "kustomization.yaml"
    canary_pod = canary_root / "pod.yaml"
    if not canary_index.is_file() or not canary_pod.is_file():
        errors.append("Flux API-path canary root or Pod is missing")
    else:
        if not active_kustomization_resource(read(canary_index), "pod.yaml"):
            errors.append("Flux API-path canary Pod is not reachable from its own root")
        canary_text = read(canary_pod)
        versions_path = root / "versions.env"
        versions_text = read(versions_path) if versions_path.is_file() else ""
        image = re.search(r"(?m)^FLUX_API_CANARY_IMAGE=(\S+)$", versions_text)
        required_canary_fragments = (
            "kind: Pod",
            "name: " + FLUX_API_CANARY_NAME,
            "namespace: flux-system",
            "app: source-controller",
            "app.kubernetes.io/part-of: flux",
            "serviceAccountName: source-controller",
            "value: kubernetes.default.svc",
            "- --raw=/api",
            "automountServiceAccountToken: true",
            "readOnlyRootFilesystem: true",
            "allowPrivilegeEscalation: false",
        )
        for fragment in required_canary_fragments:
            if fragment not in canary_text:
                errors.append("Flux API-path canary is missing: " + fragment)
        if not image:
            errors.append("versions.env is missing FLUX_API_CANARY_IMAGE")
        elif "image: " + image.group(1) not in canary_text:
            errors.append("Flux API-path canary image does not match versions.env")
        if re.search(r"(?m)^\s*(hostNetwork|hostPID|hostIPC):\s*true\s*$", canary_text):
            errors.append("Flux API-path canary must not enter a host namespace")

    # The egress overlay is deliberately NOT a resource of
    # kubernetes/flux-system remains an owner-attended installation root. The
    # bootstrap-owned sync objects live only in a deliberately non-applicable
    # review template; rendering the egress overlay separately still keeps the
    # controller-install boundary explicit.
    renderer = root / "scripts/render-manifests.sh"
    if not renderer.is_file():
        errors.append("canonical renderer is missing")
    else:
        renderer_text = read(renderer)
        if not re.search(r"(?m)^\s*kubernetes/flux-system/egress\s*$", renderer_text):
            errors.append("flux-system egress overlay is not a rendered target")
        if not re.search(r"(?m)^\s*kubernetes/flux-system/canary\s*$", renderer_text):
            errors.append("flux-system API-path canary is not a rendered target")
    root_index = root / "kubernetes/flux-system/kustomization.yaml"
    if root_index.is_file() and active_kustomization_resource(read(root_index), "egress"):
        errors.append(
            "flux-system egress must not be reachable from the unsuspended bootstrap root"
        )
    if root_index.is_file() and active_kustomization_resource(read(root_index), "canary"):
        errors.append(
            "flux-system API-path canary must not be reachable from the bootstrap root"
        )
    return errors


# The install's three cross-file properties, joined here because no single file
# can hold them: the ORDER the controllers and their allows are applied in, the
# BINDING of the tools and the target the apply runs against, and the
# completeness of the documented REMOVAL. Each has an executable regression in
# tests/security/test_flux_install_contract.py; these are the static coupling —
# a constant edited on its own, a fail-closed refusal deleted, or a
# cluster-scoped object dropped from the runbook's removal, all fail here.
# Each entry is a fail-closed refusal that a commit must not be able to delete
# quietly. A grep is NOT what pins them -- it only notices the deletion. What
# proves each still WORKS is a behavioural test that feeds the installer the
# input the refusal exists for, and
# tests/security/test_flux_install_contract.py::RefusalCoverageTests requires
# every entry here to name one. That coupling is deliberate: a refusal pinned
# only by its own message string survived being replaced with a condition that
# never matches, message intact -- which is how the phase-1 ordering guard was
# found neutered with the whole suite green.
FLUX_INSTALLER_REFUSALS = (
    "--kubeconfig is required",
    "--context is required",
    "--server is required",
    "--cni-provider is required",
    "--api-endpoint is required",
    "--expect-render-sha256 is required",
    "--expect-egress-sha256 is required",
    "--expect-canary-sha256 is required",
    "--expect-commit is required",
    "no reviewed API-destination contract",
    "could not prove the selected Calico CNI identity",
    "the installer and its guards are not the reviewed ones",
    "the egress bytes this would apply are not the reviewed ones",
    "the API endpoint-set substitution changed bytes outside",
    "the in-Pod Kubernetes Service/API canary did not succeed",
    "does not match versions.env KUSTOMIZE_LINUX_AMD64_SHA256",
    "matches no versions.env kubectl digest pin",
    "does not exactly match the complete live kubernetes.default EndpointSlice set",
    "the install inputs carry uncommitted modifications",
    "is not owned by this install",
    "ROLLBACK INCOMPLETE",
    "the ordering that prevents the egress deadlock is broken",
    "--apply installs only onto a fresh cluster",
    "API/RBAC/timeout failure keeps public egress shut",
    "the controllers are reconciling, not idle",
    "the live startup egress policies are not the reviewed shape",
    "this absent-only transaction never adopts",
    "poststate differs from the exact reviewed object",
)
FLUX_INSTALLER_PIN_KEYS = (
    "KUSTOMIZE_VERSION",
    "KUSTOMIZE_LINUX_AMD64_SHA256",
    "KUBERNETES_VERSION",
    "KUBECTL_LINUX_AMD64_SHA256",
    "KUBECTL_ARM64_SHA256",
    "FLUX_API_CANARY_IMAGE",
)


def cluster_scoped_flux_objects(root):
    """Return the install root's cluster-scoped object names.

    These are the objects a `kubectl delete namespace flux-system` cannot
    remove, so they are exactly the set the runbook's removal procedure and the
    installer's rollback both have to cover.

    That set is NOT just the generated export any more. The six per-controller
    objects (issue #98) are authored, are created by the same install, and are
    cluster scoped for the same reason the shared role is — so leaving them out
    here would let a rollback report success while three ClusterRoles and three
    ClusterRoleBindings stayed behind on the cluster.
    """

    export = root / "kubernetes/flux-system/controllers/gotk-components.yaml"
    if not export.is_file():
        return []
    controllers = export.parent
    deleted = set()
    index = controllers / "kustomization.yaml"
    if index.is_file():
        for relative in re.findall(r"(?m)^\s*path:\s*(\S+)\s*$", read(index)):
            candidate = Path(relative)
            if candidate.is_absolute() or ".." in candidate.parts:
                continue
            patch = controllers / candidate
            if not patch.is_file():
                continue
            patch_text = read(patch)
            if not re.search(r"(?m)^\$patch:\s*delete\s*$", patch_text):
                continue
            kind = re.search(r"(?m)^kind:\s*(\S+)\s*$", patch_text)
            name = re.search(r"(?m)^  name:\s*(\S+)\s*$", patch_text)
            if kind and name:
                deleted.add((kind.group(1), name.group(1)))

    sources = [read(export)]
    authored = root / FLUX_PER_CONTROLLER_RBAC_RELATIVE
    if authored.is_file():
        sources.append(read(authored))

    names = []
    for text in sources:
        for document in re.split(r"(?m)^---\s*$", text):
            kind = re.search(r"(?m)^kind:\s*(\S+)\s*$", document)
            name = re.search(r"(?m)^  name:\s*(\S+)\s*$", document)
            if not kind or not name:
                continue
            identity = (kind.group(1), name.group(1))
            if kind.group(1) in {
                "CustomResourceDefinition",
                "ClusterRole",
                "ClusterRoleBinding",
            } and identity not in deleted:
                names.append(name.group(1))
    return names


def flux_install_ceremony_errors(root):
    """Require the ordered, bound, reversible install ceremony to stay intact."""

    errors = []
    installer = root / "scripts/install-flux-controllers.sh"
    runbook = root / "docs/runbooks/flux-install.md"
    if not installer.is_file():
        return ["the sanctioned Flux controller installer is missing"]
    text = read(installer)

    # The phase constants must partition the reviewed inventory. Editing one in
    # isolation is the mistake that would silently drop an object out of a phase
    # -- or move a Deployment back into the phase that runs before its allows.
    constants = {}
    for key in (
        "EXPECTED_OBJECTS",
        "EXPECTED_PREREQUISITES",
        "EXPECTED_WORKLOADS",
        "EXPECTED_EGRESS_POLICIES",
        "EXPECTED_STARTUP_POLICIES",
    ):
        found = re.search(r"(?m)^{}=(\d+)\s*$".format(key), text)
        if not found:
            errors.append("Flux installer no longer declares " + key)
        else:
            constants[key] = int(found.group(1))
    if len(constants) == 5:
        if (
            constants["EXPECTED_PREREQUISITES"] + constants["EXPECTED_WORKLOADS"]
            != constants["EXPECTED_OBJECTS"]
        ):
            errors.append(
                "Flux install phases do not partition the reviewed controller inventory"
            )
        if constants["EXPECTED_STARTUP_POLICIES"] + 1 != constants["EXPECTED_EGRESS_POLICIES"]:
            errors.append(
                "Flux egress phases do not partition the reviewed egress overlay"
            )

    for refusal in FLUX_INSTALLER_REFUSALS:
        if refusal not in text:
            errors.append("Flux installer no longer refuses: " + refusal)
    for key in FLUX_INSTALLER_PIN_KEYS:
        if key not in text:
            errors.append("Flux installer no longer binds the versions.env pin " + key)
        versions = root / "versions.env"
        if versions.is_file() and not re.search(
            r"(?m)^{}=\S+$".format(re.escape(key)), read(versions)
        ):
            errors.append("versions.env no longer carries the pin " + key)

    if not runbook.is_file():
        errors.append("the Flux install runbook is missing")
        return errors
    # Whitespace-normalized so a reflowed paragraph is not a false failure.
    prose = " ".join(read(runbook).split())
    for fragment in (
        "--open-public-egress",
        "--expect-render-sha256",
        "--expect-egress-sha256",
        "--expect-canary-sha256",
        "--cni-provider",
        "--api-endpoint",
        "`kubectl delete namespace flux-system` is **not sufficient**",
    ):
        if fragment not in prose:
            errors.append("the Flux install runbook no longer states: " + fragment)
    for name in cluster_scoped_flux_objects(root):
        if name not in prose:
            errors.append(
                "the Flux install runbook's removal omits the cluster-scoped object " + name
            )
    return errors


# The three ServiceAccounts the reviewed component set actually creates. The
# generated export binds seven, four of which name accounts that do not exist;
# a dangling subject grants nothing today and everything the day its controller
# is installed, so the subject list is pinned to what exists.
FLUX_CONTROLLER_ACCOUNTS = ("source-controller", "kustomize-controller", "helm-controller")

# The narrowing patches, each paired with the object it rewrites. The mapping is
# the contract: a patch file that exists but is not wired into the install root
# leaves the generated export untouched while the repository reads as hardened,
# which is the same failure as having no patch at all.
FLUX_RBAC_PATCHES = {
    "cluster-reconciler.yaml": ("ClusterRoleBinding", "cluster-reconciler-flux-system"),
    "crd-controller-role.yaml": ("ClusterRole", "crd-controller-flux-system"),
    "crd-controller-binding.yaml": ("ClusterRoleBinding", "crd-controller-flux-system"),
}

# Authorization this repository writes itself, as opposed to the generated
# export. Wildcards are refused here because every rule in these files is
# derived from an enumerated desired state; a wildcard would mean the derivation
# was abandoned.
FLUX_AUTHORED_RBAC_FILES = (
    "kubernetes/flux-system/access.yaml",
    "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
    "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
)

# The per-controller replacement authority, and the one thing about it that is
# not negotiable: it is a RESOURCE OF THE INSTALL ROOT. The installer applies
# `kubernetes/flux-system/controllers` and nothing else, while access.yaml is
# reconciled later by Flux, so authority that replaces authority removed by the
# install transaction has to be created by that same transaction.
FLUX_PER_CONTROLLER_RBAC_RELATIVE = (
    "kubernetes/flux-system/controllers/per-controller-rbac.yaml"
)

# The per-controller split (issue #98). `crd-controller-flux-system` is ONE
# ClusterRole bound to all three controller ServiceAccounts, so every Flux-group
# verb it granted was a verb each controller held over the OTHER two's
# reconciliation specifications — and impersonation does not contain that,
# because the victim controller performs the resulting reconciliation. These
# three ClusterRoles carry that authority instead, one ServiceAccount each.
#
# Required by name and by subject count: a missing role is a controller that
# cannot reconcile at all, and a second subject on one of these bindings would
# rebuild the shared role under a new name while every rule still read correctly.
FLUX_PER_CONTROLLER_CLUSTER_ROLES = {
    "crd-controller-source-flux-system": "source-controller",
    "crd-controller-kustomize-flux-system": "kustomize-controller",
    "crd-controller-helm-flux-system": "helm-controller",
}

# The API groups whose objects ARE a controller's reconciliation specification.
# A verb over cluster metadata may be shared by all three controllers; a verb
# over one of these groups may not, so the shared role names none of them.
FLUX_EXECUTION_API_GROUPS = (
    "source.toolkit.fluxcd.io",
    "kustomize.toolkit.fluxcd.io",
    "helm.toolkit.fluxcd.io",
)

# Controller and impersonated identities that carry the exact direct-site
# reconciliation graph. Absence of any one is a reconciliation that cannot
# start; an extra one is unrelated path authority.
FLUX_CONTROLLER_ROLE_NAMESPACES = {
    "flux-controller-runtime": ("flux-system",),
    "flux-controller-impersonation": (
        "flux-system", "naranjo-online", "lidersea-com",
    ),
    "flux-release-reconciler": ("naranjo-online", "lidersea-com"),
    "helm-reconciler": ("naranjo-online", "lidersea-com"),
}

RBAC_WRITE_VERBS = ("create", "update", "patch", "delete", "deletecollection")
RBAC_READ_VERBS = ("get", "list", "watch")
DISABLE_CONFIG_WATCHERS_FLAG = (
    "--feature-gates=DisableConfigWatchers=true"
)


def _yaml_documents(text):
    """Split a multi-document manifest the way the other checks here do."""

    return re.split(r"(?m)^---\s*$", text)


# One `subjects:` entry, matched a line at a time. Each pattern is anchored and
# contains no cross-line `\s*`, so nothing here can scan past its own line.
_SUBJECT_KIND_LINE = re.compile(r"^\s*-\s+kind:\s*ServiceAccount\s*$")
_SUBJECT_NAME_LINE = re.compile(r"^\s*name:\s*(\S+)\s*$")
_SUBJECT_NAMESPACE_LINE = re.compile(r"^\s*namespace:\s*(\S+)\s*$")


def _service_account_subjects(document, *, with_namespace=False):
    """Return the ServiceAccount subjects of one binding document.

    Replaces the regex that spelled the same rule across lines::

        (?m)^\\s*-\\s+kind:\\s*ServiceAccount\\s*$\\n\\s*name:\\s*(\\S+)\\s*$

    ``\\s`` matches a newline, so the ``\\s*`` before ``name:`` could span an
    unbounded run of whitespace-only lines and then backtrack through it one
    position at a time — once per candidate start. The cost was QUADRATIC in
    document length: measured on a hostile document of alternating subject
    heads and blank lines, 1,000 lines took 12.7ms, 2,000 took 49.8ms, 4,000
    took 202ms and 8,000 took 783ms — a clean 4x per 2x, extrapolating past
    30 seconds at 100,000 lines (issue #166). It was slow rather than wrong,
    which is why it survived three copies.

    The line scan below reads each line once and keeps the same rule: a
    subject head, then the next NON-BLANK line must be its ``name:`` (and,
    when asked, the one after that its ``namespace:``). Whitespace-only lines
    between them are skipped, which is exactly the set the old ``\\s*`` could
    consume. Anything else ends that subject with no entry — and every caller
    compares the result against an exact expected tuple, so extracting fewer
    subjects raises the mismatch error rather than passing quietly.
    """

    lines = document.split("\n")
    subjects = []
    for index, line in enumerate(lines):
        if not _SUBJECT_KIND_LINE.match(line):
            continue
        cursor = index + 1
        fields = []
        for pattern in (
            (_SUBJECT_NAME_LINE, _SUBJECT_NAMESPACE_LINE)
            if with_namespace
            else (_SUBJECT_NAME_LINE,)
        ):
            while cursor < len(lines) and not lines[cursor].strip():
                cursor += 1
            match = pattern.match(lines[cursor]) if cursor < len(lines) else None
            if match is None:
                fields = None
                break
            fields.append(match.group(1))
            cursor += 1
        if fields is None:
            continue
        subjects.append(tuple(fields) if with_namespace else fields[0])
    return subjects


def _rbac_rule_blocks(document):
    """Return the text of each `rules:` entry in one RBAC document.

    The RBAC files this repository authors use one canonical shape — a
    top-level ``rules:`` sequence whose entries are two-space-indented ``- ``
    items — so the rules can be sliced textually without a YAML parser, which
    the fast gate deliberately cannot depend on.
    """

    match = re.search(r"(?ms)^rules:\s*$\n(?P<body>(?:[ \t].*\n?|\n)*)", document)
    if match is None:
        return []
    body = match.group("body")
    # The item indent is DERIVED from the first entry rather than assumed. An
    # assumed range (the original "no more than four spaces") is the same
    # vacuity class as matching only one list style: re-indenting a rule by two
    # columns is valid YAML that changes nothing about what it grants, and it
    # would have slipped every check built on top of this helper.
    lead = re.search(r"(?m)^(?P<indent>\s*)-\s", body)
    if lead is None:
        return []
    indent = lead.group("indent")
    item = re.compile(r"^{}-\s".format(re.escape(indent)))
    blocks = []
    current = []
    for line in body.splitlines():
        if item.match(line):
            if current:
                blocks.append("\n".join(current))
            # The `- ` item marker is replaced by the two spaces it occupies, so
            # the rule's FIRST field lines up with the rest and `_rbac_rule_list`
            # can see it. Without this the first field of every rule was
            # invisible to every check built on this helper: a rule written
            # `- resources: [secrets]` with `verbs:` below it evaded the
            # flux-system Secret-write check entirely, and the shared-role
            # apiGroups check below would have been decorative for the same
            # reason. Column alignment is preserved exactly — two characters for
            # two characters — so the indentation this helper derives is
            # unchanged.
            current = [item.sub(indent + "  ", line, count=1)]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def _rbac_rule_list(block, field):
    """Return one RBAC rule field's members, in either YAML sequence style.

    The reviewed manifests write short lists inline (``verbs: [get, list]``) and
    long ones as indented sequences, and the generated export writes everything
    as indented sequences. A check that understood only one of the two would be
    decorative on half the files it runs over.
    """

    inline = re.search(
        r"(?m)^\s*{}:\s*\[([^\]]*)\]\s*$".format(re.escape(field)), block
    )
    if inline is not None:
        return [item.strip().strip("'\"") for item in inline.group(1).split(",") if item.strip()]
    nested = re.search(
        r"(?ms)^(?P<indent>\s*){}:\s*$\n(?P<body>(?:(?P=indent)\s*-\s.*\n?)*)".format(
            re.escape(field)
        ),
        block,
    )
    if nested is None:
        return []
    return [
        item.strip().strip("'\"")
        for item in re.findall(r"(?m)^\s*-\s+(\S+)\s*$", nested.group("body"))
    ]


def _rbac_rule_fields(block):
    """Return every mapping field authored in one RBAC rule block.

    Kubernetes ignores neither ``resourceNames`` nor future rule fields.  An
    exact cache/read-back grant therefore has to pin the complete mapping
    shape, not merely the three list values the controller needs.  Sequence
    members begin with ``-`` and cannot be mistaken for mapping fields here.
    """

    return {
        match.group("field")
        for match in re.finditer(
            r"(?m)^\s*(?P<quote>['\"]?)(?P<field>[A-Za-z][A-Za-z0-9]*)"
            r"(?P=quote):(?:\s|$)",
            block,
        )
    }


def flux_rbac_contract_errors(root):
    """Require the narrowed Flux controller authorization (AUDIT S12).

    The generated export binds ``cluster-admin`` to the kustomize- and
    helm-controller accounts and shares a wildcard ClusterRole across seven
    named subjects. This function pins the three properties that replace it:
    the narrowing patches exist AND are applied by the install root, the
    authorization this repository authors contains no wildcard and no
    cluster-admin reference, and the controller-identity Roles that carry the
    replacement authority are present with the shape that keeps them narrow.
    """

    errors = []
    controllers = root / "kubernetes/flux-system/controllers"
    index_path = controllers / "kustomization.yaml"
    index_text = read(index_path) if index_path.is_file() else ""
    if not index_text:
        errors.append("Flux controller install root is missing")

    for name, (kind, target) in sorted(FLUX_RBAC_PATCHES.items()):
        patch_path = controllers / "patches" / name
        if not patch_path.is_file():
            errors.append("Flux RBAC narrowing patch is missing: " + name)
            continue
        patch_text = read(patch_path)
        if not re.search(r"(?m)^kind:\s*{}\s*$".format(kind), patch_text):
            errors.append("Flux RBAC patch {} must target kind {}".format(name, kind))
        if not re.search(r"(?m)^\s*name:\s*{}\s*$".format(re.escape(target)), patch_text):
            errors.append("Flux RBAC patch {} must name {}".format(name, target))
        # Anchored to the `path:` entry that actually wires the patch in, not to
        # the filename appearing anywhere in the file. A substring test was
        # satisfied by any COMMENT naming the patch, so a root that mentioned a
        # narrowing patch while no longer applying it read as compliant.
        if not re.search(
            r"(?m)^\s*path:\s*patches/{}\s*$".format(re.escape(name)), index_text
        ):
            errors.append("Flux controller install root does not apply patches/" + name)

    # The cluster-admin binding is deleted rather than repointed: `roleRef` is
    # immutable, so a repoint would be unappliable on the live cluster that
    # already carries the broad binding.
    deletion = controllers / "patches/cluster-reconciler.yaml"
    if deletion.is_file() and not re.search(r"(?m)^\$patch:\s*delete\s*$", read(deletion)):
        errors.append("cluster-admin binding patch must delete the binding, not repoint it")

    # Feature gates are an exact Deployment argument, not a substring. The
    # Both reconcilers' default ConfigMap/Secret metadata watches would need
    # cluster-wide Secret list/watch; disable those watches instead. No other
    # optional feature gate is enabled by this recut.
    expected_feature_gates = {
        "source-controller.yaml": (),
        "kustomize-controller.yaml": (DISABLE_CONFIG_WATCHERS_FLAG,),
        "helm-controller.yaml": (DISABLE_CONFIG_WATCHERS_FLAG,),
    }
    for patch_name, expected in expected_feature_gates.items():
        path = controllers / "patches" / patch_name
        if not path.is_file():
            continue
        values = tuple(
            value
            for value in re.findall(
                r"(?m)^-\s*op:\s*add\s*$\n"
                r"^\s*path:\s*/spec/template/spec/containers/0/args/-\s*$\n"
                r"^\s*value:\s*(--\S+)\s*$",
                read(path),
            )
            if value.startswith("--feature-gates=")
        )
        if values != expected:
            errors.append(
                "{} feature-gate args must be exactly: {}".format(
                    patch_name, ", ".join(expected) if expected else "none"
                )
            )

    # The subject list, pinned exactly. A regenerated export reintroduces four
    # subjects for controllers this install does not run.
    binding_patch = controllers / "patches/crd-controller-binding.yaml"
    if binding_patch.is_file():
        subjects = _service_account_subjects(read(binding_patch))
        if tuple(sorted(subjects)) != tuple(sorted(FLUX_CONTROLLER_ACCOUNTS)):
            errors.append(
                "crd-controller subjects must be exactly the installed controllers: "
                + ", ".join(sorted(FLUX_CONTROLLER_ACCOUNTS))
            )

    # The shared role names no Flux API group. It is the only ClusterRole bound
    # to all three controllers, so a rule here reaches every controller: the
    # split is only real while this file carries none.
    role_patch = controllers / "patches/crd-controller-role.yaml"
    if role_patch.is_file():
        shared_text = read(role_patch)
        for block in _rbac_rule_blocks(shared_text):
            if "secrets" in _rbac_rule_list(block, "resources"):
                errors.append(
                    "the shared crd-controller ClusterRole must not grant Secret access"
                )
            for group in _rbac_rule_list(block, "apiGroups"):
                if group in FLUX_EXECUTION_API_GROUPS:
                    errors.append(
                        "the shared crd-controller ClusterRole is bound to all three "
                        "controllers and must not name " + group
                    )

    for relative in FLUX_AUTHORED_RBAC_FILES:
        path = root / relative
        if not path.is_file():
            errors.append("authored Flux RBAC file is missing: " + relative)
            continue
        text = read(path)
        if re.search(r"(?m)^\s*(?:-\s+)?['\"]?\*['\"]?\s*$", text) or re.search(
            r"(?m)^\s*(?:apiGroups|resources|verbs):\s*\[[^\]]*\*", text
        ):
            errors.append("wildcard RBAC rule in " + relative)
        # Prose may name the role it removes; a manifest field may not name it
        # at all.
        if re.search(r"(?m)^\s*name:\s*cluster-admin\s*$", text):
            errors.append("cluster-admin binding in " + relative)
        if re.search(r"(?m)^\s*-\s*serviceaccounts/token\s*$", text):
            errors.append("serviceaccounts/token creation must not be granted: " + relative)

    access_path = root / "kubernetes/flux-system/access.yaml"
    if not access_path.is_file():
        return errors
    documents = _yaml_documents(read(access_path))
    expected_identities = {
        ("ServiceAccount", "flux-system", "default"),
        ("ServiceAccount", "cloudflare-public", "default"),
        ("ServiceAccount", "naranjo-online", "default"),
        ("ServiceAccount", "lidersea-com", "default"),
        ("Role", "flux-system", "flux-controller-runtime"),
        ("RoleBinding", "flux-system", "flux-controller-runtime"),
        ("Role", "flux-system", "flux-controller-impersonation"),
        ("RoleBinding", "flux-system", "flux-controller-impersonation"),
    }
    for site in ("naranjo-online", "lidersea-com"):
        expected_identities.update({
            ("Role", site, "flux-controller-impersonation"),
            ("RoleBinding", site, "flux-controller-impersonation"),
            ("ServiceAccount", "flux-system", site + "-reconciler"),
            ("Role", site, "flux-release-reconciler"),
            ("RoleBinding", site, site + "-reconciler"),
            ("ServiceAccount", site, "helm-reconciler"),
            ("Role", site, "helm-reconciler"),
            ("RoleBinding", site, "helm-reconciler"),
        })

    def expected_rule(groups, resources, verbs, names=()):
        fields = {"apiGroups", "resources", "verbs"}
        if names:
            fields.add("resourceNames")
        return (
            tuple(sorted(groups)), tuple(sorted(resources)), tuple(sorted(names)),
            tuple(sorted(verbs)), tuple(sorted(fields)),
        )

    def actual_rule(block):
        return (
            tuple(sorted(_rbac_rule_list(block, "apiGroups"))),
            tuple(sorted(_rbac_rule_list(block, "resources"))),
            tuple(sorted(_rbac_rule_list(block, "resourceNames"))),
            tuple(sorted(_rbac_rule_list(block, "verbs"))),
            tuple(sorted(_rbac_rule_fields(block))),
        )

    full = ("get", "list", "watch", "create", "update", "patch", "delete")
    readback = ("get", "list", "watch")
    expected_role_rules = {
        ("flux-system", "flux-controller-runtime"): (
            expected_rule(("coordination.k8s.io",), ("leases",), full),
            expected_rule(("",), ("configmaps",), full),
            expected_rule(("",), ("configmaps/status",), ("get", "update", "patch")),
        ),
        ("flux-system", "flux-controller-impersonation"): (
            expected_rule(
                ("",), ("serviceaccounts",), ("impersonate",),
                ("naranjo-online-reconciler", "lidersea-com-reconciler"),
            ),
        ),
    }
    for site in ("naranjo-online", "lidersea-com"):
        expected_role_rules[(site, "flux-controller-impersonation")] = (
            expected_rule(
                ("",), ("serviceaccounts",), ("impersonate",),
                ("helm-reconciler",),
            ),
        )
        expected_role_rules[(site, "flux-release-reconciler")] = (
            expected_rule(("source.toolkit.fluxcd.io",), ("ocirepositories",), ("list",)),
            expected_rule(("source.toolkit.fluxcd.io",), ("ocirepositories",), ("create",)),
            expected_rule(
                ("source.toolkit.fluxcd.io",), ("ocirepositories",),
                ("get", "update", "patch"), (site + "-chart",),
            ),
            expected_rule(("helm.toolkit.fluxcd.io",), ("helmreleases",), ("list",)),
            expected_rule(("helm.toolkit.fluxcd.io",), ("helmreleases",), ("create",)),
            expected_rule(
                ("helm.toolkit.fluxcd.io",), ("helmreleases",),
                ("get", "update", "patch"), (site,),
            ),
            expected_rule(("networking.k8s.io",), ("networkpolicies",), ("list",)),
            expected_rule(("networking.k8s.io",), ("networkpolicies",), ("create",)),
            expected_rule(
                ("networking.k8s.io",), ("networkpolicies",),
                ("get", "update", "patch"), ("default-deny",),
            ),
        )
        helm_rules = [
            expected_rule(
                ("",),
                ("configmaps", "secrets", "services", "serviceaccounts"),
                full,
            ),
            expected_rule(("",), ("pods",), readback),
            expected_rule(("apps",), ("deployments",), full),
            expected_rule(("apps",), ("replicasets",), readback),
            expected_rule(("networking.k8s.io",), ("networkpolicies",), full),
        ]
        if site == "naranjo-online":
            helm_rules.append(expected_rule(("",), ("persistentvolumeclaims",), full))
        expected_role_rules[(site, "helm-reconciler")] = tuple(helm_rules)

    expected_bindings = {
        ("flux-system", "flux-controller-runtime"): (
            "flux-controller-runtime",
            tuple(("flux-system", name) for name in FLUX_CONTROLLER_ACCOUNTS),
        ),
        ("flux-system", "flux-controller-impersonation"): (
            "flux-controller-impersonation", (("flux-system", "kustomize-controller"),),
        ),
    }
    for site in ("naranjo-online", "lidersea-com"):
        expected_bindings[(site, "flux-controller-impersonation")] = (
            "flux-controller-impersonation", (("flux-system", "helm-controller"),),
        )
        expected_bindings[(site, site + "-reconciler")] = (
            "flux-release-reconciler", (("flux-system", site + "-reconciler"),),
        )
        expected_bindings[(site, "helm-reconciler")] = (
            "helm-reconciler", ((site, "helm-reconciler"),),
        )

    seen_identities = []
    seen_roles = set()
    exact_naranjo_pvc_rules = 0
    for document in documents:
        kind_match = re.search(r"(?m)^kind:\s*(ServiceAccount|Role|RoleBinding)\s*$", document)
        name_match = re.search(r"(?m)^\s*name:\s*(\S+)\s*$", document)
        namespace_match = re.search(r"(?m)^\s*namespace:\s*(\S+)\s*$", document)
        if kind_match is None or name_match is None or namespace_match is None:
            errors.append("access.yaml contains an unclassifiable authorization object")
            continue
        kind = kind_match.group(1)
        name, namespace = name_match.group(1), namespace_match.group(1)
        seen_identities.append((kind, namespace, name))
        if kind == "ServiceAccount":
            if len(re.findall(r"(?m)^automountServiceAccountToken:\s*false\s*$", document)) != 1:
                errors.append(
                    "access.yaml ServiceAccount must disable token automount: {}/{}".format(
                        namespace, name
                    )
                )
            continue
        if kind == "RoleBinding":
            role_ref = re.search(
                r"(?m)^roleRef:\s*$\n"
                r"\s*apiGroup:\s*rbac[.]authorization[.]k8s[.]io\s*$\n"
                r"\s*kind:\s*Role\s*$\n"
                r"\s*name:\s*(\S+)\s*$",
                document,
            )
            # The scan yields (name, namespace); normalize to (namespace, name).
            subjects = tuple(sorted(
                (subject_namespace, subject_name)
                for subject_name, subject_namespace in _service_account_subjects(
                    document, with_namespace=True
                )
            ))
            expected = expected_bindings.get((namespace, name))
            if expected is None or role_ref is None or (
                role_ref.group(1), subjects
            ) != (expected[0], tuple(sorted(expected[1]))):
                errors.append(
                    "access.yaml RoleBinding is not the exact direct-site binding: {}/{}".format(
                        namespace, name
                    )
                )
            continue
        seen_roles.add((name, namespace))
        blocks = _rbac_rule_blocks(document)
        expected = expected_role_rules.get((namespace, name))
        if expected is None or tuple(sorted(actual_rule(block) for block in blocks)) != tuple(
            sorted(expected)
        ):
            errors.append(
                "access.yaml Role rules are not the exact direct-site grant: {}/{}".format(
                    namespace, name
                )
            )
        for block in blocks:
            resources = tuple(_rbac_rule_list(block, "resources"))
            if "persistentvolumeclaims" in resources:
                is_exact_naranjo_rule = (
                    name == "helm-reconciler"
                    and namespace == "naranjo-online"
                    and tuple(_rbac_rule_list(block, "apiGroups")) == ("",)
                    and resources == ("persistentvolumeclaims",)
                    and tuple(_rbac_rule_list(block, "verbs"))
                    == RBAC_READ_VERBS + ("create", "update", "patch", "delete")
                    and _rbac_rule_fields(block)
                    == {"apiGroups", "resources", "verbs"}
                )
                if is_exact_naranjo_rule:
                    exact_naranjo_pvc_rules += 1
                else:
                    errors.append(
                        "PVC lifecycle must be only the exact namespaced "
                        "naranjo-online/helm-reconciler rule"
                    )
            # Impersonation without `resourceNames` is impersonation of every
            # account in the namespace, which re-opens the escalation path the
            # deleted binding used to hold open.
            if "impersonate" in block and "resourceNames" not in block:
                errors.append(
                    "unrestricted impersonate grant in access.yaml Role {}/{}".format(
                        namespace, name
                    )
                )
            # A controller that can write Secrets in flux-system can rewrite
            # the SOPS key it decrypts with.
            if namespace == "flux-system" and "secrets" in _rbac_rule_list(block, "resources"):
                granted = _rbac_rule_list(block, "verbs")
                for verb in RBAC_WRITE_VERBS:
                    if verb in granted:
                        errors.append(
                            "flux-system Secret grant must be read-only: {}/{} grants {}".format(
                                namespace, name, verb
                            )
                        )
        if name == "helm-reconciler" and namespace in {
            "naranjo-online", "lidersea-com",
        }:
            exact_rule_fields = ("apiGroups", "resources", "verbs")
            expected_readback = {
                (("",), ("pods",), RBAC_READ_VERBS, exact_rule_fields),
                (("apps",), ("replicasets",), RBAC_READ_VERBS, exact_rule_fields),
            }
            actual_readback = {
                (
                    tuple(_rbac_rule_list(block, "apiGroups")),
                    tuple(_rbac_rule_list(block, "resources")),
                    tuple(_rbac_rule_list(block, "verbs")),
                    tuple(sorted(_rbac_rule_fields(block))),
                )
                for block in blocks
                if set(_rbac_rule_list(block, "resources")) & {"pods", "replicasets"}
            }
            if actual_readback != expected_readback:
                errors.append(
                    "tenant helm-reconciler {}/{} must grant only exact "
                    "pods and replicasets get/list/watch read-back rules".format(
                        namespace, name
                    )
                )
    if exact_naranjo_pvc_rules != 1:
        errors.append(
            "naranjo-online/helm-reconciler must carry exactly one exact PVC "
            "lifecycle rule"
        )
    if len(seen_identities) != len(expected_identities) or set(seen_identities) != expected_identities:
        errors.append(
            "access.yaml inventory must be exactly 8 ServiceAccounts, 8 Roles, "
            "and 8 RoleBindings for the direct-site topology"
        )
    for name, namespaces in sorted(FLUX_CONTROLLER_ROLE_NAMESPACES.items()):
        for namespace in namespaces:
            if (name, namespace) not in seen_roles:
                errors.append(
                    "controller-identity Role missing from access.yaml: {}/{}".format(
                        namespace, name
                    )
                )

    # The per-controller split's own objects. The subject list is checked as
    # well as the role's presence, because a role bound to a second controller
    # is the shared role again under a different name — and that is the exact
    # failure this split exists to remove.
    #
    # These six live in the INSTALL ROOT, not in access.yaml, and that placement
    # is itself the check below it: the same transaction that strips the Flux
    # API groups off the shared ClusterRole has to create the replacements, or a
    # fresh install brings up three controllers that cannot watch their own
    # custom resources and can never reach readiness.
    per_controller_path = root / FLUX_PER_CONTROLLER_RBAC_RELATIVE
    if not per_controller_path.is_file():
        errors.append("per-controller RBAC missing: " + FLUX_PER_CONTROLLER_RBAC_RELATIVE)
        return errors
    install_root = root / "kubernetes/flux-system/controllers/kustomization.yaml"
    if install_root.is_file():
        resource = "- " + Path(FLUX_PER_CONTROLLER_RBAC_RELATIVE).name
        if not re.search(r"(?m)^\s*{}\s*$".format(re.escape(resource)), read(install_root)):
            errors.append(
                "per-controller RBAC must be a resource of the install root: "
                "controllers/kustomization.yaml does not list {}".format(
                    Path(FLUX_PER_CONTROLLER_RBAC_RELATIVE).name
                )
            )
    seen_cluster_roles = {}
    seen_cluster_bindings = {}
    for document in _yaml_documents(read(per_controller_path)):
        kind_match = re.search(r"(?m)^kind:\s*(ClusterRole|ClusterRoleBinding)\s*$", document)
        name_match = re.search(r"(?m)^  name:\s*(\S+)\s*$", document)
        if kind_match is None or name_match is None:
            continue
        if kind_match.group(1) == "ClusterRole":
            seen_cluster_roles[name_match.group(1)] = document
            continue
        # Issue #98 needs only this authored four-line roleRef shape. Keep the
        # match bounded rather than importing issue #166's generalized parser
        # and scan-cost work into the RBAC split.
        role_ref_match = re.search(
            r"(?m)^roleRef:\s*$\n"
            r"  apiGroup:\s*rbac\.authorization\.k8s\.io\s*$\n"
            r"  kind:\s*ClusterRole\s*$\n"
            r"  name:\s*([^\s]+)\s*$",
            document,
        )
        role_ref = role_ref_match.group(1) if role_ref_match else None
        subjects = _service_account_subjects(document)
        seen_cluster_bindings[name_match.group(1)] = (
            role_ref,
            tuple(sorted(subjects)),
        )
    for name, owner in sorted(FLUX_PER_CONTROLLER_CLUSTER_ROLES.items()):
        if name not in seen_cluster_roles:
            errors.append(
                "per-controller ClusterRole missing from the install root: " + name
            )
        if name not in seen_cluster_bindings:
            errors.append(
                "per-controller ClusterRoleBinding missing from the install root: " + name
            )
            continue
        role_ref, subjects = seen_cluster_bindings[name]
        if role_ref != name:
            errors.append(
                "per-controller ClusterRoleBinding {} must bind ClusterRole {}".format(
                    name, name
                )
            )
        if subjects != (owner,):
            errors.append(
                "per-controller ClusterRoleBinding {} must name only {}".format(name, owner)
            )
    for name, document in sorted(seen_cluster_roles.items()):
        secondary_source_resources = {
            "crd-controller-kustomize-flux-system": (
                "buckets", "gitrepositories", "ocirepositories",
            ),
            "crd-controller-helm-flux-system": ("ocirepositories",),
        }
        if name in secondary_source_resources:
            blocks = _rbac_rule_blocks(document)
            source_blocks = [
                block for block in blocks
                if tuple(_rbac_rule_list(block, "apiGroups"))
                == ("source.toolkit.fluxcd.io",)
            ]
            read_blocks = [
                block for block in source_blocks
                if tuple(_rbac_rule_list(block, "verbs")) == RBAC_READ_VERBS
            ]
            expected_resources = secondary_source_resources[name]
            exact = [
                block for block in read_blocks
                if tuple(_rbac_rule_list(block, "resources")) == expected_resources
                and _rbac_rule_fields(block) == {"apiGroups", "resources", "verbs"}
            ]
            if len(read_blocks) != 1 or len(exact) != 1:
                errors.append(
                    "{} must have exactly one read-only secondary source rule for {}".format(
                        name, ", ".join(expected_resources)
                    )
                )
            forbidden_secondary = {
                "buckets", "gitrepositories", "ocirepositories", "externalartifacts"
            }
            for block in source_blocks:
                resources = set(_rbac_rule_list(block, "resources"))
                if resources & forbidden_secondary and block not in exact:
                    errors.append(
                        "{} secondary source authority must not add kinds, fields, "
                        "or write verbs".format(name)
                    )
        secret_blocks = [
            block for block in _rbac_rule_blocks(document)
            if "secrets" in _rbac_rule_list(block, "resources")
        ]
        if secret_blocks:
            errors.append(
                "per-controller ClusterRole must not grant cluster-wide Secret access: "
                + name
            )
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
                # This one executable pre-controller proof must authenticate
                # as the exact source-controller identity whose API path it
                # tests. The exception is identity- and purpose-bound here;
                # flux_egress_contract_errors below independently pins its
                # separate root, image, labels, ServiceAccount, command, and
                # restricted security context. Every other authored token mount
                # remains forbidden.
                if label == "ServiceAccount token mount" and (
                    rel == "kubernetes/flux-system/canary/pod.yaml"
                    and text.count("automountServiceAccountToken: true") == 1
                    and "kind: Pod" in text
                    and "name: " + FLUX_API_CANARY_NAME in text
                    and "namespace: flux-system" in text
                    and "serviceAccountName: source-controller" in text
                    and "- --raw=/api" in text
                ):
                    continue
                errors.append("{} in {}".format(label, rel))
        # The generated Flux export is excluded from this file set, so this is a
        # ban on every hand-written manifest: nothing this repository authors
        # may bind the built-in cluster-admin role to anything.
        if re.search(r"(?m)^\s*name:\s*cluster-admin\s*$", text):
            errors.append("cluster-admin binding in " + rel)
        for match in re.finditer(r"(?m)^[ \t]*image:[ \t]*([^\s#]+)", text):
            image = match.group(1).strip("'\"")
            if not DIGEST_IMAGE.match(image):
                errors.append("mutable or invalid image reference in {}: {}".format(rel, image))
    errors.extend(flux_components_errors(root))
    flux = root / "kubernetes" / "flux-system"
    if flux.exists():
        required_fragments = {
            "flux-system/controllers/patches/source-controller.yaml": [
                "runAsNonRoot", "RuntimeDefault",
                "requests/ephemeral-storage", "limits/ephemeral-storage", "sizeLimit",
            ],
            "flux-system/controllers/patches/kustomize-controller.yaml": [
                "--no-cross-namespace-refs=true", "--no-remote-bases=true",
                "--default-service-account=default",
                DISABLE_CONFIG_WATCHERS_FLAG,
                "runAsNonRoot", "RuntimeDefault",
            ],
            "flux-system/controllers/patches/helm-controller.yaml": [
                "--no-cross-namespace-refs=true", "--default-service-account=default",
                DISABLE_CONFIG_WATCHERS_FLAG,
                "runAsNonRoot", "RuntimeDefault",
            ],
            "flux-system/controllers/patches/allow-egress.yaml": [
                "- op: remove", "path: /spec/egress",
            ],
            "flux-system/access.yaml": [
                "namespace: cloudflare-public", "namespace: naranjo-online",
                "namespace: lidersea-com",
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
        per_controller = root / FLUX_PER_CONTROLLER_RBAC_RELATIVE
        if per_controller.is_file():
            errors.extend(
                flux_access_contract_errors(
                    read(per_controller),
                    FLUX_PER_CONTROLLER_CONTRACT_SHA256,
                    "Flux per-controller authorization",
                )
            )
        errors.extend(site_default_deny_contract_errors(root))
        # The per-site ingress policies (ingress-to-<site>) ship inside
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
        errors.extend(flux_egress_contract_errors(root))
        errors.extend(flux_install_ceremony_errors(root))
        errors.extend(flux_rbac_contract_errors(root))
    errors.extend(signed_chart_source_errors(root))
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


def chart_source_contract_errors(root):
    """Bind each site's published chart source to its closed identity tuple.

    The OCIRepository body must equal the exact reviewed contract: immutable
    manifest digest, audit-only release annotation, registry path, layer media
    type, and this site's keyless publisher subject and issuer. The site
    publisher's own release gate still governs what it may publish; Flux does
    not select a mutable SemVer range here.
    """

    errors = []
    for slug in sorted(CHART_REPOSITORIES):
        source = root / "kubernetes" / "websites" / slug / "source.yaml"
        if source.is_symlink() or not source.is_file():
            errors.append("{} chart source is missing or symbolic".format(slug))
            continue
        try:
            text = read(source)
        except (OSError, UnicodeError):
            errors.append("{} chart source is unavailable".format(slug))
            continue
        if chart_source_errors(text, slug):
            errors.append("{} chart source is non-canonical".format(slug))
    return errors


def signed_chart_source_errors(root):
    """Validate exact Flux source, sync, and per-site chart identity contracts."""

    errors = []
    authoritative_files = (
        (
            "kubernetes/flux-system/kustomization.yaml",
            flux_system_kustomization_errors,
            "Flux bootstrap Kustomization",
        ),
        (
            "kubernetes/flux-system/gotk-sync.yaml.in",
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
    errors.extend(chart_source_contract_errors(root))
    return errors


def site_release_values_errors(domain, release_state):
    """Require the sole platform value allowed for a site chart."""

    if release_state.values == {("deploymentReady",): "true"}:
        return []
    return [
        "{} HelmRelease values must contain exactly deploymentReady=true".format(domain)
    ]


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
    evidence_path = root / REVIEWED_SITE_CAPACITY_EVIDENCE
    try:
        expected_evidence = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    except OSError:
        expected_evidence = None
        errors.append("reviewed website capacity evidence document is unavailable")
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
        elif expected_evidence is not None and evidence != expected_evidence:
            errors.append(
                "reviewed website capacity evidence hash does not match document: "
                + namespace
            )
        hard = {
            path[-1]: _plain_yaml_scalar(value)
            for path, value in quota.items()
            if len(path) == 3 and path[:2] == ("spec", "hard")
        }
        if set(hard) != set(REVIEWED_SITE_CAPACITY_HARD):
            errors.append("reviewed website capacity limits are incomplete: " + namespace)
        elif hard != REVIEWED_SITE_CAPACITY_HARD:
            errors.append(
                "reviewed website capacity limits do not match owner decision: "
                + namespace
            )

    return errors


def check_release(root):
    errors = []
    versions = read(root / "versions.env")
    if re.search(r"(?m)^[A-Z0-9_]+=UNRESOLVED$", versions):
        errors.append("versions.env still contains UNRESOLVED pins")
    required_generated = [
        "kubernetes/flux-system/controllers/gotk-components.yaml",
        "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml",
    ] + [path.as_posix() for path in sorted(CLOUDFLARE_LOCK_FILES)]
    for name in required_generated:
        if not (root / name).is_file():
            errors.append("required reviewed/generated file missing: " + name)

    # The committed API-server egress allow points at RFC 5737 documentation
    # space until an operator substitutes the real endpoint from private
    # custody at apply time. A release claim while that sentinel is still the
    # committed desired state would claim a reachable control plane that the
    # repository has never described.
    flux_egress = root / "kubernetes/flux-system/egress/network-policies.yaml"
    if not flux_egress.is_file():
        errors.append("required reviewed file missing: " + flux_egress.name)
    elif FLUX_CONTROL_PLANE_SENTINEL in read(flux_egress):
        errors.append(
            "flux-system API-server egress still carries the unresolved control-plane sentinel"
        )

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
        errors.extend(site_release_values_errors(domain, release_state))
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
        # Every website's connector must carry its own resolved revision; an
        # unresolved revision on either one keeps the release unresolved.
        if any(
            public_release.values.get(("connectors", site, "tokenRevision"))
            in {None, "not-configured", "UNRESOLVED"}
            for site in PUBLIC_CONNECTOR_SITES
        ):
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
    errors.extend(signed_chart_source_errors(root))
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
        parent_relative = contract["parent"]
        if parent_relative is not None and (root / str(parent_relative)).is_file():
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
    return False


def _allowed_transition_release_errors(plan):
    """Return only full-release failures made inert by the classified phase."""

    allowed = set()
    phases = {
        "naranjo-online": plan.naranjo_online,
        "lidersea-com": plan.lidersea_com,
    }
    for _, slug, _ in SITE_RELEASE_CONTRACTS:
        phase = phases[slug]
        if phase == "active":
            continue
        allowed.update({
            "HelmRelease remains suspended: " + slug,
            "parent Kustomization remains suspended: " + slug,
        })
    # The flux-system API-server allow points at RFC 5737 documentation space
    # until an operator substitutes the real endpoint from private custody. The
    # SAME validator mandates that sentinel (`check_kubernetes` fails when it is
    # absent), so its presence cannot also disqualify a transition: one check
    # requiring the exact bytes another refuses is a contract no tree satisfies.
    # It is inert here for the same reason the pre-ceremony SOPS sentinels below
    # are: nothing is being released, and the operator substitution happens at
    # apply time, not in Git. A genuine release claim is unaffected — `mode ==
    # "release"` returns `check_release` UNFILTERED, so a release while the
    # sentinel is still committed still fails exactly as before.
    allowed.add(
        "flux-system API-server egress still carries the unresolved control-plane sentinel"
    )

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
    if not plan.any_website_active and error.startswith("reviewed website capacity "):
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
    "dependabot": check_dependabot,
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
