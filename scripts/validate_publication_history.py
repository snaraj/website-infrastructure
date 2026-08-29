#!/usr/bin/env python3
"""Reject unsafe content in every commit crossing a publication boundary.

The working-tree repository validator protects the candidate snapshot.  This
validator separately walks every immutable tree in ``baseline..candidate`` so
a secret, private identifier, forbidden path, link, or opaque artifact cannot
be added and deleted in an intermediate commit.  Diagnostics intentionally
contain only fixed labels, commit object IDs, and hashes of paths; content,
paths, author fields, and commit messages are never echoed.

The default interface requires ``baseline`` to be an ancestor of ``candidate``
for a protected fast-forward push.  ``--pull-request`` accepts a related but
divergent, server-authenticated PR base and scans Git's exact ``base..head`` set.
"""

import base64
import binascii
import fnmatch
import hashlib
import ipaddress
import math
import os
import re
import subprocess
import sys
from pathlib import Path


MAX_OUTGOING_COMMITS = 256
MAX_COMMIT_OBJECT_BYTES = 256 * 1024
MAX_TREE_INVENTORY_BYTES = 2 * 1024 * 1024
MAX_ALL_TREE_INVENTORIES_BYTES = 32 * 1024 * 1024
MAX_TREE_ENTRIES = 20_000
MAX_ALL_TREE_ENTRIES = 200_000
MAX_BLOB_BYTES = 2 * 1024 * 1024
MAX_TREE_BYTES = 16 * 1024 * 1024
MAX_UNIQUE_BLOB_BYTES = 64 * 1024 * 1024
MAX_FINDINGS_REPORTED = 64
MAX_GIT_OUTPUT_SECONDS = 30

FORBIDDEN_COMPONENTS = {
    ".artifacts", ".cache", ".git", ".idea", ".ssh", ".terraform",
    ".vscode", "__pycache__", "coverage", "local-evidence", "node_modules",
    "results",
}
FORBIDDEN_FILE_PATTERNS = {
    ".ds_store", ".env", ".env.*", ".gitleaksignore", ".terraformrc",
    "*.7z", "*.age", "*.agekey", "*.aes", "*.asc", "*.auto.tfvars",
    "*.auto.tfvars.json", "*.backend.hcl", "*.bak", "*.bz2", "*.cab",
    "*.bin", "*.blob", "*.ciphertext", "*.dec.*", "*.enc", "*.encrypted",
    "*.gpg", "*.gz",
    "*.key", "*.kubeconfig", "*.lz", "*.lz4", "*.p12", "*.pem", "*.pfx",
    "*.pgp", "*.plaintext.*", "*.pyc", "*.pyd", "*.pyo", "*.rar",
    "*.sarif", "*.sbom.json", "*.sops.env", "*.sops.ini", "*.sops.json",
    "*.swo", "*.swp", "*.tar", "*.tar.*", "*.tfbackend", "*.tfplan",
    "*.tfplan.json", "*.tgz", "*.tmp", "*.token", "*.txz", "*.xz",
    "*.zip", "*.zst", "*~",
    "cloudflared-token*", "crash.*.log", "crash.log", "id_ed25519*",
    "id_rsa*", "keys.txt", "known_hosts*", "kubeconfig*",
    "api-encryption-config.yaml", "encryption-config.yaml.local",
    "powershell_transcript.*.txt", "*.transcript.txt", "thumbs.db", "terraform.rc",
    "terraform.tfvars", "terraform.tfvars.json",
}
FORBIDDEN_EXACT_PATHS = {
    "bootstrap/pi/cni-manifest.local.yaml",
    "bootstrap/pi/decisions.env.local",
    "bootstrap/pi/encryption-config.yaml.local",
    "bootstrap/pi/images.lock.local",
    "bootstrap/pi/kubeadm-config.yaml.local",
    "bootstrap/pi/protected-legacy-runtime-evidence.local",
    "bootstrap/pi/protected-services.env.local",
}
# Historical law: these paths existed in already-published commits before the
# website extraction, so full-history validation must keep accepting them
# there even though no websites/ tree exists at HEAD anymore.
ALLOWED_DIST_PATHS = {
    "websites/lidersea.com/internal/web/dist/.gitkeep",
    "websites/naranjo.online/internal/web/dist/.gitkeep",
}
APPROVED_SOPS_PATH = (
    "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml"
)
# This one inert, non-rendered manifest documents only the Secret shape that a
# later SOPS ceremony must produce.  Pinning both path and bytes avoids a broad
# examples/placeholder exemption: a copy, edit, alternate token, or newly added
# plaintext Secret remains a publication failure.
STRUCTURAL_SECRET_EXAMPLE_PATH = (
    "kubernetes/platform/cloudflare-public/examples/"
    "tunnel-token.invalid-example.yaml"
)
STRUCTURAL_SECRET_EXAMPLE_SHA256 = (
    "9338ed72189de69f2949db74f34cacd5147dc8a60487826933adb1ac8e3366f1"
)

# The KEYS of this table are published diagnostic labels, not secrets. They are
# the entire description of a finding that this validator ever emits: Findings
# .add below builds every stderr line from one of these keys, a validated
# 40-hex commit id, and a truncated SHA-256 of the path — never from the blob,
# the path, or anything matched. The VALUES are detection patterns for content
# that must never be published. Naming the table for the material it hunts
# rather than for the labels it hands out misdescribed the only strings that
# leave this process, and read as though matched content were being retained.
PROHIBITED_CONTENT_PATTERNS = {
    "age private identity": re.compile(r"AGE-SECRET-KEY-(?:PQ-)?1[A-Z0-9]+"),
    "private key block": re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
    ),
    "GitHub classic token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "GitHub fine-grained token": re.compile(
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    ),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "prefixed Cloudflare API credential": re.compile(
        r"\b(?:cfk|cfut|cfat)_[A-Za-z0-9]{40}[0-9A-Fa-f]{8}\b"
    ),
    "literal Cloudflare API token": re.compile(
        r"(?i)\bcloudflare_api_token\b[\"']?\s*[:=]\s*"
        r"[\"']?[A-Za-z0-9_+/-]{20,}[\"']?"
    ),
    "Cloudflare bearer credential": re.compile(
        r"(?i)\bauthorization\b[\"']?\s*:\s*[\"']?"
        r"bearer\s+[A-Za-z0-9._~+/-]{20,}"
    ),
    "Cloudflare Tunnel runtime token": re.compile(
        r"(?i)\b(?:cloudflared[_ -]?)?tunnel[_ -]?token\b[\"']?\s*[:=]\s*"
        r"[\"']?(?:eyJ[A-Za-z0-9+/]{20,}={0,2}|"
        r"[A-Za-z0-9_+/-]{80,})[\"']?"
    ),
    "bare Cloudflare Tunnel runtime token": re.compile(
        r"eyJ[A-Za-z0-9+/]{77,4093}={0,2}"
    ),
    "local Cloudflare token receipt": re.compile(
        r"(?i)[\"']schema[\"']\s*:\s*[\"']"
        r"cloudflare-phase-token-receipt-v(?:1|2)[\"']"
    ),
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

EMAIL_ADDRESS = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
LOCAL_PROFILE = re.compile(r"(?i)[A-Z]:[\\/]+Users[\\/]+[^\\/\s]+")
WORKSPACE_PATH = re.compile(r"(?i)[A-Z]:[\\/]+dev(?:[\\/]|\b)")
OPAQUE_32_HEX = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
UUID_IDENTIFIER = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}"
    r"[0-9a-f]{12}(?![0-9a-f])"
)
IPV4_LITERAL = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
IPV6_CANDIDATE = re.compile(
    r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}"
    r"[0-9a-f]{0,4}(?![0-9a-f:])"
)
SYNTHETIC_32_HEX = {
    "1" * 32, "2" * 32, "3" * 32, "0123456789abcdef" * 2,
}
PUBLIC_NETWORK_IPV4 = {
    "0.0.0.0", "10.0.0.0", "10.42.0.0", "10.42.1.0", "10.43.0.0",
    "10.44.0.0", "10.99.0.0", "100.64.0.0", "127.0.0.0", "127.0.0.1",
    "169.254.0.0", "172.16.0.0", "192.168.0.0", "224.0.0.0",
    "240.0.0.0",
}
DOCUMENTATION_IPV4 = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
SYNTHETIC_TEST_IPV4_OCTETS = {
    (8, 8, 8, 8), (192, 168, 1, 10), (192, 168, 50, 0),
    (192, 168, 50, 1), (192, 168, 50, 10), (192, 168, 50, 11),
    (192, 168, 50, 20), (192, 168, 60, 1),
}

ARCHIVE_OR_ENCRYPTION_MAGIC = (
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"BZh",
    b"\xfd7zXZ\x00", b"7z\xbc\xaf'\x1c", b"Rar!\x1a\x07", b"(\xb5/\xfd",
    b"Salted__", b"U2FsdGVkX1", b"age-encryption.org/v1",
    b"-----BEGIN AGE ENCRYPTED FILE-----", b"-----BEGIN PGP MESSAGE-----",
)
MEDIA_SUFFIXES = {
    ".aac", ".avif", ".avi", ".bmp", ".flac", ".gif", ".heic", ".heif",
    ".ico", ".jpeg", ".jpg", ".m4a", ".mkv", ".mov", ".mp3", ".mp4",
    ".ogg", ".ogv", ".otf", ".png", ".svg", ".tif", ".tiff", ".ttf",
    ".wav", ".webm", ".webp", ".woff", ".woff2",
}
MAX_UI_ASSET_BYTES = 1 * 1024 * 1024
MAX_ASSET_TREE_BYTES = 2 * 1024 * 1024
# The one deliberate exception to the history-wide no-media law: the
# self-hosted coverage badge, admitted only in its strictest text form.
# These five constants must stay byte-identical with their copies in
# validate_repository.py (pinned by tests/security/test_approved_badge_contract.py).
APPROVED_TEXT_BADGE_PATHS = {"docs/badges/coverage.svg"}
MAX_TEXT_BADGE_BYTES = 2048
BADGE_REQUIRED_PREFIX = '<svg xmlns="http://www.w3.org/2000/svg" '
BADGE_FORBIDDEN_FRAGMENTS = (
    "base64", "data:", "script", "href", "xlink", "import", "foreignobject",
    "<image", "<use", "url(", "&#", "http", "<!", "<?",
)
BADGE_ALLOWED_ELEMENTS = {"svg", "title", "g", "rect", "text"}
TEXT_SUFFIXES = {
    ".conf", ".css", ".env", ".example", ".go", ".hcl", ".html", ".js",
    ".json", ".lock", ".md", ".mjs", ".rego", ".service", ".sh",
    ".svelte", ".tf", ".timer", ".toml", ".tpl", ".ts", ".txt",
    ".yaml", ".yml",
}


class ValidationFailure(Exception):
    """An intentionally detail-free fail-closed validation error."""


def _git_environment():
    """Drop ambient repository/config overrides from child Git processes."""

    environment = os.environ.copy()
    exact_names = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CONFIG",
        "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
        "GIT_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_WORK_TREE",
    }
    for name in list(environment):
        if name in exact_names or name.startswith("GIT_CONFIG_KEY_") or name.startswith(
            "GIT_CONFIG_VALUE_"
        ):
            environment.pop(name, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


GIT_ENVIRONMENT = _git_environment()


def _git_bytes(root, arguments, limit):
    """Read bounded Git output, suppressing attacker-controlled diagnostics."""

    try:
        process = subprocess.Popen(
            ["git", "-C", str(root), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=GIT_ENVIRONMENT,
        )
    except OSError as problem:
        raise ValidationFailure() from problem
    assert process.stdout is not None
    try:
        output = process.stdout.read(limit + 1)
        if len(output) > limit:
            process.kill()
            process.wait()
            raise ValidationFailure()
        return_code = process.wait(timeout=MAX_GIT_OUTPUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as problem:
        process.kill()
        process.wait()
        raise ValidationFailure() from problem
    finally:
        process.stdout.close()
    if return_code != 0:
        raise ValidationFailure()
    return output


def _resolve_repository():
    raw = _git_bytes(Path.cwd(), ["rev-parse", "--show-toplevel"], 4096)
    try:
        value = raw.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as problem:
        raise ValidationFailure() from problem
    root = Path(value).resolve()
    if not root.is_dir():
        raise ValidationFailure()
    return root


def _resolve_commit(root, value):
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None:
        raise ValidationFailure()
    raw = _git_bytes(root, ["rev-parse", "--verify", value + "^{commit}"], 128)
    try:
        resolved = raw.decode("ascii", "strict").strip()
    except UnicodeDecodeError as problem:
        raise ValidationFailure() from problem
    if resolved != value:
        raise ValidationFailure()
    return resolved


def _outgoing_commits(root, baseline, candidate):
    raw = _git_bytes(
        root,
        ["rev-list", "--reverse", "--topo-order", baseline + ".." + candidate],
        (MAX_OUTGOING_COMMITS + 1) * 65,
    )
    try:
        commits = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as problem:
        raise ValidationFailure() from problem
    if not commits or len(commits) > MAX_OUTGOING_COMMITS:
        raise ValidationFailure()
    if commits[-1] != candidate or len(set(commits)) != len(commits):
        raise ValidationFailure()
    if any(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", item) is None for item in commits):
        raise ValidationFailure()
    return commits


def _path_digest(raw_path):
    return hashlib.sha256(raw_path).hexdigest()[:16]


class Findings:
    """Count every issue while retaining only bounded, non-sensitive output."""

    def __init__(self):
        self.count = 0
        self.messages = []

    def add(self, label, commit, raw_path=None):
        path_identity = "" if raw_path is None else _path_digest(raw_path)
        self.count += 1
        if len(self.messages) >= MAX_FINDINGS_REPORTED:
            return
        message = "FAIL publication history: {}; commit={}".format(label, commit)
        if path_identity:
            message += "; path_sha256=" + path_identity
        self.messages.append(message)


def _commit_metadata(root, commit, findings):
    raw = _git_bytes(root, ["cat-file", "commit", commit], MAX_COMMIT_OBJECT_BYTES)
    if b"\x00" in raw or b"\n\n" not in raw:
        raise ValidationFailure()
    header, message = raw.split(b"\n\n", 1)
    authors = [line[7:] for line in header.splitlines() if line.startswith(b"author ")]
    committers = [
        line[10:] for line in header.splitlines() if line.startswith(b"committer ")
    ]
    if len(authors) != 1 or len(committers) != 1:
        raise ValidationFailure()
    # Scan the complete commit object, including optional/custom headers and
    # signed-tag material, while still requiring one canonical author and
    # committer. Tree/parent object IDs cannot satisfy the privacy patterns.
    try:
        metadata = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        findings.add("commit metadata is not UTF-8", commit)
        metadata = raw.decode("utf-8", "surrogateescape")
    for label in _text_findings(metadata, "", False):
        findings.add("commit metadata " + label, commit)
    opaque = _opaque_artifact_finding(message, "")
    if opaque is not None:
        findings.add("commit metadata " + opaque, commit)


def _path_findings(relative_path):
    findings = []
    lowered = relative_path.casefold()
    components = tuple(lowered.split("/"))
    name = components[-1]
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\\" in relative_path
        or "//" in relative_path
        or any(part in {"", ".", ".."} for part in relative_path.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in relative_path)
    ):
        findings.append("unsafe path encoding")
    if any(component in FORBIDDEN_COMPONENTS for component in components):
        findings.append("forbidden local-only path")
    if name != ".env.example" and any(
        fnmatch.fnmatchcase(name, pattern) for pattern in FORBIDDEN_FILE_PATTERNS
    ):
        findings.append("forbidden local-only path")
    if (
        lowered in FORBIDDEN_EXACT_PATHS
        or ("cloudflare" in name and "receipt" in name and name.endswith(".json"))
        or name.endswith(".tfstate")
        or ".tfstate." in name
        or name.endswith("_override.tf")
        or name.endswith("_override.tf.json")
        or name in {"override.tf", "override.tf.json"}
    ):
        findings.append("forbidden local-only path")
    if "dist" in components and lowered not in ALLOWED_DIST_PATHS:
        findings.append("forbidden generated-output path")
    if "apps" in components or "clusters" in components:
        findings.append("forbidden repository layout")
    if components[:2] == ("kubernetes", "homelab"):
        findings.append("forbidden repository layout")
    if (
        re.search(r"\.sops\.ya?ml$", lowered)
        and lowered not in {".sops.yaml", APPROVED_SOPS_PATH}
    ):
        findings.append("unapproved SOPS ciphertext path")
    return findings


def _is_test_path(relative_path):
    components = relative_path.casefold().split("/")
    return "tests" in components or components[-1].startswith("test_")


def _allowed_ipv4(value, is_test):
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
    return is_test and octets in SYNTHETIC_TEST_IPV4_OCTETS


def _has_forbidden_ipv6(text):
    documentation = ipaddress.ip_network("2001:db8::/32")
    for candidate in IPV6_CANDIDATE.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv6Address) and not (
            address.is_unspecified or address.is_loopback or address in documentation
        ):
            return True
    return False


def _text_findings(text, relative_path, is_test):
    findings = []
    inspected = text + "\n" + relative_path
    for label, pattern in PROHIBITED_CONTENT_PATTERNS.items():
        if pattern.search(inspected):
            findings.append(label)
    if _contains_plaintext_encryption_configuration(text):
        findings.append("plaintext Kubernetes API encryption configuration")
    if LOCAL_PROFILE.search(inspected) or WORKSPACE_PATH.search(inspected):
        findings.append("local workstation path")
    if any(not _allowed_ipv4(value, is_test) for value in IPV4_LITERAL.findall(inspected)):
        findings.append("non-public host IPv4 address")
    if _has_forbidden_ipv6(inspected):
        findings.append("non-public host IPv6 address")
    if any(
        value != "00000000-0000-0000-0000-000000000000"
        for value in UUID_IDENTIFIER.findall(inspected)
    ):
        findings.append("machine or tunnel UUID")
    for address in EMAIL_ADDRESS.findall(inspected):
        lowered = address.casefold()
        if not (
            lowered.endswith(".invalid")
            or lowered.endswith("@users.noreply.github.com")
        ):
            findings.append("non-private email address")
            break
    if any(value not in SYNTHETIC_32_HEX for value in OPAQUE_32_HEX.findall(inspected)):
        findings.append("non-synthetic 32-hex identifier")
    return findings


def _contains_plaintext_encryption_configuration(text):
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


def _approved_badge_violation(data):
    """True unless the bytes satisfy the strict reviewable badge contract.

    Mirrors approved_badge_errors in validate_repository.py over the same
    shared constants; the working-tree validator reports reasons while this
    history checker stays content-neutral, so it answers only yes or no.
    """

    if len(data) > MAX_TEXT_BADGE_BYTES:
        return True
    try:
        text = data.decode("ascii", "strict")
    except UnicodeError:
        return True
    if any(ord(character) < 32 and character != "\n" for character in text):
        return True
    if not text.startswith(BADGE_REQUIRED_PREFIX) or not text.endswith("</svg>\n"):
        return True
    remainder = text[len(BADGE_REQUIRED_PREFIX):].lower()
    if any(fragment in remainder for fragment in BADGE_FORBIDDEN_FRAGMENTS):
        return True
    return any(
        element.lower() not in BADGE_ALLOWED_ELEMENTS
        for element in re.findall(r"<\s*/?\s*([A-Za-z][A-Za-z0-9-]*)", text)
    )


def _media_magic_matches(data, suffix):
    if suffix == ".bmp":
        return data.startswith(b"BM")
    if suffix == ".png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if suffix in {".jpg", ".jpeg"}:
        return data.startswith(b"\xff\xd8\xff")
    if suffix == ".gif":
        return data.startswith((b"GIF87a", b"GIF89a"))
    if suffix in {".ogg", ".ogv"}:
        return data.startswith(b"OggS")
    if suffix == ".flac":
        return data.startswith(b"fLaC")
    if suffix == ".mp3":
        return data.startswith((b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"))
    if suffix in {".mkv", ".webm"}:
        return data.startswith(b"\x1aE\xdf\xa3")
    if suffix in {".ico"}:
        return data.startswith(b"\x00\x00\x01\x00")
    if suffix in {".woff", ".woff2", ".otf"}:
        return data.startswith((b"wOFF", b"wOF2", b"OTTO"))
    if suffix in {".webp", ".wav", ".avi"}:
        expected = {".webp": b"WEBP", ".wav": b"WAVE", ".avi": b"AVI "}[suffix]
        return data.startswith(b"RIFF") and data[8:12] == expected
    if suffix in {".mp4", ".m4a", ".mov", ".avif", ".heic", ".heif"}:
        return len(data) >= 12 and data[4:8] == b"ftyp"
    if suffix in {".ttf"}:
        return data.startswith(b"\x00\x01\x00\x00")
    if suffix in {".tif", ".tiff"}:
        return data.startswith((b"II*\x00", b"MM\x00*"))
    if suffix == ".aac":
        return len(data) >= 2 and data[0] == 0xFF and data[1] & 0xF6 == 0xF0
    return False


def _has_media_magic(data):
    prefix = data[:64]
    stripped = prefix.lstrip()
    return (
        prefix.startswith((
            b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
            b"OggS", b"fLaC", b"ID3", b"\x1aE\xdf\xa3", b"\x00\x01\x00\x00",
            b"wOFF", b"wOF2", b"OTTO", b"BM", b"II*\x00", b"MM\x00*",
        ))
        or (prefix.startswith(b"RIFF") and prefix[8:12] in {b"WEBP", b"WAVE", b"AVI "})
        or (len(prefix) >= 12 and prefix[4:8] == b"ftyp")
        or stripped.lower().startswith(b"<svg")
    )


def _asset_scope(relative_path):
    parts = relative_path.casefold().split("/")
    if len(parts) < 2 or parts[1] not in {"naranjo.online", "lidersea.com"}:
        return None
    if len(parts) >= 6 and parts[0] == "websites" and parts[2:5] == [
        "frontend", "src", "assets",
    ]:
        return (parts[1], "source")
    if len(parts) >= 7 and parts[0] == "websites" and parts[2:6] == [
        "internal", "web", "dist", "assets",
    ]:
        return (parts[1], "generated")
    return None


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = float(len(data))
    return -sum(
        (count / length) * math.log(count / length, 2)
        for count in counts if count
    )


def _opaque_artifact_finding(data, relative_path):
    stripped = data.lstrip()
    if data.startswith(ARCHIVE_OR_ENCRYPTION_MAGIC) or (
        len(data) >= 265 and data[257:262] == b"ustar"
    ) or stripped.startswith((b"age-encryption.org/v1", b"-----BEGIN PGP MESSAGE-----")):
        return "archive or encrypted artifact"

    suffix = Path(relative_path).suffix.casefold()
    valid_media = suffix in MEDIA_SUFFIXES and _media_magic_matches(data, suffix)
    try:
        data.decode("utf-8", "strict")
        valid_utf8 = True
    except UnicodeDecodeError:
        valid_utf8 = False
    if (b"\x00" in data or not valid_utf8) and not valid_media:
        return "opaque binary artifact"

    compact = re.sub(br"\s+", b"", data)
    if len(compact) >= 512 and (
        re.fullmatch(br"[A-Za-z0-9+/]+={0,2}", compact)
        or re.fullmatch(br"[0-9A-Fa-f]+", compact)
    ):
        return "opaque encoded artifact"

    if len(data) >= 1024 and not valid_media:
        printable = sum(
            1 for value in data if value in {9, 10, 13} or 32 <= value <= 126
        ) / float(len(data))
        if printable < 0.75 and _entropy(data) > 7.5:
            return "opaque high-entropy artifact"
    return None


_BLOCK_KIND_KEY = re.compile(r"^(?:kind|\"kind\"|'kind')\s*:")
_BLOCK_SECRET_KIND = re.compile(
    r"^(?:kind|\"kind\"|'kind')\s*:\s*(?:Secret|\"Secret\"|'Secret')"
    r"\s*(?:#.*)?$"
)
_FLOW_SECRET_KIND = re.compile(
    r"(?:^|[,{])\s*(?:kind|\"kind\"|'kind')\s*:\s*"
    r"(?:Secret|\"Secret\"|'Secret')\s*(?:[,}]|$)"
)
_SOPS_AES256_GCM = re.compile(
    r"ENC\[AES256_GCM,data:([A-Za-z0-9+/]+={0,2}),"
    r"iv:([A-Za-z0-9+/]+={0,2}),tag:([A-Za-z0-9+/]+={0,2}),type:str\]"
)
_HYBRID_AGE_RECIPIENT = re.compile(r"age1pq1[0-9a-z]+\Z")


def _top_level_yaml_lines(document):
    significant = [
        line for line in document.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not significant:
        return []
    base_indent = min(len(line) - len(line.lstrip(" ")) for line in significant)
    return [
        line[base_indent:]
        for line in significant
        if len(line) - len(line.lstrip(" ")) == base_indent
    ]


def _secret_kind_state(document):
    """Match the current parser's conservative canonical/noncanonical detector."""

    top_level = _top_level_yaml_lines(document)
    kind_lines = [line for line in top_level if _BLOCK_KIND_KEY.match(line)]
    secret_lines = [line for line in kind_lines if _BLOCK_SECRET_KIND.fullmatch(line)]
    flow_secret = _FLOW_SECRET_KIND.search(document) is not None
    suspicious_kind = False
    for line in document.splitlines():
        match = re.match(
            r"^\s*(?:kind|\"kind\"|'kind')\s*:\s*(.*?)\s*(?:#.*)?$", line
        )
        if match is None:
            continue
        value = match.group(1)
        if re.search(r"(?<![A-Za-z])Secret(?![A-Za-z])", value):
            suspicious_kind = True
        elif value.startswith(("!", "&", "*", "|", ">", "[", "{")):
            suspicious_kind = True
        elif value.startswith(('"', "'")) and "\\" in value:
            suspicious_kind = True
    secret_like = bool(secret_lines or flow_secret or suspicious_kind)
    canonical = secret_like and not flow_secret and kind_lines == ["kind: Secret"]
    return secret_like, canonical


def _contains_secret_document(text):
    return any(
        _secret_kind_state(document)[0]
        for document in re.split(r"(?m)^---\s*$", text)
    )


def _is_pinned_structural_secret_example(relative_path, data):
    return (
        relative_path.casefold() == STRUCTURAL_SECRET_EXAMPLE_PATH
        and hashlib.sha256(data).hexdigest() == STRUCTURAL_SECRET_EXAMPLE_SHA256
    )


def _canonical_base64_bytes(value):
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def _valid_sops_aes256_gcm(value):
    match = _SOPS_AES256_GCM.fullmatch(value)
    if match is None:
        return False
    data, initialization_vector, authentication_tag = (
        _canonical_base64_bytes(field) for field in match.groups()
    )
    return (
        data is not None
        and 1 <= len(data) <= 8192
        and initialization_vector is not None
        and len(initialization_vector) == 12
        and authentication_tag is not None
        and len(authentication_tag) == 16
    )


def _valid_age_armor_body(lines):
    if not lines or any(
        re.fullmatch(r"        [A-Za-z0-9+/]+={0,2}", line) is None
        or len(line) > 72
        for line in lines
    ):
        return False
    encoded = "".join(line[8:] for line in lines)
    decoded = _canonical_base64_bytes(encoded)
    return (
        decoded is not None
        and 40 <= len(decoded) <= 65536
        and decoded.startswith(b"age-encryption.org/v1\n")
        and b"\n--- " in decoded
        and decoded.endswith(b"\n")
    )


def _direct_mapping_items(document, mapping_name):
    lines = document.splitlines()
    entries = []
    for index, line in enumerate(lines):
        if not re.match(r"^{}:\s*(?:#.*)?$".format(re.escape(mapping_name)), line):
            continue
        direct_indent = None
        for child in lines[index + 1:]:
            if not child.strip() or child.lstrip().startswith("#"):
                continue
            indent = len(child) - len(child.lstrip())
            if indent == 0:
                break
            if direct_indent is None:
                direct_indent = indent
            if indent != direct_indent:
                continue
            scalar = re.match(r"^\s*([^:#][^:]*):\s*(.*?)\s*$", child)
            if scalar:
                entries.append((
                    scalar.group(1).strip(),
                    scalar.group(2).split(" #", 1)[0].strip().strip("'\""),
                ))
        break
    return entries


def _historical_sops_recipient(config):
    config = config.replace("\r\n", "\n")
    if "\r" in config:
        return None
    significant = [
        line for line in config.split("\n")
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected = [
        "creation_rules:",
        r"  - path_regex: ^kubernetes/.+\.sops\.ya?ml$",
        "    encrypted_regex: ^(data|stringData)$",
        "    age:",
    ]
    if significant[:4] != expected or len(significant) != 5:
        return None
    prefix = "      - "
    if not significant[4].startswith(prefix):
        return None
    recipient = significant[4][len(prefix):]
    return recipient if _HYBRID_AGE_RECIPIENT.fullmatch(recipient) else None


def _strict_historical_sops_secret(text, expected_recipient):
    """Mirror the current closed ENC/metadata/age and Tunnel identity grammar."""

    text = text.replace("\r\n", "\n")
    if "\r" in text:
        return False
    documents = [
        document for document in re.split(r"(?m)^---\s*$", text)
        if document.strip()
    ]
    if len(documents) != 1 or expected_recipient is None:
        return False
    document = documents[0]
    secret_like, canonical_kind = _secret_kind_state(document)
    if not secret_like or not canonical_kind:
        return False
    top_level_lines = _top_level_yaml_lines(document)
    if any(
        re.match(r"^[A-Za-z][A-Za-z0-9]*:\s*.*$", line) is None
        for line in top_level_lines
    ):
        return False
    top_level_names = [
        re.match(r"^([A-Za-z][A-Za-z0-9]*):", line).group(1)
        for line in top_level_lines
    ]
    if top_level_names != [
        "apiVersion", "kind", "metadata", "type", "stringData", "sops",
    ]:
        return False
    if re.search(r"(?m)^apiVersion:\s*v1\s*$", document) is None:
        return False
    if re.search(r"(?m)^type:\s*Opaque\s*$", document) is None:
        return False

    metadata_items = _direct_mapping_items(document, "metadata")
    if metadata_items != [
        ("name", "pi-websites-tunnel-token"),
        ("namespace", "cloudflare-public"),
    ]:
        return False

    lines = document.splitlines()
    payload_lines = [
        line for line in top_level_lines
        if re.match(
            r"^(?:data|stringData|\"data\"|'data'|\"stringData\"|'stringData')\s*:",
            line,
        )
    ]
    payloads = [
        (index, match.group(1))
        for index, line in enumerate(lines)
        for match in [re.fullmatch(r"(data|stringData):\s*(?:#.*)?", line)]
        if match is not None
    ]
    if len(payload_lines) != 1 or len(payloads) != 1 or payloads[0][1] != "stringData":
        return False
    payload_index, _payload_name = payloads[0]
    payload_items = []
    for child in lines[payload_index + 1:]:
        if not child.strip() or child.lstrip().startswith("#"):
            continue
        indent = len(child) - len(child.lstrip(" "))
        if indent == 0:
            break
        scalar = re.fullmatch(r"  ([A-Za-z0-9._-]+):\s*(\S+)\s*", child)
        if scalar is None or indent != 2:
            return False
        payload_items.append((scalar.group(1), scalar.group(2)))
    if (
        [key for key, _value in payload_items] != ["token"]
        or not _valid_sops_aes256_gcm(payload_items[0][1])
    ):
        return False

    sops_lines = [
        line for line in top_level_lines
        if re.match(r"^(?:sops|\"sops\"|'sops')\s*:", line)
    ]
    sops_indices = [
        index for index, line in enumerate(lines)
        if re.fullmatch(r"sops:\s*(?:#.*)?", line)
    ]
    if len(sops_lines) != 1 or len(sops_indices) != 1:
        return False
    sops_block = []
    for child in lines[sops_indices[0] + 1:]:
        if child.strip() and not child.lstrip().startswith("#"):
            if len(child) - len(child.lstrip(" ")) == 0:
                break
        sops_block.append(child)

    direct_entries = []
    for line in sops_block:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:len(line) - len(line.lstrip())]:
            return False
        if indent != 2:
            continue
        match = re.fullmatch(r"  ([a-z][a-z0-9_]*):\s*(.*?)\s*(?:#.*)?", line)
        if match is None:
            return False
        direct_entries.append((match.group(1), match.group(2)))
    if [key for key, _value in direct_entries] != [
        "age", "lastmodified", "mac", "encrypted_regex", "version",
    ]:
        return False
    direct_values = dict(direct_entries)
    if direct_values.get("age") != "":
        return False
    if re.fullmatch(
        r'"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
        r'(?:\.[0-9]+)?Z"',
        direct_values.get("lastmodified", ""),
    ) is None:
        return False
    if direct_values.get("encrypted_regex") != "^(data|stringData)$":
        return False
    if direct_values.get("version") != "3.13.3":
        return False
    if not _valid_sops_aes256_gcm(direct_values.get("mac", "")):
        return False

    active_direct_key = None
    for line in sops_block:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 2:
            match = re.fullmatch(r"  ([a-z][a-z0-9_]*):\s*(.*?)\s*(?:#.*)?", line)
            active_direct_key = match.group(1) if match is not None else None
        elif indent > 2 and active_direct_key != "age":
            return False

    age_indices = [
        index for index, line in enumerate(sops_block)
        if re.fullmatch(r"  age:\s*(?:#.*)?", line)
    ]
    if len(age_indices) != 1:
        return False
    age_block = []
    for child in sops_block[age_indices[0] + 1:]:
        if child.strip() and not child.lstrip().startswith("#"):
            if len(child) - len(child.lstrip(" ")) <= 2:
                break
        age_block.append(child)
    significant_age = [
        line for line in age_block
        if line.strip() and not line.lstrip().startswith("#")
    ]
    recipient = (
        re.fullmatch(r"    - recipient:\s*(age1pq1[0-9a-z]+)", significant_age[0])
        if significant_age else None
    )
    if recipient is None or recipient.group(1) != expected_recipient:
        return False
    if len(significant_age) < 5 or significant_age[1] != "      enc: |":
        return False
    if significant_age[2] != "        -----BEGIN AGE ENCRYPTED FILE-----":
        return False
    if significant_age[-1] != "        -----END AGE ENCRYPTED FILE-----":
        return False
    return _valid_age_armor_body(significant_age[3:-1])


def _parse_tree(root, commit, findings):
    raw = _git_bytes(
        root,
        ["ls-tree", "-r", "-z", "-l", "--full-tree", commit],
        MAX_TREE_INVENTORY_BYTES,
    )
    entries = []
    total_size = 0
    casefold_paths = set()
    records = [record for record in raw.split(b"\x00") if record]
    if len(records) > MAX_TREE_ENTRIES:
        raise ValidationFailure()
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_oid, raw_size = header.split()
            mode = mode.decode("ascii", "strict")
            object_type = object_type.decode("ascii", "strict")
            oid = raw_oid.decode("ascii", "strict")
        except (UnicodeDecodeError, ValueError) as problem:
            raise ValidationFailure() from problem
        path_identity = _path_digest(raw_path)
        try:
            relative_path = raw_path.decode("utf-8", "strict")
        except UnicodeDecodeError:
            relative_path = ""
            findings.add("non-UTF-8 repository path", commit, raw_path)
        folded = relative_path.casefold()
        if folded in casefold_paths:
            findings.add("case-colliding repository path", commit, raw_path)
        casefold_paths.add(folded)
        for label in _path_findings(relative_path):
            findings.add(label, commit, raw_path)
        for label in _text_findings(relative_path, "", _is_test_path(relative_path)):
            findings.add("repository path " + label, commit, raw_path)

        if mode not in {"100644", "100755"}:
            findings.add("symbolic or unsupported Git mode", commit, raw_path)
        if object_type != "blob":
            findings.add("non-blob Git tree entry", commit, raw_path)
            continue
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) is None:
            raise ValidationFailure()
        try:
            size = int(raw_size.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError) as problem:
            raise ValidationFailure() from problem
        if size < 0:
            raise ValidationFailure()
        total_size += size
        if size > MAX_BLOB_BYTES:
            findings.add("blob exceeds publication size ceiling", commit, raw_path)
            continue
        entries.append((raw_path, relative_path, path_identity, oid, size))
    if total_size > MAX_TREE_BYTES:
        findings.add("tree exceeds aggregate publication size ceiling", commit)
    return entries, len(raw)


def _read_blobs(root, sizes):
    total = sum(sizes.values())
    if total > MAX_UNIQUE_BLOB_BYTES:
        raise ValidationFailure()
    try:
        process = subprocess.Popen(
            ["git", "-C", str(root), "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=GIT_ENVIRONMENT,
        )
    except OSError as problem:
        raise ValidationFailure() from problem
    assert process.stdin is not None
    assert process.stdout is not None
    blobs = {}
    try:
        for oid in sorted(sizes):
            process.stdin.write(oid.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline(256)
            parts = header.rstrip(b"\n").split()
            if (
                len(parts) != 3
                or parts[0] != oid.encode("ascii")
                or parts[1] != b"blob"
                or not parts[2].isdigit()
                or int(parts[2]) != sizes[oid]
            ):
                raise ValidationFailure()
            data = process.stdout.read(sizes[oid])
            if len(data) != sizes[oid] or process.stdout.read(1) != b"\n":
                raise ValidationFailure()
            blobs[oid] = data
        process.stdin.close()
        if process.wait(timeout=MAX_GIT_OUTPUT_SECONDS) != 0:
            raise ValidationFailure()
    except (OSError, subprocess.TimeoutExpired):
        if not process.stdin.closed:
            process.stdin.close()
        process.kill()
        process.wait()
        raise ValidationFailure()
    finally:
        process.stdout.close()
    return blobs


def validate(root, baseline, candidate):
    commits = _outgoing_commits(root, baseline, candidate)
    findings = Findings()
    commit_entries = []
    blob_sizes = {}
    all_entries = 0
    all_inventory_bytes = 0

    for commit in commits:
        _commit_metadata(root, commit, findings)
        entries, inventory_bytes = _parse_tree(root, commit, findings)
        commit_entries.append((commit, entries))
        all_entries += len(entries)
        all_inventory_bytes += inventory_bytes
        if (
            all_entries > MAX_ALL_TREE_ENTRIES
            or all_inventory_bytes > MAX_ALL_TREE_INVENTORIES_BYTES
        ):
            raise ValidationFailure()
        for _raw_path, _relative_path, _identity, oid, size in entries:
            previous = blob_sizes.setdefault(oid, size)
            if previous != size:
                raise ValidationFailure()

    blobs = _read_blobs(root, blob_sizes)
    for commit, entries in commit_entries:
        commit_blobs = {
            relative_path.casefold(): blobs[oid]
            for _raw_path, relative_path, _identity, oid, _size in entries
        }
        config_data = commit_blobs.get(".sops.yaml")
        if config_data is None:
            expected_sops_recipient = None
        else:
            try:
                config_text = config_data.decode("utf-8", "strict")
            except UnicodeDecodeError:
                expected_sops_recipient = None
            else:
                expected_sops_recipient = _historical_sops_recipient(config_text)
        asset_totals = {}
        for raw_path, relative_path, _identity, oid, size in entries:
            data = blobs[oid]
            text = data.decode("utf-8", "surrogateescape")
            for label in _text_findings(text, relative_path, _is_test_path(relative_path)):
                findings.add(label, commit, raw_path)
            opaque = _opaque_artifact_finding(data, relative_path)
            if opaque is not None:
                findings.add(opaque, commit, raw_path)
            suffix = Path(relative_path).suffix.casefold()
            if suffix in MEDIA_SUFFIXES or _has_media_magic(data):
                scope = _asset_scope(relative_path)
                if relative_path.casefold() in APPROVED_TEXT_BADGE_PATHS:
                    if _approved_badge_violation(data):
                        findings.add(
                            "approved badge violates the strict text contract",
                            commit,
                            raw_path,
                        )
                elif scope is None:
                    findings.add("media outside approved frontend asset tree", commit, raw_path)
                else:
                    asset_totals[scope] = asset_totals.get(scope, 0) + size
                    if size > MAX_UI_ASSET_BYTES:
                        findings.add("frontend media exceeds size ceiling", commit, raw_path)
            if (
                suffix in TEXT_SUFFIXES
                and re.search(
                    r"(?i)data:(?:image|audio|video|font)/[^;,]+;base64,", text
                )
            ):
                findings.add("embedded media data URI", commit, raw_path)
            if (
                relative_path.casefold().startswith("kubernetes/")
                and relative_path.casefold().endswith((".yaml", ".yml"))
                and _contains_secret_document(text)
                and relative_path.casefold() != APPROVED_SOPS_PATH
                and not _is_pinned_structural_secret_example(relative_path, data)
            ):
                findings.add("unencrypted Kubernetes Secret manifest", commit, raw_path)
            if (
                relative_path.casefold() == APPROVED_SOPS_PATH
                and not _strict_historical_sops_secret(
                    text, expected_sops_recipient
                )
            ):
                findings.add("invalid historical SOPS Secret", commit, raw_path)
        for _scope, total in asset_totals.items():
            if total > MAX_ASSET_TREE_BYTES:
                findings.add("frontend media tree exceeds aggregate ceiling", commit)

    if findings.count:
        for message in findings.messages:
            print(message, file=sys.stderr)
        if findings.count > len(findings.messages):
            print(
                "FAIL publication history: additional findings suppressed; count={}".format(
                    findings.count - len(findings.messages)
                ),
                file=sys.stderr,
            )
        return False, len(commits)
    return True, len(commits)


def main():
    pull_request_range = False
    if len(sys.argv) == 3:
        baseline_argument, candidate_argument = sys.argv[1:]
    elif len(sys.argv) == 4 and sys.argv[1] == "--pull-request":
        pull_request_range = True
        baseline_argument, candidate_argument = sys.argv[2:]
    else:
        print("FAIL publication history validation.", file=sys.stderr)
        return 1
    try:
        root = _resolve_repository()
        baseline = _resolve_commit(root, baseline_argument)
        candidate = _resolve_commit(root, candidate_argument)
        if baseline == candidate:
            raise ValidationFailure()
        if pull_request_range:
            raw_merge_base = _git_bytes(root, ["merge-base", baseline, candidate], 128)
            try:
                merge_base = raw_merge_base.decode("ascii", "strict").strip()
            except UnicodeDecodeError as problem:
                raise ValidationFailure() from problem
            if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", merge_base) is None:
                raise ValidationFailure()
        else:
            _git_bytes(root, ["merge-base", "--is-ancestor", baseline, candidate], 0)
        allowed, commit_count = validate(root, baseline, candidate)
    except (OSError, ValidationFailure, ValueError):
        print("FAIL publication history validation.", file=sys.stderr)
        return 1
    if not allowed:
        return 1
    print(
        "PASS publication history: {} outgoing commit(s) scanned from {} to {}".format(
            commit_count, baseline, candidate
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
