#!/usr/bin/env python3
"""Dependency-free, credential-free repository policy checks."""

import argparse
import codecs
import hashlib
import ipaddress
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".conf", ".css", ".env", ".example", ".go", ".hcl", ".html", ".js",
    ".json", ".lock", ".md", ".mjs", ".rego", ".service", ".sh",
    ".svelte", ".tf", ".timer", ".toml", ".tpl", ".ts", ".txt",
    ".yaml", ".yml",
}
SKIP_PARTS = {
    ".git", ".artifacts", ".cache", ".terraform", "coverage", "dist",
    "local-evidence", "node_modules",
}
MEDIA_SCAN_SKIP_PARTS = {
    ".git", ".artifacts", ".cache", ".terraform", "coverage",
    "local-evidence", "node_modules",
}
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
ALLOWED_CLOUDFLARE_RESOURCES = {
    "cloudflare_dns_record",
    "cloudflare_zero_trust_gateway_policy",
    "cloudflare_zero_trust_tunnel_cloudflared",
    "cloudflare_zero_trust_tunnel_cloudflared_config",
    "cloudflare_zero_trust_tunnel_cloudflared_route",
}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST_IMAGE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
# One closed tuple drives every site-specific release check so adding a site
# cannot silently leave image publication, admission, or activation asymmetric.
SITE_RELEASE_CONTRACTS = (
    ("naranjo.online", "naranjo-online", "publish-naranjo-online-image.yml"),
    ("lidersea.com", "lidersea-com", "publish-lidersea-com-image.yml"),
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


def files(root):
    """Yield public UTF-8 text without following links or trusting suffixes."""

    for path in root.rglob("*"):
        if (
            path.is_symlink()
            or not path.is_file()
            or any(part in SKIP_PARTS for part in path.parts)
            # The media gate rejects this public file separately; do not load
            # an arbitrarily large candidate into memory during regex checks.
            or path.stat().st_size > MAX_REPOSITORY_FILE_BYTES
        ):
            continue
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        try:
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(64 * 1024), b""):
                    if b"\x00" in chunk:
                        break
                    decoder.decode(chunk)
                else:
                    decoder.decode(b"", final=True)
                    yield path
        except (OSError, UnicodeDecodeError):
            # Binary files remain the media gate's responsibility; privacy and
            # secret checks never follow or print their contents.
            continue


def relative(path, root):
    return path.relative_to(root).as_posix()


def read(path):
    return path.read_text(encoding="utf-8")


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


def sops_secret_errors(text):
    """Validate the fail-closed structure of every Secret document without PyYAML."""
    errors = []
    for document in re.split(r"(?m)^---\s*$", text):
        if not re.search(r"(?m)^kind:\s*Secret\s*$", document):
            continue
        encrypted_values = 0
        lines = document.splitlines()
        for index, line in enumerate(lines):
            mapping = re.match(r"^(\s*)(data|stringData):\s*(?:#.*)?$", line)
            if not mapping:
                continue
            parent_indent = len(mapping.group(1))
            for child in lines[index + 1:]:
                if not child.strip() or child.lstrip().startswith("#"):
                    continue
                child_indent = len(child) - len(child.lstrip())
                if child_indent <= parent_indent:
                    break
                scalar = re.match(r"^\s+[^:#][^:]*:\s*(.*?)\s*$", child)
                if not scalar:
                    errors.append("malformed scalar beneath {}".format(mapping.group(2)))
                    continue
                value = scalar.group(1).split(" #", 1)[0].strip().strip("'\"")
                if not re.fullmatch(r"ENC\[[^\r\n]+\]", value):
                    errors.append("plaintext or malformed value beneath {}".format(mapping.group(2)))
                else:
                    encrypted_values += 1
        if encrypted_values == 0:
            errors.append("Secret contains no encrypted data/stringData values")
        if not re.search(r"(?m)^sops:\s*$", document):
            errors.append("SOPS metadata mapping is missing")
        if not re.search(r"(?m)^\s+mac:\s*ENC\[[^\r\n]+\]\s*$", document):
            errors.append("SOPS MAC is missing or malformed")
        if not re.search(r"(?m)^\s+age:\s*$", document) or not re.search(
            r"(?m)^\s+-?\s*recipient:\s*age1[0-9a-z]+\s*$", document
        ):
            errors.append("SOPS age recipient metadata is missing")
    return errors


def direct_mapping_entries(document, mapping_name):
    """Return direct scalar entries for one top-level YAML mapping."""
    lines = document.splitlines()
    entries = {}
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
                entries[scalar.group(1).strip()] = scalar.group(2).split(" #", 1)[0].strip().strip("'\"")
        break
    return entries


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


def tunnel_secret_errors(text, expected_recipient):
    errors = sops_secret_errors(text)
    documents = [doc for doc in re.split(r"(?m)^---\s*$", text) if doc.strip()]
    secrets = [doc for doc in documents if re.search(r"(?m)^kind:\s*Secret\s*$", doc)]
    if len(documents) != 1 or len(secrets) != 1:
        return errors + ["file must contain exactly one Secret document"]
    secret = secrets[0]
    if not re.search(r"(?m)^apiVersion:\s*v1\s*$", secret):
        errors.append("apiVersion must be v1")
    metadata = direct_mapping_entries(secret, "metadata")
    if metadata.get("name") != "pi-websites-tunnel-token":
        errors.append("Secret name must be pi-websites-tunnel-token")
    if metadata.get("namespace") != "cloudflare-public":
        errors.append("Secret namespace must be cloudflare-public")
    if not re.search(r"(?m)^type:\s*Opaque\s*$", secret):
        errors.append("Secret type must be Opaque")
    secret_keys = set(direct_mapping_entries(secret, "data")) | set(
        direct_mapping_entries(secret, "stringData")
    )
    if secret_keys != {"token"}:
        errors.append("Secret must contain only the token key")
    recipients = set(re.findall(r"(?m)^\s+-?\s*recipient:\s*(age1[0-9a-z]+)\s*$", secret))
    if recipients != {expected_recipient}:
        errors.append("SOPS recipient must exactly match .sops.yaml")
    return errors


def check_layout(root):
    errors = []
    for path in root.rglob("*"):
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        rel_parts = path.relative_to(root).parts
        lowered = tuple(part.lower() for part in rel_parts)
        if "apps" in lowered:
            errors.append("forbidden directory component 'apps': " + relative(path, root))
        if "clusters" in lowered:
            errors.append("forbidden directory component 'clusters': " + relative(path, root))
        if len(lowered) >= 2 and lowered[0:2] == ("kubernetes", "homelab"):
            errors.append("forbidden kubernetes/homelab layout: " + relative(path, root))
    required = [
        "AGENTS.md", "SECURITY.md", "versions.env", "kubernetes", "websites",
        "policies/gitleaks.toml",
    ]
    for name in required:
        if not (root / name).exists():
            errors.append("required path missing: " + name)
    return errors


def check_secrets(root):
    errors = []
    signatures = {
        "age private identity": re.compile(r"AGE-SECRET-KEY-1[A-Z0-9]+"),
        "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "GitHub classic token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        "GitHub fine-grained token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "literal Cloudflare API token": re.compile(
            r"(?i)cloudflare_api_token\s*=\s*[\"'][A-Za-z0-9_-]{20,}[\"']"
        ),
    }
    for path in files(root):
        text = read(path)
        for label, pattern in signatures.items():
            if pattern.search(text):
                errors.append("{} found in {}".format(label, relative(path, root)))

        rel = relative(path, root)
        if rel.startswith("kubernetes/") and path.suffix in {".yaml", ".yml"}:
            if re.search(r"(?m)^kind:\s*Secret\s*$", text):
                if not re.search(r"\.sops\.ya?ml$", path.name) and not is_fixture(path):
                    errors.append("unencrypted Kubernetes Secret manifest: " + rel)
                elif re.search(r"\.sops\.ya?ml$", path.name):
                    for problem in sops_secret_errors(text):
                        errors.append("invalid SOPS Secret {}: {}".format(rel, problem))
    return errors


def check_privacy(root):
    """Reject local identity and host facts that do not belong in public Git."""

    errors = []
    local_profile = re.compile(r"(?i)[A-Z]:[\\/]+Users[\\/]+[^\\/\s]+")
    workspace_path = re.compile(r"(?i)[A-Z]:[\\/]+dev(?:[\\/]|\b)")
    for path in files(root):
        text = read(path)
        rel = relative(path, root)
        if local_profile.search(text) or workspace_path.search(text):
            errors.append("local workstation path found in " + rel)
        if any(not allowed_ipv4(value, path, root) for value in IPV4_LITERAL.findall(text)):
            errors.append("host IPv4 address outside the public allowlist found in " + rel)
        if forbidden_ipv6_values(text):
            errors.append("host IPv6 address outside the public allowlist found in " + rel)
        if any(
            value != "00000000-0000-0000-0000-000000000000"
            for value in UUID_IDENTIFIER.findall(text)
        ):
            errors.append("machine or tunnel UUID found in " + rel)
        for address in EMAIL_ADDRESS.findall(text):
            if not address.lower().endswith(".invalid"):
                errors.append("non-synthetic email address found in " + rel)
        for identifier in OPAQUE_32_HEX.findall(text):
            if identifier not in SYNTHETIC_32_HEX:
                errors.append("non-synthetic 32-hex identifier found in " + rel)
    return errors


def check_media(root):
    """Keep heavyweight media and unresolved storage out of public desired state."""

    errors = []
    websites_root = root / "websites"
    asset_totals = {}
    repository_total = 0
    for path in root.rglob("*"):
        if any(part in MEDIA_SCAN_SKIP_PARTS for part in path.parts):
            continue
        if path.is_symlink():
            errors.append("symlink is forbidden in public repository content: " + relative(path, root))
            continue
        if not path.is_file():
            continue

        size = path.stat().st_size
        repository_total += size
        rel = relative(path, root)
        if size > MAX_REPOSITORY_FILE_BYTES:
            errors.append("file exceeds the public repository size ceiling: " + rel)

        asset_scope = None
        if websites_root.exists():
            try:
                parts = path.relative_to(websites_root).parts
            except ValueError:
                parts = ()
            if len(parts) >= 5 and parts[1:4] == ("frontend", "src", "assets"):
                asset_scope = (parts[0], "source")
            elif len(parts) >= 6 and parts[1:5] == ("internal", "web", "dist", "assets"):
                asset_scope = (parts[0], "generated")

        suffix = path.suffix.lower()
        with path.open("rb") as source:
            prefix = source.read(32)
        media_magic = has_media_magic(prefix)
        is_media = suffix in MEDIA_SUFFIXES
        if is_media or media_magic:
            if asset_scope is None:
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
            text = path.read_text(encoding="utf-8", errors="ignore")
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
        "!/websites/naranjo.online/chart/",
        "!/websites/lidersea.com/chart/",
    )
    if not sourceignore.is_file():
        errors.append("Flux source artifact boundary is missing: .sourceignore")
    else:
        source_text = read(sourceignore)
        for fragment in source_required:
            if fragment not in source_text:
                errors.append("Flux source artifact allowlist is missing: " + fragment)

    for path in list(live_kubernetes_files(root)) + list(
        (root / "websites").glob("*/chart/templates/*.yaml")
    ):
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

    values = root / "websites/naranjo.online/chart/values.yaml"
    schema = root / "websites/naranjo.online/chart/values.schema.json"
    deployment = root / "websites/naranjo.online/chart/templates/deployment.yaml"
    required_fragments = {
        values: ["media:", "  enabled: false", "  profile: UNRESOLVED_PI_MEDIA_STORAGE"],
        schema: ['"enabled": {"type": "boolean", "const": false}',
                 '"profile": {"type": "string", "const": "UNRESOLVED_PI_MEDIA_STORAGE"}'],
        deployment: ["name: MEDIA_ENABLED", "value: {{ .Values.media.enabled | quote }}"],
    }
    for path, fragments in required_fragments.items():
        if not path.is_file():
            errors.append("media fail-closed contract is missing: " + relative(path, root))
            continue
        text = read(path)
        for fragment in fragments:
            if fragment not in text:
                errors.append("media fail-closed fragment missing from {}: {}".format(
                    relative(path, root), fragment
                ))
    return errors


def check_workflows(root):
    errors = []
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return ["workflow directory missing: .github/workflows"]
    for path in workflow_dir.glob("*.y*ml"):
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
    return errors


def live_kubernetes_files(root):
    base = root / "kubernetes"
    if not base.exists():
        return []
    result = []
    for path in base.rglob("*.y*ml"):
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
            "controllers/patches/source-controller.yaml": [
                "--no-cross-namespace-refs=true", "runAsNonRoot", "RuntimeDefault",
                "requests/ephemeral-storage", "limits/ephemeral-storage", "sizeLimit",
            ],
            "controllers/patches/kustomize-controller.yaml": [
                "--no-cross-namespace-refs=true", "--no-remote-bases=true",
                "--default-service-account=default", "runAsNonRoot", "RuntimeDefault",
            ],
            "controllers/patches/helm-controller.yaml": [
                "--no-cross-namespace-refs=true", "--default-service-account=default",
                "runAsNonRoot", "RuntimeDefault",
            ],
            "access.yaml": [
                "namespace: cloudflare-public", "namespace: naranjo-online",
                "namespace: lidersea-com",
            ],
            "../reconciliation/platform-services.yaml": [
                "provider: sops", "name: sops-age",
            ],
        }
        for name, fragments in required_fragments.items():
            path = flux / name
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
        required_network_templates = {
            "websites/naranjo.online/chart/templates/network-policy.yaml": [
                "cloudflared-to-naranjo-online",
            ],
            "websites/lidersea.com/chart/templates/network-policy.yaml": [
                "cloudflared-to-lidersea-com",
            ],
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
    return errors


def check_cloudflare(root):
    errors = []
    base = root / "infrastructure" / "cloudflare"
    if not base.exists():
        return ["Cloudflare OpenTofu directory missing"]
    for path in base.rglob("*.tf"):
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


def check_release(root):
    errors = []
    versions = read(root / "versions.env")
    if re.search(r"(?m)^[A-Z0-9_]+=UNRESOLVED$", versions):
        errors.append("versions.env still contains UNRESOLVED pins")
    required_generated = [
        "websites/naranjo.online/frontend/package-lock.json",
        "websites/lidersea.com/frontend/package-lock.json",
        "kubernetes/flux-system/controllers/gotk-components.yaml",
        "infrastructure/cloudflare/.terraform.lock.hcl",
        "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml",
        "kubernetes/platform/admission/kyverno/controllers.yaml",
        "kubernetes/platform/admission/kustomization.yaml",
        "kubernetes/reconciliation/admission.yaml",
    ]
    for name in required_generated:
        if not (root / name).is_file():
            errors.append("required reviewed/generated file missing: " + name)

    sops_config = read(root / ".sops.yaml")
    if "REPLACE_WITH_PUBLIC_RECIPIENT" in sops_config:
        errors.append(".sops.yaml still has the invalid public-recipient sentinel")
    configured_recipients = set(re.findall(r"(?m)^\s*-\s*(age1[0-9a-z]+)\s*$", sops_config))
    if len(configured_recipients) != 1:
        errors.append(".sops.yaml must contain exactly one valid age recipient")

    for domain, _, _ in SITE_RELEASE_CONTRACTS:
        website_values = read(root / "websites" / domain / "chart" / "values.yaml")
        if "sha256:" + ("0" * 64) in website_values:
            errors.append("{} chart still uses the all-zero image digest".format(domain))
        if re.search(r"(?m)^deploymentReady:\s*false\s*$", website_values):
            errors.append("{} chart is not marked deploymentReady".format(domain))

    site_releases = [
        "kubernetes/websites/{}/release.yaml".format(slug)
        for _, slug, _ in SITE_RELEASE_CONTRACTS
    ]
    for name in site_releases + [
        "kubernetes/platform/cloudflare-public/release/release.yaml",
    ]:
        if re.search(r"(?m)^\s*suspend:\s*true\s*$", read(root / name)):
            errors.append("HelmRelease remains suspended: " + name)

    public_release = read(
        root / "kubernetes/platform/cloudflare-public/release/release.yaml"
    )
    if re.search(r"(?m)^\s*tokenRevision:\s*(?:not-configured|UNRESOLVED|['\"]?['\"]?)\s*$", public_release):
        errors.append("public tunnel tokenRevision is unresolved")

    tunnel_kustomization = read(
        root / "kubernetes/platform/cloudflare-public/release/kustomization.yaml"
    )
    if not active_kustomization_resource(tunnel_kustomization, "tunnel-token.sops.yaml"):
        errors.append("encrypted tunnel token is not active in the public release Kustomization")
    tunnel_secret = root / "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml"
    if tunnel_secret.is_file() and len(configured_recipients) == 1:
        for problem in tunnel_secret_errors(read(tunnel_secret), next(iter(configured_recipients))):
            errors.append("invalid production tunnel Secret: " + problem)
    kyverno_kustomization = read(root / "policies/kyverno/kustomization.yaml")
    for domain, slug, workflow in SITE_RELEASE_CONTRACTS:
        policy_name = "require-signed-{}.yaml".format(slug)
        signature_policy = root / "policies" / "kyverno" / policy_name
        if not signature_policy.is_file():
            errors.append("{} signature admission policy is missing".format(domain))
            continue
        signature_text = read(signature_policy)
        if not re.search(
            r"(?m)^\s*validationFailureAction:\s*Enforce\s*$", signature_text
        ):
            errors.append("{} signature admission policy is not enforced".format(domain))
        for fragment in [
            "ghcr.io/snaraj/{}*".format(slug),
            "https://github.com/snaraj/website-infrastructure/.github/workflows/{}@refs/heads/main".format(workflow),
            "https://token.actions.githubusercontent.com",
            "https://slsa.dev/provenance/v1",
            "https://actions.github.io/buildtypes/workflow/v1",
            "type: SigstoreBundle",
        ]:
            if fragment not in signature_text:
                errors.append("{} signature admission contract is missing: {}".format(domain, fragment))
        if not active_kustomization_resource(kyverno_kustomization, policy_name):
            errors.append("{} signature admission policy is not active in its Kustomization".format(domain))

    errors.extend(signature_admission_install_errors(root))
    return errors


def activation_requested(root):
    for domain, _, _ in SITE_RELEASE_CONTRACTS:
        values_path = root / "websites" / domain / "chart" / "values.yaml"
        if values_path.is_file():
            values = read(values_path)
            if not re.search(r"sha256:" + ("0" * 64), values):
                return True
            if re.search(r"(?m)^deploymentReady:\s*true\s*$", values):
                return True
    site_releases = [
        "kubernetes/websites/{}/release.yaml".format(slug)
        for _, slug, _ in SITE_RELEASE_CONTRACTS
    ]
    for name in site_releases + [
        "kubernetes/platform/cloudflare-public/release/release.yaml",
    ]:
        path = root / name
        if path.is_file() and not re.search(r"(?m)^\s*suspend:\s*true\s*$", read(path)):
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
    variables = root / "infrastructure/cloudflare/variables.tf"
    if variables.is_file() and re.search(
        r'(?s)variable\s+"enable_cloudflare_resources"\s*\{.*?default\s*=\s*true',
        read(variables),
    ):
        return True
    return False


def check_activation(root):
    if activation_requested(root):
        return check_release(root)
    return []


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
        current = CHECKS[name](args.root.resolve())
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
