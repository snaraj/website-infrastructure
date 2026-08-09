#!/usr/bin/env python3
"""Dependency-free, credential-free repository policy checks."""

import argparse
import codecs
import hashlib
import ipaddress
import re
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
    CLOUDFLARE_TERRAFORM_SOURCE_FILES,
    STATE as TRANSITION_RELEASE_STATE,
    classify as classify_release_transition,
    cloudflare_default_off_errors,
    contains_secret_document,
    direct_mapping_entries,
    load_admission_suspension,
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
        "AGENTS.md", "SECURITY.md", "versions.env", "release-policy.env",
        "kubernetes", "websites", "scripts/validate_image_release.py",
        "websites/naranjo.online/VERSION", "websites/lidersea.com/VERSION",
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
            if contains_secret_document(text):
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
    errors.extend(image_release_errors(root))
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
    errors.extend(signature_policy_source_errors(root))
    return errors


def check_cloudflare(root):
    errors = []
    base = root / "infrastructure" / "cloudflare"
    if not base.exists():
        return ["Cloudflare OpenTofu directory missing"]
    errors.extend(cloudflare_default_off_errors(root))
    visible_paths, visibility_errors = _git_visible_cloudflare_paths(root)
    errors.extend(visibility_errors)
    expected_sources = {
        path.as_posix() for path in CLOUDFLARE_TERRAFORM_SOURCE_FILES
    }
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

    base = root / "infrastructure" / "cloudflare"
    if not (root / ".git").exists():
        return ({
            relative(path, root)
            for path in base.rglob("*")
            if path.is_file() or path.is_symlink()
        }, [])
    try:
        result = subprocess.run(
            [
                "git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
                "--exclude-standard", "--", "infrastructure/cloudflare",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return set(), ["Git-visible Cloudflare source inventory is unavailable"]
    if result.returncode != 0:
        return set(), ["Git-visible Cloudflare source inventory is unavailable"]
    try:
        decoded = result.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return set(), ["Git-visible Cloudflare source inventory is not UTF-8"]
    entries = decoded.split("\0")
    if entries[-1:] == [""]:
        entries.pop()
    if any(not entry.startswith("infrastructure/cloudflare/") for entry in entries):
        return set(), ["Git-visible Cloudflare source inventory escaped its root"]
    return set(entries), []


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


def site_chart_default_errors(domain, website_values):
    """Keep every chart inert even while Flux supplies reviewed overrides."""

    errors = []
    slug = next(
        (candidate for candidate_domain, candidate, _ in SITE_RELEASE_CONTRACTS
         if candidate_domain == domain),
        None,
    )
    expected_repository = (
        RELEASE_CONTRACTS[slug]["repository"] if slug is not None else None
    )
    if (
        expected_repository is not None
        and website_values.get(("image", "repository")) != expected_repository
    ):
        errors.append("{} chart default image repository is not canonical".format(domain))
    if website_values.get(("image", "digest")) != ZERO_DIGEST:
        errors.append("{} chart default must retain the all-zero digest".format(domain))
    if website_values.get(("deploymentReady",)) != "false":
        errors.append("{} chart default must remain deploymentReady false".format(domain))
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


def site_release_value_errors(domain, website_values, release_state):
    """Validate inert chart defaults and the authoritative Flux overrides."""

    return (
        site_chart_default_errors(domain, website_values)
        + site_release_override_errors(domain, release_state)
    )


def all_site_chart_default_errors(root):
    """Validate inert chart defaults in scaffold, transition, and release."""

    errors = []
    for domain, _, _ in SITE_RELEASE_CONTRACTS:
        try:
            values = load_simple_mapping_file(
                root / "websites" / domain / "chart" / "values.yaml"
            )
        except (CanonicalYamlError, OSError, UnicodeError):
            errors.append("{} chart defaults are unavailable or non-canonical".format(domain))
            continue
        errors.extend(site_chart_default_errors(domain, values))
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

    for domain, slug, _ in SITE_RELEASE_CONTRACTS:
        try:
            website_values = load_simple_mapping_file(
                root / "websites" / domain / "chart" / "values.yaml"
            )
            release_state = load_helm_release(slug, root)
        except (CanonicalYamlError, OSError, UnicodeError):
            errors.append("{} release state is unavailable or non-canonical".format(domain))
            continue
        errors.extend(site_release_value_errors(domain, website_values, release_state))
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
        for problem in tunnel_secret_errors(read(tunnel_secret), next(iter(configured_recipients))):
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
    expected_sources = {
        path.as_posix() for path in CLOUDFLARE_TERRAFORM_SOURCE_FILES
    }
    visible_sources = {
        path for path in visible_paths if path.endswith(".tf")
    }
    if visible_sources != expected_sources:
        errors.append("Cloudflare Terraform source inventory is outside the closed contract")
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
    variables = root / "infrastructure/cloudflare/variables.tf"
    if variables.is_file() and re.search(
        r'(?s)variable\s+"enable_cloudflare_resources"\s*\{.*?default\s*=\s*true',
        read(variables),
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
            "required reviewed/generated file missing: websites/{}/frontend/package-lock.json".format(domain),
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
            "required reviewed/generated file missing: infrastructure/cloudflare/.terraform.lock.hcl",
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

    errors = all_site_chart_default_errors(root)
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
