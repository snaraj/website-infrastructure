#!/usr/bin/env python3
"""Strict declared-workload registry and its manifest/Rego bindings.

The reviewed registry is the only hand-maintained workload inventory.  Release
tags and digests remain derived state: they are read from the exact annotated
OCIRepository documents and included only in the generated Rego projection.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path


REGISTRY_PATH = Path("policies/workload-registry.json")
REGISTRY_SCHEMA = "dev.snaraj.workload-registry/v1"
MAX_REGISTRY_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_WORKLOADS = 24
MAX_PLATFORMS = 8
MAX_TARGET_CLUSTERS = 8
ACQUISITION_PROFILES = frozenset({"release-publisher"})
RESERVED_NAMESPACES = frozenset(
    {
        "cloudflare-public",
        "default",
        "flux-system",
        "kube-node-lease",
        "kube-public",
        "kube-system",
    }
)
DEPLOY_ROOTS = {
    "cluster-infrastructure": "infrastructure",
    "internal-service": "services",
    "site": "websites",
}
ANNOTATION = "platform.snaraj.dev/chart-release"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
OIDC_ISSUER_PATTERN = r"^https://token\.actions\.githubusercontent\.com$"
REGO_BEGIN = "# BEGIN GENERATED WORKLOAD REGISTRY -- scripts/workload_registry.py\n"
REGO_END = "# END GENERATED WORKLOAD REGISTRY\n"

DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
PROFILE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SOURCE_REPOSITORY_RE = re.compile(r"^snaraj/[A-Za-z0-9._-]{1,100}$")
PLATFORM_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]{0,31}/[a-z0-9][a-z0-9._-]{0,31}$"
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
VERSION_RE = re.compile(
    r"^(?=.{1,32}$)(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RegistryError(ValueError):
    """The registry or one of its derived bindings is not closed."""


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError("registry JSON contains duplicate key {!r}".format(key))
        result[key] = value
    return result


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    """Read one bounded regular file without following a symbolic link."""

    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise RegistryError(label + " must be one regular single-link file")
    if metadata.st_size > limit:
        raise RegistryError("{} exceeds {} bytes".format(label, limit))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    try:
        opened = os.fstat(descriptor)
        stable = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stable(opened) != stable(metadata)
        ):
            raise RegistryError(label + " changed before it could be read")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise RegistryError("{} exceeds {} bytes".format(label, limit))
        payload = b"".join(chunks)
        try:
            final_path = path.lstat()
        except OSError as error:
            raise RegistryError(label + " changed while it was read") from error
        if (
            stable(os.fstat(descriptor)) != stable(opened)
            or stable(final_path) != stable(opened)
            or len(payload) != opened.st_size
        ):
            raise RegistryError(label + " changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def _exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise RegistryError(label + " fields are incomplete or foreign")


def _sorted_unique(values, pattern, limit, label):
    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= limit
        or any(not isinstance(value, str) or pattern.fullmatch(value) is None for value in values)
        or values != sorted(set(values))
    ):
        raise RegistryError(label + " must be a bounded sorted unique list")
    return tuple(values)


def workflow_subject_pattern(entry) -> str:
    """Return the exact anchored cosign subject carried by the manifest."""

    return "^" + entry["publisher"]["workflowRef"].replace(".", r"\.") + "$"


def receipt_inspection_label(slug: str) -> str:
    """Preserve the receipt-v2 Markdown label without adding registry state."""

    return slug.split("-", 1)[0]


def deploy_path(entry) -> str:
    """Return the only workload root admitted for this shape and slug."""

    return "./kubernetes/{}/{}".format(
        DEPLOY_ROOTS[entry["deploy"]["shape"]], entry["slug"]
    )


def reconciler(entry) -> str:
    """Return the workload's isolated Flux reconciler identity."""

    return entry["slug"] + "-reconciler"


def deployment_ignore_lines(entries) -> tuple[str, ...]:
    """Return narrow source-ignore lines for declared paths and ancestors."""

    lines = []
    parents = set()
    for entry in entries:
        parts = Path(deploy_path(entry).removeprefix("./")).parts
        for depth in range(2, len(parts)):
            parent = "/".join(parts[:depth])
            if parent not in parents:
                lines += [f"!/{parent}/", f"/{parent}/*"]
                parents.add(parent)
        path = "/".join(parts)
        lines += [f"!/{path}/", f"!/{path}/**"]
    return tuple(lines)


def render_registry(entries) -> bytes:
    document = {
        "schema": REGISTRY_SCHEMA,
        "workloads": [entries[slug] for slug in sorted(entries)],
    }
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def parse_registry_bytes(payload: bytes, label: str = "workload registry") -> dict:
    if not payload or len(payload) > MAX_REGISTRY_BYTES:
        raise RegistryError(label + " size is invalid")
    if payload.startswith(b"\xef\xbb\xbf") or b"\r" in payload or b"\t" in payload:
        raise RegistryError(label + " encoding is non-canonical")
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise RegistryError(label + " must have one terminal LF")
    try:
        document = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except RegistryError:
        raise
    except (UnicodeDecodeError, RecursionError, ValueError) as error:
        raise RegistryError(label + " is not strict UTF-8 JSON") from error
    _exact_keys(document, {"schema", "workloads"}, label)
    if document["schema"] != REGISTRY_SCHEMA:
        raise RegistryError(label + " schema is foreign")
    rows = document["workloads"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_WORKLOADS:
        raise RegistryError(
            "{} must declare between 1 and {} workloads".format(label, MAX_WORKLOADS)
        )
    entries = {}
    inspection_labels = {}
    site_domains = {}
    for position, entry in enumerate(rows):
        row_label = "{} workload {}".format(label, position + 1)
        _exact_keys(
            entry,
            {
                "acquisitionProfile",
                "chartRepository",
                "deploy",
                "namespace",
                "platforms",
                "publisher",
                "slug",
                "sourceRepository",
                "targetClusters",
                "workloadRepository",
            },
            row_label,
        )
        slug = entry.get("slug")
        namespace = entry.get("namespace")
        profile = entry.get("acquisitionProfile")
        source = entry.get("sourceRepository")
        if not isinstance(slug, str) or DNS_LABEL_RE.fullmatch(slug) is None:
            raise RegistryError(row_label + " slug is not a DNS label")
        if slug in entries:
            raise RegistryError(label + " declares duplicate workload " + slug)
        inspection_label = receipt_inspection_label(slug)
        if inspection_label in inspection_labels:
            raise RegistryError(
                "{} workloads {} and {} share receipt inspection label {}".format(
                    label,
                    inspection_labels[inspection_label],
                    slug,
                    inspection_label,
                )
            )
        inspection_labels[inspection_label] = slug
        if (
            not isinstance(namespace, str)
            or namespace != slug
            or namespace in RESERVED_NAMESPACES
        ):
            raise RegistryError(slug + " must own its non-reserved slug namespace")
        if (
            not isinstance(profile, str)
            or PROFILE_RE.fullmatch(profile) is None
            or profile not in ACQUISITION_PROFILES
        ):
            raise RegistryError(slug + " acquisition profile is unknown")
        if (
            not isinstance(source, str)
            or SOURCE_REPOSITORY_RE.fullmatch(source) is None
            or source.split("/", 1)[1] in {".", ".."}
        ):
            raise RegistryError(slug + " source repository is outside the closed owner")
        if entry.get("chartRepository") != "ghcr.io/snaraj/charts/" + slug:
            raise RegistryError(slug + " chart repository is not its exact owned path")
        if entry.get("workloadRepository") != "ghcr.io/snaraj/" + slug:
            raise RegistryError(slug + " workload repository is not its exact owned path")
        _sorted_unique(
            entry.get("platforms"), PLATFORM_RE, MAX_PLATFORMS, slug + " platforms"
        )
        _sorted_unique(
            entry.get("targetClusters"),
            DNS_LABEL_RE,
            MAX_TARGET_CLUSTERS,
            slug + " target clusters",
        )
        publisher = entry.get("publisher")
        _exact_keys(publisher, {"oidcIssuer", "workflowRef"}, slug + " publisher")
        expected_ref = (
            "https://github.com/"
            + source
            + "/.github/workflows/"
            + profile
            + ".yml@refs/heads/main"
        )
        if publisher != {"oidcIssuer": OIDC_ISSUER, "workflowRef": expected_ref}:
            raise RegistryError(slug + " publisher is not the exact protected-main identity")
        deploy = entry.get("deploy")
        if not isinstance(deploy, dict):
            raise RegistryError(slug + " deploy declaration is not an object")
        shape = deploy.get("shape")
        expected_deploy_keys = {"shape"}
        if shape == "site":
            expected_deploy_keys.add("domain")
        if shape not in DEPLOY_ROOTS:
            raise RegistryError(slug + " deploy shape is unknown")
        _exact_keys(deploy, expected_deploy_keys, slug + " deploy")
        if DNS_LABEL_RE.fullmatch(reconciler(entry)) is None:
            raise RegistryError(slug + " is too long for its reconciler identity")
        if shape == "site":
            domain = deploy.get("domain")
            if (
                not isinstance(domain, str)
                or DOMAIN_RE.fullmatch(domain) is None
                or source != "snaraj/" + domain
            ):
                raise RegistryError(slug + " site deploy identity is not exact")
            if domain in site_domains:
                raise RegistryError(
                    "{} workloads {} and {} share site domain {}".format(
                        label, site_domains[domain], slug, domain
                    )
                )
            site_domains[domain] = slug
        entries[slug] = entry
    if list(entries) != sorted(entries):
        raise RegistryError(label + " workloads are not sorted by slug")
    if payload != render_registry(entries):
        raise RegistryError(label + " is not canonical sorted JSON")
    return entries


def load_registry(root: Path) -> dict:
    path = root / REGISTRY_PATH
    return parse_registry_bytes(_read_regular(path, MAX_REGISTRY_BYTES, str(REGISTRY_PATH)))


def _one(pattern, text, label):
    values = re.findall(pattern, text, re.MULTILINE)
    if len(values) != 1:
        raise RegistryError(label + " must appear exactly once")
    return values[0]


def _oci_documents(text: str, label: str):
    for document in re.split(r"^---\s*$", text, flags=re.MULTILINE):
        # Refuse alternate YAML spellings instead of letting a quoted or
        # escaped annotation/kind exist in Flux while disappearing here.
        if "chart-release" not in document:
            continue
        annotations = re.findall(
            r"^\s*" + re.escape(ANNOTATION) + r':\s*"[^"\r\n]+"\s*$',
            document,
            re.MULTILINE,
        )
        kinds = re.findall(r"^kind:\s*([^\s#]+)\s*$", document, re.MULTILINE)
        if len(annotations) != 1 or kinds != ["OCIRepository"]:
            raise RegistryError(
                label + " chart-release document is not one canonical OCIRepository"
            )
        yield document


def manifest_inventory(root: Path) -> dict:
    """Return every annotated OCIRepository, refusing partial documents."""

    inventory = {}
    manifest_root = root / "kubernetes"
    for path in sorted(manifest_root.rglob("*")):
        if path.is_symlink():
            raise RegistryError(str(path.relative_to(root)) + " is a symbolic manifest path")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RegistryError(str(path.relative_to(root)) + " is not a regular manifest")
        payload = _read_regular(path, MAX_MANIFEST_BYTES, str(path.relative_to(root)))
        if b"chart-release" not in payload:
            continue
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise RegistryError(str(path.relative_to(root)) + " is not UTF-8") from error
        label = str(path.relative_to(root))
        for document in _oci_documents(text, label):
            slug = _one(r"^\s{2}name:\s*([a-z0-9-]+)-chart\s*$", document, label + " name")
            if slug in inventory:
                raise RegistryError("duplicate annotated OCIRepository for " + slug)
            inventory[slug] = {
                "chartRepository": _one(
                    r"^\s{2}url:\s*oci://([^\s]+)\s*$", document, label + " URL"
                ),
                "digest": _one(
                    r"^\s{4}digest:\s*(sha256:[0-9a-f]{64})\s*$",
                    document,
                    label + " digest",
                ),
                "issuerPattern": _one(
                    r"^\s{6}- issuer:\s*(\S+)\s*$", document, label + " issuer"
                ),
                "namespace": _one(
                    r"^\s{2}namespace:\s*([a-z0-9-]+)\s*$",
                    document,
                    label + " namespace",
                ),
                "path": label,
                "subjectPattern": _one(
                    r"^\s{8}subject:\s*(\S+)\s*$", document, label + " subject"
                ),
                "version": _one(
                    r"^\s{4}" + re.escape(ANNOTATION) + r':\s*"([^"]+)"\s*$',
                    document,
                    label + " release annotation",
                ),
            }
    return dict(sorted(inventory.items()))


def bind_registry_to_manifests(root: Path, entries=None) -> dict:
    entries = load_registry(root) if entries is None else entries
    manifests = manifest_inventory(root)
    if set(manifests) != set(entries):
        missing = sorted(set(entries) - set(manifests))
        foreign = sorted(set(manifests) - set(entries))
        raise RegistryError(
            "registry/manifest workload sets differ (missing={}, foreign={})".format(
                missing, foreign
            )
        )
    for slug, entry in entries.items():
        manifest = manifests[slug]
        expected = {
            "chartRepository": entry["chartRepository"],
            "issuerPattern": OIDC_ISSUER_PATTERN,
            "namespace": entry["namespace"],
            "path": deploy_path(entry).removeprefix("./") + "/source.yaml",
            "subjectPattern": workflow_subject_pattern(entry),
        }
        for field, value in expected.items():
            if manifest[field] != value:
                raise RegistryError(
                    "{} manifest {} does not equal registry".format(slug, field)
                )
        if VERSION_RE.fullmatch(manifest["version"]) is None:
            raise RegistryError(slug + " manifest release version is invalid")
        if DIGEST_RE.fullmatch(manifest["digest"]) is None:
            raise RegistryError(slug + " manifest digest is invalid")
    return manifests


def rego_workloads(root: Path, entries=None) -> dict:
    entries = load_registry(root) if entries is None else entries
    manifests = bind_registry_to_manifests(root, entries)
    result = {}
    for slug, entry in entries.items():
        deploy = entry["deploy"]
        row = {
            "chart_repository": "oci://" + entry["chartRepository"],
            "deploy_path": deploy_path(entry),
            "deploy_shape": deploy["shape"],
            "namespace": entry["namespace"],
            "oidc_issuer_pattern": OIDC_ISSUER_PATTERN,
            "publisher_subject_pattern": workflow_subject_pattern(entry),
            "reconciler": reconciler(entry),
            "release": {
                "digest": manifests[slug]["digest"],
                "tag": manifests[slug]["version"],
            },
            "workload_repository_pattern": entry["workloadRepository"].replace(
                ".", "[.]"
            )
            + "(:v[0-9]+[.][0-9]+[.][0-9]+)?",
        }
        result[slug] = row
    return result


def render_rego_block(root: Path, entries=None) -> str:
    body = json.dumps(
        rego_workloads(root, entries), ensure_ascii=False, indent=2, sort_keys=True
    )
    return REGO_BEGIN + "workload_registry := " + body + "\n" + REGO_END


def rego_binding_errors(root: Path, entries=None) -> list[str]:
    try:
        text = _read_regular(
            root / "policies/conftest/kubernetes.rego",
            2 * 1024 * 1024,
            "policies/conftest/kubernetes.rego",
        ).decode("utf-8", errors="strict")
        expected = render_rego_block(root, entries)
    except (OSError, UnicodeDecodeError, RegistryError) as error:
        return [str(error)]
    if text.count(REGO_BEGIN) != 1 or text.count(REGO_END) != 1:
        return ["kubernetes.rego must carry one generated workload-registry block"]
    start = text.index(REGO_BEGIN)
    end = text.index(REGO_END, start) + len(REGO_END)
    if text[start:end] != expected:
        return ["kubernetes.rego workload-registry block is not byte-exact"]
    return []
