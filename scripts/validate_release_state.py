#!/usr/bin/env python3
"""Parse the narrow GitOps release state without a permissive YAML fallback."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
KEY_RE = re.compile(r"[A-Za-z0-9_.-]+\Z")
# Canonical manifests contain relative chart/reconciliation paths beginning
# with ``./``.  Keep the scalar grammar deliberately narrow, but permit that
# non-YAML-significant prefix while continuing to reject block scalars,
# quoting, anchors, aliases, flow collections, and inline comments.
SCALAR_RE = re.compile(r"[A-Za-z0-9./][A-Za-z0-9_./:@+-]*\Z")
TOKEN_REVISION_RE = re.compile(
    r"(?:not-configured|UNRESOLVED|rev-[a-z0-9][a-z0-9._-]{0,62})\Z"
)
# One public connector per website (ADR 0015), each with its OWN rotation
# revision so one Tunnel rotates without disturbing the other. The order is the
# canonical order of the release values block.
PUBLIC_CONNECTOR_SITES = ("naranjo-online", "lidersea-com")
MAX_RELEASE_YAML_BYTES = 65536

RELEASE_CONTRACTS = {
    "naranjo-online": {
        "release": "kubernetes/websites/naranjo-online/release.yaml",
        # The direct parent is bootstrap-owned and deliberately absent from
        # the applicable repository manifests. Its exact live spec is proved
        # by validate_platform_bootstrap.py, not inferred from a YAML template.
        "parent": None,
        "bootstrap_parent": True,
        "parent_name": "naranjo-online-reconciler",
        "namespace": "naranjo-online",
        "repository": "ghcr.io/snaraj/naranjo-online",
        "readiness": "active-via-signature-verified-chart",
        # Site charts arrive as signed OCI artifacts selected by exact digest,
        # so this identity has no in-repository chart path and no Git chart
        # source; ``chart_ref`` is the OCIRepository beside its release.
        "chart": None,
        "source": None,
        "chart_ref": "naranjo-online-chart",
        "parent_path": "./kubernetes/websites/naranjo-online",
        "parent_service_account": "naranjo-online-reconciler",
    },
    "lidersea-com": {
        "release": "kubernetes/websites/lidersea-com/release.yaml",
        "parent": None,
        "bootstrap_parent": True,
        "parent_name": "lidersea-com-reconciler",
        "namespace": "lidersea-com",
        "repository": "ghcr.io/snaraj/lidersea-com",
        "readiness": "active-via-signature-verified-chart",
        # Site charts arrive as signed OCI artifacts selected by exact digest,
        # so this identity has no in-repository chart path and no Git chart
        # source; ``chart_ref`` is the OCIRepository beside its release.
        "chart": None,
        "source": None,
        "chart_ref": "lidersea-com-chart",
        "parent_path": "./kubernetes/websites/lidersea-com",
        "parent_service_account": "lidersea-com-reconciler",
    },
    "cloudflare-public": {
        "release": "kubernetes/platform/cloudflare-public/release/release.yaml",
        "parent": None,
        "bootstrap_parent": False,
        "parent_name": None,
        "namespace": "cloudflare-public",
        "repository": None,
        "readiness": "suspended-until-sops-token-and-cloudflare-plan",
        # The connector chart is this repository's own, so it keeps the
        # anonymous Git chart source; it has no published release identity of
        # its own and therefore no OCI chart reference.
        "chart": "./kubernetes/platform/cloudflare-public/chart",
        "source": "cloudflare-public-source",
        "chart_ref": None,
        "parent_path": "./kubernetes/platform/cloudflare-public/release",
        "parent_service_account": "platform-services-reconciler",
    },
}


class CanonicalYamlError(ValueError):
    """One security-critical YAML field is absent, duplicated, or ambiguous."""


class HelmReleaseState(NamedTuple):
    """Exact effective values consumed by one reviewed HelmRelease."""

    suspended: bool
    values: dict[tuple[str, ...], str | None]
    values_text: str


def load_simple_mapping_file(path: Path) -> dict[tuple[str, ...], str | None]:
    """Load a complete canonical scalar/mapping-only YAML document.

    This intentionally supports only the small values-file grammar used by
    the release gate.  It is not a general YAML parser and fails closed on
    lists, aliases, anchors, tags, block/flow scalars, duplicate keys, or
    ambiguous indentation.
    """

    text = _read_canonical_text(path)
    lines = text.split("\n")
    return _parse_simple_mapping(lines, 0, len(lines), 0)


def _read_canonical_text(path: Path, *, allow_documents: bool = False) -> str:
    """Read one small canonical UTF-8 YAML file without newline normalization."""

    def identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )

    absolute_path = Path(os.path.abspath(os.fspath(path)))
    try:
        if absolute_path.resolve(strict=True) != absolute_path:
            raise CanonicalYamlError("release YAML path must not contain symlinks")
        before = absolute_path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise CanonicalYamlError("release YAML must be a regular file")
        if before.st_size <= 0 or before.st_size > MAX_RELEASE_YAML_BYTES:
            raise CanonicalYamlError("release YAML size is outside the bounded contract")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(absolute_path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise CanonicalYamlError("release YAML must be a regular file")
            if identity(opened) != identity(before):
                raise CanonicalYamlError("release YAML changed while opening")
            chunks = []
            remaining = MAX_RELEASE_YAML_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after_read = os.fstat(descriptor)
            if identity(after_read) != identity(opened) or len(raw) != opened.st_size:
                raise CanonicalYamlError("release YAML changed while reading")
        finally:
            os.close(descriptor)
        after = absolute_path.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or identity(after) != identity(opened)
            or absolute_path.resolve(strict=True) != absolute_path
        ):
            raise CanonicalYamlError("release YAML path changed while reading")
    except CanonicalYamlError:
        raise
    except (OSError, RuntimeError) as error:
        raise CanonicalYamlError("release YAML cannot be opened safely") from error

    if (
        not raw
        or len(raw) > MAX_RELEASE_YAML_BYTES
        or not raw.endswith(b"\n")
    ):
        raise CanonicalYamlError("release YAML must be bounded and LF terminated")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise CanonicalYamlError("release YAML must be UTF-8") from error
    if any(
        (ord(character) < 32 and character != "\n")
        or 127 <= ord(character) <= 159
        or ord(character) in {0x2028, 0x2029}
        for character in text
    ):
        raise CanonicalYamlError("release YAML must use LF as its only control separator")
    for line in text.split("\n"):
        if (
            not allow_documents
            and re.fullmatch(r"[ ]*(?:---|[.][.][.])(?:[ ]+#.*)?", line)
        ):
            raise CanonicalYamlError("release YAML document markers are forbidden")
    return text


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _mapping_entry(line: str, indent: int) -> tuple[str, str | None] | None:
    """Parse one canonical mapping entry at an exact indentation level."""

    if _indent(line) != indent:
        return None
    content = line[indent:]
    if content in {"---", "..."}:
        raise CanonicalYamlError("release YAML document markers are forbidden")
    match = re.fullmatch(r"([A-Za-z0-9_.-]+):(.*)", content)
    if match is None:
        raise CanonicalYamlError("release YAML contains a non-canonical mapping line")
    key, suffix = match.groups()
    if not KEY_RE.fullmatch(key):
        raise CanonicalYamlError("release YAML contains an unsupported key")
    if suffix == "":
        return key, None
    if not suffix.startswith(" ") or suffix != " " + suffix[1:].strip():
        raise CanonicalYamlError("release YAML scalar spacing is not canonical")
    value = suffix[1:]
    if not SCALAR_RE.fullmatch(value):
        raise CanonicalYamlError("release YAML contains an unsupported scalar")
    return key, value


def _child(
    lines: list[str],
    start: int,
    end: int,
    indent: int,
    key: str,
    *,
    container: bool,
) -> tuple[str | None, int, int]:
    """Return one exact child and its bounded nested section."""

    matches: list[tuple[int, str | None]] = []
    for index in range(start, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        entry = _mapping_entry(line, indent)
        if entry is not None and entry[0] == key:
            matches.append((index, entry[1]))
    if len(matches) != 1:
        raise CanonicalYamlError("release YAML field is missing or duplicated")
    index, value = matches[0]
    if container and value is not None:
        raise CanonicalYamlError("release YAML mapping field is not a mapping")
    if not container and value is None:
        raise CanonicalYamlError("release YAML scalar field is not a scalar")

    nested_end = end
    for candidate in range(index + 1, end):
        line = lines[candidate]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if _indent(line) <= indent:
            nested_end = candidate
            break
    return value, index + 1, nested_end


def canonical_scalar(text: str, path: tuple[str, ...]) -> str:
    """Extract one scalar only through exact two-space mapping ancestry."""

    if not path:
        raise CanonicalYamlError("release YAML path is empty")
    lines = text.split("\n")
    start = 0
    end = len(lines)
    indent = 0
    for component in path[:-1]:
        _, start, end = _child(
            lines,
            start,
            end,
            indent,
            component,
            container=True,
        )
        indent += 2
    value, _, _ = _child(
        lines,
        start,
        end,
        indent,
        path[-1],
        container=False,
    )
    if value is None:  # Kept explicit for type narrowing and future refactors.
        raise CanonicalYamlError("release YAML scalar is unavailable")
    return value


def _mapping_section(
    text: str,
    path: tuple[str, ...],
) -> tuple[list[str], int, int, int]:
    lines = text.split("\n")
    start = 0
    end = len(lines)
    indent = 0
    for component in path:
        _, start, end = _child(
            lines,
            start,
            end,
            indent,
            component,
            container=True,
        )
        indent += 2
    return lines, start, end, indent


def _parse_simple_mapping(
    lines: list[str],
    start: int,
    end: int,
    base_indent: int,
) -> dict[tuple[str, ...], str | None]:
    """Validate the values subtree as unique map/scalar entries with no YAML magic."""

    parsed: dict[tuple[str, ...], str | None] = {}
    contexts: dict[int, tuple[str, ...]] = {base_indent: ()}
    for index in range(start, end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = _indent(line)
        if indent < base_indent or (indent - base_indent) % 2:
            raise CanonicalYamlError("release values indentation is not canonical")
        for level in tuple(contexts):
            if level > indent:
                del contexts[level]
        parent = contexts.get(indent)
        if parent is None:
            raise CanonicalYamlError("release values indentation jumps a mapping level")
        entry = _mapping_entry(line, indent)
        if entry is None:
            raise CanonicalYamlError("release values contain an unsupported document marker")
        key, value = entry
        item_path = parent + (key,)
        if item_path in parsed:
            raise CanonicalYamlError("release values contain a duplicate key")
        parsed[item_path] = value
        contexts.pop(indent + 2, None)
        if value is None:
            contexts[indent + 2] = item_path
    if not parsed:
        raise CanonicalYamlError("release values mapping is empty")
    return parsed


def _bool_scalar(value: str) -> bool:
    if value not in {"true", "false"}:
        raise CanonicalYamlError("release boolean must be explicit true or false")
    return value == "true"


def _require_exact_significant_lines(
    text: str,
    expected: list[str | re.Pattern[str]],
) -> None:
    """Reject every field outside one closed, ordered reviewed manifest shape."""

    actual = [
        line
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(actual) != len(expected):
        raise CanonicalYamlError("release YAML shape is outside the closed contract")
    for line, requirement in zip(actual, expected):
        if isinstance(requirement, str):
            matches = line == requirement
        else:
            matches = requirement.fullmatch(line) is not None
        if not matches:
            raise CanonicalYamlError("release YAML shape is outside the closed contract")


def _helm_release_shape(name: str) -> list[str | re.Pattern[str]]:
    """Return the complete per-identity HelmRelease line allowlist."""

    contract = RELEASE_CONTRACTS[name]
    common = [
        "apiVersion: helm.toolkit.fluxcd.io/v2",
        "kind: HelmRelease",
        "metadata:",
        "  name: {}".format(name),
        "  namespace: {}".format(contract["namespace"]),
        "  annotations:",
        "    platform.snaraj.dev/readiness: {}".format(contract["readiness"]),
        "spec:",
        re.compile(r"  suspend: (?:true|false)\Z"),
        "  interval: 10m0s",
        # Retention is pinned to an exact literal, not a range, because Helm
        # stores every release revision as a Secret in the release namespace
        # and prunes history to maxHistory-1 BEFORE writing the new revision.
        # A retention value that can reach the namespace Secret budget makes
        # the prune free nothing and the create fail closed against quota,
        # which wedges the release permanently — no reconcile recovers it, and
        # every later deploy of that identity is blocked (issue #198). Leaving
        # the field unset is the same failure by another route: helm-controller
        # then applies its own five-revision default. Pinning the literal here
        # means dropping, raising, or omitting retention is a hard gate failure
        # rather than a deploy that stops working several releases later.
        "  maxHistory: 2",
        "  releaseName: {}".format(name),
        "  serviceAccountName: helm-reconciler",
    ]
    if contract["repository"] is not None:
        common.extend(
            [
                "  driftDetection:",
                "    mode: enabled",
            ]
        )
    # Two mutually exclusive chart bindings, one per release family. A site
    # release must reference its own signature-verified OCIRepository and must
    # NOT carry an inline ``chart:`` block; the connector release must keep the
    # in-repository Git chart and must NOT carry a ``chartRef``. Because this
    # allowlist is exhaustive and ordered, either substitution — including one
    # site pointing at the other site's chart source — is rejected here before
    # any downstream policy sees it.
    if contract["chart_ref"] is not None:
        common.extend(
            [
                "  chartRef:",
                "    kind: OCIRepository",
                "    name: {}".format(contract["chart_ref"]),
            ]
        )
    else:
        common.extend(
            [
                "  chart:",
                "    spec:",
                "      chart: {}".format(contract["chart"]),
                "      reconcileStrategy: Revision",
                "      sourceRef:",
                "        kind: GitRepository",
                "        name: {}".format(contract["source"]),
                "      interval: 10m0s",
            ]
        )
    common.extend(
        [
            "  install:",
            "    remediation:",
            "      retries: 0",
            "  upgrade:",
            "    cleanupOnFail: true",
            "    remediation:",
            "      retries: 0",
            "      strategy: rollback",
            "  values:",
        ]
    )
    if contract["chart_ref"] is not None:
        # The verified exact-site chart is the sole image-identity carrier.
        # The exhaustive allowlist rejects every extra platform value.
        common.append("    deploymentReady: true")
    else:
        common.append("    connectors:")
        for site in PUBLIC_CONNECTOR_SITES:
            common.extend(
                [
                    "      {}:".format(site),
                    re.compile(
                        r"        tokenRevision: " + TOKEN_REVISION_RE.pattern
                    ),
                ]
            )
    return common


def _parent_shape(name: str) -> list[str | re.Pattern[str]]:
    """Return the complete per-identity parent Kustomization allowlist."""

    contract = RELEASE_CONTRACTS[name]
    parent_name = str(contract["parent_name"])
    expected: list[str | re.Pattern[str]] = [
        "apiVersion: kustomize.toolkit.fluxcd.io/v1",
        "kind: Kustomization",
        "metadata:",
        "  name: {}".format(parent_name),
        "  namespace: flux-system",
        "spec:",
    ]
    expected.extend(
        [
            "  deletionPolicy: Orphan",
            "  force: false",
            "  interval: 10m0s",
            "  path: {}".format(contract["parent_path"]),
            "  prune: false",
            "  retryInterval: 1m0s",
            "  serviceAccountName: {}".format(contract["parent_service_account"]),
            "  sourceRef:",
            "    kind: GitRepository",
            "    name: flux-system",
            "  suspend: false",
            "  timeout: 5m0s",
            "  wait: true",
        ]
    )
    return expected


def load_helm_release(name: str, root: Path = ROOT) -> HelmReleaseState:
    """Load one closed release identity and its exact spec.values mapping."""

    contract = RELEASE_CONTRACTS[name]
    text = _read_canonical_text(root / str(contract["release"]))
    _require_exact_significant_lines(text, _helm_release_shape(name))
    if canonical_scalar(text, ("apiVersion",)) != "helm.toolkit.fluxcd.io/v2":
        raise CanonicalYamlError("release apiVersion is unsupported")
    if canonical_scalar(text, ("kind",)) != "HelmRelease":
        raise CanonicalYamlError("release kind is unsupported")
    if canonical_scalar(text, ("metadata", "name")) != name:
        raise CanonicalYamlError("release name does not match its closed identity")
    if canonical_scalar(text, ("metadata", "namespace")) != contract["namespace"]:
        raise CanonicalYamlError("release namespace does not match its closed identity")
    suspended = _bool_scalar(canonical_scalar(text, ("spec", "suspend")))

    lines, start, end, base_indent = _mapping_section(text, ("spec", "values"))
    values = _parse_simple_mapping(lines, start, end, base_indent)
    rendered_lines = []
    for line in lines[start:end]:
        if line.strip() and not line.lstrip().startswith("#"):
            if _indent(line) < base_indent:
                raise CanonicalYamlError("release values escaped their mapping")
            rendered_lines.append(line[base_indent:])
        else:
            rendered_lines.append("")
    values_text = "\n".join(rendered_lines).rstrip("\n") + "\n"

    if contract["chart_ref"] is not None:
        if values != {("deploymentReady",): "true"}:
            raise CanonicalYamlError(
                "site release values must contain exactly deploymentReady: true"
            )
    else:
        # Every connector carries its own canonical revision; a missing or
        # malformed revision on EITHER connector fails closed.
        for site in PUBLIC_CONNECTOR_SITES:
            token_revision = values.get(("connectors", site, "tokenRevision"))
            if (
                not isinstance(token_revision, str)
                or TOKEN_REVISION_RE.fullmatch(token_revision) is None
            ):
                raise CanonicalYamlError("tunnel token revision is not canonical")
    return HelmReleaseState(suspended, values, values_text)


def load_parent_suspension(name: str, root: Path = ROOT) -> bool:
    """Validate the site's closed parent Kustomization and return suspension."""

    contract = RELEASE_CONTRACTS[name]
    if any((root / "kubernetes/reconciliation").glob("*.yaml")):
        raise CanonicalYamlError("retired aggregate reconciliation is present")
    if contract["parent"] is None:
        # Website parents are permanent bootstrap-owned runtime objects. The
        # repository transition gate validates only the site desired state;
        # live parent exactness belongs to the release-selector bootstrap and
        # convergence witness. Cloudflare has no such parent and remains inert.
        return not bool(contract.get("bootstrap_parent"))
    combined = _read_canonical_text(
        root / str(contract["parent"]), allow_documents=True
    )
    documents = combined.removesuffix("\n").split("\n---\n")
    expected_name = str(contract["parent_name"])
    matches = [
        document + "\n"
        for document in documents
        if "  name: {}\n".format(expected_name) in document + "\n"
    ]
    if len(matches) != 1:
        raise CanonicalYamlError("direct parent identity is absent or duplicated")
    text = matches[0]
    _require_exact_significant_lines(text, _parent_shape(name))
    if canonical_scalar(text, ("apiVersion",)) != "kustomize.toolkit.fluxcd.io/v1":
        raise CanonicalYamlError("parent apiVersion is unsupported")
    if canonical_scalar(text, ("kind",)) != "Kustomization":
        raise CanonicalYamlError("parent kind is unsupported")
    if canonical_scalar(text, ("metadata", "name")) != expected_name:
        raise CanonicalYamlError("parent name does not match its closed identity")
    return False


def site_phase(name: str, root: Path = ROOT) -> str:
    """Return the safe staged/active phase of one values-only site release.

    Chart release identity is deliberately absent here: the sibling
    OCIRepository owns its exact audit annotation and immutable digest, while
    this parser closes HelmRelease values to the sole activation scalar.
    """

    release = load_helm_release(name, root)
    parent_suspended = load_parent_suspension(name, root)
    if not release.suspended and parent_suspended:
        raise CanonicalYamlError("active website release requires an active parent")
    return "staged" if release.suspended else "active"


def all_helm_releases_suspended(root: Path = ROOT) -> bool:
    """Return true only when every exact HelmRelease spec.suspend is true."""

    return all(load_helm_release(name, root).suspended for name in RELEASE_CONTRACTS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    phase = subparsers.add_parser("site-phase")
    phase.add_argument(
        "--site",
        required=True,
        choices=("naranjo-online", "lidersea-com"),
    )
    suspended = subparsers.add_parser("all-helm-suspended")
    suspended.set_defaults(command="all-helm-suspended")
    emit = subparsers.add_parser("emit-values")
    emit.add_argument("--release", required=True, choices=sorted(RELEASE_CONTRACTS))
    args = parser.parse_args(argv)

    try:
        root = args.root.resolve()
        if args.command == "site-phase":
            print(site_phase(args.site, root))
        elif args.command == "all-helm-suspended":
            if not all_helm_releases_suspended(root):
                return 1
        else:
            sys.stdout.write(load_helm_release(args.release, root).values_text)
    except (CanonicalYamlError, OSError, UnicodeError):
        print("ERROR release state is unavailable or non-canonical", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
