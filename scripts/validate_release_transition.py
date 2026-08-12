#!/usr/bin/env python3
"""Classify only safe, canonical GitOps release transitions.

This module deliberately builds on ``validate_release_state.py``'s closed YAML
grammar.  It adds the cross-release dependency rules needed by CI without
turning the release-state parser into a general YAML loader.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import importlib.util
import re
import sys
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
ADMISSION_PATH = Path("kubernetes/reconciliation/admission.yaml")
CLOUDFLARE_RELEASE_KUSTOMIZATION = Path(
    "kubernetes/platform/cloudflare-public/release/kustomization.yaml"
)
CLOUDFLARE_TUNNEL_SECRET = Path(
    "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml"
)
CLOUDFLARE_PHASES_ROOT = Path("infrastructure/cloudflare/phases")
CLOUDFLARE_PHASE_CONTRACTS = {
    "admin-tunnel": {
        "guard": "approve_admin_tunnel_phase",
        "resources": frozenset({
            ("cloudflare_zero_trust_tunnel_cloudflared", "pi_admin"),
        }),
        "source_files": frozenset({
            "main.tf", "outputs.tf", "variables.tf", "versions.tf",
        }),
    },
    "admin-policies": {
        "guard": "approve_admin_policies_phase",
        "resources": frozenset({
            ("cloudflare_zero_trust_gateway_policy", "pi_admin_block"),
            ("cloudflare_zero_trust_gateway_policy", "pi_admin_ssh_allow"),
        }),
        "source_files": frozenset({
            "main.tf", "variables.tf", "versions.tf",
        }),
    },
    "admin-route": {
        "guard": "approve_admin_route_phase",
        "resources": frozenset({
            ("cloudflare_zero_trust_tunnel_cloudflared_route", "pi_admin"),
        }),
        "source_files": frozenset({
            "main.tf", "outputs.tf", "variables.tf", "versions.tf",
        }),
    },
    "admin-api": {
        "guard": "enable_kubernetes_api_access",
        "resources": frozenset({
            ("cloudflare_zero_trust_gateway_policy", "pi_admin_api_allow"),
        }),
        "source_files": frozenset({
            "main.tf", "outputs.tf", "variables.tf", "versions.tf",
        }),
    },
    "site-naranjo-online": {
        "guard": "approve_site_naranjo_online_phase",
        "resources": frozenset({
            ("cloudflare_zero_trust_tunnel_cloudflared", "naranjo_online"),
            ("cloudflare_zero_trust_tunnel_cloudflared_config", "naranjo_online"),
            ("cloudflare_dns_record", "naranjo_online_apex"),
            ("cloudflare_zone_setting", "naranjo_online_always_use_https"),
            ("cloudflare_zone_setting", "naranjo_online_min_tls_version"),
            ("cloudflare_zone_setting", "naranjo_online_tls_1_3"),
            ("cloudflare_zone_setting", "naranjo_online_zero_rtt"),
            ("cloudflare_zone_setting", "naranjo_online_http3"),
            ("cloudflare_zone_setting", "naranjo_online_ssl"),
        }),
        "source_files": frozenset({
            "main.tf", "variables.tf", "versions.tf",
        }),
    },
    "site-lidersea-com": {
        "guard": "approve_site_lidersea_com_phase",
        "resources": frozenset({
            ("cloudflare_zero_trust_tunnel_cloudflared", "lidersea_com"),
            ("cloudflare_zero_trust_tunnel_cloudflared_config", "lidersea_com"),
            ("cloudflare_dns_record", "lidersea_com_apex"),
            ("cloudflare_zone_setting", "lidersea_com_always_use_https"),
            ("cloudflare_zone_setting", "lidersea_com_min_tls_version"),
            ("cloudflare_zone_setting", "lidersea_com_tls_1_3"),
            ("cloudflare_zone_setting", "lidersea_com_zero_rtt"),
            ("cloudflare_zone_setting", "lidersea_com_http3"),
            ("cloudflare_zone_setting", "lidersea_com_ssl"),
        }),
        "source_files": frozenset({
            "main.tf", "variables.tf", "versions.tf",
        }),
    },
}
# One public Tunnel per website, never a shared one and never a third. Each
# site root owns exactly one Tunnel whose name is that site's identity tuple,
# and the other site's identity token must not appear anywhere inside it.
CLOUDFLARE_SITE_PHASES = {
    "site-naranjo-online": {
        "tunnel_name": "naranjo-online",
        "foreign_marker": "lidersea",
    },
    "site-lidersea-com": {
        "tunnel_name": "lidersea-com",
        "foreign_marker": "naranjo",
    },
}
CLOUDFLARE_PUBLIC_TUNNEL_COUNT = 2
CLOUDFLARE_ADMIN_TUNNEL_COUNT = 1
CLOUDFLARE_TUNNEL_CONNECTOR_RESOURCE_TYPE = "cloudflare_zero_trust_tunnel_cloudflared"
CLOUDFLARE_TERRAFORM_SOURCE_FILES = frozenset(
    CLOUDFLARE_PHASES_ROOT / phase / source
    for phase, contract in CLOUDFLARE_PHASE_CONTRACTS.items()
    for source in contract["source_files"]
)
CLOUDFLARE_TERRAFORM_REVIEW_FILES = frozenset(
    set(CLOUDFLARE_TERRAFORM_SOURCE_FILES)
    | {
        CLOUDFLARE_PHASES_ROOT / phase / name
        for phase in CLOUDFLARE_PHASE_CONTRACTS
        for name in (".terraform.lock.hcl", "terraform.tfvars.example")
    }
)
CLOUDFLARE_LOCK_FILES = frozenset(
    CLOUDFLARE_PHASES_ROOT / phase / ".terraform.lock.hcl"
    for phase in CLOUDFLARE_PHASE_CONTRACTS
)
CLOUDFLARE_RESOURCE_IDENTITIES = frozenset(
    identity
    for contract in CLOUDFLARE_PHASE_CONTRACTS.values()
    for identity in contract["resources"]
)
CLOUDFLARE_TOFU_VERSION = "1.12.5"
CLOUDFLARE_PROVIDER_VERSION = "5.22.0"
SOPS_CONFIG = Path(".sops.yaml")
AGE_RECIPIENT_RE = re.compile(r"age1pq1[0-9a-z]+\Z")
INVALID_AGE_RECIPIENT = "age1REPLACE_WITH_PUBLIC_RECIPIENT_BEFORE_ENCRYPTING"
SOPS_AES256_GCM_RE = re.compile(
    r"ENC\[AES256_GCM,data:([A-Za-z0-9+/]+={0,2}),"
    r"iv:([A-Za-z0-9+/]+={0,2}),tag:([A-Za-z0-9+/]+={0,2}),type:str\]"
)


def _canonical_base64_bytes(value: str) -> bytes | None:
    """Decode only canonical padded standard base64 without normalization."""

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def _valid_sops_aes256_gcm(value: str) -> bool:
    """Recognize SOPS' authenticated scalar envelope, not arbitrary ENC text."""

    match = SOPS_AES256_GCM_RE.fullmatch(value)
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


def _valid_age_armor_body(lines: list[str]) -> bool:
    """Validate the canonical armored age payload emitted beneath SOPS `enc`."""

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


def _load_release_state_module():
    """Load the exact sibling parser, never an ambient module of that name."""

    state_path = Path(__file__).resolve().with_name("validate_release_state.py")
    specification = importlib.util.spec_from_file_location(
        "_website_infrastructure_release_state", state_path
    )
    if specification is None or specification.loader is None:
        raise ImportError("release-state parser cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


STATE = _load_release_state_module()


class TransitionPlan(NamedTuple):
    """One fully classified, dependency-safe desired-state transition."""

    mode: str
    naranjo_online: str
    lidersea_com: str
    cloudflare_public: str
    admission_suspended: bool
    platform_suspended: bool
    naranjo_parent_suspended: bool
    lidersea_parent_suspended: bool

    @property
    def any_website_active(self) -> bool:
        """Keep production controls while a site is live or still reconcilable.

        During child-first rollback and parent-first resume, desired suspension
        is not proof that Flux has observed the child.  An active outer
        Kustomization therefore keeps the website signature/capacity envelope
        mandatory until that outer controller is separately suspended.
        """

        return (
            "active" in (self.naranjo_online, self.lidersea_com)
            or not self.naranjo_parent_suspended
            or not self.lidersea_parent_suspended
        )

    def website_parent_suspended(self, name: str) -> bool:
        """Return the exact outer reconciliation state for one closed site."""

        if name == "naranjo-online":
            return self.naranjo_parent_suspended
        if name == "lidersea-com":
            return self.lidersea_parent_suspended
        raise STATE.CanonicalYamlError(
            "website escaped the closed transition identity set"
        )

    @property
    def any_workload_active(self) -> bool:
        return (
            self.any_website_active
            or self.cloudflare_public == "active"
            or not self.admission_suspended
            or not self.platform_suspended
        )


def _admission_shape():
    """Return the complete, ordered allowlist for the admission parent."""

    return [
        "apiVersion: kustomize.toolkit.fluxcd.io/v1",
        "kind: Kustomization",
        "metadata:",
        "  name: admission",
        "  namespace: flux-system",
        "  annotations:",
        "    platform.snaraj.dev/readiness: suspended-until-reviewed-kyverno-artifact-digests-rbac-and-runtime-evidence",
        "spec:",
        "  dependsOn:",
        "    - name: platform-prerequisites",
        "  interval: 10m0s",
        "  path: ./kubernetes/platform/admission",
        "  prune: true",
        "  retryInterval: 1m0s",
        "  serviceAccountName: admission-reconciler",
        "  sourceRef:",
        "    kind: GitRepository",
        "    name: flux-system",
        re.compile(r"  suspend: (?:true|false)\Z"),
        "  timeout: 5m0s",
        "  wait: true",
    ]


def load_admission_suspension(root: Path = ROOT) -> bool:
    """Validate the exact admission Kustomization and return suspension."""

    text = STATE._read_canonical_text(root / ADMISSION_PATH)
    STATE._require_exact_significant_lines(text, _admission_shape())
    if STATE.canonical_scalar(text, ("apiVersion",)) != (
        "kustomize.toolkit.fluxcd.io/v1"
    ):
        raise STATE.CanonicalYamlError("admission apiVersion is unsupported")
    if STATE.canonical_scalar(text, ("kind",)) != "Kustomization":
        raise STATE.CanonicalYamlError("admission kind is unsupported")
    if STATE.canonical_scalar(text, ("metadata", "name")) != "admission":
        raise STATE.CanonicalYamlError("admission identity is unsupported")
    return STATE._bool_scalar(STATE.canonical_scalar(text, ("spec", "suspend")))


_BLOCK_KIND_KEY = re.compile(r"^(?:kind|\"kind\"|'kind')\s*:")
_BLOCK_SECRET_KIND = re.compile(
    r"^(?:kind|\"kind\"|'kind')\s*:\s*(?:Secret|\"Secret\"|'Secret')"
    r"\s*(?:#.*)?$"
)
_FLOW_SECRET_KIND = re.compile(
    r"(?:^|[,{])\s*(?:kind|\"kind\"|'kind')\s*:\s*"
    r"(?:Secret|\"Secret\"|'Secret')\s*(?:[,}]|$)"
)


def _top_level_yaml_lines(document: str) -> list[str]:
    """Return root-level significant lines without interpreting permissive YAML."""

    significant = [
        line
        for line in document.splitlines()
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


def _secret_kind_state(document: str) -> tuple[bool, bool]:
    """Return (is Secret-like, uses one canonical top-level kind spelling)."""

    top_level = _top_level_yaml_lines(document)
    kind_lines = [line for line in top_level if _BLOCK_KIND_KEY.match(line)]
    secret_lines = [line for line in kind_lines if _BLOCK_SECRET_KIND.fullmatch(line)]
    flow_secret = _FLOW_SECRET_KIND.search(document) is not None
    # YAML tags, anchors, aliases, block scalars, collections, and escaped
    # quoted scalars can all resolve to ``Secret`` while hiding that literal
    # from a narrow regex. This repository requires a plain canonical kind, so
    # any such kind value is conservatively Secret-like and rejected unless it
    # is exactly ``kind: Secret``.
    suspicious_kind = False
    for line in document.splitlines():
        match = re.match(
            r"^\s*(?:kind|\"kind\"|'kind')\s*:\s*(.*?)\s*(?:#.*)?$",
            line,
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
    canonical = (
        secret_like
        and not flow_secret
        and kind_lines == ["kind: Secret"]
    )
    return secret_like, canonical


def contains_secret_document(text: str) -> bool:
    """Recognize canonical and noncanonical root-level Secret declarations."""

    return any(
        _secret_kind_state(document)[0]
        for document in re.split(r"(?m)^---\s*$", text)
    )


def sops_secret_errors(text: str) -> list[str]:
    """Validate one or more canonical encrypted Secret documents.

    Only direct top-level ``data``/``stringData`` and ``sops`` blocks count.
    Flow maps, aliases, tags, nested bait fields, duplicate payloads, and
    malformed direct children fail closed without invoking a permissive YAML
    loader.
    """

    errors = []
    documents = [
        document
        for document in re.split(r"(?m)^---\s*$", text)
        if document.strip()
    ]
    if not documents:
        return ["SOPS file contains no Secret document"]
    for document in documents:
        secret_like, canonical_kind = _secret_kind_state(document)
        if not secret_like:
            errors.append("SOPS document must be one canonical Secret")
            continue
        if not canonical_kind:
            errors.append("Secret kind must use one canonical top-level 'kind: Secret' line")
        for line in _top_level_yaml_lines(document):
            if not re.match(r"^[A-Za-z][A-Za-z0-9]*:\s*.*$", line):
                errors.append("Secret top-level keys must use canonical block spelling")
        encrypted_values = 0
        lines = document.splitlines()
        top_level = _top_level_yaml_lines(document)
        payload_lines = [
            line for line in top_level
            if re.match(r"^(?:data|stringData|\"data\"|'data'|\"stringData\"|'stringData')\s*:", line)
        ]
        canonical_payloads = [
            (index, match.group(1))
            for index, line in enumerate(lines)
            if (match := re.fullmatch(r"(data|stringData):\s*(?:#.*)?", line))
        ]
        if len(payload_lines) != 1 or len(canonical_payloads) != 1:
            errors.append("Secret must contain one canonical top-level data/stringData block")
        else:
            payload_index, payload_name = canonical_payloads[0]
            seen_keys = set()
            for child in lines[payload_index + 1:]:
                if not child.strip() or child.lstrip().startswith("#"):
                    continue
                child_indent = len(child) - len(child.lstrip(" "))
                if child_indent == 0:
                    break
                scalar = re.fullmatch(
                    r"  ([A-Za-z0-9._-]+):\s*(\S+)\s*",
                    child,
                )
                if scalar is None or child_indent != 2:
                    errors.append(
                        "plaintext or malformed value beneath {}".format(payload_name)
                    )
                    continue
                key = scalar.group(1)
                if key in seen_keys:
                    errors.append("duplicate encrypted Secret payload key")
                    continue
                seen_keys.add(key)
                if not _valid_sops_aes256_gcm(scalar.group(2)):
                    errors.append("SOPS payload is not a canonical AES256_GCM envelope")
                    continue
                encrypted_values += 1
        if encrypted_values == 0:
            errors.append("Secret contains no encrypted data/stringData values")

        sops_lines = [
            line for line in top_level
            if re.match(r"^(?:sops|\"sops\"|'sops')\s*:", line)
        ]
        sops_indices = [
            index for index, line in enumerate(lines)
            if re.fullmatch(r"sops:\s*(?:#.*)?", line)
        ]
        if len(sops_lines) != 1 or len(sops_indices) != 1:
            errors.append("SOPS metadata mapping is missing or non-canonical")
            continue
        sops_index = sops_indices[0]
        sops_block = []
        for child in lines[sops_index + 1:]:
            if child.strip() and not child.lstrip().startswith("#"):
                indent = len(child) - len(child.lstrip(" "))
                if indent == 0:
                    break
            sops_block.append(child)

        # SOPS supports several master-key backends and permissive YAML key
        # spellings.  This repository deliberately permits only one canonical
        # age backend.  Treat every direct metadata entry as security relevant
        # so a quoted/tagged duplicate, PGP/KMS stanza, or alternate key group
        # cannot hide beside the recipient that the narrower checks recognize.
        required_sops_keys = [
            "age", "lastmodified", "mac", "encrypted_regex", "version",
        ]
        direct_sops_entries = []
        for line in sops_block:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if "\t" in line[:len(line) - len(line.lstrip())]:
                errors.append("SOPS metadata indentation must use spaces")
                continue
            if indent != 2:
                continue
            match = re.fullmatch(
                r"  ([a-z][a-z0-9_]*):\s*(.*?)\s*(?:#.*)?", line
            )
            if match is None:
                errors.append("SOPS metadata keys must use canonical spelling")
                continue
            direct_sops_entries.append((match.group(1), match.group(2)))
        direct_sops_keys = [key for key, _ in direct_sops_entries]
        direct_sops_values = dict(direct_sops_entries)
        if direct_sops_keys != required_sops_keys:
            errors.append("SOPS metadata must use the complete canonical field order")
        if direct_sops_values.get("age") != "":
            errors.append("SOPS age metadata must be a canonical block")
        if re.fullmatch(
            r'"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z"',
            direct_sops_values.get("lastmodified", ""),
        ) is None:
            errors.append("SOPS lastmodified metadata is malformed")
        if direct_sops_values.get("encrypted_regex") != "^(data|stringData)$":
            errors.append("SOPS encrypted_regex is outside the closed contract")
        if direct_sops_values.get("version") != "3.13.3":
            errors.append("SOPS metadata version does not match the pinned generator")
        if not _valid_sops_aes256_gcm(direct_sops_values.get("mac", "")):
            errors.append("SOPS MAC is not a canonical AES256_GCM envelope")

        active_direct_key = None
        for line in sops_block:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent == 2:
                match = re.fullmatch(
                    r"  ([a-z][a-z0-9_]*):\s*(.*?)\s*(?:#.*)?", line
                )
                active_direct_key = match.group(1) if match is not None else None
            elif indent > 2 and active_direct_key != "age":
                errors.append("scalar SOPS metadata must not contain nested controls")

        age_indices = [
            index for index, line in enumerate(sops_block)
            if re.fullmatch(r"  age:\s*(?:#.*)?", line)
        ]
        if len(age_indices) != 1:
            errors.append("SOPS age recipient metadata is missing")
        else:
            age_block = []
            for child in sops_block[age_indices[0] + 1:]:
                if child.strip() and not child.lstrip().startswith("#"):
                    indent = len(child) - len(child.lstrip(" "))
                    if indent <= 2:
                        break
                age_block.append(child)
            significant_age = [
                line for line in age_block
                if line.strip() and not line.lstrip().startswith("#")
            ]
            recipient_match = (
                re.fullmatch(r"    - recipient:\s*(age1[0-9a-z]+)", significant_age[0])
                if significant_age else None
            )
            if recipient_match is None:
                errors.append("SOPS age entries must use canonical recipient spelling")
            if len(significant_age) < 5 or significant_age[1] != "      enc: |":
                errors.append("SOPS age recipient must contain one canonical encrypted key block")
            else:
                if significant_age[2] != "        -----BEGIN AGE ENCRYPTED FILE-----":
                    errors.append("SOPS age armor opening marker is malformed")
                if significant_age[-1] != "        -----END AGE ENCRYPTED FILE-----":
                    errors.append("SOPS age armor closing marker is malformed")
                if not _valid_age_armor_body(significant_age[3:-1]):
                    errors.append("SOPS age armor payload is malformed")
    return errors


def _direct_mapping_items(document: str, mapping_name: str) -> list[tuple[str, str]]:
    """Return ordered direct scalar entries for one top-level YAML mapping."""

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
                entries.append(
                    (
                        scalar.group(1).strip(),
                        scalar.group(2).split(" #", 1)[0].strip().strip("'\""),
                    )
                )
        break
    return entries


def tunnel_secret_errors(text: str, expected_recipient: str) -> list[str]:
    """Require one canonical encrypted public-tunnel Secret identity."""

    errors = sops_secret_errors(text)
    documents = [doc for doc in re.split(r"(?m)^---\s*$", text) if doc.strip()]
    secrets = [doc for doc in documents if _secret_kind_state(doc)[0]]
    if len(documents) != 1 or len(secrets) != 1:
        return errors + ["file must contain exactly one Secret document"]
    secret = secrets[0]
    top_level = []
    for line in _top_level_yaml_lines(secret):
        match = re.match(r"^([A-Za-z][A-Za-z0-9]*):", line)
        if match is None:
            errors.append("Secret top-level keys must use canonical block spelling")
        else:
            top_level.append(match.group(1))
    data_mapping = "stringData"
    if top_level != ["apiVersion", "kind", "metadata", "type", data_mapping, "sops"]:
        errors.append("Secret top-level shape is outside the closed contract")
    if not re.search(r"(?m)^apiVersion:\s*v1\s*$", secret):
        errors.append("apiVersion must be v1")
    metadata_items = _direct_mapping_items(secret, "metadata")
    metadata = dict(metadata_items)
    if [name for name, _ in metadata_items] != ["name", "namespace"]:
        errors.append("Secret metadata shape is outside the closed contract")
    if metadata.get("name") != "pi-websites-tunnel-token":
        errors.append("Secret name must be pi-websites-tunnel-token")
    if metadata.get("namespace") != "cloudflare-public":
        errors.append("Secret namespace must be cloudflare-public")
    if not re.search(r"(?m)^type:\s*Opaque\s*$", secret):
        errors.append("Secret type must be Opaque")
    data_items = _direct_mapping_items(secret, data_mapping)
    if [name for name, _ in data_items] != ["token"]:
        errors.append("Secret must contain only the token key")
    recipients = re.findall(
        r"(?m)^\s+-?\s*recipient:\s*(age1[0-9a-z]+)\s*$", secret
    )
    if recipients != [expected_recipient]:
        errors.append("SOPS recipient must exactly match .sops.yaml")
    return errors


def sops_recipient_from_config(text: str) -> str | None:
    """Return one canonical public recipient or the exact inert sentinel."""

    significant = [
        line
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected_prefix = [
        "creation_rules:",
        r"  - path_regex: ^kubernetes/.+\.sops\.ya?ml$",
        "    encrypted_regex: ^(data|stringData)$",
        "    age:",
    ]
    if significant[:4] != expected_prefix or len(significant) != 5:
        raise STATE.CanonicalYamlError("SOPS configuration is outside the closed contract")
    recipient_line = significant[4]
    prefix = "      - "
    if not recipient_line.startswith(prefix):
        raise STATE.CanonicalYamlError("SOPS recipient is outside the closed contract")
    recipient = recipient_line[len(prefix):]
    if recipient == INVALID_AGE_RECIPIENT:
        return None
    if AGE_RECIPIENT_RE.fullmatch(recipient) is None:
        raise STATE.CanonicalYamlError("SOPS recipient is outside the closed contract")
    return recipient


def _load_sops_recipient(root: Path) -> str | None:
    """Read and classify the repository's canonical SOPS configuration."""

    return sops_recipient_from_config(
        STATE._read_canonical_text(root / SOPS_CONFIG)
    )


def _cloudflare_secret_is_listed(root: Path) -> bool:
    """Return whether the exact release inventory includes the encrypted Secret."""

    text = STATE._read_canonical_text(root / CLOUDFLARE_RELEASE_KUSTOMIZATION)
    significant = [
        line
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("#")
    ]
    base = [
        "apiVersion: kustomize.config.k8s.io/v1beta1",
        "kind: Kustomization",
        "resources:",
        "  - source.yaml",
        "  - release.yaml",
    ]
    if significant == base:
        return False
    if significant == base + ["  - tunnel-token.sops.yaml"]:
        return True
    raise STATE.CanonicalYamlError(
        "public release Kustomization is outside the closed resource inventory"
    )


def cloudflare_secret_state(root: Path = ROOT) -> str:
    """Return absent/configured only for one exact SOPS Secret lifecycle."""

    root = root.resolve()
    recipient = _load_sops_recipient(root)
    listed = _cloudflare_secret_is_listed(root)
    secret_path = root / CLOUDFLARE_TUNNEL_SECRET
    present = secret_path.exists() or secret_path.is_symlink()
    if not listed and not present:
        return "absent"
    if listed != present:
        raise STATE.CanonicalYamlError(
            "encrypted tunnel Secret presence and resource listing disagree"
        )
    if recipient is None:
        raise STATE.CanonicalYamlError(
            "encrypted tunnel Secret requires a configured SOPS recipient"
        )
    secret_text = STATE._read_canonical_text(secret_path)
    if tunnel_secret_errors(secret_text, recipient):
        raise STATE.CanonicalYamlError(
            "encrypted tunnel Secret is outside the closed production contract"
        )
    return "configured"


def _top_level_resource_blocks(source: str):
    """Return exact top-level resource identities and their canonical blocks."""

    candidate_count = len(re.findall(r'(?m)^\s*resource\s+"', source))
    header = re.compile(
        r'(?m)^resource "([a-z0-9_]+)" "([A-Za-z0-9_]+)" \{$'
    )
    blocks = []
    for match in header.finditer(source):
        closing = re.search(r"(?m)^}\s*$", source[match.end():])
        if closing is None:
            raise STATE.CanonicalYamlError(
                "Cloudflare resource block is not canonically terminated"
            )
        block_end = match.end() + closing.end()
        blocks.append(((match.group(1), match.group(2)), source[match.start():block_end]))
    if candidate_count != len(blocks):
        raise STATE.CanonicalYamlError(
            "Cloudflare resource headers are outside the closed grammar"
        )
    return blocks


def _require_cloudflare_phase_contract(root: Path) -> None:
    """Prove seven closed roots with exact false-by-default phase guards."""

    all_resource_identities = []
    reference_lock = None
    for phase, contract in CLOUDFLARE_PHASE_CONTRACTS.items():
        phase_root = root / CLOUDFLARE_PHASES_ROOT / phase
        if phase_root.is_symlink() or not phase_root.is_dir():
            raise STATE.CanonicalYamlError(
                "Cloudflare phase root is missing or symbolic"
            )

        expected_files = set(contract["source_files"]) | {
            ".terraform.lock.hcl", "terraform.tfvars.example",
        }
        observed_files = {
            path.name
            for path in phase_root.iterdir()
            if path.is_file() or path.is_symlink()
        }
        if observed_files != expected_files:
            raise STATE.CanonicalYamlError(
                "Cloudflare phase file inventory is outside the closed contract"
            )
        for name in expected_files:
            path = phase_root / name
            if path.is_symlink() or not path.is_file():
                raise STATE.CanonicalYamlError(
                    "Cloudflare phase file is missing or symbolic"
                )

        guard = str(contract["guard"])
        variables = STATE._read_canonical_text(phase_root / "variables.tf")
        guard_candidates = re.findall(
            r'(?m)^\s*variable\s+"{}"\s*\{{'.format(re.escape(guard)),
            variables,
        )
        guard_match = re.search(
            r'(?ms)^variable "{}" \{{\n(.*?)^}}\s*$'.format(re.escape(guard)),
            variables,
        )
        if len(guard_candidates) != 1 or guard_match is None:
            raise STATE.CanonicalYamlError(
                "Cloudflare phase guard is outside the closed grammar"
            )
        guard_block = guard_match.group(1)
        if (
            len(re.findall(r"(?m)^\s+type\s*=\s*bool\s*$", guard_block)) != 1
            or len(re.findall(r"(?m)^\s+default\s*=", guard_block)) != 1
            or re.search(r"(?m)^\s+default\s*=\s*false\s*$", guard_block) is None
        ):
            raise STATE.CanonicalYamlError(
                "Cloudflare phase guard must be one false-by-default boolean"
            )

        phase_resources = []
        for source_name in sorted(contract["source_files"]):
            source = STATE._read_canonical_text(phase_root / source_name)
            if re.search(
                r'(?m)^\s*(?:data|module|import|removed|moved)\s+(?:"|\{)',
                source,
            ) or re.search(r'(?m)^\s*provisioner\s+"', source):
                raise STATE.CanonicalYamlError(
                    "Cloudflare phase contains a forbidden dynamic block"
                )
            if re.search(
                r"(?im)^\s*(?:api_token|api_key|api_email|user_service_key)\s*=",
                source,
            ):
                raise STATE.CanonicalYamlError(
                    "Cloudflare provider credential must not enter Terraform source"
                )
            for identity, block in _top_level_resource_blocks(source):
                phase_resources.append(identity)
                if (
                    len(re.findall(r"(?m)^\s+prevent_destroy\s*=\s*true\s*$", block))
                    != 1
                    or len(re.findall(
                        r"(?m)^\s+condition\s*=\s*var\.{}\s*$".format(
                            re.escape(guard)
                        ),
                        block,
                    )) != 1
                    or re.search(r"(?m)^\s{2}(?:count|for_each)\s*=", block)
                ):
                    raise STATE.CanonicalYamlError(
                        "Cloudflare resource phase guard or lifecycle is unsafe"
                    )

        expected_resources = contract["resources"]
        if (
            frozenset(phase_resources) != expected_resources
            or len(phase_resources) != len(expected_resources)
        ):
            raise STATE.CanonicalYamlError(
                "Cloudflare phase resource identity inventory is unsafe"
            )
        all_resource_identities.extend(phase_resources)

        site = CLOUDFLARE_SITE_PHASES.get(phase)
        if site is not None:
            _require_site_root_isolation(phase_root, contract, site)

        versions = STATE._read_canonical_text(phase_root / "versions.tf")
        version_fragments = (
            'required_version = "= {}"'.format(CLOUDFLARE_TOFU_VERSION),
            'source  = "cloudflare/cloudflare"',
            'version = "{}"'.format(CLOUDFLARE_PROVIDER_VERSION),
            'backend "local" {}',
            'provider "cloudflare" {}',
        )
        if any(versions.count(fragment) != 1 for fragment in version_fragments):
            raise STATE.CanonicalYamlError(
                "Cloudflare phase tool, provider, or backend contract is unsafe"
            )
        if (
            len(re.findall(r'(?m)^\s*provider\s+"', versions)) != 1
            or len(re.findall(r'(?m)^\s*backend\s+"', versions)) != 1
        ):
            raise STATE.CanonicalYamlError(
                "Cloudflare phase provider/backend inventory is unsafe"
            )

        example = STATE._read_canonical_text(
            phase_root / "terraform.tfvars.example"
        )
        if len(re.findall(
            r"(?m)^{}\s*=\s*false\s*$".format(re.escape(guard)), example
        )) != 1:
            raise STATE.CanonicalYamlError(
                "Cloudflare phase example must preserve its exact guard as false"
            )

        lock_text = STATE._read_canonical_text(
            phase_root / ".terraform.lock.hcl"
        )
        if (
            lock_text.count(
                'provider "registry.opentofu.org/cloudflare/cloudflare" {'
            ) != 1
            or lock_text.count(
                'version     = "{}"'.format(CLOUDFLARE_PROVIDER_VERSION)
            ) != 1
            or lock_text.count(
                'constraints = "{}"'.format(CLOUDFLARE_PROVIDER_VERSION)
            ) != 1
            or not re.search(r'(?m)^\s+"h1:[A-Za-z0-9+/=]+",$', lock_text)
            or not re.search(r'(?m)^\s+"zh:[0-9a-f]{64}",$', lock_text)
        ):
            raise STATE.CanonicalYamlError(
                "Cloudflare provider lock is incomplete or unsafe"
            )
        if reference_lock is None:
            reference_lock = lock_text
        elif lock_text != reference_lock:
            raise STATE.CanonicalYamlError(
                "Cloudflare phase provider locks must be byte-identical"
            )

    if (
        frozenset(all_resource_identities) != CLOUDFLARE_RESOURCE_IDENTITIES
        or len(all_resource_identities) != len(CLOUDFLARE_RESOURCE_IDENTITIES)
    ):
        raise STATE.CanonicalYamlError(
            "Cloudflare resource identity inventory is outside the closed contract"
        )

    tunnels = [
        identity for identity in all_resource_identities
        if identity[0] == CLOUDFLARE_TUNNEL_CONNECTOR_RESOURCE_TYPE
    ]
    public_tunnels = [
        identity for identity in tunnels
        if identity[1] != "pi_admin"
    ]
    if (
        len(tunnels)
        != CLOUDFLARE_ADMIN_TUNNEL_COUNT + CLOUDFLARE_PUBLIC_TUNNEL_COUNT
        or len(public_tunnels) != CLOUDFLARE_PUBLIC_TUNNEL_COUNT
        or len(frozenset(public_tunnels)) != CLOUDFLARE_PUBLIC_TUNNEL_COUNT
        or len(CLOUDFLARE_SITE_PHASES) != CLOUDFLARE_PUBLIC_TUNNEL_COUNT
    ):
        raise STATE.CanonicalYamlError(
            "Cloudflare public Tunnel inventory is not exactly one per website"
        )


def _require_site_root_isolation(phase_root: Path, contract, site) -> None:
    """Prove one site root owns one Tunnel and never reaches the other site."""

    tunnel_names = [
        name for kind, name in contract["resources"]
        if kind == CLOUDFLARE_TUNNEL_CONNECTOR_RESOURCE_TYPE
    ]
    if len(tunnel_names) != 1:
        raise STATE.CanonicalYamlError(
            "a website root must declare exactly one public Tunnel"
        )
    declaration = '  name       = "{}"\n'.format(site["tunnel_name"])
    main_source = STATE._read_canonical_text(phase_root / "main.tf")
    if main_source.count(declaration) != 1:
        raise STATE.CanonicalYamlError(
            "website Tunnel name is outside its exact site identity tuple"
        )
    for name in sorted(set(contract["source_files"]) | {"terraform.tfvars.example"}):
        if site["foreign_marker"] in STATE._read_canonical_text(phase_root / name):
            raise STATE.CanonicalYamlError(
                "a website root must never reference the other website"
            )


def cloudflare_phase_contract_errors(root: Path = ROOT) -> list[str]:
    """Return one fail-closed error instead of exposing parser distinctions."""

    try:
        _require_cloudflare_phase_contract(root.resolve())
    except (STATE.CanonicalYamlError, OSError, UnicodeError):
        return ["Cloudflare Terraform phase contract is unavailable or unsafe"]
    return []


def _website_phase(name: str, root: Path, parent_suspended: bool) -> str:
    """Classify one site while preserving deterministic gate ordering.

    An active HelmRelease requires an active parent. A suspended HelmRelease
    may safely sit below either parent state: that is the required intermediate
    while rollback suspends the inner controller before its parent, and while
    resume reactivates the parent before the inner controller.
    """

    release = STATE.load_helm_release(name, root)
    if not release.suspended and parent_suspended:
        raise STATE.CanonicalYamlError(
            "active website release requires an active parent"
        )

    ready = STATE._bool_scalar(str(release.values[("deploymentReady",)]))
    digest = str(release.values[("image", "digest")])
    promoted = digest != STATE.ZERO_DIGEST

    if release.suspended and not ready and not promoted:
        return "initial"
    if release.suspended and ready and promoted:
        return "staged"
    if not release.suspended and ready and promoted:
        return "active"
    raise STATE.CanonicalYamlError("website readiness state is unsafe")


def _cloudflare_phase(root: Path, platform_suspended: bool) -> str:
    """Classify the connector while allowing its parent to serve sites first."""

    release = STATE.load_helm_release("cloudflare-public", root)
    token_revision = str(release.values[("tunnel", "tokenRevision")])
    configured = token_revision not in {"not-configured", "UNRESOLVED"}
    secret_state = cloudflare_secret_state(root)

    if release.suspended and not configured and secret_state == "absent":
        return "initial"
    if release.suspended and configured and secret_state == "configured":
        return "staged"
    if (
        not release.suspended
        and configured
        and secret_state == "configured"
        and not platform_suspended
    ):
        return "active"
    raise STATE.CanonicalYamlError("cloudflare release state is unsafe")


def classify(root: Path = ROOT) -> TransitionPlan:
    """Return scaffold, transition, or release for one exact safe state."""

    root = root.resolve()
    _require_cloudflare_phase_contract(root)
    admission_suspended = load_admission_suspension(root)
    platform_suspended = STATE.load_parent_suspension("cloudflare-public", root)
    naranjo_parent_suspended = STATE.load_parent_suspension(
        "naranjo-online", root
    )
    lidersea_parent_suspended = STATE.load_parent_suspension(
        "lidersea-com", root
    )
    naranjo_phase = _website_phase(
        "naranjo-online", root, naranjo_parent_suspended
    )
    lidersea_phase = _website_phase(
        "lidersea-com", root, lidersea_parent_suspended
    )
    cloudflare_phase = _cloudflare_phase(root, platform_suspended)

    any_website_release_active = "active" in (naranjo_phase, lidersea_phase)
    if not platform_suspended and admission_suspended:
        raise STATE.CanonicalYamlError("active platform requires active admission")
    if any_website_release_active and (admission_suspended or platform_suspended):
        raise STATE.CanonicalYamlError(
            "active website requires active admission and platform services"
        )

    if (
        naranjo_phase == "initial"
        and lidersea_phase == "initial"
        and cloudflare_phase == "initial"
        and admission_suspended
        and platform_suspended
        and naranjo_parent_suspended
        and lidersea_parent_suspended
    ):
        mode = "scaffold"
    elif (
        naranjo_phase == "active"
        and lidersea_phase == "active"
        and cloudflare_phase == "active"
        and not admission_suspended
        and not platform_suspended
    ):
        mode = "release"
    else:
        mode = "transition"

    return TransitionPlan(
        mode,
        naranjo_phase,
        lidersea_phase,
        cloudflare_phase,
        admission_suspended,
        platform_suspended,
        naranjo_parent_suspended,
        lidersea_parent_suspended,
    )


def _print_plan(plan: TransitionPlan) -> None:
    """Emit a fixed, non-executable record for the Bash renderer."""

    print("mode={}".format(plan.mode))
    print("naranjo-online={}".format(plan.naranjo_online))
    print("lidersea-com={}".format(plan.lidersea_com))
    print("cloudflare-public={}".format(plan.cloudflare_public))
    print(
        "any-website-active={}".format(
            "true" if plan.any_website_active else "false"
        )
    )
    print(
        "any-workload-active={}".format(
            "true" if plan.any_workload_active else "false"
        )
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("select-mode")
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument(
        "--expect-mode", required=True, choices=("scaffold", "transition", "release")
    )
    args = parser.parse_args(argv)

    try:
        plan = classify(args.root)
        if args.command == "select-mode":
            print(plan.mode)
        elif plan.mode != args.expect_mode:
            raise STATE.CanonicalYamlError("release mode changed between checks")
        else:
            _print_plan(plan)
    except (STATE.CanonicalYamlError, OSError, RuntimeError, UnicodeError):
        print(
            "ERROR release transition state is unavailable or unsafe",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
