#!/usr/bin/env python3
"""Classify only safe, canonical GitOps release transitions.

This module deliberately builds on ``validate_release_state.py``'s closed YAML
grammar.  It adds the cross-release dependency rules needed by CI without
turning the release-state parser into a general YAML loader.
"""

from __future__ import annotations

import argparse
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
CLOUDFLARE_VARIABLES = Path("infrastructure/cloudflare/variables.tf")
CLOUDFLARE_LOCALS = Path("infrastructure/cloudflare/locals.tf")
CLOUDFLARE_TERRAFORM_SOURCE_FILES = frozenset({
    Path("infrastructure/cloudflare/dns.tf"),
    Path("infrastructure/cloudflare/locals.tf"),
    Path("infrastructure/cloudflare/outputs.tf"),
    Path("infrastructure/cloudflare/private-routing.tf"),
    Path("infrastructure/cloudflare/providers.tf"),
    Path("infrastructure/cloudflare/security.tf"),
    Path("infrastructure/cloudflare/tunnels.tf"),
    Path("infrastructure/cloudflare/variables.tf"),
    Path("infrastructure/cloudflare/versions.tf"),
    Path("infrastructure/cloudflare/zero-trust.tf"),
})
CLOUDFLARE_RESOURCE_IDENTITIES = frozenset({
    ("cloudflare_dns_record", "lidersea_com"),
    ("cloudflare_dns_record", "naranjo_online"),
    ("cloudflare_zero_trust_gateway_policy", "pi_admin_allow"),
    ("cloudflare_zero_trust_gateway_policy", "pi_admin_block"),
    ("cloudflare_zero_trust_tunnel_cloudflared", "pi_admin"),
    ("cloudflare_zero_trust_tunnel_cloudflared", "pi_websites"),
    ("cloudflare_zero_trust_tunnel_cloudflared_config", "pi_websites"),
    ("cloudflare_zero_trust_tunnel_cloudflared_route", "pi_admin"),
})
SOPS_CONFIG = Path(".sops.yaml")
AGE_RECIPIENT_RE = re.compile(r"age1[0-9a-z]+\Z")
INVALID_AGE_RECIPIENT = "age1REPLACE_WITH_PUBLIC_RECIPIENT_BEFORE_ENCRYPTING"


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
    flow_secret = any(
        line.lstrip().startswith("{") and _FLOW_SECRET_KIND.search(line)
        for line in top_level
    )
    secret_like = bool(secret_lines or flow_secret)
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
    """Validate fail-closed ciphertext and SOPS metadata without permissive YAML."""

    errors = []
    for document in re.split(r"(?m)^---\s*$", text):
        secret_like, canonical_kind = _secret_kind_state(document)
        if not secret_like:
            continue
        if not canonical_kind:
            errors.append("Secret kind must use one canonical top-level 'kind: Secret' line")
        for line in _top_level_yaml_lines(document):
            if not re.match(r"^[A-Za-z][A-Za-z0-9]*:\s*.*$", line):
                errors.append("Secret top-level keys must use canonical block spelling")
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
                    errors.append(
                        "plaintext or malformed value beneath {}".format(
                            mapping.group(2)
                        )
                    )
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


def direct_mapping_entries(document: str, mapping_name: str) -> dict[str, str]:
    """Return direct scalar entries while callers separately reject duplicates."""

    return dict(_direct_mapping_items(document, mapping_name))


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
    data_mapping = "data" if "data" in top_level else "stringData"
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


def _load_sops_recipient(root: Path) -> str | None:
    """Return one configured public recipient or the exact inert sentinel."""

    text = STATE._read_canonical_text(root / SOPS_CONFIG)
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


def _require_cloudflare_resources_default_off(root: Path) -> None:
    """Prove the exact tracked OpenTofu inventory is gated off by one switch."""

    text = STATE._read_canonical_text(root / CLOUDFLARE_VARIABLES)
    significant = [
        line
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith(("#", "//"))
    ]
    expected = [
        'variable "enable_cloudflare_resources" {',
        '  description = "Fail-closed switch. Set true only for an audited local plan."',
        "  type        = bool",
        "  default     = false",
        "}",
    ]
    headers = [
        line
        for line in significant
        if re.fullmatch(
            r'\s*variable\s+"enable_cloudflare_resources"\s*\{\s*', line
        )
    ]
    if significant[:5] != expected or len(headers) != 1:
        raise STATE.CanonicalYamlError(
            "Cloudflare resource switch is outside the fail-closed contract"
        )

    locals_text = STATE._read_canonical_text(root / CLOUDFLARE_LOCALS)
    locals_significant = [
        line
        for line in locals_text.split("\n")
        if line.strip() and not line.lstrip().startswith(("#", "//"))
    ]
    if locals_significant != [
        "locals {",
        "  enabled = var.enable_cloudflare_resources ? 1 : 0",
        "}",
    ]:
        raise STATE.CanonicalYamlError(
            "Cloudflare local enable switch is outside the fail-closed contract"
        )

    resource_identities = []
    locals_block_count = 0
    resource_candidate_count = 0
    header_pattern = re.compile(
        r'^resource "([a-z0-9_]+)" "([A-Za-z0-9_]+)" \{$'
    )
    for relative_path in sorted(CLOUDFLARE_TERRAFORM_SOURCE_FILES):
        source = STATE._read_canonical_text(root / relative_path)
        locals_block_count += len(
            re.findall(r"(?m)^\s*locals\s*\{", source)
        )
        resource_candidate_count += len(
            re.findall(r'(?m)^\s*resource\s+"', source)
        )
        source_significant = [
            line
            for line in source.split("\n")
            if line.strip() and not line.lstrip().startswith(("#", "//"))
        ]
        for index, line in enumerate(source_significant):
            match = header_pattern.fullmatch(line)
            if match is None:
                continue
            resource_identities.append((match.group(1), match.group(2)))
            if (
                index + 1 >= len(source_significant)
                or source_significant[index + 1] != "  count = local.enabled"
            ):
                raise STATE.CanonicalYamlError(
                    "every Cloudflare resource must be directly gated by local.enabled"
                )
    if locals_block_count != 1:
        raise STATE.CanonicalYamlError(
            "Cloudflare Terraform must contain one exact locals block"
        )
    if resource_candidate_count != len(resource_identities):
        raise STATE.CanonicalYamlError(
            "Cloudflare resource headers are outside the closed grammar"
        )
    if frozenset(resource_identities) != CLOUDFLARE_RESOURCE_IDENTITIES or (
        len(resource_identities) != len(CLOUDFLARE_RESOURCE_IDENTITIES)
    ):
        raise STATE.CanonicalYamlError(
            "Cloudflare resource identity inventory is outside the closed contract"
        )


def cloudflare_default_off_errors(root: Path = ROOT) -> list[str]:
    """Return one fail-closed error instead of exposing parser distinctions."""

    try:
        _require_cloudflare_resources_default_off(root.resolve())
    except (STATE.CanonicalYamlError, OSError, UnicodeError):
        return ["Cloudflare Terraform default-off contract is unavailable or unsafe"]
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
    _require_cloudflare_resources_default_off(root)
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
