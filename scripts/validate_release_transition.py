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
CLOUDFLARE_RELEASE_KUSTOMIZATION = Path(
    "kubernetes/platform/cloudflare-public/release/kustomization.yaml"
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
    platform_suspended: bool
    naranjo_parent_suspended: bool
    lidersea_parent_suspended: bool

    @property
    def any_website_active(self) -> bool:
        """Keep production controls while a site is live or directly selected.

        The #189 topology has no suspendable aggregate parent: both direct site
        Kustomizations always select their exact website paths. A staged
        HelmRelease therefore still sits inside an active reconciliation and
        keeps the website signature/capacity envelope mandatory.
        """

        return (
            "active" in (self.naranjo_online, self.lidersea_com)
            or not self.naranjo_parent_suspended
            or not self.lidersea_parent_suspended
        )

    @property
    def any_workload_active(self) -> bool:
        return (
            self.any_website_active
            or self.cloudflare_public == "active"
            or not self.platform_suspended
        )


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


def _require_secretless_public_release(root: Path) -> None:
    """Prove the public release inventory carries no Secret of any kind.

    The repository holds no secrets: the connector's Tunnel token is created on
    the cluster by an owner ceremony (AGENTS.md safety invariant 7).  Pinning
    this Kustomization to its exact two resources is what stops a Secret — or a
    file that merely renders one — from being re-listed here.
    """

    text = STATE._read_canonical_text(root / CLOUDFLARE_RELEASE_KUSTOMIZATION)
    significant = [
        line
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if significant != [
        "apiVersion: kustomize.config.k8s.io/v1beta1",
        "kind: Kustomization",
        "resources:",
        "  - source.yaml",
        "  - release.yaml",
    ]:
        raise STATE.CanonicalYamlError(
            "public release Kustomization is outside the closed resource inventory"
        )


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
    """Prove six closed roots with exact false-by-default phase guards."""

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

    return "staged" if release.suspended else "active"


def _cloudflare_phase(root: Path, platform_suspended: bool) -> str:
    """Classify the connector while allowing its parent to serve sites first."""

    release = STATE.load_helm_release("cloudflare-public", root)
    # Each website's connector owns its own revision. A half-configured pair is
    # not a safe intermediate — it would mean one Tunnel was staged while the
    # other still carries a sentinel — so it fails closed rather than being
    # classified.
    configured_flags = {
        str(release.values[("connectors", site, "tokenRevision")])
        not in {"not-configured", "UNRESOLVED"}
        for site in STATE.PUBLIC_CONNECTOR_SITES
    }
    if len(configured_flags) != 1:
        raise STATE.CanonicalYamlError(
            "connector token revisions must be uniformly configured"
        )
    configured = configured_flags.pop()
    _require_secretless_public_release(root)

    if release.suspended and not configured:
        return "initial"
    if release.suspended and configured:
        return "staged"
    if not release.suspended and configured and not platform_suspended:
        return "active"
    raise STATE.CanonicalYamlError("cloudflare release state is unsafe")


def classify(root: Path = ROOT) -> TransitionPlan:
    """Return scaffold, transition, or release for one exact safe state."""

    root = root.resolve()
    _require_cloudflare_phase_contract(root)
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

    # The direct website loop is independent of any retired admission-controller
    # premise.

    if (
        naranjo_phase == "staged"
        and lidersea_phase == "staged"
        and cloudflare_phase == "initial"
        and platform_suspended
        and naranjo_parent_suspended
        and lidersea_parent_suspended
    ):
        mode = "scaffold"
    elif (
        naranjo_phase == "active"
        and lidersea_phase == "active"
        and cloudflare_phase == "active"
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
        "platform-services-suspended={}".format(
            "true" if plan.platform_suspended else "false"
        )
    )
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
