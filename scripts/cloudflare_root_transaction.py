#!/usr/bin/env python3
"""Fail-closed root transaction for the owner-only pie5 Cloudflare admin path.

The fixed macOS launcher extracts this exact reviewed blob from a monotonic
protected-main bundle.  This program never trusts a mutable checkout and never
prints tokens, Cloudflare identifiers, email addresses, IP addresses, plan
JSON, state, or raw API responses.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn


STATE_ROOT = Path("/private/var/db/website-infrastructure/cloudflare")
TOOL_BIN = Path("/usr/local/libexec/website-infrastructure/cloudflare-bin")
CONTEXT_PATH = STATE_ROOT / "context.json"
AUDIT_TOKEN_PATH = STATE_ROOT / "audit-token"
CA_CERTIFICATE_PATH = STATE_ROOT / "owner-device-ca.pem"
CONFIGURATION_RECEIPT_PATH = STATE_ROOT / "configuration-receipt.json"
RESULTS_ROOT = STATE_ROOT / "results"
PHASES_ROOT = STATE_ROOT / "phases"
PENDING_ROOT = STATE_ROOT / "pending"

PHASES = (
    "admin-certificate",
    "admin-enrollment-policy",
    "admin-enrollment-app",
    "admin-device",
    "admin-tunnel",
    "admin-policies",
    "admin-route",
)

PRE_AUDIT_PHASE = {
    "admin-certificate": "preflight",
    "admin-enrollment-policy": "admin-certificate",
    "admin-enrollment-app": "admin-enrollment-policy",
    "admin-device": "admin-enrollment-app",
    "admin-tunnel": "admin-device",
    "admin-policies": "admin-tunnel",
    "admin-route": "admin-policies",
}

EXPECTED_ADDRESSES = {
    "admin-certificate": ("cloudflare_mtls_certificate.pi_admin_owner_ca",),
    "admin-enrollment-policy": (
        "cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment",
    ),
    "admin-enrollment-app": (
        "cloudflare_zero_trust_access_application.pi_admin_owner_enrollment",
    ),
    "admin-device": (
        "cloudflare_zero_trust_device_custom_profile.pi_admin_owner",
        "cloudflare_zero_trust_device_posture_rule.pi_admin_owner_certificate",
    ),
    "admin-tunnel": ("cloudflare_zero_trust_tunnel_cloudflared.pi_admin",),
    "admin-policies": (
        "cloudflare_zero_trust_gateway_policy.pi_admin_block",
        "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow",
    ),
    "admin-route": (
        "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin",
    ),
}

CONTRACT_KEYS = {
    "admin-certificate": ("admin_certificate_contract_sha256",),
    "admin-enrollment-policy": ("admin_enrollment_policy_contract_sha256",),
    "admin-enrollment-app": ("admin_enrollment_contract_sha256",),
    "admin-device": ("admin_device_contract_sha256",),
    "admin-tunnel": (
        "admin_tunnel_contract_sha256",
        "admin_policy_inputs_contract_sha256",
    ),
    "admin-policies": ("admin_policies_contract_sha256",),
    "admin-route": ("admin_route_contract_sha256",),
}

ACTIVATION_KEYS = {
    "admin-certificate": ("pi_admin_certificate_activation_state",),
    "admin-enrollment-policy": (
        "pi_admin_enrollment_policy_activation_state",
    ),
    "admin-enrollment-app": ("pi_admin_enrollment_app_activation_state",),
    "admin-device": (
        "pi_admin_device_posture_activation_state",
        "pi_admin_device_profile_activation_state",
    ),
}

AUDIT_PERMISSION_SCOPES = {
    "API Tokens Read": "com.cloudflare.api.user",
    "Account Settings Read": "com.cloudflare.api.account",
    "Billing Read": "com.cloudflare.api.account",
    "Account: SSL and Certificates Read": "com.cloudflare.api.account",
    "Cloudflare One Connector: cloudflared Read": "com.cloudflare.api.account",
    "Cloudflare One Networks Read": "com.cloudflare.api.account",
    "Zero Trust Read": "com.cloudflare.api.account",
    "Access: Apps and Policies Read": "com.cloudflare.api.account",
    "Access: Audit Logs Read": "com.cloudflare.api.account",
    "Access: Organizations, Identity Providers, and Groups Read": (
        "com.cloudflare.api.account"
    ),
    "Zone Read": "com.cloudflare.api.account.zone",
    "DNS Read": "com.cloudflare.api.account.zone",
}

JIT_PERMISSION_NAMES = {
    "admin-certificate": "Account: SSL and Certificates Write",
    "admin-enrollment-policy": "Access: Apps and Policies Write",
    "admin-enrollment-app": "Access: Apps and Policies Write",
    "admin-device": "Zero Trust Write",
    "admin-tunnel": "Cloudflare One Connector: cloudflared Write",
    "admin-policies": "Zero Trust Write",
    "admin-route": "Cloudflare One Networks Write",
}

ID_KEY_BY_ADDRESS = {
    "cloudflare_mtls_certificate.pi_admin_owner_ca": "certificate_id",
    "cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment": (
        "enrollment_policy_id"
    ),
    "cloudflare_zero_trust_access_application.pi_admin_owner_enrollment": (
        "enrollment_application_id"
    ),
    "cloudflare_zero_trust_device_custom_profile.pi_admin_owner": (
        "device_profile_id"
    ),
    "cloudflare_zero_trust_device_posture_rule.pi_admin_owner_certificate": (
        "device_posture_id"
    ),
    "cloudflare_zero_trust_tunnel_cloudflared.pi_admin": "tunnel_id",
    "cloudflare_zero_trust_gateway_policy.pi_admin_block": "block_policy_id",
    "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow": (
        "ssh_policy_id"
    ),
    "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin": "route_id",
}

TOKEN_RE = re.compile(
    r"(?:[A-Za-z0-9_-]{40}|(?:cfk_|cfut_|cfat_)[A-Za-z0-9]{40}[0-9A-Fa-f]{8})"
)
HEX32_RE = re.compile(r"[0-9a-f]{32}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class TransactionError(RuntimeError):
    pass


class APIError(TransactionError):
    def __init__(self, status: int, body: bytes):
        super().__init__(f"Cloudflare API request failed with status {status}")
        self.status = status
        self.body = body


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def fail(message: str) -> NoReturn:
    raise TransactionError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def utc_text(value: dt.datetime | None = None) -> str:
    selected = value or utc_now()
    return selected.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_utc(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} is not a canonical UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TransactionError(f"{label} is not a valid timestamp") from error
    if parsed.tzinfo is None:
        fail(f"{label} is missing a timezone")
    return parsed.astimezone(dt.timezone.utc)


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} does not have the exact reviewed schema")
    return value


def valid_hex32_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and HEX32_RE.fullmatch(value) is not None
        and set(value) != {"0"}
    )


def validate_regular_file(
    path: Path,
    *,
    modes: set[int] = {0o400, 0o600},
    owner: int = 0,
    max_size: int = 5 * 1024 * 1024,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise TransactionError(f"required protected file is unavailable: {path.name}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail(f"protected input is not one regular non-symlink file: {path.name}")
    if metadata.st_uid != owner or metadata.st_nlink != 1:
        fail(f"protected input ownership/link count is unsafe: {path.name}")
    if stat.S_IMODE(metadata.st_mode) not in modes:
        fail(f"protected input mode is unsafe: {path.name}")
    if metadata.st_size <= 0 or metadata.st_size > max_size:
        fail(f"protected input size is outside the reviewed bound: {path.name}")
    return metadata


def stable_read(path: Path, *, max_size: int = 5 * 1024 * 1024) -> bytes:
    before = validate_regular_file(path, max_size=max_size)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        signature = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
            item.st_uid,
            item.st_gid,
        )
        if signature(opened) != signature(before):
            fail(f"protected input changed while opening: {path.name}")
        chunks: list[bytes] = []
        remaining = max_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining <= 0 and os.read(descriptor, 1):
            fail(f"protected input exceeds the reviewed bound: {path.name}")
        after = os.fstat(descriptor)
        if signature(after) != signature(before):
            fail(f"protected input changed while reading: {path.name}")
    finally:
        os.close(descriptor)
    final = validate_regular_file(path, max_size=max_size)
    if (
        final.st_dev,
        final.st_ino,
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ):
        fail(f"protected input changed after reading: {path.name}")
    return b"".join(chunks)


def ensure_root_directory(path: Path, mode: int = 0o700) -> None:
    if not path.exists():
        path.mkdir(mode=mode)
        os.chown(path, 0, 0)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        fail(f"root custody directory is unsafe: {path.name}")


def ensure_state_tree() -> None:
    ensure_root_directory(STATE_ROOT)
    for path in (RESULTS_ROOT, PHASES_ROOT, PENDING_ROOT):
        ensure_root_directory(path)


def atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    ensure_root_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, 0)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        validate_regular_file(path, modes={mode}, max_size=max(len(payload), 1))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_json_file(path: Path, *, max_size: int = 5 * 1024 * 1024) -> Any:
    raw = stable_read(path, max_size=max_size)
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError(f"protected JSON is malformed: {path.name}") from error


def validate_token_text(raw: bytes, label: str) -> str:
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise TransactionError(f"{label} is not an ASCII token") from error
    if value.endswith("\n"):
        value = value[:-1]
    if not TOKEN_RE.fullmatch(value):
        fail(f"{label} does not match a supported Cloudflare token format")
    return value


def validate_context(
    value: Any,
    certificate_bytes: bytes | None = None,
    *,
    allow_unbound_audit_contract: bool = False,
) -> dict[str, Any]:
    context = exact_keys(
        value,
        {
            "schema",
            "account_id",
            "owner_user_id",
            "zone_ids",
            "admin_email",
            "identity_provider_id",
            "pi_admin_cidr",
            "gateway",
            "jit_permission_group_ids",
            "audit_permission_group_ids",
            "owner_device_ca_certificate_sha256",
            "audit_token_contract_sha256",
        },
        "Cloudflare workstation context",
    )
    if context["schema"] != "pie5-cloudflare-owner-admin-v1":
        fail("Cloudflare workstation context schema is not supported")
    if not valid_hex32_identifier(context["account_id"]):
        fail("context account binding is malformed")
    if not valid_hex32_identifier(context["owner_user_id"]):
        fail("context owner-user binding is malformed")
    zones = exact_keys(
        context["zone_ids"], {"naranjo.online", "lidersea.com"}, "zone binding"
    )
    if any(not valid_hex32_identifier(item) for item in zones.values()):
        fail("context zone binding is malformed")
    if len({context["account_id"], *zones.values()}) != 3:
        fail("account and zone bindings are not distinct")
    if not isinstance(context["admin_email"], str) or not EMAIL_RE.fullmatch(
        context["admin_email"]
    ):
        fail("context owner identity is malformed")
    if not isinstance(context["identity_provider_id"], str) or not UUID_RE.fullmatch(
        context["identity_provider_id"]
    ):
        fail("context identity-provider binding is malformed")
    try:
        network = ipaddress.ip_network(context["pi_admin_cidr"], strict=True)
    except (TypeError, ValueError) as error:
        raise TransactionError("context Pi route is malformed") from error
    if network.version != 4 or network.prefixlen != 32 or not network.is_private:
        fail("context Pi route must be one private IPv4 /32")
    gateway = exact_keys(
        context["gateway"],
        {"ssh_allow_precedence", "block_precedence", "session_freshness"},
        "Gateway contract",
    )
    allow = gateway["ssh_allow_precedence"]
    block = gateway["block_precedence"]
    if not isinstance(allow, int) or isinstance(allow, bool) or allow < 0:
        fail("Gateway SSH precedence is malformed")
    if not isinstance(block, int) or isinstance(block, bool) or block <= allow:
        fail("Gateway final-block precedence must be greater than SSH allow")
    freshness = gateway["session_freshness"]
    if not isinstance(freshness, str) or not re.fullmatch(r"[1-9][0-9]{0,2}s", freshness):
        fail("Gateway freshness is malformed")
    if int(freshness[:-1]) > 900:
        fail("Gateway freshness exceeds 900 seconds")
    groups = exact_keys(
        context["jit_permission_group_ids"], set(PHASES), "JIT permission map"
    )
    if any(not valid_hex32_identifier(item) for item in groups.values()):
        fail("JIT permission-group map is malformed")
    audit_groups = exact_keys(
        context["audit_permission_group_ids"],
        set(AUDIT_PERMISSION_SCOPES),
        "audit permission map",
    )
    if any(
        not valid_hex32_identifier(item)
        for item in audit_groups.values()
    ):
        fail("audit permission-group map is malformed")
    if len(set(groups.values()) | set(audit_groups.values())) != len(
        set(groups.values())
    ) + len(audit_groups):
        fail("read and write permission-group identities overlap")
    for digest_name in (
        "owner_device_ca_certificate_sha256",
        "audit_token_contract_sha256",
    ):
        digest_value = context[digest_name]
        zero_allowed = (
            allow_unbound_audit_contract
            and digest_name == "audit_token_contract_sha256"
        )
        if not isinstance(digest_value, str) or not SHA256_RE.fullmatch(digest_value):
            fail(f"context {digest_name} is malformed")
        if set(digest_value) == {"0"} and not zero_allowed:
            fail(f"context {digest_name} is malformed")
    if certificate_bytes is not None:
        if b"PRIVATE KEY" in certificate_bytes:
            fail("owner-device CA input contains private key material")
        if certificate_bytes.count(b"-----BEGIN CERTIFICATE-----") != 1 or certificate_bytes.count(
            b"-----END CERTIFICATE-----"
        ) != 1:
            fail("owner-device CA input is not exactly one PEM certificate")
        if not 512 <= len(certificate_bytes) <= 16384:
            fail("owner-device CA input size is outside the reviewed bound")
        if sha256_bytes(certificate_bytes) != context["owner_device_ca_certificate_sha256"]:
            fail("owner-device CA input does not match the context digest")
    return context


def load_context() -> dict[str, Any]:
    receipt = exact_keys(
        load_json_file(CONFIGURATION_RECEIPT_PATH, max_size=4096),
        {"schema", "context_sha256", "certificate_sha256"},
        "Cloudflare workstation configuration receipt",
    )
    if receipt["schema"] != "pie5-cloudflare-configuration-v1":
        fail("Cloudflare workstation configuration receipt schema is unsupported")
    if any(
        not isinstance(receipt[key], str) or not SHA256_RE.fullmatch(receipt[key])
        for key in ("context_sha256", "certificate_sha256")
    ):
        fail("Cloudflare workstation configuration receipt digest is malformed")
    context_raw = stable_read(CONTEXT_PATH, max_size=65536)
    certificate = stable_read(CA_CERTIFICATE_PATH, max_size=16384)
    if (
        sha256_bytes(context_raw) != receipt["context_sha256"]
        or sha256_bytes(certificate) != receipt["certificate_sha256"]
    ):
        fail("Cloudflare workstation configuration bytes do not match their receipt")
    try:
        context_json = json.loads(context_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError("protected Cloudflare context is malformed") from error
    return validate_context(context_json, certificate)


def api_request(token: str, path: str) -> dict[str, Any]:
    if not path.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9._~/?&=%:+,-]+", path):
        fail("Cloudflare API path is outside the reviewed GET grammar")
    expected_url = "https://api.cloudflare.com/client/v4" + path
    request = urllib.request.Request(
        expected_url,
        method="GET",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        RejectRedirects(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != expected_url:
                raise APIError(response.status, b"")
            raw = response.read(5 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        body = error.read(65536)
        raise APIError(error.code, body) from error
    except urllib.error.URLError as error:
        raise TransactionError("Cloudflare API transport failed") from error
    if len(raw) > 5 * 1024 * 1024:
        fail("Cloudflare API response exceeded the reviewed size bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError("Cloudflare API returned malformed JSON") from error
    if not isinstance(value, dict):
        fail("Cloudflare API returned an unexpected top-level shape")
    return value


def validate_permission_catalog(token: str, context: dict[str, Any]) -> None:
    response = api_request(token, "/user/tokens/permission_groups")
    items = response.get("result")
    if response.get("success") is not True or not isinstance(items, list):
        fail("Cloudflare permission-group catalog is unavailable")
    by_id: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or not valid_hex32_identifier(item.get("id")):
            fail("Cloudflare permission-group catalog is malformed")
        if item["id"] in by_id:
            fail("Cloudflare permission-group catalog contains a duplicate ID")
        by_id[item["id"]] = item

    expected: list[tuple[str, str, str]] = []
    expected.extend(
        (name, identifier, AUDIT_PERMISSION_SCOPES[name])
        for name, identifier in context["audit_permission_group_ids"].items()
    )
    expected.extend(
        (
            JIT_PERMISSION_NAMES[phase],
            context["jit_permission_group_ids"][phase],
            "com.cloudflare.api.account",
        )
        for phase in PHASES
    )
    seen_names: dict[str, str] = {}
    for name, identifier, scope in expected:
        item = by_id.get(identifier)
        if (
            item is None
            or item.get("name") != name
            or item.get("scopes") != [scope]
        ):
            fail("a configured permission-group ID no longer has its exact reviewed meaning")
        previous = seen_names.setdefault(name, identifier)
        if previous != identifier:
            fail("one permission name is bound to multiple permission-group IDs")


def validate_one_host_condition(
    value: Any, label: str
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    condition = exact_keys(value, {"request_ip"}, f"{label} condition")
    request_ip = condition["request_ip"]
    if not isinstance(request_ip, dict) or set(request_ip) not in (
        {"in"},
        {"in", "not_in"},
    ):
        fail(f"{label} source-IP condition does not have the reviewed schema")
    if (
        request_ip.get("not_in", []) != []
        or not isinstance(request_ip["in"], list)
        or len(request_ip["in"]) != 1
    ):
        fail(f"{label} must have one positive source host and no negative exception")
    try:
        source = ipaddress.ip_network(request_ip["in"][0], strict=True)
    except (TypeError, ValueError) as error:
        raise TransactionError(f"{label} source condition is malformed") from error
    if source.prefixlen not in (32, 128) or not source.is_global:
        fail(f"{label} source condition must be one global IPv4 /32 or IPv6 /128")
    return source


def canonical_token_contract(details: dict[str, Any], context: dict[str, Any]) -> str:
    if details.get("success") is not True or not isinstance(details.get("result"), dict):
        fail("audit-token details are unavailable")
    result = details["result"]
    if result.get("name") != "website-infrastructure-read-only-audit":
        fail("audit token name is not exact")
    now = utc_now()
    issued = parse_utc(result.get("issued_on"), "audit token issued_on")
    not_before = parse_utc(result.get("not_before"), "audit token not_before")
    expires = parse_utc(result.get("expires_on"), "audit token expires_on")
    if issued > now + dt.timedelta(minutes=1):
        fail("audit token issue time is in the future")
    if not_before < issued - dt.timedelta(minutes=1) or not_before > now + dt.timedelta(
        minutes=1
    ):
        fail("audit token not-before time is outside the reviewed window")
    if expires <= now or expires - issued > dt.timedelta(minutes=60):
        fail("audit token is not active within a maximum 60-minute lifetime")
    validate_one_host_condition(result.get("condition"), "audit token")
    policies = result.get("policies")
    if not isinstance(policies, list) or len(policies) != 3:
        fail("audit token must have exactly three scoped allow policies")
    audit_ids = context["audit_permission_group_ids"]
    user_ids = {audit_ids["API Tokens Read"]}
    zone_ids = {audit_ids["Zone Read"], audit_ids["DNS Read"]}
    account_ids = set(audit_ids.values()) - user_ids - zone_ids
    expected_policy_sets = {frozenset(user_ids), frozenset(zone_ids), frozenset(account_ids)}
    observed_policy_sets: set[frozenset[str]] = set()
    normalized_policies: list[dict[str, Any]] = []
    for policy in policies:
        if not isinstance(policy, dict) or set(policy) != {
            "effect",
            "permission_groups",
            "resources",
        }:
            fail("audit-token policy schema changed")
        groups = policy.get("permission_groups")
        resources = policy.get("resources")
        if (
            policy.get("effect") != "allow"
            or not isinstance(groups, list)
            or not groups
            or not isinstance(resources, dict)
        ):
            fail("audit-token permission/resource schema changed")
        group_ids: list[str] = []
        for group in groups:
            if (
                not isinstance(group, dict)
                or set(group) != {"id"}
                or not valid_hex32_identifier(group.get("id"))
            ):
                fail("audit-token permission-group ID is malformed")
            group_ids.append(group["id"])
        group_set = frozenset(group_ids)
        if len(group_ids) != len(group_set) or group_set not in expected_policy_sets:
            fail("audit token permission groups are not the exact reviewed read set")
        if group_set in observed_policy_sets:
            fail("audit token duplicated one scoped permission policy")
        observed_policy_sets.add(group_set)
        if group_set == frozenset(user_ids):
            if len(resources) != 1:
                fail("audit token user-read scope is not exact")
            resource_key, resource_value = next(iter(resources.items()))
            if (
                resource_key
                != f"com.cloudflare.api.user.{context['owner_user_id']}"
                or resource_value != "*"
            ):
                fail("audit token user-read scope is not exact")
        elif group_set == frozenset(zone_ids):
            if resources != {
                f"com.cloudflare.api.account.{context['account_id']}": {
                    "com.cloudflare.api.account.zone.*": "*"
                }
            }:
                fail("audit token zone reads are not all zones in the exact account")
        elif resources != {f"com.cloudflare.api.account.{context['account_id']}": "*"}:
            fail("audit token account reads are not restricted to the exact account")
        normalized_policies.append(
            {
                "effect": "allow",
                "permission_group_ids": sorted(group_ids),
                "resources": resources,
            }
        )
    if observed_policy_sets != expected_policy_sets:
        fail("audit token does not contain every exact scoped read policy")
    normalized = {
        "schema": "cloudflare-audit-token-contract-v1",
        "maximum_lifetime_seconds": 3600,
        "source_scope": "one-global-host",
        "policies": sorted(
            normalized_policies,
            key=lambda item: canonical_json(item),
        ),
    }
    return sha256_bytes(canonical_json(normalized))


def validate_audit_token(
    token: str, context: dict[str, Any], *, enforce_contract: bool = True
) -> str:
    verify = api_request(token, "/user/tokens/verify")
    result = verify.get("result")
    if verify.get("success") is not True or not isinstance(result, dict):
        fail("audit token could not verify itself")
    token_id = result.get("id")
    if not valid_hex32_identifier(token_id):
        fail("audit token ID is malformed")
    if result.get("status") != "active":
        fail("audit token is not active")
    validate_permission_catalog(token, context)
    details = api_request(token, f"/user/tokens/{token_id}")
    detail_result = details.get("result")
    if not isinstance(detail_result, dict) or detail_result.get("id") != token_id:
        fail("audit token details do not match the verified token")
    if detail_result.get("status") != "active":
        fail("audit token details are not active")
    contract = canonical_token_contract(details, context)
    if enforce_contract and contract != context["audit_token_contract_sha256"]:
        fail("audit token live policy/condition contract does not match context")
    return contract


def validate_jit_token(
    *, phase: str, token: str, token_id: str, audit_token: str, context: dict[str, Any]
) -> dict[str, Any]:
    if not valid_hex32_identifier(token_id):
        fail("JIT token ID is malformed")
    verify = api_request(token, "/user/tokens/verify")
    details = api_request(audit_token, f"/user/tokens/{token_id}")
    verify_result = verify.get("result")
    detail_result = details.get("result")
    if (
        verify.get("success") is not True
        or details.get("success") is not True
        or not isinstance(verify_result, dict)
        or not isinstance(detail_result, dict)
    ):
        fail("JIT token verification/details are unavailable")
    if verify_result.get("id") != token_id or detail_result.get("id") != token_id:
        fail("JIT token identity does not match the operator-supplied ID")
    if verify_result.get("status") != "active" or detail_result.get("status") != "active":
        fail("JIT token is not active")
    if detail_result.get("name") != f"website-infrastructure-{phase}-jit":
        fail("JIT token name does not bind the exact phase")
    now = utc_now()
    issued = parse_utc(detail_result.get("issued_on"), "JIT issued_on")
    not_before = parse_utc(detail_result.get("not_before"), "JIT not_before")
    expires = parse_utc(detail_result.get("expires_on"), "JIT expires_on")
    if issued < now - dt.timedelta(minutes=10) or issued > now + dt.timedelta(minutes=1):
        fail("JIT token was not freshly issued")
    if not_before < issued - dt.timedelta(minutes=1) or not_before > now + dt.timedelta(
        minutes=1
    ):
        fail("JIT token not-before time is outside the reviewed window")
    if expires <= now or expires - issued > dt.timedelta(minutes=30):
        fail("JIT token lifetime is not bounded to the next 30 minutes")
    validate_one_host_condition(detail_result.get("condition"), "JIT token")
    policies = detail_result.get("policies")
    if not isinstance(policies, list) or len(policies) != 1:
        fail("JIT token must have exactly one allow policy")
    policy = policies[0]
    if (
        not isinstance(policy, dict)
        or set(policy) != {"effect", "permission_groups", "resources"}
        or policy.get("effect") != "allow"
    ):
        fail("JIT token policy is not one allow")
    groups = policy.get("permission_groups")
    if (
        not isinstance(groups, list)
        or len(groups) != 1
        or not isinstance(groups[0], dict)
        or set(groups[0]) != {"id"}
        or groups[0].get("id") != context["jit_permission_group_ids"][phase]
    ):
        fail("JIT token permission group does not exactly match the phase")
    expected_resources = {f"com.cloudflare.api.account.{context['account_id']}": "*"}
    if policy.get("resources") != expected_resources:
        fail("JIT token resources are not restricted to the selected account")
    return {
        "schema": "cloudflare-jit-preflight-v1",
        "phase": phase,
        "token_id_sha256": sha256_bytes(token_id.encode("ascii")),
        "permission_group_id_sha256": sha256_bytes(
            context["jit_permission_group_ids"][phase].encode("ascii")
        ),
        "source_scope": "one-global-host",
        "issued_on": utc_text(issued),
        "expires_on": utc_text(expires),
        "validated_at": utc_text(now),
    }


def load_result(phase: str) -> dict[str, Any]:
    path = RESULTS_ROOT / f"{phase}.json"
    result = load_json_file(path, max_size=131072)
    expected = {"schema", "phase", "commit", "ids", "contracts", "evidence"}
    parsed = exact_keys(result, expected, f"{phase} result")
    if parsed["schema"] != "pie5-cloudflare-phase-result-v1" or parsed["phase"] != phase:
        fail(f"{phase} result identity is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", str(parsed["commit"])):
        fail(f"{phase} result commit is malformed")
    if not isinstance(parsed["ids"], dict) or not isinstance(parsed["contracts"], dict):
        fail(f"{phase} result payload is malformed")
    expected_id_keys = {
        ID_KEY_BY_ADDRESS[address] for address in EXPECTED_ADDRESSES[phase]
    }
    if set(parsed["ids"]) != expected_id_keys or any(
        not isinstance(identifier, str) or not identifier or len(identifier) > 256
        for identifier in parsed["ids"].values()
    ):
        fail(f"{phase} result resource inventory is malformed")
    if len(set(parsed["ids"].values())) != len(parsed["ids"]):
        fail(f"{phase} result resource identities are not unique")
    if set(parsed["contracts"]) != set(CONTRACT_KEYS[phase]) or any(
        not isinstance(digest, str)
        or not SHA256_RE.fullmatch(digest)
        or set(digest) == {"0"}
        for digest in parsed["contracts"].values()
    ):
        fail(f"{phase} result contract inventory is malformed")
    evidence = exact_keys(
        parsed["evidence"],
        {
            "plan_sha256",
            "pre_audit_sha256",
            "post_audit_sha256",
            "audit_log_receipt_sha256",
            "jit_token_id_sha256",
            "revocation",
            "completed_at",
        },
        f"{phase} result evidence",
    )
    for key in (
        "plan_sha256",
        "pre_audit_sha256",
        "post_audit_sha256",
        "audit_log_receipt_sha256",
        "jit_token_id_sha256",
    ):
        if (
            not isinstance(evidence[key], str)
            or not SHA256_RE.fullmatch(evidence[key])
            or set(evidence[key]) == {"0"}
        ):
            fail(f"{phase} result evidence digest is malformed")
    if len(
        {
            evidence[key]
            for key in (
                "plan_sha256",
                "pre_audit_sha256",
                "post_audit_sha256",
                "audit_log_receipt_sha256",
                "jit_token_id_sha256",
            )
        }
    ) != 5:
        fail(f"{phase} result reuses a digest across distinct evidence")
    if evidence["revocation"] != "bearer-and-metadata-inactive":
        fail(f"{phase} result revocation evidence is malformed")
    parse_utc(evidence["completed_at"], f"{phase} result completion")
    return parsed


def completed_results(before_phase: str | None = None) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for phase in PHASES:
        if before_phase == phase:
            break
        path = RESULTS_ROOT / f"{phase}.json"
        if path.exists():
            output[phase] = load_result(phase)
        elif before_phase is not None:
            fail(f"required predecessor phase is incomplete: {phase}")
    return output


def combined_ids(
    results: dict[str, dict[str, Any]], current_ids: dict[str, str] | None = None
) -> dict[str, str]:
    output: dict[str, str] = {}
    for result in results.values():
        overlap = set(output) & set(result["ids"])
        if overlap:
            fail("completed phases contain overlapping resource identity keys")
        output.update(result["ids"])
    if current_ids:
        if set(output) & set(current_ids):
            fail("current phase overlaps a predecessor resource identity key")
        output.update(current_ids)
    return output


def combined_contracts(results: dict[str, dict[str, Any]]) -> dict[str, str]:
    output: dict[str, str] = {}
    for result in results.values():
        if set(output) & set(result["contracts"]):
            fail("completed phases contain overlapping contract keys")
        output.update(result["contracts"])
    return output


def audit_environment(
    *,
    root: Path,
    audit_phase: str,
    context: dict[str, Any],
    ids: dict[str, str],
) -> dict[str, str]:
    environment = {
        "PATH": f"{TOOL_BIN}:/usr/bin:/bin",
        "HOME": "/var/empty",
        "LC_ALL": "C",
        "REVIEWED_BLOB_LAUNCHER_AVAILABLE": "yes",
        "REVIEWED_BLOB_ROOT": str(root),
        "REVIEWED_BLOB_OPERATION": "cloudflare-audit",
        "CLOUDFLARE_AUDIT_PHASE": audit_phase,
        "CLOUDFLARE_AUDIT_TOKEN_OWNER": "user",
        "CLOUDFLARE_ACCOUNT_ID": context["account_id"],
        "CLOUDFLARE_NARANJO_ONLINE_ZONE_ID": context["zone_ids"]["naranjo.online"],
        "CLOUDFLARE_LIDERSEA_COM_ZONE_ID": context["zone_ids"]["lidersea.com"],
    }
    if audit_phase != "preflight":
        environment.update(
            {
                "CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_ID": ids["certificate_id"],
                "CLOUDFLARE_OWNER_DEVICE_CA_CERTIFICATE_SHA256": context[
                    "owner_device_ca_certificate_sha256"
                ],
            }
        )
    if audit_phase in PHASES[1:]:
        environment.update(
            {
                "CLOUDFLARE_OWNER_ENROLLMENT_POLICY_ID": ids["enrollment_policy_id"],
                "CLOUDFLARE_ADMIN_IDENTITY_PROVIDER_ID": context[
                    "identity_provider_id"
                ],
                "CLOUDFLARE_ADMIN_EMAIL": context["admin_email"],
            }
        )
    if audit_phase in PHASES[2:]:
        environment["CLOUDFLARE_OWNER_ENROLLMENT_APPLICATION_ID"] = ids[
            "enrollment_application_id"
        ]
    if audit_phase in PHASES[3:]:
        environment.update(
            {
                "CLOUDFLARE_PI_ADMIN_CIDR": context["pi_admin_cidr"],
                "CLOUDFLARE_ADMIN_DEVICE_POSTURE_CHECK_ID": ids["device_posture_id"],
                "CLOUDFLARE_ADMIN_DEVICE_PROFILE_ID": ids["device_profile_id"],
                "CLOUDFLARE_PI_ADMIN_SSH_ALLOW_PRECEDENCE": str(
                    context["gateway"]["ssh_allow_precedence"]
                ),
                "CLOUDFLARE_PI_ADMIN_BLOCK_PRECEDENCE": str(
                    context["gateway"]["block_precedence"]
                ),
                "CLOUDFLARE_ADMIN_SESSION_FRESHNESS": context["gateway"][
                    "session_freshness"
                ],
            }
        )
    return environment


def run_command(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int = 900,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TransactionError("reviewed child process could not complete") from error
    if check and result.returncode != 0:
        fail("reviewed child process failed; root-only transaction evidence retains details")
    return result


def parse_audit(raw: bytes, expected_phase: str) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TransactionError("Cloudflare audit output is not UTF-8") from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not re.fullmatch(r"[A-Za-z0-9_.\[\]-]+=[^\r\n]*", line):
            continue
        key, value = line.split("=", 1)
        if key in values:
            fail(f"Cloudflare audit duplicated aggregate key: {key}")
        values[key] = value
    if values.get("audit_phase") != expected_phase or values.get("audit_result") != "pass":
        fail("Cloudflare audit did not produce a unique PASS for the expected phase")
    return values


def run_audit(
    *,
    root: Path,
    audit_phase: str,
    context: dict[str, Any],
    ids: dict[str, str],
    audit_token: str,
    output_path: Path,
) -> dict[str, str]:
    environment = audit_environment(
        root=root, audit_phase=audit_phase, context=context, ids=ids
    )
    environment["CLOUDFLARE_API_TOKEN"] = audit_token
    result = run_command(
        ["/bin/bash", str(root / "scripts/cloudflare-audit.sh")],
        cwd=root,
        environment=environment,
        timeout=600,
    )
    atomic_write(output_path, result.stdout, 0o600)
    return parse_audit(result.stdout, audit_phase)


def build_tfvars(
    phase: str,
    context: dict[str, Any],
    results: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    ids = combined_ids(results)
    contracts = combined_contracts(results)
    variables: dict[str, Any] = {
        "cloudflare_account_id": context["account_id"],
        f"approve_{phase.replace('-', '_')}_phase": True,
    }
    if phase == "admin-certificate":
        variables.update(
            {
                "owner_device_ca_certificate_pem": stable_read(
                    CA_CERTIFICATE_PATH, max_size=16384
                ).decode("ascii"),
                "owner_device_ca_certificate_sha256": context[
                    "owner_device_ca_certificate_sha256"
                ],
            }
        )
    elif phase == "admin-enrollment-policy":
        variables["admin_email"] = context["admin_email"]
    elif phase == "admin-enrollment-app":
        variables.update(
            {
                "owner_enrollment_policy_id": ids["enrollment_policy_id"],
                "admin_identity_provider_id": context["identity_provider_id"],
                "admin_email": context["admin_email"],
                "verified_admin_enrollment_policy_contract_sha256": contracts[
                    "admin_enrollment_policy_contract_sha256"
                ],
            }
        )
    elif phase == "admin-device":
        variables.update(
            {
                "owner_device_ca_certificate_id": ids["certificate_id"],
                "owner_device_ca_certificate_sha256": context[
                    "owner_device_ca_certificate_sha256"
                ],
                "owner_enrollment_policy_id": ids["enrollment_policy_id"],
                "owner_enrollment_application_id": ids["enrollment_application_id"],
                "admin_identity_provider_id": context["identity_provider_id"],
                "verified_admin_certificate_contract_sha256": contracts[
                    "admin_certificate_contract_sha256"
                ],
                "verified_admin_enrollment_contract_sha256": contracts[
                    "admin_enrollment_contract_sha256"
                ],
                "pi_admin_cidr": context["pi_admin_cidr"],
                "admin_email": context["admin_email"],
            }
        )
    elif phase == "admin-tunnel":
        variables.update(
            {
                "verified_admin_enrollment_contract_sha256": contracts[
                    "admin_enrollment_contract_sha256"
                ],
                "verified_admin_device_contract_sha256": contracts[
                    "admin_device_contract_sha256"
                ],
            }
        )
    elif phase in ("admin-policies", "admin-route"):
        variables.update(
            {
                "pi_admin_tunnel_id": ids["tunnel_id"],
                "pi_admin_cidr": context["pi_admin_cidr"],
                "admin_email": context["admin_email"],
                "admin_device_posture_check_id": ids["device_posture_id"],
                "admin_device_profile_id": ids["device_profile_id"],
                "verified_admin_device_contract_sha256": contracts[
                    "admin_device_contract_sha256"
                ],
                "verified_admin_enrollment_contract_sha256": contracts[
                    "admin_enrollment_contract_sha256"
                ],
                "pi_admin_ssh_allow_precedence": context["gateway"][
                    "ssh_allow_precedence"
                ],
                "pi_admin_block_precedence": context["gateway"]["block_precedence"],
                "admin_session_freshness": context["gateway"]["session_freshness"],
            }
        )
        if phase == "admin-policies":
            variables.update(
                {
                    "verified_admin_tunnel_contract_sha256": contracts[
                        "admin_tunnel_contract_sha256"
                    ],
                    "verified_admin_policy_inputs_contract_sha256": contracts[
                        "admin_policy_inputs_contract_sha256"
                    ],
                }
            )
        else:
            variables["verified_admin_policies_contract_sha256"] = contracts[
                "admin_policies_contract_sha256"
            ]
    return variables


def base_child_environment() -> dict[str, str]:
    return {
        "PATH": f"{TOOL_BIN}:/usr/bin:/bin",
        "HOME": "/var/empty",
        "LC_ALL": "C",
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }


def validate_plan(plan: dict[str, Any], phase: str) -> dict[str, str]:
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        fail("saved plan has no bounded managed change inventory")
    observed: dict[str, str] = {}
    for change in changes:
        if not isinstance(change, dict) or change.get("mode", "managed") != "managed":
            fail("saved plan contains a non-managed object")
        address = change.get("address")
        payload = change.get("change")
        if not isinstance(address, str) or not isinstance(payload, dict):
            fail("saved plan change schema is malformed")
        if payload.get("actions") != ["create"] or payload.get("before") is not None:
            fail("admin activation saved plan is not create-only")
        if address in observed:
            fail("saved plan contains a duplicate managed address")
        if change.get("type") != address.split(".", 1)[0]:
            fail("saved plan resource type does not match its exact address")
        observed[address] = change.get("type", "")
    if tuple(sorted(observed)) != tuple(sorted(EXPECTED_ADDRESSES[phase])):
        fail("saved plan managed graph does not exactly match the selected phase")
    return observed


def prepare_plan(
    *,
    root: Path,
    phase: str,
    context: dict[str, Any],
    results: dict[str, dict[str, Any]],
    write_token: str,
    transaction_root: Path,
) -> tuple[Path, Path, dict[str, Any]]:
    phase_root = root / "infrastructure/cloudflare/phases" / phase
    state_root = PHASES_ROOT / phase
    ensure_root_directory(state_root)
    data_root = state_root / "tofu-data"
    ensure_root_directory(data_root)
    state_path = state_root / "terraform.tfstate"
    if state_path.exists() or state_path.is_symlink():
        fail("selected create-only phase already has state; use status/resume")
    tfvars_path = transaction_root / "terraform.tfvars.json"
    atomic_write(tfvars_path, canonical_json(build_tfvars(phase, context, results)), 0o600)
    environment = base_child_environment()
    environment["TF_DATA_DIR"] = str(data_root)
    tofu = str(TOOL_BIN / "tofu")
    conftest = str(TOOL_BIN / "conftest")
    init = run_command(
        [tofu, "init", "-input=false", "-no-color", "-lockfile=readonly"],
        cwd=phase_root,
        environment=environment,
    )
    atomic_write(transaction_root / "init.log", init.stdout, 0o600)
    plan_path = transaction_root / "saved-plan.tfplan"
    plan_environment = dict(environment)
    plan_environment["CLOUDFLARE_API_TOKEN"] = write_token
    plan = run_command(
        [
            tofu,
            "plan",
            "-input=false",
            "-no-color",
            "-lock-timeout=0s",
            "-parallelism=1",
            f"-state={state_path}",
            f"-out={plan_path}",
            f"-var-file={tfvars_path}",
        ],
        cwd=phase_root,
        environment=plan_environment,
    )
    atomic_write(transaction_root / "plan.log", plan.stdout, 0o600)
    show = run_command(
        [tofu, "show", "-json", str(plan_path)],
        cwd=phase_root,
        environment=environment,
    )
    try:
        plan_json = json.loads(show.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError("OpenTofu saved-plan JSON is malformed") from error
    if not isinstance(plan_json, dict):
        fail("OpenTofu saved-plan JSON has an invalid root")
    validate_plan(plan_json, phase)
    policy_input = dict(plan_json)
    policy_input["codex_contract"] = {"phase": phase}
    policy_path = transaction_root / "policy-plan.json"
    atomic_write(policy_path, canonical_json(policy_input), 0o600)
    policy = run_command(
        [
            conftest,
            "test",
            "--policy",
            str(root / "infrastructure/cloudflare/policy"),
            str(policy_path),
        ],
        cwd=root,
        environment=environment,
    )
    atomic_write(transaction_root / "policy.log", policy.stdout, 0o600)
    return plan_path, state_path, plan_json


def extract_state_ids(
    *,
    root: Path,
    phase: str,
    state_path: Path,
    transaction_root: Path,
    require_complete: bool = True,
) -> dict[str, str]:
    environment = base_child_environment()
    environment["TF_DATA_DIR"] = str(PHASES_ROOT / phase / "tofu-data")
    show = run_command(
        [str(TOOL_BIN / "tofu"), "show", "-json", str(state_path)],
        cwd=root / "infrastructure/cloudflare/phases" / phase,
        environment=environment,
    )
    atomic_write(transaction_root / "post-state.json", show.stdout, 0o600)
    try:
        state_json = json.loads(show.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError("OpenTofu state JSON is malformed") from error
    resources = (
        state_json.get("values", {}).get("root_module", {}).get("resources", [])
        if isinstance(state_json, dict)
        else []
    )
    if not isinstance(resources, list):
        fail("OpenTofu state resource inventory is malformed")
    observed: dict[str, str] = {}
    for resource in resources:
        if not isinstance(resource, dict) or resource.get("mode", "managed") != "managed":
            fail("OpenTofu state contains an unexpected non-managed object")
        address = resource.get("address")
        values = resource.get("values")
        if not isinstance(address, str) or not isinstance(values, dict):
            fail("OpenTofu state object is malformed")
        identifier = values.get("id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 256:
            fail("OpenTofu state resource ID is malformed")
        observed[address] = identifier
    expected = set(EXPECTED_ADDRESSES[phase])
    if not set(observed).issubset(expected):
        fail("OpenTofu state graph escaped the selected phase")
    if require_complete and set(observed) != expected:
        fail("OpenTofu state graph does not exactly match the selected phase")
    if len(set(observed.values())) != len(observed):
        fail("OpenTofu state contains duplicate managed resource identifiers")
    return {ID_KEY_BY_ADDRESS[address]: identifier for address, identifier in observed.items()}


def validate_audit_transition(
    *, phase: str, pre: dict[str, str], post: dict[str, str]
) -> dict[str, str]:
    if pre.get("audit_result") != "pass" or post.get("audit_result") != "pass":
        fail("pre/post live audit pair is not PASS")
    if pre.get("audit_phase") != PRE_AUDIT_PHASE[phase] or post.get("audit_phase") != phase:
        fail("pre/post live audit chronology is invalid")
    stable_keys = {
        "account_binding_sha256",
        "target_binding_sha256",
        "public_edge_contract_sha256",
        "public_dns_naranjo_binding_sha256",
        "public_dns_lidersea_binding_sha256",
        "unrelated_tunnel_inventory_sha256",
        "unrelated_tunnel_configuration_sha256",
    }
    stable_keys.update(key for key in pre if key.startswith("unrelated_") and key.endswith("_sha256"))
    stable_keys.update(key for key in post if key.startswith("unrelated_") and key.endswith("_sha256"))
    predecessor_contract_keys = set().union(*CONTRACT_KEYS.values()) - set(
        CONTRACT_KEYS[phase]
    )
    stable_keys.update(
        key
        for key in predecessor_contract_keys
        if key in pre or key in post
    )
    for key in stable_keys:
        if not SHA256_RE.fullmatch(pre.get(key, "")) or pre.get(key) != post.get(key):
            fail(f"unrelated or public baseline changed across the transaction: {key}")
    for key in ACTIVATION_KEYS.get(phase, ()):
        if pre.get(key) != "absent" or post.get(key) != "exact":
            fail(f"phase activation transition is not absent-to-exact: {key}")
    contracts: dict[str, str] = {}
    for key in CONTRACT_KEYS[phase]:
        value = post.get(key, "")
        if not SHA256_RE.fullmatch(value):
            fail(f"post-audit did not mint exact phase contract: {key}")
        contracts[key] = value
    return contracts


def validate_predecessor_contracts(
    *, pre: dict[str, str], results: dict[str, dict[str, Any]]
) -> None:
    expected = combined_contracts(results)
    for key, digest in expected.items():
        if pre.get(key) != digest:
            fail(f"fresh pre-audit does not match predecessor contract: {key}")


def api_audit_logs(
    *, token: str, account_id: str, token_id: str, since: str, before: str
) -> dict[str, Any]:
    all_results: list[dict[str, Any]] = []
    cursor = ""
    seen_ids: set[str] = set()
    for _ in range(10):
        parameters = {
            "since": since,
            "before": before,
            "actor_token_id": token_id,
            "direction": "asc",
            "limit": "1000",
        }
        if cursor:
            parameters["cursor"] = cursor
        response = api_request(
            token,
            f"/accounts/{account_id}/logs/audit?{urllib.parse.urlencode(parameters)}",
        )
        if response.get("success") is not True or not isinstance(response.get("result"), list):
            fail("Cloudflare V2 audit-log query is incomplete")
        info = response.get("result_info")
        if not isinstance(info, dict):
            fail("Cloudflare V2 audit-log pagination metadata is absent")
        try:
            count = int(info.get("count"))
        except (TypeError, ValueError) as error:
            raise TransactionError("Cloudflare V2 audit-log count is malformed") from error
        if count != len(response["result"]):
            fail("Cloudflare V2 audit-log page count is inconsistent")
        for item in response["result"]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                fail("Cloudflare V2 audit-log entry is malformed")
            if item["id"] in seen_ids:
                fail("Cloudflare V2 audit-log entry was duplicated across pages")
            seen_ids.add(item["id"])
            all_results.append(item)
        cursor = info.get("cursor") or ""
        if not isinstance(cursor, str):
            fail("Cloudflare V2 audit-log cursor is malformed")
        if not cursor:
            return {"success": True, "result": all_results, "result_info": {"complete": True}}
    fail("Cloudflare V2 audit-log pagination exceeded the reviewed bound")


def validate_audit_logs(
    *, logs: dict[str, Any], account_id: str, token_id: str, expected_ids: set[str], since: dt.datetime, before: dt.datetime
) -> dict[str, Any]:
    entries = logs.get("result")
    if logs.get("success") is not True or not isinstance(entries, list):
        fail("Cloudflare V2 audit-log inventory is not complete")
    mutations: list[dict[str, Any]] = []
    for entry in entries:
        account = entry.get("account")
        action = entry.get("action")
        actor = entry.get("actor")
        if not isinstance(account, dict) or account.get("id") != account_id:
            fail("audit-log entry escaped the exact account")
        if (
            not isinstance(actor, dict)
            or actor.get("context") != "api_token"
            or actor.get("token_id") != token_id
        ):
            fail("audit-log entry is not attributed to the exact JIT token")
        if not isinstance(action, dict) or action.get("result") != "success":
            fail("audit-log entry is not a successful action")
        action_time = parse_utc(action.get("time"), "audit-log action time")
        if action_time < since - dt.timedelta(seconds=5) or action_time > before + dt.timedelta(seconds=5):
            fail("audit-log entry falls outside the held transaction window")
        action_type = action.get("type")
        if action_type in ("create", "update", "delete"):
            raw = entry.get("raw")
            resource = entry.get("resource")
            if action_type != "create":
                fail("JIT token performed a non-create mutation")
            if (
                not isinstance(raw, dict)
                or not isinstance(raw.get("status_code"), int)
                or not 200 <= raw["status_code"] <= 299
                or not isinstance(resource, dict)
                or not isinstance(resource.get("id"), str)
            ):
                fail("JIT mutation audit entry lacks bounded success/resource evidence")
            mutations.append(entry)
        elif action_type != "view":
            fail("JIT token performed an unknown audit-log action type")
    mutation_ids = [entry["resource"]["id"] for entry in mutations]
    if len(mutation_ids) != len(set(mutation_ids)) or set(mutation_ids) != expected_ids:
        fail("JIT create audit-log resource set does not exactly match applied state")
    return {
        "schema": "cloudflare-jit-audit-log-receipt-v1",
        "entry_count": len(entries),
        "mutation_count": len(mutations),
        "mutation_resource_set_sha256": sha256_bytes(
            canonical_json(sorted(sha256_bytes(item.encode("utf-8")) for item in mutation_ids))
        ),
        "complete": True,
    }


def verify_revocation(token: str, token_id: str, audit_token: str) -> None:
    bearer_inactive = False
    try:
        verify = api_request(token, "/user/tokens/verify")
    except APIError as error:
        bearer_inactive = error.status in (400, 401, 403, 404)
    else:
        result = verify.get("result")
        bearer_inactive = (
            verify.get("success") is True
            and isinstance(result, dict)
            and result.get("status") in ("disabled", "expired")
        )
    if not bearer_inactive:
        fail("JIT bearer still verifies as active")
    metadata_inactive = False
    try:
        details = api_request(audit_token, f"/user/tokens/{token_id}")
    except APIError as error:
        metadata_inactive = error.status == 404
    else:
        result = details.get("result")
        metadata_inactive = (
            details.get("success") is True
            and isinstance(result, dict)
            and result.get("status") in ("disabled", "expired")
        )
    if not metadata_inactive:
        fail("audit credential still observes the JIT token as active")


def expected_external_confirmation(phase: str) -> str | None:
    if phase == "admin-device":
        return "DEVICE ENROLLED"
    if phase == "admin-tunnel":
        return "CONNECTOR HEALTHY"
    return None


def load_pending(phase: str) -> dict[str, Any]:
    pending = load_json_file(PENDING_ROOT / f"{phase}.json", max_size=131072)
    expected = {
        "schema",
        "phase",
        "commit",
        "token_id",
        "audit_window_started_at",
        "plan_sha256",
        "apply_started_at",
        "apply_finished_at",
        "pre_audit",
        "ids",
        "state_path",
        "status",
    }
    parsed = exact_keys(pending, expected, "pending transaction")
    if parsed["schema"] != "pie5-cloudflare-pending-v1" or parsed["phase"] != phase:
        fail("pending transaction identity is invalid")
    if parsed["status"] not in (
        "preparing",
        "applying",
        "awaiting-revocation",
        "awaiting-external-proof",
        "failed-awaiting-revocation",
        "failed-revoked",
        "aborted-revoked",
        "failed-clean-revoked",
        "complete-revoked",
    ):
        fail("pending transaction status is invalid")
    if not isinstance(parsed["commit"], str) or not re.fullmatch(
        r"[0-9a-f]{40}", parsed["commit"]
    ):
        fail("pending transaction commit is malformed")
    if not valid_hex32_identifier(parsed["token_id"]):
        fail("pending transaction token identity is malformed")
    parse_utc(parsed["audit_window_started_at"], "pending audit-window start")
    if parsed["status"] in ("preparing", "aborted-revoked"):
        if (
            parsed["plan_sha256"] != ""
            or parsed["apply_started_at"] != ""
            or parsed["apply_finished_at"] != ""
        ):
            fail("preparing transaction has impossible apply evidence")
    else:
        if not isinstance(parsed["plan_sha256"], str) or not SHA256_RE.fullmatch(
            parsed["plan_sha256"]
        ):
            fail("pending transaction plan binding is malformed")
        parse_utc(parsed["apply_started_at"], "pending apply start")
        if parsed["apply_finished_at"] == "":
            if parsed["status"] != "applying":
                fail("only an applying transaction may lack a finish timestamp")
        else:
            parse_utc(parsed["apply_finished_at"], "pending apply finish")
    expected_pre_audit = str(PHASES_ROOT / phase / "pre-audit.txt")
    expected_state = str(PHASES_ROOT / phase / "terraform.tfstate")
    if parsed["pre_audit"] != expected_pre_audit or parsed["state_path"] != expected_state:
        fail("pending transaction protected paths are not exact")
    expected_id_keys = {
        ID_KEY_BY_ADDRESS[address] for address in EXPECTED_ADDRESSES[phase]
    }
    ids = parsed["ids"]
    if not isinstance(ids, dict) or not set(ids).issubset(expected_id_keys):
        fail("pending transaction resource inventory escaped the phase")
    if any(
        not isinstance(identifier, str) or not identifier or len(identifier) > 256
        for identifier in ids.values()
    ):
        fail("pending transaction resource identifier is malformed")
    if len(set(ids.values())) != len(ids):
        fail("pending transaction resource identifiers are not unique")
    return parsed


def pending_expected_id_keys(phase: str) -> set[str]:
    return {ID_KEY_BY_ADDRESS[address] for address in EXPECTED_ADDRESSES[phase]}


def persist_pending(phase: str, pending: dict[str, Any]) -> None:
    atomic_write(PENDING_ROOT / f"{phase}.json", canonical_json(pending), 0o600)


def unlink_protected_if_present(
    path: Path, *, modes: set[int], max_size: int
) -> None:
    if path.exists() or path.is_symlink():
        validate_regular_file(path, modes=modes, max_size=max_size)
        path.unlink()


def clear_finished_pending(phase: str) -> None:
    unlink_protected_if_present(
        PENDING_ROOT / f"{phase}.jit-token", modes={0o400}, max_size=256
    )
    if phase == "admin-tunnel":
        unlink_protected_if_present(
            PENDING_ROOT / "pi-admin-runtime-token",
            modes={0o400},
            max_size=4096,
        )
    unlink_protected_if_present(
        PENDING_ROOT / f"{phase}.json", modes={0o600}, max_size=131072
    )


def recover_applying_outcome(
    *, root: Path, phase: str, pending: dict[str, Any], write_token: str
) -> dict[str, Any]:
    state_path = Path(pending["state_path"])
    if state_path.exists() or state_path.is_symlink():
        ids = extract_state_ids(
            root=root,
            phase=phase,
            state_path=state_path,
            transaction_root=PHASES_ROOT / phase / "transaction",
            require_complete=False,
        )
    else:
        ids = {}
    pending["ids"] = ids
    pending["apply_finished_at"] = utc_text()
    if set(ids) == pending_expected_id_keys(phase):
        if phase == "admin-tunnel":
            runtime_token_path = PENDING_ROOT / "pi-admin-runtime-token"
            if runtime_token_path.is_symlink():
                fail("held Tunnel runtime token path is unsafe")
            if not runtime_token_path.exists():
                obtain_runtime_tunnel_token(
                    context=load_context(),
                    tunnel_id=ids["tunnel_id"],
                    write_token=write_token,
                )
            else:
                validate_regular_file(
                    runtime_token_path, modes={0o400}, max_size=4096
                )
        pending["status"] = "awaiting-revocation"
        print("CLOUDFLARE_APPLY_RECOVERY=EXACT_STATE")
    else:
        pending["status"] = "failed-awaiting-revocation"
        print("CLOUDFLARE_APPLY_RECOVERY=INCOMPLETE_STATE")
    persist_pending(phase, pending)
    print("JIT_TOKEN_ACTION=REVOKE_NOW")
    return pending


def wait_for_audit_receipt(
    *,
    audit_token: str,
    account_id: str,
    token_id: str,
    expected_ids: set[str],
    since: dt.datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    last_error: TransactionError | None = None
    for attempt in range(6):
        before = utc_now()
        logs = api_audit_logs(
            token=audit_token,
            account_id=account_id,
            token_id=token_id,
            since=utc_text(since - dt.timedelta(minutes=1)),
            before=utc_text(before),
        )
        atomic_write(
            PENDING_ROOT / "jit-audit-logs.latest.json", canonical_json(logs), 0o600
        )
        try:
            receipt = validate_audit_logs(
                logs=logs,
                account_id=account_id,
                token_id=token_id,
                expected_ids=expected_ids,
                since=since,
                before=before,
            )
        except TransactionError as error:
            last_error = error
            if attempt == 5:
                raise
            time.sleep(5)
            continue
        if not expected_ids and attempt == 0:
            time.sleep(5)
            continue
        return logs, receipt
    assert last_error is not None
    raise last_error


def finalize_failed_pending(
    *,
    phase: str,
    pending: dict[str, Any],
    write_token: str,
    audit_token: str,
    context: dict[str, Any],
) -> None:
    verify_revocation(write_token, pending["token_id"], audit_token)
    since = parse_utc(pending["audit_window_started_at"], "audit-window start")
    raw_logs, receipt = wait_for_audit_receipt(
        audit_token=audit_token,
        account_id=context["account_id"],
        token_id=pending["token_id"],
        expected_ids=set(pending["ids"].values()),
        since=since,
    )
    transaction_dir = PHASES_ROOT / phase / "transaction"
    atomic_write(
        transaction_dir / "failed-jit-audit-logs.json",
        canonical_json(raw_logs),
        0o600,
    )
    atomic_write(
        transaction_dir / "failed-jit-audit-receipt.json",
        canonical_json(receipt),
        0o600,
    )
    token_path = PENDING_ROOT / f"{phase}.jit-token"
    if pending["ids"]:
        pending["status"] = "failed-revoked"
        persist_pending(phase, pending)
        unlink_protected_if_present(token_path, modes={0o400}, max_size=256)
        print("JIT_REVOCATION=PASS")
        print("PHASE_RESULT=FAILED_PARTIAL_LOCKED")
        fail("partial provider state is retained for reviewed incident recovery")

    state_path = Path(pending["state_path"])
    if state_path.exists() or state_path.is_symlink():
        validate_regular_file(state_path, modes={0o600}, max_size=20 * 1024 * 1024)
        os.replace(state_path, transaction_dir / "failed-empty.tfstate")
    backup_path = PHASES_ROOT / phase / "terraform.tfstate.backup"
    if backup_path.exists() or backup_path.is_symlink():
        validate_regular_file(backup_path, modes={0o600}, max_size=20 * 1024 * 1024)
        os.replace(backup_path, transaction_dir / "failed-empty.tfstate.backup")
    pending["status"] = "failed-clean-revoked"
    persist_pending(phase, pending)
    clear_finished_pending(phase)
    print("JIT_REVOCATION=PASS")
    print("FAILED_APPLY_MUTATIONS=NONE")
    print("PHASE_RETRY=SAFE")


def finalize_preparing_pending(
    *,
    root: Path,
    phase: str,
    pending: dict[str, Any],
    write_token: str,
    audit_token: str,
    context: dict[str, Any],
) -> None:
    verify_revocation(write_token, pending["token_id"], audit_token)
    state_path = Path(pending["state_path"])
    transaction_dir = PHASES_ROOT / phase / "transaction"
    if state_path.exists() or state_path.is_symlink():
        ensure_root_directory(transaction_dir)
        ids = extract_state_ids(
            root=root,
            phase=phase,
            state_path=state_path,
            transaction_root=transaction_dir,
            require_complete=False,
        )
        if ids:
            fail("a preparing transaction unexpectedly owns provider state")
    backup_path = PHASES_ROOT / phase / "terraform.tfstate.backup"
    if backup_path.exists() or backup_path.is_symlink():
        fail("a preparing transaction unexpectedly owns backup state")
    since = parse_utc(pending["audit_window_started_at"], "audit-window start")
    raw_logs, receipt = wait_for_audit_receipt(
        audit_token=audit_token,
        account_id=context["account_id"],
        token_id=pending["token_id"],
        expected_ids=set(),
        since=since,
    )
    phase_root = PHASES_ROOT / phase
    atomic_write(
        phase_root / "aborted-jit-audit-logs.json", canonical_json(raw_logs), 0o600
    )
    atomic_write(
        phase_root / "aborted-jit-audit-receipt.json", canonical_json(receipt), 0o600
    )
    if state_path.exists() or state_path.is_symlink():
        validate_regular_file(state_path, modes={0o600}, max_size=20 * 1024 * 1024)
        state_path.unlink()
    if transaction_dir.exists() or transaction_dir.is_symlink():
        ensure_root_directory(transaction_dir)
        shutil.rmtree(transaction_dir)
    pending["status"] = "aborted-revoked"
    persist_pending(phase, pending)
    clear_finished_pending(phase)
    print("JIT_REVOCATION=PASS")
    print("PRE_APPLY_MUTATIONS=NONE")
    print("PHASE_RETRY=SAFE")


def finalize_pending(*, root: Path, phase: str, commit: str) -> None:
    context = load_context()
    audit_token = validate_token_text(stable_read(AUDIT_TOKEN_PATH, max_size=256), "audit token")
    validate_audit_token(audit_token, context)
    token_path = PENDING_ROOT / f"{phase}.jit-token"
    pending = load_pending(phase)
    if pending["commit"] != commit:
        fail("pending transaction was created by a different reviewed commit")
    if pending["status"] == "failed-revoked":
        unlink_protected_if_present(token_path, modes={0o400}, max_size=256)
        fail("partial provider state requires a new reviewed incident-recovery path")
    if pending["status"] in (
        "aborted-revoked",
        "failed-clean-revoked",
        "complete-revoked",
    ):
        finished_status = pending["status"]
        clear_finished_pending(phase)
        print(f"PENDING_CLEANUP_RECOVERY={finished_status.upper()}")
        return
    write_token = validate_token_text(stable_read(token_path, max_size=256), "pending JIT token")
    if pending["status"] == "preparing":
        finalize_preparing_pending(
            root=root,
            phase=phase,
            pending=pending,
            write_token=write_token,
            audit_token=audit_token,
            context=context,
        )
        return
    if pending["status"] == "applying":
        pending = recover_applying_outcome(
            root=root, phase=phase, pending=pending, write_token=write_token
        )
    if pending["status"] == "failed-awaiting-revocation":
        finalize_failed_pending(
            phase=phase,
            pending=pending,
            write_token=write_token,
            audit_token=audit_token,
            context=context,
        )
        return
    verify_revocation(write_token, pending["token_id"], audit_token)
    if pending["status"] == "awaiting-revocation":
        pending["status"] = "awaiting-external-proof"
        persist_pending(phase, pending)
    external_confirmation = expected_external_confirmation(phase)
    if external_confirmation is not None:
        typed = input(
            f"Type {external_confirmation!r} only after the external step is complete: "
        )
        if typed != external_confirmation:
            fail("external completion acknowledgement did not match")
    results = completed_results(before_phase=phase)
    all_ids = combined_ids(results, pending["ids"])
    transaction_root = root
    post_path = PENDING_ROOT / f"{phase}.post-audit.txt"
    post = run_audit(
        root=transaction_root,
        audit_phase=phase,
        context=context,
        ids=all_ids,
        audit_token=audit_token,
        output_path=post_path,
    )
    pre_path = Path(pending["pre_audit"])
    pre = parse_audit(stable_read(pre_path), PRE_AUDIT_PHASE[phase])
    contracts = validate_audit_transition(phase=phase, pre=pre, post=post)
    since = parse_utc(pending["audit_window_started_at"], "audit-window start")
    parse_utc(pending["apply_finished_at"], "apply finish")
    raw_logs, receipt = wait_for_audit_receipt(
        audit_token=audit_token,
        account_id=context["account_id"],
        token_id=pending["token_id"],
        expected_ids=set(pending["ids"].values()),
        since=since,
    )
    raw_logs_path = PHASES_ROOT / phase / "jit-audit-logs.json"
    atomic_write(raw_logs_path, canonical_json(raw_logs), 0o600)
    atomic_write(PHASES_ROOT / phase / "jit-audit-receipt.json", canonical_json(receipt), 0o600)
    evidence = {
        "plan_sha256": pending["plan_sha256"],
        "pre_audit_sha256": sha256_file(pre_path),
        "post_audit_sha256": sha256_file(post_path),
        "audit_log_receipt_sha256": sha256_bytes(canonical_json(receipt)),
        "jit_token_id_sha256": sha256_bytes(pending["token_id"].encode("ascii")),
        "revocation": "bearer-and-metadata-inactive",
        "completed_at": utc_text(),
    }
    result = {
        "schema": "pie5-cloudflare-phase-result-v1",
        "phase": phase,
        "commit": commit,
        "ids": pending["ids"],
        "contracts": contracts,
        "evidence": evidence,
    }
    atomic_write(RESULTS_ROOT / f"{phase}.json", canonical_json(result), 0o600)
    pending["status"] = "complete-revoked"
    persist_pending(phase, pending)
    clear_finished_pending(phase)
    print(f"CLOUDFLARE_PHASE={phase}")
    print("JIT_REVOCATION=PASS")
    print("UNRELATED_STATE=UNCHANGED")
    print("JIT_AUDIT_LOG=EXACT_CREATE_SET")
    print("PHASE_RESULT=PASS")


def obtain_runtime_tunnel_token(
    *, context: dict[str, Any], tunnel_id: str, write_token: str
) -> None:
    response = api_request(
        write_token,
        f"/accounts/{context['account_id']}/cfd_tunnel/{tunnel_id}/token",
    )
    token = response.get("result")
    if response.get("success") is not True or not isinstance(token, str):
        fail("pi-admin runtime token could not be obtained")
    if len(token) < 100 or len(token) > 4096 or not re.fullmatch(r"[A-Za-z0-9._-]+", token):
        fail("pi-admin runtime token has an unexpected shape")
    atomic_write(PENDING_ROOT / "pi-admin-runtime-token", token.encode("ascii"), 0o400)


def apply_phase(
    *, root: Path, phase: str, commit: str, write_token_path: Path, token_id: str
) -> None:
    if phase not in PHASES:
        fail("unknown Cloudflare admin phase")
    ensure_state_tree()
    pending_path = PENDING_ROOT / f"{phase}.json"
    pending_token_path = PENDING_ROOT / f"{phase}.jit-token"
    if (
        (RESULTS_ROOT / f"{phase}.json").exists()
        or (RESULTS_ROOT / f"{phase}.json").is_symlink()
        or pending_path.exists()
        or pending_path.is_symlink()
        or pending_token_path.exists()
        or pending_token_path.is_symlink()
    ):
        fail("selected phase is already complete or pending")
    for candidate in PHASES:
        if (
            (PENDING_ROOT / f"{candidate}.json").exists()
            or (PENDING_ROOT / f"{candidate}.json").is_symlink()
            or (PENDING_ROOT / f"{candidate}.jit-token").exists()
            or (PENDING_ROOT / f"{candidate}.jit-token").is_symlink()
        ):
            fail("another Cloudflare phase is pending or has an orphaned token")
    runtime_token_path = PENDING_ROOT / "pi-admin-runtime-token"
    if runtime_token_path.exists() or runtime_token_path.is_symlink():
        fail("an orphaned Tunnel runtime token blocks a new phase")
    context = load_context()
    audit_token = validate_token_text(stable_read(AUDIT_TOKEN_PATH, max_size=256), "audit token")
    validate_audit_token(audit_token, context)
    results = completed_results(before_phase=phase)
    write_token = validate_token_text(stable_read(write_token_path, max_size=256), "JIT token")
    jit_receipt = validate_jit_token(
        phase=phase,
        token=write_token,
        token_id=token_id,
        audit_token=audit_token,
        context=context,
    )
    pre_path = PHASES_ROOT / phase / "pre-audit.txt"
    state_path = PHASES_ROOT / phase / "terraform.tfstate"
    ensure_root_directory(PHASES_ROOT / phase)
    pending = {
        "schema": "pie5-cloudflare-pending-v1",
        "phase": phase,
        "commit": commit,
        "token_id": token_id,
        "audit_window_started_at": jit_receipt["issued_on"],
        "plan_sha256": "",
        "apply_started_at": "",
        "apply_finished_at": "",
        "pre_audit": str(pre_path),
        "ids": {},
        "state_path": str(state_path),
        "status": "preparing",
    }
    atomic_write(pending_token_path, write_token.encode("ascii"), 0o400)
    persist_pending(phase, pending)
    ids = combined_ids(results)
    pre = run_audit(
        root=root,
        audit_phase=PRE_AUDIT_PHASE[phase],
        context=context,
        ids=ids,
        audit_token=audit_token,
        output_path=pre_path,
    )
    if pre.get("audit_result") != "pass":
        fail("pre-operation Cloudflare audit did not pass")
    validate_predecessor_contracts(pre=pre, results=results)
    transaction_dir = PHASES_ROOT / phase / "transaction"
    ensure_root_directory(transaction_dir)
    plan_path, prepared_state_path, _ = prepare_plan(
        root=root,
        phase=phase,
        context=context,
        results=results,
        write_token=write_token,
        transaction_root=transaction_dir,
    )
    if prepared_state_path != state_path:
        fail("prepared state path escaped the pending transaction")
    plan_hash = sha256_file(plan_path)
    atomic_write(transaction_dir / "jit-preflight.json", canonical_json(jit_receipt), 0o600)
    typed = input(f"Type 'APPLY {phase} {plan_hash}' to apply the exact saved plan: ")
    if typed != f"APPLY {phase} {plan_hash}":
        fail("saved-plan confirmation did not match")
    started = utc_now()
    pending["plan_sha256"] = plan_hash
    pending["apply_started_at"] = utc_text(started)
    pending["status"] = "applying"
    persist_pending(phase, pending)
    environment = base_child_environment()
    environment["TF_DATA_DIR"] = str(PHASES_ROOT / phase / "tofu-data")
    environment["CLOUDFLARE_API_TOKEN"] = write_token
    apply = run_command(
        [
            str(TOOL_BIN / "tofu"),
            "apply",
            "-input=false",
            "-no-color",
            "-auto-approve",
            "-parallelism=1",
            f"-state={state_path}",
            f"-backup={PHASES_ROOT / phase / 'terraform.tfstate.backup'}",
            str(plan_path),
        ],
        cwd=root / "infrastructure/cloudflare/phases" / phase,
        environment=environment,
        check=False,
    )
    finished = utc_now()
    atomic_write(transaction_dir / "apply.log", apply.stdout, 0o600)
    current_ids = extract_state_ids(
        root=root,
        phase=phase,
        state_path=state_path,
        transaction_root=transaction_dir,
        require_complete=False,
    )
    pending["apply_finished_at"] = utc_text(finished)
    pending["ids"] = current_ids
    complete_state = set(current_ids) == pending_expected_id_keys(phase)
    if apply.returncode == 0 and not complete_state:
        pending["status"] = "failed-awaiting-revocation"
        persist_pending(phase, pending)
        print("CLOUDFLARE_APPLY=INCOMPLETE_STATE")
        print("JIT_TOKEN_ACTION=REVOKE_NOW")
        return
    if complete_state and phase == "admin-tunnel":
        obtain_runtime_tunnel_token(
            context=context, tunnel_id=current_ids["tunnel_id"], write_token=write_token
        )
    pending["status"] = (
        "awaiting-revocation" if complete_state else "failed-awaiting-revocation"
    )
    persist_pending(phase, pending)
    if apply.returncode == 0:
        print("CLOUDFLARE_APPLY=PASS")
    elif complete_state:
        print("CLOUDFLARE_APPLY=NONZERO_EXACT_STATE")
    else:
        print("CLOUDFLARE_APPLY=NONZERO_INCOMPLETE_STATE")
    print("JIT_TOKEN_ACTION=REVOKE_NOW")
    print("PHASE_RESULT=PENDING_REVOCATION")


def configure(
    *, context_input: Path, audit_token_input: Path, certificate_input: Path
) -> None:
    ensure_state_tree()
    if CONFIGURATION_RECEIPT_PATH.exists() or CONFIGURATION_RECEIPT_PATH.is_symlink():
        fail("Cloudflare workstation context already exists")
    for path, modes, maximum in (
        (CONTEXT_PATH, {0o600}, 65536),
        (AUDIT_TOKEN_PATH, {0o400}, 256),
        (CA_CERTIFICATE_PATH, {0o400}, 16384),
    ):
        if path.exists() or path.is_symlink():
            validate_regular_file(path, modes=modes, max_size=maximum)
    context_raw = stable_read(context_input, max_size=65536)
    certificate_raw = stable_read(certificate_input, max_size=16384)
    try:
        context_json = json.loads(context_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError("workstation context JSON is malformed") from error
    context = validate_context(context_json, certificate_raw)
    audit_token_raw = stable_read(audit_token_input, max_size=256)
    audit_token = validate_token_text(audit_token_raw, "audit token")
    validate_audit_token(audit_token, context)
    atomic_write(CONTEXT_PATH, canonical_json(context), 0o600)
    atomic_write(AUDIT_TOKEN_PATH, audit_token.encode("ascii"), 0o400)
    atomic_write(CA_CERTIFICATE_PATH, certificate_raw, 0o400)
    canonical_context = stable_read(CONTEXT_PATH, max_size=65536)
    installed_certificate = stable_read(CA_CERTIFICATE_PATH, max_size=16384)
    receipt = {
        "schema": "pie5-cloudflare-configuration-v1",
        "context_sha256": sha256_bytes(canonical_context),
        "certificate_sha256": sha256_bytes(installed_certificate),
    }
    atomic_write(CONFIGURATION_RECEIPT_PATH, canonical_json(receipt), 0o600)
    load_context()
    print("CLOUDFLARE_WORKSTATION_CONTEXT=PASS")
    print("AUDIT_TOKEN_CONTRACT=PASS")
    print("PRIVATE_KEY_INGESTED=NO")


def audit_token_proposal(audit_token_input: Path, context_input: Path) -> None:
    token = validate_token_text(stable_read(audit_token_input, max_size=256), "audit token")
    draft_context = validate_context(
        load_json_file(context_input, max_size=65536),
        allow_unbound_audit_contract=True,
    )
    contract = validate_audit_token(token, draft_context, enforce_contract=False)
    print(f"AUDIT_TOKEN_CONTRACT_SHA256={contract}")
    print("AUDIT_TOKEN_STATUS=ACTIVE")
    print("AUDIT_TOKEN_SECRET_PRINTED=NO")


def rotate_audit_token(audit_token_input: Path) -> None:
    context = load_context()
    raw = stable_read(audit_token_input, max_size=256)
    token = validate_token_text(raw, "replacement audit token")
    validate_audit_token(token, context)
    atomic_write(AUDIT_TOKEN_PATH, token.encode("ascii"), 0o400)
    print("AUDIT_TOKEN_ROTATION=PASS")
    print("AUDIT_TOKEN_CONTRACT=UNCHANGED")


def status() -> None:
    ensure_state_tree()
    pending_count = sum(
        1
        for phase in PHASES
        if (PENDING_ROOT / f"{phase}.json").exists()
        or (PENDING_ROOT / f"{phase}.json").is_symlink()
    )
    if pending_count > 1:
        fail("more than one Cloudflare phase is pending")
    for phase in PHASES:
        result_path = RESULTS_ROOT / f"{phase}.json"
        pending_path = PENDING_ROOT / f"{phase}.json"
        token_path = PENDING_ROOT / f"{phase}.jit-token"
        state_path = PHASES_ROOT / phase / "terraform.tfstate"
        result_exists = result_path.exists() or result_path.is_symlink()
        pending_exists = pending_path.exists() or pending_path.is_symlink()
        token_exists = token_path.exists() or token_path.is_symlink()
        if token_exists and not pending_exists:
            fail("orphaned protected JIT token exists")
        if result_exists:
            load_result(phase)
            if not state_path.exists() or state_path.is_symlink():
                fail("completed phase state is unavailable or unsafe")
            validate_regular_file(
                state_path, modes={0o600}, max_size=20 * 1024 * 1024
            )
        if pending_exists:
            pending = load_pending(phase)
            if pending["status"] not in (
                "aborted-revoked",
                "failed-clean-revoked",
                "complete-revoked",
                "failed-revoked",
            ) and not token_exists:
                fail("pending phase has no protected JIT token")
            if result_exists and pending["status"] != "complete-revoked":
                fail("phase has conflicting pending and completed records")
            state = f"pending:{pending['status']}"
        elif result_exists:
            state = "complete"
        else:
            if state_path.exists() or state_path.is_symlink():
                fail("orphaned Cloudflare phase state exists")
            state = "absent"
        print(f"{phase}={state}")
    runtime_token = PENDING_ROOT / "pi-admin-runtime-token"
    if runtime_token.exists() or runtime_token.is_symlink():
        tunnel_pending = PENDING_ROOT / "admin-tunnel.json"
        if not tunnel_pending.exists() or tunnel_pending.is_symlink():
            fail("orphaned Tunnel runtime token exists")


def emit_runtime_token() -> None:
    if os.isatty(sys.stdout.fileno()):
        fail("runtime token emission requires a non-terminal pipe")
    pending = load_pending("admin-tunnel")
    if pending["status"] not in ("awaiting-revocation", "awaiting-external-proof"):
        fail("runtime token emission requires the exact pending Tunnel phase")
    if set(pending["ids"]) != pending_expected_id_keys("admin-tunnel"):
        fail("runtime token emission is not bound to exact Tunnel state")
    if (RESULTS_ROOT / "admin-tunnel.json").exists() or (
        RESULTS_ROOT / "admin-tunnel.json"
    ).is_symlink():
        fail("runtime token emission is closed after Tunnel phase completion")
    token_path = PENDING_ROOT / "pi-admin-runtime-token"
    raw = stable_read(token_path, max_size=4096)
    if len(raw) < 100 or not re.fullmatch(rb"[A-Za-z0-9._-]+", raw):
        fail("held runtime token is malformed")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def validate_launcher_environment() -> tuple[Path, str]:
    if os.geteuid() != 0:
        fail("Cloudflare root transaction requires EUID 0")
    if os.environ.get("REVIEWED_BLOB_LAUNCHER_AVAILABLE") != "yes":
        fail("trusted reviewed-blob launcher marker is absent")
    root_text = os.environ.get("REVIEWED_BLOB_ROOT", "")
    if not re.fullmatch(
        r"/private/var/db/website-infrastructure/runtime/cloudflare-reviewed-op\.[A-Za-z0-9]+",
        root_text,
    ):
        fail("reviewed extraction root is malformed")
    commit = os.environ.get("EXPECTED_REPOSITORY_HEAD", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("reviewed repository head is malformed")
    return Path(root_text), commit


def main(arguments: list[str]) -> int:
    root, commit = validate_launcher_environment()
    if len(arguments) < 2:
        fail("Cloudflare root transaction operation is required")
    operation = arguments[1]
    if operation == "audit-token-proposal" and len(arguments) == 4:
        audit_token_proposal(Path(arguments[2]), Path(arguments[3]))
    elif operation == "configure" and len(arguments) == 5:
        configure(
            context_input=Path(arguments[2]),
            audit_token_input=Path(arguments[3]),
            certificate_input=Path(arguments[4]),
        )
    elif operation == "apply" and len(arguments) == 5:
        apply_phase(
            root=root,
            phase=arguments[2],
            commit=commit,
            write_token_path=Path(arguments[3]),
            token_id=arguments[4],
        )
    elif operation == "resume" and len(arguments) == 3:
        if arguments[2] not in PHASES:
            fail("unknown Cloudflare admin phase")
        finalize_pending(root=root, phase=arguments[2], commit=commit)
    elif operation == "rotate-audit-token" and len(arguments) == 3:
        rotate_audit_token(Path(arguments[2]))
    elif operation == "status" and len(arguments) == 2:
        status()
    elif operation == "emit-runtime-token" and len(arguments) == 2:
        emit_runtime_token()
    else:
        fail("Cloudflare root transaction arguments are outside the closed grammar")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except TransactionError as error:
        print(f"CLOUDFLARE_ROOT_TRANSACTION=FAIL reason={error}", file=sys.stderr)
        raise SystemExit(1)
