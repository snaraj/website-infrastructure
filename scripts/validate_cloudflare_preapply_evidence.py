#!/usr/bin/env python3
"""Validate Cloudflare pre-apply state and manual evidence without credentials.

The plan gate supplies immutable snapshots and independently computed hashes.
This validator never authenticates, mutates infrastructure, or treats a human
attestation as cryptographic proof of the Cloudflare account state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any, NamedTuple


STATE_SCHEMA = "cloudflare-preapply-state-binding-v1"
ATTESTATION_SCHEMA = "cloudflare-preapply-manual-v1"
ATTESTATION_ROLE = "reviewed-manual-preapply-authorization"
BACKEND_KIND = "local-protected-file"
TOFU_VERSION = "1.12.5"
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_BACKEND_BYTES = 64 * 1024
MAX_ATTESTATION_BYTES = 32 * 1024
MAX_STATE_EVIDENCE_BYTES = 2 * 1024
MAX_PRE_STATE_RECEIPT_BYTES = 4 * 1024
MAX_ATTESTATION_TTL_SECONDS = 300
MAX_REVIEW_AGE_SECONDS = 900
MAX_RECOVERY_AGE_SECONDS = 300
MAX_WRITE_TOKEN_TTL_SECONDS = 1800

PHASES = (
    "admin-certificate",
    "admin-enrollment-policy",
    "admin-enrollment-app",
    "admin-device",
    "admin-tunnel",
    "admin-policies",
    "admin-route",
    "public-edge",
    "public-dns-naranjo",
    "public-dns-lidersea",
)

# Keep this matrix identical to the write-phase subset in
# validate_cloudflare_token_receipt.py. It describes unavoidable Cloudflare
# authorization reach, not the narrower object intent enforced by the plan.
PHASE_POLICY = {
    "admin-certificate": {
        "resource_scope": "exact-account",
        "permissions": ("SSL and Certificates Write",),
        "unavoidable_reach": ("all-mtls-certificates-in-account",),
    },
    "admin-enrollment-policy": {
        "resource_scope": "exact-account",
        "permissions": ("Access: Apps and Policies Write",),
        "unavoidable_reach": ("all-access-policies-in-account",),
    },
    "admin-enrollment-app": {
        "resource_scope": "exact-account",
        "permissions": ("Access: Apps and Policies Write",),
        "unavoidable_reach": ("all-access-applications-in-account",),
    },
    "admin-device": {
        "resource_scope": "exact-account",
        "permissions": ("Zero Trust Write",),
        "unavoidable_reach": ("all-zero-trust-device-configuration-in-account",),
    },
    "admin-tunnel": {
        "resource_scope": "exact-account",
        "permissions": ("Cloudflare One Connector: cloudflared Write",),
        "unavoidable_reach": (
            "all-cloudflared-connectors-and-tunnels-in-account",
        ),
    },
    "admin-policies": {
        "resource_scope": "exact-account",
        "permissions": ("Zero Trust Write",),
        "unavoidable_reach": ("all-zero-trust-resources-in-account",),
    },
    "admin-route": {
        "resource_scope": "exact-account",
        "permissions": ("Cloudflare One Networks Write",),
        "unavoidable_reach": (
            "all-private-routes-and-virtual-networks-in-account",
        ),
    },
    "public-edge": {
        "resource_scope": "exact-account",
        "permissions": ("Cloudflare One Connector: cloudflared Write",),
        "unavoidable_reach": (
            "all-cloudflared-connectors-and-tunnels-in-account",
        ),
    },
    "public-dns-naranjo": {
        "resource_scope": "exact-zone",
        "permissions": ("DNS Write",),
        "unavoidable_reach": ("all-dns-records-in-exact-zone",),
    },
    "public-dns-lidersea": {
        "resource_scope": "exact-zone",
        "permissions": ("DNS Write",),
        "unavoidable_reach": ("all-dns-records-in-exact-zone",),
    },
}

NONZERO_SHA256_RE = re.compile(r"(?=.*[1-9a-f])[0-9a-f]{64}\Z")
UTC_SECONDS_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
SECRET_PATTERNS = (
    re.compile(r"AGE-SECRET-KEY-(?:PQ-)?1[A-Z0-9]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:cfk|cfut|cfat)_[A-Za-z0-9]{40}[0-9A-Fa-f]{8}\b"),
    re.compile(
        r"(?i)\bcloudflare_api_token\b[\"']?\s*[:=]\s*[\"']?"
        r"[A-Za-z0-9_-]{20,}"
    ),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~-]{20,}"),
    re.compile(
        r"(?<![A-Za-z0-9+/_-])eyJ[A-Za-z0-9+/_-]{77,4093}={0,2}"
        r"(?![A-Za-z0-9+/_=-])"
    ),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,})\b"),
)

STATE_KEYS = {
    "version",
    "terraform_version",
    "serial",
    "lineage",
    "outputs",
    "resources",
    "check_results",
}
BACKEND_METADATA_KEYS = {"version", "serial", "lineage", "backend", "modules"}
BACKEND_KEYS = {"type", "config", "hash"}
BACKEND_CONFIG_KEYS = {"path", "workspace_dir"}
BACKEND_ROOT_MODULE_KEYS = {"path", "outputs", "resources", "depends_on"}
ATTESTATION_KEYS = {
    "schema",
    "phase",
    "evidence_role",
    "generated_utc",
    "expires_utc",
    "bindings",
    "entitlement",
    "account_security",
    "jit_token",
    "operator_recovery",
    "review",
}
BINDING_KEYS = {
    "repository_commit_sha256",
    "workspace_attestation_sha256",
    "saved_plan_sha256",
    "predecessor_audit_sha256",
    "provider_lock_sha256",
    "state_binding_sha256",
}
STATE_EVIDENCE_KEYS = (
    "state_backend",
    "backend_metadata_sha256",
    "state_path_sha256",
    "state_mode",
    "state_sha256",
    "state_lineage_sha256",
    "state_serial",
    "state_binding_sha256",
)
PRE_STATE_RECEIPT_KEYS = (
    "backend_metadata_sha256",
    "manual_attestation_sha256",
    "phase_root",
    "repo_commit",
    "phase_lock_sha256",
    "workspace_attestation_sha256",
    "state_binding_sha256",
    "state_evidence_sha256",
    "state_mode",
    "state_sha256",
    "plan_sha256",
    "planned_utc",
)
COMMIT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
ENTITLEMENT_KEYS = {
    "verified_at",
    "active_zone_count",
    "active_zone_names",
    "all_zones_on_free_plan",
    "zero_trust_on_free_plan",
    "paid_products_active",
    "trials_active",
    "unknown_billing_or_entitlement",
    "authorized_infrastructure_usd_monthly",
    "registrar_renewals_are_only_exception",
}
ACCOUNT_SECURITY_KEYS = {
    "verified_at",
    "member_inventory_reviewed",
    "administrator_mfa_verified",
    "api_token_inventory_reviewed",
    "unexpected_admin_or_token_authority",
}
JIT_TOKEN_KEYS = {
    "token_id_sha256",
    "resource_scope",
    "scope_binding_sha256",
    "permissions",
    "unavoidable_reach",
    "source_ip_restricted",
    "source_ip_policy_sha256",
    "issued_at",
    "expires_at",
    "active_status_verified",
    "only_write_token_live",
    "plaintext_persisted",
    "plaintext_shared",
}
RECOVERY_KEYS = {
    "verified_at",
    "physical_or_trusted_lan_recovery",
    "two_retained_sessions",
    "fresh_third_login",
    "evidence_sha256",
}
REVIEW_KEYS = {
    "approved",
    "approved_at",
    "reviewer_role",
    "approval_sha256",
}


class EvidenceError(ValueError):
    """A content-neutral validation error safe for an operator transcript."""


class DuplicateKeyError(EvidenceError):
    """Raised when a JSON member would overwrite an earlier member."""


class StateEvidence(NamedTuple):
    """Non-secret state facts derived from the exact parsed bytes."""

    mode: str
    backend_sha256: str
    state_path_sha256: str
    sha256: str
    lineage_sha256: str
    serial: str
    binding_sha256: str


class AttestationEvidence(NamedTuple):
    """Bounded result for one reviewed manual attestation."""

    phase: str
    sha256: str


class PredecessorEvidence(NamedTuple):
    """Validated bindings carried forward from one completed phase."""

    mode: str
    state_sha256: str
    state_binding_sha256: str
    backend_metadata_sha256: str
    workspace_attestation_sha256: str
    planned_utc: str
    receipt_sha256: str
    state_evidence_sha256: str


class SafeArgumentParser(argparse.ArgumentParser):
    """Do not echo protected arguments in parser diagnostics."""

    def error(self, _message: str) -> None:
        raise EvidenceError("command-line arguments are invalid")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError("JSON contains a duplicate key")
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise EvidenceError("JSON contains a non-finite number")


def _load_json(raw: bytes, *, maximum: int, label: str) -> dict[str, Any]:
    if not raw or len(raw) > maximum or raw.startswith(b"\xef\xbb\xbf"):
        raise EvidenceError(f"{label} bytes are empty, oversized, or BOM-prefixed")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise EvidenceError(f"{label} must be one JSON object")
    return value


def _exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise EvidenceError(f"{label} has missing or unsupported keys")
    return value


def _exact_bool(value: Any, expected: bool, label: str) -> None:
    if type(value) is not bool or value is not expected:
        raise EvidenceError(f"{label} is not the required boolean")


def _nonzero_sha256(value: Any, label: str) -> str:
    if type(value) is not str or not NONZERO_SHA256_RE.fullmatch(value):
        raise EvidenceError(f"{label} is not a nonzero lowercase SHA-256")
    return value


def _same(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise EvidenceError(f"{label} does not match the protected transaction")


def _parse_utc(value: Any, label: str) -> dt.datetime:
    if type(value) is not str or not UTC_SECONDS_RE.fullmatch(value):
        raise EvidenceError(f"{label} is not canonical UTC seconds")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise EvidenceError(f"{label} is not a real timestamp") from exc
    return parsed.replace(tzinfo=dt.timezone.utc)


def _phase_root(phase: str) -> str:
    if phase not in PHASES:
        raise EvidenceError("phase is outside the closed pre-apply matrix")
    return f"infrastructure/cloudflare/phases/{phase}"


def _state_binding_bytes(
    *,
    phase_root: str,
    backend_sha256: str,
    state_path_sha256: str,
    mode: str,
    state_sha256: str,
    lineage_sha256: str,
    serial: str,
) -> bytes:
    return (
        f"schema={STATE_SCHEMA}\n"
        f"phase_root={phase_root}\n"
        f"backend_kind={BACKEND_KIND}\n"
        f"backend_metadata_sha256={backend_sha256}\n"
        f"state_path_sha256={state_path_sha256}\n"
        f"state_mode={mode}\n"
        f"state_sha256={state_sha256}\n"
        f"state_lineage_sha256={lineage_sha256}\n"
        f"state_serial={serial}\n"
    ).encode("ascii")


def _canonical_path(value: Any, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise EvidenceError(f"{label} is not one absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise EvidenceError(f"{label} is not one absolute path")
    try:
        return os.path.normcase(os.path.realpath(os.path.abspath(value)))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"{label} is not one canonical path") from exc


def parse_backend_metadata(raw: bytes, *, expected_state_path: str) -> tuple[str, str]:
    """Parse initialized local-backend metadata and bind its exact state path."""

    document = _exact_object(
        _load_json(raw, maximum=MAX_BACKEND_BYTES, label="backend metadata"),
        BACKEND_METADATA_KEYS,
        "backend metadata",
    )
    if type(document["version"]) is not int or document["version"] != 3:
        raise EvidenceError("backend metadata format version is not exactly 3")
    if (
        type(document["serial"]) is not int
        or document["serial"] < 0
        or document["serial"] > 2**63 - 1
    ):
        raise EvidenceError("backend metadata serial is not bounded")
    lineage = document["lineage"]
    if type(lineage) is not str:
        raise EvidenceError("backend metadata lineage is not a canonical UUID")
    try:
        parsed_lineage = uuid.UUID(lineage)
    except (ValueError, AttributeError) as exc:
        raise EvidenceError("backend metadata lineage is not a canonical UUID") from exc
    if str(parsed_lineage) != lineage:
        raise EvidenceError("backend metadata lineage is not canonical lowercase UUID")

    backend = _exact_object(document["backend"], BACKEND_KEYS, "backend")
    if backend["type"] != "local":
        raise EvidenceError("backend type is not exactly local")
    if type(backend["hash"]) is not int or type(backend["hash"]) is bool:
        raise EvidenceError("backend configuration hash is not an integer")
    config = _exact_object(backend["config"], BACKEND_CONFIG_KEYS, "backend config")
    if config["workspace_dir"] is not None:
        raise EvidenceError("backend workspace directory must be null")
    configured_path = _canonical_path(config["path"], "backend state path")
    expected_path = _canonical_path(expected_state_path, "expected state path")
    if configured_path != expected_path:
        raise EvidenceError("backend state path does not match the protected phase path")

    modules = document["modules"]
    if type(modules) is not list or len(modules) != 1:
        raise EvidenceError("backend metadata modules are not the empty root module")
    root_module = _exact_object(
        modules[0], BACKEND_ROOT_MODULE_KEYS, "backend root module"
    )
    if (
        root_module["path"] != ["root"]
        or root_module["outputs"] != {}
        or root_module["resources"] != {}
        or root_module["depends_on"] != []
    ):
        raise EvidenceError("backend metadata root module is not empty")

    state_path_sha256 = hashlib.sha256((expected_path + "\n").encode("utf-8")).hexdigest()
    return hashlib.sha256(raw).hexdigest(), state_path_sha256


def parse_state_evidence(
    raw: bytes | None,
    *,
    backend_raw: bytes,
    phase: str,
    expected_state_path: str,
) -> StateEvidence:
    """Derive the state binding from a present snapshot or explicit absence."""

    phase_root = _phase_root(phase)
    backend_sha256, state_path_sha256 = parse_backend_metadata(
        backend_raw, expected_state_path=expected_state_path
    )
    if raw is None:
        mode = "absent"
        state_sha256 = "absent"
        lineage_sha256 = "absent"
        serial = "absent"
    else:
        document = _load_json(raw, maximum=MAX_STATE_BYTES, label="state")
        if not set(document).issubset(STATE_KEYS) or not {
            "version",
            "terraform_version",
            "serial",
            "lineage",
            "outputs",
            "resources",
        }.issubset(document):
            raise EvidenceError("state has missing or unsupported top-level keys")
        if type(document["version"]) is not int or document["version"] != 4:
            raise EvidenceError("state format version is not exactly 4")
        if document["terraform_version"] != TOFU_VERSION:
            raise EvidenceError("state OpenTofu version is not the reviewed version")
        if (
            type(document["serial"]) is not int
            or document["serial"] < 0
            or document["serial"] > 2**63 - 1
        ):
            raise EvidenceError("state serial is not a bounded non-negative integer")
        lineage = document["lineage"]
        if type(lineage) is not str:
            raise EvidenceError("state lineage is not a canonical UUID")
        try:
            parsed_lineage = uuid.UUID(lineage)
        except (ValueError, AttributeError) as exc:
            raise EvidenceError("state lineage is not a canonical UUID") from exc
        if str(parsed_lineage) != lineage:
            raise EvidenceError("state lineage is not a canonical lowercase UUID")
        if type(document["outputs"]) is not dict or document["outputs"]:
            raise EvidenceError("create-only pre-apply state must have no outputs")
        if type(document["resources"]) is not list or document["resources"]:
            raise EvidenceError("create-only pre-apply state must have no resources")
        if "check_results" in document and document["check_results"] not in (None, []):
            raise EvidenceError("create-only pre-apply state has unexpected check results")
        mode = "present"
        state_sha256 = hashlib.sha256(raw).hexdigest()
        lineage_sha256 = hashlib.sha256((lineage + "\n").encode("ascii")).hexdigest()
        serial = str(document["serial"])

    binding = _state_binding_bytes(
        phase_root=phase_root,
        backend_sha256=backend_sha256,
        state_path_sha256=state_path_sha256,
        mode=mode,
        state_sha256=state_sha256,
        lineage_sha256=lineage_sha256,
        serial=serial,
    )
    return StateEvidence(
        mode=mode,
        backend_sha256=backend_sha256,
        state_path_sha256=state_path_sha256,
        sha256=state_sha256,
        lineage_sha256=lineage_sha256,
        serial=serial,
        binding_sha256=hashlib.sha256(binding).hexdigest(),
    )


def _parse_canonical_kv(
    raw: bytes, *, expected_keys: tuple[str, ...], maximum: int, label: str
) -> dict[str, str]:
    """Parse one exact-order, LF-terminated ASCII key/value record."""

    if (
        not raw
        or len(raw) > maximum
        or raw.startswith(b"\xef\xbb\xbf")
        or b"\x00" in raw
        or b"\r" in raw
        or not raw.endswith(b"\n")
    ):
        raise EvidenceError(f"{label} is not bounded canonical ASCII")
    try:
        lines = raw.decode("ascii", errors="strict").splitlines()
    except UnicodeError as exc:
        raise EvidenceError(f"{label} is not bounded canonical ASCII") from exc
    if len(lines) != len(expected_keys):
        raise EvidenceError(f"{label} has missing or unsupported fields")
    result: dict[str, str] = {}
    for expected_key, line in zip(expected_keys, lines):
        if "=" not in line:
            raise EvidenceError(f"{label} is not canonical key/value ASCII")
        key, value = line.split("=", 1)
        if key != expected_key or not value or key in result:
            raise EvidenceError(f"{label} has reordered or duplicate fields")
        if not re.fullmatch(r"[A-Za-z0-9_.:+/-]+", value):
            raise EvidenceError(f"{label} contains a noncanonical value")
        result[key] = value
    return result


def _validate_captured_present_state(raw: bytes, evidence: StateEvidence) -> None:
    """Reparse a carried present-state snapshot and match its derived facts."""

    document = _load_json(raw, maximum=MAX_STATE_BYTES, label="predecessor state")
    if not set(document).issubset(STATE_KEYS) or not {
        "version",
        "terraform_version",
        "serial",
        "lineage",
        "outputs",
        "resources",
    }.issubset(document):
        raise EvidenceError("predecessor state has missing or unsupported keys")
    if document["version"] != 4 or document["terraform_version"] != TOFU_VERSION:
        raise EvidenceError("predecessor state format or OpenTofu version is unsupported")
    serial = document["serial"]
    if type(serial) is not int or serial < 0 or serial > 2**63 - 1:
        raise EvidenceError("predecessor state serial is not bounded")
    lineage = document["lineage"]
    try:
        parsed_lineage = uuid.UUID(lineage) if type(lineage) is str else None
    except (ValueError, AttributeError) as exc:
        raise EvidenceError("predecessor state lineage is invalid") from exc
    if parsed_lineage is None or str(parsed_lineage) != lineage:
        raise EvidenceError("predecessor state lineage is not canonical")
    if document["outputs"] != {} or document["resources"] != []:
        raise EvidenceError("predecessor state is not the empty create-only state")
    if "check_results" in document and document["check_results"] not in (None, []):
        raise EvidenceError("predecessor state has unexpected check results")
    _same(hashlib.sha256(raw).hexdigest(), evidence.sha256, "predecessor state hash")
    _same(
        hashlib.sha256((lineage + "\n").encode("ascii")).hexdigest(),
        evidence.lineage_sha256,
        "predecessor state lineage",
    )
    if str(serial) != evidence.serial:
        raise EvidenceError("predecessor state serial does not match the evidence")


def parse_captured_state_evidence(
    raw: bytes,
    *,
    phase: str,
    state_raw: bytes | None,
) -> StateEvidence:
    """Validate the exact nine-line output preserved by the original state gate."""

    _phase_root(phase)
    pass_line = b"PASS Cloudflare pre-apply state evidence\n"
    if not raw.startswith(pass_line):
        raise EvidenceError("captured state evidence lacks the exact PASS record")
    values = _parse_canonical_kv(
        raw[len(pass_line):],
        expected_keys=STATE_EVIDENCE_KEYS,
        maximum=MAX_STATE_EVIDENCE_BYTES - len(pass_line),
        label="captured state evidence",
    )
    if values["state_backend"] != BACKEND_KIND:
        raise EvidenceError("captured state backend is not the protected local backend")
    backend_hash = _nonzero_sha256(
        values["backend_metadata_sha256"], "captured backend metadata"
    )
    state_path_hash = _nonzero_sha256(
        values["state_path_sha256"], "captured state path"
    )
    mode = values["state_mode"]
    if mode == "absent":
        if state_raw is not None or (
            values["state_sha256"],
            values["state_lineage_sha256"],
            values["state_serial"],
        ) != ("absent", "absent", "absent"):
            raise EvidenceError("absent predecessor state contains fabricated facts or bytes")
    elif mode == "present":
        if state_raw is None:
            raise EvidenceError("present predecessor state snapshot is missing")
        _nonzero_sha256(values["state_sha256"], "captured state hash")
        _nonzero_sha256(values["state_lineage_sha256"], "captured state lineage")
        if not re.fullmatch(r"0|[1-9][0-9]*", values["state_serial"]):
            raise EvidenceError("captured state serial is not canonical")
        if int(values["state_serial"]) > 2**63 - 1:
            raise EvidenceError("captured state serial is not bounded")
    else:
        raise EvidenceError("captured state mode is unsupported")

    binding = hashlib.sha256(
        _state_binding_bytes(
            phase_root=_phase_root(phase),
            backend_sha256=backend_hash,
            state_path_sha256=state_path_hash,
            mode=mode,
            state_sha256=values["state_sha256"],
            lineage_sha256=values["state_lineage_sha256"],
            serial=values["state_serial"],
        )
    ).hexdigest()
    _same(binding, values["state_binding_sha256"], "captured state binding")
    evidence = StateEvidence(
        mode=mode,
        backend_sha256=backend_hash,
        state_path_sha256=state_path_hash,
        sha256=values["state_sha256"],
        lineage_sha256=values["state_lineage_sha256"],
        serial=values["state_serial"],
        binding_sha256=binding,
    )
    if state_raw is not None:
        _validate_captured_present_state(state_raw, evidence)
    return evidence


def parse_predecessor_receipt(
    raw: bytes,
    *,
    state_evidence_raw: bytes,
    state_raw: bytes | None,
    expected_phase: str,
    expected_repository_commit: str,
    expected_saved_plan_sha256: str,
    expected_provider_lock_sha256: str,
) -> PredecessorEvidence:
    """Revalidate one original plan-gate receipt and its preserved state proof."""

    phase_root = _phase_root(expected_phase)
    if not COMMIT_RE.fullmatch(expected_repository_commit):
        raise EvidenceError("expected repository commit is not canonical")
    _nonzero_sha256(expected_saved_plan_sha256, "expected saved plan")
    _nonzero_sha256(expected_provider_lock_sha256, "expected provider lock")
    state = parse_captured_state_evidence(
        state_evidence_raw,
        phase=expected_phase,
        state_raw=state_raw,
    )
    receipt = _parse_canonical_kv(
        raw,
        expected_keys=PRE_STATE_RECEIPT_KEYS,
        maximum=MAX_PRE_STATE_RECEIPT_BYTES,
        label="predecessor pre-state receipt",
    )
    if receipt["phase_root"] != phase_root:
        raise EvidenceError("predecessor receipt phase root does not match")
    if receipt["repo_commit"] != expected_repository_commit:
        raise EvidenceError("predecessor receipt repository commit does not match")
    _same(
        receipt["plan_sha256"],
        expected_saved_plan_sha256,
        "predecessor saved plan",
    )
    _same(
        receipt["phase_lock_sha256"],
        expected_provider_lock_sha256,
        "predecessor provider lock",
    )
    for key in (
        "backend_metadata_sha256",
        "manual_attestation_sha256",
        "phase_lock_sha256",
        "workspace_attestation_sha256",
        "state_binding_sha256",
        "state_evidence_sha256",
        "plan_sha256",
    ):
        _nonzero_sha256(receipt[key], f"predecessor receipt {key}")
    _parse_utc(receipt["planned_utc"], "predecessor planned_utc")
    if receipt["state_mode"] != state.mode:
        raise EvidenceError("predecessor receipt state mode does not match evidence")
    if receipt["state_sha256"] != state.sha256:
        raise EvidenceError("predecessor receipt state hash does not match evidence")
    _same(
        receipt["state_binding_sha256"],
        state.binding_sha256,
        "predecessor state binding",
    )
    _same(
        receipt["backend_metadata_sha256"],
        state.backend_sha256,
        "predecessor backend metadata",
    )
    _same(
        receipt["state_evidence_sha256"],
        hashlib.sha256(state_evidence_raw).hexdigest(),
        "predecessor state evidence",
    )
    return PredecessorEvidence(
        mode=state.mode,
        state_sha256=state.sha256,
        state_binding_sha256=state.binding_sha256,
        backend_metadata_sha256=state.backend_sha256,
        workspace_attestation_sha256=receipt["workspace_attestation_sha256"],
        planned_utc=receipt["planned_utc"],
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
        state_evidence_sha256=hashlib.sha256(state_evidence_raw).hexdigest(),
    )


def validate_post_audit_chronology(
    *,
    revocation_verified_utc: str,
    post_audit_utc: str,
    now: dt.datetime | None = None,
) -> None:
    """Require read-only post-audit generation at/after rejection verification."""

    revoked = _parse_utc(
        revocation_verified_utc,
        "revocation/rejection verification time",
    )
    audited = _parse_utc(post_audit_utc, "read-only post-audit time")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise EvidenceError("validator clock must be timezone-aware")
    current = current.astimezone(dt.timezone.utc)
    if audited < revoked or audited > current:
        raise EvidenceError(
            "read-only post-audit did not follow revocation/rejection verification"
        )


def _reject_secret_text(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise EvidenceError("manual attestation is not strict UTF-8") from exc
    if any(pattern.search(text) for pattern in SECRET_PATTERNS):
        raise EvidenceError("manual attestation resembles secret material")


def _fresh_review(
    value: Any, *, generated: dt.datetime, maximum_age: int, label: str
) -> dt.datetime:
    observed = _parse_utc(value, label)
    age = (generated - observed).total_seconds()
    if age < 0 or age > maximum_age:
        raise EvidenceError(f"{label} is future-dated or stale")
    return observed


def parse_manual_attestation(
    raw: bytes,
    *,
    expected_phase: str,
    expected_bindings: dict[str, str],
    expected_scope_binding_sha256: str,
    expected_recovery_evidence_sha256: str | None = None,
    now: dt.datetime | None = None,
) -> AttestationEvidence:
    """Validate one hash-bound, closed-schema manual pre-apply review."""

    _phase_root(expected_phase)
    if set(expected_bindings) != BINDING_KEYS:
        raise EvidenceError("expected transaction bindings are incomplete")
    for key, value in expected_bindings.items():
        _nonzero_sha256(value, f"expected {key}")
    _nonzero_sha256(expected_scope_binding_sha256, "expected scope binding")
    if expected_recovery_evidence_sha256 is not None:
        _nonzero_sha256(
            expected_recovery_evidence_sha256,
            "expected recovery evidence",
        )

    _reject_secret_text(raw)
    document = _exact_object(
        _load_json(raw, maximum=MAX_ATTESTATION_BYTES, label="manual attestation"),
        ATTESTATION_KEYS,
        "manual attestation",
    )
    if document["schema"] != ATTESTATION_SCHEMA:
        raise EvidenceError("manual attestation schema is not supported")
    if document["phase"] != expected_phase:
        raise EvidenceError("manual attestation phase does not match")
    if document["evidence_role"] != ATTESTATION_ROLE:
        raise EvidenceError("manual attestation evidence role does not match")

    generated = _parse_utc(document["generated_utc"], "attestation generated_utc")
    expires = _parse_utc(document["expires_utc"], "attestation expires_utc")
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise EvidenceError("validator clock must be timezone-aware")
    ttl = (expires - generated).total_seconds()
    if ttl <= 0 or ttl > MAX_ATTESTATION_TTL_SECONDS:
        raise EvidenceError("manual attestation TTL exceeds five minutes")
    if now < generated or now > expires:
        raise EvidenceError("manual attestation is future-dated or expired")

    bindings = _exact_object(document["bindings"], BINDING_KEYS, "bindings")
    for key, expected in expected_bindings.items():
        actual = _nonzero_sha256(bindings[key], f"bindings.{key}")
        _same(actual, expected, f"bindings.{key}")

    entitlement = _exact_object(
        document["entitlement"], ENTITLEMENT_KEYS, "entitlement"
    )
    _fresh_review(
        entitlement["verified_at"],
        generated=generated,
        maximum_age=MAX_REVIEW_AGE_SECONDS,
        label="entitlement verified_at",
    )
    if type(entitlement["active_zone_count"]) is not int or entitlement[
        "active_zone_count"
    ] != 2:
        raise EvidenceError("entitlement does not attest exactly two active zones")
    if entitlement["active_zone_names"] != ["lidersea.com", "naranjo.online"]:
        raise EvidenceError("entitlement zone names are not the exact closed set")
    for key in (
        "all_zones_on_free_plan",
        "zero_trust_on_free_plan",
        "registrar_renewals_are_only_exception",
    ):
        _exact_bool(entitlement[key], True, f"entitlement.{key}")
    for key in (
        "paid_products_active",
        "trials_active",
        "unknown_billing_or_entitlement",
    ):
        _exact_bool(entitlement[key], False, f"entitlement.{key}")
    if (
        type(entitlement["authorized_infrastructure_usd_monthly"]) is not int
        or entitlement["authorized_infrastructure_usd_monthly"] != 0
    ):
        raise EvidenceError("entitlement does not attest exact zero-dollar infrastructure")

    account_security = _exact_object(
        document["account_security"], ACCOUNT_SECURITY_KEYS, "account security"
    )
    _fresh_review(
        account_security["verified_at"],
        generated=generated,
        maximum_age=MAX_REVIEW_AGE_SECONDS,
        label="account security verified_at",
    )
    for key in (
        "member_inventory_reviewed",
        "administrator_mfa_verified",
        "api_token_inventory_reviewed",
    ):
        _exact_bool(account_security[key], True, f"account_security.{key}")
    _exact_bool(
        account_security["unexpected_admin_or_token_authority"],
        False,
        "account_security.unexpected_admin_or_token_authority",
    )

    jit = _exact_object(document["jit_token"], JIT_TOKEN_KEYS, "JIT token")
    policy = PHASE_POLICY[expected_phase]
    if jit["resource_scope"] != policy["resource_scope"]:
        raise EvidenceError("JIT token resource scope is not phase-exact")
    if jit["permissions"] != list(policy["permissions"]):
        raise EvidenceError("JIT token permission set is not phase-exact")
    if jit["unavoidable_reach"] != list(policy["unavoidable_reach"]):
        raise EvidenceError("JIT token unavoidable reach is not phase-exact")
    token_id = _nonzero_sha256(jit["token_id_sha256"], "JIT token ID hash")
    scope_binding = _nonzero_sha256(
        jit["scope_binding_sha256"], "JIT token scope binding"
    )
    _same(scope_binding, expected_scope_binding_sha256, "JIT token scope binding")
    source_ip = _nonzero_sha256(
        jit["source_ip_policy_sha256"], "JIT token source-IP policy"
    )
    for key in (
        "source_ip_restricted",
        "active_status_verified",
        "only_write_token_live",
    ):
        _exact_bool(jit[key], True, f"jit_token.{key}")
    for key in ("plaintext_persisted", "plaintext_shared"):
        _exact_bool(jit[key], False, f"jit_token.{key}")
    token_issued = _parse_utc(jit["issued_at"], "JIT token issued_at")
    token_expires = _parse_utc(jit["expires_at"], "JIT token expires_at")
    token_ttl = (token_expires - token_issued).total_seconds()
    if token_ttl <= 0 or token_ttl > MAX_WRITE_TOKEN_TTL_SECONDS:
        raise EvidenceError("JIT token lifetime exceeds thirty minutes")
    if token_issued > generated or generated > token_expires or now > token_expires:
        raise EvidenceError("JIT token chronology is invalid for this review")

    recovery = _exact_object(
        document["operator_recovery"], RECOVERY_KEYS, "operator recovery"
    )
    _fresh_review(
        recovery["verified_at"],
        generated=generated,
        maximum_age=MAX_RECOVERY_AGE_SECONDS,
        label="operator recovery verified_at",
    )
    for key in (
        "physical_or_trusted_lan_recovery",
        "two_retained_sessions",
        "fresh_third_login",
    ):
        _exact_bool(recovery[key], True, f"operator_recovery.{key}")
    recovery_hash = _nonzero_sha256(
        recovery["evidence_sha256"], "operator recovery evidence"
    )
    if expected_recovery_evidence_sha256 is not None:
        _same(
            recovery_hash,
            expected_recovery_evidence_sha256,
            "operator recovery evidence",
        )

    review = _exact_object(document["review"], REVIEW_KEYS, "review")
    _exact_bool(review["approved"], True, "review.approved")
    approved_at = _fresh_review(
        review["approved_at"],
        generated=generated,
        maximum_age=MAX_ATTESTATION_TTL_SECONDS,
        label="review approved_at",
    )
    if approved_at > generated:
        raise EvidenceError("review approval occurred after attestation generation")
    if review["reviewer_role"] != "account-owner":
        raise EvidenceError("reviewer role is not the account owner")
    approval_hash = _nonzero_sha256(review["approval_sha256"], "review approval")

    all_hashes = [
        *bindings.values(),
        token_id,
        scope_binding,
        source_ip,
        recovery_hash,
        approval_hash,
    ]
    if len(set(all_hashes)) != len(all_hashes):
        raise EvidenceError("semantically distinct evidence hashes were reused")

    return AttestationEvidence(
        phase=expected_phase,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _read_bounded(path_text: str, maximum: int, label: str) -> bytes:
    try:
        path = Path(path_text)
        size = path.stat().st_size
        if size <= 0 or size > maximum:
            raise EvidenceError(f"{label} size is outside the accepted bound")
        return path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"{label} could not be read") from exc


def _parser() -> SafeArgumentParser:
    parser = SafeArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    state = subparsers.add_parser("state")
    state.add_argument("--phase", required=True, choices=PHASES)
    state.add_argument("--backend-metadata", required=True)
    state.add_argument("--expected-state-path", required=True)
    state_source = state.add_mutually_exclusive_group(required=True)
    state_source.add_argument("--state-file")
    state_source.add_argument("--state-absent", action="store_true")

    manual = subparsers.add_parser("manual")
    manual.add_argument("--attestation", required=True)
    manual.add_argument("--phase", required=True, choices=PHASES)
    for key in sorted(BINDING_KEYS):
        manual.add_argument("--" + key.replace("_", "-"), required=True)
    manual.add_argument("--scope-binding-sha256", required=True)
    manual.add_argument("--recovery-evidence-sha256")

    predecessor = subparsers.add_parser("predecessor")
    predecessor.add_argument("--receipt", required=True)
    predecessor.add_argument("--state-evidence", required=True)
    predecessor.add_argument("--phase", required=True, choices=PHASES)
    predecessor.add_argument("--repository-commit", required=True)
    predecessor.add_argument("--saved-plan-sha256", required=True)
    predecessor.add_argument("--provider-lock-sha256", required=True)
    predecessor_state = predecessor.add_mutually_exclusive_group(required=True)
    predecessor_state.add_argument("--state-file")
    predecessor_state.add_argument("--state-absent", action="store_true")

    chronology = subparsers.add_parser("chronology")
    chronology.add_argument("--revocation-verified-utc", required=True)
    chronology.add_argument("--post-audit-utc", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.operation == "state":
            backend_raw = _read_bounded(
                args.backend_metadata,
                MAX_BACKEND_BYTES,
                "backend metadata",
            )
            raw = None
            if args.state_file is not None:
                raw = _read_bounded(args.state_file, MAX_STATE_BYTES, "state")
            evidence = parse_state_evidence(
                raw,
                backend_raw=backend_raw,
                phase=args.phase,
                expected_state_path=args.expected_state_path,
            )
            print("PASS Cloudflare pre-apply state evidence")
            print(f"state_backend={BACKEND_KIND}")
            print(f"backend_metadata_sha256={evidence.backend_sha256}")
            print(f"state_path_sha256={evidence.state_path_sha256}")
            print(f"state_mode={evidence.mode}")
            print(f"state_sha256={evidence.sha256}")
            print(f"state_lineage_sha256={evidence.lineage_sha256}")
            print(f"state_serial={evidence.serial}")
            print(f"state_binding_sha256={evidence.binding_sha256}")
            return 0

        if args.operation == "predecessor":
            state_raw = None
            if args.state_file is not None:
                state_raw = _read_bounded(
                    args.state_file,
                    MAX_STATE_BYTES,
                    "predecessor state",
                )
            evidence = parse_predecessor_receipt(
                _read_bounded(
                    args.receipt,
                    MAX_PRE_STATE_RECEIPT_BYTES,
                    "predecessor pre-state receipt",
                ),
                state_evidence_raw=_read_bounded(
                    args.state_evidence,
                    MAX_STATE_EVIDENCE_BYTES,
                    "captured state evidence",
                ),
                state_raw=state_raw,
                expected_phase=args.phase,
                expected_repository_commit=args.repository_commit,
                expected_saved_plan_sha256=args.saved_plan_sha256,
                expected_provider_lock_sha256=args.provider_lock_sha256,
            )
            print("PASS Cloudflare predecessor pre-state evidence")
            print(f"state_mode={evidence.mode}")
            print(f"state_sha256={evidence.state_sha256}")
            print(f"state_binding_sha256={evidence.state_binding_sha256}")
            print(f"backend_metadata_sha256={evidence.backend_metadata_sha256}")
            print(
                "workspace_attestation_sha256="
                f"{evidence.workspace_attestation_sha256}"
            )
            print(f"planned_utc={evidence.planned_utc}")
            print(f"pre_state_receipt_sha256={evidence.receipt_sha256}")
            print(f"state_evidence_sha256={evidence.state_evidence_sha256}")
            return 0

        if args.operation == "chronology":
            validate_post_audit_chronology(
                revocation_verified_utc=args.revocation_verified_utc,
                post_audit_utc=args.post_audit_utc,
            )
            print("PASS Cloudflare post-audit chronology")
            return 0

        expected_bindings = {
            key: getattr(args, key) for key in sorted(BINDING_KEYS)
        }
        raw = _read_bounded(
            args.attestation,
            MAX_ATTESTATION_BYTES,
            "manual attestation",
        )
        evidence = parse_manual_attestation(
            raw,
            expected_phase=args.phase,
            expected_bindings=expected_bindings,
            expected_scope_binding_sha256=args.scope_binding_sha256,
            expected_recovery_evidence_sha256=args.recovery_evidence_sha256,
        )
        print("PASS Cloudflare pre-apply manual attestation")
        print(f"phase={evidence.phase}")
        print(f"attestation_sha256={evidence.sha256}")
        print(f"evidence_role={ATTESTATION_ROLE}")
        return 0
    except (EvidenceError, OSError, ValueError):
        print("FAIL Cloudflare pre-apply evidence", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
