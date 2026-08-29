#!/usr/bin/env python3
"""Validate one local Cloudflare phase-token ceremony receipt offline.

The receipt is an operator attestation plus a hash-bound live-verification
record.  This validator neither authenticates to Cloudflare nor treats the
document as cryptographic proof of the claims it contains.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, NamedTuple


SCHEMA = "cloudflare-phase-token-receipt-v2"
MAX_RECEIPT_BYTES = 16 * 1024
MAX_CLOCK_SKEW_SECONDS = 300
RECEIPT_PATH_ENV = "CLOUDFLARE_PHASE_TOKEN_RECEIPT"
CREDENTIAL_ROOT_ENV = "WEBSITE_INFRA_CREDENTIAL_ROOT"
PHASE_ENV = "CLOUDFLARE_RECEIPT_PHASE"
REPO_ROOT = Path(__file__).resolve().parents[1]

NONZERO_SHA256_RE = re.compile(r"(?=.*[1-9a-f])[0-9a-f]{64}\Z")
UTC_SECONDS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SECRET_PATTERNS = (
    re.compile(r"AGE-SECRET-KEY-(?:PQ-)?1[A-Z0-9]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:cfk|cfut|cfat)_[A-Za-z0-9]{40}[0-9A-Fa-f]{8}\b"),
    re.compile(r"(?i)\bcloudflare_api_token\b[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9+/_-])eyJ[A-Za-z0-9+/_-]{77,4093}={0,2}(?![A-Za-z0-9+/_=-])"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,})\b"),
)

BINDING_ARGUMENTS = {
    "target_sha256": ("target-sha256", "CLOUDFLARE_EXPECTED_TARGET_SHA256"),
    "workspace_attestation_sha256": (
        "workspace-attestation-sha256",
        "CLOUDFLARE_EXPECTED_WORKSPACE_ATTESTATION_SHA256",
    ),
    "saved_plan_sha256": (
        "saved-plan-sha256",
        "CLOUDFLARE_EXPECTED_SAVED_PLAN_SHA256",
    ),
    "state_binding_sha256": (
        "state-binding-sha256",
        "CLOUDFLARE_EXPECTED_STATE_BINDING_SHA256",
    ),
    "state_sha256": ("state-sha256", "CLOUDFLARE_EXPECTED_STATE_SHA256"),
    "provider_lock_sha256": (
        "provider-lock-sha256",
        "CLOUDFLARE_EXPECTED_PROVIDER_LOCK_SHA256",
    ),
    "repository_commit_sha256": (
        "repository-commit-sha256",
        "CLOUDFLARE_EXPECTED_REPOSITORY_COMMIT_SHA256",
    ),
    "audit_sha256": ("audit-sha256", "CLOUDFLARE_EXPECTED_AUDIT_SHA256"),
    "post_audit_sha256": (
        "post-audit-sha256",
        "CLOUDFLARE_EXPECTED_POST_AUDIT_SHA256",
    ),
}
STATE_MODE_ARGUMENT = ("state-mode", "CLOUDFLARE_EXPECTED_STATE_MODE")
EXTRA_EXPECTED_ARGUMENTS = {
    "token_id_sha256": (
        "token-id-sha256",
        "CLOUDFLARE_EXPECTED_TOKEN_ID_SHA256",
    ),
    "source_ip_policy_sha256": (
        "source-ip-policy-sha256",
        "CLOUDFLARE_EXPECTED_SOURCE_IP_POLICY_SHA256",
    ),
    "preflight_evidence_sha256": (
        "preflight-evidence-sha256",
        "CLOUDFLARE_EXPECTED_PREFLIGHT_EVIDENCE_SHA256",
    ),
    "postflight_evidence_sha256": (
        "postflight-evidence-sha256",
        "CLOUDFLARE_EXPECTED_POSTFLIGHT_EVIDENCE_SHA256",
    ),
}

PHASE_POLICY = {
    "admin-tunnel": {
        "operation": "apply",
        "resource_scope": "exact-account",
        "permissions": ("Cloudflare One Connector: cloudflared Write",),
        "unavoidable_reach": (
            "all-cloudflared-connectors-and-tunnels-in-account",
        ),
    },
    "admin-policies": {
        "operation": "apply",
        "resource_scope": "exact-account",
        "permissions": ("Zero Trust Write",),
        "unavoidable_reach": ("all-zero-trust-resources-in-account",),
    },
    "admin-route": {
        "operation": "apply",
        "resource_scope": "exact-account",
        "permissions": ("Cloudflare One Networks Write",),
        "unavoidable_reach": (
            "all-private-routes-and-virtual-networks-in-account",
        ),
    },
    "admin-api": {
        "operation": "apply",
        "resource_scope": "exact-account",
        "permissions": ("Zero Trust Write",),
        "unavoidable_reach": ("all-zero-trust-resources-in-account",),
    },
    "public-edge": {
        "operation": "apply",
        "resource_scope": "exact-account",
        "permissions": ("Cloudflare One Connector: cloudflared Write",),
        "unavoidable_reach": (
            "all-cloudflared-connectors-and-tunnels-in-account",
        ),
    },
    "public-dns-naranjo": {
        "operation": "apply",
        "resource_scope": "exact-zone",
        "permissions": ("DNS Write",),
        "unavoidable_reach": ("all-dns-records-in-exact-zone",),
    },
    "public-dns-lidersea": {
        "operation": "apply",
        "resource_scope": "exact-zone",
        "permissions": ("DNS Write",),
        "unavoidable_reach": ("all-dns-records-in-exact-zone",),
    },
    "audit": {
        "operation": "audit",
        "resource_scope": "exact-account-and-all-account-zones",
        "permissions": (
            "Billing Read",
            "Zone Read",
            "DNS Read",
            "Cloudflare One Connector: cloudflared Read",
            "Cloudflare One Networks Read",
            "Zero Trust Read",
            "Access: Apps and Policies Read",
            "Access: Audit Logs Read",
        ),
        "unavoidable_reach": (
            "billing-metadata-in-account",
            "all-zones-and-dns-records-in-account",
            "all-cloudflared-connectors-and-tunnels-in-account",
            "all-private-routes-and-virtual-networks-in-account",
            "all-zero-trust-resources-in-account",
            "all-access-apps-policies-and-audit-logs-in-account",
        ),
    },
}

TOP_LEVEL_KEYS = {
    "schema",
    "phase",
    "operation",
    "token_policy",
    "bindings",
    "controls",
    "verification",
}
TOKEN_POLICY_KEYS = {
    "owner_type",
    "verification_endpoint_kind",
    "token_id_sha256",
    "resource_scope",
    "permissions",
    "unavoidable_reach",
    "issued_at",
    "expires_at",
    "source_ip_restricted",
    "source_ip_policy_sha256",
}
BINDING_KEYS = set(BINDING_ARGUMENTS) | {"state_mode"}
CONTROL_KEYS = {
    "mfa_verified",
    "token_plaintext_persisted",
    "token_plaintext_shared",
    "billing_write",
    "registrar_write",
    "api_tokens_write",
    "git_write_authority",
    "cluster_authority",
    "tunnel_runtime_authority",
}
VERIFICATION_KEYS = {"preflight", "postflight"}
PREFLIGHT_KEYS = {
    "verified_at",
    "token_active",
    "revocation_status",
    "token_id_sha256",
    "evidence_sha256",
}
POSTFLIGHT_KEYS = {
    "revoked_at",
    "verified_at",
    "revocation_status",
    "verified_with_separate_credential",
    "revoked_token_rejected",
    "token_id_sha256",
    "evidence_sha256",
}


class DuplicateKeyError(ValueError):
    """Raised when JSON tries to overwrite an earlier object member."""


class ReceiptError(ValueError):
    """A content-neutral validation failure safe to show to an operator."""


class LoadedReceipt(NamedTuple):
    """Validated non-secret output metadata."""

    phase: str
    sha256: str


class SafeArgumentParser(argparse.ArgumentParser):
    """Keep malformed CLI values out of diagnostics and transcript logs."""

    def error(self, _message: str) -> None:
        raise ReceiptError("command-line arguments are invalid")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("receipt contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ReceiptError("receipt contains a non-finite JSON number")


def _exact_object(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReceiptError(f"receipt {context} is not an object")
    if set(value) != keys:
        raise ReceiptError(f"receipt {context} has missing or unsupported keys")
    return value


def _exact_bool(value: Any, expected: bool, context: str) -> None:
    if type(value) is not bool or value is not expected:
        raise ReceiptError(f"receipt {context} is not the required boolean")


def _nonzero_sha256(value: Any, context: str) -> str:
    if type(value) is not str or not NONZERO_SHA256_RE.fullmatch(value):
        raise ReceiptError(f"receipt {context} is not a nonzero lowercase SHA-256")
    return value


def _optional_sha256(value: Any, required: bool, context: str) -> str | None:
    if not required:
        if value is not None:
            raise ReceiptError(f"receipt {context} must be null for this phase")
        return None
    return _nonzero_sha256(value, context)


def _parse_utc_seconds(value: Any, context: str) -> dt.datetime:
    if type(value) is not str or not UTC_SECONDS_RE.fullmatch(value):
        raise ReceiptError(f"receipt {context} is not canonical UTC seconds")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ReceiptError(f"receipt {context} is not a valid UTC timestamp") from error
    return parsed.replace(tzinfo=dt.timezone.utc)


def _compare_digest(actual: str, expected: str, context: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise ReceiptError(f"receipt {context} does not match the external binding")


def _reject_cross_domain_hash_reuse(
    expected_bindings: dict[str, str | None],
    expected_extra_hashes: dict[str, str],
) -> None:
    """Require a distinct digest for every semantically different artifact.

    The same token identifier intentionally appears in the token, preflight,
    and postflight sections, but it has only one external binding here. Every
    other entry represents different bytes and must not be satisfied by copying
    one convenient hash throughout an operator-authored receipt.
    """

    owners: dict[str, str] = {}
    for name, value in (
        list(expected_bindings.items()) + list(expected_extra_hashes.items())
    ):
        if value is None:
            continue
        previous = owners.get(value)
        if previous is not None:
            raise ReceiptError(
                "expected external bindings reuse one digest across evidence domains"
            )
        owners[value] = name


def parse_receipt(
    raw: bytes,
    *,
    expected_phase: str,
    expected_state_mode: str | None,
    expected_bindings: dict[str, str | None],
    expected_extra_hashes: dict[str, str],
    now: dt.datetime | None = None,
) -> LoadedReceipt:
    """Validate bounded receipt bytes without invoking Cloudflare or a shell."""

    if (
        type(expected_bindings) is not dict
        or set(expected_bindings) != set(BINDING_ARGUMENTS)
    ):
        raise ReceiptError("expected binding set has missing or unsupported keys")
    expected_extra_keys = set(EXTRA_EXPECTED_ARGUMENTS)
    if (
        type(expected_extra_hashes) is not dict
        or set(expected_extra_hashes) != expected_extra_keys
    ):
        raise ReceiptError("expected verification set has missing or unsupported keys")
    for name, value in expected_extra_hashes.items():
        _nonzero_sha256(value, f"expected {name} binding")
    for name, value in expected_bindings.items():
        if value is not None:
            _nonzero_sha256(value, f"expected {name} binding")
    _reject_cross_domain_hash_reuse(expected_bindings, expected_extra_hashes)

    if not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt is empty or exceeds the 16 KiB limit")
    if raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw:
        raise ReceiptError("receipt is not strict unmarked UTF-8 JSON")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ReceiptError("receipt is not strict UTF-8 JSON") from error
    if any(pattern.search(text) for pattern in SECRET_PATTERNS):
        raise ReceiptError("receipt contains a forbidden credential or private key")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except DuplicateKeyError:
        raise
    except (json.JSONDecodeError, ReceiptError, RecursionError) as error:
        raise ReceiptError("receipt is not strict JSON") from error

    receipt = _exact_object(document, TOP_LEVEL_KEYS, "root")
    if expected_phase not in PHASE_POLICY:
        raise ReceiptError("expected phase is unsupported")
    if receipt["schema"] != SCHEMA:
        raise ReceiptError("receipt schema is unsupported")
    if type(receipt["phase"]) is not str or receipt["phase"] != expected_phase:
        raise ReceiptError("receipt phase does not match the expected phase")
    policy = PHASE_POLICY[expected_phase]
    if receipt["operation"] != policy["operation"]:
        raise ReceiptError("receipt operation does not match the phase")

    token = _exact_object(receipt["token_policy"], TOKEN_POLICY_KEYS, "token policy")
    owner_type = token["owner_type"]
    if owner_type not in {"user", "account"}:
        raise ReceiptError("receipt token owner type is unsupported")
    expected_endpoint = {
        "user": "user-token-verify",
        "account": "account-token-verify",
    }[owner_type]
    if token["verification_endpoint_kind"] != expected_endpoint:
        raise ReceiptError("receipt token verification endpoint does not match ownership")
    token_id_hash = _nonzero_sha256(token["token_id_sha256"], "token-ID binding")
    _compare_digest(
        token_id_hash,
        expected_extra_hashes["token_id_sha256"],
        "token-ID binding",
    )
    for key in ("resource_scope", "permissions", "unavoidable_reach"):
        expected = policy[key]
        actual = token[key]
        if isinstance(expected, tuple):
            if type(actual) is not list or tuple(actual) != expected:
                raise ReceiptError(f"receipt token {key} does not match the phase policy")
        elif actual != expected:
            raise ReceiptError(f"receipt token {key} does not match the phase policy")
    _exact_bool(token["source_ip_restricted"], True, "source-IP restriction")
    source_ip_hash = _nonzero_sha256(
        token["source_ip_policy_sha256"], "source-IP policy binding"
    )
    _compare_digest(
        source_ip_hash,
        expected_extra_hashes["source_ip_policy_sha256"],
        "source-IP policy binding",
    )

    issued_at = _parse_utc_seconds(token["issued_at"], "issue time")
    expires_at = _parse_utc_seconds(token["expires_at"], "expiry time")
    ttl = (expires_at - issued_at).total_seconds()
    maximum_ttl = 3600 if expected_phase == "audit" else 1800
    if ttl <= 0 or ttl > maximum_ttl:
        raise ReceiptError("receipt token lifetime exceeds the phase maximum")

    bindings = _exact_object(receipt["bindings"], BINDING_KEYS, "bindings")
    apply_phase = policy["operation"] == "apply"
    if apply_phase:
        if expected_state_mode not in {"absent", "present"}:
            raise ReceiptError("expected state mode is absent or unsupported")
        if bindings["state_mode"] != expected_state_mode:
            raise ReceiptError("receipt state mode does not match the external binding")
    else:
        if expected_state_mode is not None:
            raise ReceiptError("expected state mode is inapplicable")
        if bindings["state_mode"] is not None:
            raise ReceiptError("receipt state mode must be null for this phase")
    required_apply_only = {
        "saved_plan_sha256",
        "state_binding_sha256",
        "state_sha256",
        "provider_lock_sha256",
        "post_audit_sha256",
    }
    for binding_name in BINDING_ARGUMENTS:
        required = binding_name not in required_apply_only or (
            apply_phase
            and (
                binding_name != "state_sha256"
                or expected_state_mode == "present"
            )
        )
        actual = _optional_sha256(
            bindings[binding_name], required, f"{binding_name} binding"
        )
        expected = expected_bindings[binding_name]
        if required:
            if expected is None:
                raise ReceiptError(f"expected {binding_name} binding is absent")
            _nonzero_sha256(expected, f"expected {binding_name} binding")
            _compare_digest(actual, expected, f"{binding_name} binding")
        elif expected is not None:
            raise ReceiptError(f"expected {binding_name} binding is inapplicable")

    controls = _exact_object(receipt["controls"], CONTROL_KEYS, "controls")
    _exact_bool(controls["mfa_verified"], True, "MFA verification")
    for control in CONTROL_KEYS - {"mfa_verified"}:
        _exact_bool(controls[control], False, control)

    verification = _exact_object(
        receipt["verification"], VERIFICATION_KEYS, "verification"
    )
    preflight = _exact_object(
        verification["preflight"], PREFLIGHT_KEYS, "preflight verification"
    )
    postflight = _exact_object(
        verification["postflight"], POSTFLIGHT_KEYS, "postflight verification"
    )
    _exact_bool(preflight["token_active"], True, "preflight token status")
    if preflight["revocation_status"] != "pending":
        raise ReceiptError("receipt preflight revocation status is not pending")
    if postflight["revocation_status"] != "verified":
        raise ReceiptError("receipt postflight revocation status is not verified")
    _exact_bool(
        postflight["verified_with_separate_credential"],
        True,
        "postflight separate-credential verification",
    )
    _exact_bool(
        postflight["revoked_token_rejected"],
        True,
        "postflight rejected-token verification",
    )
    for section, section_name in (
        (preflight, "preflight"),
        (postflight, "postflight"),
    ):
        evidence_token_id_hash = _nonzero_sha256(
            section["token_id_sha256"], f"{section_name} token-ID binding"
        )
        _compare_digest(
            evidence_token_id_hash,
            token_id_hash,
            f"{section_name} token-ID binding",
        )
    preflight_hash = _nonzero_sha256(
        preflight["evidence_sha256"], "preflight evidence binding"
    )
    postflight_hash = _nonzero_sha256(
        postflight["evidence_sha256"], "postflight evidence binding"
    )
    _compare_digest(
        preflight_hash,
        expected_extra_hashes["preflight_evidence_sha256"],
        "preflight evidence binding",
    )
    _compare_digest(
        postflight_hash,
        expected_extra_hashes["postflight_evidence_sha256"],
        "postflight evidence binding",
    )
    if hmac.compare_digest(preflight_hash, postflight_hash):
        raise ReceiptError("preflight and postflight evidence bindings are not separate")

    preflight_at = _parse_utc_seconds(preflight["verified_at"], "preflight time")
    revoked_at = _parse_utc_seconds(postflight["revoked_at"], "revocation time")
    postflight_at = _parse_utc_seconds(postflight["verified_at"], "postflight time")
    if not issued_at <= preflight_at <= revoked_at <= postflight_at:
        raise ReceiptError("receipt ceremony timestamps are not ordered")
    if revoked_at > expires_at:
        raise ReceiptError("receipt token was not revoked before expiry")
    current_time = now or dt.datetime.now(dt.timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=dt.timezone.utc)
    if postflight_at > current_time.astimezone(dt.timezone.utc) + dt.timedelta(
        seconds=MAX_CLOCK_SKEW_SECONDS
    ):
        raise ReceiptError("receipt postflight time is in the future")

    return LoadedReceipt(expected_phase, hashlib.sha256(raw).hexdigest())


# One domain failure type parameterizes the shared no-follow walk helpers.
# The four private-file validators carry byte-identical copies of the helper
# family (pinned by tests/security/test_nofollow_helper_drift.py); fix any
# defect in every copy in the same change.
_WALK_ERROR = ReceiptError


def _path_state(metadata: os.stat_result) -> tuple[int, ...]:
    """Bind a path entry and open descriptor to all stable custody metadata."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        getattr(metadata, "st_uid", -1),
        getattr(metadata, "st_gid", -1),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        getattr(metadata, "st_file_attributes", 0),
        getattr(metadata, "st_reparse_tag", 0),
    )


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    """Treat POSIX links and Windows reparse points as path indirection."""

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def _ancestor_state(metadata: os.stat_result) -> tuple[int, ...]:
    """Bind an ancestor DIRECTORY to the fields that identify that directory.

    A directory's st_nlink, st_size, st_mtime_ns and st_ctime_ns describe its
    CONTENTS, not this path: every one of them changes when an unrelated
    process creates or removes some other entry inside it. Snapshotting them
    made the walk refuse a completely stable path whenever a sibling process
    touched a shared ancestor -- and the per-user temporary root is a shared
    ancestor of every private file staged under it, so one concurrent
    ``mkdtemp`` anywhere on the machine turned a valid read into a fail-closed
    refusal. That is issue #158's transient class, measured on an untouched
    path as st_nlink 5372 -> 5373 with st_dev/st_ino/st_mode/st_uid/st_gid
    unchanged.

    Nothing a path-substitution attack must do is dropped. st_dev and st_ino
    identify the directory itself, so replacing it fails; st_mode carries the
    type bits, so swapping it for a file or a symlink fails (and
    ``_is_link_or_reparse`` refuses the symlink outright before this runs);
    st_uid/st_gid catch a concurrent chown; the Windows attribute and reparse
    fields keep the reparse-point decision intact. The FINAL component keeps
    the complete ``_path_state`` tuple, and the read window is separately
    bound to the open descriptor and to its own parent directory handle, so
    no field removed here was the only witness to anything.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        getattr(metadata, "st_uid", -1),
        getattr(metadata, "st_gid", -1),
        getattr(metadata, "st_file_attributes", 0),
        getattr(metadata, "st_reparse_tag", 0),
    )


def _path_chain(path: Path) -> tuple[tuple[str, tuple[int, ...]], ...]:
    """Snapshot every ancestor so directory replacement cannot pass silently."""

    result: list[tuple[str, tuple[int, ...]]] = []
    components = (*reversed(path.parents), path)
    for position, component in enumerate(components):
        metadata = component.lstat()
        if _is_link_or_reparse(metadata):
            raise _WALK_ERROR()
        state = (
            _path_state(metadata)
            if position == len(components) - 1
            else _ancestor_state(metadata)
        )
        result.append((os.path.normcase(str(component)), state))
    return tuple(result)


def _within(candidate: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath(
            (os.path.normcase(str(candidate)), os.path.normcase(str(parent)))
        ) == os.path.normcase(str(parent))
    except ValueError:
        return False


def _open_posix_no_follow(path: Path, flags: int) -> tuple[int, int, str]:
    """Traverse an absolute POSIX path through no-follow directory handles."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        os.name != "posix"
        or nofollow is None
        or directory is None
        or os.open not in os.supports_dir_fd
        or not path.is_absolute()
        or not path.name
    ):
        raise _WALK_ERROR()
    directory_flags = os.O_RDONLY | nofollow | directory
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    parent_descriptor = os.open("/", directory_flags)
    try:
        for component in path.parts[1:-1]:
            if component in {"", ".", ".."}:
                raise _WALK_ERROR()
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        descriptor = os.open(path.name, flags | nofollow, dir_fd=parent_descriptor)
    except BaseException:
        os.close(parent_descriptor)
        raise
    return descriptor, parent_descriptor, path.name


def _credential_root(path_text: str) -> Path:
    """Resolve one explicit protected root without accepting aliases or links."""

    if not path_text or "\x00" in path_text:
        raise ReceiptError("protected credential root was not supplied explicitly")
    supplied = Path(path_text)
    if not supplied.is_absolute() or any(part in {".", ".."} for part in supplied.parts):
        raise ReceiptError("protected credential root must be absolute and normalized")
    if os.name == "nt":
        if not re.match(r"^[A-Za-z]:[\\/]", path_text):
            raise ReceiptError("protected credential root must use a local drive letter")
        if any(
            ":" in part or part.endswith((" ", "."))
            for part in supplied.parts[1:]
        ):
            raise ReceiptError("protected credential root uses an ambiguous component")
    absolute = Path(os.path.abspath(os.path.normpath(str(supplied))))
    if _within(absolute, REPO_ROOT):
        raise ReceiptError("protected credential root must be outside the repository")
    try:
        resolved = absolute.resolve(strict=True)
        metadata = absolute.lstat()
        _path_chain(absolute)
    except (OSError, ReceiptError) as error:
        raise ReceiptError("protected credential root is unavailable") from error
    if (
        os.path.normcase(str(resolved)) != os.path.normcase(str(absolute))
        or not stat.S_ISDIR(metadata.st_mode)
        or _is_link_or_reparse(metadata)
    ):
        raise ReceiptError("protected credential root is not an exact directory")
    if os.name == "posix" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ReceiptError("protected credential root ownership or mode is unsafe")
    return absolute


def read_receipt(path_text: str, credential_root_text: str | None = None) -> bytes:
    """Read one protected-workspace regular file without following links."""

    if credential_root_text is None:
        credential_root_text = os.environ.get(CREDENTIAL_ROOT_ENV)
    if credential_root_text is None:
        raise ReceiptError("protected credential root was not supplied explicitly")
    protected_root = _credential_root(credential_root_text)

    if not path_text or "\x00" in path_text:
        raise ReceiptError("receipt path was not supplied explicitly")
    supplied = Path(path_text)
    if not supplied.is_absolute() or any(part in {".", ".."} for part in supplied.parts):
        raise ReceiptError("receipt path must be absolute and normalized")
    if os.name == "nt":
        if not re.match(r"^[A-Za-z]:[\\/]", path_text):
            raise ReceiptError("receipt path must use a local drive letter")
        if any(
            ":" in part or part.endswith((" ", "."))
            for part in supplied.parts[1:]
        ):
            raise ReceiptError("receipt path uses an ambiguous Windows component")
    absolute = Path(os.path.abspath(os.path.normpath(str(supplied))))
    if _within(absolute, REPO_ROOT):
        raise ReceiptError("receipt path must be outside the repository")
    if (
        not _within(absolute, protected_root)
        or os.path.normcase(str(absolute)) == os.path.normcase(str(protected_root))
    ):
        raise ReceiptError("receipt path must remain inside the protected workspace")
    try:
        resolved = absolute.resolve(strict=True)
        if os.path.normcase(str(resolved)) != os.path.normcase(str(absolute)):
            raise ReceiptError("receipt path must not traverse a link")
        before_chain = _path_chain(absolute)
        before = absolute.lstat()
    except ReceiptError:
        raise
    except OSError as error:
        raise ReceiptError("receipt file is unavailable") from error
    if not stat.S_ISREG(before.st_mode):
        raise ReceiptError("receipt must be a regular file")
    if before.st_nlink != 1:
        raise ReceiptError("receipt must have exactly one hard link")
    if os.name == "posix" and (
        before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise ReceiptError("receipt ownership or mode is unsafe")
    if before.st_size <= 0 or before.st_size > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt is empty or exceeds the 16 KiB limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor: int | None = None
    final_name: str | None = None
    try:
        if os.name == "posix":
            descriptor, parent_descriptor, final_name = _open_posix_no_follow(
                absolute, flags
            )
        else:
            descriptor = os.open(absolute, flags)
        try:
            opened_before = os.fstat(descriptor)
            parent_before = (
                os.fstat(parent_descriptor)
                if parent_descriptor is not None
                else None
            )
            if _path_state(opened_before) != _path_state(before):
                raise ReceiptError("receipt changed while opening")
            chunks: list[bytes] = []
            remaining = MAX_RECEIPT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            opened_after = os.fstat(descriptor)
            if parent_descriptor is not None and final_name is not None:
                parent_after = os.fstat(parent_descriptor)
                directory_entry = os.stat(
                    final_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    parent_before is None
                    or _path_state(parent_before) != _path_state(parent_after)
                    or _path_state(directory_entry) != _path_state(opened_after)
                ):
                    raise ReceiptError("receipt path changed while reading")
                reopened, reopened_parent, reopened_name = _open_posix_no_follow(
                    absolute, flags
                )
                try:
                    if (
                        reopened_name != final_name
                        or _path_state(os.fstat(reopened))
                        != _path_state(opened_after)
                        or _path_state(os.fstat(reopened_parent))
                        != _path_state(parent_after)
                    ):
                        raise ReceiptError("receipt path changed while reading")
                finally:
                    os.close(reopened)
                    os.close(reopened_parent)
        finally:
            os.close(descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)
    except ReceiptError:
        raise
    except OSError as error:
        raise ReceiptError("receipt cannot be opened safely") from error
    if (
        _path_state(opened_before) != _path_state(opened_after)
        or opened_after.st_size != len(raw)
    ):
        raise ReceiptError("receipt changed while reading")
    try:
        after_chain = _path_chain(absolute)
        after = absolute.lstat()
        final_resolved = absolute.resolve(strict=True)
    except (OSError, ReceiptError) as error:
        raise ReceiptError("receipt path changed while reading") from error
    if (
        before_chain != after_chain
        or _path_state(after) != _path_state(opened_after)
        or os.path.normcase(str(final_resolved)) != os.path.normcase(str(absolute))
    ):
        raise ReceiptError("receipt path changed while reading")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt exceeds the 16 KiB limit")
    return raw


def _source_value(cli_value: str | None, environment_name: str) -> str | None:
    environment_value = os.environ.get(environment_name)
    if cli_value is not None and environment_value is not None:
        raise ReceiptError("one input was supplied through both CLI and environment")
    return cli_value if cli_value is not None else environment_value


def _expected_hash(
    cli_value: str | None,
    environment_name: str,
    *,
    required: bool,
) -> str | None:
    value = _source_value(cli_value, environment_name)
    if value is None:
        if required:
            raise ReceiptError("one required expected binding was not supplied")
        return None
    if not required:
        raise ReceiptError("one inapplicable expected binding was supplied")
    return _nonzero_sha256(value, "expected external binding")


def _argument_parser() -> SafeArgumentParser:
    parser = SafeArgumentParser(
        description="Validate a local Cloudflare phase-token receipt offline.",
    )
    parser.add_argument("--receipt", metavar="PATH")
    parser.add_argument("--credential-root", metavar="PATH")
    parser.add_argument("--phase")
    parser.add_argument(f"--{STATE_MODE_ARGUMENT[0]}")
    for option, _environment_name in BINDING_ARGUMENTS.values():
        parser.add_argument(f"--{option}")
    for option, _environment_name in EXTRA_EXPECTED_ARGUMENTS.values():
        parser.add_argument(f"--{option}")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _argument_parser().parse_args(argv)
        path_text = _source_value(args.receipt, RECEIPT_PATH_ENV)
        credential_root_text = _source_value(
            args.credential_root, CREDENTIAL_ROOT_ENV
        )
        phase = _source_value(args.phase, PHASE_ENV)
        if path_text is None:
            raise ReceiptError("receipt path was not supplied explicitly")
        if credential_root_text is None:
            raise ReceiptError("protected credential root was not supplied explicitly")
        if phase is None or phase not in PHASE_POLICY:
            raise ReceiptError("expected phase is unsupported or absent")
        apply_phase = PHASE_POLICY[phase]["operation"] == "apply"
        state_mode = _source_value(
            getattr(args, STATE_MODE_ARGUMENT[0].replace("-", "_")),
            STATE_MODE_ARGUMENT[1],
        )
        if apply_phase:
            if state_mode not in {"absent", "present"}:
                raise ReceiptError("expected state mode is absent or unsupported")
        elif state_mode is not None:
            raise ReceiptError("expected state mode is inapplicable")
        expected_bindings: dict[str, str | None] = {}
        for binding_name, (option, environment_name) in BINDING_ARGUMENTS.items():
            required = binding_name not in {
                "saved_plan_sha256",
                "state_binding_sha256",
                "state_sha256",
                "provider_lock_sha256",
                "post_audit_sha256",
            } or (
                apply_phase
                and (
                    binding_name != "state_sha256" or state_mode == "present"
                )
            )
            expected_bindings[binding_name] = _expected_hash(
                getattr(args, option.replace("-", "_")),
                environment_name,
                required=required,
            )
        expected_extra_hashes: dict[str, str] = {}
        for binding_name, (option, environment_name) in EXTRA_EXPECTED_ARGUMENTS.items():
            value = _expected_hash(
                getattr(args, option.replace("-", "_")),
                environment_name,
                required=True,
            )
            if value is None:  # Required above; keeps the type contract explicit.
                raise ReceiptError("one required expected binding was not supplied")
            expected_extra_hashes[binding_name] = value
        raw = read_receipt(path_text, credential_root_text)
        loaded = parse_receipt(
            raw,
            expected_phase=phase,
            expected_state_mode=state_mode,
            expected_bindings=expected_bindings,
            expected_extra_hashes=expected_extra_hashes,
        )
    except (OSError, ReceiptError, UnicodeError, ValueError):
        print("FAIL Cloudflare phase-token receipt", file=sys.stderr)
        return 1

    print("PASS Cloudflare phase-token receipt")
    print(f"phase={loaded.phase}")
    print(f"receipt_sha256={loaded.sha256}")
    print("evidence_role=operator-attestation-plus-live-verification-record")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
