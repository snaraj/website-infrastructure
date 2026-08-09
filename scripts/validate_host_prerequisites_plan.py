#!/usr/bin/env python3
"""Validate the exact, inert host-prerequisites review plan."""

# Discovery creates this plan before any host mutation. The validator binds a
# human approval to one Pi identity, boot, kernel, file state, and conservative
# set of kubeadm/containerd prerequisites so stale evidence cannot be applied.

from __future__ import annotations

import re
import sys
from pathlib import Path


# FIXED contains the only paths and desired settings the later apply/rollback
# scripts understand; arbitrary targets would expand host mutation authority.
FIXED = {
    "PLAN_VERSION": "1",
    "MODULES_TARGET": "/etc/modules-load.d/90-website-infrastructure-kubeadm.conf",
    "SYSCTL_TARGET": "/etc/sysctl.d/90-website-infrastructure-kubeadm.conf",
    "FSTAB_TARGET": "/etc/fstab",
    "BACKUP_ROOT": "/var/backups/website-infrastructure/host-prerequisites",
    "STATE_ROOT": "/var/lib/website-infrastructure/host-prerequisites",
    "DESIRED_MODULES": "overlay,br_netfilter",
    "DESIRED_VM_OVERCOMMIT_MEMORY": "1",
    "DESIRED_VM_PANIC_ON_OOM": "0",
    "DESIRED_KERNEL_PANIC": "10",
    "DESIRED_KERNEL_PANIC_ON_OOPS": "1",
    "DESIRED_KERNEL_KEYS_ROOT_MAXKEYS": "1000000",
    "DESIRED_KERNEL_KEYS_ROOT_MAXBYTES": "25000000",
    "DESIRED_NET_IPV4_IP_FORWARD": "1",
    "DESIRED_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES": "1",
    "DESIRED_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES": "1",
}

# CURRENT_BOUNDS catches malformed or implausible discovery values while still
# allowing the safe range Ubuntu may report before the reviewed change.
CURRENT_BOUNDS = {
    "CURRENT_VM_OVERCOMMIT_MEMORY": (0, 2),
    "CURRENT_VM_PANIC_ON_OOM": (0, 1),
    "CURRENT_KERNEL_PANIC": (0, 3600),
    "CURRENT_KERNEL_PANIC_ON_OOPS": (0, 1),
    "CURRENT_KERNEL_KEYS_ROOT_MAXKEYS": (1, 2_000_000_000),
    "CURRENT_KERNEL_KEYS_ROOT_MAXBYTES": (1, 2_000_000_000),
    "CURRENT_NET_IPV4_IP_FORWARD": (0, 1),
    "CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES": (0, 1),
    "CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES": (0, 1),
}

# Bridge sysctls legitimately do not exist until br_netfilter is loaded, so only
# these two current-state fields may carry the explicit unavailable marker.
MODULE_GATED_CURRENT_KEYS = {
    "CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IPTABLES",
    "CURRENT_NET_BRIDGE_BRIDGE_NF_CALL_IP6TABLES",
}

# SHA_KEYS bind approval to host identity, live configuration, and exact desired
# file payloads without copying sensitive source content into the plan.
SHA_KEYS = {
    "EXPECTED_MACHINE_ID_SHA256",
    "EXPECTED_BOOT_ID_SHA256",
    "EXPECTED_OS_RELEASE_SHA256",
    "EXPECTED_FSTAB_SHA256",
    "EXPECTED_ACTIVE_SWAP_SHA256",
    "DESIRED_MODULES_SHA256",
    "DESIRED_SYSCTL_SHA256",
}

# EXPECTED_KEYS closes the input schema: missing evidence and invented controls
# both stop the apply path.
EXPECTED_KEYS = set(FIXED) | set(CURRENT_BOUNDS) | SHA_KEYS | {
    "PLAN_STATUS",
    "EXPECTED_ARCHITECTURE",
    "EXPECTED_KERNEL_RELEASE",
    "EXPECTED_MODULES_TARGET_STATE",
    "EXPECTED_SYSCTL_TARGET_STATE",
    "SWAP_MECHANISM",
    "SWAP_ACTION",
}

SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_KERNEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}\Z")
STATE_RE = re.compile(r"(?:absent|sha256:[0-9a-f]{64})\Z")


# parse_plan accepts one unindented KEY=VALUE per line so shell and human readers
# interpret the inert decision file in exactly the same way.
def parse_plan(path: Path) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return {}, [f"cannot read plan: {exc}"]

    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if raw != line or "=" not in line:
            errors.append(f"line {line_number}: expected unindented KEY=VALUE")
            continue
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            errors.append(f"line {line_number}: malformed key")
            continue
        if not value or any(character.isspace() for character in value):
            errors.append(f"line {line_number}: value must be nonempty and contain no whitespace")
            continue
        if key in values:
            errors.append(f"line {line_number}: duplicate key {key}")
            continue
        values[key] = value
    return values, errors


# validate enforces exact targets, bounded discovery evidence, identity hashes,
# and the only swap transitions the rollback implementation can reverse safely.
def validate(values: dict[str, str]) -> list[str]:
    errors: list[str] = []
    missing = sorted(EXPECTED_KEYS - set(values))
    unknown = sorted(set(values) - EXPECTED_KEYS)
    if missing:
        errors.append("missing keys: " + ", ".join(missing))
    if unknown:
        errors.append("unknown keys: " + ", ".join(unknown))
    if missing or unknown:
        return errors

    for key, expected in FIXED.items():
        if values[key] != expected:
            errors.append(f"{key} must be exactly {expected}")

    if values["PLAN_STATUS"] != "approved-after-host-discovery":
        errors.append("PLAN_STATUS must be approved-after-host-discovery")
    if values["EXPECTED_ARCHITECTURE"] not in {"aarch64", "arm64"}:
        errors.append("EXPECTED_ARCHITECTURE must be aarch64 or arm64")
    if not SAFE_KERNEL_RE.fullmatch(values["EXPECTED_KERNEL_RELEASE"]):
        errors.append("EXPECTED_KERNEL_RELEASE is malformed")

    for key in SHA_KEYS:
        if not SHA_RE.fullmatch(values[key]):
            errors.append(f"{key} must be a lowercase SHA-256")
    for key in ("EXPECTED_MODULES_TARGET_STATE", "EXPECTED_SYSCTL_TARGET_STATE"):
        if not STATE_RE.fullmatch(values[key]):
            errors.append(f"{key} must be absent or sha256:<lowercase SHA-256>")

    for key, (minimum, maximum) in CURRENT_BOUNDS.items():
        value = values[key]
        if value == "unavailable-until-module-load" and key in MODULE_GATED_CURRENT_KEYS:
            continue
        if not re.fullmatch(r"[0-9]+", value):
            errors.append(f"{key} must be an unsigned integer")
            continue
        number = int(value)
        if not minimum <= number <= maximum:
            errors.append(f"{key} must be between {minimum} and {maximum}")

    mechanism = values["SWAP_MECHANISM"]
    action = values["SWAP_ACTION"]
    if mechanism not in {"none", "fstab-only"}:
        errors.append("SWAP_MECHANISM must be none or fstab-only; unknown mechanisms are forbidden")
    expected_action = {"none": "none", "fstab-only": "disable-fstab"}.get(mechanism)
    if action != expected_action:
        errors.append(f"SWAP_ACTION must be {expected_action} for SWAP_MECHANISM={mechanism}")

    return errors


# main separates usage errors from contract failures for bootstrap automation.
def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"Usage: {argv[0]} PLAN", file=sys.stderr)
        return 2
    values, errors = parse_plan(Path(argv[1]))
    errors.extend(validate(values) if not errors else [])
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        return 1
    print("PASS host-prerequisites plan matches the exact reviewed contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
