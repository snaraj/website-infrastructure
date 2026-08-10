"""Validate the Phase H attack-surface manifest fail-closed.

The manifest is the contract the owner-authorized offensive-validation
harness asserts live reality against. This validator (stdlib only) proves
the contract is well-formed, uses only the closed result vocabulary, binds
every entry to an invariant ID, carries no private value, and — critically —
covers every surface that MUST be probed, so a probe can never silently
disappear from the contract. It never contacts a network or the Pi.
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_VOCAB = {
    "no-response",
    "wireguard-handshake-only",
    "denied",
    "allowed-to-class",
    "fail-closed",
}
CONTROL_RE = re.compile(r"^PLAT-[A-Z0-9]+-[0-9]{3}$")
# Field values are closed identifiers only; this refuses free-form text that
# could smuggle an address, key, or route into the contract.
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")

# Surfaces the contract must always assert. Losing any of these would be a
# silent coverage regression, so their absence is a hard error.
REQUIRED_INBOUND = {"wireguard-admin-udp", "all-other-ports", "kubernetes-api"}
REQUIRED_REACHABILITY = {
    ("tenant-pod", "other-tenant-pod"),
    ("tenant-pod", "kubernetes-api"),
    ("tenant-pod", "node-host"),
    ("tenant-pod", "admin-plane-subnet"),
    ("admin-peer", "kubernetes-api"),
}
REQUIRED_EGRESS = {
    ("tenant-pod", "arbitrary-internet"),
    ("host", "dns-outside-proton"),
    ("host", "arbitrary-internet-on-proton-drop"),
}
# The admin plane is SSH-only until the owner rules otherwise (PLAT-DEC-001):
# the API must be explicitly denied from the admin peer.
ADMIN_API_MUST_BE_DENIED = ("admin-peer", "kubernetes-api")


def manifest_errors(path):
    if path.is_symlink() or not path.is_file():
        return ["manifest is missing or is a symlink"]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ["manifest is not canonical JSON"]
    errors = []
    if document.get("schema") != "attack-surface/v1":
        errors.append("schema tag is not attack-surface/v1")
    if set(document.get("expected_vocabulary", [])) != EXPECTED_VOCAB:
        errors.append("expected_vocabulary drifted from the closed result set")

    def check_entries(section, key_fields):
        entries = document.get(section)
        if not isinstance(entries, list) or not entries:
            errors.append(f"section {section} is missing or empty")
            return []
        seen = []
        for index, entry in enumerate(entries):
            where = f"{section}[{index}]"
            if not isinstance(entry, dict):
                errors.append(f"{where}: not an object")
                continue
            if set(entry) != set(key_fields) | {"expected", "control"}:
                errors.append(f"{where}: field set is not exactly {sorted(set(key_fields) | {'expected', 'control'})}")
                continue
            for field in key_fields:
                if not IDENTIFIER_RE.fullmatch(str(entry.get(field, ""))):
                    errors.append(f"{where}: field {field} is not a closed identifier")
            if entry.get("expected") not in EXPECTED_VOCAB:
                errors.append(f"{where}: expected is outside the closed vocabulary")
            if not CONTROL_RE.fullmatch(str(entry.get("control", ""))):
                errors.append(f"{where}: control is not a PLAT-<AREA>-NNN id")
            if len(key_fields) == 1:
                seen.append(entry.get(key_fields[0]))
            else:
                seen.append(tuple(entry.get(field) for field in key_fields))
        return seen

    inbound = check_entries("inbound_wan", ["surface"])
    reachability = check_entries("reachability", ["from", "to"])
    egress = check_entries("egress", ["from", "to"])

    missing_inbound = REQUIRED_INBOUND - set(inbound)
    if missing_inbound:
        errors.append(f"inbound_wan is missing required surfaces: {sorted(missing_inbound)}")
    missing_reach = REQUIRED_REACHABILITY - set(reachability)
    if missing_reach:
        errors.append(f"reachability is missing required paths: {sorted(missing_reach)}")
    missing_egress = REQUIRED_EGRESS - set(egress)
    if missing_egress:
        errors.append(f"egress is missing required paths: {sorted(missing_egress)}")

    # The one inbound surface allowed to answer at all is the WireGuard admin
    # port, and only with a handshake — everything else must be no-response.
    for entry in document.get("inbound_wan", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("surface") == "wireguard-admin-udp":
            if entry.get("expected") != "wireguard-handshake-only":
                errors.append("the WireGuard admin port must expect wireguard-handshake-only")
        elif entry.get("expected") != "no-response":
            errors.append(f"inbound surface {entry.get('surface')} must expect no-response")

    # Admin-plane scope decision PLAT-DEC-001: API denied from the admin peer.
    for entry in document.get("reachability", []):
        if isinstance(entry, dict) and (entry.get("from"), entry.get("to")) == ADMIN_API_MUST_BE_DENIED:
            if entry.get("expected") != "denied":
                errors.append("admin peer to kubernetes-api must be denied (PLAT-DEC-001 SSH-only)")
    return errors


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else REPO_ROOT / "docs/assurance/attack-surface-manifest.json"
    errors = manifest_errors(path)
    for error in errors:
        print(f"attack-surface-manifest: {error}", file=sys.stderr)
    if errors:
        return 1
    print("attack-surface-manifest: PASS well-formed, closed-vocabulary, full-coverage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
