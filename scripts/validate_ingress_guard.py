#!/usr/bin/env python3
"""Prove the SSH-only host-ingress guard model, not its source text.

Owner decision PLAT-DEC-001: administration is SSH-only. From every reviewed
administrative VPN ingress interface, TCP 2379/2380/6443/10250 (etcd, the
Kubernetes API, the kubelet) must be terminally denied while TCP 22 stays
reachable. This verifier normalizes the STRUCTURED nftables representation
(`nft -j list ruleset`) against one closed expected model — never substring
matching over rendered text — so a set, verdict map, wildcard, inversion,
alternate family, duplicate chain, priority game, or future grammar the model
does not know cannot widen or bypass the proof. Every deviation is a fixed
value-free token; no interface name, address, rule text, or ruleset fragment
is ever printed.

Subcommands:
  model  — verify a captured/fixture ruleset against explicit synthetic
           interfaces (unit tests and rehearsals).
  live   — verify a captured ruleset against the securely loaded private
           admin-ingress contract (the Pi loader/preflight path).
  render — deterministically render the exact loadable policy for the
           declared interfaces into a new mode-0600 file.
  repo   — verify the tracked systemd unit, kubelet drop-in, example
           contract, and local-file privacy wiring in this repository.
"""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Exact owned identities. The loader creates them, the verifier proves them,
# and the bounded rollback path deletes exactly this table and nothing else.
OWNED_TABLE = "website_infrastructure_ingress_guard"
OWNED_FAMILY = "inet"
OWNED_CHAIN = "admin_ingress"
CHAIN_TYPE = "filter"
CHAIN_HOOK = "input"
# The guard sits just ahead of the conventional filter band (priority 0) so
# its terminal drops are evaluated deterministically early; nftables drop
# verdicts are final across every base chain regardless, so no later accept
# in another table can resurrect a dropped packet.
CHAIN_PRIORITY = -10
# Policy accept: this chain is a surgical deny layered over the reviewed
# deny-by-default host firewall. A drop policy here would take over unrelated
# admin-plane traffic decisions, which the handoff forbids.
CHAIN_POLICY = "accept"

# The complete closed port model. 22 must stay reachable (SSH is the only
# administration path); the four control-plane listeners must be dropped for
# new AND established flows, so the rules are deliberately not state-gated.
PRESERVED_SSH_PORT = 22
DENIED_PORTS = (2379, 2380, 6443, 10250)

GUARD_UNIT = "website-infrastructure-ingress-guard.service"
LOADER_PATH = "/usr/local/sbin/website-infrastructure-ingress-guard-load"
LOCAL_CONTRACT_REL = "bootstrap/pi/ingress-guard/admin-ingress.env.local"
MAX_RETROFIT_ATTESTATION_BYTES = 4096
MAX_CLUSTER_CA_BYTES = 1024 * 1024

UNIT_FILE_REL = "bootstrap/pi/ingress-guard/systemd/" + GUARD_UNIT
DROPIN_FILE_REL = (
    "bootstrap/pi/ingress-guard/systemd/kubelet.service.d/"
    "50-website-infrastructure-ingress-guard.conf"
)
EXAMPLE_FILE_REL = "bootstrap/pi/ingress-guard/admin-ingress.env.example"
MANIFEST_FILE_REL = "bootstrap/pi/ingress-guard/source-manifest.v1"
PUBLIC_CUSTODY_FILES = {
    "bootstrap/pi/ingress-guard/custody-ingress-guard.sh": "0700",
    "bootstrap/pi/ingress-guard/install-ingress-guard.sh": "0700",
    "bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh": "0700",
    "bootstrap/pi/ingress-guard/recover-ingress-guard.sh": "0700",
    "bootstrap/pi/ingress-guard/transaction-lib.sh": "0600",
    "bootstrap/pi/ingress-guard/load-ingress-guard.sh": "0700",
    "bootstrap/pi/ingress-guard/verify-ingress-guard.sh": "0700",
    UNIT_FILE_REL: "0644",
    DROPIN_FILE_REL: "0644",
    "scripts/validate_admin_ingress_contract.py": "0600",
    "scripts/validate_ingress_guard.py": "0600",
}
INSTALLER_FILE_REL = "bootstrap/pi/ingress-guard/install-ingress-guard.sh"
RETROFIT_FILE_REL = "bootstrap/pi/ingress-guard/retrofit-ingress-guard.sh"
RECOVERY_FILE_REL = "bootstrap/pi/ingress-guard/recover-ingress-guard.sh"
CUSTODY_FILE_REL = "bootstrap/pi/ingress-guard/custody-ingress-guard.sh"
TRANSACTION_LIBRARY_REL = "bootstrap/pi/ingress-guard/transaction-lib.sh"
LOADER_FILE_REL = "bootstrap/pi/ingress-guard/load-ingress-guard.sh"

# Exact line contracts for persistence and boot ordering. Requires= plus
# After= in the kubelet drop-in means kubelet cannot start unless this guard
# started successfully, and a Condition* line is forbidden because a skipped
# condition still satisfies Requires= — the one silent-open path systemd
# offers, made unrepresentable here.
EXPECTED_UNIT_LINES = (
    "[Unit]",
    "Description=SSH-only admin-ingress guard for the Kubernetes control plane",
    "Documentation=https://github.com/snaraj/website-infrastructure",
    "Wants=network-pre.target",
    "Before=network-pre.target kubelet.service",
    "After=local-fs.target",
    "[Service]",
    "Type=oneshot",
    "RemainAfterExit=yes",
    "User=root",
    "Group=root",
    "UMask=0077",
    "ExecStart=" + LOADER_PATH,
    "RuntimeDirectory=website-infrastructure-ingress-guard",
    "RuntimeDirectoryMode=0700",
    "TimeoutStartSec=2min",
    "NoNewPrivileges=yes",
    "PrivateTmp=yes",
    "ProtectClock=yes",
    "ProtectControlGroups=yes",
    "ProtectHome=yes",
    "ProtectHostname=yes",
    "ProtectKernelLogs=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelTunables=yes",
    "ProtectSystem=strict",
    "ReadOnlyPaths=/etc/website-infrastructure /usr/local/lib/website-infrastructure",
    "ReadWritePaths=/var/lib/website-infrastructure/ingress-guard",
    "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "IPAddressDeny=any",
    "CapabilityBoundingSet=CAP_NET_ADMIN",
    "SystemCallArchitectures=native",
    "[Install]",
    "WantedBy=multi-user.target",
)
FORBIDDEN_UNIT_PREFIXES = ("Condition", "ExecStop")
EXPECTED_DROPIN_LINES = (
    "[Unit]",
    "Requires=" + GUARD_UNIT,
    "After=" + GUARD_UNIT,
)


def _load_contract_module():
    """Load the sibling private-contract validator as the single schema owner."""

    script = Path(__file__).resolve().parent / "validate_admin_ingress_contract.py"
    spec = importlib.util.spec_from_file_location(
        "validate_admin_ingress_contract", script
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACT = _load_contract_module()


def expected_sequence(interfaces):
    """The one true rule model: SSH preserved first, then the four denials."""

    sequence = []
    for interface in interfaces:
        sequence.append((interface, PRESERVED_SSH_PORT, "accept"))
        for port in DENIED_PORTS:
            sequence.append((interface, port, "drop"))
    return sequence


def _parse_match(expression, kind):
    """Return the matched value for one closed match shape, or a token."""

    match = expression.get("match")
    if not isinstance(match, dict) or set(match) != {"op", "left", "right"}:
        return None, "RULE_GRAMMAR_UNSUPPORTED"
    if match["op"] != "==":
        return None, "MATCH_INVERSION_UNSUPPORTED"
    left = match["left"]
    right = match["right"]
    if isinstance(right, (list, dict)):
        # Anonymous/named sets, ranges, prefixes, and maps widen a match in
        # ways the closed model refuses to reason about.
        return None, "SET_INDIRECTION_UNSUPPORTED"
    if kind == "iifname":
        if left != {"meta": {"key": "iifname"}}:
            return None, "RULE_GRAMMAR_UNSUPPORTED"
        if not isinstance(right, str) or not right:
            return None, "RULE_GRAMMAR_UNSUPPORTED"
        if "*" in right or "\\" in right:
            return None, "WILDCARD_UNSUPPORTED"
        return right, None
    if left != {"payload": {"protocol": "tcp", "field": "dport"}}:
        return None, "RULE_GRAMMAR_UNSUPPORTED"
    # bool is an int subclass in both JSON decoders and Python; a true/false
    # port encoding is malformed input, never coerced.
    if isinstance(right, bool) or not isinstance(right, int):
        return None, "RULE_GRAMMAR_UNSUPPORTED"
    return right, None


def _parse_rule_expr(expr):
    """Reduce one rule to (interface, port, verdict) under the closed grammar."""

    if not isinstance(expr, list) or len(expr) != 4:
        return None, "RULE_GRAMMAR_UNSUPPORTED"
    if any(not isinstance(item, dict) or len(item) != 1 for item in expr):
        return None, "RULE_GRAMMAR_UNSUPPORTED"
    interface, error = _parse_match(expr[0], "iifname")
    if error:
        return None, error
    port, error = _parse_match(expr[1], "dport")
    if error:
        return None, error
    if "counter" not in expr[2]:
        # Counters are the live-proof mechanism showing the guard, not some
        # other rule, handled a blocked probe. Their absence is a violation.
        return None, "COUNTER_MISSING"
    if not isinstance(expr[2]["counter"], dict):
        return None, "RULE_GRAMMAR_UNSUPPORTED"
    verdict_key = next(iter(expr[3]))
    if verdict_key not in {"accept", "drop"} or expr[3][verdict_key] is not None:
        # jump/goto/vmap/queue/continue/return all leave the terminal-denial
        # question open, so none of them is representable in a healthy model.
        return None, "VERDICT_UNSUPPORTED"
    return (interface, port, verdict_key), None


def _classify_sequence(parsed, interfaces, errors):
    """Explain how a parsed sequence diverges from the expected model."""

    expected = expected_sequence(interfaces)
    if parsed == expected:
        return

    def note(token):
        if token not in errors:
            errors.append(token)

    declared = set(interfaces)
    for interface, port, verdict in parsed:
        if port == PRESERVED_SSH_PORT and verdict == "drop":
            note("SSH_PRESERVATION_VIOLATED")
        if port in DENIED_PORTS and verdict == "accept":
            note("DENY_WIDENING_ACCEPT")
        if port != PRESERVED_SSH_PORT and port not in DENIED_PORTS:
            # A port outside the closed model is not a wider guard; it is an
            # unreviewed rule hiding inside the owned identity.
            note("RULE_GRAMMAR_UNSUPPORTED")
        if interface not in declared:
            note("INTERFACE_OVERREACH")
    seen = set()
    for triple in parsed:
        if triple in seen:
            note("COVERAGE_DUPLICATE")
        seen.add(triple)
    for triple in expected:
        if triple not in seen:
            note("COVERAGE_INCOMPLETE")
    if not errors:
        note("RULE_ORDER_INVALID")


def model_errors(document, interfaces):
    """Validate the normalized ruleset against the exact expected model."""

    errors = []
    if not isinstance(document, dict) or not isinstance(
        document.get("nftables"), list
    ):
        return ["RULESET_JSON_INVALID"]
    metainfo_count = 0
    owned_tables = []
    owned_chains = []
    owned_rules = []
    for item in document["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            return ["RULESET_JSON_INVALID"]
        kind = next(iter(item))
        body = item[kind]
        if kind == "metainfo":
            metainfo_count += 1
            if not isinstance(body, dict) or body.get("json_schema_version") != 1:
                return ["SCHEMA_VERSION_UNSUPPORTED"]
            continue
        if not isinstance(body, dict):
            return ["RULESET_JSON_INVALID"]
        if kind == "table":
            if body.get("name") == OWNED_TABLE:
                owned_tables.append(body)
            continue
        if kind == "chain":
            if body.get("table") == OWNED_TABLE:
                owned_chains.append(body)
            elif body.get("name") == OWNED_CHAIN:
                # A same-named chain under a foreign table is exactly the
                # ambiguous-ordering decoy the handoff calls out.
                errors.append("CHAIN_NAME_COLLISION")
            continue
        if kind == "rule":
            if body.get("table") == OWNED_TABLE:
                owned_rules.append(body)
            continue
        # Sets, maps, elements, flowtables, quotas, or any future object type
        # bound to the owned table put semantics outside the closed model.
        if body.get("table") == OWNED_TABLE:
            errors.append("FOREIGN_OBJECT_IN_OWNED_TABLE")
    if metainfo_count != 1:
        return ["SCHEMA_VERSION_UNSUPPORTED"]

    if not owned_tables:
        errors.append("TABLE_MISSING")
        return errors
    if len(owned_tables) > 1:
        errors.append("TABLE_DUPLICATE")
        return errors
    if owned_tables[0].get("family") != OWNED_FAMILY:
        # ip- or ip6-only variants protect one address family and silently
        # abandon the other; only the dual-family inet table is acceptable.
        errors.append("TABLE_FAMILY_INVALID")
        return errors

    if not owned_chains:
        errors.append("CHAIN_MISSING")
        return errors
    if len(owned_chains) > 1:
        errors.append("CHAIN_UNEXPECTED")
        return errors
    chain = owned_chains[0]
    allowed_chain_keys = {
        "family", "table", "name", "handle", "type", "hook", "prio", "policy",
    }
    if set(chain) - allowed_chain_keys:
        errors.append("CHAIN_GRAMMAR_UNSUPPORTED")
    if chain.get("name") != OWNED_CHAIN:
        errors.append("CHAIN_MISSING")
    if chain.get("family") != OWNED_FAMILY:
        errors.append("TABLE_FAMILY_INVALID")
    if chain.get("type") != CHAIN_TYPE:
        errors.append("CHAIN_TYPE_INVALID")
    if chain.get("hook") != CHAIN_HOOK:
        errors.append("HOOK_INVALID")
    if chain.get("prio") != CHAIN_PRIORITY or isinstance(chain.get("prio"), bool):
        errors.append("PRIORITY_INVALID")
    if chain.get("policy") != CHAIN_POLICY:
        errors.append("POLICY_INVALID")
    if errors:
        return errors

    parsed = []
    allowed_rule_keys = {"family", "table", "chain", "handle", "expr"}
    for rule in owned_rules:
        if set(rule) - allowed_rule_keys:
            errors.append("RULE_GRAMMAR_UNSUPPORTED")
            continue
        if rule.get("family") != OWNED_FAMILY or rule.get("chain") != OWNED_CHAIN:
            errors.append("RULE_PLACEMENT_INVALID")
            continue
        triple, error = _parse_rule_expr(rule.get("expr"))
        if error:
            if error not in errors:
                errors.append(error)
            continue
        parsed.append(triple)
    if errors:
        return errors
    _classify_sequence(parsed, interfaces, errors)
    return errors


def absence_errors(document):
    """Prove no owned identity exists yet (the loader's pre-install state)."""

    if not isinstance(document, dict) or not isinstance(
        document.get("nftables"), list
    ):
        return ["RULESET_JSON_INVALID"]
    errors = []
    for item in document["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            return ["RULESET_JSON_INVALID"]
        kind = next(iter(item))
        body = item[kind]
        if not isinstance(body, dict):
            if kind == "metainfo":
                return ["SCHEMA_VERSION_UNSUPPORTED"]
            return ["RULESET_JSON_INVALID"]
        if body.get("name") == OWNED_TABLE and kind == "table":
            errors.append("PREEXISTING_OWNED_TABLE")
        elif body.get("table") == OWNED_TABLE:
            errors.append("PREEXISTING_OWNED_TABLE")
        elif kind == "chain" and body.get("name") == OWNED_CHAIN:
            errors.append("CHAIN_NAME_COLLISION")
    deduplicated = []
    for error in errors:
        if error not in deduplicated:
            deduplicated.append(error)
    return deduplicated


def render_text(interfaces):
    """Render the exact loadable nftables policy for the declared interfaces."""

    lines = [
        "#!/usr/sbin/nft -f",
        "# Rendered by validate_ingress_guard.py; do not edit by hand.",
        "# SSH-only admin plane (PLAT-DEC-001): admin-VPN ingress keeps TCP 22",
        "# and is terminally denied the cluster control-plane listeners.",
        "table %s %s {" % (OWNED_FAMILY, OWNED_TABLE),
        "\tchain %s {" % OWNED_CHAIN,
        "\t\ttype %s hook %s priority %d; policy %s;"
        % (CHAIN_TYPE, CHAIN_HOOK, CHAIN_PRIORITY, CHAIN_POLICY),
    ]
    for interface, port, verdict in expected_sequence(interfaces):
        lines.append(
            '\t\tiifname "%s" tcp dport %d counter %s' % (interface, port, verdict)
        )
    lines.extend(["\t}", "}", ""])
    return "\n".join(lines)


def _validated_interfaces(values):
    """Hold synthetic CLI interfaces to the same schema as private ones."""

    errors = []
    seen = set()
    for index, value in enumerate(values, start=1):
        if CONTRACT.interface_errors(value, index) or value in seen:
            errors.append("INTERFACE_ARGUMENT_INVALID")
            break
        seen.add(value)
    if not values:
        errors.append("INTERFACE_ARGUMENT_INVALID")
    return errors


def _read_ruleset(path):
    try:
        if path == "-":
            raw = sys.stdin.read()
        else:
            raw = Path(path).read_text(encoding="utf-8")
        return json.loads(raw), []
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, ["RULESET_JSON_INVALID"]


def unit_errors(text):
    """Pin the loader unit's persistence, ordering, and fail-closed shape."""

    lines = tuple(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if lines != EXPECTED_UNIT_LINES or any(
        line.startswith(FORBIDDEN_UNIT_PREFIXES) for line in lines
    ):
        return ["UNIT_CONTRACT_VIOLATED"]
    return []


def dropin_errors(text):
    """Pin the kubelet drop-in that makes the guard a hard start dependency."""

    lines = tuple(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    return [] if lines == EXPECTED_DROPIN_LINES else ["DROPIN_CONTRACT_VIOLATED"]


def custody_manifest_errors(root, manifest_relative=MANIFEST_FILE_REL):
    """Bind every privileged public byte to one closed custody manifest."""

    manifest = root / manifest_relative
    if manifest.is_symlink() or not manifest.is_file():
        return ["CUSTODY_MANIFEST_INVALID"]
    try:
        text = manifest.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return ["CUSTODY_MANIFEST_INVALID"]
    parsed = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            return ["CUSTODY_MANIFEST_INVALID"]
        digest, mode, relative = fields
        if (
            relative in parsed
            or relative not in PUBLIC_CUSTODY_FILES
            or mode != PUBLIC_CUSTODY_FILES[relative]
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return ["CUSTODY_MANIFEST_INVALID"]
        parsed[relative] = digest
    if set(parsed) != set(PUBLIC_CUSTODY_FILES):
        return ["CUSTODY_MANIFEST_INVALID"]
    for relative, expected in parsed.items():
        artifact = root / relative
        if artifact.is_symlink() or not artifact.is_file():
            return ["CUSTODY_MANIFEST_INVALID"]
        try:
            observed = hashlib.sha256(artifact.read_bytes()).hexdigest()
        except OSError:
            return ["CUSTODY_MANIFEST_INVALID"]
        if observed != expected:
            return ["CUSTODY_MANIFEST_INVALID"]
    return []


def parse_retrofit_attestation_text(
    text, source_revision, manifest_sha256, boot_id_sha256, cluster_ca_sha256
):
    """Validate the closed value grammar independently from host metadata."""

    expected = {
        "SCHEMA": "ingress-guard-retrofit-attestation-v1",
        "SOURCE_REVISION": source_revision,
        "MANIFEST_SHA256": manifest_sha256,
        "BOOT_ID_SHA256": boot_id_sha256,
        "CLUSTER_CA_SHA256": cluster_ca_sha256,
        "OWNED_TABLE_PRESTATE": "absent",
        "GUARD_UNIT_PRESTATE": "absent",
        "DROPIN_PRESTATE": "absent",
        "KUBELET_PRESTATE": "active",
        "TWO_RETAINED_SESSIONS": "yes",
        "PHYSICAL_LAN_RECOVERY": "yes",
        "FRESH_LOGIN_CANARY": "yes",
        "MUTATION_WINDOW_AUTHORIZED": "yes",
    }
    if "\r" in text or not text.endswith("\n"):
        return ["RETROFIT_ATTESTATION_INVALID"]
    observed = {}
    for line in text.splitlines():
        if line.count("=") != 1 or line != line.strip():
            return ["RETROFIT_ATTESTATION_INVALID"]
        key, value = line.split("=", 1)
        if key in observed or key not in expected or not value:
            return ["RETROFIT_ATTESTATION_INVALID"]
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        if any(character not in allowed for character in value):
            return ["RETROFIT_ATTESTATION_INVALID"]
        observed[key] = value
    if observed != expected:
        return ["RETROFIT_ATTESTATION_INVALID"]
    return []


def retrofit_attestation_errors(
    path, source_revision, manifest_sha256, boot_id_sha256, cluster_ca_sha256
):
    """Validate the root-private, value-free running-cluster ceremony input."""

    try:
        if path.is_symlink():
            return ["RETROFIT_ATTESTATION_INVALID"]
        metadata = path.stat()
        if (
            not path.is_file()
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_mode & 0o777 != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_RETROFIT_ATTESTATION_BYTES
        ):
            return ["RETROFIT_ATTESTATION_INVALID"]
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_RETROFIT_ATTESTATION_BYTES:
            return ["RETROFIT_ATTESTATION_INVALID"]
        text = raw.decode("utf-8")
    except (OSError, UnicodeError):
        return ["RETROFIT_ATTESTATION_INVALID"]
    return parse_retrofit_attestation_text(
        text,
        source_revision,
        manifest_sha256,
        boot_id_sha256,
        cluster_ca_sha256,
    )


def _secure_read(path, maximum_bytes, metadata_check, require_size_match=True):
    """Read one host binding through a no-follow descriptor and stable fstat."""

    descriptor = None
    try:
        descriptor = os.open(
            os.fspath(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not metadata_check(before):
            raise OSError("metadata")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum_bytes:
                raise OSError("size")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after) or (
            require_size_match and size != after.st_size
        ):
            raise OSError("metadata changed")
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def secure_retrofit_bindings(
    attestation_path,
    boot_id_path,
    cluster_ca_path,
    source_revision,
    manifest_sha256,
    attested_boot_id_sha256=None,
):
    """Bind attestation, current boot, and CA from held no-follow descriptors."""

    root_regular = lambda metadata: (
        metadata.st_uid == 0
        and metadata.st_gid == 0
        and metadata.st_nlink == 1
    )
    attestation = _secure_read(
        attestation_path,
        MAX_RETROFIT_ATTESTATION_BYTES,
        lambda metadata: root_regular(metadata)
        and stat.S_IMODE(metadata.st_mode) == 0o600,
    )
    boot_id = _secure_read(
        boot_id_path,
        128,
        lambda metadata: root_regular(metadata)
        and not (stat.S_IMODE(metadata.st_mode) & 0o022),
        False,
    )
    cluster_ca = _secure_read(
        cluster_ca_path,
        MAX_CLUSTER_CA_BYTES,
        lambda metadata: root_regular(metadata)
        and not (stat.S_IMODE(metadata.st_mode) & 0o022),
    )
    if not attestation or not boot_id or not cluster_ca:
        return None, ["RETROFIT_BINDING_INVALID"]
    try:
        attestation_text = attestation.decode("utf-8")
        boot_text = boot_id.decode("ascii")
    except UnicodeError:
        return None, ["RETROFIT_BINDING_INVALID"]
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n",
        boot_text,
    ):
        return None, ["RETROFIT_BINDING_INVALID"]
    current_boot = hashlib.sha256(boot_id).hexdigest()
    cluster_binding = hashlib.sha256(cluster_ca).hexdigest()
    expected_attested_boot = attested_boot_id_sha256 or current_boot
    if parse_retrofit_attestation_text(
        attestation_text,
        source_revision,
        manifest_sha256,
        expected_attested_boot,
        cluster_binding,
    ):
        return None, ["RETROFIT_ATTESTATION_INVALID"]
    return {
        "attestation_sha256": hashlib.sha256(attestation).hexdigest(),
        "current_boot_sha256": current_boot,
        "cluster_ca_sha256": cluster_binding,
    }, []


def transaction_script_errors(root):
    """Pin the load-bearing call sites that close the two issue-145 races."""

    texts = {}
    for relative in (
        INSTALLER_FILE_REL,
        RETROFIT_FILE_REL,
        RECOVERY_FILE_REL,
        CUSTODY_FILE_REL,
        TRANSACTION_LIBRARY_REL,
        LOADER_FILE_REL,
    ):
        path = root / relative
        if path.is_symlink() or not path.is_file():
            return ["TRANSACTION_WIRING_INVALID"]
        try:
            texts[relative] = "\n".join(
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if not line.lstrip().startswith("#")
            )
        except (OSError, UnicodeError):
            return ["TRANSACTION_WIRING_INVALID"]

    custody = texts[CUSTODY_FILE_REL]
    if not all(
        fragment in custody
        for fragment in (
            "MUTABLE_ENTRYPOINT_REFUSED",
            "os.O_NOFOLLOW",
            "os.fstat(descriptor)",
            "hashlib.sha256(payload).hexdigest() != parsed[relative]",
            "os.fsync(descriptor)",
            'operation == "verify"',
            "verify_destination()",
            "atomic_receipt",
            "os.memfd_create",
            "fcntl.F_ADD_SEALS",
            "fixed launcher manifest binding",
            "exec /usr/bin/python3 -I -B /proc/self/fd/8",
        )
    ):
        return ["TRANSACTION_WIRING_INVALID"]

    loader = texts[LOADER_FILE_REL]
    apply = loader.find('ig_run_bounded nft -f "${rendered}"')
    created = loader.find("table_created_in_memory=yes", apply)
    capture = loader.find("POST_APPLY_CAPTURE_FAILED", created)
    rollback = loader.find("rollback_load >/dev/null 2>&1")
    if min(apply, created, capture, rollback) < 0 or not (
        rollback < apply < created < capture
    ):
        return ["TRANSACTION_WIRING_INVALID"]
    if "load_journal_write apply-intent absent none" not in loader:
        return ["TRANSACTION_WIRING_INVALID"]
    if "load_journal_write commit-intent absent none" not in loader:
        return ["TRANSACTION_WIRING_INVALID"]

    installer = texts[INSTALLER_FILE_REL]
    if any(forbidden in installer for forbidden in ("repo_root=", "admin-ingress.env.local")):
        return ["TRANSACTION_WIRING_INVALID"]
    for required in (
        "KUBELET_ALREADY_ACTIVE",
        "mutation_started=yes",
        "INGRESS_GUARD_AUTOMATIC_RECOVERY=journal-bound",
        "ig_write_receipt pass verified verified verified not-needed",
        "ig_verify_custody_contract",
        "ig_verify_guard_unit_prestate",
        "TRUSTED_LAUNCH_REQUIRED",
        "IG_PHASE=commit-intent",
    ):
        if required not in installer:
            return ["TRANSACTION_WIRING_INVALID"]
    if installer.find("ig_verify_custody_contract") > installer.find(
        "mutation_started=yes"
    ):
        return ["TRANSACTION_WIRING_INVALID"]

    retrofit = texts[RETROFIT_FILE_REL]
    if not all(
        fragment in retrofit
        for fragment in (
            "KUBELET_NOT_ACTIVE",
            "ig_verify_custody_contract",
            "guard_only_verify",
            "IG_PHASE=dropin-installed",
            "IG_PHASE=kubelet-restart-intent",
            "systemctl restart kubelet.service",
            "IG_PHASE=awaiting-reboot",
            "IG_PHASE=awaiting-reboot-intent",
            "IG_PHASE=commit-intent",
            "--close-after-reboot",
            "REBOOT_CLOSURE_BINDING_MISMATCH",
            "PENDING_RECEIPT_INVALID",
            "load_secure_bindings",
            "ig_verify_cluster_health",
        )
    ):
        return ["TRANSACTION_WIRING_INVALID"]
    if retrofit.find("guard_only_verify ||") > retrofit.find(
        'ig_install_exact "${dropin_source}"'
    ):
        return ["TRANSACTION_WIRING_INVALID"]
    if retrofit.find("ig_verify_custody_contract") > retrofit.find(
        "mutation_started=yes"
    ):
        return ["TRANSACTION_WIRING_INVALID"]

    recovery = texts[RECOVERY_FILE_REL]
    if not all(
        fragment in recovery
        for fragment in (
            "IG_PHASE=rollback-intent",
            "ig_delete_owned_table_and_prove_absent",
            "KUBELET_RESTORE_FAILED",
            "GUARD_ENABLEMENT_ROLLBACK_AMBIGUOUS",
            "KUBELET_DEPENDENCY_ROLLBACK_AMBIGUOUS",
            "IG_PHASE=rolled-back",
            "interrupted-commit-reconciled",
            "interrupted-pending-state-reconciled",
            "TRUSTED_LAUNCH_REQUIRED",
            "ig_reconcile_published_load_commit",
            "ig_close_load_journal_after_absence",
        )
    ):
        return ["TRANSACTION_WIRING_INVALID"]
    return []


def repo_errors(
    root, manifest_relative=MANIFEST_FILE_REL, check_repository_privacy=True
):
    """Verify the tracked guard artifacts and the local-file privacy wiring."""

    errors = custody_manifest_errors(root, manifest_relative)
    errors.extend(transaction_script_errors(root))
    for relative, checker in (
        (UNIT_FILE_REL, unit_errors),
        (DROPIN_FILE_REL, dropin_errors),
    ):
        path = root / relative
        if path.is_symlink() or not path.is_file():
            errors.append("WIRING_INCOMPLETE")
            continue
        errors.extend(checker(path.read_text(encoding="utf-8")))
    if check_repository_privacy:
        example = root / EXAMPLE_FILE_REL
        if example.is_symlink() or not example.is_file():
            errors.append("WIRING_INCOMPLETE")
        else:
            errors.extend(CONTRACT.example_errors(example.read_text(encoding="utf-8")))
        # The private local staging file must be ignored AND rejected by the
        # repository layout gate, so a copied real contract can never become a
        # tracked file even if .gitignore were edited away.
        gitignore = root / ".gitignore"
        if not gitignore.is_file() or LOCAL_CONTRACT_REL not in gitignore.read_text(
            encoding="utf-8"
        ):
            errors.append("WIRING_INCOMPLETE")
        repository_validator = root / "scripts" / "validate_repository.py"
        spec = importlib.util.spec_from_file_location(
            "validate_repository_for_ingress_guard", repository_validator
        )
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
            forbidden = getattr(module, "FORBIDDEN_LOCAL_ONLY_EXACT_NAMES", set())
        except Exception:  # noqa: BLE001 - any load failure is a wiring failure
            forbidden = set()
        if LOCAL_CONTRACT_REL not in forbidden:
            errors.append("WIRING_INCOMPLETE")
    deduplicated = []
    for error in errors:
        if error not in deduplicated:
            deduplicated.append(error)
    return deduplicated


def _emit(errors, success_message):
    for error in errors:
        print(f"ingress-guard: FAIL {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"ingress-guard: PASS {success_message}")
    return 0


def _split_interface_arguments(argv):
    interfaces = []
    remaining = []
    index = 0
    while index < len(argv):
        if argv[index] == "--interface" and index + 1 < len(argv):
            interfaces.append(argv[index + 1])
            index += 2
            continue
        remaining.append(argv[index])
        index += 1
    return interfaces, remaining


def main(argv):
    usage = (
        "usage: validate_ingress_guard.py "
        "model --ruleset <path|-> --interface <name> [--interface <name>]... | "
        "model --ruleset <path|-> --expect-absent | "
        "live --ruleset <path|-> --contract <path> [--expect-absent] | "
        "render --output <path> (--contract <path> | --interface <name>...) | "
        "retrofit-attestation --attestation <path> --source-revision <sha> "
        "--manifest-sha256 <sha> --boot-id-sha256 <sha> "
        "--cluster-ca-sha256 <sha> | "
        "retrofit-binding --attestation <path> --boot-id-file <path> "
        "--cluster-ca <path> --source-revision <sha> --manifest-sha256 <sha> "
        "[--attested-boot-id-sha256 <sha>] | repo | repo-custody"
    )
    if len(argv) < 2:
        print(usage, file=sys.stderr)
        return 2
    command = argv[1]
    interfaces, rest = _split_interface_arguments(argv[2:])
    options = {}
    flags = set()
    index = 0
    while index < len(rest):
        if rest[index] in {
            "--ruleset", "--contract", "--output", "--attestation",
            "--source-revision", "--manifest-sha256", "--boot-id-sha256",
            "--cluster-ca-sha256", "--boot-id-file", "--cluster-ca",
            "--attested-boot-id-sha256",
        } and index + 1 < len(rest):
            options[rest[index]] = rest[index + 1]
            index += 2
        elif rest[index] == "--expect-absent":
            flags.add(rest[index])
            index += 1
        else:
            print(usage, file=sys.stderr)
            return 2

    if command in {"repo", "repo-custody"}:
        if interfaces or options or flags:
            print(usage, file=sys.stderr)
            return 2
        manifest_relative = (
            "source-manifest.v1" if command == "repo-custody" else MANIFEST_FILE_REL
        )
        return _emit(
            repo_errors(
                REPO_ROOT,
                manifest_relative,
                check_repository_privacy=command == "repo",
            ),
            "custodied-guard-artifacts-verified"
            if command == "repo-custody"
            else "tracked-guard-artifacts-verified",
        )

    if command == "retrofit-attestation":
        expected_options = {
            "--attestation", "--source-revision", "--manifest-sha256",
            "--boot-id-sha256", "--cluster-ca-sha256",
        }
        if interfaces or flags or set(options) != expected_options:
            print(usage, file=sys.stderr)
            return 2
        errors = retrofit_attestation_errors(
            Path(options["--attestation"]),
            options["--source-revision"],
            options["--manifest-sha256"],
            options["--boot-id-sha256"],
            options["--cluster-ca-sha256"],
        )
        return _emit(errors, "running-cluster-attestation-verified")

    if command == "retrofit-binding":
        required_options = {
            "--attestation",
            "--boot-id-file",
            "--cluster-ca",
            "--source-revision",
            "--manifest-sha256",
        }
        optional_options = {"--attested-boot-id-sha256"}
        if (
            interfaces
            or flags
            or not required_options.issubset(options)
            or not set(options).issubset(required_options | optional_options)
        ):
            print(usage, file=sys.stderr)
            return 2
        bindings, errors = secure_retrofit_bindings(
            Path(options["--attestation"]),
            Path(options["--boot-id-file"]),
            Path(options["--cluster-ca"]),
            options["--source-revision"],
            options["--manifest-sha256"],
            options.get("--attested-boot-id-sha256"),
        )
        if errors:
            return _emit(errors, "")
        print("attestation_sha256=" + bindings["attestation_sha256"])
        print("current_boot_sha256=" + bindings["current_boot_sha256"])
        print("cluster_ca_sha256=" + bindings["cluster_ca_sha256"])
        return 0

    if command in {"model", "live"}:
        if "--ruleset" not in options:
            print(usage, file=sys.stderr)
            return 2
        document, errors = _read_ruleset(options["--ruleset"])
        if errors:
            return _emit(errors, "")
        if command == "live":
            if interfaces or "--contract" not in options:
                print(usage, file=sys.stderr)
                return 2
            loaded, errors = CONTRACT.load_admin_ingress_contract(
                Path(options["--contract"])
            )
            if errors:
                return _emit(errors, "")
            interfaces = list(loaded)
        if "--expect-absent" in flags:
            return _emit(absence_errors(document), "owned-guard-identity-absent")
        errors = _validated_interfaces(interfaces)
        if errors:
            return _emit(errors, "")
        return _emit(
            model_errors(document, tuple(interfaces)),
            "admin-ingress-model-verified",
        )

    if command == "render":
        if "--output" not in options or flags:
            print(usage, file=sys.stderr)
            return 2
        if "--contract" in options:
            if interfaces:
                print(usage, file=sys.stderr)
                return 2
            loaded, errors = CONTRACT.load_admin_ingress_contract(
                Path(options["--contract"])
            )
            if errors:
                return _emit(errors, "")
            interfaces = list(loaded)
        errors = _validated_interfaces(interfaces)
        if errors:
            return _emit(errors, "")
        text = render_text(tuple(interfaces))
        flags_open = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags_open |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(options["--output"], flags_open, 0o600)
        except OSError:
            return _emit(["RENDER_TARGET_UNSAFE"], "")
        try:
            os.write(descriptor, text.encode("utf-8"))
        finally:
            os.close(descriptor)
        return _emit([], "rendered-admin-ingress-policy")

    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
