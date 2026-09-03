#!/usr/bin/env python3
"""Validate evidence shape for an authorized disposable-workload experiment.

This tool never connects to or mutates a cluster. It cannot grant authorization.
"""

import argparse
import datetime as dt
import json
import math
import re
import sys
from pathlib import Path


SHA256 = re.compile(r"^[0-9a-f]{64}$")
SCENARIOS = frozenset({"clean-recreate", "termination", "restart", "node-loss", "dependency-loss"})
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
ALLOWED_EPHEMERAL_KINDS = frozenset(
    {
        ("apps/v1", "DaemonSet"),
        ("apps/v1", "Deployment"),
        ("apps/v1", "ReplicaSet"),
        ("batch/v1", "CronJob"),
        ("batch/v1", "Job"),
        ("v1", "Pod"),
    }
)
MAX_INVENTORY = 32
SIGNAL_CASES = {
    "mixed-signals": ("TERM", "INT", "HUP"),
    "repeated-hup": ("HUP", "HUP"),
    "repeated-int": ("INT", "INT"),
    "repeated-term": ("TERM", "TERM"),
}
PROTECTED = frozenset(
    {
        "secrets-and-tokens",
        "private-keys-etcd-pki",
        "provider-dns-domain-tunnel-identities",
        "protected-custody",
        "git-history",
    }
)
TOP_LEVEL_FIELDS = frozenset(
    {
        "acceptance_metrics",
        "artifact_sha256",
        "authorization",
        "classification",
        "cleanup_guard",
        "cleanup_receipt",
        "cloudflare_connector",
        "desired_state_sha256",
        "externalized_state",
        "inventory",
        "protected_exclusions",
        "recovery_journal",
        "recreate_from_zero",
        "scenarios",
        "schema_version",
        "serialized_lane",
        "signal_evidence",
    }
)
INVENTORY_FIELDS = frozenset(
    {
        "apiVersion",
        "classification",
        "fault_target",
        "kind",
        "name",
        "namespace",
        "scope",
        "uid",
    }
)
METRIC_FIELDS = frozenset(
    {
        "availability_percent",
        "expected_downtime_seconds",
        "readiness_seconds",
        "rto_seconds",
    }
)
SCENARIO_FIELDS = frozenset(
    {
        "availability_accepted",
        "cleanup_receipt_sha256",
        "completed_at",
        "fault_sha256",
        "fault_target_uid",
        "name",
        "observed_availability_percent",
        "observed_downtime_seconds",
        "observed_readiness_seconds",
        "observed_rto_seconds",
        "poststate_sha256",
        "prestate_sha256",
        "public_https_recovered",
        "readiness_accepted",
        "recovery_journal_sha256",
        "recovery_sha256",
        "residue_orphans",
        "rollback_status",
        "started_at",
    }
)
GUARD_FIELDS = frozenset({"reentry_policy", "rollback_limit", "signals"})
RECEIPT_FIELDS = frozenset(
    {
        "completed_at",
        "observed_cleanup_seconds",
        "receipt_count",
        "residue_orphans",
        "rollback_count",
        "rollback_status",
        "sha256",
        "signals_deferred",
    }
)
JOURNAL_FIELDS = frozenset(
    {
        "created_before_mutation",
        "final_state",
        "initial_state",
        "recovery_action",
        "sha256",
    }
)
SIGNAL_FIELDS = frozenset(
    {
        "completed_at",
        "journal_final_state",
        "name",
        "observed_cleanup_seconds",
        "receipt_count",
        "residue_orphans",
        "rollback_count",
        "signals",
        "started_at",
    }
)


class LedgerJSONError(ValueError):
    """The serialized authorization ledger is not strict JSON."""


def decode_ledger(payload):
    """Decode one ledger without normalizing duplicate or non-finite input."""

    def unique_object(pairs):
        document = {}
        for key, value in pairs:
            if key in document:
                raise LedgerJSONError(f"ledger JSON contains duplicate member {key!r}")
            document[key] = value
        return document

    def reject_constant(value):
        raise LedgerJSONError(f"ledger JSON contains non-finite constant {value}")

    return json.loads(
        payload,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


def _hash(value):
    return isinstance(value, str) and bool(SHA256.fullmatch(value))


def _metric(value, *, percent=False):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
        return False
    return not percent or value <= 100


def _time(value):
    if not isinstance(value, str) or not UTC.fullmatch(value):
        return None
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def _exact_fields(value, fields):
    return isinstance(value, dict) and set(value) == fields


def denial(document):
    if not _exact_fields(document, TOP_LEVEL_FIELDS):
        return "ledger fields are missing or foreign"
    if document.get("schema_version") != 1:
        return "schema_version must equal 1"
    if document.get("authorization") != "explicit-owner-window":
        return "ledger does not record explicit owner live-window authorization"
    if document.get("classification") != "ephemeral-disposable":
        return "only engineered ephemeral-disposable resources may use destructive ledger"
    if document.get("externalized_state") is not True:
        return "durable state is not proven externalized"
    if not _hash(document.get("desired_state_sha256")) or not _hash(document.get("artifact_sha256")):
        return "desired state and artifact require immutable SHA-256 identities"
    inventory = document.get("inventory")
    if not isinstance(inventory, list) or not 1 <= len(inventory) <= MAX_INVENTORY:
        return "exact target inventory cardinality is outside the closed bound"
    identities = set()
    uids = set()
    fault_targets = []
    for resource in inventory:
        if not _exact_fields(resource, INVENTORY_FIELDS):
            return "inventory entry fields are missing or foreign"
        fields = tuple(resource.get(key) for key in ("apiVersion", "kind", "namespace", "name", "uid"))
        if not all(isinstance(value, str) and value for value in fields):
            return "inventory identity is incomplete"
        if fields in identities:
            return "inventory contains duplicate identity"
        identities.add(fields)
        if fields[-1] in uids:
            return "inventory UIDs must be unique"
        uids.add(fields[-1])
        if (resource.get("apiVersion"), resource.get("kind")) not in ALLOWED_EPHEMERAL_KINDS:
            return "resource API/kind is outside the closed ephemeral workload allowlist"
        if resource.get("scope") != "Namespaced" or resource.get("classification") != "ephemeral-workload":
            return "resource scope or classification is not exact"
        if not isinstance(resource.get("fault_target"), bool):
            return "resource fault_target must be boolean"
        if resource.get("fault_target"):
            fault_targets.append(resource.get("uid"))
    if len(fault_targets) != 1:
        return "inventory must classify exactly one fault target"
    exclusions = document.get("protected_exclusions")
    if not isinstance(exclusions, list) or set(exclusions) != PROTECTED or len(exclusions) != len(PROTECTED):
        return "protected exclusions are not the exact required set"
    metrics = document.get("acceptance_metrics")
    if not _exact_fields(metrics, METRIC_FIELDS):
        return "acceptance metric fields are missing or foreign"
    for key in ("expected_downtime_seconds", "rto_seconds", "readiness_seconds", "availability_percent"):
        value = metrics.get(key)
        if not _metric(value, percent=key == "availability_percent"):
            return f"acceptance metric {key} is invalid"
    if metrics["rto_seconds"] <= 0 or metrics["readiness_seconds"] <= 0:
        return "RTO and readiness acceptance bounds must be positive"

    guard = document.get("cleanup_guard")
    if not _exact_fields(guard, GUARD_FIELDS):
        return "cleanup guard fields are missing or foreign"
    if guard.get("signals") != ["HUP", "INT", "TERM"]:
        return "cleanup guard signal inventory is not exact"
    if guard.get("reentry_policy") != "ignore-after-first" or guard.get("rollback_limit") != 1:
        return "cleanup guard is not re-entry safe or single-rollback"

    journal = document.get("recovery_journal")
    if not _exact_fields(journal, JOURNAL_FIELDS):
        return "recovery journal fields are missing or foreign"
    if not _hash(journal.get("sha256")):
        return "recovery journal requires an immutable SHA-256 identity"
    if (
        journal.get("created_before_mutation") is not True
        or journal.get("initial_state") != "prepared"
        or journal.get("final_state") != "closed"
        or journal.get("recovery_action") != "rollback-or-escalate"
    ):
        return "recovery journal lifecycle is not exact"

    receipt = document.get("cleanup_receipt")
    if not _exact_fields(receipt, RECEIPT_FIELDS):
        return "cleanup receipt fields are missing or foreign"
    if not _hash(receipt.get("sha256")) or _time(receipt.get("completed_at")) is None:
        return "cleanup receipt identity or completion time is invalid"
    if (
        receipt.get("signals_deferred") is not True
        or receipt.get("rollback_count") != 1
        or receipt.get("receipt_count") != 1
        or receipt.get("rollback_status") != "verified"
        or receipt.get("residue_orphans") != 0
    ):
        return "cleanup receipt does not prove one rollback, one receipt, and no residue"
    if not _metric(receipt.get("observed_cleanup_seconds")) or receipt.get(
        "observed_cleanup_seconds"
    ) > metrics["rto_seconds"]:
        return "cleanup receipt exceeds the accepted RTO"

    signal_evidence = document.get("signal_evidence")
    if not isinstance(signal_evidence, list) or len(signal_evidence) != len(SIGNAL_CASES):
        return "signal evidence cardinality is not exact"
    signal_names = {
        item.get("name") for item in signal_evidence if isinstance(item, dict)
    }
    if signal_names != set(SIGNAL_CASES):
        return "repeated and mixed signal evidence set is incomplete or widened"
    for evidence in signal_evidence:
        if not _exact_fields(evidence, SIGNAL_FIELDS):
            return "signal evidence fields are missing or foreign"
        if evidence.get("signals") != list(SIGNAL_CASES[evidence["name"]]):
            return "signal evidence sequence is not exact"
        started = _time(evidence.get("started_at"))
        completed = _time(evidence.get("completed_at"))
        if started is None or completed is None or completed < started:
            return "signal evidence timestamps are absent, invalid, or reversed"
        if (
            evidence.get("rollback_count") != 1
            or evidence.get("receipt_count") != 1
            or evidence.get("residue_orphans") != 0
            or evidence.get("journal_final_state") != "closed"
        ):
            return "signal evidence does not prove one rollback, one receipt, and no residue"
        if not _metric(evidence.get("observed_cleanup_seconds")) or evidence.get(
            "observed_cleanup_seconds"
        ) > metrics["rto_seconds"]:
            return "signal cleanup exceeds the accepted RTO"

    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list) or {item.get("name") for item in scenarios if isinstance(item, dict)} != SCENARIOS:
        return "required destructive scenario set is incomplete or widened"
    if len(scenarios) != len(SCENARIOS):
        return "scenario set contains duplicates"
    connector = document.get("cloudflare_connector") is True
    for scenario in scenarios:
        if not _exact_fields(scenario, SCENARIO_FIELDS):
            return "scenario fields are missing or foreign"
        if scenario.get("fault_target_uid") != fault_targets[0]:
            return "scenario fault target does not bind the classified inventory UID"
        if scenario.get("cleanup_receipt_sha256") != receipt.get("sha256"):
            return "scenario cleanup receipt identity does not match"
        if scenario.get("recovery_journal_sha256") != journal.get("sha256"):
            return "scenario recovery journal identity does not match"
        for key in ("prestate_sha256", "fault_sha256", "recovery_sha256", "poststate_sha256"):
            if not _hash(scenario.get(key)):
                return f"scenario {scenario.get('name')!r} has no exact {key}"
        started = _time(scenario.get("started_at"))
        completed = _time(scenario.get("completed_at"))
        if started is None or completed is None or completed < started:
            return "scenario timestamps are absent, invalid, or reversed"
        observations = {
            "observed_downtime_seconds": "expected_downtime_seconds",
            "observed_rto_seconds": "rto_seconds",
            "observed_readiness_seconds": "readiness_seconds",
        }
        for observed, target in observations.items():
            value = scenario.get(observed)
            if not _metric(value) or value > metrics[target]:
                return f"scenario {observed} is invalid or exceeds acceptance"
        availability = scenario.get("observed_availability_percent")
        if not _metric(availability, percent=True) or availability < metrics["availability_percent"]:
            return "scenario observed availability is invalid or below acceptance"
        if scenario.get("residue_orphans") != 0 or scenario.get("rollback_status") != "verified":
            return "scenario residue or rollback is not clean"
        if scenario.get("readiness_accepted") is not True or scenario.get("availability_accepted") is not True:
            return "scenario acceptance is incomplete"
        if connector and scenario.get("public_https_recovered") is not True:
            return "connector scenario lacks public HTTPS recovery proof"
    if not isinstance(document.get("cloudflare_connector"), bool):
        return "connector classification must be boolean"
    if document.get("serialized_lane") is not True or document.get("recreate_from_zero") is not True:
        return "serialization or clean recreate-from-zero proof is absent"
    return None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger", type=Path)
    args = parser.parse_args(argv)
    try:
        document = decode_ledger(args.ledger.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, LedgerJSONError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    reason = denial(document)
    if reason:
        print(f"DENY: {reason}", file=sys.stderr)
        return 1
    print("ALLOW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
