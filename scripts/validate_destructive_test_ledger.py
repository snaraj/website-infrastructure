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
PROTECTED_KINDS = frozenset(
    {
        "Secret",
        "PersistentVolume",
        "PersistentVolumeClaim",
        "StatefulSet",
        "CustomResourceDefinition",
        "Namespace",
        "APIService",
        "ValidatingWebhookConfiguration",
        "MutatingWebhookConfiguration",
    }
)
PROTECTED = frozenset(
    {
        "secrets-and-tokens",
        "sops-age-keys-and-ciphertext",
        "private-keys-etcd-pki",
        "provider-dns-domain-tunnel-identities",
        "protected-custody",
        "git-history",
    }
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


def denial(document):
    if not isinstance(document, dict) or document.get("schema_version") != 1:
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
    if not isinstance(inventory, list) or not inventory:
        return "exact target inventory is empty"
    identities = set()
    for resource in inventory:
        if not isinstance(resource, dict):
            return "inventory entry is not an object"
        fields = tuple(resource.get(key) for key in ("apiVersion", "kind", "namespace", "name", "uid"))
        if not all(isinstance(value, str) and value for value in fields):
            return "inventory identity is incomplete"
        if fields in identities:
            return "inventory contains duplicate identity"
        identities.add(fields)
        if resource.get("kind") in PROTECTED_KINDS or resource.get("database") is True or resource.get("operator_managed") is True:
            return "protected/stateful resource cannot inherit ephemeral deletion permission"
    exclusions = document.get("protected_exclusions")
    if not isinstance(exclusions, list) or set(exclusions) != PROTECTED or len(exclusions) != len(PROTECTED):
        return "protected exclusions are not the exact required set"
    metrics = document.get("acceptance_metrics")
    if not isinstance(metrics, dict):
        return "acceptance metrics are absent"
    for key in ("expected_downtime_seconds", "rto_seconds", "readiness_seconds", "availability_percent"):
        value = metrics.get(key)
        if not _metric(value, percent=key == "availability_percent"):
            return f"acceptance metric {key} is invalid"
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list) or {item.get("name") for item in scenarios if isinstance(item, dict)} != SCENARIOS:
        return "required destructive scenario set is incomplete or widened"
    if len(scenarios) != len(SCENARIOS):
        return "scenario set contains duplicates"
    connector = document.get("cloudflare_connector") is True
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            return "scenario is not an object"
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
    if document.get("serialized_lane") is not True or document.get("recreate_from_zero") is not True:
        return "serialization or clean recreate-from-zero proof is absent"
    return None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger", type=Path)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.ledger.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
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
