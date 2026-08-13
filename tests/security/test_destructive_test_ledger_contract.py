import math
import unittest

from .support import load_script


MODULE = load_script("validate_destructive_test_ledger.py")
H = "a" * 64


def valid_ledger():
    scenario = {
        "prestate_sha256": H,
        "fault_sha256": H,
        "recovery_sha256": H,
        "poststate_sha256": H,
        "started_at": "2026-08-13T00:00:00Z",
        "completed_at": "2026-08-13T00:01:00Z",
        "observed_downtime_seconds": 30,
        "observed_rto_seconds": 60,
        "observed_readiness_seconds": 20,
        "observed_availability_percent": 99.5,
        "residue_orphans": 0,
        "rollback_status": "verified",
        "readiness_accepted": True,
        "availability_accepted": True,
        "public_https_recovered": True,
    }
    return {
        "schema_version": 1,
        "authorization": "explicit-owner-window",
        "classification": "ephemeral-disposable",
        "externalized_state": True,
        "desired_state_sha256": H,
        "artifact_sha256": H,
        "inventory": [{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "edge", "name": "connector", "uid": "uid-1"}],
        "protected_exclusions": sorted(MODULE.PROTECTED),
        "acceptance_metrics": {"expected_downtime_seconds": 60, "rto_seconds": 120, "readiness_seconds": 30, "availability_percent": 99.0},
        "scenarios": [dict(scenario, name=name) for name in sorted(MODULE.SCENARIOS)],
        "cloudflare_connector": True,
        "serialized_lane": True,
        "recreate_from_zero": True,
    }


class DestructiveLedgerTests(unittest.TestCase):
    def test_accepts_only_complete_disposable_connector_evidence(self):
        self.assertIsNone(MODULE.denial(valid_ledger()))

    def test_every_protected_or_vacuous_mutation_is_denied(self):
        mutations = []
        for key, value in (
            ("authorization", "assumed"),
            ("classification", "protected-stateful"),
            ("externalized_state", False),
            ("desired_state_sha256", "abc"),
            ("artifact_sha256", "abc"),
            ("serialized_lane", False),
            ("recreate_from_zero", False),
        ):
            item = valid_ledger(); item[key] = value; mutations.append(item)
        item = valid_ledger(); item["inventory"] = []; mutations.append(item)
        item = valid_ledger(); item["inventory"][0]["kind"] = "Secret"; mutations.append(item)
        item = valid_ledger(); item["inventory"][0]["kind"] = "StatefulSet"; mutations.append(item)
        item = valid_ledger(); item["inventory"][0]["database"] = True; mutations.append(item)
        item = valid_ledger(); item["inventory"][0]["operator_managed"] = True; mutations.append(item)
        item = valid_ledger(); item["protected_exclusions"] = item["protected_exclusions"][:-1]; mutations.append(item)
        item = valid_ledger(); item["scenarios"] = item["scenarios"][:-1]; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["poststate_sha256"] = "bad"; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["residue_orphans"] = 1; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["public_https_recovered"] = False; mutations.append(item)
        item = valid_ledger(); item["acceptance_metrics"]["availability_percent"] = 101; mutations.append(item)
        item = valid_ledger(); item["acceptance_metrics"]["rto_seconds"] = math.inf; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["started_at"] = "not-a-time"; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["completed_at"] = "2026-08-12T23:59:59Z"; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["observed_rto_seconds"] = 121; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["observed_availability_percent"] = 98.9; mutations.append(item)
        for index, item in enumerate(mutations):
            with self.subTest(index=index):
                self.assertIsNotNone(MODULE.denial(item))
