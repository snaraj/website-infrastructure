import math
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from .support import load_script


MODULE = load_script("validate_destructive_test_ledger.py")
H = "a" * 64
FIXTURE_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "ci"
    / "destructive_transaction_fixture.py"
)


def valid_ledger():
    receipt_hash = "b" * 64
    journal_hash = "c" * 64
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
        "fault_target_uid": "uid-1",
        "cleanup_receipt_sha256": receipt_hash,
        "recovery_journal_sha256": journal_hash,
    }
    return {
        "schema_version": 1,
        "authorization": "explicit-owner-window",
        "classification": "ephemeral-disposable",
        "externalized_state": True,
        "desired_state_sha256": H,
        "artifact_sha256": H,
        "inventory": [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "namespace": "edge",
                "name": "connector",
                "uid": "uid-1",
                "scope": "Namespaced",
                "classification": "ephemeral-workload",
                "fault_target": True,
            }
        ],
        "protected_exclusions": sorted(MODULE.PROTECTED),
        "acceptance_metrics": {"expected_downtime_seconds": 60, "rto_seconds": 120, "readiness_seconds": 30, "availability_percent": 99.0},
        "cleanup_guard": {
            "signals": ["HUP", "INT", "TERM"],
            "reentry_policy": "ignore-after-first",
            "rollback_limit": 1,
        },
        "cleanup_receipt": {
            "sha256": receipt_hash,
            "completed_at": "2026-08-13T00:01:00Z",
            "observed_cleanup_seconds": 30,
            "signals_deferred": True,
            "rollback_count": 1,
            "receipt_count": 1,
            "rollback_status": "verified",
            "residue_orphans": 0,
        },
        "recovery_journal": {
            "sha256": journal_hash,
            "created_before_mutation": True,
            "initial_state": "prepared",
            "final_state": "closed",
            "recovery_action": "rollback-or-escalate",
        },
        "signal_evidence": [
            {
                "name": name,
                "signals": list(signals),
                "started_at": "2026-08-13T00:00:00Z",
                "completed_at": "2026-08-13T00:00:30Z",
                "observed_cleanup_seconds": 30,
                "rollback_count": 1,
                "receipt_count": 1,
                "residue_orphans": 0,
                "journal_final_state": "closed",
            }
            for name, signals in sorted(MODULE.SIGNAL_CASES.items())
        ],
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
        item = valid_ledger()
        item["inventory"] = [
            dict(
                item["inventory"][0],
                name=f"workload-{index}",
                uid=f"uid-{index}",
                fault_target=index == 0,
            )
            for index in range(MODULE.MAX_INVENTORY + 1)
        ]
        mutations.append(item)
        for api_version, kind in (
            ("rbac.authorization.k8s.io/v1", "ClusterRole"),
            ("apiextensions.k8s.io/v1", "CustomResourceDefinition"),
            ("v1", "Namespace"),
            ("v1", "PersistentVolumeClaim"),
            ("v1", "Secret"),
            ("example.invalid/v1", "FutureThing"),
        ):
            item = valid_ledger()
            item["inventory"][0]["apiVersion"] = api_version
            item["inventory"][0]["kind"] = kind
            mutations.append(item)
        item = valid_ledger(); item["inventory"][0]["scope"] = "Cluster"; mutations.append(item)
        item = valid_ledger(); item["inventory"][0]["classification"] = "protected-stateful"; mutations.append(item)
        item = valid_ledger(); item["inventory"][0]["fault_target"] = False; mutations.append(item)
        item = valid_ledger(); item["inventory"].append(dict(item["inventory"][0], uid="uid-2", name="second", fault_target=True)); mutations.append(item)
        item = valid_ledger(); item["inventory"].append(dict(item["inventory"][0])); mutations.append(item)
        item = valid_ledger(); item["inventory"].append(dict(item["inventory"][0], name="second")); mutations.append(item)
        item = valid_ledger(); item["inventory"][0]["database"] = True; mutations.append(item)
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
        item = valid_ledger(); item["scenarios"][0]["fault_target_uid"] = "uid-foreign"; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["cleanup_receipt_sha256"] = H; mutations.append(item)
        item = valid_ledger(); item["scenarios"][0]["recovery_journal_sha256"] = H; mutations.append(item)
        item = valid_ledger(); item["cleanup_guard"]["reentry_policy"] = "default-after-first"; mutations.append(item)
        item = valid_ledger(); item["cleanup_guard"]["rollback_limit"] = 2; mutations.append(item)
        item = valid_ledger(); item["cleanup_receipt"]["signals_deferred"] = False; mutations.append(item)
        item = valid_ledger(); item["cleanup_receipt"]["rollback_count"] = 2; mutations.append(item)
        item = valid_ledger(); item["cleanup_receipt"]["receipt_count"] = 0; mutations.append(item)
        item = valid_ledger(); item["cleanup_receipt"]["residue_orphans"] = 1; mutations.append(item)
        item = valid_ledger(); item["cleanup_receipt"]["observed_cleanup_seconds"] = 121; mutations.append(item)
        item = valid_ledger(); item["recovery_journal"]["created_before_mutation"] = False; mutations.append(item)
        item = valid_ledger(); item["recovery_journal"]["final_state"] = "prepared"; mutations.append(item)
        item = valid_ledger(); item["signal_evidence"] = item["signal_evidence"][:-1]; mutations.append(item)
        item = valid_ledger(); item["signal_evidence"].append(dict(item["signal_evidence"][0])); mutations.append(item)
        item = valid_ledger(); item["signal_evidence"][0]["signals"] = ["TERM"]; mutations.append(item)
        item = valid_ledger(); item["signal_evidence"][0]["rollback_count"] = 2; mutations.append(item)
        item = valid_ledger(); item["signal_evidence"][0]["receipt_count"] = 0; mutations.append(item)
        item = valid_ledger(); item["signal_evidence"][0]["residue_orphans"] = 1; mutations.append(item)
        item = valid_ledger(); item["signal_evidence"][0]["journal_final_state"] = "prepared"; mutations.append(item)
        for field in (
            "cleanup_guard",
            "cleanup_receipt",
            "recovery_journal",
            "signal_evidence",
        ):
            item = valid_ledger(); del item[field]; mutations.append(item)
        for index, item in enumerate(mutations):
            with self.subTest(index=index):
                self.assertIsNotNone(MODULE.denial(item))

    def test_all_allowed_ephemeral_api_kind_pairs_are_positive_and_nothing_else_is(self):
        for api_version, kind in sorted(MODULE.ALLOWED_EPHEMERAL_KINDS):
            with self.subTest(api_version=api_version, kind=kind):
                item = valid_ledger()
                item["inventory"][0]["apiVersion"] = api_version
                item["inventory"][0]["kind"] = kind
                self.assertIsNone(MODULE.denial(item))

    def test_cli_requires_the_same_closed_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.json"
            path.write_text(json.dumps(valid_ledger()), encoding="utf-8")
            allowed = subprocess.run(
                [sys.executable, str(Path(MODULE.__file__)), str(path)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
            item = valid_ledger()
            item["inventory"][0]["kind"] = "ClusterRole"
            path.write_text(json.dumps(item), encoding="utf-8")
            denied = subprocess.run(
                [sys.executable, str(Path(MODULE.__file__)), str(path)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(denied.returncode, 0, denied.stdout + denied.stderr)

    def test_cli_rejects_duplicate_members_recursively_before_classification(self):
        payload = json.dumps(valid_ledger(), sort_keys=True, separators=(",", ":"))
        protected = '"protected_exclusions":' + json.dumps(
            sorted(MODULE.PROTECTED), separators=(",", ":")
        )
        replacements = (
            (
                "authorization",
                '"authorization":"explicit-owner-window"',
                '"authorization":"assumed"',
            ),
            (
                "top-classification",
                '"classification":"ephemeral-disposable"',
                '"classification":"protected-stateful"',
            ),
            ("protected-exclusions", protected, '"protected_exclusions":[]'),
            ("inventory-api", '"apiVersion":"apps/v1"', '"apiVersion":"v1"'),
            ("inventory-kind", '"kind":"Deployment"', '"kind":"Secret"'),
            ("inventory-scope", '"scope":"Namespaced"', '"scope":"Cluster"'),
            (
                "inventory-classification",
                '"classification":"ephemeral-workload"',
                '"classification":"protected-stateful"',
            ),
            ("inventory-fault-target", '"fault_target":true', '"fault_target":false'),
            ("metric-rto", '"rto_seconds":120', '"rto_seconds":0'),
            ("scenario-name", '"name":"clean-recreate"', '"name":"foreign"'),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.json"
            for label, exact, hostile in replacements:
                self.assertEqual(payload.count(exact), 1, label)
                key = exact.split(":", 1)[0]
                for order, replacement in (
                    ("hostile-first", hostile + "," + exact),
                    ("hostile-last", exact + "," + hostile),
                ):
                    with self.subTest(member=label, order=order):
                        path.write_text(
                            payload.replace(exact, replacement, 1),
                            encoding="utf-8",
                        )
                        denied = subprocess.run(
                            [sys.executable, str(Path(MODULE.__file__)), str(path)],
                            check=False,
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        self.assertEqual(
                            denied.returncode, 1, denied.stdout + denied.stderr
                        )
                        self.assertEqual(denied.stdout, "")
                        self.assertEqual(
                            denied.stderr,
                            f"DENY: ledger JSON contains duplicate member {json.loads(key)!r}\n",
                        )

    def test_strict_decoder_rejects_nonfinite_serialized_constants(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                with self.assertRaisesRegex(
                    MODULE.LedgerJSONError,
                    rf"^ledger JSON contains non-finite constant {constant}$",
                ):
                    MODULE.decode_ledger('{"value":' + constant + "}")


@unittest.skipUnless(
    os.name == "posix" and all(hasattr(signal, name) for name in ("SIGHUP", "SIGINT", "SIGTERM", "SIGKILL")),
    "POSIX signals are required for the executable rollback contract",
)
class DestructiveSignalTransactionTests(unittest.TestCase):
    MUTANT_REASONS = (
        "rollback-aborted-before-receipt",
        "prepared-journal-missing",
        "rollback-receipt-recorded-residue",
        "cleanup-receipt-rollback-count",
        "cleanup-receipt-count",
        "rollback-receipt-concealed-residue",
        "recovery-journal-not-closed",
    )

    def poll_for(self, path, process, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return None
            if process.poll() is not None:
                return f"process-exited-before-{path.name}"
            time.sleep(0.01)
        return f"timeout-before-{path.name}"

    def wait_for(self, path, process, timeout=5):
        reason = self.poll_for(path, process, timeout)
        if reason is not None:
            stdout, stderr = process.communicate()
            self.fail(f"{reason}: {stdout}{stderr}")

    def validate_closed(self, root, completed):
        self.assertFalse((root / "mutation.marker").exists())
        self.assertEqual(
            {path.name for path in root.iterdir()},
            {
                ".offline-destructive-fixture",
                "cleanup.receipt.json",
                "journal.json",
            },
        )
        self.assertEqual(completed.returncode, completed.expected_returncode)
        receipt_path = root / "cleanup.receipt.json"
        journal_path = root / "journal.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "rollback_count": receipt["rollback_count"],
                "receipt_count": receipt["receipt_count"],
                "residue_orphans": receipt["residue_orphans"],
                "signals_deferred": receipt["signals_deferred"],
                "rollback_status": receipt["rollback_status"],
            },
            {
                "rollback_count": 1,
                "receipt_count": 1,
                "residue_orphans": 0,
                "signals_deferred": True,
                "rollback_status": "verified",
            },
        )
        self.assertLessEqual(receipt["observed_cleanup_seconds"], 5.0)
        self.assertEqual(journal["state"], "closed")
        self.assertEqual(journal["rollback_count"], 1)
        self.assertEqual(journal["residue_orphans"], 0)
        self.assertEqual(
            journal["receipt_sha256"],
            __import__("hashlib").sha256(receipt_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(stat_mode(journal_path), 0o600)
        self.assertEqual(stat_mode(receipt_path), 0o600)

    def signal_result_reason(self, root, result, expected_returncode):
        journal_path = root / "journal.json"
        receipt_path = root / "cleanup.receipt.json"
        try:
            journal = (
                json.loads(journal_path.read_text(encoding="utf-8"))
                if journal_path.is_file()
                else None
            )
            receipt = (
                json.loads(receipt_path.read_text(encoding="utf-8"))
                if receipt_path.is_file()
                else None
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return "durable-record-malformed"

        if (root / "mutation.marker").exists():
            if receipt is None:
                return "rollback-aborted-before-receipt"
            if (
                receipt.get("residue_orphans") != 0
                or receipt.get("rollback_status") != "verified"
            ):
                return "rollback-receipt-recorded-residue"
            return "rollback-receipt-concealed-residue"
        if journal is None:
            return "prepared-journal-missing"
        if journal.get("state") != "closed":
            return "recovery-journal-not-closed"
        if receipt is None:
            return "cleanup-receipt-missing"
        if receipt.get("rollback_count") != 1:
            return "cleanup-receipt-rollback-count"
        if receipt.get("receipt_count") != 1:
            return "cleanup-receipt-count"
        if receipt.get("residue_orphans") != 0:
            return "cleanup-receipt-residue-count"
        if receipt.get("rollback_status") != "verified":
            return "cleanup-receipt-status"
        if receipt.get("signals_deferred") is not True:
            return "cleanup-receipt-signal-policy"
        if result["returncode"] != expected_returncode:
            return "unexpected-cleanup-exit"
        if {path.name for path in root.iterdir()} != {
            ".offline-destructive-fixture",
            "cleanup.receipt.json",
            "journal.json",
        }:
            return "closed-root-inventory-mismatch"
        if journal.get("rollback_count") != 1 or journal.get("residue_orphans") != 0:
            return "closed-journal-counts"
        if journal.get("receipt_sha256") != __import__("hashlib").sha256(
            receipt_path.read_bytes()
        ).hexdigest():
            return "closed-journal-receipt-binding"
        if stat_mode(journal_path) != 0o600 or stat_mode(receipt_path) != 0o600:
            return "durable-record-mode"
        return None

    @staticmethod
    def mutant_matches(result, expected_reason):
        return (
            result["reason"] == expected_reason
            and result["process_reaped"] is True
            and result["streams_closed"] is True
            and isinstance(result["returncode"], int)
        )

    def execute_signals(self, script_text, signal_sequence, ready_timeout=5):
        result = {
            "reason": None,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "process_reaped": False,
            "streams_closed": False,
        }
        with tempfile.TemporaryDirectory(prefix="offline-destructive-signals-") as temporary:
            base = Path(temporary)
            script = base / "fixture.py"
            script.write_text(script_text, encoding="utf-8")
            root = base / "transaction"
            root.mkdir()
            (root / ".offline-destructive-fixture").write_text(
                "offline-fixture-v1\n", encoding="utf-8"
            )
            process = None
            communicated = False
            try:
                process = subprocess.Popen(
                    [sys.executable, "-I", "-B", str(script), "run", str(root)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                result["reason"] = self.poll_for(
                    root / "mutation.ready", process, ready_timeout
                )
                if result["reason"] is None and not (root / "journal.json").is_file():
                    result["reason"] = "prepared-journal-missing"
                if result["reason"] is None and not (root / "mutation.marker").is_file():
                    result["reason"] = "mutation-marker-missing"
                if result["reason"] is None:
                    os.kill(process.pid, signal_sequence[0])
                    result["reason"] = self.poll_for(root / "cleanup.started", process)
                if result["reason"] is None:
                    for item in signal_sequence[1:]:
                        if process.poll() is not None:
                            break
                        os.kill(process.pid, item)
                    (root / "cleanup.continue").write_text(
                        "continue\n", encoding="utf-8"
                    )
                    try:
                        result["stdout"], result["stderr"] = process.communicate(
                            timeout=8
                        )
                        communicated = True
                    except subprocess.TimeoutExpired:
                        result["reason"] = "cleanup-timeout"
                if communicated:
                    result["returncode"] = process.returncode
                    result["reason"] = self.signal_result_reason(
                        root,
                        result,
                        128 + signal_sequence[0],
                    )
            except OSError as error:
                result["reason"] = "orchestration-os-error"
                result["stderr"] = str(error)
            finally:
                if process is not None:
                    if not communicated:
                        if process.poll() is None:
                            process.terminate()
                        try:
                            stdout, stderr = process.communicate(timeout=1)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            stdout, stderr = process.communicate(timeout=5)
                        result["stdout"] += stdout
                        result["stderr"] += stderr
                        communicated = True
                    process.wait(timeout=5)
                    result["returncode"] = process.returncode
                    for stream in (process.stdout, process.stderr):
                        if stream is not None and not stream.closed:
                            stream.close()
                    result["process_reaped"] = process.poll() is not None
                    result["streams_closed"] = all(
                        stream is None or stream.closed
                        for stream in (process.stdout, process.stderr)
                    )
        return result

    def test_repeated_and_mixed_signals_produce_one_rollback_receipt_and_no_residue(self):
        source = FIXTURE_SCRIPT.read_text(encoding="utf-8")
        cases = (
            (signal.SIGHUP, signal.SIGHUP),
            (signal.SIGINT, signal.SIGINT),
            (signal.SIGTERM, signal.SIGTERM),
            (signal.SIGTERM, signal.SIGINT, signal.SIGHUP),
        )
        for sequence in cases:
            with self.subTest(signals=sequence):
                result = self.execute_signals(source, sequence)
                self.assertIsNone(result["reason"], result)
                self.assertTrue(result["process_reaped"], result)
                self.assertTrue(result["streams_closed"], result)

    def test_kill_leaves_prepared_journal_and_recovery_closes_once(self):
        with tempfile.TemporaryDirectory(prefix="offline-destructive-kill-") as temporary:
            root = Path(temporary) / "transaction"
            root.mkdir()
            (root / ".offline-destructive-fixture").write_text(
                "offline-fixture-v1\n", encoding="utf-8"
            )
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", str(FIXTURE_SCRIPT), "run", str(root)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.wait_for(root / "mutation.ready", process)
            os.kill(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            self.assertEqual(
                json.loads((root / "journal.json").read_text(encoding="utf-8"))["state"],
                "prepared",
            )
            self.assertTrue((root / "mutation.marker").exists())
            for attempt in range(2):
                recovered = subprocess.run(
                    [sys.executable, "-I", "-B", str(FIXTURE_SCRIPT), "recover", str(root)],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                with self.subTest(recovery_attempt=attempt):
                    self.assertEqual(
                        recovered.returncode, 0, recovered.stdout + recovered.stderr
                    )
            completed = type(
                "Completed",
                (),
                {"returncode": 0, "expected_returncode": 0},
            )()
            self.validate_closed(root, completed)
            receipt = json.loads(
                (root / "cleanup.receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(receipt["trigger"], "journal-recovery")

    def test_kill_during_signal_cleanup_recovers_without_control_marker_residue(self):
        with tempfile.TemporaryDirectory(prefix="offline-destructive-kill-cleanup-") as temporary:
            root = Path(temporary) / "transaction"
            root.mkdir()
            (root / ".offline-destructive-fixture").write_text(
                "offline-fixture-v1\n", encoding="utf-8"
            )
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", str(FIXTURE_SCRIPT), "run", str(root)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.wait_for(root / "mutation.ready", process)
            os.kill(process.pid, signal.SIGTERM)
            self.wait_for(root / "cleanup.started", process)
            os.kill(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            recovered = subprocess.run(
                [sys.executable, "-I", "-B", str(FIXTURE_SCRIPT), "recover", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            completed = type(
                "Completed",
                (),
                {"returncode": recovered.returncode, "expected_returncode": 0},
            )()
            self.validate_closed(root, completed)

    def test_closed_receipt_trigger_finiteness_duplicates_and_modes_fail_closed(self):
        def write_closed(root, receipt_payload, trigger="signal-TERM"):
            receipt_path = root / "cleanup.receipt.json"
            receipt_path.write_bytes(receipt_payload)
            os.chmod(receipt_path, 0o600)
            journal = {
                "created_before_mutation": True,
                "receipt_sha256": __import__("hashlib").sha256(receipt_payload).hexdigest(),
                "recovery_action": "rollback-or-escalate",
                "residue_orphans": 0,
                "rollback_count": 1,
                "schema_version": 1,
                "state": "closed",
                "trigger": trigger,
            }
            journal_path = root / "journal.json"
            journal_path.write_text(
                json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            os.chmod(journal_path, 0o600)
            return journal_path

        exact_receipt = {
            "observed_cleanup_seconds": 0.1,
            "receipt_count": 1,
            "residue_orphans": 0,
            "rollback_count": 1,
            "rollback_status": "verified",
            "schema_version": 1,
            "signals_deferred": True,
            "trigger": "signal-TERM",
        }
        exact_payload = (
            json.dumps(exact_receipt, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        duplicate_payload = exact_payload.replace(
            b'"receipt_count":1,', b'"receipt_count":1,"receipt_count":1,', 1
        )
        nonfinite_payload = exact_payload.replace(
            b'"observed_cleanup_seconds":0.1',
            b'"observed_cleanup_seconds":NaN',
            1,
        )
        foreign_trigger_payload = exact_payload.replace(
            b'"trigger":"signal-TERM"', b'"trigger":"foreign-trigger"', 1
        )
        cases = (
            (foreign_trigger_payload, "foreign-trigger", False),
            (duplicate_payload, "signal-TERM", False),
            (nonfinite_payload, "signal-TERM", False),
            (exact_payload, "signal-TERM", True),
        )
        for index, (payload, trigger, weaken_mode) in enumerate(cases):
            with self.subTest(closed_record_mutant=index), tempfile.TemporaryDirectory(
                prefix="offline-destructive-closed-"
            ) as temporary:
                root = Path(temporary) / "transaction"
                root.mkdir()
                (root / ".offline-destructive-fixture").write_text(
                    "offline-fixture-v1\n", encoding="utf-8"
                )
                journal_path = write_closed(root, payload, trigger)
                if weaken_mode:
                    os.chmod(journal_path, 0o644)
                recovered = subprocess.run(
                    [sys.executable, "-I", "-B", str(FIXTURE_SCRIPT), "recover", str(root)],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(
                    recovered.returncode, 0, recovered.stdout + recovered.stderr
                )

    def test_signal_guard_journal_receipt_and_residue_mutants_are_killed(self):
        source = FIXTURE_SCRIPT.read_text(encoding="utf-8")
        guard = "        if self.cleanup_started:\n            return\n"
        ignore = "            signal.signal(item, signal.SIG_IGN)\n"
        journal = "        _write_json(self.journal, self._journal_document(\"prepared\"))\n"
        mutants = (
            (
                "signal-reentry",
                source.replace(guard, "", 1).replace(
                    ignore, "            signal.signal(item, self.handle_signal)\n", 1
                ),
                "rollback-aborted-before-receipt",
            ),
            (
                "prepared-journal",
                source.replace(journal, "", 1),
                "prepared-journal-missing",
            ),
            (
                "honest-residue",
                source.replace("            self.mutation.unlink()\n", "            pass\n", 1),
                "rollback-receipt-recorded-residue",
            ),
            (
                "rollback-count",
                source.replace('"rollback_count": 1,', '"rollback_count": 2,', 1),
                "cleanup-receipt-rollback-count",
            ),
            (
                "receipt-count",
                source.replace('"receipt_count": 1,', '"receipt_count": 0,', 1),
                "cleanup-receipt-count",
            ),
            (
                "concealed-residue",
                source.replace("            self.mutation.unlink()\n", "            pass\n", 1).replace(
                    "        residue = len(self._exact_root_entries() - allowed_before_receipt)\n",
                    "        residue = 0\n",
                    1,
                ),
                "rollback-receipt-concealed-residue",
            ),
            (
                "journal-replace",
                source.replace("            replace=True,\n", "            replace=False,\n", 1),
                "recovery-journal-not-closed",
            ),
        )
        self.assertEqual(tuple(item[2] for item in mutants), self.MUTANT_REASONS)
        for label, mutant, expected_reason in mutants:
            self.assertNotEqual(mutant, source, f"transaction mutant {label} is inert")
            with self.subTest(transaction_mutant=label):
                result = self.execute_signals(
                    mutant, (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
                )
                self.assertTrue(
                    self.mutant_matches(result, expected_reason),
                    result,
                )


class DestructiveMutantOracleControlTests(unittest.TestCase):
    def setUp(self):
        self.harness = DestructiveSignalTransactionTests(
            "test_signal_guard_journal_receipt_and_residue_mutants_are_killed"
        )

    def test_mutant_oracle_rejects_unrelated_startup_and_child_leak_controls(self):
        early_exit = self.harness.execute_signals(
            'raise RuntimeError("unrelated startup failure")\n',
            (signal.SIGTERM,),
        )
        self.assertEqual(
            early_exit["reason"], "process-exited-before-mutation.ready", early_exit
        )
        self.assertTrue(early_exit["process_reaped"], early_exit)
        self.assertTrue(early_exit["streams_closed"], early_exit)
        for expected_reason in self.harness.MUTANT_REASONS:
            with self.subTest(unrelated_exit=expected_reason):
                self.assertFalse(
                    self.harness.mutant_matches(early_exit, expected_reason)
                )

        hanging_child = self.harness.execute_signals(
            "import time\nwhile True:\n    time.sleep(1)\n",
            (signal.SIGTERM,),
            ready_timeout=0.1,
        )
        self.assertEqual(
            hanging_child["reason"], "timeout-before-mutation.ready", hanging_child
        )
        self.assertTrue(hanging_child["process_reaped"], hanging_child)
        self.assertTrue(hanging_child["streams_closed"], hanging_child)

        otherwise_matching = {
            "reason": self.harness.MUTANT_REASONS[0],
            "returncode": 1,
            "process_reaped": True,
            "streams_closed": True,
        }
        for lifecycle_field in ("process_reaped", "streams_closed"):
            leaked = dict(otherwise_matching)
            leaked[lifecycle_field] = False
            with self.subTest(leaked_lifecycle=lifecycle_field):
                self.assertFalse(
                    self.harness.mutant_matches(
                        leaked, self.harness.MUTANT_REASONS[0]
                    )
                )


def stat_mode(path):
    return os.stat(path, follow_symlinks=False).st_mode & 0o777
