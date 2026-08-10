import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_assurance_ledger.py"
LEDGER = REPO_ROOT / "docs" / "assurance" / "evidence-ledger.jsonl"

spec = importlib.util.spec_from_file_location("validate_assurance_ledger", SCRIPT)
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


def valid_record(**overrides):
    record = {
        "schema": "platform-assurance/v1",
        "time_utc": "2026-08-10T19:20:00Z",
        "base_commit": "c" * 40,
        "branch": "fable/platform-security-ci",
        "phase": "B",
        "control": "PLAT-TEST-001",
        "command_id": "unit-fixture-record",
        "result": "PASS",
        "evidence_sha256": None,
        "private_data": "ABSENT",
        "notes": "fixture",
    }
    record.update(overrides)
    return record


class AssuranceLedgerContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "ledger.jsonl"

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, records, raw=None):
        if raw is not None:
            self.path.write_text(raw, encoding="utf-8")
        else:
            lines = "".join(json.dumps(record) + "\n" for record in records)
            self.path.write_text(lines, encoding="utf-8")

    def test_committed_ledger_is_canonical(self):
        self.assertEqual(MODULE.ledger_errors(LEDGER), [])

    def test_valid_sequence_passes(self):
        self.write(
            [
                valid_record(),
                valid_record(
                    time_utc="2026-08-10T19:20:01Z", command_id="second-record"
                ),
                valid_record(
                    time_utc="2026-08-10T19:20:02Z",
                    command_id="house-prefix-record",
                    branch="fable5/platform-kubernetes-policy-audit",
                ),
            ]
        )
        self.assertEqual(MODULE.ledger_errors(self.path), [])

    def test_missing_and_extra_fields_are_rejected(self):
        record = valid_record()
        del record["notes"]
        record["surprise"] = "x"
        self.write([record])
        errors = MODULE.ledger_errors(self.path)
        self.assertTrue(any("field set mismatch" in error for error in errors))

    def test_time_regression_is_rejected(self):
        self.write(
            [
                valid_record(time_utc="2026-08-10T19:20:05Z"),
                valid_record(
                    time_utc="2026-08-10T19:20:01Z", command_id="second-record"
                ),
            ]
        )
        errors = MODULE.ledger_errors(self.path)
        self.assertTrue(any("time_utc regresses" in error for error in errors))

    def test_duplicate_record_identity_is_rejected(self):
        self.write([valid_record(), valid_record()])
        errors = MODULE.ledger_errors(self.path)
        self.assertTrue(any("duplicate" in error for error in errors))

    def test_pass_without_executable_shape_is_rejected(self):
        for field, bad in (
            ("schema", "assurance/v2"),
            ("base_commit", "main"),
            ("branch", "feature/quick-fix"),
            ("phase", "I"),
            ("control", "FINDING-1"),
            ("command_id", "X"),
            ("result", "MAYBE"),
            ("evidence_sha256", "deadbeef"),
            ("private_data", "present"),
            ("notes", "x" * 401),
        ):
            with self.subTest(field=field):
                self.write([valid_record(**{field: bad})])
                errors = MODULE.ledger_errors(self.path)
                self.assertTrue(errors, field)

    def test_forbidden_private_patterns_are_rejected(self):
        # Hostile values are assembled at runtime so the repository's own
        # privacy scanners never see them at rest in this file.
        hostile_notes = (
            "reached 192.168.1." + "10 fine",
            "owner mailto " + "admin" + chr(64) + "example.com",
            "copied /Users/" + "someone/keys",
            "token" + "=" + "abc123",
            "-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5,
            "pull via " + "ssh" + "://host",
        )
        for notes in hostile_notes:
            with self.subTest(notes=notes[:20]):
                self.write([valid_record(notes=notes)])
                errors = MODULE.ledger_errors(self.path)
                self.assertTrue(
                    any("forbidden" in error for error in errors), notes
                )

    def test_blank_lines_symlinks_and_truncation_are_rejected(self):
        self.write([], raw="\n")
        self.assertTrue(MODULE.ledger_errors(self.path))
        self.write([], raw='{"schema": "platform-assurance/v1"')
        self.assertTrue(
            any(
                "not one canonical JSON record" in error
                for error in MODULE.ledger_errors(self.path)
            )
        )
        self.write([], raw=json.dumps(valid_record()))
        self.assertTrue(
            any(
                "end with one newline" in error
                for error in MODULE.ledger_errors(self.path)
            )
        )
        missing = self.path.with_name("absent.jsonl")
        self.assertEqual(
            MODULE.ledger_errors(missing), ["ledger is missing or is a symlink"]
        )


if __name__ == "__main__":
    unittest.main()
