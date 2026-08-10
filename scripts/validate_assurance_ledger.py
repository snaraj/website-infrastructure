"""Validate the platform-assurance evidence ledger fail-closed.

Checks docs/assurance/evidence-ledger.jsonl against the platform-assurance/v1
contract with the standard library only: exact field set per record,
canonical field shapes, non-decreasing timestamps, unique (control,
command_id) pairs, and an explicit forbidden-pattern sweep so no private
value (address, email, home path, credential-shaped string) can ride along
in evidence. An absent ledger is an error once the file is expected: CI
passes the path explicitly, so a typo cannot skip validation silently.
"""

import json
import re
import sys
from pathlib import Path

REQUIRED_FIELDS = (
    "schema",
    "time_utc",
    "base_commit",
    "branch",
    "phase",
    "control",
    "command_id",
    "result",
    "evidence_sha256",
    "private_data",
    "notes",
)
TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
BRANCH_RE = re.compile(r"^fable5?/platform-[a-z0-9-]+$")
PHASE_RE = re.compile(r"^[A-G]$")
CONTROL_RE = re.compile(r"^PLAT-[A-Z0-9]+-[0-9]{3}$")
COMMAND_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RESULTS = ("PASS", "FAIL", "BLOCKED")
NOTES_RE = re.compile(r"^[\x20-\x7e]{0,400}$")

# Values that must never appear anywhere in a sanitized ledger line. The
# sweep runs against the raw line so a forbidden token cannot hide in an
# unexpected field.
FORBIDDEN_PATTERNS = (
    ("ipv4 address", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("email address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("home path", re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+")),
    ("credential assignment", re.compile(r"(?i)(?:token|secret|password|apikey|api_key)\s*[=:]")),
    ("private key header", re.compile(r"-----BEGIN")),
    ("ssh scheme", re.compile(r"(?i)ssh://|scp://")),
)


def record_errors(line_number, raw_line, record, previous_time, seen_pairs):
    errors = []
    for label, pattern in FORBIDDEN_PATTERNS:
        if pattern.search(raw_line):
            errors.append(f"line {line_number}: forbidden {label} pattern")
    if not isinstance(record, dict):
        return errors + [f"line {line_number}: record is not one JSON object"]
    if tuple(sorted(record)) != tuple(sorted(REQUIRED_FIELDS)):
        missing = sorted(set(REQUIRED_FIELDS) - set(record))
        extra = sorted(set(record) - set(REQUIRED_FIELDS))
        errors.append(
            f"line {line_number}: field set mismatch; missing={missing}, extra={extra}"
        )
        return errors
    checks = (
        ("schema", lambda value: value == "platform-assurance/v1"),
        ("time_utc", lambda value: isinstance(value, str) and TIME_RE.fullmatch(value)),
        ("base_commit", lambda value: isinstance(value, str) and COMMIT_RE.fullmatch(value)),
        ("branch", lambda value: isinstance(value, str) and BRANCH_RE.fullmatch(value)),
        ("phase", lambda value: isinstance(value, str) and PHASE_RE.fullmatch(value)),
        ("control", lambda value: isinstance(value, str) and CONTROL_RE.fullmatch(value)),
        ("command_id", lambda value: isinstance(value, str) and COMMAND_RE.fullmatch(value)),
        ("result", lambda value: value in RESULTS),
        (
            "evidence_sha256",
            lambda value: value is None
            or (isinstance(value, str) and SHA256_RE.fullmatch(value)),
        ),
        ("private_data", lambda value: value == "ABSENT"),
        ("notes", lambda value: isinstance(value, str) and NOTES_RE.fullmatch(value)),
    )
    for field, valid in checks:
        if not valid(record[field]):
            errors.append(f"line {line_number}: field {field} is not canonical")
    time_value = record.get("time_utc")
    if (
        isinstance(time_value, str)
        and TIME_RE.fullmatch(time_value)
        and previous_time is not None
        and time_value < previous_time
    ):
        errors.append(f"line {line_number}: time_utc regresses")
    pair = (record.get("control"), record.get("command_id"), record.get("time_utc"))
    if pair in seen_pairs:
        errors.append(f"line {line_number}: duplicate control/command/time record")
    seen_pairs.add(pair)
    return errors


def ledger_errors(path):
    if path.is_symlink() or not path.is_file():
        return ["ledger is missing or is a symlink"]
    errors = []
    previous_time = None
    seen_pairs = set()
    text = path.read_text(encoding="utf-8")
    if text and not text.endswith("\n"):
        errors.append("ledger must end with one newline")
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if not raw_line:
            errors.append(f"line {line_number}: blank line is not a record")
            continue
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            errors.append(f"line {line_number}: not one canonical JSON record")
            continue
        errors.extend(
            record_errors(line_number, raw_line, record, previous_time, seen_pairs)
        )
        if isinstance(record, dict):
            time_value = record.get("time_utc")
            if isinstance(time_value, str) and TIME_RE.fullmatch(time_value):
                previous_time = time_value
    return errors


def main(argv):
    if len(argv) != 2:
        print("usage: validate_assurance_ledger.py <ledger.jsonl>", file=sys.stderr)
        return 2
    errors = ledger_errors(Path(argv[1]))
    for error in errors:
        print(f"assurance-ledger: {error}", file=sys.stderr)
    if errors:
        return 1
    print("assurance-ledger: PASS canonical, ordered, sanitized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
