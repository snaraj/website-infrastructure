#!/usr/bin/env python3
"""Exercise signal-safe rollback only inside an explicit offline fixture root.

This helper cannot run a workload command or contact a cluster. It creates and
recovers one local marker so the portable cleanup protocol is executable under
hostile signals without granting live authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import stat
import sys
import time
from pathlib import Path


SENTINEL = ".offline-destructive-fixture"
SENTINEL_TEXT = "offline-fixture-v1\n"
RTO_SECONDS = 5.0
SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
SIGNAL_NAMES = {
    signal.SIGHUP: "HUP",
    signal.SIGINT: "INT",
    signal.SIGTERM: "TERM",
}
RECEIPT_FIELDS = {
    "observed_cleanup_seconds",
    "receipt_count",
    "residue_orphans",
    "rollback_count",
    "rollback_status",
    "schema_version",
    "signals_deferred",
    "trigger",
}
RECEIPT_TRIGGERS = {"journal-recovery", "signal-HUP", "signal-INT", "signal-TERM"}


class FixtureError(RuntimeError):
    """The local fixture cannot satisfy the closed transaction contract."""


def _canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _fsync_directory(root: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(str(root), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_bytes(path: Path, payload: bytes, *, replace: bool = False) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(temporary), flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not replace and path.exists():
        temporary.unlink()
        raise FixtureError(f"refusing to replace existing fixture record {path.name}")
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _write_json(path: Path, document: object, *, replace: bool = False) -> bytes:
    payload = _canonical(document)
    _write_bytes(path, payload, replace=replace)
    return payload


def _read_json(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise FixtureError(f"fixture record {path.name} is absent or unsafe")
    if stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode) != 0o600:
        raise FixtureError(f"fixture record {path.name} must use mode 0600")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise FixtureError(f"fixture record {path.name} has duplicate keys")
            document[key] = value
        return document

    def reject_constant(value: str) -> None:
        raise FixtureError(
            f"fixture record {path.name} has non-finite JSON constant {value}"
        )

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FixtureError(f"fixture record {path.name} is malformed") from error
    if not isinstance(value, dict):
        raise FixtureError(f"fixture record {path.name} is not an object")
    return value


def _root(raw: str) -> Path:
    root = Path(raw)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise FixtureError("fixture root must be an absolute ordinary directory")
    resolved = root.resolve(strict=True)
    if resolved != root:
        raise FixtureError("fixture root must not traverse aliases or symlinks")
    sentinel = root / SENTINEL
    if (
        sentinel.is_symlink()
        or not sentinel.is_file()
        or sentinel.read_text(encoding="utf-8") != SENTINEL_TEXT
    ):
        raise FixtureError("fixture root lacks the exact offline-only sentinel")
    return root


class Transaction:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.journal = root / "journal.json"
        self.mutation = root / "mutation.marker"
        self.ready = root / "mutation.ready"
        self.cleanup_started_marker = root / "cleanup.started"
        self.cleanup_continue = root / "cleanup.continue"
        self.receipt = root / "cleanup.receipt.json"
        self.cleanup_started = False

    def _exact_root_entries(self) -> set[str]:
        return {path.name for path in self.root.iterdir()}

    def _remove_transient_markers(self) -> None:
        for path in (self.ready, self.cleanup_started_marker, self.cleanup_continue):
            if path.exists() or path.is_symlink():
                path.unlink()
        _fsync_directory(self.root)

    def _journal_document(self, state: str, **extra: object) -> dict[str, object]:
        document: dict[str, object] = {
            "created_before_mutation": True,
            "recovery_action": "rollback-or-escalate",
            "rollback_count": 0 if state == "prepared" else 1,
            "schema_version": 1,
            "state": state,
        }
        document.update(extra)
        return document

    def prepare(self) -> None:
        allowed = {SENTINEL}
        actual = {path.name for path in self.root.iterdir()}
        if actual != allowed:
            raise FixtureError("run fixture root must contain only its sentinel")
        _write_json(self.journal, self._journal_document("prepared"))
        _write_bytes(self.mutation, b"offline-mutation\n")
        _write_bytes(self.ready, b"ready\n")

    def _finish_cleanup(self, trigger: str, started: float) -> None:
        if self.mutation.exists():
            if self.mutation.is_symlink() or not self.mutation.is_file():
                raise FixtureError("mutation marker changed type during rollback")
            self.mutation.unlink()
            _fsync_directory(self.root)
        self._remove_transient_markers()
        allowed_before_receipt = {SENTINEL, self.journal.name}
        residue = len(self._exact_root_entries() - allowed_before_receipt)
        elapsed = time.monotonic() - started
        if elapsed > RTO_SECONDS:
            raise FixtureError("offline rollback exceeded its bounded RTO")
        receipt_document = {
            "observed_cleanup_seconds": round(elapsed, 6),
            "receipt_count": 1,
            "residue_orphans": residue,
            "rollback_count": 1,
            "rollback_status": "verified" if residue == 0 else "failed",
            "schema_version": 1,
            "signals_deferred": True,
            "trigger": trigger,
        }
        receipt_payload = _write_json(self.receipt, receipt_document)
        receipt_sha256 = hashlib.sha256(receipt_payload).hexdigest()
        _write_json(
            self.journal,
            self._journal_document(
                "closed",
                receipt_sha256=receipt_sha256,
                residue_orphans=residue,
                trigger=trigger,
            ),
            replace=True,
        )
        expected = {SENTINEL, self.journal.name, self.receipt.name}
        if residue != 0 or self._exact_root_entries() != expected:
            raise FixtureError("offline rollback left unclassified fixture residue")

    def _validate_closed_state(self, journal: dict[str, object]) -> None:
        receipt = _read_json(self.receipt)
        if set(receipt) != RECEIPT_FIELDS:
            raise FixtureError("closed cleanup receipt fields are missing or foreign")
        if (
            receipt.get("schema_version") != 1
            or receipt.get("rollback_count") != 1
            or receipt.get("receipt_count") != 1
            or receipt.get("residue_orphans") != 0
            or receipt.get("signals_deferred") is not True
            or receipt.get("rollback_status") != "verified"
            or receipt.get("trigger") not in RECEIPT_TRIGGERS
            or not isinstance(receipt.get("observed_cleanup_seconds"), (int, float))
            or isinstance(receipt.get("observed_cleanup_seconds"), bool)
            or not math.isfinite(receipt["observed_cleanup_seconds"])
            or receipt["observed_cleanup_seconds"] < 0
            or receipt["observed_cleanup_seconds"] > RTO_SECONDS
        ):
            raise FixtureError("closed cleanup receipt is not exact")
        receipt_sha256 = hashlib.sha256(self.receipt.read_bytes()).hexdigest()
        allowed_journal = self._journal_document(
            "closed",
            receipt_sha256=receipt_sha256,
            residue_orphans=0,
            trigger=receipt.get("trigger"),
        )
        if journal != allowed_journal:
            raise FixtureError("closed recovery journal does not bind the exact receipt")
        expected = {SENTINEL, self.journal.name, self.receipt.name}
        if self._exact_root_entries() != expected or self.mutation.exists():
            raise FixtureError("closed transaction retains residue")
        for path in (self.journal, self.receipt):
            if stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode) != 0o600:
                raise FixtureError("durable transaction records must use mode 0600")

    def handle_signal(self, signum: int, _frame: object) -> None:
        if self.cleanup_started:
            return
        self.cleanup_started = True
        for item in SIGNALS:
            signal.signal(item, signal.SIG_IGN)
        started = time.monotonic()
        _write_bytes(self.cleanup_started_marker, b"cleanup-started\n")
        deadline = started + RTO_SECONDS
        while not self.cleanup_continue.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self._finish_cleanup(f"signal-{SIGNAL_NAMES[signum]}", started)
        raise SystemExit(128 + signum)

    def run(self) -> int:
        for item in SIGNALS:
            signal.signal(item, self.handle_signal)
        self.prepare()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            time.sleep(0.05)
        raise FixtureError("offline fixture received no cleanup signal")

    def recover(self) -> int:
        document = _read_json(self.journal)
        if document.get("schema_version") != 1:
            raise FixtureError("recovery journal schema is not exact")
        if document.get("state") == "closed":
            self._validate_closed_state(document)
            return 0
        if document != self._journal_document("prepared"):
            raise FixtureError("recovery journal is foreign or ambiguous")
        if self.receipt.exists():
            raise FixtureError("prepared journal cannot carry a cleanup receipt")
        self.cleanup_started = True
        for item in SIGNALS:
            signal.signal(item, signal.SIG_IGN)
        self._finish_cleanup("journal-recovery", time.monotonic())
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("run", "recover"))
    parser.add_argument("fixture_root")
    args = parser.parse_args(argv)
    try:
        transaction = Transaction(_root(args.fixture_root))
        return transaction.run() if args.mode == "run" else transaction.recover()
    except (FixtureError, OSError, UnicodeDecodeError) as error:
        print(f"DENY: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
