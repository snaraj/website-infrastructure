#!/usr/bin/env python3
"""Enforce the self-verifying, zero-third-party coverage contract.

The repository refuses external coverage services on supply-chain grounds:
uploading measurement payloads plus a repository token to a third party
contradicts a tree that checksum-verifies every CI binary and treats its
own history as adversarial.  Instead, coverage is measured inside the gate
with the one hash-pinned ``coverage`` wheel, compared against a committed
ledger (``docs/badges/coverage.json``), and rendered into a committed badge
(``docs/badges/coverage.svg``) that CI re-derives byte-for-byte.  A badge
that does not equal its deterministic re-render fails the gate, so the
badge cannot claim a number the gate did not measure.

Subcommands
    gate     Measure (from an existing coverage data file), enforce the
             floor, enforce ledger drift bounds, and prove the committed
             badge equals the deterministic render of the ledger.
    refresh  Rewrite the ledger and badge from the current measurement.
             Used locally; the result is committed and then defended by
             ``gate`` in CI.
    render   Rewrite only the badge from the committed ledger.

Every failure path exits non-zero with an actionable message; there is no
warn-only mode.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = REPO_ROOT / "docs" / "badges" / "coverage.json"
BADGE_PATH = REPO_ROOT / "docs" / "badges" / "coverage.svg"
LEDGER_SCHEMA = 1
# The ledger records the run recorded by the committer; CI re-measures on
# ubuntu.  Platform-conditional tests (Linux procfs semantics, privileged
# skips) make small cross-platform deltas legitimate, so drift inside the
# tolerance is accepted while the floor stays absolute.  Real regressions
# larger than the tolerance fail closed.
MAX_BADGE_BYTES = 2048

_CHAR_WIDTH_PX = 7.0
_BADGE_HEIGHT = 20
_LABEL_TEXT = "coverage"
_COLOR_OK = "#2da44e"
_COLOR_LOW = "#d1242f"
_COLOR_LABEL = "#444d56"


def _fail(message: str) -> int:
    print("coverage-gate: FAIL " + message, file=sys.stderr)
    return 1


def _measure_percent(data_file: Path) -> float:
    """Export totals from an existing coverage data file, fail-closed."""

    if not data_file.is_file():
        raise ValueError(
            "coverage data file is missing: {} (run the suite under "
            "'python -m coverage run' first)".format(data_file)
        )
    with tempfile.TemporaryDirectory() as scratch:
        export = Path(scratch) / "coverage-export.json"
        environment = dict(os.environ)
        environment["COVERAGE_FILE"] = str(data_file)
        environment["COVERAGE_SOURCE_ROOT"] = str(REPO_ROOT / "scripts")
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "json",
                "--rcfile",
                str(REPO_ROOT / "scripts" / "ci" / "coveragerc"),
                "-o",
                str(export),
            ],
            cwd=str(REPO_ROOT),
            env=environment,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise ValueError(
                "coverage export failed: " + completed.stderr.strip()
            )
        try:
            document = json.loads(export.read_text(encoding="utf-8"))
            percent = document["totals"]["percent_covered"]
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError("coverage export is unreadable: {}".format(error))
    if not isinstance(percent, (int, float)) or not 0.0 <= float(percent) <= 100.0:
        raise ValueError("coverage export total is out of range")
    return round(float(percent), 1)


def _load_ledger() -> dict:
    try:
        document = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError("coverage ledger is unreadable: {}".format(error))
    if not isinstance(document, dict) or document.get("schema") != LEDGER_SCHEMA:
        raise ValueError("coverage ledger schema is not recognized")
    for key in ("total_percent", "floor_percent", "drift_tolerance_percent"):
        value = document.get(key)
        if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 100.0:
            raise ValueError("coverage ledger field is invalid: " + key)
    return document


def _text_width(text: str) -> int:
    return int(len(text) * _CHAR_WIDTH_PX) + 10


def render_badge(total_percent: float, floor_percent: float) -> bytes:
    """Deterministically render the ASCII-only badge for the ledger values.

    The output is intentionally minimal: fixed element set (svg, title, g,
    rect, text), no scripts, no hyperlinks, no external references, no
    embedded data.  ``validate_repository.py`` enforces those same limits
    on the committed file, and ``gate`` proves byte equality with this
    render, so the committed badge can never diverge from the ledger.
    """

    value_text = "{:.1f}%".format(total_percent)
    color = _COLOR_OK if total_percent >= floor_percent else _COLOR_LOW
    label_width = _text_width(_LABEL_TEXT)
    value_width = _text_width(value_text)
    total_width = label_width + value_width
    template = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="{height}"'
        ' role="img" aria-label="{label}: {value}">'
        "<title>{label}: {value}</title>"
        '<g shape-rendering="crispEdges">'
        '<rect width="{lw}" height="{height}" fill="{label_color}"/>'
        '<rect x="{lw}" width="{vw}" height="{height}" fill="{color}"/>'
        "</g>"
        '<g fill="#fff" text-anchor="middle"'
        ' font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        '<text x="{lx}" y="14">{label}</text>'
        '<text x="{vx}" y="14">{value}</text>'
        "</g>"
        "</svg>\n"
    ).format(
        total=total_width,
        height=_BADGE_HEIGHT,
        label=_LABEL_TEXT,
        value=value_text,
        lw=label_width,
        vw=value_width,
        label_color=_COLOR_LABEL,
        color=color,
        lx=label_width // 2,
        vx=label_width + value_width // 2,
    )
    encoded = template.encode("ascii", "strict")
    if len(encoded) > MAX_BADGE_BYTES:
        raise ValueError("rendered badge exceeds the byte ceiling")
    return encoded


def _write_ledger_and_badge(percent: float, ledger: dict) -> None:
    ledger = dict(ledger)
    ledger["total_percent"] = percent
    serialized = json.dumps(ledger, indent=2, sort_keys=True) + "\n"
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    LEDGER_PATH.write_text(serialized, encoding="utf-8")
    BADGE_PATH.write_bytes(
        render_badge(percent, float(ledger["floor_percent"]))
    )


def _gate(data_file: Path) -> int:
    try:
        ledger = _load_ledger()
        measured = _measure_percent(data_file)
    except ValueError as error:
        return _fail(str(error))
    floor = round(float(ledger["floor_percent"]), 1)
    recorded = round(float(ledger["total_percent"]), 1)
    tolerance = round(float(ledger["drift_tolerance_percent"]), 1)
    print(
        "coverage-gate: measured {:.1f}% (ledger {:.1f}%, floor {:.1f}%, "
        "tolerance {:.1f})".format(measured, recorded, floor, tolerance)
    )
    if measured < floor:
        return _fail(
            "measured coverage {:.1f}% is below the enforced floor {:.1f}%; "
            "add tests (never weaken validators) before raising code".format(
                measured, floor
            )
        )
    if abs(measured - recorded) > tolerance:
        return _fail(
            "measured coverage {:.1f}% drifted more than {:.1f} points from "
            "the committed ledger {:.1f}%; run "
            "'make coverage-refresh' and commit docs/badges/".format(
                measured, tolerance, recorded
            )
        )
    try:
        expected = render_badge(recorded, floor)
    except ValueError as error:
        return _fail(str(error))
    try:
        committed = BADGE_PATH.read_bytes()
    except OSError as error:
        return _fail("committed badge is unreadable: {}".format(error))
    if committed != expected:
        return _fail(
            "docs/badges/coverage.svg does not equal the deterministic "
            "render of docs/badges/coverage.json; run 'make coverage-refresh'"
        )
    print("coverage-gate: PASS floor, drift, and badge integrity")
    return 0


def _refresh(data_file: Path) -> int:
    try:
        ledger = _load_ledger()
        measured = _measure_percent(data_file)
        _write_ledger_and_badge(measured, ledger)
    except ValueError as error:
        return _fail(str(error))
    print(
        "coverage-gate: refreshed ledger and badge at {:.1f}% "
        "(commit docs/badges/)".format(measured)
    )
    return 0


def _render(_: Path) -> int:
    try:
        ledger = _load_ledger()
        BADGE_PATH.write_bytes(
            render_badge(
                round(float(ledger["total_percent"]), 1),
                round(float(ledger["floor_percent"]), 1),
            )
        )
    except (OSError, ValueError) as error:
        return _fail(str(error))
    print("coverage-gate: badge rendered from the committed ledger")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("gate", "refresh", "render"))
    parser.add_argument(
        "--data-file",
        type=Path,
        default=None,
        help="coverage data file produced by 'coverage run' + 'coverage combine'",
    )
    args = parser.parse_args(argv)
    if args.command in {"gate", "refresh"} and args.data_file is None:
        parser.error("--data-file is required for gate and refresh")
    handler = {"gate": _gate, "refresh": _refresh, "render": _render}[args.command]
    return handler(args.data_file)


if __name__ == "__main__":
    raise SystemExit(main())
