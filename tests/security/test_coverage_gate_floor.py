"""Focused floor-enforcement battery for the self-hosted coverage gate.

``scripts/ci/coverage_gate.py`` refuses measurements below the committed
floor, yet that comparison had zero direct test coverage: inverting or
deleting ``measured < floor`` survived the entire suite, because every
suite run only ever exercised passing measurements. These cases drive
the gate through its own ``main()`` entry point (the same argv surface
CI invokes) against a hermetic ledger/badge pair, stubbing only the
measurement itself, and pin all three sides of the boundary: below the
floor refuses with the documented diagnostic, at the floor passes, and
above the floor passes. The fixture's drift tolerance is deliberately
wide enough that nothing except the floor comparison can reject the
below-floor cases, so a bypassed or inverted comparison flips these
assertions directly instead of hiding behind a neighboring check.
"""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_SCRIPT = REPO_ROOT / "scripts" / "ci" / "coverage_gate.py"
SPEC = importlib.util.spec_from_file_location(
    "coverage_gate_floor_battery", str(GATE_SCRIPT)
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

FLOOR_PERCENT = 76.0
RECORDED_PERCENT = 80.0
# Wide enough that every measurement probed below can only be rejected by
# the floor comparison, never by the ledger-drift bound.
DRIFT_TOLERANCE_PERCENT = 100.0


class CoverageGateFloorTests(unittest.TestCase):
    """The floor is absolute: below fails with its message, at/above pass."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        root = Path(self._directory.name).resolve()
        self.ledger_path = root / "coverage.json"
        self.badge_path = root / "coverage.svg"
        self.data_file = root / "coverage-data"
        self.ledger_path.write_text(
            json.dumps(
                {
                    "schema": MODULE.LEDGER_SCHEMA,
                    "total_percent": RECORDED_PERCENT,
                    "floor_percent": FLOOR_PERCENT,
                    "drift_tolerance_percent": DRIFT_TOLERANCE_PERCENT,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.badge_path.write_bytes(
            MODULE.render_badge(RECORDED_PERCENT, FLOOR_PERCENT)
        )
        self.data_file.write_bytes(b"")

    def run_gate(self, measured_percent):
        """Run the real gate entry point with only the measurement stubbed."""

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE, "LEDGER_PATH", self.ledger_path
        ), mock.patch.object(
            MODULE, "BADGE_PATH", self.badge_path
        ), mock.patch.object(
            MODULE, "_measure_percent", return_value=measured_percent
        ) as measure, contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(
            stderr
        ):
            result = MODULE.main(["gate", "--data-file", str(self.data_file)])
        measure.assert_called_once_with(self.data_file)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_below_floor_measurement_fails_with_the_documented_refusal(self):
        # 75.9 sits one tenth below the floor and far inside the drift
        # tolerance: the floor comparison is the only check that can (and
        # must) reject it. 38.5 proves the refusal is not an edge artifact.
        for measured in (75.9, 38.5):
            with self.subTest(measured=measured):
                result, stdout, stderr = self.run_gate(measured)
                self.assertEqual(result, 1, stderr)
                self.assertIn(
                    "coverage-gate: FAIL measured coverage {:.1f}% is below "
                    "the enforced floor {:.1f}%".format(
                        measured, FLOOR_PERCENT
                    ),
                    stderr,
                )
                self.assertIn(
                    "add tests (never weaken validators) before raising code",
                    stderr,
                )
                self.assertNotIn("PASS", stdout)

    def test_at_floor_measurement_passes(self):
        result, stdout, stderr = self.run_gate(FLOOR_PERCENT)
        self.assertEqual(result, 0, stderr)
        self.assertIn(
            "coverage-gate: PASS floor, drift, and badge integrity", stdout
        )
        self.assertEqual(stderr, "")

    def test_above_floor_measurement_passes(self):
        # Just above the boundary, and at the ceiling: an inverted
        # comparison would refuse both of these as "below the floor".
        for measured in (76.1, 100.0):
            with self.subTest(measured=measured):
                result, stdout, stderr = self.run_gate(measured)
                self.assertEqual(result, 0, stderr)
                self.assertIn(
                    "coverage-gate: PASS floor, drift, and badge integrity",
                    stdout,
                )
                self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()
