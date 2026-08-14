"""Hostile battery for the one approved-badge exception to the media law.

The repository forbids all media content; `docs/badges/coverage.svg` is the
single deliberate exception, and this suite is what keeps that exception
from becoming a hole. Every case plants a hostile "badge" and asserts
`check_media` still reports it: active content, hyperlinks, embedded data,
non-ASCII bytes, wrong envelope, out-of-allowlist elements, renamed binary
magic, oversize payloads — and any SVG at any other path, which stays
plainly forbidden exactly as before. The committed badge itself must pass,
and separately must equal the deterministic render of the coverage ledger,
so the exception admits only the artifact the gate generates.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from .support import load_script

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = load_script(
    "validate_repository.py", module_name="badge_validate_repository"
)
GATE = load_script("ci/coverage_gate.py", module_name="badge_coverage_gate")
HISTORY = load_script(
    "validate_publication_history.py", module_name="badge_publication_history"
)
BADGE_REL = "docs/badges/coverage.svg"


class ApprovedBadgeContractTests(unittest.TestCase):
    """One reviewed badge passes; every hostile variant stays media."""

    def setUp(self):
        self.committed = (REPO_ROOT / BADGE_REL).read_bytes()

    def rejects(self, data, fragment="approved badge violates"):
        problems = MODULE.approved_badge_errors(data, BADGE_REL)
        self.assertTrue(problems, "hostile badge was accepted")
        self.assertTrue(
            any(fragment in problem for problem in problems),
            problems,
        )

    def test_committed_badge_satisfies_the_strict_contract(self):
        self.assertEqual(MODULE.approved_badge_errors(self.committed, BADGE_REL), [])

    def test_committed_badge_equals_the_deterministic_ledger_render(self):
        ledger = json.loads(
            (REPO_ROOT / "docs" / "badges" / "coverage.json").read_text()
        )
        rendered = GATE.render_badge(
            round(float(ledger["total_percent"]), 1),
            round(float(ledger["floor_percent"]), 1),
        )
        self.assertEqual(self.committed, rendered)

    def test_docs_derive_coverage_and_test_inventory_without_stale_snapshots(self):
        agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "`total_percent` is the sole numeric source of truth; do not duplicate a\n"
            "  measured snapshot in prose",
            agents,
        )
        self.assertNotRegex(
            agents,
            r"\b\d+(?:\.\d+)?% at the last refresh\b",
        )
        self.assertIn(
            "tests/                 allow/deny fixtures collected by canonical unittest discovery",
            readme,
        )
        self.assertNotRegex(readme, r"\b\d[\d,]* repository tests\b")

    def test_active_content_and_references_are_rejected(self):
        body = self.committed.decode("ascii")
        prefix = MODULE.BADGE_REQUIRED_PREFIX
        suffix = "</svg>\n"
        core = body[len(prefix):-len(suffix)]
        for label, hostile_core in (
            ("script", core + "<script>window.n=1</script>"),
            ("href", core.replace("<text", '<text href="https:..."', 1)),
            ("xlink", core.replace("<text", "<text xlink:x=\"y\"", 1)),
            ("image-element", core + '<image x="0"/>'),
            ("use-element", core + '<use x="0"/>'),
            ("foreignobject", core + "<foreignObject/>"),
            ("base64-payload", core + "<!-- aGkK base64 -->"),
            ("data-uri", core.replace("fill", "fill-data:x", 1)),
            ("second-url", core + "<title>http://x</title>"),
            ("numeric-entity", core + "<title>&#106;</title>"),
            ("doctype-comment", "<!-- c -->" + core),
            ("processing-instruction", "<?xml version=\"1.0\"?>" + core),
            ("unknown-element", core + "<circle r=\"9\"/>"),
        ):
            with self.subTest(hostile=label):
                self.rejects((prefix + hostile_core + suffix).encode("ascii"))

    def test_wrong_envelope_and_encodings_are_rejected(self):
        self.rejects(b"<svg>" + self.committed[40:], "approved badge")
        self.rejects(self.committed[:-1], "approved badge")  # lost trailing LF
        self.rejects(
            self.committed.replace(b"coverage", "cöverage".encode("utf-8"), 1)
        )
        self.rejects(self.committed + b"\x07", "approved badge")

    def test_renamed_binary_magic_is_still_media(self):
        # A PNG renamed to the approved path must not ride the exception:
        # it fails the envelope/ASCII law and stays reported.
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        self.rejects(png)

    def test_oversize_badge_is_rejected(self):
        padding = b"<title>" + b"a" * MODULE.MAX_TEXT_BADGE_BYTES + b"</title>"
        oversized = self.committed[:-7] + padding + b"</svg>\n"
        self.rejects(oversized, "byte ceiling")

    def test_any_other_svg_path_stays_forbidden(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "docs" / "badges").mkdir(parents=True)
            shutil.copyfile(REPO_ROOT / BADGE_REL, root / BADGE_REL)
            stray = root / "docs" / "stray.svg"
            shutil.copyfile(REPO_ROOT / BADGE_REL, stray)
            errors = MODULE.check_media(root)
            self.assertTrue(
                any("docs/stray.svg" in error for error in errors),
                errors,
            )
            self.assertFalse(
                any(BADGE_REL in error for error in errors),
                errors,
            )

    def test_badge_law_is_identical_in_the_history_validator(self):
        """The immutable-history gate carries a mirrored copy of the badge
        law; its constants must stay byte-identical and its verdict must
        agree with the working-tree validator on every probe, or one gate
        would admit what the other rejects."""

        for name in (
            "APPROVED_TEXT_BADGE_PATHS",
            "MAX_TEXT_BADGE_BYTES",
            "BADGE_REQUIRED_PREFIX",
            "BADGE_FORBIDDEN_FRAGMENTS",
            "BADGE_ALLOWED_ELEMENTS",
        ):
            with self.subTest(constant=name):
                self.assertEqual(getattr(MODULE, name), getattr(HISTORY, name))
        probes = [
            self.committed,
            self.committed.replace(b"</svg>\n", b"<script>x</script></svg>\n"),
            self.committed.replace(b"coverage", "cöverage".encode("utf-8"), 1),
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 64,
            self.committed[:-1],
            b"<svg>tiny</svg>\n",
            self.committed[:-7] + b"<circle r=\"1\"/></svg>\n",
        ]
        for index, probe in enumerate(probes):
            with self.subTest(probe=index):
                self.assertEqual(
                    bool(MODULE.approved_badge_errors(probe, BADGE_REL)),
                    HISTORY._approved_badge_violation(probe),
                )

    def test_hostile_badge_at_the_approved_path_fails_check_media(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "docs" / "badges").mkdir(parents=True)
            hostile = self.committed.replace(
                b"</svg>\n", b"<script>x</script></svg>\n"
            )
            (root / BADGE_REL).write_bytes(hostile)
            errors = MODULE.check_media(root)
            self.assertTrue(
                any(
                    "approved badge violates" in error and BADGE_REL in error
                    for error in errors
                ),
                errors,
            )


if __name__ == "__main__":
    unittest.main()
