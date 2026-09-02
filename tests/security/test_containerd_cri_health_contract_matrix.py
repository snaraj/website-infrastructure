#!/usr/bin/env python3
"""Codex health-contract matrix for the containerd 2.3.3 CRI postcheck.

Codex's follow-up item 2 states the health contract the pinned runtime must
satisfy: on containerd 2.3.3 the retired 1.x ``io.containerd.grpc.v1 cri``
plugin is gone and the CRI gRPC frontend is served by two split plugins, so
a healthy probe requires *exactly one* ``io.containerd.cri.v1 images`` row
and *exactly one* ``io.containerd.cri.v1 runtime`` row, both reporting
``ok`` (that pair is the one healthy gRPC CRI frontend — there is no
separate grpc.v1 cri row to check, and its return must be rejected).

The two sibling batteries already pin the split-row contract from two
directions: test_containerd_cri_postcheck_contract.py drives the shipped
patterns through a real extended-regexp grep, and
test_cri_postcheck_regression.py models the same probe conjunction through
Python ``re`` over the committed script text. This third battery is the
exhaustive *allow/deny matrix* Codex item 2 asks for: it extracts the REAL
patterns the three runtime scripts ship (never re-typed here — see
``_extract_shipped_patterns``) and runs them, through the real grep binary,
against a table-driven set of faithful ``ctr plugins ls`` outputs covering
every allow and deny row Codex enumerated: missing, duplicate, malformed,
extra-field, and non-healthy.

Acceptance mirrors the scripts exactly. Each script runs the images and
runtime patterns as two independent ``grep -Eq`` probes and fails closed
(``die``/``fail``/``set -e``) unless BOTH find a line, so acceptance here is
the conjunction over the extracted pattern set. Tables are tabwriter-padded
the way ctr renders them (Go text/tabwriter, trailing tab per row, so STATUS
carries trailing spaces); an unpadded allow row guards against a pattern
that would only ever match the padding.

NOTE — Codex "exactly one" vs the script's shipped ">=1" (peer-review note).
``grep -Eq`` succeeds on the FIRST matching line and never counts, so a
table carrying two identical ``images`` rows (or two ``runtime`` rows) still
satisfies the probe: the shipped contract is ">=1 healthy row", not Codex's
stated "exactly one". This divergence was verified empirically, not assumed
(``grep -Ec`` reports 2 matching lines while ``grep -Eq`` returns 0/accept
for the duplicate table). Closing it to a true "exactly one" would require
changing the probe in bootstrap/pi/** (a platform-lane edit, out of scope
for this test-only delivery-lane task), so the duplicate rows are recorded
two ways here: ``test_duplicate_rows_are_currently_tolerated`` pins the
actual ">=1" behavior green, and the two ``..._exactly_one_..._xfail`` cases
assert Codex's desired rejection under ``unittest.expectedFailure``. They
are xfail today; the day a script tightens the probe to exactly-one they
turn into an unexpected success — a hard failure under ``python -m
unittest`` — which forces removal of the marker and converts this note into
an enforced deny row. The matrix therefore records the gap loudly instead
of greenwashing it.

NOTE — three-row platform contract vs the scripts' shipped two-row probe
(issue #49). The platform lane states the healthy CRI surface as THREE
rows: the two ``io.containerd.cri.v1`` split service rows above plus the
CRI gRPC frontend row (``io.containerd.grpc.v1 cri``) that serves them.
The shipped probes check images+runtime only, so a table with no frontend
row still passes today. That second gap is recorded in the same two-sided
style as the duplicate-row note: every ``ALLOW`` table now carries all
three rows (the faithful healthy surface), the ``FRONTEND_MISSING`` group
pins the current two-row tolerance green
(``test_frontend_row_missing_is_currently_tolerated``), and the
``test_pending_three_row_*_xfail`` cases assert the desired frontend deny
rows under ``unittest.expectedFailure``. ``FRONTEND_PATTERN`` below is the
matching probe, verified against these fixtures so the platform lane can
lift it wholesale; no script ships it yet and nothing here changes what
the scripts enforce. The flip is forced twice over: ``_SHIPPED`` also
lifts ``grpc[.]v1`` frontend probes, and ``setUpClass`` binds the shipped
set to exactly the two canonical patterns, so the moment a script ships a
third probe this battery fails loudly for conscious conversion — the
tolerated pins become enforced denies and the markers come off the xfails.
The DUPLICATE tables carry the frontend row for the same reason: once the
conjunction gains the frontend probe, they must keep isolating the
">=1 vs exactly-one" question instead of failing for a missing frontend
and greenwashing the duplicate ratchet.
"""

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import canonicalize_probe_spellings, required_tool


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = (
    ROOT / "bootstrap" / "pi" / "install-kubernetes.sh",
    ROOT / "bootstrap" / "pi" / "preflight.sh",
    ROOT / "bootstrap" / "pi" / "verify.sh",
)
# The canonical containerd 2.x split-row patterns, asserted below to equal
# what every script actually ships so this battery cannot drift into probing
# a pattern no script uses.
IMAGES_PATTERN = (
    "^io[.]containerd[.]cri[.]v1[[:space:]]+images[[:space:]].*[[:space:]]ok[[:space:]]*$"
)
RUNTIME_PATTERN = (
    "^io[.]containerd[.]cri[.]v1[[:space:]]+runtime[[:space:]].*[[:space:]]ok[[:space:]]*$"
)
EXPECTED_PATTERNS = frozenset({IMAGES_PATTERN, RUNTIME_PATTERN})
# The CRI gRPC frontend probe the pending three-row platform contract will
# need (second module NOTE). Documentation, not enforcement: no script ships
# it yet — setUpClass proves that — and it is exercised here only so the
# platform lane inherits a pattern already verified against these fixtures.
FRONTEND_PATTERN = (
    "^io[.]containerd[.]grpc[.]v1[[:space:]]+cri[[:space:]].*[[:space:]]ok[[:space:]]*$"
)
# Every ``grep -Eq '...'`` probe naming a CRI plugin type; the scripts embed
# the pattern inside the single quotes, so this lifts exactly what ships
# rather than re-declaring it. The alternation also lifts a future
# ``grpc[.]v1`` frontend probe, so the exact-two binding in setUpClass trips
# the moment the three-row implementation lands (second module NOTE).
_SHIPPED = re.compile(r"grep -Eq '(\^io\[\.\]containerd\[\.\](?:cri|grpc)\[\.\]v1[^']*)'")
GREP = shutil.which("grep")


def script_text(path):
    """Read a bootstrap script in this repository's reviewed spelling.

    ``_SHIPPED`` keys on ONE spelling — single-quoted, dots written
    ``[.]`` — so a functionally identical probe written
    ``"^io\\.containerd\\.grpc\\.v1..."`` shipped while every check in this
    battery stayed green (issue #51). The shared canonicaliser rewrites
    the quoting, the option spelling and the dot spelling, and leaves
    today's scripts byte-identical, so the pattern below keeps working
    and the evasive spellings stop being invisible.
    """

    return canonicalize_probe_spellings(path.read_text(encoding="utf-8"))


def _extract_shipped_patterns(path):
    return frozenset(_SHIPPED.findall(script_text(path)))


def table(rows):
    """Join rows into a trailing-newline ``ctr plugins ls`` block."""

    return "".join(row + "\n" for row in rows)


# --- Row vocabulary, tabwriter-padded exactly as ctr renders it. ---------
HEADER = "TYPE                            ID           PLATFORMS      STATUS    "
IMAGES_OK = "io.containerd.cri.v1            images       linux/arm64    ok        "
RUNTIME_OK = "io.containerd.cri.v1            runtime      linux/arm64    ok        "
# One row text, two readings (second module NOTE): on containerd 1.x this
# was the ONLY CRI row — the retired surface the split-row fix rejects — and
# on 2.x the SAME text is the CRI gRPC frontend row that accompanies the two
# split service rows. Context (which rows appear beside it) is what
# separates the dead 1.x table from a healthy three-row 2.x table, so both
# fixture families share this constant instead of re-typing the row.
FRONTEND_OK = "io.containerd.grpc.v1           cri          linux/arm64    ok        "
OPT_OK = "io.containerd.internal.v1       opt          -              ok        "
OVERLAY_OK = "io.containerd.snapshotter.v1    overlayfs    linux/arm64    ok        "
BLOCK_SKIP = "io.containerd.snapshotter.v1    blockfile    linux/arm64    skip      "
# A crowd of unrelated healthy plugins, including grpc.v1 rows with non-cri
# IDs: a pattern loose enough to match "any grpc.v1 row" would be satisfied
# by these, so their presence proves the CRI check is specific.
OTHER_PLUGINS = (
    "io.containerd.image-verifier.v1 bindir       -              ok        ",
    "io.containerd.internal.v1       opt          -              ok        ",
    "io.containerd.internal.v1       restart      -              ok        ",
    "io.containerd.content.v1        content      -              ok        ",
    "io.containerd.metadata.v1       bolt         -              ok        ",
    "io.containerd.snapshotter.v1    overlayfs    linux/arm64    ok        ",
    "io.containerd.snapshotter.v1    blockfile    linux/arm64    skip      ",
    "io.containerd.differ.v1         walking      linux/arm64    ok        ",
    "io.containerd.gc.v1             scheduler    -              ok        ",
    "io.containerd.lease.v1          manager      -              ok        ",
    "io.containerd.grpc.v1           containers   -              ok        ",
    "io.containerd.grpc.v1           namespaces   -              ok        ",
    "io.containerd.sandbox.store.v1  local        -              ok        ",
    "io.containerd.streaming.v1      manager      -              ok        ",
)

# --- ALLOW: healthy tables the shipped probe must accept. ----------------
# Every allow table carries the FULL three-row surface of the platform
# contract (second module NOTE): the two split service rows plus the CRI
# gRPC frontend row. The shipped probes only require the split pair, but a
# two-row allow fixture would silently lock that partial shape in as "the
# healthy table" — the two-row shape now lives in FRONTEND_MISSING below,
# tolerated-today and pending-deny, so nothing green here understates the
# contract the platform lane is implementing.
ALLOW = {
    # Canonical healthy 2.3.3 output: one images ok, one runtime ok, one
    # gRPC frontend ok, padded.
    "canonical_healthy_padded": table(
        (HEADER, OPT_OK, IMAGES_OK, RUNTIME_OK, FRONTEND_OK, BLOCK_SKIP)
    ),
    # The same surface without tabwriter padding, so a pattern cannot pass by
    # matching only the trailing spaces.
    "canonical_healthy_unpadded": table(
        (
            "io.containerd.cri.v1   images   linux/arm64   ok",
            "io.containerd.cri.v1   runtime   linux/arm64   ok",
            "io.containerd.grpc.v1   cri   linux/arm64   ok",
        )
    ),
    # Many unrelated plugins present; the three CRI rows still healthy.
    # Proves other plugins (including unhealthy skips and non-cri grpc.v1
    # rows) do not break the check.
    "healthy_with_many_other_plugins": table(
        (HEADER,) + OTHER_PLUGINS + (IMAGES_OK, RUNTIME_OK, FRONTEND_OK)
    ),
}

# --- DENY: every table the probe must fail closed on. --------------------
# Every table here is a deny row under BOTH the shipped two-probe contract
# and the pending three-row contract, so none of them moves when the
# frontend probe lands.
DENY = {
    # Missing rows: half a CRI surface, or none at all.
    "missing_images": table((HEADER, OPT_OK, RUNTIME_OK, BLOCK_SKIP)),
    "missing_runtime": table((HEADER, OPT_OK, IMAGES_OK, BLOCK_SKIP)),
    "both_missing": table((HEADER, OPT_OK, OVERLAY_OK, BLOCK_SKIP)),
    # The same half-surfaces with the gRPC frontend row present: a healthy
    # frontend row can never substitute for a missing split service row, so
    # a probe loose enough to accept "any healthy CRI-ish row" fails here.
    # These are the faithful 2.x partial-failure shapes (the frontend row
    # renders even when a service beneath it is gone).
    "missing_images_with_frontend_present": table(
        (HEADER, OPT_OK, FRONTEND_OK, RUNTIME_OK, BLOCK_SKIP)
    ),
    "missing_runtime_with_frontend_present": table(
        (HEADER, OPT_OK, IMAGES_OK, FRONTEND_OK, BLOCK_SKIP)
    ),
    # Malformed rows: the TYPE loses its v1 suffix; the ID is truncated. The
    # anchored literal type/id can no longer match either row.
    "malformed_truncated_type": table(
        (
            HEADER,
            "io.containerd.cri.v            images       linux/arm64    ok        ",
            RUNTIME_OK,
        )
    ),
    "malformed_garbled_id": table(
        (
            HEADER,
            "io.containerd.cri.v1            imag         linux/arm64    ok        ",
            RUNTIME_OK,
        )
    ),
    # Extra-field row: an unexpected column appended after STATUS pushes a
    # non-"ok" token to end-of-line. The pattern anchors ``ok`` to EOL (not a
    # fixed column), so a trailing extra field is exactly what defeats it.
    "extra_field_after_status": table(
        (
            HEADER,
            "io.containerd.cri.v1            images       linux/arm64    ok    linux/amd64 ",
            RUNTIME_OK,
        )
    ),
    # Non-healthy STATUS in the runtime row: error, skip, and blank.
    "status_error": table(
        (
            HEADER,
            OPT_OK,
            IMAGES_OK,
            "io.containerd.cri.v1            runtime      linux/arm64    error     ",
        )
    ),
    "status_skip": table(
        (
            HEADER,
            OPT_OK,
            IMAGES_OK,
            "io.containerd.cri.v1            runtime      linux/arm64    skip      ",
        )
    ),
    "status_blank": table(
        (
            HEADER,
            OPT_OK,
            IMAGES_OK,
            "io.containerd.cri.v1            runtime      linux/arm64              ",
        )
    ),
    # Two readings, one deny (see FRONTEND_OK): as the retired 1.x
    # single-row surface this must remain rejected on 2.3.3, and as a 2.x
    # frontend row standing alone it is a table missing BOTH split service
    # rows. Deny under the shipped contract and the pending three-row
    # contract alike.
    "legacy_v1_single_row": table((HEADER, OPT_OK, OVERLAY_OK, FRONTEND_OK)),
    # Degenerate probe output.
    "empty_output": "",
    "header_only": table((HEADER,)),
}

# --- DUPLICATE: Codex "exactly one" vs the shipped ">=1"; see module NOTE.
# The frontend row rides along so these tables isolate the duplication
# question under BOTH contracts: without it, the pending three-row
# conjunction would reject them for the missing frontend and the xfail pair
# below would flip for the wrong reason (second module NOTE).
DUPLICATE = {
    "duplicate_images": table(
        (HEADER, OPT_OK, IMAGES_OK, IMAGES_OK, RUNTIME_OK, FRONTEND_OK)
    ),
    "duplicate_runtime": table(
        (HEADER, OPT_OK, IMAGES_OK, RUNTIME_OK, RUNTIME_OK, FRONTEND_OK)
    ),
}

# --- FRONTEND_MISSING: shipped two-row acceptance vs the pending three-row
#     platform contract; see the second module NOTE. The first three tables
#     are byte-for-byte the allow tables this battery carried before issue
#     #49 — the split moved them here so the two-row shape stays covered as
#     a documented tolerance instead of masquerading as the healthy
#     contract.
FRONTEND_MISSING = {
    "frontend_missing_padded": table(
        (HEADER, OPT_OK, IMAGES_OK, RUNTIME_OK, BLOCK_SKIP)
    ),
    "frontend_missing_unpadded": table(
        (
            "io.containerd.cri.v1   images   linux/arm64   ok",
            "io.containerd.cri.v1   runtime   linux/arm64   ok",
        )
    ),
    "frontend_missing_among_other_plugins": table(
        (HEADER,) + OTHER_PLUGINS + (IMAGES_OK, RUNTIME_OK)
    ),
    # Frontend present but unhealthy: the split rows alone still satisfy
    # the shipped probes, so an errored gRPC frontend — no CRI API for the
    # kubelet even with both services ok — passes today.
    "frontend_unhealthy_error": table(
        (
            HEADER,
            OPT_OK,
            IMAGES_OK,
            RUNTIME_OK,
            "io.containerd.grpc.v1           cri          linux/arm64    error     ",
        )
    ),
}


@unittest.skipUnless(GREP, "an extended-regexp grep is required for the matrix")
class CriHealthContractMatrixTests(unittest.TestCase):
    """Run the shipped split-row patterns across the full Codex allow/deny set."""

    @classmethod
    def setUpClass(cls):
        # Bind the matrix to what the scripts actually ship: every script must
        # carry exactly the two canonical split-row patterns, or the premise
        # of this battery is void and it fails loudly here rather than testing
        # a pattern no script uses.
        shipped = {path.name: _extract_shipped_patterns(path) for path in SCRIPTS}
        disagreeing = {
            name: sorted(pats) for name, pats in shipped.items() if pats != EXPECTED_PATTERNS
        }
        if disagreeing:
            raise AssertionError(
                "runtime scripts do not ship exactly the two canonical CRI "
                "patterns: %r" % (disagreeing,)
            )
        cls.patterns = tuple(sorted(EXPECTED_PATTERNS))
        # Resolve the Optional grep once, before any argv exists: the
        # class-level skip excludes grep-less hosts, and this fail-closed
        # floor keeps a None out of subprocess argv if that guard is lost.
        cls.grep = required_tool(
            GREP, "an extended-regexp grep is required for the matrix"
        )

    def _matches(self, pattern, data):
        return (
            subprocess.run(
                [self.grep, "-Eq", "--", pattern],
                input=data,
                capture_output=True,
                text=True,
                check=False,
            ).returncode
            == 0
        )

    def accepts(self, data):
        """The scripts' contract: BOTH split-row probes must match."""

        return all(self._matches(pattern, data) for pattern in self.patterns)

    def test_allow_tables_pass(self):
        for label, data in ALLOW.items():
            with self.subTest(allow=label):
                self.assertTrue(self.accepts(data), label)

    def test_deny_tables_fail_closed(self):
        for label, data in DENY.items():
            with self.subTest(deny=label):
                self.assertFalse(self.accepts(data), label)

    def test_duplicate_rows_are_currently_tolerated(self):
        # Records the shipped ">=1" reality (module NOTE): grep -Eq accepts a
        # table with a duplicated split row. Green today; it is the honest
        # counterpart to the xfail cases below, which assert Codex's stricter
        # "exactly one".
        for label, data in DUPLICATE.items():
            with self.subTest(duplicate=label):
                self.assertTrue(self.accepts(data), label)

    @unittest.expectedFailure
    def test_codex_exactly_one_rejects_duplicate_images_xfail(self):
        # Codex item 2: "exactly one split images service". The shipped probe
        # does not enforce it (module NOTE), so this desired-deny assertion is
        # xfail. If a future platform-lane change tightens the probe to
        # exactly-one, this becomes an unexpected success and the suite goes
        # red, forcing this marker's removal.
        self.assertFalse(self.accepts(DUPLICATE["duplicate_images"]))

    @unittest.expectedFailure
    def test_codex_exactly_one_rejects_duplicate_runtime_xfail(self):
        # Codex item 2: "exactly one split runtime service"; see the images
        # twin above. Xfail until the shipped probe enforces exactly-one.
        self.assertFalse(self.accepts(DUPLICATE["duplicate_runtime"]))

    def test_frontend_row_missing_is_currently_tolerated(self):
        # Records the shipped two-row reality (second module NOTE): the
        # probes require only the split service pair, so a table with no
        # healthy gRPC frontend row — or an errored one — still passes.
        # Green today; these assertions go red the moment the shipped
        # probe set grows the frontend probe, forcing conversion into
        # enforced deny rows alongside the xfail pair below.
        for label, data in FRONTEND_MISSING.items():
            with self.subTest(pending=label):
                self.assertTrue(self.accepts(data), label)

    def test_documented_frontend_pattern_is_ready_for_the_three_row_contract(self):
        # FRONTEND_PATTERN is documentation for the platform lane (second
        # module NOTE), verified here against the fixtures BEFORE any
        # script ships it: it must match the frontend row in every allow
        # table and reject its absence and its unhealthy variant, in the
        # same real-grep discipline as the shipped patterns.
        for label, data in ALLOW.items():
            with self.subTest(allow=label):
                self.assertTrue(self._matches(FRONTEND_PATTERN, data), label)
        for label in (
            "frontend_missing_padded",
            "frontend_missing_unpadded",
            "frontend_missing_among_other_plugins",
            "frontend_unhealthy_error",
        ):
            with self.subTest(pending=label):
                self.assertFalse(
                    self._matches(FRONTEND_PATTERN, FRONTEND_MISSING[label]), label
                )

    @unittest.expectedFailure
    def test_pending_three_row_rejects_missing_frontend_xfail(self):
        # Pending three-row contract (second module NOTE): a table without
        # the CRI gRPC frontend row is only two thirds of the healthy
        # surface. The shipped probes do not enforce it, so this
        # desired-deny assertion is xfail; a platform-lane frontend probe
        # turns it into an unexpected success — a hard suite failure —
        # forcing the marker's removal.
        self.assertFalse(self.accepts(FRONTEND_MISSING["frontend_missing_padded"]))

    @unittest.expectedFailure
    def test_pending_three_row_rejects_unhealthy_frontend_xfail(self):
        # The unhealthy twin: a present-but-errored frontend row serves no
        # CRI API and must fail the three-row contract. Xfail until the
        # shipped probe set says so.
        self.assertFalse(self.accepts(FRONTEND_MISSING["frontend_unhealthy_error"]))


if __name__ == "__main__":
    unittest.main()
