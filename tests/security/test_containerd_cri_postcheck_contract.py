#!/usr/bin/env python3
"""Pin the containerd 2.x split-row CRI postcheck across the runtime scripts.

The pinned runtime is containerd 2.x (``CONTAINERD_VERSION`` in
``versions.env``), where the 1.x ``io.containerd.grpc.v1 cri`` plugin no
longer exists: the CRI surface is two plugins, ``io.containerd.cri.v1
images`` and ``io.containerd.cri.v1 runtime``. A peer-review finding showed
all three runtime scripts still probed the 1.x row, a postcheck that could
never pass on the pinned runtime. This battery keeps that regression dead:

* every script that postchecks CRI health must require BOTH split rows to
  report ``ok`` — half a CRI surface (images without runtime, or the
  reverse) must fail closed;
* the stale 1.x row must never return, in escaped or unescaped spelling;
* the shipped patterns — extracted from the scripts, not re-typed here —
  must match a faithful ``ctr plugins ls`` table and reject every broken
  variant. Faithful means tabwriter-padded: ctr renders the table through
  Go's text/tabwriter with a trailing tab per row (cmd/ctr/commands/
  plugins/plugins.go), which pads the STATUS column with trailing spaces,
  so an anchor that demands ``ok`` at end-of-line without tolerating that
  padding matches no real row at all. The battery therefore proves the
  patterns accept both padded and unpadded healthy tables and still reject
  ``error``, ``skip``, a missing row, an empty probe, and the 1.x table.

Three-row hygiene (issue #49): the platform contract counts a THIRD healthy
row beside the split pair — the CRI gRPC frontend, ``io.containerd.grpc.v1
cri`` — so the healthy tables here carry all three rows and a dedicated
case pins that the shipped patterns still accept a frontend-less table
today. The pending-contract ratchet (tolerated-green plus expectedFailure
deny rows, and the ready-to-lift ``FRONTEND_PATTERN``) lives in
test_containerd_cri_health_contract_matrix.py; this battery only keeps its
fixtures faithful to the three-row surface so the shipped-pattern pins can
never silently lock the two-row shape in as "the healthy table".
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import canonicalize_probe_spellings, required_tool


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = {
    "install-kubernetes.sh": ROOT / "bootstrap" / "pi" / "install-kubernetes.sh",
    "preflight.sh": ROOT / "bootstrap" / "pi" / "preflight.sh",
    "verify.sh": ROOT / "bootstrap" / "pi" / "verify.sh",
}
IMAGES_PATTERN = (
    "^io[.]containerd[.]cri[.]v1[[:space:]]+images[[:space:]].*[[:space:]]ok[[:space:]]*$"
)
RUNTIME_PATTERN = (
    "^io[.]containerd[.]cri[.]v1[[:space:]]+runtime[[:space:]].*[[:space:]]ok[[:space:]]*$"
)
# Any single-quoted extended pattern naming a CRI plugin type; the scripts
# embed the patterns inside grep -Eq '...' probes. The alternation also
# lifts a future ``grpc[.]v1`` frontend probe (the pending three-row
# contract, issue #49), so the exact-two assertions below fail loudly — for
# conscious conversion — the moment the platform lane ships a third probe.
SHIPPED_PATTERN = re.compile(r"'(\^io\[\.\]containerd\[\.\](?:cri|grpc)\[\.\]v1[^']*)'")
GREP = shutil.which("grep")


def script_text(path):
    """Read a bootstrap script in this repository's reviewed spelling.

    Canonical spelling, not raw bytes. ``SHIPPED_PATTERN`` and the stale-row
    tripwire each key on ONE spelling — single-quoted, dots written ``[.]`` —
    so an equivalent probe written with escaped dots inside double quotes
    evaded both (issue #51). Every read in this battery goes through here, and
    ``ProbeSpellingCanonicalisationTests`` pins that today's scripts
    canonicalise to themselves, so nothing is being rewritten silently.
    """

    return canonicalize_probe_spellings(path.read_text(encoding="utf-8"))


def table(rows):
    return "".join(f"{row}\n" for row in rows)


# Column layout reproduced from ctr's tabwriter configuration (minwidth 4,
# tabwidth 8, padding 4, trailing tab per row): STATUS carries trailing pad.
# The healthy tables carry the full three-row CRI surface — split pair plus
# gRPC frontend (module docstring) — so no allow fixture understates the
# platform contract.
HEALTHY_PADDED = table(
    [
        "TYPE                            ID           PLATFORMS      STATUS    ",
        "io.containerd.internal.v1       opt          -              ok        ",
        "io.containerd.cri.v1            images       linux/arm64    ok        ",
        "io.containerd.cri.v1            runtime      linux/arm64    ok        ",
        "io.containerd.grpc.v1           cri          linux/arm64    ok        ",
        "io.containerd.snapshotter.v1    blockfile    linux/arm64    skip      ",
    ]
)
HEALTHY_UNPADDED = table(
    [
        "io.containerd.cri.v1   images   linux/arm64   ok",
        "io.containerd.cri.v1   runtime   linux/arm64   ok",
        "io.containerd.grpc.v1   cri   linux/arm64   ok",
    ]
)
# The pre-#49 healthy shape: split pair present, frontend row absent. The
# shipped patterns accept it (they probe only the split pair), and the
# dedicated case below pins that tolerance so it converts consciously when
# the three-row implementation lands.
FRONTEND_MISSING = table(
    [
        "TYPE                            ID           PLATFORMS      STATUS    ",
        "io.containerd.internal.v1       opt          -              ok        ",
        "io.containerd.cri.v1            images       linux/arm64    ok        ",
        "io.containerd.cri.v1            runtime      linux/arm64    ok        ",
        "io.containerd.snapshotter.v1    blockfile    linux/arm64    skip      ",
    ]
)
RUNTIME_ERROR = HEALTHY_PADDED.replace(
    "runtime      linux/arm64    ok        ",
    "runtime      linux/arm64    error     ",
)
RUNTIME_SKIP = HEALTHY_PADDED.replace(
    "runtime      linux/arm64    ok        ",
    "runtime      linux/arm64    skip      ",
)
IMAGES_MISSING = table(
    [
        line
        for line in HEALTHY_PADDED.splitlines()
        if "images" not in line
    ]
)
# Two readings, one deny: the retired 1.x single-row table, and — read
# against 2.x — a gRPC frontend row standing alone with BOTH split service
# rows missing. Rejected under the shipped contract and the pending
# three-row contract alike; only the surrounding rows distinguish this
# table from the healthy ones above, which is exactly why the healthy
# fixtures must carry all three rows.
V1_ERA_ONLY = table(
    [
        "io.containerd.grpc.v1           cri          linux/arm64    ok        ",
    ]
)


class SplitRowContractTests(unittest.TestCase):
    """Every runtime script must demand both split rows and forget the 1.x row."""

    @classmethod
    def setUpClass(cls):
        cls.texts = {name: script_text(path) for name, path in SCRIPTS.items()}

    def test_every_script_ships_exactly_the_two_split_row_patterns(self):
        for name, text in self.texts.items():
            with self.subTest(script=name):
                self.assertEqual(
                    sorted(SHIPPED_PATTERN.findall(text)),
                    sorted((IMAGES_PATTERN, RUNTIME_PATTERN)),
                )
                self.assertIn("ctr plugins ls", text)

    def test_stale_v1_row_cannot_return_in_any_spelling(self):
        # The tripwire polices executable probes only: comment lines may keep
        # naming the retired plugin type to document why the split rows are
        # required, but any non-comment reintroduction — escaped or plain —
        # fails here before it can resurrect the dead postcheck.
        #
        # Deliberate interplay with the pending three-row contract (issue
        # #49): the frontend probe the platform lane will ship also names
        # grpc.v1, so landing it trips this tripwire ON PURPOSE. That is
        # ratchet behavior, not an accident — the same platform-lane change
        # must consciously rescope this test to police the stale SINGLE-ROW
        # postcheck (a grpc.v1 probe standing alone) rather than pre-weaken
        # it here while no third probe exists.
        for name, text in self.texts.items():
            with self.subTest(script=name):
                code = "\n".join(
                    line
                    for line in text.splitlines()
                    if not line.lstrip().startswith("#")
                )
                self.assertNotIn("grpc[.]v1", code)
                self.assertNotIn("grpc.v1", code)


class ProbeSpellingCanonicalisationTests(unittest.TestCase):
    """Issue #51: an equivalent probe in another spelling is not invisible.

    Every check in this battery, the health matrix, and the regression
    battery keys on ONE spelling: ``grep -Eq`` followed by a single-quoted
    pattern whose dots are written ``[.]``. A functionally equivalent probe
    written ``grep -Eq "^io\\.containerd\\.grpc\\.v1..."`` therefore shipped
    while all five checks — three extractions and both stale-row tripwires —
    stayed green. The dangerous direction is the retired 1.x row returning
    under a spelling the tripwire whose whole job is "in any spelling" could
    not see.

    ``support.canonicalize_probe_spellings`` normalises the SOURCE instead of
    teaching five patterns four spellings. These tests are its deny proofs.
    """

    EVASIVE = {
        "escaped dots in double quotes": (
            'ctr plugins ls | grep -Eq "^io\\.containerd\\.grpc\\.v1'
            '[[:space:]]+cri[[:space:]].*[[:space:]]ok[[:space:]]*$"'
        ),
        "escaped dots in ANSI-C quotes": (
            "ctr plugins ls | grep -Eq $'^io\\\\.containerd\\\\.grpc\\\\.v1'"
        ),
        "bracket dots in double quotes": (
            'ctr plugins ls | grep -Eq "^io[.]containerd[.]grpc[.]v1"'
        ),
        "long option words": (
            "ctr plugins ls | grep --extended-regexp --quiet "
            '"^io\\.containerd\\.grpc\\.v1"'
        ),
        "separated option words": (
            'ctr plugins ls | grep -E -q "^io\\.containerd\\.grpc\\.v1"'
        ),
    }

    def test_todays_scripts_canonicalise_to_themselves(self):
        """The identity pin: normalisation invents nothing.

        Every read in these batteries now goes through the canonicaliser, so
        it must be a no-op on the committed tree — otherwise it would be
        quietly asserting against bytes no script contains.
        """

        for name, path in sorted(SCRIPTS.items()):
            with self.subTest(script=name):
                raw = path.read_text(encoding="utf-8")
                self.assertEqual(canonicalize_probe_spellings(raw), raw)

    def test_every_evasive_spelling_becomes_the_reviewed_spelling(self):
        for label, line in sorted(self.EVASIVE.items()):
            with self.subTest(spelling=label):
                canonical = canonicalize_probe_spellings(line)
                self.assertIn("grep -Eq '^io[.]containerd[.]grpc[.]v1", canonical)

    # The subset that ALSO defeats both stale-row tripwires, because neither
    # `grpc[.]v1` nor `grpc.v1` appears anywhere in the raw line. The
    # bracket-in-double-quotes spelling is deliberately not here: the tripwire
    # already saw it, only the extraction did not.
    TRIPWIRE_EVASIVE = (
        "escaped dots in double quotes",
        "escaped dots in ANSI-C quotes",
        "long option words",
        "separated option words",
    )

    def test_each_evasive_spelling_trips_the_stale_row_tripwire(self):
        """The deny proof, against the tripwire's own two spellings."""

        for label in self.TRIPWIRE_EVASIVE:
            with self.subTest(spelling=label):
                raw = self.EVASIVE[label]
                self.assertNotIn(
                    "grpc[.]v1", raw, "the raw spelling must evade the tripwire"
                )
                self.assertNotIn("grpc.v1", raw, "and evade its second spelling")
                self.assertIn("grpc[.]v1", canonicalize_probe_spellings(raw))

    def test_a_pattern_the_shell_computes_is_left_exactly_as_written(self):
        """Fail-safe, not fail-open: an unresolvable token is not invented.

        Several legitimate probes interpolate a version or an address. Their
        value is not knowable from the text, so the canonicaliser must leave
        them untouched rather than guess — a guessed pattern would be an
        assertion about a probe nobody wrote.
        """

        for line in (
            'grep -Eq "^etcdctl version: ${ETCD_VERSION}([[:space:]]|$)"',
            'grep -Eq "(^|:)${port}$"',
            'grep -Fq "v${CONTAINERD_VERSION}"',
        ):
            with self.subTest(line=line):
                self.assertEqual(canonicalize_probe_spellings(line), line)

    def test_a_fixed_string_search_is_never_rewritten_as_an_ere(self):
        """``-Fq`` is not ``-Eq``; normalising it would assert a lie."""

        line = 'grep -Fq "io\\.containerd\\.grpc\\.v1"'
        self.assertEqual(canonicalize_probe_spellings(line), line)

    def test_this_batterys_own_read_path_sees_the_evasive_probe(self):
        """The wiring, driven rather than asserted.

        A canonicaliser that works in isolation proves nothing about THIS
        battery unless its reads go through it. Each evasive spelling is
        written into a real script and read back with ``script_text`` — the
        one function ``setUpClass`` and the pattern battery both use — and the
        battery's own extraction and the tripwire spelling must then see it.
        Reverting that wiring turns this red; nothing else does, because
        today's committed scripts canonicalise to themselves.
        """

        for label, line in sorted(self.EVASIVE.items()):
            with self.subTest(spelling=label):
                directory = Path(
                    tempfile.mkdtemp(
                        prefix="cri-spelling.", dir=os.environ.get("TMPDIR")
                    )
                )
                self.addCleanup(shutil.rmtree, directory, True)
                script = directory / "verify.sh"
                script.write_text(
                    "#!/usr/bin/env bash\n" + line + "\n", encoding="utf-8"
                )

                self.assertEqual(
                    SHIPPED_PATTERN.findall(script.read_text(encoding="utf-8")),
                    [],
                    "the raw spelling must be invisible to the extraction, or "
                    "this case is not the evasion it claims to be",
                )
                self.assertIn(
                    "^io[.]containerd[.]grpc[.]v1",
                    "".join(SHIPPED_PATTERN.findall(script_text(script))),
                )
                self.assertIn("grpc[.]v1", script_text(script))


@unittest.skipUnless(GREP, "an extended-regexp grep is required for pattern battery")
class SplitRowPatternBatteryTests(unittest.TestCase):
    """Exercise the shipped patterns against faithful and broken plugin tables."""

    @classmethod
    def setUpClass(cls):
        shipped = {
            tuple(sorted(SHIPPED_PATTERN.findall(script_text(path))))
            for path in SCRIPTS.values()
        }
        if shipped != {tuple(sorted((IMAGES_PATTERN, RUNTIME_PATTERN)))}:
            raise AssertionError(
                "runtime scripts disagree on the shipped CRI patterns: %r" % (shipped,)
            )
        # Resolve the Optional grep once, before any argv exists: the
        # class-level skip excludes grep-less hosts, and this fail-closed
        # floor keeps a None out of subprocess argv if that guard is lost.
        cls.grep = required_tool(
            GREP, "an extended-regexp grep is required for pattern battery"
        )

    def probe(self, pattern, data):
        return subprocess.run(
            [self.grep, "-Eq", "--", pattern],
            input=data,
            capture_output=True,
            text=True,
            check=False,
        ).returncode

    def check(self, data):
        """Mirror the scripts' contract: both rows must match or the check fails."""

        return self.probe(IMAGES_PATTERN, data) == 0 and self.probe(RUNTIME_PATTERN, data) == 0

    def test_healthy_padded_table_passes(self):
        self.assertTrue(self.check(HEALTHY_PADDED))

    def test_healthy_unpadded_table_passes(self):
        self.assertTrue(self.check(HEALTHY_UNPADDED))

    def test_frontend_row_missing_is_still_accepted_by_the_shipped_patterns(self):
        # Pending three-row contract (module docstring): the shipped
        # patterns probe only the split pair, so a table without the CRI
        # gRPC frontend row passes today. Pinned green ON PURPOSE — when
        # the platform lane ships the frontend probe, setUpClass's
        # exact-two binding fails first and this tolerance converts into
        # an enforced deny; the loud xfail ratchet for that flip lives in
        # test_containerd_cri_health_contract_matrix.py.
        self.assertTrue(self.check(FRONTEND_MISSING))

    def test_broken_tables_fail_closed(self):
        cases = {
            "runtime-error": RUNTIME_ERROR,
            "runtime-skip": RUNTIME_SKIP,
            "images-missing": IMAGES_MISSING,
            "v1-era-only": V1_ERA_ONLY,
            "empty-probe": "",
        }
        for label, data in cases.items():
            with self.subTest(table=label):
                self.assertFalse(self.check(data))


if __name__ == "__main__":
    unittest.main()
