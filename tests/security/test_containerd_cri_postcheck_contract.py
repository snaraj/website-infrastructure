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
"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path


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
# Any single-quoted extended pattern naming the split CRI plugin type; the
# scripts embed the patterns inside grep -Eq '...' probes.
SHIPPED_PATTERN = re.compile(r"'(\^io\[\.\]containerd\[\.\]cri\[\.\]v1[^']*)'")
GREP = shutil.which("grep")


def table(rows):
    return "".join(f"{row}\n" for row in rows)


# Column layout reproduced from ctr's tabwriter configuration (minwidth 4,
# tabwidth 8, padding 4, trailing tab per row): STATUS carries trailing pad.
HEALTHY_PADDED = table(
    [
        "TYPE                            ID           PLATFORMS      STATUS    ",
        "io.containerd.internal.v1       opt          -              ok        ",
        "io.containerd.cri.v1            images       linux/arm64    ok        ",
        "io.containerd.cri.v1            runtime      linux/arm64    ok        ",
        "io.containerd.snapshotter.v1    blockfile    linux/arm64    skip      ",
    ]
)
HEALTHY_UNPADDED = table(
    [
        "io.containerd.cri.v1   images   linux/arm64   ok",
        "io.containerd.cri.v1   runtime   linux/arm64   ok",
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
V1_ERA_ONLY = table(
    [
        "io.containerd.grpc.v1           cri          linux/arm64    ok        ",
    ]
)


class SplitRowContractTests(unittest.TestCase):
    """Every runtime script must demand both split rows and forget the 1.x row."""

    @classmethod
    def setUpClass(cls):
        cls.texts = {
            name: path.read_text(encoding="utf-8") for name, path in SCRIPTS.items()
        }

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
        for name, text in self.texts.items():
            with self.subTest(script=name):
                code = "\n".join(
                    line
                    for line in text.splitlines()
                    if not line.lstrip().startswith("#")
                )
                self.assertNotIn("grpc[.]v1", code)
                self.assertNotIn("grpc.v1", code)


@unittest.skipUnless(GREP, "an extended-regexp grep is required for pattern battery")
class SplitRowPatternBatteryTests(unittest.TestCase):
    """Exercise the shipped patterns against faithful and broken plugin tables."""

    @classmethod
    def setUpClass(cls):
        shipped = {
            tuple(sorted(SHIPPED_PATTERN.findall(path.read_text(encoding="utf-8"))))
            for path in SCRIPTS.values()
        }
        if shipped != {tuple(sorted((IMAGES_PATTERN, RUNTIME_PATTERN)))}:
            raise AssertionError(
                "runtime scripts disagree on the shipped CRI patterns: %r" % (shipped,)
            )

    def probe(self, pattern, data):
        return subprocess.run(
            [GREP, "-Eq", "--", pattern],
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
