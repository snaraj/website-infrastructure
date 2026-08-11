#!/usr/bin/env python3
"""Containerd 2.x CRI-postcheck regression battery, active.

The pinned runtime is containerd 2.x, where the 1.x ``io.containerd.grpc.v1
cri`` plugin row no longer exists: ``ctr plugins ls`` reports the CRI
surface as two rows, ``io.containerd.cri.v1 images`` and
``io.containerd.cri.v1 runtime``. The CRI postchecks in
bootstrap/pi/install-kubernetes.sh, bootstrap/pi/preflight.sh, and
bootstrap/pi/verify.sh grepped the 1.x row and could never pass on the
pinned runtime; the owner-endorsed cross-lane fix landed on this branch
(the split-row postcheck commits), so this battery — originally staged
red-by-design behind an activation guard with an always-on canary bound to
the stale pattern — is now the unconditional regression gate its staging
docstring prescribed. The canary served its purpose (it turned red the
moment the fix reached HEAD, forcing this conscious activation) and is
deleted per its own instructions.

``CriV2PostcheckRegressionTests`` asserts the shipped postcheck patterns
accept a faithful containerd 2.3 ``ctr plugins ls`` table (both split rows
``ok``) and reject the v1-era single-row table, half a CRI surface, and
unhealthy statuses. It models the scripts' probe conjunction over the
pattern set each script actually ships; the sibling battery in
test_containerd_cri_postcheck_contract.py exercises the same shipped
patterns through a real extended-regexp grep, so the two modules cover the
contract from independent directions.

The battery reads the scripts' COMMITTED content (``git show HEAD:path``)
rather than the working tree, in the spirit of test_shell_script_modes.py's
index reads: this contract binds what the branch publishes, and in-flight
edits sitting uncommitted in a shared checkout must not greenwash it.

Three-row hygiene (issue #49): the platform contract counts a THIRD healthy
row beside the split pair — the CRI gRPC frontend, whose row text is the
same ``io.containerd.grpc.v1 cri`` line that stood alone in the 1.x era —
so the healthy tables here carry all three rows and
``test_frontend_row_missing_is_currently_accepted`` pins today's two-row
tolerance. That pin is deliberately self-flipping: ``SHIPPED_PATTERN``
lifts EVERY ``io[.]containerd`` probe a script ships, so the moment the
platform lane adds the frontend probe the modeled conjunction gains it and
the tolerance assertion goes red, forcing its conversion into the enforced
frontend deny (the loud xfail ratchet pair for the same flip lives in
test_containerd_cri_health_contract_matrix.py).
"""

import re
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
POSTCHECK_SCRIPTS = (
    "bootstrap/pi/install-kubernetes.sh",
    "bootstrap/pi/preflight.sh",
    "bootstrap/pi/verify.sh",
)
# Any single-quoted grep -Eq pattern probing a containerd plugin row; this
# deliberately matches both the stale v1-era spelling and the split-row 2.x
# spelling so the battery evaluates whatever the scripts actually ship.
SHIPPED_PATTERN = re.compile(r"grep -Eq '([^']*io\[\.\]containerd[^']*)'")


def committed_text(relative):
    """Return a script's committed (HEAD) content; see module docstring."""

    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", "HEAD:" + relative],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "cannot read committed content of " + relative + ": " + result.stderr
        )
    return result.stdout


def shipped_cri_patterns(script_text):
    return SHIPPED_PATTERN.findall(script_text)


def as_python_regex(posix_pattern):
    """Translate the scripts' POSIX ERE fragment to a Python regex.

    Only ``[[:space:]]`` needs translation; anything else bracket-class
    exotic fails loudly so a future pattern change cannot be silently
    mistranslated into a vacuous assertion.
    """

    translated = posix_pattern.replace("[[:space:]]", "[ \\t]")
    if "[[:" in translated:
        raise AssertionError(
            "untranslated POSIX class in shipped pattern: " + posix_pattern
        )
    return translated


def postcheck_accepts(patterns, probe_output):
    """Model the scripts' probe pipeline: every grep assertion must match.

    Each script asserts its CRI patterns independently against ``ctr
    plugins ls`` output and fails closed if any one of them finds no line,
    so acceptance is the conjunction over the shipped pattern set.
    """

    if not patterns:
        return False
    return all(
        re.search(as_python_regex(pattern), probe_output, re.MULTILINE)
        for pattern in patterns
    )


def table(rows):
    return "".join(row + "\n" for row in rows)


# ctr renders this table through Go's text/tabwriter with a trailing tab per
# row, so the STATUS column of real output carries trailing padding; the
# padded tables below are the faithful shape and the unpadded ones guard
# against a pattern that would only match the padding.
HEADER = "TYPE                            ID           PLATFORMS      STATUS    "
V2_IMAGES_ROW = "io.containerd.cri.v1            images       linux/arm64    ok        "
V2_RUNTIME_ROW = "io.containerd.cri.v1            runtime      linux/arm64    ok        "
# One row text, two readings (module docstring): on 1.x this was the ONLY
# CRI row — the stale surface the fix retired — and on 2.x the same text is
# the CRI gRPC frontend row accompanying the split pair. Context (which
# rows appear beside it) separates the dead table from the healthy one, so
# both fixture families share the constant instead of re-typing the row.
V1_ROW = "io.containerd.grpc.v1           cri          linux/arm64    ok        "
CRI_FRONTEND_ROW = V1_ROW
NEUTRAL_ROWS = (
    "io.containerd.internal.v1       opt          -              ok        ",
    "io.containerd.snapshotter.v1    overlayfs    linux/arm64    ok        ",
    # A grpc.v1 row with a non-cri ID: v2 keeps grpc.v1 services, so a
    # pattern satisfied by any grpc.v1 row would be satisfied here too.
    "io.containerd.grpc.v1           containers   -              ok        ",
)
# Healthy = the full three-row surface. The partial tables keep the
# frontend row too — that is the faithful 2.x partial-failure shape, and it
# proves a healthy frontend row can never stand in for a missing or
# unhealthy split service row.
V2_TABLE_PADDED = table(
    (HEADER,) + NEUTRAL_ROWS + (V2_IMAGES_ROW, V2_RUNTIME_ROW, CRI_FRONTEND_ROW)
)
V2_TABLE_UNPADDED = table(
    tuple(
        row.rstrip()
        for row in (HEADER,)
        + NEUTRAL_ROWS
        + (V2_IMAGES_ROW, V2_RUNTIME_ROW, CRI_FRONTEND_ROW)
    )
)
V2_TABLE_MISSING_RUNTIME = table(
    (HEADER,) + NEUTRAL_ROWS + (V2_IMAGES_ROW, CRI_FRONTEND_ROW)
)
V2_TABLE_MISSING_IMAGES = table(
    (HEADER,) + NEUTRAL_ROWS + (V2_RUNTIME_ROW, CRI_FRONTEND_ROW)
)
V2_TABLE_RUNTIME_ERROR = table(
    (HEADER,)
    + NEUTRAL_ROWS
    + (
        V2_IMAGES_ROW,
        "io.containerd.cri.v1            runtime      linux/arm64    error     ",
        CRI_FRONTEND_ROW,
    )
)
# The pre-#49 healthy shape: split pair present, frontend row absent.
# Accepted by the shipped two-probe conjunction today; see the module
# docstring for the self-flipping tolerance pin bound to this table.
V2_TABLE_FRONTEND_MISSING = table(
    (HEADER,) + NEUTRAL_ROWS + (V2_IMAGES_ROW, V2_RUNTIME_ROW)
)
V1_TABLE_PADDED = table((HEADER,) + NEUTRAL_ROWS[:2] + (V1_ROW,))
V1_TABLE_UNPADDED = table(
    tuple(row.rstrip() for row in (HEADER,) + NEUTRAL_ROWS[:2] + (V1_ROW,))
)


class CriV2PostcheckRegressionTests(unittest.TestCase):
    """The shipped postchecks must pass on containerd 2.x and only there."""

    @classmethod
    def setUpClass(cls):
        cls.patterns = {
            relative: shipped_cri_patterns(committed_text(relative))
            for relative in POSTCHECK_SCRIPTS
        }

    def per_script(self):
        for relative in POSTCHECK_SCRIPTS:
            with self.subTest(script=relative):
                yield relative, self.patterns[relative]

    def test_every_script_ships_cri_postcheck_patterns(self):
        for relative, patterns in self.per_script():
            self.assertTrue(
                patterns, relative + " must probe the containerd CRI plugins"
            )

    def test_accepts_the_healthy_v2_split_row_table(self):
        for relative, patterns in self.per_script():
            self.assertTrue(postcheck_accepts(patterns, V2_TABLE_PADDED), relative)
            self.assertTrue(postcheck_accepts(patterns, V2_TABLE_UNPADDED), relative)

    def test_rejects_the_v1_era_single_row_table(self):
        for relative, patterns in self.per_script():
            self.assertFalse(postcheck_accepts(patterns, V1_TABLE_PADDED), relative)
            self.assertFalse(postcheck_accepts(patterns, V1_TABLE_UNPADDED), relative)

    def test_rejects_half_a_cri_surface(self):
        for relative, patterns in self.per_script():
            self.assertFalse(
                postcheck_accepts(patterns, V2_TABLE_MISSING_RUNTIME), relative
            )
            self.assertFalse(
                postcheck_accepts(patterns, V2_TABLE_MISSING_IMAGES), relative
            )

    def test_rejects_unhealthy_status_and_empty_probe_output(self):
        for relative, patterns in self.per_script():
            self.assertFalse(
                postcheck_accepts(patterns, V2_TABLE_RUNTIME_ERROR), relative
            )
            self.assertFalse(postcheck_accepts(patterns, ""), relative)

    def test_frontend_row_missing_is_currently_accepted(self):
        # Pending three-row contract, pinned two ways on purpose (module
        # docstring): today the committed scripts probe only the split
        # pair, so the frontend-less table passes. Because SHIPPED_PATTERN
        # lifts every io[.]containerd probe the scripts ship, a committed
        # frontend probe joins the conjunction automatically and turns
        # this assertion red — the conversion point into the enforced
        # frontend deny row.
        for relative, patterns in self.per_script():
            self.assertTrue(
                postcheck_accepts(patterns, V2_TABLE_FRONTEND_MISSING), relative
            )


if __name__ == "__main__":
    unittest.main()
