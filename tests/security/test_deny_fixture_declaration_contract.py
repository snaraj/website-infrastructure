"""The deny-fixture inventory pin: nothing asserts by bare rejection.

``scripts/test-policy-fixtures.sh`` refuses a deny fixture that declares
neither a reviewed ``.expected`` sidecar nor per-document ``# expect-deny:``
reasons, and the runner driver in ``test_flux_install_contract.py``
(``FluxEgressDenyFixtureTests``) proves that refusal fires by driving the real
runner with a stubbed engine.

This battery pins the same property from the other side: over the COMMITTED
inventory, with no engine and no shell in the loop, so it runs under
``make check-fast`` on a host that has no conftest installed. Both halves are
needed. The runner proves the rule is ENFORCED; this proves the tree SATISFIES
it and names the offending file the moment it stops doing so.

That distinction is the finding this battery closes (issue #138, F1): "zero
deny fixtures fall back to file-level rejection" was true of the inventory and
asserted by nothing, so the first fixture to arrive without a declaration would
have been one PASS line among a hundred rather than a failure.

The two reviewed forms are restated here in Python rather than read out of the
shell on purpose: a restatement that drifts from the runner is a failure in one
of the two readings, which is what a second reading is for.
"""

from __future__ import annotations

import re
import unittest

from .support import REPO_ROOT

DENY_FIXTURES = REPO_ROOT / "tests" / "kubernetes" / "fixtures" / "deny"

# `# expect-deny: <reason>` at column 0, the per-document form.
INLINE_DECLARATION = re.compile(r"(?m)^#[ \t]*expect-deny:[ \t]*(\S.*?)[ \t]*$")
# A sidecar line that names a denial: anything that is neither blank nor a
# comment, which is exactly the set the runner compares against conftest.
SIDECAR_MESSAGE = re.compile(r"(?m)^(?![ \t]*(?:#|$)).+$")

# One fixture that must be found by the scan below. A path that stops matching
# anything would make every assertion here vacuously true, and this battery
# exists precisely because a silent zero is what went unnoticed.
KNOWN_FIXTURE = "flux-egress-02-generated-blanket-allow-restored.yaml"


def _fixtures():
    return sorted(DENY_FIXTURES.glob("*.yaml"))


def _read(path):
    return path.read_text(encoding="utf-8")


class DenyFixtureDeclarationTests(unittest.TestCase):
    """Every committed deny fixture states what it must be rejected FOR."""

    def test_the_scan_actually_reaches_the_committed_fixtures(self):
        """A battery that scans nothing passes everything."""

        fixtures = _fixtures()
        self.assertGreater(
            len(fixtures),
            0,
            "no deny fixtures were found under {}; every assertion in this "
            "battery would pass vacuously".format(DENY_FIXTURES),
        )
        self.assertIn(
            KNOWN_FIXTURE,
            {fixture.name for fixture in fixtures},
            "the named reference fixture is missing, so the scan is no longer "
            "looking at the reviewed deny inventory",
        )

    def test_every_deny_fixture_declares_a_reviewed_mechanism(self):
        """Sidecar or per-document reasons; bare rejection is not a mechanism.

        Reported as one list rather than one failing subtest so a batch import
        of undeclared fixtures names all of them at once.
        """

        undeclared = [
            fixture.name
            for fixture in _fixtures()
            if not fixture.with_suffix(".expected").is_file()
            and not INLINE_DECLARATION.search(_read(fixture))
        ]
        self.assertEqual(
            undeclared,
            [],
            "these deny fixtures assert only that conftest exited non-zero, "
            "which cannot tell a working deny arm from a neutered one: add a "
            "reviewed .expected sidecar or one `# expect-deny:` line per YAML "
            "document",
        )

    def test_every_reviewed_sidecar_names_at_least_one_denial(self):
        """An empty sidecar is bare rejection wearing the strong form.

        The runner compares the sidecar's message set against conftest's
        output. A sidecar holding only comments declares the EMPTY set, which
        matches any rejection that emits no ``FAIL`` line at all — a fixture
        that fails to parse, say — so the file would be certified for a denial
        that never happened.
        """

        empty = [
            sidecar.name
            for sidecar in sorted(DENY_FIXTURES.glob("*.expected"))
            if not SIDECAR_MESSAGE.search(_read(sidecar))
        ]
        self.assertEqual(
            empty,
            [],
            "these reviewed denial lists name no message, so they assert "
            "nothing about why the fixture was rejected",
        )

    def test_every_sidecar_belongs_to_a_fixture(self):
        """A sidecar whose fixture is gone reviews nothing.

        Deleting the ``.yaml`` and leaving the ``.expected`` behind removes the
        assertion from the suite while the reviewed message list stays in the
        tree looking like coverage.
        """

        orphans = [
            sidecar.name
            for sidecar in sorted(DENY_FIXTURES.glob("*.expected"))
            if not sidecar.with_suffix(".yaml").is_file()
        ]
        self.assertEqual(orphans, [], "these reviewed denial lists have no fixture")


if __name__ == "__main__":
    unittest.main()
