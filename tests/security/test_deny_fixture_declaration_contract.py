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
# The same line with NOTHING after the colon. It used to be counted by the
# runner's tally and skipped by its proof loop, so a two-document fixture with
# one real reason and one of these reported both proven while asserting one
# (issue #176). It is refused outright now, in both readings.
EMPTY_DECLARATION = re.compile(r"(?m)^#[ \t]*expect-deny:[ \t]*$")
# `---` at column 0, the document separator kustomize and every fixture use.
DOCUMENT_SEPARATOR = re.compile(r"(?m)^---[ \t]*$")
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


def _fixture_for_sidecar(sidecar):
    """Map the general or release-specific reviewed reasons to their YAML."""

    suffix = ".release.expected"
    if sidecar.name.endswith(suffix):
        return sidecar.with_name(sidecar.name[: -len(suffix)] + ".yaml")
    return sidecar.with_suffix(".yaml")


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

    def test_no_fixture_carries_an_empty_declaration(self):
        """An empty `# expect-deny:` is a declaration that proves nothing.

        Checked over EVERY deny fixture, including the ones a reviewed
        sidecar already covers. Inert in a sidecar fixture today — but "inert
        here" is precisely how this shape survived long enough to be counted
        somewhere it was not proven.
        """

        offenders = [
            fixture.name
            for fixture in _fixtures()
            if EMPTY_DECLARATION.search(_read(fixture))
        ]
        self.assertEqual(
            offenders,
            [],
            "these fixtures declare an expect-deny with no reason; name the "
            "exact denial message the document must produce",
        )

    def test_every_document_of_a_declared_fixture_names_its_own_reason(self):
        """Per DOCUMENT, not per file — the half issue #176 measured.

        The old requirement was one non-empty declaration per FILE, which a
        multi-document fixture satisfied with a single real reason in one
        document while another document went unasserted. A document that
        nothing asserts is a bypass the fixture appears to cover.

        Scoped to fixtures with no `.expected` sidecar: a sidecar names the
        complete denial set for the whole file, which is the stronger form.
        """

        undeclared = {}
        for fixture in _fixtures():
            if fixture.with_suffix(".expected").is_file():
                continue
            text = _read(fixture)
            documents = len(DOCUMENT_SEPARATOR.findall(text)) + 1
            reasons = len(INLINE_DECLARATION.findall(text))
            if reasons != documents:
                undeclared[fixture.name] = (reasons, documents)
        self.assertEqual(
            undeclared,
            {},
            "each entry is (reasons, documents): a fixture must declare "
            "exactly one non-empty reason per YAML document, or one reason "
            "silently speaks for a document nobody asserted",
        )

    def test_the_per_document_scan_reaches_a_declared_fixture(self):
        """Vacuity probe: the loop above skips every sidecar-covered file."""

        scanned = [
            fixture.name
            for fixture in _fixtures()
            if not fixture.with_suffix(".expected").is_file()
        ]
        self.assertIn(KNOWN_FIXTURE, scanned, scanned)

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
            if not _fixture_for_sidecar(sidecar).is_file()
        ]
        self.assertEqual(orphans, [], "these reviewed denial lists have no fixture")


if __name__ == "__main__":
    unittest.main()
