"""Keep privacy-sensitive legacy state inert and outside the web platform.

The same architecture prose that carries the archive-denial edges also
carries the public-edge description, so the edge-accuracy pins live here
too: a document that overstates the edge (claiming a deployment that does
not exist, or a TLS mode this platform does not use) is the same class of
defect as one that quietly drops a denial edge.
"""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AGENTS = ROOT / "AGENTS.md"
ADR = ROOT / "docs" / "adr" / "0013-protected-legacy-archive.md"
RUNBOOK = ROOT / "docs" / "runbooks" / "protected-legacy-archive.md"
OVERVIEW = ROOT / "docs" / "architecture" / "overview.md"
TRUST = ROOT / "docs" / "architecture" / "trust-boundaries.md"
CAPACITY = ROOT / "docs" / "architecture" / "capacity.md"
DOCS = ROOT / "docs"

# Cloudflare's "Full (strict)" SSL mode means the edge validates a certificate
# presented by the origin. ADR 0015 records the opposite shape: the
# connector-to-origin leg is plain HTTP inside the default-deny NetworkPolicy
# boundary, and the zone target is SSL mode full. A document that names the
# strict mode as an owned control is describing protection this platform does
# not have, so the token is banned from docs/** outright.
FULL_STRICT_RE = re.compile(r"full[\s_-]*\(?strict\)?", re.IGNORECASE)

# Exactly one justified occurrence: the phase-D design note names the mode in
# order to DENY it. The entry pins the complete line, so a reword that turns
# the disclaimer back into a claim — or a deletion that removes the denial —
# fails this test as loudly as a missing guard (delivery-lane requirement 5:
# a stale justification fails exactly like a missing check).
FULL_STRICT_ALLOWLIST = {
    (
        "docs/assurance/phase-d-cloudflare-design.md",
        'boundary (ADR 0015), so "Full (strict)" is not claimed. DNSSEC posture',
    ),
}


def full_strict_occurrences():
    """Yield ``(relative path, stripped line)`` for every docs/** match."""

    for document in sorted(DOCS.rglob("*.md")):
        relative = document.relative_to(ROOT).as_posix()
        for line in document.read_text(encoding="utf-8").splitlines():
            if FULL_STRICT_RE.search(line):
                yield relative, line.strip()


class LegacyArchivePolicyTests(unittest.TestCase):
    """Prove that archive policy cannot be mistaken for runtime authority."""

    @classmethod
    def setUpClass(cls):
        cls.agents = AGENTS.read_text(encoding="utf-8")
        cls.adr = ADR.read_text(encoding="utf-8")
        cls.runbook = RUNBOOK.read_text(encoding="utf-8")
        cls.overview = OVERVIEW.read_text(encoding="utf-8")
        cls.trust = TRUST.read_text(encoding="utf-8")
        cls.capacity = CAPACITY.read_text(encoding="utf-8")

    def test_repository_invariant_forbids_runtime_authority(self):
        """Future changes must not turn the archive into a deployment source."""

        for fragment in (
            "Treat every declared protected legacy archive as inert",
            "automatic start/restore",
            "container/Kubernetes mount",
            "Reactivation requires a new ADR",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.agents)

    def test_decision_is_classification_not_inventory(self):
        """Public product policy must not claim private host facts."""

        normalized = " ".join(self.adr.split())
        for fragment in (
            "classification is not an inventory",
            "ignored mode-`0600` local contract",
            "no Kubernetes object",
            "must not be copied into a convenience directory",
            "Merely making an inert archive “current” is not a reason",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, normalized)

    def test_runbook_starts_local_only_and_separates_network_mutation(self):
        """Inventory cannot leak before VPN behavior and exact rule ownership are proven."""

        normalized = " ".join(self.runbook.split())
        for fragment in (
            "scripts/discover-pi.sh --local-only",
            "external egress probes were skipped",
            "No external DNS/HTTP/TCP probe",
            "network cleanup as a separate transaction",
            "Remove only an exact rule whose ownership is unique",
            "Cloudflare Tunnel does not replace the VPN",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, normalized)

    def test_runbook_preserves_data_and_forbids_shortcuts(self):
        """Retirement remains reversible and never scans or force-cleans the archive."""

        combined = " ".join((self.runbook + "\n" + self.capacity).split())
        for fragment in (
            "Do not use `kill -9`",
            "Do not use `disable --now`",
            "Do not move it into the catalog",
            "must not recursively scan or hash",
            "rollback preserves the last proven inactive and persistently-disabled/masked state",
            "never re-enables or starts the workload",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, combined)

    def test_private_contract_binds_presence_activation_and_storage(self):
        """An empty review or mountpoint left behind cannot pass as an archive."""

        normalized = " ".join((self.adr + "\n" + self.runbook).split())
        for fragment in (
            "PROTECTED_LEGACY_ARCHIVES_PRESENT",
            "PROTECTED_LEGACY_ACTIVATION_CLASS_REVIEWED",
            "PROTECTED_LEGACY_ARCHIVE_BINDING_SHA256",
            "missing archive disk",
            "system-manager query cannot prove anything about a user manager",
            "--emit-bindings",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, normalized)

    def test_rollback_never_restores_legacy_enablement(self):
        """Re-enablement is restoration authority, never transaction rollback."""

        normalized = " ".join((self.adr + "\n" + self.runbook).split())
        self.assertIn("Rollback never re-enables", normalized)
        self.assertNotIn(
            "Rollback restores only exact archived unit/configuration/enablement",
            normalized,
        )

    def test_architecture_denies_archive_to_platform_consumers(self):
        """The archive stays outside Kubernetes, Flux, CI, and every connector."""

        self.assertIn('Kubernetes -. "denied" .-> LegacyArchive', self.overview)
        # ADR 0015 split the public edge into two per-site Tunnels; each one
        # must carry its own explicit archive denial so neither inherits an
        # implicit allowance from the retired shared connector.
        self.assertIn('NaranjoTunnel -. "denied" .-> LegacyArchive', self.overview)
        self.assertIn('LiderseaTunnel -. "denied" .-> LegacyArchive', self.overview)
        for fragment in (
            "denied to Flux, Pods, every Tunnel connector, CI, and provider tooling",
            "cluster rebuild or ordinary rollback may not activate it",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.trust)


class EdgeProseAccuracyTests(unittest.TestCase):
    """Prose about the public edge may not claim more than the record supports."""

    @classmethod
    def setUpClass(cls):
        cls.overview = OVERVIEW.read_text(encoding="utf-8")

    def test_overview_describes_a_decision_not_a_deployment(self):
        """The overview's own header forbids deployment claims about the Pi."""

        normalized = " ".join(self.overview.split())
        self.assertIn(
            "not a claim about the current Pi",
            normalized,
            "the overview's target-state header is the premise of this pin",
        )
        self.assertNotIn(
            "as-built",
            self.overview.lower(),
            'docs/architecture/overview.md may not use "as-built": the document '
            "describes the reviewed target state, and nothing here is deployed",
        )
        self.assertIn("The decided public path is", self.overview)

    def test_no_document_claims_full_strict_origin_validation(self):
        """Only the justified denial may name the TLS mode this platform lacks."""

        unjustified = [
            "{}: {}".format(path, line)
            for path, line in full_strict_occurrences()
            if (path, line) not in FULL_STRICT_ALLOWLIST
        ]
        self.assertEqual(
            unjustified,
            [],
            "docs/** may not claim Cloudflare Full (strict) origin validation; "
            "ADR 0015 records a plain-HTTP connector-to-origin leg:\n"
            + "\n".join(unjustified),
        )

    def test_full_strict_allowlist_has_no_stale_entry(self):
        """A justification that no longer describes real prose is itself a defect."""

        observed = set(full_strict_occurrences())
        stale = sorted(FULL_STRICT_ALLOWLIST - observed)
        self.assertEqual(
            stale,
            [],
            "allowlisted lines that no longer exist verbatim:\n"
            + "\n".join("{}: {}".format(path, line) for path, line in stale),
        )

    def test_full_strict_scan_actually_reads_documents(self):
        """A scan that sees no documents would pass vacuously."""

        scanned = sorted(DOCS.rglob("*.md"))
        self.assertGreater(
            len(scanned),
            10,
            "the docs/** prose scan found suspiciously few documents; "
            "the doc root may have rotted",
        )
        self.assertTrue(FULL_STRICT_RE.search('so "Full (strict)" is not claimed'))
        self.assertTrue(FULL_STRICT_RE.search("mode full_strict"))


if __name__ == "__main__":
    unittest.main()
