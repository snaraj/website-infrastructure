"""Keep privacy-sensitive legacy state inert and outside the web platform."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AGENTS = ROOT / "AGENTS.md"
ADR = ROOT / "docs" / "adr" / "0013-protected-legacy-archive.md"
RUNBOOK = ROOT / "docs" / "runbooks" / "protected-legacy-archive.md"
OVERVIEW = ROOT / "docs" / "architecture" / "overview.md"
TRUST = ROOT / "docs" / "architecture" / "trust-boundaries.md"
CAPACITY = ROOT / "docs" / "architecture" / "capacity.md"


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
        """The archive stays outside Kubernetes, Flux, CI, and both connectors."""

        self.assertIn('Kubernetes -. "denied" .-> LegacyArchive', self.overview)
        self.assertIn('PublicTunnel -. "denied" .-> LegacyArchive', self.overview)
        for fragment in (
            "denied to Flux, Pods, both Tunnel connectors, CI, and provider tooling",
            "cluster rebuild or ordinary rollback may not activate it",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.trust)


if __name__ == "__main__":
    unittest.main()
