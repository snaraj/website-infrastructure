"""Protect the disabled, bounded, and repository-external media boundary."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_SPEC = importlib.util.spec_from_file_location(
    "media_validate_repository", REPO_ROOT / "scripts" / "validate_repository.py"
)
REPOSITORY_MODULE = importlib.util.module_from_spec(REPOSITORY_SPEC)
REPOSITORY_SPEC.loader.exec_module(REPOSITORY_MODULE)


class MediaContractTests(unittest.TestCase):
    """Catch accidental storage activation or unbounded serving drift."""

    def test_platform_release_values_never_reenable_site_media(self):
        """The media fail-closed chart contract moved to each site repository;
        the platform's HelmRelease values must not re-enable it from here."""

        releases = sorted(
            (REPO_ROOT / "kubernetes" / "websites").glob("*/release.yaml")
        )
        self.assertEqual(len(releases), 2)
        for release in releases:
            with self.subTest(release=release.name):
                text = release.read_text(encoding="utf-8")
                self.assertNotIn("media:", text)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "kubernetes" / "websites" / "naranjo-online"
            target.mkdir(parents=True)
            target.joinpath("release.yaml").write_text(
                "spec:\n"
                "  values:\n"
                "    media:\n"
                "      enabled: true\n",
                encoding="utf-8",
            )
            self.assertTrue(any(
                "platform values re-enable site media" in error
                for error in REPOSITORY_MODULE.check_media(root)
            ))

    def test_architecture_states_current_cloudflare_no_go(self):
        adr = (REPO_ROOT / "docs/adr/0012-heavy-media-storage.md").read_text(
            encoding="utf-8"
        )
        zero_spend = (REPO_ROOT / "docs/adr/0006-cloudflare-zero-spend.md").read_text(
            encoding="utf-8"
        )
        for document in (adr, zero_spend):
            self.assertIn("NO-GO", document)
            self.assertIn("service-specific-terms-application-services", document)

    def test_source_and_oci_artifacts_have_independent_media_bounds(self):
        sourceignore = (REPO_ROOT / ".sourceignore").read_text(encoding="utf-8")
        verifier = (REPO_ROOT / "scripts/ci/verify-oci-artifact.sh").read_text(
            encoding="utf-8"
        )
        for fragment in (
            "/*",
            "!/kubernetes/",
            "!/policies/kyverno/",
        ):
            self.assertIn(fragment, sourceignore)
        # Site charts arrive through their own GitRepository sources now; the
        # platform artifact must not re-include any embedded website tree.
        self.assertNotIn("websites/", sourceignore)
        self.assertIn("MAX_APPLICATION_LAYER_BYTES", verifier)
        self.assertIn("application layer exceeds the reviewed byte ceiling", verifier)


if __name__ == "__main__":
    unittest.main()
