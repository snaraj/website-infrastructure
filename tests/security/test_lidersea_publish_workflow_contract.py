"""Lock lidersea.com publication to its own verified OCI release identity."""

import unittest
from pathlib import Path


# Resolve from the test location so checks remain independent of a contributor's
# workstation path or current working directory.
REPO_ROOT = Path(__file__).resolve().parents[2]
# Naming the one permitted workflow directly prevents a broad glob from passing
# because a different site's workflow happens to contain the expected controls.
PUBLISH_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "publish-lidersea-com-image.yml"
)


class LiderseaPublishWorkflowContractTests(unittest.TestCase):
    """Prevent the second site from borrowing naranjo.online release identity."""

    @classmethod
    def setUpClass(cls):
        """Read the dedicated workflow once for deterministic contract checks."""

        cls.publish = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_builds_and_verifies_one_multiarch_graph(self):
        """Build, scan, publish, signing, and attestation must share one digest."""

        self.assertIn("context: websites/lidersea.com", self.publish)
        self.assertIn("platforms: linux/amd64,linux/arm64", self.publish)
        self.assertEqual(self.publish.count("outputs: type=oci,dest="), 1)
        self.assertIn(
            "EXPECTED_DIGEST: ${{ steps.build.outputs.digest }}", self.publish
        )
        self.assertIn("run: ./scripts/ci/verify-oci-artifact.sh", self.publish)
        self.assertIn("ARTIFACT_NAME: lidersea-com", self.publish)
        self.assertIn("MAX_APPLICATION_LAYER_BYTES: 16777216", self.publish)
        self.assertNotIn("trivy image", self.publish)

    def test_publish_identity_is_canonical_and_exact(self):
        """Keyless verification must bind lidersea.com's digest to its workflow."""

        self.assertIn("IMAGE: ghcr.io/snaraj/lidersea-com", self.publish)
        self.assertIn(
            "https://github.com/snaraj/website-infrastructure/.github/workflows/"
            "publish-lidersea-com-image.yml@refs/heads/main",
            self.publish,
        )
        self.assertNotIn("ghcr.io/snaraj/naranjo-online", self.publish)
        self.assertNotIn("publish-naranjo-online-image.yml", self.publish)
        self.assertNotIn(":latest", self.publish)

    def test_release_evidence_is_site_specific(self):
        """Uploaded files must stay attributable to the independent site graph."""

        for fragment in (
            "lidersea-com-release-evidence",
            "lidersea-com.digest",
            "lidersea-com-amd64.spdx.json",
            "lidersea-com-arm64.spdx.json",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.publish)

    def test_workflow_is_secretless_until_main_publish(self):
        """The job may receive only GitHub's scoped token after the main guard."""

        self.assertIn("permissions: {}", self.publish)
        self.assertIn("persist-credentials: false", self.publish)
        self.assertIn("github.ref == 'refs/heads/main'", self.publish)
        self.assertNotIn("CLOUDFLARE", self.publish)
        self.assertNotIn("KUBECONFIG", self.publish)


if __name__ == "__main__":
    unittest.main()
