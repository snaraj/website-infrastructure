"""Lock CI and publication to one verified multi-platform OCI artifact."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "scripts" / "ci" / "verify-oci-artifact.sh"
PULL_REQUEST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pull-request.yml"
PUBLISH_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "publish-naranjo-online-image.yml"
)
PUBLISH_CONTRACTS = {
    "naranjo.online": ("naranjo-online", "publish-naranjo-online-image.yml"),
    "lidersea.com": ("lidersea-com", "publish-lidersea-com-image.yml"),
}


class PublishWorkflowContractTests(unittest.TestCase):
    """Prevent CI and release scanning from drifting onto different artifacts."""

    @classmethod
    def setUpClass(cls):
        """Read the small contract sources once for deterministic string checks."""

        cls.verifier = VERIFIER.read_text(encoding="utf-8")
        cls.pull_request = PULL_REQUEST_WORKFLOW.read_text(encoding="utf-8")
        cls.publish = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    def test_both_workflows_use_the_shared_verifier(self):
        """PR proof must exercise the same verifier that gates publication."""

        invocation = "run: ./scripts/ci/verify-oci-artifact.sh"
        self.assertIn(invocation, self.pull_request)
        self.assertIn(invocation, self.publish)
        self.assertNotIn("trivy image", self.pull_request)
        self.assertNotIn("trivy image", self.publish)

    def test_verifier_selects_and_proves_distinct_platform_views(self):
        """A platform flag alone must not accidentally scan one child twice."""

        required_fragments = (
            'oras resolve --oci-layout "${OCI_ARCHIVE}@${EXPECTED_DIGEST}"',
            "oras cp --no-tty --from-oci-layout --to-oci-layout --platform linux/amd64",
            "oras cp --no-tty --from-oci-layout --to-oci-layout --platform linux/arm64",
            'oras manifest fetch-config --oci-layout "${amd64_layout}:scan"',
            'oras manifest fetch-config --oci-layout "${arm64_layout}:scan"',
            '[[ "${amd64_platform}" == linux/amd64 ]]',
            '[[ "${arm64_platform}" == linux/arm64 ]]',
            '[[ "${amd64_platform}" != "${arm64_platform}" ]]',
            'trivy image --input "${amd64_layout}:scan"',
            'trivy image --input "${arm64_layout}:scan"',
            ': "${ARTIFACT_NAME:?Set ARTIFACT_NAME to the canonical site slug}"',
            ': "${MAX_APPLICATION_LAYER_BYTES:?Set the reviewed final application-layer ceiling}"',
            'oras manifest fetch --oci-layout "${amd64_layout}:scan"',
            'oras manifest fetch --oci-layout "${arm64_layout}:scan"',
            '(( value <= MAX_APPLICATION_LAYER_BYTES ))',
            '[[ "${amd64_app_digest}" != "${arm64_app_digest}" ]]',
            '${ARTIFACT_NAME}-amd64.spdx.json',
            '${ARTIFACT_NAME}-arm64.spdx.json',
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.verifier)
        self.assertEqual(self.verifier.count("oras cp --no-tty"), 2)
        self.assertNotIn('trivy image --input "${OCI_ARCHIVE}"', self.verifier)

    def test_workflows_build_one_canonical_oci_archive(self):
        """Scans, publication, signatures, and evidence must share one digest."""

        for workflow in (self.pull_request, self.publish):
            with self.subTest(workflow=workflow[:40]):
                self.assertIn("platforms: linux/amd64,linux/arm64", workflow)
                self.assertEqual(workflow.count("outputs: type=oci,dest="), 1)
                self.assertIn("EXPECTED_DIGEST: ${{ steps.build.outputs.digest }}", workflow)
                self.assertIn("MAX_APPLICATION_LAYER_BYTES: 16777216", workflow)

    def test_pull_request_builds_both_sites_independently(self):
        """Every site receives its own Go/Svelte and multiarch matrix entry."""

        for fragment in (
            "site: naranjo.online",
            "site: lidersea.com",
            "artifact: naranjo-online",
            "artifact: lidersea-com",
            "ARTIFACT_NAME: ${{ matrix.artifact }}",
            "working-directory: websites/${{ matrix.site }}/frontend",
            "working-directory: websites/${{ matrix.site }}",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.pull_request)

    def test_pull_request_release_policy_watches_all_helm_releases(self):
        """Unsuspending either site or the connector must enable release policy."""

        for release in (
            "kubernetes/websites/naranjo-online/release.yaml",
            "kubernetes/websites/lidersea-com/release.yaml",
            "kubernetes/platform/cloudflare-public/release/release.yaml",
        ):
            with self.subTest(release=release):
                self.assertEqual(self.pull_request.count(release), 1)

    def test_publish_identity_is_canonical_and_exact(self):
        """Keyless verification must bind the digest to this workflow on main."""

        self.assertIn("IMAGE: ghcr.io/snaraj/naranjo-online", self.publish)
        self.assertIn(
            "https://github.com/snaraj/website-infrastructure/.github/workflows/"
            "publish-naranjo-online-image.yml@refs/heads/main",
            self.publish,
        )
        self.assertNotIn(":latest", self.publish)

    def test_each_publisher_binds_source_artifact_image_and_evidence(self):
        """A signed site identity must never build or label the other site."""

        for domain, (slug, workflow_name) in PUBLISH_CONTRACTS.items():
            workflow = (
                REPO_ROOT / ".github" / "workflows" / workflow_name
            ).read_text(encoding="utf-8")
            required = (
                "context: websites/{}".format(domain),
                "ARTIFACT_NAME: {}".format(slug),
                "IMAGE: ghcr.io/snaraj/{}".format(slug),
                "{}.oci.tar".format(slug),
                "name: {}-release-evidence".format(slug),
                "{}.digest".format(slug),
                "{}-amd64.spdx.json".format(slug),
                "{}-arm64.spdx.json".format(slug),
                "{}@refs/heads/main".format(workflow_name),
            )
            with self.subTest(domain=domain):
                for fragment in required:
                    self.assertIn(fragment, workflow)
                self.assertIn("create-storage-record: false", workflow)
                self.assertNotIn("artifact-metadata: write", workflow)
                for other_domain, (other_slug, _) in PUBLISH_CONTRACTS.items():
                    if other_domain == domain:
                        continue
                    self.assertNotIn("context: websites/{}".format(other_domain), workflow)
                    self.assertNotIn("IMAGE: ghcr.io/snaraj/{}".format(other_slug), workflow)
                    self.assertNotIn("ARTIFACT_NAME: {}".format(other_slug), workflow)


if __name__ == "__main__":
    unittest.main()
