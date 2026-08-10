"""Lock CI and publication to one verified multi-platform OCI artifact."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "scripts" / "ci" / "verify-oci-artifact.sh"
PUBLISHER = REPO_ROOT / "scripts" / "ci" / "publish-oci-artifact.sh"
STABLE_TAG_PUBLISHER = (
    REPO_ROOT / "scripts" / "ci" / "publish-stable-oci-tag.sh"
)
READ_ONLY_RELEASE_VERIFIER = (
    REPO_ROOT / "scripts" / "ci" / "verify-existing-oci-release.sh"
)
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
        cls.publisher = PUBLISHER.read_text(encoding="utf-8")
        cls.stable_tag_publisher = STABLE_TAG_PUBLISHER.read_text(encoding="utf-8")
        cls.read_only_release_verifier = READ_ONLY_RELEASE_VERIFIER.read_text(
            encoding="utf-8"
        )
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
            'syft "oci-dir:${amd64_layout}"',
            'syft "oci-dir:${arm64_layout}"',
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
        self.assertNotIn('syft "oci-archive:${OCI_ARCHIVE}"', self.verifier)
        self.assertNotIn("syft \"oci-dir:${amd64_layout}\" --platform", self.verifier)
        self.assertNotIn("syft \"oci-dir:${arm64_layout}\" --platform", self.verifier)

    def test_workflows_build_one_canonical_oci_archive(self):
        """Scans, publication, signatures, and evidence must share one digest."""

        for workflow in (self.pull_request, self.publish):
            with self.subTest(workflow=workflow[:40]):
                self.assertIn("platforms: linux/amd64,linux/arm64", workflow)
                self.assertEqual(workflow.count("outputs: type=oci,dest="), 1)
                self.assertIn("EXPECTED_DIGEST: ${{ steps.build.outputs.digest }}", workflow)
                self.assertIn("MAX_APPLICATION_LAYER_BYTES: 16777216", workflow)

    def test_publisher_retries_only_the_exact_verified_graph(self):
        """Transient GHCR visibility failures must not rebuild or retag drift."""

        required_fragments = (
            ': "${OCI_ARCHIVE:?Set OCI_ARCHIVE to the verified multi-platform OCI layout archive}"',
            ': "${EXPECTED_DIGEST:?Set EXPECTED_DIGEST to the verified sha256 index digest}"',
            ': "${PUBLISH_VERIFY_ROOT:?Set PUBLISH_VERIFY_ROOT to a new temporary verification directory}"',
            "for command_name in cmp jq oras",
            'source_digest="$(oras resolve --oci-layout "${source_reference}")"',
            'readonly image_index_media_type="application/vnd.oci.image.index.v1+json"',
            "oras manifest fetch --oci-layout",
            "jq -er '.mediaType'",
            "oras cp --no-tty --concurrency 1 --from-oci-layout",
            "oras cp --no-tty --concurrency 1 --to-oci-layout",
            'destination_reference="${IMAGE}:sha-${GITHUB_SHA}"',
            '[[ "${GITHUB_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            'if oras resolve "${destination_reference}"',
            "Error response from registry: failed to resolve digest: %s: not found",
            '[[ "${destination_resolve_status}" -ne 1 ||',
            '-s "${destination_resolve_output}"',
            'cmp -s -- "${destination_resolve_error}"',
            "could not prove destination absence",
            "readonly max_attempts=4",
            'readonly base_delay_seconds="${PUBLISH_RETRY_DELAY_SECONDS:-5}"',
            '[[ "${resolved}" == "${EXPECTED_DIGEST}" ]]',
            '[[ "${roundtrip_digest}" == "${EXPECTED_DIGEST}" ]]',
            '[[ "${roundtrip_media_type}" == "${image_index_media_type}" ]]',
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.publisher)
        self.assertEqual(self.publisher.count("oras cp "), 2)
        self.assertLess(
            self.publisher.index('oras resolve "${destination_reference}"'),
            self.publisher.index("oras cp --no-tty --concurrency 1 --from-oci-layout"),
        )
        self.assertNotIn("docker build", self.publisher)
        self.assertNotIn("GHCR_TOKEN", self.publisher)
        self.assertNotIn("[0-9a-f]{64})", self.publisher)
        self.assertNotIn("grep ", self.publisher)
        self.assertNotIn("MANIFEST_UNKNOWN", self.publisher)

    def test_stable_tag_publisher_resolves_directly_and_fails_closed(self):
        """Only pinned ORAS's exact reference-bound absence can authorize tagging."""

        publisher = self.stable_tag_publisher
        for fragment in (
            ': "${STABLE_TAG_VERIFY_ROOT:?Set STABLE_TAG_VERIFY_ROOT to a new temporary directory}"',
            "for command_name in cmp oras",
            'stable_reference="${IMAGE}:${RELEASE_TAG}"',
            'oras resolve "${stable_reference}"',
            "Error response from registry: failed to resolve digest: %s: not found",
            '[[ "${resolve_status}" -eq 1 && ! -s "${resolve_output}" ]]',
            'cmp -s -- "${resolve_error}" "${expected_absence}"',
            'oras tag "${IMAGE}@${EXPECTED_DIGEST}" "${RELEASE_TAG}"',
            "could not prove stable tag absence",
            '[[ "${GITHUB_SHA}" =~ ^[0-9a-f]{40}$ ]]',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, publisher)
        self.assertNotIn("|not found", publisher)
        self.assertNotIn("oras repo tags", publisher)
        self.assertNotIn("grep ", publisher)
        self.assertNotIn("MANIFEST_UNKNOWN", publisher)

    def test_manual_release_verifier_is_read_only_and_direct(self):
        verifier = self.read_only_release_verifier
        for fragment in (
            'oras resolve "${reference}"',
            'resolve_required "${IMAGE}:sha-${GITHUB_SHA}"',
            'resolve_required "${IMAGE}:${RELEASE_TAG}"',
            '[[ "${sha_digest}" == "${version_digest}" ]]',
            "cosign verify",
            "--certificate-identity",
            "https://token.actions.githubusercontent.com",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, verifier)
        for forbidden in (
            "oras cp",
            "oras tag",
            "cosign sign",
            "actions/attest",
            "docker build",
            "git push",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, verifier)

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

    def test_pull_request_scans_the_server_bound_immutable_commit_range(self):
        """Fork PRs use the merge ref only to authenticate exact base/head OIDs."""

        required_fragments = (
            "permissions: {}",
            "contents: read",
            "persist-credentials: false",
            "fetch-depth: 0",
            "if: github.event_name == 'pull_request'",
            "PR_BASE_REPOSITORY: ${{ github.event.pull_request.base.repo.full_name }}",
            "PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}",
            "PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
            '[[ "${GITHUB_REF}" == "refs/pull/${PR_NUMBER}/merge" ]]',
            '[[ "${GITHUB_SHA}" =~ ${oid_pattern} ]]',
            '[[ "${checked_out_sha}" == "${GITHUB_SHA}" ]]',
            'git rev-list --parents -n 1 "${checked_out_sha}"',
            '[[ "${merge_record[0]}" == "${checked_out_sha}" ]]',
            '[[ "${merge_record[1]}" == "${PR_BASE_SHA}" ]]',
            '[[ "${merge_record[2]}" == "${PR_HEAD_SHA}" ]]',
            "validate_publication_history.py \\",
            '--pull-request "${PR_BASE_SHA}" "${PR_HEAD_SHA}"',
            "gitleaks git \\",
            "--ignore-gitleaks-allow",
            "--gitleaks-ignore-path=",
            '--log-opts="${PR_BASE_SHA}..${PR_HEAD_SHA}"',
            '[[ ! -e "${empty_ignore}" ]]',
            "trap - EXIT HUP INT TERM",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.pull_request)
        self.assertNotIn("pull_request_target:", self.pull_request)
        self.assertNotIn("contents: write", self.pull_request)
        self.assertNotIn("PR_MERGE_SHA", self.pull_request)
        self.assertNotIn("github.event.pull_request.merge_commit_sha", self.pull_request)
        self.assertNotIn(
            "github.event.pull_request.head.repo.full_name", self.pull_request
        )
        self.assertLess(
            self.pull_request.index("fetch-depth: 0"),
            self.pull_request.index("validate_publication_history.py"),
        )
        self.assertLess(
            self.pull_request.index("validate_publication_history.py"),
            self.pull_request.index("gitleaks git"),
        )

    def test_pull_request_uses_one_strict_release_transition_selector(self):
        """CI must pass the classifier's exact safe mode to the renderer."""

        self.assertIn(
            'release_mode="$(python3 scripts/validate_release_transition.py select-mode)"',
            self.pull_request,
        )
        self.assertEqual(
            self.pull_request.count(
                "python3 scripts/validate_release_transition.py select-mode"
            ),
            1,
        )
        self.assertIn("scaffold|transition|release) ;;", self.pull_request)
        self.assertIn(
            './scripts/render-kubernetes.sh "--${release_mode}"', self.pull_request
        )
        self.assertNotIn("all-helm-suspended", self.pull_request)
        self.assertNotIn("grep -Eq", self.pull_request)
        state_check = self.pull_request.index(
            "python3 scripts/validate_release_transition.py select-mode"
        )
        repository_check = self.pull_request.index(
            "python3 scripts/validate_repository.py all"
        )
        exact_render = self.pull_request.index(
            './scripts/render-kubernetes.sh "--${release_mode}"'
        )
        self.assertLess(repository_check, state_check)
        self.assertLess(state_check, exact_render)
        self.assertNotIn("./scripts/render-kubernetes.sh\n", self.pull_request)
        parser = (REPO_ROOT / "scripts" / "validate_release_state.py").read_text(
            encoding="utf-8"
        )
        for release in (
            "kubernetes/websites/naranjo-online/release.yaml",
            "kubernetes/websites/lidersea-com/release.yaml",
            "kubernetes/platform/cloudflare-public/release/release.yaml",
        ):
            with self.subTest(release=release):
                self.assertEqual(parser.count(release), 1)

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
                self.assertIn(
                    "printf '%s' \"${GHCR_TOKEN}\" | oras login ghcr.io "
                    "--username \"${GITHUB_ACTOR}\" --password-stdin",
                    workflow,
                )
                self.assertIn("./scripts/ci/publish-oci-artifact.sh", workflow)
                self.assertIn(
                    "run: bash ./scripts/ci/publish-stable-oci-tag.sh", workflow
                )
                self.assertIn(
                    "OCI_ARCHIVE: ${{{{ runner.temp }}}}/{}.oci.tar".format(slug),
                    workflow,
                )
                self.assertIn(
                    "PUBLISH_VERIFY_ROOT: ${{{{ runner.temp }}}}/{}-publish-verify".format(
                        slug
                    ),
                    workflow,
                )
                self.assertIn(
                    "STABLE_TAG_VERIFY_ROOT: ${{{{ runner.temp }}}}/{}-stable-tag".format(
                        slug
                    ),
                    workflow,
                )
                self.assertNotIn("oras cp --from-oci-layout", workflow)
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
