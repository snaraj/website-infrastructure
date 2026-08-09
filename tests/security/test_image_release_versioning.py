"""Prove independent SemVer names never replace digest deployment identity."""

import contextlib
import io
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_image_release.py"
SPEC = importlib.util.spec_from_file_location("validate_image_release", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PULL_REQUEST = (REPO_ROOT / ".github/workflows/pull-request.yml").read_text(
    encoding="utf-8"
)
PUBLISHERS = {
    "naranjo-online": (
        "naranjo.online",
        REPO_ROOT / ".github/workflows/publish-naranjo-online-image.yml",
    ),
    "lidersea-com": (
        "lidersea.com",
        REPO_ROOT / ".github/workflows/publish-lidersea-com-image.yml",
    ),
}


def write_release_contract(root, naranjo="0.1.0", lidersea="0.1.0", gates=None):
    """Create the complete small release contract used by validator fixtures."""

    gates = gates or ("no", "no")
    root.joinpath("release-policy.env").write_text(
        "NARANJO_ONLINE_PRODUCTION_GRADUATED={}\n"
        "LIDERSEA_COM_PRODUCTION_GRADUATED={}\n".format(*gates),
        encoding="utf-8",
    )
    for domain, version in (("naranjo.online", naranjo), ("lidersea.com", lidersea)):
        path = root / "websites" / domain / "VERSION"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(version + "\n", encoding="utf-8")


class ImageReleaseVersionTests(unittest.TestCase):
    """Keep human release names canonical, immutable, and site-scoped."""

    def assert_git_release_path_requires_bump(self, filename):
        """Prove one exact Git pathname remains a release input."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_release_contract(root)
            source = root / "websites/naranjo.online/frontend/src" / filename
            source.parent.mkdir(parents=True)
            source.write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=release-test",
                    "-c",
                    "user.email=release-test@example.invalid",
                    "commit",
                    "-qm",
                    "base",
                ],
                check=True,
            )
            base = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()

            source.write_text("changed\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=release-test",
                    "-c",
                    "user.email=release-test@example.invalid",
                    "commit",
                    "-qm",
                    "path-change",
                ],
                check=True,
            )
            errors = MODULE.git_changed_errors(root, base)
            self.assertTrue(any("naranjo-online" in error for error in errors))

            root.joinpath("websites/naranjo.online/VERSION").write_text(
                "0.1.1\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=release-test",
                    "-c",
                    "user.email=release-test@example.invalid",
                    "commit",
                    "-qm",
                    "version-bump",
                ],
                check=True,
            )
            self.assertEqual(MODULE.git_changed_errors(root, base), [])

    def test_committed_contract_is_independent_policy_bound_semver(self):
        self.assertEqual(MODULE.repository_errors(REPO_ROOT), [])
        policy = MODULE.read_policy(REPO_ROOT)
        self.assertIsNotNone(policy)
        for site, contract in MODULE.SITE_CONTRACTS.items():
            version = MODULE.read_version(REPO_ROOT, site)
            parsed = MODULE.parse_semver(version)
            self.assertIsNotNone(parsed)
            if policy[contract["gate"]] == "no":
                self.assertEqual(parsed[0], 0)
            else:
                self.assertGreaterEqual(parsed[0], 1)
        self.assertNotEqual(
            REPO_ROOT / "websites/naranjo.online/VERSION",
            REPO_ROOT / "websites/lidersea.com/VERSION",
        )

    def test_rejects_noncanonical_or_unstable_versions(self):
        invalid_versions = (
            "v0.1.0",
            "0.1",
            "00.1.0",
            "0.01.0",
            "0.1.00",
            "0.1.0-rc.1",
            "0.1.0+build.1",
            " 0.1.0",
            "0.1.0 ",
            "0." + ("1" * 129) + ".0",
        )
        for invalid in invalid_versions:
            with self.subTest(version=invalid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_release_contract(root, naranjo=invalid)
                self.assertTrue(MODULE.repository_errors(root))

    def test_production_graduation_is_explicit_and_atomic_per_site(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_release_contract(root, naranjo="1.0.0")
            self.assertTrue(any(
                "tracked production gate" in error
                for error in MODULE.repository_errors(root)
            ))

            write_release_contract(root, naranjo="0.9.9", gates=("yes", "no"))
            self.assertTrue(any(
                "atomically move VERSION" in error
                for error in MODULE.repository_errors(root)
            ))

            write_release_contract(root, naranjo="1.0.0", gates=("yes", "no"))
            self.assertEqual(MODULE.repository_errors(root), [])
            self.assertEqual(
                MODULE.tag_errors(root, "naranjo-online", "v0.9.9"), []
            )

    def test_promotion_tags_are_exact_stable_semver_and_gate_v1(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_release_contract(root)
            self.assertEqual(MODULE.tag_errors(root, "naranjo-online", "v0.1.0"), [])
            for tag in ("0.1.0", "v0.1", "v0.1.0-rc.1", "v0.1.0+build", "latest"):
                with self.subTest(tag=tag):
                    self.assertTrue(MODULE.tag_errors(root, "naranjo-online", tag))
            self.assertTrue(any(
                "before tracked production graduation" in error
                for error in MODULE.tag_errors(root, "naranjo-online", "v1.0.0")
            ))

    def test_tag_modes_bind_forward_and_rollback_version_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_release_contract(root, naranjo="0.2.0")
            self.assertEqual(
                MODULE.tag_errors(root, "naranjo-online", "v0.1.0"),
                [],
            )
            self.assertEqual(
                MODULE.tag_errors(
                    root,
                    "naranjo-online",
                    "v0.2.0",
                    current=True,
                ),
                [],
            )
            errors = MODULE.tag_errors(
                root,
                "naranjo-online",
                "v0.1.0",
                current=True,
            )
            self.assertTrue(any("tracked VERSION" in error for error in errors))
            self.assertEqual(
                MODULE.tag_errors(
                    root,
                    "naranjo-online",
                    "v0.1.9",
                    rollback=True,
                ),
                [],
            )
            for tag in ("v0.2.0", "v0.2.1"):
                with self.subTest(rollback_tag=tag):
                    errors = MODULE.tag_errors(
                        root,
                        "naranjo-online",
                        tag,
                        rollback=True,
                    )
                    self.assertTrue(
                        any("strictly older" in error for error in errors)
                    )

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = MODULE.main(
                    [
                        "--root",
                        str(root),
                        "validate-tag",
                        "--site",
                        "naranjo-online",
                        "--tag",
                        "v0.1.0",
                        "--current",
                    ]
                )
            self.assertEqual(result, 1)
            self.assertIn("tracked VERSION", stderr.getvalue())

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = MODULE.main(
                    [
                        "--root",
                        str(root),
                        "validate-tag",
                        "--site",
                        "naranjo-online",
                        "--tag",
                        "v0.2.0",
                        "--rollback",
                    ]
                )
            self.assertEqual(result, 1)
            self.assertIn("strictly older", stderr.getvalue())

    def test_release_input_paths_do_not_couple_site_source(self):
        self.assertTrue(MODULE.is_release_input(
            "naranjo-online", "websites/naranjo.online/frontend/src/App.svelte"
        ))
        self.assertFalse(MODULE.is_release_input(
            "lidersea-com", "websites/naranjo.online/frontend/src/App.svelte"
        ))
        self.assertFalse(MODULE.is_release_input(
            "naranjo-online", "websites/naranjo.online/chart/values.yaml"
        ))
        self.assertTrue(MODULE.is_release_input(
            "naranjo-online", ".github/workflows/publish-naranjo-online-image.yml"
        ))
        for site in MODULE.SITE_CONTRACTS:
            self.assertTrue(MODULE.is_release_input(
                site, "scripts/ci/verify-oci-artifact.sh"
            ))
            self.assertTrue(MODULE.is_release_input(
                site, "scripts/ci/publish-oci-artifact.sh"
            ))
            self.assertTrue(MODULE.is_release_input(
                site, "scripts/ci/publish-stable-oci-tag.sh"
            ))

    def test_changed_site_input_requires_only_its_increasing_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_versions = {"naranjo-online": "0.1.0", "lidersea-com": "0.1.0"}
            base_policy = {
                "NARANJO_ONLINE_PRODUCTION_GRADUATED": "no",
                "LIDERSEA_COM_PRODUCTION_GRADUATED": "no",
            }
            write_release_contract(root)
            errors = MODULE.changed_release_errors(
                root,
                ["websites/naranjo.online/cmd/server/main.go"],
                base_versions,
                base_policy,
            )
            self.assertEqual(sum("naranjo-online" in error for error in errors), 1)
            self.assertFalse(any("lidersea-com" in error for error in errors))

            write_release_contract(root, naranjo="0.1.1")
            self.assertEqual(MODULE.changed_release_errors(
                root,
                ["websites/naranjo.online/cmd/server/main.go"],
                base_versions,
                base_policy,
            ), [])

    def test_shared_release_input_requires_both_versions_to_increase(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_release_contract(root, naranjo="0.1.1")
            errors = MODULE.changed_release_errors(
                root,
                ["scripts/ci/verify-oci-artifact.sh"],
                {"naranjo-online": "0.1.0", "lidersea-com": "0.1.0"},
                {
                    "NARANJO_ONLINE_PRODUCTION_GRADUATED": "no",
                    "LIDERSEA_COM_PRODUCTION_GRADUATED": "no",
                },
            )
            self.assertFalse(any("naranjo-online" in error for error in errors))
            self.assertTrue(any("lidersea-com" in error for error in errors))

    def test_version_file_cannot_move_back_without_other_input_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_release_contract(root, naranjo="0.1.0")
            errors = MODULE.changed_release_errors(
                root,
                ["websites/naranjo.online/VERSION"],
                {"naranjo-online": "0.2.0", "lidersea-com": "0.1.0"},
                {
                    "NARANJO_ONLINE_PRODUCTION_GRADUATED": "no",
                    "LIDERSEA_COM_PRODUCTION_GRADUATED": "no",
                },
            )
            self.assertTrue(any("naranjo-online" in error for error in errors))

    def test_git_base_comparison_rejects_then_accepts_a_real_bump(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_release_contract(root)
            source = root / "websites/naranjo.online/cmd/server/main.go"
            source.parent.mkdir(parents=True)
            source.write_text("package main\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run([
                "git", "-C", str(root), "-c", "user.name=release-test",
                "-c", "user.email=release-test@example.invalid", "commit", "-qm", "base",
            ], check=True)
            base = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            source.write_text("package main\n// change\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run([
                "git", "-C", str(root), "-c", "user.name=release-test",
                "-c", "user.email=release-test@example.invalid", "commit", "-qm", "source",
            ], check=True)
            self.assertTrue(MODULE.git_changed_errors(root, base))

            root.joinpath("websites/naranjo.online/VERSION").write_text(
                "0.1.1\n", encoding="utf-8"
            )
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run([
                "git", "-C", str(root), "-c", "user.name=release-test",
                "-c", "user.email=release-test@example.invalid", "commit", "-qm", "version",
            ], check=True)
            self.assertEqual(MODULE.git_changed_errors(root, base), [])

    def test_git_base_comparison_counts_deleted_and_moved_build_inputs(self):
        """Removing release input is still a rebuild-worthy product change."""

        for operation in ("delete", "move-out"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_release_contract(root)
                source = root / "websites/naranjo.online/internal/web/asset.go"
                source.parent.mkdir(parents=True)
                source.write_text("package web\n", encoding="utf-8")
                subprocess.run(["git", "init", "-q", str(root)], check=True)
                subprocess.run(["git", "-C", str(root), "add", "."], check=True)
                subprocess.run([
                    "git", "-C", str(root), "-c", "user.name=release-test",
                    "-c", "user.email=release-test@example.invalid",
                    "commit", "-qm", "base",
                ], check=True)
                base = subprocess.run(
                    ["git", "-C", str(root), "rev-parse", "HEAD"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout.strip()

                if operation == "delete":
                    source.unlink()
                else:
                    destination = root / "docs" / "asset.go"
                    destination.parent.mkdir()
                    source.rename(destination)
                subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
                subprocess.run([
                    "git", "-C", str(root), "-c", "user.name=release-test",
                    "-c", "user.email=release-test@example.invalid",
                    "commit", "-qm", operation,
                ], check=True)

                errors = MODULE.git_changed_errors(root, base)
                self.assertTrue(any("naranjo-online" in error for error in errors))

    def test_git_base_comparison_preserves_non_ascii_pathnames(self):
        """Git quoting cannot hide a Unicode path below a release input."""

        self.assert_git_release_path_requires_bump("caf\u00e9.svelte")

    @unittest.skipUnless(os.name == "posix", "newline filenames require POSIX")
    def test_git_base_comparison_preserves_newline_pathnames(self):
        """Line splitting cannot hide a control character inside a pathname."""

        self.assert_git_release_path_requires_bump("line\nbreak.svelte")

    def test_git_path_stream_requires_complete_nul_delimiters(self):
        value = "websites/naranjo.online/frontend/src/caf\u00e9.svelte"
        encoded = value.encode("utf-8") + b"\0"
        self.assertEqual(MODULE._nul_paths(encoded), [value])
        with self.assertRaises(ValueError):
            MODULE._nul_paths(encoded[:-1])
        with self.assertRaises(ValueError):
            MODULE._nul_paths(encoded + b"\0")

    def test_publishers_emit_two_exact_names_and_refuse_reassignment(self):
        stable_publisher = REPO_ROOT.joinpath(
            "scripts", "ci", "publish-stable-oci-tag.sh"
        ).read_text(encoding="utf-8")
        for site, (domain, path) in PUBLISHERS.items():
            workflow = path.read_text(encoding="utf-8")
            with self.subTest(site=site):
                self.assertIn("websites/{}/VERSION".format(domain), workflow)
                self.assertNotIn("      - release-policy.env", workflow)
                self.assertIn("fetch-depth: 0", workflow)
                self.assertIn("BASE_SHA: ${{ github.event.before }}", workflow)
                self.assertIn(
                    'validate_image_release.py changed --base "${BASE_SHA}"', workflow
                )
                self.assertIn("${{ env.IMAGE }}:sha-${{ github.sha }}", workflow)
                self.assertIn("${{ env.IMAGE }}:${{ steps.release.outputs.tag }}", workflow)
                self.assertIn("oras repo tags \"${IMAGE}\"", workflow)
                self.assertIn("assert_expected_mapping", workflow)
                self.assertIn(
                    "run: bash ./scripts/ci/publish-stable-oci-tag.sh",
                    workflow,
                )
                self.assertIn("STABLE_TAG_VERIFY_ROOT:", workflow)
                self.assertIn("./scripts/ci/publish-oci-artifact.sh", workflow)
                self.assertIn("verify-existing:", workflow)
                self.assertIn(
                    "run: bash ./scripts/ci/verify-existing-oci-release.sh",
                    workflow,
                )
                self.assertIn("PUBLISH_VERIFY_ROOT:", workflow)
                self.assertNotIn(":latest", workflow)
                self.assertNotIn("contents: write", workflow)
                publish_block, manual_block = workflow.split("  verify-existing:\n", 1)
                self.assertIn("github.event_name == 'push'", publish_block)
                self.assertIn("packages: write", publish_block)
                self.assertIn("github.event_name == 'workflow_dispatch'", manual_block)
                self.assertIn("packages: read", manual_block)
                self.assertNotIn("packages: write", manual_block)
                self.assertNotIn("id-token: write", manual_block)
                self.assertNotIn("attestations: write", manual_block)
                self.assertNotIn("cosign sign", manual_block)
                self.assertNotIn("actions/attest", manual_block)
                self.assertNotIn("publish-oci-artifact.sh", manual_block)
                self.assertNotIn("publish-stable-oci-tag.sh", manual_block)
                self.assertNotIn("oras tag", manual_block)
        self.assertIn("refusing to reassign immutable tag", stable_publisher)
        self.assertIn("MANIFEST_UNKNOWN", stable_publisher)
        self.assertNotIn("|not found", stable_publisher)
        self.assertIn(
            'oras tag "${IMAGE}@${EXPECTED_DIGEST}" "${RELEASE_TAG}"',
            stable_publisher,
        )

    def test_publishers_label_and_record_version_revision_digest(self):
        for site, (_, path) in PUBLISHERS.items():
            workflow = path.read_text(encoding="utf-8")
            with self.subTest(site=site):
                for fragment in (
                    "org.opencontainers.image.source=",
                    "org.opencontainers.image.version=${{ steps.release.outputs.version }}",
                    "org.opencontainers.image.revision=${{ github.sha }}",
                    "--arg version \"${RELEASE_VERSION}\"",
                    "--arg tag \"${RELEASE_TAG}\"",
                    "--arg revision \"${GITHUB_SHA}\"",
                    "--arg digest \"${EXPECTED_DIGEST}\"",
                    '>> "${GITHUB_STEP_SUMMARY}"',
                    "{}.release.json".format(site),
                ):
                    self.assertIn(fragment, workflow)

    def test_pull_request_uses_read_only_history_for_bump_proof(self):
        self.assertIn("fetch-depth: 0", PULL_REQUEST)
        self.assertIn("BASE_SHA: ${{ github.event.pull_request.base.sha }}", PULL_REQUEST)
        self.assertIn(
            'python3 scripts/validate_image_release.py changed --base "${BASE_SHA}"',
            PULL_REQUEST,
        )
        self.assertNotIn("pull_request_target:", PULL_REQUEST)
        self.assertNotIn("contents: write", PULL_REQUEST)

    def test_adr_documents_bumps_graduation_and_digest_authority(self):
        adr = REPO_ROOT.joinpath(
            "docs/adr/0014-immutable-container-release-versioning.md"
        ).read_text(encoding="utf-8")
        runbook = REPO_ROOT.joinpath(
            "docs/runbooks/image-rollback.md"
        ).read_text(encoding="utf-8")
        for fragment in (
            "websites/naranjo.online/VERSION",
            "websites/lidersea.com/VERSION",
            "release-policy.env",
            "increment PATCH",
            "increment MINOR",
            "1.0.0",
            "Kubernetes values remain digest-only",
            "contents: write",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, adr)
        self.assertIn(
            "vMAJOR.MINOR.PATCH sha256:<digest>", runbook
        )
        self.assertIn(
            "Kubernetes still receives only the digest", " ".join(runbook.split())
        )

    def test_promotion_rebinds_tag_through_candidate_only_review_patch(self):
        promotion = (REPO_ROOT / "scripts/promote-image.sh").read_text(encoding="utf-8")
        self.assertIn("vMAJOR.MINOR.PATCH sha256:<64 lowercase hex>", promotion)
        self.assertIn('validate_image_release.py" validate-tag', promotion)
        self.assertEqual(
            promotion.count('oras resolve "${image}:${release_tag}"'), 4
        )
        self.assertIn('[[ "${tagged_digest}" == "${digest}" ]]', promotion)
        self.assertIn(
            'scripts/create_release_candidate.py"',
            promotion,
        )
        self.assertIn(
            '--initial-phase "${initial_phase}"',
            promotion,
        )
        self.assertIn("scripts/create_release_patch.py", promotion)
        self.assertIn('git -C "${repo_root}" apply --check -- "${review_patch}"', promotion)
        self.assertIn("The worktree is unchanged", promotion)
        self.assertNotIn('mv -f -- "${candidate_values}" "${values}"', promotion)
        self.assertNotIn("sed -E -i", promotion)
        self.assertIn(
            '--root "${candidate_root}" emit-values --release "${site}"',
            promotion,
        )
        self.assertIn("[[ \"${4}\" == '--rollback' ]]", promotion)
        self.assertIn("[[ \"${operation}\" == 'promotion' ]]", promotion)
        self.assertIn(
            "parent Kustomization must be explicitly suspended before a digest change",
            promotion,
        )
        self.assertIn(
            "rollback requires an already-promoted deployment readiness gate",
            promotion,
        )
        self.assertNotIn("sed -E -i 's/^  suspend:", promotion)
        self.assertIn(
            'oras manifest fetch-config --platform "${platform}" "${reference}"',
            promotion,
        )
        self.assertIn(
            '[[ "${image_version}" == "${release_version}" ]]',
            promotion,
        )
        self.assertIn("kubernetes/websites/naranjo-online/release.yaml", promotion)
        self.assertIn("kubernetes/websites/lidersea-com/release.yaml", promotion)
        self.assertNotIn("/VERSION", promotion)
        self.assertNotIn("appVersion", promotion)


if __name__ == "__main__":
    unittest.main()
