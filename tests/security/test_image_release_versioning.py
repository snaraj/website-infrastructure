"""Prove independent SemVer names never replace digest deployment identity."""

import contextlib
import io
import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_image_release.py"
SPEC = importlib.util.spec_from_file_location("validate_image_release", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_release_contract(root, gates=None):
    """Create the closed two-gate graduation policy used by validator fixtures."""

    gates = gates or ("no", "no")
    root.joinpath("release-policy.env").write_text(
        "NARANJO_ONLINE_PRODUCTION_GRADUATED={}\n"
        "LIDERSEA_COM_PRODUCTION_GRADUATED={}\n".format(*gates),
        encoding="utf-8",
    )


class ImageReleaseVersionTests(unittest.TestCase):
    """Keep human release names canonical, immutable, and site-scoped."""

    def test_committed_contract_is_policy_bound_per_site(self):
        self.assertEqual(MODULE.repository_errors(REPO_ROOT), [])
        policy = MODULE.read_policy(REPO_ROOT)
        self.assertIsNotNone(policy)
        for site, contract in MODULE.SITE_CONTRACTS.items():
            with self.subTest(site=site):
                self.assertIn(contract["gate"], policy)
                self.assertIn(policy[contract["gate"]], {"yes", "no"})
        self.assertEqual(
            [contract["gate"] for contract in MODULE.SITE_CONTRACTS.values()],
            list(policy),
        )

    def test_policy_shape_failures_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertTrue(any(
                "two reviewed yes/no" in error
                for error in MODULE.repository_errors(root)
            ))

            root.joinpath("release-policy.env").write_text(
                "NARANJO_ONLINE_PRODUCTION_GRADUATED=maybe\n"
                "LIDERSEA_COM_PRODUCTION_GRADUATED=no\n",
                encoding="utf-8",
            )
            self.assertTrue(MODULE.repository_errors(root))

            root.joinpath("release-policy.env").write_text(
                "LIDERSEA_COM_PRODUCTION_GRADUATED=no\n"
                "NARANJO_ONLINE_PRODUCTION_GRADUATED=no\n",
                encoding="utf-8",
            )
            self.assertTrue(
                MODULE.repository_errors(root),
                "gate order outside the closed contract must fail",
            )

            write_release_contract(root)
            self.assertEqual(MODULE.repository_errors(root), [])
            self.assertEqual(
                MODULE.repository_errors(root, "unknown-site"),
                ["unknown website release identity"],
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
            with self.subTest(version=invalid):
                self.assertIsNone(MODULE.parse_semver(invalid))
                self.assertIsNone(MODULE.parse_semver("v" + invalid, tagged=True))
        self.assertEqual(MODULE.parse_semver("0.1.0"), (0, 1, 0))
        self.assertEqual(MODULE.parse_semver("v1.2.3", tagged=True), (1, 2, 3))
        self.assertIsNone(MODULE.parse_semver("0.1.0", tagged=True))

    def test_production_graduation_is_explicit_and_atomic_per_site(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_release_contract(root)
            for site in MODULE.SITE_CONTRACTS:
                with self.subTest(site=site):
                    self.assertTrue(any(
                        "before tracked production graduation" in error
                        for error in MODULE.tag_errors(root, site, "v1.0.0")
                    ))

            write_release_contract(root, gates=("yes", "no"))
            self.assertEqual(MODULE.tag_errors(root, "naranjo-online", "v1.0.0"), [])
            self.assertTrue(any(
                "before tracked production graduation" in error
                for error in MODULE.tag_errors(root, "lidersea-com", "v1.0.0")
            ))
            self.assertEqual(MODULE.tag_errors(root, "lidersea-com", "v0.9.9"), [])

    def test_promotion_tags_are_exact_stable_semver_and_gate_v1(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_release_contract(root)
            self.assertEqual(MODULE.tag_errors(root, "naranjo-online", "v0.1.0"), [])
            for tag in ("0.1.0", "v0.1", "v0.1.0-rc.1", "v0.1.0+build", "latest"):
                with self.subTest(tag=tag):
                    self.assertTrue(MODULE.tag_errors(root, "naranjo-online", tag))
            self.assertTrue(any(
                "before tracked production graduation" in error
                for error in MODULE.tag_errors(root, "naranjo-online", "v1.0.0")
            ))
            self.assertEqual(
                MODULE.tag_errors(root, "unknown-site", "v0.1.0"),
                ["unknown website release identity"],
            )

    def test_tag_modes_remain_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_release_contract(root)
            self.assertEqual(
                MODULE.tag_errors(root, "naranjo-online", "v0.1.0", current=True),
                [],
            )
            self.assertEqual(
                MODULE.tag_errors(root, "naranjo-online", "v0.1.0", rollback=True),
                [],
            )
            self.assertIn(
                "release tag cannot be both current and rollback",
                MODULE.tag_errors(
                    root,
                    "naranjo-online",
                    "v0.1.0",
                    current=True,
                    rollback=True,
                ),
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
            self.assertEqual(result, 0)
            self.assertIn("PASS", stdout.getvalue())

            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    MODULE.main(
                        [
                            "--root",
                            str(root),
                            "validate-tag",
                            "--site",
                            "naranjo-online",
                            "--tag",
                            "v0.1.0",
                            "--current",
                            "--rollback",
                        ]
                    )

    def test_changed_subcommand_is_removed_with_site_source(self):
        """The platform no longer proves per-site bumps; site repos own that."""

        self.assertFalse(hasattr(MODULE, "changed_release_errors"))
        self.assertFalse(hasattr(MODULE, "git_changed_errors"))
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                MODULE.main(["changed", "--base", "0" * 40])

    def test_adr_documents_bumps_graduation_and_digest_authority(self):
        adr = REPO_ROOT.joinpath(
            "docs/adr/0014-immutable-container-release-versioning.md"
        ).read_text(encoding="utf-8")
        runbook = REPO_ROOT.joinpath(
            "docs/runbooks/image-rollback.md"
        ).read_text(encoding="utf-8")
        for fragment in (
            "release-policy.env",
            "1.0.0",
            "Kubernetes values remain digest-only",
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
