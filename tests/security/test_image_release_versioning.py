"""Prove independent SemVer names never replace digest deployment identity."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = load_script("validate_image_release.py")


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

    def test_historical_adr_and_current_rollback_contract_are_both_honest(self):
        adr = REPO_ROOT.joinpath(
            "docs/adr/0014-immutable-container-release-versioning.md"
        ).read_text(encoding="utf-8")
        runbook = REPO_ROOT.joinpath(
            "docs/runbooks/image-rollback.md"
        ).read_text(encoding="utf-8")
        for historical in (
            "release-policy.env",
            "1.0.0",
            "Kubernetes values remain digest-only",
            "scripts/promote-image.sh",
        ):
            with self.subTest(historical=historical):
                self.assertIn(historical, adr)
        for current in (
            "scripts/promote-image.sh` is retired",
            "exactly one `spec.ref.digest`",
            "Do not select another available tag or digest",
            "no image repository, tag, or digest",
        ):
            with self.subTest(current=current):
                self.assertIn(current, runbook)

    def test_promotion_script_cannot_rebind_a_release(self):
        promotion = (REPO_ROOT / "scripts/promote-image.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("promote-image: RETIRED", promotion)
        self.assertTrue(promotion.rstrip().endswith("exit 1"))
        for retired in (
            "validate_image_release.py",
            "oras resolve",
            "create_release_candidate.py",
            "create_release_patch.py",
            "git -C",
            "--rollback",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, promotion)


if __name__ == "__main__":
    unittest.main()
