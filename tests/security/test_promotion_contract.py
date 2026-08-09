"""Keep digest promotion exact while sharing its verification machinery."""

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMOTION = REPO_ROOT / "scripts" / "promote-image.sh"


class PromotionContractTests(unittest.TestCase):
    """Protect each site's independent provenance and values boundary."""

    @classmethod
    def setUpClass(cls):
        cls.script = PROMOTION.read_text(encoding="utf-8")

    def test_each_site_has_one_exact_identity_tuple(self):
        tuples = {
            "naranjo-online": (
                "ghcr.io/snaraj/naranjo-online",
                "kubernetes/websites/naranjo-online/release.yaml",
                "kubernetes/reconciliation/naranjo-online.yaml",
                "publish-naranjo-online-image.yml@refs/heads/main",
            ),
            "lidersea-com": (
                "ghcr.io/snaraj/lidersea-com",
                "kubernetes/websites/lidersea-com/release.yaml",
                "kubernetes/reconciliation/lidersea-com.yaml",
                "publish-lidersea-com-image.yml@refs/heads/main",
            ),
        }
        for site, fragments in tuples.items():
            with self.subTest(site=site):
                match = re.search(
                    r"(?ms)^  {}\)\n(?P<body>.*?)^    ;;$".format(re.escape(site)),
                    self.script,
                )
                self.assertIsNotNone(match)
                body = match.group("body")
                for fragment in fragments:
                    self.assertIn(fragment, body)
                for other_site, other_fragments in tuples.items():
                    if other_site == site:
                        continue
                    for fragment in other_fragments:
                        self.assertNotIn(fragment, body)

    def test_promotion_stays_review_only_and_digest_bound(self):
        for fragment in (
            "cosign verify --certificate-identity",
            "cosign verify-attestation --type slsaprovenance1",
            '[[ "${digest}" != "sha256:',
            "working tree must be clean before a release change",
            "validate_release_state.py",
            "site-phase --site",
            "promotion:initial|promotion:promoted|rollback:promoted",
            "tag_validation+=(--current)",
            "tag_validation+=(--rollback)",
            'oras manifest fetch-config --platform "${platform}" "${reference}"',
            '[[ "${image_version}" == "${release_version}" ]]',
            '[[ "${image_revision}" =~ ^[0-9a-f]{40}$ ]]',
            "HelmRelease changed during registry or candidate verification",
            "parent Kustomization changed during registry or candidate verification",
            "--expect-digest",
            "release review transaction",
            'trap on_failure ERR INT TERM HUP EXIT',
            '--root "${candidate_root}" emit-values',
            '--values "${effective_values}"',
            "create_release_patch.py",
            "create_release_candidate.py",
            "write_review_artifact.py",
            "remove_review_transaction.py",
            "plan --expect-mode transition",
            "canonical_patch_fingerprint",
            "The worktree is unchanged",
            "This script did not stage, commit, push, or deploy",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.script)
        self.assertNotIn("Verified and staged", self.script)
        self.assertNotIn("chart/values.yaml", self.script)
        self.assertNotIn('mv -f -- "${candidate_values}" "${values}"', self.script)
        self.assertNotIn('mv -f -- "${original_backup}" "${values}"', self.script)
        self.assertNotRegex(self.script, r"git[^\n]*(?: add | commit | push )")

    def test_state_is_bound_around_registry_and_candidate_finalization(self):
        """Long verification cannot stale a patch or write the live release."""

        initial_phase = self.script.index('initial_phase="$(site_phase)"')
        initial_fingerprint = self.script.index(
            'initial_release_fingerprint="$(file_sha256 "${values}")"'
        )
        first_registry_resolve = self.script.index(
            'tagged_digest="$(oras resolve "${image}:${release_tag}")"'
        )
        candidate_root = self.script.index(
            'candidate_root="${transaction_root}/root"'
        )
        candidate_phase = self.script.index('candidate_phase="$(')
        revalidated_phase = self.script.index(
            'revalidated_phase="$(site_phase)"'
        )
        digest_edit = self.script.index(
            'scripts/create_release_candidate.py"'
        )
        patch_creation = self.script.index(
            'scripts/create_release_patch.py"'
        )
        final_recheck = self.script.rindex(
            'candidate release state changed during local validation'
        )

        self.assertLess(initial_phase, initial_fingerprint)
        self.assertLess(initial_fingerprint, first_registry_resolve)
        self.assertLess(first_registry_resolve, candidate_root)
        self.assertLess(candidate_root, digest_edit)
        self.assertLess(digest_edit, candidate_phase)
        self.assertLess(candidate_phase, revalidated_phase)
        self.assertLess(candidate_phase, patch_creation)
        self.assertLess(patch_creation, revalidated_phase)
        self.assertLess(revalidated_phase, final_recheck)
        self.assertNotIn(
            "sed -E -i",
            self.script,
        )

    def test_git_state_reads_are_status_checked_and_head_bound(self):
        """Failed Git reads cannot be interpreted as clean state."""

        for fragment in (
            'if ! initial_head="$(git -C "${repo_root}" rev-parse --verify HEAD)"',
            'if ! initial_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"',
            'if ! current_head="$(git -C "${repo_root}" rev-parse --verify HEAD)"',
            'if ! current_status="$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)"',
            '[[ "${current_head}" == "${initial_head}" ]]',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.script)
        self.assertNotIn("mapfile", self.script)
        self.assertNotIn("require_release_only_diff", self.script)

    def test_candidate_snapshot_is_authenticated_and_failures_never_restore(self):
        self.assertIn(
            'if ! backup_fingerprint="$(file_sha256 "${original_backup}")"',
            self.script,
        )
        self.assertIn(
            '[[ "${backup_fingerprint}" == "${initial_release_fingerprint}" ]]',
            self.script,
        )
        self.assertIn('declare -A initial_state_fingerprints=()', self.script)
        for relative_path in (
            "infrastructure/cloudflare/dns.tf",
            "infrastructure/cloudflare/locals.tf",
            "infrastructure/cloudflare/outputs.tf",
            "infrastructure/cloudflare/private-routing.tf",
            "infrastructure/cloudflare/providers.tf",
            "infrastructure/cloudflare/security.tf",
            "infrastructure/cloudflare/tunnels.tf",
            "infrastructure/cloudflare/variables.tf",
            "infrastructure/cloudflare/versions.tf",
            "infrastructure/cloudflare/zero-trust.tf",
        ):
            with self.subTest(relative_path=relative_path):
                self.assertIn("'{}'".format(relative_path), self.script)
        self.assertIn('require_transition_snapshots_unchanged', self.script)
        self.assertEqual(
            self.script.count('require_transition_snapshots_unchanged'), 3
        )
        self.assertIn("cleanup_transaction || printf 'WARNING:", self.script)
        self.assertNotIn("Restored the original HelmRelease", self.script)
        self.assertNotIn("concurrently changed HelmRelease during rollback", self.script)

    def test_external_and_text_producers_are_status_checked(self):
        for variable in (
            "tagged_digest",
            "rebound_tagged_digest",
            "finalized_tagged_digest",
            "final_tagged_digest",
        ):
            with self.subTest(variable=variable):
                self.assertIn(
                    'if ! {}="$(oras resolve "${{image}}:${{release_tag}}")"'.format(
                        variable
                    ),
                    self.script,
                )
        self.assertNotRegex(self.script, r'\[\[\s+"\$\(oras ')
        self.assertNotIn("grep -Ec", self.script)
        self.assertNotIn("grep -Fxc", self.script)

    def test_forward_and_rollback_phases_preserve_readiness_and_suspensions(self):
        """Forward updates may repeat, while rollback requires promoted state."""

        self.assertIn("operation='rollback'", self.script)
        self.assertIn(
            "promotion:initial|promotion:promoted|rollback:promoted", self.script
        )
        self.assertIn(
            "rollback requires an already-promoted deployment readiness gate",
            self.script,
        )
        self.assertIn('--initial-phase "${initial_phase}"', self.script)
        self.assertIn("tag_validation+=(--current)", self.script)
        self.assertIn("tag_validation+=(--rollback)", self.script)
        self.assertEqual(self.script.count("--current"), 1)
        self.assertEqual(self.script.count("--rollback"), 3)
        self.assertIn("Both suspension gates remain true", self.script)
        self.assertNotIn("sed -E -i 's/^  suspend:", self.script)


if __name__ == "__main__":
    unittest.main()
