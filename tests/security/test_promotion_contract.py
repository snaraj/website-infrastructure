"""Keep digest promotion exact while sharing its verification machinery."""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import load_script, required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMOTION = REPO_ROOT / "scripts" / "promote-image.sh"
TRANSITION = load_script(
    "validate_release_transition.py",
    module_name="validate_release_transition_for_promotion",
)

# The behavioral battery below executes the script's own label-verification
# loop, so it needs the same shell and JSON tooling the script itself
# requires; hosts without them skip with an explanation while CI always runs.
BASH = shutil.which("bash")
JQ = shutil.which("jq")

# One exact region: from the loop's accumulator initialization through the
# closing `done`. Executing the shipped bytes (never a copy) means the
# battery cannot drift from what promotion actually runs.
LABEL_LOOP_RE = re.compile(r"(?ms)^release_revision=''\n.*?^done$")
SITE_BODY_TEMPLATE = r"(?ms)^  {}\)\n(?P<body>.*?)^    ;;$"
EXPECTED_SOURCE_RE = re.compile(r"(?m)^    expected_source='([^']+)'$")

# The two standalone site repositories that build and label the images, and
# the retired platform-repository label that must now be denied (#8 pinned
# it; the #21 extraction moved the sources but left the pin behind).
SITE_SOURCE_LABELS = {
    "naranjo-online": "https://github.com/snaraj/naranjo.online",
    "lidersea-com": "https://github.com/snaraj/lidersea.com",
}
PLATFORM_REPOSITORY_LABEL = "https://github.com/snaraj/website-infrastructure"


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
                "https://github.com/snaraj/naranjo.online/.github/workflows/"
                "release-publisher.yml@refs/tags/",
                "expected_source='https://github.com/snaraj/naranjo.online'",
                "oci://ghcr.io/snaraj/charts/naranjo-online",
            ),
            "lidersea-com": (
                "ghcr.io/snaraj/lidersea-com",
                "kubernetes/websites/lidersea-com/release.yaml",
                "kubernetes/reconciliation/lidersea-com.yaml",
                "https://github.com/snaraj/lidersea.com/.github/workflows/"
                "release-publisher.yml@refs/tags/",
                "expected_source='https://github.com/snaraj/lidersea.com'",
                "oci://ghcr.io/snaraj/charts/lidersea-com",
            ),
        }
        for site, fragments in tuples.items():
            with self.subTest(site=site):
                match = re.search(
                    r"(?ms)^  {}\)\n(?P<body>.*?)^    ;;$".format(re.escape(site)),
                    self.script,
                )
                if match is None:
                    # A raise statement, not assertIsNotNone: it narrows the
                    # Optional for static analysis and survives python -O
                    # (same discipline as support.required_tool).
                    raise AssertionError("missing identity tuple for " + site)
                body = match.group("body")
                for fragment in fragments:
                    self.assertIn(fragment, body)
                for other_site, other_fragments in tuples.items():
                    if other_site == site:
                        continue
                    for fragment in other_fragments:
                        self.assertNotIn(fragment, body)

    def test_image_source_label_is_pinned_per_site(self):
        """The source-label gate compares against the site tuple, never a global.

        #8 introduced the label check against the then-monorepo
        (`https://github.com/snaraj/website-infrastructure`); the #21
        extraction re-pointed the cosign identities at the standalone site
        publishers but left that literal behind, so every post-extraction
        image failed promotion. The accepted label is now part of each
        site's closed identity tuple (safety invariant 14): the comparison
        must reference the tuple variable, each tuple must pin exactly its
        own repository, and no comparison against the platform repository
        may remain anywhere in the script.
        """

        self.assertIn(
            '[[ "${image_source}" == "${expected_source}" ]]', self.script
        )
        self.assertNotIn(
            "== '" + PLATFORM_REPOSITORY_LABEL + "'", self.script
        )
        for site, label in SITE_SOURCE_LABELS.items():
            with self.subTest(site=site):
                match = re.search(
                    SITE_BODY_TEMPLATE.format(re.escape(site)), self.script
                )
                if match is None:
                    raise AssertionError("missing identity tuple for " + site)
                pins = EXPECTED_SOURCE_RE.findall(match.group("body"))
                self.assertEqual(pins, [label])

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
        inventory_match = re.search(
            r"(?ms)^declare -a release_state_paths=\(\n(?P<body>.*?)^\)\n",
            self.script,
        )
        if inventory_match is None:
            raise AssertionError(
                "promote-image.sh lost its release_state_paths inventory"
            )
        cloudflare_review_paths = tuple(
            path
            for path in re.findall(
                r"(?m)^  '([^']+)'$", inventory_match.group("body")
            )
            if path.startswith("infrastructure/cloudflare/")
        )
        expected_cloudflare_review_paths = tuple(
            path.as_posix()
            for path in sorted(TRANSITION.CLOUDFLARE_TERRAFORM_REVIEW_FILES)
        )
        self.assertEqual(
            cloudflare_review_paths,
            expected_cloudflare_review_paths,
        )
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


@unittest.skipUnless(
    BASH and JQ, "bash and jq are required for the label-verification battery"
)
class SourceLabelVerificationBatteryTests(unittest.TestCase):
    """Execute the shipped label loop against forged image configs.

    The static tuple tests above prove the per-site pin exists; this
    battery proves it decides. The exact region promotion runs — from
    ``release_revision=''`` through the platform loop's ``done`` — is
    extracted from the script and executed under ``bash`` with a stub
    ``oras`` that serves a test-controlled config document, so every
    deny/allow verdict below is produced by the shipped bytes, not a
    reimplementation that could drift.
    """

    @classmethod
    def setUpClass(cls):
        cls.bash = required_tool(
            BASH, "bash is required for the label-verification battery"
        )
        required_tool(JQ, "jq is required for the label-verification battery")
        script = PROMOTION.read_text(encoding="utf-8")
        loop = LABEL_LOOP_RE.search(script)
        if loop is None:
            raise AssertionError(
                "promote-image.sh no longer contains the label-verification loop"
            )
        cls.label_loop = loop.group(0)
        if '[[ "${image_source}" == "${expected_source}" ]]' not in cls.label_loop:
            raise AssertionError(
                "the label loop lost its per-site source equality gate"
            )
        cls.expected_sources = {}
        for site, label in SITE_SOURCE_LABELS.items():
            body = re.search(SITE_BODY_TEMPLATE.format(re.escape(site)), script)
            if body is None:
                raise AssertionError("missing identity tuple for " + site)
            pins = EXPECTED_SOURCE_RE.findall(body.group("body"))
            if pins != [label]:
                raise AssertionError(
                    site + " tuple does not pin exactly its own source label"
                )
            cls.expected_sources[site] = pins[0]

    @staticmethod
    def forged_labels(source):
        """Labels that satisfy every later gate, isolating the source verdict."""

        labels = {
            "org.opencontainers.image.version": "0.1.9",
            "org.opencontainers.image.revision": "a" * 40,
        }
        if source is not None:
            labels["org.opencontainers.image.source"] = source
        return labels

    def run_label_loop(self, expected_source, labels):
        """Run the shipped loop with a stub registry serving ``labels``."""

        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps({"config": {"Labels": labels}}), encoding="utf-8"
            )
            stub_directory = root / "bin"
            stub_directory.mkdir()
            stub = stub_directory / "oras"
            stub.write_text(
                '#!/usr/bin/env bash\ncat -- "${PROMOTION_TEST_CONFIG}"\n',
                encoding="utf-8",
            )
            stub.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = (
                str(stub_directory) + os.pathsep + environment.get("PATH", "")
            )
            environment["PROMOTION_TEST_CONFIG"] = str(config_path)
            prelude = (
                "set -Eeuo pipefail\n"
                "expected_source=" + shlex.quote(expected_source) + "\n"
                "release_version='0.1.9'\n"
                "reference='registry.invalid/site@sha256:" + "1" * 64 + "'\n"
            )
            return subprocess.run(
                [self.bash, "-c", prelude + self.label_loop],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

    def assert_denied_as_unreviewed_source(self, completed):
        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "linux/amd64 image source label is not the reviewed site repository",
            completed.stderr,
        )

    def test_own_site_source_label_is_allowed(self):
        for site, expected in self.expected_sources.items():
            with self.subTest(site=site):
                completed = self.run_label_loop(
                    expected, self.forged_labels(expected)
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    completed.stdout + completed.stderr,
                )

    def test_platform_repository_source_label_is_denied(self):
        for site, expected in self.expected_sources.items():
            with self.subTest(site=site):
                self.assert_denied_as_unreviewed_source(
                    self.run_label_loop(
                        expected,
                        self.forged_labels(PLATFORM_REPOSITORY_LABEL),
                    )
                )

    def test_other_site_source_label_is_denied(self):
        """A valid label from the wrong tuple never crosses sites (invariant 14)."""

        for site, expected in self.expected_sources.items():
            others = [
                label
                for other, label in self.expected_sources.items()
                if other != site
            ]
            self.assertEqual(len(others), 1)
            with self.subTest(site=site, forged=others[0]):
                self.assert_denied_as_unreviewed_source(
                    self.run_label_loop(expected, self.forged_labels(others[0]))
                )

    def test_empty_or_absent_source_label_is_denied(self):
        for site, expected in self.expected_sources.items():
            for description, source in (("empty", ""), ("absent", None)):
                with self.subTest(site=site, label=description):
                    self.assert_denied_as_unreviewed_source(
                        self.run_label_loop(
                            expected, self.forged_labels(source)
                        )
                    )


if __name__ == "__main__":
    unittest.main()
