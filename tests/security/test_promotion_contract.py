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

# RATCHET (#58): the per-site cosign-attestation requirement may only ever be
# edited 'false' -> 'true', one site at a time, once that site's
# release-publisher attaches cosign slsaprovenance1 attestations. This pin IS
# the ratchet record: the flip PR updates the expected value here alongside
# the tuple, and a value moving back to 'false' has no legitimate diff.
EXPECTED_ATTESTATIONS_REQUIRED = {
    "naranjo-online": "false",
    "lidersea-com": "false",
}
ATTESTATIONS_REQUIRED_RE = re.compile(
    r"(?m)^    attestations_required='([^']*)'$"
)
GATED_ATTESTATION_CHECK = (
    "if [[ \"${attestations_required}\" == 'true' ]]; then\n"
    "  cosign verify-attestation --type slsaprovenance1 "
    '--certificate-identity "${identity}" '
    '--certificate-oidc-issuer "${issuer}" "${reference}" >/dev/null\n'
    "fi"
)

# The embedded-provenance battery executes this exact shipped function; the
# regex is anchored on the function's own name and closing brace at column 0.
PROVENANCE_FUNCTION_RE = re.compile(
    r"(?ms)^verify_embedded_provenance\(\) \{\n.*?\n\}$"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


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

    def test_attestation_ratchet_is_tuple_pinned_and_one_way(self):
        """The cosign-attestation requirement ratchets per site, never back.

        Bridge state (#58): the site publishers attach BuildKit-embedded SLSA
        provenance but no cosign attestation, so each identity tuple carries
        `attestations_required='false'` and the embedded-provenance review is
        the required evidence. The flag's only legitimate edit is
        'false' -> 'true' (per site, once its publisher ships cosign
        attestations); EXPECTED_ATTESTATIONS_REQUIRED pins the current value
        so any flip is a reviewed, visible diff here, and any reversal has no
        legitimate diff at all. The gated verify-attestation command must
        survive verbatim so the ratchet re-arms it without rewording, and the
        unconditional embedded-provenance call must run before it.
        """

        assignments = ATTESTATIONS_REQUIRED_RE.findall(self.script)
        self.assertEqual(len(assignments), len(EXPECTED_ATTESTATIONS_REQUIRED))
        for site, expected_value in EXPECTED_ATTESTATIONS_REQUIRED.items():
            with self.subTest(site=site):
                self.assertIn(expected_value, ("false", "true"))
                match = re.search(
                    SITE_BODY_TEMPLATE.format(re.escape(site)), self.script
                )
                if match is None:
                    raise AssertionError("missing identity tuple for " + site)
                self.assertEqual(
                    ATTESTATIONS_REQUIRED_RE.findall(match.group("body")),
                    [expected_value],
                )
        self.assertIn(GATED_ATTESTATION_CHECK, self.script)
        definitions = self.script.count("verify_embedded_provenance() {")
        self.assertEqual(definitions, 1)
        calls = re.findall(r"(?m)^verify_embedded_provenance$", self.script)
        self.assertEqual(len(calls), 1)
        self.assertLess(
            self.script.index("\nverify_embedded_provenance\n"),
            self.script.index(GATED_ATTESTATION_CHECK),
        )

    def test_promotion_stays_review_only_and_digest_bound(self):
        for fragment in (
            "cosign verify --certificate-identity",
            "cosign verify-attestation --type slsaprovenance1",
            "verify_embedded_provenance",
            "attestation-manifest",
            "in-toto.io/predicate-type",
            STATEMENT_TYPE,
            PROVENANCE_PREDICATE_TYPE,
            'oras blob fetch "${image}@${slsa_layer_digest}" --output -',
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


@unittest.skipUnless(
    BASH and JQ, "bash and jq are required for the provenance battery"
)
class EmbeddedProvenanceVerificationBatteryTests(unittest.TestCase):
    """Execute the shipped embedded-provenance verifier against forged trees.

    ``verify_embedded_provenance`` (the #58 bridge) is extracted verbatim
    from the script and executed under ``bash`` with a stub ``oras`` serving
    a test-controlled content-addressed tree — index, attestation manifests,
    and in-toto statements — so every allow/deny verdict below is produced by
    the shipped bytes. The synthetic site identity keeps the battery
    hermetic; the binding of each REAL site to its own expected source is
    already pinned by the static tuple tests above.
    """

    IMAGE = "registry.invalid/example/site"
    TAG = "v9.9.9"
    SOURCE = "https://github.com/example/site"
    REVISION = "a" * 40
    INDEX_HEX = "1" * 64
    PLATFORM_HEX = {"amd64": "a" * 64, "arm64": "b" * 64}
    ATTESTATION_HEX = {"amd64": "c" * 64, "arm64": "d" * 64}
    LAYER_HEX = {"amd64": "e" * 64, "arm64": "f" * 64}

    @classmethod
    def setUpClass(cls):
        cls.bash = required_tool(
            BASH, "bash is required for the provenance battery"
        )
        required_tool(JQ, "jq is required for the provenance battery")
        script = PROMOTION.read_text(encoding="utf-8")
        function_match = PROVENANCE_FUNCTION_RE.search(script)
        if function_match is None:
            raise AssertionError(
                "promote-image.sh no longer defines verify_embedded_provenance"
            )
        cls.function_text = function_match.group(0)
        for anchor in (
            STATEMENT_TYPE,
            PROVENANCE_PREDICATE_TYPE,
            "vnd.docker.reference.digest",
            "startswith($builder_prefix)",
        ):
            if anchor not in cls.function_text:
                raise AssertionError(
                    "the embedded-provenance verifier lost its anchor: "
                    + anchor
                )

    def statement(self, arch, **overrides):
        """One faithful SLSA statement for ``arch``, with targeted forgeries."""

        subject_name = overrides.pop(
            "subject_name",
            "pkg:docker/{}@{}?platform=linux%2F{}".format(
                self.IMAGE, self.TAG, arch
            ),
        )
        subject_digest = overrides.pop(
            "subject_digest", self.PLATFORM_HEX[arch]
        )
        builder_id = overrides.pop(
            "builder_id", self.SOURCE + "/actions/runs/12345/attempts/1"
        )
        vcs_source = overrides.pop("vcs_source", self.SOURCE)
        vcs_revision = overrides.pop("vcs_revision", self.REVISION)
        if overrides:
            raise AssertionError(
                "unknown statement overrides: %r" % sorted(overrides)
            )
        return {
            "_type": STATEMENT_TYPE,
            "subject": [
                {
                    "name": subject_name,
                    "digest": {"sha256": subject_digest},
                }
            ],
            "predicateType": PROVENANCE_PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": (
                        "https://github.com/moby/buildkit/blob/master/docs/"
                        "attestations/slsa-definitions.md"
                    )
                },
                "runDetails": {
                    "builder": {"id": builder_id},
                    "metadata": {
                        "buildkit_metadata": {
                            "vcs": {
                                "source": vcs_source,
                                "revision": vcs_revision,
                            }
                        }
                    },
                },
            },
        }

    def index_document(
        self, drop_attestation_for=None, duplicate_attestation_for=None
    ):
        manifests = []
        for arch in ("amd64", "arm64"):
            manifests.append(
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:" + self.PLATFORM_HEX[arch],
                    "platform": {"os": "linux", "architecture": arch},
                }
            )
        for arch in ("amd64", "arm64"):
            if arch == drop_attestation_for:
                continue
            entry = {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + self.ATTESTATION_HEX[arch],
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": (
                        "sha256:" + self.PLATFORM_HEX[arch]
                    ),
                },
            }
            manifests.append(entry)
            if arch == duplicate_attestation_for:
                manifests.append(dict(entry))
        return {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": manifests,
        }

    def attestation_document(self, arch, include_provenance_layer=True):
        layers = [
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": (
                    "sha256:"
                    + "9" * 63
                    + {"amd64": "0", "arm64": "1"}[arch]
                ),
                "size": 1,
                "annotations": {
                    "in-toto.io/predicate-type": "https://spdx.dev/Document"
                },
            }
        ]
        if include_provenance_layer:
            layers.append(
                {
                    "mediaType": "application/vnd.in-toto+json",
                    "digest": "sha256:" + self.LAYER_HEX[arch],
                    "size": 1,
                    "annotations": {
                        "in-toto.io/predicate-type": PROVENANCE_PREDICATE_TYPE
                    },
                }
            )
        return {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": layers,
        }

    def good_documents(self, statements=None):
        statements = statements or {}
        documents = {self.INDEX_HEX: self.index_document()}
        for arch in ("amd64", "arm64"):
            documents[self.ATTESTATION_HEX[arch]] = self.attestation_document(
                arch
            )
            documents[self.LAYER_HEX[arch]] = statements.get(
                arch, self.statement(arch)
            )
        return documents

    def run_verifier(self, documents):
        """Run the shipped function against a content-addressed stub tree."""

        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            stub_root = root / "content"
            stub_root.mkdir()
            for hex_digest, document in documents.items():
                payload = (
                    document
                    if isinstance(document, str)
                    else json.dumps(document)
                )
                (stub_root / (hex_digest + ".json")).write_text(
                    payload, encoding="utf-8"
                )
            stub_directory = root / "bin"
            stub_directory.mkdir()
            stub = stub_directory / "oras"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                'for argument in "$@"; do\n'
                '  case "${argument}" in\n'
                "    *@sha256:*)"
                ' exec cat -- "${PROMOTION_STUB_ROOT}/${argument##*@sha256:}.json"'
                " ;;\n"
                "  esac\n"
                "done\n"
                "exit 1\n",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = (
                str(stub_directory) + os.pathsep + environment.get("PATH", "")
            )
            environment["PROMOTION_STUB_ROOT"] = str(stub_root)
            prelude = (
                "set -Eeuo pipefail\n"
                "image=" + shlex.quote(self.IMAGE) + "\n"
                "reference="
                + shlex.quote(self.IMAGE + "@sha256:" + self.INDEX_HEX)
                + "\n"
                "release_tag=" + shlex.quote(self.TAG) + "\n"
                "expected_source=" + shlex.quote(self.SOURCE) + "\n"
                "release_revision=" + shlex.quote(self.REVISION) + "\n"
            )
            return subprocess.run(
                [
                    self.bash,
                    "-c",
                    prelude
                    + self.function_text
                    + "\nverify_embedded_provenance\n",
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

    def assert_denied(self, completed, message):
        self.assertEqual(completed.returncode, 1)
        self.assertIn(message, completed.stderr)

    def test_faithful_provenance_tree_is_allowed(self):
        completed = self.run_verifier(self.good_documents())
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )

    def test_missing_attestation_manifest_is_denied(self):
        documents = self.good_documents()
        documents[self.INDEX_HEX] = self.index_document(
            drop_attestation_for="arm64"
        )
        self.assert_denied(
            self.run_verifier(documents),
            "linux/arm64 attestation manifest is absent or not unique",
        )

    def test_duplicated_attestation_manifest_is_denied(self):
        documents = self.good_documents()
        documents[self.INDEX_HEX] = self.index_document(
            duplicate_attestation_for="amd64"
        )
        self.assert_denied(
            self.run_verifier(documents),
            "linux/amd64 attestation manifest is absent or not unique",
        )

    def test_wrong_source_repository_is_denied(self):
        """Neither VCS source nor builder identity may point elsewhere."""

        forgeries = (
            ("vcs_source", PLATFORM_REPOSITORY_LABEL),
            (
                "builder_id",
                PLATFORM_REPOSITORY_LABEL + "/actions/runs/1/attempts/1",
            ),
        )
        for field, forged_value in forgeries:
            with self.subTest(field=field):
                documents = self.good_documents(
                    statements={
                        "amd64": self.statement(
                            "amd64", **{field: forged_value}
                        )
                    }
                )
                self.assert_denied(
                    self.run_verifier(documents),
                    "linux/amd64 SLSA provenance statement does not match "
                    "the reviewed release identity",
                )

    def test_wrong_release_tag_is_denied(self):
        documents = self.good_documents(
            statements={
                "amd64": self.statement(
                    "amd64",
                    subject_name=(
                        "pkg:docker/{}@v0.0.1?platform=linux%2Famd64".format(
                            self.IMAGE
                        )
                    ),
                )
            }
        )
        self.assert_denied(
            self.run_verifier(documents),
            "linux/amd64 SLSA provenance statement does not match "
            "the reviewed release identity",
        )

    def test_wrong_subject_digest_is_denied(self):
        documents = self.good_documents(
            statements={
                "amd64": self.statement("amd64", subject_digest="9" * 64)
            }
        )
        self.assert_denied(
            self.run_verifier(documents),
            "linux/amd64 SLSA provenance statement does not match "
            "the reviewed release identity",
        )

    def test_wrong_release_revision_is_denied(self):
        documents = self.good_documents(
            statements={
                "arm64": self.statement("arm64", vcs_revision="b" * 40)
            }
        )
        self.assert_denied(
            self.run_verifier(documents),
            "linux/arm64 SLSA provenance statement does not match "
            "the reviewed release identity",
        )

    def test_missing_provenance_layer_is_denied(self):
        documents = self.good_documents()
        documents[self.ATTESTATION_HEX["amd64"]] = self.attestation_document(
            "amd64", include_provenance_layer=False
        )
        self.assert_denied(
            self.run_verifier(documents),
            "linux/amd64 SLSA provenance layer is absent or not unique",
        )

    def test_malformed_statement_is_denied(self):
        documents = self.good_documents(statements={"amd64": '{"not'})
        self.assert_denied(
            self.run_verifier(documents),
            "linux/amd64 SLSA provenance statement does not match "
            "the reviewed release identity",
        )


if __name__ == "__main__":
    unittest.main()
