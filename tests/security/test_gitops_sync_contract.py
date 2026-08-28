"""The digest-selected release-sync contract of ADR 0016, modelled end to end.

WHAT IS AND IS NOT PROVEN HERE
------------------------------

Proven: (1) the reviewed field values in ``kubernetes/websites/*/source.yaml``
and ``release.yaml`` are exactly the values these fixtures consume — each is
re-derived through the repository's own validators, so a manifest edit that
diverged from this model would fail the very first test below; and (2) the
release-sync contract those values describe refuses every hostile input
enumerated here, and refuses it for the stated reason.

NOT proven by this battery: that a running Flux controller behaves this way. No
source-controller, helm-controller, cosign, Helm, or Kubernetes API server
executes in this battery, and no signature is cryptographically verified —
``tests/security/testsupport`` is only a source-state model, and it says so.
This battery proves neither a completed #141/#189 transaction nor live Flux
state. The composed source tree already pins the two direct site
Kustomizations to ``prune: false`` with no aggregate or admission dependency;
live activation still requires the separately authorized transaction evidence.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from .support import load_script
from .testsupport.flux_sync import (
    ReleaseOutcome,
    RolloutOutcome,
    SourceOutcome,
    observe_rollout,
    reconcile_release,
    reconcile_source,
    remediate,
)
from .testsupport.kubernetes_api import (
    DEPLOYMENT,
    HELM_RELEASE,
    OCI_REPOSITORY,
    MockKubernetesApi,
)
from .testsupport.oci_registry import (
    ZERO_DIGEST,
    MockOciRegistry,
    PublishedChart,
    RegistryClient,
    SigningIdentity,
    synthetic_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SIGNATURE_MODULE = load_script("validate_signature_policy.py")
STATE_MODULE = load_script("validate_release_state.py")

SITES = ("naranjo-online", "lidersea-com")
REVIEWED_RELEASES = SIGNATURE_MODULE.CHART_RELEASES
PROMOTED_DIGEST = "sha256:" + ("a1" * 32)
NEXT_DIGEST = "sha256:" + ("b2" * 32)


def chart_repository_path(slug):
    """Return the registry path the committed chart source pulls."""

    return SIGNATURE_MODULE.CHART_REPOSITORIES[slug][len("oci://") :].split("/", 1)[1]


def publisher_identity(slug, *, tag, ref="refs/heads/main"):
    """Build the certificate identity that site's publisher would carry.

    ``ref`` defaults to the protected `main` branch, which is what the real
    publishers mint: each site's release contract accepts only a
    workflow_dispatch run selected from `main`, and that ref is the only one
    those repositories gate on creation and update with no bypass actors
    (ADR 0016 amendment 2026-08-22). ``tag`` names WHICH release version is
    being published and reaches the identity only when a caller asks for a
    hostile tag-ref signer via ``ref="refs/tags"``.
    """

    domain = SIGNATURE_MODULE.SIGNATURE_REPOSITORIES[slug]
    workflow = SIGNATURE_MODULE.SIGNATURE_CONTRACTS[slug]
    suffix = ref if ref == "refs/heads/main" else "{}/{}".format(ref, tag)
    return SigningIdentity(
        issuer="https://token.actions.githubusercontent.com",
        subject="https://github.com/snaraj/{}/.github/workflows/{}@{}".format(
            domain, workflow, suffix
        ),
    )


def source_spec(slug, *, suspend=False, digest=None):
    """Build the chart-source spec from the committed contract's own values."""

    if digest is None:
        digest = REVIEWED_RELEASES[slug]["digest"]
    return {
        "interval": "10m0s",
        "layerSelector": {
            "mediaType": SIGNATURE_MODULE.CHART_LAYER_MEDIA_TYPE,
            "operation": "copy",
        },
        "ref": {"digest": digest},
        "suspend": suspend,
        "timeout": "60s",
        "url": SIGNATURE_MODULE.CHART_REPOSITORIES[slug],
        "verify": {
            "matchOIDCIdentity": [
                {
                    "issuer": SIGNATURE_MODULE.CHART_OIDC_ISSUER_PATTERN,
                    "subject": SIGNATURE_MODULE.chart_source_certificate_subject(slug),
                }
            ],
            "provider": "cosign",
        },
    }


def release_spec(slug, *, suspend=True, values=None):
    """Build the release spec from the committed release contract's values.

    The verified chart is the sole workload-image identity carrier. Platform
    values contain exactly one readiness key; hostile tests pass an explicit
    alternate map so they exercise that closed boundary directly.
    """

    contract = STATE_MODULE.RELEASE_CONTRACTS[slug]
    if values is None:
        values = {"deploymentReady": True}
    return {
        "suspend": suspend,
        "interval": "10m0s",
        "releaseName": slug,
        "serviceAccountName": "helm-reconciler",
        "chartRef": {"kind": OCI_REPOSITORY, "name": contract["chart_ref"]},
        "values": values,
    }


def committed_release(slug):
    """Return the reviewed release state this repository currently commits.

    The validator is the source of truth for this exact values-only contract;
    a second platform image identity would create a conflicting authority.
    """

    state = STATE_MODULE.load_helm_release(slug, REPO_ROOT)
    if state.values != {("deploymentReady",): "true"}:
        raise AssertionError("committed HelmRelease is not exact values-only state")
    return {"suspend": state.suspended, "values": {"deploymentReady": True}}


class SyncContractHarness(unittest.TestCase):
    """Shared world: two sites, one registry, one API model."""

    slug = "naranjo-online"

    def setUp(self):
        self.registry = MockOciRegistry().start()
        self.addCleanup(self.registry.stop)
        self.client = RegistryClient(self.registry.base_url)
        self.api = MockKubernetesApi()
        self.namespace = self.slug
        self.source_name = STATE_MODULE.RELEASE_CONTRACTS[self.slug]["chart_ref"]
        self.apply_source()

    @property
    def floor_tag(self):
        return REVIEWED_RELEASES[self.slug]["tag"]

    @property
    def source_digest(self):
        return REVIEWED_RELEASES[self.slug]["digest"]

    def apply_source(self, **kwargs):
        return self.api.apply(
            OCI_REPOSITORY,
            "source.toolkit.fluxcd.io/v1",
            self.namespace,
            self.source_name,
            source_spec(self.slug, **kwargs),
        )

    def apply_release(self, **kwargs):
        return self.api.apply(
            HELM_RELEASE,
            "helm.toolkit.fluxcd.io/v2",
            self.namespace,
            self.slug,
            release_spec(self.slug, **kwargs),
        )

    def publish(
        self,
        version,
        *,
        signature="own",
        image_repository="own",
        image_digest=PROMOTED_DIGEST,
        digest=None,
    ):
        """Publish one chart version into this site's chart repository."""

        identities = {
            "own": publisher_identity(self.slug, tag=version),
            "sibling": publisher_identity(
                "lidersea-com" if self.slug == "naranjo-online" else "naranjo-online",
                tag=version,
            ),
            # Re-pointed 2026-08-22 with the identity itself (ADR 0016
            # amendment). This row is the ref-family refusal and it survives
            # the re-point by swapping sides: the trusted ref is now protected
            # `main`, so the signer source-controller must refuse is the right
            # workflow in the right repository run at a VERSION TAG — the ref
            # family whose creation those repositories do not restrict.
            "tag-ref": SigningIdentity(
                issuer="https://token.actions.githubusercontent.com",
                subject=(
                    "https://github.com/snaraj/naranjo.online/.github/workflows/"
                    "release-publisher.yml@refs/tags/" + version
                ),
            ),
            # Another branch head, so the refusal is proven against the
            # `refs/heads/*` family too and not only against a different ref
            # kind.
            "other-branch": SigningIdentity(
                issuer="https://token.actions.githubusercontent.com",
                subject=(
                    "https://github.com/snaraj/naranjo.online/.github/workflows/"
                    "release-publisher.yml@refs/heads/release"
                ),
            ),
            # Same repository, same trusted ref, different workflow file: the
            # refusal here is attributable to the workflow path alone.
            "other-workflow": SigningIdentity(
                issuer="https://token.actions.githubusercontent.com",
                subject=(
                    "https://github.com/snaraj/naranjo.online/.github/workflows/"
                    "nightly.yml@refs/heads/main"
                ),
            ),
            "other-issuer": SigningIdentity(
                issuer="https://accounts.example.invalid",
                subject=publisher_identity(self.slug, tag=version).subject,
            ),
            None: None,
        }
        if image_repository == "own":
            image_repository = "ghcr.io/snaraj/{}".format(self.slug)
        return self.registry.publish(
            chart_repository_path(self.slug),
            PublishedChart(
                version=version,
                digest=digest or self.source_digest,
                image_repository=image_repository,
                image_digest=image_digest,
                signature=identities[signature],
            ),
        )

    def sync_source(self):
        return reconcile_source(
            self.api, self.client, self.namespace, self.source_name
        )

    def sync_release(self):
        return reconcile_release(self.api, self.client, self.namespace, self.slug)

    def source(self):
        return self.api.get(OCI_REPOSITORY, self.namespace, self.source_name)


class ManifestBindingTests(unittest.TestCase):
    """The model consumes the committed values, not a parallel universe."""

    def test_every_fixture_value_is_derived_from_the_committed_manifests(self):
        for slug in SITES:
            with self.subTest(slug=slug):
                committed = REPO_ROOT.joinpath(
                    "kubernetes", "websites", slug, "source.yaml"
                ).read_text(encoding="utf-8")
                # This equality is the whole chain: the exact-body validator
                # already proves the committed file equals the rendered
                # contract, and every fixture below is built from the same
                # constants that render it.
                self.assertEqual(
                    SIGNATURE_MODULE.chart_source_errors(committed, slug), []
                )
                spec = source_spec(slug)
                self.assertIn(
                    "digest: {}".format(spec["ref"]["digest"]), committed
                )
                self.assertIn(
                    'platform.snaraj.dev/chart-release: "{}"'.format(
                        REVIEWED_RELEASES[slug]["tag"]
                    ),
                    committed,
                )
                self.assertIn("url: {}".format(spec["url"]), committed)
                self.assertIn(
                    "subject: {}".format(
                        spec["verify"]["matchOIDCIdentity"][0]["subject"]
                    ),
                    committed,
                )
                self.assertIn(
                    "issuer: {}".format(
                        spec["verify"]["matchOIDCIdentity"][0]["issuer"]
                    ),
                    committed,
                )

    def test_release_fixtures_match_the_committed_release_state(self):
        """Bind the model to exact active values-only committed state."""

        for slug in SITES:
            with self.subTest(slug=slug):
                state = STATE_MODULE.load_helm_release(slug, REPO_ROOT)
                committed = committed_release(slug)
                fixture = release_spec(slug, **committed)

                self.assertEqual(
                    fixture["chartRef"],
                    {"kind": OCI_REPOSITORY, "name": slug + "-chart"},
                )
                self.assertFalse(state.suspended)
                self.assertIs(fixture["suspend"], False)
                self.assertEqual(
                    state.values,
                    {("deploymentReady",): "true"},
                )
                self.assertEqual(fixture["values"], {"deploymentReady": True})
                committed_text = REPO_ROOT.joinpath(
                    "kubernetes", "websites", slug, "release.yaml"
                ).read_text(encoding="utf-8")
                self.assertNotIn("image:", committed_text)
                self.assertNotIn("repository:", committed_text)
                self.assertNotIn("digest:", committed_text)

    def test_the_two_site_tuples_never_share_a_value(self):
        for attribute in ("CHART_REPOSITORIES",):
            values = {
                slug: getattr(SIGNATURE_MODULE, attribute)[slug] for slug in SITES
            }
            self.assertEqual(len(set(values.values())), len(SITES), attribute)
        subjects = {
            slug: SIGNATURE_MODULE.chart_source_certificate_subject(slug)
            for slug in SITES
        }
        self.assertEqual(len(set(subjects.values())), len(SITES))
        chart_refs = {
            slug: STATE_MODULE.RELEASE_CONTRACTS[slug]["chart_ref"] for slug in SITES
        }
        self.assertEqual(len(set(chart_refs.values())), len(SITES))


class DigestSelectionTests(unittest.TestCase):
    """The reviewed audit label can never replace the immutable selector."""

    def test_each_release_pair_is_canonical_nonzero_and_site_distinct(self):
        digests = set()
        for slug in SITES:
            with self.subTest(slug=slug):
                tag, digest = SIGNATURE_MODULE.chart_source_release(slug)
                self.assertRegex(tag, r"\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
                self.assertRegex(digest, r"\Asha256:[0-9a-f]{64}\Z")
                self.assertNotEqual(digest, ZERO_DIGEST)
                digests.add(digest)
        self.assertEqual(len(digests), len(SITES))


class ChartSourceSyncTests(SyncContractHarness):
    """The verification decision, and every way it must refuse."""

    def assert_no_tag_list_request(self):
        self.assertFalse(
            any(path.endswith("/tags/list") for path in self.client.requests),
            self.client.requests,
        )

    def test_the_signed_exact_digest_becomes_the_resolved_artifact(self):
        published = self.publish(self.floor_tag)
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.ARTIFACT_UPDATED)
        self.assertEqual(result.version, self.floor_tag)
        self.assertEqual(result.digest, published.digest)
        self.assertEqual(result.revision, published.digest)
        source = self.source()
        self.assertTrue(source.is_ready())
        self.assertEqual(source.status["artifact"]["revision"], published.digest)
        self.assertNotEqual(source.status["artifact"]["digest"], published.digest)
        self.assertEqual(
            source.status["observedGeneration"], source.metadata.generation
        )
        self.assert_no_tag_list_request()

    def test_moving_the_human_tag_cannot_change_a_digest_selected_artifact(self):
        original = self.publish(self.floor_tag)
        self.sync_source()
        replacement = self.publish(
            self.floor_tag,
            digest=synthetic_digest("moved-human-tag"),
            image_digest=NEXT_DIGEST,
        )
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.ARTIFACT_UNCHANGED)
        self.assertNotEqual(replacement.digest, original.digest)
        self.assertEqual(self.source().status["artifact"]["revision"], original.digest)
        self.assert_no_tag_list_request()

    def test_deleting_the_human_tag_cannot_change_a_digest_selected_artifact(self):
        original = self.publish(self.floor_tag)
        self.sync_source()
        self.registry.remove(chart_repository_path(self.slug), self.floor_tag)
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.ARTIFACT_UNCHANGED)
        self.assertEqual(self.source().status["artifact"]["revision"], original.digest)
        self.assert_no_tag_list_request()

    def test_only_an_older_tag_never_replaces_or_resolves_the_pinned_digest(self):
        older = self.publish(
            "0.1.1",
            digest=synthetic_digest("older-only-chart"),
            image_digest=NEXT_DIGEST,
        )
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.ARTIFACT_UNAVAILABLE)
        self.assertNotEqual(older.digest, self.source_digest)
        self.assertNotIn("artifact", self.source().status)
        self.assert_no_tag_list_request()

    def test_an_unsigned_chart_never_becomes_an_artifact(self):
        self.publish(self.floor_tag, signature=None)
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.VERIFICATION_FAILED)
        source = self.source()
        self.assertFalse(source.is_ready())
        self.assertNotIn("artifact", source.status)

    def test_a_chart_signed_by_the_wrong_authority_is_refused(self):
        for label in (
            "sibling",
            "tag-ref",
            "other-branch",
            "other-workflow",
            "other-issuer",
        ):
            with self.subTest(signature=label):
                self.setUp()
                self.publish(self.floor_tag, signature=label)
                self.assertEqual(
                    self.sync_source().outcome, SourceOutcome.VERIFICATION_FAILED
                )
                self.assertNotIn("artifact", self.source().status)

    def test_cross_site_tuple_substitution_is_refused_in_both_directions(self):
        """Neither site's source may accept the other's publisher or path."""

        for slug in SITES:
            with self.subTest(slug=slug):
                self.slug = slug
                self.setUp()
                floor_tag = REVIEWED_RELEASES[slug]["tag"]
                self.publish(floor_tag, signature="sibling")
                result = self.sync_source()
                self.assertEqual(result.outcome, SourceOutcome.VERIFICATION_FAILED)
                self.assertNotIn("artifact", self.source().status)
        self.slug = "naranjo-online"

    def test_a_verification_failure_never_removes_the_running_artifact(self):
        self.publish(self.floor_tag)
        self.sync_source()
        running = self.source().status["artifact"]
        unsigned = self.publish(
            "0.2.0",
            digest=synthetic_digest("unsigned-next-chart"),
            signature=None,
        )
        self.apply_source(digest=unsigned.digest)
        self.assertEqual(self.sync_source().outcome, SourceOutcome.VERIFICATION_FAILED)
        self.assertEqual(self.source().status["artifact"], running)

    def test_an_unavailable_pinned_digest_leaves_the_source_unready(self):
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.ARTIFACT_UNAVAILABLE)
        self.assertFalse(self.source().is_ready())
        self.assertNotIn("artifact", self.source().status)

    def test_a_suspended_source_performs_no_registry_read_at_all(self):
        self.apply_source(suspend=True)
        self.publish(self.floor_tag)
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.SUSPENDED)
        self.assertEqual(self.client.requests, [])
        self.assertEqual(self.source().status, {})

    def test_every_mutable_or_ambiguous_selector_shape_fails_before_registry_io(self):
        for ref in (
            {},
            {"tag": self.floor_tag},
            {"semver": ">=0.1.0 <1.0.0"},
            {"digest": ZERO_DIGEST},
            {"digest": "sha256:not-a-digest"},
            {"digest": self.source_digest, "tag": self.floor_tag},
            {"digest": self.source_digest, "semver": ">=0.1.0 <1.0.0"},
        ):
            with self.subTest(ref=ref):
                spec = source_spec(self.slug)
                spec["ref"] = ref
                self.api.apply(
                    OCI_REPOSITORY,
                    "source.toolkit.fluxcd.io/v1",
                    self.namespace,
                    self.source_name,
                    spec,
                )
                self.assertEqual(
                    self.sync_source().outcome,
                    SourceOutcome.DIGEST_INVALID,
                )
                self.assertFalse(self.source().is_ready())
                self.assertEqual(self.client.requests, [])


class ReleaseUpgradeTests(SyncContractHarness):
    """From a verified artifact to a digest-bound workload, or not at all."""

    def setUp(self):
        super().setUp()
        self.publish(self.floor_tag, image_digest=PROMOTED_DIGEST)
        self.assertEqual(self.sync_source().outcome, SourceOutcome.ARTIFACT_UPDATED)

    def test_a_suspended_copy_of_the_committed_release_takes_no_action(self):
        """Suspension still dominates the configured release identity.

        Driven by the values this repository actually commits rather than by
        the fail-closed defaults. That distinction is the point: while the
        sites were at the all-zeros sentinel this proved only that a release
        the sentinel would already refuse stays inert. The committed site is
        now active, so this test explicitly freezes a copy and proves the
        rollback gate still leaves no trace of considering a rollout.
        """

        committed = committed_release(self.slug)
        self.assertFalse(committed["suspend"])
        self.apply_release(**{**committed, "suspend": True})
        result = self.sync_release()
        self.assertEqual(result.outcome, ReleaseOutcome.SUSPENDED)
        release = self.api.get(HELM_RELEASE, self.namespace, self.slug)
        self.assertEqual(release.status, {})
        self.assertIsNone(self.api.find(DEPLOYMENT, self.namespace, self.slug))

    def test_the_committed_active_release_uses_only_the_verified_chart_identity(self):
        """The chart carries the workload identity; platform values do not."""

        committed = committed_release(self.slug)
        self.assertFalse(committed["suspend"])
        self.assertEqual(committed["values"], {"deploymentReady": True})
        self.apply_release(**committed)
        result = self.sync_release()
        self.assertEqual(result.outcome, ReleaseOutcome.UPGRADED)
        self.assertEqual(
            self.api.get(DEPLOYMENT, self.namespace, self.slug).spec["image"],
            "ghcr.io/snaraj/{}@{}".format(self.slug, PROMOTED_DIGEST),
        )

    def test_platform_values_must_be_exact_readiness_only(self):
        for values in (
            None,
            {},
            {"deploymentReady": False},
            {"deploymentReady": "true"},
            {"deploymentReady": True, "other": True},
            {
                "deploymentReady": True,
                "image": {
                    "repository": "ghcr.io/snaraj/naranjo-online",
                    "digest": PROMOTED_DIGEST,
                },
            },
        ):
            with self.subTest(values=values):
                spec = release_spec(self.slug, suspend=False)
                spec["values"] = values
                self.api.apply(
                    HELM_RELEASE,
                    "helm.toolkit.fluxcd.io/v2",
                    self.namespace,
                    self.slug,
                    spec,
                )
                self.assertEqual(
                    self.sync_release().outcome,
                    ReleaseOutcome.VALUES_REFUSED,
                )
                self.assertIsNone(
                    self.api.find(DEPLOYMENT, self.namespace, self.slug)
                )

    def test_verified_chart_deploys_its_exact_workload_identity(self):
        self.apply_release(suspend=False)
        result = self.sync_release()
        self.assertEqual(result.outcome, ReleaseOutcome.UPGRADED)
        self.assertEqual(result.version, self.floor_tag)
        deployment = self.api.get(DEPLOYMENT, self.namespace, self.slug)
        self.assertEqual(
            deployment.spec["image"],
            "ghcr.io/snaraj/naranjo-online@" + PROMOTED_DIGEST,
        )
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.UNCHANGED)

    def test_malformed_or_cross_site_chart_workload_identity_is_refused(self):
        for repository, digest in (
            (None, PROMOTED_DIGEST),
            ("ghcr.io/snaraj/naranjo-online", None),
            ("ghcr.io/snaraj/naranjo-online", ZERO_DIGEST),
            ("ghcr.io/snaraj/naranjo-online", "sha256:not-a-digest"),
            ("ghcr.io/snaraj/lidersea-com", PROMOTED_DIGEST),
            ("registry.example.invalid/naranjo-online", PROMOTED_DIGEST),
        ):
            with self.subTest(repository=repository, digest=digest):
                self.setUp()
                candidate = self.publish(
                    "0.2.0",
                    digest=synthetic_digest(
                        "invalid-chart-identity:{}:{}".format(repository, digest)
                    ),
                    image_repository=repository,
                    image_digest=digest,
                )
                self.apply_source(digest=candidate.digest)
                self.sync_source()
                self.apply_release(suspend=False)
                self.assertEqual(
                    self.sync_release().outcome,
                    ReleaseOutcome.CHART_IDENTITY_REFUSED,
                )
                self.assertIsNone(
                    self.api.find(DEPLOYMENT, self.namespace, self.slug)
                )

    def test_an_unverified_source_cannot_be_upgraded_from(self):
        self.api.patch_status(
            OCI_REPOSITORY,
            self.namespace,
            self.source_name,
            {"conditions": [{"type": "Ready", "status": "False", "reason": "x"}]},
        )
        self.apply_release(suspend=False)
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.SOURCE_NOT_READY)
        self.assertIsNone(self.api.find(DEPLOYMENT, self.namespace, self.slug))

    def test_a_release_pointed_at_a_missing_source_refuses(self):
        self.api.delete(OCI_REPOSITORY, self.namespace, self.source_name)
        self.apply_release(suspend=False)
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.SOURCE_NOT_READY)

    def test_a_cross_namespace_chart_reference_is_refused(self):
        spec = release_spec(self.slug, suspend=False)
        spec["chartRef"]["namespace"] = "lidersea-com"
        self.api.apply(
            HELM_RELEASE, "helm.toolkit.fluxcd.io/v2", self.namespace, self.slug, spec
        )
        self.assertEqual(
            self.sync_release().outcome, ReleaseOutcome.CROSS_NAMESPACE_REFUSED
        )

    def test_a_non_oci_chart_reference_is_refused(self):
        for chart_ref in ({"kind": "HelmChart", "name": "x"}, {"kind": OCI_REPOSITORY}, {}):
            with self.subTest(chart_ref=chart_ref):
                spec = release_spec(self.slug, suspend=False)
                spec["chartRef"] = dict(chart_ref)
                self.api.apply(
                    HELM_RELEASE,
                    "helm.toolkit.fluxcd.io/v2",
                    self.namespace,
                    self.slug,
                    spec,
                )
                self.assertEqual(
                    self.sync_release().outcome, ReleaseOutcome.CHART_REF_INVALID
                )


class RolloutAndRollbackTests(SyncContractHarness):
    """Health after the upgrade, and the way back when there is none."""

    def setUp(self):
        super().setUp()
        self.publish(self.floor_tag, image_digest=PROMOTED_DIGEST)
        self.sync_source()
        self.apply_release(suspend=False)
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.UPGRADED)

    def test_a_healthy_rollout_is_recorded_against_its_own_generation(self):
        self.assertEqual(
            observe_rollout(self.api, self.namespace, self.slug, healthy=True),
            RolloutOutcome.HEALTHY,
        )
        deployment = self.api.get(DEPLOYMENT, self.namespace, self.slug)
        self.assertTrue(deployment.is_ready())
        self.assertEqual(
            deployment.status["observedGeneration"], deployment.metadata.generation
        )

    def test_a_failed_first_rollout_has_nothing_to_roll_back_to(self):
        self.assertEqual(
            observe_rollout(self.api, self.namespace, self.slug, healthy=False),
            RolloutOutcome.FAILED,
        )
        self.assertEqual(
            remediate(self.api, self.namespace, self.slug),
            RolloutOutcome.NO_PREVIOUS_RELEASE,
        )

    def test_a_failed_upgrade_returns_to_the_previous_digest(self):
        observe_rollout(self.api, self.namespace, self.slug, healthy=True)
        newer = self.publish(
            "0.2.0",
            digest=synthetic_digest("next-chart"),
            image_digest=NEXT_DIGEST,
        )
        self.apply_source(digest=newer.digest)
        self.assertEqual(self.sync_source().outcome, SourceOutcome.ARTIFACT_UPDATED)
        self.apply_release(suspend=False)
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.UPGRADED)
        self.assertEqual(
            observe_rollout(self.api, self.namespace, self.slug, healthy=False),
            RolloutOutcome.FAILED,
        )

        self.assertEqual(
            remediate(self.api, self.namespace, self.slug),
            RolloutOutcome.ROLLED_BACK,
        )
        deployment = self.api.get(DEPLOYMENT, self.namespace, self.slug)
        self.assertEqual(
            deployment.spec["image"],
            "ghcr.io/snaraj/naranjo-online@" + PROMOTED_DIGEST,
        )
        history = self.api.get(HELM_RELEASE, self.namespace, self.slug).status["history"]
        self.assertEqual(
            history[0]["chartVersion"],
            self.floor_tag + "+" + self.source_digest[7:19],
        )
        self.assertEqual(
            history[1]["chartVersion"], "0.2.0+" + newer.digest[7:19]
        )
        self.assertEqual(history[1]["status"], "failed")
        self.assertIsNotNone(newer)

    def test_rollback_replays_recorded_history_not_a_re_resolved_tag(self):
        """A rollback the registry could steer would not be a rollback."""

        observe_rollout(self.api, self.namespace, self.slug, healthy=True)
        newer = self.publish(
            "0.2.0",
            digest=synthetic_digest("next-chart-for-rollback"),
            image_digest=NEXT_DIGEST,
        )
        self.apply_source(digest=newer.digest)
        self.sync_source()
        self.apply_release(suspend=False)
        self.sync_release()
        observe_rollout(self.api, self.namespace, self.slug, healthy=False)
        # The registry is rewritten under us before remediation runs.
        self.registry.remove(chart_repository_path(self.slug), self.floor_tag)
        self.registry.publish(
            chart_repository_path(self.slug),
            PublishedChart(
                version="0.3.0",
                digest=synthetic_digest("hostile"),
                image_repository="ghcr.io/snaraj/naranjo-online",
                image_digest="sha256:" + ("c3" * 32),
                signature=publisher_identity(self.slug, tag="0.3.0"),
            ),
        )
        self.assertEqual(
            remediate(self.api, self.namespace, self.slug),
            RolloutOutcome.ROLLED_BACK,
        )
        self.assertEqual(
            self.api.get(DEPLOYMENT, self.namespace, self.slug).spec["image"],
            "ghcr.io/snaraj/naranjo-online@" + PROMOTED_DIGEST,
        )


if __name__ == "__main__":
    unittest.main()
