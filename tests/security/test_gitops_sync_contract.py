"""The tag-driven release-sync contract of ADR 0016, modelled end to end.

WHAT IS AND IS NOT PROVEN HERE
------------------------------

Proven: (1) the reviewed field values in ``kubernetes/websites/*/source.yaml``
and ``release.yaml`` are exactly the values these fixtures consume — each is
re-derived through the repository's own validators, so a manifest edit that
diverged from this model would fail the very first test below; and (2) the
release-sync contract those values describe refuses every hostile input
enumerated here, and refuses it for the stated reason.

NOT proven: that a running Flux controller behaves this way. No
source-controller, helm-controller, cosign, Helm, or Kubernetes API server
executes in this battery, and no signature is cryptographically verified —
``tests/security/testsupport`` is a model, and it says so. Flux is not installed on the
cluster; installing it is platform-lane work gated on the platform-stable
signal (ADR 0016, transition step 2). Reading any test name here as evidence
about live behavior would be reading it wrong.
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
    parse_range,
    parse_tag,
    reconcile_release,
    reconcile_source,
    remediate,
    resolve_range,
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
PROMOTED_DIGEST = "sha256:" + ("a1" * 32)
NEXT_DIGEST = "sha256:" + ("b2" * 32)


def chart_repository_path(slug):
    """Return the registry path the committed chart source pulls."""

    return SIGNATURE_MODULE.CHART_REPOSITORIES[slug][len("oci://") :].split("/", 1)[1]


def publisher_identity(slug, *, tag="v0.1.9", ref="refs/tags"):
    """Build the certificate identity that site's publisher would carry."""

    domain = SIGNATURE_MODULE.SIGNATURE_REPOSITORIES[slug]
    workflow = SIGNATURE_MODULE.SIGNATURE_CONTRACTS[slug]
    return SigningIdentity(
        issuer="https://token.actions.githubusercontent.com",
        subject="https://github.com/snaraj/{}/.github/workflows/{}@{}/{}".format(
            domain, workflow, ref, tag
        ),
    )


def source_spec(slug, *, suspend=False):
    """Build the chart-source spec from the committed contract's own values."""

    return {
        "interval": "10m0s",
        "layerSelector": {
            "mediaType": SIGNATURE_MODULE.CHART_LAYER_MEDIA_TYPE,
            "operation": "copy",
        },
        "ref": {"semver": SIGNATURE_MODULE.CHART_SEMVER_RANGES[slug]},
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


def release_spec(slug, *, suspend=True, ready=False, digest=ZERO_DIGEST):
    """Build the release spec from the committed release contract's values.

    The defaults are the fail-closed baseline — suspended, readiness shut, the
    all-zeros digest — because that is the state a release must be refused
    from, not because it is the state currently committed. Tests that mean
    "the release this repository actually commits" pass ``committed_release``
    explicitly; everything else names the hostile state it is exercising.
    """

    contract = STATE_MODULE.RELEASE_CONTRACTS[slug]
    return {
        "suspend": suspend,
        "interval": "10m0s",
        "releaseName": slug,
        "serviceAccountName": "helm-reconciler",
        "chartRef": {"kind": OCI_REPOSITORY, "name": contract["chart_ref"]},
        "values": {
            "deploymentReady": ready,
            "image": {"repository": contract["repository"], "digest": digest},
        },
    }


def committed_release(slug):
    """Return the reviewed release state this repository currently commits.

    The committed phase is deliberately NOT a constant here. A promotion is a
    two-scalar edit to ``release.yaml`` — ``deploymentReady`` and
    ``image.digest`` — and it touches nothing else in this repository, so a
    battery that restated either scalar would pin one moment of the release
    arc and go red on the next reviewed promotion for no safety reason. The
    values are therefore read back through the release-state validator, which
    is itself the gate that refuses any non-canonical or incoherent pair, and
    the invariants that make those scalars safe are asserted directly in
    ``ManifestBindingTests`` below rather than encoded as a literal.
    """

    state = STATE_MODULE.load_helm_release(slug, REPO_ROOT)
    return {
        "suspend": state.suspended,
        "ready": state.values[("deploymentReady",)] == "true",
        "digest": str(state.values[("image", "digest")]),
    }


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

    def publish(self, version, *, signature="own", image_digest=None, digest=None):
        """Publish one chart version into this site's chart repository."""

        identities = {
            "own": publisher_identity(self.slug, tag=version),
            "sibling": publisher_identity("lidersea-com", tag=version),
            "branch": SigningIdentity(
                issuer="https://token.actions.githubusercontent.com",
                subject=(
                    "https://github.com/snaraj/naranjo.online/.github/workflows/"
                    "release-publisher.yml@refs/heads/main"
                ),
            ),
            "other-workflow": SigningIdentity(
                issuer="https://token.actions.githubusercontent.com",
                subject=(
                    "https://github.com/snaraj/naranjo.online/.github/workflows/"
                    "nightly.yml@refs/tags/" + version
                ),
            ),
            "other-issuer": SigningIdentity(
                issuer="https://accounts.example.invalid",
                subject=publisher_identity(self.slug, tag=version).subject,
            ),
            None: None,
        }
        return self.registry.publish(
            chart_repository_path(self.slug),
            PublishedChart(
                version=version,
                digest=digest or synthetic_digest(self.slug + version),
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
                    'semver: "{}"'.format(spec["ref"]["semver"]), committed
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
        """Bind the model to the committed release in every reviewed phase.

        This assertion used to compare the fixture against the all-zeros
        sentinel as a literal, which pinned ONE phase of the release arc
        rather than the property that makes the sentinel safe — so a reviewed
        promotion (a two-scalar edit that this repository sanctions and gates
        elsewhere) turned it red for no safety reason. The binding is now
        re-derived and the safety property is asserted directly, which holds
        in `initial` and `promoted` alike and denies strictly more:

        * readiness is open IF AND ONLY IF the digest is not the all-zeros
          sentinel — so an unverified digest can never carry an open gate,
          and a reviewed digest can never hide behind a shut one;
        * the digest obeys the canonical content-address grammar;
        * ``site_phase`` classifies the tree into the closed reviewed set,
          which additionally requires BOTH reconciliation layers suspended
          and refuses every mixed state outright;
        * the identity half of the fixture — the image repository and the
          chart reference — still comes from the closed release contract and
          is compared against the committed file, so neither side can be
          re-pointed without the other.
        """

        for slug in SITES:
            with self.subTest(slug=slug):
                state = STATE_MODULE.load_helm_release(slug, REPO_ROOT)
                committed = committed_release(slug)
                fixture = release_spec(slug, **committed)

                # Identity: the left side is the closed release contract, the
                # right side is the parsed committed manifest, and the chart
                # reference is compared against a literal rather than against
                # the constant that produced it.
                self.assertEqual(
                    fixture["values"]["image"]["repository"],
                    state.values[("image", "repository")],
                )
                self.assertEqual(
                    fixture["chartRef"],
                    {"kind": OCI_REPOSITORY, "name": slug + "-chart"},
                )

                # Suspension: ADR 0016 step 3 is a separate reviewed event.
                self.assertTrue(
                    state.suspended,
                    "committed release must still be suspended (ADR 0016 step 3)",
                )
                self.assertIs(fixture["suspend"], True)

                # The sentinel's safety property, as the biconditional it has
                # always been rather than as one of its two sides.
                digest = str(state.values[("image", "digest")])
                self.assertRegex(digest, r"\Asha256:[0-9a-f]{64}\Z")
                self.assertEqual(
                    state.values[("deploymentReady",)] == "true",
                    digest != ZERO_DIGEST,
                    "readiness and digest must never disagree about deployability",
                )
                self.assertIn(
                    STATE_MODULE.site_phase(slug, REPO_ROOT),
                    ("initial", "promoted"),
                )

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


class SemverResolutionTests(unittest.TestCase):
    """Range grammar and selection, isolated from the rest of the machine."""

    def test_committed_ranges_parse_and_are_non_empty(self):
        for slug in SITES:
            with self.subTest(slug=slug):
                bounds = parse_range(SIGNATURE_MODULE.CHART_SEMVER_RANGES[slug])
                self.assertIsNotNone(bounds)
                floor, ceiling = bounds
                self.assertLess(floor, ceiling)
                self.assertEqual(ceiling, (1, 0, 0))

    def test_ungrammatical_ranges_have_no_parse(self):
        for candidate in (
            ">=0.1.9",
            "^0.1.9",
            "~0.1.9",
            ">=0.1.9 <1.0.1",
            ">=0.1.9 || >=2.0.0 <3.0.0",
            "*",
            "",
            None,
            0,
        ):
            with self.subTest(candidate=candidate):
                self.assertIsNone(parse_range(candidate))

    def test_only_stable_release_tags_are_candidates(self):
        for candidate in (
            "latest",
            "main",
            "v0.1.9-rc1",
            "v0.1.9+build",
            "0.1.9",
            "sha-" + ("a" * 40),
            "sha256-" + ("a" * 64) + ".sig",
            "v01.1.9",
        ):
            with self.subTest(candidate=candidate):
                self.assertIsNone(parse_tag(candidate))
                self.assertIsNone(resolve_range([candidate], ">=0.0.0 <1.0.0"))

    def test_selection_picks_the_newest_version_inside_the_range(self):
        tags = ["v0.1.8", "v0.1.9", "v0.1.10", "v0.2.0", "v1.0.0", "latest"]
        self.assertEqual(resolve_range(tags, ">=0.1.9 <1.0.0"), "v0.2.0")
        self.assertEqual(resolve_range(["v0.1.9", "v0.1.10"], ">=0.1.9 <1.0.0"), "v0.1.10")
        # Below the floor and at/above the ceiling are both outside the window.
        self.assertIsNone(resolve_range(["v0.1.8"], ">=0.1.9 <1.0.0"))
        self.assertIsNone(resolve_range(["v1.0.0", "v2.3.4"], ">=0.1.9 <1.0.0"))


class ChartSourceSyncTests(SyncContractHarness):
    """The verification decision, and every way it must refuse."""

    def test_a_signed_in_range_release_becomes_the_resolved_artifact(self):
        published = self.publish("v0.1.9")
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.ARTIFACT_UPDATED)
        self.assertEqual(result.version, "v0.1.9")
        self.assertEqual(result.digest, published.digest)
        self.assertEqual(result.revision, "v0.1.9@" + published.digest)
        source = self.source()
        self.assertTrue(source.is_ready())
        self.assertEqual(source.status["artifact"]["digest"], published.digest)
        self.assertEqual(
            source.status["observedGeneration"], source.metadata.generation
        )

    def test_publishing_a_newer_release_moves_the_artifact_forward(self):
        self.publish("v0.1.9")
        self.sync_source()
        self.assertEqual(self.sync_source().outcome, SourceOutcome.ARTIFACT_UNCHANGED)
        newer = self.publish("v0.2.0")
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.ARTIFACT_UPDATED)
        self.assertEqual(result.digest, newer.digest)

    def test_an_unsigned_chart_never_becomes_an_artifact(self):
        self.publish("v0.1.9", signature=None)
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.VERIFICATION_FAILED)
        source = self.source()
        self.assertFalse(source.is_ready())
        self.assertNotIn("artifact", source.status)

    def test_a_chart_signed_by_the_wrong_authority_is_refused(self):
        for label in ("sibling", "branch", "other-workflow", "other-issuer"):
            with self.subTest(signature=label):
                self.setUp()
                self.publish("v0.1.9", signature=label)
                self.assertEqual(
                    self.sync_source().outcome, SourceOutcome.VERIFICATION_FAILED
                )
                self.assertNotIn("artifact", self.source().status)

    def test_cross_site_tuple_substitution_is_refused_in_both_directions(self):
        """Neither site's source may accept the other's publisher or path."""

        for slug, other in (("naranjo-online", "lidersea-com"), ("lidersea-com", "naranjo-online")):
            with self.subTest(slug=slug):
                self.slug = slug
                self.setUp()
                self.publish("v0.1.9", signature="own")
                self.assertEqual(
                    self.sync_source().outcome, SourceOutcome.ARTIFACT_UPDATED
                )
                # Now substitute the other site's publisher identity into the
                # SAME repository path and publish a newer version.
                self.registry.publish(
                    chart_repository_path(slug),
                    PublishedChart(
                        version="v0.2.0",
                        digest=synthetic_digest(slug + "v0.2.0"),
                        signature=publisher_identity(other, tag="v0.2.0"),
                    ),
                )
                result = self.sync_source()
                self.assertEqual(result.outcome, SourceOutcome.VERIFICATION_FAILED)
                # The verified release that was already running is untouched.
                self.assertEqual(
                    self.source().status["artifact"]["version"], "v0.1.9"
                )
        self.slug = "naranjo-online"

    def test_a_verification_failure_never_removes_the_running_artifact(self):
        self.publish("v0.1.9")
        self.sync_source()
        running = self.source().status["artifact"]
        self.publish("v0.2.0", signature=None)
        self.assertEqual(self.sync_source().outcome, SourceOutcome.VERIFICATION_FAILED)
        self.assertEqual(self.source().status["artifact"], running)

    def test_no_release_inside_the_range_leaves_the_source_unready(self):
        self.publish("v0.1.8")
        self.publish("v1.4.0")
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.NO_MATCHING_VERSION)
        self.assertFalse(self.source().is_ready())
        self.assertNotIn("artifact", self.source().status)

    def test_a_version_above_the_graduation_ceiling_is_never_selected(self):
        """The SemVer ceiling IS the ADR 0014 production-graduation gate."""

        self.publish("v0.1.9")
        self.sync_source()
        self.publish("v1.0.0")
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.ARTIFACT_UNCHANGED)
        self.assertEqual(self.source().status["artifact"]["version"], "v0.1.9")

    def test_a_downgrade_outside_the_range_cannot_pull_the_site_backwards(self):
        self.publish("v0.2.0")
        self.sync_source()
        # The newer release is withdrawn from the registry; only an
        # out-of-range-older one remains.
        self.registry.remove(chart_repository_path(self.slug), "v0.2.0")
        self.publish("v0.1.8")
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.NO_MATCHING_VERSION)
        self.assertEqual(self.source().status["artifact"]["version"], "v0.2.0")

    def test_a_downgrade_inside_the_range_is_refused_as_a_downgrade(self):
        self.publish("v0.2.0")
        self.sync_source()
        self.registry.remove(chart_repository_path(self.slug), "v0.2.0")
        self.publish("v0.1.9")
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.DOWNGRADE_REFUSED)
        self.assertEqual(self.source().status["artifact"]["version"], "v0.2.0")

    def test_reassigning_a_published_version_to_new_content_is_refused(self):
        original = self.publish("v0.1.9")
        self.sync_source()
        self.publish("v0.1.9", digest=synthetic_digest("reassigned"))
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.TAG_REUSE_REFUSED)
        self.assertEqual(self.source().status["artifact"]["digest"], original.digest)

    def test_a_suspended_source_performs_no_registry_read_at_all(self):
        self.apply_source(suspend=True)
        self.publish("v0.1.9")
        result = self.sync_source()
        self.assertEqual(result.outcome, SourceOutcome.SUSPENDED)
        self.assertEqual(self.client.requests, [])
        self.assertEqual(self.source().status, {})

    def test_an_ungrammatical_range_resolves_nothing(self):
        spec = source_spec(self.slug)
        spec["ref"] = {"semver": "*"}
        self.api.apply(
            OCI_REPOSITORY,
            "source.toolkit.fluxcd.io/v1",
            self.namespace,
            self.source_name,
            spec,
        )
        self.publish("v0.1.9")
        self.assertEqual(self.sync_source().outcome, SourceOutcome.RANGE_UNGRAMMATICAL)
        self.assertFalse(self.source().is_ready())


class ReleaseUpgradeTests(SyncContractHarness):
    """From a verified artifact to a digest-bound workload, or not at all."""

    def setUp(self):
        super().setUp()
        self.publish("v0.1.9", image_digest=PROMOTED_DIGEST)
        self.assertEqual(self.sync_source().outcome, SourceOutcome.ARTIFACT_UPDATED)

    def test_the_committed_suspended_release_takes_no_action(self):
        """Suspension dominates the committed state whatever its phase.

        Driven by the values this repository actually commits rather than by
        the fail-closed defaults. That distinction is the point: while the
        sites were at the all-zeros sentinel this proved only that a release
        the sentinel would already refuse stays inert, so suspension was never
        the load-bearing refusal. Applied to a promoted, deploy-eligible
        release, suspension is the ONLY thing standing between this state and
        a rollout — and it must leave no trace of having considered one.
        """

        self.apply_release(**committed_release(self.slug))
        result = self.sync_release()
        self.assertEqual(result.outcome, ReleaseOutcome.SUSPENDED)
        release = self.api.get(HELM_RELEASE, self.namespace, self.slug)
        self.assertEqual(release.status, {})
        self.assertIsNone(self.api.find(DEPLOYMENT, self.namespace, self.slug))

    def test_the_committed_release_unsuspended_matches_its_reviewed_phase(self):
        """Lifting suspension yields exactly the committed phase's outcome.

        The executable half of the sentinel guard, bound to whatever this
        repository has committed rather than to a phase constant. An
        `initial` site must be refused for the sentinel even though the chart
        published here embeds a perfectly good image digest — proving the
        platform's zero-digest override is never rescued by the chart. A
        `promoted` site must deploy the exact reviewed digest its own
        manifest names, and NOT the chart-embedded one, proving the override
        still wins while ADR 0016 step 4 remains untaken.
        """

        committed = committed_release(self.slug)
        phase = STATE_MODULE.site_phase(self.slug, REPO_ROOT)
        # setUp published this chart with PROMOTED_DIGEST embedded, which is
        # deliberately not the committed digest, so the two sources of a
        # digest are distinguishable in the assertions below.
        self.assertNotEqual(committed["digest"], PROMOTED_DIGEST)
        self.apply_release(**{**committed, "suspend": False})
        result = self.sync_release()
        if phase == "initial":
            self.assertEqual(result.outcome, ReleaseOutcome.SENTINEL_REFUSED)
            self.assertIsNone(self.api.find(DEPLOYMENT, self.namespace, self.slug))
        else:
            self.assertEqual(phase, "promoted")
            self.assertEqual(result.outcome, ReleaseOutcome.UPGRADED)
            self.assertEqual(
                self.api.get(DEPLOYMENT, self.namespace, self.slug).spec["image"],
                "{}@{}".format(
                    STATE_MODULE.RELEASE_CONTRACTS[self.slug]["repository"],
                    committed["digest"],
                ),
            )

    def test_the_all_zeros_sentinel_still_refuses_deployment(self):
        self.apply_release(suspend=False, ready=False, digest=ZERO_DIGEST)
        result = self.sync_release()
        self.assertEqual(result.outcome, ReleaseOutcome.SENTINEL_REFUSED)
        self.assertIsNone(self.api.find(DEPLOYMENT, self.namespace, self.slug))

    def test_a_readiness_gate_left_closed_refuses_deployment(self):
        self.apply_release(suspend=False, ready=False, digest=PROMOTED_DIGEST)
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.SENTINEL_REFUSED)

    def test_a_zero_digest_with_readiness_open_still_refuses(self):
        """Neither half of the sentinel may carry the gate alone."""

        self.apply_release(suspend=False, ready=True, digest=ZERO_DIGEST)
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.SENTINEL_REFUSED)

    def test_a_promoted_release_deploys_the_exact_digest(self):
        self.apply_release(suspend=False, ready=True, digest=PROMOTED_DIGEST)
        result = self.sync_release()
        self.assertEqual(result.outcome, ReleaseOutcome.UPGRADED)
        self.assertEqual(result.version, "v0.1.9")
        deployment = self.api.get(DEPLOYMENT, self.namespace, self.slug)
        self.assertEqual(
            deployment.spec["image"],
            "ghcr.io/snaraj/naranjo-online@" + PROMOTED_DIGEST,
        )
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.UNCHANGED)

    def test_the_chart_embedded_digest_carries_the_release_once_the_override_is_gone(self):
        """ADR 0016 step 4: the chart, not the platform, holds the digest."""

        spec = release_spec(self.slug, suspend=False, ready=True)
        spec["values"] = {
            "deploymentReady": True,
            "image": {"repository": "ghcr.io/snaraj/naranjo-online"},
        }
        self.api.apply(
            HELM_RELEASE,
            "helm.toolkit.fluxcd.io/v2",
            self.namespace,
            self.slug,
            spec,
        )
        result = self.sync_release()
        self.assertEqual(result.outcome, ReleaseOutcome.UPGRADED)
        self.assertEqual(
            result.image, "ghcr.io/snaraj/naranjo-online@" + PROMOTED_DIGEST
        )

    def test_a_chart_that_embeds_no_digest_cannot_deploy(self):
        self.registry.remove(chart_repository_path(self.slug), "v0.1.9")
        self.publish("v0.2.0", image_digest=None)
        self.sync_source()
        spec = release_spec(self.slug, suspend=False, ready=True)
        spec["values"] = {
            "deploymentReady": True,
            "image": {"repository": "ghcr.io/snaraj/naranjo-online"},
        }
        self.api.apply(
            HELM_RELEASE,
            "helm.toolkit.fluxcd.io/v2",
            self.namespace,
            self.slug,
            spec,
        )
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.SENTINEL_REFUSED)

    def test_a_chart_that_embeds_the_zero_digest_cannot_deploy(self):
        self.registry.remove(chart_repository_path(self.slug), "v0.1.9")
        self.publish("v0.2.0", image_digest=ZERO_DIGEST)
        self.sync_source()
        spec = release_spec(self.slug, suspend=False, ready=True)
        spec["values"] = {
            "deploymentReady": True,
            "image": {"repository": "ghcr.io/snaraj/naranjo-online"},
        }
        self.api.apply(
            HELM_RELEASE,
            "helm.toolkit.fluxcd.io/v2",
            self.namespace,
            self.slug,
            spec,
        )
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.SENTINEL_REFUSED)

    def test_an_unverified_source_cannot_be_upgraded_from(self):
        self.api.patch_status(
            OCI_REPOSITORY,
            self.namespace,
            self.source_name,
            {"conditions": [{"type": "Ready", "status": "False", "reason": "x"}]},
        )
        self.apply_release(suspend=False, ready=True, digest=PROMOTED_DIGEST)
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.SOURCE_NOT_READY)
        self.assertIsNone(self.api.find(DEPLOYMENT, self.namespace, self.slug))

    def test_a_release_pointed_at_a_missing_source_refuses(self):
        spec = release_spec(self.slug, suspend=False, ready=True, digest=PROMOTED_DIGEST)
        spec["chartRef"]["name"] = "absent-chart"
        self.api.apply(
            HELM_RELEASE, "helm.toolkit.fluxcd.io/v2", self.namespace, self.slug, spec
        )
        self.assertEqual(self.sync_release().outcome, ReleaseOutcome.SOURCE_NOT_READY)

    def test_a_cross_namespace_chart_reference_is_refused(self):
        spec = release_spec(self.slug, suspend=False, ready=True, digest=PROMOTED_DIGEST)
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
                spec = release_spec(
                    self.slug, suspend=False, ready=True, digest=PROMOTED_DIGEST
                )
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
        self.publish("v0.1.9", image_digest=PROMOTED_DIGEST)
        self.sync_source()
        self.apply_release(suspend=False, ready=True, digest=PROMOTED_DIGEST)
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
        newer = self.publish("v0.2.0", image_digest=NEXT_DIGEST)
        self.assertEqual(self.sync_source().outcome, SourceOutcome.ARTIFACT_UPDATED)
        self.apply_release(suspend=False, ready=True, digest=NEXT_DIGEST)
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
        self.assertEqual(history[0]["chartVersion"], "v0.1.9")
        self.assertEqual(history[1]["chartVersion"], "v0.2.0")
        self.assertEqual(history[1]["status"], "failed")
        self.assertIsNotNone(newer)

    def test_rollback_replays_recorded_history_not_a_re_resolved_tag(self):
        """A rollback the registry could steer would not be a rollback."""

        observe_rollout(self.api, self.namespace, self.slug, healthy=True)
        self.publish("v0.2.0", image_digest=NEXT_DIGEST)
        self.sync_source()
        self.apply_release(suspend=False, ready=True, digest=NEXT_DIGEST)
        self.sync_release()
        observe_rollout(self.api, self.namespace, self.slug, healthy=False)
        # The registry is rewritten under us before remediation runs.
        self.registry.remove(chart_repository_path(self.slug), "v0.1.9")
        self.registry.publish(
            chart_repository_path(self.slug),
            PublishedChart(
                version="v0.3.0",
                digest=synthetic_digest("hostile"),
                image_digest="sha256:" + ("c3" * 32),
                signature=publisher_identity(self.slug, tag="v0.3.0"),
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
