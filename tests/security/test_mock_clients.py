"""Prove the mock clients are worth testing against.

A battery built on a mock is only as honest as the mock. These tests exercise
the two clients in ``tests/security/testsupport`` directly, so a later contract battery
cannot be passing because its registry answers yes to everything or because its
Kubernetes model silently accepts whatever it is handed.

Scope, stated plainly: the registry here is a real HTTP server on loopback and
the client performs real requests against it, but it is a MODEL of the OCI
Distribution API, not a registry; the Kubernetes model has no transport at all
and never contacts a cluster. Nothing in this file verifies a signature
cryptographically.
"""

from __future__ import annotations

import unittest

from .testsupport.kubernetes_api import (
    DEPLOYMENT,
    HELM_RELEASE,
    OCI_REPOSITORY,
    MockKubernetesApi,
    NotFound,
    UnknownKind,
    ready_condition,
)
from .testsupport.oci_registry import (
    COSIGN_ISSUER_ANNOTATION,
    COSIGN_SUBJECT_ANNOTATION,
    MockOciRegistry,
    MockRegistryError,
    PublishedChart,
    RegistryClient,
    SigningIdentity,
    synthetic_digest,
)


REPOSITORY = "snaraj/charts/example-site"
OTHER_REPOSITORY = "snaraj/charts/other-site"
IDENTITY = SigningIdentity(
    issuer="https://token.actions.githubusercontent.com",
    subject=(
        "https://github.com/snaraj/example.invalid/.github/workflows/"
        "release-publisher.yml@refs/tags/v0.1.9"
    ),
)


def chart(version, *, signed=True, image_digest=None):
    return PublishedChart(
        version=version,
        digest=synthetic_digest(REPOSITORY + version),
        image_digest=image_digest,
        signature=IDENTITY if signed else None,
    )


class MockRegistryTests(unittest.TestCase):
    """The registry model answers, and refuses, like a registry."""

    def setUp(self):
        self.registry = MockOciRegistry().start()
        self.addCleanup(self.registry.stop)
        self.client = RegistryClient(self.registry.base_url)

    def test_unstarted_registry_has_no_address(self):
        with self.assertRaises(MockRegistryError):
            MockOciRegistry().base_url

    def test_tag_listing_reflects_publication_and_removal(self):
        self.assertIsNone(self.client.list_tags(REPOSITORY))
        self.registry.publish(REPOSITORY, chart("v0.1.9"))
        self.registry.publish(REPOSITORY, chart("v0.2.0"))
        self.assertEqual(self.client.list_tags(REPOSITORY), ["v0.1.9", "v0.2.0"])
        self.registry.remove(REPOSITORY, "v0.2.0")
        self.assertEqual(self.client.list_tags(REPOSITORY), ["v0.1.9"])

    def test_manifests_resolve_by_tag_and_by_digest_only(self):
        published = self.registry.publish(REPOSITORY, chart("v0.1.9"))
        digest, manifest = self.client.manifest(REPOSITORY, "v0.1.9")
        self.assertEqual(digest, published.digest)
        self.assertEqual(
            manifest["annotations"]["org.opencontainers.image.version"], "v0.1.9"
        )
        by_digest, _ = self.client.manifest(REPOSITORY, published.digest)
        self.assertEqual(by_digest, published.digest)
        self.assertEqual(self.client.manifest(REPOSITORY, "v9.9.9"), (None, None))
        self.assertEqual(self.client.manifest("snaraj/charts/absent", "v0.1.9"), (None, None))

    def test_repositories_are_isolated_from_one_another(self):
        self.registry.publish(REPOSITORY, chart("v0.1.9"))
        self.assertIsNone(self.client.list_tags(OTHER_REPOSITORY))
        self.assertEqual(self.client.manifest(OTHER_REPOSITORY, "v0.1.9"), (None, None))

    def test_signature_presence_is_reported_per_digest(self):
        signed = self.registry.publish(REPOSITORY, chart("v0.1.9"))
        unsigned = self.registry.publish(REPOSITORY, chart("v0.2.0", signed=False))
        found = self.client.signature_identity(REPOSITORY, signed.digest)
        self.assertEqual(found, IDENTITY)
        self.assertIsNone(self.client.signature_identity(REPOSITORY, unsigned.digest))
        self.assertIsNone(
            self.client.signature_identity(REPOSITORY, synthetic_digest("absent"))
        )
        self.assertIsNone(self.client.signature_identity(REPOSITORY, "not-a-digest"))
        self.assertIsNone(self.client.signature_identity(REPOSITORY, None))

    def test_signature_annotations_use_the_cosign_key_names(self):
        signed = self.registry.publish(REPOSITORY, chart("v0.1.9"))
        tag = "sha256-{}.sig".format(signed.digest[len("sha256:"):])
        _, manifest = self.client.manifest(REPOSITORY, tag)
        annotations = manifest["layers"][0]["annotations"]
        self.assertEqual(annotations[COSIGN_ISSUER_ANNOTATION], IDENTITY.issuer)
        self.assertEqual(annotations[COSIGN_SUBJECT_ANNOTATION], IDENTITY.subject)

    def test_client_records_every_request_it_made(self):
        self.registry.publish(REPOSITORY, chart("v0.1.9"))
        self.client.list_tags(REPOSITORY)
        self.client.manifest(REPOSITORY, "v0.1.9")
        self.assertEqual(
            self.client.requests,
            [
                "{}/tags/list".format(REPOSITORY),
                "{}/manifests/v0.1.9".format(REPOSITORY),
            ],
        )

    def test_client_has_no_credential_surface_at_all(self):
        """Anonymous by construction, mirroring the desired state's refusal."""

        fields = RegistryClient.__dataclass_fields__
        self.assertEqual(set(fields), {"base_url", "timeout", "requests"})


class MockKubernetesApiTests(unittest.TestCase):
    """The API model reproduces the behaviors the contract reasons about."""

    def setUp(self):
        self.api = MockKubernetesApi()

    def apply_source(self, spec=None):
        return self.api.apply(
            OCI_REPOSITORY,
            "source.toolkit.fluxcd.io/v1",
            "example-site",
            "example-site-chart",
            spec if spec is not None else {"url": "oci://ghcr.io/snaraj/charts/x"},
        )

    def test_unknown_kinds_are_refused_rather_than_invented(self):
        for call in (
            lambda: self.api.get("ConfigMap", "example-site", "x"),
            lambda: self.api.list("Secret"),
            lambda: self.api.apply("Secret", "v1", "example-site", "x", {}),
        ):
            with self.assertRaises(UnknownKind):
                call()

    def test_missing_objects_raise_and_find_returns_none(self):
        with self.assertRaises(NotFound):
            self.api.get(HELM_RELEASE, "example-site", "absent")
        self.assertIsNone(self.api.find(HELM_RELEASE, "example-site", "absent"))
        self.assertIsNone(self.api.find("ConfigMap", "example-site", "absent"))

    def test_namespaced_identity_is_exact(self):
        self.apply_source()
        self.assertIsNone(
            self.api.find(OCI_REPOSITORY, "other-site", "example-site-chart")
        )

    def test_generation_advances_only_when_the_spec_changes(self):
        first = self.apply_source()
        self.assertEqual(first.metadata.generation, 1)
        same = self.apply_source()
        self.assertEqual(same.metadata.generation, 1)
        self.assertGreater(
            same.metadata.resource_version, first.metadata.resource_version
        )
        changed = self.apply_source({"url": "oci://ghcr.io/snaraj/charts/y"})
        self.assertEqual(changed.metadata.generation, 2)

    def test_status_writes_never_advance_the_generation(self):
        stored = self.apply_source()
        patched = self.api.patch_status(
            OCI_REPOSITORY,
            "example-site",
            "example-site-chart",
            {"conditions": [ready_condition(True, "Succeeded")]},
        )
        self.assertEqual(patched.metadata.generation, stored.metadata.generation)
        self.assertGreater(
            patched.metadata.resource_version, stored.metadata.resource_version
        )
        self.assertTrue(patched.is_ready())

    def test_status_patches_merge_rather_than_replace(self):
        self.apply_source()
        self.api.patch_status(
            OCI_REPOSITORY, "example-site", "example-site-chart", {"artifact": {"a": 1}}
        )
        merged = self.api.patch_status(
            OCI_REPOSITORY,
            "example-site",
            "example-site-chart",
            {"conditions": [ready_condition(True, "Succeeded")]},
        )
        self.assertEqual(merged.status["artifact"], {"a": 1})

    def test_applied_spec_is_copied_not_aliased(self):
        spec = {"ref": {"semver": ">=0.1.9 <1.0.0"}}
        stored = self.apply_source(spec)
        spec["ref"]["semver"] = ">=0.0.0 <9.0.0"
        self.assertEqual(stored.spec["ref"]["semver"], ">=0.1.9 <1.0.0")
        self.assertEqual(
            self.api.get(
                OCI_REPOSITORY, "example-site", "example-site-chart"
            ).spec["ref"]["semver"],
            ">=0.1.9 <1.0.0",
        )

    def test_a_duplicated_ready_condition_is_treated_as_absent(self):
        self.apply_source()
        patched = self.api.patch_status(
            OCI_REPOSITORY,
            "example-site",
            "example-site-chart",
            {
                "conditions": [
                    ready_condition(True, "Succeeded"),
                    ready_condition(True, "Succeeded"),
                ]
            },
        )
        self.assertIsNone(patched.condition("Ready"))
        self.assertFalse(patched.is_ready())

    def test_listing_is_kind_scoped_and_ordered(self):
        self.apply_source()
        self.api.apply(
            HELM_RELEASE, "helm.toolkit.fluxcd.io/v2", "example-site", "example-site", {}
        )
        self.api.apply(DEPLOYMENT, "apps/v1", "example-site", "example-site", {})
        self.assertEqual(
            [(item.namespace, item.name) for item in self.api.list(OCI_REPOSITORY)],
            [("example-site", "example-site-chart")],
        )
        self.assertEqual(len(self.api.list(HELM_RELEASE)), 1)
        self.assertEqual(len(self.api.list(DEPLOYMENT)), 1)

    def test_delete_requires_the_object_to_exist(self):
        with self.assertRaises(NotFound):
            self.api.delete(DEPLOYMENT, "example-site", "absent")
        self.apply_source()
        self.api.delete(OCI_REPOSITORY, "example-site", "example-site-chart")
        self.assertIsNone(
            self.api.find(OCI_REPOSITORY, "example-site", "example-site-chart")
        )


if __name__ == "__main__":
    unittest.main()
