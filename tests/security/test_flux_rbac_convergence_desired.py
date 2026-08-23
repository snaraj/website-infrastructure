"""Closed desired-state data for the protected Flux RBAC convergence transaction.

The transaction must never infer a broader apply set from ``access.yaml`` or
the controller install root.  This test proves that its JSON input is an exact
copy of the reviewed subset: every selected manifest object is present, no
other object is admitted, and the controller arguments and temporary proof
target are pinned to their reviewed manifests.
"""

from __future__ import annotations

import copy
import json
import re
import unittest
from pathlib import Path

from .testsupport import rbac_model as model


ROOT = Path(__file__).resolve().parents[2]
DESIRED = ROOT / "bootstrap/flux/rbac-convergence/desired-active.json"

SCHEMA = "flux-rbac-convergence-desired-v1"
TOP_LEVEL_KEYS = {
    "schema",
    "clusterRbacObjects",
    "deletionIdentities",
    "namespacedObjects",
    "controllerArgs",
    "temporaryProof",
}

CLUSTER_IDENTITIES = {
    ("ClusterRole", None, "crd-controller-source-flux-system"),
    ("ClusterRoleBinding", None, "crd-controller-source-flux-system"),
    ("ClusterRole", None, "crd-controller-kustomize-flux-system"),
    ("ClusterRoleBinding", None, "crd-controller-kustomize-flux-system"),
    ("ClusterRole", None, "crd-controller-helm-flux-system"),
    ("ClusterRoleBinding", None, "crd-controller-helm-flux-system"),
    ("ClusterRole", None, "crd-controller-flux-system"),
    ("ClusterRoleBinding", None, "crd-controller-flux-system"),
}

NAMESPACED_IDENTITIES = {
    ("Role", "flux-system", "flux-controller-runtime"),
    ("RoleBinding", "flux-system", "flux-controller-runtime"),
    ("Role", "naranjo-online", "flux-controller-impersonation"),
    ("RoleBinding", "naranjo-online", "flux-controller-impersonation"),
    ("ServiceAccount", "naranjo-online", "helm-reconciler"),
    ("Role", "naranjo-online", "helm-reconciler"),
    ("RoleBinding", "naranjo-online", "helm-reconciler"),
    ("Role", "lidersea-com", "flux-controller-impersonation"),
    ("RoleBinding", "lidersea-com", "flux-controller-impersonation"),
    ("ServiceAccount", "lidersea-com", "helm-reconciler"),
    ("Role", "lidersea-com", "helm-reconciler"),
    ("RoleBinding", "lidersea-com", "helm-reconciler"),
}

DELETION = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRoleBinding",
    "name": "cluster-reconciler-flux-system",
}

PROOF_ANNOTATION = "platform.snaraj.dev/flux-rbac-convergence-proof"


def _identity(document):
    metadata = document.get("metadata") or {}
    return document.get("kind"), metadata.get("namespace"), metadata.get("name")


def _documents_by_identity(documents):
    result = {}
    for document in documents:
        identity = _identity(document)
        if identity in result:
            raise AssertionError("duplicate manifest identity: {!r}".format(identity))
        result[identity] = document
    return result


def _generated_deployment(name):
    """Read one generated Deployment without parsing the export's CRD schemas."""

    export = (
        ROOT / "kubernetes/flux-system/controllers/gotk-components.yaml"
    ).read_text(encoding="utf-8")
    matches = []
    for chunk in re.split(r"(?m)^---\s*$", export):
        if not re.search(r"(?m)^kind:\s*Deployment\s*$", chunk):
            continue
        documents = model.parse_documents(chunk)
        if len(documents) != 1:
            raise AssertionError("generated Deployment chunk is not singular")
        document = documents[0]
        if (document.get("metadata") or {}).get("name") == name:
            matches.append(document)
    if len(matches) != 1:
        raise AssertionError("expected exactly one generated Deployment " + name)
    return matches[0]


def _manager_args(document):
    containers = (((document.get("spec") or {}).get("template") or {}).get("spec") or {}).get(
        "containers"
    )
    if not isinstance(containers, list):
        raise AssertionError("Deployment containers are absent")
    managers = [container for container in containers if container.get("name") == "manager"]
    if len(managers) != 1 or not isinstance(managers[0].get("args"), list):
        raise AssertionError("Deployment manager args are not singular")
    return managers[0]["args"]


def _reviewed_appended_args(controller):
    patch = (
        ROOT
        / "kubernetes/flux-system/controllers/patches/{}.yaml".format(controller)
    ).read_text(encoding="utf-8")
    path = "/spec/template/spec/containers/0/args/-"
    path_count = len(re.findall(r"(?m)^  path: " + re.escape(path) + r"\s*$", patch))
    values = re.findall(
        r"(?m)^  path: " + re.escape(path) + r"\s*\n  value: ([^\n]+)\s*$",
        patch,
    )
    if len(values) != path_count:
        raise AssertionError("controller arg patch is not an exact add/value pair")
    return values


class FluxRbacConvergenceDesiredTests(unittest.TestCase):
    """The protected transaction consumes only this exact, manifest-derived set."""

    def setUp(self):
        self.bundle = json.loads(DESIRED.read_text(encoding="utf-8"))
        self.access = model.load_documents(ROOT / "kubernetes/flux-system/access.yaml")

    def _assert_exact_object_set(self, actual, expected_identities, source_documents):
        self.assertIsInstance(actual, list)
        actual_map = _documents_by_identity(actual)
        self.assertEqual(set(actual_map), expected_identities)

        source_map = _documents_by_identity(
            document
            for document in source_documents
            if _identity(document) in expected_identities
        )
        self.assertEqual(set(source_map), expected_identities)
        self.assertEqual(actual_map, source_map)

    def _assert_deletion(self, bundle):
        self.assertEqual(bundle["deletionIdentities"], [DELETION])

        patch = model.load_documents(
            ROOT
            / "kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml"
        )
        self.assertEqual(len(patch), 1)
        self.assertEqual(patch[0].get("$patch"), "delete")
        self.assertEqual(
            {
                "apiVersion": patch[0].get("apiVersion"),
                "kind": patch[0].get("kind"),
                "name": (patch[0].get("metadata") or {}).get("name"),
            },
            DELETION,
        )

        generated = model.load_rbac_documents(
            ROOT / "kubernetes/flux-system/controllers/gotk-components.yaml"
        )
        generated_identities = {_identity(document) for document in generated}
        self.assertIn(("ClusterRoleBinding", None, DELETION["name"]), generated_identities)
        effective_identities = {
            _identity(document) for document in model.controller_root_rbac(ROOT)
        }
        self.assertNotIn(
            ("ClusterRoleBinding", None, DELETION["name"]), effective_identities
        )

    def _assert_controller_args(self, bundle):
        expected = {}
        for controller in ("kustomize-controller", "helm-controller"):
            expected[controller] = _manager_args(_generated_deployment(controller)) + (
                _reviewed_appended_args(controller)
            )
        self.assertEqual(bundle["controllerArgs"], expected)

    def _assert_temporary_proof(self, bundle):
        releases = [
            document
            for document in model.load_documents(
                ROOT / "kubernetes/websites/naranjo-online/release.yaml"
            )
            if document.get("kind") == "HelmRelease"
        ]
        self.assertEqual(len(releases), 1)
        release = releases[0]
        metadata = release.get("metadata") or {}
        identity = {
            "apiVersion": release.get("apiVersion"),
            "kind": release.get("kind"),
            "namespace": metadata.get("namespace"),
            "name": metadata.get("name"),
        }
        self.assertEqual(
            identity,
            {
                "apiVersion": "helm.toolkit.fluxcd.io/v2",
                "kind": "HelmRelease",
                "namespace": "naranjo-online",
                "name": "naranjo-online",
            },
        )
        self.assertNotIn(PROOF_ANNOTATION, metadata.get("annotations") or {})
        self.assertEqual(
            bundle["temporaryProof"],
            {"identity": identity, "annotationKey": PROOF_ANNOTATION},
        )

    def assert_valid_bundle(self, bundle):
        self.assertIsInstance(bundle, dict)
        self.assertEqual(set(bundle), TOP_LEVEL_KEYS)
        self.assertEqual(bundle["schema"], SCHEMA)
        self._assert_exact_object_set(
            bundle["clusterRbacObjects"],
            CLUSTER_IDENTITIES,
            model.controller_root_rbac(ROOT),
        )
        self._assert_exact_object_set(
            bundle["namespacedObjects"], NAMESPACED_IDENTITIES, self.access
        )
        self._assert_deletion(bundle)
        self._assert_controller_args(bundle)
        self._assert_temporary_proof(bundle)

    def test_bundle_has_bidirectional_manifest_parity(self):
        self.assert_valid_bundle(self.bundle)

    def test_extra_and_missing_objects_fail_closed(self):
        access_map = _documents_by_identity(self.access)
        extra = access_map[("Role", "flux-system", "flux-controller-decryption")]

        mutations = {}
        candidate = copy.deepcopy(self.bundle)
        candidate["clusterRbacObjects"].pop()
        mutations["missing cluster object"] = candidate

        candidate = copy.deepcopy(self.bundle)
        candidate["namespacedObjects"].pop()
        mutations["missing namespaced object"] = candidate

        candidate = copy.deepcopy(self.bundle)
        candidate["namespacedObjects"].append(extra)
        mutations["extra decryption object"] = candidate

        candidate = copy.deepcopy(self.bundle)
        candidate["clusterRbacObjects"][0]["rules"][0]["verbs"].append("delete")
        mutations["widened cluster role"] = candidate

        candidate = copy.deepcopy(self.bundle)
        candidate["deletionIdentities"].append(
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "name": "arbitrary-binding",
            }
        )
        mutations["arbitrary deletion"] = candidate

        candidate = copy.deepcopy(self.bundle)
        candidate["unreviewedObjects"] = []
        mutations["unknown schema field"] = candidate

        for name, mutated in mutations.items():
            with self.subTest(mutation=name):
                with self.assertRaises(AssertionError):
                    self.assert_valid_bundle(mutated)


if __name__ == "__main__":
    unittest.main()
