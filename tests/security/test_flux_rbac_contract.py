"""The narrowed Flux controller authorization, proven sufficient and narrow.

The generated Flux export binds the built-in ``cluster-admin`` ClusterRole to
the kustomize-controller and helm-controller ServiceAccounts (AUDIT S12). This
battery is the evidence that removing it is safe in both directions:

* SUFFICIENT — every object the reviewed desired state would apply is
  enumerated from the manifests and authorized against the committed Roles by
  the RBAC model in ``testsupport/rbac_model.py``. A permission this repository
  forgot to grant fails here, in `make check-fast`, instead of at reconcile time
  as a half-applied Kustomization.
* NARROW — an enumerated set of requests the reconcilers must never be able to
  make is asserted denied, ``cluster-admin`` cannot reappear, no wildcard rule
  can reach a Flux account, and impersonation stays restricted by name.

What is modelled rather than observed is stated in the module docstring of
``testsupport/rbac_model.py``. The live half of the proof is
``bootstrap/flux/bootstrap.sh --verify`` and the ``kubectl auth can-i`` sweep in
``docs/runbooks/flux-rbac-narrowing.md``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import load_script
from .testsupport import rbac_model as model
from .testsupport.rbac_model import Authorizer, Subject, YamlSubsetError


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "bootstrap" / "flux" / "bootstrap.sh"

KUSTOMIZE_CONTROLLER = Subject("flux-system", "kustomize-controller")
HELM_CONTROLLER = Subject("flux-system", "helm-controller")
SOURCE_CONTROLLER = Subject("flux-system", "source-controller")

# The one place the reviewed desired state is deliberately NOT authorized to do
# what it declares. `kubernetes/flux-system/access.yaml` grants the admission
# reconciler namespaced authority only, on purpose: it can own the inert Kyverno
# controller shell but cannot create the ClusterPolicies or the admission webhook
# the same path declares. That gap is a staging stop, and it is only tolerable
# while the `admission` Kustomization stays suspended — which the test below
# requires, so unsuspending admission without granting (or removing) this
# authority turns this battery red.
DECLARED_INSUFFICIENCIES = {
    # The Kyverno staging stop: the admission reconciler is namespaced on
    # purpose, so it can own the inert controller shell but cannot create the
    # cluster-scoped policy objects the same path declares.
    ("admission", "kyverno.io", "clusterpolicies"),
    ("admission", "admissionregistration.k8s.io", "validatingwebhookconfigurations"),
    # READINESS READ-BACK, pre-existing and NOT introduced by the narrowing
    # (these Roles are unchanged from main). A `wait: true` Kustomization and a
    # HelmRelease that has not disabled Helm's wait both evaluate readiness by
    # walking a workload down to its Pods, under the impersonated identity — so
    # each needs `get`/`list` on replicasets and pods in the target namespace.
    #
    # This CANNOT simply be granted: policies/conftest/kubernetes.rego denies
    # any Role in cloudflare-public, naranjo-online, lidersea-com, or kyverno
    # that names pods or replicasets AT ALL — the rule is verb-agnostic, so even
    # a read grant is refused as "direct workload control". Closing the gap is
    # therefore a reviewed decision between narrowing that policy to write verbs
    # and turning the waits off, not something this change may quietly pick.
    # Until then every affected object stays suspended, which the test below
    # requires.
    ("admission", "apps", "replicasets"),
    ("admission", "", "pods"),
    ("cloudflare-public", "apps", "replicasets"),
    ("cloudflare-public", "", "pods"),
    ("naranjo-online", "apps", "replicasets"),
    ("naranjo-online", "", "pods"),
    ("lidersea-com", "apps", "replicasets"),
    ("lidersea-com", "", "pods"),
}

# Requests the narrowed authorization must refuse. Each row is the concrete
# shape of a way the deleted cluster-admin binding used to let a compromised
# controller, or a mistaken manifest, reach past its boundary.
FORBIDDEN_REQUESTS = (
    (KUSTOMIZE_CONTROLLER, "create", "apps", "deployments", "kube-system", None,
     "a controller must not apply workloads under its own identity"),
    (KUSTOMIZE_CONTROLLER, "get", "", "secrets", "kube-system", None,
     "cluster-wide Secret reads are what made flux-system the crown jewel"),
    (KUSTOMIZE_CONTROLLER, "create", "", "serviceaccounts/token", "kube-system", None,
     "token minting is escalation to any account in the cluster"),
    (KUSTOMIZE_CONTROLLER, "create", "rbac.authorization.k8s.io", "clusterrolebindings",
     None, None, "no Flux account may grant authority to itself"),
    (KUSTOMIZE_CONTROLLER, "create", "", "namespaces", None, None,
     "namespace creation stays bootstrap-owned"),
    (KUSTOMIZE_CONTROLLER, "impersonate", "", "serviceaccounts", "flux-system", "default",
     "the --default-service-account fallback must not be impersonable"),
    (KUSTOMIZE_CONTROLLER, "impersonate", "", "serviceaccounts", "naranjo-online",
     "helm-reconciler", "kustomize-controller impersonates only in flux-system"),
    (HELM_CONTROLLER, "impersonate", "", "serviceaccounts", "flux-system", "root-reconciler",
     "helm-controller must not reach the root reconciler's authority"),
    (HELM_CONTROLLER, "get", "", "secrets", "flux-system", "sops-age",
     "only the decrypting controller reads the age key"),
    (HELM_CONTROLLER, "create", "", "secrets", "flux-system", None,
     "no controller writes Secrets in flux-system"),
    (SOURCE_CONTROLLER, "get", "", "secrets", "naranjo-online", None,
     "every source in this repository is anonymous"),
    (SOURCE_CONTROLLER, "impersonate", "", "serviceaccounts", "flux-system",
     "root-reconciler", "source-controller applies nothing and impersonates nobody"),
    (Subject("naranjo-online", "helm-reconciler"), "get", "", "secrets", "lidersea-com",
     None, "the two site identity tuples never couple"),
    (Subject("lidersea-com", "helm-reconciler"), "get", "", "secrets", "naranjo-online",
     None, "the two site identity tuples never couple"),
    (Subject("flux-system", "root-reconciler"), "create", "apps", "deployments",
     "flux-system", None, "the root reconciler applies Flux objects, not workloads"),
    (Subject("flux-system", "admission-reconciler"), "create", "kyverno.io",
     "clusterpolicies", None, None, "the admission staging stop is authorization, not prose"),
)

# The ServiceAccounts the reviewed three-controller component set creates. Any
# other subject on the shared ClusterRoleBinding names an account that does not
# exist today and would activate silently the day it did.
INSTALLED_CONTROLLERS = ("source-controller", "kustomize-controller", "helm-controller")

# The two generated ClusterRoles that legitimately keep wildcards: they aggregate
# into the built-in admin/edit/view roles for human operators and are bound to no
# ServiceAccount. The binding half of that claim is asserted below.
AGGREGATION_ROLES = {"flux-edit-flux-system", "flux-view-flux-system"}


class FluxRbacSufficiencyTests(unittest.TestCase):
    """Everything the reviewed desired state applies must be permitted."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.documents = model.effective_flux_rbac(ROOT)
        cls.authorizer = Authorizer.from_documents(cls.documents)
        derived = model.derive_requirements(ROOT)
        cls.requirements = derived.applied
        cls.controller_requirements = derived.controller

    def test_derivation_covers_every_reconciled_object(self):
        # A derivation that found nothing would pass every sufficiency test
        # below without proving anything, so the enumeration itself is pinned:
        # six Kustomizations, three HelmReleases, and every object they apply.
        owners = {requirement.owner for requirement in self.requirements}
        self.assertEqual(
            owners,
            {
                "flux-system", "platform-prerequisites", "admission", "platform-services",
                "naranjo-online", "lidersea-com", "cloudflare-public",
            },
        )
        applied = {
            (requirement.group, requirement.resource) for requirement in self.requirements
        }
        for expected in (
            ("apps", "deployments"),
            ("", "services"),
            ("", "serviceaccounts"),
            ("", "secrets"),
            ("", "resourcequotas"),
            ("", "limitranges"),
            ("networking.k8s.io", "networkpolicies"),
            ("kustomize.toolkit.fluxcd.io", "kustomizations"),
            ("helm.toolkit.fluxcd.io", "helmreleases"),
            ("source.toolkit.fluxcd.io", "ocirepositories"),
            ("source.toolkit.fluxcd.io", "gitrepositories"),
            ("kyverno.io", "clusterpolicies"),
        ):
            with self.subTest(resource=expected):
                self.assertIn(expected, applied)
        self.assertGreater(len(self.requirements), 250)
        self.assertGreater(len(self.controller_requirements), 150)
        # All three controllers must appear. source-controller reconciles every
        # source object under its own identity; a derivation that never named it
        # left that whole authority unproven.
        self.assertEqual(
            {str(requirement.subject) for requirement in self.controller_requirements},
            {
                "system:serviceaccount:flux-system:source-controller",
                "system:serviceaccount:flux-system:kustomize-controller",
                "system:serviceaccount:flux-system:helm-controller",
            },
        )

    def test_every_applied_object_is_permitted_or_a_declared_staging_stop(self):
        gaps = {
            (requirement.owner, requirement.group, requirement.resource)
            for requirement in model.unmet(self.authorizer, self.requirements)
        }
        self.assertEqual(
            gaps,
            DECLARED_INSUFFICIENCIES,
            "the committed RBAC does not permit an object the committed desired state "
            "applies; grant it, or declare it as a staging stop with the Kustomization "
            "suspended",
        )

    def test_a_declared_staging_stop_requires_its_owner_to_stay_suspended(self):
        # Both kinds are checked: a HelmRelease is switched off by its own
        # spec.suspend, independently of the Kustomization that delivers it.
        suspended = model.suspended_owners(ROOT)
        for owner, group, resource in sorted(DECLARED_INSUFFICIENCIES):
            with self.subTest(owner=owner, resource=resource):
                self.assertIn(
                    owner,
                    suspended,
                    "{} is no longer suspended but still cannot use {}/{}: "
                    "unsuspending it would fail halfway".format(
                        owner, group or "core", resource
                    ),
                )

    def test_the_controllers_can_run_the_reconciliation_under_their_own_identity(self):
        unmet = model.unmet(self.authorizer, self.controller_requirements)
        self.assertEqual(
            [requirement.describe() for requirement in unmet],
            [],
            "a controller cannot perform an action its own reconcile loop requires",
        )

    def test_impersonation_is_granted_for_every_account_a_custom_resource_names(self):
        impersonations = [
            requirement
            for requirement in self.controller_requirements
            if requirement.verb == "impersonate"
        ]
        # Six Kustomizations plus three HelmReleases; the accounts they name are
        # the entire surface through which anything is applied.
        self.assertEqual(len(impersonations), 9)
        for requirement in impersonations:
            with self.subTest(account=requirement.name, namespace=requirement.namespace):
                self.assertTrue(
                    self.authorizer.allows(
                        requirement.subject, "impersonate", "", "serviceaccounts",
                        requirement.namespace, requirement.name,
                    )
                )

    def test_source_resolution_is_derived_for_every_custom_resource(self):
        """The authority every reconciliation starts with (P1-1).

        A reconciler resolves `spec.sourceRef`/`spec.chartRef` through its own
        API client BEFORE impersonation is configured, so reading the source is
        the CONTROLLER's own authority. Deleting the source read rule from the
        narrowed ClusterRole is a coherent-looking further narrowing that would
        stop ALL reconciliation live — the root Kustomization could not read the
        GitRepository it syncs from — so it must fail here.
        """

        reads = [
            requirement
            for requirement in self.controller_requirements
            if "resolves its" in requirement.reason
        ]
        self.assertTrue(reads)
        # Every Kustomization and every HelmRelease resolves exactly one source,
        # and does it as the controller rather than as the impersonated account.
        self.assertEqual(
            {str(requirement.subject) for requirement in reads},
            {
                "system:serviceaccount:flux-system:kustomize-controller",
                "system:serviceaccount:flux-system:helm-controller",
            },
        )
        owners = {requirement.owner for requirement in reads}
        self.assertEqual(
            owners,
            {
                "flux-system", "platform-prerequisites", "admission", "platform-services",
                "naranjo-online", "lidersea-com", "cloudflare-public",
            },
        )
        for requirement in reads:
            with self.subTest(
                subject=str(requirement.subject),
                resource=requirement.resource,
                namespace=requirement.namespace,
            ):
                self.assertTrue(
                    self.authorizer.allows(
                        requirement.subject, requirement.verb, requirement.group,
                        requirement.resource, requirement.namespace,
                    ),
                    requirement.describe(),
                )

    def test_the_root_kustomization_can_read_the_repository_it_syncs_from(self):
        # The single most load-bearing request in the whole system, asserted on
        # its own so a regression names itself.
        for verb in ("get", "list", "watch"):
            with self.subTest(verb=verb):
                self.assertTrue(
                    self.authorizer.allows(
                        KUSTOMIZE_CONTROLLER, verb, "source.toolkit.fluxcd.io",
                        "gitrepositories", "flux-system",
                    )
                )

    def test_source_controller_can_reconcile_every_source_it_owns(self):
        sources = model.flux_custom_resources(ROOT).sources
        self.assertGreaterEqual(len(sources), 4)
        for source in sources:
            group, resource, _ = model.KIND_RESOURCES[source["kind"]]
            namespace = source["metadata"].get("namespace", "flux-system")
            with self.subTest(name=source["metadata"]["name"], namespace=namespace):
                self.assertTrue(
                    self.authorizer.allows(
                        SOURCE_CONTROLLER, "patch", group, resource, namespace
                    )
                )

    def test_controllers_can_probe_the_api_server_liveness_endpoint(self):
        # The one grant a Role cannot express, so it stays cluster-scoped and is
        # pinned rather than only justified in prose.
        for subject in (SOURCE_CONTROLLER, KUSTOMIZE_CONTROLLER, HELM_CONTROLLER):
            with self.subTest(subject=str(subject)):
                self.assertTrue(
                    self.authorizer.allows_non_resource(subject, "head", model.LIVENESS_URL)
                )
                self.assertFalse(
                    self.authorizer.allows_non_resource(subject, "get", "/metrics"),
                    "the non-resource grant must not be broader than the probe",
                )

    def test_site_release_reconcilers_grant_the_source_kind_their_own_source_declares(self):
        # The regression this catches concretely: both site reconcilers carried
        # `gitrepositories` after their sources became OCIRepositories, so the
        # first unsuspend would have been denied on the object the same commit
        # declared.
        for site in ("naranjo-online", "lidersea-com"):
            documents = model.load_documents(
                ROOT / "kubernetes" / "websites" / site / "source.yaml"
            )
            kinds = {document["kind"] for document in documents}
            self.assertEqual(kinds, {"OCIRepository"}, site)
            group, resource, _ = model.KIND_RESOURCES["OCIRepository"]
            subject = Subject("flux-system", site + "-reconciler")
            with self.subTest(site=site):
                self.assertTrue(
                    self.authorizer.allows(subject, "create", group, resource, site)
                )
                self.assertFalse(
                    self.authorizer.allows(
                        subject, "create", group, "gitrepositories", site
                    ),
                    "a site reconciler must not be able to apply a Git source",
                )


class FluxRbacNarrownessTests(unittest.TestCase):
    """The authorization must be as small as the derivation says it is."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.documents = model.effective_flux_rbac(ROOT)
        cls.authorizer = Authorizer.from_documents(cls.documents)

    def test_cluster_admin_is_bound_to_nothing(self):
        for document in self.documents:
            if document.get("kind") not in {"ClusterRoleBinding", "RoleBinding"}:
                continue
            with self.subTest(binding=document["metadata"]["name"]):
                self.assertNotEqual(
                    (document.get("roleRef") or {}).get("name"),
                    "cluster-admin",
                    "cluster-admin is bound again (AUDIT S12)",
                )
        names = {
            document["metadata"]["name"]
            for document in self.documents
            if document.get("kind") == "ClusterRoleBinding"
        }
        self.assertNotIn("cluster-reconciler-flux-system", names)

    def test_no_wildcard_rule_reaches_a_flux_service_account(self):
        subjects = [
            Subject("flux-system", name)
            for name in INSTALLED_CONTROLLERS
        ]
        subjects.extend(
            Subject(namespace, name)
            for namespace, name in (
                ("flux-system", "root-reconciler"),
                ("flux-system", "platform-prerequisites-reconciler"),
                ("flux-system", "admission-reconciler"),
                ("flux-system", "platform-services-reconciler"),
                ("flux-system", "naranjo-online-reconciler"),
                ("flux-system", "lidersea-com-reconciler"),
                ("cloudflare-public", "helm-reconciler"),
                ("naranjo-online", "helm-reconciler"),
                ("lidersea-com", "helm-reconciler"),
            )
        )
        namespaces = (
            None, "flux-system", "cloudflare-public", "naranjo-online", "lidersea-com",
            "kyverno", "kube-system",
        )
        for subject in subjects:
            for namespace in namespaces:
                for rule in self.authorizer.rules_for_subject(subject, namespace):
                    with self.subTest(subject=str(subject), namespace=namespace):
                        for field in ("apiGroups", "resources", "verbs"):
                            self.assertNotIn(
                                "*",
                                rule.get(field) or [],
                                "wildcard {} reaches {}".format(field, subject),
                            )

    def test_the_wildcard_aggregation_roles_are_bound_to_no_one(self):
        # They are the reason a blanket "no wildcards anywhere" assertion would
        # be wrong, so the claim that makes them harmless is asserted instead.
        for document in self.documents:
            if document.get("kind") not in {"ClusterRoleBinding", "RoleBinding"}:
                continue
            role_ref = document.get("roleRef") or {}
            with self.subTest(binding=document["metadata"]["name"]):
                self.assertNotIn(role_ref.get("name"), AGGREGATION_ROLES)

    def test_shared_controller_binding_names_only_installed_controllers(self):
        binding = next(
            document
            for document in self.documents
            if document.get("kind") == "ClusterRoleBinding"
            and document["metadata"]["name"] == "crd-controller-flux-system"
        )
        subjects = {
            (entry["namespace"], entry["name"]) for entry in binding["subjects"]
        }
        self.assertEqual(
            subjects,
            {("flux-system", name) for name in INSTALLED_CONTROLLERS},
            "a subject for a controller this install does not run would activate "
            "silently the day that controller was added",
        )

    def test_impersonation_grants_are_restricted_by_name(self):
        found = 0
        for document in self.documents:
            if document.get("kind") not in {"Role", "ClusterRole"}:
                continue
            for rule in document.get("rules") or []:
                if "impersonate" not in (rule.get("verbs") or []):
                    continue
                found += 1
                with self.subTest(role=document["metadata"]["name"]):
                    self.assertEqual(document["kind"], "Role", "impersonation stays namespaced")
                    self.assertTrue(
                        rule.get("resourceNames"),
                        "an impersonate grant without resourceNames covers every account "
                        "in the namespace",
                    )
        self.assertEqual(found, 4, "one impersonation Role per namespace holding accounts")

    def test_forbidden_requests_are_denied(self):
        for subject, verb, group, resource, namespace, name, why in FORBIDDEN_REQUESTS:
            with self.subTest(subject=str(subject), verb=verb, resource=resource):
                self.assertFalse(
                    self.authorizer.allows(subject, verb, group, resource, namespace, name),
                    "{} may {} {}/{}: {}".format(subject, verb, group or "core", resource, why),
                )

    def test_no_controller_can_write_secrets_anywhere(self):
        for subject in (KUSTOMIZE_CONTROLLER, HELM_CONTROLLER, SOURCE_CONTROLLER):
            for namespace in (
                "flux-system", "cloudflare-public", "naranjo-online", "lidersea-com",
                "kyverno", "kube-system", None,
            ):
                for verb in ("create", "update", "patch", "delete"):
                    with self.subTest(subject=str(subject), namespace=namespace, verb=verb):
                        self.assertFalse(
                            self.authorizer.allows(subject, verb, "", "secrets", namespace)
                        )

    def test_no_controller_can_mint_a_service_account_token(self):
        for subject in (KUSTOMIZE_CONTROLLER, HELM_CONTROLLER, SOURCE_CONTROLLER):
            for namespace in ("flux-system", "kube-system", "naranjo-online", None):
                with self.subTest(subject=str(subject), namespace=namespace):
                    self.assertFalse(
                        self.authorizer.allows(
                            subject, "create", "", "serviceaccounts/token", namespace
                        )
                    )


class FluxRbacCompositionTests(unittest.TestCase):
    """The model, the renderer, and the live-state verifier must agree."""

    maxDiff = None

    def test_patches_are_wired_into_the_install_root(self):
        index = (ROOT / "kubernetes/flux-system/controllers/kustomization.yaml").read_text(
            encoding="utf-8"
        )
        for relative in model.FLUX_RBAC_PATCH_FILES:
            with self.subTest(patch=relative):
                self.assertTrue((ROOT / relative).is_file())
                self.assertIn("patches/" + Path(relative).name, index)

    @unittest.skipIf(shutil.which("kustomize") is None, "kustomize is not installed")
    def test_model_composition_equals_the_rendered_output(self):
        # The model applies the patches itself so the fast gate needs no
        # renderer. This test proves that shortcut is faithful: the RBAC the
        # model composes must equal the RBAC the pinned Kustomize actually
        # builds, object for object and rule for rule.
        kustomize = shutil.which("kustomize")
        if kustomize is None:
            self.skipTest("kustomize is not installed")
        rendered = subprocess.run(
            [kustomize, "build", str(ROOT / "kubernetes/flux-system/controllers")],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        actual = {
            self._identity(document): document
            for document in model.parse_documents(
                "\n---\n".join(
                    chunk
                    for chunk in re.split(r"(?m)^---\s*$", rendered)
                    if re.search(r"(?m)^kind:\s*(?:Cluster)?Role(?:Binding)?\s*$", chunk)
                )
            )
        }
        composed = {
            self._identity(document): document
            for document in model.apply_patches(
                model.load_rbac_documents(
                    ROOT / "kubernetes/flux-system/controllers/gotk-components.yaml"
                ),
                [
                    document
                    for relative in model.FLUX_RBAC_PATCH_FILES
                    for document in model.load_documents(ROOT / relative)
                ],
            )
        }
        self.assertEqual(sorted(composed), sorted(actual))
        for key in sorted(actual):
            with self.subTest(object=key):
                self.assertEqual(composed[key].get("rules"), actual[key].get("rules"))
                self.assertEqual(composed[key].get("subjects"), actual[key].get("subjects"))
                self.assertEqual(composed[key].get("roleRef"), actual[key].get("roleRef"))

    @staticmethod
    def _identity(document):
        metadata = document.get("metadata") or {}
        return document.get("kind"), metadata.get("namespace"), metadata.get("name")

    def test_live_state_verifier_model_equals_the_committed_manifests(self):
        # bootstrap/flux/bootstrap.sh carries a model of the authorization it
        # expects to find on the cluster, and `--verify` fails on any drift from
        # it. If that model and these manifests disagree, one of them is a lie:
        # either the repository describes RBAC the verifier would reject, or the
        # verifier accepts RBAC the repository never reviewed.
        contract = self._bootstrap_contract()
        documents = model.effective_flux_rbac(ROOT)
        normalize_rules = contract["normalize_rules"]
        normalized_subjects = contract["normalized_subjects"]

        roles = {
            (document["metadata"].get("namespace"), document["metadata"]["name"]): document
            for document in documents
            if document.get("kind") == "Role"
        }
        for key, expected in contract["access_role_rules"]().items():
            with self.subTest(role=key):
                self.assertIn(key, roles)
                self.assertEqual(
                    normalize_rules(roles[key].get("rules")), normalize_rules(expected)
                )

        cluster_roles = {
            document["metadata"]["name"]: document
            for document in documents
            if document.get("kind") == "ClusterRole"
        }
        for name, expected in contract["cluster_role_rules"]().items():
            with self.subTest(cluster_role=name):
                self.assertIn(name, cluster_roles)
                self.assertEqual(
                    normalize_rules(cluster_roles[name].get("rules")), normalize_rules(expected)
                )

        bindings = {
            (document["metadata"].get("namespace"), document["metadata"]["name"]): document
            for document in documents
            if document.get("kind") == "RoleBinding"
        }
        expected_role_bindings = contract["expected_bindings"]()
        # Exact set equality, matching the ClusterRoleBinding assertion below.
        # `assertIn` alone let a RoleBinding that the model never modelled — a
        # group-subject grant in another namespace, say — exist on both sides of
        # the mirror without either noticing.
        self.assertEqual(set(bindings), set(expected_role_bindings))
        for key, expected in expected_role_bindings.items():
            with self.subTest(binding=key):
                self.assertIn(key, bindings)
                self.assertEqual(bindings[key]["roleRef"], expected[0])
                self.assertEqual(
                    normalized_subjects(bindings[key]["subjects"]),
                    normalized_subjects(expected[1]),
                )

        cluster_bindings = {
            document["metadata"]["name"]: document
            for document in documents
            if document.get("kind") == "ClusterRoleBinding"
        }
        expected_cluster = contract["expected_cluster_bindings"]()
        self.assertEqual(set(cluster_bindings), set(expected_cluster))
        for name, expected in expected_cluster.items():
            with self.subTest(cluster_binding=name):
                self.assertEqual(cluster_bindings[name]["roleRef"], expected[0])
                self.assertEqual(
                    normalized_subjects(cluster_bindings[name]["subjects"]),
                    normalized_subjects(expected[1]),
                )

    def test_reviewed_manifest_inventory_lists_every_narrowing_patch(self):
        text = BOOTSTRAP.read_text(encoding="utf-8")
        inventory = re.search(r"(?ms)^  expected_inventory='(?P<body>.*?)'$", text)
        if inventory is None:
            self.fail("bootstrap.sh no longer declares a reviewed manifest inventory")
        listed = {line.split(" ", 1)[1] for line in inventory.group("body").splitlines()}
        for relative in model.FLUX_RBAC_PATCH_FILES:
            with self.subTest(patch=relative):
                self.assertIn(relative, listed)

    @staticmethod
    def _bootstrap_contract():
        text = BOOTSTRAP.read_text(encoding="utf-8")
        match = re.search(
            r"<<'PY_FLUX_LIVE_STATE'.*?\n(?P<body>.*?)\nPY_FLUX_LIVE_STATE(?:\n|$)",
            text,
            re.DOTALL,
        )
        if match is None:
            raise AssertionError("missing embedded live-state program")
        definitions = match.group("body").rsplit("\ntry:\n    main()", 1)[0]
        environment = {
            "FLUX_EXPECTED_VERSION": "v2.9.3",
            "FLUX_EXPECTED_SOURCE_IMAGE": "ghcr.io/fluxcd/source-controller:v0@sha256:" + "1" * 64,
            "FLUX_EXPECTED_KUSTOMIZE_IMAGE": "ghcr.io/fluxcd/kustomize-controller:v0@sha256:" + "2" * 64,
            "FLUX_EXPECTED_HELM_IMAGE": "ghcr.io/fluxcd/helm-controller:v0@sha256:" + "3" * 64,
        }
        saved = os.environ.copy()
        os.environ.update(environment)
        try:
            contract = {}
            exec(compile(definitions, "<flux-live-contract>", "exec"), contract)
        finally:
            os.environ.clear()
            os.environ.update(saved)
        return contract


class FluxRbacEnumerationStrictnessTests(unittest.TestCase):
    """The desired-state enumeration must refuse what it cannot follow.

    Under-counting the desired state is how a sufficiency proof lies: an object
    the enumeration never saw needs no permission, so the suite stays green
    while the reconciliation it belongs to is denied on the cluster.
    """

    def build_root(self, kustomization, extra=None):
        directory = tempfile.mkdtemp(prefix="flux-rbac-enumeration.")
        self.addCleanup(shutil.rmtree, directory, True)
        root = Path(directory).resolve()
        path = root / "kubernetes" / "example"
        path.mkdir(parents=True)
        (path / "kustomization.yaml").write_text(kustomization, encoding="utf-8")
        for name, body in (extra or {}).items():
            (path / name).write_text(body, encoding="utf-8")
        return root

    def test_a_generator_or_component_is_refused_rather_than_skipped(self):
        # A configMapGenerator renders a ConfigMap that `resources:` never names,
        # into a namespace whose reconciler may not be able to create one.
        for key, body in (
            ("configMapGenerator", "configMapGenerator:\n  - name: extra\n"),
            ("components", "components:\n  - ../shared\n"),
            ("namespace", "namespace: naranjo-online\n"),
            ("namePrefix", "namePrefix: staged-\n"),
        ):
            root = self.build_root(
                "apiVersion: kustomize.config.k8s.io/v1beta1\n"
                "kind: Kustomization\n"
                "resources:\n  - object.yaml\n" + body,
                {"object.yaml": "apiVersion: v1\nkind: ServiceAccount\n"
                                "metadata:\n  name: example\n  namespace: naranjo-online\n"},
            )
            with self.subTest(key=key):
                with self.assertRaises(AssertionError) as raised:
                    model.objects_applied_by(root, "kubernetes/example")
                self.assertIn(key, str(raised.exception))

    def test_a_path_that_applies_nothing_is_refused(self):
        # `resources: []` silently drops every requirement the path should have
        # contributed, which no assertion downstream can distinguish from
        # "everything here is authorized".
        root = self.build_root(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "resources: []\n"
        )
        with self.assertRaises(AssertionError) as raised:
            model.objects_applied_by(root, "kubernetes/example")
        self.assertIn("no objects enumerated", str(raised.exception))

    def test_the_reviewed_roots_are_all_enumerable(self):
        # The strictness above must not be satisfied by refusing everything.
        for relative in (
            "kubernetes/reconciliation",
            "kubernetes/platform/prerequisites",
            "kubernetes/platform/admission",
            "kubernetes/platform/cloudflare-public/release",
            "kubernetes/websites/naranjo-online",
            "kubernetes/websites/lidersea-com",
        ):
            with self.subTest(root=relative):
                self.assertTrue(model.objects_applied_by(ROOT, relative))


class FluxRbacStructuralValidatorTests(unittest.TestCase):
    """The fast gate's own checks, each shown to fail on the thing it bans.

    A structural check written against one YAML sequence style is decorative on
    files written in the other, and this repository uses both: inline lists in
    the reviewed manifests, indented sequences in the generated export. Every
    mutation below is applied in the style the real file uses.
    """

    REQUIRED_PATHS = (
        "kubernetes/flux-system/access.yaml",
        "kubernetes/flux-system/controllers/kustomization.yaml",
        "kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml",
        "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
        "kubernetes/flux-system/controllers/patches/crd-controller-binding.yaml",
    )

    @classmethod
    def setUpClass(cls):
        cls.validator = load_script("validate_repository.py", module_name="rbac_validator")

    def build_tree(self):
        directory = tempfile.mkdtemp(prefix="flux-rbac-contract.")
        self.addCleanup(shutil.rmtree, directory, True)
        # The validator refuses to read through a reparse point, and the
        # platform temporary root is a symlink on macOS, so the fixture root is
        # resolved before anything is written under it.
        root = Path(directory).resolve()
        for relative in self.REQUIRED_PATHS:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
        return root

    def test_the_reviewed_tree_produces_no_finding(self):
        self.assertEqual(self.validator.flux_rbac_contract_errors(self.build_tree()), [])

    def mutate(self, relative, old, new):
        root = self.build_tree()
        path = root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        return self.validator.flux_rbac_contract_errors(root)

    def test_a_wildcard_is_refused_in_both_yaml_styles(self):
        for replacement in ("    resources: ['*']\n", "    resources:\n      - '*'\n"):
            with self.subTest(style=replacement.strip()):
                errors = self.mutate(
                    "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                    "    resources: [kustomizations]\n",
                    replacement,
                )
                self.assertTrue(any("wildcard RBAC rule" in error for error in errors), errors)

    def test_a_writable_flux_system_secret_grant_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/access.yaml",
            "    resources: [secrets]\n    verbs: [get, list, watch]",
            "    resources: [secrets]\n    verbs: [get, list, watch, update]",
        )
        self.assertTrue(any("must be read-only" in error for error in errors), errors)

    def test_an_unrestricted_impersonate_grant_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/access.yaml",
            "    verbs: [impersonate]\n    resourceNames: [helm-reconciler]\n",
            "    verbs: [impersonate]\n",
        )
        self.assertTrue(
            any("unrestricted impersonate grant" in error for error in errors), errors
        )

    def test_token_creation_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
            "    resources: [kustomizations]\n",
            "    resources:\n      - serviceaccounts/token\n",
        )
        self.assertTrue(
            any("serviceaccounts/token" in error for error in errors), errors
        )

    def test_a_re_broadened_subject_list_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/patches/crd-controller-binding.yaml",
            "  - kind: ServiceAccount\n    name: source-controller\n",
            "  - kind: ServiceAccount\n    name: image-automation-controller\n"
            "    namespace: flux-system\n  - kind: ServiceAccount\n    name: source-controller\n",
        )
        self.assertTrue(
            any("exactly the installed controllers" in error for error in errors), errors
        )

    def test_repointing_the_deletion_patch_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml",
            "$patch: delete\n",
            "",
        )
        self.assertTrue(
            any("delete the binding, not repoint it" in error for error in errors), errors
        )

    def test_an_unwired_patch_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/kustomization.yaml",
            "    path: patches/crd-controller-role.yaml\n",
            "",
        )
        self.assertTrue(
            any("does not apply patches/crd-controller-role.yaml" in error for error in errors),
            errors,
        )

    def test_a_missing_controller_identity_role_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/access.yaml",
            "  name: flux-controller-decryption\n  namespace: flux-system\nrules:",
            "  name: flux-controller-renamed\n  namespace: flux-system\nrules:",
        )
        self.assertTrue(
            any("flux-system/flux-controller-decryption" in error for error in errors), errors
        )

    def test_a_reindented_rule_still_reaches_the_secret_check(self):
        # P3-3, the same vacuity class as commit 2 one axis over: re-indenting a
        # rule is valid YAML that changes nothing about what it grants, and the
        # block splitter used to assume a maximum indent.
        root = self.build_tree()
        path = root / "kubernetes/flux-system/access.yaml"
        text = path.read_text(encoding="utf-8")
        old = (
            "rules:\n"
            '  - apiGroups: [""]\n'
            "    resources: [secrets]\n"
            "    verbs: [get, list, watch]"
        )
        self.assertIn(old, text)
        reindented = (
            "rules:\n"
            '      - apiGroups: [""]\n'
            "        resources: [secrets]\n"
            "        verbs: [get, list, watch, delete]"
        )
        path.write_text(text.replace(old, reindented, 1), encoding="utf-8")
        errors = self.validator.flux_rbac_contract_errors(root)
        self.assertTrue(any("must be read-only" in error for error in errors), errors)

    def test_a_patch_that_targets_the_wrong_object_is_refused(self):
        for relative, old, new, fragment in (
            (
                "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                "kind: ClusterRole\n",
                "kind: Role\n",
                "must target kind ClusterRole",
            ),
            (
                "kubernetes/flux-system/controllers/patches/crd-controller-binding.yaml",
                "  name: crd-controller-flux-system\n",
                "  name: crd-controller-renamed\n",
                "must name crd-controller-flux-system",
            ),
        ):
            with self.subTest(patch=Path(relative).name):
                errors = self.mutate(relative, old, new)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_a_missing_patch_or_install_root_or_authored_file_is_refused(self):
        for relative, fragment in (
            (
                "kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml",
                "Flux RBAC narrowing patch is missing: cluster-reconciler.yaml",
            ),
            (
                "kubernetes/flux-system/controllers/kustomization.yaml",
                "Flux controller install root is missing",
            ),
            (
                "kubernetes/flux-system/access.yaml",
                "authored Flux RBAC file is missing",
            ),
        ):
            root = self.build_tree()
            (root / relative).unlink()
            with self.subTest(removed=relative):
                errors = self.validator.flux_rbac_contract_errors(root)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_a_hand_written_cluster_admin_binding_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/access.yaml",
            "  name: flux-controller-runtime\n  namespace: flux-system\nrules:",
            "  name: cluster-admin\n  namespace: flux-system\nrules:",
        )
        self.assertTrue(any("cluster-admin binding" in error for error in errors), errors)


class YamlSubsetReaderTests(unittest.TestCase):
    """The reader is load-bearing, so its refusals are tested like a gate."""

    def test_block_mappings_sequences_and_flow_sequences(self):
        documents = model.parse_documents(
            "apiVersion: v1\n"
            "kind: Role\n"
            "metadata:\n"
            "  name: example  # trailing comment\n"
            "  namespace: flux-system\n"
            "rules:\n"
            "  - apiGroups: [\"\"]\n"
            "    resources: [secrets, configmaps]\n"
            "    verbs: [get]\n"
            "    resourceNames:\n"
            "      - sops-age\n"
            "---\n"
            "kind: Other\n"
            "spec:\n"
            "  suspend: true\n"
            "  replicas: 2\n"
            "  selector: {}\n"
        )
        self.assertEqual(len(documents), 2)
        self.assertEqual(documents[0]["metadata"]["name"], "example")
        self.assertEqual(
            documents[0]["rules"],
            [
                {
                    "apiGroups": [""],
                    "resources": ["secrets", "configmaps"],
                    "verbs": ["get"],
                    "resourceNames": ["sops-age"],
                }
            ],
        )
        self.assertIs(documents[1]["spec"]["suspend"], True)
        self.assertEqual(documents[1]["spec"]["replicas"], 2)
        self.assertEqual(documents[1]["spec"]["selector"], {})

    def test_block_scalars_are_preserved(self):
        documents = model.parse_documents("spec:\n  ignore: |\n    /*\n    !/kubernetes\n")
        self.assertEqual(documents[0]["spec"]["ignore"], "/*\n!/kubernetes\n")

    def test_a_hash_inside_a_quoted_scalar_is_not_a_comment(self):
        documents = model.parse_documents('metadata:\n  name: "a#b"\n')
        self.assertEqual(documents[0]["metadata"]["name"], "a#b")

    def test_unsupported_constructs_raise_instead_of_being_guessed(self):
        for source in (
            "base: &anchor\n  a: b\n",
            "copy:\n  <<: *anchor\n",
            "spec:\n\tname: tabbed\n",
            "spec:\n  selector: {matchLabels: {a: b}}\n",
            "spec:\n  values: [a,\n",
        ):
            with self.subTest(source=source):
                with self.assertRaises(YamlSubsetError):
                    model.parse_documents(source)

    def test_an_unmodelled_kind_is_refused_rather_than_ignored(self):
        with self.assertRaises(AssertionError):
            model._kind_tuple("StatefulSet")


class FluxRbacAuthorizerSemanticsTests(unittest.TestCase):
    """The authorizer's own rules, so a sufficiency pass cannot be vacuous."""

    def setUp(self):
        self.authorizer = Authorizer.from_documents(
            [
                {
                    "kind": "Role",
                    "metadata": {"name": "reader", "namespace": "one"},
                    "rules": [
                        {
                            "apiGroups": [""],
                            "resources": ["secrets"],
                            "verbs": ["get"],
                            "resourceNames": ["named"],
                        }
                    ],
                },
                {
                    "kind": "RoleBinding",
                    "metadata": {"name": "reader", "namespace": "one"},
                    "roleRef": {"kind": "Role", "name": "reader"},
                    "subjects": [
                        {"kind": "ServiceAccount", "name": "agent", "namespace": "flux-system"}
                    ],
                },
            ]
        )
        self.subject = Subject("flux-system", "agent")

    def test_resource_names_restrict_named_requests(self):
        self.assertTrue(
            self.authorizer.allows(self.subject, "get", "", "secrets", "one", "named")
        )
        self.assertFalse(
            self.authorizer.allows(self.subject, "get", "", "secrets", "one", "other")
        )

    def test_a_request_without_a_name_cannot_use_a_named_rule(self):
        # This is why the SOPS key read is namespace-scoped rather than
        # name-scoped: `list` carries no object name.
        self.assertFalse(self.authorizer.allows(self.subject, "get", "", "secrets", "one"))

    def test_a_rolebinding_does_not_reach_another_namespace_or_cluster_scope(self):
        self.assertFalse(
            self.authorizer.allows(self.subject, "get", "", "secrets", "two", "named")
        )
        self.assertFalse(
            self.authorizer.allows(self.subject, "get", "", "secrets", None, "named")
        )

    def test_a_binding_to_a_role_outside_the_reviewed_set_is_refused(self):
        """P2-1: an unresolvable roleRef must raise, never grant nothing.

        Built-in roles — cluster-admin, admin, edit, any system:* — are never
        among the parsed documents, so treating an unresolvable reference as an
        empty rule set made the model report "denied" for authority the cluster
        actually grants. That is a false green in the only direction that
        matters.
        """

        for role in ("admin", "cluster-admin", "edit", "system:controller:generic"):
            with self.subTest(role=role):
                with self.assertRaises(AssertionError) as raised:
                    Authorizer.from_documents(
                        [
                            {
                                "kind": "RoleBinding",
                                "metadata": {"name": "borrowed", "namespace": "kube-system"},
                                "roleRef": {"kind": "ClusterRole", "name": role},
                                "subjects": [
                                    {
                                        "kind": "ServiceAccount",
                                        "name": "kustomize-controller",
                                        "namespace": "flux-system",
                                    }
                                ],
                            }
                        ]
                    )
                self.assertIn(role, str(raised.exception))

    def test_group_and_user_subject_forms_reach_a_service_account(self):
        """P2-2: a binding need not name the account to reach it.

        The live-state verifier already refuses group-shaped bindings that reach
        a protected account. Before this, the model saw only `kind:
        ServiceAccount`, so a Role bound to `Group: system:serviceaccounts:
        flux-system` granted authority the model reported as denied — the model
        was strictly weaker than the verifier it claims to mirror.
        """

        rules = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}]
        for subject_entry in (
            {"kind": "Group", "name": "system:serviceaccounts:flux-system",
             "apiGroup": "rbac.authorization.k8s.io"},
            {"kind": "Group", "name": "system:serviceaccounts",
             "apiGroup": "rbac.authorization.k8s.io"},
            {"kind": "Group", "name": "system:authenticated",
             "apiGroup": "rbac.authorization.k8s.io"},
            {"kind": "User", "name": "system:serviceaccount:flux-system:kustomize-controller",
             "apiGroup": "rbac.authorization.k8s.io"},
        ):
            authorizer = Authorizer.from_documents(
                [
                    {
                        "kind": "Role",
                        "metadata": {"name": "borrowed", "namespace": "kube-system"},
                        "rules": rules,
                    },
                    {
                        "kind": "RoleBinding",
                        "metadata": {"name": "borrowed", "namespace": "kube-system"},
                        "roleRef": {"kind": "Role", "name": "borrowed"},
                        "subjects": [subject_entry],
                    },
                ]
            )
            with self.subTest(subject=subject_entry["name"]):
                self.assertTrue(
                    authorizer.allows(
                        KUSTOMIZE_CONTROLLER, "create", "", "secrets", "kube-system"
                    )
                )

    def test_a_group_for_another_namespace_does_not_reach_this_account(self):
        authorizer = Authorizer.from_documents(
            [
                {
                    "kind": "Role",
                    "metadata": {"name": "elsewhere", "namespace": "kube-system"},
                    "rules": [
                        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}
                    ],
                },
                {
                    "kind": "RoleBinding",
                    "metadata": {"name": "elsewhere", "namespace": "kube-system"},
                    "roleRef": {"kind": "Role", "name": "elsewhere"},
                    "subjects": [
                        {
                            "kind": "Group",
                            "name": "system:serviceaccounts:kyverno",
                            "apiGroup": "rbac.authorization.k8s.io",
                        }
                    ],
                },
            ]
        )
        self.assertFalse(
            authorizer.allows(KUSTOMIZE_CONTROLLER, "create", "", "secrets", "kube-system")
        )

    def test_an_unbound_subject_is_denied(self):
        self.assertFalse(
            self.authorizer.allows(
                Subject("flux-system", "stranger"), "get", "", "secrets", "one", "named"
            )
        )


if __name__ == "__main__":
    unittest.main()
