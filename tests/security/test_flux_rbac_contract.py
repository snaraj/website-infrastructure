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
from typing import NamedTuple

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
    ("Kustomization", "admission", "kyverno.io", "clusterpolicies"),
    ("Kustomization", "admission", "admissionregistration.k8s.io",
     "validatingwebhookconfigurations"),
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
    #
    # The owner is a (kind, name) PAIR, not a name: a Kustomization and a
    # HelmRelease may share a name — both sites do — and each is suspended by
    # its own spec.suspend. Keyed by name alone, unsuspending the
    # naranjo-online HelmRelease left the still-suspended naranjo-online
    # Kustomization satisfying the check, and the mutation survived.
    ("Kustomization", "admission", "apps", "replicasets"),
    ("Kustomization", "admission", "", "pods"),
    ("HelmRelease", "cloudflare-public", "apps", "replicasets"),
    ("HelmRelease", "cloudflare-public", "", "pods"),
    ("HelmRelease", "naranjo-online", "apps", "replicasets"),
    ("HelmRelease", "naranjo-online", "", "pods"),
    ("HelmRelease", "lidersea-com", "apps", "replicasets"),
    ("HelmRelease", "lidersea-com", "", "pods"),
}

# ---------------------------------------------------------------------------
# Declared slack: the complement of the derivation, row by row
# ---------------------------------------------------------------------------
#
# A deny-list only refuses what somebody thought to enumerate. The narrowness
# claim is made real by the opposite assertion — every request the committed
# RBAC GRANTS is either one the derivation asks for or one of the rows below,
# each with the reason it is granted anyway. The comparison is exact in both
# directions, so a new grant fails until it is derived or declared, and a
# declared row fails once the grant it describes is gone.
#
# Written literally rather than computed: a table generated from the same
# manifests it is supposed to bound would agree with anything.


class SlackRow(NamedTuple):
    """One class of granted-but-underived authority, with its justification."""

    subject: Subject
    #: Namespaces the grant is confined to, or ``(None,)`` for cluster scope.
    scopes: tuple
    group: str
    resources: tuple
    verbs: tuple
    reason: str


def _slack_requests(rows):
    requests = set()
    for row in rows:
        for scope in row.scopes:
            for resource in row.resources:
                for verb in row.verbs:
                    requests.add(
                        model.GrantedRequest(
                            row.subject, scope, verb, row.group, resource, None
                        )
                    )
    return requests


SOURCE_GROUP = "source.toolkit.fluxcd.io"
KUSTOMIZE_GROUP = "kustomize.toolkit.fluxcd.io"
HELM_GROUP = "helm.toolkit.fluxcd.io"
NETWORKING_GROUP = "networking.k8s.io"
CLUSTER = (None,)

# Reason 1 — THE CONFUSED DEPUTY, and the one residual in this table that is a
# real authorization finding rather than surplus verbs. `crd-controller-flux-system`
# is one ClusterRole bound to all three controllers, so each controller holds
# the other two's write authority over their execution objects and sources.
# Splitting it into three role/binding pairs is tracked as its own change; until
# then the residual is enumerated here exactly, so it cannot grow silently and
# the split can be verified by watching these rows disappear.
SHARED_ROLE = (
    "the shared crd-controller-flux-system ClusterRole is bound to all three "
    "controllers, so this controller holds authority derived for another one "
    "(tracked: per-controller role split, issue #98)"
)
# Reason 2 — the generated export grants a source kind whose reconciler
# registration at the pinned version this repository cannot confirm, so it is
# declared rather than asserted as required in REGISTERED_CONTROLLERS.
UNCONFIRMED_KIND = (
    "the generated export grants ExternalArtifact, a kind no reviewed object "
    "uses and whose reconciler registration at the pinned version this "
    "repository cannot confirm; declared rather than asserted as required"
)
# Reason 3 — APPLY_VERBS deliberately omits `watch`: Flux polls the objects it
# manages. The Roles grant one verb set per rule rather than trimming `watch`
# out of each, so every applied resource carries it.
APPLIED_WATCH = (
    "APPLY_VERBS omits watch because Flux polls managed objects; the Role "
    "grants one verb set per rule rather than trimming watch per resource"
)

DECLARED_SLACK = (
    # ---- the shared controller ClusterRole -------------------------------
    SlackRow(SOURCE_CONTROLLER, CLUSTER, KUSTOMIZE_GROUP,
             ("kustomizations",), ("get", "list", "watch", "update", "patch"), SHARED_ROLE),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, KUSTOMIZE_GROUP,
             ("kustomizations/status",), ("get", "patch", "update"), SHARED_ROLE),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, KUSTOMIZE_GROUP,
             ("kustomizations/finalizers",), ("update",), SHARED_ROLE),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, HELM_GROUP,
             ("helmreleases",), ("get", "list", "watch", "update", "patch"), SHARED_ROLE),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, HELM_GROUP,
             ("helmreleases/status",), ("get", "patch", "update"), SHARED_ROLE),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, HELM_GROUP,
             ("helmreleases/finalizers",), ("update",), SHARED_ROLE),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("helmcharts",), ("create", "delete"), SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, HELM_GROUP,
             ("helmreleases",), ("get", "list", "watch", "update", "patch"), SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, HELM_GROUP,
             ("helmreleases/status",), ("get", "patch", "update"), SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, HELM_GROUP,
             ("helmreleases/finalizers",), ("update",), SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("buckets", "helmrepositories", "ocirepositories"),
             ("get", "list", "watch", "update", "patch"), SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("gitrepositories",), ("update", "patch"), SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("helmcharts",), ("get", "list", "watch", "create", "update", "patch", "delete"),
             SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("buckets/status", "gitrepositories/status", "helmcharts/status",
              "helmrepositories/status", "ocirepositories/status"),
             ("get", "patch", "update"), SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("buckets/finalizers", "gitrepositories/finalizers", "helmcharts/finalizers",
              "helmrepositories/finalizers", "ocirepositories/finalizers"),
             ("update",), SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, KUSTOMIZE_GROUP,
             ("kustomizations",), ("get", "list", "watch", "update", "patch"), SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, KUSTOMIZE_GROUP,
             ("kustomizations/status",), ("get", "patch", "update"), SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, KUSTOMIZE_GROUP,
             ("kustomizations/finalizers",), ("update",), SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("buckets", "helmrepositories"),
             ("get", "list", "watch", "update", "patch"), SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("gitrepositories", "ocirepositories"), ("update", "patch"), SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP, ("helmcharts",), ("watch",), SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("buckets/status", "gitrepositories/status", "helmcharts/status",
              "helmrepositories/status", "ocirepositories/status"),
             ("get", "patch", "update"), SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("buckets/finalizers", "gitrepositories/finalizers", "helmcharts/finalizers",
              "helmrepositories/finalizers", "ocirepositories/finalizers"),
             ("update",), SHARED_ROLE),
    # ---- a kind the export grants and this repository does not use --------
    SlackRow(SOURCE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts",), ("get", "list", "watch", "update", "patch"),
             UNCONFIRMED_KIND),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts/status",), ("get", "patch", "update"), UNCONFIRMED_KIND),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts/finalizers",), ("update",), UNCONFIRMED_KIND),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts",), ("get", "list", "watch", "update", "patch"),
             UNCONFIRMED_KIND + "; " + SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts/status",), ("get", "patch", "update"),
             UNCONFIRMED_KIND + "; " + SHARED_ROLE),
    SlackRow(KUSTOMIZE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts/finalizers",), ("update",),
             UNCONFIRMED_KIND + "; " + SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts",), ("get", "list", "watch", "update", "patch"),
             UNCONFIRMED_KIND + "; " + SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts/status",), ("get", "patch", "update"),
             UNCONFIRMED_KIND + "; " + SHARED_ROLE),
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts/finalizers",), ("update",),
             UNCONFIRMED_KIND + "; " + SHARED_ROLE),
    # ---- controller runtime ----------------------------------------------
    SlackRow(SOURCE_CONTROLLER, ("flux-system",), "coordination.k8s.io", ("leases",),
             ("list", "watch", "patch", "delete"),
             "client-go's LeaseLock issues get/create/update only; the surplus "
             "matches the verb set the generated export grants"),
    SlackRow(KUSTOMIZE_CONTROLLER, ("flux-system",), "coordination.k8s.io", ("leases",),
             ("list", "watch", "patch", "delete"),
             "client-go's LeaseLock issues get/create/update only; the surplus "
             "matches the verb set the generated export grants"),
    SlackRow(HELM_CONTROLLER, ("flux-system",), "coordination.k8s.io", ("leases",),
             ("list", "watch", "patch", "delete"),
             "client-go's LeaseLock issues get/create/update only; the surplus "
             "matches the verb set the generated export grants"),
    SlackRow(KUSTOMIZE_CONTROLLER, ("flux-system",), "", ("secrets",),
             ("get", "list", "watch"),
             "the SOPS age key is the only Secret derived here, but resourceNames "
             "cannot restrict list or watch, so the read is granted namespace-wide "
             "in a namespace designed to hold no other Secret"),
    # ---- reconciler Roles: surplus that predates this change --------------
    SlackRow(Subject("flux-system", "platform-prerequisites-reconciler"),
             ("cloudflare-public", "naranjo-online", "lidersea-com"), "",
             ("serviceaccounts",),
             ("get", "list", "watch", "create", "update", "patch", "delete"),
             "pre-existing Role slack: this path applies only NetworkPolicies, "
             "ResourceQuotas and LimitRanges, and the namespace ServiceAccounts "
             "are bootstrap-owned"),
    SlackRow(Subject("flux-system", "admission-reconciler"), ("kyverno",), "",
             ("configmaps",),
             ("get", "list", "watch", "create", "update", "patch", "delete"),
             "pre-existing Role slack: the staged admission path declares no "
             "ConfigMap today, and the Role is not widened for the promotion"),
    SlackRow(Subject("flux-system", "platform-services-reconciler"),
             ("cloudflare-public",), "", ("secrets",),
             ("get", "list", "watch", "create", "update", "patch", "delete"),
             "the connector's tunnel-token Secrets are deferred to the operator-run "
             "SOPS custody change, so the grant precedes the objects it applies"),
    SlackRow(Subject("cloudflare-public", "helm-reconciler"), ("cloudflare-public",), "",
             ("configmaps", "services"),
             ("get", "list", "watch", "create", "update", "patch", "delete"),
             "pre-existing Role slack: the connector chart renders neither a "
             "ConfigMap nor a Service, and the Role is shared in shape with the "
             "two site namespaces"),
    SlackRow(Subject("naranjo-online", "helm-reconciler"), ("naranjo-online",), "",
             ("configmaps",),
             ("get", "list", "watch", "create", "update", "patch", "delete"),
             "pre-existing Role slack: the site chart's declared kinds contain no "
             "ConfigMap"),
    SlackRow(Subject("lidersea-com", "helm-reconciler"), ("lidersea-com",), "",
             ("configmaps",),
             ("get", "list", "watch", "create", "update", "patch", "delete"),
             "pre-existing Role slack: the site chart's declared kinds contain no "
             "ConfigMap"),
    # ---- `watch` on applied objects --------------------------------------
    SlackRow(Subject("flux-system", "root-reconciler"), ("flux-system",),
             KUSTOMIZE_GROUP, ("kustomizations",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "platform-prerequisites-reconciler"),
             ("cloudflare-public", "naranjo-online", "lidersea-com"), "",
             ("resourcequotas", "limitranges"), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "platform-prerequisites-reconciler"),
             ("cloudflare-public", "naranjo-online", "lidersea-com", "kyverno"),
             NETWORKING_GROUP, ("networkpolicies",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "admission-reconciler"), ("kyverno",), "",
             ("serviceaccounts", "services"), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "admission-reconciler"), ("kyverno",), "apps",
             ("deployments",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "platform-services-reconciler"),
             ("cloudflare-public",), HELM_GROUP, ("helmreleases",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "platform-services-reconciler"),
             ("cloudflare-public",), SOURCE_GROUP, ("gitrepositories",), ("watch",),
             APPLIED_WATCH),
    SlackRow(Subject("flux-system", "naranjo-online-reconciler"), ("naranjo-online",),
             HELM_GROUP, ("helmreleases",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "naranjo-online-reconciler"), ("naranjo-online",),
             SOURCE_GROUP, ("ocirepositories",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "lidersea-com-reconciler"), ("lidersea-com",),
             HELM_GROUP, ("helmreleases",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("flux-system", "lidersea-com-reconciler"), ("lidersea-com",),
             SOURCE_GROUP, ("ocirepositories",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("cloudflare-public", "helm-reconciler"), ("cloudflare-public",), "",
             ("secrets", "serviceaccounts"), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("naranjo-online", "helm-reconciler"), ("naranjo-online",), "",
             ("secrets", "serviceaccounts", "services"), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("lidersea-com", "helm-reconciler"), ("lidersea-com",), "",
             ("secrets", "serviceaccounts", "services"), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("cloudflare-public", "helm-reconciler"), ("cloudflare-public",),
             "apps", ("deployments",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("naranjo-online", "helm-reconciler"), ("naranjo-online",),
             "apps", ("deployments",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("lidersea-com", "helm-reconciler"), ("lidersea-com",),
             "apps", ("deployments",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("cloudflare-public", "helm-reconciler"), ("cloudflare-public",),
             NETWORKING_GROUP, ("networkpolicies",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("naranjo-online", "helm-reconciler"), ("naranjo-online",),
             NETWORKING_GROUP, ("networkpolicies",), ("watch",), APPLIED_WATCH),
    SlackRow(Subject("lidersea-com", "helm-reconciler"), ("lidersea-com",),
             NETWORKING_GROUP, ("networkpolicies",), ("watch",), APPLIED_WATCH),
)

DECLARED_SLACK_REQUESTS = _slack_requests(DECLARED_SLACK)

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
        cls.derived = derived
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
                ("Kustomization", "flux-system"),
                ("Kustomization", "platform-prerequisites"),
                ("Kustomization", "admission"),
                ("Kustomization", "platform-services"),
                ("Kustomization", "naranjo-online"),
                ("Kustomization", "lidersea-com"),
                ("HelmRelease", "naranjo-online"),
                ("HelmRelease", "lidersea-com"),
                ("HelmRelease", "cloudflare-public"),
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
            requirement.owner + (requirement.group, requirement.resource)
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
        for kind, name, group, resource in sorted(DECLARED_INSUFFICIENCIES):
            with self.subTest(owner="{}/{}".format(kind, name), resource=resource):
                self.assertIn(
                    (kind, name),
                    suspended,
                    "{} {} is no longer suspended but still cannot use {}/{}: "
                    "unsuspending it would fail halfway".format(
                        kind, name, group or "core", resource
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
                ("Kustomization", "flux-system"),
                ("Kustomization", "platform-prerequisites"),
                ("Kustomization", "admission"),
                ("Kustomization", "platform-services"),
                ("Kustomization", "naranjo-online"),
                ("Kustomization", "lidersea-com"),
                ("HelmRelease", "naranjo-online"),
                ("HelmRelease", "lidersea-com"),
                ("HelmRelease", "cloudflare-public"),
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

    def test_leader_election_is_required_of_every_pinned_controller(self):
        """The grant whose absence is a crashloop, not a half-reconciliation.

        All three pinned Deployments run with ``--enable-leader-election``, so
        each takes a Lease in flux-system before it reconciles anything. The
        requirement is read out of the export's own arguments, so deleting the
        Lease rule from ``access.yaml`` (and from the bootstrap mirror) fails
        here rather than at startup on the cluster.
        """

        electing = model.leader_election_controllers(ROOT)
        self.assertEqual(
            electing,
            [("flux-system", name) for name in sorted(INSTALLED_CONTROLLERS)],
        )
        leases = [
            requirement
            for requirement in self.controller_requirements
            if requirement.resource == "leases"
        ]
        self.assertEqual(len(leases), len(electing) * len(model.LEADER_ELECTION_VERBS))
        for requirement in leases:
            with self.subTest(subject=str(requirement.subject), verb=requirement.verb):
                self.assertEqual(requirement.namespace, "flux-system")
                self.assertTrue(
                    self.authorizer.allows(
                        requirement.subject, requirement.verb, "coordination.k8s.io",
                        "leases", "flux-system",
                    ),
                    requirement.describe(),
                )

    def test_the_controllers_own_runtime_authority_is_required(self):
        """Controller-owned ConfigMaps: declared, and therefore assertable.

        Nothing the desired state applies implies this authority, so a
        desired-state-only derivation reaches zero requirements for it and the
        whole `flux-controller-runtime` Role could be deleted with a green
        suite. It is declared in CONTROLLER_RUNTIME_GRANTS instead, which is
        what makes the deletion fail.
        """

        runtime = [
            requirement
            for requirement in self.controller_requirements
            if requirement.owner == ("Controller", "runtime")
        ]
        self.assertEqual(
            {requirement.resource for requirement in runtime},
            {"configmaps", "configmaps/status"},
        )
        self.assertEqual(
            {str(requirement.subject) for requirement in runtime},
            {"system:serviceaccount:flux-system:" + name for name in INSTALLED_CONTROLLERS},
        )
        for requirement in runtime:
            with self.subTest(
                subject=str(requirement.subject),
                verb=requirement.verb,
                resource=requirement.resource,
            ):
                self.assertEqual(requirement.namespace, "flux-system")
                self.assertTrue(
                    self.authorizer.allows(
                        requirement.subject, requirement.verb, requirement.group,
                        requirement.resource, requirement.namespace,
                    ),
                    requirement.describe(),
                )

    def test_every_registered_controller_kind_is_authorized_without_an_object(self):
        """A kind with no object today is still a running informer.

        source-controller registers a reconciler per source kind whatever the
        desired state contains, and every controller runs with
        ``--watch-all-namespaces=true``, so each informer is a cluster-wide
        list/watch that no Role can satisfy. Deriving these from the registered
        kinds rather than from the object inventory is what stops "there is no
        Bucket in this repository" from reading as "the Bucket grant is unused".
        """

        self.assertEqual(
            model.cluster_watching_controllers(ROOT),
            [("flux-system", name) for name in sorted(INSTALLED_CONTROLLERS)],
        )
        registered = [
            requirement
            for requirement in self.controller_requirements
            if requirement.owner == ("Controller", "registered")
        ]
        self.assertEqual(
            {(str(requirement.subject), requirement.resource) for requirement in registered}
            & {
                ("system:serviceaccount:flux-system:source-controller", "buckets"),
                ("system:serviceaccount:flux-system:source-controller", "helmrepositories"),
            },
            {
                ("system:serviceaccount:flux-system:source-controller", "buckets"),
                ("system:serviceaccount:flux-system:source-controller", "helmrepositories"),
            },
        )
        for requirement in registered:
            with self.subTest(
                subject=str(requirement.subject),
                verb=requirement.verb,
                resource=requirement.resource,
            ):
                self.assertIsNone(requirement.namespace, "the informer is cluster-wide")
                self.assertTrue(
                    self.authorizer.allows(
                        requirement.subject, requirement.verb, requirement.group,
                        requirement.resource, None,
                    ),
                    requirement.describe(),
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
        cls.derived = model.derive_requirements(ROOT)
        subjects, namespaces = model.rbac_subjects_and_namespaces(cls.documents)
        cls.subjects = subjects
        cls.namespaces = namespaces
        cls.granted = model.granted_requests(cls.authorizer, subjects, namespaces)

    def test_every_granted_request_is_derived_or_declared_slack(self):
        """granted ⊆ derived ∪ declared slack — the narrowness proof itself.

        Everything else in this class is a deny-list, and a deny-list only
        refuses what somebody thought to write down: `+delete` on kustomizations,
        a cluster-wide `pods/exec` read, a `batch/jobs` write, or a brand-new
        Role granting Deployment writes to a controller all pass every other
        assertion here — and pass the bootstrap mirror too, once the same
        mutation is applied to the mirror. This is the assertion that fails.

        The comparison is exact in BOTH directions on purpose. Slack that is no
        longer granted fails exactly like slack that was never declared: a stale
        justification is the failure mode this repository treats as a defect
        (delivery-lane requirement 5).
        """

        # The enumeration itself is pinned: an empty or tiny granted set would
        # satisfy the subset assertion while proving nothing.
        self.assertGreater(len(self.granted), 500)
        self.assertEqual(
            {str(subject) for subject in self.subjects} & {
                "system:serviceaccount:flux-system:source-controller",
                "system:serviceaccount:flux-system:kustomize-controller",
                "system:serviceaccount:flux-system:helm-controller",
            },
            {
                "system:serviceaccount:flux-system:source-controller",
                "system:serviceaccount:flux-system:kustomize-controller",
                "system:serviceaccount:flux-system:helm-controller",
            },
        )
        self.assertEqual(
            self.namespaces,
            {"flux-system", "cloudflare-public", "naranjo-online", "lidersea-com", "kyverno"},
        )

        ungrounded = model.ungrounded_grants(self.granted, self.derived)
        self.assertEqual(
            sorted(
                request.describe() for request in ungrounded - DECLARED_SLACK_REQUESTS
            ),
            [],
            "the committed RBAC grants authority the derivation does not ask for; "
            "derive it, remove it, or declare it in DECLARED_SLACK with the reason "
            "it is granted anyway",
        )
        self.assertEqual(
            sorted(
                request.describe() for request in DECLARED_SLACK_REQUESTS - ungrounded
            ),
            [],
            "a declared-slack row no longer describes a granted request: remove the "
            "row, because a stale justification hides the next real one",
        )

    def test_the_declared_slack_is_bounded_and_attributed(self):
        # The inventory is only useful while it is small enough to read and
        # every row carries a reason. Both are asserted so the table cannot
        # quietly become the place authority goes to hide.
        self.assertLess(len(DECLARED_SLACK_REQUESTS), len(self.granted) // 2)
        for row in DECLARED_SLACK:
            with self.subTest(subject=str(row.subject), resources=row.resources):
                self.assertTrue(row.verbs and row.resources and row.scopes)
                self.assertGreater(len(row.reason), 40, "every slack row states why")
        # The confused-deputy residual is the one finding in the table rather
        # than surplus verbs, so it is counted separately: it may shrink to zero
        # when the shared role is split, and it must never grow silently.
        shared = _slack_requests(
            tuple(row for row in DECLARED_SLACK if SHARED_ROLE in row.reason)
        )
        self.assertEqual(len(shared), 135)
        self.assertEqual(
            {str(request.subject) for request in shared},
            {
                "system:serviceaccount:flux-system:source-controller",
                "system:serviceaccount:flux-system:kustomize-controller",
                "system:serviceaccount:flux-system:helm-controller",
            },
        )

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
        expected_roles = contract["access_role_rules"]()
        # EXACT set equality, in both directions. `assertIn` alone checked only
        # that every mirrored Role exists in the manifests, so DELETING a Role
        # from the mirror left the suite green — and a Role absent from the
        # mirror is a Role `--verify` never compares against anything, which is
        # the live half of this whole proof.
        self.assertEqual(set(roles), set(expected_roles))
        for key, expected in expected_roles.items():
            with self.subTest(role=key):
                self.assertEqual(
                    normalize_rules(roles[key].get("rules")), normalize_rules(expected)
                )

        cluster_roles = {
            document["metadata"]["name"]: document
            for document in documents
            if document.get("kind") == "ClusterRole"
        }
        expected_cluster_roles = contract["cluster_role_rules"]()
        self.assertEqual(set(cluster_roles), set(expected_cluster_roles))
        for name, expected in expected_cluster_roles.items():
            with self.subTest(cluster_role=name):
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

    def test_every_role_a_verified_binding_names_is_itself_verified(self):
        """The mirror's own closure, which is what `--verify` can rely on live.

        Exact set equality above is only available here, against the reviewed
        manifests; live, `kubectl get roles --all-namespaces` returns the whole
        cluster's Roles, so the verifier cannot compare sets. What it CAN
        require — and now does, in `check_rbac` — is that every Role and
        ClusterRole named by a binding it verifies is itself in the rules
        mirror. Without that, deleting a Role from the mirror leaves its binding
        checked, its subjects checked, and its RULES unchecked: the live object
        could grant anything at all.
        """

        contract = self._bootstrap_contract()
        access_roles = contract["access_role_rules"]()
        cluster_roles = contract["cluster_role_rules"]()
        checked = 0
        for (namespace, _), expected in contract["expected_bindings"]().items():
            role_ref = expected[0]
            with self.subTest(binding=(namespace, role_ref["name"])):
                self.assertEqual(role_ref["kind"], "Role")
                self.assertIn((namespace, role_ref["name"]), access_roles)
                checked += 1
        for name, expected in contract["expected_cluster_bindings"]().items():
            role_ref = expected[0]
            with self.subTest(cluster_binding=name):
                self.assertEqual(role_ref["kind"], "ClusterRole")
                self.assertIn(role_ref["name"], cluster_roles)
                checked += 1
        self.assertEqual(checked, 19)

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

    def test_a_remote_base_is_refused_by_name(self):
        # `- https://github.com/…?ref=v1` parses as a mapping in this reader, so
        # it used to reach `Path / dict` and die as a TypeError — fail-closed,
        # but with a traceback that names nothing. It refuses by name now.
        root = self.build_root(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "resources:\n"
            "  - https://github.com/example/repository.git\n"
        )
        with self.assertRaises(AssertionError) as raised:
            model.objects_applied_by(root, "kubernetes/example")
        self.assertIn("Remote bases are refused", str(raised.exception))

    def test_a_chart_template_in_a_subdirectory_is_not_invisible(self):
        # Helm renders every template under `templates/` at any depth. A
        # single-level glob made `templates/jobs/cronjob.yaml` contribute
        # nothing while the identical file one level up raised "unmodelled
        # kind" — so a chart could grow a whole workload the derivation never
        # saw, purely by living in a subdirectory.
        directory = tempfile.mkdtemp(prefix="flux-rbac-chart.")
        self.addCleanup(shutil.rmtree, directory, True)
        root = Path(directory).resolve()
        nested = root / "chart" / "templates" / "jobs"
        nested.mkdir(parents=True)
        (nested / "cronjob.yaml").write_text(
            "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: example\n",
            encoding="utf-8",
        )
        self.assertEqual(model.chart_kinds(root, "chart"), ["CronJob"])
        # And an unmodelled kind is what the derivation then refuses.
        with self.assertRaises(AssertionError) as raised:
            model._kind_tuple("CronJob")
        self.assertIn("unmodelled kind", str(raised.exception))

    def test_a_custom_resource_outside_the_known_directories_is_still_found(self):
        # The enumeration follows the reconciliation graph rather than globbing
        # known directories. A HelmRelease added under a reconciled path that no
        # glob covers reconciles for real — and names a ServiceAccount
        # helm-controller may not be able to impersonate — so it must appear in
        # the derivation wherever it lives.
        found = model.flux_custom_resources(ROOT)
        self.assertEqual(len(found.kustomizations), 6)
        self.assertEqual(len(found.helm_releases), 3)
        self.assertEqual(len(found.sources), 4)
        directory = tempfile.mkdtemp(prefix="flux-rbac-graph.")
        self.addCleanup(shutil.rmtree, directory, True)
        root = Path(directory).resolve()
        for relative in (
            "kubernetes/flux-system/gotk-sync.yaml",
            "kubernetes/reconciliation",
            "kubernetes/websites",
            "kubernetes/platform",
            "kubernetes/flux-system/controllers",
            "policies/kyverno",
        ):
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy(source, target)
        extra = root / "kubernetes/websites/naranjo-online/extra"
        extra.mkdir()
        (extra / "release.yaml").write_text(
            "apiVersion: helm.toolkit.fluxcd.io/v2\n"
            "kind: HelmRelease\n"
            "metadata:\n"
            "  name: extra\n"
            "  namespace: naranjo-online\n"
            "spec:\n"
            "  interval: 10m0s\n"
            "  serviceAccountName: extra-reconciler\n"
            "  suspend: true\n"
            "  chartRef:\n"
            "    kind: OCIRepository\n"
            "    name: naranjo-online-chart\n",
            encoding="utf-8",
        )
        index = root / "kubernetes/websites/naranjo-online/kustomization.yaml"
        index.write_text(
            index.read_text(encoding="utf-8") + "  - extra/release.yaml\n", encoding="utf-8"
        )
        reached = model.flux_custom_resources(root)
        self.assertEqual(len(reached.helm_releases), 4)
        self.assertIn(
            "extra", {release["metadata"]["name"] for release in reached.helm_releases}
        )

    def test_a_flux_custom_resource_the_walk_cannot_classify_is_refused(self):
        # Fail closed on the reconciliation inputs, not just on the objects: an
        # ImageUpdateAutomation or a Receiver selects what runs and under whose
        # identity, so treating one as an ordinary applied object would leave
        # its controller-side authority underived.
        root = self.build_root(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "resources:\n  - automation.yaml\n",
            {
                "automation.yaml": "apiVersion: image.toolkit.fluxcd.io/v1beta2\n"
                "kind: ImageUpdateAutomation\n"
                "metadata:\n  name: example\n  namespace: flux-system\n",
            },
        )
        documents = model.load_documents(root / "kubernetes/example/automation.yaml")
        with self.assertRaises(AssertionError) as raised:
            model._classify_flux_document(documents[0], "automation.yaml", [], [], [])
        self.assertIn("cannot classify", str(raised.exception))

    def test_an_argument_patch_that_could_drop_a_flag_is_refused(self):
        # Leader election is read out of the generated export's arguments, which
        # is only sound while the reviewed patches can add arguments and never
        # replace the list. A patch that could remove `--enable-leader-election`
        # must therefore break the reader rather than be reasoned about.
        directory = tempfile.mkdtemp(prefix="flux-rbac-args.")
        self.addCleanup(shutil.rmtree, directory, True)
        root = Path(directory).resolve()
        for relative in (
            model.CONTROLLER_EXPORT,
        ) + model.CONTROLLER_DEPLOYMENT_PATCH_FILES:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
        self.assertTrue(model.leader_election_controllers(root))
        patch = root / model.CONTROLLER_DEPLOYMENT_PATCH_FILES[0]
        patch.write_text(
            patch.read_text(encoding="utf-8").replace(
                "- op: add\n  path: /spec/template/spec/containers/0/args/-\n"
                "  value: --no-cross-namespace-refs=true\n",
                "- op: replace\n  path: /spec/template/spec/containers/0/args\n"
                "  value: [--log-level=info]\n",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaises(AssertionError) as raised:
            model.leader_election_controllers(root)
        self.assertIn("patches the controller argument list", str(raised.exception))

    def test_a_release_with_no_declared_chart_kinds_is_refused(self):
        # SITE_CHART_KINDS is the one input this repository cannot derive, and
        # it is keyed on the owner's (kind, name) pair because a Kustomization
        # and a HelmRelease share a name for both sites. A release missing from
        # it needs no permission, which would satisfy every assertion above.
        self.assertEqual(
            set(model.SITE_CHART_KINDS),
            {("HelmRelease", "naranjo-online"), ("HelmRelease", "lidersea-com")},
        )

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
