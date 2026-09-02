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
* PER CONTROLLER — the authority each controller holds over its own custom
  resources is a ClusterRole bound to ONE ServiceAccount (issue #98). The one
  role still bound to all three grants no Flux API group at all, so no
  controller can rewrite another's reconciliation specification and have that
  controller apply the result under an impersonated identity. Both directions
  are asserted: every split grant reaches its owner, and every cross-controller
  write is denied.

What is modelled rather than observed is stated in the module docstring of
``testsupport/rbac_model.py``. The live half is the live-state comparison in
``bootstrap/flux/bootstrap.sh --verify``; the convergence ceremony that once
supplied a second live oracle was retired by the owner (issue #299).
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

# Every object in the reviewed reconciliation graph must be authorized. There
# is no dormant admission path whose missing authority is tolerated as a
# staging stop.
DECLARED_INSUFFICIENCIES = set()

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
CLUSTER = (None,)

# Reason 1 — THE CONFUSED DEPUTY, RETIRED (issue #98). It used to read: the one
# `crd-controller-flux-system` ClusterRole was bound to all three controllers,
# so each held the other two's write authority over their execution objects and
# sources, and 135 rows of this table were exactly that residual.
#
# The role is now split — the shared role grants no Flux API group at all, and
# each controller's own authority is a ClusterRole bound to ONE ServiceAccount
# in `kubernetes/flux-system/controllers/per-controller-rbac.yaml` — so the
# residual is gone and no row below cites this reason. The constant SURVIVES the
# split deliberately: it is
# what `test_the_declared_slack_is_bounded_and_attributed` counts, and the count
# it now asserts is ZERO. Re-broadening the shared role produces ungrounded
# cross-controller grants, which the exact-set assertion refuses until they are
# declared here, and declaring them with this reason fails the zero. Deleting
# the constant instead would delete the guard, so it stays.
SHARED_ROLE = (
    "the shared crd-controller-flux-system ClusterRole is bound to all three "
    "controllers, so this controller holds authority derived for another one "
    "(RETIRED by the per-controller role split, issue #98: no row may cite this)"
)
# Reason 2 — the generated export grants a source kind whose reconciler
# registration at the pinned version this repository cannot confirm, so it is
# declared rather than asserted as required in OWNED_CONTROLLER_KINDS.
UNCONFIRMED_KIND = (
    "the generated export grants ExternalArtifact, a kind no reviewed object "
    "uses and whose reconciler registration at the pinned version this "
    "repository cannot confirm; declared rather than asserted as required"
)
HELMCHART_HANDOFF = (
    "the preserved issue-141 helm-controller split role carries the HelmChart "
    "write half used by legacy spec.chart releases; the initial direct-site "
    "topology uses chartRef only, so these four controller-install grants are "
    "declared rather than attributed to an unrelated reconciled path"
)
HELM_CONFIGMAP_BASELINE = (
    "site-local Helm releases retain ordinary ConfigMap lifecycle authority so "
    "a routine chart primitive does not require a new privileged platform RBAC "
    "release; it is confined to one tenant namespace and is weaker than the "
    "same account's existing Secret lifecycle authority"
)
DECLARED_SLACK = (
    # ---- a kind the export grants and this repository does not use --------
    # Only source-controller now: the kind belongs to the source group, and
    # after the split no other controller holds any authority over it. The three
    # kustomize-controller rows and the three helm-controller rows that used to
    # sit here were cross-controller residue and are gone with the shared role.
    SlackRow(SOURCE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts",), ("get", "list", "watch", "update", "patch"),
             UNCONFIRMED_KIND),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts/status",), ("get", "patch", "update"), UNCONFIRMED_KIND),
    SlackRow(SOURCE_CONTROLLER, CLUSTER, SOURCE_GROUP,
             ("externalartifacts/finalizers",), ("update",), UNCONFIRMED_KIND),
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
    # ---- preserved controller-install handoff -----------------------------
    SlackRow(HELM_CONTROLLER, CLUSTER, SOURCE_GROUP, ("helmcharts",),
             ("create", "update", "patch", "delete"), HELMCHART_HANDOFF),
    # ---- proportionate site-local Helm baseline --------------------------
    SlackRow(
        Subject("naranjo-online", "helm-reconciler"),
        ("naranjo-online",), "", ("configmaps",),
        model.HELM_APPLY_VERBS, HELM_CONFIGMAP_BASELINE,
    ),
    SlackRow(
        Subject("lidersea-com", "helm-reconciler"),
        ("lidersea-com",), "", ("configmaps",),
        model.HELM_APPLY_VERBS, HELM_CONFIGMAP_BASELINE,
    ),
)

DECLARED_SLACK_REQUESTS = _slack_requests(DECLARED_SLACK)

# Requests the narrowed authorization must refuse. Each row is the concrete
# shape of a way the deleted cluster-admin binding used to let a compromised
# controller, or a mistaken manifest, reach past its boundary.
GENERAL_FORBIDDEN_REQUESTS = (
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
    (Subject("flux-system", "naranjo-online-reconciler"), "create", SOURCE_GROUP,
     "ocirepositories", "lidersea-com", None,
     "a site reconciler must not hold authority over the sibling site's path"),
)

ISSUE_98_CROSS_CONTROLLER_REQUESTS = (
    # ---- the confused deputy, refused by name (issue #98) -----------------
    #
    # Every row below was ALLOWED on main and is denied here. They are written
    # literally, one per crossing the issue names, so the split is asserted in
    # the deny direction and not only in the "these slack rows disappeared"
    # direction — a role file that reverted would fail here even if somebody
    # also re-declared the slack. `test_no_controller_can_write_another_controllers_objects`
    # below closes the same property exhaustively; this table is the readable
    # statement of it.
    #
    # Cluster scope is asserted (namespace None) because every one of these
    # grants would arrive through a ClusterRoleBinding, and `Authorizer.allows`
    # at cluster scope consults exactly those.
    (SOURCE_CONTROLLER, "patch", KUSTOMIZE_GROUP, "kustomizations", None, None,
     "source-controller must not rewrite a Kustomization's reconciliation spec"),
    (SOURCE_CONTROLLER, "update", KUSTOMIZE_GROUP, "kustomizations/status", None, None,
     "source-controller must not forge a Kustomization's observed state"),
    (SOURCE_CONTROLLER, "update", KUSTOMIZE_GROUP, "kustomizations/finalizers", None, None,
     "source-controller must not release another controller's finalizer"),
    (SOURCE_CONTROLLER, "patch", HELM_GROUP, "helmreleases", None, None,
     "source-controller must not rewrite a HelmRelease, including its suspend flag"),
    (SOURCE_CONTROLLER, "update", HELM_GROUP, "helmreleases/status", None, None,
     "source-controller must not forge a HelmRelease's observed state"),
    (SOURCE_CONTROLLER, "create", SOURCE_GROUP, "helmcharts", None, None,
     "the intermediate HelmChart is created by helm-controller alone"),
    (SOURCE_CONTROLLER, "delete", SOURCE_GROUP, "helmcharts", None, None,
     "the intermediate HelmChart is deleted by helm-controller alone"),
    (KUSTOMIZE_CONTROLLER, "patch", HELM_GROUP, "helmreleases", None, None,
     "kustomize-controller must not rewrite a HelmRelease it does not own"),
    (KUSTOMIZE_CONTROLLER, "update", HELM_GROUP, "helmreleases/status", None, None,
     "kustomize-controller must not forge a HelmRelease's observed state"),
    (KUSTOMIZE_CONTROLLER, "patch", SOURCE_GROUP, "ocirepositories", None, None,
     "kustomize-controller resolves sources and never writes one"),
    (KUSTOMIZE_CONTROLLER, "patch", SOURCE_GROUP, "gitrepositories", None, None,
     "kustomize-controller reads the repository it syncs from and never writes it"),
    (KUSTOMIZE_CONTROLLER, "create", SOURCE_GROUP, "helmcharts", None, None,
     "kustomize-controller has no HelmChart authority at all after the split"),
    (HELM_CONTROLLER, "patch", KUSTOMIZE_GROUP, "kustomizations", None, None,
     "helm-controller must not rewrite the Kustomization that delivers it"),
    (HELM_CONTROLLER, "update", KUSTOMIZE_GROUP, "kustomizations/status", None, None,
     "helm-controller must not forge a Kustomization's observed state"),
    (HELM_CONTROLLER, "update", KUSTOMIZE_GROUP, "kustomizations/finalizers", None, None,
     "helm-controller must not release kustomize-controller's finalizer"),
    (HELM_CONTROLLER, "patch", SOURCE_GROUP, "gitrepositories", None, None,
     "helm-controller resolves sources and never writes one"),
    (HELM_CONTROLLER, "patch", SOURCE_GROUP, "ocirepositories", None, None,
     "helm-controller resolves the site chart artifact and never writes its source"),
    (HELM_CONTROLLER, "update", SOURCE_GROUP, "buckets/status", None, None,
     "helm-controller owns no source object's status"),
)

FORBIDDEN_REQUESTS = (
    GENERAL_FORBIDDEN_REQUESTS + ISSUE_98_CROSS_CONTROLLER_REQUESTS
)

# The split, stated once: which ClusterRole carries each controller's own
# authority, and which ServiceAccount that role's binding may name. The manifest,
# the bootstrap mirror, and the additive rendered-output Conftest rules are
# checked for semantic equality with this table. Conftest is a separate
# defence-in-depth engine, not a replacement for the model or fast validator.
PER_CONTROLLER_CLUSTER_ROLES = {
    "crd-controller-source-flux-system": "source-controller",
    "crd-controller-kustomize-flux-system": "kustomize-controller",
    "crd-controller-helm-flux-system": "helm-controller",
}

# The API groups whose objects ARE a controller's reconciliation specification.
# A verb one controller holds over another's object in one of these groups is
# the confused deputy; the same verb over cluster metadata is not.
FLUX_API_GROUPS = (SOURCE_GROUP, KUSTOMIZE_GROUP, HELM_GROUP)

# HelmChart is the ONE kind two controllers legitimately touch, and it is not a
# shared role: helm-controller CREATES the intermediate chart it derives from a
# HelmRelease, and source-controller — which registers the reconciler for it —
# turns it into an artifact. They are the two ends of one handoff. Declared once
# here and consumed by both directions of the evidence below, so widening the
# exemption widens it visibly in one place instead of twice by hand.
#
# The exemption is per KIND and covers only the object itself: `helmcharts/status`
# and `helmcharts/finalizers` stay source-controller's alone, which is why the
# split's helm role grants neither.
HANDOFF_KIND_HOLDERS = {"HelmChart": ("source-controller", "helm-controller")}

# The ServiceAccounts the reviewed three-controller component set creates. Any
# other subject on the shared ClusterRoleBinding names an account that does not
# exist today and would activate silently the day it did.
INSTALLED_CONTROLLERS = ("source-controller", "kustomize-controller", "helm-controller")

# The two generated ClusterRoles that legitimately keep wildcards: they aggregate
# into the built-in admin/edit/view roles for human operators and are bound to no
# ServiceAccount. The binding half of that claim is asserted below.
AGGREGATION_ROLES = {"flux-edit-flux-system", "flux-view-flux-system"}

SITE_KUSTOMIZATIONS = {
    "naranjo-online-reconciler": (
        "./kubernetes/websites/naranjo-online",
        "naranjo-online-reconciler",
    ),
    "lidersea-com-reconciler": (
        "./kubernetes/websites/lidersea-com",
        "lidersea-com-reconciler",
    ),
}

EXPECTED_ACCESS_IDENTITIES = {
    ("ServiceAccount", "flux-system", "default"),
    ("ServiceAccount", "cloudflare-public", "default"),
    ("ServiceAccount", "naranjo-online", "default"),
    ("ServiceAccount", "lidersea-com", "default"),
    ("Role", "flux-system", "flux-controller-runtime"),
    ("RoleBinding", "flux-system", "flux-controller-runtime"),
    ("Role", "flux-system", "flux-controller-impersonation"),
    ("RoleBinding", "flux-system", "flux-controller-impersonation"),
}
for _site in ("naranjo-online", "lidersea-com"):
    EXPECTED_ACCESS_IDENTITIES.update(
        {
            ("Role", _site, "flux-controller-impersonation"),
            ("RoleBinding", _site, "flux-controller-impersonation"),
            ("ServiceAccount", "flux-system", _site + "-reconciler"),
            ("Role", _site, "flux-release-reconciler"),
            ("RoleBinding", _site, _site + "-reconciler"),
            ("ServiceAccount", _site, "helm-reconciler"),
            ("Role", _site, "helm-reconciler"),
            ("RoleBinding", _site, "helm-reconciler"),
        }
    )


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
        # two site Kustomizations, two HelmReleases, and every object they apply.
        owners = {requirement.owner for requirement in self.requirements}
        self.assertEqual(
            owners,
            {
                ("Kustomization", "naranjo-online-reconciler"),
                ("Kustomization", "lidersea-com-reconciler"),
                ("HelmRelease", "naranjo-online"),
                ("HelmRelease", "lidersea-com"),
            },
        )
        applied = {
            (requirement.group, requirement.resource) for requirement in self.requirements
        }
        for expected in (
            ("apps", "deployments"),
            ("apps", "replicasets"),
            ("", "services"),
            ("", "serviceaccounts"),
            ("", "secrets"),
            ("", "pods"),
            ("networking.k8s.io", "networkpolicies"),
            ("helm.toolkit.fluxcd.io", "helmreleases"),
            ("source.toolkit.fluxcd.io", "ocirepositories"),
        ):
            with self.subTest(resource=expected):
                self.assertIn(expected, applied)
        self.assertEqual(len(self.requirements), 119)
        self.assertEqual(len(self.controller_requirements), 205)
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

    def test_initial_sync_topology_is_exact_direct_and_non_pruning(self):
        documents = model.bootstrap_flux_documents(ROOT)
        repositories = [
            document for document in documents
            if document.get("kind") == "GitRepository"
        ]
        kustomizations = [
            document for document in documents
            if document.get("kind") == "Kustomization"
        ]
        self.assertEqual(len(repositories), 1)
        self.assertEqual(len(kustomizations), 2)
        repository = repositories[0]
        self.assertEqual(
            (
                repository["metadata"]["namespace"],
                repository["metadata"]["name"],
                repository["spec"]["url"],
                repository["spec"].get("secretRef"),
            ),
            (
                "flux-system",
                "flux-system",
                "https://github.com/snaraj/website-infrastructure.git",
                None,
            ),
        )
        self.assertEqual(
            repository["spec"]["sparseCheckout"],
            [
                "kubernetes/websites/naranjo-online",
                "kubernetes/websites/lidersea-com",
            ],
        )

        actual = {}
        for document in kustomizations:
            metadata = document["metadata"]
            spec = document["spec"]
            actual[metadata["name"]] = (
                metadata["namespace"],
                spec["path"],
                spec["serviceAccountName"],
            )
            self.assertIs(spec["prune"], False)
            self.assertEqual(spec["deletionPolicy"], "Orphan")
            self.assertEqual(
                spec["sourceRef"], {"kind": "GitRepository", "name": "flux-system"}
            )
            self.assertNotIn("dependsOn", spec)
            self.assertNotIn("decryption", spec)
        self.assertEqual(
            actual,
            {
                name: ("flux-system", path, account)
                for name, (path, account) in SITE_KUSTOMIZATIONS.items()
            },
        )

        for name, (path, _) in SITE_KUSTOMIZATIONS.items():
            site = name.removesuffix("-reconciler")
            with self.subTest(kustomization=name):
                self.assertEqual(
                    model.objects_applied_by(ROOT, path.lstrip("./")),
                    [
                        ("NetworkPolicy", site, "default-deny"),
                        ("OCIRepository", site, site + "-chart"),
                        ("HelmRelease", site, site),
                    ],
                )

    def test_access_inventory_has_no_aggregate_platform_or_cloudflare_grant(self):
        access = model.load_documents(ROOT / "kubernetes/flux-system/access.yaml")
        identities = {
            (
                document.get("kind"),
                (document.get("metadata") or {}).get("namespace"),
                (document.get("metadata") or {}).get("name"),
            )
            for document in access
        }
        self.assertEqual(identities, EXPECTED_ACCESS_IDENTITIES)
        self.assertEqual(len(access), 24)
        self.assertEqual(
            {
                identity
                for identity in identities
                if identity[1] == "cloudflare-public"
            },
            {("ServiceAccount", "cloudflare-public", "default")},
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
        # Two Kustomizations plus two HelmReleases; the accounts they name are
        # the entire surface through which anything is applied.
        self.assertEqual(len(impersonations), 4)
        for requirement in impersonations:
            with self.subTest(account=requirement.name, namespace=requirement.namespace):
                self.assertTrue(
                    self.authorizer.allows(
                        requirement.subject, "impersonate", "", "serviceaccounts",
                        requirement.namespace, requirement.name,
                    )
                )

    def test_source_resolution_is_derived_for_direct_controller_reads(self):
        """The authority every reconciliation starts with (P1-1).

        A reconciler resolves `spec.sourceRef`/`spec.chartRef` through its own
        API client BEFORE impersonation is configured, so reading the source is
        the CONTROLLER's own authority. Deleting the source read rule from the
        narrowed ClusterRole is a coherent-looking further narrowing that would
        stop ALL reconciliation live — neither direct site Kustomization could
        read the one GitRepository it syncs from — so it must fail here.
        """

        reads = [
            requirement
            for requirement in self.controller_requirements
            if "resolves its" in requirement.reason
        ]
        self.assertTrue(reads)
        # Every Kustomization and direct chartRef HelmRelease resolves a source
        # as the controller rather than as the impersonated account. A legacy
        # chart.spec.sourceRef is copied into HelmChart for source-controller to
        # resolve; helm-controller does not read that source object.
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
                ("Kustomization", "naranjo-online-reconciler"),
                ("Kustomization", "lidersea-com-reconciler"),
                ("HelmRelease", "naranjo-online"),
                ("HelmRelease", "lidersea-com"),
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

    def test_both_direct_site_kustomizations_can_read_the_single_repository(self):
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
        self.assertEqual(len(sources), 3)
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

    def test_every_owned_controller_kind_is_authorized_without_an_object(self):
        """A primary kind with no object today is still a running informer.

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

    def test_secondary_informer_model_is_exact_cluster_wide_and_read_only(self):
        """Pinned managers start secondary caches independently of desired state."""

        self.assertEqual(
            model.OWNED_CONTROLLER_KINDS,
            {
                "source-controller": (
                    "Bucket", "GitRepository", "HelmChart", "HelmRepository",
                    "OCIRepository",
                ),
                "kustomize-controller": ("Kustomization",),
                "helm-controller": ("HelmRelease",),
            },
        )
        self.assertEqual(
            model.CONTROLLER_SECONDARY_WATCH_KINDS,
            {
                "kustomize-controller": (
                    "Bucket", "GitRepository", "OCIRepository",
                ),
                "helm-controller": ("HelmChart", "OCIRepository"),
            },
        )
        secondary = [
            requirement
            for requirement in self.controller_requirements
            if requirement.owner == ("Controller", "secondary-informer")
        ]
        expected = set()
        for controller, kinds in model.CONTROLLER_SECONDARY_WATCH_KINDS.items():
            for kind in kinds:
                group, resource = model.KIND_RESOURCES[kind][:2]
                for verb in ("get", "list", "watch"):
                    expected.add((controller, verb, group, resource, None))
        self.assertEqual(
            {
                (
                    requirement.subject.name, requirement.verb,
                    requirement.group, requirement.resource,
                    requirement.namespace,
                )
                for requirement in secondary
            },
            expected,
        )
        self.assertNotIn(
            "ExternalArtifact",
            {
                kind
                for kinds in model.CONTROLLER_SECONDARY_WATCH_KINDS.values()
                for kind in kinds
            },
        )

    def test_controller_identities_have_no_cluster_secret_authority(self):
        """Optional config watchers are disabled; tenant Helm storage is separate."""

        self.assertFalse(
            any(
                requirement.owner == ("Controller", "startup-cache")
                for requirement in self.controller_requirements
            )
        )
        for subject in (SOURCE_CONTROLLER, KUSTOMIZE_CONTROLLER, HELM_CONTROLLER):
            for verb in (
                "get", "list", "watch", "create", "update", "patch", "delete",
                "deletecollection",
            ):
                with self.subTest(subject=str(subject), verb=verb):
                    self.assertFalse(
                        self.authorizer.allows(subject, verb, "", "secrets", None)
                    )

    def test_helm_release_readiness_readback_is_tenant_local_and_read_only(self):
        """Issue #186: Helm install and upgrade waits need the full read chain."""

        tenants = ("naranjo-online", "lidersea-com")
        for namespace in tenants:
            subject = Subject(namespace, "helm-reconciler")
            for group, resource in model.READ_BACK_RESOURCES:
                for verb in model.READ_BACK_VERBS:
                    with self.subTest(
                        namespace=namespace, group=group, resource=resource, verb=verb,
                    ):
                        self.assertTrue(
                            self.authorizer.allows(
                                subject, verb, group, resource, namespace
                            )
                        )
                        for foreign in {
                            None,
                            "flux-system",
                            "untrusted",
                            "kube-system",
                            *(set(tenants) - {namespace}),
                        }:
                            self.assertFalse(
                                self.authorizer.allows(
                                    subject, verb, group, resource, foreign
                                )
                            )
                for verb in ("create", "update", "patch", "delete", "deletecollection"):
                    with self.subTest(
                        namespace=namespace, resource=resource, forbidden=verb,
                    ):
                        self.assertFalse(
                            self.authorizer.allows(
                                subject, verb, group, resource, namespace
                            )
                        )

    def test_naranjo_claim_lifecycle_is_local_without_backing_storage_authority(self):
        """Issue #211: one exact site may manage claims, never their backing."""

        naranjo = Subject("naranjo-online", "helm-reconciler")
        lifecycle = ("get", "list", "watch", "create", "update", "patch", "delete")
        for verb in lifecycle:
            with self.subTest(subject="naranjo", verb=verb):
                self.assertTrue(
                    self.authorizer.allows(
                        naranjo, verb, "", "persistentvolumeclaims", "naranjo-online"
                    )
                )
            for foreign in (None, "lidersea-com", "cloudflare-public", "flux-system"):
                with self.subTest(subject="naranjo", verb=verb, foreign=foreign):
                    self.assertFalse(
                        self.authorizer.allows(
                            naranjo, verb, "", "persistentvolumeclaims", foreign
                        )
                    )

        for namespace in ("lidersea-com", "cloudflare-public"):
            subject = Subject(namespace, "helm-reconciler")
            for verb in lifecycle:
                with self.subTest(subject=namespace, verb=verb):
                    self.assertFalse(
                        self.authorizer.allows(
                            subject, verb, "", "persistentvolumeclaims", namespace
                        )
                    )

        self.assertFalse(
            self.authorizer.allows(
                naranjo, "deletecollection", "", "persistentvolumeclaims", "naranjo-online"
            )
        )
        for group, resource in (
            ("", "persistentvolumes"),
            ("", "nodes"),
            ("storage.k8s.io", "storageclasses"),
            ("storage.k8s.io", "csidrivers"),
            ("snapshot.storage.k8s.io", "volumesnapshots"),
        ):
            for verb in lifecycle:
                with self.subTest(resource=resource, verb=verb):
                    self.assertFalse(
                        self.authorizer.allows(naranjo, verb, group, resource, None)
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
        #
        # Pin the derived direct-site topology exactly. A floor would let a
        # deleted site grant hide inside arbitrary headroom and would let an
        # unrelated authority increase pass unnoticed.
        self.assertEqual(len(self.granted), 306)
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
            {"flux-system", "cloudflare-public", "naranjo-online", "lidersea-com"},
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
        self.assertEqual(len(DECLARED_SLACK_REQUESTS), 39)
        for row in DECLARED_SLACK:
            with self.subTest(subject=str(row.subject), resources=row.resources):
                self.assertTrue(row.verbs and row.resources and row.scopes)
                self.assertGreater(len(row.reason), 40, "every slack row states why")
        # The confused-deputy residual was 135 requests on main and is ZERO here
        # (issue #98). The count is asserted rather than the rows quietly
        # deleted, because the two assertions above are what make zero mean
        # something: a re-broadened shared role produces ungrounded
        # cross-controller grants, the exact-set assertion refuses them until
        # they are declared, and declaring them with this reason fails here.
        # Removing SHARED_ROLE instead of asserting against it would remove the
        # guard along with the finding.
        shared = _slack_requests(
            tuple(row for row in DECLARED_SLACK if SHARED_ROLE in row.reason)
        )
        self.assertEqual(shared, set())
    def test_the_cluster_scope_exemption_belongs_to_the_controllers_alone(self):
        """A reconciler never gets the informer-cache excuse.

        The complement assertion above accepts a cluster-scoped grant that is
        only derived per-namespace when the grant's scope is a property of
        Kubernetes rather than a choice — a controller's informer cache is
        cluster-wide and no Role can satisfy it. That is true of the three
        controller ServiceAccounts and of nothing else: an impersonated
        reconciler opens no informer, it applies a fixed set of objects in one
        namespace.

        Keyed on the apiGroup alone, the exemption let a ClusterRole grant
        `naranjo-online-reconciler` write authority over every OCIRepository and
        HelmRelease in the cluster — the other site's included — with the
        validator PASS and the battery 62/62 OK. Safety invariant 14 says the
        two site identity tuples never couple, so this is the subject check that
        makes that assertion real.
        """

        for name in INSTALLED_CONTROLLERS:
            with self.subTest(subject=name):
                self.assertTrue(
                    model._cluster_scope_is_by_design(
                        Subject("flux-system", name), SOURCE_GROUP, "ocirepositories"
                    )
                )
        for subject in (
            Subject("flux-system", "naranjo-online-reconciler"),
            Subject("flux-system", "lidersea-com-reconciler"),
            Subject("naranjo-online", "helm-reconciler"),
            Subject("kube-system", "kustomize-controller"),
        ):
            for group, resource in (
                (SOURCE_GROUP, "ocirepositories"),
                (HELM_GROUP, "helmreleases"),
                (KUSTOMIZE_GROUP, "kustomizations"),
                ("", "events"),
            ):
                with self.subTest(subject=str(subject), resource=resource):
                    self.assertFalse(
                        model._cluster_scope_is_by_design(subject, group, resource)
                    )
        # And the exemption is per (group, resource), not a blanket pass for a
        # controller: nothing outside the Flux groups and Events qualifies.
        self.assertFalse(
            model._cluster_scope_is_by_design(KUSTOMIZE_CONTROLLER, "apps", "deployments")
        )
        self.assertFalse(
            model._cluster_scope_is_by_design(KUSTOMIZE_CONTROLLER, "", "secrets")
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
                ("flux-system", "naranjo-online-reconciler"),
                ("flux-system", "lidersea-com-reconciler"),
                ("naranjo-online", "helm-reconciler"),
                ("lidersea-com", "helm-reconciler"),
            )
        )
        namespaces = (
            None, "flux-system", "cloudflare-public", "naranjo-online", "lidersea-com",
            "untrusted", "kube-system",
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
        self.assertEqual(found, 3, "one impersonation Role per namespace holding accounts")

    def test_forbidden_requests_are_denied(self):
        for subject, verb, group, resource, namespace, name, why in FORBIDDEN_REQUESTS:
            with self.subTest(subject=str(subject), verb=verb, resource=resource):
                self.assertFalse(
                    self.authorizer.allows(subject, verb, group, resource, namespace, name),
                    "{} may {} {}/{}: {}".format(subject, verb, group or "core", resource, why),
                )
    def test_the_shared_controller_role_grants_no_flux_api_group(self):
        """The structural half of the split (issue #98).

        `crd-controller-flux-system` is bound to all three controller
        ServiceAccounts, so any rule in it naming a Flux API group is authority
        every controller holds over every other one's execution objects — the
        confused deputy, whatever the verb. The deny rows above catch the
        specific crossings; this catches the SHAPE, so a rule re-added with a
        verb nobody enumerated still fails.

        The positive half is asserted with it: the role must still carry the
        metadata reads, event reporting, and liveness probe, or "grants no Flux
        group" would also be satisfied by an empty rule list.
        """

        role = next(
            document
            for document in self.documents
            if document.get("kind") == "ClusterRole"
            and document["metadata"]["name"] == "crd-controller-flux-system"
        )
        for rule in role.get("rules") or []:
            for group in rule.get("apiGroups") or []:
                with self.subTest(group=group, verbs=tuple(rule.get("verbs") or ())):
                    self.assertNotIn(
                        group,
                        FLUX_API_GROUPS,
                        "the shared role is bound to all three controllers, so a "
                        "{} rule in it is authority over the other controllers' "
                        "objects".format(group),
                    )
        for verb, resource in (
            ("get", "namespaces"), ("list", "serviceaccounts"), ("watch", "configmaps"),
            ("create", "events"), ("patch", "events"),
        ):
            for name in INSTALLED_CONTROLLERS:
                with self.subTest(shared=resource, verb=verb, subject=name):
                    self.assertTrue(
                        self.authorizer.allows(
                            Subject("flux-system", name), verb, "", resource, None
                        )
                    )
        for name in INSTALLED_CONTROLLERS:
            with self.subTest(liveness=name):
                self.assertTrue(
                    self.authorizer.allows_non_resource(
                        Subject("flux-system", name), "head", "/livez/ping"
                    )
                )

    def test_each_per_controller_role_binds_exactly_its_own_controller(self):
        """One role, one binding, one ServiceAccount — asserted per pair.

        A per-controller role that grew a second subject would re-create the
        shared role under a new name, and every request-level assertion in this
        class would keep passing for the controller that legitimately owns the
        authority. So the subject SET is pinned, not just the presence of the
        owner.
        """

        roles = {
            document["metadata"]["name"]: document
            for document in self.documents
            if document.get("kind") == "ClusterRole"
        }
        bindings = {
            document["metadata"]["name"]: document
            for document in self.documents
            if document.get("kind") == "ClusterRoleBinding"
        }
        for name, owner in sorted(PER_CONTROLLER_CLUSTER_ROLES.items()):
            with self.subTest(role=name):
                self.assertIn(name, roles, "the split's per-controller role is missing")
                self.assertTrue(roles[name].get("rules"), "an empty role grants nothing")
                self.assertIn(name, bindings)
                self.assertEqual(
                    bindings[name]["roleRef"],
                    {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "ClusterRole",
                        "name": name,
                    },
                )
                self.assertEqual(
                    {
                        (entry["namespace"], entry["name"])
                        for entry in bindings[name]["subjects"]
                    },
                    {("flux-system", owner)},
                    "a second subject here rebuilds the shared role under a new name",
                )

    def test_no_controller_can_write_another_controllers_objects(self):
        """The confused deputy, refused exhaustively rather than by example.

        The matrix comes from ``OWNED_CONTROLLER_KINDS`` — a MODEL constant
        declaring which kinds each controller reconciles — and not from the
        manifests, so it cannot agree with whatever the manifests happen to say.
        `test_every_per_controller_grant_is_owned_and_exclusive` is the other
        direction, reading the manifests; between them a grant has to be both
        derived for its owner and denied to everyone else.
        """

        self.assertEqual(
            HANDOFF_KIND_HOLDERS,
            {"HelmChart": ("source-controller", "helm-controller")},
            "the handoff exemption is exactly one kind; widening it here would "
            "silently widen the matrix below",
        )
        write_verbs = ("create", "update", "patch", "delete", "deletecollection")
        namespaces = (
            None, "flux-system", "cloudflare-public", "naranjo-online",
            "lidersea-com", "untrusted", "kube-system",
        )
        checked = 0
        for owner, kinds in sorted(model.OWNED_CONTROLLER_KINDS.items()):
            for kind in kinds:
                group, resource, _ = model.KIND_RESOURCES[kind]
                for other in INSTALLED_CONTROLLERS:
                    if other == owner or other in HANDOFF_KIND_HOLDERS.get(kind, ()):
                        continue
                    subject = Subject("flux-system", other)
                    for target in (resource, resource + "/status", resource + "/finalizers"):
                        for verb in write_verbs:
                            for namespace in namespaces:
                                checked += 1
                                if not self.authorizer.allows(
                                    subject, verb, group, target, namespace
                                ):
                                    continue
                                self.fail(
                                    "{} may {} {}/{} in {}: that is {}'s object, and "
                                    "impersonation does not contain the write because "
                                    "{} performs the resulting reconciliation".format(
                                        subject, verb, group, target,
                                        namespace or "cluster scope", owner, owner,
                                    )
                                )
        # The enumeration is pinned: a matrix that checked nothing would pass.
        # 7 kinds x 2 non-owners each, minus the one by-design pair, x 3 targets
        # x 5 write verbs x 7 scopes.
        self.assertEqual(checked, 1365)

    def test_every_per_controller_grant_is_owned_and_exclusive(self):
        """Two-sided evidence per GRANT, read out of the manifests themselves.

        For every atomic request the three split roles confer, the owning
        controller must hold it — deleting the rule fails here, which is the
        sufficiency direction at RULE granularity rather than the whole-role
        granularity `unmet` works at.

        Exclusivity is asserted for the WRITE half only, and that boundary is
        the finding's boundary rather than a convenience. Reading another
        controller's source object cannot make that controller do anything:
        kustomize-controller and helm-controller both resolve a `sourceRef`
        under their own identity before impersonation is configured, so a read
        of a GitRepository is shared authority by design (issue #98 says the
        shared read half may stay common). Writing one is not — a rewritten
        source, status, or finalizer is a reconciliation the OWNING controller
        then performs, which is the confused deputy exactly.

        Subresources are treated as writes whatever the verb: `/status` and
        `/finalizers` are ownership markers, and no controller reads another's.
        """

        roles = {
            document["metadata"]["name"]: document
            for document in self.documents
            if document.get("kind") == "ClusterRole"
        }
        # The handoff exemption, resolved from kinds to the resource strings the
        # rules actually name. Only the object itself, never its subresources.
        handoff = {
            model.KIND_RESOURCES[kind][1]: holders
            for kind, holders in HANDOFF_KIND_HOLDERS.items()
        }
        write_verbs = {"create", "update", "patch", "delete", "deletecollection"}
        checked = 0
        exclusive = 0
        exempted = 0
        for name, owner in sorted(PER_CONTROLLER_CLUSTER_ROLES.items()):
            for rule in roles[name].get("rules") or []:
                for verb, group, resource, _ in model._rule_atoms(rule):
                    checked += 1
                    with self.subTest(role=name, verb=verb, resource=resource):
                        self.assertTrue(
                            self.authorizer.allows(
                                Subject("flux-system", owner), verb, group, resource, None
                            ),
                            "{} does not reach its own {} {}".format(owner, verb, resource),
                        )
                        if verb not in write_verbs and "/" not in resource:
                            continue
                        for other in INSTALLED_CONTROLLERS:
                            if other == owner:
                                continue
                            if other in handoff.get(resource, ()):
                                exempted += 1
                                continue
                            exclusive += 1
                            self.assertFalse(
                                self.authorizer.allows(
                                    Subject("flux-system", other), verb, group, resource, None
                                ),
                                "{} holds {}'s {} on {}".format(other, owner, verb, resource),
                            )
        # Every rule of all three roles, expanded: an empty or truncated walk
        # would make the loop above vacuous. The exclusive and exempted counts
        # are pinned separately so neither the write half can shrink to nothing
        # nor the handoff become the place exclusivity goes to die.
        self.assertEqual(checked, 91)
        self.assertEqual(exclusive, 98)
        self.assertEqual(exempted, 6)

    def test_no_controller_can_write_secrets_anywhere(self):
        for subject in (KUSTOMIZE_CONTROLLER, HELM_CONTROLLER, SOURCE_CONTROLLER):
            for namespace in (
                "flux-system", "cloudflare-public", "naranjo-online", "lidersea-com",
                "untrusted", "kube-system", None,
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
        # `controller_root_rbac` IS the model's account of this root — generated
        # export, plus the narrowing patches, plus the authored per-controller
        # resource (issue #98). Comparing against it rather than re-composing
        # inline means a resource added to the root but not to the model, or the
        # reverse, fails here instead of silently splitting the two.
        composed = {
            self._identity(document): document
            for document in model.controller_root_rbac(ROOT)
        }
        self.assertEqual(sorted(composed), sorted(actual))
        for key in sorted(actual):
            with self.subTest(object=key):
                self.assertEqual(composed[key].get("rules"), actual[key].get("rules"))
                self.assertEqual(composed[key].get("subjects"), actual[key].get("subjects"))
                self.assertEqual(composed[key].get("roleRef"), actual[key].get("roleRef"))
                self.assertEqual(
                    (composed[key].get("metadata") or {}).get("labels", {}),
                    (actual[key].get("metadata") or {}).get("labels", {}),
                    "ownership/provenance labels are part of the rendered RBAC model",
                )

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
                self.assertEqual(
                    (cluster_roles[name].get("metadata") or {}).get("labels", {}),
                    contract["MATERIALIZED_CLUSTER_ROLE_LABELS"][name],
                    "live ClusterRole label expectations must mirror committed semantics",
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
                self.assertEqual(
                    (cluster_bindings[name].get("metadata") or {}).get("labels", {}),
                    contract["MATERIALIZED_CLUSTER_BINDING_LABELS"][name],
                    "live ClusterRoleBinding label expectations must mirror committed semantics",
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
        # Eight RoleBindings plus FOUR ClusterRoleBindings: the shared
        # metadata-only one and the three per-controller ones (issue #98).
        self.assertEqual(checked, 12)

    def test_the_live_verifier_sees_every_subject_form_that_reaches_a_controller(self):
        """The live half must not be weaker than the model it mirrors.

        `Authorizer._binds` understands three subject forms, because a
        ServiceAccount is reachable by all three. The live verifier's
        `binding_reaches_protected_account` — the rule that turns an unexpected
        binding into a hard `--verify` failure — knew only two: it matched
        ServiceAccount and Group subjects but not the `User:
        system:serviceaccount:…` form, and its Group set omitted
        `system:authenticated`, which every authenticated identity carries. A
        binding in either shape granted a controller authority the repository's
        own model reports as granted and the verifier accepted in silence.
        """

        reaches = self._bootstrap_contract()["binding_reaches_protected_account"]
        api_group = "rbac.authorization.k8s.io"
        for subject in (
            {"kind": "ServiceAccount", "name": "kustomize-controller", "namespace": "flux-system"},
            {"kind": "ServiceAccount", "name": "helm-reconciler", "namespace": "naranjo-online"},
            {"kind": "User", "apiGroup": api_group,
             "name": "system:serviceaccount:flux-system:kustomize-controller"},
            {"kind": "User", "apiGroup": api_group,
             "name": "system:serviceaccount:naranjo-online:helm-reconciler"},
            {"kind": "Group", "apiGroup": api_group, "name": "system:serviceaccounts"},
            {"kind": "Group", "apiGroup": api_group, "name": "system:serviceaccounts:flux-system"},
            {"kind": "Group", "apiGroup": api_group, "name": "system:authenticated"},
        ):
            with self.subTest(reaches=subject["name"], kind=subject["kind"]):
                self.assertTrue(reaches({"subjects": [subject]}), subject)
        for subject in (
            {"kind": "ServiceAccount", "name": "kustomize-controller", "namespace": "kube-system"},
            {"kind": "User", "apiGroup": api_group,
             "name": "system:serviceaccount:kube-system:kustomize-controller"},
            {"kind": "User", "apiGroup": api_group, "name": "system:node:pi"},
            {"kind": "Group", "apiGroup": api_group, "name": "system:serviceaccounts:kube-system"},
            {"kind": "Group", "apiGroup": api_group, "name": "system:masters"},
            # Suffix near-misses. Exact set membership already makes these
            # false; asserted so a future `startswith`/`in` rewrite of this
            # matcher cannot pass silently.
            {"kind": "ServiceAccount", "name": "kustomize-controller-2",
             "namespace": "flux-system"},
            {"kind": "User", "apiGroup": api_group,
             "name": "system:serviceaccount:flux-system:kustomize-controller-2"},
            {"kind": "Group", "apiGroup": api_group, "name": "system:authenticated-2"},
            {"kind": "Group", "apiGroup": api_group, "name": "system:serviceaccounts:flux-system-2"},
        ):
            with self.subTest(ignores=subject["name"], kind=subject["kind"]):
                self.assertFalse(reaches({"subjects": [subject]}), subject)

    def test_the_stock_cluster_bindings_pass_but_a_tampered_one_does_not(self):
        """The allowlist that keeps the previous test from refusing every cluster.

        `system:authenticated` is carried by every authenticated identity, so
        once the verifier understands that group, the four ClusterRoleBindings
        Kubernetes creates on every cluster reach the Flux accounts too — and
        `--verify` reads every ClusterRoleBinding on the cluster, unfiltered.
        Left alone it would refuse a conformant cluster, and the runbook runs
        `--verify` immediately after the destructive deletion: a false refusal
        aborts the migration at its most delicate boundary and sends the
        operator into a rollback that was never needed.

        The allowlist is BY NAME and pinned to the exact roleRef and subject
        set, so the stock binding passes and a tampered one — repointed, or
        grown a subject — still fails. Each is asserted both ways.
        """

        contract = self._bootstrap_contract()
        stock = contract["is_bootstrapped_cluster_role_binding"]
        reaches = contract["binding_reaches_protected_account"]
        api_group = "rbac.authorization.k8s.io"

        def binding(name, role, groups):
            return {
                "metadata": {"name": name},
                "roleRef": {"apiGroup": api_group, "kind": "ClusterRole", "name": role},
                "subjects": [
                    {"kind": "Group", "apiGroup": api_group, "name": group}
                    for group in groups
                ],
            }

        captures = {
            "system:basic-user": ("system:basic-user", ["system:authenticated"]),
            "system:discovery": ("system:discovery", ["system:authenticated"]),
            "system:public-info-viewer": (
                "system:public-info-viewer",
                ["system:authenticated", "system:unauthenticated"],
            ),
            "system:service-account-issuer-discovery": (
                "system:service-account-issuer-discovery", ["system:serviceaccounts"],
            ),
        }
        self.assertEqual(
            set(captures), set(contract["BOOTSTRAPPED_CLUSTER_ROLE_BINDINGS"])
        )
        for name, (role, groups) in sorted(captures.items()):
            value = binding(name, role, groups)
            with self.subTest(stock=name):
                # Every one of them DOES reach a protected account — that is why
                # the allowlist is needed rather than the matcher being wrong.
                self.assertTrue(reaches(value))
                self.assertTrue(stock(value))
            with self.subTest(repointed=name):
                self.assertFalse(stock(binding(name, "cluster-admin", groups)))
            with self.subTest(extra_subject=name):
                self.assertFalse(
                    stock(binding(name, role, groups + ["system:masters"]))
                )
            with self.subTest(dropped_subject=name):
                self.assertFalse(stock(binding(name, role, groups[:-1])))
            with self.subTest(service_account_subject=name):
                tampered = binding(name, role, groups)
                tampered["subjects"].append(
                    {"kind": "ServiceAccount", "name": "kustomize-controller",
                     "namespace": "flux-system"}
                )
                self.assertFalse(stock(tampered))
            with self.subTest(subject_kind_swapped=name):
                # The names line up EXACTLY and only the kind differs: a
                # ServiceAccount called `system:authenticated` is not the group
                # `system:authenticated`. Identity is the (kind, name) pair here
                # too, so a name-only comparison must not accept this.
                swapped = binding(name, role, [])
                swapped["subjects"] = [
                    {"kind": "ServiceAccount", "name": group, "namespace": "flux-system"}
                    for group in groups
                ]
                self.assertFalse(stock(swapped))
        # An unlisted name is never allowlisted, however stock it looks.
        self.assertFalse(
            stock(binding("system:almost-basic-user", "system:basic-user",
                          ["system:authenticated"]))
        )
        # And the forms the previous test pins still reach: the allowlist
        # narrows WHICH bindings are exempt, never what the matcher understands.
        for subject in (
            {"kind": "User", "apiGroup": api_group,
             "name": "system:serviceaccount:flux-system:kustomize-controller"},
            {"kind": "Group", "apiGroup": api_group, "name": "system:authenticated"},
        ):
            value = {
                "metadata": {"name": "borrowed"},
                "roleRef": {"apiGroup": api_group, "kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [subject],
            }
            with self.subTest(still_reaches=subject["kind"]):
                self.assertTrue(reaches(value))
                self.assertFalse(stock(value))

    @staticmethod
    def _check_rbac_body():
        """The source of the live verifier's RBAC check, sliced out.

        The predicates this battery exercises are reached only from
        `check_rbac`, and no test calls `check_rbac` — it needs a whole
        synthetic cluster. So its WIRING is asserted the way
        `test_patches_are_wired_into_the_install_root` asserts a patch's: a
        guard that exists but is not called is the same failure as no guard.
        """

        text = BOOTSTRAP.read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^def check_rbac\(.*?\n(?=^\w|^PSA_LABELS)", text
        )
        if match is None:
            raise AssertionError("bootstrap.sh no longer defines check_rbac")
        return match.group(0)

    def test_the_live_verifier_calls_every_guard_this_battery_proves(self):
        """Each predicate proven above, asserted to be CALLED — and in order.

        Deleting `elif is_bootstrapped_cluster_role_binding(value): continue`
        from the ClusterRoleBinding loop left the whole battery green: the
        allowlist was exhaustively covered and completely bypassed, and the
        deletion silently restores `--verify` refusing a conformant cluster at
        the runbook's most delicate step. Same exposure for the closure
        requirements and for the refusal itself.
        """

        body = self._check_rbac_body()
        self.assertIn("def check_rbac(", body)
        self.assertGreater(len(body), 1000, "the slice must be the real function body")

        # The refusal that turns an unexpected binding into a hard failure is
        # called in BOTH loops — RoleBindings and ClusterRoleBindings.
        self.assertEqual(body.count("binding_reaches_protected_account(value)"), 2)
        # The allowlist that keeps that refusal from firing on every cluster.
        self.assertIn("is_bootstrapped_cluster_role_binding(value)", body)
        # Order is load-bearing: the allowlist must be consulted BEFORE the
        # refusal, or the stock bindings are refused before it is ever reached.
        cluster_loop = body[body.index('index(cluster_binding_doc, "ClusterRoleBinding"'):]
        self.assertLess(
            cluster_loop.index("is_bootstrapped_cluster_role_binding(value)"),
            cluster_loop.index("binding_reaches_protected_account(value)"),
            "the allowlist must be consulted before the refusal",
        )
        # The mirror closure: every Role and ClusterRole a verified binding
        # names must itself be in the rules mirror.
        for fragment in (
            "for (namespace, _), expected in expected_bindings().items():",
            'require((namespace, role_ref.get("name")) in access_roles)',
            "for expected in expected_cluster_bindings().values():",
            'require(role_ref.get("name") in cluster_role_expectations)',
        ):
            with self.subTest(closure=fragment):
                self.assertIn(fragment, body)

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
            # Materialize label expectations while the same pinned version
            # environment the live verifier receives is still present. The
            # returned functions intentionally read that environment lazily;
            # calling them after restoring the process environment would test a
            # KeyError rather than the committed/live semantic parity.
            contract["MATERIALIZED_CLUSTER_ROLE_LABELS"] = {
                name: contract["expected_cluster_role_labels"](name)
                for name in contract["cluster_role_rules"]()
            }
            contract["MATERIALIZED_CLUSTER_BINDING_LABELS"] = {
                name: contract["expected_cluster_binding_labels"](name)
                for name in contract["expected_cluster_bindings"]()
            }
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
        self.assertEqual(len(found.kustomizations), 2)
        self.assertEqual(len(found.helm_releases), 2)
        self.assertEqual(len(found.sources), 3)
        directory = tempfile.mkdtemp(prefix="flux-rbac-graph.")
        self.addCleanup(shutil.rmtree, directory, True)
        root = Path(directory).resolve()
        for relative in (
            "kubernetes/flux-system/gotk-sync.yaml.in",
            "kubernetes/websites",
            "kubernetes/platform",
            "kubernetes/flux-system/controllers",
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
        self.assertEqual(len(reached.helm_releases), 3)
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

    def test_the_api_group_is_parsed_exactly_rather_than_prefix_matched(self):
        """Identity by parsing, not by string shape.

        The classification used `apiVersion.startswith("<group>/")`, which
        decides a document's identity — and therefore whose authority applies to
        it — from the shape of a string. CodeQL flagged all three as
        `py/incomplete-url-substring-sanitization`, HIGH; the security framing
        is wrong for an apiGroup check, but the underlying complaint is right,
        and it is the same principle as keying a declared gap on `(kind, name)`
        or the cluster-scope exemption on the subject: compare the identity,
        exactly, after parsing it.

        Both refusals below are the fail-closed direction — a near miss stops
        the derivation with a named error rather than being read as an ordinary
        applied object whose controller-side authority nobody derived.
        """

        classified = []

        def classify(api_version, kind):
            kustomizations, releases, sources = [], [], []
            result = model._classify_flux_document(
                {"apiVersion": api_version, "kind": kind}, "fixture",
                kustomizations, releases, sources,
            )
            classified.append((kustomizations, releases, sources))
            return result

        # The real shapes still classify, into the right bucket.
        for api_version, kind, index in (
            ("kustomize.toolkit.fluxcd.io/v1", "Kustomization", 0),
            ("helm.toolkit.fluxcd.io/v2", "HelmRelease", 1),
            ("source.toolkit.fluxcd.io/v1", "OCIRepository", 2),
            ("source.toolkit.fluxcd.io/v1beta2", "Bucket", 2),
        ):
            with self.subTest(accepts=api_version, kind=kind):
                self.assertTrue(classify(api_version, kind))
                self.assertEqual(len(classified[-1][index]), 1)
                self.assertEqual(sum(len(bucket) for bucket in classified[-1]), 1)

        # A group that is NOT exactly the Flux group is refused, however much of
        # the string it shares: a near-miss label, a group that merely contains
        # the domain, the bare domain itself, and — the two rows that used to
        # pass through silently — no version at all.
        for api_version, kind in (
            ("evil-kustomize.toolkit.fluxcd.io/v1", "Kustomization"),
            ("notkustomize.toolkit.fluxcd.io/v1", "Kustomization"),
            ("kustomize.toolkit.fluxcd.io.attacker.example/v1", "Kustomization"),
            ("helm.toolkit.fluxcd.io.attacker.example/v2", "HelmRelease"),
            ("toolkit.fluxcd.io/v1", "Kustomization"),
            ("source.toolkit.fluxcd.io/v1", "Kustomization"),
            # No version at all: the old prefix test matched nothing here AND
            # the old substring refusal missed it, so it fell through as an
            # ordinary applied object with no impersonation requirement derived.
            ("kustomize.toolkit.fluxcd.io", "Kustomization"),
            ("helm.toolkit.fluxcd.io", "HelmRelease"),
        ):
            with self.subTest(misattributed=api_version, kind=kind):
                with self.assertRaises(AssertionError) as raised:
                    classify(api_version, kind)
                self.assertIn("group it is not in", str(raised.exception))

        # A kind this module does NOT classify, in the Flux domain, is the other
        # refusal: it is a reconciliation input nobody taught this enumeration.
        for api_version, kind in (
            ("image.toolkit.fluxcd.io/v1beta2", "ImageUpdateAutomation"),
            ("notification.toolkit.fluxcd.io/v1", "Receiver"),
            ("toolkit.fluxcd.io.example.com/v1", "Deployment"),
        ):
            with self.subTest(refuses=api_version, kind=kind):
                with self.assertRaises(AssertionError) as raised:
                    classify(api_version, kind)
                self.assertIn("cannot classify", str(raised.exception))

        # An apiVersion that is not one group and one version is refused before
        # anything is decided from it — extra segments included.
        for api_version, kind in (
            ("helm.toolkit.fluxcd.io/v2/extra", "HelmRelease"),
            ("kustomize.toolkit.fluxcd.io/", "Kustomization"),
            ("/v1", "Kustomization"),
            ("apps/v1/extra", "Deployment"),
        ):
            with self.subTest(malformed=api_version, kind=kind):
                with self.assertRaises(AssertionError) as raised:
                    classify(api_version, kind)
                self.assertIn(
                    "not exactly one apiGroup and one version", str(raised.exception)
                )

        # A classified kind outside the Flux domain entirely is the same
        # mis-attribution refusal.
        for api_version, kind in (
            ("xtoolkit.fluxcd.io/v1", "Kustomization"),
            ("kustomize.example.com/v1", "Kustomization"),
            ("helm.example.com/v2", "HelmRelease"),
            ("source.example.com/v1", "OCIRepository"),
            ("v1", "GitRepository"),
        ):
            with self.subTest(foreign_group=api_version, kind=kind):
                with self.assertRaises(AssertionError) as raised:
                    classify(api_version, kind)
                self.assertIn("group it is not in", str(raised.exception))

        # And nothing outside the Flux domain is disturbed: ordinary objects are
        # not custom resources, and they do not raise. `xtoolkit.fluxcd.io`
        # CONTAINS the Flux domain as a substring while being a different
        # domain — a substring test refuses it, label comparison does not, and
        # refusing a third party's CRD is not this module's business.
        for api_version, kind in (
            ("apps/v1", "Deployment"),
            ("v1", "ServiceAccount"),
            ("networking.k8s.io/v1", "NetworkPolicy"),
            ("policy.example.test/v1", "Policy"),
            ("fluxcd.io/v1", "Thing"),
            ("xtoolkit.fluxcd.io/v1", "Deployment"),
        ):
            with self.subTest(ignores=api_version, kind=kind):
                self.assertFalse(classify(api_version, kind))
                self.assertEqual(sum(len(bucket) for bucket in classified[-1]), 0)

    def test_every_reviewed_custom_resource_classifies_identically_after_the_parse(self):
        """Behavioural equivalence on the real tree, proven rather than asserted.

        Parsing the apiGroup instead of prefix-matching the whole apiVersion
        must change NOTHING about the 7 custom resources this repository
        actually declares — it may only change what happens to shapes that were
        being handled by string luck. Both halves are pinned here: the exact
        inventory that must keep classifying, and version-agnosticism within a
        group, which the prefix test also had and which must not regress.
        """

        found = model.flux_custom_resources(ROOT)
        self.assertEqual(len(found.kustomizations), 2)
        self.assertEqual(len(found.helm_releases), 2)
        self.assertEqual(len(found.sources), 3)
        self.assertEqual(
            sorted(
                (document["kind"], document["apiVersion"])
                for bucket in (found.kustomizations, found.helm_releases, found.sources)
                for document in bucket
            ),
            sorted(
                [("Kustomization", "kustomize.toolkit.fluxcd.io/v1")] * 2
                + [("HelmRelease", "helm.toolkit.fluxcd.io/v2")] * 2
                + [("GitRepository", "source.toolkit.fluxcd.io/v1")]
                + [("OCIRepository", "source.toolkit.fluxcd.io/v1")] * 2
            ),
        )
        for index, bucket, group in (
            (0, found.kustomizations, KUSTOMIZE_GROUP),
            (1, found.helm_releases, HELM_GROUP),
            (2, found.sources, SOURCE_GROUP),
        ):
            for document in bucket:
                buckets = ([], [], [])
                with self.subTest(
                    kind=document["kind"], name=document["metadata"]["name"]
                ):
                    self.assertEqual(model._api_group(document["apiVersion"]), group)
                    self.assertTrue(
                        model._classify_flux_document(document, "reviewed", *buckets)
                    )
                    self.assertEqual(len(buckets[index]), 1)
                    self.assertEqual(sum(len(one) for one in buckets), 1)

        # Version-agnostic WITHIN the group: the group decides identity, the
        # version never did and still does not.
        for version in ("v1", "v1beta1", "v1beta2", "v2", "v2beta2", "v1alpha1"):
            for kind, group, index in (
                ("Kustomization", KUSTOMIZE_GROUP, 0),
                ("HelmRelease", HELM_GROUP, 1),
                ("OCIRepository", SOURCE_GROUP, 2),
            ):
                buckets = ([], [], [])
                with self.subTest(version=version, kind=kind):
                    self.assertTrue(
                        model._classify_flux_document(
                            {"apiVersion": group + "/" + version, "kind": kind},
                            "fixture", *buckets,
                        )
                    )
                    self.assertEqual(len(buckets[index]), 1)

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
        argument_add = (
            "- op: add\n  path: /spec/template/spec/containers/0/args/-\n"
            "  value: --no-cross-namespace-refs=true\n"
        )
        patch = next(
            (
                root / relative
                for relative in model.CONTROLLER_DEPLOYMENT_PATCH_FILES
                if argument_add in (root / relative).read_text(encoding="utf-8")
            ),
            None,
        )
        self.assertIsNotNone(patch, "no reviewed argument-add patch remains to mutate")
        patch.write_text(
            patch.read_text(encoding="utf-8").replace(
                argument_add,
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
        # The strictness above must not be satisfied by refusing everything;
        # only the two direct site roots belong to this reconciliation graph.
        for relative in (
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
        "kubernetes/flux-system/controllers/patches/source-controller.yaml",
        "kubernetes/flux-system/controllers/patches/kustomize-controller.yaml",
        "kubernetes/flux-system/controllers/patches/helm-controller.yaml",
        "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
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

    def mutate_occurrence(self, relative, old, new, occurrence):
        root = self.build_tree()
        path = root / relative
        text = path.read_text(encoding="utf-8")
        starts = [match.start() for match in re.finditer(re.escape(old), text)]
        self.assertGreater(len(starts), occurrence)
        start = starts[occurrence]
        path.write_text(
            text[:start] + new + text[start + len(old):], encoding="utf-8"
        )
        return self.validator.flux_rbac_contract_errors(root)

    def test_a_wildcard_is_refused_in_both_yaml_styles(self):
        # Applied to all three authored RBAC files: namespaced access, the
        # shared-role patch, and the install root where the per-controller roles
        # now live (issue #98). A wildcard smuggled into any one must fail.
        for relative, anchor in (
            (
                "kubernetes/flux-system/access.yaml",
                "    resources: [leases]\n",
            ),
            (
                "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                "    resources: [namespaces, serviceaccounts, configmaps]\n",
            ),
            (
                "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
                "    resources: [kustomizations]\n",
            ),
        ):
            for replacement in ("    resources: ['*']\n", "    resources:\n      - '*'\n"):
                with self.subTest(file=Path(relative).name, style=replacement.strip()):
                    errors = self.mutate(relative, anchor, replacement)
                    self.assertTrue(
                        any("wildcard RBAC rule" in error for error in errors), errors
                    )

    def test_site_parent_default_deny_rule_is_name_scoped_without_delete(self):
        relative = "kubernetes/flux-system/access.yaml"
        rule = (
            "  - apiGroups: [networking.k8s.io]\n"
            "    resources: [networkpolicies]\n"
            "    resourceNames: [default-deny]\n"
            "    verbs: [get, update, patch]\n"
        )
        for label, replacement in (
            ("missing", ""),
            ("all names", rule.replace("    resourceNames: [default-deny]\n", "")),
            ("app policy", rule.replace("default-deny", "allow-app-ingress")),
            ("delete", rule.replace("patch]", "patch, delete]")),
            ("watch", rule.replace("patch]", "patch, watch]")),
            ("extra field", rule.replace("    verbs:", "    extra: true\n    verbs:")),
            ("duplicate", rule + rule),
        ):
            with self.subTest(mutation=label):
                errors = self.mutate(relative, rule, replacement)
                self.assertTrue(
                    any("exact direct-site grant" in error for error in errors),
                    errors,
                )

    def test_flux_system_secret_authority_cannot_reappear(self):
        """Even a read of one named Secret in flux-system is refused."""

        anchor = "rules:\n  # Leader election is per-controller"
        for verbs in ("[get]", "[get, update]"):
            injected = (
                "rules:\n"
                '  - apiGroups: [""]\n'
                "    resources: [secrets]\n"
                "    verbs: {}\n".format(verbs)
                + "  # Leader election is per-controller"
            )
            with self.subTest(verbs=verbs):
                errors = self.mutate(
                    "kubernetes/flux-system/access.yaml", anchor, injected
                )
                self.assertTrue(
                    any("must not grant Secret access" in error for error in errors),
                    errors,
                )

    def test_per_controller_roles_cannot_gain_cluster_secret_access(self):
        relative = "kubernetes/flux-system/controllers/per-controller-rbac.yaml"
        rule = (
            '  - apiGroups: [""]\n'
            "    resources: [secrets]\n"
            "    verbs: [get, list, watch]\n"
        )
        for controller in ("source", "kustomize", "helm"):
            anchor = (
                "  name: crd-controller-{}-flux-system\nrules:\n".format(controller)
            )
            with self.subTest(controller=controller):
                errors = self.mutate(relative, anchor, anchor + rule)
                self.assertTrue(
                    any("must not grant cluster-wide Secret access"
                        in error for error in errors),
                    errors,
                )

    def test_shared_controller_role_cannot_regain_secret_access(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
            "    resources: [namespaces, serviceaccounts, configmaps]\n",
            "    resources: [namespaces, serviceaccounts, configmaps, secrets]\n",
        )
        self.assertTrue(
            any("shared crd-controller ClusterRole must not grant Secret access" in error
                for error in errors),
            errors,
        )

    def test_tenant_helm_readback_rules_are_required_and_cannot_write(self):
        relative = "kubernetes/flux-system/access.yaml"
        tenants = ("naranjo-online", "lidersea-com")
        for tenant_index, namespace in enumerate(tenants):
            for group, resource in (("", "pods"), ("apps", "replicasets")):
                group_text = '""' if group == "" else group
                rule = (
                    "  - apiGroups: [{}]\n".format(group_text)
                    + "    resources: [{}]\n".format(resource)
                    + "    verbs: [get, list, watch]\n"
                )
                with self.subTest(
                    namespace=namespace, resource=resource, mutation="missing"
                ):
                    errors = self.mutate_occurrence(
                        relative, rule, "", tenant_index
                    )
                    self.assertTrue(
                        any("exact pods and replicasets" in error for error in errors),
                        errors,
                    )
                with self.subTest(
                    namespace=namespace, resource=resource, mutation="write"
                ):
                    errors = self.mutate_occurrence(
                        relative,
                        rule,
                        rule.replace("get, list, watch", "get, list, watch, delete"),
                        tenant_index,
                    )
                    self.assertTrue(
                        any("exact pods and replicasets" in error for error in errors),
                        errors,
                    )
                with self.subTest(
                    namespace=namespace, resource=resource, mutation="resourceNames"
                ):
                    errors = self.mutate_occurrence(
                        relative,
                        rule,
                        rule.replace(
                            "    verbs: [get, list, watch]\n",
                            "    verbs: [get, list, watch]\n"
                            "    resourceNames: [release]\n",
                        ),
                        tenant_index,
                    )
                    self.assertTrue(
                        any("exact pods and replicasets" in error for error in errors),
                        errors,
                    )

    def test_naranjo_pvc_rule_is_required_exact_and_site_local(self):
        relative = "kubernetes/flux-system/access.yaml"
        rule = (
            '  - apiGroups: [""]\n'
            "    resources: [persistentvolumeclaims]\n"
            "    verbs: [get, list, watch, create, update, patch, delete]\n"
        )
        for label, replacement in (
            ("missing", ""),
            (
                "extra verb",
                rule.replace("patch, delete", "patch, delete, deletecollection"),
            ),
            (
                "combined backing resource",
                rule.replace(
                    "resources: [persistentvolumeclaims]",
                    "resources: [persistentvolumeclaims, persistentvolumes]",
                ),
            ),
        ):
            with self.subTest(mutation=label):
                errors = self.mutate(relative, rule, replacement)
                self.assertTrue(
                    any("exact PVC lifecycle" in error for error in errors), errors
                )

        lidersea_role = (
            "kind: Role\n"
            "metadata:\n"
            "  name: helm-reconciler\n"
            "  namespace: lidersea-com\n"
            "rules:\n"
        )
        errors = self.mutate(relative, lidersea_role, lidersea_role + rule)
        self.assertTrue(
            any("PVC lifecycle must be only" in error for error in errors), errors
        )

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
        for relative, anchor in (
            (
                "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                "    resources: [namespaces, serviceaccounts, configmaps]\n",
            ),
            (
                "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
                "    resources: [kustomizations]\n",
            ),
        ):
            with self.subTest(file=Path(relative).name):
                errors = self.mutate(
                    relative, anchor, "    resources:\n      - serviceaccounts/token\n"
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

    def test_reconciler_config_watcher_gates_are_exact_and_unique(self):
        operation = (
            "- op: add\n"
            "  path: /spec/template/spec/containers/0/args/-\n"
            "  value: --feature-gates=DisableConfigWatchers=true\n"
        )
        for controller in ("kustomize", "helm"):
            relative = (
                "kubernetes/flux-system/controllers/patches/"
                + controller
                + "-controller.yaml"
            )
            for label, replacement in (
                ("missing", ""),
                ("false", operation.replace("=true", "=false")),
                ("combined", operation.replace("=true", "=true,ExternalArtifact=true")),
                (
                    "selector substitute",
                    operation.replace(
                        "--feature-gates=DisableConfigWatchers=true",
                        "--watch-configs-label-selector=flux-watch=enabled",
                    ),
                ),
                ("duplicate", operation + operation),
            ):
                with self.subTest(controller=controller, mutation=label):
                    errors = self.mutate(relative, operation, replacement)
                    self.assertTrue(
                        any("feature-gate args must be exactly" in error for error in errors),
                        errors,
                    )

    def test_secondary_source_rules_are_exact_read_only_and_closed(self):
        relative = "kubernetes/flux-system/controllers/per-controller-rbac.yaml"
        cases = (
            (
                "kustomize",
                "  - apiGroups: [source.toolkit.fluxcd.io]\n"
                "    resources: [buckets, gitrepositories, ocirepositories]\n"
                "    verbs: [get, list, watch]\n",
            ),
            (
                "helm",
                "  - apiGroups: [source.toolkit.fluxcd.io]\n"
                "    resources: [ocirepositories]\n"
                "    verbs: [get, list, watch]\n",
            ),
        )
        for controller, rule in cases:
            for label, replacement in (
                ("missing", ""),
                ("write", rule.replace("get, list, watch", "get, list, watch, patch")),
                (
                    "extra kind",
                    rule.replace(
                        "ocirepositories]",
                        "ocirepositories, externalartifacts]",
                    ),
                ),
                (
                    "extra field",
                    rule.replace(
                        "    verbs:",
                        "    resourceNames: [one]\n    verbs:",
                    ),
                ),
                ("duplicate", rule + rule),
            ):
                with self.subTest(controller=controller, mutation=label):
                    errors = self.mutate(relative, rule, replacement)
                    self.assertTrue(
                        any(
                            "secondary source" in error
                            for error in errors
                        ),
                        errors,
                    )

    def test_a_flux_api_group_in_the_shared_role_is_refused(self):
        """The split's structural guard, shown to fail on the thing it bans.

        Re-adding a Flux group to the shared role is the whole regression: the
        role is bound to all three controllers, so one rule there hands every
        controller authority over the others' objects again.
        """

        for group in (
            "source.toolkit.fluxcd.io",
            "kustomize.toolkit.fluxcd.io",
            "helm.toolkit.fluxcd.io",
        ):
            with self.subTest(group=group):
                errors = self.mutate(
                    "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                    '  - apiGroups: [""]\n    resources: [events]\n',
                    "  - apiGroups: [{}]\n    resources: [events]\n".format(group),
                )
                self.assertTrue(
                    any("must not name " + group in error for error in errors), errors
                )

    def test_a_second_subject_on_a_per_controller_binding_is_refused(self):
        """A split role bound twice is the shared role under a new name."""

        errors = self.mutate(
            "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
            "  name: crd-controller-source-flux-system\nsubjects:\n"
            "  - kind: ServiceAccount\n    name: source-controller\n",
            "  name: crd-controller-source-flux-system\nsubjects:\n"
            "  - kind: ServiceAccount\n    name: helm-controller\n    namespace: flux-system\n"
            "  - kind: ServiceAccount\n    name: source-controller\n",
        )
        self.assertTrue(
            any("must name only source-controller" in error for error in errors), errors
        )

    def test_a_missing_per_controller_role_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
            "  name: crd-controller-helm-flux-system\nrules:\n",
            "  name: crd-controller-renamed\nrules:\n",
        )
        self.assertTrue(
            any(
                "per-controller ClusterRole missing from the install root: "
                "crd-controller-helm-flux-system" in error
                for error in errors
            ),
            errors,
        )

    def test_a_repointed_per_controller_binding_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
            "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n"
            "  name: crd-controller-kustomize-flux-system\n",
            "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n"
            "  name: crd-controller-source-flux-system\n",
        )
        self.assertTrue(
            any(
                "crd-controller-kustomize-flux-system must bind ClusterRole" in error
                for error in errors
            ),
            errors,
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
            "  name: flux-controller-runtime\n  namespace: flux-system\nrules:",
            "  name: flux-controller-renamed\n  namespace: flux-system\nrules:",
        )
        self.assertTrue(
            any("flux-system/flux-controller-runtime" in error for error in errors), errors
        )

    def test_a_reindented_rule_still_reaches_the_exact_grant_check(self):
        # P3-3, the same vacuity class as commit 2 one axis over: re-indenting a
        # rule is valid YAML that changes nothing about what it grants, and the
        # block splitter used to assume a maximum indent.
        root = self.build_tree()
        path = root / "kubernetes/flux-system/access.yaml"
        text = path.read_text(encoding="utf-8")
        old = (
            "rules:\n"
            '  - apiGroups: [""]\n'
            "    resources: [serviceaccounts]\n"
            "    verbs: [impersonate]\n"
            "    resourceNames: [helm-reconciler]"
        )
        self.assertIn(old, text)
        reindented = (
            "rules:\n"
            '      - apiGroups: [""]\n'
            "        resources: [serviceaccounts]\n"
            "        verbs: [impersonate, delete]\n"
            "        resourceNames: [helm-reconciler]"
        )
        path.write_text(text.replace(old, reindented, 1), encoding="utf-8")
        errors = self.validator.flux_rbac_contract_errors(root)
        self.assertTrue(any("exact direct-site grant" in error for error in errors), errors)

    def test_a_reordered_rule_still_reaches_the_exact_grant_check(self):
        """The same vacuity class as re-indentation, one axis over.

        `_rbac_rule_blocks` returned each rule with its `- ` item marker still
        in front of the first field, and `_rbac_rule_list` reads a field only
        where the marker is not. So the FIRST field of every rule was invisible
        to every check built on that helper, and RBAC does not care what order
        a rule's fields are written in: moving `resources:` to the front is
        valid YAML that grants exactly the same thing and used to evade the
        flux-system Secret-write check completely.

        Found while adding the shared-role apiGroups check for issue #98, whose
        field IS first on every rule — it would have been decorative for the
        same reason. The helper now substitutes the marker with the two spaces
        it occupied, and this is the proof.
        """

        root = self.build_tree()
        path = root / "kubernetes/flux-system/access.yaml"
        text = path.read_text(encoding="utf-8")
        old = (
            "rules:\n"
            '  - apiGroups: [""]\n'
            "    resources: [serviceaccounts]\n"
            "    verbs: [impersonate]\n"
            "    resourceNames: [helm-reconciler]"
        )
        self.assertIn(old, text)
        reordered = (
            "rules:\n"
            "  - resources: [serviceaccounts]\n"
            '    apiGroups: [""]\n'
            "    resourceNames: [helm-reconciler]\n"
            "    verbs: [impersonate, update]"
        )
        path.write_text(text.replace(old, reordered, 1), encoding="utf-8")
        errors = self.validator.flux_rbac_contract_errors(root)
        self.assertTrue(any("exact direct-site grant" in error for error in errors), errors)

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
            "      - example-name\n"
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
                    "resourceNames": ["example-name"],
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
        # Fixed-object get/update/patch can be name-scoped; list/create carry no
        # object name and cannot use such a rule.
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
                            "name": "system:serviceaccounts:foreign",
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


class FluxRbacControllerRootSufficiencyTests(unittest.TestCase):
    """The INSTALL ROOT alone must authorize every primary and secondary informer.

    The rest of this file proves the reviewed desired state is sufficient using
    the full composition — install root PLUS `access.yaml`. That composition is
    the steady state, and it hid a real defect: bootstrap applies `access.yaml`
    only after the controller install transaction, so it does not exist yet
    when `scripts/install-flux-controllers.sh` applies the controllers root.

    While the six per-controller objects lived in `access.yaml`, a fresh
    `--apply` therefore created three controllers whose shared ClusterRole had
    just had every Flux API group stripped out of it and whose replacements were
    nowhere in the transaction. All twenty-four primary/secondary `list`/`watch`
    probes denied; `--watch-all-namespaces=true` makes each of those a
    cluster-wide informer the controller cannot start, so the install could
    never reach readiness. Nothing in the sufficiency proof noticed, because the
    proof was reading a composition the installer does not apply.

    So this battery builds its authorizer from `controller_root_rbac` — the
    install transaction and nothing else — and root-composition drift of that
    class goes red here, by name.
    """

    @classmethod
    def setUpClass(cls):
        cls.authorizer = Authorizer.from_documents(model.controller_root_rbac(ROOT))
        cls.full = Authorizer.from_documents(model.effective_flux_rbac(ROOT))

    def informer_probes(self):
        """Every primary and secondary cluster-wide list/watch, derived once."""

        for controller in sorted(model.OWNED_CONTROLLER_KINDS):
            kinds = tuple(dict.fromkeys(
                model.OWNED_CONTROLLER_KINDS.get(controller, ())
                + model.CONTROLLER_SECONDARY_WATCH_KINDS.get(controller, ())
            ))
            for kind in kinds:
                group, resource = model.KIND_RESOURCES[kind][:2]
                for verb in ("list", "watch"):
                    yield controller, kind, group, resource, verb

    def test_every_primary_and_secondary_informer_is_authorized_by_the_install_alone(self):
        probes = list(self.informer_probes())
        # Seven primary plus five secondary kind/controller pairs, two verbs each.
        self.assertEqual(len(probes), 24, "the informer set changed shape")
        denied = [
            "{} cannot {} {}".format(controller, verb, kind)
            for controller, kind, group, resource, verb in probes
            if not self.authorizer.allows(
                Subject("flux-system", controller), verb, group, resource, namespace=None
            )
        ]
        self.assertEqual(denied, [], "the install root does not authorize its own controllers")

    def test_helm_cluster_secret_access_is_denied_by_the_install_alone(self):
        for verb in (
            "get", "list", "watch", "create", "update", "patch", "delete",
            "deletecollection",
        ):
            with self.subTest(verb=verb):
                self.assertFalse(
                    self.authorizer.allows(
                        HELM_CONTROLLER, verb, "", "secrets", namespace=None
                    )
                )

    def test_the_informer_authority_is_cluster_wide_not_namespaced(self):
        """A Role in flux-system cannot satisfy a `--watch-all-namespaces` informer.

        Asserting the probes pass with `namespace=None` above is only meaningful
        if that genuinely means cluster scope, so this pins the flag that makes
        it so: were it dropped, namespaced authority would suffice and the roles
        could be narrowed — a change that must be made deliberately, not drift
        into place.
        """

        arguments = model.controller_arguments(ROOT)
        for controller in model.OWNED_CONTROLLER_KINDS:
            with self.subTest(controller=controller):
                self.assertIn(
                    model.WATCH_ALL_NAMESPACES_FLAG,
                    arguments[Subject("flux-system", controller)],
                )

    def test_reconciler_config_watchers_are_disabled_exactly(self):
        """Avoid cluster-wide Secret list/watch without enabling other gates."""

        arguments = model.controller_arguments(ROOT)
        for controller in (KUSTOMIZE_CONTROLLER, HELM_CONTROLLER):
            with self.subTest(controller=str(controller)):
                self.assertEqual(
                    [
                        argument for argument in arguments[controller]
                        if argument.startswith("--feature-gates=")
                    ],
                    [model.DISABLE_CONFIG_WATCHERS_FLAG],
                )
        self.assertNotIn(model.DISABLE_CONFIG_WATCHERS_FLAG, arguments[SOURCE_CONTROLLER])

    def test_the_six_objects_are_rendered_by_the_install_root(self):
        """Placement, not just presence: they must be IN the applied transaction.

        `controller_root_rbac` reads the file the install root names. If the six
        objects were moved back to `access.yaml`, or the resource entry were
        dropped from `controllers/kustomization.yaml`, the authority would still
        exist in the repository and the full-composition proofs would still
        pass — and the install would still be broken.
        """

        kustomization = (
            ROOT / "kubernetes/flux-system/controllers/kustomization.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("- per-controller-rbac.yaml", kustomization)
        names = {
            (document.get("kind"), (document.get("metadata") or {}).get("name"))
            for document in model.load_documents(
                ROOT / "kubernetes/flux-system/controllers/per-controller-rbac.yaml"
            )
        }
        for role, owner in sorted(PER_CONTROLLER_CLUSTER_ROLES.items()):
            with self.subTest(role=role):
                self.assertIn(("ClusterRole", role), names)
                self.assertIn(("ClusterRoleBinding", role), names)

    def test_access_yaml_no_longer_carries_cluster_scoped_controller_authority(self):
        """The move was a MOVE. A copy would drift, and drift silently."""

        access = model.load_documents(ROOT / "kubernetes/flux-system/access.yaml")
        offenders = [
            (document.get("kind"), (document.get("metadata") or {}).get("name"))
            for document in access
            if document.get("kind") in ("ClusterRole", "ClusterRoleBinding")
        ]
        self.assertEqual(offenders, [])

    def test_the_install_root_grants_no_more_than_the_full_model(self):
        """Moving authority earlier must not have widened it.

        Everything the install root allows, the reviewed full composition must
        allow too. If the two disagree the narrowness proof — which reads the
        full composition — is no longer covering what the installer creates.
        """

        for controller, kind, group, resource, verb in self.informer_probes():
            subject = Subject("flux-system", controller)
            with self.subTest(controller=controller, kind=kind, verb=verb):
                if self.authorizer.allows(subject, verb, group, resource, namespace=None):
                    self.assertTrue(
                        self.full.allows(subject, verb, group, resource, namespace=None)
                    )


if __name__ == "__main__":
    unittest.main()
