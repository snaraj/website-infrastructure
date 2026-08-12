"""Offline contracts for the reproducible, inert Flux controller install.

Nothing here contacts a real cluster. These tests pin the properties that make
the install reviewable and the namespace fail-closed: the generated blanket
egress allow is removed, the egress allowlist is exactly the reviewed set, Pod
Security is enforced rather than warned about, the guarded installer cannot be
pointed at the unsuspended bootstrap root, and the documentation states the
ordering rather than implying it.

The *behavioural* classes run the real installer inside a disposable Git
repository whose ``versions.env``, install roots, ``kustomize`` and ``kubectl``
are all fixtures, so the installer's own bindings are exercised rather than
bypassed. The stubbed ``kubectl`` is a small model of the cluster, not a
recording: it keeps an object registry, refuses any API call that did not carry
an explicit ``--kubeconfig``/``--context``/``--server``, and — the reason it
exists — refuses to create controller Deployments into a namespace whose egress
is denied with no DNS or API-server allow in force. That refusal is the
executable form of the install-ordering deadlock:

``FreshClusterDryRunGateTests`` drives the pre-apply gate through the
fresh-cluster shape it must accept — 14 cluster-scoped ``created`` plus 11
children reporting ``namespaces "flux-system" not found``
(kubernetes/kubernetes#83562, which the old "all 25 must be created" gate could
never pass) — and the genuine failures it must still refuse.
``InstallOrderingTests`` proves the phases, ``ToolAndTargetBindingTests`` proves
the identity/target closure, and ``ApplyTransactionTests`` proves the ledger
rollback including the cluster-scoped objects no namespace delete can remove.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import hermetic_git_environment, load_script, required_tool


BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required to exercise the installer gate"
GIT = shutil.which("git")

ROOT = Path(__file__).resolve().parents[2]
CONTROLLERS = ROOT / "kubernetes" / "flux-system" / "controllers"
EGRESS = ROOT / "kubernetes" / "flux-system" / "egress"
INSTALLER = ROOT / "scripts" / "install-flux-controllers.sh"
RUNBOOK = ROOT / "docs" / "runbooks" / "flux-install.md"
RENDERER = ROOT / "scripts" / "render-manifests.sh"
REGO = ROOT / "policies" / "conftest" / "kubernetes.rego"
BOOTSTRAP_README = ROOT / "bootstrap" / "flux" / "README.md"
VERSIONS = ROOT / "versions.env"

# The exact reviewed egress inventory. Named here rather than derived from the
# manifest so that deleting a policy is a test failure instead of a silently
# smaller expectation.
EXPECTED_EGRESS_POLICIES = (
    "default-deny",
    "flux-controllers-dns",
    "flux-controllers-artifacts",
    "flux-controllers-public-https",
    "flux-controllers-kube-apiserver",
)
# The four that must be in force BEFORE any controller Pod exists. The fifth,
# public HTTPS, is deliberately deferred until the controllers are observed
# healthy and idle.
STARTUP_EGRESS_POLICIES = (
    "default-deny",
    "flux-controllers-dns",
    "flux-controllers-artifacts",
    "flux-controllers-kube-apiserver",
)
PUBLIC_EGRESS_POLICY = "flux-controllers-public-https"
# Every private, loopback, link-local, carrier-grade-NAT, multicast, and
# reserved range that the one public-HTTPS rule excludes. This is the same set
# the reviewed tunnel egress policy uses; a shorter list is a wider allow.
EXPECTED_EXCLUDED_RANGES = (
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

# The 13 cluster-scoped objects that a `kubectl delete namespace flux-system`
# cannot remove, and the Namespace itself. The installer's rollback and the
# runbook's removal procedure are both measured against this list.
CLUSTER_SCOPED_CRDS = (
    "buckets.source.toolkit.fluxcd.io",
    "externalartifacts.source.toolkit.fluxcd.io",
    "gitrepositories.source.toolkit.fluxcd.io",
    "helmcharts.source.toolkit.fluxcd.io",
    "helmreleases.helm.toolkit.fluxcd.io",
    "helmrepositories.source.toolkit.fluxcd.io",
    "kustomizations.kustomize.toolkit.fluxcd.io",
    "ocirepositories.source.toolkit.fluxcd.io",
)
CLUSTER_SCOPED_ROLES = (
    "crd-controller-flux-system",
    "flux-edit-flux-system",
    "flux-view-flux-system",
)
CLUSTER_SCOPED_BINDINGS = (
    "cluster-reconciler-flux-system",
    "crd-controller-flux-system",
)
CONTROLLER_DEPLOYMENTS = ("source-controller", "kustomize-controller", "helm-controller")

# RFC 5737 documentation space throughout: TEST-NET-2 is the fixture's reviewed
# API server, TEST-NET-3 the decoy context nobody named.
FIXTURE_SERVER = "https://198.51.100.10:6443"
FIXTURE_CONTEXT = "reviewed-operator"
FIXTURE_OTHER_SERVER = "https://203.0.113.7:6443"
FIXTURE_OTHER_CONTEXT = "some-other-cluster"
FIXTURE_KUSTOMIZE_VERSION = "v5.8.1"
FIXTURE_KUBECTL_VERSION = "v1.36.3"


def read(path):
    return path.read_text(encoding="utf-8")


class BlanketEgressRemovalTests(unittest.TestCase):
    """The generated export's `egress: [{}]` must not survive into the render."""

    def test_patch_removes_the_generated_blanket_rule(self):
        patch = read(CONTROLLERS / "patches" / "allow-egress.yaml")
        operations = re.findall(r"(?m)^-\s*op:\s*(\S+)\s*$", patch)
        self.assertEqual(
            operations,
            ["remove"],
            "the allow-egress patch must remove and nothing else",
        )
        self.assertIn("path: /spec/egress", patch)

    def test_install_root_applies_the_patch_to_the_generated_policy(self):
        index = read(CONTROLLERS / "kustomization.yaml")
        self.assertIn("path: patches/allow-egress.yaml", index)
        self.assertRegex(index, r"(?m)^\s+name:\s+allow-egress\s*$")
        self.assertRegex(index, r"(?m)^\s+kind:\s+NetworkPolicy\s*$")

    def test_generated_export_still_carries_the_rule_the_patch_removes(self):
        # A vacuity guard: if upstream ever stops shipping the blanket allow,
        # the patch becomes a no-op and this suite would otherwise keep
        # asserting a removal that removes nothing.
        components = read(CONTROLLERS / "gotk-components.yaml")
        allow_egress = components.split("name: allow-egress", 1)
        self.assertEqual(
            len(allow_egress),
            2,
            "the generated export no longer contains allow-egress",
        )
        self.assertRegex(
            allow_egress[1].split("---", 1)[0],
            r"(?m)^\s+egress:\s*\n\s+-\s+\{\}\s*$",
            "the generated export no longer carries the blanket egress rule; "
            "the removal patch has become a no-op and must be re-derived",
        )

    def test_the_patched_policy_is_a_namespace_wide_deny_which_forces_the_ordering(self):
        # The install-ordering defect starts here: with /spec/egress removed the
        # generated allow-egress keeps podSelector {} and policyTypes
        # [Ingress, Egress], which on an enforcing CNI denies egress for every
        # Pod in the namespace. That is why the controllers cannot be created
        # in the same breath as this policy, and why the installer's phase split
        # exists. If upstream ever narrows the podSelector or drops Egress from
        # policyTypes, the ordering rationale changes and this says so.
        components = read(CONTROLLERS / "gotk-components.yaml")
        document = components.split("name: allow-egress", 1)[1].split("---", 1)[0]
        self.assertRegex(document, r"(?m)^\s+podSelector:\s*\{\}\s*$")
        self.assertRegex(
            document, r"(?ms)^\s+policyTypes:\s*\n\s+-\s+Ingress\s*\n\s+-\s+Egress\s*$"
        )


class ControllerFlagScopeTests(unittest.TestCase):
    """Flags belong to the controller that implements them.

    `--no-cross-namespace-refs` bounds cross-namespace `sourceRef` on the kinds
    kustomize-controller and helm-controller reconcile. source-controller does
    not implement it, and the binary exits 2 on an unknown flag, so adding it
    there is not a hardening — it is a guaranteed crashloop. The repository
    required it on all three, which meant every install of these manifests
    would have failed.
    """

    RECONCILER_ONLY_FLAGS = (
        "--no-cross-namespace-refs",
        "--no-remote-bases",
        "--default-service-account",
    )

    def test_source_controller_carries_no_reconciler_only_flag(self):
        patch = read(CONTROLLERS / "patches" / "source-controller.yaml")
        added = re.findall(r"(?m)^\s*value:\s*(--\S+)\s*$", patch)
        for flag in added:
            for reconciler_only in self.RECONCILER_ONLY_FLAGS:
                with self.subTest(flag=flag, forbidden=reconciler_only):
                    self.assertFalse(
                        flag.startswith(reconciler_only),
                        "source-controller does not accept " + reconciler_only,
                    )

    def test_the_reconcilers_still_carry_the_cross_namespace_bound(self):
        # The tenancy boundary must not be lost while fixing where it lives.
        for name, expected in (
            (
                "kustomize-controller",
                (
                    "--no-cross-namespace-refs=true",
                    "--no-remote-bases=true",
                    "--default-service-account=default",
                ),
            ),
            (
                "helm-controller",
                ("--no-cross-namespace-refs=true", "--default-service-account=default"),
            ),
        ):
            patch = read(CONTROLLERS / "patches" / (name + ".yaml"))
            for flag in expected:
                with self.subTest(controller=name, flag=flag):
                    self.assertIn("value: " + flag, patch)

    def test_the_live_state_expectation_matches_the_patched_arguments(self):
        # bootstrap.sh both expects the reviewed argument set and re-probes the
        # live Deployment. Either one still demanding the flag would fail a
        # correctly installed source-controller.
        bootstrap = read(ROOT / "bootstrap" / "flux" / "bootstrap.sh")
        self.assertIn(
            "! grep -q -- '--no-cross-namespace-refs' <<<\"${source_args}\" || fail",
            bootstrap,
        )
        self.assertRegex(
            bootstrap,
            r'"source-controller": \(\s*\n\s*os\.environ\["FLUX_EXPECTED_SOURCE_IMAGE"\],'
            r'(?:\s*\n\s*#[^\n]*)*\s*\n\s*\[\],',
        )


class EgressAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.text = read(EGRESS / "network-policies.yaml")

    def test_every_reviewed_policy_is_present_exactly_once(self):
        for name in EXPECTED_EGRESS_POLICIES:
            with self.subTest(policy=name):
                matches = re.findall(
                    r"(?m)^\s*name:\s*{}\s*$".format(re.escape(name)), self.text
                )
                self.assertEqual(len(matches), 1)

    def test_no_policy_grants_an_unbounded_or_cleartext_flow(self):
        # `to: []` and a bare `- {}` peer both mean "everywhere".
        self.assertNotRegex(self.text, r"(?m)^\s*-\s*to:\s*\[\]\s*$")
        self.assertNotRegex(self.text, r"(?m)^\s*-\s*\{\}\s*$")
        ports = set(re.findall(r"(?m)^\s*-\s*port:\s*(\d+)\s*$", self.text))
        self.assertEqual(
            ports,
            {"53", "80", "443", "9090", "6443"},
            "the reviewed flows are DNS, the in-cluster artifact fetch, "
            "public HTTPS, and the API server",
        )

    def test_the_public_rule_excludes_every_private_range(self):
        excluded = re.findall(r"(?m)^\s*-\s*(\d+\.\d+\.\d+\.\d+/\d+)\s*$", self.text)
        self.assertEqual(tuple(excluded), EXPECTED_EXCLUDED_RANGES)

    def test_the_api_server_destination_stays_documentation_space(self):
        # RFC 5737 TEST-NET-1. A real control-plane address here would be a
        # privacy failure that this test catches before the privacy gate does.
        destinations = re.findall(r"(?m)^\s*cidr:\s*(\S+)\s*$", self.text)
        self.assertIn("192.0.2.0/32", destinations)
        self.assertEqual(
            [value for value in destinations if value != "0.0.0.0/0"],
            ["192.0.2.0/32"],
        )
        self.assertIn("sentinel-until-reviewed-control-plane-endpoint", self.text)

    def test_the_overlay_is_rendered_but_unreachable_from_the_bootstrap_root(self):
        self.assertRegex(
            read(RENDERER), r"(?m)^\s*kubernetes/flux-system/egress\s*$"
        )
        root = read(ROOT / "kubernetes" / "flux-system" / "kustomization.yaml")
        self.assertNotRegex(
            root,
            r"(?m)^\s*-\s+egress\s*$",
            "the egress overlay must not be reachable from the root that also "
            "carries the unsuspended gotk-sync objects",
        )

    def test_the_startup_allows_cover_dns_the_artifact_fetch_and_the_api_server(self):
        # The ordering fix rests on this: the four policies the installer puts
        # in force before any Pod exists must be exactly the ones a controller
        # needs to elect a leader and sync a cache. Public HTTPS is not one of
        # them, which is why it is deferred.
        self.assertEqual(
            set(EXPECTED_EGRESS_POLICIES) - set(STARTUP_EGRESS_POLICIES),
            {PUBLIC_EGRESS_POLICY},
        )
        for name in STARTUP_EGRESS_POLICIES:
            with self.subTest(policy=name):
                self.assertIn("name: " + name, self.text)


class PodSecurityEnforcementTests(unittest.TestCase):
    def test_the_namespace_patch_enforces_restricted_at_a_pinned_version(self):
        patch = read(CONTROLLERS / "patches" / "namespace.yaml")
        for label, value in (
            ("enforce", "restricted"),
            ("enforce-version", "v1.36"),
            ("audit", "restricted"),
            ("audit-version", "v1.36"),
            ("warn-version", "v1.36"),
        ):
            with self.subTest(label=label):
                self.assertRegex(
                    patch,
                    r"(?m)^\s*path:\s*/metadata/labels/pod-security\.kubernetes\.io~1{}\s*$".format(
                        re.escape(label)
                    ),
                )
                self.assertIn("value: " + value, patch)

    def test_the_install_root_applies_the_namespace_patch(self):
        # A patch file that exists but is not wired in is the same failure as
        # no patch at all. Found by mutating the wiring rather than the file.
        self.assertIn(
            "path: patches/namespace.yaml", read(CONTROLLERS / "kustomization.yaml")
        )

    def test_the_generated_namespace_only_warns(self):
        # The gap this patch closes. If a future export starts enforcing on its
        # own, the patch's `add` operations would begin colliding and this test
        # says why.
        components = read(CONTROLLERS / "gotk-components.yaml")
        namespace = components.split("kind: Namespace", 1)[1].split("---", 1)[0]
        self.assertIn("pod-security.kubernetes.io/warn: restricted", namespace)
        self.assertNotIn("pod-security.kubernetes.io/enforce", namespace)

    def test_the_live_state_verifier_expects_the_enforced_labels(self):
        # The manifest and bootstrap.sh's reviewed-live-state expectation must
        # move together; before this change they disagreed, and the disagreement
        # was invisible because the verifier is code-blocked.
        bootstrap = read(ROOT / "bootstrap" / "flux" / "bootstrap.sh")
        self.assertRegex(
            bootstrap,
            r"labels = \{\s*\n\s*\*\*flux_labels\(\),\s*\n\s*\*\*PSA_LABELS,",
        )


class InstallerGuardTests(unittest.TestCase):
    def setUp(self):
        self.text = read(INSTALLER)

    def test_the_install_target_is_a_constant_that_is_not_the_bootstrap_root(self):
        self.assertIn(
            "INSTALL_TARGET='kubernetes/flux-system/controllers'", self.text
        )
        self.assertNotIn("INSTALL_TARGET='kubernetes/flux-system'", self.text)
        self.assertNotIn('INSTALL_TARGET="$1"', self.text)
        self.assertNotIn("kustomize build \"${REPO_ROOT}/kubernetes/flux-system\"", self.text)

    def test_it_refuses_a_render_that_would_reconcile_anything(self):
        for kind in (
            "GitRepository",
            "Kustomization",
            "HelmRelease",
            "OCIRepository",
            "ImageUpdateAutomation",
        ):
            with self.subTest(kind=kind):
                self.assertIn(kind, self.text)
        self.assertIn(
            "this install must reconcile nothing", self.text
        )

    def test_it_refuses_a_render_that_reopens_egress_or_relaxes_pod_security(self):
        self.assertIn("the allow-egress patch is not applied", self.text)
        self.assertIn("does not enforce restricted Pod Security", self.text)

    def test_it_dry_runs_before_it_applies_and_bounds_the_inventory(self):
        # The gate keeps a server-side dry run and the exact-25 bound, and now
        # also carries the fresh-cluster classification (14 cluster-scoped +
        # 11 namespace-not-found children) and the namespace-independent
        # corroboration (client-side strict validation). The behaviour is
        # exercised in FreshClusterDryRunGateTests; these pins fail if the
        # corrected gate is reverted to the old "all 25 must be created" shape.
        self.assertIn("--dry-run=server", self.text)
        self.assertIn("--dry-run=client --validate=strict", self.text)
        self.assertIn("EXPECTED_OBJECTS=25", self.text)
        self.assertIn("EXPECTED_CLUSTER_SCOPED=14", self.text)
        self.assertIn("EXPECTED_NAMESPACED=11", self.text)
        self.assertIn('namespaces "flux-system" not found', self.text)
        plan_index = self.text.index('"$MODE" == \'--plan\'')
        apply_index = self.text.rindex("apply_phase workloads")
        self.assertLess(
            plan_index,
            apply_index,
            "the plan-only exit must precede the mutating apply",
        )

    def test_it_never_uses_kubectl_apply_k(self):
        self.assertNotIn("apply -k", self.text)

    def test_the_phase_constants_partition_the_reviewed_inventory(self):
        # 22 + 3 = 25 and 4 + 1 = 5. Constants that stopped adding up would let
        # a phase quietly drop an object; the installer re-checks the same sums
        # at run time against the actual split.
        self.assertIn("EXPECTED_PREREQUISITES=22", self.text)
        self.assertIn("EXPECTED_WORKLOADS=3", self.text)
        self.assertIn("EXPECTED_EGRESS_POLICIES=5", self.text)
        self.assertIn("EXPECTED_STARTUP_POLICIES=4", self.text)

    def test_every_api_operation_goes_through_the_bound_wrapper(self):
        # A single call site for the three bindings is what makes "every API
        # operation carries an explicit target" checkable at all. Any direct
        # "$KUBECTL_BIN" use outside the tool-identity probes would bypass it.
        direct = re.findall(r'"\$KUBECTL_BIN"', self.text)
        self.assertEqual(
            len(direct),
            4,
            "only the version probe, the digest probe, the kubeconfig probe, "
            "and the kube() wrapper may name the kubectl binary directly",
        )
        self.assertIn(
            '"$KUBECTL_BIN" --kubeconfig "$KUBECONFIG_PATH" --context "$KUBE_CONTEXT"',
            self.text,
        )

    def test_it_binds_the_tools_and_the_render_to_the_reviewed_pins(self):
        for fragment in (
            "KUSTOMIZE_VERSION",
            "KUBERNETES_VERSION",
            "KUBECTL_LINUX_AMD64_SHA256",
            "KUBECTL_ARM64_SHA256",
            "--expect-render-sha256",
            "status --porcelain",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)

    def test_the_kubectl_digest_pins_it_reads_exist_in_versions_env(self):
        # A pin name that drifted out of versions.env would make the digest
        # binding die on every run; a pin that was never there would make it
        # vacuous. versions.env is platform-lane and read-only from here, so
        # this asserts the coupling rather than repairing it.
        versions = read(VERSIONS)
        for key in (
            "KUSTOMIZE_VERSION",
            "KUBERNETES_VERSION",
            "KUBECTL_LINUX_AMD64_SHA256",
            "KUBECTL_ARM64_SHA256",
        ):
            with self.subTest(pin=key):
                self.assertRegex(versions, r"(?m)^{}=\S+$".format(re.escape(key)))

    def test_it_never_sources_the_pin_file(self):
        self.assertNotRegex(self.text, r"(?m)^\s*(source|\.)\s+.*versions\.env")


class InstallDocumentationTests(unittest.TestCase):
    def test_the_runbook_states_the_ordering_and_the_inert_property(self):
        text = read(RUNBOOK)
        for fragment in (
            "Never apply `kubernetes/flux-system` — the parent root",
            "no `suspend`",
            "scripts/install-flux-controllers.sh --plan",
            "scripts/install-flux-controllers.sh --apply",
            "192.0.2.0/32",
            "kubectl delete namespace flux-system",
            "separate reviewed pull request",
            "Kyverno is not installed",
            "cluster-admin",
            "fulcio.sigstore.dev",
            # The fresh-vs-existing dry-run semantics: the ns-not-found on the
            # children is documented as expected, not a failure (the P3 fix).
            'namespaces "flux-system" not found',
            "kubernetes/kubernetes#83562",
            "expected, healthy",
            "client-side strict validation",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)

    def test_the_runbook_documents_the_ordered_phases_and_the_binding(self):
        text = read(RUNBOOK)
        for fragment in (
            "--expect-render-sha256",
            "--kubeconfig",
            "--context",
            "--server",
            "--open-public-egress",
            "deadlock",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        # The readiness check must come after the startup allows, not before:
        # the ordering the runbook describes has to be the one the installer
        # performs, or the document re-creates the defect in prose. The old
        # runbook applied the controllers, demanded 3/3 at 1/1, and only then
        # applied any allow -- which on an enforcing CNI can never pass.
        rationale = text.index("Why the apply is ordered")
        apply_step = text.index("## Step 2 — apply, in phases")
        verify_step = text.index("## Step 3 — verify the controllers")
        public_step = text.index("## Step 4 — open public HTTPS, last")
        self.assertLess(rationale, apply_step)
        self.assertLess(apply_step, verify_step)
        self.assertLess(verify_step, public_step)
        self.assertIn("three Deployments `1/1`", text[verify_step:public_step])
        # ... and the phase table has to name the API-server allow before the
        # Deployments, which is the whole ordering in one line.
        self.assertLess(
            text.index("flux-controllers-kube-apiserver"),
            text.index("| 3 | the three controller Deployments"),
        )

    def test_the_runbook_removal_names_every_cluster_scoped_object(self):
        # `kubectl delete namespace flux-system` removes none of these. A
        # rollback section that omits one leaves the cluster carrying reviewed
        # RBAC and CRDs after an "undo everything".
        text = read(RUNBOOK)
        for name in (
            CLUSTER_SCOPED_CRDS + CLUSTER_SCOPED_ROLES + CLUSTER_SCOPED_BINDINGS
        ):
            with self.subTest(object=name):
                self.assertIn(name, text)

    def test_the_bootstrap_readme_no_longer_claims_an_unconditional_block(self):
        text = read(BOOTSTRAP_README)
        self.assertNotIn("Nothing in this directory authorizes a live installation", text)
        self.assertIn("scripts/install-flux-controllers.sh", text)
        # The protected path must still be described as blocked; only the
        # credential-free controllers install was carved out.
        self.assertIn("`bootstrap.sh --apply-controllers` remains blocked", text)

    def test_the_policy_pins_the_flux_system_allowlist(self):
        text = read(REGO)
        for fragment in (
            "flux_generated_network_policies",
            "valid_flux_public_https_rule",
            "valid_flux_apiserver_rule",
            'input.metadata.namespace == "flux-system"',
            "must carry no egress rule",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)


def _reviewed_render() -> str:
    """A faithful 25-object skeleton of the reviewed controller render.

    The stubbed ``kustomize`` prints this, so the installer's own content gates
    (no Flux CR, no Secret, no blanket egress, restricted Pod Security enforced,
    exactly 25 ``kind:`` lines) run against it, its inventory cross-check finds
    the exact reviewed CRD/ClusterRole/ClusterRoleBinding/Deployment names in
    it, and its document splitter has the same ``---``-separated, two-space
    indented shape ``kustomize`` emits. Only structure matters here —
    ``kustomize`` is stubbed, so no field is parsed for meaning.
    """

    docs = [
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: flux-system\n"
        "  labels:\n    pod-security.kubernetes.io/enforce: restricted\n"
    ]
    for crd in CLUSTER_SCOPED_CRDS:
        docs.append(
            "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
            "metadata:\n  name: {}\n".format(crd)
        )
    for role in CLUSTER_SCOPED_ROLES:
        docs.append(
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
            "metadata:\n  name: {}\n".format(role)
        )
    for binding in CLUSTER_SCOPED_BINDINGS:
        docs.append(
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
            "metadata:\n  name: {}\n".format(binding)
        )
    for policy in ("allow-egress", "allow-scraping", "allow-webhooks"):
        docs.append(
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n"
            "  name: {}\n  namespace: flux-system\nspec:\n  podSelector: {{}}\n".format(policy)
        )
    docs.append(
        "apiVersion: v1\nkind: ResourceQuota\nmetadata:\n"
        "  name: critical-pods-flux-system\n  namespace: flux-system\n"
    )
    for sa in CONTROLLER_DEPLOYMENTS:
        docs.append(
            "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n"
            "  name: {}\n  namespace: flux-system\n".format(sa)
        )
    docs.append(
        "apiVersion: v1\nkind: Service\nmetadata:\n"
        "  name: source-controller\n  namespace: flux-system\n"
    )
    for dep in CONTROLLER_DEPLOYMENTS:
        docs.append(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
            "  name: {}\n  namespace: flux-system\n".format(dep)
        )
    return "---\n".join(docs)


def _reviewed_egress_render() -> str:
    """A faithful 5-policy skeleton of the reviewed egress overlay render."""

    docs = []
    for policy in EXPECTED_EGRESS_POLICIES:
        document = (
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n"
            "  name: {}\n  namespace: flux-system\nspec:\n  policyTypes:\n"
            "  - Egress\n".format(policy)
        )
        if policy == "flux-controllers-kube-apiserver":
            document += (
                "  egress:\n  - to:\n    - ipBlock:\n        cidr: 192.0.2.0/32\n"
                "    ports:\n    - port: 6443\n      protocol: TCP\n"
            )
        docs.append(document)
    return "---\n".join(docs)


_KUSTOMIZE_STUB = r"""#!/usr/bin/env bash
set -u
case "${1:-}" in
  version) printf '%s\n' "${FLUX_STUB_KUSTOMIZE_VERSION}"; exit 0 ;;
  build)
    case "${2:-}" in
      */controllers) cat "${FLUX_STUB_ASSETS}/controllers.yaml"; exit 0 ;;
      */egress) cat "${FLUX_STUB_ASSETS}/egress.yaml"; exit 0 ;;
    esac
    printf 'stub kustomize: unknown root: %s\n' "${2:-}" >&2; exit 9 ;;
esac
printf 'stub kustomize: unhandled args: %s\n' "$*" >&2; exit 9
"""

# The stubbed kubectl: a small model of the cluster, not a recording. It keeps
# an object registry with per-object ownership labels, refuses any API call that
# did not carry all three explicit bindings, and refuses to create controller
# Deployments into a namespace whose egress is denied with no DNS/API-server
# allow in force. That last refusal is the executable form of the install
# ordering deadlock: an installer that applies the bundle in one shot gets a
# non-zero exit and a DEADLOCK message from it.
_KUBECTL_STUB = r"""#!/usr/bin/env bash
set -u
state="${FLUX_STUB_STATE}"
registry="${state}/registry"
scenario="${FLUX_STUB_SCENARIO:-fresh-ok}"
fail_on="${FLUX_STUB_FAIL_ON:-}"
partial="${FLUX_STUB_PARTIAL:-1}"
printf '%s\n' "$*" >>"${state}/calls.log"

if [[ "${1:-}" == '--kubeconfig' ]]; then
  if [[ "${3:-}" != '--context' || "${5:-}" != '--server' ]]; then
    printf 'stub kubectl: malformed target binding: %s\n' "$*" >&2; exit 91
  fi
  shift 6
else
  case "${1:-}" in
    version|config) ;;
    *) printf 'stub kubectl: API operation without an explicit target: %s\n' "$*" >&2; exit 90 ;;
  esac
fi

if [[ "${1:-}" == 'version' ]]; then
  printf 'clientVersion:\n  gitVersion: %s\nkustomizeVersion: %s\n' \
    "${FLUX_STUB_KUBECTL_VERSION}" "${FLUX_STUB_KUSTOMIZE_VERSION}"
  exit 0
fi

if [[ "${1:-}" == 'config' ]]; then
  wanted='' config_path='' previous=''
  for argument in "$@"; do
    if [[ "$previous" == '--context' ]]; then wanted="$argument"; fi
    if [[ "$previous" == '--kubeconfig' ]]; then config_path="$argument"; fi
    previous="$argument"
  done
  awk -v want="$wanted" '$1 == want { print $2; found = 1 } END { exit(found ? 0 : 1) }' \
    "$config_path" && exit 0
  printf 'error: context "%s" does not exist\n' "$wanted" >&2
  exit 1
fi

namespace=''
if [[ "${1:-}" == '-n' ]]; then namespace="$2"; shift 2; fi
verb="${1:-}"; shift || true

canonical() {
  case "$1" in
    namespace|namespaces) printf 'namespace' ;;
    customresourcedefinition*|crd*) printf 'customresourcedefinition.apiextensions.k8s.io' ;;
    clusterrolebinding*) printf 'clusterrolebinding.rbac.authorization.k8s.io' ;;
    clusterrole*) printf 'clusterrole.rbac.authorization.k8s.io' ;;
    networkpolicy*) printf 'networkpolicy.networking.k8s.io' ;;
    deployment*) printf 'deployment.apps' ;;
    serviceaccount*) printf 'serviceaccount' ;;
    resourcequota*) printf 'resourcequota' ;;
    service*) printf 'service' ;;
    *) printf '%s' "$1" ;;
  esac
}
registry_labels() {
  awk -v key="$1" '$1 == key { print $2; found = 1 } END { exit(found ? 0 : 1) }' "$registry"
}
registry_add() {
  registry_labels "$1" >/dev/null 2>&1 && return 0
  printf '%s %s\n' "$1" "${2:-{\"app.kubernetes.io/instance\":\"flux-system\",\"app.kubernetes.io/part-of\":\"flux\"}}" >>"$registry"
}
registry_remove() {
  awk -v key="$1" '$1 != key' "$registry" >"${registry}.next"
  mv -- "${registry}.next" "$registry"
}
# The render's documents, rendered as the "<resource>/<name> <verb>" lines the
# real kubectl prints. Derived from the manifest so a phase split that moved an
# object shows up here rather than in a hand-maintained expectation.
emit() {
  awk -v verb="$2" -v suffix="$3" '
    function resource(k) {
      if (k == "Namespace") { return "namespace" }
      if (k == "CustomResourceDefinition") { return "customresourcedefinition.apiextensions.k8s.io" }
      if (k == "ClusterRole") { return "clusterrole.rbac.authorization.k8s.io" }
      if (k == "ClusterRoleBinding") { return "clusterrolebinding.rbac.authorization.k8s.io" }
      if (k == "NetworkPolicy") { return "networkpolicy.networking.k8s.io" }
      if (k == "ResourceQuota") { return "resourcequota" }
      if (k == "ServiceAccount") { return "serviceaccount" }
      if (k == "Service") { return "service" }
      if (k == "Deployment") { return "deployment.apps" }
      return tolower(k)
    }
    function flush() {
      if (kind != "" && name != "") { printf "%s/%s %s%s\n", resource(kind), name, verb, suffix }
      kind = ""; name = ""
    }
    /^---[[:space:]]*$/ { flush(); next }
    /^kind:[[:space:]]/ { if (kind == "") { kind = $2 } ; next }
    /^  name:[[:space:]]/ { if (name == "") { name = $2 } ; next }
    END { flush() }
  ' "$1"
}
is_cluster_scoped() {
  case "$1" in
    namespace/*|customresourcedefinition.*|clusterrole.*|clusterrolebinding.*) return 0 ;;
  esac
  return 1
}

manifest='' previous=''
for argument in "$@"; do
  if [[ "$previous" == '-f' ]]; then manifest="$argument"; fi
  previous="$argument"
done
arguments="$*"

case "$verb" in
  apply)
    case "$arguments" in
      *--dry-run=client*)
        if [[ "$scenario" == 'client-invalid' ]]; then
          printf 'error: strict decoding error: unknown field "spec.bogus"\n' >&2; exit 1
        fi
        emit "$manifest" created ' (dry run)'
        exit 0 ;;
      *--dry-run=server*)
        case "$scenario" in
          existing-*)
            emit "$manifest" configured ' (server dry run)'
            exit 0 ;;
          fresh-configured)
            emit "$manifest" created ' (server dry run)' \
              | sed 's#^namespace/flux-system created#namespace/flux-system configured#' \
              | grep -E '^(namespace|customresourcedefinition|clusterrole|clusterrolebinding)'
            ;;
          *)
            emit "$manifest" created ' (server dry run)' \
              | grep -E '^(namespace|customresourcedefinition|clusterrole|clusterrolebinding)'
            ;;
        esac
        if [[ "$scenario" == 'fresh-foreign' ]]; then
          printf 'namespace/kube-system created (server dry run)\n'
        fi
        if [[ "$scenario" == 'fresh-genuine-error' ]]; then
          for index in 1 2 3 4 5 6 7 8 9 10; do
            printf 'Error from server (NotFound): error when creating "STDIN": namespaces "flux-system" not found\n'
          done
          printf 'Error from server (Forbidden): error when creating "STDIN": deployments.apps is forbidden\n'
        else
          for index in 1 2 3 4 5 6 7 8 9 10 11; do
            printf 'Error from server (NotFound): error when creating "STDIN": namespaces "flux-system" not found\n'
          done
        fi
        exit 1 ;;
    esac
    # A real apply. The ordering model first: creating controller Pods into a
    # namespace that denies egress with no DNS or API-server allow is the
    # deadlock this install exists to avoid, and the model refuses it. The
    # namespace state includes THIS manifest, because a single-shot apply
    # creates the deny-all and the Deployments in the same batch -- the exact
    # regression the phase split exists to prevent.
    denied="${state}/deny-all"; resolves="${state}/dns"; reaches="${state}/apiserver"
    grep -qE '^  name: allow-egress[[:space:]]*$' "$manifest" && : >"$denied"
    grep -qE '^  name: flux-controllers-dns[[:space:]]*$' "$manifest" && : >"$resolves"
    grep -qE '^  name: flux-controllers-kube-apiserver[[:space:]]*$' "$manifest" && : >"$reaches"
    if grep -qE '^kind: Deployment[[:space:]]*$' "$manifest"; then
      if [[ -f "$denied" ]] && { [[ ! -f "$resolves" ]] || [[ ! -f "$reaches" ]]; }; then
        printf 'stub kubectl: DEADLOCK: controller Deployments created while flux-system egress is denied with no DNS/API-server allow in force\n' >&2
        exit 80
      fi
    fi
    printf '%s\n' "$(basename -- "$manifest")" >>"${state}/applied.log"
    emitted=0
    while IFS=' ' read -r entry _; do
      [[ -n "$entry" ]] || continue
      if [[ -n "$fail_on" && "$manifest" == *"$fail_on"* && "$emitted" -ge "$partial" ]]; then
        printf 'Error from server (Forbidden): error when creating "STDIN": %s is forbidden\n' "$entry" >&2
        exit 1
      fi
      if registry_labels "$entry" >/dev/null 2>&1; then
        printf '%s configured\n' "$entry"
      else
        registry_add "$entry"
        printf '%s created\n' "$entry"
      fi
      emitted=$((emitted + 1))
    done < <(emit "$manifest" '' '')
    exit 0 ;;
  get)
    target="${1:-}"
    if [[ "$target" == */* ]]; then
      key="$target"
    elif [[ -n "${2:-}" && "${2:0:1}" != '-' ]]; then
      key="$(canonical "$target")/$2"
    else
      # A list: `get customresourcedefinition -o name`.
      awk -v prefix="$(canonical "$target")/" 'index($1, prefix) == 1 { print $1 }' "$registry"
      exit 0
    fi
    labels=''
    if ! labels="$(registry_labels "$key")"; then
      printf 'Error from server (NotFound): %s not found\n' "$key" >&2
      exit 1
    fi
    case "$arguments" in
      *jsonpath=\{.metadata.labels\}*) printf '%s' "$labels" ;;
      *jsonpath=*readyReplicas*) printf '%s' "${FLUX_STUB_READINESS:-1/1}" ;;
      *) printf '%s\n' "$key" ;;
    esac
    exit 0 ;;
  delete)
    target="${1:-}"
    if [[ "${FLUX_STUB_NO_DELETE:-}" == '1' ]]; then
      printf 'stub kubectl: delete suppressed\n' >&2
      exit 1
    fi
    if [[ "$target" == 'namespace/flux-system' ]]; then
      # Deleting the namespace takes its children with it -- and takes none of
      # the cluster-scoped objects, which is the whole point of the ledger.
      awk '!(index($1, "namespace/") == 1 || index($1, "customresourcedefinition.") == 1 || index($1, "clusterrole") == 1)' \
        "$registry" >"${registry}.doomed"
      while IFS=' ' read -r doomed _; do
        [[ -n "$doomed" ]] && registry_remove "$doomed"
      done <"${registry}.doomed"
      rm -f -- "${registry}.doomed"
    fi
    registry_remove "$target"
    printf '%s deleted\n' "$target"
    exit 0 ;;
esac
printf 'stub kubectl: unhandled args: %s\n' "$*" >&2
exit 99
"""


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


@unittest.skipUnless(BASH and GIT, "bash and git are required")
class InstallerBehaviourTestCase(unittest.TestCase):
    """A disposable repository root plus a stubbed, version-pinned toolchain.

    The fixture is a real Git repository so the installer's "reviewed bytes"
    binding runs for real, and its ``versions.env`` pins the STUB kubectl's own
    sha256 — the digest check is therefore exercised, never disabled, and a
    binary the fixture did not create fails it. Building the whole root, rather
    than pointing the real repository at a fake tool, is what keeps the
    production pins (the real ``versions.env``) load-bearing.
    """

    @classmethod
    def setUpClass(cls):
        cls.base = Path(
            tempfile.mkdtemp(prefix="flux-install-fixture.", dir=os.environ.get("TMPDIR"))
        )
        cls.assets = cls.base / "assets"
        cls.assets.mkdir()
        (cls.assets / "controllers.yaml").write_text(_reviewed_render(), encoding="utf-8")
        (cls.assets / "egress.yaml").write_text(
            _reviewed_egress_render(), encoding="utf-8"
        )

        cls.bin = cls.base / "bin"
        cls.bin.mkdir()
        _write_executable(cls.bin / "kustomize", _KUSTOMIZE_STUB)
        _write_executable(cls.bin / "kubectl", _KUBECTL_STUB)
        # A second kubectl with different bytes, identical behaviour: the
        # hostile-PATH shim Codex demonstrated. Only its digest gives it away.
        cls.hostile_bin = cls.base / "hostile-bin"
        cls.hostile_bin.mkdir()
        _write_executable(
            cls.hostile_bin / "kubectl",
            _KUBECTL_STUB + "\n# an impostor with the same behaviour\n",
        )

        cls.kubeconfig = cls.base / "kubeconfig"
        cls.kubeconfig.write_text(
            "{} {}\n{} {}\n".format(
                FIXTURE_CONTEXT,
                FIXTURE_SERVER,
                FIXTURE_OTHER_CONTEXT,
                FIXTURE_OTHER_SERVER,
            ),
            encoding="utf-8",
        )

        cls.repo = cls.base / "repo"
        cls.render_sha256 = cls._build_repository(cls.repo, cls.bin / "kubectl")

    @classmethod
    def _build_repository(cls, repo: Path, kubectl: Path) -> str:
        (repo / "scripts").mkdir(parents=True)
        (repo / "kubernetes" / "flux-system" / "controllers").mkdir(parents=True)
        (repo / "kubernetes" / "flux-system" / "egress").mkdir(parents=True)
        for target in ("controllers", "egress"):
            (repo / "kubernetes" / "flux-system" / target / "kustomization.yaml").write_text(
                "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
                encoding="utf-8",
            )
        shutil.copy2(INSTALLER, repo / "scripts" / "install-flux-controllers.sh")
        digest = hashlib.sha256(kubectl.read_bytes()).hexdigest()
        (repo / "versions.env").write_text(
            "KUSTOMIZE_VERSION={}\n"
            "KUBERNETES_VERSION={}\n"
            "KUBECTL_LINUX_AMD64_SHA256={}\n"
            "KUBECTL_ARM64_SHA256={}\n".format(
                FIXTURE_KUSTOMIZE_VERSION,
                FIXTURE_KUBECTL_VERSION,
                digest,
                hashlib.sha256(b"a different platform's kubectl").hexdigest(),
            ),
            encoding="utf-8",
        )
        environment = hermetic_git_environment(
            identity=("Flux Install Fixture", "flux-install@example.invalid")
        )
        for command in (
            ["init", "-q", "-b", "main"],
            ["add", "-A"],
            ["commit", "-q", "-m", "fixture"],
        ):
            subprocess.run(
                [required_tool(GIT, "git is required"), *command],
                cwd=str(repo),
                env=environment,
                check=True,
                capture_output=True,
            )
        return hashlib.sha256(
            (cls.assets / "controllers.yaml").read_bytes()
        ).hexdigest()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def _state(self, scenario: str) -> Path:
        state = Path(tempfile.mkdtemp(prefix="flux-stub-state.", dir=str(self.base)))
        owned = '{"app.kubernetes.io/instance":"flux-system","app.kubernetes.io/part-of":"flux"}'
        rows = []
        if scenario.startswith("existing"):
            for entry in self._reviewed_entries():
                rows.append("{} {}".format(entry, owned))
            # An existing install also carries the startup egress allows: the
            # closure this run would extend, not re-create.
            for policy in STARTUP_EGRESS_POLICIES:
                rows.append(
                    "networkpolicy.networking.k8s.io/{} {}".format(policy, owned)
                )
        if scenario == "existing-foreign-clusterrole":
            rows = [
                row
                if not row.startswith(
                    "clusterrole.rbac.authorization.k8s.io/crd-controller-flux-system "
                )
                else "clusterrole.rbac.authorization.k8s.io/crd-controller-flux-system "
                '{"app.kubernetes.io/part-of":"some-other-operator"}'
                for row in rows
            ]
        if scenario == "existing-foreign-namespace":
            rows = [
                row
                if not row.startswith("namespace/flux-system ")
                else 'namespace/flux-system {"kubernetes.io/metadata.name":"flux-system"}'
                for row in rows
            ]
        if scenario == "fresh-crd-present":
            rows.append(
                "customresourcedefinition.apiextensions.k8s.io/"
                "gitrepositories.source.toolkit.fluxcd.io " + owned
            )
        if scenario == "fresh-cr-present":
            rows.append(
                "clusterrole.rbac.authorization.k8s.io/crd-controller-flux-system " + owned
            )
        if scenario == "fresh-crb-present":
            rows.append(
                "clusterrolebinding.rbac.authorization.k8s.io/"
                "cluster-reconciler-flux-system " + owned
            )
        (state / "registry").write_text(
            "".join(row + "\n" for row in rows), encoding="utf-8"
        )
        (state / "calls.log").write_text("", encoding="utf-8")
        (state / "applied.log").write_text("", encoding="utf-8")
        if scenario.startswith("existing"):
            # An existing install already has its deny-all and its startup
            # allows in force; the ordering model has to know that.
            for marker in ("deny-all", "dns", "apiserver"):
                (state / marker).write_text("", encoding="utf-8")
        return state

    @staticmethod
    def _reviewed_entries():
        entries = ["namespace/flux-system"]
        entries += [
            "customresourcedefinition.apiextensions.k8s.io/" + name
            for name in CLUSTER_SCOPED_CRDS
        ]
        entries += [
            "clusterrole.rbac.authorization.k8s.io/" + name for name in CLUSTER_SCOPED_ROLES
        ]
        entries += [
            "clusterrolebinding.rbac.authorization.k8s.io/" + name
            for name in CLUSTER_SCOPED_BINDINGS
        ]
        entries += [
            "networkpolicy.networking.k8s.io/" + name
            for name in ("allow-egress", "allow-scraping", "allow-webhooks")
        ]
        entries.append("resourcequota/critical-pods-flux-system")
        entries += ["serviceaccount/" + name for name in CONTROLLER_DEPLOYMENTS]
        entries.append("service/source-controller")
        entries += ["deployment.apps/" + name for name in CONTROLLER_DEPLOYMENTS]
        return entries

    def _run(
        self,
        mode="--plan",
        *,
        scenario="fresh-ok",
        state=None,
        path_prefix=(),
        digest=None,
        context=FIXTURE_CONTEXT,
        server=FIXTURE_SERVER,
        kubeconfig=None,
        repo=None,
        extra_environment=None,
        omit_bindings=False,
    ):
        state = state or self._state(scenario)
        environment = dict(os.environ)
        environment["PATH"] = os.pathsep.join(
            [str(item) for item in path_prefix]
            + [str(self.bin), environment.get("PATH", "")]
        )
        environment["FLUX_STUB_SCENARIO"] = scenario
        environment["FLUX_STUB_STATE"] = str(state)
        environment["FLUX_STUB_ASSETS"] = str(self.assets)
        environment["FLUX_STUB_KUSTOMIZE_VERSION"] = FIXTURE_KUSTOMIZE_VERSION
        environment["FLUX_STUB_KUBECTL_VERSION"] = FIXTURE_KUBECTL_VERSION
        environment.update(extra_environment or {})
        repository = repo or self.repo
        argv = [
            required_tool(BASH, BASH_REQUIRED),
            str(repository / "scripts" / "install-flux-controllers.sh"),
            mode,
        ]
        if not omit_bindings:
            argv += [
                "--kubeconfig",
                str(kubeconfig or self.kubeconfig),
                "--context",
                context,
                "--server",
                server,
                "--expect-render-sha256",
                self.render_sha256 if digest is None else digest,
            ]
        completed = subprocess.run(
            argv, capture_output=True, text=True, env=environment, cwd=str(repository)
        )
        completed.state = state  # type: ignore[attr-defined]
        return completed


class FixtureFidelityTests(InstallerBehaviourTestCase):
    """Vacuity floor: the fixture must be able to pass before a refusal means anything."""

    def test_the_render_skeleton_matches_the_reviewed_shape(self):
        render = _reviewed_render()
        self.assertEqual(render.count("\nkind:") + render.startswith("kind:"), 25)
        self.assertIn("pod-security.kubernetes.io/enforce: restricted", render)
        self.assertNotIn("kind: Secret", render)
        self.assertEqual(_reviewed_egress_render().count("\nkind:"), 5)

    def test_render_mode_needs_no_cluster_and_no_binding(self):
        completed = self._run("--render", omit_bindings=True)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("RENDER only; no cluster was contacted", completed.stdout)
        self.assertIn(self.render_sha256, completed.stdout)
        self.assertEqual(
            read(Path(completed.state) / "calls.log").strip(),
            "",
            "--render must not invoke kubectl at all",
        )


class FreshClusterDryRunGateTests(InstallerBehaviourTestCase):
    """Behavioural: the pre-apply gate accepts the fresh-cluster dry-run shape.

    The defect this exists for: the install creates its own flux-system
    Namespace, and ``kubectl apply --dry-run=server`` does not persist it
    (kubernetes/kubernetes#83562), so the 11 namespaced children report
    ``namespaces "flux-system" not found`` and kubectl exits non-zero on a fresh
    cluster. The previous gate demanded all 25 objects report ``created`` and so
    could never pass the fresh install it exists to perform.
    """

    def test_fresh_cluster_shape_is_accepted(self):
        completed = self._run(scenario="fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn(
            "fresh-cluster dry run clean (14 created + 11 expected namespace-not-found)",
            completed.stdout,
        )
        self.assertIn("PLAN only; no mutation attempted", completed.stdout)

    def test_existing_cluster_shape_is_accepted(self):
        completed = self._run(scenario="existing-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("existing-cluster dry run clean (25 objects)", completed.stdout)

    def test_a_foreign_object_in_the_dry_run_fails_closed(self):
        completed = self._run(scenario="fresh-foreign")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fresh dry-run shape wrong", completed.stderr)
        self.assertNotIn("dry run clean", completed.stdout)

    def test_a_real_configured_fails_closed(self):
        completed = self._run(scenario="fresh-configured")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fresh dry-run shape wrong", completed.stderr)

    def test_a_genuine_error_on_a_child_fails_closed(self):
        completed = self._run(scenario="fresh-genuine-error")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fresh dry-run shape wrong", completed.stderr)
        self.assertNotIn("dry run clean", completed.stdout)

    def test_a_preexisting_fluxcd_crd_fails_closed(self):
        completed = self._run(scenario="fresh-crd-present")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fluxcd CRD(s) already exist", completed.stderr)

    def test_a_preexisting_clusterrole_fails_closed(self):
        completed = self._run(scenario="fresh-cr-present")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("clusterrole crd-controller-flux-system already exists", completed.stderr)

    def test_a_preexisting_clusterrolebinding_fails_closed(self):
        completed = self._run(scenario="fresh-crb-present")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "clusterrolebinding cluster-reconciler-flux-system already exists",
            completed.stderr,
        )

    def test_an_invalid_render_fails_client_validation(self):
        completed = self._run(scenario="client-invalid")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("client-side strict validation failed", completed.stderr)

    def test_apply_reaches_the_real_apply_only_after_a_clean_fresh_gate(self):
        completed = self._run("--apply", scenario="fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("applied; Flux is installed and inert", completed.stdout)


class InstallOrderingTests(InstallerBehaviourTestCase):
    """P1-A: the controllers are never created into an egress-denied namespace.

    The bundle applies ``allow-egress`` patched to a namespace-wide deny, and
    the runbook then requires all three Deployments ``1/1`` before any allow is
    applied. On a NetworkPolicy-enforcing CNI those controllers have no DNS and
    no API server at creation, so leader election and cache sync cannot
    complete and the readiness step can never pass. The stubbed cluster refuses
    exactly that sequence, so these tests fail if the ordering regresses.
    """

    def test_the_apply_is_ordered_prerequisites_then_allows_then_workloads(self):
        completed = self._run("--apply", scenario="fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        applied = read(Path(completed.state) / "applied.log").split()
        self.assertEqual(
            applied,
            [
                "phase-1-prerequisites.yaml",
                "phase-2-startup-egress.yaml",
                "phase-3-workloads.yaml",
            ],
        )

    def test_no_controller_deployment_is_applied_before_the_startup_allows(self):
        # The executable ordering regression: the modelled cluster exits 80 with
        # DEADLOCK if a Deployment is created while the namespace denies egress
        # and neither the DNS nor the API-server allow is in force. A clean run
        # must never trigger it.
        completed = self._run("--apply", scenario="fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertNotIn("DEADLOCK", completed.stderr)

    def test_the_first_phase_carries_the_deny_all_and_no_workload(self):
        completed = self._run("--apply", scenario="fresh-ok")
        calls = read(Path(completed.state) / "calls.log")
        self.assertIn("phase-1-prerequisites.yaml", calls)
        self.assertIn(
            "install-flux-controllers: phase prerequisites: applying 22 object(s)",
            completed.stdout,
        )
        self.assertIn(
            "install-flux-controllers: phase startup-egress: applying 4 object(s)",
            completed.stdout,
        )
        self.assertIn(
            "install-flux-controllers: phase workloads: applying 3 object(s)",
            completed.stdout,
        )

    def test_public_https_is_never_applied_by_the_install(self):
        completed = self._run("--apply", scenario="fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        registry = read(Path(completed.state) / "registry")
        self.assertIn("networkpolicy.networking.k8s.io/flux-controllers-dns", registry)
        self.assertNotIn(PUBLIC_EGRESS_POLICY, registry)
        self.assertIn("public HTTPS is still denied", completed.stdout)

    def test_the_deferred_public_allow_lands_only_once_the_controllers_are_ready(self):
        completed = self._run(
            "--open-public-egress", scenario="existing-ok", extra_environment={}
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("public HTTPS allowed", completed.stdout)
        self.assertIn(
            PUBLIC_EGRESS_POLICY, read(Path(completed.state) / "registry")
        )

    def test_the_deferred_public_allow_refuses_an_unhealthy_controller(self):
        completed = self._run(
            "--open-public-egress",
            scenario="existing-ok",
            extra_environment={"FLUX_STUB_READINESS": "0/1"},
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not 1/1", completed.stderr)
        self.assertIn("public egress stays shut", completed.stderr)
        self.assertNotIn(
            PUBLIC_EGRESS_POLICY, read(Path(completed.state) / "registry")
        )

    def test_the_deferred_public_allow_refuses_a_namespace_without_the_startup_allows(self):
        state = self._state("existing-ok")
        registry = state / "registry"
        registry.write_text(
            "".join(
                line + "\n"
                for line in read(registry).splitlines()
                if not any(
                    line.startswith("networkpolicy.networking.k8s.io/" + policy + " ")
                    for policy in STARTUP_EGRESS_POLICIES
                )
            ),
            encoding="utf-8",
        )
        completed = self._run(
            "--open-public-egress", scenario="existing-ok", state=state
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not in the cluster", completed.stderr)


class ToolAndTargetBindingTests(InstallerBehaviourTestCase):
    """P1-B: an unidentified tool or an unnamed cluster stops the install."""

    def test_a_hostile_kubectl_earlier_on_path_is_refused(self):
        # Codex's demonstration: a fake kubectl produced 25 accepted dry-run
        # lines, an accepted apply, and exit 0. It behaves identically here;
        # only its sha256 differs from the versions.env pin.
        completed = self._run(path_prefix=(self.hostile_bin,))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("matches no versions.env kubectl digest pin", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "calls.log").count("apply"), 0)

    def test_a_kubectl_outside_the_version_pin_is_refused(self):
        completed = self._run(
            extra_environment={"FLUX_STUB_KUBECTL_VERSION": "v1.30.0"}
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("versions.env pins v1.36.3", completed.stderr)

    def test_a_kustomize_outside_the_version_pin_is_refused(self):
        completed = self._run(
            extra_environment={"FLUX_STUB_KUSTOMIZE_VERSION": "v5.0.0"}
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("versions.env pins v5.8.1", completed.stderr)

    def test_a_context_that_resolves_to_another_server_is_refused(self):
        completed = self._run(context=FIXTURE_OTHER_CONTEXT)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("resolves to a different API server", completed.stderr)

    def test_a_server_the_kubeconfig_does_not_carry_is_refused(self):
        completed = self._run(server="https://203.0.113.99:6443")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("resolves to a different API server", completed.stderr)

    def test_an_unknown_context_is_refused(self):
        completed = self._run(context="never-reviewed")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not present in the --kubeconfig", completed.stderr)

    def test_the_ambient_target_is_never_used(self):
        completed = self._run(omit_bindings=True)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "--kubeconfig is required; the install never uses the ambient default",
            completed.stderr,
        )

    def test_every_api_call_carries_all_three_bindings(self):
        # The stub exits 90 on any API operation that arrived without them, so a
        # clean run is itself the proof; assert the shape of the log too, so a
        # future call site that skipped the wrapper is visible.
        completed = self._run("--apply", scenario="fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        calls = [
            line
            for line in read(Path(completed.state) / "calls.log").splitlines()
            if line and not line.startswith(("version", "config"))
        ]
        self.assertGreater(len(calls), 5)
        for line in calls:
            with self.subTest(call=line[:60]):
                self.assertTrue(line.startswith("--kubeconfig "))
                self.assertIn("--context " + FIXTURE_CONTEXT, line)
                self.assertIn("--server " + FIXTURE_SERVER, line)

    def test_a_drifted_render_digest_is_refused(self):
        completed = self._run(digest="0" * 64)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not the reviewed", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "calls.log").count("apply"), 0)

    def test_a_missing_render_digest_is_refused(self):
        completed = self._run(digest="")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--expect-render-sha256 is required", completed.stderr)

    def test_an_uncommitted_install_input_is_refused(self):
        dirty = self.base / "dirty-repo"
        self._build_repository(dirty, self.bin / "kubectl")
        (dirty / "kubernetes" / "flux-system" / "egress" / "kustomization.yaml").write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n# edited\n",
            encoding="utf-8",
        )
        completed = self._run(repo=dirty)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("uncommitted modifications", completed.stderr)

    def test_a_non_ipv4_server_is_refused(self):
        completed = self._run(server="https://cluster.example.invalid:6443")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must be https://<IPv4 address>:<port>", completed.stderr)

    def test_a_server_port_the_reviewed_allow_does_not_name_is_refused(self):
        completed = self._run(server="https://198.51.100.10:8443")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("the reviewed API-server egress allow names 6443", completed.stderr)


class ApplyTransactionTests(InstallerBehaviourTestCase):
    """P1-C: a partial apply is rolled back to exactly what this attempt created."""

    def test_a_failed_workload_phase_rolls_back_the_whole_attempt(self):
        completed = self._run(
            "--apply",
            scenario="fresh-ok",
            extra_environment={"FLUX_STUB_FAIL_ON": "phase-3-workloads", "FLUX_STUB_PARTIAL": "1"},
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("phase workloads apply failed", completed.stderr)
        self.assertIn("rollback complete", completed.stderr)
        # The proof that matters: nothing of this attempt survives, and that
        # includes the 13 cluster-scoped objects `delete namespace` cannot reach.
        registry = read(Path(completed.state) / "registry")
        for name in CLUSTER_SCOPED_CRDS + CLUSTER_SCOPED_ROLES + CLUSTER_SCOPED_BINDINGS:
            with self.subTest(object=name):
                self.assertNotIn(name, registry)
        self.assertNotIn("namespace/flux-system", registry)

    def test_a_partial_first_phase_rolls_back_only_the_applied_prefix(self):
        completed = self._run(
            "--apply",
            scenario="fresh-ok",
            extra_environment={
                "FLUX_STUB_FAIL_ON": "phase-1-prerequisites",
                "FLUX_STUB_PARTIAL": "5",
            },
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("a partial apply may have created objects", completed.stderr)
        self.assertIn("rollback: removing the 5 object(s)", completed.stderr)
        self.assertIn("rollback complete", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "registry").strip(), "")

    def test_an_incomplete_rollback_is_reported_rather_than_claimed(self):
        completed = self._run(
            "--apply",
            scenario="fresh-ok",
            extra_environment={
                "FLUX_STUB_FAIL_ON": "phase-3-workloads",
                "FLUX_STUB_NO_DELETE": "1",
            },
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("ROLLBACK INCOMPLETE", completed.stderr)
        self.assertIn("need manual removal", completed.stderr)
        self.assertNotIn("rollback complete", completed.stderr)

    def test_an_upgrade_over_an_owned_install_deletes_nothing_preexisting(self):
        # The reconcile-to-reviewed-bytes path: every object already exists and
        # is owned, so the apply reports `configured`, the ledger stays empty,
        # and a later failure must not delete somebody's working install.
        completed = self._run(
            "--apply",
            scenario="existing-ok",
            extra_environment={"FLUX_STUB_FAIL_ON": "phase-3-workloads"},
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("this attempt created nothing; the cluster is unchanged", completed.stderr)
        registry = read(Path(completed.state) / "registry")
        for entry in self._reviewed_entries():
            with self.subTest(object=entry):
                self.assertIn(entry, registry)

    def test_a_foreign_owned_cluster_role_stops_the_install_before_any_apply(self):
        completed = self._run("--apply", scenario="existing-foreign-clusterrole")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not owned by this install", completed.stderr)
        self.assertIn("refusing to adopt", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "applied.log").strip(), "")

    def test_a_foreign_owned_namespace_stops_the_install(self):
        completed = self._run("--apply", scenario="existing-foreign-namespace")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not owned by this install", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "applied.log").strip(), "")

    def test_the_ledger_records_only_real_creates(self):
        # Dry-run lines carry a " (dry run)" suffix and must never enter the
        # ledger; a ledger fed by the gate would try to delete objects the gate
        # only imagined.
        text = read(INSTALLER)
        self.assertIn("LEDGER_CREATED_LINE=", text)
        self.assertRegex(text, r'LEDGER_CREATED_LINE="\^\(.*\) created\\\$"')


class InstallCeremonyValidatorTests(unittest.TestCase):
    """`validate_repository.py`'s static coupling of installer, export, runbook.

    The behavioural battery above proves the installer *behaves*; this proves
    the repository *notices* when the ceremony is taken apart in a commit — a
    phase constant edited alone, a fail-closed refusal deleted, or a
    cluster-scoped object dropped from the documented removal.
    """

    @classmethod
    def setUpClass(cls):
        cls.module = load_script(
            "validate_repository.py", module_name="validate_repository_flux_install"
        )

    def _tree(self):
        # Resolved: the validator refuses to read through a symlinked path
        # component, and macOS puts TMPDIR behind one.
        base = Path(
            tempfile.mkdtemp(prefix="flux-ceremony.", dir=os.environ.get("TMPDIR"))
        ).resolve()
        self.addCleanup(shutil.rmtree, base, True)
        (base / "scripts").mkdir()
        (base / "docs" / "runbooks").mkdir(parents=True)
        (base / "kubernetes" / "flux-system" / "controllers").mkdir(parents=True)
        shutil.copy2(INSTALLER, base / "scripts" / "install-flux-controllers.sh")
        shutil.copy2(RUNBOOK, base / "docs" / "runbooks" / "flux-install.md")
        shutil.copy2(VERSIONS, base / "versions.env")
        shutil.copy2(
            CONTROLLERS / "gotk-components.yaml",
            base / "kubernetes" / "flux-system" / "controllers" / "gotk-components.yaml",
        )
        return base

    def test_the_committed_ceremony_passes(self):
        # Vacuity floor for every mutation below.
        self.assertEqual(self.module.flux_install_ceremony_errors(ROOT), [])

    def test_the_cluster_scoped_inventory_is_derived_and_not_empty(self):
        derived = self.module.cluster_scoped_flux_objects(ROOT)
        self.assertEqual(len(derived), 13, "8 CRDs + 3 ClusterRoles + 2 bindings")
        self.assertEqual(
            set(derived),
            set(CLUSTER_SCOPED_CRDS + CLUSTER_SCOPED_ROLES + CLUSTER_SCOPED_BINDINGS),
        )

    def test_a_phase_constant_edited_alone_fails(self):
        tree = self._tree()
        installer = tree / "scripts" / "install-flux-controllers.sh"
        installer.write_text(
            read(installer).replace("EXPECTED_WORKLOADS=3", "EXPECTED_WORKLOADS=2"),
            encoding="utf-8",
        )
        errors = self.module.flux_install_ceremony_errors(tree)
        self.assertTrue(
            any("do not partition the reviewed controller inventory" in e for e in errors),
            errors,
        )

    def test_an_egress_phase_constant_edited_alone_fails(self):
        tree = self._tree()
        installer = tree / "scripts" / "install-flux-controllers.sh"
        installer.write_text(
            read(installer).replace(
                "EXPECTED_STARTUP_POLICIES=4", "EXPECTED_STARTUP_POLICIES=5"
            ),
            encoding="utf-8",
        )
        errors = self.module.flux_install_ceremony_errors(tree)
        self.assertTrue(
            any("do not partition the reviewed egress overlay" in e for e in errors),
            errors,
        )

    def test_a_deleted_refusal_fails(self):
        for refusal in (
            "--server is required",
            "matches no versions.env kubectl digest pin",
            "is not owned by this install",
            "ROLLBACK INCOMPLETE",
            "the ordering that prevents the egress deadlock is broken",
        ):
            with self.subTest(refusal=refusal):
                tree = self._tree()
                installer = tree / "scripts" / "install-flux-controllers.sh"
                installer.write_text(
                    read(installer).replace(refusal, "a weaker message"),
                    encoding="utf-8",
                )
                errors = self.module.flux_install_ceremony_errors(tree)
                self.assertIn("Flux installer no longer refuses: " + refusal, errors)

    def test_a_runbook_that_drops_a_cluster_scoped_object_fails(self):
        tree = self._tree()
        runbook = tree / "docs" / "runbooks" / "flux-install.md"
        runbook.write_text(
            read(runbook).replace("flux-view-flux-system", "flux-view-removed"),
            encoding="utf-8",
        )
        errors = self.module.flux_install_ceremony_errors(tree)
        self.assertIn(
            "the Flux install runbook's removal omits the cluster-scoped object "
            "flux-view-flux-system",
            errors,
        )

    def test_a_runbook_that_calls_the_namespace_delete_sufficient_fails(self):
        tree = self._tree()
        runbook = tree / "docs" / "runbooks" / "flux-install.md"
        runbook.write_text(
            read(runbook).replace("is **not\n  sufficient**", "is sufficient"),
            encoding="utf-8",
        )
        errors = self.module.flux_install_ceremony_errors(tree)
        self.assertTrue(
            any("is **not sufficient**" in error for error in errors), errors
        )


if __name__ == "__main__":
    unittest.main()
