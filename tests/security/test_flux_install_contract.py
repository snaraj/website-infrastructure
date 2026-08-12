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
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import NamedTuple

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


class InstallerRun(NamedTuple):
    """One installer invocation together with the cluster it ran against.

    ``subprocess.CompletedProcess`` carries the process result and nothing else,
    but almost every assertion here is about what the run did to the MODELLED
    CLUSTER — which objects exist afterwards, what was applied and in what order.
    Naming that pairing in a type keeps the state directory a declared part of a
    run's result rather than an attribute bolted onto a foreign object, where a
    helper that quietly stopped returning it would type-check exactly the same.
    """

    returncode: int
    stdout: str
    stderr: str
    state: Path


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

    def test_the_api_server_allow_has_exactly_the_reviewed_shape(self):
        # The disclosed residual (runbook step 3, residual risk 4) is that a
        # NetworkPolicy selects the API server by ADDRESS, while an in-Pod client
        # reaches it through the `kubernetes` Service -- so on an enforcing CNI
        # this allow may target the wrong destination and the controllers can end
        # up API-isolated. That residual is accepted because it is disclosed and
        # fails closed. What must not happen is it silently WIDENING while the
        # disclosure stays put: a `/16` instead of a `/32`, a second port, a
        # second peer, a podSelector opened to the namespace. Existence-by-name
        # cannot see any of that, so the document body is pinned byte for byte.
        document = self.text.split("\n  name: flux-controllers-kube-apiserver\n", 1)[1]
        self.assertEqual(
            document,
            "  namespace: flux-system\n"
            "  annotations:\n"
            "    platform.snaraj.dev/readiness: sentinel-until-reviewed-control-plane-endpoint\n"
            "spec:\n"
            "  podSelector:\n"
            "    matchLabels:\n"
            "      app.kubernetes.io/part-of: flux\n"
            "  policyTypes:\n"
            "    - Egress\n"
            "  egress:\n"
            "    - to:\n"
            "        - ipBlock:\n"
            "            cidr: 192.0.2.0/32\n"
            "      ports:\n"
            "        - port: 6443\n"
            "          protocol: TCP\n",
        )

    def test_every_other_reviewed_allow_has_exactly_its_reviewed_shape(self):
        # The same pin for the rest of the closure. These are the bytes the
        # installer hashes into --expect-egress-sha256 and applies; a widening
        # here is a widening in the cluster.
        expected = {
            "default-deny": (
                "  namespace: flux-system\n"
                "spec:\n"
                "  podSelector: {}\n"
                "  policyTypes:\n"
                "    - Ingress\n"
                "    - Egress\n"
            ),
            "flux-controllers-dns": (
                "  namespace: flux-system\n"
                "spec:\n"
                "  podSelector:\n"
                "    matchLabels:\n"
                "      app.kubernetes.io/part-of: flux\n"
                "  policyTypes:\n"
                "    - Egress\n"
                "  egress:\n"
                "    - to:\n"
                "        - namespaceSelector:\n"
                "            matchLabels:\n"
                "              kubernetes.io/metadata.name: kube-system\n"
                "          podSelector:\n"
                "            matchLabels:\n"
                "              k8s-app: kube-dns\n"
                "      ports:\n"
                "        - port: 53\n"
                "          protocol: UDP\n"
                "        - port: 53\n"
                "          protocol: TCP\n"
            ),
            "flux-controllers-artifacts": (
                "  namespace: flux-system\n"
                "spec:\n"
                "  podSelector:\n"
                "    matchLabels:\n"
                "      app.kubernetes.io/part-of: flux\n"
                "  policyTypes:\n"
                "    - Egress\n"
                "  egress:\n"
                "    - to:\n"
                "        - podSelector:\n"
                "            matchLabels:\n"
                "              app.kubernetes.io/part-of: flux\n"
                "      ports:\n"
                "        - port: 80\n"
                "          protocol: TCP\n"
                "        - port: 9090\n"
                "          protocol: TCP\n"
            ),
            "flux-controllers-public-https": (
                "  namespace: flux-system\n"
                "spec:\n"
                "  podSelector:\n"
                "    matchLabels:\n"
                "      app.kubernetes.io/part-of: flux\n"
                "  policyTypes:\n"
                "    - Egress\n"
                "  egress:\n"
                "    - to:\n"
                "        - ipBlock:\n"
                "            cidr: 0.0.0.0/0\n"
                "            except:\n"
                + "".join(
                    "              - {}\n".format(value)
                    for value in EXPECTED_EXCLUDED_RANGES
                )
                + "      ports:\n"
                "        - port: 443\n"
                "          protocol: TCP\n"
            ),
        }
        for name, body in expected.items():
            with self.subTest(policy=name):
                document = self.text.split("\n  name: " + name + "\n", 1)[1]
                self.assertEqual(document.split("\n---\n", 1)[0], body.rstrip("\n"))

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
            "--expect-egress-sha256",
            "--expect-commit",
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



class FluxEgressDenyFixtureTests(unittest.TestCase):
    """The nine reopenings of the flux-system closure, each attributable alone.

    What this replaces: one nine-document fixture asserted at FILE level, plus an
    ``assertIn`` over the rego's own source text. Neither could tell a working
    deny arm from a neutered one. Changing ``count(...) > 0`` to ``> 999`` in the
    rule that forbids an egress rule on the generated policies -- leaving the
    message string byte-identical, so the source-text pin still matched -- left
    the whole suite green while Conftest accepted ``allow-egress`` with
    ``egress: [{}]`` again: the cluster-wide allow-all posture recorded as AUDIT
    NP5, which is the thing this branch exists to close.

    One document per file makes each reopening attributable to a file; the
    ``expect-deny`` declaration makes it attributable to a REASON. Both are
    needed: documents 3 and 4 are denied by the same message and differ only in
    which widening they carry, so a message alone would not separate them.
    """

    DENY = ROOT / "tests" / "kubernetes" / "fixtures" / "deny"
    RUNNER = ROOT / "scripts" / "test-policy-fixtures.sh"
    # Named, not globbed: a fixture deleted outright must be a failure, and a
    # glob would simply stop looking at it.
    FIXTURES = (
        "flux-egress-01-default-deny-permits-everything",
        "flux-egress-02-generated-blanket-allow-restored",
        "flux-egress-03-public-allow-widened-to-cleartext",
        "flux-egress-04-public-allow-drops-a-private-range",
        "flux-egress-05-apiserver-sentinel-replaced-by-an-address",
        "flux-egress-06-apiserver-sentinel-annotation-stripped",
        "flux-egress-07-artifact-fetch-widened-to-everywhere",
        "flux-egress-08-dns-granted-to-every-pod",
        "flux-egress-09-invented-node-ssh-allow",
    )

    def _fixture(self, name):
        return self.DENY / (name + ".yaml")

    def _declared(self, name):
        return re.findall(
            r"(?m)^#\s*expect-deny:\s*(.+?)\s*$", read(self._fixture(name))
        )

    def test_each_reopening_is_one_document_in_one_file(self):
        for name in self.FIXTURES:
            with self.subTest(fixture=name):
                text = read(self._fixture(name))
                self.assertRegex(text, r"(?m)^kind: NetworkPolicy\s*$")
                self.assertNotRegex(
                    text,
                    r"(?m)^---\s*$",
                    "a second document here would make the file-level rejection "
                    "ambiguous again",
                )
                self.assertEqual(len(self._declared(name)), 1)

    def test_the_generated_blanket_allow_is_one_of_them(self):
        # The specific arm the mutation neutered, named so that deleting this
        # fixture is a failure rather than a smaller expectation.
        text = read(self._fixture("flux-egress-02-generated-blanket-allow-restored"))
        self.assertRegex(text, r"(?m)^\s+name:\s+allow-egress\s*$")
        self.assertRegex(text, r"(?m)^\s+egress:\s*\n\s+-\s+\{\}\s*$")
        self.assertEqual(
            self._declared("flux-egress-02-generated-blanket-allow-restored"),
            [
                "NetworkPolicy flux-system/allow-egress must carry no egress rule; "
                "the generated blanket allow is removed by patch"
            ],
        )

    @unittest.skipUnless(shutil.which("conftest"), "conftest is required")
    def test_conftest_denies_each_reopening_for_its_declared_reason(self):
        # The behavioural per-document assertion. This is what goes red when a
        # deny arm stops firing, whatever else still rejects the same bytes.
        for name in self.FIXTURES:
            with self.subTest(fixture=name):
                completed = subprocess.run(
                    [
                        required_tool(shutil.which("conftest"), "conftest is required"),
                        "test",
                        "--no-color",
                        "--policy",
                        str(ROOT / "policies" / "conftest"),
                        str(self._fixture(name)),
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                )
                self.assertNotEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                self.assertIn(
                    self._declared(name)[0], completed.stdout + completed.stderr
                )

    @unittest.skipUnless(BASH, BASH_REQUIRED)
    def test_the_runner_fails_when_a_fixture_is_rejected_for_another_reason(self):
        # A driver for the RUNNER itself, with conftest stubbed, so the mechanism
        # is proven on every host rather than only where conftest is installed.
        # A runner whose per-reason assertion silently did nothing would pass a
        # neutered policy exactly like the file-level assertion did.
        # The stub answers allow fixtures the way a passing policy would, so the
        # only behaviour under test is the deny loop's per-reason assertion.
        allow_arm = "case \"$*\" in *fixtures/allow/*) exit 0 ;; esac\n"
        for stub, expected in (
            (
                "printf 'FAIL - fixture - main - some other rule fired\\n'; exit 1",
                "not for the declared reason",
            ),
            ("exit 0", "deny fixture unexpectedly passed"),
        ):
            with self.subTest(stub=expected):
                base = Path(
                    tempfile.mkdtemp(
                        prefix="policy-runner.", dir=os.environ.get("TMPDIR")
                    )
                ).resolve()
                self.addCleanup(shutil.rmtree, base, True)
                (base / "bin").mkdir()
                _write_executable(
                    base / "bin" / "conftest",
                    "#!/usr/bin/env bash\n" + allow_arm + stub + "\n",
                )
                (base / "scripts").mkdir()
                shutil.copy2(self.RUNNER, base / "scripts" / "test-policy-fixtures.sh")
                for kind in ("allow", "deny"):
                    (base / "tests" / "kubernetes" / "fixtures" / kind).mkdir(parents=True)
                (
                    base / "tests" / "kubernetes" / "fixtures" / "allow" / "one.yaml"
                ).write_text("kind: ConfigMap\n", encoding="utf-8")
                shutil.copy2(
                    self._fixture(self.FIXTURES[1]),
                    base / "tests" / "kubernetes" / "fixtures" / "deny" / "one.yaml",
                )
                (base / "policies" / "conftest").mkdir(parents=True)
                environment = dict(os.environ)
                environment["PATH"] = os.pathsep.join(
                    [str(base / "bin"), environment.get("PATH", "")]
                )
                completed = subprocess.run(
                    [
                        required_tool(BASH, BASH_REQUIRED),
                        str(base / "scripts" / "test-policy-fixtures.sh"),
                    ],
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn(expected, completed.stderr)


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


def _render_with_an_unrecognized_deployment() -> str:
    """The reviewed render with one document the splitter cannot see is a Deployment.

    The Service document is replaced by a fourth Deployment whose ``kind`` is
    quoted. Every count the installer takes still adds up — 25 objects, the three
    reviewed Deployment names still derive exactly, 22 + 3 still partitions — and
    the document splitter, which matches ``^kind: Deployment$``, leaves this one
    in phase 1. That is the whole hazard: a workload created into the namespace
    BEFORE its egress allows exist, which on an enforcing CNI is the deadlock
    this install ordering exists to remove.

    It is also what makes the phase-1 refusal a real guard rather than a
    decoration. A guard that asks the splitter's own question can only agree with
    it and can never fire, which is why deleting it used to leave every gate
    green; the guard's pattern is deliberately broader than the splitter's, and
    this render is the input that tells them apart.
    """

    documents = _reviewed_render().split("\n---\n")
    replaced = 0
    for index, document in enumerate(documents):
        if document.startswith("apiVersion: v1\nkind: Service\n"):
            documents[index] = (
                'apiVersion: apps/v1\nkind: "Deployment"\nmetadata:\n'
                "  name: source-controller-shim\n  namespace: flux-system\n"
            )
            replaced += 1
    if replaced != 1:  # pragma: no cover - the skeleton has exactly one Service
        raise AssertionError("expected exactly one Service document to replace")
    return "\n---\n".join(documents)


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
  rm -f -- "${state}/objects/$(printf '%s' "$1" | tr '/.' '__')"
}
# The model stores each object's BYTES, not merely its name. Existence by name
# cannot tell a reviewed API-server /32 from one widened to a subnet, so an
# --open-public-egress that only asked "is there a policy called X" was checking
# the label on the box. With the bytes recorded, a server dry run can answer
# `unchanged` or `configured` the way a real API server does, and a drifted live
# policy becomes visible.
objects="${state}/objects"
mkdir -p "$objects"
object_file() {
  printf '%s/%s' "$objects" "$(printf '%s' "$1" | tr '/.' '__')"
}
# One document of a manifest, selected by the entry it declares.
document_for() {
  awk -v want="$2" '
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
      if (kind != "" && name != "" && resource(kind) "/" name == want) { printf "%s", buffer }
      kind = ""; name = ""; buffer = ""
    }
    /^---[[:space:]]*$/ { flush(); next }
    { buffer = buffer $0 "\n" }
    /^kind:[[:space:]]/ { if (kind == "") { kind = $2; gsub(/["'"'"']/, "", kind) } ; next }
    /^  name:[[:space:]]/ { if (name == "") { name = $2 } ; next }
    END { flush() }
  ' "$1"
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
    # A deterministic window for the signal tests: hold this one apply open long
    # enough that an interrupt lands INSIDE it rather than between phases, which
    # is where the output-redirection hazard lives.
    if [[ -n "${FLUX_STUB_DELAY_ON:-}" && "$manifest" == *"${FLUX_STUB_DELAY_ON}"* ]]; then
      sleep "${FLUX_STUB_DELAY:-3}"
    fi
    case "$arguments" in
      *--dry-run=client*)
        if [[ "$scenario" == 'client-invalid' ]]; then
          printf 'error: strict decoding error: unknown field "spec.bogus"\n' >&2; exit 1
        fi
        emit "$manifest" created ' (dry run)'
        exit 0 ;;
      *--dry-run=server*)
        # Whether the dry run behaves as a fresh or an existing cluster is
        # decided by the modelled cluster's own state, not by the scenario name:
        # a run that has already applied phase 1 IS an existing cluster, and
        # --open-public-egress asks this question after exactly that.
        if registry_labels namespace/flux-system >/dev/null 2>&1 \
           && [[ "$scenario" != fresh-* ]]; then
          while IFS=' ' read -r entry _; do
            [[ -n "$entry" ]] || continue
            if ! registry_labels "$entry" >/dev/null 2>&1; then
              printf '%s created (server dry run)\n' "$entry"
            elif [[ -f "$(object_file "$entry")" ]] \
                 && [[ "$(document_for "$manifest" "$entry")" == "$(cat -- "$(object_file "$entry")")" ]]; then
              printf '%s unchanged (server dry run)\n' "$entry"
            else
              printf '%s configured (server dry run)\n' "$entry"
            fi
          done < <(emit "$manifest" '' '')
          exit 0
        fi
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
        document_for "$manifest" "$entry" >"$(object_file "$entry")"
        printf '%s configured\n' "$entry"
      else
        registry_add "$entry"
        document_for "$manifest" "$entry" >"$(object_file "$entry")"
        # FLUX_STUB_CREATE_SUFFIX models the object reaching the API server while
        # its confirmation line does not reach the operator -- a dropped
        # connection, or a signal between the create and the print. The object
        # exists; stdout never says so.
        printf '%s created%s\n' "$entry" "${FLUX_STUB_CREATE_SUFFIX:-}"
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
        cls.egress_sha256 = hashlib.sha256(
            (cls.assets / "egress.yaml").read_bytes()
        ).hexdigest()
        # A second asset set whose Deployment kinds the document splitter cannot
        # recognize. See UnrecognizedDeploymentTests: it is the input that makes
        # the phase-1 ordering refusal reachable, and therefore the input that
        # makes deleting that refusal a failure.
        cls.unrecognized_assets = cls.base / "assets-unrecognized-deployment"
        cls.unrecognized_assets.mkdir()
        (cls.unrecognized_assets / "controllers.yaml").write_text(
            _render_with_an_unrecognized_deployment(), encoding="utf-8"
        )
        (cls.unrecognized_assets / "egress.yaml").write_text(
            _reviewed_egress_render(), encoding="utf-8"
        )
        cls.unrecognized_sha256 = hashlib.sha256(
            (cls.unrecognized_assets / "controllers.yaml").read_bytes()
        ).hexdigest()

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
        cls.render_sha256, cls.commit = cls._build_repository(cls.repo, cls.bin / "kubectl")

    @classmethod
    def _build_repository(cls, repo: Path, kubectl: Path):
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
        head = subprocess.run(
            [required_tool(GIT, "git is required"), "rev-parse", "HEAD"],
            cwd=str(repo),
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return (
            hashlib.sha256((cls.assets / "controllers.yaml").read_bytes()).hexdigest(),
            head,
        )

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

    def _argv_and_environment(
        self,
        mode,
        *,
        scenario,
        state,
        path_prefix=(),
        digest=None,
        egress_digest=None,
        commit=None,
        context=FIXTURE_CONTEXT,
        server=FIXTURE_SERVER,
        kubeconfig=None,
        repo=None,
        assets=None,
        extra_environment=None,
        omit_bindings=False,
        omit=(),
    ):
        environment = dict(os.environ)
        environment["PATH"] = os.pathsep.join(
            [str(item) for item in path_prefix]
            + [str(self.bin), environment.get("PATH", "")]
        )
        environment["FLUX_STUB_SCENARIO"] = scenario
        environment["FLUX_STUB_STATE"] = str(state)
        environment["FLUX_STUB_ASSETS"] = str(assets or self.assets)
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
            bindings = (
                ("--kubeconfig", str(kubeconfig or self.kubeconfig)),
                ("--context", context),
                ("--server", server),
                (
                    "--expect-render-sha256",
                    self.render_sha256 if digest is None else digest,
                ),
                (
                    "--expect-egress-sha256",
                    self.egress_sha256 if egress_digest is None else egress_digest,
                ),
                ("--expect-commit", self.commit if commit is None else commit),
            )
            for flag, value in bindings:
                if flag in omit:
                    continue
                argv += [flag, value]
        return argv, environment, repository

    def _run(
        self, mode="--plan", *, scenario="fresh-ok", state=None, **kwargs
    ) -> InstallerRun:
        state = state or self._state(scenario)
        argv, environment, repository = self._argv_and_environment(
            mode, scenario=scenario, state=state, **kwargs
        )
        completed = subprocess.run(
            argv, capture_output=True, text=True, env=environment, cwd=str(repository)
        )
        return InstallerRun(
            completed.returncode, completed.stdout, completed.stderr, state
        )

    def _run_until_signalled(
        self, mode, *, scenario, wait_for, extra_environment, wait_file="applied.log",
        state=None,
    ):
        """Start the installer, then signal it once ``wait_for`` appears in a log.

        Returns ``(returncode, stderr, state)``. The wait is on the modelled
        cluster's own record of what it has been asked to do, not on a sleep, so
        the signal lands at a known point rather than a hoped-for one -- and the
        stub holds that one call open (``FLUX_STUB_DELAY_ON``) so the signal
        arrives *inside* it, which is where the output-redirection hazard lives.
        """

        state = state or self._state(scenario)
        argv, environment, repository = self._argv_and_environment(
            mode, scenario=scenario, state=state, extra_environment=extra_environment
        )
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            cwd=str(repository),
        )
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if wait_for in read(state / wait_file):
                    break
                if process.poll() is not None:
                    self.fail(
                        "the installer exited before reaching {}: {}".format(
                            wait_for, process.communicate()[1]
                        )
                    )
                time.sleep(0.05)
            else:  # pragma: no cover - only on a pathologically slow host
                self.fail("the installer never reached " + str(wait_for))
            process.send_signal(signal.SIGTERM)
            _, errors = process.communicate(timeout=120)
        finally:
            if process.poll() is None:  # pragma: no cover - defensive
                process.kill()
                process.communicate()
        return process.returncode, errors, state


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

    def test_apply_refuses_an_existing_install_and_touches_nothing(self):
        # The peer's P1: on the existing path the 22 phase-1 objects are rewritten
        # as `configured` with no prestate recorded, so a later failure rolls back
        # nothing and reports "the cluster is unchanged" over a namespace whose
        # RBAC, CRDs and policies were just rewritten. The scope of an honest
        # create-and-delete transaction is a fresh cluster, so --apply refuses.
        completed = self._run("--apply", scenario="existing-ok")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "--apply installs only onto a fresh cluster", completed.stderr
        )
        self.assertEqual(read(Path(completed.state) / "applied.log").strip(), "")
        # ... and the read-only classification of that same cluster still works,
        # which is how the operator inspects it.
        self.assertEqual(
            self._run("--plan", scenario="existing-ok").returncode,
            0,
        )

    def test_the_existing_path_probes_ownership_of_every_namespaced_object(self):
        # The probe used to stop at the 14 cluster-scoped objects while the
        # script claimed foreign ownership "stops the install before anything is
        # applied" of all 25. A foreign NetworkPolicy inside flux-system passed
        # the dry run and would have been overwritten.
        state = self._state("existing-ok")
        registry = state / "registry"
        registry.write_text(
            "".join(
                (
                    'networkpolicy.networking.k8s.io/allow-egress '
                    '{"app.kubernetes.io/part-of":"some-other-operator"}\n'
                    if line.startswith("networkpolicy.networking.k8s.io/allow-egress ")
                    else line + "\n"
                )
                for line in read(registry).splitlines()
            ),
            encoding="utf-8",
        )
        completed = self._run("--plan", scenario="existing-ok", state=state)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "networkpolicy allow-egress already exists and is not owned by this install",
            completed.stderr,
        )


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

    def test_a_deployment_the_splitter_cannot_recognize_stops_the_install(self):
        # The refusal that had no driver. Its input is a render whose counts all
        # add up while one document the splitter does not recognize as a
        # Deployment sits in phase 1 -- a controller Pod created before its
        # egress allows exist, which is the deadlock in the form the arithmetic
        # cannot see. The refusal must fire before any cluster contact.
        completed = self._run(
            "--plan",
            scenario="fresh-ok",
            assets=self.unrecognized_assets,
            digest=self.unrecognized_sha256,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "the ordering that prevents the egress deadlock is broken",
            completed.stderr,
        )
        self.assertEqual(read(Path(completed.state) / "calls.log").count("apply"), 0)

    def test_public_https_is_never_applied_by_the_install(self):
        completed = self._run("--apply", scenario="fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        registry = read(Path(completed.state) / "registry")
        self.assertIn("networkpolicy.networking.k8s.io/flux-controllers-dns", registry)
        self.assertNotIn(PUBLIC_EGRESS_POLICY, registry)
        self.assertIn("public HTTPS is still denied", completed.stdout)

    def _installed(self):
        """A modelled cluster carrying the real result of a real --apply.

        The deferred step's preconditions are about LIVE state, so they are now
        driven against state this suite actually installed rather than against a
        hand-seeded registry: the modelled objects carry the bytes the installer
        applied, which is what lets the shape check mean anything.
        """

        completed = self._run("--apply", scenario="fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        return Path(completed.state)

    def test_the_deferred_public_allow_lands_only_once_the_controllers_are_ready(self):
        state = self._installed()
        completed = self._run(
            "--open-public-egress", scenario="existing-ok", state=state
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("public HTTPS allowed", completed.stdout)
        self.assertIn(PUBLIC_EGRESS_POLICY, read(state / "registry"))

    def test_the_deferred_public_allow_refuses_an_unhealthy_controller(self):
        state = self._installed()
        completed = self._run(
            "--open-public-egress",
            scenario="existing-ok",
            state=state,
            extra_environment={"FLUX_STUB_READINESS": "0/1"},
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not 1/1", completed.stderr)
        self.assertIn("public egress stays shut", completed.stderr)
        self.assertNotIn(PUBLIC_EGRESS_POLICY, read(state / "registry"))

    def test_the_deferred_public_allow_refuses_while_anything_is_reconciling(self):
        # "healthy AND IDLE" was a claim in the message with nothing measuring
        # the second word. Public HTTPS is the one flow that reaches off-cluster,
        # so opening it while a Flux custom resource exists opens it to whatever
        # that object already reconciles.
        state = self._installed()
        with (state / "registry").open("a", encoding="utf-8") as registry:
            registry.write(
                "gitrepositories.source.toolkit.fluxcd.io/flux-system "
                '{"app.kubernetes.io/part-of":"flux"}\n'
            )
        completed = self._run(
            "--open-public-egress", scenario="existing-ok", state=state
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "the controllers are reconciling, not idle, and public egress stays shut",
            completed.stderr,
        )
        self.assertNotIn(PUBLIC_EGRESS_POLICY, read(state / "registry"))

    def test_the_deferred_public_allow_refuses_a_live_closure_that_drifted(self):
        # Existence by name cannot tell the reviewed API-server /32 from one
        # widened to a subnet. Here the install was bound to one API server and
        # the deferred step to another, so the live API-server allow is no longer
        # the render this run would extend: the server dry run says `configured`
        # instead of `unchanged`, and the step refuses.
        state = self._installed()
        completed = self._run(
            "--open-public-egress",
            scenario="existing-ok",
            state=state,
            context=FIXTURE_OTHER_CONTEXT,
            server=FIXTURE_OTHER_SERVER,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "the live startup egress policies are not the reviewed shape",
            completed.stderr,
        )
        self.assertNotIn(PUBLIC_EGRESS_POLICY, read(state / "registry"))

    def test_the_deferred_public_allow_refuses_a_namespace_without_the_startup_allows(self):
        state = self._installed()
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

    def test_each_binding_is_required_on_its_own(self):
        # Omitting all of them only ever proved the FIRST refusal. Each is a
        # separate way to run against something nobody named or nobody reviewed,
        # so each is dropped alone and its own message demanded.
        for flag, fragment in (
            ("--context", "--context is required"),
            ("--server", "--server is required"),
            ("--expect-render-sha256", "--expect-render-sha256 is required"),
            ("--expect-egress-sha256", "--expect-egress-sha256 is required"),
            ("--expect-commit", "--expect-commit is required"),
        ):
            with self.subTest(binding=flag):
                completed = self._run(omit=(flag,))
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(fragment, completed.stderr)
                self.assertEqual(
                    read(Path(completed.state) / "calls.log").count("apply"), 0
                )

    def test_a_drifted_egress_digest_is_refused(self):
        # The peer's P1: --expect-render-sha256 bound the CONTROLLER render only,
        # so a commit could widen an egress allow while reproducing the reviewed
        # controller digest byte for byte. The egress bundle is the security half
        # of what this applies, and --open-public-egress applies nothing else.
        completed = self._run(egress_digest="0" * 64)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "the egress bytes this would apply are not the reviewed ones",
            completed.stderr,
        )
        self.assertEqual(read(Path(completed.state) / "calls.log").count("apply"), 0)

    def test_a_widened_egress_allow_is_refused_although_the_controller_render_is_intact(self):
        # The exact probe the peer ran: change only the egress root, keep the
        # reviewed controller digest. Before this round it exited 0.
        widened = self.base / "assets-widened-egress"
        widened.mkdir(exist_ok=True)
        shutil.copy2(self.assets / "controllers.yaml", widened / "controllers.yaml")
        (widened / "egress.yaml").write_text(
            _reviewed_egress_render().replace("port: 6443", "port: 6443\n    - port: 22"),
            encoding="utf-8",
        )
        completed = self._run(assets=widened)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "the egress bytes this would apply are not the reviewed ones",
            completed.stderr,
        )

    def test_a_commit_other_than_the_reviewed_one_is_refused(self):
        # A render digest binds the bytes rendered, never the program that
        # rendered them. Only the commit binds this script and its guards.
        completed = self._run(commit="0" * 40)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not the reviewed", completed.stderr)
        self.assertIn(
            "the installer and its guards are not the reviewed ones", completed.stderr
        )
        self.assertEqual(read(Path(completed.state) / "calls.log").count("apply"), 0)

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
        _, dirty_commit = self._build_repository(dirty, self.bin / "kubectl")
        (dirty / "kubernetes" / "flux-system" / "egress" / "kustomization.yaml").write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n# edited\n",
            encoding="utf-8",
        )
        # Bound to the dirty tree's OWN commit, so the refusal under test is the
        # working-tree one and not the commit binding standing in front of it.
        completed = self._run(repo=dirty, commit=dirty_commit)
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

    def test_an_owned_install_is_never_reapplied_over(self):
        # This replaces a test that asserted the OLD behaviour verbatim: an
        # upgrade over an owned install rewrote 22 objects as `configured`, kept
        # an empty ledger, and printed "this attempt created nothing; the cluster
        # is unchanged". The names still existed, which is all the old assertion
        # checked, so the misleading all-clear was pinned rather than caught.
        # There is now no path on which that message can follow a mutation.
        completed = self._run(
            "--apply",
            scenario="existing-ok",
            extra_environment={"FLUX_STUB_FAIL_ON": "phase-3-workloads"},
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--apply installs only onto a fresh cluster", completed.stderr)
        self.assertNotIn("the cluster is unchanged", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "applied.log").strip(), "")
        registry = read(Path(completed.state) / "registry")
        for entry in self._reviewed_entries():
            with self.subTest(object=entry):
                self.assertIn(entry, registry)

    def test_a_create_kubectl_never_reported_still_enters_the_ledger(self):
        # stdout is not the record of what exists. An object can reach the API
        # server while its confirmation line does not reach the operator -- a
        # dropped connection, or a signal delivered between the create and the
        # print -- and a ledger fed only by stdout would then roll back nothing
        # while 22 objects, 14 of them cluster-scoped, stayed behind. The ledger
        # is re-derived from the cluster, so the rollback is still complete.
        completed = self._run(
            "--apply",
            scenario="fresh-ok",
            extra_environment={
                "FLUX_STUB_CREATE_SUFFIX": " (dry run)",
                "FLUX_STUB_FAIL_ON": "phase-3-workloads",
            },
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("this attempt created nothing", completed.stderr)
        self.assertIn("rollback complete", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "registry").strip(), "")

    def test_a_ledger_that_recorded_nothing_reports_a_cluster_that_changed_nothing(self):
        # The other direction, and the only path on which "created nothing" is
        # true: the first phase fails before its first object is created. It is
        # also the proof that the 25 client-dry-run lines printed moments earlier
        # never entered the ledger -- had they, this would try to delete them.
        completed = self._run(
            "--apply",
            scenario="fresh-ok",
            extra_environment={
                "FLUX_STUB_FAIL_ON": "phase-1-prerequisites",
                "FLUX_STUB_PARTIAL": "0",
            },
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("this attempt created nothing; the cluster is unchanged", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "registry").strip(), "")

    def test_a_signal_mid_transaction_never_leaves_silent_residue(self):
        # The gap a failed-phase rollback does not cover: a Ctrl-C, a hangup or a
        # `kill` during the apply leaves everything the earlier phases created,
        # including all 14 cluster-scoped objects that no `delete namespace` can
        # remove, with no undo and no list. The signal must take the same
        # rollback path a failed phase takes.
        returncode, errors, state = self._run_until_signalled(
            "--apply",
            scenario="fresh-ok",
            wait_for="phase-1-prerequisites.yaml",
            extra_environment={
                "FLUX_STUB_DELAY_ON": "phase-2-startup-egress",
                "FLUX_STUB_DELAY": "3",
            },
        )
        self.assertNotEqual(returncode, 0)
        self.assertIn("interrupted by SIGTERM", errors)
        registry = read(state / "registry")
        surviving = [line.split(" ", 1)[0] for line in registry.splitlines() if line]
        # Exactly one of the two acceptable outcomes, never silence.
        self.assertTrue(
            ("rollback complete" in errors) ^ ("ROLLBACK INCOMPLETE" in errors),
            "an interrupt must report either a completed rollback or the "
            "residue it could not remove:\n" + errors,
        )
        if "rollback complete" in errors:
            self.assertEqual(surviving, [], "a completed rollback leaves nothing")
        else:  # pragma: no cover - the stub always deletes cleanly
            for entry in surviving:
                with self.subTest(residue=entry):
                    self.assertIn(entry, errors)

    def test_a_signal_before_any_apply_exits_clean_and_says_so(self):
        # The other half of the handler's contract: interrupted during the
        # read-only gate there is nothing to undo, and a rollback attempt then
        # would itself be the bug. The transaction flag, not the ledger file, is
        # what separates the two cases.
        returncode, errors, state = self._run_until_signalled(
            "--apply",
            scenario="fresh-ok",
            wait_for="--dry-run=client",
            wait_file="calls.log",
            extra_environment={
                "FLUX_STUB_DELAY_ON": "controllers.yaml",
                "FLUX_STUB_DELAY": "4",
            },
        )
        self.assertNotEqual(returncode, 0)
        self.assertIn("interrupted by SIGTERM", errors)
        self.assertIn(
            "the interrupt arrived before anything was applied; the cluster is unchanged",
            errors,
        )
        self.assertNotIn("ROLLBACK INCOMPLETE", errors)
        self.assertEqual(read(state / "registry").strip(), "")
        self.assertEqual(read(state / "applied.log").strip(), "")

    def test_a_foreign_owned_cluster_role_stops_the_install_before_any_apply(self):
        # --plan, because --apply now refuses an existing install outright and
        # the refusal under test is the ownership one behind it.
        completed = self._run("--plan", scenario="existing-foreign-clusterrole")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not owned by this install", completed.stderr)
        self.assertIn("refusing to adopt", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "applied.log").strip(), "")

    def test_a_foreign_owned_namespace_stops_the_install(self):
        completed = self._run("--plan", scenario="existing-foreign-namespace")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not owned by this install", completed.stderr)
        self.assertEqual(read(Path(completed.state) / "applied.log").strip(), "")

    def test_the_interrupt_handler_disarms_before_it_rolls_back(self):
        # DECLARED TEXT PIN, not a behavioural driver, and the only one left in
        # this module. Re-entrancy is a race: a second signal arriving while the
        # first rollback runs must not restart it, and there is no way to make a
        # test deliver a second signal at a deterministic point inside the first
        # handler. The two behavioural signal tests above cover what the handler
        # DOES; this covers the order of the two statements that make it safe to
        # run twice.
        handler = read(INSTALLER).split("on_signal() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(
            handler.index("INTERRUPT_HANDLED='yes'"), handler.index("rollback")
        )
        self.assertLess(handler.index("trap - INT TERM HUP"), handler.index("rollback"))


class RefusalCoverageTests(unittest.TestCase):
    """No fail-closed refusal is pinned by its own message string alone.

    The defect this closes, proven on this branch: replacing a refusal's
    CONDITION with one that never matches, while leaving its message byte for
    byte where the validator greps for it, kept every gate green. The message
    survived; the guard did not. So the validator's list is not allowed to grow
    a text-only entry: each refusal must name the behavioural test that feeds the
    installer the input the refusal exists for, and that test must exist.
    """

    # refusal -> the test that drives it. Adding a refusal without a driver, or
    # renaming a driver, fails here.
    DRIVERS = {
        "--kubeconfig is required": "test_the_ambient_target_is_never_used",
        "--context is required": "test_each_binding_is_required_on_its_own",
        "--server is required": "test_each_binding_is_required_on_its_own",
        "--expect-render-sha256 is required": "test_each_binding_is_required_on_its_own",
        "--expect-egress-sha256 is required": "test_each_binding_is_required_on_its_own",
        "--expect-commit is required": "test_each_binding_is_required_on_its_own",
        "the installer and its guards are not the reviewed ones":
            "test_a_commit_other_than_the_reviewed_one_is_refused",
        "the egress bytes this would apply are not the reviewed ones":
            "test_a_widened_egress_allow_is_refused_although_the_controller_render_is_intact",
        "matches no versions.env kubectl digest pin":
            "test_a_hostile_kubectl_earlier_on_path_is_refused",
        "the install inputs carry uncommitted modifications":
            "test_an_uncommitted_install_input_is_refused",
        "is not owned by this install":
            "test_the_existing_path_probes_ownership_of_every_namespaced_object",
        "ROLLBACK INCOMPLETE":
            "test_an_incomplete_rollback_is_reported_rather_than_claimed",
        "the ordering that prevents the egress deadlock is broken":
            "test_a_deployment_the_splitter_cannot_recognize_stops_the_install",
        "--apply installs only onto a fresh cluster":
            "test_apply_refuses_an_existing_install_and_touches_nothing",
        "the controllers are reconciling, not idle":
            "test_the_deferred_public_allow_refuses_while_anything_is_reconciling",
        "the live startup egress policies are not the reviewed shape":
            "test_the_deferred_public_allow_refuses_a_live_closure_that_drifted",
    }

    @classmethod
    def setUpClass(cls):
        cls.module = load_script(
            "validate_repository.py", module_name="validate_repository_flux_refusals"
        )

    def test_every_validated_refusal_names_a_behavioural_driver(self):
        self.assertEqual(
            set(self.module.FLUX_INSTALLER_REFUSALS),
            set(self.DRIVERS),
            "a refusal in the validator with no entry here is pinned by its "
            "message string alone, which is not a pin",
        )

    def test_every_named_driver_exists_in_this_module(self):
        defined = {
            name
            for value in globals().values()
            if isinstance(value, type) and issubclass(value, unittest.TestCase)
            for name in vars(value)
            if name.startswith("test_")
        }
        for refusal, driver in sorted(self.DRIVERS.items()):
            with self.subTest(refusal=refusal):
                self.assertIn(driver, defined)

    def test_every_refusal_is_still_in_the_installer(self):
        # The floor the whole coupling stands on: the messages named above are
        # the ones the installer actually prints.
        text = read(INSTALLER)
        for refusal in sorted(self.DRIVERS):
            with self.subTest(refusal=refusal):
                self.assertIn(refusal, text)


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
            "--expect-egress-sha256 is required",
            "--expect-commit is required",
            "matches no versions.env kubectl digest pin",
            "is not owned by this install",
            "ROLLBACK INCOMPLETE",
            "the ordering that prevents the egress deadlock is broken",
            "--apply installs only onto a fresh cluster",
            "the controllers are reconciling, not idle",
            "the live startup egress policies are not the reviewed shape",
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
