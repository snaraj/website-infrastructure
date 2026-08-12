"""Offline contracts for the reproducible, inert Flux controller install.

Nothing here contacts a real cluster. These tests pin the properties that make
the install reviewable and the namespace fail-closed: the generated blanket
egress allow is removed, the egress allowlist is exactly the reviewed set, Pod
Security is enforced rather than warned about, the guarded installer cannot be
pointed at the unsuspended bootstrap root, and the documentation states the
ordering rather than implying it.

``FreshClusterDryRunGateTests`` is the one *behavioural* class: it runs the real
installer against stubbed ``kustomize``/``kubectl`` binaries on ``PATH`` (the
same stubbing shape ``test_edge_probe_contract`` uses) and drives the pre-apply
gate through the fresh-cluster shape it must accept — 14 cluster-scoped
``created`` plus 11 children reporting ``namespaces "flux-system" not found``
(kubernetes/kubernetes#83562, which the old "all 25 must be created" gate could
never pass) — and the genuine failures it must still refuse.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import required_tool


BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required to exercise the installer gate"

ROOT = Path(__file__).resolve().parents[2]
CONTROLLERS = ROOT / "kubernetes" / "flux-system" / "controllers"
EGRESS = ROOT / "kubernetes" / "flux-system" / "egress"
INSTALLER = ROOT / "scripts" / "install-flux-controllers.sh"
RUNBOOK = ROOT / "docs" / "runbooks" / "flux-install.md"
RENDERER = ROOT / "scripts" / "render-manifests.sh"
REGO = ROOT / "policies" / "conftest" / "kubernetes.rego"
BOOTSTRAP_README = ROOT / "bootstrap" / "flux" / "README.md"

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
        apply_index = self.text.rindex("kubectl apply -f \"$rendered\"")
        self.assertLess(
            plan_index,
            apply_index,
            "the plan-only exit must precede the mutating apply",
        )

    def test_it_never_uses_kubectl_apply_k(self):
        self.assertNotIn("apply -k", self.text)


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
    exactly 25 ``kind:`` lines) run against it, and the fresh-cluster absence
    probe finds the exact reviewed ClusterRole/ClusterRoleBinding names in it.
    Only structure matters here — ``kustomize`` is stubbed, so no field is
    parsed for meaning.
    """

    docs = [
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: flux-system\n"
        "  labels:\n    pod-security.kubernetes.io/enforce: restricted\n"
    ]
    for crd in (
        "buckets.source.toolkit.fluxcd.io",
        "externalartifacts.source.toolkit.fluxcd.io",
        "gitrepositories.source.toolkit.fluxcd.io",
        "helmcharts.source.toolkit.fluxcd.io",
        "helmrepositories.source.toolkit.fluxcd.io",
        "ocirepositories.source.toolkit.fluxcd.io",
        "kustomizations.kustomize.toolkit.fluxcd.io",
        "helmreleases.helm.toolkit.fluxcd.io",
    ):
        docs.append(
            "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
            "metadata:\n  name: {}\n".format(crd)
        )
    for role in ("crd-controller-flux-system", "flux-edit-flux-system", "flux-view-flux-system"):
        docs.append(
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
            "metadata:\n  name: {}\n".format(role)
        )
    for binding in ("cluster-reconciler-flux-system", "crd-controller-flux-system"):
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
    for sa in ("source-controller", "kustomize-controller", "helm-controller"):
        docs.append(
            "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n"
            "  name: {}\n  namespace: flux-system\n".format(sa)
        )
    docs.append(
        "apiVersion: v1\nkind: Service\nmetadata:\n"
        "  name: source-controller\n  namespace: flux-system\n"
    )
    for dep in ("source-controller", "kustomize-controller", "helm-controller"):
        docs.append(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
            "  name: {}\n  namespace: flux-system\n".format(dep)
        )
    return "---\n".join(docs)


# The stubbed kubectl. It reproduces the exact report shapes the real kubectl
# emits, selected by FLUX_STUB_SCENARIO: the fresh/existing clean shapes and a
# family of genuine failures. Nothing here contacts a cluster.
_KUBECTL_STUB = r"""#!/usr/bin/env bash
scenario="${FLUX_STUB_SCENARIO:-fresh-ok}"
args="$*"
cs_created() { local suf="$1"
  printf 'namespace/flux-system created %s\n' "$suf"
  for c in buckets.source.toolkit.fluxcd.io externalartifacts.source.toolkit.fluxcd.io \
    gitrepositories.source.toolkit.fluxcd.io helmcharts.source.toolkit.fluxcd.io \
    helmrepositories.source.toolkit.fluxcd.io ocirepositories.source.toolkit.fluxcd.io \
    kustomizations.kustomize.toolkit.fluxcd.io helmreleases.helm.toolkit.fluxcd.io; do
    printf 'customresourcedefinition.apiextensions.k8s.io/%s created %s\n' "$c" "$suf"; done
  for r in crd-controller-flux-system flux-edit-flux-system flux-view-flux-system; do
    printf 'clusterrole.rbac.authorization.k8s.io/%s created %s\n' "$r" "$suf"; done
  for b in cluster-reconciler-flux-system crd-controller-flux-system; do
    printf 'clusterrolebinding.rbac.authorization.k8s.io/%s created %s\n' "$b" "$suf"; done
}
ns_children() { local verb="$1" suf="$2"
  for n in allow-egress allow-scraping allow-webhooks; do
    printf 'networkpolicy.networking.k8s.io/%s %s %s\n' "$n" "$verb" "$suf"; done
  printf 'resourcequota/critical-pods-flux-system %s %s\n' "$verb" "$suf"
  for s in source-controller kustomize-controller helm-controller; do
    printf 'serviceaccount/%s %s %s\n' "$s" "$verb" "$suf"; done
  printf 'service/source-controller %s %s\n' "$verb" "$suf"
  for d in source-controller kustomize-controller helm-controller; do
    printf 'deployment.apps/%s %s %s\n' "$d" "$verb" "$suf"; done
}
ns_not_found() { local i; for i in 1 2 3 4 5 6 7 8 9 10 11; do
  printf 'Error from server (NotFound): error when creating "STDIN": namespaces "flux-system" not found\n'; done; }

case "$args" in
  *"--dry-run=client"*)
    [[ "$scenario" == client-invalid ]] && { echo 'error: strict decoding error: unknown field "spec.bogus"' >&2; exit 1; }
    cs_created "(dry run)"; ns_children created "(dry run)"; exit 0 ;;
  "get namespace flux-system"*)
    if [[ "$scenario" == existing-* ]]; then echo 'namespace/flux-system'; exit 0
    else echo 'Error from server (NotFound): namespaces "flux-system" not found' >&2; exit 1; fi ;;
  "get customresourcedefinition"*)
    if [[ "$scenario" == fresh-crd-present ]]; then
      echo 'customresourcedefinition.apiextensions.k8s.io/gitrepositories.source.toolkit.fluxcd.io'; fi
    exit 0 ;;
  "get clusterrolebinding "*)
    [[ "$scenario" == fresh-crb-present ]] && { echo 'clusterrolebinding.rbac.authorization.k8s.io/crd-controller-flux-system'; exit 0; }
    echo 'Error from server (NotFound)' >&2; exit 1 ;;
  "get clusterrole "*)
    [[ "$scenario" == fresh-cr-present ]] && { echo 'clusterrole.rbac.authorization.k8s.io/crd-controller-flux-system'; exit 0; }
    echo 'Error from server (NotFound)' >&2; exit 1 ;;
  *"--dry-run=server"*)
    case "$scenario" in
      existing-ok) cs_created "(server dry run)"; ns_children configured "(server dry run)"; exit 0 ;;
      fresh-ok) cs_created "(server dry run)"; ns_not_found; exit 1 ;;
      fresh-foreign) cs_created "(server dry run)"; printf 'namespace/kube-system created (server dry run)\n'; ns_not_found; exit 1 ;;
      fresh-configured) printf 'namespace/flux-system configured (server dry run)\n'
        for c in buckets.source.toolkit.fluxcd.io externalartifacts.source.toolkit.fluxcd.io \
          gitrepositories.source.toolkit.fluxcd.io helmcharts.source.toolkit.fluxcd.io \
          helmrepositories.source.toolkit.fluxcd.io ocirepositories.source.toolkit.fluxcd.io \
          kustomizations.kustomize.toolkit.fluxcd.io helmreleases.helm.toolkit.fluxcd.io; do
          printf 'customresourcedefinition.apiextensions.k8s.io/%s created (server dry run)\n' "$c"; done
        for r in crd-controller-flux-system flux-edit-flux-system flux-view-flux-system; do
          printf 'clusterrole.rbac.authorization.k8s.io/%s created (server dry run)\n' "$r"; done
        for b in cluster-reconciler-flux-system crd-controller-flux-system; do
          printf 'clusterrolebinding.rbac.authorization.k8s.io/%s created (server dry run)\n' "$b"; done
        ns_not_found; exit 1 ;;
      fresh-genuine-error) cs_created "(server dry run)"
        for i in 1 2 3 4 5 6 7 8 9 10; do
          printf 'Error from server (NotFound): error when creating "STDIN": namespaces "flux-system" not found\n'; done
        printf 'Error from server (Forbidden): error when creating "STDIN": deployments.apps is forbidden\n'; exit 1 ;;
    esac ;;
  "apply -f"*) printf 'namespace/flux-system created\n'; exit 0 ;;
esac
echo "stub kubectl: unhandled args: $args" >&2; exit 99
"""


@unittest.skipUnless(BASH, "bash is unavailable")
class FreshClusterDryRunGateTests(unittest.TestCase):
    """Behavioural: the pre-apply gate accepts the fresh-cluster dry-run shape.

    The defect this exists for: the install creates its own flux-system
    Namespace, and ``kubectl apply --dry-run=server`` does not persist it
    (kubernetes/kubernetes#83562), so the 11 namespaced children report
    ``namespaces "flux-system" not found`` and kubectl exits non-zero on a fresh
    cluster. The previous gate demanded all 25 objects report ``created`` and so
    could never pass the fresh install it exists to perform. These tests drive
    the real installer against stubbed binaries and prove both directions: the
    two legitimate shapes are accepted, and every genuine failure is refused.
    """

    @classmethod
    def setUpClass(cls):
        cls.stub_dir = Path(
            tempfile.mkdtemp(prefix="flux-install-gate.", dir=os.environ.get("TMPDIR"))
        )
        render_path = cls.stub_dir / "controllers.yaml"
        render_path.write_text(_reviewed_render(), encoding="utf-8")
        kustomize = cls.stub_dir / "kustomize"
        kustomize.write_text(
            "#!/usr/bin/env bash\ncat {}\n".format(shlex.quote(str(render_path))),
            encoding="utf-8",
        )
        kustomize.chmod(0o755)
        kubectl = cls.stub_dir / "kubectl"
        kubectl.write_text(_KUBECTL_STUB, encoding="utf-8")
        kubectl.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.stub_dir, ignore_errors=True)

    def _run(self, scenario, mode="--plan"):
        environment = dict(os.environ)
        environment["PATH"] = os.pathsep.join(
            [str(self.stub_dir), environment.get("PATH", "")]
        )
        environment["FLUX_STUB_SCENARIO"] = scenario
        return subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), str(INSTALLER), mode],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(ROOT),
        )

    def test_the_render_skeleton_passes_the_installers_own_content_gates(self):
        # Vacuity floor: if the stubbed render did not satisfy the content gates,
        # every acceptance test below would pass for the wrong reason (dying
        # early), so pin the 25-object shape the gate actually classifies.
        render = _reviewed_render()
        self.assertEqual(render.count("\nkind:") + render.startswith("kind:"), 25)
        self.assertIn("pod-security.kubernetes.io/enforce: restricted", render)
        self.assertNotIn("kind: Secret", render)

    def test_fresh_cluster_shape_is_accepted(self):
        completed = self._run("fresh-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn(
            "fresh-cluster dry run clean (14 created + 11 expected namespace-not-found)",
            completed.stdout,
        )
        self.assertIn("PLAN only; no mutation attempted", completed.stdout)

    def test_existing_cluster_shape_is_accepted(self):
        completed = self._run("existing-ok")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("existing-cluster dry run clean (25 objects)", completed.stdout)

    def test_a_foreign_object_in_the_dry_run_fails_closed(self):
        # A 26th line (another namespace) must break the fresh shape and stop.
        completed = self._run("fresh-foreign")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fresh dry-run shape wrong", completed.stderr)
        self.assertNotIn("dry run clean", completed.stdout)

    def test_a_real_configured_fails_closed(self):
        # A cluster-scoped object reporting "configured" instead of "created" on
        # a fresh cluster means it already exists; the gate must refuse it.
        completed = self._run("fresh-configured")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fresh dry-run shape wrong", completed.stderr)

    def test_a_genuine_error_on_a_child_fails_closed(self):
        # One child failing with something other than the flux-system
        # namespace-not-found (a Forbidden here) must not be waved through.
        completed = self._run("fresh-genuine-error")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fresh dry-run shape wrong", completed.stderr)
        self.assertNotIn("dry run clean", completed.stdout)

    def test_a_preexisting_fluxcd_crd_fails_closed(self):
        completed = self._run("fresh-crd-present")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fluxcd CRD(s) already exist", completed.stderr)

    def test_a_preexisting_clusterrole_fails_closed(self):
        completed = self._run("fresh-cr-present")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("ClusterRole crd-controller-flux-system already exists", completed.stderr)

    def test_a_preexisting_clusterrolebinding_fails_closed(self):
        completed = self._run("fresh-crb-present")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "ClusterRoleBinding cluster-reconciler-flux-system already exists",
            completed.stderr,
        )

    def test_an_invalid_render_fails_client_validation(self):
        completed = self._run("client-invalid")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("client-side strict validation failed", completed.stderr)

    def test_apply_reaches_the_real_apply_only_after_a_clean_fresh_gate(self):
        # --apply runs the identical gate, then the one mutating apply. Proving
        # the mutating path is reached on the accepted shape is what makes the
        # acceptance tests above load-bearing rather than "everything exits 0".
        completed = self._run("fresh-ok", mode="--apply")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("applied; Flux is installed and inert", completed.stdout)


if __name__ == "__main__":
    unittest.main()
