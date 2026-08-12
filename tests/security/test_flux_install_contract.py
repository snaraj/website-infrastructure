"""Offline contracts for the reproducible, inert Flux controller install.

Nothing here contacts a cluster. These tests pin the properties that make the
install reviewable and the namespace fail-closed: the generated blanket egress
allow is removed, the egress allowlist is exactly the reviewed set, Pod
Security is enforced rather than warned about, the guarded installer cannot be
pointed at the unsuspended bootstrap root, and the documentation states the
ordering rather than implying it.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


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
        self.assertIn("--dry-run=server", self.text)
        self.assertIn("EXPECTED_OBJECTS=25", self.text)
        self.assertIn(
            "dry run reported an object outside the reviewed controller inventory",
            self.text,
        )
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


if __name__ == "__main__":
    unittest.main()
