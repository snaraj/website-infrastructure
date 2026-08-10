"""Require transition rendering to consume authoritative Flux values."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RENDER = REPO_ROOT / "scripts" / "render-manifests.sh"


class ReleaseRenderOverrideTests(unittest.TestCase):
    """Keep scaffold defaults inert while proving each effective safe phase."""

    @classmethod
    def setUpClass(cls):
        cls.script = RENDER.read_text(encoding="utf-8")

    def test_closed_chart_rows_cover_only_the_platform_chart(self):
        """Site charts render in their own repositories; only the platform
        cloudflare-public chart remains a local render target."""

        self.assertIn(
            "cloudflare-public|cloudflare-public|kubernetes/platform/cloudflare-public/chart",
            self.script,
        )
        for removed in (
            "websites/naranjo.online/chart",
            "websites/lidersea.com/chart",
        ):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, self.script)

    def test_transition_and_release_use_exact_helmrelease_values(self):
        mode_gate = self.script.index("if [[ \"$MODE\" != '--scaffold' ]]")
        emit = self.script.index("validate_release_state.py\" emit-values")
        args = self.script.index('helm_values_args=(--values "$release_values")')
        lint = self.script.index('helm lint "$chart_path" "${helm_values_args[@]}"')
        template = self.script.index(
            'helm template "$release_name" "$chart_path" --namespace "$namespace"'
        )

        self.assertLess(mode_gate, emit)
        self.assertLess(emit, args)
        self.assertLess(args, lint)
        self.assertLess(lint, template)
        self.assertIn('--release "$release_name" >"$release_values"', self.script)
        self.assertIn('"${helm_values_args[@]}" >"$output"', self.script)

    def test_renderer_requires_an_exact_authoritative_transition_plan(self):
        self.assertIn("--scaffold|--transition|--release", self.script)
        self.assertIn(
            'validate_release_transition.py\" plan \\\n    --expect-mode "$mode_name"',
            self.script,
        )
        self.assertIn('((${#release_plan_lines[@]} == 6))', self.script)
        for record in (
            "mode=${mode_name}",
            "^naranjo-online=(initial|staged|active)$",
            "^lidersea-com=(initial|staged|active)$",
            "^cloudflare-public=(initial|staged|active)$",
            "^any-website-active=(true|false)$",
            "^any-workload-active=(true|false)$",
        ):
            with self.subTest(record=record):
                self.assertIn(record, self.script)
        self.assertNotIn("eval ", self.script)
        self.assertNotIn("source <", self.script)

    def test_transition_proves_each_site_at_its_classified_phase(self):
        self.assertIn("[naranjo-online]=\"$naranjo_phase\"", self.script)
        self.assertIn("[lidersea-com]=\"$lidersea_phase\"", self.script)
        self.assertIn(
            'if [[ "${WEBSITE_PHASES[$website]}" == \'initial\' ]]', self.script
        )
        self.assertIn(
            'expect_release_rejection "$output" "Deployment ${website} is not marked ready"',
            self.script,
        )
        self.assertIn(
            'expect_release_rejection "$output" "container ${website} still uses the all-zero digest"',
            self.script,
        )
        self.assertIn(
            'conftest test --policy "${REPO_ROOT}/policies/release-conftest" "$output"',
            self.script,
        )

    def test_active_workload_requires_controller_admission_and_core_policies(self):
        workload_gate = self.script.index(
            "if [[ \"$any_workload_active\" == 'true' ]]"
        )
        for artifact in (
            "kubernetes-flux-system.yaml",
            "kubernetes/platform/admission/kyverno/controllers.yaml",
            '"${CORE_POLICY_FILES[@]}"',
        ):
            with self.subTest(artifact=artifact):
                self.assertGreater(
                    self.script.index(artifact, workload_gate), workload_gate
                )
        self.assertIn(
            "Flux controller artifact is required whenever a workload is active",
            self.script,
        )
        website_gate = self.script.index(
            "if [[ \"$any_website_active\" == 'true' ]]", workload_gate
        )
        workload_block = self.script[workload_gate:website_gate]
        self.assertNotIn("policies-kyverno.yaml", workload_block)
        self.assertNotIn("kubernetes-platform-admission.yaml", workload_block)

    def test_live_or_outer_reconcilable_website_adds_production_proof(self):
        active_gate = self.script.index(
            "if [[ \"$any_website_active\" == 'true' ]]", self.script.index("else\n  # Transition mode")
        )
        for artifact in (
            "kubernetes-platform-prerequisites.yaml",
            "policies-kyverno.yaml",
        ):
            with self.subTest(artifact=artifact):
                self.assertGreater(self.script.index(artifact, active_gate), active_gate)
        self.assertIn(
            "a live or outer-reconcilable website refuses the still-active zero-site-capacity admission policy",
            self.script,
        )
        self.assertIn("active website parent", self.script)

    def test_transition_cloudflare_requires_unresolved_or_release_proof(self):
        self.assertIn("if [[ \"$cloudflare_phase\" == 'initial' ]]", self.script)
        self.assertIn(
            "'cloudflared tunnel token revision remains unresolved'", self.script
        )
        self.assertIn(
            '"${ARTIFACT_ROOT}/helm-cloudflare-public.yaml"', self.script
        )

    def test_scaffold_has_no_override_and_temporary_values_are_removed(self):
        self.assertIn("helm_values_args=()", self.script)
        self.assertIn("temporary_values+=(\"$release_values\")", self.script)
        self.assertIn("trap cleanup_temporary_values EXIT", self.script)
        self.assertIn('rm -f -- "$temporary_value"', self.script)


if __name__ == "__main__":
    unittest.main()
