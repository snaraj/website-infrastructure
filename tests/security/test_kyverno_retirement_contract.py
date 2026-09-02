"""Prove Kyverno is absent without weakening the controls that replace no gate."""

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .support import load_script, required_tool


ROOT = Path(__file__).resolve().parents[2]
CONFTEST = shutil.which("conftest")
TRANSITION = load_script(
    "validate_release_transition.py", module_name="kyverno_retirement_transition"
)
TRANSITION_FILES = (
    "kubernetes/websites/naranjo-online/release.yaml",
    "kubernetes/websites/lidersea-com/release.yaml",
    "kubernetes/platform/cloudflare-public/release/release.yaml",
    "kubernetes/platform/cloudflare-public/release/kustomization.yaml",
) + tuple(
    path.as_posix()
    for path in sorted(TRANSITION.CLOUDFLARE_TERRAFORM_REVIEW_FILES)
)


class KyvernoRetirementContractTests(unittest.TestCase):
    def test_each_direct_site_root_owns_one_exact_default_deny(self):
        for site in ("naranjo-online", "lidersea-com"):
            with self.subTest(site=site):
                policy = ROOT / "kubernetes" / "websites" / site / "default-deny.yaml"
                self.assertEqual(
                    policy.read_text(encoding="utf-8"),
                    "apiVersion: networking.k8s.io/v1\n"
                    "kind: NetworkPolicy\n"
                    "metadata:\n"
                    "  name: default-deny\n"
                    "  namespace: {}\n"
                    "spec:\n"
                    "  podSelector: {{}}\n"
                    "  policyTypes:\n"
                    "    - Ingress\n"
                    "    - Egress\n".format(site),
                )
                kustomization = (
                    ROOT / "kubernetes" / "websites" / site / "kustomization.yaml"
                ).read_text(encoding="utf-8")
                self.assertEqual(kustomization.count("  - default-deny.yaml\n"), 1)

        prerequisites = (
            ROOT / "kubernetes/platform/prerequisites/network-policies.yaml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("namespace: naranjo-online", prerequisites)
        self.assertNotIn("namespace: lidersea-com", prerequisites)
        self.assertEqual(prerequisites.count("name: default-deny\n"), 1)

    def test_revisit_trigger_is_a_material_trust_boundary_expansion(self):
        normative_paths = (
            "AGENTS.md",
            "docs/adr/0016-tag-driven-flux-release-sync.md",
            "docs/assurance/phase-c-kubernetes-adversarial.md",
            "docs/runbooks/image-signature-admission.md",
        )
        required = (
            "material trust-boundary expansion, including another independent "
            "tenant or untrusted/third-party workload"
        )
        for relative in normative_paths:
            with self.subTest(path=relative):
                text = " ".join((ROOT / relative).read_text(encoding="utf-8").split())
                self.assertIn(required, text)
                self.assertNotIn("second tenant", text.lower())
                self.assertNotIn("reconsidered only if", text.lower())

    def test_executable_kyverno_surfaces_are_absent(self):
        retired = (
            "policies/kyverno",
            "kubernetes/platform/admission",
            "kubernetes/platform/admission-install",
            "tests/kubernetes/kyverno",
            "tests/kubernetes/fixtures/kyverno-admission",
            "scripts/install-kyverno-admission.sh",
            "scripts/test-storage-engine-parity.sh",
        )
        for relative in retired:
            with self.subTest(path=relative):
                path = ROOT / relative
                if path.is_dir():
                    self.assertEqual(
                        [candidate for candidate in path.rglob("*") if candidate.is_file()],
                        [],
                    )
                else:
                    self.assertFalse(path.exists())

    def test_runtime_toolchain_policy_and_ci_do_not_recreate_the_dependency(self):
        paths = (
            "versions.env",
            "bootstrap/flux/bootstrap.sh",
            "kubernetes/flux-system/access.yaml",
            "kubernetes/platform/prerequisites/namespaces.yaml",
            "kubernetes/platform/prerequisites/network-policies.yaml",
            "policies/conftest/kubernetes.rego",
            "policies/release-conftest/deployment-readiness.rego",
            "scripts/ci/install-tools.sh",
            "scripts/flux_rbac_kind_acceptance.py",
            "scripts/render-manifests.sh",
            "scripts/release-gate.sh",
            "scripts/validate-security.sh",
            "scripts/validate_release_transition.py",
            "scripts/validate_repository.py",
            "scripts/validate_runtime_inventory_evidence.py",
            "scripts/validate_signature_policy.py",
            "scripts/ci/platform_release_contract.py",
            "tests/security/testsupport/rbac_model.py",
            ".github/workflows/pull-request.yml",
            ".sourceignore",
        )
        for relative in paths:
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8").lower()
                self.assertNotIn("kyverno", text)

    def test_no_active_executable_surface_mentions_kyverno(self):
        active_roots = (
            ROOT / ".github" / "workflows",
            ROOT / "bootstrap",
            ROOT / "kubernetes",
            ROOT / "policies",
            ROOT / "scripts",
        )
        executable_suffixes = {".env", ".py", ".rego", ".sh", ".yaml", ".yml"}
        candidates = [ROOT / "Makefile", ROOT / "versions.env", ROOT / ".sourceignore"]
        for active_root in active_roots:
            candidates.extend(
                path
                for path in active_root.rglob("*")
                if path.is_file() and path.suffix in executable_suffixes
            )
        stale = [
            str(path.relative_to(ROOT))
            for path in sorted(set(candidates))
            if "kyverno" in path.read_text(encoding="utf-8").lower()
        ]
        self.assertEqual(
            stale,
            [],
            "an active executable surface still depends on or recreates Kyverno",
        )

    def test_no_test_harness_invokes_the_retired_cli(self):
        invocation_patterns = (
            re.compile(r"\bkyverno\s+(?:apply|test|version)\b", re.IGNORECASE),
            re.compile(r"shutil\.which\(\s*['\"]kyverno['\"]\s*\)", re.IGNORECASE),
            re.compile(r"['\"]kyverno['\"]\s*,", re.IGNORECASE),
            re.compile(r"\bKYVERNO_(?:BIN|CLI|VERSION)\b"),
        )
        offenders = []
        for suffix in ("*.py", "*.sh"):
            for path in (ROOT / "tests").rglob(suffix):
                if path == Path(__file__).resolve():
                    continue
                text = path.read_text(encoding="utf-8")
                if any(pattern.search(text) for pattern in invocation_patterns):
                    offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(
            sorted(offenders),
            [],
            "a test harness still discovers or invokes the retired Kyverno CLI",
        )

    def _assert_exact_conftest_denial(self, fixture, tool=None):
        fixture_path = ROOT / "tests" / "kubernetes" / "fixtures" / "deny" / fixture
        expected_path = fixture_path.with_suffix(".expected")
        self.assertTrue(
            fixture_path.is_file(), "retained hostile fixture is missing: " + fixture
        )
        self.assertTrue(
            expected_path.is_file(), "hostile attribution sidecar is missing: " + fixture
        )
        expected = sorted(
            line.strip()
            for line in expected_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertTrue(expected, "hostile attribution sidecar is empty: " + fixture)
        completed = subprocess.run(
            [
                tool or required_tool(CONFTEST, "conftest"),
                "test",
                "--no-color",
                "--policy",
                str(ROOT / "policies/conftest"),
                str(fixture_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        actual = sorted(
            re.findall(r"(?m)^FAIL - .* - main - (.+)$", completed.stdout)
        )
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertEqual(actual, expected)

    def test_retained_hostile_controls_reject_public_mutable_and_cross_tenant(self):
        fixtures = (
            "insecure.yaml",
            "image-tag-without-digest.yaml",
            "image-sibling-site-repository-tagged.yaml",
            "helmrelease-external-inputs.yaml",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self._assert_exact_conftest_denial(fixture)

    def test_arbitrary_nonzero_tool_cannot_impersonate_conftest_denial(self):
        with self.assertRaises(AssertionError):
            self._assert_exact_conftest_denial(
                "image-tag-without-digest.yaml", "/usr/bin/false"
            )

    def test_unsafe_release_activation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for relative in TRANSITION_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            release = root / "kubernetes/websites/naranjo-online/release.yaml"
            text = release.read_text(encoding="utf-8")
            trusted = "    name: naranjo-online-chart\n"
            unsafe = "    name: lidersea-com-chart\n"
            self.assertEqual(text.count(trusted), 1)
            release.write_text(text.replace(trusted, unsafe), encoding="utf-8")

            with self.assertRaisesRegex(
                TRANSITION.STATE.CanonicalYamlError,
                "release YAML shape is outside the closed contract",
            ):
                TRANSITION.STATE.load_helm_release("naranjo-online", root)

            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/validate_release_transition.py"),
                    "--root",
                    str(root),
                    "plan",
                    "--expect-mode",
                    "transition",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(
                completed.stderr,
                "ERROR release transition state is unavailable or unsafe\n",
            )


if __name__ == "__main__":
    unittest.main()
