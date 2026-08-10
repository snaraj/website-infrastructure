"""Prove signature admission cannot be satisfied by comments or weak YAML."""

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_signature_policy.py"
SPEC = importlib.util.spec_from_file_location("validate_signature_policy", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REPOSITORY_SPEC = importlib.util.spec_from_file_location(
    "signature_validate_repository", REPO_ROOT / "scripts/validate_repository.py"
)
REPOSITORY_MODULE = importlib.util.module_from_spec(REPOSITORY_SPEC)
REPOSITORY_SPEC.loader.exec_module(REPOSITORY_MODULE)


class SignaturePolicyContractTests(unittest.TestCase):
    """Exercise both approved sites and every security-critical nested field."""

    def canonical(self, slug="naranjo-online", action="Audit"):
        return MODULE.expected_policy_body(
            slug, MODULE.SIGNATURE_CONTRACTS[slug], action
        )

    def assert_rejected(self, old, new, count=1):
        text = self.canonical().replace(old, new, count)
        self.assertNotEqual(text, self.canonical(), "mutation did not change fixture")
        self.assertTrue(
            MODULE.signature_policy_errors(
                text,
                "naranjo-online",
                MODULE.SIGNATURE_CONTRACTS["naranjo-online"],
            )
        )
        self.assertIsNone(
            MODULE.signature_policy_action(
                text,
                "naranjo-online",
                MODULE.SIGNATURE_CONTRACTS["naranjo-online"],
            )
        )

    def test_audit_and_enforce_are_exact_variants_for_both_sites(self):
        for slug, workflow in MODULE.SIGNATURE_CONTRACTS.items():
            for action in MODULE.ALLOWED_ACTIONS:
                with self.subTest(slug=slug, action=action):
                    text = MODULE.expected_policy_body(slug, workflow, action)
                    self.assertEqual(
                        MODULE.signature_policy_errors(text, slug, workflow), []
                    )
                    self.assertEqual(
                        MODULE.signature_policy_action(text, slug, workflow), action
                    )

    def test_checked_in_policies_are_the_canonical_audit_variants(self):
        for slug, workflow in MODULE.SIGNATURE_CONTRACTS.items():
            with self.subTest(slug=slug):
                text = REPO_ROOT.joinpath(
                    "policies", "kyverno", "require-signed-{}.yaml".format(slug)
                ).read_text(encoding="utf-8")
                self.assertEqual(
                    MODULE.signature_policy_errors(text, slug, workflow), []
                )
                self.assertEqual(
                    MODULE.signature_policy_action(text, slug, workflow), "Audit"
                )

    def test_action_specific_validation_cannot_confuse_audit_with_enforce(self):
        audit = self.canonical(action="Audit")
        enforce = self.canonical(action="Enforce")
        workflow = MODULE.SIGNATURE_CONTRACTS["naranjo-online"]
        self.assertTrue(MODULE.signature_policy_errors(audit, "naranjo-online", workflow, ("Enforce",)))
        self.assertTrue(MODULE.signature_policy_errors(enforce, "naranjo-online", workflow, ("Audit",)))

    def test_signature_and_provenance_rule_presence_is_structural(self):
        canonical = self.canonical()
        signature_start = canonical.index("    - name: verify-naranjo-online-signature\n")
        provenance_start = canonical.index("    - name: verify-naranjo-online-provenance\n")
        without_signature = canonical[:signature_start] + canonical[provenance_start:]
        commented_fragment = (
            "# verifyImages attestors required true verifyDigest true "
            "https://rekor.sigstore.dev\n" + without_signature
        )
        self.assertTrue(MODULE.signature_policy_errors(
            commented_fragment,
            "naranjo-online",
            MODULE.SIGNATURE_CONTRACTS["naranjo-online"],
        ))

    def test_weakened_verify_images_fields_are_rejected(self):
        mutations = {
            "verifyImages removed": ("      verifyImages:\n", "      verifyImagesDisabled:\n"),
            "broad repository prefix": (
                "ghcr.io/snaraj/naranjo-online@sha256:*",
                "ghcr.io/snaraj/naranjo-online*",
            ),
            "digest mutation": ("          mutateDigest: false\n", "          mutateDigest: true\n"),
            "not required": ("          required: true\n", "          required: false\n"),
            "digest not verified": ("          verifyDigest: true\n", "          verifyDigest: false\n"),
            "skip escape": (
                "          mutateDigest: false\n",
                "          skipImageReferences: [\"*\"]\n          mutateDigest: false\n",
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                self.assert_rejected(*mutation)

    def test_weakened_attestor_identity_and_transparency_are_rejected(self):
        mutations = {
            "attestors removed": ("          attestors:\n", "          authorities:\n"),
            "zero threshold": ("            - count: 1\n", "            - count: 0\n"),
            "subject regex": (
                "                    subject: https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/tags/v*\n",
                "                    subjectRegExp: https://github.com/.+\n",
            ),
            "wrong issuer": (
                "                    issuer: https://token.actions.githubusercontent.com\n",
                "                    issuer: https://accounts.example.invalid\n",
            ),
            "wrong Rekor": (
                "                      url: https://rekor.sigstore.dev\n",
                "                      url: https://rekor.example.invalid\n",
            ),
            "ignored tlog": (
                "                    rekor:\n                      url: https://rekor.sigstore.dev\n",
                "                    rekor:\n                      ignoreTlog: true\n                      url: https://rekor.sigstore.dev\n",
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                self.assert_rejected(*mutation)

    def test_weakened_slsa_predicate_and_build_type_are_rejected(self):
        mutations = {
            "not a Sigstore bundle": (
                "          type: SigstoreBundle\n",
                "          type: Cosign\n",
            ),
            "wrong predicate": (
                "            - type: https://slsa.dev/provenance/v1\n",
                "            - type: https://example.invalid/provenance\n",
            ),
            "wrong condition key": (
                '                    - key: "{{ buildDefinition.buildType }}"\n',
                '                    - key: "{{ builder.id }}"\n',
            ),
            "permissive operator": (
                "                      operator: Equals\n",
                "                      operator: NotEquals\n",
            ),
            "wrong build type": (
                "                      value: https://actions.github.io/buildtypes/workflow/v1\n",
                "                      value: https://example.invalid/buildtype\n",
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                self.assert_rejected(*mutation)

    def test_duplicate_keys_extra_documents_and_noncanonical_bytes_fail(self):
        canonical = self.canonical()
        candidates = (
            canonical.replace(
                "  validationFailureAction: Audit\n",
                "  validationFailureAction: Enforce\n  validationFailureAction: Audit\n",
            ),
            canonical + "---\napiVersion: v1\nkind: ConfigMap\n",
            canonical.replace("  admission: true\n", "\tadmission: true\n"),
            canonical.replace("\n", "\r\n"),
            canonical.rstrip("\n"),
        )
        for index, candidate in enumerate(candidates):
            with self.subTest(index=index):
                self.assertTrue(MODULE.signature_policy_errors(
                    candidate,
                    "naranjo-online",
                    MODULE.SIGNATURE_CONTRACTS["naranjo-online"],
                ))

    def test_policy_kustomization_is_resources_only_and_exactly_lists_both_sites(self):
        canonical = REPO_ROOT.joinpath(
            "policies", "kyverno", "kustomization.yaml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            MODULE.signature_policy_kustomization_errors(canonical, ("staging",)),
            [],
        )
        self.assertTrue(
            MODULE.signature_policy_kustomization_errors(canonical, ("promoted",))
        )

        promoted = MODULE.EXPECTED_PROMOTED_POLICY_KUSTOMIZATION
        self.assertEqual(
            MODULE.signature_policy_kustomization_errors(promoted, ("promoted",)),
            [],
        )
        self.assertTrue(
            MODULE.signature_policy_kustomization_errors(promoted, ("staging",))
        )
        self.assertEqual(
            MODULE.signature_policy_kustomization_errors(
                promoted, ("staging", "promoted")
            ),
            [],
        )
        self.assertTrue(MODULE.signature_policy_kustomization_errors(promoted, ()))
        for label, candidate in {
            "name prefix": canonical + "namePrefix: bypass-\n",
            "name suffix": canonical + "nameSuffix: -bypass\n",
            "patch": canonical + "patches:\n  - path: bypass.yaml\n",
            "duplicate": canonical + "  - require-signed-naranjo-online.yaml\n",
            "missing": canonical.replace(
                "  - require-signed-lidersea-com.yaml\n", ""
            ),
            "replacement": canonical.replace(
                "  - require-signed-lidersea-com.yaml\n",
                "  - bypass.yaml\n",
            ),
            "remote": canonical + "  - https://example.invalid/policy.yaml\n",
            "component": canonical + "components:\n  - ../../bypass\n",
            "generator": canonical + "secretGenerator:\n  - name: bypass\n",
            "image rewrite": canonical + "images:\n  - name: bypass\n",
        }.items():
            with self.subTest(label=label):
                self.assertTrue(
                    MODULE.signature_policy_kustomization_errors(
                        candidate, ("staging", "promoted")
                    )
                )

        for label, candidate in {
            "promoted extra": promoted + "  - bypass.yaml\n",
            "promoted missing": promoted.replace(
                "  - require-signed-lidersea-com.yaml\n", ""
            ),
        }.items():
            with self.subTest(label=label):
                self.assertTrue(
                    MODULE.signature_policy_kustomization_errors(
                        candidate, ("promoted",)
                    )
                )

    def test_admission_parent_rejects_every_kustomize_transform(self):
        canonical = MODULE.EXPECTED_ADMISSION_KUSTOMIZATION
        self.assertEqual(MODULE.admission_kustomization_errors(canonical), [])
        transforms = {
            "name prefix": canonical + "namePrefix: bypass-\n",
            "name suffix": canonical + "nameSuffix: -bypass\n",
            "remove policies": canonical.replace(
                "  - ../../../policies/kyverno\n", ""
            ),
            "replace policies": canonical.replace(
                "  - ../../../policies/kyverno\n", "  - ../../../bypass\n"
            ),
            "patch": canonical + "patches:\n  - path: bypass.yaml\n",
            "replacement": canonical + "replacements:\n  - source: {}\n",
            "image rewrite": canonical + "images:\n  - name: ghcr.io/snaraj/naranjo-online\n",
            "component": canonical + "components:\n  - ../../../bypass\n",
            "generator": canonical + "configMapGenerator:\n  - name: bypass\n",
        }
        for label, candidate in transforms.items():
            with self.subTest(label=label):
                self.assertTrue(MODULE.admission_kustomization_errors(candidate))

    def test_reconciliation_root_rejects_rename_removal_and_generators(self):
        canonical = MODULE.EXPECTED_RECONCILIATION_KUSTOMIZATION
        self.assertEqual(
            MODULE.reconciliation_kustomization_errors(canonical), []
        )
        mutations = {
            "name prefix": canonical + "namePrefix: bypass-\n",
            "name suffix": canonical + "nameSuffix: -bypass\n",
            "remove admission": canonical.replace("  - admission.yaml\n", ""),
            "replace admission": canonical.replace(
                "  - admission.yaml\n", "  - bypass.yaml\n"
            ),
            "patch": canonical + "patches:\n  - path: bypass.yaml\n",
            "component": canonical + "components:\n  - ../../bypass\n",
            "generator": canonical + "configMapGenerator:\n  - name: bypass\n",
        }
        for label, candidate in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(
                    MODULE.reconciliation_kustomization_errors(candidate)
                )

    def test_flux_bootstrap_rejects_root_reconciler_transform_or_removal(self):
        canonical = MODULE.EXPECTED_FLUX_SYSTEM_KUSTOMIZATION
        self.assertEqual(MODULE.flux_system_kustomization_errors(canonical), [])
        mutations = {
            "name prefix": canonical + "namePrefix: bypass-\n",
            "name suffix": canonical + "nameSuffix: -bypass\n",
            "remove sync": canonical.replace("  - gotk-sync.yaml\n", ""),
            "replace sync": canonical.replace(
                "  - gotk-sync.yaml\n", "  - bypass.yaml\n"
            ),
            "patch": canonical + "patches:\n  - path: bypass.yaml\n",
            "component": canonical + "components:\n  - ../bypass\n",
            "generator": canonical + "secretGenerator:\n  - name: bypass\n",
        }
        for label, candidate in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(MODULE.flux_system_kustomization_errors(candidate))

    def test_flux_sync_rejects_root_path_patches_and_postbuild(self):
        canonical = MODULE.EXPECTED_FLUX_SYNC
        self.assertEqual(MODULE.flux_sync_errors(canonical), [])
        mutations = {
            "remove reconciler": canonical.split("---\n", 1)[0],
            "replace path": canonical.replace(
                "  path: ./kubernetes/reconciliation\n",
                "  path: ./kubernetes/bypass\n",
            ),
            "patch": canonical.replace(
                "  prune: true\n",
                "  prune: true\n  patches:\n    - patch: bypass\n",
            ),
            "post build": canonical.replace(
                "  prune: true\n",
                "  prune: true\n  postBuild:\n    substitute:\n      bypass: true\n",
            ),
            "image rewrite": canonical.replace(
                "  prune: true\n",
                "  prune: true\n  images:\n    - name: bypass\n",
            ),
        }
        for label, candidate in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(MODULE.flux_sync_errors(candidate))

    def test_repository_and_renderer_invoke_the_closed_contract(self):
        repository_validator = REPO_ROOT.joinpath(
            "scripts", "validate_repository.py"
        ).read_text(encoding="utf-8")
        renderer = REPO_ROOT.joinpath("scripts", "render-manifests.sh").read_text(
            encoding="utf-8"
        )
        for helper in (
            "signature_policy_action",
            "signature_policy_errors",
            "signature_policy_kustomization_errors",
        ):
            with self.subTest(helper=helper):
                self.assertIn(helper, repository_validator)
        self.assertIn("validate_signature_policy.py\" kustomization", renderer)
        self.assertIn("--inventory staging", renderer)
        self.assertIn("--inventory promoted", renderer)
        self.assertIn('any_website_active" == \'true\'', renderer)
        self.assertIn(
            "validate_signature_policy.py\" admission-kustomization", renderer
        )
        for command in (
            "reconciliation-kustomization",
            "flux-system-kustomization",
            "flux-sync",
        ):
            with self.subTest(command=command):
                self.assertIn(
                    "validate_signature_policy.py\" " + command, renderer
                )
        self.assertIn("validate_signature_policy.py\" policy", renderer)
        self.assertLess(
            renderer.index("validate_signature_policy.py\" policy"),
            renderer.index("kustomize build \"${REPO_ROOT}/policies/kyverno\""),
        )
        self.assertIn(
            "input == expected_signature_policy(name, contract, action)",
            REPO_ROOT.joinpath(
                "policies", "conftest", "signature-policy.rego"
            ).read_text(encoding="utf-8"),
        )

    def test_fast_kubernetes_gate_rejects_a_weakened_audit_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            policy_root = root / "policies/kyverno"
            policy_root.mkdir(parents=True)
            admission_root = root / "kubernetes/platform/admission"
            admission_root.mkdir(parents=True)
            admission_root.joinpath("kustomization.yaml").write_text(
                MODULE.EXPECTED_ADMISSION_KUSTOMIZATION,
                encoding="utf-8",
            )
            for relative in (
                "kubernetes/reconciliation/kustomization.yaml",
                "kubernetes/reconciliation/admission.yaml",
                "kubernetes/flux-system/kustomization.yaml",
                "kubernetes/flux-system/gotk-sync.yaml",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(REPO_ROOT.joinpath(relative).read_bytes())
            policy_root.joinpath("kustomization.yaml").write_text(
                REPO_ROOT.joinpath(
                    "policies", "kyverno", "kustomization.yaml"
                ).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            for slug, workflow in MODULE.SIGNATURE_CONTRACTS.items():
                policy_root.joinpath(
                    "require-signed-{}.yaml".format(slug)
                ).write_text(
                    MODULE.expected_policy_body(slug, workflow, "Audit"),
                    encoding="utf-8",
                )
            self.assertEqual(
                REPOSITORY_MODULE.signature_policy_source_errors(
                    root, ("staging",)
                ),
                [],
            )
            target = policy_root / "require-signed-naranjo-online.yaml"
            target.write_text(
                target.read_text(encoding="utf-8").replace(
                    "          required: true\n",
                    "          required: false\n",
                    1,
                ),
                encoding="utf-8",
            )
            expected = "naranjo.online signature admission policy is non-canonical"
            self.assertIn(
                expected,
                REPOSITORY_MODULE.signature_policy_source_errors(
                    root, ("staging",)
                ),
            )
            self.assertIn(expected, REPOSITORY_MODULE.check_kubernetes(root))

            target.write_text(
                self.canonical(),
                encoding="utf-8",
            )
            admission_root.joinpath("kustomization.yaml").write_text(
                MODULE.EXPECTED_ADMISSION_KUSTOMIZATION
                + "namePrefix: bypass-\n",
                encoding="utf-8",
            )
            self.assertIn(
                "admission parent Kustomization is non-canonical",
                REPOSITORY_MODULE.check_kubernetes(root),
            )

    @unittest.skipUnless(shutil.which("conftest"), "conftest is required")
    def test_render_policy_rejects_each_nested_bypass(self):
        """OPA object equality is the post-Kustomize counterpart to source grammar."""

        mutations = (
            ("          required: true\n", "          required: false\n"),
            (
                "                    issuer: https://token.actions.githubusercontent.com\n",
                "                    issuer: https://accounts.example.invalid\n",
            ),
            (
                "            - type: https://slsa.dev/provenance/v1\n",
                "            - type: https://example.invalid/provenance\n",
            ),
            (
                '                    - key: "{{ buildDefinition.buildType }}"\n',
                '                    - key: "{{ builder.id }}"\n',
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.yaml"
            for slug, workflow in MODULE.SIGNATURE_CONTRACTS.items():
                for action in MODULE.ALLOWED_ACTIONS:
                    with self.subTest(slug=slug, action=action, canonical=True):
                        path.write_text(
                            MODULE.expected_policy_body(slug, workflow, action),
                            encoding="utf-8",
                        )
                        accepted = subprocess.run(
                            [
                                shutil.which("conftest"),
                                "test",
                                "--policy",
                                str(REPO_ROOT / "policies/conftest"),
                                str(path),
                            ],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        self.assertEqual(
                            accepted.returncode,
                            0,
                            accepted.stdout + accepted.stderr,
                        )
            for old, new in mutations:
                with self.subTest(old=old):
                    path.write_text(
                        self.canonical().replace(old, new, 1), encoding="utf-8"
                    )
                    result = subprocess.run(
                        [
                            shutil.which("conftest"),
                            "test",
                            "--policy",
                            str(REPO_ROOT / "policies/conftest"),
                            str(path),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("non-canonical verification contract", result.stdout)


if __name__ == "__main__":
    unittest.main()
