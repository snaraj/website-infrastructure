"""Prove signature admission cannot be satisfied by comments or weak YAML."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import load_script, required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
CONFTEST = shutil.which("conftest")
MODULE = load_script("validate_signature_policy.py")
REPOSITORY_MODULE = load_script(
    "validate_repository.py", module_name="signature_validate_repository"
)


def write_chart_sources(root, *, graduated=False):
    """Copy the reviewed per-site chart sources and graduation policy.

    ``graduated`` writes the ``yes`` gates so a test can prove that the
    SemVer-range/graduation binding is genuinely two-sided rather than a
    constant that happens to pass.
    """

    gate = "yes" if graduated else "no"
    root.joinpath("release-policy.env").write_text(
        "NARANJO_ONLINE_PRODUCTION_GRADUATED={}\n"
        "LIDERSEA_COM_PRODUCTION_GRADUATED={}\n".format(gate, gate),
        encoding="utf-8",
    )
    for slug in MODULE.CHART_REPOSITORIES:
        destination = root / "kubernetes" / "websites" / slug / "source.yaml"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(
            REPO_ROOT.joinpath("kubernetes", "websites", slug, "source.yaml")
            .read_bytes()
        )
    return root


class ChartSourceContractTests(unittest.TestCase):
    """Pin the reconcile-time half of each site's release identity tuple.

    These tests exercise the committed OCIRepository contract and the
    validator that enforces it. They do NOT observe a Flux controller: no
    source-controller runs here, no registry is contacted, and no signature is
    actually verified. What they prove is that the desired state this
    repository publishes cannot silently stop demanding a cosign signature
    from exactly one site's tag-triggered publisher.
    """

    def canonical(self, slug="naranjo-online"):
        return MODULE.expected_chart_source_body(slug)

    def test_committed_chart_sources_match_their_closed_contract(self):
        for slug in MODULE.CHART_REPOSITORIES:
            with self.subTest(slug=slug):
                text = REPO_ROOT.joinpath(
                    "kubernetes", "websites", slug, "source.yaml"
                ).read_text(encoding="utf-8")
                self.assertEqual(MODULE.chart_source_errors(text, slug), [])

    def test_every_site_tuple_binds_only_its_own_publisher(self):
        subjects = {
            slug: MODULE.chart_source_certificate_subject(slug)
            for slug in MODULE.CHART_REPOSITORIES
        }
        self.assertEqual(len(set(subjects.values())), len(subjects))
        for slug, subject in subjects.items():
            with self.subTest(slug=slug):
                self.assertTrue(subject.startswith("^https://github\\.com/snaraj/"))
                self.assertTrue(subject.endswith("@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$"))
                self.assertIn("/.github/workflows/".replace(".", "\\."), subject)
                for other in subjects:
                    if other != slug:
                        self.assertNotIn(
                            other.replace("-", "."), subject.replace("\\", "")
                        )

    def test_cross_site_substitution_is_rejected_in_both_directions(self):
        for slug in MODULE.CHART_REPOSITORIES:
            for other in MODULE.CHART_REPOSITORIES:
                if other == slug:
                    continue
                with self.subTest(slug=slug, other=other):
                    self.assertTrue(
                        MODULE.chart_source_errors(self.canonical(other), slug)
                    )

    def test_weakened_chart_verification_is_rejected(self):
        canonical = self.canonical()
        other_subject = MODULE.chart_source_certificate_subject("lidersea-com")
        mutations = {
            "verification block removed": canonical.replace(
                "  verify:\n"
                "    matchOIDCIdentity:\n"
                "      - issuer: {}\n"
                "        subject: {}\n"
                "    provider: cosign\n".format(
                    MODULE.CHART_OIDC_ISSUER_PATTERN,
                    MODULE.chart_source_certificate_subject("naranjo-online"),
                ),
                "",
            ),
            "provider swapped": canonical.replace(
                "    provider: cosign\n", "    provider: notation\n"
            ),
            "sibling site subject": canonical.replace(
                MODULE.chart_source_certificate_subject("naranjo-online"),
                other_subject,
            ),
            "wrong workflow path": canonical.replace(
                "release-publisher\\.yml", "publish\\.yml"
            ),
            "wrong issuer": canonical.replace(
                MODULE.CHART_OIDC_ISSUER_PATTERN,
                "^https://accounts\\.example\\.invalid$",
            ),
            "branch ref accepted": canonical.replace(
                "@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$", "@refs/heads/main$"
            ),
            "subject unanchored": canonical.replace(
                "subject: ^https://github", "subject: https://github"
            ),
            "semver range widened": canonical.replace(
                'semver: ">=0.1.9 <1.0.0"', 'semver: ">=0.0.0 <2.0.0"'
            ),
            "pinned to a mutable tag": canonical.replace(
                '    semver: ">=0.1.9 <1.0.0"\n', "    tag: latest\n"
            ),
            "registry path swapped": canonical.replace(
                "oci://ghcr.io/snaraj/charts/naranjo-online",
                "oci://ghcr.io/snaraj/charts/lidersea-com",
            ),
            "registry credential added": canonical.replace(
                "  timeout: 60s\n", "  secretRef:\n    name: ghcr-pull\n  timeout: 60s\n"
            ),
            "layer selector widened": canonical.replace(
                "    mediaType: " + MODULE.CHART_LAYER_MEDIA_TYPE + "\n", ""
            ),
        }
        for label, candidate in mutations.items():
            with self.subTest(mutation=label):
                self.assertNotEqual(candidate, canonical, "mutation changed nothing")
                self.assertTrue(
                    MODULE.chart_source_errors(candidate, "naranjo-online"),
                    "mutation was accepted: " + label,
                )

    def test_leading_comment_block_is_the_only_tolerated_prose(self):
        canonical = self.canonical()
        self.assertEqual(
            MODULE.chart_source_errors(
                "# rationale line one\n# rationale line two\n" + canonical,
                "naranjo-online",
            ),
            [],
        )
        # A comment INSIDE the body could hide a commented-out control or
        # visually detach a field from its section, so it is not tolerated.
        self.assertTrue(
            MODULE.chart_source_errors(
                canonical.replace(
                    "  verify:\n", "  # verification below\n  verify:\n"
                ),
                "naranjo-online",
            )
        )

    def test_semver_range_is_bound_to_the_tracked_graduation_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_chart_sources(Path(directory).resolve())
            self.assertEqual(
                REPOSITORY_MODULE.chart_source_contract_errors(root), []
            )
            for slug in MODULE.CHART_REPOSITORIES:
                lower, upper = MODULE.chart_source_semver_bounds(slug)
                with self.subTest(slug=slug):
                    self.assertLess(lower, upper)
                    self.assertEqual(
                        upper,
                        (1, 0, 0),
                        "an ungraduated site must not admit major 1 or later",
                    )
            missing = root / "kubernetes/websites/naranjo-online/source.yaml"
            missing.unlink()
            self.assertIn(
                "naranjo-online chart source is missing or symbolic",
                REPOSITORY_MODULE.chart_source_contract_errors(root),
            )

    def test_ungrammatical_semver_range_has_no_parse(self):
        for candidate in (
            ">=0.1.9",
            ">0.1.9 <1.0.0",
            ">=0.1.9 <=1.0.0",
            ">=0.1.9 <1.2.0",
            ">=0.1.9-rc1 <1.0.0",
            ">=1.0.0 <1.0.0",
            "*",
            "",
        ):
            with self.subTest(candidate=candidate):
                saved = MODULE.CHART_SEMVER_RANGES["naranjo-online"]
                MODULE.CHART_SEMVER_RANGES["naranjo-online"] = candidate
                try:
                    with self.assertRaises(ValueError):
                        MODULE.chart_source_semver_bounds("naranjo-online")
                finally:
                    MODULE.CHART_SEMVER_RANGES["naranjo-online"] = saved

    def test_renderer_and_repository_validator_both_run_the_contract(self):
        renderer = REPO_ROOT.joinpath("scripts", "render-manifests.sh").read_text(
            encoding="utf-8"
        )
        repository_validator = REPO_ROOT.joinpath(
            "scripts", "validate_repository.py"
        ).read_text(encoding="utf-8")
        self.assertIn('validate_signature_policy.py" chart-source', renderer)
        self.assertIn("chart_source_errors", repository_validator)
        self.assertIn("chart_source_contract_errors(root)", repository_validator)


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

    def test_checked_in_policies_are_the_canonical_enforce_variants(self):
        for slug, workflow in MODULE.SIGNATURE_CONTRACTS.items():
            with self.subTest(slug=slug):
                text = REPO_ROOT.joinpath(
                    "policies", "kyverno", "require-signed-{}.yaml".format(slug)
                ).read_text(encoding="utf-8")
                self.assertEqual(
                    MODULE.signature_policy_errors(text, slug, workflow), []
                )
                self.assertEqual(
                    MODULE.signature_policy_action(text, slug, workflow), "Enforce"
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
        policy_call = renderer[renderer.index("validate_signature_policy.py\" policy"):]
        policy_call = policy_call[: policy_call.index("done")]
        self.assertIn("--action Enforce", policy_call)
        self.assertNotIn("--action Audit", policy_call)
        self.assertLess(
            renderer.index("validate_signature_policy.py\" policy"),
            renderer.index("kustomize build \"${REPO_ROOT}/policies/kyverno\""),
        )
        signature_rego = REPO_ROOT.joinpath(
            "policies", "conftest", "signature-policy.rego"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "input == expected_signature_policy(name, contract, action, failure_policy)",
            signature_rego,
        )
        # The webhook failure policy is a parameter of the closed contract, not
        # an escape from it: object equality still pins every other byte, and
        # the parameter's domain is exactly two values. `Ignore` exists for the
        # report-only install stage, where a fail-closed webhook would refuse
        # Pod creation in the site namespaces whenever Kyverno was unreachable.
        self.assertIn(
            'signature_policy_failure_policies := {"Fail", "Ignore"}', signature_rego
        )
        self.assertIn("failure_policy in signature_policy_failure_policies", signature_rego)

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
            # The chart sources and the graduation policy are part of the same
            # pass: the image-admission identity and the chart-reconcile
            # identity are two ends of one tuple and are validated together.
            write_chart_sources(root)
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

    @unittest.skipUnless(CONFTEST, "conftest is required")
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
                                required_tool(CONFTEST, "conftest"),
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
                            required_tool(CONFTEST, "conftest"),
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
