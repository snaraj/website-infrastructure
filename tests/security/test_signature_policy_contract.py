"""Prove immutable Flux chart verification cannot be weakened or bypassed."""

import json
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
ACQUISITION_EXTRAS = {
    "naranjo-online": {
        "chartConfigDigest": "sha256:a6ad3989ad56742d2ee65eb370823fd16a4dced4c12df978b3ed8d75e6d5eee1",
        "chartLayerDigest": "sha256:08477ad37eb7a9c4d0f46b32627e302ad7a8a6df2f9c22b0c98d06d6208b031a",
        "workloadImage": "ghcr.io/snaraj/naranjo-online:v0.1.67@sha256:0bc97e1a2b87acf21b3dcc6ce8b3c0dd1b15bbd205a69cc5ec0dae2f1cdb7504",
        "arm64Digest": "sha256:5169b6c1386a6f2327e8c7660c084742dead700efa4e588d525a4f69da1e830e",
        "matchingChartLayerCount": 1,
        "release": {
            "assetDigest": "sha256:6b00e34f55f17468c4ce8cd9848a7347fe7e43a8ad46fd9af7f7c48bf504cfab",
            "sourceSha": "12eca60169238c14e429ff95f21e6141d850522d",
        },
    },
    "lidersea-com": {
        "chartConfigDigest": "sha256:bfeeb2bb371448f552e52ebdc1a0576f5f016e6421286315b4220ba8fb0a9c53",
        "chartLayerDigest": "sha256:578296a596d8835a0e9185e46d6b2ac111ff19c181890e83b44d2caec0b4e517",
        "workloadImage": "ghcr.io/snaraj/lidersea-com:v0.1.40@sha256:cf8dfc93c863296c7de42ec92850a68ab173417d87498f315fafaec9864484c0",
        "arm64Digest": "sha256:694663936ee1061df4a74c19d6f3b5caa22892225dc776587e83721b7488840d",
        "matchingChartLayerCount": 1,
        "release": {
            "assetDigest": "sha256:c6d3571e10fda52ea9472e8f328f97892408dcaccbb237aa40d7b2d33a5eb771",
            "sourceSha": "54790ce20cbe032bedcf12432001b754615b2f56",
        },
    },
}


def write_chart_sources(root):
    """Copy the two reviewed immutable chart-source contracts."""

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
    from exactly one site's publisher, run at that repository's protected
    `main` branch.
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
                self.assertTrue(subject.endswith("@refs/heads/main$"))
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
            # Re-pointed 2026-08-22 with the identity itself (ADR 0016
            # amendment): the trusted ref moved from a stable version tag to
            # protected `main`, so the mutation that must stay dead moved with
            # it. A tag ref is now the untrusted side, because tag creation in
            # the site repositories is unrestricted while `main` is gated with
            # no bypass actors. The anti-widening property is unchanged: this
            # deny row and the two below still prove the contract rejects the
            # sibling ref family and every unanchored variant.
            "tag ref accepted": canonical.replace(
                "@refs/heads/main$", "@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$"
            ),
            "branch ref family widened": canonical.replace(
                "@refs/heads/main$", "@refs/heads/.*$"
            ),
            "trusted ref unanchored": canonical.replace(
                "@refs/heads/main$", "@refs/heads/main"
            ),
            "subject unanchored": canonical.replace(
                "subject: ^https://github", "subject: https://github"
            ),
            "immutable digest changed": canonical.replace(
                MODULE.CHART_RELEASES["naranjo-online"]["digest"],
                "sha256:" + "f" * 64,
            ),
            "pinned to a mutable tag": canonical.replace(
                "    digest: "
                + MODULE.CHART_RELEASES["naranjo-online"]["digest"]
                + "\n",
                "    tag: latest\n",
            ),
            "ambiguous tag plus digest": canonical.replace(
                "  ref:\n",
                "  ref:\n    tag: 0.1.54\n",
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

    def test_exact_digest_pair_is_bound_to_the_repository_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_chart_sources(Path(directory).resolve())
            self.assertEqual(
                REPOSITORY_MODULE.chart_source_contract_errors(root), []
            )
            for slug in MODULE.CHART_REPOSITORIES:
                tag, digest = MODULE.chart_source_release(slug)
                with self.subTest(slug=slug):
                    self.assertIn(
                        'platform.snaraj.dev/chart-release: "{}"'.format(tag),
                        self.canonical(slug),
                    )
                    self.assertIn("    digest: {}\n".format(digest), self.canonical(slug))
            missing = root / "kubernetes/websites/naranjo-online/source.yaml"
            missing.unlink()
            self.assertIn(
                "naranjo-online chart source is missing or symbolic",
                REPOSITORY_MODULE.chart_source_contract_errors(root),
            )

    def test_reviewed_tag_digest_pairs_are_exact_and_mutations_fail(self):
        expected = {
            "naranjo-online": (
                "0.1.67",
                "sha256:b994ee431bd35c76d3fa49f292b3452b68006e3c8530095a2fc6cc14f43fa6f4",
            ),
            "lidersea-com": (
                "0.1.40",
                "sha256:004eaecfcc3dbbe2693e4c400be3dbf755a7972d40b7a5b5755b64e10afb354b",
            ),
        }
        for slug, reviewed in expected.items():
            with self.subTest(slug=slug):
                self.assertEqual(MODULE.chart_source_release(slug), reviewed)
                canonical = self.canonical(slug)
                for label, mutation in {
                    "older audit tag": canonical.replace(
                        'chart-release: "{}"'.format(reviewed[0]),
                        'chart-release: "0.1.1"',
                    ),
                    "zero audit tag": canonical.replace(
                        'chart-release: "{}"'.format(reviewed[0]),
                        'chart-release: "0.0.0"',
                    ),
                    "different digest": canonical.replace(
                        reviewed[1], "sha256:" + "f" * 64
                    ),
                    "mutable selector": canonical.replace(
                        "    digest: {}\n".format(reviewed[1]),
                        "    semver: \">=0.1.0 <1.0.0\"\n",
                    ),
                }.items():
                    with self.subTest(slug=slug, mutation=label):
                        self.assertNotEqual(mutation, canonical)
                        self.assertTrue(MODULE.chart_source_errors(mutation, slug))

    def test_zero_release_tag_is_not_a_valid_reviewed_pair(self):
        saved = MODULE.CHART_RELEASES["naranjo-online"]["tag"]
        MODULE.CHART_RELEASES["naranjo-online"]["tag"] = "0.0.0"
        try:
            with self.assertRaises(ValueError):
                MODULE.chart_source_release("naranjo-online")
        finally:
            MODULE.CHART_RELEASES["naranjo-online"]["tag"] = saved

    def test_acquisition_receipt_matches_every_reviewed_identity_tuple(self):
        receipt = json.loads(
            REPO_ROOT.joinpath(
                "docs", "assurance", "195-chart-acquisition-receipt.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["schema"], "dev.snaraj.chart-acquisition-receipt/v2")
        self.assertEqual(receipt["tools"], {"cosign": "3.1.3", "oras": "1.3.3"})
        self.assertEqual(receipt["chartLayerMediaType"], MODULE.CHART_LAYER_MEDIA_TYPE)
        expected = {}
        for slug in MODULE.CHART_REPOSITORIES:
            tag, manifest_digest = MODULE.chart_source_release(slug)
            expected[slug] = {
                **ACQUISITION_EXTRAS[slug],
                "chart": {"appVersion": tag, "name": slug, "version": tag},
                "chartRepository": MODULE.CHART_REPOSITORIES[slug].removeprefix(
                    "oci://"
                ),
                "chartTag": tag,
                "manifestDigest": manifest_digest,
                "signer": {
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": (
                        "https://github.com/snaraj/"
                        + MODULE.SIGNATURE_REPOSITORIES[slug]
                        + "/.github/workflows/release-publisher.yml@refs/heads/main"
                    ),
                },
            }
        self.assertEqual(receipt["records"], expected)

    @unittest.skipUnless(CONFTEST, "conftest is required")
    def test_conftest_rejects_mutable_or_changed_chart_selectors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.yaml"
            for slug in MODULE.CHART_REPOSITORIES:
                canonical = self.canonical(slug)
                _tag, digest = MODULE.chart_source_release(slug)
                for label, mutation in {
                    "changed digest": canonical.replace(digest, "sha256:" + "f" * 64),
                    "tag selector": canonical.replace(
                        "    digest: {}\n".format(digest), "    tag: latest\n"
                    ),
                    "ambiguous selector": canonical.replace(
                        "  ref:\n", "  ref:\n    tag: latest\n"
                    ),
                }.items():
                    with self.subTest(slug=slug, mutation=label):
                        self.assertNotEqual(mutation, canonical)
                        path.write_text(mutation, encoding="utf-8")
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
                        self.assertIn(
                            "exact reviewed immutable chart digest", result.stdout
                        )

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


class FluxTopologyContractTests(unittest.TestCase):
    """Keep signature verification inside the exact direct-site topology."""

    def test_retired_aggregate_validator_and_renderer_entrypoint_are_absent(self):
        self.assertFalse(hasattr(MODULE, "EXPECTED_RECONCILIATION_KUSTOMIZATION"))
        self.assertFalse(hasattr(MODULE, "reconciliation_kustomization_errors"))
        renderer = REPO_ROOT.joinpath("scripts", "render-manifests.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("reconciliation-kustomization", renderer)

    def test_flux_bootstrap_rejects_root_reconciler_transform_or_removal(self):
        canonical = MODULE.EXPECTED_FLUX_SYSTEM_KUSTOMIZATION
        self.assertEqual(MODULE.flux_system_kustomization_errors(canonical), [])
        mutations = {
            "name prefix": canonical + "namePrefix: bypass-\n",
            "name suffix": canonical + "nameSuffix: -bypass\n",
            "add sync template": canonical + "  - gotk-sync.yaml.in\n",
            "add bypass": canonical + "  - bypass.yaml\n",
            "patch": canonical + "patches:\n  - path: bypass.yaml\n",
            "component": canonical + "components:\n  - ../bypass\n",
            "generator": canonical + "secretGenerator:\n  - name: bypass\n",
        }
        for label, candidate in mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(candidate, canonical, "mutation changed nothing")
                self.assertTrue(MODULE.flux_system_kustomization_errors(candidate))

    def test_flux_sync_rejects_every_direct_site_topology_escape(self):
        canonical = MODULE.EXPECTED_FLUX_SYNC
        self.assertEqual(MODULE.flux_sync_errors(canonical), [])
        mutations = {
            "missing site reconciler": canonical.replace(
                "---\napiVersion: kustomize.toolkit.fluxcd.io/v1\n"
                "kind: Kustomization\nmetadata:\n"
                "  name: lidersea-com-reconciler\n",
                "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n"
                "  name: removed-lidersea-reconciler\n",
            ),
            "duplicate site reconciler": canonical
            + "---\n"
            + canonical.split("\n---\n", 2)[1]
            + "\n",
            "wrong path": canonical.replace(
                "  path: ./kubernetes/websites/naranjo-online\n",
                "  path: ./kubernetes/websites/lidersea-com\n",
                1,
            ),
            "wrong service account": canonical.replace(
                "  serviceAccountName: naranjo-online-reconciler\n",
                "  serviceAccountName: default\n",
                1,
            ),
            "pruning": canonical.replace("  prune: false\n", "  prune: true\n", 1),
            "deletion": canonical.replace(
                "  deletionPolicy: Orphan\n", "  deletionPolicy: Delete\n", 1
            ),
            "wrong source sentinel": canonical.replace(
                "  sourceRef: BOOTSTRAP_RENDERS_VERIFIED_SOURCE\n",
                "  sourceRef: UNREVIEWED_SOURCE\n",
                1,
            ),
            "dependency": canonical.replace(
                "spec:\n  deletionPolicy: Orphan\n",
                "spec:\n  dependsOn:\n"
                "    - name: rogue-prerequisite\n"
                "  deletionPolicy: Orphan\n",
                1,
            ),
            "wait disabled": canonical.replace("  wait: true\n", "  wait: false\n", 1),
            "third reconciler": canonical
            + "---\napiVersion: kustomize.toolkit.fluxcd.io/v1\n"
            "kind: Kustomization\nmetadata:\n  name: rogue-third-reconciler\n",
            "post build": canonical.replace(
                "  timeout: 5m0s\n",
                "  postBuild:\n    substitute:\n      bypass: true\n"
                "  timeout: 5m0s\n",
                1,
            ),
        }
        for label, candidate in mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(candidate, canonical, "mutation changed nothing")
                self.assertTrue(MODULE.flux_sync_errors(candidate))


if __name__ == "__main__":
    unittest.main()
