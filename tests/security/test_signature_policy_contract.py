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
        "chartConfigDigest": "sha256:34336fc8887ca9d4e540674d85f726d830974cb8f909f5202b9bd58a7f85a609",
        "chartLayerDigest": "sha256:56d37664cfedcddafcc9bd440b69e27b1f386012b9fe55868dd7d0e8d773a494",
        "workloadImage": "ghcr.io/snaraj/naranjo-online:v0.1.54@sha256:8f3eeac4caa0bbc8c88f1e9725e9eeb7e074ece3f7c53a77ada52fea28667c78",
        "arm64Digest": "sha256:3a4477a4d983487e2b9d0aee8b556502d9db3fc56b72d0bc111eb83bb71fc5c3",
        "matchingChartLayerCount": 1,
        "release": {
            "assetDigest": "sha256:2568aca870eff2495d217afbdd933389d2236552c704bb83b321201db7081599",
            "sourceSha": "0438570c8f0ccb40ceb0869b86cb461823c8c447",
        },
    },
    "lidersea-com": {
        "chartConfigDigest": "sha256:cbcc79cb9b45df8312038bee110559cf8f79588e6cf2000c7b5a1b7972afef0c",
        "chartLayerDigest": "sha256:56a91426551dcf1e3718b37b4919d2db940199ad50e496b6e57ba385388e058c",
        "workloadImage": "ghcr.io/snaraj/lidersea-com:v0.1.37@sha256:22673a01a892da2b644369ee3c2d0339c13ef8eddc1d3423411ce90bbe25d8b1",
        "arm64Digest": "sha256:c58f87669482096362f7a4db307403f1bcee9859c643a24f23d627c08a434db4",
        "matchingChartLayerCount": 1,
        "release": {
            "assetDigest": "sha256:cc1e2086d2840dcfdca8f5024234d13a92afba0b21bf9cdfbd1389dc23dbc42e",
            "sourceSha": "8115ec9c277af14892b41d1f712f81fe4aab16d4",
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
                "0.1.54",
                "sha256:7223dd78f308c1e211da71f6e062195724aaedc47962b0a04907eeb0baf2d7bb",
            ),
            "lidersea-com": (
                "0.1.37",
                "sha256:05ab03a6e7520ea6768e4efc3750c83f8f7bc827cac3289bf9ee1326c873c8fc",
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
