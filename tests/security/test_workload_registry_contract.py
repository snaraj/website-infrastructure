"""Hostile closure tests for the sole declared workload registry."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import test_platform_release_identity_asset as identity_asset
from .support import REPO_ROOT, load_script


REGISTRY = load_script("workload_registry.py", module_name="registry_contract")
PLATFORM = identity_asset.MODULE
PROMOTER = load_script("promote_releases.py", module_name="registry_promoter_contract")
SIGNATURE = load_script(
    "validate_signature_policy.py", module_name="registry_signature_contract"
)
REPOSITORY = load_script(
    "validate_repository.py", module_name="registry_repository_contract"
)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def copy_binding_tree(destination: Path) -> Path:
    for relative in (
        REGISTRY.REGISTRY_PATH,
        Path("policies/conftest/kubernetes.rego"),
        Path("kubernetes/websites/lidersea-com/source.yaml"),
        Path("kubernetes/websites/naranjo-online/source.yaml"),
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / relative, target)
    return destination


class WorkloadRegistryClosureTests(unittest.TestCase):
    def test_committed_registry_closes_every_derived_consumer(self) -> None:
        entries = REGISTRY.load_registry(REPO_ROOT)
        manifests = REGISTRY.bind_registry_to_manifests(REPO_ROOT, entries)
        receipt = REPO_ROOT.joinpath(
            "docs/assurance/195-chart-acquisition-receipt.json"
        ).read_bytes()
        identities = PLATFORM._site_identities_from_receipt(
            receipt, (REPO_ROOT / REGISTRY.REGISTRY_PATH).read_bytes()
        )
        selections = PROMOTER.discover_selections(REPO_ROOT)

        self.assertEqual(set(entries), set(manifests))
        self.assertEqual(set(entries), set(identities))
        self.assertEqual(set(entries), set(selections))
        self.assertEqual(
            set(REPOSITORY.IMAGE_RELEASE_SITE_CONTRACTS),
            {
                slug
                for slug, entry in entries.items()
                if entry["deploy"]["shape"] == "site"
            },
        )
        self.assertEqual(REGISTRY.rego_binding_errors(REPO_ROOT, entries), [])
        self.assertEqual(REPOSITORY.workload_registry_contract_errors(REPO_ROOT), [])
        self.assertIn(
            'connector_deployments := {"naranjo-online-tunnel", "lidersea-com-tunnel"}',
            (REPO_ROOT / "policies/conftest/kubernetes.rego").read_text(),
            "a registry edit must not widen the independent Cloudflare credential boundary",
        )
        self.assertEqual(
            SIGNATURE.CHART_REPOSITORIES,
            {
                slug: "oci://" + entry["chartRepository"]
                for slug, entry in entries.items()
            },
        )
        for slug, selection in selections.items():
            self.assertEqual(selection.platforms, tuple(entries[slug]["platforms"]))
            self.assertEqual(
                selection.acquisition_profile,
                entries[slug]["acquisitionProfile"],
            )
            self.assertEqual(selection.deploy_shape, entries[slug]["deploy"]["shape"])
            self.assertEqual(
                selection.target_clusters, tuple(entries[slug]["targetClusters"])
            )

    def test_registry_schema_wildcards_duplicates_and_noncanonical_bytes_refuse(self) -> None:
        exact = REGISTRY.load_registry(REPO_ROOT)
        mutations = {}
        duplicate_key = (REPO_ROOT / REGISTRY.REGISTRY_PATH).read_bytes().replace(
            b'  "schema":',
            b'  "schema": "dev.snaraj.workload-registry/v1",\n  "schema":',
            1,
        )
        mutations["duplicate key"] = duplicate_key
        mutations["noncanonical whitespace"] = (
            REPO_ROOT / REGISTRY.REGISTRY_PATH
        ).read_bytes()[:-1] + b" \n"

        wildcard = copy.deepcopy(exact)
        wildcard["naranjo-online"]["publisher"]["workflowRef"] = (
            "https://github.com/snaraj/naranjo.online/.github/workflows/"
            "release-publisher.yml@refs/heads/*"
        )
        mutations["wildcard publisher"] = REGISTRY.render_registry(wildcard)

        duplicate_platform = copy.deepcopy(exact)
        duplicate_platform["naranjo-online"]["platforms"] *= 2
        mutations["duplicate platform"] = REGISTRY.render_registry(
            duplicate_platform
        )

        foreign_field = copy.deepcopy(exact)
        foreign_field["naranjo-online"]["credential"] = "forbidden"
        mutations["foreign field"] = REGISTRY.render_registry(foreign_field)

        dot_segment = copy.deepcopy(exact)
        dot_segment["naranjo-online"]["sourceRepository"] = "snaraj/.."
        dot_segment["naranjo-online"]["publisher"]["workflowRef"] = (
            "https://github.com/snaraj/../.github/workflows/"
            "release-publisher.yml@refs/heads/main"
        )
        mutations["dot-segment source repository"] = REGISTRY.render_registry(
            dot_segment
        )

        unknown_shape = copy.deepcopy(exact)
        unknown_shape["naranjo-online"]["deploy"] = {"shape": "job"}
        mutations["unknown deploy shape"] = REGISTRY.render_registry(unknown_shape)

        duplicate_domain = copy.deepcopy(exact)
        duplicate_domain["naranjo-online"]["deploy"]["domain"] = "lidersea.com"
        duplicate_domain["naranjo-online"]["sourceRepository"] = (
            "snaraj/lidersea.com"
        )
        duplicate_domain["naranjo-online"]["publisher"]["workflowRef"] = (
            "https://github.com/snaraj/lidersea.com/.github/workflows/"
            "release-publisher.yml@refs/heads/main"
        )
        mutations["duplicate site domain"] = REGISTRY.render_registry(
            duplicate_domain
        )

        privileged_namespace = copy.deepcopy(exact)
        privileged = privileged_namespace.pop("naranjo-online")
        privileged.update(
            chartRepository="ghcr.io/snaraj/charts/flux-system",
            namespace="flux-system",
            slug="flux-system",
            sourceRepository="snaraj/flux-system",
            workloadRepository="ghcr.io/snaraj/flux-system",
        )
        privileged["deploy"] = {"shape": "internal-service"}
        privileged["publisher"]["workflowRef"] = (
            "https://github.com/snaraj/flux-system/.github/workflows/"
            "release-publisher.yml@refs/heads/main"
        )
        privileged_namespace["flux-system"] = privileged
        mutations["privileged namespace"] = REGISTRY.render_registry(
            privileged_namespace
        )

        privileged_path = copy.deepcopy(exact)
        privileged_path["naranjo-online"]["deploy"]["path"] = (
            "./kubernetes/flux-system"
        )
        mutations["caller-selected deploy path"] = REGISTRY.render_registry(
            privileged_path
        )

        colliding_label = copy.deepcopy(exact)
        colliding_label["naranjo-other"] = copy.deepcopy(
            colliding_label["naranjo-online"]
        )
        colliding_label["naranjo-other"]["slug"] = "naranjo-other"
        colliding_label["naranjo-other"]["chartRepository"] = (
            "ghcr.io/snaraj/charts/naranjo-other"
        )
        colliding_label["naranjo-other"]["workloadRepository"] = (
            "ghcr.io/snaraj/naranjo-other"
        )
        colliding_label["naranjo-other"]["deploy"] = {
            "path": "./kubernetes/services/naranjo-other",
            "reconciler": "naranjo-other",
            "shape": "internal-service",
        }
        colliding_label["naranjo-other"]["namespace"] = "naranjo-other"
        mutations["colliding receipt label"] = REGISTRY.render_registry(
            colliding_label
        )

        for label, payload in mutations.items():
            with self.subTest(label=label), self.assertRaises(REGISTRY.RegistryError):
                REGISTRY.parse_registry_bytes(payload)

    def test_manifest_identity_drift_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_binding_tree(Path(temporary))
            source = root / "kubernetes/websites/naranjo-online/source.yaml"
            source.write_text(
                source.read_text().replace(
                    "release-publisher\\.yml@refs/heads/main$",
                    "foreign-publisher\\.yml@refs/heads/main$",
                )
            )
            with self.assertRaisesRegex(REGISTRY.RegistryError, "manifest subjectPattern"):
                REGISTRY.bind_registry_to_manifests(root)

    def test_non_site_workload_needs_no_policy_schema_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_binding_tree(Path(temporary))
            entries = REGISTRY.load_registry(root)
            entry = copy.deepcopy(entries["naranjo-online"])
            entry.update(
                chartRepository="ghcr.io/snaraj/charts/vault",
                namespace="vault",
                slug="vault",
                sourceRepository="snaraj/vault",
                workloadRepository="ghcr.io/snaraj/vault",
            )
            entry["deploy"] = {
                "shape": "internal-service",
            }
            entry["publisher"]["workflowRef"] = (
                "https://github.com/snaraj/vault/.github/workflows/"
                "release-publisher.yml@refs/heads/main"
            )
            entries["vault"] = entry
            (root / REGISTRY.REGISTRY_PATH).write_bytes(
                REGISTRY.render_registry(entries)
            )
            source = root / "kubernetes/services/vault/source.yaml"
            source.parent.mkdir(parents=True)
            canonical = REPO_ROOT.joinpath(
                "kubernetes/websites/naranjo-online/source.yaml"
            ).read_text()
            source.write_text(
                "apiVersion:" + canonical.split("apiVersion:", 1)[1]
                .replace("naranjo-online", "vault")
                .replace(r"naranjo\.online", "vault")
            )

            parsed = REGISTRY.load_registry(root)
            self.assertEqual(set(REGISTRY.bind_registry_to_manifests(root)), set(parsed))
            self.assertEqual(
                REGISTRY.rego_workloads(root, parsed)["vault"]["deploy_shape"],
                "internal-service",
            )
            self.assertIn(
                "!/kubernetes/services/vault/**",
                SIGNATURE.deployment_ignore_lines((entry,)),
            )
            rego = root / "policies/conftest/kubernetes.rego"
            text = rego.read_text()
            start = text.index(REGISTRY.REGO_BEGIN)
            end = text.index(REGISTRY.REGO_END, start) + len(REGISTRY.REGO_END)
            rego.write_text(text[:start] + REGISTRY.render_rego_block(root) + text[end:])
            if conftest := shutil.which("conftest"):
                result = subprocess.run(
                    [conftest, "test", "--no-color", "--policy", rego.parent, source],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

                workload = root / "vault-workload.yaml"
                workload.write_text(
                    """apiVersion: v1
kind: Pod
metadata:
  name: vault
  namespace: vault
spec:
  automountServiceAccountToken: false
  serviceAccountName: foreign
  containers:
    - name: vault
      image: ghcr.io/snaraj/vault:v1.0.0@sha256:{digest}
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
""".format(digest="0" * 64)
                )
                result = subprocess.run(
                    [conftest, "test", "--no-color", "--policy", rego.parent, workload],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "must use only ServiceAccount vault",
                    result.stdout + result.stderr,
                )

    def test_noncanonical_annotated_manifest_cannot_evade_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_binding_tree(Path(temporary))
            source = root / "kubernetes/websites/naranjo-online/source.yaml"
            source.write_text(
                source.read_text().replace(
                    "kind: OCIRepository", 'kind: "OCIRepository"', 1
                )
            )
            with self.assertRaisesRegex(
                REGISTRY.RegistryError, "canonical OCIRepository"
            ):
                REGISTRY.bind_registry_to_manifests(root)

    def test_hardlinked_registry_is_not_a_trust_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "registry-source.json"
            target.write_bytes((REPO_ROOT / REGISTRY.REGISTRY_PATH).read_bytes())
            registry = root / REGISTRY.REGISTRY_PATH
            registry.parent.mkdir(parents=True)
            registry.hardlink_to(target)
            with self.assertRaisesRegex(REGISTRY.RegistryError, "single-link"):
                REGISTRY.load_registry(root)

    def test_registry_path_swap_during_read_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry = root / REGISTRY.REGISTRY_PATH
            registry.parent.mkdir(parents=True)
            shutil.copyfile(REPO_ROOT / REGISTRY.REGISTRY_PATH, registry)
            original_read = REGISTRY.os.read
            swapped = False

            def swap_after_read(descriptor, count):
                nonlocal swapped
                payload = original_read(descriptor, count)
                if payload and not swapped:
                    registry.rename(root / "replaced-registry.json")
                    shutil.copyfile(REPO_ROOT / REGISTRY.REGISTRY_PATH, registry)
                    swapped = True
                return payload

            with mock.patch.object(REGISTRY.os, "read", side_effect=swap_after_read):
                with self.assertRaisesRegex(REGISTRY.RegistryError, "changed while"):
                    REGISTRY.load_registry(root)

    def test_receipt_set_or_identity_drift_is_refused(self) -> None:
        receipt = json.loads(
            REPO_ROOT.joinpath(
                "docs/assurance/195-chart-acquisition-receipt.json"
            ).read_text()
        )
        registry = (REPO_ROOT / REGISTRY.REGISTRY_PATH).read_bytes()
        receipt["records"].pop("lidersea-com")
        with self.assertRaisesRegex(PLATFORM.ContractError, "equal the workload registry"):
            PLATFORM._site_identities_from_receipt(
                json.dumps(receipt, sort_keys=True).encode(), registry
            )

        receipt = json.loads(
            REPO_ROOT.joinpath(
                "docs/assurance/195-chart-acquisition-receipt.json"
            ).read_text()
        )
        receipt["records"]["naranjo-online"]["signer"]["subject"] = (
            "https://github.com/snaraj/foreign/.github/workflows/"
            "release-publisher.yml@refs/heads/main"
        )
        with self.assertRaisesRegex(PLATFORM.ContractError, "identity is invalid"):
            PLATFORM._site_identities_from_receipt(
                json.dumps(receipt, sort_keys=True).encode(), registry
            )

    def test_registry_absence_is_legacy_only_through_its_introduction(self) -> None:
        receipt = REPO_ROOT.joinpath(
            "docs/assurance/195-chart-acquisition-receipt.json"
        ).read_bytes()
        ceiling = "c" * 40
        predecessor = "a" * 40
        successor = "b" * 40

        # A caller cannot opt into the bridge merely by omitting the registry.
        with self.assertRaisesRegex(PLATFORM.ContractError, "migration ceiling"):
            PLATFORM._site_identities_from_receipt(receipt, None)

        def is_ancestor(_repository: Path, ancestor: str, descendant: str) -> bool:
            return descendant == ceiling and ancestor in {predecessor, ceiling}

        with (
            mock.patch.object(
                PLATFORM, "_optional_regular_file_bytes", return_value=None
            ),
            mock.patch.object(PLATFORM, "_file_bytes", return_value=receipt),
            mock.patch.object(
                PLATFORM,
                "_workload_registry_legacy_ceiling",
                return_value=ceiling,
            ),
            mock.patch.object(PLATFORM, "_is_ancestor", side_effect=is_ancestor),
        ):
            for source in (predecessor, ceiling):
                with self.subTest(source=source):
                    identities = PLATFORM._source_site_identities(
                        REPO_ROOT, source
                    )
                    self.assertEqual(
                        set(identities), {"lidersea-com", "naranjo-online"}
                    )
            with self.assertRaisesRegex(
                PLATFORM.ContractError, "migration ceiling"
            ):
                PLATFORM._source_site_identities(REPO_ROOT, successor)

    def test_registry_introduction_derives_one_immutable_ceiling(self) -> None:
        introduction = "d" * 40
        ceiling = "c" * 40
        with (
            mock.patch.object(
                PLATFORM, "_git", side_effect=[introduction + "\n", ceiling]
            ),
            mock.patch.object(
                PLATFORM,
                "_optional_regular_file_bytes",
                side_effect=[b"{}\n", None],
            ),
        ):
            self.assertEqual(
                PLATFORM._workload_registry_legacy_ceiling(REPO_ROOT), ceiling
            )

    def test_rego_projection_drift_is_refused_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_binding_tree(Path(temporary))
            rego = root / "policies/conftest/kubernetes.rego"
            rego.write_text(
                rego.read_text().replace(
                    "oci://ghcr.io/snaraj/charts/lidersea-com",
                    "oci://ghcr.io/snaraj/charts/foreign",
                    1,
                )
            )
            self.assertEqual(
                REGISTRY.rego_binding_errors(root),
                ["kubernetes.rego workload-registry block is not byte-exact"],
            )

    def test_validator_and_promoter_refuse_their_derived_side_drifting(self) -> None:
        slug = "naranjo-online"
        source = REPO_ROOT.joinpath(
            "kubernetes/websites/naranjo-online/source.yaml"
        ).read_text()
        saved_repository = SIGNATURE.CHART_REPOSITORIES[slug]
        SIGNATURE.CHART_REPOSITORIES[slug] = "oci://ghcr.io/snaraj/charts/foreign"
        try:
            self.assertTrue(SIGNATURE.chart_source_errors(source, slug))
        finally:
            SIGNATURE.CHART_REPOSITORIES[slug] = saved_repository

        selection = PROMOTER.discover_selections(REPO_ROOT)[slug]
        selection.acquisition_profile = "foreign-profile"
        with self.assertRaisesRegex(PROMOTER.Refusal, "unknown acquisition profile"):
            PROMOTER.profile_for(selection)

    def test_registry_trust_root_is_owned_and_history_gated(self) -> None:
        codeowners = (REPO_ROOT / ".github/CODEOWNERS").read_text()
        workflow = (REPO_ROOT / ".github/workflows/pull-request.yml").read_text()
        pre_push = (REPO_ROOT / "scripts/pre-push-security.sh").read_text()
        self.assertIn("/policies/ @snaraj", codeowners)
        self.assertIn("Scan immutable pull-request history", workflow)
        self.assertIn("validate_publication_history.py", workflow)
        self.assertIn("validate_publication_history.py", pre_push)


class WorkloadRegistryCapacityTests(unittest.TestCase):
    @staticmethod
    def maximal_entries(count: int) -> dict:
        platforms = [
            "o" * 32 + "/" + "a" * 31 + str(index) for index in range(8)
        ]
        clusters = ["c{}{}".format(index, "z" * 61) for index in range(8)]
        entries = {}
        for index in range(count):
            slug = "w{:02d}".format(index) + "x" * 49
            source = "snaraj/" + "s" * 100
            profile = "release-publisher"
            entries[slug] = {
                "acquisitionProfile": profile,
                "chartRepository": "ghcr.io/snaraj/charts/" + slug,
                "deploy": {
                    "shape": "internal-service",
                },
                "namespace": slug,
                "platforms": platforms,
                "publisher": {
                    "oidcIssuer": REGISTRY.OIDC_ISSUER,
                    "workflowRef": (
                        "https://github.com/snaraj/"
                        + "s" * 100
                        + "/.github/workflows/"
                        + profile
                        + ".yml@refs/heads/main"
                    ),
                },
                "slug": slug,
                "sourceRepository": source,
                "targetClusters": clusters,
                "workloadRepository": "ghcr.io/snaraj/" + slug,
            }
        return entries

    def test_twenty_four_maximal_workloads_fit_identity_and_twenty_five_refuses(self) -> None:
        entries = self.maximal_entries(REGISTRY.MAX_WORKLOADS)
        registry = REGISTRY.render_registry(entries)
        parsed = REGISTRY.parse_registry_bytes(registry)
        self.assertEqual(len(parsed), 24)
        self.assertEqual(len(registry), 52_727)
        self.assertLessEqual(len(registry), REGISTRY.MAX_REGISTRY_BYTES)

        version = "9999999999.9999999999.9999999999"
        records = {}
        for index, (slug, entry) in enumerate(parsed.items()):
            records[slug] = {
                "chart": {"appVersion": version, "name": slug, "version": version},
                "chartConfigDigest": digest("config" + slug),
                "chartLayerDigest": digest("layer" + slug),
                "chartRepository": entry["chartRepository"],
                "chartTag": version,
                "manifestDigest": digest("manifest" + slug),
                "matchingChartLayerCount": 1,
                "platformDigests": {
                    platform: digest("{}:{}".format(slug, platform))
                    for platform in entry["platforms"]
                },
                "release": {
                    "assetDigest": digest("asset" + slug),
                    "sourceSha": hashlib.sha1(slug.encode()).hexdigest(),
                },
                "signer": {
                    "issuer": entry["publisher"]["oidcIssuer"],
                    "subject": entry["publisher"]["workflowRef"],
                },
                "workloadImage": (
                    entry["workloadRepository"]
                    + ":v"
                    + version
                    + "@"
                    + digest("index" + slug)
                ),
            }
        receipt = {
            "capturedDate": "2026-09-01",
            "chartLayerMediaType": (
                "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
            ),
            "records": records,
            "schema": "dev.snaraj.chart-acquisition-receipt/v2",
            "tools": {"cosign": "3.1.3", "oras": "1.3.3"},
        }
        sites = PLATFORM._site_identities_from_receipt(
            json.dumps(receipt, sort_keys=True).encode(), registry
        )
        fixture = identity_asset.PlatformReleaseIdentityAssetTests
        evidence = copy.deepcopy(fixture.evidence())
        evidence["sites"] = sites
        identity = fixture.canonical(evidence)
        self.assertEqual(len(identity), 43_680)
        self.assertLessEqual(len(identity), PLATFORM.MAX_RELEASE_IDENTITY_BYTES)

        with self.assertRaisesRegex(REGISTRY.RegistryError, "between 1 and 24"):
            REGISTRY.parse_registry_bytes(
                REGISTRY.render_registry(self.maximal_entries(25))
            )
        with self.assertRaisesRegex(REGISTRY.RegistryError, "size is invalid"):
            REGISTRY.parse_registry_bytes(b"{" + b"x" * REGISTRY.MAX_REGISTRY_BYTES)

    def test_twenty_four_maximal_targets_keep_ref_fragment_and_title_bounded(self) -> None:
        entries = self.maximal_entries(REGISTRY.MAX_WORKLOADS)
        version = "9999999999.9999999999.9999999999"
        targets = {slug: version for slug in entries}
        branch = PROMOTER.branch_name("a" * 40, 288, targets)
        fragment = PROMOTER.fragment_path(288, targets)
        selections = {
            slug: type("SelectionView", (), {"domain": slug})()
            for slug in targets
        }
        title = PROMOTER.pr_title(selections, targets)

        self.assertLessEqual(len(branch.rsplit("/", 1)[1].encode()), 240)
        self.assertLessEqual(len(fragment.name.encode()), 240)
        self.assertLessEqual(len(title), 240)
        self.assertEqual(
            PROMOTER.parse_branch(branch)[2],
            PROMOTER.promotion_target_fingerprint(targets),
        )


if __name__ == "__main__":
    unittest.main()
