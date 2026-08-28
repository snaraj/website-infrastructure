"""Focused source contract for the bootstrap-owned #189 release selector."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOUNDARY = ROOT / "bootstrap/flux/release-selector"
SOURCE_REF_KINDS = frozenset(
    ("ExternalArtifact", "HelmChart", "HelmRelease", "Kustomization")
)
SOURCE_REF_GROUPS = {
    "ExternalArtifact": "source.toolkit.fluxcd.io/",
    "HelmChart": "source.toolkit.fluxcd.io/",
    "HelmRelease": "helm.toolkit.fluxcd.io/",
    "Kustomization": "kustomize.toolkit.fluxcd.io/",
}
SIMPLE_YAML_SCALAR = re.compile(r"[A-Za-z0-9_.:/-]+\Z")


def direct_scalars(lines: list[str], start: int, parent_indent: int) -> dict[str, str]:
    result = {}
    for line in lines[start + 1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= parent_indent:
            break
        if indent != parent_indent + 2:
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*):[ ]+([^# ]+)\s*", stripped)
        if match is not None:
            key, value = match.groups()
            if key in result or SIMPLE_YAML_SCALAR.fullmatch(value) is None:
                raise ValueError("sourceRef uses an ambiguous YAML scalar")
            result[key] = value
    return result


def flux_system_consumers(path: Path, text: str) -> list[tuple[str, ...]]:
    consumers = []
    for document in re.split(r"(?m)^---\s*$", text):
        lines = document.splitlines()
        kind = next(
            (line.removeprefix("kind: ") for line in lines if line.startswith("kind: ")),
            "",
        )
        api_version = next(
            (
                line.removeprefix("apiVersion: ")
                for line in lines if line.startswith("apiVersion: ")
            ),
            "",
        )
        if (
            kind not in SOURCE_REF_KINDS
            or not api_version.startswith(SOURCE_REF_GROUPS[kind])
        ):
            continue
        metadata_index = next(
            (index for index, line in enumerate(lines) if line == "metadata:"),
            None,
        )
        if metadata_index is None:
            raise ValueError("Flux source consumer has no metadata")
        metadata = direct_scalars(lines, metadata_index, 0)
        for index, line in enumerate(lines):
            match = re.fullmatch(r"( +)sourceRef:\s*(.*)", line)
            if match is None:
                continue
            if match.group(2):
                raise ValueError("inline or aliased sourceRef is forbidden")
            reference = direct_scalars(lines, index, len(match.group(1)))
            if not {"kind", "name"}.issubset(reference):
                raise ValueError("sourceRef lacks an exact kind or name")
            if reference["name"] == "flux-system":
                consumers.append((
                    path.as_posix(), kind, metadata.get("namespace", ""),
                    metadata.get("name", ""), reference["kind"], reference["name"],
                    reference.get("namespace", ""),
                ))
    return consumers


def rendered_sync_template() -> tuple[Path, str]:
    path = ROOT / "kubernetes/flux-system/gotk-sync.yaml.in"
    text = path.read_text()
    text = text.replace(
        "  sparseCheckout: BOOTSTRAP_RENDERS_EXACT_TWO_PATHS\n",
        "  sparseCheckout:\n"
        "    - kubernetes/websites/naranjo-online\n"
        "    - kubernetes/websites/lidersea-com\n",
    )
    text = text.replace(
        "  sourceRef: BOOTSTRAP_RENDERS_VERIFIED_SOURCE\n",
        "  sourceRef:\n"
        "    kind: GitRepository\n"
        "    name: flux-system\n",
    )
    return path, text


class PlatformReleaseSelectorContractTests(unittest.TestCase):
    maxDiff = None

    def test_direct_source_topology_is_tagged_narrow_and_non_pruning(self):
        source_path, sync = rendered_sync_template()
        self.assertFalse(source_path.with_suffix("").exists())
        self.assertIn("  ref:\n    tag: v0.1.43\n", sync)
        self.assertNotIn("branch: main", sync)
        documents = sync.rstrip("\n").split("\n---\n")
        self.assertEqual(
            sum("\nkind: GitRepository\n" in "\n" + item for item in documents), 1
        )
        self.assertEqual(
            sum("\nkind: Kustomization\n" in "\n" + item for item in documents), 2
        )
        self.assertEqual(sync.count("  prune: false\n"), 2)
        self.assertEqual(sync.count("  deletionPolicy: Orphan\n"), 2)
        self.assertNotIn("dependsOn:", sync)
        self.assertNotIn("secretRef:", sync)
        self.assertNotIn("serviceAccountName: root-reconciler", sync)
        self.assertNotIn("./kubernetes/reconciliation", sync)
        for site in ("naranjo-online", "lidersea-com"):
            self.assertIn(f"  name: {site}-reconciler\n", sync)
            self.assertIn(f"  path: ./kubernetes/websites/{site}\n", sync)
            self.assertIn(f"  serviceAccountName: {site}-reconciler\n", sync)
            self.assertIn(f"    - kubernetes/websites/{site}\n", sync)
        self.assertFalse(any((ROOT / "kubernetes/reconciliation").glob("*.yaml")))

    def test_dedicated_source_has_only_two_consumers_across_flux_kinds(self):
        self.assertEqual(
            SOURCE_REF_KINDS,
            {"ExternalArtifact", "HelmChart", "HelmRelease", "Kustomization"},
        )
        consumers = []
        for path in sorted((ROOT / "kubernetes").rglob("*.yaml")):
            consumers.extend(
                flux_system_consumers(path.relative_to(ROOT), path.read_text())
            )
        sync_path, sync = rendered_sync_template()
        consumers.extend(flux_system_consumers(sync_path.relative_to(ROOT), sync))
        self.assertEqual(consumers, [
            (
                "kubernetes/flux-system/gotk-sync.yaml.in", "Kustomization",
                "flux-system", "naranjo-online-reconciler", "GitRepository",
                "flux-system", "",
            ),
            (
                "kubernetes/flux-system/gotk-sync.yaml.in", "Kustomization",
                "flux-system", "lidersea-com-reconciler", "GitRepository",
                "flux-system", "",
            ),
        ])
        hostile = """\
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmChart
metadata:
  name: foreign-consumer
  namespace: flux-system
spec:
  sourceRef:
    kind: GitRepository
    name: flux-system
"""
        self.assertEqual(
            flux_system_consumers(Path("hostile-helmchart.yaml"), hostile),
            [(
                "hostile-helmchart.yaml", "HelmChart", "flux-system",
                "foreign-consumer", "GitRepository", "flux-system", "",
            )],
        )

    def test_permanent_rbac_and_native_admission_are_closed(self):
        permanent = (BOUNDARY / "rbac.yaml").read_text()
        self.assertIn("resourceNames: [flux-system]", permanent)
        self.assertIn("verbs: [get, patch]", permanent)
        self.assertIn(
            "resourceNames: [naranjo-online-reconciler, lidersea-com-reconciler]",
            permanent,
        )
        self.assertIn("verbs: [get]", permanent)
        for forbidden in (
            "update",
            "delete",
            "create",
            "impersonate",
            "serviceaccounts/token",
            "secrets",
        ):
            self.assertNotIn(forbidden, permanent)
        policy = json.loads((BOUNDARY / "admission-policy.json").read_text())
        binding = json.loads((BOUNDARY / "admission-binding.json").read_text())
        self.assertEqual(policy["apiVersion"], "admissionregistration.k8s.io/v1")
        self.assertEqual(policy["kind"], "ValidatingAdmissionPolicy")
        self.assertEqual(policy["spec"]["failurePolicy"], "Fail")
        self.assertEqual(binding["kind"], "ValidatingAdmissionPolicyBinding")
        self.assertEqual(binding["spec"]["validationActions"], ["Deny"])
        readme = (BOUNDARY / "README.md").read_text()
        self.assertIn("native ValidatingAdmissionPolicy", readme)
        self.assertIn("exact one-patch", readme)
        self.assertIn("forward tag", readme)
        self.assertNotIn("trusted field-level writer", readme)

    def test_retired_cutover_temporary_assets_are_absent(self):
        forbidden = (
            "admission.yaml",
            "bootstrap-rbac.yaml",
            "cutover-job.yaml.in",
            "cutover-network-policy.yaml.in",
            "source-binding.yaml",
            "source-create-binding.yaml",
            "source-prepare-job.yaml.in",
        )
        for name in forbidden:
            self.assertFalse((BOUNDARY / name).exists(), name)
        self.assertTrue((BOUNDARY / "admission-policy.json").is_file())
        self.assertTrue((BOUNDARY / "admission-binding.json").is_file())
        self.assertFalse((ROOT / "cmd/platform-release-cutover").exists())
        self.assertFalse((ROOT / "internal/releasecutover").exists())

    def test_runtime_is_permanent_credentialless_and_initially_suspended(self):
        runtime = (BOUNDARY / "runtime.yaml.in").read_text()
        self.assertIn("  suspend: true\n", runtime)
        self.assertIn("serviceAccountName: platform-release-selector", runtime)
        self.assertIn("EXPECTED_SELECTOR_IMAGE_DIGEST", runtime)
        self.assertIn("EXPECTED_SELECTOR_BUILD_SHA", runtime)
        self.assertEqual(runtime.count("SELECTOR_IMAGE_DIGEST"), 3)
        for forbidden in (
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "secretKeyRef",
            "imagePullSecrets",
            "hostNetwork: true",
            "privileged: true",
        ):
            self.assertNotIn(forbidden, runtime)

    def test_digest_pinned_production_build_runs_go_tests_in_protected_ci(self):
        dockerfile = (
            ROOT / "cmd/platform-release-selector/Dockerfile"
        ).read_text()
        workflow = (ROOT / ".github/workflows/pull-request.yml").read_text()
        self.assertEqual(
            dockerfile.splitlines()[0],
            "# syntax=docker/dockerfile:1@sha256:"
            "ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32",
        )
        self.assertIn("RUN --network=none go test ./...\n", dockerfile)
        self.assertTrue(
            all(
                line.startswith("RUN --network=none ")
                for line in dockerfile.splitlines()
                if line.startswith("RUN ")
            ),
            "every selector build command must be network-isolated",
        )
        self.assertLess(
            dockerfile.index("RUN --network=none go test ./...\n"),
            dockerfile.index("RUN --network=none CGO_ENABLED=0"),
        )
        self.assertIn(
            'selector_rootfs="$(mktemp -d "${RUNNER_TEMP}/selector-rootfs.XXXXXX")"\n'
            "            docker build --network=none \\\n"
            '            --output "type=local,dest=${selector_rootfs}" \\\n'
            "            --file cmd/platform-release-selector/Dockerfile .",
            workflow,
        )
        trusted_root = (
            ROOT / "cmd/platform-release-selector/trusted_root.json"
        ).read_bytes()
        self.assertEqual(
            hashlib.sha256(trusted_root).hexdigest(),
            "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
        )
        self.assertIn(
            "chmod 0555 /trusted-root/usr /trusted-root/usr/local \\\n"
            "      /trusted-root/usr/local/share /trusted-root/usr/local/share/sigstore",
            dockerfile,
        )
        self.assertIn("COPY --from=trusted-root /trusted-root/ /", dockerfile)
        for expected in (
            'stat --format=\'%a\' "${selector_rootfs}/usr/local/share"',
            'stat --format=\'%a\' "${selector_rootfs}/usr/local/share/sigstore"',
            'stat --format=\'%a\' "${selector_rootfs}/usr/local/share/sigstore/trusted_root.json"',
            "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
        ):
            self.assertIn(expected, workflow)

    def test_zero_asset_v0140_exception_is_one_exact_migration_edge(self):
        publisher = (ROOT / "scripts/ci/publish-platform-release.sh").read_text()
        self.assertIn('test "${BASE_TAG}" = v0.1.40', publisher)
        self.assertIn('test "${TAG}" = v0.1.41', publisher)
        self.assertIn('--base-tag "${BASE_TAG}"', publisher)
        self.assertIn('--target-tag "${TAG}"', publisher)
        self.assertNotIn("--require-ready", publisher)
        zero_asset = publisher.split(
            'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then',
            1,
        )[1].split("\n  else\n", 1)[1].split("\n  fi\n", 1)[0]
        self.assertNotIn("download_identity_asset", zero_asset)
        self.assertNotIn('--identity "${identity_download}"', zero_asset)
        self.assertIn('--main-runs-json "${legacy_main_runs_json}"', zero_asset)
        self.assertIn('--platform-runs-json "${legacy_platform_runs_json}"', zero_asset)

    def test_selector_scan_exceptions_are_exact_package_bound_and_expiring(self):
        expected = {
            "CVE-2026-33818": "pkg:golang/stdlib@v1.26.5",
            "CVE-2026-39821": "pkg:golang/stdlib@v1.26.5",
            "CVE-2026-46600": "pkg:golang/stdlib@v1.26.5",
            "CVE-2026-56853": "pkg:golang/stdlib@v1.26.5",
            "CVE-2026-56858": "pkg:golang/stdlib@v1.26.5",
            "CVE-2026-56859": "pkg:golang/stdlib@v1.26.5",
            "CVE-2026-56860": "pkg:golang/stdlib@v1.26.5",
            "CVE-2026-56862": "pkg:golang/stdlib@v1.26.5",
            "CVE-2026-56864": "pkg:golang/golang.org/x/mod@v0.38.0",
            "CVE-2026-56865": "pkg:golang/golang.org/x/mod@v0.38.0",
        }
        policy = json.loads(
            (ROOT / "policies/platform-selector-trivy-ignore.yaml").read_text()
        )
        self.assertEqual(set(policy), {"vulnerabilities"})
        entries = policy["vulnerabilities"]
        self.assertEqual(len(entries), len(expected))
        self.assertEqual({entry["id"] for entry in entries}, set(expected))
        for entry in entries:
            with self.subTest(vulnerability=entry["id"]):
                self.assertEqual(
                    set(entry),
                    {"id", "purls", "paths", "expired_at", "statement"},
                )
                self.assertEqual(entry["purls"], [expected[entry["id"]]])
                self.assertEqual(entry["paths"], ["usr/local/bin/cosign"])
                self.assertEqual(entry["expired_at"], "2026-09-15T00:00:00Z")
                self.assertIn("issue 222", entry["statement"])

        workflow = (ROOT / ".github/workflows/platform-release.yml").read_text()
        ignore = "--ignorefile policies/platform-selector-trivy-ignore.yaml"
        self.assertEqual(workflow.count(ignore), 1)
        selector_scan = workflow.split(
            "- name: Sign and attest the changed selector digest", 1
        )[1].split("- name: Bind the selector digest used by release identity", 1)[0]
        self.assertIn("--image-src remote --platform linux/arm64", selector_scan)
        self.assertIn("--ignore-unfixed=false", selector_scan)
        self.assertIn(ignore, selector_scan)

    def test_issue_211_pvc_grant_remains_namespaced_and_exact(self):
        access = (ROOT / "kubernetes/flux-system/access.yaml").read_text()
        naranjo = access.split(
            "kind: Role\nmetadata:\n  name: helm-reconciler\n  namespace: naranjo-online\n",
            1,
        )[1].split("\n---\n", 1)[0]
        self.assertIn("resources: [persistentvolumeclaims]", naranjo)
        self.assertIn(
            "verbs: [get, list, watch, create, update, patch, delete]", naranjo
        )
        self.assertNotIn("persistentvolumes", naranjo)
        self.assertNotIn("storageclasses", naranjo)
        lidersea = access.split(
            "kind: Role\nmetadata:\n  name: helm-reconciler\n  namespace: lidersea-com\n",
            1,
        )[1].split("\n---\n", 1)[0]
        self.assertNotIn("persistentvolumeclaims", lidersea)

    def test_identity_schema_and_bootstrap_boundary_are_source_only(self):
        schema = json.loads(
            (BOUNDARY / "platform-release-identity.v1.schema.json").read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["release"]["properties"]["asset_count"]["const"],
            2,
        )
        self.assertIn("tree_sha", schema["properties"]["source"]["required"])
        self.assertIn("sites", schema["required"])
        flux_sync = (ROOT / "kubernetes/flux-system/gotk-sync.yaml.in").read_text()
        self.assertIn(
            "sparseCheckout: BOOTSTRAP_RENDERS_EXACT_TWO_PATHS", flux_sync
        )
        sparse_paths = "\n".join(
            line.strip()[2:]
            for line in flux_sync.splitlines()
            if line.strip().startswith("- ")
        )
        for path in (
            "bootstrap/flux/release-selector",
            "cmd/platform-release-selector",
            "internal/releaseselector",
            "kubernetes/flux-system",
            "kubernetes/platform",
            "policies",
        ):
            self.assertNotIn(path, sparse_paths)


if __name__ == "__main__":
    unittest.main()
