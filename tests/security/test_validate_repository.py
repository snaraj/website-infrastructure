#!/usr/bin/env python3
import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "validate_repository.py"
SPEC = importlib.util.spec_from_file_location("validate_repository", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RepositoryPolicyTests(unittest.TestCase):
    def test_rejects_local_identity_and_opaque_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "docs"
            target.mkdir()
            target.joinpath("private.md").write_text(
                "Local path " + "C:" + "\\Users\\" + "person with person"
                + "@example.com and "
                + ("a1" * 16) + "\n",
                encoding="utf-8",
            )
            errors = MODULE.check_privacy(root)
            self.assertTrue(any("workstation path" in error for error in errors))
            self.assertTrue(any("email address" in error for error in errors))
            self.assertTrue(any("32-hex" in error for error in errors))

    def test_accepts_deliberately_synthetic_privacy_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "tests" / "fixtures"
            target.mkdir(parents=True)
            target.joinpath("synthetic.txt").write_text(
                "admin@example.invalid\n" + ("1" * 32) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.check_privacy(root), [])

    def test_privacy_scans_composite_dotfile_and_extensionless_names(self):
        """Every public text file must sit inside the same privacy boundary."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("terraform.tfvars.example").write_text(
                "path = '" + "C:" + "\\\\Users\\\\person\\\\config'\n",
                encoding="utf-8",
            )
            root.joinpath(".dockerignore").write_text(
                "owner" + "@example.com\n",
                encoding="utf-8",
            )
            root.joinpath("CODEOWNERS").write_text(
                "* reviewer" + "@example.org\n",
                encoding="utf-8",
            )
            errors = MODULE.check_privacy(root)
            self.assertTrue(any("workstation path" in error for error in errors))
            self.assertEqual(
                sum("email address" in error for error in errors),
                2,
            )

    def test_secret_scan_includes_service_and_template_files(self):
        """Deployment text cannot evade secret scanning through its suffix."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("connector.service").write_text(
                "Environment=KEY=AGE-" + "SECRET-KEY-1SYNTHETIC\n",
                encoding="utf-8",
            )
            root.joinpath("helper.tpl").write_text(
                "-----BEGIN " + "PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            errors = MODULE.check_secrets(root)
            self.assertTrue(any("age private identity" in error for error in errors))
            self.assertTrue(any("private key block" in error for error in errors))

    def test_privacy_rejects_host_ips_and_uuid_identifiers(self):
        """Real-looking network and machine identities remain local-only."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("inventory.txt").write_text(
                "host=" + "198.18.0." + "1\n"
                "v6=" + "fd00:" + ":1234\n"
                "machine=" + "123e4567" + "-e89b-12d3-a456-426614174000\n",
                encoding="utf-8",
            )
            errors = MODULE.check_privacy(root)
            self.assertTrue(any("IPv4" in error for error in errors))
            self.assertTrue(any("IPv6" in error for error in errors))
            self.assertTrue(any("UUID" in error for error in errors))

    def test_privacy_accepts_documentation_and_non_host_network_literals(self):
        """Policy CIDRs and standards-reserved examples stay documentable."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("networking.txt").write_text(
                "bind=127.0.0.1 docs=192.0.2.10 v6=2001:db8::10\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.check_privacy(root), [])

    def test_media_gate_rejects_binaries_outside_assets_and_large_ui_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "websites" / "example.invalid" / "media"
            outside.mkdir(parents=True)
            outside.joinpath("source.mp4").write_bytes(b"tiny")
            assets = (
                root / "websites" / "example.invalid" / "frontend" / "src"
                / "assets" / "images"
            )
            assets.mkdir(parents=True)
            # Lower the in-memory policy constant so this boundary test never
            # creates the kind of synthetic large file the repository forbids.
            original_ceiling = MODULE.MAX_UI_ASSET_BYTES
            MODULE.MAX_UI_ASSET_BYTES = 3
            try:
                assets.joinpath("oversized.png").write_bytes(b"tiny")
                errors = MODULE.check_media(root)
            finally:
                MODULE.MAX_UI_ASSET_BYTES = original_ceiling
            self.assertTrue(any("outside the small frontend asset tree" in error for error in errors))
            self.assertTrue(any("exceeds the small-asset ceiling" in error for error in errors))

    def test_media_gate_rejects_persistent_storage_before_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "kubernetes" / "storage"
            target.mkdir(parents=True)
            target.joinpath("pv.yaml").write_text(
                "apiVersion: v1\nkind: PersistentVolume\nspec:\n"
                "  hostPath:\n    path: /invented\n",
                encoding="utf-8",
            )
            errors = MODULE.check_media(root)
            self.assertTrue(any("persistent storage object" in error for error in errors))
            self.assertTrue(any("hostPath volume" in error for error in errors))

    def test_media_gate_scans_the_whole_repository_and_binary_magic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs = root / "docs"
            docs.mkdir()
            docs.joinpath("video.mp4").write_bytes(b"tiny")
            docs.joinpath("renamed.txt").write_bytes(b"\x89PNG\r\n\x1a\nrest")
            original_ceiling = MODULE.MAX_REPOSITORY_FILE_BYTES
            MODULE.MAX_REPOSITORY_FILE_BYTES = 3
            try:
                docs.joinpath("split-part.bin").write_bytes(b"tiny")
                errors = MODULE.check_media(root)
            finally:
                MODULE.MAX_REPOSITORY_FILE_BYTES = original_ceiling
            self.assertTrue(any("media file is outside" in error for error in errors))
            self.assertTrue(any("renamed media content" in error for error in errors))
            self.assertTrue(any("public repository size ceiling" in error for error in errors))

    def test_media_gate_rejects_split_asset_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = (
                root / "websites" / "example.invalid" / "frontend" / "src"
                / "assets" / "images"
            )
            assets.mkdir(parents=True)
            assets.joinpath("one.png").write_bytes(b"1234")
            assets.joinpath("two.png").write_bytes(b"5678")
            original_ceiling = MODULE.MAX_ASSET_TREE_BYTES
            MODULE.MAX_ASSET_TREE_BYTES = 6
            try:
                errors = MODULE.check_media(root)
            finally:
                MODULE.MAX_ASSET_TREE_BYTES = original_ceiling
            self.assertTrue(any("aggregate media ceiling" in error for error in errors))

    def test_media_gate_rejects_split_repository_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs = root / "docs"
            docs.mkdir()
            docs.joinpath("part-one.bin").write_bytes(b"1234")
            docs.joinpath("part-two.bin").write_bytes(b"5678")
            original_ceiling = MODULE.MAX_PUBLIC_REPOSITORY_BYTES
            MODULE.MAX_PUBLIC_REPOSITORY_BYTES = 6
            try:
                errors = MODULE.check_media(root)
            finally:
                MODULE.MAX_PUBLIC_REPOSITORY_BYTES = original_ceiling
            self.assertTrue(any("aggregate byte ceiling" in error for error in errors))

    def test_media_gate_rejects_large_or_binary_kubernetes_data_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "kubernetes" / "site"
            target.mkdir(parents=True)
            target.joinpath("config.yaml").write_text(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: payload\n"
                "binaryData:\n  clip.mp4: " + ("A" * 32) + "\n",
                encoding="utf-8",
            )
            original_ceiling = MODULE.MAX_KUBERNETES_DATA_OBJECT_BYTES
            MODULE.MAX_KUBERNETES_DATA_OBJECT_BYTES = 32
            try:
                errors = MODULE.check_media(root)
            finally:
                MODULE.MAX_KUBERNETES_DATA_OBJECT_BYTES = original_ceiling
            self.assertTrue(any("data object exceeds" in error for error in errors))
            self.assertTrue(any("binaryData is forbidden" in error for error in errors))
            self.assertTrue(any("media-shaped Kubernetes data key" in error for error in errors))

    def test_media_gate_requires_narrow_flux_artifacts_without_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "kubernetes" / "site"
            source.mkdir(parents=True)
            source.joinpath("source.yaml").write_text(
                "apiVersion: source.toolkit.fluxcd.io/v1\n"
                "kind: GitRepository\nmetadata:\n  name: site\n"
                "spec:\n  ignore: |\n    !/**\n",
                encoding="utf-8",
            )
            errors = MODULE.check_media(root)
            self.assertTrue(any(".sourceignore" in error for error in errors))
            self.assertTrue(any("ignore override" in error for error in errors))

    def test_rejects_forbidden_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "apps").mkdir()
            errors = MODULE.check_layout(root)
            self.assertTrue(any("apps" in error for error in errors))

    def test_rejects_plaintext_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "kubernetes" / "site"
            target.mkdir(parents=True)
            (target / "secret.yaml").write_text(
                "apiVersion: v1\nkind: Secret\nstringData:\n  token: nope\n",
                encoding="utf-8",
            )
            errors = MODULE.check_secrets(root)
            self.assertTrue(any("unencrypted Kubernetes Secret" in error for error in errors))

    def test_rejects_mixed_plaintext_sops_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "kubernetes" / "site"
            target.mkdir(parents=True)
            (target / "secret.sops.yaml").write_text(
                """apiVersion: v1
kind: Secret
stringData:
  encrypted: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]
  plaintext: forbidden
sops:
  age:
    - recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp5hcal
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
  mac: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]
""",
                encoding="utf-8",
            )
            errors = MODULE.check_secrets(root)
            self.assertTrue(any("plaintext or malformed" in error for error in errors))

    def test_accepts_structurally_encrypted_sops_secret(self):
        text = """apiVersion: v1
kind: Secret
data:
  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]
sops:
  age:
    - recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp5hcal
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
  mac: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]
"""
        self.assertEqual(MODULE.sops_secret_errors(text), [])

    def test_tunnel_secret_requires_exact_identity_namespace_key_and_recipient(self):
        recipient = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp5hcal"
        valid = """apiVersion: v1
kind: Secret
metadata:
  name: pi-websites-tunnel-token
  namespace: cloudflare-public
type: Opaque
data:
  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]
sops:
  age:
    - recipient: {recipient}
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
  mac: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]
""".format(recipient=recipient)
        self.assertEqual(MODULE.tunnel_secret_errors(valid, recipient), [])
        invalid = valid.replace("namespace: cloudflare-public", "namespace: default").replace(
            "  token: ENC[", "  token: ENC["
            "  extra: plaintext\n  ignored: ENC["
        )
        errors = MODULE.tunnel_secret_errors(invalid, recipient)
        self.assertTrue(any("namespace" in error for error in errors))
        self.assertTrue(any("only the token key" in error for error in errors))

    def test_active_kustomization_resource_ignores_comments(self):
        self.assertFalse(MODULE.active_kustomization_resource(
            "resources:\n  # - tunnel-token.sops.yaml\n", "tunnel-token.sops.yaml"
        ))
        self.assertTrue(MODULE.active_kustomization_resource(
            "resources:\n  - tunnel-token.sops.yaml # encrypted\n", "tunnel-token.sops.yaml"
        ))

    def test_rejects_mutable_image_and_public_service(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "kubernetes" / "site"
            target.mkdir(parents=True)
            (target / "bad.yaml").write_text(
                "image: example.invalid/site:latest\ntype: LoadBalancer\n",
                encoding="utf-8",
            )
            errors = MODULE.check_kubernetes(root)
            self.assertTrue(any("image reference" in error for error in errors))
            self.assertTrue(any("public Service" in error for error in errors))

    def test_generated_flux_components_match_pinned_three_controller_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("versions.env").write_text(
                "FLUX_VERSION=v2.9.3\n"
                "FLUX_SOURCE_CONTROLLER_IMAGE=example.invalid/source:v1@sha256:" + ("1" * 64) + "\n"
                "FLUX_KUSTOMIZE_CONTROLLER_IMAGE=example.invalid/kustomize:v1@sha256:" + ("2" * 64) + "\n"
                "FLUX_HELM_CONTROLLER_IMAGE=example.invalid/helm:v1@sha256:" + ("3" * 64) + "\n",
                encoding="utf-8",
            )
            target = root / "kubernetes" / "flux-system" / "controllers"
            target.mkdir(parents=True)
            images = (
                "example.invalid/source:v1@sha256:" + ("1" * 64),
                "example.invalid/kustomize:v1@sha256:" + ("2" * 64),
                "example.invalid/helm:v1@sha256:" + ("3" * 64),
            )
            manifest = (
                "# Flux Version: v2.9.3\n"
                "# Components: source-controller,kustomize-controller,helm-controller\n"
                + "\n".join("image: " + image for image in images)
                + "\n"
            )
            components = target / "gotk-components.yaml"
            components.write_text(manifest, encoding="utf-8")
            self.assertEqual(MODULE.flux_components_errors(root), [])

            components.write_text(
                manifest.replace(images[0], "example.invalid/source:latest")
                + "kind: Secret\n",
                encoding="utf-8",
            )
            errors = MODULE.flux_components_errors(root)
            self.assertTrue(any("images" in error for error in errors))
            self.assertTrue(any("Secret" in error for error in errors))

    def test_helm_values_image_map_is_not_misread_as_image_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "kubernetes" / "chart"
            target.mkdir(parents=True)
            (target / "values.yaml").write_text(
                "image:\n  repository: example.invalid/site\n  digest: sha256:deadbeef\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.check_kubernetes(root), [])

    def test_rejects_unpinned_action(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / ".github" / "workflows"
            target.mkdir(parents=True)
            (target / "bad.yml").write_text(
                "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v7\n",
                encoding="utf-8",
            )
            errors = MODULE.check_workflows(root)
            self.assertTrue(any("full SHA" in error for error in errors))

    def test_rejects_cloudflare_data_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "infrastructure" / "cloudflare"
            target.mkdir(parents=True)
            (target / "data.tf").write_text(
                'data "cloudflare_zones" "all" {}\n', encoding="utf-8"
            )
            errors = MODULE.check_cloudflare(root)
            self.assertTrue(any("data source is forbidden" in error for error in errors))

    def test_release_gate_requires_reconciled_admission_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            errors = MODULE.signature_admission_install_errors(root)
            self.assertTrue(any(
                "admission reconciliation is not active from the Flux root" in error
                for error in errors
            ))

            reconciliation = root / "kubernetes/reconciliation"
            reconciliation.mkdir(parents=True)
            (reconciliation / "kustomization.yaml").write_text(
                "resources:\n  - admission.yaml\n", encoding="utf-8"
            )
            (reconciliation / "admission.yaml").write_text(
                "path: ./kubernetes/platform/admission\n"
                "serviceAccountName: admission-reconciler\n"
                "wait: true\n",
                encoding="utf-8",
            )
            admission = root / "kubernetes/platform/admission"
            admission.mkdir(parents=True)
            (admission / "kustomization.yaml").write_text(
                "resources:\n"
                "  - kyverno/controllers.yaml\n"
                "  - ../../../policies/kyverno\n",
                encoding="utf-8",
            )
            controllers = admission / "kyverno/controllers.yaml"
            controllers.parent.mkdir()
            controllers.write_text(
                "kind: Deployment\n"
                "app.kubernetes.io/part-of: kyverno\n"
                "---\nkind: Service\n"
                "---\nkind: ValidatingWebhookConfiguration\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.signature_admission_install_errors(root), [])

    def test_activation_gate_observes_every_site_release_signal(self):
        """No site's digest, readiness, release, or signature state may bypass gating."""

        zero_digest = "sha256:" + ("0" * 64)
        for domain, slug, _ in MODULE.SITE_RELEASE_CONTRACTS:
            for signal in ("digest", "readiness", "release", "signature"):
                with self.subTest(domain=domain, signal=signal):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        values = root / "websites" / domain / "chart" / "values.yaml"
                        values.parent.mkdir(parents=True)
                        values.write_text(
                            "image:\n  digest: {}\ndeploymentReady: false\n".format(
                                zero_digest
                            ),
                            encoding="utf-8",
                        )
                        release = root / "kubernetes" / "websites" / slug / "release.yaml"
                        release.parent.mkdir(parents=True)
                        release.write_text("spec:\n  suspend: true\n", encoding="utf-8")
                        policy = (
                            root / "policies" / "kyverno"
                            / "require-signed-{}.yaml".format(slug)
                        )
                        policy.parent.mkdir(parents=True)
                        policy.write_text(
                            "spec:\n  validationFailureAction: Audit\n",
                            encoding="utf-8",
                        )
                        self.assertFalse(MODULE.activation_requested(root))

                        if signal == "digest":
                            values.write_text(
                                "image:\n  digest: sha256:{}\n"
                                "deploymentReady: false\n".format("a" * 64),
                                encoding="utf-8",
                            )
                        elif signal == "readiness":
                            values.write_text(
                                "image:\n  digest: {}\ndeploymentReady: true\n".format(
                                    zero_digest
                                ),
                                encoding="utf-8",
                            )
                        elif signal == "release":
                            release.write_text(
                                "spec:\n  suspend: false\n", encoding="utf-8"
                            )
                        else:
                            policy.write_text(
                                "spec:\n  validationFailureAction: Enforce\n",
                                encoding="utf-8",
                            )
                        self.assertTrue(MODULE.activation_requested(root))


if __name__ == "__main__":
    unittest.main()
