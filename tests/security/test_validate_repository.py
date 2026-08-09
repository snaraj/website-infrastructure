#!/usr/bin/env python3
import importlib.util
import shutil
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "validate_repository.py"
SPEC = importlib.util.spec_from_file_location("validate_repository", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REPO_ROOT = Path(__file__).resolve().parents[2]
ACTIVATION_FIXTURE_FILES = (
    ".sops.yaml",
    "kubernetes/websites/naranjo-online/release.yaml",
    "kubernetes/reconciliation/naranjo-online.yaml",
    "kubernetes/websites/lidersea-com/release.yaml",
    "kubernetes/reconciliation/lidersea-com.yaml",
    "kubernetes/platform/cloudflare-public/release/release.yaml",
    "kubernetes/platform/cloudflare-public/release/kustomization.yaml",
    "kubernetes/reconciliation/platform-services.yaml",
    "kubernetes/reconciliation/admission.yaml",
    "websites/naranjo.online/chart/values.yaml",
    "websites/lidersea.com/chart/values.yaml",
) + tuple(
    path.as_posix()
    for path in sorted(MODULE.CLOUDFLARE_TERRAFORM_SOURCE_FILES)
)
SYNTHETIC_RECIPIENT = (
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp5hcal"
)


def copy_activation_fixture(root):
    for relative in ACTIVATION_FIXTURE_FILES:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, destination)


def replace_once(root, relative, before, after):
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if text.count(before) != 1:
        raise AssertionError("fixture replacement is not unique: " + relative)
    path.write_bytes(text.replace(before, after).encode("utf-8"))


def configure_cloudflare_fixture(root):
    """Create the exact synthetic staged encrypted-Secret lifecycle."""

    replace_once(
        root,
        "kubernetes/platform/cloudflare-public/release/release.yaml",
        "      tokenRevision: not-configured\n",
        "      tokenRevision: rev-reviewed-test\n",
    )
    replace_once(
        root,
        "kubernetes/platform/cloudflare-public/release/kustomization.yaml",
        "  # Add tunnel-token.sops.yaml only after the user-run encryption ceremony.\n",
        "  - tunnel-token.sops.yaml\n",
    )
    root.joinpath(".sops.yaml").write_bytes((
        "creation_rules:\n"
        "  - path_regex: ^kubernetes/.+\\.sops\\.ya?ml$\n"
        "    encrypted_regex: ^(data|stringData)$\n"
        "    age:\n"
        "      - {}\n".format(SYNTHETIC_RECIPIENT)
    ).encode("utf-8"))
    secret = root / "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml"
    secret.write_bytes((
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: pi-websites-tunnel-token\n"
        "  namespace: cloudflare-public\n"
        "type: Opaque\n"
        "data:\n"
        "  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n"
        "sops:\n"
        "  age:\n"
        "    - recipient: {}\n"
        "      enc: |\n"
        "        -----BEGIN AGE ENCRYPTED FILE-----\n"
        "        synthetic-test-ciphertext\n"
        "        -----END AGE ENCRYPTED FILE-----\n"
        "  mac: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n".format(
            SYNTHETIC_RECIPIENT
        )
    ).encode("utf-8"))


def write_site_release(root, slug, *, suspended=True, ready=False, digest=None):
    """Write the complete narrow HelmRelease identity used by strict tests."""

    if digest is None:
        digest = "sha256:" + ("0" * 64)
    domains = {
        "naranjo-online": "naranjo.online",
        "lidersea-com": "lidersea.com",
    }
    domain = domains[slug]
    release = root / "kubernetes" / "websites" / slug / "release.yaml"
    release.parent.mkdir(parents=True, exist_ok=True)
    release.write_bytes((
        "apiVersion: helm.toolkit.fluxcd.io/v2\n"
        "kind: HelmRelease\n"
        "metadata:\n"
        "  name: {slug}\n"
        "  namespace: {slug}\n"
        "  annotations:\n"
        "    platform.snaraj.dev/readiness: {readiness}\n"
        "spec:\n"
        "  suspend: {suspended}\n"
        "  interval: 10m0s\n"
        "  releaseName: {slug}\n"
        "  serviceAccountName: helm-reconciler\n"
        "  driftDetection:\n"
        "    mode: enabled\n"
        "  chart:\n"
        "    spec:\n"
        "      chart: ./websites/{domain}/chart\n"
        "      reconcileStrategy: Revision\n"
        "      sourceRef:\n"
        "        kind: GitRepository\n"
        "        name: {slug}-source\n"
        "      interval: 10m0s\n"
        "  install:\n"
        "    remediation:\n"
        "      retries: 0\n"
        "  upgrade:\n"
        "    cleanupOnFail: true\n"
        "    remediation:\n"
        "      retries: 0\n"
        "      strategy: rollback\n"
        "  values:\n"
        "    deploymentReady: {ready}\n"
        "    image:\n"
        "      repository: ghcr.io/snaraj/{slug}\n"
        "      digest: {digest}\n".format(
            slug=slug,
            domain=domain,
            readiness=MODULE.RELEASE_CONTRACTS[slug]["readiness"],
            suspended=str(suspended).lower(),
            ready=str(ready).lower(),
            digest=digest,
        )).encode("utf-8"))
    return release


class RepositoryPolicyTests(unittest.TestCase):
    def test_flux_access_authorization_matches_the_reviewed_file(self):
        """Any accepted RBAC change must force review of the complete boundary."""

        access = REPO_ROOT.joinpath(
            "kubernetes", "flux-system", "access.yaml"
        ).read_text(encoding="utf-8")
        self.assertEqual(MODULE.flux_access_contract_errors(access), [])
        self.assertEqual(
            MODULE.flux_access_contract_errors(access.replace("\n", "\r\n")), []
        )

        def assert_rejected(candidate):
            self.assertTrue(any(
                "authorization changed" in error
                for error in MODULE.flux_access_contract_errors(candidate)
            ))

        widened = access.replace(
            "resources: [networkpolicies]",
            "resources: [networkpolicies, ingresses]",
            1,
        )
        assert_rejected(widened)

        cluster_scoped = access.replace("kind: Role\n", "kind: ClusterRole\n", 1)
        assert_rejected(cluster_scoped)

        broad_subject = access.replace(
            "  - kind: ServiceAccount\n"
            "    name: platform-prerequisites-reconciler\n"
            "    namespace: flux-system\n",
            "  - kind: Group\n"
            "    name: system:authenticated\n"
            "    namespace: flux-system\n",
            1,
        )
        assert_rejected(broad_subject)

        quoted_kind = access.replace("kind: Role\n", 'kind: "Role"\n', 1)
        assert_rejected(quoted_kind)

        duplicate_role_ref = access.replace(
            "subjects:\n  - kind: ServiceAccount\n    name: root-reconciler",
            "roleRef:\n"
            "  apiGroup: rbac.authorization.k8s.io\n"
            "  kind: ClusterRole\n"
            "  name: cluster-admin\n"
            "subjects:\n"
            "  - kind: ServiceAccount\n"
            "    name: root-reconciler",
            1,
        )
        assert_rejected(duplicate_role_ref)

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

    def test_rejects_plaintext_secret_with_quoted_kind_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "kubernetes" / "site"
            target.mkdir(parents=True)
            (target / "secret.yaml").write_text(
                'apiVersion: v1\n"kind": Secret\nstringData:\n  token: nope\n',
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

        quoted_override = valid.replace(
            "sops:\n",
            '"stringData":\n  token: plaintext-override\nsops:\n',
        )
        errors = MODULE.tunnel_secret_errors(quoted_override, recipient)
        self.assertTrue(any("top-level" in error for error in errors))

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

    def test_cloudflare_default_off_contract_rejects_local_bypass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                REPO_ROOT / "infrastructure" / "cloudflare",
                root / "infrastructure" / "cloudflare",
            )
            locals_file = root / "infrastructure/cloudflare/locals.tf"
            locals_file.write_text(
                locals_file.read_text(encoding="utf-8").replace(
                    "  enabled = var.enable_cloudflare_resources ? 1 : 0\n",
                    "  enabled = 1\n",
                ),
                encoding="utf-8",
            )
            errors = MODULE.check_cloudflare(root)
            self.assertTrue(any("default-off contract" in error for error in errors))

    def test_git_visible_terraform_inputs_and_json_configuration_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                REPO_ROOT / "infrastructure" / "cloudflare",
                root / "infrastructure" / "cloudflare",
            )
            base = root / "infrastructure" / "cloudflare"
            (base / "terraform.tfvars").write_text(
                "enable_cloudflare_resources = true\n", encoding="utf-8"
            )
            (base / "forced.auto.tfvars.json").write_text(
                '{"enable_cloudflare_resources":true}\n', encoding="utf-8"
            )
            (base / "override.tf.json").write_text("{}\n", encoding="utf-8")
            errors = MODULE.check_cloudflare(root)
            self.assertTrue(any("variable input is forbidden" in error for error in errors))
            self.assertTrue(any("JSON configuration is forbidden" in error for error in errors))

    def test_ignored_local_terraform_inputs_are_excluded_by_git_visibility(self):
        expected = {
            path.as_posix() for path in MODULE.CLOUDFLARE_TERRAFORM_SOURCE_FILES
        }
        with mock.patch.object(
            MODULE,
            "_git_visible_cloudflare_paths",
            return_value=(expected, []),
        ):
            self.assertEqual(MODULE.cloudflare_visible_configuration_errors(REPO_ROOT), [])

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

    def test_active_capacity_requires_exact_aggregate_quota_inventory(self):
        """Per-object policy cannot silently accept an absent site budget."""

        def quota(namespace, digit):
            return (
                "apiVersion: v1\n"
                "kind: ResourceQuota\n"
                "metadata:\n"
                "  name: namespace-budget\n"
                "  namespace: {namespace}\n"
                "  annotations:\n"
                "    platform.snaraj.dev/readiness: reviewed-pi-capacity\n"
                "    platform.snaraj.dev/capacity-evidence-sha256: {evidence}\n"
                "spec:\n"
                "  hard:\n"
                "    pods: \"2\"\n"
                "    requests.cpu: 50m\n"
                "    requests.memory: 64Mi\n"
                "    limits.cpu: 500m\n"
                "    limits.memory: 256Mi\n"
            ).format(namespace=namespace, evidence=digit * 64)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prerequisites = root / "kubernetes/platform/prerequisites"
            prerequisites.mkdir(parents=True)
            prerequisites.joinpath("kustomization.yaml").write_bytes(
                b"resources:\n  - resource-controls.yaml\n"
            )
            quotas = quota("naranjo-online", "1") + "---\n" + quota(
                "lidersea-com", "2"
            )
            prerequisites.joinpath("resource-controls.yaml").write_bytes(
                quotas.encode("utf-8")
            )
            policy = root / "policies/kyverno"
            policy.mkdir(parents=True)
            policy.joinpath("kustomization.yaml").write_bytes(
                b"resources:\n  - require-release-readiness.yaml\n"
            )
            self.assertEqual(MODULE.reviewed_capacity_errors(root), [])

            prerequisites.joinpath("resource-controls.yaml").write_bytes(
                quota("naranjo-online", "1").encode("utf-8")
            )
            self.assertIn(
                "reviewed website capacity quota missing or duplicated: lidersea-com",
                MODULE.reviewed_capacity_errors(root),
            )

            prerequisites.joinpath("resource-controls.yaml").write_bytes(
                quotas.encode("utf-8")
            )
            policy.joinpath("kustomization.yaml").write_bytes(
                b"resources:\n  - require-zero-site-capacity.yaml\n"
            )
            self.assertIn(
                "zero-site-capacity admission policy remains active",
                MODULE.reviewed_capacity_errors(root),
            )

    def test_activation_gate_observes_every_site_live_release_signal(self):
        """Unsuspension or signature enforcement for either site invokes the gate."""

        for domain, slug, _ in MODULE.SITE_RELEASE_CONTRACTS:
            for signal in ("release", "signature"):
                with self.subTest(domain=domain, signal=signal):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        release = write_site_release(root, slug)
                        policy = (
                            root / "policies" / "kyverno"
                            / "require-signed-{}.yaml".format(slug)
                        )
                        policy.parent.mkdir(parents=True)
                        policy.write_text(
                            "spec:\n  validationFailureAction: Audit\n",
                            encoding="utf-8",
                        )
                        self.assertTrue(MODULE.load_helm_release(slug, root).suspended)
                        self.assertFalse(MODULE.activation_requested(root))

                        if signal == "release":
                            release.write_bytes(
                                release.read_bytes().replace(
                                    b"  suspend: true\n", b"  suspend: false\n"
                                )
                            )
                        else:
                            policy.write_text(
                                "spec:\n  validationFailureAction: Enforce\n",
                                encoding="utf-8",
                            )
                        self.assertTrue(MODULE.activation_requested(root))

    def test_suspended_promoted_override_is_staging_not_activation(self):
        """Digest/readiness staging stays inert until a reconciliation gate moves."""

        for _, slug, _ in MODULE.SITE_RELEASE_CONTRACTS:
            with self.subTest(slug=slug):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    write_site_release(
                        root,
                        slug,
                        ready=True,
                        digest="sha256:" + ("a" * 64),
                    )
                    self.assertTrue(MODULE.load_helm_release(slug, root).suspended)
                    self.assertFalse(MODULE.activation_requested(root))

    def test_transition_activation_keeps_chart_defaults_inert(self):
        """A staged override cannot hide a live digest in chart defaults."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            self.assertEqual(MODULE.check_activation(root), [])

            release = "kubernetes/websites/naranjo-online/release.yaml"
            replace_once(
                root, release,
                "    deploymentReady: false\n",
                "    deploymentReady: true\n",
            )
            replace_once(
                root, release,
                "      digest: {}\n".format(MODULE.ZERO_DIGEST),
                "      digest: sha256:{}\n".format("a" * 64),
            )
            self.assertEqual(MODULE.check_activation(root), [])

            replace_once(
                root,
                "websites/naranjo.online/chart/values.yaml",
                "deploymentReady: false\n",
                "deploymentReady: true\n",
            )
            self.assertIn(
                "naranjo.online chart default must remain deploymentReady false",
                MODULE.check_activation(root),
            )

    def test_transition_activation_rejects_ambiguous_dependency_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            replace_once(
                root,
                "kubernetes/websites/naranjo-online/release.yaml",
                "  suspend: true\n",
                "  suspend: false\n",
            )
            self.assertEqual(
                MODULE.check_activation(root),
                ["release transition state is unavailable or unsafe"],
            )

    def test_transition_filters_only_errors_for_proven_inert_releases(self):
        """An active parent keeps its suspended child's safety envelope."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            for relative in (
                "kubernetes/reconciliation/admission.yaml",
                "kubernetes/reconciliation/platform-services.yaml",
                "kubernetes/reconciliation/naranjo-online.yaml",
                "kubernetes/reconciliation/lidersea-com.yaml",
                "kubernetes/websites/naranjo-online/release.yaml",
                "kubernetes/websites/lidersea-com/release.yaml",
            ):
                replace_once(root, relative, "  suspend: true\n", "  suspend: false\n")
            for slug, digit in (("naranjo-online", "1"), ("lidersea-com", "2")):
                relative = "kubernetes/websites/{}/release.yaml".format(slug)
                replace_once(
                    root, relative,
                    "    deploymentReady: false\n",
                    "    deploymentReady: true\n",
                )
                replace_once(
                    root, relative,
                    "      digest: {}\n".format(MODULE.ZERO_DIGEST),
                    "      digest: sha256:{}\n".format(digit * 64),
                )
            configure_cloudflare_fixture(root)
            replace_once(
                root,
                "kubernetes/platform/cloudflare-public/release/release.yaml",
                "  suspend: true\n",
                "  suspend: false\n",
            )
            # Deterministic rollback first suspends the inner release while its
            # parent remains active long enough to reconcile that change.
            replace_once(
                root,
                "kubernetes/websites/naranjo-online/release.yaml",
                "  suspend: false\n",
                "  suspend: true\n",
            )
            synthetic = [
                "HelmRelease remains suspended: naranjo-online",
                "naranjo.online signature admission policy is not enforced",
                "lidersea.com signature admission policy is not enforced",
                "admission desired state is missing active resource: kyverno/controllers.yaml",
            ]
            with mock.patch.object(MODULE, "check_release", return_value=synthetic):
                self.assertEqual(
                    MODULE.check_activation(root),
                    synthetic[1:],
                )

    def test_outer_only_website_transition_retains_signature_and_capacity(self):
        """Desired child suspension is not observation while its parent is live."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            for relative in (
                "kubernetes/reconciliation/admission.yaml",
                "kubernetes/reconciliation/platform-services.yaml",
                "kubernetes/reconciliation/naranjo-online.yaml",
            ):
                replace_once(root, relative, "  suspend: true\n", "  suspend: false\n")
            replace_once(
                root,
                "kubernetes/websites/naranjo-online/release.yaml",
                "    deploymentReady: false\n",
                "    deploymentReady: true\n",
            )
            replace_once(
                root,
                "kubernetes/websites/naranjo-online/release.yaml",
                "      digest: {}\n".format(MODULE.ZERO_DIGEST),
                "      digest: sha256:{}\n".format("a" * 64),
            )
            synthetic = [
                "HelmRelease remains suspended: naranjo-online",
                "naranjo.online signature admission policy is not enforced",
                "reviewed website capacity quota missing or duplicated: naranjo-online",
            ]
            with mock.patch.object(MODULE, "check_release", return_value=synthetic):
                self.assertEqual(MODULE.check_activation(root), synthetic[1:])

    def test_fully_suspended_staged_site_can_filter_its_inert_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            for relative in (
                "kubernetes/reconciliation/admission.yaml",
                "kubernetes/reconciliation/platform-services.yaml",
            ):
                replace_once(root, relative, "  suspend: true\n", "  suspend: false\n")
            replace_once(
                root,
                "kubernetes/websites/naranjo-online/release.yaml",
                "    deploymentReady: false\n",
                "    deploymentReady: true\n",
            )
            replace_once(
                root,
                "kubernetes/websites/naranjo-online/release.yaml",
                "      digest: {}\n".format(MODULE.ZERO_DIGEST),
                "      digest: sha256:{}\n".format("a" * 64),
            )
            synthetic = [
                "naranjo.online signature admission policy is not enforced",
                "admission desired state is missing active resource: kyverno/controllers.yaml",
            ]
            with mock.patch.object(MODULE, "check_release", return_value=synthetic):
                self.assertEqual(MODULE.check_activation(root), synthetic[1:])

    def test_configured_connector_without_secret_fails_before_filtering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            replace_once(
                root,
                "kubernetes/platform/cloudflare-public/release/release.yaml",
                "      tokenRevision: not-configured\n",
                "      tokenRevision: rev-reviewed-test\n",
            )
            self.assertEqual(
                MODULE.check_activation(root),
                ["release transition state is unavailable or unsafe"],
            )

    def test_initial_connector_rejects_latent_secret_resource_listing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            replace_once(
                root,
                "kubernetes/platform/cloudflare-public/release/kustomization.yaml",
                "  # Add tunnel-token.sops.yaml only after the user-run encryption ceremony.\n",
                "  - tunnel-token.sops.yaml\n",
            )
            self.assertEqual(
                MODULE.check_activation(root),
                ["release transition state is unavailable or unsafe"],
            )

    def test_staged_connector_never_filters_invalid_secret_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            configure_cloudflare_fixture(root)
            for relative in (
                "kubernetes/reconciliation/admission.yaml",
                "kubernetes/reconciliation/platform-services.yaml",
            ):
                replace_once(root, relative, "  suspend: true\n", "  suspend: false\n")
            error = "invalid production tunnel Secret: encrypted payload is missing"
            with mock.patch.object(MODULE, "check_release", return_value=[error]):
                self.assertEqual(MODULE.check_activation(root), [error])

    def test_cloudflare_default_true_fails_the_integrated_activation_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            replace_once(
                root,
                "infrastructure/cloudflare/variables.tf",
                "  default     = false\n",
                "  default     = true\n",
            )
            self.assertTrue(MODULE.activation_requested(root))
            self.assertEqual(
                MODULE.check_activation(root),
                ["release transition state is unavailable or unsafe"],
            )

    def test_scaffold_signature_enforcement_is_not_an_orphaned_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            policy = root / "policies/kyverno/require-signed-naranjo-online.yaml"
            policy.parent.mkdir(parents=True)
            policy.write_bytes(
                b"spec:\n  validationFailureAction: Enforce\n"
            )
            self.assertTrue(MODULE.activation_requested(root))
            self.assertEqual(
                MODULE.check_activation(root),
                ["scaffold desired state contains a release activation signal"],
            )

    def test_staged_signature_signal_invokes_shared_release_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            replace_once(
                root,
                "kubernetes/websites/naranjo-online/release.yaml",
                "    deploymentReady: false\n",
                "    deploymentReady: true\n",
            )
            replace_once(
                root,
                "kubernetes/websites/naranjo-online/release.yaml",
                "      digest: {}\n".format(MODULE.ZERO_DIGEST),
                "      digest: sha256:{}\n".format("a" * 64),
            )
            policy = root / "policies/kyverno/require-signed-naranjo-online.yaml"
            policy.parent.mkdir(parents=True)
            policy.write_bytes(
                b"spec:\n  validationFailureAction: Enforce\n"
            )
            shared_error = (
                "admission desired state is missing active resource: "
                "kyverno/controllers.yaml"
            )
            with mock.patch.object(
                MODULE, "check_release", return_value=[shared_error]
            ):
                self.assertEqual(MODULE.check_activation(root), [shared_error])

    def test_active_connector_never_filters_its_sops_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_activation_fixture(root)
            for relative in (
                "kubernetes/reconciliation/admission.yaml",
                "kubernetes/reconciliation/platform-services.yaml",
                "kubernetes/platform/cloudflare-public/release/release.yaml",
            ):
                replace_once(root, relative, "  suspend: true\n", "  suspend: false\n")
            configure_cloudflare_fixture(root)
            sops_error = "invalid production tunnel Secret: encrypted payload is missing"
            inert_site_error = (
                "naranjo.online HelmRelease override must contain one nonzero image digest"
            )
            capacity_error = "reviewed website capacity quota missing or duplicated: naranjo-online"
            with mock.patch.object(
                MODULE,
                "check_release",
                return_value=[sops_error, inert_site_error, capacity_error],
            ):
                self.assertEqual(MODULE.check_activation(root), [sops_error])

    def test_ambiguous_release_yaml_is_never_treated_as_suspended(self):
        """A text decoy cannot turn a live or ambiguous gate into inert state."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = write_site_release(root, "naranjo-online")
            release.write_bytes(
                release.read_bytes().replace(
                    b"spec:\n  suspend: true\n",
                    b"decoy: |\n  suspend: true\nspec:\n  suspend: false\n",
                )
            )
            self.assertTrue(MODULE.activation_requested(root))

    def test_release_values_use_helm_override_and_keep_chart_inert(self):
        """Production checks follow Flux's effective values, not chart defaults."""

        zero_digest = "sha256:" + ("0" * 64)
        chart = {
            ("deploymentReady",): "false",
            ("image", "digest"): zero_digest,
        }
        release = types.SimpleNamespace(
            values={
                ("deploymentReady",): "true",
                ("image", "digest"): "sha256:" + ("a" * 64),
            }
        )
        self.assertEqual(
            MODULE.site_release_value_errors("example.invalid", chart, release),
            [],
        )

        errors = MODULE.site_release_value_errors(
            "example.invalid",
            {
                ("deploymentReady",): "true",
                ("image", "digest"): "sha256:" + ("b" * 64),
            },
            types.SimpleNamespace(
                values={
                    ("deploymentReady",): "false",
                    ("image", "digest"): zero_digest,
                }
            ),
        )
        self.assertEqual(len(errors), 4)
        self.assertTrue(any("chart default" in error for error in errors))
        self.assertTrue(any("HelmRelease override" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
