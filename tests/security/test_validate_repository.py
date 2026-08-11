#!/usr/bin/env python3
import base64
import os
import shutil
import subprocess
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from unittest import mock

from .support import load_script


MODULE = load_script("validate_repository.py")
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
) + tuple(
    path.as_posix()
    for path in sorted(MODULE.CLOUDFLARE_TERRAFORM_REVIEW_FILES)
)
SYNTHETIC_RECIPIENT = "age1pq1" + ("q" * 80)


def synthetic_sops_envelope(payload):
    return "ENC[AES256_GCM,data:{},iv:{},tag:{},type:str]".format(
        base64.b64encode(payload).decode("ascii"),
        base64.b64encode(b"i" * 12).decode("ascii"),
        base64.b64encode(b"t" * 16).decode("ascii"),
    )


SYNTHETIC_TOKEN_ENVELOPE = synthetic_sops_envelope(b"synthetic encrypted token")
SYNTHETIC_MAC_ENVELOPE = synthetic_sops_envelope(b"synthetic authenticated mac")
SYNTHETIC_AGE_BODY = "\n".join(
    "        " + line
    for line in textwrap.wrap(
        base64.b64encode(
            b"age-encryption.org/v1\n-> X25519 synthetic\n"
            b"c3ludGhldGlj\n--- synthetic-mac\nciphertext\n"
        ).decode("ascii"),
        64,
    )
)


def synthetic_sops_metadata(recipient=SYNTHETIC_RECIPIENT):
    return (
        "sops:\n"
        "  age:\n"
        "    - recipient: {}\n"
        "      enc: |\n"
        "        -----BEGIN AGE ENCRYPTED FILE-----\n"
        "{}\n"
        "        -----END AGE ENCRYPTED FILE-----\n"
        "  lastmodified: \"2026-08-09T00:00:00Z\"\n"
        "  mac: {}\n"
        "  encrypted_regex: ^(data|stringData)$\n"
        "  version: 3.13.3\n"
    ).format(recipient, SYNTHETIC_AGE_BODY, SYNTHETIC_MAC_ENVELOPE)


def synthetic_tunnel_secret(recipient=SYNTHETIC_RECIPIENT):
    return (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: pi-websites-tunnel-token\n"
        "  namespace: cloudflare-public\n"
        "type: Opaque\n"
        "stringData:\n"
        "  token: {}\n"
        + synthetic_sops_metadata(recipient)
    ).format(SYNTHETIC_TOKEN_ENVELOPE)


def synthetic_api_encryption_configuration(secret):
    return (
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "resources:\n"
        "  - resources:\n"
        "      - secrets\n"
        "    providers:\n"
        "      - secretbox:\n"
        "          keys:\n"
        "            - name: key-2026-08\n"
        "              secret: " + secret + "\n"
        "      - identity: {}\n"
    )


def init_git_repository(root):
    """Create an index-only fixture without requiring commit identity."""

    subprocess.run(
        ["git", "init", "--quiet"],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=True,
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
    secret.write_bytes(synthetic_tunnel_secret().encode("utf-8"))


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
        "      chart: ./chart\n"
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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

    def test_secret_scan_rejects_classical_and_post_quantum_age_identities(self):
        """Both native age identity families are crown-jewel material."""

        identities = (
            "AGE-" + "SECRET-KEY-1" + ("A" * 58),
            "AGE-" + "SECRET-KEY-PQ-1" + ("A" * 128),
        )
        for identity in identities:
            with self.subTest(prefix=identity[:24]):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    root.joinpath("identity.txt").write_text(
                        identity + "\n", encoding="utf-8"
                    )
                    errors = MODULE.check_secrets(root)
                    self.assertTrue(
                        any("age private identity" in error for error in errors)
                    )

    def test_secret_scan_rejects_current_and_contextual_legacy_cloudflare_tokens(self):
        """Prefixed credentials need no context; legacy values still do."""

        for prefix in ("cfk_", "cfut_", "cfat_"):
            with self.subTest(prefix=prefix):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    root.joinpath("credential.txt").write_text(
                        prefix + ("A" * 40) + "deadbeef\n",
                        encoding="utf-8",
                    )
                    errors = MODULE.check_secrets(root)
                    self.assertTrue(any(
                        "prefixed Cloudflare API credential" in error
                        for error in errors
                    ))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.joinpath("legacy.txt").write_text(
                "cloudflare_api_token = \"" + ("L" * 40) + "\"\n",
                encoding="utf-8",
            )
            errors = MODULE.check_secrets(root)
            self.assertTrue(
                any("literal Cloudflare API token" in error for error in errors)
            )

    def test_secret_scan_rejects_all_contextual_cloudflare_credential_forms(self):
        """Colon, bearer, and Tunnel runtime forms cannot bypass the scanner."""

        values = {
            "colon.txt": "cloudflare_api_token: " + ("L" * 40),
            "bearer.txt": "Authorization: Bearer " + ("B" * 40),
            "tunnel.txt": "tunnel_token=" + "eyJ" + ("T" * 96),
            "encrypted-key.pem.txt": (
                "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----"
            ),
            "dsa-key.pem.txt": "-----BEGIN DSA " + "PRIVATE KEY-----",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name, value in values.items():
                root.joinpath(name).write_text(value + "\n", encoding="utf-8")
            errors = MODULE.check_secrets(root)
        for label in (
            "literal Cloudflare API token",
            "Cloudflare bearer credential",
            "Cloudflare Tunnel runtime token",
            "private key block",
        ):
            with self.subTest(label=label):
                self.assertTrue(any(label in error for error in errors), errors)

    def test_secret_scan_rejects_credential_in_empty_git_pathname(self):
        """A secret-shaped staged filename is itself public data."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            token = "cfut_" + ("A" * 40) + "deadbeef"
            root.joinpath(token).write_bytes(b"")
            subprocess.run(["git", "add", token], cwd=root, check=True)
            errors = MODULE.check_secrets(root)
        self.assertTrue(any(
            "prefixed Cloudflare API credential" in error for error in errors
        ))

    def test_secret_scan_allows_public_age_recipients_and_token_near_misses(self):
        """Public recipients and malformed prefixes must not create false alarms."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.joinpath("public-values.txt").write_text(
                "age1pq1" + ("q" * 128) + "\n"
                "cfut_" + ("A" * 39) + "deadbeef\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.check_secrets(root), [])

    def test_git_visible_gate_rejects_force_added_local_only_directories(self):
        """Ignore rules cannot exempt tracked state or artifact content."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            root.joinpath(".gitignore").write_text(
                "\n".join((
                    ".artifacts/", ".cache/", ".terraform/", "__pycache__/",
                    "coverage/", "dist/", "local-evidence/", "node_modules/",
                    "",
                )),
                encoding="utf-8",
            )
            forced = [
                root / ".artifacts" / "forced.txt",
                root / ".cache" / "forced.txt",
                root / ".terraform" / "forced.txt",
                root / "__pycache__" / "forced.txt",
                root / "coverage" / "forced.txt",
                root / "dist" / "forced.txt",
                root / "local-evidence" / "forced.txt",
                root / "node_modules" / "forced.txt",
            ]
            for path in forced:
                path.parent.mkdir()
                path.write_text(
                    "cfut_" + ("A" * 40) + "deadbeef\n",
                    encoding="utf-8",
                )
            subprocess.run(
                ["git", "add", ".gitignore"], cwd=root, check=True
            )
            subprocess.run(
                [
                    "git", "add", "--force",
                    *(path.relative_to(root).as_posix() for path in forced),
                ],
                cwd=root,
                check=True,
            )

            layout_errors = MODULE.check_layout(root)
            self.assertEqual(
                sum("local-only directory content is Git-visible" in error for error in layout_errors),
                len(forced),
            )
            secret_errors = MODULE.check_secrets(root)
            self.assertEqual(
                sum("prefixed Cloudflare API credential" in error for error in secret_errors),
                len(forced),
            )

    def test_git_visible_gate_allows_no_dist_content_at_all(self):
        """Frontend output moved to the site repositories; no generated dist
        tree (or placeholder for it) may become Git-visible here."""

        self.assertEqual(MODULE.ALLOWED_DIST_PATHS, set())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            root.joinpath(".gitignore").write_text("dist/\n", encoding="utf-8")
            placeholder = root / "frontend" / "dist" / ".gitkeep"
            placeholder.parent.mkdir(parents=True)
            placeholder.write_text("", encoding="utf-8")
            subprocess.run(
                ["git", "add", ".gitignore"], cwd=root, check=True
            )
            subprocess.run(
                ["git", "add", "--force", "frontend/dist/.gitkeep"],
                cwd=root,
                check=True,
            )

            local_only_errors = [
                error for error in MODULE.check_layout(root)
                if "local-only directory content is Git-visible" in error
            ]
            self.assertEqual(
                local_only_errors,
                [
                    "local-only directory content is Git-visible: "
                    "frontend/dist/.gitkeep"
                ],
            )

    def test_git_visible_gate_rejects_force_added_credential_and_state_files(self):
        """Binary credentials and private tool files fail before content heuristics."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            root.joinpath(".gitignore").write_text(
                "*\n!.env.example\n", encoding="utf-8"
            )
            forbidden = [
                root / ".env",
                root / "operator.p12",
                root / "cluster.agekey",
                root / "terraform.tfstate.backup",
                root / "admin.tfplan.json",
                root / "cloudflare-admin-receipt.json",
                root / "kubeconfig-private",
                root / "api-encryption-config.yaml",
                root / "copied" / "encryption-config.yaml.local",
                root / "PowerShell_transcript.fixture.txt",
                root / "bootstrap" / "pi" / "decisions.env.local",
            ]
            allowed = root / ".env.example"
            for path in [*forbidden, allowed]:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic\x00binary\n")
            subprocess.run(
                [
                    "git", "add", "--force",
                    *(path.relative_to(root).as_posix() for path in [*forbidden, allowed]),
                ],
                cwd=root,
                check=True,
            )

            local_only_errors = [
                error for error in MODULE.check_layout(root)
                if "local-only directory content is Git-visible" in error
            ]
            self.assertEqual(len(local_only_errors), len(forbidden))
            self.assertFalse(any(".env.example" in error for error in local_only_errors))

    def test_generated_api_encryption_basenames_are_ignored_everywhere(self):
        ignored = {
            line.strip()
            for line in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        }
        self.assertIn("api-encryption-config.yaml", ignored)
        self.assertIn("encryption-config.yaml.local", ignored)

    def test_secret_gate_rejects_renamed_cloudflare_token_receipt(self):
        """Receipt custody follows its schema even when the filename is generic."""

        for version in ("v1", "v2"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                init_git_repository(root)
                receipt = root / "evidence.json"
                receipt.write_text(
                    '{"schema":"cloudflare-phase-token-receipt-'
                    + version
                    + '"}\n',
                    encoding="utf-8",
                )
                subprocess.run(["git", "add", "evidence.json"], cwd=root, check=True)

                self.assertTrue(any(
                    "local Cloudflare token receipt" in error
                    for error in MODULE.check_secrets(root)
                ))

    def test_validators_never_open_ignored_owner_only_files(self):
        """Local custody material is excluded before any content read occurs."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            root.joinpath(".gitignore").write_text(
                ".artifacts/\n.terraform/\n", encoding="utf-8"
            )
            root.joinpath("public.txt").write_text("public\n", encoding="utf-8")
            ignored = {
                root / ".artifacts" / "owner-only.txt",
                root / ".terraform" / "terraform.tfstate",
            }
            for path in ignored:
                path.parent.mkdir()
                path.write_text(
                    "cfk_" + ("A" * 40) + "deadbeef\n", encoding="utf-8"
                )
            subprocess.run(
                ["git", "add", ".gitignore", "public.txt"], cwd=root, check=True
            )

            original_open = Path.open

            def guarded_open(path, *args, **kwargs):
                if path in ignored:
                    raise AssertionError("ignored owner-only file was opened")
                return original_open(path, *args, **kwargs)

            with mock.patch.object(Path, "open", guarded_open):
                self.assertEqual(MODULE.check_secrets(root), [])
                self.assertEqual(MODULE.check_privacy(root), [])
                MODULE.check_media(root)
                MODULE.check_layout(root)

    def test_secret_scan_reads_exact_staged_blob_not_safe_worktree_substitute(self):
        """A secret staged then overwritten locally must still block the push."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            candidate = root / "candidate.txt"
            staged_secret = "cfut_" + ("A" * 40) + "deadbeef"
            candidate.write_text(staged_secret + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "candidate.txt"], cwd=root, check=True)
            candidate.write_text("safe working tree\n", encoding="utf-8")

            errors = MODULE.check_secrets(root)
            self.assertTrue(any(
                "prefixed Cloudflare API credential found in candidate.txt" in error
                for error in errors
            ))

    def test_secret_scan_does_not_skip_staged_binary_bytes(self):
        """NUL and invalid UTF-8 cannot hide an otherwise literal staged token."""

        for suffix in (b"\x00", b"\xff"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                init_git_repository(root)
                candidate = root / "candidate.bin"
                staged_secret = b"cfut_" + (b"A" * 40) + b"deadbeef"
                candidate.write_bytes(staged_secret + suffix)
                subprocess.run(["git", "add", "candidate.bin"], cwd=root, check=True)
                candidate.write_bytes(b"safe working tree\n")

                errors = MODULE.check_secrets(root)
                self.assertTrue(any(
                    "prefixed Cloudflare API credential found in candidate.bin" in error
                    for error in errors
                ))

    def test_exact_index_rejects_symbolic_mode_hidden_by_regular_worktree(self):
        """A regular worktree file cannot conceal a staged symbolic entry."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            blob = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=root,
                input=b"synthetic-target\n",
                stdout=subprocess.PIPE,
                check=True,
            ).stdout.decode("ascii").strip()
            subprocess.run(
                ["git", "update-index", "--add", "--cacheinfo", "120000", blob,
                 "candidate.txt"],
                cwd=root,
                check=True,
            )
            (root / "candidate.txt").write_text(
                "safe working tree\n", encoding="utf-8"
            )

            errors = MODULE.check_secrets(root)
            self.assertIn(
                "symbolic Git index entry is forbidden: candidate.txt", errors
            )

    def test_exact_index_enforces_aggregate_byte_ceiling_while_streaming(self):
        """Many small blobs cannot make exact-index scanning unbounded."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            for index in range(3):
                root.joinpath("candidate-{}.txt".format(index)).write_text(
                    "x" * 8, encoding="utf-8"
                )
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            with mock.patch.object(MODULE, "MAX_PUBLIC_REPOSITORY_BYTES", 16):
                _, errors = MODULE._git_index_text_documents(root)
        self.assertIn("Git index exceeds the aggregate byte ceiling", errors)

    def test_worktree_scanners_reject_hardlinked_public_file(self):
        """A Git-visible hardlink cannot proxy content from another custody path."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "custody-source.txt"
            public = root / "public.txt"
            source.write_text("synthetic\n", encoding="utf-8")
            try:
                os.link(source, public)
            except OSError as error:
                self.skipTest("hardlinks unavailable: {}".format(error))
            secret_errors = MODULE.check_secrets(root)
            media_errors = MODULE.check_media(root)
        self.assertTrue(any("unsafe or unstable" in error for error in secret_errors))
        self.assertTrue(any("unsafe or unstable" in error for error in media_errors))

    def test_privacy_scan_reads_exact_staged_blob_not_safe_worktree_substitute(self):
        """Private staged inventory cannot hide behind a sanitized worktree file."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            candidate = root / "inventory.txt"
            candidate.write_text(
                "operator@" + "private.example\n", encoding="utf-8"
            )
            subprocess.run(["git", "add", "inventory.txt"], cwd=root, check=True)
            candidate.write_text("safe working tree\n", encoding="utf-8")

            errors = MODULE.check_privacy(root)
            self.assertTrue(any(
                "non-synthetic email address found in inventory.txt" in error
                for error in errors
            ))

    def test_privacy_rejects_host_ips_and_uuid_identifiers(self):
        """Real-looking network and machine identities remain local-only."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
            root.joinpath("networking.txt").write_text(
                "bind=127.0.0.1 docs=192.0.2.10 v6=2001:db8::10\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.check_privacy(root), [])

    def test_media_gate_rejects_media_content_everywhere(self):
        """The platform tree carries no application asset trees at all, so any
        media content anywhere in it is a violation."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            outside = root / "docs" / "media"
            outside.mkdir(parents=True)
            outside.joinpath("source.mp4").write_bytes(b"tiny")
            former_assets = (
                root / "websites" / "example.invalid" / "frontend" / "src"
                / "assets" / "images"
            )
            former_assets.mkdir(parents=True)
            former_assets.joinpath("logo.png").write_bytes(b"tiny")
            errors = MODULE.check_media(root)
            self.assertEqual(
                sum(
                    "outside the small frontend asset tree" in error
                    for error in errors
                ),
                2,
            )

    def test_media_gate_rejects_persistent_storage_before_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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

    def test_media_gate_rejects_split_repository_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
            (root / "apps").mkdir()
            errors = MODULE.check_layout(root)
            self.assertTrue(any("apps" in error for error in errors))

    def test_layout_rejects_force_added_tokens_archives_and_opaque_ciphertext(self):
        for name in ("pi-admin.token", "review.zip", "review.enc", "review.gpg"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (root / name).write_text("synthetic\n", encoding="utf-8")
                self.assertTrue(any(
                    "local-only" in error for error in MODULE.check_layout(root)
                ))

    def test_media_rejects_renamed_archive_and_encrypted_magic(self):
        for prefix in (b"PK\x03\x04", b"\x1f\x8b", b"Salted__"):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                target = root / "docs" / "review.txt"
                target.parent.mkdir(parents=True)
                target.write_bytes(prefix + b"synthetic")
                self.assertTrue(any(
                    "opaque archive or encrypted artifact" in error
                    for error in MODULE.check_media(root)
                ))

    def test_rejects_plaintext_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
            target = root / "kubernetes" / "site"
            target.mkdir(parents=True)
            (target / "secret.yaml").write_text(
                'apiVersion: v1\n"kind": Secret\nstringData:\n  token: nope\n',
                encoding="utf-8",
            )
            errors = MODULE.check_secrets(root)
            self.assertTrue(any("unencrypted Kubernetes Secret" in error for error in errors))

    def test_rejects_renamed_api_encryption_config_from_exact_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            init_git_repository(root)
            target = root / "notes" / "review.txt"
            target.parent.mkdir(parents=True)
            synthetic_key = base64.b64encode(bytes(range(32))).decode("ascii")
            target.write_text(
                synthetic_api_encryption_configuration(synthetic_key),
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "notes/review.txt"], cwd=root, check=True)
            target.write_text(
                synthetic_api_encryption_configuration(
                    MODULE.ENCRYPTION_CONFIGURATION_SENTINEL
                ),
                encoding="utf-8",
            )

            errors = MODULE.check_secrets(root)

            self.assertTrue(any(
                "plaintext Kubernetes API encryption configuration" in error
                for error in errors
            ))
            self.assertFalse(any(synthetic_key in error for error in errors))

    def test_allows_only_the_api_encryption_sentinel_example(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.joinpath("review.example").write_text(
                synthetic_api_encryption_configuration(
                    MODULE.ENCRYPTION_CONFIGURATION_SENTINEL
                ),
                encoding="utf-8",
            )
            self.assertEqual(MODULE.check_secrets(root), [])

    def test_secret_scan_rejects_bare_tunnel_tokens_and_inline_suppressions(self):
        candidates = (
            "eyJ" + ("A" * 100),
            "gitleaks" + ":allow",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate[:8]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (root / "review.txt").write_text(candidate + "\n", encoding="utf-8")
                self.assertTrue(MODULE.check_secrets(root))

    def test_rejects_mixed_plaintext_sops_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            recipient = "age1pq1" + ("q" * 80)
            root.joinpath(".sops.yaml").write_text(
                "creation_rules:\n"
                "  - path_regex: ^kubernetes/.+\\.sops\\.ya?ml$\n"
                "    encrypted_regex: ^(data|stringData)$\n"
                "    age:\n"
                "      - {}\n".format(recipient),
                encoding="utf-8",
            )
            target = root / "kubernetes/platform/cloudflare-public/release"
            target.mkdir(parents=True)
            (target / "tunnel-token.sops.yaml").write_text(
                synthetic_tunnel_secret(recipient).replace(
                    "  token: {}\n".format(SYNTHETIC_TOKEN_ENVELOPE),
                    "  token: {}\n  plaintext: forbidden\n".format(
                        SYNTHETIC_TOKEN_ENVELOPE
                    ),
                ),
                encoding="utf-8",
            )
            errors = MODULE.check_secrets(root)
            self.assertTrue(any(
                "payload" in error or "only the token key" in error
                for error in errors
            ))

    def test_rejects_unapproved_sops_secret_path(self):
        for relative_path in (
            "kubernetes/site/secret.sops.yaml",
            "docs/opaque-archive.sops.yaml",
        ):
            with self.subTest(path=relative_path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                target = root / relative_path
                target.parent.mkdir(parents=True)
                target.write_text("synthetic\n", encoding="utf-8")
                self.assertIn(
                    "unapproved SOPS Secret path: " + relative_path,
                    MODULE.check_secrets(root),
                )

    def test_accepts_structurally_encrypted_sops_secret(self):
        recipient = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp5hcal"
        text = (
            "apiVersion: v1\nkind: Secret\nstringData:\n  token: {}\n".format(
                SYNTHETIC_TOKEN_ENVELOPE
            )
            + synthetic_sops_metadata(recipient)
        )
        self.assertEqual(MODULE.sops_secret_errors(text), [])

    def test_sops_requires_real_envelopes_complete_metadata_and_age_armor(self):
        valid = (
            "apiVersion: v1\nkind: Secret\nstringData:\n  token: {}\n".format(
                SYNTHETIC_TOKEN_ENVELOPE
            )
            + synthetic_sops_metadata()
        )
        mutations = (
            valid.replace(SYNTHETIC_TOKEN_ENVELOPE, "ENC[not-ciphertext]", 1),
            valid.replace("  lastmodified: \"2026-08-09T00:00:00Z\"\n", ""),
            valid.replace(SYNTHETIC_AGE_BODY, "        synthetic-test-ciphertext"),
            valid.replace(SYNTHETIC_MAC_ENVELOPE, "ENC[not-a-mac]"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-80:]):
                self.assertTrue(MODULE.sops_secret_errors(mutation))

    def test_sops_rejects_hidden_recipient_and_alternate_key_backends(self):
        """Only one canonically spelled age master-key backend is permitted."""

        recipient = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp5hcal"
        base = (
            "apiVersion: v1\nkind: Secret\nstringData:\n  token: {}\n".format(
                SYNTHETIC_TOKEN_ENVELOPE
            )
            + synthetic_sops_metadata(recipient)
        )
        for before, after in (
            (
                "    - recipient: {}\n".format(recipient),
                "    - recipient: {}\n    - \"recipient\": {}\n".format(
                    recipient, recipient
                ),
            ),
            (
                "  lastmodified:",
                "  pgp:\n    - fp: {}\n  lastmodified:".format("A" * 40),
            ),
            ("  lastmodified:", '  "age": []\n  lastmodified:'),
            ("  lastmodified:", "  key_groups:\n    - age: []\n  lastmodified:"),
        ):
            with self.subTest(after=after):
                errors = MODULE.sops_secret_errors(base.replace(before, after, 1))
                self.assertTrue(errors)
                self.assertTrue(any(
                    marker in error
                    for error in errors
                    for marker in (
                        "canonical", "ambiguous", "unapproved",
                        "duplicate", "malformed", "complete",
                    )
                ))

    def test_sops_rejects_extra_age_recipient_controls(self):
        text = (
            "apiVersion: v1\nkind: Secret\nstringData:\n  token: {}\n".format(
                SYNTHETIC_TOKEN_ENVELOPE
            )
            + synthetic_sops_metadata().replace(
                "      enc: |\n",
                "      enc: |\n      created_at: now\n",
                1,
            )
        )
        self.assertTrue(MODULE.sops_secret_errors(text))

    def test_sops_rejects_nested_or_noncanonical_scalar_metadata(self):
        base = (
            "apiVersion: v1\nkind: Secret\nstringData:\n  token: {}\n".format(
                SYNTHETIC_TOKEN_ENVELOPE
            )
            + synthetic_sops_metadata()
        )
        for before, after in (
            (
                '  lastmodified: "2026-08-09T00:00:00Z"',
                "  lastmodified:\n    pgp: hidden",
            ),
            ('  lastmodified: "2026-08-09T00:00:00Z"', "  lastmodified: yesterday"),
            ("  encrypted_regex: ^(data|stringData)$", "  encrypted_regex: .*"),
            ("  version: 3.13.3", "  version: 3.12.0"),
        ):
            with self.subTest(after=after):
                self.assertTrue(MODULE.sops_secret_errors(base.replace(before, after, 1)))

    def test_sops_rejects_nested_ciphertext_bait_and_flow_plaintext(self):
        text = (
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: synthetic\n"
            "  annotations:\n    data:\n      bait: {}\n"
            "stringData: {{password: plaintext}}\n".format(SYNTHETIC_TOKEN_ENVELOPE)
            + synthetic_sops_metadata()
        )
        errors = MODULE.sops_secret_errors(text)
        self.assertTrue(any("top-level data/stringData" in error for error in errors))
        self.assertTrue(any("no encrypted data/stringData" in error for error in errors))

    def test_secret_detection_rejects_tagged_aliased_and_escaped_kind(self):
        for text in (
            "apiVersion: v1\nkind: !!str Secret\n",
            "apiVersion: v1\nsecretKind: &secret Secret\nkind: *secret\n",
            'apiVersion: v1\nkind: "\\x53ecret"\n',
        ):
            with self.subTest(text=text):
                self.assertTrue(MODULE.contains_secret_document(text))

    def test_tunnel_secret_requires_exact_identity_namespace_key_and_recipient(self):
        recipient = "age1pq1" + ("q" * 80)
        valid = synthetic_tunnel_secret(recipient)
        self.assertEqual(MODULE.tunnel_secret_errors(valid, recipient), [])
        invalid = valid.replace("namespace: cloudflare-public", "namespace: default").replace(
            "  token: {}\n".format(SYNTHETIC_TOKEN_ENVELOPE),
            "  token: {}\n  extra: plaintext\n".format(SYNTHETIC_TOKEN_ENVELOPE),
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
            target = root / "kubernetes" / "chart"
            target.mkdir(parents=True)
            (target / "values.yaml").write_text(
                "image:\n  repository: example.invalid/site\n  digest: sha256:deadbeef\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.check_kubernetes(root), [])

    def test_rejects_unpinned_action(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
            target = root / "infrastructure" / "cloudflare"
            target.mkdir(parents=True)
            (target / "data.tf").write_text(
                'data "cloudflare_zones" "all" {}\n', encoding="utf-8"
            )
            errors = MODULE.check_cloudflare(root)
            self.assertTrue(any("data source is forbidden" in error for error in errors))

    def test_cloudflare_phase_contract_rejects_guard_bypass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            shutil.copytree(
                REPO_ROOT / "infrastructure" / "cloudflare",
                root / "infrastructure" / "cloudflare",
            )
            variables_file = root / (
                "infrastructure/cloudflare/phases/admin-tunnel/variables.tf"
            )
            variables_file.write_text(
                variables_file.read_text(encoding="utf-8").replace(
                    "  default     = false\n",
                    "  default     = true\n",
                ),
                encoding="utf-8",
            )
            errors = MODULE.check_cloudflare(root)
            self.assertTrue(any("phase contract" in error for error in errors))

    def test_git_visible_terraform_inputs_and_json_configuration_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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
            path.as_posix() for path in MODULE.CLOUDFLARE_TERRAFORM_REVIEW_FILES
        }
        with mock.patch.object(
            MODULE,
            "_git_visible_cloudflare_paths",
            return_value=(expected, []),
        ):
            self.assertEqual(MODULE.cloudflare_visible_configuration_errors(REPO_ROOT), [])

    def test_release_gate_requires_reconciled_admission_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
                        root = Path(directory).resolve()
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
                    root = Path(directory).resolve()
                    write_site_release(
                        root,
                        slug,
                        ready=True,
                        digest="sha256:" + ("a" * 64),
                    )
                    self.assertTrue(MODULE.load_helm_release(slug, root).suspended)
                    self.assertFalse(MODULE.activation_requested(root))

    def test_transition_activation_rejects_ambiguous_dependency_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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

        # A detached git housekeeping process can still be writing under the
        # fixture's object store when this context exits, which intermittently
        # fails cleanup with "Directory not empty: 'pack'" on CI runners. The
        # assertions above the cleanup are unaffected; ignore cleanup races.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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

    def test_cloudflare_phase_guard_true_fails_the_integrated_activation_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            copy_activation_fixture(root)
            replace_once(
                root,
                "infrastructure/cloudflare/phases/admin-tunnel/variables.tf",
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
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
            root = Path(directory).resolve()
            release = write_site_release(root, "naranjo-online")
            release.write_bytes(
                release.read_bytes().replace(
                    b"spec:\n  suspend: true\n",
                    b"decoy: |\n  suspend: true\nspec:\n  suspend: false\n",
                )
            )
            self.assertTrue(MODULE.activation_requested(root))

    def test_release_values_use_the_authoritative_helm_override(self):
        """Production checks follow Flux's effective values; chart defaults now
        live (and are enforced) in the standalone site repositories."""

        promoted = types.SimpleNamespace(
            values={
                ("deploymentReady",): "true",
                ("image", "digest"): "sha256:" + ("a" * 64),
            }
        )
        self.assertEqual(
            MODULE.site_release_override_errors("example.invalid", promoted),
            [],
        )

        staged = types.SimpleNamespace(
            values={
                ("deploymentReady",): "false",
                ("image", "digest"): MODULE.ZERO_DIGEST,
            }
        )
        errors = MODULE.site_release_override_errors("example.invalid", staged)
        self.assertEqual(len(errors), 2)
        self.assertTrue(any(
            "must contain one nonzero image digest" in error for error in errors
        ))
        self.assertTrue(any(
            "is not deploymentReady" in error for error in errors
        ))


if __name__ == "__main__":
    unittest.main()
