"""Keep CI's downloaded validator toolchain aligned with versions.env."""

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERSIONS = REPO_ROOT / "versions.env"
INSTALLER = REPO_ROOT / "scripts" / "ci" / "install-tools.sh"
SCHEDULED_SECURITY = REPO_ROOT / ".github" / "workflows" / "scheduled-security.yml"
GITLEAKS_POLICY = REPO_ROOT / "policies" / "gitleaks.toml"


def version_values():
    """Parse the simple public KEY=VALUE version registry without shelling out."""

    values = {}
    for line in VERSIONS.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


class CiToolPinTests(unittest.TestCase):
    """Prevent a version bump from silently leaving CI on another validator."""

    @classmethod
    def setUpClass(cls):
        """Load the public installer and canonical pins once."""

        cls.installer = INSTALLER.read_text(encoding="utf-8")
        cls.versions = version_values()

    def test_every_downloaded_tool_matches_versions_env(self):
        """Each independently downloaded CI tool must use the canonical version."""

        keys = (
            "TRIVY_VERSION",
            "SYFT_VERSION",
            "GITLEAKS_VERSION",
            "ACTIONLINT_VERSION",
            "KUBECONFORM_VERSION",
            "CONFTEST_VERSION",
            "KUSTOMIZE_VERSION",
            "OPENTOFU_VERSION",
            "HELM_VERSION",
            "ORAS_VERSION",
            "HADOLINT_VERSION",
            "COSIGN_VERSION",
            "SHELLCHECK_VERSION",
            "KUBERNETES_VERSION",
        )
        for key in keys:
            with self.subTest(key=key):
                self.assertIn(self.versions[key], self.installer)

    def test_ci_kubectl_matches_the_protected_operator_pin(self):
        """Protocol parity must not fall back to the runner's ambient client."""

        self.assertIn(
            self.versions["KUBECTL_LINUX_AMD64_SHA256"],
            self.installer,
        )
        self.assertIn("${install_root}/kubectl", self.installer)

    def test_downloads_cross_a_full_sha256_boundary(self):
        """No archive or standalone executable may be installed before hashing."""

        hashes = re.findall(r"(?m)^\s*'([0-9a-f]{64})'\s*\\?$", self.installer)
        self.assertGreaterEqual(len(hashes), 12)
        self.assertEqual(len(hashes), len(set(hashes)))
        self.assertIn("sha256sum --check --status", self.installer)
        self.assertLess(
            self.installer.index("sha256sum --check --status"),
            self.installer.index("tar -xf"),
        )

    def test_release_assets_use_the_publishers_canonical_linux_names(self):
        """Release URL spelling must match the publisher's exact asset metadata."""

        configured = self.versions["ACTIONLINT_VERSION"]
        version = configured[1:] if configured.startswith("v") else configured
        expected_asset = "actionlint_{}_linux_amd64.tar.gz".format(version)
        self.assertIn(expected_asset, self.installer)
        self.assertNotIn("actionlint_{}_linux_x86_64.tar.gz".format(version), self.installer)

        hadolint = self.versions["HADOLINT_VERSION"].lstrip("v")
        self.assertIn(
            "hadolint/releases/download/v{}/hadolint-linux-x86_64".format(hadolint),
            self.installer,
        )
        self.assertNotIn("hadolint-Linux-x86_64", self.installer)

        cosign = self.versions["COSIGN_VERSION"]
        self.assertIn(
            "sigstore/cosign/releases/download/{}/cosign-linux-amd64".format(cosign),
            self.installer,
        )
        self.assertIn('${install_root}/cosign', self.installer)

    def test_installer_rejects_archive_path_traversal(self):
        """A valid release hash must not authorize unsafe archive member paths."""

        self.assertIn("safe_extract()", self.installer)
        self.assertIn('members="$(tar -tf', self.installer)
        self.assertIn("(^/|(^|/)\\.\\.(/|$))", self.installer)
        self.assertIn('member_modes="$(LC_ALL=C tar -tvf', self.installer)
        self.assertIn("grep -Eqv '^[d-]'", self.installer)
        self.assertNotIn("tar -tf \"${archive}\" | grep", self.installer)

    def test_github_actions_tools_stay_outside_the_scanned_checkout(self):
        """Downloaded scanners must never become inputs to later repo scans."""

        self.assertIn('"${GITHUB_ACTIONS:-}" == true', self.installer)
        self.assertIn("RUNNER_TEMP:?GitHub Actions must provide RUNNER_TEMP", self.installer)
        self.assertIn('"${repo_root}/"*', self.installer)
        self.assertIn(
            'mktemp -d "${tool_parent%/}/website-infrastructure-tools.XXXXXX"',
            self.installer,
        )
        self.assertIn('tool_parent_input="${TMPDIR:-/tmp}"', self.installer)
        self.assertNotIn("${repo_root}/.artifacts/bin", self.installer)

    def test_full_history_scan_uses_the_repository_secret_rules(self):
        """Scheduled history scanning must include the same custom detectors."""

        workflow = SCHEDULED_SECURITY.read_text(encoding="utf-8")
        self.assertIn(
            "gitleaks git --no-banner --redact --config policies/gitleaks.toml .",
            workflow,
        )

    def test_gitleaks_scans_local_only_paths_and_current_credential_families(self):
        """Force-added custody paths and newly scannable credentials stay covered."""

        policy = GITLEAKS_POLICY.read_text(encoding="utf-8")
        allowlist = policy.split("[[rules]]", 1)[0]
        self.assertNotIn("\\.artifacts", allowlist)
        self.assertNotIn("\\.terraform", allowlist)
        self.assertIn("AGE-SECRET-KEY-(?:PQ-)?1", policy)
        for prefix in ("cfk_", "cfut_", "cfat_"):
            with self.subTest(prefix=prefix):
                self.assertIn(prefix, policy)
        self.assertIn("cloudflare_api_token", policy)


if __name__ == "__main__":
    unittest.main()
