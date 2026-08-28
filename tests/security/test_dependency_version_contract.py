"""Keep dependency manifests, builders, and CI on one reviewed version set."""

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERSIONS_FILE = REPO_ROOT / "versions.env"
CLOUDFLARE_PHASES = (
    "admin-api",
    "admin-policies",
    "admin-route",
    "admin-tunnel",
    "site-lidersea-com",
    "site-naranjo-online",
)


def version_values():
    """Parse the public KEY=VALUE registry without executing it as shell code."""

    values = {}
    for line in VERSIONS_FILE.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


class DependencyVersionContractTests(unittest.TestCase):
    """Reject partial updates before they can produce inconsistent site images."""

    @classmethod
    def setUpClass(cls):
        """Load the canonical public registry once for the complete contract."""

        cls.versions = version_values()

    def test_builder_references_encode_canonical_versions(self):
        """Digest pins must identify the same Node and Go versions they review."""

        node_pattern = (
            r"docker\.io/library/node:{}-[^@]+@sha256:[0-9a-f]{{64}}".format(
                re.escape(self.versions["NODE_VERSION"])
            )
        )
        go_pattern = (
            r"docker\.io/library/golang:{}-[^@]+@sha256:[0-9a-f]{{64}}".format(
                re.escape(self.versions["GO_VERSION"])
            )
        )
        self.assertRegex(self.versions["WEBSITE_NODE_BUILDER"], r"^{}$".format(node_pattern))
        self.assertRegex(self.versions["WEBSITE_GO_BUILDER"], r"^{}$".format(go_pattern))
        for key in ("WEBSITE_NODE_BUILDER", "WEBSITE_GO_BUILDER", "WEBSITE_RUNTIME"):
            with self.subTest(key=key):
                self.assertRegex(self.versions[key], r"@sha256:[0-9a-f]{64}$")

    def test_site_toolchains_stay_external_and_selector_build_is_exact(self):
        """Platform CI builds only its selector, never either site frontend."""

        pull_request = (
            REPO_ROOT / ".github" / "workflows" / "pull-request.yml"
        ).read_text(encoding="utf-8")
        codeql = (
            REPO_ROOT / ".github" / "workflows" / "codeql.yml"
        ).read_text(encoding="utf-8")
        for workflow in (pull_request, codeql):
            self.assertNotIn("node-version:", workflow)
            self.assertNotIn("go-version:", workflow)
            self.assertNotIn("npm ", workflow)
        self.assertEqual(pull_request.count("docker build"), 1)
        self.assertIn(
            "docker build --network=none \\\n"
            '            --output "type=tar,dest=${selector_tar}" \\\n'
            "            --file cmd/platform-release-selector/Dockerfile .",
            pull_request,
        )
        self.assertIn(
            'git diff --quiet "${selector_base}" "${selector_head}" --',
            pull_request,
        )
        self.assertIn(
            "Selector build inputs unchanged; skipping duplicate container build.",
            pull_request,
        )
        self.assertEqual(pull_request.count("-m unittest discover"), 1)
        self.assertNotIn("docker build", codeql)
        selector = (
            REPO_ROOT / "cmd" / "platform-release-selector" / "Dockerfile"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "FROM --platform=$BUILDPLATFORM "
            + self.versions["WEBSITE_GO_BUILDER"]
            + " AS build",
            selector,
        )
        self.assertIn(
            "FROM " + self.versions["PLATFORM_SELECTOR_COSIGN_IMAGE"] + " AS cosign",
            selector,
        )
        self.assertIn("FROM " + self.versions["WEBSITE_RUNTIME"], selector)

    def test_cloudflare_manifest_and_lock_match_versions_registry(self):
        """Every isolated phase must keep manifest and lock pins atomic."""

        phases = REPO_ROOT / "infrastructure" / "cloudflare" / "phases"
        tofu = self.versions["OPENTOFU_VERSION"].lstrip("v")
        provider = self.versions["CLOUDFLARE_PROVIDER_VERSION"]

        self.assertEqual(
            tuple(path.name for path in sorted(phases.iterdir()) if path.is_dir()),
            CLOUDFLARE_PHASES,
        )
        for phase in CLOUDFLARE_PHASES:
            with self.subTest(phase=phase):
                root = phases / phase
                manifest = (root / "versions.tf").read_text(encoding="utf-8")
                lock = (root / ".terraform.lock.hcl").read_text(encoding="utf-8")
                self.assertRegex(
                    manifest,
                    r'(?m)^\s*required_version\s*=\s*"= {}"$'.format(
                        re.escape(tofu)
                    ),
                )
                self.assertRegex(
                    manifest,
                    r'(?m)^\s*version\s*=\s*"{}"$'.format(re.escape(provider)),
                )
                self.assertRegex(
                    lock,
                    r'(?m)^\s*version\s*=\s*"{}"$'.format(re.escape(provider)),
                )
                self.assertRegex(
                    lock,
                    r'(?m)^\s*constraints\s*=\s*"{}"$'.format(
                        re.escape(provider)
                    ),
                )

if __name__ == "__main__":
    unittest.main()
