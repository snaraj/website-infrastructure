"""Keep dependency manifests, builders, and CI on one reviewed version set."""

import json
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERSIONS_FILE = REPO_ROOT / "versions.env"
SITES = ("naranjo.online", "lidersea.com")
FRONTEND_PINS = {
    "@sveltejs/vite-plugin-svelte": "SVELTE_VITE_PLUGIN_VERSION",
    "svelte": "SVELTE_VERSION",
    "svelte-check": "SVELTE_CHECK_VERSION",
    "typescript": "TYPESCRIPT_VERSION",
    "vite": "VITE_VERSION",
}


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

    def test_frontend_manifests_and_locks_match_versions_registry(self):
        """Both Svelte roots and their locks must encode every reviewed pin."""

        for site in SITES:
            frontend = REPO_ROOT / "websites" / site / "frontend"
            package = json.loads((frontend / "package.json").read_text(encoding="utf-8"))
            lock = json.loads((frontend / "package-lock.json").read_text(encoding="utf-8"))
            lock_root = lock["packages"][""]

            with self.subTest(site=site, field="node"):
                self.assertEqual(package["engines"]["node"], self.versions["NODE_VERSION"])
                self.assertEqual(
                    package["packageManager"],
                    "npm@{}".format(self.versions["NPM_VERSION"]),
                )
                self.assertEqual(lock["lockfileVersion"], 3)
                self.assertEqual(lock["name"], package["name"])
                self.assertEqual(lock["version"], package["version"])
                self.assertEqual(lock_root["engines"], package["engines"])
                self.assertEqual(
                    lock_root["devDependencies"], package["devDependencies"]
                )
                self.assertEqual(
                    set(package["devDependencies"]),
                    set(FRONTEND_PINS),
                )
                # The production bundle has no runtime npm dependency graph;
                # frontend packages remain isolated build-time tooling.
                for field in (
                    "dependencies",
                    "optionalDependencies",
                    "peerDependencies",
                    "bundleDependencies",
                    "bundledDependencies",
                ):
                    with self.subTest(site=site, forbidden_field=field):
                        self.assertNotIn(field, package)
                        self.assertNotIn(field, lock_root)

            for dependency, key in FRONTEND_PINS.items():
                with self.subTest(site=site, dependency=dependency):
                    expected = self.versions[key]
                    self.assertEqual(package["devDependencies"][dependency], expected)
                    self.assertEqual(
                        lock["packages"]["node_modules/{}".format(dependency)]["version"],
                        expected,
                    )

    def test_go_modules_match_canonical_toolchain(self):
        """Both independent modules compile with the exact reviewed Go patch."""

        go_version = self.versions["GO_VERSION"]
        go_baseline = ".".join(go_version.split(".")[:2]) + ".0"
        for site in SITES:
            go_mod = (
                REPO_ROOT / "websites" / site / "go.mod"
            ).read_text(encoding="utf-8")
            with self.subTest(site=site):
                self.assertRegex(go_mod, r"(?m)^go {}$".format(re.escape(go_baseline)))
                self.assertRegex(
                    go_mod, r"(?m)^toolchain go{}$".format(re.escape(go_version))
                )

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

    def test_ci_and_container_toolchains_verify_canonical_versions(self):
        """Selected tools must be checked before they execute untrusted builds."""

        pull_request = (
            REPO_ROOT / ".github" / "workflows" / "pull-request.yml"
        ).read_text(encoding="utf-8")
        codeql = (
            REPO_ROOT / ".github" / "workflows" / "codeql.yml"
        ).read_text(encoding="utf-8")

        node_selectors = re.findall(r"(?m)^\s+node-version:\s+'([^']+)'$", pull_request)
        pull_go_selectors = re.findall(r"(?m)^\s+go-version:\s+'([^']+)'$", pull_request)
        codeql_go_selectors = re.findall(r"(?m)^\s+go-version:\s+'([^']+)'$", codeql)
        self.assertEqual(node_selectors, [self.versions["NODE_VERSION"]])
        self.assertEqual(pull_go_selectors, [self.versions["GO_VERSION"]])
        self.assertEqual(codeql_go_selectors, [self.versions["GO_VERSION"]])

        node_check = 'test "$(node --version)" = "v{}"'.format(
            self.versions["NODE_VERSION"]
        )
        npm_check = 'test "$(npm --version)" = "{}"'.format(
            self.versions["NPM_VERSION"]
        )
        go_check = 'test "$(go env GOVERSION)" = "go{}"'.format(
            self.versions["GO_VERSION"]
        )
        self.assertIn(node_check, pull_request)
        self.assertIn(npm_check, pull_request)
        self.assertIn(go_check, pull_request)
        for site in SITES:
            dockerfile = (
                REPO_ROOT / "websites" / site / "Dockerfile"
            ).read_text(encoding="utf-8")
            with self.subTest(site=site):
                self.assertIn(node_check, dockerfile)
                self.assertIn(npm_check, dockerfile)

    def test_cloudflare_manifest_and_lock_match_versions_registry(self):
        """Provider updates must keep canonical, manifest, and lock pins atomic."""

        infrastructure = REPO_ROOT / "infrastructure" / "cloudflare"
        manifest = (infrastructure / "versions.tf").read_text(encoding="utf-8")
        lock = (infrastructure / ".terraform.lock.hcl").read_text(encoding="utf-8")
        tofu = self.versions["OPENTOFU_VERSION"].lstrip("v")
        provider = self.versions["CLOUDFLARE_PROVIDER_VERSION"]

        self.assertRegex(
            manifest,
            r'(?m)^\s*required_version\s*=\s*"= {}"$'.format(re.escape(tofu)),
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
            r'(?m)^\s*constraints\s*=\s*"{}"$'.format(re.escape(provider)),
        )

    def test_frontend_experience_validation_is_mandatory_everywhere(self):
        """No site or container build may silently skip source or dist checks."""

        workflow = (
            REPO_ROOT / ".github" / "workflows" / "pull-request.yml"
        ).read_text(encoding="utf-8")
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertNotIn("npm test --if-present", workflow)
        self.assertIn("          npm test\n", workflow)
        self.assertIn(
            'python3 ../../../scripts/validate_frontend_dist.py --site "${{ matrix.site }}"',
            workflow,
        )

        for site in SITES:
            package = json.loads(
                (
                    REPO_ROOT / "websites" / site / "frontend" / "package.json"
                ).read_text(encoding="utf-8")
            )
            dockerfile = (
                REPO_ROOT / "websites" / site / "Dockerfile"
            ).read_text(encoding="utf-8")
            with self.subTest(site=site):
                self.assertIn("test", package["scripts"])
                self.assertIn("npm run check && npm test && npm run build", dockerfile)
                self.assertIn(
                    "scripts/validate_frontend_dist.py --site {}".format(site),
                    makefile,
                )


if __name__ == "__main__":
    unittest.main()
