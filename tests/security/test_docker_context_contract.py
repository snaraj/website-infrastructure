#!/usr/bin/env python3
"""Protect the independent website build contexts from local credential files."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SITES = ("naranjo.online", "lidersea.com")
SITE_RELEASES = {
    "naranjo.online": ("naranjo-online", "publish-naranjo-online-image.yml"),
    "lidersea.com": ("lidersea-com", "publish-lidersea-com-image.yml"),
}
SENSITIVE_CONTEXT_PATTERNS = {
    "**/.env",
    "**/.env.*",
    "**/.npmrc",
    "**/.ssh",
    "**/*.agekey",
    "**/*.key",
    "**/*.pem",
    "**/*.p12",
    "**/*.pfx",
    "**/*.dec.*",
    "**/*.plaintext.*",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/known_hosts*",
    "**/*credential*",
    "**/keys.txt",
    "**/cloudflared-token*",
    "**/kubeconfig*",
    "**/*.kubeconfig",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/*.tfplan",
    "**/terraform.tfvars",
    "**/*.auto.tfvars",
}


class DockerContextContractTests(unittest.TestCase):
    """Keep each site's image definition isolated and safe for local builds."""

    def test_each_site_owns_its_docker_definition(self):
        self.assertFalse((ROOT / "Dockerfile").exists())
        self.assertFalse((ROOT / ".dockerignore").exists())
        for site in SITES:
            with self.subTest(site=site):
                site_root = ROOT / "websites" / site
                self.assertTrue((site_root / "Dockerfile").is_file())
                self.assertTrue((site_root / ".dockerignore").is_file())

    def test_repository_ignores_future_ssh_and_kubeconfig_inventory(self):
        """Local Pi connection material must not become Git-eligible."""

        lines = {
            line.strip()
            for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertTrue(
            {".ssh/", "id_rsa*", "id_ed25519*", "known_hosts*", "*.kubeconfig"}
            .issubset(lines)
        )

    def test_each_context_excludes_common_local_secret_files(self):
        for site in SITES:
            with self.subTest(site=site):
                lines = {
                    line.strip()
                    for line in (ROOT / "websites" / site / ".dockerignore")
                    .read_text(encoding="utf-8")
                    .splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                }
                self.assertTrue(
                    SENSITIVE_CONTEXT_PATTERNS.issubset(lines),
                    "{} is missing sensitive-context exclusions".format(site),
                )

    def test_every_context_change_can_trigger_its_publish_workflow(self):
        """Build-context filters and future Go sums are release inputs."""

        for site, (_, workflow_name) in SITE_RELEASES.items():
            workflow = (
                ROOT / ".github" / "workflows" / workflow_name
            ).read_text(encoding="utf-8")
            for relative_input in (".dockerignore", "Dockerfile", "go.mod", "go.sum"):
                with self.subTest(site=site, relative_input=relative_input):
                    self.assertIn(
                        "- websites/{}/{}".format(site, relative_input), workflow
                    )
            self.assertIn("- versions.env", workflow)

    def test_both_sites_match_the_reviewed_runtime_pins(self):
        """Independent images must still share the repository's toolchain review."""

        versions = {}
        for line in (ROOT / "versions.env").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                versions[key] = value

        for site, (binary_name, _) in SITE_RELEASES.items():
            site_root = ROOT / "websites" / site
            package = json.loads(
                (site_root / "frontend" / "package.json").read_text(encoding="utf-8")
            )
            dockerfile = (site_root / "Dockerfile").read_text(encoding="utf-8")
            with self.subTest(site=site):
                self.assertEqual(package["engines"]["node"], versions["NODE_VERSION"])
                self.assertEqual(
                    package["packageManager"], "npm@{}".format(versions["NPM_VERSION"])
                )
                self.assertEqual(
                    package["devDependencies"]["svelte"], versions["SVELTE_VERSION"]
                )
                for key in (
                    "WEBSITE_NODE_BUILDER",
                    "WEBSITE_GO_BUILDER",
                    "WEBSITE_RUNTIME",
                ):
                    self.assertIn("FROM {}".format(versions[key]), dockerfile)
                self.assertIn("USER 65532:65532", dockerfile)
                self.assertIn('ENTRYPOINT ["/{}"]'.format(binary_name), dockerfile)
                self.assertNotIn(":latest", dockerfile)

    def test_dependabot_covers_each_independent_dependency_root(self):
        """Both images receive equivalent Go, npm, and Docker update reviews."""

        dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        for site in SITES:
            directories = {
                "gomod": "/websites/{}".format(site),
                "npm": "/websites/{}/frontend".format(site),
                "docker": "/websites/{}".format(site),
            }
            for ecosystem, directory in directories.items():
                with self.subTest(site=site, ecosystem=ecosystem):
                    entry = (
                        "- package-ecosystem: {}\n"
                        "    directory: {}\n"
                    ).format(ecosystem, directory)
                    self.assertEqual(dependabot.count(entry), 1)


if __name__ == "__main__":
    unittest.main()
