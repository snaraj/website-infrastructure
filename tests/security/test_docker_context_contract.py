#!/usr/bin/env python3
"""Protect the independent website build contexts from local credential files."""

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

    def test_both_sites_use_reviewed_builder_and_runtime_images(self):
        """Independent images must consume every centrally reviewed base image."""

        versions = {}
        for line in (ROOT / "versions.env").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                versions[key] = value

        for site, (binary_name, _) in SITE_RELEASES.items():
            site_root = ROOT / "websites" / site
            dockerfile = (site_root / "Dockerfile").read_text(encoding="utf-8")
            with self.subTest(site=site):
                for key in (
                    "WEBSITE_NODE_BUILDER",
                    "WEBSITE_GO_BUILDER",
                    "WEBSITE_RUNTIME",
                ):
                    self.assertIn("FROM {}".format(versions[key]), dockerfile)
                self.assertIn("USER 65532:65532", dockerfile)
                self.assertIn('ENTRYPOINT ["/{}"]'.format(binary_name), dockerfile)
                self.assertNotIn(":latest", dockerfile)

    def test_dependabot_consolidates_equivalent_roots_by_ecosystem(self):
        """One ecosystem job should update both sites without joining releases."""

        dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        blocks = {}
        for raw_block in dependabot.split("\n  - package-ecosystem: ")[1:]:
            ecosystem, *lines = raw_block.splitlines()
            self.assertNotIn(ecosystem, blocks)
            blocks[ecosystem] = "\n".join(lines)

        expected = {
            "gomod": ["/websites/naranjo.online", "/websites/lidersea.com"],
            "npm": [
                "/websites/naranjo.online/frontend",
                "/websites/lidersea.com/frontend",
            ],
            "docker": ["/websites/naranjo.online", "/websites/lidersea.com"],
        }
        for ecosystem, directories in expected.items():
            block = blocks[ecosystem]
            with self.subTest(ecosystem=ecosystem):
                self.assertIn("    directories:", block)
                self.assertNotIn("    directory:", block)
                # The plural-directory job already updates one dependency
                # across both roots. A groups rule would instead combine
                # unrelated dependencies and is intentionally absent.
                self.assertNotIn("    groups:", block)
                for directory in directories:
                    self.assertEqual(block.count("      - {}".format(directory)), 1)


if __name__ == "__main__":
    unittest.main()
