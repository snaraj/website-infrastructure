#!/usr/bin/env python3
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "build-website-infrastructure"


class SkillStructureTests(unittest.TestCase):
    def test_frontmatter_matches_official_validator_contract(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
        self.assertIsNotNone(match)
        frontmatter = match.group(1).splitlines()
        keys = [line.split(":", 1)[0] for line in frontmatter if ":" in line]
        self.assertEqual(keys, ["name", "description"])
        name = frontmatter[0].split(":", 1)[1].strip()
        description = frontmatter[1].split(":", 1)[1].strip()
        self.assertRegex(name, r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
        self.assertLessEqual(len(name), 64)
        self.assertTrue(description)
        self.assertLessEqual(len(description), 1024)
        self.assertNotRegex(description, r"[<>]")

    def test_references_and_interface_exist(self):
        for name in (
            "project-contract.md", "github-actions.md", "external-gates.md",
            "media-storage.md",
        ):
            self.assertTrue((SKILL / "references" / name).is_file())
        interface = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn('display_name: "Build Website Infrastructure"', interface)
        self.assertIn("$build-website-infrastructure", interface)

    def test_skill_contains_methods_not_this_repository_identity(self):
        texts = [
            path.read_text(encoding="utf-8")
            for path in sorted(SKILL.rglob("*"))
            if path.is_file()
        ]
        combined = "\n".join(texts)
        for value in (
            "naranjo.online",
            "lidersea.com",
            "snaraj",
            "pi-admin",
            "pi-websites",
            "UNRESOLVED_PI_MEDIA_STORAGE",
            "2026-08-08",
            "512 MB",
            "protected `main`",
            "GHCR repository",
            "SOPS identity install",
        ):
            with self.subTest(value=value):
                self.assertNotIn(value, combined)
        self.assertNotRegex(combined, r"@[0-9a-f]{40}\b")
        self.assertNotRegex(combined, r"(?i)[A-Z]:[\\/](?:Users|dev)[\\/]")

    def test_all_references_are_linked_and_documents_stay_focused(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        references = sorted((SKILL / "references").glob("*.md"))
        for reference in references:
            with self.subTest(reference=reference.name):
                self.assertIn(f"references/{reference.name}", main)
                self.assertLessEqual(len(reference.read_text(encoding="utf-8").splitlines()), 200)
        self.assertLessEqual(len(main.splitlines()), 500)

    def test_skill_explicitly_discovers_portable_variants(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        media = (SKILL / "references" / "media-storage.md").read_text(
            encoding="utf-8"
        )
        release = (SKILL / "references" / "github-actions.md").read_text(
            encoding="utf-8"
        )
        for fragment, document in (
            ("where those layers exist", main),
            ("one conditional variant", main),
            ("selected CSI, object", media),
            ("not a universal mandate", media),
            ("runner trust model", release),
            ("protected release event/ref", release),
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, document)


if __name__ == "__main__":
    unittest.main()
