import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "gh-pr-flow"


class GitHubFlowSkillContractTests(unittest.TestCase):
    def test_frontmatter_references_and_interface_are_portable(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---", main, re.DOTALL)
        self.assertIsNotNone(match)
        keys = [line.split(":", 1)[0] for line in match.group(1).splitlines() if ":" in line]
        self.assertEqual(keys, ["name", "description"])
        self.assertLessEqual(len(main.splitlines()), 500)
        references = sorted((SKILL / "references").glob("*.md"))
        self.assertEqual(
            [path.name for path in references],
            ["destructive-workloads.md", "governance.md", "releases.md", "reviews.md"],
        )
        for reference in references:
            with self.subTest(reference=reference.name):
                self.assertIn(f"references/{reference.name}", main)
                self.assertLessEqual(len(reference.read_text(encoding="utf-8").splitlines()), 200)
        interface = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn('display_name: "GitHub PR Flow"', interface)
        self.assertIn("$gh-pr-flow", interface)

    def test_authority_review_release_and_metadata_controls_are_load_bearing(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        governance = (SKILL / "references" / "governance.md").read_text(encoding="utf-8")
        reviews = (SKILL / "references" / "reviews.md").read_text(encoding="utf-8")
        releases = (SKILL / "references" / "releases.md").read_text(encoding="utf-8")
        for fragment, text in (
            ("**NEVER MERGE**", main),
            ("Stop and question even a later request", main),
            ("Only the coordinator flips Ready", main),
            ("exact standalone `Closes #N`", main),
            ("Dependabot", main),
            ("owner assignee", main),
            ("milestone", main),
            ("repo-specific coverage", main),
            ("HEAD: 0123456789abcdef0123456789abcdef01234567", reviews),
            ("VERDICT: REQUEST-CHANGES", reviews),
            ("Any new commit invalidates", reviews),
            ("POST-MERGE AUDIT", reviews),
            ("shared account", governance),
            ("Infrastructure/tool outages", governance),
            ("Every merge", releases),
            ("Distinct main SHAs", releases),
            ("two and three rapid merges", releases),
            ("burned/conflicting", releases),
            ("For Helm OCI", releases),
            ("never permits numeric Git/image tags", releases),
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)

    def test_destructive_contract_never_turns_stateful_or_secret_material_ephemeral(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        destructive = (SKILL / "references" / "destructive-workloads.md").read_text(encoding="utf-8")
        for fragment in (
            "engineered and proven",
            "clean recreate from zero",
            "termination, restart, node loss, and dependency loss",
            "never encode replica=1",
            "PV/PVC, database, operator",
            "SOPS/age keys and ciphertext",
            "API/Tunnel tokens",
            "public HTTPS recovery proof",
            "prestate hash -> exact fault -> recovery action -> poststate hash",
            "grants no live action",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, destructive)
        self.assertIn("Stateful/PV/PVC/database/", main)

    def test_pr_template_requires_release_and_two_independent_receipts(self):
        template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
        for fragment in (
            "Closes #",
            "Exact base",
            "Exact head",
            "Platform source release",
            "requires-review",
            "Independent normal-comment verdict",
            "architecture sanity review",
            "Merge order and collision paths",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, template)


if __name__ == "__main__":
    unittest.main()
