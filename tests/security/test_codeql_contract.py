"""Ensure CodeQL captures both independent Go services."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"


class CodeQlContractTests(unittest.TestCase):
    """Prevent one site from falling outside manual Go build tracing."""

    def test_manual_go_build_captures_every_site_module(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("language: go", workflow)
        self.assertIn("build-mode: manual", workflow)
        for site in ("naranjo.online", "lidersea.com"):
            with self.subTest(site=site):
                self.assertIn(
                    "(cd websites/{} && go build ./...)".format(site), workflow
                )

    def test_javascript_analysis_does_not_build_only_one_frontend(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("language: javascript-typescript", workflow)
        self.assertIn("build-mode: none", workflow)
        self.assertNotIn("working-directory: websites/", workflow)


if __name__ == "__main__":
    unittest.main()
