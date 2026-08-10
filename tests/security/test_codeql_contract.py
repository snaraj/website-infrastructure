"""Ensure CodeQL still analyzes the platform's own code after site extraction."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"


class CodeQlContractTests(unittest.TestCase):
    """The platform repository carries only Python; site repos scan their own code."""

    def test_python_analysis_is_the_single_matrix_entry(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("language: python", workflow)
        self.assertIn("build-mode: none", workflow)
        self.assertIn("- name: Initialize CodeQL", workflow)
        self.assertIn("- name: Analyze", workflow)

    def test_site_language_lanes_left_with_the_site_repositories(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("language: go", workflow)
        self.assertNotIn("language: javascript-typescript", workflow)
        self.assertNotIn("build-mode: manual", workflow)
        self.assertNotIn("- name: Set up Go", workflow)
        self.assertNotIn("go build", workflow)
        self.assertNotIn("websites/", workflow)


if __name__ == "__main__":
    unittest.main()
