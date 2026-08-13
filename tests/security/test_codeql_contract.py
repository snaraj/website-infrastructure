"""Ensure CodeQL still analyzes the platform's own code after site extraction."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
CONFIG = ROOT / ".github" / "codeql" / "codeql-config.yml"
CONFIG_REFERENCE = "config-file: ./.github/codeql/codeql-config.yml"

# The excluded tree, spelled once. `scripts/**` is the platform's production
# surface and must never appear in this set; the assertions below compare
# against it exactly, so an added entry fails rather than silently widening.
EXPECTED_EXCLUSIONS = ["tests"]


def config_structure():
    """Read the CodeQL config as keys and list items, ignoring commentary.

    The rationale in that file is long on purpose and will keep growing, so a
    substring search over its text would pass on a sentence and prove nothing
    about what CodeQL is actually told. This reads the directives instead: the
    top-level keys and the items beneath them, with comments and blank lines
    dropped. The repository carries no YAML dependency (safety invariant 11),
    and the file's supported shape is a flat map of string lists, so this stays
    a few lines rather than a parser.
    """

    keys = {}
    current = None
    for raw in CONFIG.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("  - "):
            if current is None:
                raise AssertionError("list item before any key: {!r}".format(raw))
            keys[current].append(line[4:].strip())
            continue
        if line.startswith(" "):
            raise AssertionError("unsupported nesting in CodeQL config: {!r}".format(raw))
        name, _, inline = line.partition(":")
        current = name.strip()
        keys[current] = [inline.strip()] if inline.strip() else []
    return keys


class CodeQlConfigScopeTests(unittest.TestCase):
    """The analysis-scope decision is in the tree, and it stays narrow.

    Alert dismissal in the GitHub UI leaves no artifact a checkout can show
    and no gate can re-verify. This battery is what makes the in-tree config
    the real control: it pins that the workflow consumes it, that it excludes
    exactly the test tree, and that it never reaches the production surface or
    trims the query suite.
    """

    def test_workflow_initializes_with_the_committed_config(self):
        self.assertTrue(CONFIG.is_file(), "CodeQL config file is missing")
        self.assertIn(CONFIG_REFERENCE, WORKFLOW.read_text(encoding="utf-8"))

    def test_exclusion_is_exactly_the_test_tree(self):
        structure = config_structure()
        self.assertIn("paths-ignore", structure)
        self.assertEqual(structure["paths-ignore"], EXPECTED_EXCLUSIONS)

    def test_production_surface_is_never_excluded(self):
        """Named separately from the equality above so the reason survives.

        `scripts/**` is what runs on the host and inside the gates. An
        exclusion reaching it would hide findings on the only Python in this
        repository that executes outside a test process.
        """

        for entry in config_structure().get("paths-ignore", []):
            with self.subTest(entry=entry):
                self.assertFalse(
                    entry == "scripts" or entry.startswith("scripts/"),
                    "CodeQL must not exclude the production script surface",
                )

    def test_config_does_not_narrow_the_query_suite(self):
        """No `queries` or `query-filters`: the default suite runs in full.

        Either key can silently disable a query across the whole repository,
        including `scripts/**`. Excluding one tree from every query is a scope
        decision; disabling a query everywhere is a weakening, and this
        repository does not make that trade in this file.
        """

        self.assertEqual(set(config_structure()), {"paths-ignore"})


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
