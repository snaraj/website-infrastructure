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
PRODUCTION_ROOTS = ("scripts", "cmd", "internal")


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

    def test_production_surfaces_are_never_excluded(self):
        """Named separately from the equality above so the reason survives.

        `scripts/**` runs on the host and inside the gates; `cmd/**` and
        `internal/**` contain the release selector. None may be hidden.
        """

        for entry in config_structure().get("paths-ignore", []):
            for production_root in PRODUCTION_ROOTS:
                with self.subTest(entry=entry, production_root=production_root):
                    self.assertFalse(
                        entry == production_root
                        or entry.startswith(production_root + "/"),
                        "CodeQL must not exclude a production surface",
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
    """Analyze both production languages; site repos scan their own code."""

    def test_python_and_go_are_the_exact_production_matrix(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "          - language: python\n"
            "            build-mode: none\n"
            "          - language: go\n"
            "            build-mode: autobuild\n",
            workflow,
        )
        self.assertEqual(
            [
                line.strip()
                for line in workflow.splitlines()
                if line.strip().startswith("- language:")
            ],
            ["- language: python", "- language: go"],
        )
        self.assertIn("- name: Initialize CodeQL", workflow)
        self.assertIn("- name: Analyze", workflow)

    def test_site_language_lanes_left_with_the_site_repositories(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("language: javascript-typescript", workflow)
        self.assertNotIn("build-mode: manual", workflow)
        self.assertNotIn("actions/setup-go", workflow)
        self.assertNotIn("go build", workflow)
        self.assertNotIn("websites/", workflow)


if __name__ == "__main__":
    unittest.main()
