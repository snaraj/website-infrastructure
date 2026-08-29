"""Ensure CodeQL still analyzes the platform's own code after site extraction."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "codeql.yml"
CONFIG = ROOT / ".github" / "codeql" / "codeql-config.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
CONFIG_REFERENCE = "config-file: ./.github/codeql/codeql-config.yml"

# One pinned use of a `github/codeql-action/<sub>` action: full commit SHA plus
# the mandatory version comment. Both halves are captured because both must
# move together — a SHA bump with a stale comment is a lie in the diff.
CODEQL_ACTION_PIN = re.compile(
    r"uses:\s*github/codeql-action/(?P<sub>[A-Za-z0-9._-]+)"
    r"@(?P<sha>[0-9a-f]{40})\s*#\s*(?P<version>\S+)"
)
# The sub-actions that load and consume one CodeQL bundle. They are the pair
# whose split produces the runtime "Loaded a configuration file for version X,
# but running version Y" failure.
REQUIRED_SUB_ACTIONS = {"init", "analyze"}


def codeql_action_pins(text):
    """Return ``(sub-action, sha, version)`` for each pin in one workflow.

    Takes the TEXT rather than a path so the extractor can be pointed at a
    hostile document and shown to report a split; an extractor that quietly
    stops matching would make every comparison below compare an empty list
    with itself.
    """

    pins = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = CODEQL_ACTION_PIN.search(line)
        if match is not None:
            pins.append((match["sub"], match["sha"], match["version"]))
    return pins


def all_codeql_action_pins():
    """Sweep every workflow, so a third use elsewhere joins the lockstep."""

    found = {}
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        pins = codeql_action_pins(workflow.read_text(encoding="utf-8"))
        if pins:
            found[workflow.name] = pins
    return found

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


class CodeQlActionLockstepTests(unittest.TestCase):
    """`init` and `analyze` load and consume ONE bundle; pin them together.

    Issue #130: reverting `init` alone to v4.37.6 while `analyze` stayed on
    v4.37.7 survived every local gate — validators, actionlint, and the full
    battery — because nothing compared the two pins to each other. The failure
    then appears only at CodeQL runtime, as "Loaded a configuration file for
    version X, but running version Y", which is a red analysis on main rather
    than a red pull request. `dependabot.yml`'s `groups:` stanza stops the bot
    from PROPOSING a split; this is what detects one that arrives anyway,
    from a manual edit, a revert, or a partially applied bump.
    """

    @classmethod
    def setUpClass(cls):
        cls.pins = all_codeql_action_pins()
        cls.flat = [pin for pins in cls.pins.values() for pin in pins]

    def test_the_sweep_finds_the_pins_it_exists_to_compare(self):
        """Two pins found, both sub-actions present: nothing compares vacuously."""

        self.assertGreaterEqual(len(self.flat), 2, self.pins)
        self.assertLessEqual(
            REQUIRED_SUB_ACTIONS,
            {sub for sub, _sha, _version in self.flat},
            "the CodeQL analysis must still run through init and analyze; "
            "found {}".format(sorted({sub for sub, _s, _v in self.flat})),
        )

    def test_the_extractor_reports_a_split_when_there_is_one(self):
        """Vacuity probe: the comparison must be able to go red."""

        hostile = (
            "      - uses: github/codeql-action/init@"
            + "a" * 40
            + " # v4.37.6\n"
            "      - uses: github/codeql-action/analyze@"
            + "b" * 40
            + " # v4.37.7\n"
        )
        extracted = codeql_action_pins(hostile)
        self.assertEqual(len(extracted), 2)
        self.assertEqual(len({sha for _sub, sha, _version in extracted}), 2)
        self.assertEqual(len({version for _sub, _sha, version in extracted}), 2)

    def test_every_codeql_action_pin_names_one_sha(self):
        shas = {sha for _sub, sha, _version in self.flat}
        self.assertEqual(
            len(shas),
            1,
            "github/codeql-action sub-actions must be pinned to ONE commit; "
            "found {} across {}".format(sorted(shas), sorted(self.pins)),
        )

    def test_every_codeql_action_pin_names_one_version(self):
        versions = {version for _sub, _sha, version in self.flat}
        self.assertEqual(
            len(versions),
            1,
            "the version comments must move with the SHA; found {}".format(
                sorted(versions)
            ),
        )

    def test_dependabot_still_groups_the_sub_actions_together(self):
        """The preventive half, kept alive next to the detective half.

        Detection without prevention means the split arrives as a red build
        every time the bot bumps one sub-action; prevention without detection
        is what issue #130 measured. Both, or neither is worth much.
        """

        self.assertIn(
            '- "github/codeql-action*"',
            DEPENDABOT.read_text(encoding="utf-8"),
            "the dependabot group that stops a proposed split is gone",
        )


if __name__ == "__main__":
    unittest.main()
