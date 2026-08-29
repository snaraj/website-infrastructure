#!/usr/bin/env python3
"""Hostile battery for the ``.github/dependabot.yml`` structural gate (#131).

Every mutation here reproduces one way PR #127's adversarial review proved
``.github/dependabot.yml`` had no gate at all: ``actionlint`` globs
``.github/workflows/*.yml`` only, so a corrupted ``groups`` key (or a typo'd
ecosystem, or a rewritten ``version``) previously survived every repository
check. Each hostile case below mutates a temp copy of the *real* committed
file and proves the gate turns red, per the adversarial-review protocol's
mutation-kill-matrix requirement in ``AGENTS.md``.
"""

import contextlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .support import REPO_ROOT, load_script, run_script

MODULE = load_script("dependabot_contract.py")
REAL_CONFIG_PATH = REPO_ROOT / ".github" / "dependabot.yml"
REAL_CONFIG_TEXT = REAL_CONFIG_PATH.read_text(encoding="utf-8")


@contextlib.contextmanager
def temp_config(text):
    """Materialize ``text`` as a real ``dependabot.yml`` for CLI-level tests.

    The registry-wiring and function-level tests exercise
    ``document_errors``/``contract_errors`` directly against in-memory
    text; the CLI tests below need an actual path on disk, since the
    contract is what ``python3 scripts/dependabot_contract.py <path>``
    reports, not what an importable function returns.
    """

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "dependabot.yml"
        path.write_text(text, encoding="utf-8")
        yield path


def mutate(text, old, new, *, count=1):
    """Replace ``old`` with ``new`` exactly ``count`` times, or fail loudly.

    A silently-no-op mutation (a typo in the fixture's own ``old`` string)
    would make the surrounding assertion pass vacuously -- the same class
    of vacuous-guard risk the review protocol's evidence doctrine warns
    about, just in test fixtures instead of the code under test.
    """

    found = text.count(old)
    if found != count:
        raise AssertionError(
            "expected {!r} to occur {} time(s), found {}".format(old, count, found)
        )
    return text.replace(old, new, count)


class RealConfigTests(unittest.TestCase):
    """The committed file is the one input that must always be accepted."""

    def test_real_config_satisfies_the_contract(self):
        self.assertEqual(MODULE.document_errors(REAL_CONFIG_TEXT), [])

    def test_real_config_parses_to_the_expected_shape(self):
        document = MODULE.parse_document(REAL_CONFIG_TEXT)
        self.assertEqual(document["version"], "2")
        self.assertEqual(len(document["updates"]), 1)
        entry = document["updates"][0]
        self.assertEqual(entry["package-ecosystem"], "github-actions")
        self.assertEqual(entry["directory"], "/")
        self.assertEqual(entry["schedule"], {"interval": "weekly"})
        self.assertEqual(
            entry["groups"],
            {"codeql-action": {"patterns": ["github/codeql-action*"]}},
        )

    def test_corrupted_groups_stanza_on_a_temp_copy_turns_the_gate_red(self):
        # The exact class of mutation PR #127's adversarial review used to
        # prove this gap: a `groups` stanza rewritten to a key this schema
        # does not recognize.
        corrupted = mutate(REAL_CONFIG_TEXT, "patterns:", "paterns:")
        errors = MODULE.document_errors(corrupted)
        self.assertTrue(errors)
        self.assertTrue(any("unknown key" in message for message in errors), errors)

    def test_corrupted_groups_stanza_on_an_actual_temp_file_turns_the_cli_red(self):
        corrupted = mutate(REAL_CONFIG_TEXT, "patterns:", "paterns:")
        with temp_config(corrupted) as path:
            completed = run_script(REPO_ROOT / "scripts" / "dependabot_contract.py", path)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("FAIL", completed.stderr)
        self.assertIn("unknown key", completed.stderr)


class CliTests(unittest.TestCase):
    """The standalone CLI's own exit-code contract (0 pass / 2 fail)."""

    def test_cli_exits_zero_on_the_real_config(self):
        completed = run_script(REPO_ROOT / "scripts" / "dependabot_contract.py", REAL_CONFIG_PATH)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("PASS", completed.stdout)

    def test_cli_exits_two_and_reports_every_failure_on_stderr(self):
        broken = mutate(REAL_CONFIG_TEXT, "version: 2", "version: 1")
        broken = mutate(broken, "github-actions", "not-a-real-ecosystem")
        with temp_config(broken) as path:
            completed = run_script(REPO_ROOT / "scripts" / "dependabot_contract.py", path)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("FAIL", completed.stderr)
        self.assertIn("version", completed.stderr)
        self.assertIn("unknown package-ecosystem", completed.stderr)

    def test_cli_reports_a_missing_file_as_a_failure_not_a_crash(self):
        completed = run_script(
            REPO_ROOT / "scripts" / "dependabot_contract.py",
            REPO_ROOT / "does" / "not" / "exist.yml",
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("cannot read", completed.stderr)

    def test_cli_denies_a_deeply_nested_document_instead_of_a_traceback(self):
        # Before the fix, a document nested well past any real schema need
        # raised an uncaught RecursionError: a Python traceback on stderr
        # and exit 1 (the interpreter's default for an unhandled
        # exception), not this CLI's documented 0/2 contract. `Popen`
        # captures stderr as text either way, so a traceback would show up
        # here as ordinary (non-"FAIL") stderr content with returncode 1.
        with temp_config(deeply_nested_document()) as path:
            completed = run_script(REPO_ROOT / "scripts" / "dependabot_contract.py", path)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("FAIL", completed.stderr)
        self.assertIn("nesting exceeds the maximum supported depth", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)
        self.assertNotIn("RecursionError", completed.stderr)


class RichFixtureTests(unittest.TestCase):
    """Every optional field the schema supports, none of which the real
    config currently exercises, must still be accepted when well-formed."""

    RICH = """\
version: 2
updates:
  - package-ecosystem: npm
    directory: /frontend
    schedule:
      interval: daily
      day: monday
      time: 04:00
      timezone: America/New_York
    open-pull-requests-limit: 3
    groups:
      dev-deps:
        patterns:
          - "eslint*"
          - "prettier"
        exclude-patterns:
          - "eslint-plugin-legacy"
        dependency-type: development
        update-types:
          - minor
          - patch
        applies-to: version-updates
  - package-ecosystem: docker
    directory: /
    schedule:
      interval: monthly
  - package-ecosystem: pip
    directory: /scripts
    schedule:
      interval: weekly
"""

    def test_rich_fixture_is_accepted(self):
        self.assertEqual(MODULE.document_errors(self.RICH), [])

    def test_every_official_ecosystem_is_individually_accepted(self):
        for ecosystem in sorted(MODULE.KNOWN_ECOSYSTEMS):
            text = (
                "version: 2\n"
                "updates:\n"
                "  - package-ecosystem: {}\n"
                "    directory: /\n"
                "    schedule:\n"
                "      interval: weekly\n"
            ).format(ecosystem)
            with self.subTest(ecosystem=ecosystem):
                self.assertEqual(MODULE.document_errors(text), [])


MINIMAL = (
    "version: 2\n"
    "updates:\n"
    "  - package-ecosystem: npm\n"
    "    directory: /\n"
    "    schedule:\n"
    "      interval: weekly\n"
)


def deeply_nested_document(depth=2000):
    """Build a document nested far past `_MAX_NESTING_DEPTH` (20).

    Before the fix, parsing this raised an uncaught `RecursionError` from
    inside `document_errors` -- a traceback and (via the CLI's default
    handling of an unhandled exception) exit 1, not the contract's
    documented exit 0/2. `depth=2000` is chosen to stay comfortably under
    CPython's default ~1000-frame recursion limit even before this fix
    (so the module-level probe reliably reproduces the *documented* bug,
    a fail-open false accept, rather than incidentally already crashing
    for an unrelated reason) while sitting 100x past the explicit cap
    this fix adds.
    """

    text = "version: 2\nupdates:\n  - package-ecosystem: npm\n"
    indent = 4
    for index in range(depth):
        text += " " * indent + "k{}:\n".format(index)
        indent += 2
    text += " " * indent + "directory: /\n"
    return text


class GrammarHostileTests(unittest.TestCase):
    """Every YAML feature this restricted subset deliberately refuses."""

    def assert_denied(self, text, expected_fragment):
        errors = MODULE.document_errors(text)
        self.assertTrue(errors, "expected a rejection but the document was accepted")
        self.assertTrue(
            any(expected_fragment in message for message in errors),
            "no error mentioned {!r}: {}".format(expected_fragment, errors),
        )

    def test_tabs_anywhere_are_rejected(self):
        text = mutate(MINIMAL, "  - package-ecosystem: npm\n", "\t- package-ecosystem: npm\n")
        self.assert_denied(text, "tabs are not permitted")

    def test_carriage_returns_are_rejected(self):
        self.assert_denied(MINIMAL.replace("\n", "\r\n"), "carriage returns")

    def test_flow_style_mapping_is_rejected(self):
        text = mutate(MINIMAL, "    schedule:\n      interval: weekly\n", "    schedule: {interval: weekly}\n")
        self.assert_denied(text, "flow-style")

    def test_flow_style_sequence_is_rejected(self):
        text = MINIMAL + "    groups:\n      g:\n        patterns: [\"a\", \"b\"]\n"
        self.assert_denied(text, "flow-style")

    # The diagnostics name the structural failure and the exact source line,
    # never the key: a key is an unrestricted scalar read out of the inspected
    # file (issue #175, applying issue #112's contract to this parser).
    def test_duplicate_top_level_key_is_rejected(self):
        text = mutate(MINIMAL, "version: 2\n", "version: 2\nversion: 2\n")
        self.assert_denied(text, "duplicate mapping key")

    def test_duplicate_key_within_an_entry_is_rejected(self):
        text = mutate(MINIMAL, "    directory: /\n", "    directory: /\n    directory: /\n")
        self.assert_denied(text, "duplicate mapping key")

    def test_document_marker_is_rejected(self):
        self.assert_denied("---\n" + MINIMAL, "document markers")

    def test_inline_trailing_comment_is_rejected(self):
        text = mutate(MINIMAL, "      interval: weekly\n", "      interval: weekly  # note\n")
        self.assertTrue(MODULE.document_errors(text))

    def test_full_line_leading_comment_is_accepted(self):
        # A comment block before the document's first key is the easier,
        # more commonly special-cased case; kept as a distinct scenario
        # from the interior-comment test below, which pins what the real
        # file actually needs.
        text = "# rationale\n# more rationale\n" + MINIMAL
        self.assertEqual(MODULE.document_errors(text), [])

    def test_interior_comment_between_sibling_keys_is_accepted(self):
        # This is the real file's actual shape: its six-line rationale
        # comment sits on lines 2-7, between `version: 2` (line 1) and
        # `updates:` (line 8) -- interior to the top-level mapping, not a
        # leading block before the document starts. A parser that only
        # special-cased leading comments would fail this (and would fail
        # the real file), so this is pinned as its own case rather than
        # left to `RealConfigTests` alone to prove.
        text = mutate(
            MINIMAL,
            "version: 2\n",
            "version: 2\n# interior rationale, line 1 of 2\n# interior rationale, line 2 of 2\n",
        )
        self.assertEqual(MODULE.document_errors(text), [])

    def test_alias_marker_is_rejected(self):
        # `*name` is a YAML alias reference; this parser tracks no
        # anchors, so an alias is unresolvable and must be refused, not
        # silently treated as the literal text "*name".
        text = mutate(MINIMAL, "directory: /\n", "directory: *somealias\n")
        self.assert_denied(text, "alias")

    def test_alias_in_a_patterns_list_item_is_rejected(self):
        # The silent-acceptance path the adversarial review actually
        # found: an alias as a bare sequence-item scalar had no
        # downstream field-format check to coincidentally catch it,
        # unlike `directory`'s '/'-prefix check -- proving the parser
        # itself refuses it, not a lucky schema-layer side effect.
        text = MINIMAL + "    groups:\n      g:\n        patterns:\n          - *anchor\n"
        self.assert_denied(text, "alias")

    def test_quoted_scalar_containing_asterisk_is_still_accepted(self):
        # The other direction, at the exact same position as
        # test_alias_in_a_patterns_list_item_is_rejected above: a
        # *quoted* value starting with `*` is ordinary text (this
        # repository's real glob patterns end in an unquoted `*`, but a
        # leading one is plausible too), not an alias reference, and
        # must still parse -- proving the fix denies only the unquoted
        # alias shape, not every value containing `*`.
        text = MINIMAL + "    groups:\n      g:\n        patterns:\n          - \"*not-an-alias\"\n"
        self.assertEqual(MODULE.document_errors(text), [])

    def test_anchor_marker_is_rejected(self):
        text = mutate(MINIMAL, "directory: /\n", "directory: &anchor\n")
        self.assert_denied(text, "anchor")

    def test_tag_marker_is_rejected(self):
        text = mutate(MINIMAL, "directory: /\n", "directory: !!str /\n")
        self.assert_denied(text, "tag")

    def test_block_scalar_indicator_is_rejected(self):
        text = mutate(MINIMAL, "      interval: weekly\n", "      interval: |\n        weekly\n")
        self.assertTrue(MODULE.document_errors(text))

    def test_over_indented_nested_block_is_rejected(self):
        text = mutate(
            MINIMAL,
            "    schedule:\n      interval: weekly\n",
            "    schedule:\n        interval: weekly\n",
        )
        self.assert_denied(text, "indented exactly 2 spaces")

    def test_inconsistent_indentation_is_rejected(self):
        text = mutate(MINIMAL, "    directory: /\n", "   directory: /\n")
        self.assertTrue(MODULE.document_errors(text))

    def test_unparseable_line_is_rejected(self):
        text = MINIMAL + "this is not a mapping entry at all\n"
        self.assertTrue(MODULE.document_errors(text))

    def test_deeply_nested_document_is_denied_not_a_traceback(self):
        errors = MODULE.document_errors(deeply_nested_document())
        self.assertTrue(errors)
        self.assertTrue(any("nesting exceeds the maximum supported depth" in e for e in errors), errors)

    def test_nesting_exactly_at_the_cap_is_still_accepted(self):
        # The cap must reject only past its stated bound, not one level
        # early -- proving `_MAX_NESTING_DEPTH` itself, not merely "deep
        # nesting is denied somewhere". Checked at the *parser* layer
        # (`parse_document` must not raise) rather than through
        # `document_errors`: the synthetic `k0`/`k1`/... keys this
        # fixture nests through are not real Dependabot fields, so
        # schema validation would correctly flag them as unknown keys
        # regardless of depth -- noise this test must not confuse with
        # the depth cap itself.
        text = deeply_nested_document(depth=MODULE._MAX_NESTING_DEPTH - 2)
        MODULE.parse_document(text)  # must not raise

    def test_quoted_and_plain_scalars_are_both_accepted(self):
        quoted = mutate(MINIMAL, "directory: /", 'directory: "/"')
        self.assertEqual(MODULE.document_errors(quoted), [])

    def test_unterminated_quote_is_rejected(self):
        text = mutate(MINIMAL, "directory: /", 'directory: "/')
        self.assertTrue(MODULE.document_errors(text))


class SchemaHostileTests(unittest.TestCase):
    """Every structural rule the contract layer enforces on a parsed document."""

    def assert_denied(self, text, expected_fragment):
        errors = MODULE.document_errors(text)
        self.assertTrue(errors, "expected a rejection but the document was accepted")
        self.assertTrue(
            any(expected_fragment in message for message in errors),
            "no error mentioned {!r}: {}".format(expected_fragment, errors),
        )

    def test_version_must_be_exactly_2(self):
        self.assert_denied(mutate(MINIMAL, "version: 2", "version: 1"), "must be exactly 2")

    def test_unknown_top_level_key_is_rejected(self):
        self.assert_denied(MINIMAL + "registries: x\n", "unknown top-level key")

    def test_updates_with_no_value_is_rejected(self):
        self.assertTrue(MODULE.document_errors("version: 2\nupdates:\n"))

    def test_updates_must_not_be_empty_list(self):
        # Unreachable from block-style text (an empty block sequence has no
        # written form; `[]` is flow-style and already denied separately),
        # so this exercises `contract_errors` directly on a hand-built
        # document -- the same "reachable at the function layer even where
        # the text parser cannot produce it" testing the parser's own
        # `test_updates_with_no_value_is_rejected` case complements.
        errors = MODULE.contract_errors({"version": "2", "updates": []})
        self.assertTrue(any("must not be empty" in message for message in errors), errors)

    def test_updates_entries_must_be_mappings(self):
        errors = MODULE.contract_errors({"version": "2", "updates": ["not-a-mapping"]})
        self.assertTrue(any("must be a mapping" in message for message in errors), errors)

    def test_missing_schedule_is_rejected(self):
        text = mutate(MINIMAL, "    schedule:\n      interval: weekly\n", "")
        self.assert_denied(text, "'schedule' is required")

    def test_unknown_ecosystem_is_rejected(self):
        self.assert_denied(mutate(MINIMAL, "npm", "not-a-real-ecosystem"), "unknown package-ecosystem")

    def test_hex_is_not_a_valid_package_ecosystem_value(self):
        # "Hex" is Elixir's package host and the display name in GitHub's
        # own docs table (data/reusables/dependabot/supported-package-
        # managers.md); the `package-ecosystem` value that table maps it
        # to is `mix`. `hex` is refused like any other typo, converging
        # with the mix-only sibling gates in naranjo.online (#59) and
        # lidersea.com (#56) -- see KNOWN_ECOSYSTEMS's provenance comment.
        self.assert_denied(mutate(MINIMAL, "npm", "hex"), "unknown package-ecosystem")

    def test_mix_is_the_accepted_elixir_ecosystem_value(self):
        self.assertEqual(MODULE.document_errors(mutate(MINIMAL, "npm", "mix")), [])

    def test_package_ecosystem_must_be_a_plain_scalar(self):
        errors = MODULE.contract_errors(
            {
                "version": "2",
                "updates": [
                    {
                        "package-ecosystem": {"nested": "block"},
                        "directory": "/",
                        "schedule": {"interval": "weekly"},
                    }
                ],
            }
        )
        self.assertTrue(any("must be a plain scalar" in message for message in errors), errors)

    def test_directory_must_start_with_a_slash(self):
        self.assert_denied(mutate(MINIMAL, "directory: /", "directory: frontend"), "must start with '/'")

    def test_unknown_key_on_an_update_entry_is_rejected(self):
        text = mutate(MINIMAL, "    directory: /\n", "    directory: /\n    bogus-key: yes\n")
        self.assert_denied(text, "unknown key(s): bogus-key")

    def test_missing_required_entry_key_is_rejected(self):
        errors = MODULE.contract_errors(
            {"version": "2", "updates": [{"package-ecosystem": "npm"}]}
        )
        self.assertTrue(any("'directory' is required" in message for message in errors), errors)
        self.assertTrue(any("'schedule' is required" in message for message in errors), errors)

    def test_open_pull_requests_limit_must_be_a_non_negative_integer(self):
        text = MINIMAL + "    open-pull-requests-limit: five\n"
        self.assert_denied(text, "non-negative integer")

    def test_interval_is_restricted_to_daily_weekly_monthly(self):
        text = mutate(MINIMAL, "interval: weekly", "interval: quarterly")
        self.assert_denied(text, "must be one of")

    def test_unknown_key_on_schedule_is_rejected(self):
        text = mutate(MINIMAL, "      interval: weekly\n", "      interval: weekly\n      frequency: often\n")
        self.assert_denied(text, "unknown key(s): frequency")

    def test_day_must_be_a_lowercase_weekday_name(self):
        text = mutate(MINIMAL, "      interval: weekly\n", "      interval: weekly\n      day: Someday\n")
        self.assert_denied(text, "lowercase weekday name")

    def test_time_must_be_24_hour_hh_mm(self):
        text = mutate(MINIMAL, "      interval: weekly\n", "      interval: weekly\n      time: 25:00\n")
        self.assert_denied(text, "24-hour")

    def test_timezone_must_look_like_an_iana_zone(self):
        text = mutate(
            MINIMAL, "      interval: weekly\n", "      interval: weekly\n      timezone: \"not a zone\"\n"
        )
        self.assertTrue(MODULE.document_errors(text))

    def test_malformed_groups_patterns_typo_is_rejected(self):
        text = MINIMAL + "    groups:\n      g:\n        paterns:\n          - \"x\"\n"
        self.assert_denied(text, "unknown key(s): paterns")

    def test_group_by_is_rejected_as_an_unknown_key(self):
        # Real Dependabot supports `group-by`; this contract deliberately
        # narrows it away (see the module docstring) until a reviewed need
        # for cross-directory grouping arrives.
        text = MINIMAL + "    groups:\n      g:\n        patterns:\n          - \"x\"\n        group-by: dependency-name\n"
        self.assert_denied(text, "unknown key(s): group-by")

    def test_patterns_must_be_a_non_empty_list_of_strings(self):
        errors = MODULE.contract_errors(
            {
                "version": "2",
                "updates": [
                    {
                        "package-ecosystem": "npm",
                        "directory": "/",
                        "schedule": {"interval": "weekly"},
                        "groups": {"g": {"patterns": "not-a-list"}},
                    }
                ],
            }
        )
        self.assertTrue(any("non-empty list of strings" in message for message in errors), errors)

    def test_dependency_type_must_be_development_or_production(self):
        text = MINIMAL + "    groups:\n      g:\n        patterns:\n          - \"x\"\n        dependency-type: staging\n"
        self.assert_denied(text, "'dependency-type' must be one of")

    def test_update_types_items_are_restricted_to_major_minor_patch(self):
        text = (
            MINIMAL
            + "    groups:\n      g:\n        patterns:\n          - \"x\"\n"
            + "        update-types:\n          - minor\n          - breaking\n"
        )
        self.assert_denied(text, "'update-types' must be a non-empty list from")

    def test_applies_to_is_restricted_to_the_two_documented_targets(self):
        text = MINIMAL + "    groups:\n      g:\n        patterns:\n          - \"x\"\n        applies-to: everything\n"
        self.assert_denied(text, "'applies-to' must be one of")

    def test_groups_entry_must_be_a_mapping(self):
        errors = MODULE.contract_errors(
            {
                "version": "2",
                "updates": [
                    {
                        "package-ecosystem": "npm",
                        "directory": "/",
                        "schedule": {"interval": "weekly"},
                        "groups": {"g": "not-a-mapping"},
                    }
                ],
            }
        )
        self.assertTrue(any("must be a mapping" in message for message in errors), errors)

    def test_multiple_violations_are_all_reported_together(self):
        text = mutate(MINIMAL, "version: 2", "version: 1")
        text = mutate(text, "npm", "not-a-real-ecosystem")
        text = mutate(text, "directory: /", "directory: relative")
        errors = MODULE.document_errors(text)
        self.assertGreaterEqual(len(errors), 3, errors)


class RegistryWiringTests(unittest.TestCase):
    """The module is reachable through validate_repository.py's own CHECKS."""

    def test_validate_repository_registers_a_dependabot_check(self):
        validate_repository = load_script("validate_repository.py")
        self.assertIn("dependabot", validate_repository.CHECKS)

    def test_validate_repository_dependabot_check_passes_on_this_checkout(self):
        validate_repository = load_script("validate_repository.py", module_name="validate_repository_2")
        self.assertEqual(validate_repository.CHECKS["dependabot"](REPO_ROOT), [])

    def test_validate_repository_all_mode_includes_dependabot(self):
        completed = subprocess.run(
            [sys.executable, "-B", str(REPO_ROOT / "scripts" / "validate_repository.py"), "all"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertIn("PASS dependabot", completed.stdout, completed.stdout + completed.stderr)


class ParserDiagnosticRedactionTests(unittest.TestCase):
    """Issue #175: this parser's three key echoes, closed the issue #112 way.

    The parser is a general structural gate over a file it does not control,
    and its diagnostics reach CI logs. All three shapes — a duplicate key, a
    valueless key, and a key carrying both an inline value and nested content
    — used to print the key with ``{!r}``. Each now reports the structural
    class and the exact source line, which is what locates the defect.
    """

    MARKER = "zz" + "dependabotkeymarker" + "zz"

    def _errors(self, text):
        errors = MODULE.document_errors(text)
        self.assertTrue(errors, "the document must still be refused")
        return errors

    def test_no_diagnostic_reproduces_a_key_read_from_the_file(self):
        cases = {
            "duplicate-key": (
                "version: 2\n{m}: a\n{m}: b\n".format(m=self.MARKER),
                "duplicate mapping key",
            ),
            "valueless-key": (
                "version: 2\n{}:\n".format(self.MARKER),
                "mapping key has no value",
            ),
            "inline-value-and-nested-content": (
                "version: 2\n{}: inline\n  nested: x\n".format(self.MARKER),
                "has both an inline value and nested content",
            ),
        }
        for label, (text, structural_fragment) in sorted(cases.items()):
            with self.subTest(shape=label):
                errors = self._errors(text)
                self.assertFalse(
                    any(self.MARKER in message for message in errors),
                    "a file-derived key reached the diagnostic: {}".format(errors),
                )
                self.assertTrue(
                    any(structural_fragment in message for message in errors),
                    "the refusal must still name the structural failure: "
                    "{}".format(errors),
                )
                self.assertTrue(
                    any("line " in message for message in errors),
                    "the refusal must still say WHERE: {}".format(errors),
                )

    def test_the_marker_probe_can_see_an_echo(self):
        """Vacuity probe: the scan finds the marker when one is present."""

        echoing = ["line 1: duplicate key {!r}".format(self.MARKER)]
        self.assertTrue(any(self.MARKER in message for message in echoing))


if __name__ == "__main__":
    unittest.main()
