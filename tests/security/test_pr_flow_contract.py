"""Allow/deny contract for the gh-pr-flow rules (scripts/validate_pr_flow.py)."""

import re
import unittest

from .support import REPO_ROOT, load_script

MODULE = load_script("validate_pr_flow.py")

AGENTS_CONTRACT = REPO_ROOT / "AGENTS.md"
# The agent-label roster as AGENTS.md writes it: a backticked label followed by
# the model it names, inside the "Agent labels" bullet. Parsing that bullet
# alone keeps every other backticked word in the contract out of the set.
AGENT_LABEL_ROSTER = re.compile(r"`([a-z0-9][a-z0-9.-]*)`\s*\((?:Claude|ChatGPT|GPT)[^)]*\)")


class BranchRuleTests(unittest.TestCase):
    def test_allows_reviewed_namespaces(self):
        for name in (
            "5.6-sol/141-v030-cleanup-repair",
            "fable5/stage0",
            "fable5/stage0-audit-repo-split",
            "deploy/pi-live-readiness",
            "import/monorepo-history",
            "ci/pr-gate",
            "docs/readme-badges",
            "feat/contact-form",
            "fix/frontend-dist",
            "chore/dependabot-pins",
            "media/ingest-design",
        ):
            self.assertIsNone(MODULE.branch_denial(name), name)

    def test_sol_namespace_does_not_generalize_branch_grammar(self):
        for name in (
            "5.6-sol",
            "5.6-sol/",
            "5.6-sol//double",
            "5.6-sol/UPPER",
            "5.6-terra/141-v030-cleanup-repair",
        ):
            self.assertIsNotNone(MODULE.branch_denial(name), repr(name))

    def test_denies_protected_and_malformed_names(self):
        for name in (
            "main",
            "master",
            "HEAD",
            "",
            None,
            "fable5/",
            "fable5",
            "ci",
            "feature",
            "fable5//double",
            "fable5/UPPER",
            "fable5/../escape",
            "fable5/name.lock",
            "-fable5/leading-dash",
            "release-1",
        ):
            self.assertIsNotNone(MODULE.branch_denial(name), repr(name))


class AgentLaneNamespaceTests(unittest.TestCase):
    """Issue #137: the namespace list had fallen behind the label taxonomy.

    `opus5/`, `opus4.8/`, `sonnet5/` and `daybreak-blue/` were all DENY while
    real work shipped from exactly those branches. The measured consequence
    was none — this validator is documentary, wired to no gate, and improving
    it wires it nowhere new — but a policy file that denies the repository's
    own convention is a trap for whoever eventually does wire it up.
    """

    def test_every_registered_lane_is_allowed_in_both_grammars(self):
        for lane in MODULE.AGENT_LANES:
            with self.subTest(lane=lane, grammar="legacy"):
                self.assertIsNone(MODULE.branch_denial(lane + "/some-topic"))
            for effort in MODULE.REASONING_EFFORTS:
                name = "{}-{}/137-namespace-taxonomy".format(lane, effort)
                with self.subTest(lane=lane, effort=effort):
                    self.assertIsNone(MODULE.branch_denial(name), name)

    def test_the_lane_registry_covers_every_agent_label_in_agents_md(self):
        """The rule for adding a future lane, made enforceable.

        AGENTS.md's "Agent labels" bullet is the roster; this validator must
        never be behind it. Deliberately a SUBSET assertion: the repository's
        live label set may register a lane before the contract prose names it,
        and the direction that matters is a documented lane being refused.
        """

        bullet = AGENTS_CONTRACT.read_text(encoding="utf-8").split(
            "- **Agent labels.**", 1
        )[1].split("\n- **", 1)[0]
        documented = set(AGENT_LABEL_ROSTER.findall(bullet))
        self.assertGreaterEqual(
            len(documented),
            4,
            "the agent-label roster parse found {}; it can no longer prove "
            "anything about the lane registry".format(sorted(documented)),
        )
        missing = documented - set(MODULE.AGENT_LANES)
        self.assertFalse(
            missing,
            "AGENTS.md documents agent labels this validator would deny: {} "
            "— add them to AGENT_LANES".format(sorted(missing)),
        )

    def test_effort_tagged_branches_must_still_name_their_issue(self):
        for name in (
            "opus5-high/no-issue-number",
            "fable5-med/-leading-dash",
            "sonnet5-low/97",
        ):
            with self.subTest(name=name):
                self.assertIsNotNone(MODULE.branch_denial(name), name)

    def test_an_unregistered_lane_or_effort_is_still_denied(self):
        for name in (
            "opus9/some-topic",
            "opus5-turbo/97-topic",
            "daybreak/97-topic",
            "opus5-high",
            "opus5-high/",
        ):
            with self.subTest(name=name):
                self.assertIsNotNone(MODULE.branch_denial(name), name)

    def test_lane_parsing_is_longest_match_first(self):
        """Vacuity probe for the sort in parse_lane.

        Injected registry, because the property needs a shorter lane that is a
        prefix of a longer one AND a leftover that spells a valid effort. With
        shortest-first matching this returns ("alpha", "low", ...) and the
        branch is attributed to the wrong writer.
        """

        lanes = ("alpha", "alpha-low")
        self.assertEqual(
            MODULE.parse_lane("alpha-low/97-topic", lanes=lanes),
            ("alpha-low", None, "97-topic"),
        )
        self.assertEqual(
            MODULE.parse_lane("alpha-low-high/97-topic", lanes=lanes),
            ("alpha-low", "high", "97-topic"),
        )
        self.assertEqual(
            MODULE.parse_lane("alpha-high/97-topic", lanes=lanes),
            ("alpha", "high", "97-topic"),
        )

    def test_allowed_namespaces_is_derived_from_the_registry(self):
        expected = len(MODULE.AGENT_LANES) * (1 + len(MODULE.REASONING_EFFORTS))
        expected += len(MODULE.GENERIC_NAMESPACES)
        self.assertEqual(len(MODULE.ALLOWED_NAMESPACES), expected)
        self.assertEqual(
            len(set(MODULE.ALLOWED_NAMESPACES)),
            expected,
            "a duplicated prefix means two registry entries collided",
        )


class RefspecRuleTests(unittest.TestCase):
    CURRENT = "fable5/stage0-audit-repo-split"

    def test_allows_same_name_branch_push_of_current_branch(self):
        for refspec in (
            self.CURRENT,
            "{0}:{0}".format(self.CURRENT),
            "refs/heads/{0}:refs/heads/{0}".format(self.CURRENT),
        ):
            self.assertIsNone(MODULE.refspec_denial(refspec, self.CURRENT), refspec)

    def test_allows_same_name_sol_branch_push_only(self):
        current = "5.6-sol/141-v030-cleanup-repair"
        for refspec in (
            current,
            "{0}:{0}".format(current),
            "refs/heads/{0}:refs/heads/{0}".format(current),
        ):
            self.assertIsNone(MODULE.refspec_denial(refspec, current), refspec)

        self.assertIsNotNone(
            MODULE.refspec_denial(
                "5.6-terra/141-v030-cleanup-repair:5.6-terra/141-v030-cleanup-repair",
                "5.6-terra/141-v030-cleanup-repair",
            )
        )

    def test_denies_force_delete_wildcard_tag_and_main(self):
        cases = (
            "+{0}:{0}".format(self.CURRENT),
            ":{0}".format(self.CURRENT),
            "{0}:".format(self.CURRENT),
            "refs/heads/*:refs/heads/*",
            "{0}:refs/tags/v1.0.0".format(self.CURRENT),
            "{0}:main".format(self.CURRENT),
            "{0}:refs/heads/main".format(self.CURRENT),
            "main:main",
            "",
        )
        for refspec in cases:
            self.assertIsNotNone(MODULE.refspec_denial(refspec, self.CURRENT), refspec)

    def test_denies_pushing_a_branch_other_than_current(self):
        self.assertIsNotNone(
            MODULE.refspec_denial("fable5/other:fable5/other", self.CURRENT)
        )

    def test_denies_cross_branch_and_unreviewed_namespaces(self):
        self.assertIsNotNone(
            MODULE.refspec_denial(
                "{0}:fable5/renamed".format(self.CURRENT), self.CURRENT
            )
        )
        self.assertIsNotNone(MODULE.refspec_denial("wip:wip", "wip"))


class OperationRuleTests(unittest.TestCase):
    def test_allows_only_bounded_agent_operations(self):
        for operation in ("author", "review", "comment", "draft-pr", "push-work-branch"):
            self.assertIsNone(MODULE.operation_denial(operation), operation)

    def test_never_merge_ready_rewrite_or_delete(self):
        for operation in sorted(MODULE.FORBIDDEN_AGENT_OPERATIONS):
            self.assertIsNotNone(MODULE.operation_denial(operation), operation)
        for unknown in ("", None, "deploy", "override"):
            self.assertIsNotNone(MODULE.operation_denial(unknown), repr(unknown))


if __name__ == "__main__":
    unittest.main()
