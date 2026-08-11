"""Allow/deny contract for the gh-pr-flow rules (scripts/validate_pr_flow.py)."""

import unittest

from .support import load_script

MODULE = load_script("validate_pr_flow.py")


class BranchRuleTests(unittest.TestCase):
    def test_allows_reviewed_namespaces(self):
        for name in (
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


class RefspecRuleTests(unittest.TestCase):
    CURRENT = "fable5/stage0-audit-repo-split"

    def test_allows_same_name_branch_push_of_current_branch(self):
        for refspec in (
            self.CURRENT,
            "{0}:{0}".format(self.CURRENT),
            "refs/heads/{0}:refs/heads/{0}".format(self.CURRENT),
        ):
            self.assertIsNone(MODULE.refspec_denial(refspec, self.CURRENT), refspec)

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


if __name__ == "__main__":
    unittest.main()
