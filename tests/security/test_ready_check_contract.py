"""Pin `scripts/ready_check.py`: the ReadyRuleTests cases that survived the promoter's deleted auto-Ready machinery, on the one-APPROVE rule."""

import unittest

from .support import load_script

MODULE = load_script("ready_check.py")
HEAD = "1" * 40
# The metadata a real reviewable pull request carries; each hostile case below
# changes exactly one field of it, so the blocker it proves is unambiguous.
LABELS = ["agent-authored", "security", "cybersecurity-review-requested"]
OPEN = {"state": "open", "base_ref": "main", "default_branch": "main"}
# Distinct from None, which is itself a case under test: unreadable labels.
DEFAULT = object()


def decide(labels=DEFAULT, comments=DEFAULT, check_runs=DEFAULT, behind_by=0, **overrides):
    """`ready_decision` on an otherwise-eligible pull request."""
    return MODULE.ready_decision(
        HEAD,
        LABELS if labels is DEFAULT else labels,
        [comment()] if comments is DEFAULT else comments,
        checks() if check_runs is DEFAULT else check_runs,
        behind_by,
        **dict(OPEN, **overrides),
    )


def comment(head=HEAD, verdict="APPROVE", lane="Opus5", login=MODULE.REVIEWS_APP, uid=MODULE.REVIEWS_APP_USER_ID, kind="Bot", app=MODULE.REVIEWS_APP_ID):
    body = f"HEAD: {head}\nVERDICT: {verdict}\n\nMutation matrix and claim audit: supported.\n\n- {lane} (adversarial reviewer)\n"
    return {"user": {"login": login, "id": uid, "type": kind}, "performed_via_github_app": {"id": app}, "body": body}


def checks(conclusion="success", app=MODULE.REQUIRED_CHECK_APP, other="neutral"):
    return [{"name": n, "status": "completed", "conclusion": conclusion, "app": {"slug": app}} for n in MODULE.REQUIRED_CHECKS] + [{"name": "CodeQL", "status": "completed", "conclusion": other, "app": {"slug": "github-code-scanning"}}]


class ReadyRuleTests(unittest.TestCase):
    def test_one_exact_head_approval_from_the_app_with_green_checks_is_eligible(self):
        self.assertEqual(decide(comments=[comment(lane="Opus 5")]), (["opus5"], ["security"], []))
        self.assertEqual(MODULE.ACCEPTABLE_CONCLUSIONS, frozenset({"success", "neutral", "skipped"}), "the allowlist is the contract; widen it only with a case here")

    def test_every_receipt_evasion_leaves_the_head_unapproved(self):
        # Another head or poster, the bot login without the bot's own id or
        # App, a user account wearing it, a loose verdict, an unsigned lane.
        for override in ({"head": "2" * 40}, {"login": "snaraj"}, {"uid": 1}, {"app": None}, {"kind": "User"}, {"verdict": "APPROVE with caveats"}, {"lane": " "}):
            with self.subTest(override=override):
                self.assertIn("no adversarial APPROVE receipt binds this head", decide(comments=[comment(**override)])[2])

    def test_every_single_failure_blocks(self):
        good = [comment()]
        for reason, state in {
            "a REQUEST-CHANGES receipt": {"comments": good + [comment(verdict="REQUEST-CHANGES", lane="Codex")]},
            "requires-review is still armed": {"labels": LABELS + ["requires-review"]},
            "was not produced by": {"check_runs": checks(app="mallory-ci")},
            "appears 2 times": {"check_runs": checks() + [dict(checks()[0], app={"slug": "mallory-ci"})]},
            "has not succeeded": {"check_runs": checks("failure")},
            "appears 0 times": {"check_runs": []},
            "CodeQL ended failure": {"check_runs": checks(other="failure")},
            "behind main": {"behind_by": 3},
            "base freshness is unknown": {"behind_by": None},
        }.items():
            with self.subTest(reason=reason):
                self.assertTrue(any(reason in b for b in decide(**state)[2]), reason)

    def test_a_check_still_running_at_this_head_is_a_blocker(self):
        # Finding 3: only completed checks were judged, so an otherwise-valid
        # snapshot carrying a pending CodeQL run was ELIGIBLE. A run with no
        # verdict yet cannot be green, and it can still fail.
        for status in ("queued", "in_progress", "waiting", None):
            with self.subTest(status=status):
                pending = checks()[:-1] + [{"name": "CodeQL", "status": status, "conclusion": None, "app": {"slug": "github-code-scanning"}}]
                self.assertIn(f"a check at this head has not finished: CodeQL is {status}", decide(check_runs=pending)[2])
        # The same input, with that one run completed, has no blocker at all.
        self.assertEqual(decide(check_runs=checks())[2], [])


class WrongPullRequestTests(unittest.TestCase):
    """Finding 1: state, base and tier decide WHICH pull request this is.

    Each case changes exactly one field of an otherwise-eligible pull request,
    proves the exact blocker, and proves the same input goes green once that
    one condition is repaired — so none of them can pass vacuously.
    """

    def test_each_wrong_pull_request_is_blocked_and_repairable(self):
        for reason, broken, repaired in (
            ("the pull request is not open (state: closed)", {"state": "closed"}, {"state": "open"}),
            ("the pull request is not open (state: merged)", {"state": "merged"}, {"state": "open"}),
            ("the pull request is not open (state: unreadable)", {"state": None}, {"state": "open"}),
            ("targets not-main, not the default branch main", {"base_ref": "not-main"}, {"base_ref": "main"}),
            ("base branch is missing or unreadable", {"base_ref": None}, {"base_ref": "main"}),
            ("base branch is missing or unreadable", {"default_branch": None}, {"default_branch": "main"}),
        ):
            with self.subTest(reason=reason):
                self.assertTrue(any(reason in b for b in decide(**broken)[2]), reason)
                self.assertEqual(decide(**dict(broken, **repaired))[2], [], "repairing the one field must clear every blocker")

    def test_a_stale_base_names_the_branch_it_is_behind(self):
        self.assertIn("branch is 3 commit(s) behind main", decide(behind_by=3)[2])
        self.assertEqual(decide(behind_by=0)[2], [])

    def test_missing_or_contradictory_metadata_is_a_blocker(self):
        for reason, labels in (
            ("carries no tier label", ["agent-authored"]),
            ("missing the agent-authored umbrella label", ["security", "cybersecurity-review-requested"]),
            ("labels are missing or unreadable", None),
            ("conflicting tier labels", ["agent-authored", "security"]),
            ("conflicting tier labels", ["agent-authored", "docs", "cybersecurity-review-requested"]),
        ):
            with self.subTest(reason=reason):
                self.assertTrue(any(reason in b for b in decide(labels=labels)[2]), reason)
        # The documentation tier needs neither security label, and passes.
        self.assertEqual(decide(labels=["agent-authored", "docs"])[2], [])

    def test_the_tier_labels_are_reported_beside_the_approving_lanes(self):
        lanes, tiers, blockers = decide(labels=["agent-authored", "docs", "tests"])
        self.assertEqual((lanes, tiers, blockers), (["opus5"], ["docs", "tests"], []))
        # The lane-to-tier judgment is deliberately NOT made here; the module
        # says so where a reader of its output will see it.
        self.assertIn("coordinator", MODULE.__doc__)
