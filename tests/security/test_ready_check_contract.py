"""Pin `scripts/ready_check.py`: the ReadyRuleTests cases that survived the promoter's deleted auto-Ready machinery, on the one-APPROVE rule."""

import unittest

from .support import load_script

MODULE = load_script("ready_check.py")
HEAD = "1" * 40


def comment(head=HEAD, verdict="APPROVE", lane="Opus5", login=MODULE.REVIEWS_APP, uid=MODULE.REVIEWS_APP_USER_ID, kind="Bot", app=MODULE.REVIEWS_APP_ID):
    body = f"HEAD: {head}\nVERDICT: {verdict}\n\nMutation matrix and claim audit: supported.\n\n- {lane} (adversarial reviewer)\n"
    return {"user": {"login": login, "id": uid, "type": kind}, "performed_via_github_app": {"id": app}, "body": body}


def checks(conclusion="success", app=MODULE.REQUIRED_CHECK_APP, other="neutral"):
    return [{"name": n, "status": "completed", "conclusion": conclusion, "app": {"slug": app}} for n in MODULE.REQUIRED_CHECKS] + [{"name": "CodeQL", "status": "completed", "conclusion": other, "app": {"slug": "github-code-scanning"}}]


class ReadyRuleTests(unittest.TestCase):
    def test_one_exact_head_approval_from_the_app_with_green_checks_is_eligible(self):
        self.assertEqual(MODULE.ready_decision(HEAD, ["security"], [comment(lane="Opus 5")], checks(), 0), (["opus5"], []))
        self.assertEqual(MODULE.ACCEPTABLE_CONCLUSIONS, frozenset({"success", "neutral", "skipped"}), "the allowlist is the contract; widen it only with a case here")

    def test_every_receipt_evasion_leaves_the_head_unapproved(self):
        # Another head or poster, the bot login without the bot's own id or
        # App, a user account wearing it, a loose verdict, an unsigned lane.
        for override in ({"head": "2" * 40}, {"login": "snaraj"}, {"uid": 1}, {"app": None}, {"kind": "User"}, {"verdict": "APPROVE with caveats"}, {"lane": " "}):
            with self.subTest(override=override):
                self.assertIn("no adversarial APPROVE receipt binds this head", MODULE.ready_decision(HEAD, [], [comment(**override)], checks(), 0)[1])

    def test_every_single_failure_blocks(self):
        good = [comment()]
        for reason, state in {
            "a REQUEST-CHANGES receipt": ([], good + [comment(verdict="REQUEST-CHANGES", lane="Codex")], checks(), 0),
            "requires-review is still armed": (["requires-review"], good, checks(), 0),
            "was not produced by": ([], good, checks(app="mallory-ci"), 0),
            "appears 2 times": ([], good, checks() + [dict(checks()[0], app={"slug": "mallory-ci"})], 0),
            "has not succeeded": ([], good, checks("failure"), 0),
            "appears 0 times": ([], good, [], 0),
            "CodeQL ended failure": ([], good, checks(other="failure"), 0),
            "behind main": ([], good, checks(), 3),
            "base freshness is unknown": ([], good, checks(), None),
        }.items():
            with self.subTest(reason=reason):
                self.assertTrue(any(reason in b for b in MODULE.ready_decision(HEAD, *state)[1]), reason)
