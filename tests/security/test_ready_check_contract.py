"""Pin `scripts/ready_check.py`: the ReadyRuleTests cases that survived the promoter's deleted auto-Ready machinery, on the one-APPROVE rule."""

import unittest

from .support import load_script

MODULE = load_script("ready_check.py")
# The evaluator pins the promoter's label set itself rather than importing it
# from the tool it judges, so changing that tool cannot widen what Ready
# accepts. Drift is caught HERE instead: the emitter's own constants are read
# and compared below, so the two cannot disagree without a red test.
PROMOTER = load_script("promote_releases.py", module_name="ready_check_promoter_labels")
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


def comment(head=HEAD, verdict="APPROVE", lane="Opus5", login=MODULE.REVIEWS_APP, uid=MODULE.REVIEWS_APP_USER_ID, kind="Bot", app=MODULE.REVIEWS_APP_ID, at="2026-09-04T00:00:00Z"):
    body = f"HEAD: {head}\nVERDICT: {verdict}\n\nMutation matrix and claim audit: supported.\n\n- {lane} (adversarial reviewer)\n"
    return {"user": {"login": login, "id": uid, "type": kind}, "performed_via_github_app": {"id": app}, "body": body, "created_at": at}


def checks(conclusion="success", app=MODULE.REQUIRED_CHECK_APP, other="neutral"):
    return [{"name": n, "status": "completed", "conclusion": conclusion, "app": {"slug": app}} for n in MODULE.REQUIRED_CHECKS] + [{"name": "CodeQL", "status": "completed", "conclusion": other, "app": {"slug": "github-code-scanning"}}]


class ReadyRuleTests(unittest.TestCase):
    def test_one_exact_head_approval_from_the_app_with_green_checks_is_eligible(self):
        self.assertEqual(decide(comments=[comment(lane="Opus 5")]), (["opus5"], ["security"], []))
        self.assertEqual(MODULE.ACCEPTABLE_CONCLUSIONS, frozenset({"success", "neutral", "skipped"}), "the allowlist is the contract; widen it only with a case here")

    def test_a_comment_newer_than_the_receipt_is_outstanding_and_blocks(self):
        # AGENTS.md: the flip happens only when no owner or peer comment is
        # outstanding. A comment the reviewer never saw is outstanding.
        owner = {"user": {"login": "snaraj", "id": 1, "type": "User"}, "body": "BLOCK", "created_at": "2026-09-04T00:00:01Z"}
        blocker = "a comment by snaraj is newer than the APPROVE receipt and outstanding"
        self.assertIn(blocker, decide(comments=[comment(), owner])[2])
        self.assertEqual(decide(comments=[comment(), dict(owner, created_at="2026-09-03T23:59:59Z")])[2], [],
                         "a comment the reviewer could see is not outstanding")
        undated = {key: value for key, value in owner.items() if key != "created_at"}
        self.assertIn(blocker, decide(comments=[comment(), undated])[2], "a comment without a time fails closed")
        # A newer receipt at the same head clears an older comment.
        self.assertEqual(decide(comments=[comment(), owner, comment(at="2026-09-04T00:00:02Z")])[2], [])

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


class PromoterTupleTests(unittest.TestCase):
    """AGENTS.md: the receipted promoter "is NOT an agent: its pull requests
    carry `promoter` in place of the agent pair", and its standing authority
    names one exact label set. The evaluator demanded the agent pair from every
    author anyway, so no promotion pull request could be judged Ready; the first
    repair waived only the umbrella label, which let `promoter` stand beside an
    acting-model label, a foreign tier, or a partial tuple (PR #303, findings 1).
    `promoter` is an exact ALTERNATIVE, so the accepted set is compared whole.
    """

    # `requires-review` is armed at open and removed by the reviewer with either
    # verdict, so the set a Ready evaluation ever sees is the emitted one minus
    # it. Derived from the emitter, never retyped.
    EMITTED = sorted(set(PROMOTER.PR_LABELS + PROMOTER.REVIEW_LABELS) - {MODULE.REVIEW_ATTENTION_LABEL})

    def test_the_evaluator_and_the_promoter_name_the_same_tuple(self):
        # The evaluator pins its own copy so the tool it judges cannot widen it;
        # this is the only thing keeping the two honest, so it is a test, not a
        # comment. Change one tuple without the other and this goes red.
        self.assertEqual(MODULE.PROMOTER_TUPLE, frozenset(self.EMITTED))
        self.assertIn(MODULE.PROMOTER_LABEL, MODULE.PROMOTER_TUPLE)

    def test_the_exact_promoter_tuple_is_eligible(self):
        lanes, tiers, blockers = decide(labels=list(self.EMITTED))
        self.assertEqual(blockers, [], "the labels the promoter emits must satisfy the rule it must pass")
        self.assertEqual((lanes, tiers), (["opus5"], ["delivery-lane", "release", "security"]))

    def test_each_listed_hybrid_of_the_promoter_tuple_is_denied(self):
        # Every shape here was ELIGIBLE with zero blockers under the first
        # repair; the first is the live metadata PR #303 itself wore.
        for reason, labels in (
            ("unexpected opus5", self.EMITTED + ["opus5"]),
            ("unexpected fable5, unexpected tests", [MODULE.PROMOTER_LABEL, "fable5", "tests"]),
            ("unexpected docs", [MODULE.PROMOTER_LABEL, "docs"]),
            ("unexpected agent-authored", self.EMITTED + [MODULE.UMBRELLA_LABEL]),
            ("missing release", [n for n in self.EMITTED if n != "release"]),
            ("missing delivery-lane", [n for n in self.EMITTED if n != "delivery-lane"]),
            ("missing security", [n for n in self.EMITTED if n != MODULE.SECURITY_TIER_LABEL]),
            # Issue #309 dropped this label from the promoter's set: a promotion
            # earns its receipt by re-derivation instead. Adding it back is now a
            # hybrid like any other, and the exact-set comparison says so.
            ("unexpected cybersecurity-review-requested", self.EMITTED + [MODULE.SECURITY_REVIEW_LABEL]),
        ):
            with self.subTest(reason=reason):
                blockers = decide(labels=labels)[2]
                self.assertTrue(any(f"{MODULE.PROMOTER_LABEL} pins an exact label set: " in b and reason in b for b in blockers), (reason, blockers))

    def test_the_promoter_still_waits_for_the_review_it_armed(self):
        # `requires-review` is reported by its own blocker, so the exact-set
        # comparison deliberately ignores it rather than reporting it twice.
        blockers = decide(labels=self.EMITTED + [MODULE.REVIEW_ATTENTION_LABEL])[2]
        self.assertEqual(blockers, [f"{MODULE.REVIEW_ATTENTION_LABEL} is still armed"])

    def test_an_ordinary_pull_request_still_needs_the_umbrella_label(self):
        # Drop only `promoter` and BOTH ordinary-author rules return — the
        # umbrella label and the security tier/review pair — so neither
        # exception can be inherited by anything else wearing these labels.
        without = [name for name in self.EMITTED if name != MODULE.PROMOTER_LABEL]
        self.assertEqual(decide(labels=without)[2], [
            f"the pull request is missing the {MODULE.UMBRELLA_LABEL} umbrella label",
            f"conflicting tier labels: exactly one of {MODULE.SECURITY_TIER_LABEL} and {MODULE.SECURITY_REVIEW_LABEL} is present",
        ])
        self.assertEqual(decide(labels=without + [MODULE.UMBRELLA_LABEL, MODULE.SECURITY_REVIEW_LABEL])[2], [])
