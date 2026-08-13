import unittest

from .support import load_script


MODULE = load_script("validate_review_receipt.py")
HEAD = "a" * 40


def receipt(head=HEAD, verdict="APPROVE", reviewer="fresh-context"):
    return (
        f"HEAD: {head}\n"
        f"VERDICT: {verdict}\n\n"
        "Claim audit: supported.\n"
        "Mutation matrix: all load-bearing.\n\n"
        f"- {reviewer} (adversarial reviewer)\n"
    )


class ReviewReceiptTests(unittest.TestCase):
    def test_accepts_exact_head_signed_normal_comment_shape(self):
        self.assertIsNone(
            MODULE.denial(receipt(), HEAD, "author-context", "pull-request")
        )

    def test_issue_labels_cannot_be_mistaken_for_a_reviewable_pr_head(self):
        self.assertEqual(
            MODULE.denial(receipt(), HEAD, "author-context", "issue"),
            "exact-head review receipts apply only to pull requests",
        )
        self.assertEqual(
            MODULE.denial(receipt(), HEAD, "author-context", ""),
            "exact-head review receipts apply only to pull requests",
        )

    def test_head_change_and_every_receipt_evasion_fail(self):
        cases = (
            (receipt(head="b" * 40), "author-context"),
            (receipt() + f"HEAD: {HEAD}\n", "author-context"),
            (receipt(verdict="LGTM"), "author-context"),
            (receipt() + "VERDICT: REQUEST-CHANGES\n", "author-context"),
            (receipt(reviewer="author-context"), "author-context"),
            (receipt().replace("Mutation matrix", "Experiments"), "author-context"),
            (receipt().replace("Claim audit", "Summary"), "author-context"),
            (receipt().replace("- fresh-context (adversarial reviewer)", "- fresh-context"), "author-context"),
        )
        for text, author in cases:
            with self.subTest(text=text):
                self.assertIsNotNone(
                    MODULE.denial(text, HEAD, author, "pull-request")
                )
