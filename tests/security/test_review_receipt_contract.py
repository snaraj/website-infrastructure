import contextlib
import io
import tempfile
import unittest
from pathlib import Path

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
        self.assertIsNone(MODULE.denial(receipt(), HEAD, "pull-request"))

    def test_same_lane_review_passes_because_the_actor_is_the_boundary(self):
        """Issue #203: independence binds to the POSTING ACTOR, not to wording.

        A receipt whose reviewing lane is spelled exactly like the authoring
        lane — the ordinary case when one model both authors and reviews, which
        AGENTS.md expressly permits — must validate. The old textual
        author/reviewer comparison made that case unrepresentable while proving
        only that the reviewer could type a different word; the App that posts
        the comment is what makes the receipt a second party, and this script
        never sees it.
        """

        self.assertIsNone(MODULE.denial(receipt(reviewer="Opus5"), HEAD, "pull-request"))
        # No author context can reach the shape check at all, so no invented
        # `--author-context` string can be tried until the validator says ALLOW.
        self.assertEqual(
            MODULE.denial.__code__.co_varnames[
                : MODULE.denial.__code__.co_argcount
            ],
            ("text", "expected_head", "resource_kind"),
        )

    def test_issue_labels_cannot_be_mistaken_for_a_reviewable_pr_head(self):
        self.assertEqual(
            MODULE.denial(receipt(), HEAD, "issue"),
            "exact-head review receipts apply only to pull requests",
        )
        self.assertEqual(
            MODULE.denial(receipt(), HEAD, ""),
            "exact-head review receipts apply only to pull requests",
        )

    def test_head_change_and_every_receipt_evasion_fail(self):
        cases = (
            receipt(head="b" * 40),
            receipt() + f"HEAD: {HEAD}\n",
            receipt(verdict="LGTM"),
            receipt() + "VERDICT: REQUEST-CHANGES\n",
            receipt().replace("Mutation matrix", "Experiments"),
            receipt().replace("Claim audit", "Summary"),
            receipt().replace("- fresh-context (adversarial reviewer)", "- fresh-context"),
            # A signature that names no lane is not provenance: the shape check
            # that survived #203 still refuses a blank reviewing identity.
            receipt(reviewer=" "),
            "",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertIsNotNone(MODULE.denial(text, HEAD, "pull-request"))
        self.assertIsNotNone(MODULE.denial(receipt(), "B" * 40, "pull-request"))

    def test_the_byte_ceiling_denies_for_SIZE_at_the_exact_boundary(self):
        """The padding goes BEFORE the signature, so only size can deny it.

        Appending the extra byte after the final signature line would make the
        receipt invalid for a second reason — the signature would no longer be
        the last non-empty line — and the case would still deny with the
        ceiling removed, proving nothing. Padding the body keeps the receipt
        otherwise perfectly valid, so the ONLY thing separating the two
        assertions below is one byte crossing the cap.
        """

        def sized(total):
            base = receipt()
            pad = total - len(base.encode("utf-8"))
            self.assertGreater(pad, 0)
            return base.replace("Claim audit: supported.", "Claim audit: supported." + "x" * pad)

        at_cap = sized(MODULE.RECEIPT_BYTE_CEILING)
        over_cap = sized(MODULE.RECEIPT_BYTE_CEILING + 1)
        self.assertEqual(len(at_cap.encode("utf-8")), MODULE.RECEIPT_BYTE_CEILING)
        self.assertEqual(len(over_cap.encode("utf-8")), MODULE.RECEIPT_BYTE_CEILING + 1)
        # Both are otherwise valid: the signature is still the final line.
        self.assertIsNone(MODULE.denial(at_cap, HEAD, "pull-request"))
        self.assertEqual(
            MODULE.denial(over_cap, HEAD, "pull-request"),
            f"receipt exceeds the {MODULE.RECEIPT_BYTE_CEILING}-byte ceiling",
        )

    def test_cli_validates_shape_without_an_author_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.txt"
            path.write_text(receipt(reviewer="Opus5"), encoding="utf-8")
            args = [
                str(path),
                "--head",
                HEAD,
                "--resource-kind",
                "pull-request",
                "--required-verdict",
                "APPROVE",
            ]
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(MODULE.main(args), 0)
            self.assertEqual(output.getvalue().strip(), "ALLOW")
            # The retired option is still accepted, and identical author and
            # reviewer strings no longer deny.
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    MODULE.main(args + ["--author-context", "Opus5"]), 0
                )
            self.assertEqual(output.getvalue().strip(), "ALLOW")
            path.write_text(receipt(verdict="REQUEST-CHANGES"), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(MODULE.main(args), 1)
