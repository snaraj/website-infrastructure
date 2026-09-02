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


def main_worker_receipt(
    head=HEAD, role="MAIN-WORKER", verdict="PASS", worker="coordinator-context"
):
    return (
        f"HEAD: {head}\n"
        f"ROLE: {role}\n"
        f"VERDICT: {verdict}\n"
        f"SCOPE: {MODULE.MAIN_WORKER_SCOPE}\n\n"
        f"- {worker} (Main Worker)\n"
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
        # The byte ceiling, at both sides of the boundary.
        padded = receipt().replace("Claim audit:", "Claim audit:" + "x" * (MODULE.RECEIPT_BYTE_CEILING - len(receipt().encode())))
        self.assertIsNone(MODULE.denial(padded, HEAD, "pull-request"))
        self.assertIsNotNone(MODULE.denial(padded + "x", HEAD, "pull-request"))

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

    def test_cli_main_worker_mode_still_requires_an_author_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.txt"
            path.write_text(main_worker_receipt(), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(
                    MODULE.main(
                        [
                            str(path),
                            "--head",
                            HEAD,
                            "--resource-kind",
                            "pull-request",
                            "--receipt-kind",
                            "main-worker",
                            "--reviewer-context",
                            "reviewer-context",
                        ]
                    ),
                    1,
                )
            self.assertIn("requires the author context", errors.getvalue())


class MainWorkerReceiptTests(unittest.TestCase):
    def test_exact_head_role_scope_and_pass_are_ready_gate_inputs(self):
        self.assertIsNone(
            MODULE.main_worker_denial(
                main_worker_receipt(),
                HEAD,
                "author-context",
                "fresh-reviewer-context",
                "pull-request",
            )
        )

    def test_head_role_verdict_scope_resource_and_role_mutants_are_denied(self):
        cases = (
            (main_worker_receipt(head="b" * 40), "author-context", "reviewer-context", "pull-request", "PASS"),
            (main_worker_receipt() + f"HEAD: {HEAD}\n", "author-context", "reviewer-context", "pull-request", "PASS"),
            (main_worker_receipt(role="REVIEWER"), "author-context", "reviewer-context", "pull-request", "PASS"),
            (main_worker_receipt(verdict="BLOCK"), "author-context", "reviewer-context", "pull-request", "PASS"),
            (main_worker_receipt().replace(MODULE.MAIN_WORKER_SCOPE, "architecture"), "author-context", "reviewer-context", "pull-request", "PASS"),
            (main_worker_receipt(), "author-context", "reviewer-context", "issue", "PASS"),
            (main_worker_receipt(worker="author-context"), "author-context", "reviewer-context", "pull-request", "PASS"),
            (main_worker_receipt(worker="reviewer-context"), "author-context", "reviewer-context", "pull-request", "PASS"),
            (main_worker_receipt(), "same-context", "same-context", "pull-request", "PASS"),
            (main_worker_receipt().replace(" (Main Worker)", ""), "author-context", "reviewer-context", "pull-request", "PASS"),
        )
        for index, (text, author, reviewer, resource, verdict) in enumerate(cases):
            with self.subTest(receipt_mutant=index):
                self.assertIsNotNone(
                    MODULE.main_worker_denial(
                        text, HEAD, author, reviewer, resource, verdict
                    )
                )

    def test_cli_requires_main_worker_mode_reviewer_context_and_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.txt"
            path.write_text(main_worker_receipt(), encoding="utf-8")
            args = [
                str(path),
                "--head",
                HEAD,
                "--author-context",
                "author-context",
                "--reviewer-context",
                "reviewer-context",
                "--resource-kind",
                "pull-request",
                "--receipt-kind",
                "main-worker",
                "--required-verdict",
                "PASS",
            ]
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(MODULE.main(args), 0)
            self.assertEqual(output.getvalue().strip(), "ALLOW")
            path.write_text(main_worker_receipt(verdict="BLOCK"), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(MODULE.main(args), 1)
