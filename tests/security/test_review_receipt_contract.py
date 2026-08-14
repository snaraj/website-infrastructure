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
