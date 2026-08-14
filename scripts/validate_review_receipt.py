#!/usr/bin/env python3
"""Validate exact-head adversarial-review and Main Worker receipt shapes."""

import argparse
import re
import sys
from pathlib import Path


SHA = re.compile(r"^[0-9a-f]{40}$")
SIGNATURE = re.compile(r"^- (.+?) \(adversarial reviewer\)$")
MAIN_WORKER_SIGNATURE = re.compile(r"^- (.+?) \(Main Worker\)$")
VERDICTS = frozenset({"APPROVE", "REQUEST-CHANGES"})
MAIN_WORKER_VERDICTS = frozenset({"BLOCK", "PASS"})
MAIN_WORKER_SCOPE = (
    "architecture,merge-order,authority,settings,base-freshness,required-checks"
)


def denial(text, expected_head, author_context, resource_kind):
    if resource_kind != "pull-request":
        return "exact-head review receipts apply only to pull requests"
    if not SHA.fullmatch(expected_head):
        return "expected head is not one lowercase 40-hex SHA"
    lines = text.replace("\r\n", "\n").splitlines()
    heads = [line[6:] for line in lines if line.startswith("HEAD: ")]
    verdicts = [line[9:] for line in lines if line.startswith("VERDICT: ")]
    if heads != [expected_head]:
        return "receipt must bind exactly one expected HEAD line"
    if len(verdicts) != 1 or verdicts[0] not in VERDICTS:
        return "receipt must contain exactly one supported VERDICT line"
    nonempty = [line for line in lines if line.strip()]
    if not nonempty:
        return "receipt is empty"
    match = SIGNATURE.fullmatch(nonempty[-1])
    if not match:
        return "final non-empty line must be adversarial reviewer signature"
    reviewer = match.group(1).strip().casefold()
    if not reviewer or reviewer == author_context.strip().casefold():
        return "reviewer context must differ textually from author context"
    if "mutation" not in text.casefold() or "claim" not in text.casefold():
        return "receipt must report mutation and claim audit evidence"
    return None


def main_worker_denial(
    text,
    expected_head,
    author_context,
    reviewer_context,
    resource_kind,
    required_verdict="PASS",
):
    """Require one fresh, role-separated, bounded Ready-coordination receipt."""
    if resource_kind != "pull-request":
        return "Main Worker receipts apply only to pull requests"
    if not SHA.fullmatch(expected_head):
        return "expected head is not one lowercase 40-hex SHA"
    if required_verdict not in MAIN_WORKER_VERDICTS:
        return "required Main Worker verdict is unsupported"
    lines = text.replace("\r\n", "\n").splitlines()
    heads = [line[6:] for line in lines if line.startswith("HEAD: ")]
    roles = [line[6:] for line in lines if line.startswith("ROLE: ")]
    verdicts = [line[9:] for line in lines if line.startswith("VERDICT: ")]
    scopes = [line[7:] for line in lines if line.startswith("SCOPE: ")]
    if heads != [expected_head]:
        return "Main Worker receipt must bind exactly one expected HEAD line"
    if roles != ["MAIN-WORKER"]:
        return "Main Worker receipt must contain exactly ROLE: MAIN-WORKER"
    if verdicts != [required_verdict]:
        return "Main Worker receipt does not carry the exact required verdict"
    if scopes != [MAIN_WORKER_SCOPE]:
        return "Main Worker receipt scope is missing, widened, or reordered"
    nonempty = [line for line in lines if line.strip()]
    if not nonempty:
        return "Main Worker receipt is empty"
    match = MAIN_WORKER_SIGNATURE.fullmatch(nonempty[-1])
    if not match:
        return "final non-empty line must be Main Worker signature"
    worker = match.group(1).strip().casefold()
    excluded = {
        author_context.strip().casefold(),
        reviewer_context.strip().casefold(),
    }
    if (
        not worker
        or not all(excluded)
        or len(excluded) != 2
        or worker in excluded
    ):
        return "Main Worker context must differ textually from author and reviewer"
    return None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--head", required=True)
    parser.add_argument("--author-context", required=True)
    parser.add_argument("--resource-kind", required=True)
    parser.add_argument(
        "--receipt-kind",
        choices=("adversarial-review", "main-worker"),
        default="adversarial-review",
    )
    parser.add_argument("--reviewer-context")
    parser.add_argument(
        "--required-verdict", choices=("APPROVE", "REQUEST-CHANGES", "PASS", "BLOCK")
    )
    args = parser.parse_args(argv)
    try:
        text = args.receipt.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    if args.receipt_kind == "adversarial-review":
        if args.reviewer_context is not None or args.required_verdict not in (
            None,
            "APPROVE",
            "REQUEST-CHANGES",
        ):
            reason = "adversarial-review receipt options are inconsistent"
        else:
            reason = denial(text, args.head, args.author_context, args.resource_kind)
            if reason is None and args.required_verdict is not None:
                lines = text.replace("\r\n", "\n").splitlines()
                if [line[9:] for line in lines if line.startswith("VERDICT: ")] != [
                    args.required_verdict
                ]:
                    reason = "adversarial-review receipt does not carry the required verdict"
    else:
        if args.reviewer_context is None:
            reason = "Main Worker receipt requires the adversarial reviewer context"
        elif args.required_verdict not in (None, "PASS", "BLOCK"):
            reason = "Main Worker receipt options are inconsistent"
        else:
            reason = main_worker_denial(
                text,
                args.head,
                args.author_context,
                args.reviewer_context,
                args.resource_kind,
                args.required_verdict or "PASS",
            )
    if reason:
        print(f"DENY: {reason}", file=sys.stderr)
        return 1
    print("ALLOW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
