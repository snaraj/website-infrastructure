#!/usr/bin/env python3
"""Validate exact-head adversarial-review and Main Worker receipt shapes.

This validator proves TEXT SHAPE and nothing else. It never sees who posted a
comment, which is where AGENTS.md locates reviewer independence, and it never
confers Ready or merge authority. The `main-worker` receipt kind below is
contract-retired and kept only until issue #188 removes its remaining call
sites; see its docstring.
"""

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


def denial(text, expected_head, resource_kind):
    """Validate one exact-head adversarial-review receipt's SHAPE, and only that.

    Reviewer independence is NOT decided here and deliberately cannot be: per
    AGENTS.md "Reviewer independence" it binds to the POSTING ACTOR — the
    review App that publishes the comment — and this script is handed a text
    file with no author metadata attached, so it can never observe who posted
    it. The coordinator reads that from the forge.

    Until issue #203 this function also required the reviewer's signature to
    differ textually from an author-context string. That check was retired
    rather than repaired: a reviewer satisfies a textual comparison by typing
    a different word, so it proved only that the reviewer can type, while
    making the contract's own explicitly permitted same-lane review
    unrepresentable. What remains is a closed shape — one bound head, one
    supported verdict, a lane-provenance signature, and the audit evidence a
    verdict must carry — every part of which a real receipt satisfies and a
    forged or stale one does not.
    """

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
    # The signature is lane provenance, so it must name a lane; it is never
    # compared against the author, only required to be present and non-blank.
    if not match.group(1).strip():
        return "adversarial reviewer signature must name the reviewing lane"
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
    """Require one fresh, role-separated, bounded Ready-coordination receipt.

    TRANSITIONAL. The Main Worker Ready receipt is RETIRED in contract: per
    AGENTS.md the coordinator flips Ready straight after an exact-head
    APPROVE, and no receipt of this kind is a Ready input. This kind stays
    executable only so the skill, template, and gate rows that still name it
    are removed together by issue #188's machinery pass, rather than leaving
    documented call sites pointing at an absent capability. Do not build new
    call sites on it.
    """
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
    # Optional for adversarial-review receipts since issue #203 retired the
    # textual author/reviewer comparison; documented call sites that still
    # pass it keep working. The retired main-worker kind still requires it.
    parser.add_argument("--author-context")
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
            reason = denial(text, args.head, args.resource_kind)
            if reason is None and args.required_verdict is not None:
                lines = text.replace("\r\n", "\n").splitlines()
                if [line[9:] for line in lines if line.startswith("VERDICT: ")] != [
                    args.required_verdict
                ]:
                    reason = "adversarial-review receipt does not carry the required verdict"
    else:
        if args.author_context is None:
            reason = "Main Worker receipt requires the author context"
        elif args.reviewer_context is None:
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
