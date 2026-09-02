#!/usr/bin/env python3
"""Validate the exact-head adversarial-review receipt shape.

This validator proves TEXT SHAPE and nothing else. It never sees who posted a
comment, which is where AGENTS.md locates reviewer independence, and it never
confers Ready or merge authority.
"""

import argparse
import re
import sys
from pathlib import Path


SHA = re.compile(r"^[0-9a-f]{40}$")
SIGNATURE = re.compile(r"^- (.+?) \(adversarial reviewer\)$")
VERDICTS = frozenset({"APPROVE", "REQUEST-CHANGES"})
# A verdict the owner reads in one sitting: AGENTS.md caps a receipt here.
RECEIPT_BYTE_CEILING = 6000


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
    if len(text.encode("utf-8")) > RECEIPT_BYTE_CEILING:
        return f"receipt exceeds the {RECEIPT_BYTE_CEILING}-byte ceiling"
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


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--head", required=True)
    # Accepted but ignored since issue #203 retired the textual
    # author/reviewer comparison; documented call sites that still pass it
    # keep working.
    parser.add_argument("--author-context")
    parser.add_argument("--resource-kind", required=True)
    parser.add_argument(
        "--required-verdict", choices=("APPROVE", "REQUEST-CHANGES")
    )
    args = parser.parse_args(argv)
    try:
        text = args.receipt.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    reason = denial(text, args.head, args.resource_kind)
    if reason is None and args.required_verdict is not None:
        lines = text.replace("\r\n", "\n").splitlines()
        if [line[9:] for line in lines if line.startswith("VERDICT: ")] != [
            args.required_verdict
        ]:
            reason = "receipt does not carry the required verdict"
    if reason:
        print(f"DENY: {reason}", file=sys.stderr)
        return 1
    print("ALLOW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
