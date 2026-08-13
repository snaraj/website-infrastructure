#!/usr/bin/env python3
"""Validate the portable exact-PR-head adversarial review receipt shape."""

import argparse
import re
import sys
from pathlib import Path


SHA = re.compile(r"^[0-9a-f]{40}$")
SIGNATURE = re.compile(r"^- (.+?) \(adversarial reviewer\)$")
VERDICTS = frozenset({"APPROVE", "REQUEST-CHANGES"})


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


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--head", required=True)
    parser.add_argument("--author-context", required=True)
    parser.add_argument("--resource-kind", required=True)
    args = parser.parse_args(argv)
    try:
        text = args.receipt.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    reason = denial(text, args.head, args.author_context, args.resource_kind)
    if reason:
        print(f"DENY: {reason}", file=sys.stderr)
        return 1
    print("ALLOW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
