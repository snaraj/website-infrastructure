#!/usr/bin/env python3
"""Create one exact promoted release candidate without in-place editing."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from create_release_patch import PatchError, read_regular_lf
from write_review_artifact import ArtifactError, write_exclusive


DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
DIGEST_LINE_RE = re.compile(
    r"^      digest: sha256:[0-9a-f]{64}$", re.MULTILINE
)
INITIAL_READY_RE = re.compile(r"^    deploymentReady: false$", re.MULTILINE)
PROMOTED_READY_RE = re.compile(r"^    deploymentReady: true$", re.MULTILINE)


class CandidateError(ValueError):
    """The requested release candidate is not one exact state transition."""


def create_candidate(
    original: Path, output: Path, digest: str, initial_phase: str
) -> None:
    if not DIGEST_RE.fullmatch(digest) or digest == "sha256:" + ("0" * 64):
        raise CandidateError("candidate digest is not one canonical nonzero digest")
    try:
        text = read_regular_lf(original)
    except PatchError as error:
        raise CandidateError("candidate source cannot be read safely") from error

    text, digest_count = DIGEST_LINE_RE.subn("      digest: " + digest, text)
    if digest_count != 1:
        raise CandidateError("candidate source lacks one exact digest target")
    if initial_phase == "initial":
        text, readiness_count = INITIAL_READY_RE.subn(
            "    deploymentReady: true", text
        )
        if readiness_count != 1 or PROMOTED_READY_RE.findall(text) != [
            "    deploymentReady: true"
        ]:
            raise CandidateError("initial candidate lacks one exact readiness target")
    elif initial_phase == "promoted":
        if INITIAL_READY_RE.search(text) or PROMOTED_READY_RE.findall(text) != [
            "    deploymentReady: true"
        ]:
            raise CandidateError("promoted candidate readiness is not exact")
    else:
        raise CandidateError("candidate source phase is outside the closed allowlist")

    raw = text.encode("utf-8")
    try:
        write_exclusive(output, raw)
    except ArtifactError as error:
        raise CandidateError("candidate output cannot be created exclusively") from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--initial-phase", choices=("initial", "promoted"), required=True)
    args = parser.parse_args(argv)
    try:
        create_candidate(args.original, args.output, args.digest, args.initial_phase)
    except CandidateError:
        print("ERROR release candidate could not be created safely", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
