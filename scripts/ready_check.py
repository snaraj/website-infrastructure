#!/usr/bin/env python3
"""AGENTS.md's Ready rule, evaluated read-only: ELIGIBLE or every blocker.

The rule's one expression in code (issue #295), extracted from the promoter's
deleted auto-Ready machinery so no second copy can drift. It NEVER writes, so
running it is never an action: the coordinator reads it and flips. Exit 0
eligible, 3 blocked, 1 refused.
"""

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

REPOSITORY = "snaraj/website-infrastructure"
# A receipt binds to the review App's immutable identity, never to a login or
# a signature line alone: the bot user's id and type, and the App id it was
# performed through. A check from another writer is never the required check.
REVIEWS_APP = "snaraj-agent-reviews[bot]"
REVIEWS_APP_USER_ID = 318424677
REVIEWS_APP_ID = 4641855
REQUIRED_CHECKS = ("dependency-review", "repository-and-infrastructure")
REQUIRED_CHECK_APP = "github-actions"
ACCEPTABLE_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})


class Refusal(Exception):
    """A fail-closed judgment. The message names the check that failed."""


# The canonical shape: a receipt counted here is one the validator accepts.
_SPEC = importlib.util.spec_from_file_location("ready_check_review_receipt", Path(__file__).resolve().parent / "validate_review_receipt.py")
RECEIPTS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(RECEIPTS)


def gh(path, listing=False):
    """One bounded READ through the owner's own gh credential."""
    argv = ["gh", "api", "-H", "Accept: application/vnd.github+json", path]
    if listing:
        argv[2:2] = ["--paginate", "--slurp"]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal(f"`gh api {path}` could not be run: {type(error).__name__}") from None
    if done.returncode != 0:
        raise Refusal(f"`gh api {path}` exited {done.returncode}")
    decoded = json.loads(done.stdout) if done.stdout.strip() else {}
    return [item for page in decoded for item in page] if listing else decoded


def ready_decision(head, labels, comments, checks, behind_by):
    """Return ``(approving lanes, blockers)`` for one exact head."""
    blockers, verdicts = [], []
    for c in comments:
        body = c.get("body", "")
        # Only the review App's own comment is a receipt, and only in the
        # canonical shape: ``Opus 5`` and ``opus-5`` are the one lane opus5.
        if ((c.get("user") or {}).get("login"), (c.get("user") or {}).get("id"), (c.get("user") or {}).get("type"), (c.get("performed_via_github_app") or {}).get("id")) != (REVIEWS_APP, REVIEWS_APP_USER_ID, "Bot", REVIEWS_APP_ID):
            continue
        if RECEIPTS.denial(body, head, "pull-request") is not None:
            continue
        lines = body.replace("\r\n", "\n").splitlines()
        lane = RECEIPTS.SIGNATURE.fullmatch([line for line in lines if line.strip()][-1]).group(1)
        verdicts.append(([line[9:] for line in lines if line.startswith("VERDICT: ")][0], re.sub(r"[^a-z0-9]", "", lane.lower())))
    lanes = sorted({lane for verdict, lane in verdicts if verdict == "APPROVE" and lane})
    if any(verdict == "REQUEST-CHANGES" for verdict, _ in verdicts):
        blockers.append("a REQUEST-CHANGES receipt binds this head")
    if not lanes:
        blockers.append("no adversarial APPROVE receipt binds this head")
    if "requires-review" in labels:
        blockers.append("requires-review is still armed")
    for name in REQUIRED_CHECKS:
        found = [check for check in checks if check.get("name") == name]
        if len(found) != 1:
            blockers.append(f"required check {name} appears {len(found)} times at this head; exactly one authoritative run is required")
        elif (found[0].get("app") or {}).get("slug") != REQUIRED_CHECK_APP:
            blockers.append(f"required check {name} was not produced by {REQUIRED_CHECK_APP}")
        elif found[0].get("status") != "completed" or found[0].get("conclusion") != "success":
            blockers.append(f"required check {name} has not succeeded at this head")
    # Every completed check at the head, required or not, must have ended in a
    # conclusion meaning "nothing went wrong": every other terminal conclusion,
    # and any value this code has never seen, fails closed.
    for check in checks:
        if check.get("status") == "completed" and check.get("conclusion") not in ACCEPTABLE_CONCLUSIONS:
            blockers.append(f"a check at this head did not succeed: {check.get('name')} ended {check.get('conclusion')}")
    if behind_by is None:
        blockers.append("base freshness is unknown")
    elif behind_by:
        blockers.append(f"branch is {behind_by} commit(s) behind main")
    return lanes, blockers


def snapshot(repository, number):
    """Every input the rule reads, bound to the pull request's exact head."""
    pull = gh(f"repos/{repository}/pulls/{number}")
    head = (pull.get("head") or {}).get("sha") or ""
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise Refusal(f"PR #{number}: GitHub answered without one exact head")
    behind_by = gh(f"repos/{repository}/compare/main...{head}").get("behind_by")
    runs = gh(f"repos/{repository}/commits/{head}/check-runs?per_page=100")
    if runs.get("total_count") != len(runs.get("check_runs", [])):
        raise Refusal(f"PR #{number}: the check-run listing is truncated; refusing to judge a partial view")
    return {"head": head, "draft": pull.get("draft"), "behind_by": behind_by if isinstance(behind_by, int) else None,
            "labels": [label.get("name") for label in pull.get("labels") or []], "checks": runs["check_runs"],
            "comments": gh(f"repos/{repository}/issues/{number}/comments?per_page=100", listing=True)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("pull_request", type=int)
    parser.add_argument("--repo", default=REPOSITORY)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        pull = snapshot(args.repo, args.pull_request)
        lanes, blockers = ready_decision(pull["head"], pull["labels"], pull["comments"], pull["checks"], pull["behind_by"])
    except Refusal as error:
        print(f"DENY: {error}", file=sys.stderr)
        return 1
    report = {"head": pull["head"], "draft": pull["draft"], "approvingLanes": lanes, "blockers": blockers}
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else f"HEAD: {pull['head']}\nDRAFT: {pull['draft']}\nLANES: {', '.join(lanes) or 'none'}\n"
          + ("ELIGIBLE" if not blockers else "BLOCKED\n" + "\n".join(f"- {b}" for b in blockers)))
    return 3 if blockers else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
