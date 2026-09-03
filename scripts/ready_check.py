#!/usr/bin/env python3
"""AGENTS.md's Ready rule, evaluated read-only: ELIGIBLE or every blocker.

The rule's one expression in code (issue #295), extracted from the promoter's
deleted auto-Ready machinery so no second copy can drift. It NEVER writes, so
running it is never an action: the coordinator reads it and flips. Exit 0
eligible, 3 blocked, 1 refused.

What it proves is exactly: the pull request is open, targets its repository's
default branch, is not behind that branch, carries an App-posted exact-head
APPROVE with no REQUEST-CHANGES at the same head, has every required check
green, and still carries the metadata AGENTS.md requires. What it does NOT
decide is whether the lanes that approved are the right lanes for this change's
risk tier: AGENTS.md pins no model roster and binds independence to the posting
actor rather than the signature wording, so this prints the approving lanes and
the tier labels side by side and leaves that judgment to the coordinator.
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
# AGENTS.md: every agent-created pull request carries the umbrella label, and
# one taxonomy label is what tells a reader which review tier the change earns.
# A pull request wearing neither cannot have its tier judged, so it fails closed.
UMBRELLA_LABEL = "agent-authored"
TIER_LABELS = frozenset({
    "production-readiness", "conventions", "security", "tests", "ci", "docs",
    "release", "fix", "provider-neutrality", "delivery-lane", "features",
    "platform", "extraction",
})
# The receipted release promoter "is NOT an agent: its pull requests carry
# `promoter` in place of the agent pair" (AGENTS.md, Agent labels). Demanding
# the umbrella label of it would ask an automation to claim an authorship it
# does not have, and a pull request wearing BOTH asserts two provenances at
# once — so the promoter label replaces the umbrella requirement rather than
# waiving it, and the pair together is a contradiction.
PROMOTER_LABEL = "promoter"
# The security-surface tier and the label that arms its reviewer travel
# together; exactly one of them is a metadata contradiction, not a tier.
SECURITY_TIER_LABEL = "security"
SECURITY_REVIEW_LABEL = "cybersecurity-review-requested"


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


def ready_decision(head, labels, comments, checks, behind_by, state=None, base_ref=None, default_branch=None):
    """Return ``(approving lanes, blockers)`` for one exact head.

    ``state``, ``base_ref`` and ``default_branch`` are read from the pull
    request itself; a missing or unreadable one is a blocker rather than an
    omission, because every one of them decides WHICH pull request this is.
    """
    blockers, verdicts = [], []
    if state != "open":
        blockers.append(f"the pull request is not open (state: {state or 'unreadable'})")
    if not base_ref or not default_branch:
        blockers.append("the pull request's base branch is missing or unreadable")
    elif base_ref != default_branch:
        blockers.append(f"the pull request targets {base_ref}, not the default branch {default_branch}")
    if labels is None:
        blockers.append("the pull request's labels are missing or unreadable")
        labels = []
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
    tiers = sorted(TIER_LABELS.intersection(labels))
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
    # Every check at the head, required or not, must have FINISHED and ended in
    # a conclusion meaning "nothing went wrong". A queued or in-progress run has
    # no verdict yet, so it cannot be green: AGENTS.md permits the flip only
    # when every check is green at the exact head, and a run still executing can
    # still fail. Every other terminal conclusion, and any status or conclusion
    # value this code has never seen, fails closed the same way.
    for check in checks:
        if check.get("status") != "completed":
            blockers.append(f"a check at this head has not finished: {check.get('name')} is {check.get('status')}")
        elif check.get("conclusion") not in ACCEPTABLE_CONCLUSIONS:
            blockers.append(f"a check at this head did not succeed: {check.get('name')} ended {check.get('conclusion')}")
    if not tiers:
        blockers.append("the pull request carries no tier label, so its review depth cannot be judged")
    if PROMOTER_LABEL in labels:
        if UMBRELLA_LABEL in labels:
            blockers.append(f"conflicting provenance labels: {PROMOTER_LABEL} stands in place of {UMBRELLA_LABEL}, never beside it")
    elif UMBRELLA_LABEL not in labels:
        blockers.append(f"the pull request is missing the {UMBRELLA_LABEL} umbrella label")
    if (SECURITY_TIER_LABEL in labels) != (SECURITY_REVIEW_LABEL in labels):
        blockers.append(f"conflicting tier labels: exactly one of {SECURITY_TIER_LABEL} and {SECURITY_REVIEW_LABEL} is present")
    if behind_by is None:
        blockers.append("base freshness is unknown")
    elif behind_by:
        blockers.append(f"branch is {behind_by} commit(s) behind {base_ref or 'its base'}")
    return lanes, tiers, blockers


def snapshot(repository, number):
    """Every input the rule reads, bound to the pull request's exact head."""
    pull = gh(f"repos/{repository}/pulls/{number}")
    head = (pull.get("head") or {}).get("sha") or ""
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise Refusal(f"PR #{number}: GitHub answered without one exact head")
    base = pull.get("base") or {}
    base_ref = base.get("ref")
    default_branch = ((base.get("repo") or {}).get("default_branch"))
    # Freshness is measured against the branch this pull request actually
    # targets. Comparing a fixed name would answer about a different branch.
    behind_by = None
    if base_ref:
        behind_by = gh(f"repos/{repository}/compare/{base_ref}...{head}").get("behind_by")
    runs = gh(f"repos/{repository}/commits/{head}/check-runs?per_page=100")
    if runs.get("total_count") != len(runs.get("check_runs", [])):
        raise Refusal(f"PR #{number}: the check-run listing is truncated; refusing to judge a partial view")
    raw_labels = pull.get("labels")
    return {"head": head, "draft": pull.get("draft"), "behind_by": behind_by if isinstance(behind_by, int) else None,
            "state": pull.get("state"), "baseRef": base_ref, "defaultBranch": default_branch,
            "labels": None if raw_labels is None else [label.get("name") for label in raw_labels],
            "checks": runs["check_runs"],
            "comments": gh(f"repos/{repository}/issues/{number}/comments?per_page=100", listing=True)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("pull_request", type=int)
    parser.add_argument("--repo", default=REPOSITORY)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        pull = snapshot(args.repo, args.pull_request)
        lanes, tiers, blockers = ready_decision(pull["head"], pull["labels"], pull["comments"], pull["checks"],
                                                pull["behind_by"], pull["state"], pull["baseRef"], pull["defaultBranch"])
    except Refusal as error:
        print(f"DENY: {error}", file=sys.stderr)
        return 1
    report = {"head": pull["head"], "draft": pull["draft"], "state": pull["state"], "baseRef": pull["baseRef"],
              "approvingLanes": lanes, "tierLabels": tiers, "blockers": blockers}
    # Lanes and tiers are printed side by side deliberately: whether these
    # lanes are the right reviewers for this tier is the coordinator's call.
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else
          f"HEAD: {pull['head']}\nSTATE: {pull['state']} -> {pull['baseRef']}\nDRAFT: {pull['draft']}\n"
          f"LANES: {', '.join(lanes) or 'none'}\nTIERS: {', '.join(tiers) or 'none'}\n"
          "(whether these lanes suit these tiers is the coordinator's judgment, not this tool's)\n"
          + ("ELIGIBLE" if not blockers else "BLOCKED\n" + "\n".join(f"- {b}" for b in blockers)))
    return 3 if blockers else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
