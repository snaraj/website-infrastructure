"""Allow/deny rules for the repository PR flow.

Pure policy: no Git execution, no network, no credentials. The gh-pr-flow
skill and its contract tests are the only intended callers. Rules are
generic over repositories; nothing here names a website or a provider.

Deny-by-construction targets:
  - authoring on or pushing to a protected integration target (main),
  - force pushes and deletions of any remote ref,
  - tag or non-branch ref creation from the PR flow,
  - branch names outside the reviewed namespaces or with unsafe characters.
"""

import re
import sys

PROTECTED_BRANCHES = frozenset({"main", "master", "HEAD"})

# The agent lanes, spelled exactly as the repository's agent labels are. This
# tuple is the ONE place a new model lane is added, and the contract test binds
# it to the agent-label roster written into AGENTS.md, so a lane documented
# there but missing here fails loudly instead of silently denying real work.
#
# Before issue #137 this file listed only two lanes, so `opus5/...`,
# `opus4.8/...`, `sonnet5/...` and `daybreak-blue/...` all returned DENY —
# every lane the label taxonomy gained after the file was written.
AGENT_LANES = (
    "5.6-sol",
    "daybreak-blue",
    "fable5",
    "opus4.8",
    "opus5",
    "sonnet5",
)

# The dispatched reasoning effort carried by the newer branch grammar,
# `<lane>-<effort>/<issue#>-<topic>`. The effort lives inside the FIRST
# segment, which is why lane matching must be longest-first (see parse_lane).
REASONING_EFFORTS = ("low", "med", "high", "max")

# Work namespaces that belong to no particular lane.
GENERIC_NAMESPACES = (
    "deploy/",
    "import/",
    "ci/",
    "docs/",
    "feat/",
    "fix/",
    "chore/",
    "media/",
)

# Every accepted first segment, as prefixes. A single flat name such as
# "fix-typo" is rejected: namespacing keeps ownership and cleanup auditable.
ALLOWED_NAMESPACES = (
    tuple(lane + "/" for lane in AGENT_LANES)
    + tuple(
        "{}-{}/".format(lane, effort)
        for lane in AGENT_LANES
        for effort in REASONING_EFFORTS
    )
    + GENERIC_NAMESPACES
)

_BRANCH_SHAPE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
# `<issue#>-<topic>`: the remainder the newer grammar requires, so a branch
# that advertises a dispatched effort still says which issue it is working.
_ISSUE_TOPIC = re.compile(r"^[0-9]+-[a-z0-9]")


def parse_lane(name, lanes=AGENT_LANES):
    """Split a branch name into ``(lane, effort, remainder)``, or None.

    ``lanes`` is injectable so the longest-match rule can be exercised against
    a registry that actually contains an ambiguous pair: the live registry may
    not always have one, and a rule that no input can violate is a rule
    nothing proves.

    Longest match first is load-bearing. When a shorter lane is a prefix of a
    longer one and the leftover spells a valid effort, shortest-first parsing
    assigns the branch to the WRONG lane — and lane ownership is exactly what
    the one-writer-per-branch and cleanup rules are keyed on. `daybreak-blue`
    is the live hyphenated lane that makes this shape realistic.
    """

    head, separator, remainder = name.partition("/")
    if not separator:
        return None
    for lane in sorted(lanes, key=len, reverse=True):
        if head == lane:
            return lane, None, remainder
        if head.startswith(lane + "-"):
            effort = head[len(lane) + 1:]
            if effort in REASONING_EFFORTS:
                return lane, effort, remainder
    return None

FORBIDDEN_AGENT_OPERATIONS = frozenset(
    {
        "merge",
        "auto-merge",
        "squash-merge",
        "rebase-main",
        "push-main",
        "force-push",
        "delete-ref",
        "create-tag",
        "ready-author",
        "ready-reviewer",
    }
)


def branch_denial(name):
    """Return the reason a work-branch name is denied, or None if allowed."""
    if not isinstance(name, str) or not name:
        return "branch name is empty"
    if name in PROTECTED_BRANCHES:
        return "protected branch may not be authored directly"
    if not _BRANCH_SHAPE.match(name):
        return "branch name has unsafe shape"
    if name.endswith("/") or "//" in name or ".." in name or name.endswith(".lock"):
        return "branch name has unsafe shape"
    parsed = parse_lane(name)
    if parsed is None:
        if not name.startswith(GENERIC_NAMESPACES):
            return "branch name is outside the reviewed namespaces"
        for namespace in GENERIC_NAMESPACES:
            if name == namespace.rstrip("/"):
                return "branch name is a bare namespace"
        return None
    _lane, effort, remainder = parsed
    if not remainder:
        return "branch name is a bare namespace"
    if effort is not None and not _ISSUE_TOPIC.match(remainder):
        return "effort-tagged branch must be <lane>-<effort>/<issue#>-<topic>"
    return None


def refspec_denial(refspec, current_branch):
    """Return the reason a push refspec is denied, or None if allowed.

    Only one shape is ever allowed: a non-forced, same-name branch push of
    the currently checked-out work branch.
    """
    if not isinstance(refspec, str) or not refspec:
        return "refspec is empty"
    if refspec.startswith("+"):
        return "force push is never allowed"
    if refspec.startswith(":") or refspec.endswith(":"):
        return "ref deletion is never allowed"
    source, separator, destination = refspec.partition(":")
    if not separator:
        source, destination = refspec, refspec
    if "*" in refspec:
        return "wildcard refspecs are never allowed"
    if destination.startswith("refs/") and not destination.startswith("refs/heads/"):
        return "only branch refs may be pushed"
    plain_destination = destination[len("refs/heads/"):] if destination.startswith(
        "refs/heads/"
    ) else destination
    plain_source = source[len("refs/heads/"):] if source.startswith(
        "refs/heads/"
    ) else source
    if plain_destination in PROTECTED_BRANCHES:
        return "pushing to a protected branch is never allowed"
    if plain_source != plain_destination:
        return "source and destination branch must match"
    denied = branch_denial(plain_destination)
    if denied:
        return denied
    if plain_destination != current_branch:
        return "only the currently checked-out work branch may be pushed"
    return None


def operation_denial(operation):
    """Deny operations outside an agent's authority without exceptions."""
    if not isinstance(operation, str) or not operation:
        return "operation is empty"
    if operation in FORBIDDEN_AGENT_OPERATIONS:
        return "operation is reserved to the owner or coordinator"
    if operation not in {"author", "review", "comment", "draft-pr", "push-work-branch"}:
        return "operation is unknown and therefore denied"
    return None


def _main(argv):
    if len(argv) == 3 and argv[1] == "branch":
        denial = branch_denial(argv[2])
    elif len(argv) == 4 and argv[1] == "refspec":
        denial = refspec_denial(argv[2], argv[3])
    elif len(argv) == 3 and argv[1] == "operation":
        denial = operation_denial(argv[2])
    else:
        print(
            "usage: validate_pr_flow.py branch <name> | "
            "refspec <refspec> <current-branch> | operation <name>",
            file=sys.stderr,
        )
        return 2
    if denial:
        print("DENY: {}".format(denial))
        return 1
    print("ALLOW")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
