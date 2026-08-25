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

# Branch namespaces reviewed for agent work. A single flat name such as
# "fix-typo" is rejected: namespacing keeps ownership and cleanup auditable.
ALLOWED_NAMESPACES = (
    "5.6-sol/",
    "fable5/",
    "deploy/",
    "import/",
    "ci/",
    "docs/",
    "feat/",
    "fix/",
    "chore/",
    "media/",
)

_BRANCH_SHAPE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")

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
    if not name.startswith(ALLOWED_NAMESPACES):
        return "branch name is outside the reviewed namespaces"
    for namespace in ALLOWED_NAMESPACES:
        if name == namespace.rstrip("/"):
            return "branch name is a bare namespace"
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
