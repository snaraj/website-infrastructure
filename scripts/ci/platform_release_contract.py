#!/usr/bin/env python3
"""Pure policy for an immutable platform patch release on every main merge."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_NAME = "Pull request"
WORKFLOW_PATH = ".github/workflows/pull-request.yml"


class ContractError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "Version":
        match = SEMVER_RE.fullmatch(raw.strip())
        if not match:
            raise ContractError(f"invalid semantic version: {raw!r}")
        return cls(*(int(part) for part in match.groups()))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def tag(self) -> str:
        return f"v{self}"


@dataclass(frozen=True)
class Intent:
    source_sha: str
    version: Version

    @property
    def tag(self) -> str:
        return self.version.tag


def require_sha(raw: object, field: str) -> str:
    if not isinstance(raw, str) or not SHA_RE.fullmatch(raw):
        raise ContractError(f"{field} must be one lowercase 40-hex SHA")
    return raw


def validate_changelog(text: str, version: Version) -> None:
    escaped = re.escape(str(version))
    dates = re.findall(rf"^## \[{escaped}\] - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})$", text, re.MULTILINE)
    if len(dates) != 1:
        raise ContractError("changelog must contain exactly one current-version heading")
    try:
        dt.date.fromisoformat(dates[0])
    except ValueError as exc:
        raise ContractError("changelog release date is not a real ISO date") from exc
    if not re.search(rf"^## \[Unreleased\]\s*\n+## \[{escaped}\] - {dates[0]}$", text, re.MULTILINE):
        raise ContractError("current release must immediately follow empty Unreleased")


def next_version(base: Version | None) -> Version:
    if base is None:
        return Version(0, 1, 0)
    return Version(base.major, base.minor, base.patch + 1)


def _git(repository: Path, *args: str, allow_absent: bool = False) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    if result.returncode:
        if allow_absent:
            return None
        raise ContractError(f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _file(repository: Path, revision: str, path: str, *, allow_absent: bool = False) -> str | None:
    return _git(repository, "show", f"{revision}:{path}", allow_absent=allow_absent)


def validate_transition(repository: Path, base_sha: str, head_sha: str, *, first_parent: bool) -> Intent:
    base_sha = require_sha(base_sha, "base SHA")
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ContractError("base did not resolve exactly")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head did not resolve exactly")
    if first_parent:
        if _git(repository, "rev-parse", f"{head_sha}^1") != base_sha:
            raise ContractError("main base is not the head commit's first parent")
        if _git(repository, "rev-list", "--first-parent", "--count", f"{base_sha}..{head_sha}") != "1":
            raise ContractError("one event must cover exactly one first-parent commit")
    else:
        _git(repository, "merge-base", "--is-ancestor", base_sha, head_sha)

    base_raw = _file(repository, base_sha, "VERSION", allow_absent=True)
    base = Version.parse(base_raw) if base_raw is not None else None
    head_raw = _file(repository, head_sha, "VERSION")
    assert head_raw is not None
    head = Version.parse(head_raw)
    expected = next_version(base)
    if head != expected:
        raise ContractError(f"head version {head} must be exact next patch {expected}")
    changelog = _file(repository, head_sha, "CHANGELOG.md")
    assert changelog is not None
    validate_changelog(changelog, head)
    return Intent(head_sha, head)


def plan_workflow_run(event: Mapping[str, object], expected_repository: str) -> str:
    repository = event.get("repository")
    run = event.get("workflow_run")
    if not isinstance(repository, Mapping) or repository.get("full_name") != expected_repository:
        raise ContractError("repository identity mismatch")
    if not isinstance(run, Mapping):
        raise ContractError("workflow_run payload is absent")
    required = {
        "name": WORKFLOW_NAME,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
    }
    for key, value in required.items():
        if run.get(key) != value:
            raise ContractError(f"workflow_run {key} must equal {value!r}")
    if not isinstance(run.get("path"), str) or run["path"].split("@", 1)[0] != WORKFLOW_PATH:
        raise ContractError("workflow path mismatch")
    head_repository = run.get("head_repository")
    if not isinstance(head_repository, Mapping) or head_repository.get("full_name") != expected_repository:
        raise ContractError("head repository identity mismatch")
    return require_sha(run.get("head_sha"), "head SHA")


def classify_publication(*, tag_present: bool, tag_exact: bool, release_present: bool, release_exact: bool) -> str:
    if not tag_present and not release_present:
        if tag_exact or release_exact:
            raise ContractError("absent state cannot be exact")
        return "absent"
    if tag_present and tag_exact and release_present and release_exact:
        return "complete"
    if tag_present and tag_exact and not release_present and not release_exact:
        return "resume-release"
    return "burned"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    transition = commands.add_parser("transition")
    transition.add_argument("--repository", type=Path, required=True)
    transition.add_argument("--base", required=True)
    transition.add_argument("--head", required=True)
    transition.add_argument("--first-parent", action="store_true")
    event = commands.add_parser("workflow-run")
    event.add_argument("--event", type=Path, required=True)
    event.add_argument("--repository", required=True)
    publication = commands.add_parser("publication-state")
    for name in ("tag-present", "tag-exact", "release-present", "release-exact"):
        publication.add_argument(f"--{name}", choices=("true", "false"), required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "transition":
            intent = validate_transition(args.repository, args.base, args.head, first_parent=args.first_parent)
            print(json.dumps({"source_sha": intent.source_sha, "tag": intent.tag, "version": str(intent.version)}, sort_keys=True))
        elif args.command == "workflow-run":
            event = json.loads(args.event.read_text(encoding="utf-8"))
            print(plan_workflow_run(event, args.repository))
        elif args.command == "publication-state":
            state = classify_publication(
                tag_present=args.tag_present == "true",
                tag_exact=args.tag_exact == "true",
                release_present=args.release_present == "true",
                release_exact=args.release_exact == "true",
            )
            print(state)
            if state == "burned":
                return 1
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
