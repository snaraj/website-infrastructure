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
REQUIRED_CHECKS = frozenset(("dependency-review", "repository-and-infrastructure"))


class ContractError(ValueError):
    """A platform release input cannot satisfy the immutable contract."""


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


@dataclass(frozen=True)
class TransitionWindow:
    base_sha: str
    intent: Intent


def require_sha(raw: object, field: str) -> str:
    if not isinstance(raw, str) or not SHA_RE.fullmatch(raw):
        raise ContractError(f"{field} must be one lowercase 40-hex SHA")
    return raw


def validate_changelog(text: str, version: Version) -> None:
    escaped = re.escape(str(version))
    dates = re.findall(
        rf"^## \[{escaped}\] - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})$",
        text,
        re.MULTILINE,
    )
    if len(dates) != 1:
        raise ContractError("changelog must contain exactly one current-version heading")
    try:
        dt.date.fromisoformat(dates[0])
    except ValueError as exc:
        raise ContractError("changelog release date is not a real ISO date") from exc
    if not re.search(
        rf"^## \[Unreleased\]\s*\n+## \[{escaped}\] - {re.escape(dates[0])}$",
        text,
        re.MULTILINE,
    ):
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


def _file(
    repository: Path, revision: str, path: str, *, allow_absent: bool = False
) -> str | None:
    return _git(repository, "show", f"{revision}:{path}", allow_absent=allow_absent)


def _version_at(repository: Path, revision: str) -> Version | None:
    raw = _file(repository, revision, "VERSION", allow_absent=True)
    return Version.parse(raw) if raw is not None else None


def _linear_commits(repository: Path, base_sha: str, head_sha: str) -> list[str]:
    """Return every commit in one contiguous, merge-free base..head range."""
    _git(repository, "merge-base", "--is-ancestor", base_sha, head_sha)
    raw = _git(
        repository,
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{base_sha}..{head_sha}",
    )
    commits = raw.splitlines() if raw else []
    if not commits or commits[-1] != head_sha:
        raise ContractError("release range is empty or does not end at the exact head")
    previous = base_sha
    for commit in commits:
        fields = _git(repository, "rev-list", "--parents", "-n", "1", commit).split()
        if len(fields) != 2 or fields[0] != commit or fields[1] != previous:
            raise ContractError("release range must be one contiguous linear commit chain")
        previous = commit
    return commits


def validate_transition(
    repository: Path, base_sha: str, head_sha: str, *, first_parent: bool
) -> Intent:
    """Bind one allowed integration range to its exact final-tree patch."""
    base_sha = require_sha(base_sha, "base SHA")
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ContractError("base did not resolve exactly")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head did not resolve exactly")
    if first_parent:
        # Merge commits are disabled. A squash is one commit; GitHub rebase
        # may install several commits in one push. Both are one exact linear
        # base -> final-tree release intent.
        _linear_commits(repository, base_sha, head_sha)
    else:
        _git(repository, "merge-base", "--is-ancestor", base_sha, head_sha)

    base = _version_at(repository, base_sha)
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


def discover_transition_window(repository: Path, head_sha: str) -> TransitionWindow:
    """Recover the exact linear version boundary ending at a main SHA."""
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head did not resolve exactly")
    head_version = _version_at(repository, head_sha)
    if head_version is None:
        raise ContractError("release head has no VERSION")
    cursor = head_sha
    while True:
        fields = _git(repository, "rev-list", "--parents", "-n", "1", cursor).split()
        if len(fields) != 2 or fields[0] != cursor:
            raise ContractError("could not recover one linear release boundary")
        parent = fields[1]
        if _version_at(repository, parent) != head_version:
            intent = validate_transition(repository, parent, head_sha, first_parent=True)
            return TransitionWindow(parent, intent)
        cursor = parent


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
    path = run.get("path")
    if not isinstance(path, str) or path.split("@", 1)[0] != WORKFLOW_PATH:
        raise ContractError("workflow path mismatch")
    head_repository = run.get("head_repository")
    if not isinstance(head_repository, Mapping) or head_repository.get("full_name") != expected_repository:
        raise ContractError("head repository identity mismatch")
    return require_sha(run.get("head_sha"), "head SHA")


def _object(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{field} must be a JSON object")
    return value


def _string_set(value: object, field: str) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ContractError(f"{field} must be an array of strings")
    if len(value) != len(set(value)):
        raise ContractError(f"{field} must not contain duplicates")
    return set(value)


def validate_settings_receipt(receipt: Mapping[str, object], repository: str) -> None:
    """Validate an owner-observed, value-only protected-main settings receipt."""
    fields = {
        "allow_deletions",
        "allow_force_pushes",
        "branch",
        "bypass_actors",
        "merge_methods",
        "repository",
        "require_linear_history",
        "require_pull_request",
        "required_status_checks",
        "strict_status_checks",
    }
    if set(receipt) != fields:
        raise ContractError("settings receipt fields are missing or foreign")
    if receipt.get("repository") != repository or receipt.get("branch") != "main":
        raise ContractError("settings receipt repository or branch is not exact")
    if _string_set(receipt.get("merge_methods"), "merge methods") != {"rebase", "squash"}:
        raise ContractError("only squash and rebase merge methods may be enabled")
    if _string_set(receipt.get("required_status_checks"), "required status checks") != set(REQUIRED_CHECKS):
        raise ContractError("required status checks are missing or foreign")
    for field, expected in (
        ("strict_status_checks", True),
        ("require_pull_request", True),
        ("require_linear_history", True),
        ("allow_force_pushes", False),
        ("allow_deletions", False),
    ):
        if receipt.get(field) is not expected:
            raise ContractError(f"settings receipt {field} must be {expected}")
    bypass = receipt.get("bypass_actors")
    if bypass != []:
        raise ContractError("protected-main rules must have no bypass actors")


def _same_instant(actual: object, expected: str, field: str) -> None:
    if not isinstance(actual, str):
        raise ContractError(f"{field} must be an ISO-8601 timestamp")
    try:
        actual_time = dt.datetime.fromisoformat(actual.replace("Z", "+00:00"))
        expected_time = dt.datetime.fromisoformat(expected.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{field} must be an ISO-8601 timestamp") from exc
    if actual_time.tzinfo is None or expected_time.tzinfo is None or actual_time != expected_time:
        raise ContractError(f"{field} does not equal the deterministic source-commit instant")


def validate_tag_record(
    ref_record: Mapping[str, object],
    tag_record: Mapping[str, object],
    *,
    tag: str,
    source_sha: str,
    message: str,
    tagger_name: str,
    tagger_email: str,
    tagger_date: str,
) -> None:
    """Verify the complete annotated-tag identity from authoritative REST."""
    source_sha = require_sha(source_sha, "tag target SHA")
    ref_object = _object(ref_record.get("object"), "tag ref object")
    tag_object_sha = require_sha(ref_object.get("sha"), "annotated tag object SHA")
    if ref_record.get("ref") != f"refs/tags/{tag}" or ref_object.get("type") != "tag":
        raise ContractError("tag ref is not the exact annotated tag object")
    if tag_record.get("sha") != tag_object_sha or tag_record.get("tag") != tag:
        raise ContractError("annotated tag object identity does not match its ref")
    target = _object(tag_record.get("object"), "annotated tag target")
    if target.get("type") != "commit" or target.get("sha") != source_sha:
        raise ContractError("annotated tag target is not the exact source commit")
    if tag_record.get("message") != message:
        raise ContractError("annotated tag message is not exact")
    tagger = _object(tag_record.get("tagger"), "annotated tagger")
    if tagger.get("name") != tagger_name or tagger.get("email") != tagger_email:
        raise ContractError("annotated tagger identity violates policy")
    _same_instant(tagger.get("date"), tagger_date, "annotated tagger date")


def validate_release_record(
    release_record: Mapping[str, object], *, tag: str, title: str, body: str
) -> None:
    """Verify exact GitHub Release metadata and a closed empty asset set."""
    if release_record.get("tag_name") != tag or release_record.get("name") != title:
        raise ContractError("GitHub Release tag or title is not exact")
    actual_body = release_record.get("body")
    if not isinstance(actual_body, str) or actual_body.rstrip("\r\n") != body.rstrip("\r\n"):
        raise ContractError("GitHub Release notes are not exact")
    if release_record.get("draft") is not False or release_record.get("prerelease") is not False:
        raise ContractError("GitHub Release must be published and non-prerelease")
    if release_record.get("assets") != []:
        raise ContractError("GitHub Release asset inventory must be exactly empty")


def classify_tag_state(
    http_status: int,
    ref_record: Mapping[str, object] | None,
    tag_record: Mapping[str, object] | None,
    **expected: str,
) -> str:
    if http_status == 404:
        if ref_record is not None or tag_record is not None:
            raise ContractError("absent tag state cannot carry tag records")
        return "absent"
    if http_status != 200:
        raise ContractError(f"tag ref probe returned unexpected HTTP {http_status}")
    if ref_record is None or tag_record is None:
        raise ContractError("present tag state requires both REST tag records")
    validate_tag_record(ref_record, tag_record, **expected)
    return "exact"


def classify_release_state(
    http_status: int,
    release_record: Mapping[str, object] | None,
    *,
    tag: str,
    title: str,
    body: str,
) -> str:
    if http_status == 404:
        if release_record is not None:
            raise ContractError("absent GitHub Release state cannot carry a record")
        return "absent"
    if http_status != 200:
        raise ContractError(f"GitHub Release probe returned unexpected HTTP {http_status}")
    if release_record is None:
        raise ContractError("present GitHub Release state requires its REST record")
    validate_release_record(release_record, tag=tag, title=title, body=body)
    return "exact"


def require_publication_state(actual: str, required: str) -> str:
    """Turn one API classification into a shell-safe exact assertion."""
    if required not in {"absent", "exact"} or actual != required:
        raise ContractError(f"publication state {actual!r} does not equal required {required!r}")
    return actual


def _emit(intent: Intent) -> None:
    print(
        json.dumps(
            {
                "source_sha": intent.source_sha,
                "tag": intent.tag,
                "version": str(intent.version),
            },
            sort_keys=True,
        )
    )


def _read_object(path: Path) -> Mapping[str, object]:
    return _object(json.loads(path.read_text(encoding="utf-8")), str(path))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    transition = commands.add_parser("transition")
    transition.add_argument("--repository", type=Path, required=True)
    transition.add_argument("--base", required=True)
    transition.add_argument("--head", required=True)
    transition.add_argument("--first-parent", action="store_true")
    window = commands.add_parser("release-window")
    window.add_argument("--repository", type=Path, required=True)
    window.add_argument("--head", required=True)
    event = commands.add_parser("workflow-run")
    event.add_argument("--event", type=Path, required=True)
    event.add_argument("--repository", required=True)
    settings = commands.add_parser("settings-receipt")
    settings.add_argument("--receipt", type=Path, required=True)
    settings.add_argument("--repository", required=True)
    tag_record = commands.add_parser("tag-record")
    tag_record.add_argument("--ref-json", type=Path, required=True)
    tag_record.add_argument("--tag-json", type=Path, required=True)
    tag_record.add_argument("--tag", required=True)
    tag_record.add_argument("--source-sha", required=True)
    tag_record.add_argument("--message", required=True)
    tag_record.add_argument("--tagger-name", required=True)
    tag_record.add_argument("--tagger-email", required=True)
    tag_record.add_argument("--tagger-date", required=True)
    tag_state = commands.add_parser("tag-state")
    tag_state.add_argument("--http-status", type=int, required=True)
    tag_state.add_argument("--require", choices=("absent", "exact"))
    tag_state.add_argument("--ref-json", type=Path)
    tag_state.add_argument("--tag-json", type=Path)
    tag_state.add_argument("--tag", required=True)
    tag_state.add_argument("--source-sha", required=True)
    tag_state.add_argument("--message", required=True)
    tag_state.add_argument("--tagger-name", required=True)
    tag_state.add_argument("--tagger-email", required=True)
    tag_state.add_argument("--tagger-date", required=True)
    release_record = commands.add_parser("release-record")
    release_record.add_argument("--release-json", type=Path, required=True)
    release_record.add_argument("--tag", required=True)
    release_record.add_argument("--title", required=True)
    release_record.add_argument("--body", type=Path, required=True)
    release_state = commands.add_parser("release-state")
    release_state.add_argument("--http-status", type=int, required=True)
    release_state.add_argument("--require", choices=("absent", "exact"))
    release_state.add_argument("--release-json", type=Path)
    release_state.add_argument("--tag", required=True)
    release_state.add_argument("--title", required=True)
    release_state.add_argument("--body", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "transition":
            _emit(
                validate_transition(
                    args.repository,
                    args.base,
                    args.head,
                    first_parent=args.first_parent,
                )
            )
        elif args.command == "release-window":
            window = discover_transition_window(args.repository, args.head)
            print(
                json.dumps(
                    {
                        "base_sha": window.base_sha,
                        "source_sha": window.intent.source_sha,
                        "tag": window.intent.tag,
                        "version": str(window.intent.version),
                    },
                    sort_keys=True,
                )
            )
        elif args.command == "workflow-run":
            print(
                plan_workflow_run(
                    json.loads(args.event.read_text(encoding="utf-8")),
                    args.repository,
                )
            )
        elif args.command == "settings-receipt":
            validate_settings_receipt(_read_object(args.receipt), args.repository)
            print("exact")
        elif args.command == "tag-record":
            validate_tag_record(
                _read_object(args.ref_json),
                _read_object(args.tag_json),
                tag=args.tag,
                source_sha=args.source_sha,
                message=args.message,
                tagger_name=args.tagger_name,
                tagger_email=args.tagger_email,
                tagger_date=args.tagger_date,
            )
            print("exact")
        elif args.command == "tag-state":
            state = classify_tag_state(
                args.http_status,
                _read_object(args.ref_json) if args.ref_json else None,
                _read_object(args.tag_json) if args.tag_json else None,
                tag=args.tag,
                source_sha=args.source_sha,
                message=args.message,
                tagger_name=args.tagger_name,
                tagger_email=args.tagger_email,
                tagger_date=args.tagger_date,
            )
            print(require_publication_state(state, args.require) if args.require else state)
        elif args.command == "release-record":
            validate_release_record(
                _read_object(args.release_json),
                tag=args.tag,
                title=args.title,
                body=args.body.read_text(encoding="utf-8"),
            )
            print("exact")
        elif args.command == "release-state":
            state = classify_release_state(
                args.http_status,
                _read_object(args.release_json) if args.release_json else None,
                tag=args.tag,
                title=args.title,
                body=args.body.read_text(encoding="utf-8"),
            )
            print(require_publication_state(state, args.require) if args.require else state)
        else:  # pragma: no cover - argparse owns this path
            raise ContractError("unknown command")
    except (ContractError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
