#!/usr/bin/env python3
"""Pure policy for an immutable platform patch release on every main merge."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
TAG_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FRAGMENT_PATH_RE = re.compile(
    r"^changelog\.d/([1-9][0-9]*)-[a-z0-9]+(?:-[a-z0-9]+)*\.md$"
)
FRAGMENT_CATEGORIES = frozenset({"Added", "Changed", "Fixed", "Security"})
GENERATED_RELEASE_PATHS = frozenset({"VERSION", "CHANGELOG.md"})
MAX_FRAGMENT_BYTES = 16 * 1024
WORKFLOW_NAME = "Pull request"
WORKFLOW_PATH = ".github/workflows/pull-request.yml"
GITHUB_API_VERSION = "2026-03-10"
EXPECTED_MAIN_RULESET = "only-me-merge"
EXPECTED_RELEASE_TAG_RULESET = "immutable-platform-release-tags"
EXPECTED_RELEASE_TAG_PATTERN = "refs/tags/v*.*.*"
GITHUB_ACTIONS_INTEGRATION_ID = 15368
REQUIRED_CHECKS = (
    "dependency-review",
    "repository-and-infrastructure",
)
MAIN_CI_REQUIRED_STEPS = (
    "Check out repository",
    "Enforce the platform release transition",
    "Install checksum-verified tools",
    "Validate workflows",
    "Validate Python policy tooling",
    "Enforce the self-hosted coverage contract",
    "Check shell",
    "Scan current tree for secrets",
    "Render and validate Helm and Kubernetes",
    "Prove render determinism and validate the assurance ledger",
    "Test staged Kyverno policies",
    "Validate OpenTofu without credentials",
    "Scan dependencies and full-tree secrets",
    "Scan IaC and configuration",
)
MAIN_CI_PUSH_SKIPPED_STEPS = ("Scan immutable pull-request history",)
MAIN_CI_EXACT_STEPS = (
    ("Set up job", "success"),
    *((name, "success") for name in MAIN_CI_REQUIRED_STEPS[:3]),
    *((name, "skipped") for name in MAIN_CI_PUSH_SKIPPED_STEPS),
    *((name, "success") for name in MAIN_CI_REQUIRED_STEPS[3:]),
    ("Post Check out repository", "success"),
    ("Complete job", "success"),
)
CODEQL_WORKFLOW_NAME = "CodeQL"
CODEQL_WORKFLOW_PATH = ".github/workflows/codeql.yml"
CODEQL_JOB_NAME = "analyze (python, none)"
CODEQL_REQUIRED_STEPS = (
    "Check out repository",
    "Initialize CodeQL",
    "Analyze",
)
CODEQL_EXACT_STEPS = (
    ("Set up job", "success"),
    *((name, "success") for name in CODEQL_REQUIRED_STEPS),
    ("Post Analyze", "success"),
    ("Post Initialize CodeQL", "success"),
    ("Post Check out repository", "success"),
    ("Complete job", "success"),
)
RECOVERY_BASE_SHA = "c63f357fbc77d55f6e60050f687cceb8723eda6c"
RECOVERY_SOURCE_SHA = "51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e"
RECOVERY_TAG = "v0.1.0"
# Issue #164 moves the publisher from commit-authored VERSION boundaries to an
# immutable tag ledger.  Historical source releases before this exact boundary
# contain two intentionally absent tags, so the new contiguous state machine
# starts at the last release produced by the retired model rather than
# pretending the legacy gap never existed.
TAG_LEDGER_FLOOR_TAG = "v0.1.9"
TAG_LEDGER_FLOOR_SHA = "02863737ec3759e03e032f0a478f4b5298c61a0b"
RELEASE_TAGGER_NAME = "github-actions[bot]"
RELEASE_TAGGER_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
PREFLIGHT_APP_ID_VARIABLE = "PLATFORM_RELEASE_APP_ID"
PREFLIGHT_APP_PRIVATE_KEY_SECRET = "PLATFORM_RELEASE_APP_PRIVATE_KEY"
PREFLIGHT_ENVIRONMENT = "platform-release"


class ContractError(ValueError):
    """A platform release input cannot satisfy the immutable contract."""


class PendingRelease(ContractError):
    """A later main SHA is waiting for an earlier release identity."""


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
    base_tag: str
    intent: Intent
    fragment_path: str
    fragment_sha256: str


@dataclass(frozen=True)
class FragmentIntent:
    source_sha: str
    fragment_path: str
    fragment_sha256: str


@dataclass(frozen=True, order=True)
class TagBoundary:
    version: Version
    tag: str
    source_sha: str


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


def _git_bytes(repository: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ContractError(f"git {' '.join(args)} failed")
    return result.stdout


def _file_bytes(repository: Path, revision: str, path: str) -> bytes:
    return _git_bytes(repository, "show", f"{revision}:{path}")


def _require_regular_fragment_entry(
    repository: Path, revision: str, path: str
) -> None:
    raw = _git_bytes(
        repository, "ls-tree", "-z", "--full-tree", revision, "--", path
    )
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        raise ContractError("fragment tree entry is absent or duplicated")
    try:
        metadata, encoded_path = raw[:-1].split(b"\t", 1)
        mode, object_type, object_id = metadata.split(b" ", 2)
        decoded_path = encoded_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContractError("fragment tree entry is malformed") from exc
    if (
        decoded_path != path
        or mode != b"100644"
        or object_type != b"blob"
        or not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", object_id)
    ):
        raise ContractError("fragment must be one regular non-executable 100644 blob")


def _exact_commit(repository: Path, revision: str, field: str) -> str:
    revision = require_sha(revision, field)
    if _git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}") != revision:
        raise ContractError(f"{field} did not resolve exactly")
    return revision


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise ContractError("git ancestry check failed")


def _nul_paths(repository: Path, *args: str) -> tuple[str, ...]:
    raw = _git_bytes(repository, *args)
    fields = raw.split(b"\0")
    if fields[-1] != b"":
        raise ContractError("git path inventory was not NUL terminated")
    paths: list[str] = []
    for field in fields[:-1]:
        try:
            path = field.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError("release path is not UTF-8") from exc
        if not path or path in paths:
            raise ContractError("release path inventory is empty or duplicated")
        paths.append(path)
    return tuple(sorted(paths))


def validate_fragment_bytes(path: str, payload: bytes) -> str:
    if not FRAGMENT_PATH_RE.fullmatch(path):
        raise ContractError(
            "fragment path must be changelog.d/<issue>-<lowercase-slug>.md"
        )
    if not payload or len(payload) > MAX_FRAGMENT_BYTES:
        raise ContractError("fragment must be non-empty and at most 16 KiB")
    if payload.startswith(b"\xef\xbb\xbf") or b"\r" in payload or b"\x00" in payload:
        raise ContractError("fragment must be BOM-free UTF-8 with LF line endings")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("fragment is not UTF-8") from exc
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise ContractError("fragment must end in exactly one newline")
    if "${{" in text:
        raise ContractError("fragment must not contain a workflow expression opener")
    lines = text.splitlines()
    if len(lines) < 3 or lines[1] != "":
        raise ContractError("fragment must contain one category heading and bullet list")
    heading = lines[0]
    if not heading.startswith("### ") or heading[4:] not in FRAGMENT_CATEGORIES:
        raise ContractError("fragment category must be Added, Changed, Fixed, or Security")
    bullets = lines[2:]
    if not bullets or any(not line.startswith("- ") or len(line) == 2 for line in bullets):
        raise ContractError("every fragment body line must be one non-empty Markdown bullet")
    if any(line.rstrip() != line for line in lines):
        raise ContractError("fragment lines must not contain trailing whitespace")
    return text


def _release_surface_intents(
    repository: Path, base_sha: str, head_sha: str
) -> tuple[FragmentIntent, ...]:
    _linear_commits(repository, base_sha, head_sha)
    pathspec = ("--", "VERSION", "CHANGELOG.md", "changelog.d")
    changed = _nul_paths(
        repository,
        "diff",
        "--name-only",
        "--no-renames",
        "-z",
        base_sha,
        head_sha,
        *pathspec,
    )
    added = _nul_paths(
        repository,
        "diff",
        "--name-only",
        "--no-renames",
        "--diff-filter=A",
        "-z",
        base_sha,
        head_sha,
        *pathspec,
    )
    generated = sorted(set(changed) & GENERATED_RELEASE_PATHS)
    if generated:
        raise ContractError(
            "retired generated release files changed: " + ", ".join(generated)
        )
    if changed != added:
        raise ContractError("release fragments may only be newly added, never edited or removed")
    intents: list[FragmentIntent] = []
    for path in added:
        _require_regular_fragment_entry(repository, head_sha, path)
        payload = _file_bytes(repository, head_sha, path)
        validate_fragment_bytes(path, payload)
        intents.append(
            FragmentIntent(head_sha, path, hashlib.sha256(payload).hexdigest())
        )
    return tuple(intents)


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
) -> FragmentIntent:
    """Bind one PR or protected-main range to one immutable fragment."""
    del first_parent  # Both enabled merge methods require the same linear range.
    base_sha = _exact_commit(repository, base_sha, "base SHA")
    head_sha = _exact_commit(repository, head_sha, "head SHA")
    intents = _release_surface_intents(repository, base_sha, head_sha)
    if len(intents) != 1:
        raise ContractError("release range must add exactly one changelog fragment")
    return intents[0]


def _platform_tag_boundaries(repository: Path) -> tuple[TagBoundary, ...]:
    raw = _git(repository, "tag", "--list", "v*")
    names = raw.splitlines() if raw else []
    boundaries: list[TagBoundary] = []
    seen_versions: set[Version] = set()
    for name in names:
        match = TAG_RE.fullmatch(name)
        if not match:
            raise ContractError(f"platform tag is not canonical SemVer: {name!r}")
        version = Version(*(int(part) for part in match.groups()))
        if version in seen_versions:
            raise ContractError("platform tag version is duplicated")
        seen_versions.add(version)
        raw = _git_bytes(
            repository,
            "for-each-ref",
            "--count=1",
            "--format=%(objecttype)%00%(*objecttype)%00%(tag)%00%(taggername)%00%(taggeremail)%00%(taggerdate:iso-strict)%00%(contents)%00%(*objectname)%00",
            f"refs/tags/{name}",
        )
        if not raw.endswith(b"\0\n"):
            raise ContractError(f"platform tag {name} metadata is not bounded")
        try:
            fields = tuple(field.decode("utf-8") for field in raw[:-2].split(b"\0"))
        except UnicodeDecodeError as exc:
            raise ContractError(f"platform tag {name} metadata is not UTF-8") from exc
        if len(fields) != 8:
            raise ContractError(f"platform tag {name} metadata is incomplete")
        (
            object_type,
            peeled_type,
            embedded_name,
            tagger_name,
            tagger_email,
            tagger_date,
            message,
            source_sha,
        ) = fields
        source_sha = require_sha(source_sha, f"{name} target")
        expected_message = f"Platform release {name} from {source_sha}"
        expected_date = _git(repository, "show", "-s", "--format=%cI", source_sha)
        if (
            object_type != "tag"
            or peeled_type != "commit"
            or embedded_name != name
            or tagger_name != RELEASE_TAGGER_NAME
            or tagger_email != f"<{RELEASE_TAGGER_EMAIL}>"
            or tagger_date != expected_date
            or message != expected_message
        ):
            raise ContractError(f"platform tag {name} metadata is not exact")
        boundaries.append(TagBoundary(version, name, source_sha))
    boundaries.sort()
    floor_version = Version.parse(TAG_LEDGER_FLOOR_TAG.removeprefix("v"))
    ledger = tuple(boundary for boundary in boundaries if boundary.version >= floor_version)
    if not ledger:
        raise ContractError("tag-derived release ledger has no migration floor")
    floor = ledger[0]
    if floor.tag != TAG_LEDGER_FLOOR_TAG or floor.source_sha != TAG_LEDGER_FLOOR_SHA:
        raise ContractError("tag-derived release ledger floor is not exact")
    previous = floor
    for boundary in ledger[1:]:
        if boundary.version != next_version(previous.version):
            raise ContractError("tag-derived release ledger skips or reverses a patch")
        if boundary.source_sha == previous.source_sha or not _is_ancestor(
            repository, previous.source_sha, boundary.source_sha
        ):
            raise ContractError("tag-derived release ledger is not one ancestral sequence")
        _linear_commits(repository, previous.source_sha, boundary.source_sha)
        intents = _release_surface_intents(
            repository, previous.source_sha, boundary.source_sha
        )
        if len(intents) != 1:
            raise ContractError(
                "every adjacent tag-derived release must bind exactly one fragment"
            )
        previous = boundary
    return ledger


def discover_transition_window(repository: Path, head_sha: str) -> TransitionWindow:
    """Derive one exact patch from the immutable tag ledger and one fragment."""
    head_sha = _exact_commit(repository, head_sha, "head SHA")
    ledger = _platform_tag_boundaries(repository)

    for index, boundary in enumerate(ledger):
        if boundary.source_sha != head_sha:
            continue
        if index == 0:
            raise ContractError("the migration-floor release is not a publishable new window")
        previous = ledger[index - 1]
        intents = _release_surface_intents(repository, previous.source_sha, head_sha)
        if len(intents) != 1:
            raise ContractError("an existing release tag must bind exactly one fragment")
        fragment = intents[0]
        return TransitionWindow(
            previous.source_sha,
            previous.tag,
            Intent(head_sha, boundary.version),
            fragment.fragment_path,
            fragment.fragment_sha256,
        )

    for boundary in ledger:
        if _is_ancestor(repository, head_sha, boundary.source_sha):
            raise ContractError("source SHA is behind a later tag but has no exact release tag")

    latest = ledger[-1]
    if not _is_ancestor(repository, latest.source_sha, head_sha):
        raise ContractError("source SHA does not descend from the latest platform tag")
    intents = _release_surface_intents(repository, latest.source_sha, head_sha)
    if len(intents) > 1:
        raise PendingRelease(
            f"source is waiting for {len(intents) - 1} earlier main release(s)"
        )
    if len(intents) != 1:
        raise ContractError("unreleased source must add exactly one changelog fragment")
    fragment = intents[0]
    version = next_version(latest.version)
    return TransitionWindow(
        latest.source_sha,
        latest.tag,
        Intent(head_sha, version),
        fragment.fragment_path,
        fragment.fragment_sha256,
    )


def _legacy_release_notes(head_sha: str, tag: str) -> str:
    return (
        f"## Platform {tag}\n\n"
        f"Immutable repository source: `{head_sha}`\n\n"
        "This release names platform source only. It does not deploy, promote, "
        "mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n"
        "See `CHANGELOG.md` at this tag for the human-readable change record.\n"
    )


def render_release_notes(
    repository: Path,
    head_sha: str,
    tag: str,
    *,
    expected_base_sha: str | None = None,
    expected_base_tag: str | None = None,
) -> str:
    if (expected_base_sha is None) != (expected_base_tag is None):
        raise ContractError("release-notes base SHA and tag must be supplied together")
    head_sha = _exact_commit(repository, head_sha, "release-notes head SHA")
    if tag == TAG_LEDGER_FLOOR_TAG:
        if head_sha != TAG_LEDGER_FLOOR_SHA:
            raise ContractError("legacy migration-floor notes source is not exact")
        ledger = _platform_tag_boundaries(repository)
        if ledger[0].source_sha != head_sha or ledger[0].tag != tag:
            raise ContractError("legacy migration-floor release is not exact")
        if expected_base_sha is not None:
            raise ContractError("legacy migration-floor notes have no derived base")
        return _legacy_release_notes(head_sha, tag)
    window = discover_transition_window(repository, head_sha)
    if window.intent.tag != tag:
        raise ContractError("release-notes tag is not the derived tag")
    if expected_base_sha is not None and (
        window.base_sha != expected_base_sha or window.base_tag != expected_base_tag
    ):
        raise ContractError("release-notes predecessor is not the derived base")
    payload = _file_bytes(repository, head_sha, window.fragment_path)
    text = validate_fragment_bytes(window.fragment_path, payload)
    if hashlib.sha256(payload).hexdigest() != window.fragment_sha256:
        raise ContractError("release fragment changed after window derivation")
    return (
        f"## Platform {tag}\n\n"
        f"Immutable repository source: `{head_sha}`\n\n"
        "This release names platform source only. It does not deploy, promote, "
        "mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n"
        f"Fragment: `{window.fragment_path}` "
        f"(`sha256:{window.fragment_sha256}`)\n\n"
        f"{text}"
    )


def validate_recovery_release(repository: Path, source_sha: str, tag: str) -> Intent:
    """Bind the sole pre-App release backlog entry to its immutable history."""
    source_sha = _exact_commit(repository, source_sha, "recovery source SHA")
    if source_sha != RECOVERY_SOURCE_SHA or tag != RECOVERY_TAG:
        raise ContractError("release recovery source or tag is not the exact frozen backlog")
    if _git(repository, "rev-parse", f"{source_sha}^") != RECOVERY_BASE_SHA:
        raise ContractError("release recovery base is not the exact protected predecessor")
    if _git(repository, "cat-file", "-t", f"refs/tags/{tag}") != "tag":
        raise ContractError("release recovery tag is not annotated")
    if _git(repository, "rev-parse", f"refs/tags/{tag}^{{commit}}") != source_sha:
        raise ContractError("release recovery tag target is not exact")
    version = Version.parse(_file(repository, source_sha, "VERSION") or "")
    if version.tag != tag:
        raise ContractError("release recovery VERSION is not exact")
    changelog = _file(repository, source_sha, "CHANGELOG.md")
    assert changelog is not None
    validate_changelog(changelog, version)
    return Intent(source_sha, version)


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


def _array(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(f"{field} must be a JSON array")
    return value


def _status_check_set(value: object) -> set[tuple[str, int]]:
    checks: set[tuple[str, int]] = set()
    for item in _array(value, "required status checks"):
        record = _object(item, "required status check")
        if set(record) != {"context", "integration_id"}:
            raise ContractError("required status check fields are missing or foreign")
        context = record.get("context")
        integration_id = record.get("integration_id")
        if not isinstance(context, str) or not context:
            raise ContractError("required status check context must be non-empty")
        if isinstance(integration_id, bool) or not isinstance(integration_id, int):
            raise ContractError("required status check integration_id must be an integer")
        check = (context, integration_id)
        if check in checks:
            raise ContractError("required status checks must not contain duplicates")
        checks.add(check)
    return checks


def validate_immutable_settings(settings: Mapping[str, object]) -> None:
    """Require the authoritative repository immutable-release control."""
    if set(settings) != {"enabled", "enforced_by_owner"}:
        raise ContractError("immutable-release settings fields are missing or foreign")
    if settings.get("enabled") is not True:
        raise ContractError("GitHub immutable releases must be enabled")
    if not isinstance(settings.get("enforced_by_owner"), bool):
        raise ContractError("immutable-release owner-enforcement state must be boolean")


def build_immutable_settings_receipt(
    settings: Mapping[str, object],
    repository: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
) -> Mapping[str, object]:
    """Return a public, value-only receipt after current-settings validation."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ContractError("repository identity must be owner/name")
    source_sha = require_sha(source_sha, "settings source SHA")
    if not run_id.isascii() or not run_id.isdecimal() or int(run_id) <= 0:
        raise ContractError("settings run ID must be one positive decimal integer")
    if (
        not run_attempt.isascii()
        or not run_attempt.isdecimal()
        or int(run_attempt) <= 0
    ):
        raise ContractError("settings run attempt must be one positive decimal integer")
    validate_immutable_settings(settings)
    receipt: dict[str, object] = {
        "immutable_releases_enabled": True,
        "repository": repository,
        "run_attempt": int(run_attempt),
        "run_id": int(run_id),
        "schema": "platform-release-immutable-settings-v1",
        "source_sha": source_sha,
        "status": "PASS",
    }
    return receipt


def build_main_ci_jobs_receipt(
    jobs_record: Mapping[str, object],
    codeql_runs_record: Mapping[str, object],
    codeql_jobs_record: Mapping[str, object],
    repository: str,
    run_id: str,
    run_attempt: str,
    source_sha: str,
) -> Mapping[str, object]:
    """Prove the exact protected-main jobs and ordered step inventory."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ContractError("jobs repository identity must be owner/name")
    source_sha = require_sha(source_sha, "jobs source SHA")
    if not run_id.isascii() or not run_id.isdecimal() or int(run_id) <= 0:
        raise ContractError("jobs run ID must be one positive decimal integer")
    if (
        not run_attempt.isascii()
        or not run_attempt.isdecimal()
        or int(run_attempt) <= 0
    ):
        raise ContractError("jobs run attempt must be one positive decimal integer")
    if set(jobs_record) != {"jobs", "total_count"}:
        raise ContractError("Actions jobs response fields are missing or foreign")
    total_count = jobs_record.get("total_count")
    jobs = _array(jobs_record.get("jobs"), "Actions jobs")
    if (
        isinstance(total_count, bool)
        or not isinstance(total_count, int)
        or total_count != 2
        or len(jobs) != 2
    ):
        raise ContractError("protected-main run must expose exactly two jobs")

    by_name: dict[str, Mapping[str, object]] = {}
    for value in jobs:
        job = _object(value, "Actions job")
        name = job.get("name")
        if not isinstance(name, str) or not name or name in by_name:
            raise ContractError("Actions job names must be non-empty and unique")
        if (
            job.get("run_id") != int(run_id)
            or job.get("run_attempt") != int(run_attempt)
            or job.get("head_sha") != source_sha
            or job.get("head_branch") != "main"
            or job.get("workflow_name") != WORKFLOW_NAME
            or job.get("status") != "completed"
        ):
            raise ContractError("Actions job identity or completed-run binding is not exact")
        by_name[name] = job
    if set(by_name) != set(REQUIRED_CHECKS):
        raise ContractError("Actions job inventory is missing, duplicate, or foreign")

    repository_job = by_name["repository-and-infrastructure"]
    if repository_job.get("conclusion") != "success":
        raise ContractError("required repository job did not conclude success")
    step_conclusions: dict[str, str] = {}
    ordered_steps: list[tuple[str, str]] = []
    for value in _array(repository_job.get("steps"), "repository job steps"):
        step = _object(value, "repository job step")
        name = step.get("name")
        conclusion = step.get("conclusion")
        if not isinstance(name, str) or not name or name in step_conclusions:
            raise ContractError("repository job step names must be non-empty and unique")
        if not isinstance(conclusion, str) or not conclusion:
            raise ContractError("repository job step conclusion is missing")
        step_conclusions[name] = conclusion
        ordered_steps.append((name, conclusion))
    if tuple(ordered_steps) != MAIN_CI_EXACT_STEPS:
        raise ContractError(
            "protected-main step order, inventory, or conclusions are not exact"
        )

    dependency_job = by_name["dependency-review"]
    if dependency_job.get("conclusion") != "skipped":
        raise ContractError("dependency-review must be skipped for a protected-main push")
    dependency_steps = _array(dependency_job.get("steps"), "dependency-review steps")
    if dependency_steps != []:
        raise ContractError("skipped dependency-review must expose no steps")

    codeql_run = classify_codeql_run(codeql_runs_record, source_sha)
    if codeql_run is None:
        raise ContractError("exact-SHA CodeQL main run is absent or incomplete")
    codeql_run_id, codeql_run_attempt = codeql_run
    if not codeql_jobs_ready(
        codeql_jobs_record,
        run_id=codeql_run_id,
        run_attempt=codeql_run_attempt,
        source_sha=source_sha,
    ):
        raise ContractError("exact-SHA CodeQL main job is absent or incomplete")

    return {
        "codeql": "success",
        "dependency_review": "skipped-on-push",
        "repository": repository,
        "repository_and_infrastructure": "success",
        "run_attempt": int(run_attempt),
        "run_id": int(run_id),
        "schema": "platform-release-main-ci-jobs-v1",
        "source_sha": source_sha,
        "status": "PASS",
    }


def classify_codeql_run(
    runs_record: Mapping[str, object], source_sha: str
) -> tuple[int, int] | None:
    """Return the one exact completed CodeQL run ID, or None while pending."""
    source_sha = require_sha(source_sha, "CodeQL source SHA")
    if set(runs_record) != {"total_count", "workflow_runs"}:
        raise ContractError("CodeQL run response fields are missing or foreign")
    total_count = runs_record.get("total_count")
    runs = _array(runs_record.get("workflow_runs"), "CodeQL workflow runs")
    if isinstance(total_count, bool) or not isinstance(total_count, int):
        raise ContractError("CodeQL run count must be an integer")
    if total_count == 0 and runs == []:
        return None
    if total_count != 1 or len(runs) != 1:
        raise ContractError("expected exactly one CodeQL push run for the source SHA")
    run = _object(runs[0], "CodeQL workflow run")
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    if (
        isinstance(run_id, bool)
        or not isinstance(run_id, int)
        or run_id <= 0
        or isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt <= 0
        or run.get("name") != CODEQL_WORKFLOW_NAME
        or run.get("path") != CODEQL_WORKFLOW_PATH
        or run.get("event") != "push"
        or run.get("head_branch") != "main"
        or run.get("head_sha") != source_sha
    ):
        raise ContractError("CodeQL run identity or protected-main binding is not exact")
    status = run.get("status")
    conclusion = run.get("conclusion")
    if status in {"queued", "in_progress", "pending", "requested", "waiting"}:
        if conclusion is not None:
            raise ContractError("incomplete CodeQL run has a foreign conclusion")
        return None
    if status != "completed" or conclusion != "success":
        raise ContractError("CodeQL run did not complete successfully")
    return run_id, run_attempt


def codeql_jobs_ready(
    jobs_record: Mapping[str, object], *, run_id: int, run_attempt: int, source_sha: str
) -> bool:
    """Validate the sole exact CodeQL job and ordered step inventory."""
    source_sha = require_sha(source_sha, "CodeQL job source SHA")
    if (
        isinstance(run_id, bool)
        or not isinstance(run_id, int)
        or run_id <= 0
        or isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt <= 0
    ):
        raise ContractError("CodeQL job run identity is not positive integers")
    if set(jobs_record) != {"jobs", "total_count"}:
        raise ContractError("CodeQL jobs response fields are missing or foreign")
    total_count = jobs_record.get("total_count")
    jobs = _array(jobs_record.get("jobs"), "CodeQL jobs")
    if isinstance(total_count, bool) or not isinstance(total_count, int):
        raise ContractError("CodeQL job count must be an integer")
    if total_count == 0 and jobs == []:
        return False
    if total_count != 1 or len(jobs) != 1:
        raise ContractError("expected exactly one CodeQL job for the source SHA")
    job = _object(jobs[0], "CodeQL job")
    if (
        job.get("name") != CODEQL_JOB_NAME
        or job.get("run_id") != run_id
        or job.get("run_attempt") != run_attempt
        or job.get("head_sha") != source_sha
        or job.get("head_branch") != "main"
        or job.get("workflow_name") != CODEQL_WORKFLOW_NAME
    ):
        raise ContractError("CodeQL job identity or source binding is not exact")
    status = job.get("status")
    conclusion = job.get("conclusion")
    if status in {"queued", "in_progress", "pending", "requested", "waiting"}:
        if conclusion is not None:
            raise ContractError("incomplete CodeQL job has a foreign conclusion")
        return False
    if status != "completed" or conclusion != "success":
        raise ContractError("CodeQL job did not complete successfully")
    conclusions: dict[str, str] = {}
    ordered_steps: list[tuple[str, str]] = []
    for value in _array(job.get("steps"), "CodeQL job steps"):
        step = _object(value, "CodeQL job step")
        name = step.get("name")
        conclusion = step.get("conclusion")
        if not isinstance(name, str) or not name or name in conclusions:
            raise ContractError("CodeQL step names must be non-empty and unique")
        if not isinstance(conclusion, str) or not conclusion:
            raise ContractError("CodeQL step conclusion is missing")
        conclusions[name] = conclusion
        ordered_steps.append((name, conclusion))
    if tuple(ordered_steps) != CODEQL_EXACT_STEPS:
        raise ContractError("CodeQL step order, inventory, or conclusions are not exact")
    return True


def validate_app_provisioning_receipt(
    receipt: Mapping[str, object], repository: str
) -> None:
    """Validate the value-only, independently observed release-App authority."""
    fields = {
        "app_identity_binding_exact",
        "environment_branch_policies",
        "environment_custom_branch_policies",
        "environment_name",
        "environment_private_key_secret_name",
        "environment_private_key_secret_present",
        "environment_protected_branches",
        "environment_required_reviewers",
        "environment_variable_name",
        "environment_wait_timer_minutes",
        "immutable_releases",
        "installation_account",
        "installation_events",
        "installation_permissions",
        "installation_repositories",
        "installation_repository_selection",
        "installation_suspended",
        "repository",
    }
    if set(receipt) != fields:
        raise ContractError("release-App receipt fields are missing or foreign")
    if receipt.get("repository") != repository:
        raise ContractError("release-App receipt repository is not exact")
    owner, separator, _name = repository.partition("/")
    if not separator or receipt.get("installation_account") != owner:
        raise ContractError("release-App installation account is not the repository owner")
    if receipt.get("environment_name") != PREFLIGHT_ENVIRONMENT:
        raise ContractError("release-App environment name is not exact")
    reviewers = receipt.get("environment_required_reviewers")
    wait_minutes = receipt.get("environment_wait_timer_minutes")
    if (
        receipt.get("environment_protected_branches") is not False
        or receipt.get("environment_custom_branch_policies") is not True
        or receipt.get("environment_branch_policies")
        != [{"name": "main", "type": "branch"}]
        or isinstance(reviewers, bool)
        or not isinstance(reviewers, int)
        or reviewers != 0
        or isinstance(wait_minutes, bool)
        or not isinstance(wait_minutes, int)
        or wait_minutes != 0
    ):
        raise ContractError("release-App environment is not unattended protected-main only")
    if receipt.get("environment_variable_name") != PREFLIGHT_APP_ID_VARIABLE:
        raise ContractError("release-App ID variable name is not exact")
    if (
        receipt.get("environment_private_key_secret_name")
        != PREFLIGHT_APP_PRIVATE_KEY_SECRET
        or receipt.get("environment_private_key_secret_present") is not True
    ):
        raise ContractError("release-App private-key secret-name receipt is not exact")
    if receipt.get("app_identity_binding_exact") is not True:
        raise ContractError("release-App variable and installation identity are not exact")
    if receipt.get("installation_repository_selection") != "selected":
        raise ContractError("release-App installation must use selected repositories")
    repositories = receipt.get("installation_repositories")
    if repositories != [repository]:
        raise ContractError("release-App installation must select only the exact repository")
    if receipt.get("installation_permissions") != {
        "administration": "read",
        "metadata": "read",
    }:
        raise ContractError("release-App installation permissions are not least-authority")
    if receipt.get("installation_events") != []:
        raise ContractError("release-App installation must subscribe to no events")
    if receipt.get("installation_suspended") is not False:
        raise ContractError("release-App installation must be active")
    if receipt.get("immutable_releases") is not True:
        raise ContractError("release-App token did not prove immutable releases enabled")


def validate_private_vulnerability_reporting(settings: Mapping[str, object]) -> None:
    """Require the authoritative private vulnerability reporting control."""
    if set(settings) != {"enabled"}:
        raise ContractError(
            "private-vulnerability-reporting settings fields are missing or foreign"
        )
    if settings.get("enabled") is not True:
        raise ContractError("GitHub private vulnerability reporting must be enabled")


def validate_settings_receipt(receipt: Mapping[str, object], repository: str) -> None:
    """Validate an owner-observed, value-only protected-main settings receipt."""
    fields = {
        "actions_allowed_actions",
        "actions_can_approve_pull_request_reviews",
        "actions_enabled",
        "actions_sha_pinning_required",
        "allow_deletions",
        "allow_force_pushes",
        "branch",
        "bypass_actors",
        "default_workflow_permissions",
        "immutable_releases",
        "merge_methods",
        "private_vulnerability_reporting",
        "active_release_tag_ruleset_count",
        "release_tag_bypass_actors",
        "release_tag_creation_restricted",
        "release_tag_deletions_allowed",
        "release_tag_excludes",
        "release_tag_includes",
        "release_tag_non_fast_forward_allowed",
        "release_tag_pattern",
        "release_tag_rule_types",
        "release_tag_ruleset",
        "release_tag_ruleset_active",
        "release_tag_ruleset_repository_owned",
        "release_tag_ruleset_target",
        "release_tag_updates_allowed",
        "repository",
        "require_linear_history",
        "require_pull_request",
        "require_signed_commits",
        "required_status_checks",
        "restrict_updates",
        "secret_scanning",
        "secret_scanning_non_provider_patterns",
        "secret_scanning_push_protection",
        "secret_scanning_validity_checks",
        "strict_status_checks",
    }
    if set(receipt) != fields:
        raise ContractError("settings receipt fields are missing or foreign")
    if receipt.get("repository") != repository or receipt.get("branch") != "main":
        raise ContractError("settings receipt repository or branch is not exact")
    if _string_set(receipt.get("merge_methods"), "merge methods") != {"rebase", "squash"}:
        raise ContractError("only squash and rebase merge methods may be enabled")
    expected_checks = {
        (context, GITHUB_ACTIONS_INTEGRATION_ID) for context in REQUIRED_CHECKS
    }
    if _status_check_set(receipt.get("required_status_checks")) != expected_checks:
        raise ContractError("required GitHub Actions checks are missing, foreign, or unbound")
    if receipt.get("actions_allowed_actions") not in {"all", "local_only", "selected"}:
        raise ContractError("Actions allow policy is missing or foreign")
    if receipt.get("default_workflow_permissions") != "read":
        raise ContractError("default workflow token permissions must be read-only")
    for field, expected in (
        ("actions_enabled", True),
        ("actions_sha_pinning_required", True),
        ("actions_can_approve_pull_request_reviews", False),
        ("immutable_releases", True),
        ("private_vulnerability_reporting", True),
        ("release_tag_ruleset_active", True),
        ("release_tag_creation_restricted", False),
        ("release_tag_updates_allowed", False),
        ("release_tag_deletions_allowed", False),
        ("release_tag_non_fast_forward_allowed", False),
        ("strict_status_checks", True),
        ("require_pull_request", True),
        ("require_linear_history", True),
        ("require_signed_commits", True),
        ("allow_force_pushes", False),
        ("allow_deletions", False),
        ("restrict_updates", False),
        ("secret_scanning", True),
        ("secret_scanning_push_protection", True),
    ):
        if receipt.get(field) is not expected:
            raise ContractError(f"settings receipt {field} must be {expected}")
    for field in (
        "secret_scanning_non_provider_patterns",
        "secret_scanning_validity_checks",
    ):
        if not isinstance(receipt.get(field), bool):
            raise ContractError(f"settings receipt {field} must be boolean")
    bypass = receipt.get("bypass_actors")
    if bypass != []:
        raise ContractError("protected-main rules must have no bypass actors")
    if receipt.get("release_tag_ruleset") != EXPECTED_RELEASE_TAG_RULESET:
        raise ContractError("release-tag ruleset identity is not exact")
    if receipt.get("release_tag_pattern") != EXPECTED_RELEASE_TAG_PATTERN:
        raise ContractError("release-tag ruleset pattern is not exact")
    if receipt.get("release_tag_bypass_actors") != []:
        raise ContractError("release-tag rules must have no bypass actors")
    if receipt.get("active_release_tag_ruleset_count") != 1:
        raise ContractError("release-tag ruleset count is not exact")
    if receipt.get("release_tag_ruleset_repository_owned") is not True:
        raise ContractError("release-tag ruleset is not repository-owned")
    if receipt.get("release_tag_ruleset_target") != "tag":
        raise ContractError("release-tag ruleset target is not exact")
    if receipt.get("release_tag_includes") != [EXPECTED_RELEASE_TAG_PATTERN]:
        raise ContractError("release-tag include inventory is not exact")
    if receipt.get("release_tag_excludes") != []:
        raise ContractError("release-tag exclusions must be empty")
    if receipt.get("release_tag_rule_types") != [
        "deletion",
        "non_fast_forward",
        "update",
    ]:
        raise ContractError("release-tag rule inventory is not exact")


def _select_main_ruleset_id(summaries: object, repository: str) -> int:
    candidates: list[Mapping[str, object]] = []
    for value in _array(summaries, "repository rulesets"):
        summary = _object(value, "repository ruleset summary")
        if (
            summary.get("target") == "branch"
            and summary.get("enforcement") == "active"
            and summary.get("source_type") == "Repository"
            and summary.get("source") == repository
        ):
            candidates.append(summary)
    if len(candidates) != 1 or candidates[0].get("name") != EXPECTED_MAIN_RULESET:
        raise ContractError(
            f"expected exactly one active repository-owned {EXPECTED_MAIN_RULESET} ruleset"
        )
    ruleset_id = candidates[0].get("id")
    if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise ContractError(f"{EXPECTED_MAIN_RULESET} ruleset has no authoritative numeric ID")
    return ruleset_id


def _select_release_tag_ruleset_id(summaries: object, repository: str) -> int:
    active_tag_rulesets: list[Mapping[str, object]] = []
    for value in _array(summaries, "repository rulesets"):
        summary = _object(value, "repository ruleset summary")
        if summary.get("target") == "tag" and summary.get("enforcement") == "active":
            active_tag_rulesets.append(summary)
    if len(active_tag_rulesets) != 1:
        raise ContractError(
            "expected exactly one active release-tag ruleset across all sources"
        )
    candidate = active_tag_rulesets[0]
    if (
        candidate.get("name") != EXPECTED_RELEASE_TAG_RULESET
        or candidate.get("source_type") != "Repository"
        or candidate.get("source") != repository
    ):
        raise ContractError("active release-tag ruleset is not the exact repository rule")
    ruleset_id = candidate.get("id")
    if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise ContractError("release-tag ruleset has no authoritative numeric ID")
    return ruleset_id


def _release_tag_ruleset_receipt(
    ruleset_id: int,
    ruleset_record: Mapping[str, object],
    repository: str,
) -> dict[str, object]:
    """Validate creation-permitting, pre-Release immutable tag protection."""
    if (
        ruleset_record.get("id") != ruleset_id
        or ruleset_record.get("name") != EXPECTED_RELEASE_TAG_RULESET
        or ruleset_record.get("target") != "tag"
        or ruleset_record.get("source_type") != "Repository"
        or ruleset_record.get("source") != repository
        or ruleset_record.get("enforcement") != "active"
    ):
        raise ContractError("release-tag ruleset identity or enforcement is not exact")
    conditions = _object(ruleset_record.get("conditions"), "release-tag conditions")
    if set(conditions) != {"ref_name"}:
        raise ContractError("release-tag conditions are missing or foreign")
    ref_name = _object(conditions.get("ref_name"), "release-tag ref condition")
    if (
        set(ref_name) != {"exclude", "include"}
        or ref_name.get("exclude") != []
        or ref_name.get("include") != [EXPECTED_RELEASE_TAG_PATTERN]
    ):
        raise ContractError("release-tag ruleset must target the exact conservative v*.*.* namespace")
    bypass = _array(ruleset_record.get("bypass_actors"), "release-tag bypass actors")
    if bypass:
        raise ContractError("release-tag ruleset must have no bypass actors")

    rules_by_type: dict[str, Mapping[str, object]] = {}
    for value in _array(ruleset_record.get("rules"), "release-tag rules"):
        rule = _object(value, "release-tag rule")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or not rule_type or rule_type in rules_by_type:
            raise ContractError("release-tag rule types must be non-empty and unique")
        rules_by_type[rule_type] = rule
    if set(rules_by_type) != {"update", "deletion", "non_fast_forward"}:
        raise ContractError(
            "release-tag rules must allow creation and forbid update/deletion/force-update"
        )
    update = rules_by_type["update"]
    # GitHub's canonical GET omits the branch-only update parameter from tag
    # rulesets even when the accepted write payload set that parameter false.
    # Bind the authoritative read shape exactly: any parameter or foreign field
    # is an unproved update escape and must fail closed.
    if set(update) != {"type"}:
        raise ContractError(
            "release-tag update rule must use the exact safe tag normalization"
        )
    for rule_type in ("deletion", "non_fast_forward"):
        if set(rules_by_type[rule_type]) != {"type"}:
            raise ContractError(f"release-tag {rule_type} rule has foreign parameters")
    return {
        "active_release_tag_ruleset_count": 1,
        "release_tag_ruleset": EXPECTED_RELEASE_TAG_RULESET,
        "release_tag_ruleset_active": True,
        "release_tag_ruleset_repository_owned": True,
        "release_tag_ruleset_target": "tag",
        "release_tag_pattern": EXPECTED_RELEASE_TAG_PATTERN,
        "release_tag_includes": [EXPECTED_RELEASE_TAG_PATTERN],
        "release_tag_excludes": [],
        "release_tag_creation_restricted": False,
        "release_tag_updates_allowed": False,
        "release_tag_deletions_allowed": False,
        "release_tag_non_fast_forward_allowed": False,
        "release_tag_bypass_actors": [],
        "release_tag_rule_types": ["deletion", "non_fast_forward", "update"],
    }


def build_settings_receipt(
    repository: str,
    repository_record: Mapping[str, object],
    immutable_record: Mapping[str, object],
    private_vulnerability_record: Mapping[str, object],
    actions_record: Mapping[str, object],
    workflow_permissions_record: Mapping[str, object],
    ruleset_id: int,
    ruleset_record: Mapping[str, object],
    tag_ruleset_id: int,
    tag_ruleset_record: Mapping[str, object],
) -> dict[str, object]:
    """Derive and validate a privacy-bounded receipt from authoritative REST."""
    if (
        repository_record.get("full_name") != repository
        or repository_record.get("default_branch") != "main"
    ):
        raise ContractError("repository settings identity or default branch is not exact")
    merge_methods: list[str] = []
    for field, method in (
        ("allow_merge_commit", "merge"),
        ("allow_rebase_merge", "rebase"),
        ("allow_squash_merge", "squash"),
    ):
        enabled = repository_record.get(field)
        if not isinstance(enabled, bool):
            raise ContractError(f"repository setting {field} is not boolean")
        if enabled:
            merge_methods.append(method)
    validate_immutable_settings(immutable_record)
    validate_private_vulnerability_reporting(private_vulnerability_record)

    actions_enabled = actions_record.get("enabled")
    actions_allowed = actions_record.get("allowed_actions")
    actions_sha_pinning = actions_record.get("sha_pinning_required")
    if not isinstance(actions_enabled, bool):
        raise ContractError("Actions enabled state must be boolean")
    if actions_allowed not in {"all", "local_only", "selected"}:
        raise ContractError("Actions allow policy is missing or foreign")
    if not isinstance(actions_sha_pinning, bool):
        raise ContractError("Actions SHA-pinning state must be boolean")
    default_permissions = workflow_permissions_record.get(
        "default_workflow_permissions"
    )
    can_approve = workflow_permissions_record.get(
        "can_approve_pull_request_reviews"
    )
    if default_permissions not in {"read", "write"} or not isinstance(
        can_approve, bool
    ):
        raise ContractError("default workflow permission settings are malformed")

    security = _object(
        repository_record.get("security_and_analysis"),
        "repository security-and-analysis settings",
    )

    def security_enabled(field: str) -> bool:
        record = _object(security.get(field), f"repository {field} setting")
        status = record.get("status")
        if status not in {"enabled", "disabled"}:
            raise ContractError(f"repository {field} status is missing or foreign")
        return status == "enabled"

    if (
        ruleset_record.get("id") != ruleset_id
        or ruleset_record.get("name") != EXPECTED_MAIN_RULESET
        or ruleset_record.get("target") != "branch"
        or ruleset_record.get("source_type") != "Repository"
        or ruleset_record.get("source") != repository
        or ruleset_record.get("enforcement") != "active"
    ):
        raise ContractError("protected-main ruleset identity or enforcement is not exact")
    conditions = _object(ruleset_record.get("conditions"), "protected-main conditions")
    if set(conditions) != {"ref_name"}:
        raise ContractError("protected-main conditions are missing or foreign")
    ref_name = _object(conditions.get("ref_name"), "protected-main ref condition")
    if (
        set(ref_name) != {"exclude", "include"}
        or ref_name.get("exclude") != []
        or ref_name.get("include") != ["refs/heads/main"]
    ):
        raise ContractError("protected-main ruleset must target only refs/heads/main")

    bypass = _array(ruleset_record.get("bypass_actors"), "protected-main bypass actors")
    rules_by_type: dict[str, Mapping[str, object]] = {}
    for value in _array(ruleset_record.get("rules"), "protected-main rules"):
        rule = _object(value, "protected-main rule")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or not rule_type or rule_type in rules_by_type:
            raise ContractError("protected-main rule types must be non-empty and unique")
        rules_by_type[rule_type] = rule

    pull_request = rules_by_type.get("pull_request")
    if pull_request is None:
        raise ContractError("protected main must require pull requests")
    pull_parameters = _object(pull_request.get("parameters"), "pull-request rule parameters")
    allowed_merge_methods = _string_set(
        pull_parameters.get("allowed_merge_methods"), "ruleset merge methods"
    )
    if allowed_merge_methods != set(merge_methods):
        raise ContractError("repository and ruleset merge methods do not match")

    status_rule = rules_by_type.get("required_status_checks")
    if status_rule is None:
        raise ContractError("protected main must require exact status checks")
    status_parameters = _object(status_rule.get("parameters"), "status-check rule parameters")
    if status_parameters.get("do_not_enforce_on_create") is not False:
        raise ContractError("required checks must also apply when the ref is created")
    status_checks = _status_check_set(status_parameters.get("required_status_checks"))

    receipt: dict[str, object] = {
        "repository": repository,
        "branch": "main",
        "merge_methods": sorted(merge_methods),
        "required_status_checks": [
            {"context": context, "integration_id": integration_id}
            for context, integration_id in sorted(status_checks)
        ],
        "strict_status_checks": status_parameters.get(
            "strict_required_status_checks_policy"
        ),
        "actions_enabled": actions_enabled,
        "actions_allowed_actions": actions_allowed,
        "actions_sha_pinning_required": actions_sha_pinning,
        "default_workflow_permissions": default_permissions,
        "actions_can_approve_pull_request_reviews": can_approve,
        "require_pull_request": True,
        "require_linear_history": "required_linear_history" in rules_by_type,
        "require_signed_commits": "required_signatures" in rules_by_type,
        "allow_force_pushes": "non_fast_forward" not in rules_by_type,
        "allow_deletions": "deletion" not in rules_by_type,
        "restrict_updates": "update" in rules_by_type,
        # Actor and ruleset IDs are not publication-safe. Presence is the only
        # receipt fact, and the only accepted value is the empty set.
        "bypass_actors": [] if not bypass else ["present"],
        "immutable_releases": immutable_record.get("enabled"),
        "private_vulnerability_reporting": private_vulnerability_record.get("enabled"),
        "secret_scanning": security_enabled("secret_scanning"),
        "secret_scanning_push_protection": security_enabled(
            "secret_scanning_push_protection"
        ),
        "secret_scanning_non_provider_patterns": security_enabled(
            "secret_scanning_non_provider_patterns"
        ),
        "secret_scanning_validity_checks": security_enabled(
            "secret_scanning_validity_checks"
        ),
    }
    receipt.update(
        _release_tag_ruleset_receipt(
            tag_ruleset_id,
            tag_ruleset_record,
            repository,
        )
    )
    validate_settings_receipt(receipt, repository)
    return receipt


def _github_api_get(endpoint: str, *, paginate: bool = False) -> object:
    command = [
        "gh",
        "api",
        "--method",
        "GET",
        "--header",
        "Accept: application/vnd.github+json",
        "--header",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
    ]
    if paginate:
        command.extend(("--paginate", "--slurp"))
    command.append(endpoint)
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ContractError("read-only GitHub settings query failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ContractError("read-only GitHub settings query returned malformed JSON") from exc
    if not paginate:
        return value
    flattened: list[object] = []
    for page in _array(value, "paginated GitHub settings response"):
        flattened.extend(_array(page, "paginated GitHub settings page"))
    return flattened


def observe_live_settings(repository: str) -> dict[str, object]:
    """Query GET endpoints only and emit a receipt only for exact live state."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ContractError("repository must be an exact owner/name pair")
    repository_record = _object(_github_api_get(f"repos/{repository}"), "repository settings")
    immutable_record = _object(
        _github_api_get(f"repos/{repository}/immutable-releases"),
        "immutable-release settings",
    )
    private_vulnerability_record = _object(
        _github_api_get(f"repos/{repository}/private-vulnerability-reporting"),
        "private-vulnerability-reporting settings",
    )
    actions_record = _object(
        _github_api_get(f"repos/{repository}/actions/permissions"),
        "Actions policy settings",
    )
    workflow_permissions_record = _object(
        _github_api_get(f"repos/{repository}/actions/permissions/workflow"),
        "default workflow permission settings",
    )
    summaries = _github_api_get(
        f"repos/{repository}/rulesets?includes_parents=true&per_page=100",
        paginate=True,
    )
    ruleset_id = _select_main_ruleset_id(summaries, repository)
    tag_ruleset_id = _select_release_tag_ruleset_id(summaries, repository)
    ruleset_record = _object(
        _github_api_get(f"repos/{repository}/rulesets/{ruleset_id}"),
        "protected-main ruleset",
    )
    tag_ruleset_record = _object(
        _github_api_get(f"repos/{repository}/rulesets/{tag_ruleset_id}"),
        "release-tag ruleset",
    )
    return build_settings_receipt(
        repository,
        repository_record,
        immutable_record,
        private_vulnerability_record,
        actions_record,
        workflow_permissions_record,
        ruleset_id,
        ruleset_record,
        tag_ruleset_id,
        tag_ruleset_record,
    )


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
    if (
        tagger_name != "github-actions[bot]"
        or tagger_email
        != "41898282+github-actions[bot]@users.noreply.github.com"
    ):
        raise ContractError("expected annotated tagger is not the GitHub Actions bot")
    tagger = _object(tag_record.get("tagger"), "annotated tagger")
    if tagger.get("name") != tagger_name or tagger.get("email") != tagger_email:
        raise ContractError("annotated tagger identity violates policy")
    _same_instant(tagger.get("date"), tagger_date, "annotated tagger date")


def validate_release_record(
    release_record: Mapping[str, object], *, tag: str, title: str, body: str
) -> None:
    """Verify the immutable GitHub Actions Release and closed asset set."""
    if release_record.get("tag_name") != tag or release_record.get("name") != title:
        raise ContractError("GitHub Release tag or title is not exact")
    actual_body = release_record.get("body")
    if not isinstance(actual_body, str) or actual_body.rstrip("\r\n") != body.rstrip("\r\n"):
        raise ContractError("GitHub Release notes are not exact")
    if release_record.get("draft") is not False or release_record.get("prerelease") is not False:
        raise ContractError("GitHub Release must be published and non-prerelease")
    if release_record.get("immutable") is not True:
        raise ContractError("GitHub Release must be authoritatively immutable")
    author = _object(release_record.get("author"), "GitHub Release author")
    if (
        author.get("login") != "github-actions[bot]"
        or author.get("id") != 41898282
    ):
        raise ContractError("GitHub Release author is not the GitHub Actions bot")
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


def _emit_fragment(intent: FragmentIntent) -> None:
    print(
        json.dumps(
            {
                "fragment_path": intent.fragment_path,
                "fragment_sha256": intent.fragment_sha256,
                "source_sha": intent.source_sha,
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
    notes = commands.add_parser("release-notes")
    notes.add_argument("--repository", type=Path, required=True)
    notes.add_argument("--head", required=True)
    notes.add_argument("--tag", required=True)
    notes.add_argument("--base-sha")
    notes.add_argument("--base-tag")
    recovery = commands.add_parser("recovery-release")
    recovery.add_argument("--repository", type=Path, required=True)
    recovery.add_argument("--source-sha", required=True)
    recovery.add_argument("--tag", required=True)
    event = commands.add_parser("workflow-run")
    event.add_argument("--event", type=Path, required=True)
    event.add_argument("--repository", required=True)
    settings = commands.add_parser("settings-receipt")
    settings.add_argument("--receipt", type=Path, required=True)
    settings.add_argument("--repository", required=True)
    settings_preflight = commands.add_parser("settings-preflight")
    settings_preflight.add_argument("--repository", required=True)
    app_receipt = commands.add_parser("app-provisioning-receipt")
    app_receipt.add_argument("--receipt", type=Path, required=True)
    app_receipt.add_argument("--repository", required=True)
    immutable_settings = commands.add_parser("immutable-settings")
    immutable_settings.add_argument("--settings-json", type=Path, required=True)
    immutable_receipt = commands.add_parser("immutable-settings-receipt")
    immutable_receipt.add_argument("--settings-json", type=Path, required=True)
    immutable_receipt.add_argument("--repository", required=True)
    immutable_receipt.add_argument("--source-sha", required=True)
    immutable_receipt.add_argument("--run-id", required=True)
    immutable_receipt.add_argument("--run-attempt", required=True)
    jobs_receipt = commands.add_parser("main-ci-jobs-receipt")
    jobs_receipt.add_argument("--jobs-json", type=Path, required=True)
    jobs_receipt.add_argument("--codeql-runs-json", type=Path, required=True)
    jobs_receipt.add_argument("--codeql-jobs-json", type=Path, required=True)
    jobs_receipt.add_argument("--repository", required=True)
    jobs_receipt.add_argument("--source-sha", required=True)
    jobs_receipt.add_argument("--run-id", required=True)
    jobs_receipt.add_argument("--run-attempt", required=True)
    codeql_run_state = commands.add_parser("codeql-run-state")
    codeql_run_state.add_argument("--runs-json", type=Path, required=True)
    codeql_run_state.add_argument("--source-sha", required=True)
    codeql_jobs_state = commands.add_parser("codeql-jobs-state")
    codeql_jobs_state.add_argument("--jobs-json", type=Path, required=True)
    codeql_jobs_state.add_argument("--run-id", type=int, required=True)
    codeql_jobs_state.add_argument("--run-attempt", type=int, required=True)
    codeql_jobs_state.add_argument("--source-sha", required=True)
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
            _emit_fragment(
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
                        "base_tag": window.base_tag,
                        "fragment_path": window.fragment_path,
                        "fragment_sha256": window.fragment_sha256,
                        "source_sha": window.intent.source_sha,
                        "tag": window.intent.tag,
                        "version": str(window.intent.version),
                    },
                    sort_keys=True,
                )
            )
        elif args.command == "release-notes":
            print(
                render_release_notes(
                    args.repository,
                    args.head,
                    args.tag,
                    expected_base_sha=args.base_sha,
                    expected_base_tag=args.base_tag,
                ),
                end="",
            )
        elif args.command == "recovery-release":
            _emit(
                validate_recovery_release(
                    args.repository,
                    args.source_sha,
                    args.tag,
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
        elif args.command == "settings-preflight":
            print(json.dumps(observe_live_settings(args.repository), indent=2, sort_keys=True))
        elif args.command == "app-provisioning-receipt":
            validate_app_provisioning_receipt(
                _read_object(args.receipt), args.repository
            )
            print("exact")
        elif args.command == "immutable-settings":
            validate_immutable_settings(_read_object(args.settings_json))
            print("exact")
        elif args.command == "immutable-settings-receipt":
            print(
                json.dumps(
                    build_immutable_settings_receipt(
                        _read_object(args.settings_json),
                        args.repository,
                        args.source_sha,
                        args.run_id,
                        args.run_attempt,
                    ),
                    sort_keys=True,
                )
            )
        elif args.command == "main-ci-jobs-receipt":
            print(
                json.dumps(
                    build_main_ci_jobs_receipt(
                        _read_object(args.jobs_json),
                        _read_object(args.codeql_runs_json),
                        _read_object(args.codeql_jobs_json),
                        args.repository,
                        args.run_id,
                        args.run_attempt,
                        args.source_sha,
                    ),
                    sort_keys=True,
                )
            )
        elif args.command == "codeql-run-state":
            codeql_run = classify_codeql_run(
                _read_object(args.runs_json), args.source_sha
            )
            if codeql_run is None:
                print("pending")
            else:
                print(f"ready:{codeql_run[0]}:{codeql_run[1]}")
        elif args.command == "codeql-jobs-state":
            print(
                "ready"
                if codeql_jobs_ready(
                    _read_object(args.jobs_json),
                    run_id=args.run_id,
                    run_attempt=args.run_attempt,
                    source_sha=args.source_sha,
                )
                else "pending"
            )
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
    except PendingRelease as exc:
        print(f"PENDING: {exc}", file=sys.stderr)
        return 3
    except (ContractError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
