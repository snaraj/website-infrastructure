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
GITHUB_API_VERSION = "2026-03-10"
EXPECTED_MAIN_RULESET = "only-me-merge"
GITHUB_ACTIONS_INTEGRATION_ID = 15368
REQUIRED_CHECKS = (
    "dependency-review",
    "repository-and-infrastructure",
)
RELEASE_AUTHOR_LOGIN = "github-actions[bot]"
RELEASE_AUTHOR_ID = 41898282


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


def _linear_history(repository: Path, head_sha: str) -> list[str]:
    """Return the complete merge-free history ending at one exact head."""
    raw = _git(repository, "rev-list", "--reverse", head_sha)
    commits = raw.splitlines() if raw else []
    if not commits or commits[-1] != head_sha:
        raise ContractError("release history is empty or does not end at the exact head")
    previous: str | None = None
    for commit in commits:
        fields = _git(repository, "rev-list", "--parents", "-n", "1", commit).split()
        if fields[0] != commit:
            raise ContractError("release history commit identity is not exact")
        if previous is None:
            if len(fields) != 1:
                raise ContractError("release history root must have no parent")
        elif len(fields) != 2 or fields[1] != previous:
            raise ContractError("release history must be one contiguous linear commit chain")
        previous = commit
    return commits


def _monotonic_transitions(
    repository: Path, base_sha: str, commits: list[str]
) -> list[tuple[str, str, Version]]:
    """Classify exact patch boundaries without permitting skips or reversions."""
    current = _version_at(repository, base_sha)
    previous = base_sha
    transitions: list[tuple[str, str, Version]] = []
    for commit in commits:
        observed = _version_at(repository, commit)
        if observed == current:
            previous = commit
            continue
        expected = next_version(current)
        if observed != expected:
            rendered = "absent" if observed is None else str(observed)
            raise ContractError(
                f"commit {commit} version {rendered} must remain at the base "
                f"or advance exactly once to {expected}"
            )
        transitions.append((previous, commit, expected))
        current = expected
        previous = commit
    return transitions


def _validated_history_transitions(
    repository: Path, head_sha: str
) -> list[tuple[str, str, Version]]:
    """Prove the complete publisher-visible history and return its boundaries."""
    history = _linear_history(repository, head_sha)
    root = history[0]
    if _version_at(repository, root) is not None:
        raise ContractError("platform release history must begin before VERSION exists")
    return _monotonic_transitions(repository, root, history[1:])


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
    # A squash may collapse several reviewed commits to one main commit, while
    # GitHub rebase installs those commits individually. Both enabled owner
    # choices are release-live only when the reviewed and installed range is a
    # single linear chain with the same monotonic VERSION state machine. A
    # merge-bearing topic is therefore denied even on the PR endpoint: prose
    # cannot make its enabled rebase outcome publisher-recoverable.
    commits = _linear_commits(repository, base_sha, head_sha)
    transitions = _monotonic_transitions(repository, base_sha, commits)
    if len(transitions) != 1:
        raise ContractError("release range must contain exactly one patch boundary")
    history_transitions = _validated_history_transitions(repository, head_sha)
    if not history_transitions or history_transitions[-1] != transitions[0]:
        raise ContractError(
            "release range boundary is not the exact publisher-visible boundary"
        )

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
    """Recover the last boundary from the same monotonic history main CI enforces."""
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head did not resolve exactly")
    transitions = _validated_history_transitions(repository, head_sha)
    if not transitions:
        raise ContractError("release history contains no patch boundary")
    head_version = _version_at(repository, head_sha)
    if head_version is None:
        raise ContractError("release head has no VERSION")
    base_sha, _transition_commit, transition_version = transitions[-1]
    if transition_version != head_version:
        raise ContractError("release head does not retain the last patch boundary")
    changelog = _file(repository, head_sha, "CHANGELOG.md")
    assert changelog is not None
    validate_changelog(changelog, head_version)
    return TransitionWindow(base_sha, Intent(head_sha, head_version))


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


def build_settings_receipt(
    repository: str,
    repository_record: Mapping[str, object],
    immutable_record: Mapping[str, object],
    private_vulnerability_record: Mapping[str, object],
    actions_record: Mapping[str, object],
    workflow_permissions_record: Mapping[str, object],
    ruleset_id: int,
    ruleset_record: Mapping[str, object],
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
    summaries = _github_api_get(f"repos/{repository}/rulesets", paginate=True)
    ruleset_id = _select_main_ruleset_id(summaries, repository)
    ruleset_record = _object(
        _github_api_get(f"repos/{repository}/rulesets/{ruleset_id}"),
        "protected-main ruleset",
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
        author.get("login") != RELEASE_AUTHOR_LOGIN
        or author.get("id") != RELEASE_AUTHOR_ID
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
    settings_preflight = commands.add_parser("settings-preflight")
    settings_preflight.add_argument("--repository", required=True)
    immutable_settings = commands.add_parser("immutable-settings")
    immutable_settings.add_argument("--settings-json", type=Path, required=True)
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
        elif args.command == "settings-preflight":
            print(json.dumps(observe_live_settings(args.repository), indent=2, sort_keys=True))
        elif args.command == "immutable-settings":
            validate_immutable_settings(_read_object(args.settings_json))
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
