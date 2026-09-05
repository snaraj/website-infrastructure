"""Hostile tests for the per-main-merge platform release contract."""

from __future__ import annotations

import contextlib
import concurrent.futures
import copy
import datetime as dt
import hashlib
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Mapping
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "platform_release_contract",
    ROOT / "scripts" / "ci" / "platform_release_contract.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

# The publisher re-derives the exact tag and notes from the checked-out source,
# fetched immutable tag ledger, and one fragment before every write boundary.
PUBLISHER_TAG_GUARD = (
    'python3 -I -B "${contract}" release-notes \\\n'
    '    --repository . --head "${SOURCE_SHA}" --tag "${TAG}" \\\n'
    '    --base-sha "${BASE_SHA}" --base-tag "${BASE_TAG}" > "${notes}"'
)

# Every shape a frozen version can take in the publisher, including the
# un-prefixed one. The `v` is OPTIONAL on purpose: the guard above builds its
# tag as `v` + a value, so a constant written without the prefix and
# interpolated at the use site — `frozen='X.Y.Z'` … `= "v${frozen}"` — is the
# same stranding defect wearing the same idiom the fix itself introduces, and a
# `v`-anchored pattern cannot see it. The pins below are subtracted in both
# forms so widening never mistakes frozen history for a stale constant.
VERSION_LITERAL = r"v?[0-9]+\.[0-9]+\.[0-9]+"


def validate_single_asset_publication_transaction(transaction: str) -> None:
    """Reject any publisher shape outside the signed two-asset transaction."""

    required = (
        ': "${MAIN_RUN_ID:?MAIN_RUN_ID is required}"',
        ': "${MAIN_RUN_ATTEMPT:?MAIN_RUN_ATTEMPT is required}"',
        ': "${SELECTOR_IMAGE_DIGEST:?SELECTOR_IMAGE_DIGEST is required}"',
        'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"',
        'test -z "${ACTIONS_READ_TOKEN-}"',
        'test -z "${CONTENTS_READ_TOKEN-}"',
        'test -z "${GITHUB_TOKEN-}"',
        'test -z "${GH_ENTERPRISE_TOKEN-}"',
        'test -z "${GITHUB_ENTERPRISE_TOKEN-}"',
        'write_token="${GH_TOKEN}"',
        "unset GH_TOKEN",
        'GH_TOKEN="${write_token}" gh "$@"',
        PUBLISHER_TAG_GUARD,
        "recovery_source_sha='51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e'",
        "recovery_tag='v0.1.0'",
        '-f object="${SOURCE_SHA}" -f type=commit',
        'tagger[name]=${tagger_name}',
        'tagger[email]=${tagger_email}',
        'tagger[date]=${tagger_date}',
        'run_write_gh release create "${recovery_tag}" --verify-tag',
        '--target "${recovery_source_sha}"',
        "identity_asset_name='platform-release-identity.v1.json'",
        "identity_bundle_name='platform-release-identity.v1.json.sigstore.json'",
        '(.assets | length == $count)',
        '(([.assets[].name] | sort) == ($expected | sort))',
        'selector-image-from-release --release-json "${release_json}"',
        '--identity "${identity_download}" --bundle "${bundle_download}"',
        '--source-tree-sha "${tree_sha}"',
        "identity-run-records",
        "validate_selector_transition",
        '[[ "${SELECTOR_IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]',
        'git diff --quiet "${BASE_SHA}" "${SOURCE_SHA}" --',
        "cmd/platform-release-selector internal/releaseselector go.mod",
        'test "${SELECTOR_IMAGE_DIGEST}" = "${predecessor_digest}"',
        'test "${SELECTOR_IMAGE_DIGEST}" != "${predecessor_digest}"',
        'test "${SELECTOR_BUILD_SHA}" = "${predecessor_build_sha}"',
        'test "${SELECTOR_BUILD_SHA}" = "${SOURCE_SHA}"',
        'test "${SELECTOR_BUILD_SHA}" != "${predecessor_build_sha}"',
        "identity-release-state",
        '--http-status "${status}" --require "${required}"',
        "burned_source_sha='6d85c2b01dd4bd66add4192372b26bcdf1b0a951'",
        "burned_tag='v0.1.42'",
        "burned_draft_id='378336604'",
        "burned_main_run_id='33152936164'",
        "burned_platform_run_id='33153400419'",
        "burned_selector_digest='sha256:c9f8d59013bc5ca9431e3ccd22227e4e05920746829318cacf1ccb70b17d2e61'",
        "run_write_gh api --paginate --slurp",
        'repos/${GITHUB_REPOSITORY}/releases?per_page=100',
        "release-draft-state",
        '--expected-release-id "${burned_draft_id}"',
        "--expected-asset-count 2",
        "burned-partial-release-record",
        "validate_burned_partial",
        'run_write_gh api --method DELETE',
        'repos/${GITHUB_REPOSITORY}/releases/${release_id}',
        "retire_burned_partial_draft",
        'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then',
        'test "${BASE_TAG}" = v0.1.40',
        'test "${TAG}" = v0.1.41',
        '--base-tag "${BASE_TAG}" --target-tag "${TAG}"',
        '--repository .',
        '--release-json "${release_json}"',
        '--main-runs-json "${legacy_main_runs_json}"',
        '--platform-runs-json "${legacy_platform_runs_json}"',
        '--emit > "${legacy_predecessor_json}"',
        'actions/runs/${legacy_main_run_id}/attempts/${legacy_main_run_attempt}',
        'actions/runs/${legacy_platform_run_id}/attempts/${legacy_platform_run_attempt}',
        '--main-run-json "${legacy_main_run_json}"',
        '--platform-run-json "${legacy_platform_run_json}"',
        "'{body:$body,draft:true,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}'",
        '--input "${draft_request}" --jq \'.id\')"',
        "release-draft-record",
        '--release-id "${release_id}"',
        '--main-run-id "${main_run_id}"',
        '--main-run-attempt "${main_run_attempt}"',
        '--platform-run-id "${platform_run_id}"',
        '--platform-run-attempt "${platform_run_attempt}"',
        '--selector-image-digest "${selector_digest}"',
        'cosign sign-blob --yes',
        '--bundle "${identity_bundle}" "${identity_asset}"',
        'verify_identity_signature "${identity_asset}" "${identity_bundle}"',
        "--header 'Content-Type: application/json'",
        '--data-binary "@${path}"',
        'upload_identity_asset "${release_id}" "${identity_asset_name}"',
        'upload_identity_asset "${release_id}" "${identity_bundle_name}"',
        'test "${status}" = 201',
        'download_identity_pair "${release_json}"',
        'cmp -s "${identity_asset}" "${identity_download}"',
        'cmp -s "${identity_bundle}" "${bundle_download}"',
        "staged-identity-release-record",
        "'{body:$body,draft:false,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}'",
        '--input "${publish_patch}"',
    )
    for token in required:
        if token not in transaction:
            raise ValueError(f"signed identity transaction lost exact guard: {token}")

    forbidden = (
        'run_write_gh release create "${TAG}"',
        '--target "${SOURCE_SHA}"',
        "selector-seed",
        "validate_selector_seed",
        "releasecutover",
        "release-cutover",
        "cutover-image",
        "settings_token",
        "--require-ready",
        "0000000000000000000000000000000000000000",
        "git tag -d",
        "refs/tags/${burned_tag}",
    )
    for token in forbidden:
        if token in transaction:
            raise ValueError(f"signed identity transaction retained retired path: {token}")

    notes_start = transaction.index("write_current_notes() {")
    notes_end = transaction.index("\n}\n", notes_start) + 3
    expected_notes = (
        "write_current_notes() {\n"
        "  python3 -I -B \"${contract}\" release-notes \\\n"
        "    --repository . --head \"${SOURCE_SHA}\" --tag \"${TAG}\" \\\n"
        "    --base-sha \"${BASE_SHA}\" --base-tag \"${BASE_TAG}\" > \"${notes}\"\n"
        "}\n"
    )
    if transaction[notes_start:notes_end] != expected_notes:
        raise ValueError("current release-notes command drifted or gained a stray shell command")

    exact_counts = {
        "release-draft-record": 1,
        "release-draft-state": 3,
        "staged-identity-release-record": 1,
        "identity-release-state": 1,
        'upload_identity_asset "${release_id}"': 2,
        "validate_platform_predecessor.py": 2,
        "validate_selector_transition": 2,
        "cosign sign-blob": 1,
        "cosign verify-blob": 1,
        'run_write_gh release create "${recovery_tag}"': 1,
        "'{body:$body,draft:true,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}'": 2,
        "'{body:$body,draft:false,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}'": 1,
        "tag_name:$tag,target_commitish:$target": 3,
    }
    for token, expected in exact_counts.items():
        actual = transaction.count(token)
        if actual != expected:
            raise ValueError(
                f"signed identity transaction count drifted for {token}: {actual} != {expected}"
            )

    classifier_start = transaction.index("classify_current_release() {")
    classifier_end = transaction.index("classify_predecessor_release() {")
    current_classifier = transaction[classifier_start:classifier_end]
    if "--body" in current_classifier or '"${contract}" release-state' in current_classifier:
        raise ValueError("immutable current release must not trust Markdown body")
    for token in (
        "download_identity_pair",
        "selector-image-from-release",
        '--bundle "${bundle_download}"',
        '--source-tree-sha "${tree_sha}"',
        "identity-release-state",
    ):
        if token not in current_classifier:
            raise ValueError(f"current classifier lost identity input: {token}")

    legacy_edge = 'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then'
    legacy_start = transaction.index(legacy_edge)
    legacy_end = transaction.index("\n  fi", legacy_start)
    legacy = transaction[legacy_start:legacy_end]
    for token in (
        '--repository .',
        '--base-tag "${BASE_TAG}" --target-tag "${TAG}"',
        '--release-json "${release_json}"',
        '--main-runs-json "${legacy_main_runs_json}"',
        '--platform-runs-json "${legacy_platform_runs_json}"',
        '--emit > "${legacy_predecessor_json}"',
        '--main-run-json "${legacy_main_run_json}"',
        '--platform-run-json "${legacy_platform_run_json}"',
    ):
        if token not in legacy:
            raise ValueError(f"legacy predecessor validation lost exact input: {token}")
    if legacy.count("validate_platform_predecessor.py") != 2:
        raise ValueError("legacy predecessor must be validated before and after run retrieval")

    burned_start = transaction.index("validate_burned_partial() {")
    burned_end = transaction.index("\n}\n", burned_start)
    burned = transaction[burned_start:burned_end]
    burned_order = (
        '${api}/releases/${burned_draft_id}',
        "write_burned_notes",
        'download_identity_pair "${release_json}"',
        'actions/runs/${burned_main_run_id}/attempts/${burned_run_attempt}',
        'actions/runs/${burned_platform_run_id}/attempts/${burned_run_attempt}',
        "burned-partial-release-record",
        'test "${digest}" = "${burned_selector_digest}"',
        'test "${digest}" = "${SELECTOR_IMAGE_DIGEST}"',
        'test "${SELECTOR_BUILD_SHA}" = "${burned_source_sha}"',
    )
    burned_positions = [burned.index(token) for token in burned_order]
    if burned_positions != sorted(burned_positions):
        raise ValueError("burned partial validation order drifted")

    retire_start = transaction.index("retire_burned_partial_draft() {")
    retire_end = transaction.index("complete_recovery_release() {", retire_start)
    retirement = transaction[retire_start:retire_end]
    if not (
        retirement.index("validate_burned_partial")
        < retirement.index("run_write_gh api --method DELETE")
        < retirement.rindex("validate_burned_partial")
    ):
        raise ValueError("burned draft deletion lost pre/post validation")

    current_start = transaction.index("publish_current_release() {")
    current = transaction[current_start:]
    ordered = (
        "write_current_draft_marker",
        "write_current_notes",
        "${draft_request}",
        'release_id="$(run_write_gh api --method POST',
        "release-draft-state",
        "${body_patch}",
        "release-draft-record",
        'test "$(classify_current_draft exact)"',
        "write_current_identity",
        "cosign sign-blob --yes",
        'verify_identity_signature "${identity_asset}" "${identity_bundle}"',
        'upload_identity_asset "${release_id}" "${identity_asset_name}"',
        'upload_identity_asset "${release_id}" "${identity_bundle_name}"',
        "download_identity_pair",
        'cmp -s "${identity_asset}" "${identity_download}"',
        'cmp -s "${identity_bundle}" "${bundle_download}"',
        "staged-identity-release-record",
        "${publish_patch}",
        '--input "${publish_patch}"',
    )
    positions = [current.index(token) for token in ordered]
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise ValueError("draft, asset validation, and immutable publication order drifted")
    if current.rindex("classify_current_release exact") < positions[-1]:
        raise ValueError("immutable publication lacks a terminal exact-state observation")

    expected_incident_versions = {
        "v0.1.40": 3,
        "v0.1.41": 4,
        "v0.1.42": 1,
        "v0.1.43": 2,
    }
    for version, expected in expected_incident_versions.items():
        if transaction.count(version) != expected:
            raise ValueError(
                f"the reviewed release incident literal drifted: {version}"
            )
    allowed_versions = {
        MODULE.RECOVERY_TAG,
        MODULE.RECOVERY_TAG.removeprefix("v"),
        "v0.1.40",
        "0.1.40",
        "v0.1.41",
        "0.1.41",
        "v0.1.42",
        "0.1.42",
        "v0.1.43",
        "0.1.43",
    }
    foreign_versions = set(re.findall(VERSION_LITERAL, transaction)) - allowed_versions
    if foreign_versions:
        raise ValueError(
            f"publisher contains a stale version literal: {sorted(foreign_versions)}"
        )


def event(sha: str) -> dict[str, object]:
    return {
        "repository": {"full_name": "owner/platform"},
        "workflow_run": {
            "name": "Pull request",
            "path": ".github/workflows/pull-request.yml@refs/heads/main",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": sha,
            "head_repository": {"full_name": "owner/platform"},
        },
    }


def settings_receipt() -> dict[str, object]:
    return {
        "active_main_branch_ruleset_count": 2,
        "owner_update_ruleset": "Owner-PR-Updates",
        "owner_update_ref": "~DEFAULT_BRANCH",
        "owner_update_fetch_and_merge": False,
        "owner_update_bypass": "owner-user-pull-request",
        "repository": "owner/platform",
        "branch": "main",
        "actions_enabled": True,
        "actions_allowed_actions": "all",
        "actions_sha_pinning_required": True,
        "default_workflow_permissions": "read",
        "actions_can_approve_pull_request_reviews": False,
        "merge_methods": ["rebase", "squash"],
        "required_status_checks": [
            {"context": context, "integration_id": 15368}
            for context in MODULE.REQUIRED_CHECKS
        ],
        "strict_status_checks": True,
        "require_pull_request": True,
        "require_linear_history": True,
        "require_signed_commits": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "restrict_updates": False,
        "bypass_actors": [],
        "active_release_tag_ruleset_count": 1,
        "release_tag_ruleset": "immutable-platform-release-tags",
        "release_tag_ruleset_active": True,
        "release_tag_ruleset_repository_owned": True,
        "release_tag_ruleset_target": "tag",
        "release_tag_pattern": "refs/tags/v*.*.*",
        "release_tag_includes": ["refs/tags/v*.*.*"],
        "release_tag_excludes": [],
        "release_tag_creation_restricted": False,
        "release_tag_updates_allowed": False,
        "release_tag_deletions_allowed": False,
        "release_tag_non_fast_forward_allowed": False,
        "release_tag_bypass_actors": [],
        "release_tag_rule_types": ["deletion", "non_fast_forward", "update"],
        "immutable_releases": True,
        "private_vulnerability_reporting": True,
        "secret_scanning": True,
        "secret_scanning_push_protection": True,
        "secret_scanning_non_provider_patterns": False,
        "secret_scanning_validity_checks": False,
    }


def app_provisioning_receipt() -> dict[str, object]:
    return {
        "repository": "owner/platform",
        "environment_name": "platform-release",
        "environment_protected_branches": False,
        "environment_custom_branch_policies": True,
        "environment_branch_policies": [{"name": "main", "type": "branch"}],
        "environment_required_reviewers": 0,
        "environment_wait_timer_minutes": 0,
        "environment_variable_name": "PLATFORM_RELEASE_APP_ID",
        "environment_private_key_secret_name": "PLATFORM_RELEASE_APP_PRIVATE_KEY",
        "environment_private_key_secret_present": True,
        "app_identity_binding_exact": True,
        "installation_account": "owner",
        "installation_repository_selection": "selected",
        "installation_repositories": ["owner/platform"],
        "installation_permissions": {
            "administration": "read",
            "metadata": "read",
        },
        "installation_events": [],
        "installation_suspended": False,
        "immutable_releases": True,
    }


def main_ci_jobs_record() -> dict[str, object]:
    source = "a" * 40
    repository_steps = [
        {"name": name, "conclusion": conclusion}
        for name, conclusion in MODULE.MAIN_CI_EXACT_STEPS
    ]
    common = {
        "run_id": 4242,
        "run_attempt": 1,
        "head_sha": source,
        "head_branch": "main",
        "workflow_name": "Pull request",
        "status": "completed",
    }
    return {
        "total_count": 2,
        "jobs": [
            {
                **common,
                "id": 1001,
                "name": "repository-and-infrastructure",
                "conclusion": "success",
                "steps": repository_steps,
            },
            {
                **common,
                "id": 1002,
                "name": "dependency-review",
                "conclusion": "skipped",
                "steps": [],
            },
        ],
    }


def codeql_runs_record() -> dict[str, object]:
    return {
        "total_count": 1,
        "workflow_runs": [
            {
                "id": 5001,
                "name": "CodeQL",
                "path": ".github/workflows/codeql.yml",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "head_branch": "main",
                "head_sha": "a" * 40,
                "run_attempt": 1,
            }
        ],
    }


def codeql_jobs_record() -> dict[str, object]:
    return {
        "total_count": len(MODULE.CODEQL_EXACT_STEPS),
        "jobs": [
            {
                "id": 6001 + index,
                "name": name,
                "run_id": 5001,
                "run_attempt": 1,
                "head_sha": "a" * 40,
                "head_branch": "main",
                "workflow_name": "CodeQL",
                "status": "completed",
                "conclusion": "success",
                "steps": [
                    {"name": step_name, "conclusion": conclusion}
                    for step_name, conclusion in exact_steps
                ],
            }
            for index, (name, exact_steps) in enumerate(
                MODULE.CODEQL_EXACT_STEPS.items()
            )
        ],
    }


def settings_api() -> dict[str, object]:
    ruleset_id = 42
    tag_ruleset_id = 43
    checks = [
        {"context": context, "integration_id": 15368}
        for context in MODULE.REQUIRED_CHECKS
    ]
    records = {
        "repos/owner/platform": {
            "full_name": "owner/platform",
            "default_branch": "main",
            "allow_merge_commit": False,
            "allow_rebase_merge": True,
            "allow_squash_merge": True,
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
                "secret_scanning_non_provider_patterns": {"status": "disabled"},
                "secret_scanning_validity_checks": {"status": "disabled"},
            },
        },
        "repos/owner/platform/immutable-releases": {
            "enabled": True,
            "enforced_by_owner": False,
        },
        "repos/owner/platform/private-vulnerability-reporting": {
            "enabled": True,
        },
        "repos/owner/platform/actions/permissions": {
            "enabled": True,
            "allowed_actions": "all",
            "sha_pinning_required": True,
        },
        "repos/owner/platform/actions/permissions/workflow": {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        "repos/owner/platform/rulesets?includes_parents=true&per_page=100": [
            {
                "id": ruleset_id,
                "name": "only-me-merge",
                "target": "branch",
                "source_type": "Repository",
                "source": "owner/platform",
                "enforcement": "active",
            },
            {
                "id": tag_ruleset_id,
                "name": "immutable-platform-release-tags",
                "target": "tag",
                "source_type": "Repository",
                "source": "owner/platform",
                "enforcement": "active",
            },
        ],
        f"repos/owner/platform/rulesets/{ruleset_id}": {
            "id": ruleset_id,
            "name": "only-me-merge",
            "target": "branch",
            "source_type": "Repository",
            "source": "owner/platform",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"exclude": [], "include": ["refs/heads/main"]},
            },
            "bypass_actors": [],
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "allowed_merge_methods": ["rebase", "squash"]
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "do_not_enforce_on_create": False,
                        "required_status_checks": checks,
                        "strict_required_status_checks_policy": True,
                    },
                },
                {"type": "required_signatures"},
            ],
        },
        f"repos/owner/platform/rulesets/{tag_ruleset_id}": {
            "id": tag_ruleset_id,
            "name": "immutable-platform-release-tags",
            "target": "tag",
            "source_type": "Repository",
            "source": "owner/platform",
            "enforcement": "active",
            "conditions": {
                "ref_name": {
                    "exclude": [],
                    "include": ["refs/tags/v*.*.*"],
                },
            },
            "bypass_actors": [],
            "rules": [
                {"type": "update"},
                {"type": "deletion"},
                {"type": "non_fast_forward"},
            ],
        },
    }

    owner = {
        "id": 44, "name": "Owner-PR-Updates", "target": "branch",
        "source_type": "Repository", "source": "owner/platform", "enforcement": "active",
    }
    records["repos/owner/platform/rulesets?includes_parents=true&per_page=100"].append(owner)
    records["repos/owner/platform/rulesets/44"] = {
        **owner,
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}],
    }
    records["repos/owner/platform/rulesets/44"]["bypass_actors"] = [{
        "actor_id": 39077795, "actor_type": "User", "bypass_mode": "pull_request",
    }]
    return records


def exact_tag_records(
    tag: str, source: str, message: str, date: str
) -> tuple[dict[str, object], dict[str, object]]:
    tag_object = "b" * 40
    return (
        {"ref": f"refs/tags/{tag}", "object": {"type": "tag", "sha": tag_object}},
        {
            "sha": tag_object,
            "tag": tag,
            "message": message,
            "object": {"type": "commit", "sha": source},
            "tagger": {
                "name": "github-actions[bot]",
                "email": "41898282+github-actions[bot]@users.noreply.github.com",
                "date": date,
            },
        },
    )


class VersionAndEventTests(unittest.TestCase):
    SHA = "a" * 40

    def test_initial_and_later_versions_are_exact_arithmetic_patches(self):
        self.assertEqual(MODULE.next_version(None), MODULE.Version(0, 1, 0))
        self.assertEqual(
            MODULE.next_version(MODULE.Version.parse("0.1.9")),
            MODULE.Version.parse("0.1.10"),
        )
        for invalid in ("v0.1.0", "01.0.0", "0.1", "0.1.0-rc1", "0.1.-1"):
            with self.subTest(invalid=invalid), self.assertRaises(MODULE.ContractError):
                MODULE.Version.parse(invalid)

    def test_exact_success_event_and_every_hostile_identity(self):
        self.assertEqual(MODULE.plan_workflow_run(event(self.SHA), "owner/platform"), self.SHA)
        mutations = (
            ("repository", "full_name", "other/platform"),
            ("workflow_run", "name", "Other"),
            ("workflow_run", "path", ".github/workflows/other.yml"),
            ("workflow_run", "event", "pull_request"),
            ("workflow_run", "status", "in_progress"),
            ("workflow_run", "conclusion", "failure"),
            ("workflow_run", "head_branch", "feature"),
            ("workflow_run", "head_sha", "1234567"),
        )
        for parent, key, value in mutations:
            payload = json.loads(json.dumps(event(self.SHA)))
            payload[parent][key] = value
            with self.subTest(parent=parent, key=key), self.assertRaises(MODULE.ContractError):
                MODULE.plan_workflow_run(payload, "owner/platform")
        payload = event(self.SHA)
        payload["workflow_run"]["head_repository"]["full_name"] = "other/platform"
        with self.assertRaises(MODULE.ContractError):
            MODULE.plan_workflow_run(payload, "owner/platform")

    def test_workflow_run_cli_binds_the_same_event_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "event.json"
            path.write_text(json.dumps(event(self.SHA)), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = MODULE.main(
                    [
                        "workflow-run",
                        "--event",
                        str(path),
                        "--repository",
                        "owner/platform",
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(output.getvalue().strip(), self.SHA)

    def test_frozen_recovery_release_is_exact_history_not_an_input_escape(self):
        intent = MODULE.validate_recovery_release(
            ROOT, MODULE.RECOVERY_SOURCE_SHA, MODULE.RECOVERY_TAG
        )
        self.assertEqual(intent.source_sha, MODULE.RECOVERY_SOURCE_SHA)
        self.assertEqual(intent.tag, MODULE.RECOVERY_TAG)
        for source, tag in (
            ("a" * 40, MODULE.RECOVERY_TAG),
            (MODULE.RECOVERY_SOURCE_SHA, "v0.1.1"),
        ):
            with self.subTest(source=source, tag=tag), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_recovery_release(ROOT, source, tag)

        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                MODULE.main(
                    [
                        "recovery-release",
                        "--repository",
                        str(ROOT),
                        "--source-sha",
                        MODULE.RECOVERY_SOURCE_SHA,
                        "--tag",
                        MODULE.RECOVERY_TAG,
                    ]
                ),
                0,
            )
        self.assertEqual(json.loads(output.getvalue())["tag"], MODULE.RECOVERY_TAG)



class OwnerMergeRestrictionTests(unittest.TestCase):
    def test_github_readback_omits_only_the_false_update_parameters(self):
        exact = settings_api()
        rule = exact["repos/owner/platform/rulesets/44"]["rules"][0]
        del rule["parameters"]
        self.assertEqual(SettingsReceiptTests.observe(exact), settings_receipt())
        for invalid in (None, {}, {"unknown": False},
                        {"update_allows_fetch_and_merge": True},
                        {"update_allows_fetch_and_merge": 0}):
            changed = copy.deepcopy(exact)
            changed["repos/owner/platform/rulesets/44"]["rules"][0]["parameters"] = invalid
            with self.subTest(parameters=invalid), self.assertRaises(MODULE.ContractError):
                SettingsReceiptTests.observe(changed)

    def test_owner_restriction_requires_exact_structure_and_scalar_types(self):
        exact = settings_api()
        self.assertEqual(SettingsReceiptTests.observe(exact), settings_receipt())
        for path, value in (
            (("id",), True), (("id",), 45), (("name",), "foreign"),
            (("target",), "tag"), (("source_type",), "Organization"),
            (("source",), "foreign/repository"), (("enforcement",), "disabled"),
            (("conditions", "ref_name", "include"), ["~ALL"]),
            (("conditions", "ref_name", "exclude"), ["refs/heads/main"]),
            (("rules",), []),
            (("rules", 0, "type"), "deletion"),
            (("rules", 0, "parameters", "update_allows_fetch_and_merge"), True),
            (("rules", 0, "parameters", "update_allows_fetch_and_merge"), 0),
        ):
            with self.subTest(path=path, value=value):
                changed = copy.deepcopy(exact)
                target = changed["repos/owner/platform/rulesets/44"]
                for key in path[:-1]: target = target[key]
                target[path[-1]] = value
                with self.assertRaises(MODULE.ContractError):
                    SettingsReceiptTests.observe(changed)
        for field in ("id", "conditions", "rules"):
            changed = copy.deepcopy(exact)
            del changed["repos/owner/platform/rulesets/44"][field]
            with self.subTest(missing=field), self.assertRaises(MODULE.ContractError):
                SettingsReceiptTests.observe(changed)

    def test_both_rulesets_are_required_without_ambiguous_or_foreign_inventory(self):
        exact = settings_api()
        summaries = exact["repos/owner/platform/rulesets?includes_parents=true&per_page=100"]
        for changed_summaries in (
            [r for r in summaries if r["name"] != "Owner-PR-Updates"],
            [r for r in summaries if r["name"] == "Owner-PR-Updates"],
            [*summaries, summaries[-1]],
            [*summaries, {**summaries[-1], "id": 45, "name": "foreign"}],
            [*summaries[:-1], {**summaries[-1], "id": 42}],
        ):
            changed = copy.deepcopy(exact)
            changed["repos/owner/platform/rulesets?includes_parents=true&per_page=100"] = changed_summaries
            with self.subTest(inventory=changed_summaries), self.assertRaises(MODULE.ContractError):
                SettingsReceiptTests.observe(changed)

    def test_receipt_cannot_drop_or_weaken_the_owner_restriction(self):
        for field in ("active_main_branch_ruleset_count", "owner_update_ruleset",
                      "owner_update_ref", "owner_update_fetch_and_merge"):
            for invalid in (None, "foreign", True, 0):
                changed = settings_receipt()
                changed[field] = invalid
                with self.subTest(field=field, value=invalid), self.assertRaises(MODULE.ContractError):
                    MODULE.validate_settings_receipt(changed, "owner/platform")

    def test_only_the_exact_owner_user_can_bypass_through_a_pr(self):
        actor = {"actor_id": 39077795, "actor_type": "User", "bypass_mode": "pull_request"}
        for actors in (None, [], [actor, actor], [{**actor, "actor_id": True}],
                       [{**actor, "actor_id": 1}], [{**actor, "actor_type": "RepositoryRole"}],
                       [{**actor, "bypass_mode": "always"}], [{**actor, "extra": True}]):
            changed = settings_api()
            changed["repos/owner/platform/rulesets/44"]["bypass_actors"] = actors
            with self.subTest(actors=actors), self.assertRaises(MODULE.ContractError):
                SettingsReceiptTests.observe(changed)
        changed = settings_api()
        del changed["repos/owner/platform/rulesets/44"]["bypass_actors"]
        with self.assertRaises(MODULE.ContractError): SettingsReceiptTests.observe(changed)


class SettingsReceiptTests(unittest.TestCase):
    @staticmethod
    def require_documented_settings_contract(text: str) -> None:
        for required in (
            "Platform release readiness receipt",
            '"immutable_releases": true',
            '"private_vulnerability_reporting": true',
            '"actions_enabled": true',
            '"actions_allowed_actions": "all"',
            '"actions_sha_pinning_required": true',
            '"default_workflow_permissions": "read"',
            '"actions_can_approve_pull_request_reviews": false',
            '"merge_methods": ["rebase", "squash"]',
            '"required_status_checks": [',
            '"context": "dependency-review", "integration_id": 15368',
            '"context": "repository-and-infrastructure", "integration_id": 15368',
            '"strict_status_checks": true',
            '"require_pull_request": true',
            '"require_linear_history": true',
            '"require_signed_commits": true',
            '"allow_force_pushes": false',
            '"allow_deletions": false',
            '"restrict_updates": false',
            '"bypass_actors": []',
            '"active_release_tag_ruleset_count": 1',
            '"release_tag_ruleset": "immutable-platform-release-tags"',
            '"release_tag_ruleset_active": true',
            '"release_tag_ruleset_repository_owned": true',
            '"release_tag_ruleset_target": "tag"',
            '"release_tag_pattern": "refs/tags/v*.*.*"',
            '"release_tag_includes": ["refs/tags/v*.*.*"]',
            '"release_tag_excludes": []',
            '"release_tag_creation_restricted": false',
            '"release_tag_updates_allowed": false',
            '"release_tag_deletions_allowed": false',
            '"release_tag_non_fast_forward_allowed": false',
            '"release_tag_bypass_actors": []',
            '"release_tag_rule_types": ["deletion", "non_fast_forward", "update"]',
            '"secret_scanning": true',
            '"secret_scanning_push_protection": true',
            '"secret_scanning_non_provider_patterns": false',
            '"secret_scanning_validity_checks": false',
            "private-vulnerability-reporting",
            "settings-preflight",
            "settings-receipt",
            "must not become Ready until",
            "2026-03-10 repository-ruleset REST schema",
            "describes `update_allows_fetch_and_merge` as branch behavior",
            'exact type-only object `{"type":"update"}`',
            "any `parameters` object,",
            "top-level update escape, or foreign update-rule field denies",
            "remain independently load-bearing",
        ):
            if required not in text:
                raise ValueError(f"GitHub settings contract lost: {required}")

    def test_only_the_exact_immutable_no_bypass_main_contract_is_ready(self):
        exact = settings_receipt()
        MODULE.validate_settings_receipt(exact, "owner/platform")
        mutations: list[dict[str, object]] = []
        for key, value in (
            ("repository", "other/platform"),
            ("branch", "release"),
            ("merge_methods", ["squash"]),
            ("merge_methods", ["merge", "rebase", "squash"]),
            ("merge_methods", ["rebase", "rebase", "squash"]),
            ("actions_enabled", False),
            ("actions_allowed_actions", "foreign"),
            ("actions_sha_pinning_required", False),
            ("default_workflow_permissions", "write"),
            ("actions_can_approve_pull_request_reviews", True),
            ("strict_status_checks", False),
            ("require_pull_request", False),
            ("require_linear_history", False),
            ("require_signed_commits", False),
            ("allow_force_pushes", True),
            ("allow_deletions", True),
            ("restrict_updates", True),
            ("bypass_actors", ["present"]),
            ("active_release_tag_ruleset_count", 2),
            ("release_tag_ruleset", "foreign"),
            ("release_tag_ruleset_active", False),
            ("release_tag_ruleset_repository_owned", False),
            ("release_tag_ruleset_target", "branch"),
            ("release_tag_pattern", "refs/tags/v*"),
            ("release_tag_includes", ["refs/tags/v*"]),
            ("release_tag_excludes", ["refs/tags/v0.1.0"]),
            ("release_tag_creation_restricted", True),
            ("release_tag_updates_allowed", True),
            ("release_tag_deletions_allowed", True),
            ("release_tag_non_fast_forward_allowed", True),
            ("release_tag_bypass_actors", ["present"]),
            ("release_tag_rule_types", ["deletion", "update"]),
            ("immutable_releases", False),
            ("private_vulnerability_reporting", False),
            ("secret_scanning", False),
            ("secret_scanning_push_protection", False),
            ("secret_scanning_non_provider_patterns", "false"),
            ("secret_scanning_validity_checks", None),
        ):
            changed = copy.deepcopy(exact)
            changed[key] = value
            mutations.append(changed)
        checks = copy.deepcopy(exact["required_status_checks"])
        for replacement in (
            checks[:-1],
            [*checks, {"context": "foreign", "integration_id": 15368}],
            [*checks, copy.deepcopy(checks[0])],
            [{**check, "integration_id": 1} for check in checks],
            [{"context": check["context"]} for check in checks],
        ):
            changed = copy.deepcopy(exact)
            changed["required_status_checks"] = replacement
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(MODULE.ContractError):
                MODULE.validate_settings_receipt(changed, "owner/platform")
        for key in exact:
            changed = copy.deepcopy(exact)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(MODULE.ContractError):
                MODULE.validate_settings_receipt(changed, "owner/platform")
        changed = copy.deepcopy(exact)
        changed["ruleset_id"] = "not-for-publication"
        with self.assertRaises(MODULE.ContractError):
            MODULE.validate_settings_receipt(changed, "owner/platform")

    @staticmethod
    def observe(records: dict[str, object]) -> dict[str, object]:
        with mock.patch.object(
            MODULE,
            "_github_api_get",
            side_effect=lambda endpoint, **_options: records[endpoint],
        ) as getter:
            receipt = MODULE.observe_live_settings("owner/platform")
        calls = [call.args[0] for call in getter.call_args_list]
        expected = [
            "repos/owner/platform",
            "repos/owner/platform/immutable-releases",
            "repos/owner/platform/private-vulnerability-reporting",
            "repos/owner/platform/actions/permissions",
            "repos/owner/platform/actions/permissions/workflow",
            "repos/owner/platform/rulesets?includes_parents=true&per_page=100",
            "repos/owner/platform/rulesets/42",
            "repos/owner/platform/rulesets/43",
            "repos/owner/platform/rulesets/44",
        ]
        if calls != expected:
            raise AssertionError(f"unexpected settings endpoints: {calls}")
        if getter.call_args_list[5].kwargs != {"paginate": True}:
            raise AssertionError("ruleset inventory must use exhaustive pagination")
        if any(
            call.kwargs
            for index, call in enumerate(getter.call_args_list)
            if index != 5
        ):
            raise AssertionError("only the ruleset-list endpoint should paginate")
        return receipt

    def test_authoritative_raw_preflight_rejects_every_control_mutant(self):
        exact = settings_api()
        self.assertEqual(self.observe(copy.deepcopy(exact)), settings_receipt())

        mutations: list[dict[str, object]] = []
        for endpoint, path, value in (
            ("repos/owner/platform", ("allow_merge_commit",), True),
            ("repos/owner/platform", ("allow_rebase_merge",), False),
            ("repos/owner/platform", ("default_branch",), "release"),
            ("repos/owner/platform/immutable-releases", ("enabled",), False),
            (
                "repos/owner/platform/private-vulnerability-reporting",
                ("enabled",),
                False,
            ),
            ("repos/owner/platform/actions/permissions", ("enabled",), False),
            (
                "repos/owner/platform/actions/permissions",
                ("sha_pinning_required",),
                False,
            ),
            (
                "repos/owner/platform/actions/permissions/workflow",
                ("default_workflow_permissions",),
                "write",
            ),
            (
                "repos/owner/platform/actions/permissions/workflow",
                ("can_approve_pull_request_reviews",),
                True,
            ),
            (
                "repos/owner/platform",
                ("security_and_analysis", "secret_scanning", "status"),
                "disabled",
            ),
            (
                "repos/owner/platform",
                (
                    "security_and_analysis",
                    "secret_scanning_push_protection",
                    "status",
                ),
                "disabled",
            ),
            ("repos/owner/platform/rulesets/42", ("enforcement",), "disabled"),
            (
                "repos/owner/platform/rulesets/42",
                ("conditions", "ref_name", "include"),
                ["~ALL"],
            ),
            (
                "repos/owner/platform/rulesets/42",
                ("conditions", "ref_name", "include"),
                [],
            ),
            (
                "repos/owner/platform/rulesets/42",
                ("conditions", "ref_name", "include"),
                ["refs/heads/release"],
            ),
            (
                "repos/owner/platform/rulesets/42",
                ("conditions", "ref_name", "exclude"),
                ["refs/heads/main"],
            ),
            (
                "repos/owner/platform/rulesets/42",
                ("bypass_actors",),
                [{"actor_type": "RepositoryRole"}],
            ),
            ("repos/owner/platform/rulesets/43", ("id",), 44),
            ("repos/owner/platform/rulesets/43", ("name",), "foreign"),
            ("repos/owner/platform/rulesets/43", ("target",), "branch"),
            ("repos/owner/platform/rulesets/43", ("source_type",), "Organization"),
            ("repos/owner/platform/rulesets/43", ("source",), "owner/foreign"),
            ("repos/owner/platform/rulesets/43", ("enforcement",), "evaluate"),
            (
                "repos/owner/platform/rulesets/43",
                ("conditions", "ref_name", "include"),
                ["refs/tags/v*"],
            ),
            (
                "repos/owner/platform/rulesets/43",
                ("conditions", "ref_name", "include"),
                ["~ALL"],
            ),
            (
                "repos/owner/platform/rulesets/43",
                ("conditions", "ref_name", "include"),
                ["refs/heads/main"],
            ),
            (
                "repos/owner/platform/rulesets/43",
                ("conditions", "ref_name", "exclude"),
                ["refs/tags/v0.1.0"],
            ),
            (
                "repos/owner/platform/rulesets/43",
                ("bypass_actors",),
                [{"actor_type": "RepositoryRole"}],
            ),
        ):
            changed = copy.deepcopy(exact)
            parent = changed[endpoint]
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)

        rules = exact["repos/owner/platform/rulesets/42"]["rules"]
        for rule_type in (
            "deletion",
            "non_fast_forward",
            "required_linear_history",
            "pull_request",
            "required_status_checks",
            "required_signatures",
        ):
            changed = copy.deepcopy(exact)
            changed["repos/owner/platform/rulesets/42"]["rules"] = [
                rule for rule in rules if rule["type"] != rule_type
            ]
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["repos/owner/platform/rulesets/42"]["rules"].append({"type": "update"})
        mutations.append(changed)

        for value in (["merge", "rebase", "squash"], ["squash"]):
            changed = copy.deepcopy(exact)
            pull = next(
                rule
                for rule in changed["repos/owner/platform/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            pull["parameters"]["allowed_merge_methods"] = value
            mutations.append(changed)
        for field, value in (
            ("strict_required_status_checks_policy", False),
            ("do_not_enforce_on_create", True),
        ):
            changed = copy.deepcopy(exact)
            status = next(
                rule
                for rule in changed["repos/owner/platform/rulesets/42"]["rules"]
                if rule["type"] == "required_status_checks"
            )
            status["parameters"][field] = value
            mutations.append(changed)
        for replacement in (
            [
                {"context": MODULE.REQUIRED_CHECKS[0], "integration_id": 15368}
            ],
            [
                *[
                    {"context": context, "integration_id": 15368}
                    for context in MODULE.REQUIRED_CHECKS
                ],
                {"context": "foreign", "integration_id": 15368},
            ],
            [
                {"context": context, "integration_id": 1}
                for context in MODULE.REQUIRED_CHECKS
            ],
        ):
            changed = copy.deepcopy(exact)
            status = next(
                rule
                for rule in changed["repos/owner/platform/rulesets/42"]["rules"]
                if rule["type"] == "required_status_checks"
            )
            status["parameters"]["required_status_checks"] = replacement
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed[
            "repos/owner/platform/rulesets?includes_parents=true&per_page=100"
        ].append(
            copy.deepcopy(
                changed[
                    "repos/owner/platform/rulesets?includes_parents=true&per_page=100"
                ][0]
            )
        )
        mutations.append(changed)

        tag_inventory = "repos/owner/platform/rulesets?includes_parents=true&per_page=100"
        tag_detail = "repos/owner/platform/rulesets/43"
        tag_rules = exact[tag_detail]["rules"]
        for rule_type in ("update", "deletion", "non_fast_forward"):
            changed = copy.deepcopy(exact)
            changed[tag_detail]["rules"] = [
                rule for rule in tag_rules if rule["type"] != rule_type
            ]
            mutations.append(changed)
        for foreign_rule in (
            {"type": "creation"},
            {"type": "required_signatures"},
            copy.deepcopy(tag_rules[0]),
        ):
            changed = copy.deepcopy(exact)
            changed[tag_detail]["rules"].append(foreign_rule)
            mutations.append(changed)
        for update_parameters in (
            {},
            {"update_allows_fetch_and_merge": False},
            {"update_allows_fetch_and_merge": True},
            {
                "update_allows_fetch_and_merge": False,
                "foreign": False,
            },
        ):
            changed = copy.deepcopy(exact)
            update = next(
                rule
                for rule in changed[tag_detail]["rules"]
                if rule["type"] == "update"
            )
            update["parameters"] = update_parameters
            mutations.append(changed)
        for field, value in (
            ("update_allows_fetch_and_merge", False),
            ("update_allows_fetch_and_merge", True),
            ("foreign", False),
        ):
            changed = copy.deepcopy(exact)
            update = next(
                rule
                for rule in changed[tag_detail]["rules"]
                if rule["type"] == "update"
            )
            update[field] = value
            mutations.append(changed)
        for rule_type in ("deletion", "non_fast_forward"):
            changed = copy.deepcopy(exact)
            rule = next(
                rule
                for rule in changed[tag_detail]["rules"]
                if rule["type"] == rule_type
            )
            rule["parameters"] = {}
            mutations.append(changed)
        for field in (
            "id",
            "name",
            "target",
            "source_type",
            "source",
            "enforcement",
            "conditions",
            "bypass_actors",
            "rules",
        ):
            changed = copy.deepcopy(exact)
            del changed[tag_detail][field]
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed[tag_detail]["conditions"]["foreign"] = {}
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed[tag_detail]["conditions"]["ref_name"]["foreign"] = []
        mutations.append(changed)

        changed = copy.deepcopy(exact)
        changed[tag_inventory] = [
            summary
            for summary in changed[tag_inventory]
            if summary["target"] != "tag"
        ]
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed[tag_inventory].append(copy.deepcopy(changed[tag_inventory][1]))
        mutations.append(changed)
        for field, value in (
            ("name", "foreign"),
            ("target", "branch"),
            ("source_type", "Organization"),
            ("source", "owner/foreign"),
            ("enforcement", "evaluate"),
            ("id", "43"),
        ):
            changed = copy.deepcopy(exact)
            changed[tag_inventory][1][field] = value
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed[tag_inventory].append(
            {
                "id": 44,
                "name": "inherited-tag-policy",
                "target": "tag",
                "source_type": "Organization",
                "source": "owner",
                "enforcement": "active",
            }
        )
        mutations.append(changed)

        for index, changed in enumerate(mutations):
            with self.subTest(raw_mutation=index), self.assertRaises(
                MODULE.ContractError
            ):
                self.observe(changed)

    def test_release_tag_rules_permit_creation_and_deny_every_ref_rewrite(self):
        exact = settings_api()
        record = exact["repos/owner/platform/rulesets/43"]
        receipt = MODULE._release_tag_ruleset_receipt(43, record, "owner/platform")
        self.assertFalse(receipt["release_tag_creation_restricted"])
        self.assertFalse(receipt["release_tag_updates_allowed"])
        self.assertFalse(receipt["release_tag_deletions_allowed"])
        self.assertFalse(receipt["release_tag_non_fast_forward_allowed"])
        self.assertEqual(
            {rule["type"] for rule in record["rules"]},
            {"update", "deletion", "non_fast_forward"},
        )
        self.assertEqual(
            next(rule for rule in record["rules"] if rule["type"] == "update"),
            {"type": "update"},
        )
        self.assertNotIn("creation", {rule["type"] for rule in record["rules"]})

        for hostile_update in (
            {
                "type": "update",
                "parameters": {"update_allows_fetch_and_merge": False},
            },
            {
                "type": "update",
                "parameters": {"update_allows_fetch_and_merge": True},
            },
            {"type": "update", "update_allows_fetch_and_merge": False},
            {"type": "update", "foreign": False},
        ):
            changed = copy.deepcopy(record)
            changed["rules"] = [
                hostile_update if rule["type"] == "update" else rule
                for rule in changed["rules"]
            ]
            with self.subTest(hostile_update=hostile_update), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE._release_tag_ruleset_receipt(
                    43, changed, "owner/platform"
                )

    def test_github_settings_reader_is_get_only_and_fails_closed(self):
        completed = subprocess.CompletedProcess(
            [], 0, stdout='{"enabled": true}', stderr=""
        )
        with mock.patch.object(MODULE.subprocess, "run", return_value=completed) as run:
            self.assertEqual(
                MODULE._github_api_get(
                    "repos/owner/platform/immutable-releases"
                ),
                {"enabled": True},
            )
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
        self.assertIn("X-GitHub-Api-Version: 2026-03-10", command)
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            self.assertNotIn(method, command)

        pages = subprocess.CompletedProcess(
            [], 0, stdout='[[{"id": 1}], [{"id": 2}]]', stderr=""
        )
        with mock.patch.object(MODULE.subprocess, "run", return_value=pages) as run:
            self.assertEqual(
                MODULE._github_api_get(
                    "repos/owner/platform/rulesets", paginate=True
                ),
                [{"id": 1}, {"id": 2}],
            )
        self.assertIn("--paginate", run.call_args.args[0])
        self.assertIn("--slurp", run.call_args.args[0])
        for result in (
            subprocess.CompletedProcess([], 1, stdout="", stderr="denied"),
            subprocess.CompletedProcess([], 0, stdout="not-json", stderr=""),
        ):
            with mock.patch.object(
                MODULE.subprocess, "run", return_value=result
            ), self.assertRaises(MODULE.ContractError):
                MODULE._github_api_get("repos/owner/platform/immutable-releases")

    def test_paginated_tag_inventory_rejects_inherited_second_page(self):
        exact = settings_api()[
            "repos/owner/platform/rulesets?includes_parents=true&per_page=100"
        ]
        inherited = {
            "id": 44,
            "name": "inherited-tag-policy",
            "target": "tag",
            "source_type": "Organization",
            "source": "owner",
            "enforcement": "active",
        }
        pages = subprocess.CompletedProcess(
            [],
            0,
            stdout=json.dumps([[exact[0], exact[1]], [inherited]]),
            stderr="",
        )
        with mock.patch.object(MODULE.subprocess, "run", return_value=pages):
            flattened = MODULE._github_api_get(
                "repos/owner/platform/rulesets?includes_parents=true&per_page=100",
                paginate=True,
            )
        self.assertEqual(len(flattened), 3)
        with self.assertRaises(MODULE.ContractError):
            MODULE._select_release_tag_ruleset_id(flattened, "owner/platform")

    def test_immutable_settings_cli_kills_field_deletion_and_inversion(self):
        exact = {"enabled": True, "enforced_by_owner": False}
        MODULE.validate_immutable_settings(exact)
        mutations = (
            {"enabled": False, "enforced_by_owner": False},
            {"enabled": True, "enforced_by_owner": "false"},
            {"enabled": True},
            {**exact, "foreign": True},
        )
        for index, changed in enumerate(mutations):
            with self.subTest(immutable_mutation=index), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_immutable_settings(changed)
        with tempfile.TemporaryDirectory() as temporary:
            settings = Path(temporary) / "immutable.json"
            settings.write_text(json.dumps(exact), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    MODULE.main(
                        [
                            "immutable-settings",
                            "--settings-json",
                            str(settings),
                        ]
                    ),
                    0,
                )
            self.assertEqual(output.getvalue().strip(), "exact")

    def test_release_app_receipt_is_value_only_exact_and_load_bearing(self):
        exact = app_provisioning_receipt()
        MODULE.validate_app_provisioning_receipt(exact, "owner/platform")
        replacements = (
            ("repository", "other/platform"),
            ("environment_name", "production"),
            ("environment_protected_branches", True),
            ("environment_custom_branch_policies", False),
            ("environment_branch_policies", []),
            ("environment_branch_policies", [{"name": "*", "type": "branch"}]),
            ("environment_branch_policies", [{"name": "main", "type": "tag"}]),
            ("environment_required_reviewers", 1),
            ("environment_required_reviewers", False),
            ("environment_wait_timer_minutes", 1),
            ("environment_wait_timer_minutes", False),
            ("environment_variable_name", "FOREIGN_APP_ID"),
            ("environment_private_key_secret_name", "FOREIGN_PRIVATE_KEY"),
            ("environment_private_key_secret_present", False),
            ("app_identity_binding_exact", False),
            ("installation_account", "other"),
            ("installation_repository_selection", "all"),
            ("installation_repositories", ["owner/platform", "owner/foreign"]),
            ("installation_permissions", {"administration": "write", "metadata": "read"}),
            ("installation_permissions", {"administration": "read", "metadata": "read", "contents": "read"}),
            ("installation_events", ["push"]),
            ("installation_suspended", True),
            ("immutable_releases", False),
        )
        for key, value in replacements:
            changed = copy.deepcopy(exact)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_app_provisioning_receipt(changed, "owner/platform")
        for key in exact:
            changed = copy.deepcopy(exact)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(MODULE.ContractError):
                MODULE.validate_app_provisioning_receipt(changed, "owner/platform")
        changed = copy.deepcopy(exact)
        changed["installation_id"] = "not-for-publication"
        with self.assertRaises(MODULE.ContractError):
            MODULE.validate_app_provisioning_receipt(changed, "owner/platform")

        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "app.json"
            receipt.write_text(json.dumps(exact), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    MODULE.main(
                        [
                            "app-provisioning-receipt",
                            "--receipt",
                            str(receipt),
                            "--repository",
                            "owner/platform",
                        ]
                    ),
                    0,
                )
            self.assertEqual(output.getvalue().strip(), "exact")

    def test_private_vulnerability_reporting_kills_field_mutants(self):
        exact = {"enabled": True}
        MODULE.validate_private_vulnerability_reporting(exact)
        for changed in ({"enabled": False}, {}, {"enabled": True, "foreign": True}):
            with self.subTest(changed=changed), self.assertRaises(MODULE.ContractError):
                MODULE.validate_private_vulnerability_reporting(changed)

    def test_settings_receipt_cli_is_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "settings.json"
            receipt.write_text(json.dumps(settings_receipt()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                exact = MODULE.main(
                    [
                        "settings-receipt",
                        "--receipt",
                        str(receipt),
                        "--repository",
                        "owner/platform",
                    ]
                )
            self.assertEqual(exact, 0)
            self.assertEqual(output.getvalue().strip(), "exact")
            with contextlib.redirect_stderr(io.StringIO()):
                inverted = MODULE.main(
                    [
                        "settings-receipt",
                        "--receipt",
                        str(receipt),
                        "--repository",
                        "other/platform",
                    ]
                )
            self.assertEqual(inverted, 1)

        with mock.patch.object(
            MODULE, "observe_live_settings", return_value=settings_receipt()
        ), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                MODULE.main(
                    ["settings-preflight", "--repository", "owner/platform"]
                ),
                0,
            )
        self.assertEqual(json.loads(output.getvalue()), settings_receipt())

    def test_runbook_readiness_gate_kills_deleted_or_inverted_settings(self):
        runbook = (ROOT / "docs" / "runbooks" / "github-controls.md").read_text(
            encoding="utf-8"
        )
        self.require_documented_settings_contract(runbook)
        tokens = (
            "Platform release readiness receipt",
            '"immutable_releases": true',
            '"private_vulnerability_reporting": true',
            '"actions_enabled": true',
            '"actions_allowed_actions": "all"',
            '"actions_sha_pinning_required": true',
            '"default_workflow_permissions": "read"',
            '"actions_can_approve_pull_request_reviews": false',
            '"merge_methods": ["rebase", "squash"]',
            '"context": "dependency-review", "integration_id": 15368',
            '"context": "repository-and-infrastructure", "integration_id": 15368',
            '"strict_status_checks": true',
            '"require_pull_request": true',
            '"require_linear_history": true',
            '"require_signed_commits": true',
            '"allow_force_pushes": false',
            '"allow_deletions": false',
            '"restrict_updates": false',
            '"bypass_actors": []',
            '"active_release_tag_ruleset_count": 1',
            '"release_tag_ruleset": "immutable-platform-release-tags"',
            '"release_tag_ruleset_active": true',
            '"release_tag_ruleset_repository_owned": true',
            '"release_tag_ruleset_target": "tag"',
            '"release_tag_pattern": "refs/tags/v*.*.*"',
            '"release_tag_includes": ["refs/tags/v*.*.*"]',
            '"release_tag_excludes": []',
            '"release_tag_creation_restricted": false',
            '"release_tag_updates_allowed": false',
            '"release_tag_deletions_allowed": false',
            '"release_tag_non_fast_forward_allowed": false',
            '"release_tag_bypass_actors": []',
            '"release_tag_rule_types": ["deletion", "non_fast_forward", "update"]',
            '"secret_scanning": true',
            '"secret_scanning_push_protection": true',
            '"secret_scanning_non_provider_patterns": false',
            '"secret_scanning_validity_checks": false',
            "settings-preflight",
            "settings-receipt",
            "must not become Ready until",
            "2026-03-10 repository-ruleset REST schema",
            "describes `update_allows_fetch_and_merge` as branch behavior",
            'exact type-only object `{"type":"update"}`',
            "any `parameters` object,",
            "top-level update escape, or foreign update-rule field denies",
            "remain independently load-bearing",
        )
        for token in tokens:
            with self.subTest(deletion=token), self.assertRaises(ValueError):
                self.require_documented_settings_contract(runbook.replace(token, "", 1))
        for old, new in (
            ('"immutable_releases": true', '"immutable_releases": false'),
            (
                '"private_vulnerability_reporting": true',
                '"private_vulnerability_reporting": false',
            ),
            ('"actions_sha_pinning_required": true', '"actions_sha_pinning_required": false'),
            ('"strict_status_checks": true', '"strict_status_checks": false'),
            ('"allow_force_pushes": false', '"allow_force_pushes": true'),
            ('"allow_deletions": false', '"allow_deletions": true'),
            ('"restrict_updates": false', '"restrict_updates": true'),
            (
                '"release_tag_creation_restricted": false',
                '"release_tag_creation_restricted": true',
            ),
            (
                '"release_tag_updates_allowed": false',
                '"release_tag_updates_allowed": true',
            ),
            (
                '"release_tag_deletions_allowed": false',
                '"release_tag_deletions_allowed": true',
            ),
            (
                '"release_tag_non_fast_forward_allowed": false',
                '"release_tag_non_fast_forward_allowed": true',
            ),
            (
                'exact type-only object `{"type":"update"}`',
                'parameterized object `{"type":"update","parameters":{}}`',
            ),
            (
                "foreign update-rule field denies",
                "foreign update-rule field passes",
            ),
            ('"require_signed_commits": true', '"require_signed_commits": false'),
            ('"secret_scanning": true', '"secret_scanning": false'),
            (
                '"secret_scanning_push_protection": true',
                '"secret_scanning_push_protection": false',
            ),
        ):
            with self.subTest(inversion=old), self.assertRaises(ValueError):
                self.require_documented_settings_contract(runbook.replace(old, new, 1))

    def test_security_reporting_is_truthful_and_bound_to_the_live_setting(self):
        policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

        def require_contract(text: str) -> None:
            for token in (
                "Private Vulnerability Reporting is currently disabled",
                "does not presently claim a working\nprivate intake",
                "detail-free public issue",
                "withhold all sensitive details",
                "private-vulnerability-reporting` GET",
                "both report `enabled: true`",
                'Security tab →\n"Report a vulnerability"',
            ):
                if token not in text:
                    raise ValueError(f"security reporting contract lost: {token}")

        require_contract(policy)
        for token in (
            "currently disabled",
            "does not presently claim a working\nprivate intake",
            "detail-free public issue",
            "withhold all sensitive details",
            "private-vulnerability-reporting` GET",
            "both report `enabled: true`",
        ):
            with self.subTest(deletion=token), self.assertRaises(ValueError):
                require_contract(policy.replace(token, "", 1))
        with self.assertRaises(ValueError):
            require_contract(policy.replace("currently disabled", "currently enabled", 1))


class ImmutableMetadataTests(unittest.TestCase):
    TAG = "v0.1.0"
    SOURCE = "a" * 40
    MESSAGE = f"Platform release {TAG} from {SOURCE}"
    DATE = "2026-08-13T15:21:32Z"
    TITLE = f"Platform {TAG}"
    BODY = "exact platform notes\n"

    def tag_expected(self) -> dict[str, str]:
        return {
            "tag": self.TAG,
            "source_sha": self.SOURCE,
            "message": self.MESSAGE,
            "tagger_name": "github-actions[bot]",
            "tagger_email": "41898282+github-actions[bot]@users.noreply.github.com",
            "tagger_date": self.DATE,
        }

    def release(self) -> dict[str, object]:
        return {
            "tag_name": self.TAG,
            "target_commitish": self.SOURCE,
            "name": self.TITLE,
            "body": self.BODY,
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "author": {
                "login": "github-actions[bot]",
                "id": 41898282,
            },
            "assets": [],
        }

    def draft_release(self) -> dict[str, object]:
        release = self.release()
        release.update(
            {
                "id": 378293955,
                "tag_name": "untagged-a4e9ac48228029344306",
                "draft": True,
                "immutable": False,
            }
        )
        return release

    def test_draft_inventory_is_exact_bounded_and_completed_replay_safe(self):
        draft = self.draft_release()
        arguments = {
            "tag": self.TAG,
            "source_sha": self.SOURCE,
            "title": self.TITLE,
            "bodies": (self.BODY,),
        }
        self.assertEqual(
            MODULE.classify_draft_release_state([], **arguments),
            ("absent", None),
        )
        self.assertEqual(
            MODULE.classify_draft_release_state([[draft]], **arguments),
            ("exact", draft["id"]),
        )

        # A completed exact Release is intentionally outside the mutable-draft
        # inventory so a fully successful workflow can replay idempotently.
        published = self.release()
        published["id"] = 378293956
        self.assertEqual(
            MODULE.classify_draft_release_state([[published]], **arguments),
            ("absent", None),
        )
        # A concurrent mutable draft is still detected beside that completed
        # record, allowing the caller to reject the impossible dual state.
        self.assertEqual(
            MODULE.classify_draft_release_state(
                [[published, draft]], **arguments
            ),
            ("exact", draft["id"]),
        )

        for key, value in (
            ("tag_name", "untagged-not-hex"),
            ("target_commitish", "b" * 40),
            ("name", "foreign"),
            ("body", "foreign"),
            ("draft", None),
            ("draft", False),
            ("prerelease", True),
            ("immutable", True),
            ("author", {"login": "repository-owner", "id": 1}),
            ("assets", [{"name": "foreign.bin"}]),
        ):
            changed = copy.deepcopy(draft)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.classify_draft_release_state([[changed]], **arguments)

        with self.assertRaises(MODULE.ContractError):
            MODULE.classify_draft_release_state([[draft, copy.deepcopy(draft)]], **arguments)
        with self.assertRaises(MODULE.ContractError):
            MODULE.classify_draft_release_state(
                [[draft]],
                **arguments,
                expected_release_id=draft["id"],
                expected_server_tag="untagged-bbbbbbbbbbbbbbbbbbbb",
            )
        with self.assertRaises(MODULE.ContractError):
            MODULE.classify_draft_release_state(
                [[draft]],
                **arguments,
                expected_release_id=1,
                expected_server_tag="untagged-a4e9ac48228029344306",
            )

    def test_annotated_tag_type_target_message_and_tagger_are_exact(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        MODULE.validate_tag_record(
            ref,
            tag,
            **{**self.tag_expected(), "tagger_date": "2026-08-13T08:21:32-07:00"},
        )
        mutations: list[tuple[dict[str, object], dict[str, object]]] = []
        for target, path, value in (
            ("ref", ("ref",), "refs/tags/v0.1.1"),
            ("ref", ("object", "type"), "commit"),
            ("ref", ("object", "sha"), "c" * 40),
            ("tag", ("sha",), "c" * 40),
            ("tag", ("tag",), "v0.1.1"),
            ("tag", ("message",), self.MESSAGE + " foreign"),
            ("tag", ("object", "type"), "tree"),
            ("tag", ("object", "sha"), "d" * 40),
            ("tag", ("tagger", "name"), "repository-owner"),
            ("tag", ("tagger", "email"), "foreign@example.invalid"),
            ("tag", ("tagger", "date"), "2026-08-13T15:21:33Z"),
        ):
            changed_ref, changed_tag = copy.deepcopy(ref), copy.deepcopy(tag)
            changed = changed_ref if target == "ref" else changed_tag
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append((changed_ref, changed_tag))
        for index, (changed_ref, changed_tag) in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(MODULE.ContractError):
                MODULE.validate_tag_record(
                    changed_ref, changed_tag, **self.tag_expected()
                )
        for field, foreign in (
            ("tagger_name", "repository-owner"),
            ("tagger_email", "foreign@example.invalid"),
        ):
            changed_ref, changed_tag = copy.deepcopy(ref), copy.deepcopy(tag)
            expected = self.tag_expected()
            expected[field] = foreign
            tagger_field = "name" if field == "tagger_name" else "email"
            changed_tag["tagger"][tagger_field] = foreign
            with self.subTest(paired_foreign=field), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_tag_record(changed_ref, changed_tag, **expected)

    def test_release_metadata_and_zero_asset_inventory_are_exact(self):
        exact = self.release()
        MODULE.validate_release_record(
            exact,
            tag=self.TAG,
            source_sha=self.SOURCE,
            title=self.TITLE,
            body=self.BODY.rstrip(),
        )
        for key, value in (
            ("tag_name", "v0.1.1"),
            ("target_commitish", "main"),
            ("target_commitish", "b" * 40),
            ("target_commitish", None),
            ("name", "foreign"),
            ("body", "foreign"),
            ("body", None),
            ("draft", True),
            ("prerelease", True),
            ("immutable", False),
            ("immutable", None),
            ("author", {"login": "repository-owner", "id": 41898282}),
            ("author", {"login": "github-actions[bot]", "id": 1}),
            ("author", None),
            ("assets", [{"name": "foreign.bin"}]),
            ("assets", None),
        ):
            changed = copy.deepcopy(exact)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(MODULE.ContractError):
                MODULE.validate_release_record(
                    changed,
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    title=self.TITLE,
                    body=self.BODY,
                )

    def test_only_the_two_exact_legacy_tuples_can_bridge_main_target(self):
        for tag, source_sha in MODULE.GRANDFATHERED_MAIN_RELEASE_TARGETS:
            with self.subTest(accepted_tag=tag):
                release = self.release()
                release.update(
                    {
                        "tag_name": tag,
                        "target_commitish": "main",
                        "name": f"Platform {tag}",
                    }
                )
                MODULE.validate_release_record(
                    release,
                    tag=tag,
                    source_sha=source_sha,
                    title=f"Platform {tag}",
                    body=self.BODY,
                    allow_grandfathered_main_target=True,
                )
                with self.assertRaises(MODULE.ContractError):
                    MODULE.validate_release_record(
                        release,
                        tag=tag,
                        source_sha=source_sha,
                        title=f"Platform {tag}",
                        body=self.BODY,
                    )

        tag, source_sha = next(iter(MODULE.GRANDFATHERED_MAIN_RELEASE_TARGETS))
        release = self.release()
        release.update(
            {"tag_name": tag, "target_commitish": "main", "name": f"Platform {tag}"}
        )
        for changed_tag, changed_sha in (("v9.9.9", source_sha), (tag, "f" * 40)):
            changed = dict(release)
            changed["tag_name"] = changed_tag
            changed["name"] = f"Platform {changed_tag}"
            with self.subTest(tag=changed_tag, source_sha=changed_sha), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_release_record(
                    changed,
                    tag=changed_tag,
                    source_sha=changed_sha,
                    title=f"Platform {changed_tag}",
                    body=self.BODY,
                    allow_grandfathered_main_target=True,
                )

    def test_absent_exact_races_and_non_authoritative_states_fail_closed(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        for _racer in range(2):
            self.assertEqual(
                MODULE.classify_tag_state(404, None, None, **self.tag_expected()),
                "absent",
            )
            self.assertEqual(
                MODULE.classify_release_state(
                    404,
                    None,
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    title=self.TITLE,
                    body=self.BODY,
                ),
                "absent",
            )
        for _retry in range(2):
            self.assertEqual(
                MODULE.classify_tag_state(200, ref, tag, **self.tag_expected()),
                "exact",
            )
            self.assertEqual(
                MODULE.classify_release_state(
                    200,
                    self.release(),
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    title=self.TITLE,
                    body=self.BODY,
                ),
                "exact",
            )
        for status in (0, 301, 401, 403, 409, 422, 429, 500, 503):
            with self.subTest(kind="tag", status=status), self.assertRaises(MODULE.ContractError):
                MODULE.classify_tag_state(status, None, None, **self.tag_expected())
            with self.subTest(kind="release", status=status), self.assertRaises(MODULE.ContractError):
                MODULE.classify_release_state(
                    status,
                    None,
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    title=self.TITLE,
                    body=self.BODY,
                )
        for changed_ref, changed_tag in ((None, tag), (ref, None)):
            with self.assertRaises(MODULE.ContractError):
                MODULE.classify_tag_state(
                    200, changed_ref, changed_tag, **self.tag_expected()
                )
        with self.assertRaises(MODULE.ContractError):
            MODULE.classify_tag_state(404, ref, tag, **self.tag_expected())
        with self.assertRaises(MODULE.ContractError):
            MODULE.classify_release_state(
                404,
                self.release(),
                tag=self.TAG,
                source_sha=self.SOURCE,
                title=self.TITLE,
                body=self.BODY,
            )
        with self.assertRaises(MODULE.ContractError):
            MODULE.classify_release_state(
                404,
                None,
                tag=self.TAG,
                source_sha="main",
                title=self.TITLE,
                body=self.BODY,
            )

    def test_cli_exact_state_requirements_kill_deletion_and_inversion(self):
        def invoke(arguments: list[str]) -> int:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return MODULE.main(arguments)

        for state in ("absent", "exact"):
            self.assertEqual(MODULE.require_publication_state(state, state), state)
        for actual, required in (("absent", "exact"), ("exact", "absent"), ("foreign", "exact")):
            with self.subTest(actual=actual, required=required), self.assertRaises(MODULE.ContractError):
                MODULE.require_publication_state(actual, required)

        tag_args = [
            "tag-state",
            "--http-status",
            "404",
            "--tag",
            self.TAG,
            "--source-sha",
            self.SOURCE,
            "--message",
            self.MESSAGE,
            "--tagger-name",
            "github-actions[bot]",
            "--tagger-email",
            "41898282+github-actions[bot]@users.noreply.github.com",
            "--tagger-date",
            self.DATE,
        ]
        self.assertEqual(invoke([*tag_args, "--require", "absent"]), 0)
        self.assertEqual(invoke([*tag_args, "--require", "exact"]), 1)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            notes = root / "notes.md"
            notes.write_text(self.BODY, encoding="utf-8")
            release_args = [
                "release-state",
                "--http-status",
                "404",
                "--tag",
                self.TAG,
                "--source-sha",
                self.SOURCE,
                "--title",
                self.TITLE,
                "--body",
                str(notes),
            ]
            self.assertEqual(invoke([*release_args, "--require", "absent"]), 0)
            self.assertEqual(invoke([*release_args, "--require", "exact"]), 1)
            invalid_source_args = list(release_args)
            invalid_source_args[invalid_source_args.index(self.SOURCE)] = "main"
            self.assertEqual(
                invoke([*invalid_source_args, "--require", "absent"]), 1
            )

            ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
            ref_path, tag_path, release_path = (
                root / "ref.json",
                root / "tag.json",
                root / "release.json",
            )
            ref_path.write_text(json.dumps(ref), encoding="utf-8")
            tag_path.write_text(json.dumps(tag), encoding="utf-8")
            release_path.write_text(json.dumps(self.release()), encoding="utf-8")
            exact_tag_args = [
                "tag-state",
                "--http-status",
                "200",
                *tag_args[3:],
                "--ref-json",
                str(ref_path),
                "--tag-json",
                str(tag_path),
            ]
            self.assertEqual(
                invoke(
                    [
                        "tag-record",
                        "--ref-json",
                        str(ref_path),
                        "--tag-json",
                        str(tag_path),
                        "--tag",
                        self.TAG,
                        "--source-sha",
                        self.SOURCE,
                        "--message",
                        self.MESSAGE,
                        "--tagger-name",
                        "github-actions[bot]",
                        "--tagger-email",
                        "41898282+github-actions[bot]@users.noreply.github.com",
                        "--tagger-date",
                        self.DATE,
                    ]
                ),
                0,
            )
            self.assertEqual(
                invoke([*exact_tag_args, "--require", "exact"]), 0
            )


class MainCIJobsReceiptTests(unittest.TestCase):
    SOURCE = "a" * 40

    @classmethod
    def build(
        cls,
        jobs: dict[str, object],
        codeql_runs: dict[str, object] | None = None,
        codeql_jobs: dict[str, object] | None = None,
    ) -> Mapping[str, object]:
        return MODULE.build_main_ci_jobs_receipt(
            jobs,
            codeql_runs if codeql_runs is not None else codeql_runs_record(),
            codeql_jobs if codeql_jobs is not None else codeql_jobs_record(),
            "owner/platform",
            "4242",
            "1",
            cls.SOURCE,
        )

    def test_exact_completed_main_job_inventory_emits_value_only_receipt(self):
        receipt = self.build(main_ci_jobs_record())
        self.assertEqual(
            receipt,
            {
                "codeql": "success",
                "dependency_review": "skipped-on-push",
                "repository": "owner/platform",
                "repository_and_infrastructure": "success",
                "run_attempt": 1,
                "run_id": 4242,
                "schema": "platform-release-main-ci-jobs-v1",
                "source_sha": self.SOURCE,
                "status": "PASS",
            },
        )
        self.assertNotIn("1001", json.dumps(receipt))

    def test_missing_skipped_cancelled_duplicate_and_foreign_jobs_fail_closed(self):
        exact = main_ci_jobs_record()
        mutations: list[dict[str, object]] = []
        for key, value in (
            ("total_count", 1),
            ("total_count", True),
        ):
            changed = copy.deepcopy(exact)
            changed[key] = value
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["foreign"] = True
        mutations.append(changed)
        for index in (0, 1):
            changed = copy.deepcopy(exact)
            del changed["jobs"][index]
            changed["total_count"] = 1
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][1]["name"] = "repository-and-infrastructure"
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][1]["name"] = "foreign"
        mutations.append(changed)
        for job_index in (0, 1):
            for field, value in (
                ("run_id", 4243),
                ("run_attempt", 2),
                ("head_sha", "b" * 40),
                ("head_branch", "feature"),
                ("workflow_name", "foreign"),
                ("status", "in_progress"),
            ):
                changed = copy.deepcopy(exact)
                changed["jobs"][job_index][field] = value
                mutations.append(changed)
        for conclusion in ("skipped", "cancelled", "failure", None):
            changed = copy.deepcopy(exact)
            changed["jobs"][0]["conclusion"] = conclusion
            mutations.append(changed)
        for conclusion in ("success", "cancelled", "failure", None):
            changed = copy.deepcopy(exact)
            changed["jobs"][1]["conclusion"] = conclusion
            mutations.append(changed)

        for index, changed in enumerate(mutations):
            with self.subTest(job_mutation=index), self.assertRaises(
                MODULE.ContractError
            ):
                self.build(changed)

    def test_if_false_and_every_exact_step_mutant_fail_closed(self):
        exact = main_ci_jobs_record()
        steps = exact["jobs"][0]["steps"]
        for expected_name, expected_conclusion in MODULE.MAIN_CI_EXACT_STEPS:
            for conclusion in (None, "success", "skipped", "cancelled", "failure"):
                if conclusion == expected_conclusion:
                    continue
                changed = copy.deepcopy(exact)
                if conclusion is None:
                    changed["jobs"][0]["steps"] = [
                        step for step in steps if step["name"] != expected_name
                    ]
                else:
                    step = next(
                        value
                        for value in changed["jobs"][0]["steps"]
                        if value["name"] == expected_name
                    )
                    step["conclusion"] = conclusion
                with self.subTest(
                    expected_name=expected_name, conclusion=conclusion
                ):
                    with self.assertRaises(MODULE.ContractError):
                        self.build(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][0]["steps"].append(
            copy.deepcopy(changed["jobs"][0]["steps"][0])
        )
        with self.assertRaises(MODULE.ContractError):
            self.build(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][0]["steps"].append(
            {"name": "Foreign successful step", "conclusion": "success"}
        )
        with self.assertRaises(MODULE.ContractError):
            self.build(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][0]["steps"][1:3] = reversed(
            changed["jobs"][0]["steps"][1:3]
        )
        with self.assertRaises(MODULE.ContractError):
            self.build(changed)

    def test_codeql_run_absent_in_progress_failed_duplicate_and_foreign_fail_closed(self):
        absent = {"total_count": 0, "workflow_runs": []}
        self.assertIsNone(MODULE.classify_codeql_run(absent, self.SOURCE))
        queued = codeql_runs_record()
        queued["workflow_runs"][0]["status"] = "in_progress"
        queued["workflow_runs"][0]["conclusion"] = None
        self.assertIsNone(MODULE.classify_codeql_run(queued, self.SOURCE))
        for pending in (absent, queued):
            with self.subTest(pending=pending), self.assertRaises(MODULE.ContractError):
                self.build(main_ci_jobs_record(), codeql_runs=pending)

        exact = codeql_runs_record()
        mutations: list[dict[str, object]] = []
        for field, value in (
            ("id", 0),
            ("name", "Foreign"),
            ("path", ".github/workflows/foreign.yml"),
            ("event", "pull_request"),
            ("status", "completed"),
            ("conclusion", "failure"),
            ("head_branch", "feature"),
            ("head_sha", "b" * 40),
            ("run_attempt", 0),
        ):
            changed = copy.deepcopy(exact)
            changed["workflow_runs"][0][field] = value
            if field == "status" and value == "completed":
                changed["workflow_runs"][0]["conclusion"] = "cancelled"
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["total_count"] = 2
        changed["workflow_runs"].append(copy.deepcopy(changed["workflow_runs"][0]))
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["foreign"] = True
        mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(codeql_run_mutation=index), self.assertRaises(
                MODULE.ContractError
            ):
                self.build(main_ci_jobs_record(), codeql_runs=changed)

    def test_codeql_job_and_if_false_step_mutants_fail_closed(self):
        absent = {"total_count": 0, "jobs": []}
        self.assertFalse(
            MODULE.codeql_jobs_ready(
                absent, run_id=5001, run_attempt=1, source_sha=self.SOURCE
            )
        )
        pending_records = [absent]
        for job_index in range(len(MODULE.CODEQL_EXACT_STEPS)):
            queued = codeql_jobs_record()
            queued["jobs"][job_index]["status"] = "in_progress"
            queued["jobs"][job_index]["conclusion"] = None
            self.assertFalse(
                MODULE.codeql_jobs_ready(
                    queued, run_id=5001, run_attempt=1, source_sha=self.SOURCE
                )
            )
            pending_records.append(queued)
        for pending in pending_records:
            with self.subTest(codeql_pending=pending), self.assertRaises(
                MODULE.ContractError
            ):
                self.build(main_ci_jobs_record(), codeql_jobs=pending)

        exact = codeql_jobs_record()
        mutations: list[dict[str, object]] = []
        for job_index, (_, expected_steps) in enumerate(
            MODULE.CODEQL_EXACT_STEPS.items()
        ):
            for field, value in (
                ("name", "analyze (javascript)"),
                ("run_id", 5002),
                ("run_attempt", 2),
                ("head_sha", "b" * 40),
                ("head_branch", "feature"),
                ("workflow_name", "Foreign"),
                ("status", "completed"),
                ("conclusion", "failure"),
            ):
                changed = copy.deepcopy(exact)
                changed["jobs"][job_index][field] = value
                if field == "status" and value == "completed":
                    changed["jobs"][job_index]["conclusion"] = "cancelled"
                mutations.append(changed)
            for expected_name, expected_conclusion in expected_steps:
                for conclusion in (
                    None, "success", "skipped", "cancelled", "failure"
                ):
                    if conclusion == expected_conclusion:
                        continue
                    changed = copy.deepcopy(exact)
                    if conclusion is None:
                        changed["jobs"][job_index]["steps"] = [
                            step
                            for step in changed["jobs"][job_index]["steps"]
                            if step["name"] != expected_name
                        ]
                    else:
                        step = next(
                            value
                            for value in changed["jobs"][job_index]["steps"]
                            if value["name"] == expected_name
                        )
                        step["conclusion"] = conclusion
                    mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["total_count"] = len(MODULE.CODEQL_EXACT_STEPS) + 1
        changed["jobs"].append(copy.deepcopy(changed["jobs"][0]))
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["total_count"] -= 1
        changed["jobs"].pop()
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][1] = copy.deepcopy(changed["jobs"][0])
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][0]["steps"].append(
            copy.deepcopy(changed["jobs"][0]["steps"][0])
        )
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][0]["steps"].append(
            {"name": "Foreign successful step", "conclusion": "success"}
        )
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][0]["steps"][1:3] = reversed(
            changed["jobs"][0]["steps"][1:3]
        )
        mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(codeql_job_mutation=index), self.assertRaises(
                MODULE.ContractError
            ):
                self.build(main_ci_jobs_record(), codeql_jobs=changed)

    def test_dependency_review_step_and_cli_are_load_bearing(self):
        changed = main_ci_jobs_record()
        changed["jobs"][1]["steps"] = [
            {"name": "Review dependency changes", "conclusion": "success"}
        ]
        with self.assertRaises(MODULE.ContractError):
            self.build(changed)
        changed = main_ci_jobs_record()
        changed["jobs"][1]["steps"] = [
            {"name": "Foreign skipped step", "conclusion": "skipped"}
        ]
        with self.assertRaises(MODULE.ContractError):
            self.build(changed)
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs.json"
            jobs.write_text(json.dumps(main_ci_jobs_record()), encoding="utf-8")
            codeql_runs = Path(temporary) / "codeql-runs.json"
            codeql_runs.write_text(json.dumps(codeql_runs_record()), encoding="utf-8")
            codeql_jobs = Path(temporary) / "codeql-jobs.json"
            codeql_jobs.write_text(json.dumps(codeql_jobs_record()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    MODULE.main(
                        [
                            "main-ci-jobs-receipt",
                            "--jobs-json",
                            str(jobs),
                            "--codeql-runs-json",
                            str(codeql_runs),
                            "--codeql-jobs-json",
                            str(codeql_jobs),
                            "--repository",
                            "owner/platform",
                            "--source-sha",
                            self.SOURCE,
                            "--run-id",
                            "4242",
                            "--run-attempt",
                            "1",
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                json.loads(output.getvalue())["repository_and_infrastructure"],
                "success",
            )


class ImmutableSettingsShellTests(unittest.TestCase):
    SOURCE = "a" * 40

    @staticmethod
    def script() -> str:
        return (
            ROOT / "scripts" / "ci" / "verify-platform-release-settings.sh"
        ).read_text(encoding="utf-8")

    @staticmethod
    def bash_executable() -> str:
        discovered = shutil.which("bash")
        if discovered:
            return discovered
        if os.name == "nt":
            candidate = (
                Path(os.environ.get("ProgramFiles", "C:/Program Files"))
                / "Git"
                / "bin"
                / "bash.exe"
            )
            if candidate.is_file():
                return str(candidate)
        raise AssertionError("bash is required to execute the settings proof")

    @staticmethod
    def bash_path(path: str | Path) -> str:
        normalized = Path(path).resolve().as_posix()
        if len(normalized) >= 3 and normalized[1:3] == ":/":
            return f"/{normalized[0].lower()}/{normalized[3:]}"
        return normalized

    def execute(
        self,
        script: str,
        *,
        settings: dict[str, object] | None = None,
        http_status: int = 200,
        settings_token: str | None = "settings-token",
        write_token: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str, str, str]:
        with tempfile.TemporaryDirectory(
            dir=ROOT, prefix=".platform-settings-shell-"
        ) as temporary:
            runner = Path(temporary)
            transaction = runner / "settings.sh"
            with transaction.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(script)
            fixture = runner / "fixture.json"
            fixture.write_text(
                json.dumps(
                    settings
                    if settings is not None
                    else {"enabled": True, "enforced_by_owner": False}
                ),
                encoding="utf-8",
            )
            output = runner / "output.txt"
            summary = runner / "summary.md"
            calls = runner / "calls.log"
            relative = runner.relative_to(ROOT).as_posix()
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

curl() {
  local output='' method='' authorization='' url='' token=''
  if [ -n "${GH_TOKEN-}" ] || [ -n "${IMMUTABLE_SETTINGS_TOKEN-}" ]; then
    return 92
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --request) method="$2"; shift 2 ;;
      --header)
        if [[ "$2" == Authorization:\ Bearer\ * ]]; then
          authorization="$2"
        fi
        shift 2
        ;;
      http*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  printf '<%s>\n<%s>\n' "${method}" "${url}" >> "${MOCK_CALLS}"
  token="${authorization#Authorization: Bearer }"
  if [ "${method}" != GET ] || [ "${token}" != "${MOCK_SETTINGS_TOKEN}" ]; then
    printf '{}' > "${output}"
    printf '403'
    return 0
  fi
  cp "${MOCK_FIXTURE}" "${output}"
  printf '%s' "${MOCK_HTTP_STATUS}"
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": self.bash_path(sys.executable),
                    "MOCK_FIXTURE": f"{relative}/fixture.json",
                    "MOCK_CALLS": f"{relative}/calls.log",
                    "MOCK_HTTP_STATUS": str(http_status),
                    "MOCK_SETTINGS_TOKEN": "settings-token",
                    "MOCK_SCRIPT": f"{relative}/settings.sh",
                    "SOURCE_SHA": self.SOURCE,
                    "GITHUB_API_URL": "https://api.github.test",
                    "GITHUB_REPOSITORY": "owner/platform",
                    "GITHUB_RUN_ID": "4242",
                    "GITHUB_RUN_ATTEMPT": "1",
                    "RUNNER_TEMP": relative,
                    "GITHUB_OUTPUT": f"{relative}/output.txt",
                    "GITHUB_STEP_SUMMARY": f"{relative}/summary.md",
                }
            )
            if settings_token is None:
                environment.pop("IMMUTABLE_SETTINGS_TOKEN", None)
            else:
                environment["IMMUTABLE_SETTINGS_TOKEN"] = settings_token
            if write_token is None:
                environment.pop("GH_TOKEN", None)
            else:
                environment["GH_TOKEN"] = write_token
            completed = subprocess.run(
                [
                    self.bash_executable(),
                    "-c",
                    prelude + '\nsource "${MOCK_SCRIPT}"\n',
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            return (
                completed,
                output.read_text(encoding="utf-8") if output.exists() else "",
                summary.read_text(encoding="utf-8") if summary.exists() else "",
                calls.read_text(encoding="utf-8") if calls.exists() else "",
            )

    def test_exact_get_emits_only_a_value_receipt_and_pass_state(self):
        completed, output, summary, calls = self.execute(self.script())
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(
            output,
            f"attestation=PASS:owner/platform:4242:1:{self.SOURCE}\n",
        )
        match = re.search(r"```json\n([^\n]+)\n```", summary)
        self.assertIsNotNone(match)
        self.assertEqual(
            json.loads(match.group(1)),
            {
                "immutable_releases_enabled": True,
                "repository": "owner/platform",
                "run_attempt": 1,
                "run_id": 4242,
                "schema": "platform-release-immutable-settings-v1",
                "source_sha": self.SOURCE,
                "status": "PASS",
            },
        )
        self.assertEqual(calls.count("<GET>"), 1)
        self.assertNotIn("settings-token", completed.stdout + completed.stderr + summary)

    def test_missing_broadened_or_foreign_settings_authority_fails_closed(self):
        cases = (
            {"settings_token": None},
            {"settings_token": "foreign"},
            {"write_token": "write-token"},
            {"http_status": 403},
            {"settings": {"enabled": False, "enforced_by_owner": False}},
            {
                "settings": {
                    "enabled": True,
                    "enforced_by_owner": False,
                    "foreign": True,
                }
            },
        )
        for index, options in enumerate(cases):
            with self.subTest(index=index):
                completed, output, summary, _calls = self.execute(
                    self.script(), **options
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(output, "")
                self.assertEqual(summary, "")

    def test_get_only_token_is_unexported_and_validator_is_load_bearing(self):
        script = self.script()
        mutations = (
            script.replace("unset IMMUTABLE_SETTINGS_TOKEN", ":", 1),
            script.replace("--request GET", "--request POST", 1),
            script.replace(
                'python3 -I -B "${contract}" immutable-settings-receipt',
                'python3 -I -B "${contract}" immutable-settings',
                1,
            ),
        )
        for index, mutant in enumerate(mutations):
            with self.subTest(index=index):
                completed, output, summary, _calls = self.execute(mutant)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(output, "")
                self.assertEqual(summary, "")


class MainCIJobsShellTests(unittest.TestCase):
    SOURCE = "a" * 40

    @staticmethod
    def script() -> str:
        return (
            ROOT / "scripts" / "ci" / "verify-platform-release-main-jobs.sh"
        ).read_text(encoding="utf-8")

    def execute(
        self,
        script: str,
        *,
        jobs: dict[str, object] | None = None,
        codeql_runs: dict[str, object] | None = None,
        codeql_jobs: dict[str, object] | None = None,
        http_status: int = 200,
        actions_token: str | None = "actions-token",
        write_token: str | None = None,
        settings_token: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str, str, str]:
        with tempfile.TemporaryDirectory(
            dir=ROOT, prefix=".platform-main-jobs-shell-"
        ) as temporary:
            runner = Path(temporary)
            transaction = runner / "jobs.sh"
            with transaction.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(script)
            fixture = runner / "main-jobs.json"
            fixture.write_text(
                json.dumps(jobs if jobs is not None else main_ci_jobs_record()),
                encoding="utf-8",
            )
            codeql_runs_fixture = runner / "codeql-runs.json"
            codeql_runs_fixture.write_text(
                json.dumps(
                    codeql_runs if codeql_runs is not None else codeql_runs_record()
                ),
                encoding="utf-8",
            )
            codeql_jobs_fixture = runner / "codeql-jobs.json"
            codeql_jobs_fixture.write_text(
                json.dumps(
                    codeql_jobs if codeql_jobs is not None else codeql_jobs_record()
                ),
                encoding="utf-8",
            )
            output = runner / "output.txt"
            summary = runner / "summary.md"
            calls = runner / "calls.log"
            relative = runner.relative_to(ROOT).as_posix()
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

curl() {
  local output='' method='' authorization='' url='' token=''
  if [ -n "${GH_TOKEN-}" ] || [ -n "${GITHUB_TOKEN-}" ] || \
     [ -n "${IMMUTABLE_SETTINGS_TOKEN-}" ] || [ -n "${ACTIONS_READ_TOKEN-}" ]; then
    return 92
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --request) method="$2"; shift 2 ;;
      --header)
        if [[ "$2" == Authorization:\ Bearer\ * ]]; then
          authorization="$2"
        fi
        shift 2
        ;;
      http*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  printf '<%s>\n<%s>\n' "${method}" "${url}" >> "${MOCK_CALLS}"
  token="${authorization#Authorization: Bearer }"
  if [ "${method}" != GET ] || [ "${token}" != "${MOCK_ACTIONS_TOKEN}" ]; then
    printf '{}' > "${output}"
    printf '403'
    return 0
  fi
  case "${url}" in
    */actions/workflows/codeql.yml/runs\?*)
      cp "${MOCK_CODEQL_RUNS}" "${output}"
      ;;
    */actions/runs/5001/jobs\?*)
      cp "${MOCK_CODEQL_JOBS}" "${output}"
      ;;
    */actions/runs/4242/jobs\?*)
      cp "${MOCK_FIXTURE}" "${output}"
      ;;
    *) return 94 ;;
  esac
  printf '%s' "${MOCK_HTTP_STATUS}"
}
'''
            environment = os.environ.copy()
            for name in (
                "ACTIONS_READ_TOKEN",
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "IMMUTABLE_SETTINGS_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
            ):
                environment.pop(name, None)
            environment.update(
                {
                    "TEST_PYTHON": ImmutableSettingsShellTests.bash_path(sys.executable),
                    "MOCK_FIXTURE": f"{relative}/main-jobs.json",
                    "MOCK_CODEQL_RUNS": f"{relative}/codeql-runs.json",
                    "MOCK_CODEQL_JOBS": f"{relative}/codeql-jobs.json",
                    "MOCK_CALLS": f"{relative}/calls.log",
                    "MOCK_HTTP_STATUS": str(http_status),
                    "MOCK_ACTIONS_TOKEN": "actions-token",
                    "MOCK_SCRIPT": f"{relative}/jobs.sh",
                    "SOURCE_SHA": self.SOURCE,
                    "COMPLETED_RUN_ID": "4242",
                    "COMPLETED_RUN_ATTEMPT": "1",
                    "GITHUB_API_URL": "https://api.github.test",
                    "GITHUB_REPOSITORY": "owner/platform",
                    "RUNNER_TEMP": relative,
                    "GITHUB_OUTPUT": f"{relative}/output.txt",
                    "GITHUB_STEP_SUMMARY": f"{relative}/summary.md",
                }
            )
            if actions_token is not None:
                environment["ACTIONS_READ_TOKEN"] = actions_token
            if write_token is not None:
                environment["GH_TOKEN"] = write_token
            if settings_token is not None:
                environment["IMMUTABLE_SETTINGS_TOKEN"] = settings_token
            completed = subprocess.run(
                [
                    ImmutableSettingsShellTests.bash_executable(),
                    "-c",
                    prelude + '\nsource "${MOCK_SCRIPT}"\n',
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            return (
                completed,
                output.read_text(encoding="utf-8") if output.exists() else "",
                summary.read_text(encoding="utf-8") if summary.exists() else "",
                calls.read_text(encoding="utf-8") if calls.exists() else "",
            )

    def test_exact_actions_get_emits_only_run_bound_value_receipt(self):
        completed, output, summary, calls = self.execute(self.script())
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(
            output,
            f"attestation=PASS:owner/platform:4242:1:{self.SOURCE}\n",
        )
        match = re.search(r"```json\n([^\n]+)\n```", summary)
        self.assertIsNotNone(match)
        self.assertEqual(
            json.loads(match.group(1)),
            {
                "codeql": "success",
                "dependency_review": "skipped-on-push",
                "repository": "owner/platform",
                "repository_and_infrastructure": "success",
                "run_attempt": 1,
                "run_id": 4242,
                "schema": "platform-release-main-ci-jobs-v1",
                "source_sha": self.SOURCE,
                "status": "PASS",
            },
        )
        self.assertEqual(calls.count("<GET>"), 3)
        self.assertIn("filter=latest&per_page=100", calls)
        self.assertIn(
            "/actions/workflows/codeql.yml/runs?branch=main&event=push&head_sha=",
            calls,
        )
        self.assertNotIn("actions-token", completed.stdout + completed.stderr + summary)

    def test_missing_swapped_crossover_and_if_false_fixtures_fail_closed(self):
        skipped = main_ci_jobs_record()
        step = next(
            value
            for value in skipped["jobs"][0]["steps"]
            if value["name"] == "Validate Python policy tooling"
        )
        step["conclusion"] = "skipped"
        cases = (
            {"actions_token": None},
            {"actions_token": "foreign"},
            {"write_token": "write-token"},
            {"settings_token": "settings-token"},
            {"http_status": 403},
            {"jobs": skipped},
        )
        for index, options in enumerate(cases):
            with self.subTest(index=index):
                completed, output, summary, _calls = self.execute(
                    self.script(), **options
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(output, "")
                self.assertEqual(summary, "")

    def test_actions_token_is_unexported_and_validator_is_load_bearing(self):
        script = self.script()
        mutations = (
            script.replace("unset ACTIONS_READ_TOKEN", ":", 1),
            script.replace("--request GET", "--request POST", 1),
            script.replace(
                'python3 -I -B "${contract}" main-ci-jobs-receipt',
                'python3 -I -B "${contract}" immutable-settings-receipt',
                1,
            ),
        )
        for index, mutant in enumerate(mutations):
            with self.subTest(index=index):
                completed, output, summary, _calls = self.execute(mutant)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(output, "")
                self.assertEqual(summary, "")


class PublicationTransactionShellTests(unittest.TestCase):
    TAG = MODULE.next_version(
        MODULE.Version.parse(MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v"))
    ).tag
    SOURCE = "a" * 40
    RECOVERY_TAG = MODULE.RECOVERY_TAG
    BASE_TAG = MODULE.TAG_LEDGER_FLOOR_TAG
    BASE_SOURCE = MODULE.TAG_LEDGER_FLOOR_SHA
    DATE = "2026-08-13T15:21:32Z"

    @staticmethod
    def script() -> str:
        return (ROOT / "scripts" / "ci" / "publish-platform-release.sh").read_text(
            encoding="utf-8"
        )

    @staticmethod
    def bash_executable() -> str:
        discovered = shutil.which("bash")
        if discovered:
            return discovered
        if os.name == "nt":
            candidate = (
                Path(os.environ.get("ProgramFiles", "C:/Program Files"))
                / "Git"
                / "bin"
                / "bash.exe"
            )
            if candidate.is_file():
                return str(candidate)
        raise AssertionError("bash is required to execute the publication transaction")

    @staticmethod
    def bash_path(path: str | Path) -> str:
        normalized = Path(path).resolve().as_posix()
        if len(normalized) >= 3 and normalized[1:3] == ":/":
            return f"/{normalized[0].lower()}/{normalized[3:]}"
        return normalized

    @staticmethod
    def legacy_notes(tag: str, source: str) -> str:
        return (
            f"## Platform {tag}\n\n"
            f"Immutable repository source: `{source}`\n\n"
            "This release names platform source only. It does not deploy, promote, "
            "mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n"
            "See `CHANGELOG.md` at this tag for the human-readable change record.\n"
        )

    def test_draft_upload_redownload_validate_then_publish_is_exact(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)

        mutation_tokens = (
            "identity_asset_name='platform-release-identity.v1.json'",
            "identity_bundle_name='platform-release-identity.v1.json.sigstore.json'",
            '(.assets | length == $count)',
            '(([.assets[].name] | sort) == ($expected | sort))',
            "'{body:$body,draft:true,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}'",
            '--input "${draft_request}" --jq \'.id\')"',
            "release-draft-record",
            '--release-id "${release_id}"',
            "cosign sign-blob --yes",
            'verify_identity_signature "${identity_asset}" "${identity_bundle}"',
            '--data-binary "@${path}"',
            'upload_identity_asset "${release_id}" "${identity_asset_name}"',
            'upload_identity_asset "${release_id}" "${identity_bundle_name}"',
            'test "${status}" = 201',
            'cmp -s "${identity_asset}" "${identity_download}"',
            'cmp -s "${identity_bundle}" "${bundle_download}"',
            "staged-identity-release-record",
            "'{body:$body,draft:false,name:$name,prerelease:false,"
            "tag_name:$tag,target_commitish:$target}'",
            '--input "${publish_patch}"',
        )
        for token in mutation_tokens:
            with self.subTest(deleted=token), self.assertRaises(ValueError):
                validate_single_asset_publication_transaction(
                    script.replace(token, "")
                )

        with self.assertRaises(ValueError):
            validate_single_asset_publication_transaction(
                script
                + '\nupload_identity_asset "${release_id}" '
                '"${identity_asset_name}" "${identity_asset}"\n'
            )

    def test_app_token_crossover_denies_before_any_publication_call(self):
        script = self.script()
        guard = 'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"'
        self.assertIn(guard, script)
        with self.assertRaises(ValueError):
            validate_single_asset_publication_transaction(
                script.replace(guard, ":", 1)
            )
        with self.assertRaises(ValueError):
            validate_single_asset_publication_transaction(
                script + "\nsettings_token=crossed\n"
            )

    def test_actions_token_crossover_denies_before_any_publication_call(self):
        script = self.script()
        guard = 'test -z "${ACTIONS_READ_TOKEN-}"'
        self.assertIn(guard, script)
        with self.assertRaises(ValueError):
            validate_single_asset_publication_transaction(
                script.replace(guard, ":", 1)
            )

    def test_contents_token_crossover_denies_before_any_publication_call(self):
        script = self.script()
        guard = 'test -z "${CONTENTS_READ_TOKEN-}"'
        self.assertIn(guard, script)
        with self.assertRaises(ValueError):
            validate_single_asset_publication_transaction(
                script.replace(guard, ":", 1)
            )

    def test_missing_or_foreign_recovery_tag_denies_before_every_write(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)
        recovery_start = script.index("complete_recovery_release() {")
        current_start = script.index("publish_current_release() {")
        recovery = script[recovery_start:current_start]
        self.assertNotIn("classify_tag absent", recovery)
        self.assertNotIn("run_write_gh api", recovery)
        self.assertLess(
            recovery.index("classify_tag exact"),
            recovery.index('run_write_gh release create "${recovery_tag}"'),
        )
        for token in (
            "recovery_source_sha='51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e'",
            "recovery_tag='v0.1.0'",
            'run_write_gh release create "${recovery_tag}" --verify-tag',
            '--target "${recovery_source_sha}"',
        ):
            with self.subTest(deleted=token), self.assertRaises(ValueError):
                validate_single_asset_publication_transaction(
                    script.replace(token, "", 1)
                )

    def test_v0140_predecessor_exception_is_exact_and_fail_closed(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)
        legacy_start = script.index(
            'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then'
        )
        legacy_end = script.index("\n  fi\n}", legacy_start)
        legacy = script[legacy_start:legacy_end]
        zero_asset = legacy.split("\n  else\n", 1)[1]
        self.assertNotIn("0" * 40, legacy)
        self.assertNotIn('--identity "${identity_download}"', zero_asset)
        self.assertNotIn("download_identity_asset", zero_asset)
        self.assertIn('--repository .', zero_asset)
        self.assertIn('--base-tag "${BASE_TAG}" --target-tag "${TAG}"', zero_asset)
        self.assertIn('--release-json "${release_json}"', zero_asset)
        self.assertIn('--main-runs-json "${legacy_main_runs_json}"', zero_asset)
        self.assertIn('--platform-runs-json "${legacy_platform_runs_json}"', zero_asset)
        self.assertIn("actions/workflows/pull-request.yml/runs?", zero_asset)
        self.assertIn("actions/workflows/platform-release.yml/runs?", zero_asset)
        self.assertIn('--emit > "${legacy_predecessor_json}"', zero_asset)
        self.assertIn(
            "actions/runs/${legacy_main_run_id}/attempts/${legacy_main_run_attempt}",
            legacy,
        )
        self.assertIn(
            "actions/runs/${legacy_platform_run_id}/attempts/${legacy_platform_run_attempt}",
            legacy,
        )
        self.assertIn('--main-run-json "${legacy_main_run_json}"', legacy)
        self.assertIn('--platform-run-json "${legacy_platform_run_json}"', legacy)

        mutation_tokens = (
            'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then',
            'test "${BASE_TAG}" = v0.1.40',
            'test "${TAG}" = v0.1.41',
            '--repository .',
            '--base-tag "${BASE_TAG}" --target-tag "${TAG}"',
            '--release-json "${release_json}"',
            '--main-runs-json "${legacy_main_runs_json}"',
            '--platform-runs-json "${legacy_platform_runs_json}"',
            '--emit > "${legacy_predecessor_json}"',
            "actions/runs/${legacy_main_run_id}/attempts/${legacy_main_run_attempt}",
            "actions/runs/${legacy_platform_run_id}/attempts/${legacy_platform_run_attempt}",
            '--main-run-json "${legacy_main_run_json}"',
            '--platform-run-json "${legacy_platform_run_json}"',
        )
        for token in mutation_tokens:
            with self.subTest(deleted=token), self.assertRaises(ValueError):
                validate_single_asset_publication_transaction(
                    script.replace(token, "")
                )

    def test_current_release_uses_identity_asset_and_never_markdown_body(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)
        start = script.index("classify_current_release() {")
        end = script.index("classify_predecessor_release() {")
        classifier = script[start:end]
        self.assertNotIn("--body", classifier)
        self.assertNotIn('"${contract}" release-state', classifier)
        self.assertIn("download_identity_pair", classifier)
        self.assertIn("selector-image-from-release", classifier)
        self.assertIn("identity-release-state", classifier)
        self.assertIn('--identity "${identity_download}"', classifier)
        self.assertIn('--bundle "${bundle_download}"', classifier)
        self.assertIn('--source-tree-sha "${tree_sha}"', classifier)

        classifier_mutants = (
            classifier.replace("download_identity_pair", ":", 1),
            classifier.replace("selector-image-from-release", "release-state", 1),
            classifier.replace("identity-release-state", "release-state", 1),
            classifier.replace(
                '--http-status "${status}" --require "${required}"',
                '--http-status "${status}" --require "${required}" --body "${notes}"',
                1,
            ),
        )
        for index, mutant_classifier in enumerate(classifier_mutants):
            mutant = script[:start] + mutant_classifier + script[end:]
            with self.subTest(mutant=index), self.assertRaises(ValueError):
                validate_single_asset_publication_transaction(mutant)

    def test_selector_transition_accepts_only_exact_reuse_or_source_build(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)
        call = (
            '    validate_selector_transition \\\n'
            '      "${predecessor_selector_digest}" "${predecessor_build_sha}"'
        )
        self.assertIn(call, script)
        with self.assertRaises(ValueError):
            validate_single_asset_publication_transaction(
                script.replace(call, "    :", 1)
            )
        start = script.index("validate_selector_transition() {")
        end = script.index("\n}\n", start) + 3
        function = script[start:end]
        digest_a = "sha256:" + "a" * 64
        digest_b = "sha256:" + "b" * 64
        source = "a" * 40
        base = "c" * 40
        predecessor_build = "b" * 40

        harness = r'''set -euo pipefail
git() {
  test "$#" = 8
  test "$1" = diff
  test "$2" = --quiet
  test "$3" = "${BASE_SHA}"
  test "$4" = "${SOURCE_SHA}"
  test "$5" = --
  test "$6" = cmd/platform-release-selector
  test "$7" = internal/releaseselector
  test "$8" = go.mod
  test "${MOCK_CHANGED}" != true
}
''' + function + '''
validate_selector_transition "${PREDECESSOR_DIGEST}" "${PREDECESSOR_BUILD_SHA}"
'''

        cases = (
            (False, digest_a, predecessor_build, True),
            (True, digest_b, source, True),
            (False, digest_b, predecessor_build, False),
            (False, digest_a, source, False),
            (True, digest_a, source, False),
            (True, digest_b, predecessor_build, False),
            (True, digest_b, "d" * 40, False),
            (True, "sha256:short", source, False),
            (True, digest_b, "short", False),
        )
        for changed, digest, build_sha, accepted in cases:
            with self.subTest(
                changed=changed, digest=digest, build_sha=build_sha
            ):
                environment = os.environ.copy()
                environment.update(
                    {
                        "BASE_SHA": base,
                        "SOURCE_SHA": source,
                        "SELECTOR_IMAGE_DIGEST": digest,
                        "SELECTOR_BUILD_SHA": build_sha,
                        "PREDECESSOR_DIGEST": digest_a,
                        "PREDECESSOR_BUILD_SHA": predecessor_build,
                        "MOCK_CHANGED": str(changed).lower(),
                    }
                )
                completed = subprocess.run(
                    [self.bash_executable(), "-c", harness],
                    env=environment,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    timeout=10,
                )
                self.assertEqual(completed.returncode == 0, accepted)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, "")

    def test_event_tag_and_notes_are_rederived_from_checked_out_ledger(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)
        self.assertIn(PUBLISHER_TAG_GUARD, script)
        self.assertNotIn("current_tag=", script)
        self.assertNotIn("< VERSION", script)
        with self.assertRaises(ValueError):
            validate_single_asset_publication_transaction(
                script.replace(PUBLISHER_TAG_GUARD, "false", 1)
            )

    def test_only_frozen_recovery_and_reviewed_incident_edges_are_literal(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)
        allowed = {
            self.RECOVERY_TAG,
            self.RECOVERY_TAG.removeprefix("v"),
            "v0.1.40",
            "0.1.40",
            "v0.1.41",
            "0.1.41",
            "v0.1.42",
            "0.1.42",
            "v0.1.43",
            "0.1.43",
        }
        self.assertEqual(set(re.findall(VERSION_LITERAL, script)) - allowed, set())
        self.assertEqual(script.count("v0.1.40"), 3)
        self.assertEqual(script.count("v0.1.41"), 4)
        self.assertEqual(script.count("v0.1.42"), 1)
        self.assertEqual(script.count("v0.1.43"), 2)
        for foreign in ("v0.1.31", "v0.1.34", "v9.9.9"):
            with self.subTest(foreign=foreign), self.assertRaises(ValueError):
                validate_single_asset_publication_transaction(
                    script + f"\nforeign_tag='{foreign}'\n"
                )

    def test_write_credential_is_process_scoped_and_fails_closed(self):
        script = self.script()
        for required in (
            'write_token="${GH_TOKEN}"',
            "unset GH_TOKEN",
            'GH_TOKEN="${write_token}" gh "$@"',
        ):
            self.assertIn(required, script)
            with self.subTest(deleted=required), self.assertRaises(ValueError):
                validate_single_asset_publication_transaction(
                    script.replace(required, "", 1)
                )
        self.assertNotIn("settings_token", script)

    def test_current_tag_and_draft_release_binding_mutants_are_killed(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)
        mutations = (
            script.replace(
                '-f object="${SOURCE_SHA}" -f type=commit',
                '-f object="' + "0" * 40 + '" -f type=commit',
                1,
            ),
            script.replace('-f type=commit', '-f type=tree', 1),
            script.replace(
                "draft:true,name:$name,prerelease:false",
                "draft:false,name:$name,prerelease:false",
                1,
            ),
            script.replace(
                "tag_name:$tag,target_commitish:$target",
                "tag_name:$tag,target_commitish:\"main\"",
                1,
            ),
            script.replace(
                "body:$body,draft:false,name:$name,prerelease:false",
                "body:$body,draft:true,name:$name,prerelease:false",
                1,
            ),
        )
        for index, mutant in enumerate(mutations):
            with self.subTest(mutant=index), self.assertRaises(ValueError):
                validate_single_asset_publication_transaction(mutant)

    def test_recovery_uses_verify_target_and_current_uses_draft_target_commitish(self):
        script = self.script()
        validate_single_asset_publication_transaction(script)
        self.assertEqual(script.count('--target "${recovery_source_sha}"'), 1)
        self.assertNotIn('--target "${SOURCE_SHA}"', script)
        self.assertEqual(
            script.count(
                "'{body:$body,draft:true,name:$name,prerelease:false,"
                "tag_name:$tag,target_commitish:$target}'"
            ),
            2,
        )
        for token in (
            '--target "${recovery_source_sha}"',
            "tag_name:$tag,target_commitish:$target",
        ):
            with self.subTest(deleted=token), self.assertRaises(ValueError):
                validate_single_asset_publication_transaction(
                    script.replace(token, "", 1)
                )


class PredecessorWaitShellTests(unittest.TestCase):
    SOURCE = "a" * 40
    BASE_TAG = "v0.1.40"
    BASE_SOURCE = "3f25c3dc9912a53702926d4abac55435ad02c1b0"
    DATE = "2026-08-27T14:59:58-07:00"

    @staticmethod
    def script() -> str:
        return (
            ROOT / "scripts" / "ci" / "wait-platform-release-predecessor.sh"
        ).read_text(encoding="utf-8")

    def execute(
        self,
        *,
        base_tag: str | None = None,
        base_source: str | None = None,
        target_tag: str = "v0.1.41",
        release_state: str = "complete",
        pending_attempts: int = 0,
        gh_token: str | None = None,
        release_race: bool = False,
        script_override: str | None = None,
        window_status: int = 0,
        tag_snapshot_changes: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        if release_state not in {
            "missing",
            "complete",
            "foreign",
            "foreign-target",
            "partial",
        }:
            raise AssertionError("predecessor Release fixture state is not closed")
        base_tag = base_tag or self.BASE_TAG
        base_source = base_source or self.BASE_SOURCE
        with tempfile.TemporaryDirectory(
            dir=ROOT, prefix=".platform-predecessor-shell-"
        ) as temporary:
            runner = Path(temporary)
            ref, tag = exact_tag_records(
                base_tag,
                base_source,
                f"Platform release {base_tag} from {base_source}",
                self.DATE,
            )
            ref["object"]["sha"] = "e" * 40
            tag["sha"] = "e" * 40
            release = {
                "tag_name": base_tag,
                "target_commitish": base_source,
                "name": f"Platform {base_tag}",
                "body": PublicationTransactionShellTests.legacy_notes(
                    base_tag, base_source
                ),
                "draft": False,
                "prerelease": False,
                "immutable": release_state != "partial",
                "author": {"login": "github-actions[bot]", "id": 41898282},
                "assets": [],
            }
            if release_state == "foreign":
                release["author"] = {"login": "owner", "id": 1}
            if release_state == "foreign-target":
                release["target_commitish"] = "main"
            records = runner / "records"
            records.mkdir()
            (records / "ref.json").write_text(json.dumps(ref), encoding="utf-8")
            (records / "tag.json").write_text(json.dumps(tag), encoding="utf-8")
            if release_state != "missing":
                (records / "release.json").write_text(
                    json.dumps(release), encoding="utf-8"
                )
            elif release_race:
                (records / "race-release.json").write_text(
                    json.dumps(release), encoding="utf-8"
                )

            # Two attempts keep the hostile absent-state fixture fast while the
            # structural gate below freezes the production bound at 30.
            script = script_override or self.script()
            self.assertIn("for _attempt in {1..30}", script)
            transaction = runner / "wait.sh"
            transaction.write_text(
                script.replace("for _attempt in {1..30}", "for _attempt in {1..2}"),
                encoding="utf-8",
                newline="\n",
            )
            prelude = r'''
python3() {
  if [ "${4-}" = release-window ]; then
    if [ "${MOCK_WINDOW_STATUS}" -ne 0 ]; then
      return "${MOCK_WINDOW_STATUS}"
    fi
    count=0
    if [ -f "${MOCK_WINDOW_COUNT}" ]; then count="$(<"${MOCK_WINDOW_COUNT}")"; fi
    count=$((count + 1))
    printf '%s' "${count}" > "${MOCK_WINDOW_COUNT}"
    printf 'WINDOW\n' >> "${MOCK_CALLS}"
    if [ "${count}" -le "${MOCK_PENDING_ATTEMPTS}" ]; then return 3; fi
    printf '{"base_sha":"%s","base_tag":"%s","source_sha":"%s","tag":"%s"}\n' \
      "${BASE_SHA}" "${BASE_TAG}" "${SOURCE_SHA}" "${TARGET_TAG}"
    return 0
  fi
  if [ "${4-}" = release-notes ]; then
    local head='' tag=''
    shift 4
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --repository) test "$2" = .; shift 2 ;;
        --head) head="$2"; shift 2 ;;
        --tag) tag="$2"; shift 2 ;;
        *) return 2 ;;
      esac
    done
    test "${head}" = "${BASE_SHA}"
    test "${tag}" = "${BASE_TAG}"
    printf '%s' "${MOCK_BASE_NOTES}"
    return 0
  fi
  "${TEST_PYTHON}" "$@"
}

git() {
  if [ "$1" = fetch ]; then
    test "$2" = --quiet
    test "$3" = --tags
    test "$4" = origin
    count=0
    if [ -f "${MOCK_FETCH_COUNT}" ]; then count="$(<"${MOCK_FETCH_COUNT}")"; fi
    count=$((count + 1))
    printf '%s' "${count}" > "${MOCK_FETCH_COUNT}"
    return 0
  fi
  if [ "$1" = for-each-ref ]; then
    test "$2" = --count=1025
    test "$3" = '--format=%(refname)%09%(objectname)%09%(*objectname)'
    test "$4" = 'refs/tags/v*'
    count="$(<"${MOCK_FETCH_COUNT}")"
    printf 'refs/tags/%s\t%s\t%s\n' "${BASE_TAG}" "$(printf 'e%.0s' {1..40})" "${BASE_SHA}"
    if [ "${MOCK_TAG_SNAPSHOT_CHANGES}" = true ] && [ "${count}" -gt 1 ]; then
      printf 'refs/tags/v0.1.10\t%s\t%s\n' "$(printf 'd%.0s' {1..40})" "${SOURCE_SHA}"
    fi
    return 0
  fi
  if [ "$1" = show ]; then printf '%s\n' "${MOCK_DATE}"; return 0; fi
  return 2
}

jq() {
  test "$1" = -er
  if [ "$2" = '.object.sha' ]; then
    "${TEST_PYTHON}" -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["object"]["sha"])' "$3"
    return
  fi
  "${TEST_PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1][1:]])' "$2"
}

curl() {
  local output='' authorization='' method='' url='' token=''
  if [ -n "${CONTENTS_READ_TOKEN-}" ] || [ -n "${GH_TOKEN-}" ] || \
     [ -n "${GITHUB_TOKEN-}" ] || [ -n "${IMMUTABLE_SETTINGS_TOKEN-}" ] || \
     [ -n "${ACTIONS_READ_TOKEN-}" ]; then return 93; fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --request) method="$2"; shift 2 ;;
      --header)
        if [[ "$2" == Authorization:\ Bearer\ * ]]; then authorization="$2"; fi
        shift 2
        ;;
      http*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  test "${method}" = GET || return 94
  token="${authorization#Authorization: Bearer }"
  test "${token}" = "${MOCK_READ_TOKEN}"
  printf 'GET %s\n' "${url}" >> "${MOCK_CALLS}"
  case "${url}" in
    */git/ref/tags/*) cp "${MOCK_RECORDS}/ref.json" "${output}"; printf '200' ;;
    */git/tags/*) cp "${MOCK_RECORDS}/tag.json" "${output}"; printf '200' ;;
    */releases/tags/*)
      if [ -f "${MOCK_RECORDS}/release.json" ]; then
        cp "${MOCK_RECORDS}/release.json" "${output}"; printf '200'
      else
        printf '{}' > "${output}"; printf '404'
        if [ -f "${MOCK_RECORDS}/race-release.json" ]; then
          mv "${MOCK_RECORDS}/race-release.json" "${MOCK_RECORDS}/release.json"
        fi
      fi
      ;;
    *) return 2 ;;
  esac
}

sleep() { printf 'SLEEP %s\n' "$1" >> "${MOCK_CALLS}"; }
'''
            harness = runner / "harness.sh"
            harness.write_text(
                prelude + '\nsource "${MOCK_SCRIPT}"\n',
                encoding="utf-8",
                newline="\n",
            )
            relative = runner.relative_to(ROOT).as_posix()
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": PublicationTransactionShellTests.bash_path(
                        sys.executable
                    ),
                    "MOCK_DATE": self.DATE,
                    "MOCK_PENDING_ATTEMPTS": str(pending_attempts),
                    "MOCK_WINDOW_COUNT": f"{relative}/window-count",
                    "MOCK_FETCH_COUNT": f"{relative}/fetch-count",
                    "MOCK_WINDOW_STATUS": str(window_status),
                    "MOCK_TAG_SNAPSHOT_CHANGES": str(tag_snapshot_changes).lower(),
                    "MOCK_BASE_NOTES": PublicationTransactionShellTests.legacy_notes(
                        base_tag, base_source
                    ),
                    "MOCK_READ_TOKEN": "read-token",
                    "MOCK_RECORDS": f"{relative}/records",
                    "MOCK_CALLS": f"{relative}/calls.log",
                    "MOCK_SCRIPT": f"{relative}/wait.sh",
                    "CONTENTS_READ_TOKEN": "read-token",
                    "SOURCE_SHA": self.SOURCE,
                    "BASE_SHA": base_source,
                    "BASE_TAG": base_tag,
                    "TARGET_TAG": target_tag,
                    "GITHUB_API_URL": "https://api.github.test",
                    "GITHUB_REPOSITORY": "owner/platform",
                    "GITHUB_OUTPUT": f"{relative}/output",
                    "RUNNER_TEMP": relative,
                }
            )
            for name in (
                "GITHUB_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
                "IMMUTABLE_SETTINGS_TOKEN",
                "ACTIONS_READ_TOKEN",
            ):
                environment.pop(name, None)
            if gh_token is None:
                environment.pop("GH_TOKEN", None)
            else:
                environment["GH_TOKEN"] = gh_token
            completed = subprocess.run(
                [
                    PublicationTransactionShellTests.bash_executable(),
                    PublicationTransactionShellTests.bash_path(harness),
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            output = (
                (runner / "output").read_text(encoding="utf-8")
                if (runner / "output").exists()
                else ""
            )
            calls = (
                (runner / "calls.log").read_text(encoding="utf-8")
                if (runner / "calls.log").exists()
                else ""
            )
            return completed, output, calls

    def test_exact_predecessor_emits_only_the_bound_attestation(self):
        completed, output, calls = self.execute(
            pending_attempts=1, tag_snapshot_changes=True
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(output, f"attestation=PASS:owner/platform:{self.SOURCE}\n")
        self.assertNotIn("token", output.lower())
        self.assertEqual(calls.count("/git/ref/tags/"), 1)
        self.assertEqual(calls.count("/releases/tags/"), 1)

        raced, raced_output, raced_calls = self.execute(
            release_state="missing", release_race=True
        )
        self.assertEqual(raced.returncode, 0, raced.stdout + raced.stderr)
        self.assertEqual(
            raced_output, f"attestation=PASS:owner/platform:{self.SOURCE}\n"
        )
        self.assertEqual(raced_calls.count("/releases/tags/"), 3)

    def test_only_burned_v0142_to_v0143_accepts_a_missing_release(self):
        completed, output, calls = self.execute(
            base_tag=MODULE.BURNED_PARTIAL_TAG,
            base_source=MODULE.BURNED_PARTIAL_SOURCE_SHA,
            target_tag="v0.1.43",
            release_state="missing",
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(output, f"attestation=PASS:owner/platform:{self.SOURCE}\n")
        self.assertEqual(calls.count("/releases/tags/"), 1)
        self.assertNotIn("SLEEP", calls)

        for near_target in ("v0.1.42", "v0.1.44"):
            with self.subTest(target=near_target):
                denied, denied_output, denied_calls = self.execute(
                    base_tag=MODULE.BURNED_PARTIAL_TAG,
                    base_source=MODULE.BURNED_PARTIAL_SOURCE_SHA,
                    target_tag=near_target,
                    release_state="missing",
                )
                self.assertNotEqual(denied.returncode, 0)
                self.assertEqual(denied_output, "")
                self.assertIn("bounded wait", denied.stderr)
                self.assertIn("SLEEP 10\n", denied_calls)

    def test_future_predecessors_consume_the_two_asset_identity_receipt(self):
        script = self.script()
        for required in (
            "platform-release-identity.v1.json",
            "platform-release-identity.v1.json.sigstore.json",
            "Accept: application/octet-stream",
            'if [ "${tag}" = v0.1.40 ]; then',
            'identity-release-state \\\n',
            '--selector-build-sha "${selector_build_sha}"',
            '--tag-object-sha "${tag_object_sha}"',
            '--source-tree-sha "${source_tree_sha}"',
        ):
            self.assertIn(required, script)

    def test_unchanged_tag_snapshot_caches_the_validated_release_window(self):
        completed, output, calls = self.execute(release_state="missing")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output, "")
        self.assertEqual(calls.count("WINDOW\n"), 1)
        self.assertEqual(calls.count("SLEEP 10\n"), 2)
        self.assertEqual(calls.count("/releases/tags/"), 4)

        changed, changed_output, changed_calls = self.execute(
            pending_attempts=1, tag_snapshot_changes=True
        )
        self.assertEqual(changed.returncode, 0, changed.stdout + changed.stderr)
        self.assertNotEqual(changed_output, "")
        self.assertEqual(changed_calls.count("WINDOW\n"), 2)

    def test_absent_foreign_and_mutable_predecessors_fail_closed(self):
        for release_state in ("missing", "foreign", "foreign-target", "partial"):
            with self.subTest(release_state=release_state):
                completed, output, calls = self.execute(release_state=release_state)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(output, "")
                self.assertNotEqual(calls, "")
                if release_state == "missing":
                    self.assertIn("bounded wait", completed.stderr)
                else:
                    self.assertNotIn("bounded wait", completed.stderr)

    def test_publication_token_crossover_fails_before_any_get(self):
        completed, output, calls = self.execute(gh_token="write-token")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output, "")
        self.assertEqual(calls, "")

    def test_non_get_mutation_fails_when_literal_get_survives_only_in_comment(self):
        script = self.script()
        mutant = script.replace(
            '  local url="$1" output="$2"\n',
            '  local method=POST url="$1" output="$2" # --request GET\n',
            1,
        ).replace('    --request GET \\\n', '    --request "${method}" \\\n', 1)
        self.assertNotEqual(mutant, script)
        completed, output, calls = self.execute(script_override=mutant)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output, "")
        self.assertEqual(calls, "WINDOW\n")

    def test_unsafe_release_window_denies_without_wait_get_or_attestation(self):
        completed, output, calls = self.execute(window_status=1)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output, "")
        self.assertEqual(calls, "")
        self.assertNotIn("bounded wait", completed.stderr)


class GitTransitionTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def commit(self, root: Path, marker: str) -> str:
        marker_path = root / "markers" / (re.sub(r"[^a-z0-9]+", "-", marker.lower()).strip("-") + ".txt")
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(marker + "\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(
            root,
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-m",
            marker,
        )
        return self.git(root, "rev-parse", "HEAD")

    def commit_staged(self, root: Path, marker: str) -> str:
        self.git(
            root,
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-m",
            marker,
        )
        return self.git(root, "rev-parse", "HEAD")

    def stage_fragment_mode(
        self, root: Path, path: str, payload: bytes, mode: str
    ) -> None:
        created = subprocess.run(
            ["git", "-C", str(root), "hash-object", "-w", "--stdin"],
            check=True,
            input=payload,
            stdout=subprocess.PIPE,
        )
        object_id = created.stdout.decode("ascii").strip()
        self.git(
            root,
            "update-index",
            "--add",
            "--cacheinfo",
            f"{mode},{object_id},{path}",
        )

    def add_fragment(
        self,
        root: Path,
        issue: int,
        slug: str,
        marker: str,
        *,
        category: str = "Security",
    ) -> str:
        path = root / "changelog.d" / f"{issue}-{slug}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"### {category}\n\n- {marker}\n",
            encoding="utf-8",
            newline="\n",
        )
        return self.commit(root, marker)

    def tag(
        self,
        root: Path,
        name: str,
        target: str,
        *,
        message: str | None = None,
        tagger_name: str = MODULE.RELEASE_TAGGER_NAME,
        tagger_email: str = MODULE.RELEASE_TAGGER_EMAIL,
        tagger_date: str | None = None,
    ) -> None:
        resolved_date = tagger_date or self.git(
            root, "show", "-s", "--format=%cI", target
        )
        parsed_date = dt.datetime.fromisoformat(resolved_date)
        offset = parsed_date.strftime("%z")
        payload = (
            f"object {target}\n"
            "type commit\n"
            f"tag {name}\n"
            f"tagger {tagger_name} <{tagger_email}> "
            f"{int(parsed_date.timestamp())} {offset}\n\n"
            f"{message or f'Platform release {name} from {target}'}"
        ).encode("utf-8")
        created = subprocess.run(
            ["git", "-C", str(root), "hash-object", "-t", "tag", "-w", "--stdin"],
            check=True,
            input=payload,
            stdout=subprocess.PIPE,
        )
        tag_object = created.stdout.decode("ascii").strip()
        self.git(root, "update-ref", f"refs/tags/{name}", tag_object)

    def initialize(self, root: Path) -> str:
        self.git(root, "init", "-q")
        # Writing Git commands may otherwise launch detached automatic
        # maintenance. A TemporaryDirectory can then enumerate .git while that
        # background process creates a lock or object, making Linux rmtree fail
        # with ENOTEMPTY. Disable both the modern maintenance path and legacy
        # auto-gc in this disposable repository; keeping both detach fallbacks
        # false also makes any unexpected maintenance synchronous with the Git
        # subprocess whose completion the fixture already waits for.
        for key, value in (
            ("maintenance.auto", "false"),
            ("maintenance.autoDetach", "false"),
            ("gc.auto", "0"),
            ("gc.autoDetach", "false"),
            ("core.autocrlf", "false"),
        ):
            self.git(root, "config", "--local", key, value)
        self.git(root, "branch", "-m", "main")
        floor_version = MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v")
        (root / "VERSION").write_text(
            floor_version + "\n", encoding="utf-8", newline="\n"
        )
        (root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [Unreleased]\n\n"
            f"## [{floor_version}] - 2026-08-20\n\n- Legacy floor.\n",
            encoding="utf-8",
            newline="\n",
        )
        floor = self.commit(root, "legacy migration floor")
        self.tag(root, MODULE.TAG_LEDGER_FLOOR_TAG, floor)
        return floor

    def assert_fixture_git_is_quiescent(self, root: Path) -> None:
        expected = {
            "maintenance.auto": "false",
            "maintenance.autoDetach": "false",
            "gc.auto": "0",
            "gc.autoDetach": "false",
            "core.autocrlf": "false",
        }
        actual = {
            key: self.git(root, "config", "--local", "--get", key)
            for key in expected
        }
        self.assertEqual(actual, expected)

    def test_repeated_concurrent_git_fixtures_finish_before_safe_cleanup(self):
        def lifecycle(round_index: int, worker_index: int, barrier: threading.Barrier):
            with tempfile.TemporaryDirectory(prefix="platform-release-git-") as temporary:
                root = Path(temporary)
                initial = self.initialize(root)
                self.assert_fixture_git_is_quiescent(root)
                barrier.wait(timeout=30)
                head = self.add_fragment(
                    root,
                    100 + worker_index,
                    f"round-{round_index}",
                    f"concurrent release {round_index}-{worker_index}",
                )
                intent = MODULE.validate_transition(
                    root, initial, head, first_parent=True
                )
                self.assertEqual(intent.source_sha, head)
                self.assertEqual(intent.fragment_path, f"changelog.d/{100 + worker_index}-round-{round_index}.md")
                self.assertRegex(intent.fragment_sha256, r"^[0-9a-f]{64}$")
                return temporary

        cleaned: list[str] = []
        for round_index in range(2):
            barrier = threading.Barrier(4)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(lifecycle, round_index, worker_index, barrier)
                    for worker_index in range(4)
                ]
                cleaned.extend(future.result(timeout=60) for future in futures)
        for temporary in cleaned:
            self.assertFalse(Path(temporary).exists())

    def test_one_fragment_is_the_only_valid_pr_and_main_release_surface(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self.initialize(root)
            head = self.add_fragment(root, 164, "release-fragments", "one release input")
            for first_parent in (False, True):
                intent = MODULE.validate_transition(
                    root, base, head, first_parent=first_parent
                )
                self.assertEqual(intent.source_sha, head)
                self.assertEqual(intent.fragment_path, "changelog.d/164-release-fragments.md")

            no_fragment = self.commit(root, "content without release input")
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, head, no_fragment, first_parent=True)

            self.git(root, "checkout", "-q", "-b", "two-fragments", base)
            first = root / "changelog.d" / "165-first.md"
            second = root / "changelog.d" / "166-second.md"
            first.parent.mkdir(parents=True, exist_ok=True)
            first.write_text("### Added\n\n- First.\n", encoding="utf-8")
            second.write_text("### Fixed\n\n- Second.\n", encoding="utf-8")
            two = self.commit(root, "two release inputs")
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, base, two, first_parent=True)

    def test_fragment_grammar_and_generated_files_fail_closed(self):
        invalid_payloads = (
            (b"", "empty", "non-empty"),
            (
                b"### Security\n\n- " + b"a" * 16_385 + b"\n",
                "oversize",
                "at most 16 KiB",
            ),
            (
                b"\xef\xbb\xbf### Security\n\n- item\n",
                "bom",
                "BOM-free UTF-8",
            ),
            (
                b"### Security\n\n- item\x00\n",
                "embedded-nul",
                "BOM-free UTF-8",
            ),
            (b"### Security\n\n- item \xff\n", "invalid-utf8", "not UTF-8"),
            (
                b"### Security\n\n- missing final newline",
                "missing-final-newline",
                "exactly one newline",
            ),
            (
                b"### Security\n\n- double final newline\n\n",
                "double-final-newline",
                "exactly one newline",
            ),
            (b"### Other\n\n- item\n", "category", "fragment category"),
            (
                b"### Security\n\nplain text\n",
                "not-a-bullet",
                "every fragment body line",
            ),
            (b"### Security\r\n\r\n- item\r\n", "crlf", "LF line endings"),
            (
                b"### Security\n\n- ${{ github.token }}\n",
                "expression",
                "workflow expression opener",
            ),
            (
                b"### Security\n\n- trailing \n",
                "trailing",
                "trailing whitespace",
            ),
        )
        for payload, label, reason in invalid_payloads:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                base = self.initialize(root)
                path = root / "changelog.d" / "164-invalid.md"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                head = self.commit(root, label)
                with self.assertRaises(MODULE.ContractError) as denied:
                    MODULE.validate_transition(root, base, head, first_parent=True)
                self.assertIn(reason, str(denied.exception))

        for filename in (
            "release-fragments.md",
            "0164-release-fragments.md",
            "164-Release-Fragments.md",
            "164_release_fragments.md",
            "164-release-fragments.txt",
            "164-release/fragments.md",
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                base = self.initialize(root)
                path = root / "changelog.d" / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("### Security\n\n- Invalid filename.\n", encoding="utf-8")
                head = self.commit(root, "invalid fragment filename")
                with self.assertRaises(MODULE.ContractError):
                    MODULE.validate_transition(root, base, head, first_parent=True)

        for generated in ("VERSION", "CHANGELOG.md"):
            with self.subTest(generated=generated), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                base = self.initialize(root)
                self.add_fragment(root, 164, "valid", "valid fragment")
                with (root / generated).open("a", encoding="utf-8") as handle:
                    handle.write("foreign generated edit\n")
                head = self.commit(root, f"edit {generated}")
                with self.assertRaises(MODULE.ContractError) as denied:
                    MODULE.validate_transition(root, base, head, first_parent=True)
                self.assertEqual(
                    str(denied.exception),
                    f"retired generated release files changed: {generated}",
                )

    def test_fragment_size_bound_is_literal_and_exact(self):
        self.assertEqual(MODULE.MAX_FRAGMENT_BYTES, 16_384)
        prefix = b"### Security\n\n- "
        valid = prefix + b"a" * (16_384 - len(prefix) - 1) + b"\n"
        oversize = prefix + b"a" * (16_385 - len(prefix) - 1) + b"\n"
        self.assertEqual(len(valid), 16_384)
        self.assertEqual(len(oversize), 16_385)
        self.assertTrue(
            MODULE.validate_fragment_bytes("changelog.d/164-bound.md", valid).endswith(
                "\n"
            )
        )
        with self.assertRaises(MODULE.ContractError) as denied:
            MODULE.validate_fragment_bytes("changelog.d/164-bound.md", oversize)
        self.assertEqual(
            str(denied.exception),
            "fragment must be non-empty and at most 16 KiB",
        )

    def test_release_notes_do_not_rehash_the_same_immutable_blob(self):
        source = inspect.getsource(MODULE.render_release_notes)
        self.assertNotIn("hashlib.sha256(payload)", source)
        self.assertNotIn("release fragment changed after window derivation", source)

    def test_existing_fragments_cannot_be_edited_deleted_or_renamed(self):
        for operation in ("edit", "delete", "rename"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.initialize(root)
                base = self.add_fragment(root, 100, "existing", "Existing release.")
                existing = root / "changelog.d" / "100-existing.md"
                if operation == "edit":
                    existing.write_text(
                        "### Security\n\n- Edited historical release.\n",
                        encoding="utf-8",
                    )
                elif operation == "delete":
                    existing.unlink()
                else:
                    existing.rename(root / "changelog.d" / "100-renamed.md")
                new_fragment = root / "changelog.d" / "164-current.md"
                new_fragment.write_text(
                    "### Changed\n\n- Current release.\n", encoding="utf-8"
                )
                head = self.commit(root, operation + " an existing fragment")
                with self.assertRaises(MODULE.ContractError):
                    MODULE.validate_transition(root, base, head, first_parent=True)

    def test_one_still_unpublished_fragment_can_be_edited_in_place(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            floor = self.initialize(root)
            base = self.add_fragment(
                root, 189, "platform-gitops-activation", "Initial recovery text."
            )
            fragment = root / "changelog.d" / "189-platform-gitops-activation.md"
            fragment.write_text(
                "### Security\n\n- Corrected recovery text.\n",
                encoding="utf-8",
                newline="\n",
            )
            head = self.commit(root, "correct unpublished fragment")

            with mock.patch.object(MODULE, "TAG_LEDGER_FLOOR_SHA", floor):
                intent = MODULE.validate_transition(
                    root, base, head, first_parent=True
                )
            self.assertEqual(intent.source_sha, head)
            self.assertEqual(
                intent.fragment_path,
                "changelog.d/189-platform-gitops-activation.md",
            )
            self.assertEqual(
                intent.fragment_sha256,
                hashlib.sha256(fragment.read_bytes()).hexdigest(),
            )

    def test_unpublished_fragment_recovery_rejects_unrelated_only_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            floor = self.initialize(root)
            base = self.add_fragment(root, 189, "pending", "Pending release.")
            (root / "unrelated.txt").write_text(
                "This must not manufacture a release recovery.\n",
                encoding="utf-8",
                newline="\n",
            )
            head = self.commit(root, "change unrelated content only")

            with mock.patch.object(
                MODULE, "TAG_LEDGER_FLOOR_SHA", floor
            ), self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, base, head, first_parent=True)

    def test_unpublished_fragment_edit_rejects_release_surface_substitutions(self):
        for operation in (
            "wrong-path",
            "delete",
            "generated",
            "second-at-head",
            "second-at-base",
        ):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                floor = self.initialize(root)
                base = self.add_fragment(root, 189, "pending", "Pending release.")
                pending = root / "changelog.d" / "189-pending.md"
                if operation == "wrong-path":
                    pending.rename(root / "changelog.d" / "190-replacement.md")
                elif operation == "delete":
                    pending.unlink()
                elif operation == "generated":
                    pending.write_text(
                        "### Security\n\n- Edited pending release.\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                    with (root / "VERSION").open("a", encoding="utf-8") as handle:
                        handle.write("generated edit\n")
                elif operation == "second-at-head":
                    pending.write_text(
                        "### Security\n\n- Edited pending release.\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                    (root / "changelog.d" / "190-second.md").write_text(
                        "### Fixed\n\n- Second release.\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                else:
                    self.add_fragment(root, 190, "second", "Second pending release.")
                    base = self.git(root, "rev-parse", "HEAD")
                    pending.write_text(
                        "### Security\n\n- Edited pending release.\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                head = self.commit(root, f"hostile unpublished edit {operation}")
                with mock.patch.object(
                    MODULE, "TAG_LEDGER_FLOOR_SHA", floor
                ), self.assertRaises(MODULE.ContractError):
                    MODULE.validate_transition(root, base, head, first_parent=True)

    def test_unpublished_fragment_edit_rejects_tagged_history_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            floor = self.initialize(root)
            released = self.add_fragment(root, 188, "released", "Released text.")
            release_tag = MODULE.next_version(
                MODULE.Version.parse(MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v"))
            ).tag
            self.tag(root, release_tag, released)
            base = self.add_fragment(root, 189, "pending", "Pending text.")
            (root / "changelog.d" / "188-released.md").write_text(
                "### Security\n\n- Mutated released text.\n",
                encoding="utf-8",
                newline="\n",
            )
            (root / "changelog.d" / "189-pending.md").write_text(
                "### Security\n\n- Edited pending text.\n",
                encoding="utf-8",
                newline="\n",
            )
            head = self.commit(root, "mutate tagged history")
            with mock.patch.object(
                MODULE, "TAG_LEDGER_FLOOR_SHA", floor
            ), self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, base, head, first_parent=True)

    def test_unpublished_fragment_edit_rejects_moved_nonlinear_and_tagged_ranges(self):
        floor_version = MODULE.Version.parse(
            MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v")
        )
        with self.subTest(case="latest-tag-not-ancestor"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            floor = self.initialize(root)
            self.git(root, "checkout", "-q", "-b", "published", floor)
            published = self.add_fragment(root, 188, "published", "Published text.")
            self.tag(root, MODULE.next_version(floor_version).tag, published)
            self.git(root, "checkout", "-q", "main")
            base = self.add_fragment(root, 189, "pending", "Pending text.")
            (root / "changelog.d" / "189-pending.md").write_text(
                "### Security\n\n- Edited pending text.\n",
                encoding="utf-8",
                newline="\n",
            )
            head = self.commit(root, "edit on moved base")
            with mock.patch.object(
                MODULE, "TAG_LEDGER_FLOOR_SHA", floor
            ), self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, base, head, first_parent=True)

        with self.subTest(case="nonlinear"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            floor = self.initialize(root)
            base = self.add_fragment(root, 189, "pending", "Pending text.")
            self.git(root, "checkout", "-q", "-b", "side", base)
            self.commit(root, "side content")
            self.git(root, "checkout", "-q", "main")
            (root / "changelog.d" / "189-pending.md").write_text(
                "### Security\n\n- Edited pending text.\n",
                encoding="utf-8",
                newline="\n",
            )
            self.commit(root, "edit before merge")
            self.git(
                root,
                "-c",
                "user.name=Release Test",
                "-c",
                "user.email=release@example.invalid",
                "merge",
                "--no-ff",
                "side",
                "-m",
                "merge side",
            )
            head = self.git(root, "rev-parse", "HEAD")
            with mock.patch.object(
                MODULE, "TAG_LEDGER_FLOOR_SHA", floor
            ), self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, base, head, first_parent=True)

        for endpoint in ("base", "head"):
            with self.subTest(endpoint=endpoint), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                floor = self.initialize(root)
                base = self.add_fragment(root, 189, "pending", "Pending text.")
                if endpoint == "base":
                    self.git(root, "tag", "recovery-base", base)
                (root / "changelog.d" / "189-pending.md").write_text(
                    "### Security\n\n- Edited pending text.\n",
                    encoding="utf-8",
                    newline="\n",
                )
                head = self.commit(root, f"edit with tagged {endpoint}")
                if endpoint == "head":
                    self.git(root, "tag", "recovery-head", head)
                with mock.patch.object(
                    MODULE, "TAG_LEDGER_FLOOR_SHA", floor
                ), self.assertRaises(MODULE.ContractError):
                    MODULE.validate_transition(root, base, head, first_parent=True)

    def test_fragment_tree_entry_must_be_a_regular_non_executable_blob(self):
        payload = b"### Security\n\n- Exact tree entry.\n"
        for mode in ("120000", "100755"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                base = self.initialize(root)
                self.stage_fragment_mode(
                    root, "changelog.d/164-tree-mode.md", payload, mode
                )
                head = self.commit_staged(root, f"hostile fragment mode {mode}")
                with self.assertRaises(MODULE.ContractError) as denied:
                    MODULE.validate_transition(root, base, head, first_parent=True)
                self.assertIn(
                    "regular non-executable 100644 blob", str(denied.exception)
                )

    def test_squash_and_arbitrary_position_rebase_ranges_bind_the_final_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = self.initialize(root)
            self.commit(root, "rebased content before fragment")
            fragment_commit = self.add_fragment(root, 164, "rebased", "rebased fragment")
            final_head = self.commit(root, "rebased content after fragment")
            intent = MODULE.validate_transition(
                root, initial, final_head, first_parent=True
            )
            self.assertEqual(intent.source_sha, final_head)
            self.assertEqual(intent.fragment_path, "changelog.d/164-rebased.md")
            self.assertNotEqual(fragment_commit, final_head)

            self.git(root, "checkout", "-q", "-b", "double-fragment", initial)
            self.add_fragment(root, 165, "first", "first fragment")
            double_head = self.add_fragment(root, 166, "second", "second fragment")
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, initial, double_head, first_parent=True)

    def test_squash_and_every_rebase_fragment_position_share_semantics(self):
        for before, after in ((0, 0), (0, 2), (2, 0), (2, 2)):
            with self.subTest(before=before, after=after), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                initial = self.initialize(root)
                for index in range(before):
                    self.commit(root, f"content before {index}")
                self.add_fragment(root, 164, "position", "exact fragment boundary")
                for index in range(after):
                    self.commit(root, f"content after {index}")
                head = self.git(root, "rev-parse", "HEAD")
                for first_parent in (False, True):
                    intent = MODULE.validate_transition(
                        root, initial, head, first_parent=first_parent
                    )
                    self.assertEqual(intent.source_sha, head)
                    self.assertEqual(intent.fragment_path, "changelog.d/164-position.md")

    def test_tag_ledger_derives_ready_complete_notes_and_rapid_merge_waits(self):
        floor_version = MODULE.Version.parse(
            MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v")
        )
        first_tag = MODULE.next_version(floor_version).tag
        second_tag = MODULE.next_version(MODULE.next_version(floor_version)).tag
        third_tag = MODULE.next_version(
            MODULE.next_version(MODULE.next_version(floor_version))
        ).tag
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            floor = self.initialize(root)
            first = self.add_fragment(root, 164, "first", "First release.")
            second = self.add_fragment(root, 165, "second", "Second release.")
            third = self.add_fragment(root, 166, "third", "Third release.")
            with mock.patch.object(MODULE, "TAG_LEDGER_FLOOR_SHA", floor):
                first_window = MODULE.discover_transition_window(root, first)
                self.assertEqual(first_window.base_sha, floor)
                self.assertEqual(first_window.base_tag, MODULE.TAG_LEDGER_FLOOR_TAG)
                self.assertEqual(first_window.intent.tag, first_tag)
                with self.assertRaises(MODULE.PendingRelease):
                    MODULE.discover_transition_window(root, second)
                with self.assertRaises(MODULE.PendingRelease):
                    MODULE.discover_transition_window(root, third)
                with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(
                    io.StringIO()
                ) as errors:
                    status = MODULE.main(
                        [
                            "release-window",
                            "--repository",
                            str(root),
                            "--head",
                            second,
                        ]
                    )
                self.assertEqual(status, 3)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("PENDING:", errors.getvalue())

                self.tag(root, first_tag, first)
                complete = MODULE.discover_transition_window(root, first)
                self.assertEqual(complete.base_tag, MODULE.TAG_LEDGER_FLOOR_TAG)
                self.assertEqual(complete.intent.tag, first_tag)
                second_window = MODULE.discover_transition_window(root, second)
                self.assertEqual(second_window.base_tag, first_tag)
                self.assertEqual(second_window.intent.tag, second_tag)
                notes = MODULE.render_release_notes(
                    root,
                    second,
                    second_tag,
                    expected_base_sha=first,
                    expected_base_tag=first_tag,
                )
                self.assertIn("`changelog.d/165-second.md`", notes)
                self.assertIn("### Security\n\n- Second release.\n", notes)
                self.assertNotIn("CHANGELOG.md", notes)
                for wrong_base in (
                    {
                        "expected_base_sha": floor,
                        "expected_base_tag": MODULE.TAG_LEDGER_FLOOR_TAG,
                    },
                    {"expected_base_sha": first},
                ):
                    with self.subTest(wrong_base=wrong_base), self.assertRaises(
                        MODULE.ContractError
                    ):
                        MODULE.render_release_notes(
                            root, second, second_tag, **wrong_base
                        )
                with self.assertRaises(MODULE.PendingRelease):
                    MODULE.discover_transition_window(root, third)

                self.tag(root, second_tag, second)
                third_window = MODULE.discover_transition_window(root, third)
                self.assertEqual(third_window.intent.tag, third_tag)

                legacy = MODULE.render_release_notes(
                    root, floor, MODULE.TAG_LEDGER_FLOOR_TAG
                )
                self.assertIn("See `CHANGELOG.md`", legacy)

    def test_migration_floor_tag_and_source_are_both_exact(self):
        first_tag = MODULE.next_version(
            MODULE.Version.parse(MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v"))
        ).tag
        for case in ("wrong-tag", "wrong-source"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                expected_floor = self.initialize(root)
                self.git(root, "update-ref", "-d", f"refs/tags/{MODULE.TAG_LEDGER_FLOOR_TAG}")
                if case == "wrong-tag":
                    self.tag(root, first_tag, expected_floor)
                else:
                    wrong_source = self.commit(root, "wrong migration floor source")
                    self.tag(root, MODULE.TAG_LEDGER_FLOOR_TAG, wrong_source)
                with mock.patch.object(
                    MODULE, "TAG_LEDGER_FLOOR_SHA", expected_floor
                ), self.assertRaises(MODULE.ContractError) as denied:
                    MODULE._platform_tag_boundaries(root)
                self.assertEqual(
                    str(denied.exception),
                    "tag-derived release ledger floor is not exact",
                )

    def test_tag_ledger_inventory_has_a_literal_validation_bound(self):
        self.assertEqual(MODULE.MAX_TAG_LEDGER_ENTRIES, 1024)
        tags = "\n".join(f"v0.1.{patch}" for patch in range(1025))
        with mock.patch.object(MODULE, "_git", return_value=tags), self.assertRaises(
            MODULE.ContractError
        ) as denied:
            MODULE._platform_tag_boundaries(Path("unused-by-bounded-inventory"))
        self.assertEqual(
            str(denied.exception),
            "tag-derived release ledger exceeds the 1024-entry validation bound",
        )

    def test_source_behind_later_exact_tag_uses_the_named_denial(self):
        first_tag = MODULE.next_version(
            MODULE.Version.parse(MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v"))
        ).tag
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            floor = self.initialize(root)
            source = self.add_fragment(root, 164, "source", "Release source.")
            tagged_source = self.commit(root, "content after release source")
            self.tag(root, first_tag, tagged_source)
            with mock.patch.object(
                MODULE, "TAG_LEDGER_FLOOR_SHA", floor
            ), self.assertRaises(MODULE.ContractError) as denied:
                MODULE.discover_transition_window(root, source)
            self.assertEqual(
                str(denied.exception),
                "source SHA is behind a later tag but has no exact release tag",
            )

    def test_a_misplaced_tag_cannot_swallow_an_earlier_fragment(self):
        first_tag = MODULE.next_version(
            MODULE.Version.parse(MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v"))
        ).tag
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            floor = self.initialize(root)
            first = self.add_fragment(root, 164, "first", "First release.")
            second = self.add_fragment(root, 165, "second", "Second release.")
            third = self.add_fragment(root, 166, "third", "Third release.")
            self.tag(root, first_tag, second)
            with mock.patch.object(MODULE, "TAG_LEDGER_FLOOR_SHA", floor):
                for source in (first, second, third):
                    with self.subTest(source=source), self.assertRaises(
                        MODULE.ContractError
                    ):
                        MODULE.discover_transition_window(root, source)

    def test_tag_skip_lightweight_foreign_target_and_missing_earlier_tag_deny(self):
        first_version = MODULE.next_version(
            MODULE.Version.parse(MODULE.TAG_LEDGER_FLOOR_TAG.removeprefix("v"))
        )
        first_tag = first_version.tag
        skipped_tag = MODULE.next_version(first_version).tag
        cases = (
            "skip",
            "lightweight",
            "foreign",
            "missing-earlier",
            "foreign-message",
            "foreign-tagger",
            "foreign-date",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                floor = self.initialize(root)
                first = self.add_fragment(root, 164, "first", "First release.")
                if case == "skip":
                    self.tag(root, skipped_tag, first)
                elif case == "lightweight":
                    self.git(root, "tag", first_tag, first)
                elif case == "foreign":
                    self.git(root, "checkout", "-q", "-b", "foreign", floor)
                    foreign = self.commit(root, "foreign release target")
                    self.tag(root, first_tag, foreign)
                    self.git(root, "checkout", "-q", "main")
                elif case == "missing-earlier":
                    second = self.add_fragment(root, 165, "second", "Second release.")
                    self.tag(root, first_tag, second)
                elif case == "foreign-message":
                    self.tag(root, first_tag, first, message="Foreign message")
                elif case == "foreign-tagger":
                    self.tag(
                        root,
                        first_tag,
                        first,
                        tagger_name="Foreign Tagger",
                        tagger_email="foreign@example.invalid",
                    )
                else:
                    self.tag(
                        root,
                        first_tag,
                        first,
                        tagger_date="2026-08-20T00:00:00+00:00",
                    )
                with mock.patch.object(MODULE, "TAG_LEDGER_FLOOR_SHA", floor):
                    with self.assertRaises(MODULE.ContractError):
                        MODULE.discover_transition_window(root, first)

    def test_pr_and_main_reject_merge_ranges_that_cannot_guarantee_rebase_liveness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self.initialize(root)
            self.git(root, "checkout", "-q", "-b", "topic", base)
            self.commit(root, "topic content")
            self.git(root, "checkout", "-q", "-b", "side", base)
            self.commit(root, "side content")
            self.git(root, "checkout", "-q", "topic")
            self.git(
                root,
                "-c",
                "user.name=Release Test",
                "-c",
                "user.email=release@example.invalid",
                "merge",
                "--no-ff",
                "side",
                "-m",
                "merge side",
            )
            head = self.add_fragment(root, 164, "merged", "final fragment")
            for first_parent in (False, True):
                with self.assertRaises(MODULE.ContractError):
                    MODULE.validate_transition(
                        root, base, head, first_parent=first_parent
                    )

    def test_base_move_denial_names_the_owner_rebase_or_fresh_branch_actions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = self.initialize(root)
            self.git(root, "checkout", "-q", "-b", "topic", initial)
            head = self.add_fragment(root, 164, "topic", "Topic release input.")
            self.git(root, "checkout", "-q", "-b", "moved-main", initial)
            moved_base = self.commit(root, "protected base moved")
            with self.assertRaises(MODULE.ContractError) as denied:
                MODULE.validate_transition(
                    root, moved_base, head, first_parent=False
                )
            self.assertEqual(
                str(denied.exception),
                "release head does not descend from the exact current base; "
                "request an owner-operated GitHub rebase update or create a fresh branch",
            )


class WorkflowStructureTests(unittest.TestCase):
    ACTION_PIN = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0"

    @staticmethod
    def require_exact_wiring(
        workflow: str,
        jobs_verifier: str,
        predecessor_wait: str,
        settings_verifier: str,
        transaction: str,
    ) -> None:
        if workflow.count("  main-ci-jobs:\n") != 1:
            raise ValueError("workflow must have one dedicated main-CI jobs proof")
        if workflow.count("  immutable-settings:\n") != 1:
            raise ValueError("workflow must have one dedicated immutable-settings job")
        if workflow.count("  publish:\n") != 1:
            raise ValueError("workflow must have one physically separate publish job")
        jobs_start = workflow.index("  main-ci-jobs:\n")
        settings_start = workflow.index("  immutable-settings:\n")
        publish_start = workflow.index("  publish:\n")
        if not jobs_start < settings_start < publish_start:
            raise ValueError("both read-only proofs must precede publication")
        jobs_job = workflow[jobs_start:settings_start]
        settings_job = workflow[settings_start:publish_start]
        publish_job = workflow[publish_start:]

        for required in (
            "platform-release-${{ github.event.workflow_run.head_sha }}",
            "cancel-in-progress: false",
            "branches: [main]",
        ):
            if required not in workflow:
                raise ValueError(f"platform workflow lost exact wiring: {required}")
        if workflow.count("fetch-depth: 0") != 2:
            raise ValueError("both jobs must independently fetch exact complete history")
        if workflow.count("release-window") != 1 or "release-window" not in publish_job:
            raise ValueError("the write job must rebind the release window exactly once")
        if "release-window" in settings_job:
            raise ValueError("ordering must be isolated in the GET-only predecessor script")

        for required in (
            "outputs:\n      attestation: ${{ steps.required-jobs.outputs.attestation }}",
            "permissions:\n      actions: read\n      contents: read",
            "ACTIONS_READ_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            "COMPLETED_RUN_ID: ${{ github.event.workflow_run.id }}",
            "COMPLETED_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}",
            "SOURCE_SHA: ${{ github.event.workflow_run.head_sha }}",
            "bash scripts/ci/verify-platform-release-main-jobs.sh",
        ):
            if required not in jobs_job:
                raise ValueError(f"read-only main-CI jobs proof lost exact wiring: {required}")
        for forbidden in (
            "environment:",
            "contents: write",
            "create-github-app-token",
            "PLATFORM_RELEASE_APP_ID",
            "PLATFORM_RELEASE_APP_PRIVATE_KEY",
            "IMMUTABLE_SETTINGS_TOKEN",
            "permission-administration",
        ):
            if forbidden in jobs_job:
                raise ValueError(f"foreign authority crossed into jobs proof: {forbidden}")
        jobs_outputs = jobs_job[
            jobs_job.index("    outputs:\n") : jobs_job.index("    runs-on:")
        ]
        if "token" in jobs_outputs.lower() or jobs_outputs.count("attestation:") != 1:
            raise ValueError("jobs proof may export only one sanitized attestation")

        for required in (
            "outputs:\n      attestation: ${{ steps.immutable-settings.outputs.attestation }}",
            "predecessor: ${{ steps.predecessor.outputs.attestation }}",
            "CONTENTS_READ_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            "bash scripts/ci/wait-platform-release-predecessor.sh",
            "environment:\n      name: platform-release\n      deployment: false",
            "permissions:\n      contents: read",
            WorkflowStructureTests.ACTION_PIN,
            "app-id: ${{ vars.PLATFORM_RELEASE_APP_ID }}",
            "private-key: ${{ secrets.PLATFORM_RELEASE_APP_PRIVATE_KEY }}",
            "owner: snaraj",
            "repositories: website-infrastructure",
            "permission-administration: read",
            "skip-token-revoke: false",
            "IMMUTABLE_SETTINGS_TOKEN: ${{ steps.immutable-settings-token.outputs.token }}",
            "SOURCE_SHA: ${{ steps.source.outputs.source_sha }}",
            "bash scripts/ci/verify-platform-release-settings.sh",
        ):
            if required not in settings_job:
                raise ValueError(f"read-only settings job lost exact wiring: {required}")
        if (
            "contents: write" in settings_job
            or "GH_TOKEN:" in settings_job
            or "actions:" in settings_job
            or "ACTIONS_READ_TOKEN" in settings_job
        ):
            raise ValueError("settings job must never receive publication authority")
        outputs = settings_job[
            settings_job.index("    outputs:\n") : settings_job.index("    runs-on:")
        ]
        if "token" in outputs.lower() or outputs.count("attestation:") != 1:
            raise ValueError("settings job may export only sanitized attestations")
        if not (
            settings_job.index("bash scripts/ci/wait-platform-release-predecessor.sh")
            < settings_job.index(WorkflowStructureTests.ACTION_PIN)
            < settings_job.index("bash scripts/ci/verify-platform-release-settings.sh")
        ):
            raise ValueError(
                "bounded ordering must finish before the fresh immutable-settings proof"
            )

        for required in (
            "needs: [main-ci-jobs, immutable-settings]",
            "needs.main-ci-jobs.outputs.attestation ==",
            "github.event.workflow_run.id, github.event.workflow_run.run_attempt,",
            "needs.immutable-settings.outputs.attestation ==",
            "needs.immutable-settings.outputs.predecessor ==",
            "format('PASS:{0}:{1}:{2}:{3}', github.repository, github.run_id,",
            "github.run_attempt, github.event.workflow_run.head_sha)",
            "format('PASS:{0}:{1}', github.repository,",
            "permissions:\n      contents: write",
            "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            "git fetch --quiet --tags origin",
            "release-window",
            "base_sha=\"$(jq -er '.base_sha'",
            "base_tag=\"$(jq -er '.base_tag'",
            "BASE_SHA: ${{ steps.release.outputs.base_sha }}",
            "BASE_TAG: ${{ steps.release.outputs.base_tag }}",
            "permissions:\n      contents: write\n      id-token: write\n      packages: write",
            "SELECTOR_IMAGE: ghcr.io/snaraj/website-infrastructure/platform-release-selector",
            "Install checksum-verified release tools",
            "Select the immutable selector image lineage",
            'git diff --quiet "${BASE_SHA}" "${SOURCE_SHA}" --',
            "cmd/platform-release-selector internal/releaseselector go.mod",
            '[ "${BASE_SHA}" = 6d85c2b01dd4bd66add4192372b26bcdf1b0a951 ]',
            '[ "${BASE_TAG}" = v0.1.42 ]',
            '[ "${TAG}" = v0.1.43 ]',
            "'sha256:c9f8d59013bc5ca9431e3ccd22227e4e05920746829318cacf1ccb70b17d2e61'",
            'test "${predecessor_status}" = 404',
            'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then',
            "platform-release-identity.v1.json.sigstore.json",
            "cosign verify-blob",
            "identity-run-records",
            '--source-tree-sha "${tree_sha}"',
            '--base-tag "${BASE_TAG}" --target-tag "${TAG}"',
            '--emit > "${legacy_predecessor}"',
            "actions/runs/${legacy_main_id}/attempts/${legacy_main_attempt}",
            "actions/runs/${legacy_platform_id}/attempts/${legacy_platform_attempt}",
            "state=reuse",
            "state=build",
            "if: steps.selector-image-state.outputs.state == 'build'",
            "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e # v4.3.0",
            "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7.3.0",
            "context: https://github.com/snaraj/website-infrastructure.git#${{ steps.release.outputs.source_sha }}",
            "platforms: linux/arm64",
            "push-by-digest=true",
            "provenance: mode=max,version=v1",
            "sbom: true",
            "--format '{{ json .Provenance.SLSA }}'",
            '$definition.externalParameters.configSource == {',
            '"digest": {"sha1": $source}',
            ".runDetails.metadata.buildkit_completeness.resolvedDependencies == true",
            ".runDetails.metadata.buildkit_hermetic == true",
            "trivy image --image-src remote --platform linux/arm64",
            'identity="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/.github/workflows/platform-release.yml@refs/heads/main"',
            "issuer='https://token.actions.githubusercontent.com'",
            'cosign verify --certificate-identity "${identity}"',
            "cosign verify-attestation --type slsaprovenance1",
            "MAIN_RUN_ID: ${{ github.event.workflow_run.id }}",
            "MAIN_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}",
            "SELECTOR_IMAGE_DIGEST: ${{ steps.selector-image.outputs.digest }}",
            "bash scripts/ci/publish-platform-release.sh",
        ):
            if required not in publish_job:
                raise ValueError(f"write-only publish job lost exact wiring: {required}")
        for forbidden in (
            "environment:",
            "create-github-app-token",
            "PLATFORM_RELEASE_APP_ID",
            "PLATFORM_RELEASE_APP_PRIVATE_KEY",
            "IMMUTABLE_SETTINGS_TOKEN",
            "ACTIONS_READ_TOKEN",
            "CONTENTS_READ_TOKEN",
            "permission-administration",
            "verify-platform-release-settings.sh",
            "verify-platform-release-main-jobs.sh",
            "fragment_path=\"$(jq -er '.fragment_path'",
            "fragment_sha256=\"$(jq -er '.fragment_sha256'",
            "steps.release.outputs.fragment_path",
            "steps.release.outputs.fragment_sha256",
        ):
            if forbidden in publish_job:
                raise ValueError(f"App authority crossed into publish job: {forbidden}")

        if workflow.count("permission-administration: read") != 1:
            raise ValueError("release App token must request Administration:read exactly once")
        if workflow.count("PLATFORM_RELEASE_APP_ID") != 1:
            raise ValueError("release App ID must occur only in the settings job")
        if workflow.count("PLATFORM_RELEASE_APP_PRIVATE_KEY") != 1:
            raise ValueError("release App key must occur only in the settings job")
        if workflow.count("actions: read") != 1:
            raise ValueError("Actions read must occur only in the jobs-proof job")
        if workflow.count("ACTIONS_READ_TOKEN") != 1:
            raise ValueError("Actions token must occur only in the jobs-proof job")
        if workflow.count("CONTENTS_READ_TOKEN") != 1:
            raise ValueError("contents-read token must occur only in predecessor ordering")
        for forbidden in (
            "permission-administration: write",
            "permission-contents:",
            "actions: write",
            "skip-token-revoke: true",
            "deployment: true",
        ):
            if forbidden in workflow:
                raise ValueError(f"release App workflow broadened authority: {forbidden}")

        for required in (
            ': "${ACTIONS_READ_TOKEN:?ACTIONS_READ_TOKEN is required}"',
            ': "${COMPLETED_RUN_ID:?COMPLETED_RUN_ID is required}"',
            ': "${COMPLETED_RUN_ATTEMPT:?COMPLETED_RUN_ATTEMPT is required}"',
            'actions_token="${ACTIONS_READ_TOKEN}"',
            "unset ACTIONS_READ_TOKEN",
            'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"',
            'test -z "${GH_TOKEN-}"',
            'test -z "${GITHUB_TOKEN-}"',
            'test -z "${GH_ENTERPRISE_TOKEN-}"',
            'test -z "${GITHUB_ENTERPRISE_TOKEN-}"',
            "--request GET",
            '"Authorization: Bearer ${actions_token}"',
            "unset actions_token",
            "/actions/runs/${COMPLETED_RUN_ID}/jobs?filter=latest&per_page=100",
            "/actions/workflows/codeql.yml/runs?branch=main&event=push&head_sha=${SOURCE_SHA}&per_page=100",
            "/actions/runs/${codeql_run_id}/jobs?filter=latest&per_page=100",
            "for poll_attempt in {1..30}",
            'python3 -I -B "${contract}" codeql-run-state',
            'python3 -I -B "${contract}" codeql-jobs-state',
            'test "${codeql_ready}" = true',
            'python3 -I -B "${contract}" main-ci-jobs-receipt',
            '--codeql-runs-json "${codeql_runs_json}"',
            '--codeql-jobs-json "${codeql_jobs_json}"',
            '--run-id "${COMPLETED_RUN_ID}"',
            '--run-attempt "${COMPLETED_RUN_ATTEMPT}"',
            "printf 'attestation=PASS:%s:%s:%s:%s\\n'",
        ):
            if required not in jobs_verifier:
                raise ValueError(f"main-CI jobs verifier lost exact guard: {required}")
        if jobs_verifier.count("actions_token") != 3:
            raise ValueError("Actions token must be captured, used once, and cleared")
        for forbidden in (
            "--request POST",
            "--request PUT",
            "--request PATCH",
            "--request DELETE",
            "gh ",
            "/git/refs",
            "/releases/tags",
            "IMMUTABLE_SETTINGS_TOKEN: ${{",
        ):
            if forbidden in jobs_verifier:
                raise ValueError(f"jobs verifier gained foreign authority: {forbidden}")

        for required in (
            ': "${CONTENTS_READ_TOKEN:?CONTENTS_READ_TOKEN is required}"',
            ': "${SOURCE_SHA:?SOURCE_SHA is required}"',
            'test -z "${GH_TOKEN-}"',
            'test -z "${GITHUB_TOKEN-}"',
            'test -z "${GH_ENTERPRISE_TOKEN-}"',
            'test -z "${GITHUB_ENTERPRISE_TOKEN-}"',
            'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"',
            'test -z "${ACTIONS_READ_TOKEN-}"',
            'read_token="${CONTENTS_READ_TOKEN}"',
            "unset CONTENTS_READ_TOKEN",
            "--request GET",
            '"Authorization: Bearer ${read_token}"',
            "git fetch --quiet --tags origin",
            "for _attempt in {1..30}",
            'tag_snapshot="$(git for-each-ref',
            "--count=1025",
            "--format='%(refname)%09%(objectname)%09%(*objectname)'",
            '[ "${have_cached_window}" != true ] ||',
            '[ "${tag_snapshot}" != "${cached_tag_snapshot}" ]',
            'python3 -I -B "${contract}" release-window',
            'test "${status}" -eq 3 || exit "${status}"',
            'python3 -I -B "${contract}" release-notes',
            "classify_predecessor_tag",
            '[ "${base_sha}" = "${burned_source_sha}" ]',
            '[ "${base_tag}" = "${burned_tag}" ]',
            '[ "${target_tag}" = v0.1.43 ]',
            'classify_predecessor_release absent "${base_tag}" "${base_sha}"',
            "classify_predecessor_release exact",
            "classify_predecessor_release absent",
            '--source-sha "${source_sha}" \\\n'
            '    --title "Platform ${tag}" --body "${notes}" >/dev/null',
            'classify_predecessor_release exact "${base_tag}" "${base_sha}"',
            'printf \'attestation=PASS:%s:%s\\n\'',
            "unset read_token",
        ):
            if required not in predecessor_wait:
                raise ValueError(f"predecessor waiter lost exact guard: {required}")
        for token, expected in (
            ("--request GET", 2),
            ('"Authorization: Bearer ${read_token}"', 2),
        ):
            if predecessor_wait.count(token) != expected:
                raise ValueError(
                    f"predecessor waiter read path count drifted: {token}"
                )
        for forbidden in (
            "--request POST",
            "--request PUT",
            "--request PATCH",
            "--request DELETE",
            "gh ",
            "contents: write",
            "run_write_gh",
            "release create",
            "/immutable-releases",
            "/actions/",
        ):
            if forbidden in predecessor_wait:
                raise ValueError(
                    f"GET-only predecessor waiter gained foreign authority: {forbidden}"
                )
        if predecessor_wait.count("attestation=") != 1:
            raise ValueError("predecessor waiter may export only one sanitized attestation")
        if predecessor_wait.count("classify_predecessor_tag") != 2:
            raise ValueError("predecessor tag classifier must be defined and invoked once")
        if predecessor_wait.count(
            'classify_predecessor_release absent "${base_tag}" "${base_sha}"'
        ) != 2:
            raise ValueError(
                "predecessor absence must remain exact in the incident and normal paths"
            )
        if predecessor_wait.count("unset read_token") != 2:
            raise ValueError("predecessor read token must be cleared on both exits")
        normal_exact = predecessor_wait.index(
            'elif classify_predecessor_release exact "${base_tag}" "${base_sha}"'
        )
        normal_absent = predecessor_wait.index(
            'elif classify_predecessor_release absent "${base_tag}" "${base_sha}"',
            normal_exact,
        )
        if normal_exact > normal_absent:
            raise ValueError("predecessor exact state must be attempted before clean absence")

        for required in (
            ': "${IMMUTABLE_SETTINGS_TOKEN:?IMMUTABLE_SETTINGS_TOKEN is required}"',
            'test -z "${GH_TOKEN-}"',
            'test -z "${GITHUB_TOKEN-}"',
            'test -z "${GH_ENTERPRISE_TOKEN-}"',
            'test -z "${GITHUB_ENTERPRISE_TOKEN-}"',
            'settings_token="${IMMUTABLE_SETTINGS_TOKEN}"',
            "unset IMMUTABLE_SETTINGS_TOKEN",
            "--request GET",
            '"Authorization: Bearer ${settings_token}"',
            "unset settings_token",
            "/immutable-releases",
            'python3 -I -B "${contract}" immutable-settings-receipt',
            ': "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"',
            ': "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"',
            "--run-id \"${GITHUB_RUN_ID}\"",
            "--run-attempt \"${GITHUB_RUN_ATTEMPT}\"",
            "printf 'attestation=PASS:%s:%s:%s:%s\\n'",
        ):
            if required not in settings_verifier:
                raise ValueError(f"settings verifier lost exact guard: {required}")
        if settings_verifier.count("settings_token") != 3:
            raise ValueError("App token must be captured, used once, and cleared")
        for forbidden in (
            "--request POST",
            "--request PUT",
            "--request PATCH",
            "--request DELETE",
            "gh ",
            "/git/refs",
            "/releases/tags",
            "/rulesets",
            "bypass_actors",
            "settings-preflight",
            "release_tag_",
        ):
            if forbidden in settings_verifier:
                raise ValueError(f"settings verifier gained mutation surface: {forbidden}")

        validate_single_asset_publication_transaction(transaction)
        if "settings_token" in transaction or "/immutable-releases" in transaction:
            raise ValueError("App settings authority must not enter the write transaction")
        if transaction.count('--target "') != 1:
            raise ValueError("only the frozen recovery Release may use direct --target")
        if transaction.count("for attempt in 1 2 3 4 5") != 4:
            raise ValueError(
                "draft retirement, recovery Release, current tag, and immutable "
                "Release need bounded retries"
            )
        if transaction.count("preflight_publication_state") != 6:
            raise ValueError(
                "all remote states need an initial preflight and mutation-boundary rechecks"
            )
        if (
            "preflight_publication_state\n"
            "complete_recovery_release\n"
            "retire_burned_partial_draft\n"
            "publish_current_release"
        ) not in transaction:
            raise ValueError("all remote states must close before publication phases")
        if transaction.count('test "${tag_race_verified}" = true') != 1:
            raise ValueError("current tag race lacks one terminal exact assertion")
        if transaction.count('test "${release_race_verified}" = true') != 2:
            raise ValueError("both Release races lack terminal exact assertions")

        selector_required = (
            "permissions:\n      contents: write\n      id-token: write\n      packages: write",
            "SELECTOR_IMAGE: ghcr.io/snaraj/website-infrastructure/platform-release-selector",
            "Install checksum-verified release tools",
            "Select the immutable selector image lineage",
            'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then',
            "platform-release-identity.v1.json.sigstore.json",
            "cosign verify-blob",
            "identity-run-records",
            '--source-tree-sha "${tree_sha}"',
            "validate_platform_predecessor.py",
            "actions/workflows/pull-request.yml/runs?branch=main&event=push&head_sha=${BASE_SHA}&status=success&per_page=100",
            "actions/workflows/platform-release.yml/runs?branch=main&event=workflow_run&head_sha=${BASE_SHA}&status=success&per_page=100",
            '--repository .',
            '--base-tag "${BASE_TAG}" --target-tag "${TAG}"',
            '--main-runs-json "${legacy_main_runs}"',
            '--platform-runs-json "${legacy_platform_runs}"',
            '--emit > "${legacy_predecessor}"',
            "actions/runs/${legacy_main_id}/attempts/${legacy_main_attempt}",
            "actions/runs/${legacy_platform_id}/attempts/${legacy_platform_attempt}",
            "state=reuse",
            "state=build",
            "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e # v4.3.0",
            "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7.3.0",
            "context: https://github.com/snaraj/website-infrastructure.git#${{ steps.release.outputs.source_sha }}",
            "platforms: linux/arm64",
            "push-by-digest=true",
            "provenance: mode=max,version=v1",
            "sbom: true",
            '$definition.externalParameters.configSource == {',
            '"digest": {"sha1": $source}',
            ".runDetails.metadata.buildkit_completeness.resolvedDependencies == true",
            ".runDetails.metadata.buildkit_hermetic == true",
            'cosign sign --yes "${SELECTOR_IMAGE}@${DIGEST}"',
            "cosign attest --yes",
            'identity="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/.github/workflows/platform-release.yml@refs/heads/main"',
            "issuer='https://token.actions.githubusercontent.com'",
            'cosign verify --certificate-identity "${identity}"',
            "cosign verify-attestation --type slsaprovenance1",
            'MAIN_RUN_ID: ${{ github.event.workflow_run.id }}',
            'MAIN_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}',
            'SELECTOR_IMAGE_DIGEST: ${{ steps.selector-image.outputs.digest }}',
        )
        for required in selector_required:
            if required not in publish_job:
                raise ValueError(f"selector workflow lost exact guard: {required}")
        if "index .Provenance" in publish_job:
            raise ValueError("single-platform selector provenance must not use map indexing")
        if publish_job.count(
            "if: steps.selector-image-state.outputs.state == 'build'"
        ) != 4:
            raise ValueError("all four selector-build steps must be build-only")
        if not (
            publish_job.index("Install checksum-verified release tools")
            < publish_job.index("Select the immutable selector image lineage")
        ):
            raise ValueError("Cosign must be installed before receipt consumption")
        if publish_job.count("state=reuse") != 3 or publish_job.count("state=build") != 2:
            raise ValueError("selector reuse and reviewed changed-build branches drifted")
        for repeated in (
            "BASE_SHA: ${{ steps.release.outputs.base_sha }}",
            "BASE_TAG: ${{ steps.release.outputs.base_tag }}",
        ):
            if publish_job.count(repeated) != 2:
                raise ValueError(f"selector and publisher must both receive {repeated}")
        selector_start = publish_job.index("Select the immutable selector image lineage")
        selector_end = publish_job.index("Set up Buildx for a changed selector image")
        selector = publish_job[selector_start:selector_end]
        legacy_start = selector.index(
            'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then'
        )
        current_identity_path = selector[:legacy_start]
        ordinary_path, legacy_path = selector[legacy_start:].split(
            "\n          else\n", 1
        )
        if ".body" in current_identity_path:
            raise ValueError("current selector reuse must not trust Release Markdown")
        if (
            'git diff --quiet "${BASE_SHA}" "${SOURCE_SHA}" --'
            not in ordinary_path
            or "cmd/platform-release-selector internal/releaseselector go.mod"
            not in ordinary_path
            or 'git diff --quiet "${BASE_SHA}" "${SOURCE_SHA}" --'
            in current_identity_path + legacy_path
        ):
            raise ValueError(
                "only an ordinary release may rebuild changed selector inputs"
            )
        if '"${predecessor_identity}" 1' in legacy_path or "download_asset" in legacy_path:
            raise ValueError("zero-asset v0.1.40 path must not download an identity asset")
        if "--require-ready" in legacy_path or "0000000000000000000000000000000000000000" in legacy_path:
            raise ValueError("legacy exception retained a static predecessor seed")
        if legacy_path.count('--header "Authorization: Bearer ${GH_TOKEN}"') != 4:
            raise ValueError("all four legacy immutable checks must use job authentication")
        for retired in (
            "selector-seed",
            "validate_selector_seed",
            "releasecutover",
            "release-cutover",
            "cutover-image",
        ):
            if retired in workflow + transaction:
                raise ValueError(f"retired selector path remains wired: {retired}")
        for forbidden in (
            'git rev-list -n 1 "${TAG}"',
            "publication-state",
            "targetCommitish",
        ):
            if forbidden in workflow + jobs_verifier + predecessor_wait + settings_verifier + transaction:
                raise ValueError(f"platform publisher has non-authoritative verifier: {forbidden}")

    def test_every_main_sha_has_split_read_and_write_exact_paths(self):
        ci = (ROOT / ".github" / "workflows" / "pull-request.yml").read_text(
            encoding="utf-8"
        )
        workflow = (
            ROOT / ".github" / "workflows" / "platform-release.yml"
        ).read_text(encoding="utf-8")
        settings_verifier = (
            ROOT / "scripts" / "ci" / "verify-platform-release-settings.sh"
        ).read_text(encoding="utf-8")
        jobs_verifier = (
            ROOT / "scripts" / "ci" / "verify-platform-release-main-jobs.sh"
        ).read_text(encoding="utf-8")
        predecessor_wait = (
            ROOT / "scripts" / "ci" / "wait-platform-release-predecessor.sh"
        ).read_text(encoding="utf-8")
        transaction = (
            ROOT / "scripts" / "ci" / "publish-platform-release.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.number || github.run_id", ci)
        self.assertIn('first_parent=(--first-parent)', ci)
        self.assertIn("workflow_run:", workflow)
        self.assertIn("github.event.workflow_run.head_sha", workflow)
        self.assertNotIn("queue:", ci + workflow)
        self.require_exact_wiring(
            workflow, jobs_verifier, predecessor_wait, settings_verifier, transaction
        )

        workflow_deletions = (
            "  main-ci-jobs:\n",
            "  immutable-settings:\n",
            "  publish:\n",
            "fetch-depth: 0",
            "release-window",
            "platform-release-${{ github.event.workflow_run.head_sha }}",
            "cancel-in-progress: false",
            "branches: [main]",
            "outputs:\n      attestation: ${{ steps.immutable-settings.outputs.attestation }}",
            "predecessor: ${{ steps.predecessor.outputs.attestation }}",
            "CONTENTS_READ_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            "bash scripts/ci/wait-platform-release-predecessor.sh",
            "environment:\n      name: platform-release\n      deployment: false",
            self.ACTION_PIN,
            "app-id: ${{ vars.PLATFORM_RELEASE_APP_ID }}",
            "private-key: ${{ secrets.PLATFORM_RELEASE_APP_PRIVATE_KEY }}",
            "owner: snaraj",
            "repositories: website-infrastructure",
            "permission-administration: read",
            "skip-token-revoke: false",
            "IMMUTABLE_SETTINGS_TOKEN: ${{ steps.immutable-settings-token.outputs.token }}",
            "bash scripts/ci/verify-platform-release-settings.sh",
            "outputs:\n      attestation: ${{ steps.required-jobs.outputs.attestation }}",
            "permissions:\n      actions: read\n      contents: read",
            "ACTIONS_READ_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            "COMPLETED_RUN_ID: ${{ github.event.workflow_run.id }}",
            "COMPLETED_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}",
            "bash scripts/ci/verify-platform-release-main-jobs.sh",
            "needs: [main-ci-jobs, immutable-settings]",
            "needs.main-ci-jobs.outputs.attestation ==",
            "github.event.workflow_run.id, github.event.workflow_run.run_attempt,",
            "needs.immutable-settings.outputs.attestation ==",
            "needs.immutable-settings.outputs.predecessor ==",
            "format('PASS:{0}:{1}:{2}:{3}', github.repository, github.run_id,",
            "github.run_attempt, github.event.workflow_run.head_sha)",
            "format('PASS:{0}:{1}', github.repository,",
            "BASE_SHA: ${{ steps.release.outputs.base_sha }}",
            "BASE_TAG: ${{ steps.release.outputs.base_tag }}",
            "bash scripts/ci/publish-platform-release.sh",
        )
        for token in workflow_deletions:
            with self.subTest(workflow_deletion=token), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    workflow.replace(token, "", 1),
                    jobs_verifier,
                    predecessor_wait,
                    settings_verifier,
                    transaction,
                )

        jobs_deletions = (
            ': "${ACTIONS_READ_TOKEN:?ACTIONS_READ_TOKEN is required}"',
            ': "${COMPLETED_RUN_ID:?COMPLETED_RUN_ID is required}"',
            ': "${COMPLETED_RUN_ATTEMPT:?COMPLETED_RUN_ATTEMPT is required}"',
            'actions_token="${ACTIONS_READ_TOKEN}"',
            "unset ACTIONS_READ_TOKEN",
            'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"',
            'test -z "${GH_TOKEN-}"',
            'test -z "${GITHUB_TOKEN-}"',
            'test -z "${GH_ENTERPRISE_TOKEN-}"',
            'test -z "${GITHUB_ENTERPRISE_TOKEN-}"',
            "--request GET",
            '"Authorization: Bearer ${actions_token}"',
            "unset actions_token",
            "/actions/runs/${COMPLETED_RUN_ID}/jobs?filter=latest&per_page=100",
            "/actions/workflows/codeql.yml/runs?branch=main&event=push&head_sha=${SOURCE_SHA}&per_page=100",
            "/actions/runs/${codeql_run_id}/jobs?filter=latest&per_page=100",
            "for poll_attempt in {1..30}",
            'python3 -I -B "${contract}" codeql-run-state',
            'python3 -I -B "${contract}" codeql-jobs-state',
            'test "${codeql_ready}" = true',
            'python3 -I -B "${contract}" main-ci-jobs-receipt',
            '--codeql-runs-json "${codeql_runs_json}"',
            '--codeql-jobs-json "${codeql_jobs_json}"',
            '--run-id "${COMPLETED_RUN_ID}"',
            '--run-attempt "${COMPLETED_RUN_ATTEMPT}"',
            "printf 'attestation=PASS:%s:%s:%s:%s\\n'",
        )
        for token in jobs_deletions:
            with self.subTest(jobs_deletion=token), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    workflow,
                    jobs_verifier.replace(token, "", 1),
                    predecessor_wait,
                    settings_verifier,
                    transaction,
                )

        predecessor_deletions = (
            ': "${CONTENTS_READ_TOKEN:?CONTENTS_READ_TOKEN is required}"',
            ': "${SOURCE_SHA:?SOURCE_SHA is required}"',
            'test -z "${GH_TOKEN-}"',
            'test -z "${GITHUB_TOKEN-}"',
            'test -z "${GH_ENTERPRISE_TOKEN-}"',
            'test -z "${GITHUB_ENTERPRISE_TOKEN-}"',
            'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"',
            'test -z "${ACTIONS_READ_TOKEN-}"',
            'read_token="${CONTENTS_READ_TOKEN}"',
            "unset CONTENTS_READ_TOKEN",
            "--request GET",
            '"Authorization: Bearer ${read_token}"',
            "git fetch --quiet --tags origin",
            "for _attempt in {1..30}",
            'python3 -I -B "${contract}" release-window',
            'test "${status}" -eq 3 || exit "${status}"',
            'python3 -I -B "${contract}" release-notes',
            "classify_predecessor_tag",
            "classify_predecessor_release exact",
            "classify_predecessor_release absent",
            '--source-sha "${source_sha}" \\\n'
            '    --title "Platform ${tag}" --body "${notes}" >/dev/null',
            'classify_predecessor_release exact "${base_tag}" "${base_sha}"',
            'printf \'attestation=PASS:%s:%s\\n\'',
            "unset read_token",
        )
        for token in predecessor_deletions:
            with self.subTest(predecessor_deletion=token), self.assertRaises(
                ValueError
            ):
                self.require_exact_wiring(
                    workflow,
                    jobs_verifier,
                    predecessor_wait.replace(token, "", 1),
                    settings_verifier,
                    transaction,
                )

        settings_deletions = (
            ': "${IMMUTABLE_SETTINGS_TOKEN:?IMMUTABLE_SETTINGS_TOKEN is required}"',
            'test -z "${GH_TOKEN-}"',
            'test -z "${GITHUB_TOKEN-}"',
            'test -z "${GH_ENTERPRISE_TOKEN-}"',
            'test -z "${GITHUB_ENTERPRISE_TOKEN-}"',
            'settings_token="${IMMUTABLE_SETTINGS_TOKEN}"',
            "unset IMMUTABLE_SETTINGS_TOKEN",
            "--request GET",
            '"Authorization: Bearer ${settings_token}"',
            "unset settings_token",
            "/immutable-releases",
            'python3 -I -B "${contract}" immutable-settings-receipt',
            ': "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"',
            ': "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"',
            "--run-id \"${GITHUB_RUN_ID}\"",
            "--run-attempt \"${GITHUB_RUN_ATTEMPT}\"",
            "printf 'attestation=PASS:%s:%s:%s:%s\\n'",
        )
        for token in settings_deletions:
            with self.subTest(settings_deletion=token), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    workflow,
                    jobs_verifier,
                    predecessor_wait,
                    settings_verifier.replace(token, "", 1),
                    transaction,
                )

        transaction_deletions = (
            ': "${MAIN_RUN_ID:?MAIN_RUN_ID is required}"',
            ': "${MAIN_RUN_ATTEMPT:?MAIN_RUN_ATTEMPT is required}"',
            ': "${SELECTOR_IMAGE_DIGEST:?SELECTOR_IMAGE_DIGEST is required}"',
            'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"',
            'test -z "${ACTIONS_READ_TOKEN-}"',
            'test -z "${CONTENTS_READ_TOKEN-}"',
            'write_token="${GH_TOKEN}"',
            "unset GH_TOKEN",
            'GH_TOKEN="${write_token}" gh "$@"',
            PUBLISHER_TAG_GUARD,
            "recovery_source_sha='51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e'",
            "recovery_tag='v0.1.0'",
            '-f object="${SOURCE_SHA}" -f type=commit',
            'run_write_gh release create "${recovery_tag}" --verify-tag',
            '--target "${recovery_source_sha}"',
            "identity_asset_name='platform-release-identity.v1.json'",
            "identity_bundle_name='platform-release-identity.v1.json.sigstore.json'",
            '(.assets | length == $count)',
            '(([.assets[].name] | sort) == ($expected | sort))',
            'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then',
            'test "${BASE_TAG}" = v0.1.40',
            'test "${TAG}" = v0.1.41',
            '--repository .',
            '--base-tag "${BASE_TAG}" --target-tag "${TAG}"',
            '--release-json "${release_json}"',
            '--main-runs-json "${legacy_main_runs_json}"',
            '--platform-runs-json "${legacy_platform_runs_json}"',
            '--emit > "${legacy_predecessor_json}"',
            "actions/runs/${legacy_main_run_id}/attempts/${legacy_main_run_attempt}",
            "actions/runs/${legacy_platform_run_id}/attempts/${legacy_platform_run_attempt}",
            '--main-run-json "${legacy_main_run_json}"',
            '--platform-run-json "${legacy_platform_run_json}"',
            "'{body:$body,draft:true,name:$name,prerelease:false,tag_name:$tag,target_commitish:$target}'",
            '--input "${draft_request}" --jq \'.id\')"',
            "release-draft-record",
            '--release-id "${release_id}"',
            '--main-run-id "${main_run_id}"',
            '--main-run-attempt "${main_run_attempt}"',
            '--platform-run-id "${platform_run_id}"',
            '--platform-run-attempt "${platform_run_attempt}"',
            '--selector-image-digest "${selector_digest}"',
            'cosign sign-blob --yes',
            '--bundle "${identity_bundle}" "${identity_asset}"',
            'verify_identity_signature "${identity_asset}" "${identity_bundle}"',
            '--data-binary "@${path}"',
            'upload_identity_asset "${release_id}" "${identity_asset_name}"',
            'upload_identity_asset "${release_id}" "${identity_bundle_name}"',
            'test "${status}" = 201',
            'download_identity_pair "${release_json}"',
            'cmp -s "${identity_asset}" "${identity_download}"',
            'cmp -s "${identity_bundle}" "${bundle_download}"',
            "staged-identity-release-record",
            "'{body:$body,draft:false,name:$name,prerelease:false,"
            "tag_name:$tag,target_commitish:$target}'",
            '--input "${publish_patch}"',
            "preflight_publication_state",
            "for attempt in 1 2 3 4 5",
            'test "${tag_race_verified}" = true',
            'test "${release_race_verified}" = true',
        )
        for token in transaction_deletions:
            if token in {
                '--repository .',
                '--base-tag "${BASE_TAG}" --target-tag "${TAG}"',
                '--release-json "${release_json}"',
                '--main-runs-json "${legacy_main_runs_json}"',
                '--platform-runs-json "${legacy_platform_runs_json}"',
            }:
                edge = 'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then'
                start = transaction.index(edge)
                end = transaction.index("\n  fi", start)
                changed_transaction = (
                    transaction[:start]
                    + transaction[start:end].replace(token, "")
                    + transaction[end:]
                )
            elif token in {
                '--main-run-json "${legacy_main_run_json}"',
                '--platform-run-json "${legacy_platform_run_json}"',
            }:
                before, after = transaction.rsplit(token, 1)
                changed_transaction = before + after
            else:
                changed_transaction = transaction.replace(token, "", 1)
            with self.subTest(transaction_deletion=token), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    workflow,
                    jobs_verifier,
                    predecessor_wait,
                    settings_verifier,
                    changed_transaction,
                )

        workflow_mutants = (
            workflow.replace("permission-administration: read", "permission-administration: write", 1),
            workflow.replace("repositories: website-infrastructure", "repositories: other-repository", 1),
            workflow.replace("deployment: false", "deployment: true", 1),
            workflow.replace(
                "outputs:\n      attestation: ${{ steps.immutable-settings.outputs.attestation }}",
                "outputs:\n      token: ${{ steps.immutable-settings-token.outputs.token }}",
                1,
            ),
            workflow.replace(
                "  publish:\n",
                "  publish:\n    environment: platform-release\n",
                1,
            ),
            workflow.replace(
                "  publish:\n",
                "  publish:\n    env:\n      IMMUTABLE_SETTINGS_TOKEN: crossed\n",
                1,
            ),
            workflow.replace("actions: read", "actions: write", 1),
            workflow.replace(
                "outputs:\n      attestation: ${{ steps.required-jobs.outputs.attestation }}",
                "outputs:\n      token: ${{ secrets.GITHUB_TOKEN }}",
                1,
            ),
            workflow.replace(
                "  main-ci-jobs:\n",
                "  main-ci-jobs:\n    environment: platform-release\n",
                1,
            ),
            workflow.replace(
                "  publish:\n",
                "  publish:\n    env:\n      ACTIONS_READ_TOKEN: crossed\n",
                1,
            ),
            workflow.replace(
                "bash scripts/ci/wait-platform-release-predecessor.sh",
                "__WAIT_FOR_PREDECESSOR__",
                1,
            ).replace(
                "bash scripts/ci/verify-platform-release-settings.sh",
                "bash scripts/ci/wait-platform-release-predecessor.sh",
                1,
            ).replace(
                "__WAIT_FOR_PREDECESSOR__",
                "bash scripts/ci/verify-platform-release-settings.sh",
                1,
            ),
            workflow.replace(
                'current_identity="${RUNNER_TEMP}/current-platform-release-identity.json"',
                '.body\n          current_identity="${RUNNER_TEMP}/current-platform-release-identity.json"',
                1,
            ),
            workflow.replace(
                "Authorization: Bearer ${GH_TOKEN}",
                "Authorization: crossed",
            ),
            workflow + "\nselector-seed=retired\n",
        )
        for index, mutant in enumerate(workflow_mutants):
            with self.subTest(workflow_mutant=index), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    mutant,
                    jobs_verifier,
                    predecessor_wait,
                    settings_verifier,
                    transaction,
                )

        transaction_mutants = (
            transaction.replace(
                'GH_TOKEN="${write_token}" gh "$@"',
                'GH_TOKEN="${settings_token}" gh "$@"',
                1,
            ),
            transaction.replace(
                'run_write_gh release create "${recovery_tag}" --verify-tag',
                'gh release create "${recovery_tag}" --verify-tag',
                1,
            ),
            transaction.replace(
                '--target "${recovery_source_sha}"',
                '--target "${SOURCE_SHA}"',
                1,
            ),
            transaction.replace(
                "draft:true,name:$name,prerelease:false",
                "draft:false,name:$name,prerelease:false",
                1,
            ),
            transaction.replace(
                '(.assets | length == $count)',
                '(.assets | length > 0)',
                1,
            ),
            transaction.replace(
                'if [ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]; then',
                'if [ "${BASE_TAG}" != v0.1.31 ] || [ "${TAG}" != v0.1.41 ]; then',
                1,
            ),
            transaction.replace("identity-release-state", "release-state", 1),
            transaction + '\nupload_identity_asset "${release_id}" "${identity_asset_name}"\n',
            transaction.replace(
                PUBLISHER_TAG_GUARD, 'test "${TAG}" = "v0.1.29"', 1
            ),
            transaction + '\nrun_write_gh release create "${TAG}" --verify-tag\n',
            transaction + "\nreleasecutover=retired\n",
        )
        for index, mutant in enumerate(transaction_mutants):
            with self.subTest(transaction_mutant=index), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    workflow,
                    jobs_verifier,
                    predecessor_wait,
                    settings_verifier,
                    mutant,
                )
        with self.assertRaises(ValueError):
            self.require_exact_wiring(
                workflow.replace("cancel-in-progress: false", "cancel-in-progress: true", 1),
                jobs_verifier,
                predecessor_wait,
                settings_verifier,
                transaction,
            )
        with self.assertRaises(ValueError):
            self.require_exact_wiring(
                workflow,
                jobs_verifier,
                predecessor_wait,
                settings_verifier,
                transaction + '\ngit rev-list -n 1 "${TAG}"\n',
            )
        for forbidden in ("kubectl", "flux", "tofu apply", "terraform apply", "cloudflared"):
            self.assertNotIn(
                forbidden,
                (
                    workflow
                    + jobs_verifier
                    + predecessor_wait
                    + settings_verifier
                    + transaction
                ).lower(),
            )


if __name__ == "__main__":
    unittest.main()
