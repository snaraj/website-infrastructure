"""Hostile tests for the per-main-merge platform release contract."""

from __future__ import annotations

import contextlib
import concurrent.futures
import copy
import importlib.util
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

# The publisher binds the tag it publishes to the version the checked-out
# source declares, never to a frozen literal. Several independent gates below
# pin this exact line, so it is spelled once here and they cannot drift apart.
PUBLISHER_TAG_GUARD = "test \"${TAG}\" = \"v$(tr -d '[:space:][:cntrl:]' < VERSION)\""


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
        "total_count": 1,
        "jobs": [
            {
                "id": 6001,
                "name": "analyze (python, none)",
                "run_id": 5001,
                "run_attempt": 1,
                "head_sha": "a" * 40,
                "head_branch": "main",
                "workflow_name": "CodeQL",
                "status": "completed",
                "conclusion": "success",
                "steps": [
                    {"name": name, "conclusion": conclusion}
                    for name, conclusion in MODULE.CODEQL_EXACT_STEPS
                ],
            }
        ],
    }


def settings_api() -> dict[str, object]:
    ruleset_id = 42
    tag_ruleset_id = 43
    checks = [
        {"context": context, "integration_id": 15368}
        for context in MODULE.REQUIRED_CHECKS
    ]
    return {
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
            exact, tag=self.TAG, title=self.TITLE, body=self.BODY.rstrip()
        )
        for key, value in (
            ("tag_name", "v0.1.1"),
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
                    changed, tag=self.TAG, title=self.TITLE, body=self.BODY
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
                    404, None, tag=self.TAG, title=self.TITLE, body=self.BODY
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
                    status, None, tag=self.TAG, title=self.TITLE, body=self.BODY
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
                "--title",
                self.TITLE,
                "--body",
                str(notes),
            ]
            self.assertEqual(invoke([*release_args, "--require", "absent"]), 0)
            self.assertEqual(invoke([*release_args, "--require", "exact"]), 1)

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
            self.assertEqual(
                invoke(
                    [
                        "release-record",
                        "--release-json",
                        str(release_path),
                        "--tag",
                        self.TAG,
                        "--title",
                        self.TITLE,
                        "--body",
                        str(notes),
                    ]
                ),
                0,
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
        queued = codeql_jobs_record()
        queued["jobs"][0]["status"] = "in_progress"
        queued["jobs"][0]["conclusion"] = None
        self.assertFalse(
            MODULE.codeql_jobs_ready(
                queued, run_id=5001, run_attempt=1, source_sha=self.SOURCE
            )
        )
        for pending in (absent, queued):
            with self.subTest(codeql_pending=pending), self.assertRaises(
                MODULE.ContractError
            ):
                self.build(main_ci_jobs_record(), codeql_jobs=pending)

        exact = codeql_jobs_record()
        mutations: list[dict[str, object]] = []
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
            changed["jobs"][0][field] = value
            if field == "status" and value == "completed":
                changed["jobs"][0]["conclusion"] = "cancelled"
            mutations.append(changed)
        for expected_name, expected_conclusion in MODULE.CODEQL_EXACT_STEPS:
            for conclusion in (None, "success", "skipped", "cancelled", "failure"):
                if conclusion == expected_conclusion:
                    continue
                changed = copy.deepcopy(exact)
                if conclusion is None:
                    changed["jobs"][0]["steps"] = [
                        step
                        for step in changed["jobs"][0]["steps"]
                        if step["name"] != expected_name
                    ]
                else:
                    step = next(
                        value
                        for value in changed["jobs"][0]["steps"]
                        if value["name"] == expected_name
                    )
                    step["conclusion"] = conclusion
                mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["total_count"] = 2
        changed["jobs"].append(copy.deepcopy(changed["jobs"][0]))
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
    # The publisher accepts only the tag the checked-out VERSION declares, and
    # this harness executes it from the repository root, so the fixture tag is
    # derived the same way. A literal here would go stale every patch exactly
    # as the script constant it replaces did.
    TAG = f"v{(ROOT / 'VERSION').read_text(encoding='utf-8').strip()}"
    SOURCE = "a" * 40
    RECOVERY_TAG = MODULE.RECOVERY_TAG
    RECOVERY_SOURCE = MODULE.RECOVERY_SOURCE_SHA
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
    def notes(tag: str, source: str) -> str:
        return (
            f"## Platform {tag}\n\n"
            f"Immutable repository source: `{source}`\n\n"
            "This release names platform source only. It does not deploy, promote, "
            "mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n"
            "See `CHANGELOG.md` at this tag for the human-readable change record.\n"
        )

    def exact_records(
        self, tag_name: str, source: str, tag_object: str
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        ref, tag = exact_tag_records(
            tag_name,
            source,
            f"Platform release {tag_name} from {source}",
            self.DATE,
        )
        ref["object"]["sha"] = tag_object
        tag["sha"] = tag_object
        release = {
            "tag_name": tag_name,
            "name": f"Platform {tag_name}",
            "body": self.notes(tag_name, source),
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "author": {"login": "github-actions[bot]", "id": 41898282},
            "assets": [],
        }
        return ref, tag, release

    def execute(
        self,
        script: str,
        *,
        race: bool = False,
        current_state: str = "missing",
        immutable: bool = True,
        drift_before_release: bool = False,
        drift_during_release: bool = False,
        current_release_race: bool = False,
        settings_fail_call: int = 0,
        settings_env: str | None = None,
        actions_env: str | None = None,
        write_env: str | None = "write-token",
        recovery_state: str = "tag",
        event_tag: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str, dict[str, object]]:
        with tempfile.TemporaryDirectory(
            dir=ROOT, prefix=".platform-release-shell-"
        ) as temporary:
            runner = Path(temporary)
            transaction_path = runner / "transaction.sh"
            with transaction_path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(script)
            state_root = runner / "state"
            state_root.mkdir()
            if recovery_state not in {"missing", "tag", "complete", "foreign"}:
                raise AssertionError("recovery fixture state is not closed")
            if recovery_state != "missing":
                ref, tag, release = self.exact_records(
                    self.RECOVERY_TAG, self.RECOVERY_SOURCE, "b" * 40
                )
                if recovery_state == "foreign":
                    tag["object"]["sha"] = "0" * 40
                (state_root / f"ref-{self.RECOVERY_TAG}.json").write_text(
                    json.dumps(ref), encoding="utf-8"
                )
                (state_root / f"tag-{'b' * 40}.json").write_text(
                    json.dumps(tag), encoding="utf-8"
                )
                if recovery_state == "complete":
                    (state_root / f"release-{self.RECOVERY_TAG}.json").write_text(
                        json.dumps(release), encoding="utf-8"
                    )
            if current_state not in {
                "missing",
                "tag",
                "complete",
                "foreign-tag",
                "release-only",
                "foreign-release",
                "partial-release",
            }:
                raise AssertionError("current fixture state is not closed")
            if current_state != "missing":
                ref, tag, release = self.exact_records(
                    self.TAG, self.SOURCE, "c" * 40
                )
                if current_state == "foreign-tag":
                    tag["object"]["sha"] = "0" * 40
                if current_state != "release-only":
                    (state_root / f"ref-{self.TAG}.json").write_text(
                        json.dumps(ref), encoding="utf-8"
                    )
                    (state_root / f"tag-{'c' * 40}.json").write_text(
                        json.dumps(tag), encoding="utf-8"
                    )
                if current_state in {
                    "complete",
                    "release-only",
                    "foreign-release",
                    "partial-release",
                }:
                    if current_state == "foreign-release":
                        release["author"] = {"login": "owner", "id": 1}
                    if current_state == "partial-release":
                        release["immutable"] = False
                    (state_root / f"release-{self.TAG}.json").write_text(
                        json.dumps(release), encoding="utf-8"
                    )
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

git() {
  if [ "$1" = show ]; then
    printf '%s\n' "${MOCK_DATE}"
  else
    command git "$@"
  fi
}

jq() {
  test "$1" = -er
  test "$2" = '.object.sha'
  "${TEST_PYTHON}" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["object"]["sha"])' "$3"
}

curl() {
  local output='' url='' authorization='' token='' tag='' object_sha='' path=''
  if [ -n "${GH_TOKEN-}" ] || [ -n "${IMMUTABLE_SETTINGS_TOKEN-}" ] || \
     [ -n "${ACTIONS_READ_TOKEN-}" ]; then
    return 93
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
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
  token="${authorization#Authorization: Bearer }"
  case "${url}" in
    */immutable-releases)
      if [ "${token}" != "${MOCK_SETTINGS_TOKEN}" ]; then
        printf '{}' > "${output}"
        printf '403'
        return 0
      fi
      settings_count=0
      if [ -f "${MOCK_SETTINGS_COUNT}" ]; then
        settings_count="$(<"${MOCK_SETTINGS_COUNT}")"
      fi
      settings_count=$((settings_count + 1))
      printf '%s' "${settings_count}" > "${MOCK_SETTINGS_COUNT}"
      if [ "${MOCK_SETTINGS_FAIL_CALL}" -eq "${settings_count}" ]; then
        printf '{}' > "${output}"
        printf '403'
        return 0
      fi
      printf '{"enabled":%s,"enforced_by_owner":false}' "${MOCK_IMMUTABLE}" > "${output}"
      printf '200'
      ;;
    */git/ref/tags/*)
      if [ "${token}" != "${MOCK_WRITE_TOKEN}" ]; then
        printf '{}' > "${output}"; printf '403'; return 0
      fi
      tag="${url##*/}"
      path="${MOCK_STATE}/ref-${tag}.json"
      if [ -f "${path}" ]; then cp "${path}" "${output}"; printf '200';
      else printf '{}' > "${output}"; printf '404'; fi
      if [ "${tag}" = "${MOCK_CURRENT_TAG}" ] && \
         [ "${MOCK_CURRENT_RELEASE_RACE}" = true ]; then
        current_ref_reads=0
        if [ -f "${MOCK_CURRENT_REF_READS}" ]; then
          current_ref_reads="$(<"${MOCK_CURRENT_REF_READS}")"
        fi
        current_ref_reads=$((current_ref_reads + 1))
        printf '%s' "${current_ref_reads}" > "${MOCK_CURRENT_REF_READS}"
        if [ "${current_ref_reads}" -eq 3 ]; then
          printf '{"tag_name":"%s"}' "${tag}" > \
            "${MOCK_STATE}/release-${tag}.json"
        fi
      fi
      ;;
    */git/tags/*)
      if [ "${token}" != "${MOCK_WRITE_TOKEN}" ]; then
        printf '{}' > "${output}"; printf '403'; return 0
      fi
      object_sha="${url##*/}"
      path="${MOCK_STATE}/tag-${object_sha}.json"
      if [ -f "${path}" ]; then cp "${path}" "${output}"; printf '200';
      else printf '{}' > "${output}"; printf '404'; fi
      ;;
    */releases/tags/*)
      if [ "${token}" != "${MOCK_WRITE_TOKEN}" ]; then
        printf '{}' > "${output}"; printf '403'; return 0
      fi
      tag="${url##*/}"
      path="${MOCK_STATE}/release-${tag}.json"
      if [ -f "${path}" ]; then cp "${path}" "${output}"; printf '200';
      else
        if [ "${MOCK_DRIFT_BEFORE_RELEASE}" = true ] && [ ! -f "${MOCK_DRIFT_MARKER}" ]; then
          object_sha="$("${TEST_PYTHON}" -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["object"]["sha"])' "${MOCK_STATE}/ref-${tag}.json")"
          "${TEST_PYTHON}" -c 'import json,sys; p=sys.argv[1]; v=json.load(open(p,encoding="utf-8")); v["object"]["sha"]="0"*40; json.dump(v,open(p,"w",encoding="utf-8")); open(sys.argv[2],"w").close()' \
            "${MOCK_STATE}/tag-${object_sha}.json" "${MOCK_DRIFT_MARKER}"
        fi
        printf '{}' > "${output}"; printf '404'
      fi
      ;;
    *) return 2 ;;
  esac
}

gh() {
  if [ "${GH_TOKEN}" != "${MOCK_WRITE_TOKEN}" ] || \
    [ -n "${IMMUTABLE_SETTINGS_TOKEN-}" ] || \
    [ -n "${ACTIONS_READ_TOKEN-}" ]; then
    return 91
  fi
  printf 'CALL\n' >> "${MOCK_CALLS}"
  printf '<%s>\n' "$@" >> "${MOCK_CALLS}"
  if [ "$1" = api ]; then
    local endpoint='' arg tag='' message='' object='' type='' tag_object=''
    local tagger_name='' tagger_email='' tagger_date='' ref='' sha=''
    for arg in "$@"; do
      case "${arg}" in
        repos/*) endpoint="${arg}" ;;
        tag=*) tag="${arg#*=}" ;;
        message=*) message="${arg#*=}" ;;
        object=*) object="${arg#*=}" ;;
        type=*) type="${arg#*=}" ;;
        tagger\[name\]=*) tagger_name="${arg#*=}" ;;
        tagger\[email\]=*) tagger_email="${arg#*=}" ;;
        tagger\[date\]=*) tagger_date="${arg#*=}" ;;
        ref=*) ref="${arg#*=}" ;;
        sha=*) sha="${arg#*=}" ;;
      esac
    done
    case "${endpoint}" in
      */git/tags)
        if [ -z "${tag}" ] || [ -z "${message}" ] || [ -z "${object}" ] || \
          [ "${type}" != commit ] || [ -z "${tagger_name}" ] || \
          [ -z "${tagger_email}" ] || [ -z "${tagger_date}" ]; then
          return 2
        fi
        tag_object="$("${TEST_PYTHON}" -c 'import hashlib,sys; print(hashlib.sha1(sys.argv[1].encode()).hexdigest())' "${tag}")"
        "${TEST_PYTHON}" -c 'import json,sys; json.dump({"sha":sys.argv[2],"tag":sys.argv[3],"message":sys.argv[4],"object":{"type":"commit","sha":sys.argv[5]},"tagger":{"name":sys.argv[6],"email":sys.argv[7],"date":sys.argv[8]}},open(sys.argv[1],"w",encoding="utf-8"))' \
          "${MOCK_STATE}/tag-${tag_object}.json" "${tag_object}" "${tag}" "${message}" "${object}" \
          "${tagger_name}" "${tagger_email}" "${tagger_date}"
        printf '%s\n' "${tag_object}"
        ;;
      */git/refs)
        if [[ "${ref}" != refs/tags/* ]] || \
          [ ! -f "${MOCK_STATE}/tag-${sha}.json" ]; then
          return 2
        fi
        "${TEST_PYTHON}" -c 'import json,sys; json.dump({"ref":sys.argv[2],"object":{"type":"tag","sha":sys.argv[3]}},open(sys.argv[1],"w",encoding="utf-8"))' \
          "${MOCK_STATE}/ref-${ref#refs/tags/}.json" "${ref}" "${sha}"
        if [ "${MOCK_RACE}" = true ]; then return 1; fi
        ;;
      *) return 2 ;;
    esac
    return 0
  fi
  if [ "$1" = release ] && [ "$2" = create ]; then
    local release_tag="$3" tag_verified='' draft=false prerelease=false title='' notes='' object_sha=''
    shift 3
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --verify-tag) tag_verified=true; shift ;;
        --draft) draft=true; shift ;;
        --prerelease) prerelease=true; shift ;;
        --title) title="$2"; shift 2 ;;
        --notes-file) notes="$2"; shift 2 ;;
        *) return 2 ;;
      esac
    done
    if [ "${tag_verified}" != true ] || [ -z "${title}" ] || [ ! -f "${notes}" ]; then
      return 2
    fi
    "${TEST_PYTHON}" -c 'import json,sys; json.dump({"tag_name":sys.argv[2],"name":sys.argv[3],"body":open(sys.argv[4],encoding="utf-8").read(),"draft":sys.argv[5]=="true","prerelease":sys.argv[6]=="true","immutable":sys.argv[7]=="true","author":{"login":"github-actions[bot]","id":41898282},"assets":[]},open(sys.argv[1],"w",encoding="utf-8"))' \
      "${MOCK_STATE}/release-${release_tag}.json" "${release_tag}" "${title}" "${notes}" "${draft}" "${prerelease}" "${MOCK_IMMUTABLE}"
    if [ "${MOCK_DRIFT_DURING_RELEASE}" = true ]; then
      object_sha="$("${TEST_PYTHON}" -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["object"]["sha"])' "${MOCK_STATE}/ref-${release_tag}.json")"
      "${TEST_PYTHON}" -c 'import json,sys; p=sys.argv[1]; v=json.load(open(p,encoding="utf-8")); v["object"]["sha"]="0"*40; json.dump(v,open(p,"w",encoding="utf-8"))' \
        "${MOCK_STATE}/tag-${object_sha}.json"
    fi
    if [ "${MOCK_RACE}" = true ]; then return 1; fi
    return 0
  fi
  return 2
}

sleep() { :; }
'''
            relative = runner.relative_to(ROOT).as_posix()
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": self.bash_path(sys.executable),
                    "MOCK_DATE": self.DATE,
                    "MOCK_IMMUTABLE": "true" if immutable else "false",
                    "MOCK_RACE": "true" if race else "false",
                    "MOCK_DRIFT_BEFORE_RELEASE": "true" if drift_before_release else "false",
                    "MOCK_DRIFT_DURING_RELEASE": "true" if drift_during_release else "false",
                    "MOCK_CURRENT_RELEASE_RACE": "true" if current_release_race else "false",
                    "MOCK_CURRENT_TAG": self.TAG,
                    "MOCK_CURRENT_REF_READS": f"{relative}/current-ref-reads",
                    "MOCK_DRIFT_MARKER": f"{relative}/drift.marker",
                    "MOCK_SETTINGS_FAIL_CALL": str(settings_fail_call),
                    "MOCK_SETTINGS_COUNT": f"{relative}/settings-count",
                    "MOCK_SETTINGS_TOKEN": "settings-token",
                    "MOCK_WRITE_TOKEN": "write-token",
                    "MOCK_STATE": f"{relative}/state",
                    "MOCK_CALLS": f"{relative}/calls.log",
                    "MOCK_SCRIPT": f"{relative}/transaction.sh",
                    "SOURCE_SHA": self.SOURCE,
                    "TAG": event_tag if event_tag is not None else self.TAG,
                    "GITHUB_API_URL": "https://api.github.test",
                    "GITHUB_REPOSITORY": "owner/platform",
                    "RUNNER_TEMP": relative,
                }
            )
            if settings_env is None:
                environment.pop("IMMUTABLE_SETTINGS_TOKEN", None)
            else:
                environment["IMMUTABLE_SETTINGS_TOKEN"] = settings_env
            if actions_env is None:
                environment.pop("ACTIONS_READ_TOKEN", None)
            else:
                environment["ACTIONS_READ_TOKEN"] = actions_env
            if write_env is None:
                environment.pop("GH_TOKEN", None)
            else:
                environment["GH_TOKEN"] = write_env
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
            calls = (
                (runner / "calls.log").read_text(encoding="utf-8")
                if (runner / "calls.log").exists()
                else ""
            )
            state: dict[str, object] = {}
            for ref_path in state_root.glob("ref-*.json"):
                ref = json.loads(ref_path.read_text(encoding="utf-8"))
                tag_ref = ref["ref"]
                tag_name = tag_ref[len("refs/tags/") :]
                object_sha = ref["object"]["sha"]
                record: dict[str, object] = {"ref": ref}
                tag_path = state_root / f"tag-{object_sha}.json"
                release_path = state_root / f"release-{tag_name}.json"
                if tag_path.exists():
                    record["tag"] = json.loads(tag_path.read_text(encoding="utf-8"))
                if release_path.exists():
                    record["release"] = json.loads(
                        release_path.read_text(encoding="utf-8")
                    )
                state[tag_name] = record
            return completed, calls, state

    def test_actual_absent_existing_and_both_concurrent_winner_paths(self):
        script = self.script()
        for race in (False, True):
            with self.subTest(race=race):
                completed, calls, state = self.execute(script, race=race)
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                self.assertIn(f"<object={self.SOURCE}>", calls)
                self.assertIn(f"<{self.TAG}>", calls)
                self.assertIn("<--verify-tag>", calls)
                self.assertNotIn("<--draft>", calls)
                self.assertNotIn("<--prerelease>", calls)
                self.assertEqual(
                    state[self.TAG]["tag"]["object"]["sha"], self.SOURCE
                )
                self.assertEqual(state[self.TAG]["release"]["draft"], False)
                self.assertEqual(state[self.TAG]["release"]["prerelease"], False)
                self.assertEqual(state[self.TAG]["release"]["immutable"], True)
                self.assertEqual(
                    state[self.RECOVERY_TAG]["release"]["author"]["login"],
                    "github-actions[bot]",
                )
                self.assertLess(
                    calls.index(f"<{self.RECOVERY_TAG}>"),
                    calls.index(f"<object={self.SOURCE}>")
                )
                if race:
                    self.assertIn("exact concurrent winner", completed.stderr)

        existing, calls, _state = self.execute(
            script, current_state="complete", recovery_state="complete"
        )
        self.assertEqual(existing.returncode, 0, existing.stdout + existing.stderr)
        self.assertEqual(calls, "")
        self.assertIn("verified existing", existing.stdout)
        self.assertIn("verified complete existing", existing.stdout)

        resumable, calls, state = self.execute(
            script, current_state="tag", recovery_state="complete"
        )
        self.assertEqual(resumable.returncode, 0, resumable.stdout + resumable.stderr)
        self.assertNotIn(f"<object={self.SOURCE}>", calls)
        self.assertEqual(calls.count("CALL\n"), 1)
        self.assertIn(f"<{self.TAG}>", calls)
        self.assertEqual(state[self.TAG]["release"]["immutable"], True)

    def test_app_token_crossover_denies_before_any_publication_call(self):
        script = self.script()
        completed, calls, state = self.execute(
            script, settings_env="settings-token"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(calls, "")
        self.assertNotIn(self.TAG, state)
        self.assertNotIn("release", state[self.RECOVERY_TAG])
        guard = 'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"'
        self.assertIn(guard, script)
        deleted_guard, mutant_calls, _state = self.execute(
            script.replace(guard, ":", 1), settings_env="settings-token"
        )
        self.assertNotEqual(deleted_guard.returncode, 0)
        self.assertEqual(mutant_calls, "")

    def test_actions_token_crossover_denies_before_any_publication_call(self):
        script = self.script()
        completed, calls, state = self.execute(
            script, actions_env="actions-token"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(calls, "")
        self.assertNotIn(self.TAG, state)
        self.assertNotIn("release", state[self.RECOVERY_TAG])
        guard = 'test -z "${ACTIONS_READ_TOKEN-}"'
        self.assertIn(guard, script)
        deleted_guard, mutant_calls, _state = self.execute(
            script.replace(guard, ":", 1), actions_env="actions-token"
        )
        self.assertNotEqual(deleted_guard.returncode, 0)
        self.assertEqual(mutant_calls, "")

    def test_missing_or_foreign_recovery_tag_denies_before_every_write(self):
        script = self.script()
        for recovery_state in ("missing", "foreign"):
            with self.subTest(recovery_state=recovery_state):
                completed, calls, state = self.execute(
                    script, recovery_state=recovery_state
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(calls, "")
                self.assertNotIn(self.TAG, state)

    def test_foreign_partial_current_states_and_races_deny_before_every_write(self):
        script = self.script()
        for current_state in (
            "foreign-tag",
            "release-only",
            "foreign-release",
            "partial-release",
        ):
            with self.subTest(current_state=current_state):
                completed, calls, state = self.execute(
                    script, current_state=current_state
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(calls, "")
                self.assertNotIn("release", state[self.RECOVERY_TAG])

        race_cases = (
            {"current_state": "tag", "drift_before_release": True},
            {"current_state": "missing", "current_release_race": True},
        )
        for race_case in race_cases:
            with self.subTest(race_case=race_case):
                completed, calls, _state = self.execute(
                    script, recovery_state="complete", **race_case
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(calls, "")

    def test_event_tag_that_is_not_the_checked_out_version_is_refused(self):
        version = MODULE.Version.parse((ROOT / "VERSION").read_text(encoding="utf-8"))
        # An event tag ahead of the source, the stranded era constant, and a
        # plainly foreign tag must all deny before any write. Each candidate is
        # asserted distinct from the derived tag, so this can never pass by
        # accidentally naming the version the publisher would rightly accept.
        for event_tag in (MODULE.next_version(version).tag, "v0.1.1", "v9.9.9"):
            with self.subTest(event_tag=event_tag):
                self.assertNotEqual(event_tag, self.TAG)
                completed, calls, state = self.execute(
                    self.script(), event_tag=event_tag
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(calls, "")
                self.assertNotIn(event_tag, state)

    def test_publisher_derives_the_tag_and_pins_no_current_version_literal(self):
        script = self.script()
        # Run 32174376337 (the #123 merge, TAG=v0.1.2) died on this guard:
        # `current_tag='v0.1.1'`, written for the #122 recovery era, made the
        # publisher structurally unable to publish any later patch, and no gate
        # bound that constant to VERSION — so the first post-era advance
        # stranded publication in silence. The recovery pins stay frozen
        # because they name immutable history; nothing else may name a version.
        self.assertIn(PUBLISHER_TAG_GUARD, script)
        self.assertNotIn("current_tag=", script)
        self.assertIn(f"recovery_tag='{self.RECOVERY_TAG}'", script)
        self.assertIn(f"recovery_source_sha='{self.RECOVERY_SOURCE}'", script)
        self.assertEqual(
            set(re.findall(r"v[0-9]+\.[0-9]+\.[0-9]+", script)),
            {self.RECOVERY_TAG},
        )

        # Executable proof, not merely textual: a publisher frozen to any one
        # patch refuses the tag its own checked-out source declares, and does
        # it with no output at all — the exact signature of the failed run.
        stranded = script.replace(
            PUBLISHER_TAG_GUARD, "test \"${TAG}\" = 'v0.1.1'", 1
        )
        self.assertNotIn(PUBLISHER_TAG_GUARD, stranded)
        completed, calls, state = self.execute(stranded, recovery_state="complete")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(calls, "")
        self.assertNotIn(self.TAG, state)
        self.assertEqual(completed.stdout + completed.stderr, "")

    def test_write_credential_is_process_scoped_and_fails_closed(self):
        script = self.script()
        for write_env in (None, "settings-token"):
            completed, calls, _state = self.execute(
                script, write_env=write_env
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(calls, "")
        for required in (
            'write_token="${GH_TOKEN}"',
            "unset GH_TOKEN",
            'GH_TOKEN="${write_token}" gh "$@"',
        ):
            self.assertIn(required, script)
        self.assertNotIn("settings_token", script)

    def test_current_source_creation_and_publication_mutants_are_killed(self):
        script = self.script()
        source = '-f object="${SOURCE_SHA}" -f type=commit \\\n'
        release = 'run_write_gh release create "${TAG}" --verify-tag \\\n'
        verify = '"${TAG}" --verify-tag \\\n'
        markers = (source, release, verify)
        for marker in markers:
            self.assertIn(marker, script)
        mutants = (
            script.replace(
                source,
                '-f object="0000000000000000000000000000000000000000" -f type=commit \\\n',
                1,
            ),
            script.replace(source, "", 1),
            script.replace("-f type=commit", "-f type=tree", 1),
            script.replace(
                release,
                'run_write_gh release create "${TAG}" --verify-tag --draft \\\n',
                1,
            ),
            script.replace(
                release,
                'run_write_gh release create "${TAG}" --verify-tag --prerelease \\\n',
                1,
            ),
            script.replace(verify, '"${TAG}" \\\n', 1),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(transaction_mutant=index):
                completed, _calls, _state = self.execute(
                    mutant, recovery_state="complete"
                )
                self.assertNotEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )


class GitTransitionTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def commit(self, root: Path, version: str | None, marker: str) -> str:
        if version is not None:
            (root / "VERSION").write_text(version + "\n", encoding="utf-8")
            (root / "CHANGELOG.md").write_text(
                f"# Changelog\n\n## [Unreleased]\n\n## [{version}] - 2026-08-13\n\n- release\n",
                encoding="utf-8",
            )
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
        ):
            self.git(root, "config", "--local", key, value)
        self.git(root, "branch", "-m", "main")
        return self.commit(root, None, "initial")

    def remove_version(self, root: Path, marker: str) -> str:
        for name in ("VERSION", "CHANGELOG.md"):
            (root / name).unlink()
        return self.commit(root, None, marker)

    def assert_fixture_git_is_quiescent(self, root: Path) -> None:
        expected = {
            "maintenance.auto": "false",
            "maintenance.autoDetach": "false",
            "gc.auto": "0",
            "gc.autoDetach": "false",
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
                head = self.commit(
                    root,
                    "0.1.0",
                    f"concurrent release {round_index}-{worker_index}",
                )
                intent = MODULE.validate_transition(
                    root, initial, head, first_parent=True
                )
                self.assertEqual(intent, MODULE.Intent(head, MODULE.Version(0, 1, 0)))
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

    def test_initial_rapid_and_out_of_order_patch_releases_are_unique(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = self.initialize(root)
            commits = [initial]
            for version in ("0.1.0", "0.1.1", "0.1.2"):
                commits.append(self.commit(root, version, version))
            intents = [
                MODULE.validate_transition(
                    root, commits[index - 1], commits[index], first_parent=True
                )
                for index in range(1, len(commits))
            ]
            self.assertEqual(
                [intent.tag for intent in (intents[2], intents[0], intents[1])],
                ["v0.1.2", "v0.1.0", "v0.1.1"],
            )
            self.assertEqual(len({intent.source_sha for intent in intents}), 3)
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, commits[1], commits[3], first_parent=True)
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, commits[2], commits[1], first_parent=True)

    def test_squash_and_arbitrary_position_rebase_ranges_release_final_sha_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = self.initialize(root)
            pre_bump = self.commit(root, None, "rebased content before bump")
            bump = self.commit(root, "0.1.0", "rebased bump")
            final_head = self.commit(root, None, "rebased content after bump")
            intent = MODULE.validate_transition(
                root, initial, final_head, first_parent=True
            )
            self.assertEqual(intent, MODULE.Intent(final_head, MODULE.Version(0, 1, 0)))
            window = MODULE.discover_transition_window(root, final_head)
            self.assertEqual(window.base_sha, pre_bump)
            self.assertEqual(window.intent, intent)
            self.assertNotEqual(bump, final_head)

            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = MODULE.main(
                    [
                        "release-window",
                        "--repository",
                        str(root),
                        "--head",
                        final_head,
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["source_sha"], final_head)

            self.git(root, "checkout", "-q", "-b", "double-bump", initial)
            self.commit(root, "0.1.0", "first bump")
            double_head = self.commit(root, "0.1.1", "second bump")
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, initial, double_head, first_parent=True)

    def test_squash_and_every_rebase_bump_position_share_window_semantics(self):
        for before, after in ((0, 0), (0, 2), (2, 0), (2, 2)):
            with self.subTest(before=before, after=after), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                initial = self.initialize(root)
                for index in range(before):
                    self.commit(root, None, f"content before {index}")
                boundary_parent = self.git(root, "rev-parse", "HEAD")
                self.commit(root, "0.1.0", "exact patch boundary")
                for index in range(after):
                    self.commit(root, None, f"content after {index}")
                head = self.git(root, "rev-parse", "HEAD")
                for first_parent in (False, True):
                    self.assertEqual(
                        MODULE.validate_transition(
                            root, initial, head, first_parent=first_parent
                        ),
                        MODULE.Intent(head, MODULE.Version(0, 1, 0)),
                    )
                window = MODULE.discover_transition_window(root, head)
                self.assertEqual(window.base_sha, boundary_parent)
                self.assertEqual(window.intent.source_sha, head)
                self.assertEqual(window.intent.tag, "v0.1.0")

    def test_skip_and_reversion_histories_fail_main_pr_and_window_together(self):
        builders = (
            lambda root: (
                self.commit(root, "0.1.1", "skip transient required patch"),
                self.commit(root, "0.1.0", "revert skip to final endpoint"),
            )[-1],
            lambda root: (
                self.commit(root, "0.1.0", "premature required patch"),
                self.remove_version(root, "revert VERSION and changelog"),
                self.commit(root, "0.1.0", "reintroduce endpoint patch"),
            )[-1],
        )
        for index, build in enumerate(builders):
            with self.subTest(history_mutant=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                initial = self.initialize(root)
                head = build(root)
                for first_parent in (False, True):
                    with self.assertRaises(MODULE.ContractError):
                        MODULE.validate_transition(
                            root, initial, head, first_parent=first_parent
                        )
                with self.assertRaises(MODULE.ContractError):
                    MODULE.discover_transition_window(root, head)

    def test_clean_range_on_poisoned_prefix_cannot_pass_main_before_publisher_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.initialize(root)
            self.commit(root, "0.1.0", "historical premature patch")
            base = self.remove_version(root, "historical VERSION reversion")
            head = self.commit(root, "0.1.0", "locally clean endpoint patch")
            for first_parent in (False, True):
                with self.assertRaises(MODULE.ContractError):
                    MODULE.validate_transition(
                        root, base, head, first_parent=first_parent
                    )
            with self.assertRaises(MODULE.ContractError):
                MODULE.discover_transition_window(root, head)

    def test_pr_and_main_reject_merge_ranges_that_cannot_guarantee_rebase_liveness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = self.initialize(root)
            base = self.commit(root, "0.1.0", "base")
            self.git(root, "checkout", "-q", "-b", "topic", base)
            self.commit(root, None, "topic content")
            self.git(root, "checkout", "-q", "-b", "side", base)
            self.commit(root, None, "side content")
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
            head = self.commit(root, "0.1.1", "final bump")
            for first_parent in (False, True):
                with self.assertRaises(MODULE.ContractError):
                    MODULE.validate_transition(
                        root, base, head, first_parent=first_parent
                    )

            self.git(root, "checkout", "-q", "-b", "stale", initial)
            stale = self.commit(root, "0.1.2", "stale")
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, base, stale, first_parent=False)


class WorkflowStructureTests(unittest.TestCase):
    ACTION_PIN = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0"

    @staticmethod
    def require_exact_wiring(
        workflow: str,
        jobs_verifier: str,
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
        if workflow.count("release-window") != 2:
            raise ValueError("both jobs must independently bind the release window")

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
            raise ValueError("settings job may export only one sanitized attestation")

        for required in (
            "needs: [main-ci-jobs, immutable-settings]",
            "needs.main-ci-jobs.outputs.attestation ==",
            "github.event.workflow_run.id, github.event.workflow_run.run_attempt,",
            "needs.immutable-settings.outputs.attestation ==",
            "format('PASS:{0}:{1}:{2}:{3}', github.repository, github.run_id,",
            "github.run_attempt, github.event.workflow_run.head_sha)",
            "permissions:\n      contents: write",
            "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
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
            "permission-administration",
            "verify-platform-release-settings.sh",
            "verify-platform-release-main-jobs.sh",
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

        for required in (
            "tag-state",
            'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"',
            'test -z "${ACTIONS_READ_TOKEN-}"',
            'write_token="${GH_TOKEN}"',
            "unset GH_TOKEN",
            'GH_TOKEN="${write_token}" gh "$@"',
            "recovery-release",
            "recovery_source_sha='51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e'",
            "recovery_tag='v0.1.0'",
            PUBLISHER_TAG_GUARD,
            'tagger[name]=${tagger_name}',
            'tagger[email]=${tagger_email}',
            'tagger[date]=${tagger_date}',
            "release-state",
            '"${api}/releases/tags/${tag}"',
            "preflight_publication_state",
            'classify_tag "${current_tag_state}"',
            'classify_release "${current_release_state}"',
            'test "${current_release_state}" = absent',
            "for attempt in 1 2 3 4 5",
            'test "${tag_race_verified}" = true',
            'test "${release_race_verified}" = true',
            'run_write_gh release create "${recovery_tag}" --verify-tag',
            'run_write_gh release create "${TAG}" --verify-tag',
        ):
            if required not in transaction:
                raise ValueError(f"platform transaction lost exact wiring: {required}")
        # The two recovery pins are legitimately frozen history; any OTHER
        # vX.Y.Z literal is a current-version constant that goes stale at the
        # next patch and silently strands publication, as `current_tag='v0.1.1'`
        # did for v0.1.2. Only the derivation above may name the current tag.
        stale_pins = set(re.findall(r"v[0-9]+\.[0-9]+\.[0-9]+", transaction)) - {
            MODULE.RECOVERY_TAG
        }
        if stale_pins:
            raise ValueError(
                f"platform transaction pins a current-version tag literal: {sorted(stale_pins)}"
            )
        if "settings_token" in transaction or "/immutable-releases" in transaction:
            raise ValueError("App settings authority must not enter the write transaction")
        if "--target" in transaction:
            raise ValueError("existing exact tags must never gain a workflow-sensitive target")
        if transaction.count("for attempt in 1 2 3 4 5") != 3:
            raise ValueError("recovery Release, current tag, and current Release need bounded retries")
        if transaction.count("preflight_publication_state") != 6:
            raise ValueError("all four states need an initial preflight and four mutation-boundary rechecks")
        if (
            "preflight_publication_state\n"
            "complete_recovery_release\n"
            "publish_current_release"
        ) not in transaction:
            raise ValueError("all four states must be classified before either publication phase")
        if transaction.count('test "${tag_race_verified}" = true') != 1:
            raise ValueError("current tag race must have one terminal exact-state assertion")
        if transaction.count('test "${release_race_verified}" = true') != 2:
            raise ValueError("both Release races must have terminal exact-state assertions")
        if transaction.count("classify_tag exact") < 8:
            raise ValueError("recovery/current tag reuse and pre/post checks must be exact")
        if transaction.count("classify_release exact") < 6:
            raise ValueError("recovery/current Release paths must reach exact REST state")

        preflight_start = transaction.index("preflight_publication_state() {")
        recovery_start = transaction.index("complete_recovery_release() {")
        initial_preflight = transaction[preflight_start:recovery_start]
        if initial_preflight.count(
            'classify_tag exact \\\n    "${recovery_source_sha}"'
        ) != 2 or 'classify_tag absent \\\n    "${recovery_source_sha}"' in initial_preflight:
            raise ValueError("both recovery-tag preflight observations must require exact state")
        current_start = transaction.index("publish_current_release() {")
        recovery = transaction[recovery_start:current_start]
        recovery_write = 'run_write_gh release create "${recovery_tag}" --verify-tag'
        if "classify_tag absent" in recovery or "run_write_gh api" in recovery:
            raise ValueError("recovery path must never create or accept an absent v0.1.0 tag")
        if recovery.index("classify_tag exact") > recovery.index(recovery_write):
            raise ValueError("exact owner-prepared recovery tag must precede every write")
        if recovery.index("classify_release absent") > recovery.index(recovery_write):
            raise ValueError("recovery Release absence must precede its create")

        current = transaction[current_start:]
        for required in (
            "classify_tag absent",
            "run_write_gh api --method POST",
            '-f object="${SOURCE_SHA}" -f type=commit',
            'run_write_gh release create "${TAG}" --verify-tag',
        ):
            if required not in current:
                raise ValueError(f"current Release transaction lost exact create guard: {required}")
        for forbidden in (
            'git rev-list -n 1 "${TAG}"',
            "publication-state",
            "targetCommitish",
        ):
            if forbidden in workflow + jobs_verifier + settings_verifier + transaction:
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
        transaction = (
            ROOT / "scripts" / "ci" / "publish-platform-release.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.number || github.run_id", ci)
        self.assertIn('first_parent=(--first-parent)', ci)
        self.assertIn("workflow_run:", workflow)
        self.assertIn("github.event.workflow_run.head_sha", workflow)
        self.assertNotIn("queue:", ci + workflow)
        self.require_exact_wiring(
            workflow, jobs_verifier, settings_verifier, transaction
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
            "format('PASS:{0}:{1}:{2}:{3}', github.repository, github.run_id,",
            "github.run_attempt, github.event.workflow_run.head_sha)",
            "bash scripts/ci/publish-platform-release.sh",
        )
        for token in workflow_deletions:
            with self.subTest(workflow_deletion=token), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    workflow.replace(token, "", 1),
                    jobs_verifier,
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
                    settings_verifier.replace(token, "", 1),
                    transaction,
                )

        transaction_deletions = (
            "tag-state",
            'test -z "${IMMUTABLE_SETTINGS_TOKEN-}"',
            'test -z "${ACTIONS_READ_TOKEN-}"',
            'write_token="${GH_TOKEN}"',
            "unset GH_TOKEN",
            'GH_TOKEN="${write_token}" gh "$@"',
            "recovery-release",
            "recovery_source_sha='51c5f44f9cf1d35f68c6e9613e73ad50ef2e644e'",
            "recovery_tag='v0.1.0'",
            PUBLISHER_TAG_GUARD,
            'tagger[name]=${tagger_name}',
            'tagger[email]=${tagger_email}',
            'tagger[date]=${tagger_date}',
            "release-state",
            '"${api}/releases/tags/${tag}"',
            "preflight_publication_state",
            'classify_tag "${current_tag_state}"',
            'classify_release "${current_release_state}"',
            'test "${current_release_state}" = absent',
            "for attempt in 1 2 3 4 5",
            'test "${tag_race_verified}" = true',
            'test "${release_race_verified}" = true',
            'run_write_gh release create "${recovery_tag}" --verify-tag',
            'run_write_gh release create "${TAG}" --verify-tag',
        )
        for token in transaction_deletions:
            with self.subTest(transaction_deletion=token), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    workflow,
                    jobs_verifier,
                    settings_verifier,
                    transaction.replace(token, "", 1),
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
        )
        for index, mutant in enumerate(workflow_mutants):
            with self.subTest(workflow_mutant=index), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    mutant, jobs_verifier, settings_verifier, transaction
                )

        transaction_mutants = (
            transaction.replace(
                'GH_TOKEN="${write_token}" gh "$@"',
                'GH_TOKEN="${settings_token}" gh "$@"',
                1,
            ),
            transaction.replace("classify_tag exact \\", "classify_tag absent \\", 1),
            transaction.replace(
                'run_write_gh release create "${recovery_tag}" --verify-tag',
                'gh release create "${recovery_tag}" --verify-tag',
                1,
            ),
            transaction.replace(
                '"${recovery_tag}" --verify-tag',
                '"${recovery_tag}" --verify-tag --target "${recovery_source_sha}"',
                1,
            ),
            # Both mutants name the version this source currently declares, so
            # they are the hardest case: a literal that is correct TODAY still
            # strands the very next patch, and the gate must refuse it in both
            # the inline shape and the named-constant shape the era used.
            transaction.replace(
                PUBLISHER_TAG_GUARD, 'test "${TAG}" = "v0.1.3"', 1
            ),
            transaction.replace(
                "recovery_tag='v0.1.0'",
                "recovery_tag='v0.1.0'\ncurrent_tag='v0.1.3'",
                1,
            ),
        )
        for index, mutant in enumerate(transaction_mutants):
            with self.subTest(transaction_mutant=index), self.assertRaises(ValueError):
                self.require_exact_wiring(
                    workflow, jobs_verifier, settings_verifier, mutant
                )
        with self.assertRaises(ValueError):
            self.require_exact_wiring(
                workflow.replace("cancel-in-progress: false", "cancel-in-progress: true", 1),
                jobs_verifier,
                settings_verifier,
                transaction,
            )
        with self.assertRaises(ValueError):
            self.require_exact_wiring(
                workflow,
                jobs_verifier,
                settings_verifier,
                transaction + '\ngit rev-list -n 1 "${TAG}"\n',
            )
        for forbidden in ("kubectl", "flux", "tofu apply", "terraform apply", "cloudflared"):
            self.assertNotIn(
                forbidden,
                (workflow + jobs_verifier + settings_verifier + transaction).lower(),
            )


if __name__ == "__main__":
    unittest.main()
