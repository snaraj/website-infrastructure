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
        "immutable_releases": True,
        "private_vulnerability_reporting": True,
        "secret_scanning": True,
        "secret_scanning_push_protection": True,
        "secret_scanning_non_provider_patterns": False,
        "secret_scanning_validity_checks": False,
    }


def settings_api() -> dict[str, object]:
    ruleset_id = 42
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
        "repos/owner/platform/rulesets": [
            {
                "id": ruleset_id,
                "name": "only-me-merge",
                "target": "branch",
                "source_type": "Repository",
                "source": "owner/platform",
                "enforcement": "active",
            }
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
            '"secret_scanning": true',
            '"secret_scanning_push_protection": true',
            '"secret_scanning_non_provider_patterns": false',
            '"secret_scanning_validity_checks": false',
            "private-vulnerability-reporting",
            "settings-preflight",
            "settings-receipt",
            "must not become Ready until",
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
            "repos/owner/platform/rulesets",
            "repos/owner/platform/rulesets/42",
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
        changed["repos/owner/platform/rulesets"].append(
            copy.deepcopy(changed["repos/owner/platform/rulesets"][0])
        )
        mutations.append(changed)

        for index, changed in enumerate(mutations):
            with self.subTest(raw_mutation=index), self.assertRaises(
                MODULE.ContractError
            ):
                self.observe(changed)

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
            '"secret_scanning": true',
            '"secret_scanning_push_protection": true',
            '"secret_scanning_non_provider_patterns": false',
            '"secret_scanning_validity_checks": false',
            "settings-preflight",
            "settings-receipt",
            "must not become Ready until",
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


class PublicationTransactionShellTests(unittest.TestCase):
    TAG = "v0.1.0"
    SOURCE = "a" * 40
    TAG_OBJECT = "b" * 40
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

    @property
    def notes(self) -> str:
        return (
            f"## Platform {self.TAG}\n\n"
            f"Immutable repository source: `{self.SOURCE}`\n\n"
            "This release names platform source only. It does not deploy, promote, "
            "mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n"
            "See `CHANGELOG.md` at this tag for the human-readable change record.\n"
        )

    def exact_records(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, f"Platform release {self.TAG} from {self.SOURCE}", self.DATE)
        release = {
            "tag_name": self.TAG,
            "name": f"Platform {self.TAG}",
            "body": self.notes,
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
        initial_exact: bool = False,
        immutable: bool = True,
        drift_before_release: bool = False,
        drift_during_release: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], str, dict[str, object]]:
        with tempfile.TemporaryDirectory(
            dir=ROOT, prefix=".platform-release-shell-"
        ) as temporary:
            runner = Path(temporary)
            transaction_path = runner / "transaction.sh"
            with transaction_path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(script)
            if initial_exact:
                ref, tag, release = self.exact_records()
                (runner / "ref.json").write_text(json.dumps(ref), encoding="utf-8")
                (runner / "tag.json").write_text(json.dumps(tag), encoding="utf-8")
                (runner / "release.json").write_text(
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
  local output='' url='' value
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      http*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  case "${url}" in
    */immutable-releases)
      printf '{"enabled":%s,"enforced_by_owner":false}' "${MOCK_IMMUTABLE}" > "${output}"
      printf '200'
      ;;
    */git/ref/tags/*)
      if [ -f "${MOCK_REF_JSON}" ]; then cp "${MOCK_REF_JSON}" "${output}"; printf '200';
      else printf '{}' > "${output}"; printf '404'; fi
      ;;
    */git/tags/*)
      if [ -f "${MOCK_TAG_JSON}" ]; then cp "${MOCK_TAG_JSON}" "${output}"; printf '200';
      else printf '{}' > "${output}"; printf '404'; fi
      ;;
    */releases/tags/*)
      if [ -f "${MOCK_RELEASE_JSON}" ]; then cp "${MOCK_RELEASE_JSON}" "${output}"; printf '200';
      else
        if [ "${MOCK_DRIFT_BEFORE_RELEASE}" = true ] && [ ! -f "${MOCK_DRIFT_MARKER}" ]; then
          "${TEST_PYTHON}" -c 'import json,sys; p=sys.argv[1]; v=json.load(open(p,encoding="utf-8")); v["object"]["sha"]="0"*40; json.dump(v,open(p,"w",encoding="utf-8")); open(sys.argv[2],"w").close()' \
            "${MOCK_TAG_JSON}" "${MOCK_DRIFT_MARKER}"
        fi
        printf '{}' > "${output}"; printf '404'
      fi
      ;;
    *) return 2 ;;
  esac
}

gh() {
  printf 'CALL\n' >> "${MOCK_CALLS}"
  printf '<%s>\n' "$@" >> "${MOCK_CALLS}"
  if [ "$1" = api ]; then
    local endpoint='' arg tag='' message='' object='' type=''
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
        "${TEST_PYTHON}" -c 'import json,sys; json.dump({"sha":sys.argv[2],"tag":sys.argv[3],"message":sys.argv[4],"object":{"type":"commit","sha":sys.argv[5]},"tagger":{"name":sys.argv[6],"email":sys.argv[7],"date":sys.argv[8]}},open(sys.argv[1],"w",encoding="utf-8"))' \
          "${MOCK_TAG_JSON}" "${MOCK_TAG_OBJECT}" "${tag}" "${message}" "${object}" \
          "${tagger_name}" "${tagger_email}" "${tagger_date}"
        printf '%s\n' "${MOCK_TAG_OBJECT}"
        ;;
      */git/refs)
        if [ "${ref}" != "refs/tags/${TAG}" ] || \
          [ "${sha}" != "${MOCK_TAG_OBJECT}" ]; then
          return 2
        fi
        "${TEST_PYTHON}" -c 'import json,sys; json.dump({"ref":sys.argv[2],"object":{"type":"tag","sha":sys.argv[3]}},open(sys.argv[1],"w",encoding="utf-8"))' \
          "${MOCK_REF_JSON}" "${ref}" "${sha}"
        if [ "${MOCK_RACE}" = true ]; then return 1; fi
        ;;
      *) return 2 ;;
    esac
    return 0
  fi
  if [ "$1" = release ] && [ "$2" = create ]; then
    local release_tag="$3" tag_verified='' draft=false prerelease=false title='' notes=''
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
      "${MOCK_RELEASE_JSON}" "${release_tag}" "${title}" "${notes}" "${draft}" "${prerelease}" "${MOCK_IMMUTABLE}"
    if [ "${MOCK_DRIFT_DURING_RELEASE}" = true ]; then
      "${TEST_PYTHON}" -c 'import json,sys; p=sys.argv[1]; v=json.load(open(p,encoding="utf-8")); v["object"]["sha"]="0"*40; json.dump(v,open(p,"w",encoding="utf-8"))' \
        "${MOCK_TAG_JSON}"
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
                    "MOCK_DRIFT_MARKER": f"{relative}/drift.marker",
                    "MOCK_TAG_OBJECT": self.TAG_OBJECT,
                    "MOCK_REF_JSON": f"{relative}/ref.json",
                    "MOCK_TAG_JSON": f"{relative}/tag.json",
                    "MOCK_RELEASE_JSON": f"{relative}/release.json",
                    "MOCK_CALLS": f"{relative}/calls.log",
                    "MOCK_SCRIPT": f"{relative}/transaction.sh",
                    "GH_TOKEN": "fixture-token",
                    "SOURCE_SHA": self.SOURCE,
                    "TAG": self.TAG,
                    "GITHUB_API_URL": "https://api.github.test",
                    "GITHUB_REPOSITORY": "owner/platform",
                    "RUNNER_TEMP": relative,
                }
            )
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
            for name in ("ref", "tag", "release"):
                path = runner / f"{name}.json"
                if path.exists():
                    state[name] = json.loads(path.read_text(encoding="utf-8"))
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
                self.assertEqual(state["tag"]["object"]["sha"], self.SOURCE)
                self.assertEqual(state["release"]["draft"], False)
                self.assertEqual(state["release"]["prerelease"], False)
                self.assertEqual(state["release"]["immutable"], True)
                if race:
                    self.assertIn("exact concurrent winner", completed.stderr)

        existing, calls, _state = self.execute(script, initial_exact=True)
        self.assertEqual(existing.returncode, 0, existing.stdout + existing.stderr)
        self.assertEqual(calls, "")
        self.assertIn("verified existing", existing.stdout)
        self.assertIn("verified complete existing", existing.stdout)

    def test_immutable_setting_denies_before_any_publication_call(self):
        script = self.script()
        completed, calls, state = self.execute(script, immutable=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(calls, "")
        self.assertEqual(state, {})
        self.assertIn("GitHub immutable releases must be enabled", completed.stderr)

        guard = (
            'python3 -I -B "${contract}" immutable-settings \\\n'
            '  --settings-json "${immutable_json}" >/dev/null'
        )
        self.assertIn(guard, script)
        deleted_guard, mutant_calls, _state = self.execute(
            script.replace(guard, ":", 1), immutable=False
        )
        self.assertNotEqual(deleted_guard.returncode, 0)
        self.assertNotEqual(mutant_calls, "")

    def test_foreign_tag_races_are_rejected_before_and_after_release_create(self):
        script = self.script()
        pre_guard = (
            "  # The tag is not locked until the Release exists. Close the last observable\n"
            "  # pre-publication window after proving Release absence and before creating it.\n"
            "  classify_tag exact >/dev/null\n"
        )
        post_guard = (
            "# Re-query both halves after create/reuse. An immutable Release locks its tag,\n"
            "# but a foreign pre-lock race must never be accepted as a successful release.\n"
            "classify_release exact >/dev/null\n"
            "classify_tag exact >/dev/null\n"
        )
        self.assertIn(pre_guard, script)
        self.assertIn(post_guard, script)

        before, _calls, before_state = self.execute(
            script, drift_before_release=True
        )
        self.assertNotEqual(before.returncode, 0)
        self.assertNotIn("release", before_state)
        deleted_pre, _calls, deleted_pre_state = self.execute(
            script.replace(pre_guard, "", 1), drift_before_release=True
        )
        self.assertNotEqual(deleted_pre.returncode, 0)
        self.assertIn("release", deleted_pre_state)

        during, _calls, during_state = self.execute(
            script, drift_during_release=True
        )
        self.assertNotEqual(during.returncode, 0)
        self.assertIn("release", during_state)
        deleted_post, _calls, _state = self.execute(
            script.replace(post_guard, "", 1), drift_during_release=True
        )
        self.assertEqual(
            deleted_post.returncode, 0, deleted_post.stdout + deleted_post.stderr
        )

    def test_source_creation_and_publication_mutants_are_killed_end_to_end(self):
        script = self.script()
        source = '-f object="${SOURCE_SHA}" \\\n'
        release = 'gh release create "${TAG}" --verify-tag \\\n'
        verify = '"${TAG}" --verify-tag \\\n'
        markers = (source, release, verify, "-f type=commit")
        for marker in markers:
            self.assertIn(marker, script)
        mutants = (
            script.replace(source, '-f object="0000000000000000000000000000000000000000" \\\n', 1),
            script.replace(source, "", 1),
            script.replace("-f type=commit", "-f type=tree", 1),
            script.replace(release, 'gh release create "${TAG}" --verify-tag --draft \\\n', 1),
            script.replace(release, 'gh release create "${TAG}" --verify-tag --prerelease \\\n', 1),
            script.replace(verify, '"${TAG}" \\\n', 1),
            script.replace("classify_tag absent >/dev/null", "classify_tag exact >/dev/null", 1),
            script.replace("classify_release absent >/dev/null", "classify_release exact >/dev/null", 1),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(transaction_mutant=index):
                completed, _calls, _state = self.execute(mutant)
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
    @staticmethod
    def require_exact_wiring(workflow: str, transaction: str) -> None:
        for required in (
            "fetch-depth: 0",
            "release-window",
            "platform-release-${{ github.event.workflow_run.head_sha }}",
            "cancel-in-progress: false",
            "bash scripts/ci/publish-platform-release.sh",
        ):
            if required not in workflow:
                raise ValueError(f"platform publisher lost exact wiring: {required}")
        for required in (
            "/immutable-releases",
            "immutable-settings",
            "tag-state",
            "classify_tag exact >/dev/null",
            "classify_tag absent >/dev/null",
            'tagger[name]=${tagger_name}',
            'tagger[email]=${tagger_email}',
            'tagger[date]=${tagger_date}',
            "release-state",
            "classify_release exact >/dev/null",
            "classify_release absent >/dev/null",
            "/releases/tags/${TAG}",
            "for attempt in 1 2 3 4 5",
            'test "${tag_race_verified}" = true',
            'test "${release_race_verified}" = true',
            'gh release create "${TAG}" --verify-tag',
        ):
            if required not in transaction:
                raise ValueError(f"platform transaction lost exact wiring: {required}")
        if transaction.count("classify_tag exact >/dev/null") < 5:
            raise ValueError("tag reuse/create/race and pre/post Release checks must be exact")
        if transaction.count("classify_release exact >/dev/null") < 4:
            raise ValueError("Release reuse/create/race must each reach exact REST state")
        if transaction.count("for attempt in 1 2 3 4 5") != 2:
            raise ValueError("tag and Release transactions each need one bounded retry loop")
        for forbidden in (
            'git rev-list -n 1 "${TAG}"',
            "publication-state",
            "targetCommitish",
        ):
            if forbidden in workflow + transaction:
                raise ValueError(f"platform publisher has non-authoritative verifier: {forbidden}")

    def test_every_main_sha_has_an_independent_non_deploying_exact_path(self):
        ci = (ROOT / ".github" / "workflows" / "pull-request.yml").read_text(
            encoding="utf-8"
        )
        publish = (ROOT / ".github" / "workflows" / "platform-release.yml").read_text(
            encoding="utf-8"
        )
        transaction = (
            ROOT / "scripts" / "ci" / "publish-platform-release.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.number || github.run_id", ci)
        self.assertIn('first_parent=(--first-parent)', ci)
        self.assertIn("workflow_run:", publish)
        self.assertIn("github.event.workflow_run.head_sha", publish)
        self.assertNotIn("queue:", ci + publish)
        self.require_exact_wiring(publish, transaction)
        for token in (
            "fetch-depth: 0",
            "release-window",
            "platform-release-${{ github.event.workflow_run.head_sha }}",
            "cancel-in-progress: false",
            "bash scripts/ci/publish-platform-release.sh",
        ):
            with self.subTest(workflow_deletion=token), self.assertRaises(ValueError):
                self.require_exact_wiring(publish.replace(token, "", 1), transaction)
        for token in (
            "/immutable-releases",
            "immutable-settings",
            "tag-state",
            "classify_tag exact >/dev/null",
            "classify_tag absent >/dev/null",
            'tagger[name]=${tagger_name}',
            'tagger[email]=${tagger_email}',
            'tagger[date]=${tagger_date}',
            "release-state",
            "classify_release exact >/dev/null",
            "classify_release absent >/dev/null",
            "/releases/tags/${TAG}",
            "for attempt in 1 2 3 4 5",
            'test "${tag_race_verified}" = true',
            'test "${release_race_verified}" = true',
            'gh release create "${TAG}" --verify-tag',
        ):
            with self.subTest(transaction_deletion=token), self.assertRaises(ValueError):
                self.require_exact_wiring(publish, transaction.replace(token, "", 1))
        for old, new in (
            ("classify_tag absent >/dev/null", "classify_tag exact >/dev/null"),
            ("classify_release absent >/dev/null", "classify_release exact >/dev/null"),
        ):
            with self.subTest(inversion=old), self.assertRaises(ValueError):
                self.require_exact_wiring(publish, transaction.replace(old, new, 1))
        with self.assertRaises(ValueError):
            self.require_exact_wiring(
                publish.replace("cancel-in-progress: false", "cancel-in-progress: true", 1),
                transaction,
            )
        with self.assertRaises(ValueError):
            self.require_exact_wiring(
                publish, transaction + '\ngit rev-list -n 1 "${TAG}"\n'
            )
        for forbidden in ("kubectl", "flux", "tofu apply", "terraform apply", "cloudflared"):
            self.assertNotIn(forbidden, (publish + transaction).lower())


if __name__ == "__main__":
    unittest.main()
