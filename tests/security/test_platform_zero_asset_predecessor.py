"""Hostile tests for the one-time v0.1.40 zero-asset release bridge."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/ci/validate_platform_predecessor.py"
SPEC = importlib.util.spec_from_file_location("zero_asset_predecessor", VALIDATOR)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ZeroAssetPredecessorTests(unittest.TestCase):
    maxDiff = None

    def fixture(self):
        local = {
            "notes": "## Platform v0.1.40\n\nRuntime-derived notes.\n",
            "predecessor_sha": "7" * 40,
            "predecessor_tag": "v0.1.39",
            "source_sha": "8" * 40,
            "tag_object_sha": "9" * 40,
            "tagger_date": "2026-08-25T12:34:56Z",
        }
        release = {
            "assets": [],
            "author": {"id": 41898282, "login": "github-actions[bot]"},
            "body": local["notes"],
            "draft": False,
            "id": 12,
            "immutable": True,
            "name": "Platform v0.1.40",
            "prerelease": False,
            "tag_name": "v0.1.40",
            "target_commitish": local["source_sha"],
        }
        ref = {
            "object": {"sha": local["tag_object_sha"], "type": "tag"},
            "ref": "refs/tags/v0.1.40",
        }
        tag = {
            "message": f"Platform release v0.1.40 from {local['source_sha']}",
            "object": {"sha": local["source_sha"], "type": "commit"},
            "sha": local["tag_object_sha"],
            "tag": "v0.1.40",
            "tagger": {
                "date": local["tagger_date"],
                "email": MODULE.BOT_EMAIL,
                "name": MODULE.BOT_NAME,
            },
        }

        def run(run_id: int, attempt: int, event: str, workflow: str):
            return {
                "conclusion": "success",
                "event": event,
                "head_branch": "main",
                "head_sha": local["source_sha"],
                "id": run_id,
                "path": workflow,
                "repository": {"full_name": MODULE.REPOSITORY},
                "run_attempt": attempt,
                "status": "completed",
            }

        main = run(10, 1, "push", MODULE.MAIN_WORKFLOW)
        platform = run(11, 2, "workflow_run", MODULE.PLATFORM_WORKFLOW)
        main_runs = {"total_count": 1, "workflow_runs": [main]}
        platform_runs = {"total_count": 1, "workflow_runs": [platform]}
        return local, release, ref, tag, main_runs, platform_runs, main, platform

    def validate(self, fixture):
        local, release, ref, tag, main_runs, platform_runs, _, _ = fixture
        with mock.patch.object(
            MODULE, "derive_local_identity", return_value=local
        ):
            return MODULE.validate_records(
                ROOT, release, ref, tag, main_runs, platform_runs
            )

    def test_local_identity_is_derived_from_git_and_the_release_contract(self):
        source_sha = "8" * 40
        tag_object_sha = "9" * 40
        window = types.SimpleNamespace(
            base_sha="7" * 40,
            base_tag="v0.1.39",
            intent=types.SimpleNamespace(tag="v0.1.40"),
        )

        def git_result(_repository, *arguments):
            command = " ".join(arguments)
            if command == "rev-parse refs/tags/v0.1.40":
                return tag_object_sha
            if command == f"cat-file -t {tag_object_sha}":
                return "tag"
            if command == "rev-parse refs/tags/v0.1.40^{commit}":
                return source_sha
            if command == f"show -s --format=%cI {source_sha}":
                return "2026-08-25T12:34:56Z"
            raise AssertionError(command)

        with (
            mock.patch.object(MODULE, "git", side_effect=git_result),
            mock.patch.object(
                MODULE.release_contract,
                "discover_transition_window",
                return_value=window,
            ) as discover,
            mock.patch.object(
                MODULE.release_contract,
                "render_release_notes",
                return_value="derived notes\n",
            ) as render,
        ):
            actual = MODULE.derive_local_identity(ROOT)
        self.assertEqual(actual["source_sha"], source_sha)
        self.assertEqual(actual["tag_object_sha"], tag_object_sha)
        self.assertEqual(actual["notes"], "derived notes\n")
        discover.assert_called_once_with(ROOT.resolve(), source_sha)
        render.assert_called_once_with(
            ROOT.resolve(),
            source_sha,
            "v0.1.40",
            expected_base_sha="7" * 40,
            expected_base_tag="v0.1.39",
        )

    def test_exact_bridge_is_runtime_derived_zero_asset_and_sanitized(self):
        fixture = self.fixture()
        local = fixture[0]
        derived = self.validate(fixture)
        self.assertEqual(derived["source"], {"merge_sha": local["source_sha"]})
        self.assertEqual(derived["release"]["asset_count"], 0)
        self.assertEqual(derived["tag"]["object_sha"], local["tag_object_sha"])
        self.assertEqual(derived["main_ci"], {"run_attempt": 1, "run_id": 10})
        self.assertEqual(
            derived["platform_release"], {"run_attempt": 2, "run_id": 11}
        )
        self.assertNotIn("selector", derived)
        for base, target in (
            ("v0.1.39", "v0.1.41"),
            ("v0.1.40", "v0.1.42"),
            ("main", "v0.1.41"),
        ):
            with self.subTest(base=base, target=target), self.assertRaises(SystemExit):
                MODULE.validate_edge(base, target)

    def test_release_and_annotated_tag_mutations_fail_closed(self):
        base = self.fixture()
        release_mutations = (
            ("assets", [{"name": "platform-release-identity.v1.json"}]),
            ("body", "foreign"),
            ("target_commitish", "0" * 40),
            ("immutable", False),
            ("author", {"id": 1, "login": "github-actions[bot]"}),
            ("draft", True),
        )
        for field, value in release_mutations:
            changed = list(copy.deepcopy(base))
            changed[1][field] = value
            with self.subTest(release=field), self.assertRaises(SystemExit):
                self.validate(tuple(changed))
        for target, path, value in (
            (2, ("object", "sha"), "0" * 40),
            (2, ("object", "type"), "commit"),
            (3, ("object", "sha"), "0" * 40),
            (3, ("message",), "foreign"),
            (3, ("tagger", "name"), "repository-owner"),
        ):
            changed = list(copy.deepcopy(base))
            parent = changed[target]
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            with self.subTest(tag=path), self.assertRaises(SystemExit):
                self.validate(tuple(changed))

    def test_run_discovery_rejects_absent_ambiguous_failed_and_foreign(self):
        base = self.fixture()
        for name, mutate in (
            ("absent", lambda value: value.update(total_count=0, workflow_runs=[])),
            (
                "ambiguous",
                lambda value: value.update(
                    total_count=2,
                    workflow_runs=value["workflow_runs"] * 2,
                ),
            ),
            (
                "failed",
                lambda value: value["workflow_runs"][0].update(conclusion="failure"),
            ),
            (
                "foreign-sha",
                lambda value: value["workflow_runs"][0].update(head_sha="0" * 40),
            ),
            (
                "foreign-workflow",
                lambda value: value["workflow_runs"][0].update(path="foreign.yml"),
            ),
            ("partial", lambda value: value.update(decoy=[])),
        ):
            changed = list(copy.deepcopy(base))
            mutate(changed[4])
            with self.subTest(name=name), self.assertRaises(SystemExit):
                self.validate(tuple(changed))

    def test_exact_attempt_must_match_the_runtime_query(self):
        fixture = self.fixture()
        local, _, _, _, _, _, main, _ = fixture
        expected = {"run_attempt": 1, "run_id": 10}
        MODULE.validate_run_record(
            main,
            expected,
            source_sha=local["source_sha"],
            event="push",
            workflow=MODULE.MAIN_WORKFLOW,
            label="main CI",
        )
        for field, value in (
            ("run_attempt", 2),
            ("id", 99),
            ("status", "in_progress"),
            ("conclusion", "failure"),
        ):
            changed = copy.deepcopy(main)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(SystemExit):
                MODULE.validate_run_record(
                    changed,
                    expected,
                    source_sha=local["source_sha"],
                    event="push",
                    workflow=MODULE.MAIN_WORKFLOW,
                    label="main CI",
                )

    def test_json_is_duplicate_free_and_source_has_no_invented_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text('{"one":1,"one":2}\n', encoding="utf-8")
            with self.assertRaises(SystemExit):
                MODULE.load_object(path)
        source = VALIDATOR.read_text(encoding="utf-8")
        self.assertNotIn("--identity", source)
        self.assertNotIn("IDENTITY_ASSET", source)
        self.assertNotIn("SELECTOR_IMAGE", source)
        self.assertEqual(
            set(re.findall(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", source)),
            set(),
        )


if __name__ == "__main__":
    unittest.main()
