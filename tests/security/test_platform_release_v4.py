"""Source and executor are separate facts in the finite publication recovery."""

import copy
import hashlib
import json
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .support import load_script
from . import test_platform_release_identity_asset as asset_fixtures

ROOT = Path(__file__).resolve().parents[2]
C = load_script("ci/platform_release_contract.py", module_name="release_v4_contract")
E = C.EPOCH
EXECUTOR = "e" * 40
EXECUTOR_TREE = "f" * 40


def main_ci(source, run_id):
    return {"event": "push", "head_sha": source, "ref": "refs/heads/main",
            "run_id": run_id, "run_attempt": 1, "conclusion": "success",
            "workflow": ".github/workflows/pull-request.yml"}


def evidence(recovering=True):
    frozen = E.HISTORICAL_RELEASES[0]
    source = frozen["source_sha"] if recovering else EXECUTOR
    tree = frozen["tree_sha"] if recovering else EXECUTOR_TREE
    tag = "v0.1.81" if recovering else "v0.1.84"
    original_ci = main_ci(source, frozen["main_run_id"] if recovering else 400)
    return {
        "schema": "https://snaraj.dev/schemas/platform-release-identity/v4",
        "repository": "snaraj/platform", "repository_id": 1327645656,
        "source": {"merge_sha": source, "tree_sha": tree, "protected_ref": "refs/heads/main"},
        "tag": {"name": tag, "object_sha": "b" * 40, "object_type": "tag", "peeled_commit": source},
        "predecessor": {"tag": "v0.1.80" if recovering else "v0.1.83",
                        "peeled_commit": frozen["parent_sha"] if recovering else E.HISTORICAL_RELEASES[-1]["source_sha"]},
        "changelog": {"fragment_path": frozen["fragment_path"] if recovering else "changelog.d/1-example.md",
                      "fragment_sha256": "sha256:" + (frozen["fragment_sha256"] if recovering else "a" * 64)},
        "release": {"id": 300, "asset_count": 2, "draft": False, "immutable": True,
                    "prerelease": False, "tag_name": tag, "target_commitish": "main" if recovering else source},
        "main_ci": original_ci,
        "execution": {"source_sha": EXECUTOR, "tree_sha": EXECUTOR_TREE, "main_ci": main_ci(EXECUTOR, 400)},
        "platform_release": {
            "event": "workflow_dispatch" if recovering else "workflow_run", "head_sha": EXECUTOR,
            "ref": "refs/heads/main", "run_id": 500, "run_attempt": 1,
            "workflow": ".github/workflows/platform-release-recovery.yml" if recovering else ".github/workflows/platform-release.yml",
        },
    }


def records(value):
    canonical = asset_fixtures.PlatformReleaseIdentityAssetTests.canonical(value)
    bundle = asset_fixtures.PlatformReleaseIdentityAssetTests.bundle(canonical)
    tag = value["tag"]["name"]
    assets = []
    version = value["schema"].rsplit("/", 1)[1]
    for number, name, raw in ((900, f"platform-release-identity.{version}.json", canonical),
                              (901, f"platform-release-identity.{version}.json.sigstore.json", bundle)):
        assets.append({"id": number, "name": name, "label": None, "state": "uploaded",
                       "content_type": "application/json", "size": len(raw),
                       "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                       "url": f"https://api.github.com/repos/snaraj/platform/releases/assets/{number}",
                       "browser_download_url": f"https://github.com/snaraj/platform/releases/download/{tag}/{name}",
                       "download_count": 0, "uploader": {"login": "github-actions[bot]", "id": 41898282}})
    release = {**value["release"], "name": "Platform " + tag, "body": "Informational notes",
               "author": {"login": "github-actions[bot]", "id": 41898282}, "assets": assets}
    release.pop("asset_count")
    runs = []
    execution = value.get("execution", {})
    tuples = [(value["main_ci"], value["source"]["tree_sha"]),
              (value["platform_release"], execution.get("tree_sha", value["source"]["tree_sha"]))]
    if "execution" in value:
        tuples.append((execution.get("main_ci", main_ci(EXECUTOR, 400)), execution.get("tree_sha", EXECUTOR_TREE)))
    for run, tree in tuples:
        runs.append({"id": run["run_id"], "run_attempt": run["run_attempt"],
                     "event": run["event"], "head_sha": run["head_sha"], "head_branch": "main",
                     "path": run["workflow"], "status": "completed", "conclusion": "success",
                     "repository": {"id": 1327645656, "full_name": "snaraj/platform"},
                     "head_commit": {"id": run["head_sha"], "tree_id": tree}})
    return canonical, bundle, release, runs


def validate(value, *, run_records=True):
    identity, bundle, release, runs = records(value)
    C.validate_identity_release_record(
        release, identity=identity, bundle=bundle, tag=value["tag"]["name"],
        source_sha=value["source"]["merge_sha"], tree_sha=value["source"]["tree_sha"],
        tag_object_sha=value["tag"]["object_sha"], api_repository="snaraj/platform", api_repository_id=1327645656,
    )
    if run_records:
        C.validate_identity_run_records(identity, runs[0], runs[1], execution_main_run_record=runs[2])


class PlatformReleaseV4Tests(unittest.TestCase):
    def staged_recovery(self, token="untagged-" + "a" * 20):
        value = evidence()
        identity, bundle, release, _ = records(value)
        release.update(tag_name=token, draft=True, immutable=False)
        for asset in release["assets"]:
            asset["browser_download_url"] = asset["browser_download_url"].replace("/v0.1.81/", f"/{token}/")
        kwargs = dict(identity=identity, bundle=bundle, tag="v0.1.81",
                      source_sha=value["source"]["merge_sha"], tree_sha=value["source"]["tree_sha"],
                      tag_object_sha=value["tag"]["object_sha"],
                      api_repository="snaraj/platform", api_repository_id=1327645656, staged=True)
        return release, kwargs

    def test_staged_recovery_accepts_bound_temporary_and_canonical_tags(self):
        for token in ("untagged-" + "a" * 20, "untagged-" + "b" * 20):
            release, kwargs = self.staged_recovery(token)
            for tag in (token, "v0.1.81"):
                with self.subTest(token=token, tag=tag):
                    try:
                        C.validate_identity_release_record({**release, "tag_name": tag}, **kwargs)
                    except C.ContractError as error:
                        self.fail(f"bound staged draft refused: {error}")

    def test_staged_recovery_refuses_foreign_record_and_asset_namespaces(self):
        release, kwargs = self.staged_recovery()
        for tag in (None, "v0.1.82", "untagged-" + "b" * 20, "untagged-" + "A" * 20,
                    "untagged-" + "a" * 19, "untagged-" + "a" * 21):
            with self.subTest(tag=tag), self.assertRaises(C.ContractError):
                C.validate_identity_release_record({**release, "tag_name": tag}, **kwargs)
        for indexes in ((0,), (1,), (0, 1)):
            changed = copy.deepcopy(release)
            for index in indexes:
                changed["assets"][index]["browser_download_url"] = changed["assets"][index][
                    "browser_download_url"].replace("untagged-" + "a" * 20, "untagged-" + "b" * 20)
            with self.subTest(assets=indexes), self.assertRaises(C.ContractError):
                C.validate_identity_release_record(changed, **kwargs)
        for token in ("untagged-" + "A" * 20, "untagged-" + "a" * 19, "untagged-" + "a" * 21):
            # A coherent pair must still reject a malformed namespace, without
            # relying on the separate mixed-token guard to catch it.
            changed, kwargs = self.staged_recovery(token)
            with self.subTest(coherent_token=token), self.assertRaises(C.ContractError):
                C.validate_identity_release_record(changed, **kwargs)

    def test_staged_recovery_keeps_lifecycle_custody_and_intended_tag_checks(self):
        release, kwargs = self.staged_recovery()
        for key, value in (("draft", False), ("immutable", True), ("prerelease", True),
                           ("target_commitish", "a" * 40), ("name", "Platform v0.1.82"),
                           ("id", 301), ("author", {"login": "other", "id": 1})):
            with self.subTest(field=key), self.assertRaises(C.ContractError):
                C.validate_identity_release_record({**release, key: value}, **kwargs)
        for key, value in (("source_sha", "a" * 40), ("tag", "v0.1.82"),
                           ("tag_object_sha", "c" * 40), ("tree_sha", "d" * 40)):
            with self.subTest(binding=key), self.assertRaises(C.ContractError):
                C.validate_identity_release_record(release, **{**kwargs, key: value})

    def test_immutable_recovery_refuses_temporary_tag_even_with_matching_asset_urls(self):
        release, kwargs = self.staged_recovery()
        release.update(draft=False, immutable=True)
        # Coherent temporary final URLs pass the metadata projection; the
        # immutable release boundary itself must still reject this tag.
        with self.assertRaisesRegex(C.ContractError, "REST release"):
            C.validate_identity_release_record(release, **{**kwargs, "staged": False})

    def test_recovery_draft_target_custody_and_zero_assets_are_independent(self):
        value = evidence()
        record = {"id": 300, "tag_name": "v0.1.81", "name": "Platform v0.1.81", "target_commitish": "main",
                  "body": "exact marker", "draft": True, "prerelease": False, "immutable": False,
                  "author": {"login": "github-actions[bot]", "id": 41898282}, "assets": []}
        def check(candidate):
            C.validate_draft_release_record(candidate, tag="v0.1.81", source_sha=value["source"]["merge_sha"],
                                             title="Platform v0.1.81", body="exact marker", expected_release_id=300)
        check(record)
        for key, replacement in (("target_commitish", value["source"]["merge_sha"]), ("target_commitish", "master"),
                ("name", "foreign"), ("assets", [{}]), ("id", 301), ("immutable", True),
                ("author", {"login": "other", "id": 1})):
            with self.subTest(field=key), self.assertRaises(C.ContractError):
                check({**record, key: replacement})

    def test_run_record_cli_requires_the_actual_executor_attempt(self):
        raw, _, _, runs = records(evidence())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "identity.json").write_bytes(raw)
            paths = []
            for index, record in enumerate(runs):
                path = root / f"run-{index}.json"
                path.write_text(json.dumps(record))
                paths.append(str(path))
            args = ["contract", "identity-run-records", "--identity", str(root / "identity.json"),
                    "--main-run-json", paths[0], "--platform-run-json", paths[1],
                    "--execution-main-run-json", paths[2]]
            with mock.patch.object(sys, "argv", args), mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(C.main(), 0)
            runs[2]["id"] = 999
            Path(paths[2]).write_text(json.dumps(runs[2]))
            with mock.patch.object(sys, "argv", args), mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(C.main(), 1)

    def test_closed_historical_lookup_and_publication_cli(self):
        for index, entry in enumerate(E.HISTORICAL_RELEASES):
            tag = f"v0.1.{81 + index}"
            with mock.patch.object(sys, "argv", ["epoch", tag, "--historical-main-run"]), \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(E.main(), 0)
                self.assertEqual(output.getvalue(), str(entry["main_run_id"]) + "\n")
            self.assertEqual(E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, tag,
                             f"v0.1.{80 + index}", entry["parent_sha"], entry["source_sha"])["version"], 4)
            for source, parent in ((None, entry["parent_sha"]), ("a" * 40, entry["parent_sha"]),
                                   (entry["source_sha"], "a" * 40)):
                with self.subTest(source=source, parent=parent), self.assertRaises(ValueError):
                    E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, tag, f"v0.1.{80 + index}", parent, source)
            with self.assertRaises(ValueError):
                E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, "v0.1.84", "v0.1.83", "a" * 40, entry["source_sha"])
            with self.assertRaises(ValueError):
                E.release_target(tag, "a" * 40)
        for argv in (["epoch", "v0.1.80", "--historical-main-run"],
                     ["epoch", "v0.1.84", "--historical-main-run"],
                     ["epoch", "v0.1.81", "--historical-main-run", "--source-sha", "a" * 40]):
            with self.subTest(argv=argv), mock.patch.object(sys, "argv", argv), mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(E.main(), 1)

    def test_execution_semantics_refuse_unknown_fields_and_historical_executors(self):
        exact = evidence()
        changes = [({"extra": True}, "execution"), ({"extra": True}, "main_ci")]
        for extra, field in changes:
            value = copy.deepcopy(exact)
            target = value["execution"] if field == "execution" else value["execution"]["main_ci"]
            target.update(extra)
            with self.subTest(field=field), self.assertRaises(ValueError):
                E.validate_execution(value)
        for replacement in (None, [], "execution"):
            value = copy.deepcopy(exact)
            value["execution"] = replacement
            with self.subTest(shape=replacement), self.assertRaises(ValueError):
                E.validate_execution(value)
        for key, replacement in (("source_sha", None), ("tree_sha", 42), ("main_ci", None),
                                  ("main_ci", [])):
            value = copy.deepcopy(exact)
            value["execution"][key] = replacement
            with self.subTest(field=key, replacement=replacement), self.assertRaises(ValueError):
                E.validate_execution(value)
        for key, replacement in (("conclusion", "failure"), ("event", "workflow_dispatch"),
                ("head_sha", "a" * 40), ("ref", "refs/heads/other"), ("workflow", "foreign.yml"),
                ("run_id", True), ("run_id", 0), ("run_attempt", True), ("run_attempt", 0)):
            value = copy.deepcopy(exact)
            value["execution"]["main_ci"][key] = replacement
            with self.subTest(ci=key, replacement=replacement), self.assertRaises(ValueError):
                E.validate_execution(value)
        for recovering in (True, False):
            value = evidence(recovering)
            value["source"]["merge_sha"] = "a" * 40
            with self.subTest(source=recovering), self.assertRaises(ValueError):
                E.validate_execution(value)
        for sha in (E.TERMINAL_V3_SOURCE, *(row["source_sha"] for row in E.HISTORICAL_RELEASES)):
            value = copy.deepcopy(exact)
            value["execution"]["source_sha"] = sha
            value["execution"]["main_ci"]["head_sha"] = sha
            value["platform_release"]["head_sha"] = sha
            with self.subTest(sha=sha), self.assertRaisesRegex(ValueError, "historical execution"):
                E.validate_execution(value)
        for key, replacement in (("tree_sha", "a" * 40), ("main_ci", main_ci(EXECUTOR, 401))):
            value = evidence(False)
            value["execution"][key] = replacement
            with self.subTest(ordinary=key), self.assertRaisesRegex(ValueError, "ordinary publication"):
                E.validate_execution(value)

    def test_policy_preserves_old_epochs_and_closes_recovery_subjects(self):
        for tag, version in (("v0.1.69", 1), ("v0.1.77", 2), ("v0.1.80", 3), ("v0.1.81", 4), ("v0.1.84", 4)):
            self.assertEqual(E.identity(tag)["version"], version)
        for tag in ("v0.1.81", "v0.1.82", "v0.1.83"):
            selected = E.identity(tag)
            self.assertEqual(selected["publisher_workflow"], ".github/workflows/platform-release-recovery.yml")
            self.assertEqual(selected["publisher_event"], "workflow_dispatch")
            self.assertEqual(selected["subject"], "https://github.com/snaraj/platform/.github/workflows/platform-release-recovery.yml@refs/heads/main")
        self.assertEqual(E.identity("v0.1.84")["publisher_event"], "workflow_run")
        self.assertEqual(E.identity("v0.1.84")["subject"], "https://github.com/snaraj/platform/.github/workflows/platform-release.yml@refs/heads/main")

    def test_historical_and_ordinary_assets_and_actual_run_bindings_pass(self):
        validate(evidence())
        validate(evidence(False))

    def test_recovery_cannot_substitute_source_or_executor_claims(self):
        exact = evidence()
        mutations = [
            (("execution", "source_sha"), "a" * 40),
            (("execution", "tree_sha"), "bad"),
            (("execution", "main_ci", "head_sha"), "a" * 40),
            (("execution", "main_ci", "event"), "workflow_dispatch"),
            (("execution", "main_ci", "workflow"), "foreign.yml"),
            (("execution", "main_ci", "conclusion"), "failure"),
            (("execution", "main_ci", "ref"), "refs/heads/other"),
            (("execution", "main_ci", "run_id"), True),
            (("execution", "main_ci", "run_attempt"), 0),
            (("platform_release", "head_sha"), exact["source"]["merge_sha"]),
            (("platform_release", "event"), "workflow_run"),
            (("platform_release", "workflow"), ".github/workflows/platform-release.yml"),
            (("platform_release", "run_attempt"), 2),
            (("main_ci", "run_id"), 401),
            (("main_ci", "run_attempt"), 2),
            (("source", "tree_sha"), "a" * 40),
            (("changelog", "fragment_sha256"), "sha256:" + "0" * 64),
            (("predecessor", "peeled_commit"), "a" * 40),
        ]
        for path, replacement in mutations:
            changed = copy.deepcopy(exact)
            parent = changed
            for part in path[:-1]:
                parent = parent[part]
            parent[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises((C.ContractError, ValueError)):
                validate(changed, run_records=False)
        for field in ("source_sha", "tree_sha", "main_ci"):
            changed = copy.deepcopy(exact)
            del changed["execution"][field]
            with self.subTest(missing=field), self.assertRaises(C.ContractError):
                validate(changed)

    def test_ordinary_publication_cannot_claim_a_different_executor(self):
        changed = evidence(False)
        changed["execution"]["source_sha"] = "a" * 40
        changed["execution"]["main_ci"]["head_sha"] = "a" * 40
        changed["platform_release"]["head_sha"] = "a" * 40
        with self.assertRaises(C.ContractError):
            validate(changed)

    def test_original_failed_or_running_attempt_cannot_be_replaced_by_later_success(self):
        identity, _, _, runs = records(evidence())
        for index in (0, 1, 2):
            for field, value in (("conclusion", "failure"), ("conclusion", "cancelled"),
                                 ("status", "in_progress"), ("run_attempt", 2),
                                 ("id", 999), ("head_sha", "a" * 40)):
                changed = copy.deepcopy(runs)
                changed[index][field] = value
                with self.subTest(index=index, field=field, value=value), self.assertRaises(C.ContractError):
                    C.validate_identity_run_records(identity, changed[0], changed[1], execution_main_run_record=changed[2])
        with self.assertRaisesRegex(C.ContractError, "requires executor main CI proof"):
            C.validate_identity_run_records(identity, runs[0], runs[1])
        for repository_id in (True, 1):
            changed = evidence()
            changed["repository_id"] = repository_id
            raw, _, _, actual = records(changed)
            with self.assertRaisesRegex(C.ContractError, "run identity epoch"):
                C.validate_identity_run_records(raw, *actual[:2], execution_main_run_record=actual[2])
        changed = copy.deepcopy(runs)
        changed[2]["head_commit"]["tree_id"] = "a" * 40
        with self.assertRaises(C.ContractError):
            C.validate_identity_run_records(identity, changed[0], changed[1], execution_main_run_record=changed[2])

    def test_pending_reader_mode_never_substitutes_original_identity_or_success(self):
        identity, _, _, runs = records(evidence())
        for status in ("queued", "in_progress", "pending", "requested", "waiting"):
            pending = copy.deepcopy(runs)
            pending[1].update(status=status, conclusion=None)
            C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2], platform_pending=True)
            with self.assertRaises(C.ContractError):
                C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2])
            for row, field, replacement in ((0, "status", "queued"), (2, "status", "queued"),
                    (1, "conclusion", "success"), (1, "conclusion", "failure"), (1, "status", "unknown"),
                    (1, "status", "completed"), (1, "id", 501), (1, "run_attempt", 2), (1, "head_sha", "a" * 40)):
                changed = copy.deepcopy(pending)
                changed[row][field] = replacement
                with self.subTest(status=status, row=row, field=field), self.assertRaises(C.ContractError):
                    C.validate_identity_run_records(identity, *changed[:2], execution_main_run_record=changed[2], platform_pending=True)
            with self.assertRaises(C.ContractError):
                C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2],
                                                platform_pending=True, platform_conclusion="failure")
        ordinary, _, _, ordinary_runs = records(evidence(False))
        # Equal source/executor may reuse the same exact main record; unlike
        # recovery this path does not require a separately supplied record.
        C.validate_identity_run_records(ordinary, *ordinary_runs[:2])
        legacy = evidence(False)
        del legacy["execution"]
        legacy["schema"] = "https://snaraj.dev/schemas/platform-release-identity/v3"
        legacy["tag"]["name"] = legacy["release"]["tag_name"] = "v0.1.80"
        raw, _, _, prior_runs = records(legacy)
        prior_runs[1].update(status="in_progress", conclusion=None)
        with self.assertRaisesRegex(C.ContractError, "pending publisher classification"):
            C.validate_identity_run_records(raw, *prior_runs, platform_pending=True)
        for path, replacement in (("fragment_path", "changelog.d/1-foreign.md"), ("fragment_sha256", "sha256:" + "0" * 64)):
            value = evidence()
            value["changelog"][path] = replacement
            raw, _, _, changed_runs = records(value)
            with self.assertRaisesRegex(C.ContractError, "signed publication execution"):
                C.validate_identity_run_records(raw, *changed_runs[:2], execution_main_run_record=changed_runs[2])

    def test_default_target_hint_is_exact_and_does_not_replace_the_tag_source(self):
        for target in ("master", EXECUTOR, evidence()["source"]["merge_sha"], "refs/heads/main"):
            changed = evidence()
            changed["release"]["target_commitish"] = target
            with self.subTest(target=target), self.assertRaises(C.ContractError):
                validate(changed)

    def test_renderer_separates_actual_execution_and_preserves_source(self):
        expected = evidence()
        source = expected["source"]["merge_sha"]
        window = C.TransitionWindow(expected["predecessor"]["peeled_commit"], "v0.1.80",
                                    C.Intent(source, C.Version(0, 1, 81)),
                                    expected["changelog"]["fragment_path"], expected["changelog"]["fragment_sha256"][7:])
        def git(_repository, *args):
            return expected["source"]["tree_sha"] if args[-1] == source + "^{tree}" else EXECUTOR_TREE
        with mock.patch.object(C, "_exact_commit", side_effect=lambda _repo, sha, _field: sha), mock.patch.object(C, "_git", side_effect=git), mock.patch.object(C, "discover_transition_window", return_value=window):
            kwargs = dict(expected_base_sha=window.base_sha, expected_base_tag=window.base_tag,
                tag_object_sha="b" * 40, release_id=300, main_run_id=expected["main_ci"]["run_id"],
                main_run_attempt=1, platform_run_id=500, platform_run_attempt=1,
                github_repository="snaraj/platform", github_repository_id=1327645656,
                execution_sha=EXECUTOR, execution_main_run_id=400, execution_main_run_attempt=1,
            )
            rendered = C.render_release_identity(ROOT, source, "v0.1.81", **kwargs)
            for change in ({"github_repository": None, "github_repository_id": None},
                           {"execution_main_run_id": None}, {"execution_main_run_id": True},
                           {"execution_main_run_id": 0}, {"execution_main_run_attempt": None},
                           {"execution_main_run_attempt": True}, {"execution_main_run_attempt": 0}):
                message = "repository" if "github_repository" in change else "executor main CI requires"
                with self.subTest(change=change), self.assertRaisesRegex(C.ContractError, message):
                    C.render_release_identity(ROOT, source, "v0.1.81", **{**kwargs, **change})
        self.assertEqual(json.loads(rendered), expected)
        ordinary = evidence(False)
        window = C.TransitionWindow(ordinary["predecessor"]["peeled_commit"], "v0.1.83",
                                    C.Intent(EXECUTOR, C.Version(0, 1, 84)), "changelog.d/1-example.md", "a" * 64)
        with mock.patch.object(C, "_exact_commit", side_effect=lambda _repo, sha, _field: sha), \
                mock.patch.object(C, "_git", return_value=EXECUTOR_TREE), \
                mock.patch.object(C, "discover_transition_window", return_value=window):
            rendered = C.render_release_identity(ROOT, EXECUTOR, "v0.1.84", expected_base_sha=window.base_sha,
                expected_base_tag=window.base_tag, tag_object_sha="b" * 40, release_id=300,
                main_run_id=400, main_run_attempt=1, platform_run_id=500, platform_run_attempt=1,
                github_repository="snaraj/platform", github_repository_id=1327645656)
        self.assertEqual(json.loads(rendered), ordinary)

    def test_schema_requires_closed_execution_and_only_documented_target_shapes(self):
        schema = json.loads((ROOT / "bootstrap/flux/release-selector/platform-release-identity.v4.schema.json").read_text())
        self.assertEqual(schema["$id"], "https://snaraj.dev/schemas/platform-release-identity/v4")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("execution", schema["required"])
        execution = schema["properties"]["execution"]
        self.assertEqual(execution["type"], "object")
        self.assertEqual(schema["properties"]["schema"], {"const": "https://snaraj.dev/schemas/platform-release-identity/v4"})
        self.assertFalse(execution["additionalProperties"])
        self.assertEqual(set(execution["required"]), {"source_sha", "tree_sha", "main_ci"})
        self.assertEqual(execution["properties"]["main_ci"], {"$ref": "#/properties/main_ci"})
        self.assertEqual(schema["properties"]["release"]["properties"]["target_commitish"], {"oneOf": [{"$ref": "#/$defs/sha"}, {"const": "main"}]})
        self.assertEqual(schema["properties"]["platform_release"]["properties"]["event"],
                         {"enum": ["workflow_run", "workflow_dispatch"]})
        self.assertEqual(schema["properties"]["platform_release"]["properties"]["workflow"],
                         {"enum": [".github/workflows/platform-release.yml", ".github/workflows/platform-release-recovery.yml"]})
        self.assertEqual(execution["properties"]["source_sha"], {"$ref": "#/$defs/sha"})
        self.assertEqual(execution["properties"]["tree_sha"], {"$ref": "#/$defs/sha"})
        # All old schema requirements carry forward unchanged except these
        # explicit source/executor additions. No inherited field becomes open.
        previous = json.loads((ROOT / "bootstrap/flux/release-selector/platform-release-identity.v3.schema.json").read_text())
        comparable = copy.deepcopy(schema)
        comparable["$id"] = previous["$id"]
        comparable["properties"]["schema"] = previous["properties"]["schema"]
        del comparable["properties"]["execution"]
        comparable["required"].remove("execution")
        for name in ("event", "workflow"):
            comparable["properties"]["platform_release"]["properties"][name] = previous["properties"]["platform_release"]["properties"][name]
        comparable["properties"]["release"]["properties"]["target_commitish"] = previous["properties"]["release"]["properties"]["target_commitish"]
        self.assertEqual(comparable, previous)


if __name__ == "__main__":
    unittest.main()
