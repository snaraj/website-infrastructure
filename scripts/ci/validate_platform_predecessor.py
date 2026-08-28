#!/usr/bin/env python3
"""Validate the sole zero-asset v0.1.40 predecessor at runtime.

v0.1.40 predates canonical signed release-identity assets. The exception is
therefore deliberately smaller than the canonical path: derive its source,
annotated-tag object, predecessor edge, and Release notes from the checked-out
tag ledger; then bind those facts to GitHub REST Release/tag records and the
one successful exact attempt of each required workflow. No historical SHA,
run ID, attempt, body, or artifact digest is compiled into this validator.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import platform_release_contract as release_contract  # noqa: E402


REPOSITORY = "snaraj/website-infrastructure"
PREDECESSOR_TAG = "v0.1.40"
SUCCESSOR_TAG = "v0.1.41"
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
MAIN_WORKFLOW = ".github/workflows/pull-request.yml"
PLATFORM_WORKFLOW = ".github/workflows/platform-release.yml"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


def fail(message: str) -> None:
    raise SystemExit(message)


def unique_object(path: Path):
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                fail(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    return unique


def load_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object(path),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON object {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain one JSON object")
    return value


def positive(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{label} is not one positive integer")
    return value


def sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        fail(f"{label} is not one lowercase commit SHA")
    return value


def git(repository: Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot derive predecessor from the local tag ledger: {exc}")


def validate_edge(base_tag: str, target_tag: str) -> None:
    if base_tag != PREDECESSOR_TAG or target_tag != SUCCESSOR_TAG:
        fail("zero-asset predecessor exception is only v0.1.40 to v0.1.41")


def derive_local_identity(repository: Path) -> dict[str, str]:
    """Derive all historical identity from the fetched, validated tag ledger."""
    repository = repository.resolve()
    tag_object_sha = sha(
        git(repository, "rev-parse", f"refs/tags/{PREDECESSOR_TAG}"),
        "local annotated tag object SHA",
    )
    if git(repository, "cat-file", "-t", tag_object_sha) != "tag":
        fail("v0.1.40 local tag is not annotated")
    source_sha = sha(
        git(repository, "rev-parse", f"refs/tags/{PREDECESSOR_TAG}^{{commit}}"),
        "local peeled commit SHA",
    )
    try:
        window = release_contract.discover_transition_window(repository, source_sha)
        notes = release_contract.render_release_notes(
            repository,
            source_sha,
            PREDECESSOR_TAG,
            expected_base_sha=window.base_sha,
            expected_base_tag=window.base_tag,
        )
    except release_contract.ContractError as exc:
        fail(f"v0.1.40 local release ledger is invalid: {exc}")
    if window.intent.tag != PREDECESSOR_TAG:
        fail("local release ledger does not derive v0.1.40")
    return {
        "notes": notes,
        "predecessor_sha": window.base_sha,
        "predecessor_tag": window.base_tag,
        "source_sha": source_sha,
        "tag_object_sha": tag_object_sha,
        "tagger_date": git(repository, "show", "-s", "--format=%cI", source_sha),
    }


def validate_release(
    release: Mapping[str, object], local: Mapping[str, str]
) -> int:
    release_id = positive(release.get("id"), "GitHub Release ID")
    try:
        release_contract.validate_release_record(
            release,
            tag=PREDECESSOR_TAG,
            source_sha=local["source_sha"],
            title=f"Platform {PREDECESSOR_TAG}",
            body=local["notes"],
        )
    except release_contract.ContractError as exc:
        fail(f"v0.1.40 immutable zero-asset GitHub Release is foreign: {exc}")
    if release.get("assets") != []:
        fail("v0.1.40 GitHub Release must have exactly zero assets")
    return release_id


def validate_tag(
    ref: Mapping[str, object],
    tag_record: Mapping[str, object],
    local: Mapping[str, str],
) -> None:
    expected_message = (
        f"Platform release {PREDECESSOR_TAG} from {local['source_sha']}"
    )
    ref_object = ref.get("object")
    if (
        not isinstance(ref_object, dict)
        or ref_object.get("sha") != local["tag_object_sha"]
    ):
        fail("v0.1.40 REST ref does not match the local annotated tag object")
    try:
        release_contract.validate_tag_record(
            ref,
            tag_record,
            tag=PREDECESSOR_TAG,
            source_sha=local["source_sha"],
            message=expected_message,
            tagger_name=BOT_NAME,
            tagger_email=BOT_EMAIL,
            tagger_date=local["tagger_date"],
        )
    except release_contract.ContractError as exc:
        fail(f"v0.1.40 annotated tag moved or conflicts: {exc}")


def validate_run_shape(
    run: Mapping[str, object],
    *,
    source_sha: str,
    event: str,
    workflow: str,
    label: str,
) -> tuple[int, int]:
    run_id = positive(run.get("id"), f"{label} run ID")
    run_attempt = positive(run.get("run_attempt"), f"{label} run attempt")
    repository = run.get("repository")
    if (
        run.get("event") != event
        or run.get("head_sha") != source_sha
        or run.get("head_branch") != "main"
        or run.get("path") != workflow
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(repository, dict)
        or repository.get("full_name") != REPOSITORY
    ):
        fail(f"v0.1.40 {label} run is partial, failed, or foreign")
    return run_id, run_attempt


def select_exact_run(
    listing: Mapping[str, object],
    *,
    source_sha: str,
    event: str,
    workflow: str,
    label: str,
) -> dict[str, int]:
    if set(listing) != {"total_count", "workflow_runs"}:
        fail(f"v0.1.40 {label} run listing is partial or foreign")
    runs = listing.get("workflow_runs")
    total = listing.get("total_count")
    if (
        not isinstance(total, int)
        or isinstance(total, bool)
        or total != 1
        or not isinstance(runs, list)
        or len(runs) != 1
        or not isinstance(runs[0], dict)
    ):
        fail(f"v0.1.40 must have one successful exact {label} run")
    run_id, attempt = validate_run_shape(
        runs[0],
        source_sha=source_sha,
        event=event,
        workflow=workflow,
        label=label,
    )
    return {"run_attempt": attempt, "run_id": run_id}


def validate_run_record(
    actual: Mapping[str, object],
    expected: Mapping[str, object],
    *,
    source_sha: str,
    event: str,
    workflow: str,
    label: str,
) -> None:
    run_id, attempt = validate_run_shape(
        actual,
        source_sha=source_sha,
        event=event,
        workflow=workflow,
        label=label,
    )
    if run_id != expected.get("run_id") or attempt != expected.get("run_attempt"):
        fail(f"v0.1.40 {label} attempt does not match its runtime query")


def validate_records(
    repository: Path,
    release: Mapping[str, object],
    ref: Mapping[str, object],
    tag_record: Mapping[str, object],
    main_runs: Mapping[str, object],
    platform_runs: Mapping[str, object],
) -> dict[str, object]:
    local = derive_local_identity(repository)
    release_id = validate_release(release, local)
    validate_tag(ref, tag_record, local)
    main = select_exact_run(
        main_runs,
        source_sha=local["source_sha"],
        event="push",
        workflow=MAIN_WORKFLOW,
        label="main CI",
    )
    platform = select_exact_run(
        platform_runs,
        source_sha=local["source_sha"],
        event="workflow_run",
        workflow=PLATFORM_WORKFLOW,
        label="platform release",
    )
    return {
        "main_ci": main,
        "platform_release": platform,
        "predecessor": {
            "peeled_commit": local["predecessor_sha"],
            "tag": local["predecessor_tag"],
        },
        "release": {
            "asset_count": 0,
            "id": release_id,
            "tag_name": PREDECESSOR_TAG,
            "target_commitish": local["source_sha"],
        },
        "source": {"merge_sha": local["source_sha"]},
        "tag": {
            "object_sha": local["tag_object_sha"],
            "peeled_commit": local["source_sha"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base-tag", required=True)
    parser.add_argument("--target-tag", required=True)
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--ref-json", type=Path, required=True)
    parser.add_argument("--tag-json", type=Path, required=True)
    parser.add_argument("--main-runs-json", type=Path, required=True)
    parser.add_argument("--platform-runs-json", type=Path, required=True)
    parser.add_argument("--main-run-json", type=Path)
    parser.add_argument("--platform-run-json", type=Path)
    parser.add_argument("--emit", action="store_true")
    arguments = parser.parse_args()

    validate_edge(arguments.base_tag, arguments.target_tag)
    if (arguments.main_run_json is None) != (arguments.platform_run_json is None):
        fail("both exact workflow-run attempt records are required together")
    derived = validate_records(
        arguments.repository,
        load_object(arguments.release_json),
        load_object(arguments.ref_json),
        load_object(arguments.tag_json),
        load_object(arguments.main_runs_json),
        load_object(arguments.platform_runs_json),
    )
    if arguments.main_run_json is not None:
        source = derived["source"]
        assert isinstance(source, dict)
        source_sha = source["merge_sha"]
        assert isinstance(source_sha, str)
        validate_run_record(
            load_object(arguments.main_run_json),
            derived["main_ci"],
            source_sha=source_sha,
            event="push",
            workflow=MAIN_WORKFLOW,
            label="main CI",
        )
        validate_run_record(
            load_object(arguments.platform_run_json),
            derived["platform_release"],
            source_sha=source_sha,
            event="workflow_run",
            workflow=PLATFORM_WORKFLOW,
            label="platform release",
        )
    if arguments.emit:
        print(json.dumps(derived, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
