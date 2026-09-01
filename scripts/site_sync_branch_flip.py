"""Fail-closed tooling for the site-sync branch-flip ceremony (issue #275).

The ceremony in ``docs/runbooks/site-sync-branch-flip.md`` moves the live
``flux-system`` GitRepository from the selector-advanced platform tag to
protected ``main``. Every load-bearing judgment in that ceremony lives HERE,
where tests can pin it, instead of in runbook prose (PR #272 round-2
findings): the trust-anchor receipt proves the exact protecting ruleset;
quiescence reuses the bootstrap validator's owner-UID/terminal-state logic
(a label-filtered ``kubectl get jobs`` misses selector Jobs, which carry no
labels); the prestate is a bounded semantic capture with private, atomic
custody; both live mutations are emitted as JSON patches whose ``test``
operations bind the object UID and the contested ref field, so a concurrent
writer loses the race loudly instead of being overwritten; and the
outside-in proof is an executable probe with exact singleton expectations,
not an operator improvisation.

The tool NEVER contacts the cluster. Cluster state goes in as ``kubectl get
-o json`` captures and mutations come out as patch documents for ``kubectl
patch --type=json``; only ``verify-live`` speaks HTTPS, anonymously, to the
public site and registry. Standard library only.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import importlib.util
import json
import os
import re
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import NoReturn

try:  # executed as a script: scripts/ is sys.path[0]
    import validate_platform_bootstrap as bootstrap
except ImportError:  # loaded by file path (the test batteries' loader)
    _spec = importlib.util.spec_from_file_location(
        "validate_platform_bootstrap",
        Path(__file__).resolve().parent / "validate_platform_bootstrap.py",
    )
    if _spec is None or _spec.loader is None:
        raise AssertionError("validate_platform_bootstrap.py is unloadable")
    bootstrap = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(bootstrap)

NAMESPACE = "flux-system"
SOURCE_NAME = "flux-system"
ANNOTATION_PREFIX = "release-selector.platform.snaraj.dev/"
RESERVED_ANNOTATIONS = tuple(
    ANNOTATION_PREFIX + suffix
    for suffix in (
        "schema",
        "release-id",
        "release-tag",
        "release-target-sha",
        "tag-object-sha",
        "main-ci",
        "platform-release",
        "selector-image-digest",
        "identity-sha256",
    )
)

# The exact ruleset that makes protected main the trust anchor. The ceremony
# refuses to proceed if the live document has weakened in ANY field below.
# Every rule parameter is compared verbatim — a receipt that dropped
# parameters would still pass after do_not_enforce_on_create or a
# pull-request control was flipped (round-2 security finding 5). The only
# fields deliberately outside the comparison are node_id, created_at,
# updated_at, and _links: pure identifiers/timestamps that cannot relax an
# enforced control.
EXPECTED_RULESET = {
    "id": 20601016,
    "name": "only-me-merge",
    "target": "branch",
    "source_type": "Repository",
    "source": "snaraj/website-infrastructure",
    "enforcement": "active",
    "bypass_actors": [],
    "current_user_can_bypass": "never",
    "conditions": {"ref_name": {"exclude": [], "include": ["refs/heads/main"]}},
    "rules": [
        {"type": "creation", "parameters": {}},
        {"type": "deletion", "parameters": {}},
        {"type": "non_fast_forward", "parameters": {}},
        {"type": "required_linear_history", "parameters": {}},
        {"type": "required_signatures", "parameters": {}},
        {
            "type": "pull_request",
            "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": False,
                "required_reviewers": [],
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_review_thread_resolution": False,
                "require_extra_approval_for_unattributed_changes": True,
                "allowed_merge_methods": ["squash", "rebase"],
            },
        },
        {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
                "required_status_checks": [
                    {"context": "dependency-review", "integration_id": 15368},
                    {
                        "context": "repository-and-infrastructure",
                        "integration_id": 15368,
                    },
                ],
            },
        },
    ],
}
# A listing this long may be one truncated page (the ceremony captures with
# per_page=100): refuse rather than reason about an inventory that might
# hide a second branch-target ruleset past the page boundary.
RULESET_LISTING_BOUND = 100

# The closed live GitRepository shape (round-2 security finding 1): exactly
# these spec keys, with the selection/authentication/artifact-shaping fields
# bound to the reviewed values. A key outside this set — secretRef,
# proxySecretRef, serviceAccountName, recurseSubmodules, include, verify,
# suspend — is refused by the closed-set comparison itself.
SOURCE_API_VERSION = "source.toolkit.fluxcd.io/v1"
SOURCE_URL = "https://github.com/snaraj/website-infrastructure.git"
SOURCE_SPEC_KEYS = frozenset(
    {"ignore", "interval", "ref", "sparseCheckout", "timeout", "url"}
)
SOURCE_INTERVAL = "1m0s"
SOURCE_TIMEOUT = "60s"
SOURCE_IGNORE = (
    "/*\n"
    "!/kubernetes/\n"
    "/kubernetes/*\n"
    "!/kubernetes/websites/\n"
    "/kubernetes/websites/*\n"
    "!/kubernetes/websites/naranjo-online/\n"
    "!/kubernetes/websites/naranjo-online/**\n"
    "!/kubernetes/websites/lidersea-com/\n"
    "!/kubernetes/websites/lidersea-com/**\n"
)
SPARSE_ENTRY = re.compile(
    r"^\.?/?kubernetes/websites/(naranjo-online|lidersea-com)/?$"
)

# The reviewed selector CronJob identity (round-2 security finding 2): the
# quiescence receipt binds the object it suspends, so rollback can never
# activate a foreign or replaced CronJob.
SELECTOR_SCHEDULE = "7,37 * * * *"
SELECTOR_SERVICE_ACCOUNT = "platform-release-selector"
SELECTOR_IMAGE = re.compile(
    r"^ghcr\.io/snaraj/website-infrastructure/platform-release-selector"
    r"@sha256:[0-9a-f]{64}$"
)
# The live asset must be a real stylesheet, not a stub that could appear in
# an unrelated layer by coincidence.
MIN_ASSET_BYTES = 1024

# The ordered ceremony, canonically. docs/runbooks/site-sync-branch-flip.md
# must carry EXACTLY these fenced command blocks, in this order, and no
# other kubectl/python3/flux/gh invocation anywhere — the battery compares
# structurally, so a neutralized invocation, a narrowed capture, or a
# retargeted patch is a red test, not a prose drift (round-2 security
# finding 3). Editing a block here and in the runbook together is the one
# sanctioned way the ceremony changes.
CEREMONY_BLOCKS = (
    'scratch="$(mktemp -d)"\n',
    "gh api 'repos/snaraj/website-infrastructure/rulesets?per_page=100'"
    ' > "$scratch/rulesets.json"\n'
    "gh api repos/snaraj/website-infrastructure/rulesets/20601016"
    ' > "$scratch/ruleset.json"\n'
    "python3 -I -B scripts/site_sync_branch_flip.py ruleset-receipt"
    ' "$scratch/rulesets.json" "$scratch/ruleset.json"\n',
    "kubectl get cronjob -n flux-system platform-release-selector -o json"
    ' > "$scratch/cronjob.json"\n'
    "python3 -I -B scripts/site_sync_branch_flip.py selector-prestate"
    ' "$scratch/cronjob.json" --receipt-dir "$scratch"\n',
    "python3 -I -B scripts/site_sync_branch_flip.py suspend-patch"
    ' "$scratch/selector-prestate.json" > "$scratch/suspend.json"\n'
    "kubectl patch cronjob -n flux-system platform-release-selector"
    ' --type=json --patch-file "$scratch/suspend.json"\n',
    "kubectl get cronjob -n flux-system platform-release-selector -o json"
    ' > "$scratch/cronjob-now.json"\n'
    'kubectl get jobs -n flux-system -o json > "$scratch/jobs.json"\n'
    'kubectl get pods -n flux-system -o json > "$scratch/pods.json"\n'
    "python3 -I -B scripts/site_sync_branch_flip.py quiescence"
    ' "$scratch/cronjob-now.json" "$scratch/jobs.json" "$scratch/pods.json"\n',
    "kubectl get gitrepository -n flux-system flux-system -o json"
    ' > "$scratch/gitrepository.json"\n'
    "python3 -I -B scripts/site_sync_branch_flip.py prestate"
    ' "$scratch/gitrepository.json" --receipt-dir "$scratch"\n',
    "python3 -I -B scripts/site_sync_branch_flip.py flip-patch"
    ' "$scratch/flip-prestate.json" > "$scratch/flip.json"\n'
    "kubectl patch gitrepository -n flux-system flux-system --type=json"
    ' --patch-file "$scratch/flip.json"\n',
    "kubectl get gitrepository -n flux-system flux-system -o json"
    ' > "$scratch/post.json"\n'
    "python3 -I -B scripts/site_sync_branch_flip.py poststate"
    ' "$scratch/post.json" "$scratch/flip-prestate.json"\n',
    "flux reconcile source git flux-system -n flux-system\n"
    "flux reconcile kustomization naranjo-online-reconciler -n flux-system\n"
    "flux reconcile kustomization lidersea-com-reconciler -n flux-system\n",
    "kubectl get gitrepository -n flux-system flux-system"
    " -o jsonpath='{.status.artifact.revision}'\n",
    "python3 -I -B scripts/site_sync_branch_flip.py verify-live"
    " kubernetes/websites/naranjo-online/source.yaml https://naranjo.online\n"
    "python3 -I -B scripts/site_sync_branch_flip.py verify-live"
    " kubernetes/websites/lidersea-com/source.yaml https://lidersea.com\n",
    "python3 -I -B scripts/site_sync_branch_flip.py rollback-patch"
    ' "$scratch/flip-prestate.json" > "$scratch/rollback.json"\n'
    "kubectl patch gitrepository -n flux-system flux-system --type=json"
    ' --patch-file "$scratch/rollback.json"\n'
    "kubectl get gitrepository -n flux-system flux-system -o json"
    ' > "$scratch/rolled-back.json"\n'
    "python3 -I -B scripts/site_sync_branch_flip.py rollback-verify"
    ' "$scratch/rolled-back.json" "$scratch/flip-prestate.json"\n',
    "python3 -I -B scripts/site_sync_branch_flip.py resume-patch"
    ' "$scratch/selector-prestate.json" > "$scratch/resume.json"\n'
    "kubectl patch cronjob -n flux-system platform-release-selector"
    ' --type=json --patch-file "$scratch/resume.json"\n'
    "kubectl get cronjob -n flux-system platform-release-selector -o json"
    ' > "$scratch/cronjob-final.json"\n'
    "python3 -I -B scripts/site_sync_branch_flip.py resume-verify"
    ' "$scratch/cronjob-final.json" "$scratch/selector-prestate.json"\n'
    "flux reconcile source git flux-system -n flux-system\n",
)

HELM_CONTENT_TYPE = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
BUNDLE_PATTERN = re.compile(r"assets/index-[A-Za-z0-9_-]+\.css")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


def fail(message) -> NoReturn:
    raise SystemExit("DENY: " + message)


def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        fail("cannot read JSON capture {}: {}".format(path, error))


def normalized_rules(rules):
    """The complete rule inventory, parameters verbatim, deterministically
    ordered. Nothing is projected away: a dropped parameter is a field the
    receipt would silently stop defending."""

    if not isinstance(rules, list):
        fail("ruleset rules are not a list")
    reduced = []
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            fail("ruleset rule is malformed")
        parameters = json.loads(json.dumps(rule.get("parameters") or {}))
        checks = parameters.get("required_status_checks")
        if isinstance(checks, list):
            parameters["required_status_checks"] = sorted(
                checks, key=lambda check: str(check.get("context"))
            )
        reduced.append({"type": rule["type"], "parameters": parameters})
    return sorted(reduced, key=lambda rule: rule["type"])


def ruleset_receipt(rulesets, ruleset):
    """Prove the exact no-bypass ruleset protects refs/heads/main, entirely."""

    if not isinstance(rulesets, list):
        fail("ruleset listing is not a list")
    if len(rulesets) >= RULESET_LISTING_BOUND:
        fail(
            "ruleset listing carries {} entries — a full page may be a "
            "truncated one, and a hidden branch ruleset past the boundary "
            "would evade the inventory; capture with --paginate and a "
            "higher per_page".format(len(rulesets))
        )
    branch_ids = [
        entry.get("id")
        for entry in rulesets
        if isinstance(entry, dict) and entry.get("target") == "branch"
    ]
    if branch_ids != [EXPECTED_RULESET["id"]]:
        fail(
            "branch-target ruleset inventory is {} — expected exactly "
            "[{}]".format(branch_ids, EXPECTED_RULESET["id"])
        )
    observed = {
        "id": ruleset.get("id"),
        "name": ruleset.get("name"),
        "target": ruleset.get("target"),
        "source_type": ruleset.get("source_type"),
        "source": ruleset.get("source"),
        "enforcement": ruleset.get("enforcement"),
        "bypass_actors": ruleset.get("bypass_actors"),
        "current_user_can_bypass": ruleset.get("current_user_can_bypass"),
        "conditions": ruleset.get("conditions"),
        "rules": normalized_rules(ruleset.get("rules")),
    }
    expected = dict(EXPECTED_RULESET)
    expected["rules"] = normalized_rules(EXPECTED_RULESET["rules"])
    if observed != expected:
        fail(
            "protecting ruleset drifted from the reviewed anchor:\n"
            "observed {}\nexpected {}".format(
                json.dumps(observed, indent=2, sort_keys=True),
                json.dumps(expected, indent=2, sort_keys=True),
            )
        )
    return "RECEIPT ruleset {} '{}' anchors refs/heads/main with no bypass".format(
        observed["id"], observed["name"]
    )


def selector_identity(cronjob):
    """The reviewed selector CronJob, closed on its load-bearing identity:
    a suspension receipt for a foreign, replaced, or lookalike CronJob
    would let rollback activate an unproved object (round-2 security
    finding 2). Returns (uid, resourceVersion, image, suspend)."""

    metadata = cronjob.get("metadata")
    if (
        cronjob.get("apiVersion") != "batch/v1"
        or cronjob.get("kind") != "CronJob"
        or not isinstance(metadata, dict)
        or metadata.get("name") != "platform-release-selector"
        or metadata.get("namespace") != NAMESPACE
    ):
        fail("capture is not the flux-system platform-release-selector CronJob")
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    if not isinstance(uid, str) or not uid:
        fail("selector CronJob UID is absent")
    if not isinstance(resource_version, str) or not resource_version:
        fail("selector CronJob resourceVersion is absent")
    spec = cronjob.get("spec")
    if not isinstance(spec, dict):
        fail("selector CronJob spec is absent")
    if spec.get("schedule") != SELECTOR_SCHEDULE:
        fail(
            "selector schedule is {!r} — the reviewed selector runs "
            "{!r}".format(spec.get("schedule"), SELECTOR_SCHEDULE)
        )
    if spec.get("concurrencyPolicy") != "Forbid":
        fail("selector concurrencyPolicy is not Forbid")
    pod = (
        spec.get("jobTemplate", {})
        .get("spec", {})
        .get("template", {})
        .get("spec", {})
    )
    if pod.get("serviceAccountName") != SELECTOR_SERVICE_ACCOUNT:
        fail(
            "selector serviceAccountName is {!r} — the reviewed identity "
            "is {!r}".format(
                pod.get("serviceAccountName"), SELECTOR_SERVICE_ACCOUNT
            )
        )
    containers = pod.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        fail("selector job template must carry exactly one container")
    image = containers[0].get("image")
    if not isinstance(image, str) or SELECTOR_IMAGE.match(image) is None:
        fail(
            "selector image is {!r} — the reviewed identity is the "
            "digest-pinned selector image".format(image)
        )
    suspend = spec.get("suspend")
    if suspend is not True and suspend is not False:
        fail("selector spec.suspend is not an explicit boolean")
    return uid, resource_version, image, suspend


def quiescence(cronjob, jobs, pods):
    """Suspension of the PROVEN selector, zero live executions by lineage,
    and capture-completeness: every Job the CronJob's own status still
    names as active must appear in the supplied inventory, so a narrowed
    jobs capture cannot hide a running execution behind an empty list."""

    uid, _, _, suspend = selector_identity(cronjob)
    if suspend is not True:
        fail("selector CronJob is not suspended")
    supplied = {
        item.get("metadata", {}).get("uid")
        for item in jobs.get("items", [])
        if isinstance(item, dict)
    }
    for reference in cronjob.get("status", {}).get("active") or []:
        if reference.get("uid") not in supplied:
            fail(
                "the CronJob's own status names active Job {} but the "
                "supplied inventory does not contain it — the capture is "
                "incomplete or filtered".format(reference.get("name"))
            )
    bootstrap.selector_quiescent(cronjob, jobs, pods)
    return (
        "RECEIPT selector {} suspended and quiescent (closed identity, "
        "owner-UID lineage, terminal states, status-complete "
        "inventory)".format(uid)
    )


def selector_prestate(cronjob, receipt_dir):
    """Private, atomic capture of the selector's pre-ceremony state — the
    rollback authority for suspend/resume. Records whether the selector
    was ALREADY suspended: a rollback never resumes an object the
    ceremony did not suspend."""

    uid, resource_version, image, suspend = selector_identity(cronjob)
    document = {
        "schema": "site-sync-branch-flip/selector-prestate/v1",
        "uid": uid,
        "resourceVersion": resource_version,
        "image": image,
        "suspend": suspend,
    }
    return write_receipt(
        document, receipt_dir, "selector-prestate.json",
        "suspend={}".format(suspend),
    )


def load_selector_prestate(path):
    document = load_json(path)
    if (
        document.get("schema") != "site-sync-branch-flip/selector-prestate/v1"
        or not isinstance(document.get("uid"), str)
        or not isinstance(document.get("image"), str)
        or not isinstance(document.get("suspend"), bool)
    ):
        fail("selector prestate document is not a valid v1 capture")
    return document


def suspend_patch(document):
    if document["suspend"] is True:
        fail(
            "the selector was ALREADY suspended before the ceremony — "
            "there is nothing to suspend, and rollback must not resume it"
        )
    return json.dumps(
        [
            {"op": "test", "path": "/metadata/uid", "value": document["uid"]},
            {
                "op": "test",
                "path": "/spec/jobTemplate/spec/template/spec/containers/0/image",
                "value": document["image"],
            },
            {"op": "test", "path": "/spec/suspend", "value": False},
            {"op": "replace", "path": "/spec/suspend", "value": True},
        ]
    )


def resume_patch(document):
    if document["suspend"] is True:
        fail(
            "the selector was suspended BEFORE the ceremony — resuming it "
            "is not a rollback of anything this ceremony did; leave it to "
            "the owner"
        )
    return json.dumps(
        [
            {"op": "test", "path": "/metadata/uid", "value": document["uid"]},
            {
                "op": "test",
                "path": "/spec/jobTemplate/spec/template/spec/containers/0/image",
                "value": document["image"],
            },
            {"op": "test", "path": "/spec/suspend", "value": True},
            {"op": "replace", "path": "/spec/suspend", "value": False},
        ]
    )


def resume_verify(cronjob, document):
    uid, _, image, suspend = selector_identity(cronjob)
    if uid != document["uid"]:
        fail("live CronJob UID changed — this is not the captured selector")
    if image != document["image"]:
        fail("live selector image drifted from the captured identity")
    if suspend != document["suspend"]:
        fail(
            "live suspend is {} — the captured pre-ceremony state was "
            "{}".format(suspend, document["suspend"])
        )


def source_shape(gitrepository):
    """The closed live GitRepository shape: exactly the reviewed spec keys,
    the selection/artifact fields bound to reviewed values, and therefore
    the structural ABSENCE of secretRef, proxySecretRef, serviceAccountName,
    recurseSubmodules, include, verify, and suspend. Flux defines those as
    repository selection, authentication, and artifact-shaping inputs, so a
    receipt that ignored them could bless a foreign or credentialed source
    (round-2 security finding 1). Returns the validated spec."""

    if gitrepository.get("apiVersion") != SOURCE_API_VERSION:
        fail(
            "GitRepository apiVersion is {!r} — expected {}".format(
                gitrepository.get("apiVersion"), SOURCE_API_VERSION
            )
        )
    spec = gitrepository.get("spec")
    if not isinstance(spec, dict) or set(spec) != SOURCE_SPEC_KEYS:
        fail(
            "GitRepository spec keys are {} — the reviewed closed shape is "
            "exactly {}".format(
                sorted(spec) if isinstance(spec, dict) else spec,
                sorted(SOURCE_SPEC_KEYS),
            )
        )
    for key, expected in (
        ("url", SOURCE_URL),
        ("interval", SOURCE_INTERVAL),
        ("timeout", SOURCE_TIMEOUT),
        ("ignore", SOURCE_IGNORE),
    ):
        if spec.get(key) != expected:
            fail(
                "GitRepository spec.{} is {!r} — the reviewed value is "
                "{!r}".format(key, spec.get(key), expected)
            )
    sparse = spec.get("sparseCheckout")
    matches = (
        [SPARSE_ENTRY.match(str(entry)) for entry in sparse]
        if isinstance(sparse, list)
        else []
    )
    if (
        len(matches) != 2
        or any(match is None for match in matches)
        or {match.group(1) for match in matches}
        != {"naranjo-online", "lidersea-com"}
    ):
        fail(
            "GitRepository sparseCheckout is {!r} — expected exactly the "
            "two site directories".format(sparse)
        )
    return spec


def source_identity(gitrepository):
    metadata = gitrepository.get("metadata")
    if (
        not isinstance(metadata, dict)
        or metadata.get("name") != SOURCE_NAME
        or metadata.get("namespace") != NAMESPACE
        or gitrepository.get("kind") != "GitRepository"
    ):
        fail("capture is not the flux-system GitRepository")
    source_shape(gitrepository)
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    if not isinstance(uid, str) or not uid:
        fail("GitRepository UID is absent")
    if not isinstance(resource_version, str) or not resource_version:
        fail("GitRepository resourceVersion is absent")
    annotations = metadata.get("annotations")
    if not isinstance(annotations, dict):
        fail("GitRepository annotations are absent")
    reserved = {}
    for key in RESERVED_ANNOTATIONS:
        value = annotations.get(key)
        if not isinstance(value, str) or not value:
            fail("reserved annotation {} is absent — the suspended selector "
                 "cannot reactivate without it".format(key))
        reserved[key] = value
    return uid, resource_version, reserved


def write_receipt(document, receipt_dir, filename, note):
    """Atomic private receipt custody, shared by both prestate captures."""

    directory = Path(receipt_dir)
    if not directory.is_dir():
        fail("receipt directory {} does not exist".format(receipt_dir))
    mode = directory.stat().st_mode & 0o777
    if mode & 0o077:
        fail(
            "receipt directory {} is group/world accessible (mode {:o}) — "
            "use a fresh `mktemp -d`".format(receipt_dir, mode)
        )
    serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
    final = directory / filename
    if final.exists():
        fail("{} already exists — refuse to overwrite a prior capture".format(final))
    staged = directory / (".{}.staged".format(filename))
    descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(serialized)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(staged, final)
    digest = hashlib.sha256(serialized.encode()).hexdigest()
    if final.read_text() != serialized or final.stat().st_mode & 0o077:
        fail("receipt {} failed its own revalidation".format(filename))
    return "RECEIPT {} sha256:{} {}".format(final, digest, note)


def prestate(gitrepository, receipt_dir):
    """Bounded semantic prestate, written atomically under private custody."""

    uid, resource_version, reserved = source_identity(gitrepository)
    spec = gitrepository["spec"]
    ref = spec.get("ref")
    if not isinstance(ref, dict) or set(ref) != {"tag"} or not ref.get("tag"):
        fail("live ref is {} — the flip starts from exactly {{tag}}".format(ref))
    document = {
        "schema": "site-sync-branch-flip/prestate/v2",
        "uid": uid,
        "resourceVersion": resource_version,
        "ref": {"tag": ref["tag"]},
        "spec": {key: spec[key] for key in sorted(SOURCE_SPEC_KEYS - {"ref"})},
        "annotations": reserved,
    }
    return write_receipt(
        document, receipt_dir, "flip-prestate.json", "tag={}".format(ref["tag"])
    )


def load_prestate(path):
    document = load_json(path)
    if (
        document.get("schema") != "site-sync-branch-flip/prestate/v2"
        or not isinstance(document.get("uid"), str)
        or not isinstance(document.get("ref"), dict)
        or set(document["ref"]) != {"tag"}
        or not isinstance(document.get("spec"), dict)
        or set(document["spec"]) != SOURCE_SPEC_KEYS - {"ref"}
        or sorted(document.get("annotations", {})) != sorted(RESERVED_ANNOTATIONS)
    ):
        fail("prestate document is not a valid v2 capture")
    return document


def flip_patch(document):
    """The flip as a UID- and field-bound compare-and-swap patch."""

    return json.dumps(
        [
            {"op": "test", "path": "/metadata/uid", "value": document["uid"]},
            {"op": "test", "path": "/spec/ref/tag", "value": document["ref"]["tag"]},
            {"op": "remove", "path": "/spec/ref/tag"},
            {"op": "add", "path": "/spec/ref/branch", "value": "main"},
        ]
    )


def rollback_patch(document):
    return json.dumps(
        [
            {"op": "test", "path": "/metadata/uid", "value": document["uid"]},
            {"op": "test", "path": "/spec/ref/branch", "value": "main"},
            {"op": "remove", "path": "/spec/ref/branch"},
            {"op": "add", "path": "/spec/ref/tag", "value": document["ref"]["tag"]},
        ]
    )


def state_matches(gitrepository, document, expected_ref):
    uid, _, reserved = source_identity(gitrepository)
    if uid != document["uid"]:
        fail("live object UID changed — this is not the captured GitRepository")
    spec = gitrepository["spec"]
    if spec.get("ref") != expected_ref:
        fail(
            "live ref is {} — expected exactly {}".format(
                spec.get("ref"), expected_ref
            )
        )
    for key in sorted(SOURCE_SPEC_KEYS - {"ref"}):
        if spec.get(key) != document["spec"][key]:
            fail(
                "live spec.{} drifted from the prestate capture — the flip "
                "must never bless concurrent source drift".format(key)
            )
    if reserved != document["annotations"]:
        fail("reserved annotations drifted from the prestate capture")


def http_get(url, headers=None, limit=64 * 1024 * 1024):
    merged = {"User-Agent": "site-sync-branch-flip/1 (WI ceremony probe)"}
    merged.update(headers or {})
    request = urllib.request.Request(url, headers=merged)
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read(limit + 1)
    if len(payload) > limit:
        fail("response from {} exceeds the {}-byte bound".format(url, limit))
    return payload


def ghcr_token(repository):
    payload = http_get(
        "https://ghcr.io/token?scope=repository:{}:pull".format(repository)
    )
    return json.loads(payload)["token"]


def ghcr_json(repository, reference, accept, token):
    payload = http_get(
        "https://ghcr.io/v2/{}/manifests/{}".format(repository, reference),
        {"Authorization": "Bearer " + token, "Accept": accept},
    )
    # Every manifest this probe fetches is addressed by digest, and the blob
    # checks downstream validate against digests read out of THIS document —
    # so an unverified manifest would let a hostile registry substitute the
    # whole tree while every blob check passes.
    if reference.startswith("sha256:"):
        observed = "sha256:" + hashlib.sha256(payload).hexdigest()
        if observed != reference:
            fail(
                "manifest {} hashed to {} — registry content lied".format(
                    reference, observed
                )
            )
    return json.loads(payload)


def ghcr_blob(repository, digest, token):
    payload = http_get(
        "https://ghcr.io/v2/{}/blobs/{}".format(repository, digest),
        {"Authorization": "Bearer " + token},
    )
    observed = "sha256:" + hashlib.sha256(payload).hexdigest()
    if observed != digest:
        fail("blob {} hashed to {} — registry content lied".format(digest, observed))
    return payload


def verify_live(source_text, site_url):
    """Outside-in: the live page's bundle exists inside the exact committed
    selection's image bytes, resolved digest-by-digest with singleton checks.
    """

    url_match = re.search(r"url:\s*oci://ghcr\.io/(\S+)", source_text)
    digest_match = re.search(r"digest:\s*(sha256:[0-9a-f]{64})", source_text)
    if not url_match or not digest_match:
        fail("source.yaml carries no ghcr chart URL and digest")
    chart_repository, chart_digest = url_match.group(1), digest_match.group(1)

    page = http_get(site_url.rstrip("/") + "/", limit=4 * 1024 * 1024).decode(
        "utf-8", "replace"
    )
    bundles = sorted(set(BUNDLE_PATTERN.findall(page)))
    if len(bundles) != 1:
        fail("live page names {} CSS bundles — expected exactly one".format(len(bundles)))
    bundle = bundles[0].split("/", 1)[1]
    # The proof object is the asset's CONTENT, not its name: a filename
    # string can occur in an unrelated layer, log, or stale workload, but
    # the exact served bytes existing verbatim inside the committed image
    # ties what the visitor receives to what the owner reviewed (round-2
    # security finding 4).
    asset = http_get(
        site_url.rstrip("/") + "/" + bundles[0], limit=4 * 1024 * 1024
    )
    if len(asset) < MIN_ASSET_BYTES:
        fail(
            "live asset {} is {} bytes — too small to be the fingerprinted "
            "stylesheet this probe binds".format(bundle, len(asset))
        )

    ready = http_get(site_url.rstrip("/") + "/readyz", limit=4096)
    if not ready:
        fail("/readyz returned an empty body")

    token = ghcr_token(chart_repository)
    manifest = ghcr_json(
        chart_repository,
        chart_digest,
        "application/vnd.oci.image.manifest.v1+json",
        token,
    )
    content_layers = [
        layer
        for layer in manifest.get("layers", [])
        if layer.get("mediaType") == HELM_CONTENT_TYPE
    ]
    if len(content_layers) != 1:
        fail(
            "chart manifest carries {} Helm content layers — expected exactly "
            "one".format(len(content_layers))
        )
    chart_bytes = ghcr_blob(chart_repository, content_layers[0]["digest"], token)
    values_text = None
    with tarfile.open(fileobj=io.BytesIO(chart_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isreg() or member.name.count("/") != 1:
                continue
            if member.name.split("/", 1)[1] == "values.yaml":
                extracted = archive.extractfile(member)
                values_text = extracted.read().decode() if extracted else None
    if values_text is None:
        fail("chart layer carries no values.yaml")
    image_digests = sorted(set(DIGEST_PATTERN.findall(values_text)))
    repository_match = re.search(
        r"repository:\s*ghcr\.io/(\S+)", values_text
    )
    if len(image_digests) != 1 or not repository_match:
        fail(
            "chart values carry {} image digests — expected exactly one with "
            "its repository".format(len(image_digests))
        )
    image_repository, image_digest = repository_match.group(1), image_digests[0]

    image_token = ghcr_token(image_repository)
    index = ghcr_json(
        image_repository, image_digest, "application/vnd.oci.image.index.v1+json",
        image_token,
    )
    arm64 = [
        entry["digest"]
        for entry in index.get("manifests", [])
        if entry.get("platform", {}).get("architecture") == "arm64"
    ]
    if len(arm64) != 1:
        fail("image index carries {} arm64 children — expected exactly one".format(len(arm64)))
    child = ghcr_json(
        image_repository, arm64[0], "application/vnd.oci.image.manifest.v1+json",
        image_token,
    )
    hits = []
    for layer in child.get("layers", []):
        blob = ghcr_blob(image_repository, layer["digest"], image_token)
        try:
            blob = gzip.decompress(blob)
        except OSError:
            pass
        if asset in blob:
            hits.append(layer["digest"])
    if not hits:
        fail(
            "the {} bytes the live site serves as {} exist in none of the "
            "{} arm64 layers of the committed selection {} — the served "
            "content is NOT the committed content".format(
                len(asset), bundle, len(child.get("layers", [])), chart_digest
            )
        )
    # Honest boundary: from outside the cluster this proves the exact bytes
    # the site serves exist verbatim inside the committed image — it cannot
    # prove which image digest the running workload was started from.
    return (
        "RECEIPT {} serves {} ({} bytes) whose exact content exists in "
        "committed image layer(s) {} (chart {}, image {})".format(
            site_url, bundle, len(asset), ",".join(hits), chart_digest,
            image_digest,
        )
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    receipt = commands.add_parser("ruleset-receipt")
    receipt.add_argument("rulesets_json")
    receipt.add_argument("ruleset_json")
    quiet = commands.add_parser("quiescence")
    quiet.add_argument("cronjob_json")
    quiet.add_argument("jobs_json")
    quiet.add_argument("pods_json")
    capture = commands.add_parser("prestate")
    capture.add_argument("gitrepository_json")
    capture.add_argument("--receipt-dir", required=True)
    selector_capture = commands.add_parser("selector-prestate")
    selector_capture.add_argument("cronjob_json")
    selector_capture.add_argument("--receipt-dir", required=True)
    for name in ("flip-patch", "rollback-patch"):
        emitter = commands.add_parser(name)
        emitter.add_argument("prestate_json")
    for name in ("suspend-patch", "resume-patch"):
        emitter = commands.add_parser(name)
        emitter.add_argument("selector_prestate_json")
    for name in ("poststate", "rollback-verify"):
        checker = commands.add_parser(name)
        checker.add_argument("gitrepository_json")
        checker.add_argument("prestate_json")
    resume_check = commands.add_parser("resume-verify")
    resume_check.add_argument("cronjob_json")
    resume_check.add_argument("selector_prestate_json")
    live = commands.add_parser("verify-live")
    live.add_argument("source_yaml")
    live.add_argument("site_url")
    arguments = parser.parse_args(argv)

    if arguments.command == "ruleset-receipt":
        print(
            ruleset_receipt(
                load_json(arguments.rulesets_json), load_json(arguments.ruleset_json)
            )
        )
    elif arguments.command == "quiescence":
        print(
            quiescence(
                load_json(arguments.cronjob_json),
                load_json(arguments.jobs_json),
                load_json(arguments.pods_json),
            )
        )
    elif arguments.command == "prestate":
        print(prestate(load_json(arguments.gitrepository_json), arguments.receipt_dir))
    elif arguments.command == "selector-prestate":
        print(
            selector_prestate(
                load_json(arguments.cronjob_json), arguments.receipt_dir
            )
        )
    elif arguments.command == "flip-patch":
        print(flip_patch(load_prestate(arguments.prestate_json)))
    elif arguments.command == "rollback-patch":
        print(rollback_patch(load_prestate(arguments.prestate_json)))
    elif arguments.command == "suspend-patch":
        print(
            suspend_patch(load_selector_prestate(arguments.selector_prestate_json))
        )
    elif arguments.command == "resume-patch":
        print(
            resume_patch(load_selector_prestate(arguments.selector_prestate_json))
        )
    elif arguments.command == "resume-verify":
        resume_verify(
            load_json(arguments.cronjob_json),
            load_selector_prestate(arguments.selector_prestate_json),
        )
        print("RECEIPT selector restored to its captured pre-ceremony state")
    elif arguments.command == "poststate":
        document = load_prestate(arguments.prestate_json)
        state_matches(
            load_json(arguments.gitrepository_json), document, {"branch": "main"}
        )
        print("RECEIPT poststate matches: ref={branch: main}, annotations intact")
    elif arguments.command == "rollback-verify":
        document = load_prestate(arguments.prestate_json)
        state_matches(
            load_json(arguments.gitrepository_json), document, dict(document["ref"])
        )
        print("RECEIPT rollback restored the captured prestate exactly")
    elif arguments.command == "verify-live":
        print(
            verify_live(
                Path(arguments.source_yaml).read_text(), arguments.site_url
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
