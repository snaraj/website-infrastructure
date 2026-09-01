"""Ceremony-tool battery for the site-sync branch flip (issue #275, PR #272).

Every load-bearing ceremony judgment lives in
``scripts/site_sync_branch_flip.py`` so it can be pinned here instead of as
runbook prose. Each battery pins one mode's fail-closed boundary, and the
runbook-canon battery at the end compares the runbook's command blocks byte
for byte against the tool's ``CEREMONY_BLOCKS`` — so a neutralized
invocation, a narrowed capture, or a retargeted patch (the round-2 security
review's three surviving mutants) is a red test, never prose drift.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .support import REPO_ROOT, load_script

flip = load_script("site_sync_branch_flip.py")

RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "site-sync-branch-flip.md"

SELECTOR_IMAGE = (
    "ghcr.io/snaraj/website-infrastructure/platform-release-selector"
    "@sha256:" + "a" * 64
)


def live_ruleset():
    """The reviewed anchor plus the volatile fields the live API also
    carries (identifiers/timestamps deliberately outside the comparison)."""

    document = json.loads(json.dumps(flip.EXPECTED_RULESET))
    document["node_id"] = "RRS_x"
    document["created_at"] = "2026-08-08T22:05:51.271-07:00"
    document["updated_at"] = "2026-08-13T23:53:34.486-07:00"
    document["_links"] = {"self": {"href": "x"}}
    return document


def live_listing():
    return [
        {"id": 20867356, "target": "tag"},
        {"id": 20601016, "target": "branch"},
    ]


def rule(document, kind):
    return next(r for r in document["rules"] if r["type"] == kind)


class RulesetReceiptTests(unittest.TestCase):
    maxDiff = None

    def test_the_live_anchor_document_is_accepted(self):
        receipt = flip.ruleset_receipt(live_listing(), live_ruleset())
        self.assertIn("20601016", receipt)
        self.assertIn("no bypass", receipt)

    def test_every_weakening_direction_is_refused(self):
        cases = {
            "second branch ruleset": (
                live_listing() + [{"id": 999, "target": "branch"}],
                live_ruleset(),
            ),
            "listing at the truncation bound": (
                [{"id": index, "target": "tag"} for index in range(100)],
                live_ruleset(),
            ),
        }
        for label, mutate in {
            "evaluate-only enforcement": lambda r: r.update(enforcement="evaluate"),
            "bypass actor added": lambda r: r.update(
                bypass_actors=[{"actor_id": 1, "actor_type": "Integration"}]
            ),
            "current_user_can_bypass widened": lambda r: r.update(
                current_user_can_bypass="always"
            ),
            "foreign source repository": lambda r: r.update(source="snaraj/other"),
            "include widened": lambda r: r["conditions"]["ref_name"].update(
                include=["refs/heads/*"]
            ),
            "signatures rule dropped": lambda r: r.update(
                rules=[u for u in r["rules"] if u["type"] != "required_signatures"]
            ),
            "strict checks disabled": lambda r: rule(
                r, "required_status_checks"
            )["parameters"].update(strict_required_status_checks_policy=False),
            "creation enforcement lifted": lambda r: rule(
                r, "required_status_checks"
            )["parameters"].update(do_not_enforce_on_create=True),
            "gate check context dropped": lambda r: rule(
                r, "required_status_checks"
            )["parameters"].update(
                required_status_checks=[
                    {"context": "dependency-review", "integration_id": 15368}
                ]
            ),
            "foreign integration id": lambda r: [
                check.update(integration_id=99999)
                for check in rule(r, "required_status_checks")["parameters"][
                    "required_status_checks"
                ]
            ],
            "code-owner review quietly required": lambda r: rule(
                r, "pull_request"
            )["parameters"].update(require_code_owner_review=True),
            "merge methods widened": lambda r: rule(r, "pull_request")[
                "parameters"
            ].update(allowed_merge_methods=["merge", "squash", "rebase"]),
        }.items():
            ruleset = live_ruleset()
            mutate(ruleset)
            cases[label] = (live_listing(), ruleset)
        for label, (listing, ruleset) in cases.items():
            with self.subTest(escape=label):
                with self.assertRaises(SystemExit):
                    flip.ruleset_receipt(listing, ruleset)


def selector_cronjob(
    suspended=True, image=SELECTOR_IMAGE, schedule=None, account=None,
    uid="cron-uid-1", active=None,
):
    return {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {
            "name": "platform-release-selector",
            "namespace": "flux-system",
            "uid": uid,
            "resourceVersion": "9",
        },
        "spec": {
            "suspend": suspended,
            "schedule": schedule or flip.SELECTOR_SCHEDULE,
            "concurrencyPolicy": "Forbid",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "serviceAccountName": account
                            or flip.SELECTOR_SERVICE_ACCOUNT,
                            "containers": [{"image": image}],
                        }
                    }
                }
            },
        },
        "status": {"active": active} if active else {},
    }


def selector_document(**kwargs):
    """A v2 custody capture of the (pre-suspend) selector fixture."""

    cronjob = selector_cronjob(suspended=False, **kwargs)
    return {
        "schema": "site-sync-branch-flip/selector-prestate/v2",
        "uid": cronjob["metadata"]["uid"],
        "resourceVersion": "9",
        "image": SELECTOR_IMAGE,
        "suspend": False,
        "spec": cronjob["spec"],
    }


def apply_patch(target, operations):
    """A minimal RFC 6902 applier so the race tests prove the emitted
    patches' SEMANTICS — a failed ``test`` refuses the whole patch — not
    just their shape."""

    target = copy.deepcopy(target)
    for operation in operations:
        parts = [
            part.replace("~1", "/").replace("~0", "~")
            for part in operation["path"].split("/")[1:]
        ]
        node = target
        for part in parts[:-1]:
            node = node[part]
        leaf = parts[-1]
        if operation["op"] == "test":
            if node.get(leaf) != operation["value"]:
                raise AssertionError("test failed at " + operation["path"])
        elif operation["op"] == "remove":
            del node[leaf]
        else:
            node[leaf] = operation["value"]
    return target


def selector_job(terminal=True):
    return {
        "metadata": {
            "name": "platform-release-selector-29300000",
            "namespace": "flux-system",
            "uid": "job-uid-1",
            "ownerReferences": [
                {
                    "kind": "CronJob",
                    "name": "platform-release-selector",
                    "uid": "cron-uid-1",
                    "controller": True,
                }
            ],
        },
        "status": (
            {"conditions": [{"type": "Complete", "status": "True"}]}
            if terminal
            else {}
        ),
    }


class QuiescenceTests(unittest.TestCase):
    def empty(self, kind):
        return {"kind": kind, "items": []}

    def quiet(self, cronjob, jobs=None):
        return flip.quiescence(
            cronjob,
            jobs or self.empty("JobList"),
            self.empty("PodList"),
            selector_document(),
        )

    def test_unsuspended_cronjob_is_refused_before_anything_else(self):
        with self.assertRaises(SystemExit):
            self.quiet(selector_cronjob(suspended=False))

    def test_suspended_and_empty_inventories_are_quiescent(self):
        self.assertIn("quiescent", self.quiet(selector_cronjob()))

    def test_foreign_selector_identities_are_refused(self):
        """A suspension receipt binds the PROVEN selector: a foreign image,
        service account, or schedule is a different object, and rollback
        must never activate one (round-2 security finding 2)."""

        for label, cronjob in {
            "foreign image": selector_cronjob(
                image="docker.io/attacker/selector@sha256:" + "b" * 64
            ),
            "tag-referenced image": selector_cronjob(
                image="ghcr.io/snaraj/website-infrastructure/"
                "platform-release-selector:latest"
            ),
            "foreign service account": selector_cronjob(account="admin"),
            "foreign schedule": selector_cronjob(schedule="* * * * *"),
        }.items():
            with self.subTest(escape=label):
                with self.assertRaises(SystemExit):
                    self.quiet(cronjob)

    def test_unlabeled_live_selector_job_is_still_seen(self):
        """Selector Jobs carry NO labels (only their Pods do), so a filtered
        listing reports quiescence while a Job races the flip. Lineage
        matching must catch the unlabeled Job."""

        jobs = {"kind": "JobList", "items": [selector_job(terminal=False)]}
        with self.assertRaises(SystemExit):
            self.quiet(selector_cronjob(), jobs)

    def test_terminal_selector_job_is_quiescent(self):
        jobs = {"kind": "JobList", "items": [selector_job(terminal=True)]}
        self.assertIn("quiescent", self.quiet(selector_cronjob(), jobs))

    def test_status_named_job_missing_from_the_capture_is_refused(self):
        """Capture completeness: the CronJob's own status names its active
        Jobs, so an inventory narrowed by any query mechanism that hides
        one is refused as incomplete rather than trusted as empty."""

        cronjob = selector_cronjob(
            active=[{"name": "platform-release-selector-x", "uid": "job-uid-9"}]
        )
        with self.assertRaises(SystemExit):
            self.quiet(cronjob)

    def test_template_drift_since_capture_is_refused(self):
        """The round-3 security race: an execution template altered while
        keeping every tested identity field must never be receipted — the
        COMPLETE live spec must equal the capture except for the
        suspension the ceremony itself applied."""

        drifted = selector_cronjob()
        drifted["spec"]["jobTemplate"]["spec"]["template"]["spec"][
            "containers"
        ][0]["args"] = ["--exfiltrate"]
        with self.assertRaises(SystemExit):
            self.quiet(drifted)


class ScratchMixin:
    def scratch(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        os.chmod(directory.name, 0o700)
        return directory.name


class SelectorCustodyTests(ScratchMixin, unittest.TestCase):
    def capture(self, cronjob):
        scratch = self.scratch()
        flip.selector_prestate(cronjob, scratch)
        return json.loads((Path(scratch) / "selector-prestate.json").read_text())

    def test_prestate_records_the_pre_ceremony_suspension(self):
        document = self.capture(selector_cronjob(suspended=False))
        self.assertEqual(document["suspend"], False)
        self.assertEqual(document["image"], SELECTOR_IMAGE)

    def test_suspend_and_resume_patches_bind_uid_and_the_entire_spec(self):
        document = self.capture(selector_cronjob(suspended=False))
        forward = json.loads(flip.suspend_patch(document))
        self.assertEqual(
            [op["op"] for op in forward], ["test", "test", "replace"]
        )
        self.assertEqual(forward[0]["path"], "/metadata/uid")
        self.assertEqual(forward[1]["path"], "/spec")
        self.assertEqual(forward[1]["value"]["suspend"], False)
        self.assertEqual(
            forward[1]["value"]["jobTemplate"],
            selector_cronjob()["spec"]["jobTemplate"],
        )
        self.assertEqual(forward[2], {
            "op": "replace", "path": "/spec/suspend", "value": True,
        })
        backward = json.loads(flip.resume_patch(document))
        self.assertEqual(backward[1]["path"], "/spec")
        self.assertEqual(backward[1]["value"]["suspend"], True)
        self.assertEqual(backward[2], {
            "op": "replace", "path": "/spec/suspend", "value": False,
        })

    def test_the_patches_refuse_post_capture_template_drift(self):
        """The round-3 security race, semantically: the whole-spec test
        operation makes the API server itself refuse a suspend or resume
        of a template altered after capture — no window exists between the
        identity check and the mutation."""

        document = self.capture(selector_cronjob(suspended=False))
        live = selector_cronjob(suspended=False)
        suspended = apply_patch(live, json.loads(flip.suspend_patch(document)))
        self.assertEqual(suspended["spec"]["suspend"], True)
        drifted = selector_cronjob(suspended=False)
        drifted["spec"]["jobTemplate"]["spec"]["template"]["spec"][
            "containers"
        ][0]["args"] = ["--exfiltrate"]
        with self.assertRaises(AssertionError):
            apply_patch(drifted, json.loads(flip.suspend_patch(document)))
        drifted_suspended = selector_cronjob(suspended=True)
        drifted_suspended["spec"]["jobTemplate"]["spec"]["template"]["spec"][
            "serviceAccountName"
        ] = "admin"
        with self.assertRaises(AssertionError):
            apply_patch(
                drifted_suspended, json.loads(flip.resume_patch(document))
            )

    def test_a_pre_suspended_selector_is_never_suspended_or_resumed(self):
        """The rollback restores what the ceremony changed and nothing
        else: a selector that was already suspended before the ceremony is
        an owner decision, and both patch emitters refuse it."""

        document = self.capture(selector_cronjob(suspended=True))
        with self.assertRaises(SystemExit):
            flip.suspend_patch(document)
        with self.assertRaises(SystemExit):
            flip.resume_patch(document)

    def test_resume_verify_requires_the_captured_identity_back(self):
        document = self.capture(selector_cronjob(suspended=False))
        flip.resume_verify(selector_cronjob(suspended=False), document)
        for label, final in {
            "foreign uid": selector_cronjob(suspended=False, uid="other"),
            "drifted image": selector_cronjob(
                suspended=False,
                image="ghcr.io/snaraj/website-infrastructure/"
                "platform-release-selector@sha256:" + "c" * 64,
            ),
            "still suspended": selector_cronjob(suspended=True),
        }.items():
            with self.subTest(escape=label):
                with self.assertRaises(SystemExit):
                    flip.resume_verify(final, document)


def live_gitrepository(ref=None, uid="uid-1", spec_overrides=None):
    reserved = {
        key: "value-" + key.rsplit("/", 1)[1] for key in flip.RESERVED_ANNOTATIONS
    }
    spec = {
        "ignore": flip.SOURCE_IGNORE,
        "interval": flip.SOURCE_INTERVAL,
        "ref": dict(ref if ref is not None else {"tag": "v0.1.54"}),
        "sparseCheckout": [
            "kubernetes/websites/naranjo-online",
            "kubernetes/websites/lidersea-com",
        ],
        "timeout": flip.SOURCE_TIMEOUT,
        "url": flip.SOURCE_URL,
    }
    spec.update(spec_overrides or {})
    return {
        "apiVersion": flip.SOURCE_API_VERSION,
        "kind": "GitRepository",
        "metadata": {
            "name": "flux-system",
            "namespace": "flux-system",
            "uid": uid,
            "resourceVersion": "77",
            "annotations": reserved,
        },
        "spec": spec,
    }


class PrestateAndPatchTests(ScratchMixin, unittest.TestCase):
    def capture(self, gitrepository, scratch=None):
        scratch = scratch or self.scratch()
        flip.prestate(gitrepository, scratch)
        return json.loads((Path(scratch) / "flip-prestate.json").read_text())

    def test_prestate_captures_the_bounded_semantic_document(self):
        document = self.capture(live_gitrepository())
        self.assertEqual(document["schema"], "site-sync-branch-flip/prestate/v3")
        self.assertEqual(document["ref"], {"tag": "v0.1.54"})
        self.assertEqual(document["spec"]["url"], flip.SOURCE_URL)
        self.assertEqual(
            sorted(document["annotations"]), sorted(flip.RESERVED_ANNOTATIONS)
        )

    def test_prestate_captures_foreign_annotations_whole(self):
        """An annotation beyond the reserved nine (a prior ceremony's
        reconcile request stamp, say) is CAPTURED, not refused — the
        patches test the complete map by equality, so a partial capture
        could not express that test, and refusing would strand any object
        a legitimate operator action ever annotated."""

        annotated = live_gitrepository()
        annotated["metadata"]["annotations"][
            "reconcile.fluxcd.io/requestedAt"
        ] = "2026-08-31T00:00:00Z"
        document = self.capture(annotated)
        self.assertEqual(
            document["annotations"]["reconcile.fluxcd.io/requestedAt"],
            "2026-08-31T00:00:00Z",
        )
        self.assertEqual(
            len(document["annotations"]), len(flip.RESERVED_ANNOTATIONS) + 1
        )

    def test_the_closed_source_shape_refuses_every_escape(self):
        """The spec fields ARE the security boundary: a foreign URL, a
        credential, a widened checkout, or a submodule walk turns the
        anonymous two-site source into something else entirely, and a
        receipt that ignored them would bless it (round-2 security
        finding 1)."""

        cases = {
            "foreign url": {"url": "https://github.com/attacker/repo.git"},
            "credential attached": {"secretRef": {"name": "creds"}},
            "impersonation attached": {"serviceAccountName": "admin"},
            "submodule walk": {"recurseSubmodules": True},
            "checkout widened": {
                "sparseCheckout": [
                    "kubernetes/websites/naranjo-online",
                    "kubernetes/websites/lidersea-com",
                    "bootstrap",
                ]
            },
            "checkout narrowed": {
                "sparseCheckout": ["kubernetes/websites/naranjo-online"]
            },
            "checkout duplicated": {
                "sparseCheckout": [
                    "kubernetes/websites/naranjo-online",
                    "kubernetes/websites/naranjo-online",
                ]
            },
            "ignore rewritten": {"ignore": "/*\n"},
            "interval drifted": {"interval": "10s"},
        }
        for label, overrides in cases.items():
            with self.subTest(escape=label):
                with self.assertRaises(SystemExit):
                    self.capture(live_gitrepository(spec_overrides=overrides))
        wrong_api = live_gitrepository()
        wrong_api["apiVersion"] = "source.toolkit.fluxcd.io/v1beta2"
        with self.assertRaises(SystemExit):
            self.capture(wrong_api)

    def test_prestate_refuses_branch_refs_and_missing_annotations(self):
        with self.assertRaises(SystemExit):
            self.capture(live_gitrepository(ref={"branch": "main"}))
        broken = live_gitrepository()
        del broken["metadata"]["annotations"][flip.RESERVED_ANNOTATIONS[0]]
        with self.assertRaises(SystemExit):
            self.capture(broken)

    def test_prestate_refuses_shared_directories_and_overwrites(self):
        loose = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, loose)
        os.chmod(loose, 0o755)
        with self.assertRaises(SystemExit):
            flip.prestate(live_gitrepository(), loose)
        private = self.scratch()
        self.capture(live_gitrepository(), private)
        with self.assertRaises(SystemExit):
            flip.prestate(live_gitrepository(), private)

    def test_both_patches_test_the_complete_captured_boundary(self):
        """WHOLE-OBJECT equality tests — UID, the entire annotations map,
        the entire spec with the direction's ref — then one ref
        replacement, and nothing else. Round-6 security finding (both
        reviewers): a per-key test list refuses a changed field but not
        an ADDED one, so a credential-bearing spec key introduced after
        capture rode through both directions; only equality over the
        whole object refuses additions, removals, and changes alike."""

        document = self.capture(live_gitrepository())
        base = {
            key: document["spec"][key]
            for key in sorted(flip.SOURCE_SPEC_KEYS - {"ref"})
        }
        guards = [
            {"op": "test", "path": "/metadata/uid", "value": document["uid"]},
            {
                "op": "test",
                "path": "/metadata/annotations",
                "value": document["annotations"],
            },
        ]
        self.assertEqual(
            json.loads(flip.flip_patch(document)),
            guards
            + [
                {
                    "op": "test",
                    "path": "/spec",
                    "value": {**base, "ref": {"tag": "v0.1.54"}},
                },
                {
                    "op": "replace",
                    "path": "/spec/ref",
                    "value": {"branch": "main"},
                },
            ],
        )
        self.assertEqual(
            json.loads(flip.rollback_patch(document)),
            guards
            + [
                {
                    "op": "test",
                    "path": "/spec",
                    "value": {**base, "ref": {"branch": "main"}},
                },
                {
                    "op": "replace",
                    "path": "/spec/ref",
                    "value": {"tag": "v0.1.54"},
                },
            ],
        )

    def test_the_emitted_patches_refuse_post_capture_drift(self):
        """The round-3 and round-6 security races, semantically: applying
        the emitted patch to an object whose URL moved, whose reserved
        annotation moved, or which gained a spec key or an annotation the
        capture never saw must fail its test operations — the API server
        refuses the mutation; no post-hoc check is the defense."""

        document = self.capture(live_gitrepository())
        honest = apply_patch(
            live_gitrepository(), json.loads(flip.flip_patch(document))
        )
        self.assertEqual(honest["spec"]["ref"], {"branch": "main"})
        foreign_url = live_gitrepository(
            spec_overrides={"url": "https://github.com/attacker/repo.git"}
        )
        with self.assertRaises(AssertionError):
            apply_patch(foreign_url, json.loads(flip.flip_patch(document)))
        moved_annotation = live_gitrepository()
        moved_annotation["metadata"]["annotations"][
            flip.RESERVED_ANNOTATIONS[2]
        ] = "moved"
        with self.assertRaises(AssertionError):
            apply_patch(
                moved_annotation, json.loads(flip.flip_patch(document))
            )
        credentialed = live_gitrepository(
            spec_overrides={"secretRef": {"name": "creds"}}
        )
        with self.assertRaises(AssertionError):
            apply_patch(credentialed, json.loads(flip.flip_patch(document)))
        credentialed_back = live_gitrepository(
            ref={"branch": "main"},
            spec_overrides={"secretRef": {"name": "creds"}},
        )
        with self.assertRaises(AssertionError):
            apply_patch(
                credentialed_back, json.loads(flip.rollback_patch(document))
            )
        annotated = live_gitrepository()
        annotated["metadata"]["annotations"][
            "reconcile.fluxcd.io/requestedAt"
        ] = "post-capture"
        with self.assertRaises(AssertionError):
            apply_patch(annotated, json.loads(flip.flip_patch(document)))
        drifted_back = live_gitrepository(
            ref={"branch": "main"},
            spec_overrides={"sparseCheckout": ["kubernetes"]},
        )
        with self.assertRaises(AssertionError):
            apply_patch(
                drifted_back, json.loads(flip.rollback_patch(document))
            )

    def test_state_checks_bind_uid_ref_spec_and_annotations(self):
        document = self.capture(live_gitrepository())
        flipped = live_gitrepository(ref={"branch": "main"})
        flip.state_matches(flipped, document, {"branch": "main"})
        with self.assertRaises(SystemExit):
            flip.state_matches(
                live_gitrepository(ref={"branch": "main"}, uid="uid-2"),
                document,
                {"branch": "main"},
            )
        drifted = live_gitrepository(ref={"branch": "main"})
        drifted["metadata"]["annotations"][flip.RESERVED_ANNOTATIONS[2]] = "moved"
        with self.assertRaises(SystemExit):
            flip.state_matches(drifted, document, {"branch": "main"})
        with self.assertRaises(SystemExit):
            flip.state_matches(flipped, document, {"tag": "v0.1.54"})

    def test_poststate_never_blesses_concurrent_spec_drift(self):
        """Round-2 security finding 1's second half: a URL or checkout that
        moved between capture and verification is a different source, even
        with the expected ref."""

        document = self.capture(live_gitrepository())
        moved = live_gitrepository(
            ref={"branch": "main"},
            spec_overrides={"url": "https://github.com/attacker/repo.git"},
        )
        with self.assertRaises(SystemExit):
            flip.state_matches(moved, document, {"branch": "main"})
        gained = live_gitrepository(
            ref={"branch": "main"},
            spec_overrides={"secretRef": {"name": "creds"}},
        )
        with self.assertRaises(SystemExit):
            flip.state_matches(gained, document, {"branch": "main"})


class VerifyLiveTests(unittest.TestCase):
    """The probe's singleton, digest, and CONTENT expectations, over faked
    transports. Every fixture digest — manifests included — is computed
    from the bytes it names, and the proof object is the served asset's
    exact bytes inside a committed layer, never a filename string."""

    def probe(
        self,
        page="x assets/index-AAAA.css x",
        content_layer_count=1,
        layer_holds="served",
        served_asset=None,
        manifest_lie=False,
    ):
        import gzip
        import hashlib
        import io
        import tarfile

        def digest_of(data):
            return "sha256:" + hashlib.sha256(data).hexdigest()

        asset = (
            served_asset
            if served_asset is not None
            else (b"/* committed stylesheet */\n" * 60)
        )
        committed = {
            "served": asset,
            "other-bytes": b"#" * len(asset),
            "nothing": b"empty",
        }[layer_holds]
        layer_blob = gzip.compress(b"binary " + committed + b" tail")
        image_layer_digest = digest_of(layer_blob)
        child_body = json.dumps({"layers": [{"digest": image_layer_digest}]}).encode()
        arm64_digest = digest_of(child_body)
        index_body = json.dumps(
            {
                "manifests": [
                    {"digest": arm64_digest, "platform": {"architecture": "arm64"}}
                ]
            }
        ).encode()
        image_digest = digest_of(index_body)
        values = (
            "image:\n  repository: ghcr.io/snaraj/naranjo-online\n"
            "  digest: " + image_digest + "\n"
        )
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            data = values.encode()
            info = tarfile.TarInfo("naranjo-online/values.yaml")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        chart_blob = buffer.getvalue()
        chart_layer_digest = digest_of(chart_blob)
        chart_manifest_body = json.dumps(
            {
                "layers": [
                    {"mediaType": flip.HELM_CONTENT_TYPE, "digest": chart_layer_digest}
                ]
                * content_layer_count
            }
        ).encode()
        chart_digest = digest_of(chart_manifest_body)
        if manifest_lie:
            chart_digest = "sha256:" + "0" * 64
        source_text = (
            "  url: oci://ghcr.io/snaraj/charts/naranjo-online\n"
            "    digest: " + chart_digest + "\n"
        )
        manifests = {
            chart_digest: chart_manifest_body,
            image_digest: index_body,
            arm64_digest: child_body,
        }
        blobs = {chart_layer_digest: chart_blob, image_layer_digest: layer_blob}

        def fake_http_get(url, headers=None, limit=0):
            if url.endswith("/assets/index-AAAA.css"):
                return asset
            if url.endswith("naranjo.online/"):
                return page.encode()
            if url.endswith("/readyz"):
                return b"ok"
            if "token?scope" in url:
                return json.dumps({"token": "t"}).encode()
            for digest, body in manifests.items():
                if url.endswith("/manifests/" + digest):
                    return body
            for digest, body in blobs.items():
                if url.endswith("/blobs/" + digest):
                    return body
            raise AssertionError("unexpected URL " + url)

        with mock.patch.object(flip, "http_get", fake_http_get):
            return flip.verify_live(source_text, "https://naranjo.online")

    def test_happy_path_binds_the_served_bytes_into_the_committed_image(self):
        receipt = self.probe()
        self.assertIn("index-AAAA.css", receipt)
        self.assertIn("exact content exists", receipt)
        self.assertIn("(chart sha256:", receipt)

    def test_two_live_bundles_are_refused(self):
        with self.assertRaises(SystemExit):
            self.probe(page="assets/index-AAAA.css assets/index-BBBB.css")

    def test_multiple_chart_content_layers_are_refused(self):
        with self.assertRaises(SystemExit):
            self.probe(content_layer_count=2)

    def test_served_bytes_absent_from_every_layer_are_refused(self):
        with self.assertRaises(SystemExit):
            self.probe(layer_holds="nothing")

    def test_a_stale_workload_serving_different_bytes_is_refused(self):
        """The round-2 gap: a filename string can occur in an unrelated
        layer or an older image, but the served CONTENT must be the
        committed content — same-length different bytes fail."""

        with self.assertRaises(SystemExit):
            self.probe(layer_holds="other-bytes")

    def test_a_stub_asset_below_the_floor_is_refused(self):
        with self.assertRaises(SystemExit):
            self.probe(served_asset=b"tiny")

    def test_manifest_that_lies_about_its_digest_is_refused(self):
        """A hostile registry serving a substitute manifest at the committed
        digest must be caught at the MANIFEST, because every downstream blob
        digest is read out of that document."""

        with self.assertRaises(SystemExit):
            self.probe(manifest_lie=True)

    def test_source_without_chart_coordinates_is_refused(self):
        with self.assertRaises(SystemExit):
            flip.verify_live("nothing here", "https://naranjo.online")


def indent_columns(line):
    """CommonMark indentation is COLUMN-based, not character-based
    (round-8 convergent finding, both lanes): a leading tab advances to
    the next four-column tab stop, so ``\\t``, ``  \\t``, and ``   \\t``
    all open an indented code block exactly as four spaces do — GitHub's
    own renderer turns each into ``<pre><code>``. Measure columns the
    way the spec does; a literal-prefix check refuses only one spelling
    of the block."""

    columns = 0
    for char in line:
        if char == " ":
            columns += 1
        elif char == "\t":
            columns += 4 - (columns % 4)
        else:
            break
        if columns >= 4:
            break
    return columns


_LIST_MARKER = re.compile(r"^(?:[-+*]|\d{1,9}[.)])([ \t]+)")


def canon_residue_violations(text):
    """Everything outside the canonical fences that a Markdown renderer
    could present as an unreviewed command block (round-7 review
    finding): indented code blocks at four COLUMNS under CommonMark tab
    stops (round-8: tab and space-then-tab spellings included); block
    quotes ENTIRELY, because a quoted fence or quoted indented block
    renders as an ordinary copyable code block while its marker is
    invisible to both a column-anchored fence inventory and an indent
    check; any three-plus backtick or tilde run anywhere in a line,
    which every container-nested fence of any form needs to open; and
    CommonMark's four type-1 raw-HTML starts plus code/comment markers.
    Returns the violations so the battery can prove hostile shapes
    non-empty and the honest document empty."""

    violations = []
    inside = False
    for number, line in enumerate(text.split("\n"), start=1):
        if line in ("```sh", "```"):
            inside = not inside
            continue
        if inside:
            continue
        if indent_columns(line) >= 4:
            violations.append("{}: indented code block".format(number))
        # Container-relative indentation (round-9 finding): a list marker
        # padded with more than one space or any tab shifts its content
        # column, and enough padding turns the SAME line into indented
        # code inside the item — invisible to the absolute measure above.
        # Canonical padding here is exactly one space; walk marker chains
        # so nesting cannot hide the padding, and refuse quote content at
        # any depth (a quoted block inside a list evades the bare-line
        # quote check the same way).
        content = line.lstrip(" ")
        while True:
            marker = _LIST_MARKER.match(content)
            if marker is None:
                break
            if marker.group(1) != " ":
                violations.append(
                    "{}: noncanonical list-marker padding".format(number)
                )
                break
            content = content[marker.end():]
        if content.lstrip().startswith(">"):
            violations.append("{}: block quote".format(number))
        if re.search(r"`{3,}|~{3,}", line):
            violations.append(
                "{}: fence-capable character run".format(number)
            )
        lowered = line.lower()
        for marker in (
            "<pre",
            "<code",
            "<script",
            "<style",
            "<textarea",
            "<!--",
        ):
            if marker in lowered:
                violations.append("{}: {}".format(number, marker))
    return violations


class RunbookCanonTests(unittest.TestCase):
    """The runbook IS the canon: its fenced command blocks equal the tool's
    CEREMONY_BLOCKS byte for byte, in order, with no other invocation
    anywhere in the document. The round-2 security review's three surviving
    mutants — a neutralized invocation retaining its text, an inventory
    narrowed through another query form, a retargeted patch — all change a
    block or a token count, and all go red here."""

    maxDiff = None

    def test_the_fenced_blocks_are_exactly_the_canon(self):
        """Complete extraction, complete equality (round-3 security
        finding 3): every fenced block's ENTIRE content — ordered — must
        equal the canon. The fence inventory is proven under the
        CommonMark opener grammar at column 0 (round-6 finding 2:
        counting literal triple-backticks admits a tilde or longer-run
        fence carrying an unreviewed block): every line opening with
        three-plus backticks or tildes after at most three spaces must
        be exactly the reviewed ```sh opener or bare closer at column 0,
        alternating, 2N lines total. Container-NESTED fences (a
        block-quoted or list-prefixed opener — round-7 finding) are not
        this inventory's job: the residue sweep below refuses block
        quotes and any fence-capable character run outside the reviewed
        fences, so no such form parses anywhere. A line appended INSIDE
        an existing fence changes that fence's extracted bytes and goes
        red."""

        text = RUNBOOK.read_text()
        fences = tuple(re.findall(r"(?ms)^```sh\n(.*?)^```$", text))
        self.assertEqual(fences, flip.CEREMONY_BLOCKS)
        fence_lines = [
            line
            for line in text.split("\n")
            if re.match(r"^ {0,3}(?:`{3,}|~{3,})", line)
        ]
        self.assertEqual(
            fence_lines, ["```sh", "```"] * len(flip.CEREMONY_BLOCKS)
        )

    def test_no_code_block_or_html_exists_outside_the_fences(self):
        """CommonMark's other executable-looking containers (round-6
        finding 2's class, closed over container nesting by the round-7
        finding): the sweep refuses everything a renderer could present
        as an unreviewed command block. The fence walk is sound because
        the test above proves the only fence lines are the reviewed
        openers and closers."""

        self.assertEqual(
            canon_residue_violations(RUNBOOK.read_text()), []
        )

    def test_container_nested_blocks_are_refused(self):
        """The round-7 through round-9 survivors, pinned as named
        regressions: a block-quoted ```sh fence (GitHub renders it as an
        ordinary copyable code block inside a callout), a block-quoted
        indented code block, a <textarea> block (a CommonMark type-1
        raw-HTML start the earlier enumeration missed, with <style> its
        sibling), a list-marker-prefixed fence, every indented-code
        spelling the column rule owns — four spaces, tab-only,
        space-then-tab, and a list-child block — and the
        container-RELATIVE forms: same-line list indented code (bullet
        and ordered), a tab-padded marker, and a quote nested in a list
        item, each measured by GitHub's renderer as a real command
        block. Each shape carries a verb OUTSIDE the five counted
        tokens, so the residue sweep alone must catch it, and the pins
        are what make each sweep clause undeletable. The honest
        document stays clean."""

        text = RUNBOOK.read_text()
        self.assertEqual(canon_residue_violations(text), [])
        for label, block in {
            "block-quoted fence": "> ```sh\n> helm rollback site 1\n> ```\n",
            "block-quoted indented code": ">     helm rollback site 1\n",
            "textarea block": "<textarea>\nhelm rollback site 1\n</textarea>\n",
            "style block": "<style>\nbody { display: none }\n</style>\n",
            "list-marker fence": "- ```sh\n  helm rollback site 1\n  ```\n",
            "four-space indented code": "    helm rollback site 1\n",
            "tab-indented code": "\thelm rollback site 1\n",
            "space-then-tab indented code": "  \thelm rollback site 1\n",
            "three-space-tab indented code": "   \thelm rollback site 1\n",
            "list-child indented code": (
                "- item\n\n      helm rollback site 1\n"
            ),
            "same-line list indented code": "-      helm rollback site 1\n",
            "tab-padded list marker": "-\thelm rollback site 1\n",
            "ordered same-line list code": "1.      helm rollback site 1\n",
            "list-nested block quote": "- >     helm rollback site 1\n",
            "chained-marker same-line code": (
                "- 1.      helm rollback site 1\n"
            ),
            "two-space list-marker padding": "-  helm rollback site 1\n",
        }.items():
            with self.subTest(shape=label):
                violations = canon_residue_violations(text + "\n" + block)
                self.assertNotEqual(violations, [], label)

    def test_no_invocation_exists_outside_the_canonical_blocks(self):
        """Bare tokens, not line-anchored ones (round-6 review LOW): a
        leading-newline token count admitted a mid-sentence or inline
        invocation; the document must carry each verb exactly as often
        as the canon does, anywhere."""

        text = RUNBOOK.read_text()
        canon = "".join(flip.CEREMONY_BLOCKS)
        for token in (
            "kubectl ",
            "python3 ",
            "flux ",
            "gh api ",
            "scratch=",
        ):
            with self.subTest(token=token.strip()):
                self.assertEqual(text.count(token), canon.count(token))

    def test_the_canon_itself_stays_inside_the_reviewed_grammar(self):
        canon = "".join(flip.CEREMONY_BLOCKS)
        self.assertNotIn("--type=merge", canon)
        self.assertNotIn("-l app.kubernetes.io", canon)
        self.assertNotIn("--field-selector", canon)
        self.assertIn("kubectl get jobs -n flux-system -o json", canon)
        self.assertIn(
            "kubectl patch gitrepository -n flux-system flux-system", canon
        )


if __name__ == "__main__":
    unittest.main()
