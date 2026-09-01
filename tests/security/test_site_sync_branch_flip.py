"""Ceremony-tool battery for the site-sync branch flip (issue #275, PR #272).

Round-2 review findings put every load-bearing ceremony judgment into
``scripts/site_sync_branch_flip.py`` so it can be pinned here instead of
living as runbook prose. Each battery below pins one mode's fail-closed
boundary, and the runbook battery at the end pins the runbook TO the tool —
the two round-2 surviving mutants (drain selector edited, live target
edited) die there, because the commands are now assertable text.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .support import REPO_ROOT, load_script

flip = load_script("site_sync_branch_flip.py")

RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "site-sync-branch-flip.md"


def live_ruleset():
    return {
        "id": 20601016,
        "name": "only-me-merge",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"exclude": [], "include": ["refs/heads/main"]}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "creation"},
            {"type": "required_linear_history"},
            {"type": "required_signatures"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 0,
                    "required_review_thread_resolution": False,
                    "required_reviewers": [],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
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


def live_listing():
    return [
        {"id": 20867356, "target": "tag"},
        {"id": 20601016, "target": "branch"},
    ]


class RulesetReceiptTests(unittest.TestCase):
    maxDiff = None

    def test_the_live_anchor_document_is_accepted(self):
        receipt = flip.ruleset_receipt(live_listing(), live_ruleset())
        self.assertIn("20601016", receipt)
        self.assertIn("no bypass", receipt)

    def test_every_weakening_direction_is_refused(self):
        cases = {}
        extra_branch = live_listing() + [{"id": 999, "target": "branch"}]
        cases["second branch ruleset"] = (extra_branch, live_ruleset())
        for label, mutate in {
            "evaluate-only enforcement": lambda r: r.update(enforcement="evaluate"),
            "bypass actor added": lambda r: r.update(
                bypass_actors=[{"actor_id": 1, "actor_type": "Integration"}]
            ),
            "include widened": lambda r: r["conditions"]["ref_name"].update(
                include=["refs/heads/*"]
            ),
            "signatures rule dropped": lambda r: r.update(
                rules=[u for u in r["rules"] if u["type"] != "required_signatures"]
            ),
            "strict checks disabled": lambda r: [
                u["parameters"].update(strict_required_status_checks_policy=False)
                for u in r["rules"]
                if u["type"] == "required_status_checks"
            ],
            "gate check context dropped": lambda r: [
                u["parameters"].update(
                    required_status_checks=[
                        {"context": "dependency-review", "integration_id": 15368}
                    ]
                )
                for u in r["rules"]
                if u["type"] == "required_status_checks"
            ],
            "foreign integration id": lambda r: [
                check.update(integration_id=99999)
                for u in r["rules"]
                if u["type"] == "required_status_checks"
                for check in u["parameters"]["required_status_checks"]
            ],
        }.items():
            ruleset = live_ruleset()
            mutate(ruleset)
            cases[label] = (live_listing(), ruleset)
        for label, (listing, ruleset) in cases.items():
            with self.subTest(escape=label):
                with self.assertRaises(SystemExit):
                    flip.ruleset_receipt(listing, ruleset)


def selector_cronjob(suspended=True):
    return {
        "kind": "CronJob",
        "metadata": {
            "name": "platform-release-selector",
            "namespace": "flux-system",
            "uid": "cron-uid-1",
        },
        "spec": {"suspend": suspended},
    }


def selector_job(terminal=True, labeled=False):
    metadata = {
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
    }
    if labeled:
        metadata["labels"] = {"app.kubernetes.io/name": "platform-release-selector"}
    status = (
        {"conditions": [{"type": "Complete", "status": "True"}]} if terminal else {}
    )
    return {"metadata": metadata, "status": status}


class QuiescenceTests(unittest.TestCase):
    def empty(self, kind):
        return {"kind": kind, "items": []}

    def test_unsuspended_cronjob_is_refused_before_anything_else(self):
        with self.assertRaises(SystemExit):
            flip.quiescence(
                selector_cronjob(suspended=False),
                self.empty("JobList"),
                self.empty("PodList"),
            )

    def test_suspended_and_empty_inventories_are_quiescent(self):
        receipt = flip.quiescence(
            selector_cronjob(), self.empty("JobList"), self.empty("PodList")
        )
        self.assertIn("quiescent", receipt)

    def test_unlabeled_live_selector_job_is_still_seen(self):
        """The round-2 gap: selector Jobs carry NO labels (only their Pods
        do), so a label-filtered listing reports quiescence while a Job
        races the flip. Lineage matching must catch the unlabeled Job."""

        jobs = {"kind": "JobList", "items": [selector_job(terminal=False)]}
        with self.assertRaises(SystemExit):
            flip.quiescence(selector_cronjob(), jobs, self.empty("PodList"))

    def test_terminal_selector_job_is_quiescent(self):
        jobs = {"kind": "JobList", "items": [selector_job(terminal=True)]}
        receipt = flip.quiescence(selector_cronjob(), jobs, self.empty("PodList"))
        self.assertIn("quiescent", receipt)


def live_gitrepository(ref=None, uid="uid-1", annotations=None):
    reserved = {key: "value-" + key.rsplit("/", 1)[1] for key in flip.RESERVED_ANNOTATIONS}
    if annotations is not None:
        reserved = annotations
    return {
        "kind": "GitRepository",
        "metadata": {
            "name": "flux-system",
            "namespace": "flux-system",
            "uid": uid,
            "resourceVersion": "77",
            "annotations": reserved,
        },
        "spec": {"ref": dict(ref if ref is not None else {"tag": "v0.1.54"})},
    }


class PrestateAndPatchTests(unittest.TestCase):
    def scratch(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        os.chmod(directory.name, 0o700)
        return directory.name

    def capture(self, gitrepository, scratch=None):
        scratch = scratch or self.scratch()
        flip.prestate(gitrepository, scratch)
        return json.loads((Path(scratch) / "flip-prestate.json").read_text())

    def test_prestate_captures_the_bounded_semantic_document(self):
        document = self.capture(live_gitrepository())
        self.assertEqual(document["schema"], "site-sync-branch-flip/prestate/v1")
        self.assertEqual(document["ref"], {"tag": "v0.1.54"})
        self.assertEqual(
            sorted(document["annotations"]), sorted(flip.RESERVED_ANNOTATIONS)
        )

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

    def test_both_patches_lead_with_uid_and_field_test_operations(self):
        document = self.capture(live_gitrepository())
        forward = json.loads(flip.flip_patch(document))
        self.assertEqual(
            [op["op"] for op in forward], ["test", "test", "remove", "add"]
        )
        self.assertEqual(forward[0]["path"], "/metadata/uid")
        self.assertEqual(forward[1], {
            "op": "test", "path": "/spec/ref/tag", "value": "v0.1.54",
        })
        self.assertEqual(forward[3], {
            "op": "add", "path": "/spec/ref/branch", "value": "main",
        })
        backward = json.loads(flip.rollback_patch(document))
        self.assertEqual(
            [op["op"] for op in backward], ["test", "test", "remove", "add"]
        )
        self.assertEqual(backward[1]["path"], "/spec/ref/branch")
        self.assertEqual(backward[3]["value"], "v0.1.54")

    def test_state_checks_bind_uid_ref_and_annotations(self):
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


SOURCE_TEXT = (
    "  url: oci://ghcr.io/snaraj/charts/naranjo-online\n"
    "    digest: sha256:" + "a" * 64 + "\n"
)


class VerifyLiveTests(unittest.TestCase):
    """The probe's singleton expectations, over faked transports."""

    def probe(self, page="x assets/index-AAAA.css x", layers=None, bundles_layer=True):
        chart_digest = "sha256:" + "a" * 64
        image_digest = "sha256:" + "b" * 64
        values = (
            "image:\n  repository: ghcr.io/snaraj/naranjo-online\n"
            "  digest: " + image_digest + "\n"
        )
        import gzip
        import io
        import tarfile

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            data = values.encode()
            info = tarfile.TarInfo("naranjo-online/values.yaml")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        chart_blob = buffer.getvalue()
        layer_blob = gzip.compress(
            b"binary " + (b"assets/index-AAAA.css" if bundles_layer else b"nothing")
        )
        chart_layer_digest = "sha256:" + __import__("hashlib").sha256(chart_blob).hexdigest()
        image_layer_digest = "sha256:" + __import__("hashlib").sha256(layer_blob).hexdigest()
        arm64_digest = "sha256:" + "c" * 64

        def fake_http_get(url, headers=None, limit=0):
            if url.endswith("naranjo.online/"):
                return page.encode()
            if url.endswith("/readyz"):
                return b"ok"
            if "token?scope" in url:
                return json.dumps({"token": "t"}).encode()
            if url.endswith("/manifests/" + chart_digest):
                return json.dumps(
                    {
                        "layers": layers
                        if layers is not None
                        else [
                            {
                                "mediaType": flip.HELM_CONTENT_TYPE,
                                "digest": chart_layer_digest,
                            }
                        ]
                    }
                ).encode()
            if url.endswith("/blobs/" + chart_layer_digest):
                return chart_blob
            if url.endswith("/manifests/" + image_digest):
                return json.dumps(
                    {
                        "manifests": [
                            {
                                "digest": arm64_digest,
                                "platform": {"architecture": "arm64"},
                            }
                        ]
                    }
                ).encode()
            if url.endswith("/manifests/" + arm64_digest):
                return json.dumps(
                    {"layers": [{"digest": image_layer_digest}]}
                ).encode()
            if url.endswith("/blobs/" + image_layer_digest):
                return layer_blob
            raise AssertionError("unexpected URL " + url)

        with mock.patch.object(flip, "http_get", fake_http_get):
            return flip.verify_live(SOURCE_TEXT, "https://naranjo.online")

    def test_happy_path_names_bundle_chart_and_image(self):
        receipt = self.probe()
        self.assertIn("index-AAAA.css", receipt)
        self.assertIn("sha256:" + "a" * 64, receipt)

    def test_two_live_bundles_are_refused(self):
        with self.assertRaises(SystemExit):
            self.probe(page="assets/index-AAAA.css assets/index-BBBB.css")

    def test_multiple_chart_content_layers_are_refused(self):
        with self.assertRaises(SystemExit):
            self.probe(
                layers=[
                    {"mediaType": flip.HELM_CONTENT_TYPE, "digest": "sha256:" + "d" * 64},
                    {"mediaType": flip.HELM_CONTENT_TYPE, "digest": "sha256:" + "e" * 64},
                ]
            )

    def test_bundle_absent_from_every_layer_is_refused(self):
        with self.assertRaises(SystemExit):
            self.probe(bundles_layer=False)

    def test_source_without_chart_coordinates_is_refused(self):
        with self.assertRaises(SystemExit):
            flip.verify_live("nothing here", "https://naranjo.online")


class RunbookBindingTests(unittest.TestCase):
    """The runbook is pinned TO the tool: editing a ceremony command in the
    prose without the tool (the two round-2 surviving mutants) goes red."""

    def test_every_tool_mode_is_invoked_by_the_runbook(self):
        text = RUNBOOK.read_text()
        for command in (
            "site_sync_branch_flip.py ruleset-receipt",
            "site_sync_branch_flip.py quiescence",
            "site_sync_branch_flip.py prestate",
            "site_sync_branch_flip.py flip-patch",
            "site_sync_branch_flip.py poststate",
            "site_sync_branch_flip.py rollback-patch",
            "site_sync_branch_flip.py rollback-verify",
            "site_sync_branch_flip.py verify-live",
        ):
            self.assertIn(command, text, command)

    def test_captures_are_full_json_inventories_never_label_filtered(self):
        text = RUNBOOK.read_text()
        self.assertNotIn("-l app.kubernetes.io", text)
        self.assertIn("kubectl get cronjob", text)
        self.assertIn("-o json", text)
        self.assertIn("kubectl get jobs -n flux-system -o json", text)
        self.assertIn("kubectl get pods -n flux-system -o json", text)

    def test_the_live_target_is_the_flux_system_gitrepository(self):
        text = RUNBOOK.read_text()
        self.assertIn("kubectl get gitrepository -n flux-system flux-system", text)
        self.assertIn("--type=json", text)
        self.assertNotIn("--type=merge -p '{\"spec\":{\"ref\"", text)


if __name__ == "__main__":
    unittest.main()
