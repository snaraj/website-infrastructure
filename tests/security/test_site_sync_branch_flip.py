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

import json
import os
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
            cronjob, jobs or self.empty("JobList"), self.empty("PodList")
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

    def test_suspend_and_resume_patches_bind_uid_image_and_state(self):
        document = self.capture(selector_cronjob(suspended=False))
        forward = json.loads(flip.suspend_patch(document))
        self.assertEqual(
            [op["op"] for op in forward], ["test", "test", "test", "replace"]
        )
        self.assertEqual(forward[0]["path"], "/metadata/uid")
        self.assertEqual(forward[1]["value"], SELECTOR_IMAGE)
        self.assertEqual(forward[2], {
            "op": "test", "path": "/spec/suspend", "value": False,
        })
        self.assertEqual(forward[3], {
            "op": "replace", "path": "/spec/suspend", "value": True,
        })
        backward = json.loads(flip.resume_patch(document))
        self.assertEqual(backward[2]["value"], True)
        self.assertEqual(backward[3], {
            "op": "replace", "path": "/spec/suspend", "value": False,
        })

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
        self.assertEqual(document["schema"], "site-sync-branch-flip/prestate/v2")
        self.assertEqual(document["ref"], {"tag": "v0.1.54"})
        self.assertEqual(document["spec"]["url"], flip.SOURCE_URL)
        self.assertEqual(
            sorted(document["annotations"]), sorted(flip.RESERVED_ANNOTATIONS)
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


class RunbookCanonTests(unittest.TestCase):
    """The runbook IS the canon: its fenced command blocks equal the tool's
    CEREMONY_BLOCKS byte for byte, in order, with no other invocation
    anywhere in the document. The round-2 security review's three surviving
    mutants — a neutralized invocation retaining its text, an inventory
    narrowed through another query form, a retargeted patch — all change a
    block or a token count, and all go red here."""

    def test_every_canonical_block_appears_exactly_once_in_order(self):
        text = RUNBOOK.read_text()
        position = -1
        for block in flip.CEREMONY_BLOCKS:
            anchored = "\n" + block
            with self.subTest(block=block.splitlines()[0]):
                self.assertEqual(text.count(anchored), 1)
                index = text.index(anchored)
                self.assertGreater(index, position)
                position = index

    def test_no_invocation_exists_outside_the_canonical_blocks(self):
        text = RUNBOOK.read_text()
        canon = "\n" + "".join(flip.CEREMONY_BLOCKS)
        for token in (
            "\nkubectl ",
            "\npython3 ",
            "\nflux ",
            "\ngh api ",
            "\nscratch=",
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
