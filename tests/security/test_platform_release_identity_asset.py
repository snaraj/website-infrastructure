"""Focused hostile tests for the canonical platform release identity asset."""

from __future__ import annotations

import base64
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "platform_release_identity_contract",
    ROOT / "scripts" / "ci" / "platform_release_contract.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PlatformReleaseIdentityAssetTests(unittest.TestCase):
    SOURCE = "a" * 40
    TREE = "f" * 40
    TAG_OBJECT = "b" * 40
    PREDECESSOR = "c" * 40
    TAG = "v0.1.41"
    SELECTOR = "sha256:" + "d" * 64
    RELEASE_ID = 300
    ASSET_ID = 900

    def test_v0142_incident_constants_are_exact_and_closed(self) -> None:
        self.assertEqual(
            {
                "tag": MODULE.BURNED_PARTIAL_TAG,
                "source": MODULE.BURNED_PARTIAL_SOURCE_SHA,
                "tag_object": MODULE.BURNED_PARTIAL_TAG_OBJECT_SHA,
                "tree": MODULE.BURNED_PARTIAL_TREE_SHA,
                "draft_id": MODULE.BURNED_PARTIAL_DRAFT_ID,
                "download_token_sha256": MODULE.BURNED_PARTIAL_DOWNLOAD_TOKEN_SHA256,
                "identity_id": MODULE.BURNED_PARTIAL_IDENTITY_ASSET_ID,
                "identity_sha256": MODULE.BURNED_PARTIAL_IDENTITY_SHA256,
                "bundle_id": MODULE.BURNED_PARTIAL_BUNDLE_ASSET_ID,
                "bundle_sha256": MODULE.BURNED_PARTIAL_BUNDLE_SHA256,
                "main_run": MODULE.BURNED_PARTIAL_MAIN_RUN_ID,
                "platform_run": MODULE.BURNED_PARTIAL_PLATFORM_RUN_ID,
                "run_attempt": MODULE.BURNED_PARTIAL_RUN_ATTEMPT,
                "selector": MODULE.BURNED_PARTIAL_SELECTOR_DIGEST,
            },
            {
                "tag": "v0.1.42",
                "source": "6d85c2b01dd4bd66add4192372b26bcdf1b0a951",
                "tag_object": "9821c1bdb462bb76a9a8c89d5523ab44cdab35e2",
                "tree": "ac999a9d0f1626df897d66903ed52c42a26e65a9",
                "draft_id": 378336604,
                "download_token_sha256": (
                    "b20952c4af11ed71690a8f921cf4010982ef458806d97d2c6073215c28c5644c"
                ),
                "identity_id": 533468594,
                "identity_sha256": (
                    "36d9be841c616aee31a72484f3dddafaa419363c35aa3056bdb3a13becf091f8"
                ),
                "bundle_id": 533468609,
                "bundle_sha256": (
                    "c98827ef92cfb2727128b6acd227ad9a111cada5682a9f1cda7fb6b1e814ca3c"
                ),
                "main_run": 33152936164,
                "platform_run": 33153400419,
                "run_attempt": 1,
                "selector": (
                    "sha256:c9f8d59013bc5ca9431e3ccd22227e4e05920746829318cacf1ccb70b17d2e61"
                ),
            },
        )

    @classmethod
    def receipt_bytes(cls) -> bytes:
        return (
            ROOT / "docs" / "assurance" / "195-chart-acquisition-receipt.json"
        ).read_bytes()

    @classmethod
    def evidence(cls) -> dict[str, object]:
        return {
            "changelog": {
                "fragment_path": "changelog.d/189-195-platform-gitops-activation.md",
                "fragment_sha256": "sha256:" + "e" * 64,
            },
            "main_ci": {
                "conclusion": "success",
                "event": "push",
                "head_sha": cls.SOURCE,
                "ref": MODULE.PROTECTED_REF,
                "run_attempt": 2,
                "run_id": 100,
                "workflow": MODULE.WORKFLOW_PATH,
            },
            "platform_release": {
                "event": "workflow_run",
                "head_sha": cls.SOURCE,
                "ref": MODULE.PROTECTED_REF,
                "run_attempt": 3,
                "run_id": 200,
                "workflow": MODULE.PLATFORM_WORKFLOW_PATH,
            },
            "predecessor": {
                "peeled_commit": cls.PREDECESSOR,
                "tag": "v0.1.40",
            },
            "release": {
                "asset_count": 2,
                "draft": False,
                "id": cls.RELEASE_ID,
                "immutable": True,
                "prerelease": False,
                "tag_name": cls.TAG,
                "target_commitish": cls.SOURCE,
            },
            "repository": "snaraj/website-infrastructure",
            "schema": MODULE.RELEASE_IDENTITY_SCHEMA,
            "selector": {
                "digest": cls.SELECTOR,
                "image": MODULE.SELECTOR_IMAGE,
                "provenance": {
                    "attestor_identity": MODULE.SELECTOR_CERTIFICATE_SUBJECT,
                    "predicate_type": MODULE.SLSA_PROVENANCE_V1,
                    "source_sha": cls.SOURCE,
                    "subject_digest": cls.SELECTOR,
                },
                "signature": {
                    "certificate_identity": MODULE.SELECTOR_CERTIFICATE_SUBJECT,
                    "oidc_issuer": MODULE.SELECTOR_CERTIFICATE_ISSUER,
                },
            },
            "sites": MODULE._site_identities_from_receipt(cls.receipt_bytes()),
            "source": {
                "merge_sha": cls.SOURCE,
                "protected_ref": MODULE.PROTECTED_REF,
                "tree_sha": cls.TREE,
            },
            "tag": {
                "name": cls.TAG,
                "object_sha": cls.TAG_OBJECT,
                "object_type": "tag",
                "peeled_commit": cls.SOURCE,
            },
        }

    @staticmethod
    def canonical(value: object) -> bytes:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

    @classmethod
    def bundle(cls, identity: bytes) -> bytes:
        value = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(
                        hashlib.sha256(identity).digest()
                    ).decode("ascii"),
                },
                "signature": base64.b64encode(b"test-signature").decode("ascii"),
            },
            "verificationMaterial": {
                "certificate": {
                    "rawBytes": base64.b64encode(b"test-certificate").decode(
                        "ascii"
                    )
                },
                "tlogEntries": [{"logIndex": "1"}],
            },
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def release(
        cls,
        identity: bytes,
        bundle: bytes,
        *,
        staged: bool = False,
    ) -> dict[str, object]:
        server_draft_tag = "untagged-aaaaaaaaaaaaaaaaaaaa"
        download_component = server_draft_tag if staged else cls.TAG
        assets = []
        for asset_id, name, payload in (
            (cls.ASSET_ID, MODULE.RELEASE_IDENTITY_ASSET_NAME, identity),
            (
                cls.ASSET_ID + 1,
                MODULE.RELEASE_IDENTITY_BUNDLE_ASSET_NAME,
                bundle,
            ),
        ):
            assets.append(
                {
                    "id": asset_id,
                    "name": name,
                    "label": None,
                    "state": "uploaded",
                    "content_type": "application/json",
                    "size": len(payload),
                    "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                    "url": (
                        "https://api.github.com/repos/"
                        "snaraj/website-infrastructure/releases/assets/"
                        f"{asset_id}"
                    ),
                    "browser_download_url": (
                        "https://github.com/snaraj/website-infrastructure/"
                        f"releases/download/{download_component}/{name}"
                    ),
                    "download_count": 1,
                    "uploader": {
                        "login": "github-actions[bot]",
                        "id": 41898282,
                    },
                }
            )
        return {
            "id": cls.RELEASE_ID,
            # GitHub keeps the canonical draft tag_name while exposing the
            # mutable draft download namespace only in asset URLs.
            "tag_name": cls.TAG,
            "target_commitish": cls.SOURCE,
            "name": f"Platform {cls.TAG}",
            "body": "## Informational notes only\n\nNot a trust input.\n",
            "draft": staged,
            "prerelease": False,
            "immutable": not staged,
            "author": {"login": "github-actions[bot]", "id": 41898282},
            "assets": assets,
        }

    def test_receipt_derives_exact_current_site_identities(self) -> None:
        sites = MODULE._site_identities_from_receipt(self.receipt_bytes())
        self.assertEqual(set(sites), {"lidersea-com", "naranjo-online"})
        self.assertEqual(
            sites["naranjo-online"]["chart"],
            {
                "layer_digest": (
                    "sha256:2ceeb381106d3c75504d8c67"
                    "69431db0d969ecf0af4aedd3b"
                    "43bc3e88e00a62c"
                ),
                "manifest_digest": (
                    "sha256:12bab1e17f838615f81d3901"
                    "cc08fec8a9e8741bf1023c7b0"
                    "6c83ca6442cabc2"
                ),
                "repository": "ghcr.io/snaraj/charts/naranjo-online",
                "version": "0.1.62",
            },
        )
        self.assertEqual(
            sites["naranjo-online"]["workload"],
            {
                "arm64_digest": (
                    "sha256:81c30d13b79ae0bdba2c77af"
                    "04e82868bc5ce50819cdabb6"
                    "af387e5fcc90e89c"
                ),
                "image": (
                    "ghcr.io/snaraj/naranjo-online:v0.1.62@"
                    "sha256:be9593c9ecc3616f9cd1aae"
                    "af641e8a52be5f8f6365498e"
                    "958da8fcaf99cc4e6"
                ),
            },
        )
        self.assertEqual(
            sites["lidersea-com"]["workload"],
            {
                "arm64_digest": (
                    "sha256:694663936ee1061df4a74c19"
                    "d6f3b5caa22892225dc77658"
                    "7e83721b7488840d"
                ),
                "image": (
                    "ghcr.io/snaraj/lidersea-com:v0.1.40@"
                    "sha256:cf8dfc93c863296c7de42ec"
                    "92850a68ab173417d87498f3"
                    "15fafaec9864484c0"
                ),
            },
        )

    def test_receipt_v2_rejects_partial_or_conflicting_acquisition_evidence(self) -> None:
        exact = json.loads(self.receipt_bytes())
        mutations = {
            "legacy schema": lambda value: value.update(
                schema="dev.snaraj.chart-acquisition-receipt/v1"
            ),
            "missing chart config": lambda value: value["records"]
            ["naranjo-online"].pop("chartConfigDigest"),
            "config aliases layer": lambda value: value["records"]
            ["naranjo-online"].update(
                chartConfigDigest=value["records"]["naranjo-online"]
                ["chartLayerDigest"]
            ),
            "missing release source": lambda value: value["records"]
            ["lidersea-com"]["release"].pop("sourceSha"),
            "foreign release source": lambda value: value["records"]
            ["lidersea-com"]["release"].update(sourceSha="f" * 39),
            "foreign release asset": lambda value: value["records"]
            ["lidersea-com"]["release"].update(assetDigest="sha256:" + "G" * 64),
        }
        for name, mutate in mutations.items():
            changed = copy.deepcopy(exact)
            mutate(changed)
            with self.subTest(name=name), self.assertRaises(MODULE.ContractError):
                MODULE._site_identities_from_receipt(self.canonical(changed))

    def test_canonical_signed_pair_is_exact_in_draft_and_immutable_states(self) -> None:
        identity = self.canonical(self.evidence())
        bundle = self.bundle(identity)
        self.assertLessEqual(len(identity), MODULE.MAX_RELEASE_IDENTITY_BYTES)
        final = self.release(identity, bundle)
        staged = self.release(identity, bundle, staged=True)
        MODULE.validate_identity_release_record(
            final,
            identity=identity,
            bundle=bundle,
            tag=self.TAG,
            source_sha=self.SOURCE,
            tag_object_sha=self.TAG_OBJECT,
            tree_sha=self.TREE,
        )
        MODULE.validate_identity_release_record(
            staged,
            identity=identity,
            bundle=bundle,
            tag=self.TAG,
            source_sha=self.SOURCE,
            tag_object_sha=self.TAG_OBJECT,
            tree_sha=self.TREE,
            staged=True,
        )
        self.assertEqual(
            MODULE.selector_image_from_release(
                final,
                identity=identity,
                bundle=bundle,
                expected_tag=self.TAG,
                expected_sha=self.SOURCE,
                expected_selector_build_sha=self.SOURCE,
                expected_tag_object_sha=self.TAG_OBJECT,
                expected_tree_sha=self.TREE,
            ),
            self.SELECTOR,
        )
        changed_body = copy.deepcopy(final)
        changed_body["body"] = "Arbitrary informational Markdown.\n"
        MODULE.validate_identity_release_record(
            changed_body,
            identity=identity,
            bundle=bundle,
            tag=self.TAG,
            source_sha=self.SOURCE,
        )

    def test_staged_urls_and_asset_labels_accept_only_github_normalization(self) -> None:
        identity = self.canonical(self.evidence())
        bundle = self.bundle(identity)
        staged = self.release(identity, bundle, staged=True)

        for label in (None, ""):
            exact = copy.deepcopy(staged)
            for asset in exact["assets"]:
                asset["label"] = label
            MODULE.validate_identity_release_record(
                exact,
                identity=identity,
                bundle=bundle,
                tag=self.TAG,
                source_sha=self.SOURCE,
                staged=True,
            )

        mutations: dict[str, object] = {}
        missing_label = copy.deepcopy(staged)
        del missing_label["assets"][0]["label"]
        mutations["missing label"] = missing_label
        nonempty_label = copy.deepcopy(staged)
        nonempty_label["assets"][0]["label"] = "identity"
        mutations["nonempty label"] = nonempty_label
        synthetic_tag = copy.deepcopy(staged)
        synthetic_tag["tag_name"] = "untagged-aaaaaaaaaaaaaaaaaaaa"
        mutations["synthetic tag_name"] = synthetic_tag
        mixed_tokens = copy.deepcopy(staged)
        mixed_tokens["assets"][1]["browser_download_url"] = mixed_tokens[
            "assets"
        ][1]["browser_download_url"].replace(
            "untagged-aaaaaaaaaaaaaaaaaaaa",
            "untagged-bbbbbbbbbbbbbbbbbbbb",
        )
        mutations["mixed tokens"] = mixed_tokens

        base_url = staged["assets"][0]["browser_download_url"]
        for name, url in {
            "bad token shape": base_url.replace(
                "untagged-aaaaaaaaaaaaaaaaaaaa", "untagged-AAAAAAAAAAAAAAAAAAAA"
            ),
            "bad owner": base_url.replace("github.com/snaraj/", "github.com/other/"),
            "bad repository": base_url.replace(
                "website-infrastructure", "website-infrastructure-fork"
            ),
            "bad asset": base_url + ".foreign",
            "query": base_url + "?download=1",
            "fragment": base_url + "#asset",
            "port": base_url.replace("github.com/", "github.com:443/"),
            "userinfo": base_url.replace(
                "github.com/", "owner" + chr(64) + "github.com/"
            ),
        }.items():
            changed = copy.deepcopy(staged)
            changed["assets"][0]["browser_download_url"] = url
            mutations[name] = changed

        for name, changed in mutations.items():
            with self.subTest(name=name), self.assertRaises(MODULE.ContractError):
                MODULE.validate_identity_release_record(
                    changed,
                    identity=identity,
                    bundle=bundle,
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    staged=True,
                )

        final_with_synthetic_url = self.release(identity, bundle)
        final_with_synthetic_url["assets"][0]["browser_download_url"] = (
            staged["assets"][0]["browser_download_url"]
        )
        with self.assertRaises(MODULE.ContractError):
            MODULE.validate_identity_release_record(
                final_with_synthetic_url,
                identity=identity,
                bundle=bundle,
                tag=self.TAG,
                source_sha=self.SOURCE,
            )

    def test_noncanonical_oversized_duplicate_and_semantic_mutations_fail(self) -> None:
        evidence = self.evidence()
        identity = self.canonical(evidence)
        bundle = self.bundle(identity)
        malformed = (
            identity[:-1],
            identity.replace(b"\n", b"\r\n"),
            json.dumps(evidence, indent=2).encode() + b"\n",
            identity.replace(
                b'{"changelog":',
                b'{"repository":"snaraj/website-infrastructure","changelog":',
                1,
            ),
            b'{"padding":"' + b"x" * MODULE.MAX_RELEASE_IDENTITY_BYTES + b'"}\n',
        )
        for index, payload in enumerate(malformed):
            with self.subTest(malformed=index), self.assertRaises(MODULE.ContractError):
                MODULE._canonical_release_identity(payload)

        for path, foreign in (
            (("release", "asset_count"), 0),
            (("release", "asset_count"), True),
            (("release", "id"), 301),
            (("schema",), "foreign/v1"),
            (("source", "tree_sha"), None),
            (("source", "protected_ref"), "refs/heads/Main"),
            (("tag", "object_sha"), "0" * 40),
            (
                ("sites", "naranjo-online", "chart", "manifest_digest"),
                evidence["sites"]["naranjo-online"]["chart"]["layer_digest"],
            ),
            (("sites", "lidersea-com", "workload", "image"), "foreign"),
        ):
            changed = copy.deepcopy(evidence)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = foreign
            changed_identity = self.canonical(changed)
            with self.subTest(path=path), self.assertRaises(MODULE.ContractError):
                MODULE.validate_identity_release_record(
                    self.release(changed_identity, self.bundle(changed_identity)),
                    identity=changed_identity,
                    bundle=self.bundle(changed_identity),
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    tag_object_sha=self.TAG_OBJECT,
                )

        for path in (
            ("release", "draft"),
            ("release", "prerelease"),
            ("source", "tree_sha"),
        ):
            changed = copy.deepcopy(evidence)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            del parent[path[-1]]
            changed_identity = self.canonical(changed)
            with self.subTest(omitted=path), self.assertRaises(MODULE.ContractError):
                MODULE.validate_identity_release_record(
                    self.release(changed_identity, self.bundle(changed_identity)),
                    identity=changed_identity,
                    bundle=self.bundle(changed_identity),
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    tag_object_sha=self.TAG_OBJECT,
                )

        changed = copy.deepcopy(evidence)
        changed["platform_release"]["conclusion"] = "success"
        changed_identity = self.canonical(changed)
        with self.assertRaises(MODULE.ContractError):
            MODULE.validate_identity_release_record(
                self.release(changed_identity, self.bundle(changed_identity)),
                identity=changed_identity,
                bundle=self.bundle(changed_identity),
                tag=self.TAG,
                source_sha=self.SOURCE,
                tag_object_sha=self.TAG_OBJECT,
            )

    def test_partial_and_foreign_asset_metadata_fail_closed(self) -> None:
        identity = self.canonical(self.evidence())
        bundle = self.bundle(identity)
        exact = self.release(identity, bundle)
        mutations = []
        for field, value in (
            ("name", "foreign.json"),
            ("label", "mutable"),
            ("state", "new"),
            ("content_type", "application/octet-stream"),
            ("size", len(identity) + 1),
            ("digest", "sha256:" + "0" * 64),
            ("url", "https://example.invalid/asset"),
            ("browser_download_url", "https://example.invalid/asset"),
            ("download_count", -1),
            ("uploader", {"login": "owner", "id": 1}),
        ):
            changed = copy.deepcopy(exact)
            changed["assets"][0][field] = value
            mutations.append(changed)
        missing = copy.deepcopy(exact)
        missing["assets"] = []
        mutations.append(missing)
        partial = copy.deepcopy(exact)
        del partial["assets"][0]["digest"]
        mutations.append(partial)
        extra = copy.deepcopy(exact)
        extra["assets"].append(copy.deepcopy(extra["assets"][0]))
        mutations.append(extra)
        for index, changed in enumerate(mutations):
            with self.subTest(asset_mutation=index), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_identity_release_record(
                    changed,
                    identity=identity,
                    bundle=bundle,
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                )

    def test_bundle_must_sign_exact_identity_and_have_supported_material(self) -> None:
        identity = self.canonical(self.evidence())
        bundle = self.bundle(identity)
        release = self.release(identity, bundle)
        MODULE.validate_identity_release_record(
            release,
            identity=identity,
            bundle=bundle,
            tag=self.TAG,
            source_sha=self.SOURCE,
        )
        mutations = []
        decoded = json.loads(bundle)
        for path, value in (
            (("mediaType",), "foreign"),
            (("messageSignature", "messageDigest", "algorithm"), "SHA2_512"),
            (
                ("messageSignature", "messageDigest", "digest"),
                base64.b64encode(b"0" * 32).decode("ascii"),
            ),
            (("messageSignature", "signature"), "not-base64"),
            (("verificationMaterial", "certificate", "rawBytes"), ""),
            (("verificationMaterial", "tlogEntries"), []),
        ):
            changed = copy.deepcopy(decoded)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(self.canonical(changed).rstrip(b"\n"))
        for index, changed_bundle in enumerate(mutations):
            changed_release = self.release(identity, changed_bundle)
            with self.subTest(bundle_mutation=index), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_identity_release_record(
                    changed_release,
                    identity=identity,
                    bundle=changed_bundle,
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                )

    def test_selector_build_lineage_is_carried_independently_of_platform_source(self) -> None:
        build_sha = "9" * 40
        evidence = self.evidence()
        evidence["selector"]["provenance"]["source_sha"] = build_sha
        identity = self.canonical(evidence)
        bundle = self.bundle(identity)
        release = self.release(identity, bundle)
        self.assertEqual(
            MODULE.selector_image_from_release(
                release,
                identity=identity,
                bundle=bundle,
                expected_tag=self.TAG,
                expected_sha=self.SOURCE,
                expected_selector_build_sha=build_sha,
            ),
            self.SELECTOR,
        )
        with self.assertRaises(MODULE.ContractError):
            MODULE.selector_image_from_release(
                release,
                identity=identity,
                bundle=bundle,
                expected_tag=self.TAG,
                expected_sha=self.SOURCE,
                expected_selector_build_sha=self.SOURCE,
            )

    def test_signed_receipt_run_ids_select_exact_successful_attempts(self) -> None:
        identity = self.canonical(self.evidence())

        def run(key: str) -> dict[str, object]:
            receipt = self.evidence()[key]
            return {
                "id": receipt["run_id"],
                "run_attempt": receipt["run_attempt"],
                "event": receipt["event"],
                "head_branch": "main",
                "head_sha": self.SOURCE,
                "path": receipt["workflow"],
                "status": "completed",
                "conclusion": "success",
                "repository": {
                    "full_name": "snaraj/website-infrastructure"
                },
            }

        main = run("main_ci")
        platform = run("platform_release")
        MODULE.validate_identity_run_records(identity, main, platform)
        for record, field, value in (
            (main, "run_attempt", 3),
            (main, "conclusion", "failure"),
            (platform, "id", 201),
            (platform, "head_sha", "0" * 40),
        ):
            changed_main = copy.deepcopy(main)
            changed_platform = copy.deepcopy(platform)
            changed = changed_main if record is main else changed_platform
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_identity_run_records(
                    identity, changed_main, changed_platform
                )

    def test_burned_partial_is_one_exact_signed_failed_attempt(self) -> None:
        evidence = self.evidence()
        evidence["main_ci"]["run_attempt"] = 1
        evidence["platform_release"]["run_attempt"] = 1
        identity = self.canonical(evidence)
        bundle = self.bundle(identity)
        release = self.release(identity, bundle, staged=True)

        def run(key: str, conclusion: str) -> dict[str, object]:
            receipt = evidence[key]
            return {
                "id": receipt["run_id"],
                "run_attempt": receipt["run_attempt"],
                "event": receipt["event"],
                "head_branch": "main",
                "head_sha": self.SOURCE,
                "path": receipt["workflow"],
                "status": "completed",
                "conclusion": conclusion,
                "repository": {"full_name": "snaraj/website-infrastructure"},
            }

        main = run("main_ci", "success")
        platform = run("platform_release", "failure")
        incident = {
            "BURNED_PARTIAL_TAG": self.TAG,
            "BURNED_PARTIAL_SOURCE_SHA": self.SOURCE,
            "BURNED_PARTIAL_TAG_OBJECT_SHA": self.TAG_OBJECT,
            "BURNED_PARTIAL_TREE_SHA": self.TREE,
            "BURNED_PARTIAL_DRAFT_ID": self.RELEASE_ID,
            "BURNED_PARTIAL_DOWNLOAD_TOKEN_SHA256": hashlib.sha256(
                b"untagged-aaaaaaaaaaaaaaaaaaaa"
            ).hexdigest(),
            "BURNED_PARTIAL_IDENTITY_ASSET_ID": self.ASSET_ID,
            "BURNED_PARTIAL_IDENTITY_SHA256": hashlib.sha256(identity).hexdigest(),
            "BURNED_PARTIAL_BUNDLE_ASSET_ID": self.ASSET_ID + 1,
            "BURNED_PARTIAL_BUNDLE_SHA256": hashlib.sha256(bundle).hexdigest(),
            "BURNED_PARTIAL_MAIN_RUN_ID": 100,
            "BURNED_PARTIAL_PLATFORM_RUN_ID": 200,
            "BURNED_PARTIAL_RUN_ATTEMPT": 1,
            "BURNED_PARTIAL_SELECTOR_DIGEST": self.SELECTOR,
        }

        def validate(
            release_record: dict[str, object],
            identity_payload: bytes = identity,
            bundle_payload: bytes = bundle,
            main_record: dict[str, object] = main,
            platform_record: dict[str, object] = platform,
        ) -> str:
            with mock.patch.multiple(MODULE, **incident):
                return MODULE.validate_burned_partial_release_record(
                    release_record,
                    identity=identity_payload,
                    bundle=bundle_payload,
                    body=release_record["body"],
                    main_run_record=main_record,
                    platform_run_record=platform_record,
                )

        self.assertEqual(validate(release), self.SELECTOR)

        release_mutations = {
            "foreign draft id": ("id", self.RELEASE_ID + 1),
            "moved draft source": ("target_commitish", "0" * 40),
            "foreign draft tag": ("tag_name", "v0.1.99"),
        }
        for name, (field, value) in release_mutations.items():
            changed = copy.deepcopy(release)
            changed[field] = value
            with self.subTest(name=name), self.assertRaises(MODULE.ContractError):
                validate(changed)

        partial = copy.deepcopy(release)
        partial["assets"].pop()
        with self.subTest(name="partial asset inventory"), self.assertRaises(
            MODULE.ContractError
        ):
            validate(partial)

        different_asset_id = copy.deepcopy(release)
        different_asset_id["assets"][0]["id"] = self.ASSET_ID + 10
        different_asset_id["assets"][0]["url"] = (
            "https://api.github.com/repos/snaraj/website-infrastructure/"
            f"releases/assets/{self.ASSET_ID + 10}"
        )
        MODULE.validate_identity_release_record(
            different_asset_id,
            identity=identity,
            bundle=bundle,
            tag=self.TAG,
            source_sha=self.SOURCE,
            staged=True,
        )
        with self.subTest(name="coherent foreign asset id"), self.assertRaises(
            MODULE.ContractError
        ):
            validate(different_asset_id)

        different_token = copy.deepcopy(release)
        for asset in different_token["assets"]:
            asset["browser_download_url"] = asset["browser_download_url"].replace(
                "untagged-aaaaaaaaaaaaaaaaaaaa",
                "untagged-bbbbbbbbbbbbbbbbbbbb",
            )
        MODULE.validate_identity_release_record(
            different_token,
            identity=identity,
            bundle=bundle,
            tag=self.TAG,
            source_sha=self.SOURCE,
            staged=True,
        )
        with self.subTest(name="coherent foreign staged token"), self.assertRaises(
            MODULE.ContractError
        ):
            validate(different_token)

        altered_evidence = copy.deepcopy(evidence)
        altered_evidence["changelog"]["fragment_sha256"] = "sha256:" + "0" * 64
        altered_identity = self.canonical(altered_evidence)
        altered_bundle = self.bundle(altered_identity)
        altered_release = self.release(altered_identity, altered_bundle, staged=True)
        MODULE.validate_identity_release_record(
            altered_release,
            identity=altered_identity,
            bundle=altered_bundle,
            tag=self.TAG,
            source_sha=self.SOURCE,
            staged=True,
        )
        with self.subTest(name="coherent foreign identity bytes"), self.assertRaises(
            MODULE.ContractError
        ):
            validate(altered_release, altered_identity, altered_bundle)

        for name, record, field, value in (
            ("foreign main run", main, "id", 101),
            ("wrong platform conclusion", platform, "conclusion", "success"),
            ("incomplete platform run", platform, "status", "in_progress"),
        ):
            changed_main = copy.deepcopy(main)
            changed_platform = copy.deepcopy(platform)
            changed = changed_main if record is main else changed_platform
            changed[field] = value
            with self.subTest(name=name), self.assertRaises(MODULE.ContractError):
                validate(release, main_record=changed_main, platform_record=changed_platform)

        moved_evidence = copy.deepcopy(evidence)
        moved_evidence["tag"]["object_sha"] = "0" * 40
        moved_identity = self.canonical(moved_evidence)
        moved_bundle = self.bundle(moved_identity)
        moved_release = self.release(moved_identity, moved_bundle, staged=True)
        with self.subTest(name="moved annotated tag"), self.assertRaises(
            MODULE.ContractError
        ):
            validate(moved_release, moved_identity, moved_bundle)

    def test_renderer_is_deterministic_compact_and_receipt_bound(self) -> None:
        window = MODULE.TransitionWindow(
            base_sha=self.PREDECESSOR,
            base_tag="v0.1.40",
            intent=MODULE.Intent(self.SOURCE, MODULE.Version(0, 1, 41)),
            fragment_path="changelog.d/189-195-platform-gitops-activation.md",
            fragment_sha256="e" * 64,
        )
        with (
            mock.patch.object(MODULE, "_exact_commit", return_value=self.SOURCE),
            mock.patch.object(MODULE, "_git", return_value=self.TREE),
            mock.patch.object(MODULE, "discover_transition_window", return_value=window),
            mock.patch.object(MODULE, "_file_bytes", return_value=self.receipt_bytes()),
        ):
            first = MODULE.render_release_identity(
                ROOT,
                self.SOURCE,
                self.TAG,
                expected_base_sha=self.PREDECESSOR,
                expected_base_tag="v0.1.40",
                tag_object_sha=self.TAG_OBJECT,
                release_id=self.RELEASE_ID,
                main_run_id=100,
                main_run_attempt=2,
                platform_run_id=200,
                platform_run_attempt=3,
                selector_image_digest=self.SELECTOR,
                selector_build_sha=self.SOURCE,
            )
            second = MODULE.render_release_identity(
                ROOT,
                self.SOURCE,
                self.TAG,
                expected_base_sha=self.PREDECESSOR,
                expected_base_tag="v0.1.40",
                tag_object_sha=self.TAG_OBJECT,
                release_id=self.RELEASE_ID,
                main_run_id=100,
                main_run_attempt=2,
                platform_run_id=200,
                platform_run_attempt=3,
                selector_image_digest=self.SELECTOR,
                selector_build_sha=self.SOURCE,
            )
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))
        self.assertFalse(first.endswith("\n\n"))
        self.assertNotIn("\n ", first)
        rendered = json.loads(first)
        self.assertEqual(rendered["release"]["asset_count"], 2)
        self.assertEqual(rendered["source"]["tree_sha"], self.TREE)
        self.assertEqual(rendered["sites"], self.evidence()["sites"])

    def test_asset_cli_paths_enforce_exact_and_absent_states(self) -> None:
        identity = self.canonical(self.evidence())
        bundle = self.bundle(identity)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity_path = root / MODULE.RELEASE_IDENTITY_ASSET_NAME
            bundle_path = root / MODULE.RELEASE_IDENTITY_BUNDLE_ASSET_NAME
            final_path = root / "release.json"
            staged_path = root / "staged.json"
            identity_path.write_bytes(identity)
            bundle_path.write_bytes(bundle)
            final_path.write_text(
                json.dumps(self.release(identity, bundle)), encoding="utf-8"
            )
            staged_path.write_text(
                json.dumps(self.release(identity, bundle, staged=True)),
                encoding="utf-8",
            )
            common = [
                "--identity",
                str(identity_path),
                "--bundle",
                str(bundle_path),
                "--tag",
                self.TAG,
                "--source-sha",
                self.SOURCE,
                "--selector-build-sha",
                self.SOURCE,
                "--tag-object-sha",
                self.TAG_OBJECT,
                "--source-tree-sha",
                self.TREE,
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    MODULE.main(
                        [
                            "identity-release-record",
                            "--release-json",
                            str(final_path),
                            *common,
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    MODULE.main(
                        [
                            "staged-identity-release-record",
                            "--release-json",
                            str(staged_path),
                            *common,
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    MODULE.main(
                        [
                            "identity-release-state",
                            "--http-status",
                            "404",
                            "--require",
                            "absent",
                            "--tag",
                            self.TAG,
                            "--source-sha",
                            self.SOURCE,
                        ]
                    ),
                    0,
                )

    def test_publisher_signs_uploads_revalidates_then_publishes(self) -> None:
        publisher = (
            ROOT / "scripts" / "ci" / "publish-platform-release.sh"
        ).read_text(encoding="utf-8")
        publication = publisher.split(
            "write_current_identity \"${release_id}\" \"${tag_object}\"", 1
        )[1]
        ordered = (
            "cosign sign-blob --yes",
            'verify_identity_signature "${identity_asset}" "${identity_bundle}"',
            'upload_identity_asset "${release_id}" "${identity_asset_name}"',
            'upload_identity_asset "${release_id}" "${identity_bundle_name}"',
            "download_identity_pair",
            'cmp -s "${identity_asset}" "${identity_download}"',
            'cmp -s "${identity_bundle}" "${bundle_download}"',
            "staged-identity-release-record",
            "'{body:$body,draft:false,name:$name,prerelease:false,"
            "tag_name:$tag,target_commitish:$target}'",
        )
        cursor = -1
        for token in ordered:
            position = publication.find(token, cursor + 1)
            self.assertGreater(position, cursor, token)
            cursor = position
        self.assertNotIn(".body | fromjson", publisher)
        self.assertIn('--data-binary "@${path}"', publisher)
        self.assertIn("--header 'Content-Type: application/json'", publisher)
        legacy_edge = (
            '[ "${BASE_TAG}" != v0.1.40 ] || [ "${TAG}" != v0.1.41 ]'
        )
        self.assertEqual(publisher.count(legacy_edge), 1)
        self.assertIn('test "${BASE_TAG}" = v0.1.40', publisher)
        self.assertIn('test "${TAG}" = v0.1.41', publisher)
        self.assertNotIn("require-ready", publisher)
        self.assertNotIn("validate_selector_seed.py", publisher)
        self.assertIn("validate_platform_predecessor.py", publisher)
        self.assertIn("identity-run-records", publisher)
        self.assertIn("--source-tree-sha", publisher)

        workflow = (ROOT / ".github" / "workflows" / "platform-release.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".body | fromjson", workflow)
        self.assertIn("platform-release-identity.v1.json", workflow)
        self.assertIn("platform-release-identity.v1.json.sigstore.json", workflow)
        self.assertNotIn(
            '--identity "${predecessor_identity}" --release-json "${predecessor}"',
            workflow,
        )
        self.assertIn('--main-runs-json "${legacy_main_runs}"', workflow)
        self.assertIn('--platform-runs-json "${legacy_platform_runs}"', workflow)
        self.assertEqual(workflow.count(legacy_edge), 1)
        self.assertEqual(workflow.count("actions: read"), 1)
        self.assertIn("validate_platform_predecessor.py", workflow)
        self.assertIn("cosign verify-blob", workflow)
        run_records = workflow.split("fetch_run_records() {", 1)[1].split(
            "verify_canonical_identity() {", 1
        )[0]
        self.assertEqual(
            run_records.count('--header "Authorization: Bearer ${GH_TOKEN}"'), 2
        )
        workflow_lines = workflow.splitlines()
        api_calls = [
            index
            for index, line in enumerate(workflow_lines)
            if '"${api}/' in line
        ]
        self.assertGreater(len(api_calls), 0)
        for endpoint in api_calls:
            command = endpoint
            while command >= 0 and "curl " not in workflow_lines[command]:
                command -= 1
            self.assertGreaterEqual(command, 0)
            self.assertIn(
                '--header "Authorization: Bearer ${GH_TOKEN}"',
                "\n".join(workflow_lines[command : endpoint + 1]),
            )
        self.assertLess(
            workflow.index("Install checksum-verified release tools"),
            workflow.index("Select the immutable selector image lineage"),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
