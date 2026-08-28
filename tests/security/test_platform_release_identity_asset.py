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
        download_component = "untagged-draft" if staged else cls.TAG
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
                    "sha256:df748d25b8a4f69491f8ccce"
                    "4b3d8c2b915cb41b525b5d0d"
                    "80c94c780fbdf09e"
                ),
                "manifest_digest": (
                    "sha256:22a29d488a9578d87d4a2f69"
                    "fd02e4ef35daa1fb5800bc6b"
                    "d12ac974b73a8c42"
                ),
                "repository": "ghcr.io/snaraj/charts/naranjo-online",
                "version": "0.1.50",
            },
        )
        self.assertEqual(
            sites["naranjo-online"]["workload"],
            {
                "arm64_digest": (
                    "sha256:3b648da2b4b6c1df1232344c"
                    "a16746ddb907cfcbf9b8da04"
                    "da60b1253ceee361"
                ),
                "image": (
                    "ghcr.io/snaraj/naranjo-online:v0.1.50@"
                    "sha256:89a9e34730d32ee68338da93"
                    "c8d146b315441e454aae55a7"
                    "0db349396295b41f"
                ),
            },
        )
        self.assertEqual(
            sites["lidersea-com"]["workload"],
            {
                "arm64_digest": (
                    "sha256:c58f87669482096362f7a4db"
                    "307403f1bcee9859c643a24f"
                    "23d627c08a434db4"
                ),
                "image": (
                    "ghcr.io/snaraj/lidersea-com:v0.1.37@"
                    "sha256:22673a01a892da2b644369ee"
                    "3c2d0339c13ef8eddc1d3423"
                    "411ce90bbe25d8b1"
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
            "printf '{\"draft\":false}",
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
