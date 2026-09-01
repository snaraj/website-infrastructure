"""Pin every judgment of ``scripts/promote_releases.py`` (issue #286).

The fake fleet below is byte-honest: every digest the registry answers is
computed from the bytes it names (chain: child manifests -> index ->
values.yaml -> chart layer -> config -> manifest -> Release asset), so a
placeholder digest can never hide a missing verification. Each refusal test
perturbs exactly one thing and asserts the specific ``Refusal`` message, so
a load error or a vacuous pass cannot read as a kill. The tick test runs
the real tool against a real local bare ``origin`` with scripted ``gh``,
``cosign``, ``make`` and ``ssh-add`` answers, and pins the argv shapes the
tool sends (signed commit, push refspec, Draft pull request, both review
labels, the Ready flip).
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from .support import REPO_ROOT, hermetic_git_environment, load_script

MODULE = load_script("promote_releases.py")
# The contract module declares dataclasses, which resolve their annotations
# through ``sys.modules`` — so it must be registered under its own name.
_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "promoter_release_contract", REPO_ROOT / "scripts" / "ci" / "platform_release_contract.py"
)
assert _CONTRACT_SPEC and _CONTRACT_SPEC.loader
CONTRACT = importlib.util.module_from_spec(_CONTRACT_SPEC)
sys.modules[_CONTRACT_SPEC.name] = CONTRACT
_CONTRACT_SPEC.loader.exec_module(CONTRACT)
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "release-promotion.md"
SUBJECT = "https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/heads/main"
# The owner's synthetic noreply identity for the hermetic repositories: the
# same shape the tool derives from the authenticated user, built from parts
# so no address literal enters the tree.
OWNER_ID = 7
OWNER_EMAIL = f"{OWNER_ID}+{MODULE.ASSIGNEE}@{MODULE.NOREPLY_DOMAIN}"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hex_tokens(text: str, width: int) -> set:
    return set(re.findall(r"\b[0-9a-f]{%d}\b" % width, text))


class FakeFleet:
    """One workload's registry, Release and cosign answers, all derived from
    bytes. ``perturb`` hooks let a test change exactly one answer."""

    def __init__(self, slug="naranjo-online", site="snaraj/naranjo.online", version="0.1.71", schema="naranjo"):
        self.slug, self.site, self.version, self.schema = slug, site, version, schema
        self.chart_repo = f"ghcr.io/snaraj/charts/{slug}"
        self.image_repo = f"ghcr.io/snaraj/{slug}"
        self.subject = f"https://github.com/{site}/.github/workflows/release-publisher.yml@refs/heads/main"
        self.source_sha = hashlib.sha1(f"{site} {version}".encode()).hexdigest()
        self.tag_object_sha = hashlib.sha1(f"tag {version}".encode()).hexdigest()
        self.calls = []
        self.manifest_answers = {}
        self.blobs = {}
        self.gh = {}
        self.downloads = {}
        # A mutation that changes chart bytes sets one of these and rebuilds,
        # so every digest downstream of the change is re-derived honestly.
        self.overrides = {}
        self.build()

    # -- construction ------------------------------------------------------
    def build(self):
        amd64 = json.dumps({"schemaVersion": 2, "layers": [{"digest": "sha256:" + "1" * 64}]}).encode()
        arm64 = json.dumps({"schemaVersion": 2, "layers": [{"digest": "sha256:" + "2" * 64}]}).encode()
        self.arm64_digest = sha(arm64)
        self.index_children = self.overrides.get(
            "index_children",
            [
                {"mediaType": MODULE.OCI_MANIFEST, "digest": sha(amd64), "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": MODULE.OCI_MANIFEST, "digest": self.arm64_digest, "platform": {"os": "linux", "architecture": "arm64"}},
                {"mediaType": MODULE.OCI_MANIFEST, "digest": "sha256:" + "3" * 64, "platform": {"os": "unknown", "architecture": "unknown"}},
            ],
        )
        self.index_bytes = json.dumps({"schemaVersion": 2, "mediaType": MODULE.OCI_INDEX, "manifests": self.index_children}).encode()
        self.index_digest = sha(self.index_bytes)
        self.chart_yaml = self.overrides.get(
            "chart_yaml",
            (
                f"apiVersion: v2\nappVersion: {self.version}\ndescription: test\nname: {self.slug}\n"
                f"type: application\nversion: {self.version}\n"
            ).encode(),
        )
        self.values_yaml = (
            "replicaCount: 1\n\nimage:\n"
            f"  repository: {self.image_repo}\n  # the published tag\n  tag: v{self.version}\n"
            f"  digest: {self.overrides.get('values_digest', self.index_digest)}\n  pullPolicy: IfNotPresent\n\nservice:\n  port: 8080\n"
        ).encode()
        self.layer_bytes = self.tar({f"{self.slug}/Chart.yaml": self.chart_yaml, f"{self.slug}/values.yaml": self.values_yaml})
        self.layer_digest = sha(self.layer_bytes)
        self.config_bytes = json.dumps(
            {"name": self.slug, "version": self.version, "apiVersion": "v2", "appVersion": self.version, "type": "application"}
        ).encode()
        self.config_digest = sha(self.config_bytes)
        self.layers = [{"mediaType": MODULE.HELM_LAYER, "digest": self.layer_digest, "size": len(self.layer_bytes)}]
        self.manifest_bytes = json.dumps(
            {
                "schemaVersion": 2,
                "config": {"mediaType": MODULE.HELM_CONFIG, "digest": self.config_digest, "size": len(self.config_bytes)},
                "layers": self.layers,
            }
        ).encode()
        self.manifest_digest = sha(self.manifest_bytes)
        self.asset_bytes = json.dumps(self.release_manifest()).encode()
        self.asset_digest = sha(self.asset_bytes)
        self.asset_url = f"https://github.com/{self.site}/releases/download/v{self.version}/release-manifest.json"
        self.blobs = {
            (self.chart_repo, self.config_digest): self.config_bytes,
            (self.chart_repo, self.layer_digest): self.layer_bytes,
        }
        self.manifest_answers = {
            (self.chart_repo, self.version, MODULE.OCI_MANIFEST): (self.manifest_bytes, self.manifest_digest),
            (self.image_repo, f"v{self.version}", MODULE.OCI_INDEX): (self.index_bytes, self.index_digest),
        }
        self.gh = {
            f"repos/{self.site}/releases/tags/v{self.version}": {
                "immutable": True,
                "draft": False,
                "prerelease": False,
                "assets": [{"name": "release-manifest.json", "digest": self.asset_digest, "browser_download_url": self.asset_url}],
            },
            f"repos/{self.site}/git/ref/tags/v{self.version}": {"object": {"type": "tag", "sha": self.tag_object_sha}},
            f"repos/{self.site}/git/tags/{self.tag_object_sha}": {
                "tag": f"v{self.version}",
                "object": {"type": "commit", "sha": self.source_sha},
            },
            f"repos/{self.site}/compare/main...{self.source_sha}": {"status": "behind"},
        }
        self.downloads = {self.asset_url: self.asset_bytes}

    def release_manifest(self):
        if self.schema == "lidersea":
            return {
                "schema": "lidersea.release-manifest/v1",
                "repository": self.site,
                "tag": f"v{self.version}",
                "version": self.version,
                "workflow_identity": self.subject,
                "source_sha": self.source_sha,
                "artifacts": {
                    "chart": {"registry": self.chart_repo, "digest": self.manifest_digest, "signature": {"certificate_identity": self.subject, "oidc_issuer": MODULE.ACTIONS_ISSUER, "required": True}},
                    "image": {"registry": self.image_repo, "digest": self.index_digest, "signature": {"certificate_identity": self.subject, "oidc_issuer": MODULE.ACTIONS_ISSUER, "required": True}},
                },
            }
        return {
            "schema": "https://naranjo.online/schemas/release-manifest/v1",
            "repository": self.site,
            "release": {"tag": f"v{self.version}", "version": self.version},
            "publisher": {"workflow": ".github/workflows/release-publisher.yml", "ref": "refs/heads/main"},
            "source_sha": self.source_sha,
            "artifacts": {
                "chart": {"repository": self.chart_repo, "tag": self.version, "digest": self.manifest_digest, "signature_identity": self.subject},
                "image": {"repository": self.image_repo, "tag": f"v{self.version}", "digest": self.index_digest, "signature_identity": self.subject, "platforms": ["linux/amd64", "linux/arm64"]},
            },
        }

    @staticmethod
    def tar(members: dict) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    # -- transports --------------------------------------------------------
    def fetch(self, url, headers, limit):
        self.calls.append(("fetch", url))
        # The distribution API takes the repository PATH; a host-qualified
        # name in the URL or the token scope is the real registry's 404.
        if url.startswith("https://ghcr.io/token?"):
            if "repository:ghcr.io/" in url:
                raise MODULE.Refusal(f"fake registry: host-qualified token scope {url}")
            return b'{"token": "anonymous-pull"}', {}
        if url.startswith("https://ghcr.io/v2/ghcr.io/"):
            raise MODULE.Refusal(f"fake registry: host-qualified repository path {url}")
        match = re.match(r"https://ghcr\.io/v2/(snaraj/[a-z0-9/-]+)/manifests/([^/]+)$", url)
        if match:
            key = ("ghcr.io/" + match.group(1), match.group(2), headers.get("Accept"))
            if key not in self.manifest_answers:
                raise MODULE.Refusal(f"fake registry: no manifest for {key}")
            body, header = self.manifest_answers[key]
            return body, {"docker-content-digest": header}
        match = re.match(r"https://ghcr\.io/v2/(snaraj/[a-z0-9/-]+)/blobs/(sha256:[0-9a-f]{64})$", url)
        if match:
            return self.blobs[("ghcr.io/" + match.group(1), match.group(2))], {}
        if url in self.downloads:
            return self.downloads[url], {}
        raise AssertionError(f"unexpected fetch {url}")

    def run(self, argv, cwd=None, input_text=None, env=None):
        self.calls.append(("run", tuple(argv)))
        if argv[:2] == ["gh", "api"]:
            path = argv[-1] if "--input" not in argv else argv[argv.index("--input") - 1]
            path = [a for a in argv if not a.startswith("-") and a not in ("gh", "api", "GET", "POST", "PATCH", "DELETE", "Accept: application/vnd.github+json")][-1]
            if path not in self.gh:
                raise MODULE.Refusal(f"`gh api {path}` exited 1: gh: Not Found (HTTP 404)")
            return json.dumps(self.gh[path])
        if argv[:3] == ["cosign", "version", "--json"]:
            return json.dumps({"gitVersion": "v3.1.3"})
        if argv[:2] == ["cosign", "verify"]:
            digest = argv[-1].split("@", 1)[1]
            return json.dumps([{"critical": {"image": {"docker-manifest-digest": digest}, "identity": {"docker-reference": argv[-1]}}, "optional": {}}])
        if argv[:2] == ["cosign", "verify-attestation"]:
            digest = argv[-1].split("@", 1)[1]
            statement = {"_type": "https://in-toto.io/Statement/v0.1", "subject": [{"name": argv[-1].split("@")[0], "digest": {"sha256": digest.split(":")[1]}}], "predicateType": MODULE.SLSA_V1, "predicate": {}}
            envelope = {"payloadType": MODULE.IN_TOTO, "payload": base64.b64encode(json.dumps(statement).encode()).decode(), "signatures": []}
            return json.dumps(envelope) + "\n" + json.dumps(envelope) + "\n"
        raise AssertionError(f"unexpected command {argv}")

    def registry(self):
        return MODULE.Registry(fetch=self.fetch)

    def github(self):
        return MODULE.GitHub(run=self.run, fetch=self.fetch)

    def cosign(self):
        return MODULE.Cosign(run=self.run, pinned_version="v3.1.3")

    def selection(self, committed="0.1.69"):
        return MODULE.Selection(self.slug, f"kubernetes/websites/{self.slug}/source.yaml", committed, "sha256:" + "0" * 64, self.chart_repo, self.site, self.subject)

    def acquire(self):
        return MODULE.acquire(self.selection(), self.version, self.registry(), self.github(), self.cosign())

    def expected_record(self):
        return {
            "arm64Digest": self.arm64_digest,
            "chart": {"appVersion": self.version, "name": self.slug, "version": self.version},
            "chartConfigDigest": self.config_digest,
            "chartLayerDigest": self.layer_digest,
            "chartRepository": self.chart_repo,
            "chartTag": self.version,
            "manifestDigest": self.manifest_digest,
            "matchingChartLayerCount": 1,
            "release": {"assetDigest": self.asset_digest, "sourceSha": self.source_sha},
            "signer": {"issuer": MODULE.ACTIONS_ISSUER, "subject": self.subject},
            "workloadImage": f"{self.image_repo}:v{self.version}@{self.index_digest}",
        }


class DiscoveryTests(unittest.TestCase):
    def test_committed_selections_are_discovered_from_the_manifests(self):
        selections = MODULE.discover_selections(REPO_ROOT)
        receipt = MODULE.load_receipt(REPO_ROOT)
        self.assertEqual(set(selections), set(receipt["records"]))
        for slug, selection in selections.items():
            record = receipt["records"][slug]
            self.assertEqual(selection.version, record["chartTag"])
            self.assertEqual(selection.digest, record["manifestDigest"])
            self.assertEqual(selection.chart_repository, record["chartRepository"])
            self.assertEqual(selection.subject, record["signer"]["subject"])
            self.assertEqual(selection.source_repository, "snaraj/" + selection.domain)
            self.assertEqual(MODULE.profile_for(selection.subject), "release-publisher")

    def test_unannotated_documents_are_ignored_and_ambiguous_ones_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifests = root / "kubernetes" / "x"
            manifests.mkdir(parents=True)
            source = (REPO_ROOT / "kubernetes/websites/naranjo-online/source.yaml").read_text()
            (manifests / "plain.yaml").write_text("kind: OCIRepository\nmetadata:\n  name: other-chart\n")
            self.assertEqual(MODULE.discover_selections(root), {})
            (manifests / "twice.yaml").write_text(source.replace("  ref:\n    digest:", "  ref:\n    digest: sha256:" + "a" * 64 + "\n    digest:", 1))
            with self.assertRaisesRegex(MODULE.Refusal, "not a closed selection"):
                MODULE.discover_selections(root)

    def test_unknown_publisher_identity_has_no_profile(self):
        with self.assertRaisesRegex(MODULE.Refusal, "no acquisition profile"):
            MODULE.profile_for("https://github.com/someone-else/nas/.github/workflows/release.yml@refs/heads/main")
        with self.assertRaisesRegex(MODULE.Refusal, "no acquisition profile"):
            MODULE.profile_for(SUBJECT.replace("refs/heads/main", "refs/heads/feature"))


class CeremonyTests(unittest.TestCase):
    def test_honest_fleet_yields_the_exact_record_and_pins_cosign_at_digests(self):
        for schema in ("naranjo", "lidersea"):
            with self.subTest(schema=schema):
                fleet = FakeFleet(schema=schema)
                record, inspection = fleet.acquire()
                self.assertEqual(record, fleet.expected_record())
                self.assertEqual(inspection, {"Chart.yaml": sha(fleet.chart_yaml), "values.yaml": sha(fleet.values_yaml)})
                verify = [c for c in fleet.calls if c[0] == "run" and c[1][:2] == ("cosign", "verify")]
                attest = [c for c in fleet.calls if c[0] == "run" and c[1][:2] == ("cosign", "verify-attestation")]
                self.assertEqual(len(verify), 1)
                self.assertEqual(len(attest), 1)
                self.assertEqual(verify[0][1][-1], f"{fleet.chart_repo}@{fleet.manifest_digest}")
                self.assertIn("--certificate-identity", verify[0][1])
                self.assertEqual(verify[0][1][verify[0][1].index("--certificate-identity") + 1], fleet.subject)
                self.assertEqual(attest[0][1][-1], f"{fleet.image_repo}@{fleet.index_digest}")
                self.assertIn("--new-bundle-format", attest[0][1])
                self.assertEqual(attest[0][1][attest[0][1].index("--type") + 1], "slsaprovenance1")
                manifests = [c[1] for c in fleet.calls if c[0] == "fetch" and "/manifests/" in c[1]]
                # The distribution path carries the repository NAME; the host
                # is the URL's, never repeated inside the path.
                chart_name = fleet.chart_repo.removeprefix("ghcr.io/")
                image_name = fleet.image_repo.removeprefix("ghcr.io/")
                self.assertEqual(manifests.count(f"https://ghcr.io/v2/{chart_name}/manifests/{fleet.version}"), 2)
                self.assertEqual(manifests.count(f"https://ghcr.io/v2/{image_name}/manifests/v{fleet.version}"), 2)
                for call in fleet.calls:
                    if call[0] == "run" and call[1][0] == "cosign":
                        self.assertNotIn(f":{fleet.version}", call[1][-1])
                        self.assertNotIn(f":v{fleet.version}", call[1][-1])

    def refusal(self, mutate, message):
        fleet = FakeFleet()
        mutate(fleet)
        with self.assertRaisesRegex(MODULE.Refusal, message):
            fleet.acquire()

    def test_every_moved_or_lying_answer_is_refused(self):
        def header_lies(f):
            body, _ = f.manifest_answers[(f.chart_repo, f.version, MODULE.OCI_MANIFEST)]
            f.manifest_answers[(f.chart_repo, f.version, MODULE.OCI_MANIFEST)] = (body, "sha256:" + "e" * 64)

        def second_resolution_moves(f):
            original = f.fetch
            state = {"count": 0}

            def fetch(url, headers, limit):
                body, headers_out = original(url, headers, limit)
                if url.endswith(f"/manifests/{f.version}"):
                    state["count"] += 1
                    if state["count"] == 2:
                        body = body + b" "
                        headers_out = {"docker-content-digest": sha(body)}
                return body, headers_out

            f.fetch = fetch

        def two_layers(f):
            f.layers.append(dict(f.layers[0]))
            manifest = json.loads(f.manifest_bytes)
            manifest["layers"] = f.layers
            body = json.dumps(manifest).encode()
            f.manifest_answers[(f.chart_repo, f.version, MODULE.OCI_MANIFEST)] = (body, sha(body))

        def config_version_off(f):
            config = json.loads(f.config_bytes)
            config["version"] = "0.1.70"
            body = json.dumps(config).encode()
            f.blobs[(f.chart_repo, f.config_digest)] = body  # digest now lies too

        def layer_size_off(f):
            manifest = json.loads(f.manifest_bytes)
            manifest["layers"][0]["size"] += 1
            body = json.dumps(manifest).encode()
            f.manifest_answers[(f.chart_repo, f.version, MODULE.OCI_MANIFEST)] = (body, sha(body))

        def chart_yaml_name_off(f):
            f.overrides["chart_yaml"] = f.chart_yaml.replace(b"name: naranjo-online", b"name: other")
            f.build()

        def values_pin_off(f):
            f.overrides["values_digest"] = "sha256:" + "d" * 64
            f.build()

        def no_arm64(f):
            f.overrides["index_children"] = [m for m in f.index_children if m["platform"]["architecture"] != "arm64"]
            f.build()

        def two_arm64(f):
            f.overrides["index_children"] = f.index_children + [dict(f.index_children[1], digest="sha256:" + "4" * 64)]
            f.build()

        def signature_binds_other_digest(f):
            original = f.run

            def run(argv, **kwargs):
                if argv[:2] == ["cosign", "verify"]:
                    return json.dumps([{"critical": {"image": {"docker-manifest-digest": "sha256:" + "b" * 64}}}])
                return original(argv, **kwargs)

            f.run = run

        def attestation_subject_off(f):
            original = f.run

            def run(argv, **kwargs):
                out = original(argv, **kwargs)
                if argv[:2] == ["cosign", "verify-attestation"]:
                    envelope = json.loads(out.splitlines()[0])
                    statement = json.loads(base64.b64decode(envelope["payload"]))
                    statement["subject"][0]["digest"]["sha256"] = "c" * 64
                    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
                    return json.dumps(envelope) + "\n"
                return out

            f.run = run

        def attestation_not_slsa(f):
            original = f.run

            def run(argv, **kwargs):
                out = original(argv, **kwargs)
                if argv[:2] == ["cosign", "verify-attestation"]:
                    envelope = json.loads(out.splitlines()[0])
                    statement = json.loads(base64.b64decode(envelope["payload"]))
                    statement["predicateType"] = "https://slsa.dev/provenance/v0.2"
                    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
                    return json.dumps(envelope) + "\n"
                return out

            f.run = run

        def no_attestation(f):
            original = f.run
            f.run = lambda argv, **kw: "" if argv[:2] == ["cosign", "verify-attestation"] else original(argv, **kw)

        def cosign_off_pin(f):
            original = f.run
            f.run = lambda argv, **kw: json.dumps({"gitVersion": "v3.1.2"}) if argv[:3] == ["cosign", "version", "--json"] else original(argv, **kw)

        def release_mutable(f):
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["immutable"] = False

        def two_assets(f):
            assets = f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"]
            assets.append(dict(assets[0], name="other-release-manifest.json"))

        def asset_digest_lies(f):
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = "sha256:" + "f" * 64

        def manifest_chart_digest_off(f):
            asset = json.loads(f.asset_bytes)
            asset["artifacts"]["chart"]["digest"] = "sha256:" + "9" * 64
            body = json.dumps(asset).encode()
            f.downloads[f.asset_url] = body
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = sha(body)

        def manifest_states_no_identity(f):
            asset = json.loads(f.asset_bytes)
            asset.pop("publisher")
            for kind in ("chart", "image"):
                asset["artifacts"][kind].pop("signature_identity")
            body = json.dumps(asset).encode()
            f.downloads[f.asset_url] = body
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = sha(body)

        def source_sha_disagrees(f):
            f.gh[f"repos/{f.site}/git/tags/{f.tag_object_sha}"]["object"]["sha"] = "a" * 40

        def lightweight_tag(f):
            f.gh[f"repos/{f.site}/git/ref/tags/v{f.version}"]["object"]["type"] = "commit"

        def foreign_download_host(f):
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["browser_download_url"] = "https://evil.example/release-manifest.json"

        def source_not_on_main(f):
            f.gh[f"repos/{f.site}/compare/main...{f.source_sha}"] = {"status": "diverged"}

        def source_ancestry_unknown(f):
            f.gh[f"repos/{f.site}/compare/main...{f.source_sha}"] = {}

        def manifest_omits_chart_repository(f):
            asset = json.loads(f.asset_bytes)
            asset["artifacts"]["chart"].pop("repository")
            body = json.dumps(asset).encode()
            f.downloads[f.asset_url] = body
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = sha(body)

        def asset_is_not_json(f):
            body = b"not json"
            f.downloads[f.asset_url] = body
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = sha(body)

        cases = {
            "content digest header lies": (header_lies, "disagrees with the bytes"),
            "reference moves between resolutions": (second_resolution_moves, "moved between two resolutions"),
            "two helm layers": (two_layers, "exactly one Helm chart layer"),
            "config blob altered": (config_version_off, "do not hash to their digest"),
            "layer size disagrees": (layer_size_off, "layer size disagrees"),
            "chart yaml identity": (chart_yaml_name_off, "Chart.yaml identity"),
            "values pin is not the index": (values_pin_off, "is not the embedded pin"),
            "no arm64 child": (no_arm64, "exactly one linux/arm64 child"),
            "two arm64 children": (two_arm64, "exactly one linux/arm64 child"),
            "signature binds another digest": (signature_binds_other_digest, "signature binds"),
            "attestation subject": (attestation_subject_off, "provenance subject is not exactly"),
            "attestation predicate": (attestation_not_slsa, "not SLSA v1"),
            "no attestation": (no_attestation, "no SLSA v1 provenance statement"),
            "cosign off pin": (cosign_off_pin, "not the versions.env pin"),
            "release not immutable": (release_mutable, "not an immutable final release"),
            "two assets": (two_assets, "exactly one release-manifest.json"),
            "asset digest lies": (asset_digest_lies, "GitHub states"),
            "manifest chart digest": (manifest_chart_digest_off, "release manifest chart.digest states"),
            "manifest states no identity": (manifest_states_no_identity, "states no identity"),
            "source sha disagrees": (source_sha_disagrees, "annotated tag dereferences to"),
            "lightweight tag": (lightweight_tag, "not an annotated tag"),
            "foreign download host": (foreign_download_host, "refusing to download"),
            "source not on main": (source_not_on_main, "not reachable from protected main"),
            "source ancestry unknown": (source_ancestry_unknown, "not reachable from protected main"),
            "manifest omits chart repository": (manifest_omits_chart_repository, "states no chart.repository"),
            "asset is not json": (asset_is_not_json, "malformed answer"),
        }
        for name, (mutate, message) in cases.items():
            with self.subTest(case=name):
                self.refusal(mutate, message)

    def test_chart_layer_hash_mismatch_is_refused_by_the_registry_layer(self):
        fleet = FakeFleet()
        fleet.blobs[(fleet.chart_repo, fleet.layer_digest)] = fleet.layer_bytes + b"\0"
        with self.assertRaisesRegex(MODULE.Refusal, "do not hash to their digest"):
            fleet.acquire()

    def test_registry_names_are_host_stripped_and_foreign_hosts_refused(self):
        fleet = FakeFleet()
        registry = fleet.registry()
        body, header = registry.manifest(fleet.chart_repo, fleet.version, MODULE.OCI_MANIFEST)
        self.assertEqual(sha(body), header)
        self.assertIn(("fetch", f"https://ghcr.io/v2/snaraj/charts/{fleet.slug}/manifests/{fleet.version}"), fleet.calls)
        self.assertIn(("fetch", f"https://ghcr.io/token?scope=repository:snaraj/charts/{fleet.slug}:pull"), fleet.calls)
        with self.assertRaisesRegex(MODULE.Refusal, "not a repository on ghcr.io"):
            registry.manifest("docker.io/snaraj/charts/x", "1.0.0", MODULE.OCI_MANIFEST)
        with self.assertRaisesRegex(MODULE.Refusal, "not a repository on ghcr.io"):
            registry.blob("snaraj/charts/x", "sha256:" + "0" * 64)

    def test_version_must_be_plain_semver(self):
        fleet = FakeFleet()
        for bad in ("v0.1.71", "0.1", "0.01.1", "latest"):
            with self.subTest(version=bad), self.assertRaisesRegex(MODULE.Refusal, "plain semantic version"):
                MODULE.acquire(fleet.selection(), bad, fleet.registry(), fleet.github(), fleet.cosign())

    def test_release_manifest_binding_covers_both_fleet_schemas(self):
        for schema in ("naranjo", "lidersea"):
            fleet = FakeFleet(schema=schema)
            asset = fleet.release_manifest()
            expected = {
                "repository": fleet.site, "version": fleet.version, "tag": f"v{fleet.version}", "identity": fleet.subject,
                "chart.repository": fleet.chart_repo, "chart.digest": fleet.manifest_digest,
                "image.repository": fleet.image_repo, "image.digest": fleet.index_digest,
            }
            with self.subTest(schema=schema):
                MODULE.bind_release_manifest(asset, expected, schema)
                statements = MODULE.release_manifest_statements(asset)
                self.assertTrue(all(statements[key] for key in ("repository", "version", "identity", "chart.digest", "image.digest")))
                for field in expected:
                    wrong = dict(expected, **{field: "not-" + expected[field]})
                    with self.subTest(schema=schema, field=field), self.assertRaisesRegex(MODULE.Refusal, re.escape(field)):
                        MODULE.bind_release_manifest(asset, wrong, schema)
                for field in expected:
                    with self.subTest(schema=schema, missing=field), self.assertRaisesRegex(MODULE.Refusal, "states no " + re.escape(field)):
                        MODULE.bind_release_manifest({}, {field: expected[field]}, "empty")


class ReceiptRenderingTests(unittest.TestCase):
    def test_json_renderer_is_byte_exact_against_the_committed_receipt(self):
        committed = (REPO_ROOT / MODULE.RECEIPT_JSON).read_text(encoding="utf-8")
        self.assertEqual(MODULE.render_receipt_json(json.loads(committed)), committed)

    def test_markdown_view_is_the_template_output_and_keeps_coherence(self):
        receipt = MODULE.load_receipt(REPO_ROOT)
        selections = MODULE.discover_selections(REPO_ROOT)
        committed = (REPO_ROOT / MODULE.RECEIPT_MD).read_text(encoding="utf-8")
        inspection = MODULE.parse_inspection(committed)
        date, issues = MODULE.parse_capture_header(committed)
        self.assertEqual(date, receipt["capturedDate"])
        # The committed header states its own context (which selections
        # moved, which capture it supersedes); the template must reproduce
        # it from that context alone, whatever the tree currently commits.
        header = committed.split("\n\n")[1].replace("\n", " ")
        stated = re.match(r"Captured (\S+) for issues (\S+), which (.+?); it supersedes the issues (\S+) capture of (\S+)\.", header)
        self.assertIsNotNone(stated, header)
        advanced = {slug for slug, selection in selections.items() if f"advanced {selection.domain} to" in stated.group(3)}
        context = {"issues": issues, "advanced": advanced, "previous": (stated.group(5), stated.group(4))}
        rendered = MODULE.render_receipt_markdown(receipt, selections, inspection, context)
        self.assertEqual(rendered, committed)
        self.assertEqual(hex_tokens(rendered, 64), hex_tokens(json.dumps(receipt), 64) | {v.split(":")[1] for h in inspection.values() for v in h.values()})
        self.assertEqual(MODULE.parse_capture_header(rendered), (date, issues))
        with self.assertRaisesRegex(MODULE.Refusal, "capture date and issue"):
            MODULE.parse_capture_header("# nothing\n")

    def test_tool_pins_come_from_versions_env(self):
        self.assertEqual(MODULE.tool_pins(REPO_ROOT), MODULE.load_receipt(REPO_ROOT)["tools"])


def tracked_copy(destination: Path) -> Path:
    """Copy the WORKING TREE of every tracked file into a fresh git repository
    on branch ``main`` with one commit, so ``git ls-files`` and the rewrite
    see exactly what a checkout of this head would."""

    env = hermetic_git_environment()
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True).stdout
    for name in listing.decode().split("\0"):
        if not name:
            continue
        source = REPO_ROOT / name
        if not source.is_file():
            continue
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=destination, check=True, env=env)
    subprocess.run(["git", "add", "-A"], cwd=destination, check=True, env=env)
    subprocess.run(["git", "-c", "user.name=t", "-c", f"user.email={OWNER_EMAIL}", "commit", "-q", "-m", "base"], cwd=destination, check=True, env=env)
    return destination


def promoted_record(record: dict, version: str, salt: str) -> dict:
    """A synthetic successor record with every digest derived from the salt."""

    new = json.loads(json.dumps(record))
    for key in ("manifestDigest", "chartConfigDigest", "chartLayerDigest", "arm64Digest"):
        new[key] = sha(f"{salt}{key}".encode())
    new["release"] = {"assetDigest": sha(f"{salt}asset".encode()), "sourceSha": hashlib.sha1(f"{salt}source".encode()).hexdigest()}
    new["chartTag"] = version
    new["chart"] = {"appVersion": version, "name": record["chart"]["name"], "version": version}
    new["workloadImage"] = f"{record['workloadImage'].split(':v')[0]}:v{version}@{sha(f'{salt}index'.encode())}"
    return new


PINNED = (
    "kubernetes/websites/naranjo-online/source.yaml",
    "policies/conftest/kubernetes.rego",
    "scripts/validate_signature_policy.py",
    "tests/security/test_platform_release_identity_asset.py",
    "tests/security/test_signature_policy_contract.py",
    "docs/assurance/195-chart-acquisition-receipt.json",
    "docs/assurance/195-chart-acquisition-receipt.md",
    "README.md",
)


class RewriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = tracked_copy(Path(self.tmp.name))
        self.selections = MODULE.discover_selections(self.root)
        self.receipt = MODULE.load_receipt(self.root)
        self.markdown = (self.root / MODULE.RECEIPT_MD).read_text()
        self.inspection = MODULE.parse_inspection(self.markdown)
        self.originals = {name: (self.root / name).read_bytes() for name in PINNED}

    def tearDown(self):
        self.tmp.cleanup()

    def promote(self, slug="naranjo-online", version="0.1.99", salt="s1", issue=990):
        record = promoted_record(self.receipt["records"][slug], version, salt)
        inspection = {"Chart.yaml": sha(f"{salt}chart".encode()), "values.yaml": sha(f"{salt}values".encode())}
        changed = MODULE.apply_promotion(self.root, self.selections, {slug: (record, inspection)}, issue, f"#{issue}", "2026-09-02")
        return record, inspection, changed

    def tracked_text(self):
        for name in subprocess.run(["git", "ls-files"], cwd=self.root, capture_output=True, text=True, check=True).stdout.split():
            path = self.root / name
            try:
                yield name, path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, IsADirectoryError):
                continue

    def test_forward_promotion_rewrites_every_pinned_surface_coherently(self):
        old = self.receipt["records"]["naranjo-online"]
        record, inspection, changed = self.promote()
        self.assertEqual(set(changed), set(PINNED) | {"changelog.d/990-promote-naranjo-online-0-1-99.md"})
        old_tokens = {old[k] for k in ("manifestDigest", "chartConfigDigest", "chartLayerDigest", "arm64Digest")}
        old_tokens |= {old["release"]["assetDigest"], old["release"]["sourceSha"], old["workloadImage"]}
        old_tokens |= {v.split(":")[1] for v in self.inspection["naranjo"].values()}
        for name, text in self.tracked_text():
            if name.startswith("changelog.d/"):
                continue
            logical = MODULE.join_literal_runs(text) if name.endswith(".py") else text
            for token in old_tokens:
                self.assertNotIn(token, logical, f"{token[:16]} survives in {name}")
        new_json = json.loads((self.root / MODULE.RECEIPT_JSON).read_text())
        self.assertEqual(new_json["records"]["naranjo-online"], record)
        self.assertEqual(new_json["records"]["lidersea-com"], self.receipt["records"]["lidersea-com"])
        self.assertEqual(new_json["capturedDate"], "2026-09-02")
        CONTRACT._site_identities_from_receipt((self.root / MODULE.RECEIPT_JSON).read_bytes())
        markdown = (self.root / MODULE.RECEIPT_MD).read_text()
        self.assertEqual(MODULE.parse_inspection(markdown)["naranjo"], inspection)
        self.assertEqual(MODULE.parse_capture_header(markdown), ("2026-09-02", "#990"))
        previous_date, previous_issues = MODULE.parse_capture_header(self.markdown)
        self.assertIn(f"supersedes the issues {previous_issues} capture of {previous_date}", markdown.replace("\n", " "))
        self.assertEqual(hex_tokens(markdown, 64), hex_tokens(json.dumps(new_json), 64) | {v.split(":")[1] for h in MODULE.parse_inspection(markdown).values() for v in h.values()})
        for name in ("tests/security/test_platform_release_identity_asset.py", "tests/security/test_signature_policy_contract.py", "scripts/validate_signature_policy.py"):
            compile((self.root / name).read_text(), name, "exec")
        identity_test = (self.root / "tests/security/test_platform_release_identity_asset.py").read_text()
        self.assertIn(inspection["Chart.yaml"].split(":")[1], identity_test)
        self.assertIn('"version": "0.1.99"', identity_test)
        source = (self.root / "kubernetes/websites/naranjo-online/source.yaml").read_text()
        self.assertIn('chart-release: "0.1.99"', source)
        self.assertIn(f"digest: {record['manifestDigest']}", source)
        lidersea = (self.root / "kubernetes/websites/lidersea-com/source.yaml").read_bytes()
        self.assertEqual(lidersea, (REPO_ROOT / "kubernetes/websites/lidersea-com/source.yaml").read_bytes())
        self.assertIn("Current selections: lidersea.com `0.1.41` and naranjo.online `0.1.99`, captured 2026-09-02 for issues #990", (self.root / "README.md").read_text())
        fragment = (self.root / "changelog.d/990-promote-naranjo-online-0-1-99.md").read_text()
        self.assertTrue(CONTRACT.FRAGMENT_PATH_RE.match("changelog.d/990-promote-naranjo-online-0-1-99.md"))
        # The tool's fragment must pass the release-transition gate's own
        # validator, or every promotion PR would fail its required check.
        fragment_path = "changelog.d/990-promote-naranjo-online-0-1-99.md"
        CONTRACT.validate_fragment_bytes(fragment_path, (self.root / fragment_path).read_bytes())
        self.assertTrue(all(line.startswith(("###", "- ")) or not line for line in fragment.splitlines()))
        self.assertIn("naranjo.online `0.1.99`", fragment)

    def test_inverse_promotion_restores_every_pinned_file_byte_for_byte(self):
        self.promote()
        original = self.receipt["records"]["naranjo-online"]
        (self.root / "changelog.d/990-promote-naranjo-online-0-1-99.md").unlink()
        # The committed README row states the capture the inverse must restore.
        date, issues = MODULE.README_ROW_RE.search(self.originals["README.md"].decode()).group(2, 3)
        MODULE.apply_promotion(
            self.root, self.selections, {"naranjo-online": (original, self.inspection["naranjo"])}, int(issues.split("/")[0].lstrip("#")), issues, date
        )
        for name in PINNED:
            if name == "docs/assurance/195-chart-acquisition-receipt.md":
                continue
            with self.subTest(path=name):
                self.assertEqual((self.root / name).read_bytes(), self.originals[name])
        self.assertEqual(MODULE.parse_inspection((self.root / MODULE.RECEIPT_MD).read_text()), self.inspection)

    def test_both_workloads_promote_in_one_rewrite(self):
        acquired = {}
        for slug, salt in (("naranjo-online", "n"), ("lidersea-com", "l")):
            acquired[slug] = (promoted_record(self.receipt["records"][slug], "0.2.0", salt), {"Chart.yaml": sha(f"{salt}c".encode()), "values.yaml": sha(f"{salt}v".encode())})
        changed = MODULE.apply_promotion(self.root, self.selections, acquired, 991, "#991", "2026-09-02")
        self.assertIn("kubernetes/websites/lidersea-com/source.yaml", changed)
        self.assertIn("changelog.d/991-promote-lidersea-com-0-2-0-naranjo-online-0-2-0.md", changed)
        for slug in acquired:
            self.assertIn('"tag": "0.2.0"', (self.root / "policies/conftest/kubernetes.rego").read_text())
        rego = (self.root / "policies/conftest/kubernetes.rego").read_text()
        self.assertEqual(rego.count('"tag": "0.2.0"'), 2)

    def assert_tree_untouched(self):
        for name in PINNED:
            self.assertEqual((self.root / name).read_bytes(), self.originals[name], f"{name} was written by a refused promotion")

    def test_refused_fragment_collision_writes_nothing(self):
        (self.root / "changelog.d/990-promote-naranjo-online-0-1-99.md").write_text("### Changed\n\n- taken\n")
        with self.assertRaisesRegex(MODULE.Refusal, "fragments are immutable"):
            self.promote()
        self.assert_tree_untouched()

    def test_refused_unknown_workload_writes_nothing(self):
        record = promoted_record(self.receipt["records"]["naranjo-online"], "0.1.99", "x")
        with self.assertRaisesRegex(MODULE.Refusal, "does not yet bind this workload"):
            MODULE.apply_promotion(self.root, self.selections, {"nas": (record, {"Chart.yaml": "sha256:" + "0" * 64, "values.yaml": "sha256:" + "1" * 64})}, 1, "#1", "2026-09-02")
        self.assert_tree_untouched()

    def test_refused_missing_readme_sentence_writes_nothing(self):
        readme = self.root / "README.md"
        readme.write_text(readme.read_text().replace("Current selections:", "Selections:"))
        self.originals["README.md"] = readme.read_bytes()
        with self.assertRaisesRegex(MODULE.Refusal, "machine-maintained current-selection sentence"):
            self.promote(issue=992)
        self.assert_tree_untouched()

    def test_stale_rewrite_grammar_is_refused(self):
        receipt = json.loads(json.dumps(self.receipt))
        receipt["records"]["naranjo-online"]["arm64Digest"] = "sha256:" + "5" * 64
        (self.root / MODULE.RECEIPT_JSON).write_text(MODULE.render_receipt_json(receipt))
        with self.assertRaisesRegex(MODULE.Refusal, "pinned nowhere in the tree"):
            self.promote(issue=993)

    def test_stale_version_shape_is_refused(self):
        contract = self.root / "tests/security/test_signature_policy_contract.py"
        text = contract.read_text()
        version = self.receipt["records"]["naranjo-online"]["chartTag"]
        needle = '"naranjo-online": (\n                "' + version + '",'
        self.assertEqual(text.count(needle), 1)
        contract.write_text(text.replace(needle, '"naranjo-online": (\n                "0.0.0",'))
        subprocess.run(["git", "-c", "user.name=t", "-c", f"user.email={OWNER_EMAIL}", "commit", "-qam", "drift"], cwd=self.root, check=True, env=hermetic_git_environment())
        with self.assertRaisesRegex(MODULE.Refusal, "version pin shape 3 matched nowhere"):
            self.promote(issue=994)

    def test_literal_run_rewriter_re_splits_at_the_original_chunk_lengths(self):
        old = "sha256:" + "a" * 64
        new = "sha256:" + "b" * 64
        text = '    x = (\n        "sha256:aaaaaaaaaaaaaaaaaaaaaaaa"\n        "' + "a" * 25 + '"\n        "' + "a" * 15 + '"\n    )\n    y = "unrelated"\n'
        self.assertEqual(MODULE.join_literal_runs(text).count(old), 1)
        rewritten = MODULE.rewrite_literal_runs(text, {old: new})
        self.assertEqual(MODULE.join_literal_runs(rewritten).count(new), 1)
        self.assertNotIn("a" * 15, MODULE.join_literal_runs(rewritten))
        self.assertEqual([len(p) for p in re.findall(r'"([^"]*)"', rewritten)], [len(p) for p in re.findall(r'"([^"]*)"', text)])
        self.assertEqual(MODULE.rewrite_literal_runs(text, {"zzz": "yyy"}), text)


class ReadyRuleTests(unittest.TestCase):
    HEAD = "1" * 40

    def receipt(self, head, verdict, lane, user=MODULE.REVIEWS_APP, preamble=""):
        return {"user": user, "body": f"{preamble}HEAD: {head}\nVERDICT: {verdict}\n\nFindings: none.\n\n- {lane} (adversarial reviewer)\n"}

    def checks(self, conclusion="success"):
        return [{"name": name, "status": "completed", "conclusion": conclusion} for name in MODULE.REQUIRED_CHECKS] + [{"name": "CodeQL", "status": "completed", "conclusion": "neutral"}]

    def test_two_distinct_exact_head_approvals_with_green_checks_flip(self):
        ready, reasons = MODULE.ready_decision(self.HEAD, ["release"], [self.receipt(self.HEAD, "APPROVE", "Opus5"), self.receipt(self.HEAD, "APPROVE", "Codex")], self.checks(), 0, True)
        self.assertEqual((ready, reasons), (True, []))

    def test_every_single_failure_keeps_the_draft(self):
        good = [self.receipt(self.HEAD, "APPROVE", "Opus5"), self.receipt(self.HEAD, "APPROVE", "Codex")]
        cases = {
            "one approval": (["release"], good[:1], self.checks(), 0, True, "two are required"),
            "same lane twice": (["release"], [good[0], good[0]], self.checks(), 0, True, "1 distinct"),
            "approval at old head": (["release"], [good[0], self.receipt("2" * 40, "APPROVE", "Codex")], self.checks(), 0, True, "two are required"),
            "approval not from the App": (["release"], [good[0], self.receipt(self.HEAD, "APPROVE", "Codex", user="snaraj")], self.checks(), 0, True, "two are required"),
            "request changes": (["release"], good + [self.receipt(self.HEAD, "REQUEST-CHANGES", "Daybreak")], self.checks(), 0, True, "REQUEST-CHANGES"),
            "request changes under a heading": (["release"], good + [self.receipt(self.HEAD, "REQUEST-CHANGES", "Daybreak", preamble="## Adversarial review of #300\n\n")], self.checks(), 0, True, "REQUEST-CHANGES"),
            "same lane spelled twice": (["release"], [good[0], self.receipt(self.HEAD, "APPROVE", "Opus 5")], self.checks(), 0, True, "1 distinct"),
            "same lane cased twice": (["release"], [good[0], self.receipt(self.HEAD, "APPROVE", "OPUS5")], self.checks(), 0, True, "1 distinct"),
            "requires-review armed": (["requires-review"], good, self.checks(), 0, True, "still armed"),
            "check failed": (["release"], good, self.checks("failure"), 0, True, "has not succeeded"),
            "check pending": (["release"], good, [{"name": n, "status": "in_progress", "conclusion": None} for n in MODULE.REQUIRED_CHECKS], 0, True, "has not succeeded"),
            "check missing": (["release"], good, [], 0, True, "has not succeeded"),
            "behind main": (["release"], good, self.checks(), 2, True, "behind main"),
            "already ready": (["release"], good, self.checks(), 0, False, "already Ready"),
            "unsigned receipt": (["release"], [good[0], {"user": MODULE.REVIEWS_APP, "body": f"HEAD: {self.HEAD}\nVERDICT: APPROVE\n\nno lane line\n"}], self.checks(), 0, True, "two are required"),
        }
        for name, (labels, comments, checks, behind, draft, reason) in cases.items():
            with self.subTest(case=name):
                ready, reasons = MODULE.ready_decision(self.HEAD, labels, comments, checks, behind, draft)
                self.assertFalse(ready)
                self.assertTrue(any(reason in r for r in reasons), reasons)

    def test_receipt_parser(self):
        parsed = MODULE.parse_receipt(self.receipt(self.HEAD, "APPROVE", "Opus5")["body"])
        self.assertEqual(parsed, {"head": self.HEAD, "verdict": "APPROVE", "lane": "opus5"})
        under_heading = MODULE.parse_receipt(self.receipt(self.HEAD, "REQUEST-CHANGES", "Codex", preamble="## Review\n\n")["body"])
        self.assertEqual(under_heading, {"head": self.HEAD, "verdict": "REQUEST-CHANGES", "lane": "codex"})
        self.assertIsNone(MODULE.parse_receipt("REVIEW-CLAIM head=abc reviewer=x"))
        self.assertIsNone(MODULE.parse_receipt("VERDICT: APPROVE\nHEAD: x"))
        self.assertIsNone(MODULE.parse_receipt(f"HEAD: {self.HEAD}\nHEAD: {self.HEAD}\nVERDICT: APPROVE\n"))
        self.assertIsNone(MODULE.parse_receipt(f"HEAD: {self.HEAD}\nVERDICT: MAYBE\n"))
        self.assertEqual(MODULE.parse_receipt(f"HEAD: {self.HEAD}\nVERDICT: APPROVE\n\nno signature\n")["lane"], None)


class PlanningTests(unittest.TestCase):
    def test_targets_and_open_pull_request_handling(self):
        base = "8369bf7"
        behind = {"naranjo-online": {"committed": "0.1.69", "latest": "0.1.71", "verdict": "behind"}, "lidersea-com": {"committed": "0.1.41", "latest": "0.1.41", "verdict": "current"}}
        matching = {"number": 300, "branch": MODULE.branch_name(base, 285, {"naranjo-online": "0.1.71"}), "behind_by": 0}
        stale = dict(matching, number=301, behind_by=3)
        other = {"number": 302, "branch": MODULE.branch_name(base, 285, {"naranjo-online": "0.1.70"}), "behind_by": 0}
        foreign = {"number": 303, "branch": "fable5-high/286-tool", "behind_by": 0}
        self.assertEqual(MODULE.plan(behind, []), {"targets": {"naranjo-online": "0.1.71"}, "keep": [], "supersede": []})
        self.assertEqual(MODULE.plan(behind, [matching, stale, other, foreign]), {"targets": {"naranjo-online": "0.1.71"}, "keep": [300], "supersede": [301, 302]})
        current = {slug: dict(entry, verdict="current", committed=entry["latest"]) for slug, entry in behind.items()}
        self.assertEqual(MODULE.plan(current, [matching]), {"targets": {}, "keep": [], "supersede": [300]})
        for verdict in ("ahead", "unpublished"):
            with self.subTest(verdict=verdict), self.assertRaisesRegex(MODULE.Refusal, "the watchdog owns"):
                MODULE.plan({"naranjo-online": {"committed": "0.1.69", "latest": None, "verdict": verdict}}, [])

    def test_branch_grammar_round_trips_and_rejects_foreign_names(self):
        targets = {"naranjo-online": "0.1.71", "lidersea-com": "0.1.42"}
        branch = MODULE.branch_name("8369bf7a6e487ea3", 285, targets)
        self.assertEqual(branch, "promoter/8369bf7/285-lidersea-com-0.1.42_naranjo-online-0.1.71")
        self.assertEqual(MODULE.parse_branch(branch), ("8369bf7", 285, targets))
        for bad in ("promoter/285-naranjo-online-0.1.71", "promoter/8369bf7/x-naranjo-online-0.1.71", "fable5-high/286-tool", "promoter/8369bf7/285-naranjo-online-latest"):
            with self.subTest(branch=bad):
                self.assertIsNone(MODULE.parse_branch(bad))

    def test_fragment_path_obeys_the_release_contract_grammar(self):
        for targets in ({"naranjo-online": "0.1.71"}, {"naranjo-online": "0.2.0", "lidersea-com": "1.0.0"}):
            path = MODULE.fragment_path(286, targets).as_posix()
            self.assertTrue(CONTRACT.FRAGMENT_PATH_RE.match(path), path)


class TickTests(unittest.TestCase):
    """The real tool against a real local bare origin, with scripted answers
    for gh, cosign, make and ssh-add. Signing itself is replaced by an
    unsigned commit through the scripted runner, and the exact signed argv
    the tool sent is pinned instead."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.env = hermetic_git_environment()
        source = tracked_copy(base / "source")
        self.origin = base / "origin.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(source), str(self.origin)], check=True, env=self.env)
        self.repo = base / "repo"
        subprocess.run(["git", "clone", "-q", str(self.origin), str(self.repo)], check=True, env=self.env)
        # The fake publisher is one patch ahead of whatever the tracked tree
        # commits, so the tree can move without this battery moving.
        committed = MODULE.load_receipt(REPO_ROOT)["records"]["naranjo-online"]["chartTag"]
        major, minor, patch = committed.split(".")
        self.next = f"{major}.{minor}.{int(patch) + 1}"
        self.fleet = FakeFleet(version=self.next)
        self.fleet.gh[f"repos/{self.fleet.site}/releases/latest"] = {"tag_name": f"v{self.next}"}
        self.fleet.gh["repos/snaraj/lidersea.com/releases/latest"] = {"tag_name": "v0.1.41"}
        self.fleet.gh["user"] = {"login": MODULE.ASSIGNEE, "id": OWNER_ID, "name": "t"}
        self.fleet.gh[f"users/{MODULE.ASSIGNEE}/ssh_signing_keys"] = [[{"key": "ssh-ed25519 AAAATESTKEY comment"}]]
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls?state=open&per_page=100"] = [[]]
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues?state=open&labels=delivery-lane&per_page=100"] = [[{"number": 285, "title": "deploy-assurance[site-drift/naranjo-online]"}]]
        self.commits = []
        self.mutations = []
        self.log_lines = []
        self._log = MODULE.log
        MODULE.log = self.log_lines.append

    def tearDown(self):
        MODULE.log = self._log
        self.tmp.cleanup()

    def run_command(self, argv, cwd=None, input_text=None, env=None):
        argv = list(argv)
        if argv[0] == "git":
            if "commit" in argv and "-S" in argv:
                self.commits.append(tuple(argv))
                stripped = [a for a in argv if a not in ("-S",) and not a.startswith("user.signingkey=") and a != "gpg.format=ssh"]
                stripped = [a for i, a in enumerate(stripped) if not (a == "-c" and i + 1 < len(stripped) and stripped[i + 1] in ("gpg.format=ssh",))]
                stripped = [a for a in stripped if a != "-c"]
                merged = dict(self.env)
                merged.update(env or {})
                return MODULE.run_command(stripped, cwd=cwd, input_text=input_text, env=merged)
            merged = dict(self.env)
            merged.update(env or {})
            return MODULE.run_command(argv, cwd=cwd, input_text=input_text, env=merged)
        if argv[0] == "make":
            self.mutations.append(("gate", tuple(argv)))
            return ""
        if argv[:2] == ["ssh-add", "-L"]:
            return "ssh-ed25519 AAAATESTKEY loaded\nssh-ed25519 AAAAOTHER other\n"
        if argv[:3] == ["gh", "pr", "create"]:
            self.mutations.append(("pr-create", tuple(argv)))
            return "https://github.com/snaraj/website-infrastructure/pull/300\n"
        if argv[:3] == ["gh", "pr", "ready"]:
            self.mutations.append(("pr-ready", tuple(argv)))
            return ""
        if argv[:2] == ["gh", "api"] and "-X" in argv and argv[argv.index("-X") + 1] != "GET":
            path = argv[argv.index("--input") - 1] if "--input" in argv else argv[-1]
            self.mutations.append(("api-write", path, input_text, argv[argv.index("-X") + 1]))
            # GitHub answers label writes with the label ARRAY, not an object.
            return "[]" if "/labels" in path else "{}"
        return self.fleet.run(argv, cwd=cwd, input_text=input_text, env=env)

    def writes(self, suffix):
        return [m for m in self.mutations if m[0] == "api-write" and m[1].endswith(suffix)]

    def test_dry_run_reads_and_gates_but_never_writes(self):
        code = MODULE.tick(self.repo, True, registry=self.fleet.registry(), github=MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch), cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 0)
        self.assertEqual([m for m in self.mutations if m[0] != "gate"], [])
        self.assertEqual([m[1][1] for m in self.mutations if m[0] == "gate"], ["check-fast", "check-gitleaks", "check-kubernetes"])
        self.assertEqual(self.commits, [])
        heads = subprocess.run(["git", "for-each-ref", "refs/heads/"], cwd=self.origin, capture_output=True, text=True, check=True).stdout
        self.assertNotIn("promoter/", heads)
        status = subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True, text=True, check=True).stdout
        self.assertEqual(status, "", "the dry run left the clone dirty")

    def test_live_tick_cuts_signs_pushes_opens_and_arms_then_flips_when_both_verdicts_land(self):
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        code = MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 0)
        self.assertEqual(len(self.commits), 1)
        commit = self.commits[0]
        self.assertIn("-S", commit)
        self.assertIn("gpg.format=ssh", commit)
        self.assertIn("user.signingkey=key::ssh-ed25519 AAAATESTKEY", commit)
        base = subprocess.run(["git", "rev-parse", "main"], cwd=self.origin, capture_output=True, text=True, check=True).stdout.strip()
        branch = MODULE.branch_name(base, 285, {"naranjo-online": self.next})
        heads = subprocess.run(["git", "for-each-ref", "--format=%(refname:short)", "refs/heads/"], cwd=self.origin, capture_output=True, text=True, check=True).stdout.split()
        self.assertIn(branch, heads)
        message = subprocess.run(["git", "log", "-1", "--format=%an <%ae>%n%cn <%ce>%n%B", branch], cwd=self.origin, capture_output=True, text=True, check=True).stdout
        self.assertTrue(message.startswith(f"t <{OWNER_EMAIL}>\nt <{OWNER_EMAIL}>\n"), message[:120])
        self.assertTrue(message.rstrip().endswith(MODULE.SIGNATURE))
        self.assertIn("Closes #285", message)
        self.assertNotIn("Co-Authored-By", message)
        pushed_tree = subprocess.run(["git", "ls-tree", "--name-only", branch, "changelog.d/"], cwd=self.origin, capture_output=True, text=True, check=True).stdout
        self.assertIn(f"changelog.d/285-promote-naranjo-online-{self.next.replace('.', '-')}.md", pushed_tree)
        create = next(m for m in self.mutations if m[0] == "pr-create")[1]
        self.assertIn("--draft", create)
        for label in MODULE.PR_LABELS:
            self.assertIn(label, create)
        self.assertNotIn("agent-authored", create)
        self.assertIn(MODULE.MILESTONE, create)
        arm = self.writes("/issues/300/labels")
        self.assertEqual(len(arm), 1)
        self.assertEqual(json.loads(arm[0][2]), {"labels": list(MODULE.REVIEW_LABELS)})
        self.assertEqual([m for m in self.mutations if m[0] == "pr-ready"], [])
        head = subprocess.run(["git", "rev-parse", branch], cwd=self.origin, capture_output=True, text=True, check=True).stdout.strip()
        detached = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(detached, base, "the clone must return to origin/main after a cut")

        # Second tick: the pull request is open at exact head with both verdicts.
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls?state=open&per_page=100"] = [[{"number": 300, "draft": True, "head": {"ref": branch, "sha": head}, "labels": [{"name": n} for n in ("release", "delivery-lane", "promoter", "cybersecurity-review-requested")]}]]
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/compare/main...{head}"] = {"behind_by": 0}
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/300/comments?per_page=100"] = [[
            {"user": {"login": MODULE.REVIEWS_APP}, "body": f"HEAD: {head}\nVERDICT: APPROVE\n\n- Opus5 (adversarial reviewer)\n"},
            {"user": {"login": MODULE.REVIEWS_APP}, "body": f"HEAD: {head}\nVERDICT: APPROVE\n\n- Codex (adversarial reviewer)\n"},
        ]]
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/commits/{head}/check-runs?per_page=100"] = {"total_count": 2, "check_runs": [{"name": n, "status": "completed", "conclusion": "success"} for n in MODULE.REQUIRED_CHECKS]}
        self.fleet.gh[f"repos/{self.fleet.site}/releases/latest"] = {"tag_name": f"v{self.next}"}
        self.mutations.clear()
        code = MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 0)
        kinds = [m[0] for m in self.mutations]
        self.assertEqual(kinds.count("pr-create"), 0)
        self.assertEqual(kinds.count("pr-ready"), 1)
        cleared = self.writes("/labels/cybersecurity-review-requested")
        self.assertEqual(len(cleared), 1)
        self.assertEqual(cleared[0][3], "DELETE")
        ready_note = self.writes("/issues/300/comments")
        self.assertEqual(len(ready_note), 1)
        self.assertIn("two distinct exact-head adversarial", json.loads(ready_note[0][2])["body"])

        # Third tick: one verdict withdrawn -> the same head stays Draft.
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/300/comments?per_page=100"][0].pop()
        self.mutations.clear()
        MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual([m[0] for m in self.mutations], [])
        self.assertTrue(any("two are required" in line for line in self.log_lines))

        # Fourth tick: a truncated check-run listing is refused, not judged.
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/commits/{head}/check-runs?per_page=100"]["total_count"] = 150
        with self.assertRaisesRegex(MODULE.Refusal, "check-run listing is truncated"):
            MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertFalse((self.repo / ".git" / "promoter.lock").exists(), "the lock must be released on every exit path")

    def test_a_refused_ceremony_reports_once_on_the_drift_issue_and_leaves_the_clone_clean(self):
        self.fleet.gh[f"repos/{self.fleet.site}/releases/tags/v{self.next}"]["immutable"] = False
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/285/comments?per_page=100"] = [[]]
        code = MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 1)
        reports = self.writes("/issues/285/comments")
        self.assertEqual(len(reports), 1)
        body = json.loads(reports[0][2])["body"]
        self.assertIn(f"promoter-failure naranjo-online={self.next} step=cut", body)
        self.assertIn("not an immutable final release", body)
        self.assertEqual(self.commits, [])
        status = subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True, text=True, check=True).stdout
        self.assertEqual(status, "")
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/285/comments?per_page=100"] = [[{"body": body}]]
        self.mutations.clear()
        MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual([m for m in self.mutations if m[0] == "api-write"], [])

    def test_lock_and_dirty_clone_guards(self):
        lock = self.repo / ".git" / "promoter.lock"
        self.assertTrue(MODULE.acquire_lock(lock))
        self.assertFalse(MODULE.acquire_lock(lock))
        os.utime(lock, (1, 1))
        self.assertTrue(MODULE.acquire_lock(lock))
        lock.unlink()
        (self.repo / "stray.txt").write_text("x")
        with self.assertRaisesRegex(MODULE.Refusal, "clone is dirty"):
            MODULE.Workspace(self.repo, self.run_command).refresh()

    def test_signing_key_requires_exactly_one_registered_loaded_key(self):
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        workspace = MODULE.Workspace(self.repo, self.run_command)
        self.assertEqual(workspace.signing_key(github), "ssh-ed25519 AAAATESTKEY")
        self.fleet.gh[f"users/{MODULE.ASSIGNEE}/ssh_signing_keys"] = [[{"key": "ssh-ed25519 AAAATESTKEY a"}, {"key": "ssh-ed25519 AAAAOTHER b"}]]
        with self.assertRaisesRegex(MODULE.Refusal, "exactly one registered signing key"):
            workspace.signing_key(github)

    def test_commit_identity_is_the_authenticated_owner_reconciled_with_history(self):
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        workspace = MODULE.Workspace(self.repo, self.run_command)
        workspace.refresh()
        identity = workspace.identity(github)
        self.assertEqual(identity["GIT_AUTHOR_EMAIL"], OWNER_EMAIL)
        self.assertEqual(identity["GIT_COMMITTER_EMAIL"], OWNER_EMAIL)
        self.assertEqual(identity["GIT_AUTHOR_NAME"], "t")
        # A bot at the tip of main must not become the promoter's identity.
        subprocess.run(["git", "-c", "user.name=dependabot[bot]", "-c", f"user.email=1+dependabot[bot]@{MODULE.NOREPLY_DOMAIN}", "commit", "-q", "--allow-empty", "-m", "bump"], cwd=self.repo, check=True, env=self.env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], cwd=self.repo, check=True, env=self.env)
        workspace.refresh()
        self.assertEqual(workspace.identity(github)["GIT_AUTHOR_EMAIL"], OWNER_EMAIL)
        self.fleet.gh["user"] = {"login": "someone-else", "id": 9}
        with self.assertRaisesRegex(MODULE.Refusal, "not authenticated as the repository owner"):
            workspace.identity(github)
        self.fleet.gh["user"] = {"login": MODULE.ASSIGNEE, "id": OWNER_ID + 1}
        with self.assertRaisesRegex(MODULE.Refusal, "no published commit"):
            workspace.identity(github)


class RunbookAndLaunchdTests(unittest.TestCase):
    def test_runbook_fences_are_exactly_the_canon(self):
        text = RUNBOOK.read_text(encoding="utf-8")
        fences = re.findall(r"^```sh\n(.*?)```\n", text, re.DOTALL | re.MULTILINE)
        self.assertEqual(tuple(fences), MODULE.RUNBOOK_BLOCKS)
        self.assertEqual(len(re.findall(r"^```", text, re.MULTILINE)), 2 * len(MODULE.RUNBOOK_BLOCKS))
        self.assertNotIn("~", "".join(MODULE.RUNBOOK_BLOCKS))
        for block in MODULE.RUNBOOK_BLOCKS:
            self.assertNotRegex(block, r"/Users/|/home/")
        self.assertIn(MODULE.LAUNCHD_LABEL, text)
        self.assertIn("scripts/promote_releases.py", text)

    def test_launchd_plist_names_the_tick_with_the_given_paths(self):
        plist = plistlib.loads(MODULE.launchd_plist("/tmp/a b/repo", "/tmp/log & more.log").encode())
        self.assertEqual(plist["Label"], MODULE.LAUNCHD_LABEL)
        self.assertEqual(plist["StartInterval"], MODULE.LAUNCHD_INTERVAL_SECONDS)
        self.assertTrue(plist["RunAtLoad"])
        self.assertEqual(plist["ProgramArguments"][-3:], ["tick", "--repo", "/tmp/a b/repo"])
        self.assertIn("/tmp/a b/repo/scripts/promote_releases.py", plist["ProgramArguments"])
        self.assertEqual(plist["StandardOutPath"], "/tmp/log & more.log")
        self.assertIn("-I", plist["ProgramArguments"])
        self.assertNotIn("--dry-run", plist["ProgramArguments"])

    def test_cli_status_and_verify_are_wired(self):
        output = subprocess.run([__import__("sys").executable, "-B", str(REPO_ROOT / "scripts" / "promote_releases.py"), "--help"], capture_output=True, text=True, check=True).stdout
        for mode in ("status", "verify", "tick", "launchd-plist"):
            self.assertIn(mode, output)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
