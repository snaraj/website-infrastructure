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
labels). The Ready rule is not here: it left with the machinery, and
``tests/security/test_ready_check_contract.py`` pins its one evaluator.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
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
        self.layer_bytes = self.overrides.get("layer_bytes") or self.tar({f"{self.slug}/Chart.yaml": self.chart_yaml, f"{self.slug}/values.yaml": self.values_yaml})
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
        return hostile_tar([(name, data, tarfile.REGTYPE) for name, data in members.items()])

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

    def run(self, argv, cwd=None, input_text=None, env=None, timeout=None):
        self.calls.append(("run", tuple(argv)))
        if argv[:2] == ["gh", "api"]:
            path = argv[-1] if "--input" not in argv else argv[argv.index("--input") - 1]
            path = [a for a in argv if not a.startswith("-") and a not in ("gh", "api", "GET", "POST", "PATCH", "DELETE", "Accept: application/vnd.github+json")][-1]
            if path not in self.gh:
                raise MODULE.Refusal(f"`gh api {path}` exited 1: gh: Not Found (HTTP 404)")
            answer = self.gh[path]
            if isinstance(answer, Exception):
                raise answer
            return json.dumps(answer)
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

        def archive(f, entries):
            f.overrides["layer_bytes"] = hostile_tar(entries)
            f.build()

        good = lambda f: [(f"{f.slug}/Chart.yaml", f.chart_yaml, tarfile.REGTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE)]

        def duplicate_chart_yaml(f):
            archive(f, good(f) + [(f"{f.slug}/Chart.yaml", f.chart_yaml.replace(b"version: ", b"version: 9."), tarfile.REGTYPE)])

        def dot_prefixed_twin(f):
            archive(f, good(f) + [(f"./{f.slug}/Chart.yaml", f.chart_yaml.replace(b"name: ", b"name: x"), tarfile.REGTYPE)])

        def unrelated_symlink(f):
            archive(f, [(f"{f.slug}/Chart.yaml", f.chart_yaml, tarfile.REGTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE), (f"{f.slug}/templates/link.yaml", b"", tarfile.SYMTYPE)])

        def unrelated_hardlink(f):
            archive(f, [(f"{f.slug}/Chart.yaml", f.chart_yaml, tarfile.REGTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE), (f"{f.slug}/templates/link.yaml", b"", tarfile.LNKTYPE)])

        def symlinked_chart_yaml(f):
            archive(f, [(f"{f.slug}/Chart.yaml", b"", tarfile.SYMTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE)])

        def entry_outside_root(f):
            archive(f, good(f) + [("../escape", b"x", tarfile.REGTYPE)])

        def too_many_entries(f):
            archive(f, good(f) + [(f"{f.slug}/pad-{i}", b"", tarfile.REGTYPE) for i in range(MODULE.ARCHIVE_MEMBER_CEILING)])

        def oversized_chart_yaml(f):
            archive(f, [(f"{f.slug}/Chart.yaml", f.chart_yaml + b"#" * MODULE.CHART_FILE_CEILING, tarfile.REGTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE)])

        def expansion_bomb(f):
            archive(f, [(f"{f.slug}/pad", b"\0" * (MODULE.ARCHIVE_EXPANSION_CEILING + 1024 * 1024), tarfile.REGTYPE)] + good(f))

        def truncated_archive(f):
            raw = gzip.decompress(hostile_tar(good(f)))
            f.overrides["layer_bytes"] = gzip.compress(raw[: 512 + 40])
            f.build()

        def not_a_gzip_tar(f):
            f.overrides["layer_bytes"] = b"\x1f\x8b" + b"not really" * 8
            f.build()

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
            "duplicate Chart.yaml entries": (duplicate_chart_yaml, "more than once"),
            "dot-prefixed twin of Chart.yaml": (dot_prefixed_twin, "more than once"),
            "symlinked Chart.yaml": (symlinked_chart_yaml, "not a regular file"),
            "unrelated symlink under templates": (unrelated_symlink, "not a regular file"),
            "unrelated hardlink under templates": (unrelated_hardlink, "not a regular file"),
            "entry outside the archive root": (entry_outside_root, "outside the archive root"),
            "too many entries": (too_many_entries, f"more than {MODULE.ARCHIVE_MEMBER_CEILING} entries"),
            "oversized Chart.yaml": (oversized_chart_yaml, f"exceeds {MODULE.CHART_FILE_CEILING} bytes"),
            "expansion bomb": (expansion_bomb, "expands past"),
            "not a gzip tar": (not_a_gzip_tar, "not a readable gzip tar"),
            "truncated archive": (truncated_archive, "not a readable gzip tar"),
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


def quiet_git_environment(*args, **kwargs) -> dict:
    """``hermetic_git_environment`` with git's post-command auto maintenance
    off. After ``fetch`` and ``commit`` git spawns a detached
    ``maintenance run --auto`` (``gc --auto`` on older versions) that takes
    ``.git/objects/maintenance.lock`` even when there is nothing to do; a
    child that outlives the command races the ``TemporaryDirectory``
    removal and cleanup fails with ``Directory not empty: .git`` — observed
    once on the CI runner at head 38e3bba. Disabling it makes every
    hermetic repository single-process."""

    environment = hermetic_git_environment(*args, **kwargs)
    pins = (("gc.auto", "0"), ("gc.autoDetach", "false"), ("maintenance.auto", "false"))
    environment["GIT_CONFIG_COUNT"] = str(len(pins))
    for index, (key, value) in enumerate(pins):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


def tracked_copy(destination: Path) -> Path:
    """Copy the WORKING TREE of every tracked file into a fresh git repository
    on branch ``main`` with one commit, so ``git ls-files`` and the rewrite
    see exactly what a checkout of this head would."""

    env = quiet_git_environment()
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


def hostile_tar(entries) -> bytes:
    """A gzip tar with exactly the given entries, in order: ``(name, data,
    type)``; duplicates, twins, links and directories are all expressible."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = "values.yaml"
                archive.addfile(info)
            elif kind == tarfile.DIRTYPE:
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def pr_record(number: int, branch: str, head: str, draft: bool = True, labels=MODULE.PR_LABELS) -> dict:
    """A pull request as GitHub lists it, satisfying the owned-PR tuple."""

    return {
        "number": number,
        "draft": draft,
        "user": {"login": MODULE.ASSIGNEE},
        "head": {"ref": branch, "sha": head, "repo": {"full_name": MODULE.REPOSITORY}},
        "base": {"ref": "main", "repo": {"full_name": MODULE.REPOSITORY}},
        "labels": [{"name": n} for n in labels],
    }


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
        issue = int(issues.split("/")[0].lstrip("#"))
        # FIXTURE — the shape `main` takes from the first canonical promotion
        # this tool cuts onward: the fragment that capture committed is already
        # in the tree. Today's `main` predates that only because the #285
        # fragment was hand-named, so testing against today's tree alone would
        # measure a coincidence (PR #305 finding 1).
        replayed = self.root / MODULE.fragment_path(issue, {"naranjo-online": original["chartTag"]})
        replayed.write_text("### Changed\n\n- committed by that promotion\n", encoding="utf-8")
        # REPAIR under test — the inverse REPLAYS exactly that capture, so on
        # the fixture above it meets apply_promotion's immutable-fragment
        # refusal instead of restoring bytes. The pre-promotion tree carried
        # neither fragment, so dropping this one is the same scratch setup as
        # the 990 line above, not a relaxation: the refusal itself stays pinned
        # by test_refused_fragment_collision_writes_nothing below, and the
        # rewrite never reads changelog.d/ at all. Delete this line and the
        # restoration below never runs.
        replayed.unlink()
        MODULE.apply_promotion(
            self.root, self.selections, {"naranjo-online": (original, self.inspection["naranjo"])}, issue, issues, date
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
        subprocess.run(["git", "-c", "user.name=t", "-c", f"user.email={OWNER_EMAIL}", "commit", "-qam", "drift"], cwd=self.root, check=True, env=quiet_git_environment())
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

    def test_only_owned_promoter_pull_requests_are_discovered(self):
        fleet = FakeFleet()
        head = "3" * 40
        owned = pr_record(300, MODULE.branch_name("8" * 40, 285, {"naranjo-online": "0.1.99"}), head)
        variants = {
            "fork head": {"head": dict(owned["head"], repo={"full_name": "mallory/website-infrastructure"})},
            "foreign base repository": {"base": {"ref": "main", "repo": {"full_name": "mallory/website-infrastructure"}}},
            "base is not main": {"base": {"ref": "release", "repo": {"full_name": MODULE.REPOSITORY}}},
            "not the owner": {"user": {"login": "mallory"}},
            "unknown draft state": {"draft": None},
            "branch outside the grammar": {"head": dict(owned["head"], ref="promoter/not-a-branch")},
        }
        for name, override in variants.items():
            with self.subTest(variant=name):
                self.assertIsNone(MODULE.owned_pull_request(dict(owned, **override)))
        self.assertEqual(MODULE.owned_pull_request(owned)["number"], 300)
        foreign = dict(owned, number=301, **variants["fork head"])
        fleet.gh[f"repos/{MODULE.REPOSITORY}/pulls?state=open&per_page=100"] = [[foreign, owned]]
        fleet.gh[f"repos/{MODULE.REPOSITORY}/compare/main...{head}"] = {"behind_by": 0}
        found = MODULE.open_promoter_prs(fleet.github())
        self.assertEqual([pr["number"] for pr in found], [300], "a fork with a promoter head is never adopted")
        # Unknown freshness keeps the pull request in view with no verdict.
        fleet.gh[f"repos/{MODULE.REPOSITORY}/compare/main...{head}"] = {}
        found = MODULE.open_promoter_prs(fleet.github())
        self.assertEqual([(pr["number"], pr["behind_by"]) for pr in found], [(300, None)])
        decision = MODULE.plan({"naranjo-online": {"verdict": "behind", "committed": "0.1.71", "latest": "0.1.99"}}, found)
        self.assertEqual((decision["keep"], decision["supersede"]), ([300], []), "unknown freshness is never superseded on")

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
        self.env = quiet_git_environment()
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
        self.fail_gates = set()
        # A tracked file a gate rewrites during the cut; see run_command.
        self.gate_rewrites = ""
        self.log_lines = []
        self._log = MODULE.log
        MODULE.log = self.log_lines.append

    def tearDown(self):
        MODULE.log = self._log
        self.tmp.cleanup()

    def run_command(self, argv, cwd=None, input_text=None, env=None, timeout=None):
        argv = list(argv)
        if argv[0] == "git":
            if "commit" in argv and "-S" in argv:
                self.commits.append(tuple(argv))
                self.mutations.append(("commit", tuple(argv)))
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
            if argv[1] in self.fail_gates:
                raise MODULE.Refusal(f"`make {argv[1]}` exited 2: FAIL pre-push security gate did not authorize publication.")
            # Real gates rewrite tracked files — a formatter, a regenerated
            # badge or ledger. When a test asks for it this one does too, so
            # the committed index and `apply_promotion`'s returned path list
            # DISAGREE in count and the accounting oracle can tell which of
            # the two the body actually states (PR #308 review, finding 1).
            if self.gate_rewrites:
                path = self.repo / self.gate_rewrites
                path.write_text(path.read_text(encoding="utf-8") + "\nrewritten by a gate\n", encoding="utf-8")
                # Once, before the commit: the publication gate runs after it,
                # and a second rewrite would leave residue the cut never saw.
                self.gate_rewrites = ""
            return ""
        if argv[:2] == ["ssh-add", "-L"]:
            return "ssh-ed25519 AAAATESTKEY loaded\nssh-ed25519 AAAAOTHER other\n"
        if argv[:3] == ["gh", "pr", "ready"]:
            raise AssertionError("the promoter must never flip or withdraw Ready")
        if argv[:3] == ["gh", "pr", "create"]:
            # The body file is unlinked right after this call, so capture what
            # gh was actually handed rather than inferring it afterwards.
            handed = Path(argv[argv.index("--body-file") + 1]).read_text(encoding="utf-8")
            self.mutations.append(("pr-create", tuple(argv), handed))
            return "https://github.com/snaraj/website-infrastructure/pull/300\n"
        if argv[:2] == ["gh", "api"] and "-X" in argv and argv[argv.index("-X") + 1] != "GET":
            path = argv[argv.index("--input") - 1] if "--input" in argv else argv[-1]
            self.mutations.append(("api-write", path, input_text, argv[argv.index("-X") + 1]))
            # GitHub answers label writes with the label ARRAY, not an object.
            return "[]" if "/labels" in path else "{}"
        return self.fleet.run(argv, cwd=cwd, input_text=input_text, env=env)

    def writes(self, suffix):
        return [m for m in self.mutations if m[0] == "api-write" and m[1].endswith(suffix)]

    def local_heads(self):
        return subprocess.run(["git", "for-each-ref", "--format=%(refname:short)", "refs/heads/"], cwd=self.repo, capture_output=True, text=True, check=True).stdout

    def test_publication_gate_refusal_pushes_nothing(self):
        self.fail_gates = {"pre-push-security"}
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/285/comments?per_page=100"] = [[]]
        code = MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 1)
        self.assertEqual(len(self.commits), 1, "the gate runs on the signed commit")
        self.assertEqual([m[0] for m in self.mutations if m[0] == "pr-create"], [])
        heads = subprocess.run(["git", "for-each-ref", "refs/heads/"], cwd=self.origin, capture_output=True, text=True, check=True).stdout
        self.assertNotIn("promoter/", heads, "a refused outgoing commit is never pushed")
        body = json.loads(self.writes("/issues/285/comments")[0][2])["body"]
        self.assertIn("refused the outgoing commit; nothing was pushed", body)
        self.assertNotIn("promoter/", self.local_heads())
        self.assertEqual(subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True, text=True, check=True).stdout, "")

    def assert_precommit_refusal(self, gate):
        """A failed candidate check cannot reach signing or publication."""
        self.fail_gates = {gate}
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/285/comments?per_page=100"] = [[]]
        code = MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github,
                           cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 1)
        self.assertEqual(self.commits, [], "candidate validation precedes signing")
        self.assertFalse(any(m[0] == "pr-create" for m in self.mutations))
        heads = subprocess.run(["git", "for-each-ref", "refs/heads/"], cwd=self.origin,
                               capture_output=True, text=True, check=True).stdout
        self.assertNotIn("promoter/", heads, "a failed candidate is never pushed")
        self.assertFalse(any(m[0] == "gate" and m[1][1] == "pre-push-security"
                             for m in self.mutations))

    def test_tree_secret_scan_refusal_prevents_signing_and_publication(self):
        self.assert_precommit_refusal("check-gitleaks")

    def test_kubernetes_policy_refusal_prevents_signing_and_publication(self):
        self.assert_precommit_refusal("check-kubernetes")

    def test_public_failure_text_carries_no_private_host_detail(self):
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/285/comments?per_page=100"] = [[]]
        host = socket.gethostname()
        user = os.environ.get("USER") or "operator"
        # A private address built at runtime, so no literal enters the tree.
        address = ".".join(str(octet) for octet in (10, 0, 0, 5))
        raw = f"`gh pr` exited 1: could not read /Users/{user}/Library/Application Support/x/body.md on {host} at {address} (~/.config too)"
        MODULE.report_failure(github, {"naranjo-online": self.next}, "cut", raw, False)
        body = json.loads(self.writes("/issues/285/comments")[0][2])["body"]
        for private in ("/Users", "Library", "body.md", address, "~/.config"):
            self.assertNotIn(private, body)
        if len(user) > 2:
            self.assertNotIn(user, body)
        if len(host) > 2:
            self.assertNotIn(host, body)
        self.assertIn("<path>", body)
        self.assertIn("step=cut", body)
        with self.assertRaisesRegex(MODULE.Refusal, r"`sleep 5` exceeded 0\.2s"):
            MODULE.run_command(["sleep", "5"], timeout=0.2)
        # A descendant that detaches its output dies with the command's
        # process group, on completion and on timeout alike.
        marker = self.repo / "descendant-marker"
        MODULE.run_command(["sh", "-c", f"(sleep 0.4; touch '{marker}') >/dev/null 2>&1 & exit 0"])
        time.sleep(0.8)
        self.assertFalse(marker.exists(), "a descendant must not outlive its command's process group")
        late = self.repo / "late-marker"
        with self.assertRaisesRegex(MODULE.Refusal, r"`sh -c` exceeded 0\.2s"):
            MODULE.run_command(["sh", "-c", f"(sleep 0.6; touch '{late}') >/dev/null 2>&1 & sleep 5"], timeout=0.2)
        time.sleep(1.0)
        self.assertFalse(late.exists(), "a descendant of a timed-out command is killed with its group")
        try:
            MODULE.run_command(["git", "-C", str(self.repo / "definitely-missing"), "status"])
        except MODULE.Refusal as error:
            self.assertNotIn(str(self.repo), str(error), "a refusal never echoes the full argv")

    def test_dry_run_reads_and_gates_but_never_writes(self):
        code = MODULE.tick(self.repo, True, registry=self.fleet.registry(), github=MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch), cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 0)
        self.assertEqual([m for m in self.mutations if m[0] != "gate"], [])
        self.assertEqual([m[1][1] for m in self.mutations if m[0] == "gate"], ["check-gitleaks", "check-kubernetes"])
        self.assertEqual(self.commits, [])
        heads = subprocess.run(["git", "for-each-ref", "refs/heads/"], cwd=self.origin, capture_output=True, text=True, check=True).stdout
        self.assertNotIn("promoter/", heads)
        self.assertNotIn("promoter/", self.local_heads(), "a dry run must leave no local promoter ref to collide with the real cut")
        status = subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True, text=True, check=True).stdout
        self.assertEqual(status, "", "the dry run left the clone dirty")

    def test_a_refused_dry_run_writes_nothing_not_even_the_failure_report(self):
        # The one write a dry run can reach is report_failure after a refused
        # ceremony; the rehearsal must reach it and prove it writes nothing.
        self.fleet.gh[f"repos/{self.fleet.site}/releases/tags/v{self.next}"]["immutable"] = False
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/285/comments?per_page=100"] = [[]]
        code = MODULE.tick(self.repo, True, registry=self.fleet.registry(), github=MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch), cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 1)
        self.assertTrue(any("promotion refused" in line and "not an immutable final release" in line for line in self.log_lines))
        self.assertEqual([m for m in self.mutations if m[0] != "gate"], [], "a refused dry run posts nothing, not even the drift-issue report")
        self.assertEqual(self.commits, [])
        status = subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True, text=True, check=True).stdout
        self.assertEqual(status, "", "the refused dry run left the clone dirty")

    def test_a_live_tick_traces_every_documented_call_kind_and_ends_in_one_summary(self):
        # PR #313 round 1, finding 2: the runbook's list of call kinds is bound
        # to what a real tick EMITS, not to strings the module contains, and
        # the summary prefix the runbook names is the one the tick writes.
        captured = []
        original = MODULE.log
        MODULE.log = captured.append
        self.addCleanup(setattr, MODULE, "log", original)
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        code = MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 0)
        runbook = (REPO_ROOT / "docs" / "runbooks" / "release-promotion.md").read_text(encoding="utf-8")
        section = runbook.split("### Reading the log", 1)[1].split("## Disable", 1)[0]
        listed = re.findall(r"`([a-z]+(?:-[a-z]+)+)`", section.split("- `DONE", 1)[0].split("`<kind>` is one of", 1)[1])
        self.assertGreaterEqual(len(listed), 12, listed)
        starts = [line for line in captured if line.startswith("START ")]
        for kind in listed:
            self.assertTrue(any(line.startswith(f"START {kind} ") for line in starts), (kind, starts))
            self.assertTrue(any(line.startswith(f"DONE {kind} ") for line in captured), kind)
        for line in captured:
            if line.startswith("DONE "):
                self.assertRegex(line, r"elapsed=\d+\.\d+s (OK$|FAILED decision=\S+ reason=)")
        summaries = [line for line in captured if line.startswith("SUMMARY ")]
        self.assertEqual(len(summaries), 1, summaries)
        self.assertRegex(summaries[0], r"^SUMMARY tick elapsed=\d+\.\d+s dry-run=False ")
        self.assertIn("cut=", summaries[0])

    def test_live_tick_cuts_signs_pushes_opens_and_arms_but_never_flips(self):
        # One gate rewrites a tracked file the promotion never names, so the
        # committed index carries MORE paths than `apply_promotion` returned.
        # That divergence is what gives the accounting oracle below its teeth:
        # a body counting the tool's own list instead of the index states a
        # different number and the assertion fails (PR #308 review, finding 1).
        self.gate_rewrites = "ROADMAP.md"
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        code = MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual(code, 0)
        self.assertEqual(len(self.commits), 1)
        # Two gates before the commit, the publication gate on the signed
        # commit before the push, then the pull request.
        sequence = [m[1][1] if m[0] == "gate" else m[0] for m in self.mutations]
        self.assertEqual(sequence[:5], ["check-gitleaks", "check-kubernetes", "commit", "pre-push-security", "pr-create"])
        commit = self.commits[0]
        self.assertIn("-S", commit)
        self.assertIn("gpg.format=ssh", commit)
        self.assertIn("user.signingkey=key::ssh-ed25519 AAAATESTKEY", commit)
        base = subprocess.run(["git", "rev-parse", "main"], cwd=self.origin, capture_output=True, text=True, check=True).stdout.strip()
        branch = MODULE.branch_name(base, 285, {"naranjo-online": self.next})
        heads = subprocess.run(["git", "for-each-ref", "--format=%(refname:short)", "refs/heads/"], cwd=self.origin, capture_output=True, text=True, check=True).stdout.split()
        self.assertIn(branch, heads)
        self.assertNotIn("promoter/", self.local_heads(), "the cut must leave no local promoter branch behind")
        message = subprocess.run(["git", "log", "-1", "--format=%an <%ae>%n%cn <%ce>%n%B", branch], cwd=self.origin, capture_output=True, text=True, check=True).stdout
        self.assertTrue(message.startswith(f"t <{OWNER_EMAIL}>\nt <{OWNER_EMAIL}>\n"), message[:120])
        self.assertTrue(message.rstrip().endswith(MODULE.SIGNATURE))
        self.assertIn("Closes #285", message)
        self.assertNotIn("Co-Authored-By", message)
        pushed_tree = subprocess.run(["git", "ls-tree", "--name-only", branch, "changelog.d/"], cwd=self.origin, capture_output=True, text=True, check=True).stdout
        self.assertIn(f"changelog.d/285-promote-naranjo-online-{self.next.replace('.', '-')}.md", pushed_tree)
        # AGENTS.md: the commission states an estimate and the PR BODY the
        # actuals. Measure the pushed head the way the line tells the reviewer
        # to, and require the body gh was handed to state exactly that (#307).
        numstat = subprocess.run(["git", "diff", "--numstat", f"{base}..{branch}"], cwd=self.origin, capture_output=True, text=True, check=True).stdout.splitlines()
        rows = [line.split("\t") for line in numstat]
        self.assertIn("ROADMAP.md", [row[2] for row in rows], "the gate's rewrite is in the commit")
        reported = [line for line in self.log_lines if line.startswith("rewrote ")][0]
        self.assertNotEqual(
            len(rows), int(reported.split()[1]),
            "the fixture must make the index and the reported path list disagree, or the count below proves nothing",
        )
        expected = MODULE.accounting_line(base, len(rows), sum(int(r[0]) for r in rows), sum(int(r[1]) for r in rows))
        self.assertIn(MODULE.ACCOUNTING_PREFIX, expected)
        handed = next(m for m in self.mutations if m[0] == "pr-create")[2]
        self.assertIn(expected, handed, "the body gh received must carry the measured accounting")
        self.assertIn(expected, message, "the commit message and the body must state the same numbers")
        self.assertEqual(handed.count(MODULE.ACCOUNTING_PREFIX), 1, "exactly one accounting line per body")
        create = next(m for m in self.mutations if m[0] == "pr-create")[1]
        self.assertIn("--draft", create)
        for label in MODULE.PR_LABELS:
            self.assertIn(label, create)
        self.assertNotIn("agent-authored", create)
        self.assertIn(MODULE.MILESTONE, create)
        arm = self.writes("/issues/300/labels")
        self.assertEqual(len(arm), 1)
        self.assertEqual(json.loads(arm[0][2]), {"labels": list(MODULE.REVIEW_LABELS)})
        self.assertEqual([m[1] for m in self.writes("")], [f"repos/{MODULE.REPOSITORY}/issues/300/labels"], "arming both review lanes is the tool's only write after the cut")
        detached = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(detached, base, "the clone must return to origin/main after a cut")
        released = MODULE.acquire_lock(self.repo / ".git" / "promoter.lock")
        self.assertIsNotNone(released, "the lock must be released on every exit path")
        MODULE.release_lock(released)

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
        self.fleet.gh[f"repos/{MODULE.REPOSITORY}/issues/285/comments?per_page=100"] = [[{"user": {"login": MODULE.ASSIGNEE, "id": OWNER_ID}, "body": body}]]
        self.mutations.clear()
        MODULE.tick(self.repo, False, registry=self.fleet.registry(), github=github, cosign=self.fleet.cosign(), run=self.run_command)
        self.assertEqual([m for m in self.mutations if m[0] == "api-write"], [])

    def test_failure_alert_dedup_binds_the_owner_actor_and_the_exact_marker(self):
        github = MODULE.GitHub(run=self.run_command, fetch=self.fleet.fetch)
        path = f"repos/{MODULE.REPOSITORY}/issues/285/comments?per_page=100"
        self.fleet.gh[path] = [[]]
        report = lambda: MODULE.report_failure(github, {"naranjo-online": self.next}, "cut", "boom", False)
        report()
        body = json.loads(self.writes("/issues/285/comments")[0][2])["body"]
        marker = body.splitlines()[0]
        self.fleet.gh[path] = [[{"user": {"login": "mallory", "id": 4242}, "body": body}]]
        report()
        self.assertEqual(len(self.writes("/issues/285/comments")), 2, "an outsider's preseed never suppresses the alert")
        self.fleet.gh[path] = [[{"user": {"login": MODULE.ASSIGNEE, "id": OWNER_ID + 1}, "body": body}]]
        report()
        self.assertEqual(len(self.writes("/issues/285/comments")), 3, "a reused owner login with another immutable actor id never suppresses the alert")
        self.fleet.gh[path] = [[{"user": {"login": MODULE.ASSIGNEE, "id": OWNER_ID}, "body": "quoting " + marker + " in prose"}]]
        report()
        self.assertEqual(len(self.writes("/issues/285/comments")), 4, "a lookalike never suppresses the alert")
        self.fleet.gh[path] = [[{"user": {"login": MODULE.ASSIGNEE, "id": OWNER_ID}, "body": body}]]
        report()
        self.assertEqual(len(self.writes("/issues/285/comments")), 4, "the promoter's own exact report is reported once")

    def test_lock_and_dirty_clone_guards(self):
        lock = self.repo / ".git" / "promoter.lock"
        held = MODULE.acquire_lock(lock)
        self.assertIsNotNone(held)
        self.assertIsNone(MODULE.acquire_lock(lock), "a live holder's lock is never taken")
        os.utime(lock, (1, 1))
        self.assertIsNone(MODULE.acquire_lock(lock), "age never reaps a lock a live process holds")
        MODULE.release_lock(held)
        again = MODULE.acquire_lock(lock)
        self.assertIsNotNone(again, "a released lock is free")
        MODULE.release_lock(again)
        # A holder that dies releases the lock with it: no stale lock exists.
        subprocess.run([sys.executable, "-c", "import fcntl, os, sys; fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR); fcntl.flock(fd, fcntl.LOCK_EX)", str(lock)], check=True)
        orphaned = MODULE.acquire_lock(lock)
        self.assertIsNotNone(orphaned)
        MODULE.release_lock(orphaned)
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


class HermeticGitTests(unittest.TestCase):
    def test_auto_maintenance_is_pinned_off_in_every_hermetic_repository(self):
        environment = quiet_git_environment()
        pins = {environment[f"GIT_CONFIG_KEY_{i}"]: environment[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(environment["GIT_CONFIG_COUNT"]))}
        self.assertEqual(pins, {"gc.auto": "0", "gc.autoDetach": "false", "maintenance.auto": "false"})
        for key, value in pins.items():
            seen = subprocess.run(["git", "config", "--get", key], capture_output=True, text=True, env=environment).stdout.strip()
            self.assertEqual(seen, value, f"{key} must reach git through the environment")
        bare = hermetic_git_environment()
        self.assertNotIn("GIT_CONFIG_COUNT", bare)
        self.assertNotEqual(subprocess.run(["git", "config", "--get", "maintenance.auto"], capture_output=True, text=True, env=bare).stdout.strip(), "false")


    def test_every_command_runs_with_git_auto_maintenance_pinned_off(self):
        # The production path: run_command pins the maintenance keys into
        # every command's environment, extending an existing GIT_CONFIG set.
        quiet = quiet_git_environment()
        pinned = MODULE.pinned_environment(quiet)
        self.assertEqual(int(pinned["GIT_CONFIG_COUNT"]), int(quiet["GIT_CONFIG_COUNT"]) + len(MODULE.GIT_MAINTENANCE_PINS))
        for index in range(int(quiet["GIT_CONFIG_COUNT"])):
            self.assertEqual(pinned[f"GIT_CONFIG_KEY_{index}"], quiet[f"GIT_CONFIG_KEY_{index}"])
        bare = hermetic_git_environment()
        for key, value in MODULE.GIT_MAINTENANCE_PINS:
            self.assertEqual(MODULE.run_command(["git", "config", "--get", key], env=bare).strip(), value, f"{key} must reach git under run_command")
            self.assertEqual(MODULE.run_command(["sh", "-c", f"git config --get {key}"], env=bare).strip(), value, f"{key} must reach a git started by an intermediate command")
        self.assertEqual(MODULE.run_command(["git", "config", "--get", "maintenance.auto"]).strip(), "false", "the pins apply when the caller passes no environment")
        self.assertNotIn("GIT_CONFIG_COUNT", bare, "run_command never mutates the caller's mapping")


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

    def test_status_exit_code_is_three_for_any_selection_that_is_not_current(self):
        current = {"committed": "0.1.71", "latest": "0.1.71", "verdict": "current"}
        self.assertEqual(MODULE.status_exit_code({"a": current, "b": current}), 0)
        for verdict in ("behind", "ahead", "unpublished"):
            with self.subTest(verdict=verdict):
                self.assertEqual(MODULE.status_exit_code({"a": current, "b": dict(current, verdict=verdict)}), 3)

    def test_an_unrunnable_program_is_a_refusal_not_a_traceback(self):
        with self.assertRaisesRegex(MODULE.Refusal, r"`definitely-not-a-real-binary-xyz version` could not be run: "):
            MODULE.run_command(["definitely-not-a-real-binary-xyz", "version"])

    def test_latest_release_distinguishes_no_releases_from_any_other_refusal(self):
        fleet = FakeFleet()
        self.assertEqual(MODULE.latest_release(fleet.github(), "snaraj/publishes-nothing"), (None, None), "the API's 404 means the repository publishes nothing")
        self.assertIsNotNone(MODULE.NOT_FOUND_RE.search("`gh api x` exited 1: gh: Not Found (HTTP 404)"))
        self.assertIsNotNone(MODULE.NOT_FOUND_RE.search("`gh api x` exited 1: gh: Not Found (HTTP 404)  "), "trailing whitespace after the final marker is still the final marker")

        for text in (
            "`gh api` exited 1: transport failure",
            "`gh api` exited 1: proxy port 4040 refused the connection",
            "`gh api` exited 1: gh: Forbidden (HTTP 403)",
            "`gh api` exited 1: gh: Bad Gateway (HTTP 5404)",
            "`gh api` exited 1: proxy body said (HTTP 404) | gh: Internal Server Error (HTTP 500)",
            "`gh api` exited 1: gh: Not Found (HTTP 404) | then a trailing hint line",
        ):
            with self.subTest(refusal=text):
                def down(argv, cwd=None, input_text=None, env=None, timeout=None, text=text):
                    raise MODULE.Refusal(text)

                with self.assertRaisesRegex(MODULE.Refusal, re.escape(text)):
                    MODULE.latest_release(MODULE.GitHub(run=down, fetch=fleet.fetch), "snaraj/publishes-nothing")


class SiblingLoaderTests(unittest.TestCase):
    """`_load_sibling` publishes the module under its own name so a PEP 563
    annotation can resolve while the body runs (without it the promoter aborts
    at import and every tick fails). Publishing is only half the contract: the
    name must be gone again afterwards, or the promoter would leave an
    importable alias for a private copy — and on the second call would find the
    FIRST copy's leftovers instead of a clean slate. These pin the cleanup on
    both exits (PR #305 round 4, finding 1)."""

    def tearDown(self):
        for name in ("promoter_loader_probe", "promoter_loader_sentinel"):
            sys.modules.pop(name, None)

    def test_an_absent_name_is_absent_again_after_a_successful_load(self):
        self.assertNotIn("promoter_loader_probe", sys.modules)
        module = MODULE._load_sibling("ci/deploy_assurance.py", "promoter_loader_probe")
        self.assertTrue(hasattr(module, "drift_verdict"), "the sibling really did execute")
        self.assertNotIn("promoter_loader_probe", sys.modules)

    def test_a_pre_existing_name_is_restored_after_a_successful_load(self):
        sentinel = object()
        sys.modules["promoter_loader_sentinel"] = sentinel
        MODULE._load_sibling("ci/deploy_assurance.py", "promoter_loader_sentinel")
        self.assertIs(sys.modules["promoter_loader_sentinel"], sentinel)

    def test_a_sibling_whose_body_fails_leaks_no_name(self):
        # The exception path is the one a `finally` exists for: a sibling that
        # raises must not leave its half-executed module published.
        self.assertNotIn("promoter_loader_probe", sys.modules)
        with self.assertRaises(FileNotFoundError):
            MODULE._load_sibling("no_such_sibling_for_this_test.py", "promoter_loader_probe")
        self.assertNotIn("promoter_loader_probe", sys.modules)

    def test_a_sibling_whose_body_fails_restores_a_pre_existing_name(self):
        sentinel = object()
        sys.modules["promoter_loader_sentinel"] = sentinel
        with self.assertRaises(FileNotFoundError):
            MODULE._load_sibling("no_such_sibling_for_this_test.py", "promoter_loader_sentinel")
        self.assertIs(sys.modules["promoter_loader_sentinel"], sentinel)

    def test_a_pre_existing_none_entry_is_restored_not_dropped(self):
        # A stored `None` is Python's import-blocking marker, not absence: it
        # is a state some other importer deliberately put there, and dropping
        # it silently unblocks that import. Tracking absence by `.get()` and
        # `is None` cannot tell the two apart, so both exits are pinned.
        for label, load in (
            ("success", lambda: MODULE._load_sibling("ci/deploy_assurance.py", "promoter_loader_probe")),
            ("failure", lambda: MODULE._load_sibling("no_such_sibling_for_this_test.py", "promoter_loader_probe")),
        ):
            with self.subTest(path=label):
                sys.modules["promoter_loader_probe"] = None
                if label == "failure":
                    with self.assertRaises(FileNotFoundError):
                        load()
                else:
                    load()
                self.assertIn("promoter_loader_probe", sys.modules)
                self.assertIsNone(sys.modules["promoter_loader_probe"])


class BodyAccountingTests(unittest.TestCase):
    """AGENTS.md's accounting contract: the commission states an estimate and
    the pull-request body the actuals, so the doubling rule has something to
    compare. The generated promotion body carried none, which made every cut
    structurally unable to satisfy it (PR #306, security finding). The line is
    rendered from measured numbers and names the command that reproduces it.
    """

    BASE = "b424421eb9b539fa559c24d915c36211c369720e"

    def test_the_line_states_the_measured_numbers_and_its_own_command(self):
        for (files, added, deleted), expected in (
            ((9, 51, 47), "9 files, +51 / -47, net +4."),
            ((3, 4, 120), "3 files, +4 / -120, net -116."),
            ((1, 7, 7), "1 files, +7 / -7, net +0."),
        ):
            with self.subTest(files=files):
                line = MODULE.accounting_line(self.BASE, files, added, deleted)
                self.assertEqual(
                    line,
                    f"Accounting (measured, `git diff --numstat {self.BASE[:7]}..HEAD`): {expected}",
                )

    def test_the_body_carries_the_line_between_the_evidence_and_the_closes(self):
        record = self.receipt_record()
        accounting = MODULE.accounting_line(self.BASE, 9, 51, 47)
        body = MODULE.pr_body(
            MODULE.discover_selections(REPO_ROOT),
            {"naranjo-online": (record, {})},
            [285],
            self.BASE,
            accounting,
        )
        self.assertIn(accounting, body)
        self.assertLess(body.index("Evidence:"), body.index(accounting))
        self.assertLess(body.index(accounting), body.index("Closes #285"))
        self.assertTrue(body.rstrip().endswith(MODULE.SIGNATURE))

    def test_a_body_may_state_its_accounting_exactly_once(self):
        # Two sets of numbers state neither: a reader cannot tell which the
        # commit records, and one named command reproduces only one of them
        # (PR #308 review, finding 2). Enforced, not trusted.
        record = self.receipt_record()
        one = MODULE.accounting_line(self.BASE, 9, 51, 47)
        arguments = (MODULE.discover_selections(REPO_ROOT), {"naranjo-online": (record, {})}, [285], self.BASE)
        self.assertIn(one, MODULE.pr_body(*arguments, one))
        for doubled in (one + "\n" + one, one + " " + MODULE.accounting_line(self.BASE, 1, 1, 1)):
            with self.subTest(shape=doubled[:40]):
                with self.assertRaisesRegex(MODULE.Refusal, "exactly once, not 2 times"):
                    MODULE.pr_body(*arguments, doubled)
        with self.assertRaisesRegex(MODULE.Refusal, "exactly once, not 0 times"):
            MODULE.pr_body(*arguments, "no accounting at all")

    def test_an_unmeasurable_numstat_row_refuses_the_cut(self):
        # git renders a binary path's counts as `-`; summing that would raise
        # or silently mis-state, so the cut refuses instead of guessing.
        for rendered in ("-\t-\tdocs/logo.png", "12\tdocs/only-two-fields.md", "x\t3\tdocs/a.md"):
            with self.subTest(rendered=rendered):
                workspace = MODULE.Workspace(REPO_ROOT, run=lambda argv, **kw: "" if argv[1] == "add" else rendered + "\n")
                with self.assertRaisesRegex(MODULE.Refusal, "not measurable"):
                    workspace.numstat(self.BASE)

    def test_the_measured_totals_sum_every_row(self):
        rows = "1\t1\tREADME.md\n4\t0\tchangelog.d/285-x.md\n9\t9\tdocs/receipt.json\n"
        workspace = MODULE.Workspace(REPO_ROOT, run=lambda argv, **kw: "" if argv[1] == "add" else rows)
        self.assertEqual(workspace.numstat(self.BASE), (3, 14, 10))

    def receipt_record(self):
        record = json.loads((REPO_ROOT / MODULE.RECEIPT_JSON).read_text())["records"]["naranjo-online"]
        return record


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
