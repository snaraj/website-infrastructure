"""Ordinary offline controls for the isolated private-connector artifact."""

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from .test_connector_identity_contract import documents, render


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "private_connector", ROOT / "scripts/render_obsync_private_connector.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REVISION = "rev-isolated-artifact-check"


def fixture():
    """Synthetic known identities; real chart equivalence is tested below."""
    parts = []
    for api, kind, name in sorted(MODULE.INVENTORY):
        text = (
            f"apiVersion: {api}\nkind: {kind}\nmetadata:\n"
            f"  name: {name}\n  namespace: cloudflare-public\n"
            "  labels:\n    app.kubernetes.io/managed-by: Helm\n"
        )
        if kind == "Deployment":
            text += (
                "spec:\n  template:\n    metadata:\n      labels:\n"
                "        app.kubernetes.io/managed-by: Helm\n      annotations:\n"
                f'        platform.snaraj.dev/tunnel-token-revision: "{REVISION}"\n'
            )
        parts.append(text)
    return "---\n" + "---\n".join(parts)


class SelectionTests(unittest.TestCase):
    def test_emits_policy_then_one_deployment_and_no_shared_object(self):
        selected = MODULE.select_artifact(fixture(), REVISION)
        self.assertEqual(list(documents(selected)), [
            ("NetworkPolicy", "cloudflared-obsidian"), ("Deployment", "obsync-tunnel")
        ])
        self.assertEqual(selected.count("managed-by: obsync-private-operator"), 3)
        self.assertNotIn("managed-by: Helm", selected)

    def test_missing_duplicate_or_added_identity_refuses(self):
        baseline = fixture()
        first = baseline.split("---\n")[1]
        for altered in (
            baseline.replace(first, "", 1), baseline + "---\n" + first,
            baseline + "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: additional\n  namespace: cloudflare-public\n",
        ):
            with self.subTest(altered=altered[-80:]), self.assertRaises(ValueError):
                MODULE.select_artifact(altered, REVISION)

    def test_changed_namespace_api_identity_or_ownership_shape_refuses(self):
        for before, after in (
            ("namespace: cloudflare-public", "namespace: different"),
            ("apiVersion: apps/v1", "apiVersion: apps/v2"),
            ("managed-by: Helm", "managed-by: different"),
            ("  name: obsync-tunnel", "  name: obsync-tunnel\n  name: duplicate"),
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                MODULE.select_artifact(fixture().replace(before, after), REVISION)

    def test_empty_oversized_and_unidentified_documents_refuse(self):
        valid = fixture()
        at_bound = valid + " " * (128 * 1024 - len(valid.encode("utf-8")))
        self.assertEqual(MODULE.select_artifact(at_bound, REVISION),
                         MODULE.select_artifact(valid, REVISION))
        for text in ("", at_bound + " ", valid + "---\n# extra document\n"):
            with self.subTest(size=len(text)), self.assertRaises(ValueError):
                MODULE.select_artifact(text, REVISION)

    def test_resolved_revision_must_be_exact_and_canonical(self):
        for value in ("not-configured", "UNRESOLVED", "", "rev-", "rev-UPPER", "rev-a\n", "rev-" + "a" * 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.select_artifact(fixture(), value)
        with self.assertRaises(ValueError):
            MODULE.select_artifact(fixture(), "rev-different")

    def test_fixed_parts_compose_byte_exactly_and_no_other_part_is_accepted(self):
        policy = MODULE.select_artifact(fixture(), REVISION, "policy")
        deployment = MODULE.select_artifact(fixture(), REVISION, "deployment")
        self.assertEqual(policy + deployment, MODULE.select_artifact(fixture(), REVISION))
        self.assertEqual(list(documents(policy)), [("NetworkPolicy", "cloudflared-obsidian")])
        self.assertEqual(list(documents(deployment)), [("Deployment", "obsync-tunnel")])
        with self.assertRaises(ValueError):
            MODULE.select_artifact(fixture(), REVISION, "shared")

    def test_cli_failure_emits_no_partial_manifest_or_subprocess_details(self):
        for failure in (ValueError(), OSError(), subprocess.TimeoutExpired("helm", 30),
                        subprocess.CalledProcessError(1, "helm", stderr="unfiltered output")):
            output, error = io.StringIO(), io.StringIO()
            with patch.object(MODULE, "render", side_effect=failure), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                self.assertEqual(MODULE.main(["--token-revision", REVISION]), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn("unfiltered output", error.getvalue())

    def test_cli_success_emits_only_selected_artifact(self):
        expected = MODULE.select_artifact(fixture(), REVISION)
        output = io.StringIO()
        with patch.object(MODULE, "render", return_value=expected), contextlib.redirect_stdout(output):
            self.assertEqual(MODULE.main(["--token-revision", REVISION]), 0)
        self.assertEqual(output.getvalue(), expected)


class OfflineCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / MODULE.CHART).mkdir(parents=True)
        (self.root / "versions.env").write_text("HELM_VERSION=v4.2.4\n")

    def test_only_fixed_helm_commands_execute_without_shell_or_live_inputs(self):
        responses = [subprocess.CompletedProcess([], 0, "v4.2.4"),
                     subprocess.CompletedProcess([], 0, fixture())]
        with patch.object(MODULE.subprocess, "run", side_effect=responses) as run:
            selected = MODULE.render(REVISION, self.root)
        self.assertEqual(selected, MODULE.select_artifact(fixture(), REVISION))
        self.assertEqual(run.call_args_list[0].args[0], ["helm", "version", "--template", "{{.Version}}"])
        self.assertEqual(run.call_args_list[1].args[0], [
            "helm", "template", "cloudflare-public", str(self.root / MODULE.CHART),
            "--namespace", "cloudflare-public", "--set-string", f"connectors.obsync.tokenRevision={REVISION}"
        ])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs, dict(check=True, capture_output=True, text=True, timeout=30))

    def test_dependency_or_unresolved_revision_stops_before_any_command(self):
        chart = self.root / MODULE.CHART
        for dependency in ("Chart.lock", "charts/dependency.yaml"):
            target = chart / dependency
            target.parent.mkdir(exist_ok=True)
            target.touch()
            with patch.object(MODULE.subprocess, "run") as run, self.assertRaises(ValueError):
                MODULE.render(REVISION, self.root)
            run.assert_not_called()
            target.unlink()
        with patch.object(MODULE.subprocess, "run") as run, self.assertRaises(ValueError):
            MODULE.render("not-configured", self.root)
        run.assert_not_called()

    def test_tool_pin_mismatch_stops_before_render(self):
        with patch.object(MODULE.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "v0.0.0")) as run, self.assertRaises(ValueError):
            MODULE.render(REVISION, self.root)
        self.assertEqual(run.call_count, 1)


@unittest.skipUnless(shutil.which("helm"), "helm is required")
class RealChartTests(unittest.TestCase):
    def test_real_artifact_is_exact_chart_selection_except_ownership_labels(self):
        before = render()
        changed = render(f"connectors.obsync.tokenRevision={REVISION}")
        full = documents(changed)
        artifact = MODULE.render(REVISION)
        selected = documents(artifact)
        self.assertEqual(set(selected), {("NetworkPolicy", "cloudflared-obsidian"), ("Deployment", "obsync-tunnel")})
        for identity, value in selected.items():
            self.assertEqual(value.replace("managed-by: obsync-private-operator", "managed-by: Helm").removeprefix("---\n").strip(), full[identity].removeprefix("---\n").strip())
        baseline = documents(before)
        for identity, value in baseline.items():
            if identity != ("Deployment", "obsync-tunnel"):
                self.assertEqual(full[identity], value)
        self.assertEqual(render(), before, "offline selection must leave the normal chart unchanged")


class CanonicalGateTests(unittest.TestCase):
    def canonical_gate(self, *, empty=False):
        """Run the complete canonical shell with recording offline adapters."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            scripts, tools = root / "scripts", root / "bin"
            scripts.mkdir()
            tools.mkdir()
            (scripts / "render-manifests.sh").write_text(
                (ROOT / "scripts/render-manifests.sh").read_text())
            (scripts / "test-policy-fixtures.sh").write_text("exit 0\n")
            for name in (
                "kubernetes/platform/cloudflare-public/chart/Chart.yaml",
                *(f"kubernetes/{name}/kustomization.yaml" for name in (
                    "flux-system/canary", "flux-system/egress", "platform/prerequisites",
                    "platform/obsync-tls-proxy", "platform/cloudflare-public/release")),
                "tests/kubernetes/fixtures/release-deny/missing-readiness.yaml",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("offline fixture\n")
            artifact = "" if empty else MODULE.select_artifact(fixture(), REVISION)
            (root / "selected.yaml").write_text(artifact)
            adapter = f"#!{sys.executable}\n" + '''import json,os,sys
from pathlib import Path
tool,args=Path(sys.argv[0]).name,sys.argv[1:]
root=Path(os.environ["CONNECTOR_GATE_FIXTURE"])
if tool=="python3":
    script=Path(args[1]).name
    if script=="validate_release_transition.py":
        print("mode=scaffold\\ncloudflare-public=initial\\nplatform-services-suspended=true\\nany-workload-active=false")
    elif script=="render_obsync_private_connector.py":
        assert args[2:]==["--token-revision","rev-offline-validation"]
        print((root/"selected.yaml").read_text(),end="")
    else: assert script=="validate_signature_policy.py"
elif tool in ("helm","kustomize"):
    if args[0]!="lint": print("kind: ConfigMap\\nmetadata:\\n  name: offline-fixture")
else:
    assert tool in ("kubeconform","conftest")
    path=Path(args[-1])
    with (root/"calls.jsonl").open("a") as out:
        out.write(json.dumps([tool,args,path.read_text()])+"\\n")
    if tool=="conftest" and Path(args[2]).name=="release-conftest":
        print({"missing-readiness.yaml":"Deployment readiness-missing is not marked ready",
               "helm-cloudflare-public.yaml":"cloudflared tunnel token revision remains unresolved",
               "kubernetes-platform-cloudflare-public-release.yaml":"HelmRelease cloudflare-public remains suspended"}[path.name])
        sys.exit(1)
'''
            for name in ("python3", "helm", "kustomize", "kubeconform", "conftest"):
                executable = tools / name
                executable.write_text(adapter)
                executable.chmod(0o700)
            env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                   "CONNECTOR_GATE_FIXTURE": str(root)}
            result = subprocess.run(["bash", str(scripts / "render-manifests.sh"), "--scaffold"],
                                    env=env, capture_output=True, text=True, check=False)
            calls = root / "calls.jsonl"
            recorded = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        return result, recorded, artifact

    def test_selected_artifact_reaches_both_canonical_validators(self):
        result, recorded, artifact = self.canonical_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = [(tool, args, text) for tool, args, text in recorded
                    if pathlib.Path(args[-1]).name == "obsync-private-connector.yaml"]
        self.assertEqual([tool for tool, _, _ in selected], ["kubeconform", "conftest"])
        self.assertTrue(all(text == artifact for _, _, text in selected))
        self.assertEqual(pathlib.Path(selected[1][1][2]).name, "conftest")

    def test_empty_selected_artifact_stops_before_canonical_validation(self):
        result, recorded, _ = self.canonical_gate(empty=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private connector selection produced an empty render", result.stderr)
        self.assertEqual(recorded, [])


class RunbookTests(unittest.TestCase):
    def test_operator_ceremony_keeps_source_and_live_authority_separate(self):
        text = " ".join((ROOT / "docs/runbooks/obsync-private-connector.md").read_text().split())
        for required in (
            "create-only", "source commit", "artifact SHA-256", "resourceVersion", "UID",
            "ServiceAccount", "cloudflared-dns", "cloudflared-edge", "default-deny",
            "obsync-tunnel-token", "private-network route", "Do Not Inspect",
            "suspended", "partial", "No token value", "owner approval",
            "never adopt", "not native-device acceptance",
        ):
            self.assertIn(required, text)

    def preflight(self, *, existing=(), missing=(), failed_read=None, automount="false"):
        text = (ROOT / "docs/runbooks/obsync-private-connector.md").read_text()
        blocks = re.findall(r"```bash\n(.*?)\n```", text, re.DOTALL)
        self.assertEqual(len(blocks), 1)
        with tempfile.TemporaryDirectory() as home:
            home = pathlib.Path(home)
            state = home / "state.json"
            state.write_text(json.dumps(dict(existing=existing, missing=missing, failed_read=failed_read, automount=automount)))
            calls = home / "calls.jsonl"
            executable = home / "kubectl"
            executable.write_text(f"#!{sys.executable}\n" + '''import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ["CONNECTOR_TEST_CALLS"]).open("a") as log: log.write(json.dumps(args)+"\\n")
state=json.loads(Path(os.environ["CONNECTOR_TEST_STATE"]).read_text())
if args[0]=="create": sys.exit(0)
assert args[0]=="get" and args[2:4]==["--namespace","cloudflare-public"]
target=args[1]
if target==state["failed_read"]: sys.exit(1)
if args[-1]=="jsonpath={.automountServiceAccountToken}": print(state["automount"])
elif target in ("deployment/obsync-tunnel","networkpolicy/cloudflared-obsidian"):
    if target in state["existing"]: print(target)
elif target not in state["missing"]: print(target)
''')
            executable.chmod(0o700)
            env = {**os.environ, "PATH": str(home) + os.pathsep + os.environ["PATH"],
                   "CONNECTOR_TEST_STATE": str(state), "CONNECTOR_TEST_CALLS": str(calls)}
            # The witness is a mock command after the exact documented guard;
            # a refusal must exit before reaching any creation at all.
            result = subprocess.run(["bash", "-c", blocks[0] + '\nkubectl create -f synthetic-artifact.yaml\n'],
                                    env=env, capture_output=True, text=True, check=False)
            recorded = [json.loads(line) for line in calls.read_text().splitlines()]
        return result.returncode, recorded

    def test_either_preexisting_selected_object_stops_before_any_creation(self):
        for target in ("deployment/obsync-tunnel", "networkpolicy/cloudflared-obsidian"):
            with self.subTest(target=target):
                status, calls = self.preflight(existing=[target])
                self.assertNotEqual(status, 0)
                self.assertTrue(all(call[0] == "get" for call in calls))

    def test_missing_shared_prerequisites_and_failed_reads_stop_without_adoption(self):
        for target in ("serviceaccount/cloudflared", "networkpolicy/default-deny", "networkpolicy/cloudflared-dns", "networkpolicy/cloudflared-edge"):
            with self.subTest(target=target):
                status, calls = self.preflight(missing=[target])
                self.assertNotEqual(status, 0)
                self.assertTrue(all(call[0] == "get" for call in calls))
        status, calls = self.preflight(failed_read="deployment/obsync-tunnel")
        self.assertNotEqual(status, 0)
        self.assertTrue(all(call[0] == "get" for call in calls))

    def test_shared_account_requires_explicit_false_automount(self):
        for value in ("", "true"):
            with self.subTest(value=value):
                status, calls = self.preflight(automount=value)
                self.assertNotEqual(status, 0)
                self.assertTrue(all(call[0] == "get" for call in calls))

    def test_valid_preflight_reaches_creation_witness_after_all_named_reads(self):
        status, calls = self.preflight()
        self.assertEqual(status, 0)
        self.assertEqual(len(calls), 8)
        self.assertEqual(calls[-1], ["create", "-f", "synthetic-artifact.yaml"])


if __name__ == "__main__":
    unittest.main()
