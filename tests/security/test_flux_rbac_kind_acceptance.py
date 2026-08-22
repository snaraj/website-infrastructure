"""Contract tests for the isolated real-controller Flux RBAC acceptance."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from scripts import flux_rbac_kind_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[2]
TEST_TOOL_IDENTITY = acceptance.ToolIdentity.capture(
    Path(sys.executable).resolve(strict=True)
)
TEST_DOCKER_CUSTODY = acceptance.DockerCustody(
    context="test-local",
    endpoint="unix:///var/run/docker.sock",
    daemon_id="test-daemon-id",
)


def test_tool_documents():
    return {
        name: TEST_TOOL_IDENTITY.document() for name in acceptance.TOOL_NAMES
    }


def completed(
    arguments: tuple[str, ...] = ("tool",),
    *,
    stdout: object = b"",
    stderr: bytes = b"",
    returncode: int = 0,
) -> subprocess.CompletedProcess[bytes]:
    if not isinstance(stdout, bytes):
        stdout = json.dumps(stdout).encode("utf-8")
    return subprocess.CompletedProcess(list(arguments), returncode, stdout, stderr)


def synthetic_git_repository(base: Path) -> tuple[Path, str]:
    repository = base / "repo"
    remote = base / "remote.git"
    repository.mkdir()

    def git(*arguments: str, cwd: Path = repository) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return result.stdout.decode("utf-8").strip()

    git("init", "--bare", "-q", str(remote), cwd=base)
    git("init", "-q")
    git("config", "user.name", "Synthetic")
    git("config", "user.email", "synthetic" + "@" + "example.invalid")
    (repository / "fixture.txt").write_text("fixture\n", encoding="utf-8")
    git("add", "fixture.txt")
    git("commit", "-qm", "fixture")
    git("branch", "-M", "review")
    git("remote", "add", "origin", str(remote))
    git("push", "-qu", "origin", "review")
    return repository, git("rev-parse", "HEAD")


class SyntheticPreflightRunner:
    def __init__(self, repository: Path, expected: str) -> None:
        self.repository = repository
        self.expected = expected

    def run(self, arguments, **_kwargs):
        command = tuple(arguments)
        if command == ("git", "remote", "get-url", "--all", "origin"):
            return completed(command, stdout=acceptance.CANONICAL_ORIGIN_URLS[0].encode())
        if command == (
            "git",
            "ls-remote",
            "--exit-code",
            acceptance.CANONICAL_ORIGIN_URLS[0],
            "refs/heads/review",
        ):
            return completed(
                command,
                stdout=(self.expected + "\trefs/heads/review\n").encode(),
            )
        return subprocess.run(
            list(arguments),
            cwd=self.repository,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )


class MatrixContractTests(unittest.TestCase):
    def test_literal_matrix_cardinalities_and_uniqueness(self):
        self.assertEqual(len(acceptance.CROSSING_ROWS), 18)
        self.assertEqual(len(acceptance.OWNED_ROWS), 9)
        self.assertEqual(len(acceptance.GENERAL_DENIED_ROWS), 6)
        self.assertEqual(len(acceptance.HELM_SECRET_ROWS), 3)
        self.assertEqual(len(acceptance.TENANT_ALLOWED_ROWS), 18)
        self.assertEqual(len(acceptance.TENANT_DENIED_ROWS), 12)
        for matrix in (
            acceptance.CROSSING_ROWS,
            acceptance.OWNED_ROWS,
            acceptance.GENERAL_DENIED_ROWS,
            acceptance.HELM_SECRET_ROWS,
            acceptance.TENANT_ALLOWED_ROWS,
            acceptance.TENANT_DENIED_ROWS,
        ):
            self.assertEqual(len({row.label for row in matrix}), len(matrix))

    def test_crossing_matrix_pins_status_and_authorization_only_finalizers(self):
        identities = {
            (row.subject, row.verb, row.group, row.resource, row.subresource)
            for row in acceptance.CROSSING_ROWS
        }
        self.assertIn(
            (
                acceptance.SOURCE,
                "update",
                "kustomize.toolkit.fluxcd.io",
                "kustomizations",
                "finalizers",
            ),
            identities,
        )
        self.assertIn(
            (
                acceptance.HELM,
                "update",
                "source.toolkit.fluxcd.io",
                "buckets",
                "status",
            ),
            identities,
        )

    def test_tenant_matrix_is_local_read_only_and_closed_cross_tenant(self):
        for namespace in acceptance.TENANTS:
            subject = acceptance.tenant_subject(namespace)
            local = [row for row in acceptance.TENANT_ALLOWED_ROWS if row.subject == subject]
            denied = [row for row in acceptance.TENANT_DENIED_ROWS if row.subject == subject]
            self.assertEqual(len(local), 6)
            self.assertEqual({row.namespace for row in local}, {namespace})
            self.assertEqual({row.verb for row in local}, {"get", "list", "watch"})
            self.assertEqual(len(denied), 4)
            self.assertEqual(sum(row.namespace != namespace for row in denied), 2)

    def test_review_document_omits_cluster_scope_and_preserves_subresource(self):
        row = acceptance.AccessRow(
            "finalizer",
            acceptance.KUSTOMIZE,
            "update",
            "kustomize.toolkit.fluxcd.io",
            "kustomizations",
            "finalizers",
        )
        attributes = acceptance.review_document(row)["spec"]["resourceAttributes"]
        self.assertNotIn("namespace", attributes)
        self.assertEqual(attributes["subresource"], "finalizers")

    def test_service_account_groups_are_exact(self):
        self.assertEqual(
            acceptance.service_account_groups(acceptance.HELM),
            (
                "system:serviceaccounts",
                "system:serviceaccounts:flux-system",
                "system:authenticated",
            ),
        )
        with self.assertRaisesRegex(acceptance.AcceptanceError, "SUBJECT_INVALID"):
            acceptance.service_account_groups("admin")


class PureContractTests(unittest.TestCase):
    def test_registry_publish_uses_explicit_random_loopback_port(self):
        self.assertEqual(acceptance.registry_publish_spec(), "127.0.0.1:0:5000")
        infrastructure = (
            (ROOT / "scripts" / "flux_rbac_kind_acceptance.py")
            .read_text(encoding="utf-8")
            .split("    def create_infrastructure", 1)[1]
            .split("    def build_artifacts", 1)[0]
        )
        self.assertIn("registry_publish_spec()", infrastructure)
        self.assertNotIn('LOOPBACK + ":" + ":5000"', infrastructure)

    def test_versions_parser_requires_digest_pins_and_no_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "versions.env"
            values = {
                key: "v1" for key in acceptance.REQUIRED_PINS
            }
            for key in (
                "KIND_NODE_IMAGE",
                "FLUX_SOURCE_CONTROLLER_IMAGE",
                "FLUX_KUSTOMIZE_CONTROLLER_IMAGE",
                "FLUX_HELM_CONTROLLER_IMAGE",
            ):
                values[key] = "example.invalid/image:v1@sha256:" + "1" * 64
            path.write_text(
                "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(acceptance.parse_versions(path)["KIND_VERSION"], "v1")
            path.write_text(path.read_text(encoding="utf-8") + "KIND_VERSION=v2\n", encoding="utf-8")
            with self.assertRaisesRegex(acceptance.AcceptanceError, "VERSION_FILE_INVALID"):
                acceptance.parse_versions(path)

    def test_clean_environment_drops_credential_shaped_ambient_values(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/bin",
                "HOME": "/tmp/home",
                "GITHUB_TOKEN": "not-forwarded",
                "AWS_SECRET_ACCESS_KEY": "not-forwarded",
                "DOCKER_HOST": "tcp://remote.example:2376",
                "DOCKER_CONTEXT": "remote-context",
                "SSH_AUTH_SOCK": "/tmp/host-agent.sock",
            },
            clear=True,
        ):
            environment = acceptance.clean_environment({"GOOS": "linux"})
        self.assertEqual(environment["PATH"], "/bin")
        self.assertEqual(environment["KUBECONFIG"], "")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GOOS"], "linux")
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("DOCKER_CONTEXT", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "ENVIRONMENT_ROUTE_OVERRIDE"
        ):
            acceptance.clean_environment({"DOCKER_HOST": "ssh://remote.example"})
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "ENVIRONMENT_ROUTE_OVERRIDE"
        ):
            acceptance.clean_environment({"GIT_NO_REPLACE_OBJECTS": "0"})
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "ENVIRONMENT_ROUTE_OVERRIDE"
        ):
            acceptance.clean_environment({"GIT_NO_LAZY_FETCH": "0"})

    def test_remote_docker_context_is_rejected_before_daemon_contact(self):
        runner = acceptance.Runner()
        runner._tools["docker"] = TEST_TOOL_IDENTITY
        responses = [
            completed(("docker", "context", "show"), stdout=b"remote\n"),
            completed(
                ("docker", "context", "inspect"),
                stdout=b'"ssh://remote.example"\n',
            ),
        ]
        with (
            mock.patch.dict(
                os.environ,
                {
                    "DOCKER_HOST": "tcp://remote.example:2376",
                    "DOCKER_CONTEXT": "ambient-remote",
                    "SSH_AUTH_SOCK": "/tmp/agent.sock",
                },
                clear=False,
            ),
            mock.patch("subprocess.run", side_effect=responses) as invoked,
        ):
            with self.assertRaisesRegex(
                acceptance.AcceptanceError, "DOCKER_ENDPOINT_NOT_LOCAL"
            ):
                runner.bind_local_docker()
        self.assertEqual(invoked.call_count, 2)
        for call in invoked.call_args_list:
            environment = call.kwargs["env"]
            self.assertNotIn("DOCKER_HOST", environment)
            self.assertNotIn("DOCKER_CONTEXT", environment)
            self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertFalse(runner.docker_bound())

    def test_bound_docker_commands_use_only_the_verified_local_socket(self):
        custody = acceptance.DockerCustody(
            context="local-test",
            endpoint="unix:///private/tmp/docker.sock",
            daemon_id="local-daemon-id",
        )
        runner = acceptance.Runner()
        runner._tools["docker"] = TEST_TOOL_IDENTITY
        runner._docker_custody = custody
        with (
            mock.patch.dict(
                os.environ,
                {
                    "DOCKER_HOST": "ssh://remote.example",
                    "DOCKER_CONTEXT": "remote",
                    "SSH_AUTH_SOCK": "/tmp/agent.sock",
                },
                clear=False,
            ),
            mock.patch.object(
                acceptance,
                "local_docker_socket",
                return_value=Path("/private/tmp/docker.sock"),
            ),
            mock.patch(
                "subprocess.run", return_value=completed(stdout=b"ok")
            ) as invoked,
        ):
            runner.run(("docker", "version"))
        environment = invoked.call_args.kwargs["env"]
        self.assertEqual(environment["DOCKER_HOST"], custody.endpoint)
        self.assertNotIn("DOCKER_CONTEXT", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)

    def test_runner_never_uses_a_shell_or_streams_output(self):
        result = completed(stdout=b"ok")
        runner = acceptance.Runner()
        runner._tools["git"] = TEST_TOOL_IDENTITY
        with mock.patch("subprocess.run", return_value=result) as invoked:
            observed = runner.run(("git", "--version"))
        self.assertEqual(observed.stdout, b"ok")
        keyword = invoked.call_args.kwargs
        self.assertEqual(invoked.call_args.args[0][0], TEST_TOOL_IDENTITY.path)
        self.assertIn("--no-replace-objects", invoked.call_args.args[0])
        self.assertIn("protocol.https.allow=always", invoked.call_args.args[0])
        self.assertEqual(
            keyword["env"]["PATH"], str(Path(TEST_TOOL_IDENTITY.path).parent)
        )
        self.assertNotIn("shell", keyword)
        self.assertEqual(keyword["stdout"], subprocess.PIPE)
        self.assertEqual(keyword["stderr"], subprocess.PIPE)

    def test_bound_tool_mutation_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / "git"
            tool.write_bytes(Path(sys.executable).read_bytes())
            tool.chmod(0o700)
            runner = acceptance.Runner()
            runner._tools["git"] = acceptance.ToolIdentity.capture(tool)
            tool.write_bytes(tool.read_bytes() + b"mutation")
            with mock.patch("subprocess.run") as invoked:
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "TOOL_IDENTITY_CHANGED"
                ):
                    runner.run(("git", "--version"))
            invoked.assert_not_called()

    def test_state_machine_rejects_skip_and_repeat(self):
        machine = acceptance.StateMachine()
        machine.advance(acceptance.State.NEW, acceptance.State.PREFLIGHT)
        with self.assertRaisesRegex(acceptance.AcceptanceError, "STATE_ORDER_INVALID"):
            machine.advance(acceptance.State.NEW, acceptance.State.PREFLIGHT)
        with self.assertRaisesRegex(acceptance.AcceptanceError, "STATE_TRANSITION_INVALID"):
            machine.advance(acceptance.State.PREFLIGHT, acceptance.State.INFRASTRUCTURE)

    def test_exact_rule_lookup_rejects_widening_and_ambiguity(self):
        exact = {
            "rules": [
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}
            ]
        }
        self.assertEqual(
            acceptance.exact_rule_index(
                exact, group="", resource="pods", verbs=("get", "list", "watch")
            ),
            0,
        )
        widened = {"rules": exact["rules"] * 2}
        with self.assertRaisesRegex(acceptance.AcceptanceError, "RBAC_RULE_NOT_EXACT"):
            acceptance.exact_rule_index(
                widened, group="", resource="pods", verbs=("get", "list", "watch")
            )

    def test_generation_condition_and_history_are_non_vacuous(self):
        document = {
            "metadata": {"generation": 2},
            "status": {
                "observedGeneration": 2,
                "conditions": [{"type": "Ready", "status": "True", "reason": "InstallSucceeded"}],
                "history": [{"status": "deployed", "version": 1}],
            },
        }
        self.assertTrue(acceptance.current_generation(document))
        self.assertEqual(acceptance.condition(document, "Ready")["reason"], "InstallSucceeded")
        self.assertEqual(acceptance.deployed_history(document)["version"], 1)
        document["status"]["observedGeneration"] = 1
        document["status"]["history"][0]["status"] = "failed"
        self.assertFalse(acceptance.current_generation(document))
        self.assertIsNone(acceptance.deployed_history(document))

    def test_advanced_upgrade_history_does_not_replace_workload_effect_proof(self):
        release = {
            "metadata": {"generation": 2},
            "status": {
                "observedGeneration": 2,
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "UpgradeSucceeded",
                    }
                ],
                "history": [
                    {"status": "deployed", "version": 2, "configDigest": "sha256:two"}
                ],
            },
        }
        deployment = {
            "metadata": {
                "generation": 2,
                "annotations": {"acceptance.snaraj.dev/revision": "one"},
            },
            "status": {
                "observedGeneration": 2,
                "availableReplicas": 1,
                "readyReplicas": 1,
            },
        }
        self.assertFalse(
            acceptance.upgrade_effect_bound(
                release,
                deployment,
                previous_version=1,
                annotation="acceptance.snaraj.dev/revision",
                value="two",
            )
        )
        deployment["metadata"]["annotations"]["acceptance.snaraj.dev/revision"] = "two"
        self.assertTrue(
            acceptance.upgrade_effect_bound(
                release,
                deployment,
                previous_version=1,
                annotation="acceptance.snaraj.dev/revision",
                value="two",
            )
        )

    def test_authorization_failure_binds_resource_subject_and_namespace(self):
        message = (
            'pods is forbidden: User "system:serviceaccount:naranjo-online:'
            'helm-reconciler" cannot list resource "pods" in API group "" '
            'in the namespace "naranjo-online"'
        )
        self.assertTrue(
            acceptance.authorization_failure_bound(
                [message], namespace="naranjo-online", resource="pods", group=""
            )
        )
        self.assertFalse(
            acceptance.authorization_failure_bound(
                [message],
                namespace="naranjo-online",
                resource="replicasets",
                group="apps",
            )
        )

    def test_authorization_failure_cannot_be_assembled_across_messages(self):
        messages = [
            'pods is forbidden: User "system:serviceaccount:naranjo-online:helm-reconciler"',
            'cannot list resource "pods" in API group "" in the namespace "naranjo-online"',
        ]
        self.assertFalse(
            acceptance.authorization_failure_bound(
                messages,
                namespace="naranjo-online",
                resource="pods",
                group="",
            )
        )

    def test_upgrade_failure_is_current_generation_and_injected_change_bound(self):
        message = (
            'replicasets.apps is forbidden: User "system:serviceaccount:'
            'naranjo-online:helm-reconciler" cannot list resource "replicasets" '
            'in API group "apps" in the namespace "naranjo-online"'
        )
        release = {
            "metadata": {"generation": 4},
            "spec": {
                "commonMetadata": {
                    "annotations": {
                        "acceptance.snaraj.dev/readiness-negative": "replicasets"
                    }
                }
            },
            "status": {
                "observedGeneration": 4,
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "False",
                        "reason": "UpgradeFailed",
                        "message": message,
                    }
                ],
            },
        }
        self.assertTrue(
            acceptance.current_upgrade_failure_bound(
                release,
                generation=4,
                namespace="naranjo-online",
                resource="replicasets",
                group="apps",
            )
        )
        release["status"]["observedGeneration"] = 3
        self.assertFalse(
            acceptance.current_upgrade_failure_bound(
                release,
                generation=4,
                namespace="naranjo-online",
                resource="replicasets",
                group="apps",
            )
        )

    def test_rollback_requires_a_distinct_object_after_failure_observation(self):
        release = {
            "metadata": {"generation": 4, "resourceVersion": "100"},
            "status": {
                "observedGeneration": 4,
                "conditions": [
                    {
                        "type": "Remediated",
                        "status": "True",
                        "reason": "RollbackSucceeded",
                    }
                ],
            },
        }
        self.assertFalse(
            acceptance.rollback_after_failure_bound(
                release, generation=4, failure_resource_version="100"
            )
        )
        release["metadata"]["resourceVersion"] = "101"
        self.assertTrue(
            acceptance.rollback_after_failure_bound(
                release, generation=4, failure_resource_version="100"
            )
        )

    def test_same_pod_retry_requires_restart_advance_and_ready_container(self):
        failed = {
            "metadata": {"uid": "pod-1"},
            "status": {"containerStatuses": [{"restartCount": 2, "ready": False}]},
        }
        recovered = {
            "metadata": {"uid": "pod-1"},
            "status": {
                "phase": "Running",
                "containerStatuses": [{"restartCount": 3, "ready": True}],
                "conditions": [{"type": "Ready", "status": "True"}],
            },
        }
        self.assertTrue(acceptance.same_pod_kubelet_retry_bound(failed, recovered))
        recovered["status"]["containerStatuses"][0]["restartCount"] = 2
        self.assertFalse(acceptance.same_pod_kubelet_retry_bound(failed, recovered))
        recovered["status"]["containerStatuses"][0]["restartCount"] = 3
        recovered["metadata"]["uid"] = "replacement-pod"
        self.assertFalse(acceptance.same_pod_kubelet_retry_bound(failed, recovered))

    def test_controller_zero_transform_changes_exactly_two_replica_fields(self):
        original = acceptance.STOCK_COMPONENTS.read_bytes()
        transformed = acceptance.controller_deployments_zero_replica(original)
        self.assertNotEqual(original, transformed)
        self.assertEqual(len(original), len(transformed))
        self.assertEqual(
            transformed.count(b"\n  replicas: 0\n"),
            original.count(b"\n  replicas: 0\n") + 2,
        )
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "CONTROLLER_ZERO_TRANSFORM_INVALID"
        ):
            acceptance.controller_deployments_zero_replica(transformed)

    def test_controller_zero_transform_rejects_missing_and_duplicate_targets(self):
        original = acceptance.STOCK_COMPONENTS.read_bytes()
        for payload in (
            original.replace(
                b"  name: kustomize-controller\n",
                b"  name: absent-controller\n",
            ),
            original.replace(
                b"  name: helm-controller\n",
                b"  name: kustomize-controller\n",
            ),
        ):
            with self.subTest(payload=hashlib.sha256(payload).hexdigest()):
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "CONTROLLER_ZERO_TRANSFORM_INVALID"
                ):
                    acceptance.controller_deployments_zero_replica(payload)

    def test_controller_cold_start_bound_is_current_single_and_zero_restart(self):
        deployment = {
            "metadata": {
                "name": "kustomize-controller",
                "namespace": "flux-system",
                "generation": 4,
            },
            "spec": {"replicas": 1},
            "status": {
                "observedGeneration": 4,
                "replicas": 1,
                "updatedReplicas": 1,
                "availableReplicas": 1,
                "readyReplicas": 1,
            },
        }
        pod = {
            "metadata": {
                "uid": "pod-1",
                "labels": {"app": "kustomize-controller"},
            },
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {"name": "manager", "ready": True, "restartCount": 0}
                ],
                "conditions": [{"type": "Ready", "status": "True"}],
            },
        }
        self.assertTrue(
            acceptance.controller_cold_start_ready_bound(
                deployment, [pod], "kustomize-controller", expected_pod_uid="pod-1"
            )
        )
        mutants = []
        stale = copy.deepcopy((deployment, [pod]))
        stale[0]["status"]["observedGeneration"] = 3
        mutants.append(stale)
        multiple = copy.deepcopy((deployment, [pod]))
        multiple[1].append(copy.deepcopy(pod))
        mutants.append(multiple)
        restarted = copy.deepcopy((deployment, [pod]))
        restarted[1][0]["status"]["containerStatuses"][0]["restartCount"] = 1
        mutants.append(restarted)
        not_ready = copy.deepcopy((deployment, [pod]))
        not_ready[1][0]["status"]["containerStatuses"][0]["ready"] = False
        mutants.append(not_ready)
        for mutant_deployment, mutant_pods in mutants:
            self.assertFalse(
                acceptance.controller_cold_start_ready_bound(
                    mutant_deployment, mutant_pods, "kustomize-controller"
                )
            )
        self.assertFalse(
            acceptance.controller_cold_start_ready_bound(
                deployment, [pod], "kustomize-controller", expected_pod_uid="replacement"
            )
        )
        self.assertTrue(
            acceptance.zero_replica_without_pods({"spec": {"replicas": 0}}, [])
        )
        self.assertFalse(
            acceptance.zero_replica_without_pods({"spec": {"replicas": 0}}, [pod])
        )

    def test_docker_absence_requires_an_explicit_not_found_response(self):
        missing = completed(returncode=1, stderr=b"Error: No such image: example")
        daemon_failure = completed(returncode=1, stderr=b"Cannot connect to the Docker daemon")
        self.assertTrue(acceptance.docker_object_absent(missing))
        self.assertFalse(acceptance.docker_object_absent(daemon_failure))

    def test_preexisting_foreign_image_name_fails_before_build(self):
        runner = mock.Mock()
        runner.run.return_value = completed(
            ("docker", "image", "inspect", "example:v1"), stdout=[{}]
        )
        with self.assertRaisesRegex(acceptance.AcceptanceError, "IMAGE_NAME_COLLISION"):
            acceptance.require_docker_image_name_available(runner, "example:v1")
        runner.run.assert_called_once_with(
            ("docker", "image", "inspect", "example:v1"),
            check=False,
            timeout=30,
        )

    def test_kubeconfig_binding_rejects_non_loopback_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kubeconfig"
            path.write_text(
                "apiVersion: v1\n"
                "clusters:\n"
                "- cluster:\n"
                "    server: https://protected.example:6443\n"
                "  name: kind-owned\n"
                "current-context: kind-owned\n",
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(
                acceptance.AcceptanceError, "OWNED_KUBECONFIG_ENDPOINT_INVALID"
            ):
                acceptance.kubeconfig_binding(path, "owned")


class FakeGitRunner:
    def __init__(
        self,
        expected: str,
        branch: str = "5.6-sol/issue-98",
        origin_url: str = acceptance.CANONICAL_ORIGIN_URLS[0],
    ) -> None:
        self.expected = expected
        self.branch = branch
        self.origin_url = origin_url
        self.fixture_path = ".editorconfig"
        fixture = ROOT / self.fixture_path
        payload = fixture.read_bytes()
        self.fixture_mode = (
            "100755" if stat.S_IMODE(fixture.stat().st_mode) & 0o111 else "100644"
        )
        self.fixture_oid = acceptance.git_blob_oid(len(payload), (payload,))
        self.calls = []

    def run(self, arguments, **kwargs):
        key = tuple(arguments)
        self.calls.append((key, kwargs))
        values = {
            ("git", "rev-parse", "--show-toplevel"): str(ROOT),
            (
                "git",
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "info/grafts",
            ): str(ROOT / ".git" / "info" / "grafts-not-present"),
            (
                "git",
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "objects/info/alternates",
            ): str(ROOT / ".git" / "objects" / "info" / "alternates-not-present"),
            (
                "git",
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "objects/info/http-alternates",
            ): str(
                ROOT
                / ".git"
                / "objects"
                / "info"
                / "http-alternates-not-present"
            ),
            ("git", "for-each-ref", "--format=%(refname)", "refs/replace"): "",
            ("git", "rev-parse", "--is-shallow-repository"): "false",
            ("git", "fsck", "--strict", "--full", "--no-reflogs"): "",
            ("git", "rev-parse", "HEAD"): self.expected,
            ("git", "ls-tree", "-r", "-z", self.expected): (
                f"{self.fixture_mode} blob {self.fixture_oid}\t{self.fixture_path}\0"
            ),
            ("git", "ls-files", "--stage", "-v", "-z"): (
                f"H {self.fixture_mode} {self.fixture_oid} 0\t{self.fixture_path}\0"
            ),
            ("git", "symbolic-ref", "--quiet", "--short", "HEAD"): self.branch,
            ("git", "status", "--porcelain=v1", "--untracked-files=all"): "",
            ("git", "rev-parse", "@{upstream}"): self.expected,
            ("git", "config", "--get", f"branch.{self.branch}.remote"): "origin",
            ("git", "remote", "get-url", "--all", "origin"): self.origin_url,
            ("git", "config", "--get", f"branch.{self.branch}.merge"): f"refs/heads/{self.branch}",
            (
                "git",
                "ls-remote",
                "--exit-code",
                self.origin_url,
                f"refs/heads/{self.branch}",
            ): (
                f"{self.expected}\trefs/heads/{self.branch}"
            ),
        }
        if key not in values:
            raise AssertionError(key)
        value = values[key]
        return completed(
            key,
            stdout=value if isinstance(value, bytes) else value.encode("utf-8"),
        )


class PreflightTests(unittest.TestCase):
    def test_git_preflight_binds_clean_exact_pushed_head(self):
        commit = "a" * 40
        runner = FakeGitRunner(commit)
        self.assertEqual(
            acceptance.git_preflight(runner, commit), "5.6-sol/issue-98"
        )
        remote_calls = [
            (command, kwargs)
            for command, kwargs in runner.calls
            if command[:2] == ("git", "ls-remote")
        ]
        self.assertEqual(len(remote_calls), 1)
        remote_cwd = remote_calls[0][1]["cwd"]
        self.assertNotEqual(remote_cwd, ROOT)
        self.assertFalse((remote_cwd / ".git").exists())
        self.assertEqual(
            remote_calls[0][1]["extra_environment"]["GIT_CEILING_DIRECTORIES"],
            str(remote_cwd),
        )

    def test_git_preflight_rejects_dirty_or_unpushed(self):
        commit = "a" * 40
        runner = FakeGitRunner(commit)
        original = runner.run

        def dirty(arguments, **kwargs):
            if tuple(arguments) == ("git", "status", "--porcelain=v1", "--untracked-files=all"):
                return completed(stdout=b"?? residue")
            return original(arguments, **kwargs)

        runner.run = dirty
        with self.assertRaisesRegex(acceptance.AcceptanceError, "WORKTREE_DIRTY"):
            acceptance.git_preflight(runner, commit)

    def test_git_preflight_rejects_a_noncanonical_effective_origin(self):
        commit = "a" * 40
        runner = FakeGitRunner(commit, origin_url="file:///tmp/foreign.git")
        with self.assertRaisesRegex(acceptance.AcceptanceError, "ORIGIN_URL_INVALID"):
            acceptance.git_preflight(runner, commit)

    def test_git_preflight_rejects_an_insteadof_transport_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "repo"
            remote = base / "foreign.git"
            repository.mkdir()

            def git(*arguments: str, cwd: Path = repository) -> str:
                result = subprocess.run(
                    ["git", *arguments],
                    cwd=cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                return result.stdout.decode("utf-8").strip()

            git("init", "--bare", "-q", str(remote), cwd=base)
            git("init", "-q")
            git("config", "user.name", "Synthetic")
            git("config", "user.email", "synthetic" + "@" + "example.invalid")
            (repository / "fixture.txt").write_text("fixture\n", encoding="utf-8")
            git("add", "fixture.txt")
            git("commit", "-qm", "fixture")
            git("branch", "-M", "review")
            canonical = acceptance.CANONICAL_ORIGIN_URLS[0]
            git("remote", "add", "origin", canonical)
            git(
                "config",
                f"url.{remote.resolve().as_uri()}.insteadOf",
                canonical,
            )
            git("push", "-qu", "origin", "review")
            commit = git("rev-parse", "HEAD")

            class RealGitRunner:
                @staticmethod
                def run(arguments, **_kwargs):
                    return subprocess.run(
                        list(arguments),
                        cwd=repository,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )

            with mock.patch.object(acceptance, "ROOT", repository.resolve()):
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError,
                    "ORIGIN_URL_INVALID",
                ):
                    acceptance.git_preflight(RealGitRunner(), commit)

    def test_git_preflight_rejects_assume_unchanged_and_skip_worktree(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                repository, commit = synthetic_git_repository(Path(directory))
                subprocess.run(
                    ["git", "update-index", flag, "fixture.txt"],
                    cwd=repository,
                    check=True,
                )
                (repository / "fixture.txt").write_text(
                    "hidden mutation\n", encoding="utf-8"
                )
                status = subprocess.run(
                    ["git", "status", "--porcelain=v1"],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    check=True,
                )
                self.assertEqual(status.stdout, b"")
                with mock.patch.object(acceptance, "ROOT", repository.resolve()):
                    with self.assertRaisesRegex(
                        acceptance.AcceptanceError, "INDEX_FLAGS_INVALID"
                    ):
                        acceptance.git_preflight(
                            SyntheticPreflightRunner(repository, commit), commit
                        )

    def test_git_preflight_rejects_replacement_refs_before_tree_use(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, commit = synthetic_git_repository(Path(directory))

            def git(*arguments: str) -> str:
                result = subprocess.run(
                    ["git", *arguments],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                return result.stdout.decode("utf-8").strip()

            tree = git("rev-parse", "HEAD^{tree}")
            replacement = subprocess.run(
                ["git", "commit-tree", tree, "-p", commit],
                cwd=repository,
                input=b"replacement\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout.decode("ascii").strip()
            git("replace", commit, replacement)
            with mock.patch.object(acceptance, "ROOT", repository.resolve()):
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "REPLACE_REFS_PRESENT"
                ):
                    acceptance.git_preflight(
                        SyntheticPreflightRunner(repository, commit), commit
                    )

    def test_git_preflight_rejects_alternate_object_stores(self):
        for name in ("alternates", "http-alternates"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                repository, commit = synthetic_git_repository(base)
                alternate = repository / ".git" / "objects" / "info" / name
                alternate.write_text(str(base / "foreign-objects") + "\n")
                with mock.patch.object(acceptance, "ROOT", repository.resolve()):
                    with self.assertRaisesRegex(
                        acceptance.AcceptanceError,
                        "ALTERNATE_OBJECT_STORE_PRESENT",
                    ):
                        acceptance.git_preflight(
                            SyntheticPreflightRunner(repository, commit), commit
                        )

    def test_git_preflight_fsck_rejects_corrupt_loose_object(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, commit = synthetic_git_repository(Path(directory))
            created = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=repository,
                input=b"canonical dangling object\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout.decode("ascii").strip()
            loose = repository / ".git" / "objects" / created[:2] / created[2:]
            malicious = b"different bytes under the old object name\n"
            loose.chmod(0o600)
            loose.write_bytes(
                zlib.compress(
                    f"blob {len(malicious)}\x00".encode("ascii") + malicious
                )
            )
            with mock.patch.object(acceptance, "ROOT", repository.resolve()):
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "GIT_OBJECT_STORE_INVALID"
                ):
                    acceptance.git_preflight(
                        SyntheticPreflightRunner(repository, commit), commit
                    )

    def test_git_preflight_raw_tree_rejects_filter_hidden_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository, commit = synthetic_git_repository(base)

            def git(*arguments: str) -> str:
                result = subprocess.run(
                    ["git", *arguments],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                return result.stdout.decode("utf-8").strip()

            canonical = base / "canonical.txt"
            canonical.write_text("fixture\n", encoding="utf-8")
            clean_filter = base / "clean-filter.sh"
            clean_filter.write_text(
                "#!/bin/sh\nexec /bin/cat -- " + str(canonical) + "\n",
                encoding="utf-8",
            )
            clean_filter.chmod(0o700)
            git("config", "filter.canonical.clean", str(clean_filter))
            git("config", "filter.canonical.required", "true")
            (repository / ".git" / "info" / "attributes").write_text(
                "fixture.txt filter=canonical\n", encoding="utf-8"
            )
            (repository / "fixture.txt").write_text(
                "hidden mutation\n", encoding="utf-8"
            )
            git("add", "fixture.txt")
            self.assertEqual(git("status", "--porcelain=v1"), "")
            with mock.patch.object(acceptance, "ROOT", repository.resolve()):
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "WORKTREE_RAW_MISMATCH"
                ):
                    acceptance.git_preflight(
                        SyntheticPreflightRunner(repository, commit), commit
                    )

    def test_launch_context_rejects_ambient_root_without_private_handoff(self):
        with (
            mock.patch.object(acceptance, "_configured_root", str(ROOT)),
            mock.patch.object(acceptance, "_configured_launch_root", None),
            mock.patch.object(acceptance, "_configured_handoff", None),
        ):
            with self.assertRaisesRegex(
                acceptance.AcceptanceError, "LAUNCH_CONTEXT_INVALID"
            ):
                acceptance.validate_launch_context(mock.Mock(), "a" * 40)

    def test_launch_context_binds_and_consumes_exact_staged_script(self):
        with tempfile.TemporaryDirectory() as directory:
            launch_root = Path(directory).resolve() / "launch"
            launch_root.mkdir(mode=0o700)
            script = launch_root / "flux_rbac_kind_acceptance.py"
            payload = (ROOT / "scripts" / "flux_rbac_kind_acceptance.py").read_bytes()
            script.write_bytes(payload)
            script.chmod(0o600)
            expected_commit = "a" * 40
            expected_oid = acceptance.git_blob_oid(len(payload), (payload,))
            handoff = launch_root / "handoff"
            handoff.write_bytes(
                f"1\n{expected_commit}\n{expected_oid}\n".encode("ascii")
            )
            handoff.chmod(0o600)
            runner = mock.Mock()
            runner.run.return_value = completed(stdout=(expected_oid + "\n").encode())
            with (
                mock.patch.object(acceptance, "_configured_root", str(ROOT)),
                mock.patch.object(
                    acceptance, "_configured_launch_root", str(launch_root)
                ),
                mock.patch.object(acceptance, "_configured_handoff", str(handoff)),
                mock.patch.object(acceptance, "__file__", str(script)),
            ):
                acceptance.validate_launch_context(runner, expected_commit)
            self.assertFalse(handoff.exists())

    def test_make_values_do_not_become_shell_source(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first = base / "first-sentinel"
            second = base / "second-sentinel"
            third = base / "third-sentinel"
            expected_payload = (
                f"$(shell /usr/bin/touch {first})"
                + f'bad"; /usr/bin/touch {first}; printf "'
                + "\n"
                + f'`/usr/bin/touch {first}`'
            )
            receipt_payload = (
                f"$(shell /usr/bin/touch {second})"
                + str(base / "receipt")
                + f'"; /usr/bin/touch {second}; printf "'
                + "\n"
                + f'`/usr/bin/touch {second}`'
            )
            python_payload = f"$(shell /usr/bin/touch {third})/usr/bin/false"
            result = subprocess.run(
                [
                    "make",
                    "flux-rbac-kind-acceptance",
                    f"EXPECTED_COMMIT={expected_payload}",
                    f"FLUX_RBAC_KIND_RECEIPT={receipt_payload}",
                    f"PYTHON={python_payload}",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "TMPDIR": directory},
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(first.exists())
            self.assertFalse(second.exists())
            self.assertFalse(third.exists())

    def test_filter_hidden_worktree_harness_is_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "repo"
            scripts = repository / "scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(ROOT / "Makefile", repository / "Makefile")
            source = ROOT / "scripts" / "flux_rbac_kind_acceptance.py"
            destination = scripts / source.name
            shutil.copy2(source, destination)

            def git(*arguments: str) -> str:
                result = subprocess.run(
                    ["git", *arguments],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                return result.stdout.decode("utf-8").strip()

            git("init", "-q")
            git("config", "user.name", "Synthetic")
            git("config", "user.email", "synthetic" + "@" + "example.invalid")
            git("add", "Makefile", f"scripts/{source.name}")
            git("commit", "-qm", "fixture")
            commit = git("rev-parse", "HEAD")
            canonical = base / "canonical.py"
            canonical.write_bytes(destination.read_bytes())
            clean_filter = base / "clean-filter.sh"
            clean_filter.write_text(
                "#!/bin/sh\nexec /bin/cat -- " + str(canonical) + "\n",
                encoding="utf-8",
            )
            clean_filter.chmod(0o700)
            git("config", "filter.canonical.clean", str(clean_filter))
            git("config", "filter.canonical.required", "true")
            info = repository / ".git" / "info"
            (info / "attributes").write_text(
                f"scripts/{source.name} filter=canonical\n", encoding="utf-8"
            )
            sentinel = base / "executed-sentinel"
            malicious = destination.read_text(encoding="utf-8").replace(
                "from __future__ import annotations\n",
                "from __future__ import annotations\n"
                "from pathlib import Path as _SentinelPath\n"
                f"_SentinelPath({str(sentinel)!r}).touch()\n",
                1,
            )
            destination.write_text(malicious, encoding="utf-8")
            self.assertEqual(
                git("check-attr", "filter", "--", f"scripts/{source.name}"),
                f"scripts/{source.name}: filter: canonical",
            )
            self.assertEqual(
                git(
                    "hash-object",
                    f"--path=scripts/{source.name}",
                    f"scripts/{source.name}",
                ),
                git("rev-parse", f"HEAD:scripts/{source.name}"),
            )
            git("add", f"scripts/{source.name}")
            self.assertEqual(git("status", "--porcelain=v1"), "")
            tmpdir = base / "tmp"
            tmpdir.mkdir()
            result = subprocess.run(
                [
                    "make",
                    "flux-rbac-kind-acceptance",
                    f"EXPECTED_COMMIT={commit}",
                    f"FLUX_RBAC_KIND_RECEIPT={base / 'receipt.json'}",
                    f"PYTHON={sys.executable}",
                ],
                cwd=repository,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "TMPDIR": str(tmpdir)},
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"Worktree harness bytes differ", result.stderr)
            self.assertFalse(sentinel.exists())

    def test_receipt_path_must_be_new_absolute_and_external(self):
        with self.assertRaisesRegex(acceptance.AcceptanceError, "RECEIPT_PATH_NOT_ABSOLUTE"):
            acceptance.validate_receipt_path(Path("receipt.json"))
        with self.assertRaisesRegex(acceptance.AcceptanceError, "RECEIPT_PATH_INVALID"):
            acceptance.validate_receipt_path(ROOT / "receipt.json")

    def test_receipt_path_must_not_collide_with_journal_or_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / "journal.json"
            for candidate in (
                journal,
                journal.with_name(journal.name + ".new"),
            ):
                with self.subTest(candidate=candidate.name):
                    with self.assertRaisesRegex(
                        acceptance.AcceptanceError,
                        "RECEIPT_PATH_INVALID",
                    ):
                        acceptance.validate_receipt_path(
                            candidate,
                            journal_path=journal,
                        )

    def test_sanctioned_launcher_is_isolated_and_ignores_pythonpath(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            '"$${FLUX_RBAC_PYTHON}" -I -B -S "$${harness}"',
            makefile,
        )
        self.assertIn("git --no-replace-objects", makefile)
        self.assertIn("cat-file blob", makefile)
        self.assertIn("hash-object --no-filters", makefile)
        self.assertIn("FLUX_RBAC_ACCEPTANCE_HANDOFF", makefile)
        script = ROOT / "scripts" / "flux_rbac_kind_acceptance.py"
        direct = subprocess.run(
            [sys.executable, str(script), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(direct.returncode, 2)
        self.assertIn(b"INTERPRETER_MODE_INVALID", direct.stderr)
        with tempfile.TemporaryDirectory() as directory:
            ambient = Path(directory)
            sentinel = ambient / "sitecustomize-ran"
            (ambient / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ambient)
            isolated = subprocess.run(
                [sys.executable, "-I", "-B", "-S", str(script), "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
            self.assertEqual(isolated.returncode, 0, isolated.stderr)
            self.assertFalse(sentinel.exists())

    def test_state_home_rejects_checkout_and_symlinked_ancestors(self):
        with mock.patch.dict(
            os.environ, {"XDG_STATE_HOME": str(ROOT / ".acceptance-state")}
        ):
            with self.assertRaisesRegex(acceptance.AcceptanceError, "STATE_HOME_UNSAFE"):
                acceptance.default_journal_path()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "destination"
            destination.mkdir()
            link = root / "state-link"
            link.symlink_to(destination, target_is_directory=True)
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(link)}):
                with self.assertRaisesRegex(acceptance.AcceptanceError, "STATE_HOME_UNSAFE"):
                    acceptance.default_journal_path()

    def test_tool_preflight_checks_pinned_versions_and_binds_external_identities(self):
        pins = acceptance.parse_versions()

        class ToolRunner:
            def run(self, arguments, **_kwargs):
                command = tuple(arguments)
                if command == ("git", "--version"):
                    return completed(command, stdout=b"git version test")
                if command[:2] == ("docker", "version"):
                    return completed(command, stdout=b"28.0.0")
                if command == ("kind", "version"):
                    return completed(command, stdout=("kind " + pins["KIND_VERSION"] + " go1.x").encode())
                if command[:3] == ("kubectl", "version", "--client"):
                    return completed(command, stdout={"clientVersion": {"gitVersion": pins["KUBERNETES_VERSION"]}})
                if command[:2] == ("helm", "version"):
                    return completed(command, stdout=pins["HELM_VERSION"].encode())
                if command == ("go", "version"):
                    return completed(command, stdout=("go version go" + pins["GO_VERSION"].lstrip("v") + " host").encode())
                raise AssertionError(command)

            @staticmethod
            def tool_identity(_name):
                return TEST_TOOL_IDENTITY

            @staticmethod
            def docker_receipt():
                return TEST_DOCKER_CUSTODY.receipt()

        with mock.patch.object(acceptance, "require_isolated_interpreter"):
            observed = acceptance.verify_tools(ToolRunner(), pins)
        self.assertEqual(observed["python"], acceptance.python_version())
        self.assertEqual(observed["kind"], pins["KIND_VERSION"])
        self.assertEqual(observed["kubectl"], pins["KUBERNETES_VERSION"])
        for name in acceptance.TOOL_NAMES:
            self.assertRegex(observed[f"{name}Sha256"], r"\Asha256:[0-9a-f]{64}\Z")
            self.assertEqual(observed[f"{name}Inode"], TEST_TOOL_IDENTITY.inode)

    def test_commit_input_snapshot_ignores_later_mutation_and_detects_held_tamper(self):
        commit = "7" * 40
        pins = acceptance.parse_versions()
        blobs = {
            relative: f"committed:{relative}\n".encode()
            for relative in acceptance.SNAPSHOT_INPUTS
        }
        blobs[acceptance.VERSIONS_RELATIVE] = acceptance.VERSIONS_FILE.read_bytes()

        class SnapshotRunner:
            def run(self, arguments, **_kwargs):
                command = tuple(arguments)
                self.assertion(command)
                relative = command[3].split(":", 1)[1]
                return completed(command, stdout=blobs[relative])

            @staticmethod
            def assertion(command):
                if command[:3] != ("git", "cat-file", "blob"):
                    raise AssertionError(command)
                if not command[3].startswith(commit + ":"):
                    raise AssertionError(command)

            @staticmethod
            def journal_tool_identities():
                return test_tool_documents()

            @staticmethod
            def journal_docker_custody():
                return TEST_DOCKER_CUSTODY.document()

        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "journal.json"
                runner = SnapshotRunner()
                harness = acceptance.AcceptanceHarness(
                    runner,
                    commit,
                    pins,
                    journal_path=journal,
                    receipt_path=Path(parent) / "receipt.json",
                )
                harness.owned = acceptance.allocate_owned(
                    runner, commit, journal, Path(parent) / "receipt.json"
                )
                harness.materialize_commit_inputs()
                relative = f"{acceptance.FIXTURE_RELATIVE}/chart/Chart.yaml"
                held = harness.held_path(relative)
                committed = held.read_bytes()
                blobs[relative] = b"later mutable checkout bytes\n"
                self.assertEqual(harness.held_path(relative).read_bytes(), committed)
                held.write_bytes(b"tampered held bytes\n")
                with self.assertRaisesRegex(acceptance.AcceptanceError, "HELD_INPUT_INVALID"):
                    harness.held_path(relative)


class ReceiptTests(unittest.TestCase):
    def values(self):
        pins = acceptance.parse_versions()
        digest = lambda character: "sha256:" + character * 64
        tools = {
            "python": acceptance.python_version(),
            "git": "git version test",
            "docker": "28.0.0",
            "kind": pins["KIND_VERSION"],
            "kubectl": pins["KUBERNETES_VERSION"],
            "helm": pins["HELM_VERSION"],
            "go": pins["GO_VERSION"],
        }
        for name in acceptance.TOOL_NAMES:
            tools[f"{name}Sha256"] = digest("9")
            tools[f"{name}Device"] = 1
            tools[f"{name}Inode"] = 2
        tools.update(TEST_DOCKER_CUSTODY.receipt())
        inventory = {
            item: digest("1") for item in acceptance.SNAPSHOT_INPUTS
        }
        evidence = {
            "priorOwnedResidueRecovered": False,
            "inputInventorySha256": inventory,
            "stockCrossingsAllowed": len(acceptance.CROSSING_ROWS),
            "finalOwnedAllowed": len(acceptance.OWNED_ROWS),
            "finalCrossingsDenied": len(acceptance.CROSSING_ROWS),
            "generalDenials": len(acceptance.GENERAL_DENIED_ROWS),
            "tenantReadsAllowed": len(acceptance.TENANT_ALLOWED_ROWS),
            "tenantBoundariesDenied": len(acceptance.TENANT_DENIED_ROWS),
            "controllerInitialCreation": {
                "stockInputSha256": inventory[acceptance.STOCK_COMPONENTS_RELATIVE],
                "stockZeroSha256": digest("2"),
                "finalRenderSha256": digest("3"),
                "finalZeroSha256": digest("4"),
                "changedFields": list(acceptance.CONTROLLER_ZERO_CHANGED_FIELDS),
                "bothZeroPodsBeforeStart": True,
                "destructiveWorkloadAction": False,
                "initialCreationOnly": True,
            },
            "kustomizeFinalRbacColdStart": {
                "zeroPodsBeforeStart": True,
                "finalRbacOnly": True,
                "currentGenerationReady": True,
                "singleReadyPod": True,
                "managerRestartCount": 0,
                "helmRemainedZero": True,
                "podUidPreservedAfterHelmRestore": True,
                "destructiveWorkloadAction": False,
                "initialCreationOnly": True,
            },
            "helmSecretColdStart": {
                "negativeCacheSyncDenied": True,
                "positiveKubeletRetryReady": True,
                "readVerbsAllowed": len(acceptance.HELM_SECRET_ROWS),
                "writeDenied": True,
                "samePodRecovered": True,
                "destructiveWorkloadAction": False,
                "initialCreationOnly": True,
            },
            "readinessNegatives": {
                "pods": {
                    "phase": "install",
                    "reason": "InstallFailed",
                    "authorizationMessageBound": True,
                    "workloadHealthy": True,
                },
                "replicasets": {
                    "phase": "upgrade",
                    "reason": "UpgradeFailed",
                    "authorizationMessageBound": True,
                    "currentGenerationFailureObserved": True,
                    "injectedFailureBound": True,
                    "rollbackReason": "RollbackSucceeded",
                    "helmRemediationRollback": "acceptance-only",
                    "priorConfigRestored": True,
                    "workloadHealthy": True,
                },
            },
            "releaseLifecycle": {
                "installReason": "InstallSucceeded",
                "upgradeReason": "UpgradeSucceeded",
                "upgradeUsedCommonMetadata": True,
                "rollbackReason": "RollbackSucceeded",
                "remediateLastFailure": True,
                "rollbackRestoredPriorConfig": True,
                "helmRemediationRollback": "acceptance-only",
                "protectedConvergenceRollbackTested": False,
            },
        }
        return {
            "expected_commit": "a" * 40,
            "result": "PASS",
            "phase": acceptance.State.COMPLETE,
            "primary_error_code": None,
            "cleanup_error_code": None,
            "tools": tools,
            "pins": pins,
            "evidence": evidence,
            "cleanup": {key: True for key in acceptance.PASS_CLEANUP_KEYS},
        }

    def receipt(self, **overrides):
        values = self.values()
        values.update(overrides)
        return acceptance.build_receipt(**values)

    def test_receipt_is_closed_bounded_and_contains_no_runtime_names(self):
        receipt = self.receipt()
        encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        self.assertLess(len(encoded), acceptance.MAX_RECEIPT_BYTES)
        self.assertEqual(receipt["result"], "PASS")
        self.assertEqual(
            receipt["scope"],
            acceptance.SCOPE_RECEIPT,
        )
        self.assertNotIn("destructiveWorkloadAction", receipt["scope"])
        self.assertNotIn("initialCreationOnly", receipt["scope"])
        self.assertEqual(
            receipt["scope"]["evidenceClass"],
            "owner-controlled-local-disposable-acceptance",
        )
        self.assertFalse(receipt["scope"]["stageZeroProvenanceClaimed"])
        self.assertFalse(receipt["scope"]["promotionAuthorized"])
        self.assertEqual(
            receipt["scope"]["acceptanceWorkloadLifecycle"],
            "install-upgrade-fail-rollback",
        )
        self.assertFalse(
            receipt["scope"]["protectedOrForeignWorkloadMutationAuthorized"]
        )
        self.assertNotIn(str(Path.home()), encoded.decode())
        self.assertNotIn("registryAddress", encoded.decode())

    def test_receipt_hashes_private_docker_context_name(self):
        raw_context = "private-pie5-control-plane"
        custody = acceptance.DockerCustody(
            context=raw_context,
            endpoint="unix:///private/tmp/docker.sock",
            daemon_id="private-daemon-id",
        )
        values = self.values()
        values["tools"].update(custody.receipt())
        receipt = acceptance.build_receipt(**values)
        encoded = json.dumps(
            receipt, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertNotIn(raw_context.encode("utf-8"), encoded)
        self.assertNotIn("dockerContext", receipt["tools"])
        self.assertEqual(
            receipt["tools"]["dockerContextSha256"],
            "sha256:" + hashlib.sha256(raw_context.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(custody.document()["context"], raw_context)

    def test_receipt_rejects_forbidden_nested_fields(self):
        with self.assertRaisesRegex(acceptance.AcceptanceError, "RECEIPT_FIELD_FORBIDDEN"):
            self.receipt(
                result="FAIL",
                phase=acceptance.State.NEW,
                primary_error_code="TEST_FAILURE",
                evidence={"secret": "redacted"},
            )

    def test_pass_receipt_rejects_missing_false_and_foreign_fields(self):
        missing = self.values()
        missing["evidence"].pop("helmSecretColdStart")
        with self.assertRaisesRegex(acceptance.AcceptanceError, "RECEIPT_PASS_SCHEMA_INVALID"):
            acceptance.build_receipt(**missing)
        missing_kustomize = self.values()
        missing_kustomize["evidence"].pop("kustomizeFinalRbacColdStart")
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "RECEIPT_PASS_SCHEMA_INVALID"
        ):
            acceptance.build_receipt(**missing_kustomize)
        false_preservation = self.values()
        false_preservation["evidence"]["kustomizeFinalRbacColdStart"][
            "podUidPreservedAfterHelmRestore"
        ] = False
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "RECEIPT_LIFECYCLE_SCHEMA_INVALID"
        ):
            acceptance.build_receipt(**false_preservation)
        foreign_kustomize = self.values()
        foreign_kustomize["evidence"]["kustomizeFinalRbacColdStart"]["podUid"] = "private"
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "RECEIPT_LIFECYCLE_SCHEMA_INVALID"
        ):
            acceptance.build_receipt(**foreign_kustomize)
        false_cleanup = self.values()
        false_cleanup["cleanup"]["clusterAbsent"] = False
        with self.assertRaisesRegex(acceptance.AcceptanceError, "RECEIPT_PASS_SCHEMA_INVALID"):
            acceptance.build_receipt(**false_cleanup)
        foreign = self.values()
        foreign["tools"]["foreign"] = "value"
        with self.assertRaisesRegex(acceptance.AcceptanceError, "RECEIPT_PASS_SCHEMA_INVALID"):
            acceptance.build_receipt(**foreign)

    def test_primary_and_cleanup_failures_are_distinct_receipt_fields(self):
        receipt = self.receipt(
            result="FAIL",
            phase=acceptance.State.RELEASE,
            primary_error_code="ROLLBACK_NOT_OBSERVED",
            cleanup_error_code="CLEANUP_FAILED",
            cleanup={key: False for key in acceptance.PASS_CLEANUP_KEYS},
        )
        self.assertEqual(receipt["primaryErrorCode"], "ROLLBACK_NOT_OBSERVED")
        self.assertEqual(receipt["cleanupErrorCode"], "CLEANUP_FAILED")

    def test_receipt_writer_is_exclusive_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            with mock.patch.object(
                acceptance,
                "fsync_directory",
                wraps=acceptance.fsync_directory,
            ) as parent_fsync:
                observed = acceptance.write_receipt(path, self.receipt())
            self.assertRegex(observed, r"\Asha256:[0-9a-f]{64}\Z")
            self.assertEqual(parent_fsync.call_count, 2)
            self.assertTrue(
                all(call.args == (path.parent,) for call in parent_fsync.call_args_list)
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(acceptance.AcceptanceError, "RECEIPT_WRITE_FAILED"):
                acceptance.write_receipt(path, self.receipt())


class CleanupRunner:
    def __init__(self, owner: str, cluster: str) -> None:
        self.owner = owner
        self.cluster = cluster
        self.image = True
        self.container = True
        self.network = True
        self.kind = True
        self.node_network = True
        self.node_labels = True
        self.kind_inspection_failure = False
        self.calls: list[tuple[str, ...]] = []

    @staticmethod
    def journal_tool_identities():
        return test_tool_documents()

    @staticmethod
    def journal_docker_custody():
        return TEST_DOCKER_CUSTODY.document()

    @staticmethod
    def adopt_journal_tools(_value):
        return None

    @staticmethod
    def adopt_journal_docker(_value):
        return None

    def run(self, arguments, **_kwargs):
        arguments = tuple(arguments)
        self.calls.append(arguments)
        if arguments[:3] == ("docker", "image", "inspect"):
            return completed(arguments, stdout=[{"Config": {"Labels": {acceptance.OWNER_LABEL: self.owner}}}], returncode=0) if self.image else completed(arguments, returncode=1, stderr=b"Error: No such image: workload")
        if arguments[:4] == ("docker", "image", "rm", "--force"):
            self.image = False
            return completed(arguments)
        if arguments[:4] == ("docker", "container", "ls", "--all"):
            node = f"{self.cluster}-control-plane\n" if self.kind else ""
            return completed(arguments, stdout=node.encode())
        if arguments[:3] == ("docker", "container", "inspect"):
            if arguments[3] == f"{self.cluster}-control-plane":
                if not self.kind:
                    return completed(arguments, returncode=1, stderr=b"Error: No such container: kind node")
                labels = {
                    "io.x-k8s.kind.cluster": self.cluster,
                    "io.x-k8s.kind.role": "control-plane",
                } if self.node_labels else {"io.x-k8s.kind.cluster": "foreign"}
                networks = {acceptance.network_name(self.owner): {}} if self.node_network else {"bridge": {}}
                return completed(
                    arguments,
                    stdout=[
                        {
                            "Config": {"Labels": labels},
                            "NetworkSettings": {"Networks": networks},
                        }
                    ],
                )
            return completed(arguments, stdout=[{"Config": {"Labels": {acceptance.OWNER_LABEL: self.owner}}}], returncode=0) if self.container else completed(arguments, returncode=1, stderr=b"Error: No such container: registry")
        if arguments[:4] == ("docker", "container", "rm", "--force"):
            self.container = False
            return completed(arguments)
        if arguments == ("kind", "get", "clusters"):
            if self.kind_inspection_failure:
                return completed(arguments, returncode=1, stderr=b"kind backend unavailable")
            return completed(arguments, stdout=(self.cluster + "\n").encode()) if self.kind else completed(arguments)
        if arguments[:4] == ("kind", "delete", "cluster", "--name"):
            self.kind = False
            return completed(arguments)
        if arguments[:3] == ("docker", "network", "inspect"):
            return completed(arguments, stdout=[{"Labels": {acceptance.OWNER_LABEL: self.owner}}], returncode=0) if self.network else completed(arguments, returncode=1, stderr=b"Error: network acceptance not found")
        if arguments[:3] == ("docker", "network", "rm"):
            self.network = False
            return completed(arguments)
        raise AssertionError(arguments)


class CleanupTests(unittest.TestCase):
    def test_cleanup_is_owned_ordered_idempotent_and_zero_residue(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                placeholder = CleanupRunner("pending", "pending")
                journal = Path(parent) / "state" / "flux-rbac-kind-acceptance.json"
                receipt = Path(parent) / "receipt.json"
                owned = acceptance.allocate_owned(
                    placeholder, "a" * 40, journal, receipt
                )
                runner = CleanupRunner(owned.run_id, owned.cluster)
                owned.runner = runner
                owned.network_created = True
                owned.registry_created = True
                owned.cluster_created = True
                owned.image_created = True
                owned.workload_image = (
                    f"127.0.0.1:50000/acceptance/"
                    f"flux-rbac-workload-{owned.run_id}:v1"
                )
                owned.prepare_for_cleanup()
                observed = owned.cleanup()
                self.assertTrue(all(observed.values()))
                self.assertTrue(all(owned.cleanup().values()))
                self.assertTrue(journal.exists())
                operations = [call[:3] for call in runner.calls]
                self.assertLess(operations.index(("docker", "container", "rm")), operations.index(("kind", "delete", "cluster")))
                self.assertLess(operations.index(("kind", "delete", "cluster")), operations.index(("docker", "network", "rm")))

    def test_restart_recovery_closes_durable_receipt_before_journal_removal(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "flux-rbac-kind-acceptance.json"
                receipt_path = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder, "b" * 40, journal, receipt_path
                )
                self.assertEqual(owned.cluster, acceptance.cluster_name(owned.run_id))
                self.assertEqual(owned.network, acceptance.network_name(owned.run_id))
                self.assertEqual(owned.registry, acceptance.registry_name(owned.run_id))
                runner = CleanupRunner(owned.run_id, owned.cluster)
                owned.runner = runner
                owned.network_created = True
                owned.registry_created = True
                owned.cluster_created = True
                owned.image_created = True
                owned.workload_image = (
                    f"127.0.0.1:50000/acceptance/"
                    f"flux-rbac-workload-{owned.run_id}:v1"
                )
                owned.record()
                owned.prepare_for_cleanup()
                cleanup = owned.cleanup()
                receipt = {"commit": "b" * 40, "cleanup": cleanup}
                digest = acceptance.receipt_digest(receipt)
                owned.bind_receipt(digest, cleanup)
                acceptance.write_receipt(receipt_path, receipt)
                self.assertEqual(
                    acceptance.load_journal_document(journal)["state"], "prepared"
                )
                self.assertTrue(acceptance.recover_previous(runner, journal))
                self.assertFalse(journal.exists())
                self.assertTrue(receipt_path.exists())

    def test_journal_rejects_a_temp_root_outside_the_canonical_temp_parent(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "flux-rbac-kind-acceptance.json"
                receipt = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder, "c" * 40, journal, receipt
                )
                document = json.loads(journal.read_text(encoding="utf-8"))
                document["tempParent"] = "/tmp"
                document["tempRoot"] = "/tmp/flux-rbac-kind-forged"
                document["kubeconfig"] = "/tmp/flux-rbac-kind-forged/kubeconfig"
                journal.write_text(json.dumps(document), encoding="utf-8")
                os.chmod(journal, 0o600)
                with self.assertRaisesRegex(acceptance.AcceptanceError, "JOURNAL_INVALID"):
                    acceptance.load_journal_document(journal)
                # Restore the real journal and prove the owned temporary root
                # remains recoverable after the hostile document is rejected.
                journal.unlink()
                owned.claim_journal()
                runner = CleanupRunner(owned.run_id, owned.cluster)
                runner.image = False
                runner.container = False
                runner.network = False
                runner.kind = False
                owned.runner = runner
                owned.prepare_for_cleanup()
                self.assertTrue(all(owned.cleanup().values()))

    def test_collision_race_never_deletes_a_same_named_foreign_kind_cluster(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "flux-rbac-kind-acceptance.json"
                receipt = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder, "e" * 40, journal, receipt
                )
                runner = CleanupRunner(owned.run_id, owned.cluster)
                runner.image = False
                runner.container = False
                runner.node_network = False
                owned.runner = runner
                owned.network_created = True
                owned.cluster_created = True
                owned.record()
                owned.prepare_for_cleanup()
                with self.assertRaisesRegex(acceptance.AcceptanceError, "CLEANUP_FAILED"):
                    owned.cleanup()
                self.assertTrue(runner.kind)
                self.assertNotIn(
                    ("kind", "delete", "cluster", "--name", owned.cluster),
                    runner.calls,
                )
                self.assertTrue(journal.exists())
                self.assertTrue(owned.temp_root.exists())

    def test_kind_inspection_failure_preserves_recovery_state(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "flux-rbac-kind-acceptance.json"
                receipt = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder, "f" * 40, journal, receipt
                )
                runner = CleanupRunner(owned.run_id, owned.cluster)
                runner.image = False
                runner.container = False
                runner.kind_inspection_failure = True
                owned.runner = runner
                owned.network_created = True
                owned.cluster_created = True
                owned.record()
                owned.prepare_for_cleanup()
                with self.assertRaisesRegex(acceptance.AcceptanceError, "CLEANUP_FAILED"):
                    owned.cleanup()
                self.assertTrue(journal.exists())
                self.assertTrue(owned.temp_root.exists())

    def test_cryptographic_name_collision_loses_journal_claim_before_mutation(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "journal.json"
                receipt = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                with mock.patch("secrets.token_hex", return_value="1" * 32):
                    first = acceptance.allocate_owned(
                        placeholder, "1" * 40, journal, receipt
                    )
                    with self.assertRaisesRegex(
                        acceptance.AcceptanceError, "JOURNAL_CLAIM_FAILED"
                    ):
                        acceptance.allocate_owned(
                            placeholder, "1" * 40, journal, receipt
                        )
                current = acceptance.load_journal_document(journal)
                self.assertEqual(current["owner"], first.run_id)
                self.assertEqual(current["cluster"], acceptance.cluster_name(first.run_id))

    def test_receipt_failure_window_retains_prepared_journal(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "journal.json"
                receipt_path = Path(parent) / "receipt.json"
                runner = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    runner, "8" * 40, journal, receipt_path
                )
                runner = CleanupRunner(owned.run_id, owned.cluster)
                runner.image = False
                runner.container = False
                runner.network = False
                runner.kind = False
                owned.runner = runner
                owned.prepare_for_cleanup()
                cleanup = owned.cleanup()
                receipt = {"commit": "8" * 40, "cleanup": cleanup}
                owned.bind_receipt(acceptance.receipt_digest(receipt), cleanup)
                with mock.patch("os.link", side_effect=OSError("injected crash")):
                    with self.assertRaisesRegex(
                        acceptance.AcceptanceError, "RECEIPT_WRITE_FAILED"
                    ):
                        acceptance.write_receipt(receipt_path, receipt)
                current = acceptance.load_journal_document(journal)
                self.assertEqual(current["state"], "prepared")
                self.assertIsNotNone(current["receiptSha256"])
                self.assertFalse(receipt_path.exists())
                self.assertTrue(acceptance.recover_previous(runner, journal))
                self.assertTrue(receipt_path.exists())
                self.assertFalse(journal.exists())

    def test_recovery_closes_after_a_durable_cleanup_failure_receipt(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "journal.json"
                receipt_path = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder,
                    "7" * 40,
                    journal,
                    receipt_path,
                )
                owned.network_created = True
                owned.registry_created = True
                owned.cluster_created = True
                owned.image_created = True
                owned.workload_image = (
                    f"127.0.0.1:50000/acceptance/"
                    f"flux-rbac-workload-{owned.run_id}:v1"
                )
                owned.record()
                owned.prepare_for_cleanup()
                historical_cleanup = {
                    key: True for key in acceptance.PASS_CLEANUP_KEYS
                }
                historical_cleanup["clusterAbsent"] = False
                receipt = acceptance.build_receipt(
                    expected_commit="7" * 40,
                    result="FAIL",
                    phase=acceptance.State.NEW,
                    primary_error_code="CLEANUP_FAILED",
                    cleanup_error_code="CLEANUP_FAILED",
                    tools={},
                    pins={},
                    evidence={},
                    cleanup=historical_cleanup,
                )
                digest = acceptance.receipt_digest(receipt)
                owned.bind_receipt(digest, historical_cleanup)
                acceptance.write_receipt(receipt_path, receipt)
                original = receipt_path.read_bytes()
                runner = CleanupRunner(owned.run_id, owned.cluster)
                runner.image = False
                runner.container = False
                runner.network = False
                runner.kind = False
                self.assertTrue(acceptance.recover_previous(runner, journal))
                self.assertFalse(journal.exists())
                self.assertFalse(journal.with_name(journal.name + ".new").exists())
                self.assertFalse(owned.temp_root.exists())
                self.assertEqual(receipt_path.read_bytes(), original)
                self.assertEqual(acceptance.receipt_digest(receipt), digest)
                self.assertFalse(acceptance.recover_previous(runner, journal))

    def test_recovery_refuses_a_different_current_python_before_cleanup(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                root = Path(parent)
                journal = root / "state" / "journal.json"
                receipt = root / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder,
                    "5" * 40,
                    journal,
                    receipt,
                )
                foreign_python = root / "foreign-python"
                foreign_python.write_bytes(b"#!/bin/sh\nexit 0\n")
                foreign_python.chmod(0o700)
                document = json.loads(journal.read_text(encoding="utf-8"))
                document["toolIdentities"]["python"] = (
                    acceptance.ToolIdentity.capture(foreign_python).document()
                )
                document["networkCreated"] = True
                document["registryCreated"] = True
                document["clusterCreated"] = True
                journal.write_text(json.dumps(document), encoding="utf-8")
                journal.chmod(0o600)
                runner = acceptance.Runner()
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError,
                    "INTERPRETER_IDENTITY_CHANGED",
                ):
                    acceptance.recover_previous(runner, journal)
                self.assertTrue(journal.exists())
                self.assertTrue(owned.temp_root.exists())

    def test_recovery_tool_identity_mismatch_never_deletes(self):
        class ChangedToolRunner(CleanupRunner):
            @staticmethod
            def adopt_journal_tools(_value):
                raise acceptance.AcceptanceError("TOOL_IDENTITY_CHANGED")

        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "journal.json"
                receipt = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder, "9" * 40, journal, receipt
                )
                owned.network_created = True
                owned.registry_created = True
                owned.cluster_created = True
                owned.record()
                runner = ChangedToolRunner(owned.run_id, owned.cluster)
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "TOOL_IDENTITY_CHANGED"
                ):
                    acceptance.recover_previous(runner, journal)
                self.assertTrue(runner.kind)
                self.assertTrue(runner.network)
                self.assertTrue(runner.container)
                self.assertFalse(
                    any(call[:3] in {("kind", "delete", "cluster"), ("docker", "network", "rm")} for call in runner.calls)
                )

    def test_recovery_docker_custody_mismatch_never_deletes(self):
        class ChangedDockerRunner(CleanupRunner):
            @staticmethod
            def adopt_journal_docker(_value):
                raise acceptance.AcceptanceError("DOCKER_CONTEXT_CHANGED")

        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "journal.json"
                receipt = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder, "4" * 40, journal, receipt
                )
                owned.network_created = True
                owned.registry_created = True
                owned.cluster_created = True
                owned.record()
                runner = ChangedDockerRunner(owned.run_id, owned.cluster)
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "DOCKER_CONTEXT_CHANGED"
                ):
                    acceptance.recover_previous(runner, journal)
                self.assertTrue(runner.kind)
                self.assertTrue(runner.network)
                self.assertTrue(runner.container)
                self.assertFalse(
                    any(
                        call[:3]
                        in {
                            ("kind", "delete", "cluster"),
                            ("docker", "network", "rm"),
                        }
                        for call in runner.calls
                    )
                )

    def test_sigkill_active_journal_recovers_with_durable_failure_receipt(self):
        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "journal.json"
                receipt_path = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder, "6" * 40, journal, receipt_path
                )
                runner = CleanupRunner(owned.run_id, owned.cluster)
                runner.image = False
                runner.container = False
                runner.network = False
                runner.kind = False
                self.assertTrue(acceptance.recover_previous(runner, journal))
                recovered = json.loads(receipt_path.read_text(encoding="utf-8"))
                self.assertEqual(recovered["result"], "FAIL")
                self.assertEqual(
                    recovered["primaryErrorCode"], "RECOVERED_INCOMPLETE_RUN"
                )
                self.assertTrue(all(recovered["cleanup"].values()))
                self.assertFalse(journal.exists())


class HarnessContractTests(unittest.TestCase):
    def harness(self):
        pins = acceptance.parse_versions()
        harness = acceptance.AcceptanceHarness(mock.Mock(), "a" * 40, pins)
        harness.workload_reference = "example.invalid/workload:v1@sha256:" + "1" * 64
        return harness

    def test_release_is_local_oci_and_rollback_is_explicitly_acceptance_only(self):
        harness = self.harness()
        source = harness.source_document("lidersea-com")
        release = harness.release_document("lidersea-com")
        self.assertTrue(source["spec"]["insecure"])
        self.assertEqual(source["spec"]["url"], harness.chart_url)
        remediation = release["spec"]["upgrade"]["remediation"]
        self.assertEqual(
            remediation,
            {"retries": 0, "remediateLastFailure": True, "strategy": "rollback"},
        )
        self.assertEqual(release["spec"]["serviceAccountName"], "helm-reconciler")
        script = (ROOT / "scripts" / "flux_rbac_kind_acceptance.py").read_text()
        self.assertIn('"helmRemediationRollback": "acceptance-only"', script)
        self.assertIn('"protectedConvergenceRollbackTested": False', script)

    def test_readiness_negative_covers_install_and_rbac_induced_upgrade_rollback(self):
        script = (ROOT / "scripts" / "flux_rbac_kind_acceptance.py").read_text()
        self.assertIn("run_install_readiness_negative", script)
        self.assertIn("run_upgrade_readiness_negative", script)
        self.assertIn('"reason": "UpgradeFailed"', script)
        self.assertIn("authorization_failure_bound", script)
        self.assertIn('"rollbackReason": "RollbackSucceeded"', script)

    def test_controller_cold_starts_are_initial_creation_without_destructive_commands(self):
        script = (ROOT / "scripts" / "flux_rbac_kind_acceptance.py").read_text()
        final_rbac = script.split("    def apply_final_rbac", 1)[1].split(
            "    def remove_exact_rule", 1
        )[0]
        kustomize_cold = script.split(
            "    def kustomize_final_rbac_cold_start", 1
        )[1].split("    def helm_secret_cold_start", 1)[0]
        helm_cold = script.split("    def helm_secret_cold_start", 1)[1].split(
            "    @property\n    def chart_url", 1
        )[0]
        self.assertIn(
            'self.wait_controllers(("source-controller",))',
            final_rbac,
        )
        self.assertIn("controller_deployments_zero_replica", final_rbac)
        self.assertNotIn("self.wait_controllers()", final_rbac)
        for forbidden in (
            '"scale", "deployment/helm-controller"',
            '"delete", "pod"',
            '"rollout", "restart"',
            '"exec"',
        ):
            self.assertNotIn(forbidden, kustomize_cold + helm_cold)
        self.assertIn("zero_replica_without_pods", kustomize_cold)
        self.assertIn("BROAD_BINDING_ABSENCE_UNPROVEN", kustomize_cold)
        self.assertIn('"kustomize-controller"', kustomize_cold)
        self.assertIn('"helmRemainedZero": True', kustomize_cold)
        self.assertLess(
            helm_cold.index("zero_replica_without_pods"),
            helm_cold.index("remove_exact_rule"),
        )
        self.assertLess(
            helm_cold.index("remove_exact_rule"),
            helm_cold.index("'{\"spec\":{\"replicas\":1}}'"),
        )
        for cold in (kustomize_cold, helm_cold):
            self.assertIn('"destructiveWorkloadAction": False', cold)
            self.assertIn('"initialCreationOnly": True', cold)
        self.assertIn("KUSTOMIZE_POD_CHANGED_DURING_HELM_RESTORE", helm_cold)

    def test_recovery_precedes_publication_gates_and_kubectl_is_owned_only(self):
        script = (ROOT / "scripts" / "flux_rbac_kind_acceptance.py").read_text()
        run_body = script.split("    def run(self) -> dict[str, object]:", 1)[1].split(
            "    def create_infrastructure", 1
        )[0]
        self.assertLess(run_body.index("recover_previous"), run_body.index("git_preflight"))
        self.assertLess(run_body.index("recover_previous"), run_body.index("verify_tools"))
        kube_body = script.split("    def kube(\n", 1)[1].split("    def kube_json", 1)[0]
        self.assertIn("load_journal_document", kube_body)
        self.assertIn('("kubectl", "--kubeconfig", str(self.owned.kubeconfig)', kube_body)
        parsed = acceptance.parser().parse_args(
            ["--expected-commit", "a" * 40, "--receipt", "/tmp/r"]
        )
        self.assertFalse(hasattr(parsed, "kubeconfig"))

    def test_fixtures_pin_never_pull_and_offer_real_readiness_failure(self):
        chart = (acceptance.FIXTURE_ROOT / "chart" / "templates" / "deployment.yaml").read_text()
        workload = (acceptance.FIXTURE_ROOT / "workload" / "main.go").read_text()
        dockerfile = (acceptance.FIXTURE_ROOT / "workload" / "Dockerfile").read_text()
        self.assertIn("imagePullPolicy: Never", chart)
        self.assertIn("FAIL_STARTUP", chart)
        self.assertIn("readinessProbe:", chart)
        self.assertIn("os.Exit(42)", workload)
        self.assertEqual(dockerfile.splitlines()[0], "FROM scratch")

    def test_make_target_requires_explicit_commit_and_external_receipt(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        target = makefile.split("flux-rbac-kind-acceptance:", 1)[1]
        self.assertIn('test -n "$${FLUX_RBAC_EXPECTED_COMMIT}"', target)
        self.assertIn('test -n "$${FLUX_RBAC_RECEIPT_PATH}"', target)
        self.assertIn('--expected-commit "$${FLUX_RBAC_EXPECTED_COMMIT}"', target)
        self.assertIn('--receipt "$${FLUX_RBAC_RECEIPT_PATH}"', target)
        self.assertIn("unexport EXPECTED_COMMIT FLUX_RBAC_KIND_RECEIPT PYTHON", makefile)
        self.assertIn("$(value EXPECTED_COMMIT)", makefile)
        self.assertIn("GIT_NO_LAZY_FETCH=1", target)
        self.assertIn("fsck --strict --full --no-reflogs", target)
        recipe = target.split("check-tofu:", 1)[0]
        self.assertNotIn('"$(EXPECTED_COMMIT)"', recipe)
        self.assertNotIn('"$(FLUX_RBAC_KIND_RECEIPT)"', recipe)

    def test_top_level_state_machine_runs_every_acceptance_phase_in_order(self):
        pins = acceptance.parse_versions()
        called: list[str] = []

        class OrchestrationHarness(acceptance.AcceptanceHarness):
            def materialize_commit_inputs(self):
                called.append("snapshot")

            def create_infrastructure(self):
                called.append("infrastructure")

            def build_artifacts(self):
                called.append("artifacts")

            def install_stock(self):
                called.append("stock")

            def assert_matrix(self, rows, expected):
                called.append(f"matrix-{len(rows)}-{expected}")

            def assert_review(self, row, expected):
                called.append(f"review-{row.label}-{expected}")

            def apply_final_rbac(self):
                called.append("final")

            def kustomize_final_rbac_cold_start(self):
                called.append("kustomize-cold-start")

            def helm_secret_cold_start(self):
                called.append("helm-cold-start")

            def readiness_negatives(self):
                called.append("readiness-negatives")

            def release_lifecycle(self):
                called.append("release")

        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "state" / "journal.json"
            harness = OrchestrationHarness(
                mock.Mock(),
                "a" * 40,
                pins,
                journal_path=journal,
                receipt_path=Path(directory) / "receipt.json",
            )
            owned = mock.Mock()
            with (
                mock.patch.object(acceptance, "recover_previous", return_value=False),
                mock.patch.object(acceptance, "git_preflight", return_value="branch"),
                mock.patch.object(acceptance, "verify_tools", return_value={"kind": pins["KIND_VERSION"]}),
                mock.patch.object(acceptance, "allocate_owned", return_value=owned),
            ):
                evidence = harness.run()
        self.assertIs(harness.machine.current, acceptance.State.COMPLETE)
        self.assertFalse(evidence["priorOwnedResidueRecovered"])
        self.assertEqual(
            [item for item in called if not item.startswith("matrix-") and not item.startswith("review-")],
            [
                "snapshot", "infrastructure", "artifacts", "stock", "final",
                "kustomize-cold-start", "helm-cold-start",
                "readiness-negatives", "release",
            ],
        )

    def test_authorization_and_mutation_commands_cannot_escape_owned_kubeconfig(self):
        pins = acceptance.parse_versions()

        class KubeRunner(CleanupRunner):
            def run(self, arguments, **kwargs):
                command = tuple(arguments)
                if command and command[0] == "kubectl":
                    self.calls.append(command)
                    if "selfsubjectaccessreviews" in " ".join(command):
                        return completed(command, stdout={"status": {"allowed": True}})
                    if "get" in command and "role" in command:
                        return completed(
                            command,
                            stdout={
                                "rules": [
                                    {
                                        "apiGroups": [""],
                                        "resources": ["pods"],
                                        "verbs": ["get", "list", "watch"],
                                    }
                                ]
                            },
                        )
                    return completed(command, stdout={})
                return super().run(arguments, **kwargs)

        with tempfile.TemporaryDirectory() as parent:
            with mock.patch.dict(os.environ, {"TMPDIR": parent}, clear=False):
                journal = Path(parent) / "state" / "journal.json"
                receipt = Path(parent) / "receipt.json"
                placeholder = CleanupRunner("pending", "pending")
                owned = acceptance.allocate_owned(
                    placeholder, "d" * 40, journal, receipt
                )
                kubeconfig_text = (
                    "apiVersion: v1\n"
                    "clusters:\n"
                    "- cluster:\n"
                    "    server: https://127.0.0.1:6443\n"
                    f"  name: kind-{owned.cluster}\n"
                    f"current-context: kind-{owned.cluster}\n"
                )
                owned.kubeconfig.write_text(kubeconfig_text, encoding="utf-8")
                os.chmod(owned.kubeconfig, 0o600)
                owned.cluster_created = True
                runner = KubeRunner(owned.run_id, owned.cluster)
                owned.runner = runner
                (
                    owned.kubeconfig_sha256,
                    owned.kubeconfig_server,
                ) = acceptance.kubeconfig_binding(owned.kubeconfig, owned.cluster)
                owned.record()
                harness = acceptance.AcceptanceHarness(
                    runner, "d" * 40, pins, journal_path=journal
                )
                harness.owned = owned
                harness.assert_review(acceptance.OWNED_ROWS[0], True)
                harness.remove_exact_rule(
                    "role",
                    "helm-reconciler",
                    namespace="cloudflare-public",
                    group="",
                    resource="pods",
                    verbs=("get", "list", "watch"),
                )
                kubectl_calls = [call for call in runner.calls if call[0] == "kubectl"]
                self.assertTrue(kubectl_calls)
                self.assertTrue(
                    all(call[1:3] == ("--kubeconfig", str(owned.kubeconfig)) for call in kubectl_calls)
                )
                owned.kubeconfig.write_text(
                    kubeconfig_text.replace(
                        "https://127.0.0.1:6443", "https://127.0.0.1:6444"
                    ),
                    encoding="utf-8",
                )
                os.chmod(owned.kubeconfig, 0o600)
                before_rejected_call = len(kubectl_calls)
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "OWNED_KUBECONFIG_INVALID"
                ):
                    harness.assert_review(acceptance.OWNED_ROWS[0], True)
                self.assertEqual(
                    len([call for call in runner.calls if call[0] == "kubectl"]),
                    before_rejected_call,
                )
                runner.image = False
                runner.container = False
                runner.network = False
                runner.kind = False
                owned.prepare_for_cleanup()
                self.assertTrue(all(owned.cleanup().values()))

    def test_workload_health_requires_current_generation_and_exact_ready_replica(self):
        harness = self.harness()
        healthy = {
            "metadata": {"generation": 3},
            "status": {
                "observedGeneration": 3,
                "availableReplicas": 1,
                "readyReplicas": 1,
            },
        }
        harness.kube_json = mock.Mock(return_value=healthy)
        self.assertTrue(harness.workload_healthy("naranjo-online"))
        stale = json.loads(json.dumps(healthy))
        stale["status"]["observedGeneration"] = 2
        harness.kube_json.return_value = stale
        self.assertFalse(harness.workload_healthy("naranjo-online"))
        unavailable = json.loads(json.dumps(healthy))
        unavailable["status"]["readyReplicas"] = 0
        harness.kube_json.return_value = unavailable
        self.assertFalse(harness.workload_healthy("naranjo-online"))


if __name__ == "__main__":
    unittest.main()
