"""Fail-closed unit tests for the protected Flux RBAC transaction.

These tests deliberately avoid root, a kubeconfig, Kubernetes, GitHub, and the
network.  They exercise the transaction's closed inventory and the recovery
decisions which must remain safe after a process loses a mutation response.
"""

from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import inspect
import json
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TEST_TEMP_ROOT = Path(tempfile.gettempdir()).resolve()
if TEST_TEMP_ROOT == ROOT or ROOT in TEST_TEMP_ROOT.parents:
    raise RuntimeError("test temporary root must remain outside the checkout")
TRANSACTION_PATH = ROOT / "bootstrap/flux/rbac-convergence/transaction.py"
DESIRED_PATH = ROOT / "bootstrap/flux/rbac-convergence/desired-active.json"
SOURCE_MANIFEST_PATH = ROOT / "bootstrap/flux/rbac-convergence/source-manifest.v1"
RUNBOOK_PATH = ROOT / "docs/runbooks/flux-rbac-narrowing.md"


def _load_transaction():
    name = "flux_rbac_convergence_transaction_under_test"
    spec = importlib.util.spec_from_file_location(name, TRANSACTION_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("transaction module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


transaction = _load_transaction()

def _synthetic_uid(digit):
    return "{}-{}-4{}-8{}-{}".format(
        digit * 8, digit * 4, digit * 3, digit * 3, digit * 12
    )


UID_ONE = _synthetic_uid("1")
UID_TWO = _synthetic_uid("2")
UID_THREE = _synthetic_uid("3")
UID_FOUR = _synthetic_uid("4")


def _oracle_discovery(*, verb="get"):
    return {
        "state": "RESOLVED",
        "groupVersion": "v1",
        "resource": "pods",
        "kind": "Pod",
        "namespaced": True,
        "crdName": None,
        "verb": verb,
        "verbEvidence": "DISCOVERY",
    }


def _oracle_receipt(index=0, *, authorization="ALLOWED"):
    return {
        "request": {
            "subject": "system:serviceaccount:flux-system:source-controller",
            "verb": "get",
            "apiGroup": "",
            "resource": "pods",
            "subresource": None,
            "namespace": "flux-system",
            "name": f"proof-{index}",
            "allNamespaces": False,
        },
        "discovery": _oracle_discovery(),
        "authorization": authorization,
        "expected": authorization,
        "controls": [
            {
                "name": "builtin-authorizer",
                "discovery": _oracle_discovery(verb="create"),
                "authorization": "ALLOWED",
            },
            {
                "name": "flux-authorizer",
                "discovery": _oracle_discovery(verb="list"),
                "authorization": "ALLOWED",
            },
            {
                "name": "inert-denial",
                "discovery": _oracle_discovery(),
                "authorization": "DENIED",
            },
        ],
        "result": "PASS",
    }


def _role(*, rules, uid=None, resource_version=None, marker=None):
    metadata = {"name": "example", "namespace": "flux-system"}
    if uid is not None:
        metadata["uid"] = uid
    if resource_version is not None:
        metadata["resourceVersion"] = resource_version
    if marker is not None:
        metadata["annotations"] = {
            transaction.TRANSACTION_ANNOTATION: marker,
        }
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": metadata,
        "rules": copy.deepcopy(rules),
    }


def _cluster_role_binding(
    name,
    *,
    role_name=None,
    subject_names=("system:authenticated",),
    uid=UID_ONE,
    resource_version="7",
    marker=None,
):
    metadata = {
        "name": name,
        "uid": uid,
        "resourceVersion": resource_version,
    }
    if marker is not None:
        metadata["annotations"] = {transaction.TRANSACTION_ANNOTATION: marker}
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": metadata,
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": role_name or name,
        },
        "subjects": [
            {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Group",
                "name": subject,
            }
            for subject in subject_names
        ],
    }


class _Journal:
    def __init__(self, attempt_id, operation_id, state, **record):
        self.document = {
            "attemptId": attempt_id,
            "operations": {operation_id: {"state": state, **record}},
            "sequence": 7,
            "state": "applying",
            "closedAt": "2026-08-22T12:00:00Z",
        }

    def write(self):
        self.document["sequence"] += 1


class _FakeClient:
    def __init__(self, live=None, *, post_uid=UID_TWO):
        self.live = copy.deepcopy(live)
        self.post_uid = post_uid
        self.calls = []

    def get_optional(self, url):
        self.calls.append(("get_optional", url))
        return copy.deepcopy(self.live)

    def get(self, url):
        self.calls.append(("get", url))
        return copy.deepcopy(self.live)

    def delete(self, url, uid, resource_version):
        self.calls.append(("delete", url, uid, resource_version))
        self.live = None
        return {"kind": "Status", "apiVersion": "v1", "metadata": {}}

    def put(self, url, body):
        self.calls.append(("put", url, copy.deepcopy(body)))
        result = copy.deepcopy(body)
        result["metadata"]["resourceVersion"] = str(
            int(result["metadata"]["resourceVersion"]) + 1
        )
        self.live = result
        return copy.deepcopy(result)

    def post(self, collection, body):
        self.calls.append(("post", collection, copy.deepcopy(body)))
        result = copy.deepcopy(body)
        result["metadata"]["uid"] = self.post_uid
        result["metadata"]["resourceVersion"] = "1"
        self.live = result
        return copy.deepcopy(result)

    def post_fence(self, collection, body):
        return self.post(collection, body)

    def put_fence(self, url, body):
        return self.put(url, body)


class _ExternalDeleteClient(_FakeClient):
    def delete(self, url, uid, resource_version):
        self.calls.append(("delete", url, uid, resource_version))
        self.live = None
        raise transaction.TransactionError("injected external deletion")


class _SequenceClient(_FakeClient):
    def __init__(self, sequence, *, post_uid=UID_TWO):
        super().__init__(None, post_uid=post_uid)
        self.sequence = [copy.deepcopy(item) for item in sequence]

    def get_optional(self, url):
        self.calls.append(("get_optional", url))
        if self.sequence:
            value = self.sequence.pop(0)
            self.live = copy.deepcopy(value)
        return copy.deepcopy(self.live)

class ManifestParsingTests(unittest.TestCase):
    def test_canonical_manifest_is_accepted(self):
        first = "1" * 64
        second = "a" * 64
        payload = (
            "# reviewed source bundle\n"
            f"{first} 0700 bootstrap/flux/rbac-convergence/transaction.py\n"
            "\n"
            f"{second} 0600 versions.env\n"
        ).encode("ascii")
        self.assertEqual(
            transaction.parse_source_manifest(payload),
            {
                "bootstrap/flux/rbac-convergence/transaction.py": (first, 0o700),
                "versions.env": (second, 0o600),
            },
        )

    def test_duplicate_traversal_absolute_digest_and_mode_fail_closed(self):
        digest = "a" * 64
        invalid = {
            "duplicate": f"{digest} 0600 versions.env\n{digest} 0600 versions.env\n",
            "parent traversal": f"{digest} 0600 ../versions.env\n",
            "absolute": f"{digest} 0600 /etc/passwd\n",
            "bad digest": "A" * 64 + " 0600 versions.env\n",
            "bad mode": f"{digest} 0644 versions.env\n",
        }
        for label, payload in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(transaction.TransactionError):
                    transaction.parse_source_manifest(payload.encode("ascii"))

    def test_noncanonical_field_separators_fail_before_staging(self):
        digest = "a" * 64
        for separator in ("  ", "\t"):
            with self.subTest(separator=repr(separator)):
                payload = f"{digest}{separator}0600 versions.env\n".encode("ascii")
                with self.assertRaises(transaction.TransactionError):
                    transaction.parse_source_manifest(payload)

    def test_custodied_module_loader_supports_dataclass_modules(self):
        payload = (
            b"from dataclasses import dataclass\n"
            b"@dataclass(frozen=True)\n"
            b"class Receipt:\n"
            b"    value: str\n"
        )
        name = "custodied_dataclass_test_module"
        sys.modules.pop(name, None)
        self.addCleanup(sys.modules.pop, name, None)
        with mock.patch.object(transaction, "read_regular", return_value=payload):
            loaded = transaction.load_module(Path("/custody/module.py"), name)
        self.assertEqual(loaded.Receipt("bound").value, "bound")
        self.assertIs(sys.modules.get(name), loaded)

    def test_help_lists_custody_stage_as_a_reviewed_mode(self):
        self.assertIn("--stage", transaction.parser().format_help())


class PrivilegedProcessBoundaryTests(unittest.TestCase):
    @staticmethod
    def environment(mode):
        return {
            key: (
                "C"
                if key == "LC_ALL"
                else "/reviewed/source"
                if key == "FLUX_RBAC_SOURCE_ROOT"
                else "reviewed"
            )
            for key in transaction.MODE_ENVIRONMENT[mode]
        }

    @staticmethod
    def flags(**overrides):
        values = {
            "isolated": 1,
            "ignore_environment": 1,
            "no_user_site": 1,
            "dont_write_bytecode": 1,
        }
        values.update(overrides)
        return mock.Mock(**values)

    def invoke(
        self,
        mode,
        environment=None,
        *,
        flags=None,
        executable=None,
        argv0=None,
        euid=0,
        version_info=(3, 9, 0),
    ):
        environment = self.environment(mode) if environment is None else environment
        with mock.patch.dict(transaction.os.environ, environment, clear=True), mock.patch.object(
            transaction.os, "geteuid", return_value=euid
        ), mock.patch.object(
            transaction.sys,
            "argv",
            [argv0 or str(transaction.INSTALLED_LAUNCHER), mode],
        ), mock.patch.object(
            transaction.sys,
            "executable",
            executable or str(transaction.PYTHON_PATH),
        ), mock.patch.object(
            transaction.sys, "version_info", version_info
        ), mock.patch.object(
            transaction.sys, "flags", flags or self.flags()
        ):
            transaction.validate_process_boundary(mode)

    def test_each_mode_accepts_only_its_closed_environment(self):
        for mode in transaction.MODE_ENVIRONMENT:
            with self.subTest(mode=mode):
                self.invoke(mode)

    def test_ambient_python_proxy_tls_path_and_home_are_rejected(self):
        for mode in transaction.MODE_ENVIRONMENT:
            for extra in (
                "PATH",
                "HOME",
                "PYTHONPATH",
                "HTTPS_PROXY",
                "SSL_CERT_FILE",
                "BASH_ENV",
                "LD_PRELOAD",
            ):
                with self.subTest(mode=mode, extra=extra):
                    environment = self.environment(mode)
                    environment[extra] = "unreviewed"
                    with self.assertRaisesRegex(
                        transaction.TransactionError,
                        "PROCESS_ENVIRONMENT_INVALID",
                    ):
                        self.invoke(mode, environment)

    def test_wrong_privilege_launcher_interpreter_or_python_flags_fail(self):
        cases = (
            {"euid": 1000},
            {"version_info": (3, 8, 18)},
            {"argv0": "/tmp/alternate-launcher"},
            {"executable": "/usr/local/bin/python3"},
            {"flags": self.flags(isolated=0)},
            {"flags": self.flags(ignore_environment=0)},
            {"flags": self.flags(no_user_site=0)},
            {"flags": self.flags(dont_write_bytecode=0)},
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaisesRegex(
                    transaction.TransactionError, "PROCESS_BOUNDARY_INVALID"
                ):
                    self.invoke("--plan", **case)

    def test_installed_launcher_shebang_binds_isolated_fixed_python(self):
        self.assertEqual(
            TRANSACTION_PATH.read_bytes().splitlines()[0],
            b"#!/usr/bin/python3 -IB",
        )

    def test_source_manifest_is_exact_and_fresh(self):
        expected_modes = {
            "bootstrap/flux/rbac-convergence/desired-active.json": 0o600,
            "bootstrap/flux/rbac-convergence/recovery.py": 0o600,
            "bootstrap/flux/rbac-convergence/transaction.py": 0o700,
            "changelog.d/141-flux-rbac-v037-service-proof.md": 0o600,
            "scripts/ci/platform_release_contract.py": 0o600,
            "scripts/flux_rbac_denial_oracle.py": 0o600,
            "scripts/validate_kubeconfig_snapshot.py": 0o600,
            "versions.env": 0o600,
        }
        entries = transaction.parse_source_manifest(
            SOURCE_MANIFEST_PATH.read_bytes()
        )
        self.assertEqual(
            {path: mode for path, (_digest, mode) in entries.items()},
            expected_modes,
        )
        for relative, (digest, _mode) in entries.items():
            self.assertEqual(
                digest,
                transaction.sha256_bytes((ROOT / relative).read_bytes()),
                relative,
            )
        launcher_digest = entries[
            "bootstrap/flux/rbac-convergence/transaction.py"
        ][0]
        transaction.validate_source_manifest_bundle(entries, launcher_digest)

    def test_v037_uses_fresh_versioned_state_root(self):
        expected = Path(
            "/var/lib/website-infrastructure/flux-rbac-convergence-v0.1.37"
        )
        self.assertEqual(transaction.STATE_ROOT, expected)
        self.assertEqual(transaction.STATE_PARENT, expected.parent)
        self.assertEqual(transaction.CUSTODY_ROOT.parent, expected)
        self.assertEqual(transaction.INPUT_ROOT.parent, expected)
        self.assertEqual(transaction.PLAN_PATH.parent, expected)
        self.assertEqual(transaction.JOURNAL_PATH.parent, expected)
        self.assertEqual(transaction.RECEIPT_ROOT.parent, expected)
        self.assertEqual(transaction.EVIDENCE_ROOT.parent, expected)
        self.assertEqual(transaction.LOCK_PATH.parent, expected)


class HeldSourceDescriptorTests(unittest.TestCase):
    def test_held_root_descriptor_survives_source_path_replacement(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            base = Path(temporary)
            source = base / "source"
            (source / "nested").mkdir(parents=True)
            (source / "nested/reviewed.txt").write_bytes(b"reviewed\n")
            descriptor = transaction.open_directory_no_symlinks(source)
            try:
                source.rename(base / "renamed-reviewed-source")
                (source / "nested").mkdir(parents=True)
                (source / "nested/reviewed.txt").write_bytes(b"replacement\n")
                self.assertEqual(
                    transaction.read_relative_regular(
                        descriptor, "nested/reviewed.txt", maximum=1024
                    ),
                    b"reviewed\n",
                )
            finally:
                transaction.os.close(descriptor)

    def test_root_intermediate_and_final_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            base = Path(temporary)
            source = base / "source"
            (source / "real").mkdir(parents=True)
            (source / "real/file").write_bytes(b"reviewed\n")
            (source / "linked-directory").symlink_to(source / "real")
            (source / "linked-file").symlink_to(source / "real/file")
            root_link = base / "source-link"
            root_link.symlink_to(source)
            with self.assertRaises(transaction.TransactionError):
                transaction.open_directory_no_symlinks(root_link)
            descriptor = transaction.open_directory_no_symlinks(source)
            try:
                for relative in ("linked-directory/file", "linked-file"):
                    with self.subTest(relative=relative):
                        with self.assertRaises(transaction.TransactionError):
                            transaction.read_relative_regular(
                                descriptor, relative, maximum=1024
                            )
            finally:
                transaction.os.close(descriptor)

    def test_existing_custody_receipt_recovery_never_reopens_source_path(self):
        source_revision = "b" * 40
        launcher_payload = b"reviewed launcher"
        python_payload = b"reviewed python"
        manifest_payload = b"reviewed manifest"
        manifest_sha256 = transaction.sha256_bytes(manifest_payload)
        launcher_sha256 = transaction.sha256_bytes(launcher_payload)
        python_sha256 = transaction.sha256_bytes(python_payload)
        environment = {
            "FLUX_RBAC_SOURCE_ROOT": "/untrusted/replaced/source",
            "FLUX_RBAC_SOURCE_REVISION": source_revision,
            "FLUX_RBAC_MANIFEST_SHA256": manifest_sha256,
            "FLUX_RBAC_LAUNCHER_SHA256": launcher_sha256,
            "FLUX_RBAC_PYTHON_SHA256": python_sha256,
            "CONFIRM_FLUX_RBAC_CUSTODY": (
                f"stage-reviewed-flux-rbac-{source_revision}-{manifest_sha256}"
            ),
        }
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            root = Path(temporary)
            custody = root / "custody"
            custody.mkdir()
            receipt_path = root / "custody.receipt.json"
            launcher_path = root / "launcher"
            python_path = root / "python"

            def payload(path, **_kwargs):
                if path == launcher_path:
                    return launcher_payload
                if path == python_path.resolve():
                    return python_payload
                if path == custody / transaction.SOURCE_MANIFEST_REL:
                    return manifest_payload
                raise AssertionError(f"unexpected read: {path}")

            stdin = mock.Mock()
            stdin.isatty.return_value = True
            receipt = {
                "sourceRevision": source_revision,
                "manifestSha256": manifest_sha256,
            }
            pending_receipt = receipt_path.with_name(receipt_path.name + ".new")
            pending_receipt.write_bytes(transaction.canonical_json(receipt))
            pending_receipt.chmod(0o600)
            transaction.os.link(pending_receipt, receipt_path)
            with mock.patch.dict(
                transaction.os.environ, environment, clear=True
            ), mock.patch.object(
                transaction.sys, "stdin", stdin
            ), mock.patch.object(
                transaction, "CUSTODY_ROOT", custody
            ), mock.patch.object(
                transaction, "CUSTODY_RECEIPT", receipt_path
            ), mock.patch.object(
                transaction, "INSTALLED_LAUNCHER", launcher_path
            ), mock.patch.object(
                transaction, "PYTHON_PATH", python_path
            ), mock.patch.object(
                transaction, "read_regular", side_effect=payload
            ), mock.patch.object(
                transaction, "ensure_state_root"
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(
                transaction, "acquire_lock", return_value=19
            ), mock.patch.object(
                transaction.os, "close"
            ), mock.patch.object(
                transaction, "parse_source_manifest", return_value={}
            ), mock.patch.object(
                transaction, "validate_source_manifest_bundle"
            ), mock.patch.object(
                transaction, "expected_custody_receipt", return_value=receipt
            ), mock.patch.object(
                transaction, "validate_custody"
            ), mock.patch.object(
                transaction, "load_custody_receipt", return_value=receipt
            ), mock.patch.object(
                transaction, "open_directory_no_symlinks"
            ) as open_source:
                transaction.stage_custody()
            open_source.assert_not_called()
            self.assertFalse(pending_receipt.exists())
            self.assertEqual(receipt_path.stat().st_nlink, 1)


class KubeClientCustodyCleanupTests(unittest.TestCase):
    def target(self):
        return transaction.Target(
            release_tag=transaction.AUTHORIZED_RELEASE_TAG,
            kubectl=Path("/reviewed/kubectl"),
            kubeconfig=Path("/reviewed/kubeconfig"),
            context="reviewed-context",
            server="https://api.example.invalid",
            ca_sha256="a" * 64,
            kube_system_uid_sha256="b" * 64,
            node_identity_sha256="c" * 64,
        )

    def test_second_bound_file_failure_closes_first(self):
        first = mock.Mock()
        oracle = mock.Mock()
        oracle.BoundFile.side_effect = [first, RuntimeError("injected")]
        versions = {
            "KUBECTL_LINUX_AMD64_SHA256": "d" * 64,
            "KUBECTL_ARM64_SHA256": "e" * 64,
        }
        with mock.patch.object(
            transaction.os, "uname", return_value=mock.Mock(machine="x86_64")
        ), self.assertRaisesRegex(
            transaction.TransactionError, "KUBECTL_CUSTODY_FAILED"
        ):
            transaction.KubeClient(self.target(), versions, oracle)
        first.close.assert_called_once_with()

    def test_partial_cleanup_failure_is_fail_closed(self):
        first = mock.Mock()
        first.close.side_effect = OSError("injected cleanup failure")
        oracle = mock.Mock()
        oracle.BoundFile.side_effect = [first, RuntimeError("injected bind failure")]
        versions = {
            "KUBECTL_LINUX_AMD64_SHA256": "d" * 64,
            "KUBECTL_ARM64_SHA256": "e" * 64,
        }
        with mock.patch.object(
            transaction.os, "uname", return_value=mock.Mock(machine="x86_64")
        ), self.assertRaisesRegex(
            transaction.TransactionError, "KUBECTL_CUSTODY_CLEANUP_FAILED"
        ):
            transaction.KubeClient(self.target(), versions, oracle)
        first.close.assert_called_once_with()


class HelmChainContractTests(unittest.TestCase):
    UPSTREAM = "sha256:" + "a" * 64
    STORED = "sha256:" + "b" * 64

    @staticmethod
    def source(namespace, name, version, uid, resource_version):
        generation = 3
        return {
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "OCIRepository",
            "metadata": {
                "name": name + "-chart",
                "namespace": namespace,
                "uid": uid,
                "resourceVersion": resource_version,
                "generation": generation,
            },
            "spec": transaction.expected_site_oci_spec(namespace, name),
            "status": {
                "observedGeneration": generation,
                "artifact": {
                    "revision": version + "@" + HelmChainContractTests.UPSTREAM,
                    "digest": HelmChainContractTests.STORED,
                },
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "Succeeded",
                        "observedGeneration": generation,
                    },
                    {
                        "type": "SourceVerified",
                        "status": "True",
                        "reason": "Succeeded",
                        "observedGeneration": generation,
                    },
                ],
            },
        }

    @staticmethod
    def release(namespace, name, version, uid, resource_version):
        generation = 5
        attempted = version + "+" + "a" * 12
        return {
            "apiVersion": "helm.toolkit.fluxcd.io/v2",
            "kind": "HelmRelease",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "uid": uid,
                "resourceVersion": resource_version,
                "generation": generation,
            },
            "spec": {
                "chartRef": {"kind": "OCIRepository", "name": name + "-chart"},
                "interval": "10m0s",
                "releaseName": name,
                "serviceAccountName": "helm-reconciler",
                "suspend": False,
                "values": {"deploymentReady": True},
            },
            "status": {
                "observedGeneration": generation,
                "lastAttemptedGeneration": generation,
                "lastAttemptedRevision": attempted,
                "lastAttemptedRevisionDigest": HelmChainContractTests.UPSTREAM,
                "lastAttemptedReleaseAction": "upgrade",
                "storageNamespace": namespace,
                "inventory": {
                    "entries": [
                        {"id": f"{namespace}_{name}_apps_Deployment", "v": "v1"},
                        {"id": f"{namespace}_{name}__Service", "v": "v1"},
                        {"id": f"{namespace}_{name}__ServiceAccount", "v": "v1"},
                        {
                            "id": f"{namespace}_{name}_networking.k8s.io_NetworkPolicy",
                            "v": "v1",
                        },
                    ]
                },
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "UpgradeSucceeded",
                        "observedGeneration": generation,
                    }
                ],
                "history": [
                    {
                        "action": "upgrade",
                        "chartName": name,
                        "chartVersion": attempted,
                        "configDigest": "sha256:" + "c" * 64,
                        "digest": "sha256:" + "d" * 64,
                        "name": name,
                        "namespace": namespace,
                        "ociDigest": HelmChainContractTests.UPSTREAM,
                        "status": "deployed",
                        "version": 7,
                    }
                ],
            },
        }

    def valid_release(self):
        return self.release("naranjo-online", "naranjo-online", "0.1.30", UID_THREE, "13")

    def validate(self, release):
        return transaction.validate_site_helm_release(
            release,
            "naranjo-online",
            "naranjo-online",
            "0.1.30",
            self.UPSTREAM,
        )

    def flux_snapshot_for_versions(
        self, naranjo_version, lidersea_version, source_mutation=None
    ):
        paths = {path: [] for path in transaction.FLUX_CRD_COLLECTIONS.values()}
        paths[transaction.FLUX_CRD_COLLECTIONS["OCIRepository"]] = [
            self.source(
                "naranjo-online",
                "naranjo-online",
                naranjo_version,
                UID_ONE,
                "11",
            ),
            self.source(
                "lidersea-com", "lidersea-com", lidersea_version, UID_TWO, "12"
            ),
        ]
        paths[transaction.FLUX_CRD_COLLECTIONS["HelmRelease"]] = [
            self.release(
                "naranjo-online",
                "naranjo-online",
                naranjo_version,
                UID_THREE,
                "13",
            ),
            self.release(
                "lidersea-com", "lidersea-com", lidersea_version, UID_FOUR, "14"
            ),
        ]
        if source_mutation is not None:
            source_mutation(
                paths[transaction.FLUX_CRD_COLLECTIONS["OCIRepository"]][0]
            )

        class Client:
            def get(self, path):
                return {"items": copy.deepcopy(paths[path])}

        return transaction.flux_snapshot(Client())

    def test_runbook_binds_dynamic_site_chart_identity_to_immutable_plan(self):
        runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
        procedure_marker = "## Procedure"
        step_marker = "1. **Freeze the live prestate without Secret data.**"
        next_step_marker = "2. **Close the mutation inventory.**"
        self.assertEqual(runbook.count(procedure_marker), 1)
        procedure = runbook.split(procedure_marker, 1)[1]
        self.assertEqual(procedure.count(step_marker), 1)
        self.assertEqual(procedure.count(next_step_marker), 1)
        step_one = procedure.split(step_marker, 1)[1].split(next_step_marker, 1)[0]
        contract = " ".join(step_one.split())

        for required in (
            "`naranjo-online/naranjo-online-chart` to "
            "`naranjo-online/naranjo-online`",
            "`lidersea-com/lidersea-com-chart` to `lidersea-com/lidersea-com`",
            "derive `chartVersion` only during `--plan` from the exact current "
            "Cosign-verified OCI artifact `revision`",
            "canonical stable release SemVer inside the exact "
            "`>=0.1.9 <1.0.0` source range",
            "its nonzero upstream `sha256:` `upstreamDigest`",
            "`attemptedRevision=<chartVersion>+<first-12-upstreamDigest-hex>`",
            "`attemptedRevisionDigest=<upstreamDigest>`",
            "`historyChartVersion=<attemptedRevision>`",
            "`historyOciDigest` either absent or exactly `<upstreamDigest>`",
            "must remain exactly equal to its recorded immutable plan baseline",
            "A later chart version, even when canonical, stable, and in range, "
            "is drift; do not recapture or replan it into this transaction.",
        ):
            with self.subTest(required=required):
                self.assertIn(required, contract)
        for former_fixed_version in ("`0.1.30`", "`0.1.26`"):
            with self.subTest(former_fixed_version=former_fixed_version):
                self.assertNotIn(former_fixed_version, contract)

    def test_dynamic_source_identity_requires_current_successful_verification(self):
        for label, field, value in (
            ("missing", None, None),
            ("false", "status", "False"),
            ("stale generation", "observedGeneration", 2),
            ("wrong reason", "reason", "VerificationFailed"),
        ):
            def mutate(source):
                conditions = source["status"]["conditions"]
                verified = next(
                    condition
                    for condition in conditions
                    if condition.get("type") == "SourceVerified"
                )
                if field is None:
                    conditions.remove(verified)
                else:
                    verified[field] = value

            with self.subTest(label=label), self.assertRaisesRegex(
                transaction.TransactionError, "OCI_REVISION_INVALID"
            ):
                self.flux_snapshot_for_versions("0.1.32", "0.1.29", mutate)

    def test_source_revision_derives_only_canonical_in_range_release_versions(self):
        self.assertEqual(
            transaction.expected_site_oci_spec(
                "naranjo-online", "naranjo-online"
            )["ref"],
            {"semver": ">=0.1.9 <1.0.0"},
        )
        for revision, expected in (
            ("0.1.9@" + self.UPSTREAM, "0.1.9"),
            ("v0.1.32@" + self.UPSTREAM, "0.1.32"),
            ("0.99.0@" + self.UPSTREAM, "0.99.0"),
        ):
            with self.subTest(revision=revision):
                version, digest = transaction.parse_site_oci_revision(revision)
                self.assertEqual(version, expected)
                self.assertEqual(digest, self.UPSTREAM)

        for version in (
            "0.1.8",
            "1.0.0",
            "0.01.32",
            "0.1.32-rc.1",
            "0.1.32+build.1",
        ):
            with self.subTest(version=version), self.assertRaisesRegex(
                transaction.TransactionError, "OCI_REVISION_INVALID"
            ):
                transaction.parse_site_oci_revision(version + "@" + self.UPSTREAM)

    def test_flux_snapshot_accepts_and_records_current_in_range_site_versions(self):
        snapshot = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        self.assertEqual(
            snapshot["oci"]["naranjo-online/naranjo-online-chart"]["chartVersion"],
            "0.1.32",
        )
        self.assertEqual(
            snapshot["oci"]["lidersea-com/lidersea-com-chart"]["chartVersion"],
            "0.1.29",
        )
        self.assertEqual(
            snapshot["helm"]["naranjo-online/naranjo-online"][
                "attemptedRevision"
            ],
            "0.1.32+" + "a" * 12,
        )

    def test_source_and_helm_chart_versions_must_match(self):
        paths = {path: [] for path in transaction.FLUX_CRD_COLLECTIONS.values()}
        paths[transaction.FLUX_CRD_COLLECTIONS["OCIRepository"]] = [
            self.source(
                "naranjo-online", "naranjo-online", "0.1.32", UID_ONE, "11"
            ),
            self.source(
                "lidersea-com", "lidersea-com", "0.1.29", UID_TWO, "12"
            ),
        ]
        paths[transaction.FLUX_CRD_COLLECTIONS["HelmRelease"]] = [
            self.release(
                "naranjo-online", "naranjo-online", "0.1.30", UID_THREE, "13"
            ),
            self.release(
                "lidersea-com", "lidersea-com", "0.1.29", UID_FOUR, "14"
            ),
        ]

        class Client:
            def get(self, path):
                return {"items": copy.deepcopy(paths[path])}

        with self.assertRaisesRegex(
            transaction.TransactionError, "HELM_REVISION_INVALID"
        ):
            transaction.flux_snapshot(Client())

    def test_helm_proof_recovers_exact_chart_identity_from_plan_baseline(self):
        flux = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        plan = {"baselines": {"flux": flux}}
        version, digest, release = transaction.planned_site_chart_identity(
            plan, "naranjo-online", "naranjo-online"
        )
        self.assertEqual(version, "0.1.32")
        self.assertEqual(digest, self.UPSTREAM)
        self.assertEqual(release["attemptedRevision"], "0.1.32+" + "a" * 12)

        for label, mutate in (
            (
                "source version",
                lambda candidate: candidate["baselines"]["flux"]["oci"][
                    "naranjo-online/naranjo-online-chart"
                ].update(chartVersion="0.1.31"),
            ),
            (
                "Helm history",
                lambda candidate: candidate["baselines"]["flux"]["helm"][
                    "naranjo-online/naranjo-online"
                ].update(historyChartVersion="0.1.31+" + "a" * 12),
            ),
        ):
            with self.subTest(label=label):
                candidate = copy.deepcopy(plan)
                mutate(candidate)
                with self.assertRaisesRegex(
                    transaction.TransactionError,
                    "PLAN_SITE_CHART_BINDING_INVALID",
                ):
                    transaction.planned_site_chart_identity(
                        candidate, "naranjo-online", "naranjo-online"
                    )

    def test_helm_proof_spec_builder_is_exact_and_fail_closed(self):
        plan_sha256 = "a" * 64
        self.assertEqual(
            transaction.HELM_PROOF_TARGET,
            {
                "group": "",
                "version": "v1",
                "kind": "Service",
                "namespace": "naranjo-online",
                "name": "naranjo-online",
            },
        )
        self.assertEqual(
            transaction.HELM_PROOF_JSON_POINTER,
            "/metadata/annotations/"
            "platform.snaraj.dev~1flux-rbac-convergence-proof",
        )
        pre_spec = copy.deepcopy(self.valid_release()["spec"])
        pre_spec["commonMetadata"] = {
            "annotations": {"example.test/existing": "kept"},
            "labels": {"example.test/existing": "kept"},
        }
        original = copy.deepcopy(pre_spec)
        changed = transaction.build_helm_proof_spec(pre_spec, plan_sha256)
        self.assertEqual(pre_spec, original)
        self.assertEqual(changed["commonMetadata"], pre_spec["commonMetadata"])
        self.assertEqual(
            changed["postRenderers"],
            transaction.helm_proof_post_renderers(plan_sha256),
        )

        cases = {
            "spec": ([], plan_sha256, "HELM_PROOF_SPEC_INVALID"),
            "common metadata": (
                {**pre_spec, "commonMetadata": []},
                plan_sha256,
                "HELM_PROOF_COMMON_METADATA_INVALID",
            ),
            "annotations": (
                {**pre_spec, "commonMetadata": {"annotations": []}},
                plan_sha256,
                "HELM_PROOF_ANNOTATIONS_INVALID",
            ),
            "collision": (
                {
                    **pre_spec,
                    "commonMetadata": {
                        "annotations": {transaction.PROOF_ANNOTATION: plan_sha256}
                    },
                },
                plan_sha256,
                "HELM_PROOF_ANNOTATION_COLLISION",
            ),
            "post-renderer collision": (
                {**pre_spec, "postRenderers": []},
                plan_sha256,
                "HELM_PROOF_POST_RENDERERS_COLLISION",
            ),
            "plan hash": (
                pre_spec,
                "A" * 64,
                "HELM_PROOF_PLAN_SHA256_INVALID",
            ),
        }
        for label, (candidate, candidate_hash, code) in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                transaction.TransactionError, code
            ):
                transaction.build_helm_proof_spec(candidate, candidate_hash)

    def test_temporary_helm_proof_allows_only_exact_service_post_renderer(self):
        plan_sha256 = "a" * 64
        release = self.valid_release()
        release["spec"] = transaction.build_helm_proof_spec(
            release["spec"], plan_sha256
        )
        snapshot = transaction.validate_site_helm_release(
            release,
            "naranjo-online",
            "naranjo-online",
            "0.1.30",
            self.UPSTREAM,
            expected_proof_annotation=plan_sha256,
        )
        self.assertEqual(snapshot["uid"], UID_THREE)
        with self.assertRaisesRegex(
            transaction.TransactionError, "HELM_FORBIDDEN_SPEC_PATH"
        ):
            self.validate(release)

        for label, mutate in (
            (
                "wrong kind",
                lambda value: value[0]["kustomize"]["patches"][0][
                    "target"
                ].update(kind="Deployment"),
            ),
            (
                "wrong name",
                lambda value: value[0]["kustomize"]["patches"][0][
                    "target"
                ].update(name="other"),
            ),
            (
                "extra patch",
                lambda value: value[0]["kustomize"]["patches"].append(
                    copy.deepcopy(value[0]["kustomize"]["patches"][0])
                ),
            ),
            (
                "wrong value",
                lambda value: value[0]["kustomize"]["patches"][0].update(
                    patch=value[0]["kustomize"]["patches"][0]["patch"].replace(
                        plan_sha256, "b" * 64
                    )
                ),
            ),
        ):
            with self.subTest(label=label):
                candidate = copy.deepcopy(release)
                mutate(candidate["spec"]["postRenderers"])
                with self.assertRaisesRegex(
                    transaction.TransactionError,
                    "HELM_PROOF_POST_RENDERERS_INVALID",
                ):
                    transaction.validate_site_helm_release(
                        candidate,
                        "naranjo-online",
                        "naranjo-online",
                        "0.1.30",
                        self.UPSTREAM,
                        expected_proof_annotation=plan_sha256,
                    )

    def test_forward_helm_proof_calls_shared_spec_builder_before_write(self):
        plan_sha256 = "a" * 64
        plan = {
            "temporaryProof": {
                "identity": {
                    "apiVersion": "helm.toolkit.fluxcd.io/v2",
                    "kind": "HelmRelease",
                    "namespace": "naranjo-online",
                    "name": "naranjo-online",
                },
                "annotationKey": transaction.PROOF_ANNOTATION,
            },
            "baselines": {
                "flux": self.flux_snapshot_for_versions("0.1.30", "0.1.26")
            },
        }
        live = self.valid_release()

        class Client:
            put_calls = 0

            def get(self, _url):
                return copy.deepcopy(live)

            def put(self, _url, _body):
                self.put_calls += 1
                raise AssertionError("write must not precede builder")

        journal = mock.Mock()
        journal.document = {"planSha256": plan_sha256}
        client = Client()
        with mock.patch.object(
            transaction,
            "build_helm_proof_spec",
            side_effect=transaction.TransactionError("BUILDER_SENTINEL"),
        ) as builder, self.assertRaisesRegex(
            transaction.TransactionError, "BUILDER_SENTINEL"
        ):
            transaction.helm_proof(client, plan, plan_sha256, journal)
        builder.assert_called_once_with(live["spec"], plan_sha256)
        self.assertEqual(client.put_calls, 0)
        journal.write.assert_not_called()

    def test_forward_helm_proof_uses_current_resource_version_as_write_fence(self):
        plan_sha256 = "a" * 64
        plan = {
            "temporaryProof": {
                "identity": {
                    "apiVersion": "helm.toolkit.fluxcd.io/v2",
                    "kind": "HelmRelease",
                    "namespace": "naranjo-online",
                    "name": "naranjo-online",
                },
                "annotationKey": transaction.PROOF_ANNOTATION,
            },
            "baselines": {
                "flux": self.flux_snapshot_for_versions("0.1.30", "0.1.26")
            },
        }
        live = self.valid_release()
        planned = plan["baselines"]["flux"]["helm"][
            "naranjo-online/naranjo-online"
        ]
        live["metadata"]["resourceVersion"] = str(
            int(live["metadata"]["resourceVersion"]) + 1
        )

        class Client:
            put_body = None

            def get(self, _url):
                return copy.deepcopy(live)

            def put(self, _url, body):
                self.put_body = copy.deepcopy(body)
                raise transaction.TransactionError("PUT_SENTINEL")

        journal = mock.Mock()
        journal.document = {"planSha256": plan_sha256}
        client = Client()
        with self.assertRaisesRegex(transaction.TransactionError, "PUT_SENTINEL"):
            transaction.helm_proof(client, plan, plan_sha256, journal)
        self.assertNotEqual(
            live["metadata"]["resourceVersion"], planned["resourceVersion"]
        )
        self.assertEqual(
            client.put_body["metadata"]["resourceVersion"],
            live["metadata"]["resourceVersion"],
        )
        journal.write.assert_called_once_with()

    def test_forward_helm_proof_still_rejects_non_version_drift(self):
        plan_sha256 = "a" * 64
        plan = {
            "temporaryProof": {
                "identity": {
                    "apiVersion": "helm.toolkit.fluxcd.io/v2",
                    "kind": "HelmRelease",
                    "namespace": "naranjo-online",
                    "name": "naranjo-online",
                },
                "annotationKey": transaction.PROOF_ANNOTATION,
            },
            "baselines": {
                "flux": self.flux_snapshot_for_versions("0.1.30", "0.1.26")
            },
        }
        live = self.valid_release()
        live["status"]["lastAttemptedReleaseAction"] = "install"
        client = mock.Mock()
        client.get.return_value = copy.deepcopy(live)
        journal = mock.Mock()
        journal.document = {"planSha256": plan_sha256}
        with self.assertRaisesRegex(
            transaction.TransactionError, "HELM_PROOF_PLAN_PRESTATE_DRIFT"
        ):
            transaction.helm_proof(client, plan, plan_sha256, journal)
        client.put.assert_not_called()
        journal.write.assert_not_called()

    def test_chart_movement_after_plan_is_baseline_drift(self):
        planned = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        moved = self.flux_snapshot_for_versions("0.1.33", "0.1.29")
        plan = {
            "baselines": {"flux": planned, "workloads": {}, "publicSites": {}}
        }
        with mock.patch.object(
            transaction, "flux_snapshot", return_value=moved
        ), mock.patch.object(
            transaction, "workload_snapshot", return_value={}
        ), mock.patch.object(
            transaction, "validate_helm_workload_inventory"
        ), mock.patch.object(
            transaction, "public_health", return_value={}
        ), self.assertRaisesRegex(
            transaction.TransactionError, "FLUX_BASELINE_DRIFT"
        ):
            transaction.stable_baselines(plan, object())

    def assert_stable_flux(self, planned, current, *, allow_proof=False):
        plan = {
            "baselines": {"flux": planned, "workloads": {}, "publicSites": {}}
        }
        with mock.patch.object(
            transaction, "flux_snapshot", return_value=current
        ), mock.patch.object(
            transaction, "workload_snapshot", return_value={}
        ), mock.patch.object(
            transaction, "validate_helm_workload_inventory"
        ), mock.patch.object(
            transaction, "public_health", return_value={}
        ):
            transaction.stable_baselines(
                plan, object(), allow_proof=allow_proof
            )

    def test_resource_version_only_flux_drift_is_tolerated(self):
        planned = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        current = copy.deepcopy(planned)
        next_resource_version = 100
        for section in ("oci", "helm"):
            for row in current[section].values():
                row["resourceVersion"] = str(next_resource_version)
                next_resource_version += 1
        self.assert_stable_flux(planned, current)

    def test_missing_or_malformed_flux_resource_version_fails_closed(self):
        planned = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        identity = next(iter(planned["oci"]))
        for label, replacement in (
            ("missing", None),
            ("malformed", "moved"),
            ("zero", "0"),
        ):
            with self.subTest(label=label):
                current = copy.deepcopy(planned)
                if replacement is None:
                    current["oci"][identity].pop("resourceVersion")
                else:
                    current["oci"][identity]["resourceVersion"] = replacement
                with self.assertRaisesRegex(
                    transaction.TransactionError, "FLUX_BASELINE_INVALID"
                ):
                    self.assert_stable_flux(planned, current)

    def test_every_other_flux_row_field_remains_bound(self):
        planned = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        for section in ("oci", "helm"):
            identity, planned_row = next(iter(planned[section].items()))
            for field in sorted(set(planned_row) - {"resourceVersion"}):
                with self.subTest(section=section, field=field):
                    current = copy.deepcopy(planned)
                    current[section][identity][field] = {"hostile": True}
                    with self.assertRaisesRegex(
                        transaction.TransactionError, "FLUX_BASELINE_DRIFT"
                    ):
                        self.assert_stable_flux(planned, current)

    def test_json_numeric_type_drift_remains_bound(self):
        planned = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        identity = next(iter(planned["oci"]))
        current = copy.deepcopy(planned)
        self.assertEqual(current["oci"][identity]["generation"], 3)
        current["oci"][identity]["generation"] = 3.0
        with self.assertRaisesRegex(
            transaction.TransactionError, "FLUX_BASELINE_DRIFT"
        ):
            self.assert_stable_flux(planned, current)

    def test_closed_flux_inventory_fields_remain_bound(self):
        planned = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        for field, hostile in (
            ("closedEmptyInventories", {"Bucket": 1}),
            ("gitRepositories", 1),
            ("kustomizations", 1),
        ):
            with self.subTest(field=field):
                current = copy.deepcopy(planned)
                current[field] = hostile
                with self.assertRaisesRegex(
                    transaction.TransactionError, "FLUX_BASELINE_DRIFT"
                ):
                    self.assert_stable_flux(planned, current)

    def test_post_proof_oci_resource_version_only_drift_is_tolerated(self):
        planned = self.flux_snapshot_for_versions("0.1.32", "0.1.29")
        current = copy.deepcopy(planned)
        for index, row in enumerate(current["oci"].values(), start=100):
            row["resourceVersion"] = str(index)
        self.assert_stable_flux(planned, current, allow_proof=True)

    def test_flux_snapshot_binds_helm_to_upstream_not_stored_artifact_digest(self):
        sources = [
            self.source("naranjo-online", "naranjo-online", "0.1.30", UID_ONE, "11"),
            self.source("lidersea-com", "lidersea-com", "0.1.26", UID_TWO, "12"),
        ]
        releases = [
            self.release("naranjo-online", "naranjo-online", "0.1.30", UID_THREE, "13"),
            self.release("lidersea-com", "lidersea-com", "0.1.26", UID_FOUR, "14"),
        ]
        paths = {path: [] for path in transaction.FLUX_CRD_COLLECTIONS.values()}
        paths[transaction.FLUX_CRD_COLLECTIONS["OCIRepository"]] = sources
        paths[transaction.FLUX_CRD_COLLECTIONS["HelmRelease"]] = releases

        class Client:
            def get(self, path):
                return {"items": copy.deepcopy(paths[path])}

        snapshot = transaction.flux_snapshot(Client())
        source = snapshot["oci"]["naranjo-online/naranjo-online-chart"]
        release = snapshot["helm"]["naranjo-online/naranjo-online"]
        self.assertEqual(source["upstreamDigest"], self.UPSTREAM)
        self.assertEqual(source["storedArtifactDigest"], self.STORED)
        self.assertNotEqual(source["upstreamDigest"], source["storedArtifactDigest"])
        self.assertEqual(release["attemptedRevisionDigest"], self.UPSTREAM)
        self.assertEqual(release["attemptedRevision"], "0.1.30+" + "a" * 12)

    def test_every_unapproved_flux_crd_kind_must_be_empty(self):
        sources = [
            self.source("naranjo-online", "naranjo-online", "0.1.30", UID_ONE, "11"),
            self.source("lidersea-com", "lidersea-com", "0.1.26", UID_TWO, "12"),
        ]
        releases = [
            self.release("naranjo-online", "naranjo-online", "0.1.30", UID_THREE, "13"),
            self.release("lidersea-com", "lidersea-com", "0.1.26", UID_FOUR, "14"),
        ]
        for kind in sorted(transaction.FLUX_EMPTY_KINDS):
            with self.subTest(kind=kind):
                paths = {
                    path: [] for path in transaction.FLUX_CRD_COLLECTIONS.values()
                }
                paths[transaction.FLUX_CRD_COLLECTIONS["OCIRepository"]] = sources
                paths[transaction.FLUX_CRD_COLLECTIONS["HelmRelease"]] = releases
                paths[transaction.FLUX_CRD_COLLECTIONS[kind]] = [
                    {"apiVersion": "v1", "kind": kind, "metadata": {"name": "stale"}}
                ]

                class Client:
                    def get(self, path):
                        return {"items": copy.deepcopy(paths[path])}

                with self.assertRaisesRegex(
                    transaction.TransactionError, "FLUX_UNOWNED_RESOURCE_PRESENT"
                ):
                    transaction.flux_snapshot(Client())

    def test_closed_flux_surface_matches_every_pinned_components_crd(self):
        components = (
            ROOT / "kubernetes/flux-system/controllers/gotk-components.yaml"
        ).read_text(encoding="utf-8").splitlines()
        crds = []
        waiting_for_name = False
        for line in components:
            if line == "kind: CustomResourceDefinition":
                waiting_for_name = True
            elif waiting_for_name and line.startswith("  name: "):
                crds.append(line.removeprefix("  name: "))
                waiting_for_name = False
        expected = {
            "buckets.source.toolkit.fluxcd.io",
            "externalartifacts.source.toolkit.fluxcd.io",
            "gitrepositories.source.toolkit.fluxcd.io",
            "helmcharts.source.toolkit.fluxcd.io",
            "helmrepositories.source.toolkit.fluxcd.io",
            "ocirepositories.source.toolkit.fluxcd.io",
            "kustomizations.kustomize.toolkit.fluxcd.io",
            "helmreleases.helm.toolkit.fluxcd.io",
        }
        self.assertEqual(set(crds), expected)
        self.assertEqual(set(transaction.FLUX_CRD_COLLECTIONS), {
            "Bucket",
            "ExternalArtifact",
            "GitRepository",
            "HelmChart",
            "HelmRepository",
            "OCIRepository",
            "Kustomization",
            "HelmRelease",
        })

    def test_optional_legacy_history_fields_may_be_absent(self):
        release = self.valid_release()
        release["status"]["history"][0].pop("action")
        release["status"]["history"][0].pop("ociDigest")
        self.assertEqual(self.validate(release)["historyChartVersion"], "0.1.30+" + "a" * 12)

    def test_credential_remote_and_cross_namespace_spec_paths_fail_closed(self):
        for field, value in {
            "chart": {"spec": {}},
            "dependsOn": [],
            "kubeConfig": {"secretRef": {"name": "remote"}},
            "postRenderers": [{"kustomize": {"patches": []}}],
            "storageNamespace": "other",
            "targetNamespace": "other",
            "valuesFrom": [],
        }.items():
            with self.subTest(field=field):
                release = self.valid_release()
                release["spec"][field] = value
                with self.assertRaises(transaction.TransactionError):
                    self.validate(release)

        for field, value in (("upgrade", {"force": True}), ("install", {"replace": True})):
            with self.subTest(field=field):
                release = self.valid_release()
                release["spec"][field] = value
                with self.assertRaises(transaction.TransactionError):
                    self.validate(release)

    def test_chart_reference_must_be_exact_same_site_and_status_has_no_helmchart(self):
        mutations = []
        cross = self.valid_release()
        cross["spec"]["chartRef"]["name"] = "lidersea-com-chart"
        mutations.append(cross)
        namespaced = self.valid_release()
        namespaced["spec"]["chartRef"]["namespace"] = "naranjo-online"
        mutations.append(namespaced)
        generated = self.valid_release()
        generated["status"]["helmChart"] = "naranjo-online/generated"
        mutations.append(generated)
        for release in mutations:
            with self.subTest(release=release["spec"]["chartRef"]):
                with self.assertRaises(transaction.TransactionError):
                    self.validate(release)

    def test_revision_digest_history_generation_and_remediation_mutations_fail(self):
        cases = {}
        bare = self.valid_release()
        bare["status"]["lastAttemptedRevision"] = "0.1.30"
        cases["bare revision"] = bare
        stored_suffix = self.valid_release()
        stored_suffix["status"]["lastAttemptedRevision"] = "0.1.30+" + "b" * 12
        cases["stored digest suffix"] = stored_suffix
        wrong_digest = self.valid_release()
        wrong_digest["status"]["lastAttemptedRevisionDigest"] = self.STORED
        cases["stored attempted digest"] = wrong_digest
        stale = self.valid_release()
        stale["status"]["lastAttemptedGeneration"] = 4
        cases["stale generation"] = stale
        chart = self.valid_release()
        chart["status"]["history"][0]["chartVersion"] = "0.1.29+" + "a" * 12
        cases["history chart"] = chart
        oci = self.valid_release()
        oci["status"]["history"][0]["ociDigest"] = self.STORED
        cases["history OCI digest"] = oci
        action = self.valid_release()
        action["status"]["history"][0]["action"] = "rollback"
        cases["history rollback"] = action
        attempted_action = self.valid_release()
        attempted_action["status"]["lastAttemptedReleaseAction"] = "rollback"
        cases["attempted rollback"] = attempted_action
        ready = self.valid_release()
        ready["status"]["conditions"][0]["reason"] = "RollbackSucceeded"
        cases["rollback ready"] = ready
        remediated = self.valid_release()
        remediated["status"]["conditions"].append(
            {"type": "Remediated", "status": "True", "reason": "RollbackSucceeded"}
        )
        cases["remediated"] = remediated
        extra_inventory = self.valid_release()
        extra_inventory["status"]["inventory"]["entries"].append(
            {
                "id": "naranjo-online_unreviewed__Secret",
                "v": "v1",
            }
        )
        cases["extra inventory"] = extra_inventory
        for label, release in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(transaction.TransactionError):
                    self.validate(release)


class WorkloadSnapshotTypeMetaTests(unittest.TestCase):
    @staticmethod
    def fixtures():
        paths = {}
        for namespace, name in sorted(transaction.SITE_RELEASES):
            annotations = {
                "meta.helm.sh/release-name": name,
                "meta.helm.sh/release-namespace": namespace,
            }

            def metadata(object_name, uid, resource_version):
                return {
                    "name": object_name,
                    "namespace": namespace,
                    "uid": uid,
                    "resourceVersion": resource_version,
                    "annotations": copy.deepcopy(annotations),
                }

            labels = {"app": name}
            deployment = {
                "metadata": {
                    **metadata(name, UID_ONE, "11"),
                    "generation": 2,
                },
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": labels},
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {"containers": [{"name": name}]},
                    },
                },
                "status": {
                    "observedGeneration": 2,
                    "availableReplicas": 1,
                    "updatedReplicas": 1,
                },
            }
            service = {"metadata": metadata(name, UID_TWO, "12")}
            service_account = {"metadata": metadata(name, UID_THREE, "13")}
            network_policy = {"metadata": metadata(name, UID_FOUR, "14")}
            pod = {
                "metadata": {
                    "name": name + "-pod",
                    "namespace": namespace,
                    "uid": UID_FOUR,
                    "resourceVersion": "15",
                    "labels": labels,
                },
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [
                        {
                            "restartCount": 0,
                            "image": "example.invalid/site@sha256:" + "a" * 64,
                        }
                    ],
                },
            }
            paths[
                f"/apis/apps/v1/namespaces/{namespace}/deployments"
            ] = [deployment]
            paths[f"/api/v1/namespaces/{namespace}/services"] = [service]
            paths[f"/api/v1/namespaces/{namespace}/serviceaccounts"] = [
                service_account
            ]
            paths[
                f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies"
            ] = [network_policy]
            paths[f"/api/v1/namespaces/{namespace}/pods"] = [pod]
        return paths

    @staticmethod
    def snapshot(paths):
        class Client:
            def get(self, path):
                return {"items": copy.deepcopy(paths[path])}

        return transaction.workload_snapshot(Client())

    def test_raw_list_items_without_type_meta_use_closed_path_identity(self):
        paths = self.fixtures()
        for path, items in paths.items():
            if path.endswith("/pods"):
                continue
            self.assertNotIn("apiVersion", items[0])
            self.assertNotIn("kind", items[0])

        snapshot = self.snapshot(paths)
        self.assertEqual(
            set(snapshot),
            {
                "lidersea-com/lidersea-com",
                "naranjo-online/naranjo-online",
            },
        )
        expected_versions = {
            kind: version if not group else f"{group}/{version}"
            for kind, (group, version) in transaction.SITE_INVENTORY_KINDS.items()
        }
        for workload in snapshot.values():
            rows = {row["kind"]: row for row in workload["ownedObjects"]}
            self.assertEqual(set(rows), set(expected_versions))
            self.assertEqual(
                {kind: row["apiVersion"] for kind, row in rows.items()},
                expected_versions,
            )
            self.assertEqual(
                workload["semanticSha256"],
                rows["Deployment"]["semanticSha256"],
            )

    def test_conflicting_type_meta_and_wrong_inventory_fail_closed(self):
        namespace = "lidersea-com"
        service_path = f"/api/v1/namespaces/{namespace}/services"
        policy_path = (
            f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies"
        )

        def add_extra(paths):
            extra = copy.deepcopy(paths[service_path][0])
            extra["metadata"].update(
                name="lidersea-com-extra",
                uid=UID_FOUR,
                resourceVersion="99",
            )
            paths[service_path].append(extra)

        cases = {
            "conflicting apiVersion": (
                lambda paths: paths[service_path][0].update(apiVersion="v2"),
                "SITE_OWNED_OBJECT_IDENTITY_INVALID",
            ),
            "conflicting kind": (
                lambda paths: paths[service_path][0].update(kind="Secret"),
                "SITE_OWNED_OBJECT_IDENTITY_INVALID",
            ),
            "null apiVersion": (
                lambda paths: paths[service_path][0].update(apiVersion=None),
                "SITE_OWNED_OBJECT_IDENTITY_INVALID",
            ),
            "non-string kind": (
                lambda paths: paths[service_path][0].update(kind=7),
                "SITE_OWNED_OBJECT_IDENTITY_INVALID",
            ),
            "extra owned object": (
                add_extra,
                "SITE_OWNED_OBJECT_INVENTORY_INVALID",
            ),
            "missing owned kind": (
                lambda paths: paths[policy_path].clear(),
                "SITE_OWNED_OBJECT_INVENTORY_INVALID",
            ),
        }
        for label, (mutate, error) in cases.items():
            with self.subTest(label=label):
                paths = self.fixtures()
                mutate(paths)
                with self.assertRaises(transaction.TransactionError) as caught:
                    self.snapshot(paths)
                self.assertEqual(str(caught.exception), error)


class BindingGraphTypeMetaTests(unittest.TestCase):
    CLUSTER_PATH = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
    NAMESPACED_PATH = "/apis/rbac.authorization.k8s.io/v1/rolebindings"

    @classmethod
    def fixtures(cls):
        broad = _cluster_role_binding(
            transaction.BROAD_NAME,
            role_name="cluster-admin",
        )
        role_binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": "source-controller-runtime",
                "namespace": "flux-system",
                "uid": UID_TWO,
                "resourceVersion": "8",
            },
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "source-controller-runtime",
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "namespace": "flux-system",
                    "name": "source-controller",
                }
            ],
        }
        for item in (broad, role_binding):
            item.pop("apiVersion")
            item.pop("kind")
        return {
            cls.CLUSTER_PATH: [broad],
            cls.NAMESPACED_PATH: [role_binding],
        }

    @staticmethod
    def snapshot(paths, *, require_broad=True):
        class Client:
            def get(self, path):
                return {"items": copy.deepcopy(paths[path])}

        snapshotter = (
            transaction.binding_graph
            if require_broad
            else transaction.binding_graph_without_broad_requirement
        )
        return snapshotter(Client())

    def test_raw_binding_lists_restore_only_caller_bound_type_meta_on_copies(self):
        paths = self.fixtures()
        original = copy.deepcopy(paths)
        graph = self.snapshot(paths)
        terminal_graph = self.snapshot(paths, require_broad=False)

        self.assertEqual(paths, original)
        self.assertEqual(terminal_graph, graph)
        rows = {row["name"]: row for row in graph["rows"]}
        self.assertEqual(
            set(rows),
            {transaction.BROAD_NAME, "source-controller-runtime"},
        )
        self.assertEqual(
            rows[transaction.BROAD_NAME]["kind"],
            "ClusterRoleBinding",
        )
        self.assertEqual(rows["source-controller-runtime"]["kind"], "RoleBinding")
        self.assertEqual(
            rows["source-controller-runtime"]["trackedSubjects"],
            ["ServiceAccount:flux-system/source-controller"],
        )
        for path, kind in (
            (self.CLUSTER_PATH, "ClusterRoleBinding"),
            (self.NAMESPACED_PATH, "RoleBinding"),
        ):
            normalized = transaction.collection_item_with_type_meta(
                paths[path][0],
                expected_kind=kind,
                expected_api_version="rbac.authorization.k8s.io/v1",
                error_token="OBJECT_IDENTITY_INVALID",
            )
            self.assertEqual(
                rows[normalized["metadata"]["name"]]["semanticSha256"],
                transaction.semantic_hash(normalized),
            )

    def test_present_invalid_binding_type_meta_and_broad_graph_fail_closed(self):
        cases = {
            "wrong cluster apiVersion": (
                self.CLUSTER_PATH,
                lambda item: item.update(apiVersion="v1"),
                "OBJECT_IDENTITY_INVALID",
            ),
            "null cluster kind": (
                self.CLUSTER_PATH,
                lambda item: item.update(kind=None),
                "OBJECT_IDENTITY_INVALID",
            ),
            "wrong namespaced kind": (
                self.NAMESPACED_PATH,
                lambda item: item.update(kind="ClusterRoleBinding"),
                "OBJECT_IDENTITY_INVALID",
            ),
            "non-string namespaced apiVersion": (
                self.NAMESPACED_PATH,
                lambda item: item.update(apiVersion=7),
                "OBJECT_IDENTITY_INVALID",
            ),
        }
        for label, (path, mutate, error) in cases.items():
            for require_broad in (True, False):
                with self.subTest(label=label, require_broad=require_broad):
                    paths = self.fixtures()
                    mutate(paths[path][0])
                    with self.assertRaises(transaction.TransactionError) as caught:
                        self.snapshot(paths, require_broad=require_broad)
                    self.assertEqual(str(caught.exception), error)

        paths = self.fixtures()
        second_broad = copy.deepcopy(paths[self.CLUSTER_PATH][0])
        second_broad["metadata"].update(name="unexpected-broad", uid=UID_THREE)
        paths[self.CLUSTER_PATH].append(second_broad)
        with self.assertRaises(transaction.TransactionError) as caught:
            self.snapshot(paths)
        self.assertEqual(
            str(caught.exception),
            "CONTROLLER_CLUSTER_ADMIN_GRAPH_INVALID",
        )


class HelmProofInventoryTests(unittest.TestCase):
    PLAN_SHA = "9" * 64

    @staticmethod
    def flux_baseline():
        paths = {path: [] for path in transaction.FLUX_CRD_COLLECTIONS.values()}
        paths[transaction.FLUX_CRD_COLLECTIONS["OCIRepository"]] = [
                HelmChainContractTests.source(
                    "naranjo-online", "naranjo-online", "0.1.30", UID_ONE, "11"
                ),
                HelmChainContractTests.source(
                    "lidersea-com", "lidersea-com", "0.1.26", UID_TWO, "12"
                ),
            ]
        paths[transaction.FLUX_CRD_COLLECTIONS["HelmRelease"]] = [
                HelmChainContractTests.release(
                    "naranjo-online", "naranjo-online", "0.1.30", UID_THREE, "13"
                ),
                HelmChainContractTests.release(
                    "lidersea-com", "lidersea-com", "0.1.26", UID_FOUR, "14"
                ),
            ]

        class Client:
            def get(self, path):
                return {"items": copy.deepcopy(paths[path])}

        return transaction.flux_snapshot(Client())

    @staticmethod
    def workload(identity):
        namespace, name = identity.split("/", 1)
        kinds = {
            "Deployment": "apps/v1",
            "Service": "v1",
            "ServiceAccount": "v1",
            "NetworkPolicy": "networking.k8s.io/v1",
        }
        uids = {
            "Deployment": UID_ONE if namespace == "naranjo-online" else UID_TWO,
            "Service": UID_TWO if namespace == "naranjo-online" else UID_THREE,
            "ServiceAccount": UID_THREE if namespace == "naranjo-online" else UID_FOUR,
            "NetworkPolicy": UID_FOUR if namespace == "naranjo-online" else UID_ONE,
        }
        rows = []
        for kind, api_version in kinds.items():
            digest = transaction.sha256_bytes(f"{identity}:{kind}".encode())
            rows.append(
                {
                    "kind": kind,
                    "name": name,
                    "apiVersion": api_version,
                    "uid": uids[kind],
                    "semanticSha256": digest,
                    "proofAnnotation": None,
                    "semanticWithoutProofSha256": digest,
                }
            )
        rows.sort(key=lambda row: (row["kind"], row["name"]))
        deployment = next(row for row in rows if row["kind"] == "Deployment")
        return {
            "uid": deployment["uid"],
            "generation": 2,
            "replicas": 1,
            "templateSha256": transaction.sha256_bytes(
                f"{identity}:template".encode()
            ),
            "semanticSha256": deployment["semanticSha256"],
            "proofAnnotation": None,
            "semanticWithoutProofSha256": deployment["semanticSha256"],
            "pods": [
                {
                    "uid": UID_FOUR,
                    "restartCounts": [0],
                    "images": ["example.invalid/site@sha256:" + "a" * 64],
                }
            ],
            "ownedObjects": rows,
        }

    def fixtures(self):
        flux = self.flux_baseline()
        workloads = {
            identity: self.workload(identity)
            for identity in (
                "naranjo-online/naranjo-online",
                "lidersea-com/lidersea-com",
            )
        }
        active = copy.deepcopy(workloads)
        naranjo = active["naranjo-online/naranjo-online"]
        service = next(
            row for row in naranjo["ownedObjects"] if row["kind"] == "Service"
        )
        service["proofAnnotation"] = self.PLAN_SHA
        service["semanticWithoutProofSha256"] = service["semanticSha256"]
        service["semanticSha256"] = transaction.sha256_bytes(b"Service:active")
        plan = {"baselines": {"flux": flux, "workloads": workloads}}
        return plan, flux, workloads, active

    def validate_active(self, plan, flux, active):
        upgraded = flux["helm"]["naranjo-online/naranjo-online"]
        client = object()
        with mock.patch.object(
            transaction, "flux_snapshot", return_value=copy.deepcopy(flux)
        ) as flux_snapshot, mock.patch.object(
            transaction, "workload_snapshot", return_value=copy.deepcopy(active)
        ):
            result = transaction.validate_active_helm_proof_inventory(
                client, plan, self.PLAN_SHA, upgraded
            )
        flux_snapshot.assert_called_once_with(
            client, expected_proof_annotation=self.PLAN_SHA
        )
        return result

    def test_active_inventory_binds_exact_service_only_annotation_mutation(self):
        plan, flux, _workloads, active = self.fixtures()
        evidence = self.validate_active(plan, flux, active)
        self.assertEqual(len(evidence["workloads"]), 2)
        self.assertEqual(len(evidence["sha256"]), 64)

    def test_active_inventory_rejects_missing_or_wrong_proof_and_extra_delta(self):
        for label, mutate in {
            "missing proof": lambda row: row.update(proofAnnotation=None),
            "wrong proof": lambda row: row.update(proofAnnotation="8" * 64),
            "extra semantic delta": lambda row: row.update(
                semanticWithoutProofSha256="7" * 64
            ),
            "uid replacement": lambda row: row.update(uid=UID_FOUR),
        }.items():
            with self.subTest(label=label):
                plan, flux, _workloads, active = self.fixtures()
                service = next(
                    row
                    for row in active["naranjo-online/naranjo-online"][
                        "ownedObjects"
                    ]
                    if row["kind"] == "Service"
                )
                mutate(service)
                with self.assertRaises(transaction.TransactionError):
                    self.validate_active(plan, flux, active)

    def test_active_inventory_rejects_any_non_service_owned_mutation(self):
        plan, flux, _workloads, active = self.fixtures()
        deployment = next(
            row
            for row in active["naranjo-online/naranjo-online"]["ownedObjects"]
            if row["kind"] == "Deployment"
        )
        deployment["semanticSha256"] = "7" * 64
        with self.assertRaisesRegex(
            transaction.TransactionError,
            "HELM_PROOF_UNEXPECTED_OWNED_MUTATION",
        ):
            self.validate_active(plan, flux, active)

    def test_active_inventory_rejects_extra_workload_evidence_field(self):
        plan, flux, _workloads, active = self.fixtures()
        active["naranjo-online/naranjo-online"]["unexpected"] = "field"
        with self.assertRaisesRegex(
            transaction.TransactionError,
            "HELM_PROOF_WORKLOAD_IDENTITY_DRIFT",
        ):
            self.validate_active(plan, flux, active)

    def test_active_inventory_rejects_pod_or_unrelated_site_drift(self):
        for label in ("pod", "lidersea"):
            with self.subTest(label=label):
                plan, flux, _workloads, active = self.fixtures()
                if label == "pod":
                    active["naranjo-online/naranjo-online"]["pods"][0][
                        "restartCounts"
                    ] = [1]
                else:
                    active["lidersea-com/lidersea-com"]["replicas"] = 2
                with self.assertRaises(transaction.TransactionError):
                    self.validate_active(plan, flux, active)

    def test_restored_inventory_rejects_any_remaining_proof_mutation(self):
        plan, flux, workloads, active = self.fixtures()
        restored_release = copy.deepcopy(
            flux["helm"]["naranjo-online/naranjo-online"]
        )
        restored_release["generation"] += 2
        restored_release["observedGeneration"] += 2
        restored_release["lastAttemptedGeneration"] += 2
        restored_release["historyRevision"] += 2
        restored_flux = copy.deepcopy(flux)
        restored_flux["helm"]["naranjo-online/naranjo-online"] = restored_release

        with mock.patch.object(
            transaction, "flux_snapshot", return_value=copy.deepcopy(restored_flux)
        ), mock.patch.object(
            transaction, "workload_snapshot", return_value=copy.deepcopy(workloads)
        ):
            evidence = transaction.validate_restored_helm_proof_inventory(
                object(), plan, restored_release
            )
        self.assertEqual(len(evidence["sha256"]), 64)

        with mock.patch.object(
            transaction, "flux_snapshot", return_value=copy.deepcopy(restored_flux)
        ), mock.patch.object(
            transaction, "workload_snapshot", return_value=copy.deepcopy(active)
        ):
            with self.assertRaises(transaction.TransactionError):
                transaction.validate_restored_helm_proof_inventory(
                    object(), plan, restored_release
                )


class ControllerRuntimeContractTests(unittest.TestCase):
    def fixture(self):
        images = {
            "source-controller": "ghcr.io/fluxcd/source-controller:v1@sha256:" + "a" * 64,
            "kustomize-controller": "ghcr.io/fluxcd/kustomize-controller:v1@sha256:" + "b" * 64,
            "helm-controller": "ghcr.io/fluxcd/helm-controller:v1@sha256:" + "c" * 64,
        }
        deployments = {}
        pods = []
        replica_sets = []
        for index, name in enumerate(transaction.CONTROLLERS, start=1):
            args = ["--events-addr=http://notification-controller.flux-system.svc.cluster.local./"]
            deployment_uid = f"{index:08d}-1111-4111-8111-111111111111"
            replica_set_uid = f"{index:08d}-2222-4222-8222-222222222222"
            pod_uid = f"{index:08d}-3333-4333-8333-333333333333"
            replica_set_name = name + "-abc123"
            deployments[name] = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": name,
                    "namespace": "flux-system",
                    "uid": deployment_uid,
                    "resourceVersion": str(10 + index),
                    "generation": 2,
                },
                "spec": {
                    "replicas": 1,
                    "template": {
                        "metadata": {"labels": {"app": name}},
                        "spec": {
                            "serviceAccountName": name,
                            "containers": [
                                {"name": "manager", "image": images[name], "args": args}
                            ],
                        },
                    },
                },
                "status": {
                    "observedGeneration": 2,
                    "availableReplicas": 1,
                    "updatedReplicas": 1,
                },
            }
            replica_sets.append(
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "metadata": {
                        "name": replica_set_name,
                        "namespace": "flux-system",
                        "uid": replica_set_uid,
                        "resourceVersion": str(20 + index),
                        "ownerReferences": [
                            {
                                "apiVersion": "apps/v1",
                                "kind": "Deployment",
                                "name": name,
                                "uid": deployment_uid,
                                "controller": True,
                            }
                        ],
                    },
                }
            )
            repository = images[name].split(":v1@", 1)[0]
            digest = images[name].rsplit("@", 1)[1]
            pods.append(
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": name + "-pod",
                        "namespace": "flux-system",
                        "uid": pod_uid,
                        "resourceVersion": str(30 + index),
                        "labels": {"app": name},
                        "ownerReferences": [
                            {
                                "apiVersion": "apps/v1",
                                "kind": "ReplicaSet",
                                "name": replica_set_name,
                                "uid": replica_set_uid,
                                "controller": True,
                            }
                        ],
                    },
                    "spec": {
                        "serviceAccountName": name,
                        "containers": [
                            {"name": "manager", "image": images[name], "args": args}
                        ],
                    },
                    "status": {
                        "phase": "Running",
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "containerStatuses": [
                            {
                                "name": "manager",
                                "ready": True,
                                "state": {"running": {"startedAt": "2026-08-22T00:00:00Z"}},
                                "restartCount": 2 if name == "source-controller" else 0,
                                "image": "sha256:" + "d" * 64,
                                "imageID": "containerd://" + repository + "@" + digest,
                            }
                        ],
                    },
                }
            )
        return images, deployments, pods, replica_sets

    def snapshot(self, images, deployments, pods, replica_sets):
        class Client:
            def get(self, path):
                if path == "/api/v1/namespaces/flux-system/pods":
                    return {"items": copy.deepcopy(pods)}
                if path == "/apis/apps/v1/namespaces/flux-system/replicasets":
                    return {"items": copy.deepcopy(replica_sets)}
                name = path.rsplit("/", 1)[-1]
                return copy.deepcopy(deployments[name])

        versions = {
            "FLUX_SOURCE_CONTROLLER_IMAGE": images["source-controller"],
            "FLUX_KUSTOMIZE_CONTROLLER_IMAGE": images["kustomize-controller"],
            "FLUX_HELM_CONTROLLER_IMAGE": images["helm-controller"],
        }
        with mock.patch.object(transaction, "read_regular", return_value=b""), mock.patch.object(
            transaction, "parse_versions", return_value=versions
        ):
            return transaction.controller_snapshot(Client())

    def test_runtime_status_image_representations_and_bound_image_id_pass(self):
        images, deployments, pods, replica_sets = self.fixture()
        snapshot = self.snapshot(images, deployments, pods, replica_sets)
        source = snapshot["source-controller"]
        self.assertEqual(
            pods[0]["status"]["containerStatuses"][0]["image"],
            "sha256:" + "d" * 64,
        )
        self.assertEqual(source["podRestarts"], 2)
        self.assertEqual(source["podImage"], source["image"])
        self.assertEqual(source["podArgs"], source["args"])
        self.assertEqual(source["podServiceAccountName"], "source-controller")
        self.assertTrue(source["podImageID"].endswith("@sha256:" + "a" * 64))

        pods[0]["status"]["containerStatuses"][0][
            "image"
        ] = "runtime.example/display:v9"
        alternate = self.snapshot(images, deployments, pods, replica_sets)
        self.assertEqual(
            alternate["source-controller"]["podImageID"],
            source["podImageID"],
        )

    def test_runtime_and_owner_mutations_fail_closed(self):
        mutations = {
            "deployment spec image": lambda d, _p, _r: d[
                "source-controller"
            ]["spec"]["template"]["spec"]["containers"][0].__setitem__(
                "image", "ghcr.io/example/wrong@sha256:" + "a" * 64
            ),
            "pod service account": lambda _d, p, _r: p[0]["spec"].__setitem__(
                "serviceAccountName", "default"
            ),
            "pod args": lambda _d, p, _r: p[0]["spec"]["containers"][0].__setitem__(
                "args", ["--unexpected"]
            ),
            "pod spec image": lambda _d, p, _r: p[0]["spec"]["containers"][0].__setitem__(
                "image", "ghcr.io/example/wrong@sha256:" + "a" * 64
            ),
            "empty status image": lambda _d, p, _r: p[0]["status"][
                "containerStatuses"
            ][0].__setitem__("image", ""),
            "missing status image": lambda _d, p, _r: p[0]["status"][
                "containerStatuses"
            ][0].pop("image"),
            "non-string status image": lambda _d, p, _r: p[0]["status"][
                "containerStatuses"
            ][0].__setitem__("image", None),
            "oversized status image": lambda _d, p, _r: p[0]["status"][
                "containerStatuses"
            ][0].__setitem__(
                "image", "x" * (transaction.MAX_CONTROLLER_STATUS_IMAGE_CHARS + 1)
            ),
            "image id repository": lambda _d, p, _r: p[0]["status"][
                "containerStatuses"
            ][0].__setitem__(
                "imageID",
                "containerd://ghcr.io/example/source-controller@sha256:"
                + "a" * 64,
            ),
            "image id digest": lambda _d, p, _r: p[0]["status"]["containerStatuses"][0].__setitem__(
                "imageID", "ghcr.io/fluxcd/source-controller@sha256:" + "f" * 64
            ),
            "phase": lambda _d, p, _r: p[0]["status"].__setitem__("phase", "Pending"),
            "negative restarts": lambda _d, p, _r: p[0]["status"]["containerStatuses"][0].__setitem__(
                "restartCount", -1
            ),
            "pod owner": lambda _d, p, _r: p[0]["metadata"]["ownerReferences"][0].__setitem__(
                "uid", UID_FOUR
            ),
            "replicaset owner": lambda _d, _p, r: r[0]["metadata"]["ownerReferences"][0].__setitem__(
                "uid", UID_FOUR
            ),
        }
        expected_errors = {
            "deployment spec image": "CONTROLLER_IMAGE_INVALID",
            "pod service account": "CONTROLLER_POD_NOT_READY",
            "pod args": "CONTROLLER_POD_NOT_READY",
            "pod spec image": "CONTROLLER_POD_NOT_READY",
            "empty status image": "CONTROLLER_POD_NOT_READY",
            "missing status image": "CONTROLLER_POD_NOT_READY",
            "non-string status image": "CONTROLLER_POD_NOT_READY",
            "oversized status image": "CONTROLLER_POD_NOT_READY",
            "image id repository": "CONTROLLER_POD_IMAGE_ID_INVALID",
            "image id digest": "CONTROLLER_POD_IMAGE_ID_INVALID",
            "phase": "CONTROLLER_POD_NOT_READY",
            "negative restarts": "CONTROLLER_POD_NOT_READY",
            "pod owner": "CONTROLLER_REPLICASET_INVALID",
            "replicaset owner": "CONTROLLER_REPLICASET_OWNER_INVALID",
        }
        self.assertEqual(set(mutations), set(expected_errors))
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                images, deployments, pods, replica_sets = self.fixture()
                mutate(deployments, pods, replica_sets)
                with self.assertRaises(transaction.TransactionError) as caught:
                    self.snapshot(images, deployments, pods, replica_sets)
                self.assertEqual(str(caught.exception), expected_errors[label])


class PlanLifetimeTests(unittest.TestCase):
    def _plan(self, expires_at):
        return {
            "schema": transaction.PLAN_SCHEMA,
            "createdAt": "2026-08-21T12:00:00Z",
            "expiresAt": expires_at,
        }

    def _read(self, plan, *, now, require_fresh):
        payload = transaction.canonical_json(plan)
        with mock.patch.object(transaction, "read_regular", return_value=payload), mock.patch.object(
            transaction, "utc_now", return_value=now
        ):
            return transaction.read_plan(
                transaction.sha256_bytes(payload), require_fresh=require_fresh
            )

    def test_expired_plan_is_rejected_for_mutation_but_available_for_recovery(self):
        self.assertIn("require_fresh", inspect.signature(transaction.read_plan).parameters)
        now = dt.datetime(2026, 8, 22, 13, 0, tzinfo=dt.timezone.utc)
        expired = self._plan("2026-08-22T12:00:00Z")
        with self.assertRaisesRegex(transaction.TransactionError, "PLAN_EXPIRED"):
            self._read(expired, now=now, require_fresh=True)
        loaded, digest = self._read(expired, now=now, require_fresh=False)
        self.assertEqual(loaded, expired)
        self.assertEqual(digest, transaction.sha256_bytes(transaction.canonical_json(expired)))

    def test_unexpired_plan_remains_usable_for_mutation(self):
        now = dt.datetime(2026, 8, 22, 11, 0, tzinfo=dt.timezone.utc)
        plan = self._plan("2026-08-22T12:00:00Z")
        loaded, _digest = self._read(plan, now=now, require_fresh=True)
        self.assertEqual(loaded, plan)

    def test_modes_enforce_freshness_only_for_apply(self):
        digest = "a" * 64

        class ContextClient:
            def __enter__(self):
                return object()

            def __exit__(self, *_args):
                return None

        for mode, require_fresh in (
            ("--apply", True),
            ("--rollback", False),
            ("--verify", False),
        ):
            with self.subTest(mode=mode), mock.patch.dict(
                transaction.os.environ,
                {"FLUX_RBAC_EXPECTED_PLAN_SHA256": digest},
            ), mock.patch.object(
                transaction,
                "validate_runtime_custody",
                return_value=({"sourceRevision": "b" * 40}, {}),
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(
                transaction, "acquire_lock", return_value=19
            ), mock.patch.object(
                transaction.os, "close"
            ), mock.patch.object(
                transaction, "load_target", return_value=object()
            ), mock.patch.object(
                transaction, "read_regular", return_value=b""
            ), mock.patch.object(
                transaction, "parse_versions", return_value={}
            ), mock.patch.object(
                transaction, "load_module", return_value=object()
            ), mock.patch.object(
                transaction, "KubeClient", return_value=ContextClient()
            ), mock.patch.object(
                transaction, "read_plan", return_value=({}, digest)
            ) as read_plan, mock.patch.object(
                transaction, "apply"
            ), mock.patch.object(
                transaction, "rollback"
            ), mock.patch.object(
                transaction, "verify"
            ), mock.patch(
                "builtins.print"
            ):
                transaction.run_mode(mode)
            read_plan.assert_called_once_with(digest, require_fresh=require_fresh)


class ReleaseOrderingTests(unittest.TestCase):
    SOURCE = "a" * 40
    LATER_MAIN = "f" * 40
    HEAD = "b" * 40
    TREE = "c" * 40
    BASE = "e" * 40
    TAG_OBJECT = "d" * 40
    TAG = transaction.AUTHORIZED_RELEASE_TAG

    class Contract:
        @staticmethod
        def classify_codeql_run(_runs, _source_revision):
            return 20, 1

        @staticmethod
        def build_main_ci_jobs_receipt(*_args):
            return {"result": "PASS"}

        @staticmethod
        def validate_tag_record(*_args, **_kwargs):
            return None

        @staticmethod
        def validate_release_record(*_args, **_kwargs):
            return None

    def _responses(
        self,
        *,
        ci_updated,
        platform_started,
        release_published,
        platform_updated,
        main_sha=None,
        comparison=None,
    ):
        pull_run = {
            "head_sha": self.SOURCE,
            "head_branch": "main",
            "path": ".github/workflows/pull-request.yml",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "id": 10,
            "run_attempt": 1,
            "updated_at": ci_updated,
        }
        platform_run = {
            "head_sha": self.SOURCE,
            "head_branch": "main",
            "path": ".github/workflows/platform-release.yml",
            "event": "workflow_run",
            "status": "completed",
            "conclusion": "success",
            "id": 30,
            "run_attempt": 1,
            "run_started_at": platform_started,
            "updated_at": platform_updated,
        }

        def github_get(path):
            if path == f"/repos/{transaction.REPOSITORY}/commits/{self.SOURCE}":
                return {
                    "sha": self.SOURCE,
                    "commit": {
                        "verification": {"verified": True, "reason": "valid"},
                        "tree": {"sha": self.TREE},
                    },
                    "parents": [{"sha": self.BASE}],
                }
            if path == f"/repos/{transaction.REPOSITORY}/git/ref/heads/main":
                return {
                    "ref": "refs/heads/main",
                    "object": {
                        "type": "commit",
                        "sha": main_sha or self.SOURCE,
                    },
                }
            if path == (
                f"/repos/{transaction.REPOSITORY}/compare/"
                f"{self.SOURCE}...{main_sha}"
            ):
                if comparison is None:
                    raise AssertionError("unexpected ancestry comparison")
                return comparison
            if path.startswith(f"/repos/{transaction.REPOSITORY}/pulls/"):
                return {
                    "number": 17,
                    "state": "closed",
                    "draft": False,
                    "merged": True,
                    "merged_at": "2026-08-22T11:58:00Z",
                    "merge_commit_sha": self.SOURCE,
                    "user": {"login": transaction.OWNER_LOGIN},
                    "base": {
                        "ref": "main",
                        "label": f"{transaction.OWNER_LOGIN}:main",
                        "sha": self.BASE,
                        "user": {"login": transaction.OWNER_LOGIN},
                        "repo": {"full_name": transaction.REPOSITORY},
                    },
                    "head": {
                        "ref": "5.6-sol/issue-141-flux-convergence-transaction",
                        "label": (
                            f"{transaction.OWNER_LOGIN}:"
                            "5.6-sol/issue-141-flux-convergence-transaction"
                        ),
                        "sha": self.HEAD,
                        "user": {"login": transaction.OWNER_LOGIN},
                        "repo": {"full_name": transaction.REPOSITORY},
                    },
                    "merged_by": {"login": transaction.OWNER_LOGIN},
                }
            if path == f"/repos/{transaction.REPOSITORY}/commits/{self.HEAD}":
                return {
                    "sha": self.HEAD,
                    "commit": {
                        "verification": {"verified": True, "reason": "valid"},
                        "tree": {"sha": self.TREE},
                    },
                }
            if "/actions/workflows/pull-request.yml/runs?" in path:
                return {"total_count": 1, "workflow_runs": [pull_run]}
            if path == f"/repos/{transaction.REPOSITORY}/actions/runs/10/jobs?filter=latest&per_page=100":
                return {"total_count": 0, "jobs": []}
            if "/actions/workflows/codeql.yml/runs?" in path:
                return {"total_count": 1, "workflow_runs": []}
            if path == f"/repos/{transaction.REPOSITORY}/actions/runs/20/jobs?filter=latest&per_page=100":
                return {"total_count": 0, "jobs": []}
            if "/actions/workflows/platform-release.yml/runs?" in path:
                return {"total_count": 1, "workflow_runs": [platform_run]}
            if path == f"/repos/{transaction.REPOSITORY}/git/ref/tags/{self.TAG}":
                return {
                    "ref": f"refs/tags/{self.TAG}",
                    "object": {"type": "tag", "sha": self.TAG_OBJECT},
                }
            if path == f"/repos/{transaction.REPOSITORY}/git/tags/{self.TAG_OBJECT}":
                return {"tagger": {"date": "2026-08-22T12:00:00Z"}}
            if path == f"/repos/{transaction.REPOSITORY}/git/commits/{self.SOURCE}":
                return {"committer": {"date": "2026-08-22T12:00:00Z"}}
            if path == f"/repos/{transaction.REPOSITORY}/releases/tags/{self.TAG}":
                return {
                    "id": 40,
                    "tag_name": self.TAG,
                    "target_commitish": self.SOURCE,
                    "published_at": release_published,
                }
            raise AssertionError("unexpected GitHub path: " + path)

        return github_get

    def _verify(
        self,
        *,
        associations=None,
        response_mutator=None,
        merge_status_error=None,
        require_main_tip=True,
        **times,
    ):
        responses = self._responses(**times)
        association_rows = [{"number": 17}] if associations is None else associations

        def github_get(path):
            document = copy.deepcopy(responses(path))
            if response_mutator is not None:
                response_mutator(path, document)
            return document

        with mock.patch.object(transaction, "github_get", side_effect=github_get), mock.patch.object(
            transaction,
            "github_get_list",
            return_value=association_rows,
        ), mock.patch.object(
            transaction,
            "github_require_pull_merged",
            side_effect=merge_status_error,
        ) as merged_check:
            receipt = transaction.verify_release_identity(
                self.SOURCE,
                self.TAG,
                self.Contract(),
                b"- reviewed transaction\n",
                require_main_tip=require_main_tip,
            )
        pull_number = association_rows[0]["number"]
        merged_check.assert_called_once_with(
            f"/repos/{transaction.REPOSITORY}/pulls/{pull_number}/merge"
        )
        return receipt

    def test_main_ci_platform_start_release_and_completion_order_is_accepted(self):
        receipt = self._verify(
            ci_updated="2026-08-22T12:00:00Z",
            platform_started="2026-08-22T12:00:00Z",
            release_published="2026-08-22T12:01:00Z",
            platform_updated="2026-08-22T12:01:00Z",
        )
        self.assertEqual(receipt["sourceRevision"], self.SOURCE)
        self.assertEqual(receipt["releasePublishedAt"], "2026-08-22T12:01:00Z")

    def test_later_protected_main_accepts_only_exact_release_ancestry(self):
        times = {
            "ci_updated": "2026-08-22T12:00:00Z",
            "platform_started": "2026-08-22T12:00:00Z",
            "release_published": "2026-08-22T12:01:00Z",
            "platform_updated": "2026-08-22T12:01:00Z",
        }
        receipt = self._verify(
            require_main_tip=False,
            main_sha=self.LATER_MAIN,
            comparison={
                "status": "ahead",
                "merge_base_commit": {"sha": self.SOURCE},
                "base_commit": {"sha": self.SOURCE},
            },
            **times,
        )
        self.assertEqual(receipt["sourceRevision"], self.SOURCE)

        invalid = {
            "diverged main": {
                "status": "diverged",
                "merge_base_commit": {"sha": self.SOURCE},
                "base_commit": {"sha": self.SOURCE},
            },
            "moved source base": {
                "status": "ahead",
                "merge_base_commit": {"sha": self.BASE},
                "base_commit": {"sha": self.BASE},
            },
        }
        for label, comparison in invalid.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                transaction.TransactionError,
                "PROTECTED_MAIN_ANCESTRY_INVALID",
            ):
                self._verify(
                    require_main_tip=False,
                    main_sha=self.LATER_MAIN,
                    comparison=comparison,
                    **times,
                )

        with self.assertRaisesRegex(
            transaction.TransactionError, "PROTECTED_MAIN_HEAD_MOVED"
        ):
            self._verify(main_sha=self.LATER_MAIN, **times)

    def test_public_omitted_or_null_merge_commit_sha_is_accepted_with_strong_identity(self):
        delete = object()
        for name, value in (("omitted", delete), ("null", None)):
            def mutate(path, document, *, value=value):
                if path == f"/repos/{transaction.REPOSITORY}/pulls/17":
                    if value is delete:
                        document.pop("merge_commit_sha")
                    else:
                        document["merge_commit_sha"] = value

            with self.subTest(name=name):
                receipt = self._verify(
                    response_mutator=mutate,
                    ci_updated="2026-08-22T12:00:00Z",
                    platform_started="2026-08-22T12:00:00Z",
                    release_published="2026-08-22T12:01:00Z",
                    platform_updated="2026-08-22T12:01:00Z",
                )
                self.assertEqual(receipt["pullRequestNumber"], 17)
                self.assertEqual(receipt["pullHeadSha"], self.HEAD)

    def test_distinct_valid_merge_timestamps_change_the_plan_bound_identity(self):
        receipts = []
        for merged_at in (
            "2026-08-22T11:58:00+00:00",
            "2026-08-22T11:58:01Z",
        ):
            def mutate(path, document, *, merged_at=merged_at):
                if path == f"/repos/{transaction.REPOSITORY}/pulls/17":
                    document["merged_at"] = merged_at

            receipts.append(
                self._verify(
                    response_mutator=mutate,
                    ci_updated="2026-08-22T12:00:00Z",
                    platform_started="2026-08-22T12:00:00Z",
                    release_published="2026-08-22T12:01:00Z",
                    platform_updated="2026-08-22T12:01:00Z",
                )
            )

        self.assertEqual(receipts[0]["pullMergedAt"], "2026-08-22T11:58:00Z")
        self.assertEqual(receipts[1]["pullMergedAt"], "2026-08-22T11:58:01Z")
        self.assertNotEqual(receipts[0], receipts[1])
        plan_hashes = [
            transaction.sha256_bytes(
                transaction.canonical_json({"source": receipt})
            )
            for receipt in receipts
        ]
        self.assertNotEqual(plan_hashes[0], plan_hashes[1])

    def test_missing_conflicting_and_arbitrary_associations_fail_closed(self):
        cases = (
            ("missing", []),
            ("conflicting", [{"number": 17}, {"number": 18}]),
            ("non-object", [17]),
            ("missing-number", [{}]),
            ("arbitrary-number", [{"number": 18}]),
        )
        times = {
            "ci_updated": "2026-08-22T12:00:00Z",
            "platform_started": "2026-08-22T12:00:00Z",
            "release_published": "2026-08-22T12:01:00Z",
            "platform_updated": "2026-08-22T12:01:00Z",
        }
        for name, associations in cases:
            with self.subTest(name=name), self.assertRaises(transaction.TransactionError):
                self._verify(associations=associations, **times)

    def test_pr_merge_base_head_tree_signature_and_owner_mutants_fail_closed(self):
        delete = object()
        pull_path = f"/repos/{transaction.REPOSITORY}/pulls/17"
        source_path = f"/repos/{transaction.REPOSITORY}/commits/{self.SOURCE}"
        head_path = f"/repos/{transaction.REPOSITORY}/commits/{self.HEAD}"
        cases = (
            ("conflicting-merge-commit", pull_path, ("merge_commit_sha",), "f" * 40),
            ("wrong-merge-commit-type", pull_path, ("merge_commit_sha",), 17),
            ("not-merged", pull_path, ("merged",), False),
            ("open", pull_path, ("state",), "open"),
            ("draft", pull_path, ("draft",), True),
            ("missing-merge-time", pull_path, ("merged_at",), None),
            ("malformed-merge-time", pull_path, ("merged_at",), "not-a-time"),
            ("wrong-base-ref", pull_path, ("base", "ref"), "release"),
            ("wrong-base-label", pull_path, ("base", "label"), "other:main"),
            ("wrong-base-repository", pull_path, ("base", "repo", "full_name"), "other/repository"),
            ("wrong-base-owner", pull_path, ("base", "user", "login"), "other-owner"),
            ("wrong-base-parent", pull_path, ("base", "sha"), "f" * 40),
            ("wrong-head-repository", pull_path, ("head", "repo", "full_name"), "other/repository"),
            ("wrong-head-owner", pull_path, ("head", "user", "login"), "other-owner"),
            ("wrong-head-label", pull_path, ("head", "label"), "other:branch"),
            ("malformed-head", pull_path, ("head", "sha"), "not-a-sha"),
            ("wrong-pr-author", pull_path, ("user", "login"), "other-owner"),
            ("wrong-owner", pull_path, ("merged_by", "login"), "other-owner"),
            ("unsigned-source", source_path, ("commit", "verification", "verified"), False),
            ("wrong-source-parent", source_path, ("parents",), [{"sha": "f" * 40}]),
            ("unsigned-head", head_path, ("commit", "verification", "verified"), False),
            ("wrong-head-tree", head_path, ("commit", "tree", "sha"), "f" * 40),
        )
        times = {
            "ci_updated": "2026-08-22T12:00:00Z",
            "platform_started": "2026-08-22T12:00:00Z",
            "release_published": "2026-08-22T12:01:00Z",
            "platform_updated": "2026-08-22T12:01:00Z",
        }
        for name, endpoint, keys, value in cases:
            def mutate(path, document, *, endpoint=endpoint, keys=keys, value=value):
                if path != endpoint:
                    return
                target = document
                for key in keys[:-1]:
                    target = target[key]
                if value is delete:
                    target.pop(keys[-1])
                else:
                    target[keys[-1]] = value

            with self.subTest(name=name), self.assertRaises(transaction.TransactionError):
                self._verify(response_mutator=mutate, **times)

    def test_authoritative_merge_endpoint_failure_stops_release_verification(self):
        with self.assertRaisesRegex(transaction.TransactionError, "GITHUB_PULL_NOT_MERGED"):
            self._verify(
                merge_status_error=transaction.TransactionError(
                    "GITHUB_PULL_NOT_MERGED"
                ),
                ci_updated="2026-08-22T12:00:00Z",
                platform_started="2026-08-22T12:00:00Z",
                release_published="2026-08-22T12:01:00Z",
                platform_updated="2026-08-22T12:01:00Z",
            )

    def test_authoritative_merge_endpoint_requires_exact_empty_204(self):
        class Response:
            def __init__(self, status, payload=b"", url="https://api.github.com/example"):
                self.status = status
                self.payload = payload
                self.url = url

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return self.url

            def read(self, _size):
                return self.payload

        path = f"/repos/{transaction.REPOSITORY}/pulls/17/merge"
        url = transaction.GITHUB_API + path
        with mock.patch.object(
            transaction, "github_urlopen", return_value=Response(204, url=url)
        ):
            transaction.github_require_pull_merged(path)

        rejected = (
            ("wrong-status", Response(200, url=url)),
            ("body-on-204", Response(204, b"x", url=url)),
            ("same-origin-redirect", Response(204, url=url + "?redirected=1")),
            ("redirect", Response(204, url="https://example.invalid/redirect")),
        )
        for name, response in rejected:
            with self.subTest(name=name), mock.patch.object(
                transaction, "github_urlopen", return_value=response
            ), self.assertRaises(transaction.TransactionError):
                transaction.github_require_pull_merged(path)

        not_merged = transaction.urllib.error.HTTPError(
            "https://api.github.com/example", 404, "not merged", {}, None
        )
        with mock.patch.object(
            transaction, "github_urlopen", side_effect=not_merged
        ), self.assertRaisesRegex(transaction.TransactionError, "GITHUB_PULL_NOT_MERGED"):
            transaction.github_require_pull_merged(path)
        not_merged.close()

    def test_all_github_helpers_reject_redirects_before_following(self):
        request = transaction.urllib.request.Request(
            transaction.GITHUB_API + "/repos/example/example"
        )
        sentinel = object()
        with mock.patch.object(
            transaction.urllib.request, "build_opener"
        ) as build_opener:
            build_opener.return_value.open.return_value = sentinel
            self.assertIs(transaction.github_urlopen(request), sentinel)
        handler = build_opener.call_args.args[0]
        self.assertIsInstance(handler, transaction.GitHubRejectRedirectHandler)
        build_opener.return_value.open.assert_called_once_with(request, timeout=20)

        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status), self.assertRaisesRegex(
                transaction.TransactionError, "GITHUB_REDIRECT_INVALID"
            ):
                handler.redirect_request(
                    request,
                    None,
                    status,
                    "redirect",
                    {},
                    request.full_url + "?same-origin-redirect=1",
                )

        class Response:
            status = 200

            def __init__(self, url):
                self.url = url

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return self.url

            def read(self, _size):
                return b"{}"

        path = "/repos/example/example"
        exact_url = transaction.GITHUB_API + path
        for name, redirected_url in (
            ("same-origin", exact_url + "?redirected=1"),
            ("cross-origin", "https://example.invalid/redirect"),
        ):
            with self.subTest(helper="github_request", name=name), mock.patch.object(
                transaction, "github_urlopen", return_value=Response(redirected_url)
            ), self.assertRaisesRegex(
                transaction.TransactionError, "GITHUB_REDIRECT_INVALID"
            ):
                transaction.github_request(path)

    def test_only_reviewed_one_time_release_tag_reaches_public_reads(self):
        self.assertEqual(transaction.AUTHORIZED_RELEASE_TAG, "v0.1.37")
        for rejected in (
            "v0.1.0",
            "v0.1.21",
            "v0.1.22",
            "v0.1.23",
            "v0.1.24",
            "v0.1.25",
            "v0.1.26",
            "v0.1.27",
            "v0.1.28",
            "v0.1.29",
            "v0.1.30",
            "v0.1.31",
            "v0.1.32",
            "v9.9.9",
        ):
            with self.subTest(rejected=rejected), mock.patch.object(
                transaction, "github_get"
            ) as github_get:
                with self.assertRaisesRegex(
                    transaction.TransactionError, "RELEASE_INPUT_INVALID"
                ):
                    transaction.verify_release_identity(
                        self.SOURCE,
                        rejected,
                        self.Contract(),
                        b"- reviewed transaction\n",
                    )
                github_get.assert_not_called()

    def test_release_after_platform_completion_fails_closed(self):
        with self.assertRaisesRegex(transaction.TransactionError, "RELEASE_ORDER_INVALID"):
            self._verify(
                ci_updated="2026-08-22T12:00:00Z",
                platform_started="2026-08-22T12:00:30Z",
                release_published="2026-08-22T12:02:00Z",
                platform_updated="2026-08-22T12:01:00Z",
            )

    def test_platform_cannot_start_before_required_main_ci_completes(self):
        with self.assertRaisesRegex(transaction.TransactionError, "RELEASE_ORDER_INVALID"):
            self._verify(
                ci_updated="2026-08-22T12:00:00Z",
                platform_started="2026-08-22T11:59:00Z",
                release_published="2026-08-22T12:00:30Z",
                platform_updated="2026-08-22T12:01:00Z",
            )


class CurrentReleaseExecutionModeTests(unittest.TestCase):
    def test_build_plan_revalidates_immutable_release_by_main_ancestry(self):
        target = mock.Mock(release_tag=transaction.AUTHORIZED_RELEASE_TAG)
        custody = {"sourceRevision": "a" * 40}
        with mock.patch.object(
            transaction, "load_desired", return_value={}
        ), mock.patch.object(
            transaction, "desired_operations", return_value=[]
        ), mock.patch.object(
            transaction, "load_module", return_value=object()
        ), mock.patch.object(
            transaction, "read_regular", return_value=b"reviewed fragment\n"
        ), mock.patch.object(
            transaction,
            "verify_release_identity",
            return_value={"sourceTreeSha": "b" * 40},
        ) as verify_release, mock.patch.object(
            transaction,
            "validate_custody",
            side_effect=RuntimeError("stop after release validation"),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "stop after release validation"
            ):
                transaction.build_plan(object(), target, custody)
        self.assertEqual(
            verify_release.call_args.args[:2],
            ("a" * 40, transaction.AUTHORIZED_RELEASE_TAG),
        )
        self.assertIs(
            verify_release.call_args.kwargs["require_main_tip"], False
        )

    def test_apply_revalidates_immutable_release_by_main_ancestry(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            transaction, "JOURNAL_PATH", Path(temporary) / "journal.json"
        ), mock.patch.object(
            transaction,
            "validate_plan_bindings",
            side_effect=RuntimeError("stop after release validation"),
        ) as validate:
            with self.assertRaisesRegex(
                RuntimeError, "stop after release validation"
            ):
                transaction.apply(
                    {}, "a" * 64, object(), object(), {"sourceRevision": "b" * 40}
                )
        validate.assert_called_once_with(
            {},
            "a" * 64,
            mock.ANY,
            mock.ANY,
            {"sourceRevision": "b" * 40},
            require_main_tip=False,
        )


class DesiredOperationTests(unittest.TestCase):
    def setUp(self):
        self.desired = json.loads(DESIRED_PATH.read_text(encoding="utf-8"))

    def test_reviewed_bundle_maps_to_exact_23_operation_sequence(self):
        operations = transaction.desired_operations(self.desired)
        self.assertEqual(len(operations), 23)
        self.assertEqual(
            [operation["phase"] for operation in operations],
            ["split"] * 6
            + ["namespaced"] * 12
            + ["watchers"] * 2
            + ["shared"] * 2
            + ["broad-delete"],
        )
        self.assertEqual(len({operation["id"] for operation in operations}), 23)
        self.assertEqual(
            operations[-1],
            {
                "id": "delete:ClusterRoleBinding:cluster-reconciler-flux-system",
                "phase": "broad-delete",
                "action": "delete",
                "kind": "ClusterRoleBinding",
                "namespace": None,
                "name": "cluster-reconciler-flux-system",
            },
        )
        self.assertEqual(
            {operation["kind"] for operation in operations},
            {"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "ServiceAccount", "Deployment"},
        )

    def test_inventory_add_remove_duplicate_and_deletion_mutations_fail_closed(self):
        mutations = {}

        candidate = copy.deepcopy(self.desired)
        candidate["clusterRbacObjects"].pop()
        mutations["missing cluster object"] = candidate

        candidate = copy.deepcopy(self.desired)
        candidate["clusterRbacObjects"].append(
            copy.deepcopy(candidate["clusterRbacObjects"][0])
        )
        mutations["duplicate cluster object"] = candidate

        candidate = copy.deepcopy(self.desired)
        candidate["namespacedObjects"].pop()
        mutations["missing namespaced object"] = candidate

        candidate = copy.deepcopy(self.desired)
        candidate["deletionIdentities"][0]["name"] = "arbitrary-binding"
        mutations["arbitrary deletion"] = candidate

        candidate = copy.deepcopy(self.desired)
        candidate["deletionIdentities"][0]["namespace"] = None
        mutations["nonliteral deletion fields"] = candidate

        for label, candidate in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(transaction.TransactionError):
                    transaction.desired_operations(candidate)

    def test_controller_inventory_and_single_watcher_gate_are_exact(self):
        mutations = {}

        candidate = copy.deepcopy(self.desired)
        del candidate["controllerArgs"]["helm-controller"]
        mutations["missing controller"] = candidate

        candidate = copy.deepcopy(self.desired)
        candidate["controllerArgs"]["source-controller"] = []
        mutations["extra controller"] = candidate

        candidate = copy.deepcopy(self.desired)
        args = candidate["controllerArgs"]["helm-controller"]
        args.remove("--feature-gates=DisableConfigWatchers=true")
        mutations["watcher gate absent"] = candidate

        candidate = copy.deepcopy(self.desired)
        candidate["controllerArgs"]["helm-controller"].append(
            "--feature-gates=DisableConfigWatchers=true"
        )
        mutations["watcher gate duplicate"] = candidate

        for label, candidate in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(transaction.TransactionError):
                    transaction.desired_operations(candidate)

    def test_load_desired_rejects_extra_top_level_authority(self):
        candidate = copy.deepcopy(self.desired)
        candidate["applyAllAccessYaml"] = True
        payload = transaction.canonical_json(candidate)
        with mock.patch.object(transaction, "read_regular", return_value=payload):
            with self.assertRaises(transaction.TransactionError):
                transaction.load_desired()


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.receipts = Path(self.temporary.name) / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.read_regular = lambda path, **_kwargs: Path(path).read_bytes()
        self.plan_sha256 = "a" * 64
        self.source_revision = "b" * 40
        self.journal = _Journal("c" * 64, "operation", "committed")
        self.journal.document["state"] = "committed"
        self.journal.document["planSha256"] = self.plan_sha256
        self.journal.document["sourceRevision"] = self.source_revision

    def set_terminal_evidence(self):
        result = transaction.terminal_result(self.journal.document["state"])
        label, phase = (
            ("post-proof-final", "final")
            if result == "pass"
            else ("rollback-terminal", "rollback")
        )
        public_oracle = {
            "label": label,
            "matrixPhase": phase,
            "receiptCount": transaction.ORACLE_PHASE_COUNTS[phase],
            "receiptsSha256": "d" * 64,
            "file": f"oracle.{label}.json",
            "fileSha256": "e" * 64,
        }
        self.journal.document["oracleEvidenceRecords"] = {
            label: copy.deepcopy(public_oracle)
        }
        rows = []
        operation_ids = ["operation"] + [
            f"operation-{index:02d}"
            for index in range(transaction.TRANSACTION_TARGET_COUNT - 1)
        ]
        self.journal.document["operations"] = {
            identifier: {"state": "verified"} for identifier in operation_ids
        }
        evidence = {
            "bindingGraph": {
                "rows": rows,
                "sha256": transaction.sha256_bytes(
                    transaction.canonical_json(rows)
                ),
            },
            "authorizationEvidence": public_oracle,
            "terminalTargetInventory": [
                {"id": identifier, "present": False}
                for identifier in operation_ids
            ],
        }
        self.journal.document["terminalEvidence"] = copy.deepcopy(evidence)
        self.journal.document["terminalEvidenceSha256"] = (
            transaction.sha256_bytes(transaction.canonical_json(evidence))
        )
        return evidence

    def test_identical_receipt_is_idempotent_across_retry_time(self):
        first = dt.datetime(2026, 8, 22, 12, 0, tzinfo=dt.timezone.utc)
        later = first + dt.timedelta(minutes=30)
        evidence = self.set_terminal_evidence()
        with mock.patch.object(transaction, "RECEIPT_ROOT", self.receipts), mock.patch.object(
            transaction, "ensure_root_directory"
        ), mock.patch.object(transaction, "read_regular", side_effect=self.read_regular), mock.patch.object(
            transaction, "utc_now", side_effect=[first, later]
        ):
            first_path = transaction.write_receipt(
                "pass", self.plan_sha256, self.source_revision, self.journal, evidence
            )
            second_path = transaction.write_receipt(
                "pass", self.plan_sha256, self.source_revision, self.journal, evidence
            )
        self.assertEqual(first_path, second_path)
        document = json.loads(first_path.read_text(encoding="utf-8"))
        self.assertEqual(document["recordedAt"], "2026-08-22T12:00:00Z")

    def test_same_receipt_path_with_different_evidence_is_a_collision(self):
        now = dt.datetime(2026, 8, 22, 12, 0, tzinfo=dt.timezone.utc)
        evidence = self.set_terminal_evidence()
        with mock.patch.object(transaction, "RECEIPT_ROOT", self.receipts), mock.patch.object(
            transaction, "ensure_root_directory"
        ), mock.patch.object(transaction, "read_regular", side_effect=self.read_regular), mock.patch.object(
            transaction, "utc_now", return_value=now
        ):
            transaction.write_receipt(
                "pass", self.plan_sha256, self.source_revision, self.journal, evidence
            )
            with self.assertRaisesRegex(
                transaction.TransactionError,
                r"RECEIPT_(?:TERMINAL_EVIDENCE_MISMATCH|RECORD_COLLISION)",
            ):
                transaction.write_receipt(
                    "pass",
                    self.plan_sha256,
                    self.source_revision,
                    self.journal,
                    {**evidence, "terminalTargetInventory": []},
                )

    def test_terminal_receipt_recovers_no_replace_link_publication_window(self):
        now = dt.datetime(2026, 8, 22, 12, 0, tzinfo=dt.timezone.utc)
        evidence = self.set_terminal_evidence()
        with mock.patch.object(
            transaction, "RECEIPT_ROOT", self.receipts
        ), mock.patch.object(
            transaction, "ensure_root_directory"
        ), mock.patch.object(
            transaction, "utc_now", return_value=now
        ), mock.patch.object(
            transaction,
            "publish_once",
            side_effect=OSError("injected link-window crash"),
        ):
            with self.assertRaisesRegex(OSError, "link-window crash"):
                transaction.write_receipt(
                    "pass",
                    self.plan_sha256,
                    self.source_revision,
                    self.journal,
                    evidence,
                )
        record = self.journal.document["receiptRecords"]["pass"]
        document = {
            "schema": transaction.RECEIPT_SCHEMA,
            "result": "pass",
            "planSha256": self.plan_sha256,
            "sourceRevision": self.source_revision,
            "journalSequence": record["journalSequence"],
            "journalState": record["journalState"],
            "evidenceSha256": record["evidenceSha256"],
            "recordedAt": record["recordedAt"],
        }
        path = self.receipts / f"pass.{self.plan_sha256}.json"
        pending = path.with_name(path.name + ".new")
        pending.write_bytes(transaction.canonical_json(document))
        pending.chmod(0o600)
        transaction.os.link(pending, path)
        with mock.patch.object(
            transaction, "RECEIPT_ROOT", self.receipts
        ), mock.patch.object(transaction, "ensure_root_directory"):
            transaction.write_receipt(
                "pass",
                self.plan_sha256,
                self.source_revision,
                self.journal,
                evidence,
            )
        self.assertFalse(pending.exists())
        self.assertEqual(path.stat().st_nlink, 1)

    def test_distinct_terminal_results_have_independent_receipts(self):
        first = dt.datetime(2026, 8, 22, 12, 0, tzinfo=dt.timezone.utc)
        later = first + dt.timedelta(minutes=1)
        with mock.patch.object(transaction, "RECEIPT_ROOT", self.receipts), mock.patch.object(
            transaction, "ensure_root_directory"
        ), mock.patch.object(transaction, "read_regular", side_effect=self.read_regular), mock.patch.object(
            transaction, "utc_now", side_effect=[first, later]
        ):
            self.journal.document["state"] = "recovery-required"
            recovery = transaction.write_receipt(
                "recovery-required",
                self.plan_sha256,
                self.source_revision,
                self.journal,
                {"cause": "interrupted"},
            )
            self.journal.document["state"] = "rolled-back"
            terminal_evidence = self.set_terminal_evidence()
            rolled_back = transaction.write_receipt(
                "rolled-back",
                self.plan_sha256,
                self.source_revision,
                self.journal,
                terminal_evidence,
            )
        self.assertNotEqual(recovery, rolled_back)
        self.assertTrue(recovery.is_file())
        self.assertTrue(rolled_back.is_file())
        self.assertEqual(
            set(self.journal.document["receiptRecords"]),
            {"recovery-required", "rolled-back"},
        )


class OracleEvidenceTests(unittest.TestCase):
    PLAN = "a" * 64
    SOURCE = "b" * 40

    @staticmethod
    def evidence(phase):
        count = transaction.ORACLE_PHASE_COUNTS[phase]
        return transaction.build_oracle_evidence(
            phase, [_oracle_receipt(index) for index in range(count)]
        )

    @staticmethod
    def journal(state="prepared"):
        journal = transaction.Journal(
            OracleEvidenceTests.PLAN,
            OracleEvidenceTests.SOURCE,
            "c" * 64,
        )
        journal.document["attemptId"] = "d" * 64
        journal.document["state"] = state

        def write():
            journal.document["sequence"] += 1

        journal.write = write
        return journal

    def test_closed_phase_counts_are_accepted_and_missing_row_fails(self):
        for phase, count in transaction.ORACLE_PHASE_COUNTS.items():
            with self.subTest(phase=phase):
                evidence = self.evidence(phase)
                self.assertEqual(evidence["receiptCount"], count)
                with self.assertRaisesRegex(
                    transaction.TransactionError,
                    "AUTHORIZATION_RECEIPT_COUNT_INVALID",
                ):
                    transaction.build_oracle_evidence(
                        phase,
                        [_oracle_receipt(index) for index in range(count - 1)],
                    )

    def test_secret_bearing_extra_fields_malformed_controls_and_overflow_fail(self):
        mutations = []
        extra = _oracle_receipt()
        extra["token"] = "do-not-persist"
        mutations.append(extra)
        request_extra = _oracle_receipt()
        request_extra["request"]["credential"] = "do-not-persist"
        mutations.append(request_extra)
        controls = _oracle_receipt()
        controls["controls"][2]["authorization"] = "ALLOWED"
        mutations.append(controls)
        for receipt in mutations:
            with self.subTest(receipt=receipt.keys()):
                with self.assertRaises(transaction.TransactionError):
                    transaction.normalized_oracle_receipt(receipt)
        with mock.patch.object(transaction, "ORACLE_PHASE_MAX_BYTES", 1):
            with self.assertRaisesRegex(
                transaction.TransactionError, "AUTHORIZATION_PHASE_TOO_LARGE"
            ):
                self.evidence("rollback")

    def test_oracle_request_must_echo_the_exact_caller_tuple(self):
        receipt = _oracle_receipt()
        receipt["request"]["namespace"] = "kube-system"

        class Oracle:
            @staticmethod
            def run_oracle(_client, **_kwargs):
                return 0, copy.deepcopy(receipt)

        with self.assertRaisesRegex(
            transaction.TransactionError, "AUTHORIZATION_ORACLE_REQUEST_MISMATCH"
        ):
            transaction.run_oracle_request(
                Oracle,
                object(),
                subject="system:serviceaccount:flux-system:source-controller",
                verb="get",
                group="",
                resource="pods",
                namespace="flux-system",
                expected="ALLOWED",
            )

    def test_journal_first_crash_is_republished_and_tamper_or_orphan_fails(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            evidence_root = Path(temporary) / "evidence"
            evidence_root.mkdir(mode=0o700)
            journal = self.journal()
            evidence = self.evidence("rollback")
            with mock.patch.object(
                transaction, "EVIDENCE_ROOT", evidence_root
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(
                transaction,
                "publish_oracle_evidence_records",
                side_effect=transaction.TransactionError("injected crash"),
            ):
                with self.assertRaisesRegex(
                    transaction.TransactionError, "injected crash"
                ):
                    transaction.persist_oracle_evidence(
                        "rollback-terminal",
                        evidence,
                        self.PLAN,
                        self.SOURCE,
                        journal,
                    )
            self.assertEqual(list(evidence_root.iterdir()), [])
            record = journal.document["oracleEvidenceRecords"]["rollback-terminal"]
            path = evidence_root / record["file"]
            pending = path.with_name(path.name + ".new")
            pending.write_bytes(transaction.canonical_json(record["document"]))
            pending.chmod(0o600)
            transaction.os.link(pending, path)
            with mock.patch.object(
                transaction, "EVIDENCE_ROOT", evidence_root
            ), mock.patch.object(transaction, "ensure_root_directory"):
                transaction.publish_oracle_evidence_records(journal)
                self.assertFalse(pending.exists())
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(
                    transaction.sha256_bytes(path.read_bytes()),
                    record["fileSha256"],
                )
                path.write_bytes(b"tampered\n")
                with self.assertRaises(transaction.TransactionError):
                    transaction.publish_oracle_evidence_records(journal)
                path.write_bytes(transaction.canonical_json(record["document"]))
                orphan = evidence_root / "orphan.json"
                orphan.write_bytes(b"orphan\n")
                orphan.chmod(0o600)
                with self.assertRaisesRegex(
                    transaction.TransactionError, "ORACLE_EVIDENCE_ORPHAN_FILE"
                ):
                    transaction.publish_oracle_evidence_records(journal)

    def test_embedded_oracle_record_rejects_post_journal_secret_injection(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            evidence_root = Path(temporary) / "evidence"
            evidence_root.mkdir(mode=0o700)
            journal = self.journal()
            with mock.patch.object(
                transaction, "EVIDENCE_ROOT", evidence_root
            ), mock.patch.object(transaction, "ensure_root_directory"):
                transaction.persist_oracle_evidence(
                    "rollback-terminal",
                    self.evidence("rollback"),
                    self.PLAN,
                    self.SOURCE,
                    journal,
                )
            candidate = copy.deepcopy(journal.document)
            candidate["oracleEvidenceRecords"]["rollback-terminal"]["document"][
                "receipts"
            ][0]["token"] = "injected"
            with self.assertRaises(transaction.TransactionError):
                transaction.parse_journal_payload(transaction.canonical_json(candidate))

    def test_terminal_journal_binds_complete_evidence_and_oracle_document(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            evidence_root = Path(temporary) / "evidence"
            evidence_root.mkdir(mode=0o700)
            journal = self.journal()
            with mock.patch.object(
                transaction, "EVIDENCE_ROOT", evidence_root
            ), mock.patch.object(transaction, "ensure_root_directory"):
                public_oracle = transaction.persist_oracle_evidence(
                    "post-proof-final",
                    self.evidence("final"),
                    self.PLAN,
                    self.SOURCE,
                    journal,
                )
            inventory = [
                {"id": f"operation-{index:02d}", "present": False}
                for index in range(transaction.TRANSACTION_TARGET_COUNT)
            ]
            graph_rows = []
            terminal_evidence = {
                "bindingGraph": {
                    "rows": graph_rows,
                    "sha256": transaction.sha256_bytes(
                        transaction.canonical_json(graph_rows)
                    ),
                },
                "authorizationEvidence": public_oracle,
                "terminalTargetInventory": inventory,
            }
            journal.document.update(
                {
                    "state": "committed",
                    "phase": "committed",
                    "operations": {
                        row["id"]: {"state": "verified"} for row in inventory
                    },
                    "terminalEvidence": terminal_evidence,
                    "terminalEvidenceSha256": transaction.sha256_bytes(
                        transaction.canonical_json(terminal_evidence)
                    ),
                }
            )
            payload = transaction.canonical_json(journal.document)
            self.assertEqual(
                transaction.parse_journal_payload(payload), journal.document
            )

            candidate = copy.deepcopy(journal.document)
            candidate["terminalEvidence"]["authorizationEvidence"][
                "receiptsSha256"
            ] = "f" * 64
            candidate["terminalEvidenceSha256"] = transaction.sha256_bytes(
                transaction.canonical_json(candidate["terminalEvidence"])
            )
            with self.assertRaisesRegex(
                transaction.TransactionError, "JOURNAL_TERMINAL_ORACLE_INVALID"
            ):
                transaction.parse_journal_payload(
                    transaction.canonical_json(candidate)
                )


class VerificationEvidenceTests(unittest.TestCase):
    PLAN = "a" * 64
    SOURCE = "b" * 40
    NOW = dt.datetime(2026, 8, 22, 12, 0, tzinfo=dt.timezone.utc)

    @classmethod
    def evidence(cls):
        graph_rows = []
        return {
            "bindingGraph": {
                "rows": graph_rows,
                "sha256": transaction.sha256_bytes(
                    transaction.canonical_json(graph_rows)
                ),
            },
            "authorizationEvidence": transaction.build_oracle_evidence(
                "final",
                [
                    _oracle_receipt(index)
                    for index in range(transaction.ORACLE_PHASE_COUNTS["final"])
                ],
            ),
            "terminalTargetInventory": [
                {"id": f"operation-{index:02d}", "present": False}
                for index in range(transaction.TRANSACTION_TARGET_COUNT)
            ],
        }

    @classmethod
    def journal(cls, *, counter=0):
        journal = transaction.Journal(cls.PLAN, cls.SOURCE, "d" * 64)
        fresh_evidence = cls.evidence()
        terminal_evidence = copy.deepcopy(fresh_evidence)
        public_oracle = {
            "label": "post-proof-final",
            "matrixPhase": "final",
            "receiptCount": transaction.ORACLE_PHASE_COUNTS["final"],
            "receiptsSha256": fresh_evidence["authorizationEvidence"][
                "receiptsSha256"
            ],
            "file": "oracle.post-proof-final.json",
            "fileSha256": "f" * 64,
        }
        terminal_evidence["authorizationEvidence"] = public_oracle
        terminal_digest = transaction.sha256_bytes(
            transaction.canonical_json(terminal_evidence)
        )
        journal.document.update(
            {
                "attemptId": "e" * 64,
                "state": "committed",
                "phase": "committed",
                "sequence": 1,
                "verificationCounter": counter,
                "pendingVerification": None,
                "terminalEvidence": terminal_evidence,
                "terminalEvidenceSha256": terminal_digest,
                "oracleEvidenceRecords": {
                    "post-proof-final": copy.deepcopy(public_oracle)
                },
                "operations": {
                    row["id"]: {"state": "verified"}
                    for row in terminal_evidence["terminalTargetInventory"]
                },
                "receiptRecords": {
                    "pass": {
                        "result": "pass",
                        "evidenceSha256": terminal_digest,
                        "recordedAt": "2026-08-22T11:59:00Z",
                        "journalSequence": 1,
                        "journalState": "committed",
                    }
                },
            }
        )

        def write():
            journal.document["sequence"] += 1

        journal.write = write
        return journal

    def test_same_second_verifies_are_distinct_and_index_above_32_succeeds(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            receipts = Path(temporary) / "receipts"
            receipts.mkdir(mode=0o700)
            journal = self.journal()
            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(transaction, "utc_now", return_value=self.NOW):
                first = transaction.write_verification_record(
                    "pass", self.PLAN, self.SOURCE, journal, self.evidence()
                )
                second = transaction.write_verification_record(
                    "pass", self.PLAN, self.SOURCE, journal, self.evidence()
                )
            self.assertNotEqual(first, second)
            self.assertEqual(journal.document["verificationCounter"], 2)
            self.assertIsNone(journal.document["pendingVerification"])
            self.assertEqual(
                json.loads(first.read_text())["recordedAt"],
                json.loads(second.read_text())["recordedAt"],
            )

            template = json.loads(second.read_text())
            previous_sha256 = journal.document["verificationChainSha256"]
            for index in range(3, 33):
                document = copy.deepcopy(template)
                document["verificationIndex"] = index
                document["previousVerificationSha256"] = previous_sha256
                payload = transaction.canonical_json(document)
                seeded = receipts / f"verify.{index:08d}.{self.PLAN}.json"
                seeded.write_bytes(payload)
                seeded.chmod(0o600)
                previous_sha256 = transaction.sha256_bytes(payload)
            journal.document["verificationCounter"] = 32
            journal.document["verificationChainSha256"] = previous_sha256
            journal.document["sequence"] = 100
            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(transaction, "utc_now", return_value=self.NOW):
                path = transaction.write_verification_record(
                    "pass", self.PLAN, self.SOURCE, journal, self.evidence()
                )
            self.assertIn("verify.00000033.", path.name)
            self.assertEqual(journal.document["verificationCounter"], 33)

    def test_pending_record_survives_crash_and_nlink_two_publish_then_next_verify(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            receipts = Path(temporary) / "receipts"
            receipts.mkdir(mode=0o700)
            journal = self.journal()
            real_publish = transaction.publish_pending_verification

            def crash_after_journal(candidate):
                if candidate.document.get("pendingVerification") is not None:
                    raise OSError("injected publication crash")
                return real_publish(candidate)

            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(
                transaction, "publish_pending_verification", side_effect=crash_after_journal
            ), mock.patch.object(transaction, "utc_now", return_value=self.NOW):
                with self.assertRaisesRegex(OSError, "publication crash"):
                    transaction.write_verification_record(
                        "pass", self.PLAN, self.SOURCE, journal, self.evidence()
                    )
            pending = journal.document["pendingVerification"]
            self.assertIsInstance(pending, dict)
            payload = transaction.canonical_json(pending)
            destination = receipts / f"verify.00000001.{self.PLAN}.json"
            temporary_path = destination.with_name(destination.name + ".new")
            temporary_path.write_bytes(payload)
            temporary_path.chmod(0o600)
            transaction.os.link(temporary_path, destination)
            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(transaction, "ensure_root_directory"):
                real_publish(journal)
            self.assertFalse(temporary_path.exists())
            self.assertEqual(destination.stat().st_nlink, 1)
            self.assertIsNone(journal.document["pendingVerification"])

            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(transaction, "utc_now", return_value=self.NOW):
                second = transaction.write_verification_record(
                    "pass", self.PLAN, self.SOURCE, journal, self.evidence()
                )
            self.assertIn("verify.00000002.", second.name)

    def test_history_gap_tamper_chain_change_and_orphan_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            receipts = Path(temporary) / "receipts"
            receipts.mkdir(mode=0o700)
            journal = self.journal()
            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(transaction, "utc_now", return_value=self.NOW):
                path = transaction.write_verification_record(
                    "pass", self.PLAN, self.SOURCE, journal, self.evidence()
                )
                payload = path.read_bytes()

                path.unlink()
                with self.assertRaises(transaction.TransactionError):
                    transaction.validate_verification_history(journal)
                path.write_bytes(payload)
                path.chmod(0o600)

                path.write_bytes(b"tampered\n")
                with self.assertRaises(transaction.TransactionError):
                    transaction.validate_verification_history(journal)
                path.write_bytes(payload)

                saved_chain = journal.document["verificationChainSha256"]
                journal.document["verificationChainSha256"] = "f" * 64
                with self.assertRaisesRegex(
                    transaction.TransactionError,
                    "VERIFICATION_HISTORY_CHAIN_MISMATCH",
                ):
                    transaction.validate_verification_history(journal)
                journal.document["verificationChainSha256"] = saved_chain

                orphan = receipts / f"verify.99999999.{self.PLAN}.json"
                orphan.write_bytes(payload)
                orphan.chmod(0o600)
                with self.assertRaisesRegex(
                    transaction.TransactionError,
                    "VERIFICATION_HISTORY_ORPHAN_FILE",
                ):
                    transaction.validate_verification_history(journal)

    def test_terminal_receipt_exact_bytes_recover_missing_and_block_corrupt_pending(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            receipts = Path(temporary) / "receipts"
            receipts.mkdir(mode=0o700)
            journal = self.journal()
            real_publish = transaction.publish_pending_verification

            def crash_with_pending(candidate):
                if candidate.document.get("pendingVerification") is not None:
                    raise OSError("injected pending crash")
                return real_publish(candidate)

            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(
                transaction, "ensure_root_directory"
            ), mock.patch.object(
                transaction,
                "publish_pending_verification",
                side_effect=crash_with_pending,
            ), mock.patch.object(transaction, "utc_now", return_value=self.NOW):
                with self.assertRaisesRegex(OSError, "pending crash"):
                    transaction.write_verification_record(
                        "pass", self.PLAN, self.SOURCE, journal, self.evidence()
                    )

            receipt = receipts / f"pass.{self.PLAN}.json"
            self.assertEqual(
                transaction.terminal_receipt_sha256(journal, "pass"),
                transaction.sha256_bytes(receipt.read_bytes()),
            )
            receipt.unlink()
            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(transaction, "ensure_root_directory"):
                transaction.validate_verification_history(journal)
            self.assertTrue(receipt.is_file())

            receipt.write_bytes(b"corrupt\n")
            pending_path = receipts / f"verify.00000001.{self.PLAN}.json"
            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(transaction, "ensure_root_directory"):
                with self.assertRaisesRegex(
                    transaction.TransactionError, "OUTPUT_PUBLISH_COLLISION"
                ):
                    real_publish(journal)
            self.assertFalse(pending_path.exists())
            self.assertIsNotNone(journal.document["pendingVerification"])

    def test_successor_rejects_unattributable_verification_chain_transitions(self):
        previous = transaction.Journal(
            self.PLAN, self.SOURCE, "d" * 64
        ).document
        previous["sequence"] = 1
        for mutation in (
            {"verificationChainSha256": "f" * 64},
            {"verificationCounter": 2},
        ):
            with self.subTest(mutation=mutation):
                successor = copy.deepcopy(previous)
                successor["sequence"] = 2
                successor.update(mutation)
                with self.assertRaisesRegex(
                    transaction.TransactionError,
                    "JOURNAL_TEMP_VERIFICATION_REGRESSION",
                ):
                    transaction.validate_journal_successor(previous, successor)

        pending = {"verificationIndex": 1, "reviewed": True}
        previous["verificationCounter"] = 1
        previous["pendingVerification"] = pending
        successor = copy.deepcopy(previous)
        successor["sequence"] = 2
        successor["pendingVerification"] = None
        successor["verificationChainSha256"] = "e" * 64
        with self.assertRaisesRegex(
            transaction.TransactionError,
            "JOURNAL_TEMP_VERIFICATION_REGRESSION",
        ):
            transaction.validate_journal_successor(previous, successor)

        successor["verificationChainSha256"] = transaction.sha256_bytes(
            transaction.canonical_json(pending)
        )
        transaction.validate_journal_successor(previous, successor)

    def test_terminal_inventory_rejects_missing_operation_and_substituted_id(self):
        journal = self.journal()
        transaction.validate_terminal_evidence_document(journal.document)
        candidate = copy.deepcopy(journal.document)
        removed_id = next(iter(candidate["operations"]))
        candidate["operations"].pop(removed_id)
        candidate["terminalEvidence"]["terminalTargetInventory"][0]["id"] = (
            "substituted-operation"
        )
        candidate["terminalEvidenceSha256"] = transaction.sha256_bytes(
            transaction.canonical_json(candidate["terminalEvidence"])
        )
        with self.assertRaisesRegex(
            transaction.TransactionError,
            "TERMINAL_EVIDENCE_INVENTORY_INVALID",
        ):
            transaction.validate_terminal_evidence_document(candidate)

    def test_malformed_evidence_never_creates_positive_pending_record(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            receipts = Path(temporary) / "receipts"
            receipts.mkdir(mode=0o700)
            journal = self.journal()
            evidence = self.evidence()
            evidence["authorizationEvidence"]["receipts"][0]["token"] = (
                "injected"
            )
            with mock.patch.object(
                transaction, "RECEIPT_ROOT", receipts
            ), mock.patch.object(transaction, "ensure_root_directory"):
                with self.assertRaises(transaction.TransactionError):
                    transaction.write_verification_record(
                        "pass", self.PLAN, self.SOURCE, journal, evidence
                    )
            self.assertEqual(journal.document["verificationCounter"], 0)
            self.assertIsNone(journal.document["pendingVerification"])


class TerminalModeTests(unittest.TestCase):
    def test_terminal_journal_refuses_recovery_state_regression(self):
        for state in ("committed", "rolled-back"):
            with self.subTest(state=state):
                journal = object.__new__(transaction.Journal)
                journal.document = {"state": state}
                journal.write = mock.Mock()
                with self.assertRaisesRegex(
                    transaction.TransactionError,
                    "TERMINAL_JOURNAL_RECOVERY_REGRESSION",
                ):
                    journal.mark_recovery_required()
                self.assertEqual(journal.document, {"state": state})
                journal.write.assert_not_called()

    def test_apply_preserves_rolled_back_state_when_terminal_exit_fails(self):
        plan_sha256 = "a" * 64
        source_revision = "b" * 40
        plan = {"target": {}, "targets": [{"phase": "split"}]}

        for failure_point in ("signal-unmask", "receipt"):
            with self.subTest(failure_point=failure_point), tempfile.TemporaryDirectory(
                dir=str(TEST_TEMP_ROOT)
            ) as temporary:
                journal = mock.Mock()
                journal.document = {"state": "prepared"}

                def mark_recovery_required():
                    journal.document["state"] = "recovery-required"

                journal.mark_recovery_required.side_effect = mark_recovery_required

                def finish_rollback(*_args):
                    journal.document["state"] = "rolled-back"
                    if failure_point == "signal-unmask":
                        raise transaction.Interrupted("SIGNAL_15")

                receipt_error = OSError("receipt publication failed")
                receipt_effect = receipt_error if failure_point == "receipt" else None
                with mock.patch.object(
                    transaction, "JOURNAL_PATH", Path(temporary) / "journal.json"
                ), mock.patch.object(
                    transaction, "validate_plan_bindings", return_value=object()
                ), mock.patch.object(
                    transaction, "compare_prestate"
                ), mock.patch.object(
                    transaction, "stable_baselines"
                ), mock.patch.object(
                    transaction, "Journal", return_value=journal
                ), mock.patch.object(
                    transaction.signal, "signal", return_value=signal.SIG_DFL
                ), mock.patch.object(
                    transaction,
                    "apply_operation",
                    side_effect=transaction.TransactionError("TRIGGER_ROLLBACK"),
                ), mock.patch.object(
                    transaction, "rollback_internal", side_effect=finish_rollback
                ), mock.patch.object(
                    transaction, "write_receipt", side_effect=receipt_effect
                ) as write_receipt:
                    with self.assertRaisesRegex(
                        transaction.RecoveryRequired,
                        "ROLLED_BACK_RECEIPT_INCOMPLETE",
                    ) as raised:
                        transaction.apply(
                            plan,
                            plan_sha256,
                            object(),
                            object(),
                            {"sourceRevision": source_revision},
                        )

                self.assertEqual(journal.document["state"], "rolled-back")
                self.assertEqual(journal.mark_recovery_required.call_count, 1)
                if failure_point == "signal-unmask":
                    write_receipt.assert_not_called()
                    self.assertIsInstance(
                        raised.exception.__cause__, transaction.Interrupted
                    )
                else:
                    write_receipt.assert_called_once()
                    self.assertIs(raised.exception.__cause__, receipt_error)

    def test_apply_persists_sanitized_forward_failure_before_rollback(self):
        plan_sha256 = "a" * 64
        source_revision = "b" * 40
        plan = {"target": {}, "targets": [{"phase": "split"}]}
        journal = mock.Mock()
        journal.document = {"state": "prepared"}
        events = []

        def record_failure(phase, error):
            events.append(("failure", phase, str(error)))

        def mark_recovery_required():
            events.append(("recovery",))
            journal.document["state"] = "recovery-required"

        def finish_rollback(*_args):
            events.append(("rollback",))
            journal.document["state"] = "rolled-back"

        journal.record_forward_failure.side_effect = record_failure
        journal.mark_recovery_required.side_effect = mark_recovery_required
        with tempfile.TemporaryDirectory(
            dir=str(TEST_TEMP_ROOT)
        ) as temporary, mock.patch.object(
            transaction, "JOURNAL_PATH", Path(temporary) / "journal.json"
        ), mock.patch.object(
            transaction, "validate_plan_bindings", return_value=object()
        ), mock.patch.object(
            transaction, "compare_prestate"
        ), mock.patch.object(
            transaction, "stable_baselines"
        ), mock.patch.object(
            transaction, "Journal", return_value=journal
        ), mock.patch.object(
            transaction.signal, "signal", return_value=signal.SIG_DFL
        ), mock.patch.object(
            transaction,
            "apply_operation",
            side_effect=transaction.TransactionError("FORWARD_FAILED"),
        ), mock.patch.object(
            transaction, "rollback_internal", side_effect=finish_rollback
        ), mock.patch.object(
            transaction, "write_receipt"
        ):
            with self.assertRaisesRegex(
                transaction.TransactionError, "APPLY_ROLLED_BACK"
            ):
                transaction.apply(
                    plan,
                    plan_sha256,
                    object(),
                    object(),
                    {"sourceRevision": source_revision},
                )

        self.assertEqual(
            events,
            [
                ("failure", "forward", "FORWARD_FAILED"),
                ("recovery",),
                ("rollback",),
            ],
        )

    def test_committed_transaction_refuses_rollback_and_requires_verify(self):
        plan_sha256 = "a" * 64
        source_revision = "b" * 40
        journal = mock.Mock()
        journal.document = {
            "planSha256": plan_sha256,
            "sourceRevision": source_revision,
            "state": "committed",
        }
        with mock.patch.dict(
            "os.environ",
            {
                "CONFIRM_FLUX_RBAC_ROLLBACK": (
                    f"rollback-reviewed-flux-rbac-{plan_sha256}"
                )
            },
            clear=True,
        ), mock.patch.object(
            transaction.Journal, "load", return_value=journal
        ), mock.patch.object(
            transaction, "validate_local_plan_bindings"
        ), mock.patch.object(
            transaction, "publish_oracle_evidence_records"
        ), mock.patch.object(
            transaction, "publish_pending_verification"
        ), mock.patch.object(
            transaction, "rollback_internal"
        ) as rollback_internal:
            with self.assertRaisesRegex(
                transaction.TransactionError, "COMMITTED_USE_VERIFY"
            ):
                transaction.rollback(
                    {},
                    plan_sha256,
                    object(),
                    object(),
                    {"sourceRevision": source_revision},
                )
        rollback_internal.assert_not_called()


class RollbackResponseLossTests(unittest.TestCase):
    def _created_target(self, desired):
        return {
            "id": "create:Role:flux-system:example",
            "action": "create",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "url": "/role/example",
            "prestate": {"present": False},
            "desired": copy.deepcopy(desired),
            "desiredSha256": transaction.semantic_hash(desired),
        }

    def _updated_target(self, before, desired):
        return {
            "id": "replace:Role:flux-system:example",
            "action": "replace",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "url": "/role/example",
            "prestate": {
                "present": True,
                "uid": UID_ONE,
                "resourceVersion": str(before["metadata"]["resourceVersion"]),
                "semanticSha256": transaction.semantic_hash(before),
                "rollbackObject": transaction.writable_from_live(before),
            },
            "desired": copy.deepcopy(desired),
            "desiredSha256": transaction.semantic_hash(desired),
        }

    def test_pending_create_response_is_recovered_only_with_transaction_marker(self):
        attempt = "c" * 64
        desired = _role(rules=[{"verbs": ["get"], "resources": ["pods"]}])
        target = self._created_target(desired)
        live = _role(
            rules=desired["rules"],
            uid=UID_ONE,
            resource_version="9",
            marker=attempt,
        )
        journal = _Journal(attempt, target["id"], "intent")
        client = _FakeClient(live)
        transaction.restore_object(client, target, journal)
        self.assertIsNone(client.live)
        self.assertEqual(
            [call[0] for call in client.calls].count("delete"),
            1,
        )

        for marker in (None, "d" * 64):
            with self.subTest(marker=marker):
                unbound = _role(
                    rules=desired["rules"],
                    uid=UID_ONE,
                    resource_version="9",
                    marker=marker,
                )
                with self.assertRaises(transaction.RecoveryRequired):
                    transaction.restore_object(
                        _FakeClient(unbound), target, _Journal(attempt, target["id"], "intent")
                    )

    def test_pending_create_reissues_fence_after_lost_response_then_removes_object(self):
        attempt = "c" * 64
        desired = _role(rules=[{"verbs": ["get"], "resources": ["pods"]}])
        target = self._created_target(desired)

        class LostPostFenceClient(_FakeClient):
            def post_fence(self, collection, body):
                self.post(collection, body)
                return None

        client = LostPostFenceClient(None, post_uid=UID_ONE)
        transaction.restore_object(
            client, target, _Journal(attempt, target["id"], "intent")
        )
        self.assertIsNone(client.live)
        self.assertEqual([call[0] for call in client.calls].count("post"), 1)
        self.assertEqual([call[0] for call in client.calls].count("delete"), 1)

    def test_pending_create_fence_transport_failure_stays_recovery_required(self):
        attempt = "c" * 64
        desired = _role(rules=[{"verbs": ["get"], "resources": ["pods"]}])
        target = self._created_target(desired)

        class FailedPostFenceClient(_FakeClient):
            def post_fence(self, _collection, _body):
                raise transaction.TransactionError("injected transport failure")

        with self.assertRaisesRegex(
            transaction.RecoveryRequired,
            "ROLLBACK_CREATE_FENCE_TRANSPORT_UNRESOLVED",
        ):
            transaction.restore_object(
                FailedPostFenceClient(None),
                target,
                _Journal(attempt, target["id"], "intent"),
            )

    def test_committed_create_requires_recorded_response_uid_after_marker_cleanup(self):
        attempt = "c" * 64
        desired = _role(rules=[{"verbs": ["get"], "resources": ["pods"]}])
        target = self._created_target(desired)
        live = _role(
            rules=desired["rules"], uid=UID_ONE, resource_version="9"
        )
        matching = _Journal(attempt, target["id"], "committed", uid=UID_ONE)
        client = _FakeClient(live)
        transaction.restore_object(client, target, matching)
        self.assertIsNone(client.live)

        mismatched = _Journal(attempt, target["id"], "committed", uid=UID_TWO)
        with self.assertRaises(transaction.RecoveryRequired):
            transaction.restore_object(_FakeClient(live), target, mismatched)

    def test_pending_update_response_requires_marker_then_restores_exact_prestate(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        desired = _role(rules=[{"verbs": ["get", "list"], "resources": ["pods"]}])
        target = self._updated_target(before, desired)
        live = _role(
            rules=desired["rules"],
            uid=UID_ONE,
            resource_version="8",
            marker=attempt,
        )
        journal = _Journal(attempt, target["id"], "intent")
        client = _FakeClient(live)
        transaction.restore_object(client, target, journal)
        self.assertEqual(transaction.semantic_hash(client.live), transaction.semantic_hash(before))
        self.assertEqual([call[0] for call in client.calls].count("put"), 1)

        unmarked = _role(
            rules=desired["rules"], uid=UID_ONE, resource_version="8"
        )
        with self.assertRaises(transaction.RecoveryRequired):
            transaction.restore_object(
                _FakeClient(unmarked), target, _Journal(attempt, target["id"], "intent")
            )

    def test_pending_update_loses_both_fence_responses_and_still_restores(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        desired = _role(rules=[{"verbs": ["get", "list"], "resources": ["pods"]}])
        target = self._updated_target(before, desired)

        class LostPutFenceClient(_FakeClient):
            def put_fence(self, url, body):
                self.put(url, body)
                return None

        journal = _Journal(attempt, target["id"], "intent")
        client = LostPutFenceClient(before)
        transaction.restore_object(client, target, journal)
        self.assertEqual(
            transaction.semantic_hash(client.live), transaction.semantic_hash(before)
        )
        record = journal.document["operations"][target["id"]]
        self.assertEqual(record["rollbackState"], "restored")
        self.assertGreater(
            int(record["rollbackRestoredResourceVersion"]),
            int(record["rollbackSourceResourceVersion"]),
        )

    def test_lost_update_restore_response_is_completed_from_advanced_prestate(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="9",
        )
        desired = _role(rules=[{"verbs": ["get", "list"], "resources": ["pods"]}])
        target = self._updated_target(
            _role(
                rules=before["rules"],
                uid=UID_ONE,
                resource_version="7",
            ),
            desired,
        )
        journal = _Journal(
            attempt,
            target["id"],
            "intent",
            rollbackState="restore-intent",
            rollbackSourceResourceVersion="8",
        )
        client = _FakeClient(before)
        transaction.restore_object(client, target, journal)
        self.assertEqual(
            journal.document["operations"][target["id"]]["rollbackState"],
            "restored",
        )
        self.assertEqual([call[0] for call in client.calls], ["get_optional"])

    def test_pending_update_fence_transport_failure_stays_recovery_required(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        desired = _role(rules=[{"verbs": ["get", "list"], "resources": ["pods"]}])
        target = self._updated_target(before, desired)

        class FailedPutFenceClient(_FakeClient):
            def put_fence(self, _url, _body):
                raise transaction.TransactionError("injected transport failure")

        with self.assertRaisesRegex(
            transaction.RecoveryRequired,
            "ROLLBACK_UPDATE_FENCE_TRANSPORT_UNRESOLVED",
        ):
            transaction.restore_object(
                FailedPutFenceClient(before),
                target,
                _Journal(attempt, target["id"], "intent"),
            )

    def test_committed_update_uses_recorded_uid_after_marker_cleanup(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        desired = _role(rules=[{"verbs": ["get", "list"], "resources": ["pods"]}])
        target = self._updated_target(before, desired)
        live = _role(
            rules=desired["rules"], uid=UID_ONE, resource_version="8"
        )
        journal = _Journal(attempt, target["id"], "committed", uid=UID_ONE)
        client = _FakeClient(live)
        transaction.restore_object(client, target, journal)
        self.assertEqual(transaction.semantic_hash(client.live), transaction.semantic_hash(before))

        mismatched = _Journal(attempt, target["id"], "committed", uid=UID_TWO)
        with self.assertRaises(transaction.RecoveryRequired):
            transaction.restore_object(_FakeClient(live), target, mismatched)

    def test_delete_response_loss_after_accepted_response_recreates_exact_prestate(self):
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        target = {
            "id": "delete:Role:flux-system:example",
            "action": "delete",
            "url": "/role/example",
            "prestate": {
                "present": True,
                "uid": UID_ONE,
                "semanticSha256": transaction.semantic_hash(before),
                "rollbackObject": transaction.writable_from_live(before),
            },
        }
        client = _FakeClient(None)
        transaction.restore_object(
            client,
            target,
            _Journal(
                "c" * 64,
                target["id"],
                "intent",
                deleteState="delete-accepted",
            ),
        )
        self.assertEqual(transaction.semantic_hash(client.live), transaction.semantic_hash(before))
        self.assertEqual([call[0] for call in client.calls].count("post"), 1)

    def test_external_delete_between_mark_and_delete_is_never_resurrected(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        target = {
            "id": "delete:Role:flux-system:example",
            "phase": "broad-delete",
            "action": "delete",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "url": "/role/example",
            "prestate": {
                "present": True,
                "uid": UID_ONE,
                "resourceVersion": "7",
                "semanticSha256": transaction.semantic_hash(before),
                "rollbackObject": transaction.writable_from_live(before),
            },
            "desiredSha256": None,
        }
        journal = transaction.Journal("a" * 64, "b" * 40, "d" * 64)
        journal.document["attemptId"] = attempt
        journal.write = mock.Mock()
        client = _ExternalDeleteClient(before)
        with self.assertRaises(transaction.TransactionError):
            transaction.apply_operation(client, target, journal)
        self.assertEqual(
            journal.document["operations"][target["id"]]["deleteState"],
            "delete-intent",
        )
        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "ROLLBACK_DELETE_ABSENCE_UNATTRIBUTED"
        ):
            transaction.restore_object(client, target, journal)
        self.assertEqual([call[0] for call in client.calls].count("post"), 0)

    def test_accepted_terminating_delete_waits_for_absence_then_restores(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        terminating = transaction.with_transaction_annotation(before, attempt)
        terminating["metadata"]["deletionTimestamp"] = "2026-08-22T12:00:00Z"
        target = {
            "id": "delete:Role:flux-system:example",
            "action": "delete",
            "url": "/role/example",
            "prestate": {
                "present": True,
                "uid": UID_ONE,
                "semanticSha256": transaction.semantic_hash(before),
                "rollbackObject": transaction.writable_from_live(before),
            },
        }
        client = _SequenceClient([terminating, None])
        transaction.restore_object(
            client,
            target,
            _Journal(
                attempt,
                target["id"],
                "intent",
                deleteState="delete-accepted",
            ),
        )
        self.assertEqual(transaction.semantic_hash(client.live), transaction.semantic_hash(before))
        self.assertEqual([call[0] for call in client.calls].count("post"), 1)

    def test_delete_intent_with_unchanged_prestate_is_a_noop(self):
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        target = {
            "id": "delete:Role:flux-system:example",
            "action": "delete",
            "url": "/role/example",
            "prestate": {
                "present": True,
                "uid": UID_ONE,
                "semanticSha256": transaction.semantic_hash(before),
                "rollbackObject": transaction.writable_from_live(before),
            },
        }
        client = _FakeClient(before)
        transaction.restore_object(
            client, target, _Journal("c" * 64, target["id"], "intent")
        )
        self.assertEqual([call[0] for call in client.calls], ["get_optional"])

    def test_lost_delete_marker_response_is_fenced_then_cleaned(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        target = {
            "id": "delete:Role:flux-system:example",
            "action": "delete",
            "url": "/role/example",
            "prestate": {
                "present": True,
                "uid": UID_ONE,
                "resourceVersion": "7",
                "semanticSha256": transaction.semantic_hash(before),
                "rollbackObject": transaction.writable_from_live(before),
            },
        }

        class LostMarkerFenceClient(_FakeClient):
            def put_fence(self, url, body):
                self.put(url, body)
                return None

        journal = _Journal(
            attempt,
            target["id"],
            "intent",
            deleteState="mark-intent",
        )
        client = LostMarkerFenceClient(before)
        transaction.restore_object(client, target, journal)
        self.assertEqual(
            transaction.semantic_hash(client.live), transaction.semantic_hash(before)
        )
        self.assertFalse(transaction.has_transaction_marker(client.live, attempt))
        self.assertEqual(
            journal.document["operations"][target["id"]]["rollbackState"],
            "marker-cleaned",
        )

    def test_lost_helm_add_response_is_fenced_then_exact_spec_is_restored(self):
        pre = HelmChainContractTests().valid_release()
        pre_snapshot = transaction.validate_site_helm_release(
            pre,
            "naranjo-online",
            "naranjo-online",
            "0.1.30",
            HelmChainContractTests.UPSTREAM,
        )
        plan = {
            "baselines": {
                "flux": HelmChainContractTests().flux_snapshot_for_versions(
                    "0.1.30", "0.1.26"
                )
            }
        }
        plan_sha256 = "a" * 64
        pre_spec = copy.deepcopy(pre["spec"])
        mutated_spec = transaction.build_helm_proof_spec(pre_spec, plan_sha256)
        mutated_spec_sha256 = transaction.sha256_bytes(
            transaction.canonical_json(mutated_spec)
        )

        class ProofJournal:
            def __init__(self):
                self.document = {
                    "planSha256": plan_sha256,
                    "helmProof": {
                        "state": "add-intent",
                        "uid": UID_THREE,
                        "preGeneration": 5,
                        "preHistoryRevision": 7,
                        "preSnapshot": copy.deepcopy(pre_snapshot),
                        "namespace": "naranjo-online",
                        "name": "naranjo-online",
                        "version": "0.1.30",
                        "upstreamDigest": HelmChainContractTests.UPSTREAM,
                        "preSpec": copy.deepcopy(pre_spec),
                        "mutatedSpec": copy.deepcopy(mutated_spec),
                        "mutatedSpecSha256": mutated_spec_sha256,
                    }
                }
                self.writes = 0

            def write(self):
                self.writes += 1

        class LostHelmFenceClient:
            def __init__(self, live):
                self.live = copy.deepcopy(live)
                self.put_fence_calls = 0
                self.last_fence_resource_version = None

            def get(self, _url):
                return copy.deepcopy(self.live)

            def _replace(self, body):
                result = copy.deepcopy(body)
                result["metadata"]["resourceVersion"] = str(
                    int(self.live["metadata"]["resourceVersion"]) + 1
                )
                result["metadata"]["generation"] = int(
                    self.live["metadata"]["generation"]
                ) + 1
                result["status"] = copy.deepcopy(self.live["status"])
                self.live = result
                return copy.deepcopy(result)

            def put_fence(self, _url, body):
                self.put_fence_calls += 1
                self.last_fence_resource_version = body["metadata"][
                    "resourceVersion"
                ]
                self._replace(body)
                return None

            def put(self, _url, body):
                return self._replace(body)

        tampered_journal = ProofJournal()
        tampered_proof = tampered_journal.document["helmProof"]
        tampered_proof["version"] = "0.1.31"
        tampered_proof["upstreamDigest"] = "sha256:" + "b" * 64
        tampered_snapshot = tampered_proof["preSnapshot"]
        tampered_snapshot["attemptedRevision"] = "0.1.31+" + "b" * 12
        tampered_snapshot["attemptedRevisionDigest"] = "sha256:" + "b" * 64
        tampered_snapshot["historyChartVersion"] = "0.1.31+" + "b" * 12
        tampered_snapshot["historyOciDigest"] = "sha256:" + "b" * 64
        tampered_client = LostHelmFenceClient(pre)
        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "ROLLBACK_HELM_PLAN_BINDING_INVALID"
        ):
            transaction.restore_helm_proof(tampered_client, plan, tampered_journal)
        self.assertEqual(tampered_client.put_fence_calls, 0)
        self.assertEqual(tampered_journal.writes, 0)

        substituted_journal = ProofJournal()
        substituted_proof = substituted_journal.document["helmProof"]
        substituted_proof["mutatedSpec"]["interval"] = "1m0s"
        substituted_proof["mutatedSpecSha256"] = transaction.sha256_bytes(
            transaction.canonical_json(substituted_proof["mutatedSpec"])
        )
        substituted_client = LostHelmFenceClient(pre)
        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "ROLLBACK_HELM_PROOF_BINDING_INVALID"
        ):
            transaction.restore_helm_proof(
                substituted_client, plan, substituted_journal
            )
        self.assertEqual(substituted_client.put_fence_calls, 0)
        self.assertEqual(substituted_journal.writes, 0)

        hash_tampered_journal = ProofJournal()
        hash_tampered_journal.document["helmProof"][
            "mutatedSpecSha256"
        ] = "0" * 64
        hash_tampered_client = LostHelmFenceClient(pre)
        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "ROLLBACK_HELM_PROOF_BINDING_INVALID"
        ):
            transaction.restore_helm_proof(
                hash_tampered_client, plan, hash_tampered_journal
            )
        self.assertEqual(hash_tampered_client.put_fence_calls, 0)
        self.assertEqual(hash_tampered_journal.writes, 0)

        zero_version_journal = ProofJournal()
        zero_version_journal.document["helmProof"]["preSnapshot"][
            "resourceVersion"
        ] = "0"
        zero_version_client = LostHelmFenceClient(pre)
        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "ROLLBACK_HELM_PLAN_BINDING_INVALID"
        ):
            transaction.restore_helm_proof(
                zero_version_client, plan, zero_version_journal
            )
        self.assertEqual(zero_version_client.put_fence_calls, 0)
        self.assertEqual(zero_version_journal.writes, 0)

        drifted_pre = copy.deepcopy(pre)
        drifted_pre["metadata"]["resourceVersion"] = str(
            int(drifted_pre["metadata"]["resourceVersion"]) + 1
        )
        drifted_snapshot = transaction.validate_site_helm_release(
            drifted_pre,
            "naranjo-online",
            "naranjo-online",
            "0.1.30",
            HelmChainContractTests.UPSTREAM,
        )
        journal = ProofJournal()
        journal.document["helmProof"]["preSnapshot"] = drifted_snapshot
        client = LostHelmFenceClient(drifted_pre)
        client.live["metadata"]["resourceVersion"] = str(
            int(client.live["metadata"]["resourceVersion"]) + 1
        )
        current_resource_version = client.live["metadata"]["resourceVersion"]
        with mock.patch.object(transaction, "wait_helm_restored"):
            transaction.restore_helm_proof(client, plan, journal)
        self.assertEqual(client.put_fence_calls, 1)
        self.assertEqual(client.last_fence_resource_version, current_resource_version)
        self.assertEqual(client.live["spec"], pre_spec)
        self.assertEqual(journal.document["helmProof"]["state"], "restored")

    def test_helm_recovery_rejects_coherent_pre_spec_substitution_before_writes(self):
        pre = HelmChainContractTests().valid_release()
        pre_snapshot = transaction.validate_site_helm_release(
            pre,
            "naranjo-online",
            "naranjo-online",
            "0.1.30",
            HelmChainContractTests.UPSTREAM,
        )
        plan = {
            "baselines": {
                "flux": HelmChainContractTests().flux_snapshot_for_versions(
                    "0.1.30", "0.1.26"
                )
            }
        }
        plan_sha256 = "a" * 64
        substituted_pre_spec = copy.deepcopy(pre["spec"])
        substituted_pre_spec["interval"] = "1m0s"
        substituted_mutated_spec = transaction.build_helm_proof_spec(
            substituted_pre_spec, plan_sha256
        )
        journal = mock.Mock()
        journal.document = {
            "planSha256": plan_sha256,
            "helmProof": {
                "state": "add-intent",
                "uid": UID_THREE,
                "preGeneration": 5,
                "preHistoryRevision": 7,
                "preSnapshot": copy.deepcopy(pre_snapshot),
                "namespace": "naranjo-online",
                "name": "naranjo-online",
                "version": "0.1.30",
                "upstreamDigest": HelmChainContractTests.UPSTREAM,
                "preSpec": substituted_pre_spec,
                "mutatedSpec": substituted_mutated_spec,
                "mutatedSpecSha256": transaction.sha256_bytes(
                    transaction.canonical_json(substituted_mutated_spec)
                ),
            },
        }
        client = mock.Mock()
        client.get.return_value = copy.deepcopy(pre)

        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "ROLLBACK_HELM_PLAN_BINDING_INVALID"
        ):
            transaction.restore_helm_proof(client, plan, journal)

        client.put.assert_not_called()
        client.put_fence.assert_not_called()
        journal.write.assert_not_called()

    def test_rollback_restores_broad_authority_before_every_other_object(self):
        broad_id = "delete:ClusterRoleBinding:cluster-reconciler-flux-system"
        narrow_id = "create:Role:flux-system:example"
        plan = {
            "targets": [
                {"id": narrow_id, "name": "example"},
                {"id": broad_id, "name": "cluster-reconciler-flux-system"},
            ],
            "operationOrder": [narrow_id, broad_id],
        }
        journal = _Journal("c" * 64, narrow_id, "intent")
        journal.document["operations"][broad_id] = {"state": "intent"}
        journal.write = mock.Mock()
        order = []

        def record_restore(_client, target, _journal):
            order.append(target["id"])

        with mock.patch.object(transaction, "restore_object", side_effect=record_restore), mock.patch.object(
            transaction, "restore_helm_proof"
        ), mock.patch.object(
            transaction, "load_module", return_value=object()
        ), mock.patch.object(
            transaction,
            "verify_rolled_back_state",
            return_value={"authorizationEvidence": {"matrixPhase": "rollback"}},
        ), mock.patch.object(
            transaction,
            "persist_oracle_evidence",
            return_value={"receiptsSha256": "d" * 64},
        ), mock.patch.object(
            transaction, "publish_oracle_evidence_records"
        ), mock.patch.object(
            transaction,
            "capture_terminal_target_inventory",
            return_value=[
                {"id": narrow_id, "present": False},
                {"id": broad_id, "present": False},
            ],
        ), mock.patch.object(
            transaction, "TRANSACTION_TARGET_COUNT", len(plan["targets"])
        ), mock.patch.object(
            transaction, "validate_terminal_evidence_document"
        ):
            transaction.rollback_internal(object(), plan, journal)
        self.assertEqual(order[0], broad_id)
        self.assertEqual(set(order), {broad_id, narrow_id})


class AnnotationCleanupTests(unittest.TestCase):
    ATTEMPT = "c" * 64
    OPERATION_ID = "create:Role:flux-system:example"

    def role_case(self, marker):
        live = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
            marker=marker,
        )
        target = {
            "id": self.OPERATION_ID,
            "phase": "split",
            "action": "create",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "url": "/role/example",
            "desiredSha256": transaction.semantic_hash(live),
        }
        journal = transaction.Journal("a" * 64, "b" * 40, "d" * 64)
        journal.document["attemptId"] = self.ATTEMPT
        journal.document["operations"] = {
            self.OPERATION_ID: {
                "state": "committed",
                "uid": UID_ONE,
                "resourceVersion": "7",
                "semanticSha256": transaction.semantic_hash(live),
            }
        }
        journal.write = mock.Mock()
        return live, {"targets": [target]}, journal

    def test_absent_marker_is_response_bound_already_clean_without_put(self):
        live, plan, journal = self.role_case(None)
        client = _FakeClient(live)

        transaction.cleanup_transaction_annotations(client, plan, journal)

        self.assertFalse(any(call[0] == "put" for call in client.calls))
        record = journal.document["operations"][self.OPERATION_ID]
        self.assertEqual(record["state"], "verified")
        self.assertEqual(record["cleanupState"], "already-clean")
        self.assertEqual(record["resourceVersion"], "7")
        journal.write.assert_called_once()

    def test_foreign_marker_fails_before_intent_or_put(self):
        live, plan, journal = self.role_case("f" * 64)
        client = _FakeClient(live)

        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "TRANSACTION_ANNOTATION_COLLISION"
        ):
            transaction.cleanup_transaction_annotations(client, plan, journal)

        self.assertEqual(
            journal.document["operations"][self.OPERATION_ID]["state"],
            "committed",
        )
        journal.write.assert_not_called()
        self.assertFalse(any(call[0] == "put" for call in client.calls))

    def test_present_null_marker_collides_without_journal_or_put(self):
        live, plan, journal = self.role_case(None)
        live["metadata"]["annotations"] = {
            transaction.TRANSACTION_ANNOTATION: None
        }
        client = _FakeClient(live)

        with self.assertRaisesRegex(
            transaction.RecoveryRequired, "TRANSACTION_ANNOTATION_COLLISION"
        ):
            transaction.cleanup_transaction_annotations(client, plan, journal)

        self.assertEqual(
            journal.document["operations"][self.OPERATION_ID]["state"],
            "committed",
        )
        journal.write.assert_not_called()
        self.assertFalse(any(call[0] == "put" for call in client.calls))

    def test_exact_marker_persists_bound_intent_before_fenced_put(self):
        live, plan, journal = self.role_case(self.ATTEMPT)

        class Client(_FakeClient):
            def put_fence(inner_self, url, body):
                record = journal.document["operations"][self.OPERATION_ID]
                self.assertEqual(record["cleanupState"], "remove-intent")
                self.assertEqual(record["cleanupSourceUid"], UID_ONE)
                self.assertEqual(record["cleanupSourceResourceVersion"], "7")
                self.assertEqual(
                    journal.document["pendingOperation"], self.OPERATION_ID
                )
                self.assertEqual(journal.write.call_count, 1)
                return super().put_fence(url, body)

        client = Client(live)
        transaction.cleanup_transaction_annotations(client, plan, journal)

        record = journal.document["operations"][self.OPERATION_ID]
        self.assertEqual(record["state"], "verified")
        self.assertEqual(record["cleanupState"], "removed")
        self.assertEqual(record["resourceVersion"], "8")
        self.assertEqual(journal.write.call_count, 2)
        self.assertIsNone(journal.document["pendingOperation"])

    def test_fenced_put_and_response_substitutions_fail_closed(self):
        mutations = {
            "conflict": lambda result: None,
            "identity": lambda result: result["metadata"].__setitem__(
                "name", "substituted"
            ),
            "uid": lambda result: result["metadata"].__setitem__("uid", UID_TWO),
            "resource version": lambda result: result["metadata"].__setitem__(
                "resourceVersion", "7"
            ),
            "terminating": lambda result: result["metadata"].__setitem__(
                "deletionTimestamp", "2026-08-25T00:00:00Z"
            ),
            "semantics": lambda result: result["rules"][0].__setitem__(
                "verbs", ["list"]
            ),
            "foreign marker": lambda result: result["metadata"].setdefault(
                "annotations", {}
            ).__setitem__(transaction.TRANSACTION_ANNOTATION, "f" * 64),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                live, plan, journal = self.role_case(self.ATTEMPT)

                class Client(_FakeClient):
                    def put_fence(inner_self, url, body):
                        if label == "conflict":
                            return None
                        result = super().put_fence(url, body)
                        mutate(result)
                        return result

                with self.assertRaises(transaction.RecoveryRequired):
                    transaction.cleanup_transaction_annotations(
                        Client(live), plan, journal
                    )
                record = journal.document["operations"][self.OPERATION_ID]
                self.assertEqual(record["state"], "committed")
                self.assertEqual(record["cleanupState"], "remove-intent")
                self.assertEqual(journal.write.call_count, 1)

    @staticmethod
    def controller_value(name, generation, pod_uid, semantic):
        image = "ghcr.io/fluxcd/controller:v1@sha256:" + "f" * 64
        args = ["--feature-gates=DisableConfigWatchers=true"]
        return {
            "uid": UID_ONE,
            "resourceVersion": str(generation),
            "generation": generation,
            "image": image,
            "args": args,
            "podUid": pod_uid,
            "podRestarts": 0,
            "podServiceAccountName": name,
            "podContainerName": "manager",
            "podImage": image,
            "podImageID": "ghcr.io/fluxcd/controller@sha256:" + "f" * 64,
            "podArgs": copy.deepcopy(args),
            "podCommand": None,
            "podReplicaSetName": name + "-abc123",
            "podReplicaSetUid": UID_TWO,
            "semanticSha256": semantic,
        }

    def watcher_case(self):
        name = "kustomize-controller"
        live = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": name,
                "namespace": "flux-system",
                "uid": UID_ONE,
                "resourceVersion": "20",
                "generation": 2,
                "annotations": {
                    transaction.TRANSACTION_ANNOTATION: self.ATTEMPT
                },
            },
            "spec": {"replicas": 1},
        }
        desired_sha = transaction.semantic_hash(live)
        rollout = self.controller_value(name, 2, "new-pod", desired_sha)
        baseline = {
            "source-controller": self.controller_value(
                "source-controller", 1, "source-pod", "a" * 64
            ),
            name: self.controller_value(name, 1, "old-pod", "b" * 64),
            "helm-controller": self.controller_value(
                "helm-controller", 1, "helm-pod", "c" * 64
            ),
        }
        operation_id = "rollout:Deployment:flux-system:" + name
        plan = {
            "baselines": {"controllers": baseline},
            "targets": [
                {
                    "id": operation_id,
                    "phase": "watchers",
                    "action": "args",
                    "kind": "Deployment",
                    "namespace": "flux-system",
                    "name": name,
                    "url": "/deployment/" + name,
                    "desiredSha256": desired_sha,
                }
            ],
        }
        journal = transaction.Journal("a" * 64, "b" * 40, "d" * 64)
        journal.document["attemptId"] = self.ATTEMPT
        journal.document["operations"] = {
            operation_id: {
                "state": "committed",
                "uid": UID_ONE,
                "resourceVersion": "20",
                "semanticSha256": desired_sha,
                "rolloutSnapshot": {
                    field: copy.deepcopy(rollout[field])
                    for field in transaction.CONTROLLER_RUNTIME_FIELDS
                },
            }
        }
        journal.write = mock.Mock()
        return name, live, rollout, baseline, operation_id, plan, journal

    def test_watcher_cleanup_binds_generation_and_final_verify_to_cleanup_snapshot(self):
        name, live, rollout, baseline, operation_id, plan, journal = (
            self.watcher_case()
        )
        cleaned = copy.deepcopy(rollout)
        cleaned["generation"] = 3
        current_before = {
            "source-controller": copy.deepcopy(baseline["source-controller"]),
            name: copy.deepcopy(rollout),
            "helm-controller": copy.deepcopy(baseline["helm-controller"]),
        }
        current_after = copy.deepcopy(current_before)
        current_after[name] = cleaned

        class Client(_FakeClient):
            def put_fence(inner_self, url, body):
                result = super().put_fence(url, body)
                result["metadata"]["generation"] = 3
                return result

        with mock.patch.object(
            transaction,
            "controller_snapshot",
            side_effect=[current_before, current_after],
        ):
            transaction.cleanup_transaction_annotations(
                Client(live), plan, journal
            )
        record = journal.document["operations"][operation_id]
        self.assertEqual(record["cleanupSnapshot"]["generation"], 3)
        self.assertEqual(record["cleanupSnapshot"]["podUid"], "new-pod")

        with mock.patch.object(
            transaction, "controller_snapshot", return_value=current_after
        ):
            transaction.verify_controller_phase(
                plan, object(), frozenset({name}), journal
            )

    def test_watcher_cleanup_rejects_nonunit_generation_and_runtime_drift(self):
        for generation in (2, 4):
            with self.subTest(generation=generation):
                name, live, rollout, baseline, _operation_id, plan, journal = (
                    self.watcher_case()
                )

                class Client(_FakeClient):
                    def put_fence(inner_self, url, body):
                        result = super().put_fence(url, body)
                        result["metadata"]["generation"] = generation
                        return result

                current = {
                    "source-controller": baseline["source-controller"],
                    name: rollout,
                    "helm-controller": baseline["helm-controller"],
                }
                with mock.patch.object(
                    transaction, "controller_snapshot", return_value=current
                ), self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "ANNOTATION_CLEANUP_RESPONSE_INVALID",
                ):
                    transaction.cleanup_transaction_annotations(
                        Client(live), plan, journal
                    )

        for field in (
            "podUid",
            "podReplicaSetUid",
            "image",
            "args",
            "podCommand",
            "podServiceAccountName",
            "podRestarts",
        ):
            with self.subTest(field=field):
                name, _live, rollout, _baseline, _operation_id, _plan, _journal = (
                    self.watcher_case()
                )
                drifted = copy.deepcopy(rollout)
                drifted["generation"] = 3
                drifted[field] = 1 if field == "podRestarts" else "unexpected"
                with mock.patch.object(
                    transaction,
                    "controller_snapshot",
                    return_value={name: drifted},
                ), self.assertRaisesRegex(
                    transaction.RecoveryRequired,
                    "CONTROLLER_CLEANUP_RUNTIME_DRIFT",
                ):
                    transaction.wait_controller_cleanup(
                        object(), name, rollout, 3
                    )

    def test_forward_failure_fields_are_allowlisted_and_immutable(self):
        journal = transaction.Journal("a" * 64, "b" * 40, "d" * 64)
        journal.write = mock.Mock()
        journal.record_forward_failure(
            "annotation-cleanup",
            transaction.RecoveryRequired("ANNOTATION_CLEANUP_DRIFT"),
        )
        self.assertEqual(
            journal.document["forwardFailureToken"],
            "ANNOTATION_CLEANUP_DRIFT",
        )

        unexpected = transaction.Journal("a" * 64, "b" * 40, "d" * 64)
        unexpected.write = mock.Mock()
        unexpected.record_forward_failure(
            "annotation-cleanup", OSError("private path must not persist")
        )
        self.assertEqual(
            unexpected.document["forwardFailureToken"],
            "UNEXPECTED_FORWARD_FAILURE",
        )
        self.assertNotIn("private", json.dumps(unexpected.document))

        previous = copy.deepcopy(journal.document)
        previous["sequence"] = 1
        successor = copy.deepcopy(previous)
        successor["sequence"] = 2
        successor["forwardFailureToken"] = "SUBSTITUTED_TOKEN"
        with self.assertRaisesRegex(
            transaction.TransactionError,
            "JOURNAL_TEMP_FORWARD_FAILURE_REGRESSION",
        ):
            transaction.validate_journal_successor(previous, successor)

        cleanup_previous = transaction.Journal(
            "a" * 64, "b" * 40, "d" * 64
        ).document
        cleanup_previous["sequence"] = 1
        cleanup_previous["operations"] = {
            self.OPERATION_ID: {
                "state": "committed",
                "uid": UID_ONE,
                "resourceVersion": "7",
            }
        }
        cleanup_intent = copy.deepcopy(cleanup_previous)
        cleanup_intent["sequence"] = 2
        cleanup_intent["operations"][self.OPERATION_ID].update(
            {
                "cleanupState": "remove-intent",
                "cleanupSourceUid": UID_ONE,
                "cleanupSourceResourceVersion": "7",
            }
        )
        transaction.validate_journal_successor(
            cleanup_previous, cleanup_intent
        )
        substituted = copy.deepcopy(cleanup_intent)
        substituted["operations"][self.OPERATION_ID][
            "cleanupSourceUid"
        ] = UID_TWO
        with self.assertRaisesRegex(
            transaction.TransactionError,
            "JOURNAL_TEMP_CLEANUP_STATE_INVALID",
        ):
            transaction.validate_journal_successor(
                cleanup_previous, substituted
            )


class SemanticGuardTests(unittest.TestCase):
    def test_duplicate_json_keys_and_nonfinite_numbers_fail_closed(self):
        for payload in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(payload=payload):
                with self.assertRaises(transaction.TransactionError):
                    transaction.parse_json_bytes(payload)

    def test_transaction_marker_is_not_a_desired_semantic_change(self):
        desired = _role(rules=[{"verbs": ["get"], "resources": ["pods"]}])
        marked = transaction.with_transaction_annotation(desired, "c" * 64)
        self.assertEqual(transaction.semantic_hash(marked), transaction.semantic_hash(desired))
        self.assertEqual(transaction.remove_transaction_annotation(marked), desired)

    def test_annotation_collision_and_resource_allowlist_fail_closed(self):
        desired = _role(rules=[])
        desired["metadata"]["annotations"] = {
            transaction.TRANSACTION_ANNOTATION: "d" * 64
        }
        with self.assertRaises(transaction.TransactionError):
            transaction.with_transaction_annotation(desired, "c" * 64)
        with self.assertRaises(transaction.TransactionError):
            transaction.resource_urls("Secret", "flux-system", "example")

    def test_semantically_equal_converge_is_a_zero_write_noop(self):
        live = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        operation = {
            "id": "converge:Role:flux-system:example",
            "phase": "namespaced",
            "action": "converge",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "desired": transaction.semantic_object(live),
        }
        client = _FakeClient(live)
        target = transaction.plan_target(client, operation)
        self.assertEqual(target["action"], "noop")
        self.assertEqual(target["declaredAction"], "converge")

        journal = transaction.Journal("a" * 64, "b" * 40, "c" * 64)
        journal.write = mock.Mock()
        client.calls.clear()
        transaction.apply_operation(client, target, journal)
        self.assertEqual([call[0] for call in client.calls], ["get_optional"])
        self.assertEqual(
            journal.document["operations"][target["id"]]["state"], "committed"
        )

    def test_semantically_equal_shared_replace_is_a_zero_write_noop(self):
        live = _cluster_role_binding(
            transaction.SHARED_NAME,
            role_name=transaction.SHARED_NAME,
            subject_names=("system:serviceaccounts:flux-system",),
        )
        operation = {
            "id": f"replace:ClusterRoleBinding:{transaction.SHARED_NAME}",
            "phase": "shared",
            "action": "replace",
            "kind": "ClusterRoleBinding",
            "namespace": None,
            "name": transaction.SHARED_NAME,
            "desired": transaction.semantic_object(live),
        }
        client = _FakeClient(live)
        target = transaction.plan_target(client, operation)
        self.assertEqual(target["action"], "noop")
        journal = transaction.Journal("a" * 64, "b" * 40, "c" * 64)
        journal.write = mock.Mock()
        client.calls.clear()
        transaction.apply_operation(client, target, journal)
        self.assertEqual([call[0] for call in client.calls], ["get_optional"])

    def test_semantically_equal_controller_args_are_a_zero_write_noop(self):
        live = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "helm-controller",
                "namespace": "flux-system",
                "uid": UID_ONE,
                "resourceVersion": "7",
                "generation": 3,
            },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "manager", "args": ["--events-addr=http://notification-controller.flux-system.svc.cluster.local./"]}
                        ]
                    }
                }
            },
        }
        operation = {
            "id": "rollout:Deployment:flux-system:helm-controller",
            "phase": "watchers",
            "action": "args",
            "kind": "Deployment",
            "namespace": "flux-system",
            "name": "helm-controller",
            "desiredArgs": live["spec"]["template"]["spec"]["containers"][0]["args"],
        }
        client = _FakeClient(live)
        target = transaction.plan_target(client, operation)
        self.assertEqual(target["action"], "noop")
        journal = transaction.Journal("a" * 64, "b" * 40, "c" * 64)
        journal.write = mock.Mock()
        client.calls.clear()
        transaction.apply_operation(client, target, journal)
        self.assertEqual([call[0] for call in client.calls], ["get_optional"])

    def test_terminating_target_is_rejected_before_plan_capture(self):
        live = _role(rules=[], uid=UID_ONE, resource_version="7")
        live["metadata"]["deletionTimestamp"] = "2026-08-22T12:00:00Z"
        operation = {
            "id": "converge:Role:flux-system:example",
            "phase": "namespaced",
            "action": "converge",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "desired": transaction.semantic_object(live),
        }
        with self.assertRaisesRegex(
            transaction.TransactionError, "TARGET_PRESTATE_TERMINATING"
        ):
            transaction.plan_target(_FakeClient(live), operation)

    def test_foreign_transaction_marker_is_refused_at_plan_time(self):
        live = _role(
            rules=[],
            uid=UID_ONE,
            resource_version="7",
            marker="d" * 64,
        )
        operation = {
            "id": "converge:Role:flux-system:example",
            "phase": "namespaced",
            "action": "converge",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "desired": transaction.semantic_object(live),
        }
        with self.assertRaisesRegex(
            transaction.TransactionError, "FOREIGN_TRANSACTION_MARKER_PRESENT"
        ):
            transaction.plan_target(_FakeClient(live), operation)

    def test_binding_reach_includes_service_account_user_and_groups(self):
        subjects = [
            {
                "kind": "ServiceAccount",
                "namespace": "flux-system",
                "name": "source-controller",
            },
            {
                "kind": "User",
                "name": "system:serviceaccount:naranjo-online:helm-reconciler",
            },
            {"kind": "Group", "name": "system:serviceaccounts:lidersea-com"},
            {"kind": "Group", "name": "system:authenticated"},
        ]
        self.assertEqual(
            transaction.tracked_binding_subjects(subjects),
            [
                "Group:system:authenticated",
                "Group:system:serviceaccounts:lidersea-com",
                "ServiceAccount:flux-system/source-controller",
                "User:system:serviceaccount:naranjo-online:helm-reconciler",
            ],
        )

    def test_startup_matrix_contains_all_twenty_four_informer_probes(self):
        with mock.patch.object(
            transaction,
            "run_oracle_request",
            side_effect=lambda *_args, **kwargs: dict(kwargs),
        ):
            receipts = transaction.startup_authorization_phase(object(), object())
        informer = [
            row
            for row in receipts
            if row.get("verb") in {"list", "watch"}
            and row.get("group")
            in {
                "source.toolkit.fluxcd.io",
                "kustomize.toolkit.fluxcd.io",
                "helm.toolkit.fluxcd.io",
            }
        ]
        self.assertEqual(len(informer), 24)

    def test_kubernetes_default_group_bindings_are_closed_and_malformed_posture_fails(self):
        for name, subjects in transaction.KUBERNETES_DEFAULT_GROUP_BINDINGS.items():
            with self.subTest(name=name):
                row = transaction.binding_graph_row(
                    _cluster_role_binding(name, subject_names=tuple(subjects))
                )
                self.assertEqual(row["classification"], "kubernetes-default-group")
        malformed = _cluster_role_binding(
            "system:basic-user",
            role_name="cluster-admin",
        )
        with self.assertRaisesRegex(
            transaction.TransactionError,
            "KUBERNETES_DEFAULT_BINDING_POSTURE_INVALID",
        ):
            transaction.binding_graph_row(malformed)

    def test_site_oci_specs_are_public_keyless_and_site_isolated(self):
        subjects = set()
        for namespace, name in transaction.SITE_RELEASES:
            spec = transaction.expected_site_oci_spec(namespace, name)
            self.assertEqual(spec["provider"], "generic")
            self.assertEqual(spec["verify"]["provider"], "cosign")
            self.assertTrue(spec["url"].startswith("oci://ghcr.io/snaraj/charts/"))
            for forbidden in (
                "secretRef",
                "serviceAccountName",
                "certSecretRef",
                "proxySecretRef",
            ):
                self.assertNotIn(forbidden, spec)
            subjects.add(spec["verify"]["matchOIDCIdentity"][0]["subject"])
        self.assertEqual(len(subjects), 2)

    def test_final_tenant_matrix_denies_default_service_account_helm_authority(self):
        calls = []

        def capture(_oracle, _client, **kwargs):
            calls.append(kwargs)
            return {"result": "PASS", "authorization": kwargs["expected"]}

        with mock.patch.object(transaction, "run_oracle_request", side_effect=capture):
            transaction.tenant_authorization_phase(
                object(), object(), include_impersonation=True
            )
        default_denials = [
            call
            for call in calls
            if call["subject"].endswith(":default")
        ]
        self.assertEqual(len(default_denials), 6)
        self.assertTrue(all(call["expected"] == "DENIED" for call in default_denials))

    def test_changed_controller_is_bound_to_exact_post_rollout_pod(self):
        def snapshot(name, *, generation, pod_uid, semantic):
            image = "ghcr.io/fluxcd/controller:v1@sha256:" + "f" * 64
            args = ["--feature-gates=DisableConfigWatchers=true"]
            return {
                "uid": UID_ONE,
                "resourceVersion": str(generation),
                "generation": generation,
                "image": image,
                "args": args,
                "podUid": pod_uid,
                "podRestarts": 0,
                "podServiceAccountName": name,
                "podContainerName": "manager",
                "podImage": image,
                "podImageID": "ghcr.io/fluxcd/controller@sha256:" + "f" * 64,
                "podArgs": copy.deepcopy(args),
                "podCommand": None,
                "podReplicaSetName": name + "-abc123",
                "podReplicaSetUid": UID_TWO,
                "semanticSha256": semantic,
            }

        baseline = {
            "source-controller": snapshot(
                "source-controller", generation=1, pod_uid="source-pod", semantic="a" * 64
            ),
            "kustomize-controller": snapshot(
                "kustomize-controller", generation=1, pod_uid="old-pod", semantic="b" * 64
            ),
            "helm-controller": snapshot(
                "helm-controller", generation=1, pod_uid="helm-pod", semantic="c" * 64
            ),
        }
        rolled_out = snapshot(
            "kustomize-controller", generation=2, pod_uid="reviewed-pod", semantic="d" * 64
        )
        target_id = "rollout:Deployment:flux-system:kustomize-controller"
        plan = {
            "baselines": {"controllers": baseline},
            "targets": [
                {
                    "id": target_id,
                    "phase": "watchers",
                    "action": "args",
                    "name": "kustomize-controller",
                    "desiredSha256": "d" * 64,
                }
            ],
        }
        journal = _Journal(
            "e" * 64,
            target_id,
            "committed",
            rolloutSnapshot={
                key: copy.deepcopy(rolled_out[key])
                for key in transaction.CONTROLLER_RUNTIME_FIELDS
            },
        )
        current = {
            "source-controller": copy.deepcopy(baseline["source-controller"]),
            "kustomize-controller": copy.deepcopy(rolled_out),
            "helm-controller": copy.deepcopy(baseline["helm-controller"]),
        }
        with mock.patch.object(transaction, "controller_snapshot", return_value=current):
            transaction.verify_controller_phase(
                plan, object(), frozenset({"kustomize-controller"}), journal
            )
        for field in (
            "podUid",
            "podServiceAccountName",
            "podImage",
            "podImageID",
            "podArgs",
            "podReplicaSetUid",
        ):
            with self.subTest(field=field):
                tampered = copy.deepcopy(current)
                tampered["kustomize-controller"][field] = "unexpected"
                with mock.patch.object(
                    transaction, "controller_snapshot", return_value=tampered
                ):
                    with self.assertRaisesRegex(
                        transaction.TransactionError,
                        "CONTROLLER_EXPECTED_ROLLOUT_INVALID",
                    ):
                        transaction.verify_controller_phase(
                            plan,
                            object(),
                            frozenset({"kustomize-controller"}),
                            journal,
                        )


class AtomicWriteRecoveryTests(unittest.TestCase):
    def test_publish_once_reestablishes_durability_after_directory_fsync_failure(self):
        for linked_window in (False, True):
            with self.subTest(linked_window=linked_window), tempfile.TemporaryDirectory(
                dir=str(TEST_TEMP_ROOT)
            ) as temporary:
                path = Path(temporary) / "receipt.json"
                payload = b"reviewed\n"
                if linked_window:
                    pending = path.with_name(path.name + ".new")
                    pending.write_bytes(payload)
                    pending.chmod(0o600)
                    transaction.os.link(pending, path)
                real_fsync_directory = transaction.fsync_directory
                calls = 0

                def fail_first(candidate):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise OSError("injected directory fsync failure")
                    return real_fsync_directory(candidate)

                with mock.patch.object(
                    transaction, "fsync_directory", side_effect=fail_first
                ):
                    with self.assertRaisesRegex(OSError, "directory fsync failure"):
                        transaction.publish_once(path, payload)
                self.assertTrue(path.is_file())

                with mock.patch.object(
                    transaction,
                    "fsync_directory",
                    wraps=real_fsync_directory,
                ) as barrier:
                    transaction.publish_once(path, payload)
                barrier.assert_called_with(path.parent)
                self.assertEqual(path.read_bytes(), payload)
                self.assertEqual(path.stat().st_nlink, 1)

    def test_journal_load_reestablishes_file_and_parent_durability(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            journal_path = Path(temporary) / "journal.json"
            journal = transaction.Journal("a" * 64, "b" * 40, "c" * 64)
            journal.document["sequence"] = 1
            journal_path.write_bytes(transaction.canonical_json(journal.document))
            journal_path.chmod(0o600)
            real_read = transaction.read_regular
            durable_reads = []

            def read_as_test_owner(path, **kwargs):
                durable_reads.append(kwargs.get("durable"))
                kwargs["owner"] = transaction.os.getuid()
                return real_read(path, **kwargs)

            with mock.patch.object(
                transaction, "JOURNAL_PATH", journal_path
            ), mock.patch.object(
                transaction, "read_regular", side_effect=read_as_test_owner
            ), mock.patch.object(
                transaction,
                "fsync_directory",
                wraps=transaction.fsync_directory,
            ) as parent_barrier:
                loaded = transaction.Journal.load()
            self.assertEqual(loaded.document, journal.document)
            self.assertEqual(durable_reads, [True])
            parent_barrier.assert_called_with(journal_path.parent)

    def test_write_plan_recovers_no_replace_link_publication_window(self):
        with tempfile.TemporaryDirectory(dir=str(TEST_TEMP_ROOT)) as temporary:
            path = Path(temporary) / "plan.json"
            plan = {"reviewed": True}
            payload = transaction.canonical_json(plan)
            pending = path.with_name("plan.json.new")
            pending.write_bytes(payload)
            pending.chmod(0o600)
            transaction.os.link(pending, path)
            with mock.patch.object(transaction, "PLAN_PATH", path):
                digest = transaction.write_plan(plan)
            self.assertEqual(digest, transaction.sha256_bytes(payload))
            self.assertFalse(pending.exists())
            self.assertEqual(path.stat().st_nlink, 1)

    def test_visible_initial_journal_is_not_accepted_after_directory_fsync_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal_path = Path(temporary) / "journal.json"
            journal = transaction.Journal("a" * 64, "b" * 40, "c" * 64)
            with mock.patch.object(transaction, "JOURNAL_PATH", journal_path), mock.patch.object(
                transaction,
                "fsync_directory",
                side_effect=[OSError("injected directory fsync failure"), None],
            ), mock.patch.object(
                transaction, "read_regular", side_effect=lambda path, **_kwargs: Path(path).read_bytes()
            ):
                with self.assertRaisesRegex(OSError, "directory fsync failure"):
                    journal.write()
            self.assertTrue(journal_path.exists())
            self.assertEqual(journal.document["sequence"], 1)

    def test_interrupted_write_removes_temporary_and_retry_succeeds(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "journal.json"
            with mock.patch.object(
                transaction.os,
                "write",
                side_effect=transaction.Interrupted("injected"),
            ):
                with self.assertRaises(transaction.Interrupted):
                    transaction.atomic_write(path, b"first\n", replace=False)
            self.assertFalse(path.exists())
            self.assertFalse(path.with_name("journal.json.new").exists())

            transaction.atomic_write(path, b"second\n", replace=False)
            self.assertEqual(path.read_bytes(), b"second\n")

    def test_complete_stale_temporary_is_promoted_and_partial_is_rewritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            pending = path.with_name("plan.json.new")
            pending.write_bytes(b"complete\n")
            pending.chmod(0o600)
            transaction.atomic_write(path, b"complete\n", replace=False)
            self.assertEqual(path.read_bytes(), b"complete\n")
            self.assertFalse(pending.exists())

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            pending = path.with_name("plan.json.new")
            pending.write_bytes(b"part")
            pending.chmod(0o600)
            transaction.atomic_write(path, b"complete\n", replace=False)
            self.assertEqual(path.read_bytes(), b"complete\n")
            self.assertFalse(pending.exists())

    def test_initial_journal_link_crash_is_recovered_before_replace(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "journal.json"
            pending = path.with_name("journal.json.new")
            pending.write_bytes(b"old\n")
            pending.chmod(0o600)
            transaction.os.link(pending, path)
            self.assertEqual(pending.stat().st_nlink, 2)
            transaction.atomic_write(path, b"new\n", replace=True)
            self.assertEqual(path.read_bytes(), b"new\n")
            self.assertFalse(pending.exists())

    def test_complete_next_journal_record_is_promoted_before_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal_path = Path(temporary) / "journal.json"
            with mock.patch.object(transaction, "JOURNAL_PATH", journal_path):
                journal = transaction.Journal("a" * 64, "b" * 40, "c" * 64)
                journal.write()
                operation_id = "delete:Role:flux-system:example"
                journal.intent(operation_id, "broad-delete")
                record = journal.document["operations"][operation_id]
                record["deleteState"] = "delete-intent"
                journal.write()

                successor = copy.deepcopy(journal.document)
                successor["sequence"] += 1
                successor["operations"][operation_id]["deleteState"] = "delete-accepted"
                pending = journal_path.with_name("journal.json.new")
                pending.write_bytes(transaction.canonical_json(successor))
                pending.chmod(0o600)

                def test_read(path, **_kwargs):
                    return Path(path).read_bytes()

                with mock.patch.object(transaction, "read_regular", side_effect=test_read):
                    loaded = transaction.Journal.load()
                self.assertEqual(loaded.document, successor)
                self.assertFalse(pending.exists())

    def test_delete_response_directory_fsync_failure_stops_forward_execution(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        target = {
            "id": "delete:Role:flux-system:example",
            "phase": "broad-delete",
            "action": "delete",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "url": "/role/example",
            "prestate": {
                "present": True,
                "uid": UID_ONE,
                "resourceVersion": "7",
                "semanticSha256": transaction.semantic_hash(before),
                "rollbackObject": transaction.writable_from_live(before),
            },
            "desiredSha256": None,
        }
        client = _FakeClient(before)
        with tempfile.TemporaryDirectory() as temporary:
            journal_path = Path(temporary) / "journal.json"
            journal = transaction.Journal("a" * 64, "b" * 40, "d" * 64)
            journal.document["attemptId"] = attempt
            calls = 0
            real_fsync_directory = transaction.fsync_directory

            def fail_delete_accepted(path):
                nonlocal calls
                calls += 1
                if calls == 5:
                    raise OSError("injected accepted-record fsync failure")
                return real_fsync_directory(path)

            with mock.patch.object(transaction, "JOURNAL_PATH", journal_path), mock.patch.object(
                transaction, "fsync_directory", side_effect=fail_delete_accepted
            ):
                with self.assertRaisesRegex(OSError, "accepted-record fsync failure"):
                    transaction.apply_operation(client, target, journal)
            self.assertIsNone(client.live)
            self.assertEqual(
                journal.document["operations"][target["id"]]["deleteState"],
                "delete-accepted",
            )
            self.assertNotEqual(
                journal.document["operations"][target["id"]].get("state"),
                "committed",
            )

    @unittest.skipUnless(hasattr(signal, "pthread_sigmask"), "POSIX signal masks required")
    def test_delete_response_is_journaled_before_pending_signal_is_delivered(self):
        attempt = "c" * 64
        before = _role(
            rules=[{"verbs": ["get"], "resources": ["pods"]}],
            uid=UID_ONE,
            resource_version="7",
        )
        target = {
            "id": "delete:Role:flux-system:example",
            "phase": "broad-delete",
            "action": "delete",
            "kind": "Role",
            "namespace": "flux-system",
            "name": "example",
            "url": "/role/example",
            "prestate": {
                "present": True,
                "uid": UID_ONE,
                "resourceVersion": "7",
                "semanticSha256": transaction.semantic_hash(before),
                "rollbackObject": transaction.writable_from_live(before),
            },
            "desiredSha256": None,
        }

        class SignaledDeleteClient(_FakeClient):
            def delete(self, url, uid, resource_version):
                self.calls.append(("delete", url, uid, resource_version))
                self.live = None
                signal.raise_signal(signal.SIGTERM)
                return {"apiVersion": "v1", "kind": "Status", "metadata": {}}

        journal = transaction.Journal("a" * 64, "b" * 40, "d" * 64)
        journal.document["attemptId"] = attempt
        journal.write = mock.Mock()
        client = SignaledDeleteClient(before)
        previous = signal.signal(
            signal.SIGTERM,
            lambda *_args: (_ for _ in ()).throw(transaction.Interrupted("injected")),
        )
        try:
            with self.assertRaises(transaction.Interrupted):
                transaction.apply_operation(client, target, journal)
        finally:
            signal.signal(signal.SIGTERM, previous)
        self.assertEqual(
            journal.document["operations"][target["id"]]["deleteState"],
            "delete-accepted",
        )
        transaction.restore_object(client, target, journal)
        self.assertEqual(transaction.semantic_hash(client.live), transaction.semantic_hash(before))


if __name__ == "__main__":
    unittest.main()
