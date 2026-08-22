"""Hostile and protocol-parity tests for the Flux RBAC denial oracle."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import platform
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from scripts import flux_rbac_denial_oracle as oracle


ROOT = Path(__file__).resolve().parents[2]
KUBECTL = shutil.which("kubectl")
OPENSSL = shutil.which("openssl")
POSIX_CUSTODY = os.name == "posix" and hasattr(os, "geteuid")
FLUX_SERVICE_ACCOUNT_GROUPS = (
    "system:serviceaccounts",
    "system:serviceaccounts:flux-system",
    "system:authenticated",
)


def _resource_list(group_version: str, resources: list[dict[str, object]]) -> dict[str, object]:
    document = {
        "groupVersion": group_version,
        "kind": "APIResourceList",
        "resources": resources,
    }
    if group_version != "v1":
        document["apiVersion"] = "v1"
    return document


def _resource(
    name: str,
    kind: str,
    namespaced: bool,
    verbs: object = None,
) -> dict[str, object]:
    return {
        "name": name,
        "singularName": "",
        "namespaced": namespaced,
        "kind": kind,
        "verbs": verbs if verbs is not None else ["create", "get", "list", "watch"],
    }


def _completed_json(document: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        ["kubectl"],
        0,
        stdout=json.dumps(document).encode("utf-8"),
        stderr=b"",
    )


def _synthetic_pem(label: str, marker: int, size: int) -> bytes:
    der = bytes((0x30,)) + bytes((marker,)) * (size - 1)
    body = base64.b64encode(der).decode("ascii")
    lines = [body[offset : offset + 64] for offset in range(0, len(body), 64)]
    return (
        "\n".join((f"-----BEGIN {label}-----", *lines, f"-----END {label}-----", ""))
    ).encode("ascii")


def _closed_kubeconfig_bytes() -> bytes:
    encoded = lambda value: base64.b64encode(value).decode("ascii")
    return json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "oracle",
            "clusters": [
                {
                    "name": "cluster",
                    "cluster": {
                        "server": "https://127.0.0.1:6443",
                        "certificate-authority-data": encoded(
                            _synthetic_pem("CERTIFICATE", 1, 64)
                        ),
                    },
                }
            ],
            "users": [
                {
                    "name": "user",
                    "user": {
                        "client-certificate-data": encoded(
                            _synthetic_pem("CERTIFICATE", 2, 64)
                        ),
                        "client-key-data": encoded(
                            _synthetic_pem("PRIVATE KEY", 3, 32)
                        ),
                    },
                }
            ],
            "contexts": [
                {
                    "name": "oracle",
                    "context": {"cluster": "cluster", "user": "user"},
                }
            ],
            "preferences": {},
        },
        separators=(",", ":"),
    ).encode("utf-8")


class OracleApiState:
    def __init__(self) -> None:
        self.discovery_state = "reviewed"
        self.authorization_response_state = "reviewed"
        self.constant_allow = False
        self.pre_deletion_broad_binding = False
        self.warning = False
        self.requests: list[dict[str, object]] = []
        source = "system:serviceaccount:flux-system:source-controller"
        kustomize = "system:serviceaccount:flux-system:kustomize-controller"
        inert = oracle.DENIAL_CONTROL_SUBJECT
        self.decisions = {
            (
                source,
                FLUX_SERVICE_ACCOUNT_GROUPS,
                "create",
                "coordination.k8s.io",
                "v1",
                "leases",
                None,
                "flux-system",
                None,
                "reviewed",
            ): True,
            (
                kustomize,
                FLUX_SERVICE_ACCOUNT_GROUPS,
                "list",
                "kustomize.toolkit.fluxcd.io",
                "v1",
                "kustomizations",
                None,
                "flux-system",
                None,
                "reviewed",
            ): True,
            (
                kustomize,
                FLUX_SERVICE_ACCOUNT_GROUPS,
                "create",
                "",
                "v1",
                "serviceaccounts",
                "token",
                "flux-system",
                "controller",
                "reviewed",
            ): False,
            (
                kustomize,
                FLUX_SERVICE_ACCOUNT_GROUPS,
                "create",
                "apps",
                "v1",
                "deployments",
                None,
                "kube-system",
                None,
                "reviewed",
            ): False,
            (
                inert,
                FLUX_SERVICE_ACCOUNT_GROUPS,
                "get",
                "",
                "v1",
                "secrets",
                None,
                "kube-system",
                None,
                "reviewed",
            ): False,
            (
                kustomize,
                FLUX_SERVICE_ACCOUNT_GROUPS,
                "list",
                "kustomize.toolkit.fluxcd.io",
                "v1",
                "kustomizations",
                None,
                None,
                None,
                "reviewed",
            ): True,
        }


class OracleApiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    @property
    def state(self) -> OracleApiState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_: object) -> None:
        return

    def _send(self, status: int, value: dict[str, object]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, body)

    def _send_bytes(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.state.warning:
            self.send_header("Warning", '299 oracle "hostile warning"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.state.requests.append({"method": "GET", "path": self.path})
        path = self.path.partition("?")[0]
        if path == "/api":
            self._send(200, {"apiVersion": "v1", "kind": "APIVersions", "versions": ["v1"], "serverAddressByClientCIDRs": []})
            return
        if path == "/apis":
            groups = []
            for group, version in (
                ("apps", "v1"),
                ("coordination.k8s.io", "v1"),
                ("kustomize.toolkit.fluxcd.io", "v1"),
                ("authorization.k8s.io", "v1"),
                ("apiextensions.k8s.io", "v1"),
            ):
                groups.append(
                    {
                        "name": group,
                        "versions": [{"groupVersion": f"{group}/{version}", "version": version}],
                        "preferredVersion": {"groupVersion": f"{group}/{version}", "version": version},
                    }
                )
            self._send(200, {"apiVersion": "v1", "kind": "APIGroupList", "groups": groups})
            return
        if path == "/api/v1":
            self._send(
                200,
                _resource_list(
                    "v1",
                    [
                        _resource("secrets", "Secret", True),
                        _resource("serviceaccounts/token", "TokenRequest", True),
                    ],
                ),
            )
            return
        if path == "/apis/coordination.k8s.io/v1":
            self._send(200, _resource_list("coordination.k8s.io/v1", [_resource("leases", "Lease", True)]))
            return
        if path == "/apis/apps/v1":
            self._send(200, _resource_list("apps/v1", [_resource("deployments", "Deployment", True)]))
            return
        if path == "/apis/authorization.k8s.io/v1":
            self._send(200, _resource_list("authorization.k8s.io/v1", [_resource("selfsubjectaccessreviews", "SelfSubjectAccessReview", False)]))
            return
        if path == "/apis/apiextensions.k8s.io/v1":
            self._send(200, _resource_list("apiextensions.k8s.io/v1", [_resource("customresourcedefinitions", "CustomResourceDefinition", False)]))
            return
        if path == "/apis/kustomize.toolkit.fluxcd.io/v1":
            if self.state.discovery_state == "absent":
                self._send(200, _resource_list("kustomize.toolkit.fluxcd.io/v1", []))
            elif self.state.discovery_state == "transport":
                self._send(503, {"kind": "Status", "message": "private-sentinel-body"})
            elif self.state.discovery_state == "unparseable":
                self._send_bytes(200, b'{"private-sentinel-token":')
            elif self.state.discovery_state == "foreign-version":
                self._send(200, _resource_list("kustomize.toolkit.fluxcd.io/v1beta1", [_resource("kustomizations", "Kustomization", True)]))
            elif self.state.discovery_state == "malformed":
                self._send(200, {"apiVersion": "v1", "kind": "APIResourceList", "resources": "wrong"})
            else:
                resource = _resource(
                    "kustomizations",
                    "ForeignKind" if self.state.discovery_state == "foreign-kind" else "Kustomization",
                    self.state.discovery_state != "foreign-scope",
                )
                self._send(200, _resource_list("kustomize.toolkit.fluxcd.io/v1", [resource]))
            return
        if path.endswith("/customresourcedefinitions/kustomizations.kustomize.toolkit.fluxcd.io"):
            version = "v1beta1" if self.state.discovery_state == "foreign-crd" else "v1"
            established = "False" if self.state.discovery_state == "stale" else "True"
            conditions = [
                {"type": "Established", "status": established},
                {"type": "NamesAccepted", "status": "True"},
            ]
            if self.state.discovery_state == "duplicate-conditions":
                conditions.insert(0, {"type": "Established", "status": "False"})
            self._send(
                200,
                {
                    "apiVersion": "apiextensions.k8s.io/v1",
                    "kind": "CustomResourceDefinition",
                    "metadata": {
                        "name": (
                            "foreign.kustomize.toolkit.fluxcd.io"
                            if self.state.discovery_state == "foreign-crd-name"
                            else "kustomizations.kustomize.toolkit.fluxcd.io"
                        )
                    },
                    "spec": {
                        "group": "kustomize.toolkit.fluxcd.io",
                        "scope": "Namespaced",
                        "names": {"plural": "kustomizations", "kind": "Kustomization"},
                        "versions": [{"name": version, "served": True, "storage": True}],
                    },
                    "status": {"conditions": conditions},
                },
            )
            return
        self._send(404, {"apiVersion": "v1", "kind": "Status", "status": "Failure"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            payload = self.rfile.read(length)
        elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = bytearray()
            while True:
                size = int(self.rfile.readline().strip().split(b";", 1)[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.extend(self.rfile.read(size))
                self.rfile.read(2)
            payload = bytes(chunks)
        else:
            payload = b""
        # kubectl v1.36 `create --raw -f -` sends the exact JSON bytes without
        # a Content-Type header; this absence is part of the observed adapter.
        if self.headers.get("Content-Type") is not None:
            self._send(415, {"apiVersion": "v1", "kind": "Status", "status": "Failure"})
            return
        body = json.loads(payload)
        attributes = body["spec"]["resourceAttributes"]
        identity = self.headers.get("Impersonate-User")
        groups = tuple(self.headers.get_all("Impersonate-Group", []))
        key = (
            identity,
            groups,
            attributes.get("verb"),
            attributes.get("group", ""),
            attributes.get("version"),
            attributes.get("resource"),
            attributes.get("subresource"),
            attributes.get("namespace"),
            attributes.get("name"),
            self.state.discovery_state,
        )
        allowed = True if self.state.constant_allow else self.state.decisions.get(key, False)
        if self.state.pre_deletion_broad_binding and key[:9] == (
            "system:serviceaccount:flux-system:kustomize-controller",
            FLUX_SERVICE_ACCOUNT_GROUPS,
            "create",
            "apps",
            "v1",
            "deployments",
            None,
            "kube-system",
            None,
        ):
            allowed = True
        peer = self.connection.getpeercert()  # type: ignore[attr-defined]
        peer_names = dict(item for group in peer.get("subject", ()) for item in group)
        self.state.requests.append(
            {
                "method": "POST",
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "clientCommonName": peer_names.get("commonName"),
                "impersonate": identity,
                "impersonateGroups": groups,
                "contentType": self.headers.get("Content-Type"),
                "attributes": attributes,
                "allowed": allowed,
            }
        )
        if self.path.partition("?")[0] != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
            self._send(404, {"apiVersion": "v1", "kind": "Status", "status": "Failure"})
            return
        response = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": attributes},
            "status": {"allowed": allowed},
        }
        if self.state.authorization_response_state == "foreign-spec":
            response["spec"] = {
                "resourceAttributes": {**attributes, "resource": "statefulsets"}
            }
        elif self.state.authorization_response_state == "nonboolean-allowed":
            response["status"]["allowed"] = "false"
        elif self.state.authorization_response_state == "nonboolean-denied":
            response["status"]["denied"] = "false"
        elif self.state.authorization_response_state == "evaluation-error":
            response["status"]["evaluationError"] = ["private-sentinel"]
        elif self.state.authorization_response_state == "contradictory":
            response["status"]["denied"] = True
        elif self.state.authorization_response_state == "explicit-denied" and not allowed:
            response["status"]["denied"] = True
        self._send(201, response)


class ProtocolFixture:
    def __init__(self) -> None:
        if KUBECTL is None:
            raise unittest.SkipTest("kubectl is unavailable for production-adapter parity")
        if OPENSSL is None:
            raise unittest.SkipTest("openssl is unavailable for authenticated TLS parity")
        # macOS exposes the tempfile root through the /var -> /private/var
        # compatibility symlink.  Resolve the fixture-owned root once so the
        # production no-follow traversal receives a canonical path.
        self.scratch = Path(tempfile.mkdtemp(prefix="flux-rbac-oracle-test.")).resolve()
        self.state = OracleApiState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), OracleApiHandler)
        self.server.state = self.state  # type: ignore[attr-defined]
        ca_key = self.scratch / "ca-key.pem"
        ca_cert = self.scratch / "ca.pem"
        server_key = self.scratch / "server-key.pem"
        server_csr = self.scratch / "server.csr"
        server_cert = self.scratch / "server.pem"
        client_key = self.scratch / "client-key.pem"
        client_csr = self.scratch / "client.csr"
        client_cert = self.scratch / "client.pem"
        extension = self.scratch / "server.ext"
        extension.write_text("subjectAltName=IP:127.0.0.1\n", encoding="utf-8")
        commands = (
            ("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=oracle-ca", "-keyout", str(ca_key), "-out", str(ca_cert)),
            ("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", str(server_key), "-out", str(server_csr)),
            ("x509", "-req", "-days", "1", "-in", str(server_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-extfile", str(extension), "-out", str(server_cert)),
            ("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=oracle-client", "-keyout", str(client_key), "-out", str(client_csr)),
            ("x509", "-req", "-days", "1", "-in", str(client_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAserial", str(self.scratch / "ca.srl"), "-out", str(client_cert)),
        )
        for command in commands:
            generated = subprocess.run(
                [OPENSSL, *command], capture_output=True, check=False
            )
            if generated.returncode != 0:
                self.server.server_close()
                shutil.rmtree(self.scratch, ignore_errors=True)
                raise unittest.SkipTest(
                    "openssl could not create the ephemeral mTLS fixture"
                )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(server_cert, server_key)
        context.load_verify_locations(cafile=ca_cert)
        context.verify_mode = ssl.CERT_REQUIRED
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"https://127.0.0.1:{self.server.server_address[1]}"
        self.kubeconfig_path = self.scratch / "kubeconfig"
        encoded = lambda path: base64.b64encode(path.read_bytes()).decode("ascii")
        self.kubeconfig_path.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "current-context": "oracle",
                    "clusters": [
                        {
                            "name": "oracle-cluster",
                            "cluster": {
                                "server": self.endpoint,
                                "certificate-authority-data": encoded(ca_cert),
                            },
                        }
                    ],
                    "users": [
                        {
                            "name": "oracle-user",
                            "user": {
                                "client-certificate-data": encoded(client_cert),
                                "client-key-data": encoded(client_key),
                            },
                        }
                    ],
                    "contexts": [
                        {
                            "name": "oracle",
                            "context": {
                                "cluster": "oracle-cluster",
                                "user": "oracle-user",
                            },
                        }
                    ],
                    "preferences": {},
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
            newline="\n",
        )
        self.kubeconfig_path.chmod(0o600)
        self.kubectl_path = Path(KUBECTL).resolve()
        self.kubectl = oracle.BoundFile(
            self.kubectl_path,
            executable=True,
            expected_digest=hashlib.sha256(self.kubectl_path.read_bytes()).hexdigest(),
        )
        self.kubeconfig = oracle.BoundFile(self.kubeconfig_path, executable=False)
        self.adapter = oracle.KubectlAdapter(
            self.kubectl, self.kubeconfig, "oracle", self.endpoint
        )

    def reset(self) -> None:
        self.state = OracleApiState()
        self.server.state = self.state  # type: ignore[attr-defined]

    def close(self) -> None:
        self.kubectl.close()
        self.kubeconfig.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        shutil.rmtree(self.scratch, ignore_errors=True)

    def run_denial(self) -> tuple[int, dict[str, object]]:
        return oracle.run_oracle(
            self.adapter,
            subject="system:serviceaccount:flux-system:kustomize-controller",
            verb="create",
            group="apps",
            resource="deployments",
            namespace="kube-system",
            name=None,
            expected="DENIED",
        )

    def run_allowed(self) -> tuple[int, dict[str, object]]:
        return oracle.run_oracle(
            self.adapter,
            subject="system:serviceaccount:flux-system:source-controller",
            verb="create",
            group="coordination.k8s.io",
            resource="leases",
            namespace="flux-system",
            name=None,
            expected="ALLOWED",
        )

    def run_pre_deletion_protected_allowed(self) -> tuple[int, dict[str, object]]:
        self.state.pre_deletion_broad_binding = True
        return oracle.run_oracle(
            self.adapter,
            subject="system:serviceaccount:flux-system:kustomize-controller",
            verb="create",
            group="apps",
            resource="deployments",
            namespace="kube-system",
            name=None,
            expected="ALLOWED",
        )

    def run_all_namespaces(self) -> tuple[int, dict[str, object]]:
        return oracle.run_oracle(
            self.adapter,
            subject="system:serviceaccount:flux-system:kustomize-controller",
            verb="list",
            group="kustomize.toolkit.fluxcd.io",
            resource="kustomizations",
            namespace=None,
            name=None,
            all_namespaces=True,
            expected="ALLOWED",
        )

    def run_token_denial(self) -> tuple[int, dict[str, object]]:
        return oracle.run_oracle(
            self.adapter,
            subject="system:serviceaccount:flux-system:kustomize-controller",
            verb="create",
            group="",
            resource="serviceaccounts/token",
            namespace="flux-system",
            name="controller",
            expected="DENIED",
        )


@unittest.skipUnless(POSIX_CUSTODY, "POSIX descriptor custody runs under WSL/Linux or macOS")
class FluxRbacOracleCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="flux-rbac-custody-test.")).resolve()
        self.tool = self.scratch / "kubectl"
        self.tool.write_text("#!/bin/bash -p\nprintf '%s\\n' trusted\n", encoding="utf-8")
        self.tool.chmod(0o700)
        self.digest = hashlib.sha256(self.tool.read_bytes()).hexdigest()

    def tearDown(self) -> None:
        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_symlink_hardlink_and_unsafe_mode_are_refused(self) -> None:
        link = self.scratch / "kubectl-link"
        link.symlink_to(self.tool.name)
        with self.subTest(case="symlink"), self.assertRaises(oracle.OracleError):
            oracle.BoundFile(link, executable=True, expected_digest=self.digest)
        hardlink = self.scratch / "kubectl-hardlink"
        os.link(self.tool, hardlink)
        with self.subTest(case="hardlink"), self.assertRaises(oracle.OracleError):
            oracle.BoundFile(self.tool, executable=True, expected_digest=self.digest)
        hardlink.unlink()
        self.tool.chmod(0o722)
        with self.subTest(case="mode"), self.assertRaises(oracle.OracleError):
            oracle.BoundFile(self.tool, executable=True, expected_digest=self.digest)

    def test_wrong_executable_digest_is_refused(self) -> None:
        wrong_digest = "0" * 64
        self.assertNotEqual(wrong_digest, self.digest)
        with self.assertRaisesRegex(oracle.OracleError, "reviewed SHA-256 pin"):
            oracle.BoundFile(
                self.tool,
                executable=True,
                expected_digest=wrong_digest,
            )

    def test_symlinked_parent_is_refused(self) -> None:
        real_parent = self.scratch / "real-parent"
        real_parent.mkdir()
        nested_tool = real_parent / "kubectl"
        nested_tool.write_bytes(self.tool.read_bytes())
        nested_tool.chmod(0o700)
        alias = self.scratch / "parent-alias"
        alias.symlink_to(real_parent, target_is_directory=True)
        digest = hashlib.sha256(nested_tool.read_bytes()).hexdigest()
        with self.assertRaises(oracle.OracleError):
            oracle.BoundFile(alias / "kubectl", executable=True, expected_digest=digest)

    def test_wrong_owner_metadata_is_refused(self) -> None:
        values = list(self.tool.stat())
        values[stat.ST_UID] = os.geteuid() + 1
        with self.assertRaisesRegex(oracle.OracleError, "owner"):
            oracle._validate_regular_source(os.stat_result(values), executable=True)

    def test_source_replacement_race_is_refused(self) -> None:
        real_hash = oracle._sha256_fd
        calls = 0

        def replace_after_first_hash(descriptor: int) -> str:
            nonlocal calls
            result = real_hash(descriptor)
            calls += 1
            if calls == 1:
                replacement = self.scratch / "replacement"
                replacement.write_text("#!/bin/bash -p\nexit 97\n", encoding="utf-8")
                replacement.chmod(0o700)
                replacement.replace(self.tool)
            return result

        with mock.patch.object(oracle, "_sha256_fd", side_effect=replace_after_first_hash):
            with self.assertRaisesRegex(oracle.OracleError, "changed"):
                oracle.BoundFile(self.tool, executable=True, expected_digest=self.digest)

    def test_source_path_replacement_cannot_change_invoked_bytes(self) -> None:
        with oracle.BoundFile(self.tool, executable=True, expected_digest=self.digest) as bound:
            hostile = self.scratch / "hostile"
            hostile.write_text("#!/bin/bash -p\nprintf '%s\\n' hostile\n", encoding="utf-8")
            hostile.chmod(0o700)
            hostile.replace(self.tool)
            completed = subprocess.run(
                [bound.invocation_path()],
                executable=bound.invocation_path(),
                pass_fds=(bound.descriptor,),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "trusted\n")

    def test_production_adapter_invokes_only_the_held_executable(self) -> None:
        config = self.scratch / "kubeconfig"
        config.write_bytes(_closed_kubeconfig_bytes())
        config.chmod(0o600)
        with oracle.BoundFile(self.tool, executable=True, expected_digest=self.digest) as tool:
            with oracle.BoundFile(config, executable=False) as kubeconfig:
                adapter = oracle.KubectlAdapter(
                    tool, kubeconfig, "oracle", "https://127.0.0.1:6443"
                )
                hostile = self.scratch / "hostile"
                hostile.write_text("#!/bin/bash -p\nexit 97\n", encoding="utf-8")
                hostile.chmod(0o700)
                hostile.replace(self.tool)
                completed = adapter.run(())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, b"trusted\n")

    def test_descriptor_provenance_is_rechecked_before_invocation(self) -> None:
        with oracle.BoundFile(self.tool, executable=True, expected_digest=self.digest) as bound:
            os.fchmod(bound.descriptor, 0o700)
            with self.assertRaisesRegex(oracle.OracleError, "mode"):
                bound.invocation_path()

    def test_staged_kubeconfig_is_read_only_against_reopen_races(self) -> None:
        config = self.scratch / "kubeconfig"
        config.write_bytes(_closed_kubeconfig_bytes())
        config.chmod(0o600)
        with oracle.BoundFile(config, executable=False) as bound:
            self.assertEqual(stat.S_IMODE(os.fstat(bound.descriptor).st_mode), 0o400)
            with self.assertRaises(PermissionError):
                os.open(bound.invocation_path(), os.O_WRONLY)

    def test_adapter_refuses_unreviewed_context_or_server(self) -> None:
        config = self.scratch / "kubeconfig"
        config.write_bytes(_closed_kubeconfig_bytes())
        config.chmod(0o600)
        with oracle.BoundFile(self.tool, executable=True, expected_digest=self.digest) as tool:
            with oracle.BoundFile(config, executable=False) as kubeconfig:
                for context, server in (
                    ("foreign-context", "https://127.0.0.1:6443"),
                    ("oracle", "https://127.0.0.1:7443"),
                ):
                    with self.subTest(context=context, server=server):
                        with self.assertRaisesRegex(oracle.OracleError, "reviewed target"):
                            oracle.KubectlAdapter(tool, kubeconfig, context, server)

    def test_external_kubeconfig_references_and_exec_plugins_are_never_opened(self) -> None:
        sentinel = self.scratch / "must-not-open"
        base = {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "oracle",
            "clusters": [{"name": "cluster", "cluster": {"server": "https://127.0.0.1:6443"}}],
            "users": [{"name": "user", "user": {}}],
            "contexts": [{"name": "oracle", "context": {"cluster": "cluster", "user": "user"}}],
            "preferences": {},
        }
        hostile = (
            ("certificate-authority", {"certificate-authority": str(sentinel)}),
            ("client-key", {"client-key": str(sentinel)}),
            ("tokenFile", {"tokenFile": str(sentinel)}),
            ("exec", {"exec": {"command": str(sentinel), "apiVersion": "client.authentication.k8s.io/v1"}}),
        )
        real_open = os.open

        def guarded_open(path: object, *args: object, **kwargs: object) -> int:
            self.assertNotEqual(str(path), str(sentinel), "external kubeconfig source opened")
            return real_open(path, *args, **kwargs)

        for label, value in hostile:
            with self.subTest(label=label):
                document = json.loads(json.dumps(base))
                if label == "certificate-authority":
                    document["clusters"][0]["cluster"].update(value)
                else:
                    document["users"][0]["user"].update(value)
                config = self.scratch / f"{label}.json"
                config.write_text(json.dumps(document), encoding="utf-8")
                config.chmod(0o600)
                with mock.patch.object(oracle.os, "open", side_effect=guarded_open):
                    with self.assertRaisesRegex(oracle.OracleError, "flattened"):
                        oracle.BoundFile(config, executable=False)
                self.assertFalse(sentinel.exists())

    def test_unreviewed_script_interpreter_is_refused(self) -> None:
        self.tool.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        self.tool.chmod(0o700)
        digest = hashlib.sha256(self.tool.read_bytes()).hexdigest()
        with self.assertRaisesRegex(oracle.OracleError, "fixed"):
            oracle.BoundFile(self.tool, executable=True, expected_digest=digest)


class FluxRbacOracleIdentityTests(unittest.TestCase):
    def test_exact_canonical_service_account_is_accepted(self) -> None:
        self.assertEqual(
            oracle.canonical_service_account(
                "system:serviceaccount:flux-system:kustomize-controller"
            ),
            ("flux-system", "kustomize-controller"),
        )

    def test_boundary_adjacent_and_test_envelope_identities_are_refused(self) -> None:
        hostile = (
            "xsystem:serviceaccount:flux-system:kustomize-controller",
            "system:serviceaccount:flux-system:kustomize-controllerx/",
            "system:serviceaccount:flux-system:",
            "system:serviceaccount::kustomize-controller",
            "prefix[system:serviceaccount:flux-system:kustomize-controller]suffix",
            "fixture:system:serviceaccount:flux-system:kustomize-controller",
            "system:serviceaccount:flux-system:kustomize-controller\n",
            f"system:serviceaccount:{'n' * 64}:controller",
            f"system:serviceaccount:flux-system:{'n' * 64}.{'n' * 64}.{'n' * 64}.{'n' * 62}",
        )
        for value in hostile:
            with self.subTest(value=value), self.assertRaises(oracle.OracleError):
                oracle.canonical_service_account(value)


@unittest.skipUnless(POSIX_CUSTODY and KUBECTL, "real kubectl protocol parity requires POSIX custody and kubectl")
class FluxRbacOracleProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = ProtocolFixture()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.close()

    def setUp(self) -> None:
        self.fixture.reset()

    def tearDown(self) -> None:
        self.assertFalse(ROOT.joinpath(".kube").exists(), "kubectl cache escaped private custody")

    def test_real_kubectl_uses_discovery_and_self_subject_access_review(self) -> None:
        code, receipt = self.fixture.run_denial()
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["discovery"]["state"], "RESOLVED")
        self.assertEqual(
            receipt["discovery"],
            {
                "state": "RESOLVED",
                "groupVersion": "apps/v1",
                "resource": "deployments",
                "kind": "Deployment",
                "namespaced": True,
                "crdName": None,
                "verb": "create",
                "verbEvidence": "DISCOVERY",
            },
        )
        self.assertEqual(receipt["authorization"], "DENIED")
        posts = [item for item in self.fixture.state.requests if item["method"] == "POST"]
        self.assertEqual(len(posts), 4, self.fixture.state.requests)
        for item in posts:
            self.assertEqual(
                item["path"],
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews?timeout=10s",
            )
            self.assertIsNone(item["authorization"])
            self.assertEqual(item["clientCommonName"], "oracle-client")
            self.assertRegex(
                str(item["impersonate"]),
                r"\Asystem:serviceaccount:[a-z0-9-]+:[a-z0-9.-]+\Z",
            )
            self.assertEqual(
                item["impersonateGroups"],
                FLUX_SERVICE_ACCOUNT_GROUPS,
            )
            self.assertIsNone(item["contentType"])
        requested = posts[-1]["attributes"]
        self.assertEqual(
            requested,
            {
                "group": "apps",
                "version": "v1",
                "resource": "deployments",
                "verb": "create",
                "namespace": "kube-system",
            },
        )

    def test_absent_stale_foreign_malformed_warning_parse_and_transport_are_unresolved(self) -> None:
        for state in (
            "absent",
            "stale",
            "foreign-version",
            "foreign-crd",
            "foreign-kind",
            "foreign-scope",
            "foreign-crd-name",
            "duplicate-conditions",
            "malformed",
            "unparseable",
            "transport",
        ):
            with self.subTest(state=state):
                self.fixture.state.discovery_state = state
                self.fixture.state.requests.clear()
                with self.assertRaises(oracle.OracleError):
                    self.fixture.run_denial()
                self.assertFalse(
                    any(item["method"] == "POST" for item in self.fixture.state.requests),
                    "authorization must not run after unresolved discovery",
                )
        self.fixture.state.discovery_state = "reviewed"
        self.fixture.state.warning = True
        with self.assertRaisesRegex(oracle.OracleError, "warning"):
            self.fixture.run_denial()

    def test_constant_allow_is_non_evidence(self) -> None:
        self.fixture.state.constant_allow = True
        code, receipt = self.fixture.run_allowed()
        self.assertEqual(code, oracle.EXIT_MISMATCH)
        self.assertEqual(receipt["authorization"], "UNRESOLVED")
        self.assertEqual(receipt["controls"][-1]["name"], "inert-denial")
        self.assertEqual(receipt["controls"][-1]["authorization"], "ALLOWED")
        self.assertEqual(receipt["result"], "FAIL")

    def test_constant_deny_is_non_evidence(self) -> None:
        self.fixture.state.decisions.clear()
        code, receipt = self.fixture.run_denial()
        self.assertEqual(code, oracle.EXIT_MISMATCH)
        self.assertEqual(receipt["authorization"], "UNRESOLVED")
        self.assertEqual(receipt["controls"][0]["name"], "builtin-authorizer")
        self.assertEqual(receipt["controls"][0]["authorization"], "DENIED")
        self.assertEqual(receipt["result"], "FAIL")

    def test_foreign_or_malformed_authorization_responses_are_unresolved(self) -> None:
        for state in (
            "foreign-spec",
            "nonboolean-allowed",
            "nonboolean-denied",
            "evaluation-error",
            "contradictory",
        ):
            with self.subTest(state=state):
                self.fixture.state.authorization_response_state = state
                with self.assertRaises(oracle.OracleError):
                    self.fixture.run_denial()
        self.fixture.state.authorization_response_state = "explicit-denied"
        code, receipt = self.fixture.run_denial()
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["authorization"], "DENIED")

    def test_pre_deletion_broad_binding_can_be_observed_without_weakening_denial_control(self) -> None:
        code, receipt = self.fixture.run_pre_deletion_protected_allowed()
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["authorization"], "ALLOWED")
        self.assertEqual(receipt["controls"][-1]["name"], "inert-denial")
        self.assertEqual(receipt["controls"][-1]["authorization"], "DENIED")

    def test_requested_denial_becoming_allowed_fails_after_controls_pass(self) -> None:
        self.fixture.state.pre_deletion_broad_binding = True
        code, receipt = self.fixture.run_denial()
        self.assertEqual(code, oracle.EXIT_MISMATCH)
        self.assertEqual(receipt["authorization"], "ALLOWED")
        self.assertEqual(
            [control["authorization"] for control in receipt["controls"]],
            ["ALLOWED", "ALLOWED", "DENIED"],
        )
        self.assertEqual(receipt["result"], "FAIL")

    def test_all_namespaces_is_explicit_in_protocol_and_receipt(self) -> None:
        code, receipt = self.fixture.run_all_namespaces()
        self.assertEqual(code, 0, receipt)
        self.assertTrue(receipt["request"]["allNamespaces"])
        self.assertIsNone(receipt["request"]["namespace"])
        self.assertEqual(
            receipt["discovery"],
            {
                "state": "RESOLVED",
                "groupVersion": "kustomize.toolkit.fluxcd.io/v1",
                "resource": "kustomizations",
                "kind": "Kustomization",
                "namespaced": True,
                "crdName": "kustomizations.kustomize.toolkit.fluxcd.io",
                "verb": "list",
                "verbEvidence": "DISCOVERY",
            },
        )
        attributes = [
            item["attributes"]
            for item in self.fixture.state.requests
            if item["method"] == "POST"
        ][-1]
        self.assertNotIn("namespace", attributes)

    def test_subresource_is_separate_and_value_sensitive(self) -> None:
        code, receipt = self.fixture.run_token_denial()
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["request"]["resource"], "serviceaccounts/token")
        self.assertEqual(receipt["request"]["subresource"], "token")
        self.assertEqual(receipt["discovery"]["resource"], "serviceaccounts/token")
        self.assertEqual(
            self.fixture.state.requests[-1]["attributes"],
            {
                "verb": "create",
                "version": "v1",
                "resource": "serviceaccounts",
                "subresource": "token",
                "namespace": "flux-system",
                "name": "controller",
            },
        )

    def test_authorizer_is_value_sensitive_to_every_request_dimension(self) -> None:
        subject = "system:serviceaccount:flux-system:source-controller"
        identity = oracle.RESOURCE_IDENTITIES[("coordination.k8s.io", "leases")]
        baseline = oracle.authorize(
            self.fixture.adapter,
            subject=subject,
            verb="create",
            identity=identity,
            namespace="flux-system",
            name=None,
        )
        self.assertEqual(baseline, "ALLOWED")
        mutations = (
            (
                "identity-and-groups",
                "system:serviceaccount:flux-system:helm-controller",
                "create",
                identity,
                "flux-system",
                None,
            ),
            ("verb", subject, "patch", identity, "flux-system", None),
            (
                "group",
                subject,
                "create",
                oracle.ResourceIdentity("foreign.example", "v1", "leases", "Lease", True),
                "flux-system",
                None,
            ),
            (
                "version",
                subject,
                "create",
                oracle.ResourceIdentity("coordination.k8s.io", "v2", "leases", "Lease", True),
                "flux-system",
                None,
            ),
            (
                "resource",
                subject,
                "create",
                oracle.ResourceIdentity("coordination.k8s.io", "v1", "foreign", "Lease", True),
                "flux-system",
                None,
            ),
            (
                "subresource",
                subject,
                "create",
                oracle.ResourceIdentity(
                    "coordination.k8s.io", "v1", "leases", "Lease", True,
                    subresource="status",
                ),
                "flux-system",
                None,
            ),
            ("namespace", subject, "create", identity, "default", None),
            ("name", subject, "create", identity, "flux-system", "foreign"),
        )
        for label, changed_subject, verb, changed_identity, namespace, name in mutations:
            with self.subTest(dimension=label):
                self.assertEqual(
                    oracle.authorize(
                        self.fixture.adapter,
                        subject=changed_subject,
                        verb=verb,
                        identity=changed_identity,
                        namespace=namespace,
                        name=name,
                    ),
                    "DENIED",
                )
        self.fixture.state.discovery_state = "stale"
        self.assertEqual(
            oracle.authorize(
                self.fixture.adapter,
                subject=subject,
                verb="create",
                identity=identity,
                namespace="flux-system",
                name=None,
            ),
            "DENIED",
        )


class FluxRbacOraclePortableStructureTests(unittest.TestCase):
    def test_reviewed_verbs_and_name_grammars_are_exact_and_bounded(self) -> None:
        self.assertEqual(oracle.VERBS, {"create", "get", "impersonate", "list", "patch"})
        self.assertTrue(oracle._valid_namespace("n" * 63))
        self.assertFalse(oracle._valid_namespace("n" * 64))
        self.assertFalse(oracle._valid_namespace("flux.system"))
        self.assertTrue(oracle._valid_object_name("object.part"))
        self.assertFalse(oracle._valid_object_name("n" * 64 + ".part"))
        self.assertFalse(oracle._valid_object_name("n" * 254))
        self.assertEqual(
            oracle.service_account_groups(
                "system:serviceaccount:flux-system:kustomize-controller"
            ),
            (
                "system:serviceaccounts",
                "system:serviceaccounts:flux-system",
                "system:authenticated",
            ),
        )

    def test_executable_pin_is_mandatory_and_closed_before_any_path_open(self) -> None:
        unopened = Path("relative-path-must-not-be-opened")
        for pin in (None, "", "0" * 63, "A" * 64):
            with self.subTest(pin=pin), self.assertRaisesRegex(
                oracle.OracleError,
                "reviewed SHA-256 pin",
            ):
                oracle.BoundFile(
                    unopened,
                    executable=True,
                    expected_digest=pin,
                )

    def test_discovery_binds_the_exact_request_verb_without_kubectl(self) -> None:
        identity = oracle.RESOURCE_IDENTITIES[("apps", "deployments")]

        def completed(verbs: object) -> subprocess.CompletedProcess[bytes]:
            return _completed_json(
                _resource_list(
                    "apps/v1",
                    [_resource("deployments", "Deployment", True, verbs)],
                )
            )

        for verbs in (
            [],
            ["get", "list"],
            "create",
            ["create", "create"],
            ["create", 1],
            ["CREATE"],
        ):
            adapter = mock.Mock()
            adapter.run.return_value = completed(verbs)
            with self.subTest(verbs=verbs), self.assertRaisesRegex(
                oracle.OracleError,
                "exact reviewed request verb",
            ):
                oracle.discover(adapter, identity, "create")

        adapter = mock.Mock()
        adapter.run.return_value = completed(["create", "get", "list", "watch"])
        receipt = oracle.discover(adapter, identity, "create")
        self.assertEqual(receipt["verb"], "create")
        self.assertEqual(receipt["verbEvidence"], "DISCOVERY")
        self.assertEqual(receipt["resource"], "deployments")

        service_accounts = oracle.RESOURCE_IDENTITIES[("", "serviceaccounts")]
        adapter.run.return_value = _completed_json(
            _resource_list(
                "v1",
                [_resource("serviceaccounts", "ServiceAccount", True)],
            )
        )
        receipt = oracle.discover(adapter, service_accounts, "impersonate")
        self.assertEqual(receipt["verbEvidence"], "AUTHORIZATION_ONLY")
        adapter.run.return_value = completed(["create", "get", "list", "watch"])
        with self.assertRaisesRegex(oracle.OracleError, "exact reviewed request verb"):
            oracle.discover(adapter, identity, "impersonate")

    def test_authorization_protocol_shape_and_echo_are_portable(self) -> None:
        adapter = mock.Mock()
        subject = "system:serviceaccount:flux-system:kustomize-controller"
        spec = {
            "resourceAttributes": {
                "verb": "create",
                "version": "v1",
                "resource": "deployments",
                "group": "apps",
                "namespace": "kube-system",
            }
        }
        arguments = (
            "create",
            "--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            "-f",
            "-",
            f"--as={subject}",
            "--as-group=system:serviceaccounts",
            "--as-group=system:serviceaccounts:flux-system",
            "--as-group=system:authenticated",
        )
        request = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": spec,
        }
        response = {**request, "status": {"allowed": False, "denied": True}}
        adapter.run.return_value = _completed_json(response)
        self.assertEqual(
            oracle.authorize(
                adapter,
                subject=subject,
                verb="create",
                identity=oracle.RESOURCE_IDENTITIES[("apps", "deployments")],
                namespace="kube-system",
                name=None,
            ),
            "DENIED",
        )
        payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        adapter.run.assert_called_once_with(arguments, stdin=payload)

        foreign = json.loads(json.dumps(response))
        foreign["spec"]["resourceAttributes"]["namespace"] = "foreign"
        adapter.run.return_value = _completed_json(foreign)
        with self.assertRaisesRegex(oracle.OracleError, "exactly echo"):
            oracle.authorize(
                adapter,
                subject=subject,
                verb="create",
                identity=oracle.RESOURCE_IDENTITIES[("apps", "deployments")],
                namespace="kube-system",
                name=None,
            )

    def test_constant_answer_controls_are_portable(self) -> None:
        request = {
            "subject": "system:serviceaccount:flux-system:source-controller",
            "verb": "create",
            "group": "coordination.k8s.io",
            "resource": "leases",
            "namespace": "flux-system",
            "name": None,
            "expected": "ALLOWED",
        }
        with mock.patch.object(
            oracle,
            "discover",
            return_value={"state": "RESOLVED"},
        ):
            for answer in ("ALLOWED", "DENIED"):
                with self.subTest(answer=answer), mock.patch.object(
                    oracle,
                    "authorize",
                    return_value=answer,
                ):
                    code, receipt = oracle.run_oracle(mock.Mock(), **request)
                    self.assertEqual(code, oracle.EXIT_MISMATCH)
                    self.assertEqual(receipt["result"], "FAIL")

    def test_cli_has_no_apply_or_mutating_kubectl_verb(self) -> None:
        source = (ROOT / "scripts" / "flux_rbac_denial_oracle.py").read_text(encoding="utf-8")
        for forbidden in ('"apply"', '"patch"', '"delete"', '"create"'):
            if forbidden == '"create"':
                continue  # authorization requests may ask whether create is allowed.
            self.assertNotIn(f"adapter.run(({forbidden}", source)
        self.assertIn('"--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"', source)
        self.assertIn('"get", f"--raw=', source)

    def test_windows_runtime_refusal_keeps_parsing_and_identity_portable(self) -> None:
        with mock.patch.object(oracle.platform, "system", return_value="Windows"):
            with self.assertRaisesRegex(oracle.OracleError, "WSL"):
                oracle._pin_key()
        self.assertEqual(
            oracle.RESOURCE_IDENTITIES[("apps", "deployments")].group_version,
            "apps/v1",
        )

    def test_required_linux_ci_lane_uses_repository_pinned_kubectl(self) -> None:
        if not (
            os.environ.get("GITHUB_ACTIONS") == "true"
            and platform.system() == "Linux"
        ):
            self.skipTest("the required process-level parity lane runs in Linux CI")
        self.assertTrue(POSIX_CUSTODY)
        self.assertIsNotNone(KUBECTL, "Linux CI must not skip real-kubectl parity")
        pins = {}
        for line in ROOT.joinpath("versions.env").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                pins[key] = value
        pin_key = oracle._pin_key()
        self.assertIn(pin_key, pins)
        self.assertEqual(
            hashlib.sha256(Path(KUBECTL or "").resolve().read_bytes()).hexdigest(),
            pins[pin_key],
        )

    def test_invalid_scope_verb_and_names_never_reach_kubectl(self) -> None:
        adapter = mock.Mock()
        hostile = (
            {"verb": "--as=attacker", "namespace": "default", "all_namespaces": False},
            {"verb": "get", "namespace": None, "all_namespaces": False},
            {"verb": "get", "namespace": "Bad_Namespace", "all_namespaces": False},
            {"verb": "get", "namespace": "default", "all_namespaces": True},
        )
        for changed in hostile:
            with self.subTest(changed=changed), self.assertRaises(oracle.OracleError):
                oracle.run_oracle(
                    adapter,
                    subject="system:serviceaccount:flux-system:kustomize-controller",
                    verb=changed["verb"],
                    group="apps",
                    resource="deployments",
                    namespace=changed["namespace"],
                    name=None,
                    all_namespaces=changed["all_namespaces"],
                    expected="DENIED",
                )
        adapter.run.assert_not_called()

    def test_invalid_expected_state_and_nonboolean_scope_never_reach_kubectl(self) -> None:
        adapter = mock.Mock()
        for expected, all_namespaces in (("UNRESOLVED", False), ("DENIED", 1)):
            with self.subTest(expected=expected, all_namespaces=all_namespaces):
                with self.assertRaises(oracle.OracleError):
                    oracle.run_oracle(
                        adapter,
                        subject="system:serviceaccount:flux-system:kustomize-controller",
                        verb="get",
                        group="",
                        resource="secrets",
                        namespace="kube-system",
                        name=None,
                        all_namespaces=all_namespaces,
                        expected=expected,
                    )
        adapter.run.assert_not_called()

    def test_process_timeout_is_a_closed_transport_failure(self) -> None:
        kubectl = mock.Mock(descriptor=3)
        kubectl.invocation_path.return_value = "/proc/self/fd/3"
        kubeconfig = mock.Mock(
            descriptor=4,
            kubeconfig_context="oracle",
            kubeconfig_server="https://127.0.0.1:6443",
            work=Path("/tmp/oracle-test-custody"),
        )
        kubeconfig.invocation_path.return_value = "/proc/self/fd/4"
        adapter = oracle.KubectlAdapter(
            kubectl, kubeconfig, "oracle", "https://127.0.0.1:6443"
        )
        with mock.patch.object(
            oracle.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("kubectl", 15),
        ):
            with self.assertRaisesRegex(oracle.OracleError, "bounded response"):
                adapter.run(("get", "--raw=/api/v1"))

    def test_direct_checkout_entrypoint_is_blocked_without_opening_inputs(self) -> None:
        sentinel = "/protected/sentinel-kubeconfig-token"
        stdout = io.StringIO()
        with mock.patch.object(oracle, "BoundFile") as bound, mock.patch(
            "sys.stdout", stdout
        ):
            code = oracle.main(
                (
                    "--kubectl", "/protected/kubectl",
                    "--kubeconfig", sentinel,
                    "--context", "private-context",
                    "--server", "https://private-sentinel.invalid",
                    "--subject", "system:serviceaccount:flux-system:kustomize-controller",
                    "--verb", "get",
                    "--resource", "secrets",
                    "--namespace", "kube-system",
                    "--expect", "DENIED",
                )
            )
        self.assertEqual(code, oracle.EXIT_UNRESOLVED)
        bound.assert_not_called()
        self.assertIn("trusted reviewed-blob launcher", stdout.getvalue())
        for private in (sentinel, "private-context", "private-sentinel"):
            self.assertNotIn(private, stdout.getvalue())

    def test_direct_script_entrypoint_is_importable_and_fails_closed(self) -> None:
        script = ROOT / "scripts" / "flux_rbac_denial_oracle.py"
        help_result = subprocess.run(
            [sys.executable, "-B", str(script), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(script),
                "--kubectl", "/protected/kubectl-sentinel",
                "--kubeconfig", "/protected/kubeconfig-sentinel",
                "--context", "private-context",
                "--server", "https://private-sentinel.invalid",
                "--subject", "system:serviceaccount:flux-system:kustomize-controller",
                "--verb", "get",
                "--resource", "secrets",
                "--namespace", "kube-system",
                "--expect", "DENIED",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, oracle.EXIT_UNRESOLVED, result.stderr)
        self.assertEqual(result.stderr, "")
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["result"], "UNRESOLVED")
        for private in ("kubectl-sentinel", "kubeconfig-sentinel", "private-context"):
            self.assertNotIn(private, result.stdout)

    def test_runbook_preserves_do_not_apply_and_blocks_checkout_execution(self) -> None:
        text = (ROOT / "docs" / "runbooks" / "flux-rbac-narrowing.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Status: `DO NOT APPLY`", text)
        self.assertIn("BLOCKED", text)
        self.assertNotIn("python3 -B scripts/flux_rbac_denial_oracle.py", text)


if __name__ == "__main__":
    unittest.main()
