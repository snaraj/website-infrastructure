"""Adversarial tests for the protected kubeconfig snapshot validator."""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_kubeconfig_snapshot.py"
SPEC = importlib.util.spec_from_file_location("validate_kubeconfig_snapshot", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def pem_blob(label: str, marker: int, length: int = 96) -> bytes:
    """Create a structurally canonical synthetic PEM block at runtime."""

    der = b"\x30" + bytes((marker,)) * (length - 1)
    body = base64.b64encode(der).decode("ascii")
    lines = [body[offset : offset + 64] for offset in range(0, len(body), 64)]
    return (
        "-----BEGIN "
        + label
        + "-----\n"
        + "\n".join(lines)
        + "\n-----END "
        + label
        + "-----\n"
    ).encode("ascii")


def embedded(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")


def valid_document() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "preferences": {},
        "current-context": "operator@kubernetes",
        "clusters": [
            {
                "name": "kubernetes",
                "cluster": {
                    "server": "https://127.0.0.1:6443",
                    "certificate-authority-data": embedded(
                        pem_blob("CERTIFICATE", 1)
                    ),
                },
            }
        ],
        "users": [
            {
                "name": "operator",
                "user": {
                    "client-certificate-data": embedded(
                        pem_blob("CERTIFICATE", 2)
                    ),
                    "client-key-data": embedded(pem_blob("PRIVATE KEY", 3)),
                },
            }
        ],
        "contexts": [
            {
                "name": "operator@kubernetes",
                "context": {
                    "cluster": "kubernetes",
                    "user": "operator",
                    "namespace": "default",
                },
            }
        ],
    }


def document_bytes(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def parse(document: dict) -> None:
    MODULE.parse_snapshot(document_bytes(document))


def write_private(path: Path, raw: bytes | None = None) -> Path:
    path.write_bytes(document_bytes(valid_document()) if raw is None else raw)
    if os.name == "posix":
        path.chmod(0o600)
    return path


class KubeconfigSchemaTests(unittest.TestCase):
    """Require one exact, fully embedded kubeconfig authority graph."""

    def test_accepts_exact_closed_document_and_optional_namespace(self):
        parse(valid_document())
        document = valid_document()
        del document["contexts"][0]["context"]["namespace"]
        parse(document)

    def test_accepts_exact_dns_server_and_all_supported_key_encodings(self):
        for label in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"):
            document = valid_document()
            document["clusters"][0]["cluster"]["server"] = (
                "https://api.example.test:6443"
            )
            document["users"][0]["user"]["client-key-data"] = embedded(
                pem_blob(label, 3)
            )
            with self.subTest(label=label):
                parse(document)

    def test_rejects_yaml_bom_non_utf8_nonfinite_and_duplicate_json_keys(self):
        invalid_documents = (
            b"apiVersion: v1\nkind: Config\n",
            b"\xef\xbb\xbf{}",
            b"\xff{}",
            b'{"apiVersion":NaN}',
        )
        for raw in invalid_documents:
            with self.subTest(prefix=raw[:4]), self.assertRaises(MODULE.SnapshotError):
                MODULE.parse_snapshot(raw)

        raw = document_bytes(valid_document())
        duplicate = raw.replace(
            b'"kind":"Config"', b'"kind":"Config","kind":"Config"', 1
        )
        with self.assertRaises(MODULE.DuplicateKeyError):
            MODULE.parse_snapshot(duplicate)
        nested_duplicate = raw.replace(
            b'"server":"https://127.0.0.1:6443"',
            b'"server":"https://127.0.0.1:6443",'
            b'"server":"https://127.0.0.1:6443"',
            1,
        )
        with self.assertRaises(MODULE.DuplicateKeyError):
            MODULE.parse_snapshot(nested_duplicate)

    def test_top_level_schema_is_exact(self):
        mutations = []
        for key in MODULE.TOP_LEVEL_KEYS:
            document = valid_document()
            del document[key]
            mutations.append(document)
        for field, value in (
            ("extensions", []),
            ("extra", False),
        ):
            document = valid_document()
            document[field] = value
            mutations.append(document)
        for document in mutations:
            with self.subTest(keys=sorted(document)), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

        document = valid_document()
        document["preferences"] = {"colors": True}
        with self.assertRaises(MODULE.SnapshotError):
            parse(document)

    def test_api_version_and_kind_are_exact_strings(self):
        for field, value in (
            ("apiVersion", "v1beta1"),
            ("apiVersion", True),
            ("kind", "List"),
            ("kind", None),
        ):
            document = valid_document()
            document[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

    def test_each_authority_collection_is_exactly_one_object(self):
        for field in ("clusters", "users", "contexts"):
            for value in ([], [1], {}, None):
                document = valid_document()
                document[field] = value
                with self.subTest(field=field, shape=type(value).__name__), self.assertRaises(
                    MODULE.SnapshotError
                ):
                    parse(document)
            document = valid_document()
            document[field].append(copy.deepcopy(document[field][0]))
            with self.subTest(field=field, shape="two"), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

    def test_named_entry_wrappers_are_closed(self):
        for collection, body_name in (
            ("clusters", "cluster"),
            ("users", "user"),
            ("contexts", "context"),
        ):
            document = valid_document()
            document[collection][0]["unsupported"] = None
            with self.subTest(collection=collection, mutation="extra"), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)
            document = valid_document()
            del document[collection][0][body_name]
            with self.subTest(collection=collection, mutation="missing"), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

    def test_names_are_bounded_ascii_and_reference_exactly(self):
        for collection in ("clusters", "users", "contexts"):
            for bad_name in ("", "-bad", "bad/child", "bad:name", "caf\u00e9", "x" * 129):
                document = valid_document()
                document[collection][0]["name"] = bad_name
                with self.subTest(collection=collection, name=bad_name[:8]), self.assertRaises(
                    MODULE.SnapshotError
                ):
                    parse(document)

        reference_mutations = (
            ("current-context", None, "different"),
            ("cluster", "context", "different"),
            ("user", "context", "different"),
        )
        for field, parent, value in reference_mutations:
            document = valid_document()
            target = document if parent is None else document["contexts"][0][parent]
            target[field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.SnapshotError):
                parse(document)

    def test_cluster_schema_forbids_external_and_unsafe_transport_fields(self):
        for field, value in (
            ("certificate-authority", "/protected/ca.pem"),
            ("insecure-skip-tls-verify", True),
            ("proxy-url", "http://127.0.0.1:8080"),
            ("disable-compression", True),
            ("extensions", []),
        ):
            document = valid_document()
            document["clusters"][0]["cluster"][field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.SnapshotError):
                parse(document)

    def test_user_schema_allows_only_embedded_certificate_and_key(self):
        forbidden = (
            ("exec", {"command": "helper"}),
            ("auth-provider", {"name": "oidc"}),
            ("token", "credential"),
            ("tokenFile", "/protected/token"),
            ("client-certificate", "/protected/client.crt"),
            ("client-key", "/protected/client.key"),
            ("username", "operator"),
            ("password", "credential"),
        )
        for field, value in forbidden:
            document = valid_document()
            document["users"][0]["user"][field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.SnapshotError):
                parse(document)
        for required in MODULE.USER_KEYS:
            document = valid_document()
            del document["users"][0]["user"][required]
            with self.subTest(required=required), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

    def test_context_is_closed_and_namespace_is_one_dns_label(self):
        for field, value in (("extensions", []), ("unsupported", False)):
            document = valid_document()
            document["contexts"][0]["context"][field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.SnapshotError):
                parse(document)
        for namespace in ("", "UPPER", "two.parts", "-start", "end-", "x" * 64, 1):
            document = valid_document()
            document["contexts"][0]["context"]["namespace"] = namespace
            with self.subTest(namespace=namespace), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

    def test_https_server_is_canonical_and_has_no_url_side_channels(self):
        invalid_servers = (
            "http://127.0.0.1:6443",
            "HTTPS://127.0.0.1:6443",
            "https://user@127.0.0.1:6443",
            "https://127.0.0.1:6443/",
            "https://127.0.0.1:6443/path",
            "https://127.0.0.1:6443?query=yes",
            "https://127.0.0.1:6443#fragment",
            "https://127.000.000.001:6443",
            "https://127.0.0.1:0",
            "https://127.0.0.1:65536",
            "https://127.0.0.1:06443",
            "https://EXAMPLE.test:6443",
            "https://example.test.:6443",
            "https://caf\u00e9.test:6443",
            " https://127.0.0.1:6443",
            "https://",
        )
        for server in invalid_servers:
            document = valid_document()
            document["clusters"][0]["cluster"]["server"] = server
            with self.subTest(server=server[:24]), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

    def test_tls_server_name_requires_an_ip_server_and_concrete_dns_name(self):
        document = valid_document()
        document["clusters"][0]["cluster"]["tls-server-name"] = (
            "api.example.test"
        )
        parse(document)

        mutations = (
            ("https://api.example.test:6443", "api.example.test"),
            ("https://127.0.0.1:6443", "127.0.0.1"),
            ("https://127.0.0.1:6443", "*.example.test"),
            ("https://127.0.0.1:6443", "API.example.test"),
            ("https://127.0.0.1:6443", ""),
        )
        for server, tls_name in mutations:
            document = valid_document()
            cluster = document["clusters"][0]["cluster"]
            cluster["server"] = server
            cluster["tls-server-name"] = tls_name
            with self.subTest(tls_name=tls_name), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

    def test_outer_base64_and_inner_pem_must_both_be_canonical(self):
        invalid_values = (
            "",
            "AA-_",
            embedded(b"not a PEM document"),
            embedded(pem_blob("CERTIFICATE", 1)) + "\n",
        )
        for value in invalid_values:
            document = valid_document()
            document["clusters"][0]["cluster"]["certificate-authority-data"] = value
            with self.subTest(value_length=len(value)), self.assertRaises(
                MODULE.SnapshotError
            ):
                parse(document)

        canonical = pem_blob("CERTIFICATE", 1)
        lines = canonical.decode("ascii").splitlines()
        joined = "".join(lines[1:-1])
        noncanonical_wrap = (
            lines[0] + "\n" + joined[:63] + "\n" + joined[63:] + "\n" + lines[-1] + "\n"
        ).encode("ascii")
        document = valid_document()
        document["clusters"][0]["cluster"]["certificate-authority-data"] = embedded(
            noncanonical_wrap
        )
        with self.assertRaises(MODULE.SnapshotError):
            parse(document)

    def test_pem_roles_lengths_and_separation_are_fail_closed(self):
        mutations = []
        document = valid_document()
        document["clusters"][0]["cluster"]["certificate-authority-data"] = embedded(
            pem_blob("CERTIFICATE", 1, length=63)
        )
        mutations.append(document)

        document = valid_document()
        document["users"][0]["user"]["client-key-data"] = embedded(
            pem_blob("ENCRYPTED PRIVATE KEY", 3)
        )
        mutations.append(document)

        document = valid_document()
        document["users"][0]["user"]["client-certificate-data"] = document[
            "clusters"
        ][0]["cluster"]["certificate-authority-data"]
        mutations.append(document)

        document = valid_document()
        document["users"][0]["user"]["client-key-data"] = 1
        mutations.append(document)

        for index, document in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(MODULE.SnapshotError):
                parse(document)


class KubeconfigSnapshotReaderTests(unittest.TestCase):
    """Bind parsed bytes to one private regular path without link traversal."""

    def test_reads_one_absolute_private_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_private(Path(directory) / "snapshot.json")
            self.assertEqual(MODULE.read_snapshot(str(path.resolve())), path.read_bytes())

    def test_rejects_relative_directory_empty_and_oversize_inputs(self):
        with self.assertRaises(MODULE.SnapshotError):
            MODULE.read_snapshot("relative/snapshot.json")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(root.resolve()))
            empty = write_private(root / "empty.json", b"")
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(empty.resolve()))
            oversized = write_private(
                root / "oversized.json", b"x" * (MODULE.MAX_KUBECONFIG_BYTES + 1)
            )
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(oversized.resolve()))

    def test_rejects_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_private(root / "snapshot.json")
            alias = root / "alias.json"
            try:
                os.link(source, alias)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(source.resolve()))

    def test_rejects_file_and_ancestor_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = write_private(root / "target.json")
            link = root / "snapshot.json"
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(link.absolute()))

            real_directory = root / "real"
            real_directory.mkdir()
            nested = write_private(real_directory / "nested.json")
            linked_directory = root / "linked"
            linked_directory.symlink_to(real_directory, target_is_directory=True)
            self.assertTrue(nested.exists())
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str((linked_directory / "nested.json").absolute()))

    @unittest.skipUnless(os.name == "posix", "POSIX ownership and mode are required")
    def test_rejects_group_or_world_access_and_nonregular_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_private(root / "snapshot.json")
            path.chmod(0o640)
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(path.resolve()))
            fifo = root / "snapshot.fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(fifo.resolve()))

    @unittest.skipUnless(os.name == "posix", "atomic rename race is POSIX-specific")
    def test_rejects_path_replacement_during_same_handle_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_private(root / "snapshot.json")
            replacement = write_private(root / "replacement.json")
            retired = root / "retired.json"
            original_read = os.read
            raced = False

            def racing_read(descriptor, count):
                nonlocal raced
                chunk = original_read(descriptor, count)
                if chunk and not raced:
                    raced = True
                    path.rename(retired)
                    replacement.rename(path)
                return chunk

            with mock.patch.object(MODULE.os, "read", side_effect=racing_read):
                with self.assertRaises(MODULE.SnapshotError):
                    MODULE.read_snapshot(str(path.resolve()))
            self.assertTrue(raced)


class KubeconfigSnapshotCliTests(unittest.TestCase):
    """Keep the CLI isolated, environment-only, bounded, and content-neutral."""

    def run_cli(self, path: Path | None, *arguments: str, isolated: bool = True):
        environment = os.environ.copy()
        if path is None:
            environment.pop(MODULE.KUBECONFIG_SNAPSHOT_ENV, None)
        else:
            environment[MODULE.KUBECONFIG_SNAPSHOT_ENV] = str(path.resolve())
        command = [sys.executable]
        if isolated:
            command.append("-I")
        command.append(str(SCRIPT))
        command.extend(arguments)
        return subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def test_cli_passes_only_in_isolated_mode_with_environment_path(self):
        with tempfile.TemporaryDirectory(prefix="identifier-must-not-print-") as directory:
            path = write_private(Path(directory) / "sensitive-context-marker.json")
            result = self.run_cli(path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout, "PASS Kubernetes kubeconfig snapshot validation.\n"
            )
            self.assertEqual(result.stderr, "")
            self.assertNotIn("sensitive-context-marker", result.stdout)
            self.assertNotIn("operator@kubernetes", result.stdout)

            nonisolated = self.run_cli(path, isolated=False)
            self.assertEqual(nonisolated.returncode, 1)
            self.assertEqual(nonisolated.stdout, "")
            self.assertEqual(
                nonisolated.stderr,
                "FAIL Kubernetes kubeconfig snapshot validation.\n",
            )

    def test_cli_has_no_positional_or_option_path_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_private(Path(directory) / "snapshot.json")
            for argument in (str(path), "--file", "--help"):
                with self.subTest(argument=argument):
                    result = self.run_cli(path, argument)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr,
                        "FAIL Kubernetes kubeconfig snapshot validation.\n",
                    )

    def test_cli_missing_or_invalid_input_never_echoes_path_or_content(self):
        missing = self.run_cli(None)
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(
            missing.stderr, "FAIL Kubernetes kubeconfig snapshot validation.\n"
        )
        with tempfile.TemporaryDirectory(prefix="never-echo-this-") as directory:
            path = write_private(Path(directory) / "private-marker.json", b"private-value")
            result = self.run_cli(path)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr, "FAIL Kubernetes kubeconfig snapshot validation.\n"
            )
            self.assertNotIn("never-echo-this", result.stderr)
            self.assertNotIn("private-value", result.stderr)

    def test_main_collapses_unexpected_exceptions_to_the_generic_failure(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(MODULE.sys, "flags") as flags, mock.patch.object(
            MODULE, "validate", side_effect=RuntimeError("protected-value")
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            flags.isolated = 1
            result = MODULE.main([])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(), "FAIL Kubernetes kubeconfig snapshot validation.\n"
        )
        self.assertNotIn("protected-value", stderr.getvalue())

    def test_validator_is_stdlib_only_and_has_no_network_or_command_surface(self):
        source = SCRIPT.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertLessEqual(
            imported_roots,
            {
                "__future__",
                "base64",
                "binascii",
                "hmac",
                "ipaddress",
                "json",
                "os",
                "re",
                "stat",
                "sys",
                "urllib",
                "pathlib",
                "typing",
            },
        )
        for forbidden in ("subprocess", "socket", "http.client", "urlopen", "requests"):
            self.assertNotIn(forbidden, source)
        for required in (
            'KUBECONFIG_SNAPSHOT_ENV = "KUBECONFIG_SNAPSHOT_FILE"',
            "sys.flags.isolated != 1",
            "object_pairs_hook=_reject_duplicate_keys",
            "O_NOFOLLOW",
            "st_nlink != 1",
            "follow_symlinks=False",
            'print("FAIL Kubernetes kubeconfig snapshot validation."',
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
