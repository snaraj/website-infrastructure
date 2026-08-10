"""Adversarial tests for the protected SOPS ciphertext snapshot validator."""

from __future__ import annotations

import ast
import base64
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_sops_ciphertext_snapshot.py"
SPEC = importlib.util.spec_from_file_location(
    "validate_sops_ciphertext_snapshot", SCRIPT
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

SYNTHETIC_RECIPIENT = "age1" + "pq1" + ("q" * 80)
OTHER_RECIPIENT = "age1" + "pq1" + ("m" * 80)


def sops_envelope(payload: bytes) -> str:
    """Create one canonical, structurally synthetic SOPS scalar."""

    return "ENC[AES256_GCM,data:{},iv:{},tag:{},type:str]".format(
        base64.b64encode(payload).decode("ascii"),
        base64.b64encode(b"i" * 12).decode("ascii"),
        base64.b64encode(b"t" * 16).decode("ascii"),
    )


def valid_config(recipient: str = SYNTHETIC_RECIPIENT) -> bytes:
    return (
        "creation_rules:\n"
        "  - path_regex: ^kubernetes/.+\\.sops\\.ya?ml$\n"
        "    encrypted_regex: ^(data|stringData)$\n"
        "    age:\n"
        "      - {}\n".format(recipient)
    ).encode("utf-8")


def valid_ciphertext(recipient: str = SYNTHETIC_RECIPIENT) -> bytes:
    age_payload = (
        b"age-encryption.org/v1\n-> X25519 synthetic\n"
        b"c3ludGhldGlj\n--- synthetic-mac\nciphertext\n"
    )
    armored_body = "\n".join(
        "        " + line
        for line in textwrap.wrap(
            base64.b64encode(age_payload).decode("ascii"), 64
        )
    )
    return (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: pi-websites-tunnel-token\n"
        "  namespace: cloudflare-public\n"
        "type: Opaque\n"
        "stringData:\n"
        "  token: {}\n"
        "sops:\n"
        "  age:\n"
        "    - recipient: {}\n"
        "      enc: |\n"
        "        -----BEGIN AGE ENCRYPTED FILE-----\n"
        "{}\n"
        "        -----END AGE ENCRYPTED FILE-----\n"
        "  lastmodified: \"2026-08-09T00:00:00Z\"\n"
        "  mac: {}\n"
        "  encrypted_regex: ^(data|stringData)$\n"
        "  version: 3.13.3\n".format(
            sops_envelope(b"synthetic encrypted token"),
            recipient,
            armored_body,
            sops_envelope(b"synthetic authenticated mac"),
        )
    ).encode("utf-8")


def write_private(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    if os.name == "posix":
        path.chmod(0o600)
    return path


class SopsCiphertextGrammarTests(unittest.TestCase):
    """Reuse the reviewed exact SOPS and Tunnel Secret grammar in memory."""

    def test_accepts_exact_configured_hybrid_pq_tunnel_secret(self):
        MODULE.parse_snapshots(valid_config(), valid_ciphertext())

    def test_rejects_inert_sentinel_and_non_hybrid_recipient(self):
        sentinel = "age1" + "REPLACE_WITH_PUBLIC_RECIPIENT_BEFORE_ENCRYPTING"
        for recipient in (sentinel, "age1" + ("q" * 80)):
            with self.subTest(recipient_kind=recipient[:7]), self.assertRaises(
                MODULE.SnapshotError
            ):
                MODULE.parse_snapshots(
                    valid_config(recipient), valid_ciphertext(recipient)
                )

    def test_rejects_ciphertext_recipient_different_from_configuration(self):
        with self.assertRaises(MODULE.SnapshotError):
            MODULE.parse_snapshots(
                valid_config(SYNTHETIC_RECIPIENT),
                valid_ciphertext(OTHER_RECIPIENT),
            )

    def test_rejects_fake_or_plaintext_token_envelopes(self):
        original = sops_envelope(b"synthetic encrypted token").encode("ascii")
        mutations = (
            b"plaintext-value",
            b"ENC[AES256_GCM,data:AAAA,iv:AAAA,tag:AAAA,type:str]",
            (
                b"ENC[AES256_GCM,data:YWJj,iv:aWlpaWlpaWlpaWlp,"
                b"tag:dHR0dHR0dHR0dHR0dHR0dA,type:str]"
            ),
        )
        for replacement in mutations:
            with self.subTest(replacement_length=len(replacement)), self.assertRaises(
                MODULE.SnapshotError
            ):
                MODULE.parse_snapshots(
                    valid_config(),
                    valid_ciphertext().replace(original, replacement, 1),
                )

    def test_rejects_missing_malformed_or_reordered_sops_metadata(self):
        source = valid_ciphertext()
        mutations = (
            source.replace(
                b"  lastmodified: \"2026-08-09T00:00:00Z\"\n", b"", 1
            ),
            source.replace(b"  version: 3.13.3\n", b"  version: 3.13.2\n", 1),
            source.replace(
                sops_envelope(b"synthetic authenticated mac").encode("ascii"),
                b"ENC[AES256_GCM,data:AAAA,iv:AAAA,tag:AAAA,type:str]",
                1,
            ),
            source.replace(
                b"  mac: "
                + sops_envelope(b"synthetic authenticated mac").encode("ascii")
                + b"\n  encrypted_regex: ^(data|stringData)$\n",
                b"  encrypted_regex: ^(data|stringData)$\n  mac: "
                + sops_envelope(b"synthetic authenticated mac").encode("ascii")
                + b"\n",
                1,
            ),
            source.replace(
                b"        -----END AGE ENCRYPTED FILE-----\n", b"", 1
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(MODULE.SnapshotError):
                MODULE.parse_snapshots(valid_config(), mutation)

    def test_rejects_noncanonical_text_and_nonexact_secret_shape(self):
        mutations = (
            valid_ciphertext().replace(b"\n", b"\r\n"),
            b"\xef\xbb\xbf" + valid_ciphertext(),
            valid_ciphertext().rstrip(b"\n"),
            b"---\n" + valid_ciphertext(),
            valid_ciphertext().replace(b"stringData:\n", b"data:\n", 1),
            valid_ciphertext().replace(
                b"  token: ",
                b"  unexpected: "
                + sops_envelope(b"x").encode("ascii")
                + b"\n  token: ",
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(MODULE.SnapshotError):
                MODULE.parse_snapshots(valid_config(), mutation)


class SopsCiphertextSnapshotReaderTests(unittest.TestCase):
    """Bind each snapshot to one private regular path without link traversal."""

    def test_reads_one_absolute_private_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_private(Path(directory) / "snapshot.yaml", valid_config())
            self.assertEqual(
                MODULE.read_snapshot(str(path.resolve())), path.read_bytes()
            )

    def test_rejects_relative_directory_empty_and_oversize_inputs(self):
        with self.assertRaises(MODULE.SnapshotError):
            MODULE.read_snapshot("relative/snapshot.yaml")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(root.resolve()))
            empty = write_private(root / "empty.yaml", b"")
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(empty.resolve()))
            oversized = write_private(
                root / "oversized.yaml", b"x" * (MODULE.MAX_SNAPSHOT_BYTES + 1)
            )
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(oversized.resolve()))

    def test_rejects_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_private(root / "snapshot.yaml", valid_config())
            alias = root / "alias.yaml"
            try:
                os.link(source, alias)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(source.resolve()))

    def test_rejects_file_and_ancestor_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = write_private(root / "target.yaml", valid_config())
            link = root / "snapshot.yaml"
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(link.absolute()))

            real_directory = root / "real"
            real_directory.mkdir()
            write_private(real_directory / "nested.yaml", valid_config())
            linked_directory = root / "linked"
            linked_directory.symlink_to(real_directory, target_is_directory=True)
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(
                    str((linked_directory / "nested.yaml").absolute())
                )

    @unittest.skipUnless(os.name == "posix", "POSIX ownership and mode are required")
    def test_rejects_group_access_wrong_owner_and_nonregular_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_private(root / "snapshot.yaml", valid_config())
            path.chmod(0o640)
            with self.assertRaises(MODULE.SnapshotError):
                MODULE.read_snapshot(str(path.resolve()))
            path.chmod(0o600)
            with mock.patch.object(MODULE.os, "getuid", return_value=os.getuid() + 1):
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
            path = write_private(root / "snapshot.yaml", valid_config())
            replacement = write_private(root / "replacement.yaml", valid_config())
            retired = root / "retired.yaml"
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


class SopsCiphertextSnapshotCliTests(unittest.TestCase):
    """Keep the CLI isolated, environment-only, and content-neutral."""

    def run_cli(
        self,
        config: Path | None,
        ciphertext: Path | None,
        *arguments: str,
        isolated: bool = True,
    ):
        environment = os.environ.copy()
        for name, path in (
            (MODULE.SOPS_CONFIG_SNAPSHOT_ENV, config),
            (MODULE.SOPS_CIPHERTEXT_SNAPSHOT_ENV, ciphertext),
        ):
            if path is None:
                environment.pop(name, None)
            else:
                environment[name] = str(path.resolve())
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

    def test_cli_passes_only_in_isolated_mode_with_two_environment_paths(self):
        with tempfile.TemporaryDirectory(
            prefix="protected-values-must-not-print-"
        ) as directory:
            root = Path(directory)
            config = write_private(root / "private-config.yaml", valid_config())
            ciphertext = write_private(
                root / "private-ciphertext.yaml", valid_ciphertext()
            )
            result = self.run_cli(config, ciphertext)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout, "PASS SOPS ciphertext snapshot validation.\n"
            )
            self.assertEqual(result.stderr, "")
            self.assertNotIn(SYNTHETIC_RECIPIENT, result.stdout)
            self.assertNotIn("protected-values", result.stdout)

            nonisolated = self.run_cli(config, ciphertext, isolated=False)
            self.assertEqual(nonisolated.returncode, 1)
            self.assertEqual(nonisolated.stdout, "")
            self.assertEqual(
                nonisolated.stderr,
                "FAIL SOPS ciphertext snapshot validation.\n",
            )

    def test_cli_rejects_arguments_and_missing_environment_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = write_private(root / "config.yaml", valid_config())
            ciphertext = write_private(
                root / "ciphertext.yaml", valid_ciphertext()
            )
            for arguments in (("--help",), (str(ciphertext),), ("--file",)):
                with self.subTest(arguments=arguments):
                    result = self.run_cli(config, ciphertext, *arguments)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr,
                        "FAIL SOPS ciphertext snapshot validation.\n",
                    )
            for missing_config, missing_ciphertext in (
                (None, ciphertext),
                (config, None),
                (None, None),
            ):
                result = self.run_cli(missing_config, missing_ciphertext)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    "FAIL SOPS ciphertext snapshot validation.\n",
                )

    def test_cli_failure_never_echoes_path_recipient_or_content(self):
        with tempfile.TemporaryDirectory(prefix="never-echo-this-") as directory:
            root = Path(directory)
            config = write_private(root / "private-config.yaml", valid_config())
            ciphertext = write_private(
                root / "private-ciphertext.yaml", b"protected-content-marker\n"
            )
            result = self.run_cli(config, ciphertext)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr, "FAIL SOPS ciphertext snapshot validation.\n"
            )
            combined = result.stdout + result.stderr
            self.assertNotIn("never-echo-this", combined)
            self.assertNotIn("protected-content-marker", combined)
            self.assertNotIn(SYNTHETIC_RECIPIENT, combined)

    def test_main_collapses_unexpected_exceptions_to_generic_failure(self):
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
            stderr.getvalue(), "FAIL SOPS ciphertext snapshot validation.\n"
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
                "importlib",
                "os",
                "re",
                "stat",
                "sys",
                "pathlib",
                "types",
            },
        )
        for forbidden in (
            "subprocess",
            "socket",
            "http.client",
            "urlopen",
            "requests",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            'SOPS_CONFIG_SNAPSHOT_ENV = "SOPS_CONFIG_SNAPSHOT_FILE"',
            'SOPS_CIPHERTEXT_SNAPSHOT_ENV = "SOPS_CIPHERTEXT_SNAPSHOT_FILE"',
            "sys.flags.isolated != 1",
            "spec_from_file_location",
            "O_NOFOLLOW",
            "st_nlink != 1",
            "follow_symlinks=False",
            'print("FAIL SOPS ciphertext snapshot validation."',
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
