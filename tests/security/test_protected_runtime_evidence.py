"""Prove that the fresh protected-host review attestation fails closed."""

import ast
import contextlib
import hashlib
import importlib.util
import io
import os
import stat
import tempfile
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_protected_runtime_evidence.py"
EXAMPLE = ROOT / "bootstrap" / "pi" / "protected-legacy-runtime-evidence.example"
GITIGNORE = ROOT / ".gitignore"
ADR = ROOT / "docs" / "adr" / "0013-protected-legacy-archive.md"
RUNBOOK = ROOT / "docs" / "runbooks" / "protected-legacy-archive.md"
SCRIPTS_README = ROOT / "scripts" / "README.md"
SPEC = importlib.util.spec_from_file_location(
    "validate_protected_runtime_evidence", str(SCRIPT)
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

NOW = 1786250000
BOOT_SHA256 = "a" * 64


def evidence_bytes(**overrides):
    """Build a canonical synthetic summary without private host identities."""

    values = {
        "RUNTIME_EVIDENCE_SCHEMA": MODULE.EVIDENCE_SCHEMA,
        "BOOT_ID_SHA256": BOOT_SHA256,
        "CREATED_UNIX": str(NOW),
        MODULE.PRESENCE_FIELD: "yes",
    }
    values.update({field: "PASS" for field in MODULE.STATUS_FIELDS})
    values.update(overrides)
    return (
        "\n".join("{}={}".format(field, values[field]) for field in MODULE.REQUIRED_FIELDS)
        + "\n"
    ).encode("ascii")


def metadata(mode, *, uid=1000, gid=1000, nlink=1, mtime=NOW):
    """Create only the stat fields consumed by the metadata policy."""

    return SimpleNamespace(
        st_mode=mode,
        st_uid=uid,
        st_gid=gid,
        st_nlink=nlink,
        st_mtime=mtime,
    )


class ProtectedRuntimeEvidenceTests(unittest.TestCase):
    """Exercise schema, freshness, boot, file, and content bindings."""

    def test_accepts_only_the_complete_canonical_pass_summary(self):
        """Every activation and runtime exposure class has an explicit PASS."""

        parsed, errors = MODULE.parse_evidence_bytes(
            evidence_bytes(), current_boot_sha256=BOOT_SHA256, now_epoch=NOW
        )
        self.assertEqual(errors, [])
        self.assertEqual(parsed.boot_id_sha256, BOOT_SHA256)
        self.assertEqual(parsed.created_unix, NOW)
        self.assertTrue(parsed.archives_present)
        self.assertEqual(
            set(MODULE.STATUS_FIELDS),
            {
                "ARCHIVE_INVENTORY_STATUS",
                "SYSTEM_MANAGER_UNITS_STATUS",
                "USER_MANAGER_UNITS_STATUS",
                "CONTAINERS_STATUS",
                "PACKAGE_ACTIVATION_STATUS",
                "SCHEDULERS_AUTOSTART_STATUS",
                "PROCESSES_STATUS",
                "CGROUPS_STATUS",
                "OPEN_FILES_STATUS",
                "LISTENERS_STATUS",
                "PRODUCT_EXECUTION_STATUS",
            },
        )

    def test_archive_presence_decision_is_explicit_and_parseable(self):
        """The attestation records the reviewed yes/no decision it must bind."""

        parsed, errors = MODULE.parse_evidence_bytes(
            evidence_bytes(LEGACY_ARCHIVES_PRESENT="no"),
            current_boot_sha256=BOOT_SHA256,
            now_epoch=NOW,
        )
        self.assertEqual(errors, [])
        self.assertFalse(parsed.archives_present)

        parsed, errors = MODULE.parse_evidence_bytes(
            evidence_bytes(LEGACY_ARCHIVES_PRESENT="unknown"),
            current_boot_sha256=BOOT_SHA256,
            now_epoch=NOW,
        )
        self.assertIsNone(parsed)
        self.assertTrue(any("presence decision" in error for error in errors), errors)

    def test_each_non_pass_status_fails_closed(self):
        """FAIL, UNKNOWN, stale template text, and omissions never become truthy."""

        for field in MODULE.STATUS_FIELDS:
            for value in ("FAIL", "UNKNOWN", "REPLACE_ME"):
                with self.subTest(field=field, value=value):
                    parsed, errors = MODULE.parse_evidence_bytes(
                        evidence_bytes(**{field: value}),
                        current_boot_sha256=BOOT_SHA256,
                        now_epoch=NOW,
                    )
                    self.assertIsNone(parsed)
                    self.assertTrue(any("non-PASS" in error for error in errors), errors)

    def test_boot_and_short_freshness_are_mandatory(self):
        """An old summary, another boot, or a future timestamp cannot be rebound."""

        cases = (
            (
                evidence_bytes(),
                "b" * 64,
                NOW,
                "different boot",
            ),
            (
                evidence_bytes(CREATED_UNIX=str(NOW - MODULE.MAX_EVIDENCE_AGE_SECONDS - 1)),
                BOOT_SHA256,
                NOW,
                "stale",
            ),
            (
                evidence_bytes(CREATED_UNIX=str(NOW + 1)),
                BOOT_SHA256,
                NOW,
                "future",
            ),
        )
        for raw, boot_sha256, now_epoch, fragment in cases:
            with self.subTest(fragment=fragment):
                parsed, errors = MODULE.parse_evidence_bytes(
                    raw,
                    current_boot_sha256=boot_sha256,
                    now_epoch=now_epoch,
                )
                self.assertIsNone(parsed)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_schema_is_bounded_ascii_lf_and_exactly_ordered(self):
        """Alternate encodings, hidden fields, and reordered claims are rejected."""

        valid = evidence_bytes()
        lines = valid.decode("ascii").splitlines()
        reordered = "\n".join([lines[1], lines[0]] + lines[2:]).encode("ascii") + b"\n"
        cases = (
            (valid.rstrip(b"\n"), "LF-terminated"),
            (valid.replace(b"\n", b"\r\n"), "LF-terminated"),
            (valid + b"EXTRA_STATUS=PASS\n", "extra fields"),
            (reordered, "canonical order"),
            (b"x" * (MODULE.MAX_EVIDENCE_BYTES + 1), "size limit"),
        )
        for raw, fragment in cases:
            with self.subTest(fragment=fragment):
                parsed, errors = MODULE.parse_evidence_bytes(
                    raw, current_boot_sha256=BOOT_SHA256, now_epoch=NOW
                )
                self.assertIsNone(parsed)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_raw_boot_identifier_is_normalized_and_never_returned(self):
        """Only a SHA-256 of the valid Linux boot UUID reaches the summary."""

        # Build the synthetic UUID at runtime so even fixture-shaped machine
        # identifiers remain absent from the public Git index.
        boot_id = "-".join(("12345678", "1234", "4abc", "8def", "1234567890ab"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot-id"
            path.write_text(boot_id + "\n", encoding="ascii")
            self.assertEqual(
                MODULE.current_boot_id_sha256(path),
                hashlib.sha256(boot_id.encode("ascii")).hexdigest(),
            )
            path.write_text("not-a-boot-identifier\n", encoding="ascii")
            self.assertIsNone(MODULE.current_boot_id_sha256(path))

    def test_metadata_requires_exact_mode_owner_link_and_fresh_write(self):
        """A copied, shared, stale, or differently owned summary is invalid."""

        contract = metadata(stat.S_IFREG | 0o600)
        self.assertEqual(
            MODULE._metadata_errors(
                contract, metadata(stat.S_IFREG | 0o600), now_epoch=NOW
            ),
            [],
        )
        cases = (
            (metadata(stat.S_IFREG | 0o640), "0600"),
            (metadata(stat.S_IFREG | 0o600, nlink=2), "hard link"),
            (metadata(stat.S_IFREG | 0o600, uid=2000), "owner"),
            (
                metadata(
                    stat.S_IFREG | 0o600,
                    mtime=NOW - MODULE.MAX_EVIDENCE_AGE_SECONDS - 1,
                ),
                "stale",
            ),
            (metadata(stat.S_IFREG | 0o600, mtime=NOW + 1), "future"),
        )
        for evidence, fragment in cases:
            with self.subTest(fragment=fragment):
                errors = MODULE._metadata_errors(contract, evidence, now_epoch=NOW)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_fixed_adjacent_file_and_raw_content_hash_are_enforced(self):
        """The contract cannot point at another summary or accept changed bytes."""

        contract_path = Path("/private/review/protected-services.env.local")
        self.assertEqual(
            MODULE.evidence_path_for_contract(contract_path),
            Path("/private/review") / MODULE.EVIDENCE_FILENAME,
        )
        raw = evidence_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        contract_metadata = metadata(stat.S_IFREG | 0o600)
        directory_metadata = metadata(stat.S_IFDIR | 0o700)
        evidence_metadata = metadata(stat.S_IFREG | 0o600)

        def lstat_for(path):
            return contract_metadata if path == contract_path else directory_metadata

        with mock.patch.object(
            Path,
            "lstat",
            autospec=True,
            side_effect=lstat_for,
        ), mock.patch.object(
            MODULE, "_read_evidence_file", return_value=(raw, evidence_metadata, [])
        ) as read_evidence:
            loaded, errors = MODULE.validate_runtime_evidence(
                contract_path,
                digest,
                expected_archives_present=True,
                now_epoch=NOW,
                boot_id_probe=lambda: BOOT_SHA256,
            )
            self.assertEqual(errors, [])
            self.assertEqual(loaded.sha256, digest)

            read_evidence.return_value = (
                raw,
                metadata(stat.S_IFREG | 0o600, mtime=NOW - 5),
                [],
            )
            loaded, errors = MODULE.validate_runtime_evidence(
                contract_path,
                digest,
                expected_archives_present=True,
                now_epoch=NOW,
                boot_id_probe=lambda: BOOT_SHA256,
            )
            self.assertIsNone(loaded)
            self.assertTrue(any("predates" in error for error in errors), errors)

            read_evidence.return_value = (raw, evidence_metadata, [])
            loaded, errors = MODULE.validate_runtime_evidence(
                contract_path,
                "f" * 64,
                expected_archives_present=True,
                now_epoch=NOW,
                boot_id_probe=lambda: BOOT_SHA256,
            )
            self.assertIsNone(loaded)
            self.assertEqual(errors, ["runtime evidence binding changed"])

            loaded, errors = MODULE.validate_runtime_evidence(
                contract_path,
                digest,
                expected_archives_present=False,
                now_epoch=NOW,
                boot_id_probe=lambda: BOOT_SHA256,
            )
            self.assertIsNone(loaded)
            self.assertTrue(any("does not match" in error for error in errors), errors)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "nonblocking no-follow path walking is POSIX-only",
    )
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_secure_read_rejects_regular_file_to_fifo_substitution(self):
        """A lookup race cannot turn the bounded read into a blocking FIFO open."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / MODULE.EVIDENCE_FILENAME
            path.write_bytes(evidence_bytes())
            path.chmod(0o600)
            real_secure_open = MODULE._open_absolute_file_no_follow
            substituted = []

            def substitute_before_open(open_path, flags):
                if not substituted:
                    self.assertTrue(flags & os.O_NONBLOCK)
                    path.unlink()
                    os.mkfifo(path, 0o600)
                    substituted.append(True)
                return real_secure_open(open_path, flags)

            with mock.patch.object(
                MODULE,
                "_open_absolute_file_no_follow",
                side_effect=substitute_before_open,
            ):
                raw, opened, errors = MODULE._read_evidence_file(path)

            self.assertIsNone(raw)
            self.assertIsNone(opened)
            self.assertTrue(any("changed while opening" in error for error in errors))
            self.assertNotIn(str(path), "\n".join(errors))

    @unittest.skipUnless(os.name == "posix", "no-follow path walking is POSIX-only")
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_secure_read_rejects_parent_rename_to_same_inode_symlink_race(self):
        """The retained parent cannot be renamed and reached through a new symlink."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            original_parent = Path(directory) / "evidence-parent"
            moved_parent = Path(directory) / "moved-parent"
            original_parent.mkdir()
            path = original_parent / MODULE.EVIDENCE_FILENAME
            path.write_bytes(evidence_bytes())
            path.chmod(0o600)
            real_read = MODULE.os.read
            substituted = []

            def swap_parent_after_read(descriptor, size):
                data = real_read(descriptor, size)
                if data and not substituted:
                    original_parent.rename(moved_parent)
                    original_parent.symlink_to(moved_parent, target_is_directory=True)
                    substituted.append(True)
                return data

            with mock.patch.object(MODULE.os, "read", side_effect=swap_parent_after_read):
                raw, opened, errors = MODULE._read_evidence_file(path)

            self.assertIsNone(raw)
            self.assertIsNone(opened)
            self.assertTrue(any("changed while reading" in error for error in errors))
            self.assertNotIn(str(path), "\n".join(errors))

    @unittest.skipUnless(os.name == "posix", "no-follow path walking is POSIX-only")
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_secure_read_rejects_ancestor_rename_to_same_inode_symlink_race(self):
        """A swapped ancestor is caught even when the retained parent stays stable."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            original_ancestor = Path(directory) / "evidence-ancestor"
            moved_ancestor = Path(directory) / "moved-ancestor"
            parent = original_ancestor / "parent"
            parent.mkdir(parents=True)
            path = parent / MODULE.EVIDENCE_FILENAME
            path.write_bytes(evidence_bytes())
            path.chmod(0o600)
            real_read = MODULE.os.read
            substituted = []

            def swap_ancestor_after_read(descriptor, size):
                data = real_read(descriptor, size)
                if data and not substituted:
                    original_ancestor.rename(moved_ancestor)
                    original_ancestor.symlink_to(
                        moved_ancestor,
                        target_is_directory=True,
                    )
                    substituted.append(True)
                return data

            with mock.patch.object(MODULE.os, "read", side_effect=swap_ancestor_after_read):
                raw, opened, errors = MODULE._read_evidence_file(path)

            self.assertIsNone(raw)
            self.assertIsNone(opened)
            self.assertTrue(any("path changed" in error for error in errors))
            self.assertNotIn(str(path), "\n".join(errors))

    def test_cli_emits_only_the_contract_assignment_on_stdout(self):
        """Generation is contract-bound and stdout remains safely appendable."""

        digest = "d" * 64
        loaded = MODULE.LoadedRuntimeEvidence(
            MODULE.RuntimeEvidence(BOOT_SHA256, NOW, True), digest
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE, "adjacent_contract_presence", return_value=(True, [])
        ) as presence_probe, mock.patch.object(
            MODULE, "validate_runtime_evidence", return_value=(loaded, [])
        ) as validate, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = MODULE.main(["/private/contract", "--emit-sha256"])
        self.assertEqual(result, 0)
        self.assertEqual(
            presence_probe.call_args_list,
            [mock.call(Path("/private/contract"))] * 2,
        )
        validate.assert_called_once_with(
            Path("/private/contract"),
            None,
            expected_archives_present=True,
        )
        self.assertEqual(
            stdout.getvalue(),
            "{}={}\n".format(MODULE.EVIDENCE_HASH_KEY, digest),
        )
        self.assertIn("PASS", stderr.getvalue())
        self.assertIn("DIGEST EMISSION ONLY, NOT AUTHORIZATION", stderr.getvalue())
        self.assertNotIn("/private/contract", stdout.getvalue() + stderr.getvalue())

    def test_cli_rejects_contract_presence_drift_before_emitting(self):
        """The contract decision must remain stable through evidence validation."""

        loaded = MODULE.LoadedRuntimeEvidence(
            MODULE.RuntimeEvidence(BOOT_SHA256, NOW, True), "d" * 64
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE,
            "adjacent_contract_presence",
            side_effect=((True, []), (False, [])),
        ), mock.patch.object(
            MODULE, "validate_runtime_evidence", return_value=(loaded, [])
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = MODULE.main(["/private/contract", "--emit-sha256"])

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("changed during validation", stderr.getvalue())

    def test_cli_expected_digest_validation_is_contract_bound(self):
        """The non-emitting validation path uses the adjacent decision too."""

        digest = "d" * 64
        loaded = MODULE.LoadedRuntimeEvidence(
            MODULE.RuntimeEvidence(BOOT_SHA256, NOW, False), digest
        )
        stdout = io.StringIO()
        with mock.patch.object(
            MODULE, "adjacent_contract_presence", return_value=(False, [])
        ), mock.patch.object(
            MODULE, "validate_runtime_evidence", return_value=(loaded, [])
        ) as validate, contextlib.redirect_stdout(stdout):
            result = MODULE.main(
                ["/private/contract", "--expected-sha256", digest]
            )

        self.assertEqual(result, 0)
        validate.assert_called_once_with(
            Path("/private/contract"),
            digest,
            expected_archives_present=False,
        )
        self.assertIn("matches the adjacent contract", stdout.getvalue())

    def test_cli_fails_before_validation_when_contract_presence_is_invalid(self):
        """A supplied contract that cannot bind presence never yields a digest."""

        private_path = "/private/operator/contract"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE,
            "adjacent_contract_presence",
            return_value=(None, ["protected-host contract presence is invalid"]),
        ), mock.patch.object(MODULE, "validate_runtime_evidence") as validate, contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(stderr):
            result = MODULE.main([private_path, "--emit-sha256"])

        self.assertEqual(result, 1)
        validate.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(private_path, stderr.getvalue())

    def test_adjacent_contract_presence_uses_the_secure_host_parser(self):
        """The emitter derives presence from the contract instead of a CLI claim."""

        contract_path = Path("/private/operator/contract")
        load_contract = mock.Mock(
            return_value=(SimpleNamespace(legacy_archives_present=False), [])
        )
        presence, errors = MODULE.adjacent_contract_presence(
            contract_path,
            loader=lambda: SimpleNamespace(load_contract=load_contract),
        )

        self.assertFalse(presence)
        self.assertEqual(errors, [])
        load_contract.assert_called_once_with(
            contract_path,
            allow_missing_bindings=True,
            allow_unreviewed=True,
        )

        private_value = "/private/operator/identity"
        presence, errors = MODULE.adjacent_contract_presence(
            contract_path,
            loader=lambda: SimpleNamespace(
                load_contract=mock.Mock(return_value=(None, [private_value]))
            ),
        )
        self.assertIsNone(presence)
        self.assertNotIn(private_value, "\n".join(errors))

    def test_fixed_host_contract_loader_has_the_matching_api(self):
        """The reverse sibling loader pins the same schema and API constants."""

        host = MODULE._load_host_contract_validator()
        self.assertIsNotNone(host)
        self.assertEqual(host.RUNTIME_EVIDENCE_HASH_KEY, MODULE.EVIDENCE_HASH_KEY)
        self.assertEqual(host.RUNTIME_EVIDENCE_SCHEMA, MODULE.EVIDENCE_SCHEMA)
        self.assertEqual(
            host.RUNTIME_EVIDENCE_PRESENCE_FIELD,
            MODULE.PRESENCE_FIELD,
        )
        self.assertEqual(
            host.RUNTIME_EVIDENCE_VALIDATOR_API_VERSION,
            MODULE.EVIDENCE_VALIDATOR_API_VERSION,
        )

    def test_tracked_template_is_inert_ignored_and_identity_free(self):
        """The public example cannot pass before a fresh local review."""

        template = EXAMPLE.read_text(encoding="utf-8")
        ignored = GITIGNORE.read_text(encoding="utf-8")
        self.assertEqual(
            template.splitlines()[0],
            "RUNTIME_EVIDENCE_SCHEMA=" + MODULE.EVIDENCE_SCHEMA,
        )
        self.assertIn("REPLACE_WITH_CURRENT_BOOT_ID_SHA256", template)
        self.assertIn("REPLACE_WITH_CURRENT_UNIX_EPOCH", template)
        self.assertIn(
            MODULE.PRESENCE_FIELD
            + "=REPLACE_WITH_YES_OR_NO_AFTER_PRIVATE_REVIEW",
            template,
        )
        self.assertIn(
            "bootstrap/pi/protected-legacy-runtime-evidence.local", ignored
        )
        for field in MODULE.STATUS_FIELDS:
            self.assertIn(
                field + "=REPLACE_WITH_PASS_AFTER_PRIVATE_REVIEW", template
            )
        for private_shape in (".service", "/dev/", "/srv/", "127.0.0.1", "::1"):
            with self.subTest(private_shape=private_shape):
                self.assertNotIn(private_shape, template)

    def test_validator_has_no_command_or_product_execution_surface(self):
        """Validation cannot accidentally launch discovery or archived software."""

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
        self.assertNotIn("subprocess", imported_roots)
        for forbidden in ("system(", "popen(", "spawn", "execv", "shell=True"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source.lower())
        for required in (
            "O_NOFOLLOW",
            "O_NONBLOCK",
            "_open_absolute_file_no_follow",
            "dir_fd",
            "opened_before",
            "opened_after",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)

    def test_adr_and_runbook_define_the_fresh_fail_closed_gate(self):
        """Operators are told that PASS summaries never replace private checks."""

        combined = " ".join(
            (
                ADR.read_text(encoding="utf-8")
                + "\n"
                + RUNBOOK.read_text(encoding="utf-8")
            ).split()
        )
        for fragment in (
            "PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256",
            "protected-legacy-runtime-evidence.local",
            "600 seconds",
            "invalid after every reboot",
            "The validator runs no discovery command and no product binary",
            "copying the public example is not discovery",
            "boot-bound, bounded operator attestation",
            "does not mean that the validator observed",
            "equivalent, namespace-complete live machine probe",
            "refuses to emit a digest",
            "derivation only",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, combined)

        scripts_readme = SCRIPTS_README.read_text(encoding="utf-8")
        self.assertIn(
            "fresh presence-bound protected-host review attestation",
            scripts_readme,
        )
        self.assertNotIn("absence attestation", scripts_readme.lower())


if __name__ == "__main__":
    unittest.main()
