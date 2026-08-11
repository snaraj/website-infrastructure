"""Protect the offline host-level Cloudflare connector installation contract."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from .support import load_script


ROOT = Path(__file__).resolve().parents[2]
CLOUDFLARED_DIR = ROOT / "bootstrap" / "pi" / "cloudflared"
INSTALLER = CLOUDFLARED_DIR / "install-host-binary.sh"
TOKEN_INSTALLER = CLOUDFLARED_DIR / "install-host-token.sh"
TOKEN_CANARY = CLOUDFLARED_DIR / "verify-host-token-redaction.sh"
TOKEN_VALIDATOR = ROOT / "scripts" / "validate_cloudflared_tunnel_token.py"
TOKEN_VALIDATOR_MODULE = load_script("validate_cloudflared_tunnel_token.py")
UNIT = CLOUDFLARED_DIR / "pi-admin.service"
README = CLOUDFLARED_DIR / "README.md"
ROTATION = ROOT / "docs" / "runbooks" / "tunnel-token-rotation.md"
BASH = "/bin/bash" if Path("/bin/bash").is_file() else shutil.which("bash")


class CloudflaredHostBinaryInstallerTests(unittest.TestCase):
    """Keep root apply bound to one privately copied and verified binary."""

    @classmethod
    def setUpClass(cls):
        cls.installer = INSTALLER.read_text(encoding="utf-8")

    def test_mutable_staging_path_is_never_executed(self):
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", self.installer)
        self.assertIn(
            'install -o root -g root -m 0755 -- "${staged_binary}" "${candidate_binary}"',
            self.installer,
        )
        self.assertIn('verify_binary "${candidate_binary}"', self.installer)
        self.assertIn('unshare --net -- setpriv', self.installer)
        self.assertIn('timeout --signal=KILL 10s', self.installer)
        self.assertIn('"${isolated_runner[@]}" "${binary}" --version', self.installer)
        self.assertIn('"${isolated_runner[@]}" "${binary}" tunnel run --help', self.installer)
        self.assertGreaterEqual(self.installer.count('digest_after="$(sha256_file'), 2)
        self.assertIn("--token-file", self.installer)
        for line in self.installer.splitlines():
            self.assertFalse(
                line.lstrip().startswith('"${staged_binary}"'),
                "the caller-controlled staging path must never be executed",
            )

    @unittest.skipUnless(BASH, "Bash is required")
    def test_all_binary_installer_modes_are_code_blocked_before_staging_access(self):
        blocker = (
            "BLOCKED cloudflared host-binary validation and installation require "
            "the trusted reviewed-blob launcher; no staged binary was executed "
            "and no host change was attempted.\n"
        )
        self.assertTrue(self.installer.startswith("#!/bin/bash\n"))
        self.assertIn("readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no", self.installer)
        self.assertLess(self.installer.index("BLOCKED cloudflared host-binary"), self.installer.index("PATH="))
        for mode in ("--check", "--apply"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [BASH, str(INSTALLER), mode],
                    cwd=ROOT,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, blocker)

    def test_apply_uses_private_root_candidate_lock_and_atomic_commit(self):
        for fragment in (
            "/run/website-infrastructure",
            "umask 077",
            'assert_safe_root_directory /run',
            'ensure_private_root_directory "${lock_directory}"',
            'ensure_private_root_file "${lock_path}"',
            'exec 9<>"${lock_path}"',
            'flock -n 9',
            'assert_safe_root_directory "${destination_directory}"',
            '${destination_directory}/.cloudflared-install.XXXXXXXX',
            'destination_is_unchanged || die',
            'ln -- "${candidate_binary}" "${destination}"',
            'mv -fT -- "${candidate_binary}" "${destination}"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.installer)
        lock_call = self.installer.rindex('flock -n 9')
        destination_check_call = self.installer.rindex(
            "\nvalidate_existing_destination\n"
        )
        candidate_call = self.installer.rindex("\nprepare_candidate\n")
        drift_check_call = self.installer.rindex(
            "\ndestination_is_unchanged || die"
        )
        self.assertLess(lock_call, destination_check_call)
        self.assertLess(destination_check_call, candidate_call)
        self.assertLess(candidate_call, drift_check_call)

    def test_root_process_parses_pins_as_data_instead_of_sourcing_repository_code(self):
        self.assertIn(
            'CLOUDFLARED_HOST_VERSION="$(load_version_value CLOUDFLARED_HOST_VERSION)"',
            self.installer,
        )
        self.assertIn(
            'CLOUDFLARED_HOST_ARM64_SHA256="$(load_version_value CLOUDFLARED_HOST_ARM64_SHA256)"',
            self.installer,
        )
        self.assertNotIn('source "${repo_root}/versions.env"', self.installer)

    def test_failed_or_interrupted_commit_has_drift_safe_rollback(self):
        for fragment in (
            "trap on_exit EXIT",
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
            'rollback_installation',
            'installed destination drifted; refusing rollback overwrite',
            '[[ "$(destination_identity)" != "${candidate_identity}" ]]',
            'cp -a -- "${backup_directory}/cloudflared.pre" "${rollback_candidate}"',
            'destination_metadata "${rollback_candidate}"',
            'mv -fT -- "${rollback_candidate}" "${destination}"',
            'PASS checked previous cloudflared binary state restored',
            'rollback incomplete;',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.installer)
        self.assertLess(
            self.installer.rindex('candidate_identity="$(stat'),
            self.installer.rindex("\nif [[ \"${previous_state}\" == absent ]]"),
        )

    def test_installer_stays_binary_only_and_offline(self):
        for forbidden in (
            "curl ",
            "wget ",
            "systemctl enable",
            "systemctl start",
            "useradd ",
            "ufw ",
            "wg ",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.installer)
        self.assertIn(
            "No unit, user, token, or firewall changed.",
            self.installer,
        )

    def test_apply_requires_recovery_and_two_proven_sessions(self):
        self.assertIn('PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes', self.installer)
        self.assertIn('TWO_WORKING_SESSIONS_PROVEN:-}" == yes', self.installer)

    def test_hardlinks_capabilities_xattrs_and_extended_acls_are_rejected(self):
        for fragment in (
            'stat -c %h',
            'getcap -n',
            'getfattr -d -m-',
            'getfacl -cp',
            'extended file ACL entries are unsupported',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.installer)


class PiAdminUnitTests(unittest.TestCase):
    """Keep the unit least-privileged without embedding private network state."""

    @classmethod
    def setUpClass(cls):
        cls.unit = UNIT.read_text(encoding="utf-8")

    def test_token_is_loaded_as_a_systemd_credential(self):
        self.assertIn(
            "LoadCredential=tunnel-token:/etc/cloudflared/pi-admin.token", self.unit
        )
        self.assertIn(
            "--token-file ${CREDENTIALS_DIRECTORY}/tunnel-token", self.unit
        )
        self.assertNotIn("--token ", self.unit)

    def test_static_unit_hardening_remains_explicit(self):
        for directive in (
            "AmbientCapabilities=",
            "CapabilityBoundingSet=",
            "KeyringMode=private",
            "NoNewPrivileges=yes",
            "ProtectProc=invisible",
            "ProtectSystem=strict",
            "RestrictAddressFamilies=AF_INET AF_INET6",
            "RestrictNamespaces=yes",
            "SystemCallArchitectures=native",
            "SystemCallFilter=@system-service",
            "UMask=0077",
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, self.unit)

    def test_unit_does_not_invent_private_network_bindings(self):
        for forbidden in (
            "BindToDevice=",
            "IPAddressAllow=",
            "IPAddressDeny=",
            "wg-quick@",
            "ufw.service",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.unit)


class PiAdminTokenCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = TOKEN_INSTALLER.read_text(encoding="utf-8")
        cls.canary = TOKEN_CANARY.read_text(encoding="utf-8")

    def test_latent_token_check_uses_the_exact_reviewed_validator_without_mutation(self):
        for fragment in (
            "CLOUDFLARED_TOKEN_WORKSPACE",
            "EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256",
            "EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256",
            "validate_cloudflared_tunnel_token.py",
            "EXPECTED_REPOSITORY_HEAD",
            "EXPECTED_REPOSITORY_OWNER_UID",
            "refs/heads/main",
            '"${git_binary}" --no-replace-objects',
            "GIT_CONFIG_NOSYSTEM=1",
            '"${git_dir}/info/grafts"',
            '"${git_dir}/objects/info/alternates"',
            "refs/replace",
            "hash-object --no-filters",
            "cat-file blob",
            "self_blob=",
            "validator_worktree=",
            'cmp -s -- "${validator_worktree}" "${token_validator}"',
            'env -i PATH=/usr/bin:/bin',
            '"${python3_binary}" -I -B "${token_validator}"',
            "no host state changed",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.installer)

    def test_mutable_checkout_token_paths_are_explicitly_closed_before_secret_access(self):
        release_guard = "BLOCKED pi-admin token validation and installation require the trusted reviewed-blob launcher"
        self.assertIn("readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no", self.installer)
        self.assertLess(
            self.installer.index(release_guard),
            self.installer.index("PATH=/usr/sbin:/usr/bin:/sbin:/bin"),
        )
        self.assertLess(
            self.installer.index(release_guard),
            self.installer.index("CLOUDFLARED_TUNNEL_TOKEN_FILE"),
        )
        guard = '[[ "${mode}" == --check ]] || die'
        self.assertIn(guard, self.installer)
        self.assertLess(
            self.installer.index(guard),
            self.installer.index("CLOUDFLARED_TUNNEL_TOKEN_FILE"),
        )
        self.assertIn("root-owned immutable launcher", self.installer)
        for forbidden in (
            "destination=/etc/cloudflared",
            "install -o root",
            "flock -n",
            "mv -fT",
            'ln -- "${candidate}"',
            "systemctl start",
            "systemctl restart",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.installer)

    @unittest.skipUnless(BASH, "Bash is required")
    def test_all_bearer_reading_modes_fail_before_credentials_are_required(self):
        expected_installer = (
            "BLOCKED pi-admin token validation and installation require the trusted "
            "reviewed-blob launcher; no token was read and no host change was attempted.\n"
        )
        expected_canary = (
            "BLOCKED pi-admin runtime token verification requires the trusted "
            "reviewed-blob launcher; no token or runtime metadata was read.\n"
        )
        for script, arguments, expected in (
            (TOKEN_INSTALLER, ["--check"], expected_installer),
            (TOKEN_INSTALLER, ["--apply"], expected_installer),
            (TOKEN_CANARY, [], expected_canary),
        ):
            with self.subTest(script=script.name, arguments=arguments):
                result = subprocess.run(
                    [BASH, str(script), *arguments],
                    cwd=ROOT,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, expected)

    def test_secret_readers_reject_runtime_injection_and_disable_coredumps(self):
        for text in (self.installer, self.canary):
            with self.subTest(source=text[:40]):
                self.assertTrue(text.startswith("#!/bin/bash\n"))
                self.assertIn("readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no", text)
                for fragment in (
                    "builtin set +o history",
                    "builtin declare -F",
                    "builtin compgen -e",
                    "BASH_ENV|ENV|BASHOPTS|SHELLOPTS",
                    "BASH_XTRACEFD|PS4|POSIXLY_CORRECT",
                    "BASH_FUNC_*|LD_*",
                    "builtin ulimit -S -c 0",
                    "builtin ulimit -H -c 0",
                    '[[ "${BASH}" == /bin/bash ]]',
                ):
                    with self.subTest(fragment=fragment):
                        self.assertIn(fragment, text)
        for fragment in (
            "DBUS_*|SYSTEMD_*|SYSTEMCTL_*|JOURNAL_*",
            "trusted_systemctl",
            "trusted_journalctl",
            "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.canary)

    def test_canary_binds_itself_and_pins_to_reviewed_main_before_token_read(self):
        for fragment in (
            "EXPECTED_REPOSITORY_HEAD",
            "EXPECTED_REPOSITORY_OWNER_UID",
            '"${git_binary}" --no-replace-objects',
            "GIT_CONFIG_GLOBAL=/dev/null",
            "refs/heads/main",
            "refs/replace",
            "cat-file blob",
            "hash-object --no-filters",
            "self_blob=",
            'cmp -s -- "${self_worktree}" "${self_blob}"',
            'cmp -s -- "${versions_worktree}" "${versions_file}"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.canary)
        self.assertLess(
            self.canary.index('cmp -s -- "${self_worktree}" "${self_blob}"'),
            self.canary.index('exec {token_fd}<"${token_file}"'),
        )

    def test_runtime_canary_never_places_token_in_command_arguments(self):
        for fragment in (
            'grep -aFq -f "${pattern_descriptor}"',
            '"/proc/${pid}/cmdline"',
            '"/proc/${pid}/environ"',
            "InvocationID",
            '[[ "$(runtime_identity)" == "${identity_before}" ]]',
            "/usr/local/bin/cloudflared",
            "credential_directory=/run/credentials/pi-admin.service",
            "expected_credential_file=${credential_directory}/tunnel-token",
            'credential_file="$(runtime_credential_file "${pid}")"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.canary)
        self.assertNotIn("/usr/local/sbin/cloudflared", self.canary)
        self.assertNotIn("$(cat", self.canary)

    def test_runtime_canary_binds_binary_and_systemd_credential_custody(self):
        for fragment in (
            "CLOUDFLARED_HOST_ARM64_SHA256",
            'sha256sum -- "/proc/${pid}/exe"',
            "ulimit -H -c 0",
            "runtime_process_owner",
            "assert_runtime_credential_custody",
            "findmnt -rn -T",
            '"${mount_target}" == "${credential_directory}"',
            '"${mount_type}" == ramfs || "${mount_type}" == tmpfs',
            "ro nosuid nodev noexec",
            "swapon --show=NAME --noheadings --raw",
            ':400:1',
            ':600:1',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.canary)

    def test_runtime_canary_scans_complete_records_and_closes_credential_fd(self):
        for fragment in (
            "--all --output=export --unit=pi-admin.service",
            "COREDUMP_UNIT=pi-admin.service",
            "compare_active_credential",
            'exec {descriptor}<&-',
            'rm -f -- "${pattern_file}"',
            'exec {pattern_fd}<&-',
            '[[ ! -e "${pattern_descriptor}" ]]',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.canary)
        self.assertNotIn("--output=cat", self.canary)
        first_compare = self.canary.index(
            'compare_active_credential "${credential_state}" || fail'
        )
        first_scan = self.canary.index(
            'assert_pattern_absent "/proc/${pid}/cmdline"'
        )
        self.assertLess(first_compare, first_scan)
        self.assertGreaterEqual(self.canary.count('exec {descriptor}<&-'), 3)
        self.assertLess(
            self.canary.index('rm -f -- "${pattern_file}"'), first_scan
        )
        self.assertGreater(
            self.canary.index('exec {pattern_fd}<&-'),
            self.canary.rindex('compare_active_credential "${credential_state}"'),
        )


class TunnelTokenIdentityValidatorTests(unittest.TestCase):
    """Bind a bearer token to the reviewed account and Tunnel without disclosure."""

    account = "a" * 32
    tunnel = str(uuid.UUID(hex="1" * 32))

    def token(self, *, account=None, tunnel=None, secret=None, extra=None):
        payload = {
            "a": account or self.account,
            "s": secret or base64.b64encode(b"s" * 32).decode("ascii"),
            "t": tunnel or self.tunnel,
        }
        if extra is not None:
            payload["e"] = extra
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(encoded).decode("ascii")

    def environment_for(self, path, *, account=None, tunnel=None):
        environment = os.environ.copy()
        environment.update({
            "CLOUDFLARED_TUNNEL_TOKEN_FILE": str(path),
            "EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256": hashlib.sha256(
                (account or self.account).encode("ascii")
            ).hexdigest(),
            "EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256": hashlib.sha256(
                (tunnel or self.tunnel).encode("ascii")
            ).hexdigest(),
        })
        return environment

    def invoke_path(
        self,
        path,
        *,
        account=None,
        tunnel=None,
        isolated=True,
        arguments=(),
    ):
        command = [sys.executable]
        if isolated:
            command.append("-I")
        command.extend((str(TOKEN_VALIDATOR), *arguments))
        return subprocess.run(
            command,
            cwd=ROOT,
            env=self.environment_for(path, account=account, tunnel=tunnel),
            text=True,
            capture_output=True,
            check=False,
        )

    def invoke(self, content, *, account=None, tunnel=None, isolated=True, arguments=()):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_bytes((content + "\n").encode("ascii"))
            path.chmod(0o600)
            return self.invoke_path(
                path.resolve(),
                account=account,
                tunnel=tunnel,
                isolated=isolated,
                arguments=arguments,
            )

    def assert_generic_failure(self, result, token=None):
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr, "FAIL Cloudflare Tunnel token validation.\n"
        )
        if token is not None:
            self.assertNotIn(token, result.stdout + result.stderr)

    def test_canonical_standard_base64_token_and_identity_pass(self):
        result = self.invoke(self.token())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.account, result.stdout + result.stderr)
        self.assertNotIn(self.tunnel, result.stdout + result.stderr)

    def test_wrong_identity_extra_endpoint_and_short_secret_fail_generically(self):
        candidates = (
            (self.token(), "b" * 32, self.tunnel),
            (self.token(extra="https://example.invalid"), self.account, self.tunnel),
            (
                self.token(secret=base64.b64encode(b"short").decode("ascii")),
                self.account,
                self.tunnel,
            ),
        )
        for token, account, tunnel in candidates:
            with self.subTest(account=account[:1], length=len(token)):
                result = self.invoke(token, account=account, tunnel=tunnel)
                self.assert_generic_failure(result, token)

    def test_cli_requires_isolation_and_zero_arguments(self):
        token = self.token()
        self.assert_generic_failure(self.invoke(token, isolated=False), token)
        self.assert_generic_failure(
            self.invoke(token, arguments=("unexpected",)), token
        )

    def test_relative_path_fails_without_disclosure(self):
        result = self.invoke_path(Path("relative-token"))
        self.assert_generic_failure(result)

    @unittest.skipUnless(os.name == "posix", "POSIX file custody is required")
    def test_group_access_hardlinks_and_ancestor_symlinks_fail(self):
        token = self.token()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mode_path = root / "mode-token"
            mode_path.write_text(token + "\n", encoding="ascii")
            mode_path.chmod(0o640)
            self.assert_generic_failure(self.invoke_path(mode_path.resolve()), token)

            original = root / "hardlink-token"
            alias = root / "hardlink-alias"
            original.write_text(token + "\n", encoding="ascii")
            original.chmod(0o600)
            os.link(original, alias)
            self.assert_generic_failure(self.invoke_path(original.resolve()), token)

            real_parent = root / "real-parent"
            linked_parent = root / "linked-parent"
            real_parent.mkdir(mode=0o700)
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            linked_token = real_parent / "token"
            linked_token.write_text(token + "\n", encoding="ascii")
            linked_token.chmod(0o600)
            self.assert_generic_failure(
                self.invoke_path(linked_parent / "token"), token
            )

    @unittest.skipUnless(os.name == "posix", "atomic rename race is POSIX-specific")
    def test_path_replacement_during_same_handle_read_fails(self):
        token = (self.token() + "\n").encode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "token"
            replacement = root / "replacement"
            retired = root / "retired"
            path.write_bytes(token)
            replacement.write_bytes(token)
            path.chmod(0o600)
            replacement.chmod(0o600)
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

            with mock.patch.object(
                TOKEN_VALIDATOR_MODULE.os, "read", side_effect=racing_read
            ):
                with self.assertRaises(TOKEN_VALIDATOR_MODULE.InvalidToken):
                    TOKEN_VALIDATOR_MODULE.stable_private_read(str(path.resolve()))
            self.assertTrue(raced)

    def test_validator_source_binds_same_handle_and_every_ancestor(self):
        source = TOKEN_VALIDATOR.read_text(encoding="utf-8")
        for fragment in (
            "os.supports_dir_fd",
            "O_NOFOLLOW",
            "dir_fd=parent_descriptor",
            "before_chain = _path_chain(path)",
            "after_chain = _path_chain(path)",
            "opened_before = os.fstat(descriptor)",
            "opened_after = os.fstat(descriptor)",
            "metadata.st_mtime_ns",
            "metadata.st_ctime_ns",
            "sys.flags.isolated != 1",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)


class TunnelTokenRotationRunbookTests(unittest.TestCase):
    """Keep routine availability separate from compromised-token eviction."""

    @classmethod
    def setUpClass(cls):
        cls.rotation = " ".join(ROTATION.read_text(encoding="utf-8").split())
        cls.readme = " ".join(README.read_text(encoding="utf-8").split())

    def test_rotation_semantics_reject_old_token_rollback(self):
        for fragment in (
            "the old token cannot establish a new connection",
            "already connected with the old token remain connected",
            "an old token is never a post-rotation rollback credential",
            "Physical or trusted-LAN recovery is the admin-path fallback",
            "The old token cannot reconnect after rotation and is not a rollback path",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.rotation)

    def test_compromise_path_force_disconnects_existing_connectors(self):
        self.assertEqual(
            self.rotation.count("suspected or confirmed compromise"), 2
        )
        self.assertIn(
            "DELETE /accounts/<ACCOUNT_ID>/cfd_tunnel/<TUNNEL_ID>/connections",
            self.rotation,
        )
        self.assertIn(
            "every old-token connector, including a malicious one", self.rotation
        )
        self.assertIn("Never restore the compromised token", self.rotation)

    def test_routine_and_compromise_keep_tunnels_independent(self):
        for fragment in (
            "Never rotate both in one change",
            "Prove the public connector recovered and `pi-admin` remained unchanged",
            "Public connector health must remain unchanged",
            "prove `pi-websites` remained unchanged",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.rotation)

    def test_connector_readme_records_the_safe_install_and_recovery_boundary(self):
        for fragment in (
            "It never executes the mutable staging path",
            "acquires an exclusive lock",
            "atomic same-filesystem operation",
            "token apply is intentionally blocked",
            "root-owned reviewed-blob launcher",
            "at least two working sessions have been proven immediately before mutation",
            "Physical access is the independent recovery path if either session later drops",
            "force-disconnect every existing connection",
            "physical/LAN access, never the old token",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.readme)


if __name__ == "__main__":
    unittest.main()
