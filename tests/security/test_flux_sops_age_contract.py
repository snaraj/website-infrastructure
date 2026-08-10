"""Static and mocked contracts for protected Flux age-key installation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.security.test_validate_kubeconfig_snapshot import document_bytes, valid_document


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "bootstrap" / "flux" / "verify-sops-age-secret.sh"
INSTALL = ROOT / "bootstrap" / "flux" / "install-sops-age-secret.sh"
BOOTSTRAP = ROOT / "bootstrap" / "flux" / "bootstrap.sh"
VERIFY_ENTRY = ROOT / "bootstrap" / "flux" / "verify.sh"
VERIFY_CIPHERTEXT = ROOT / "bootstrap" / "flux" / "verify-sops-ciphertext.sh"
PROTECTED_FIXTURE_ROOT = os.environ.get("PROTECTED_LUKS_TEST_WORKSPACE")
BASH = shutil.which("bash")
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)


class FluxSopsAgeStaticContractTests(unittest.TestCase):
    """Keep every secret-aware step pinned, snapshotted, and target-bound."""

    def test_installer_snapshots_tools_keys_and_closed_kubeconfig(self):
        text = INSTALL.read_text(encoding="utf-8")
        for fragment in (
            "AGE_KEYGEN_LINUX_AMD64_SHA256",
            "KUBECTL_LINUX_AMD64_SHA256",
            'PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes',
            'TWO_WORKING_SESSIONS_PROVEN:-}" == yes',
            'snapshot_protected_file "${kubeconfig_source}" "${kubeconfig}" data',
            'snapshot_protected_file "${kubectl_source}" "${kubectl}" executable',
            'snapshot_protected_file "${age_keygen_source}" "${age_keygen}" executable',
            'KUBECONFIG_SNAPSHOT_FILE="${kubeconfig}"',
            '"${age_keygen}" -y "${identity_snapshot}" > "${derived_output}"',
            'cmp -s -- "${derived_output}" "${expected_output}"',
            'kubectl_target_args=("${kubectl_config_args[@]}" --server=',
            '"${kubectl}" "${kubectl_target_args[@]}" replace -f "${final}" -o json',
            '"${kubectl}" "${kubectl_target_args[@]}" create -f "${final}" -o json',
            'mktemp -d "${workspace%/}/sops-age-install.',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertNotIn("source \"${repo_root}/versions.env\"", text)

    def test_secret_readers_require_encrypted_custody_and_clean_process_state(self):
        for path in (INSTALL, VERIFY, VERIFY_CIPHERTEXT):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertTrue(text.startswith("#!/bin/bash\n"))
                self.assertIn("readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no", text)
                self.assertLess(
                    text.index("BLOCKED "),
                    text.index('if [[ -n "${BASH_ENV+x}"'),
                )
                for fragment in (
                    '"${BASH_ENV+x}"',
                    '"$(declare -Fx)"',
                    '"${LD_PRELOAD+x}"',
                    "ulimit -H -c 0",
                    "EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256",
                    "encrypted-storage-no-swap-no-coredump-no-cloud-sync-no-session-recording",
                    "lsblk --inverse --noheadings --raw --output TYPE",
                    "swapon --show=NAME --noheadings --raw",
                    "/proc/sys/kernel/yama/ptrace_scope",
                    "SOPS_AGE_TWO_BACKUPS_RESTORE_TESTED",
                ):
                    self.assertIn(fragment, text)

    def test_secret_readers_disable_replace_refs_and_bind_reviewed_blobs(self):
        for path in (INSTALL, VERIFY, VERIFY_CIPHERTEXT):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                for fragment in (
                    "git --no-replace-objects",
                    "GIT_CONFIG_NOSYSTEM=1",
                    '"${git_dir}/info/grafts"',
                    "refs/replace",
                    "hash-object --no-filters",
                    "cat-file blob",
                    "self_blob=",
                ):
                    self.assertIn(fragment, text)

    def test_installer_compares_server_returned_private_bytes_without_printing(self):
        text = INSTALL.read_text(encoding="utf-8")
        for fragment in (
            'mutation_result="${temporary}/mutation-result.json"',
            "base64.b64decode(encoded, validate=True)",
            "base64.b64encode(decoded).decode(\"ascii\") != encoded",
            "hmac.compare_digest(decoded, identity)",
            'live_result="${temporary}/live-result.json"',
            '"${mutation_result}" "${live_result}" "${combined}"',
            "if mutation_identity != live_identity",
            '"ownerReferences"',
            "EXPECTED_PREDECESSOR_SOPS_AGE_SECRET_SHA256",
            'metadata.get("annotations") != expected_annotations',
            'set(data) != {"age.agekey"}',
            "mutation_attempted=1",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertNotIn('jsonpath=\'{.data', text)

    def test_verifier_compares_exact_live_bytes_on_the_protected_target(self):
        text = VERIFY.read_text(encoding="utf-8")
        for fragment in (
            "KUBECONFIG_FILE",
            "KUBECTL_BINARY",
            "AGE_KEYGEN_BINARY",
            "SOPS_AGE_IDENTITY_FILE",
            "EXPECTED_KUBECONFIG_CONTEXT",
            "EXPECTED_KUBERNETES_SERVER",
            "EXPECTED_PI_NODE_NAME",
            "KUBECONFIG_SNAPSHOT_FILE",
            '"${kubectl}" "${kubectl_target_args[@]}" -n flux-system get secret',
            '-o json > "${live_result}"',
            "hmac.compare_digest(decoded, identity)",
            "EXPECTED_KUBERNETES_CA_SHA256",
            "EXPECTED_KUBE_SYSTEM_NAMESPACE_UID_SHA256",
            "verify_cluster_target || fail",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertNotRegex(text, r"(?m)^\s*kubectl\s")
        self.assertNotIn("go-template", text)

    def test_bootstrap_snapshots_reviewed_commit_and_never_uses_bare_kubectl(self):
        text = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertLess(
            text.index("BLOCKED Flux live mode requires the trusted reviewed-blob launcher"),
            text.index('versions_file="${repo_root}/versions.env"'),
        )
        for fragment in (
            "EXPECTED_REPOSITORY_HEAD",
            'PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes',
            'TWO_WORKING_SESSIONS_PROVEN:-}" == yes',
            "refs/heads/main",
            "git_repo archive",
            "KUBECTL_LINUX_AMD64_SHA256",
            "validate_kubeconfig_snapshot.py",
            '"${kubectl}" "${kubectl_target_args[@]}" apply -k',
            '"${kubectl}" "${kubectl_target_args[@]}" apply -f',
            'KUBECONFIG_FILE="${kubeconfig}" KUBECTL_BINARY="${kubectl}"',
            "GIT_CONFIG_GLOBAL=/dev/null",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertNotRegex(text, r"(?m)^\s*kubectl\s")

    def test_verify_entry_delegates_to_the_same_protected_implementation(self):
        text = VERIFY_ENTRY.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/bash\n"))
        self.assertIn("readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no", text)
        self.assertLess(text.index("BLOCKED Flux verification"), text.index('repo_root="$(cd'))
        self.assertIn('bootstrap/flux/bootstrap.sh" --verify', text)
        self.assertNotIn("kubectl ", text)

    @unittest.skipUnless(BASH, "Bash is required for blocker behavior")
    def test_every_secret_or_live_entrypoint_stops_before_protected_access(self):
        cases = (
            (INSTALL, ["create"], "BLOCKED sops-age installation requires the trusted reviewed-blob launcher; no private file was read and no cluster mutation was attempted.\n"),
            (VERIFY, [], "BLOCKED sops-age verification requires the trusted reviewed-blob launcher; no private file was read.\n"),
            (VERIFY_CIPHERTEXT, [], "BLOCKED protected SOPS verification requires the trusted reviewed-blob launcher; no private file was read and no ciphertext was decrypted.\n"),
            (VERIFY_ENTRY, [], "BLOCKED Flux verification requires the trusted reviewed-blob launcher; no protected file was read and no cluster request was attempted.\n"),
            (BOOTSTRAP, ["--apply-controllers"], "BLOCKED Flux live mode requires the trusted reviewed-blob launcher; no protected file was read and no cluster mutation or request was attempted.\n"),
            (BOOTSTRAP, ["--apply-sync"], "BLOCKED Flux live mode requires the trusted reviewed-blob launcher; no protected file was read and no cluster mutation or request was attempted.\n"),
            (BOOTSTRAP, ["--verify"], "BLOCKED Flux live mode requires the trusted reviewed-blob launcher; no protected file was read and no cluster mutation or request was attempted.\n"),
        )
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"}
            and not key.startswith("BASH_FUNC_")
            and not key.startswith("LD_")
        }
        for path, arguments, expected in cases:
            with self.subTest(path=path.name, arguments=arguments):
                result = subprocess.run(
                    [BASH, str(path), *arguments],
                    capture_output=True,
                    check=False,
                    text=True,
                    env=environment,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, expected)

    def test_offline_ciphertext_verifier_authenticates_mac_and_token_identity(self):
        text = VERIFY_CIPHERTEXT.read_text(encoding="utf-8")
        for fragment in (
            "SOPS_LINUX_AMD64_SHA256",
            "AGE_KEYGEN_LINUX_AMD64_SHA256",
            "EXPECTED_CLOUDFLARE_ACCOUNT_ID_SHA256",
            "EXPECTED_CLOUDFLARE_TUNNEL_ID_SHA256",
            "validate_sops_ciphertext_snapshot.py",
            '"${python3_binary}" -I -B "${validator_directory}/validate_sops_ciphertext_snapshot.py"',
            "validate_cloudflared_tunnel_token.py",
            "SOPS_AGE_KEY_FILE=\"${identity}\"",
            "unshare --user --map-current-user --net",
            "--disable-version-check --decrypt",
            "--extract '[\"stringData\"][\"token\"]'",
            '> "${token}" 2> "${sops_stderr}"',
            "ciphertext_sha256=%s",
            "kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml",
            '"${EXPECTED_REPOSITORY_HEAD}:${public_path}"',
            "Establish repository trust before the first private-identity read",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertNotIn("cat \"${token}\"", text)

    @unittest.skipUnless(BASH, "Bash is required for parse checks")
    def test_scripts_parse(self):
        for path in (VERIFY, INSTALL, BOOTSTRAP, VERIFY_ENTRY, VERIFY_CIPHERTEXT):
            with self.subTest(path=path.name):
                subprocess.run([BASH, "-n", str(path)], check=True)


@unittest.skipUnless(
    os.name == "posix"
    and platform.system() == "Linux"
    and platform.machine() == "x86_64"
    and bool(PROTECTED_FIXTURE_ROOT),
    "protected runtime fixture requires an explicit encrypted Linux workspace",
)
class FluxSopsAgeLinuxRuntimeTests(unittest.TestCase):
    recipient_one = "age1pq1" + "q" * 80
    recipient_two = "age1pq1" + "z" * 80

    def run_fixture(self, recipients=None, *, expected="1", shape=None):
        if recipients is None:
            recipients = [self.recipient_one]
        digest = hashlib.sha256(
            ("".join(value + "\n" for value in recipients)).encode("ascii")
        ).hexdigest()
        if shape is None:
            shape = (
                "Opaque 1 present {} {} "
                "website-infrastructure-sops-age-installer-v1"
            ).format(expected, digest)
        with tempfile.TemporaryDirectory(dir=PROTECTED_FIXTURE_ROOT) as directory:
            root = Path(directory)
            mini_repo = root / "repo"
            workspace = root / "credentials"
            (mini_repo / "bootstrap" / "flux").mkdir(parents=True)
            (mini_repo / "scripts").mkdir()
            workspace.mkdir(mode=0o700)
            script = mini_repo / "bootstrap" / "flux" / VERIFY.name
            validator = mini_repo / "scripts" / "validate_kubeconfig_snapshot.py"
            shutil.copyfile(VERIFY, script)
            shutil.copyfile(
                ROOT / "scripts" / "validate_kubeconfig_snapshot.py", validator
            )

            kubeconfig = workspace / "kubeconfig.json"
            kubeconfig.write_bytes(document_bytes(valid_document()))
            kubeconfig.chmod(0o600)
            kubectl = workspace / "kubectl"
            kubectl.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "args=\" $* \"\n"
                "if [[ \"${args}\" == *\" version --client -o yaml \"* ]]; then\n"
                "  printf 'gitVersion: v1.36.3\\n'\n"
                "elif [[ \"${args}\" == *\" config current-context \"* ]]; then\n"
                "  printf 'operator@kubernetes\\n'\n"
                "elif [[ \"${args}\" == *\" config view \"* ]]; then\n"
                "  printf 'https://127.0.0.1:6443'\n"
                "elif [[ \"${args}\" == *\" get nodes \"* ]]; then\n"
                "  printf 'pi-node'\n"
                "elif [[ \"${args}\" == *\" get secret sops-age \"* ]]; then\n"
                "  printf '%s' \"${MOCK_SHAPE}\"\n"
                "else\n"
                "  exit 92\n"
                "fi\n",
                encoding="utf-8",
            )
            kubectl.chmod(0o700)
            kubectl_digest = hashlib.sha256(kubectl.read_bytes()).hexdigest()
            (mini_repo / "versions.env").write_text(
                "KUBERNETES_VERSION=v1.36.3\n"
                f"KUBECTL_LINUX_AMD64_SHA256={kubectl_digest}\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "init", "-b", "main"], cwd=mini_repo, check=True,
                           capture_output=True, text=True)
            subprocess.run(["git", "add", "."], cwd=mini_repo, check=True,
                           capture_output=True, text=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=mini_repo,
                check=True,
                capture_output=True,
                text=True,
            )
            reviewed_head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=mini_repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            environment = {
                key: value
                for key, value in os.environ.items()
                if key
                not in {
                    "KUBECONFIG",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                    "NO_PROXY",
                    "http_proxy",
                    "https_proxy",
                    "all_proxy",
                    "no_proxy",
                    "KUBECTL_PLUGINS_PATH",
                }
            }
            environment.update(
                {
                    "CREDENTIAL_WORKSPACE": str(workspace.resolve()),
                    "KUBECONFIG_FILE": str(kubeconfig.resolve()),
                    "KUBECTL_BINARY": str(kubectl.resolve()),
                    "EXPECTED_KUBECONFIG_CONTEXT": "operator@kubernetes",
                    "EXPECTED_KUBERNETES_SERVER": "https://127.0.0.1:6443",
                    "EXPECTED_PI_NODE_NAME": "pi-node",
                    "EXPECTED_REPOSITORY_HEAD": reviewed_head,
                    "MOCK_SHAPE": shape,
                }
            )
            return subprocess.run(
                ["/bin/bash", str(script), expected, *recipients],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=15,
            )

    def test_one_and_two_recipient_metadata_pass_without_disclosure(self):
        for recipients, expected in (
            ([self.recipient_one], "1"),
            ([self.recipient_one, self.recipient_two], "2"),
        ):
            with self.subTest(expected=expected):
                result = self.run_fixture(recipients, expected=expected)
                self.assertEqual(result.returncode, 0, result.stderr)
                for recipient in recipients:
                    self.assertNotIn(recipient, result.stdout + result.stderr)

    def test_duplicate_bad_recipient_and_wrong_shape_fail_generically(self):
        cases = (
            ([self.recipient_one, self.recipient_one], "2", None),
            (["age1" + "q" * 80], "1", None),
            ([self.recipient_one], "1", "Opaque 2 missing 1 " + "0" * 64 + " bad"),
        )
        for recipients, expected, shape in cases:
            with self.subTest(expected=expected, shape=shape):
                result = self.run_fixture(recipients, expected=expected, shape=shape)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, "FAIL sops-age Secret verification.\n")


if __name__ == "__main__":
    unittest.main()
