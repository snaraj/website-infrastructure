"""Static contract for the root-only stacked-etcd Secret encryption canary."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import required_tool


ROOT = Path(__file__).resolve().parents[2]
CANARY = ROOT / "bootstrap" / "pi" / "verify-secret-encryption-at-rest.sh"
BASH = shutil.which("bash")
BASH_REQUIRED = "Bash is required to execute the encryption canary"
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)


class SecretEncryptionAtRestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = CANARY.read_text(encoding="utf-8")

    def test_is_root_only_and_requires_every_exact_mutation_gate(self) -> None:
        for fragment in (
            '[[ "${EUID}" -eq 0 ]]',
            'PHYSICAL_OR_LAN_RECOVERY_TESTED:-}" == yes',
            'TWO_WORKING_SESSIONS_PROVEN:-}" == yes',
            "CONFIRM_SECRET_ENCRYPTION_AT_REST_CANARY",
            "run-reviewed-secret-encryption-at-rest-canary",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)

    @unittest.skipUnless(BASH, "Bash is required for blocker behavior")
    def test_all_modes_are_code_blocked_before_root_or_credential_access(self) -> None:
        blocker = (
            "BLOCKED Secret encryption-at-rest canary requires the trusted "
            "reviewed-blob launcher and an installed etcdctl digest pin; no "
            "protected file was read and no cluster or etcd request was attempted.\n"
        )
        self.assertTrue(self.text.startswith("#!/bin/bash\n"))
        self.assertIn("readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no", self.text)
        self.assertLess(self.text.index("BLOCKED Secret encryption-at-rest"), self.text.index("PATH="))
        self.assertLess(
            self.text.index("BLOCKED Secret encryption-at-rest"),
            self.text.index('[[ "${EUID}" -eq 0 ]]'),
        )
        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory) / "protected-kubeconfig"
            versions = Path(directory) / "protected-versions"
            protected.write_bytes(b"must-not-be-read-or-modified")
            versions.write_bytes(b"must-not-be-read-or-modified")
            environment = {
                key: value
                for key, value in os.environ.items()
                if key not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"}
                and not key.startswith("BASH_FUNC_")
                and not key.startswith("LD_")
            }
            environment["KUBECONFIG_FILE"] = str(protected)
            environment["WEBSITE_INFRA_VERSIONS_FILE"] = str(versions)
            for mode in ("--check", "--dry-run", "--apply"):
                with self.subTest(mode=mode):
                    result = subprocess.run(
                        [required_tool(BASH, BASH_REQUIRED), str(CANARY), mode],
                        capture_output=True,
                        check=False,
                        text=True,
                        env=environment,
                        timeout=10,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, blocker)
                    self.assertEqual(protected.read_bytes(), b"must-not-be-read-or-modified")
                    self.assertEqual(versions.read_bytes(), b"must-not-be-read-or-modified")

    def test_check_and_dry_run_exit_before_any_object_mutation(self) -> None:
        for fragment in ("--check|--dry-run|--apply", '"${mode}" == --check', "no Kubernetes object"):
            self.assertIn(fragment, self.text)
        exit_index = self.text.index("exit 0", self.text.index('if [[ "${mode}" == --check'))
        create_index = self.text.index('"${kubectl}" "${kubectl_target_args[@]}" create -f')
        self.assertLess(exit_index, create_index)

    def test_latent_design_declares_clients_tls_and_target_binding(self) -> None:
        for fragment in (
            "kubectl=/usr/local/bin/kubectl",
            "etcdctl=/usr/local/bin/etcdctl",
            "KUBECTL_ARM64_SHA256",
            "KUBERNETES_VERSION",
            "ETCD_VERSION",
            "ETCD_TOOLS_ARM64_SHA256",
            "default_kubeconfig=/etc/kubernetes/admin.conf",
            'kubeconfig="/proc/$$/fd/${kubeconfig_fd}"',
            "EXPECTED_KUBECONFIG_CONTEXT",
            "EXPECTED_KUBERNETES_SERVER",
            "EXPECTED_PI_NODE_NAME",
            "endpoint=https://127.0.0.1:2379",
            "/etc/kubernetes/pki/etcd/ca.crt",
            "/etc/kubernetes/pki/etcd/healthcheck-client.crt",
            "/etc/kubernetes/pki/etcd/healthcheck-client.key",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)
        self.assertNotRegex(self.text, r"(?m)^\s*(kubectl|etcdctl)\s")
        self.assertIn("installed etcdctl binary does not yet have its own", self.text)

    def test_creates_one_immutable_high_entropy_secret_without_argument_disclosure(self) -> None:
        for fragment in (
            "canary_namespace=website-infrastructure-encryption-canary",
            "canary_name=secret-at-rest-canary",
            "/usr/bin/head -c 48 /dev/urandom",
            "/usr/bin/base64 -w 0",
            'create secret generic "${canary_name}"',
            '--from-file="canary-marker=${marker}"',
            "--dry-run=client",
            '"path":"/immutable","value":true',
            '"${kubectl}" "${kubectl_target_args[@]}" create -f "${manifest}"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)
        for forbidden in ("kubectl apply", "--from-literal", "stringData:", "set -x", 'cat "${marker}"'):
            self.assertNotIn(forbidden, self.text)

    def test_reads_only_the_exact_raw_etcd_key_and_checks_ciphertext(self) -> None:
        for fragment in (
            'etcd_key="/registry/secrets/${canary_namespace}/${canary_name}"',
            'get "${etcd_key}" --limit=1',
            '--write-out=json',
            'raw_value="${temporary}/raw-etcd-value"',
            "k8s:enc:secretbox:v1:",
            'grep -aFq -f "${marker}" "${raw_value}"',
            'str(item["mod_revision"]) != expected_revision',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)
        self.assertNotIn("--prefix", self.text)

    def test_captures_metadata_separately_and_deletes_with_server_preconditions(self) -> None:
        for fragment in (
            "capture_owned_identity",
            ".metadata.uid",
            ".metadata.resourceVersion",
            '"preconditions":{"uid":"%s","resourceVersion":"%s"}',
            'connection.request("DELETE", path, body=payload',
            'api_path="/api/v1/namespaces/${canary_namespace}/secrets/${canary_name}"',
            '--unix-socket="${proxy_socket}"',
            "socket.AF_UNIX",
            "--reject-methods='^(GET|POST|PUT|PATCH|CONNECT|HEAD|OPTIONS|TRACE)$'",
            "no broad deletion was attempted",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)
        for forbidden in ("kubectl delete", "delete namespace", "--all", "--selector", "-l security"):
            self.assertNotIn(forbidden, self.text)
        self.assertNotIn("--port=", self.text)

    def test_audit_proof_is_metadata_only_and_no_host_network_controls_change(self) -> None:
        for fragment in (
            "/var/log/kubernetes/audit/audit.log",
            "expected_audit_policy_sha256",
            '"requestObject" in event',
            '"responseObject" in event',
            '{"create", "get", "delete"}.issubset(seen)',
            "audit metadata-only records could not be proven",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)
        for forbidden_command in ("systemctl ", "ufw ", "iptables ", "nft ", "wg-quick ", "ssh ", "apt "):
            self.assertNotRegex(self.text, rf"(?m)^\s*{forbidden_command}")

    @unittest.skipUnless(BASH, "Bash is required for parse checks")
    def test_script_parses(self) -> None:
        subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), "-n", str(CANARY)], check=True
        )


if __name__ == "__main__":
    unittest.main()
