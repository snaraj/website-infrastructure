#!/usr/bin/env python3
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import required_tool


SCRIPT = Path(__file__).resolve().parents[2] / "bootstrap" / "pi" / "init-control-plane.sh"
BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required for init-script helper tests"
if BASH is None and os.name == "nt":
    git_bash = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
    if git_bash.is_file():
        BASH = str(git_bash)


def bash_path(path):
    value = path.as_posix()
    if os.name == "nt" and len(value) >= 3 and value[1:3] == ":/":
        return f"/{value[0].lower()}{value[2:]}"
    return value


@unittest.skipUnless(BASH, "bash is required for init-script helper tests")
class BootstrapTokenCleanupTests(unittest.TestCase):
    def run_bash(self, body):
        result = subprocess.run(
            [
                required_tool(BASH, BASH_REQUIRED),
                "-c",
                'source "$1"\n' + body,
                "token-cleanup-test",
                bash_path(SCRIPT),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_apply_path_deletes_tokens_before_network_bootstrap(self):
        source = SCRIPT.read_text(encoding="utf-8")
        init_call = source.index(
            "kubeadm init --skip-token-print --config /etc/kubernetes/kubeadm-config.yaml"
        )
        strict_delete = source.index("\ndelete_bootstrap_tokens\n", init_call)
        strict_verify = source.index("\nassert_no_bootstrap_token_secrets\n", strict_delete)
        first_snapshot = source.index("\nCONFIRM_ETCD_SNAPSHOT=create-reviewed", strict_verify)
        cni_apply = source.index("\nkubectl apply --server-side", first_snapshot)
        final_verify = source.index("\nassert_no_bootstrap_token_secrets\n", cni_apply)
        success = source.index("\ntrap - EXIT\n", final_verify)
        self.assertLess(init_call, strict_delete)
        self.assertLess(strict_delete, strict_verify)
        self.assertLess(strict_verify, first_snapshot)
        self.assertLess(first_snapshot, cni_apply)
        self.assertLess(strict_verify, cni_apply)
        self.assertLess(cni_apply, final_verify)
        self.assertLess(final_verify, success)

    def test_failure_trap_invokes_best_effort_cleanup(self):
        source = SCRIPT.read_text(encoding="utf-8")
        trap_start = source.index("cleanup_failure() {")
        trap_end = source.index("\n}\ntrap cleanup_failure EXIT", trap_start)
        cleanup_body = source[trap_start:trap_end]
        self.assertIn("best_effort_delete_bootstrap_tokens", cleanup_body)

    def test_token_list_failure_is_propagated(self):
        self.run_bash(
            r'''
kubeadm() { return 23; }
if delete_bootstrap_tokens; then
  exit 90
fi
'''
        )

    def test_every_token_is_attempted_and_delete_failure_is_propagated(self):
        self.run_bash(
            r'''
attempts=()
kubeadm() {
  if [[ "$1 $2" == "token list" ]]; then
    printf '%s\n' \
      'TOKEN                     TTL' \
      'abcdef.0123456789abcdef   23h' \
      'bcdefg.fedcba9876543210   23h'
    return 0
  fi
  if [[ "$1 $2" == "token delete" ]]; then
    attempts+=("$3")
    [[ "$3" != 'abcdef.0123456789abcdef' ]]
    return
  fi
  return 91
}
if delete_bootstrap_tokens; then
  exit 92
fi
[[ "${#attempts[@]}" -eq 2 ]]
'''
        )

    def test_secret_verification_fails_closed(self):
        self.run_bash(
            r'''
kubectl() {
  printf '%s\n' default-token bootstrap-token-abcdef
}
if assert_no_bootstrap_token_secrets; then
  exit 93
fi

kubectl() { return 47; }
if assert_no_bootstrap_token_secrets; then
  exit 94
fi
'''
        )

    def test_failure_cleanup_falls_back_to_narrow_secret_deletion(self):
        self.run_bash(
            r'''
deleted=no
deleted_resource=''
kubeadm() { return 48; }
kubectl() {
  if [[ "$*" == *'get secrets -o jsonpath='* ]]; then
    [[ "${deleted}" == yes ]] || printf '%s\n' bootstrap-token-abcdef
    return 0
  fi
  if [[ "$*" == *'get secrets -o name'* ]]; then
    printf '%s\n' secret/bootstrap-token-abcdef secret/unrelated
    return 0
  fi
  if [[ "$*" == *'delete secret/bootstrap-token-abcdef --wait=true'* ]]; then
    deleted=yes
    deleted_resource=secret/bootstrap-token-abcdef
    return 0
  fi
  return 95
}
best_effort_delete_bootstrap_tokens
[[ "${deleted}" == yes ]]
[[ "${deleted_resource}" == secret/bootstrap-token-abcdef ]]
'''
        )


if __name__ == "__main__":
    unittest.main()
