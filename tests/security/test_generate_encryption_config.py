"""Contract and runtime tests for no-display API encryption config generation."""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "generate_encryption_config.py"
VALIDATOR = ROOT / "scripts" / "validate_encryption_config.py"
TEMPLATE = ROOT / "bootstrap" / "pi" / "encryption-config.yaml.example"
CEREMONY = ROOT / "bootstrap" / "pi" / "generate-encryption-config.sh"
BASH = shutil.which("bash")
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)

SPEC = importlib.util.spec_from_file_location("generate_encryption_config", GENERATOR)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

VALIDATOR_SPEC = importlib.util.spec_from_file_location("test_exact_encryption_validator", VALIDATOR)
VALIDATOR_MODULE = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader is not None
VALIDATOR_SPEC.loader.exec_module(VALIDATOR_MODULE)


class EncryptionConfigGeneratorTests(unittest.TestCase):
    def test_render_is_exact_and_validator_approved(self) -> None:
        rendered = MODULE.render_config(
            TEMPLATE.read_text(encoding="utf-8"),
            "key-2026-08",
            b"a" * 32,
            VALIDATOR_MODULE,
        )
        self.assertEqual(VALIDATOR_MODULE.validate(rendered), [])
        self.assertNotIn("REPLACE_", rendered)
        self.assertIn("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=", rendered)

    def test_rejects_bad_name_key_length_or_template_shape(self) -> None:
        template = TEMPLATE.read_text(encoding="utf-8")
        for name, key, candidate in (
            ("current", b"a" * 32, template),
            ("key-2026-08", b"a" * 31, template),
            ("key-2026-08", b"a" * 32, template.replace("REPLACE_KEY_NAME", "key-2026-08")),
        ):
            with self.subTest(name=name, length=len(key)):
                with self.assertRaises(MODULE.GenerationError):
                    MODULE.render_config(candidate, name, key, VALIDATOR_MODULE)

    def test_cli_writes_mode_0600_silently_and_never_clobbers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "encryption-config.yaml"
            command = [
                os.fspath(Path(os.sys.executable)),
                "-B",
                os.fspath(GENERATOR),
                os.fspath(VALIDATOR),
                os.fspath(TEMPLATE),
                os.fspath(output),
                "key-2026-08",
            ]
            first = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, b"")
            self.assertEqual(first.stderr, b"")
            original = output.read_bytes()
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(VALIDATOR_MODULE.validate(original.decode("utf-8")), [])

            second = subprocess.run(command, capture_output=True, check=False)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(second.stdout, b"")
            self.assertEqual(output.read_bytes(), original)
            encoded_key = original.split(b"secret: ", 1)[1].splitlines()[0]
            self.assertNotIn(encoded_key, second.stderr)

    def test_ceremony_binds_protected_runtime_and_exact_main_blobs(self) -> None:
        text = CEREMONY.read_text(encoding="utf-8")
        generator_text = GENERATOR.read_text(encoding="utf-8")
        for fragment in (
            "encrypted-storage-no-swap-no-coredump-no-cloud-sync-no-session-recording",
            "EXPECTED_CREDENTIAL_WORKSPACE_MOUNT_UUID_SHA256",
            "swapon --show=NAME",
            "/proc/sys/kernel/yama/ptrace_scope",
            "git --no-replace-objects",
            "refs/remotes/origin/main^{commit}",
            "bootstrap/pi/generate-encryption-config.sh",
            "scripts/generate_encryption_config.py",
            "scripts/validate_encryption_config.py",
            "scripts/validate_kubeadm_config.py",
            ">/dev/null 2>/dev/null",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)
        self.assertIn("os.urandom(32)", generator_text)
        self.assertNotIn("head -c 32", text)
        self.assertNotIn("base64", text)

    @unittest.skipUnless(BASH, "Bash is required for blocker behavior")
    def test_ceremony_is_code_blocked_before_repository_or_key_access(self) -> None:
        text = CEREMONY.read_text(encoding="utf-8")
        blocker = "BLOCKED API encryption generation requires the trusted reviewed-blob launcher"
        self.assertIn("readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no", text)
        self.assertLess(text.index(blocker), text.index('if [[ -n "${BASH_ENV+x}"'))
        self.assertLess(text.index(blocker), text.index('repo_root="$(cd'))
        self.assertLess(text.index(blocker), text.index("if ! PYTHONDONTWRITEBYTECODE=1"))

        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"}
            and not key.startswith("BASH_FUNC_")
            and not key.startswith("LD_")
        }
        result = subprocess.run(
            [BASH, str(CEREMONY)],
            capture_output=True,
            check=False,
            text=True,
            env=environment,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            blocker + "; no key was generated.\n",
        )

    @unittest.skipUnless(BASH, "Bash is required for parse checks")
    def test_ceremony_parses(self) -> None:
        subprocess.run([BASH, "-n", str(CEREMONY)], check=True)


if __name__ == "__main__":
    unittest.main()
