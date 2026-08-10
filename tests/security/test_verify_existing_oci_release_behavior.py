"""Exercise the read-only manual release verifier without a registry."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts/ci/verify-existing-oci-release.sh"
DIGEST = "sha256:" + ("a" * 64)


def bash_executable():
    discovered = shutil.which("bash")
    if discovered:
        return discovered
    if os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
        if candidate.is_file():
            return str(candidate)
    return None


@unittest.skipUnless(bash_executable(), "Bash is required for OCI release behavior tests")
class VerifyExistingOCIReleaseBehaviorTests(unittest.TestCase):
    def run_fixture(self, *, sha_digest=DIGEST, version_digest=DIGEST, fail_version=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            log = root / "cosign.log"
            oras = binary / "oras"
            oras.write_bytes(
                b"""#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == resolve ]] || exit 90
case "${2:-}" in
  *:sha-*) printf '%s\n' "${FAKE_SHA_DIGEST}" ;;
  *:v*)
    if [[ "${FAKE_FAIL_VERSION}" == 1 ]]; then
      printf 'MANIFEST_UNKNOWN: synthetic missing stable tag\n' >&2
      exit 1
    fi
    printf '%s\n' "${FAKE_VERSION_DIGEST}"
    ;;
  *) exit 91 ;;
esac
"""
            )
            cosign = binary / "cosign"
            cosign.write_bytes(
                b"""#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == verify ]] || exit 92
printf '%s\n' "$*" > "${FAKE_COSIGN_LOG}"
"""
            )
            oras.chmod(0o755)
            cosign.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": str(binary) + os.pathsep + environment.get("PATH", ""),
                    "IMAGE": "ghcr.io/snaraj/naranjo-online",
                    "RELEASE_TAG": "v0.1.0",
                    "GITHUB_SHA": "b" * 40,
                    "WORKFLOW_IDENTITY": (
                        "https://github.com/snaraj/naranjo.online/.github/"
                        "workflows/release-publisher.yml@refs/tags/v*"
                    ),
                    "VERIFY_ERROR_ROOT": (root / "errors").as_posix(),
                    "FAKE_SHA_DIGEST": sha_digest,
                    "FAKE_VERSION_DIGEST": version_digest,
                    "FAKE_FAIL_VERSION": "1" if fail_version else "0",
                    "FAKE_COSIGN_LOG": log.as_posix(),
                }
            )
            result = subprocess.run(
                [bash_executable(), str(SCRIPT)],
                cwd=str(REPO_ROOT),
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            return result, log.read_text(encoding="utf-8") if log.exists() else ""

    def test_matching_names_verify_one_exact_digest(self):
        result, cosign_call = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Read-only verification passed", result.stdout)
        self.assertIn("ghcr.io/snaraj/naranjo-online@{}".format(DIGEST), cosign_call)

    def test_mismatched_names_fail_before_signature_verification(self):
        result, cosign_call = self.run_fixture(
            version_digest="sha256:" + ("c" * 64)
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("do not identify the same digest", result.stderr)
        self.assertEqual(cosign_call, "")

    def test_missing_stable_name_fails_before_signature_verification(self):
        result, cosign_call = self.run_fixture(fail_version=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required immutable reference is unavailable", result.stderr)
        self.assertEqual(cosign_call, "")

    def test_malformed_registry_digest_fails_closed(self):
        result, cosign_call = self.run_fixture(sha_digest="sha256:short")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("malformed digest", result.stderr)
        self.assertEqual(cosign_call, "")


if __name__ == "__main__":
    unittest.main()
