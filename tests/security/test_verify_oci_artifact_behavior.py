"""Exercise exact per-platform OCI evidence selection without a container runtime."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "scripts" / "ci" / "verify-oci-artifact.sh"
EXPECTED_DIGEST = "sha256:" + ("a" * 64)


def bash_executable():
    """Find Bash on Linux CI or the ordinary Git for Windows installation."""

    discovered = shutil.which("bash")
    if discovered:
        return discovered
    if os.name == "nt":
        candidate = (
            Path(os.environ.get("ProgramFiles", "C:/Program Files"))
            / "Git/bin/bash.exe"
        )
        if candidate.is_file():
            return str(candidate)
    return None


@unittest.skipUnless(bash_executable(), "Bash is required for OCI verifier tests")
class VerifyOCIArtifactBehaviorTests(unittest.TestCase):
    """Model ORAS-selected views and record the sources given to each scanner."""

    def _run_fixture(self, root):
        """Run the verifier with deterministic ORAS, scanner, and jq doubles."""

        binary_dir = root / "bin"
        binary_dir.mkdir()
        archive = root / "site.oci.tar"
        archive.write_bytes(b"synthetic OCI archive\n")
        evidence = root / "evidence"
        syft_log = root / "syft-calls"
        trivy_log = root / "trivy-calls"

        fake_oras = binary_dir / "oras"
        fake_oras.write_bytes(
            b"""#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == resolve ]]; then
  printf '%s\n' "${FAKE_EXPECTED_DIGEST}"
  exit 0
fi
if [[ ${1:-} == cp ]]; then
  target="${@: -1}"
  mkdir -p -- "${target%:scan}"
  exit 0
fi
if [[ ${1:-} == manifest && ${2:-} == fetch-config ]]; then
  target="${@: -1}"
  if [[ "${target}" == *amd64* ]]; then
    printf 'CONFIG linux/amd64\n'
  else
    printf 'CONFIG linux/arm64\n'
  fi
  exit 0
fi
if [[ ${1:-} == manifest && ${2:-} == fetch ]]; then
  target="${@: -1}"
  if [[ "${target}" == *amd64* ]]; then
    printf 'LAYER sha256:%064d 1024\n' 1
  else
    printf 'LAYER sha256:%064d 1024\n' 2
  fi
  exit 0
fi
exit 90
"""
        )
        fake_jq = binary_dir / "jq"
        fake_jq.write_bytes(
            b"""#!/usr/bin/env bash
set -euo pipefail
read -r record value size
case "${record}" in
  CONFIG) printf '%s\n' "${value}" ;;
  LAYER) printf '%s\t%s\n' "${value}" "${size}" ;;
  *) exit 91 ;;
esac
"""
        )
        fake_trivy = binary_dir / "trivy"
        fake_trivy.write_bytes(
            b"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${FAKE_TRIVY_LOG}"
"""
        )
        fake_syft = binary_dir / "syft"
        fake_syft.write_bytes(
            b"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${FAKE_SYFT_LOG}"
for argument in "$@"; do
  case "${argument}" in
    spdx-json=*)
      output="${argument#spdx-json=}"
      mkdir -p -- "${output%/*}"
      printf '{}\n' > "${output}"
      ;;
  esac
done
"""
        )
        for executable in (fake_oras, fake_jq, fake_trivy, fake_syft):
            executable.chmod(0o755)

        environment = os.environ.copy()
        environment.update(
            {
                "PATH": str(binary_dir) + os.pathsep + environment.get("PATH", ""),
                "OCI_ARCHIVE": archive.as_posix(),
                "EXPECTED_DIGEST": EXPECTED_DIGEST,
                "EVIDENCE_DIR": evidence.as_posix(),
                "ARTIFACT_NAME": "example-site",
                "MAX_APPLICATION_LAYER_BYTES": "16777216",
                "FAKE_EXPECTED_DIGEST": EXPECTED_DIGEST,
                "FAKE_SYFT_LOG": syft_log.as_posix(),
                "FAKE_TRIVY_LOG": trivy_log.as_posix(),
            }
        )
        result = subprocess.run(
            [bash_executable(), str(VERIFIER)],
            cwd=str(REPO_ROOT),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        syft_calls = (
            syft_log.read_text(encoding="utf-8").splitlines()
            if syft_log.exists()
            else []
        )
        trivy_calls = (
            trivy_log.read_text(encoding="utf-8").splitlines()
            if trivy_log.exists()
            else []
        )
        return result, syft_calls, trivy_calls

    def test_sboms_reuse_the_exact_oras_selected_platform_layouts(self):
        """Attached index evidence must not send Syft back to the root archive."""

        with tempfile.TemporaryDirectory() as temporary:
            result, syft_calls, trivy_calls = self._run_fixture(Path(temporary))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(syft_calls), 2, syft_calls)
        self.assertIn("oci-dir:", syft_calls[0])
        self.assertIn("example-site-amd64.oci", syft_calls[0])
        self.assertIn("example-site-amd64.spdx.json", syft_calls[0])
        self.assertIn("oci-dir:", syft_calls[1])
        self.assertIn("example-site-arm64.oci", syft_calls[1])
        self.assertIn("example-site-arm64.spdx.json", syft_calls[1])
        self.assertTrue(all("oci-archive:" not in call for call in syft_calls))
        self.assertTrue(all("--platform" not in call for call in syft_calls))
        self.assertEqual(len(trivy_calls), 2, trivy_calls)
        self.assertIn("example-site-amd64.oci:scan", trivy_calls[0])
        self.assertIn("example-site-arm64.oci:scan", trivy_calls[1])


if __name__ == "__main__":
    unittest.main()
