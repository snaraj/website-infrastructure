"""Exercise fail-closed stable OCI tag publication without a registry."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = REPO_ROOT / "scripts" / "ci" / "publish-stable-oci-tag.sh"
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


class PublishStableOCITagBehaviorTests(unittest.TestCase):
    """Model stable-tag existence, races, and ambiguous registry failures."""

    def _run_fixture(self, root, destination_state, github_sha="b" * 40):
        binary_dir = root / "bin"
        binary_dir.mkdir()
        call_log = root / "oras-calls"
        created = root / "stable-created"
        fake_oras = binary_dir / "oras"
        fake_oras.write_bytes(
            b"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${ORAS_CALL_LOG}"
if [[ "$1" == resolve ]]; then
  reference="$2"
  if [[ "${reference}" == *":sha-"* ]]; then
    printf '%s\n' "${FAKE_EXPECTED_DIGEST}"
    exit 0
  fi
  case "${FAKE_DESTINATION_STATE}" in
    expected)
      printf '%s\n' "${FAKE_EXPECTED_DIGEST}"
      ;;
    absent)
      if [[ -f "${FAKE_DESTINATION_CREATED}" ]]; then
        printf '%s\n' "${FAKE_EXPECTED_DIGEST}"
      else
        printf 'Error response from registry: failed to resolve digest: %s: not found\n' "${reference}" >&2
        exit 1
      fi
      ;;
    partial-absent)
      printf '%s\n' "${FAKE_EXPECTED_DIGEST}"
      printf 'Error response from registry: failed to resolve digest: %s: not found\n' "${reference}" >&2
      exit 1
      ;;
    wrong-reference-not-found)
      printf 'Error response from registry: failed to resolve digest: ghcr.io/example/other:v0.4.2: not found\n' >&2
      exit 1
      ;;
    extra-line-not-found)
      printf 'Error response from registry: failed to resolve digest: %s: not found\nwarning: synthetic extra context\n' "${reference}" >&2
      exit 1
      ;;
    extra-blank-line-not-found)
      printf 'Error response from registry: failed to resolve digest: %s: not found\n\n' "${reference}" >&2
      exit 1
      ;;
    wrong-status-not-found)
      printf 'Error response from registry: failed to resolve digest: %s: not found\n' "${reference}" >&2
      exit 17
      ;;
    manifest-unknown)
      printf 'MANIFEST_UNKNOWN: synthetic absent stable tag\n' >&2
      exit 1
      ;;
    name-unknown)
      printf 'NAME_UNKNOWN: synthetic absent repository\n' >&2
      exit 1
      ;;
    mismatch)
      printf 'sha256:%064d\n' 0
      ;;
    indeterminate)
      printf 'synthetic registry timeout\n' >&2
      exit 70
      ;;
    generic-not-found)
      printf 'repository not found after an authentication proxy timeout\n' >&2
      exit 71
      ;;
    unauthorized)
      printf 'Error response from registry: response status code 401: Unauthorized\n' >&2
      exit 1
      ;;
    server-error)
      printf 'Error response from registry: response status code 503: Service Unavailable\n' >&2
      exit 1
      ;;
    *) exit 91 ;;
  esac
  exit 0
fi
if [[ "$1" == tag ]]; then
  : > "${FAKE_DESTINATION_CREATED}"
  exit 0
fi
exit 90
"""
        )
        fake_oras.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": str(binary_dir) + os.pathsep + environment.get("PATH", ""),
                "EXPECTED_DIGEST": EXPECTED_DIGEST,
                "IMAGE": "ghcr.io/example/site",
                "GITHUB_SHA": github_sha,
                "RELEASE_TAG": "v0.4.2",
                "STABLE_TAG_VERIFY_ROOT": (root / "verify").as_posix(),
                "FAKE_EXPECTED_DIGEST": EXPECTED_DIGEST,
                "FAKE_DESTINATION_STATE": destination_state,
                "FAKE_DESTINATION_CREATED": created.as_posix(),
                "ORAS_CALL_LOG": call_log.as_posix(),
            }
        )
        result = subprocess.run(
            [bash_executable(), str(PUBLISHER)],
            cwd=str(REPO_ROOT),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        calls = []
        if call_log.exists():
            calls = call_log.read_text(encoding="utf-8").splitlines()
        return result, calls

    @unittest.skipUnless(bash_executable(), "Bash is required")
    def test_existing_expected_mapping_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(Path(temporary), "expected")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(any(call.startswith("tag ") for call in calls), calls)

    @unittest.skipUnless(bash_executable(), "Bash is required")
    def test_exact_reference_bound_not_found_allows_one_tag_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(Path(temporary), "absent")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                len([call for call in calls if call.startswith("tag ")]), 1, calls
            )

    @unittest.skipUnless(bash_executable(), "Bash is required")
    def test_not_found_lookalikes_fail_before_tag(self):
        """Partial, differently scoped, and legacy text cannot create a tag."""

        for destination_state in (
            "partial-absent",
            "wrong-reference-not-found",
            "extra-line-not-found",
            "extra-blank-line-not-found",
            "wrong-status-not-found",
            "manifest-unknown",
            "name-unknown",
            "unauthorized",
            "server-error",
        ):
            with self.subTest(destination_state=destination_state):
                with tempfile.TemporaryDirectory() as temporary:
                    result, calls = self._run_fixture(
                        Path(temporary), destination_state
                    )
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("could not prove stable tag absence", result.stderr)
                    self.assertFalse(
                        any(call.startswith("tag ") for call in calls), calls
                    )

    @unittest.skipUnless(bash_executable(), "Bash is required")
    def test_existing_mismatch_fails_before_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(Path(temporary), "mismatch")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("refusing to reassign", result.stderr)
            self.assertFalse(any(call.startswith("tag ") for call in calls), calls)

    @unittest.skipUnless(bash_executable(), "Bash is required")
    def test_indeterminate_failure_fails_before_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(Path(temporary), "indeterminate")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("could not prove stable tag absence", result.stderr)
            self.assertFalse(any(call.startswith("tag ") for call in calls), calls)

    @unittest.skipUnless(bash_executable(), "Bash is required")
    def test_generic_not_found_text_fails_before_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(Path(temporary), "generic-not-found")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("could not prove stable tag absence", result.stderr)
            self.assertFalse(any(call.startswith("tag ") for call in calls), calls)

    @unittest.skipUnless(bash_executable(), "Bash is required")
    def test_non_github_sha_width_fails_before_registry_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(
                Path(temporary), "expected", github_sha="b" * 64
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("GITHUB_SHA is malformed", result.stderr)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
