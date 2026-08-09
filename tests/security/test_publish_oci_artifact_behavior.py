"""Exercise the bounded OCI publication retry loop without a registry."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = REPO_ROOT / "scripts" / "ci" / "publish-oci-artifact.sh"
EXPECTED_DIGEST = "sha256:" + ("a" * 64)
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"


def bash_executable():
    """Find Bash on Linux CI or the ordinary Git for Windows installation."""

    discovered = shutil.which("bash")
    if discovered:
        return discovered
    if os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
        if candidate.is_file():
            return str(candidate)
    return None


class PublishOCIArtifactBehaviorTests(unittest.TestCase):
    """Model transient GHCR errors with deterministic fake ORAS commands."""

    def _run_fixture(
        self,
        root,
        source_media_type=OCI_INDEX_MEDIA_TYPE,
        roundtrip_media_type=OCI_INDEX_MEDIA_TYPE,
        roundtrip_succeeds_at=3,
    ):
        """Run the publisher against isolated ORAS and jq command doubles."""

        binary_dir = root / "bin"
        binary_dir.mkdir()
        archive = root / "site.oci.tar"
        archive.write_bytes(b"fixture\n")
        count_file = root / "oras-count"
        call_log = root / "oras-calls"

        fake_oras = binary_dir / "oras"
        fake_oras.write_bytes(
            b"""#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == resolve ]]; then
  printf '%s\\n' "${FAKE_EXPECTED_DIGEST}"
  exit 0
fi
if [[ "$1" == manifest && "$2" == fetch ]]; then
  media_type="${FAKE_SOURCE_MEDIA_TYPE}"
  if [[ " $* " == *"roundtrip"* ]]; then
    media_type="${FAKE_ROUNDTRIP_MEDIA_TYPE}"
  fi
  printf '{"mediaType":"%s"}\\n' "${media_type}"
  exit 0
fi
[[ "$1" == cp ]] || exit 90
printf '%s\\n' "$*" >> "${ORAS_CALL_LOG}"
if [[ " $* " != *" --to-oci-layout "* ]]; then
  exit 0
fi
count=0
if [[ -f "${ORAS_COUNT_FILE}" ]]; then
  read -r count < "${ORAS_COUNT_FILE}"
fi
count=$((count + 1))
printf '%d\\n' "${count}" > "${ORAS_COUNT_FILE}"
(( count >= FAKE_ROUNDTRIP_SUCCEEDS_AT ))
"""
        )
        fake_jq = binary_dir / "jq"
        fake_jq.write_bytes(
            b"""#!/usr/bin/env bash
set -euo pipefail
read -r payload
media_type="${payload#*\\"mediaType\\":\\"}"
media_type="${media_type%%\\"*}"
printf '%s\\n' "${media_type}"
"""
        )
        fake_oras.chmod(0o755)
        fake_jq.chmod(0o755)

        environment = os.environ.copy()
        environment.update(
            {
                "PATH": str(binary_dir) + os.pathsep + environment.get("PATH", ""),
                "OCI_ARCHIVE": archive.as_posix(),
                "EXPECTED_DIGEST": EXPECTED_DIGEST,
                "IMAGE": "ghcr.io/example/site",
                "GITHUB_SHA": "b" * 40,
                "FAKE_EXPECTED_DIGEST": EXPECTED_DIGEST,
                "FAKE_SOURCE_MEDIA_TYPE": source_media_type,
                "FAKE_ROUNDTRIP_MEDIA_TYPE": roundtrip_media_type,
                "FAKE_ROUNDTRIP_SUCCEEDS_AT": str(roundtrip_succeeds_at),
                "ORAS_COUNT_FILE": count_file.as_posix(),
                "ORAS_CALL_LOG": call_log.as_posix(),
                "PUBLISH_RETRY_DELAY_SECONDS": "0",
                "PUBLISH_VERIFY_ROOT": (root / "roundtrip").as_posix(),
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

    @unittest.skipUnless(bash_executable(), "Bash is required for release-helper behavior tests")
    def test_retries_until_the_complete_remote_graph_round_trips(self):
        """Two missing-child reads must retry without rebuilding or changing tags."""

        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(Path(temporary))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Published and round-trip verified", result.stdout)
            publish_calls = [call for call in calls if "--from-oci-layout" in call]
            roundtrip_calls = [call for call in calls if "--to-oci-layout" in call]
            self.assertEqual(len(publish_calls), 3)
            self.assertTrue(all("--concurrency 1" in call for call in calls), calls)
            self.assertEqual(len(set(publish_calls)), 1, publish_calls)
            self.assertEqual(len(roundtrip_calls), 3, roundtrip_calls)
            for call in roundtrip_calls:
                self.assertIn("ghcr.io/example/site@{}".format(EXPECTED_DIGEST), call)
            self.assertEqual(len(set(roundtrip_calls)), 3, roundtrip_calls)
            self.assertEqual(result.stderr.count("Retrying the same"), 2)
            self.assertEqual(result.stderr.count("complete remote OCI graph"), 2)

    @unittest.skipUnless(bash_executable(), "Bash is required for release-helper behavior tests")
    def test_rejects_non_index_source_before_publication(self):
        """A single-platform or artifact manifest is not the reviewed release graph."""

        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(
                Path(temporary),
                source_media_type="application/vnd.oci.image.manifest.v1+json",
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("not an OCI image index", result.stderr)
            self.assertEqual(calls, [])

    @unittest.skipUnless(bash_executable(), "Bash is required for release-helper behavior tests")
    def test_rejects_wrong_media_type_after_remote_round_trip(self):
        """A remote graph must retain both the digest and OCI index identity."""

        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run_fixture(
                Path(temporary),
                roundtrip_media_type="application/vnd.oci.image.manifest.v1+json",
                roundtrip_succeeds_at=1,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("media type application/vnd.oci.image.manifest", result.stderr)
            self.assertEqual(
                len([call for call in calls if "--from-oci-layout" in call]),
                4,
            )
            self.assertEqual(
                len([call for call in calls if "--to-oci-layout" in call]),
                4,
            )


if __name__ == "__main__":
    unittest.main()
