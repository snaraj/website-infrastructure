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
    #: The one keyless identity this verifier trusts: that site's own
    #: release-publisher workflow run at its protected `main` branch. A run at
    #: a ref executes the workflow definition AT that ref, and `main` is the
    #: only ref those repositories gate on creation and update with no bypass
    #: actors, whereas tag creation there is unrestricted
    #: (ADR 0016 amendment 2026-08-22).
    TRUSTED_IDENTITY = (
        "https://github.com/snaraj/naranjo.online/.github/"
        "workflows/release-publisher.yml@refs/heads/main"
    )

    def run_fixture(
        self,
        *,
        sha_digest=DIGEST,
        version_digest=DIGEST,
        fail_version=False,
        workflow_identity=None,
    ):
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
                        self.TRUSTED_IDENTITY
                        if workflow_identity is None
                        else workflow_identity
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

    def test_identities_outside_the_trust_boundary_fail_closed(self):
        # The trust-boundary regex had no negative coverage before the
        # 2026-08-22 identity re-point, so re-pointing it could have widened
        # it invisibly. Every row below must be refused BEFORE any registry
        # call, and the empty cosign log is what proves the refusal came from
        # the guard rather than from a signature check that never ran.
        rejected = {
            # The ref family this verifier stopped trusting. Tag creation in
            # the site repositories carries no ruleset rule, so a tag ref is
            # not evidence that the publisher definition passed any gate.
            "version tag ref": (
                "https://github.com/snaraj/naranjo.online/.github/"
                "workflows/release-publisher.yml@refs/tags/v0.1.0"
            ),
            "legacy tag glob": (
                "https://github.com/snaraj/naranjo.online/.github/"
                "workflows/release-publisher.yml@refs/tags/v*"
            ),
            # Widening the trusted ref to its family, in both the glob and the
            # unanchored-suffix forms a careless edit would produce.
            "branch ref family widened": (
                "https://github.com/snaraj/naranjo.online/.github/"
                "workflows/release-publisher.yml@refs/heads/*"
            ),
            "another branch head": (
                "https://github.com/snaraj/naranjo.online/.github/"
                "workflows/release-publisher.yml@refs/heads/release"
            ),
            "trusted ref with a suffix": (
                "https://github.com/snaraj/naranjo.online/.github/"
                "workflows/release-publisher.yml@refs/heads/main-attacker"
            ),
            # The rest of the tuple must stay just as closed as the ref.
            "third-party repository": (
                "https://github.com/attacker/naranjo.online/.github/"
                "workflows/release-publisher.yml@refs/heads/main"
            ),
            "another workflow file": (
                "https://github.com/snaraj/naranjo.online/.github/"
                "workflows/nightly.yml@refs/heads/main"
            ),
            "look-alike host": (
                "https://github.com.attacker.invalid/snaraj/naranjo.online/"
                ".github/workflows/release-publisher.yml@refs/heads/main"
            ),
        }
        for label, identity in rejected.items():
            with self.subTest(identity=label):
                result, cosign_call = self.run_fixture(workflow_identity=identity)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(
                    "outside the protected-main publisher trust boundary",
                    result.stderr,
                )
                self.assertEqual(cosign_call, "")

    def test_the_trusted_identity_is_the_committed_one(self):
        # Binds this battery to the script itself: if the guard's literal ever
        # moves again, the accepting fixture above must move with it instead
        # of silently testing an identity the script no longer trusts.
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(r"release-publisher\.yml@refs/heads/main$", script)
        self.assertNotIn("@refs/tags/", script)


if __name__ == "__main__":
    unittest.main()
