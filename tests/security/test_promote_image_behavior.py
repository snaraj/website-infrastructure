"""Run the promotion wrapper with local deterministic registry doubles."""

import os
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + ("a" * 64)
REVISION = "b" * 40
NARANJO_VERSION = (
    REPO_ROOT / "websites" / "naranjo.online" / "VERSION"
).read_text(encoding="utf-8").strip()
NARANJO_TAG = "v" + NARANJO_VERSION


def pinned_version(name):
    for line in (REPO_ROOT / "versions.env").read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1]
    raise AssertionError("missing pinned version: " + name)


def bash_path():
    candidates = (
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def bash_executable_path(path):
    """Translate a Windows executable path for Git Bash."""

    value = str(path)
    if len(value) >= 3 and value[1:3] == ":\\":
        return "/{}/{}".format(value[0].lower(), value[3:].replace("\\", "/"))
    return value


class PromotionBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = bash_path()
        if cls.bash is None:
            raise unittest.SkipTest("Bash is unavailable")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        shutil.copytree(
            REPO_ROOT,
            self.root,
            ignore=shutil.ignore_patterns(
                ".git",
                ".artifacts",
                ".cache",
                "__pycache__",
                "*.pyc",
                "node_modules",
                "dist",
                "coverage",
            ),
        )
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "operator@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Synthetic Operator"],
            cwd=self.root,
            check=True,
        )
        # A disposable fixture must not leave detached Git maintenance running
        # after the command under test exits. Disable both the current
        # maintenance runner and legacy auto-gc so TemporaryDirectory cleanup
        # cannot race a process that is still writing beneath .git.
        subprocess.run(
            ["git", "config", "maintenance.auto", "false"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "gc.auto", "0"], cwd=self.root, check=True
        )
        subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "switch", "-q", "-c", "promotion-test"],
            cwd=self.root,
            check=True,
        )

        self.fake_bin = Path(self.temporary.name) / "fake-bin"
        self.fake_bin.mkdir()
        self.counter = Path(self.temporary.name) / "oras-count"
        self._write_executable(
            "python3",
            '#!/usr/bin/env bash\nexec "{}" "$@"\n'.format(
                bash_executable_path(sys.executable).replace('"', '\\"')
            ),
        )
        self._write_executable(
            "cosign",
            "#!/usr/bin/env bash\n"
            "if [[ ${1:-} == version ]]; then printf 'GitVersion: "
            + pinned_version("COSIGN_VERSION")
            + "\\n'; fi\n"
            "exit 0\n",
        )
        self._write_jq()
        self._write_executable("helm", "#!/usr/bin/env bash\nexit 0\n")

    def tearDown(self):
        self.temporary.cleanup()

    def _write_executable(self, name, text):
        path = self.fake_bin / name
        path.write_bytes(text.encode("utf-8"))
        path.chmod(0o755)

    def _write_jq(self, fail_after_labels=False):
        self._write_executable(
            "jq",
            "#!/usr/bin/env bash\n"
            "case \" $* \" in\n"
            "  *' -er '*) printf 'https://github.com/snaraj/website-infrastructure\\t{}\\t{}\\n'; {} ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n".format(
                NARANJO_VERSION,
                REVISION,
                "exit 41" if fail_after_labels else "exit 0",
            ),
        )

    def _write_oras(
        self, fail_resolve=0, tamper_patch_resolve=0, fail_after_output_resolve=0
    ):
        script = (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ ${1:-} == version ]]; then printf 'Version: "
            + pinned_version("ORAS_VERSION").lstrip("v") + "\\n'; exit 0; fi\n"
            "if [[ ${1:-} == resolve ]]; then\n"
            "  count=0; [[ ! -f \"$FAKE_ORAS_COUNT\" ]] || count=$(<\"$FAKE_ORAS_COUNT\")\n"
            "  count=$((count + 1)); printf '%s\\n' \"$count\" >\"$FAKE_ORAS_COUNT\"\n"
            "  if [[ " + str(tamper_patch_resolve) + " -ne 0 && $count -eq "
            + str(tamper_patch_resolve) + " ]]; then\n"
            "    patch=(.artifacts/promotion.naranjo-online.*/promotion.patch)\n"
            "    [[ ${#patch[@]} -eq 1 && -f ${patch[0]} ]] || exit 43\n"
            "    sed -i 's/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/' \"${patch[0]}\"\n"
            "  fi\n"
            "  if [[ " + str(fail_resolve) + " -ne 0 && $count -eq "
            + str(fail_resolve) + " ]]; then exit 41; fi\n"
            "  printf '" + DIGEST + "\\n'\n"
            "  if [[ " + str(fail_after_output_resolve) + " -ne 0 && $count -eq "
            + str(fail_after_output_resolve) + " ]]; then exit 41; fi\n"
            "  exit 0\n"
            "fi\n"
            "if [[ ${1:-} == manifest && ${2:-} == fetch-config ]]; then\n"
            "  printf '{\"config\":{\"Labels\":{}}}\\n'; exit 0\n"
            "fi\n"
            "if [[ ${1:-} == manifest && ${2:-} == fetch ]]; then\n"
            "  printf '{\"manifests\":[{\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\"}},{\"platform\":{\"os\":\"linux\",\"architecture\":\"arm64\"}}]}\\n'; exit 0\n"
            "fi\n"
            "exit 42\n"
        )
        self._write_executable("oras", script)

    def _run(self):
        environment = os.environ.copy()
        environment["PATH"] = str(self.fake_bin) + os.pathsep + environment.get("PATH", "")
        environment["FAKE_ORAS_COUNT"] = bash_executable_path(self.counter)
        return subprocess.run(
            [
                self.bash,
                "scripts/promote-image.sh",
                "naranjo-online",
                NARANJO_TAG,
                DIGEST,
            ],
            cwd=self.root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_success_retains_review_patch_and_never_changes_worktree(self):
        self._write_oras()
        release = self.root / "kubernetes/websites/naranjo-online/release.yaml"
        original = release.read_bytes()
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(release.read_bytes(), original)
        self.assertEqual(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.root,
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout,
            "",
        )
        transactions = list((self.root / ".artifacts").glob("promotion.naranjo-online.*"))
        self.assertEqual(len(transactions), 1)
        transaction = transactions[0]
        patch = transaction / "promotion.patch"
        evidence = transaction / "evidence.env"
        self.assertTrue(patch.is_file())
        self.assertTrue(evidence.is_file())
        evidence_values = dict(
            line.split("=", 1)
            for line in evidence.read_text(encoding="utf-8").splitlines()
        )
        file_hash = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(evidence_values["PATCH_SHA256"], file_hash(patch))
        self.assertEqual(
            evidence_values["ORIGINAL_RELEASE_SHA256"],
            file_hash(transaction / "original.release.yaml"),
        )
        self.assertEqual(
            evidence_values["ORIGINAL_RELEASE_SHA256"], file_hash(release)
        )
        self.assertEqual(
            evidence_values["CANDIDATE_RELEASE_SHA256"],
            file_hash(
                transaction
                / "root/kubernetes/websites/naranjo-online/release.yaml"
            ),
        )
        reviewed_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        self.assertEqual(evidence_values["REVIEWED_HEAD"], reviewed_head)
        if os.name != "nt":
            self.assertEqual(transaction.stat().st_mode & 0o777, 0o700)
            self.assertEqual(patch.stat().st_mode & 0o777, 0o600)
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
        subprocess.run(
            ["git", "apply", "--check", "--", str(patch)],
            cwd=self.root,
            check=True,
        )

    def test_late_registry_failure_cleans_artifacts_without_worktree_change(self):
        self._write_oras(fail_resolve=4)
        release = self.root / "kubernetes/websites/naranjo-online/release.yaml"
        original = release.read_bytes()
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(release.read_bytes(), original)
        artifact_root = self.root / ".artifacts"
        self.assertEqual(list(artifact_root.glob("promotion.naranjo-online.*")), [])
        self.assertEqual(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.root,
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout,
            "",
        )

    def test_late_patch_tampering_fails_and_cleans_without_worktree_change(self):
        self._write_oras(tamper_patch_resolve=4)
        release = self.root / "kubernetes/websites/naranjo-online/release.yaml"
        original = release.read_bytes()
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("review patch changed", result.stderr)
        self.assertEqual(release.read_bytes(), original)
        self.assertEqual(
            list((self.root / ".artifacts").glob("promotion.naranjo-online.*")),
            [],
        )
        self.assertEqual(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.root,
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout,
            "",
        )

    def test_jq_partial_output_failure_is_not_accepted(self):
        self._write_jq(fail_after_labels=True)
        self._write_oras()
        release = self.root / "kubernetes/websites/naranjo-online/release.yaml"
        original = release.read_bytes()
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("image labels could not be read exactly", result.stderr)
        self.assertEqual(release.read_bytes(), original)
        artifact_root = self.root / ".artifacts"
        self.assertEqual(list(artifact_root.glob("promotion.naranjo-online.*")), [])
        self.assertEqual(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.root,
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout,
            "",
        )

    def test_oras_partial_output_failure_is_not_accepted(self):
        self._write_oras(fail_after_output_resolve=4)
        release = self.root / "kubernetes/websites/naranjo-online/release.yaml"
        original = release.read_bytes()
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("could not be resolved during local validation", result.stderr)
        self.assertEqual(release.read_bytes(), original)
        self.assertEqual(
            list((self.root / ".artifacts").glob("promotion.naranjo-online.*")),
            [],
        )

if __name__ == "__main__":
    unittest.main()
