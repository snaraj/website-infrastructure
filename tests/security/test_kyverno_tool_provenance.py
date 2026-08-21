"""Hostile contracts for Kyverno installer executable provenance.

The installer may hand cluster authority only to the reviewed ``kubectl`` and
``kustomize`` bytes.  These tests drive the real shell entry point against a
minimal synthetic repository and prove that candidate metadata, held-descriptor
staging, and every later invocation remain load-bearing.  Nothing contacts a
cluster. Linux exercises the production unlinked descriptor path, Darwin proves
the private-path fallback, and native Windows keeps the portable structure and
policy assertions while WSL/Linux CI owns POSIX custody semantics.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install-kyverno-admission.sh"
BASH = shutil.which("bash")
SYSTEM_BASH = Path("/bin/bash")
LINUX = sys.platform.startswith("linux")
REQUIRES_BASH = unittest.skipUnless(BASH, "bash is required for this behavior")
REQUIRES_POSIX_PROVENANCE = unittest.skipUnless(
    BASH and os.name != "nt",
    "native Windows lacks POSIX descriptor/mode semantics; run under WSL or Linux CI",
)


KUSTOMIZE_STUB = r"""#!/bin/bash -p
set -euo pipefail
[[ -z "${BASH_ENV:-}" && -z "${ENV:-}" ]] || {
  printf '%s\n' inherited-shell-startup-hook >&2
  exit 94
}

record_invocation() {
  [[ -n "${KYVERNO_TOOL_EXEC_LOG:-}" ]] || return 0
  target="$(/usr/bin/readlink "$0" 2>/dev/null || true)"
  printf '%s|%s\n' "$0" "$target" >>"${KYVERNO_TOOL_EXEC_LOG}"
}

case "${1:-}" in
  version)
    record_invocation
    if [[ -n "${KYVERNO_TOOL_SOURCE_TO_REPLACE:-}" ]]; then
      printf '%s\n' '#!/usr/bin/env bash' 'exit 97' \
        >"${KYVERNO_TOOL_SOURCE_TO_REPLACE}"
      chmod 0755 "${KYVERNO_TOOL_SOURCE_TO_REPLACE}"
    fi
    if [[ "${KYVERNO_TAMPER_BOUND_TOOL:-no}" == yes ]]; then
      chmod u+w "$0"
      printf '%s\n' '# bound mutation' >>"$0"
    fi
    printf '%s\n' 'v5.8.1'
    ;;
  build)
    record_invocation
    printf '%s\n' 'apiVersion: v1' 'kind: ConfigMap' 'metadata:' '  name: synthetic'
    ;;
  *) exit 96 ;;
esac
"""


KUBECTL_STUB = r"""#!/bin/bash -p
set -euo pipefail
if [[ "${1:-}" == version ]]; then
  printf '%s\n' '{"clientVersion":{"gitVersion":"v1.36.3"}}'
  exit 0
fi
exit 95
"""


class KyvernoToolProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(tempfile.mkdtemp(prefix="kyverno-tool-provenance."))
        self.repo = self.scratch / "repo"
        self.bin = self.scratch / "bin"
        (self.repo / "scripts").mkdir(parents=True)
        (
            self.repo
            / "kubernetes"
            / "platform"
            / "admission-install"
            / "report-only"
        ).mkdir(parents=True)
        self.bin.mkdir()
        shutil.copy2(INSTALLER, self.repo / "scripts" / INSTALLER.name)
        self.installer = self.repo / "scripts" / INSTALLER.name
        self.installer.chmod(0o755)

        self.kustomize = self.bin / "kustomize"
        self.kubectl = self.bin / "kubectl"
        self.kustomize.write_text(KUSTOMIZE_STUB, encoding="utf-8", newline="\n")
        self.kubectl.write_text(KUBECTL_STUB, encoding="utf-8", newline="\n")
        self.kustomize.chmod(0o755)
        self.kubectl.chmod(0o755)
        self._write_versions()
        lock = (
            self.repo
            / "kubernetes"
            / "platform"
            / "admission-install"
            / "render.lock"
        )
        lock.write_text(
            "stage.report-only.authorized=yes\nrender.tool.version=v5.8.1\n",
            encoding="utf-8",
            newline="\n",
        )

    def tearDown(self):
        shutil.rmtree(self.scratch, ignore_errors=True)

    def _write_versions(self):
        (self.repo / "versions.env").write_text(
            "\n".join(
                (
                    "KUSTOMIZE_VERSION=v5.8.1",
                    "KUBERNETES_VERSION=v1.36.3",
                    "KUSTOMIZE_LINUX_AMD64_SHA256="
                    + hashlib.sha256(self.kustomize.read_bytes()).hexdigest(),
                    "KUBECTL_LINUX_AMD64_SHA256="
                    + hashlib.sha256(self.kubectl.read_bytes()).hexdigest(),
                    "",
                )
            ),
            encoding="utf-8",
            newline="\n",
        )

    def _run(self, **overrides):
        environment = dict(os.environ)
        environment["PATH"] = os.pathsep.join(
            (str(self.bin), environment.get("PATH", ""))
        )
        environment.update(overrides)
        return subprocess.run(
            [BASH, "-p", str(self.installer), "--stage", "report-only", "--render"],
            cwd=self.repo,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def _mutate_installer_once(self, old, new):
        text = self.installer.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, "mutation target must be unique")
        self.installer.write_text(
            text.replace(old, new, 1), encoding="utf-8", newline="\n"
        )
        self.installer.chmod(0o755)

    def _run_metadata_function(self, metadata, expected_owner):
        text = self.installer.read_text(encoding="utf-8")
        start = text.index("validate_tool_metadata() {")
        end = text.index("\nvalidate_bound_tool() {", start)
        production_function = text[start:end]
        script = "\n".join(
            (
                "set -euo pipefail",
                "die() { printf '%s\\n' \"$1\" >&2; exit 1; }",
                production_function,
                "validate_tool_metadata synthetic "
                + repr(metadata)
                + " "
                + repr(expected_owner),
            )
        )
        return subprocess.run(
            [BASH, "-p", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )

    @REQUIRES_POSIX_PROVENANCE
    def test_reviewed_tools_execute_from_bound_platform_custody(self):
        execution_log = self.scratch / "tool-exec.log"
        completed = self._run(KYVERNO_TOOL_EXEC_LOG=str(execution_log))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("render.tool.version=v5.8.1", completed.stdout)
        self.assertIn("report-only.objects=1", completed.stdout)
        records = execution_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(records), 3, records)
        custody_roots = set()
        for record in records:
            invoked, target = record.split("|", 1)
            custody = re.search(
                r"(?P<root>/[^ |]+/kyverno-tools\.[^/ |]+)/kustomize",
                "{} {}".format(invoked, target),
            )
            self.assertIsNotNone(custody, record)
            custody_roots.add(Path(custody.group("root")))
            if LINUX:
                self.assertRegex(invoked, r"^/proc/self/fd/[0-9]+$")
                self.assertRegex(
                    target, r"/kyverno-tools\.[^/]+/kustomize \(deleted\)$"
                )
            else:
                self.assertRegex(invoked, r"/kyverno-tools\.[^/]+/kustomize$")
                self.assertEqual(target, "")
        for custody_root in custody_roots:
            self.assertFalse(
                custody_root.exists(),
                "private tool custody directory must be removed on exit",
            )

    @REQUIRES_POSIX_PROVENANCE
    def test_symlinked_candidate_is_refused_before_execution(self):
        real = self.bin / "kustomize.real"
        self.kustomize.replace(real)
        self.kustomize.symlink_to(real.name)
        self._write_versions()
        completed = self._run()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("executable path is a symlink", completed.stderr)

    @REQUIRES_POSIX_PROVENANCE
    def test_script_candidate_requires_the_fixed_privileged_interpreter(self):
        self.kustomize.write_text(
            KUSTOMIZE_STUB.replace("#!/bin/bash -p", "#!/usr/bin/env bash", 1),
            encoding="utf-8",
            newline="\n",
        )
        self.kustomize.chmod(0o755)
        self._write_versions()
        completed = self._run()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "script interpreter is not the reviewed /bin/bash -p", completed.stderr
        )

    @REQUIRES_POSIX_PROVENANCE
    def test_hard_linked_candidate_is_refused_before_execution(self):
        os.link(self.kubectl, self.bin / "kubectl.second-name")
        completed = self._run()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("more than one hard link", completed.stderr)

    @REQUIRES_POSIX_PROVENANCE
    def test_group_writable_candidate_is_refused_before_execution(self):
        self.kustomize.chmod(0o775)
        completed = self._run()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("writable by group or other", completed.stderr)

    @REQUIRES_POSIX_PROVENANCE
    def test_source_path_replacement_after_binding_cannot_change_execution(self):
        completed = self._run(KYVERNO_TOOL_SOURCE_TO_REPLACE=str(self.kustomize))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("report-only.objects=1", completed.stdout)
        self.assertIn("exit 97", self.kustomize.read_text(encoding="utf-8"))

    @REQUIRES_POSIX_PROVENANCE
    def test_bound_descriptor_mutation_is_refused_before_next_invocation(self):
        completed = self._run(KYVERNO_TAMPER_BOUND_TOOL="yes")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("kustomize bound executable", completed.stderr)
        self.assertTrue(
            "is writable" in completed.stderr
            or "no longer matches its reviewed sha256" in completed.stderr,
            completed.stderr,
        )

    @REQUIRES_POSIX_PROVENANCE
    def test_source_metadata_guard_is_load_bearing(self):
        self._mutate_installer_once(
            '  validate_tool_metadata "$tool" "$before" "$operator_uid"',
            "  : # hostile mutation removes source metadata validation",
        )
        os.link(self.kubectl, self.bin / "kubectl.second-name")
        completed = self._run()
        self.assertEqual(
            completed.returncode,
            0,
            "without the production metadata call the hostile hard link should survive",
        )

    @REQUIRES_POSIX_PROVENANCE
    def test_per_invocation_descriptor_guard_is_load_bearing(self):
        self._mutate_installer_once(
            '  validate_bound_tool "$tool" "$fd" "$expected_digest" "$operator_uid"',
            "  : # hostile mutation removes the per-invocation descriptor guard",
        )
        completed = self._run(KYVERNO_TAMPER_BOUND_TOOL="yes")
        self.assertEqual(
            completed.returncode,
            0,
            "without the production recheck the mutated descriptor should execute",
        )

    @REQUIRES_POSIX_PROVENANCE
    def test_bash_env_cannot_replace_provenance_probes(self):
        bash_env = self.scratch / "bash-env"
        sourced = self.scratch / "bash-env-sourced"
        bash_env.write_text(
            f"printf '%s\\n' sourced >{str(sourced)!r}\n"
            "sha256sum() { printf '%s\\n' hostile-probe >&2; exit 91; }\n"
            "stat() { printf '%s\\n' hostile-probe >&2; exit 91; }\n"
            "function /usr/bin/sha256sum { printf '%s\\n' hostile-slash >&2; exit 92; }\n"
            "function /usr/bin/shasum { printf '%s\\n' hostile-slash >&2; exit 92; }\n"
            "function /usr/bin/stat { printf '%s\\n' hostile-slash >&2; exit 92; }\n",
            encoding="utf-8",
            newline="\n",
        )
        completed = self._run(BASH_ENV=str(bash_env), ENV=str(bash_env))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("hostile-probe", completed.stderr)
        self.assertNotIn("hostile-slash", completed.stderr)
        self.assertNotIn("inherited-shell-startup-hook", completed.stderr)
        self.assertFalse(sourced.exists(), "bash -p must ignore BASH_ENV before guards")

    @REQUIRES_BASH
    def test_non_privileged_bash_invocation_is_refused(self):
        environment = dict(os.environ)
        environment.pop("BASH_ENV", None)
        completed = subprocess.run(
            [BASH, str(self.installer), "--stage", "report-only", "--render"],
            cwd=self.repo,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("privileged Bash startup mode is required", completed.stderr)

    @unittest.skipUnless(
        SYSTEM_BASH.is_file(), "the fixed POSIX interpreter is unavailable"
    )
    def test_fixed_interpreter_parses_the_installer(self):
        completed = subprocess.run(
            [str(SYSTEM_BASH), "-p", "-n", str(INSTALLER)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(LINUX, "the production shebang is a Linux runtime proof")
    def test_linux_direct_entrypoint_ignores_startup_hooks(self):
        marker = self.scratch / "direct-entrypoint-startup-hook"
        bash_env = self.scratch / "direct-entrypoint-bash-env"
        bash_env.write_text(
            f"printf '%s\\n' sourced >{str(marker)!r}\n",
            encoding="utf-8",
            newline="\n",
        )
        environment = dict(os.environ)
        environment["PATH"] = os.pathsep.join(
            (str(self.bin), environment.get("PATH", ""))
        )
        environment["BASH_ENV"] = str(bash_env)
        environment["ENV"] = str(bash_env)
        completed = subprocess.run(
            [str(self.installer), "--stage", "report-only", "--render"],
            cwd=self.repo,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(marker.exists(), "the fixed shebang must select bash -p")

    @REQUIRES_POSIX_PROVENANCE
    def test_hostile_path_cannot_replace_provenance_primitives(self):
        marker = self.scratch / "hostile-helper-ran"
        for name in (
            "bash",
            "basename",
            "cut",
            "dirname",
            "grep",
            "head",
            "id",
            "install",
            "mktemp",
            "rm",
            "sed",
            "sha256sum",
            "shasum",
            "stat",
            "tr",
            "uname",
        ):
            hostile = self.bin / name
            hostile.write_text(
                "#!/bin/bash -p\n"
                f"printf '%s\\n' {name!r} >>{str(marker)!r}\n"
                "printf '%s\\n' hostile-tool >&2\n"
                "exit 91\n",
                encoding="utf-8",
                newline="\n",
            )
            hostile.chmod(0o755)
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("hostile-tool", completed.stderr)
        self.assertFalse(marker.exists(), "ambient PATH helper executed")

    @REQUIRES_BASH
    def test_metadata_guard_rejects_wrong_owner_type_link_and_mode(self):
        rejected = (
            (
                "1:2:81ed:456:456:755:1:10:11:12",
                "123",
                "owner is outside the operator/root contract",
            ),
            ("1:2:41ed:123:123:755:1:10:11:12", "123", "not a regular file"),
            ("1:2:81ed:123:123:755:2:10:11:12", "123", "more than one hard link"),
            ("1:2:81ed:123:123:775:1:10:11:12", "123", "writable by group or other"),
            ("1:2:89ed:123:123:4755:1:10:11:12", "123", "special permission bits"),
            ("1:2:81a4:123:123:644:1:10:11:12", "123", "is not executable"),
        )
        for metadata, expected_owner, diagnostic in rejected:
            with self.subTest(diagnostic=diagnostic):
                completed = self._run_metadata_function(metadata, expected_owner)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(diagnostic, completed.stderr)

        for owner, expected_owner in (("0", "123"), ("123", "123")):
            with self.subTest(accepted_owner=owner):
                completed = self._run_metadata_function(
                    f"1:2:81ed:{owner}:{owner}:755:1:10:11:12", expected_owner
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_every_tool_invocation_uses_the_bound_wrapper(self):
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertNotRegex(text, r'"\$KUSTOMIZE_BIN"')
        self.assertNotRegex(text, r'"\$KUBECTL_BIN"')
        self.assertIn(
            'run_bound_tool kustomize "$KUSTOMIZE_FD" "$KUSTOMIZE_PATH" '
            'KUSTOMIZE_LINUX_AMD64_SHA256 "$@"',
            text.replace("\\\n    ", ""),
        )
        self.assertIn(
            'run_bound_tool kubectl "$KUBECTL_FD" "$KUBECTL_PATH" '
            'KUBECTL_LINUX_AMD64_SHA256 "$@"',
            text.replace("\\\n    ", ""),
        )
        self.assertEqual(
            re.findall(r'"\$path" "\$@"', text),
            ['"$path" "$@"'],
        )

    def test_fixed_bootstrap_and_closed_helper_path_are_explicit(self):
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/bash -p\n"))
        self.assertIn("unset BASH_ENV ENV", text)
        self.assertIn("TOOL_SEARCH_PATH=", text)
        self.assertIn("PATH='/usr/bin:/bin'", text)


if __name__ == "__main__":
    unittest.main()
