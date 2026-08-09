"""Keep Pi discovery bounded, source-minimized, and explicit when incomplete."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISCOVERY = ROOT / "scripts" / "discover-pi.sh"


def function_body(script, name):
    marker = f"{name}() {{"
    return script.split(marker, 1)[1].split("\n}", 1)[0]


class DiscoverPiPrivacyContractTests(unittest.TestCase):
    """Prove shareable output omits topology and reports evidence quality."""

    @classmethod
    def setUpClass(cls):
        cls.script = DISCOVERY.read_text(encoding="utf-8")

    def test_nft_structure_emits_only_counts_and_digest(self):
        body = function_body(self.script, "nft_structure")
        for field in (
            "table_count=%s",
            "chain_count=%s",
            "hook_count=%s",
            "byte_count=%s",
            "sha256=%s",
        ):
            with self.subTest(field=field):
                self.assertIn(field, body)
        self.assertIn("capture_private_output sudo -n nft list ruleset", body)
        self.assertIn('>"${private_probe_file}"', function_body(self.script, "capture_private_output"))
        self.assertNotIn("${ruleset}", body)
        self.assertNotRegex(body, r"printf[^\n]*(?:table|chain)[^\n]*name")

    def test_sensitive_topology_is_counted_or_hashed_not_printed(self):
        required = (
            "block topology count and fingerprint",
            "mount identity fingerprint",
            "containerd configuration fingerprint",
            "interface inventory fingerprint",
            "IPv4 address inventory fingerprint",
            "IPv4 route inventory fingerprint",
            "IPv4 policy-rule inventory fingerprint",
            "TCP/UDP listener inventory fingerprint",
            "local CRI socket inventory fingerprint",
            "fingerprint_stdout ss -lntu",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.script)

        forbidden = (
            "capture 'redacted routes' ip",
            "capture 'redacted policy rules' ip",
            "capture 'redacted IPv4 addresses' ip",
            "capture 'interface names",
            "capture 'local CRI sockets' sh",
            "safe-selected containerd config",
            "findmnt -T \"${target}\" -o TARGET,SOURCE",
            "df -hT",
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, self.script)

        self.assertIn("df -B1 --output=size,used,avail,pcent", self.script)
        self.assertIn("mount_type_summary", self.script)

    def test_short_volume_ids_and_bip38_shapes_have_final_redaction(self):
        body = function_body(self.script, "sanitize_stream")
        self.assertIn("PARTUUID=?)[0-9A-Fa-f]{8}-[0-9]{2}", body)
        self.assertIn("[[:xdigit:]]{4}-[[:xdigit:]]{4}", body)
        self.assertIn("6P[1-9A-HJ-NP-Za-km-z]{56}", body)
        self.assertIn("[REDACTED_UUID]", body)
        self.assertIn("[REDACTED_PRIVATE_KEY]", body)

    def test_every_probe_is_bounded_and_incompleteness_is_machine_readable(self):
        self.assertIn('timeout --signal=TERM --kill-after=2s', self.script)
        self.assertIn("readonly probe_timeout_seconds=15", self.script)
        self.assertIn("readonly max_private_probe_bytes=", self.script)
        self.assertIn('head -c "$((max_private_probe_bytes + 1))"', self.script)
        self.assertIn("probe_failure_count", self.script)
        self.assertIn("probe_unknown_count", self.script)
        self.assertIn("discovery_completeness=COMPLETE", self.script)
        self.assertIn("discovery_completeness=INCOMPLETE", self.script)
        self.assertIn("discovery_exit_code=3", self.script)
        self.assertRegex(self.script, r"(?m)^exit 3$")

    def test_optional_empty_results_never_mask_probe_failures(self):
        """No-match is safe only when the bounded producer itself succeeded."""

        helper = function_body(self.script, "filter_allow_empty")
        for fragment in (
            'run_bounded "$@"',
            'pipeline_status=("${PIPESTATUS[@]}")',
            'producer_status="${pipeline_status[0]:-1}"',
            'filter_status="${pipeline_status[1]:-1}"',
            "filter_status != 0 && filter_status != 1",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, helper)

        for required in (
            "capture 'cgroup controllers' cat /sys/fs/cgroup/cgroup.controllers",
            "capture 'installed platform packages' filter_allow_empty",
            "wg show interfaces",
            "filter_allow_empty 'containerd|crio|cri-dockerd' ss -lx",
            "capture 'IPv4 iptables implementation' iptables --version",
            "capture 'IPv6 iptables implementation' ip6tables --version",
            "capture 'nftables implementation' nft --version",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.script)

        for masked in (
            "cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true",
            'dpkg-query -W 2>/dev/null | grep -E',
            "wg show interfaces || true",
            'ss -lx | grep -E "containerd|crio|cri-dockerd" || true',
            "iptables --version 2>/dev/null || true",
            "ip6tables --version 2>/dev/null || true",
            "nft --version 2>/dev/null || true",
        ):
            with self.subTest(masked=masked):
                self.assertNotIn(masked, self.script)

    @unittest.skipUnless(os.name == "posix", "bounded filter execution is a Linux test")
    def test_optional_empty_filter_distinguishes_absence_from_failure(self):
        """The helper returns success for no match, but not producer failure."""

        bash = shutil.which("bash")
        if bash is None or shutil.which("timeout") is None:
            self.skipTest("bash and GNU timeout are required")
        harness = (
            "set -euo pipefail\n"
            "probe_timeout_seconds=2\n"
            "run_bounded() {"
            + function_body(self.script, "run_bounded")
            + "\n}\nfilter_allow_empty() {"
            + function_body(self.script, "filter_allow_empty")
            + '\n}\nfilter_allow_empty "$@"\n'
        )

        def invoke(*arguments):
            return subprocess.run(
                [bash, "-c", harness, "probe", *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

        no_match = invoke("^wanted$", "sh", "-c", "printf 'other\\n'")
        self.assertEqual(no_match.returncode, 0, no_match.stderr)
        self.assertEqual(no_match.stdout, "")

        matched = invoke("^wanted$", "sh", "-c", "printf 'wanted\\n'")
        self.assertEqual(matched.returncode, 0, matched.stderr)
        self.assertEqual(matched.stdout, "wanted\n")

        failed = invoke("^wanted$", "sh", "-c", "exit 9")
        self.assertEqual(failed.returncode, 1, failed.stderr)

        unavailable = invoke("^wanted$", "definitely-not-a-probe-command")
        self.assertEqual(unavailable.returncode, 4, unavailable.stderr)

    def test_trim_state_uses_structured_systemctl_show(self):
        self.assertIn("capture 'TRIM timer state' systemctl show", self.script)
        for field in ("LoadState", "ActiveState", "UnitFileState"):
            self.assertIn(f"--property={field}", self.script)
        self.assertNotIn("systemctl is-enabled fstrim.timer", self.script)

    def test_known_egress_programs_exist_only_inside_explicit_gate(self):
        body = function_body(self.script, "run_external_egress_probes")
        outside = self.script.replace(
            "run_external_egress_probes() {" + body + "\n}", ""
        )
        executable_outside = "\n".join(
            line for line in outside.splitlines() if not line.lstrip().startswith("#")
        )
        patterns = {
            "curl": r"\bcurl(?=\s)",
            "wget": r"\bwget(?=\s)",
            "nc": r"\bnc(?=\s|$)",
            "getent ahosts": r"\bgetent\s+ahosts\b",
            "apt": r"(?<![A-Za-z0-9_-])apt(?=\s)",
            "apt-get": r"(?<![A-Za-z0-9_-])apt-get(?=\s)",
        }
        for name, pattern in patterns.items():
            with self.subTest(program=name):
                self.assertIsNone(re.search(pattern, executable_outside))

        for expected in ("curl --fail", "getent ahosts", "nc -vz"):
            self.assertIn(expected, body)

    @unittest.skipUnless(os.name == "posix", "hermetic command PATH is a Linux test")
    def test_local_only_run_cannot_reach_egress_wrappers(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is unavailable")

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            sentinel = Path(directory) / "egress-called"
            probe_file = Path(directory) / "probe.raw"
            missing_contract = Path(directory) / "missing-contract"
            dispatcher = fake_bin / "dispatcher"
            dispatcher.write_text(
                """#!/bin/bash
name=${0##*/}
case \"${name}\" in
  curl|wget|nc|getent|apt|apt-get)
    printf '%s\\n' \"${name}\" >>\"${EGRESS_SENTINEL}\"
    exit 97
    ;;
  dirname)
    printf '%s\\n' \"${1%/*}\"
    ;;
  uname)
    if [[ \"${1:-}\" == -s ]]; then printf 'Linux\\n'; else printf 'stub\\n'; fi
    ;;
  date)
    printf '2026-08-09T00:00:00Z\\n'
    ;;
  mktemp)
    : >\"${FAKE_PROBE_FILE}\"
    printf '%s\\n' \"${FAKE_PROBE_FILE}\"
    ;;
  python3|sed)
    while IFS= read -r line || [[ -n \"${line}\" ]]; do printf '%s\\n' \"${line}\"; done
    ;;
  timeout)
    while (($#)); do
      case \"$1\" in
        --signal=*|--kill-after=*|[0-9]*s) shift ;;
        *) break ;;
      esac
    done
    \"$@\"
    ;;
  chmod|grep|rm|sha256sum|wc)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
""",
                encoding="utf-8",
            )
            dispatcher.chmod(0o700)
            for name in (
                "apt",
                "apt-get",
                "chmod",
                "curl",
                "date",
                "dirname",
                "getent",
                "grep",
                "head",
                "mktemp",
                "nc",
                "python3",
                "rm",
                "sed",
                "sha256sum",
                "timeout",
                "uname",
                "wc",
                "wget",
            ):
                (fake_bin / name).symlink_to(dispatcher)

            environment = os.environ.copy()
            environment.update(
                {
                    "EGRESS_SENTINEL": str(sentinel),
                    "FAKE_PROBE_FILE": str(probe_file),
                    "PATH": str(fake_bin),
                    "PROTECTED_SERVICES_PATH": str(missing_contract),
                }
            )
            completed = subprocess.run(
                [bash, str(DISCOVERY), "--local-only"],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
                env=environment,
            )
            self.assertEqual(completed.returncode, 3, completed.stderr)
            self.assertFalse(sentinel.exists(), sentinel.read_text() if sentinel.exists() else "")
            self.assertIn("external_egress_probes=SKIPPED_LOCAL_ONLY", completed.stdout)
            self.assertIn("discovery_completeness=INCOMPLETE", completed.stdout)


if __name__ == "__main__":
    unittest.main()
