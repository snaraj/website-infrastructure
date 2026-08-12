#!/usr/bin/env python3
"""Regression battery for the token-free edge acceptance probe.

``scripts/edge-probe.sh`` measures a live public edge, so most of it cannot run
in CI. What CAN run here, and does, is everything that made the 2026-08-12
attestation's probes wrong before they were fixed: the transcript parsers and
the capability gate. Those are the parts where a plausible-looking change turns
a real observation into a false verdict, silently.

Two classes of test live here, kept apart on purpose:

* ``EdgeProbeParserTests`` and ``EdgeProbeCapabilityGateTests`` are
  **behavioural**. They source the script (it defines its parsers and returns
  when sourced) and run the real functions against the real captures under
  ``fixtures_edge_probe/`` — see that directory's PROVENANCE.md for how each
  capture was taken and exactly which bytes were edited. Every assertion here
  fails if the corresponding defect is reintroduced.
* ``EdgeProbeSourceContractTests`` are **source-level pins**, and are labelled
  as such because the behaviour they protect is only observable against a live
  network from a specific host. A pin is weaker evidence than an execution: it
  proves the rule is still written down, not that it still holds. They are here
  because the alternative for these particular rules is nothing at all.

The two defects the behavioural tests exist for are mirror images:

1. **False FAIL** (attestation §9.2): a successful TLS 1.3 handshake prints no
   ``SSL-Session:`` block, so a parser keyed on the indented ``Protocol  :``
   line inside it reported HANDSHAKE-FAILED for a handshake that succeeded.
2. **False PASS** (captured 2026-08-12 while building this battery): OpenSSL
   prints an unindented ``Protocol: TLSv1`` line even for a handshake it just
   *failed*, next to ``New, (NONE), Cipher is (NONE)``. A parser keyed on that
   line reports a server that correctly refused TLS 1.0 as accepting it — which
   would make the post-remediation ``--enforce`` run pass while the edge was
   still broken, or fail while it was fixed.
"""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "edge-probe.sh"
FIXTURES = Path(__file__).resolve().parent / "fixtures_edge_probe"
BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required to exercise the shell parsers"


def call_parser(function, fixture_name=None, text=None):
    """Run one of the script's parser functions against real captured input.

    The script is sourced, not executed: it defines its parsers and returns
    without probing anything, which is exactly the seam this battery needs.
    """

    source = FIXTURES / fixture_name if fixture_name else None
    program = ". '{}'\n{}\n".format(SCRIPT, function)
    completed = subprocess.run(
        [required_tool(BASH, BASH_REQUIRED), "-c", program],
        input=source.read_text(encoding="utf-8") if source else (text or ""),
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    if completed.returncode != 0:
        raise AssertionError(
            "parser {} failed: {}".format(function, completed.stderr)
        )
    return completed.stdout.strip()


@unittest.skipUnless(BASH, "bash is unavailable")
class EdgeProbeParserTests(unittest.TestCase):
    """Behavioural: the real parsers against the real captures."""

    def test_successful_tls13_without_session_block_is_accepted(self):
        # The §9.2 false negative. This capture has no SSL-Session: block at
        # all; a parser that needs one calls a good handshake a failure.
        self.assertNotIn(
            "SSL-Session:",
            (FIXTURES / "tls13-remote-success.txt").read_text(encoding="utf-8"),
            "the fixture must keep the property that made the old parser wrong",
        )
        self.assertEqual(
            call_parser("classify_tls_transcript", "tls13-remote-success.txt"),
            "accepted TLSv1.3",
        )

    def test_refused_handshake_is_refused_despite_its_protocol_lines(self):
        # The mirror-image false positive. This capture carries BOTH an
        # unindented `Protocol: TLSv1` and an indented `    Protocol  : TLSv1`
        # inside an SSL-Session: block, for a handshake the server refused.
        capture = (FIXTURES / "tls10-refused-by-server.txt").read_text(encoding="utf-8")
        self.assertIn("\nProtocol: TLSv1\n", capture)
        self.assertIn("\n    Protocol  : TLSv1\n", capture)
        self.assertEqual(
            call_parser("classify_tls_transcript", "tls10-refused-by-server.txt"),
            "refused",
            "a Protocol line is printed for failed handshakes too; only the "
            "New, TLSv line proves a handshake completed",
        )

    def test_client_limitation_is_never_a_server_verdict(self):
        self.assertEqual(
            call_parser("classify_tls_transcript", "client-cannot-attempt.txt"),
            "client-limited",
        )

    def test_transport_failure_is_an_error_not_a_refusal(self):
        self.assertEqual(
            call_parser(
                "classify_tls_transcript",
                text="CONNECTED(00000003)\nconnect:errno=61\n",
            ),
            "error transport",
            "a host that could not be reached says nothing about its TLS floor",
        )

    def test_early_data_zero_is_off(self):
        self.assertEqual(
            call_parser("early_data_verdict", "early-data-zero.txt"), "off"
        )

    def test_truncated_early_data_probe_is_not_off(self):
        # `echo |` closes stdin before the post-handshake tickets arrive. The
        # absence of a ticket is a probe defect, not evidence that 0-RTT is off.
        self.assertEqual(
            call_parser("early_data_verdict", "early-data-truncated-probe.txt"),
            "no-ticket",
        )

    def test_nonzero_early_data_budget_is_on(self):
        self.assertEqual(
            call_parser(
                "early_data_verdict",
                text="Post-Handshake New Session Ticket arrived:\n"
                "    Max Early Data: 16384\n",
            ),
            "on",
        )

    def test_signed_zone_nodata_counts_as_absence(self):
        # A DNSSEC-signed Cloudflare zone never returns NXDOMAIN; it answers
        # NOERROR/NODATA for every nonexistent name (compact denial of
        # existence). Rejecting that shape would fail the signed zone only.
        self.assertEqual(
            call_parser("dns_absence_verdict", "dig-www-signed-zone-nodata.txt"),
            "absent-nodata",
        )

    def test_unsigned_zone_nxdomain_counts_as_absence(self):
        self.assertEqual(
            call_parser("dns_absence_verdict", "dig-www-unsigned-zone-nxdomain.txt"),
            "absent-nxdomain",
        )

    def test_existing_name_is_not_absence(self):
        # Without this the absence check would be vacuous: a parser that
        # answered "absent" unconditionally would pass the two tests above.
        self.assertEqual(
            call_parser("dns_absence_verdict", "dig-name-present.txt"),
            "present 2",
        )

    def test_ad_flag_detection_is_not_vacuous(self):
        self.assertEqual(
            call_parser("dnssec_ad_verdict", "dig-www-signed-zone-nodata.txt"), "ad"
        )
        self.assertEqual(
            call_parser(
                "dnssec_ad_verdict", "dig-www-unsigned-zone-nxdomain.txt"
            ),
            "no-ad",
        )

    def test_hsts_must_match_the_target_exactly(self):
        self.assertEqual(
            call_parser(
                "hsts_verdict",
                text="strict-transport-security: max-age=31536000\n",
            ),
            "exact",
        )
        self.assertEqual(
            call_parser(
                "hsts_verdict",
                text="strict-transport-security: max-age=31536000; includeSubDomains\n",
            ),
            "extra max-age=31536000; includeSubDomains",
            "includeSubDomains and preload are deliberately not the target "
            "state in this phase, so they are not silently accepted",
        )
        self.assertEqual(
            call_parser(
                "hsts_verdict", text="strict-transport-security: max-age=300\n"
            ),
            "wrong max-age=300",
        )
        self.assertEqual(call_parser("hsts_verdict", text=""), "absent")


@unittest.skipUnless(BASH, "bash is unavailable")
class EdgeProbeCapabilityGateTests(unittest.TestCase):
    """Behavioural: an unproven client never produces a server verdict."""

    def _probe_tls_version(self, capability):
        records = Path(os.environ.get("TMPDIR", "/tmp")) / "edge-probe-records.tsv"
        program = (
            ". '{script}'\n"
            "RECORDS='{records}'\n"
            ": >\"$RECORDS\"\n"
            "PREFLIGHT_TLS1={capability}\n"
            # A hostname in the reserved .invalid TLD: if the capability gate
            # were removed this call would attempt a connection and could not
            # succeed, so the test can never silently pass over a live network.
            "probe_tls_version 1 probe.invalid tls10-refused tls1 refused\n"
            "cat \"$RECORDS\"\n"
            "rm -f \"$RECORDS\"\n"
        ).format(script=SCRIPT, records=records, capability=capability)
        completed = subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), "-c", program],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip().split("\t")

    def test_unproven_client_records_skip_not_a_verdict(self):
        fields = self._probe_tls_version("incapable")
        self.assertEqual(fields[4], "SKIP")
        self.assertIn("client=incapable", fields[5])
        self.assertNotIn(fields[4], {"PASS", "GAP"})

    def test_unprovable_client_state_also_records_skip(self):
        fields = self._probe_tls_version("unproven")
        self.assertEqual(fields[4], "SKIP")


@unittest.skipUnless(BASH, "bash is unavailable")
class EdgeProbeCommandLineTests(unittest.TestCase):
    """Behavioural: the command surface, without touching the network."""

    def _run(self, *argv):
        return subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), str(SCRIPT), *argv],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

    def test_help_describes_the_report_only_default(self):
        completed = self._run("--help")
        self.assertEqual(completed.returncode, 0)
        self.assertIn("--enforce", completed.stdout)
        self.assertIn("report-only", completed.stdout)

    def test_unknown_argument_is_a_usage_error(self):
        completed = self._run("--probe-everything")
        self.assertEqual(completed.returncode, 2)

    def test_only_the_two_site_hostnames_are_accepted(self):
        self.assertEqual(self._run("--zone", "example.com").returncode, 2)
        self.assertEqual(self._run("--rounds", "9").returncode, 2)
        self.assertEqual(self._run("--timeout", "1").returncode, 2)


class EdgeProbeSourceContractTests(unittest.TestCase):
    """Source-level pins.

    Labelled honestly: these assert that a rule is still written into the
    script, not that the rule still holds against a live edge. They cover the
    attestation lessons whose behaviour cannot be reproduced in CI, where the
    alternative is no check at all.
    """

    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_no_dependency_on_the_timeout_command(self):
        # timeout(1)/gtimeout(1) do not exist on the operator host; a probe
        # that depends on them cannot run at all (attestation §10).
        for command in ("timeout ", "gtimeout "):
            self.assertNotIn(
                "\n  " + command,
                self.source,
                "bounding must use curl --max-time and the script's own watchdog",
            )

    def test_every_curl_invocation_is_time_bounded(self):
        invocations = [
            line for line in self.source.splitlines() if '"${CURL}" --' in line
        ]
        self.assertGreaterEqual(
            len(invocations), 4, "the curl invocations must remain findable"
        )
        for line in invocations:
            with self.subTest(line=line.strip()):
                self.assertIn("--max-time", line)

    def test_grep_is_resolved_absolutely(self):
        # An interactive shell shimming grep to ugrep eats dash-leading
        # patterns and returns empty output silently (attestation §10).
        self.assertIn("/usr/bin/grep", self.source)
        self.assertNotIn("| grep ", self.source)
        self.assertNotIn("$(grep ", self.source)

    def test_session_ticket_probe_keeps_the_connection_open(self):
        # `echo |` closes stdin before the ticket arrives (attestation §9).
        self.assertIn("-ign_eof", self.source)
        self.assertIn("HEAD / HTTP/1.1", self.source)

    def test_legacy_tls_probes_lower_the_client_security_level(self):
        # OpenSSL 3.x refuses sub-1.2 protocols client-side by default, which
        # reads exactly like a server refusing them (attestation §10).
        self.assertIn("ALL:@SECLEVEL=0", self.source)

    def test_distinctness_never_uses_a_body_hash_or_the_shared_heading(self):
        # Cloudflare injects a per-request ray ID into every HTML response, so
        # the body hash differs between identical rounds; the <h1> is identical
        # on both sites, so an assertion on it is vacuous (attestation §7.1).
        # (TLS ciphersuite names contain SHA256, so the pin names the hashing
        # commands rather than the substring.)
        code = "\n".join(
            line
            for line in self.source.splitlines()
            if not line.lstrip().startswith("#")
        )
        for hasher in ("sha256sum", "shasum", "md5", "openssl dgst", "cksum"):
            self.assertNotIn(hasher, code)
        self.assertNotIn("<h1", code, "the shared heading is not a marker")
        self.assertIn("<title>", code)
        self.assertIn("/assets/index-", code)

    def test_no_address_literal_targets_a_resolver(self):
        # Resolvers are addressed by name so the repository privacy gate keeps
        # holding over this file; the check here is that nobody reverts it.
        self.assertIn("one.one.one.one", self.source)
        self.assertIn("dns.google", self.source)

    def test_the_probe_takes_no_credential(self):
        for forbidden in ("CF_API_TOKEN", "CLOUDFLARE_API_TOKEN", "Authorization"):
            self.assertNotIn(forbidden, self.source)


if __name__ == "__main__":
    unittest.main()
