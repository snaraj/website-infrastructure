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
import tempfile
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

    def test_empty_transcript_is_an_unclassified_error(self):
        # The fail-closed fallback, and the reason it must stay a fallback: the
        # watchdog kills a hung s_client and leaves an empty transcript behind.
        # If the fallback said "refused", that empty file would score a PASS on
        # tls10-refused / tls11-refused -- a timeout would silently certify the
        # TLS floor as fixed.
        self.assertEqual(
            call_parser("classify_tls_transcript", text=""), "error unclassified"
        )

    def test_session_block_only_transcript_is_an_unclassified_error(self):
        # A transcript truncated to its SSL-Session: block carries an indented
        # `Protocol  :` line and nothing else. It is neither a completed
        # handshake nor a refusal, and must not be scored as either.
        self.assertEqual(
            call_parser(
                "classify_tls_transcript",
                text="SSL-Session:\n    Protocol  : TLSv1\n    Cipher    : 0000\n",
            ),
            "error unclassified",
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

    def test_a_probe_that_produced_no_transcript_records_error(self):
        # The watchdog path, end to end: a bounded run that yields an empty
        # transcript must reach the ERROR branch, never the refused-is-PASS
        # branch. `/bin/true` stands in for a killed s_client -- it exits 0 and
        # writes nothing, which is the worst case for a fail-open parser.
        records = Path(os.environ.get("TMPDIR", "/tmp")) / "edge-probe-timeout.tsv"
        workdir = Path(os.environ.get("TMPDIR", "/tmp")) / "edge-probe-timeout-dir"
        program = (
            ". '{script}'\n"
            "WORKDIR='{workdir}'\n"
            "mkdir -p \"$WORKDIR\"\n"
            "RECORDS='{records}'\n"
            ": >\"$RECORDS\"\n"
            "PREFLIGHT_TLS1=capable\n"
            "OPENSSL=/usr/bin/true\n"
            "probe_tls_version 1 probe.invalid tls10-refused tls1 refused\n"
            "cat \"$RECORDS\"\n"
            "rm -rf \"$WORKDIR\" \"$RECORDS\"\n"
        ).format(script=SCRIPT, workdir=workdir, records=records)
        completed = subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), "-c", program],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        fields = completed.stdout.strip().split("\t")
        self.assertEqual(fields[4], "ERROR")
        self.assertNotEqual(fields[4], "PASS")


@unittest.skipUnless(BASH, "bash is unavailable")
class EdgeProbeEnforcementScopeTests(unittest.TestCase):
    """Behavioural: --enforce fails on unproven, not on inapplicable.

    A single-zone run cannot evaluate cross-zone distinctness. Scoring that as
    an asserted SKIP made every single-zone enforcing run exit 1 no matter how
    healthy the zone was — which is worse than useless in the middle of the
    half-completed toggle ceremony the runbook prescribes, because it trains
    the operator to wave a nonzero exit through. These tests pin the carve-out
    and its boundary: inapplicable passes, genuinely unproven still fails.

    A boundary record MUST name an item that is not already in
    ``HEALTHY_SINGLE_ZONE``. ``final_verdicts`` collapses two differing
    verdicts for the same (zone, item) key to DIVERGENT, so re-using a key
    silently converts a SKIP or GAP boundary test into a DIVERGENT test wearing
    the wrong label — which is exactly what the first version of these two
    tests did, leaving three enforcement-bypass mutations alive under a green
    998-test suite. Every boundary test therefore asserts the RESULT counters,
    not merely the exit code: the counter is what proves which branch of the
    failure sum actually fired.
    """

    HEALTHY_SINGLE_ZONE = (
        "record 1 naranjo.online http-redirect-root assert PASS "
        "'http_code=301 location=https://naranjo.online/ chain=1:200' ''\n"
        "record 1 naranjo.online tls10-refused assert PASS refused ''\n"
        "record 1 naranjo.online tls11-refused assert PASS refused ''\n"
        "record 1 naranjo.online tls12-accepted assert PASS 'accepted TLSv1.2' ''\n"
        "record 1 naranjo.online hsts-exact assert PASS max-age=31536000 ''\n"
        "record 1 naranjo.online readyz assert PASS 'http_code=200 body=ok' ''\n"
    )
    # Items deliberately absent from HEALTHY_SINGLE_ZONE, reserved for boundary
    # records so a boundary verdict can never collapse into DIVERGENT.
    UNUSED_SKIP_ITEM = "www-absent"
    UNUSED_GAP_ITEM = "dnssec"

    def _enforce(self, extra_records=""):
        workdir = Path(os.environ.get("TMPDIR", "/tmp")) / "edge-probe-enforce"
        program = (
            ". '{script}'\n"
            "WORKDIR='{workdir}'\n"
            "rm -rf \"$WORKDIR\"; mkdir -p \"$WORKDIR\"\n"
            "RECORDS=\"$WORKDIR/records.tsv\"\n"
            ": >\"$RECORDS\"\n"
            "ZONES='naranjo.online'\n"
            "ROUNDS=1\n"
            "ENFORCE=yes\n"
            "PREFLIGHT_TLS1=capable\n"
            "PREFLIGHT_TLS1_1=capable\n"
            "PREFLIGHT_TLS1_2=capable\n"
            "PREFLIGHT_TLS1_3=capable\n"
            "{healthy}"
            "{extra}"
            # The real function decides the scope verdict; the test does not
            # hand-write it, so removing the carve-out shows up here.
            "probe_cross_zone_distinctness 1\n"
            "if print_report; then status=0; else status=$?; fi\n"
            "printf 'ENFORCE-EXIT=%s\\n' \"$status\"\n"
            "rm -rf \"$WORKDIR\"\n"
        ).format(
            script=SCRIPT,
            workdir=workdir,
            healthy=self.HEALTHY_SINGLE_ZONE,
            extra=extra_records,
        )
        completed = subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), "-c", program],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout

    @staticmethod
    def _result_counters(output):
        """Return the RESULT line's key=value pairs as a dict."""

        for line in output.splitlines():
            if line.startswith("RESULT "):
                pairs = {}
                for token in line.split():
                    if "=" in token:
                        key, _, value = token.partition("=")
                        pairs[key] = value
                return pairs
        raise AssertionError("no RESULT line in:\n" + output)

    def test_single_zone_enforce_exits_zero_when_every_applicable_item_passes(self):
        output = self._enforce()
        counters = self._result_counters(output)
        self.assertIn("ENFORCE-EXIT=0", output)
        self.assertIn("INAPPLICABLE", output)
        self.assertEqual(counters["skip"], "0")
        self.assertEqual(counters["gap"], "0")
        self.assertEqual(counters["divergent"], "0")
        self.assertEqual(counters["inapplicable"], "1")
        self.assertEqual(counters["exit"], "0")

    def test_a_genuine_capability_skip_still_fails_enforce(self):
        # The boundary. An item that could not be proven is still fatal, so the
        # carve-out above cannot be widened into "SKIP is fine". The counter
        # assertion is what makes this a SKIP test rather than an accidental
        # DIVERGENT test: without skip=1 divergent=0, dropping skip from the
        # failure sum would still leave this green.
        output = self._enforce(
            extra_records=(
                "record 1 naranjo.online {item} assert SKIP "
                "client=incapable 'the local client could not be proven able' \n"
            ).format(item=self.UNUSED_SKIP_ITEM)
        )
        counters = self._result_counters(output)
        self.assertEqual(counters["skip"], "1")
        self.assertEqual(counters["divergent"], "0")
        self.assertEqual(counters["exit"], "1")
        self.assertIn("ENFORCE-EXIT=1", output)

    def test_a_gap_still_fails_enforce(self):
        output = self._enforce(
            extra_records=(
                "record 1 naranjo.online {item} assert GAP "
                "'ds1=absent ds2=absent' 'the zone is expected to be signed' \n"
            ).format(item=self.UNUSED_GAP_ITEM)
        )
        counters = self._result_counters(output)
        self.assertEqual(counters["gap"], "1")
        self.assertEqual(counters["divergent"], "0")
        self.assertEqual(counters["exit"], "1")
        self.assertIn("ENFORCE-EXIT=1", output)

    def _two_zone_distinctness(self, naranjo_assets, lidersea_assets):
        """Run the real cross-zone check with BOTH zones selected."""

        workdir = Path(os.environ.get("TMPDIR", "/tmp")) / "edge-probe-two-zone"
        program = (
            ". '{script}'\n"
            "WORKDIR='{workdir}'\n"
            "rm -rf \"$WORKDIR\"; mkdir -p \"$WORKDIR\"\n"
            "RECORDS=\"$WORKDIR/records.tsv\"\n"
            ": >\"$RECORDS\"\n"
            "ZONES=\"$ZONE_A $ZONE_B\"\n"
            "record 1 naranjo.online assets record RECORD '{a}' ''\n"
            "record 1 lidersea.com assets record RECORD '{b}' ''\n"
            "probe_cross_zone_distinctness 1\n"
            "awk -F'\\t' '$3==\"sites-distinct\"' \"$RECORDS\"\n"
            "rm -rf \"$WORKDIR\"\n"
        ).format(
            script=SCRIPT,
            workdir=workdir,
            a=naranjo_assets,
            b=lidersea_assets,
        )
        completed = subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), "-c", program],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip().split("\t")

    def test_two_zone_distinctness_is_asserted_and_passes_on_disjoint_assets(self):
        # The INAPPLICABLE carve-out is scoped to single-zone runs ONLY. With
        # both zones selected the item must still be an ASSERTED check, or the
        # carve-out has quietly disabled distinctness for the run that matters.
        fields = self._two_zone_distinctness(
            "/assets/index-AAAA.css,/assets/index-AAAA.js",
            "/assets/index-BBBB.css,/assets/index-BBBB.js",
        )
        self.assertEqual(fields[3], "assert", "two-zone runs must still assert")
        self.assertEqual(fields[4], "PASS")
        self.assertEqual(fields[5], "assets-disjoint")

    def test_two_zone_distinctness_gaps_on_identical_assets(self):
        # The failing direction, and the vacuity probe for the test above: if
        # this item were re-tiered to a record it could no longer fail a run,
        # and two sites serving one build would pass unnoticed.
        fields = self._two_zone_distinctness(
            "/assets/index-SAME.css,/assets/index-SAME.js",
            "/assets/index-SAME.css,/assets/index-SAME.js",
        )
        self.assertEqual(fields[3], "assert", "a GAP must stay in the asserted tier")
        self.assertEqual(fields[4], "GAP")
        self.assertEqual(fields[5], "assets-identical")

    def test_two_verdicts_for_one_key_collapse_to_divergent(self):
        # The behaviour that silently mislabelled the two boundary tests above.
        # Pinned explicitly so the next person to add a boundary record sees
        # why item names must not be re-used, and so the collapse itself stays
        # a deliberate property rather than an accident.
        output = self._enforce(
            extra_records=(
                "record 1 naranjo.online readyz assert GAP "
                "'http_code=503' 'the readiness endpoint is not answering 200' \n"
            )
        )
        counters = self._result_counters(output)
        self.assertEqual(counters["divergent"], "1")
        self.assertEqual(counters["gap"], "0", "the collapse absorbs the GAP")
        self.assertEqual(counters["exit"], "1")


@unittest.skipUnless(BASH, "bash is unavailable")
class EdgeProbeRedirectSimulationTests(unittest.TestCase):
    """Behavioural: the post-remediation redirect verdicts, both directions.

    The remediated state cannot be observed until the owner throws the toggles,
    so the redirect assertion is a CI-invisible path. The review protocol asks
    for simulated evidence of both directions; this drives the real
    ``probe_http_redirect`` against a curl test double and pins one PASS shape
    and five distinct GAP shapes. The scenario set came from the adversarial
    review round.
    """

    SCENARIOS = (
        ("301 preserving root", "/", "301 https://naranjo.online/", "1:200", "PASS"),
        ("308 preserving root", "/", "308 https://naranjo.online/", "1:200", "PASS"),
        (
            "query string dropped",
            "/readyz?probe=1&x=2",
            "301 https://naranjo.online/readyz",
            "1:200",
            "GAP",
        ),
        ("two redirect hops", "/", "301 https://naranjo.online/", "2:200", "GAP"),
        ("temporary 302", "/", "302 https://naranjo.online/", "1:200", "GAP"),
        (
            "https downgraded to http",
            "/",
            "301 http://naranjo.online/",
            "1:200",
            "GAP",
        ),
        ("today: served directly", "/", "200 ", "0:200", "GAP"),
    )

    @classmethod
    def setUpClass(cls):
        cls.stub_dir = Path(
            tempfile.mkdtemp(prefix="edge-probe-curl-stub.", dir=os.environ.get("TMPDIR"))
        )
        cls.stub = cls.stub_dir / "curl-double"
        cls.stub.write_text(
            "#!/usr/bin/env bash\n"
            "# curl test double. --dump-header means a header observation, the\n"
            "# follow-up hop-count request is the one carrying --location, and\n"
            "# everything else is the first redirect observation.\n"
            "previous=''\n"
            "for argument in \"$@\"; do\n"
            "  if [[ \"${previous}\" == --dump-header ]]; then\n"
            "    printf '%s' \"${EDGE_PROBE_SIM_HEADERS:-}\" >\"${argument}\"\n"
            "    exit 0\n"
            "  fi\n"
            "  if [[ \"${argument}\" == --location ]]; then\n"
            "    printf '%s' \"${EDGE_PROBE_SIM_HOPS}\"\n"
            "    exit 0\n"
            "  fi\n"
            "  previous=\"${argument}\"\n"
            "done\n"
            "printf '%s' \"${EDGE_PROBE_SIM_FIRST}\"\n"
            "exit 0\n",
            encoding="utf-8",
        )
        cls.stub.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.stub_dir, ignore_errors=True)

    def _redirect_verdict(self, path, first, hops):
        workdir = self.stub_dir / "work"
        program = (
            ". '{script}'\n"
            "WORKDIR='{workdir}'\n"
            "rm -rf \"$WORKDIR\"; mkdir -p \"$WORKDIR\"\n"
            "RECORDS=\"$WORKDIR/records.tsv\"\n"
            ": >\"$RECORDS\"\n"
            "CURL='{stub}'\n"
            "TIMEOUT=5\n"
            "probe_http_redirect 1 naranjo.online http-redirect-root '{path}'\n"
            "cat \"$RECORDS\"\n"
        ).format(script=SCRIPT, workdir=workdir, stub=self.stub, path=path)
        environment = dict(os.environ)
        environment["EDGE_PROBE_SIM_FIRST"] = first
        environment["EDGE_PROBE_SIM_HOPS"] = hops
        completed = subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), "-c", program],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip().split("\t")

    def test_every_post_remediation_redirect_shape_scores_correctly(self):
        for label, path, first, hops, expected in self.SCENARIOS:
            with self.subTest(scenario=label):
                fields = self._redirect_verdict(path, first, hops)
                self.assertEqual(
                    fields[4],
                    expected,
                    "{}: expected {}, observed {} ({})".format(
                        label, expected, fields[4], fields[5]
                    ),
                )

    def test_the_simulation_can_produce_both_verdicts(self):
        # Vacuity probe: the scenario set must contain at least one of each, so
        # the table above cannot be satisfied by a constant verdict.
        verdicts = {scenario[4] for scenario in self.SCENARIOS}
        self.assertEqual(verdicts, {"PASS", "GAP"})

    def _cleartext_hsts(self, headers):
        workdir = self.stub_dir / "work-hsts"
        program = (
            ". '{script}'\n"
            "WORKDIR='{workdir}'\n"
            "rm -rf \"$WORKDIR\"; mkdir -p \"$WORKDIR\"\n"
            "RECORDS=\"$WORKDIR/records.tsv\"\n"
            ": >\"$RECORDS\"\n"
            "CURL='{stub}'\n"
            "TIMEOUT=5\n"
            "probe_cleartext_hsts 1 naranjo.online\n"
            "cat \"$RECORDS\"\n"
        ).format(script=SCRIPT, workdir=workdir, stub=self.stub)
        environment = dict(os.environ)
        environment["EDGE_PROBE_SIM_HEADERS"] = headers
        completed = subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), "-c", program],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip().split("\t")

    def test_cleartext_hsts_is_recorded_in_both_directions_and_never_asserted(self):
        # Deployed-state signal, not a control: a browser ignores HSTS received
        # over cleartext (RFC 6797 7.2), so this must never become an assertion
        # that could pass or fail the run.
        present = self._cleartext_hsts(
            "HTTP/1.1 200 OK\r\nstrict-transport-security: max-age=31536000\r\n\r\n"
        )
        self.assertEqual(present[3], "record")
        self.assertEqual(present[4], "RECORD")
        self.assertEqual(present[5], "present")

        absent = self._cleartext_hsts("HTTP/1.1 301 Moved Permanently\r\n\r\n")
        self.assertEqual(absent[3], "record")
        self.assertEqual(absent[5], "absent")


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

    def test_the_cleartext_hsts_record_is_wired_into_every_zone_probe(self):
        # Source pin. The behaviour of the record item itself is executed in
        # EdgeProbeRedirectSimulationTests; what cannot be executed offline is
        # the per-zone probe sequence, so its wiring is pinned here.
        sequence = self.source.split("probe_zone() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("probe_cleartext_hsts", sequence)

    def test_the_probe_takes_no_credential(self):
        for forbidden in ("CF_API_TOKEN", "CLOUDFLARE_API_TOKEN", "Authorization"):
            self.assertNotIn(forbidden, self.source)


if __name__ == "__main__":
    unittest.main()
