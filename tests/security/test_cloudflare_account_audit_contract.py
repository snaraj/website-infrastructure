#!/usr/bin/env python3
"""Regression battery for the owner-run read-only Cloudflare account audit.

``scripts/cloudflare-account-audit.sh`` takes a live API token, so its audit
path cannot run here and no test in this file supplies a credential or reaches
the network. What is exercised is everything that decides whether handing this
script a token is safe: the credential guard, the request surface, and the
redaction that makes an audit capture shareable.

``CloudflareAccountAuditBehaviourTests`` execute the script or source it and
call its real functions. ``CloudflareAccountAuditSourceTests`` are source-level
pins, labelled as such: they assert a rule is still written into the script, not
that it still holds against the live API. Both matter here — a script that reads
a bearer token deserves belt and braces — but they are not the same strength of
evidence and are not presented as if they were.
"""

import os
import re
import shlex
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "cloudflare-account-audit.sh"
BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required to exercise the audit script"
# A syntactically valid but entirely fictional token shape: 40 characters from
# the documented alphabet. It is never sent anywhere -- every test that uses it
# asserts the script stops before any request.
FAKE_TOKEN = "A" * 40


def run_script(*argv, env_overrides=None):
    environment = dict(os.environ)
    environment.pop("CF_API_TOKEN", None)
    if env_overrides:
        environment.update(env_overrides)
    return subprocess.run(
        [required_tool(BASH, BASH_REQUIRED), str(SCRIPT), *argv],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=environment,
    )


def call_function(program, env_overrides=None):
    """Source the script and run shell code against its real functions."""

    environment = dict(os.environ)
    environment.pop("CF_API_TOKEN", None)
    if env_overrides:
        environment.update(env_overrides)
    return subprocess.run(
        [required_tool(BASH, BASH_REQUIRED), "-c", ". '{}'\n{}\n".format(SCRIPT, program)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=environment,
    )


@unittest.skipUnless(BASH, "bash is unavailable")
class CloudflareAccountAuditBehaviourTests(unittest.TestCase):
    """Behavioural: the real script, with no credential and no network."""

    def test_self_test_passes_offline(self):
        completed = run_script("--self-test")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("failures=0", completed.stdout)
        self.assertIn("credential-untouched   -> ok", completed.stdout)

    def test_help_states_the_credential_and_redaction_contract(self):
        completed = run_script("--help")
        self.assertEqual(completed.returncode, 0)
        self.assertIn("CF_API_TOKEN", completed.stdout)
        self.assertIn("READ-ONLY", completed.stdout)
        self.assertIn("Never pass a token as an argument", completed.stdout)
        self.assertIn("--raw", completed.stdout)

    def test_missing_token_is_a_tooling_error_not_a_pass(self):
        completed = run_script()
        self.assertEqual(completed.returncode, 2)
        self.assertIn("CF_API_TOKEN", completed.stderr)

    def test_malformed_token_stops_before_any_request(self):
        completed = run_script(env_overrides={"CF_API_TOKEN": "not a token"})
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unsupported or unsafe format", completed.stderr)
        # The rejected value must not be echoed back in the diagnostic.
        self.assertNotIn("not a token", completed.stderr)

    def test_a_token_shaped_argument_is_refused(self):
        # The one mistake that would put a bearer in the process table.
        completed = run_script(FAKE_TOKEN)
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn(FAKE_TOKEN, completed.stdout)
        self.assertIn("unknown argument", completed.stderr)

    def test_redaction_is_stable_distinct_and_opaque(self):
        program = (
            "resolve_tools\n"
            "redact sample-identifier-one\n"
            "redact sample-identifier-one\n"
            "redact sample-identifier-two\n"
            "redact ''\n"
        )
        completed = call_function(program)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        first, second, other, empty = completed.stdout.strip().splitlines()
        self.assertEqual(first, second, "a diff between two runs must be stable")
        self.assertNotEqual(first, other, "distinct inputs must stay distinct")
        self.assertTrue(first.startswith("id:"))
        self.assertNotIn("sample-identifier", first, "the pseudonym must not carry its input")
        self.assertEqual(empty, "none")

    def test_raw_mode_returns_the_identifier_verbatim(self):
        completed = call_function(
            "resolve_tools\nRAW=yes\nredact sample-identifier-one\n"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.strip(), "sample-identifier-one"
        )

    def test_redaction_fails_closed_without_a_digest_tool(self):
        # An empty pseudonym would collapse every identifier to one token and
        # make an audit diff look clean while hiding real change.
        completed = call_function("redact sample-identifier-one\n")
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("id:", completed.stdout)

    @staticmethod
    def _api_get_with_stubbed_curl(path):
        # curl is replaced by a shell function, so this proves whether the path
        # validator stopped the request WITHOUT any packet leaving the host. A
        # test that merely observed a nonzero return could not tell rejection
        # from an unset-variable error and would pass even with the validator
        # removed.
        program = (
            "curl() { cat >/dev/null; printf 'CURL-INVOKED\\n'; }\n"
            "api_get " + shlex.quote(path) + " || printf 'REJECTED\\n'\n"
        )
        return call_function(
            program, env_overrides={"CF_API_TOKEN": FAKE_TOKEN}
        )

    def test_request_paths_reject_injection(self):
        # api_get validates the path before the credential is interpolated into
        # the curl configuration document, so a malformed path can never reach
        # the network or smuggle a second URL or header past the fixed method.
        for hostile in (
            '/zones"\nurl = "https://example.invalid/',
            '/zones\nheader = "X-Injected: 1"',
            "https://example.invalid/zones",
            "/zones; rm -rf /",
            "/zones $(id)",
        ):
            with self.subTest(path=hostile):
                completed = self._api_get_with_stubbed_curl(hostile)
                self.assertIn("REJECTED", completed.stdout)
                self.assertNotIn("CURL-INVOKED", completed.stdout)

    def test_a_legitimate_path_does_reach_the_request_builder(self):
        # The vacuity probe for the test above: a validator that rejected
        # everything would satisfy it while making the audit useless.
        completed = self._api_get_with_stubbed_curl("/user/tokens/verify")
        self.assertIn("CURL-INVOKED", completed.stdout)
        self.assertNotIn("REJECTED", completed.stdout)


class CloudflareAccountAuditSourceTests(unittest.TestCase):
    """Source-level pins for properties the live API path cannot prove here."""

    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")
        cls.lines = cls.source.splitlines()

    def test_the_api_version_is_pinned(self):
        self.assertIn(
            "readonly API_BASE='https://api.cloudflare.com/client/v4'", self.source
        )

    def test_there_is_exactly_one_egress_point_and_it_is_a_get(self):
        invocations = [
            line for line in self.lines if "curl --disable --config -" in line
        ]
        self.assertEqual(
            len(invocations), 1, "every request must go through the one helper"
        )
        methods = [line for line in self.lines if 'request = "GET"' in line]
        self.assertEqual(len(methods), 1)

    def test_no_write_verb_appears_anywhere(self):
        # A real invocation writes the verb after actual whitespace. The
        # script's own detector spells its alternation with a character class,
        # so this pattern cannot match the detector and call it a violation.
        pattern = re.compile(
            r"(?:--request|\s-X)\s+[\"']?(?:POST|PUT|PATCH|DELETE)"
        )
        self.assertEqual(
            pattern.findall(self.source), [], "this reader issues GET only"
        )

    def test_the_credential_never_reaches_argv_or_a_file(self):
        # The token appears in exactly three places: the guard that reads it,
        # the un-export that stops it being inherited, and the stdin
        # configuration document that hands it to curl.
        uses = [
            line
            for line in self.lines
            if "CF_API_TOKEN" in line and not line.lstrip().startswith("#")
        ]
        self.assertTrue(uses)
        for line in uses:
            with self.subTest(line=line.strip()):
                self.assertNotIn(">", line, "the token is never redirected to a file")
                self.assertNotIn("echo", line)
        self.assertIn("export -n CF_API_TOKEN", self.source)

    def test_tracing_and_history_are_disabled_before_anything_runs(self):
        prologue = "\n".join(self.lines[:60])
        self.assertIn("set +x", prologue)
        self.assertIn("set +o history", prologue)

    def test_raw_mode_carries_its_own_warning(self):
        self.assertIn("RAW MODE", self.source)
        self.assertIn("Never commit it", self.source)

    def test_expectations_match_the_two_tunnel_target_state(self):
        for expected in (
            "readonly TUNNEL_A='naranjo-online'",
            "readonly TUNNEL_B='lidersea-com'",
            "http_status:404",
            "always_use_https on",
            "min_tls_version 1.2",
            "tls_1_3 on",
            "0rtt off",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.source)

    def test_unreadable_answers_are_findings_not_passes(self):
        # Fail-closed is the whole point: every branch that could not read an
        # answer must call finding(), never ok().
        unavailable = [
            line
            for line in self.lines
            if "could not be read" in line or "could not be verified" in line
        ]
        self.assertGreaterEqual(len(unavailable), 8)
        for line in unavailable:
            with self.subTest(line=line.strip()):
                self.assertIn("finding ", line)


if __name__ == "__main__":
    unittest.main()
