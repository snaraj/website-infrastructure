"""Fail-closed contract for the two-zone HTTPS/TLS transaction (issue #118)."""

import copy
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
CLOUDFLARE_ROOT = REPO_ROOT / "infrastructure" / "cloudflare"
PHASE_ROOT = CLOUDFLARE_ROOT / "phases"
FIXTURE_ROOT = (
    REPO_ROOT / "infrastructure" / "cloudflare" / "tests" / "fixtures"
)
POLICY = (
    REPO_ROOT / "infrastructure" / "cloudflare" / "policy" / "cloudflare-plan.rego"
).read_text(encoding="utf-8")
MUTATOR_PATH = REPO_ROOT / "scripts" / "mutate_cloudflare_fixture.py"
POLICY_DRIVER = (REPO_ROOT / "scripts" / "test-cloudflare-policy.sh").read_text(
    encoding="utf-8"
)
SSLSTREAM_PROBE_PATH = REPO_ROOT / "scripts" / "cloudflare-edge-sslstream-probe.ps1"
SSLSTREAM_PROBE = SSLSTREAM_PROBE_PATH.read_text(encoding="utf-8")
RUNBOOK = (
    REPO_ROOT / "docs" / "runbooks" / "cloudflare-edge-hardening.md"
).read_text(encoding="utf-8")
LEGACY_RUNBOOK = (
    REPO_ROOT / "docs" / "runbooks" / "edge-remediation-and-rotation.md"
).read_text(encoding="utf-8")
WORKFLOW = (REPO_ROOT / ".github" / "workflows" / "pull-request.yml").read_text(
    encoding="utf-8"
)
PWSH = shutil.which("pwsh")

SITES = {
    "site-naranjo-online": {
        "slug": "naranjo_online",
        "hostname": "naranjo.online",
    },
    "site-lidersea-com": {
        "slug": "lidersea_com",
        "hostname": "lidersea.com",
    },
}

TARGET_TRANSITIONS = {
    "always_use_https": ("off", "on"),
    "min_tls_version": ("1.0", "1.2"),
}

ALL_SETTING_VALUES = {
    "always_use_https": "on",
    "min_tls_version": "1.2",
    "tls_1_3": "on",
    "0rtt": "off",
    "http3": "on",
    "ssl": "full",
}

SETTING_RESOURCE_SUFFIXES = {
    "always_use_https": "always_use_https",
    "min_tls_version": "min_tls_version",
    "tls_1_3": "tls_1_3",
    "0rtt": "zero_rtt",
    "http3": "http3",
    "ssl": "ssl",
}


def setting_owners(source):
    """Extract resource-name/setting-id pairs from one closed site root."""

    return re.findall(
        r'(?ms)^resource "cloudflare_zone_setting" "([a-z0-9_]+)" \{'
        r'.*?^  setting_id = "([a-z0-9_]+)"$',
        source,
    )


class CloudflareEdgeHardeningContractTests(unittest.TestCase):
    """Bind source ownership, plan transitions, probes, and rollback together."""

    def test_each_setting_has_one_existing_owner_per_site_and_no_second_root(self):
        repository_counts = {setting: 0 for setting in ALL_SETTING_VALUES}
        expected_repository_owners = []
        for phase, identity in SITES.items():
            source = (PHASE_ROOT / phase / "main.tf").read_text(encoding="utf-8")
            owners = setting_owners(source)
            self.assertEqual(len(owners), len(ALL_SETTING_VALUES))
            observed = [setting for _resource, setting in owners]
            self.assertEqual(set(observed), set(ALL_SETTING_VALUES))
            self.assertEqual(len(observed), len(set(observed)))
            for setting in ALL_SETTING_VALUES:
                repository_counts[setting] += observed.count(setting)
                expected_repository_owners.append(
                    (
                        (PHASE_ROOT / phase / "main.tf")
                        .relative_to(REPO_ROOT)
                        .as_posix(),
                        "{}_{}".format(
                            identity["slug"], SETTING_RESOURCE_SUFFIXES[setting]
                        ),
                        setting,
                    )
                )

            for setting_key, setting_id in (
                ("always_use_https", "always_use_https"),
                ("min_tls_version", "min_tls_version"),
            ):
                expected_resource = "{}_{}".format(identity["slug"], setting_key)
                self.assertIn((expected_resource, setting_id), owners)

            # Hostile source proof: the same parser must detect a duplicated
            # state owner even when it carries the exact desired value.
            duplicated = source + (
                '\nresource "cloudflare_zone_setting" "duplicate_owner" {\n'
                '  setting_id = "always_use_https"\n'
                '  value      = "on"\n'
                '}\n'
            )
            duplicated_ids = [setting for _resource, setting in setting_owners(duplicated)]
            self.assertEqual(duplicated_ids.count("always_use_https"), 2)

        self.assertEqual(
            repository_counts,
            {setting: len(SITES) for setting in ALL_SETTING_VALUES},
        )

        # Scan every Terraform source under the Cloudflare root, not just the
        # two expected main.tf files. The separate header inventory makes a
        # dynamic/missing setting_id fail instead of disappearing from the
        # parsed owner list.
        repository_headers = []
        repository_owners = []
        for terraform_source in sorted(CLOUDFLARE_ROOT.rglob("*.tf")):
            source = terraform_source.read_text(encoding="utf-8")
            relative = terraform_source.relative_to(REPO_ROOT).as_posix()
            repository_headers.extend(
                (relative, resource)
                for resource in re.findall(
                    r'(?m)^resource "cloudflare_zone_setting" "([a-z0-9_]+)" \{',
                    source,
                )
            )
            repository_owners.extend(
                (relative, resource, setting)
                for resource, setting in setting_owners(source)
            )

        self.assertEqual(
            sorted(repository_owners), sorted(expected_repository_owners)
        )
        self.assertEqual(
            sorted(repository_headers),
            sorted(
                (path, resource)
                for path, resource, _setting in repository_owners
            ),
        )

    def test_existing_roots_encode_ordered_target_and_provider_readback(self):
        for phase, identity in SITES.items():
            source = (PHASE_ROOT / phase / "main.tf").read_text(encoding="utf-8")
            slug = identity["slug"]
            min_address = "cloudflare_zone_setting.{}_min_tls_version".format(slug)
            self.assertIn(
                "depends_on = [{}]".format(min_address),
                source,
            )
            self.assertLess(
                source.index('setting_id = "min_tls_version"'),
                source.index('setting_id = "always_use_https"'),
            )
            for expression in (
                'self.setting_id == "min_tls_version" && self.value == "1.2"',
                'self.setting_id == "always_use_https" && self.value == "on"',
            ):
                self.assertEqual(source.count(expression), 1)

            versions = (PHASE_ROOT / phase / "versions.tf").read_text(
                encoding="utf-8"
            )
            lock = (PHASE_ROOT / phase / ".terraform.lock.hcl").read_text(
                encoding="utf-8"
            )
            self.assertIn('required_version = "= 1.12.5"', versions)
            self.assertIn('version = "5.22.0"', versions)
            self.assertIn('version     = "5.22.0"', lock)

    def test_allow_fixtures_change_only_the_two_existing_setting_owners(self):
        for phase, identity in SITES.items():
            fixture = json.loads(
                (FIXTURE_ROOT / ("allow-" + phase + ".json")).read_text(
                    encoding="utf-8"
                )
            )
            changes = fixture["resource_changes"]
            updated = {
                change["address"]: change["change"]
                for change in changes
                if change["change"]["actions"] == ["update"]
            }
            expected_addresses = {
                "cloudflare_zone_setting.{}_{}".format(identity["slug"], key)
                for key in TARGET_TRANSITIONS
            }
            self.assertEqual(set(updated), expected_addresses)
            self.assertEqual(len(changes), 9)

            for key, (before, after) in TARGET_TRANSITIONS.items():
                address = "cloudflare_zone_setting.{}_{}".format(
                    identity["slug"], key
                )
                self.assertEqual(updated[address]["before"]["value"], before)
                self.assertEqual(updated[address]["after"]["value"], after)

            for change in changes:
                if change["address"] in expected_addresses:
                    continue
                self.assertEqual(change["change"]["actions"], ["no-op"])
                self.assertEqual(change["change"]["before"], change["change"]["after"])

    def test_policy_binds_prestate_and_forbids_every_other_update(self):
        for fragment in (
            "edge_hardening_prechange_values := {",
            '"always_use_https": "off"',
            '"min_tls_version": "1.0"',
            "zone_setting_transition_exact(address, setting, zone_id)",
            "only the existing HTTPS and minimum-TLS setting owners may update",
            "pre-change value does not match the frozen baseline",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, POLICY)

        for mutation in (
            "duplicate-setting-owner",
            "tunnel-config-update",
            "wrong-https-prestate",
            "wrong-min-tls-prestate",
            "unrelated-zone-setting-update",
        ):
            with self.subTest(mutation=mutation):
                self.assertIn('"{}"'.format(mutation), MUTATOR_PATH.read_text(encoding="utf-8"))
                self.assertIn(mutation, POLICY_DRIVER)

    def test_duplicate_owner_mutation_really_creates_overlapping_custody(self):
        mutator = load_script(
            "mutate_cloudflare_fixture.py", module_name="edge_hardening_mutator"
        )
        for phase in SITES:
            original = json.loads(
                (FIXTURE_ROOT / ("allow-" + phase + ".json")).read_text(
                    encoding="utf-8"
                )
            )
            mutated = copy.deepcopy(original)
            mutator.mutate(mutated, "duplicate-setting-owner")
            owners = [
                change
                for change in mutated["resource_changes"]
                if change["type"] == "cloudflare_zone_setting"
                and change["change"]["after"]["setting_id"] == "always_use_https"
            ]
            self.assertEqual(len(owners), 2)
            self.assertEqual(len({owner["address"] for owner in owners}), 2)

    def test_sslstream_probe_is_fixed_host_validating_and_baseline_bound(self):
        for fragment in (
            '[ValidateSet("all", "naranjo.online", "lidersea.com")]',
            '$ExpectedPowerShell = "7.6.4"',
            '$ExpectedFramework = ".NET 10.0.10"',
            "$options.TargetHost = $HostName",
            "$options.EnabledSslProtocols = $Offer",
            "CertificateRevocationCheckMode",
            "X509RevocationMode]::Online",
            "$handler.AllowAutoRedirect = $false",
            '"(?is)<script\\b[^>]*>.*?</script>"',
            '"(?m)^[ \\t]*\\r?\\n"',
            "0B90BBD8ED52F7106D187188DDB5FF62E39376672D5709D8EADCE3DD10ABFE1A",
            "400CB6544FF009DC244E7C2CA583130323E75E4FF5DC2519FBDAD6DF728896DE",
            'Outcome = "rejected"',
            "NegotiatedProtocol",
            "CertificateSha256",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, SSLSTREAM_PROBE)

        for forbidden in (
            "RemoteCertificateValidationCallback",
            "ServerCertificateCustomValidationCallback",
            "DangerousAcceptAnyServerCertificateValidator",
            "CLOUDFLARE_API_TOKEN",
            "Authorization",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, SSLSTREAM_PROBE)

    @unittest.skipUnless(PWSH, "PowerShell is required for the hermetic self-test")
    def test_sslstream_probe_offline_self_test(self):
        result = subprocess.run(
            [
                PWSH,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(SSLSTREAM_PROBE_PATH),
                "-SelfTest",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "PASS cloudflare-edge-sslstream-probe offline self-test\n",
        )
        self.assertEqual(result.stderr, "")

    def test_runbook_serializes_readback_acceptance_and_exact_rollback(self):
        for fragment in (
            "Current `main` already declares the desired values",
            "never adds a second state owner",
            "trusted reviewed-blob",
            "strict current-phase token-preflight",
            "exactly two\nupdates and seven no-ops",
            "finish `naranjo.online`",
            "before planning `lidersea.com`",
            "Minimum TLS Version before Always Use HTTPS",
            "fresh normal plan",
            "must refresh remote state and exit with no changes",
            "`PowerShell`, `Framework`, `OS`, and\n   `ScriptSha256` runtime fields",
            "expected `Prechange` → `Postchange`\n   difference",
            "TLS 1.0 and 1.1\n   `rejected`",
            "TLS 1.2 and 1.3 `accepted`",
            "same canonical body length/SHA-256",
            "certificate SHA-256 to match the before",
            "DNS/Tunnel continuity",
            "restore Always Use HTTPS first",
            "restore Minimum TLS Version",
            "`always_use_https=off` and `min_tls_version=1.0`",
            "no `VERSION` edit",
            "no `requires-review`",
            "fresh\nUltra and Main Worker gates",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, RUNBOOK)

        self.assertNotRegex(RUNBOOK, r"\b[0-9a-f]{32}\b")
        self.assertNotRegex(
            RUNBOOK,
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        )

    def test_legacy_dashboard_transaction_is_unambiguously_retired(self):
        self.assertIn("Historical Ceremony A — superseded; do not execute", LEGACY_RUNBOOK)
        self.assertIn("docs/runbooks/cloudflare-edge-hardening.md", LEGACY_RUNBOOK)
        self.assertIn("Do not reconstruct the removed dashboard procedure", LEGACY_RUNBOOK)
        self.assertNotIn("### A.2 The two toggles", LEGACY_RUNBOOK)
        self.assertNotIn("For each zone, in the Cloudflare dashboard", LEGACY_RUNBOOK)

    def test_ci_remains_bounded_credential_free_and_concurrency_safe(self):
        self.assertIn("timeout-minutes: 30", WORKFLOW)
        self.assertIn("cancel-in-progress: true", WORKFLOW)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", WORKFLOW)
        self.assertNotIn("cloudflare-edge-sslstream-probe.ps1 -Mode", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
