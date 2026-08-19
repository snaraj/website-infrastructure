"""Fail-closed contract for the two-zone HTTPS/TLS transaction (issue #118).

Scope note. This is the load-bearing half of the edge-hardening surface: the
two site-owned OpenTofu roots, the plan policy that binds the transaction to
its measured prestate, the allow fixtures, and the hostile mutations that
prove each denial. The acceptance-probe client and the owner-run transaction
runbook are deferred to a tracked follow-up issue, so nothing here asserts
anything about a probe binary or a runbook that this tree does not contain —
an assertion over an absent file passes for the wrong reason.
"""

import copy
import json
import re
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
LEGACY_RUNBOOK_PATH = (
    REPO_ROOT / "docs" / "runbooks" / "edge-remediation-and-rotation.md"
)
LEGACY_RUNBOOK = LEGACY_RUNBOOK_PATH.read_text(encoding="utf-8")
WORKFLOW = (REPO_ROOT / ".github" / "workflows" / "pull-request.yml").read_text(
    encoding="utf-8"
)

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


def rego_rule_bodies(policy, rule_name):
    """Return each body of a named Rego rule, definitions excluded.

    Asserting a call by searching the whole policy text cannot tell a call site
    apart from the rule's own definition header, so deleting the call leaves
    such an assertion green. Reading the calling rule's body is what makes the
    difference visible.
    """

    pattern = re.compile(
        r"(?ms)^" + re.escape(rule_name) + r"\([^)]*\) if \{\n(.*?)^\}$"
    )
    return [match.group(1) for match in pattern.finditer(policy)]


class CloudflareEdgeHardeningContractTests(unittest.TestCase):
    """Bind source ownership, plan transitions, and hostile denials together."""

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
            "only the existing HTTPS and minimum-TLS setting owners may update",
            "pre-change value does not match the frozen baseline",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, POLICY)

        # The transition contract has to be INVOKED, not merely defined. A
        # whole-file search cannot distinguish the call from the two rule
        # headers that spell it identically, so read the calling rule's body.
        bodies = rego_rule_bodies(POLICY, "exact_zone_setting")
        self.assertEqual(len(bodies), 1)
        self.assertIn(
            "zone_setting_transition_exact(address, setting, zone_id)", bodies[0]
        )
        # Both branches must exist: the steady-state no-op already at target,
        # and the update from the frozen pre-change value.
        self.assertEqual(
            len(rego_rule_bodies(POLICY, "zone_setting_transition_exact")), 2
        )

        for mutation in (
            "duplicate-setting-owner",
            "tunnel-config-update",
            "wrong-https-prestate",
            "wrong-min-tls-prestate",
            "unrelated-zone-setting-update",
            "lying-no-op-setting",
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

    def test_each_new_hostile_mutation_really_produces_the_shape_it_names(self):
        """A mutation the Conftest driver lists must actually build the bad plan.

        The shell driver only records that Conftest said "deny". If a mutation
        silently produced the *unchanged* allow plan, the driver would still be
        red for the wrong reason on the day the rule was deleted — the plan
        would be admitted and the assertion would report a policy failure that
        the policy never made. These checks read the mutated object directly,
        so each denial is anchored to a specific hostile difference.
        """

        mutator = load_script(
            "mutate_cloudflare_fixture.py", module_name="edge_hardening_mutator"
        )
        for phase, identity in SITES.items():
            slug = identity["slug"]
            original = json.loads(
                (FIXTURE_ROOT / ("allow-" + phase + ".json")).read_text(
                    encoding="utf-8"
                )
            )

            def mutated_change(name, address, _original=original):
                plan = copy.deepcopy(_original)
                mutator.mutate(plan, name)
                matches = [
                    change
                    for change in plan["resource_changes"]
                    if change["address"] == address
                ]
                self.assertEqual(len(matches), 1, address)
                return matches[0]["change"]

            with self.subTest(phase=phase, mutation="tunnel-config-update"):
                address = (
                    "cloudflare_zero_trust_tunnel_cloudflared_config.{}".format(slug)
                )
                self.assertEqual(
                    original_actions_for(original, address), ["no-op"]
                )
                change = mutated_change("tunnel-config-update", address)
                self.assertEqual(change["actions"], ["update"])
                self.assertEqual(
                    change["before"]["config"]["ingress"][0]["service"],
                    "http://unreviewed.invalid:8080",
                )
                self.assertNotEqual(
                    change["before"]["config"]["ingress"][0]["service"],
                    change["after"]["config"]["ingress"][0]["service"],
                )

            with self.subTest(phase=phase, mutation="wrong-https-prestate"):
                address = "cloudflare_zone_setting.{}_always_use_https".format(slug)
                change = mutated_change("wrong-https-prestate", address)
                self.assertEqual(change["actions"], ["update"])
                self.assertEqual(change["before"]["value"], "on")
                self.assertNotEqual(
                    change["before"]["value"],
                    TARGET_TRANSITIONS["always_use_https"][0],
                )

            with self.subTest(phase=phase, mutation="wrong-min-tls-prestate"):
                address = "cloudflare_zone_setting.{}_min_tls_version".format(slug)
                change = mutated_change("wrong-min-tls-prestate", address)
                self.assertEqual(change["actions"], ["update"])
                self.assertEqual(change["before"]["value"], "1.1")
                self.assertNotEqual(
                    change["before"]["value"],
                    TARGET_TRANSITIONS["min_tls_version"][0],
                )

            with self.subTest(phase=phase, mutation="unrelated-zone-setting-update"):
                address = "cloudflare_zone_setting.{}_tls_1_3".format(slug)
                self.assertEqual(
                    original_actions_for(original, address), ["no-op"]
                )
                change = mutated_change("unrelated-zone-setting-update", address)
                self.assertEqual(change["actions"], ["update"])
                self.assertEqual(change["before"]["value"], "off")
                self.assertEqual(change["after"]["value"], "on")

            with self.subTest(phase=phase, mutation="lying-no-op-setting"):
                address = "cloudflare_zone_setting.{}_always_use_https".format(slug)
                self.assertEqual(
                    original_actions_for(original, address), ["update"]
                )
                change = mutated_change("lying-no-op-setting", address)
                # The lie: a declared no-op whose own before and after differ.
                # No deny rule for this transaction keys on "no-op", so this is
                # the input that only the positive transition contract catches.
                self.assertEqual(change["actions"], ["no-op"])
                self.assertNotEqual(
                    change["before"]["value"], change["after"]["value"]
                )
                self.assertEqual(
                    change["before"]["value"],
                    TARGET_TRANSITIONS["always_use_https"][0],
                )
                self.assertEqual(
                    change["after"]["value"],
                    TARGET_TRANSITIONS["always_use_https"][1],
                )

    def test_legacy_dashboard_ceremony_names_the_owning_state_roots(self):
        """The deferral must be visible where a reader would act on it.

        The acceptance probe and the owner-run transaction runbook are tracked
        separately, so the older dashboard ceremony is still in the tree. A
        reader who reaches it has to learn from that page — not from a pull
        request they will never open — that the two settings now have committed
        OpenTofu owners and that a dashboard toggle is break-glass.
        """

        for fragment in (
            "`infrastructure/cloudflare/phases/site-naranjo-online/main.tf`",
            "`infrastructure/cloudflare/phases/site-lidersea-com/main.tf`",
            "committed state owners",
            "break-glass",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, LEGACY_RUNBOOK)

        # Every repository path this note cites must exist, or the note is
        # itself the documentation rot it warns about.
        for reference in re.findall(r"`(infrastructure/[A-Za-z0-9._/-]+)`", LEGACY_RUNBOOK):
            with self.subTest(reference=reference):
                self.assertTrue((REPO_ROOT / reference).exists(), reference)

    def test_ci_remains_bounded_credential_free_and_concurrency_safe(self):
        self.assertIn("timeout-minutes: 30", WORKFLOW)
        self.assertIn("cancel-in-progress: true", WORKFLOW)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", WORKFLOW)


def original_actions_for(plan, address):
    """Return the unmutated action list, so a mutation's delta is provable."""

    matches = [
        change for change in plan["resource_changes"] if change["address"] == address
    ]
    if len(matches) != 1:
        raise AssertionError("expected exactly one {}".format(address))
    return matches[0]["change"]["actions"]


if __name__ == "__main__":
    unittest.main()
