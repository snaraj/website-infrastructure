"""Prove Cloudflare plans and live audits bind both public zones exactly."""

import copy
import importlib.util
import json
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLOUDFLARE_ROOT = REPO_ROOT / "infrastructure" / "cloudflare"
FIXTURE = CLOUDFLARE_ROOT / "tests" / "fixtures" / "allow-plan.json"
POLICY = CLOUDFLARE_ROOT / "policy" / "cloudflare-plan.rego"
VARIABLES = CLOUDFLARE_ROOT / "variables.tf"
DNS = CLOUDFLARE_ROOT / "dns.tf"
TFVARS_EXAMPLE = CLOUDFLARE_ROOT / "terraform.tfvars.example"
README = CLOUDFLARE_ROOT / "README.md"
AUDIT = REPO_ROOT / "scripts" / "cloudflare-audit.sh"
PLAN_GATE = REPO_ROOT / "scripts" / "cloudflare-plan-gate.sh"
MUTATOR = REPO_ROOT / "scripts" / "mutate_cloudflare_fixture.py"
POLICY_TEST = REPO_ROOT / "scripts" / "test-cloudflare-policy.sh"


class CloudflareTargetBindingContractTests(unittest.TestCase):
    """Keep zero-spend evidence bound to one account and two named zones."""

    @classmethod
    def setUpClass(cls):
        """Load synthetic evidence and policy sources without external APIs."""

        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.policy = POLICY.read_text(encoding="utf-8")
        cls.variables = VARIABLES.read_text(encoding="utf-8")
        cls.dns = DNS.read_text(encoding="utf-8")
        cls.tfvars_example = TFVARS_EXAMPLE.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")
        cls.audit = AUDIT.read_text(encoding="utf-8")
        cls.plan_gate = PLAN_GATE.read_text(encoding="utf-8")
        cls.mutator = MUTATOR.read_text(encoding="utf-8")
        cls.policy_test = POLICY_TEST.read_text(encoding="utf-8")

    def test_allowed_fixture_has_one_account_and_two_distinct_zones(self):
        """The positive fixture must model three labelled fingerprint inputs."""

        changes = self.fixture["resource_changes"]
        self.assertEqual(len(changes), 8)
        account_ids = {
            change["change"]["after"]["account_id"]
            for change in changes
            if change["type"]
            in {
                "cloudflare_zero_trust_gateway_policy",
                "cloudflare_zero_trust_tunnel_cloudflared",
                "cloudflare_zero_trust_tunnel_cloudflared_config",
                "cloudflare_zero_trust_tunnel_cloudflared_route",
            }
        }
        zone_ids = {
            change["change"]["after"]["zone_id"]
            for change in changes
            if change["type"] == "cloudflare_dns_record"
        }
        self.assertEqual(len(account_ids), 1)
        self.assertEqual(len(zone_ids), 2)
        for identifier in account_ids | zone_ids:
            self.assertRegex(identifier, r"^[0-9a-f]{32}$")
        self.assertTrue(account_ids.isdisjoint(zone_ids))

    def test_configuration_references_only_reviewed_target_variables(self):
        """Literal, swapped, or cross-wired opaque targets must be impossible."""

        resources = self.fixture["configuration"]["root_module"]["resources"]
        self.assertEqual(len(resources), 8)
        zone_references = {
            "cloudflare_dns_record.naranjo_online": [
                "var.cloudflare_naranjo_online_zone_id"
            ],
            "cloudflare_dns_record.lidersea_com": [
                "var.cloudflare_lidersea_com_zone_id"
            ],
        }
        for resource in resources:
            expressions = resource["expressions"]
            if resource["type"] == "cloudflare_dns_record":
                self.assertEqual(
                    expressions["zone_id"]["references"],
                    zone_references[resource["address"]],
                )
                content_references = expressions["content"]["references"]
                self.assertIn(
                    "cloudflare_zero_trust_tunnel_cloudflared.pi_websites",
                    content_references,
                )
                self.assertTrue(
                    all(
                        reference.startswith(
                            "cloudflare_zero_trust_tunnel_cloudflared.pi_websites"
                        )
                        for reference in content_references
                    )
                )
            else:
                self.assertEqual(
                    expressions["account_id"]["references"],
                    ["var.cloudflare_account_id"],
                )

    def test_fixture_pins_ingress_order_dns_and_one_public_tunnel(self):
        """Both domains must share the exact ordered pi-websites edge route."""

        changes = {
            change["address"]: change["change"]["after"]
            for change in self.fixture["resource_changes"]
        }
        self.assertEqual(
            changes[
                "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites[0]"
            ]["config"]["ingress"],
            [
                {
                    "hostname": "naranjo.online",
                    "service": "http://naranjo-online.naranjo-online.svc.cluster.local:8080",
                },
                {
                    "hostname": "lidersea.com",
                    "service": "http://lidersea-com.lidersea-com.svc.cluster.local:8080",
                },
                {"service": "http_status:404"},
            ],
        )
        for address, hostname in (
            ("cloudflare_dns_record.naranjo_online[0]", "naranjo.online"),
            ("cloudflare_dns_record.lidersea_com[0]", "lidersea.com"),
        ):
            dns = changes[address]
            self.assertEqual(dns["name"], hostname)
            self.assertEqual(dns["type"], "CNAME")
            self.assertIs(dns["proxied"], True)
            self.assertEqual(dns["ttl"], 1)
        public_tunnels = [
            change
            for change in self.fixture["resource_changes"]
            if change["type"] == "cloudflare_zero_trust_tunnel_cloudflared"
            and change["change"]["after"]["name"] == "pi-websites"
        ]
        self.assertEqual(len(public_tunnels), 1)

    def test_variables_are_sensitive_distinct_and_fail_closed(self):
        """Two exact zone inputs replace the ambiguous old one-zone interface."""

        for variable_name in (
            "cloudflare_account_id",
            "cloudflare_naranjo_online_zone_id",
            "cloudflare_lidersea_com_zone_id",
        ):
            block = re.search(
                rf'variable "{variable_name}" \{{(?P<body>.*?)\n\}}',
                self.variables,
                re.DOTALL,
            )
            self.assertIsNotNone(block)
            self.assertIn("sensitive   = true", block.group("body"))
            self.assertIn(variable_name, self.tfvars_example)
        self.assertNotIn('variable "cloudflare_zone_id"', self.variables)
        self.assertIn("default     = false", self.variables)
        self.assertIn(
            "var.cloudflare_naranjo_online_zone_id != var.cloudflare_lidersea_com_zone_id",
            (CLOUDFLARE_ROOT / "tunnels.tf").read_text(encoding="utf-8"),
        )

    def test_policy_pins_domains_origins_and_target_shape(self):
        """The Rego contract must name both sites and all eight instances."""

        for fragment in (
            'canonical_naranjo_online_hostname := "naranjo.online"',
            'canonical_naranjo_online_origin := "http://naranjo-online.naranjo-online.svc.cluster.local:8080"',
            'canonical_lidersea_com_hostname := "lidersea.com"',
            'canonical_lidersea_com_origin := "http://lidersea-com.lidersea-com.svc.cluster.local:8080"',
            '"cloudflare_dns_record.naranjo_online": "var.cloudflare_naranjo_online_zone_id"',
            '"cloudflare_dns_record.lidersea_com":    "var.cloudflare_lidersea_com_zone_id"',
            "count(managed_changes) != 8",
            "count(zone_target_ids) != 2",
            "has_only_reference_tree",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.policy)

    def test_audit_and_plan_gate_hash_identical_labelled_material(self):
        """Fingerprints bind domain labels without printing raw target IDs."""

        hash_material = (
            "account=%s\\npublic_domain[lidersea.com]=%s\\n"
            "public_domain[naranjo.online]=%s\\n"
        )
        self.assertIn(hash_material, self.audit)
        self.assertIn(hash_material, self.plan_gate)
        for env_name in (
            "CLOUDFLARE_NARANJO_ONLINE_ZONE_ID",
            "CLOUDFLARE_LIDERSEA_COM_ZONE_ID",
        ):
            self.assertIn(env_name, self.audit)
        for address, hostname in (
            ("cloudflare_dns_record.naranjo_online[0]", "naranjo.online"),
            ("cloudflare_dns_record.lidersea_com[0]", "lidersea.com"),
        ):
            self.assertIn(
                f'select(.address == "{address}")',
                self.plan_gate,
            )
            self.assertIn(
                f'select(.change.after.name == "{hostname}")',
                self.plan_gate,
            )
        for source in (self.audit, self.plan_gate):
            self.assertIn("target_binding_sha256=%s", source)
            self.assertIsNone(
                re.search(r"printf[^\n]*(account_id|zone_id)=%", source, re.IGNORECASE)
            )

    def test_audit_hard_gates_exact_named_free_zones_and_subscriptions(self):
        """A broad account query must prove names, IDs, account, and Free state."""

        for fragment in (
            'map(.name) | sort) == ["lidersea.com", "naranjo.online"]',
            "all(.result[]; .account.id == env.CLOUDFLARE_ACCOUNT_ID)",
            'all(.result[]; .status == "active")',
            '.result.rate_plan.id == "free"',
            ".result.price == 0",
            "id_name_account_binding=verified",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.audit)

    def test_large_media_is_no_go_while_ordinary_sites_remain_audited(self):
        """Technical cache eligibility must not be presented as permission."""

        self.assertIn("Large-media delivery is a fail-closed **NO-GO**", self.readme)
        self.assertIn("ordinary sites remain technically in scope", self.readme)
        self.assertIn("large-media delivery is NO-GO", self.audit)
        self.assertIn("Large-media delivery remains a Free-plan NO-GO", self.plan_gate)

    def test_negative_suite_covers_every_target_misdirection_class(self):
        """Missing, extra, duplicate, swapped, literal, and unknown plans fail."""

        names = (
            "cross-account-target",
            "wrong-account-variable",
            "literal-account-target",
            "missing-account-target",
            "unknown-account-target",
            "wrong-zone-variable",
            "wrong-lidersea-zone-variable",
            "swapped-zone-variables",
            "literal-zone-target",
            "missing-zone-target",
            "unknown-zone-target",
            "duplicate-zone-target",
            "malformed-zone-target",
            "zone-equals-account-target",
            "wrong-lidersea-cname-tunnel",
            "wrong-lidersea-cname-attribute",
            "missing-dns-record",
            "duplicate-dns-record",
            "extra-dns-record",
            "extra-public-tunnel",
            "swapped-public-ingress",
            "wrong-lidersea-origin",
            "nonterminal-catchall",
            "duplicate-ingress-hostname",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertIn(f'elif name == "{name}"', self.mutator)
                self.assertIn(f"assert_mutation_denied {name}", self.policy_test)

    def test_every_declared_mutation_executes_from_the_allow_fixture(self):
        """A renamed address must not silently break negative-plan generation."""

        spec = importlib.util.spec_from_file_location("cloudflare_mutator", MUTATOR)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        names = re.findall(
            r"^assert_mutation_denied ([a-z0-9-]+)$",
            self.policy_test,
            re.MULTILINE,
        )
        self.assertGreater(len(names), 20)
        for name in names:
            with self.subTest(name=name):
                mutated = copy.deepcopy(self.fixture)
                module.mutate(mutated, name)
                self.assertNotEqual(mutated, self.fixture)


if __name__ == "__main__":
    unittest.main()
