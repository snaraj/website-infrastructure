"""Prove Cloudflare state, plan, audit, and target boundaries stay staged."""

import copy
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
CLOUDFLARE_ROOT = REPO_ROOT / "infrastructure" / "cloudflare"
PHASE_ROOT = CLOUDFLARE_ROOT / "phases"
FIXTURE_ROOT = CLOUDFLARE_ROOT / "tests" / "fixtures"
POLICY = (CLOUDFLARE_ROOT / "policy" / "cloudflare-plan.rego").read_text(
    encoding="utf-8"
)
COST_POLICY = (
    CLOUDFLARE_ROOT / "policy" / "cloudflare-cost-policy.yaml"
).read_text(encoding="utf-8")
README = (CLOUDFLARE_ROOT / "README.md").read_text(encoding="utf-8")
AUDIT = (REPO_ROOT / "scripts" / "cloudflare-audit.sh").read_text(
    encoding="utf-8"
)
PLAN_GATE = (REPO_ROOT / "scripts" / "cloudflare-plan-gate.sh").read_text(
    encoding="utf-8"
)
PREAPPLY_VALIDATOR = (
    REPO_ROOT / "scripts" / "validate_cloudflare_preapply_evidence.py"
).read_text(encoding="utf-8")
MUTATOR_PATH = REPO_ROOT / "scripts" / "mutate_cloudflare_fixture.py"
MUTATOR = MUTATOR_PATH.read_text(encoding="utf-8")
POLICY_TEST = (REPO_ROOT / "scripts" / "test-cloudflare-policy.sh").read_text(
    encoding="utf-8"
)
IAC_VALIDATOR = (REPO_ROOT / "scripts" / "validate-cloudflare-iac.sh").read_text(
    encoding="utf-8"
)
MAKEFILE = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
PULL_REQUEST_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "pull-request.yml"
).read_text(encoding="utf-8")
BASH = shutil.which("bash")
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)

PHASES = (
    "admin-tunnel",
    "admin-policies",
    "admin-route",
    "admin-api",
    "public-edge",
    "public-dns-naranjo",
    "public-dns-lidersea",
)

EXPECTED_RESOURCES = {
    "admin-tunnel": {"cloudflare_zero_trust_tunnel_cloudflared.pi_admin"},
    "admin-policies": {
        "cloudflare_zero_trust_gateway_policy.pi_admin_block",
        "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow",
    },
    "admin-route": {"cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin"},
    "admin-api": {"cloudflare_zero_trust_gateway_policy.pi_admin_api_allow"},
    "public-edge": {
        "cloudflare_zero_trust_tunnel_cloudflared.pi_websites",
        "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites",
    },
    "public-dns-naranjo": {"cloudflare_dns_record.naranjo_online"},
    "public-dns-lidersea": {"cloudflare_dns_record.lidersea_com"},
}


class CloudflareTargetBindingContractTests(unittest.TestCase):
    """Keep every irreversible Cloudflare step behind an independent gate."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = {
            phase: json.loads(
                (FIXTURE_ROOT / ("allow-" + phase + ".json")).read_text(
                    encoding="utf-8"
                )
            )
            for phase in PHASES
        }

    def test_exactly_seven_nonempty_phase_roots_exist(self):
        observed = {
            path.name
            for path in PHASE_ROOT.iterdir()
            if path.is_dir() and any(path.glob("*.tf"))
        }
        self.assertEqual(observed, set(PHASES))

    def test_each_phase_has_its_own_pinned_backend_and_lock(self):
        self.assertFalse((CLOUDFLARE_ROOT / ".terraform.lock.hcl").exists())
        for phase in PHASES:
            with self.subTest(phase=phase):
                root = PHASE_ROOT / phase
                versions = (root / "versions.tf").read_text(encoding="utf-8")
                lock = (root / ".terraform.lock.hcl").read_text(encoding="utf-8")
                self.assertIn('required_version = "= 1.12.5"', versions)
                self.assertIn('version = "5.22.0"', versions)
                self.assertIn('backend "local" {}', versions)
                self.assertIn('provider "cloudflare" {}', versions)
                self.assertIn('version     = "5.22.0"', lock)

    def test_ci_validates_every_phase_without_credentials_or_repo_cache(self):
        self.assertIn("./scripts/validate-cloudflare-iac.sh", MAKEFILE)
        self.assertIn("./scripts/validate-cloudflare-iac.sh", PULL_REQUEST_WORKFLOW)
        self.assertNotIn(
            "tofu -chdir=infrastructure/cloudflare init", PULL_REQUEST_WORKFLOW
        )
        for phase in PHASES:
            with self.subTest(phase=phase):
                self.assertIn(phase, IAC_VALIDATOR)
        for fragment in (
            "CLOUDFLARE_API_TOKEN",
            "TF_DATA_DIR",
            "-backend=false",
            "-input=false",
            "-lockfile=readonly",
            "validate_repository.py\" cloudflare",
            "test-cloudflare-policy.sh",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, IAC_VALIDATOR)
        self.assertNotIn("tofu plan", IAC_VALIDATOR)
        self.assertNotIn("tofu apply", IAC_VALIDATOR)

    @unittest.skipUnless(BASH, "Bash is required for blocker behavior")
    def test_authenticated_audit_is_blocked_before_token_or_network_access(self):
        blocker = (
            "BLOCKED authenticated Cloudflare audit requires the trusted "
            "reviewed-blob launcher; no API token was read and no network request "
            "was attempted.\n"
        )
        self.assertTrue(AUDIT.startswith("#!/bin/bash\n"))
        self.assertIn("readonly REVIEWED_BLOB_LAUNCHER_AVAILABLE=no", AUDIT)
        self.assertLess(AUDIT.index("BLOCKED authenticated Cloudflare audit"), AUDIT.index("required=("))
        self.assertLess(AUDIT.index("BLOCKED authenticated Cloudflare audit"), AUDIT.index("CLOUDFLARE_API_TOKEN:?"))
        result = subprocess.run(
            [BASH, str(REPO_ROOT / "scripts" / "cloudflare-audit.sh")],
            capture_output=True,
            check=False,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, blocker)

    def test_no_global_count_switch_or_cross_phase_resource_graph(self):
        all_phase_text = ""
        for phase in PHASES:
            text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((PHASE_ROOT / phase).glob("*.tf"))
            )
            all_phase_text += text
            self.assertNotRegex(text, r"(?m)^\s*count\s*=")
            self.assertNotIn("enable_cloudflare_resources", text)
            self.assertIn("prevent_destroy = true", text)
        self.assertNotIn("admin-control/", README)
        self.assertNotIn("public-dns/", README)
        self.assertNotIn("cloudflare_zero_trust_tunnel_cloudflared_route", (
            PHASE_ROOT / "admin-policies" / "main.tf"
        ).read_text(encoding="utf-8"))
        self.assertNotIn("cloudflare_dns_record", (
            PHASE_ROOT / "public-edge" / "main.tf"
        ).read_text(encoding="utf-8"))

    def test_admin_policies_precede_route_and_api_is_separate(self):
        policies = (PHASE_ROOT / "admin-policies" / "main.tf").read_text(
            encoding="utf-8"
        )
        route = (PHASE_ROOT / "admin-route" / "main.tf").read_text(
            encoding="utf-8"
        )
        api = (PHASE_ROOT / "admin-api" / "main.tf").read_text(
            encoding="utf-8"
        )
        self.assertIn("net.dst.port in {22}", policies)
        self.assertNotIn("6443", policies)
        self.assertIn("verified_admin_policies_contract_sha256", route)
        self.assertIn("verified_admin_posture_contract_sha256", policies)
        self.assertIn("verified block and SSH-only allow required", route)
        self.assertIn("net.dst.port in {6443}", api)
        self.assertIn("enable_kubernetes_api_access", api)
        self.assertIn("verified_admin_route_contract_sha256", api)
        self.assertIn("verified_admin_api_inputs_contract_sha256", api)

    def test_dns_is_one_zone_per_state_and_public_edge_is_terminal(self):
        edge = (PHASE_ROOT / "public-edge" / "main.tf").read_text(encoding="utf-8")
        self.assertIn("http_status:404", edge)
        self.assertLess(edge.index("naranjo.online"), edge.index("lidersea.com"))
        self.assertLess(edge.index("lidersea.com"), edge.index("http_status:404"))
        for phase, expected, forbidden in (
            ("public-dns-naranjo", "naranjo.online", "lidersea.com"),
            ("public-dns-lidersea", "lidersea.com", "naranjo.online"),
        ):
            text = (PHASE_ROOT / phase / "main.tf").read_text(encoding="utf-8")
            self.assertIn(expected, text)
            self.assertNotIn(forbidden, text)
            self.assertIn("verified_public_edge_contract_sha256", text)

    def test_allow_fixtures_exactly_match_phase_graphs(self):
        for phase, fixture in self.fixtures.items():
            with self.subTest(phase=phase):
                self.assertEqual(fixture["codex_contract"]["phase"], phase)
                planned = {change["address"] for change in fixture["resource_changes"]}
                configured = {
                    resource["address"]
                    for resource in fixture["configuration"]["root_module"][
                        "resources"
                    ]
                    if resource.get("mode", "managed") == "managed"
                }
                self.assertEqual(planned, EXPECTED_RESOURCES[phase])
                self.assertEqual(configured, EXPECTED_RESOURCES[phase])

    def test_rego_enforces_exact_arguments_sessions_and_deletion_denial(self):
        for fragment in (
            "expected_expression_fields :=",
            'object.keys(policy.rule_settings) == {"check_session"}',
            'object.keys(session) == {"enforce", "duration"}',
            '"delete" in change.change.actions',
            "critical field is unknown",
            "configured argument fields are not exact",
            'phase == "public-dns-naranjo"',
            'phase == "public-dns-lidersea"',
            'valid_contract_hash(variable_value("verified_admin_policy_inputs_contract_sha256"))',
            'valid_contract_hash(variable_value("verified_admin_api_inputs_contract_sha256"))',
            'change.change.actions != ["create"]',
            'count(configured_module_calls) != 0',
            'count(object.get(resource, "provisioners", [])) != 0',
            'count(configured_providers) != 1',
            'object.get(change, "mode", "managed") != "managed"',
            'object.keys(edge.config) == {"ingress"}',
        ):
            self.assertIn(fragment, POLICY)

    def test_plan_gate_binds_protected_custody_and_fresh_audit(self):
        for fragment in (
            "protected workspace",
            "TMPDIR",
            "phase_lock_sha256",
            "repo_commit",
            "state_lineage_sha256",
            "state_serial",
            "state_binding_sha256",
            "state_mode",
            "state_sha256",
            "backend_metadata_sha256",
            "manual_attestation_sha256",
            "validate_cloudflare_preapply_evidence.py",
            "stable_handle_snapshot",
            "Current-phase absent-state proof",
            "reviewed-manual-preapply-authorization",
            "pre_state_receipt_sha256",
            "workspace_attestation_sha256",
            "CLOUDFLARE_WORKSPACE_ATTESTATION_SHA256",
            "audit_result",
            "expected_audit_phase",
            "audit_age_seconds",
            "CLOUDFLARE_AUDIT_MAX_AGE_SECONDS",
            "public_dns_naranjo_binding_sha256",
            "public_dns_lidersea_binding_sha256",
            "predecessor_post_audit_sha256",
            "predecessor_token_receipt_sha256",
            "predecessor_token_validation_sha256",
            "Naranjo post-audit must follow revocation/rejection verification",
            "pre-apply-state-evidence.txt",
            "pre-state-receipt.txt",
            "expected_naranjo_absent_inventory",
            "expected_naranjo_present_inventory",
            "predecessor_pre_state_receipt_sha256",
            "predecessor_state_evidence_sha256",
            "--state-binding-sha256",
            "--post-audit-sha256",
            "PASS Cloudflare predecessor pre-state evidence",
            "PASS Cloudflare post-audit chronology",
            "stable_snapshot",
            "validate-windows-credential-workspace.ps1",
            "powershell.exe",
            "admin_policy_inputs_contract_sha256",
            "admin_api_inputs_contract_sha256",
            "admin-recovery-session-v1",
            "operator-attestation-plus-independent-challenges",
            "recovery_evidence_sha256",
            "assert_exact_kv_schema",
            "canonical_utc_epoch",
            "Naranjo transaction directory inventory",
            "validate_cloudflare_token_receipt.py",
            "--postflight-evidence-sha256",
            "assert_public_admin_path",
            "public-edge-preflight",
            "ls-files --others --",
            "assert_snapshot_still_matches",
            "CLOUDFLARE_API_TOKEN",
            "-RepositoryRoot",
            "-ProtectedFile",
            "protected_file_set_sha256",
            "validation_attestation_sha256",
        ):
            self.assertIn(fragment, PLAN_GATE)

        receipt_schema = re.search(
            r"expected_receipt_keys=\$'([^']+)'", PLAN_GATE
        )
        self.assertIsNotNone(receipt_schema)
        self.assertNotIn("state_lineage_sha256", receipt_schema.group(1))
        self.assertNotIn("state_serial", receipt_schema.group(1))
        self.assertIn("state_binding_sha256", receipt_schema.group(1))
        self.assertIn("state_evidence_sha256", receipt_schema.group(1))
        self.assertIn("manual_attestation_sha256", receipt_schema.group(1))
        self.assertIn(
            '"${audit_epoch}" -ge "${naranjo_revocation_epoch}"',
            PLAN_GATE,
        )
        self.assertNotIn(
            '"${naranjo_revocation_epoch}" -ge "${audit_epoch}"',
            PLAN_GATE,
        )
        self.assertIn("parse_backend_metadata", PREAPPLY_VALIDATOR)
        self.assertNotIn("requests", PREAPPLY_VALIDATOR)
        for fragment in (
            "currentPhaseStateStableHandleAndSha256: required-when-present",
            "unchangedParentAndAbsentLeafProof: required-for-first-create-absence",
            "callerAssertedLineageOrSerial: forbidden",
            "closedSchema: cloudflare-preapply-manual-v1",
            "substitutesForLiveTokenPreflight: false",
            "policyPassIsApplyAuthorization: false",
            "strict-current-phase-token-preflight-authorization-receipt",
        ):
            self.assertIn(fragment, COST_POLICY)

    def test_audit_mints_contracts_only_after_exact_live_evidence(self):
        for fragment in (
            "admin_policies_verified=true",
            "admin_route_verified=true",
            "public_edge_verified=true",
            "net.dst.port in {22}",
            "net.dst.port in {6443}",
            "devices/posture",
            "devices/policies",
            "devices/physical-devices",
            "api_get_single_page",
            "service_mode_v2.mode == \"warp\"",
            "apex_state=conflict",
            "admin_policies_contract_sha256",
            "admin_policy_inputs_contract_sha256",
            "admin_posture_contract_sha256",
            "admin_route_contract_sha256",
            "admin_api_inputs_contract_sha256",
            "public_edge_contract_sha256",
            "pi_admin_tunnel_activation_state",
            "gateway_l4_inventory_count",
            "gateway_policy_inventory_count",
            "pi_admin_api_policy_activation_state",
            "public-edge-preflight",
            '(map(.id) | unique | length) == length',
            'verification_canonical',
            '.expiration == "5m" and .schedule == "5m"',
            "public_dns_naranjo_activation_state",
            "public_dns_lidersea_activation_state",
            'client_certificate_v2',
            'check_private_key',
            '${serial_number}',
            '((.identity // "") == "")',
            '((.rule_settings // {}) | compact_settings) == {}',
            "audit_result=pass",
            "/accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/verify",
        ):
            self.assertIn(fragment, AUDIT)

    def test_docs_admit_provider_permission_reach_and_require_jit_compensation(self):
        for fragment in (
            "cannot be restricted",
            "JIT",
            "source-IP",
            "revocation",
            "seven",
            "public-dns-naranjo",
            "public-dns-lidersea",
        ):
            self.assertIn(fragment.lower(), README.lower())

    def test_every_declared_mutation_executes_from_its_phase_fixture(self):
        module = load_script(
            "mutate_cloudflare_fixture.py", module_name="cloudflare_mutator"
        )
        calls = re.findall(
            r'^\s*assert_mutation_denied\s+(?:"\$\{phase\}"|([a-z0-9-]+))\s+([a-z0-9-]+)$',
            POLICY_TEST,
            re.MULTILINE,
        )
        self.assertGreater(len(calls), 30)
        # Explicit calls are sufficient here; shell policy validation exercises
        # the loop-expanded generic and per-zone cases.
        for phase, mutation in calls:
            if not phase:
                continue
            with self.subTest(phase=phase, mutation=mutation):
                mutated = copy.deepcopy(self.fixtures[phase])
                module.mutate(mutated, mutation)
                self.assertNotEqual(mutated, self.fixtures[phase])


if __name__ == "__main__":
    unittest.main()
