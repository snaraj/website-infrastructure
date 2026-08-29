"""Prove Cloudflare state, plan, audit, and target boundaries stay staged."""

import copy
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import load_script, required_tool


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
BASH_REQUIRED = "Bash is required for blocker behavior"
if BASH is None and os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)

PHASES = (
    "admin-tunnel",
    "admin-policies",
    "admin-route",
    "admin-api",
    "site-naranjo-online",
    "site-lidersea-com",
)

SITE_PHASES = ("site-naranjo-online", "site-lidersea-com")

ZONE_SETTING_TARGETS = (
    ("always_use_https", "on"),
    ("min_tls_version", "1.2"),
    ("tls_1_3", "on"),
    ("zero_rtt", "off"),
    ("http3", "on"),
    ("ssl", "full"),
)

SITE_IDENTITY = {
    "site-naranjo-online": {
        "slug": "naranjo_online",
        "tunnel_name": "naranjo-online",
        "hostname": "naranjo.online",
        "origin": "http://naranjo-online.naranjo-online.svc.cluster.local:8080",
        "foreign_marker": "lidersea",
    },
    "site-lidersea-com": {
        "slug": "lidersea_com",
        "tunnel_name": "lidersea-com",
        "hostname": "lidersea.com",
        "origin": "http://lidersea-com.lidersea-com.svc.cluster.local:8080",
        "foreign_marker": "naranjo",
    },
}

EXPECTED_RESOURCES = {
    "admin-tunnel": {"cloudflare_zero_trust_tunnel_cloudflared.pi_admin"},
    "admin-policies": {
        "cloudflare_zero_trust_gateway_policy.pi_admin_block",
        "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow",
    },
    "admin-route": {"cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin"},
    "admin-api": {"cloudflare_zero_trust_gateway_policy.pi_admin_api_allow"},
}
for _phase, _identity in SITE_IDENTITY.items():
    _slug = _identity["slug"]
    EXPECTED_RESOURCES[_phase] = {
        "cloudflare_zero_trust_tunnel_cloudflared." + _slug,
        "cloudflare_zero_trust_tunnel_cloudflared_config." + _slug,
        "cloudflare_dns_record.{}_apex".format(_slug),
    } | {
        "cloudflare_zone_setting.{}_{}".format(_slug, _key)
        for _key, _value in ZONE_SETTING_TARGETS
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

    def test_exactly_six_nonempty_phase_roots_exist(self):
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
        # The shared fail-closed floor rather than a local re-implementation
        # of it: one helper, one message shape, one place to fix (issue #51).
        bash = required_tool(BASH, BASH_REQUIRED)
        result = subprocess.run(
            [bash, str(REPO_ROOT / "scripts" / "cloudflare-audit.sh")],
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
        for phase in SITE_PHASES:
            with self.subTest(phase=phase):
                text = (PHASE_ROOT / phase / "main.tf").read_text(
                    encoding="utf-8"
                )
                self.assertNotIn(
                    "cloudflare_zero_trust_tunnel_cloudflared_route", text
                )
                self.assertNotIn("cloudflare_zero_trust_gateway_policy", text)

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

    def test_each_site_root_is_one_tunnel_one_apex_and_no_other_site(self):
        """One website per root: its own Tunnel, its own apex, nothing shared.

        The superseded design put both sites behind one ``pi-websites`` Tunnel,
        so one compromised or rate-limited object reached both zones. These
        assertions are the textual half of that separation; the policy matrix
        in ``scripts/test-cloudflare-policy.sh`` is the behavioural half.
        """

        for phase in SITE_PHASES:
            identity = SITE_IDENTITY[phase]
            with self.subTest(phase=phase):
                text = (PHASE_ROOT / phase / "main.tf").read_text(
                    encoding="utf-8"
                )
                self.assertIn('name       = "{}"'.format(identity["tunnel_name"]), text)
                self.assertIn('hostname = "{}"'.format(identity["hostname"]), text)
                self.assertIn('service  = "{}"'.format(identity["origin"]), text)
                self.assertIn("http_status:404", text)
                self.assertLess(
                    text.index(identity["origin"]),
                    text.index("http_status:404"),
                )
                self.assertEqual(text.count("hostname ="), 1)
                self.assertNotIn("*.", text)
                # No cross-site reference of any kind, in any file of the root.
                for path in sorted((PHASE_ROOT / phase).glob("*")):
                    if path.name == ".terraform.lock.hcl":
                        continue
                    self.assertNotIn(
                        identity["foreign_marker"],
                        path.read_text(encoding="utf-8"),
                        "cross-site reference in " + str(path),
                    )

    def test_each_site_root_encodes_the_zone_security_target_state(self):
        """The five settings, their exact values, and no strict SSL variant."""

        for phase in SITE_PHASES:
            identity = SITE_IDENTITY[phase]
            text = (PHASE_ROOT / phase / "main.tf").read_text(encoding="utf-8")
            for key, value in ZONE_SETTING_TARGETS:
                with self.subTest(phase=phase, setting=key):
                    self.assertIn(
                        'resource "cloudflare_zone_setting" "{}_{}" {{'.format(
                            identity["slug"], key
                        ),
                        text,
                    )
                    self.assertIn('value      = "{}"'.format(value), text)
            self.assertEqual(
                text.count('resource "cloudflare_zone_setting"'),
                len(ZONE_SETTING_TARGETS),
            )
            # Strict origin pull would break a plain-HTTP origin leg, and
            # Cloudflare-managed HSTS would fight the application's header.
            self.assertNotIn('"strict"', text)
            self.assertNotIn("security_header", text)
            self.assertNotIn("automatic_https_rewrites", text)

    def test_site_roots_adopt_and_never_create_or_destroy(self):
        """The plan policy must refuse a create, a delete, and a replacement."""

        for fragment in (
            "adopt_only_phases",
            "create_only_phases",
            'adoption_action(actions) if {',
            'actions == ["no-op"]',
            'actions == ["update"]',
            "site roots must never create a live object",
            "adopted Tunnel and apex identity must plan as no-op",
            '"delete" in change.change.actions',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, POLICY)
        # Reviewer finding F1: a third clause admitting ["create"] passed the
        # whole suite, because the only create-shaped fixture also nulled its
        # prior object and the before-null denial masked the weakening. The
        # clause count is pinned, and the create-with-prior-object fixture is
        # the behavioural half of the same guard.
        self.assertEqual(POLICY.count("adoption_action(actions) if {"), 2)
        self.assertIn("create-with-prior-object", POLICY_TEST)
        self.assertIn('"create-with-prior-object"', MUTATOR)

    def test_apex_and_config_are_bound_to_the_planned_tunnel_value(self):
        """A reference-only binding accepts a forged plan (reviewer F2).

        The plan JSON is exactly what this policy adjudicates, so the apex
        content and the configuration's tunnel id must equal the Tunnel's
        PLANNED id, not merely reference the right address.
        """

        self.assertIn(
            'apex.content == sprintf("%s.cfargotunnel.com", [tunnel_id])', POLICY
        )
        self.assertIn("edge.tunnel_id == tunnel_id", POLICY)
        self.assertIn('tunnel_id := object.get(tunnel, "id", "")', POLICY)
        for mutation in ("apex-foreign-tunnel-uuid", "config-foreign-tunnel-uuid"):
            with self.subTest(mutation=mutation):
                self.assertIn(mutation, POLICY_TEST)

    def test_token_receipt_matrix_lists_exactly_the_tracked_phase_roots(self):
        """An operator minting from a stale table gets the wrong scope.

        Reviewer finding F4. The runbook's phase column is bound to the tracked
        root inventory so the ceremony reconciliation (issue #82) has to move
        it in lockstep rather than leaving an under-scoped row behind.
        """

        receipt = (
            REPO_ROOT / "docs" / "runbooks" / "cloudflare-token-receipt.md"
        ).read_text(encoding="utf-8")
        rows = re.findall(r"(?m)^\| `([a-z0-9-]+)` \|", receipt)
        self.assertTrue(rows, "fail closed: no phase rows found in the matrix")
        tracked = {
            path.name for path in PHASE_ROOT.iterdir() if path.is_dir()
        }
        # `audit` is the read-only token, not a phase root.
        self.assertEqual(set(rows) - {"audit"}, tracked)
        self.assertIn("audit", rows)
        for phase in ("site-naranjo-online", "site-lidersea-com"):
            with self.subTest(phase=phase):
                row = next(line for line in receipt.splitlines()
                           if line.startswith("| `" + phase + "`"))
                self.assertIn("Zone Settings Write", row)
                self.assertIn("DNS Write", row)
        self.assertIn("#82", receipt)

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
            "phase in adopt_only_phases",
            "site_root_exact(phase)",
            "origin address records are forbidden",
            "wildcard DNS names are forbidden",
            "wildcard Tunnel hostnames are forbidden",
            "WARP or private routing is forbidden on a public Tunnel",
            "private routes are forbidden in a public site root",
            "cross-site value is forbidden in",
            "cross-site ingress value is forbidden in",
            "cross-site reference is forbidden in",
            "zone setting %s must equal %v in %s",
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
        if receipt_schema is None:
            self.fail(
                "the plan gate no longer declares expected_receipt_keys; the "
                "receipt schema assertions below would silently vanish"
            )
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
            "six",
            "site-naranjo-online",
            "site-lidersea-com",
        ):
            self.assertIn(fragment.lower(), README.lower())

    def test_every_declared_mutation_executes_from_its_phase_fixture(self):
        """Every mutation the shell driver names must really mutate its fixture.

        Both call shapes are covered: the explicit ``phase mutation`` lines and
        the loop-expanded ``"${phase}" mutation`` lines. Missing the loops would
        leave the whole website-adoption matrix — the majority of the driver —
        unproved on this side of the gate.
        """

        module = load_script(
            "mutate_cloudflare_fixture.py", module_name="cloudflare_mutator"
        )
        declared = set()
        for phases, body in re.findall(
            r"(?ms)^for phase in ([a-z0-9 -]+); do\n(.*?)^done$", POLICY_TEST
        ):
            for mutation in re.findall(
                r'(?m)^\s*assert_mutation_denied "\$\{phase\}" ([a-z0-9-]+)$',
                body,
            ):
                for phase in phases.split():
                    declared.add((phase, mutation))
        for phase, mutation in re.findall(
            r"(?m)^\s*assert_mutation_denied ([a-z0-9-]+) ([a-z0-9-]+)$",
            POLICY_TEST,
        ):
            declared.add((phase, mutation))

        self.assertGreater(len(declared), 100)
        for phase in PHASES:
            with self.subTest(phase=phase):
                self.assertTrue(
                    any(declared_phase == phase for declared_phase, _ in declared),
                    "no mutation exercises " + phase,
                )
        for phase, mutation in sorted(declared):
            with self.subTest(phase=phase, mutation=mutation):
                mutated = copy.deepcopy(self.fixtures[phase])
                module.mutate(mutated, mutation)
                self.assertNotEqual(mutated, self.fixtures[phase])


if __name__ == "__main__":
    unittest.main()
