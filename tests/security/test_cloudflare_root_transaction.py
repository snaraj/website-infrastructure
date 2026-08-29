"""Hostile tests for the root-owned pie5 Cloudflare transaction boundary."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from scripts import cloudflare_root_transaction as transaction


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_PATH = ROOT / "scripts" / "cloudflare-reviewed-launcher.sh"
LAUNCHER = LAUNCHER_PATH.read_text(encoding="utf-8")
ENGINE = (ROOT / "scripts" / "cloudflare_root_transaction.py").read_text(
    encoding="utf-8"
)
AUDIT = (ROOT / "scripts" / "cloudflare-audit.sh").read_text(encoding="utf-8")
RUNBOOK = (ROOT / "docs" / "runbooks" / "cloudflare-owner-admin-launcher.md").read_text(
    encoding="utf-8"
)


def _identifier(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()[:32]


def _context() -> dict[str, object]:
    jit_ids = {
        phase: _identifier("jit:" + transaction.JIT_PERMISSION_NAMES[phase])
        for phase in transaction.PHASES
    }
    audit_ids = {
        name: _identifier("audit:" + name)
        for name in transaction.AUDIT_PERMISSION_SCOPES
    }
    return {
        "schema": "pie5-cloudflare-owner-admin-v1",
        "account_id": "1" * 32,
        "owner_user_id": "a" * 32,
        "zone_ids": {"naranjo.online": "2" * 32, "lidersea.com": "3" * 32},
        "admin_email": "owner@example.invalid",
        "identity_provider_id": "12345678-" + "1234-4123-8123-123456789abc",
        "pi_admin_cidr": "192.168.50.10/32",
        "gateway": {
            "ssh_allow_precedence": 100,
            "block_precedence": 200,
            "session_freshness": "300s",
        },
        "jit_permission_group_ids": jit_ids,
        "audit_permission_group_ids": audit_ids,
        "owner_device_ca_certificate_sha256": "4" * 64,
        "audit_token_contract_sha256": "5" * 64,
    }


def _catalog(context: dict[str, object]) -> dict[str, object]:
    items: dict[str, dict[str, object]] = {}
    audit_ids = context["audit_permission_group_ids"]
    assert isinstance(audit_ids, dict)
    for name, identifier in audit_ids.items():
        items[str(identifier)] = {
            "id": identifier,
            "name": name,
            "scopes": [transaction.AUDIT_PERMISSION_SCOPES[str(name)]],
        }
    jit_ids = context["jit_permission_group_ids"]
    assert isinstance(jit_ids, dict)
    for phase, identifier in jit_ids.items():
        items[str(identifier)] = {
            "id": identifier,
            "name": transaction.JIT_PERMISSION_NAMES[str(phase)],
            "scopes": ["com.cloudflare.api.account"],
        }
    return {"success": True, "result": list(items.values())}


def _timestamps() -> tuple[dt.datetime, str, str, str]:
    now = dt.datetime(2026, 8, 29, 12, 0, tzinfo=dt.timezone.utc)
    issued = transaction.utc_text(now - dt.timedelta(minutes=2))
    not_before = transaction.utc_text(now - dt.timedelta(minutes=2))
    expires = transaction.utc_text(now + dt.timedelta(minutes=28))
    return now, issued, not_before, expires


def _audit_details(context: dict[str, object]) -> dict[str, object]:
    _, issued, not_before, expires = _timestamps()
    audit_ids = context["audit_permission_group_ids"]
    assert isinstance(audit_ids, dict)
    account_ids = [
        identifier
        for name, identifier in audit_ids.items()
        if transaction.AUDIT_PERMISSION_SCOPES[str(name)]
        == "com.cloudflare.api.account"
    ]
    zone_ids = [audit_ids["Zone Read"], audit_ids["DNS Read"]]
    user_ids = [audit_ids["API Tokens Read"]]
    account_id = context["account_id"]
    return {
        "success": True,
        "result": {
            "id": "6" * 32,
            "name": "website-infrastructure-read-only-audit",
            "status": "active",
            "issued_on": issued,
            "not_before": not_before,
            "expires_on": expires,
            "condition": {"request_ip": {"in": ["8.8.8.8/32"], "not_in": []}},
            "policies": [
                {
                    "effect": "allow",
                    "permission_groups": [{"id": item} for item in user_ids],
                    "resources": {
                        "com.cloudflare.api.user." + str(context["owner_user_id"]): "*"
                    },
                },
                {
                    "effect": "allow",
                    "permission_groups": [{"id": item} for item in account_ids],
                    "resources": {f"com.cloudflare.api.account.{account_id}": "*"},
                },
                {
                    "effect": "allow",
                    "permission_groups": [{"id": item} for item in zone_ids],
                    "resources": {
                        f"com.cloudflare.api.account.{account_id}": {
                            "com.cloudflare.api.account.zone.*": "*"
                        }
                    },
                },
            ],
        },
    }


def _api_for_audit(context: dict[str, object], details: dict[str, object]):
    def responder(_token: str, path: str) -> dict[str, object]:
        if path == "/user/tokens/verify":
            return {"success": True, "result": {"id": "6" * 32, "status": "active"}}
        if path == "/user/tokens/permission_groups":
            return _catalog(context)
        if path == "/user/tokens/" + "6" * 32:
            return details
        raise AssertionError(path)

    return responder


def _audit_entry(
    *,
    resource_id: str,
    action_type: str = "create",
    token_id: str = "6" * 32,
    account_id: str = "1" * 32,
) -> dict[str, object]:
    return {
        "id": _identifier(resource_id + action_type),
        "account": {"id": account_id},
        "action": {
            "result": "success",
            "time": "2026-08-29T12:00:05Z",
            "type": action_type,
        },
        "actor": {"context": "api_token", "token_id": token_id},
        "raw": {"status_code": 200},
        "resource": {"id": resource_id},
    }


class CloudflareTokenBoundaryTests(unittest.TestCase):
    def test_api_transport_rejects_every_redirect(self):
        handler = transaction.RejectRedirects()
        redirected = handler.redirect_request(
            transaction.urllib.request.Request(
                "https://api.cloudflare.com/client/v4/test"
            ),
            None,
            302,
            "redirect",
            {},
            "https://example.invalid/",
        )
        self.assertIsNone(redirected)
        for fragment in (
            "RejectRedirects()",
            "response.geturl() != expected_url",
            "urllib.request.ProxyHandler({})",
        ):
            self.assertIn(fragment, ENGINE)

    def test_context_requires_exact_read_and_write_permission_maps(self):
        context = _context()
        self.assertEqual(transaction.validate_context(context)["account_id"], "1" * 32)
        for mutation in (
            lambda value: value["audit_permission_group_ids"].pop("API Tokens Read"),
            lambda value: value["audit_permission_group_ids"].update(
                {"Unexpected Read": "8" * 32}
            ),
            lambda value: value["jit_permission_group_ids"].update(
                {"admin-route": value["audit_permission_group_ids"]["Billing Read"]}
            ),
            lambda value: value.update({"owner_user_id": "0" * 32}),
            lambda value: value["audit_permission_group_ids"].update(
                {"Billing Read": "0" * 32}
            ),
        ):
            hostile = copy.deepcopy(context)
            mutation(hostile)
            with self.subTest(hostile=hostile):
                with self.assertRaises(transaction.TransactionError):
                    transaction.validate_context(hostile)

    def test_audit_token_is_exact_read_only_scoped_and_bounded(self):
        context = _context()
        details = _audit_details(context)
        now, _, _, _ = _timestamps()
        with mock.patch.object(transaction, "utc_now", return_value=now):
            contract = transaction.canonical_token_contract(details, context)
            context["audit_token_contract_sha256"] = contract
            with mock.patch.object(
                transaction, "api_request", side_effect=_api_for_audit(context, details)
            ):
                self.assertEqual(
                    transaction.validate_audit_token("A" * 40, context), contract
                )

    def test_audit_token_rejects_scope_permission_ttl_and_source_mutations(self):
        context = _context()
        baseline = _audit_details(context)
        now, _, _, _ = _timestamps()
        mutations = {
            "write permission": lambda value: value["result"]["policies"][1][
                "permission_groups"
            ].append({"id": "f" * 32}),
            "all accounts": lambda value: value["result"]["policies"][1].update(
                {"resources": {"com.cloudflare.api.account.*": "*"}}
            ),
            "all global zones": lambda value: value["result"]["policies"][2].update(
                {"resources": {"com.cloudflare.api.account.zone.*": "*"}}
            ),
            "different user": lambda value: value["result"]["policies"][0].update(
                {"resources": {"com.cloudflare.api.user." + "7" * 32: "*"}}
            ),
            "no source restriction": lambda value: value["result"].update(
                {"condition": {}}
            ),
            "wide source": lambda value: value["result"].update(
                {"condition": {"request_ip": {"in": ["192.0.2.0/24"]}}}
            ),
            "long ttl": lambda value: value["result"].update(
                {"expires_on": "2026-08-29T13:30:00Z"}
            ),
            "unknown policy field": lambda value: value["result"]["policies"][1].update(
                {"unexpected": True}
            ),
            "unknown permission field": lambda value: value["result"]["policies"][1][
                "permission_groups"
            ][0].update({"name": "decoy"}),
        }
        for label, mutate in mutations.items():
            details = copy.deepcopy(baseline)
            mutate(details)
            with self.subTest(label=label), mock.patch.object(
                transaction, "utc_now", return_value=now
            ):
                with self.assertRaises(transaction.TransactionError):
                    transaction.canonical_token_contract(details, context)

    def test_permission_catalog_rejects_cosmetic_name_or_scope_rebinding(self):
        context = _context()
        catalog = _catalog(context)
        catalog["result"][0]["name"] = "API Tokens Write"
        with mock.patch.object(transaction, "api_request", return_value=catalog):
            with self.assertRaises(transaction.TransactionError):
                transaction.validate_permission_catalog("A" * 40, context)

    def test_all_zero_token_identity_is_rejected(self):
        self.assertFalse(transaction.valid_hex32_identifier("0" * 32))
        with self.assertRaises(transaction.TransactionError):
            transaction.validate_jit_token(
                phase="admin-route",
                token="A" * 40,
                token_id="0" * 32,
                audit_token="B" * 40,
                context=_context(),
            )

    def test_jit_token_is_one_fresh_account_scoped_permission(self):
        context = _context()
        now, issued, not_before, expires = _timestamps()
        token_id = "8" * 32
        phase = "admin-route"
        details = {
            "success": True,
            "result": {
                "id": token_id,
                "status": "active",
                "name": "website-infrastructure-admin-route-jit",
                "issued_on": issued,
                "not_before": not_before,
                "expires_on": expires,
                "condition": {"request_ip": {"in": ["8.8.8.8/32"]}},
                "policies": [
                    {
                        "effect": "allow",
                        "permission_groups": [
                            {"id": context["jit_permission_group_ids"][phase]}
                        ],
                        "resources": {
                            "com.cloudflare.api.account." + str(context["account_id"]): "*"
                        },
                    }
                ],
            },
        }

        def api(_token: str, path: str) -> dict[str, object]:
            if path == "/user/tokens/verify":
                return {"success": True, "result": {"id": token_id, "status": "active"}}
            return details

        with mock.patch.object(transaction, "utc_now", return_value=now), mock.patch.object(
            transaction, "api_request", side_effect=api
        ):
            receipt = transaction.validate_jit_token(
                phase=phase,
                token="A" * 40,
                token_id=token_id,
                audit_token="B" * 40,
                context=context,
            )
        self.assertEqual(receipt["source_scope"], "one-global-host")


class CloudflareJournalTests(unittest.TestCase):
    def test_every_phase_consumes_only_contracts_emitted_by_predecessors(self):
        results: dict[str, dict[str, object]] = {}
        context = _context()
        with mock.patch.object(
            transaction,
            "stable_read",
            return_value=b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
        ):
            for phase in transaction.PHASES:
                with self.subTest(phase=phase):
                    variables = transaction.build_tfvars(phase, context, results)
                    self.assertTrue(variables[f"approve_{phase.replace('-', '_')}_phase"])
                results[phase] = {
                    "ids": {
                        transaction.ID_KEY_BY_ADDRESS[address]: f"id-{index}-{phase}"
                        for index, address in enumerate(
                            transaction.EXPECTED_ADDRESSES[phase]
                        )
                    },
                    "contracts": {
                        key: hashlib.sha256((phase + key).encode()).hexdigest()
                        for key in transaction.CONTRACT_KEYS[phase]
                    },
                }

    def test_completed_result_has_exact_ids_contracts_and_revocation_evidence(self):
        phase = "admin-certificate"
        baseline = {
            "schema": "pie5-cloudflare-phase-result-v1",
            "phase": phase,
            "commit": "9" * 40,
            "ids": {"certificate_id": "resource-id"},
            "contracts": {"admin_certificate_contract_sha256": "7" * 64},
            "evidence": {
                "plan_sha256": "1" * 64,
                "pre_audit_sha256": "2" * 64,
                "post_audit_sha256": "3" * 64,
                "audit_log_receipt_sha256": "4" * 64,
                "jit_token_id_sha256": "5" * 64,
                "revocation": "bearer-and-metadata-inactive",
                "completed_at": "2026-08-29T12:00:00Z",
            },
        }
        with mock.patch.object(transaction, "load_json_file", return_value=baseline):
            self.assertEqual(transaction.load_result(phase)["phase"], phase)
        mutations = (
            lambda value: value["ids"].update({"decoy_id": "decoy"}),
            lambda value: value["contracts"].update(
                {"admin_certificate_contract_sha256": "0" * 64}
            ),
            lambda value: value["evidence"].update({"revocation": "claimed"}),
            lambda value: value["evidence"].pop("audit_log_receipt_sha256"),
        )
        for mutate in mutations:
            hostile = copy.deepcopy(baseline)
            mutate(hostile)
            with mock.patch.object(
                transaction, "load_json_file", return_value=hostile
            ), self.assertRaises(transaction.TransactionError):
                transaction.load_result(phase)

    def test_revocation_rejects_transient_or_ambiguous_api_failures(self):
        token_id = "8" * 32

        def server_error(_token: str, _path: str):
            raise transaction.APIError(500, b"")

        with mock.patch.object(transaction, "api_request", side_effect=server_error):
            with self.assertRaises(transaction.TransactionError):
                transaction.verify_revocation("A" * 40, token_id, "B" * 40)

        responses = [
            transaction.APIError(401, b""),
            transaction.APIError(403, b""),
        ]

        def ambiguous(_token: str, _path: str):
            raise responses.pop(0)

        with mock.patch.object(transaction, "api_request", side_effect=ambiguous):
            with self.assertRaises(transaction.TransactionError):
                transaction.verify_revocation("A" * 40, token_id, "B" * 40)

    def test_revocation_accepts_rejected_bearer_and_absent_metadata(self):
        responses = [
            transaction.APIError(401, b""),
            transaction.APIError(404, b""),
        ]

        def revoked(_token: str, _path: str):
            raise responses.pop(0)

        with mock.patch.object(transaction, "api_request", side_effect=revoked):
            transaction.verify_revocation("A" * 40, "8" * 32, "B" * 40)

    def test_runtime_token_emission_requires_exact_pending_tunnel_state(self):
        with mock.patch.object(transaction.os, "isatty", return_value=False), mock.patch.object(
            transaction,
            "load_pending",
            return_value={"status": "applying", "ids": {}},
        ):
            with self.assertRaises(transaction.TransactionError):
                transaction.emit_runtime_token()

    def test_status_rejects_orphaned_token_or_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending = root / "pending"
            phases = root / "phases"
            results = root / "results"
            pending.mkdir()
            phases.mkdir()
            results.mkdir()
            orphan = pending / "admin-certificate.jit-token"
            orphan.write_text("A" * 40)
            with mock.patch.object(transaction, "PENDING_ROOT", pending), mock.patch.object(
                transaction, "PHASES_ROOT", phases
            ), mock.patch.object(transaction, "RESULTS_ROOT", results), mock.patch.object(
                transaction, "ensure_state_tree"
            ):
                with self.assertRaises(transaction.TransactionError):
                    transaction.status()

    def test_saved_plan_rejects_duplicate_address_and_type_mismatch(self):
        phase = "admin-certificate"
        address = transaction.EXPECTED_ADDRESSES[phase][0]
        baseline = {
            "resource_changes": [
                {
                    "address": address,
                    "type": "cloudflare_mtls_certificate",
                    "change": {"actions": ["create"], "before": None},
                }
            ]
        }
        self.assertEqual(
            transaction.validate_plan(copy.deepcopy(baseline), phase),
            {address: "cloudflare_mtls_certificate"},
        )
        duplicate = copy.deepcopy(baseline)
        duplicate["resource_changes"].append(
            copy.deepcopy(duplicate["resource_changes"][0])
        )
        wrong_type = copy.deepcopy(baseline)
        wrong_type["resource_changes"][0]["type"] = "cloudflare_dns_record"
        for hostile in (duplicate, wrong_type):
            with self.assertRaises(transaction.TransactionError):
                transaction.validate_plan(hostile, phase)

    def test_fresh_pre_audit_must_equal_every_predecessor_contract(self):
        results = {
            "admin-certificate": {
                "contracts": {"admin_certificate_contract_sha256": "1" * 64}
            },
            "admin-enrollment-policy": {
                "contracts": {"admin_enrollment_policy_contract_sha256": "2" * 64}
            },
        }
        transaction.validate_predecessor_contracts(
            pre={
                "admin_certificate_contract_sha256": "1" * 64,
                "admin_enrollment_policy_contract_sha256": "2" * 64,
            },
            results=results,
        )
        with self.assertRaises(transaction.TransactionError):
            transaction.validate_predecessor_contracts(
                pre={
                    "admin_certificate_contract_sha256": "1" * 64,
                    "admin_enrollment_policy_contract_sha256": "3" * 64,
                },
                results=results,
            )

    def test_apply_journals_token_and_intent_before_capable_child(self):
        context = _context()
        phase = "admin-certificate"
        events: list[tuple[str, object]] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan"
            plan.write_bytes(b"exact plan")
            phase_root = root / "phases" / phase
            state = phase_root / "terraform.tfstate"
            token_input = root / "input"
            token_input.write_bytes(b"A" * 40)
            plan_hash = transaction.sha256_file(plan)

            def write(path: Path, payload: bytes, mode: int = 0o600) -> None:
                events.append((str(path), json.loads(payload) if path.suffix == ".json" else mode))

            def apply_child(*_args, **kwargs):
                self.assertFalse(kwargs["check"])
                pending = [item for item in events if item[0].endswith("admin-certificate.json")]
                token = [item for item in events if item[0].endswith("admin-certificate.jit-token")]
                self.assertTrue(token)
                self.assertEqual(pending[-1][1]["status"], "applying")
                return subprocess.CompletedProcess(["tofu"], 0, stdout=b"applied")

            patches = (
                mock.patch.object(transaction, "PENDING_ROOT", root / "pending"),
                mock.patch.object(transaction, "PHASES_ROOT", root / "phases"),
                mock.patch.object(transaction, "ensure_state_tree"),
                mock.patch.object(transaction, "ensure_root_directory"),
                mock.patch.object(transaction, "load_context", return_value=context),
                mock.patch.object(transaction, "stable_read", return_value=b"A" * 40),
                mock.patch.object(transaction, "validate_audit_token"),
                mock.patch.object(
                    transaction,
                    "validate_jit_token",
                    return_value={"issued_on": "2026-08-29T11:58:00Z"},
                ),
                mock.patch.object(transaction, "completed_results", return_value={}),
                mock.patch.object(
                    transaction,
                    "run_audit",
                    return_value={"audit_result": "pass", "audit_phase": "preflight"},
                ),
                mock.patch.object(
                    transaction, "prepare_plan", return_value=(plan, state, {})
                ),
                mock.patch.object(transaction, "atomic_write", side_effect=write),
                mock.patch.object(transaction, "run_command", side_effect=apply_child),
                mock.patch.object(
                    transaction,
                    "extract_state_ids",
                    return_value={"certificate_id": "resource-id"},
                ),
                mock.patch("builtins.input", return_value=f"APPLY {phase} {plan_hash}"),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[
                5
            ], patches[6], patches[7], patches[8], patches[9], patches[10], patches[
                11
            ], patches[12], patches[13], patches[14]:
                output = io.StringIO()
                with redirect_stdout(output):
                    transaction.apply_phase(
                        root=root,
                        phase=phase,
                        commit="9" * 40,
                        write_token_path=token_input,
                        token_id="8" * 32,
                    )
        self.assertIn("PHASE_RESULT=PENDING_REVOCATION", output.getvalue())
        latest = [item for item in events if item[0].endswith("admin-certificate.json")][-1]
        self.assertEqual(latest[1]["status"], "awaiting-revocation")

    def test_pending_schema_rejects_path_and_resource_escape(self):
        phase = "admin-tunnel"
        baseline = {
            "schema": "pie5-cloudflare-pending-v1",
            "phase": phase,
            "commit": "9" * 40,
            "token_id": "8" * 32,
            "audit_window_started_at": "2026-08-29T11:58:00Z",
            "plan_sha256": "7" * 64,
            "apply_started_at": "2026-08-29T12:00:00Z",
            "apply_finished_at": "",
            "pre_audit": str(transaction.PHASES_ROOT / phase / "pre-audit.txt"),
            "ids": {},
            "state_path": str(transaction.PHASES_ROOT / phase / "terraform.tfstate"),
            "status": "applying",
        }
        for label, mutate in (
            ("path", lambda value: value.update({"state_path": "/tmp/state"})),
            ("id", lambda value: value["ids"].update({"foreign_id": "x"})),
            ("status", lambda value: value.update({"status": "complete"})),
        ):
            value = copy.deepcopy(baseline)
            mutate(value)
            with self.subTest(label=label), mock.patch.object(
                transaction, "load_json_file", return_value=value
            ):
                with self.assertRaises(transaction.TransactionError):
                    transaction.load_pending(phase)

    def test_preparing_journal_requires_revocation_and_zero_mutations_to_clear(self):
        phase = "admin-certificate"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending_root = root / "pending"
            phases_root = root / "phases"
            pending_root.mkdir()
            (phases_root / phase).mkdir(parents=True)
            (pending_root / f"{phase}.jit-token").write_text("A" * 40)
            (pending_root / f"{phase}.json").write_text("{}")
            pending = {
                "token_id": "8" * 32,
                "audit_window_started_at": "2026-08-29T11:58:00Z",
                "state_path": str(phases_root / phase / "terraform.tfstate"),
            }
            receipt = {"schema": "cloudflare-jit-audit-log-receipt-v1"}
            with mock.patch.object(transaction, "PENDING_ROOT", pending_root), mock.patch.object(
                transaction, "PHASES_ROOT", phases_root
            ), mock.patch.object(transaction, "verify_revocation") as revoked, mock.patch.object(
                transaction,
                "wait_for_audit_receipt",
                return_value=({"success": True, "result": []}, receipt),
            ) as audit, mock.patch.object(transaction, "atomic_write"):
                with mock.patch.object(transaction, "validate_regular_file"):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        transaction.finalize_preparing_pending(
                            root=root,
                            phase=phase,
                            pending=pending,
                            write_token="A" * 40,
                            audit_token="B" * 40,
                            context={"account_id": "1" * 32},
                        )
            revoked.assert_called_once()
            self.assertEqual(audit.call_args.kwargs["expected_ids"], set())
            self.assertFalse((pending_root / f"{phase}.jit-token").exists())
            self.assertFalse((pending_root / f"{phase}.json").exists())
            self.assertIn("PRE_APPLY_MUTATIONS=NONE", output.getvalue())

    def test_audit_log_closure_rejects_wrong_actor_update_and_extra_resource(self):
        since = dt.datetime(2026, 8, 29, 12, 0, tzinfo=dt.timezone.utc)
        before = since + dt.timedelta(minutes=1)
        expected = {"resource-one"}
        baseline = {"success": True, "result": [_audit_entry(resource_id="resource-one")]}
        transaction.validate_audit_logs(
            logs=baseline,
            account_id="1" * 32,
            token_id="6" * 32,
            expected_ids=expected,
            since=since,
            before=before,
        )
        hostile_logs = (
            {"success": True, "result": [_audit_entry(resource_id="resource-one", action_type="update")]},
            {"success": True, "result": [_audit_entry(resource_id="resource-one", token_id="7" * 32)]},
            {
                "success": True,
                "result": [
                    _audit_entry(resource_id="resource-one"),
                    _audit_entry(resource_id="resource-two"),
                ],
            },
        )
        for logs in hostile_logs:
            with self.subTest(logs=logs):
                with self.assertRaises(transaction.TransactionError):
                    transaction.validate_audit_logs(
                        logs=logs,
                        account_id="1" * 32,
                        token_id="6" * 32,
                        expected_ids=expected,
                        since=since,
                        before=before,
                    )


class CloudflareLauncherContractTests(unittest.TestCase):
    def test_launcher_is_fixed_root_owned_and_protected_main_only(self):
        for fragment in (
            "/usr/local/sbin/website-infrastructure-cloudflare-launcher",
            "safe_root_file \"${installed_launcher}\" 755",
            "verify_installed_launcher_blob",
            "verify_live_main_tip",
            "merge-base --is-ancestor",
            "pending_phase_exists && fail",
            "scripts/cloudflare-reviewed-launcher.sh",
            "/usr/bin/env -i",
            "/usr/bin/python3 -I -B",
        ):
            self.assertIn(fragment, LAUNCHER)
        self.assertNotIn("/opt/homebrew", LAUNCHER)
        self.assertNotIn("git -C", LAUNCHER)
        self.assertNotIn("\nsource ", LAUNCHER)
        self.assertNotIn("\neval ", LAUNCHER)

    def test_launcher_binds_promotion_to_the_fixed_live_main_ref(self):
        for fragment in (
            "readonly source_remote=https://github.com/snaraj/website-infrastructure.git",
            "readonly source_main_ref=refs/heads/main",
            "GIT_ALLOW_PROTOCOL=https",
            "-c protocol.file.allow=never",
            "-c protocol.ssh.allow=never",
            "-c http.sslVerify=true",
            "-c http.followRedirects=false",
            "trusted_remote_git ls-remote --refs --exit-code",
            '[[ "${observed}" == "${commit}"$\'\\t\'"${source_main_ref}" ]]',
            'trusted_git bundle list-heads "${private_bundle}"',
            '[[ "${bundle_main}" == "${commit} ${source_main_ref}" ]]',
        ):
            self.assertIn(fragment, LAUNCHER)
        self.assertLess(
            LAUNCHER.index('verify_live_main_tip "${commit}"'),
            LAUNCHER.index('trusted_git init --bare "${source_repository}"'),
        )
        self.assertEqual(LAUNCHER.count("https://github.com/"), 1)

    def test_launcher_requires_mac_disk_platform_and_execution_protections(self):
        for fragment in (
            "FileVault is On.",
            "System Integrity Protection status: enabled.",
            "assessments enabled",
            "$(/usr/bin/uname -m)\" == arm64",
            "DYLD_*",
            "BASH_ENV",
            "ulimit -S -c 0",
        ):
            self.assertIn(fragment, LAUNCHER)

    def test_tool_bootstrap_is_exact_and_stable_before_extraction(self):
        for digest in (
            "2ae38150a667f5c0bd57b318d18ad8091d08f93fcca40345f3d88998661de5a9",
            "96557429623614140cf41afeb147b8a7e1fbe53e55923b63e7b581bc608d60ca",
            "78302d045f0ec52e9786a06c6c621ac4516b4c5dd1e54efc8050c86c29b964d9",
            "0534d8d2636d2ab5bb8284cf9a13c8a534108ce976e983ab4f5e2d9cf400b1a1",
            "2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e",
        ):
            self.assertIn(digest, LAUNCHER)
        self.assertLess(
            LAUNCHER.index('copy_stable_owner_file "${OPENTOFU_ARCHIVE_PATH}"'),
            LAUNCHER.index('tofu_inventory="$(/usr/bin/bsdtar'),
        )
        self.assertIn("/usr/bin/codesign --verify --strict", LAUNCHER)
        self.assertIn("validate_tool_manifest", LAUNCHER)
        self.assertEqual(
            LAUNCHER.count(
                'temporary="$(/usr/bin/mktemp "${runtime_parent}/launcher-blob.XXXXXXXX")"'
            ),
            1,
        )

    def test_launcher_has_closed_operations_and_token_safe_output(self):
        for operation in (
            "tools-install",
            "tool-manifest-proposal",
            "tool-manifest-commit",
            "promote",
            "audit-token-proposal",
            "configure",
            "rotate-audit-token",
            "apply",
            "resume",
            "status",
            "emit-runtime-token",
            "recover-lock",
        ):
            self.assertIn(operation, LAUNCHER)
        self.assertIn('if [[ "${operation}" != emit-runtime-token ]]', LAUNCHER)
        self.assertIn("runtime token emission requires a non-terminal pipe", ENGINE)
        self.assertIn("atomic_write(pending_token_path", ENGINE)
        self.assertLess(
            ENGINE.index("atomic_write(pending_token_path"),
            ENGINE.index('"apply",\n            "-input=false"'),
        )

    def test_mutable_checkout_is_not_an_entrypoint(self):
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": "/var/empty",
        }
        result = subprocess.run(
            ["/bin/bash", str(LAUNCHER_PATH), "status"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "CLOUDFLARE_REVIEWED_LAUNCH=FAIL\n")

    def test_launcher_blob_is_executable_and_transaction_root_is_exact(self):
        self.assertTrue(LAUNCHER_PATH.stat().st_mode & stat.S_IXUSR)
        self.assertIn(
            "/private/var/db/website-infrastructure/runtime/cloudflare-reviewed-op",
            ENGINE,
        )
        self.assertNotIn("/private/var/run/website-infrastructure", ENGINE)
        self.assertIn(
            "/private/var/db/website-infrastructure/runtime/cloudflare-reviewed-op",
            AUDIT,
        )
        self.assertNotIn("/private/var/run/website-infrastructure", AUDIT)

    def test_runbook_carries_exact_owner_and_safe_sudo_boundaries(self):
        for fragment in (
            '"owner_user_id"',
            "/usr/bin/env -u TERMINFO /usr/bin/sudo",
            "destroy the CA private key",
            "FAILED_PARTIAL_LOCKED",
            "owner-laptop LAN/hotspot/Proton positives",
            "unauthorized-device LAN/off-LAN negatives",
        ):
            self.assertIn(fragment, RUNBOOK)
        self.assertNotIn("192" + ".168.", RUNBOOK)


if __name__ == "__main__":
    unittest.main()
