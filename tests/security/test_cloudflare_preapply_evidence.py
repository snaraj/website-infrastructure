"""Adversarial tests for credential-free Cloudflare pre-apply evidence."""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_cloudflare_preapply_evidence.py"
FIXTURES = ROOT / "infrastructure" / "cloudflare" / "tests" / "fixtures"
SPEC = importlib.util.spec_from_file_location("cloudflare_preapply_evidence", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

NOW = dt.datetime(2026, 8, 9, 12, 1, tzinfo=dt.timezone.utc)


def synthetic_uuid(tail: int) -> str:
    """Build a valid test UUID without storing identifier-shaped fixture text."""

    return "-".join(("00000000", "0000", "4000", "8000", f"{tail:012x}"))


BACKEND_LINEAGE = synthetic_uuid(1)
STATE_LINEAGE = synthetic_uuid(2)
OTHER_STATE_LINEAGE = synthetic_uuid(3)
SCOPE_BINDING_SHA256 = "8" * 64
RECOVERY_EVIDENCE_SHA256 = "a" * 64
BINDINGS = {
    "repository_commit_sha256": "1" * 64,
    "workspace_attestation_sha256": "2" * 64,
    "saved_plan_sha256": "3" * 64,
    "predecessor_audit_sha256": "4" * 64,
    "provider_lock_sha256": "5" * 64,
    "state_binding_sha256": "6" * 64,
}


def strict_json_bytes(document: dict) -> bytes:
    """Encode one deterministic synthetic JSON object."""

    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def backend_document(
    state_path: Path,
    *,
    backend_type: str = "local",
    serial: int = 3,
    lineage: str = BACKEND_LINEAGE,
) -> dict:
    """Return initialized, empty local-backend metadata."""

    return {
        "version": 3,
        "serial": serial,
        "lineage": lineage,
        "backend": {
            "type": backend_type,
            "config": {"path": str(state_path), "workspace_dir": None},
            "hash": 42,
        },
        "modules": [
            {
                "path": ["root"],
                "outputs": {},
                "resources": {},
                "depends_on": [],
            }
        ],
    }


def state_document(*, serial: int = 7, lineage: str = STATE_LINEAGE) -> dict:
    """Return an empty create-only OpenTofu state document."""

    return {
        "version": 4,
        "terraform_version": MODULE.TOFU_VERSION,
        "serial": serial,
        "lineage": lineage,
        "outputs": {},
        "resources": [],
        "check_results": None,
    }


def captured_state_bytes(evidence) -> bytes:
    """Encode the exact bounded state-validator output preserved before apply."""

    values = {
        "state_backend": MODULE.BACKEND_KIND,
        "backend_metadata_sha256": evidence.backend_sha256,
        "state_path_sha256": evidence.state_path_sha256,
        "state_mode": evidence.mode,
        "state_sha256": evidence.sha256,
        "state_lineage_sha256": evidence.lineage_sha256,
        "state_serial": evidence.serial,
        "state_binding_sha256": evidence.binding_sha256,
    }
    lines = ["PASS Cloudflare pre-apply state evidence"]
    lines.extend(f"{key}={values[key]}" for key in MODULE.STATE_EVIDENCE_KEYS)
    return ("\n".join(lines) + "\n").encode("ascii")


def predecessor_receipt_bytes(evidence, *, mutation: dict[str, str] | None = None) -> bytes:
    """Encode one canonical Naranjo pre-state receipt for handoff tests."""

    evidence_raw = captured_state_bytes(evidence)
    values = {
        "backend_metadata_sha256": evidence.backend_sha256,
        "manual_attestation_sha256": "e" * 64,
        "phase_root": "infrastructure/cloudflare/phases/public-dns-naranjo",
        "repo_commit": "1" * 40,
        "phase_lock_sha256": "5" * 64,
        "workspace_attestation_sha256": "2" * 64,
        "state_binding_sha256": evidence.binding_sha256,
        "state_evidence_sha256": hashlib.sha256(evidence_raw).hexdigest(),
        "state_mode": evidence.mode,
        "state_sha256": evidence.sha256,
        "plan_sha256": "3" * 64,
        "planned_utc": "2026-08-09T12:00:00Z",
    }
    values.update(mutation or {})
    return (
        "\n".join(f"{key}={values[key]}" for key in MODULE.PRE_STATE_RECEIPT_KEYS)
        + "\n"
    ).encode("ascii")


def manual_document(phase: str = "admin-tunnel") -> dict:
    """Return a complete synthetic attestation for one closed phase."""

    policy = MODULE.PHASE_POLICY[phase]
    return {
        "schema": MODULE.ATTESTATION_SCHEMA,
        "phase": phase,
        "evidence_role": MODULE.ATTESTATION_ROLE,
        "generated_utc": "2026-08-09T12:00:00Z",
        "expires_utc": "2026-08-09T12:05:00Z",
        "bindings": copy.deepcopy(BINDINGS),
        "entitlement": {
            "verified_at": "2026-08-09T11:59:00Z",
            "active_zone_count": 2,
            "active_zone_names": ["lidersea.com", "naranjo.online"],
            "all_zones_on_free_plan": True,
            "zero_trust_on_free_plan": True,
            "paid_products_active": False,
            "trials_active": False,
            "unknown_billing_or_entitlement": False,
            "authorized_infrastructure_usd_monthly": 0,
            "registrar_renewals_are_only_exception": True,
        },
        "account_security": {
            "verified_at": "2026-08-09T11:59:00Z",
            "member_inventory_reviewed": True,
            "administrator_mfa_verified": True,
            "api_token_inventory_reviewed": True,
            "unexpected_admin_or_token_authority": False,
        },
        "jit_token": {
            "token_id_sha256": "7" * 64,
            "resource_scope": policy["resource_scope"],
            "scope_binding_sha256": SCOPE_BINDING_SHA256,
            "permissions": list(policy["permissions"]),
            "unavoidable_reach": list(policy["unavoidable_reach"]),
            "source_ip_restricted": True,
            "source_ip_policy_sha256": "9" * 64,
            "issued_at": "2026-08-09T11:50:00Z",
            "expires_at": "2026-08-09T12:20:00Z",
            "active_status_verified": True,
            "only_write_token_live": True,
            "plaintext_persisted": False,
            "plaintext_shared": False,
        },
        "operator_recovery": {
            "verified_at": "2026-08-09T11:59:00Z",
            "physical_or_trusted_lan_recovery": True,
            "two_retained_sessions": True,
            "fresh_third_login": True,
            "evidence_sha256": RECOVERY_EVIDENCE_SHA256,
        },
        "review": {
            "approved": True,
            "approved_at": "2026-08-09T12:00:00Z",
            "reviewer_role": "account-owner",
            "approval_sha256": "b" * 64,
        },
    }


def validate_manual(
    document: dict,
    *,
    phase: str = "admin-tunnel",
    expected_bindings: dict[str, str] | None = None,
    expected_scope: str = SCOPE_BINDING_SHA256,
    expected_recovery: str | None = RECOVERY_EVIDENCE_SHA256,
    now: dt.datetime = NOW,
):
    """Validate a synthetic manual attestation with external bindings."""

    return MODULE.parse_manual_attestation(
        strict_json_bytes(document),
        expected_phase=phase,
        expected_bindings=copy.deepcopy(
            BINDINGS if expected_bindings is None else expected_bindings
        ),
        expected_scope_binding_sha256=expected_scope,
        expected_recovery_evidence_sha256=expected_recovery,
        now=now,
    )


class CloudflarePreapplyStateEvidenceTests(unittest.TestCase):
    """Prove state facts come from exact parsed bytes and backend metadata."""

    def test_absent_and_present_state_bindings_are_distinct_and_content_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            expected_path = (
                Path(directory)
                / "protected"
                / "cloudflare"
                / "admin-tunnel"
                / "terraform.tfstate"
            )
            backend_raw = strict_json_bytes(backend_document(expected_path))
            state_raw = strict_json_bytes(state_document())

            absent = MODULE.parse_state_evidence(
                None,
                backend_raw=backend_raw,
                phase="admin-tunnel",
                expected_state_path=str(expected_path),
            )
            present = MODULE.parse_state_evidence(
                state_raw,
                backend_raw=backend_raw,
                phase="admin-tunnel",
                expected_state_path=str(expected_path),
            )

            self.assertEqual(absent.mode, "absent")
            self.assertEqual(
                (absent.sha256, absent.lineage_sha256, absent.serial),
                ("absent", "absent", "absent"),
            )
            self.assertEqual(present.mode, "present")
            self.assertEqual(present.sha256, hashlib.sha256(state_raw).hexdigest())
            self.assertEqual(
                present.lineage_sha256,
                hashlib.sha256((STATE_LINEAGE + "\n").encode()).hexdigest(),
            )
            self.assertEqual(present.serial, "7")
            self.assertNotEqual(absent.binding_sha256, present.binding_sha256)

            changed_backend = MODULE.parse_state_evidence(
                state_raw,
                backend_raw=strict_json_bytes(
                    backend_document(expected_path, serial=4)
                ),
                phase="admin-tunnel",
                expected_state_path=str(expected_path),
            )
            changed_lineage = MODULE.parse_state_evidence(
                strict_json_bytes(state_document(lineage=OTHER_STATE_LINEAGE)),
                backend_raw=backend_raw,
                phase="admin-tunnel",
                expected_state_path=str(expected_path),
            )
            changed_serial = MODULE.parse_state_evidence(
                strict_json_bytes(state_document(serial=8)),
                backend_raw=backend_raw,
                phase="admin-tunnel",
                expected_state_path=str(expected_path),
            )

            self.assertNotEqual(present.backend_sha256, changed_backend.backend_sha256)
            self.assertEqual(changed_backend.serial, "7")
            self.assertNotEqual(present.lineage_sha256, changed_lineage.lineage_sha256)
            self.assertEqual(changed_lineage.serial, "7")
            self.assertEqual(changed_serial.serial, "8")
            self.assertEqual(changed_serial.lineage_sha256, present.lineage_sha256)
            self.assertEqual(
                len(
                    {
                        present.binding_sha256,
                        changed_backend.binding_sha256,
                        changed_lineage.binding_sha256,
                        changed_serial.binding_sha256,
                    }
                ),
                4,
            )

    def test_relative_cross_phase_and_nonlocal_backends_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory) / "protected" / "cloudflare"
            expected_path = protected / "admin-tunnel" / "terraform.tfstate"
            cross_phase = protected / "public-edge" / "terraform.tfstate"
            cases = (
                (
                    "relative",
                    backend_document(Path("relative/terraform.tfstate")),
                ),
                ("cross-phase", backend_document(cross_phase)),
                (
                    "non-local",
                    backend_document(expected_path, backend_type="remote"),
                ),
            )
            for label, backend in cases:
                with self.subTest(label=label), self.assertRaises(
                    MODULE.EvidenceError
                ):
                    MODULE.parse_state_evidence(
                        None,
                        backend_raw=strict_json_bytes(backend),
                        phase="admin-tunnel",
                        expected_state_path=str(expected_path),
                    )

    def test_create_only_state_rejects_outputs_resources_and_check_results(self):
        with tempfile.TemporaryDirectory() as directory:
            expected_path = Path(directory) / "terraform.tfstate"
            backend_raw = strict_json_bytes(backend_document(expected_path))
            mutations = {
                "output": ("outputs", {"unexpected": {"value": True}}),
                "resource": ("resources", [{"mode": "managed"}]),
                "check-result": ("check_results", [{"status": "pass"}]),
            }
            for label, (field, value) in mutations.items():
                document = state_document()
                document[field] = value
                with self.subTest(label=label), self.assertRaises(
                    MODULE.EvidenceError
                ):
                    MODULE.parse_state_evidence(
                        strict_json_bytes(document),
                        backend_raw=backend_raw,
                        phase="admin-tunnel",
                        expected_state_path=str(expected_path),
                    )

    def test_state_cli_output_is_fixed_bounded_and_content_neutral(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected_path = root / "protected" / "terraform.tfstate"
            backend_path = root / "backend.json"
            snapshot_path = root / "state.snapshot"
            backend_path.write_bytes(
                strict_json_bytes(backend_document(expected_path))
            )
            snapshot_path.write_bytes(strict_json_bytes(state_document()))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                stderr
            ):
                result = MODULE.main(
                    [
                        "state",
                        "--phase",
                        "admin-tunnel",
                        "--backend-metadata",
                        str(backend_path),
                        "--expected-state-path",
                        str(expected_path),
                        "--state-file",
                        str(snapshot_path),
                    ]
                )

        lines = stdout.getvalue().splitlines()
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(lines), 9)
        self.assertEqual(lines[0], "PASS Cloudflare pre-apply state evidence")
        self.assertEqual(lines[1], "state_backend=local-protected-file")
        self.assertEqual(lines[7], "state_serial=7")
        self.assertLess(len(stdout.getvalue()), 1_024)
        self.assertNotIn(directory, stdout.getvalue())
        self.assertNotIn(STATE_LINEAGE, stdout.getvalue())

    def test_predecessor_receipt_accepts_exact_absent_and_present_state(self):
        with tempfile.TemporaryDirectory() as directory:
            expected_path = Path(directory) / "terraform.tfstate"
            backend_raw = strict_json_bytes(backend_document(expected_path))
            state_raw = strict_json_bytes(state_document())
            absent = MODULE.parse_state_evidence(
                None,
                backend_raw=backend_raw,
                phase="public-dns-naranjo",
                expected_state_path=str(expected_path),
            )
            present = MODULE.parse_state_evidence(
                state_raw,
                backend_raw=backend_raw,
                phase="public-dns-naranjo",
                expected_state_path=str(expected_path),
            )

            for evidence, carried_state in ((absent, None), (present, state_raw)):
                with self.subTest(mode=evidence.mode):
                    loaded = MODULE.parse_predecessor_receipt(
                        predecessor_receipt_bytes(evidence),
                        state_evidence_raw=captured_state_bytes(evidence),
                        state_raw=carried_state,
                        expected_phase="public-dns-naranjo",
                        expected_repository_commit="1" * 40,
                        expected_saved_plan_sha256="3" * 64,
                        expected_provider_lock_sha256="5" * 64,
                    )
                    self.assertEqual(loaded.mode, evidence.mode)
                    self.assertEqual(loaded.state_sha256, evidence.sha256)
                    self.assertEqual(
                        loaded.state_binding_sha256,
                        evidence.binding_sha256,
                    )

    def test_predecessor_receipt_rejects_mode_bytes_and_binding_mismatches(self):
        with tempfile.TemporaryDirectory() as directory:
            expected_path = Path(directory) / "terraform.tfstate"
            backend_raw = strict_json_bytes(backend_document(expected_path))
            state_raw = strict_json_bytes(state_document())
            absent = MODULE.parse_state_evidence(
                None,
                backend_raw=backend_raw,
                phase="public-dns-naranjo",
                expected_state_path=str(expected_path),
            )
            present = MODULE.parse_state_evidence(
                state_raw,
                backend_raw=backend_raw,
                phase="public-dns-naranjo",
                expected_state_path=str(expected_path),
            )

            cases = (
                (
                    "absent-with-bytes",
                    predecessor_receipt_bytes(absent),
                    captured_state_bytes(absent),
                    state_raw,
                ),
                (
                    "present-without-bytes",
                    predecessor_receipt_bytes(present),
                    captured_state_bytes(present),
                    None,
                ),
                (
                    "receipt-mode",
                    predecessor_receipt_bytes(absent, mutation={"state_mode": "present"}),
                    captured_state_bytes(absent),
                    None,
                ),
                (
                    "receipt-binding",
                    predecessor_receipt_bytes(
                        absent, mutation={"state_binding_sha256": "f" * 64}
                    ),
                    captured_state_bytes(absent),
                    None,
                ),
                (
                    "receipt-state-evidence",
                    predecessor_receipt_bytes(
                        absent, mutation={"state_evidence_sha256": "f" * 64}
                    ),
                    captured_state_bytes(absent),
                    None,
                ),
                (
                    "changed-present-state",
                    predecessor_receipt_bytes(present),
                    captured_state_bytes(present),
                    strict_json_bytes(state_document(serial=8)),
                ),
            )
            for label, receipt, captured, carried_state in cases:
                with self.subTest(label=label), self.assertRaises(MODULE.EvidenceError):
                    MODULE.parse_predecessor_receipt(
                        receipt,
                        state_evidence_raw=captured,
                        state_raw=carried_state,
                        expected_phase="public-dns-naranjo",
                        expected_repository_commit="1" * 40,
                        expected_saved_plan_sha256="3" * 64,
                        expected_provider_lock_sha256="5" * 64,
                    )

    def test_predecessor_records_reject_reordered_or_noncanonical_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            expected_path = Path(directory) / "terraform.tfstate"
            evidence = MODULE.parse_state_evidence(
                None,
                backend_raw=strict_json_bytes(backend_document(expected_path)),
                phase="public-dns-naranjo",
                expected_state_path=str(expected_path),
            )
            receipt = predecessor_receipt_bytes(evidence)
            first, second, *remaining = receipt.splitlines()
            reordered = b"\n".join((second, first, *remaining)) + b"\n"
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.parse_predecessor_receipt(
                    reordered,
                    state_evidence_raw=captured_state_bytes(evidence),
                    state_raw=None,
                    expected_phase="public-dns-naranjo",
                    expected_repository_commit="1" * 40,
                    expected_saved_plan_sha256="3" * 64,
                    expected_provider_lock_sha256="5" * 64,
                )

    def test_post_audit_must_be_at_or_after_revocation_verification(self):
        now = dt.datetime(2026, 8, 9, 12, 20, tzinfo=dt.timezone.utc)
        for audited in ("2026-08-09T12:10:00Z", "2026-08-09T12:11:00Z"):
            with self.subTest(audited=audited):
                MODULE.validate_post_audit_chronology(
                    revocation_verified_utc="2026-08-09T12:10:00Z",
                    post_audit_utc=audited,
                    now=now,
                )
        for audited in ("2026-08-09T12:09:59Z", "2026-08-09T12:20:01Z"):
            with self.subTest(audited=audited), self.assertRaises(
                MODULE.EvidenceError
            ):
                MODULE.validate_post_audit_chronology(
                    revocation_verified_utc="2026-08-09T12:10:00Z",
                    post_audit_utc=audited,
                    now=now,
                )


class CloudflarePreapplyManualEvidenceTests(unittest.TestCase):
    """Reject stale, over-scoped, insecure, or unbound manual attestations."""

    def test_committed_allow_and_paid_deny_fixtures(self):
        allow = json.loads(
            (FIXTURES / "preapply-manual-attestation-allow.json").read_text(
                encoding="utf-8"
            )
        )
        deny = json.loads(
            (FIXTURES / "preapply-manual-attestation-deny-paid.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(validate_manual(allow).phase, "admin-tunnel")
        with self.assertRaises(MODULE.EvidenceError):
            validate_manual(deny)

    def test_all_seven_phase_attestations_accept_only_their_exact_policy(self):
        self.assertEqual(set(MODULE.PHASES), set(MODULE.PHASE_POLICY))
        for phase in MODULE.PHASES:
            with self.subTest(phase=phase):
                evidence = validate_manual(manual_document(phase), phase=phase)
                self.assertEqual(evidence.phase, phase)
                self.assertRegex(evidence.sha256, r"^[0-9a-f]{64}$")

    def test_paid_mfa_scope_ip_ttl_and_recovery_mutations_fail_closed(self):
        mutations = (
            ("paid", ("entitlement", "paid_products_active"), True),
            (
                "mfa",
                ("account_security", "administrator_mfa_verified"),
                False,
            ),
            ("scope", ("jit_token", "resource_scope"), "exact-zone"),
            (
                "permission",
                ("jit_token", "permissions"),
                ["Cloudflare One Connector: cloudflared Write", "DNS Write"],
            ),
            (
                "unavoidable-reach",
                ("jit_token", "unavoidable_reach"),
                ["one-selected-tunnel-only"],
            ),
            ("source-ip", ("jit_token", "source_ip_restricted"), False),
            ("ttl", ("jit_token", "expires_at"), "2026-08-09T12:20:01Z"),
            (
                "physical-recovery",
                ("operator_recovery", "physical_or_trusted_lan_recovery"),
                False,
            ),
            (
                "retained-sessions",
                ("operator_recovery", "two_retained_sessions"),
                False,
            ),
            (
                "fresh-login",
                ("operator_recovery", "fresh_third_login"),
                False,
            ),
        )
        for label, (section, field), value in mutations:
            document = manual_document()
            document[section][field] = value
            with self.subTest(label=label), self.assertRaises(
                MODULE.EvidenceError
            ):
                validate_manual(document)

    def test_transaction_scope_and_recovery_bindings_fail_on_any_mismatch(self):
        cases = []

        changed_transaction = manual_document()
        changed_transaction["bindings"]["state_binding_sha256"] = "c" * 64
        cases.append(("transaction", changed_transaction))

        changed_scope = manual_document()
        changed_scope["jit_token"]["scope_binding_sha256"] = "c" * 64
        cases.append(("scope", changed_scope))

        changed_recovery = manual_document()
        changed_recovery["operator_recovery"]["evidence_sha256"] = "c" * 64
        cases.append(("recovery", changed_recovery))

        for label, document in cases:
            with self.subTest(label=label), self.assertRaises(
                MODULE.EvidenceError
            ):
                validate_manual(document)

        wrong_expected = copy.deepcopy(BINDINGS)
        wrong_expected["repository_commit_sha256"] = "c" * 64
        with self.assertRaises(MODULE.EvidenceError):
            validate_manual(manual_document(), expected_bindings=wrong_expected)
        with self.assertRaises(MODULE.EvidenceError):
            validate_manual(manual_document(), expected_scope="c" * 64)
        with self.assertRaises(MODULE.EvidenceError):
            validate_manual(manual_document(), expected_recovery="c" * 64)

    def test_duplicate_extra_missing_stale_and_secret_input_fail_closed(self):
        raw = strict_json_bytes(manual_document())
        duplicate = raw.replace(
            b'"phase":"admin-tunnel"',
            b'"phase":"admin-tunnel","phase":"admin-tunnel"',
            1,
        )
        with self.assertRaises(MODULE.DuplicateKeyError):
            MODULE.parse_manual_attestation(
                duplicate,
                expected_phase="admin-tunnel",
                expected_bindings=copy.deepcopy(BINDINGS),
                expected_scope_binding_sha256=SCOPE_BINDING_SHA256,
                expected_recovery_evidence_sha256=RECOVERY_EVIDENCE_SHA256,
                now=NOW,
            )

        for label in ("extra", "missing"):
            document = manual_document()
            if label == "extra":
                document["unsupported"] = False
            else:
                del document["account_security"]["administrator_mfa_verified"]
            with self.subTest(label=label), self.assertRaises(
                MODULE.EvidenceError
            ):
                validate_manual(document)

        stale_now = dt.datetime(2026, 8, 9, 12, 5, 1, tzinfo=dt.timezone.utc)
        with self.assertRaises(MODULE.EvidenceError):
            validate_manual(manual_document(), now=stale_now)

        secret_shape = "Authorization" + ": Bearer " + "S" * 40
        with self.assertRaisesRegex(MODULE.EvidenceError, "secret material"):
            MODULE.parse_manual_attestation(
                raw + secret_shape.encode(),
                expected_phase="admin-tunnel",
                expected_bindings=copy.deepcopy(BINDINGS),
                expected_scope_binding_sha256=SCOPE_BINDING_SHA256,
                expected_recovery_evidence_sha256=RECOVERY_EVIDENCE_SHA256,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
