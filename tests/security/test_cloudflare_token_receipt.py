"""Focused contract tests for the offline Cloudflare token receipt gate."""

from __future__ import annotations

import ast
import contextlib
import copy
import datetime as dt
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .support import load_script


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_cloudflare_token_receipt.py"
RUNBOOK = ROOT / "docs" / "runbooks" / "cloudflare-token-receipt.md"
MODULE = load_script(
    "validate_cloudflare_token_receipt.py", module_name="cloudflare_token_receipt"
)

HASHES = {
    "target_sha256": "1" * 64,
    "workspace_attestation_sha256": "2" * 64,
    "saved_plan_sha256": "3" * 64,
    "state_sha256": "4" * 64,
    "provider_lock_sha256": "5" * 64,
    "repository_commit_sha256": "6" * 64,
    "audit_sha256": "7" * 64,
    "source_ip_policy_sha256": "8" * 64,
    "preflight_evidence_sha256": "9" * 64,
    "postflight_evidence_sha256": "a" * 64,
    "token_id_sha256": "b" * 64,
    "state_binding_sha256": "c" * 64,
    "post_audit_sha256": "d" * 64,
}
NOW = dt.datetime(2026, 8, 9, 14, 0, tzinfo=dt.timezone.utc)


def valid_document(
    phase: str = "admin-tunnel", *, state_mode: str = "present"
) -> dict:
    """Return a complete synthetic receipt containing no operational values."""

    policy = MODULE.PHASE_POLICY[phase]
    apply_phase = policy["operation"] == "apply"
    effective_state_mode = state_mode if apply_phase else None
    expires_at = "2026-08-09T12:30:00Z" if apply_phase else "2026-08-09T13:00:00Z"
    revoked_at = "2026-08-09T12:10:00Z" if apply_phase else "2026-08-09T12:40:00Z"
    postflight_at = "2026-08-09T12:11:00Z" if apply_phase else "2026-08-09T12:41:00Z"
    return {
        "schema": MODULE.SCHEMA,
        "phase": phase,
        "operation": policy["operation"],
        "token_policy": {
            "owner_type": "account",
            "verification_endpoint_kind": "account-token-verify",
            "token_id_sha256": HASHES["token_id_sha256"],
            "resource_scope": policy["resource_scope"],
            "permissions": list(policy["permissions"]),
            "unavoidable_reach": list(policy["unavoidable_reach"]),
            "issued_at": "2026-08-09T12:00:00Z",
            "expires_at": expires_at,
            "source_ip_restricted": True,
            "source_ip_policy_sha256": HASHES["source_ip_policy_sha256"],
        },
        "bindings": {
            "target_sha256": HASHES["target_sha256"],
            "workspace_attestation_sha256": HASHES[
                "workspace_attestation_sha256"
            ],
            "saved_plan_sha256": HASHES["saved_plan_sha256"] if apply_phase else None,
            "state_mode": effective_state_mode,
            "state_binding_sha256": HASHES["state_binding_sha256"]
            if apply_phase
            else None,
            "state_sha256": HASHES["state_sha256"]
            if effective_state_mode == "present"
            else None,
            "provider_lock_sha256": HASHES["provider_lock_sha256"]
            if apply_phase
            else None,
            "repository_commit_sha256": HASHES["repository_commit_sha256"],
            "audit_sha256": HASHES["audit_sha256"],
            "post_audit_sha256": HASHES["post_audit_sha256"]
            if apply_phase
            else None,
        },
        "controls": {
            "mfa_verified": True,
            "token_plaintext_persisted": False,
            "token_plaintext_shared": False,
            "billing_write": False,
            "registrar_write": False,
            "api_tokens_write": False,
            "git_write_authority": False,
            "cluster_authority": False,
            "tunnel_runtime_authority": False,
        },
        "verification": {
            "preflight": {
                "verified_at": "2026-08-09T12:01:00Z",
                "token_active": True,
                "revocation_status": "pending",
                "token_id_sha256": HASHES["token_id_sha256"],
                "evidence_sha256": HASHES["preflight_evidence_sha256"],
            },
            "postflight": {
                "revoked_at": revoked_at,
                "verified_at": postflight_at,
                "revocation_status": "verified",
                "verified_with_separate_credential": True,
                "revoked_token_rejected": True,
                "token_id_sha256": HASHES["token_id_sha256"],
                "evidence_sha256": HASHES["postflight_evidence_sha256"],
            },
        },
    }


def receipt_bytes(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def expected_bindings(
    phase: str = "admin-tunnel", *, state_mode: str = "present"
) -> dict[str, str | None]:
    apply_phase = MODULE.PHASE_POLICY[phase]["operation"] == "apply"
    return {
        name: (
            HASHES[name]
            if name not in {
                "saved_plan_sha256",
                "state_binding_sha256",
                "state_sha256",
                "provider_lock_sha256",
                "post_audit_sha256",
            }
            or (
                apply_phase
                and (name != "state_sha256" or state_mode == "present")
            )
            else None
        )
        for name in MODULE.BINDING_ARGUMENTS
    }


def expected_extra_hashes() -> dict[str, str]:
    return {name: HASHES[name] for name in MODULE.EXTRA_EXPECTED_ARGUMENTS}


def validate(
    document: dict, phase: str = "admin-tunnel", *, state_mode: str = "present"
):
    return MODULE.parse_receipt(
        receipt_bytes(document),
        expected_phase=phase,
        expected_state_mode=state_mode if phase != "audit" else None,
        expected_bindings=expected_bindings(phase, state_mode=state_mode),
        expected_extra_hashes=expected_extra_hashes(),
        now=NOW,
    )


class CloudflareTokenReceiptTests(unittest.TestCase):
    """Reject over-scoped, unbound, stale, or credential-bearing receipts."""

    def test_all_eight_phase_policies_accept_only_their_exact_contract(self):
        self.assertEqual(
            set(MODULE.PHASE_POLICY),
            {
                "admin-tunnel",
                "admin-policies",
                "admin-route",
                "admin-api",
                "public-edge",
                "public-dns-naranjo",
                "public-dns-lidersea",
                "audit",
            },
        )
        for phase in MODULE.PHASE_POLICY:
            with self.subTest(phase=phase):
                loaded = validate(valid_document(phase), phase)
                self.assertEqual(loaded.phase, phase)
                self.assertRegex(loaded.sha256, r"^[0-9a-f]{64}$")

    def test_permission_and_unavoidable_reach_are_exact_not_self_selected(self):
        for field, added in (
            ("permissions", "API Tokens Write"),
            ("unavoidable_reach", "one-selected-tunnel-only"),
        ):
            document = valid_document()
            document["token_policy"][field].append(added)
            with self.subTest(field=field), self.assertRaises(MODULE.ReceiptError):
                validate(document)

    def test_dns_token_is_one_zone_but_honestly_reaches_every_record_in_it(self):
        for phase in ("public-dns-naranjo", "public-dns-lidersea"):
            policy = MODULE.PHASE_POLICY[phase]
            self.assertEqual(policy["resource_scope"], "exact-zone")
            self.assertEqual(policy["permissions"], ("DNS Write",))
            self.assertEqual(
                policy["unavoidable_reach"],
                ("all-dns-records-in-exact-zone",),
            )

    def test_audit_is_read_only_and_has_no_apply_artifact_bindings(self):
        document = valid_document("audit")
        self.assertEqual(
            MODULE.PHASE_POLICY["audit"]["permissions"],
            (
                "Billing Read",
                "Zone Read",
                "DNS Read",
                "Cloudflare One Connector: cloudflared Read",
                "Cloudflare One Networks Read",
                "Zero Trust Read",
                "Access: Apps and Policies Read",
                "Access: Audit Logs Read",
            ),
        )
        validate(document, "audit")
        for field in (
            "saved_plan_sha256",
            "state_binding_sha256",
            "state_sha256",
            "provider_lock_sha256",
            "post_audit_sha256",
        ):
            changed = copy.deepcopy(document)
            changed["bindings"][field] = "b" * 64
            with self.subTest(field=field), self.assertRaises(MODULE.ReceiptError):
                validate(changed, "audit")
        changed = copy.deepcopy(document)
        changed["bindings"]["state_mode"] = "absent"
        with self.assertRaises(MODULE.ReceiptError):
            validate(changed, "audit")

    def test_apply_accepts_exact_absent_or_present_state_and_denies_substitution(self):
        present = valid_document(state_mode="present")
        absent = valid_document(state_mode="absent")
        validate(present, state_mode="present")
        validate(absent, state_mode="absent")
        self.assertIsNone(absent["bindings"]["state_sha256"])
        self.assertEqual(absent["bindings"]["state_mode"], "absent")
        self.assertEqual(
            absent["bindings"]["state_binding_sha256"],
            HASHES["state_binding_sha256"],
        )

        cases = []
        wrong_mode = copy.deepcopy(absent)
        wrong_mode["bindings"]["state_mode"] = "present"
        cases.append(("mode", wrong_mode, "absent", expected_bindings(state_mode="absent")))
        fabricated_absent_hash = copy.deepcopy(absent)
        fabricated_absent_hash["bindings"]["state_sha256"] = HASHES["state_sha256"]
        cases.append(
            (
                "fabricated-absent-hash",
                fabricated_absent_hash,
                "absent",
                expected_bindings(state_mode="absent"),
            )
        )
        missing_present_hash = copy.deepcopy(present)
        missing_present_hash["bindings"]["state_sha256"] = None
        cases.append(
            (
                "missing-present-hash",
                missing_present_hash,
                "present",
                expected_bindings(state_mode="present"),
            )
        )
        for label, document, mode, bindings in cases:
            with self.subTest(label=label), self.assertRaises(MODULE.ReceiptError):
                MODULE.parse_receipt(
                    receipt_bytes(document),
                    expected_phase="admin-tunnel",
                    expected_state_mode=mode,
                    expected_bindings=bindings,
                    expected_extra_hashes=expected_extra_hashes(),
                    now=NOW,
                )

    def test_apply_requires_every_external_hash_and_rejects_zero_or_mismatch(self):
        document = valid_document()
        for field in MODULE.BINDING_ARGUMENTS:
            with self.subTest(field=field):
                missing = copy.deepcopy(document)
                missing["bindings"][field] = None
                with self.assertRaises(MODULE.ReceiptError):
                    validate(missing)
                zero = copy.deepcopy(document)
                zero["bindings"][field] = "0" * 64
                with self.assertRaises(MODULE.ReceiptError):
                    validate(zero)
                mismatched = expected_bindings()
                mismatched[field] = "f" * 64
                with self.assertRaises(MODULE.ReceiptError):
                    MODULE.parse_receipt(
                        receipt_bytes(document),
                        expected_phase="admin-tunnel",
                        expected_state_mode="present",
                        expected_bindings=mismatched,
                        expected_extra_hashes=expected_extra_hashes(),
                        now=NOW,
                    )

    def test_direct_callers_must_supply_exact_expected_binding_maps(self):
        raw = receipt_bytes(valid_document())
        binding_mutations = []
        missing_binding = expected_bindings()
        missing_binding.pop("target_sha256")
        binding_mutations.append(missing_binding)
        extra_binding = expected_bindings()
        extra_binding["unsupported_sha256"] = "b" * 64
        binding_mutations.append(extra_binding)
        invalid_binding = expected_bindings()
        invalid_binding["target_sha256"] = "not-a-sha256"
        binding_mutations.append(invalid_binding)
        for bindings in binding_mutations:
            with self.subTest(binding_keys=len(bindings)), self.assertRaises(
                MODULE.ReceiptError
            ):
                MODULE.parse_receipt(
                    raw,
                    expected_phase="admin-tunnel",
                    expected_state_mode="present",
                    expected_bindings=bindings,
                    expected_extra_hashes=expected_extra_hashes(),
                    now=NOW,
                )

        extra_mutations = []
        missing_extra = expected_extra_hashes()
        missing_extra.pop("source_ip_policy_sha256")
        extra_mutations.append(missing_extra)
        unsupported_extra = expected_extra_hashes()
        unsupported_extra["unsupported_sha256"] = "b" * 64
        extra_mutations.append(unsupported_extra)
        invalid_extra = expected_extra_hashes()
        invalid_extra["source_ip_policy_sha256"] = "not-a-sha256"
        extra_mutations.append(invalid_extra)
        for extra_hashes in extra_mutations:
            with self.subTest(extra_keys=len(extra_hashes)), self.assertRaises(
                MODULE.ReceiptError
            ):
                MODULE.parse_receipt(
                    raw,
                    expected_phase="admin-tunnel",
                    expected_state_mode="present",
                    expected_bindings=expected_bindings(),
                    expected_extra_hashes=extra_hashes,
                    now=NOW,
                )

    def test_semantically_distinct_evidence_cannot_reuse_one_hash(self):
        document = valid_document()
        bindings = expected_bindings()
        extra = expected_extra_hashes()
        copied = bindings["target_sha256"]
        self.assertIsNotNone(copied)
        bindings["audit_sha256"] = copied
        document["bindings"]["audit_sha256"] = copied
        with self.assertRaisesRegex(MODULE.ReceiptError, "evidence domains"):
            MODULE.parse_receipt(
                receipt_bytes(document),
                expected_phase="admin-tunnel",
                expected_state_mode="present",
                expected_bindings=bindings,
                expected_extra_hashes=extra,
                now=NOW,
            )

    def test_pre_and_post_audit_bindings_are_distinct_and_not_substitutable(self):
        document = valid_document()
        document["bindings"]["post_audit_sha256"] = HASHES["audit_sha256"]
        bindings = expected_bindings()
        bindings["post_audit_sha256"] = HASHES["audit_sha256"]
        with self.assertRaisesRegex(MODULE.ReceiptError, "evidence domains"):
            MODULE.parse_receipt(
                receipt_bytes(document),
                expected_phase="admin-tunnel",
                expected_state_mode="present",
                expected_bindings=bindings,
                expected_extra_hashes=expected_extra_hashes(),
                now=NOW,
            )

        external = expected_bindings()
        external["post_audit_sha256"] = "e" * 64
        with self.assertRaises(MODULE.ReceiptError):
            MODULE.parse_receipt(
                receipt_bytes(valid_document()),
                expected_phase="admin-tunnel",
                expected_state_mode="present",
                expected_bindings=external,
                expected_extra_hashes=expected_extra_hashes(),
                now=NOW,
            )

    def test_source_ip_mfa_and_forbidden_authorities_fail_closed(self):
        mutations = (
            ("token_policy", "source_ip_restricted", False),
            ("controls", "mfa_verified", False),
            ("controls", "token_plaintext_persisted", True),
            ("controls", "token_plaintext_shared", True),
            ("controls", "billing_write", True),
            ("controls", "registrar_write", True),
            ("controls", "api_tokens_write", True),
            ("controls", "git_write_authority", True),
            ("controls", "cluster_authority", True),
            ("controls", "tunnel_runtime_authority", True),
        )
        for parent, field, value in mutations:
            document = valid_document()
            document[parent][field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.ReceiptError):
                validate(document)

    def test_owner_type_selects_the_matching_verify_endpoint(self):
        document = valid_document()
        document["token_policy"]["owner_type"] = "user"
        document["token_policy"]["verification_endpoint_kind"] = "user-token-verify"
        validate(document)
        document["token_policy"]["verification_endpoint_kind"] = "account-token-verify"
        with self.assertRaises(MODULE.ReceiptError):
            validate(document)

    def test_apply_ttl_is_at_most_30_minutes_and_audit_at_most_60(self):
        apply = valid_document()
        validate(apply)
        apply["token_policy"]["expires_at"] = "2026-08-09T12:30:01Z"
        with self.assertRaises(MODULE.ReceiptError):
            validate(apply)

        audit = valid_document("audit")
        validate(audit, "audit")
        audit["token_policy"]["expires_at"] = "2026-08-09T13:00:01Z"
        with self.assertRaises(MODULE.ReceiptError):
            validate(audit, "audit")

    def test_preflight_pending_and_separate_postflight_revocation_are_required(self):
        mutations = (
            ("preflight", "revocation_status", "verified"),
            ("preflight", "token_active", False),
            ("postflight", "revocation_status", "pending"),
            ("postflight", "verified_with_separate_credential", False),
            ("postflight", "revoked_token_rejected", False),
        )
        for section, field, value in mutations:
            document = valid_document()
            document["verification"][section][field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.ReceiptError):
                validate(document)

        document = valid_document()
        document["verification"]["postflight"]["evidence_sha256"] = HASHES[
            "preflight_evidence_sha256"
        ]
        expected = expected_extra_hashes()
        expected["postflight_evidence_sha256"] = HASHES[
            "preflight_evidence_sha256"
        ]
        with self.assertRaises(MODULE.ReceiptError):
            MODULE.parse_receipt(
                receipt_bytes(document),
                expected_phase="admin-tunnel",
                expected_state_mode="present",
                expected_bindings=expected_bindings(),
                expected_extra_hashes=expected,
                now=NOW,
            )

    def test_one_external_token_id_hash_binds_policy_preflight_and_postflight(self):
        for section in ("token_policy", "preflight", "postflight"):
            document = valid_document()
            target = (
                document[section]
                if section == "token_policy"
                else document["verification"][section]
            )
            target["token_id_sha256"] = "c" * 64
            with self.subTest(section=section), self.assertRaises(
                MODULE.ReceiptError
            ):
                validate(document)

        external = expected_extra_hashes()
        external["token_id_sha256"] = "c" * 64
        with self.assertRaises(MODULE.ReceiptError):
            MODULE.parse_receipt(
                receipt_bytes(valid_document()),
                expected_phase="admin-tunnel",
                expected_state_mode="present",
                expected_bindings=expected_bindings(),
                expected_extra_hashes=external,
                now=NOW,
            )

    def test_revocation_must_precede_expiry_and_timestamps_are_ordered(self):
        document = valid_document()
        document["verification"]["postflight"]["revoked_at"] = (
            "2026-08-09T12:31:00Z"
        )
        document["verification"]["postflight"]["verified_at"] = (
            "2026-08-09T12:32:00Z"
        )
        with self.assertRaises(MODULE.ReceiptError):
            validate(document)

        document = valid_document()
        document["verification"]["postflight"]["revoked_at"] = (
            "2026-08-09T12:00:30Z"
        )
        with self.assertRaises(MODULE.ReceiptError):
            validate(document)

    def test_json_duplicate_missing_extra_and_nonfinite_values_are_rejected(self):
        raw = receipt_bytes(valid_document())
        duplicate = raw.replace(
            b'"phase":', b'"phase":"admin-tunnel","phase":', 1
        )
        with self.assertRaises(MODULE.DuplicateKeyError):
            MODULE.parse_receipt(
                duplicate,
                expected_phase="admin-tunnel",
                expected_state_mode="present",
                expected_bindings=expected_bindings(),
                expected_extra_hashes=expected_extra_hashes(),
                now=NOW,
            )
        for mutation in ("missing", "extra"):
            document = valid_document()
            if mutation == "missing":
                del document["controls"]["mfa_verified"]
            else:
                document["controls"]["unknown"] = False
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.ReceiptError):
                validate(document)
        nonfinite = raw.replace(b'"phase":"admin-tunnel"', b'"phase":NaN')
        with self.assertRaises(MODULE.ReceiptError):
            MODULE.parse_receipt(
                nonfinite,
                expected_phase="admin-tunnel",
                expected_state_mode="present",
                expected_bindings=expected_bindings(),
                expected_extra_hashes=expected_extra_hashes(),
                now=NOW,
            )

    def test_raw_secret_shapes_are_rejected_before_json_processing(self):
        # Assemble at runtime so the tracked test itself never resembles a secret.
        secret_shapes = (
            "AGE-" + "SECRET-KEY-PQ-1" + "A" * 30,
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "cf" + "k_" + "A" * 40 + "deadbeef",
            "cloudflare_api_token: " + "L" * 40,
            "Authorization: Bearer " + "B" * 40,
            "eyJ" + "T" * 96,
            "gh" + "p_" + "A" * 36,
            "github_" + "pat_" + "A" * 82,
        )
        raw = receipt_bytes(valid_document())
        for secret in secret_shapes:
            with self.subTest(kind=secret[:4]), self.assertRaisesRegex(
                MODULE.ReceiptError, "forbidden credential"
            ):
                MODULE.parse_receipt(
                    raw + secret.encode(),
                    expected_phase="admin-tunnel",
                    expected_state_mode="present",
                    expected_bindings=expected_bindings(),
                    expected_extra_hashes=expected_extra_hashes(),
                    now=NOW,
                )

    def test_reader_requires_absolute_outside_repo_single_link_regular_file(self):
        with tempfile.TemporaryDirectory() as protected_directory:
            with self.assertRaises(MODULE.ReceiptError):
                MODULE.read_receipt("relative/receipt.json", protected_directory)
            with tempfile.NamedTemporaryFile(dir=ROOT, delete=False) as handle:
                inside_repo = Path(handle.name)
                handle.write(b"{}")
            try:
                with self.assertRaises(MODULE.ReceiptError):
                    MODULE.read_receipt(str(inside_repo), protected_directory)
            finally:
                inside_repo.unlink()

        with tempfile.TemporaryDirectory() as directory:
            resolved = Path(directory).resolve()
            source = resolved / "receipt.json"
            alias = resolved / "receipt-hardlink.json"
            source.write_bytes(b"{}")
            if os.name == "posix":
                source.chmod(0o600)
            self.assertEqual(MODULE.read_receipt(str(source), str(resolved)), b"{}")
            os.link(source, alias)
            with self.assertRaises(MODULE.ReceiptError):
                MODULE.read_receipt(str(source), str(resolved))

    def test_reader_requires_receipt_inside_explicit_protected_root(self):
        with tempfile.TemporaryDirectory() as protected_directory, \
                tempfile.TemporaryDirectory() as other_directory:
            source = Path(other_directory) / "receipt.json"
            source.write_bytes(b"{}")
            if os.name == "posix":
                source.chmod(0o600)
            with self.assertRaises(MODULE.ReceiptError):
                MODULE.read_receipt(str(source), protected_directory)

    def test_reader_rejects_symlink_and_oversize_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            link = root / "receipt.json"
            target.write_bytes(b"{}")
            if os.name == "posix":
                target.chmod(0o600)
            try:
                link.symlink_to(target)
            except OSError:
                link = None
            if link is not None:
                with self.assertRaises(MODULE.ReceiptError):
                    MODULE.read_receipt(str(link), directory)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (MODULE.MAX_RECEIPT_BYTES + 1))
            if os.name == "posix":
                oversized.chmod(0o600)
            with self.assertRaises(MODULE.ReceiptError):
                MODULE.read_receipt(str(oversized), directory)

    @unittest.skipUnless(os.name == "nt", "Windows-local path rules are host-specific")
    def test_reader_rejects_unc_device_ads_and_win32_alias_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (
                r"\\server\share\receipt.json",
                r"\\?\C:\protected\receipt.json",
                r"C:\protected\receipt.json:alternate",
                "C:\\protected\\alias.\\receipt.json",
                "C:\\protected\\alias \\receipt.json",
            ):
                with self.subTest(path_kind=path[:4]), self.assertRaises(
                    MODULE.ReceiptError
                ):
                    MODULE.read_receipt(path, directory)

    def test_cli_success_output_is_bounded_and_never_prints_the_path_or_content(self):
        private_path = str(Path(tempfile.gettempdir()) / "operator-private-receipt.json")
        argv = [
            "--receipt", private_path,
            "--credential-root", tempfile.gettempdir(),
            "--phase", "admin-tunnel",
            "--state-mode", "present",
        ]
        for name, (option, _environment_name) in MODULE.BINDING_ARGUMENTS.items():
            argv.extend((f"--{option}", HASHES[name]))
        for name, (option, _environment_name) in MODULE.EXTRA_EXPECTED_ARGUMENTS.items():
            argv.extend((f"--{option}", HASHES[name]))
        stdout = io.StringIO()
        stderr = io.StringIO()
        loaded = MODULE.LoadedReceipt("admin-tunnel", "b" * 64)
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            MODULE, "read_receipt", return_value=b"PRIVATE-CONTENT"
        ), mock.patch.object(
            MODULE, "parse_receipt", return_value=loaded
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = MODULE.main(argv)
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            stdout.getvalue().splitlines(),
            [
                "PASS Cloudflare phase-token receipt",
                "phase=admin-tunnel",
                "receipt_sha256=" + "b" * 64,
                "evidence_role=operator-attestation-plus-live-verification-record",
            ],
        )
        self.assertNotIn(private_path, stdout.getvalue())
        self.assertNotIn("PRIVATE-CONTENT", stdout.getvalue())

    def test_cli_environment_and_cli_sources_cannot_be_ambiguous(self):
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {MODULE.RECEIPT_PATH_ENV: str(Path(tempfile.gettempdir()) / "receipt.json")},
            clear=True,
        ), contextlib.redirect_stderr(stderr):
            result = MODULE.main(["--receipt", "C:\\different\\receipt.json"])
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "FAIL Cloudflare phase-token receipt\n")
        self.assertNotIn("different", stderr.getvalue())

    def test_cli_parser_never_echoes_an_unrecognized_secret_shaped_value(self):
        secret_shaped_option = "--" + "cf" + "k_" + "A" * 40 + "deadbeef"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(stderr):
            result = MODULE.main([secret_shaped_option])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "FAIL Cloudflare phase-token receipt\n")
        self.assertNotIn(secret_shaped_option, stderr.getvalue())

    def test_validator_has_no_network_command_or_secret_output_surface(self):
        source = SCRIPT.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        for forbidden in ("subprocess", "socket", "urllib", "requests", "http"):
            self.assertNotIn(forbidden, imported_roots)
        for forbidden in ("print(raw", "print(text", "print(path_text", "shell=true"):
            self.assertNotIn(forbidden, source.lower())
        for required in (
            "MAX_RECEIPT_BYTES = 16 * 1024",
            "object_pairs_hook=_reject_duplicate_keys",
            "O_NOFOLLOW",
            "_open_posix_no_follow",
            "dir_fd=parent_descriptor",
            "FILE_ATTRIBUTE_REPARSE_POINT",
            "CREDENTIAL_ROOT_ENV",
            "receipt path must remain inside the protected workspace",
            "operator-attestation-plus-live-verification-record",
        ):
            self.assertIn(required, source)

    def test_runbook_denies_proof_and_authorization_semantics(self):
        text = " ".join(RUNBOOK.read_text(encoding="utf-8").split())
        for fragment in (
            "operator attestation plus a live-verification record",
            "not cryptographic proof",
            "does not authorize",
            "never contains the token",
            "separate credential",
            "30 minutes",
            "60 minutes",
            "outside the repository",
            "all Cloudflared connectors and Tunnels in the account",
            # A website token also carries Zone Settings Write, so the reach
            # sentence must say so: the previous "all DNS records in that one
            # zone" understated it and an operator minting from it would have
            # produced an under-scoped token.
            "every DNS record and every zone setting in that one zone",
            "Zone Settings Write",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)


if __name__ == "__main__":
    unittest.main()
