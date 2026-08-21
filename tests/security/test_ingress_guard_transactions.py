"""Hostile offline tests for ingress-guard custody and retrofit transactions."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .support import load_script

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = load_script("validate_ingress_guard.py", module_name="ingress_tx_validator")


def read(relative):
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def executable(text):
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


SOURCE = "a" * 40
DIGEST = "b" * 64
BOOT = "c" * 64
CLUSTER = "d" * 64


def attestation(**overrides):
    values = {
        "SCHEMA": "ingress-guard-retrofit-attestation-v1",
        "SOURCE_REVISION": SOURCE,
        "MANIFEST_SHA256": DIGEST,
        "BOOT_ID_SHA256": BOOT,
        "CLUSTER_CA_SHA256": CLUSTER,
        "OWNED_TABLE_PRESTATE": "absent",
        "GUARD_UNIT_PRESTATE": "absent",
        "DROPIN_PRESTATE": "absent",
        "KUBELET_PRESTATE": "active",
        "TWO_RETAINED_SESSIONS": "yes",
        "PHYSICAL_LAN_RECOVERY": "yes",
        "FRESH_LOGIN_CANARY": "yes",
        "MUTATION_WINDOW_AUTHORIZED": "yes",
    }
    values.update(overrides)
    return "".join(f"{key}={value}\n" for key, value in values.items())


def errors(text):
    return MODULE.parse_retrofit_attestation_text(
        text, SOURCE, DIGEST, BOOT, CLUSTER
    )


class RetrofitAttestationTests(unittest.TestCase):
    def test_exact_value_free_attestation_passes(self):
        self.assertEqual(errors(attestation()), [])

    def test_every_binding_and_recovery_gate_is_mandatory(self):
        healthy = attestation()
        for key in (
            "SOURCE_REVISION",
            "MANIFEST_SHA256",
            "BOOT_ID_SHA256",
            "CLUSTER_CA_SHA256",
            "OWNED_TABLE_PRESTATE",
            "GUARD_UNIT_PRESTATE",
            "DROPIN_PRESTATE",
            "KUBELET_PRESTATE",
            "TWO_RETAINED_SESSIONS",
            "PHYSICAL_LAN_RECOVERY",
            "FRESH_LOGIN_CANARY",
            "MUTATION_WINDOW_AUTHORIZED",
        ):
            with self.subTest(key=key):
                mutated = "\n".join(
                    line for line in healthy.splitlines() if not line.startswith(key + "=")
                ) + "\n"
                self.assertEqual(errors(mutated), ["RETROFIT_ATTESTATION_INVALID"])

    def test_foreign_duplicate_mismatched_and_injected_values_fail(self):
        cases = (
            attestation() + "FOREIGN=yes\n",
            attestation() + f"SOURCE_REVISION={SOURCE}\n",
            attestation(SOURCE_REVISION="e" * 40),
            attestation(OWNED_TABLE_PRESTATE="healthy"),
            attestation(TWO_RETAINED_SESSIONS="no"),
            attestation(MUTATION_WINDOW_AUTHORIZED="yes;id"),
            attestation().replace("\n", "\r\n"),
            attestation().rstrip("\n"),
        )
        for case in cases:
            with self.subTest(case=case[-32:]):
                self.assertEqual(errors(case), ["RETROFIT_ATTESTATION_INVALID"])


class TransactionShapeTests(unittest.TestCase):
    def test_custody_reconciles_commit_before_receipt_without_reopening_source(self):
        text = executable(read(MODULE.CUSTODY_FILE_REL))
        self.assertIn("operation=verify", text)
        self.assertIn('elif operation == "verify":', text)
        self.assertIn("verify_destination()", text)
        self.assertLess(
            text.index('mv -T -- "${stage}" "${destination}"'),
            text.index('atomic_receipt "${custody_receipt}"'),
        )
        for metadata_guard in (
            "metadata.st_uid != 0",
            "metadata.st_gid != 0",
            "metadata.st_nlink != 1",
            "stat.S_IMODE(metadata.st_mode) != allowed[relative]",
            "observed_files != expected_files",
            "observed_directories != expected_directories",
        ):
            self.assertIn(metadata_guard, text)
        for launch_guard in (
            "os.memfd_create",
            "fcntl.F_ADD_SEALS",
            "fixed launcher manifest binding",
            "exec /usr/bin/python3 -I -B /proc/self/fd/8",
        ):
            self.assertIn(launch_guard, text)

    def test_checkout_entrypoint_and_library_are_never_parsed_before_fixed_launch(self):
        for relative in (MODULE.INSTALLER_FILE_REL, MODULE.RETROFIT_FILE_REL):
            text = executable(read(relative))
            with self.subTest(relative=relative):
                self.assertNotIn('dirname "${BASH_SOURCE[0]}"', text)
                self.assertLess(
                    text.index("TRUSTED_LAUNCH_REQUIRED"),
                    text.index('source "${transaction_library}"'),
                )
                self.assertIn("^/proc/self/fd/[0-9]+$", text)

    def test_custodied_repository_contract_runs_before_host_mutation(self):
        for relative in (MODULE.INSTALLER_FILE_REL, MODULE.RETROFIT_FILE_REL):
            text = executable(read(relative))
            with self.subTest(relative=relative):
                self.assertLess(
                    text.index("ig_verify_custody_contract"),
                    text.index("mutation_started=yes"),
                )

    def test_mutating_entrypoints_defer_repeated_signals_to_one_exit_path(self):
        for relative in (
            MODULE.CUSTODY_FILE_REL,
            MODULE.INSTALLER_FILE_REL,
            MODULE.RETROFIT_FILE_REL,
            MODULE.RECOVERY_FILE_REL,
            MODULE.LOADER_FILE_REL,
        ):
            text = executable(read(relative))
            with self.subTest(relative=relative):
                if "on_exit()" in text:
                    self.assertIn("trap on_exit EXIT", text)
                self.assertIn("trap \"\" HUP INT TERM", text)

    def test_retrofit_orders_guard_proof_before_dependency_and_restart(self):
        text = executable(read(MODULE.RETROFIT_FILE_REL))
        library = executable(read(MODULE.TRANSACTION_LIBRARY_REL))
        health = library[
            library.index("ig_cluster_health_scope()") :
            library.index("ig_verify_cluster_health()")
        ]
        object_loops = [
            line.strip()
            for line in health.splitlines()
            if line.strip().startswith("for object in ")
        ]
        self.assertEqual(
            object_loops,
            [
                "for object in source-controller kustomize-controller helm-controller; do",
                "for object in naranjo-online-tunnel lidersea-com-tunnel; do",
            ],
        )
        self.assertIn(
            'ig_kubectl_name flux-system "deployment/${object}"', health
        )
        self.assertIn(
            'get --raw=/readyz >/dev/null 2>&1 || return 1', health
        )
        self.assertIn('rollout status "deployment/${object}"', health)
        activation = text[text.index('[[ "${CONFIRM_INGRESS_GUARD_RETROFIT:-}"') :]
        guard_proof = activation.index("guard_only_verify ||")
        dropin = activation.index('ig_install_exact "${dropin_source}"')
        restart_intent = activation.index("IG_PHASE=kubelet-restart-intent")
        restart = activation.index("systemctl restart kubelet.service")
        pending = activation.index("IG_PHASE=awaiting-reboot")
        self.assertLess(guard_proof, dropin)
        self.assertLess(dropin, restart_intent)
        self.assertLess(restart_intent, restart)
        self.assertLess(restart, pending)

    def test_ruleset_captures_explicitly_request_kernel_handles(self):
        library = executable(read(MODULE.TRANSACTION_LIBRARY_REL))
        verifier = executable(
            read("bootstrap/pi/ingress-guard/verify-ingress-guard.sh")
        )
        self.assertEqual(
            library.count("ig_run_bounded nft -a -j list ruleset"), 1
        )
        self.assertEqual(verifier.count("run_bounded nft -a -j list ruleset"), 1)
        self.assertNotIn("nft -j list ruleset", library)
        self.assertNotIn("nft -j list ruleset", verifier)

    def test_receipts_are_closed_and_exclude_inventory_values(self):
        library = executable(read(MODULE.TRANSACTION_LIBRARY_REL))
        receipt_body = library[
            library.index("ig_write_receipt()") : library.index("ig_write_receipt()")
            + 2600
        ]
        for field in (
            "schema=ingress-guard-receipt-v2",
            "source_binding=verified",
            "custody_binding=verified",
            "private_contract=validated-root-custody",
            "guard_state=",
            "rollback=",
        ):
            self.assertIn(field, receipt_body)
        for forbidden in (
            "ADMIN_INGRESS_INTERFACE",
            "interface=",
            "address=",
            "ruleset=",
            "peer=",
        ):
            self.assertNotIn(forbidden, receipt_body)
        self.assertIn('%s.%s.%s.receipt.v2', library)
        self.assertIn("custody_receipt_sha256=", receipt_body)
        self.assertIn("cluster_health=", receipt_body)

    def test_reboot_closure_preserves_and_validates_pending_receipt(self):
        retrofit = executable(read(MODULE.RETROFIT_FILE_REL))
        closure = retrofit[
            retrofit.index('if [[ "${mode}" == --close-after-reboot ]]') :
            retrofit.index('[[ "${CONFIRM_INGRESS_GUARD_RETROFIT:-}"')
        ]
        self.assertIn("REBOOT_CLOSURE_BINDING_MISMATCH", closure)
        self.assertIn("pending_receipt=", closure)
        self.assertIn("PENDING_RECEIPT_INVALID", closure)
        self.assertLess(
            closure.index("PENDING_RECEIPT_INVALID"),
            closure.index("ig_write_receipt pass"),
        )

    def test_recovery_keeps_guard_until_active_kubelet_is_restored(self):
        recovery = executable(read(MODULE.RECOVERY_FILE_REL))
        restore = recovery.index("systemctl start kubelet.service")
        stop_guard = recovery.index('systemctl stop "${IG_GUARD_UNIT}"')
        delete_table = recovery.index("ig_delete_owned_table_and_prove_absent")
        self.assertLess(restore, stop_guard)
        self.assertLess(stop_guard, delete_table)
        self.assertIn("GUARD_ENABLEMENT_ROLLBACK_AMBIGUOUS", recovery)
        self.assertIn("KUBELET_DEPENDENCY_ROLLBACK_AMBIGUOUS", recovery)

    def test_recovery_binds_selected_bundle_and_arms_failure_after_rollback_intent(self):
        recovery_source = read(MODULE.RECOVERY_FILE_REL)
        recovery = executable(recovery_source)
        library = executable(read(MODULE.TRANSACTION_LIBRARY_REL))
        load = recovery.index("ig_load_journal")
        rollback_intent = recovery.index("IG_PHASE=rollback-intent")
        publication_arm = recovery.index("recovery_state_publication_armed=yes")
        for selected_binding in (
            '"${IG_SOURCE_REVISION}" == "${launch_revision}"',
            '"${IG_MANIFEST_SHA256}" == "${launch_manifest}"',
            '"${IG_CUSTODY_DIR}" == "${launch_custody}"',
            '"${IG_CUSTODY_RECEIPT_SHA256}" == "${launch_custody_receipt}"',
        ):
            self.assertIn(selected_binding, recovery)
            self.assertLess(load, recovery.index(selected_binding))
            self.assertLess(recovery.index(selected_binding), rollback_intent)
        source_lines = recovery_source.splitlines()
        guard_start = source_lines.index(
            '[[ "${IG_SOURCE_REVISION}" == "${launch_revision}" && \\'
        )
        self.assertEqual(
            source_lines[guard_start : guard_start + 5],
            [
                '[[ "${IG_SOURCE_REVISION}" == "${launch_revision}" && \\',
                '  "${IG_MANIFEST_SHA256}" == "${launch_manifest}" && \\',
                '  "${IG_CUSTODY_DIR}" == "${launch_custody}" && \\',
                '  "${IG_CUSTODY_RECEIPT_SHA256}" == "${launch_custody_receipt}" ]] \\',
                "  || ig_die RECOVERY_BUNDLE_JOURNAL_MISMATCH",
            ],
        )
        self.assertIn('"${recovery_state_publication_armed}" == yes', recovery)
        self.assertLess(
            recovery.index("ig_journal_write", rollback_intent), publication_arm
        )
        receipt_body = library[
            library.index("ig_write_receipt()") : library.index("ig_write_receipt()")
            + 3000
        ]
        self.assertIn('if [[ "${result}" == recovery-required ]]', receipt_body)
        for field in (
            "boot_binding=unverified",
            "cluster_binding=unverified",
            "private_contract=unverified",
        ):
            self.assertIn(field, receipt_body)

    def test_every_mutating_phase_reenters_one_exact_recovery_path(self):
        recovery = executable(read(MODULE.RECOVERY_FILE_REL))
        library = executable(read(MODULE.TRANSACTION_LIBRARY_REL))
        phase_fragment = library[
            library.index('[[ "${IG_PHASE}" =~') :
            library.index('[[ "${IG_TABLE_PRESTATE}" =~')
        ]
        for phase in (
            "prepared",
            "artifacts-installed",
            "guard-start-intent",
            "guard-active",
            "dropin-installed",
            "kubelet-restart-intent",
            "awaiting-reboot-intent",
            "awaiting-reboot",
            "commit-intent",
            "rollback-intent",
            "recovery-required",
        ):
            with self.subTest(phase=phase):
                self.assertIn(phase, phase_fragment)
        self.assertIn(
            'if [[ "${IG_PHASE}" == committed || "${IG_PHASE}" == rolled-back ]]',
            recovery,
        )
        self.assertIn("IG_PHASE=rollback-intent", recovery)


class SecureBindingReadTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "O_NOFOLLOW semantics require POSIX")
    def test_secure_read_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "binding"
            source.write_bytes(b"bound\n")
            accepted = MODULE._secure_read(
                source, 64, lambda metadata: metadata.st_nlink == 1
            )
            self.assertEqual(accepted, b"bound\n")
            symlink = root / "binding-symlink"
            symlink.symlink_to(source)
            self.assertIsNone(
                MODULE._secure_read(
                    symlink, 64, lambda metadata: metadata.st_nlink == 1
                )
            )
            hardlink = root / "binding-hardlink"
            os.link(source, hardlink)
            self.assertIsNone(
                MODULE._secure_read(
                    hardlink, 64, lambda metadata: metadata.st_nlink == 1
                )
            )


class BehavioralTransactionTests(unittest.TestCase):
    def test_real_shell_hostile_namespace_matrix(self):
        fixture = REPO_ROOT / "scripts/ci/ingress_guard_transaction_fixture.py"
        completed = subprocess.run(
            [sys.executable, "-B", os.fspath(fixture)],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1200,
            check=False,
        )
        if completed.stdout.startswith("SKIP:"):
            self.skipTest(completed.stdout.strip())
        self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
        result = json.loads(completed.stdout.splitlines()[-1])
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["scenarios"], 41)
        self.assertEqual(result["failure_phases"], 8)
        self.assertEqual(result["signal_phases"], 16)
        self.assertEqual(result["private_values"], "none")
        self.assertEqual(result["live_actions"], "none")


if __name__ == "__main__":
    unittest.main()
