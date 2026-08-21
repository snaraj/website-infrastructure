"""Pin the tracked ingress-guard artifacts, ordering, and gate wiring.

The guard is only as strong as its persistence and its wiring: the unit must
load before kubelet and refuse the silent-skip path, the kubelet drop-in
must stay a hard Requires= dependency, the loader must stay transactional
with a bounded rollback, the verify wrapper must stay read-only, and the
validators must stay wired into the Makefile and the pull-request gate so
none of it can rot invisibly.
"""

import unittest
import shutil
import tempfile
from pathlib import Path

from .support import load_script

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD_DIR = REPO_ROOT / "bootstrap" / "pi" / "ingress-guard"

MODULE = load_script("validate_ingress_guard.py")


def read(relative):
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def code(text):
    """Return only executable lines: comments must never satisfy or hide a
    mutation-verb assertion."""

    return "\n".join(
        line for line in text.splitlines() if not line.strip().startswith("#")
    )


class TrackedArtifactTests(unittest.TestCase):
    def test_repo_mode_passes_on_the_tracked_tree(self):
        self.assertEqual(MODULE.repo_errors(REPO_ROOT), [])

    def test_unit_orders_guard_before_kubelet_and_refuses_silent_skip(self):
        unit = read(MODULE.UNIT_FILE_REL)
        for fragment in (
            "Before=network-pre.target kubelet.service",
            "Wants=network-pre.target",
            "Type=oneshot",
            "RemainAfterExit=yes",
            "ExecStart=/usr/local/sbin/website-infrastructure-ingress-guard-load",
            "WantedBy=multi-user.target",
            "CapabilityBoundingSet=CAP_NET_ADMIN",
            "IPAddressDeny=any",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "RuntimeDirectory=website-infrastructure-ingress-guard",
            "ReadWritePaths=/var/lib/website-infrastructure/ingress-guard",
        ):
            self.assertIn(fragment, unit)
        # A Condition* line would let systemd skip the guard while still
        # satisfying kubelet's Requires=; it must never appear.
        for line in unit.splitlines():
            self.assertFalse(line.strip().startswith("Condition"), line)
            self.assertFalse(line.strip().startswith("ExecStop"), line)

    def test_unit_contract_rejects_mutations(self):
        healthy = read(MODULE.UNIT_FILE_REL)
        self.assertEqual(MODULE.unit_errors(healthy), [])
        without_ordering = healthy.replace(
            "Before=network-pre.target kubelet.service\n", ""
        )
        self.assertEqual(MODULE.unit_errors(without_ordering), ["UNIT_CONTRACT_VIOLATED"])
        with_condition = healthy + "ConditionPathExists=/etc/website-infrastructure\n"
        self.assertEqual(MODULE.unit_errors(with_condition), ["UNIT_CONTRACT_VIOLATED"])
        with_extra_capability = healthy.replace(
            "CapabilityBoundingSet=CAP_NET_ADMIN\n",
            "CapabilityBoundingSet=CAP_NET_ADMIN\nAmbientCapabilities=CAP_SYS_ADMIN\n",
        )
        self.assertEqual(
            MODULE.unit_errors(with_extra_capability),
            ["UNIT_CONTRACT_VIOLATED"],
        )

    def test_dropin_makes_the_guard_a_hard_kubelet_dependency(self):
        dropin = read(MODULE.DROPIN_FILE_REL)
        self.assertEqual(MODULE.dropin_errors(dropin), [])
        for fragment in (
            "Requires=website-infrastructure-ingress-guard.service",
            "After=website-infrastructure-ingress-guard.service",
        ):
            self.assertIn(fragment, dropin)
        weakened = dropin.replace("Requires=", "Wants=")
        self.assertEqual(MODULE.dropin_errors(weakened), ["DROPIN_CONTRACT_VIOLATED"])

    def test_codex_owned_kubelet_unit_is_not_edited(self):
        kubelet = read("bootstrap/pi/systemd/kubelet.service")
        self.assertNotIn("ingress-guard", kubelet)


class LoaderAndVerifierScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loader = read("bootstrap/pi/ingress-guard/load-ingress-guard.sh")
        cls.verify = read("bootstrap/pi/ingress-guard/verify-ingress-guard.sh")
        cls.installer = read("bootstrap/pi/ingress-guard/install-ingress-guard.sh")

    def test_loader_is_transactional_and_fails_closed(self):
        combined = self.loader + read(
            "bootstrap/pi/ingress-guard/transaction-lib.sh"
        )
        for fragment in (
            "set -Eeuo pipefail",
            "CONTRACT ",
            "--expect-absent",
            "PREEXISTING_STATE",
            "nft -c -f",
            "load_journal_write apply-intent absent none",
            "table_created_in_memory=yes",
            "POST_APPLY_CAPTURE_FAILED",
            "ig_delete_owned_table_and_prove_absent",
        ):
            self.assertIn(fragment, combined)
        # Broad deletion or replacement is forbidden: the only mutation verbs
        # are one atomic load and one exact-table rollback delete.
        self.assertNotIn("flush", code(self.loader))
        self.assertNotIn("set -x", code(self.loader))

    def test_verify_wrapper_is_read_only_and_proves_ordering(self):
        for fragment in (
            "is-enabled",
            "ActiveState",
            "-p After --value kubelet.service",
            "-p Requires --value kubelet.service",
            "KUBELET_ORDERING_MISSING",
            "KUBELET_REQUIRES_MISSING",
            " live ",
        ):
            self.assertIn(fragment, self.verify)
        for mutation in ("nft -f", "nft delete", "nft add", "flush",
                         "systemctl start", "systemctl stop", "systemctl enable"):
            self.assertNotIn(mutation, code(self.verify))

    def test_installer_refuses_root_ssh_active_kubelet_and_overwrites(self):
        for fragment in (
            "ROOT_SSH_FORBIDDEN",
            "KUBELET_ALREADY_ACTIVE",
            "install-reviewed-ssh-only-ingress-guard",
            "TARGET_PRESTATE_INVALID",
            "ROLLED_BACK_VERIFIED",
            "STAGED_CONTRACT_INVALID",
            "MUTABLE_ENTRYPOINT_REFUSED",
        ):
            combined = (
                self.installer
                + read("bootstrap/pi/ingress-guard/custody-ingress-guard.sh")
                + read("bootstrap/pi/ingress-guard/transaction-lib.sh")
            )
            self.assertIn(fragment, combined)

    def test_no_guard_script_can_start_or_restart_platform_services(self):
        for text in (self.loader, self.verify, self.installer):
            body = code(text)
            self.assertNotIn("systemctl start kubelet", body)
            self.assertNotIn("systemctl restart", body)
            self.assertNotIn("kubeadm reset", body)
            self.assertNotIn("systemctl reboot", body)
            self.assertNotIn("shutdown", body)
        # The installer may start exactly one unit: the guard itself.
        self.assertIn('systemctl start --no-block "${IG_GUARD_UNIT}"', self.installer)

    def test_diagnostics_stay_value_free_tokens(self):
        # nft output can echo rule text (interface names), so every nft
        # invocation that could print must discard stderr.
        for line in self.loader.splitlines() + self.verify.splitlines():
            stripped = line.strip()
            if stripped.startswith("nft ") or " nft " in f" {stripped} ":
                if "command -v" in stripped or stripped.startswith("#"):
                    continue
                self.assertTrue(
                    "2>/dev/null" in stripped or "2>&1" in stripped, stripped
                )


class GateWiringTests(unittest.TestCase):
    def test_make_and_ci_run_the_guard_validators(self):
        makefile = read("Makefile")
        self.assertIn("check-ingress-guard:", makefile)
        self.assertIn("validate_ingress_guard.py repo", makefile)
        self.assertIn("validate_admin_ingress_contract.py EXAMPLE", makefile)
        self.assertRegex(makefile, r"(?m)^check: .*check-ingress-guard")
        workflow = read(".github/workflows/pull-request.yml")
        self.assertIn("validate_ingress_guard.py repo", workflow)
        self.assertIn("validate_admin_ingress_contract.py EXAMPLE", workflow)

    def test_private_local_contract_is_ignored_and_layout_gated(self):
        self.assertIn(MODULE.LOCAL_CONTRACT_REL, read(".gitignore"))
        repository = REPO_ROOT / "scripts" / "validate_repository.py"
        module = load_script("validate_repository.py", module_name="vr_wiring")
        self.assertIn(
            MODULE.LOCAL_CONTRACT_REL, module.FORBIDDEN_LOCAL_ONLY_EXACT_NAMES
        )
        self.assertFalse((REPO_ROOT / MODULE.LOCAL_CONTRACT_REL).exists())

    def test_live_proof_design_is_triple_gated_and_never_automatic(self):
        design = " ".join(
            read("docs/assurance/phase-h-ssh-only-ingress-guard.md").split()
        )
        for fragment in (
            "CODEX_PLATFORM_STABLE",
            "direct authorization of the exact probe list",
            "no overlapping Pi mutation",
            "Nothing in this repository can execute this section automatically",
        ):
            self.assertIn(fragment, design)
        for port in ("2379", "2380", "6443", "10250"):
            self.assertIn(port, design)

    def test_trust_boundary_records_ssh_only_admin_plane(self):
        boundaries = read("docs/architecture/trust-boundaries.md")
        self.assertIn("SSH-only, PLAT-DEC-001", boundaries)
        self.assertNotIn("TCP 22/6443", boundaries)
        self.assertIn("kubelet 10250 (host-ingress guard)", boundaries)


class TransactionRegressionTests(unittest.TestCase):
    """Issue #145's two defects must fail the repository gate when restored."""

    @staticmethod
    def _copy_transaction_tree(destination):
        for relative in set(MODULE.PUBLIC_CUSTODY_FILES) | {MODULE.MANIFEST_FILE_REL}:
            source = REPO_ROOT / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def test_manifest_rejects_mutable_source_replacement(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            self._copy_transaction_tree(root)
            self.assertEqual(MODULE.custody_manifest_errors(root), [])
            loader = root / MODULE.LOADER_FILE_REL
            loader.write_text(loader.read_text() + "# replacement\n", encoding="utf-8")
            self.assertEqual(
                MODULE.custody_manifest_errors(root), ["CUSTODY_MANIFEST_INVALID"]
            )

    def test_manifest_rejects_digest_mode_duplicate_and_foreign_mutations(self):
        healthy = (REPO_ROOT / MODULE.MANIFEST_FILE_REL).read_text(encoding="ascii")
        first = healthy.splitlines()[0]
        mutations = (
            healthy.replace(first[:64], "0" * 64, 1),
            healthy.replace("\t0700\t", "\t0777\t", 1),
            healthy + first + "\n",
            healthy + ("0" * 64) + "\t0600\tscripts/foreign.py\n",
        )
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            self._copy_transaction_tree(root)
            manifest = root / MODULE.MANIFEST_FILE_REL
            for mutation in mutations:
                with self.subTest(mutation=mutation[-80:]):
                    manifest.write_text(mutation, encoding="ascii")
                    self.assertEqual(
                        MODULE.custody_manifest_errors(root),
                        ["CUSTODY_MANIFEST_INVALID"],
                    )

    def test_custody_mode_revalidates_the_closed_runtime_tree(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            for relative in MODULE.PUBLIC_CUSTODY_FILES:
                source = REPO_ROOT / relative
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            shutil.copy2(
                REPO_ROOT / MODULE.MANIFEST_FILE_REL,
                root / "source-manifest.v1",
            )
            self.assertEqual(
                MODULE.repo_errors(
                    root,
                    "source-manifest.v1",
                    check_repository_privacy=False,
                ),
                [],
            )

    def test_loader_arms_rollback_before_post_apply_capture(self):
        loader = code(read(MODULE.LOADER_FILE_REL))
        self.assertLess(
            loader.index("table_created_in_memory=yes"),
            loader.index("POST_APPLY_CAPTURE_FAILED"),
        )
        self.assertIn("rollback_load >/dev/null 2>&1", loader)
        self.assertEqual(MODULE.transaction_script_errors(REPO_ROOT), [])

        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            self._copy_transaction_tree(root)
            path = root / MODULE.LOADER_FILE_REL
            text = path.read_text(encoding="utf-8")
            apply = text.index('ig_run_bounded nft -f "${rendered}"')
            created = text.index("table_created_in_memory=yes", apply)
            path.write_text(
                text[:created] + "true" + text[created + len("table_created_in_memory=yes") :],
                encoding="utf-8",
            )
            self.assertEqual(
                MODULE.transaction_script_errors(root),
                ["TRANSACTION_WIRING_INVALID"],
            )

    def test_installer_post_start_failure_reenters_durable_recovery(self):
        installer = code(read(MODULE.INSTALLER_FILE_REL))
        self.assertLess(
            installer.index("mutation_started=yes"),
            installer.index("POST_INSTALL_VERIFICATION_FAILED"),
        )
        self.assertLess(
            installer.index("POST_INSTALL_VERIFICATION_FAILED"),
            installer.rindex("mutation_started=no"),
        )
        self.assertIn("INGRESS_GUARD_AUTOMATIC_RECOVERY=journal-bound", installer)

    def test_running_cluster_has_a_distinct_reboot_closed_transaction(self):
        retrofit = code(read(MODULE.RETROFIT_FILE_REL))
        installer = code(read(MODULE.INSTALLER_FILE_REL))
        self.assertIn("KUBELET_ALREADY_ACTIVE", installer)
        self.assertNotIn("systemctl restart kubelet.service", installer)
        self.assertIn("KUBELET_NOT_ACTIVE", retrofit)
        self.assertIn("systemctl restart kubelet.service", retrofit)
        self.assertIn("IG_PHASE=awaiting-reboot", retrofit)
        self.assertIn("--close-after-reboot", retrofit)


if __name__ == "__main__":
    unittest.main()
