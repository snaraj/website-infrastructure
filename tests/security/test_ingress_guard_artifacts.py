"""Pin the tracked ingress-guard artifacts, ordering, and gate wiring.

The guard is only as strong as its persistence and its wiring: the unit must
load before kubelet and refuse the silent-skip path, the kubelet drop-in
must stay a hard Requires= dependency, the loader must stay transactional
with a bounded rollback, the verify wrapper must stay read-only, and the
validators must stay wired into the Makefile and the pull-request gate so
none of it can rot invisibly.
"""

import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD_DIR = REPO_ROOT / "bootstrap" / "pi" / "ingress-guard"
SCRIPT = REPO_ROOT / "scripts" / "validate_ingress_guard.py"

spec = importlib.util.spec_from_file_location("validate_ingress_guard", SCRIPT)
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


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
        for fragment in (
            "set -euo pipefail",
            "CONTRACT ",
            "--expect-absent",
            "PREEXISTING_STATE",
            "nft -c -f",
            "nft delete table inet \"${owned_table}\"",
            "ROLLBACK_AMBIGUOUS",
            "ROLLED_BACK_VERIFICATION_FAILED",
        ):
            self.assertIn(fragment, self.loader)
        self.assertIn(
            "owned_table=website_infrastructure_ingress_guard", self.loader
        )
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
            "TARGET_CONFLICT",
            "ROLLED_BACK_THIS_RUN_ONLY",
            "STAGED_CONTRACT_INVALID",
        ):
            self.assertIn(fragment, self.installer)

    def test_no_guard_script_can_start_or_restart_platform_services(self):
        for text in (self.loader, self.verify, self.installer):
            body = code(text)
            self.assertNotIn("systemctl start kubelet", body)
            self.assertNotIn("systemctl restart", body)
            self.assertNotIn("kubeadm reset", body)
            self.assertNotIn("systemctl reboot", body)
            self.assertNotIn("shutdown", body)
        # The installer may start exactly one unit: the guard itself.
        self.assertIn('systemctl start "${guard_unit}"', self.installer)

    def test_diagnostics_stay_value_free_tokens(self):
        # nft output can echo rule text (interface names), so every nft
        # invocation that could print must discard stderr.
        for line in self.loader.splitlines() + self.verify.splitlines():
            stripped = line.strip()
            if stripped.startswith("nft ") or " nft " in f" {stripped} ":
                if "command -v" in stripped or stripped.startswith("#"):
                    continue
                self.assertIn("2>/dev/null", stripped, stripped)


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
        loaded = importlib.util.spec_from_file_location("vr_wiring", repository)
        module = importlib.util.module_from_spec(loaded)
        loaded.loader.exec_module(module)
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


if __name__ == "__main__":
    unittest.main()
