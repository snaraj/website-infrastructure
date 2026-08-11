#!/usr/bin/env python3
"""Pin the install-before-guard service-ordering contract, textually.

The peer-reviewed bootstrap ordering has three legs, each owned by a
different artifact and each individually able to rot without the others
noticing:

* the runtime installer must probe for pre-existing containerd.service and
  kubelet.service state (unit file, activation, enablement) BEFORE it
  mutates the host, and must refuse with its documented message when it
  finds any — a fresh host is the only sanctioned runtime-install target;
* the ingress-guard installer must refuse to run while kubelet.service is
  already active — retrofitting the guard under a live cluster is a
  separately authorized operation, never a silent side effect;
* the guard's additive kubelet drop-in must make kubelet.service require
  and order after the guard unit, so a kubelet that starts at all starts
  behind a verified guard (PLAT-DEC-001).

Together those legs force the only safe sequence — install runtime on a
clean host, install the guard before the cluster goes live, and let systemd
refuse any kubelet start that would sidestep the guard.

These are textual pins in the style of test_shell_script_modes.py, not
functional fake-injection probes: the collision gate sits inline in
install-kubernetes.sh's main() behind the root, exact-confirmation, and
payload-SHA gates, so no test harness can reach it without staging a full
signed payload as root. A functional battery needs the platform lane to
extract the gate into a named sourceable helper; until that lands, these
pins hold the reviewed contract in place. The assertions bind the contract
(which probes exist, what they refuse, and what must come before what) and
not one exact control-flow shape, so a platform-lane restructuring that
preserves the contract keeps passing while losing a probe, a refusal, or
the pre-mutation placement fails.
"""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "bootstrap" / "pi" / "install-kubernetes.sh"
GUARD_INSTALLER = (
    REPO_ROOT / "bootstrap" / "pi" / "ingress-guard" / "install-ingress-guard.sh"
)
GUARD_DROPIN = (
    REPO_ROOT
    / "bootstrap"
    / "pi"
    / "ingress-guard"
    / "systemd"
    / "kubelet.service.d"
    / "50-website-infrastructure-ingress-guard.conf"
)

# The gate must inspect exactly the two services the installer is about to
# create; the loop header is load-bearing because dropping either name
# silently halves the collision surface.
COLLISION_LOOP = "for name in containerd.service kubelet.service; do"
# First mutation marker: everything at or after this point may change the
# host, so every collision probe must appear before it.
TRANSACTION_START = "transaction_started='yes'"


class RuntimeInstallerCollisionGateTests(unittest.TestCase):
    """The runtime installer refuses pre-existing service state, pre-mutation."""

    @classmethod
    def setUpClass(cls):
        cls.script = INSTALLER.read_text(encoding="utf-8")

    def gate_region(self):
        """Return the text from the collision loop to the first mutation.

        Scoping the probe assertions to this region proves the probes belong
        to the collision gate itself, not to some later post-install check
        that would run only after the host was already mutated.
        """

        start = self.script.index(COLLISION_LOOP)
        end = self.script.index(TRANSACTION_START)
        self.assertLess(start, end, "collision loop must precede the transaction")
        return self.script[start:end]

    def test_gate_probes_both_services_with_all_three_probes(self):
        region = self.gate_region()
        for probe in (
            # Unit-file presence: a foreign containerd/kubelet unit anywhere
            # in the systemd search path is a collision even when inactive.
            'systemctl cat "${name}"',
            # Activation and enablement state, each probed per service name.
            'systemctl is-active --quiet "${name}" 2>/dev/null',
            'systemctl is-enabled --quiet "${name}" 2>/dev/null',
        ):
            with self.subTest(probe=probe):
                self.assertIn(probe, region)

    def test_gate_refuses_with_the_documented_message(self):
        self.assertIn(
            'die "refusing to replace or alter existing systemd service state:'
            ' ${name}"',
            self.gate_region(),
        )

    def test_gate_is_ordered_before_every_service_mutation(self):
        marker = self.script.index("phase='pre-mutation-collision-validation'")
        loop = self.script.index(COLLISION_LOOP)
        transaction = self.script.index(TRANSACTION_START)
        first_service_mutation = self.script.index(
            "systemctl enable --now containerd.service"
        )
        self.assertLess(marker, loop)
        self.assertLess(loop, transaction)
        self.assertLess(transaction, first_service_mutation)


class IngressGuardOrderingTests(unittest.TestCase):
    """The guard installs before kubelet runs, and kubelet requires the guard."""

    def test_guard_installer_refuses_while_kubelet_is_active(self):
        script = GUARD_INSTALLER.read_text(encoding="utf-8")
        probe = "systemctl show -p ActiveState --value kubelet.service"
        refusal = "die KUBELET_ALREADY_ACTIVE"
        self.assertIn(probe, script)
        self.assertIn(refusal, script)
        # The refusal must precede all mutation machinery: the rollback
        # bookkeeping, the rollback trap, and the first artifact install.
        refusal_at = script.index(refusal)
        self.assertLess(refusal_at, script.index("created_paths=()"))
        self.assertLess(refusal_at, script.index("trap rollback EXIT"))
        self.assertLess(refusal_at, script.index("install_exact"))

    def test_kubelet_dropin_binds_kubelet_to_the_guard_unit(self):
        # Exact whole-line membership: a commented-out or suffixed directive
        # must not satisfy the pin, and the file's own prose mentions the
        # directive names, so substring checks would be satisfiable by a
        # comment alone.
        lines = GUARD_DROPIN.read_text(encoding="utf-8").splitlines()
        self.assertIn("[Unit]", lines)
        section = lines.index("[Unit]")
        for directive in (
            "Requires=website-infrastructure-ingress-guard.service",
            "After=website-infrastructure-ingress-guard.service",
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, lines)
                self.assertGreater(
                    lines.index(directive),
                    section,
                    "ordering directives must live inside the [Unit] section",
                )


if __name__ == "__main__":
    unittest.main()
