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
payload-SHA gates, so no test harness can execute the whole script without
staging a full signed payload as root. The sibling battery
test_kubelet_partial_init_state_matrix.py now drives both gates
functionally anyway — it executes each gate's own extracted text under a
fake-systemctl fixture set (issue #49), covering the partial-init kubelet
states hermetically — while a platform-lane extraction into a named
sourceable helper remains the path to whole-script functional coverage.
These pins still hold the placement half of the reviewed contract: the
assertions bind which probes exist, what they refuse, and what must come
before what — not one exact control-flow shape — so a platform-lane
restructuring that preserves the contract keeps passing while losing a
probe, a refusal, or the pre-mutation placement fails.
"""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "bootstrap" / "pi" / "install-kubernetes.sh"
GUARD_INSTALLER = (
    REPO_ROOT / "bootstrap" / "pi" / "ingress-guard" / "install-ingress-guard.sh"
)
TRANSACTION_LIBRARY = (
    REPO_ROOT / "bootstrap" / "pi" / "ingress-guard" / "transaction-lib.sh"
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
        library = TRANSACTION_LIBRARY.read_text(encoding="utf-8")
        probe = 'kubelet_state="$(ig_systemctl_state kubelet.service ActiveState)"'
        refusal = "die KUBELET_ALREADY_ACTIVE"
        self.assertIn(probe, script)
        self.assertIn(refusal, script)
        helper_start = library.index("ig_systemctl_state()")
        helper_end = library.index("\n}\n", helper_start)
        helper = library[helper_start:helper_end]
        self.assertIn(
            'ig_run_bounded systemctl show -p "${property}" --value "${unit}"',
            helper,
        )
        # The helper-backed refusal must precede the transaction lock,
        # durable mutation intent, and every system artifact install.
        refusal_at = script.index(refusal)
        self.assertLess(script.index(probe), refusal_at)
        self.assertLess(refusal_at, script.index("ig_acquire_lock"))
        self.assertLess(refusal_at, script.index("mutation_started=yes"))
        self.assertLess(refusal_at, script.index("ig_install_exact"))

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
