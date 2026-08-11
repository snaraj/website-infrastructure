#!/usr/bin/env python3
"""Hermetic kubelet partial-init state matrix for the collision/ordering gates.

Issue #49 item 2: a partial control-plane init leaves kubelet.service in
states the happy-path fixtures never exercised — stopped (``inactive`` with
the unit still installed and enabled) or crash-looping (``activating`` with
SubState ``auto-restart``, because systemd keeps restarting a kubelet whose
control plane never came up). The two recovery-path gates that must hold
against those states are:

* the runtime installer's pre-mutation collision gate in
  bootstrap/pi/install-kubernetes.sh (``for name in containerd.service
  kubelet.service``), which must refuse to reinstall over ANY pre-existing
  service state; and
* the ingress-guard installer's ordering gate in
  bootstrap/pi/ingress-guard/install-ingress-guard.sh, which must refuse a
  live retrofit (``die KUBELET_ALREADY_ACTIVE``).

Both gates sit behind root/exact-confirmation/payload gates, so the whole
scripts cannot be executed by a test harness (see
test_service_collision_guard_ordering.py, which pins the same contract
textually). This battery gets functional coverage anyway by executing the
gates' OWN text: each region is sliced verbatim out of the shipped script
between load-bearing markers — never re-typed here — prefixed only with
stub ``die``/``check_sha`` definitions and the two ``guard_dropin_*``
variables the region reads, and run under the script's own ``set -euo
pipefail`` discipline. If a platform-lane restructuring moves the markers,
the slice fails loudly instead of silently testing stale text.

The fake-systemctl fixture set makes the run hermetic: a ``systemctl``
shim earlier on PATH replays one pinned host state per scenario and logs
every invocation, so no live systemd, host, or network is ever consulted.
The shim models the real exit-code semantics the gates depend on —
verified against systemctl(1) — most importantly that ``is-active``
succeeds ONLY for an active (or reloading) unit: ``inactive``, ``failed``,
and ``activating``/auto-restart all exit non-zero, which is exactly why
the collision gate's enablement and unit-file probes are load-bearing for
partial-init states and an activation probe alone would wave them through.
``stat`` and ``sha256sum`` are shimmed beside it (custody is host state a
test cannot own, and sha256sum does not exist on every dev platform; the
shim still computes the REAL digest via hashlib so the recorded hash is
verifiable). Everything else (find, sort, awk) runs real against
temporary directories only.

NOTE — restarting kubelet vs the guard installer's exact-match refusal
(pending-contract ratchet, same style as the duplicate-row NOTE in
test_containerd_cri_health_contract_matrix.py). The ordering gate
string-compares ``ActiveState`` to ``active``, so a kubelet mid
crash-loop — ``activating``/auto-restart, a unit systemd is about to
start again — is NOT refused today, even though installing the guard
under it is operationally a live retrofit. The gap is recorded two ways:
``test_restarting_kubelet_is_currently_tolerated`` pins the shipped
behavior green, and ``test_pending_restarting_kubelet_refusal_xfail``
asserts the desired refusal under ``unittest.expectedFailure``. Because
the harness executes the EXTRACTED shipped text, the day the platform
lane widens the refusal both flip on their own — the tolerated pin goes
red and the xfail becomes an unexpected success, a hard failure under
``python -m unittest`` — forcing the marker's removal and converting
this note into an enforced deny row. Nothing here changes what the
shipped scripts enforce.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "bootstrap" / "pi" / "install-kubernetes.sh"
GUARD_INSTALLER = (
    REPO_ROOT / "bootstrap" / "pi" / "ingress-guard" / "install-ingress-guard.sh"
)
# The tracked drop-in source the collision gate hashes on its tolerance leg;
# read-only platform-lane input, byte-copied into each scenario's temp tree.
GUARD_DROPIN_SOURCE = (
    REPO_ROOT
    / "bootstrap"
    / "pi"
    / "ingress-guard"
    / "systemd"
    / "kubelet.service.d"
    / "50-website-infrastructure-ingress-guard.conf"
)
GUARD_DROPIN_NAME = "50-website-infrastructure-ingress-guard.conf"

# Slice markers. COLLISION_LOOP matches the textual pin in
# test_service_collision_guard_ordering.py; the region ends at the loop's
# own two-space ``done``. The guard gate is the one ActiveState refusal.
COLLISION_LOOP = "for name in containerd.service kubelet.service; do"
COLLISION_END = "\n  done\n"
GUARD_GATE_START = (
    'if [[ "$(systemctl show -p ActiveState --value kubelet.service'
)
GUARD_GATE_END = "\nfi\n"

BASH = shutil.which("bash")

# Refusals exit through the stub ``die`` below with this distinctive code,
# so a scenario's outcome is never confused with an unmodeled-command trip
# (97 from the shims) or an incidental bash failure.
DIE_STATUS = 70
STUB_PREAMBLE = """set -euo pipefail
die() { printf 'DIE %s\\n' "$1" >&2; exit 70; }
check_sha() { printf 'check_sha %s %s\\n' "$1" "$2" >>"${FAKE_SYSTEMCTL_LOG}"; }
guard_dropin_source="${FAKE_GUARD_DROPIN_SOURCE}"
guard_dropin_target="${FAKE_GUARD_DROPIN_TARGET}"
"""

# --- The fake-systemctl fixture set. -------------------------------------
# One shim, one pinned host state per scenario: each unit's state is a
# ``ActiveState|UnitFileState|FragmentPath|DropInPaths`` tuple in the
# environment, and every invocation is appended to FAKE_SYSTEMCTL_LOG so
# the battery can attribute a refusal to the exact probe that caught it.
# Unmodeled commands and units exit 97 loudly: the harness must never lean
# on behavior the fixture does not deliberately replay.
FAKE_SYSTEMCTL = """#!/usr/bin/env bash
set -u
printf 'systemctl %s\\n' "$*" >>"${FAKE_SYSTEMCTL_LOG}"
unmodeled() { printf 'systemctl-unmodeled %s\\n' "$*" >>"${FAKE_SYSTEMCTL_LOG}"; exit 97; }
load_state() {
  case "$1" in
    kubelet.service) state="${FAKE_KUBELET_STATE}" ;;
    containerd.service) state="${FAKE_CONTAINERD_STATE}" ;;
    *) unmodeled "$@" ;;
  esac
  IFS='|' read -r active_state unit_file_state fragment_path dropin_paths <<<"${state}"
}
case "${1:-}" in
  is-active)
    [[ "${2:-}" == --quiet && -n "${3:-}" ]] || unmodeled "$@"
    load_state "$3"
    # systemctl(1): is-active succeeds only when the unit IS active (or
    # reloading). inactive, failed, and activating/auto-restart all exit
    # 3 — the crash-looping partial-init kubelet is invisible to this
    # probe, which is why the gates cannot rely on it alone.
    [[ "${active_state}" == active ]] && exit 0
    exit 3
    ;;
  is-enabled)
    [[ "${2:-}" == --quiet && -n "${3:-}" ]] || unmodeled "$@"
    load_state "$3"
    # enabled exits 0; disabled exits 1; a unit with no unit file at all
    # fails with a lookup error. The gates branch only on success.
    [[ "${unit_file_state}" == enabled ]] && exit 0
    exit 1
    ;;
  cat)
    [[ -n "${2:-}" ]] || unmodeled "$@"
    load_state "$2"
    # cat renders whatever unit files exist — fragment and/or drop-ins —
    # and fails only when there are none. A drop-in without a fragment
    # (the sanctioned guard-before-runtime state) therefore SUCCEEDS,
    # which is what routes the collision gate into its tolerance leg.
    if [[ -n "${fragment_path}" || -n "${dropin_paths}" ]]; then
      printf '# %s\\n' "${fragment_path:-${dropin_paths}}"
      exit 0
    fi
    printf 'No files found for %s.\\n' "$2" >&2
    exit 1
    ;;
  show)
    [[ "${2:-}" == -p && -n "${3:-}" && "${4:-}" == --value && -n "${5:-}" ]] || unmodeled "$@"
    load_state "$5"
    # show succeeds even for unloaded units, printing the property value
    # (possibly empty) — the gates parse stdout, not the exit code.
    case "$3" in
      ActiveState) printf '%s\\n' "${active_state}" ;;
      UnitFileState) printf '%s\\n' "${unit_file_state}" ;;
      FragmentPath) printf '%s\\n' "${fragment_path}" ;;
      DropInPaths) printf '%s\\n' "${dropin_paths}" ;;
      *) unmodeled "$@" ;;
    esac
    exit 0
    ;;
  *) unmodeled "$@" ;;
esac
"""

# Custody is host state a non-root test cannot own, so the tolerance leg's
# one stat invocation is replayed from the fixture (root-owned 0644 by
# default, matching what the gate demands of the real drop-in).
FAKE_STAT = """#!/usr/bin/env bash
set -u
printf 'stat %s\\n' "$*" >>"${FAKE_SYSTEMCTL_LOG}"
[[ "${1:-}" == -c && "${2:-}" == '%u:%g:%a' && -n "${3:-}" ]] || exit 97
printf '%s\\n' "${FAKE_STAT_CUSTODY:-0:0:644}"
"""

# sha256sum is absent on some development platforms; the shim computes the
# REAL digest through hashlib so the hash the gate records stays verifiable
# against the tracked source instead of becoming fixture fiction.
FAKE_SHA256SUM = """#!/usr/bin/env bash
set -u
printf 'sha256sum %s\\n' "$*" >>"${FAKE_SYSTEMCTL_LOG}"
exec python3 - "$@" <<'PYEOF'
import hashlib
import sys

for path in [argument for argument in sys.argv[1:] if argument != "--"]:
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    print(digest + "  " + path)
PYEOF
"""

# Real unit-file locations as the installer creates them; used verbatim in
# fixtures so FragmentPath refusals exercise the true post-partial-init
# shape rather than a placeholder.
KUBELET_FRAGMENT = "/etc/systemd/system/kubelet.service"
CONTAINERD_FRAGMENT = "/etc/systemd/system/containerd.service"


def unit_state(active="inactive", unit_file="absent", fragment="", dropins=""):
    """Encode one unit's pinned systemd state for the shim."""

    return "|".join((active, unit_file, fragment, dropins))


# A host with no containerd/kubelet state at all: every kubelet-focused
# scenario pins containerd to this so the loop's first iteration falls
# through and the kubelet leg is exercised in isolation.
UNIT_ABSENT = unit_state()


def slice_region(text, start_marker, end_marker):
    """Cut the gate's shipped text between markers; missing markers raise."""

    start = text.index(start_marker)
    end = text.index(end_marker, start) + len(end_marker)
    return text[start:end]


@unittest.skipUnless(os.name == "posix", "the harness drives bash with a PATH shim")
@unittest.skipUnless(BASH, "bash is required to execute the extracted gates")
class FakeSystemctlHarness(unittest.TestCase):
    """Shared machinery: build the shim set, run one extracted gate region."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        # Resolve the Optional interpreter once, before any argv exists:
        # the class-level skip already excludes bash-less hosts, and this
        # fail-closed floor keeps a None out of subprocess argv if that
        # guard is ever lost. Subclasses extend setUpClass and must call
        # super().
        cls.bash = required_tool(
            BASH, "bash not found - the partial-init matrix cannot run"
        )

    def run_gate(self, region, kubelet, containerd=UNIT_ABSENT, with_dropin_file=False):
        """Execute one extracted gate under the fake-systemctl fixture set.

        Returns ``(completed, log_lines)`` where ``log_lines`` is every
        shim invocation in order. ``with_dropin_file`` byte-copies the
        tracked guard drop-in into the scenario's temp drop-in directory
        so the tolerance leg's real ``find`` enumeration sees exactly the
        sanctioned single entry. A ``__TARGET__`` placeholder in the
        kubelet state resolves to the per-run temp drop-in path, which
        only exists once the harness has built it.
        """

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            for name, body in (
                ("systemctl", FAKE_SYSTEMCTL),
                ("stat", FAKE_STAT),
                ("sha256sum", FAKE_SHA256SUM),
            ):
                shim = fake_bin / name
                shim.write_text(body, encoding="utf-8")
                shim.chmod(0o700)
            log_path = Path(directory) / "invocations.log"
            log_path.touch()
            dropin_dir = Path(directory) / "kubelet.service.d"
            dropin_dir.mkdir()
            dropin_target = dropin_dir / GUARD_DROPIN_NAME
            if with_dropin_file:
                dropin_target.write_bytes(GUARD_DROPIN_SOURCE.read_bytes())
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                    "FAKE_SYSTEMCTL_LOG": str(log_path),
                    "FAKE_KUBELET_STATE": kubelet.replace(
                        "__TARGET__", str(dropin_target)
                    ),
                    "FAKE_CONTAINERD_STATE": containerd,
                    "FAKE_GUARD_DROPIN_SOURCE": str(GUARD_DROPIN_SOURCE),
                    "FAKE_GUARD_DROPIN_TARGET": str(dropin_target),
                }
            )
            completed = subprocess.run(
                [self.bash, "-c", STUB_PREAMBLE + region, "gate"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            log_lines = log_path.read_text(encoding="utf-8").splitlines()
        self.assertNotEqual(
            completed.returncode,
            97,
            "the gate reached a command/unit the fixture does not model: %r"
            % (log_lines,),
        )
        return completed, log_lines


class RuntimeInstallerCollisionGateMatrixTests(FakeSystemctlHarness):
    """Drive the shipped collision gate across the partial-init state matrix."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.region = slice_region(
            INSTALLER.read_text(encoding="utf-8"), COLLISION_LOOP, COLLISION_END
        )

    def test_extracted_region_is_the_pre_mutation_collision_gate(self):
        # Bind the slice to what it must be: all three probe families and
        # the documented refusal, and none of the mutation machinery that
        # follows the gate — so a marker drift can never leave this battery
        # exercising the wrong text.
        for fragment in (
            'systemctl is-active --quiet "${name}" 2>/dev/null',
            'systemctl is-enabled --quiet "${name}" 2>/dev/null',
            'systemctl cat "${name}" >/dev/null 2>&1 || continue',
            "refusing to replace or alter existing systemd service state",
            'check_sha "${guard_dropin_hash}" "${guard_dropin_target}"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.region)
        for mutation in (
            "transaction_started='yes'",
            "systemctl daemon-reload",
            "systemctl enable",
            "exclusive_install",
        ):
            with self.subTest(mutation=mutation):
                self.assertNotIn(mutation, self.region)

    def test_clean_host_passes_and_probes_both_services_in_order(self):
        # The one sanctioned runtime-install target: no containerd/kubelet
        # state anywhere. The gate must complete AND must have consulted
        # every probe for both services, in unit order — the functional
        # twin of the textual loop-header pin.
        completed, log_lines = self.run_gate(self.region, kubelet=UNIT_ABSENT)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            log_lines,
            [
                "systemctl is-active --quiet containerd.service",
                "systemctl is-enabled --quiet containerd.service",
                "systemctl cat containerd.service",
                "systemctl is-active --quiet kubelet.service",
                "systemctl is-enabled --quiet kubelet.service",
                "systemctl cat kubelet.service",
            ],
        )

    def test_tracked_guard_dropin_state_passes_with_verified_custody(self):
        # Guard-then-runtime ordering (PLAT-DEC-001): the only other allow
        # row is kubelet carrying EXACTLY the tracked ingress-guard drop-in
        # under root-owned 0644 custody. The recorded hash must be the real
        # digest of the tracked source — the tolerance is byte-bound, not
        # name-bound.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(dropins="__TARGET__"),
            with_dropin_file=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        recorded = [line for line in log_lines if line.startswith("check_sha ")]
        self.assertEqual(len(recorded), 1, log_lines)
        digest = hashlib.sha256(GUARD_DROPIN_SOURCE.read_bytes()).hexdigest()
        self.assertEqual(recorded[0].split(" ")[1], digest)
        self.assertTrue(
            any(line.startswith("stat -c %u:%g:%a ") for line in log_lines),
            log_lines,
        )

    def assert_refused_for(self, completed, unit):
        self.assertEqual(completed.returncode, DIE_STATUS, completed.stderr)
        self.assertIn(
            "refusing to replace or alter existing systemd service state: " + unit,
            completed.stderr,
        )

    def test_active_kubelet_refuses_via_the_activation_probe(self):
        # Init got far enough to start kubelet before failing: the very
        # first kubelet probe catches it, and the shell's short-circuit
        # proves it — no enablement probe ever runs.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="active", unit_file="enabled", fragment=KUBELET_FRAGMENT
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertIn("systemctl is-active --quiet kubelet.service", log_lines)
        self.assertNotIn("systemctl is-enabled --quiet kubelet.service", log_lines)

    def test_inactive_enabled_kubelet_refuses_via_the_enablement_probe(self):
        # Partial-init state 1: kubelet stopped but still installed and
        # enabled. is-active exits 3 for inactive, so the refusal REQUIRES
        # the enablement probe — both invocations in the log prove the
        # activation probe alone would have waved this host through.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="inactive", unit_file="enabled", fragment=KUBELET_FRAGMENT
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertIn("systemctl is-active --quiet kubelet.service", log_lines)
        self.assertIn("systemctl is-enabled --quiet kubelet.service", log_lines)
        self.assertNotIn("systemctl cat kubelet.service", log_lines)

    def test_restarting_kubelet_refuses_via_the_enablement_probe(self):
        # Partial-init state 2: kubelet crash-looping under auto-restart.
        # ActiveState is ``activating`` — NOT active — so is-active exits 3
        # here too; only the enablement probe stands between this host and
        # a reinstall over a unit systemd is about to start again.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="activating", unit_file="enabled", fragment=KUBELET_FRAGMENT
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertIn("systemctl is-active --quiet kubelet.service", log_lines)
        self.assertIn("systemctl is-enabled --quiet kubelet.service", log_lines)
        self.assertNotIn("systemctl cat kubelet.service", log_lines)

    def test_inactive_disabled_kubelet_unit_refuses_via_the_unit_file_probes(self):
        # An operator who disabled kubelet mid-recovery but left the unit
        # file: activation and enablement probes both miss, so the refusal
        # falls to the cat probe and the FragmentPath validation — a real
        # kubelet.service fragment can never satisfy the drop-in-only
        # tolerance.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="inactive",
                unit_file="disabled",
                fragment=KUBELET_FRAGMENT,
                dropins="__TARGET__",
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertIn("systemctl cat kubelet.service", log_lines)
        self.assertIn(
            "systemctl show -p FragmentPath --value kubelet.service", log_lines
        )

    def test_restarting_disabled_kubelet_unit_refuses_via_the_unit_file_probes(self):
        # The crash-loop variant of the same recovery posture: disabled but
        # manually started into auto-restart. Same unit-file refusal.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="activating",
                unit_file="disabled",
                fragment=KUBELET_FRAGMENT,
                dropins="__TARGET__",
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertIn("systemctl cat kubelet.service", log_lines)
        self.assertIn(
            "systemctl show -p FragmentPath --value kubelet.service", log_lines
        )

    def test_full_partial_init_host_refuses_on_containerd_before_kubelet(self):
        # The faithful whole-host state after a partial init: containerd
        # still running and enabled, kubelet crash-looping. The gate must
        # refuse on the loop's FIRST iteration — containerd — before any
        # kubelet probe runs at all.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="activating", unit_file="enabled", fragment=KUBELET_FRAGMENT
            ),
            containerd=unit_state(
                active="active", unit_file="enabled", fragment=CONTAINERD_FRAGMENT
            ),
        )
        self.assert_refused_for(completed, "containerd.service")
        self.assertEqual(
            log_lines, ["systemctl is-active --quiet containerd.service"]
        )


class IngressGuardOrderingGateMatrixTests(FakeSystemctlHarness):
    """Drive the guard installer's kubelet refusal across the same states."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.region = slice_region(
            GUARD_INSTALLER.read_text(encoding="utf-8"),
            GUARD_GATE_START,
            GUARD_GATE_END,
        )

    def test_extracted_region_is_the_ordering_refusal_and_nothing_more(self):
        self.assertIn("die KUBELET_ALREADY_ACTIVE", self.region)
        for mutation in ("install_exact", "systemctl start", "systemctl enable"):
            with self.subTest(mutation=mutation):
                self.assertNotIn(mutation, self.region)

    def probe_gate(self, active_state):
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active=active_state,
                unit_file="enabled",
                fragment=KUBELET_FRAGMENT,
            ),
        )
        # The gate's one probe, in its exact shipped shape.
        self.assertEqual(
            log_lines,
            ["systemctl show -p ActiveState --value kubelet.service"],
        )
        return completed

    def test_active_kubelet_is_refused(self):
        completed = self.probe_gate("active")
        self.assertEqual(completed.returncode, DIE_STATUS, completed.stderr)
        self.assertIn("DIE KUBELET_ALREADY_ACTIVE", completed.stderr)

    def test_inactive_kubelet_after_partial_init_proceeds(self):
        # The sanctioned recovery posture: kubelet fully stopped. Guard
        # installation before (re)init is exactly the guard-then-runtime
        # ordering PLAT-DEC-001 prescribes, so the gate must not refuse.
        completed = self.probe_gate("inactive")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_restarting_kubelet_is_currently_tolerated(self):
        # Shipped behavior, pinned green (module NOTE): the refusal
        # string-matches ActiveState ``active`` exactly, so a kubelet mid
        # auto-restart — ``activating`` — passes the gate today. This pin
        # goes red the day the platform lane widens the refusal, forcing
        # conversion into an enforced deny alongside the xfail below.
        completed = self.probe_gate("activating")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.expectedFailure
    def test_pending_restarting_kubelet_refusal_xfail(self):
        # Desired contract (module NOTE): a crash-looping kubelet is a live
        # kubelet — systemd will start it again momentarily, so installing
        # the guard under it is a live retrofit and should be refused like
        # ``active``. Xfail until the shipped gate says so; the extracted
        # region flips this to an unexpected success automatically when it
        # does.
        completed = self.probe_gate("activating")
        self.assertEqual(completed.returncode, DIE_STATUS)


if __name__ == "__main__":
    unittest.main()
