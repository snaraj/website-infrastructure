"""A release must fit its namespace — at rest and mid-rollout.

Owner ruling, 2026-08-12: *"Replicacount can be set to 1 but it shouldn't be a
hard limit since we may have new apps with other requirements or we may
introduce a DB etc."* So the durable invariant is capacity, not equality. This
battery drives ``testsupport.capacity_model`` two ways:

* against the REAL rendered connector chart and the REAL committed
  ResourceQuota, so the production configuration is the thing under test; and
* against four synthetic cases that prove the rule is not an equality check in
  disguise — the reason the reshape is verifiable at all.

The trap it was written for is live: at ``replicaCount: 2`` the two connectors
reach ``limits.cpu 2/2`` and ``limits.memory 1Gi/1Gi`` exactly, and the chart's
former ``maxSurge: 1`` then needs a Pod the quota refuses. Steady state fits;
the rollout does not. That failure surfaces only on the NEXT deploy, which is
why a steady-state-only check would have shipped it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

from .testsupport.capacity_model import (
    CapacityError,
    Quota,
    Workload,
    check_namespace_fits,
    parse_cpu,
    parse_memory,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CHART = REPO_ROOT / "kubernetes" / "platform" / "cloudflare-public" / "chart"
RESOURCE_CONTROLS = (
    REPO_ROOT / "kubernetes" / "platform" / "prerequisites" / "resource-controls.yaml"
)
CONNECTOR_NAMESPACE = "cloudflare-public"
HELM = shutil.which("helm")


def committed_quota(namespace):
    """The ``hard`` block of the ResourceQuota committed for a namespace.

    Parsed from the committed text with the standard library, like every other
    contract battery here. FAILS rather than returns None when the namespace has
    no quota: "capacity is not knowable" is a refusal, never a skip.
    """

    text = RESOURCE_CONTROLS.read_text(encoding="utf-8")
    for document in text.split("\n---\n"):
        if "kind: ResourceQuota" not in document:
            continue
        if not re.search(r"(?m)^  namespace: {}$".format(namespace), document):
            continue
        hard = {}
        block = document.split("  hard:\n", 1)
        if len(block) != 2:
            raise CapacityError("{}: ResourceQuota has no hard block".format(namespace))
        for line in block[1].split("\n"):
            if line.startswith("    ") and not line.strip().startswith("#"):
                key, _, value = line.strip().partition(":")
                hard[key] = value.strip().strip('"')
            elif line.strip() and not line.startswith("    "):
                break
        return hard
    raise CapacityError(
        "{}: no committed ResourceQuota; capacity is not knowable".format(namespace)
    )


def render(*overrides):
    command = [
        str(HELM), "template", "cloudflare-public", str(CHART),
        "--namespace", CONNECTOR_NAMESPACE,
    ]
    for override in overrides:
        command.extend(["--set", override])
    completed = subprocess.run(
        command, capture_output=True, text=True, check=False, cwd=str(REPO_ROOT)
    )
    if completed.returncode != 0:
        raise AssertionError("helm template failed: " + completed.stderr)
    return completed.stdout


def rendered_connector_workloads(rendered):
    """Every rendered connector Deployment, as a capacity Workload.

    Read out of the RENDER rather than out of values.yaml on purpose: values are
    an input to the question and the rendered object is the answer, and a
    template change can move one without the other.
    """

    workloads = []
    for document in rendered.split("\n---\n"):
        if "kind: Deployment" not in document:
            continue
        name = re.search(r"(?m)^  name: (\S+)$", document)
        replicas = re.search(r"(?m)^  replicas: (\d+)$", document)
        surge = re.search(r"(?m)^      maxSurge: (\d+)$", document)
        # Anchored to the LIMITS block specifically: `requests` carries keys of
        # the same names, and a capacity check that silently measured requests
        # would understate every workload it looked at.
        limits = re.search(
            r"(?m)^            limits:\n"
            r"              cpu: (\S+)\n"
            r"              memory: (\S+)$",
            document,
        )
        missing = [
            label
            for label, matched in (
                ("name", name), ("replicas", replicas), ("maxSurge", surge),
                ("limits.cpu/limits.memory", limits),
            )
            if matched is None
        ]
        if missing:
            raise CapacityError(
                "rendered Deployment does not state {}; capacity is not "
                "knowable".format(", ".join(missing))
            )
        workloads.append(
            Workload(
                name=name.group(1),
                replicas=int(replicas.group(1)),
                surge=int(surge.group(1)),
                cpu_limit=limits.group(1),
                memory_limit=limits.group(2),
            )
        )
    if not workloads:
        raise CapacityError("the chart rendered no Deployment at all")
    return workloads


class QuantityParsing(unittest.TestCase):
    """Comparing "1" against "1000m" as strings is the quiet wrongness."""

    def test_cpu_units(self):
        self.assertEqual(parse_cpu("1"), 1000)
        self.assertEqual(parse_cpu("500m"), 500)
        self.assertEqual(parse_cpu("2"), 2000)

    def test_memory_units(self):
        self.assertEqual(parse_memory("1Gi"), 1024 ** 3)
        self.assertEqual(parse_memory("256Mi"), 256 * 1024 ** 2)
        self.assertEqual(parse_memory("512Mi"), 512 * 1024 ** 2)

    def test_unparseable_quantities_refuse_rather_than_default(self):
        for bad in ("", "lots", "1.5m", "1Gib", None, 1):
            with self.subTest(value=bad):
                with self.assertRaises(CapacityError):
                    parse_cpu(bad)
        for bad in ("", "lots", "1Gib", None, 1):
            with self.subTest(value=bad):
                with self.assertRaises(CapacityError):
                    parse_memory(bad)


class CapacityRuleIsNotAnEqualityCheck(unittest.TestCase):
    """The four cases the ruling requires, and the fail-closed edges."""

    CONNECTOR_QUOTA = Quota(
        "cloudflare-public",
        {"pods": "6", "limits.cpu": "2", "limits.memory": "1Gi"},
    )

    def connectors(self, replicas, surge):
        return [
            Workload(site, replicas, surge, "500m", "256Mi")
            for site in ("naranjo-online-tunnel", "lidersea-com-tunnel")
        ]

    def test_two_replicas_with_surge_one_is_refused(self):
        """The exact production trap, as the regression test for the reshape.

        Steady state is 2 CPU of 2 and 512Mi of 1Gi — it FITS. The rollout is
        what does not: one more Pod at 500m/256Mi takes CPU past the budget.
        """

        with self.assertRaises(CapacityError) as raised:
            check_namespace_fits(self.CONNECTOR_QUOTA, self.connectors(2, 1))
        self.assertIn("rolling", str(raised.exception))

    def test_one_replica_with_surge_one_is_allowed(self):
        check_namespace_fits(self.CONNECTOR_QUOTA, self.connectors(1, 1))

    def test_one_replica_with_no_surge_is_allowed(self):
        check_namespace_fits(self.CONNECTOR_QUOTA, self.connectors(1, 0))

    def test_three_replicas_are_allowed_where_the_quota_affords_them(self):
        """The proof this is not an equality check wearing a new name.

        A single workload, three replicas, in a namespace budgeted for them.
        Nothing here is special-cased to the connectors; the rule simply has
        no opinion about the NUMBER.
        """

        roomy = Quota(
            "some-future-namespace",
            {"pods": "8", "limits.cpu": "4", "limits.memory": "2Gi"},
        )
        check_namespace_fits(
            roomy, [Workload("api", 3, 1, "500m", "256Mi")]
        )

    def test_a_database_with_different_limits_is_allowed(self):
        """Different shape, same rule: two big Pods inside a big enough quota."""

        roomy = Quota(
            "data",
            {"pods": "4", "limits.cpu": "4", "limits.memory": "8Gi"},
        )
        check_namespace_fits(roomy, [Workload("postgres", 2, 0, "1500m", "3Gi")])

    def test_a_workload_whose_surge_does_not_fit_is_refused(self):
        """The subtle half: steady state fits EXACTLY, the rollout cannot.

        Distinct from the connector case because it is a single workload and
        the binding dimension is Pods rather than CPU — the same defect has to
        be caught whichever resource runs out first.
        """

        exact = Quota(
            "tight", {"pods": "2", "limits.cpu": "8", "limits.memory": "8Gi"}
        )
        check_namespace_fits(exact, [Workload("api", 2, 0, "500m", "256Mi")])
        with self.assertRaises(CapacityError) as raised:
            check_namespace_fits(exact, [Workload("api", 2, 1, "500m", "256Mi")])
        self.assertIn("rolling", str(raised.exception))

    def test_steady_state_overflow_is_refused_before_any_rollout(self):
        with self.assertRaises(CapacityError) as raised:
            check_namespace_fits(self.CONNECTOR_QUOTA, self.connectors(3, 0))
        self.assertIn("steady state", str(raised.exception))

    def test_an_unbounded_namespace_fails_closed(self):
        """A quota that does not bound a dimension is not a permissive quota."""

        for hard in (
            {"limits.cpu": "2", "limits.memory": "1Gi"},
            {"pods": "6", "limits.memory": "1Gi"},
            {"pods": "6", "limits.cpu": "2"},
            {"pods": "0", "limits.cpu": "2", "limits.memory": "not-a-quantity"},
        ):
            with self.subTest(hard=sorted(hard)):
                with self.assertRaises(CapacityError):
                    Quota("unbounded", hard)

    def test_a_namespace_with_no_committed_quota_fails_closed(self):
        with self.assertRaises(CapacityError):
            committed_quota("no-such-namespace")

    def test_degenerate_workloads_refuse_rather_than_default(self):
        for replicas, surge in ((0, 0), (-1, 0), (1, -1), ("2", 0), (True, 0)):
            with self.subTest(replicas=replicas, surge=surge):
                with self.assertRaises(CapacityError):
                    Workload("probe", replicas, surge, "500m", "256Mi")

    def test_a_claim_over_no_workloads_is_refused(self):
        with self.assertRaises(CapacityError):
            check_namespace_fits(self.CONNECTOR_QUOTA, [])


class TheCommittedConnectorReleaseFits(unittest.TestCase):
    """The production configuration, rendered, against the committed quota."""

    def test_the_committed_quota_is_the_one_the_cluster_runs(self):
        """Reconciled to a read-only capture on 2026-08-12.

        If the committed quota drifts from the cluster's, this check is
        measuring a budget nobody enforces.
        """

        self.assertEqual(
            committed_quota(CONNECTOR_NAMESPACE),
            {
                "limits.cpu": "2",
                "limits.memory": "1Gi",
                "pods": "6",
                "requests.cpu": "500m",
                "requests.memory": "512Mi",
                "secrets": "8",
            },
        )

    @unittest.skipUnless(HELM, "helm is required")
    def test_the_rendered_connectors_fit_their_namespace(self):
        quota = Quota(CONNECTOR_NAMESPACE, committed_quota(CONNECTOR_NAMESPACE))
        check_namespace_fits(quota, rendered_connector_workloads(render()))

    @unittest.skipUnless(HELM, "helm is required")
    def test_the_render_states_exactly_one_replica_per_connector_today(self):
        """Pins the VALUE without pinning it as a rule.

        The number is a fact about this cluster, so it is asserted; the rule is
        the capacity check above, which is what would permit a different number
        the day a namespace affords one.
        """

        workloads = rendered_connector_workloads(render())
        self.assertEqual([workload.replicas for workload in workloads], [1, 1])
        self.assertEqual([workload.surge for workload in workloads], [0, 0])

    @unittest.skipUnless(HELM, "helm is required")
    def test_raising_the_replica_count_is_governed_by_capacity_not_by_a_constant(self):
        """The schema permits it now; capacity is what has an opinion.

        The schema used to pin ``replicaCount`` to the constant 2, which both
        forbade the correct value and would have forbidden any future workload
        needing a different one. It is now ``minimum: 1``, so this override
        RENDERS — and what governs it is the budget.

        Stated exactly, because the honest answer is more interesting than
        "it fails": with the surge-free strategy this change also reconciles,
        two replicas per connector FIT — and fit EXACTLY, consuming the whole
        namespace CPU and memory budget with nothing left. It is the pairing
        with the former ``maxSurge: 1``, which is what merged ``main`` carries,
        that the rule refuses. So the trap was never the replica count alone.
        """

        workloads = rendered_connector_workloads(render("replicaCount=2"))
        self.assertEqual([workload.replicas for workload in workloads], [2, 2])
        quota = Quota(CONNECTOR_NAMESPACE, committed_quota(CONNECTOR_NAMESPACE))

        # Fits — and leaves nothing: exactly the quota, in both dimensions.
        check_namespace_fits(quota, workloads)
        self.assertEqual(
            sum(workload.replicas * workload.cpu for workload in workloads),
            quota.cpu,
        )
        self.assertEqual(
            sum(workload.replicas * workload.memory for workload in workloads),
            quota.memory,
        )

        # THE MERGED-MAIN CONFIGURATION, and the regression this all exists
        # for: the same two replicas with the surge strategy this change
        # replaces. The rollout needs a Pod the budget cannot pay for.
        surging = [
            Workload(workload.name, workload.replicas, 1, "500m", "256Mi")
            for workload in workloads
        ]
        with self.assertRaises(CapacityError) as raised:
            check_namespace_fits(quota, surging)
        self.assertIn("rolling", str(raised.exception))

    @unittest.skipUnless(HELM, "helm is required")
    def test_a_zero_replica_count_is_still_refused_by_the_schema(self):
        """Relaxing the constant must not have opened the floor."""

        with self.assertRaises(AssertionError):
            render("replicaCount=0")


if __name__ == "__main__":
    unittest.main()
