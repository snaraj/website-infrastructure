"""Does a release fit in its namespace — at rest AND mid-rollout?

The invariant this expresses, per the owner's ruling of 2026-08-12, is a
CAPACITY assertion and never an equality assertion. "Replicas must be 1" is the
wrong shape of rule: it would refuse a future application with different
availability requirements, or a stateful workload such as a database, for a
reason that has nothing to do with why the current number is right. What is
actually true is narrower and generalises:

    a release's declared replicas, PLUS the headroom its rolling update needs,
    multiplied by its per-Pod limits, must fit inside its namespace's
    ResourceQuota — together with everything else in that namespace.

That permits three replicas where the quota affords them, permits a database
with quite different limits, and still refuses the exact trap this module was
written for: two connector replicas with ``maxSurge: 1`` against a six-Pod,
two-CPU, one-gibibyte namespace budget.

THE SURGE HALF IS THE SUBTLE ONE, and it is the half the cluster actually
exhibited. A workload whose steady state fits exactly has no room left to roll:
the update needs a Pod the quota refuses, the rollout blocks, and the workload
becomes un-updatable without an outage — a failure that appears only on the
next deploy, long after the change that caused it. Steady state is not enough.

FAIL CLOSED, ALWAYS. An unknown quota, an unparseable quantity, a missing
limit, a negative or zero replica count: every one of them raises rather than
skipping. A capacity check that stands down when it cannot measure something is
a capacity check that reports success on the workloads it understands least.

Quantities are parsed to integers in their base unit — millicores for CPU,
bytes for memory — because comparing "1" against "1000m" as strings is exactly
the kind of quiet wrongness this file exists to prevent. Standard library only:
this repository stays dependency-free.
"""

from __future__ import annotations

import re


class CapacityError(Exception):
    """A capacity claim could not be evaluated, or does not hold.

    One exception type for "does not fit" and for "cannot tell", deliberately.
    Both must stop the build, and separating them invites a caller to catch the
    second and carry on.
    """


_CPU = re.compile(r"^(\d+(?:\.\d+)?)(m?)$")
_MEMORY = re.compile(r"^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|K|M|G|T|k)?$")
_MEMORY_SCALE = {
    None: 1,
    "": 1,
    "k": 1000,
    "K": 1000,
    "M": 1000 ** 2,
    "G": 1000 ** 3,
    "T": 1000 ** 4,
    "Ki": 1024,
    "Mi": 1024 ** 2,
    "Gi": 1024 ** 3,
    "Ti": 1024 ** 4,
}


def parse_cpu(value) -> int:
    """Millicores. ``"1"`` is 1000m and ``"500m"`` is 500m."""

    if not isinstance(value, str):
        raise CapacityError("CPU quantity is not a string: {!r}".format(value))
    matched = _CPU.match(value.strip())
    if matched is None:
        raise CapacityError("unparseable CPU quantity: {!r}".format(value))
    amount, suffix = matched.groups()
    if suffix == "m":
        millicores = float(amount)
    else:
        millicores = float(amount) * 1000
    if millicores != int(millicores):
        raise CapacityError("sub-millicore CPU quantity: {!r}".format(value))
    return int(millicores)


def parse_memory(value) -> int:
    """Bytes. Binary and decimal suffixes both, as Kubernetes accepts them."""

    if not isinstance(value, str):
        raise CapacityError("memory quantity is not a string: {!r}".format(value))
    matched = _MEMORY.match(value.strip())
    if matched is None:
        raise CapacityError("unparseable memory quantity: {!r}".format(value))
    amount, suffix = matched.groups()
    scaled = float(amount) * _MEMORY_SCALE[suffix]
    if scaled != int(scaled):
        raise CapacityError("fractional byte quantity: {!r}".format(value))
    return int(scaled)


class Workload:
    """One controller's demand on a namespace.

    ``surge`` is the EXTRA Pods a rolling update may create beyond ``replicas``
    — ``maxSurge`` resolved to an absolute number. ``0`` is the honest value for
    a surge-free strategy and is not a default: a caller that cannot determine
    the strategy must say so rather than pass zero.
    """

    def __init__(self, name, replicas, surge, cpu_limit, memory_limit, containers=1):
        if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas < 1:
            raise CapacityError(
                "{}: replicas must be a positive integer, got {!r}".format(
                    name, replicas
                )
            )
        if not isinstance(surge, int) or isinstance(surge, bool) or surge < 0:
            raise CapacityError(
                "{}: surge must be a non-negative integer, got {!r}".format(
                    name, surge
                )
            )
        if not isinstance(containers, int) or containers < 1:
            raise CapacityError("{}: containers must be positive".format(name))
        self.name = name
        self.replicas = replicas
        self.surge = surge
        self.containers = containers
        self.cpu = parse_cpu(cpu_limit) * containers
        self.memory = parse_memory(memory_limit) * containers

    @property
    def peak_pods(self) -> int:
        return self.replicas + self.surge


class Quota:
    """The namespace budget, read from a committed ResourceQuota's ``hard``."""

    REQUIRED = ("pods", "limits.cpu", "limits.memory")

    def __init__(self, namespace, hard):
        if not isinstance(hard, dict):
            raise CapacityError(
                "{}: ResourceQuota hard block is not a mapping".format(namespace)
            )
        missing = [key for key in self.REQUIRED if key not in hard]
        if missing:
            raise CapacityError(
                "{}: ResourceQuota does not bound {}; capacity is not "
                "knowable".format(namespace, ", ".join(sorted(missing)))
            )
        self.namespace = namespace
        pods = hard["pods"]
        if not isinstance(pods, str) or not pods.isdigit():
            raise CapacityError(
                "{}: unparseable pod quota {!r}".format(namespace, pods)
            )
        self.pods = int(pods)
        self.cpu = parse_cpu(hard["limits.cpu"])
        self.memory = parse_memory(hard["limits.memory"])


def check_namespace_fits(quota: Quota, workloads) -> None:
    """Raise unless every workload fits, at rest and mid-rollout.

    Two passes, because they fail for different reasons and a caller reading
    only the first would draw the wrong conclusion:

    1. STEADY STATE — the sum of all replicas must fit. A namespace that is
       already over budget cannot be fixed by scheduling.
    2. PEAK — one workload rolling at a time, since a rollout of everything at
       once is not something any controller does and demanding headroom for it
       would refuse configurations that work. The peak is therefore the steady
       state plus the LARGEST single surge, and it must still fit.
    """

    workloads = list(workloads)
    if not workloads:
        raise CapacityError(
            "{}: no workloads supplied; a capacity claim over nothing is not a "
            "claim".format(quota.namespace)
        )

    steady_pods = sum(workload.replicas for workload in workloads)
    steady_cpu = sum(workload.replicas * workload.cpu for workload in workloads)
    steady_memory = sum(
        workload.replicas * workload.memory for workload in workloads
    )
    for measured, budget, unit in (
        (steady_pods, quota.pods, "pods"),
        (steady_cpu, quota.cpu, "limits.cpu (millicores)"),
        (steady_memory, quota.memory, "limits.memory (bytes)"),
    ):
        if measured > budget:
            raise CapacityError(
                "{}: steady state needs {} {} but the quota allows {}".format(
                    quota.namespace, measured, unit, budget
                )
            )

    for rolling in workloads:
        if rolling.surge == 0:
            continue
        peak_pods = steady_pods + rolling.surge
        peak_cpu = steady_cpu + rolling.surge * rolling.cpu
        peak_memory = steady_memory + rolling.surge * rolling.memory
        for measured, budget, unit in (
            (peak_pods, quota.pods, "pods"),
            (peak_cpu, quota.cpu, "limits.cpu (millicores)"),
            (peak_memory, quota.memory, "limits.memory (bytes)"),
        ):
            if measured > budget:
                raise CapacityError(
                    "{}: rolling {} needs {} {} at peak but the quota allows "
                    "{}; the steady state fits and the ROLLOUT does not, so "
                    "this only fails on the next deploy".format(
                        quota.namespace, rolling.name, measured, unit, budget
                    )
                )
