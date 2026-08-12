"""Structural contract for the storage-exposure admission gate.

The behavioural fixtures under ``tests/kubernetes/`` prove what the gate does
to storage objects it evaluates. They cannot prove that it evaluates them at
all, and that is the failure mode that matters here.

``kyverno test`` reports a resource that falls outside a rule's ``match`` block
as ``Pass`` with reason ``Excluded``. Removing ``PersistentVolume`` from the
storage rule's matched kinds therefore leaves the entire Kyverno suite green
while an ``nfs`` PersistentVolume — the exact object the policy exists to
refuse — sails through. A deny-external-reachability policy that has silently
stopped reaching its objects is indistinguishable, in the behavioural suite,
from one that works.

So this battery checks the gate's SHAPE rather than its answers:

* the kinds the Kyverno rule matches are exactly the kinds its CEL expressions
  reason about — derived from the expressions, never restated, so narrowing
  either half fails here;
* the Conftest mirror keys a deny rule on every one of those kinds, so the two
  engines cover the same surface rather than merely agreeing on the objects
  they happen to share;
* the enumerations themselves — classes, provisioners, CSI drivers, local
  roots, admitted volume sources, and the PersistentVolume non-source field
  list — are byte-identical between the two engines;
* the enumerations cannot be widened into the very exposure the policy denies
  (a cloud CSI driver, a local root on the control-plane filesystem, a network
  volume source smuggled into the "not a source" list);
* every enumerated kind has at least one deny fixture, so no kind is covered in
  policy and unproven in fact.

Everything is parsed from the committed text with the standard library only:
this repository keeps Python dependency-free, and reading the raw text is also
what makes the derivation honest — the test cannot accidentally agree with the
policy by importing the same constant twice.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
KYVERNO_POLICY = REPO_ROOT / "policies" / "kyverno" / "disallow-undiscovered-storage.yaml"
CONFTEST_POLICY = REPO_ROOT / "policies" / "conftest" / "kubernetes.rego"
FIXTURES = REPO_ROOT / "tests" / "kubernetes" / "fixtures"
STORAGE_RULE = "disallow-persistent-storage-resources"

# The Kyverno policy is a fixed-arity object by contract: the staged install
# transaction patches ``/spec/rules/<index>/validate/failureAction`` one index at
# a time, deliberately not by wildcard, so a rule added or removed here silently
# ships an ENFORCING rule during the fail-open audit stage. Changing this number
# is legitimate only together with that patch.
EXPECTED_RULE_COUNT = 7

# Upstream PersistentVolume volume sources that place bytes somewhere other than
# this node's own filesystem. The policy never enumerates these — it derives
# sources by subtracting the known non-source fields, so unknown sources are
# denied automatically — but that derivation is only sound while none of these
# names is sitting in the non-source list. This is the ratchet that keeps a
# one-word edit from turning ``nfs`` into "not a volume source".
NETWORK_AND_CLOUD_VOLUME_SOURCES = frozenset(
    {
        "awsElasticBlockStore",
        "azureDisk",
        "azureFile",
        "cephfs",
        "cinder",
        "fc",
        "flexVolume",
        "flocker",
        "gcePersistentDisk",
        "glusterfs",
        "hostPath",
        "iscsi",
        "nfs",
        "photonPersistentDisk",
        "portworxVolume",
        "quobyte",
        "rbd",
        "scaleIO",
        "storageos",
        "vsphereVolume",
    }
)

# A driver whose name resolves to a managed cloud service can never be a "local
# provisioner", whatever a future reviewed diff calls it.
CLOUD_CSI_DRIVER_MARKERS = (
    "aws",
    "azure",
    "gke",
    "gcp",
    "digitalocean",
    "linode",
    "hetzner",
    "vsphere",
    "openstack",
    "cinder",
    "nfs",
    "smb",
    "ceph",
    "rook",
)

# Roots that belong to the OS, the container runtime, or the control plane. A
# local PersistentVolume anchored in any of them hands node or cluster state to
# whatever binds the claim, which is the same exposure by a shorter path.
FORBIDDEN_LOCAL_ROOT_PREFIXES = (
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/usr",
    "/var",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def require(match: re.Match[str] | None, expectation: str) -> re.Match[str]:
    """Return ``match``, or fail loudly naming what was expected.

    Every derivation below reads a group out of a regular-expression match. A
    ``None`` match means the assertion that follows had nothing to assert on —
    the vacuity failure mode this battery exists to prevent — so it is raised
    here rather than surfacing as an attribute error on ``None`` (or, worse,
    being papered over with a default that quietly makes the check pass).
    ``raise`` rather than ``assert`` so the guard survives ``python -O``.
    """

    if match is None:
        raise AssertionError("the policy no longer states " + expectation)
    return match


def storage_rule_text(policy: str) -> str:
    """Return the text of the storage rule alone.

    Slicing at the next sibling ``- name:`` keeps every derivation below scoped
    to this one rule: the same policy also carries the tenant-volume, token, and
    toleration rules, whose kinds and fields must not leak into the storage
    coverage set.
    """

    start = policy.index("    - name: " + STORAGE_RULE)
    remainder = policy[start + 1 :]
    match = re.search(r"(?m)^    - name: ", remainder)
    end = len(policy) if match is None else start + 1 + match.start()
    return policy[start:end]


def cel_list_variable(rule: str, name: str) -> list[str]:
    """Extract one CEL ``variables`` entry as a list of string literals."""

    pattern = re.compile(
        r"(?ms)^            - name: " + re.escape(name) + r"\n              expression: (.*?)(?=^            - name: |^          expressions:)"
    )
    match = require(pattern.search(rule), "CEL variable " + name)
    return re.findall(r"'([^']*)'", match.group(1))


def rego_set_literal(policy: str, name: str) -> list[str]:
    """Extract a Rego set constant as a list of string literals.

    ``:= set()`` is the empty set; Rego has no ``{}`` set literal, so the empty
    case has its own spelling and must be recognized rather than mis-parsed as a
    missing constant.
    """

    empty = re.search(r"(?m)^" + re.escape(name) + r" := set\(\)\s*$", policy)
    if empty is not None:
        return []
    match = require(
        re.search(r"(?ms)^" + re.escape(name) + r" := \{(.*?)\}\s*$", policy),
        "Conftest mirror constant " + name,
    )
    return re.findall(r'"([^"]*)"', match.group(1))


class StorageRuleCoverage(unittest.TestCase):
    """The gate must reach every storage object it claims to govern."""

    def setUp(self) -> None:
        self.policy = read(KYVERNO_POLICY)
        self.rule = storage_rule_text(self.policy)
        self.rego = read(CONFTEST_POLICY)

    def matched_kinds(self) -> list[str]:
        block = require(
            re.search(r"(?ms)^      match:\n(.*?)^      validate:", self.rule),
            "a match block on the storage rule",
        )
        return re.findall(r"(?m)^                - (\S+)$", block.group(1))

    def reasoned_kinds(self) -> set[str]:
        expressions = self.rule[self.rule.index("          expressions:") :]
        return set(re.findall(r"object\.kind (?:!=|==) '([A-Za-z]+)'", expressions))

    def test_match_block_covers_exactly_the_kinds_the_expressions_reason_about(self) -> None:
        """Narrowing either half — the match list or the expressions — fails here.

        This is the check the behavioural suite cannot make. With
        ``PersistentVolume`` deleted from the match list, ``kyverno test``
        reports every PersistentVolume fixture as ``Pass / Excluded`` and the
        suite stays entirely green; the set comparison below goes red.
        """

        matched = self.matched_kinds()
        self.assertEqual(
            sorted(matched),
            sorted(set(matched)),
            "the storage rule lists a matched kind twice",
        )
        self.assertEqual(
            set(matched),
            self.reasoned_kinds(),
            "the kinds the storage rule MATCHES and the kinds its CEL expressions "
            "REASON ABOUT have diverged; one of them no longer covers what the other does",
        )

    def test_matched_kinds_are_the_storage_surface_and_nothing_else(self) -> None:
        """A vacuity guard on the comparison above.

        Both halves could be narrowed together and the equality would still
        hold, so the storage surface itself is pinned once, here, where a
        reviewer reads it.
        """

        self.assertEqual(
            set(self.matched_kinds()),
            {
                "PersistentVolume",
                "PersistentVolumeClaim",
                "StorageClass",
                "CSIDriver",
                "VolumeAttributesClass",
            },
        )

    def test_storage_rule_carves_out_no_exemption_from_its_own_coverage(self) -> None:
        """The other half of the coverage question the kind list cannot answer.

        Matching the right kinds still covers nothing if the rule then narrows
        by namespace, by object name, by label selector, or by an ``exclude``
        block — and Kyverno reports every carved-out object as ``Pass /
        Excluded`` exactly as it does for an unmatched kind. Storage classes,
        volumes, drivers, and attribute classes are cluster-scoped or
        cluster-relevant, so the rule must reach every namespace and every name.
        Whatever a future exemption is for, it stops being invisible here.
        """

        for narrowing in (
            "exclude:",
            "namespaces:",
            "namespaceSelector:",
            "names:",
            "selector:",
            "annotations:",
            "operations:",
            "preconditions:",
        ):
            with self.subTest(narrowing=narrowing):
                self.assertNotIn(
                    narrowing,
                    self.rule,
                    "the storage rule narrows its own coverage with " + narrowing,
                )

    def test_conftest_mirror_denies_on_every_matched_kind(self) -> None:
        """Lockstep: the CI mirror must see the same surface as admission.

        Kind-for-kind, not fixture-for-fixture — a kind that admission matches
        but Conftest never keys a deny rule on would pass CI and only ever be
        caught by a live webhook that is not installed yet.
        """

        deny_blocks = re.findall(r"(?s)deny contains msg if \{(.*?)\n\}", self.rego)
        for kind in self.matched_kinds():
            covering = [block for block in deny_blocks if '"' + kind + '"' in block]
            self.assertTrue(
                covering,
                "the Conftest mirror has no deny rule keyed on " + kind,
            )

    def test_conftest_storage_kind_constant_matches_the_admission_match_block(self) -> None:
        self.assertEqual(
            sorted(rego_set_literal(self.rego, "storage_kinds")),
            sorted(self.matched_kinds()),
        )

    def test_rule_arity_stays_bound_to_the_staged_install_patch(self) -> None:
        rules = re.findall(r"(?m)^    - name: (\S+)$", self.policy)
        self.assertEqual(len(rules), EXPECTED_RULE_COUNT)
        self.assertIn(STORAGE_RULE, rules)

    def test_policy_stays_fail_closed_at_the_webhook(self) -> None:
        self.assertIn("\n  validationFailureAction: Enforce\n", self.policy)
        self.assertIn("\n    failurePolicy: Fail\n", self.policy)
        self.assertIn("\n        failureAction: Enforce\n", self.rule)


class EnumerationLockstep(unittest.TestCase):
    """The enumeration is the allowlist, and there is only one of it."""

    def setUp(self) -> None:
        self.rule = storage_rule_text(read(KYVERNO_POLICY))
        self.rego = read(CONFTEST_POLICY)

    def test_enumerations_are_identical_in_both_engines(self) -> None:
        pairs = (
            ("enumeratedStorageClasses", "enumerated_storage_classes"),
            ("enumeratedProvisioners", "enumerated_storage_provisioners"),
            ("enumeratedCsiDrivers", "enumerated_csi_drivers"),
            ("enumeratedLocalRoots", "enumerated_local_volume_roots"),
            ("nonSourceFields", "persistent_volume_non_source_fields"),
        )
        for cel_name, rego_name in pairs:
            with self.subTest(enumeration=cel_name):
                self.assertEqual(
                    sorted(cel_list_variable(self.rule, cel_name)),
                    sorted(rego_set_literal(self.rego, rego_name)),
                    "admission and CI disagree about " + cel_name,
                )

    def test_admitted_volume_sources_are_identical_in_both_engines(self) -> None:
        expressions = self.rule[self.rule.index("          expressions:") :]
        admitted = require(
            re.search(r"field in \[([^\]]*)\]", expressions),
            "an admitted volume-source set in its expressions",
        )
        self.assertEqual(
            sorted(re.findall(r"'([^']*)'", admitted.group(1))),
            sorted(rego_set_literal(self.rego, "admitted_persistent_volume_sources")),
        )

    def test_only_node_local_volume_sources_may_be_admitted(self) -> None:
        admitted = set(rego_set_literal(self.rego, "admitted_persistent_volume_sources"))
        self.assertTrue(
            admitted <= {"local", "csi"},
            "a volume source outside the node-local pair was admitted: "
            + ", ".join(sorted(admitted - {"local", "csi"})),
        )

    def test_no_network_source_can_hide_in_the_non_source_field_list(self) -> None:
        """The subtraction that makes unknown sources deny-by-default.

        Sources are whatever is left after the non-source fields are removed. A
        single name added to that list stops being a source and starts being
        ignored, which would admit it silently — the one edit that converts this
        policy from fail-closed to fail-open without touching a deny rule.
        """

        declared = set(rego_set_literal(self.rego, "persistent_volume_non_source_fields"))
        leaked = declared & NETWORK_AND_CLOUD_VOLUME_SOURCES
        self.assertEqual(
            leaked,
            set(),
            "a real volume source is declared as a non-source field: " + ", ".join(sorted(leaked)),
        )

    def test_enumerated_csi_drivers_cannot_name_a_managed_cloud_service(self) -> None:
        for driver in rego_set_literal(self.rego, "enumerated_csi_drivers"):
            for marker in CLOUD_CSI_DRIVER_MARKERS:
                self.assertNotIn(
                    marker,
                    driver.lower(),
                    "a managed/remote driver was enumerated as a local provisioner: " + driver,
                )

    def test_enumerated_local_roots_stay_off_the_control_plane_filesystem(self) -> None:
        roots = rego_set_literal(self.rego, "enumerated_local_volume_roots")
        self.assertTrue(roots, "the local-root enumeration is missing entirely")
        for root in roots:
            with self.subTest(root=root):
                self.assertTrue(root.startswith("/"), "a local root must be absolute: " + root)
                self.assertNotIn("..", root)
                self.assertFalse(root.endswith("/"), "a local root must not carry a trailing slash: " + root)
                # A single-segment root ("/mnt", "/srv") is a mount PARENT: it
                # admits every filesystem anyone ever mounts beneath it, which is
                # an open door dressed as an enumeration.
                self.assertGreaterEqual(
                    len([segment for segment in root.split("/") if segment]),
                    2,
                    "a local root must name a specific directory, not a mount parent: " + root,
                )
                for forbidden in FORBIDDEN_LOCAL_ROOT_PREFIXES:
                    self.assertFalse(
                        root == forbidden or root.startswith(forbidden + "/"),
                        "a local root sits on the OS/control-plane filesystem: " + root,
                    )

    def test_enumerated_provisioners_are_static_and_local(self) -> None:
        provisioners = rego_set_literal(self.rego, "enumerated_storage_provisioners")
        self.assertTrue(provisioners, "the provisioner enumeration is missing entirely")
        for provisioner in provisioners:
            with self.subTest(provisioner=provisioner):
                self.assertEqual(
                    provisioner,
                    "kubernetes.io/no-provisioner",
                    "only static local provisioning is enumerated; a dynamic provisioner "
                    "decides where bytes land without a reviewed diff",
                )


class FixtureCoverage(unittest.TestCase):
    """Every covered kind is proven, and every proof is where the runners look."""

    def setUp(self) -> None:
        self.rule = storage_rule_text(read(KYVERNO_POLICY))
        block = require(
            re.search(r"(?ms)^      match:\n(.*?)^      validate:", self.rule),
            "a match block on the storage rule",
        )
        self.matched = re.findall(r"(?m)^                - (\S+)$", block.group(1))
        self.deny_fixtures = sorted((FIXTURES / "deny").glob("storage-*.yaml"))
        self.allow_fixture = FIXTURES / "allow" / "storage-enumerated-local.yaml"

    def kinds_in(self, paths) -> set[str]:
        found: set[str] = set()
        for path in paths:
            found.update(re.findall(r"(?m)^kind: (\S+)$", read(path)))
        return found

    def test_every_matched_kind_has_at_least_one_deny_fixture(self) -> None:
        proven = self.kinds_in(self.deny_fixtures)
        for kind in self.matched:
            with self.subTest(kind=kind):
                self.assertIn(
                    kind,
                    proven,
                    kind + " is covered by policy but no deny fixture ever exercises it",
                )

    def test_the_allow_fixture_carries_the_whole_admissible_shape(self) -> None:
        self.assertEqual(
            self.kinds_in([self.allow_fixture]),
            {"StorageClass", "PersistentVolume", "PersistentVolumeClaim"},
        )

    def test_each_deny_fixture_holds_exactly_one_object(self) -> None:
        """One object per file, so no denial can hide behind another.

        The Conftest deny runner only asserts that a fixture FAILS. Two objects
        in one file would let a single rule's denial stand in for both.
        """

        for path in self.deny_fixtures:
            with self.subTest(fixture=path.name):
                self.assertEqual(len(re.findall(r"(?m)^kind: \S+$", read(path))), 1)
                self.assertNotIn("\n---\n", read(path))

    def test_deny_fixtures_live_where_both_runners_scan(self) -> None:
        """``scripts/test-policy-fixtures.sh`` globs this directory, and the
        trivy misconfiguration pass excludes exactly this directory, so a
        fixture placed anywhere else is neither proven nor exempted."""

        self.assertTrue(self.deny_fixtures, "the storage deny fixtures have disappeared")
        for path in self.deny_fixtures:
            self.assertEqual(path.parent, FIXTURES / "deny")


if __name__ == "__main__":
    unittest.main()
