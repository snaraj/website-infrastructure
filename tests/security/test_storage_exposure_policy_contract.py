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

# The complete storage rule set, stated ONCE here in the test rather than read
# out of either policy. Every other check below compares the two engines against
# each other, and two files can be narrowed together; this literal is the outside
# anchor that makes such a matching narrowing fail. It is also the reason nothing
# in this battery ever SKIPs: a guard that stands down when its expectation stops
# matching is a guard that disables itself.
EXPECTED_RULE_IDS = frozenset("SR-{}".format(index) for index in range(17))

# The complete non-source field list, stated here as a LITERAL for the same
# reason ``EXPECTED_RULE_IDS`` is. Comparing the two engines against each other
# proves they agree; it does not prove they are right, and a name added to this
# list in BOTH engines is the one edit that converts the subtraction from
# fail-closed to fail-open without touching a deny rule. The blocklist-shaped
# guard below (``NETWORK_AND_CLOUD_VOLUME_SOURCES``) only catches names upstream
# has already invented — it is exactly the "blocklist to maintain" this design
# claims to have eliminated, and it cannot catch whatever upstream invents next.
# This literal catches ANY addition, whatever it is called.
EXPECTED_NON_SOURCE_FIELDS = frozenset(
    {
        "accessModes",
        "capacity",
        "claimRef",
        "mountOptions",
        "nodeAffinity",
        "persistentVolumeReclaimPolicy",
        "storageClassName",
        "volumeAttributesClassName",
        "volumeMode",
    }
)

# The pod-level gate uses the same subtraction model, so it gets the same outside
# anchor. Only sources whose bytes come from the cluster's own API server or the
# node's ephemeral storage may be admitted; anything added here is a new means of
# reaching bytes from a workload.
EXPECTED_ADMITTED_POD_VOLUME_SOURCES = frozenset(
    {"emptyDir", "configMap", "secret", "projected", "downwardAPI"}
)

# The differential harness's corpus floor, held outside the harness so that
# neither the corpus nor the floor inside the script can be trimmed quietly. A
# harness that compares nothing is the next vacuity after a battery that compares
# only constants.
MINIMUM_PARITY_DENY_FIXTURES = 30

# Degenerate shapes that MUST stay in the corpus. Every one of these was an
# engine divergence measured on this policy (wi #96 adversarial review): the
# Conftest mirror admitted them while Kyverno denied them, because a nested
# ``object.get`` on a null/scalar/list value raises a builtin type error and an
# erroring expression is UNDEFINED — the deny rule silently does not fire. The
# name on the left is the fixture stem; losing any of them silently retires a
# proven regression.
REQUIRED_DEGENERATE_FIXTURES = (
    "storage-local-source-null",
    "storage-local-source-scalar",
    "storage-local-source-list",
    "storage-csi-source-null",
    "storage-csi-source-scalar",
    "storage-claim-null-data-source",
    "storage-class-null-parameters",
    "storage-node-affinity-null",
    "storage-node-affinity-list",
    "storage-node-affinity-required-scalar",
    "storage-local-unbounded-node-affinity",
    "storage-persistent-volume-attributes-class-reference",
    "storage-claim-attributes-class-reference",
    "storage-persistent-volume-mount-options",
    "storage-null-spec-persistent-volume",
    "storage-null-spec-claim",
)

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

        ``subjects``/``roles``/``clusterRoles`` are the userInfo half of
        Kyverno's ``MatchResources`` and belong on this list for a sharper
        reason: adding ``clusterRoles: [no-such-cluster-role]`` makes the rule
        match only principals bound to a role nobody holds — i.e. nobody — and
        the behavioural suite stays 74/74 green because ``kyverno test`` counts
        the resulting ``Skip`` rows as PASSES, not only ``Pass``/``Excluded``.
        Measured on this exact rule (wi #96 adversarial review, 2026-08-12).
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
            "subjects:",
            "roles:",
            "clusterRoles:",
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
        """Enforcement mode, failure policy, and the admission switch itself.

        ``spec.admission: false`` is ONE WORD that stops every rule in this
        policy running at admission — the policy degrades to background scanning
        and refuses nothing — while the structural battery stayed 22/22 and
        ``kyverno test`` stayed 74/74 green. Measured on this policy (wi #96
        adversarial review, 2026-08-12). No behavioural suite can see it, so it
        is pinned here beside the other two fail-closed switches.
        """

        self.assertIn("\n  admission: true\n", self.policy)
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
            ("enumeratedVolumeAttributesClasses", "enumerated_volume_attributes_classes"),
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

    def test_the_non_source_field_list_is_exactly_the_reviewed_nine(self) -> None:
        """The subtraction that makes unknown sources deny-by-default.

        Sources are whatever is left after the non-source fields are removed. A
        single name added to that list stops being a source and starts being
        ignored, which would admit it silently — the one edit that converts this
        policy from fail-closed to fail-open without touching a deny rule.

        The SR-1 arity rule is only a partial backstop for that edit: it holds
        when the poisoned field is the object's ONLY source, and not when a
        legitimate `local:` source sits beside it. Measured: with `quantumMesh`
        added to the list in both engines, a PersistentVolume carrying a valid
        local source under the enumerated root PLUS `quantumMesh: {endpoint:
        storage.invalid:9999}` went from denied in both engines to admitted in
        both, with every other committed check green (wi #96 adversarial
        review, 2026-08-12). So the list is pinned exactly, name for name,
        rather than merely screened against today's known network sources.
        """

        declared = set(rego_set_literal(self.rego, "persistent_volume_non_source_fields"))
        self.assertEqual(
            declared,
            set(EXPECTED_NON_SOURCE_FIELDS),
            "the PersistentVolume non-source field list changed; every addition makes "
            "that field invisible to the source derivation, whatever it is named",
        )

    def test_no_network_source_can_hide_in_the_non_source_field_list(self) -> None:
        """Named-source screen, kept beside the exact pin above.

        This is the weaker of the two guards — a blocklist of the sources
        upstream has already invented — but it names the exposure explicitly in
        the failure message, which the set comparison above cannot do.
        """

        declared = set(rego_set_literal(self.rego, "persistent_volume_non_source_fields"))
        leaked = declared & NETWORK_AND_CLOUD_VOLUME_SOURCES
        self.assertEqual(
            leaked,
            set(),
            "a real volume source is declared as a non-source field: " + ", ".join(sorted(leaked)),
        )

    def test_pod_volume_sources_are_derived_by_the_same_subtraction(self) -> None:
        """The pod-level gate uses the model, not a blocklist.

        It used to be a ten-name blocklist of the network sources upstream had
        invented, so an otherwise fully compliant Pod outside the tenant
        namespaces could mount `azureFile` or `awsElasticBlockStore` and be
        admitted by CI (measured, wi #96 adversarial review). Both halves are
        pinned: the non-source field set that makes the derivation a
        subtraction, and the admitted-source set it subtracts against.
        """

        self.assertEqual(
            set(rego_set_literal(self.rego, "pod_volume_non_source_fields")),
            {"name"},
            "a Pod volume field other than `name` was declared a non-source field, "
            "which makes whatever it is invisible to the source derivation",
        )
        admitted = set(rego_set_literal(self.rego, "admitted_pod_volume_sources"))
        self.assertEqual(
            admitted,
            set(EXPECTED_ADMITTED_POD_VOLUME_SOURCES),
            "the admitted Pod volume sources changed; every entry is a means of "
            "reaching bytes from a workload",
        )
        leaked = admitted & NETWORK_AND_CLOUD_VOLUME_SOURCES
        self.assertEqual(
            leaked,
            set(),
            "a network or cloud volume source was admitted at the Pod level: "
            + ", ".join(sorted(leaked)),
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


class RuleIdentityLock(unittest.TestCase):
    """Three-way lock: admission, CI mirror, and the fixtures that kill them.

    A deny fixture that merely proves "this file is rejected" cannot show WHICH
    rule rejected it, so deleting one rule can leave the suite green while
    another rule's denial covers for it. Every fixture here therefore holds one
    object and names the rule it exists to kill, and the three sets — the rules
    admission states, the rules the CI mirror states, and the rules the fixtures
    claim — must be the same set, and that set must be the one named above.
    """

    def setUp(self) -> None:
        self.rule = storage_rule_text(read(KYVERNO_POLICY))
        self.rego = read(CONFTEST_POLICY)
        self.deny_fixtures = sorted((FIXTURES / "deny").glob("storage-*.yaml"))

    @staticmethod
    def ids_in(text: str) -> set[str]:
        return set(re.findall(r"#\s*(SR-\d+)[.,\s]", text))

    def test_admission_states_exactly_the_expected_rule_set(self) -> None:
        self.assertEqual(self.ids_in(self.rule), set(EXPECTED_RULE_IDS))

    def test_the_conftest_mirror_states_exactly_the_same_rule_set(self) -> None:
        storage_section = self.rego[self.rego.index("# SR-0.") :]
        self.assertEqual(self.ids_in(storage_section), set(EXPECTED_RULE_IDS))

    def test_every_rule_is_claimed_by_at_least_one_deny_fixture(self) -> None:
        claimed: dict[str, list[str]] = {}
        for path in self.deny_fixtures:
            match = require(
                re.match(r"# proves: (SR-\d+)\n", read(path)),
                "a `# proves: SR-N` claim on deny fixture " + path.name,
            )
            claimed.setdefault(match.group(1), []).append(path.name)
        self.assertEqual(
            set(claimed),
            set(EXPECTED_RULE_IDS),
            "a rule exists with no fixture that kills it, or a fixture claims a rule "
            "that no longer exists",
        )

    def test_every_deny_fixture_declares_the_message_its_rule_emits(self) -> None:
        """Attribution, not just rejection.

        Both fixture runners assert only that a FILE is rejected, so a rule can
        be neutralized and stay green whenever any OTHER rule also denies the
        same object. Measured: the Rego SR-0 arm was replaced with a condition
        that never matches, message string left byte-identical, and the
        structural battery, the fixture runner, and the Kyverno suite all stayed
        green — its fixture also fails SR-1 and SR-7.

        Each fixture therefore declares the exact message fragment its claimed
        rule emits, and ``scripts/test-storage-engine-parity.sh`` requires that
        fragment in the Conftest output. This test keeps the declarations from
        being dropped, and keeps them from degenerating into fragments so short
        that any denial would satisfy them.
        """

        declared: dict[str, list[str]] = {}
        for path in self.deny_fixtures:
            text = read(path)
            claim = require(
                re.match(r"# proves: (SR-\d+)\n# rego-message: (.+)\n", text),
                "`# proves:` and `# rego-message:` headers on deny fixture " + path.name,
            )
            fragment = claim.group(2).strip()
            with self.subTest(fixture=path.name):
                self.assertGreaterEqual(
                    len(fragment),
                    20,
                    "the declared denial message is too short to attribute anything: " + fragment,
                )
                self.assertNotIn("SR-", fragment, "declare the MESSAGE, not the rule identifier")
            declared.setdefault(claim.group(1), []).append(fragment)
        self.assertEqual(
            set(declared),
            set(EXPECTED_RULE_IDS),
            "a rule has no fixture declaring the message it emits",
        )
        for rule_id, fragments in declared.items():
            with self.subTest(rule=rule_id):
                for fragment in fragments:
                    self.assertIn(
                        fragment,
                        self.rego,
                        "no Conftest rule emits the message fixture "
                        + rule_id
                        + " claims: "
                        + fragment,
                    )

    def test_admission_and_the_mirror_agree_rule_for_rule(self) -> None:
        """The lockstep the two engines must keep even if both were rewritten."""

        storage_section = self.rego[self.rego.index("# SR-0.") :]
        self.assertEqual(self.ids_in(self.rule), self.ids_in(storage_section))


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

    def test_the_allow_fixture_teaches_a_bounded_node_selection(self) -> None:
        """The model answer must satisfy SR-6's PURPOSE, not just its letter.

        This fixture is what a reviewer copies. Its earlier shape —
        ``key: kubernetes.io/hostname, operator: Exists`` — satisfies "declares
        required nodeAffinity" while matching EVERY node that ever joins the
        cluster, which is precisely the unbounded selection SR-6 exists to
        refuse. An allow fixture that teaches the bypass is worse than no
        fixture.
        """

        # Comment lines are excluded deliberately: the fixture's own header
        # explains why `operator: Exists` is wrong, and a substring check that
        # cannot tell the explanation from the manifest would be satisfied by
        # the very shape it exists to forbid.
        text = "\n".join(
            line for line in read(self.allow_fixture).splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn("operator: In", text)
        self.assertNotIn("operator: Exists", text)
        self.assertRegex(text, r"values: \[[^\]]+\]")

    def test_deny_fixtures_live_where_both_runners_scan(self) -> None:
        """``scripts/test-policy-fixtures.sh`` globs this directory, and the
        trivy misconfiguration pass excludes exactly this directory, so a
        fixture placed anywhere else is neither proven nor exempted."""

        self.assertTrue(self.deny_fixtures, "the storage deny fixtures have disappeared")
        for path in self.deny_fixtures:
            self.assertEqual(path.parent, FIXTURES / "deny")


class EngineParityHarnessContract(unittest.TestCase):
    """The differential harness must exist, run, and have something to compare.

    Everything else in this file compares TEXT: enumerations, rule identifiers,
    matched kinds, comment markers. Text agreement proved the two engines said
    the same thing and never proved they DID the same thing — and they did not,
    on nine degenerate shapes. ``scripts/test-storage-engine-parity.sh`` closes
    that by feeding both engines the same corpus and failing on any
    disagreement, so this battery keeps the harness honest: a harness that is not
    wired into the pipeline, or whose corpus has been trimmed, compares nothing
    and reports success either way.
    """

    def setUp(self) -> None:
        self.harness = REPO_ROOT / "scripts" / "test-storage-engine-parity.sh"
        self.pipeline = REPO_ROOT / "scripts" / "render-manifests.sh"
        self.deny_fixtures = sorted((FIXTURES / "deny").glob("storage-*.yaml"))

    def test_the_harness_exists_and_is_executable(self) -> None:
        self.assertTrue(self.harness.is_file(), "the storage engine-parity harness is gone")
        self.assertTrue(self.harness.stat().st_mode & 0o111, "the harness is not executable")

    def test_the_harness_runs_in_the_same_pipeline_as_the_fixture_runner(self) -> None:
        """A gate nobody invokes is a gate that cannot fail.

        ``scripts/render-manifests.sh`` is the path CI takes (Render and
        validate Helm and Kubernetes) and the path ``make check-kubernetes``
        takes, and it is where ``test-policy-fixtures.sh`` already runs.
        """

        pipeline = read(self.pipeline)
        self.assertIn("test-storage-engine-parity.sh", pipeline)
        self.assertIn("test-policy-fixtures.sh", pipeline)

    def test_the_harness_feeds_both_engines_and_pins_the_expected_verdict(self) -> None:
        harness = read(self.harness)
        for required in ("conftest test", "kyverno apply", "'deny'", "'allow'", "skip"):
            with self.subTest(required=required):
                self.assertIn(required, harness)

    def test_the_corpus_cannot_be_trimmed_below_the_floor(self) -> None:
        """The floor lives here as well as in the harness.

        A floor a script holds alone is a floor that script can lower. This is
        the outside anchor for it, and it is also what keeps the degenerate
        corpus from being deleted as "redundant" once the guards are in place.
        """

        self.assertGreaterEqual(
            len(self.deny_fixtures),
            MINIMUM_PARITY_DENY_FIXTURES,
            "the storage deny corpus shrank below the differential harness floor",
        )
        self.assertIn(
            "minimum_deny_objects={}".format(MINIMUM_PARITY_DENY_FIXTURES),
            read(self.harness),
            "the harness's own corpus floor no longer matches the one pinned here",
        )

    def test_every_proven_degenerate_shape_is_still_in_the_corpus(self) -> None:
        """Each of these was a measured engine divergence; none may be retired."""

        present = {path.stem for path in self.deny_fixtures}
        for stem in REQUIRED_DEGENERATE_FIXTURES:
            with self.subTest(fixture=stem):
                self.assertIn(
                    stem,
                    present,
                    stem + " proved an engine divergence and is no longer in the corpus",
                )


class DocumentedCountsMatchTheArtifacts(unittest.TestCase):
    """Counts stated in prose are claims, and claims drift.

    The PR that introduced this gate stated "1 allow / 19 deny fixtures" and
    "nineteen single-object deny fixtures, one per rule" while shipping twenty,
    and the runbook said "All fourteen checks" above a table of fifteen. None of
    it was load bearing, and all of it was wrong — so the numbers are derived
    from the artifacts here instead of being trusted.
    """

    def setUp(self) -> None:
        self.deny_fixtures = sorted((FIXTURES / "deny").glob("storage-*.yaml"))
        self.runbook = read(REPO_ROOT / "docs" / "runbooks" / "storage-admission.md")
        self.phase_a = read(REPO_ROOT / "docs" / "assurance" / "phase-a-invariants.md")
        self.phase_c = read(
            REPO_ROOT / "docs" / "assurance" / "phase-c-kubernetes-adversarial.md"
        )

    def test_the_runbook_documents_every_rule_and_no_others(self) -> None:
        documented = set(re.findall(r"(?m)^\| (SR-\d+) \|", self.runbook))
        self.assertEqual(
            documented,
            set(EXPECTED_RULE_IDS),
            "the runbook's rule table and the rule set have diverged",
        )

    def test_the_assurance_documents_state_the_real_fixture_counts(self) -> None:
        count = len(self.deny_fixtures)
        self.assertIn(
            "1 allow / {} deny fixtures".format(count),
            self.phase_a,
            "phase-a states a storage fixture count that no longer matches the corpus",
        )
        self.assertIn(
            "{} single-object deny fixtures".format(count),
            self.phase_c,
            "phase-c states a storage fixture count that no longer matches the corpus",
        )


if __name__ == "__main__":
    unittest.main()
