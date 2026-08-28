"""Structural and hostile contract for the self-sufficient storage Rego gate.

The fixture runner proves the verdict of every extant file, while this battery
prevents the corpus, exact SR-0..SR-16 rule inventory, enumerated local means,
and the two independent Pod-volume arms from being narrowed or deleted. All
expectations are outside literals parsed with the standard library only.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFTEST_POLICY = REPO_ROOT / "policies" / "conftest" / "kubernetes.rego"
FIXTURES = REPO_ROOT / "tests" / "kubernetes" / "fixtures"

# The complete storage rule set, stated ONCE here in the test rather than read
# out of the policy. A policy and its fixtures can be narrowed together; this
# literal is the outside
# anchor that makes such a matching narrowing fail. It is also the reason nothing
# in this battery ever SKIPs: a guard that stands down when its expectation stops
# matching is a guard that disables itself.
EXPECTED_RULE_IDS = frozenset("SR-{}".format(index) for index in range(17))

# Exact API surface protected by the storage model. Deriving this expectation
# from `storage_kinds` would let a kind, its rules, and its fixtures disappear
# together without a failure.
EXPECTED_STORAGE_KINDS = frozenset(
    {
        "PersistentVolume",
        "PersistentVolumeClaim",
        "StorageClass",
        "CSIDriver",
        "VolumeAttributesClass",
    }
)

# The complete non-source field list, stated here as a LITERAL for the same
# reason ``EXPECTED_RULE_IDS`` is. A name added to this list is the one edit
# that converts the subtraction from
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

# The pod-volume model has TWO arms, and each one needs its own killer. The
# subtraction was the largest new control of the round that introduced it and it
# shipped with none: neutering either arm left the then-current gates green
# while the probe the model was written to deny — a fully compliant Pod in
# `default` mounting ``azureFile`` — went straight back to admitted (historical
# wi #96 delta review). The only
# fixture touching the arms held twenty objects under a file-level assertion,
# which is the multi-document masking defect this branch fixed everywhere else.
#
# So each arm gets a single-object deny fixture that ONLY it rejects, and each
# fixture declares the message fragment its arm emits. The mapping is held here,
# outside both the fixture and the runner, so neither the fixture nor its
# attribution can be dropped quietly.
#
# The global fixture runner rejects each file, which alone kills either arm
# because each fixture is rejected by exactly one arm. The declarations below
# separately bind every fixture to the exact message its arm emits.
POD_VOLUME_ARM_FIXTURES = {
    "pod-volume-undiscovered-source": "uses undiscovered storage source",
    "pod-volume-multiple-sources": "must declare exactly one volume source, found",
}

# The storage corpus floor is held outside the fixture runner so neither the
# corpus nor its minimum can be trimmed quietly.
MINIMUM_STORAGE_DENY_FIXTURES = 30

# Degenerate shapes that MUST stay in the corpus. A historical differential
# review (wi #96) proved each could make Rego admit malformed storage because a
# nested ``object.get`` type error made the deny rule undefined. The name on the
# left is the fixture stem; losing any silently retires a proven regression.
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


class EnumerationLockstep(unittest.TestCase):
    """The exact Rego enumeration is the storage allowlist."""

    def setUp(self) -> None:
        self.rego = read(CONFTEST_POLICY)

    def test_storage_kind_scope_remains_exact(self) -> None:
        self.assertEqual(
            set(rego_set_literal(self.rego, "storage_kinds")),
            set(EXPECTED_STORAGE_KINDS),
            "the storage policy kind scope changed; a removed kind loses all "
            "of its hostile coverage with it",
        )

    def test_enumerated_local_means_remain_exact(self) -> None:
        expected = {
            "enumerated_storage_classes": {"local-pie-ssd"},
            "enumerated_storage_provisioners": {"kubernetes.io/no-provisioner"},
            "enumerated_local_volume_roots": {"/mnt/local-pie-ssd"},
            "enumerated_csi_drivers": set(),
            "enumerated_volume_attributes_classes": set(),
            "admitted_persistent_volume_sources": {"local", "csi"},
        }
        for name, values in expected.items():
            with self.subTest(enumeration=name):
                self.assertEqual(set(rego_set_literal(self.rego, name)), values)

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
        added to the list, a PersistentVolume carrying a valid
        local source under the enumerated root PLUS `quantumMesh: {endpoint:
        storage.invalid:9999}` went from denied to admitted, with every other
        committed check green (wi #96 adversarial
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
    """Two-way lock: the Rego rules and the fixtures that kill them.

    A deny fixture that merely proves "this file is rejected" cannot show WHICH
    rule rejected it, so deleting one rule can leave the suite green while
    another rule's denial covers for it. Every fixture here therefore holds one
    object and names the rule it exists to kill. Both sets must equal the exact
    outside SR-0..SR-16 inventory above.
    """

    def setUp(self) -> None:
        self.rego = read(CONFTEST_POLICY)
        self.deny_fixtures = sorted((FIXTURES / "deny").glob("storage-*.yaml"))

    @staticmethod
    def ids_in(text: str) -> set[str]:
        return set(re.findall(r"#\s*(SR-\d+)[.,\s]", text))

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

        The fixture runner asserts only that a FILE is rejected, so a rule can
        be neutralized and stay green whenever any OTHER rule also denies the
        same object. The exact message declaration below prevents one rule's
        denial from standing in for another.

        Each fixture therefore declares the exact message fragment its claimed
        rule emits. This test keeps the declarations from being dropped or
        degenerating into fragments so short that any denial would satisfy them.
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

class FixtureCoverage(unittest.TestCase):
    """Every covered kind is proven, and every proof is where the runners look."""

    def setUp(self) -> None:
        self.matched = rego_set_literal(read(CONFTEST_POLICY), "storage_kinds")
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

    def test_deny_fixtures_live_where_the_fixture_runner_scans(self) -> None:
        """``scripts/test-policy-fixtures.sh`` globs this directory, and the
        trivy misconfiguration pass excludes exactly this directory, so a
        fixture placed anywhere else is neither proven nor exempted."""

        self.assertTrue(self.deny_fixtures, "the storage deny fixtures have disappeared")
        for path in self.deny_fixtures:
            self.assertEqual(path.parent, FIXTURES / "deny")


class StorageCorpusContract(unittest.TestCase):
    """Keep the hostile storage corpus above its reviewed exact floor."""

    def setUp(self) -> None:
        self.deny_fixtures = sorted((FIXTURES / "deny").glob("storage-*.yaml"))

    def test_the_corpus_cannot_be_trimmed_below_the_floor(self) -> None:
        self.assertGreaterEqual(
            len(self.deny_fixtures),
            MINIMUM_STORAGE_DENY_FIXTURES,
            "the storage deny corpus shrank below its reviewed floor",
        )

    def test_every_proven_degenerate_shape_is_still_in_the_corpus(self) -> None:
        present = {path.stem for path in self.deny_fixtures}
        for stem in REQUIRED_DEGENERATE_FIXTURES:
            with self.subTest(fixture=stem):
                self.assertIn(
                    stem,
                    present,
                    stem + " proved a fail-open Rego shape and is no longer in the corpus",
                )


class PodVolumeArmsAreIndividuallyKillable(unittest.TestCase):
    """Each pod-volume arm has one fixture that only it rejects.

    The subtraction model that replaced the ten-name pod blocklist was the
    largest new control of its round and shipped with no killer at all: either
    arm could be neutralized while a multi-document file was still rejected by
    the other arm. The single-object killers below close that masking defect.

    This class is the outside anchor for the correction: the two fixtures, the
    message each one attributes its denial to, the one-object-per-file rule that
    keeps the attribution honest, and the wiring that turns the declaration into
    a check on every run.
    """

    def setUp(self) -> None:
        self.rego = read(CONFTEST_POLICY)
        self.runner = REPO_ROOT / "scripts" / "test-policy-fixtures.sh"

    def test_each_pod_volume_arm_has_a_single_object_deny_fixture(self) -> None:
        for stem, fragment in sorted(POD_VOLUME_ARM_FIXTURES.items()):
            path = FIXTURES / "deny" / (stem + ".yaml")
            with self.subTest(fixture=stem):
                self.assertTrue(
                    path.is_file(),
                    stem + " is the only killer for its pod-volume arm and it is gone",
                )
                text = read(path)
                # One object per file, for the same reason the storage corpus
                # holds one: a second object's denial would stand in for this
                # one's and the arm would stop being separately killable.
                self.assertEqual(len(re.findall(r"(?m)^kind: \S+$", text)), 1)
                self.assertNotIn("\n---\n", text)
                claim = require(
                    re.match(r"# proves: (\S+)\n# rego-message: (.+)\n", text),
                    "`# proves:` and `# rego-message:` headers on deny fixture " + path.name,
                )
                self.assertEqual(
                    claim.group(2).strip(),
                    fragment,
                    "the message " + stem + " attributes its denial to has changed",
                )

    def test_each_declared_pod_message_is_a_message_the_mirror_actually_emits(self) -> None:
        """A fragment no rule emits would make the attribution unfalsifiable."""

        for stem, fragment in sorted(POD_VOLUME_ARM_FIXTURES.items()):
            with self.subTest(fixture=stem):
                self.assertGreaterEqual(
                    len(fragment),
                    20,
                    "the declared denial message is too short to attribute anything: " + fragment,
                )
                self.assertIn(
                    fragment,
                    self.rego,
                    "no Conftest rule emits the message " + stem + " claims: " + fragment,
                )

    def test_the_two_fixtures_cover_the_two_distinct_arms(self) -> None:
        """One fixture per arm — not two fixtures for the same arm.

        The arms are separate deny rules with separate messages, and the
        fragments above are what tells them apart.
        """

        self.assertEqual(len(set(POD_VOLUME_ARM_FIXTURES.values())), 2)

    def test_the_file_level_runner_still_reaches_the_pod_corpus(self) -> None:
        """The second, independent killer, and the reason it is enough on its own.

        Each fixture above is rejected by ONE arm, so plain file-level rejection
        already fails when that arm is neutered — no attribution needed to go
        red, only to say which arm. This pins that the file-level runner keeps
        globbing the directory the fixtures live in, so the two killers stay
        independent rather than both routing through the same mechanism.
        """

        runner = read(self.runner)
        self.assertIn(
            "tests/kubernetes/fixtures/deny/*.yaml",
            runner,
            "the fixture runner no longer scans the directory the pod fixtures live in",
        )
        self.assertIn(
            "deny fixture unexpectedly passed",
            runner,
            "the fixture runner no longer fails when a deny fixture is admitted",
        )

if __name__ == "__main__":
    unittest.main()
