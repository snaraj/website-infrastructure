"""One excluded-range set, four readers, no silent divergence.

Every "public destinations only" egress rule in this repository is an
``ipBlock`` of ``0.0.0.0/0`` minus the private, loopback, link-local, CGNAT,
multicast, and reserved blocks. The exclusion list IS the rule: a shorter list
is a wider allow, and one dropped entry hands a rule whose only reason to exist
is Sigstore/GHCR or the tunnel edge a LAN, a node, or a neighbouring namespace.

The set is written out in four places that CANNOT reference each other:

* ``policies/conftest/kubernetes.rego`` — the named ``private_and_reserved_ranges``
  set, the one definition every rego rule now compares against. Its own comment
  states the rule this battery enforces: "a set that exists twice is a set that
  gets widened once". It existed twice anyway — ``valid_flux_public_https_rule``
  retyped all eight literals inline — which is issue #138 F6 and is fixed in
  the same change as this battery.
* ``policies/kyverno/require-exact-tenant-networking.yaml`` — a CEL expression.
  CEL cannot import rego, so the literal list is unavoidable there; what is
  avoidable is its drifting from the rego unnoticed.
* the two installer batteries' constants, which read the committed manifests
  DIRECTLY and deliberately do not consult the policy engines: a widening
  applied to a rego arm and to the manifest together passes conftest by
  construction (that was reproduced on this repository), so those pins are the
  independent reading that stays red. Their independence is authorial, not
  numeric — nothing about it requires them to disagree, and a divergence is
  drift rather than review.

This battery adds no fifth copy of the numbers. It reads the rego definition
and asserts the other readers equal it, so drift in any one of them fails here
and names the reader that moved.
"""

from __future__ import annotations

import re
import unittest

from . import test_flux_install_contract as flux_battery
from . import test_kyverno_install_contract as kyverno_battery
from .support import REPO_ROOT

REGO = REPO_ROOT / "policies" / "conftest" / "kubernetes.rego"
TENANT_NETWORKING_POLICY = (
    REPO_ROOT / "policies" / "kyverno" / "require-exact-tenant-networking.yaml"
)

# `private_and_reserved_ranges := { ... }` — the whole brace group, then the
# quoted CIDRs inside it, in the order the file writes them.
REGO_DEFINITION = re.compile(
    r"private_and_reserved_ranges\s*:=\s*\{(?P<body>[^}]*)\}", re.DOTALL
)
# `... ipBlock.except == ['10.0.0.0/8', ...]` in the CEL expression.
CEL_EXCLUSIONS = re.compile(r"ipBlock\.except\s*==\s*\[(?P<body>[^\]]*)\]")
QUOTED = re.compile(r"""['"]([^'"]+)['"]""")


def _rego_text():
    return REGO.read_text(encoding="utf-8")


def _reviewed_ranges():
    match = REGO_DEFINITION.search(_rego_text())
    if match is None:
        raise AssertionError(
            "the named excluded-range set is gone from {}; every rule that "
            "referenced it now means something else".format(REGO)
        )
    return QUOTED.findall(match.group("body"))


class ExcludedRangeSetParityTests(unittest.TestCase):
    """The rego definition is the source; everything else must equal it."""

    def setUp(self):
        self.reviewed = _reviewed_ranges()

    def test_the_definition_is_a_real_set(self):
        """A definition that is empty or duplicated would pass every comparison
        below while excluding nothing."""

        self.assertGreater(len(self.reviewed), 0)
        self.assertEqual(
            len(self.reviewed),
            len(set(self.reviewed)),
            "a repeated entry hides a missing one behind an unchanged count",
        )
        self.assertEqual(
            self.reviewed,
            sorted(self.reviewed),
            "the reviewed order is the order the rendered manifests use and "
            "the order the CEL list is compared against",
        )

    def test_the_rego_states_each_range_exactly_once(self):
        """The in-file single-source pin (F6).

        Rego CAN reference the named set, so every occurrence of these literals
        in the policy file beyond the definition is a second copy — the shape
        the definition's own comment warns about, and the shape
        ``valid_flux_public_https_rule`` carried until this change. Counting
        literals catches a re-inlining anywhere in the file, including in a
        rule this battery has never heard of.
        """

        text = _rego_text()
        repeated = {
            cidr: text.count('"' + cidr + '"')
            for cidr in self.reviewed
            if text.count('"' + cidr + '"') != 1
        }
        self.assertEqual(
            repeated,
            {},
            "these ranges are typed more than once in the policy; compare "
            "against private_and_reserved_ranges instead of retyping the set",
        )

    def test_every_rego_comparison_uses_the_named_set(self):
        """A helper that stopped comparing at all would satisfy the count above.

        Each ``ipBlock.except`` comparison in the rego must be against the
        named set — the count pin proves no literal copy exists, this proves
        the rules did not simply drop the exclusion check while removing it.
        """

        comparisons = re.findall(
            r'\{cidr \| some cidr in object\.get\([^)]*"except", \[\]\)\} == (\S+)',
            _rego_text(),
        )
        self.assertGreaterEqual(
            len(comparisons),
            3,
            "the reviewed public-egress rules are the tunnel edge, the Flux "
            "public-HTTPS rule, and the admission public-HTTPS rule; fewer "
            "comparisons means a rule stopped excluding anything",
        )
        self.assertEqual(
            set(comparisons),
            {"private_and_reserved_ranges"},
            "every excluded-range comparison must name the one definition",
        )

    def test_the_kyverno_cel_list_equals_the_rego_set(self):
        """Two engines that exclude different ranges enforce two contracts.

        CEL compares lists by order as well as by membership, so the equality
        asserted here is the exact list the admission engine demands.
        """

        match = CEL_EXCLUSIONS.search(
            TENANT_NETWORKING_POLICY.read_text(encoding="utf-8")
        )
        self.assertIsNotNone(
            match,
            "the tunnel-edge egress rule no longer pins an excluded-range "
            "list at all",
        )
        self.assertEqual(
            QUOTED.findall(match.group("body")),
            self.reviewed,
            "the Kyverno CEL exclusion list drifted from the reviewed rego "
            "set; whichever engine is installed would enforce the narrower "
            "one",
        )

    def test_the_installer_batteries_pin_the_same_set(self):
        """The manifest-reading pins are independent, not divergent."""

        self.assertEqual(
            list(flux_battery.EXPECTED_EXCLUDED_RANGES),
            self.reviewed,
            "the Flux install battery's excluded ranges drifted from the "
            "reviewed rego set",
        )
        self.assertEqual(
            list(kyverno_battery.AdmissionNetworkShapeTests.EXCLUDED_RANGES),
            self.reviewed,
            "the admission network-shape battery's excluded ranges drifted "
            "from the reviewed rego set",
        )


if __name__ == "__main__":
    unittest.main()
