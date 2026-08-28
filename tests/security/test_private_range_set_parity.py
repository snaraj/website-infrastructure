"""One excluded-range set, two exact Rego consumers, no silent widening.

Every "public destinations only" egress rule in this repository is an
``ipBlock`` of ``0.0.0.0/0`` minus the private, loopback, link-local, CGNAT,
multicast, and reserved blocks. The exclusion list IS the rule: a shorter list
is a wider allow, and one dropped entry hands a rule whose only reason to exist
is public HTTPS or the tunnel edge a LAN, a node, or a neighbouring namespace.

The set lives once in ``policies/conftest/kubernetes.rego`` and both reviewed
rules must actively compare against it. Each consumer has a single-document
fixture missing exactly one range, so structural wiring and hostile behavior
are both pinned without an absent runtime engine.

WHY THE BINDING IS PER RULE AND OVER COMMENT-STRIPPED TEXT
---------------------------------------------------------

The first version of this battery scanned the whole rego as raw text and asked
two global questions: are there at least three comparisons, and does every
captured operand name the canonical set. Both survive the regression they
exist to catch. Comment out ONE rule's comparison and the raw text still
contains three matching strings — a commented one counts — every captured
operand still reads ``private_and_reserved_ranges``, and the guard stays green
while that rule accepts any exclusion list at all. A global count cannot tell
which rule owns which comparison, and raw text cannot tell code from prose.

So the reviewed consumers are named individually, their bodies are extracted,
comments are stripped, and each body must contain exactly one ACTIVE
comparison. A dropped or commented-out comparison fails by rule name. The
count is not hard-coded either: no active comparison may live outside the two
reviewed bodies, so a fourth consumer has to be registered here rather than
inheriting an unexamined pass.

Structure is only half of it. Each consumer also has a behavioural killer — a
deny fixture whose exclusion list is one range short — because a rule can be
wired to the right set and still never be asked to refuse anything.
"""

from __future__ import annotations

import re
import unittest

from .support import REPO_ROOT

REGO = REPO_ROOT / "policies" / "conftest" / "kubernetes.rego"

# Outside anchor for the exact threat boundary. If this were derived from the
# policy, both reviewed consumers and their hostile fixtures could shrink with
# the definition while the whole battery stayed green.
EXPECTED_PRIVATE_AND_RESERVED_RANGES = frozenset(
    {
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    }
)

# `private_and_reserved_ranges := { ... }` — the whole brace group, then the
# quoted CIDRs inside it, in the order the file writes them.
REGO_DEFINITION = re.compile(
    r"private_and_reserved_ranges\s*:=\s*\{(?P<body>[^}]*)\}", re.DOTALL
)
QUOTED = re.compile(r"""['"]([^'"]+)['"]""")
# One comprehension over an `except` list compared to the canonical set. The
# operand is captured rather than assumed so a comparison against some OTHER
# set is a failure that prints what it found.
EXCEPT_COMPARISON = re.compile(
    r'\{cidr \| some cidr in object\.get\([^)]*"except", \[\]\)\} == (?P<operand>\S+)'
)

# The reviewed consumers, by the exact rule head that opens each body, with the
REVIEWED_CONSUMERS = (
    ("valid_public_edge_rule(rule)", None),
    ("valid_flux_public_https_rule(rule)", None),
)

# Each consumer's behavioural killer: a deny fixture that is the reviewed shape
# in every respect EXCEPT one missing private range, so it can only be rejected
# by that rule's comparison. Without these, a rule can be wired to the canonical
# set and still never be asked to refuse a shortened list — which is how a
# rule-specific removal survived the whole fixture suite.
DENY_FIXTURES = REPO_ROOT / "tests" / "kubernetes" / "fixtures" / "deny"
CONSUMER_FIXTURES = {
    "valid_public_edge_rule(rule)": "public-edge-egress-drops-a-private-range",
    "valid_flux_public_https_rule(rule)": (
        "flux-egress-04-public-allow-drops-a-private-range"
    ),
}


def _rego_text():
    return REGO.read_text(encoding="utf-8")


def _strip_comments(text):
    """Return the rego with `#` comments removed, string literals intact.

    A commented-out line is not policy, and every structural question this
    battery asks is a question about policy. Quoting is tracked so a `#` inside
    a string literal could never truncate a real line.
    """

    lines = []
    for line in text.splitlines():
        kept = []
        in_string = False
        escaped = False
        for character in line:
            if in_string:
                kept.append(character)
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
                kept.append(character)
                continue
            if character == "#":
                break
            kept.append(character)
        lines.append("".join(kept))
    return "\n".join(lines)


def _active_rego_text():
    return _strip_comments(_rego_text())


def _rule_body(text, head, discriminator=None):
    """Return the one body of `<head> if { ... }`, by line structure.

    Rego closes a rule body with `}` at column 0, and every nested brace here is
    indented, so the block is delimited without parsing the language. When a
    head is defined more than once, `discriminator` selects the body that
    contains it.
    """

    opener = head + " if {"
    bodies = []
    collecting = None
    for line in text.splitlines():
        if collecting is None:
            if line.strip() == opener:
                collecting = []
            continue
        if line == "}":
            bodies.append("\n".join(collecting))
            collecting = None
            continue
        collecting.append(line)
    if discriminator is not None:
        bodies = [body for body in bodies if discriminator in body]
    if len(bodies) != 1:
        raise AssertionError(
            "expected exactly one active `{}` body{}, found {}".format(
                head,
                "" if discriminator is None else " containing " + discriminator,
                len(bodies),
            )
        )
    return bodies[0]


def _reviewed_ranges():
    match = REGO_DEFINITION.search(_active_rego_text())
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
            "the order the hostile fixtures teach",
        )
        self.assertEqual(
            set(self.reviewed),
            set(EXPECTED_PRIVATE_AND_RESERVED_RANGES),
            "the named exclusion set changed the exact private, loopback, "
            "link-local, CGNAT, multicast, or reserved boundary",
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

    def test_each_reviewed_rule_actively_compares_against_the_named_set(self):
        """Bound per rule, over code rather than text.

        The rule this fails for is the rule that stopped excluding anything.
        A global count cannot say that: three matching strings elsewhere in the
        file — one of them commented out — satisfy a count while one consumer
        silently accepts any exclusion list.
        """

        active = _active_rego_text()
        for head, discriminator in REVIEWED_CONSUMERS:
            with self.subTest(rule=head):
                body = _rule_body(active, head, discriminator)
                operands = EXCEPT_COMPARISON.findall(body)
                self.assertEqual(
                    operands,
                    ["private_and_reserved_ranges"],
                    "{} must contain exactly one ACTIVE comparison of its "
                    "ipBlock.except set against private_and_reserved_ranges; "
                    "found {}".format(head, operands),
                )

    def test_no_active_comparison_lives_outside_the_reviewed_rules(self):
        """A fourth consumer must be registered here, not inherit a pass.

        Keeps the per-rule binding exhaustive without hard-coding a count: the
        comparisons found in the whole policy must be exactly the ones the
        reviewed bodies account for.
        """

        active = _active_rego_text()
        in_file = EXCEPT_COMPARISON.findall(active)
        in_reviewed_rules = [
            operand
            for head, discriminator in REVIEWED_CONSUMERS
            for operand in EXCEPT_COMPARISON.findall(
                _rule_body(active, head, discriminator)
            )
        ]
        self.assertEqual(
            len(in_file),
            len(in_reviewed_rules),
            "an excluded-range comparison exists outside the reviewed "
            "consumers; add the new rule to REVIEWED_CONSUMERS with its own "
            "deny fixture rather than leaving it unbound",
        )
        self.assertEqual(
            set(in_file),
            {"private_and_reserved_ranges"},
            "every excluded-range comparison must name the one definition",
        )

    def test_each_reviewed_rule_has_a_shortened_exclusion_deny_fixture(self):
        """The behavioural half: a rule nothing refuses is a rule nothing proves.

        Each consumer's fixture must be the reviewed shape with exactly one
        canonical range missing — one document, so the rejection is
        attributable to that rule, and the missing range is a range the
        definition names.
        """

        for head, _ in REVIEWED_CONSUMERS:
            with self.subTest(rule=head):
                fixture = DENY_FIXTURES / (CONSUMER_FIXTURES[head] + ".yaml")
                self.assertTrue(
                    fixture.is_file(),
                    "{} has no shortened-exclusion deny fixture; a rule with "
                    "no fixture that violates it survives its own removal "
                    "silently".format(head),
                )
                text = fixture.read_text(encoding="utf-8")
                self.assertNotRegex(
                    text,
                    r"(?m)^---\s*$",
                    "a second document would make the rejection ambiguous "
                    "again",
                )
                declared = [
                    cidr for cidr in self.reviewed if cidr + "\n" in text
                ]
                missing = [
                    cidr for cidr in self.reviewed if cidr not in declared
                ]
                self.assertEqual(
                    len(missing),
                    1,
                    "the fixture must drop exactly one canonical range so the "
                    "only reason it can be rejected is this rule's "
                    "comparison; it drops {}".format(missing),
                )

if __name__ == "__main__":
    unittest.main()
