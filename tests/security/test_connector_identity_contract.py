"""Prove each website's connector is one indivisible identity tuple.

ADR 0015 gives every website its own public Tunnel, its own runtime token, and
its own rotation. Four properties make that real in the rendered desired state
rather than only in prose, and each is a regression this battery pins:

1. **Rotation isolation.** Every connector Deployment reads ITS OWN
   ``tokenRevision``. Rotating one Tunnel must leave the other Deployment
   byte-for-byte unchanged — a shared revision would roll both connectors and
   turn a one-site rotation into a two-site outage window.
2. **Token binding.** A connector's mounted Secret name is DERIVED from its own
   instance, so neither connector can mount the other's token even though both
   token names are individually approved.
3. **Identity root.** That instance label is itself bound to the Deployment
   NAME, so a caller-supplied label can never become the root of trust: keeping
   an allowlisted Deployment name while moving its labels AND its Secret to the
   other site is refused, in both directions.
4. **Closed connector inventory.** The chart renders exactly the two reviewed
   connector identities, each with its own token, so a third connector or a
   renamed one cannot appear silently.

The rendering assertions execute the real ``helm template`` because the defect
they guard is a TEMPLATE-level coupling that no static read of values can see.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CHART = REPO_ROOT / "kubernetes" / "platform" / "cloudflare-public" / "chart"
HELM = shutil.which("helm")

# The exact reviewed connector inventory: site key -> (instance, token Secret).
# Token names are public logical identifiers; no token VALUE exists here.
CONNECTORS = {
    "naranjo-online": ("naranjo-online-tunnel", "naranjo-online-tunnel-token"),
    "lidersea-com": ("lidersea-com-tunnel", "lidersea-com-tunnel-token"),
}
CONNECTOR_INSTANCES = tuple(instance for instance, _ in CONNECTORS.values())
# A canonical but deliberately synthetic revision: this battery proves the
# chart's coupling, never a real rotation value.
ROTATED_REVISION = "rev-rotation-isolation-probe"

# One Kyverno rule opens at this exact prefix and every key it owns sits at
# this exact indent; both are fixed by the policies' own committed layout.
RULE_PREFIX = "    - name: "
RULE_KEY_INDENT = "      "


def render(*overrides: str) -> str:
    """Render the connector chart exactly as the release gate does."""

    command = [
        str(HELM), "template", "cloudflare-public", str(CHART),
        "--namespace", "cloudflare-public",
    ]
    for override in overrides:
        command.extend(["--set", override])
    completed = subprocess.run(
        command, capture_output=True, text=True, check=False, cwd=str(REPO_ROOT)
    )
    if completed.returncode != 0:
        raise AssertionError("helm template failed: " + completed.stderr)
    return completed.stdout


def capture(pattern: str, text: str, what: str) -> str:
    """Return one required capture group, or fail loudly naming the gap.

    These assertions read a policy's own source to prove it still covers every
    connector. If the pattern stops matching — a reformat, a rename, a rule
    removed — the honest outcome is a NAMED failure saying the check stopped
    covering the thing it claims to cover. Letting ``None.group`` raise instead
    would surface as a crash, and a crash where a coverage report belongs reads
    far too easily as "nothing wrong here".
    """

    matched = re.search(pattern, text)
    if matched is None:
        raise AssertionError(
            "this check silently stopped covering it: {}".format(what)
        )
    return matched.group(1)


def documents(rendered: str) -> dict[tuple[str, str], str]:
    """Split one render into exact {(kind, name): document} parts."""

    parsed = {}
    for document in rendered.split("\n---\n"):
        kind = re.search(r"(?m)^kind: (\S+)$", document)
        name = re.search(r"(?m)^  name: (\S+)$", document)
        if kind and name:
            parsed[(kind.group(1), name.group(1))] = document
    return parsed


def document(parsed: dict[tuple[str, str], str], kind: str, name: str) -> str:
    """Return one rendered object, or fail naming the object that vanished.

    Same reasoning as ``capture()``: a bare ``KeyError`` from ``parsed[...]``
    is a crash where a coverage report belongs, and a crash reads far too
    easily as an environment problem rather than the chart having stopped
    rendering an object this contract requires.
    """

    try:
        return parsed[(kind, name)]
    except KeyError:
        raise AssertionError(
            "the chart no longer renders {} {} — rendered: {}".format(
                kind, name, sorted(parsed)
            )
        ) from None


def rule_sections(policy: Path, rule: str) -> dict[str, str]:
    """Return one Kyverno rule's own sections, keyed by their YAML key.

    Blank and comment-only lines are dropped because a YAML comment cannot
    change what a rule matches; every line that CAN change matching survives
    verbatim, so the callers below can pin whole stanzas by string equality.
    """

    lines = policy.read_text(encoding="utf-8").split("\n")
    opening = RULE_PREFIX + rule
    start = None
    for index, line in enumerate(lines):
        if line == opening:
            start = index
            break
    if start is None:
        raise AssertionError(
            "this check silently stopped covering it: rule {} in {}".format(
                rule, policy.name
            )
        )
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith(RULE_PREFIX) or (
            line and not line.startswith(RULE_KEY_INDENT)
        ):
            end = index
            break

    sections: dict[str, list[str]] = {"name": [rule]}
    body = sections["name"]
    for line in lines[start + 1:end]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line.startswith(RULE_KEY_INDENT) and line[len(RULE_KEY_INDENT)] != " ":
            key, _, inline = stripped.partition(":")
            sections[key] = []
            body = sections[key]
            if inline.strip():
                body.append(inline.strip())
            continue
        body.append(line)
    return {key: "\n".join(value) for key, value in sections.items()}


@unittest.skipUnless(HELM, "helm is required")
class ConnectorRotationIsolationTests(unittest.TestCase):
    """Rotating one Tunnel must not disturb the other connector."""

    def test_each_connector_deployment_reads_its_own_revision(self):
        parsed = documents(render())
        for instance, _ in CONNECTORS.values():
            self.assertIn(
                'platform.snaraj.dev/tunnel-token-revision: "not-configured"',
                document(parsed, "Deployment", instance),
                instance,
            )

    def test_rotating_one_connector_leaves_the_other_byte_identical(self):
        """The exact defect: a shared revision rolls BOTH Deployments."""

        baseline = documents(render())
        for site, (instance, _) in CONNECTORS.items():
            with self.subTest(rotated=site):
                rotated = documents(
                    render(
                        "connectors.{}.tokenRevision={}".format(
                            site, ROTATED_REVISION
                        )
                    )
                )
                self.assertNotEqual(
                    document(baseline, "Deployment", instance),
                    document(rotated, "Deployment", instance),
                    "the rotated connector must actually change",
                )
                self.assertIn(
                    'platform.snaraj.dev/tunnel-token-revision: "{}"'.format(
                        ROTATED_REVISION
                    ),
                    document(rotated, "Deployment", instance),
                )
                # Every other rendered object — including the OTHER connector's
                # Deployment — must be untouched, byte for byte.
                for identity, rendered in baseline.items():
                    if identity == ("Deployment", instance):
                        continue
                    self.assertEqual(
                        rendered,
                        document(rotated, *identity),
                        "{} changed while rotating {}".format(identity, site),
                    )

    def test_a_revision_outside_the_closed_grammar_is_rejected(self):
        """The schema fails closed on a non-canonical revision."""

        with self.assertRaises(AssertionError):
            render("connectors.naranjo-online.tokenRevision=NOT A REVISION")

    def test_a_blank_revision_is_rejected(self):
        with self.assertRaises(AssertionError):
            render("connectors.naranjo-online.tokenRevision=")


@unittest.skipUnless(HELM, "helm is required")
class ConnectorTokenBindingTests(unittest.TestCase):
    """Each connector carries exactly its own token and instance."""

    def test_each_connector_mounts_only_its_own_token(self):
        parsed = documents(render())
        for instance, secret in CONNECTORS.values():
            deployment = document(parsed, "Deployment", instance)
            self.assertIn("secretName: {}".format(secret), deployment)
            self.assertIn(
                "app.kubernetes.io/instance: {}".format(instance), deployment
            )
            # The other site's token must not appear in this connector at all.
            for other_instance, other_secret in CONNECTORS.values():
                if other_secret == secret:
                    continue
                self.assertNotIn(other_secret, deployment)
                self.assertNotIn(other_instance, deployment)

    def test_every_connector_instance_label_is_its_own_deployment_name(self):
        """The identity root: the label may never disagree with the name.

        Codex's bypass keeps an allowlisted Deployment NAME and moves the three
        instance labels plus the Secret to the other site, so every
        instance-derived check agrees with itself while that Deployment's Pods
        consume the other website's credential. Admission refuses it; the chart
        must never render it either.
        """

        parsed = documents(render())
        for instance, _ in CONNECTORS.values():
            deployment = document(parsed, "Deployment", instance)
            claimed = re.findall(
                r"app\.kubernetes\.io/instance: (\S+)", deployment
            )
            self.assertEqual(
                len(claimed), 3, "metadata, selector and template labels"
            )
            self.assertEqual(set(claimed), {instance})

    def test_a_foreign_token_name_is_rejected_by_the_schema(self):
        """A connector may not be pointed at the other site's Secret."""

        with self.assertRaises(AssertionError):
            render("connectors.naranjo-online.secretName=lidersea-com-tunnel-token")

    def test_the_superseded_shared_token_is_rejected_by_the_schema(self):
        with self.assertRaises(AssertionError):
            render("connectors.naranjo-online.secretName=pi-websites-tunnel-token")

    def test_the_connector_inventory_is_exactly_the_two_reviewed_sites(self):
        parsed = documents(render())
        connectors = {
            name for kind, name in parsed if kind == "Deployment"
        }
        self.assertEqual(connectors, set(CONNECTOR_INSTANCES))

    def test_the_superseded_single_connector_deployment_is_gone(self):
        parsed = documents(render())
        self.assertNotIn(("Deployment", "cloudflared"), parsed)


class ConnectorAdmissionCoverageTests(unittest.TestCase):
    """Bind the admission match stanzas to the RENDERED connector inventory.

    ``kyverno test`` cannot prove this on its own: when a resource falls
    OUTSIDE a rule's ``match`` block the CLI reports the row as ``Pass``
    (status ``Excluded``), so a narrowed rule leaves every asserted row green
    while both real connectors silently bypass the gate.

    Pinning only the VALUE LISTS closed exactly one axis of that class. Seven
    other narrowings survived a fully green suite: swapping the token-revision
    rule's ``namespaces`` for a decoy, its ``kinds`` for ``StatefulSet``,
    adding an ``exclude`` block, pointing the ReplicaSet rule at another
    namespace, downgrading ``failureAction`` to ``Audit``, and the same
    namespace/kind swaps on the storage rule. So the assertion has to pin the
    WHOLE stanza of every connector-bearing rule by string equality — match,
    the absence of any exclude, and the enforced failure action — with the
    matched identities interpolated from the inventory the chart renders.
    """

    READINESS_POLICY = (
        REPO_ROOT / "policies" / "kyverno" / "require-release-readiness.yaml"
    )
    RELEASE_POLICY = (
        REPO_ROOT / "policies" / "release-conftest" / "deployment-readiness.rego"
    )
    STORAGE_POLICY = (
        REPO_ROOT / "policies" / "kyverno" / "disallow-undiscovered-storage.yaml"
    )

    # rule -> (policy attribute, exact reviewed match stanza). The connector
    # names are interpolated, never spelled twice, so a chart rename that
    # skipped the policies cannot be papered over by editing this file's
    # expectation alone: ``CONNECTORS`` is proven equal to the rendered
    # inventory by ``test_admission_identities_equal_the_rendered_identities``.
    CONNECTOR_RULES = {
        "require-tunnel-token-revision": (
            "READINESS_POLICY",
            "        any:\n"
            "          - resources:\n"
            "              kinds: [Deployment]\n"
            "              namespaces: [cloudflare-public]\n"
            "              names: [{}]".format(", ".join(CONNECTOR_INSTANCES)),
        ),
        "require-connector-identity-tuple": (
            "READINESS_POLICY",
            "        any:\n"
            "          - resources:\n"
            "              kinds: [Deployment]\n"
            "              namespaces: [cloudflare-public]",
        ),
        "require-replicaset-owned-by-exact-deployment": (
            "READINESS_POLICY",
            "        any:\n"
            "          - resources:\n"
            "              kinds: [ReplicaSet]\n"
            "              namespaces: [cloudflare-public, naranjo-online, lidersea-com]",
        ),
        "allow-only-tunnel-token-volume": (
            "STORAGE_POLICY",
            "        any:\n"
            "          - resources:\n"
            "              kinds: [Pod]\n"
            "              namespaces: [cloudflare-public]",
        ),
    }
    # The CEL of the rules that carry the inventory inside an expression rather
    # than in ``names:``. Same binding, different syntax.
    CEL_INVENTORIES = {
        "require-connector-identity-tuple": "READINESS_POLICY",
        "allow-only-tunnel-token-volume": "STORAGE_POLICY",
    }

    def test_every_connector_rule_matches_exactly_the_reviewed_stanza(self):
        """Any narrowing of match — kinds, namespaces, names — goes red here."""

        for rule, (attribute, expected) in self.CONNECTOR_RULES.items():
            with self.subTest(rule=rule):
                sections = rule_sections(getattr(self, attribute), rule)
                self.assertEqual(
                    sections.get("match"),
                    expected,
                    "the reviewed match stanza of {} changed; a narrowed match "
                    "silently stops covering the connectors".format(rule),
                )

    def test_no_connector_rule_carries_an_exclude_or_extra_stanza(self):
        """An added ``exclude`` narrows a rule without touching ``match``."""

        for rule, (attribute, _) in self.CONNECTOR_RULES.items():
            with self.subTest(rule=rule):
                sections = rule_sections(getattr(self, attribute), rule)
                self.assertEqual(
                    list(sections),
                    ["name", "match", "validate"],
                    "{} gained or lost a stanza; only match and validate are "
                    "reviewed".format(rule),
                )

    def test_every_connector_rule_fails_closed(self):
        """``Audit`` would report the bypass instead of refusing it."""

        for rule, (attribute, _) in self.CONNECTOR_RULES.items():
            with self.subTest(rule=rule):
                sections = rule_sections(getattr(self, attribute), rule)
                self.assertIn(
                    "        failureAction: Enforce",
                    sections.get("validate", "").split("\n"),
                    "{} must refuse, not merely audit".format(rule),
                )

    def test_both_connector_policies_fail_closed_at_the_policy_level(self):
        for policy in (self.READINESS_POLICY, self.STORAGE_POLICY):
            with self.subTest(policy=policy.name):
                lines = policy.read_text(encoding="utf-8").split("\n")
                self.assertIn("  validationFailureAction: Enforce", lines)
                self.assertIn("    failurePolicy: Fail", lines)

    def test_both_connector_policies_run_at_admission(self):
        """``admission: false`` disables EVERY rule in the policy.

        One word, invisible to both engines' suites: the policy still parses,
        every asserted row still passes, and in-cluster nothing is evaluated at
        admission at all — the policy degrades to a background scan. It is a
        wider narrowing than any single rule's match block, so it is pinned at
        the policy level.
        """

        for policy in (self.READINESS_POLICY, self.STORAGE_POLICY):
            with self.subTest(policy=policy.name):
                self.assertIn(
                    "  admission: true",
                    policy.read_text(encoding="utf-8").split("\n"),
                    "{} must still run at admission".format(policy.name),
                )

    # Kyverno's userInfo selectors narrow a rule to principals, not resources.
    # `clusterRoles: [no-such-role]` makes a rule match nobody in-cluster while
    # `kyverno test` reports the row as Skip — and Skip counts as a PASS there,
    # exactly like the Excluded rows an out-of-match resource produces. Neither
    # engine's suite can see this, so it is pinned structurally.
    FORBIDDEN_NARROWING_KEYS = ("clusterRoles", "subjects", "roles")

    def test_no_connector_rule_narrows_by_principal(self):
        for rule, (attribute, _) in self.CONNECTOR_RULES.items():
            sections = rule_sections(getattr(self, attribute), rule)
            for key in self.FORBIDDEN_NARROWING_KEYS:
                with self.subTest(rule=rule, key=key):
                    self.assertNotIn(
                        key + ":",
                        "\n".join(sections.values()),
                        "{} must not narrow to principals: a userInfo "
                        "selector makes it match nobody while the suite "
                        "reports Skip".format(rule),
                    )

    def test_the_cel_connector_inventories_are_the_rendered_inventory(self):
        """The rules whose inventory lives in an expression, not in names."""

        expected = ", ".join(
            "'{}'".format(instance) for instance in CONNECTOR_INSTANCES
        )
        for rule, attribute in self.CEL_INVENTORIES.items():
            with self.subTest(rule=rule):
                sections = rule_sections(getattr(self, attribute), rule)
                self.assertIn(
                    "[{}]".format(expected),
                    sections.get("validate", ""),
                    "{} must name exactly the rendered connectors".format(rule),
                )

    def test_replicaset_owner_rule_admits_exactly_the_rendered_connectors(self):
        text = self.READINESS_POLICY.read_text(encoding="utf-8")
        owners = {
            name.strip().strip("'")
            for name in capture(
                r"owner\.name in \[([^\]]+)\]",
                text,
                "the ReplicaSet rule's connector owner list",
            ).split(",")
        }
        self.assertEqual(
            owners,
            set(CONNECTOR_INSTANCES),
            "connector rollout must be possible for every rendered connector",
        )

    def test_release_policy_covers_every_rendered_connector(self):
        text = self.RELEASE_POLICY.read_text(encoding="utf-8")
        names = {
            name.strip().strip('"')
            for name in capture(
                r"cloudflared_connector_deployments := \{([^}]+)\}",
                text,
                "the release policy's connector Deployment set",
            ).split(",")
        }
        self.assertEqual(names, set(CONNECTOR_INSTANCES))

    def test_no_policy_still_names_the_superseded_shared_connector(self):
        """The single-connector identity must not survive anywhere."""

        for policy in (
            self.READINESS_POLICY, self.RELEASE_POLICY, self.STORAGE_POLICY
        ):
            text = policy.read_text(encoding="utf-8")
            self.assertNotIn("pi-websites-tunnel-token", text, policy.name)
            self.assertIsNone(
                re.search(r"""['"]cloudflared['"]""", text),
                "{} still pins the superseded connector identity".format(
                    policy.name
                ),
            )

    @unittest.skipUnless(HELM, "helm is required")
    def test_admission_identities_equal_the_rendered_identities(self):
        """A chart rename that skipped the policies fails here."""

        rendered = {
            name
            for kind, name in documents(render())
            if kind == "Deployment"
        }
        self.assertEqual(
            set(CONNECTOR_INSTANCES),
            rendered,
            "the reviewed connector inventory drifted from the rendered chart",
        )
        matched = capture(
            r"(?m)^              names: \[([^\]]+)\]$",
            self.READINESS_POLICY.read_text(encoding="utf-8"),
            "the token-revision rule's connector name match list",
        )
        self.assertEqual(
            {name.strip() for name in matched.split(",")},
            rendered,
            "the admission match list drifted from the rendered connectors",
        )


if __name__ == "__main__":
    unittest.main()
