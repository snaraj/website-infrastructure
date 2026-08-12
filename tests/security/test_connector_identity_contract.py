"""Prove each website's connector is one indivisible identity tuple.

ADR 0015 gives every website its own public Tunnel, its own runtime token, and
its own rotation. Three properties make that real in the rendered desired state
rather than only in prose, and each is a regression this battery pins:

1. **Rotation isolation.** Every connector Deployment reads ITS OWN
   ``tokenRevision``. Rotating one Tunnel must leave the other Deployment
   byte-for-byte unchanged — a shared revision would roll both connectors and
   turn a one-site rotation into a two-site outage window.
2. **Token binding.** A connector's mounted Secret name is DERIVED from its own
   instance, so neither connector can mount the other's token even though both
   token names are individually approved.
3. **Closed connector inventory.** The chart renders exactly the two reviewed
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
# A canonical but deliberately synthetic revision: this battery proves the
# chart's coupling, never a real rotation value.
ROTATED_REVISION = "rev-rotation-isolation-probe"


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


@unittest.skipUnless(HELM, "helm is required")
class ConnectorRotationIsolationTests(unittest.TestCase):
    """Rotating one Tunnel must not disturb the other connector."""

    def test_each_connector_deployment_reads_its_own_revision(self):
        parsed = documents(render())
        for instance, _ in CONNECTORS.values():
            deployment = parsed[("Deployment", instance)]
            self.assertIn(
                'platform.snaraj.dev/tunnel-token-revision: "not-configured"',
                deployment,
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
                    baseline[("Deployment", instance)],
                    rotated[("Deployment", instance)],
                    "the rotated connector must actually change",
                )
                self.assertIn(
                    'platform.snaraj.dev/tunnel-token-revision: "{}"'.format(
                        ROTATED_REVISION
                    ),
                    rotated[("Deployment", instance)],
                )
                # Every other rendered object — including the OTHER connector's
                # Deployment — must be untouched, byte for byte.
                for identity, document in baseline.items():
                    if identity == ("Deployment", instance):
                        continue
                    self.assertEqual(
                        document,
                        rotated[identity],
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
            deployment = parsed[("Deployment", instance)]
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
        self.assertEqual(
            connectors, {instance for instance, _ in CONNECTORS.values()}
        )

    def test_the_superseded_single_connector_deployment_is_gone(self):
        parsed = documents(render())
        self.assertNotIn(("Deployment", "cloudflared"), parsed)


class ConnectorAdmissionCoverageTests(unittest.TestCase):
    """Bind the admission match lists to the RENDERED connector inventory.

    ``kyverno test`` cannot prove this on its own: when a resource falls
    OUTSIDE a rule's ``match`` block the CLI reports the row as ``Pass``
    (status ``Excluded``), so narrowing ``names:`` back to the superseded
    ``cloudflared`` leaves every asserted row green while both real connectors
    silently bypass the gate. That is precisely the defect this battery exists
    to prevent, so the coverage assertion has to be structural: the identities
    the policies match must EQUAL the connector identities the chart renders.
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

    def test_token_revision_rule_matches_exactly_the_rendered_connectors(self):
        text = self.READINESS_POLICY.read_text(encoding="utf-8")
        names = {
            name.strip()
            for name in capture(
                r"(?m)^              names: \[([^\]]+)\]$",
                text,
                "the token-revision rule's connector name match list",
            ).split(",")
        }
        self.assertEqual(
            names,
            {instance for instance, _ in CONNECTORS.values()},
            "the token-revision gate must match every rendered connector",
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
            {instance for instance, _ in CONNECTORS.values()},
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
        self.assertEqual(names, {instance for instance, _ in CONNECTORS.values()})

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
        text = self.READINESS_POLICY.read_text(encoding="utf-8")
        matched = capture(
            r"(?m)^              names: \[([^\]]+)\]$",
            text,
            "the token-revision rule's connector name match list",
        )
        self.assertEqual(
            {name.strip() for name in matched.split(",")},
            rendered,
            "the admission match list drifted from the rendered connectors",
        )


if __name__ == "__main__":
    unittest.main()
