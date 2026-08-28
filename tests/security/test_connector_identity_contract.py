"""Hostile Conftest and Helm checks for per-site connector isolation."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from .support import required_tool


ROOT = Path(__file__).resolve().parents[2]
CONFTEST = shutil.which("conftest")
CONFTEST_POLICY = ROOT / "policies/conftest"
HELM = shutil.which("helm")
CHART = ROOT / "kubernetes/platform/cloudflare-public/chart"
CONNECTORS = {
    "naranjo-online": ("naranjo-online-tunnel", "naranjo-online-tunnel-token"),
    "lidersea-com": ("lidersea-com-tunnel", "lidersea-com-tunnel-token"),
}
CONNECTOR_INSTANCES = tuple(instance for instance, _ in CONNECTORS.values())
ROTATED_REVISION = "rev-rotation-isolation-probe"


def render(*overrides):
    """Render the real connector chart with only synthetic public values."""

    command = [
        str(HELM),
        "template",
        "cloudflare-public",
        str(CHART),
        "--namespace",
        "cloudflare-public",
    ]
    for override in overrides:
        command.extend(["--set", override])
    completed = subprocess.run(
        command, capture_output=True, text=True, check=False, cwd=ROOT
    )
    if completed.returncode != 0:
        raise AssertionError("helm template failed: " + completed.stderr)
    return completed.stdout


def documents(rendered):
    """Split a Helm render into exact ``(kind, name)`` documents."""

    parsed = {}
    for rendered_document in rendered.split("\n---\n"):
        kind = re.search(r"(?m)^kind: (\S+)$", rendered_document)
        name = re.search(r"(?m)^  name: (\S+)$", rendered_document)
        if kind and name:
            parsed[(kind.group(1), name.group(1))] = rendered_document
    return parsed


def document(parsed, kind, name):
    try:
        return parsed[(kind, name)]
    except KeyError:
        raise AssertionError(
            "the chart no longer renders {} {} — rendered: {}".format(
                kind, name, sorted(parsed)
            )
        ) from None


def conftest_denials(path):
    """Return every exact denial, preserving duplicate messages."""

    completed = subprocess.run(
        [
            required_tool(CONFTEST, "conftest"),
            "test",
            "--policy",
            str(CONFTEST_POLICY),
            "--output",
            "json",
            "--no-color",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            "conftest emitted unreadable JSON for {}: {}{}".format(
                path.name, completed.stdout, completed.stderr
            )
        ) from error
    return sorted(
        failure.get("msg", "")
        for document_result in report
        for failure in document_result.get("failures", [])
    )


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
                )
                self.assertIn(
                    'platform.snaraj.dev/tunnel-token-revision: "{}"'.format(
                        ROTATED_REVISION
                    ),
                    document(rotated, "Deployment", instance),
                )
                for identity, rendered_document in baseline.items():
                    if identity == ("Deployment", instance):
                        continue
                    self.assertEqual(
                        rendered_document,
                        document(rotated, *identity),
                        "{} changed while rotating {}".format(identity, site),
                    )

    def test_a_revision_outside_the_closed_grammar_is_rejected(self):
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
            for other_instance, other_secret in CONNECTORS.values():
                if other_secret == secret:
                    continue
                self.assertNotIn(other_secret, deployment)
                self.assertNotIn(other_instance, deployment)

    def test_every_connector_instance_label_is_its_own_deployment_name(self):
        parsed = documents(render())
        for instance, _ in CONNECTORS.values():
            deployment = document(parsed, "Deployment", instance)
            claimed = re.findall(
                r"app\.kubernetes\.io/instance: (\S+)", deployment
            )
            self.assertEqual(len(claimed), 3)
            self.assertEqual(set(claimed), {instance})

    def test_a_foreign_token_name_is_rejected_by_the_schema(self):
        with self.assertRaises(AssertionError):
            render("connectors.naranjo-online.secretName=lidersea-com-tunnel-token")

    def test_the_superseded_shared_token_is_rejected_by_the_schema(self):
        with self.assertRaises(AssertionError):
            render("connectors.naranjo-online.secretName=pi-websites-tunnel-token")

    def test_the_connector_inventory_is_exactly_the_two_reviewed_sites(self):
        parsed = documents(render())
        connectors = {name for kind, name in parsed if kind == "Deployment"}
        self.assertEqual(connectors, set(CONNECTOR_INSTANCES))

    def test_the_superseded_single_connector_deployment_is_gone(self):
        parsed = documents(render())
        self.assertNotIn(("Deployment", "cloudflared"), parsed)


class ConnectorIdentityContractTests(unittest.TestCase):
    def run_fixture(self, family, name):
        return subprocess.run(
            [
                required_tool(CONFTEST, "conftest"),
                "test",
                "--policy",
                str(ROOT / "policies/conftest"),
                str(ROOT / "tests/kubernetes/fixtures" / family / name),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_reviewed_connectors_are_accepted(self):
        for name in ("live-connector-env-token.yaml", "two-connector-networking.yaml"):
            with self.subTest(name=name):
                completed = self.run_fixture("allow", name)
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )

    def test_cross_site_credentials_and_egress_are_rejected(self):
        fixtures = (
            "connector-egress-cross-site.yaml",
            "connector-token-cross-swap-naranjo.yaml",
            "connector-token-cross-swap-lidersea.yaml",
            "env-token-envfrom-cross-site.yaml",
            "env-token-ephemeral-container-cross-site.yaml",
            "connector-identity-degenerate-labels.yaml",
        )
        for name in fixtures:
            with self.subTest(name=name):
                completed = self.run_fixture("deny", name)
                self.assertNotEqual(completed.returncode, 0)

    def test_site_ingress_policy_name_is_exact_and_provider_neutral(self):
        text = (ROOT / "policies/conftest/kubernetes.rego").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'site_ingress_policy_name(namespace) := sprintf("ingress-to-%s", [namespace])',
            text,
        )
        self.assertNotIn('sprintf("cloudflared-to-%s"', text)


class SiteIngressAndTokenCorpusTests(unittest.TestCase):
    """Pin every hostile connector-token and site-ingress fixture by identity."""

    REGO = ROOT / "policies/conftest/kubernetes.rego"
    FIXTURES = ROOT / "tests/kubernetes/fixtures"
    LIVE_FIXTURE = FIXTURES / "allow/live-site-ingress-policies.yaml"
    SUPERSEDED_FIXTURE = FIXTURES / "deny/ingress-policy-superseded-name.yaml"
    SITE_NAMESPACES = ("naranjo-online", "lidersea-com")
    SUPERSEDED_PREFIX = "cloudflared-to-"
    PROVIDER_TOKENS = ("cloudflare", "cloudflared", "argo", "ngrok", "tailscale")
    TOKEN_BINDING_DENY_CORPUS = {
        "connector-map-env.yaml": (
            "      env:\n        TUNNEL_TOKEN:\n",
            "              name: naranjo-online-tunnel-token",
        ),
        "env-token-unreviewed-identity.yaml": (
            "    app.kubernetes.io/instance: invented-tunnel",
            "              name: invented-tunnel-token",
        ),
        "env-token-init-container-cross-site.yaml": (
            "  initContainers:",
            "              name: lidersea-com-tunnel-token",
        ),
        "env-token-ephemeral-container-cross-site.yaml": (
            "  ephemeralContainers:",
            "              name: lidersea-com-tunnel-token",
        ),
        "env-token-wrong-key.yaml": (
            "              name: naranjo-online-tunnel-token",
            "              key: credentials.json",
        ),
        "env-token-envfrom-cross-site.yaml": (
            "      envFrom:",
            "            name: lidersea-com-tunnel-token",
        ),
        "env-token-cross-swap-naranjo.yaml": (
            "    app.kubernetes.io/instance: naranjo-online-tunnel",
            "              name: lidersea-com-tunnel-token",
        ),
        "env-token-cross-swap-lidersea.yaml": (
            "    app.kubernetes.io/instance: lidersea-com-tunnel",
            "              name: naranjo-online-tunnel-token",
        ),
        "env-token-superseded-shared.yaml": (
            "              name: pi-websites-tunnel-token",
            "              key: token",
        ),
        "env-token-optional-secret.yaml": (
            "              name: naranjo-online-tunnel-token",
            "              optional: true",
        ),
        "connector-null-env.yaml": (
            "      env: null",
            "    app.kubernetes.io/instance: naranjo-online-tunnel",
        ),
    }

    def rego_prefix(self):
        matched = re.search(
            r'site_ingress_policy_name\(namespace\) := '
            r'sprintf\("([^%"]*)%s", \[namespace\]\)',
            self.REGO.read_text(encoding="utf-8"),
        )
        self.assertIsNotNone(matched, "site-ingress name derivation disappeared")
        return matched.group(1)

    @staticmethod
    def fixture_names(path):
        return re.findall(r"(?m)^  name: (\S+)$", path.read_text(encoding="utf-8"))

    def test_the_derivation_is_actually_called_by_the_ingress_rule(self):
        text = self.REGO.read_text(encoding="utf-8")
        matched = re.search(r"(?s)valid_site_ingress_policy if \{(.*?)\n\}", text)
        self.assertIsNotNone(matched, "site-ingress rule body disappeared")
        self.assertIn(
            "input.metadata.name == site_ingress_policy_name(namespace)",
            matched.group(1),
        )

    def test_the_policy_name_is_provider_neutral_and_superseded_prefix_is_gone(self):
        prefix = self.rego_prefix()
        for token in self.PROVIDER_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token, prefix)
        active = "\n".join(
            line
            for line in self.REGO.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertNotIn(self.SUPERSEDED_PREFIX, active)

    def test_the_positive_fixture_carries_both_derived_names(self):
        prefix = self.rego_prefix()
        self.assertEqual(
            self.fixture_names(self.LIVE_FIXTURE),
            [prefix + namespace for namespace in self.SITE_NAMESPACES],
        )

    def test_the_token_binding_deny_corpus_is_complete(self):
        for name, required in self.TOKEN_BINDING_DENY_CORPUS.items():
            with self.subTest(fixture=name):
                path = self.FIXTURES / "deny" / name
                self.assertTrue(path.is_file(), name + " is the only pinned shape and is gone")
                text = path.read_text(encoding="utf-8")
                for fragment in required:
                    self.assertIn(fragment, text)

    @unittest.skipUnless(CONFTEST, "conftest is required")
    def test_each_token_binding_mutant_has_only_its_reviewed_attribution(self):
        for name in self.TOKEN_BINDING_DENY_CORPUS:
            path = self.FIXTURES / "deny" / name
            resource = re.search(r"(?m)^  name: (\S+)$", path.read_text(encoding="utf-8"))
            self.assertIsNotNone(resource, name + " lost its resource name")
            expected = (
                "Pod cloudflare-public/{} may take its Tunnel token only from "
                "the Secret derived from its own app.kubernetes.io/instance, "
                "through env.valueFrom.secretKeyRef and never through envFrom"
            ).format(resource.group(1))
            with self.subTest(fixture=name):
                self.assertEqual(conftest_denials(path), [expected])

    def test_the_superseded_name_is_still_exercised_as_a_denial(self):
        names = self.fixture_names(self.SUPERSEDED_FIXTURE)
        self.assertEqual(len(names), 1)
        self.assertTrue(names[0].startswith(self.SUPERSEDED_PREFIX))
        self.assertFalse(names[0].startswith(self.rego_prefix()))

    @unittest.skipUnless(CONFTEST, "conftest is required")
    def test_each_site_ingress_mutant_has_only_its_reviewed_attribution(self):
        for name in (
            "ingress-peer-name-only.yaml",
            "ingress-peer-wrong-instance.yaml",
            "ingress-policy-superseded-name.yaml",
        ):
            path = self.FIXTURES / "deny" / name
            resource = re.search(r"(?m)^  name: (\S+)$", path.read_text(encoding="utf-8"))
            self.assertIsNotNone(resource, name + " lost its resource name")
            expected = (
                "NetworkPolicy naranjo-online/{} widens the exact "
                "cloudflare-public TCP 8080 ingress contract"
            ).format(resource.group(1))
            with self.subTest(fixture=name):
                self.assertEqual(conftest_denials(path), [expected])


if __name__ == "__main__":
    unittest.main()
