"""Protect lidersea.com's canonical application and fail-closed chart identity."""

import json
import unittest
from pathlib import Path


# Resolve public source paths without encoding any local workspace identity.
REPO_ROOT = Path(__file__).resolve().parents[2]
# The canonical source directory is part of lidersea.com's release identity.
SITE_ROOT = REPO_ROOT / "websites" / "lidersea.com"
# The zero digest is a deliberate, syntactically valid but non-runnable
# promotion sentinel shared by values and policy assertions.
ZERO_DIGEST = "sha256:" + ("0" * 64)


class LiderseaSiteContractTests(unittest.TestCase):
    """Catch identity, exposure, and launch-sentinel drift before rendering."""

    def test_raw_fallback_contains_both_launch_messages(self):
        """A browser without JavaScript must still receive the promised copy."""

        index = (SITE_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("data-static-fallback", index)
        self.assertIn("Hello World!", index)
        self.assertIn("Website coming soon!", index)

    def test_application_identity_is_exact(self):
        """Module, package, image, and chart names must describe one release."""

        go_mod = (SITE_ROOT / "go.mod").read_text(encoding="utf-8")
        package = json.loads(
            (SITE_ROOT / "frontend" / "package.json").read_text(encoding="utf-8")
        )
        chart = (SITE_ROOT / "chart" / "Chart.yaml").read_text(encoding="utf-8")
        values = (SITE_ROOT / "chart" / "values.yaml").read_text(encoding="utf-8")
        self.assertIn(
            "module github.com/snaraj/website-infrastructure/websites/lidersea.com",
            go_mod,
        )
        self.assertEqual(package["name"], "lidersea-com-frontend")
        self.assertIn("name: lidersea-com", chart)
        self.assertIn("repository: ghcr.io/snaraj/lidersea-com", values)

    def test_chart_stays_fail_closed_before_promotion(self):
        """No valid-looking placeholder may turn the unreviewed release ready."""

        values = (SITE_ROOT / "chart" / "values.yaml").read_text(encoding="utf-8")
        deployment = (
            SITE_ROOT / "chart" / "templates" / "deployment.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("deploymentReady: false", values)
        self.assertIn(f"digest: {ZERO_DIGEST}", values)
        self.assertIn("@{{ .Values.image.digest }}", deployment)
        self.assertNotIn(":latest", deployment)

    def test_chart_has_private_service_and_exact_network_flow(self):
        """Only the public connector may enter on 8080; the site gets no egress."""

        service = (SITE_ROOT / "chart" / "templates" / "service.yaml").read_text(
            encoding="utf-8"
        )
        policy = (
            SITE_ROOT / "chart" / "templates" / "network-policy.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("type: ClusterIP", service)
        for forbidden in ("NodePort", "LoadBalancer", "externalIPs", "hostPort"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, service + policy)
        for required in (
            "kubernetes.io/metadata.name: cloudflare-public",
            "app.kubernetes.io/name: cloudflare-public",
            "port: {{ .Values.service.port }}",
            "- Egress",
            "egress: []",
        ):
            with self.subTest(required=required):
                self.assertIn(required, policy)


if __name__ == "__main__":
    unittest.main()
