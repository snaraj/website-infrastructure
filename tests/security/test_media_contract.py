"""Protect the disabled, bounded, and repository-external media boundary."""

import tempfile
import unittest
from pathlib import Path

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_MODULE = load_script(
    "validate_repository.py", module_name="media_validate_repository"
)


class MediaContractTests(unittest.TestCase):
    """Catch accidental storage activation or unbounded serving drift."""

    def test_platform_release_values_never_reenable_site_media(self):
        """The media fail-closed chart contract moved to each site repository;
        the platform's HelmRelease values must not re-enable it from here."""

        releases = sorted(
            (REPO_ROOT / "kubernetes" / "websites").glob("*/release.yaml")
        )
        self.assertEqual(len(releases), 2)
        for release in releases:
            with self.subTest(release=release.name):
                text = release.read_text(encoding="utf-8")
                self.assertNotIn("media:", text)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "kubernetes" / "websites" / "naranjo-online"
            target.mkdir(parents=True)
            target.joinpath("release.yaml").write_text(
                "spec:\n"
                "  values:\n"
                "    media:\n"
                "      enabled: true\n",
                encoding="utf-8",
            )
            self.assertTrue(any(
                "platform values re-enable site media" in error
                for error in REPOSITORY_MODULE.check_media(root)
            ))

    def test_helm_releases_cannot_add_controller_side_external_inputs(self):
        for field in (
            "  valuesFrom:\n    - kind: Secret\n      name: runtime-values\n",
            "  kubeConfig:\n    secretRef:\n      name: remote-cluster\n",
            "  storageNamespace: other\n",
            "  targetNamespace: other\n",
        ):
            with self.subTest(field=field.split(":", 1)[0].strip()):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    root.joinpath(".sourceignore").write_text(
                        "/*\n"
                        "!/.sourceignore\n"
                        "!/kubernetes/\n"
                        "/kubernetes/*\n"
                        "!/kubernetes/websites/\n"
                        "/kubernetes/websites/*\n"
                        "!/kubernetes/websites/naranjo-online/\n"
                        "!/kubernetes/websites/naranjo-online/**\n"
                        "!/kubernetes/websites/lidersea-com/\n"
                        "!/kubernetes/websites/lidersea-com/**\n",
                        encoding="utf-8",
                    )
                    target = root / "kubernetes" / "websites" / "naranjo-online"
                    target.mkdir(parents=True)
                    target.joinpath("release.yaml").write_text(
                        "apiVersion: helm.toolkit.fluxcd.io/v2\n"
                        "kind: HelmRelease\n"
                        "metadata:\n"
                        "  name: naranjo-online\n"
                        "spec:\n"
                        + field,
                        encoding="utf-8",
                    )
                    self.assertTrue(any(
                        "must not use controller-side external inputs or namespace redirects"
                        in error
                        for error in REPOSITORY_MODULE.check_media(root)
                    ))

    def test_architecture_states_current_cloudflare_no_go(self):
        adr = (REPO_ROOT / "docs/adr/0012-heavy-media-storage.md").read_text(
            encoding="utf-8"
        )
        zero_spend = (REPO_ROOT / "docs/adr/0006-cloudflare-zero-spend.md").read_text(
            encoding="utf-8"
        )
        for document in (adr, zero_spend):
            self.assertIn("NO-GO", document)
            self.assertIn("service-specific-terms-application-services", document)

    def test_source_artifact_keeps_exact_media_bounds(self):
        # The OCI-image media ceiling moved to the site repositories with
        # their publishers; the platform Flux artifact bound stays here.
        sourceignore = (REPO_ROOT / ".sourceignore").read_text(encoding="utf-8")
        expected = (
            "/*",
            "!/.sourceignore",
            "!/kubernetes/",
            "/kubernetes/*",
            "!/kubernetes/websites/",
            "/kubernetes/websites/*",
            "!/kubernetes/websites/naranjo-online/",
            "!/kubernetes/websites/naranjo-online/**",
            "!/kubernetes/websites/lidersea-com/",
            "!/kubernetes/websites/lidersea-com/**",
        )
        self.assertEqual(
            tuple(
                line.strip() for line in sourceignore.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ),
            expected,
        )


if __name__ == "__main__":
    unittest.main()
