"""Protect the disabled, bounded, and repository-external media boundary."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SITE_ROOT = REPO_ROOT / "websites" / "naranjo.online"


class MediaContractTests(unittest.TestCase):
    """Catch accidental storage activation or unbounded serving drift."""

    def test_frontend_has_one_logical_media_url_contract(self):
        helper = (SITE_ROOT / "frontend/src/lib/media.ts").read_text(encoding="utf-8")
        for fragment in (
            "export function mediaUrl",
            "/media/immutable/",
            "/media/mutable/",
            "lowercase SHA-256 digest",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, helper)
        for category in ("images", "audio", "video", "icons", "fonts", "textures"):
            self.assertTrue((SITE_ROOT / "frontend/src/assets" / category).is_dir())

    def test_go_streams_from_a_traversal_resistant_root(self):
        media = (SITE_ROOT / "internal/server/media.go").read_text(encoding="utf-8")
        for fragment in (
            "os.OpenRoot",
            "root.Lstat",
            "os.ModeSymlink",
            "os.SameFile",
            "mediaFileHasMultipleLinks",
            "http.ServeContent",
            "MaxConcurrent",
            "maxRangeHeaderBytes",
            "SetWriteDeadline",
            '"application/octet-stream"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, media)
        for forbidden in ("os.ReadFile", "io.ReadAll", "http.FileServer"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, media)

        server = (SITE_ROOT / "internal/server/server.go").read_text(encoding="utf-8")
        self.assertIn('mux.Handle("/media", http.NotFoundHandler())', server)
        self.assertIn('mux.Handle("/media/", mediaRoute)', server)

    def test_chart_cannot_render_storage_before_discovery(self):
        values = (SITE_ROOT / "chart/values.yaml").read_text(encoding="utf-8")
        schema = (SITE_ROOT / "chart/values.schema.json").read_text(encoding="utf-8")
        templates = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (SITE_ROOT / "chart/templates").glob("*.yaml")
        )
        self.assertIn("enabled: false", values)
        self.assertIn("UNRESOLVED_PI_MEDIA_STORAGE", values)
        self.assertIn('"const": false', schema)
        for forbidden in ("hostPath:", "persistentVolumeClaim:", "kind: PersistentVolume"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, templates)

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

    def test_source_and_oci_artifacts_have_independent_media_bounds(self):
        sourceignore = (REPO_ROOT / ".sourceignore").read_text(encoding="utf-8")
        verifier = (REPO_ROOT / "scripts/ci/verify-oci-artifact.sh").read_text(
            encoding="utf-8"
        )
        for fragment in (
            "/*",
            "!/kubernetes/",
            "!/policies/kyverno/",
            "!/websites/naranjo.online/chart/",
            "!/websites/lidersea.com/chart/",
        ):
            self.assertIn(fragment, sourceignore)
        self.assertIn("MAX_APPLICATION_LAYER_BYTES", verifier)
        self.assertIn("application layer exceeds the reviewed byte ceiling", verifier)

    def test_generated_frontends_remain_ignored_except_placeholders(self):
        ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for site in ("naranjo.online", "lidersea.com"):
            prefix = f"websites/{site}/internal/web/dist"
            with self.subTest(site=site):
                self.assertIn(f"{prefix}/*", ignore)
                self.assertIn(f"!{prefix}/.gitkeep", ignore)


if __name__ == "__main__":
    unittest.main()
