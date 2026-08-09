#!/usr/bin/env python3
"""Focused allow/deny tests for the generated frontend artifact boundary."""

import contextlib
import importlib.util
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_frontend_dist.py"
SPEC = importlib.util.spec_from_file_location("validate_frontend_dist", str(SCRIPT))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


VALID_INDEX = """<!doctype html>
<html lang="en">
  <head>
    <link rel="stylesheet" href="/assets/site-abc12345.css">
  </head>
  <body>
    <a href="https://example.invalid/documentation">ordinary links are not resources</a>
    <script type="module" src="/assets/site-def67890.js"></script>
  </body>
</html>
"""


class FrontendDistValidatorTests(unittest.TestCase):
    """Build tiny fixtures that exercise policy without invoking Vite or a browser."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.dist = Path(self.temporary.name) / "dist"
        self._write_valid_dist(self.dist)

    def tearDown(self):
        self.temporary.cleanup()

    def _write(self, relative, content, root=None):
        destination = (root or self.dist) / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            destination.write_text(content, encoding="utf-8")
        else:
            destination.write_bytes(content)
        return destination

    def _write_valid_dist(self, root):
        self._write("index.html", VALID_INDEX, root)
        self._write(
            "assets/site-abc12345.css",
            "body { background-image: url('./pixel-aaaabbbb.svg'); }\n",
            root,
        )
        self._write(
            "assets/site-def67890.js",
            "import './chunk-ccccdddd.js';\nconsole.log('ready');\n",
            root,
        )
        self._write("assets/chunk-ccccdddd.js", "export const ready = true;\n", root)
        self._write("assets/pixel-aaaabbbb.svg", "<svg xmlns='http://www.w3.org/2000/svg'/>\n", root)
        self._write(".gitkeep", "generated placeholder\n", root)

    def assert_rejected(self, fragment, root=None):
        errors = MODULE.validate_dist(root or self.dist)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_accepts_one_local_hashed_bundle(self):
        """Local resources, module chunks, CSS assets, and content links are valid."""

        self.assertEqual(MODULE.validate_dist(self.dist), [])

    def test_cli_sites_are_exact_repository_rooted_choices(self):
        """The operational command cannot validate an arbitrary filesystem tree."""

        self.assertEqual(
            set(MODULE.SITE_DIST_ROOTS),
            {"naranjo.online", "lidersea.com"},
        )
        for site, path in MODULE.SITE_DIST_ROOTS.items():
            with self.subTest(site=site):
                self.assertEqual(
                    path,
                    ROOT / "websites" / site / "internal" / "web" / "dist",
                )
        # argparse correctly writes rejected choices to stderr; capture it so a
        # passing negative test does not resemble a CI failure in the log.
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as rejected:
                MODULE.main(["--site", "unreviewed.example"])
        self.assertEqual(rejected.exception.code, 2)

    def test_rejects_symlink_files_and_directories(self):
        """An embedded build must not acquire bytes through another filesystem root."""

        outside = Path(self.temporary.name) / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        try:
            os.symlink(outside, self.dist / "assets" / "linked-eeeeffff.txt")
            os.symlink(
                Path(self.temporary.name),
                self.dist / "assets" / "linked-dir-eeeeffff",
                target_is_directory=True,
            )
        except (NotImplementedError, OSError) as exc:
            self.skipTest("filesystem cannot create test symlinks: {}".format(exc))
        errors = MODULE.validate_dist(self.dist)
        self.assertTrue(any("link/reparse file" in error for error in errors), errors)
        self.assertTrue(any("link/reparse directory" in error for error in errors), errors)

    def test_recognizes_windows_reparse_points_without_following_them(self):
        """A junction is an escape boundary even when is_symlink reports false."""

        fake_status = type(
            "FakeStatus",
            (),
            {
                "st_mode": stat.S_IFDIR,
                "st_file_attributes": MODULE.WINDOWS_REPARSE_POINT,
            },
        )()
        self.assertTrue(MODULE._is_link_or_reparse(fake_status))

    def test_rejects_source_maps_sources_and_source_map_markers(self):
        """Vite configuration drift must not publish checkout or debugging material."""

        cases = {
            "source map": ("assets/site-eeeeffff.js.map", "{}\n", "source map output"),
            "TypeScript source": (
                "assets/source-eeeeffff.ts",
                "export const value: number = 1;\n",
                "frontend source output",
            ),
            "mapping marker": (
                "assets/site-def67890.js",
                "console.log('ready');\n//# sourceMappingURL=site.js.map\n",
                "sourceMappingURL marker",
            ),
        }
        for name, (relative, content, fragment) in cases.items():
            with self.subTest(name=name):
                case_root = Path(self.temporary.name) / ("case-" + name.replace(" ", "-"))
                self._write_valid_dist(case_root)
                self._write(relative, content, case_root)
                self.assert_rejected(fragment, case_root)

    def test_rejects_external_html_css_and_javascript_resources(self):
        """Executable resources may not silently add a CDN or telemetry origin."""

        cases = {
            "HTML script": (
                "index.html",
                VALID_INDEX.replace(
                    "/assets/site-def67890.js",
                    "https://cdn.example.invalid/site.js",
                ),
            ),
            "CSS import": (
                "assets/site-abc12345.css",
                "@import 'https://fonts.example.invalid/site.css';\n",
            ),
            "JavaScript fetch": (
                "assets/site-def67890.js",
                "fetch('https://telemetry.example.invalid/event');\n",
            ),
        }
        for name, (relative, content) in cases.items():
            with self.subTest(name=name):
                case_root = Path(self.temporary.name) / ("external-" + name.replace(" ", "-"))
                self._write_valid_dist(case_root)
                self._write(relative, content, case_root)
                self.assert_rejected("external resource URL", case_root)

    def test_rejects_duplicate_html_attributes(self):
        """A later local attribute cannot conceal the first browser-parsed value."""

        duplicate = VALID_INDEX.replace(
            'src="/assets/site-def67890.js"',
            'src="/assets/site-def67890.js" src="https://cdn.example.invalid/site.js"',
        )
        self._write("index.html", duplicate)
        self.assert_rejected("repeats attribute src")

    def test_rejects_unhashed_immutable_asset(self):
        """The Go server's one-year cache policy requires a filename identity."""

        self._write("assets/application.js", "console.log('unhashed');\n")
        self.assert_rejected("immutable asset lacks a Vite content hash")

    def test_rejects_browser_resource_outside_hashed_assets(self):
        """A loaded root file must not bypass the immutable cache identity."""

        self._write("logo.svg", "<svg xmlns='http://www.w3.org/2000/svg'/>\n")
        self._write(
            "index.html",
            VALID_INDEX.replace(
                "<body>",
                '<body><img src="/logo.svg" alt="fixture">',
            ),
        )
        self.assert_rejected("without an immutable content hash")

    def test_rejects_transitive_asset_that_go_embed_omits(self):
        """A hashed CSS child must still be reachable in the production binary."""

        self._write(
            "assets/site-abc12345.css",
            "body { background-image: url('./_pixel-aaaabbbb.svg'); }\n",
        )
        self._write(
            "assets/_pixel-aaaabbbb.svg",
            "<svg xmlns='http://www.w3.org/2000/svg'/>\n",
        )
        self.assert_rejected("Go embed excludes dot/underscore generated path")

    def test_rejects_missing_html_css_and_module_references(self):
        """Every static edge in the built graph must resolve inside the same artifact."""

        cases = {
            "HTML": (
                "index.html",
                VALID_INDEX.replace(
                    "/assets/site-def67890.js",
                    "/assets/missing-eeeeffff.js",
                ),
            ),
            "CSS": (
                "assets/site-abc12345.css",
                "body { background: url('./missing-eeeeffff.svg'); }\n",
            ),
            "JavaScript": (
                "assets/site-def67890.js",
                "import './missing-eeeeffff.js';\n",
            ),
        }
        for name, (relative, content) in cases.items():
            with self.subTest(kind=name):
                case_root = Path(self.temporary.name) / ("missing-" + name.lower())
                self._write_valid_dist(case_root)
                self._write(relative, content, case_root)
                self.assert_rejected("references missing generated file", case_root)

    def test_rejects_each_per_file_budget(self):
        """Each artifact class has an explicit ceiling independent of the total."""

        cases = {
            "index.html": (
                "index.html",
                b"x" * (MODULE.MAX_INDEX_BYTES + 1),
                "index.html index.html exceeds",
            ),
            "JavaScript": (
                "assets/large-eeeeffff.js",
                b"x" * (MODULE.MAX_JAVASCRIPT_BYTES + 1),
                "JavaScript file",
            ),
            "CSS": (
                "assets/large-eeeeffff.css",
                b"x" * (MODULE.MAX_CSS_BYTES + 1),
                "CSS file",
            ),
            "other": (
                "assets/large-eeeeffff.bin",
                b"x" * (MODULE.MAX_OTHER_FILE_BYTES + 1),
                "generated file",
            ),
        }
        for name, (relative, content, fragment) in cases.items():
            with self.subTest(kind=name):
                case_root = Path(self.temporary.name) / ("budget-" + name.lower())
                self._write_valid_dist(case_root)
                self._write(relative, content, case_root)
                self.assert_rejected(fragment, case_root)

    def test_rejects_aggregate_budget_without_relying_on_one_large_file(self):
        """Many individually valid chunks cannot bypass the complete bundle ceiling."""

        # Six 90 KiB chunks stay below the JavaScript ceiling but exceed the
        # 512 KiB total once the ordinary index, CSS, and existing chunks join.
        for index in range(6):
            self._write(
                "assets/extra{}-{:08x}.js".format(index, index + 1),
                b"x" * (90 * 1024),
            )
        self.assert_rejected("generated frontend exceeds")

    def test_rejects_missing_entrypoint(self):
        """A placeholder-only checkout is not a production browser application."""

        (self.dist / "index.html").unlink()
        self.assert_rejected("missing regular index.html")


if __name__ == "__main__":
    unittest.main()
