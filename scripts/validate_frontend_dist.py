#!/usr/bin/env python3
"""Validate one built website bundle without a browser or network access.

The production Go binaries embed Vite's output directly, so this check treats
the generated ``dist`` tree as a release input rather than disposable frontend
cache.  It intentionally uses only Python's standard library: pull-request CI
already provides Python, and validating a bundle must not create a second npm
dependency tree beside the application toolchain it is meant to constrain.

The command-line interface accepts only the two reviewed site identities and
derives their output directories from this repository.  Tests call
``validate_dist`` with isolated fixtures, but an operator cannot use the CLI to
bless an unrelated directory by supplying an arbitrary path.
"""

import argparse
import os
import posixpath
import re
import stat
import sys
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import NamedTuple
from urllib.parse import unquote, urlsplit


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SITE_DIST_ROOTS = {
    "lidersea.com": REPOSITORY_ROOT / "websites/lidersea.com/internal/web/dist",
    "naranjo.online": REPOSITORY_ROOT / "websites/naranjo.online/internal/web/dist",
}

# These ceilings are deliberately stated in uncompressed bytes.  Raw sizes are
# stable across platforms and tool invocations, unlike synthetic network timing
# or an edge provider's changing Brotli implementation.  Increasing a ceiling
# is possible, but requires a visible review of the new application payload.
MAX_INDEX_BYTES = 8 * 1024
MAX_JAVASCRIPT_BYTES = 128 * 1024
MAX_CSS_BYTES = 32 * 1024
MAX_OTHER_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024

JAVASCRIPT_SUFFIXES = {".js", ".mjs", ".cjs"}
SOURCE_SUFFIXES = {
    ".cts",
    ".jsx",
    ".less",
    ".mts",
    ".sass",
    ".scss",
    ".svelte",
    ".ts",
    ".tsx",
    ".vue",
}
SOURCE_MAP_MARKER = b"sourcemappingurl="
WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

# Vite's default names end in a content token such as ``-CoygYBfe.js``.  The
# Go server grants every /assets/ response a one-year immutable cache lifetime,
# so an unhashed filename in that directory would make changed bytes stale even
# if the build itself succeeded.
HASHED_ASSET_NAME = re.compile(r"-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$")

CSS_URL = re.compile(
    r"url\(\s*(?P<quote>['\"]?)(?P<value>.*?)\1\s*\)",
    flags=re.IGNORECASE,
)
CSS_QUOTED_IMPORT = re.compile(
    r"@import\s+(?!url\()(?P<quote>['\"])(?P<value>.*?)\1",
    flags=re.IGNORECASE,
)
CSS_COMMENT = re.compile(r"/\*.*?\*/", flags=re.DOTALL)

# Production Vite chunks may import sibling chunks.  These deliberately narrow
# patterns are not a JavaScript parser; they cover emitted module syntax and the
# literal browser network calls most likely to introduce an accidental origin.
# The origin CSP remains the runtime fail-closed boundary for dynamically
# constructed values that no static, dependency-free check can prove.
JS_DYNAMIC_OR_BARE_IMPORT = re.compile(
    r"\bimport\s*(?:\(\s*)?(?P<quote>['\"])(?P<value>[^'\"]+)\1",
)
JS_FROM_IMPORT = re.compile(
    r"\b(?:import|export)\b[^;\n]*?\bfrom\s*(?P<quote>['\"])(?P<value>[^'\"]+)\1",
)
JS_NEW_URL = re.compile(
    r"\bnew\s+URL\(\s*(?P<quote>['\"])(?P<value>[^'\"]+)\1\s*,\s*import\.meta\.url\s*\)",
)
JS_NETWORK_LITERAL = re.compile(
    r"(?:\bfetch|\bWebSocket|\bEventSource|navigator\.sendBeacon)\s*"
    r"\(\s*(?P<quote>['\"])(?P<value>[^'\"]+)\1",
)


class ResourceReference(NamedTuple):
    """One URL-bearing construct and whether it must name an emitted file."""

    value: str
    context: str
    require_file: bool = True


class BuiltHTMLParser(HTMLParser):
    """Collect resources that a browser would load from the generated shell.

    Navigation links are intentionally not treated as application dependencies:
    a future article may link elsewhere without making that host a script, font,
    image, or API origin.  Resource-bearing tags, inline CSS, connection hints,
    and refresh redirects remain in scope.
    """

    RESOURCE_ATTRIBUTES = {
        "audio": ("src",),
        "embed": ("src",),
        "iframe": ("src",),
        "img": ("src", "srcset"),
        "input": ("src",),
        "object": ("data",),
        "script": ("src",),
        "source": ("src", "srcset"),
        "track": ("src",),
        "video": ("src", "poster"),
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []
        self.inline_styles = []
        self.problems = []
        self._style_depth = 0

    def handle_starttag(self, tag, attrs):
        self._handle_tag(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self._handle_tag(tag, attrs)

    def handle_endtag(self, tag):
        if tag.lower() == "style" and self._style_depth:
            self._style_depth -= 1

    def handle_data(self, data):
        if self._style_depth and data.strip():
            self.inline_styles.append((data, "index.html inline <style>"))

    def _handle_tag(self, raw_tag, raw_attrs):
        tag = raw_tag.lower()
        line, _ = self.getpos()
        context = "index.html line {} <{}>".format(line, tag)
        attrs = {}
        for raw_name, value in raw_attrs:
            name = raw_name.lower()
            if name in attrs:
                # Browsers keep one duplicate attribute according to parsing
                # rules that differ from a naive dictionary conversion. Reject
                # the ambiguity so an external first value cannot be hidden by
                # a later local value during validation.
                self.problems.append(
                    "{} repeats attribute {}".format(context, name)
                )
                continue
            attrs[name] = value or ""

        if tag == "base":
            # A base element changes how every later relative URL resolves and
            # can turn apparently local markup into a remote dependency.  The
            # origin's CSP also declares base-uri 'none', so generated output
            # containing one is a build error rather than a supported feature.
            self.problems.append("{} contains a forbidden base element".format(context))

        if tag == "style":
            self._style_depth += 1

        if "style" in attrs:
            self.inline_styles.append((attrs["style"], context + " style attribute"))

        if tag == "link" and "href" in attrs:
            rels = set(attrs.get("rel", "").lower().split())
            # DNS and connection hints do not name a local file, but an external
            # value would still create a browser-visible dependency.
            require_file = not bool(rels & {"dns-prefetch", "preconnect"})
            self.references.append(
                ResourceReference(attrs["href"], context + " href", require_file)
            )
            if "imagesrcset" in attrs:
                self._append_srcset(attrs["imagesrcset"], context + " imagesrcset")

        for attribute in self.RESOURCE_ATTRIBUTES.get(tag, ()):
            if attribute not in attrs:
                continue
            value = attrs[attribute]
            if attribute == "srcset":
                self._append_srcset(value, context + " srcset")
            else:
                self.references.append(
                    ResourceReference(value, context + " " + attribute)
                )

        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"(?i)(?:^|;)\s*url\s*=\s*(.+)\s*$", attrs.get("content", ""))
            if match:
                value = match.group(1).strip().strip("'\"")
                self.references.append(
                    ResourceReference(value, context + " refresh URL", False)
                )

    def _append_srcset(self, value, context):
        # Data URLs contain commas, but all URL schemes are rejected below.  A
        # simple split therefore stays deterministic for the only accepted form:
        # local paths followed by optional width or density descriptors.
        for candidate in value.split(","):
            fields = candidate.strip().split()
            if fields:
                self.references.append(ResourceReference(fields[0], context))


def _relative_name(path, root):
    """Return one slash-normalized path for stable errors on Windows and Linux."""

    return Path(os.path.relpath(path, root)).as_posix()


def _is_link_or_reparse(file_status):
    """Reject POSIX links and Windows junction/reparse escape points alike."""

    return stat.S_ISLNK(file_status.st_mode) or bool(
        getattr(file_status, "st_file_attributes", 0) & WINDOWS_REPARSE_POINT
    )


def _is_go_embed_excluded(relative):
    """Return whether Go's normal directory walk omits a generated path."""

    return any(
        part.startswith((".", "_")) for part in PurePosixPath(relative).parts
    )


def _collect_files(dist_root, errors):
    """Collect regular files without following links or reading past budgets."""

    files = {}
    total_size = 0
    for current, directories, names in os.walk(dist_root, topdown=True, followlinks=False):
        directories.sort()
        names.sort()

        # os.walk lists a directory symlink in ``directories`` even when it will
        # not descend into it.  Removing it explicitly makes that refusal clear
        # and ensures no later platform behavior can change the boundary.
        for directory in list(directories):
            candidate = Path(current, directory)
            try:
                file_status = os.lstat(candidate)
            except OSError as exc:
                errors.append(
                    "cannot inspect generated directory {}: {}".format(
                        _relative_name(candidate, dist_root), exc
                    )
                )
                directories.remove(directory)
                continue
            if _is_link_or_reparse(file_status):
                errors.append(
                    "generated tree contains link/reparse directory: "
                    + _relative_name(candidate, dist_root)
                )
                directories.remove(directory)
                continue
            relative = _relative_name(candidate, dist_root)
            if _is_go_embed_excluded(relative):
                errors.append(
                    "Go embed excludes dot/underscore generated path: " + relative
                )
                directories.remove(directory)

        for name in names:
            candidate = Path(current, name)
            relative = _relative_name(candidate, dist_root)
            try:
                file_status = os.lstat(candidate)
            except OSError as exc:
                errors.append("cannot inspect generated file {}: {}".format(relative, exc))
                continue
            if _is_link_or_reparse(file_status):
                errors.append("generated tree contains link/reparse file: " + relative)
                continue
            if not stat.S_ISREG(file_status.st_mode):
                errors.append("generated tree contains non-regular file: " + relative)
                continue
            # The tracked placeholder is deliberately not a browser artifact
            # and Go's embed walk omits it. Every other emitted file must be
            # reachable through the same walk the production binary uses.
            if relative == ".gitkeep":
                continue
            if _is_go_embed_excluded(relative):
                errors.append(
                    "Go embed excludes dot/underscore generated path: " + relative
                )
                continue

            size = file_status.st_size
            total_before_file = total_size
            total_size += size
            ceiling, label = _size_budget(relative)
            if size > ceiling:
                errors.append(
                    "{} {} exceeds {} bytes: {}".format(
                        label, relative, ceiling, size
                    )
                )

            # The total and per-file limits are also read limits. Even a broken
            # or adversarial build cannot make this validator allocate an
            # unbounded file before discovering that the artifact is invalid.
            remaining_total = max(0, MAX_TOTAL_BYTES - total_before_file)
            read_limit = min(ceiling, remaining_total)
            if size > read_limit:
                continue
            try:
                with candidate.open("rb") as source:
                    data = source.read(read_limit + 1)
            except OSError as exc:
                errors.append("cannot read generated file {}: {}".format(relative, exc))
                continue
            if len(data) != size:
                errors.append(
                    "generated file changed while being validated: " + relative
                )
                continue
            files[relative] = data

    if total_size > MAX_TOTAL_BYTES:
        errors.append(
            "generated frontend exceeds {} total bytes: {}".format(
                MAX_TOTAL_BYTES, total_size
            )
        )
    return files


def _size_budget(relative):
    """Return the reviewed per-file ceiling for one generated path."""

    if relative == "index.html":
        return MAX_INDEX_BYTES, "index.html"
    suffix = PurePosixPath(relative).suffix.lower()
    if suffix in JAVASCRIPT_SUFFIXES:
        return MAX_JAVASCRIPT_BYTES, "JavaScript file"
    if suffix == ".css":
        return MAX_CSS_BYTES, "CSS file"
    return MAX_OTHER_FILE_BYTES, "generated file"


def _asset_name_is_hashed(relative):
    """Return whether an immutable /assets/ file carries a Vite content token."""

    path = PurePosixPath(relative)
    return path.parts and path.parts[0] == "assets" and bool(
        HASHED_ASSET_NAME.search(path.name)
    )


def _resolve_local_reference(raw_value, base_directory, files, context, require_file, errors):
    """Validate and resolve one browser reference inside the generated tree."""

    value = raw_value.strip()
    if not value:
        errors.append("{} contains an empty resource URL".format(context))
        return
    if value.startswith("#"):
        # A same-document fragment neither fetches a resource nor changes origin.
        return
    if "\\" in value or "\x00" in value:
        errors.append("{} contains a non-canonical resource URL: {}".format(context, value))
        return

    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value.startswith("//"):
        errors.append("{} contains an external resource URL: {}".format(context, value))
        return
    if parsed.query:
        # Vite content hashes already express cache identity in the filename.
        # Query aliases would let the same bytes acquire multiple public URLs.
        errors.append("{} contains a query-bearing resource URL: {}".format(context, value))
        return

    decoded_path = unquote(parsed.path)
    if "\\" in decoded_path or "\x00" in decoded_path or "//" in decoded_path:
        errors.append("{} contains a non-canonical resource URL: {}".format(context, value))
        return
    if not decoded_path:
        errors.append("{} does not identify a generated resource: {}".format(context, value))
        return

    if decoded_path.startswith("/"):
        candidate = PurePosixPath(decoded_path.lstrip("/"))
    else:
        candidate = PurePosixPath(base_directory, decoded_path)

    if not candidate.parts or any(part in {"", ".", ".."} for part in candidate.parts):
        errors.append("{} escapes or ambiguously names the generated tree: {}".format(context, value))
        return
    normalized = posixpath.normpath(candidate.as_posix())
    if normalized.startswith("../") or normalized == ".." or normalized.startswith("/"):
        errors.append("{} escapes the generated tree: {}".format(context, value))
        return
    if require_file:
        if normalized not in files:
            errors.append(
                "{} references missing generated file: {}".format(context, normalized)
            )
        elif not _asset_name_is_hashed(normalized):
            # Browser-loaded resources must use the same content identity that
            # earns /assets/ its immutable cache lifetime. Unreferenced root
            # protocol files may still exist and are served with no-store.
            errors.append(
                "{} references a resource without an immutable content hash: {}".format(
                    context, normalized
                )
            )


def _css_references(text):
    """Yield local-or-external URLs from CSS after removing inert comments."""

    uncommented = CSS_COMMENT.sub("", text)
    for match in CSS_URL.finditer(uncommented):
        yield match.group("value").strip()
    for match in CSS_QUOTED_IMPORT.finditer(uncommented):
        yield match.group("value").strip()


def _validate_css(text, relative, files, errors):
    base = PurePosixPath(relative).parent
    for index, value in enumerate(_css_references(text), start=1):
        _resolve_local_reference(
            value,
            base,
            files,
            "{} CSS resource {}".format(relative, index),
            True,
            errors,
        )


def _validate_javascript(text, relative, files, errors):
    """Check emitted module edges and literal browser-network destinations."""

    base = PurePosixPath(relative).parent
    seen = set()
    for pattern in (JS_DYNAMIC_OR_BARE_IMPORT, JS_FROM_IMPORT, JS_NEW_URL):
        for match in pattern.finditer(text):
            value = match.group("value")
            key = (match.start(), value)
            if key in seen:
                continue
            seen.add(key)
            _resolve_local_reference(
                value,
                base,
                files,
                "{} JavaScript module reference".format(relative),
                True,
                errors,
            )

    for match in JS_NETWORK_LITERAL.finditer(text):
        value = match.group("value")
        parsed = urlsplit(value.strip())
        if parsed.scheme or parsed.netloc or value.startswith("//"):
            errors.append(
                "{} contains an external resource URL in a browser network call: {}".format(
                    relative, value
                )
            )


def validate_dist(dist_root):
    """Return deterministic policy errors for one generated frontend directory."""

    root = Path(dist_root)
    errors = []
    try:
        root_status = os.lstat(root)
    except FileNotFoundError:
        return ["generated dist root does not exist"]
    except OSError as exc:
        return ["cannot inspect generated dist root: {}".format(exc)]
    if _is_link_or_reparse(root_status):
        return ["generated dist root must not be a link/reparse point"]
    if not stat.S_ISDIR(root_status.st_mode):
        return ["generated dist root is not a directory"]

    files = _collect_files(root, errors)
    if "index.html" not in files:
        errors.append("generated dist is missing regular index.html")

    for relative, data in sorted(files.items()):
        path = PurePosixPath(relative)
        suffixes = {suffix.lower() for suffix in path.suffixes}
        if ".map" in suffixes:
            errors.append("source map output is forbidden: " + relative)
        if suffixes & SOURCE_SUFFIXES:
            errors.append("frontend source output is forbidden: " + relative)
        if SOURCE_MAP_MARKER in data.lower():
            errors.append("sourceMappingURL marker is forbidden: " + relative)

        if path.parts and path.parts[0] == "assets" and not _asset_name_is_hashed(relative):
            errors.append("immutable asset lacks a Vite content hash: " + relative)

    index = files.get("index.html")
    if index is not None:
        try:
            index_text = index.decode("utf-8")
        except UnicodeDecodeError:
            errors.append("generated index.html is not UTF-8")
        else:
            parser = BuiltHTMLParser()
            try:
                parser.feed(index_text)
                parser.close()
            except Exception as exc:  # HTMLParser errors are still policy errors.
                errors.append("cannot parse generated index.html: {}".format(exc))
            else:
                errors.extend(parser.problems)
                for reference in parser.references:
                    _resolve_local_reference(
                        reference.value,
                        PurePosixPath("."),
                        files,
                        reference.context,
                        reference.require_file,
                        errors,
                    )
                for style, context in parser.inline_styles:
                    for value in _css_references(style):
                        _resolve_local_reference(
                            value,
                            PurePosixPath("."),
                            files,
                            context,
                            True,
                            errors,
                        )

    for relative, data in sorted(files.items()):
        suffix = PurePosixPath(relative).suffix.lower()
        if suffix != ".css" and suffix not in JAVASCRIPT_SUFFIXES:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append("generated text asset is not UTF-8: " + relative)
            continue
        if suffix == ".css":
            _validate_css(text, relative, files, errors)
        else:
            _validate_javascript(text, relative, files, errors)

    # A set avoids reporting the same malformed import through two deliberately
    # overlapping JavaScript patterns while sorting makes CI output reproducible.
    return sorted(set(errors))


def main(argv=None):
    """Run the repository-rooted validator for one explicit website identity."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--site",
        choices=sorted(SITE_DIST_ROOTS),
        required=True,
        help="reviewed website identity whose generated dist tree will be checked",
    )
    args = parser.parse_args(argv)

    errors = validate_dist(SITE_DIST_ROOTS[args.site])
    if errors:
        for error in errors:
            print("frontend-dist: FAIL {}: {}".format(args.site, error), file=sys.stderr)
        return 1
    print("frontend-dist: PASS " + args.site)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
