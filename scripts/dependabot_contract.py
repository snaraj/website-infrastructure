#!/usr/bin/env python3
"""Fail-closed structural contract for ``.github/dependabot.yml`` (issue #131).

No other gate reads ``dependabot.yml``: ``check_workflows`` in
``validate_repository.py`` globs ``.github/workflows/*.yml`` only, and
``actionlint`` does not know the Dependabot config schema, so a corrupted
``groups`` stanza survives every other check. This module closes that gap and
shares its design with the sibling site repositories -- same enums, same
two-space block-YAML subset, same 0/2 exit contract -- while wiring into this
repository's own umbrella; see "Wiring" below.

This is not a general YAML parser. It accepts only the small,
indentation-based block subset every real ``dependabot.yml`` in this
repository family actually uses -- two-space nesting, block mappings,
block sequences, plain and single/double-quoted scalars -- and fails
closed on everything outside that subset: tabs, flow collections
(``[...]``/``{...}``), duplicate keys, anchors (``&name``), aliases
(``*name``), tags (``!tag``), block scalars, document markers, and
inline trailing comments. Every scalar is checked for a leading
``&``/``*``/``!`` before anything else, so an alias or anchor is refused
outright rather than silently accepted as its own literal text (an
unresolved ``*name`` has no defined meaning without the anchor it would
reference, and this parser does not track anchors at all). Only
full-line ``#`` comments are accepted: this repository's real file
carries a six-line rationale comment for omitting the ``terraform``
ecosystem, interior to the top-level mapping between ``version: 2`` and
``updates:`` (lines 2-7, not a leading block before the document
starts) -- rejecting all comments outright, as the sibling repositories'
gate does, would fail that real file.

Two-phase design: ``parse_document`` reads the restricted grammar into
plain ``dict``/``list``/``str`` nodes, raising ``DependabotContractError``
with a line number on anything unparseable; ``contract_errors`` then
walks that structure against the schema below and returns every
violation found (not just the first), matching this repository's other
multi-error validators (``validate_repository.py``'s ``check_*``
functions, ``validate_pi_network.py``'s ``failures`` list) rather than
stopping at the first problem.

Deliberate narrowings versus Dependabot's real schema (each is a
conscious, reviewed scope decision, not an oversight):

- ``schedule.interval`` accepts only ``daily``/``weekly``/``monthly``.
  Dependabot's real enum also allows ``quarterly``, ``semiannually``,
  ``yearly``, and cron strings; every ``updates:`` entry across all three
  repositories uses ``weekly`` today, so the wider forms are out of scope
  until a real need arrives.
- ``groups.<name>`` accepts only ``patterns``, ``exclude-patterns``,
  ``dependency-type``, ``update-types``, ``applies-to``. Dependabot also
  supports ``group-by`` for cross-directory monorepo grouping; no
  ``updates:`` entry here groups across directories, so it is treated as
  an unknown key pending a deliberate widening.
- The ``updates[]`` key set is exactly ``package-ecosystem``,
  ``directory``, ``schedule``, ``open-pull-requests-limit``, ``groups``
  -- what this repository family's real files actually use.
  Dependabot's full schema also has ``ignore``, ``labels``,
  ``reviewers``, and others; an unrecognized key is refused rather than
  passed through unvalidated, so adopting one is a deliberate edit here,
  not a silent pass-through.

Wiring: this module deliberately does NOT follow the ``validate_*.py``
naming convention. ``tests/security/test_validator_invocation_parity.py``
enrolls any ``scripts/validate_*.py`` name it finds in
``validate-security.sh`` or ``.github/workflows/pull-request.yml`` into a
strict local/CI symmetry check; naming this file with that prefix would
pull it into that machinery for no benefit, since it is invoked
exclusively through ``validate_repository.py``'s own ``CHECKS`` registry
(the ``"dependabot"`` entry) -- the same "imported, not separately
CLI-wired" pattern ``validate_image_release.py`` and
``validate_release_state.py`` already use for their ``check_workflows``/
``check_kubernetes`` helper functions. That registry already runs inside
``make check-fast`` (``validate_repository.py all``) and the pull-request
workflow's existing inline ``validate_repository.py all`` step, so no
new CI step or ``validate-security.sh`` file reference was needed for the
schema check itself; ``validate-security.sh`` still gained one word
(``dependabot`` appended to its explicit check-name list) so the local
credential-free entry point keeps running everything ``all`` runs --
mirroring the exact class of drift its own comment already warns about
(commit 3ad45c6, which had to retrofit the ``media``/``activation``
modes after the short entry point silently ran less than CI).

CLI (also supported directly, for a fast local check outside the
registry):

    python3 -B scripts/dependabot_contract.py .github/dependabot.yml

Exit 0 when the file satisfies the contract; exit 2 (never 1, which
argparse's own usage errors already claim) with one ``FAIL`` line per
violation on stderr otherwise.
"""

import argparse
import re
import sys
from pathlib import Path


class DependabotContractError(ValueError):
    """The document is outside the supported dependabot.yml contract subset."""


# Mirrors GitHub's documented `package-ecosystem` enum -- the exact string
# each `updates[].package-ecosystem` value must be, which is NOT always the
# same as the ecosystem's display name. Ground truth per naranjo.online
# issue #84's adversarial review: github/docs' own source table
# (`data/reusables/dependabot/supported-package-managers.md`) maps
# Hex/Elixir to the YAML value `mix` -- "Hex" is Elixir's package host and
# the display name in GitHub's docs table, never a `package-ecosystem`
# value -- and the community-maintained schemastore.org/dependabot-2.0.json
# JSON Schema's enum carries `mix` and not `hex` either. An earlier revision
# of this set carried both as a deliberate "union of two sources that
# disagreed" hedge; that hedge itself admitted one undocumented value (a
# fail-open sliver in an allowlist whose entire job is precision), and the
# sibling gates in naranjo.online (#59) and lidersea.com (#56) are mix-only,
# so this repository converges with them: `hex` is not a valid
# `package-ecosystem` value and is refused like any other typo. Keep
# sorted; revalidate against upstream docs before adding an entry -- this
# allowlist, not actionlint, is now this repository's only defense against
# a typo'd ecosystem silently never running.
KNOWN_ECOSYSTEMS = frozenset(
    {
        "bazel",
        "bun",
        "bundler",
        "cargo",
        "composer",
        "conda",
        "deno",
        "devcontainers",
        "docker",
        "docker-compose",
        "dotnet-sdk",
        "elm",
        "github-actions",
        "gitsubmodule",
        "gomod",
        "gradle",
        "helm",
        "julia",
        "maven",
        "mix",
        "nix",
        "npm",
        "nuget",
        "opentofu",
        "pip",
        "pre-commit",
        "pub",
        "rust-toolchain",
        "sbt",
        "swift",
        "terraform",
        "uv",
        "vcpkg",
    }
)

TOP_LEVEL_KEYS = frozenset({"version", "updates"})
ENTRY_KEYS = frozenset(
    {"package-ecosystem", "directory", "schedule", "open-pull-requests-limit", "groups"}
)
REQUIRED_ENTRY_KEYS = frozenset({"package-ecosystem", "directory", "schedule"})
SCHEDULE_KEYS = frozenset({"interval", "day", "time", "timezone"})
ALLOWED_INTERVALS = frozenset({"daily", "weekly", "monthly"})
ALLOWED_WEEKDAYS = frozenset(
    {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
)
TIME_RE = re.compile(r"([01][0-9]|2[0-3]):[0-5][0-9]\Z")
TIMEZONE_RE = re.compile(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*\Z")

# A deliberate narrowing of Dependabot's real `groups.<name>` schema (see the
# module docstring): `group-by` is out of scope until a reviewed need for
# cross-directory grouping arrives, so it is rejected as unknown like any
# other typo.
GROUP_KEYS = frozenset(
    {"patterns", "exclude-patterns", "dependency-type", "update-types", "applies-to"}
)
DEPENDENCY_TYPES = frozenset({"development", "production"})
UPDATE_TYPES = frozenset({"major", "minor", "patch"})
APPLIES_TO = frozenset({"version-updates", "security-updates"})


# --- Lexical grammar ---------------------------------------------------
#
# Every scalar in the accepted subset is one YAML "word" -- letters,
# digits, and a small punctuation set that covers every value this
# schema needs (ecosystem names, absolute directories, cron-free
# intervals, HH:MM times, IANA-shaped timezones) -- or a single/double
# quoted string with no embedded quote or backslash (glob patterns like
# "github/codeql-action*"). Deliberately no unquoted multi-word plain
# scalars: nothing in this schema needs one, and supporting them would
# reopen exactly the ambiguity (where does the value end?) this module
# exists to close.
_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")
_MAPPING_START_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]*:(?:[ ]|\Z)")
_PLAIN_SCALAR_RE = re.compile(r"[A-Za-z0-9_./:*+-]+\Z")
_DQUOTE_RE = re.compile(r'"[^"\\]*"\Z')
_SQUOTE_RE = re.compile(r"'[^']*'\Z")
_DOC_MARKER_RE = re.compile(r"(?:---|\.\.\.)[ ]*\Z")

# The deepest real structure any of the three repositories' dependabot.yml
# files need is six levels (updates[] -> entry -> groups -> group-name ->
# patterns -> list item); 20 is generous headroom for a legitimate future
# variant while stopping a maliciously or accidentally deep document (a
# "recursion bomb" of thousands of nested mapping keys) with a clean,
# deterministic DependabotContractError long before Python's own recursion
# limit is anywhere close -- this recursive-descent parser adds roughly two
# stack frames per nesting level, so the default ~1000-frame limit would
# otherwise only be reached, uncontrolled, past roughly 400-500 levels.
_MAX_NESTING_DEPTH = 20


def _tokenize(text):
    """Reduce raw text to ``(line_no, indent, content)`` structural lines.

    Blank lines and full-line ``#`` comments are dropped entirely (they
    carry no structure). A ``- `` sequence marker with an inline mapping
    key (``- package-ecosystem: github-actions``, the shape every real
    ``updates[]`` entry in this repository family uses) is split into a
    synthetic dash-only entry followed by its inline remainder re-based
    two columns deeper, so the recursive parser below has exactly one
    shape to handle for "what is nested under a sequence item" regardless
    of whether the first key rode in on the dash's own line.
    """

    entries = []
    for line_no, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line.rstrip(" ")
        if line.strip(" ") == "":
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line[indent:]
        if content.startswith("#"):
            continue
        if _DOC_MARKER_RE.match(content):
            raise DependabotContractError(
                "line {}: document markers ('---'/'...') are not supported".format(line_no)
            )
        if content == "-":
            entries.append((line_no, indent, "-"))
            continue
        if content.startswith("- "):
            entries.append((line_no, indent, "-"))
            remainder = content[2:]
            if remainder.strip(" ") == "":
                raise DependabotContractError(
                    "line {}: sequence item has no content after '-'".format(line_no)
                )
            entries.append((line_no, indent + 2, remainder))
            continue
        entries.append((line_no, indent, content))
    return entries


def _parse_scalar(value_text, line_no):
    if value_text.startswith("{") or value_text.startswith("["):
        raise DependabotContractError(
            "line {}: flow-style collections ('{{...}}'/'[...]') are not supported".format(line_no)
        )
    # An unquoted `*name` (alias) was previously indistinguishable from
    # plain text: `_PLAIN_SCALAR_RE` admits `*` anywhere, including as the
    # leading character, so an alias reference like `*anchor` parsed as the
    # literal string "*anchor" -- a false PASS on unparseable YAML, since
    # this module never defines or resolves anchors and an alias without
    # one is meaningless. `&name` (anchor) and `!tag` (tag) already failed
    # for an incidental reason (their characters sit outside every scalar
    # regex below), which this makes an explicit, deliberate rejection
    # instead. Checked before the quoted/plain branches so a quoted
    # `"*anchor"` (a genuine, harmless literal string) is unaffected --
    # only an *unquoted* leading `&`/`*`/`!` is refused.
    if value_text[:1] in ("*", "&", "!"):
        kind = {"*": "alias ('*name')", "&": "anchor ('&name')", "!": "tag ('!tag')"}[value_text[0]]
        raise DependabotContractError(
            "line {}: YAML {} is not supported".format(line_no, kind)
        )
    if _DQUOTE_RE.fullmatch(value_text):
        return value_text[1:-1]
    if _SQUOTE_RE.fullmatch(value_text):
        return value_text[1:-1]
    if _PLAIN_SCALAR_RE.fullmatch(value_text):
        return value_text
    raise DependabotContractError("line {}: unsupported scalar {!r}".format(line_no, value_text))


def _split_mapping_entry(content, line_no):
    """Split ``key:`` or ``key: value`` on the first colon.

    A value's own colon (``time: 04:00``) is never re-examined: only the
    first colon in ``content`` is treated as the key/value separator,
    matching real YAML and this repository's existing
    ``validate_release_state.py`` mapping-entry convention.
    """

    key, _, suffix = content.partition(":")
    if not _KEY_RE.fullmatch(key):
        raise DependabotContractError("line {}: unsupported mapping key {!r}".format(line_no, key))
    if suffix == "":
        return key, None
    if not suffix.startswith(" ") or suffix[1:] != suffix[1:].strip(" "):
        raise DependabotContractError(
            "line {}: expected exactly one space after '{}:'".format(line_no, key)
        )
    return key, suffix[1:]


def _is_mapping_entry(content):
    return bool(_MAPPING_START_RE.match(content))


def _parse_node(entries, pos, indent, depth):
    """Parse whichever node sits at exactly ``indent`` starting at ``pos``.

    The caller always verifies ``entries[pos]`` is present at exactly
    this indent before recursing (either it is the document's first
    line, or a parent's own child-indent check already confirmed it), so
    the three-way dispatch below never needs to re-derive indentation.

    ``depth`` counts nesting levels from the document root (0); it is
    checked here, the one entry point every recursive descent into a
    child block passes through, so neither a deeply nested mapping nor a
    deeply nested sequence can bypass the cap.
    """

    if depth > _MAX_NESTING_DEPTH:
        raise DependabotContractError(
            "line {}: nesting exceeds the maximum supported depth ({})"
            .format(entries[pos][0], _MAX_NESTING_DEPTH)
        )
    line_no, _, content = entries[pos]
    if content == "-":
        return _parse_sequence(entries, pos, indent, depth)
    if _is_mapping_entry(content):
        return _parse_mapping(entries, pos, indent, depth)
    # A bare scalar occupying its own line: only reachable as a sequence
    # item's content (patterns: / - "github/codeql-action*"), since a
    # mapping value is always written inline after "key: ".
    if pos + 1 < len(entries) and entries[pos + 1][1] >= indent:
        raise DependabotContractError(
            "line {}: unexpected content after a scalar value".format(entries[pos + 1][0])
        )
    return _parse_scalar(content, line_no), pos + 1


# Diagnostics here report the structural failure and its exact source line and
# never reproduce a key read from the inspected file: the same contract issue
# #112 landed on the shared kubeadm/encryption parser, applied to this parser's
# three residual echo sites by issue #175. The line number is what an operator
# needs; the scalar is what a log must not carry.
def _parse_mapping(entries, pos, indent, depth):
    mapping = {}
    while pos < len(entries):
        line_no, line_indent, content = entries[pos]
        if line_indent != indent or content == "-":
            break
        if not _is_mapping_entry(content):
            raise DependabotContractError(
                "line {}: expected a 'key:' mapping entry".format(line_no)
            )
        key, value_text = _split_mapping_entry(content, line_no)
        if key in mapping:
            raise DependabotContractError(
                "line {}: duplicate mapping key".format(line_no)
            )
        pos += 1
        if value_text is None:
            if pos < len(entries) and entries[pos][1] > indent:
                child_indent = entries[pos][1]
                if child_indent != indent + 2:
                    raise DependabotContractError(
                        "line {}: nested content must be indented exactly 2 spaces past its key"
                        .format(entries[pos][0])
                    )
                node, pos = _parse_node(entries, pos, child_indent, depth + 1)
                mapping[key] = node
            else:
                raise DependabotContractError(
                    "line {}: mapping key has no value".format(line_no)
                )
        else:
            if pos < len(entries) and entries[pos][1] > indent:
                raise DependabotContractError(
                    "line {}: mapping key has both an inline value and nested "
                    "content".format(line_no)
                )
            mapping[key] = _parse_scalar(value_text, line_no)
    return mapping, pos


def _parse_sequence(entries, pos, indent, depth):
    items = []
    while pos < len(entries):
        line_no, line_indent, content = entries[pos]
        if line_indent != indent or content != "-":
            break
        pos += 1
        if pos >= len(entries) or entries[pos][1] <= indent:
            raise DependabotContractError("line {}: sequence item has no value".format(line_no))
        child_indent = entries[pos][1]
        if child_indent != indent + 2:
            raise DependabotContractError(
                "line {}: sequence item must be indented exactly 2 spaces past its '-'"
                .format(entries[pos][0])
            )
        node, pos = _parse_node(entries, pos, child_indent, depth + 1)
        items.append(node)
    return items, pos


def parse_document(text):
    """Parse the restricted subset into plain ``dict``/``list``/``str`` nodes.

    Raises ``DependabotContractError`` (always naming a line) on anything
    outside the accepted grammar; never returns a partially-parsed
    result.
    """

    if "\t" in text:
        line_no = next(i for i, line in enumerate(text.split("\n"), 1) if "\t" in line)
        raise DependabotContractError("line {}: tabs are not permitted".format(line_no))
    if "\r" in text:
        raise DependabotContractError("carriage returns are not permitted (LF only)")
    entries = _tokenize(text)
    if not entries:
        raise DependabotContractError("document is empty")
    node, pos = _parse_node(entries, 0, entries[0][1], 0)
    if entries[0][1] != 0:
        raise DependabotContractError(
            "line {}: the document must start at column 0".format(entries[0][0])
        )
    if pos != len(entries):
        raise DependabotContractError(
            "line {}: unexpected content (inconsistent indentation?)".format(entries[pos][0])
        )
    if not isinstance(node, dict):
        raise DependabotContractError("the top-level document must be a mapping")
    return node


# --- Schema validation ---------------------------------------------------
#
# Operates on the plain dict/list/str tree `parse_document` returns.
# Every function returns a list of violation strings (empty means valid)
# instead of raising, so one run reports every problem at once -- the
# same shape as `validate_repository.py`'s `check_*` functions and
# `validate_pi_network.py`'s `failures` list, rather than stopping at the
# first mistake the way the sibling repositories' gate does.


def _prefixed(prefix, messages):
    return ["{}: {}".format(prefix, message) for message in messages]


def contract_errors(document):
    """Validate an already-parsed document against the dependabot.yml contract."""

    if not isinstance(document, dict):
        return ["the top-level document must be a mapping"]
    errors = []
    unknown = sorted(set(document) - TOP_LEVEL_KEYS)
    if unknown:
        errors.append("unknown top-level key(s): {}".format(", ".join(unknown)))
    version = document.get("version")
    if version is None:
        errors.append("top-level 'version' is required")
    elif version != "2":
        errors.append("top-level 'version' must be exactly 2, found {!r}".format(version))
    if "updates" not in document:
        errors.append("top-level 'updates' is required")
    else:
        errors.extend(_prefixed("updates", _validate_updates(document["updates"])))
    return errors


def _validate_updates(updates):
    if not isinstance(updates, list):
        return ["must be a list"]
    if not updates:
        return ["must not be empty"]
    errors = []
    for index, entry in enumerate(updates):
        errors.extend(_prefixed("[{}]".format(index), _validate_entry(entry)))
    return errors


def _validate_entry(entry):
    if not isinstance(entry, dict):
        return ["each updates[] entry must be a mapping"]
    errors = []
    unknown = sorted(set(entry) - ENTRY_KEYS)
    if unknown:
        errors.append("unknown key(s): {}".format(", ".join(unknown)))
    for required in sorted(REQUIRED_ENTRY_KEYS):
        if required not in entry:
            errors.append("{!r} is required".format(required))

    ecosystem = entry.get("package-ecosystem")
    if ecosystem is not None:
        if not isinstance(ecosystem, str):
            errors.append("'package-ecosystem' must be a plain scalar")
        elif ecosystem not in KNOWN_ECOSYSTEMS:
            errors.append("unknown package-ecosystem {!r}".format(ecosystem))

    directory = entry.get("directory")
    if directory is not None:
        if not isinstance(directory, str):
            errors.append("'directory' must be a plain scalar")
        elif not directory.startswith("/"):
            errors.append("'directory' must start with '/' (found {!r})".format(directory))

    if "schedule" in entry:
        errors.extend(_prefixed("schedule", _validate_schedule(entry["schedule"])))

    if "groups" in entry:
        errors.extend(_prefixed("groups", _validate_groups(entry["groups"])))

    if "open-pull-requests-limit" in entry:
        limit = entry["open-pull-requests-limit"]
        if not (isinstance(limit, str) and limit.isdigit()):
            errors.append("'open-pull-requests-limit' must be a non-negative integer")

    return errors


def _validate_schedule(schedule):
    if not isinstance(schedule, dict):
        return ["must be a mapping"]
    errors = []
    unknown = sorted(set(schedule) - SCHEDULE_KEYS)
    if unknown:
        errors.append("unknown key(s): {}".format(", ".join(unknown)))

    interval = schedule.get("interval")
    if interval is None:
        errors.append("'interval' is required")
    elif interval not in ALLOWED_INTERVALS:
        errors.append(
            "'interval' must be one of {} (found {!r})".format(sorted(ALLOWED_INTERVALS), interval)
        )

    if "day" in schedule and schedule["day"] not in ALLOWED_WEEKDAYS:
        errors.append("'day' must be a lowercase weekday name (found {!r})".format(schedule["day"]))

    if "time" in schedule:
        time_value = schedule["time"]
        if not (isinstance(time_value, str) and TIME_RE.fullmatch(time_value)):
            errors.append("'time' must be 24-hour 'HH:MM' (found {!r})".format(time_value))

    if "timezone" in schedule:
        timezone = schedule["timezone"]
        if not (isinstance(timezone, str) and TIMEZONE_RE.fullmatch(timezone)):
            errors.append("'timezone' must look like an IANA zone identifier (found {!r})".format(timezone))

    return errors


def _validate_groups(groups):
    if not isinstance(groups, dict):
        return ["must be a mapping"]
    errors = []
    for name, spec in groups.items():
        errors.extend(_prefixed(name, _validate_group(spec)))
    return errors


def _validate_group(spec):
    if not isinstance(spec, dict):
        return ["must be a mapping"]
    errors = []
    unknown = sorted(set(spec) - GROUP_KEYS)
    if unknown:
        errors.append("unknown key(s): {}".format(", ".join(unknown)))

    for list_key in ("patterns", "exclude-patterns"):
        if list_key not in spec:
            continue
        value = spec[list_key]
        if not (isinstance(value, list) and value and all(isinstance(item, str) and item for item in value)):
            errors.append("'{}' must be a non-empty list of strings".format(list_key))

    if "dependency-type" in spec and spec["dependency-type"] not in DEPENDENCY_TYPES:
        errors.append("'dependency-type' must be one of {}".format(sorted(DEPENDENCY_TYPES)))

    if "update-types" in spec:
        value = spec["update-types"]
        if not (isinstance(value, list) and value and all(item in UPDATE_TYPES for item in value)):
            errors.append("'update-types' must be a non-empty list from {}".format(sorted(UPDATE_TYPES)))

    if "applies-to" in spec and spec["applies-to"] not in APPLIES_TO:
        errors.append("'applies-to' must be one of {}".format(sorted(APPLIES_TO)))

    return errors


def document_errors(text):
    """Parse and validate ``text``, collapsing a parse failure to one message.

    ``_MAX_NESTING_DEPTH`` in the parser is the primary, deterministic
    defense against a deeply nested document; catching ``RecursionError``
    here is the belt-and-suspenders backstop, so that if any path were
    ever found to bypass the explicit cap, the caller still gets one
    clean fail-closed message and exit 2 instead of an uncaught traceback
    and exit 1 (the exact class of gap the depth cap closes).
    """

    try:
        document = parse_document(text)
    except DependabotContractError as error:
        return [str(error)]
    except RecursionError:
        return ["document nesting is too deep to parse safely"]
    return contract_errors(document)


def file_errors(path):
    """Read ``path`` safely and return every contract violation found."""

    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as error:
        return ["cannot read {}: {}".format(path, error)]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        return ["{} is not valid UTF-8: {}".format(path, error)]
    return document_errors(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="path to a dependabot.yml to validate")
    args = parser.parse_args(argv)
    errors = file_errors(args.path)
    if errors:
        for message in errors:
            print("FAIL " + message, file=sys.stderr)
        return 2
    print("PASS {} satisfies the dependabot.yml contract".format(args.path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
