#!/usr/bin/env python3
import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
SKILLS_ROOT = ROOT / "skills"
SKILL = SKILLS_ROOT / "build-website-infrastructure"
PR_FLOW = SKILLS_ROOT / "gh-pr-flow"
# Every committed skill is a portable METHOD, so all of them are held to one
# structure contract: strict frontmatter, typed/bounded resource areas, every
# reference linked from SKILL.md, and no trace of THIS repository's identity in
# text resources.
# A skill that names this repository's sites, owner, hosts, commits, issue
# numbers, or a workstation path is no longer reusable anywhere else.
FORBIDDEN_IDENTITY = (
    # Sites and owner. The bare tokens, not the full domains and handles they
    # appear in: a substring forbids every spelling built on it.
    "naranjo",
    "lidersea",
    "snaraj",
    "samuel",
    # Host and service names. Aliases of the edge host are matched as a SHAPE
    # below rather than listed here: a denylist that spells out the value it
    # protects publishes it to everyone who reads the denylist.
    "pi-admin",
    "pi-websites",
    # This repository, and the agent labels that only exist in these
    # repositories — hyphenated and spaced, because a line wrap or a habit
    # respells them.
    "website-infrastructure",
    "fable5",
    "opus5",
    "opus4.8",
    "5.6-sol",
    "5.6 sol",
    "sol ultra",
)
# Identity only one skill is realistically at risk of absorbing: the
# media-storage vocabulary that produced the first skill.
SKILL_LOCAL_FORBIDDEN_IDENTITY = {
    "build-website-infrastructure": (
        "UNRESOLVED_PI_MEDIA_STORAGE",
        "2026-08-08",
        "512 MB",
        "protected `main`",
        "GHCR repository",
        "SOPS identity install",
    ),
}
# The shared list applies to every skill; an exemption is per-skill, explicit,
# and load-bearing. The only one: that skill's own NAME contains the
# repository name, so this literal cannot be enforced against it. Each
# exemption carries the EXACT occurrence count it licenses, because "present
# somewhere" would license the literal in PROSE too — an exemption must be no
# wider than the collision forcing it. Both licensed occurrences are
# structural: the frontmatter name, and the invocation token in the agent
# interface. A stale or outgrown exemption fails like a missing check.
IDENTITY_EXEMPTIONS = {
    "build-website-infrastructure": (("website-infrastructure", 2),),
}
# Prose that must NEVER trip a shape. Each string was a real false positive
# of a wider earlier pattern. These are the guard's boundary: if one goes
# red, narrow the SHAPE — deleting the string is how a guard dies.
BENIGN_PROSE = (
    "pin 3 rule NAMES structurally against the rendered inventory",
    "pipeline 2 runs after pipeline 1",
    "pins 4 things, pinned 2 ways, pinning 1 setting",
    "pipe 3 documents, pick 2 of them",
    "defaced acceded decade beaded",
    "scanned ~10945256 bytes in 1.35s",
    "the badge colours #0075ca and #d73a4a",
    "sections 1-3 and rows 10-20",
)

MAX_SKILL_ENTRY_LINES = 500
MAX_REFERENCE_LINES = 200
MAX_SCRIPT_BYTES = 256 * 1024
MAX_AGENT_FILE_BYTES = 64 * 1024
MAX_ASSET_BYTES = 1024 * 1024
MAX_ASSET_TREE_BYTES = 2 * 1024 * 1024
TEXT_AREAS = frozenset({"references", "scripts", "agents"})
KNOWN_AREAS = TEXT_AREAS | {"assets"}
# Shapes, not literals. The repository privacy validator is NOT a second net
# here: it covers emails, addresses, UUIDs, 32-hex and Windows paths only, so
# commits, short commits, POSIX and home-relative workstation paths, and
# item cross-references have to be caught right here or nowhere.
FORBIDDEN_IDENTITY_SHAPES = {
    # Subsumed by "bare commit" below — every pinned form also matches the
    # bare one — and kept only so the failure message names the likelier
    # mistake. It is not an independent guard; do not read it as one.
    "pinned commit": re.compile(r"@[0-9a-f]{40}\b"),
    "bare commit": re.compile(r"(?<![0-9a-zA-Z])[0-9a-f]{40}(?![0-9a-zA-Z])"),
    # An abbreviated commit. A context-free candidate needs both a digit and a
    # letter so ordinary hex words and long decimal counts stay clean. Explicit
    # commit syntax ("commit", "SHA", "head", "base", or "revision") admits
    # every 7-39 digit hexadecimal candidate, including the all-numeric class
    # that the mixed-only form used to miss. The context is load-bearing: an
    # unrestricted all-numeric shape would relabel ordinary counts as commits.
    "short commit": re.compile(
        r"(?ix)(?:"
        r"\b(?=[0-9a-f]{7,39}\b)(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])"
        r"[0-9a-f]{7,39}\b|"
        r"\b(?:commit|sha|head|base|revision)\b\s*(?:[:=]\s*)?[`@]?"
        r"[0-9a-f]{7,39}`?(?![0-9a-z_])"
        r")"
    ),
    # A single-board-host alias: the family name, at most two more letters,
    # an optional separator, and a unit number. A shape, so this file never
    # has to name the host it protects. The bounds are load-bearing: an
    # unbounded [a-z]* with a space separator matched this document's own
    # vocabulary ("pin 3 rule names", "pipeline 2"), and a guard that fires
    # on ordinary prose while naming nothing gets weakened rather than
    # diagnosed. BENIGN_PROSE below pins that boundary. Known residual: the
    # hyphenated "pin-3" is genuinely alias-shaped and still matches — write
    # "pin 3" in prose; do not widen the separator class to escape it.
    "host alias": re.compile(r"(?i)\bpi[a-z]{0,2}[-_]?[0-9]{1,3}\b"),
    "windows workstation path": re.compile(r"(?i)[A-Z]:[\\/](?:Users|dev)[\\/]"),
    # No trailing slash required: the leaf is usually the operator's name,
    # which is exactly the part that must not ship. Known benign match:
    # a CI runner's home ("/home/runner/work"). If a skill needs to describe
    # it, write "the runner's home" or "$HOME" — the shape stays as it is.
    "posix workstation path": re.compile(
        r"(?<![A-Za-z0-9_.-])/(?:Users|home)/[A-Za-z0-9._-]+"
    ),
    "home-relative workstation path": re.compile(r"~/[A-Za-z0-9._-]+"),
    # Bare, not just the "PR #12" spelling. The lookahead clears hex colour
    # literals that contain a letter. Known residual: an ALL-DIGIT colour
    # ("#012345") is indistinguishable from an item reference and still
    # matches — name the colour or write a form containing a letter. Do not
    # bound the digit count to escape it: real item numbers reach six digits,
    # and that trade sheds detections to buy prose convenience.
    "repository item reference": re.compile(r"#[0-9]+(?![0-9a-fA-F])"),
}


def governed_skills(skills_root=SKILLS_ROOT):
    """Every skill directory, DISCOVERED — never a hardcoded list.

    A hardcoded tuple would be this repository's own vacuity catalogue turned
    on the test that ships it: a new skill would fall outside the match and
    every row would stay green while it opted itself out of the contract.
    """
    return tuple(sorted(path for path in skills_root.iterdir() if path.is_dir()))


def skill_files(skill):
    """Every file below a skill, independent of its content type."""
    return tuple(sorted(path for path in skill.rglob("*") if path.is_file()))


def skill_file_area(skill, path):
    """Classify a file by its TOP-LEVEL skill area.

    A nested directory whose name happens to be ``assets`` does not turn text
    below ``scripts/``, ``agents/``, or ``references/`` into an opaque asset.
    Layout and privacy use this same classifier so those two boundaries cannot
    disagree about which contract governs a file.
    """
    relative = path.relative_to(skill)
    if relative.as_posix() == "SKILL.md":
        return "entry"
    if len(relative.parts) >= 2 and relative.parts[0] in KNOWN_AREAS:
        return relative.parts[0]
    return None


def skill_layout_findings(skill):
    """Return fixed-label findings for the portable skill anatomy.

    SKILL.md, references, scripts, and agent metadata are UTF-8 text. Binary
    assets have their own bounded tree and are never decoded as documents.
    Unknown top-level areas fail closed instead of silently escaping the
    contract.
    """
    findings = []
    entry = skill / "SKILL.md"
    if not entry.is_file():
        findings.append("missing SKILL.md")
    asset_bytes = 0
    for path in skill_files(skill):
        relative = path.relative_to(skill)
        data = path.read_bytes()
        area = skill_file_area(skill, path)
        if area is None:
            findings.append("file outside a recognized skill area")
            continue

        if area == "assets":
            asset_bytes += len(data)
            if len(data) > MAX_ASSET_BYTES:
                findings.append("asset exceeds per-file size ceiling")
            continue
        if area == "scripts" and len(data) > MAX_SCRIPT_BYTES:
            findings.append("script exceeds size ceiling")
        if area == "agents" and len(data) > MAX_AGENT_FILE_BYTES:
            findings.append("agent metadata exceeds size ceiling")
        if area == "references" and path.suffix.casefold() != ".md":
            findings.append("reference is not Markdown")
        try:
            data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            findings.append("text resource is not UTF-8")
    if asset_bytes > MAX_ASSET_TREE_BYTES:
        findings.append("asset tree exceeds aggregate size ceiling")
    return tuple(findings)


def searchable_skill_text(skill):
    """A searchable projection of the entry and UTF-8 text resource areas."""
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in skill_files(skill)
        if skill_file_area(skill, path) in ({"entry"} | TEXT_AREAS)
    )


def skill_identity_findings(skill):
    """Return fixed labels for identity leaks in UTF-8 text resources.

    Assets stay opaque bytes rather than being decoded as documents; their
    size and placement are governed separately by skill_layout_findings and the
    repository-wide publication gates. Scripts and agent metadata remain in
    the privacy scan instead of escaping when binary anatomy is introduced.
    """
    raw = searchable_skill_text(skill)
    combined = raw + "\n" + " ".join(raw.split())
    exempt = IDENTITY_EXEMPTIONS.get(skill.name, ())
    licensed = tuple(value for value, _ in exempt)
    findings = []
    for position, (value, occurrences) in enumerate(exempt):
        if raw.lower().count(value.lower()) != occurrences:
            findings.append(f"exemption #{position} count mismatch")
    forbidden = (
        *(value for value in FORBIDDEN_IDENTITY if value not in licensed),
        *SKILL_LOCAL_FORBIDDEN_IDENTITY.get(skill.name, ()),
    )
    for position, value in enumerate(forbidden):
        if value.lower() in combined.lower():
            findings.append(f"forbidden identity #{position}")
    for label, shape in FORBIDDEN_IDENTITY_SHAPES.items():
        if shape.search(combined):
            findings.append(f"shape {label!r}")
    return tuple(findings)


def parse_frontmatter_scalar(raw):
    """Parse the repository's strict one-line YAML string subset.

    Double-quoted JSON strings and YAML single-quoted strings are accepted.
    Plain strings must begin with a letter and may not use YAML structure,
    comments, implicit null/boolean/number forms, or multiline syntax.
    """
    if not raw or raw != raw.strip() or "\t" in raw:
        raise ValueError("frontmatter scalar is empty or padded")
    if raw.startswith('"'):
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as problem:
            raise ValueError("malformed double-quoted scalar") from problem
        if not isinstance(value, str):
            raise ValueError("frontmatter scalar is not a string")
    elif raw.startswith("'"):
        if len(raw) < 2 or not raw.endswith("'"):
            raise ValueError("malformed single-quoted scalar")
        inner = raw[1:-1]
        if "'" in inner.replace("''", ""):
            raise ValueError("single quotes must be doubled")
        value = inner.replace("''", "'")
    else:
        lowered = raw.casefold()
        if (
            raw[0] in "-?:,[]{}#&*!|>@`"
            or not raw[0].isalpha()
            or lowered in {
                "null", "~", "true", "false", "yes", "no", "on", "off",
                ".nan", ".inf", "+.inf", "-.inf",
            }
            or re.search(r":(?:\s|$)|(?:^|\s)#", raw)
        ):
            raise ValueError("plain scalar is outside the strict string grammar")
        value = raw
    if any(ord(character) < 32 for character in value):
        raise ValueError("frontmatter string contains a control character")
    return value


def parse_skill_frontmatter(text):
    """Parse exactly name+description frontmatter under the strict grammar."""
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("missing opening frontmatter delimiter")
    try:
        closing = lines.index("---", 1)
    except ValueError as problem:
        raise ValueError("missing closing frontmatter delimiter") from problem
    entries = []
    for line in lines[1:closing]:
        match = re.fullmatch(r"([a-z][a-z0-9_-]*):[ \t]+(.*)", line)
        if match is None:
            raise ValueError("malformed frontmatter entry")
        entries.append((match.group(1), parse_frontmatter_scalar(match.group(2))))
    keys = [key for key, _value in entries]
    if keys != ["name", "description"] or len(set(keys)) != len(keys):
        raise ValueError("frontmatter keys must be name then description once")
    return dict(entries)


def frontmatter_findings(text, expected_name):
    """Validate parsed values without relying on YAML truthiness/coercion."""
    try:
        fields = parse_skill_frontmatter(text)
    except ValueError:
        return ("invalid frontmatter grammar",)
    findings = []
    name = fields["name"]
    description = fields["description"]
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        findings.append("name is outside the portable slug grammar")
    if name != expected_name:
        findings.append("name does not match its directory")
    if len(name) > 64:
        findings.append("name exceeds size ceiling")
    if not description.strip():
        findings.append("description is empty")
    if len(description) > 1024:
        findings.append("description exceeds size ceiling")
    if re.search(r"[<>]", description):
        findings.append("description contains reserved markup")
    return tuple(findings)


def _markdown_without_code_or_comments(markdown):
    """Remove fenced, indented and inline code plus HTML comments.

    This is deliberately a strict link-evidence projection, not a Markdown
    renderer: a link used to prove that a resource is discoverable must appear
    in ordinary prose. Four-space/tab-indented blocks and code spans are inert
    even when they contain syntactically convincing link text.
    """
    markdown = re.sub(r"<!--.*?-->", "", markdown, flags=re.DOTALL)
    visible_lines = []
    fence_character = None
    fence_length = 0
    for line in markdown.splitlines():
        fence = re.match(r"^[ ]{0,3}(`{3,}|~{3,})", line)
        if fence_character is not None:
            if (
                fence is not None
                and fence.group(1)[0] == fence_character
                and len(fence.group(1)) >= fence_length
            ):
                fence_character = None
                fence_length = 0
            visible_lines.append("")
            continue
        if fence is not None:
            fence_character = fence.group(1)[0]
            fence_length = len(fence.group(1))
            visible_lines.append("")
            continue
        if line.startswith("\t") or line.startswith("    "):
            visible_lines.append("")
            continue
        visible_lines.append(line)

    visible = "\n".join(visible_lines)
    output = list(visible)
    position = 0
    while position < len(visible):
        if visible[position] != "`":
            position += 1
            continue
        end_ticks = position
        while end_ticks < len(visible) and visible[end_ticks] == "`":
            end_ticks += 1
        ticks = visible[position:end_ticks]
        closing = visible.find(ticks, end_ticks)
        if closing < 0:
            position = end_ticks
            continue
        end = closing + len(ticks)
        for index in range(position, end):
            if output[index] != "\n":
                output[index] = " "
        position = end
    return "".join(output)


def _is_backslash_escaped(text, position):
    """Whether the character at position has an odd backslash prefix."""
    backslashes = 0
    position -= 1
    while position >= 0 and text[position] == "\\":
        backslashes += 1
        position -= 1
    return backslashes % 2 == 1


def _normalized_link_target(value):
    value = value.strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    return unquote(value.split("#", 1)[0].split("?", 1)[0])


def markdown_link_targets(markdown):
    """Return actual inline and full/collapsed reference-style link targets."""
    visible = _markdown_without_code_or_comments(markdown)
    targets = set()
    inline = re.compile(
        r"(?<!!)\[[^\]\n]*\]\(\s*(<[^>\n]+>|(?:\\.|[^\s)\n])+)"
    )
    for match in inline.finditer(visible):
        if not _is_backslash_escaped(visible, match.start()):
            targets.add(_normalized_link_target(match.group(1)))

    definitions = {}
    definition = re.compile(
        r"(?m)^[ ]{0,3}\[([^\]\n]+)\]:[ \t]*(<[^>\n]+>|\S+)"
    )
    for match in definition.finditer(visible):
        label = " ".join(match.group(1).split()).casefold()
        definitions[label] = _normalized_link_target(match.group(2))
    uses_visible = definition.sub("", visible)
    reference_use = re.compile(r"(?<!!)\[([^\]\n]+)\]\[([^\]\n]*)\]")
    for match in reference_use.finditer(uses_visible):
        if _is_backslash_escaped(uses_visible, match.start()):
            continue
        label = match.group(2) or match.group(1)
        normalized_label = " ".join(label.split()).casefold()
        if normalized_label in definitions:
            targets.add(definitions[normalized_label])
    shortcut_use = re.compile(r"(?<!!)\[([^\]\n]+)\](?![\[(])")
    for match in shortcut_use.finditer(uses_visible):
        if _is_backslash_escaped(uses_visible, match.start()):
            continue
        normalized_label = " ".join(match.group(1).split()).casefold()
        if normalized_label in definitions:
            targets.add(definitions[normalized_label])
    return frozenset(targets)


def collapsed(path):
    """Document text with runs of whitespace flattened to single spaces.

    The doctrine pins below assert CONTENT, so they must survive a reflow:
    matching raw text would turn every line-wrap change into a false failure
    and would tempt the next author to weaken the pin instead of the prose.
    """
    return " ".join(path.read_text(encoding="utf-8").split())


class SkillStructureTests(unittest.TestCase):
    def test_every_committed_skill_is_governed(self):
        """Discovery covers the whole tree, and the tree is all directories.

        Without this, `skills/` could grow a skill — or a loose document —
        that no other test in this file ever reads.
        """
        discovered = governed_skills()
        self.assertTrue(discovered)
        for known in (SKILL, PR_FLOW):
            self.assertIn(known, discovered)
        self.assertEqual(
            sorted(path.name for path in SKILLS_ROOT.iterdir()),
            sorted(path.name for path in discovered),
            "a non-directory under skills/ would escape every check below",
        )
        for skill in discovered:
            with self.subTest(skill=skill.name):
                self.assertTrue((skill / "SKILL.md").is_file())
                self.assertEqual(skill_layout_findings(skill), ())

    def test_frontmatter_matches_repository_strict_yaml_contract(self):
        for skill in governed_skills():
            with self.subTest(skill=skill.name):
                text = (skill / "SKILL.md").read_text(encoding="utf-8")
                self.assertEqual(frontmatter_findings(text, skill.name), ())

    def test_frontmatter_fixture_matrix_rejects_yaml_coercion_and_ambiguity(self):
        valid = (
            (
                '---\nname: "quoted-skill"\n'
                'description: "Quoted and explicit"\n---\n',
                "quoted-skill",
            ),
            (
                "---\nname: 'single-quoted'\n"
                "description: 'It''s still a string'\n---\n",
                "single-quoted",
            ),
        )
        for text, expected_name in valid:
            with self.subTest(valid=expected_name):
                self.assertEqual(frontmatter_findings(text, expected_name), ())

        invalid = {
            "quoted empty": (
                "quoted-empty",
                '---\nname: quoted-empty\ndescription: ""\n---\n',
            ),
            "quoted whitespace": (
                "quoted-whitespace",
                '---\nname: quoted-whitespace\ndescription: "   "\n---\n',
            ),
            "escaped control": (
                "escaped-control",
                '---\nname: escaped-control\ndescription: "line\\nfeed"\n---\n',
            ),
            "implicit null": (
                "implicit-null",
                "---\nname: implicit-null\ndescription: null\n---\n",
            ),
            "explicit null": (
                "explicit-null",
                "---\nname: explicit-null\ndescription: ~\n---\n",
            ),
            "numeric": (
                "numeric", "---\nname: numeric\ndescription: 42\n---\n"
            ),
            "sequence": (
                "sequence", "---\nname: sequence\ndescription: [portable]\n---\n"
            ),
            "mapping": (
                "mapping",
                "---\nname: mapping\ndescription: {kind: portable}\n---\n",
            ),
            "duplicate": (
                "duplicate",
                "---\nname: duplicate\ndescription: first\n"
                "description: second\n---\n",
            ),
            "malformed quote": (
                "malformed-quote",
                '---\nname: malformed-quote\ndescription: "unterminated\n---\n',
            ),
            "malformed entry": (
                "malformed-entry",
                "---\nname: malformed-entry\ndescription portable\n---\n",
            ),
        }
        for label, (expected_name, text) in invalid.items():
            with self.subTest(invalid=label):
                self.assertTrue(frontmatter_findings(text, expected_name))

    def test_references_and_interface_exist(self):
        for name in (
            "project-contract.md", "github-actions.md", "external-gates.md",
            "media-storage.md",
        ):
            self.assertTrue((SKILL / "references" / name).is_file())
        interface = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn('display_name: "Build Website Infrastructure"', interface)
        self.assertIn("$build-website-infrastructure", interface)

    def test_skill_contains_methods_not_this_repository_identity(self):
        for skill in governed_skills():
            with self.subTest(skill=skill.name):
                self.assertEqual(skill_identity_findings(skill), ())

    def test_portable_layout_fixture_supports_scripts_agents_and_binary_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            skill = Path(temporary) / "codex-tool"
            for area in ("references", "scripts", "agents", "assets"):
                (skill / area).mkdir(parents=True, exist_ok=True)
            (skill / "SKILL.md").write_text(
                '---\nname: "codex-tool"\n'
                'description: "A portable tool method"\n---\n\n'
                '[Guide](references/guide.md)\n',
                encoding="utf-8",
            )
            (skill / "references" / "guide.md").write_text(
                "# Guide\n", encoding="utf-8"
            )
            (skill / "scripts" / "check.py").write_text(
                "print('portable')\n", encoding="utf-8"
            )
            (skill / "agents" / "openai.yaml").write_text(
                "interface:\n  display_name: Portable\n", encoding="utf-8"
            )
            asset = skill / "assets" / "sample.png"
            asset.write_bytes(b"\x89PNG\r\n\x1a\n\xff\x00")

            self.assertEqual(skill_layout_findings(skill), ())
            self.assertEqual(
                frontmatter_findings(
                    (skill / "SKILL.md").read_text(encoding="utf-8"),
                    skill.name,
                ),
                (),
            )
            self.assertEqual(skill_identity_findings(skill), ())
            self.assertIn(
                "references/guide.md",
                markdown_link_targets(
                    (skill / "SKILL.md").read_text(encoding="utf-8")
                ),
            )

            # New text areas remain inside the portable identity boundary.
            script = skill / "scripts" / "check.py"
            script.write_text(FORBIDDEN_IDENTITY[0], encoding="utf-8")
            self.assertTrue(skill_identity_findings(skill))
            script.write_text("print('portable')\n", encoding="utf-8")

            # Only the TOP-LEVEL assets tree is opaque. A nested directory
            # called assets inside any text area remains searchable text.
            for area, suffix in (
                ("scripts", "check.py"),
                ("agents", "openai.yaml"),
                ("references", "guide.md"),
            ):
                nested = skill / area / "nested" / "assets" / suffix
                nested.parent.mkdir(parents=True, exist_ok=True)
                nested.write_text(FORBIDDEN_IDENTITY[0], encoding="utf-8")
                with self.subTest(nested_assets_area=area):
                    self.assertTrue(skill_identity_findings(skill))
                nested.unlink()

            # Conversely, top-level assets are deliberately opaque bytes even
            # when their byte stream happens to decode as identity-shaped text.
            asset.write_bytes(FORBIDDEN_IDENTITY[0].encode("utf-8"))
            self.assertEqual(skill_identity_findings(skill), ())

            # Text areas remain strict UTF-8 and assets remain bounded.
            asset.write_bytes(b"\x00" * (MAX_ASSET_BYTES + 1))
            self.assertIn(
                "asset exceeds per-file size ceiling",
                skill_layout_findings(skill),
            )
            (skill / "scripts" / "check.py").write_bytes(b"\xff")
            self.assertIn(
                "text resource is not UTF-8", skill_layout_findings(skill)
            )

    def test_identity_shapes_do_not_match_ordinary_prose(self):
        """The false-positive boundary of every shape, pinned.

        A shape that fires on ordinary prose still fails closed, but its
        message names nothing by design, so the next author's cheapest move
        is to weaken the shape rather than diagnose it. That is how a guard
        dies. These rows make the boundary explicit and regression-proof.
        """
        for text in BENIGN_PROSE:
            for label, shape in FORBIDDEN_IDENTITY_SHAPES.items():
                with self.subTest(prose=text, shape=label):
                    self.assertNotRegex(text, shape)

    def test_short_commit_shape_catches_numeric_context_and_boundaries(self):
        shape = FORBIDDEN_IDENTITY_SHAPES["short commit"]
        for text in (
            "Commit 1234567.",
            "SHA: `7654321`,",
            "base=0123456789",
            "head @123456789012345678901234567890123456789",
        ):
            with self.subTest(forbidden=text):
                self.assertRegex(text, shape)
        for text in (
            "scanned 1234567 bytes",
            "commitment 1234567 is not commit syntax",
            "commit 123456",
            "commit 1234567890123456789012345678901234567890",
            "commit 1234567suffix",
            "sha 7654321_name",
            "the badge colour #01234567",
        ):
            with self.subTest(benign=text):
                self.assertNotRegex(text, shape)

    def test_all_references_are_linked_and_documents_stay_focused(self):
        for skill in governed_skills():
            entry = skill / "SKILL.md"
            main = entry.read_text(encoding="utf-8")
            links = markdown_link_targets(main)
            with self.subTest(skill=skill.name):
                self.assertLessEqual(len(main.splitlines()), MAX_SKILL_ENTRY_LINES)
            for document in sorted((skill / "references").rglob("*.md")):
                relative = document.relative_to(skill).as_posix()
                with self.subTest(skill=skill.name, document=relative):
                    self.assertIn(relative, links)
                    self.assertLessEqual(
                        len(document.read_text(encoding="utf-8").splitlines()),
                        MAX_REFERENCE_LINES,
                    )

    def test_markdown_reference_parser_rejects_inert_path_mentions(self):
        target = "references/guide.md"
        for markdown in (
            "[Guide](references/guide.md)",
            "[Guide][portable]\n\n[portable]: references/guide.md",
            "[Guide][]\n\n[Guide]: <references/guide.md#details>",
            "[Guide]\n\n[Guide]: references/guide.md?view=portable",
        ):
            with self.subTest(real_link=markdown):
                self.assertIn(target, markdown_link_targets(markdown))
        for markdown in (
            "See references/guide.md.",
            "See `references/guide.md`.",
            "`code starts\n[Guide](references/guide.md)\nand ends here`",
            "```text\nreferences/guide.md\n```",
            "    [Guide](references/guide.md)",
            "\t[Guide](references/guide.md)",
            "\\[Guide](references/guide.md)",
            "<!-- [Guide](references/guide.md) -->",
            "![Guide](references/guide.md)",
            "[Guide]: references/guide.md",
        ):
            with self.subTest(inert=markdown):
                self.assertNotIn(target, markdown_link_targets(markdown))

    def test_skill_explicitly_discovers_portable_variants(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        media = (SKILL / "references" / "media-storage.md").read_text(
            encoding="utf-8"
        )
        release = (SKILL / "references" / "github-actions.md").read_text(
            encoding="utf-8"
        )
        for fragment, document in (
            ("where those layers exist", main),
            ("one conditional variant", main),
            ("selected CSI, object", media),
            ("not a universal mandate", media),
            ("runner trust model", release),
            ("protected release event/ref", release),
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, document)

    def test_pr_flow_states_the_review_authority_split(self):
        """Each fragment is the killer for one control this flow carries.

        Deleting any of the roles, the label semantics, the escalation rule,
        the scanner or base-drift steps, the live-acceptance rule, or the
        publication rule turns exactly one of these subtests red — so no
        section of the flow ships without a test that fails when it is gone.
        """
        main = collapsed(PR_FLOW / "SKILL.md")
        for fragment in (
            "references/evidence-doctrine.md",
            "already-configured principal",
            "Never acquire, extract, exchange, print, change, or repurpose",
            "author never posts its own verdict",
            "Neither the author nor the reviewer performs the readiness flip",
            "If no separate coordinator exists, the owner may perform",
            "alone holds merge authority",
            "EVIDENCE, never",
            "is NOT a readiness signal",
            "complete-from-author when it is not",
            "reports a proposed split",
            "invisible at the point of use is not a deferral",
            "evidence to VERIFY, never authority",
            "code-scanning/alerts",
            "output.summary",
            "EMPTY bodies",
            "aggregate pull-request alerts check is distinct from each per-language analysis check",
            "fail on configuration, extraction, build, or upload",
            "A RED aggregate means REAL ALERTS",
            "There is no \"aggregation race\"",
            "NEVER FULLY ANALYSED",
            "merge-cleanliness against the CURRENT target",
            "Predict, capture, diff",
            "a PR comment is publication",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, main)

    def test_role_compatibility_and_identity_doctrine_are_consistent(self):
        flow = collapsed(PR_FLOW / "SKILL.md").casefold()
        contract = collapsed(ROOT / "AGENTS.md").casefold()
        for fragment in (
            "branch author and independent reviewer are never the same context",
            "neither the author nor the reviewer performs the readiness flip",
            "if no separate coordinator exists, the owner may perform that coordination action",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, flow)
                self.assertIn(fragment, contract)
        for fragment, document in (
            ("alone holds merge authority", flow),
            ("the owner alone merges", contract),
            ("already-configured principal", flow),
            ("already configured, task-authorized owner account", contract),
            ("never acquire, extract, exchange", flow),
            ("never acquire, extract, exchange", contract),
            ("never print or repurpose", contract),
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, document)

    def test_evidence_doctrine_catalogues_each_vacuity_mechanism(self):
        """One killer per catalogued mechanism, for the same reason."""
        doctrine = collapsed(PR_FLOW / "references" / "evidence-doctrine.md")
        for fragment in (
            "OUTSIDE a rule's match block",
            "A SKIP counts as a pass",
            "RENAMING a rule out of existence",
            "can retire the rule that carries the property",
            "pin the short-circuit setting structurally",
            "Enforcement can be switched off wholesale",
            "MULTI-DOCUMENT deny fixture",
            "its own SOURCE TEXT",
            "reads its THRESHOLD from the artifact it verifies",
            "satisfied by a COMMENT",
            "realistic regression is DELETION",
            "whose CALL SITE no test invokes",
            "HAND-WRITTEN stub",
            "DIFFERENTIAL harness",
            "bind scope to KIND",
            "keyed on PART of an identity",
            "Patching by INDEX",
            "likeliest survivors",
            "NO killer",
            "BAD MUTANT",
            "NORMALISATION",
            "TRUE NEGATIVES",
            "A STAGED command is not a VERIFIED result",
            "needs a PRISTINE checkout",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, doctrine)

    def test_repository_contract_routes_review_to_the_doctrine(self):
        """The contract must point INTO the skill, and the pointer must land.

        A review protocol that delegates to a document is only as good as the
        cross-reference: renaming the reference, or citing one that was never
        written, would otherwise leave the protocol quietly pointing at
        nothing while every other check stays green.
        """
        contract = collapsed(ROOT / "AGENTS.md")
        contract_folded = contract.casefold()
        referenced = re.findall(
            r"skills/[a-z0-9.-]+/references/[a-z0-9.-]+\.md", contract
        )
        self.assertIn(
            "skills/gh-pr-flow/references/evidence-doctrine.md", referenced
        )
        for reference in sorted(set(referenced)):
            with self.subTest(reference=reference):
                self.assertTrue((ROOT / reference).is_file())
        # The shared-surface and compatible-role rulings must stay at the
        # repository authority layer instead of existing only in a skill.
        for fragment in (
            "shared agent governance",
            "not the exclusive property of either implementation lane",
            "review comes from a different context",
            "never supersedes agents.md",
            "never grants credential, live-mutation, or merge authority",
            "permission requires an owner ruling",
            "that removal is not a readiness signal",
            "neither the author nor the reviewer performs the readiness flip",
            "coordinator — whoever is directing the work — performs that flip",
            "if no separate coordinator exists, the owner may perform",
            "the approve verdict and the flip by the coordinator",
            "the owner alone merges",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, contract_folded)


if __name__ == "__main__":
    unittest.main()
