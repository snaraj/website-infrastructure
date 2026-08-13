#!/usr/bin/env python3
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILLS_ROOT = ROOT / "skills"
SKILL = SKILLS_ROOT / "build-website-infrastructure"
PR_FLOW = SKILLS_ROOT / "gh-pr-flow"
# Every committed skill is a portable METHOD, so all of them are held to one
# structure contract: the official frontmatter shape, bounded documents, every
# reference linked from SKILL.md, and no trace of THIS repository's identity.
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
    "codex",
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
    # An abbreviated commit. Requiring both a digit and a letter keeps English
    # words that happen to be hex ("defaced", "acceded") and long decimal
    # counts out of it, while a real short commit essentially always has both.
    "short commit": re.compile(
        r"\b(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]{7,39}\b"
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
    # Bare, not just the "PR #12" spelling. The negative lookahead keeps hex
    # colour literals out of it.
    "repository item reference": re.compile(r"#[0-9]+(?![0-9a-fA-F])"),
}


def governed_skills():
    """Every skill directory, DISCOVERED — never a hardcoded list.

    A hardcoded tuple would be this repository's own vacuity catalogue turned
    on the test that ships it: a new skill would fall outside the match and
    every row would stay green while it opted itself out of the contract.
    """
    return tuple(sorted(path for path in SKILLS_ROOT.iterdir() if path.is_dir()))


def skill_documents(skill):
    """Every tracked byte of one skill, as a single searchable string."""
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(skill.rglob("*"))
        if path.is_file()
    )


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

    def test_frontmatter_matches_official_validator_contract(self):
        for skill in governed_skills():
            with self.subTest(skill=skill.name):
                text = (skill / "SKILL.md").read_text(encoding="utf-8")
                match = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
                self.assertIsNotNone(match)
                frontmatter = match.group(1).splitlines()
                keys = [
                    line.split(":", 1)[0]
                    for line in frontmatter
                    if ":" in line
                ]
                self.assertEqual(keys, ["name", "description"])
                name = frontmatter[0].split(":", 1)[1].strip()
                description = frontmatter[1].split(":", 1)[1].strip()
                self.assertRegex(name, r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
                self.assertEqual(name, skill.name)
                self.assertLessEqual(len(name), 64)
                self.assertTrue(description)
                self.assertLessEqual(len(description), 1024)
                self.assertNotRegex(description, r"[<>]")

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
            raw = skill_documents(skill)
            # Both spellings: collapsing whitespace catches an identity that a
            # line wrap split across two lines, which raw text cannot see.
            combined = raw + "\n" + " ".join(raw.split())
            exempt = IDENTITY_EXEMPTIONS.get(skill.name, ())
            licensed = tuple(value for value, _ in exempt)
            for position, (value, occurrences) in enumerate(exempt):
                # The value is deliberately NOT a subTest parameter: a subTest
                # label is echoed into logs and evidence tables, and a guard
                # must not publish what it protects.
                with self.subTest(skill=skill.name, exemption=position):
                    self.assertEqual(raw.lower().count(value.lower()), occurrences)
            forbidden = (
                *(v for v in FORBIDDEN_IDENTITY if v not in licensed),
                *SKILL_LOCAL_FORBIDDEN_IDENTITY.get(skill.name, ()),
            )
            for position, value in enumerate(forbidden):
                # Indexed, not named, for the same reason as the exemptions
                # above: this list holds the values a public artefact must
                # never carry, and a failure label is a public artefact.
                with self.subTest(skill=skill.name, forbidden=position):
                    self.assertNotIn(value.lower(), combined.lower())
            for label, shape in FORBIDDEN_IDENTITY_SHAPES.items():
                with self.subTest(skill=skill.name, shape=label):
                    self.assertNotRegex(combined, shape)

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

    def test_all_references_are_linked_and_documents_stay_focused(self):
        for skill in governed_skills():
            entry = skill / "SKILL.md"
            main = entry.read_text(encoding="utf-8")
            with self.subTest(skill=skill.name):
                self.assertLessEqual(len(main.splitlines()), 500)
            # rglob, not glob: a subdirectory or a document outside
            # references/ would otherwise carry any length, unlinked.
            for document in sorted(skill.rglob("*.md")):
                if document == entry:
                    continue
                relative = document.relative_to(skill).as_posix()
                with self.subTest(skill=skill.name, document=relative):
                    self.assertIn(relative, main)
                    self.assertLessEqual(
                        len(document.read_text(encoding="utf-8").splitlines()),
                        200,
                    )

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
            "Never posts its own verdict",
            "flips draft to ready",
            "EVIDENCE, never",
            "is NOT a readiness signal",
            "complete-from-author when it is not",
            "reports a proposed split",
            "invisible at the point of use is not a deferral",
            "evidence to VERIFY, never authority",
            "code-scanning/alerts",
            "output.summary",
            "EMPTY bodies",
            "A RED aggregate means REAL ALERTS",
            "There is no \"aggregation race\"",
            "NEVER FULLY ANALYSED",
            "merge-cleanliness against the CURRENT target",
            "Predict, capture, diff",
            "a PR comment is publication",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, main)

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
        referenced = re.findall(
            r"skills/[a-z0-9.-]+/references/[a-z0-9.-]+\.md", contract
        )
        self.assertIn(
            "skills/gh-pr-flow/references/evidence-doctrine.md", referenced
        )
        for reference in sorted(set(referenced)):
            with self.subTest(reference=reference):
                self.assertTrue((ROOT / reference).is_file())
        # The two authority facts that agents got wrong when the protocol
        # described the transition without naming who performs it.
        for fragment in (
            "That removal is NOT a readiness signal",
            "performs the flip from draft to ready",
            # The role has to be DEFINED where the contract first uses it.
            "whoever is directing the work",
            "the APPROVE verdict and coordinator flip that make a PR ready",
            "the owner then merges",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, contract)


if __name__ == "__main__":
    unittest.main()
