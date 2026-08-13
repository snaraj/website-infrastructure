#!/usr/bin/env python3
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "build-website-infrastructure"
PR_FLOW = ROOT / "skills" / "gh-pr-flow"
# Every committed skill is a portable METHOD, so all of them are held to one
# structure contract: the official frontmatter shape, bounded documents, every
# reference linked from SKILL.md, and no trace of THIS repository's identity.
# A skill that names this repository's sites, owner, hosts, commits, issue
# numbers, or a workstation path is no longer reusable anywhere else.
GOVERNED_SKILLS = (SKILL, PR_FLOW)
FORBIDDEN_IDENTITY = (
    "naranjo.online",
    "lidersea.com",
    "snaraj",
    "pi-admin",
    "pi-websites",
)
# Identity that only one skill is realistically at risk of absorbing: the
# media-storage vocabulary that produced the first skill, and the repository
# and agent-label names that the pull-request flow is written from.
SKILL_LOCAL_FORBIDDEN_IDENTITY = {
    SKILL: (
        "UNRESOLVED_PI_MEDIA_STORAGE",
        "2026-08-08",
        "512 MB",
        "protected `main`",
        "GHCR repository",
        "SOPS identity install",
    ),
    PR_FLOW: (
        "website-infrastructure",
        "fable5",
        "opus5",
        "opus4.8",
        "5.6-sol",
        "Codex",
    ),
}
# Shapes, not literals: a pinned commit, a bare commit, a workstation path in
# either platform's spelling, and a cross-reference to an issue or pull request
# that only exists in this repository.
FORBIDDEN_IDENTITY_SHAPES = {
    # Subsumed by "bare commit" below — every pinned form also matches the
    # bare one — and kept only so the failure message names the likelier
    # mistake. It is not an independent guard; do not read it as one.
    "pinned commit": re.compile(r"@[0-9a-f]{40}\b"),
    "bare commit": re.compile(r"(?<![0-9a-zA-Z])[0-9a-f]{40}(?![0-9a-zA-Z])"),
    "windows workstation path": re.compile(r"(?i)[A-Z]:[\\/](?:Users|dev)[\\/]"),
    "posix workstation path": re.compile(
        r"(?<![A-Za-z0-9_.-])/(?:Users|home)/[A-Za-z0-9._-]+/"
    ),
    "repository item reference": re.compile(
        r"(?i)\b(?:pull requests?|prs?|issues?)\s*#[0-9]+"
    ),
}


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
    def test_frontmatter_matches_official_validator_contract(self):
        for skill in GOVERNED_SKILLS:
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
        for skill in GOVERNED_SKILLS:
            combined = skill_documents(skill)
            forbidden = (
                *FORBIDDEN_IDENTITY,
                *SKILL_LOCAL_FORBIDDEN_IDENTITY[skill],
            )
            for value in forbidden:
                with self.subTest(skill=skill.name, value=value):
                    self.assertNotIn(value.lower(), combined.lower())
            for label, shape in FORBIDDEN_IDENTITY_SHAPES.items():
                with self.subTest(skill=skill.name, shape=label):
                    self.assertNotRegex(combined, shape)

    def test_all_references_are_linked_and_documents_stay_focused(self):
        for skill in GOVERNED_SKILLS:
            main = (skill / "SKILL.md").read_text(encoding="utf-8")
            references = sorted((skill / "references").glob("*.md"))
            for reference in references:
                with self.subTest(skill=skill.name, reference=reference.name):
                    self.assertIn(f"references/{reference.name}", main)
                    self.assertLessEqual(
                        len(reference.read_text(encoding="utf-8").splitlines()),
                        200,
                    )
            with self.subTest(skill=skill.name):
                self.assertLessEqual(len(main.splitlines()), 500)

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
            "Disabling enforcement wholesale",
            "MULTI-DOCUMENT deny fixture",
            "its own SOURCE TEXT",
            "reads its THRESHOLD from the artifact it verifies",
            "satisfied by a COMMENT",
            "whose CALL SITE no test invokes",
            "DIFFERENTIAL harness",
            "bind scope to KIND",
            "Patching by INDEX",
            "likeliest survivors",
            "NO killer",
            "BAD MUTANT",
            "NORMALISATION",
            "TRUE NEGATIVES",
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
            "The COORDINATOR performs the flip",
            "the owner then merges",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, contract)


if __name__ == "__main__":
    unittest.main()
