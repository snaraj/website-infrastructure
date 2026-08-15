import re
import unittest
from pathlib import Path

from . import test_actions_zero_spend_exposure as actions_contract
from .support import load_script


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "gh-pr-flow"
RECEIPTS = load_script("validate_review_receipt.py", module_name="flow_receipts")


class GitHubFlowSkillContractTests(unittest.TestCase):
    def test_frontmatter_references_and_interface_are_portable(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---", main, re.DOTALL)
        self.assertIsNotNone(match)
        keys = [line.split(":", 1)[0] for line in match.group(1).splitlines() if ":" in line]
        self.assertEqual(keys, ["name", "description"])
        self.assertLessEqual(len(main.splitlines()), 500)
        body = main.split("---", 2)[2]
        for heading in re.findall(r"^## (.+)$", body, re.MULTILINE):
            with self.subTest(imperative_heading=heading):
                self.assertNotRegex(heading, r"^When to use", re.IGNORECASE)
        references = sorted((SKILL / "references").glob("*.md"))
        self.assertEqual(
            [path.name for path in references],
            [
                "destructive-workloads.md",
                "evidence-doctrine.md",
                "governance.md",
                "releases.md",
                "reviews.md",
            ],
        )
        for reference in references:
            with self.subTest(reference=reference.name):
                self.assertIn(f"references/{reference.name}", main)
                self.assertLessEqual(len(reference.read_text(encoding="utf-8").splitlines()), 200)
                self.assertNotRegex(
                    reference.read_text(encoding="utf-8"),
                    r"\]\((?:\.\./|references/)[^)]+\.md\)",
                )
        files = sorted(
            path.relative_to(SKILL).as_posix()
            for path in SKILL.rglob("*")
            if path.is_file()
        )
        self.assertEqual(
            files,
            [
                "SKILL.md",
                "agents/openai.yaml",
                "references/destructive-workloads.md",
                "references/evidence-doctrine.md",
                "references/governance.md",
                "references/releases.md",
                "references/reviews.md",
            ],
        )
        interface = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertEqual(
            interface,
            'interface:\n'
            '  display_name: "GitHub PR Flow"\n'
            '  short_description: "Owner-only merge flow with exact-head review and releases"\n'
            '  default_prompt: "Use $gh-pr-flow to handle this GitHub change with issue-first metadata, isolated append-only authoring, exact-head adversarial review, an enforced release consequence, and absolute NEVER MERGE authority."\n'
            'policy:\n'
            '  allow_implicit_invocation: true\n',
        )

    def test_authority_review_release_and_metadata_controls_are_load_bearing(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        governance = (SKILL / "references" / "governance.md").read_text(encoding="utf-8")
        reviews = (SKILL / "references" / "reviews.md").read_text(encoding="utf-8")
        releases = (SKILL / "references" / "releases.md").read_text(encoding="utf-8")
        for fragment, text in (
            ("**NEVER MERGE**", main),
            ("Stop and question even a later request", main),
            ("Only the coordinator flips Ready", main),
            ("exact standalone `Closes #N`", main),
            ("Dependabot", main),
            ("Never apply or interpret it on an\n   issue", main),
            ("--resource-kind pull-request", main),
            ("owner assignee", main),
            ("milestone", main),
            ("exact proposed `vX.Y.Z` milestone", main),
            ("never infer completion from a title", main),
            ("repo-specific coverage", main),
            ("neutral/skipped/canceled", main),
            ("HEAD: <40-lowercase-hex>", reviews),
            ("VERDICT: REQUEST-CHANGES", reviews),
            ("Any new commit invalidates", reviews),
            ("POST-MERGE AUDIT", reviews),
            ("shared account", governance),
            ("**Author:**", governance),
            ("**Reviewer:**", governance),
            ("**Coordinator/Main Worker:**", governance),
            ("**Owner:**", governance),
            ("`requires-review` is PR-head-only", governance),
            ("cannot satisfy a PR receipt or Ready gate", governance),
            ("Infrastructure/tool outages", governance),
            ("required checks", governance),
            ("strict", governance),
            ("bypass actors", governance),
            ("Every merge", releases),
            ("exactly one patch", releases),
            ("every intermediate\n`VERSION` state", releases),
            ("transient future values", releases),
            ("same complete-history monotonic state machine", releases),
            ("publisher-recoverable release intent", releases),
            ("Distinct main SHAs", releases),
            ("two and three rapid merges", releases),
            ("burned/conflicting", releases),
            ("For Helm OCI", releases),
            ("never permits numeric Git/image tags", releases),
            ("authoritative\nimmutable-release control", releases),
            ("foreign-author", releases),
            ("exact source SHA", releases),
            ("branch/ref-only key", releases),
            ("positive `timeout-minutes`", releases),
            ("checksum-verified immutable version", releases),
            ("HIGH/CRITICAL", releases),
            ("registry digest", releases),
            ("verified mutable alias", releases),
            ("human notes as\ninformational", releases),
            ("mode 0600", releases),
            ("deterministic machine-readable manifest", releases),
            ("exact asset name, count, size", releases),
            ("Actions policy", governance),
            ("SHA-pinning", governance),
            ("signed protected-main commits", governance),
            ("`refs/heads/main`", governance),
            ("empty/mis-scoped include", governance),
            ("problem, acceptance", governance),
            ("threats, tests/mutations, exclusions, rollout/rollback", governance),
            ("exactly match the\nproposed `VERSION` as `vX.Y.Z`", governance),
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)

    def test_issue_form_carries_the_issue_first_minimum_schema(self):
        form = (ROOT / ".github" / "ISSUE_TEMPLATE" / "change.yml").read_text(
            encoding="utf-8"
        )
        config = (ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(
            encoding="utf-8"
        )
        for fragment in (
            "Problem and invariant",
            "Acceptance criteria",
            "Threats and failure modes",
            "Tests and mutation plan",
            "Scope and exclusions",
            "Rollout and rollback",
            "Exact release milestone",
            "scope and agent-provenance labels",
            "repository owner will be assigned",
            "standalone `Closes #N`",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, form)
        self.assertEqual(form.count("required: true"), 10)
        self.assertEqual(config, "blank_issues_enabled: false\n")

    def test_rapid_main_audits_have_distinct_sha_groups_and_job_timeouts(self):
        codeql = (ROOT / ".github" / "workflows" / "codeql.yml").read_text(
            encoding="utf-8"
        )
        platform = (
            ROOT / ".github" / "workflows" / "platform-release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.number || github.sha || github.run_id", codeql)
        self.assertNotIn("github.event.pull_request.number || github.ref", codeql)
        first = "1" * 40
        second = "2" * 40

        def group(pr_number, sha, run_id):
            return "codeql-{}".format(pr_number or sha or run_id)

        self.assertNotEqual(group(None, first, 1), group(None, second, 2))
        self.assertEqual(group(None, first, 1), group(None, first, 2))
        self.assertEqual(group(49, first, 1), group(49, second, 2))
        self.assertRegex(platform, r"(?m)^    timeout-minutes: [1-9][0-9]*$")

    def test_destructive_contract_never_turns_stateful_or_secret_material_ephemeral(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        destructive = (SKILL / "references" / "destructive-workloads.md").read_text(encoding="utf-8")
        for fragment in (
            "engineered and proven",
            "closed positive allowlist",
            "ClusterRole, CRD,\nNamespace, PVC, and Secret",
            "1–32 unique inventory entries",
            "exactly one explicit\n  fault target",
            "clean recreate from zero",
            "termination, restart, node loss, and dependency loss",
            "never encode replica=1",
            "PV/PVC, database, operator",
            "SOPS/age keys and ciphertext",
            "API/Tunnel tokens",
            "public HTTPS recovery proof",
            "prestate hash -> exact fault -> recovery action -> poststate hash",
            "grants no live action",
            "cleanup guard",
            "repeated and mixed signals",
            "one rollback, one bounded\nreceipt, and no residue",
            "uncatchable kill and power loss",
            "recovery journal",
            "mode\n0600 `prepared` recovery journal",
            "scripts/ci/destructive_transaction_fixture.py",
            "neither\nauthenticates live state",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, destructive)
        self.assertIn("Stateful/PV/PVC/database/", main)

    def test_pr_template_requires_release_and_two_independent_receipts(self):
        template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
        for fragment in (
            "Closes #",
            "Exact base",
            "Exact head",
            "Platform source release",
            "requires-review",
            "Independent normal-comment verdict",
            "ROLE: MAIN-WORKER",
            "VERDICT: PASS",
            "Merge order and collision paths",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, template)

    def test_main_worker_is_an_executable_exact_head_ready_gate(self):
        main = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        reviews = (SKILL / "references" / "reviews.md").read_text(encoding="utf-8")
        ready = main.split("## Ready gate", 1)[1].split("\n## ", 1)[0]
        for fragment in (
            "Main Worker",
            "distinct from both author and reviewer",
            "exact head",
            "closed scope",
        ):
            with self.subTest(ready_fragment=fragment):
                self.assertIn(fragment, ready)
        for fragment in (
            "ROLE: MAIN-WORKER",
            "VERDICT: PASS",
            f"SCOPE: {RECEIPTS.MAIN_WORKER_SCOPE}",
            "--receipt-kind\nmain-worker",
            "--required-verdict PASS",
            "Any head\nchange invalidates it",
        ):
            with self.subTest(receipt_fragment=fragment):
                self.assertIn(fragment, reviews)

        head = "a" * 40
        receipt = (
            f"HEAD: {head}\n"
            "ROLE: MAIN-WORKER\n"
            "VERDICT: PASS\n"
            f"SCOPE: {RECEIPTS.MAIN_WORKER_SCOPE}\n\n"
            "- coordinator-context (Main Worker)\n"
        )
        self.assertIsNone(
            RECEIPTS.main_worker_denial(
                receipt,
                head,
                "author-context",
                "reviewer-context",
                "pull-request",
            )
        )
        mutants = (
            receipt.replace(head, "b" * 40),
            receipt.replace("ROLE: MAIN-WORKER", "ROLE: REVIEWER"),
            receipt.replace("VERDICT: PASS", "VERDICT: BLOCK"),
            receipt.replace(RECEIPTS.MAIN_WORKER_SCOPE, "architecture"),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(main_worker_mutant=index):
                self.assertIsNotNone(
                    RECEIPTS.main_worker_denial(
                        mutant,
                        head,
                        "author-context",
                        "reviewer-context",
                        "pull-request",
                    )
                )

    def test_ready_requires_zero_unresolved_blockers(self):
        """Owner attention and merge authority never waive a Ready blocker."""

        skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        ready = skill.split("## Ready gate", 1)[1].split("\n## ", 1)[0]

        def collapsed(text):
            return " ".join(text.split())

        def doctrine_denial(skill_ready, repository_contract):
            required = (
                "Ready means zero unresolved blockers",
                "code, CI, review, sequencing, settings, Main Worker, "
                "metadata, or any other declared gate",
                "Owner review or owner merge authority does not waive a blocker",
                "a blocker-bearing PR stays Draft",
            )
            for document in (skill_ready, repository_contract):
                normalized = collapsed(document)
                for fragment in required:
                    if fragment not in normalized:
                        return "Ready zero-blocker doctrine is incomplete"
            return None

        self.assertIsNone(doctrine_denial(ready, agents))
        normalized_ready = collapsed(ready)
        mutants = (
            normalized_ready.replace(
                "zero unresolved blockers", "some unresolved blockers"
            ),
            normalized_ready.replace(
                "does not waive a blocker", "may waive a blocker"
            ),
            normalized_ready.replace(
                "a blocker-bearing PR stays Draft", "a blocker may leave Draft"
            ),
            normalized_ready.replace("settings, Main Worker, ", ""),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(doctrine_mutant=index):
                self.assertIsNotNone(doctrine_denial(mutant, agents))

        blocker_names = (
            "code",
            "ci",
            "review",
            "sequencing",
            "settings",
            "main_worker",
            "metadata",
            "declared_other",
        )

        def ready_from_packet(packet):
            return not any(packet[name] for name in blocker_names)

        raw_packet = {name: False for name in blocker_names}
        raw_packet.update(owner_reviewed=True, owner_may_merge=True)
        self.assertTrue(ready_from_packet(raw_packet))
        for blocker in blocker_names:
            packet = dict(raw_packet)
            packet[blocker] = True
            with self.subTest(raw_minimal_packet_blocker=blocker):
                self.assertFalse(ready_from_packet(packet))

    def test_agents_ci_map_matches_executable_workflow_trigger_topology(self):
        expected = {
            "codeql.yml": {"pull_request", "push", "schedule", "workflow_dispatch"},
            "platform-release.yml": {"workflow_run"},
            "pull-request.yml": {"pull_request", "push", "workflow_dispatch"},
            "scheduled-security.yml": {"schedule", "workflow_dispatch"},
        }
        actual = {}
        for name in expected:
            path = ROOT / ".github" / "workflows" / name
            shape, violations = actions_contract._parse_workflow(
                path, path.read_text(encoding="utf-8")
            )
            self.assertEqual(violations, [], name)
            actual[name] = shape["events"]
        self.assertEqual(actual, expected)

        def require_documented_topology(text):
            section = text.split("## CI map", 1)[1].split("\n## ", 1)[0]
            fragments = {
                "pull-request.yml": "pull requests, pushes to `main`, and manual dispatch",
                "codeql.yml": "pull requests, `main` pushes, weekly cron, and manual",
                "platform-release.yml": "`workflow_run` of the named Pull request workflow",
                "scheduled-security.yml": "weekly cron full-history scan plus manual",
            }
            for name, fragment in fragments.items():
                if section.count(f"**{name}**") != 1 or fragment not in section:
                    raise ValueError(f"CI map is stale for {name}")
            if "followed success-only by the source publisher" not in section:
                raise ValueError("post-merge publisher topology is absent")

        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        require_documented_topology(agents)
        mutants = (
            agents.replace("pushes to `main`", "does not run on main", 1),
            agents.replace("platform-release.yml", "publisher.yml", 1),
            agents.replace("`workflow_run`", "manual dispatch", 1),
            agents.replace("followed success-only by the source publisher", "publisher omitted", 1),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(ci_map_mutant=index), self.assertRaises(ValueError):
                require_documented_topology(mutant)


if __name__ == "__main__":
    unittest.main()
