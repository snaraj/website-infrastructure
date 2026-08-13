import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("platform_release_contract", ROOT / "scripts" / "ci" / "platform_release_contract.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def event(sha):
    return {
        "repository": {"full_name": "owner/platform"},
        "workflow_run": {
            "name": "Pull request",
            "path": ".github/workflows/pull-request.yml@refs/heads/main",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": sha,
            "head_repository": {"full_name": "owner/platform"},
        },
    }


class EventContractTests(unittest.TestCase):
    SHA = "a" * 40

    def test_exact_success_event_and_every_hostile_identity(self):
        self.assertEqual(MODULE.plan_workflow_run(event(self.SHA), "owner/platform"), self.SHA)
        mutations = (
            ("repository", "full_name", "other/platform"),
            ("workflow_run", "name", "Other"),
            ("workflow_run", "path", ".github/workflows/other.yml"),
            ("workflow_run", "event", "pull_request"),
            ("workflow_run", "status", "in_progress"),
            ("workflow_run", "conclusion", "failure"),
            ("workflow_run", "head_branch", "feature"),
            ("workflow_run", "head_sha", "1234567"),
        )
        for parent, key, value in mutations:
            payload = json.loads(json.dumps(event(self.SHA)))
            payload[parent][key] = value
            with self.subTest(parent=parent, key=key), self.assertRaises(MODULE.ContractError):
                MODULE.plan_workflow_run(payload, "owner/platform")

    def test_workflow_binds_release_to_the_exact_annotated_tag_target(self):
        workflow = (ROOT / ".github" / "workflows" / "platform-release.yml").read_text(encoding="utf-8")
        self.assertNotIn("targetCommitish", workflow)
        self.assertIn('git rev-list -n 1 "${TAG}"', workflow)
        self.assertIn('gh release create "${TAG}" --verify-tag', workflow)


class PublicationStateTests(unittest.TestCase):
    def test_absent_resume_complete_and_burned_states(self):
        classify = MODULE.classify_publication
        self.assertEqual(classify(tag_present=False, tag_exact=False, release_present=False, release_exact=False), "absent")
        self.assertEqual(classify(tag_present=True, tag_exact=True, release_present=False, release_exact=False), "resume-release")
        self.assertEqual(classify(tag_present=True, tag_exact=True, release_present=True, release_exact=True), "complete")
        for values in ((True, False, False, False), (False, False, True, False), (True, True, True, False), (True, False, True, True)):
            with self.subTest(values=values):
                self.assertEqual(classify(tag_present=values[0], tag_exact=values[1], release_present=values[2], release_exact=values[3]), "burned")


class GitTransitionTests(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.run(["git", "-C", str(root), *args], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()

    def commit(self, root, version):
        if version is not None:
            (root / "VERSION").write_text(version + "\n", encoding="utf-8")
            (root / "CHANGELOG.md").write_text(
                f"# Changelog\n\n## [Unreleased]\n\n## [{version}] - 2026-08-13\n\n- release\n",
                encoding="utf-8",
            )
        else:
            (root / "README.md").write_text("initial\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", version or "initial")
        return self.git(root, "rev-parse", "HEAD")

    def test_initial_then_three_rapid_patch_releases_and_stale_events(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-q")
            self.git(root, "branch", "-m", "main")
            commits = [self.commit(root, value) for value in (None, "0.1.0", "0.1.1", "0.1.2")]
            intents = [MODULE.validate_transition(root, commits[i - 1], commits[i], first_parent=True) for i in range(1, 4)]
            self.assertEqual([intent.tag for intent in (intents[2], intents[0], intents[1])], ["v0.1.2", "v0.1.0", "v0.1.1"])
            self.assertEqual(len({intent.source_sha for intent in intents}), 3)
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, commits[1], commits[3], first_parent=True)
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, commits[2], commits[1], first_parent=True)

            self.git(root, "checkout", "-q", "-b", "stale", commits[0])
            stale_head = self.commit(root, "0.1.3")
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_transition(root, commits[3], stale_head, first_parent=False)


class WorkflowStructureTests(unittest.TestCase):
    def test_every_main_sha_has_an_independent_non_deploying_path(self):
        ci = (ROOT / ".github/workflows/pull-request.yml").read_text(encoding="utf-8")
        publish = (ROOT / ".github/workflows/platform-release.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.number || github.run_id", ci)
        self.assertIn("workflow_run:", publish)
        self.assertIn("github.event.workflow_run.head_sha", publish)
        self.assertNotIn("queue:", ci + publish)
        self.assertIn("publication-state", publish)
        for forbidden in ("kubectl", "flux", "tofu apply", "terraform apply", "cloudflared"):
            self.assertNotIn(forbidden, publish.lower())


if __name__ == "__main__":
    unittest.main()
