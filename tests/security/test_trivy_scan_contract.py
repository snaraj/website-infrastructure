"""Keep Trivy exceptions narrower than the controls they compensate for."""

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PULL_REQUEST = REPO_ROOT / ".github" / "workflows" / "pull-request.yml"
SCHEDULED = REPO_ROOT / ".github" / "workflows" / "scheduled-security.yml"
IGNORE_FILE = REPO_ROOT / "policies" / "trivy-ignore.yaml"


def ignore_entries(text):
    """Return finding paths from the intentionally small Trivy YAML subset."""

    entries = {}
    for match in re.finditer(
        r"(?ms)^  - id:\s*([^\s]+)\s*\n(.*?)(?=^  - id:|\Z)", text
    ):
        finding_id, body = match.groups()
        paths_match = re.search(r"(?ms)^    paths:\s*\n(.*?)(?=^    \w|\Z)", body)
        paths = set()
        if paths_match:
            paths = {
                value.strip().strip("'\"")
                for value in re.findall(r"(?m)^      -\s+(.+?)\s*$", paths_match.group(1))
            }
        entries[finding_id] = paths
    return entries


class TrivyScanContractTests(unittest.TestCase):
    """Prevent an accepted scanner finding from becoming a broad bypass."""

    def test_workflows_keep_full_tree_secret_scanning(self):
        """Skipping intentional misconfigurations must never skip secret files."""

        full_tree = (
            "trivy fs --exit-code 1 --ignore-unfixed "
            "--scanners vuln,secret --severity HIGH,CRITICAL ."
        )
        compensating_validators = {
            PULL_REQUEST: "python3 scripts/validate_repository.py all",
            SCHEDULED: "python3 scripts/validate_repository.py kubernetes",
        }
        for path, validator in compensating_validators.items():
            workflow = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIn(full_tree, workflow)
                self.assertIn("--ignorefile policies/trivy-ignore.yaml", workflow)
                self.assertIn(validator, workflow)
                self.assertLess(
                    workflow.index(validator),
                    workflow.index("--ignorefile policies/trivy-ignore.yaml"),
                )
                self.assertIn(
                    "--skip-dirs ./tests/kubernetes/fixtures/deny", workflow
                )
                self.assertIn("--scanners misconfig", workflow)
                self.assertNotIn("--skip-files", workflow)

    def test_ignore_file_allows_only_reviewed_ids_and_paths(self):
        """Every accepted result stays coupled to one known source artifact."""

        text = IGNORE_FILE.read_text(encoding="utf-8")
        generated = ".artifacts/rendered/kubernetes-flux-system.yaml"
        self.assertEqual(
            ignore_entries(text),
            {
                "AVD-KSV-0041": {
                    "kubernetes/flux-system/controllers/gotk-components.yaml",
                    generated,
                },
                "AVD-KSV-0046": {
                    "kubernetes/flux-system/controllers/gotk-components.yaml",
                    generated,
                },
                "AVD-KSV-0056": {
                    "kubernetes/flux-system/access.yaml",
                    generated,
                },
            },
        )
        self.assertEqual(text.count("expired_at: 2027-08-08"), 3)
        self.assertEqual(text.count("statement: >-"), 3)
        self.assertNotIn("vulnerabilities:", text)
        self.assertNotIn("secrets:", text)

    def test_skipped_deny_directory_remains_executable_policy_input(self):
        """Trivy excludes test intent, while both policy engines still reject it."""

        conftest = REPO_ROOT.joinpath("scripts", "test-policy-fixtures.sh").read_text(
            encoding="utf-8"
        )
        kyverno = REPO_ROOT.joinpath(
            "tests", "kubernetes", "kyverno", "kyverno-test.yaml"
        ).read_text(encoding="utf-8")
        objective_two = REPO_ROOT.joinpath(
            "tests", "kubernetes", "kyverno", "objective2", "kyverno-test.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("tests/kubernetes/fixtures/deny/*.yaml", conftest)
        self.assertIn("../fixtures/deny/insecure.yaml", kyverno)
        self.assertIn("../../fixtures/deny/objective2-bypasses.yaml", objective_two)


if __name__ == "__main__":
    unittest.main()
