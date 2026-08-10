import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_no_security_toggles.py"

spec = importlib.util.spec_from_file_location("validate_no_security_toggles", SCRIPT)
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


def matches_any(line):
    return [label for label, pattern in MODULE.TOGGLE_PATTERNS if pattern.search(line)]


class NoSecurityTogglesTests(unittest.TestCase):
    def test_tracked_tree_has_no_unjustified_toggle(self):
        self.assertEqual(MODULE.toggle_errors(str(REPO_ROOT)), [])

    def test_hostile_toggle_idioms_are_detected(self):
        # Hostile fixtures are runtime-assembled so this file never holds a
        # toggle idiom at rest.
        hostile_lines = (
            "SK" + "IP_SIGNATURE_CHECK=1 ./release.sh",
            "export " + "DIS" + "ABLE_POLICY_ENFORCEMENT=true",
            "BY" + "PASS_ADMISSION_GATE: yes",
            "ALLOW_" + "UNSIGNED=1 helm push",
            "cosign verify " + "--in" + "secure image",
            "git push " + "--no-" + "verify",
            "gate " + "--sk" + "ip-checks",
            "curl " + "--sk" + "ip-tls-validation",
            "cosign " + "verify" + "=false",
        )
        for line in hostile_lines:
            with self.subTest(line=line[:24]):
                self.assertTrue(matches_any(line), line)

    def test_benign_lines_do_not_match(self):
        benign = (
            "skip the introduction section",
            "disable_animation: true",
            "the bypass road is closed",
            "verify everything twice",
            "SKIP_LIST = ['a', 'b']",
            "--skip-token-print keeps the token out of logs",
        )
        for line in benign:
            label = matches_any(line)
            with self.subTest(line=line[:24]):
                if line.startswith("--" + "sk"):
                    # The kubeadm flag DOES match the closed skip-flag idiom;
                    # it is legal only through the justified allowlist, which
                    # keeps the exemption reviewable instead of pattern-holed.
                    self.assertTrue(label)
                else:
                    self.assertFalse(label, line)

    def test_stale_allowlist_entry_is_an_error(self):
        original = MODULE.ALLOWLIST
        try:
            MODULE.ALLOWLIST = original + (
                ("docs/README-nonexistent.md", "never-present-fragment", "stale"),
            )
            errors = MODULE.toggle_errors(str(REPO_ROOT))
            self.assertTrue(
                any("allowlist entry no longer matches" in error for error in errors)
            )
        finally:
            MODULE.ALLOWLIST = original

    def test_self_exempt_markers_are_present_and_tamper_checked(self):
        for name, marker in MODULE.SELF_EXEMPT.items():
            with self.subTest(name=name):
                self.assertIn(marker, (REPO_ROOT / name).read_text(encoding="utf-8"))
        original = MODULE.SELF_EXEMPT
        try:
            MODULE.SELF_EXEMPT = dict(original)
            MODULE.SELF_EXEMPT["scripts/validate_no_security_toggles.py"] = (
                "marker-that-is-absent"
            )
            errors = MODULE.toggle_errors(str(REPO_ROOT))
            self.assertTrue(
                any("self-exempt marker is missing" in error for error in errors)
            )
        finally:
            MODULE.SELF_EXEMPT = original


if __name__ == "__main__":
    unittest.main()
