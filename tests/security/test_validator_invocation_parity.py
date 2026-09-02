"""Pin the Python validator inventory identical across its three surfaces.

The repository invokes its ``validate_*.py`` policy validators from two
lanes — the local credential-free entry point
(``scripts/validate-security.sh``) and the pull-request workflow's inline
steps — and documents every validator in ``scripts/README.md``. Those
surfaces have drifted before: commit 3ad45c6 ("ci: bound every job with
timeouts; close the validate-security mode gap") had to retrofit the
media and activation modes into validate-security.sh after the local
entry point silently ran less than CI's terminal gate. This suite turns
that class of drift into a red test instead of a future audit finding:

* every validator the local entry point runs must also run in CI;
* a validator that CI runs inline but the local entry point does not must
  be one of the explicitly justified entries below — exactly, in both
  directions, so a stale justification fails as loudly as a missing one —
  and each justification names the tracked local surface that provides
  parity, which this suite re-verifies so the reason cannot rot;
* every validator named on either invocation surface must exist as a
  tracked script and be documented (linked) in scripts/README.md, whose
  "Adding a validator" checklist enumerates exactly these surfaces.

The parse deliberately keys on one stable signature — a non-comment line
naming ``scripts/validate_*.py`` (for the workflow, one that also invokes
``python``) — not on step names, YAML structure, or ordering, so
reformatting cannot fool it and a renamed or deleted validator fails the
existence check rather than vanishing from the comparison.
"""

import re
import unittest

from .support import REPO_ROOT, SCRIPTS_DIR, load_script

REPOSITORY_VALIDATOR = load_script(
    "validate_repository.py", module_name="parity_validate_repository"
)

LOCAL_ENTRY_POINT = SCRIPTS_DIR / "validate-security.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pull-request.yml"
SCRIPTS_README = SCRIPTS_DIR / "README.md"

VALIDATOR_NAME = re.compile(r"scripts/(validate_\w+\.py)")
README_LINK = re.compile(r"\]\(\./(validate_\w+\.py)\)")

# Validators CI runs inline that the local entry point deliberately does
# not. Every entry must name the tracked local surface that provides the
# equivalent local run; the justification is load-bearing because the
# named file must still contain the named invocation fragment.
CI_ONLY = {
    "validate_publication_history.py": (
        "consumes the pull_request event's immutable base/head range; the "
        "local equivalent is the pre-push gate, which runs it over "
        "origin/main..HEAD",
        "scripts/pre-push-security.sh",
        "scripts/validate_publication_history.py",
    ),
    "validate_release_transition.py": (
        "the CI inline call is select-mode, choosing the render flag for "
        "the render step; every local render runs the validator's plan "
        "mode through the render lane",
        "scripts/render-manifests.sh",
        "scripts/validate_release_transition.py",
    ),
    "validate_ingress_guard.py": (
        "runs locally through the dedicated ingress-guard lane that "
        "'make check' includes",
        "Makefile",
        "validate_ingress_guard.py repo",
    ),
    "validate_admin_ingress_contract.py": (
        "runs locally through the dedicated ingress-guard lane that "
        "'make check' includes",
        "Makefile",
        "validate_admin_ingress_contract.py EXAMPLE",
    ),
}


# The check names `validate_repository.py` accepts, as they appear on an
# invocation line: lowercase words with no option dash, path separator, or
# shell expansion. Everything else on that line (the interpreter, `-B`, the
# quoted script path) fails this shape.
MODE_WORD = re.compile(r"^[a-z][a-z0-9]*$")

# Registry entries the credential-free local entry point deliberately does not
# run, each with the surface that does run it. Same load-bearing shape as
# CI_ONLY above: the named file must still contain the named invocation, so a
# justification cannot outlive the parity it claims.
LOCAL_MODE_EXCLUSIONS = {
    "release": (
        "the release gate asserts deployment sentinels rather than repository "
        "invariants; it runs through 'make release-check' and, in CI, through "
        "the release-transition lane, and validate_repository's own 'all' "
        "selection excludes it for the same reason",
        "Makefile",
        "validate_repository.py release",
    ),
}


def repository_check_modes(path):
    """Return the check names one surface passes to validate_repository.py.

    Keyed on the invocation itself rather than on step names or ordering: a
    non-comment line naming the validator, everything after the script path
    that still looks like a mode word. That is deliberately the same parsing
    discipline as ``named_validators`` above.
    """

    modes = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "validate_repository.py" not in stripped:
            continue
        _, _, tail = stripped.partition("validate_repository.py")
        modes.extend(word for word in tail.split() if MODE_WORD.match(word))
    return modes


def named_validators(path, *, require_python=False):
    """Collect validate_*.py names from non-comment lines of one surface."""

    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if require_python and "python" not in stripped:
            continue
        names.update(VALIDATOR_NAME.findall(stripped))
    return names


class ValidatorInvocationParityTests(unittest.TestCase):
    """One validator inventory; three surfaces; zero silent drift."""

    @classmethod
    def setUpClass(cls):
        cls.local = named_validators(LOCAL_ENTRY_POINT)
        cls.ci = named_validators(WORKFLOW, require_python=True)
        cls.documented = set(
            README_LINK.findall(SCRIPTS_README.read_text(encoding="utf-8"))
        )

    def test_each_surface_parse_finds_its_known_floor(self):
        # A regex that silently stops matching would make every subset
        # assertion below pass vacuously; pin each surface's minimum.
        self.assertGreaterEqual(len(self.local), 4, sorted(self.local))
        self.assertGreaterEqual(len(self.ci), 8, sorted(self.ci))
        self.assertGreaterEqual(len(self.documented), 20, sorted(self.documented))

    def test_every_local_validator_also_runs_in_ci(self):
        missing = self.local - self.ci
        self.assertFalse(
            missing,
            "validate-security.sh runs validators the pull-request workflow "
            "does not: {} — commit 3ad45c6 closed exactly this class of gap; "
            "add the inline invocation or the local run is not CI-verified"
            .format(sorted(missing)),
        )

    def test_ci_only_validators_are_exactly_the_justified_set(self):
        ci_only = self.ci - self.local
        unjustified = ci_only - set(CI_ONLY)
        stale = set(CI_ONLY) - ci_only
        self.assertFalse(
            unjustified,
            "CI runs validators the local entry point does not, without a "
            "justification: {} — either add them to validate-security.sh or "
            "justify the asymmetry here with its local surface"
            .format(sorted(unjustified)),
        )
        self.assertFalse(
            stale,
            "stale CI-only justifications (no longer CI-only, or no longer "
            "invoked inline): {} — remove or correct them".format(sorted(stale)),
        )

    def test_ci_only_justifications_name_real_local_surfaces(self):
        for name, (reason, surface, fragment) in sorted(CI_ONLY.items()):
            with self.subTest(validator=name):
                self.assertGreaterEqual(len(reason), 40, "justify properly")
                surface_path = REPO_ROOT / surface
                self.assertTrue(surface_path.is_file(), surface)
                self.assertIn(
                    fragment,
                    surface_path.read_text(encoding="utf-8"),
                    "the justification for {} points at {}, which no longer "
                    "contains {!r}; the claimed local parity is gone"
                    .format(name, surface, fragment),
                )

    def test_every_invoked_validator_exists_and_is_documented(self):
        for name in sorted(self.local | self.ci):
            with self.subTest(validator=name):
                self.assertTrue(
                    (SCRIPTS_DIR / name).is_file(),
                    "an invocation surface names {} but no such tracked "
                    "script exists".format(name),
                )
                self.assertIn(
                    name,
                    self.documented,
                    "{} is invoked but not documented in scripts/README.md"
                    .format(name),
                )

class RepositoryCheckModeParityTests(unittest.TestCase):
    """The eight mode words are bound to ``validate_repository.CHECKS``.

    Issue #153, from PR #151's adversarial review: deleting a mode word from
    ``validate-security.sh`` survived the whole battery. The suite above keys
    on ``scripts/validate_*.py`` PATHS, so it sees one validator invoked and
    notices nothing when that invocation silently stops selecting a check —
    and the eight words are eight separate categories of repository invariant,
    each of which simply stops running. Nothing else in the tree compared the
    list to the registry it indexes.

    A set comparison is what makes both directions fail: a word deleted from
    the shell no longer covers its registry entry, and an entry deleted from
    the registry leaves a word the shell would pass and argparse would refuse.
    """

    @classmethod
    def setUpClass(cls):
        cls.local_modes = repository_check_modes(LOCAL_ENTRY_POINT)
        cls.registry = set(REPOSITORY_VALIDATOR.CHECKS)

    def test_the_mode_parse_finds_its_known_floor(self):
        # The same anti-vacuity floor the validator-name parse carries: a
        # regex that stopped matching would make the equality below compare
        # two empty sets and pass forever.
        self.assertGreaterEqual(len(self.local_modes), 8, self.local_modes)
        self.assertGreaterEqual(len(self.registry), 9, sorted(self.registry))

    def test_the_local_entry_point_names_each_mode_once(self):
        self.assertEqual(
            sorted(self.local_modes),
            sorted(set(self.local_modes)),
            "a repeated mode word runs a check twice and hides a missing one",
        )

    def test_the_mode_words_are_exactly_the_registry_minus_its_exclusions(self):
        expected = self.registry - set(LOCAL_MODE_EXCLUSIONS)
        actual = set(self.local_modes)
        self.assertEqual(
            actual,
            expected,
            "validate-security.sh's mode words and validate_repository.CHECKS "
            "have drifted — dropped from the shell: {}; missing a "
            "justification: {}".format(
                sorted(expected - actual), sorted(actual - expected)
            ),
        )

    def test_every_exclusion_is_a_real_registry_entry_with_a_live_surface(self):
        for name, (reason, surface, fragment) in sorted(
            LOCAL_MODE_EXCLUSIONS.items()
        ):
            with self.subTest(mode=name):
                self.assertIn(
                    name,
                    self.registry,
                    "{} is excluded from the local entry point but is no "
                    "longer a registry check at all".format(name),
                )
                self.assertGreaterEqual(len(reason), 40, "justify properly")
                surface_path = REPO_ROOT / surface
                self.assertTrue(surface_path.is_file(), surface)
                self.assertIn(
                    fragment,
                    surface_path.read_text(encoding="utf-8"),
                    "the justification for excluding {} points at {}, which "
                    "no longer contains {!r}".format(name, surface, fragment),
                )

    def test_the_workflow_runs_the_terminal_all_selection(self):
        # `all` expands, inside the validator, to the registry minus `release`.
        # Pinning the word here is what makes the local list above the
        # complete statement of what CI's terminal gate covers.
        self.assertIn("all", repository_check_modes(WORKFLOW))


if __name__ == "__main__":
    unittest.main()
