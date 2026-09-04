"""Pin the security suite's own machinery: the shared loader, and the shape
every battery in the package has to keep.

`load_script` publishes each subject under its module name so a PEP 563 string
annotation can resolve while the body runs — without it any script carrying
`from __future__ import annotations` and a dataclass dies at class creation with
a bare `AttributeError` on `None`. The name must then be gone again, or the
docstring's promise that "the copies stay visibly independent" is false and one
battery's subject becomes importable by the next (PR #305 round 4).

`EntrypointLayoutTests` covers the other half: a battery's `__main__` guard has
to be the LAST top-level statement, because a guard placed above a class runs
`unittest.main()` before that class exists and its tests vanish from direct
execution while discovery still reports them (PR #305 rounds 4 and 5). The gate
runs discovery, so nothing else in the suite can see that regression.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

from .support import load_script

PROBE = "support_loader_probe"
SECURITY_DIR = Path(__file__).resolve().parent


class LoadScriptCleanupTests(unittest.TestCase):
    def tearDown(self):
        sys.modules.pop(PROBE, None)

    def test_an_absent_name_is_absent_again_after_a_successful_load(self):
        self.assertNotIn(PROBE, sys.modules)
        module = load_script("ci/deploy_assurance.py", module_name=PROBE)
        self.assertTrue(hasattr(module, "Estimate"), "the subject really did execute")
        self.assertNotIn(PROBE, sys.modules)

    def test_a_pre_existing_name_is_restored_after_a_successful_load(self):
        sentinel = object()
        sys.modules[PROBE] = sentinel
        load_script("ci/deploy_assurance.py", module_name=PROBE)
        self.assertIs(sys.modules[PROBE], sentinel)

    def test_a_subject_whose_body_fails_leaks_no_name(self):
        self.assertNotIn(PROBE, sys.modules)
        with self.assertRaises(FileNotFoundError):
            load_script("no_such_script_for_this_test.py", module_name=PROBE)
        self.assertNotIn(PROBE, sys.modules)

    def test_a_subject_whose_body_fails_restores_a_pre_existing_name(self):
        sentinel = object()
        sys.modules[PROBE] = sentinel
        with self.assertRaises(FileNotFoundError):
            load_script("no_such_script_for_this_test.py", module_name=PROBE)
        self.assertIs(sys.modules[PROBE], sentinel)

    def test_a_pre_existing_none_entry_is_restored_not_dropped(self):
        # A stored `None` is Python's import-blocking marker, not absence, so
        # it must come back rather than be popped as a never-present key.
        for label in ("success", "failure"):
            with self.subTest(path=label):
                sys.modules[PROBE] = None
                if label == "failure":
                    with self.assertRaises(FileNotFoundError):
                        load_script("no_such_script_for_this_test.py", module_name=PROBE)
                else:
                    load_script("ci/deploy_assurance.py", module_name=PROBE)
                self.assertIn(PROBE, sys.modules)
                self.assertIsNone(sys.modules[PROBE])

    def test_two_loads_of_one_script_stay_independent(self):
        # The property the cleanup protects: each load is a private copy, so a
        # value set on one is not observable through the other.
        first = load_script("ci/deploy_assurance.py", module_name=PROBE)
        second = load_script("ci/deploy_assurance.py", module_name=PROBE)
        self.assertIsNot(first, second)


class EntrypointLayoutTests(unittest.TestCase):
    """Every `tests/security/test_*.py` keeps its `__main__` guard last."""

    def test_every_battery_puts_its_main_guard_last(self):
        modules = sorted(SECURITY_DIR.glob("test_*.py"))
        self.assertGreater(len(modules), 1, "the scan must actually find batteries")
        for path in modules:
            with self.subTest(module=path.name):
                body = ast.parse(path.read_text(encoding="utf-8"), filename=str(path)).body
                guards = [i for i, node in enumerate(body) if _is_main_guard(node)]
                self.assertLessEqual(len(guards), 1, "one entrypoint guard at most")
                for index in guards:
                    trailing = [type(node).__name__ for node in body[index + 1:]]
                    self.assertEqual(
                        trailing, [],
                        f"{path.name}: the __main__ guard is followed by {trailing}; "
                        "anything after it is invisible to direct execution",
                    )


def _is_main_guard(node):
    """``if __name__ == "__main__":`` at module level, however it is spelled."""

    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        return False
    left, comparators = node.test.left, node.test.comparators
    names = [n.id for n in (left,) if isinstance(n, ast.Name)]
    values = [c.value for c in comparators if isinstance(c, ast.Constant)]
    return "__name__" in names and "__main__" in values


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
