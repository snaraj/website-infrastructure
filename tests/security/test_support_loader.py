"""Pin `tests/security/support.py`'s own loader.

`load_script` publishes each subject under its module name so a PEP 563 string
annotation can resolve while the body runs — without it any script carrying
`from __future__ import annotations` and a dataclass dies at class creation with
a bare `AttributeError` on `None`. The name must then be gone again, or the
docstring's promise that "the copies stay visibly independent" is false and one
battery's subject becomes importable by the next. These pin the cleanup on both
exits (PR #305 round 4, finding 1).
"""

from __future__ import annotations

import sys
import unittest

from .support import load_script

PROBE = "support_loader_probe"


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

    def test_two_loads_of_one_script_stay_independent(self):
        # The property the cleanup protects: each load is a private copy, so a
        # value set on one is not observable through the other.
        first = load_script("ci/deploy_assurance.py", module_name=PROBE)
        second = load_script("ci/deploy_assurance.py", module_name=PROBE)
        self.assertIsNot(first, second)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
