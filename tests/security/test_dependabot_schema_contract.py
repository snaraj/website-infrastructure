"""Pin the closed `.github/dependabot.yml` schema: a misspelled key must fail."""

import tempfile
import unittest
from pathlib import Path

from .support import load_script

MODULE = load_script("validate_repository.py")


class DependabotSchemaTests(unittest.TestCase):
    def test_the_live_configuration_satisfies_the_closed_schema(self):
        self.assertIn("dependabot", MODULE.CHECKS)
        self.assertEqual(MODULE.check_dependabot(MODULE.ROOT), [])

    def test_a_misspelled_key_fails_where_every_other_gate_passes(self):
        # The exact reviewer mutation: Dependabot ignores `paterns:`, so the
        # group stops matching and nothing else in the repository notices.
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        target = scratch / MODULE.DEPENDABOT_PATH
        target.parent.mkdir(parents=True)
        original = (MODULE.ROOT / MODULE.DEPENDABOT_PATH).read_text(encoding="utf-8")
        target.write_text(original.replace("patterns:", "paterns:"), encoding="utf-8")
        self.assertTrue(any("paterns" in e for e in MODULE.check_dependabot(scratch)))
        target.write_text(original, encoding="utf-8")
        self.assertEqual(MODULE.check_dependabot(scratch), [])


if __name__ == "__main__":
    unittest.main()
