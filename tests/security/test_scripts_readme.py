"""Keep the concise scripts guide complete as the control surface evolves."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"


class ScriptsReadmeTests(unittest.TestCase):
    """Require every executable helper to explain its role in one short guide."""

    def test_every_script_is_linked_exactly_once(self):
        readme = (SCRIPTS / "README.md").read_text(encoding="utf-8")
        for path in sorted(SCRIPTS.rglob("*")):
            if not path.is_file() or path.suffix not in {".py", ".sh", ".ps1"}:
                continue
            relative = path.relative_to(SCRIPTS).as_posix()
            with self.subTest(script=relative):
                self.assertEqual(readme.count(f"(./{relative})"), 1)

    def test_guide_stays_one_paragraph_and_one_diagram(self):
        readme = (SCRIPTS / "README.md").read_text(encoding="utf-8")
        before_diagram = readme.split("```mermaid", 1)[0]
        prose_blocks = [
            block for block in before_diagram.split("\n\n")
            if block and not block.startswith("# ")
        ]
        self.assertEqual(len(prose_blocks), 1)
        self.assertEqual(readme.count("```mermaid"), 1)


if __name__ == "__main__":
    unittest.main()
