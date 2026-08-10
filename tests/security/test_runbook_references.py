import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Repository-path references inside runbooks and assurance docs must exist:
# an instruction that cannot be executed as written is documentation rot
# (Phase E case E7). Paths are matched inside backticks to stay precise.
DOC_ROOTS = ("docs/runbooks", "docs/assurance")
PATH_RE = re.compile(
    r"`((?:scripts|bootstrap|policies|kubernetes|tests|docs|infrastructure)"
    r"/[A-Za-z0-9._/-]+)`"
)
# Illustrative names that deliberately do not exist as tracked files.
PLACEHOLDERS = {
    "bootstrap/pi/decisions.env.local",  # ignored-by-design local input
    "bootstrap/pi/cni-manifest.local.yaml",
    "bootstrap/pi/encryption-config.yaml.local",
    "bootstrap/pi/images.lock.local",
    "bootstrap/pi/kubeadm-config.yaml.local",
    "bootstrap/pi/protected-services.env.local",
    "docs/assurance/evidence-ledger.jsonl",  # exists, listed for clarity
    "scripts/__pycache__",  # generated artifact the macOS runbook warns about
}


def referenced_paths():
    for root in DOC_ROOTS:
        for document in sorted((REPO_ROOT / root).rglob("*.md")):
            text = document.read_text(encoding="utf-8")
            for match in PATH_RE.finditer(text):
                yield document.relative_to(REPO_ROOT), match.group(1)


class RunbookReferenceTests(unittest.TestCase):
    def test_every_referenced_repository_path_exists(self):
        missing = []
        for document, reference in referenced_paths():
            candidate = reference.rstrip("/")
            if candidate in PLACEHOLDERS or candidate.endswith(".local"):
                continue
            target = REPO_ROOT / candidate
            if not target.exists():
                missing.append(f"{document}: `{candidate}`")
        self.assertEqual(
            missing,
            [],
            "documented paths that cannot be executed as written:\n"
            + "\n".join(missing),
        )

    def test_reference_scan_actually_sees_documents(self):
        references = list(referenced_paths())
        self.assertGreater(
            len(references),
            10,
            "the reference scan found suspiciously few paths; "
            "pattern or doc roots may have rotted",
        )


if __name__ == "__main__":
    unittest.main()
