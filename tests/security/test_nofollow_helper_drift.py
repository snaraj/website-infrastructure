"""Pin the shared no-follow walk helpers byte-identical across validators.

Four validators read owner-private files (tunnel token, Cloudflare token
receipt, kubeconfig snapshot, SOPS ciphertext snapshot) through a private
copy of the same TOCTOU-hardened helper family. Before this pin the four
copies had silently diverged — two of them compared a narrower custody
tuple that ignored st_uid/st_gid, so a concurrent chown inside the read
window passed unnoticed. A fix applied to one copy must now land in every
copy: this suite fails the moment any of the function bodies differ by a
single byte, and separately proves the runtime behavior each copy must
keep (domain-typed failure, ancestor-symlink rejection, uid/gid custody).
"""

import ast
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The validators that must carry byte-identical helper copies, with the
# domain error type each copy is required to raise through _WALK_ERROR.
FAMILY_CARRIERS = {
    "scripts/validate_cloudflared_tunnel_token.py": "InvalidToken",
    "scripts/validate_cloudflare_token_receipt.py": "ReceiptError",
    "scripts/validate_kubeconfig_snapshot.py": "SnapshotError",
    "scripts/validate_sops_ciphertext_snapshot.py": "SnapshotError",
}
FAMILY_FUNCTIONS = (
    "_path_state",
    "_is_link_or_reparse",
    "_path_chain",
    "_open_posix_no_follow",
)
# A fifth and sixth copy of the same opener exists under a different name in
# the protected-host pair; pin those two to each other as well so they also
# cannot drift apart.
SIBLING_OPENER_FILES = (
    "scripts/validate_protected_host_contract.py",
    "scripts/validate_protected_runtime_evidence.py",
)
SIBLING_OPENER_NAME = "_open_absolute_file_no_follow"


def _function_sources(relative):
    path = REPO_ROOT / relative
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            found[node.name] = ast.get_source_segment(source, node)
    return found


def _load_module(relative):
    path = REPO_ROOT / relative
    spec = importlib.util.spec_from_file_location(
        "drift_" + path.stem, path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoFollowHelperDriftTests(unittest.TestCase):
    """One canonical helper family, enforced byte-for-byte."""

    @classmethod
    def setUpClass(cls):
        cls.sources = {
            relative: _function_sources(relative) for relative in FAMILY_CARRIERS
        }
        cls.modules = {
            relative: _load_module(relative) for relative in FAMILY_CARRIERS
        }

    def test_every_family_function_is_byte_identical_across_carriers(self):
        """A divergent copy is a latent unfixed vulnerability; reject drift."""

        for name in FAMILY_FUNCTIONS:
            variants = {}
            for relative in FAMILY_CARRIERS:
                segment = self.sources[relative].get(name)
                self.assertIsNotNone(
                    segment, f"{relative} no longer defines {name}"
                )
                variants.setdefault(segment, []).append(relative)
            self.assertEqual(
                len(variants),
                1,
                "helper {} drifted between carriers: {}".format(
                    name, sorted(sum(variants.values(), []))
                ),
            )

    def test_walk_error_is_each_carriers_domain_failure(self):
        """The shared text stays fail-closed by raising the local domain error."""

        for relative, error_name in FAMILY_CARRIERS.items():
            module = self.modules[relative]
            self.assertTrue(
                hasattr(module, "_WALK_ERROR"),
                f"{relative} lost its _WALK_ERROR domain alias",
            )
            self.assertIs(
                module._WALK_ERROR,
                getattr(module, error_name),
                f"{relative} must alias _WALK_ERROR to {error_name}",
            )
            self.assertTrue(issubclass(module._WALK_ERROR, Exception))

    def test_path_state_binds_ownership_custody(self):
        """The custody tuple must include st_uid/st_gid so a chown during the
        read window changes the state and fails the same-handle comparison."""

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "probe"
            target.write_bytes(b"probe\n")
            metadata = os.lstat(target)
            for relative in FAMILY_CARRIERS:
                state = self.modules[relative]._path_state(metadata)
                with self.subTest(carrier=relative):
                    self.assertEqual(len(state), 11)
                    self.assertIn(metadata.st_uid, state)
                    self.assertIn(metadata.st_gid, state)
                    self.assertEqual(state[4], metadata.st_uid)
                    self.assertEqual(state[5], metadata.st_gid)

    @unittest.skipUnless(os.name == "posix", "no-follow walking is POSIX-only")
    def test_open_posix_no_follow_agrees_on_accept_and_reject(self):
        """Every copy opens a clean path and refuses a symlinked ancestor
        with its own domain error, never a silent success."""

        for relative in FAMILY_CARRIERS:
            module = self.modules[relative]
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                real_dir = root / "real"
                real_dir.mkdir()
                target = real_dir / "private.bin"
                target.write_bytes(b"payload\n")
                with self.subTest(carrier=relative, case="accept"):
                    descriptor, parent_descriptor, name = (
                        module._open_posix_no_follow(target, os.O_RDONLY)
                    )
                    try:
                        self.assertEqual(name, "private.bin")
                        self.assertTrue(
                            stat.S_ISREG(os.fstat(descriptor).st_mode)
                        )
                    finally:
                        os.close(descriptor)
                        os.close(parent_descriptor)
                linked = root / "linked"
                os.symlink(real_dir, linked)
                with self.subTest(carrier=relative, case="ancestor-symlink"):
                    with self.assertRaises(Exception) as context:
                        opened = module._open_posix_no_follow(
                            linked / "private.bin", os.O_RDONLY
                        )
                        os.close(opened[0])
                        os.close(opened[1])
                    self.assertIsInstance(
                        context.exception, (module._WALK_ERROR, OSError)
                    )
                with self.subTest(carrier=relative, case="relative-path"):
                    with self.assertRaises(module._WALK_ERROR):
                        module._open_posix_no_follow(
                            Path("relative/private.bin"), os.O_RDONLY
                        )

    def test_sibling_openers_stay_byte_identical(self):
        """The protected-host pair carries the same opener under another
        name; those two copies must also never drift from each other."""

        segments = []
        for relative in SIBLING_OPENER_FILES:
            found = _function_sources(relative)
            self.assertIn(
                SIBLING_OPENER_NAME, found, f"{relative} lost its opener"
            )
            segments.append(found[SIBLING_OPENER_NAME])
        self.assertEqual(
            segments[0],
            segments[1],
            "protected-host sibling openers drifted apart",
        )


if __name__ == "__main__":
    unittest.main()
