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

The carrier sets below are deliberate, explicit allowlists — but they are
enforced by discovery, not assumption: every tracked ``*.py`` under
``scripts/`` is swept for definitions of the helper names, the set of
files found must equal the pinned set exactly, and every found copy must
be byte-identical to the canonical carrier's. A fifth tracked copy (or a
divergent one) therefore fails by file name, and adding a legitimate new
carrier is a conscious edit to the explicit sets in this file.
"""

import ast
import importlib.util
import os
import stat
import subprocess
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
    "_ancestor_state",
    "_is_link_or_reparse",
    "_path_chain",
    "_open_posix_no_follow",
)
# The ancestor tuple's fields, by index, so the pin below names what each
# position is for instead of asserting an opaque length.
ANCESTOR_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
# Fields deliberately NOT in the ancestor tuple: each one describes a
# directory's CONTENTS, so an unrelated process creating or removing some
# other entry changes it (issue #158).
ANCESTOR_CONTENT_FIELDS = ("st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
# A fifth and sixth copy of the same opener exists under a different name in
# the protected-host pair; pin those two to each other as well so they also
# cannot drift apart.
SIBLING_OPENER_FILES = (
    "scripts/validate_protected_host_contract.py",
    "scripts/validate_protected_runtime_evidence.py",
)
SIBLING_OPENER_NAME = "_open_absolute_file_no_follow"
# Every discovered copy must equal this carrier's text, byte for byte.
CANONICAL_CARRIER = "scripts/validate_cloudflared_tunnel_token.py"


def _function_sources(relative):
    path = REPO_ROOT / relative
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            found[node.name] = ast.get_source_segment(source, node)
    return found


def _tracked_python_files_under_scripts():
    """Enumerate tracked scripts/**.py so no copy can hide from the sweep."""

    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z", "--", "scripts"],
        check=True,
        capture_output=True,
    )
    return sorted(
        name
        for name in listed.stdout.decode("utf-8").split("\0")
        if name.endswith(".py")
    )


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

    def test_ancestor_state_keeps_identity_and_drops_content_churn(self):
        """Issue #158: a shared ancestor's content fields are not custody.

        ``_path_chain`` used the full ``_path_state`` tuple for every
        component, so the per-user temporary root — a shared ancestor of every
        private file staged under it — carried st_nlink/st_size/st_mtime_ns/
        st_ctime_ns into the before/after comparison. Any other process
        creating or removing its own temp entry flipped those fields and the
        read failed closed on a path nothing had touched. The narrowing must
        drop exactly those four and keep every identity field.
        """

        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory).resolve()
            metadata = os.lstat(probe)
            for relative in FAMILY_CARRIERS:
                module = self.modules[relative]
                state = module._ancestor_state(metadata)
                with self.subTest(carrier=relative):
                    for position, field in enumerate(ANCESTOR_IDENTITY_FIELDS):
                        self.assertEqual(
                            state[position],
                            getattr(metadata, field),
                            "the ancestor tuple must still bind " + field,
                        )
                    for field in ANCESTOR_CONTENT_FIELDS:
                        self.assertNotIn(
                            getattr(metadata, field),
                            state,
                            "{} describes the directory's contents, not this "
                            "path; keeping it re-opens issue #158".format(field),
                        )

    def test_path_chain_survives_sibling_churn_but_not_substitution(self):
        """The behavioural half: benign churn passes, every attack still fails.

        Each mutation is applied to a fresh chain and reverted by construction
        (a new temporary tree per case), so no case can mask another.
        """

        for relative in FAMILY_CARRIERS:
            module = self.modules[relative]
            with tempfile.TemporaryDirectory() as directory:
                shared = Path(directory).resolve()
                middle = shared / "middle"
                middle.mkdir()
                target = middle / "private.bin"
                target.write_bytes(b"payload\n")
                os.chmod(target, 0o600)
                baseline = module._path_chain(target)

                with self.subTest(carrier=relative, case="sibling-created"):
                    sibling = tempfile.mkdtemp(dir=str(shared))
                    self.assertEqual(
                        baseline,
                        module._path_chain(target),
                        "a sibling entry in a shared ancestor is not a change "
                        "to this path",
                    )
                with self.subTest(carrier=relative, case="sibling-removed"):
                    os.rmdir(sibling)
                    self.assertEqual(baseline, module._path_chain(target))

                with self.subTest(carrier=relative, case="ancestor-replaced"):
                    payload = target.read_bytes()
                    for entry in middle.iterdir():
                        entry.unlink()
                    middle.rmdir()
                    middle.mkdir()
                    target.write_bytes(payload)
                    os.chmod(target, 0o600)
                    self.assertNotEqual(
                        baseline,
                        module._path_chain(target),
                        "a replaced ancestor directory must still be caught",
                    )

                replaced = module._path_chain(target)
                with self.subTest(carrier=relative, case="ancestor-chmod"):
                    # Pick a mode that genuinely differs from the current one:
                    # chmod to the mode a directory already has is a no-op, and
                    # a mutation that mutates nothing proves nothing.
                    original = stat.S_IMODE(os.lstat(middle).st_mode)
                    os.chmod(middle, 0o700 if original != 0o700 else 0o750)
                    self.assertNotEqual(replaced, module._path_chain(target))
                    os.chmod(middle, original)

                restored = module._path_chain(target)
                self.assertEqual(
                    replaced, restored, "the chmod mutation must be reverted"
                )
                with self.subTest(carrier=relative, case="final-file-rewritten"):
                    target.write_bytes(b"payload-two\n")
                    self.assertNotEqual(
                        restored,
                        module._path_chain(target),
                        "the final component keeps the full custody tuple",
                    )

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

    def test_helper_copies_are_discovered_never_assumed(self):
        """Sweep every tracked scripts/*.py for the helper definitions. The
        fixed carrier dict alone would silently ignore a fifth divergent
        copy planted anywhere else under scripts/, letting it drift with
        the very vulnerability this suite exists to pin down. Discovery
        makes the pinned sets exhaustive: an unexpected or missing carrier
        fails naming the file, and every discovered copy must match the
        canonical carrier byte for byte."""

        family_found = {}
        sibling_found = {}
        for relative in _tracked_python_files_under_scripts():
            found = _function_sources(relative)
            family_names = sorted(set(found) & set(FAMILY_FUNCTIONS))
            if family_names:
                family_found[relative] = {
                    name: found[name] for name in family_names
                }
            if SIBLING_OPENER_NAME in found:
                sibling_found[relative] = found[SIBLING_OPENER_NAME]

        self.assertEqual(
            sorted(family_found),
            sorted(FAMILY_CARRIERS),
            "files defining the no-follow helper family must be exactly "
            "the pinned carriers; unexpected: {} missing: {}".format(
                sorted(set(family_found) - set(FAMILY_CARRIERS)),
                sorted(set(FAMILY_CARRIERS) - set(family_found)),
            ),
        )
        self.assertEqual(
            sorted(sibling_found),
            sorted(SIBLING_OPENER_FILES),
            "files defining {} must be exactly the pinned sibling pair; "
            "unexpected: {} missing: {}".format(
                SIBLING_OPENER_NAME,
                sorted(set(sibling_found) - set(SIBLING_OPENER_FILES)),
                sorted(set(SIBLING_OPENER_FILES) - set(sibling_found)),
            ),
        )

        canonical = family_found[CANONICAL_CARRIER]
        for name in FAMILY_FUNCTIONS:
            self.assertIn(
                name,
                canonical,
                "{} lost the canonical helper {}".format(
                    CANONICAL_CARRIER, name
                ),
            )
        for relative, sources in sorted(family_found.items()):
            for name in FAMILY_FUNCTIONS:
                with self.subTest(carrier=relative, helper=name):
                    self.assertIn(
                        name,
                        sources,
                        "{} no longer defines {}".format(relative, name),
                    )
                    self.assertEqual(
                        sources[name],
                        canonical[name],
                        "{}: {} diverged from the canonical copy in "
                        "{}".format(relative, name, CANONICAL_CARRIER),
                    )
        canonical_opener = sibling_found[SIBLING_OPENER_FILES[0]]
        for relative, segment in sorted(sibling_found.items()):
            with self.subTest(carrier=relative, helper=SIBLING_OPENER_NAME):
                self.assertEqual(
                    segment,
                    canonical_opener,
                    "{}: {} diverged from the copy in {}".format(
                        relative, SIBLING_OPENER_NAME, SIBLING_OPENER_FILES[0]
                    ),
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
