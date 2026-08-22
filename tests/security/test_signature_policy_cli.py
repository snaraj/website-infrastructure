"""End-to-end fail-closed battery for the signature-policy CLI.

Before this battery the validator's ``main()`` and its bounded reader
``_read_bounded`` had never been executed by the suite: the functions were
unit-tested on in-memory strings, but the actual CLI contract — the thing
CI and operators call — was unproven, and every filesystem refusal
(symlink, FIFO, oversize, TOCTOU identity, non-UTF-8) was dead code as far
as the tests were concerned. Each case runs the real script as a
subprocess. The passing fixtures are the committed policy artifacts
themselves, which doubles as a regression pin: if the pinned contracts in
the validator and the committed YAML ever diverge, this battery fails
before the cluster does.
"""

import os
import tempfile
import unittest
from pathlib import Path

from .support import run_script

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_signature_policy.py"
POLICY = REPO_ROOT / "policies" / "kyverno" / "require-signed-naranjo-online.yaml"
KUSTOMIZATION = REPO_ROOT / "policies" / "kyverno" / "kustomization.yaml"
FLUX_SYNC = REPO_ROOT / "kubernetes" / "flux-system" / "gotk-sync.yaml"
PASS_LINE = "PASS closed Kyverno image-signature policy contract"


def run_validator(*argv):
    return run_script(VALIDATOR, *argv)


def policy_args(file_path):
    return (
        "policy",
        "--file",
        str(file_path),
        "--site",
        "naranjo-online",
        "--workflow",
        "release-publisher.yml",
        "--action",
        "Enforce",
    )


class SignaturePolicyCliTests(unittest.TestCase):
    """The CLI must accept the committed artifacts and nothing weaker."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()

    def assert_rejected(self, completed, fragment, code=1):
        self.assertEqual(completed.returncode, code, completed.stderr)
        self.assertIn(fragment, completed.stderr)
        self.assertNotIn(PASS_LINE, completed.stdout)

    # -- passing fixtures: the real committed artifacts ------------------

    def test_committed_policy_passes_for_both_sites(self):
        for slug in ("naranjo-online", "lidersea-com"):
            with self.subTest(site=slug):
                completed = run_validator(
                    "policy",
                    "--file",
                    str(REPO_ROOT / "policies" / "kyverno" / f"require-signed-{slug}.yaml"),
                    "--site",
                    slug,
                    "--workflow",
                    "release-publisher.yml",
                    "--action",
                    "Enforce",
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn(PASS_LINE, completed.stdout)

    def test_committed_kustomization_and_flux_sync_pass(self):
        cases = (
            ("kustomization", KUSTOMIZATION, ("--inventory", "staging")),
            ("flux-sync", FLUX_SYNC, ()),
        )
        for command, file_path, extra in cases:
            with self.subTest(command=command):
                completed = run_validator(
                    command, "--file", str(file_path), *extra
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn(PASS_LINE, completed.stdout)

    # -- hostile content ------------------------------------------------

    def test_weakened_policy_body_is_rejected(self):
        # Downgrading enforcement (or any single-byte change to the pinned
        # body) must fail; a validator that accepts an edited policy would
        # let admission strength be weakened invisibly.
        text = POLICY.read_text(encoding="utf-8")
        for old, new, label in (
            ("validationFailureAction: Enforce", "validationFailureAction: Audit", "action-downgrade"),
            ("failurePolicy: Fail", "failurePolicy: Ignore", "webhook-downgrade"),
            ("rekor:", "rekor_disabled:", "rekor-tamper"),
            # Re-pointed 2026-08-22 with the identity itself (ADR 0016
            # amendment). The trusted subject now ends in the protected `main`
            # branch ref, so `identity-widening` widens THAT ref to the
            # `refs/heads/*` family, and `identity-tag-ref` proves the ref
            # family this contract stopped trusting is now refused. Widening in
            # either direction stays dead.
            ("@refs/heads/main", "@refs/heads/*", "identity-widening"),
            ("@refs/heads/main", "@refs/tags/v*", "identity-tag-ref"),
        ):
            # A mutation whose source text is absent silently proves nothing.
            # This assertion is why the re-point above could not be a deletion:
            # when the committed identity moved, a `continue` here would have
            # turned the deny row into a no-op and the suite would have stayed
            # green with no negative coverage at all.
            self.assertIn(old, text, f"mutation source vanished: {label}")
            hostile = self.root / f"{label}.yaml"
            hostile.write_bytes(text.replace(old, new, 1).encode("utf-8"))
            with self.subTest(mutation=label):
                self.assert_rejected(
                    run_validator(*policy_args(hostile)),
                    "signature policy body does not match the pinned",
                )

    def test_wrong_identity_pair_is_rejected(self):
        completed = run_validator(
            "policy",
            "--file",
            str(POLICY),
            "--site",
            "naranjo-online",
            "--workflow",
            "attacker.yml",
        )
        self.assert_rejected(
            completed,
            "site/workflow signature identity is outside the closed allowlist",
        )

    def test_noncanonical_encodings_are_rejected(self):
        text = POLICY.read_text(encoding="utf-8")
        cases = (
            ("crlf.yaml", text.replace("\n", "\r\n", 1).encode(), "must use LF line endings"),
            ("tab.yaml", text.replace("  admission", "\tadmission", 1).encode(), "must not contain tabs"),
            ("bom.yaml", b"\xef\xbb\xbf" + text.encode(), "must not contain a UTF-8 BOM"),
            ("no-lf.yaml", text.rstrip("\n").encode(), "must end with one LF"),
            ("binary.yaml", text.encode() + b"\xff\xfe\n", "policy input is not valid UTF-8"),
        )
        for name, payload, fragment in cases:
            hostile = self.root / name
            hostile.write_bytes(payload)
            with self.subTest(case=name):
                self.assert_rejected(run_validator(*policy_args(hostile)), fragment)

    def test_reordered_kustomization_inventory_is_rejected(self):
        text = KUSTOMIZATION.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        reordered = "".join(lines[:-2] + [lines[-1], lines[-2]])
        self.assertNotEqual(text, reordered)
        hostile = self.root / "kustomization.yaml"
        hostile.write_bytes(reordered.encode("utf-8"))
        self.assert_rejected(
            run_validator("kustomization", "--file", str(hostile), "--inventory", "staging"),
            "must match the exact",
        )

    # -- hostile filesystem custody (_read_bounded) ----------------------

    def test_symlink_policy_input_is_rejected(self):
        link = self.root / "link.yaml"
        link.symlink_to(POLICY)
        self.assert_rejected(
            run_validator(*policy_args(link)),
            "policy input must be one regular non-symlink file",
        )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo is unavailable")
    def test_fifo_policy_input_is_rejected(self):
        fifo = self.root / "fifo.yaml"
        os.mkfifo(fifo)
        self.assert_rejected(
            run_validator(*policy_args(fifo)),
            "policy input must be one regular non-symlink file",
        )

    def test_oversize_policy_input_is_rejected(self):
        oversize = self.root / "big.yaml"
        oversize.write_text("#" + "x" * (64 * 1024) + "\n")
        self.assert_rejected(
            run_validator(*policy_args(oversize)),
            "policy input exceeds the 64 KiB ceiling",
        )

    def test_missing_policy_input_is_rejected(self):
        completed = run_validator(*policy_args(self.root / "absent.yaml"))
        self.assertEqual(completed.returncode, 1)
        self.assertIn("ERROR", completed.stderr)
        self.assertNotIn(PASS_LINE, completed.stdout)

    def test_missing_subcommand_is_a_usage_error(self):
        completed = run_validator()
        self.assertEqual(completed.returncode, 2)
        self.assertIn("usage", completed.stderr)


if __name__ == "__main__":
    unittest.main()
