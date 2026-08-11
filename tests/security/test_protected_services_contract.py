"""Keep private host identities local while proving active and archived state."""

import os
import re
import tempfile
import sys
import unittest
from pathlib import Path
from unittest import mock

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = REPO_ROOT / "bootstrap" / "pi" / "preflight.sh"
DISCOVERY = REPO_ROOT / "scripts" / "discover-pi.sh"
EXAMPLE = REPO_ROOT / "bootstrap" / "pi" / "protected-services.env.example"
VALIDATOR = REPO_ROOT / "scripts" / "validate_protected_host_contract.py"
GITIGNORE = REPO_ROOT / ".gitignore"
MODULE = load_script("validate_protected_host_contract.py")


def contract_text(
    *,
    active_units=("required.service",),
    legacy_archives_present="yes",
    archive_roots=None,
    archive_bindings=None,
    legacy_units=None,
    activation_classes=None,
):
    """Build a synthetic private contract without using operator identities."""

    if archive_roots is None:
        archive_roots = (
            ("/srv/protected/archive-one",)
            if legacy_archives_present == "yes"
            else ()
        )
    if archive_bindings is None:
        archive_bindings = tuple(
            f"{index:064x}" for index, _value in enumerate(archive_roots, start=1)
        )
    if legacy_units is None:
        legacy_units = (
            ("retired.service",)
            if legacy_archives_present == "yes"
            else ()
        )
    if activation_classes is None:
        activation_classes = tuple(sorted(MODULE.REQUIRED_ACTIVATION_CLASSES))

    lines = [
        "PROTECTED_SERVICES_REVIEWED=yes",
        "PROTECTED_LEGACY_ARCHIVES_REVIEWED=yes",
        f"PROTECTED_LEGACY_ARCHIVES_PRESENT={legacy_archives_present}",
    ]
    lines.append(f"{MODULE.RUNTIME_EVIDENCE_HASH_KEY}={'e' * 64}")
    lines.extend(f"PROTECTED_SYSTEMD_UNIT={value}" for value in active_units)
    lines.extend(f"PROTECTED_LEGACY_ARCHIVE_ROOT={value}" for value in archive_roots)
    lines.extend(
        f"PROTECTED_LEGACY_ARCHIVE_BINDING_SHA256={value}"
        for value in archive_bindings
    )
    lines.extend(f"PROTECTED_LEGACY_SYSTEMD_UNIT={value}" for value in legacy_units)
    lines.extend(
        f"PROTECTED_LEGACY_ACTIVATION_CLASS_REVIEWED={value}"
        for value in activation_classes
    )
    return "\n".join(lines) + "\n"


class ProtectedServicesContractTests(unittest.TestCase):
    """Protect local identities while distinguishing active and archived state."""

    @classmethod
    def setUpClass(cls):
        """Load the cross-file privacy contract once for static assertions."""

        cls.preflight = PREFLIGHT.read_text(encoding="utf-8")
        cls.discovery = DISCOVERY.read_text(encoding="utf-8")
        cls.example = EXAMPLE.read_text(encoding="utf-8")
        cls.validator = VALIDATOR.read_text(encoding="utf-8")
        cls.gitignore = GITIGNORE.read_text(encoding="utf-8")

    def parse(self, text):
        return MODULE.parse_contract_text(text)

    def test_local_inventory_is_ignored_and_example_is_unapproved(self):
        """Copying the template must not create a committable or approved file."""

        self.assertIn("bootstrap/pi/protected-services.env.local", self.gitignore)
        for key in (
            "PROTECTED_SERVICES_REVIEWED",
            "PROTECTED_LEGACY_ARCHIVES_REVIEWED",
        ):
            with self.subTest(key=key):
                self.assertIn(f"{key}=no", self.example)
                self.assertNotIn(f"{key}=yes", self.example)
        self.assertIn("PROTECTED_LEGACY_ARCHIVES_PRESENT=unknown", self.example)

    def test_static_contract_accepts_active_and_archived_roles(self):
        """Static parsing succeeds without requiring any declared root to exist."""

        contract, errors = self.parse(
            contract_text(
                legacy_units=(
                    "retired.service",
                    "retired.socket",
                    "retired.timer",
                    "retired.path",
                )
            )
        )
        self.assertEqual(errors, [])
        self.assertEqual(contract.active_units, ("required.service",))
        self.assertTrue(contract.legacy_archives_present)
        self.assertEqual(len(contract.legacy_units), 4)

    def test_presence_and_activation_coverage_fail_closed(self):
        """Archive presence and every generic activation class are explicit."""

        valid = contract_text()
        candidates = (
            valid.replace("PROTECTED_LEGACY_ARCHIVES_PRESENT=yes\n", ""),
            valid.replace(
                "PROTECTED_LEGACY_ARCHIVES_PRESENT=yes\n",
                "PROTECTED_LEGACY_ARCHIVES_PRESENT=unknown\n",
            ),
            contract_text(archive_roots=(), archive_bindings=()),
            contract_text(
                legacy_archives_present="no",
                archive_roots=("/srv/protected/archive-one",),
                archive_bindings=("1" * 64,),
                legacy_units=(),
            ),
            contract_text(activation_classes=("system-manager-units",)),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate[:80]):
                _, errors = self.parse(candidate)
                self.assertTrue(errors)

        contract, errors = self.parse(
            contract_text(legacy_archives_present="no")
        )
        self.assertEqual(errors, [])
        self.assertFalse(contract.legacy_archives_present)
        self.assertEqual(contract.archive_roots, ())

    def test_active_units_remain_service_only(self):
        """The existing must-active contract cannot silently gain socket authority."""

        _, errors = self.parse(contract_text(active_units=("required.socket",)))
        self.assertTrue(any("active unit 1" in error for error in errors))

    def test_review_flags_and_input_schema_fail_closed(self):
        """Missing approval, duplicate approval, and invented keys are rejected."""

        valid = contract_text()
        candidates = (
            valid.replace("PROTECTED_SERVICES_REVIEWED=yes\n", ""),
            valid.replace(
                "PROTECTED_LEGACY_ARCHIVES_REVIEWED=yes\n",
                "PROTECTED_LEGACY_ARCHIVES_REVIEWED=no\n",
            ),
            valid + "PROTECTED_SERVICES_REVIEWED=yes\n",
            valid + "PRIVATE_INVENTORY_VALUE=do-not-echo\n",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate.splitlines()[-1].split("=", 1)[0]):
                _, errors = self.parse(candidate)
                output = "\n".join(errors)
                self.assertTrue(errors)
                self.assertNotIn("do-not-echo", output)

    def test_rejects_relative_noncanonical_broad_and_overlapping_roots(self):
        """One archive declaration may never claim a host hierarchy or another root."""

        for root in (
            "relative/archive",
            "/",
            "/home",
            "/home/operator",
            "/single",
            "/etc/archive",
            "/tmp/archive",
            "/usr/local/archive",
            "/var/cache/archive",
            "/var/lib/containerd/archive",
            "/var/lib/docker/archive",
            "/var/lib/kubelet/archive",
            "/var/log/archive",
            "/var/snap/archive",
            "/var/tmp/archive",
            "/srv/protected/../private",
            "/srv//protected/archive",
        ):
            with self.subTest(root=root):
                _, errors = self.parse(contract_text(archive_roots=(root,)))
                self.assertTrue(any("archive root 1" in error for error in errors))
                self.assertNotIn(root, "\n".join(errors))

        _, duplicate_errors = self.parse(
            contract_text(
                archive_roots=(
                    "/srv/protected/archive-one",
                    "/srv/protected/archive-one",
                )
            )
        )
        self.assertTrue(any("archive root 2 duplicates" in error for error in duplicate_errors))

        _, nested_errors = self.parse(
            contract_text(
                archive_roots=(
                    "/srv/protected/archive-one",
                    "/srv/protected/archive-one/child",
                )
            )
        )
        self.assertTrue(any("archive root 2 overlaps" in error for error in nested_errors))

    def test_rejects_duplicate_units_and_active_legacy_overlap(self):
        """No identity may carry conflicting runtime expectations."""

        _, active_errors = self.parse(
            contract_text(active_units=("required.service", "required.service"))
        )
        self.assertTrue(any("active unit 2 duplicates" in error for error in active_errors))

        _, legacy_errors = self.parse(
            contract_text(
                active_units=("shared.service",),
                legacy_units=("shared.service", "retired.service", "retired.service"),
            )
        )
        self.assertTrue(any("legacy unit 1 overlaps" in error for error in legacy_errors))
        self.assertTrue(any("legacy unit 3 duplicates" in error for error in legacy_errors))

    def test_parser_diagnostics_never_echo_values(self):
        """Even malformed local values remain absent from validator diagnostics."""

        private_root = "/home/private-operator/archive/../hidden"
        private_unit = "private-identity.invalid"
        text = contract_text(
            archive_roots=(private_root,), legacy_units=(private_unit,)
        )
        _, errors = self.parse(text)
        output = "\n".join(errors)
        self.assertTrue(errors)
        self.assertNotIn(private_root, output)
        self.assertNotIn(private_unit, output)
        self.assertNotIn("private-operator", output)

    def test_static_and_live_checks_are_separate_and_injectable(self):
        """Tests can prove runtime semantics without touching local systemd or paths."""

        contract, errors = self.parse(
            contract_text(
                active_units=("required.service",),
                archive_roots=("/srv/protected/archive-one",),
                legacy_units=("retired.service", "retired.timer"),
            )
        )
        self.assertEqual(errors, [])

        states = {
            "required.service": MODULE.UnitState("loaded", "inactive", "enabled", ""),
            "retired.service": MODULE.UnitState("loaded", "active", "disabled", "/legacy"),
            "retired.timer": MODULE.UnitState("loaded", "inactive", "enabled", ""),
        }
        live_errors = MODULE.check_live_state(
            contract,
            unit_probe=states.__getitem__,
            archive_probe=lambda _value: ("must not grant group or world access",),
            binding_probe=lambda _value: "f" * 64,
        )
        combined = "\n".join(live_errors)
        for fragment in (
            "active unit 1 is not exactly active",
            "legacy unit 1 must be exactly inactive",
            "legacy unit 1 still has a control group",
            "legacy unit 2 must be persistently disabled or masked",
            "archive root 1 must not grant group or world access",
            "archive root 1 binding changed",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, combined)
        for private_value in (*states, *contract.archive_roots):
            self.assertNotIn(private_value, combined)

        valid_states = {
            "required.service": MODULE.UnitState("loaded", "active", "enabled", "/required"),
            "retired.service": MODULE.UnitState("loaded", "inactive", "disabled", ""),
            "retired.timer": MODULE.UnitState("masked", "inactive", "masked", ""),
        }
        self.assertEqual(
            MODULE.check_live_state(
                contract,
                unit_probe=valid_states.__getitem__,
                archive_probe=lambda _value: (),
                binding_probe=lambda _value: contract.archive_bindings[0],
            ),
            [],
        )

    def test_legacy_unit_states_do_not_collapse_to_inactive(self):
        """Missing, failed, transitioning, runtime-only, and lingering states fail."""

        contract, errors = self.parse(contract_text())
        self.assertEqual(errors, [])
        active = MODULE.UnitState("loaded", "active", "enabled", "/required")
        unsafe = (
            MODULE.UnitState("not-found", "inactive", "", ""),
            MODULE.UnitState("loaded", "failed", "disabled", ""),
            MODULE.UnitState("loaded", "activating", "disabled", ""),
            MODULE.UnitState("loaded", "deactivating", "disabled", ""),
            MODULE.UnitState("loaded", "inactive", "masked-runtime", ""),
            MODULE.UnitState("loaded", "inactive", "disabled", "/lingering"),
            MODULE.UnitState(None, None, None, None),
        )
        for state in unsafe:
            with self.subTest(state=state):
                live_errors = MODULE.check_live_state(
                    contract,
                    unit_probe=lambda unit, current=state: (
                        active if unit == "required.service" else current
                    ),
                    archive_probe=lambda _value: (),
                    binding_probe=lambda _value: contract.archive_bindings[0],
                )
                self.assertTrue(live_errors)

    def test_systemd_probe_requires_complete_exact_system_manager_output(self):
        """Malformed output and command failures become unavailable, never safe."""

        valid_output = (
            "LoadState=loaded\n"
            "ActiveState=inactive\n"
            "UnitFileState=disabled\n"
            "ControlGroup=\n"
        )
        completed = mock.Mock(returncode=0, stdout=valid_output)
        with mock.patch.object(MODULE.shutil, "which", return_value="/bin/systemctl"), mock.patch.object(
            MODULE.subprocess, "run", return_value=completed
        ) as run:
            self.assertEqual(
                MODULE.systemd_unit_state("retired.service"),
                MODULE.UnitState("loaded", "inactive", "disabled", ""),
            )
            command = run.call_args.args[0]
            self.assertIn("--system", command)
            self.assertEqual(command[-2:], ["--", "retired.service"])

        for returncode, output in (
            (1, valid_output),
            (0, "LoadState=loaded\nActiveState=inactive\n"),
            (0, valid_output + "Unexpected=value\n"),
            (0, valid_output + "LoadState=loaded\n"),
        ):
            with self.subTest(returncode=returncode, output=output[-20:]), mock.patch.object(
                MODULE.shutil, "which", return_value="/bin/systemctl"
            ), mock.patch.object(
                MODULE.subprocess,
                "run",
                return_value=mock.Mock(returncode=returncode, stdout=output),
            ):
                self.assertEqual(
                    MODULE.systemd_unit_state("private.service"),
                    MODULE.UnitState(None, None, None, None),
                )

    def test_binding_is_required_and_private_values_never_reach_errors(self):
        """A directory on the wrong storage cannot satisfy a reviewed binding."""

        private_root = "/srv/private-operator/archive-one"
        expected = "a" * 64
        contract, errors = self.parse(
            contract_text(
                archive_roots=(private_root,), archive_bindings=(expected,)
            )
        )
        self.assertEqual(errors, [])
        states = {
            "required.service": MODULE.UnitState("loaded", "active", "enabled", "/required"),
            "retired.service": MODULE.UnitState("loaded", "inactive", "disabled", ""),
        }
        live_errors = MODULE.check_live_state(
            contract,
            unit_probe=states.__getitem__,
            archive_probe=lambda _value: (),
            binding_probe=lambda _value: "b" * 64,
        )
        output = "\n".join(live_errors)
        self.assertIn("archive root 1 binding changed", output)
        self.assertNotIn(private_root, output)
        self.assertNotIn(expected, output)

        _, missing_errors = self.parse(
            contract_text(archive_bindings=())
        )
        self.assertTrue(any("binding SHA-256" in error for error in missing_errors))

    @unittest.skipUnless(os.name == "posix", "POSIX modes and symlinks are Linux contracts")
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_live_archive_root_rejects_group_world_access_and_symlinks(self):
        """Live metadata checks protect roots with a bounded retained-data sentinel."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory) / "archive"
            root.mkdir(mode=0o700)
            (root / "retained").mkdir()
            metadata = root.lstat()
            record = MODULE.MountInfoRecord(
                10,
                1,
                "{}:{}".format(os.major(metadata.st_dev), os.minor(metadata.st_dev)),
                MODULE.PurePosixPath("/"),
                MODULE.PurePosixPath("/"),
                "ext4",
            )
            identity = {
                "filesystem_type": "ext4",
                "options": ["noatime", "rw"],
                "target": "/",
                "stable_ids": {"uuid": "aabb"},
            }
            with mock.patch.object(
                MODULE,
                "_archive_mount_record",
                return_value=(record, ()),
            ):
                with mock.patch.object(
                    MODULE,
                    "_findmnt_identity",
                    return_value=identity,
                ):
                    self.assertEqual(MODULE.archive_root_issues(str(root)), ())
                    binding = MODULE.archive_binding_fingerprint(str(root))
                    self.assertRegex(binding or "", r"^[0-9a-f]{64}$")
                    self.assertEqual(
                        MODULE.archive_binding_fingerprint(str(root)), binding
                    )

                    root.chmod(0o750)
                    self.assertTrue(
                        any(
                            "group or world" in item
                            for item in MODULE.archive_root_issues(str(root))
                        )
                    )
                    self.assertNotEqual(
                        MODULE.archive_binding_fingerprint(str(root)), binding
                    )
                    root.chmod(0o700)

            link = Path(directory) / "archive-link"
            link.symlink_to(root, target_is_directory=True)
            self.assertTrue(any("symbolic link" in item for item in MODULE.archive_root_issues(str(link))))

    @unittest.skipUnless(os.name == "posix", "mode-0600 is a Linux file contract")
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_contract_file_rejects_wrong_mode_without_echoing_path(self):
        """File-level validation remains generic even for a private location."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "private-contract"
            path.write_text(contract_text(), encoding="utf-8")
            path.chmod(0o644)
            _, errors = MODULE.load_contract(path)
            output = "\n".join(errors)
            self.assertIn("mode must be exactly 0600", output)
            self.assertNotIn(str(path), output)

    @unittest.skipUnless(os.name == "posix", "no-follow path walking is POSIX-only")
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_contract_file_rejects_hardlinks_and_symlink_components(self):
        """Every contract path component and the opened inode fail closed."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            real_parent = Path(directory) / "real"
            real_parent.mkdir()
            path = real_parent / "private-contract"
            path.write_text(contract_text(), encoding="utf-8")
            path.chmod(0o600)
            contract, errors = MODULE.load_contract(path)
            self.assertIsNotNone(contract)
            self.assertEqual(errors, [])

            alias_parent = Path(directory) / "alias"
            alias_parent.symlink_to(real_parent, target_is_directory=True)
            _, alias_errors = MODULE.load_contract(alias_parent / path.name)
            self.assertTrue(any("symbolic link" in item for item in alias_errors))

            hardlink = real_parent / "second-name"
            os.link(str(path), str(hardlink))
            _, hardlink_errors = MODULE.load_contract(path)
            self.assertTrue(any("hard link" in item for item in hardlink_errors))

    @unittest.skipUnless(os.name == "posix", "no-follow path walking is POSIX-only")
    @unittest.skipUnless(sys.platform.startswith("linux"), "exercises Linux-only filesystem/procfs semantics")
    def test_contract_file_rejects_parent_rename_to_same_inode_symlink_race(self):
        """A parent path cannot become a symlink while the opened file stays valid."""

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            original_parent = Path(directory) / "contract-parent"
            moved_parent = Path(directory) / "moved-parent"
            original_parent.mkdir()
            path = original_parent / "private-contract"
            path.write_text(contract_text(), encoding="utf-8")
            path.chmod(0o600)
            real_read = MODULE.os.read
            substituted = []

            def swap_parent_after_read(descriptor, size):
                data = real_read(descriptor, size)
                if data and not substituted:
                    original_parent.rename(moved_parent)
                    original_parent.symlink_to(moved_parent, target_is_directory=True)
                    substituted.append(True)
                return data

            with mock.patch.object(MODULE.os, "read", side_effect=swap_parent_after_read):
                contract, errors = MODULE.load_contract(path)

            self.assertIsNone(contract)
            self.assertTrue(
                any("changed while reading" in error for error in errors),
                errors,
            )
            self.assertNotIn(str(path), "\n".join(errors))

    def test_preflight_delegates_static_and_live_validation(self):
        """Install/init use the shared validator instead of re-parsing identities."""

        for fragment in (
            'PROTECTED_SERVICES_PATH:-${repo_root}/bootstrap/pi/protected-services.env.local',
            'scripts/validate_protected_host_contract.py"',
            '"${protected_services_path}" --check-live',
            "protected-host contract is required before an install or init phase",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.preflight)
        for fragment in (
            '"--system"',
            '"--property=LoadState"',
            '"--property=ActiveState"',
            '"--property=UnitFileState"',
            '"--property=ControlGroup"',
        ):
            self.assertIn(fragment, self.validator)
        self.assertNotIn('"is-active"', self.validator)
        self.assertNotIn('"is-enabled"', self.validator)

    def test_discovery_delegates_live_validation_and_reports_counts_only(self):
        """Discovery reuses the validator without parsing or echoing private values."""

        self.assertIn("running service inventory fingerprint", self.discovery)
        self.assertIn("service unit-file inventory fingerprint", self.discovery)
        self.assertIn("fingerprint_stdout", self.discovery)
        self.assertIn(
            'scripts/validate_protected_host_contract.py"', self.discovery
        )
        self.assertIn('"${protected_services_path}" --check-live', self.discovery)
        for fragment in (
            "protected_host_contract=REVIEWED",
            "active_unit_count=%d",
            "inactive_legacy_unit_count=%d",
            "archive_root_count=%d",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.discovery)

        for obsolete in (
            "protected_unit_state()",
            "protected_service_line#*=",
            "protected_service_contract=DUPLICATE_UNIT",
            "grep -Eqv '^(#|$|PROTECTED_SERVICES_REVIEWED",
        ):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, self.discovery)

    def test_committed_contract_contains_no_private_product_examples(self):
        """Executable contracts remain generic even when policy docs name products."""

        combined = "\n".join(
            (self.preflight, self.discovery, self.example, self.validator)
        ).lower()
        for term in ("bit" + "coin", "pro" + "ton", "t" + "or", "spar" + "row"):
            with self.subTest(term=term):
                self.assertIsNone(re.search(r"\b{}\b".format(re.escape(term)), combined))


if __name__ == "__main__":
    unittest.main()
