"""Integrate fresh runtime evidence with the private protected-host contract."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from .support import load_script


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_VALIDATOR = ROOT / "scripts" / "validate_protected_runtime_evidence.py"
EXAMPLE = ROOT / "bootstrap" / "pi" / "protected-services.env.example"
PREFLIGHT = ROOT / "bootstrap" / "pi" / "preflight.sh"
INSTALL = ROOT / "bootstrap" / "pi" / "install-kubernetes.sh"
INIT = ROOT / "bootstrap" / "pi" / "init-control-plane.sh"
MODULE = load_script(
    "validate_protected_host_contract.py", module_name="validate_protected_host_contract_runtime_integration"
)


def contract_text(*, present="yes", evidence_sha256="e" * 64):
    """Build a generic contract containing no real host identity."""

    lines = [
        "PROTECTED_SERVICES_REVIEWED=yes",
        "PROTECTED_LEGACY_ARCHIVES_REVIEWED=yes",
        "PROTECTED_LEGACY_ARCHIVES_PRESENT={}".format(present),
    ]
    if evidence_sha256 is not None:
        lines.append(
            "PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256={}".format(evidence_sha256)
        )
    if present == "yes":
        lines.extend(
            (
                "PROTECTED_LEGACY_ARCHIVE_ROOT=/srv/protected/generic-archive",
                "PROTECTED_LEGACY_ARCHIVE_BINDING_SHA256={}".format("a" * 64),
                "PROTECTED_LEGACY_SYSTEMD_UNIT=generic-retired.service",
            )
        )
    lines.extend(
        "PROTECTED_LEGACY_ACTIVATION_CLASS_REVIEWED={}".format(value)
        for value in sorted(MODULE.REQUIRED_ACTIVATION_CLASSES)
    )
    return "\n".join(lines) + "\n"


class ProtectedRuntimeContractIntegrationTests(unittest.TestCase):
    """Require a fresh presence-bound attestation for either archive decision."""

    def test_static_contract_requires_exactly_one_lowercase_evidence_hash(self):
        contract, errors = MODULE.parse_contract_text(contract_text())
        self.assertEqual(errors, [])
        self.assertEqual(contract.runtime_evidence_sha256, "e" * 64)

        candidates = (
            contract_text(evidence_sha256=None),
            contract_text(evidence_sha256="E" * 64),
            contract_text() + "PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256={0}\n".format(
                "f" * 64
            ),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate.count("RUNTIME_EVIDENCE")):
                parsed, candidate_errors = MODULE.parse_contract_text(candidate)
                self.assertIsNone(parsed)
                self.assertTrue(candidate_errors)

    def test_absent_archives_require_hash_and_derivation_alone_allows_omission(self):
        contract, errors = MODULE.parse_contract_text(
            contract_text(present="no")
        )
        self.assertEqual(errors, [])
        self.assertFalse(contract.legacy_archives_present)
        self.assertEqual(contract.runtime_evidence_sha256, "e" * 64)

        parsed, errors = MODULE.parse_contract_text(
            contract_text(present="no", evidence_sha256=None)
        )
        self.assertIsNone(parsed)
        self.assertTrue(any("either archive-presence decision" in error for error in errors))

        for present in ("yes", "no"):
            with self.subTest(present=present):
                parsed, errors = MODULE.parse_contract_text(
                    contract_text(present=present, evidence_sha256=None),
                    allow_missing_bindings=True,
                    allow_unreviewed=True,
                )
                self.assertEqual(errors, [])
                self.assertIsNotNone(parsed)

    def test_check_live_calls_fixed_validator_and_never_echoes_its_values(self):
        contract, errors = MODULE.parse_contract_text(contract_text())
        self.assertEqual(errors, [])
        private_value = "/private/operator/runtime-identity"
        validator = SimpleNamespace(
            validate_runtime_evidence=mock.Mock(
                return_value=(None, ["runtime evidence mentions " + private_value])
            )
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(MODULE, "load_contract", return_value=(contract, [])), mock.patch.object(
            MODULE, "check_live_state", return_value=[]
        ), mock.patch.object(
            MODULE, "_load_runtime_evidence_validator", return_value=validator
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = MODULE.main([private_value, "--check-live"])

        self.assertEqual(result, 1)
        validator.validate_runtime_evidence.assert_called_once_with(
            Path(private_value),
            "e" * 64,
            expected_archives_present=True,
        )
        output = stdout.getvalue() + stderr.getvalue()
        self.assertIn("fresh boot-bound runtime evidence is invalid", output)
        self.assertNotIn(private_value, output)

    def test_check_live_requires_matching_runtime_evidence_when_archives_are_absent(self):
        contract, errors = MODULE.parse_contract_text(
            contract_text(present="no")
        )
        self.assertEqual(errors, [])
        loaded = SimpleNamespace(
            sha256="e" * 64,
            evidence=SimpleNamespace(archives_present=False),
        )
        validator = SimpleNamespace(
            validate_runtime_evidence=mock.Mock(return_value=(loaded, []))
        )
        stdout = io.StringIO()
        with mock.patch.object(MODULE, "load_contract", return_value=(contract, [])), mock.patch.object(
            MODULE, "check_live_state", return_value=[]
        ), mock.patch.object(
            MODULE, "_load_runtime_evidence_validator", return_value=validator
        ), contextlib.redirect_stdout(stdout):
            result = MODULE.main(["/private/contract", "--check-live"])

        self.assertEqual(result, 0)
        validator.validate_runtime_evidence.assert_called_once_with(
            Path("/private/contract"),
            "e" * 64,
            expected_archives_present=False,
        )
        self.assertIn("PASS protected-host contract", stdout.getvalue())

    def test_fixed_sibling_loader_and_preflight_describe_the_combined_gate(self):
        validator = MODULE._load_runtime_evidence_validator()
        self.assertIsNotNone(validator)
        self.assertEqual(
            Path(validator.__file__).resolve(), RUNTIME_VALIDATOR.resolve()
        )
        self.assertEqual(
            validator.EVIDENCE_VALIDATOR_API_VERSION,
            MODULE.RUNTIME_EVIDENCE_VALIDATOR_API_VERSION,
        )
        self.assertEqual(validator.EVIDENCE_SCHEMA, MODULE.RUNTIME_EVIDENCE_SCHEMA)
        self.assertEqual(
            validator.PRESENCE_FIELD,
            MODULE.RUNTIME_EVIDENCE_PRESENCE_FIELD,
        )

        example = EXAMPLE.read_text(encoding="utf-8")
        preflight = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("PROTECTED_LEGACY_RUNTIME_EVIDENCE_SHA256", example)
        self.assertIn("--emit-sha256", example)
        self.assertIn(
            "protected-host live checks and mandatory presence-bound boot attestation",
            preflight,
        )

    def test_apply_paths_revalidate_at_the_final_pre_mutation_boundary(self):
        install = INSTALL.read_text(encoding="utf-8")
        init = INIT.read_text(encoding="utf-8")

        install_preflight = (
            'bash "${repo_root}/bootstrap/pi/preflight.sh" --phase install'
        )
        self.assertEqual(install.count(install_preflight), 2)
        install_final = install.rindex(install_preflight)
        install_long_validation = install.index(
            "refusing to replace or alter existing systemd service state"
        )
        install_transaction = install.index("transaction_started='yes'")
        self.assertLess(install_long_validation, install_final)
        self.assertLess(install_final, install_transaction)
        self.assertEqual(
            install[install_final + len(install_preflight) : install_transaction].strip(),
            "",
        )

        init_preflight = 'bash "${repo_root}/bootstrap/pi/preflight.sh" --phase init'
        self.assertEqual(init.count(init_preflight), 2)
        init_dry_run = init.index("kubeadm init --dry-run --skip-token-print")
        init_acknowledgement = init.index(
            "exact kubeadm initialization acknowledgement missing"
        )
        init_final = init.rindex(init_preflight)
        init_first_mutation = init.index(
            "install -d -m 0700 /etc/kubernetes/admission"
        )
        self.assertLess(init_dry_run, init_final)
        self.assertLess(init_acknowledgement, init_final)
        self.assertLess(init_final, init_first_mutation)

    def test_fixed_sibling_import_suppresses_persistent_bytecode(self):
        loaded_module = SimpleNamespace(
            EVIDENCE_HASH_KEY=MODULE.RUNTIME_EVIDENCE_HASH_KEY,
            EVIDENCE_SCHEMA=MODULE.RUNTIME_EVIDENCE_SCHEMA,
            PRESENCE_FIELD=MODULE.RUNTIME_EVIDENCE_PRESENCE_FIELD,
            EVIDENCE_VALIDATOR_API_VERSION=MODULE.RUNTIME_EVIDENCE_VALIDATOR_API_VERSION,
            validate_runtime_evidence=lambda _path, _digest: (None, ["invalid"]),
        )
        loader = mock.Mock()

        def execute(_module):
            self.assertTrue(sys.dont_write_bytecode)
            _module.EVIDENCE_HASH_KEY = loaded_module.EVIDENCE_HASH_KEY
            _module.EVIDENCE_SCHEMA = loaded_module.EVIDENCE_SCHEMA
            _module.PRESENCE_FIELD = loaded_module.PRESENCE_FIELD
            _module.EVIDENCE_VALIDATOR_API_VERSION = (
                loaded_module.EVIDENCE_VALIDATOR_API_VERSION
            )
            _module.validate_runtime_evidence = loaded_module.validate_runtime_evidence

        loader.exec_module.side_effect = execute
        specification = SimpleNamespace(loader=loader)
        original_policy = sys.dont_write_bytecode
        with mock.patch.object(
            MODULE.importlib.util,
            "spec_from_file_location",
            return_value=specification,
        ), mock.patch.object(
            MODULE.importlib.util,
            "module_from_spec",
            return_value=SimpleNamespace(),
        ):
            loaded = MODULE._load_runtime_evidence_validator()

        self.assertIsNotNone(loaded)
        self.assertEqual(sys.dont_write_bytecode, original_policy)
        loader.exec_module.assert_called_once()

    def test_fixed_sibling_loader_rejects_api_and_schema_drift(self):
        """A sibling with a different API, schema, or presence field fails closed."""

        expected = {
            "EVIDENCE_HASH_KEY": MODULE.RUNTIME_EVIDENCE_HASH_KEY,
            "EVIDENCE_SCHEMA": MODULE.RUNTIME_EVIDENCE_SCHEMA,
            "PRESENCE_FIELD": MODULE.RUNTIME_EVIDENCE_PRESENCE_FIELD,
            "EVIDENCE_VALIDATOR_API_VERSION": MODULE.RUNTIME_EVIDENCE_VALIDATOR_API_VERSION,
            "validate_runtime_evidence": lambda _path, _digest: (None, ["invalid"]),
        }
        for changed_key in (
            "EVIDENCE_SCHEMA",
            "PRESENCE_FIELD",
            "EVIDENCE_VALIDATOR_API_VERSION",
        ):
            with self.subTest(changed_key=changed_key):
                values = dict(expected)
                values[changed_key] = "unsupported"
                loader = mock.Mock()
                loader.exec_module.side_effect = lambda module, current=values: vars(
                    module
                ).update(current)
                specification = SimpleNamespace(loader=loader)
                with mock.patch.object(
                    MODULE.importlib.util,
                    "spec_from_file_location",
                    return_value=specification,
                ), mock.patch.object(
                    MODULE.importlib.util,
                    "module_from_spec",
                    return_value=SimpleNamespace(),
                ):
                    self.assertIsNone(MODULE._load_runtime_evidence_validator())

    def test_archive_binding_emission_is_explicitly_non_authorizing(self):
        """The permissive derivation mode cannot be mistaken for a live gate."""

        contract, errors = MODULE.parse_contract_text(contract_text(present="no"))
        self.assertEqual(errors, [])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE, "load_contract", return_value=(contract, [])
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = MODULE.main(["/private/contract", "--emit-bindings"])

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("DERIVATION ONLY, NOT AUTHORIZATION", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
