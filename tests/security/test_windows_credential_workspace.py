"""Static contract for the user-run Windows credential-workspace gate."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-windows-credential-workspace.ps1"


class WindowsCredentialWorkspaceTests(unittest.TestCase):
    """Keep the offline preflight fail-closed and free of weak shell escapes."""

    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_requires_exact_encryption_acl_owner_and_non_reparse_root(self):
        for required in (
            "Get-BitLockerVolume",
            "EncryptionPercentage",
            "VolumeStatus.ToString() -ne 'FullyEncrypted'",
            "system-volume BitLocker protection is not active and complete",
            "AreAccessRulesProtected",
            "WindowsIdentity]::GetCurrent()",
            "[System.Environment]::SystemDirectory",
            "S-1-5-18",
            "rules.Count -ne $allowedSids.Count",
            "[int64]$rule.FileSystemRights -ne [int64]$fullControl",
            "protected path DACL is not the exact two-principal allowlist",
            "FileAttributes]'ReparsePoint'",
            "FileAttributes]'NotContentIndexed'",
            "workspace must be outside the repository",
            "workspace must be the root of its dedicated volume",
            "workspace volume must differ from the repository volume",
            "workspace volume must differ from the Windows system volume",
        ):
            self.assertIn(required, self.source)

    def test_enforces_non_elevated_cross_authority_isolation(self):
        for required in (
            "Assert-NonElevatedOperator",
            "WindowsBuiltInRole]'Administrator'",
            "S-1-16-12288",
            "credential ceremony must run in a non-elevated process",
            "Assert-NoAmbientCrossAuthority",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "SSH_AUTH_SOCK",
            "GIT_CONFIG(?:_|$)",
            "GCM(?:_|$)",
            "ambient Git, GitHub, or SSH credential authority must be absent",
        ):
            self.assertIn(required, self.source)

    def test_enumerates_pagefile_crash_and_dedicated_dump_volumes(self):
        for required in (
            "Win32_ComputerSystem",
            "AutomaticManagedPagefile",
            "Win32_PageFileSetting",
            "Win32_PageFileUsage",
            "Session Manager\\Memory Management",
            "PagingFiles",
            "ExistingPageFiles",
            "Win32_OSRecoveryConfiguration",
            "CrashControl",
            "CrashDumpEnabled",
            "DumpFile",
            "MinidumpDir",
            "DedicatedDumpFile",
            "automatic pagefile backing volume is not observable",
            "residue destination is not an unambiguous local drive path",
            "residue backing-volume BitLocker protection is not active and complete",
        ):
            self.assertIn(required, self.source)

    def test_session_mode_confines_temp_and_binds_cli_config(self):
        for required in (
            "@('TEMP', 'TMP', 'TF_DATA_DIR', 'TF_PLUGIN_CACHE_DIR')",
            "Get-Item -LiteralPath ('Env:{0}' -f $name)",
            "TF_CLI_CONFIG_FILE",
            "Get-ProtectedFileRecord -Path $cliConfig",
            "Assert-ProtectedAcl -Item $item",
            "HistorySaveStyle",
            "SaveNothing",
            "process-local temporary or tool path escapes the workspace",
            "Env:TF_CLI_ARGS*",
            "TF_CLI_ARGS(?:_|$)",
            "TF_LOG_PROVIDER",
            "TF_REATTACH_PROVIDERS",
            "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE",
            "CLOUDFLARE_API_USER_SERVICE_KEY",
            "legacy Cloudflare authentication environment must be absent",
            "cli-config={0}",
        ):
            self.assertIn(required, self.source)

    def test_protected_file_set_is_array_valued_single_link_and_same_handle_hashed(self):
        for required in (
            "[string[]]$ProtectedFile = @()",
            "@($ProtectedFile).Count -gt 128",
            "protected files require current-session validation",
            "CreateFileW",
            "GetFileInformationByHandle",
            "$openReparsePoint = [uint32]0x00200000",
            "NumberOfLinks",
            "RequireSingleLink",
            "[System.IO.FileStream]::new(",
            "$hasher.ComputeHash($stream)",
            "protected file changed during validation",
            "protected file ACL changed during validation",
            "protected file set contains a duplicate path",
            "protected_file_set_sha256={0}",
        ):
            self.assertIn(required, self.source)

    def test_attestation_binds_config_tool_provenance_and_fresh_validation(self):
        for required in (
            "schema=2",
            "repository-root={0}",
            "residue-destination={0}",
            "residue-volume={0}",
            "session-path={0}",
            "windows-credential-validator",
            "powershell-host",
            "powershell-version={0}",
            "cross-authority-environment=absent",
            "validation_utc={0}",
            "process-start={0}",
            "validation_attestation_sha256={0}",
        ):
            self.assertIn(required, self.source)

    def test_repository_root_supports_protected_validator_snapshot(self):
        for required in (
            "[string]$RepositoryRoot",
            "$RepositoryRoot = Join-Path -Path $PSScriptRoot -ChildPath '..'",
            "repository root must be supplied as an absolute local path",
            "repository root lacks the expected local checkout markers",
            "-ContentOnly",
        ):
            self.assertIn(required, self.source)

    def test_avoids_shell_escape_mutation_and_bypass_primitives(self):
        lowered = self.source.lower()
        for forbidden in (
            "invoke-expression",
            "executionpolicy bypass",
            "start-process",
            "cmd.exe",
            "icacls.exe",
            "manage-bde.exe",
            "set-acl",
            "set-itemproperty",
            "remove-item",
            "stop-process",
            "stop-service",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_success_and_failure_output_are_bounded_and_path_free(self):
        self.assertEqual(
            self.source.count("PASS protected Windows credential workspace"), 1
        )
        self.assertEqual(
            self.source.count("FAIL protected Windows credential workspace"), 1
        )
        self.assertNotIn("Write-Output $Root", self.source)
        self.assertNotIn("Write-Host $Root", self.source)
        self.assertNotIn("$_.Exception.Message", self.source)
        self.assertIn("[Console]::" + "\n        Error.WriteLine(", self.source)
        self.assertIn("workspace_attestation_sha256={0}", self.source)
        self.assertIn(
            "[System.Security.Cryptography.SHA256]::" + "\n        Create()",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
