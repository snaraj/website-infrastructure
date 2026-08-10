[CmdletBinding()]
param(
    [string]$Root = $env:WEBSITE_INFRA_CREDENTIAL_ROOT,
    [string]$RepositoryRoot,
    [switch]$Session,
    [string[]]$ProtectedFile = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

function Stop-Validation {
    param([Parameter(Mandatory)][string]$Reason)
    throw (New-Object System.InvalidOperationException -ArgumentList $Reason)
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $hasher = [System.Security.Cryptography.SHA256]::
        Create()
    try {
        return (($hasher.ComputeHash($Bytes) | ForEach-Object {
            $_.ToString('x2')
        }) -join '')
    }
    finally {
        $hasher.Dispose()
    }
}

function Get-TextSha256 {
    param([Parameter(Mandatory)][string]$Text)

    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    return Get-Sha256Hex -Bytes $encoding.GetBytes($Text)
}

function Test-WithinRoot {
    param(
        [Parameter(Mandatory)][string]$Candidate,
        [Parameter(Mandatory)][string]$Parent
    )

    $comparison = [System.StringComparison]'OrdinalIgnoreCase'
    $normalizedParent = $Parent.TrimEnd([char[]]@('\', '/'))
    $prefix = $normalizedParent + '\'
    return $Candidate.Equals($normalizedParent, $comparison) -or
        $Candidate.StartsWith($prefix, $comparison)
}

function Assert-NoReparseAncestor {
    param([Parameter(Mandatory)][System.IO.FileSystemInfo]$Item)

    $current = $Item
    while ($null -ne $current) {
        if (($current.Attributes -band [System.IO.FileAttributes]'ReparsePoint') -ne 0) {
            Stop-Validation 'protected path contains a reparse-point boundary'
        }
        $current = $current.Parent
    }
}

function Resolve-Sid {
    param([Parameter(Mandatory)][string]$Identity)

    try {
        $account = New-Object System.Security.Principal.NTAccount -ArgumentList $Identity
        return $account.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $Identity
            return $sid.Value
        }
        catch {
            Stop-Validation 'protected path ACL contains an unresolvable identity'
        }
    }
}

function Assert-ProtectedAcl {
    param(
        [Parameter(Mandatory)][System.IO.FileSystemInfo]$Item,
        [Parameter(Mandatory)][string]$OperatorSid,
        [Parameter(Mandatory)][string]$SystemSid,
        [switch]$RequireProtectedRoot
    )

    $acl = Get-Acl -LiteralPath $Item.FullName
    if ($RequireProtectedRoot -and -not $acl.AreAccessRulesProtected) {
        Stop-Validation 'workspace ACL inheritance must be disabled'
    }
    if ((Resolve-Sid -Identity $acl.Owner) -ne $OperatorSid) {
        Stop-Validation 'protected path owner is not the current operator SID'
    }

    $allowedSids = @($OperatorSid, $SystemSid)
    $rules = @($acl.Access)
    if ($rules.Count -ne $allowedSids.Count) {
        Stop-Validation 'protected path DACL is not the exact two-principal allowlist'
    }

    $seenSids = @{}
    $fullControl = [System.Security.AccessControl.FileSystemRights]'FullControl'
    $requiredInheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($rule in $rules) {
        $sid = Resolve-Sid -Identity $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]'Allow' -or
            $allowedSids -notcontains $sid -or
            $seenSids.ContainsKey($sid) -or
            [int64]$rule.FileSystemRights -ne [int64]$fullControl -or
            $rule.PropagationFlags -ne
                [System.Security.AccessControl.PropagationFlags]'None' -or
            ($RequireProtectedRoot -and $rule.IsInherited)) {
            Stop-Validation 'protected path ACL is outside the exact operator-and-SYSTEM contract'
        }
        if ($Item.PSIsContainer -and
            ($rule.InheritanceFlags -band $requiredInheritance) -ne
                $requiredInheritance) {
            Stop-Validation 'protected directory ACL does not propagate exact full control'
        }
        $seenSids[$sid] = $true
    }
    foreach ($requiredSid in $allowedSids) {
        if (-not $seenSids.ContainsKey($requiredSid)) {
            Stop-Validation 'protected path ACL lacks exact full-control authority'
        }
    }
    return $acl
}

function Assert-NonElevatedOperator {
    param([Parameter(Mandatory)][System.Security.Principal.WindowsIdentity]$Identity)

    $principal = New-Object System.Security.Principal.WindowsPrincipal -ArgumentList $Identity
    if ($principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]'Administrator')) {
        Stop-Validation 'credential ceremony must run in a non-elevated process'
    }
    $forbiddenIntegritySids = @(
        'S-1-16-12288',
        'S-1-16-16384',
        'S-1-16-20480'
    )
    foreach ($group in @($Identity.Groups)) {
        if ($forbiddenIntegritySids -contains $group.Value) {
            Stop-Validation 'credential ceremony process integrity is elevated'
        }
    }
}

function Assert-NoAmbientCrossAuthority {
    $exactNames = @(
        'GH_TOKEN',
        'GITHUB_TOKEN',
        'GH_ENTERPRISE_TOKEN',
        'GITHUB_ENTERPRISE_TOKEN',
        'GIT_ASKPASS',
        'SSH_ASKPASS',
        'SSH_ASKPASS_REQUIRE',
        'SSH_AUTH_SOCK',
        'SSH_AGENT_PID',
        'GIT_SSH',
        'GIT_SSH_COMMAND',
        'GIT_CREDENTIAL_HELPER',
        'GIT_TERMINAL_PROMPT'
    )
    foreach ($entry in @(Get-ChildItem -Path 'Env:' -ErrorAction Stop)) {
        $value = [string]$entry.Value
        if ($value.Length -eq 0) {
            continue
        }
        if ($exactNames -contains $entry.Name -or
            $entry.Name -match '^(?i:GIT_CONFIG(?:_|$))' -or
            $entry.Name -match '^(?i:GCM(?:_|$))') {
            Stop-Validation 'ambient Git, GitHub, or SSH credential authority must be absent'
        }
    }
}

function Get-ExactVolume {
    param([Parameter(Mandatory)][string]$DriveLetter)

    $volumes = @(Get-Volume -DriveLetter $DriveLetter -ErrorAction Stop)
    if ($volumes.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$volumes[0].UniqueId)) {
        Stop-Validation 'a protected backing volume could not be identified exactly'
    }
    return $volumes[0]
}

function Assert-BitLockerProtected {
    param(
        [Parameter(Mandatory)][string]$MountPoint,
        [Parameter(Mandatory)][string]$FailureReason
    )

    $statuses = @(Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop)
    if ($statuses.Count -ne 1) {
        Stop-Validation $FailureReason
    }
    $status = $statuses[0]
    if ($status.ProtectionStatus.ToString() -ne 'On' -or
        [int]$status.EncryptionPercentage -ne 100 -or
        $status.VolumeStatus.ToString() -ne 'FullyEncrypted') {
        Stop-Validation $FailureReason
    }
    return $status
}

function Get-ObjectProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [switch]$Required
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        if ($Required) {
            Stop-Validation 'Windows residue configuration is incomplete'
        }
        return $null
    }
    return $property.Value
}

function Add-Destination {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$List,
        [Parameter(Mandatory)][string]$Kind,
        [AllowNull()][object]$Value
    )

    foreach ($candidate in @($Value)) {
        if ($null -eq $candidate -or
            [string]::IsNullOrWhiteSpace([string]$candidate)) {
            continue
        }
        $List.Add([pscustomobject]@{
            Kind = $Kind
            RawPath = ([string]$candidate).Trim()
        })
    }
}

function Get-PageFileDestinations {
    $destinations = New-Object 'System.Collections.Generic.List[object]'
    try {
        $computerSystems = @(Get-CimInstance -ClassName Win32_ComputerSystem `
            -Property AutomaticManagedPagefile -ErrorAction Stop)
        $settings = @(Get-CimInstance -ClassName Win32_PageFileSetting `
            -Property Name -ErrorAction Stop)
        $usage = @(Get-CimInstance -ClassName Win32_PageFileUsage `
            -Property Name -ErrorAction Stop)
        $memoryManagement = Get-ItemProperty -LiteralPath (
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        ) -ErrorAction Stop
    }
    catch {
        Stop-Validation 'pagefile destination inventory is unavailable'
    }

    if ($computerSystems.Count -ne 1 -or
        $null -eq $computerSystems[0].AutomaticManagedPagefile) {
        Stop-Validation 'pagefile management mode is ambiguous'
    }
    $pagingFiles = Get-ObjectProperty -Object $memoryManagement `
        -Name 'PagingFiles' -Required
    foreach ($specObject in @($pagingFiles)) {
        if ($null -eq $specObject -or
            [string]::IsNullOrWhiteSpace([string]$specObject)) {
            continue
        }
        $spec = ([string]$specObject).Trim()
        $match = [regex]::Match($spec, '^(?<path>.+?)\s+\d+\s+\d+$')
        if (-not $match.Success) {
            Stop-Validation 'configured pagefile syntax is ambiguous'
        }
        Add-Destination -List $destinations -Kind 'pagefile-registry' `
            -Value $match.Groups['path'].Value
    }
    Add-Destination -List $destinations -Kind 'pagefile-existing' `
        -Value (Get-ObjectProperty -Object $memoryManagement `
            -Name 'ExistingPageFiles')

    foreach ($setting in $settings) {
        $name = Get-ObjectProperty -Object $setting -Name 'Name' -Required
        if ([string]::IsNullOrWhiteSpace([string]$name)) {
            Stop-Validation 'configured pagefile destination is ambiguous'
        }
        Add-Destination -List $destinations -Kind 'pagefile-setting' -Value $name
    }
    foreach ($instance in $usage) {
        $name = Get-ObjectProperty -Object $instance -Name 'Name' -Required
        if ([string]::IsNullOrWhiteSpace([string]$name)) {
            Stop-Validation 'active pagefile destination is ambiguous'
        }
        Add-Destination -List $destinations -Kind 'pagefile-active' -Value $name
    }

    if ([bool]$computerSystems[0].AutomaticManagedPagefile -and
        $usage.Count -eq 0) {
        Stop-Validation 'automatic pagefile backing volume is not observable'
    }
    return @($destinations)
}

function Get-CrashDumpDestinations {
    $destinations = New-Object 'System.Collections.Generic.List[object]'
    try {
        $crashControl = Get-ItemProperty -LiteralPath (
            'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
        ) -ErrorAction Stop
        $recoveryConfigurations = @(Get-CimInstance `
            -ClassName Win32_OSRecoveryConfiguration `
            -Property DebugFilePath, MiniDumpDirectory -ErrorAction Stop)
    }
    catch {
        Stop-Validation 'crash-dump destination inventory is unavailable'
    }
    if ($recoveryConfigurations.Count -ne 1) {
        Stop-Validation 'crash-dump destination inventory is ambiguous'
    }

    $enabledValue = Get-ObjectProperty -Object $crashControl `
        -Name 'CrashDumpEnabled' -Required
    try {
        $enabled = [int]$enabledValue
    }
    catch {
        Stop-Validation 'crash-dump mode is ambiguous'
    }
    if (@(0, 1, 2, 3, 7) -notcontains $enabled) {
        Stop-Validation 'crash-dump mode is unsupported or ambiguous'
    }

    $dumpFile = Get-ObjectProperty -Object $crashControl -Name 'DumpFile'
    $miniDumpDirectory = Get-ObjectProperty -Object $crashControl `
        -Name 'MinidumpDir'
    $dedicatedDumpFile = Get-ObjectProperty -Object $crashControl `
        -Name 'DedicatedDumpFile'
    if (@(1, 2, 7) -contains $enabled -and
        [string]::IsNullOrWhiteSpace([string]$dumpFile)) {
        Stop-Validation 'enabled crash-dump file destination is unavailable'
    }
    if ($enabled -eq 3 -and
        [string]::IsNullOrWhiteSpace([string]$miniDumpDirectory)) {
        Stop-Validation 'enabled minidump destination is unavailable'
    }

    Add-Destination -List $destinations -Kind 'crash-dump-registry' `
        -Value $dumpFile
    Add-Destination -List $destinations -Kind 'minidump-registry' `
        -Value $miniDumpDirectory
    Add-Destination -List $destinations -Kind 'dedicated-dump-registry' `
        -Value $dedicatedDumpFile

    $recovery = $recoveryConfigurations[0]
    Add-Destination -List $destinations -Kind 'crash-dump-cim' `
        -Value (Get-ObjectProperty -Object $recovery -Name 'DebugFilePath' -Required)
    Add-Destination -List $destinations -Kind 'minidump-cim' `
        -Value (Get-ObjectProperty -Object $recovery -Name 'MiniDumpDirectory' -Required)
    return @($destinations)
}

function Resolve-ResidueDestination {
    param(
        [Parameter(Mandatory)][string]$RawPath,
        [Parameter(Mandatory)][string]$TrustedSystemRoot,
        [Parameter(Mandatory)][string]$TrustedSystemMount
    )

    $value = $RawPath.Trim()
    if ($value.Length -ge 2 -and $value[0] -eq '"' -and
        $value[$value.Length - 1] -eq '"') {
        $value = $value.Substring(1, $value.Length - 2)
    }
    if ($value.StartsWith('\??\', [System.StringComparison]'Ordinal')) {
        $value = $value.Substring(4)
    }
    $value = $value -ireplace '%SystemRoot%', $TrustedSystemRoot
    $value = $value -ireplace '%windir%', $TrustedSystemRoot
    $value = $value -ireplace '%SystemDrive%', $TrustedSystemMount.TrimEnd('\')
    if ($value.Contains('%') -or $value.IndexOfAny([char[]]@('*', '?')) -ge 0 -or
        $value -notmatch '^[A-Za-z]:[\\/]' -or
        $value.Substring(2).Contains(':')) {
        Stop-Validation 'residue destination is not an unambiguous local drive path'
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($value).Replace('/', '\')
    }
    catch {
        Stop-Validation 'residue destination cannot be canonicalized'
    }
    $mountPoint = [System.IO.Path]::GetPathRoot($fullPath)
    if ($mountPoint -notmatch '^[A-Za-z]:\\$') {
        Stop-Validation 'residue backing volume is ambiguous'
    }
    return [pscustomobject]@{
        FullPath = $fullPath
        MountPoint = $mountPoint
    }
}

function Initialize-NativeFileApi {
    $existing = New-Object System.Management.Automation.PSTypeName `
        -ArgumentList 'WebsiteInfrastructureNativeFile'
    if ($null -ne $existing.Type) {
        return
    }

    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

[StructLayout(LayoutKind.Sequential)]
public struct WebsiteInfrastructureFileInformation
{
    public uint FileAttributes;
    public uint CreationTimeLow;
    public uint CreationTimeHigh;
    public uint LastAccessTimeLow;
    public uint LastAccessTimeHigh;
    public uint LastWriteTimeLow;
    public uint LastWriteTimeHigh;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
}

public static class WebsiteInfrastructureNativeFile
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out WebsiteInfrastructureFileInformation information);
}
'@ | Out-Null
}

function Test-NativeFileInformationEqual {
    param(
        [Parameter(Mandatory)][object]$Left,
        [Parameter(Mandatory)][object]$Right
    )

    return $Left.FileAttributes -eq $Right.FileAttributes -and
        $Left.LastWriteTimeLow -eq $Right.LastWriteTimeLow -and
        $Left.LastWriteTimeHigh -eq $Right.LastWriteTimeHigh -and
        $Left.VolumeSerialNumber -eq $Right.VolumeSerialNumber -and
        $Left.FileSizeHigh -eq $Right.FileSizeHigh -and
        $Left.FileSizeLow -eq $Right.FileSizeLow -and
        $Left.NumberOfLinks -eq $Right.NumberOfLinks -and
        $Left.FileIndexHigh -eq $Right.FileIndexHigh -and
        $Left.FileIndexLow -eq $Right.FileIndexLow
}

function Get-NativeFileSnapshot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Exclusive,
        [switch]$RequireSingleLink,
        [scriptblock]$DuringOpenValidation
    )

    Initialize-NativeFileApi
    $genericRead = [uint32]0x80000000
    $shareMode = if ($Exclusive) { [uint32]0 } else { [uint32]7 }
    $openExisting = [uint32]3
    $openReparsePoint = [uint32]0x00200000
    $sequentialScan = [uint32]0x08000000
    $handle = [WebsiteInfrastructureNativeFile]::
        CreateFileW(
        $Path,
        $genericRead,
        $shareMode,
        [IntPtr]::Zero,
        $openExisting,
        ($openReparsePoint -bor $sequentialScan),
        [IntPtr]::Zero
    )
    if ($null -eq $handle -or $handle.IsInvalid) {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        Stop-Validation 'protected file could not be opened as one stable object'
    }

    $stream = $null
    try {
        $before = New-Object WebsiteInfrastructureFileInformation
        if (-not [WebsiteInfrastructureNativeFile]::GetFileInformationByHandle(
                $handle, [ref]$before)) {
            Stop-Validation 'protected file identity could not be read'
        }
        $directoryFlag = [uint32][System.IO.FileAttributes]'Directory'
        $reparseFlag = [uint32][System.IO.FileAttributes]'ReparsePoint'
        if (($before.FileAttributes -band $directoryFlag) -ne 0 -or
            ($before.FileAttributes -band $reparseFlag) -ne 0) {
            Stop-Validation 'protected file is not a regular non-reparse file'
        }
        if ($RequireSingleLink -and $before.NumberOfLinks -ne 1) {
            Stop-Validation 'protected file must have exactly one hard-link name'
        }
        if ($null -ne $DuringOpenValidation) {
            $null = & $DuringOpenValidation
        }

        $stream = [System.IO.FileStream]::new(
            $handle, [System.IO.FileAccess]::Read, 65536, $false
        )
        $handle = $null
        $hasher = [System.Security.Cryptography.SHA256]::
            Create()
        try {
            $hash = $hasher.ComputeHash($stream)
        }
        finally {
            $hasher.Dispose()
        }
        if ($null -ne $DuringOpenValidation) {
            $null = & $DuringOpenValidation
        }

        $after = New-Object WebsiteInfrastructureFileInformation
        if (-not [WebsiteInfrastructureNativeFile]::GetFileInformationByHandle(
                $stream.SafeFileHandle, [ref]$after) -or
            -not (Test-NativeFileInformationEqual -Left $before -Right $after)) {
            Stop-Validation 'protected file changed during validation'
        }
        if ($RequireSingleLink -and $after.NumberOfLinks -ne 1) {
            Stop-Validation 'protected file link count changed during validation'
        }

        $fileIndex = ([uint64]$after.FileIndexHigh -shl 32) -bor
            [uint64]$after.FileIndexLow
        $fileSize = ([uint64]$after.FileSizeHigh -shl 32) -bor
            [uint64]$after.FileSizeLow
        $lastWrite = ([uint64]$after.LastWriteTimeHigh -shl 32) -bor
            [uint64]$after.LastWriteTimeLow
        return [pscustomobject]@{
            Sha256 = (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
            VolumeSerialNumber = $after.VolumeSerialNumber
            FileIndex = $fileIndex
            FileSize = $fileSize
            LastWriteFileTime = $lastWrite
            NumberOfLinks = $after.NumberOfLinks
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        elseif ($null -ne $handle) {
            $handle.Dispose()
        }
    }
}

function Get-ProtectedFileRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$OperatorSid,
        [Parameter(Mandatory)][string]$SystemSid
    )

    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or
        $Path.Substring(2).Contains(':')) {
        Stop-Validation 'protected file path must be an absolute local path'
    }
    $initial = Get-Item -LiteralPath $Path -Force
    if ($initial.PSIsContainer -or $initial -isnot [System.IO.FileInfo]) {
        Stop-Validation 'protected file input is not a regular file'
    }
    Assert-NoReparseAncestor -Item $initial
    if (-not (Test-WithinRoot -Candidate $initial.FullName -Parent $RootPath) -or
        $initial.FullName.Equals(
            $RootPath, [System.StringComparison]'OrdinalIgnoreCase')) {
        Stop-Validation 'protected file input escapes the credential workspace'
    }

    $validationState = @{
        Count = 0
        Descriptor = $null
    }
    $validateOpenPath = {
        $current = Get-Item -LiteralPath $initial.FullName -Force
        if ($current.PSIsContainer -or $current -isnot [System.IO.FileInfo]) {
            Stop-Validation 'protected file changed type during validation'
        }
        Assert-NoReparseAncestor -Item $current
        if (-not (Test-WithinRoot -Candidate $current.FullName -Parent $RootPath)) {
            Stop-Validation 'protected file changed containment during validation'
        }
        $currentAcl = Assert-ProtectedAcl -Item $current `
            -OperatorSid $OperatorSid -SystemSid $SystemSid
        $descriptor = $currentAcl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]'All'
        )
        if ($validationState.Count -eq 0) {
            $validationState.Descriptor = $descriptor
        }
        elseif ($validationState.Descriptor -ne $descriptor) {
            Stop-Validation 'protected file ACL changed during validation'
        }
        $validationState.Count++
    }
    $snapshot = Get-NativeFileSnapshot -Path $initial.FullName -Exclusive `
        -RequireSingleLink -DuringOpenValidation $validateOpenPath
    if ($validationState.Count -ne 2) {
        Stop-Validation 'protected file validation was incomplete'
    }

    return [pscustomobject]@{
        Path = $initial.FullName
        Record = @(
            ('path={0}' -f $initial.FullName),
            ('volume-serial={0}' -f $snapshot.VolumeSerialNumber),
            ('file-index={0}' -f $snapshot.FileIndex),
            ('size={0}' -f $snapshot.FileSize),
            ('last-write-filetime={0}' -f $snapshot.LastWriteFileTime),
            ('links={0}' -f $snapshot.NumberOfLinks),
            ('acl={0}' -f $validationState.Descriptor),
            ('sha256={0}' -f $snapshot.Sha256)
        ) -join "`n"
    }
}

function Get-ToolProvenanceRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Role,
        [switch]$Exclusive,
        [switch]$ContentOnly
    )

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item -isnot [System.IO.FileInfo]) {
        Stop-Validation 'validator tool provenance is not a regular file'
    }
    Assert-NoReparseAncestor -Item $item
    $snapshot = Get-NativeFileSnapshot -Path $item.FullName `
        -Exclusive:$Exclusive
    if ($ContentOnly) {
        return @(
            ('role={0}' -f $Role),
            ('sha256={0}' -f $snapshot.Sha256)
        ) -join "`n"
    }
    return @(
        ('role={0}' -f $Role),
        ('volume-serial={0}' -f $snapshot.VolumeSerialNumber),
        ('file-index={0}' -f $snapshot.FileIndex),
        ('size={0}' -f $snapshot.FileSize),
        ('last-write-filetime={0}' -f $snapshot.LastWriteFileTime),
        ('sha256={0}' -f $snapshot.Sha256)
    ) -join "`n"
}

function Invoke-Validation {
    if ($env:OS -ne 'Windows_NT') {
        Stop-Validation 'this gate must run on Windows'
    }
    if ($null -eq $Root -or $Root.Trim().Length -eq 0) {
        Stop-Validation 'protected workspace path was not supplied through the process'
    }
    if ($Root -notmatch '^[A-Za-z]:[\\/]') {
        Stop-Validation 'protected workspace path must be absolute'
    }
    if (-not $Session -and @($ProtectedFile).Count -ne 0) {
        Stop-Validation 'protected files require current-session validation'
    }
    if (@($ProtectedFile).Count -gt 128) {
        Stop-Validation 'protected file set exceeds the bounded validation limit'
    }

    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $currentIdentity -or $null -eq $currentIdentity.User) {
        Stop-Validation 'current Windows operator identity is unavailable'
    }
    Assert-NonElevatedOperator -Identity $currentIdentity
    $operatorSid = $currentIdentity.User.Value
    $systemSid = 'S-1-5-18'

    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not $rootItem.PSIsContainer) {
        Stop-Validation 'protected workspace is not a directory'
    }
    Assert-NoReparseAncestor -Item $rootItem

    if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        $RepositoryRoot = Join-Path -Path $PSScriptRoot -ChildPath '..'
    }
    if ($RepositoryRoot -notmatch '^[A-Za-z]:[\\/]') {
        Stop-Validation 'repository root must be supplied as an absolute local path'
    }
    $repoItem = Get-Item -LiteralPath $RepositoryRoot -Force
    if (-not $repoItem.PSIsContainer) {
        Stop-Validation 'repository root is not a directory'
    }
    Assert-NoReparseAncestor -Item $repoItem
    $repoRoot = $repoItem.FullName
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot '.git')) -or
        -not (Test-Path -LiteralPath (Join-Path $repoRoot 'AGENTS.md') `
            -PathType Leaf)) {
        Stop-Validation 'repository root lacks the expected local checkout markers'
    }

    $rootPath = $rootItem.FullName
    if (Test-WithinRoot -Candidate $rootPath -Parent $repoRoot) {
        Stop-Validation 'protected workspace must be outside the repository'
    }

    if ($rootItem.PSDrive.Name -notmatch '^[A-Za-z]$') {
        Stop-Validation 'protected workspace must use a dedicated drive-letter volume'
    }
    $mountPoint = '{0}:\' -f $rootItem.PSDrive.Name
    $pathComparison = [System.StringComparison]'OrdinalIgnoreCase'
    if (-not $rootPath.TrimEnd('\').Equals(
            $mountPoint.TrimEnd('\'), $pathComparison)) {
        Stop-Validation 'protected workspace must be the root of its dedicated volume'
    }
    $repositoryMount = [System.IO.Path]::GetPathRoot($repoRoot)
    if ($mountPoint.Equals($repositoryMount, $pathComparison)) {
        Stop-Validation 'workspace volume must differ from the repository volume'
    }
    $systemDirectory = [System.Environment]::SystemDirectory
    $systemMount = [System.IO.Path]::GetPathRoot($systemDirectory)
    if ($systemMount -notmatch '^[A-Za-z]:\\$') {
        Stop-Validation 'Windows system volume is unavailable'
    }
    if ($mountPoint.Equals($systemMount, $pathComparison)) {
        Stop-Validation 'workspace volume must differ from the Windows system volume'
    }
    $systemRoot = [System.IO.Directory]::GetParent($systemDirectory).FullName

    $volume = Get-ExactVolume -DriveLetter $rootItem.PSDrive.Name
    if ($volume.FileSystem -ne 'NTFS') {
        Stop-Validation 'protected workspace volume must use NTFS'
    }
    $bitLocker = Assert-BitLockerProtected -MountPoint $mountPoint `
        -FailureReason 'workspace BitLocker protection is not active and complete'

    $systemVolume = Get-ExactVolume -DriveLetter $systemMount.Substring(0, 1)
    $systemBitLocker = Assert-BitLockerProtected `
        -MountPoint $systemMount `
        -FailureReason 'system-volume BitLocker protection is not active and complete'

    if (($rootItem.Attributes -band [System.IO.FileAttributes]'NotContentIndexed') -eq 0) {
        Stop-Validation 'protected workspace must be marked not-content-indexed'
    }
    $acl = Assert-ProtectedAcl -Item $rootItem -OperatorSid $operatorSid `
        -SystemSid $systemSid -RequireProtectedRoot

    $destinationRecords = New-Object 'System.Collections.Generic.List[string]'
    $residueVolumes = New-Object `
        'System.Collections.Generic.Dictionary[string,object]' `
        ([System.StringComparer]::OrdinalIgnoreCase)
    $residueDestinations = @(
        @(Get-PageFileDestinations)
        @(Get-CrashDumpDestinations)
    )
    foreach ($destination in $residueDestinations) {
        $resolved = Resolve-ResidueDestination -RawPath $destination.RawPath `
            -TrustedSystemRoot $systemRoot -TrustedSystemMount $systemMount
        $destinationRecords.Add(
            ('{0}={1}' -f $destination.Kind, $resolved.FullPath)
        )
        if (-not $residueVolumes.ContainsKey($resolved.MountPoint)) {
            $backingVolume = Get-ExactVolume `
                -DriveLetter $resolved.MountPoint.Substring(0, 1)
            $backingBitLocker = Assert-BitLockerProtected `
                -MountPoint $resolved.MountPoint `
                -FailureReason 'residue backing-volume BitLocker protection is not active and complete'
            $residueVolumes[$resolved.MountPoint] = [pscustomobject]@{
                Volume = $backingVolume
                BitLocker = $backingBitLocker
            }
        }
    }

    $sessionRecords = New-Object 'System.Collections.Generic.List[string]'
    $cliConfigRecord = $null
    if ($Session) {
        Assert-NoAmbientCrossAuthority
        $cliArgumentOverrides = @(
            Get-ChildItem -Path 'Env:TF_CLI_ARGS*' -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^(?i:TF_CLI_ARGS(?:_|$))' }
        )
        foreach ($entry in $cliArgumentOverrides) {
            $value = [string]$entry.Value
            if ($value.Length -ne 0) {
                Stop-Validation 'ambient OpenTofu CLI argument injection must be absent'
            }
        }
        foreach ($name in @('TF_LOG', 'TF_LOG_CORE', 'TF_LOG_PROVIDER')) {
            $entry = Get-Item -LiteralPath ('Env:{0}' -f $name) `
                -ErrorAction SilentlyContinue
            $value = if ($null -eq $entry) { $null } else { [string]$entry.Value }
            if ($null -ne $value -and $value.Trim().Length -ne 0 -and
                $value -notmatch '^(?i:off)$') {
                Stop-Validation 'ambient OpenTofu logging must be disabled'
            }
        }
        foreach ($name in @(
                'TF_LOG_PATH', 'TF_REATTACH_PROVIDERS', 'TF_WORKSPACE',
                'TF_IGNORE', 'TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE'
            )) {
            $entry = Get-Item -LiteralPath ('Env:{0}' -f $name) `
                -ErrorAction SilentlyContinue
            $value = if ($null -eq $entry) { $null } else { [string]$entry.Value }
            if ($null -ne $value -and $value.Trim().Length -ne 0) {
                Stop-Validation 'ambient OpenTofu workspace, debug, or lockfile override must be absent'
            }
        }
        foreach ($name in @(
                'CLOUDFLARE_API_KEY', 'CLOUDFLARE_EMAIL',
                'CLOUDFLARE_API_USER_SERVICE_KEY'
            )) {
            $entry = Get-Item -LiteralPath ('Env:{0}' -f $name) `
                -ErrorAction SilentlyContinue
            $value = if ($null -eq $entry) { $null } else { [string]$entry.Value }
            if ($null -ne $value -and $value.Length -ne 0) {
                Stop-Validation 'legacy Cloudflare authentication environment must be absent'
            }
        }

        foreach ($name in @('TEMP', 'TMP', 'TF_DATA_DIR', 'TF_PLUGIN_CACHE_DIR')) {
            $entry = Get-Item -LiteralPath ('Env:{0}' -f $name) `
                -ErrorAction SilentlyContinue
            $value = if ($null -eq $entry) { $null } else { [string]$entry.Value }
            if ($null -eq $value -or $value.Trim().Length -eq 0 -or
                $value -notmatch '^[A-Za-z]:[\\/]') {
                Stop-Validation 'required process-local protected path is absent'
            }
            $item = Get-Item -LiteralPath $value -Force
            if (-not $item.PSIsContainer) {
                Stop-Validation 'required process-local protected path is not a directory'
            }
            Assert-NoReparseAncestor -Item $item
            if (-not (Test-WithinRoot -Candidate $item.FullName -Parent $rootPath)) {
                Stop-Validation 'process-local temporary or tool path escapes the workspace'
            }
            $itemAcl = Assert-ProtectedAcl -Item $item -OperatorSid $operatorSid `
                -SystemSid $systemSid
            $itemDescriptor = $itemAcl.GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]'All'
            )
            $sessionRecords.Add(
                ('path={0}|value={1}|acl={2}' -f $name, $item.FullName, $itemDescriptor)
            )
        }

        $cliConfigEntry = Get-Item -LiteralPath 'Env:TF_CLI_CONFIG_FILE' `
            -ErrorAction SilentlyContinue
        $cliConfig = if ($null -eq $cliConfigEntry) {
            $null
        }
        else {
            [string]$cliConfigEntry.Value
        }
        if ($null -eq $cliConfig -or $cliConfig.Trim().Length -eq 0 -or
            $cliConfig -notmatch '^[A-Za-z]:[\\/]') {
            Stop-Validation 'protected OpenTofu CLI configuration path is absent'
        }
        $cliConfigRecord = Get-ProtectedFileRecord -Path $cliConfig `
            -RootPath $rootPath -OperatorSid $operatorSid -SystemSid $systemSid

        $psReadLine = Get-Module -Name PSReadLine
        if ($null -ne $psReadLine) {
            $historyStyle = (Get-PSReadLineOption).HistorySaveStyle
            if ($historyStyle -ne 'SaveNothing') {
                Stop-Validation 'PSReadLine history must be disabled for the ceremony process'
            }
        }
    }

    $scriptProvenance = Get-ToolProvenanceRecord -Path $PSCommandPath `
        -Role 'windows-credential-validator' -Exclusive -ContentOnly
    $hostPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $hostProvenance = Get-ToolProvenanceRecord -Path $hostPath `
        -Role 'powershell-host'

    $descriptor = $acl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]'All'
    )
    $attestationLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @(
            'schema=2',
            ('root={0}' -f $rootPath),
            ('repository-root={0}' -f $repoRoot),
            ('volume={0}' -f $volume.UniqueId),
            ('filesystem={0}' -f $volume.FileSystem),
            ('bitlocker={0}:{1}:{2}' -f $bitLocker.ProtectionStatus,
                $bitLocker.EncryptionPercentage, $bitLocker.VolumeStatus),
            ('system-volume={0}' -f $systemVolume.UniqueId),
            ('system-bitlocker={0}:{1}:{2}' -f $systemBitLocker.ProtectionStatus,
                $systemBitLocker.EncryptionPercentage,
                $systemBitLocker.VolumeStatus),
            ('owner={0}' -f $operatorSid),
            ('acl={0}' -f $descriptor),
            ('non-elevated=true'),
            ('session={0}' -f $Session.IsPresent),
            ('powershell-edition={0}' -f $PSVersionTable.PSEdition),
            ('powershell-version={0}' -f $PSVersionTable.PSVersion.ToString()),
            ('script-provenance={0}' -f $scriptProvenance.Replace("`n", '|')),
            ('host-provenance={0}' -f $hostProvenance.Replace("`n", '|'))
        )) {
        $attestationLines.Add($line)
    }
    foreach ($line in @($destinationRecords | Sort-Object)) {
        $attestationLines.Add(('residue-destination={0}' -f $line))
    }
    foreach ($mount in @($residueVolumes.Keys | Sort-Object)) {
        $status = $residueVolumes[$mount]
        $attestationLines.Add(
            ('residue-volume={0}|id={1}|bitlocker={2}:{3}:{4}' -f
                $mount, $status.Volume.UniqueId,
                $status.BitLocker.ProtectionStatus,
                $status.BitLocker.EncryptionPercentage,
                $status.BitLocker.VolumeStatus)
        )
    }
    foreach ($line in @($sessionRecords | Sort-Object)) {
        $attestationLines.Add(('session-path={0}' -f $line))
    }
    if ($null -ne $cliConfigRecord) {
        $attestationLines.Add(
            ('cli-config={0}' -f $cliConfigRecord.Record.Replace("`n", '|'))
        )
        $attestationLines.Add('cross-authority-environment=absent')
    }
    $attestationInput = $attestationLines -join "`n"
    $workspaceAttestationSha256 = Get-TextSha256 -Text $attestationInput

    $protectedRecords = New-Object 'System.Collections.Generic.List[object]'
    $protectedPaths = New-Object 'System.Collections.Generic.HashSet[string]' `
        ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @($ProtectedFile)) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            Stop-Validation 'protected file input is empty'
        }
        $record = Get-ProtectedFileRecord -Path $path -RootPath $rootPath `
            -OperatorSid $operatorSid -SystemSid $systemSid
        if (-not $protectedPaths.Add($record.Path)) {
            Stop-Validation 'protected file set contains a duplicate path'
        }
        $protectedRecords.Add($record)
    }

    Write-Output 'PASS protected Windows credential workspace'
    Write-Output ('workspace_attestation_sha256={0}' -f $workspaceAttestationSha256)
    if ($protectedRecords.Count -ne 0) {
        $fileSetLines = New-Object 'System.Collections.Generic.List[string]'
        $fileSetLines.Add('schema=1')
        foreach ($record in @($protectedRecords | Sort-Object -Property Path)) {
            $fileSetLines.Add($record.Record)
        }
        $protectedFileSetSha256 = Get-TextSha256 `
            -Text ($fileSetLines -join "`n")
        $validationUtc = [DateTime]::UtcNow.ToString(
            'yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture
        )
        $processStart = [System.Diagnostics.Process]::GetCurrentProcess().StartTime
        $processStartUtc = $processStart.ToUniversalTime().ToString(
                'yyyy-MM-ddTHH:mm:ssZ',
                [System.Globalization.CultureInfo]::InvariantCulture
            )
        $validationInput = @(
            'schema=1',
            ('workspace={0}' -f $workspaceAttestationSha256),
            ('protected-files={0}' -f $protectedFileSetSha256),
            ('validated-at={0}' -f $validationUtc),
            ('process-start={0}' -f $processStartUtc)
        ) -join "`n"
        $validationAttestationSha256 = Get-TextSha256 -Text $validationInput
        Write-Output ('protected_file_set_sha256={0}' -f $protectedFileSetSha256)
        Write-Output ('validation_utc={0}' -f $validationUtc)
        Write-Output ('validation_attestation_sha256={0}' -f $validationAttestationSha256)
    }
}

try {
    Invoke-Validation
}
catch {
    [Console]::
        Error.WriteLine('FAIL protected Windows credential workspace')
    exit 1
}
