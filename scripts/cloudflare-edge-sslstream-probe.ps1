#!/usr/bin/env pwsh
<#
.SYNOPSIS
Fail-closed public edge acceptance using the frozen legacy-capable SslStream client.

.DESCRIPTION
This script is read-only and accepts only the two production apex hostnames. A
live probe requires the exact PowerShell/.NET pair that negotiated TLS 1.0,
1.1, 1.2, and 1.3 before hardening. Certificate validation and revocation
checking remain enabled. -SelfTest is hermetic and performs no network access.
#>

[CmdletBinding(DefaultParameterSetName = "Probe")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Probe")]
    [ValidateSet("Prechange", "Postchange")]
    [string]$Mode,

    [Parameter(ParameterSetName = "Probe")]
    [ValidateSet("all", "naranjo.online", "lidersea.com")]
    [string]$Zone = "all",

    [Parameter(Mandatory = $true, ParameterSetName = "SelfTest")]
    [switch]$SelfTest,

    [ValidateRange(1000, 30000)]
    [int]$TimeoutMilliseconds = 15000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ExpectedPowerShell = "7.6.4"
$ExpectedFramework = ".NET 10.0.10"
$CanonicalScriptPattern = "(?is)<script\b[^>]*>.*?</script>"
$CanonicalBlankLinePattern = "(?m)^[ \t]*\r?\n"

$ZoneContracts = [ordered]@{
    "naranjo.online" = [ordered]@{
        Characters = 512
        Sha256 = "0B90BBD8ED52F7106D187188DDB5FF62E39376672D5709D8EADCE3DD10ABFE1A"
    }
    "lidersea.com" = [ordered]@{
        Characters = 546
        Sha256 = "400CB6544FF009DC244E7C2CA583130323E75E4FF5DC2519FBDAD6DF728896DE"
    }
}

$ProtocolOffers = [ordered]@{
    tls10 = [System.Security.Authentication.SslProtocols]::Tls
    tls11 = [System.Security.Authentication.SslProtocols]::Tls11
    tls12 = [System.Security.Authentication.SslProtocols]::Tls12
    tls13 = [System.Security.Authentication.SslProtocols]::Tls13
}

$NegotiatedNames = [ordered]@{
    tls10 = "Tls"
    tls11 = "Tls11"
    tls12 = "Tls12"
    tls13 = "Tls13"
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)
    )
}

function Get-CanonicalBody {
    param([Parameter(Mandatory = $true)][string]$Body)

    $matches = [regex]::Matches($Body, $CanonicalScriptPattern)
    if ($matches.Count -ne 3) {
        throw "canonical body requires exactly three injected script elements"
    }
    $canonical = [regex]::Replace($Body, $CanonicalScriptPattern, "")
    $canonical = [regex]::Replace(
        $canonical,
        $CanonicalBlankLinePattern,
        ""
    )
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonical)
    return [pscustomobject][ordered]@{
        ScriptCount = $matches.Count
        Characters = $canonical.Length
        Sha256 = Get-Sha256Hex -Bytes $bytes
        CanonicalText = $canonical
    }
}

function Get-ExpectedTlsOutcome {
    param(
        [Parameter(Mandatory = $true)][string]$SelectedMode,
        [Parameter(Mandatory = $true)][string]$Protocol
    )

    if ($SelectedMode -eq "Prechange") {
        return "accepted"
    }
    if ($Protocol -in @("tls10", "tls11")) {
        return "rejected"
    }
    return "accepted"
}

function Assert-TlsMatrix {
    param(
        [Parameter(Mandatory = $true)][string]$SelectedMode,
        [Parameter(Mandatory = $true)][object[]]$Records
    )

    if ($Records.Count -ne 4) {
        throw "TLS matrix must contain exactly four protocol records"
    }
    foreach ($protocol in $ProtocolOffers.Keys) {
        $matching = @($Records | Where-Object { $_.Protocol -eq $protocol })
        if ($matching.Count -ne 1) {
            throw "TLS matrix must contain exactly one record for $protocol"
        }
        $record = $matching[0]
        $expected = Get-ExpectedTlsOutcome -SelectedMode $SelectedMode -Protocol $protocol
        if ($record.Outcome -ne $expected) {
            throw "TLS outcome mismatch for $protocol"
        }
        if (
            $expected -eq "accepted" -and
            $record.NegotiatedProtocol -ne $NegotiatedNames[$protocol]
        ) {
            throw "negotiated protocol mismatch for $protocol"
        }
    }
}

function Invoke-TlsOffer {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)]
        [System.Security.Authentication.SslProtocols]$Offer
    )

    $tcp = $null
    $stream = $null
    $connectCancellation = $null
    $authenticateCancellation = $null
    $stage = "connect"
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $connectCancellation = [System.Threading.CancellationTokenSource]::new(
            $TimeoutMilliseconds
        )
        $tcp.ConnectAsync(
            $HostName,
            443,
            $connectCancellation.Token
        ).GetAwaiter().GetResult()

        $stage = "authenticate"
        # No validation callback is supplied: platform chain/name validation is
        # load-bearing, and Online revocation checking is explicit below.
        $stream = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false)
        $options = [System.Net.Security.SslClientAuthenticationOptions]::new()
        $options.TargetHost = $HostName
        $options.EnabledSslProtocols = $Offer
        $options.CertificateRevocationCheckMode = (
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        )
        $authenticateCancellation = (
            [System.Threading.CancellationTokenSource]::new($TimeoutMilliseconds)
        )
        $stream.AuthenticateAsClientAsync(
            $options,
            $authenticateCancellation.Token
        ).GetAwaiter().GetResult()

        if ($null -eq $stream.RemoteCertificate) {
            throw "accepted TLS handshake returned no remote certificate"
        }
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $stream.RemoteCertificate
        )
        try {
            $certificateSha256 = $certificate.GetCertHashString(
                [System.Security.Cryptography.HashAlgorithmName]::SHA256
            )
        }
        finally {
            $certificate.Dispose()
        }
        return [pscustomobject][ordered]@{
            Protocol = $Protocol
            Outcome = "accepted"
            NegotiatedProtocol = $stream.SslProtocol.ToString()
            CertificateSha256 = $certificateSha256
            ErrorType = $null
        }
    }
    catch [System.Security.Authentication.AuthenticationException] {
        if ($stage -ne "authenticate") {
            throw
        }
        return [pscustomobject][ordered]@{
            Protocol = $Protocol
            Outcome = "rejected"
            NegotiatedProtocol = $null
            CertificateSha256 = $null
            ErrorType = $_.Exception.GetType().FullName
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Protocol = $Protocol
            Outcome = "error"
            NegotiatedProtocol = $null
            CertificateSha256 = $null
            ErrorType = $_.Exception.GetType().FullName
        }
    }
    finally {
        if ($null -ne $authenticateCancellation) {
            $authenticateCancellation.Dispose()
        }
        if ($null -ne $connectCancellation) {
            $connectCancellation.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if ($null -ne $tcp) {
            $tcp.Dispose()
        }
    }
}

function Invoke-BoundedHttpGet {
    param(
        [Parameter(Mandatory = $true)][string]$Uri
    )

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.CheckCertificateRevocationList = $true
    $handler.SslProtocols = (
        [System.Security.Authentication.SslProtocols]::Tls12 -bor
        [System.Security.Authentication.SslProtocols]::Tls13
    )
    $client = [System.Net.Http.HttpClient]::new($handler, $true)
    $client.Timeout = [TimeSpan]::new(0, 0, 0, 0, $TimeoutMilliseconds)
    $response = $null
    try {
        $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $location = if ($null -eq $response.Headers.Location) {
            $null
        }
        else {
            $response.Headers.Location.ToString()
        }
        return [pscustomobject][ordered]@{
            Status = [int]$response.StatusCode
            Location = $location
            Body = $body
        }
    }
    finally {
        if ($null -ne $response) {
            $response.Dispose()
        }
        $client.Dispose()
    }
}

function Assert-CanonicalContract {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][string]$Body
    )

    $actual = Get-CanonicalBody -Body $Body
    $expected = $ZoneContracts[$HostName]
    if (
        $actual.Characters -ne $expected.Characters -or
        $actual.Sha256 -ne $expected.Sha256
    ) {
        throw "canonical body identity mismatch for $HostName"
    }
    return $actual
}

function Invoke-HttpAcceptance {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][string]$SelectedMode
    )

    $rootPath = "/"
    $queryPath = "/readyz?probe=1&x=2"
    $httpRoot = Invoke-BoundedHttpGet -Uri "http://$HostName$rootPath"
    $httpQuery = Invoke-BoundedHttpGet -Uri "http://$HostName$queryPath"
    $httpsRoot = Invoke-BoundedHttpGet -Uri "https://$HostName$rootPath"

    if ($httpsRoot.Status -ne 200 -or $null -ne $httpsRoot.Location) {
        throw "HTTPS root must return direct status 200 for $HostName"
    }
    $httpsCanonical = Assert-CanonicalContract -HostName $HostName -Body $httpsRoot.Body

    if ($SelectedMode -eq "Prechange") {
        if (
            $httpRoot.Status -ne 200 -or
            $httpQuery.Status -ne 200 -or
            $null -ne $httpRoot.Location -or
            $null -ne $httpQuery.Location
        ) {
            throw "pre-change HTTP requests must return direct status 200 for $HostName"
        }
        $httpCanonical = Assert-CanonicalContract -HostName $HostName -Body $httpRoot.Body
        if (
            $httpCanonical.Characters -ne $httpsCanonical.Characters -or
            $httpCanonical.Sha256 -ne $httpsCanonical.Sha256
        ) {
            throw "pre-change HTTP and HTTPS canonical bodies disagree for $HostName"
        }
    }
    else {
        foreach ($pair in @(
            @($httpRoot, "https://$HostName$rootPath"),
            @($httpQuery, "https://$HostName$queryPath")
        )) {
            $response = $pair[0]
            $expectedLocation = $pair[1]
            if (
                $response.Status -notin @(301, 308) -or
                $response.Location -ne $expectedLocation
            ) {
                throw "post-change HTTP redirect contract failed for $HostName"
            }
        }
    }

    return [pscustomobject][ordered]@{
        HttpRootStatus = $httpRoot.Status
        HttpRootLocation = $httpRoot.Location
        HttpQueryStatus = $httpQuery.Status
        HttpQueryLocation = $httpQuery.Location
        HttpsRootStatus = $httpsRoot.Status
        CanonicalScriptCount = $httpsCanonical.ScriptCount
        CanonicalCharacters = $httpsCanonical.Characters
        CanonicalSha256 = $httpsCanonical.Sha256
    }
}

if ($SelfTest) {
    $sample = "alpha<script></script><script type='text/plain'>x</script><script src='x'></script>beta"
    $canonical = Get-CanonicalBody -Body $sample
    if (
        $canonical.CanonicalText -ne "alphabeta" -or
        $canonical.Characters -ne 9 -or
        $canonical.Sha256 -ne "A4C4AEB92C20500F364B12B3771EF3A11193E2CF04D0F28956A829749993B39F"
    ) {
        throw "canonical body self-test vector failed"
    }
    $cardinalityRejected = $false
    try {
        $null = Get-CanonicalBody -Body "<script></script><script></script>"
    }
    catch {
        $cardinalityRejected = $true
    }
    if (-not $cardinalityRejected) {
        throw "script-cardinality self-test did not fail closed"
    }

    $prechange = @(
        foreach ($protocol in $ProtocolOffers.Keys) {
            [pscustomobject]@{
                Protocol = $protocol
                Outcome = "accepted"
                NegotiatedProtocol = $NegotiatedNames[$protocol]
            }
        }
    )
    Assert-TlsMatrix -SelectedMode "Prechange" -Records $prechange
    $postchange = @(
        foreach ($protocol in $ProtocolOffers.Keys) {
            [pscustomobject]@{
                Protocol = $protocol
                Outcome = Get-ExpectedTlsOutcome -SelectedMode "Postchange" -Protocol $protocol
                NegotiatedProtocol = if ($protocol -in @("tls10", "tls11")) {
                    $null
                }
                else {
                    $NegotiatedNames[$protocol]
                }
            }
        }
    )
    Assert-TlsMatrix -SelectedMode "Postchange" -Records $postchange
    $postchange[0].Outcome = "accepted"
    $postchange[0].NegotiatedProtocol = $NegotiatedNames[$postchange[0].Protocol]
    $badMatrixRejected = $false
    try {
        Assert-TlsMatrix -SelectedMode "Postchange" -Records $postchange
    }
    catch {
        $badMatrixRejected = $true
    }
    if (-not $badMatrixRejected) {
        throw "legacy-acceptance self-test did not fail closed"
    }
    Write-Output "PASS cloudflare-edge-sslstream-probe offline self-test"
    exit 0
}

if ($PSVersionTable.PSVersion.ToString() -ne $ExpectedPowerShell) {
    throw "live probe requires PowerShell $ExpectedPowerShell"
}
$framework = ".NET " + [System.Environment]::Version.ToString()
if ($framework -ne $ExpectedFramework) {
    throw "live probe requires $ExpectedFramework"
}
if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)) {
    throw "live probe requires the frozen Windows SslStream client"
}

$scriptSha256 = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($PSCommandPath))
$runtimeRecord = [pscustomobject][ordered]@{
    Schema = "cloudflare-edge-sslstream-probe/v1"
    Record = "runtime"
    Mode = $Mode
    PowerShell = $PSVersionTable.PSVersion.ToString()
    Framework = $framework
    OS = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    ScriptSha256 = $scriptSha256
}
$runtimeRecord | ConvertTo-Json -Compress

$selectedZones = if ($Zone -eq "all") {
    @($ZoneContracts.Keys)
}
else {
    @($Zone)
}

foreach ($hostName in $selectedZones) {
    $records = @(
        foreach ($protocol in $ProtocolOffers.Keys) {
            Invoke-TlsOffer -HostName $hostName -Protocol $protocol -Offer $ProtocolOffers[$protocol]
        }
    )
    foreach ($record in $records) {
        [pscustomobject][ordered]@{
            Schema = "cloudflare-edge-sslstream-probe/v1"
            Record = "tls"
            Mode = $Mode
            Zone = $hostName
            Protocol = $record.Protocol
            Outcome = $record.Outcome
            NegotiatedProtocol = $record.NegotiatedProtocol
            CertificateSha256 = $record.CertificateSha256
            ErrorType = $record.ErrorType
        } | ConvertTo-Json -Compress
    }
    Assert-TlsMatrix -SelectedMode $Mode -Records $records

    $http = Invoke-HttpAcceptance -HostName $hostName -SelectedMode $Mode
    [pscustomobject][ordered]@{
        Schema = "cloudflare-edge-sslstream-probe/v1"
        Record = "http-body"
        Mode = $Mode
        Zone = $hostName
        HttpRootStatus = $http.HttpRootStatus
        HttpRootLocation = $http.HttpRootLocation
        HttpQueryStatus = $http.HttpQueryStatus
        HttpQueryLocation = $http.HttpQueryLocation
        HttpsRootStatus = $http.HttpsRootStatus
        CanonicalScriptCount = $http.CanonicalScriptCount
        CanonicalCharacters = $http.CanonicalCharacters
        CanonicalSha256 = $http.CanonicalSha256
    } | ConvertTo-Json -Compress
}

[pscustomobject][ordered]@{
    Schema = "cloudflare-edge-sslstream-probe/v1"
    Record = "result"
    Mode = $Mode
    Zones = @($selectedZones)
    Verdict = "pass"
} | ConvertTo-Json -Compress
