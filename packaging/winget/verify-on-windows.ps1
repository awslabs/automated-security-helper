# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Installs ASH through the real winget client from the manifests in this directory, scans
    with it, upgrades it, and uninstalls it.

.DESCRIPTION
    The end-to-end leg for the winget channel. validate-manifests.py checks the manifests
    against Microsoft's schemas without a client; this script runs the client.

      1. Get a winget client. The hosted Windows images do not list one, so the script uses
         one already registered for this user if there is one, then tries to register the
         App Installer the OS may carry, then installs a pinned winget-cli release whose two
         files are checked against SHA-256 digests recorded below. Which of the three
         produced the client is printed. If none does, the script fails: that is the
         measurement the operator decision about hosted runners rests on. A client older
         than $MinimumWingetVersion (set below) does not count: it checks the 1.12.0
         manifests this directory holds against an older schema.
      2. Render two manifest sets from the .msix the msix job built, with
         set-release-metadata.py: the release set (the real release asset URL and the
         artifact's digest) for `winget validate`, and a loopback set (the same digest, the
         same .msix served from 127.0.0.1, and the package's PackageFamilyName) for
         `winget install`. No release asset exists for an unreleased commit, so installing
         needs the loopback copy. `winget uninstall --manifest` and `winget upgrade
         --manifest` find the installed MSIX by that PackageFamilyName, so after each
         install the value in the set must equal what Get-AppxPackage reports.
      3. `winget validate --manifest` on the release set.
      4. Negative control: the loopback set with a wrong InstallerSha256 must be refused
         with winget's installer-hash-mismatch code, and nothing may be installed.
      5. Fresh install of N through `winget install --manifest`, then the three shared
         cases from tests/e2e/fixtures/cases.json through scripts/e2e/run_case.py:
         findings (exit 2), clean (exit 0), incomplete (exit 1), each judged by
         scripts/e2e/assert_outcome.py. Then a findings scan with --no-fail-on-findings,
         which run_case.py must reject, so this leg is seen able to fail.
      6. `winget uninstall --manifest`, and the package and its venv must be gone.
      7. Upgrade: an N-1 .msix built here from an exported copy of this tree with every
         [tool.commitizen] version_files entry lowered (scripts/e2e/lower_version.py),
         installed through winget, scanned, then `winget upgrade --manifest` to N. N must
         be the only installed version afterwards and must scan.
      8. `winget uninstall --manifest` again, and nothing may remain.

    The N-1 tree differs from N in its version only. winget decides an upgrade from the
    versions it compares, so that is what this leg exercises; the wheel leg in
    .github/workflows/ash-e2e.yml is the one whose upgrade crosses a code change.

    The entry point is reached through its app execution alias when the host provides one,
    and through the packaged executable otherwise, for the reason
    packaging/msix/verify-on-windows.ps1 gives: alias support on Windows Server is
    undocumented, and whether ASH scans is a separate question from how it was invoked.

.PARAMETER Msix
    The .msix the msix job built and uploaded. Defaults to the single .msix under
    build/msix-artifact.

.PARAMETER WorkDirectory
    Scratch space. Defaults to $env:RUNNER_TEMP\ash-winget-e2e.

.PARAMETER PfxBase64
    Passed to packaging/msix/build.ps1 for the N-1 build, so that N-1 and N are signed
    with the same certificate subject when a real certificate is configured. Windows
    treats packages whose Publisher differs as different packages, and an upgrade between
    them would not be an upgrade.

.PARAMETER PfxPassword
    Passed to packaging/msix/build.ps1 with PfxBase64.
#>
[CmdletBinding()]
param(
    [string] $Msix,
    [string] $WorkDirectory,
    [string] $PfxBase64 = '',
    [string] $PfxPassword = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Every native exit code below is read on purpose: `ashx scan` exits 2 on findings and a
# negative control expects winget to fail. See packaging/chocolatey/verify-on-windows.ps1
# for why this is off.
$PSNativeCommandUseErrorActionPreference = $false

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptDirectory)

# The winget client this leg installs when the host has none. One stable release, and the
# digests of the two files it needs, as published in that release's
# Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.txt and recomputed from the downloads.
# Raising the version means replacing all three values together. The digests are public by
# construction; each carries detect-secrets' inline marker because any 64-character hex
# string reads to it as a high-entropy secret.
$WingetReleaseTag = 'v1.29.380'
$WingetBundleSha256 = '65DEA9C01CE08EE7B763366B27C0E651F97DB857C11CA9B9C301826C10092F2E'  # pragma: allowlist secret
$WingetDependenciesSha256 = 'BA875AFE9D190F61218985AC0292A99D1DB710BF93E13C68944CA9D89F0D82D1'  # pragma: allowlist secret
$WingetReleaseBase = "https://github.com/microsoft/winget-cli/releases/download/$WingetReleaseTag"
$AppInstallerFamily = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe'

# The oldest client that knows the 1.12 manifest schemas. winget-cli added them in
# v1.12.210-preview (s_ManifestVersionV1_12 in
# src/AppInstallerCommonCore/Manifest/ManifestSchemaValidation.cpp; v1.12.170-preview
# does not have it). An older client does not refuse a 1.12.0 manifest: it reads it
# against the newest schema it has, so a failure would name some field rather than the
# client. The check below names the client instead.
$MinimumWingetVersion = '1.12.210'

# APPINSTALLER_CLI_ERROR_INSTALLER_HASH_MISMATCH, 0x8A150011, as the signed 32-bit exit code
# winget returns.
$HashMismatchExitCode = -1978335215

$PackageIdentifier = 'Amazon.AutomatedSecurityHelper'
$PackageIdentityName = 'AWSLabs.AutomatedSecurityHelper'
$CliName = (Get-Content -Raw (Join-Path $repoRoot 'scripts/e2e/cli_name.json') | ConvertFrom-Json).cli_name

function Write-Step {
    param([string] $Text)
    Write-Host ''
    Write-Host "== $Text"
}

function Fail {
    param([string] $Text)
    Write-Host "   FAIL: $Text"
    Write-Host "::error::$Text"
    Show-WingetLog
    exit 1
}

function Show-WingetLog {
    $logs = Join-Path $env:LOCALAPPDATA "Packages\$AppInstallerFamily\LocalState\DiagOutputDir"
    if (-not (Test-Path $logs)) {
        return
    }
    $latest = Get-ChildItem -Path $logs -Filter '*.log' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Write-Host "--- last 40 lines of $($latest.FullName)"
        Get-Content -LiteralPath $latest.FullName -Tail 40 | ForEach-Object { Write-Host "    $_" }
    }
}

function Assert-Sha256 {
    param([string] $Path, [string] $Expected)
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $Expected) {
        Fail "$(Split-Path -Leaf $Path) has SHA-256 $actual, expected the pinned $Expected"
    }
    Write-Host "   $(Split-Path -Leaf $Path): SHA-256 matches the pin"
}

function Test-Winget {
    $command = Get-Command winget -CommandType Application -ErrorAction SilentlyContinue
    if (-not $command) {
        return $null
    }
    $version = (& $command.Source --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   winget at $($command.Source) exited $LASTEXITCODE for --version: $version"
        return $null
    }
    return @{ Path = $command.Source; Version = $version }
}

function ConvertTo-WingetVersion {
    param([string] $Text)
    # `winget --version` prints v1.29.380, or v1.30.140-preview for a preview build.
    if ($Text -match '^v?(\d+)\.(\d+)\.(\d+)') {
        return [version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
    }
    return $null
}

function Test-WingetVersion {
    param($Client)
    $parsed = ConvertTo-WingetVersion -Text $Client.Version
    if ($parsed -and $parsed -ge [version]$MinimumWingetVersion) {
        return $true
    }
    Write-Host "   winget $($Client.Version) at $($Client.Path) is older than $MinimumWingetVersion, or its version did not parse"
    return $false
}

function Assert-WingetVersion {
    param($Client)
    if (-not (Test-WingetVersion -Client $Client)) {
        Fail @"
winget $($Client.Version) at $($Client.Path) is older than $MinimumWingetVersion, the first
release that knows the 1.12 manifest schemas the manifests here declare (ManifestVersion
1.12.0). It would read them against an older schema. Update the App Installer, or raise
the pinned winget-cli release, which this script installs only when no usable client is
registered.
"@
    }
}

# winget, like the MSIX's own aliases, lives under WindowsApps, which a service account's
# PATH may not include.
$windowsApps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
if ($env:PATH -notlike "*$windowsApps*") {
    $env:PATH = "$windowsApps;$env:PATH"
}

function Get-WingetClient {
    param([string] $Downloads)

    $client = Test-Winget
    if ($client -and (Test-WingetVersion -Client $client)) {
        Write-Host "   source: already registered for this user ($($client.Version))"
        return $client
    }

    Write-Host '   no usable winget for this user; trying to register the App Installer the OS carries'
    try {
        Add-AppxPackage -RegisterByFamilyName -MainPackage $AppInstallerFamily -ErrorAction Stop
    }
    catch {
        Write-Host "   registration failed: $($_.Exception.Message)"
    }
    $client = Test-Winget
    if ($client -and (Test-WingetVersion -Client $client)) {
        Write-Host "   source: the OS App Installer, registered by family name ($($client.Version))"
        return $client
    }

    Write-Host "   installing winget-cli $WingetReleaseTag from its release, digest-pinned"
    New-Item -ItemType Directory -Force -Path $Downloads | Out-Null
    $bundle = Join-Path $Downloads "$AppInstallerFamily.msixbundle"
    $dependencies = Join-Path $Downloads 'DesktopAppInstaller_Dependencies.zip'
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "$WingetReleaseBase/$AppInstallerFamily.msixbundle" -OutFile $bundle
    Invoke-WebRequest -Uri "$WingetReleaseBase/DesktopAppInstaller_Dependencies.zip" -OutFile $dependencies
    Assert-Sha256 -Path $bundle -Expected $WingetBundleSha256
    Assert-Sha256 -Path $dependencies -Expected $WingetDependenciesSha256

    $expanded = Join-Path $Downloads 'dependencies'
    Expand-Archive -LiteralPath $dependencies -DestinationPath $expanded -Force
    $architecture = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
    $appx = @(Get-ChildItem -Path (Join-Path $expanded $architecture) -Filter '*.appx' -File)
    if ($appx.Count -eq 0) {
        Fail "the pinned dependencies archive has no $architecture packages"
    }
    try {
        foreach ($package in $appx) {
            Write-Host "   dependency: $($package.Name)"
            Add-AppxPackage -Path $package.FullName -ErrorAction Stop
        }
        Add-AppxPackage -Path $bundle -ErrorAction Stop
    }
    catch {
        Fail @"
installing the pinned winget client failed: $($_.Exception.Message)
This host cannot run the Windows Package Manager client, so the winget channel cannot be
exercised end to end here. The schema job still validates the manifests.
"@
    }
    $client = Test-Winget
    if (-not $client) {
        $installed = Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue
        Fail @"
the App Installer package installed ($(if ($installed) { $installed.PackageFullName } else { 'not listed by Get-AppxPackage' }))
but no winget command became reachable, under $windowsApps or anywhere on PATH. The alias is
how winget is invoked; without it the client is present and unusable.
"@
    }
    Write-Host "   source: winget-cli $WingetReleaseTag release ($($client.Version))"
    return $client
}

function Invoke-Winget {
    param([string[]] $Arguments, [string] $LogName)
    $log = Join-Path $script:work "$LogName.log"
    Write-Host "   winget $($Arguments -join ' ')"
    & $script:winget @Arguments *> $log
    $code = $LASTEXITCODE
    $body = if (Test-Path $log) { Get-Content -Raw -LiteralPath $log } else { '' }
    Write-Host "   exit $code ($('0x{0:X8}' -f $code))"
    if ($body) {
        ($body.TrimEnd() -split "`n") | Select-Object -Last 25 | ForEach-Object { Write-Host "     $_" }
    }
    return @{ Code = $code; Output = $body }
}

function Get-AshPackage {
    # PowerShell unrolls an array a function returns: zero packages reach the caller as
    # $null and one as a bare object, and under StrictMode Latest .Count on either throws.
    # Callers wrap the call in @() to get an array back.
    return @(Get-AppxPackage -Name $PackageIdentityName -ErrorAction SilentlyContinue)
}

function Assert-Installed {
    param([string] $Version)
    $packages = @(Get-AshPackage)
    if ($packages.Count -ne 1) {
        Fail "expected exactly 1 installed $PackageIdentityName, found $($packages.Count): $(($packages | ForEach-Object { $_.PackageFullName }) -join ', ')"
    }
    if ($packages[0].Version -ne "$Version.0") {
        Fail "$PackageIdentityName is installed at $($packages[0].Version), expected $Version.0"
    }
    Write-Host "   installed: $($packages[0].PackageFullName)"
    return $packages[0]
}

function Assert-FamilyName {
    param($Package, [string] $Manifests)
    # The loopback set's PackageFamilyName is computed by set-release-metadata.py from
    # the AppxManifest. A wrong value still matches the schema pattern, and winget would
    # then fail to find the package on uninstall or upgrade, so compare it with the one
    # Windows assigned to the package just installed from that set.
    $installer = Join-Path $Manifests "$PackageIdentifier.installer.yaml"
    $match = [regex]::Match((Get-Content -Raw -LiteralPath $installer), '(?m)^  PackageFamilyName: (\S+)\s*$')
    if (-not $match.Success) {
        Fail "$installer has no PackageFamilyName, so winget uninstall and upgrade --manifest cannot find the package"
    }
    $declared = $match.Groups[1].Value
    if ($declared -cne $Package.PackageFamilyName) {
        Fail "$installer declares PackageFamilyName $declared, and Get-AppxPackage reports $($Package.PackageFamilyName)"
    }
    Write-Host "   PackageFamilyName $declared matches Get-AppxPackage"
    return $declared
}

function Assert-NothingInstalled {
    param([string] $After)
    $packages = @(Get-AshPackage)
    if ($packages.Count -ne 0) {
        Fail "after $After, $PackageIdentityName is still installed: $(($packages | ForEach-Object { $_.PackageFullName }) -join ', ')"
    }
    Write-Host "   no $PackageIdentityName installed"
}

function Resolve-Cli {
    param($Package)
    $alias = Join-Path $windowsApps "$CliName.exe"
    if (Test-Path $alias) {
        Write-Host "   $CliName : app execution alias at $alias"
        return $alias
    }
    $direct = Join-Path $Package.InstallLocation "$CliName.exe"
    if (-not (Test-Path $direct)) {
        Fail "neither an alias at $alias nor $direct exists, so $CliName is unreachable"
    }
    Write-Host "   $CliName : no alias on this host; using the packaged executable $direct"
    return $direct
}

function Assert-CliVersion {
    param([string] $Cli, [string] $Version)
    $output = (& $Cli --version 2>&1 | Out-String).Trim()
    $code = $LASTEXITCODE
    Write-Host "   $CliName --version: $output (exit $code)"
    if ($code -ne 0) {
        Fail "$CliName --version exited $code"
    }
    if ($output -notmatch [regex]::Escape($Version)) {
        Fail "$CliName --version does not report $Version"
    }
}

function Invoke-Case {
    param([string] $Cli, [string] $Case, [string] $Label, [string[]] $Extra = @())
    $arguments = @(
        (Join-Path $repoRoot 'scripts/e2e/run_case.py'),
        '--cli', $Cli, '--case', $Case, '--work', (Join-Path $script:work 'scans'), '--label', $Label
    )
    if ($Extra.Count -gt 0) {
        $arguments += '--'
        $arguments += $Extra
    }
    # Out-Host, so run_case.py's output is shown rather than returned alongside the
    # exit code: a function returns everything its native commands write to stdout.
    & python @arguments | Out-Host
    return $LASTEXITCODE
}

function Assert-Case {
    param([string] $Cli, [string] $Case, [string] $Label)
    $code = Invoke-Case -Cli $Cli -Case $Case -Label $Label
    if ($code -ne 0) {
        Fail "the $Case case ($Label) did not match tests/e2e/fixtures/cases.json; run_case.py exited $code"
    }
}

function Add-SignerTrust {
    param([string] $Package)
    $signature = Get-AuthenticodeSignature -FilePath $Package
    if (-not $signature.SignerCertificate) {
        Fail "$(Split-Path -Leaf $Package) is not signed"
    }
    $certificate = Join-Path $script:work ("signer-" + $signature.SignerCertificate.Thumbprint + '.cer')
    [System.IO.File]::WriteAllBytes($certificate, $signature.SignerCertificate.RawData)
    Import-Certificate -FilePath $certificate -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
    Write-Host "   trusted $($signature.SignerCertificate.Subject) ($($signature.SignerCertificate.Thumbprint))"
}

function Build-ManifestSet {
    param([string] $Tree, [string] $Package, [string] $OutDirectory, [string] $UrlBase)
    $arguments = @(
        'run', (Join-Path $Tree 'packaging/winget/set-release-metadata.py'),
        '--msix', $Package, '--out-dir', $OutDirectory
    )
    if ($UrlBase) {
        $arguments += @('--local-url-base', $UrlBase)
    }
    & uv @arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "set-release-metadata.py exited $LASTEXITCODE rendering $OutDirectory"
    }
}

# ---------------------------------------------------------------------------------------

if (-not $WorkDirectory) {
    $base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
    $WorkDirectory = Join-Path $base 'ash-winget-e2e'
}
if (Test-Path $WorkDirectory) {
    Remove-Item -Recurse -Force -LiteralPath $WorkDirectory
}
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$script:work = (Resolve-Path -LiteralPath $WorkDirectory).Path

Write-Step '1. a winget client'
$client = Get-WingetClient -Downloads (Join-Path $script:work 'winget-client')
Assert-WingetVersion -Client $client
$script:winget = $client.Path
Write-Host "   winget: $($client.Path), $($client.Version)"

# Installing from a manifest file is off by default and needs administrator rights, which
# the hosted runner account has.
$result = Invoke-Winget -Arguments @('settings', '--enable', 'LocalManifestFiles') -LogName 'settings'
if ($result.Code -ne 0) {
    Fail "winget settings --enable LocalManifestFiles exited $($result.Code)"
}

Write-Step '2. the N package and its manifest sets'
if (-not $Msix) {
    $candidates = @(Get-ChildItem -Path (Join-Path $repoRoot 'build/msix-artifact') -Filter '*.msix' -File -ErrorAction SilentlyContinue)
    if ($candidates.Count -ne 1) {
        Fail "expected exactly 1 .msix under build/msix-artifact, found $($candidates.Count). Pass -Msix."
    }
    $Msix = $candidates[0].FullName
}
$version = (& python -c "import tomllib,sys; print(tomllib.load(open(sys.argv[1],'rb'))['project']['version'])" (Join-Path $repoRoot 'pyproject.toml') | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $version) {
    Fail 'could not read [project] version from pyproject.toml'
}
Write-Host "   N = $version, $(Split-Path -Leaf $Msix)"

$served = Join-Path $script:work 'served'
New-Item -ItemType Directory -Force -Path $served | Out-Null
Copy-Item -LiteralPath $Msix -Destination $served
$msixN = Join-Path $served (Split-Path -Leaf $Msix)

# A free loopback port, taken from the OS rather than hardcoded.
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$urlBase = "http://127.0.0.1:$port"

$releaseN = Join-Path $script:work 'manifests-release-N'
$localN = Join-Path $script:work 'manifests-local-N'
Build-ManifestSet -Tree $repoRoot -Package $msixN -OutDirectory $releaseN
Build-ManifestSet -Tree $repoRoot -Package $msixN -OutDirectory $localN -UrlBase $urlBase

Write-Step '3. winget validate, on the release set'
$result = Invoke-Winget -Arguments @('validate', '--manifest', $releaseN, '--disable-interactivity') -LogName 'validate'
if ($result.Code -ne 0) {
    Fail "winget validate exited $($result.Code) on the release manifest set"
}

$server = $null
try {
    Write-Step "4. serve the packages on $urlBase"
    $server = Start-Process -FilePath python -PassThru -NoNewWindow `
        -ArgumentList @('-m', 'http.server', "$port", '--bind', '127.0.0.1', '--directory', $served) `
        -RedirectStandardOutput (Join-Path $script:work 'http.out') `
        -RedirectStandardError (Join-Path $script:work 'http.err')
    $ready = $false
    foreach ($attempt in 1..30) {
        try {
            $probe = Invoke-WebRequest -Uri "$urlBase/$(Split-Path -Leaf $msixN)" -Method Head -UseBasicParsing
            if ($probe.StatusCode -eq 200) {
                $ready = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $ready) {
        Fail "the loopback server on $urlBase never served $(Split-Path -Leaf $msixN)"
    }
    Write-Host '   serving'

    Add-SignerTrust -Package $msixN
    Assert-NothingInstalled -After 'a fresh start'

    Write-Step '5. NEGATIVE CONTROL: a manifest whose InstallerSha256 is wrong must not install'
    $badN = Join-Path $script:work 'manifests-local-N-bad-hash'
    Copy-Item -Recurse -LiteralPath $localN -Destination $badN
    $badInstaller = Join-Path $badN "$PackageIdentifier.installer.yaml"
    $wrongDigest = 'A' * 64
    $text = Get-Content -Raw -LiteralPath $badInstaller
    $rewritten = [regex]::Replace($text, '(?m)^(  InstallerSha256: ).*$', "`${1}$wrongDigest")
    if ($rewritten -eq $text) {
        Fail 'the negative control did not change InstallerSha256, so it would test nothing'
    }
    Set-Content -LiteralPath $badInstaller -Value $rewritten -NoNewline -Encoding utf8
    $result = Invoke-Winget -Arguments @(
        'install', '--manifest', $badN, '--accept-package-agreements', '--accept-source-agreements',
        '--disable-interactivity', '--silent'
    ) -LogName 'negative-install'
    if ($result.Code -ne $HashMismatchExitCode) {
        Fail "winget install with a wrong InstallerSha256 exited $($result.Code); expected the installer-hash-mismatch code $HashMismatchExitCode (0x8A150011)"
    }
    Assert-NothingInstalled -After 'the refused install'
    Write-Host '   OK: refused for the hash, and nothing was installed'

    Write-Step "6. fresh install of $version through winget, and the three cases"
    $result = Invoke-Winget -Arguments @(
        'install', '--manifest', $localN, '--accept-package-agreements', '--accept-source-agreements',
        '--disable-interactivity', '--silent'
    ) -LogName 'install-N'
    if ($result.Code -ne 0) {
        Fail "winget install --manifest exited $($result.Code)"
    }
    $package = Assert-Installed -Version $version
    $familyN = Assert-FamilyName -Package $package -Manifests $localN
    $venv = Join-Path $env:LOCALAPPDATA "Packages\$($package.PackageFamilyName)\LocalCache\ash-venv"
    $cli = Resolve-Cli -Package $package
    Assert-CliVersion -Cli $cli -Version $version
    Assert-Case -Cli $cli -Case 'findings' -Label 'fresh-findings'
    Assert-Case -Cli $cli -Case 'clean' -Label 'fresh-clean'
    Assert-Case -Cli $cli -Case 'incomplete' -Label 'fresh-incomplete'

    Write-Step '7. NEGATIVE CONTROL: a findings scan that exits 0 must be rejected'
    $code = Invoke-Case -Cli $cli -Case 'findings' -Label 'negative-no-fail-on-findings' -Extra @('--no-fail-on-findings')
    if ($code -ne 1) {
        Fail "run_case.py returned $code for a findings scan run with --no-fail-on-findings; expected 1"
    }
    Write-Host '   OK: the leg rejects a wrong exit code'

    Write-Step '8. winget uninstall'
    $result = Invoke-Winget -Arguments @('uninstall', '--manifest', $localN, '--disable-interactivity', '--silent') -LogName 'uninstall-N'
    if ($result.Code -ne 0) {
        Fail "winget uninstall --manifest exited $($result.Code)"
    }
    Assert-NothingInstalled -After 'winget uninstall'
    if (Test-Path $venv) {
        Fail "the package is gone but its venv survived at $venv"
    }
    Write-Host "   venv removed with the package"

    Write-Step '9. build N-1 from an exported copy of this tree'
    $tree = Join-Path $script:work 'tree-previous'
    $archive = Join-Path $script:work 'tree.zip'
    & git -C $repoRoot archive --format=zip -o $archive HEAD
    if ($LASTEXITCODE -ne 0) {
        Fail "git archive exited $LASTEXITCODE"
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $tree
    $previous = (& python (Join-Path $repoRoot 'scripts/e2e/lower_version.py') --tree $tree | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $previous) {
        Fail "lower_version.py exited $LASTEXITCODE"
    }
    Write-Host "   N-1 = $previous"
    & uv build --wheel --out-dir (Join-Path $tree 'dist') $tree
    if ($LASTEXITCODE -ne 0) {
        Fail "uv build of the N-1 tree exited $LASTEXITCODE"
    }
    $previousWheel = Join-Path $tree "dist/automated_security_helper-$previous-py3-none-any.whl"
    if (-not (Test-Path $previousWheel)) {
        Fail "the N-1 build did not produce $previousWheel"
    }
    & (Join-Path $tree 'packaging/msix/build.ps1') -Wheel $previousWheel `
        -OutputDirectory (Join-Path $tree 'build/msix') -PfxBase64 $PfxBase64 -PfxPassword $PfxPassword
    if ($LASTEXITCODE -ne 0) {
        Fail "build.ps1 for N-1 exited $LASTEXITCODE"
    }
    $previousMsix = Join-Path $tree "build/msix/automated-security-helper-$previous.msix"
    if (-not (Test-Path $previousMsix)) {
        Fail "the N-1 build did not produce $previousMsix"
    }
    Copy-Item -LiteralPath $previousMsix -Destination $served
    $msixPrevious = Join-Path $served (Split-Path -Leaf $previousMsix)
    Add-SignerTrust -Package $msixPrevious
    $localPrevious = Join-Path $script:work 'manifests-local-N-1'
    Build-ManifestSet -Tree $tree -Package $msixPrevious -OutDirectory $localPrevious -UrlBase $urlBase

    Write-Step "10. install $previous through winget, then upgrade to $version"
    $result = Invoke-Winget -Arguments @(
        'install', '--manifest', $localPrevious, '--accept-package-agreements', '--accept-source-agreements',
        '--disable-interactivity', '--silent'
    ) -LogName 'install-N-1'
    if ($result.Code -ne 0) {
        Fail "winget install --manifest (N-1) exited $($result.Code)"
    }
    $package = Assert-Installed -Version $previous
    $familyPrevious = Assert-FamilyName -Package $package -Manifests $localPrevious
    # The upgrade below finds N-1 through the family name in the N set, so the two sets
    # must name the same family: the same Identity Name and the same signing subject.
    if ($familyPrevious -cne $familyN) {
        Fail "the N-1 set names family $familyPrevious and the N set names $familyN; winget upgrade --manifest would not find N-1"
    }
    $cli = Resolve-Cli -Package $package
    Assert-CliVersion -Cli $cli -Version $previous
    Assert-Case -Cli $cli -Case 'findings' -Label 'upgrade-before'

    $result = Invoke-Winget -Arguments @(
        'upgrade', '--manifest', $localN, '--accept-package-agreements', '--accept-source-agreements',
        '--disable-interactivity', '--silent'
    ) -LogName 'upgrade'
    if ($result.Code -ne 0) {
        Fail "winget upgrade --manifest exited $($result.Code)"
    }
    $package = Assert-Installed -Version $version
    $cli = Resolve-Cli -Package $package
    Assert-CliVersion -Cli $cli -Version $version
    Assert-Case -Cli $cli -Case 'findings' -Label 'upgrade-after'

    Write-Step '11. winget uninstall after the upgrade'
    $venv = Join-Path $env:LOCALAPPDATA "Packages\$($package.PackageFamilyName)\LocalCache\ash-venv"
    $result = Invoke-Winget -Arguments @('uninstall', '--manifest', $localN, '--disable-interactivity', '--silent') -LogName 'uninstall-upgraded'
    if ($result.Code -ne 0) {
        Fail "winget uninstall --manifest after the upgrade exited $($result.Code)"
    }
    Assert-NothingInstalled -After 'the second winget uninstall'
    if (Test-Path $venv) {
        Fail "the package is gone but its venv survived at $venv"
    }
}
finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
    }
}

Write-Host ''
Write-Host "WINGET END-TO-END PASSED: validate, hash-mismatch refusal, install $version, findings/clean/incomplete, uninstall, $previous -> $version upgrade, uninstall"
