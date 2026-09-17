# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Builds the .msix, installs it, and runs a real scan.

.DESCRIPTION
    The Windows counterpart to packaging/deb/verify-in-container.sh and
    packaging/rpm/verify-in-container.sh, and held to the same bar: build in the real target
    environment, assert the package metadata, count the bundled wheels and fail unless there
    is exactly one, install, run the entry point, run a real scan over a fixture with a
    planted secret, parse the SARIF and fail unless the finding count is nonzero, then
    uninstall and fail if the venv survived.

    The scan assertion is the one that matters and the reason the others are not enough. An
    ASH scan that finds nothing exits 0, so "it installed and ran" is indistinguishable from
    "it installed and cannot see the file system" -- which is the exact failure a packaged app
    with the wrong capabilities produces, and the failure this whole package is arranged to
    avoid.

    Where this falls short of its deb and rpm siblings, stated plainly rather than left for a
    reader to discover:

    * The deb and rpm jobs build inside the distro they target, so a missing dependency cannot
      be masked by the build host. There is no equivalent here: a hosted Windows runner is the
      build host and the test host. A dependency that happens to be present on the runner and
      absent on a user's machine would pass. The one dependency that matters is a Python
      interpreter, and the launcher probes for it explicitly and reports its absence as an
      actionable message, which is the best available substitute for a clean container.
    * App execution alias support on Windows Server is not documented. Microsoft lists
      windows.appExecutionAlias among the extensions NOT supported on Windows Server 2019, and
      publishes no equivalent statement for 2022 or 2025; the MSIX feature matrix has no
      Windows Server 2025 column at all, and windows-latest is Windows Server 2025. So whether
      typing `ash` works on this host is measured here and reported, not asserted. When aliases
      are unavailable the scan still runs, through the packaged executable, because the
      question of whether ASH can scan is separate from the question of how it was invoked.

.PARAMETER Wheel
    Path to the wheel. Defaults to the single .whl under dist/, matching how the deb and rpm
    verification scripts find theirs.

.PARAMETER PfxBase64
    Passed straight through to build.ps1. Empty means self-signed.

.PARAMETER PfxPassword
    Passed straight through to build.ps1.
#>
[CmdletBinding()]
param(
    [string] $Wheel,
    [string] $PfxBase64 = '',
    [string] $PfxPassword = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptDirectory)
$packageIdentityName = 'AWSLabs.AutomatedSecurityHelper'

function Write-Step {
    param([string] $Text)
    Write-Host ''
    Write-Host "== $Text"
}

function Fail {
    param([string] $Text)
    Write-Host "   FAIL: $Text"
    # A GitHub Actions annotation as well as the log line, so a failure is visible on the run
    # summary rather than only to whoever opens the log.
    Write-Host "::error::$Text"
    exit 1
}

# Removes the package if a previous run left it installed. Verification that depends on
# starting clean has to make itself clean, or a rerun on the same runner measures the previous
# run's state.
function Remove-AshPackage {
    Get-AppxPackage -Name $packageIdentityName -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue }
}

Write-Step '1. resolve the wheel'
if (-not $Wheel) {
    $candidates = @(Get-ChildItem -Path (Join-Path $repoRoot 'dist') -Filter '*.whl' -File -ErrorAction SilentlyContinue)
    if ($candidates.Count -ne 1) {
        Fail "expected exactly 1 wheel under dist/, found $($candidates.Count). Pass -Wheel to name one."
    }
    $Wheel = $candidates[0].FullName
}
Write-Host "   wheel: $(Split-Path -Leaf $Wheel)"

Write-Step '2. build and sign the package'
Remove-AshPackage
& (Join-Path $scriptDirectory 'build.ps1') `
    -Wheel $Wheel `
    -OutputDirectory (Join-Path $repoRoot 'build/msix') `
    -PfxBase64 $PfxBase64 `
    -PfxPassword $PfxPassword
if ($LASTEXITCODE -ne 0) {
    Fail "build.ps1 exited $LASTEXITCODE"
}

$built = @(Get-ChildItem -Path (Join-Path $repoRoot 'build/msix') -Filter '*.msix' -File)
if ($built.Count -ne 1) {
    Fail "expected exactly 1 .msix in build/msix, found $($built.Count)"
}
$msix = $built[0].FullName
Write-Host "   built: $(Split-Path -Leaf $msix)"

Write-Step '3. package metadata is well formed, read back out of the package'
# An .msix is a zip. Reading the manifest back from the built artifact rather than from the
# staged layout is the point: it proves what makeappx actually packed, the way the rpm script
# asks `rpm -qp` rather than trusting the spec it just wrote.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($msix)
try {
    $entries = @($archive.Entries | ForEach-Object { $_.FullName })

    $manifestEntry = $archive.GetEntry('AppxManifest.xml')
    if (-not $manifestEntry) {
        Fail 'the package contains no AppxManifest.xml'
    }
    $reader = New-Object System.IO.StreamReader($manifestEntry.Open())
    try {
        $manifestXml = [xml] $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }

    $identity = $manifestXml.Package.Identity
    Write-Host "   Name:         $($identity.Name)"
    Write-Host "   Version:      $($identity.Version)"
    Write-Host "   Publisher:    $($identity.Publisher)"
    Write-Host "   Architecture: $($identity.ProcessorArchitecture)"

    # The publishing boundary, asserted against the artifact rather than the directory it was
    # built from. packaging/README.md phrases it as a count deliberately: one wheel means no
    # third-party code shipped, checkable without judging each dependency one at a time.
    $wheelEntries = @($entries | Where-Object { $_ -like '*.whl' })
    Write-Host "   wheels in package: $($wheelEntries.Count)"
    if ($wheelEntries.Count -ne 1) {
        Fail @"
expected exactly 1 bundled wheel, found $($wheelEntries.Count): $($wheelEntries -join ', ').
Bundling dependency wheels would put third-party scanner code in a published artifact. See
packaging/README.md.
"@
    }

    # The other half of the same rule. A venv baked into the package would carry every
    # dependency's code AND would not work, because a venv records the absolute paths and
    # interpreter ABI of the machine that built it.
    $venvEntries = @($entries | Where-Object { $_ -like '*pyvenv.cfg' -or $_ -like '*site-packages/*' })
    if ($venvEntries.Count -ne 0) {
        Fail "the package contains virtualenv contents: $($venvEntries[0]) (and $($venvEntries.Count - 1) more)"
    }

    $launchers = @($entries | Where-Object { $_ -match '^[^/]+\.exe$' } | Sort-Object)
    Write-Host "   launchers: $($launchers -join ', ')"
}
finally {
    $archive.Dispose()
}

Write-Step '4. trust the signing certificate, then install'
# A self-signed package cannot install until the certificate is trusted, and the store is
# Local Computer \ Trusted People specifically. Not Trusted Root: the certificate is not a
# root CA, and putting it there would trust it to vouch for anything. Hosted Windows runners
# run as administrator with UAC disabled, which is what makes writing to a LocalMachine store
# possible here at all.
$signature = Get-AuthenticodeSignature -FilePath $msix
if (-not $signature.SignerCertificate) {
    Fail 'the package is not signed, so there is no certificate to trust'
}
Write-Host "   signer: $($signature.SignerCertificate.Subject)"
Write-Host "   status: $($signature.Status)"

$certificateFile = Join-Path $env:RUNNER_TEMP 'ash-msix-signer.cer'
if (-not $env:RUNNER_TEMP) {
    $certificateFile = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-msix-signer.cer'
}
[System.IO.File]::WriteAllBytes($certificateFile, $signature.SignerCertificate.RawData)
Import-Certificate -FilePath $certificateFile -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
Write-Host '   imported into Cert:\LocalMachine\TrustedPeople'

try {
    Add-AppxPackage -Path $msix -ErrorAction Stop
}
catch {
    Fail @"
Add-AppxPackage failed: $($_.Exception.Message)

If this says the certificate is untrusted (0x800B0109) the import above did not take. If it
says the deployment service is unavailable, this host does not support installing app
packages, which is a documented gap for Windows Server: Microsoft's MSIX feature matrix
covers Windows Server 2019 and 2022 and has no Windows Server 2025 column, and
windows-latest is Windows Server 2025. Read the detail in the event log at Applications and
Services Logs > Microsoft > Windows > AppxDeployment-Server > Operational.
"@
}

$installed = Get-AppxPackage -Name $packageIdentityName
if (-not $installed) {
    Fail 'Add-AppxPackage reported success but the package is not installed'
}
Write-Host "   installed: $($installed.PackageFullName)"
$packageFamilyName = $installed.PackageFamilyName
$venv = Join-Path $env:LOCALAPPDATA "Packages\$packageFamilyName\LocalCache\ash-venv"
Write-Host "   venv will be created at: $venv"

Write-Step '5. are the three names reachable from a shell'
# Measured, not asserted, for the Windows Server reason in the .DESCRIPTION above. All three
# are checked because all three are part of the entry-point contract, and the long name in
# particular is the escape hatch for hosts where a bare `ash` resolves to something else --
# MSYS2 ships the Almquist shell under that name and has already shadowed ASH's entry point.
$windowsApps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
if ($env:PATH -notlike "*$windowsApps*") {
    # The directory aliases land in is normally already on PATH. If it is not, adding it is
    # the difference between measuring alias support and measuring PATH.
    Write-Host "   note: $windowsApps was not on PATH; adding it for this process"
    $env:PATH = "$windowsApps;$env:PATH"
}

$expectedNames = @('ash', 'ashv3', 'automated-security-helper')
$resolved = @{}
foreach ($name in $expectedNames) {
    $aliasPath = Join-Path $windowsApps "$name.exe"
    $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
    if (Test-Path $aliasPath) {
        Write-Host "   $name : alias present at $aliasPath"
        $resolved[$name] = $name
    }
    elseif ($command) {
        Write-Host "   $name : resolves to $($command.Source)"
        $resolved[$name] = $name
    }
    else {
        Write-Host "   $name : NO alias on this host"
    }
}

$aliasesWork = $resolved.Count -eq $expectedNames.Count
if (-not $aliasesWork) {
    $missing = $expectedNames | Where-Object { -not $resolved.ContainsKey($_) }
    $message = @"
app execution aliases are not available for: $($missing -join ', '). windows.appExecutionAlias
is documented as unsupported on Windows Server 2019 and Microsoft publishes no statement for
Server 2022 or 2025, so this is the expected outcome on a Windows Server host rather than a
defect in the manifest. The scan below runs through the packaged executable instead, so the
capability assertions still mean something. Alias reachability on Windows client remains
UNVERIFIED by this run.
"@
    Write-Host "   $message"
    Write-Host "::warning::$message"

    # Fall back to the executable inside the installed package. Reachable because
    # InstallLocation is readable even though it is not writable.
    foreach ($name in $expectedNames) {
        if (-not $resolved.ContainsKey($name)) {
            $direct = Join-Path $installed.InstallLocation "$name.exe"
            if (-not (Test-Path $direct)) {
                Fail "neither an alias nor $direct exists, so $name is unreachable by any route"
            }
            $resolved[$name] = $direct
        }
    }
}

Write-Step '6. the entry point runs, which is also the first-run venv creation'
# First invocation does the bootstrap, so this step is slow on purpose and is where a missing
# Python interpreter or an unreachable package index surfaces.
& $resolved['ash'] --version
if ($LASTEXITCODE -ne 0) {
    Fail "ash --version exited $LASTEXITCODE"
}
if (-not (Test-Path (Join-Path $venv 'Scripts\ash.exe'))) {
    Fail "ash ran but created no venv at $venv, so nothing was bootstrapped where uninstall can reclaim it"
}
Write-Host "   venv created at $venv"

Write-Step '7. the deprecated name warns and the long name does not'
# The entry-point contract, exercised rather than assumed. `ash` is canonical, `ashv3` warns
# once on stderr, and `automated-security-helper` is kept indefinitely and silent. The
# launchers derive which venv console script to run from their own filenames, so this is what
# catches all three collapsing onto the same one.
$errorFile = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-stderr.txt'

& $resolved['ashv3'] --version 2>$errorFile | Out-Null
$ashv3Stderr = if (Test-Path $errorFile) { Get-Content -Raw $errorFile } else { '' }
if ($ashv3Stderr -notmatch '(?i)deprecat') {
    Fail @"
ashv3 --version printed nothing about deprecation on stderr. That warning comes from the
wheel's own run_ashv3 wrapper, so its absence means ashv3.exe is running the `ash` console
script instead of the `ashv3` one, and the three launchers have collapsed onto one target.
stderr was: $ashv3Stderr
"@
}
Write-Host '   ashv3 warned on stderr, as it should'

& $resolved['automated-security-helper'] --version 2>$errorFile | Out-Null
$longNameStderr = if (Test-Path $errorFile) { Get-Content -Raw $errorFile } else { '' }
if ($longNameStderr -match '(?i)deprecat') {
    Fail @"
automated-security-helper --version warned about deprecation. That name is kept indefinitely
and is deliberately silent: it is the escape hatch for hosts where a bare `ash` resolves to
another program, and a warning on it would train users away from the one name that always
works. stderr was: $longNameStderr
"@
}
Write-Host '   automated-security-helper was silent, as it should be'

Write-Step '8. scan a fixture with a KNOWN finding'
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-msix-fixture'
if (Test-Path $fixture) {
    Remove-Item -Recurse -Force $fixture
}
New-Item -ItemType Directory -Force -Path $fixture | Out-Null

# The planted key is assembled from two halves rather than written as one literal, and that is
# not obfuscation. ASH scans its own repository, and .ash/.ash.yaml suppresses SECRET-* under
# tests/ and scripts/ but not under packaging/, so a complete key sitting in this file would
# be a finding in ASH's own scan of itself. Splitting it keeps this file clean while the file
# it WRITES carries the whole thing, which is the only copy the scan under test needs to see.
$plantedKey = 'wJalrXUtnFEMI/K7MDENG/' + 'bPxRfiCYEXAMPLEKEY'
@"
# Fixture for packaging verification. Not a real credential.
AWS_SECRET_ACCESS_KEY = "$plantedKey"
"@ | Set-Content -Path (Join-Path $fixture 'leak.py') -Encoding utf8

# detect-secrets is a runtime dependency of ASH and drives in process, so it is the one default
# scanner present after installing ASH alone. The rest are correctly reported SKIPPED rather
# than MISSING.
#
# --source-dir is passed explicitly rather than relying on the working directory. The default
# source IS the working directory, which is the behavior broadFileSystemAccess exists for, but
# a test that depended on it would be testing Push-Location as much as the package.
$outputDirectory = Join-Path $fixture '.ash\ash_output'
& $resolved['ash'] scan --source-dir $fixture --output-dir $outputDirectory `
    --scanners detect-secrets --no-progress
$scanExit = $LASTEXITCODE
Write-Host "   ash scan exit code: $scanExit"

Write-Step '9. assert a finding was actually reported'
# The load-bearing assertion. An empty ASH scan exits 0, so asserting the exit code alone would
# pass a package that installed, ran, and could not read a single file.
$sarif = Join-Path $outputDirectory 'reports\ash.sarif'
if (-not (Test-Path $sarif)) {
    $found = @(Get-ChildItem -Path $outputDirectory -Filter '*.sarif' -Recurse -File -ErrorAction SilentlyContinue)
    if ($found.Count -eq 0) {
        Fail "no SARIF produced under $outputDirectory, so nothing can be asserted about findings"
    }
    $sarif = $found[0].FullName
}
$report = Get-Content -Raw $sarif | ConvertFrom-Json
$results = @($report.runs | ForEach-Object { $_.results } | Where-Object { $_ })
Write-Host "   SARIF: $(Split-Path -Leaf $sarif), $($results.Count) result(s)"
if ($results.Count -eq 0) {
    Fail @"
the scan produced 0 findings on a fixture planted with a secret. A packaged ASH that installs
and cannot read the tree it was pointed at exits 0 and looks identical to a clean scan, which
is why this is asserted rather than inferred from the exit code.
"@
}
foreach ($result in $results | Select-Object -First 3) {
    $uri = $result.locations[0].physicalLocation.artifactLocation.uri
    Write-Host "     - $($result.ruleId) at $uri"
}
Write-Host '   OK: the installed package ran a scan and reported findings'

Write-Step '10. a reinstall must not lose the venv'
# The MSIX equivalent of the rpm script's %postun check. There is no scriptlet ordering to get
# wrong here, but the launcher decides whether to bootstrap by looking for one file, so a
# reinstall that left a partial venv behind would be found and used.
Add-AppxPackage -Path $msix -ForceUpdateFromAnyVersion -ErrorAction Stop
if (-not (Test-Path (Join-Path $venv 'Scripts\ash.exe'))) {
    Fail 'the venv did not survive a reinstall'
}
& $resolved['ash'] --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail "ash --version exited $LASTEXITCODE after a reinstall"
}
Write-Host '   OK: venv survived, ash still runs'

Write-Step '11. uninstall reclaims the venv'
Remove-AshPackage
if (Get-AppxPackage -Name $packageIdentityName -ErrorAction SilentlyContinue) {
    Fail 'the package is still installed after Remove-AppxPackage'
}
if (Test-Path $venv) {
    Fail @"
$venv survived uninstall. The venv lives under the package's own per-user state directory
precisely so that Windows reclaims it, because MSIX has no uninstall hook that could delete
it. If it is still there, the launcher is creating it somewhere else and every uninstall
leaves several hundred megabytes behind.
"@
}
Write-Host '   OK: venv removed with the package'

Write-Host ''
Write-Host 'MSIX VERIFICATION PASSED'
if (-not $aliasesWork) {
    Write-Host 'with one caveat: app execution aliases were not available on this host, so the'
    Write-Host 'three names were exercised through the packaged executables instead. See step 5.'
}
