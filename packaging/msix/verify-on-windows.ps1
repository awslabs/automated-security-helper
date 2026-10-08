# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Builds the .msix, installs it, upgrades it, runs the three e2e scans, and uninstalls it.

.DESCRIPTION
    The Windows counterpart to packaging/deb/verify-in-container.sh and
    packaging/rpm/verify-in-container.sh, and the MSIX leg of the v4 end-to-end contract
    (tests/e2e/README.md). In order:

      1. build and sign N, the package for this checkout's wheel, and gate its contents;
      2. build and sign N-1 in a scratch directory: this checkout's tree, exported with
         `git archive`, with its version lowered (3.7.0 -> 3.6.0), the same derivation
         packaging/build-test-wheels.sh uses for the deb and rpm upgrade legs;
      3. negative controls: the package-contents gate must refuse a copy of N with a scanner
         binary planted in it (packaging/assert-planted-scanner-rejected.py), and a copy of
         N with one payload byte changed must be refused by Add-AppxPackage;
      4. install N-1 fresh, bootstrap its venv, and check it reports N-1's version;
      5. upgrade to N with Add-AppxPackage, and require the installed version to move, the
         venv to be REBUILT from N's wheel, and `ashx --version` to report N;
      6. the three entry-point names behave as the contract says;
      7. the three cases from tests/e2e/fixtures/cases.json through scripts/e2e/run_case.py,
         judged by scripts/e2e/assert_outcome.py: findings (exit 2, 3 findings), clean
         (exit 0) and incomplete (exit 1, opengrep MISSING), with exact report paths;
      8. negative controls on the verdict: a findings scan run with --no-fail-on-findings must
         be rejected for its exit code, and the clean output judged as a findings outcome
         must be rejected;
      8c. `ashx dependencies install --tool grype` through the installed package, checked
         against the pin, and `--tool <unknown>` refused with EXIT_BAD_SELECTION;
      9. a same-version reinstall must keep the venv rather than rebuild it;
     10. uninstall, then require the package, its venv and its three aliases to be gone.

    Nothing built here except N is kept where the workflow uploads from. N-1 is this tree's
    code labeled with a version it is not, and the tampered package is broken on purpose, so
    both live under -WorkDirectory and never under build/msix.

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
      typing `ashx` works on this host is measured here and reported, not asserted. When aliases
      are unavailable the scans still run, through the packaged executable, because the
      question of whether ASH can scan is separate from the question of how it was invoked.
      On windows-latest the aliases have been present on every run so far.
    * N-1 is this tree with a lower version, not an earlier release. That is enough to prove
      what an MSIX update has to get right, which is that Windows replaces the payload and the
      launcher rebuilds a venv that Windows deliberately keeps (LocalCache survives updates),
      and the version ASH reports can only move if both happened.

.PARAMETER Wheel
    Path to the wheel. Defaults to the single .whl under dist/, matching how the deb and rpm
    verification scripts find theirs.

.PARAMETER PfxBase64
    Passed straight through to build.ps1, for N and for N-1. Empty means self-signed. N-1 is
    signed with the same certificate so the two packages share a Publisher, and so a package
    family; with different publishers the second install would be a second app rather than an
    upgrade.

.PARAMETER PfxPassword
    Passed straight through to build.ps1.

.PARAMETER WorkDirectory
    Scratch space for N-1, the tampered package and the scans. Defaults to
    $env:RUNNER_TEMP\ash-msix-e2e, or the system temp directory outside Actions. Emptied first.

.PARAMETER SelfTest
    Runs only the checks of this script's own pure helpers and exits. They also run at the
    start of every real verification, so a helper that broke fails the job before it can
    judge anything.
#>
[CmdletBinding()]
param(
    [string] $Wheel,
    [string] $PfxBase64 = '',
    [string] $PfxPassword = '',
    [string] $WorkDirectory,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Several native commands below are EXPECTED to exit nonzero (the negative controls), and each
# exit code is read and judged explicitly, so a nonzero exit must not throw on its own.
$PSNativeCommandUseErrorActionPreference = $false

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptDirectory)
$packageIdentityName = 'AWSLabs.AutomatedSecurityHelper'
# The marker the launcher writes when a bootstrap finishes, and the prefix of its first line,
# which names the wheel the venv was built from. Both are constants in AshLauncher.cs.
$completionMarker = '.ash-bootstrap-complete'
$markerWheelPrefix = 'wheel: '

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

# ------------------------------------------------------------------------------------------
# Pure helpers. Each is exercised by Invoke-HelperSelfTest, which runs before anything else.
# ------------------------------------------------------------------------------------------

# The last non-zero component decremented and everything after it zeroed: 3.7.0 -> 3.6.0,
# 4.0.0 -> 3.0.0. The same rule as vl_lower_version in packaging/verify-lib.sh.
function Get-LowerVersion {
    param([Parameter(Mandatory = $true)][string] $Version)
    if ($Version -notmatch '^\d+(\.\d+)*$') {
        throw "version '$Version' is not dotted integers"
    }
    $parts = @($Version.Split('.') | ForEach-Object { [int] $_ })
    $index = $parts.Count - 1
    while ($index -ge 0 -and $parts[$index] -eq 0) {
        $index--
    }
    if ($index -lt 0) {
        throw "cannot derive a lower version from $Version"
    }
    $parts[$index]--
    for ($i = $index + 1; $i -lt $parts.Count; $i++) {
        $parts[$i] = 0
    }
    return ($parts -join '.')
}

# Rewrites `version = "<From>"` in [project] and in [tool.commitizen], and nowhere else. Both,
# because msix.py compares the staged Identity/@Version with commitizen's version and the
# wheel's version comes from [project]'s. Exactly one line in each table, or it throws: a
# rewrite that matched nothing would build N-1 with N's version and the "upgrade" would be a
# reinstall.
function Set-ProjectVersions {
    param(
        [Parameter(Mandatory = $true)][string] $Text,
        [Parameter(Mandatory = $true)][string] $From,
        [Parameter(Mandatory = $true)][string] $To
    )
    $lines = $Text -split "`n"
    $table = ''
    $replaced = @{ 'project' = 0; 'tool.commitizen' = 0 }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].TrimEnd("`r")
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $table = $Matches[1].Trim()
            continue
        }
        if ($replaced.ContainsKey($table) -and $line -eq "version = `"$From`"") {
            $ending = if ($lines[$i].EndsWith("`r")) { "`r" } else { '' }
            $lines[$i] = "version = `"$To`"$ending"
            $replaced[$table]++
        }
    }
    foreach ($name in $replaced.Keys) {
        if ($replaced[$name] -ne 1) {
            throw "expected exactly one 'version = `"$From`"' line in [$name], rewrote $($replaced[$name])"
        }
    }
    return ($lines -join "`n")
}

# The wheel file name a finished bootstrap recorded in the marker, or $null.
function Get-MarkerWheel {
    param([string] $MarkerText)
    if (-not $MarkerText) {
        return $null
    }
    foreach ($line in ($MarkerText -split "`r?`n")) {
        if ($line.StartsWith($markerWheelPrefix)) {
            return $line.Substring($markerWheelPrefix.Length).Trim()
        }
    }
    return $null
}

# Copies a zip and changes one byte of the first member whose name ends in $MemberSuffix,
# leaving every other member as it was. Returns the member's name.
function New-TamperedZip {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Destination,
        [Parameter(Mandatory = $true)][string] $MemberSuffix
    )
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    $archive = [System.IO.Compression.ZipFile]::Open($Destination, [System.IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = @($archive.Entries | Where-Object { $_.FullName.EndsWith($MemberSuffix) }) | Select-Object -First 1
        if (-not $entry) {
            throw "no member ending in '$MemberSuffix' in $Source"
        }
        $name = $entry.FullName
        $stream = $entry.Open()
        try {
            $buffer = New-Object System.IO.MemoryStream
            $stream.CopyTo($buffer)
            $bytes = $buffer.ToArray()
        }
        finally {
            $stream.Dispose()
        }
        if ($bytes.Length -eq 0) {
            throw "member $name is empty, so there is no byte to change"
        }
        $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 0xFF
        $entry.Delete()
        $replacement = $archive.CreateEntry($name)
        $out = $replacement.Open()
        try {
            $out.Write($bytes, 0, $bytes.Length)
        }
        finally {
            $out.Dispose()
        }
        return $name
    }
    finally {
        $archive.Dispose()
    }
}

function Invoke-HelperSelfTest {
    function Check([string] $Name, [scriptblock] $Body) {
        $script:checks++
        try {
            $ok = & $Body
        }
        catch {
            $ok = $false
            Write-Host "     ($Name threw: $($_.Exception.Message))"
        }
        Write-Host "   $(if ($ok) { 'ok' } else { 'FAIL' }): $Name"
        if (-not $ok) { $script:failures++ }
    }
    function Throws([scriptblock] $Body) {
        try { & $Body | Out-Null; return $false } catch { return $true }
    }

    Check 'lower 3.7.0' { (Get-LowerVersion '3.7.0') -eq '3.6.0' }
    Check 'lower 4.0.0' { (Get-LowerVersion '4.0.0') -eq '3.0.0' }
    Check 'lower 3.10.2' { (Get-LowerVersion '3.10.2') -eq '3.10.1' }
    Check 'lower 3.1.0' { (Get-LowerVersion '3.1.0') -eq '3.0.0' }
    Check 'lower refuses 0.0.0' { Throws { Get-LowerVersion '0.0.0' } }
    Check 'lower refuses a pre-release' { Throws { Get-LowerVersion '3.7.0rc1' } }

    $pyproject = "[project]`nname = `"x`"`nversion = `"3.7.0`"`n[project.urls]`nversion = `"3.7.0`"`n[tool.commitizen]`nversion = `"3.7.0`"`n[tool.other]`nversion = `"3.7.0`"`n"
    Check 'rewrite both tables and nothing else' {
        $out = Set-ProjectVersions -Text $pyproject -From '3.7.0' -To '3.6.0'
        $out -eq "[project]`nname = `"x`"`nversion = `"3.6.0`"`n[project.urls]`nversion = `"3.7.0`"`n[tool.commitizen]`nversion = `"3.6.0`"`n[tool.other]`nversion = `"3.7.0`"`n"
    }
    Check 'rewrite keeps CRLF' {
        $out = Set-ProjectVersions -Text ($pyproject -replace "`n", "`r`n") -From '3.7.0' -To '3.6.0'
        $out.Contains("version = `"3.6.0`"`r`n[project.urls]")
    }
    Check 'rewrite refuses a missing commitizen version' {
        Throws { Set-ProjectVersions -Text "[project]`nversion = `"3.7.0`"`n" -From '3.7.0' -To '3.6.0' }
    }
    Check 'rewrite refuses a version that does not match' {
        Throws { Set-ProjectVersions -Text $pyproject -From '3.8.0' -To '3.6.0' }
    }

    Check 'marker wheel read from the first line' {
        (Get-MarkerWheel "wheel: a-3.7.0-py3-none-any.whl`r`nWritten by ...`r`n") -eq 'a-3.7.0-py3-none-any.whl'
    }
    Check 'marker from an older launcher names no wheel' {
        $null -eq (Get-MarkerWheel "Written by ASH's MSIX launcher once pip finished.`n")
    }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ash-msix-selftest-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = Join-Path $tmp 'in.zip'
        $archive = [System.IO.Compression.ZipFile]::Open($zip, [System.IO.Compression.ZipArchiveMode]::Create)
        foreach ($pair in @(@('assets/Logo.png', 'logo-bytes'), @('AppxManifest.xml', '<Package/>'))) {
            $writer = New-Object System.IO.StreamWriter($archive.CreateEntry($pair[0]).Open())
            $writer.Write($pair[1])
            $writer.Dispose()
        }
        $archive.Dispose()
        $read = {
            param($Path, $Name)
            $a = [System.IO.Compression.ZipFile]::OpenRead($Path)
            try {
                $r = New-Object System.IO.StreamReader($a.GetEntry($Name).Open())
                try { $r.ReadToEnd() } finally { $r.Dispose() }
            }
            finally { $a.Dispose() }
        }
        Check 'tamper changes the named member only' {
            $out = Join-Path $tmp 'out.zip'
            $name = New-TamperedZip -Source $zip -Destination $out -MemberSuffix 'Logo.png'
            ($name -eq 'assets/Logo.png') -and
                ((& $read $out 'assets/Logo.png') -ne 'logo-bytes') -and
                ((& $read $out 'AppxManifest.xml') -eq '<Package/>') -and
                ((& $read $zip 'assets/Logo.png') -eq 'logo-bytes')
        }
        Check 'tamper refuses a member that is not there' {
            Throws { New-TamperedZip -Source $zip -Destination (Join-Path $tmp 'x.zip') -MemberSuffix 'Nope.png' }
        }
    }
    finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    if ($script:failures) {
        Write-Host "   helper self-test FAILED: $($script:failures) of $($script:checks) checks"
        return $false
    }
    Write-Host "   helper self-test passed: $($script:checks) checks"
    return $true
}

Write-Step '0. this script''s own helpers'
$script:checks = 0
$script:failures = 0
if (-not (Invoke-HelperSelfTest)) {
    Fail 'the helper self-test failed, so nothing below could be trusted'
}
if ($SelfTest) {
    exit 0
}

# ------------------------------------------------------------------------------------------
# Windows-only helpers.
# ------------------------------------------------------------------------------------------

# The CLI name comes from the one file the e2e scripts share, so the next rename is one line.
$cliName = (Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'scripts/e2e/cli_name.json') | ConvertFrom-Json).cli_name
if (-not $cliName) {
    Fail 'scripts/e2e/cli_name.json names no cli_name'
}
# The three names this package exposes. The wheel also declares the deprecated `ash`, which
# this package must not expose: on Windows `ash` is the name MSYS2 and Git for Windows give
# the Almquist shell. NOT_EXPOSED_SCRIPTS in msix.py.
$expectedNames = @($cliName, 'ashv3', 'automated-security-helper')
$windowsApps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'

# The harness runs under uv's interpreter, never under the package being tested.
function Invoke-Harness {
    & uv run --no-project --python 3.13 python @args
}

# Removes the package if a previous run left it installed. Verification that depends on
# starting clean has to make itself clean, or a rerun on the same runner measures the previous
# run's state.
function Remove-AshPackage {
    Get-AppxPackage -Name $packageIdentityName -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue }
}

function Get-InstalledAsh {
    $all = @(Get-AppxPackage -Name $packageIdentityName -ErrorAction SilentlyContinue)
    if ($all.Count -gt 1) {
        Fail "$($all.Count) packages named $packageIdentityName are installed; an update must replace, not add"
    }
    if ($all.Count -eq 0) {
        return $null
    }
    return $all[0]
}

function Install-Msix {
    param([string] $Path, [string] $Label)
    try {
        Add-AppxPackage -Path $Path -ErrorAction Stop
    }
    catch {
        Fail @"
Add-AppxPackage failed for $Label ($(Split-Path -Leaf $Path)): $($_.Exception.Message)

If this says the certificate is untrusted (0x800B0109) the import above did not take. If it
says the deployment service is unavailable, this host does not support installing app
packages, which is a documented gap for Windows Server: Microsoft's MSIX feature matrix
covers Windows Server 2019 and 2022 and has no Windows Server 2025 column, and
windows-latest is Windows Server 2025. Read the detail in the event log at Applications and
Services Logs > Microsoft > Windows > AppxDeployment-Server > Operational.
"@
    }
}

function Import-PackageSigner {
    param([string] $Path, [string] $Label)
    # A self-signed package cannot install until the certificate is trusted, and the store is
    # Local Computer \ Trusted People specifically. Not Trusted Root: the certificate is not a
    # root CA, and putting it there would trust it to vouch for anything. Hosted Windows
    # runners run as administrator with UAC disabled, which is what makes writing to a
    # LocalMachine store possible here at all.
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if (-not $signature.SignerCertificate) {
        Fail "$Label is not signed, so there is no certificate to trust"
    }
    Write-Host "   $Label signer: $($signature.SignerCertificate.Subject) ($($signature.Status))"
    $certificateFile = Join-Path $work "signer-$($signature.SignerCertificate.Thumbprint).cer"
    [System.IO.File]::WriteAllBytes($certificateFile, $signature.SignerCertificate.RawData)
    Import-Certificate -FilePath $certificateFile -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
    return $signature.SignerCertificate.Subject
}

# Whether the three names are reachable from a shell, measured rather than asserted for the
# Windows Server reason in the .DESCRIPTION. All three are checked because all three are part
# of the entry-point contract, and the long name in particular is the escape hatch for hosts
# where a short name resolves to something else. Returns name -> what to invoke.
function Resolve-PackagedNames {
    param($Installed)
    if ($env:PATH -notlike "*$windowsApps*") {
        # The directory aliases land in is normally already on PATH. If it is not, adding it is
        # the difference between measuring alias support and measuring PATH.
        Write-Host "   note: $windowsApps was not on PATH; adding it for this process"
        $env:PATH = "$windowsApps;$env:PATH"
    }
    $resolved = @{}
    foreach ($name in $expectedNames) {
        $aliasPath = Join-Path $windowsApps "$name.exe"
        if (Test-Path $aliasPath) {
            Write-Host "   $name : alias present at $aliasPath"
            $resolved[$name] = $aliasPath
        }
        else {
            Write-Host "   $name : NO alias on this host"
        }
    }
    $script:aliasesWork = $resolved.Count -eq $expectedNames.Count
    if (-not $script:aliasesWork) {
        $missing = $expectedNames | Where-Object { -not $resolved.ContainsKey($_) }
        $message = @"
app execution aliases are not available for: $($missing -join ', '). windows.appExecutionAlias
is documented as unsupported on Windows Server 2019 and Microsoft publishes no statement for
Server 2022 or 2025, so this is the expected outcome on a Windows Server host rather than a
defect in the manifest. The scans run through the packaged executable instead, so the
capability assertions still mean something. Alias reachability on Windows client remains
UNVERIFIED by this run.
"@
        Write-Host "   $message"
        Write-Host "::warning::$message"
        # Fall back to the executable inside the installed package. Reachable because
        # InstallLocation is readable even though it is not writable.
        foreach ($name in $missing) {
            $direct = Join-Path $Installed.InstallLocation "$name.exe"
            if (-not (Test-Path $direct)) {
                Fail "neither an alias nor $direct exists, so $name is unreachable by any route"
            }
            $resolved[$name] = $direct
        }
    }
    return $resolved
}

# Prints the venv's state and fails if it was created somewhere other than where it lives.
#
# The state is described BEFORE any exit code is judged, and the reason is a real failure an
# exit-code-first ordering could not explain. On the job's first run (35275790822) the
# bootstrap completed -- pip printed "Successfully installed automated-security-helper-3.7.0"
# -- and then `ash --version` exited 1 having written nothing further. With the venv check
# after the exit-code check, the run failed with one line and no way to tell whether the
# bootstrap had finished, whether the console script existed, or whether the launcher had
# found it and failed to exec it. That is three different bugs behind one message.
#
# The moved-venv check: on Windows pip writes each Scripts\*.exe with the absolute path of the
# interpreter it generated the script for embedded in it, so moving a venv leaves every shim
# naming a directory that is gone. python.exe keeps working, because it resolves its home
# through the relative pyvenv.cfg beside it. The result is a venv that passes every other check
# here and whose console scripts exit 1 with both streams empty -- indistinguishable at a
# glance from ASH failing silently, and it cost this job several runs and one wrong diagnosis
# blaming Python 3.14.
#
# Read out of pyvenv.cfg's `command`, not out of the .exe. Parsing the shim was tried first and
# is a trap: the launcher stub pip prepends carries its own UTF-16 diagnostic strings, several
# of them about shebang lines, so a regex for `#!` over the file's bytes matches inside the stub
# long before it reaches the real shebang. `command` records the path as passed to `-m venv`,
# which is exactly the question. It is written by Python 3.11 and newer; on an older
# interpreter it is absent and this says so rather than passing quietly.
function Show-Venv {
    param([string] $Venv)
    $scripts = Join-Path $Venv 'Scripts'
    $console = Join-Path $scripts "$cliName.exe"
    Write-Host "   venv present:        $(Test-Path $Venv)"
    Write-Host "   venv console script: $(Test-Path $console)  ($console)"
    if (Test-Path $scripts) {
        $names = Get-ChildItem -LiteralPath $scripts -Filter '*.exe' | Select-Object -ExpandProperty Name
        Write-Host "   Scripts\*.exe:       $($names -join ', ')"
    }
    $marker = Join-Path $Venv $completionMarker
    if (Test-Path $marker) {
        Write-Host "   marker wheel:        $(Get-MarkerWheel (Get-Content -Raw -LiteralPath $marker))"
    }
    $pyvenvCfg = Join-Path $Venv 'pyvenv.cfg'
    if (-not (Test-Path $pyvenvCfg)) {
        return
    }
    Write-Host '   pyvenv.cfg:'
    Get-Content -LiteralPath $pyvenvCfg | ForEach-Object { Write-Host "     $_" }
    $commandLine = Get-Content -LiteralPath $pyvenvCfg |
        Where-Object { $_ -match '^\s*command\s*=' } |
        Select-Object -First 1
    $venvMarker = '-m venv '
    if (-not $commandLine) {
        Write-Host "   pyvenv.cfg has no 'command' key (Python 3.11+ writes it), so where this venv"
        Write-Host "   was created cannot be read back and the moved-venv check is not running"
        return
    }
    if ($commandLine.LastIndexOf($venvMarker) -lt 0) {
        Write-Host "   pyvenv.cfg 'command' does not contain '$venvMarker', so the creation path cannot"
        Write-Host "   be read out of it: $commandLine"
        return
    }
    $index = $commandLine.LastIndexOf($venvMarker) + $venvMarker.Length
    $createdAt = $commandLine.Substring($index).Trim().Trim('"')
    $createdFull = [System.IO.Path]::GetFullPath($createdAt).TrimEnd('\')
    $venvFull = [System.IO.Path]::GetFullPath($Venv).TrimEnd('\')
    Write-Host "   venv was created at: $createdFull"
    Write-Host "   venv now lives at:   $venvFull"
    if ($createdFull -ine $venvFull) {
        Fail @"
this virtualenv was created somewhere other than where it now lives:

  created at: $createdFull
  now at:     $venvFull

A virtualenv cannot be moved on Windows. pip embeds the absolute path of the interpreter into
every Scripts\*.exe, so after a move each one names a directory that no longer exists and fails
by exiting 1 with nothing on stdout or stderr, while python.exe inside the venv keeps working.
Build the venv where it will live; see the CreateVenv comment in packaging/msix/AshLauncher.cs.
"@
    }
}

# When `ashx --version` failed: the readings that separate a broken launcher, a broken shim and
# a broken ASH. They have fired once in anger and the answer was the shim: probe A ran, probe C
# printed a version and exited 0, and the console script exited 1 with both streams empty. The
# moved-venv check in Show-Venv now names that fault directly, so reaching this means something
# ELSE is wrong.
#
#   * If A fails, the venv's interpreter is not usable at all and nothing below matters.
#   * If A passes and C fails, the defect is in ASH's CLI rather than in this package.
#   * If A and C pass while the console script does not, the shim is broken in some way the
#     moved-venv check did not catch, and that check is what needs widening.
#
# B and C pass -I, and that flag is load-bearing. Without it `python -c` puts the current
# directory on sys.path, and this script runs from the repository root, so both probes would
# import the SOURCE TREE instead of what pip installed into the venv. -I drops cwd from
# sys.path, so an import that succeeds now succeeded out of site-packages.
function Show-VersionFailure {
    param([string] $Invoke, [string] $Venv)
    Write-Host '   re-running with stdout and stderr captured:'
    $stdoutPath = Join-Path $work 'version-stdout.txt'
    $stderrPath = Join-Path $work 'version-stderr.txt'
    $process = Start-Process -FilePath $Invoke -ArgumentList '--version' `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    Write-Host "     second run exit: $($process.ExitCode)"
    foreach ($stream in @(@('stdout', $stdoutPath), @('stderr', $stderrPath))) {
        $body = if (Test-Path $stream[1]) { Get-Content -LiteralPath $stream[1] -Raw } else { '' }
        if ([string]::IsNullOrWhiteSpace($body)) {
            Write-Host "     $($stream[0]): <empty>"
        }
        else {
            Write-Host "     $($stream[0]):"
            $body.TrimEnd() -split "`n" | ForEach-Object { Write-Host "       $_" }
        }
    }
    $console = Join-Path $Venv "Scripts\$cliName.exe"
    if (Test-Path $console) {
        Write-Host "   the venv's own $cliName.exe, bypassing the launcher:"
        & $console --version
        Write-Host "     exit: $LASTEXITCODE"
    }
    $venvPython = Join-Path $Venv 'Scripts\python.exe'
    if (-not (Test-Path $venvPython)) {
        Write-Host "   no python.exe in the venv's Scripts, so the venv itself is incomplete"
        return
    }
    Write-Host '   probe A -- the venv interpreter runs at all:'
    & $venvPython -c "import sys; print(sys.version); print(sys.executable)"
    Write-Host "     exit: $LASTEXITCODE"
    Write-Host '   probe B -- ASH imports in that interpreter, out of site-packages:'
    & $venvPython -I -c "import automated_security_helper as m; print('import ok', m.__file__)"
    Write-Host "     exit: $LASTEXITCODE"
    # The same callable [project.scripts] binds the CLI name to, reached without the .exe shim.
    Write-Host '   probe C -- the console-script callable, bypassing the .exe shim:'
    & $venvPython -I -c "from automated_security_helper.cli.main import app; app(['--version'])"
    Write-Host "     exit: $LASTEXITCODE"
}

# Runs `<cli> --version` twice: once streamed, which is the first-run bootstrap when the venv is
# missing or stale and is slow on purpose, and once captured, which must name $ExpectedVersion.
# Then requires a finished venv whose marker names $ExpectedWheel.
function Assert-RunsAs {
    param([string] $Invoke, [string] $Venv, [string] $ExpectedVersion, [string] $ExpectedWheel, [string] $Label)
    & $Invoke --version
    $exit = $LASTEXITCODE
    Show-Venv -Venv $Venv
    if ($exit -ne 0) {
        Show-VersionFailure -Invoke $Invoke -Venv $Venv
        Fail "[$Label] $cliName --version exited $exit"
    }
    $lines = @(& $Invoke --version 2>$null)
    $exit = $LASTEXITCODE
    $line = ($lines | Where-Object { $_ } | Select-Object -Last 1)
    if ($exit -ne 0) {
        Fail "[$Label] the second $cliName --version exited $exit"
    }
    if ("$line" -notlike "*v$ExpectedVersion*") {
        Fail "[$Label] $cliName --version printed '$line', expected v$ExpectedVersion"
    }
    Write-Host "   [$Label] $cliName --version: $line"
    $marker = Join-Path $Venv $completionMarker
    if (-not (Test-Path (Join-Path $Venv "Scripts\$cliName.exe")) -or -not (Test-Path $marker)) {
        Fail "[$Label] $cliName ran but there is no finished venv at $Venv, so nothing was bootstrapped where uninstall can reclaim it"
    }
    $built = Get-MarkerWheel (Get-Content -Raw -LiteralPath $marker)
    if ($built -ne $ExpectedWheel) {
        Fail "[$Label] the venv's marker names '$built', expected '$ExpectedWheel'"
    }
}

function Get-AliasLeftover {
    return @($expectedNames + @('ash') | Where-Object { Test-Path (Join-Path $windowsApps "$_.exe") })
}

# ------------------------------------------------------------------------------------------

if (-not $WorkDirectory) {
    $base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
    $WorkDirectory = Join-Path $base 'ash-msix-e2e'
}
if (Test-Path $WorkDirectory) {
    Remove-Item -Recurse -Force -LiteralPath $WorkDirectory
}
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$work = (Resolve-Path -LiteralPath $WorkDirectory).Path
$buildMsix = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'build/msix'))
if ($work.StartsWith($buildMsix, [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail "-WorkDirectory $work is under build/msix, which the workflow uploads; N-1 and the tampered package must never be uploaded"
}
Write-Host "   work directory: $work"

Write-Step '1. resolve the wheel'
if (-not $Wheel) {
    $candidates = @(Get-ChildItem -Path (Join-Path $repoRoot 'dist') -Filter '*.whl' -File -ErrorAction SilentlyContinue)
    if ($candidates.Count -ne 1) {
        Fail "expected exactly 1 wheel under dist/, found $($candidates.Count). Pass -Wheel to name one."
    }
    $Wheel = $candidates[0].FullName
}
$wheelName = Split-Path -Leaf $Wheel
if ($wheelName -notmatch '^automated_security_helper-(\d+\.\d+\.\d+)-py3-none-any\.whl$') {
    Fail "cannot read a three-part version from $wheelName"
}
$version = $Matches[1]
$prevVersion = Get-LowerVersion $version
$prevWheelName = "automated_security_helper-$prevVersion-py3-none-any.whl"
Write-Host "   wheel: $wheelName (N = $version, N-1 = $prevVersion)"

Write-Step '2. build and sign N'
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

Write-Step '2b. the package-contents gate, on the signed package'
# packaging/assert-package-contents.py on the artifact makeappx and signtool produced, the
# same file a user downloads: every member must be one the MSIX layout names, each
# launcher must be a managed executable AppxManifest.xml declares, AppxBlockMap.xml must
# match the payload byte for byte, and the one wheel is handed to the gate the published
# wheel passes. `uv run --script` because the MSIX checks parse XML with defusedxml, which
# the script's PEP 723 block declares.
& uv run --script --python 3.13 (Join-Path $repoRoot 'packaging/assert-package-contents.py') $msix
if ($LASTEXITCODE -ne 0) {
    Fail "packaging/assert-package-contents.py exited $LASTEXITCODE on $(Split-Path -Leaf $msix)"
}

Write-Step '2c. negative control: the gate must refuse this package with a scanner planted in it'
# The gate's --self-test proves each check can fail on fixtures shaped like this package.
# This proves it on the package itself: a copy of the signed .msix above with
# assets/grype (an ELF header) added must be refused with the native-binary verdict on
# that member, and the unmodified package must pass. The copy is written under the work
# directory, never build/msix, which the workflow uploads.
& uv run --script --python 3.13 (Join-Path $repoRoot 'packaging/assert-planted-scanner-rejected.py') $msix --work (Join-Path $work 'planted')
if ($LASTEXITCODE -ne 0) {
    Fail "NEGATIVE CONTROL: packaging/assert-planted-scanner-rejected.py exited $LASTEXITCODE on $(Split-Path -Leaf $msix); the gate did not refuse the real package with a scanner planted in it"
}

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
    if ($identity.Version -ne "$version.0") {
        Fail "Identity/@Version is $($identity.Version), expected $version.0 from the wheel"
    }

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
    if ($launchers -contains 'ash.exe') {
        Fail "the package ships an ash.exe launcher; it exposes $($expectedNames -join ', ') only"
    }
    foreach ($name in $expectedNames) {
        if ($launchers -notcontains "$name.exe") {
            Fail "the package ships no $name.exe launcher; launchers are: $($launchers -join ', ')"
        }
    }
}
finally {
    $archive.Dispose()
}

Write-Step "3b. build and sign N-1 ($prevVersion) in the work directory"
# `git archive HEAD` rather than a copy of the checkout: the build hook writes into the tree it
# builds, and the export carries nothing a build of the checkout left behind. Both
# [project] and [tool.commitizen] versions are lowered, because the N-1 tree's own msix.py
# compares the staged Identity/@Version against commitizen's, and that check must pass for N-1
# as it does for N. The N-1 package is then built by the EXPORT's build.ps1, so nothing in it
# depends on this checkout.
$prevRoot = Join-Path $work 'prev'
$prevTree = Join-Path $prevRoot 'tree'
New-Item -ItemType Directory -Force -Path $prevTree | Out-Null
$prevZip = Join-Path $prevRoot 'tree.zip'
& git -C $repoRoot archive --format=zip -o $prevZip HEAD
if ($LASTEXITCODE -ne 0) {
    Fail "git archive exited $LASTEXITCODE"
}
Expand-Archive -LiteralPath $prevZip -DestinationPath $prevTree
$prevPyproject = Join-Path $prevTree 'pyproject.toml'
$text = [System.IO.File]::ReadAllText($prevPyproject)
try {
    $text = Set-ProjectVersions -Text $text -From $version -To $prevVersion
}
catch {
    Fail "could not set the N-1 version in the exported pyproject.toml: $($_.Exception.Message)"
}
[System.IO.File]::WriteAllText($prevPyproject, $text, (New-Object System.Text.UTF8Encoding($false)))

$prevDist = Join-Path $prevRoot 'dist'
& uv build --quiet --wheel --out-dir $prevDist $prevTree
if ($LASTEXITCODE -ne 0) {
    Fail "uv build of the N-1 tree exited $LASTEXITCODE"
}
$prevWheel = Join-Path $prevDist $prevWheelName
if (-not (Test-Path $prevWheel)) {
    Fail "uv build did not write $prevWheel"
}
# The same gate the build job runs on N's wheel, so N-1 cannot carry anything N could not.
Invoke-Harness (Join-Path $repoRoot '.github/scripts/assert-artifact-contents.py') $prevWheel
if ($LASTEXITCODE -ne 0) {
    Fail "assert-artifact-contents.py exited $LASTEXITCODE on $prevWheelName"
}
& (Join-Path $prevTree 'packaging/msix/build.ps1') `
    -Wheel $prevWheel `
    -OutputDirectory (Join-Path $prevRoot 'msix') `
    -PfxBase64 $PfxBase64 `
    -PfxPassword $PfxPassword
if ($LASTEXITCODE -ne 0) {
    Fail "the N-1 build.ps1 exited $LASTEXITCODE"
}
$prevBuilt = @(Get-ChildItem -Path (Join-Path $prevRoot 'msix') -Filter '*.msix' -File)
if ($prevBuilt.Count -ne 1) {
    Fail "expected exactly 1 N-1 .msix, found $($prevBuilt.Count)"
}
$prevMsix = $prevBuilt[0].FullName
Write-Host "   built N-1: $prevMsix"
if (@(Get-ChildItem -Path (Join-Path $repoRoot 'build/msix') -Filter '*.msix' -File).Count -ne 1) {
    Fail 'build/msix no longer holds exactly one .msix; the N-1 build wrote into the uploaded directory'
}

Write-Step '4. trust the signing certificates'
$publisherN = Import-PackageSigner -Path $msix -Label 'N'
$publisherPrev = Import-PackageSigner -Path $prevMsix -Label 'N-1'
if ($publisherN -ne $publisherPrev) {
    Fail "N and N-1 have different publishers ('$publisherN' and '$publisherPrev'), so the second install would be a different app rather than an upgrade"
}

Write-Step '4b. negative control: a package with one changed byte must be refused'
# The install step has to be able to fail. A copy of N with the last byte of one payload file
# flipped no longer matches the hash AppxBlockMap.xml records for it, and the signature covers
# the block map, so Windows must refuse it. If it installs, nothing below proves that
# Add-AppxPackage checked what it installed.
$tampered = Join-Path $work 'tampered.msix'
$tamperedMember = New-TamperedZip -Source $msix -Destination $tampered -MemberSuffix 'StoreLogo.png'
Write-Host "   changed one byte of $tamperedMember in $(Split-Path -Leaf $tampered)"
$refused = $false
try {
    Add-AppxPackage -Path $tampered -ErrorAction Stop
}
catch {
    $refused = $true
    Write-Host "   refused, as it must be: $($_.Exception.Message)"
}
if (-not $refused) {
    Remove-AshPackage
    Fail 'NEGATIVE CONTROL: Add-AppxPackage installed a package whose payload no longer matches its signed block map'
}
if (Get-InstalledAsh) {
    Fail 'NEGATIVE CONTROL: the refused package is installed anyway'
}
Write-Host '   OK: refused, and nothing is installed'

Write-Step "5. install N-1 ($prevVersion) fresh"
Install-Msix -Path $prevMsix -Label 'N-1'
$installed = Get-InstalledAsh
if (-not $installed) {
    Fail 'Add-AppxPackage reported success but the N-1 package is not installed'
}
Write-Host "   installed: $($installed.PackageFullName)"
if ($installed.Version.ToString() -ne "$prevVersion.0") {
    Fail "the installed version is $($installed.Version), expected $prevVersion.0"
}
$packageFamilyName = $installed.PackageFamilyName
$venv = Join-Path $env:LOCALAPPDATA "Packages\$packageFamilyName\LocalCache\ash-venv"
Write-Host "   venv will be created at: $venv"
if (Test-Path $venv) {
    Fail "$venv exists before the first run; the cleanup at the start did not take"
}
$resolved = Resolve-PackagedNames -Installed $installed
Assert-RunsAs -Invoke $resolved[$cliName] -Venv $venv -ExpectedVersion $prevVersion -ExpectedWheel $prevWheelName -Label 'N-1'

# Proof the upgrade REBUILDS the venv rather than finding it: Windows keeps LocalCache across a
# package update, so this file survives the update itself and is gone only if the launcher
# deleted the N-1 venv.
$sentinel = Join-Path $venv 'e2e-n-minus-1-sentinel.txt'
Set-Content -LiteralPath $sentinel -Value "written into the N-1 venv by verify-on-windows.ps1"

Write-Step "6. upgrade to N ($version)"
Install-Msix -Path $msix -Label 'N'
$installed = Get-InstalledAsh
if (-not $installed) {
    Fail 'the package is not installed after the upgrade'
}
Write-Host "   installed: $($installed.PackageFullName)"
if ($installed.Version.ToString() -ne "$version.0") {
    Fail "the installed version after the upgrade is $($installed.Version), expected $version.0"
}
if ($installed.PackageFamilyName -ne $packageFamilyName) {
    Fail "the upgrade changed the package family from $packageFamilyName to $($installed.PackageFamilyName)"
}
if (-not (Test-Path $sentinel)) {
    Fail "the N-1 venv was gone before N first ran, so this run cannot tell whether the launcher rebuilt it"
}
$resolved = Resolve-PackagedNames -Installed $installed
Assert-RunsAs -Invoke $resolved[$cliName] -Venv $venv -ExpectedVersion $version -ExpectedWheel $wheelName -Label 'N after upgrade'
if (Test-Path $sentinel) {
    Fail "the N-1 venv survived the upgrade: $sentinel is still there, so N is running in a venv built from N-1's wheel"
}
Write-Host '   OK: the version moved and the venv was rebuilt from the new wheel'

Write-Step '7. the deprecated name warns and the long name does not'
# The entry-point contract, exercised rather than assumed. The CLI name is canonical, `ashv3`
# warns once on stderr, and `automated-security-helper` is kept indefinitely and silent. The
# launchers derive which venv console script to run from their own filenames, so this is what
# catches all three collapsing onto the same one.
$errorFile = Join-Path $work 'names-stderr.txt'
& $resolved['ashv3'] --version 2>$errorFile | Out-Null
$ashv3Stderr = if (Test-Path $errorFile) { Get-Content -Raw $errorFile } else { '' }
if ($ashv3Stderr -notmatch '(?i)deprecat') {
    Fail @"
ashv3 --version printed nothing about deprecation on stderr. That warning comes from the
wheel's own run_ashv3 wrapper, so its absence means ashv3.exe is running the `$cliName` console
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
and is deliberately silent: it is the escape hatch for hosts where a short name resolves to
another program, and a warning on it would train users away from the one name that always
works. stderr was: $longNameStderr
"@
}
Write-Host '   automated-security-helper was silent, as it should be'

Write-Step '8. the three e2e cases'
# run_case.py copies each fixture into the work directory, runs the scan with the case's
# scanners, args and environment, and judges the result with assert_outcome.py: the exact exit
# code, reports/ash.sarif and ash_aggregated_results.json at exactly those paths, the finding
# count in both, and for exit 1 that opengrep is the scanner that did not complete. The
# installed package scans a tree outside its own directory, which is what
# broadFileSystemAccess exists for: an install that cannot read the tree exits 0 with nothing
# found, and the findings case rejects that.
$scans = Join-Path $work 'scans'
$runCase = Join-Path $repoRoot 'scripts/e2e/run_case.py'
foreach ($case in @('findings', 'clean', 'incomplete')) {
    Invoke-Harness $runCase --cli $resolved[$cliName] --case $case --work $scans --label "msix-$case"
    if ($LASTEXITCODE -ne 0) {
        Fail "the $case case failed through the MSIX package (run_case.py exited $LASTEXITCODE)"
    }
}

Write-Step '8b. negative controls on the verdict'
# A findings scan told not to fail on findings exits 0. run_case.py must reject it, and for the
# exit code: rc 1 alone would also come from a missing report or a wrong count, and then this
# control would control nothing about the exit-code check. The '--' is quoted because PowerShell
# consumes a bare -- as its own end-of-parameters token when calling a function, and
# run_case.py needs it to tell its own options from the scan's. --expect-reject, here and
# below, makes the expected rejection print as plain lines rather than as error
# annotations on a green run; the exit code and the reason are still judged here.
$negativeLog = Join-Path $work 'negative-no-fail-on-findings.log'
Invoke-Harness $runCase --cli $resolved[$cliName] --case findings --work $scans --label 'msix-negative-no-fail-on-findings' --expect-reject '--' --no-fail-on-findings *> $negativeLog
$negativeExit = $LASTEXITCODE
Get-Content -LiteralPath $negativeLog | ForEach-Object { Write-Host "   | $_" }
if ($negativeExit -ne 1) {
    Fail "NEGATIVE CONTROL: run_case.py returned $negativeExit for a findings scan run with --no-fail-on-findings; expected 1"
}
if (-not (Select-String -LiteralPath $negativeLog -SimpleMatch 'exit code 0 (nothing actionable), expected exactly 2' -Quiet)) {
    Fail 'NEGATIVE CONTROL: run_case.py rejected the --no-fail-on-findings scan, but not for its exit code 0'
}
Write-Host '   OK: rejected for exit code 0'

# The real clean output, judged as if it were a findings outcome, must be rejected.
Invoke-Harness (Join-Path $repoRoot 'scripts/e2e/assert_outcome.py') `
    --output-dir (Join-Path $scans 'msix-clean\out') --rc 0 `
    --expect-rc 2 --min-findings 1 --require-scanner detect-secrets --selected detect-secrets --expect-reject
$negativeExit = $LASTEXITCODE
if ($negativeExit -ne 1) {
    Fail "NEGATIVE CONTROL: assert_outcome.py returned $negativeExit on a clean output expected to hold findings; expected 1"
}
Write-Host '   OK: the clean output was rejected as a findings outcome'

Write-Step '8c. select a scanner after install: ashx dependencies install --tool grype'
# No package bundles a scanner; a user selects one after installing (README.msix).
# scripts/e2e/assert_dependencies_install.py runs under the installed venv's interpreter,
# with the packaged alias as the CLI: it requires nothing installed yet, the install to
# exit 0, grype at ~\.ash\bin with a receipt recording this ASH's pinned version and
# archive SHA-256 and the binary's own hash, `grype version` to name the pin, and
# `--tool <unknown>` to exit EXIT_BAD_SELECTION, which is the negative control.
#
# As the installing user, unlike the Chocolatey leg's separate unprivileged account: an
# MSIX package is registered per user, so another account has no `ashx` to run. That the
# install needs no privilege is the Chocolatey leg's proof; this one proves the packaged
# app's own process can download and place a scanner outside the package, where ~\.ash
# lives and where package file-system virtualization does not reach.
$venvPython = Join-Path $venv 'Scripts\python.exe'
& $venvPython -I (Join-Path $repoRoot 'scripts/e2e/assert_dependencies_install.py') --cli $resolved[$cliName] --tool grype
if ($LASTEXITCODE -ne 0) {
    Fail "ashx dependencies install --tool grype through the installed package failed (assert_dependencies_install.py exit $LASTEXITCODE)"
}

Write-Step '9. a same-version reinstall keeps the venv'
# The MSIX equivalent of the rpm script's %postun check, and the other half of step 6: the
# launcher must rebuild when the wheel changes and must NOT rebuild when it does not. A
# reinstall that discarded the venv would cost every user a full dependency download.
$keep = Join-Path $venv 'e2e-reinstall-sentinel.txt'
Set-Content -LiteralPath $keep -Value 'written before a same-version reinstall'
Add-AppxPackage -Path $msix -ForceUpdateFromAnyVersion -ErrorAction Stop
& $resolved[$cliName] --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail "$cliName --version exited $LASTEXITCODE after a reinstall"
}
if (-not (Test-Path $keep)) {
    Fail 'the venv was rebuilt by a same-version reinstall; it should have been kept'
}
Write-Host "   OK: venv kept, $cliName still runs"

Write-Step '10. uninstall reclaims the package, the venv and the aliases'
Remove-AshPackage
if (Get-InstalledAsh) {
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
$leftovers = @(Get-AliasLeftover)
if ($leftovers.Count -ne 0) {
    Fail "app execution aliases survived uninstall: $($leftovers -join ', ') in $windowsApps"
}
Write-Host '   OK: package, venv and aliases removed'

Write-Host ''
Write-Host 'MSIX VERIFICATION PASSED'
if (-not $script:aliasesWork) {
    Write-Host 'with one caveat: app execution aliases were not available on this host, so the'
    Write-Host 'three names were exercised through the packaged executables instead. See step 5.'
}
