# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
The Chocolatey channel end to end: build N and N-1, install, scan, upgrade, uninstall,
and show each gate failing.

.DESCRIPTION
The Windows counterpart of packaging/deb/verify-in-container.sh and
packaging/rpm/verify-in-container.sh, held to the e2e bar in tests/e2e/README.md:

  1-3   Build the package from the wheel the build job made from this commit, assert
        its metadata, count the bundled wheels (exactly one), run the
        package-contents gate on the .nupkg, and require it to refuse a copy with a
        scanner binary planted in it (packaging/assert-planted-scanner-rejected.py).
  3c    Build an N-1 package from E2E_PREV_REF's tree (scripts/e2e/prev_tree.py), with
        its version lowered, using that tree's own build.ps1 and install scripts, so
        the upgrade crosses a real code change and runs the new install script over a
        real old install.
  4-5   Install N fresh, require Chocolatey to have resolved the python3 dependency,
        and require exactly the shims the package promises, each resolving under the
        Chocolatey bin directory and printing N's version.
  6     Run the three cases in tests/e2e/fixtures/cases.json through
        scripts/e2e/run_case.py against the installed shim: findings (exit 2, 3
        findings), clean (exit 0) and incomplete (exit 1, opengrep MISSING). The
        verdict is scripts/e2e/assert_outcome.py, the one every channel uses.
  7     Negative controls on the verdicts: a findings scan with --no-fail-on-findings
        must be rejected for its exit code, a clean output judged as a findings
        outcome must be rejected, and the uninstall check must fail while ASH is
        installed.
  7b    As a local account in Users and nothing else, `ashx dependencies install --tool
        grype` through the installed shim: grype lands in that user's ~\.ash\bin with a
        receipt matching this ASH's pin, runs, and `--tool <unknown>` exits
        EXIT_BAD_SELECTION (scripts/e2e/assert_dependencies_install.py).
  8     Uninstall, and require the venv, every shim and the package record gone.
  9-10  Install N-1, scan with it, plant a sentinel in its venv, show the version and
        rebuild checks rejecting N-1, then `choco upgrade` to N and require N's
        version, a rebuilt venv, N's shim set (the N-1 `ash` shim removed) and a
        passing scan.
  11    Uninstall again.
  12    Negative control on the install leg: a package whose chocolateyinstall.ps1
        exits 1 must make `choco install` fail, for that reason, and leave nothing
        installed.

Where this falls short of the deb and rpm scripts, stated rather than implied: those
two build inside a container that starts with neither an interpreter nor pip, which is
what makes the package's own dependency declaration load-bearing. A GitHub Actions
windows runner cannot be stripped that way; its image ships Python on PATH. So this
script does not prove that the python3 dependency is what provides the interpreter. It
asserts instead that Chocolatey resolved and installed that dependency, which catches
a dependency nothing can satisfy without pretending the host was bare.

Needs choco, git, and uv on PATH. uv runs the e2e harness and builds the N-1 wheel.

.PARAMETER Repo
Repository root. Defaults to two directories above this script.

.PARAMETER OutDir
Where to write the built N .nupkg.

.PARAMETER Work
Scratch directory for N-1, the scans and the negative-control package. Replaced.

.PARAMETER PrevRef
The git ref N-1 is built from. Defaults to $env:E2E_PREV_REF, then `auto`: the newest
release tag, else the newest ancestor of HEAD, that differs from HEAD and carries
packaging/chocolatey (scripts/e2e/prev_tree.py). `auto` names no branch, so it keeps
working once the branch this channel was developed on is merged and deleted. A named
ref with HEAD's tree falls back to HEAD's first parent.
#>
[CmdletBinding()]
param(
    [string] $Repo,
    [string] $OutDir,
    [string] $Work,
    [string] $PrevRef
)

$ErrorActionPreference = 'Stop'

# PowerShell 7.4 turned $PSNativeCommandUseErrorActionPreference on by default, so with
# $ErrorActionPreference = 'Stop' a native command that exits nonzero throws. That is
# wrong for this script in a way that would look like a packaging failure: `ashx scan`
# exits nonzero when it FINDS something, and several steps below require a native
# command to fail. GitHub Actions also prepends $ErrorActionPreference = 'stop' to
# every `shell: pwsh` step, so the default cannot be left to chance here.
#
# Turning it off means every native exit code has to be read deliberately, which is what
# Assert-NativeSuccess is for. The variable does not exist in Windows PowerShell 5.1 or
# in pwsh before 7.3; assigning it there is a harmless no-op.
$PSNativeCommandUseErrorActionPreference = $false

function Assert-NativeSuccess {
    param(
        [Parameter(Mandatory = $true)][string] $What,
        [Parameter(Mandatory = $true)][AllowNull()][int] $ExitCode
    )
    if ($ExitCode -ne 0) {
        throw "$What failed with exit code $ExitCode."
    }
}

# Fail-Verification rather than `throw` for the assertions, so a failure prints the
# reason as the last thing in the log instead of a PowerShell stack trace that buries
# it. Matches how the shell scripts print "FAIL: ..." and exit 1.
function Fail-Verification {
    param([Parameter(Mandatory = $true)][string[]] $Message)
    foreach ($line in $Message) { Write-Host "   FAIL: $line" }
    exit 1
}

function Fail-IfProblems {
    param([string] $What, [AllowEmptyCollection()][string[]] $Problems)
    if ($Problems.Count -ne 0) {
        Fail-Verification (@("$What`:") + @($Problems | ForEach-Object { "  $_" }))
    }
}

if (-not $Repo) { $Repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path }
if (-not $OutDir) { $OutDir = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-choco-out' }
if (-not $Work) { $Work = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-choco-e2e' }
if (-not $PrevRef) { $PrevRef = if ($env:E2E_PREV_REF) { $env:E2E_PREV_REF } else { 'auto' } }
if (Test-Path -LiteralPath $Work) { Remove-Item -LiteralPath $Work -Recurse -Force }
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$Work = (Resolve-Path -LiteralPath $Work).Path

# The v4 command name comes from the one file the PowerShell and Python e2e scripts
# share, so the rename that produced it is a one-line change for every channel.
$cli = (Get-Content -LiteralPath (Join-Path $Repo 'scripts\e2e\cli_name.json') -Raw | ConvertFrom-Json).cli_name
if (-not $cli) { Fail-Verification 'scripts/e2e/cli_name.json names no cli_name' }
# The console scripts this package shims. The wheel also declares the deprecated `ash`,
# which this package must never put on PATH; see chocolateyinstall.ps1.
$expectedShims = @($cli, 'ashv3', 'automated-security-helper')
$allShimNames = @($expectedShims + @('ash'))

$chocoBin = Join-Path $env:ChocolateyInstall 'bin'
$ashHome = Join-Path $env:ProgramData 'ash'
$venvDir = Join-Path $ashHome 'venv'
$venvPython = Join-Path $venvDir 'Scripts\python.exe'
$shimList = Join-Path $ashHome 'installed-shims.txt'
$sentinel = Join-Path $venvDir 'e2e-upgrade-sentinel.txt'
$communityFeed = 'https://community.chocolatey.org/api/v2/'

# The harness runs under uv's interpreter, never under the venv being tested: the
# uninstall checks have to be able to judge a machine that no longer holds ASH.
# Output goes to two files and is echoed, so a caller can search it. Two separate
# redirections rather than `2>&1`: merging a native command's stderr into the success
# stream makes PowerShell wrap those lines as ErrorRecords, which under
# $ErrorActionPreference = 'Stop' terminates the script on a progress line.
$script:harnessSeq = 0
function Invoke-Harness {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)
    $script:harnessSeq++
    $out = Join-Path $Work ("harness-{0:d2}.out.log" -f $script:harnessSeq)
    $err = Join-Path $Work ("harness-{0:d2}.err.log" -f $script:harnessSeq)
    & uv run --no-project --python 3.12 python @Arguments > $out 2> $err
    $rc = $LASTEXITCODE
    Get-Content -LiteralPath $out -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "   $_" }
    Get-Content -LiteralPath $err -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "   [stderr] $_" }
    $text = ((Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue) + '') +
        ((Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue) + '')
    return [pscustomobject]@{ Rc = $rc; Out = (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue); Text = $text }
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)][string] $Cli,
        [Parameter(Mandatory = $true)][string] $Case,
        [Parameter(Mandatory = $true)][string] $Label,
        [string[]] $Extra = @(),
        # A negative control: its rejection prints as plain lines, not as error
        # annotations on a green run. The exit code is unchanged and still judged.
        [switch] $ExpectReject
    )
    $arguments = @(
        (Join-Path $Repo 'scripts\e2e\run_case.py'),
        '--cli', $Cli, '--case', $Case, '--work', (Join-Path $Work 'scans'), '--label', $Label
    )
    if ($ExpectReject) { $arguments += '--expect-reject' }
    if ($Extra.Count -gt 0) { $arguments += @('--') + $Extra }
    return Invoke-Harness -Arguments $arguments
}

# Every choco call that resolves a package gets its own download cache, so a package
# cached by an earlier call can never stand in for the one a later call names. The
# negative-control package below has N's id and version on purpose.
$script:chocoSeq = 0
function Invoke-Choco {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)
    $script:chocoSeq++
    $cache = Join-Path $Work ("choco-cache-{0:d2}" -f $script:chocoSeq)
    # Captured into a variable and filtered afterwards, NOT piped straight into
    # `Select-Object -First`. `-First` stops the upstream pipeline as soon as it has
    # enough items, and upstream here is choco: it would kill the installer partway
    # through, and the symptom would be a half-installed package with no error.
    $log = @(choco @Arguments --yes --no-progress --cache-location $cache)
    $rc = $LASTEXITCODE
    $log |
        Select-String -Pattern 'Installing|Upgrading|upgraded|python3|Chocolatey installed|Chocolatey uninstalled|ash:|ERROR|WARNING|not successful|e2e negative' |
        Select-Object -First 40 |
        ForEach-Object { Write-Host "   $_" }
    return [pscustomobject]@{ Rc = $rc; Text = ($log -join "`n") }
}

function Get-InstalledVersion {
    param([Parameter(Mandatory = $true)][string] $Id)
    $rows = @(choco list --limit-output)
    Assert-NativeSuccess -What 'choco list' -ExitCode $LASTEXITCODE
    $row = @($rows | Where-Object { $_ -match "^$([regex]::Escape($Id))\|" })
    if ($row.Count -eq 0) { return $null }
    return ($row[0] -split '\|', 2)[1].Trim()
}

function Read-Nupkg {
    param([Parameter(Mandatory = $true)][string] $Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName })
        $reader = New-Object System.IO.StreamReader($zip.GetEntry('ash.nuspec').Open())
        try { [xml] $packed = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally {
        $zip.Dispose()
    }
    return [pscustomobject]@{ Entries = $entries; Meta = $packed.package.metadata }
}

# The installed state N must be in. Returns the problems rather than failing, so the
# same check can be required to FAIL against N-1 before the upgrade.
function Get-InstallProblems {
    param([Parameter(Mandatory = $true)][string] $Version)
    $problems = New-Object System.Collections.Generic.List[string]
    $installed = Get-InstalledVersion -Id 'ash'
    if ($installed -ne $Version) { $problems.Add("choco reports ash $installed installed, expected $Version") }
    if (-not (Test-Path -LiteralPath $venvPython)) {
        $problems.Add("$venvPython does not exist")
        return $problems.ToArray()
    }
    # No double quotes inside the -c argument: how those survive the trip to a native
    # command depends on $PSNativeCommandArgumentPassing, which differs across pwsh
    # releases.
    $venvVersion = (& $venvPython -I -c "import importlib.metadata as m; print(m.version('automated-security-helper'))" 2>$null) -join ''
    if ($LASTEXITCODE -ne 0 -or $venvVersion.Trim() -ne $Version) {
        $problems.Add("the venv holds automated-security-helper '$($venvVersion.Trim())', expected $Version")
    }
    $recorded = @()
    if (Test-Path -LiteralPath $shimList) {
        $recorded = @(Get-Content -LiteralPath $shimList | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Sort-Object)
    }
    $want = @($expectedShims | Sort-Object)
    if (($recorded -join ',') -ne ($want -join ',')) {
        $problems.Add("$shimList records [$($recorded -join ', ')], expected [$($want -join ', ')]")
    }
    # The wheel declares `ash`, and this package must not shim it: MSYS2 and Git for
    # Windows ship the Almquist shell under that name, which is why the v4 command is
    # `ashx`. An upgrade from a package that did shim it has to take it away.
    if (Test-Path -LiteralPath (Join-Path $chocoBin 'ash.exe')) {
        $problems.Add("an ash shim exists at $(Join-Path $chocoBin 'ash.exe'); this package must not expose ash")
    }
    foreach ($name in $expectedShims) {
        $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cmd) { $problems.Add("$name is not on PATH"); continue }
        if (-not $cmd.Source.StartsWith($chocoBin, [StringComparison]::OrdinalIgnoreCase)) {
            # A different program by this name earlier on PATH would make every check
            # below measure someone else's program.
            $problems.Add("$name resolves to $($cmd.Source), not to a shim under $chocoBin")
            continue
        }
        $stderrFile = Join-Path $Work "version-$name.err.txt"
        $stdout = (& $cmd.Source --version 2> $stderrFile) -join ' '
        $rc = $LASTEXITCODE
        $stderrText = ((Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue) + '').Trim()
        Write-Host "   $name --version -> $($stdout.Trim())"
        if ($rc -ne 0) { $problems.Add("$name --version exited $rc"); continue }
        if ($stdout -notmatch "v$([regex]::Escape($Version))\b") {
            $problems.Add("$name --version printed '$($stdout.Trim())', expected v$Version")
        }
        if ($name -eq 'ashv3') {
            if ($stderrText.Length -eq 0) { $problems.Add('ashv3 printed no deprecation warning on stderr') }
        } elseif ($stderrText.Length -ne 0) {
            $problems.Add("$name wrote to stderr, and only ashv3 is deprecated: $stderrText")
        }
    }
    return $problems.ToArray()
}

# The state a full uninstall must leave. Also required to FAIL while ASH is installed.
function Get-AbsenceProblems {
    $problems = New-Object System.Collections.Generic.List[string]
    $installed = Get-InstalledVersion -Id 'ash'
    if ($installed) { $problems.Add("choco still reports ash $installed installed") }
    if (Test-Path -LiteralPath $ashHome) { $problems.Add("$ashHome exists") }
    foreach ($name in $allShimNames) {
        $shim = Join-Path $chocoBin "$name.exe"
        if (Test-Path -LiteralPath $shim) { $problems.Add("the $name shim exists at $shim") }
    }
    return $problems.ToArray()
}

# An upgrade must rebuild the venv, not patch the old one in place. The sentinel is
# planted in the N-1 venv; it must be gone afterwards.
function Get-RebuildProblems {
    $problems = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $sentinel) { $problems.Add("$sentinel survived, so the venv was not rebuilt") }
    if (-not (Test-Path -LiteralPath (Join-Path $venvDir 'pyvenv.cfg'))) { $problems.Add("$venvDir has no pyvenv.cfg") }
    return $problems.ToArray()
}

# ------------------------------------------------------------------------------------------
# An unprivileged user, for `ashx dependencies install` (step 7b).
#
# This package installs machine-wide, under ProgramData, from an elevated shell. The person
# who then selects a scanner is usually not an administrator, and their install goes to
# their own ~\.ash\bin. Running that step as the runner's account would prove nothing about
# it: on hosted runners that account is an administrator with UAC off, so it can write
# anywhere. So step 7b creates a local account in Users and nothing else, proves from that
# account's own token that it is not an administrator, and runs the install as it.
# ------------------------------------------------------------------------------------------

# Through ADSI's WinNT provider rather than the LocalAccounts cmdlets, which PowerShell 7
# may load through the Windows PowerShell compatibility layer and then hand back
# deserialized objects. And not `net user`, which would put the password on a command line.
function New-StandardUser {
    param([Parameter(Mandatory = $true)][string] $Name)
    $computer = [ADSI] "WinNT://$env:COMPUTERNAME,computer"
    if ([ADSI]::Exists("WinNT://$env:COMPUTERNAME/$Name,user")) {
        $computer.Delete('User', $Name) | Out-Null
    }
    # A random password, never printed and never written anywhere; the account lives for
    # this step only. The suffix covers the complexity policy whatever the random part
    # happens to contain.
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $plain = [Convert]::ToBase64String($bytes) + 'a1!A'
    $account = $computer.Create('User', $Name)
    # Out-Null on each COM call, so no return value leaks into this function's output.
    $account.SetPassword($plain) | Out-Null
    $account.Put('Description', 'ASH e2e: an unprivileged user for ashx dependencies install') | Out-Null
    # Not "must change password at next logon", which would refuse the logon below.
    $account.Put('PasswordExpired', 0) | Out-Null
    $account.SetInfo() | Out-Null
    # Users (S-1-5-32-545), by SID because the group's name is localized. It carries the
    # right to log on locally, which the logon below needs.
    $usersGroup = ([System.Security.Principal.SecurityIdentifier] 'S-1-5-32-545').Translate(
        [System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    $group = [ADSI] "WinNT://$env:COMPUTERNAME/$usersGroup,group"
    if (-not $group.IsMember("WinNT://$env:COMPUTERNAME/$Name")) {
        $group.Add("WinNT://$env:COMPUTERNAME/$Name,user") | Out-Null
    }
    $sid = ([System.Security.Principal.NTAccount] "$env:COMPUTERNAME\$Name").Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    $plain = $null
    return [pscustomobject]@{ Name = $Name; Password = $secure; Sid = $sid }
}

# By name, not by the object New-StandardUser returns, so it also cleans up after a
# New-StandardUser that failed partway (account created, group or SID step failed) and
# returned nothing. Removing an account that does not exist is a no-op.
function Remove-StandardUser {
    param([Parameter(Mandatory = $true)][string] $Name)
    if (-not [ADSI]::Exists("WinNT://$env:COMPUTERNAME/$Name,user")) {
        return
    }
    $sid = ([System.Security.Principal.NTAccount] "$env:COMPUTERNAME\$Name").Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $sid } |
        Remove-CimInstance -ErrorAction SilentlyContinue
    ([ADSI] "WinNT://$env:COMPUTERNAME,computer").Delete('User', $Name) | Out-Null
}

# Runs one command as $User and returns its exit code and output.
#
# System.Diagnostics.Process with UserName, which is CreateProcessWithLogonW, and with
# LoadUserProfile, so the child gets that user's profile. Its Environment is deliberately
# never touched: then .NET passes no environment block, and Windows builds the child's from
# the user's own profile, so USERPROFILE, TEMP and PATH are the user's, as they would be in
# their shell. Copying this process's environment would point the child at the runner
# account's home, and the install would be measuring that account's directory again.
function Invoke-AsStandardUser {
    param(
        [Parameter(Mandatory = $true)] $User,
        [Parameter(Mandatory = $true)][string] $FilePath,
        [Parameter(Mandatory = $true)][string[]] $ArgumentList,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $FilePath
    foreach ($argument in $ArgumentList) { $info.ArgumentList.Add($argument) }
    $info.UserName = $User.Name
    $info.Domain = $env:COMPUTERNAME
    $info.Password = $User.Password
    $info.LoadUserProfile = $true
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.WorkingDirectory = $WorkingDirectory
    Write-Host "   as $($User.Name): $FilePath $($ArgumentList -join ' ')"
    try {
        $process = [System.Diagnostics.Process]::Start($info)
    } catch {
        Fail-Verification @(
            "could not start a process as $($User.Name): $($_.Exception.Message)",
            'This is CreateProcessWithLogonW. It needs the Secondary Logon service and the',
            "account's right to log on locally, which Users holds by default."
        )
    }
    # Both streams drained concurrently, or a child that fills one pipe while this waits on
    # the other never exits.
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(1200000)) {
        $process.Kill($true)
        Fail-Verification "$FilePath did not finish within 20 minutes as $($User.Name)"
    }
    $process.WaitForExit()
    $out = $stdout.Result
    $text = $out + $stderr.Result
    $text -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host "   $_" }
    return [pscustomobject]@{ Rc = $process.ExitCode; Out = $out; Text = $text }
}

Write-Host '== 0. the e2e verdict can fail'
$r = Invoke-Harness -Arguments @((Join-Path $Repo 'scripts\e2e\assert_outcome.py'), '--self-test')
Assert-NativeSuccess -What 'assert_outcome.py --self-test' -ExitCode $r.Rc

Write-Host '== 1. toolchain'
# Deliberately does not install Python. See the .DESCRIPTION note above: the runner
# image already has one, so installing another here would only add noise. The point of
# the python3 dependency is checked at step 4 by asking Chocolatey what it installed.
choco --version | ForEach-Object { Write-Host "   choco $_" }
Assert-NativeSuccess -What 'choco --version' -ExitCode $LASTEXITCODE
uv --version | ForEach-Object { Write-Host "   $_" }
Assert-NativeSuccess -What 'uv --version' -ExitCode $LASTEXITCODE
if (Get-InstalledVersion -Id 'ash') { Fail-Verification 'ash is already installed; this leg needs a fresh machine' }

Write-Host '== 2. build the package from the wheel the build job made from this commit'
$wheel = Get-ChildItem -LiteralPath (Join-Path $Repo 'dist') -Filter '*.whl' -File -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $wheel) { Fail-Verification "no wheel in $(Join-Path $Repo 'dist')" }
Write-Host "   wheel: $($wheel.Name)"
$nupkg = & (Join-Path $PSScriptRoot 'build.ps1') $wheel.FullName $OutDir | Select-Object -Last 1
if (-not $nupkg -or -not (Test-Path -LiteralPath $nupkg)) { Fail-Verification 'build.ps1 produced no package' }
Write-Host "   built: $nupkg"

Write-Host '== 3. package metadata is well formed'
$packed = Read-Nupkg -Path $nupkg
$meta = $packed.Meta
$version = [string] $meta.version
Write-Host "   Id: $($meta.id)"
Write-Host "   Version: $version"
Write-Host "   Dependencies: $(($meta.dependencies.dependency | ForEach-Object { "$($_.id) $($_.version)" }) -join ', ')"

# The payload must be ASH's wheel and nothing else. The contents gate covers what is
# inside the wheel; this covers what the Chocolatey package adds around it. Phrased as
# a count for the reason packaging/README.md gives: a rule saying "no third-party
# wheels" would need a judgment call per dependency, and would be enforced by whoever
# reviewed the build script that day.
$payloadWheels = @($packed.Entries | Where-Object { $_ -like 'tools/wheels/*.whl' })
Write-Host "   wheels in package: $($payloadWheels.Count)"
if ($payloadWheels.Count -ne 1) {
    Fail-Verification @(
        "expected exactly 1 bundled wheel, found $($payloadWheels.Count).",
        'Bundling dependency wheels would put third-party scanner code in a',
        'published artifact. See packaging/README.md.'
    )
}
if ($version -ne ($wheel.Name -replace '^automated_security_helper-(.+)-py3-none-any\.whl$', '$1')) {
    Fail-Verification "packed version $version does not match the wheel $($wheel.Name)"
}

Write-Host '== 3b. the package-contents gate'
# packaging/assert-package-contents.py on the packed .nupkg: every member must be one
# build.ps1 stages or `choco pack` adds, none may be a binary, and the one wheel is handed
# to the gate the published wheel passes. The .nupkg checks are stdlib-only.
$r = Invoke-Harness -Arguments @((Join-Path $Repo 'packaging\assert-package-contents.py'), $nupkg)
Assert-NativeSuccess -What 'packaging/assert-package-contents.py' -ExitCode $r.Rc

Write-Host '== 3b2. negative control: the gate must refuse this package with a scanner planted in it'
# The gate's --self-test proves each check can fail on fixtures shaped like this package.
# This proves it on the .nupkg just packed: a copy with tools/grype.exe (a native PE
# image) added must be refused with the native-binary verdict on that member, and the
# unmodified package must pass. The copy is written under $Work, never $OutDir.
$r = Invoke-Harness -Arguments @((Join-Path $Repo 'packaging\assert-planted-scanner-rejected.py'), $nupkg, '--work', (Join-Path $Work 'planted'))
if ($r.Rc -ne 0) {
    Fail-Verification "NEGATIVE CONTROL: packaging/assert-planted-scanner-rejected.py exited $($r.Rc) on $nupkg; the gate did not refuse the real package with a scanner planted in it"
}

Write-Host "== 3c. build N-1 from $PrevRef"
# N-1 is the older tree's own wheel, nuspec and install scripts, packed by its own
# build.ps1. Only the version literals are lowered, in pyproject.toml by
# prev_tree.py and in the nuspec here, because build.ps1 refuses a nuspec whose version
# differs from the wheel's. The N-1 version was never released, so neither the wheel
# nor the package ever leaves $Work.
$prevWork = Join-Path $Work 'prev'
$r = Invoke-Harness -Arguments @((Join-Path $Repo 'scripts\e2e\prev_tree.py'), '--repo', $Repo, '--prev-ref', $PrevRef, '--require', 'packaging/chocolatey/ash.nuspec', '--require', 'packaging/chocolatey/build.ps1', '--out', $prevWork)
Assert-NativeSuccess -What 'scripts/e2e/prev_tree.py' -ExitCode $r.Rc
$prev = ($r.Out.Trim() -split "`n" | Select-Object -Last 1) | ConvertFrom-Json
if ($prev.head_version -ne $version) {
    Fail-Verification "pyproject.toml says $($prev.head_version) but the package is $version"
}
$prevVersion = [string] $prev.prev_version
$prevNuspec = Join-Path $prev.src 'packaging\chocolatey\ash.nuspec'
$prevBuild = Join-Path $prev.src 'packaging\chocolatey\build.ps1'
if (-not (Test-Path -LiteralPath $prevNuspec) -or -not (Test-Path -LiteralPath $prevBuild)) {
    Fail-Verification "$($prev.prev_ref) ($($prev.prev_sha)) has no packaging/chocolatey to build N-1 from"
}
$nuspecDoc = New-Object System.Xml.XmlDocument
$nuspecDoc.PreserveWhitespace = $true
$nuspecDoc.Load($prevNuspec)
if ($nuspecDoc.package.metadata.version -ne $prev.prev_base_version) {
    Fail-Verification "the N-1 nuspec declares $($nuspecDoc.package.metadata.version), expected $($prev.prev_base_version)"
}
$nuspecDoc.package.metadata.version = $prevVersion
# Written without a BOM, as the checked-in nuspec is, so the only byte that differs is
# the version.
[System.IO.File]::WriteAllText($prevNuspec, $nuspecDoc.OuterXml, (New-Object System.Text.UTF8Encoding $false))

$prevDist = Join-Path $Work 'prev-dist'
& uv build --quiet --wheel --out-dir $prevDist $prev.src
Assert-NativeSuccess -What 'uv build (N-1)' -ExitCode $LASTEXITCODE
$prevWheel = Join-Path $prevDist "automated_security_helper-$prevVersion-py3-none-any.whl"
if (-not (Test-Path -LiteralPath $prevWheel)) { Fail-Verification "uv build did not write $prevWheel" }
$r = Invoke-Harness -Arguments @((Join-Path $Repo '.github\scripts\assert-artifact-contents.py'), $prevWheel)
Assert-NativeSuccess -What 'assert-artifact-contents.py (N-1 wheel)' -ExitCode $r.Rc
$prevOut = Join-Path $Work 'prev-out'
$prevNupkg = & $prevBuild $prevWheel $prevOut | Select-Object -Last 1
if (-not $prevNupkg -or -not (Test-Path -LiteralPath $prevNupkg)) { Fail-Verification 'the N-1 build.ps1 produced no package' }
if ([string] (Read-Nupkg -Path $prevNupkg).Meta.version -ne $prevVersion) {
    Fail-Verification "$prevNupkg does not declare version $prevVersion"
}
Write-Host "   N = $version, N-1 = $prevVersion from $($prev.prev_ref) ($($prev.prev_sha))"

Write-Host '== 4. install N fresh, and let Chocolatey resolve the python3 dependency'
# The local directory first, then the community feed, so the ash package resolves to
# the one just built and its python3 dependency resolves to the published one. This
# downloads a third-party package; it does not publish anything.
$r = Invoke-Choco -Arguments @('install', 'ash', '--version', $version, '--source', "$OutDir;$communityFeed")
Assert-NativeSuccess -What 'choco install ash' -ExitCode $r.Rc

# Proof that the declared dependency was satisfiable, which is the property the
# nuspec's version range asserts.
$python3 = Get-InstalledVersion -Id 'python3'
if (-not $python3) {
    Fail-Verification @(
        'Chocolatey did not install the python3 dependency.',
        'The nuspec declares python3 [3.10,3.14); if no published version falls in',
        'that range the install would still appear to succeed on this runner, because',
        'the image already has Python on PATH.'
    )
}
Write-Host "   python3 dependency Chocolatey installed: $python3"

Write-Host '== 5. exactly the promised shims are on PATH and run as N'
#   ashx                       canonical.
#   ashv3                      deprecated, warns once on stderr, still works.
#   automated-security-helper  kept indefinitely and silent; the escape hatch for hosts
#                              where a short name resolves to something else.
# They are required by name here, not read back from the wheel: chocolateyinstall.ps1
# derives the shim set from the wheel's metadata, and if that derivation ever drops or
# adds a name, this is what notices.
Fail-IfProblems 'the fresh install of N is wrong' (Get-InstallProblems -Version $version)
# -V and not -v. -v is --verbose and has been for all of v3.
$shortForm = & (Join-Path $chocoBin "$cli.exe") -V
Assert-NativeSuccess -What "$cli -V" -ExitCode $LASTEXITCODE
Write-Host "   $cli -V -> $(($shortForm -join ' ').Trim())"
Write-Host '   OK'

$shim = Join-Path $chocoBin "$cli.exe"

Write-Host '== 6. the three e2e cases, exit 2, 0 and 1'
foreach ($case in @('findings', 'clean', 'incomplete')) {
    $r = Invoke-Case -Cli $shim -Case $case -Label "fresh-$case"
    if ($r.Rc -ne 0) { Fail-Verification "the $case case did not match tests/e2e/fixtures/cases.json (run_case exit $($r.Rc))" }
}

Write-Host '== 7. negative controls on the verdicts'
Write-Host '   a findings scan with --no-fail-on-findings must be rejected for its exit code'
$r = Invoke-Case -Cli $shim -Case 'findings' -Label 'negative-no-fail-on-findings' -Extra @('--no-fail-on-findings') -ExpectReject
if ($r.Rc -ne 1) { Fail-Verification "NEGATIVE CONTROL: run_case returned $($r.Rc) for a findings scan that exited 0; expected 1" }
# rc 1 alone would also come from a missing report or a wrong count. The control only
# controls anything if the exit-code check is what fired.
if ($r.Text -notmatch [regex]::Escape('exit code 0 (nothing actionable), expected exactly 2')) {
    Fail-Verification 'NEGATIVE CONTROL: run_case rejected the --no-fail-on-findings scan, but not for its exit code 0'
}
Write-Host "   OK: rejected for exit code 0 (exit $($r.Rc))"

Write-Host '   the clean output judged as a findings outcome must be rejected'
$r = Invoke-Harness -Arguments @(
    (Join-Path $Repo 'scripts\e2e\assert_outcome.py'),
    '--output-dir', (Join-Path $Work 'scans\fresh-clean\out'), '--rc', '0',
    '--expect-rc', '2', '--min-findings', '1', '--require-scanner', 'detect-secrets', '--selected', 'detect-secrets', '--expect-reject'
)
if ($r.Rc -ne 1) { Fail-Verification "NEGATIVE CONTROL: assert_outcome returned $($r.Rc) on a clean output expected to hold findings" }
# For its exit code: under --expect-reject the problems are plain lines, so an rc of 1 for
# some other reason would otherwise pass unnoticed.
if ($r.Text -notmatch [regex]::Escape('[expect-rc 2] exit code 0 (nothing actionable), expected exactly 2')) {
    Fail-Verification 'NEGATIVE CONTROL: assert_outcome rejected the clean output, but not for its exit code 0'
}
Write-Host "   OK: rejected for exit code 0 (exit $($r.Rc))"

Write-Host '   the uninstall check must fail while ASH is installed'
$p = @(Get-AbsenceProblems)
if ($p.Count -eq 0) { Fail-Verification 'NEGATIVE CONTROL: the uninstall check passed on a machine that still holds ASH' }
Write-Host "   OK: rejected ($($p.Count) problem(s), first: $($p[0]))"

Write-Host '== 7b. an unprivileged user selects a scanner: ashx dependencies install --tool grype'
# No package bundles a scanner; a user selects one after installing (README.chocolatey).
# scripts/e2e/assert_dependencies_install.py runs under the installed venv's interpreter, as
# that user, through the shim on PATH: it requires nothing installed yet, the install to
# exit 0, grype at that user's ~\.ash\bin with a receipt recording this ASH's pinned
# version and archive SHA-256 and the binary's own hash, `grype version` to name the pin,
# and `--tool <unknown>` to exit EXIT_BAD_SELECTION. That last one is the negative control.
# The account is created inside try and removed by name in finally, together with its
# directory, so neither a failed check nor a New-StandardUser that failed partway leaves
# them behind. PowerShell runs a finally block when exit leaves the try block.
$standardUserName = 'ashe2estd'
$userWork = Join-Path $env:SystemDrive 'ash-e2e-standard-user'
try {
    $standardUser = New-StandardUser -Name $standardUserName
    if (Test-Path -LiteralPath $userWork) { Remove-Item -LiteralPath $userWork -Recurse -Force }
    New-Item -ItemType Directory -Path $userWork | Out-Null
    & icacls.exe $userWork /grant "$($standardUser.Name):(OI)(CI)M" | Out-Null
    Assert-NativeSuccess -What "icacls $userWork" -ExitCode $LASTEXITCODE
    # A copy the user can read. The checkout lives under the runner account's directories.
    $depsScript = Join-Path $userWork 'assert_dependencies_install.py'
    Copy-Item -LiteralPath (Join-Path $Repo 'scripts\e2e\assert_dependencies_install.py') -Destination $depsScript

    # Proof from the account's own token, not from the group list it was created with: a token
    # carrying BUILTIN\Administrators (S-1-5-32-544), even filtered, would make this an
    # administrator's install again.
    $r = Invoke-AsStandardUser -User $standardUser -FilePath (Join-Path $env:SystemRoot 'System32\whoami.exe') `
        -ArgumentList @('/groups', '/fo', 'csv') -WorkingDirectory $userWork
    Assert-NativeSuccess -What "whoami /groups as $($standardUser.Name)" -ExitCode $r.Rc
    if ($r.Text -match 'S-1-5-32-544') {
        Fail-Verification "$($standardUser.Name)'s token carries BUILTIN\Administrators, so it is not an unprivileged user"
    }
    if ($r.Text -notmatch 'S-1-5-32-545') {
        Fail-Verification "$($standardUser.Name)'s token does not carry BUILTIN\Users; the logon is not the one intended"
    }
    Write-Host "   OK: $($standardUser.Name)'s token has Users and not Administrators"

    $r = Invoke-AsStandardUser -User $standardUser -FilePath $venvPython `
        -ArgumentList @('-I', $depsScript, '--cli', (Join-Path $chocoBin "$cli.exe"), '--tool', 'grype') `
        -WorkingDirectory $userWork
    if ($r.Rc -ne 0) {
        Fail-Verification "ashx dependencies install --tool grype as the unprivileged user $($standardUser.Name) failed (assert_dependencies_install.py exit $($r.Rc))"
    }
    $installedTool = ($r.Out.Trim() -split "`r?`n" | Select-Object -Last 1) | ConvertFrom-Json
    # The install went to that user's home and the file is theirs, which is what makes this an
    # unprivileged install and not the runner account's.
    if ($installedTool.home -ieq $HOME -or -not $installedTool.binary.StartsWith($installedTool.home, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-Verification "grype landed at $($installedTool.binary), not under $($standardUser.Name)'s home $($installedTool.home)"
    }
    $owner = (Get-Acl -LiteralPath $installedTool.binary).Owner
    if ($owner -notlike "*\$($standardUser.Name)") {
        Fail-Verification "$($installedTool.binary) is owned by $owner, not by $($standardUser.Name)"
    }
    Write-Host "   OK: $($installedTool.tool) $($installedTool.version) at $($installedTool.binary), owned by $owner"
} finally {
    Remove-StandardUser -Name $standardUserName
    if (Test-Path -LiteralPath $userWork) { Remove-Item -LiteralPath $userWork -Recurse -Force }
}

Write-Host '== 8. uninstall drops the venv, the shims and the package record'
$r = Invoke-Choco -Arguments @('uninstall', 'ash')
Assert-NativeSuccess -What 'choco uninstall ash' -ExitCode $r.Rc
Fail-IfProblems 'the uninstall left ASH behind' (Get-AbsenceProblems)
Write-Host '   OK'

Write-Host "== 9. install N-1 ($prevVersion)"
$r = Invoke-Choco -Arguments @('install', 'ash', '--version', $prevVersion, '--source', "$prevOut;$communityFeed")
Assert-NativeSuccess -What "choco install ash $prevVersion" -ExitCode $r.Rc
if ((Get-InstalledVersion -Id 'ash') -ne $prevVersion) { Fail-Verification "choco does not report ash $prevVersion installed" }
# N-1 may predate the $cli command. automated-security-helper is the name every version
# of this package has shimmed.
$prevShim = Join-Path $chocoBin "$cli.exe"
if (-not (Test-Path -LiteralPath $prevShim)) { $prevShim = Join-Path $chocoBin 'automated-security-helper.exe' }
if (-not (Test-Path -LiteralPath $prevShim)) { Fail-Verification "N-1 shimmed neither $cli nor automated-security-helper" }
Write-Host "   N-1 command: $(Split-Path -Leaf $prevShim)"
$r = Invoke-Case -Cli $prevShim -Case 'findings' -Label 'upgrade-before'
if ($r.Rc -ne 0) { Fail-Verification "the findings case failed on N-1 (run_case exit $($r.Rc))" }
Set-Content -LiteralPath $sentinel -Encoding ASCII -Value 'planted in the N-1 venv; an upgrade must rebuild the venv'

Write-Host '   negative control: the N install check must reject N-1'
$p = @(Get-InstallProblems -Version $version)
if (-not ($p | Where-Object { $_ -like "choco reports ash $prevVersion installed, expected $version" })) {
    Fail-Verification (@('NEGATIVE CONTROL: the install check did not reject N-1 for its version. It reported:') + $p)
}
Write-Host "   OK: rejected ($($p.Count) problem(s))"
Write-Host '   negative control: the rebuild check must reject the N-1 venv'
$p = @(Get-RebuildProblems)
if ($p.Count -eq 0) { Fail-Verification 'NEGATIVE CONTROL: the rebuild check passed on the venv it was planted in' }
Write-Host "   OK: rejected ($($p[0]))"

Write-Host "== 10. choco upgrade $prevVersion -> $version"
$r = Invoke-Choco -Arguments @('upgrade', 'ash', '--version', $version, '--source', "$OutDir;$communityFeed")
Assert-NativeSuccess -What 'choco upgrade ash' -ExitCode $r.Rc
Fail-IfProblems 'the upgraded install is wrong' (@(Get-InstallProblems -Version $version) + @(Get-RebuildProblems))
$r = Invoke-Case -Cli $shim -Case 'findings' -Label 'upgrade-after'
if ($r.Rc -ne 0) { Fail-Verification "the findings case failed after the upgrade (run_case exit $($r.Rc))" }
Write-Host "   OK: upgraded $prevVersion -> $version, venv rebuilt"

Write-Host '== 11. uninstall the upgraded package'
$r = Invoke-Choco -Arguments @('uninstall', 'ash')
Assert-NativeSuccess -What 'choco uninstall ash (after the upgrade)' -ExitCode $r.Rc
Fail-IfProblems 'the uninstall after the upgrade left ASH behind' (Get-AbsenceProblems)
Write-Host '   OK'

Write-Host '== 12. negative control: an install script that exits 1 must fail choco install'
# Same tree, same wheel, same id and version as N, with only chocolateyinstall.ps1
# replaced. Its own download cache (Invoke-Choco) keeps the good N from substituting.
$brokenSrc = Join-Path $Work 'broken-src'
Copy-Item -LiteralPath $PSScriptRoot -Destination $brokenSrc -Recurse
$marker = 'e2e negative control: this install script fails on purpose'
Set-Content -LiteralPath (Join-Path $brokenSrc 'tools\chocolateyinstall.ps1') -Encoding ASCII -Value @(
    "Write-Host '$marker'",
    'exit 1'
)
$brokenOut = Join-Path $Work 'broken-out'
$brokenNupkg = & (Join-Path $brokenSrc 'build.ps1') $wheel.FullName $brokenOut | Select-Object -Last 1
if (-not $brokenNupkg -or -not (Test-Path -LiteralPath $brokenNupkg)) { Fail-Verification 'the negative-control package was not built' }
$r = Invoke-Choco -Arguments @('install', 'ash', '--version', $version, '--source', "$brokenOut;$communityFeed")
if ($r.Rc -eq 0) { Fail-Verification 'NEGATIVE CONTROL: choco install reported success for a package whose install script exits 1' }
# A nonzero exit for some other reason (an unreachable source, a missing version) would
# prove nothing about the install leg. The marker shows the script ran and was the cause.
if ($r.Text -notmatch [regex]::Escape($marker)) {
    Fail-Verification "NEGATIVE CONTROL: choco install failed (exit $($r.Rc)), but the broken install script never ran"
}
Fail-IfProblems 'the failed install left something behind' (Get-AbsenceProblems)
Write-Host "   OK: choco install failed (exit $($r.Rc)) because the install script did"

Write-Host ''
Write-Host "CHOCOLATEY E2E PASSED: N=$version, N-1=$prevVersion ($($prev.prev_ref) $($prev.prev_sha))"
