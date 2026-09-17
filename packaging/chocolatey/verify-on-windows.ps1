# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
Builds the ASH Chocolatey package, installs it, runs a real scan, and uninstalls it.

.DESCRIPTION
The Windows counterpart of packaging/deb/verify-in-container.sh and
packaging/rpm/verify-in-container.sh, and held to the same bar: build the package in
the target environment, assert its metadata, count the bundled wheels and fail unless
there is exactly one, install it, put every declared entry point on PATH, scan a
fixture that contains a planted secret, parse the SARIF and fail unless the result
count is nonzero, then uninstall and fail if the venv survived.

The scan must report a finding. An empty ASH scan exits 0, so asserting exit 0 alone
would prove only that the command started.

Where this falls short of the deb and rpm scripts, stated rather than implied:

  * Those two build inside a container that starts with neither an interpreter nor
    pip, which is what makes the package's own dependency declaration load-bearing.
    A GitHub Actions windows runner cannot be stripped that way; its image ships
    Python 3.12.10 already on PATH. So this script does not prove that the python3
    dependency is what provides the interpreter. What it does instead is assert that
    Chocolatey actually resolved and installed the python3 dependency, which catches
    the failure that matters (a dependency nothing can satisfy) without pretending the
    host was bare.

  * There is no upgrade leg. The rpm script reinstalls to prove %postun's $1 guard,
    because rpm runs the old package's %postun after the new package's %post and an
    unguarded one deletes the venv the new install just built. Chocolatey has no
    equivalent ordering hazard: an upgrade runs the new chocolateyinstall.ps1, which
    rebuilds the venv from scratch, and the old chocolateyuninstall.ps1 is not run.

.PARAMETER Repo
Repository root. Defaults to two directories above this script.

.PARAMETER OutDir
Where to write the built .nupkg.
#>
[CmdletBinding()]
param(
    [string] $Repo,
    [string] $OutDir
)

$ErrorActionPreference = 'Stop'

# PowerShell 7.4 turned $PSNativeCommandUseErrorActionPreference on by default, so with
# $ErrorActionPreference = 'Stop' a native command that exits nonzero throws. That is
# wrong for this script in a way that would look like a packaging failure: `ash scan`
# exits nonzero when it FINDS something, which is the expected outcome at step 6, and
# the throw would happen before the SARIF was ever read. GitHub Actions also prepends
# $ErrorActionPreference = 'stop' to every `shell: pwsh` step, so the default cannot be
# left to chance here.
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

if (-not $Repo) { $Repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path }
if (-not $OutDir) { $OutDir = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-choco-out' }

Write-Host '== 1. toolchain'
# Deliberately does not install Python. See the .DESCRIPTION note above: the runner
# image already has one, so installing another here would only add noise. The point of
# the python3 dependency is checked at step 4 by asking Chocolatey what it installed.
choco --version | ForEach-Object { Write-Host "   choco $_" }
Assert-NativeSuccess -What 'choco --version' -ExitCode $LASTEXITCODE

Write-Host '== 2. build the package'
$wheel = Get-ChildItem -LiteralPath (Join-Path $Repo 'dist') -Filter '*.whl' -File -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $wheel) { Fail-Verification "no wheel in $(Join-Path $Repo 'dist')" }
Write-Host "   wheel: $($wheel.Name)"
$nupkg = & (Join-Path $PSScriptRoot 'build.ps1') $wheel.FullName $OutDir | Select-Object -Last 1
if (-not $nupkg -or -not (Test-Path -LiteralPath $nupkg)) { Fail-Verification 'build.ps1 produced no package' }
Write-Host "   built: $nupkg"

Write-Host '== 3. package metadata is well formed'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg)
try {
    $entries = @($zip.Entries | ForEach-Object { $_.FullName })
    $nuspecEntry = $zip.GetEntry('ash.nuspec')
    $reader = New-Object System.IO.StreamReader($nuspecEntry.Open())
    try { [xml] $packed = $reader.ReadToEnd() } finally { $reader.Dispose() }
} finally {
    $zip.Dispose()
}
$meta = $packed.package.metadata
Write-Host "   Id: $($meta.id)"
Write-Host "   Version: $($meta.version)"
Write-Host "   Dependencies: $(($packed.package.metadata.dependencies.dependency | ForEach-Object { "$($_.id) $($_.version)" }) -join ', ')"

# The payload must be ASH's wheel and nothing else. The contents gate covers what is
# inside the wheel; this covers what the Chocolatey package adds around it. Phrased as
# a count for the reason packaging/README.md gives: a rule saying "no third-party
# wheels" would need a judgment call per dependency, and would be enforced by whoever
# reviewed the build script that day.
$payloadWheels = @($entries | Where-Object { $_ -like 'tools/wheels/*.whl' })
Write-Host "   wheels in package: $($payloadWheels.Count)"
if ($payloadWheels.Count -ne 1) {
    Fail-Verification @(
        "expected exactly 1 bundled wheel, found $($payloadWheels.Count).",
        'Bundling dependency wheels would put third-party scanner code in a',
        'published artifact. See packaging/README.md.'
    )
}
if ($meta.version -ne ($wheel.Name -replace '^automated_security_helper-(.+)-py3-none-any\.whl$', '$1')) {
    Fail-Verification "packed version $($meta.version) does not match the wheel $($wheel.Name)"
}

Write-Host '== 4. install it, and let Chocolatey resolve the python3 dependency'
# The local directory first, then the community feed, so the ash package resolves to
# the one just built and its python3 dependency resolves to the published one. This
# downloads a third-party package; it does not publish anything.
$sources = "$OutDir;https://community.chocolatey.org/api/v2/"
# Captured into a variable and filtered afterwards, NOT piped straight into
# `Select-Object -First`. `-First` stops the upstream pipeline as soon as it has enough
# items, and upstream here is choco: a `choco install | Select-String | Select-Object
# -First 20` would kill the installer partway through as soon as the twentieth matching
# line appeared, and the symptom would be a half-installed package with no error.
# `-Last`, used further down, buffers everything and does not have this problem.
$installLog = @(choco install ash --version $meta.version --source $sources --yes --no-progress)
$installRc = $LASTEXITCODE
$installLog |
    Select-String -Pattern 'Installing|python3|Chocolatey installed|ERROR|WARNING' |
    Select-Object -First 20 |
    ForEach-Object { Write-Host "   $_" }
Assert-NativeSuccess -What 'choco install ash' -ExitCode $installRc

# Proof that the declared dependency was satisfiable, which is the property the
# nuspec's version range asserts. `choco list` with a filter reports locally installed
# packages on Chocolatey 2.x.
$installed = choco list --limit-output
Assert-NativeSuccess -What 'choco list' -ExitCode $LASTEXITCODE
$python3Row = @($installed | Where-Object { $_ -match '^python3\|' })
if ($python3Row.Count -eq 0) {
    Fail-Verification @(
        'Chocolatey did not install the python3 dependency.',
        'The nuspec declares python3 [3.10,3.14); if no published version falls in',
        'that range the install would still appear to succeed on this runner, because',
        'the image already has Python on PATH.'
    )
}
Write-Host "   python3 dependency Chocolatey installed: $($python3Row[0])"

$venvDir = Join-Path $env:ProgramData 'ash\venv'
$venvPython = Join-Path $venvDir 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) { Fail-Verification "$venvPython does not exist after install" }
Write-Host "   venv interpreter: $(& $venvPython -V 2>&1)"

Write-Host '== 5. every console script the wheel declares is on PATH and runs'
# All three names are required by name here, not read back from the wheel, because
# this is the assertion about the entry-point contract rather than about the
# mechanism. chocolateyinstall.ps1 derives the shim set from the wheel's metadata; if
# that derivation ever drops a name, this step is what notices.
#
#   ash                        canonical.
#   ashv3                      deprecated, warns once on stderr, still works.
#   automated-security-helper  kept indefinitely and silent. This is the escape hatch
#                              for hosts where a bare `ash` resolves to something
#                              else, and on Windows that is not hypothetical: MSYS2
#                              ships the Almquist shell as `ash` and has already
#                              shadowed this entry point in CI, with `Illegal option
#                              --` as the symptom.
$chocoBin = Join-Path $env:ChocolateyInstall 'bin'
foreach ($name in @('ash', 'ashv3', 'automated-security-helper')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) { Fail-Verification "$name is not on PATH after install" }
    if (-not $cmd.Source.StartsWith($chocoBin, [StringComparison]::OrdinalIgnoreCase)) {
        # A different `ash` earlier on PATH would make every check below measure
        # someone else's program.
        Fail-Verification "$name resolves to $($cmd.Source), not to a shim under $chocoBin"
    }
    $stderrFile = Join-Path ([System.IO.Path]::GetTempPath()) "ash-$name-stderr.txt"
    $stdout = & $name --version 2> $stderrFile
    Assert-NativeSuccess -What "$name --version" -ExitCode $LASTEXITCODE
    $stderrText = (Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue)
    if (-not $stderrText) { $stderrText = '' }
    Write-Host "   $name --version -> $(($stdout -join ' ').Trim())"

    if ($name -eq 'ashv3') {
        if ($stderrText.Trim().Length -eq 0) {
            Fail-Verification 'ashv3 printed no deprecation warning on stderr.'
        }
        Write-Host "   ashv3 warned on stderr, as intended"
    } else {
        if ($stderrText.Trim().Length -ne 0) {
            Fail-Verification @(
                "$name wrote to stderr: $($stderrText.Trim())",
                'Only ashv3 is deprecated. ash and automated-security-helper are silent.'
            )
        }
    }
    Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
}

# -V and not -v. -v is --verbose and has been for all of v3, so a package that got
# this wrong would turn a verbose run into a version print for anyone with -v in CI.
$shortForm = & ash -V
Assert-NativeSuccess -What 'ash -V' -ExitCode $LASTEXITCODE
Write-Host "   ash -V -> $(($shortForm -join ' ').Trim())"

Write-Host '== 6. scan a fixture with a KNOWN finding'
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-choco-fixture'
if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
New-Item -ItemType Directory -Path $fixture -Force | Out-Null
# detect-secrets is a runtime dependency of ASH and drives in process, so it is the
# one default scanner present after installing ASH alone. The rest are correctly
# reported SKIPPED rather than MISSING.
Set-Content -LiteralPath (Join-Path $fixture 'leak.py') -Encoding ASCII -Value @(
    '# Fixture for packaging verification. Not a real credential.',
    'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
)
$outputDir = Join-Path $fixture '.ash\ash_output'
$scanLog = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-choco-scan.log'
$scanErrLog = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-choco-scan.err.log'
Push-Location $fixture
try {
    # Two separate file redirections rather than `*>` or `2>&1`. Merging a native
    # command's stderr into the success stream is what makes PowerShell wrap those lines
    # as ErrorRecords, which under $ErrorActionPreference = 'Stop' terminates the script
    # on a progress line. Redirecting each stream to its own file happens at the process
    # level and does not.
    #
    # The exit code is recorded and not asserted: ASH exits nonzero when it FINDS
    # something, which is the expected outcome here. Step 7 is the assertion.
    & ash scan --source-dir $fixture --output-dir $outputDir --scanners detect-secrets --no-progress > $scanLog 2> $scanErrLog
    $scanRc = $LASTEXITCODE
} finally {
    Pop-Location
}
Get-Content -LiteralPath $scanLog -Tail 4 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "   $_" }
Get-Content -LiteralPath $scanErrLog -Tail 4 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "   [stderr] $_" }
Write-Host "   ash scan rc=$scanRc"

Write-Host '== 7. assert a finding was actually reported'
# Run with the venv interpreter, so the parse cannot silently depend on whatever
# python the runner image happens to preinstall.
$assert = Join-Path ([System.IO.Path]::GetTempPath()) 'ash-assert-sarif.py'
Set-Content -LiteralPath $assert -Encoding ASCII -Value @'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
sarif = out / "reports" / "ash.sarif"
if not sarif.exists():
    cands = sorted(out.rglob("*.sarif"))
    if not cands:
        print("   FAIL: no SARIF produced, so nothing can be asserted about findings")
        raise SystemExit(1)
    sarif = cands[0]
doc = json.loads(sarif.read_text(encoding="utf-8"))
results = [r for run in doc.get("runs", []) for r in run.get("results", [])]
print(f"   SARIF: {sarif.name}, {len(results)} result(s)")
if not results:
    print("   FAIL: scan produced 0 findings on a fixture planted with a secret.")
    raise SystemExit(1)
for r in results[:3]:
    loc = (r.get("locations") or [{}])[0]
    uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "?")
    print(f"     - {r.get('ruleId','?')} at {uri}")
print("   OK: the installed package ran a scan and reported findings")
'@
try {
    & $venvPython $assert $outputDir | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { exit 1 }
} finally {
    Remove-Item -LiteralPath $assert -Force -ErrorAction SilentlyContinue
}

Write-Host '== 8. uninstall drops the venv and the shims'
$uninstallLog = @(choco uninstall ash --yes --no-progress)
$uninstallRc = $LASTEXITCODE
$uninstallLog | Select-Object -Last 6 | ForEach-Object { Write-Host "   $_" }
Assert-NativeSuccess -What 'choco uninstall ash' -ExitCode $uninstallRc
if (Test-Path -LiteralPath (Join-Path $env:ProgramData 'ash')) {
    Fail-Verification "$(Join-Path $env:ProgramData 'ash') survived the uninstall"
}
foreach ($name in @('ash', 'ashv3', 'automated-security-helper')) {
    if (Test-Path -LiteralPath (Join-Path $chocoBin "$name.exe")) {
        Fail-Verification "the $name shim survived the uninstall"
    }
}
Write-Host '   OK: venv and shims removed'

Write-Host ''
Write-Host 'CHOCOLATEY VERIFICATION PASSED'
