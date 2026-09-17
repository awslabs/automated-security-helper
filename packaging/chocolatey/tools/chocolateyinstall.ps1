# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Chocolatey install script for ASH.
#
# The shape is the one packaging/README.md documents for the deb and the rpm, ported
# to Windows: the package carries exactly one wheel, this script builds a virtualenv
# on the target and installs that wheel into it, and the entry points the wheel
# declares are put on PATH. Nothing here downloads a payload, and nothing unpacks a
# vendored third-party binary.
#
# WHY THE VENV IS NOT INSIDE THE PACKAGE DIRECTORY
#
# The obvious place for it is $env:ChocolateyInstall\lib\ash\venv, which Chocolatey
# deletes on uninstall for free. It is the wrong place: after this script returns,
# Chocolatey scans the package directory for executables and generates a shim in
# $env:ChocolateyInstall\bin for each one it finds. A venv there would therefore put
# python.exe, pythonw.exe, pip.exe and pip3.exe on every user's PATH, ahead of
# whatever Python they actually chose. Suppressing that means dropping a .ignore file
# beside each executable, which is a list of filenames that has to stay in step with
# whatever the venv module and pip happen to create.
#
# So the venv goes under %ProgramData%\ash, the direct analog of the deb's
# /usr/lib/ash, and this script creates the shims it wants explicitly with
# Install-BinFile. chocolateyuninstall.ps1 removes them and the venv.
#
# WHY A SHIM AND NOT A WRAPPER SCRIPT
#
# packaging/deb/build.sh installs /usr/bin/ash as a shell wrapper rather than a
# symlink, because `ash` shells out to sys.executable for the container runner and a
# symlink leaves sys.executable pointing at /usr/bin/ash. That failure mode does not
# reproduce here: the venv's ash.exe is a launcher that starts the venv's own
# interpreter, and a Chocolatey shim starts ash.exe as a child process, so
# sys.executable is the venv python either way. verify-on-windows.ps1 checks the
# consequence that matters, which is that a scan actually runs.

$ErrorActionPreference = 'Stop'

# Chocolatey runs this under Windows PowerShell 5.1, where a nonzero exit from a native
# command never throws. It is set anyway because Chocolatey's host is not the only thing
# that ever runs this file, and PowerShell 7.4 flipped the default the other way: with
# $PSNativeCommandUseErrorActionPreference on and $ErrorActionPreference = 'Stop', pip
# exiting nonzero would throw before the message below could name what failed. The
# variable does not exist in 5.1; assigning it there is a harmless no-op.
$PSNativeCommandUseErrorActionPreference = $false

# PowerShell does not raise on a nonzero exit from a native command, and this script
# runs several. An unchecked native call is the PowerShell form of the shell bug
# where `set -e` is missing: pip fails, the script keeps going, and the package
# reports a successful install with a half-built venv. Every native call below is
# followed by Assert-NativeSuccess.
function Assert-NativeSuccess {
    param(
        [Parameter(Mandatory = $true)][string] $What,
        [Parameter(Mandatory = $true)][AllowNull()][int] $ExitCode
    )
    if ($ExitCode -ne 0) {
        throw "$What failed with exit code $ExitCode."
    }
}

$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$wheelDir = Join-Path $toolsDir 'wheels'
$ashHome = Join-Path $env:ProgramData 'ash'
$venvDir = Join-Path $ashHome 'venv'
$shimList = Join-Path $ashHome 'installed-shims.txt'

# The publishing boundary, checked again on the user's machine. build.ps1 and
# verify-on-windows.ps1 both count the wheels too; this copy is the one that runs
# where nobody is watching, and it costs one Get-ChildItem. A count is used rather
# than a name test for the reason packaging/README.md gives: if the answer is one, no
# third-party code shipped, and that is checkable without judging each dependency.
$wheels = @(Get-ChildItem -LiteralPath $wheelDir -Filter '*.whl' -File -ErrorAction SilentlyContinue)
if ($wheels.Count -ne 1) {
    throw @"
Expected exactly 1 bundled wheel under tools\wheels, found $($wheels.Count).
Bundling dependency wheels would put third-party scanner code in a published
artifact. See packaging/README.md.
"@
}
$wheel = $wheels[0].FullName
Write-Host "ash: bundled wheel is $($wheels[0].Name)"

# Chocolatey installed the python3 dependency in this same run, and the PATH entry it
# added is not visible to a process that started before it. Update-SessionEnvironment
# is Chocolatey's helper for exactly that; without it the interpreter search below
# can miss an interpreter that was installed thirty seconds ago and fail with a
# message telling the user to install what they just installed.
if (Get-Command Update-SessionEnvironment -ErrorAction SilentlyContinue) {
    Update-SessionEnvironment
}

# Interpreter selection. The nuspec pins python3 to [3.10,3.14), so Chocolatey has
# provided something in range, but `python` on PATH is not necessarily it: a machine
# can carry an older Python from a previous install, from the Microsoft Store stub,
# or from a conda environment, and whichever one is earliest on PATH wins. So probe
# candidates and take the first that reports a version ASH supports, rather than
# trusting the first that answers at all.
#
# The py launcher entries come first because they resolve through the registry rather
# than through PATH, which is what makes them immune to the ordering problem above.
$candidates = @(
    @{ Exe = 'py';      Args = @('-3.13') },
    @{ Exe = 'py';      Args = @('-3.12') },
    @{ Exe = 'py';      Args = @('-3.11') },
    @{ Exe = 'py';      Args = @('-3.10') },
    @{ Exe = 'py';      Args = @('-3') },
    @{ Exe = 'python';  Args = @() },
    @{ Exe = 'python3'; Args = @() }
)

$probe = Join-Path ([System.IO.Path]::GetTempPath()) ("ash-probe-" + [guid]::NewGuid().ToString('N') + ".py")
Set-Content -LiteralPath $probe -Encoding ASCII -Value 'import sys; print("%d.%d" % sys.version_info[:2])'

$python = $null
$pythonVersion = $null
$tried = New-Object System.Collections.Generic.List[string]
try {
    foreach ($c in $candidates) {
        $label = (@($c.Exe) + $c.Args) -join ' '
        if (-not (Get-Command $c.Exe -ErrorAction SilentlyContinue)) {
            $tried.Add("$label (not on PATH)")
            continue
        }
        $reported = & $c.Exe @($c.Args + @($probe)) 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $reported) {
            $tried.Add("$label (did not run)")
            continue
        }
        $reported = ([string]$reported).Trim()
        $parsed = $null
        if (-not [version]::TryParse($reported, [ref] $parsed)) {
            $tried.Add("$label (unreadable version '$reported')")
            continue
        }
        if ($parsed -lt [version]'3.10' -or $parsed -ge [version]'3.14') {
            $tried.Add("$label ($reported, outside [3.10,3.14))")
            continue
        }
        $python = @($c.Exe) + $c.Args
        $pythonVersion = $reported
        break
    }
} finally {
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
}

if (-not $python) {
    throw @"
No Python interpreter in the range [3.10,3.14) was found. Candidates tried:
  $($tried -join "`n  ")
The package declares a python3 dependency in that range, so Chocolatey should have
provided one. If it did and this still failed, the interpreter is installed somewhere
this search does not reach; install it for all users so the py launcher records it,
or put it on PATH, then reinstall the package.
"@
}
Write-Host "ash: building the venv with $($python -join ' ') (Python $pythonVersion)"

# A leftover venv from a failed install would make `python -m venv` reuse a tree
# built by a different interpreter, and pip would then install into it happily. Start
# clean. This is safe on upgrade because Chocolatey runs the new version's install
# script and the old version's uninstall script is not what rebuilds this.
if (Test-Path -LiteralPath $venvDir) {
    Write-Host "ash: removing an existing venv at $venvDir"
    Remove-Item -LiteralPath $venvDir -Recurse -Force
}
New-Item -ItemType Directory -Path $ashHome -Force | Out-Null

& $python[0] @($python[1..($python.Length - 1)] + @('-m', 'venv', $venvDir))
Assert-NativeSuccess -What "python -m venv $venvDir" -ExitCode $LASTEXITCODE

$venvPython = Join-Path $venvDir 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    throw "python -m venv reported success but $venvPython does not exist."
}

# --no-cache-dir so a wheel of the same version cached from an earlier install cannot
# be substituted for the one this package carries, which is the same reason
# ash-package.yml passes --no-cache when it installs the built wheel.
Write-Host 'ash: installing the bundled wheel and resolving its dependencies'
& $venvPython -m pip install --no-cache-dir --disable-pip-version-check $wheel
Assert-NativeSuccess -What 'pip install' -ExitCode $LASTEXITCODE

# The shim set comes from the wheel's own console_scripts metadata rather than from a
# hardcoded list of three names. [project.scripts] in pyproject.toml declares ash,
# ashv3 and automated-security-helper today; a list here would be a fourth place that
# has to be edited when that changes, and the failure when it is not edited is silent
# (the new name simply never reaches PATH).
$enumerate = Join-Path ([System.IO.Path]::GetTempPath()) ("ash-eps-" + [guid]::NewGuid().ToString('N') + ".py")
Set-Content -LiteralPath $enumerate -Encoding ASCII -Value @'
from importlib.metadata import distribution
eps = distribution("automated-security-helper").entry_points
for name in sorted({ep.name for ep in eps if ep.group == "console_scripts"}):
    print(name)
'@
try {
    $scriptNames = @(& $venvPython $enumerate)
    Assert-NativeSuccess -What 'reading console_scripts from the installed wheel' -ExitCode $LASTEXITCODE
} finally {
    Remove-Item -LiteralPath $enumerate -Force -ErrorAction SilentlyContinue
}
$scriptNames = @($scriptNames | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })

# An empty list here would leave a working venv with nothing on PATH and no error, so
# it is checked rather than assumed. The floor is 1 and not 3 because the assertion is
# about the mechanism reporting something, not about which names exist this release;
# verify-on-windows.ps1 is where the three specific names are required.
if ($scriptNames.Count -lt 1) {
    throw 'The installed wheel declares no console_scripts, so nothing would be put on PATH.'
}

Set-Content -LiteralPath $shimList -Encoding ASCII -Value $scriptNames
foreach ($name in $scriptNames) {
    $target = Join-Path $venvDir "Scripts\$name.exe"
    if (-not (Test-Path -LiteralPath $target)) {
        throw "The wheel declares a console script named '$name' but $target was not created."
    }
    Install-BinFile -Name $name -Path $target
    Write-Host "ash: shimmed $name"
}

Write-Host ''
Write-Host "ash: installed. Run 'ash --help' to start."
Write-Host "ash: on a machine where 'ash' resolves to something else (MSYS2 ships the"
Write-Host "ash: Almquist shell under that name), 'automated-security-helper' is the"
Write-Host "ash: same program under a name nothing else claims."
Write-Host "ash: scanners are not installed by this package. Run 'ash dependencies install'."
