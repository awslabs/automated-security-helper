# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Chocolatey uninstall script for ASH.
#
# Removes what chocolateyinstall.ps1 created outside the package directory: the shims
# in the Chocolatey bin directory and the venv under %ProgramData%\ash. Chocolatey
# tracks the files it laid down itself and removes those on its own, but a venv that
# pip built after install is invisible to it, exactly as no package manager tracks
# files a Debian postinst wrote.
#
# The shim names come from the list chocolateyinstall.ps1 wrote, not from asking the
# venv what its entry points are. By the time an uninstall runs, the venv may be the
# reason the user is uninstalling: a broken interpreter, a half-finished install, a
# tree someone deleted by hand. Re-deriving the list from a venv that cannot start
# would leave the shims behind, and a shim pointing into a deleted venv is worse than
# no shim, because it is on PATH and fails with a Windows error rather than an ASH one.

$ErrorActionPreference = 'Stop'

$ashHome = Join-Path $env:ProgramData 'ash'
$venvDir = Join-Path $ashHome 'venv'
$shimList = Join-Path $ashHome 'installed-shims.txt'

$names = @()
if (Test-Path -LiteralPath $shimList) {
    $names = @(Get-Content -LiteralPath $shimList |
        ForEach-Object { ([string]$_).Trim() } |
        Where-Object { $_ })
}

# The fallback exists for one case: an install that failed after creating shims but
# before writing the list, or a list a user deleted. These are the three names
# [project.scripts] declares, and Uninstall-BinFile on a name that was never shimmed
# is a no-op, so an over-broad list here cannot damage anything.
if ($names.Count -eq 0) {
    Write-Warning "ash: $shimList is missing, so falling back to the known shim names."
    $names = @('ash', 'ashv3', 'automated-security-helper')
}

foreach ($name in $names) {
    $target = Join-Path $venvDir "Scripts\$name.exe"
    try {
        Uninstall-BinFile -Name $name -Path $target
        Write-Host "ash: removed the $name shim"
    } catch {
        # Do not abort the uninstall over one shim. Stopping here would leave the venv
        # in place and the package half-removed, and the next install would then find a
        # venv it did not build.
        Write-Warning "ash: could not remove the $name shim: $($_.Exception.Message)"
    }
}

if (Test-Path -LiteralPath $ashHome) {
    Remove-Item -LiteralPath $ashHome -Recurse -Force
    Write-Host "ash: removed $ashHome"
}

if (Test-Path -LiteralPath $venvDir) {
    throw "$venvDir survived the uninstall."
}
