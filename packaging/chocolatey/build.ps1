# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
Builds the ASH Chocolatey package from an already-built wheel.

.DESCRIPTION
Takes the wheel rather than building one, for the same reason packaging/deb/build.sh
and packaging/rpm/build.sh do: a packaging step that also builds its own payload can
ship a different wheel than the one .github/scripts/assert-artifact-contents.py
approved. Pass the artifact that passed the gate.

Writes the .nupkg into OutDir and prints its full path as the only line on stdout, so
a caller can capture it. Progress goes to the host stream.

Requires choco, which is why CI runs this on windows-latest. The runner image ships
Chocolatey preinstalled (Chocolatey 2.7.4 as of the Windows Server 2025 image), so no
bootstrap step is needed there.

.PARAMETER Wheel
Path to automated_security_helper-<version>-py3-none-any.whl.

.PARAMETER OutDir
Directory to write the .nupkg into. Created if absent.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string] $Wheel,
    [Parameter(Mandatory = $true, Position = 1)][string] $OutDir
)

$ErrorActionPreference = 'Stop'

# See the long note in verify-on-windows.ps1. PowerShell 7.4 makes a nonzero exit from a
# native command throw when $ErrorActionPreference is 'Stop', which would turn every
# native call in this script into an unlabeled terminating error instead of the named
# failure Assert-NativeSuccess produces. Off, and read the codes deliberately.
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

$sourceDir = $PSScriptRoot
$nuspecSource = Join-Path $sourceDir 'ash.nuspec'

if (-not (Test-Path -LiteralPath $Wheel -PathType Leaf)) {
    throw "no such wheel: $Wheel"
}
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    throw 'choco not found. This script needs Chocolatey; CI runs it on windows-latest, which ships it.'
}

# Version comes from the wheel filename, not from pyproject.toml or a git tag, which
# is the rule packaging/deb/build.sh states: the wheel is the thing being packaged, so
# reading anything else introduces a way for the package version and its payload to
# disagree.
$wheelName = Split-Path -Leaf $Wheel
$match = [regex]::Match($wheelName, '^automated_security_helper-(?<v>[^-]+)-py3-none-any\.whl$')
if (-not $match.Success) {
    throw @"
could not read a version from '$wheelName'.
       expected automated_security_helper-<version>-py3-none-any.whl
"@
}
$wheelVersion = $match.Groups['v'].Value

# A nuspec must carry a literal <version>, and commitizen keeps it in step with
# pyproject.toml. That leaves one failure this script has to catch: a release that
# bumped pyproject.toml and left the nuspec behind, or the reverse. `choco pack
# --version` would paper over it by overriding the literal, producing a package whose
# metadata is right and whose checked-in source is wrong, and nothing would ever
# report the drift. So compare and refuse instead.
[xml] $nuspecXml = Get-Content -LiteralPath $nuspecSource -Raw
$declaredVersion = $nuspecXml.package.metadata.version
if ($declaredVersion -ne $wheelVersion) {
    throw @"
version drift: ash.nuspec declares $declaredVersion, the wheel is $wheelVersion.
       These must match. ash.nuspec is listed in [tool.commitizen] version_files in
       pyproject.toml, so a release bump rewrites it; if it did not, the bump and the
       version_files entry disagree.
"@
}

# NuGet and Chocolatey accept SemVer-shaped versions. PEP 440 permits shapes they do
# not, notably a local version segment (1.0.0+local) and an epoch (1!1.0.0). The deb
# and rpm builders translate those to a tilde because both formats have a defined
# ordering for one. NuGet has no such translation that preserves ordering, so this
# fails loudly and names the wheel rather than emitting a version string whose sort
# order is anybody's guess.
if ($wheelVersion -notmatch '^[0-9]+(\.[0-9]+){1,3}(-[0-9A-Za-z][0-9A-Za-z.-]*)?$') {
    throw @"
'$wheelVersion' is not a version Chocolatey can order.
       Chocolatey follows SemVer; this looks like a PEP 440 local or epoch version.
       Build the package from a release wheel, or rename the wheel to a SemVer
       version first.
"@
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

# Staged in a temp tree rather than packed in place. `choco pack` resolves the
# nuspec's <files> globs relative to the nuspec, so packing in the repository would
# require writing the wheel into packaging/chocolatey/tools/wheels/ and would leave it
# there as an untracked build artifact that the next pack would happily include a
# second time. Then the exactly-one-wheel count would start failing for a reason that
# has nothing to do with what the package ships.
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("ash-choco-" + [guid]::NewGuid().ToString('N'))
try {
    $stageTools = Join-Path $stage 'tools'
    $stageWheels = Join-Path $stageTools 'wheels'
    New-Item -ItemType Directory -Path $stageWheels -Force | Out-Null

    Copy-Item -LiteralPath $nuspecSource -Destination (Join-Path $stage 'ash.nuspec')
    Copy-Item -LiteralPath (Join-Path $sourceDir 'tools\chocolateyinstall.ps1') -Destination $stageTools
    Copy-Item -LiteralPath (Join-Path $sourceDir 'tools\chocolateyuninstall.ps1') -Destination $stageTools
    # chocolateyinstall.ps1's failure messages and the nuspec description both point at
    # README.chocolatey, so it has to be in the package. An error message citing a file
    # the package never installed is worse than no message.
    Copy-Item -LiteralPath (Join-Path $sourceDir 'README.chocolatey') -Destination $stageTools
    Copy-Item -LiteralPath $Wheel -Destination $stageWheels

    $staged = @(Get-ChildItem -LiteralPath $stageWheels -Filter '*.whl' -File)
    if ($staged.Count -ne 1) {
        throw "staged $($staged.Count) wheels, expected exactly 1. See packaging/README.md."
    }

    Write-Host "building the ash Chocolatey package, version $wheelVersion"
    # choco pack writes into the current directory, and it has no option to write
    # elsewhere, so the working directory is moved rather than passing a path.
    Push-Location $stage
    try {
        choco pack ash.nuspec --outputdirectory $OutDir | Write-Host
        Assert-NativeSuccess -What 'choco pack' -ExitCode $LASTEXITCODE
    } finally {
        Pop-Location
    }
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}

$nupkg = Join-Path $OutDir "ash.$wheelVersion.nupkg"
if (-not (Test-Path -LiteralPath $nupkg -PathType Leaf)) {
    throw "choco pack exited 0 but $nupkg does not exist."
}

# choco pack exiting 0 is not evidence it wrote a readable package; open it. A .nupkg
# is a zip, so this is the analog of `dpkg-deb --info` and `rpm -qp --list`: a
# truncated central directory surfaces here rather than on a user's machine.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg)
try {
    $entries = @($zip.Entries | ForEach-Object { $_.FullName })
} finally {
    $zip.Dispose()
}
if (-not ($entries -contains 'ash.nuspec')) {
    throw "$nupkg does not contain ash.nuspec. Entries: $($entries -join ', ')"
}

Write-Output $nupkg
