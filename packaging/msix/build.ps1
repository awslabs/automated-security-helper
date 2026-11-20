# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Builds a signed ASH .msix from an already-built wheel.

.DESCRIPTION
    Takes the wheel rather than building one, for the same reason packaging/rpm/build.sh
    does: a packaging step that also builds its own payload can ship a different wheel than
    the one the contents gate approved.

    Order of operations, and why it is this order:

      1. resolve a signing certificate      the manifest's Publisher comes from its subject
      2. msix.py stage                      layout, mapping file, version stamp, assets
      3. csc.exe, three times                the launchers named in the mapping
      4. msix.py validate --layout          the gate, after the layout is complete
      5. makeappx pack /f                   the authoritative schema check, as a side effect
      6. signtool sign                      with the certificate from step 1

    Step 1 comes first because Windows refuses to install a package whose
    Identity/@Publisher is not byte-identical to its signing certificate's subject, so the
    subject is an input to the manifest rather than something checked afterwards. Step 4 sits
    between the compile and the pack because makeappx reports a missing referenced file as a
    path error, and msix.py reports it as "the compile step did not run".

.PARAMETER Wheel
    Path to automated_security_helper-<version>-py3-none-any.whl.

.PARAMETER OutputDirectory
    Where the layout and the .msix are written. Defaults to build/msix under the repo root,
    which is gitignored and is also a directory the version-reference walk in
    tests/unit/test_agent_plugin_ash_version.py skips.

.PARAMETER PfxBase64
    Base64 of a PKCS#12 (.pfx) signing certificate. When empty, a throwaway self-signed
    certificate is generated instead and the package is marked as such.

    This parameter is the ENTIRE difference between a self-signed development package and one
    signed with a real Authenticode certificate. There is no thumbprint to edit, no store to
    pre-populate and no certificate path baked into any file: the subject is read out of
    whichever .pfx this resolves to and stamped into the manifest. Swapping in a real
    certificate is populating one secret.

.PARAMETER PfxPassword
    Password for the .pfx. Optional, because a password-less .pfx is valid and keeps the swap
    to literally one secret.

.PARAMETER TimestampUrl
    RFC 3161 timestamp server. Deliberately has no default: a signature without a timestamp
    stops validating when the certificate expires, so a real release wants one, but baking in
    a particular timestamping service would put a third-party URL in this repository and
    would make every self-signed development build depend on reaching it. Left empty, the
    signature is not timestamped, which is correct for a throwaway certificate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Wheel,
    [string] $OutputDirectory,
    [string] $PfxBase64 = '',
    [string] $PfxPassword = '',
    [string] $TimestampUrl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# PowerShell does not fail a script when a native command exits nonzero, so every external
# call below is followed by a check. Without this the pack could fail and the sign step would
# then report "file not found", one layer away from the cause.
$PSNativeCommandUseErrorActionPreference = $false

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptDirectory)

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'build/msix'
}

function Assert-LastExitCode {
    param([string] $What)
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE"
    }
}

# The SDK bin directory is not documented as being on PATH on any runner image, and
# Microsoft's own MSIX troubleshooting guide has a "SignTool not found in CI/CD" entry whose
# stated cause is that SignTool is not on standard CI images. So these are located rather
# than invoked bare.
#
# The version directory is globbed and the newest taken, not hardcoded. windows-latest ships
# exactly one SDK today (10.0.26100.0) and windows-2022 ships four, so a literal version
# would be a version that is right on one image and absent on the other.
function Find-SdkTool {
    param([Parameter(Mandatory = $true)][string] $Name)

    $onPath = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue
    if ($onPath) {
        return $onPath.Source
    }

    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        # Sorted by PARSED version, not by path string. windows-2022 carries four SDKs
        # (10.0.17763.0, 10.0.19041.0, 10.0.22621.0, 10.0.26100.0) and a lexicographic sort
        # puts 10.0.9... above 10.0.26100..., which would silently pick an older tool than the
        # newest installed. Measured, not assumed: sorting those three path strings descending
        # returns the 10.0.9.0 one first.
        #
        # Then by architecture, x64 before arm64 before x86. arm64 is in the list because an
        # arm64 Windows box has arm64 tools and would otherwise find nothing; it is second
        # rather than first because the x64 tools run everywhere through emulation and the
        # hosted runners are x64.
        $architecturePreference = @{ 'x64' = 0; 'arm64' = 1; 'x86' = 2 }
        $found = Get-ChildItem -Path $root -Filter $Name -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.DirectoryName -match '\\10\.[0-9.]+\\(x64|arm64|x86)$' } |
            Sort-Object -Property `
                @{ Expression = { [version]($_.DirectoryName -replace '.*\\(10\.[0-9.]+)\\(?:x64|arm64|x86)$', '$1') }; Descending = $true }, `
                @{ Expression = { $architecturePreference[($_.DirectoryName -replace '.*\\', '')] }; Descending = $false } |
            Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }

    throw @"
could not find $Name.

It ships with the Windows SDK and is not on PATH by default. Looked on PATH and under
'Windows Kits\10\bin' in both Program Files directories. Either install the Windows SDK, or
run this from a Developer Command Prompt, or fetch the tools without an SDK install:

  nuget install Microsoft.Windows.SDK.BuildTools

which carries makeappx.exe and signtool.exe under bin/<version>/<arch>/.
"@
}

# csc.exe from the .NET Framework, not the Roslyn compiler from an SDK. It is present on
# every Windows that can install this package: TargetDeviceFamily/@MinVersion is 10.0.19041,
# and .NET Framework 4.8 is an OS component from Windows 10 1903 onward. That also means the
# compiled launchers need no runtime dependency declared in the manifest.
function Find-CSharpCompiler {
    $candidates = @(
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    throw "could not find csc.exe. Looked at: $($candidates -join ', ')"
}

# Resolves to a .pfx path plus its password, from one of two sources, and everything
# downstream treats them identically. That sameness is the point: the self-signed path and
# the real-certificate path differ only in where the bytes came from, so exercising one
# exercises the other.
function Resolve-SigningCertificate {
    param(
        [string] $Base64,
        [string] $Password,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $pfxPath = Join-Path $WorkingDirectory 'signing.pfx'

    if ($Base64) {
        Write-Host 'signing certificate: supplied (a secret is set)'
        try {
            [System.IO.File]::WriteAllBytes($pfxPath, [System.Convert]::FromBase64String($Base64))
        }
        catch [System.FormatException] {
            throw 'the signing certificate secret is not valid base64.'
        }
        return @{ Path = $pfxPath; Password = $Password; SelfSigned = $false }
    }

    Write-Host 'signing certificate: generating a throwaway self-signed one (no secret set)'
    # The subject says what it is. A package signed with this cannot be installed by anyone
    # who has not first chosen to trust the certificate, and it is not Store installable, so
    # the subject should not be mistakable for an official signature.
    $subject = 'CN=ASH Development (self-signed), O=ASH, C=US'
    $certificate = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $subject `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')

    # A password is required to export a .pfx, and this one protects a key that exists for the
    # length of one build and is never trusted anywhere else.
    $generatedPassword = [System.Guid]::NewGuid().ToString('N')
    $secure = ConvertTo-SecureString -String $generatedPassword -Force -AsPlainText
    Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $secure | Out-Null
    Remove-Item -Path ("Cert:\CurrentUser\My\" + $certificate.Thumbprint) -Force

    return @{ Path = $pfxPath; Password = $generatedPassword; SelfSigned = $true }
}

# Read through Get-PfxData rather than the X509Certificate2 constructor. .NET 9 obsoleted
# constructing a certificate from PKCS#12 bytes in favour of X509CertificateLoader, and the
# obsoletion is version-dependent, so which spelling works depends on which PowerShell is
# running the script. Get-PfxData is in the PKI module, which this script already needs for
# New-SelfSignedCertificate and Export-PfxCertificate, and its behavior does not move.
function Get-CertificateSubject {
    param([Parameter(Mandatory = $true)][hashtable] $Certificate)

    $data = if ($Certificate.Password) {
        Get-PfxData -FilePath $Certificate.Path `
            -Password (ConvertTo-SecureString -String $Certificate.Password -Force -AsPlainText)
    }
    else {
        Get-PfxData -FilePath $Certificate.Path
    }

    $leaf = @($data.EndEntityCertificates)
    if ($leaf.Count -ne 1) {
        throw @"
the signing certificate contains $($leaf.Count) end-entity certificates, expected 1.

Identity/@Publisher is stamped from one subject, so a .pfx carrying several leaf certificates
leaves no single answer to stamp. Export just the signing certificate and its chain.
"@
    }
    return $leaf[0].Subject
}

# ------------------------------------------------------------------------------------------

$Wheel = (Resolve-Path -LiteralPath $Wheel).Path
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

Write-Host "wheel:  $Wheel"
Write-Host "output: $OutputDirectory"

$makeappx = Find-SdkTool -Name 'makeappx.exe'
$signtool = Find-SdkTool -Name 'signtool.exe'
$csc = Find-CSharpCompiler
Write-Host "makeappx: $makeappx"
Write-Host "signtool: $signtool"
Write-Host "csc:      $csc"

$certificate = Resolve-SigningCertificate -Base64 $PfxBase64 -Password $PfxPassword -WorkingDirectory $OutputDirectory
$publisher = Get-CertificateSubject -Certificate $certificate
Write-Host "publisher (from the certificate subject): $publisher"

Write-Host ''
Write-Host '== 1. stage the layout'
# uv with a pinned interpreter, and --script so the PEP 723 block at the top of msix.py is
# read and its one dependency (defusedxml) is installed into an environment isolated from any
# project virtualenv. That isolation is what --no-project used to provide here; --script keeps
# it while allowing the dependency. Naming the interpreter after `python`, as this line did
# before, makes uv ignore the PEP 723 block entirely and msix.py then dies on the defusedxml
# import. The 3.13 pin stays because a bare `python` resolves to whatever the image
# preinstalled, which on the Windows runner images is a 3.9 with no tomllib.
& uv run --script --python 3.13 (Join-Path $scriptDirectory 'msix.py') `
    stage --wheel $Wheel --out $OutputDirectory --publisher $publisher
Assert-LastExitCode 'msix.py stage'

$layout = Join-Path $OutputDirectory 'layout'

Write-Host ''
Write-Host '== 2. compile the launchers'
# One source, three output names. The program reads its own filename to decide which venv
# console script to run, so the names are the behavior and not decoration. They come from the
# mapping file rather than from a list here, so this loop cannot go out of step with
# [project.scripts]: msix.py derives the mapping from it, and validate asserts set equality.
$launcherSource = Join-Path $scriptDirectory 'AshLauncher.cs'
$launcherNames = Select-String -Path (Join-Path $layout 'mapping.txt') -Pattern '"([^"]+\.exe)"$' |
    ForEach-Object { $_.Matches[0].Groups[1].Value }
if (-not $launcherNames) {
    throw "no launcher names found in $layout\mapping.txt; msix.py stage did not write them."
}
foreach ($name in $launcherNames) {
    $target = Join-Path $layout $name
    # /target:exe, not winexe: a console subsystem binary is the point, since without one the
    # launcher would have no stdout to inherit and ASH's output would go nowhere.
    #
    # No /warnaserror. A compiler warning here is worth reading and is visible in the log, but
    # turning one into a failed package build means a future csc adding a new diagnostic
    # breaks releases for something that is not a defect.
    & $csc /nologo /optimize+ /target:exe /platform:anycpu ("/out:" + $target) $launcherSource
    Assert-LastExitCode "csc $name"
    Write-Host "   compiled $name"
}

Write-Host ''
Write-Host '== 3. validate the manifest and the staged layout'
# The same script a developer runs, and the gate before anything is packed. Everything it
# checks was observed rejecting a corrupted manifest before being trusted to pass a correct
# one; see the commit that added it.
# --script for the same reason as the stage step above: it is what makes msix.py's PEP 723
# dependency resolve. Both invocations have to carry it or neither works.
& uv run --script --python 3.13 (Join-Path $scriptDirectory 'msix.py') `
    validate --manifest (Join-Path $layout 'AppxManifest.xml') --layout $layout
Assert-LastExitCode 'msix.py validate'

Write-Host ''
Write-Host '== 4. pack'
# The output name is derived from the wheel and is stable, because a GitHub release asset URL
# is templated on it: packaging/winget/ points at this filename.
$version = [System.IO.Path]::GetFileName($Wheel) -replace '^automated_security_helper-', '' -replace '-py3-none-any\.whl$', ''
$msix = Join-Path $OutputDirectory ("automated-security-helper-" + $version + ".msix")
if (Test-Path $msix) {
    Remove-Item -LiteralPath $msix -Force
}

# /f with the mapping file rather than /d with the directory. The mapping enumerates what
# ships, so a stray file in the layout does not silently become part of a signed package;
# msix.py asserts the mapping and the layout describe the same set, in both directions.
#
# This step is also the authoritative schema check. There is no way to validate an
# AppxManifest against its XSD off Windows (the namespace URIs do not resolve and the
# redistributable XSD set is missing 30 of the 47 namespaces its own schemas reference,
# including the one that declares broadFileSystemAccess), so makeappx reading the manifest is
# the first and only time the real schema is applied.
& $makeappx pack /f (Join-Path $layout 'mapping.txt') /p $msix /o
Assert-LastExitCode 'makeappx pack'

Write-Host ''
Write-Host '== 5. sign'
$signArguments = @('sign', '/fd', 'SHA256', '/f', $certificate.Path)
if ($certificate.Password) {
    $signArguments += @('/p', $certificate.Password)
}
if ($TimestampUrl) {
    $signArguments += @('/tr', $TimestampUrl, '/td', 'SHA256')
}
else {
    Write-Host '   not timestamped: no -TimestampUrl given'
}
$signArguments += $msix

& $signtool @signArguments
if ($LASTEXITCODE -ne 0) {
    # The overwhelmingly likely cause, and the one whose error text does not say so.
    throw @"
signtool failed with exit code $LASTEXITCODE.

If it reported a publisher mismatch, the manifest's Identity/@Publisher and the
certificate's subject have diverged. This script stamps the manifest from the subject it
read, which was:

  $publisher

so a mismatch means the subject string as signtool reads it differs from the normalized form
X509Certificate2.Subject produced, usually in the order or spacing of the relative
distinguished names. Pass the certificate's subject exactly as its issuer wrote it.
"@
}

Write-Host ''
Write-Host "built $msix"
if ($certificate.SelfSigned) {
    # Said at the end, where it is read, rather than only in the README.
    Write-Host 'This package is SELF-SIGNED. It is not Store installable, and it will not'
    Write-Host 'install anywhere until its certificate is trusted. README.msix has the exact'
    Write-Host 'commands, and the certificate to trust can be exported from the package with:'
    Write-Host "  Get-AuthenticodeSignature '$msix' | ForEach-Object { `$_.SignerCertificate }"
}
