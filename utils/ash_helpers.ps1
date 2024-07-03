function Invoke-ASH {
    <#
    .SYNOPSIS
    Provides a PowerShell entrypoint to build and invoke ASH as a container executable.

    .DESCRIPTION
    Provides a PowerShell entrypoint to build and invoke ASH as a container executable.

    .PARAMETER SourceDir
    The source directory to scan with ASH.

    Defaults to the current working directory.

    .PARAMETER OutputDir
    The output directory for ASH results to be stored in.

    Defaults to `ash_output` within the current working directory.

    .PARAMETER AshArgs
    Additional arguments to pass to ASH.

    .PARAMETER OCIRunner
    Preferred OCI runner CLI tool to use, e.g. `docker`, `finch`, `nerdctl`, or `podman`.

    Supports tab-completion of common OCI runner CLI tools or overriding to provide
    something else entirely.

    Defaults to `$env:ASH_OCI_RUNNER` if set, otherwise attempts to resolve based on the
    first found executable in PATH.

    .PARAMETER NoBuild
    If $true, skips the `OCI_RUNNER build ...` call.

    Requires target image tag to be present on the host already, either through a previous
    build or by pulling from a registry.

    .PARAMETER NoRun
    If $true, skips the `OCI_RUNNER run ...` call.

    Used primarily when a rebuild is needed during development of ASH, but a re-run of
    the ASH scan is not needed after build.

    .EXAMPLE
    Invoke-ASH -SourceDir ./dummy_files -OCIRunner finch -AshArgs '--quiet --force' -Verbose

    .EXAMPLE
    Get-Help Invoke-ASH
    #>
    [CmdletBinding()]
    Param(
        [parameter(Position=0)]
        [ValidateScript({Test-Path $_})]
        [string]
        $SourceDir = $PWD.Path,
        [parameter()]
        [string]
        $OutputDir = $(Join-Path $PWD.Path 'ash_output'),
        [parameter(Position = 1, ValueFromRemainingArguments)]
        [string]
        $AshArgs = $null,
        [parameter()]
        [string]
        $OCIRunner = $env:ASH_OCI_RUNNER,
        [parameter()]
        [string]
        $AshImageName = $(if ($null -ne $env:ASH_IMAGE_NAME) {
            $env:ASH_IMAGE_NAME
        } else {
            "automated-security-helper:local"
        }),
        [parameter()]
        [switch]
        $NoBuild,
        [parameter()]
        [switch]
        $NoRun
    )
    Begin {
        $ashRoot = (Get-Item $PSScriptRoot).Parent.FullName
        $buildArgs = [System.Collections.Generic.List[string]]::new()
        if ("$AshArgs" -match '\-\-force') {
            $buildArgs.Add('--no-cache')
        }
        if ("$AshArgs" -match '(\-\-quiet|\-q)') {
            $buildArgs.Add('-q')
        }
        $runners = if ($null -ne $OCIRunner) {
            @(
                $OCIRunner
            )
        } else {
            @(
                'docker'
                'finch'
                'nerdctl'
                'podman'
            )
        }
        $sourceDirFull = Get-Item $SourceDir | Select-Object -ExpandProperty FullName
        Write-Verbose "Resolved SourceDir to: $sourceDirFull"

        # Create the output directory if it doesn't exist, otherwise the bind mount of the
        # OUTPUT_DIR will fail.
        if (-not (Test-Path $OutputDir)) {
            Write-Verbose "Creating OutputDir: $OutputDir"
            New-Item $OutputDir -ItemType Directory -Force | Out-Null
        }
        $outputDirFull = Get-Item $OutputDir | Select-Object -ExpandProperty FullName
    }
    Process {
        try {
            $RESOLVED_OCI_RUNNER = $null
            foreach ($runner in $runners) {
                if ($FOUND = Get-Command $runner -ErrorAction SilentlyContinue) {
                    $RESOLVED_OCI_RUNNER = $FOUND
                    break
                }
            }
            if ($null -eq $RESOLVED_OCI_RUNNER) {
                Write-Error "Unable to resolve an $RESOLVED_OCI_RUNNER -- exiting"
                exit 1
            } else {
                Write-Verbose "Resolved OCI_RUNNER to: $RESOLVED_OCI_RUNNER"
                $buildCmd = @(
                    $RESOLVED_OCI_RUNNER
                    'build'
                    '-t'
                    $AshImageName
                    "'$ashRoot'"
                    $($buildArgs -join ' ')
                ) -join ' '
                $runCmd = @(
                    $RESOLVED_OCI_RUNNER
                    'run'
                    '--rm'
                    '-it'
                    "--mount type=bind,source=$sourceDirFull,destination=/src,readonly"
                    "--mount type=bind,source=$outputDirFull,destination=/out"
                    $AshImageName
                    'ash'
                    '--source-dir /src'
                    '--output-dir /out'
                    "$AshArgs"
                ) -join ' '

                if (-not $NoBuild) {
                    Write-Verbose "Executing: $buildCmd"
                    Invoke-Expression $buildCmd
                }
                if (-not $NoRun) {
                    Write-Verbose "Executing: $runCmd"
                    Invoke-Expression $runCmd
                }
            }
        } catch {
            throw $_
        }
    }
}

Register-ArgumentCompleter -CommandName Invoke-ASH -ParameterName 'OCIRunner' -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)
    $exampleOCIRunners = @(
        'docker'
        'finch'
        'nerdctl'
        'podman'
    )
    $exampleOCIRunners | Where-Object {$_ -match $wordToComplete} | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new(
            $_, $_, 'ParameterValue', $_)
    }
}
