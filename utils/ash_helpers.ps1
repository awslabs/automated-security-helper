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

    .PARAMETER ContainerUID
    The UID to use for the container user.

    Defaults to the current user's UID.

    .PARAMETER ContainerGID
    The GID to use for the container user.

    Defaults to the current user's GID.

    .PARAMETER Debug
    If $true, enables debug output.

    .PARAMETER OutputFormat
    The output format for ASH results.

    Defaults to 'text'.

    .PARAMETER BuildTarget
    The target stage to build in the Dockerfile.

    Defaults to 'non-root'.

    .PARAMETER Offline
    If $true, runs ASH in offline mode.

    .PARAMETER OfflineSemgrepRulesets
    The Semgrep rulesets to use in offline mode.

    Defaults to 'p/ci'.

    .EXAMPLE
    Invoke-ASH -SourceDir ./dummy_files -OCIRunner finch -AshArgs '--quiet --force' -Verbose

    .EXAMPLE
    Get-Help Invoke-ASH
    #>
    [CmdletBinding()]
    param(
        [parameter(Position = 0)]
        [ValidateScript({ Test-Path $_ })]
        [string]
        $SourceDir = (Get-Location).Path,
        [parameter()]
        [string]
        $OutputDir = $(Join-Path (Get-Location).Path '.ash' 'ash_output'),
        [parameter()]
        [string]
        $Config = $env:ASH_CONFIG,
        [parameter()]
        [string]
        $OCIRunner = $env:ASH_OCI_RUNNER,
        [parameter()]
        [string]
        $AshImageName = $(if ($null -ne $env:ASH_IMAGE_NAME) {
                $env:ASH_IMAGE_NAME
            }
            else {
                "automated-security-helper"
            }),
        [parameter()]
        [switch]
        $NoBuild,
        [parameter()]
        [switch]
        $NoRun,
        [parameter()]
        [string[]]
        $Scanners,
        [parameter()]
        [string[]]
        $ExcludeScanners,
        [parameter()]
        [string]
        $ContainerUID,
        [parameter()]
        [string]
        $ContainerGID,
        [parameter()]
        [string]
        $OutputFormat = "text",
        [parameter()]
        [ValidateSet("ci", "non-root")]
        [string]
        $BuildTarget = $(if($env:CI -or $env:IsCI -or $env:CODEBUILD_BUILD_ID){"ci"}else{"non-root"}),
        [parameter()]
        [switch]
        $Offline,
        [parameter()]
        [switch]
        $Progress,
        [parameter()]
        [switch]
        $NoFailOnFindings,
        [parameter()]
        [switch]
        $ShowSummary,
        [parameter()]
        [string]
        $OfflineSemgrepRulesets = "p/ci",
        [parameter(ValueFromRemainingArguments)]
        [string]
        $AshArgs = $null
    )
    begin {
        $ashRoot = (Get-Item $PSScriptRoot).Parent.FullName
        $buildArgs = [System.Collections.Generic.List[string]]::new()
        $runArgs = [System.Collections.Generic.List[string]]::new()
        $ashCmdArgs = [System.Collections.Generic.List[string]]::new()

        # Process AshArgs to extract options)
        if ("$AshArgs" -match '\-\-force') {
            $buildArgs.Add('--no-cache')
        }
        if ("$AshArgs" -match '(\-\-quiet|\-q)') {
            $buildArgs.Add('-q')
            $ashCmdArgs.Add('--quiet')
        }
        if ("$AshArgs" -match '(\-\-no-color|\-c)') {
            $ashCmdArgs.Add('--no-color')
        }
        if ($Progress) {
            $ashCmdArgs.Add('--progress')
        }
        else {
            $ashCmdArgs.Add('--no-progress')
        }
        if ($ShowSummary) {
            $ashCmdArgs.Add('--show-summary')
        }
        else {
            $ashCmdArgs.Add('--no-show-summary')
        }
        if ($NoFailOnFindings) {
            $ashCmdArgs.Add('--no-fail-on-findings')
        }
        else {
            $ashCmdArgs.Add('--fail-on-findings')
        }
        if ($PSBoundParameters.ContainsKey('Verbose')) {
            $ashCmdArgs.Add('--verbose')
        }
        if ($PSBoundParameters.ContainsKey('Debug')) {
            $ashCmdArgs.Add('--debug')
        }
        if ($Offline) {
            $ashCmdArgs.Add('--offline')
        }
        if ($PSBoundParameters.ContainsKey('Config')) {
            $ashCmdArgs.Add("--config")
            $ashCmdArgs.Add($Config)
        }
        if ($PSBoundParameters.ContainsKey('Scanners')) {
            foreach ($scanner in $Scanners) {
                $ashCmdArgs.Add("--scanners")
                $ashCmdArgs.Add($scanner)
            }
        }
        if ($PSBoundParameters.ContainsKey('ExcludeScanners')) {
            foreach ($scanner in $ExcludeScanners) {
                $ashCmdArgs.Add("--exclude-scanners")
                $ashCmdArgs.Add($scanner)
            }
        }

        # Resolve OCI runner
        $runners = if ($null -ne $OCIRunner) {
            @($OCIRunner)
        }
        else {
            @('docker', 'finch', 'nerdctl', 'podman')
        }

        # Resolve source and output directories
        $sourceDirFull = Get-Item $SourceDir | Select-Object -ExpandProperty FullName
        Write-Verbose "Resolved SourceDir to: $sourceDirFull"

        # Create the output directory if it doesn't exist
        if (-not (Test-Path $OutputDir)) {
            Write-Verbose "Creating OutputDir: $OutputDir"
            New-Item $OutputDir -ItemType Directory -Force | Out-Null
        }
        $outputDirFull = Get-Item $OutputDir | Select-Object -ExpandProperty FullName

        # Set image name with target stage
        if ($AshImageName -notmatch ":") {
            $AshImageName = "$($AshImageName):$BuildTarget"
        }

        # Handle offline mode
        if ($Offline) {
            $runArgs.Add('--network=none')
        }

        # Capture terminal dimensions for better container experience
        $H = Get-Host
        $COLUMNS = $H.UI.RawUI.WindowSize.Width
        $LINES = $H.UI.RawUI.WindowSize.Height
        $runArgs.Add("-e COLUMNS=$COLUMNS")
        $runArgs.Add("-e LINES=$LINES")

        # Add color support
        if (-not ("$AshArgs" -match '(\-\-no-color|\-c)')) {
            $runArgs.Add("-t")
        }
    }
    process {
        try {
            $RESOLVED_OCI_RUNNER = $null
            foreach ($runner in $runners) {
                if ($FOUND = Get-Command $runner -ErrorAction SilentlyContinue) {
                    $RESOLVED_OCI_RUNNER = $FOUND.Name
                    break
                }
            }
            if ($null -eq $RESOLVED_OCI_RUNNER) {
                Write-Error "Unable to resolve an OCI_RUNNER -- exiting"
                exit 1
            }
            else {
                Write-Verbose "Resolved OCI_RUNNER to: $RESOLVED_OCI_RUNNER"

                # Build the container if not skipped
                if (-not $NoBuild) {
                    Write-Host "Building image $AshImageName -- this may take a few minutes during the first build..."

                    $buildCmd = @(
                        $RESOLVED_OCI_RUNNER
                        'build'
                    )

                    # Add UID/GID build args
                    if ($ContainerUID) {
                        $buildCmd += "--build-arg", "UID=$ContainerUID"
                    }
                    if ($ContainerGID) {
                        $buildCmd += "--build-arg", "GID=$ContainerGID"
                    }
                    $dockerfilePath = Resolve-Path $(Join-Path $ashRoot "Dockerfile")
                    # Add other build args
                    $buildCmd += @(
                        "--tag", $AshImageName
                        "--target", $BuildTarget
                        "--file", "`"$dockerfilePath`""
                        "--build-arg", "OFFLINE=$($Offline -eq $true ? 'YES' : 'NO')"
                        "--build-arg", "OFFLINE_SEMGREP_RULESETS=`"$OfflineSemgrepRulesets`""
                        "--build-arg", "BUILD_DATE=$(Get-Date -UFormat %s)"
                    )

                    # Add any extra build args
                    if ($buildArgs.Count -gt 0) {
                        $buildCmd += $buildArgs
                    }

                    # Add the build context
                    $buildCmd += "`"$ashRoot`""

                    # Execute the build command
                    $buildCmdStr = $buildCmd -join ' '
                    Write-Verbose "Build command: $buildCmdStr"
                    Invoke-Expression $buildCmdStr
                }

                # Run the container if not skipped
                if (-not $NoRun) {
                    Write-Host "Running ASH scan using built image..."
                    $ashDebug = "$(if($PSBoundParameters.ContainsKey('Debug')){"YES"}else{"NO"})".Trim()
                    $runCmd = @(
                        $RESOLVED_OCI_RUNNER
                        'run'
                        '--rm'
                        "-e", "ASH_ACTUAL_SOURCE_DIR=`"$sourceDirFull`""
                        "-e", "ASH_ACTUAL_OUTPUT_DIR=`"$outputDirFull`""
                        "-e", "ASH_DEBUG=`"$ashDebug`""
                        "-e", "ASH_OUTPUT_FORMAT=`"$OutputFormat`""
                    )

                    # Add source directory mount
                    $mountSourceDir = "--mount `"type=bind,source=$sourceDirFull,destination=/src"

                    # Make source dir readonly if output dir is not a subdirectory
                    if ($outputDirFull -notmatch [regex]::Escape($sourceDirFull)) {
                        $mountSourceDir += ",readonly"
                    }
                    $mountSourceDir += '"'
                    $runCmd += $mountSourceDir

                    # Add output directory mount
                    $runCmd += "--mount `"type=bind,source=$outputDirFull,destination=/out`""

                    # Add any extra run args
                    if ($runArgs.Count -gt 0) {
                        $runCmd += $runArgs
                    }

                    # Add image name and ASH command
                    $runCmd += @(
                        $AshImageName
                        'ash'
                        '--source-dir /src'
                        '--output-dir /out'
                    )

                    # Add any ASH command args
                    if ($ashCmdArgs.Count -gt 0) {
                        $runCmd += $ashCmdArgs
                    }

                    # Add any remaining ASH args
                    if ($AshArgs) {
                        $runCmd += $AshArgs
                    }

                    # Execute the run command
                    $runCmdStr = $runCmd -join ' '
                    Write-Verbose "Run command: $runCmdStr"
                    Invoke-Expression $runCmdStr
                    $exitCode = $LASTEXITCODE
                    return $exitCode
                }
            }
        }
        catch {
            Write-Error $_
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
    $exampleOCIRunners | Where-Object { $_ -match $wordToComplete } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new(
            $_, $_, 'ParameterValue', $_)
    }
}
