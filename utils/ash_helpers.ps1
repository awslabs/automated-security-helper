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

    Defaults to 'non-root', and to 'ci' on Windows. CI environment variables do not
    change it.

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
        [ValidateScript({ Test-Path -LiteralPath $_ })]
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
        [switch]
        $IgnoreSuppressions,
        [parameter()]
        [string]
        $ContainerUID,
        [parameter()]
        [string]
        $ContainerGID,
        [parameter()]
        [string]
        $OutputFormat = "text",
        # 'ci' on Windows (Windows PowerShell 5 runs only there), where the bind-mounted
        # output directory is not writable by the non-root user; 'non-root' everywhere
        # else. CI variables do not choose the stage: pass -BuildTarget ci to ask for it.
        [parameter()]
        [ValidateSet("ci", "non-root")]
        [string]
        $BuildTarget = $(if($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows){"ci"}else{"non-root"}),
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
        # ValidateSet and -eq ignore case, and so does the build: -BuildTarget NON-ROOT
        # is non-root. Lower-cased once, so the --target value and the image tag are too.
        $BuildTarget = $BuildTarget.ToLowerInvariant()
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
        # The commands below run through Invoke-Expression, which parses its string as
        # PowerShell. Every value that comes from the operator or the file system is
        # therefore written into it by name (`$Scanners[0]`, "$sourceDirFull"), which
        # Invoke-Expression expands as a value without parsing it, so a directory
        # named `a$(...)` is passed as that name.
        if ($PSBoundParameters.ContainsKey('Scanners')) {
            for ($i = 0; $i -lt $Scanners.Count; $i++) {
                $ashCmdArgs.Add("--scanners")
                $ashCmdArgs.Add("`$Scanners[$i]")
            }
        }
        if ($PSBoundParameters.ContainsKey('ExcludeScanners')) {
            for ($i = 0; $i -lt $ExcludeScanners.Count; $i++) {
                $ashCmdArgs.Add("--exclude-scanners")
                $ashCmdArgs.Add("`$ExcludeScanners[$i]")
            }
        }
        if ($IgnoreSuppressions) {
            $ashCmdArgs.Add("--ignore-suppressions")
        }

        # Resolve OCI runner. IsNullOrEmpty, not `$null -ne`: $OCIRunner is a [string]
        # defaulting to $env:ASH_OCI_RUNNER, and with that unset PowerShell binds "" rather
        # than $null, so the null test always chose @("") and Get-Command rejected the
        # empty name. An empty value falls back to discovery, as ./ash does.
        $runners = if (-not [string]::IsNullOrEmpty($OCIRunner)) {
            @($OCIRunner)
        }
        else {
            @('docker', 'finch', 'nerdctl', 'podman')
        }

        # Resolve source and output directories. -LiteralPath: -Path reads '[', ']',
        # '*' and '?' as wildcards, so 'src[1]' would name 'src1'. New-Item has no
        # -LiteralPath and reads its -Path as written.
        $sourceDirFull = Get-Item -LiteralPath $SourceDir | Select-Object -ExpandProperty FullName
        Write-Verbose "Resolved SourceDir to: $sourceDirFull"

        # Create the output directory if it doesn't exist
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            Write-Verbose "Creating OutputDir: $OutputDir"
            New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
        }
        $outputDirFull = Get-Item -LiteralPath $OutputDir | Select-Object -ExpandProperty FullName

        # --mount reads its value as comma-separated fields, so a comma in a host path
        # starts a field of its own (a,b), a double quote starts CSV
        # quoting, and a line break ends the argument. A path holding one is refused
        # before anything is built or run, with exit 3.
        function Assert-Mountable([string]$Label, [string]$Path) {
            if ($Path -match '[,"\r\n]') {
                Stop-AshRefusal 3 "The $Label '$Path' cannot be handed to the container runner: --mount reads its value as comma-separated fields, so a path holding a comma, a double quote or a line break would be read as something else. Rename it, or choose another path."
            }
        }
        if (-not $NoRun) {
            Assert-Mountable 'source directory' $sourceDirFull
            Assert-Mountable 'output directory' $outputDirFull
            # /out is mounted read-write and /src read-only: an output directory that
            # is the source directory or above it would hold the source tree, writable,
            # at /out. A directory that is itself a link is compared by its target.
            $separatorChars = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            $nameComparison = if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
            $directories = foreach ($path in @($sourceDirFull, $outputDirFull)) {
                $item = Get-Item -LiteralPath $path
                $real = if ($item.LinkType -and $item.ResolvedTarget) { [string]$item.ResolvedTarget } else { $item.FullName }
                $real.TrimEnd($separatorChars) + [System.IO.Path]::DirectorySeparatorChar
            }
            if ($directories[0].StartsWith($directories[1], $nameComparison)) {
                Stop-AshRefusal 3 "The output directory '$outputDirFull' is the source directory '$sourceDirFull' or a directory above it. Container mode mounts the output read-write at /out and the source read-only at /src, so the source would be writable through /out. Use an output directory inside the source (the default .ash/ash_output) or outside it, not above it."
            }
        }

        # The config file, -Config or else ASH_CONFIG, is read by the scan inside the
        # container, which sees the host only through its mounts: the host path names
        # nothing there. A config inside SourceDir is read through the read-only /src
        # mount, with every extends base it can name; one outside it is mounted
        # read-only on its own at /ash-config. Refused with exit 3, as any unusable
        # config is, when it is not an existing file. -NoRun scans nothing, so it
        # does not need one.
        $configMountArg = $null
        $configFromRepository = $false
        $configInCheckout = $false
        if (-not $NoRun -and ($PSBoundParameters.ContainsKey('Config') -or -not [string]::IsNullOrEmpty($Config))) {
            if ([string]::IsNullOrEmpty($Config) -or -not (Test-Path -LiteralPath $Config -PathType Leaf)) {
                Stop-AshRefusal 3 "Config file not found: $Config. -Config (or ASH_CONFIG) has to name an existing file: it is mounted read-only for the scan inside the container."
            }
            # The runner mounts with its own rights, which can be wider than this user's.
            try {
                [System.IO.File]::OpenRead((Get-Item -LiteralPath $Config).FullName).Close()
            }
            catch {
                Stop-AshRefusal 3 "Config file cannot be read: $Config. ASH does not hand the container runner a file it cannot read itself."
            }
            $configFull = (Get-Item -LiteralPath $Config).FullName
            Assert-Mountable 'config file' $configFull
            $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            $sourcePrefix = $sourceDirFull.TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar
            $pathComparison = if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
            if ($configFull.StartsWith($sourcePrefix, $pathComparison)) {
                $configInner = "/src/" + $configFull.Substring($sourcePrefix.Length).Replace('\', '/')
            }
            else {
                # Mounted on its own, without the files it extends, so a config with an
                # extends entry would not resolve inside the container. Refused, as is
                # every chain ash --mode container cannot mount whole. Not parsed here,
                # so this errs toward refusing: the key followed by ':' or '=' anywhere
                # in the text with line breaks read as spaces (a JSON key and its ':'
                # on two lines, TOML's '=', YAML's '? extends' key), and any quoted key
                # holding a backslash, which may spell the name with an escape.
                # Case-sensitive, as ASH reads the key.
                $configText = [string](Get-Content -LiteralPath $configFull -Raw)
                $configFlat = $configText -replace "[`r`n]", ' '
                if (($configFlat -cmatch '(^|[\s{,])["'']?extends["'']?\s*[:=]') -or ($configText -cmatch '(?m)"[^"\r\n]*\\[^"\r\n]*"\s*:')) {
                    Stop-AshRefusal 3 "The config file '$Config' is outside the source directory and has an extends entry. Invoke-ASH mounts such a config on its own, without the files it extends. Run ash --mode container, which mounts the chain, or put the config inside the source directory."
                }
                $configInner = "/ash-config/" + (Split-Path -Leaf $configFull)
                $configMountArg = '--mount "type=bind,source=$configFull,destination=$configInner,readonly"'
                # A config elsewhere in the scanned checkout -- the outermost directory
                # at or above SourceDir holding a .git entry, as a local scan defines
                # it -- was written by the repository being scanned. The scan inside
                # sees it only at /ash-config, outside its own tree, so it is told.
                $checkout = $sourceDirFull
                $dir = Get-Item -LiteralPath $sourceDirFull
                while ($null -ne $dir) {
                    if (Test-Path -LiteralPath (Join-Path $dir.FullName '.git')) {
                        $checkout = $dir.FullName
                    }
                    $dir = $dir.Parent
                }
                $checkoutPrefix = $checkout.TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar
                $configFromRepository = $configFull.StartsWith($checkoutPrefix, $pathComparison)
                # A config inside any other git checkout is one a local scan counts as
                # repository-written too (config/sandbox_grants.repository_written), so
                # it is marked; the link check below stays with the scanned checkout.
                $dir = Get-Item -LiteralPath (Split-Path -Parent $configFull)
                while ($null -ne $dir) {
                    if (Test-Path -LiteralPath (Join-Path $dir.FullName '.git')) {
                        $configInCheckout = $true
                        break
                    }
                    $dir = $dir.Parent
                }
                # The runner resolves links when it mounts. A config inside the scanned
                # checkout is mounted only when neither the file nor a directory on the
                # way to it is a link; otherwise the run is refused.
                if ($configFromRepository) {
                    $item = Get-Item -LiteralPath $configFull
                    while ($null -ne $item -and $item.FullName.StartsWith($checkoutPrefix, $pathComparison)) {
                        if ($item.LinkType) {
                            Stop-AshRefusal 3 "The config file '$Config' is inside the scanned tree and is reached through a link ('$($item.FullName)'). ASH does not mount a file the repository being scanned points it at."
                        }
                        $item = Get-Item -LiteralPath (Split-Path -Parent $item.FullName)
                    }
                }
            }
            $ashCmdArgs.Add("--config")
            $ashCmdArgs.Add('"$configInner"')
            if ($configFromRepository -or $configInCheckout) {
                $ashCmdArgs.Add('--config-from-scanned-repository')
            }
        }

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

        # Add color support (only when running in an interactive terminal)
        if (-not ("$AshArgs" -match '(\-\-no-color|\-c)') -and [Environment]::UserInteractive -and -not [Console]::IsOutputRedirected) {
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
                Stop-AshRefusal 1 "Unable to resolve an OCI_RUNNER -- exiting"
            }
            else {
                Write-Verbose "Resolved OCI_RUNNER to: $RESOLVED_OCI_RUNNER"

                # OCI_RUNNER_WRAPPER prefixes all OCI commands (like RUSTC_WRAPPER)
                $OCI_WRAPPER = if ($env:OCI_RUNNER_WRAPPER) { $env:OCI_RUNNER_WRAPPER } else { $null }

                # Build the container if not skipped
                if (-not $NoBuild) {
                    # On Linux and macOS the non-root user gets the caller's own UID and
                    # GID (id -u, id -g) unless -ContainerUID or -ContainerGID names
                    # another, as ./ash and `ash --mode container` give it, so it owns
                    # what the caller created; both are then checked the same way. On
                    # Windows there is no such ID and the Dockerfile's defaults apply.
                    if (-not ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) -and (Get-Command id -ErrorAction SilentlyContinue)) {
                        if (-not $ContainerUID) { $ContainerUID = "$(& id -u)".Trim() }
                        if (-not $ContainerGID) { $ContainerGID = "$(& id -g)".Trim() }
                    }
                    # -ContainerUID and -ContainerGID become build arguments, read as
                    # numbers.
                    foreach ($id in @(@('UID', $ContainerUID), @('GID', $ContainerGID))) {
                        # \A and \z: .NET's ^ and $ also match around a final line feed.
                        if ($id[1] -and $id[1] -notmatch '\A[0-9]+\z') {
                            Stop-AshRefusal 3 "Container $($id[0]) must be a numeric value: '$($id[1])'."
                        }
                    }
                    # The non-root stage creates its user with `adduser --uid <UID>
                    # --gid <GID>`. UID 0 is root, which already exists, and GID 0 is
                    # root's group. A non-root build with either is refused before
                    # building, as ./ash and `ash --mode container` refuse it: given as
                    # -ContainerUID or -ContainerGID 0 (any spelling of zero), or taken
                    # from a caller running as root. -BuildTarget ci is the opt-in for
                    # the image that runs as root.
                    if ($BuildTarget -eq 'non-root') {
                        if ($ContainerUID -match '\A0+\z') {
                            Stop-AshRefusal 3 "The non-root image stage creates a user with UID 0, which is root: Invoke-ASH is running as root, or -ContainerUID 0 was given. Pass -BuildTarget ci to build the image that runs as root. Another -ContainerUID and -ContainerGID work only when the output directory is writable by that UID: the container runs as that user and writes its reports there."
                        }
                        if ($ContainerGID -match '\A0+\z') {
                            Stop-AshRefusal 3 "The non-root image stage gives its user GID 0, which is root's group: Invoke-ASH is running with GID 0, or -ContainerGID 0 was given. Pass -BuildTarget ci to build the image that runs as root. Another -ContainerGID works only when the output directory is writable by the container's user, which writes its reports there."
                        }
                    }
                    Write-Host "Building image $AshImageName -- this may take a few minutes during the first build..."

                    $buildCmd = @()
                    if ($OCI_WRAPPER) { $buildCmd += $OCI_WRAPPER }
                    $buildCmd += @(
                        $RESOLVED_OCI_RUNNER
                        'build'
                    )

                    # Add UID/GID build args
                    if ($ContainerUID) {
                        $buildCmd += "--build-arg", '"UID=$ContainerUID"'
                    }
                    if ($ContainerGID) {
                        $buildCmd += "--build-arg", '"GID=$ContainerGID"'
                    }
                    $dockerfilePath = Resolve-Path $(Join-Path $ashRoot "Dockerfile")
                    # Add other build args
                    $buildCmd += @(
                        "--tag", '"$AshImageName"'
                        "--target", $BuildTarget
                        "--file", '"$dockerfilePath"'
                        "--build-arg", "OFFLINE=$(if ($Offline) {'YES'} else {'NO'})"
                        "--build-arg", '"OFFLINE_SEMGREP_RULESETS=$OfflineSemgrepRulesets"'
                        "--build-arg", "BUILD_DATE=$(Get-Date -UFormat %s)"
                    )

                    # ASH_BASE_IMAGE_OVERRIDE redirects `FROM ${BASE_IMAGE}` at whichever
                    # registry actually served the base image.
                    # .github/actions/prepull-base-image sets it when ECR Public refuses and
                    # Docker Hub answers, as a digest-pinned reference.
                    #
                    # A local tag under the ECR name does not suffice on its own. BuildKit only
                    # falls back to a local store when its worker has one, and
                    # worker/runc/runc.go sets `ImageStore: nil` explicitly -- so a buildkitd on
                    # its default OCI worker, and `docker buildx` on a docker-container driver,
                    # ignore the tag. Emitted before $buildArgs so a caller's explicit
                    # BASE_IMAGE build-arg lands later and wins -- a duplicate --build-arg is
                    # last-wins.
                    #
                    # ASH_BASE_OCI_LAYOUT=<layout dir>@<arch manifest digest> is the cache-hit
                    # hand-off from the same action, a layout it verified against the pinned
                    # digest. This runs `<runner> build`: on docker that is the docker driver,
                    # which turns an oci-layout context into a registry lookup, so the action
                    # loads the layout into the engine instead; podman has no oci-layout
                    # context and gets the same treatment in its own store. nerdctl and finch
                    # take the layout as a build context, spelled without the digest (nerdctl
                    # reads the image from index.json), plus --pull=false, which nerdctl maps
                    # to image-resolve-mode=local.
                    $ociRunnerName = [System.IO.Path]::GetFileNameWithoutExtension($RESOLVED_OCI_RUNNER)
                    if ($env:ASH_BASE_OCI_LAYOUT) {
                        if ($env:ASH_BASE_OCI_LAYOUT -notmatch '^(?<dir>.+)@(?<digest>sha256:[0-9a-f]{64})$') {
                            throw "ASH_BASE_OCI_LAYOUT is '$($env:ASH_BASE_OCI_LAYOUT)', which is not <layout dir>@sha256:<64 hex>. Unset it to build from the Dockerfile's own base image reference."
                        }
                        $baseLayoutDir = $Matches['dir']
                        if ($ociRunnerName -in @('nerdctl', 'finch')) {
                            Write-Host "Base image taken from the verified OCI layout named by ASH_BASE_OCI_LAYOUT, with no registry call."
                            $buildCmd += "--build-context", '"ash-base-image=oci-layout://$baseLayoutDir"'
                            $buildCmd += "--build-arg", "BASE_IMAGE=ash-base-image"
                            $buildCmd += "--pull=false"
                        }
                        else {
                            Write-Host "Base image expected in $ociRunnerName's local store, placed there from the verified OCI layout named by ASH_BASE_OCI_LAYOUT."
                        }
                    }
                    elseif ($env:ASH_BASE_IMAGE_OVERRIDE) {
                        Write-Host "Base image redirected to $($env:ASH_BASE_IMAGE_OVERRIDE) by ASH_BASE_IMAGE_OVERRIDE."
                        $buildCmd += "--build-arg", '"BASE_IMAGE=$env:ASH_BASE_IMAGE_OVERRIDE"'
                    }

                    # Add any extra build args
                    if ($buildArgs.Count -gt 0) {
                        $buildCmd += $buildArgs
                    }

                    # Add the build context
                    $buildCmd += '"$ashRoot"'

                    # Execute the build command
                    $buildCmdStr = $buildCmd -join ' '
                    Write-Verbose "Build command: $buildCmdStr"
                    Invoke-Expression $buildCmdStr

                    # Invoke-Expression on a native command does not throw on a
                    # non-zero exit, so without this a failed build continues to
                    # the run below, which then fails trying to pull the image
                    # from a registry and blames the registry rather than the
                    # build step that actually broke.
                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to build image $AshImageName (exit $LASTEXITCODE). See the build output above for the failing step."
                    }
                }

                # Run the container if not skipped
                if (-not $NoRun) {
                    Write-Host "Running ASH scan using built image..."
                    $ashDebug = "$(if($PSBoundParameters.ContainsKey('Debug')){"YES"}else{"NO"})".Trim()
                    $runCmd = @()
                    if ($OCI_WRAPPER) { $runCmd += $OCI_WRAPPER }
                    $runCmd += @(
                        $RESOLVED_OCI_RUNNER
                        'run'
                        '--rm'
                        "-e", '"ASH_ACTUAL_SOURCE_DIR=$sourceDirFull"'
                        "-e", '"ASH_ACTUAL_OUTPUT_DIR=$outputDirFull"'
                        "-e", "ASH_DEBUG=`"$ashDebug`""
                        "-e", '"ASH_OUTPUT_FORMAT=$OutputFormat"'
                    )

                    # Add source directory mount, read-only wherever the output
                    # directory is: the output has its own mount at /out and the scan
                    # inside writes there, also when OutputDir is inside SourceDir.
                    $runCmd += '--mount "type=bind,source=$sourceDirFull,destination=/src,readonly"'

                    # Add output directory mount
                    $runCmd += '--mount "type=bind,source=$outputDirFull,destination=/out"'

                    # Add the config file mount, when the config is outside SourceDir
                    if ($configMountArg) {
                        $runCmd += $configMountArg
                    }

                    # Add any extra run args
                    if ($runArgs.Count -gt 0) {
                        $runCmd += $runArgs
                    }

                    # Add image name and ASH command
                    $runCmd += @(
                        '"$AshImageName"'
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
            # Rethrown as it is: writing it as an error record first showed it twice.
            throw
        }
    }
}

function Test-AshInteractiveSession {
    <#
    .SYNOPSIS
    Whether this PowerShell session is one a person types into.

    .DESCRIPTION
    Decided from the call stack first: when a script file is among Invoke-ASH's
    callers, `exit` ends that script and nothing else, so the session that ran it
    stays whether a person types into it or not. With no script among the callers,
    Invoke-ASH was typed at a prompt or given in a -Command string, which the call
    stack cannot tell apart. Then a host other than the console host (an editor's
    integrated console) is typed into, and for the console host the process command
    line decides: pwsh and powershell started with a command or a script to run
    (-Command, -File, -EncodedCommand, a script path, or -NonInteractive) end when it
    does; one started without either, or with -NoExit, is typed into. Parameter
    names may be abbreviated, as PowerShell accepts them.
    #>
    param(
        [string[]]
        $Arguments = [Environment]::GetCommandLineArgs(),
        [string]
        $HostName = $Host.Name,
        [AllowNull()]
        [string[]]
        $ScriptFrames = $null
    )
    if ($null -eq $ScriptFrames) {
        $helpers = $MyInvocation.MyCommand.ScriptBlock.File
        $ScriptFrames = @(
            Get-PSCallStack |
                Where-Object { $_.ScriptName -and $_.ScriptName -ne $helpers } |
                ForEach-Object { $_.ScriptName }
        )
    }
    if ($ScriptFrames.Count -gt 0) {
        return $false
    }
    if ($HostName -and $HostName -notin @('ConsoleHost', 'Default Host')) {
        return $true
    }
    $rest = @($Arguments | Select-Object -Skip 1)
    foreach ($argument in $rest) {
        $flag = ("$argument" -replace '^/', '-').ToLowerInvariant()
        if ($flag.Length -ge 4 -and '-noexit'.StartsWith($flag)) {
            return $true
        }
    }
    foreach ($argument in $rest) {
        $flag = ("$argument" -replace '^/', '-').ToLowerInvariant()
        if ($flag -like '*.ps1' -or $flag -in @('-c', '-f', '-e', '-ec')) {
            return $false
        }
        foreach ($name in @('-command', '-file', '-encodedcommand')) {
            if ($flag.Length -ge 4 -and $name.StartsWith($flag)) {
                return $false
            }
        }
        if ($flag.Length -ge 5 -and '-noninteractive'.StartsWith($flag)) {
            return $false
        }
    }
    return $true
}

function Stop-AshRefusal {
    <#
    .SYNOPSIS
    End an Invoke-ASH run that is refused, with its exit code and message.

    .DESCRIPTION
    The message goes to stderr directly: Write-Error under
    $ErrorActionPreference = 'Stop' would end the script with exit 1 before the exit
    code is set. In a session a person types into, the refusal throws instead of
    exiting, so the session stays open; $LASTEXITCODE holds the code either way.
    #>
    param([int]$ExitCode, [string]$Message)
    $global:LASTEXITCODE = $ExitCode
    if (Test-AshInteractiveSession) {
        throw "ERROR: $Message"
    }
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $ExitCode
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
