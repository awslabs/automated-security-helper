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

    .EXAMPLE
    try { Invoke-ASH -SourceDir . } catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }

    As a CI step that needs the refusal's code: writes the error record once and
    exits with the code, or with 1 for an error raised before Invoke-ASH sets one.
    On GitHub Actions run it with `shell: pwsh -File {0}`: the built-in `shell: pwsh`
    runs the script as `pwsh -command ". '<script>'"`, which reports every non-zero
    exit as 1.

    .NOTES
    A refusal throws, with $LASTEXITCODE set to its code: 3 for an input Invoke-ASH
    refuses, 1 when it finds no OCI runner. It never calls `exit`, so a script that
    dot-sources these helpers can catch it and go on. Any other error Invoke-ASH
    raises leaves $LASTEXITCODE non-zero too. Uncaught, `pwsh -File` and
    `pwsh -Command` exit 1, as PowerShell does for any uncaught error.
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
        # A refusal (Stop-AshRefusal) sets $LASTEXITCODE before it throws. Any other
        # error raised here, such as an output directory that cannot be created under
        # Stop, leaves it at 1 when it is 0, so a CI step's catch block, which exits
        # with $LASTEXITCODE (see .EXAMPLE), never exits 0 after a failure. `break`
        # rethrows the error unchanged.
        trap { if (-not $global:LASTEXITCODE) { $global:LASTEXITCODE = 1 }; break }
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

        # The path with every link on the way followed, which is what the runner
        # mounts. Component by component, so a link to a directory higher up is
        # followed too; bounded, so a cycle of links ends.
        function Get-AshRealPath([string]$Path, [int]$Depth = 0) {
            $full = [System.IO.Path]::GetFullPath($Path)
            if ($Depth -gt 40) { return $full }
            $root = [System.IO.Path]::GetPathRoot($full)
            $current = $root
            foreach ($part in $full.Substring($root.Length).Split([char[]]@('/', '\'), [System.StringSplitOptions]::RemoveEmptyEntries)) {
                $current = Join-Path $current $part
                $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
                if ($item -and $item.LinkType -and $item.Target) {
                    $target = [string]@($item.Target)[0]
                    if (-not [System.IO.Path]::IsPathRooted($target)) {
                        $target = Join-Path (Split-Path -Parent $current) $target
                    }
                    $current = Get-AshRealPath $target ($Depth + 1)
                }
            }
            return $current
        }
        $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        $pathComparison = if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
        function Test-AshUnder([string]$Path, [string]$Root) {
            $Root = $Root.TrimEnd($separators)
            return $Path.StartsWith($Root + [System.IO.Path]::DirectorySeparatorChar, $pathComparison)
        }
        $sourceReal = Get-AshRealPath $sourceDirFull

        # /out is mounted read-write and /src read-only: an output directory that is
        # the source directory or above it would hold the source tree, writable, at
        # /out. A directory that is itself a link is compared by its target. One that
        # does not exist yet cannot hold the source, so this runs before it is created.
        if (-not $NoRun -and (Test-Path -LiteralPath $OutputDir -PathType Container)) {
            $existingOutput = (Get-Item -LiteralPath $OutputDir).FullName
            $directories = foreach ($path in @($sourceDirFull, $existingOutput)) {
                $item = Get-Item -LiteralPath $path
                $real = if ($item.LinkType -and $item.ResolvedTarget) { [string]$item.ResolvedTarget } else { $item.FullName }
                $real.TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar
            }
            if ($directories[0].StartsWith($directories[1], $pathComparison)) {
                Stop-AshRefusal 3 "The output directory '$existingOutput' is the source directory '$sourceDirFull' or a directory above it. Container mode mounts the output read-write at /out and the source read-only at /src, so the source would be writable through /out. Use an output directory inside the source (the default .ash/ash_output) or outside it, not above it."
            }
        }

        # The same /out mount is why a linked output directory is refused: the scan
        # inside would write wherever the link leads, and a repository that commits
        # `.ash -> /some/host/dir` would choose that directory. Refused with exit 3:
        # the output directory when it is a symbolic link or junction, wherever it is,
        # and any link from below SourceDir down to it, with SourceDir taken under its
        # name and its real path. Links at or above SourceDir are the operator's own
        # spelling. The path is walked as written, '..' included, and before the
        # directory is created, because creating it through a linked .ash already
        # writes where the link points; so -NoRun, which creates it too, is refused as
        # well. ./ash and `ash --mode container` apply the same rule.
        function Test-AshLink([string]$Path) {
            $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            return [bool]($item -and $item.LinkType -in @('SymbolicLink', 'Junction'))
        }
        $spelledOutput = if ([System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir } else { Join-Path (Get-Location).Path $OutputDir }
        $outputRoot = [System.IO.Path]::GetPathRoot($spelledOutput)
        $walked = [System.Collections.Generic.List[string]]::new()
        $current = $null
        $linkOnTheWay = $null
        foreach ($part in $spelledOutput.Substring($outputRoot.Length).Split($separators, [System.StringSplitOptions]::RemoveEmptyEntries)) {
            if ($part -eq '.') { continue }
            if ($part -eq '..') {
                if ($walked.Count -gt 0) { $walked.RemoveAt($walked.Count - 1) }
                continue
            }
            $walked.Add($part)
            $current = $outputRoot.TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar + ($walked -join [System.IO.Path]::DirectorySeparatorChar)
            if (((Test-AshUnder $current $sourceDirFull) -or (Test-AshUnder $current $sourceReal)) -and (Test-AshLink $current)) {
                $linkOnTheWay = $current
                break
            }
        }
        if (-not $linkOnTheWay -and $walked.Count -gt 0 -and (Test-AshLink $current)) {
            $linkOnTheWay = $current
        }
        if ($linkOnTheWay) {
            Stop-AshRefusal 3 "Refusing the output directory '$OutputDir': the output directory path '$linkOnTheWay' is a symlink. Container mode mounts the output directory read-write at /out, so the scan inside the container would write through the link. Use a directory that is not a symlink and is not reached through one below the source directory."
        }

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
            # The config as named, and the real file the runner would mount
            # (Get-AshRealPath, above, with $sourceReal).
            $configNamed = (Get-Item -LiteralPath $Config).FullName
            $configFull = Get-AshRealPath $configNamed
            Assert-Mountable 'config file' $configFull
            # The scanned tree, as a local scan defines it: the outermost directory at
            # or above SourceDir holding a .git entry, found from SourceDir's name and
            # from its real path, each under both names.
            $trees = @()
            foreach ($start in @($sourceDirFull, $sourceReal)) {
                $checkout = $start
                $dir = Get-Item -LiteralPath $start
                while ($null -ne $dir) {
                    if (Test-Path -LiteralPath (Join-Path $dir.FullName '.git')) {
                        $checkout = $dir.FullName
                    }
                    $dir = $dir.Parent
                }
                $trees += $checkout
                $trees += (Get-AshRealPath $checkout)
            }
            $namedInTree = @($trees | Where-Object { Test-AshUnder $configNamed $_ }).Count -gt 0
            $realInTree = @($trees | Where-Object { Test-AshUnder $configFull $_ }).Count -gt 0
            # A config named inside the scanned tree is used only when its real path,
            # every link on the way followed, is inside the tree too, wherever in the
            # tree it is named: otherwise the repository being scanned would choose
            # which host file is read. A link that stays inside the tree is followed.
            if ($namedInTree -and -not $realInTree) {
                Stop-AshRefusal 3 "The config file '$Config' is inside the scanned tree but is a link, or is reached through one, to '$configFull', which is outside it. ASH does not mount a file the repository being scanned points it at."
            }
            if (Test-AshUnder $configFull $sourceReal) {
                $configInner = "/src/" + $configFull.Substring($sourceReal.TrimEnd($separators).Length + 1).Replace('\', '/')
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
                # A config elsewhere in the scanned tree was written by the repository
                # being scanned. The scan inside sees it only at /ash-config, outside its
                # own tree, so it is told.
                $configFromRepository = $realInTree
                # A config inside any other git checkout is one a local scan counts as
                # repository-written too (config/sandbox_grants.repository_written), so
                # it is marked; the link check above stays with the scanned tree.
                $dir = Get-Item -LiteralPath (Split-Path -Parent $configFull)
                while ($null -ne $dir) {
                    if (Test-Path -LiteralPath (Join-Path $dir.FullName '.git')) {
                        $configInCheckout = $true
                        break
                    }
                    $dir = $dir.Parent
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
            # As in begin: whatever raised, $LASTEXITCODE is not left at 0. Rethrown
            # as it is: writing it as an error record first showed it twice.
            if (-not $global:LASTEXITCODE) { $global:LASTEXITCODE = 1 }
            throw
        }
    }
}

function Stop-AshRefusal {
    <#
    .SYNOPSIS
    End an Invoke-ASH run that is refused: set $LASTEXITCODE to its code and throw.

    .DESCRIPTION
    It never calls `exit`. In a function a script dot-sources, `exit` ends that whole
    script, so its caller could neither handle the refusal nor go on. The thrown
    error carries the message; a caller that catches it reads the code from
    $LASTEXITCODE, and a CI step that needs the code exits with it:
    `try { Invoke-ASH ... } catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }`,
    under `shell: pwsh -File {0}` on GitHub Actions. Uncaught, `pwsh -File` and `pwsh -Command` exit 1, as PowerShell does for any
    uncaught error. The code is set first, before anything else can raise.
    #>
    param([int]$ExitCode, [string]$Message)
    $global:LASTEXITCODE = $ExitCode
    throw "ERROR: $Message"
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
