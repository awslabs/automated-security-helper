function Invoke-ASH {
    <#
    .SYNOPSIS
    Provides a PowerShell entrypoint to build and invoke ASH as a container executable.

    .DESCRIPTION
    Provides a PowerShell entrypoint to build and invoke ASH as a container executable.

    When Invoke-ASH refuses its input, it sets $LASTEXITCODE to 3, the code ASH uses
    for input it refuses, and throws, before anything is built or run. That covers a
    parameter given an empty or blank value, an -OutputDir that is reached through a
    link, a -BuildTarget other than ci or non-root,
    an image name or ASH_BASE_IMAGE_OVERRIDE that starts with '-' or holds a character
    other than A-Z, a-z, 0-9 and . _ : / @ -, an -AshArgs it cannot read, a
    --workspace or --workspace-config among ASH's arguments (Invoke-ASH scans one
    directory), no OCI runner, and a malformed ASH_BASE_OCI_LAYOUT. The exceptions are
    the usage errors `ash` itself refuses with 5, refused the same way with 5 and its
    text: a --sandbox among ASH's arguments with a mode other than off, because the
    scanners run unsandboxed inside the container; a -SourceDir that does not exist,
    is not a directory, or cannot be entered; and an -OutputDir that is a file, cannot
    be created, cannot be entered, or cannot be written. The throw does
    not end the caller's session; a script that does not catch it ends with 1, as
    PowerShell ends any script on an uncaught error. A failed build keeps the build's
    exit code.

    A script that should end with Invoke-ASH's own exit code (3 for a refusal, the
    build's code for a failed build) wraps the call:

        try { Invoke-ASH ... } catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }

    The Write-Error reports the error, which the catch would otherwise hide. The 1 is
    for an error PowerShell raises itself, before Invoke-ASH runs: a parameter given
    with no value, or a parameter name it cannot place (an ambiguous prefix such as
    -Con). Those are PowerShell's binding errors, not refusals of Invoke-ASH's, and
    they leave $LASTEXITCODE unset, so `exit $LASTEXITCODE` alone would exit 0. Start
    such a script with `pwsh -File`: `pwsh -Command`, which GitHub's stock
    `shell: pwsh` uses, reports any exit code a script sets, other than 0, as 1.

    A config reaches the scan in the container through -Config and through ASH_CONFIG,
    the rule ./ash also follows: the file a set ASH_CONFIG names is mounted read-only at
    /ash-env-config and named to the scan as the host's config, whether or not -Config
    is given, and the scan reads it as its --config only when none was given -- an
    explicit option wins, and ASH_CONFIG fills in only when none was given. A
    Windows host path works there, because the scan sees the container path. A file
    inside the source directory is read through /src instead of being mounted. An
    ASH_CONFIG that names no regular, readable file is refused with 3, and so is one
    outside the source directory that has an `extends` entry, since the files it extends
    are not mounted with it, and so is a file named inside the scanned tree that a link
    leads out of it, since the scanned repository would choose which host file is
    mounted. A mounted file that the scanned repository wrote (it is inside the scanned
    checkout, or its name goes through a link that sits there) is passed with the marks
    that tell the scan so. This applies only to a run that will happen: under -NoRun
    nothing is resolved, refused or warned about. -Config is passed in the spelling
    given and resolves in the container (see -Config).

    .PARAMETER SourceDir
    The source directory to scan with ASH.

    Defaults to the current working directory. Read as a literal path, so a directory
    named `src[1]` is that directory. Refused with 5, ASH's usage-error code,
    when it does not exist, is not a directory, or cannot be entered, with the text
    `ash scan` gives for the same input.

    .PARAMETER OutputDir
    The output directory for ASH results to be stored in.

    Defaults to `.ash/ash_output` within the current working directory, as with `./ash`.
    Created when it does not exist. Refused with 5, as `ash scan` refuses it, when a
    file is at the path, when a directory cannot be created there (a file on the way
    to it, for one), and when it is there but cannot be entered or written (a file is
    made there and deleted to find out).
    Refused when it is a link, or is reached through a link below the working directory
    or inside -SourceDir, where the scanned repository could have placed one. In CI the
    working directory is the scanned checkout, so a link anywhere under it counts,
    including a linked directory passed as -SourceDir. The refusal names the link; pass
    the resolved path instead, with no link in it.

    .PARAMETER Config
    Path to the ASH configuration file, passed to ASH in the container as `--config`,
    in the spelling given. The scan resolves it in the container, whose working
    directory is the mounted source directory: a path under the source directory
    reaches the file, and a host path outside the mounted directories does not exist
    there, so the scan refuses it by name.

    The file a set `$env:ASH_CONFIG` names is mounted read-only at `/ash-env-config`
    and the scan is given its container path as the host's config, with or without
    -Config, and as `--config` when -Config is not given, so a Windows absolute path
    works and a relative value does not re-resolve against the source directory. A
    file named inside the scanned tree that a link leads out of it is refused with 3
    before anything is built. With neither, ASH looks for a configuration file in the
    source directory.

    .PARAMETER AshArgs
    Additional arguments to pass to ASH, as one string that PowerShell's tokenizer
    splits the way it splits a command line: a quoted value is one argument, spaces
    and all, and pieces with no space between them are one argument, so
    `sarif,html` stays `sarif,html`. Variables are not expanded. A token that is not
    an argument (`;`, `|`, `&`, `>`, a `$variable`, `$(...)`, `@(...)`, or a comment)
    is refused, and so is a word or a double-quoted string that PowerShell would
    expand, such as `x$a`, `a$(y)`, `$a/b` or `"dq$a"`: on a command line it would
    hold a variable's value or a command's output, not the text typed. Single-quote
    a value holding a `$` inside -AshArgs, as in `--config-overrides 'a.b=$x'`, to
    pass it to ASH as typed. PowerShell reads the typographic quotes U+2018, U+2019,
    U+201A, and U+201B as single quotes, so put a value holding one, such as O'Neil
    spelled with U+2019, in double quotes.

    Three arguments are handled here, as `./ash` handles them: `--force` rebuilds the
    image without the build cache, `-q` or `--quiet` quiets the build and passes
    `--quiet`, and `-c` or `--no-color` passes `--no-color`. Every other argument is
    passed through unchanged. ASH's source and output directories reach the
    container as `ASH_SOURCE_DIR` and `ASH_OUTPUT_DIR`, so a subcommand such as
    `report` can come first. That is also why `--workspace` and `--workspace-config`
    are refused with exit 3, before anything is built: the scan inside refuses a
    workspace next to a source directory. Run `ash --mode container --workspace
    <file>` for a workspace scan.

    The first argument that names an ash subcommand is the subcommand, unless it is
    the value of an ash option that takes one (`--phases report` names no
    subcommand). The options Invoke-ASH adds from its own parameters (-Config,
    -Scanners, -Offline, -Verbose, and the rest, and --quiet and --no-color from the
    arguments above) go right after it, and only those it takes. Invoke-ASH does not
    pass the others, and warns about each except --quiet and --no-color, which have
    already quieted the build and kept the container off a terminal. With no
    subcommand, ash scans and takes them all.

    .PARAMETER RemainingAshArgs
    Arguments after Invoke-ASH's own parameters, handled like those in -AshArgs. Each
    is passed to ASH as one argument. The first of them is -SourceDir, which takes
    position 0, unless -SourceDir is given: `Invoke-ASH report` takes report as
    -SourceDir, so it scans a directory named report, and is refused with 5 when
    there is none. `Invoke-ASH -SourceDir . report` runs `ash report`. PowerShell reads
    them before Invoke-ASH does: a comma list such as `sarif,html` is rejoined with
    commas, but a bare `-c` is an ambiguous prefix of -Config, -ContainerUID, and
    -ContainerGID and is refused by PowerShell, so write it as '-c' or put it in
    -AshArgs.

    .PARAMETER OCIRunner
    Preferred OCI runner CLI tool to use, e.g. `docker`, `finch`, `nerdctl`, or `podman`.

    Supports tab-completion of common OCI runner CLI tools or overriding to provide
    something else entirely.

    Defaults to `$env:OCI_RUNNER` if set, the variable `./ash` and the ash CLI read,
    otherwise the first of `finch`, `docker`, `nerdctl`, and `podman` found in PATH.
    `$env:ASH_OCI_RUNNER`, the deprecated name, is honored when `OCI_RUNNER` is unset,
    with a deprecation warning.

    .PARAMETER AshImageName
    The image to build and run. Defaults to `$env:ASH_IMAGE_NAME` if it is set and not
    empty, otherwise `automated-security-helper`. A name without a tag gets
    `:<BuildTarget>`. It may
    hold only A-Z, a-z, 0-9 and . _ : / @ -, and may not start with '-', as ./ash
    requires of ASH_IMAGE_NAME; any other name is refused with 3. A registry named by
    a bracketed IPv6 literal, such as [::1]:5000, is refused too, since [ and ] are not
    among them: name the registry by a host name instead.

    .PARAMETER Scanners
    Scanners to run, passed to ASH as one `--scanners` per name.

    .PARAMETER ExcludeScanners
    Scanners to skip, passed to ASH as one `--exclude-scanners` per name.

    .PARAMETER IgnoreSuppressions
    If $true, passes `--ignore-suppressions` to ASH.

    .PARAMETER Progress
    `-Progress` passes `--progress` and `-Progress:$false` passes `--no-progress`.
    Unset, ASH's own default applies, as with `./ash`.

    .PARAMETER ShowSummary
    `-ShowSummary` passes `--show-summary` and `-ShowSummary:$false` passes
    `--no-show-summary`. Unset, ASH's own default (show it) applies.

    .PARAMETER NoFailOnFindings
    `-NoFailOnFindings` passes `--no-fail-on-findings` and `-NoFailOnFindings:$false`
    passes `--fail-on-findings`. Unset, the configuration's `fail_on_findings` decides,
    as with `./ash` and `ash --mode container`. A configuration file in the scanned
    repository can therefore set its own verdict, `fail_on_findings: false` included,
    so a gate that must fail on findings pins it: with `-NoFailOnFindings:$false`,
    which takes precedence over any configuration, or with an operator configuration
    named by -Config that sets `fail_on_findings: true`, which is used in place of the
    repository's own file (see -Config).

    .PARAMETER NoBuild
    If $true, skips the `OCI_RUNNER build ...` call.

    Requires target image tag to be present on the host already, either through a previous
    build or by pulling from a registry.

    .PARAMETER NoRun
    If $true, skips the `OCI_RUNNER run ...` call.

    Used primarily when a rebuild is needed during development of ASH, but a re-run of
    the ASH scan is not needed after build.

    .PARAMETER ContainerUID
    The UID the image is built for, passed to the build as `--build-arg UID=...`.

    Defaults to the current user's UID (`id -u`) on Linux and macOS, as `./ash` and
    `ash --mode container` do, so the container can write a host-owned output
    directory. On Windows, and for a caller running as root, it is not passed, and the
    image's default (500) applies.

    .PARAMETER ContainerGID
    The GID the image is built for, passed to the build as `--build-arg GID=...`.

    Defaults to the current user's GID (`id -g`) on Linux and macOS. On Windows, and
    for a caller running as root, it is not passed, and the image's default (100)
    applies.

    .PARAMETER Debug
    If $true, enables debug output.

    .PARAMETER OutputFormat
    Accepted so that existing scripts keep working, and ignored: ASH reads no
    output-format variable, and this function passes none to the container. Choose
    report formats with `-AshArgs '--output-formats sarif,html'`.

    Defaults to 'text'.

    .PARAMETER BuildTarget
    The target stage to build in the Dockerfile, `ci` or `non-root`, in any case. Any
    other value is refused with exit 3. Tab completion offers the two.

    Defaults to `ci` when `CI`, `IsCI`, `ISCI`, or `CODEBUILD_BUILD_ID` is set, the
    variables `ash --mode container` reads, on Windows, or under PowerShell 5, and to
    `non-root` otherwise. Off Windows the names are case-sensitive. A variable set to an
    empty value counts as unset here, where `ash --mode container` counts it as set.
    `./ash` reads none of them and builds `non-root` unless given --build-target.

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
        # Checked in the body, not with ValidateScript: see the checks at the top of
        # the begin block.
        [parameter(Position = 0)]
        [string]
        $SourceDir = (Get-Location).Path,
        [parameter()]
        [string]
        # Two Join-Paths: one with a third path binds only from PowerShell 6.
        $OutputDir = $(Join-Path (Join-Path (Get-Location).Path '.ash') 'ash_output'),
        [parameter()]
        [string]
        $Config,
        [parameter()]
        [string]
        $OCIRunner = $env:OCI_RUNNER,
        [parameter()]
        [string]
        # An empty ASH_IMAGE_NAME is unset, as ./ash reads it: off Windows pwsh keeps
        # it as '' rather than $null, and a $null test made the default ''.
        $AshImageName = $(if (-not [string]::IsNullOrEmpty($env:ASH_IMAGE_NAME)) {
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
        # Checked in the body, not with ValidateSet, and completed by the argument
        # completer registered after this function.
        [parameter()]
        [string]
        # The CI variables `ash --mode container` reads (run_ash_container.py).
        $BuildTarget = $(if($env:CI -or $env:IsCI -or $env:ISCI -or $env:CODEBUILD_BUILD_ID -or $PSVersionTable.PSVersion.Major -le 5 -or $IsWindows){"ci"}else{"non-root"}),
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
        [parameter()]
        [string]
        $AshArgs,
        [parameter(ValueFromRemainingArguments)]
        [object[]]
        $RemainingAshArgs
    )
    begin {
        # A refusal (Stop-AshRefusal) sets $LASTEXITCODE before it throws. Any other
        # error raised here, such as an output directory that cannot be created under
        # Stop, leaves it at 1 when it is 0, so a CI step's catch block, which exits
        # with $LASTEXITCODE (see .EXAMPLE), never exits 0 after a failure. `break`
        # rethrows the error unchanged.
        trap { if (-not $global:LASTEXITCODE) { $global:LASTEXITCODE = 1 }; break }
        # Invoke-ASH scans one directory: it hands the scan inside --source-dir /src,
        # which that scan refuses next to --workspace, after the container has
        # started. It also cannot tell the scan inside that a workspace's config was
        # written by the repository (a workspace scan refuses
        # --config-from-scanned-repository), so a config in the checkout but outside
        # the workspace would be read there as the operator's. A --workspace passed
        # through is refused before anything is built or mounted. The text is matched
        # with its quote characters and escape backticks removed, because the command
        # that runs it is parsed again and reads '"--workspace"' as --workspace.
        # This match is best-effort: that second parse can also spell the flag with a
        # subexpression ('--work$()space'), which is not looked for here. The control
        # that holds for every spelling is the scan inside, which refuses --workspace
        # next to the --source-dir /src it is always given, ahead of anything passed
        # through (see the run command below).
        if (("$AshArgs" -replace '["''`]', '') -match '(^|\s)--workspace(\s|=|$)') {
            Stop-AshRefusal 3 "Invoke-ASH scans one directory and cannot run a workspace scan: the scan inside the container is given --source-dir /src, which it refuses next to --workspace, and it could not be told which workspace config the repository wrote. Run ash --mode container --workspace <file> instead."
        }
        # ValidateSet and -eq ignore case, and so does the build: -BuildTarget NON-ROOT
        # is non-root. Lower-cased once, so the --target value and the image tag are too.
        $BuildTarget = $BuildTarget.ToLowerInvariant()
        $ashRoot = (Get-Item $PSScriptRoot).Parent.FullName
        $onWindows = ($PSVersionTable.PSVersion.Major -le 5) -or $IsWindows
        # The exit code every refusal leaves in $LASTEXITCODE before it throws: 3, the
        # code ASH uses for input it refuses, as ./ash and utils/ash_helpers.sh do.
        # A failed build is not a refusal and keeps the build's own code.
        $refusalExitCode = 3
        # The code, and below the text, `ash scan`, ./ash and the MCP server give a
        # -SourceDir that names no directory to scan and an -OutputDir that is a file:
        # 5, ASH's usage-error code (automated_security_helper/utils/directory_refusals.py).
        $usageErrorExitCode = 5
        # The characters an image name and a base image reference may hold, for both
        # checks below, so the two cannot drift apart: A-Z, a-z, 0-9 and . _ : / @ -,
        # as ./ash requires. Matched with -cnotmatch (case-sensitive, so [A-Za-z] is
        # those 52 code points in every culture) and anchored with \z, not $, which
        # also matches before a final newline.
        $imageReferencePattern = '\A[A-Za-z0-9._:/@-]+\z'

        # The values the caller gave, checked before anything is read, built or run.
        # Here, not in ValidateScript and ValidateSet attributes: those refuse in
        # PowerShell's parameter binding, before Invoke-ASH runs, with $LASTEXITCODE
        # unset, so a script would end with 1, or with 0 under `exit $LASTEXITCODE`.
        #
        # A parameter given an empty or blank value is refused, as ./ash refuses an
        # option given one, so an empty -OCIRunner does not fall back to whichever
        # runner is on PATH. Only bound parameters are read, so an -OCIRunner that defaults from an
        # empty OCI_RUNNER still discovers a runner, and an empty -AshArgs is no extra
        # arguments.
        foreach ($name in @('SourceDir', 'OutputDir', 'Config', 'OCIRunner', 'AshImageName', 'ContainerUID', 'ContainerGID', 'OutputFormat', 'BuildTarget', 'OfflineSemgrepRulesets', 'Scanners', 'ExcludeScanners')) {
            if (-not $PSBoundParameters.ContainsKey($name)) {
                continue
            }
            $given = @($PSBoundParameters[$name])
            if ($given.Count -eq 0 -or @($given | Where-Object { [string]::IsNullOrWhiteSpace("$_") }).Count -gt 0) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "-$name needs a value: it was given an empty or blank one."
            }
        }
        # ci and non-root are the stages the Dockerfile has. Case is ignored, as
        # ValidateSet ignored it, and nothing else is: compared ordinally, since -notin
        # compares with the culture, which ignores control and format characters, so
        # 'ci' followed by ESC or U+200B was taken as ci.
        $knownStage = @('ci', 'non-root') | Where-Object { [string]::Equals($BuildTarget, $_, [System.StringComparison]::OrdinalIgnoreCase) }
        if (-not $knownStage) {
            $global:LASTEXITCODE = $refusalExitCode
            throw "-BuildTarget '$(Format-AshShownValue $BuildTarget)' is not a stage the image has. Use ci or non-root."
        }
        # -LiteralPath, so a directory named src[1] is that directory: Test-Path $_
        # read the name as a wildcard and matched src1, or nothing. A directory of the
        # file system, not any provider's container: Env: and Function: passed a
        # Test-Path -PathType Container, and then Invoke-ASH failed reading FullName.
        # In the words and the order ./ash and `ash scan` use: whether the path can be
        # reached, whether it is a directory, and whether its entries can be both
        # listed and entered. A path under a directory that cannot be searched is
        # denied, not missing, whether or not it is there.
        $sourceErrors = $null
        $sourceItem = Get-Item -LiteralPath $SourceDir -Force -ErrorAction SilentlyContinue -ErrorVariable sourceErrors
        if ($null -eq $sourceItem) {
            $global:LASTEXITCODE = $usageErrorExitCode
            if ($sourceErrors | Where-Object { $_.Exception -is [System.UnauthorizedAccessException] }) {
                throw "Source directory cannot be entered: $(Format-AshShownValue $SourceDir)"
            }
            throw "Source directory does not exist: $(Format-AshShownValue $SourceDir)"
        }
        # Get-Item gives a link itself, so a link to nothing read as a file. Its final
        # target is what ./ash's -e and `ash scan`'s stat look at: a link to nothing,
        # or one that leads back to itself, which ResolveLinkTarget throws for, names
        # nothing. Windows PowerShell has no ResolveLinkTarget and keeps the item.
        if ($sourceItem.LinkType -in @('SymbolicLink', 'Junction') -and $sourceItem.PSObject.Methods['ResolveLinkTarget']) {
            $linkTarget = $null
            $linkDenied = $false
            try {
                $linkTarget = $sourceItem.ResolveLinkTarget($true)
            }
            catch [System.UnauthorizedAccessException] {
                $linkDenied = $true
            }
            catch [System.IO.IOException] {
                $linkTarget = $null
            }
            if (-not $linkDenied -and ($null -eq $linkTarget -or -not $linkTarget.Exists)) {
                # Exists is false for a target that is not there and for one that cannot
                # be reached alike. Opening it through the link tells them apart, as
                # stat does for `ash scan`: denied, or not found.
                try {
                    $null = [System.IO.Directory]::EnumerateFileSystemEntries($sourceItem.FullName).GetEnumerator().MoveNext()
                }
                catch [System.UnauthorizedAccessException] {
                    $linkDenied = $true
                }
                catch {
                    # Not there, or a link that leads back to itself.
                }
            }
            if ($linkDenied) {
                $global:LASTEXITCODE = $usageErrorExitCode
                throw "Source directory cannot be entered: $(Format-AshShownValue $SourceDir)"
            }
            if ($null -eq $linkTarget -or -not $linkTarget.Exists) {
                $global:LASTEXITCODE = $usageErrorExitCode
                throw "Source directory does not exist: $(Format-AshShownValue $SourceDir)"
            }
        }
        if (-not ($sourceItem -is [System.IO.DirectoryInfo])) {
            $global:LASTEXITCODE = $usageErrorExitCode
            throw "Source directory is not a directory: $(Format-AshShownValue $SourceDir)"
        }
        # Listing its entries needs read permission. Looking a name up in it needs
        # search permission, which listing does not: a name that is not there is
        # "not found" in a directory that can be searched and "denied" in one that
        # cannot.
        try {
            $null = [System.IO.Directory]::EnumerateFileSystemEntries($sourceItem.FullName).GetEnumerator().MoveNext()
            $null = [System.IO.File]::GetAttributes([System.IO.Path]::Combine($sourceItem.FullName, '.ash-search-check'))
        }
        catch [System.UnauthorizedAccessException] {
            $global:LASTEXITCODE = $usageErrorExitCode
            throw "Source directory cannot be entered: $(Format-AshShownValue $SourceDir)"
        }
        catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
            # The name is not there, so the directory can be searched.
        }
        # -OutputDir names a place in the file system as well, refused here, before the
        # output directory is resolved, created or checked for links: a drive that does
        # not exist failed with exit 1, and a path in another provider was taken (Env:/x
        # made ./x).
        $outputProvider = $null
        $outputDrive = $null
        try {
            [void]$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir, [ref]$outputProvider, [ref]$outputDrive)
        }
        catch {
            $global:LASTEXITCODE = $refusalExitCode
            throw "-OutputDir '$(Format-AshShownValue $OutputDir)' is not a path in the file system ($(Format-AshShownValue $_.Exception.Message)). Name a directory, or a path to create one at."
        }
        if ($outputProvider.Name -ne 'FileSystem') {
            $global:LASTEXITCODE = $refusalExitCode
            throw "-OutputDir '$(Format-AshShownValue $OutputDir)' is in PowerShell's $($outputProvider.Name) provider, not in the file system. Name a directory, or a path to create one at."
        }
        # ASH_BASE_IMAGE_OVERRIDE is a base image reference, so it holds the characters
        # an image name may (see the image-name check below), as ./ash requires. It is
        # read here, with the other input, before anything is built or run.
        $baseImageOverride = $env:ASH_BASE_IMAGE_OVERRIDE
        if ($baseImageOverride -and ($baseImageOverride -clike '-*' -or $baseImageOverride -cnotmatch $imageReferencePattern)) {
            $global:LASTEXITCODE = $refusalExitCode
            throw "ASH_BASE_IMAGE_OVERRIDE '$(Format-AshShownValue $baseImageOverride)' starts with '-' or holds a character other than A-Z, a-z, 0-9 and . _ : / @ -, which no image reference does. Name an image reference with only those characters, or unset it to build from the Dockerfile's own base image reference."
        }

        # Each value has to reach the runner as one argument. Under 'Legacy' native
        # argument passing PowerShell wraps an argument holding a space in double quotes
        # without escaping the quotes inside it, so a value of `q" --privileged ` merged
        # with its neighbors and left --privileged as an argument of its own. This scope
        # uses the standard rules instead ('Windows' on Windows, which is Standard except
        # for batch files and a few programs that need the old quoting). PowerShell
        # before 7.3 has only the legacy rules, and a batch file gets them under every
        # version and has its arguments parsed again by cmd.exe; what those would
        # break is refused by Assert-AshArgumentsPassWhole before the runner starts.
        if ($PSNativeCommandArgumentPassing -eq 'Legacy') {
            $PSNativeCommandArgumentPassing = if ($onWindows) { 'Windows' } else { 'Standard' }
        }
        $legacyArgumentsOnly = $PSVersionTable.PSVersion -lt [version]'7.3'
        function Assert-OneArgumentEach([object[]]$Arguments, [string[]]$Programs) {
            # The first of the programs the arguments reach that is a batch file: the
            # one started (the wrapper, when there is one), or the runner it starts.
            $batchFile = ''
            if ($onWindows) {
                foreach ($program in @($Programs | Where-Object { $_ })) {
                    $found = Get-Command $program -ErrorAction SilentlyContinue | Select-Object -First 1
                    $path = if ($found -and $found.CommandType -eq 'Application') { $found.Source } else { $program }
                    if ([System.IO.Path]::GetExtension($path) -in @('.bat', '.cmd')) {
                        $batchFile = $path
                        break
                    }
                }
            }
            Assert-AshArgumentsPassWhole -Arguments $Arguments -LegacyQuoting:$legacyArgumentsOnly -BatchFile $batchFile
        }
        $buildArgs =[System.Collections.Generic.List[string]]::new()
        $runArgs = [System.Collections.Generic.List[string]]::new()
        # The options Invoke-ASH adds for ash, each with its values as one group, so a
        # subcommand that does not take an option drops its value with it.
        $ashCmdArgs = [System.Collections.Generic.List[object]]::new()

        # Build for the caller's UID and GID, as ./ash and `ash --mode container` do. Only
        # -ContainerUID and -ContainerGID were passed, so the image ran as its default
        # 500:100, which cannot write an output directory the caller owns with mode 0755.
        # Not on Windows, which has no id; PowerShell 5 runs only there. Only for a build,
        # the one place they are used.
        if (-not $NoBuild -and -not $onWindows -and (-not $ContainerUID -or -not $ContainerGID)) {
            if (Get-Command id -ErrorAction SilentlyContinue) {
                $callerUID = "$(& id -u)".Trim()
                # A root caller is the exception. ./ash and `ash --mode container` pass
                # UID=0 for one, which the non-root stage's adduser refuses (root exists),
                # so the image's own 500:100 is kept instead.
                if ($callerUID -match '^0+$') {
                    if ($BuildTarget -eq 'non-root') {
                        Write-Warning "Running as root, so the image is built for its default UID and GID (500:100), which cannot write an output directory that only root may write to. Pass -BuildTarget ci for the image that runs as root, or -ContainerUID and -ContainerGID."
                    }
                }
                else {
                    if (-not $ContainerUID) {
                        $ContainerUID = $callerUID
                    }
                    if (-not $ContainerGID) {
                        $ContainerGID = "$(& id -g)".Trim()
                    }
                }
            }
            else {
                Write-Warning "id is not on PATH, so the image is built for its default UID and GID (500:100). Pass -ContainerUID and -ContainerGID to choose them."
            }
        }
        # -ContainerUID and -ContainerGID become build arguments, read as numbers.
        foreach ($id in @(@('UID', $ContainerUID), @('GID', $ContainerGID))) {
            # \A and \z: .NET's ^ and $ also match around a final line feed.
            if ($id[1] -and "$($id[1])" -notmatch '\A[0-9]+\z') {
                $global:LASTEXITCODE = $refusalExitCode
                throw "Container $($id[0]) must be a numeric value: '$(Format-AshShownValue $id[1])'."
            }
        }
        # The non-root stage creates its user with `adduser --uid <UID> --gid <GID>`.
        # UID 0 is root, which already exists, and GID 0 is root's group. A non-root
        # build with either is refused before building, as ./ash and `ash --mode
        # container` refuse it; a caller running as root keeps the image's default
        # IDs above, so this names -ContainerUID or -ContainerGID 0 (any spelling of
        # zero). -BuildTarget ci is the opt-in for the image that runs as root.
        if (-not $NoBuild -and $BuildTarget -eq 'non-root') {
            if ("$ContainerUID" -match '\A0+\z') {
                $global:LASTEXITCODE = $refusalExitCode
                throw "The non-root image stage creates a user with UID 0, which is root: -ContainerUID 0 was given. Pass -BuildTarget ci to build the image that runs as root. Another -ContainerUID and -ContainerGID work only when the output directory is writable by that UID: the container runs as that user and writes its reports there."
            }
            if ("$ContainerGID" -match '\A0+\z') {
                $global:LASTEXITCODE = $refusalExitCode
                throw "The non-root image stage gives its user GID 0, which is root's group: -ContainerGID 0 was given. Pass -BuildTarget ci to build the image that runs as root. Another -ContainerGID works only when the output directory is writable by the container's user, which writes its reports there."
            }
        }

        # -AshArgs is one string. It is read with PowerShell's own tokenizer, so a quoted
        # value is one argument with its spacing, and pieces with no space between them
        # are one argument too: `sarif,html`, a word, a comma, and a word, stays
        # `sarif,html`. The words are handed to the runner as array elements and never
        # parsed again. A token that is not an argument is refused rather than taken
        # literally, since PowerShell would not take it literally either. So is one
        # PowerShell would expand, checked with its own parser below.
        $ashArgWords = [System.Collections.Generic.List[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace($AshArgs)) {
            $ashArgsLine = "Invoke-ASH $AshArgs"
            $tokenErrors = $null
            $tokens = [System.Management.Automation.PSParser]::Tokenize($ashArgsLine, [ref]$tokenErrors)
            if (@($tokenErrors).Count -gt 0) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "-AshArgs could not be read as arguments: $(Format-AshShownValue $tokenErrors[0].Message) PowerShell also reads the quotes U+2018, U+2019, U+201A, and U+201B as single quotes; put a value holding one in double quotes."
            }
            $word = $null
            $wordEnd = -1
            foreach ($token in @($tokens | Select-Object -Skip 1)) {
                $tokenType = "$($token.Type)"
                if ($tokenType -in @('NewLine', 'LineContinuation')) {
                    continue
                }
                if ($tokenType -in @('CommandArgument', 'CommandParameter', 'String', 'Number')) {
                    $piece = [string]$token.Content
                }
                elseif ($tokenType -eq 'Operator' -and $token.Content -eq ',') {
                    $piece = ','
                }
                else {
                    $text = $ashArgsLine.Substring($token.Start, $token.Length)
                    $global:LASTEXITCODE = $refusalExitCode
                    throw "-AshArgs holds '$(Format-AshShownValue $text)', which PowerShell reads as $tokenType, not as an argument. Put it in single quotes to pass it to ASH as typed."
                }
                if ($null -ne $word -and $token.Start -eq $wordEnd) {
                    $word += $piece
                }
                else {
                    if ($null -ne $word) {
                        $ashArgWords.Add($word)
                    }
                    $word = $piece
                }
                $wordEnd = $token.Start + $token.Length
            }
            if ($null -ne $word) {
                $ashArgWords.Add($word)
            }
            # The tokenizer types a bare word holding a $ (x$a, a$(y), $a/b) as an
            # argument, and a double-quoted string holding one as a string, so the loop
            # above takes their text. PowerShell's parser reads either as an expandable
            # string, with a variable's value or a command's output in place of the $
            # part, so ASH would get a different value from the one PowerShell would
            # make of it on a command line. Refused, as a bare $variable is; a
            # single-quoted string is never expanded. The parser's own check is an
            # allowlist: an argument is taken only as a constant (a string, quoted or
            # not, or a number), a parameter name with no value or a constant one, or
            # a comma list of those. Every other node (a variable, a member or method
            # call, $( ), @( ), @{ }, a splat, a script block, a type or a
            # parenthesized expression) is refused here whatever the loop above made
            # of its tokens. In every input measured, the parser found no error the
            # tokenizer missed; if it ever does, the input is refused as one the
            # tokenizer could not read.
            $parseTokens = $null
            $parseErrors = $null
            $ashArgsAst = [System.Management.Automation.Language.Parser]::ParseInput($ashArgsLine, [ref]$parseTokens, [ref]$parseErrors)
            if (@($parseErrors).Count -gt 0) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "-AshArgs could not be read as arguments: $(Format-AshShownValue $parseErrors[0].Message)"
            }
            $isTypedArgument = {
                param($node)
                if ($node -is [System.Management.Automation.Language.ConstantExpressionAst]) {
                    return $true
                }
                if ($node -is [System.Management.Automation.Language.CommandParameterAst]) {
                    return ($null -eq $node.Argument) -or (& $isTypedArgument $node.Argument)
                }
                if ($node -is [System.Management.Automation.Language.ArrayLiteralAst]) {
                    return @($node.Elements | Where-Object { -not (& $isTypedArgument $_) }).Count -eq 0
                }
                return $false
            }
            # The first command is Invoke-ASH itself, the word the line starts with;
            # the loop above has refused anything that would start another.
            $ashArgsCommand = $ashArgsAst.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $false)
            foreach ($element in @($ashArgsCommand.CommandElements | Select-Object -Skip 1)) {
                if (-not (& $isTypedArgument $element)) {
                    $global:LASTEXITCODE = $refusalExitCode
                    throw "-AshArgs holds '$(Format-AshShownValue $element.Extent.Text)', which PowerShell would expand rather than pass as typed. Put it in single quotes to pass it to ASH as typed."
                }
            }
        }
        # PowerShell has already split these. A comma list arrives as an array, which
        # [string] would join with spaces; it is joined with the commas it was written
        # with.
        foreach ($item in @($RemainingAshArgs)) {
            if ($null -eq $item) {
                continue
            }
            if ($item -is [array]) {
                $ashArgWords.Add((@($item) | ForEach-Object { "$_" }) -join ',')
            }
            else {
                $ashArgWords.Add("$item")
            }
        }

        # The scan inside the container runs its scanners unsandboxed (container mode
        # never sandboxes inside the image; the container is the boundary), so a
        # sandbox asked for here would not be applied. Refused as a usage error before
        # the image is built, as `ash scan --mode container --sandbox <mode>` and ./ash
        # refuse it. Every
        # --sandbox counts, since the scan inside takes the last one, and so does one
        # with no mode or a value that is not a mode. Refused by throwing with
        # $LASTEXITCODE set: `exit` would end the session of a caller who dot-sourced
        # this file, and Write-Error throws before an `exit` under
        # $ErrorActionPreference = 'Stop'. The words are the ones read above, so a
        # quoted value is one word here as it is on the scan's command line.
        $sandboxRefusalExitCode = 5
        $sandboxModes = @('auto', 'bwrap', 'firejail', 'landlock', 'sandbox-exec')
        for ($i = 0; $i -lt $ashArgWords.Count; $i++) {
            if ($ashArgWords[$i] -ceq '--sandbox') {
                $sandboxMode = if ($i + 1 -lt $ashArgWords.Count) { $ashArgWords[$i + 1] } else { '' }
            }
            elseif ($ashArgWords[$i] -clike '--sandbox=*') {
                $sandboxMode = $ashArgWords[$i].Substring('--sandbox='.Length)
            }
            else {
                continue
            }
            # Ordinal, ignoring only case: -eq compares with the culture, which ignores
            # control and format characters, so 'off' followed by ESC or U+200B was off.
            if ([string]::Equals($sandboxMode, 'off', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            $global:LASTEXITCODE = $sandboxRefusalExitCode
            # Shown with its control and format characters written as escapes, so the
            # value cannot move the cursor, change colors or reverse the text in the
            # error view: Cc is C0, DEL and C1, so CSI (U+009B) as well as ESC.
            $shownMode = Format-AshShownValue $sandboxMode
            if (@($sandboxModes | Where-Object { [string]::Equals($sandboxMode, $_, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) {
                throw "--sandbox $shownMode cannot be used with ASH in a container: the scanners run unsandboxed inside the container. Run 'ash scan --mode local --sandbox $shownMode' to sandbox each scanner, or drop --sandbox."
            }
            throw "--sandbox '$shownMode' cannot be used with ASH in a container: it is not a sandbox mode, and off is the only one a container takes, since the scanners run unsandboxed inside it. To sandbox each scanner, run 'ash scan --mode local --sandbox <mode>' with one of $($sandboxModes -join ', ')."
        }

        # A workspace scan is refused over the same words, with exit 3, before anything
        # is built or mounted. Invoke-ASH scans one directory: the scan inside the
        # container is given ASH_SOURCE_DIR=/src, which counts as --source-dir and is
        # refused next to --workspace (exit 4, after the image was built), and
        # --workspace-config applies only to a workspace scan. `ash --mode container
        # --workspace <file>` mounts the workspace itself. This pass runs after the
        # sandbox pass, as ./ash runs its passes, so an explicit --sandbox other than
        # off is refused with 5 wherever it stands next to a --workspace.
        foreach ($argWord in $ashArgWords) {
            if ($argWord -cin @('--workspace', '--workspace-config') -or $argWord -clike '--workspace=*' -or $argWord -clike '--workspace-config=*') {
                $global:LASTEXITCODE = $refusalExitCode
                throw "Invoke-ASH scans one directory and cannot run a workspace scan: the scan inside the container is given --source-dir /src, which it refuses next to --workspace, and it could not be told which workspace config the repository wrote. Run ash --mode container --workspace <file> instead."
            }
        }

        # The -Config path is passed in the spelling the operator wrote, for the scan
        # in the container to resolve and judge. A set ASH_CONFIG is mounted read-only
        # at /ash-env-config and named to the scan by its container path, with or
        # without -Config (see the ASH_CONFIG carry below).

        # An image name that starts with '-' reaches the runner as an option of its own,
        # however it is quoted, so it is refused, as ./ash refuses it, before anything
        # is created or built. Beyond that it may hold only A-Z, a-z, 0-9 and
        # . _ : / @ -, the characters ./ash takes, with the same message: the build and
        # run commands are argument arrays, so any other value would reach the runner
        # whole, as an image name that no runtime takes. The pattern is
        # $imageReferencePattern, shared with the ASH_BASE_IMAGE_OVERRIDE check above;
        # -match would ignore case and take the Kelvin sign U+212A as K. -BuildTarget
        # is checked above.
        if ($AshImageName -clike '-*' -or $AshImageName -cnotmatch $imageReferencePattern) {
            $global:LASTEXITCODE = $refusalExitCode
            throw "The image name '$(Format-AshShownValue $AshImageName)' starts with '-', which the container runtime would read as an option, or holds a character other than A-Z, a-z, 0-9 and . _ : / @ -, which no image name does. Name an image with only those characters, not starting with '-'."
        }

        # The arguments that ./ash handles itself, compared whole and case-sensitively.
        # They were substring matches with -match, which ignores case, so any word
        # containing "-c" or "-q" (--config, --cleanup, a -ConfigFile typo) counted as -c
        # or -q. They are consumed rather than forwarded, as ./ash does: ash has no -q and
        # reads -c as --config.
        $wrapperWords = @('--force', '--quiet', '-q', '--no-color', '-c')
        $noColor = ($ashArgWords -ccontains '--no-color') -or ($ashArgWords -ccontains '-c')
        $forwardedAshArgs = @($ashArgWords | Where-Object { $_ -cnotin $wrapperWords })
        if ($ashArgWords -ccontains '--force') {
            $buildArgs.Add('--no-cache')
        }
        if (($ashArgWords -ccontains '--quiet') -or ($ashArgWords -ccontains '-q')) {
            $buildArgs.Add('-q')
            $ashCmdArgs.Add(@('--quiet'))
        }
        if ($noColor) {
            $ashCmdArgs.Add(@('--no-color'))
        }
        # Passed only when the caller asked, as ./ash does. These were always passed, which
        # overrode a configuration's fail_on_findings and printed no summary at all;
        # `ash --mode container` hides the summary inside the container only because it
        # prints its own on the host.
        if ($PSBoundParameters.ContainsKey('Progress')) {
            $ashCmdArgs.Add(@(if ($Progress) { '--progress' } else { '--no-progress' }))
        }
        if ($PSBoundParameters.ContainsKey('ShowSummary')) {
            $ashCmdArgs.Add(@(if ($ShowSummary) { '--show-summary' } else { '--no-show-summary' }))
        }
        if ($PSBoundParameters.ContainsKey('NoFailOnFindings')) {
            $ashCmdArgs.Add(@(if ($NoFailOnFindings) { '--no-fail-on-findings' } else { '--fail-on-findings' }))
        }
        # By value, as -Progress is: -Verbose:$false is bound too.
        $verboseRequested = $PSBoundParameters.ContainsKey('Verbose') -and [bool]$PSBoundParameters['Verbose']
        $debugRequested = $PSBoundParameters.ContainsKey('Debug') -and [bool]$PSBoundParameters['Debug']
        if ($verboseRequested) {
            $ashCmdArgs.Add(@('--verbose'))
        }
        if ($debugRequested) {
            $ashCmdArgs.Add(@('--debug'))
        }
        if ($Offline) {
            $ashCmdArgs.Add(@('--offline'))
        }
        if ($PSBoundParameters.ContainsKey('Config')) {
            $ashCmdArgs.Add(@('--config', $Config))
        }
        # A set ASH_CONFIG is carried for a scan whether or not -Config was given, as
        # ./ash carries it: the scan reads the file as its base config, and takes it as
        # its --config only when -Config did not name one (an explicit -Config wins).
        # Only a scan takes it, and the subcommand is not known yet, so only the place
        # in the argument list is remembered here. The groups are built once the file
        # is resolved below, for a scan, or the variable is warned about, for anything
        # else.
        $envConfigPending = -not [string]::IsNullOrEmpty($env:ASH_CONFIG)
        $envConfigAt = $ashCmdArgs.Count
        $envConfigGroups = [System.Collections.Generic.List[object]]::new()
        if ($PSBoundParameters.ContainsKey('Scanners')) {
            foreach ($scanner in $Scanners) {
                $ashCmdArgs.Add(@('--scanners', $scanner))
            }
        }
        if ($PSBoundParameters.ContainsKey('ExcludeScanners')) {
            foreach ($scanner in $ExcludeScanners) {
                $ashCmdArgs.Add(@('--exclude-scanners', $scanner))
            }
        }
        if ($IgnoreSuppressions) {
            $ashCmdArgs.Add(@('--ignore-suppressions'))
        }

        # ash takes an option given before a subcommand only when the subcommand
        # declares it, and refuses it otherwise (`ash --quiet report` exits 5). So the
        # options above go after the subcommand, and only to one that takes them, as
        # ./ash does for --quiet and --no-color; with no subcommand ash scans, and takes
        # all of them. The subcommand is the first argument that names one and is not a
        # root option's value, which can be a command's name (`--phases inspect`,
        # `--config config`). The command groups (config, dependencies, inspect, plugin)
        # take none of them ahead of their own subcommand. The caller's own arguments
        # stay in the order written. tests/unit/test_powershell_wrapper_tables.py checks
        # the tables against the real commands, and
        # tests/unit/test_sandbox_refused_by_every_container_entrypoint.py checks these
        # lists against ./ash's and the real commands and options.
        $ashSubcommands = @('scan', 'build-image', 'report', 'merge', 'mcp', 'get-genai-guide', 'config', 'dependencies', 'inspect', 'plugin')
        $ashTakesSandbox = @('scan')
        # The root ash options that take a value, ASH_ROOT_VALUE_OPTIONS in ./ash. A value
        # can be a subcommand's name (`--phases report`, `--source-dir report`), so the
        # word after one of these is the option's value, not the subcommand.
        $ashRootValueOptions = @('--ash-config-from-host', '--ash-plugin-modules', '--ash-revision-to-install', '--base-ref', '--build-target', '--config', '--config-file-from-scanned-repository', '--config-overrides', '--container-gid', '--container-uid', '--custom-build-arg', '--custom-containerfile', '--exclude-scanners', '--format', '--formats', '--log-level', '--min-severity', '--mode', '--oci', '--oci-runner', '--offline-semgrep-rulesets', '--output-dir', '--output-format', '--output-formats', '--phases', '--runner', '--sandbox', '--scanners', '--shard-count', '--shard-index', '--source-dir', '--strategy', '--workspace', '--workspace-config', '-c', '-f', '-g', '-o', '-u')
        $ashOptionSubcommands = @{
            '--quiet'                = 'scan build-image mcp'
            '--no-color'             = 'scan build-image report merge mcp'
            '--progress'             = 'scan'
            '--no-progress'          = 'scan'
            '--show-summary'         = 'scan'
            '--no-show-summary'      = 'scan'
            '--fail-on-findings'     = 'scan merge'
            '--no-fail-on-findings'  = 'scan merge'
            '--verbose'              = 'scan build-image report merge mcp'
            '--debug'                = 'scan build-image report merge mcp'
            '--offline'              = 'scan build-image'
            '--config'               = 'scan build-image report merge'
            '--scanners'             = 'scan'
            '--exclude-scanners'     = 'scan'
            '--ignore-suppressions'  = 'scan merge'
        }
        $subcommandAt = -1
        $subcommand = ''
        $skipValue = $false
        for ($i = 0; $i -lt $forwardedAshArgs.Count; $i++) {
            $word = $forwardedAshArgs[$i]
            if ($skipValue) {
                $skipValue = $false
                continue
            }
            if ($word -cin $ashSubcommands) {
                $subcommandAt = $i
                $subcommand = $word
                break
            }
            if ($word -cin $ashRootValueOptions) {
                # `--phases report` or `-f sarif`. `--phases=report` and `-fsarif`
                # carry their value in the same word.
                $skipValue = $true
            }
            elseif ($word -cmatch '^-[^-].') {
                # Clustered short options, as click reads them: the first letter that
                # takes a value takes the rest of the word, or the next word when it
                # is last.
                for ($at = 1; $at -lt $word.Length; $at++) {
                    if (('-' + $word[$at]) -cin $ashRootValueOptions) {
                        $skipValue = ($at + 1 -eq $word.Length)
                        break
                    }
                }
            }
        }

        # Resolve source and output directories. -LiteralPath: -Path reads '[', ']',
        # '*' and '?' as wildcards, so 'src[1]' would name 'src1'. New-Item has no
        # -LiteralPath and reads its -Path as written.
        $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)

        # A '..' goes to the parent of where the part before it really is, as the
        # operating system and ./ash apply it, not to the part before it in the
        # spelling: 'a/../b' with 'a' a link is the file beside what 'a' leads to.
        # [System.IO.Path]::GetFullPath and Get-Item's FullName drop the part before a
        # '..' without looking at it, so a path with a '..' is walked here instead.
        # A directory that cannot be searched has no parent to go up to (the OS refuses
        # 'locked/..'), so a '..' after one refuses the path.
        function Step-AshParent([string]$Real, [string]$Whole) {
            if (-not (Test-AshSearchable $Real)) {
                Stop-AshRefusal 3 "The path '$Whole' goes up with '..' from '$Real', which cannot be searched, so where it leads cannot be placed. Use a path without that '..'."
            }
            $parent = Split-Path -Parent $Real
            if ($parent) { return $parent }
            return [System.IO.Path]::GetPathRoot($Real)
        }

        # A relative path is made absolute the way PowerShell makes it for every other
        # command: from the session's current location, which Set-Location and
        # Push-Location move and the process's working directory does not follow, with
        # '~' and a PSDrive name read as PowerShell reads them. The path is spelled as
        # written, '..' included: PowerShell would drop the part before a '..' without
        # looking at it, so only the part before the first '..' is handed to it, and
        # the rest is kept for the walk below to apply.
        function Resolve-AshSpelling([string]$Path) {
            $match = [regex]::Match($Path, '(^|[/\\])\.\.([/\\]|$)')
            $head = $Path
            $tail = ''
            if ($match.Success) {
                $head = $Path.Substring(0, $match.Index)
                $tail = $Path.Substring($match.Index + $match.Groups[1].Length)
                if ($match.Index -eq 0 -and $match.Groups[1].Length -gt 0) {
                    $head = $match.Groups[1].Value
                }
                elseif ($head -match '^[A-Za-z]:$') {
                    $head += '\'
                }
            }
            if ([string]::IsNullOrEmpty($head)) { $head = '.' }
            try {
                $base = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($head)
            }
            catch {
                $base = Join-Path $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath $head
            }
            if (-not $tail) { return $base }
            return $base.TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar + $tail
        }
        # The one walk every path check below is built on. A path is read one part at
        # a time. A link met on the way is followed where it is met: the parts of its
        # target are read next, in its place, so a link to a directory higher up is
        # followed too. A '..' goes to the parent of the real location reached so far.
        # A relative path is made absolute by Resolve-AshSpelling. It returns:
        #   Steps  one entry per part met, in order: Dir (the real directory the part
        #          is in), Part, Candidate (Dir and Part joined), IsLink (the part is
        #          a symbolic link or junction), Named (the part is in the spelling,
        #          not in the target of a link) and NamedPath (the spelling up to and
        #          including the part).
        #   Named  the spelling made absolute with every '..' applied to the real
        #          location before it, and no link followed.
        #   Real   the path with every link on the way followed, which is what the
        #          runner mounts.
        # At most 40 links are followed over the whole walk, so a cycle of links ends:
        # a path with more is refused, because taking it as spelled would judge a
        # directory by a name the runner resolves differently. A '..' after a part that
        # does not exist is refused: it cannot be placed.
        function Get-AshWalk([string]$Spelling) {
            $whole = if ([System.IO.Path]::IsPathRooted($Spelling)) { $Spelling } else { Resolve-AshSpelling $Spelling }
            $root = [System.IO.Path]::GetPathRoot($whole)
            $walked = $root
            $named = $root
            $unplaced = $false
            $hops = 0
            $steps = [System.Collections.Generic.List[object]]::new()
            $rest = [System.Collections.Generic.List[object]]::new()
            foreach ($name in $whole.Substring($root.Length).Split($separators, [System.StringSplitOptions]::RemoveEmptyEntries)) {
                $rest.Add([pscustomobject]@{ Name = $name; Named = $true })
            }
            while ($rest.Count -gt 0) {
                $entry = $rest[0]
                $rest.RemoveAt(0)
                $part = $entry.Name
                if ($part -eq '.') { continue }
                if ($part -eq '..') {
                    if ($unplaced) {
                        Stop-AshRefusal 3 "The path '$Spelling' goes up with '..' from a part that does not exist, so where it leads cannot be placed. Use a path without that '..'."
                    }
                    $walked = Step-AshParent $walked $Spelling
                    if ($entry.Named) { $named = $walked }
                    continue
                }
                $candidate = Join-Path $walked $part
                if ($entry.Named) { $named = Join-Path $named $part }
                $item = $null
                if (-not $unplaced) {
                    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
                    if (-not $item) { $unplaced = $true }
                }
                $isLink = [bool]($item -and $item.LinkType -in @('SymbolicLink', 'Junction') -and $item.Target)
                $steps.Add([pscustomobject]@{ Dir = $walked; Part = $part; Candidate = $candidate; IsLink = $isLink; Named = $entry.Named; NamedPath = $named })
                if (-not $isLink) {
                    $walked = $candidate
                    continue
                }
                $hops++
                if ($hops -gt 40) {
                    Stop-AshRefusal 3 "The path '$Spelling' is reached through more than 40 links (the walk reached $hops). Invoke-ASH follows at most 40 links to find where a directory or file really is, and does not run on a path it cannot place. Use a path with fewer links."
                }
                $target = [string]@($item.Target)[0]
                if ([System.IO.Path]::IsPathRooted($target)) {
                    $walked = [System.IO.Path]::GetPathRoot($target)
                    $target = $target.Substring($walked.Length)
                }
                $given = [System.Collections.Generic.List[object]]::new()
                foreach ($targetPart in $target.Split($separators, [System.StringSplitOptions]::RemoveEmptyEntries)) {
                    $given.Add([pscustomobject]@{ Name = $targetPart; Named = $false })
                }
                $rest.InsertRange(0, $given)
            }
            return [pscustomobject]@{ Steps = $steps; Named = $named; Real = $walked }
        }
        function Get-AshRealPath([string]$Path) {
            return (Get-AshWalk $Path).Real
        }

        # Whether a name can be looked up in the directory, which needs search
        # permission and not the read permission listing needs: a name that is not
        # there is "not found" in a directory that can be searched and "denied" in
        # one that cannot. Defined before the first Get-AshWalk call below: its
        # Step-AshParent path calls this when the walked spelling holds "..".
        function Test-AshSearchable([string]$Directory) {
            try {
                $null = [System.IO.File]::GetAttributes([System.IO.Path]::Combine($Directory, '.ash-search-check'))
            }
            catch [System.UnauthorizedAccessException] {
                return $false
            }
            catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
                # The name is not there, so the directory can be searched.
            }
            return $true
        }

        $null = Get-Item -LiteralPath $SourceDir
        $sourceWalk = Get-AshWalk $SourceDir
        $sourceDirFull = $sourceWalk.Named
        Write-Verbose "Resolved SourceDir to: $sourceDirFull"
        # Case is ignored on Windows and macOS, whose file systems usually ignore it: a
        # different spelling of a directory's case is the same directory there. Where
        # the file system is case-sensitive, two spellings that differ in case are two
        # directories, so a check that decides a path is in a tree can then find it in
        # one it is not in. That is safe for a check that refuses or marks a config
        # (it only refuses or marks more). It is not safe for a decision that picks
        # which file is read, so that one compares the case exactly (the /src
        # mapping of the config below).
        $pathComparison = if (Test-AshCaseInsensitiveHost) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
        function Test-AshUnder([string]$Path, [string]$Root, [System.StringComparison]$Comparison = $pathComparison) {
            $Root = $Root.TrimEnd($separators)
            return $Path.StartsWith($Root + [System.IO.Path]::DirectorySeparatorChar, $Comparison)
        }
        $sourceReal = $sourceWalk.Real
        # Helpers for the ASH_CONFIG carry below, ports of ./ash's resolve_file and
        # TREES. A link is anything with a LinkType but a hard link, which names no
        # other path. Link targets are read from .Target, which Windows PowerShell 5.1
        # has too, so no step needs a newer runtime.
        function Test-AshLink([string]$Path) {
            $found = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            return ($null -ne $found -and [bool]$found.LinkType -and $found.LinkType -ne 'HardLink')
        }
        # The path with every link on the way followed one component at a time, as the
        # kernel follows them, or $null when a link cannot be followed (no target to
        # read, or more than the 40 the kernel allows): callers refuse on $null.
        function Resolve-AshRealPath([string]$Path) {
            $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            if (-not [System.IO.Path]::IsPathRooted($Path)) {
                $Path = [System.IO.Path]::Combine((Get-Location).ProviderPath, $Path)
            }
            $root = [System.IO.Path]::GetPathRoot($Path)
            $queue = [System.Collections.Generic.List[string]]::new()
            $queue.AddRange([string[]]$Path.Substring($root.Length).Split($separators))
            $walked = $root
            $hops = 0
            while ($queue.Count -gt 0) {
                $part = $queue[0]
                $queue.RemoveAt(0)
                if ($part -eq '' -or $part -eq '.') {
                    continue
                }
                if ($part -eq '..') {
                    $parent = if ($walked -eq $root) { $null } else { [System.IO.Path]::GetDirectoryName($walked) }
                    $walked = if ($parent) { $parent } else { $root }
                    continue
                }
                $next = [System.IO.Path]::Combine($walked, $part)
                if (Test-AshLink $next) {
                    $hops++
                    if ($hops -gt 40) {
                        return $null
                    }
                    $target = @((Get-Item -LiteralPath $next -Force).Target)[0]
                    if ([string]::IsNullOrEmpty($target)) {
                        return $null
                    }
                    if ([System.IO.Path]::IsPathRooted($target)) {
                        $walked = [System.IO.Path]::GetPathRoot($target)
                        $target = $target.Substring($walked.Length)
                    }
                    $queue.InsertRange(0, [string[]]$target.Split($separators))
                }
                else {
                    $walked = $next
                }
            }
            return $walked
        }
        # The scanned tree under its logical and physical names, for each start
        # directory given: the outermost directory at or above it holding a .git entry
        # (a directory or a file), else the start itself.
        function Get-AshTrees([string[]]$Starts) {
            $trees = [System.Collections.Generic.List[string]]::new()
            foreach ($start in $Starts) {
                $checkout = $start
                $dir = $start
                while ($dir) {
                    $gitEntry = [System.IO.Path]::Combine($dir, '.git')
                    if ([System.IO.Directory]::Exists($gitEntry) -or [System.IO.File]::Exists($gitEntry)) {
                        $checkout = $dir
                    }
                    $dir = [System.IO.Path]::GetDirectoryName($dir)
                }
                $trees.Add($checkout)
                $checkoutReal = Resolve-AshRealPath $checkout
                if ($null -ne $checkoutReal) {
                    $trees.Add($checkoutReal)
                }
            }
            return , $trees.ToArray()
        }
        function Test-AshInAny([string]$Path, [string[]]$Trees, [System.StringComparison]$Comparison) {
            foreach ($tree in $Trees) {
                $prefix = $tree.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
                if ($Path.StartsWith($prefix, $Comparison)) {
                    return $true
                }
            }
            return $false
        }
        # Whether the directory, or one above it, holds a .git entry: is it in a
        # git checkout.
        function Test-AshInCheckout([string]$Directory) {
            $dir = Get-Item -LiteralPath $Directory -Force -ErrorAction SilentlyContinue
            while ($null -ne $dir) {
                if (Test-Path -LiteralPath (Join-Path $dir.FullName '.git')) { return $true }
                $dir = $dir.Parent
            }
            return $false
        }
        # Whether a link the walk met sits inside one of $Trees or any git checkout:
        # a link reached only through another link counts too, because whoever writes
        # the directory a link sits in chooses where it leads
        # (config/sandbox_grants.links_followed).
        function Test-AshFollowsLinkInCheckout($Steps, [string[]]$Trees) {
            foreach ($step in $Steps) {
                if (-not $step.IsLink) { continue }
                $linkDir = $step.Dir.TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar
                if (@($Trees | Where-Object { Test-AshUnder $linkDir $_ }).Count -gt 0) { return $true }
                if (Test-AshInCheckout $step.Dir) { return $true }
            }
            return $false
        }
        # Whether the path as named is inside one of $Trees, judged where each part of
        # the name really is: a part the name itself gives counts when the real
        # directory it is in is inside a tree. The parts a link's target gives do not
        # count: a name that leaves the tree by the operator's own link and comes back
        # through a target is not named inside it. So a tree reached through an alias,
        # of the tree or of a directory above it, is judged as the direct spelling is.
        function Test-AshNamedInTree($Steps, [string[]]$Trees) {
            foreach ($step in $Steps) {
                if (-not $step.Named) { continue }
                $here = $step.Dir.TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar
                if (@($Trees | Where-Object { Test-AshUnder $here $_ }).Count -gt 0) { return $true }
            }
            return $false
        }
        # Whether the path is a regular file, which is what ./ash requires (test -f). A
        # FIFO would block the read that checks the file can be opened, and a character
        # device such as /dev/zero would never end. Where PowerShell reports a UnixStat
        # for the item (PowerShell 7 off Windows), the item's type is read from
        # UnixStat.ItemType, whose members are Directory, File, SymbolicLink,
        # BlockDevice, CharacterDevice, NamedPipe and Socket, and only File passes. The
        # UnixMode string is not read for this: its text starts with '-' for any item
        # whose permission bits are 0444 or 0644, before the item type is looked at, so a
        # FIFO made under the usual umask would read as a regular file. Windows
        # PowerShell 5.1 has no UnixStat; there a device attribute refuses, and on
        # any other runtime that reports none, nothing here can tell the type, so the
        # path is allowed (directories are refused everywhere).
        # Off Windows a backslash is an ordinary character in a file name, but the file
        # system provider reads it as a separator: Get-Item -LiteralPath finds another
        # file, or none, for a name such as a\b.yaml. So existence is read from .NET on
        # the name as written, and the UnixStat type is trusted only for an item whose
        # full name is the path asked for. For any other name, the type is asked of the
        # platform's own test -f (the check ./ash makes), and where there is no test
        # program the name is allowed, as for a runtime that reports no type.
        function Test-AshRegularFile([string]$Path) {
            if (-not $onWindows) {
                if ([System.IO.Directory]::Exists($Path) -or -not [System.IO.File]::Exists($Path)) {
                    return $false
                }
            }
            $found = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            if (-not $onWindows -and ($null -eq $found -or $found.FullName -cne $Path)) {
                $testTool = Get-Command -Name test -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($null -eq $testTool) {
                    return $true
                }
                $savedExitCode = $global:LASTEXITCODE
                & $testTool.Source -f $Path
                $isRegular = ($LASTEXITCODE -eq 0)
                $global:LASTEXITCODE = $savedExitCode
                return $isRegular
            }
            if ($null -eq $found -or $found.PSIsContainer) {
                return $false
            }
            $unixStat = $found.PSObject.Properties['UnixStat']
            if ($null -ne $unixStat -and $null -ne $unixStat.Value) {
                return ([string]$unixStat.Value.ItemType) -ceq 'File'
            }
            if ($onWindows) {
                return -not ($found.Attributes -band [System.IO.FileAttributes]::Device)
            }
            return $true
        }
        # The name as ./ash's named_in_a_scanned_tree reads it, a port of its walk over
        # the absolute, uncollapsed spelling: the components in order, with '..'
        # stepping up from the path walked so far. The first link whose directory is
        # inside a scanned tree decides, since the rest of the name is then the tree's to
        # steer, and the path up to and including that link is returned, which
        # Test-AshInAny reads as inside. A link outside every tree is replaced by where
        # it really leads, so a '..' after it steps out of the link's target, as the
        # kernel steps, and not out of the directory the link sits in. The operator's
        # own string is what is walked: PowerShell collapses a '..' by text before it
        # looks at any link on the way, which would judge another file than the one
        # the kernel, ./ash and a local scan read. $null when the walk cannot be
        # decided, and $UndecidedAt says why: 'link' for a link that cannot be followed,
        # 'directory' for a name that cannot be looked up because its directory cannot
        # be searched, which may be a link nobody here can see, as ./ash reads it.
        function Get-AshNamedPath([string]$Path, [string[]]$Trees, [System.StringComparison]$Comparison, [ref]$UndecidedAt) {
            $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            $root = [System.IO.Path]::GetPathRoot($Path)
            $walked = $root
            foreach ($part in $Path.Substring($root.Length).Split($separators)) {
                if ($part -eq '' -or $part -eq '.') {
                    continue
                }
                if ($part -eq '..') {
                    $parent = if ($walked -eq $root) { $null } else { [System.IO.Path]::GetDirectoryName($walked) }
                    $walked = if ($parent) { $parent } else { $root }
                    continue
                }
                $walked = [System.IO.Path]::Combine($walked, $part)
                if (Test-AshLink $walked) {
                    if (Test-AshInAny $walked $Trees $Comparison) {
                        return $walked
                    }
                    $walked = Resolve-AshRealPath $walked
                    if ($null -eq $walked) {
                        $UndecidedAt.Value = 'link'
                        return $null
                    }
                }
                elseif ($null -eq (Get-Item -LiteralPath $walked -Force -ErrorAction SilentlyContinue)) {
                    # Not a link and not there. Absent is a plain component; but a name
                    # that cannot be looked up because its directory cannot be searched
                    # may be a link nobody here can see, so the walk cannot decide.
                    $walkedParent = [System.IO.Path]::GetDirectoryName($walked)
                    if ($walkedParent -and [System.IO.Directory]::Exists($walkedParent) -and -not (Test-AshSearchable $walkedParent)) {
                        $UndecidedAt.Value = 'directory'
                        return $null
                    }
                }
            }
            return $walked
        }
        # The file ASH_CONFIG names, carried into the container for a scan (no
        # subcommand, or scan), as ./ash carries it: the file is mounted read-only under
        # /ash-env-config and the scan is given that container path as --ash-config-from-host,
        # which tells the scan the file is the operator's, and, when no -Config was given,
        # as --config. A raw host path would not do: a Windows absolute path
        # names nothing in the container, and a relative value would resolve against
        # /src. Refused with 3, before anything is built, when it names no regular,
        # readable file.
        # A config inside the scanned tree is read through /src, where the scan judges it
        # itself, so nothing is mounted for it. Every other file is the operator's by
        # location; the wrapper mounts only those. A file named inside the scanned tree
        # whose real path, every link followed, is outside it is refused, as ./ash
        # refuses it: the repository being scanned would otherwise choose which host
        # file is mounted. A mounted file the scanned repository wrote (its real path
        # inside the scanned tree, or its name following a link that sits in the tree)
        # is marked with --config-file-from-scanned-repository, as ./ash marks it, so
        # the scan inside does not read it as the operator's. The judgment over a whole
        # extends chain is ash --mode container's. The file is carried whether or not
        # -Config was given (ASH_CONFIG is the environment variable of the CLI's
        # --config option, and the scan reads the file as its base config whatever
        # names the config): only the --config fill-in depends on -Config, which
        # keeps its documented raw-spelling contract and wins. The words for the file
        # go where the -Config words sit, in the order ./ash gives them. As in ./ash,
        # all of it, refusals included, applies only to a run that will happen: under
        # -NoRun nothing is resolved, mounted or warned about, and any other
        # subcommand is warned about, with or without -Config, and not given the file.
        if ($envConfigPending -and -not $NoRun -and $subcommand -cne '' -and $subcommand -cne 'scan') {
            Write-Warning "ASH_CONFIG is set ($(Format-AshShownValue $env:ASH_CONFIG)), but Invoke-ASH mounts the file and passes it only for a scan, so ash $subcommand there does not read it."
        }
        elseif ($envConfigPending -and -not $NoRun) {
            $envConfigGiven = $env:ASH_CONFIG
            # The operator's own string, made absolute, is what is resolved: a relative
            # name from the physical working directory, as the kernel takes it. Item
            # names such as FullName are not used, because PowerShell collapses a '..'
            # after a link by text and so finds another file than the one the kernel,
            # ./ash and a local scan read.
            # A name rooted without a drive (\repo\cfg.yaml) is on the current drive, so
            # it is compared with the scanned trees, which start with one. Windows
            # PowerShell 5.1 throws from the path functions on a quote or a control
            # character, as in the quotes cmd keeps in set ASH_CONFIG="C:\x.yaml": no
            # file has such a name, so the throw is refused as a missing file with the
            # code of any other, never left as a raw .NET error.
            $envConfigAbsolute = $null
            $envConfigReal = $null
            try {
                if ($onWindows -and $envConfigGiven -match '^[\\/](?![\\/])') {
                    $envConfigAbsolute = [System.IO.Path]::GetPathRoot((Get-Location).ProviderPath).TrimEnd('\', '/') + $envConfigGiven
                }
                elseif ([System.IO.Path]::IsPathRooted($envConfigGiven)) {
                    $envConfigAbsolute = $envConfigGiven
                }
                else {
                    $envConfigWorking = Resolve-AshRealPath (Get-Location).ProviderPath
                    if ($null -ne $envConfigWorking) {
                        $envConfigAbsolute = [System.IO.Path]::Combine($envConfigWorking, $envConfigGiven)
                    }
                }
                # The file as it really is (every link on the way followed, one
                # component at a time).
                if ($null -ne $envConfigAbsolute) {
                    $envConfigReal = Resolve-AshRealPath $envConfigAbsolute
                }
            }
            catch {
                $global:LASTEXITCODE = $refusalExitCode
                throw "Config file not found: $(Format-AshShownValue $envConfigGiven). --config (or ASH_CONFIG) has to name an existing file: container mode mounts it read-only for the scan inside the container."
            }
            # A link that cannot be followed is a refusal, never a pass.
            if ($null -eq $envConfigAbsolute -or $null -eq $envConfigReal) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "Config file cannot be read: $(Format-AshShownValue $envConfigGiven). A link on its path cannot be followed, and ASH does not hand the container runner a file it cannot resolve."
            }
            # ./ash's test -f: a missing path, a directory, a FIFO or a device is not a
            # config file, and is refused before anything opens it.
            if (-not (Test-AshRegularFile $envConfigReal)) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "Config file not found: $(Format-AshShownValue $envConfigGiven). --config (or ASH_CONFIG) has to name an existing file: container mode mounts it read-only for the scan inside the container."
            }
            # The runner mounts with its own rights, which can be wider than ASH's, so
            # the file is opened here first.
            try {
                [System.IO.File]::OpenRead($envConfigReal).Dispose()
            }
            catch {
                $global:LASTEXITCODE = $refusalExitCode
                throw "Config file cannot be read: $(Format-AshShownValue $envConfigGiven). ASH does not hand the container runner a file it cannot read itself."
            }
            $envConfigComparison = if ($onWindows -or $IsMacOS) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
            $envConfigSourceFull = (Get-Item -LiteralPath $SourceDir).FullName
            $envConfigSourceReal = Resolve-AshRealPath $envConfigSourceFull
            if ($null -eq $envConfigSourceReal) {
                $global:LASTEXITCODE = $usageErrorExitCode
                throw "Source directory cannot be entered: $(Format-AshShownValue $SourceDir). A link on its path cannot be followed."
            }
            # The scanned tree, as a local scan defines it: the outermost directory at or
            # above the source directory holding a .git entry, under its logical and
            # physical names; with no checkout around it, the source directory itself, as
            # ./ash does. A file named inside it must also really be inside it: otherwise
            # a link the scanned repository committed would choose which host file is
            # mounted.
            $envConfigTrees = Get-AshTrees @($envConfigSourceFull, $envConfigSourceReal)
            # The file as the operator named it: a link in the name keeps its name where
            # it sits in a scanned tree, and a '..' after any other link steps out of
            # the link's target.
            $envConfigUndecidedAt = ''
            $envConfigNamed = Get-AshNamedPath $envConfigAbsolute $envConfigTrees $envConfigComparison ([ref]$envConfigUndecidedAt)
            if ($null -eq $envConfigNamed -and $envConfigUndecidedAt -ceq 'directory') {
                $global:LASTEXITCODE = $refusalExitCode
                throw "The ASH_CONFIG file '$(Format-AshShownValue $envConfigGiven)' goes through a directory that cannot be searched. ASH does not hand the container runner a name it cannot resolve: a directory on the way cannot be searched. Name the file itself."
            }
            if ($null -eq $envConfigNamed) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "Config file cannot be read: $(Format-AshShownValue $envConfigGiven). A link on its path cannot be followed, and ASH does not hand the container runner a file it cannot resolve."
            }
            $envConfigNamedInTree = Test-AshInAny $envConfigNamed $envConfigTrees $envConfigComparison
            $envConfigRealInTree = Test-AshInAny $envConfigReal $envConfigTrees $envConfigComparison
            if ($envConfigNamedInTree -and -not $envConfigRealInTree) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "The ASH_CONFIG file '$(Format-AshShownValue $envConfigGiven)' is inside the scanned tree but is a link, or is reached through one, to '$(Format-AshShownValue $envConfigReal)', which is outside it. ASH does not mount a file the repository being scanned points it at. Name the file itself, outside the repository, or one inside it."
            }
            $envConfigSourceRoot = $envConfigSourceReal.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
            $envConfigMarked = $false
            if ($envConfigReal.StartsWith($envConfigSourceRoot, $envConfigComparison)) {
                $envConfigRelative = $envConfigReal.Substring($envConfigSourceRoot.Length)
                if ($onWindows) {
                    $envConfigRelative = $envConfigRelative.Replace('\', '/')
                }
                $envConfigInner = "/src/$envConfigRelative"
            }
            else {
                # A --mount value is read as CSV by the runtimes, so a comma, a double
                # quote or a line break in the source path cannot be written into it.
                $envConfigHeld = if ($envConfigReal.Contains("`n")) { 'a newline' } elseif ($envConfigReal.Contains("`r")) { 'a carriage return' } elseif ($envConfigReal.Contains(',')) { 'a comma' } elseif ($envConfigReal.Contains('"')) { 'a double quote' } else { $null }
                if ($envConfigHeld) {
                    $global:LASTEXITCODE = $refusalExitCode
                    throw "ASH_CONFIG $(Format-AshShownValue $envConfigGiven) is a path with $envConfigHeld in it, which a container runtime's --mount cannot take. Rename the directory or give another."
                }
                # Mounted on its own, without the files it extends, so a config with an
                # extends entry would not resolve inside the container. Refused, as is
                # every chain this wrapper cannot mount whole. It cannot parse YAML, JSON
                # or TOML, so it errs toward refusing, as ./ash does: the key followed by
                # ':' or '=' anywhere in the text with line breaks read as spaces (a JSON
                # key and its ':' on two lines, TOML's '=', YAML's '? extends' key), and
                # any quoted key holding a backslash, which may spell the name with an
                # escape.
                $envConfigText = [System.IO.File]::ReadAllText($envConfigReal)
                $envConfigFlat = $envConfigText.Replace("`r", ' ').Replace("`n", ' ')
                if ([regex]::IsMatch($envConfigFlat, '(^|[\s{,])["'']?extends["'']?\s*[:=]') -or [regex]::IsMatch($envConfigText, '"[^"\r\n]*\\[^"\r\n]*"[ \t]*:')) {
                    $global:LASTEXITCODE = $refusalExitCode
                    throw "The ASH_CONFIG file '$(Format-AshShownValue $envConfigGiven)' is outside the source directory and has an extends entry. Invoke-ASH mounts such a config on its own, without the files it extends. Run ash --mode container, which mounts the chain, or put the config inside the source directory."
                }
                # A YAML anchor or alias on a key can spell the name another way (an
                # alias to an anchored 'extends' used as a key), which the scan above
                # does not see. A key that starts with one is refused too: at the start
                # of a line, after '- ' or '? ', or after a '{' or ',' in flow style,
                # followed by its ':'. An anchor or alias on a value is not a key. A '? '
                # explicit key whose node starts with one is refused whether or not its
                # ':' is on the same line, because the ':' of an explicit key can start
                # the next line: at the start of a line (after '- ' entries) or after a
                # '{' or ',' in flow style, with the node on the same line or the next.
                $aliasAsKey = ($envConfigText -match '(?m)^[ \t]*(-[ \t]+)?(\?[ \t]+)?[&*]\S+([ \t]+\S+)?[ \t]*:') -or ($envConfigFlat -match '(^|[{,])\s*[&*][^\s,{}\[\]]+(\s+[^\s:,{}\[\]]+)?\s*:')
                $aliasAsExplicitKey = ($envConfigText -match '(?m)^[ \t]*(-[ \t]+)*\?\s+[&*]') -or ($envConfigText -match '[{,]\s*\?\s+[&*]')
                if ($aliasAsKey -or $aliasAsExplicitKey) {
                    Stop-AshRefusal 3 "The config file '$envConfigGiven' is outside the source directory and has a YAML anchor or alias on a key, which can spell an extends entry. Invoke-ASH mounts such a config on its own, without the files it extends. Run ash --mode container, which mounts the chain, or put the config inside the source directory."
                }
                $envConfigInner = '/ash-env-config/' + [System.IO.Path]::GetFileName($envConfigReal)
                $runArgs.Add('--mount')
                $runArgs.Add("type=bind,source=$envConfigReal,destination=$envConfigInner,readonly")
                # A file the scanned repository wrote: its real path is inside the scanned
                # tree (a checkout wider than the source directory), or its name, as the
                # operator wrote it, follows a link that sits in the tree. The scan inside
                # sees the file only under /ash-env-config, outside its own tree, so the
                # wrapper tells it, as ./ash does. A file in some other checkout is the
                # operator's.
                $envConfigMarked = $envConfigRealInTree -or (Test-AshFollowsLinkInCheckout (Get-AshWalk $envConfigAbsolute).Steps $envConfigTrees)
            }
            # The words ./ash gives a scan, in its order: the host's file and its mark,
            # and only without an explicit -Config the file as the scan's own --config
            # with its mark. They go where the -Config words sit.
            $envConfigGroups.Add(@('--ash-config-from-host', $envConfigInner))
            if ($envConfigMarked) {
                $envConfigGroups.Add(@('--config-file-from-scanned-repository', $envConfigInner))
            }
            if (-not $PSBoundParameters.ContainsKey('Config')) {
                $envConfigGroups.Add(@('--config', $envConfigInner))
                if ($envConfigMarked) {
                    $envConfigGroups.Add(@('--config-from-scanned-repository'))
                }
            }
            for ($i = 0; $i -lt $envConfigGroups.Count; $i++) {
                $ashCmdArgs.Insert($envConfigAt + $i, $envConfigGroups[$i])
            }
        }

        $ashArguments = [System.Collections.Generic.List[string]]::new()
        if ($subcommandAt -lt 0) {
            foreach ($group in $ashCmdArgs) {
                $ashArguments.AddRange([string[]]$group)
            }
            foreach ($word in $forwardedAshArgs) {
                $ashArguments.Add($word)
            }
        }
        else {
            for ($i = 0; $i -le $subcommandAt; $i++) {
                $ashArguments.Add($forwardedAshArgs[$i])
            }
            foreach ($group in $ashCmdArgs) {
                $option = $group[0]
                if ($envConfigGroups.Contains($group)) {
                    # The ASH_CONFIG words exist only for a scan, which takes them all.
                    $ashArguments.AddRange([string[]]$group)
                }
                elseif (@($ashOptionSubcommands[$option] -split ' ') -ccontains $subcommand) {
                    $ashArguments.AddRange([string[]]$group)
                }
                elseif ($option -cnotin @('--quiet', '--no-color')) {
                    # --quiet and --no-color have quieted the build and chosen the
                    # terminal already, so only the others are worth a warning.
                    Write-Warning "ash $subcommand does not take $option, so it is not passed."
                }
            }
            for ($i = $subcommandAt + 1; $i -lt $forwardedAshArgs.Count; $i++) {
                $ashArguments.Add($forwardedAshArgs[$i])
            }
        }

        # OCI_RUNNER is what ./ash and the ash CLI read. ASH_OCI_RUNNER, a deprecated name
        # only this function reads, applies when OCI_RUNNER is unset and no -OCIRunner
        # was passed, so a profile that sets it keeps the runner it chose.
        if (-not $PSBoundParameters.ContainsKey('OCIRunner') -and [string]::IsNullOrEmpty($OCIRunner) -and -not [string]::IsNullOrEmpty($env:ASH_OCI_RUNNER)) {
            Write-Warning "ASH_OCI_RUNNER is deprecated; set OCI_RUNNER instead, which ./ash and the ash CLI also read."
            $OCIRunner = $env:ASH_OCI_RUNNER
        }

        # Resolve OCI runner. IsNullOrEmpty, not `$null -ne`: $OCIRunner is a [string]
        # defaulting to $env:OCI_RUNNER, and with that unset PowerShell binds "" rather
        # than $null, so the null test always chose @("") and Get-Command rejected the
        # empty name. An unbound -OCIRunner whose OCI_RUNNER default is empty falls back
        # to discovery, in the order ./ash and the ash CLI use; an explicit -OCIRunner ''
        # was refused with 3 when Invoke-ASH started.
        $runners = if (-not [string]::IsNullOrEmpty($OCIRunner)) {
            @($OCIRunner)
        }
        else {
            @('finch', 'docker', 'nerdctl', 'podman')
        }

        # Resolve source and output directories
        $sourceDirFull = Get-Item -LiteralPath $SourceDir | Select-Object -ExpandProperty FullName
        Write-Verbose "Resolved SourceDir to: $(Format-AshShownValue $sourceDirFull)"

        # Refuse an output directory reached through a link, before anything is created
        # or mounted. A repository that commits .ash/ash_output (or .ash) as a link, or a
        # link inside -SourceDir, would get the scan's output and the in-container
        # cleanup of the previous run's output sent wherever the link points, and with the
        # image built for the caller's IDs those writes succeed. The output directory
        # itself is checked wherever it is; its parents only below the working directory
        # or -SourceDir, where the scanned repository could have put them. Get-Item
        # -Force also finds a dangling link, which New-Item would create the target of.
        # The working directory is checked as well as -SourceDir, and fails closed: in CI
        # the working directory is the scanned checkout, so a link there (a linked
        # directory passed as -SourceDir included) may be one the repository committed.
        # Case is ignored on Windows and macOS, whose volumes usually ignore it, so an
        # -OutputDir typed in another case is still found to be below them.
        $outputDirAbsolute = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
        $pathComparison = if ($onWindows -or $IsMacOS) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
        $separator = [System.IO.Path]::DirectorySeparatorChar
        $repositoryRoots = @((Get-Location).Path, $sourceDirFull) | ForEach-Object { $_.TrimEnd($separator) + $separator }
        $candidate = $outputDirAbsolute
        while ($candidate) {
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
            if ($null -ne $item -and $item.LinkType) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "The output directory '$(Format-AshShownValue $OutputDir)' is reached through a link ('$(Format-AshShownValue $candidate)'). ASH does not write through a link below the working directory or inside -SourceDir, where the scanned repository could have placed it. Remove the link, or pass -OutputDir as the resolved path, with no link in it."
            }
            $parent = Split-Path -Parent $candidate
            $insideRepository = @($repositoryRoots | Where-Object { $parent -and $parent.StartsWith($_, $pathComparison) }).Count -gt 0
            $candidate = if ($insideRepository) { $parent } else { $null }
        }

        # /out is mounted read-write and /src read-only: an output directory that is
        # the source directory or above it would hold the source tree, writable, at
        # /out. A directory that is itself a link is compared by its target. One that
        # does not exist yet cannot hold the source, so this runs before it is created.
        if (-not $NoRun -and (Test-Path -LiteralPath $outputDirAbsolute -PathType Container)) {
            $existingOutput = (Get-Item -LiteralPath $outputDirAbsolute).FullName
            $directories = foreach ($path in @($sourceDirFull, $existingOutput)) {
                $item = Get-Item -LiteralPath $path
                $real = if ($item.LinkType -and $item.ResolvedTarget) { [string]$item.ResolvedTarget } else { $item.FullName }
                $real.TrimEnd($separator) + [System.IO.Path]::DirectorySeparatorChar
            }
            if ($directories[0].StartsWith($directories[1], $pathComparison)) {
                $global:LASTEXITCODE = $refusalExitCode
                throw "The output directory '$(Format-AshShownValue $existingOutput)' is the source directory '$(Format-AshShownValue $sourceDirFull)' or a directory above it. Container mode mounts the output read-write at /out and the source read-only at /src, so the source would be writable through /out. Use an output directory inside the source (the default .ash/ash_output) or outside it, not above it."
            }
        }

        # Create the output directory if it doesn't exist, then require a directory
        # there that can be entered, as ./ash and `ash scan` do, in their words and
        # with their 5. A file at the path was mounted at /out, and the runner failed
        # on it after the image was built. New-Item on Linux returned without an error
        # under a file on the way and made nothing, so the directory is made with
        # CreateDirectory, which says why it cannot be. Its exception's message names
        # the path again, so the reason is the system's text for the error, as ./ash
        # gives mkdir's.
        if (Test-Path -LiteralPath $outputDirAbsolute -PathType Leaf) {
            $global:LASTEXITCODE = $usageErrorExitCode
            throw "Output directory is not a directory: $(Format-AshShownValue $OutputDir)"
        }
        $outputDirExisted = Test-Path -LiteralPath $outputDirAbsolute -PathType Container
        if (-not (Test-Path -LiteralPath $outputDirAbsolute)) {
            Write-Verbose "Creating OutputDir: $(Format-AshShownValue $OutputDir)"
            $createReason = $null
            try {
                $null = [System.IO.Directory]::CreateDirectory($outputDirAbsolute)
            }
            catch [System.UnauthorizedAccessException] {
                $createReason = 'Permission denied'
            }
            catch [System.IO.DirectoryNotFoundException] {
                # A file on the way to it: what mkdir calls ENOTDIR.
                $createReason = 'Not a directory'
            }
            catch {
                # Any other error carries its errno on Linux and macOS, whose text
                # the system gives; elsewhere there is none to give.
                $errno = if ($_.Exception.InnerException) { $_.Exception.InnerException.HResult } else { 0 }
                $createReason = if ($errno -gt 0 -and $errno -lt 4096) { [System.Runtime.InteropServices.Marshal]::GetPInvokeErrorMessage($errno) } else { 'it could not be made' }
            }
            if ($createReason) {
                $global:LASTEXITCODE = $usageErrorExitCode
                throw "Output directory cannot be created: $(Format-AshShownValue $OutputDir) ($createReason)"
            }
        }
        # A name looked up in it is "not found" when it can be entered, and "denied"
        # when it cannot.
        try {
            $null = [System.IO.File]::GetAttributes([System.IO.Path]::Combine($outputDirAbsolute, '.ash-search-check'))
        }
        catch [System.UnauthorizedAccessException] {
            $global:LASTEXITCODE = $usageErrorExitCode
            throw "Output directory cannot be entered: $(Format-AshShownValue $OutputDir)"
        }
        catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
            # The name is not there, so the directory can be entered.
        }
        # One that was there already must take a file, as the scan writes them: one is
        # made under a name of its own (CreateNew, so O_EXCL) and deleted. Asking the
        # permissions instead misses ACLs and a read-only mount. The reason is the
        # system's text for the error.
        if ($outputDirExisted) {
            $writeCheck = [System.IO.Path]::Combine($outputDirAbsolute, '.ash-write-check.' + [System.Guid]::NewGuid().ToString('N'))
            $writeReason = $null
            try {
                $stream = [System.IO.File]::Open($writeCheck, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
                try {
                    $stream.Dispose()
                }
                finally {
                    [System.IO.File]::Delete($writeCheck)
                }
            }
            catch [System.UnauthorizedAccessException] {
                $writeReason = 'Permission denied'
            }
            catch {
                $errno = if ($_.Exception.InnerException) { $_.Exception.InnerException.HResult } else { 0 }
                $writeReason = if ($errno -gt 0 -and $errno -lt 4096) { [System.Runtime.InteropServices.Marshal]::GetPInvokeErrorMessage($errno) } else { 'a file could not be made there' }
            }
            if ($writeReason) {
                $global:LASTEXITCODE = $usageErrorExitCode
                throw "Output directory cannot be written: $(Format-AshShownValue $OutputDir) ($writeReason)"
            }
        }
        $outputDirFull = Get-Item -LiteralPath $outputDirAbsolute | Select-Object -ExpandProperty FullName

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
        $runArgs.Add('-e')
        $runArgs.Add("COLUMNS=$COLUMNS")
        $runArgs.Add('-e')
        $runArgs.Add("LINES=$LINES")

        # Add color support (only when running in an interactive terminal)
        if (-not $noColor -and [Environment]::UserInteractive -and -not [Console]::IsOutputRedirected) {
            $runArgs.Add("-t")
        }
    }
    process {
        try {
            $RESOLVED_OCI_RUNNER = $null
            foreach ($runner in $runners) {
                if ($FOUND = Get-Command $runner -ErrorAction SilentlyContinue) {
                    # A program by its full path: its Name alone ("docker") would run
                    # whichever program PATH holds under that name, or none, when the
                    # runner was named by a path outside PATH.
                    $RESOLVED_OCI_RUNNER = if ($FOUND.CommandType -eq 'Application') { $FOUND.Source } else { $FOUND.Name }
                    break
                }
            }
            if ($null -eq $RESOLVED_OCI_RUNNER) {
                # throw, not exit: this runs in the caller's session, and exit ended it,
                # closing an interactive window and skipping the caller's own catch. A bare
                # throw is script-terminating, so the caller's next statement does not
                # run; ThrowTerminatingError would end only this statement. $LASTEXITCODE
                # is set first for a caller that continues anyway (trap { continue }) and
                # then exits with it, as every refusal here does.
                $candidates = @($runners | ForEach-Object { Format-AshShownValue $_ })
                $tried = if ($candidates.Count -eq 1) { "'$($candidates[0])' was not found" } else { "none of $($candidates -join ', ') was found on PATH" }
                $global:LASTEXITCODE = $refusalExitCode
                throw "Unable to resolve an OCI_RUNNER: $tried. Install one, or name it with -OCIRunner or OCI_RUNNER."
            }
            else {
                Write-Verbose "Resolved OCI_RUNNER to: $(Format-AshShownValue ([System.IO.Path]::GetFileNameWithoutExtension($RESOLVED_OCI_RUNNER))) ($(Format-AshShownValue $RESOLVED_OCI_RUNNER))"

                # OCI_RUNNER_WRAPPER prefixes all OCI commands (like RUSTC_WRAPPER), split
                # into words at whitespace, as ./ash splits it.
                $OCI_WRAPPER = @("$env:OCI_RUNNER_WRAPPER" -split '\s+' | Where-Object { $_ })

                # The build and run commands are argument arrays, and the runner is called
                # with them directly (& $command @arguments), so every value reaches it as
                # one argument, exactly as written, and nothing is passed through
                # Invoke-Expression, which would parse it as PowerShell.

                # Build the container if not skipped
                if (-not $NoBuild) {
                    Write-Host "Building image $AshImageName -- this may take a few minutes during the first build..."

                    $buildCmd = @()
                    $buildCmd += $OCI_WRAPPER
                    $buildCmd += @(
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
                    $dockerfilePath = (Resolve-Path -LiteralPath (Join-Path $ashRoot "Dockerfile")).Path
                    # Add other build args
                    $buildCmd += @(
                        "--tag", $AshImageName
                        "--target", $BuildTarget
                        "--file", $dockerfilePath
                        "--build-arg", "OFFLINE=$(if ($Offline) {'YES'} else {'NO'})"
                        "--build-arg", "OFFLINE_SEMGREP_RULESETS=$OfflineSemgrepRulesets"
                    )
                    # A new BUILD_DATE_EPOCH re-runs the Dockerfile's core stage from
                    # its apt-get upgrade step down, offline download included (see
                    # ARG BUILD_DATE_EPOCH there). It is UTC midnight of today, so
                    # rebuilds on the same day come from the layer cache, and OS
                    # packages and offline databases are at most a day old.
                    $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                    $buildCmd += "--build-arg", "BUILD_DATE_EPOCH=$($nowEpoch - ($nowEpoch % 86400))"

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
                            $global:LASTEXITCODE = $refusalExitCode
                            throw "ASH_BASE_OCI_LAYOUT is '$($env:ASH_BASE_OCI_LAYOUT)', which is not <layout dir>@sha256:<64 hex>. Unset it to build from the Dockerfile's own base image reference."
                        }
                        $baseLayoutDir = $Matches['dir']
                        if ($ociRunnerName -in @('nerdctl', 'finch')) {
                            Write-Host "Base image taken from the verified OCI layout named by ASH_BASE_OCI_LAYOUT, with no registry call."
                            $buildCmd += "--build-context", "ash-base-image=oci-layout://$baseLayoutDir"
                            $buildCmd += "--build-arg", "BASE_IMAGE=ash-base-image"
                            $buildCmd += "--pull=false"
                        }
                        else {
                            Write-Host "Base image expected in $ociRunnerName's local store, placed there from the verified OCI layout named by ASH_BASE_OCI_LAYOUT."
                        }
                    }
                    elseif ($env:ASH_BASE_IMAGE_OVERRIDE) {
                        Write-Host "Base image redirected to $($env:ASH_BASE_IMAGE_OVERRIDE) by ASH_BASE_IMAGE_OVERRIDE."
                        $buildCmd += "--build-arg", "BASE_IMAGE=$($env:ASH_BASE_IMAGE_OVERRIDE)"
                    }

                    # Add any extra build args
                    if ($buildArgs.Count -gt 0) {
                        $buildCmd += $buildArgs
                    }

                    # Add the build context
                    $buildCmd += $ashRoot

                    # Execute the build command
                    $shownBuildCmd = @($buildCmd | ForEach-Object { Format-AshShownValue $_ }) -join ' '
                    Write-Verbose "Build command: $shownBuildCmd"
                    $buildArgv = @($buildCmd | Select-Object -Skip 1)
                    Assert-OneArgumentEach $buildArgv @($buildCmd[0], $RESOLVED_OCI_RUNNER)
                    & $buildCmd[0] @buildArgv

                    # A native command does not throw on a non-zero exit, so without
                    # this a failed build continues to the run below, which then
                    # fails trying to pull the image from a registry and blames the
                    # registry rather than the build step that actually broke.
                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to build image $AshImageName (exit $LASTEXITCODE). See the build output above for the failing step."
                    }
                }

                # Run the container if not skipped
                if (-not $NoRun) {
                    Write-Host "Running ASH scan using built image..."
                    $ashDebug = if ($debugRequested) { 'YES' } else { 'NO' }
                    $runCmd = @()
                    $runCmd += $OCI_WRAPPER
                    $runCmd += @(
                        $RESOLVED_OCI_RUNNER
                        'run'
                        '--rm'
                        "-e", "ASH_ACTUAL_SOURCE_DIR=$sourceDirFull"
                        "-e", "ASH_ACTUAL_OUTPUT_DIR=$outputDirFull"
                        "-e", "ASH_DEBUG=$ashDebug"
                        # As variables rather than --source-dir and --output-dir ahead of the
                        # caller's arguments, which put options in front of a subcommand
                        # (-AshArgs 'report'). scan reads both; report and merge read
                        # ASH_OUTPUT_DIR.
                        "-e", "ASH_SOURCE_DIR=/src"
                        "-e", "ASH_OUTPUT_DIR=/out"
                    )

                    # Add source directory mount, read-only wherever the output
                    # directory is: the output has its own mount at /out and the scan
                    # inside writes there, also when OutputDir is inside SourceDir.
                    $runCmd += "--mount", "type=bind,source=$sourceDirFull,destination=/src,readonly"

                    # Add output directory mount
                    $runCmd += "--mount", "type=bind,source=$outputDirFull,destination=/out"

                    # Add any extra run args
                    if ($runArgs.Count -gt 0) {
                        $runCmd += $runArgs
                    }

                    # Add image name and ASH command
                    $runCmd += @(
                        $AshImageName
                        'ash'
                    )


                    # Container mode never sandboxes the scanners inside the image; the
                    # container is the boundary. So the scan is given --sandbox off, as
                    # `ash scan --mode container` gives its inner scan sandbox.mode=off
                    # (run_ash_scan.py). The scan applies the flag as sandbox.mode after
                    # every --config-overrides, which beat a config file, and a flag on
                    # the command line beats a --cli-json-input document's sandbox; a
                    # document's own config_overrides still apply. Only scan takes
                    # --sandbox, as does ash with no command named, which scans; another
                    # command refuses it and runs no scanners, so it is given nothing.
                    # The command is $subcommand, at $subcommandAt in $ashArguments, both
                    # found in the begin block. ASH's own arguments follow, each one array
                    # element, with --sandbox off right after the command word, or before
                    # every word when no command is named, never after them: there a `--`
                    # would make it scan's extra arguments, and a value-taking option left
                    # last (`--base-ref`) would take --sandbox as its value. Ahead of
                    # them, that option fails as a usage error. The position does not
                    # change what wins: the scan applies the flag after every override,
                    # and every other --sandbox is refused above. The words are the ones
                    # the refusal checked.
                    $callerWords = @($ashArguments)
                    if ($subcommand -eq '' -or $subcommand -cin $ashTakesSandbox) {
                        $sandboxOffAt = $subcommandAt + 1
                        $callerWords = @($ashArguments | Select-Object -First $sandboxOffAt) + @('--sandbox', 'off') + @($ashArguments | Select-Object -Skip $sandboxOffAt)
                    }
                    $runCmd += $callerWords

                    # Execute the run command
                    $shownRunCmd = @($runCmd | ForEach-Object { Format-AshShownValue $_ }) -join ' '
                    Write-Verbose "Run command: $shownRunCmd"
                    $runArgv = @($runCmd | Select-Object -Skip 1)
                    Assert-OneArgumentEach $runArgv @($runCmd[0], $RESOLVED_OCI_RUNNER)
                    & $runCmd[0] @runArgv
                    $exitCode = $LASTEXITCODE
                    return $exitCode
                }
            }
        }
        catch {
            # Whatever raised, $LASTEXITCODE is not left at 0. Rethrown as is, so it
            # is reported once: by the caller's catch, or by PowerShell. A Write-Error
            # here printed it a second time.
            if (-not $global:LASTEXITCODE) { $global:LASTEXITCODE = 1 }
            throw
        }
    }
}

function Test-AshCaseInsensitiveHost {
    <#
    .SYNOPSIS
    Whether the file systems of this host usually ignore the case of a name.

    .DESCRIPTION
    Windows and macOS do. The path checks in Invoke-ASH compare case-insensitively
    where this is true.
    #>
    return [bool]($IsWindows -or $IsMacOS -or $PSVersionTable.PSVersion.Major -le 5)
}

function Format-AshShownValue {
    <#
    .SYNOPSIS
    A value as Invoke-ASH's refusals show it, with nothing in it a terminal acts on.

    .DESCRIPTION
    Each character that would move the cursor or change colors, reverse or hide the
    text after it, or break the line is written as an escape: a control character
    (Cc: C0, DEL and C1, CSI among them) as \xHH, and a format character, a line or
    paragraph separator, a lone surrogate, a private-use or an unassigned code point
    (Cf, Zl, Zp, Cs, Co, Cn) as \uXXXX, or \UXXXXXXXX above U+FFFF. These are the
    classes ./ash and merge write out. Every other character is kept as typed, so a
    path or a non-ASCII letter reads as it was given. That includes characters a
    terminal shows but a reader may not see for what they are: spaces other than
    ASCII's (Zs, such as U+00A0 and U+3000), combining marks (Mn) and fillers such as
    U+3164. They are outside the set written out here and in ./ash, so a shown value
    holding one can still look like another. ./ash shows them as typed only in a
    UTF-8 locale: in the C locale their bytes are not printable, so it quotes the
    value with them in octal, as in $'img\302\240name'. Here they are kept in every
    locale.

    A run of backslashes is doubled where it would read as part of an escape: before
    an x and two hex digits, a u and four, a U and eight, or a character written as
    an escape. So an odd run there ends in an escape and an even one is text, and the
    display reads back to the value one to one: a literal backslash, x, 1, B shows as
    two backslashes and x1B, a real ESC as one backslash and x1B. Any other backslash
    is kept as it is, so a Windows path reads as typed. This is the rule ASH's own
    terminal text uses (automated_security_helper/utils/terminal_text.py).
    #>
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )
    if ([string]::IsNullOrEmpty($Value)) {
        return [string]$Value
    }
    $written = @(
        [System.Globalization.UnicodeCategory]::Format,
        [System.Globalization.UnicodeCategory]::LineSeparator,
        [System.Globalization.UnicodeCategory]::ParagraphSeparator,
        [System.Globalization.UnicodeCategory]::Surrogate,
        [System.Globalization.UnicodeCategory]::PrivateUse,
        [System.Globalization.UnicodeCategory]::OtherNotAssigned
    )
    # Text an escape could be read into, at the position given.
    $escapeText = [regex]::new('\G(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})')
    $shown = New-Object System.Text.StringBuilder
    $backslashes = 0
    $at = 0
    while ($at -lt $Value.Length) {
        if ($Value[$at] -eq [char]'\') {
            $backslashes++
            $at++
            continue
        }
        # A surrogate pair is one code point, and its category is that code point's.
        $width = if ([char]::IsSurrogatePair($Value, $at)) { 2 } else { 1 }
        $codePoint = if ($width -eq 2) { [char]::ConvertToUtf32($Value, $at) } else { [int]$Value[$at] }
        $category = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($Value, $at)
        $isControl = $category -eq [System.Globalization.UnicodeCategory]::Control
        $isWritten = $written -contains $category
        if ($backslashes -gt 0) {
            $readsAsEscape = $isControl -or $isWritten -or $escapeText.IsMatch($Value, $at)
            [void]$shown.Append([char]'\', $(if ($readsAsEscape) { 2 * $backslashes } else { $backslashes }))
            $backslashes = 0
        }
        if ($isControl) {
            [void]$shown.AppendFormat('\x{0:X2}', $codePoint)
        }
        elseif ($isWritten) {
            $form = if ($codePoint -gt 0xFFFF) { '\U{0:X8}' } else { '\u{0:X4}' }
            [void]$shown.AppendFormat($form, $codePoint)
        }
        else {
            [void]$shown.Append($Value, $at, $width)
        }
        $at += $width
    }
    if ($backslashes -gt 0) {
        [void]$shown.Append([char]'\', $backslashes)
    }
    $shown.ToString()
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

function Assert-AshArgumentsPassWhole {
    <#
    .SYNOPSIS
    Refuses, for Invoke-ASH, arguments a program would not get one for one.

    .DESCRIPTION
    With -LegacyQuoting (PowerShell before 7.3, which has only the legacy rules for
    passing arguments to a program) or -BatchFile (the arguments reach a batch file,
    which gets the legacy rules under every PowerShell), it refuses a value holding a
    double quote, which the legacy rules cannot pass inside one argument; an empty
    value, which they drop; and a value holding a space or tab that ends with a
    backslash, which they wrap in double quotes so that the backslash escapes the
    closing one. With -BatchFile it also refuses & | < > ^ and %, which cmd.exe acts
    on when it reads a batch file's arguments.

    A refusal sets $LASTEXITCODE to 3, as Invoke-ASH's refusals do, and throws.
    #>
    param(
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]
        $Arguments,
        [switch]
        $LegacyQuoting,
        [string]
        $BatchFile
    )
    if (-not $LegacyQuoting -and -not $BatchFile) {
        return
    }
    $reader = if ($BatchFile) { "the batch file '$BatchFile'" } else { "a program from PowerShell $($PSVersionTable.PSVersion)" }
    $instead = if ($BatchFile) { 'Use a runner and wrapper that are not batch files' } else { 'Use PowerShell 7.3 or later' }
    foreach ($argument in @($Arguments)) {
        $text = "$argument"
        $problem = if ($text.Contains('"')) {
            'holds a double quote, which cannot be passed inside one argument to'
        }
        elseif ($text -eq '') {
            'is empty, and an empty argument is dropped on its way to'
        }
        elseif ($text -match '[ \t]' -and $text.EndsWith('\')) {
            'holds a space and ends with a backslash, which escapes the closing quote on its way to'
        }
        elseif ($BatchFile -and $text -match '[&|<>^%]') {
            'holds one of & | < > ^ %, which cmd.exe acts on in the arguments of'
        }
        if ($problem) {
            # The refusal code, 3, as $refusalExitCode in Invoke-ASH.
            $global:LASTEXITCODE = 3
            throw "The argument '$(Format-AshShownValue $text)' $problem $reader. $instead, or a value without it."
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

# The stages -BuildTarget takes, completed here and not by a ValidateSet: Invoke-ASH
# checks the value in its body, so a stage it does not have is refused with exit 3.
Register-ArgumentCompleter -CommandName Invoke-ASH -ParameterName 'BuildTarget' -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)
    @('ci', 'non-root') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new(
            $_, $_, 'ParameterValue', $_)
    }
}
