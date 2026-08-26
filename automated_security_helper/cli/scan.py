# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from rich import print
from typing import Annotated, List, NoReturn, Optional
import typer
from pathlib import Path

from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    RunMode,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.interactions.run_ash_scan import (
    run_ash_scan,
)
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.workspace.plan import WorkspacePlan
from automated_security_helper.workspace.resolver import resolve_workspace
from automated_security_helper.workspace.workspace_file import (
    WORKSPACE_AUTO,
    discover_workspace_file,
)


def _fail_workspace(
    message: str,
    code: WorkspaceExitCode = WorkspaceExitCode.WORKSPACE_ERROR,
) -> NoReturn:
    """Report a workspace-mode refusal and exit with its contract code.

    Written with ``typer.echo`` rather than the Rich ``print`` imported above,
    because these messages quote operator-supplied paths and Rich would read a
    bracketed fragment in one as a style name and fail while rendering the error.
    """
    typer.echo(message, err=True)
    raise typer.Exit(code)


def _handle_workspace_mode(
    workspace: str,
    source_dir: str | None,
    allow_missing_projects: bool,
    dry_run: bool,
    workspace_config: str | None = None,
    config_overrides: tuple[str, ...] = (),
) -> "WorkspacePlan":
    """Resolve a workspace and return the plan, or exit.

    Every failure path is an exit, because a workspace that will not resolve has
    nothing to scan: 4 for a workspace definition or policy problem, 3 for a
    project whose own config is invalid. Never 2 -- that code means a scan ran and
    found actionable findings, which is the opposite of what any exit from here
    reports. ``--dry-run`` also exits, at 0, after printing the plan.

    The success path returns rather than exiting, and the caller runs the scans
    from the same plan object the operator would have inspected. Re-resolving for
    execution would let the two drift, which is exactly what ``--dry-run`` exists
    to rule out.

    Argument validation happens before any filesystem work, so an operator who
    passed a contradictory pair of flags is told that rather than being sent to
    debug their workspace file first.
    """
    if source_dir is not None:
        _fail_workspace(
            "--workspace and --source-dir are mutually exclusive. In workspace "
            "mode the directory holding the workspace file is the scan root, so "
            "honouring both would leave it ambiguous which tree was scanned. "
            "Note that --source-dir is also set by the ASH_SOURCE_DIR "
            "environment variable, which counts as setting it."
        )

    try:
        workspace_file = (
            discover_workspace_file(Path.cwd())
            if workspace == WORKSPACE_AUTO
            else Path(workspace)
        )
        plan = resolve_workspace(
            workspace_file,
            allow_missing_projects=allow_missing_projects,
            workspace_config=(
                Path(workspace_config) if workspace_config is not None else None
            ),
            # Resolution needs these so each project's DECLARED threshold
            # reflects an override. The ceiling applies to that, and --dry-run
            # prints the value the scan will actually enforce.
            config_overrides=config_overrides,
        )
    except WorkspaceDefinitionError as exc:
        _fail_workspace(str(exc))
    except ASHConfigValidationError as exc:
        _fail_workspace(str(exc), code=WorkspaceExitCode.INVALID_PROJECT_CONFIG)

    if dry_run:
        typer.echo(plan.render())
        raise typer.Exit(WorkspaceExitCode.SUCCESS)

    return plan


def run_ash_scan_cli_command(
    ctx: typer.Context,
    source_dir: Annotated[
        str | None,
        typer.Option(
            help="The source directory to scan",
            envvar="ASH_SOURCE_DIR",
            writable=False,
        ),
    ] = None,
    output_dir: Annotated[
        str | None,
        typer.Option(
            help="The directory to output results to",
            envvar="ASH_OUTPUT_DIR",
            writable=True,
        ),
    ] = None,
    scanners: Annotated[
        Optional[List[str]],
        typer.Option(
            help="Specific scanner names to run. Defaults to all scanners.",
            envvar="ASH_SCANNERS",
        ),
    ] = None,
    exclude_scanners: Annotated[
        Optional[List[str]],
        typer.Option(
            help="Specific scanner names to exclude from running. Takes precedence over scanners parameter.",
            envvar="ASH_EXCLUDED_SCANNERS",
        ),
    ] = None,
    ash_plugin_modules: Annotated[
        Optional[List[str]],
        typer.Option(
            help="List of Python modules to import containing ASH plugins and/or event subscribers. These are loaded in addition to the default modules.",
            envvar="ASH_PLUGIN_MODULES",
        ),
    ] = None,
    config_overrides: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2'). "
            "Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax. See docs/config-overrides.md",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            help="Run scan in offline/airgapped mode (skips NPM/PNPM/Yarn Audit checks). IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage."
        ),
    ] = False,
    offline_semgrep_rulesets: Annotated[
        str,
        typer.Option(
            "--offline-semgrep-rulesets",
            help="Specify Semgrep rulesets for use in ASH offline mode",
        ),
    ] = "p/ci",
    strategy: Annotated[
        ExecutionStrategy,
        typer.Option(help="Whether to run scanners in parallel or sequential"),
    ] = ExecutionStrategy.PARALLEL.value,
    progress: Annotated[
        bool,
        typer.Option(
            "--progress/--no-progress",
            "-p/-P",
            help="Show progress of each job live in the console. Defaults to True.",
        ),
    ] = True,
    output_formats: Annotated[
        Optional[List[str]],
        typer.Option(
            "--output-formats",
            "--output-format",
            "--formats",
            "--format",
            "-f",
            help=f"The output formats to use (comma-separated). Available formats: {', '.join([f.value for f in ExportFormat])}",
        ),
    ] = None,
    cleanup: Annotated[
        bool,
        typer.Option(
            help="Clean up 'converted' directory and other temporary files after scan completes. Defaults to False. Note: Scans will always clean up existing files in the output directory before a new scan starts. This parameter only affects the cleanup of the temporary work directory after a scan has completed, typically for inspection of temporary artifacts."
        ),
    ] = False,
    phases: Annotated[
        Optional[List[ExecutionPhase]],
        typer.Option(
            help="The phases to run. Defaults to all phases except inspect.",
        ),
    ] = None,
    inspect: Annotated[
        bool,
        typer.Option(
            help="Enable inspection of SARIF fields after running. This adds the inspect phase to the execution.",
        ),
    ] = False,
    use_existing: Annotated[
        bool,
        typer.Option(
            help="Use an existing ash_aggregated_results.json file in the output-dir. If True, the scan phase will be skipped and reports will be generated from this file.",
        ),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Prints version number",
        ),
    ] = False,
    mode: Annotated[
        Optional[RunMode],
        typer.Option(
            help="Execution mode preset. 'precommit' enables python-based plugins only and simplified output. 'container' runs non-Python plugins in a container. 'local' (default) runs everything in the local Python process.",
            envvar="ASH_MODE",
        ),
    ] = RunMode.local,
    python_based_plugins_only: Annotated[
        bool,
        typer.Option(
            "--python-only/--full",
            "--python-based-scanners-only/--all-enabled-scanners",
            "--python-based-plugins-only/--all-enabled-plugins",
            help="Exclude execution of any plugins or tools that have depencies external to Python.",
        ),
    ] = False,
    show_summary: Annotated[
        bool, typer.Option(help="Show metrics table and results summary")
    ] = True,
    quiet: Annotated[bool, typer.Option(help="Hide all log output")] = False,
    log_level: Annotated[
        AshLogLevel,
        typer.Option(
            "--log-level",
            help="Set the log level.",
        ),
    ] = AshLogLevel.INFO,
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    fail_on_findings: Annotated[
        bool | None,
        typer.Option(
            help="Enable/disable throwing non-successful exit codes if any actionable findings are found. Defaults to unset, which prefers the configuration value. If this is set directly, it takes precedence over the configuration value."
        ),
    ] = None,
    simple: Annotated[
        bool,
        typer.Option(
            help="Simplified output mode with minimal logging",
        ),
    ] = False,
    ignore_suppressions: Annotated[
        bool,
        typer.Option(
            help="Ignore all suppression rules and report all findings regardless of suppression status."
        ),
    ] = False,
    min_severity: Annotated[
        str,
        typer.Option(
            help="Minimum severity to trigger non-zero exit code (critical, high, medium, low, none). 'critical' and 'high' are equivalent because SARIF does not distinguish them. Findings below this threshold are still reported but don't affect the exit code.",
        ),
    ] = "low",
    compact_report: Annotated[
        bool,
        typer.Option(
            "--compact-report",
            help="Produce a shorter markdown report suitable for PR comments. Omits the severity legend, scan metadata, footer, and rows for scanners that were skipped or had zero findings.",
        ),
    ] = False,
    changed_files_only: Annotated[
        bool,
        typer.Option(
            "--changed-files-only",
            help="Limit the scan to files changed between the base branch and HEAD. Useful in CI to scan only PR changes. Falls back to a full scan when git is unavailable.",
            envvar="ASH_CHANGED_FILES_ONLY",
        ),
    ] = False,
    base_ref: Annotated[
        str,
        typer.Option(
            "--base-ref",
            help="Git ref to diff against when --changed-files-only is set.",
            envvar="ASH_BASE_REF",
        ),
    ] = "origin/main",
    ### WORKSPACE-RELATED OPTIONS
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            help="Path to a '.code-workspace' file whose folders are scanned as separate, independently-scoped projects. Pass 'auto' to use the single '*.code-workspace' file in the current directory. Mutually exclusive with --source-dir.",
            envvar="ASH_WORKSPACE",
        ),
    ] = None,
    workspace_config: Annotated[
        str | None,
        typer.Option(
            "--workspace-config",
            help="Path to the workspace policy file (severity ceiling, workspace-wide suppressions and ignore paths, additional scanners). Without this, ASH looks for 'ash-workspace.{yaml,yml,json}' in the workspace root or its '.ash' directory; finding none is not an error. Must not be any project's own ASH config: workspace policy governs every project, so reading one project's config as policy would apply its settings to its siblings.",
            envvar="ASH_WORKSPACE_CONFIG",
        ),
    ] = None,
    allow_missing_projects: Annotated[
        bool,
        typer.Option(
            "--allow-missing-projects",
            help="In workspace mode, skip project folders that are absent or unreadable instead of failing. Skipped projects are recorded in the plan. Without this, a missing project fails the whole workspace, so a typo or an un-cloned repository cannot pass as a clean scan.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="In workspace mode, print the resolved execution plan and exit without scanning anything.",
        ),
    ] = False,
    ### CONTAINER-RELATED OPTIONS
    build: Annotated[
        bool,
        typer.Option(
            "--build/--no-build",
            "-b/-B",
            help="Whether to build the ASH container image",
        ),
    ] = True,
    run: Annotated[
        bool,
        typer.Option(
            "--run/--no-run",
            "-r/-R",
            help="Whether to run the ASH container image",
        ),
    ] = True,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Force rebuild of the ASH container image",
        ),
    ] = False,
    oci_runner: Annotated[
        Optional[str],
        typer.Option(
            "--oci-runner",
            "--oci",
            "--runner",
            "-o",
            help="Use the specified OCI runner instead of docker to run the containerized tools",
            envvar="OCI_RUNNER",
        ),
    ] = None,
    build_target: Annotated[
        BuildTarget | None,
        typer.Option(
            "--build-target",
            help="Specify the target stage of the ASH image to build",
            case_sensitive=False,
        ),
    ] = None,
    container_uid: Annotated[
        Optional[str],
        typer.Option(
            "--container-uid",
            "-u",
            help="UID to use for the container user",
        ),
    ] = None,
    container_gid: Annotated[
        Optional[str],
        typer.Option(
            "--container-gid",
            "-g",
            help="GID to use for the container user",
        ),
    ] = None,
    ash_revision_to_install: Annotated[
        str | None,
        typer.Option(
            help="ASH branch or tag to install in the container image for usage during containerized scans",
        ),
    ] = None,
    custom_containerfile: Annotated[
        str | None,
        typer.Option(
            help="Path to a custom container definition (e.g. Dockerfile) that you would like to build *after* the ASH container image builds. This is typically used when building a custom container image for ASH and including custom tooling that ASH does not come with by default. The fully qualified image name for the ASH image is passed in as the `ASH_BASE_IMAGE` build-arg so you can use it as a base. IMPORTANT: When a custom_containerfile path is provided, the build-target is set to `ci` so the container run-as configuration is not shifted to the non-root user. If you are using this parameter, you are responsible for securing your final container as appropriate.",
        ),
    ] = None,
    custom_build_arg: Annotated[
        Optional[List[str]],
        typer.Option(
            help="Custom build arguments to pass to the container build",
        ),
    ] = None,
):
    """Runs an ASH scan against the source-dir, outputting results to the output-dir. This is the default command used when there is no explicit. subcommand specified."""
    # Skip if this is tab completion or if a subcommand was invoked
    # When invoked_subcommand is not None, it means we're in the callback and a subcommand
    # (like 'scan') will handle the actual execution with the correct arguments
    if ctx.resilient_parsing or ctx.invoked_subcommand is not None:
        return

    if version:
        typer.echo(f"awslabs/automated-security-helper v{get_ash_version()}")
        raise typer.Exit()

    # Workspace mode is handled before any cwd-based default is applied, because
    # --workspace and --source-dir are mutually exclusive and defaulting
    # source_dir first would make every invocation look like it had both.
    if workspace is None and (
        dry_run or allow_missing_projects or workspace_config is not None
    ):
        # None of these flags mean anything outside workspace mode. Silently
        # ignoring --dry-run would run a full scan for someone who asked for
        # none; silently ignoring --workspace-config would scan with no policy
        # for someone who believes a severity ceiling is in force.
        offending = [
            flag
            for flag, given in (
                ("--dry-run", dry_run),
                ("--allow-missing-projects", allow_missing_projects),
                ("--workspace-config", workspace_config is not None),
            )
            if given
        ]
        _fail_workspace(
            f"{' and '.join(offending)} only applies in workspace mode; pass "
            f"'--workspace <file>' or '--workspace auto' as well."
        )

    # Built HERE, above the workspace block, rather than with the other
    # None-to-empty normalisations below. Workspace resolution needs the COMPLETE
    # override list, because a threshold override changes what each project
    # declares and therefore what --dry-run must print. Normalising afterwards
    # would hand resolution an empty list and the plan would report a threshold
    # the scan does not enforce.
    #
    # --compact-report is why this is not just a None check: it synthesises an
    # override, so config_overrides is non-empty for an operator who never passed
    # --config-overrides. Leaving that below the workspace block would omit it
    # from the plan while the scan applied it.
    if config_overrides is None:
        config_overrides = []
    if compact_report:
        config_overrides.append("reporters.markdown.options.compact=true")

    workspace_plan: WorkspacePlan | None = None
    if workspace is not None:
        workspace_plan = _handle_workspace_mode(
            workspace=workspace,
            source_dir=source_dir,
            allow_missing_projects=allow_missing_projects,
            dry_run=dry_run,
            workspace_config=workspace_config,
            config_overrides=tuple(config_overrides),
        )
        # The workspace root is the scan root: it is what container mode mounts at
        # /src, and what every workspace-relative finding path is relative to.
        # Individual projects get their own source_dir inside the executor.
        source_dir = workspace_plan.workspace_root

    # Rebind list defaults to fresh empty lists at call time so each CLI
    # invocation gets its own collection (typer will populate them if the
    # user supplies --scanners etc., but we guard against reusing aliases).
    if scanners is None:
        scanners = []
    if exclude_scanners is None:
        exclude_scanners = []
    if ash_plugin_modules is None:
        ash_plugin_modules = []
    # config_overrides is normalised above the workspace block; see the comment
    # there for why it cannot happen here.
    if output_formats is None:
        output_formats = []
    if phases is None:
        phases = [ExecutionPhase.CONVERT, ExecutionPhase.SCAN, ExecutionPhase.REPORT]
    if custom_build_arg is None:
        custom_build_arg = []

    # Resolve cwd-based defaults at call time (not import time).
    if source_dir is None:
        source_dir = Path.cwd().as_posix()
    if output_dir is None:
        # Default output_dir is relative to source_dir, not CWD.
        # This ensures that when --source-dir points to a different project,
        # the output (and config resolution) happens in the correct location.
        output_dir = Path(source_dir).joinpath(".ash", "ash_output").as_posix()

    if Path(source_dir).absolute().as_posix() == Path(output_dir).absolute().as_posix():
        output_dir = Path(output_dir).joinpath(".ash", "ash_output")
        print(
            f"[bold yellow]output-dir has been adjusted to the following to avoid collisions and potential impact to source code: {Path(output_dir).as_posix()}[/bold yellow]"
        )

    # Apply mode presets if specified
    precommit_mode = mode == RunMode.precommit or str(mode).lower() == "precommit"
    if precommit_mode:
        print(
            "[green]-------------- Running ASH in pre-commit mode with minimal output --------------[/green]"
        )

    existing_results = None
    if use_existing:
        poss_existing_results = Path(output_dir).joinpath("ash_aggregated_results.json")
        if poss_existing_results.exists():
            existing_results = poss_existing_results.as_posix()
        else:
            raise ValueError(
                f"{poss_existing_results.name} not found in output directory at {poss_existing_results.as_posix()}"
            )

    cli_final_show_progress = (
        progress
        and not verbose
        and not precommit_mode
        and os.environ.get("CI", None) is None
        and os.environ.get("ASH_IN_CONTAINER", "NO").upper()
        not in [
            "YES",
            "1",
            "TRUE",
        ]
    )

    # --compact-report is translated into its config override above the workspace
    # block, so that workspace resolution sees it. Appending here as well would
    # apply it twice.

    # Parse comma-separated output formats
    parsed_output_formats = []
    for item in output_formats:
        for fmt in item.split(","):
            fmt = fmt.strip()
            if fmt:
                try:
                    parsed_output_formats.append(ExportFormat(fmt))
                except ValueError:
                    valid_formats = [f.value for f in ExportFormat]
                    raise typer.BadParameter(
                        f"'{fmt}' is not a valid format. Valid formats are: {', '.join(valid_formats)}"
                    )

    # Call run_ash_scan with all parameters
    run_ash_scan(
        source_dir=source_dir,
        output_dir=output_dir,
        config=config,
        config_overrides=config_overrides,
        offline=offline,
        strategy=strategy,
        scanners=scanners,
        exclude_scanners=exclude_scanners,
        progress=cli_final_show_progress,
        output_formats=parsed_output_formats,
        cleanup=cleanup,
        phases=phases,
        inspect=inspect,
        existing_results=existing_results,
        python_based_plugins_only=python_based_plugins_only,
        log_level=log_level,
        quiet=quiet,
        verbose=verbose,
        debug=debug,
        color=color,
        fail_on_findings=fail_on_findings,
        ignore_suppressions=ignore_suppressions,
        min_severity=min_severity,
        changed_files_only=changed_files_only,
        base_ref=base_ref,
        mode=mode or RunMode.local,
        show_summary=show_summary,
        simple=simple
        or precommit_mode
        or log_level == AshLogLevel.SIMPLE
        or str(log_level).lower() == "simple",
        # Pass the ash_plugin_modules parameter
        ash_plugin_modules=ash_plugin_modules,
        # Container-specific params
        build=build,
        run=run,
        force=force,
        oci_runner=oci_runner,
        build_target=build_target,
        offline_semgrep_rulesets=offline_semgrep_rulesets,
        container_uid=container_uid,
        container_gid=container_gid,
        ash_revision_to_install=ash_revision_to_install,
        custom_containerfile=custom_containerfile,
        custom_build_arg=custom_build_arg,
        workspace_plan=workspace_plan,
        allow_missing_projects=allow_missing_projects,
    )
