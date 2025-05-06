# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from rich import print
from typing import Annotated, List, Optional
import typer
from pathlib import Path

from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    Phases,
    RunMode,
    Strategy,
)
from automated_security_helper.interactions.run_ash_scan import (
    run_ash_scan,
)
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.utils.get_ash_version import get_ash_version


def run_ash_scan_cli_command(
    ctx: typer.Context,
    source_dir: Annotated[
        str,
        typer.Option(
            help="The source directory to scan",
        ),
    ] = Path.cwd().as_posix(),
    output_dir: Annotated[
        str,
        typer.Option(
            help="The directory to output results to",
            envvar="ASH_OUTPUT_DIR",
        ),
    ] = Path.cwd().joinpath(".ash", "ash_output").as_posix(),
    scanners: Annotated[
        List[str],
        typer.Option(help="Specific scanner names to run. Defaults to all scanners."),
    ] = [],
    exclude_scanners: Annotated[
        List[str],
        typer.Option(
            help="Specific scanner names to exclude from running. Takes precedence over scanners parameter."
        ),
    ] = [],
    config: Annotated[
        str,
        typer.Option(
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
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
        Strategy,
        typer.Option(help="Whether to run scanners in parallel or sequential"),
    ] = Strategy.parallel.value,
    progress: Annotated[
        bool,
        typer.Option(
            help="Show progress of each job live in the console. Defaults to True."
        ),
    ] = True,
    output_formats: Annotated[
        List[ExportFormat],
        typer.Option(
            "--output-formats",
            "-o",
            help="The output formats to use",
        ),
    ] = [],
    cleanup: Annotated[
        bool,
        typer.Option(
            help="Clean up 'converted' directory and other temporary files after scan completes. Defaults to False. Note: Scans will always clean up existing files in the output directory before a new scan starts. This parameter only affects the cleanup of the temporary work directory after a scan has completed, typically for inspection of temporary artifacts."
        ),
    ] = False,
    phases: Annotated[
        List[Phases],
        typer.Option(
            help="The phases to run. Defaults to all phases except inspect.",
        ),
    ] = [
        Phases.convert,
        Phases.scan,
        Phases.report,
    ],
    inspect: Annotated[
        bool,
        typer.Option(
            help="Enable inspection of SARIF fields after running. This adds the inspect phase to the execution.",
        ),
    ] = False,
    existing_results: Annotated[
        str,
        typer.Option(
            "--existing-results",
            help="Path to an existing ash_aggregated_results.json file. If provided, the scan phase will be skipped and reports will be generated from this file.",
        ),
    ] = None,
    version: Annotated[
        bool,
        typer.Option(
            "-v",
            "--version",
            help="Prints version number",
        ),
    ] = False,
    mode: Annotated[
        Optional[RunMode],
        typer.Option(
            help="Execution mode preset. 'precommit' enables python-based plugins only and simplified output. 'container' runs non-Python plugins in a container. 'local' (default) runs everything in the local Python process.",
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
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    fail_on_findings: Annotated[
        bool | None,
        typer.Option(
            help="Enable/disable throwing non-successful exit codes if any actionable findings are found. Defaults to unset, which prefers the configuration value. If this is set directly, it takes precedence over the configuration value."
        ),
    ] = None,
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
            "-f",
            help="Force rebuild of the ASH container image",
        ),
    ] = False,
    oci_runner: Annotated[
        Optional[str],
        typer.Option(
            "--oci-runner",
            "--oci",
            "--runner",
            "-r",
            help="Use the specified OCI runner instead of docker to run the containerized tools",
            envvar="OCI_RUNNER",
        ),
    ] = None,
    # preserve_report: Annotated[
    #     bool,
    #     typer.Option(
    #         "--preserve-report",
    #         "-p",
    #         help="Add timestamp to the final report file to avoid overwriting it after multiple executions",
    #     ),
    # ] = False,
    # extension: Annotated[
    #     Optional[str],
    #     typer.Option(
    #         "--ext",
    #         "--extension",
    #         "-e",
    #         help="Force a file extension to scan. Defaults to identify files automatically",
    #     ),
    # ] = None,
    build_target: Annotated[
        BuildTarget,
        typer.Option(
            "--build-target",
            help="Specify the target stage of the ASH image to build",
            case_sensitive=False,
        ),
    ] = BuildTarget.NON_ROOT,
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
        List[str],
        typer.Option(
            help="Custom build arguments to pass to the container build",
        ),
    ] = [],
):
    """Runs an ASH scan against the source-dir, outputting results to the output-dir. This is the default command used when there is no explicit. subcommand specified."""
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "scan"]:
        return

    if version:
        typer.echo(f"awslabs/automated-security-helper v{get_ash_version()}")
        raise typer.Exit()

    # Apply mode presets if specified
    precommit_mode = mode == RunMode.precommit or str(mode).lower() == "precommit"
    if precommit_mode:
        print(
            "[green]╭───────────── Running ASH in pre-commit mode with minimal output ─────────────╮[/green]"
        )

    # Call run_ash_scan with all parameters
    run_ash_scan(
        source_dir=source_dir,
        output_dir=output_dir,
        config=config,
        offline=offline,
        strategy=strategy,
        scanners=scanners,
        exclude_scanners=exclude_scanners,
        progress=not precommit_mode and progress,
        output_formats=output_formats,
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
        mode=mode,
        show_summary=show_summary,
        simple=precommit_mode
        or log_level == AshLogLevel.SIMPLE
        or str(log_level).lower() == "simple",
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
    )
