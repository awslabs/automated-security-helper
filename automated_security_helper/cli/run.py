# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
from typing import Annotated, List
import typer
from pathlib import Path

from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
)
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.models.core import ExportFormat


class Phases(str, Enum):
    convert = "convert"
    scan = "scan"
    report = "report"
    inspect = "inspect"


class Strategy(str, Enum):
    parallel = "parallel"
    sequential = "sequential"


class AshBuildTarget(str, Enum):
    default = "default"
    ci = "ci"


def run(
    ctx: typer.Context,
    source_dir: Annotated[
        str,
        typer.Option(help="The source directory to scan"),
    ] = Path.cwd().as_posix(),
    output_dir: Annotated[
        str,
        typer.Option(
            help="The directory to output results to",
        ),
    ] = Path.cwd().joinpath(".ash", "ash_output").as_posix(),
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
    strategy: Annotated[
        Strategy,
        typer.Option(help="Whether to run scanners in parallel or sequential"),
    ] = Strategy.parallel.value,
    scanners: Annotated[
        List[str],
        typer.Option(help="Specific scanner names to run. Defaults to all scanners."),
    ] = [],
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
    python_based_plugins_only: Annotated[
        bool,
        typer.Option(
            "--python-only",
            "--python-based-scanners-only",
            "--python-based-plugins-only",
            help="Exclude execution of any plugins or tools that have depencies external to Python.",
        ),
    ] = False,
    quiet: Annotated[bool, typer.Option(help="Hide all log output")] = False,
    simple: Annotated[
        bool,
        typer.Option(
            help="Enable simplified logging. Good for use when you just want brief status and summary of a scan, e.g. during a pre-commit hook."
        ),
    ] = False,
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    fail_on_findings: Annotated[
        bool | None,
        typer.Option(
            help="Enable/disable throwing non-successful exit codes if any actionable findings are found. Defaults to unset, which prefers the configuration value. If this is set directly, it takes precedence over the configuration value."
        ),
    ] = None,
):
    """Runs an ASH scan against the source-dir, outputting results to the output-dir. This is the default command used when there is no explicit. subcommand specified."""
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "scan"]:
        return

    if version:
        from automated_security_helper import __version__

        typer.echo(f"awslabs/automated-security-helper v{__version__}")
        raise typer.Exit()

    run_ash_scan(
        source_dir=source_dir,
        output_dir=output_dir,
        config=config,
        offline=offline,
        strategy=strategy,
        scanners=scanners,
        progress=progress,
        output_formats=output_formats,
        cleanup=cleanup,
        phases=phases,
        inspect=inspect,
        existing_results=existing_results,
        version=version,
        python_based_plugins_only=python_based_plugins_only,
        quiet=quiet,
        simple=simple,
        verbose=verbose,
        debug=debug,
        color=color,
        fail_on_findings=fail_on_findings,
    )
