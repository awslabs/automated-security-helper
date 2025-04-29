# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
import logging
import os
from typing import Annotated, List
import typer
import json
import sys
from pathlib import Path

from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_WORK_DIR_NAME,
)
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
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """Runs an ASH scan against the source-dir, outputting results to the output-dir. This is the default command used when there is no explicit. subcommand specified."""
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "scan"]:
        return

    if version:
        from automated_security_helper import __version__

        typer.echo(f"awslabs/automated-security-helper v{__version__}")
        raise typer.Exit()

    # These are lazy-loaded to prevent slow CLI load-in, which impacts tab-completion
    from automated_security_helper.core.progress import ExecutionStrategy
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.models.asharp_model import ASHARPModel
    from automated_security_helper.utils.log import get_logger

    try:
        logger = get_logger(
            level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
            output_dir=Path(output_dir),
            show_progress=progress
            and os.environ.get("ASH_IN_CONTAINER", "NO").upper()
            not in ["YES", "1", "TRUE"],
            use_color=color,
        )
        # Create orchestrator instance
        source_dir = Path(source_dir)
        output_dir = Path(output_dir)
        logger.debug(f"Scanners specified: {scanners}")

        if config is None:
            for config_file in ASH_CONFIG_FILE_NAMES:
                def_paths = [
                    Path(source_dir).joinpath(config_file),
                    Path(source_dir).joinpath(".ash", config_file),
                ]
                for def_path in def_paths:
                    if def_path.exists():
                        logger.info(
                            f"Using config file found at: {def_path.as_posix()}"
                        )
                        config = def_path.as_posix()
                        break
                if config is not None:
                    break
        else:
            logger.info(f"Using config file specified at: {config}")

        orchestrator = ASHScanOrchestrator(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=output_dir.joinpath(ASH_WORK_DIR_NAME),
            enabled_scanners=scanners,
            config_path=config,
            verbose=verbose or debug,
            debug=debug,
            strategy=(
                ExecutionStrategy.PARALLEL
                if strategy == Strategy.parallel
                else ExecutionStrategy.SEQUENTIAL
            ),
            no_cleanup=not cleanup,
            output_formats=output_formats,
            show_progress=progress
            and (
                os.environ.get("ASH_IN_CONTAINER", "NO").upper()
                not in [
                    "YES",
                    "1",
                    "TRUE",
                ]  # Running inside the container is not guaranteed to produce the live progress outputs correctly
                or os.environ.get("CI", None)
                is not None  # Neither is running in a CI pipeline
            ),
            color_system="auto" if color else None,
            offline=(
                offline
                if offline is not None
                else os.environ.get("ASH_OFFLINE", "NO").upper() in ["YES", "1", "TRUE"]
            ),
            existing_results_path=Path(existing_results) if existing_results else None,
        )

        # Determine which phases to run. Process them in required order to build the
        # final ordered list of execution.
        phases_to_run = []
        if Phases.convert in phases:
            phases_to_run.append("convert")
        if Phases.scan in phases:
            phases_to_run.append("scan")
        if Phases.report in phases:
            phases_to_run.append("report")
        if Phases.inspect in phases or inspect:
            phases_to_run.append("inspect")

            # If inspect is enabled via command line, update the config
            if inspect and orchestrator.config:
                if not hasattr(orchestrator.config, "inspect"):
                    setattr(orchestrator.config, "inspect", {})
                orchestrator.config.inspect["enabled"] = True

        # Default to all phases if none specified
        if not phases_to_run:
            phases_to_run = ["convert", "scan", "report"]

        logger.debug(f"Running phases: {phases_to_run}")

        # Execute scan with specified phases
        results = orchestrator.execute_scan(phases=phases_to_run)
        if isinstance(results, ASHARPModel):
            content = results.model_dump_json(indent=2, by_alias=True)
        else:
            content = json.dumps(results, indent=2, default=str)

        # Write results to output file
        output_file = output_dir.joinpath("ash_aggregated_results.json")
        with open(output_file, "w") as f:
            f.write(content)

    except Exception as e:
        logger.exception(e)
        sys.exit(1)
