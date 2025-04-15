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

from automated_security_helper.models.core import ExportFormat


app = typer.Typer(
    name="ash",
    help="Automated Security Helper Multi-Scanner",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=True,
)


class Strategy(Enum):
    parallel = "parallel"
    sequential = "sequential"


class AshBuildTarget(Enum):
    default = "default"
    ci = "ci"


@app.command(
    name="scan",
    no_args_is_help=False,
)
def scan(
    source_dir: Annotated[
        str,
        typer.Option(help="The source directory to scan"),
    ] = Path.cwd().as_posix(),
    output_dir: Annotated[
        str,
        typer.Option(
            help="The directory to output results to",
        ),
    ] = Path.cwd().joinpath("ash_output").as_posix(),
    config: Annotated[
        str,
        typer.Option(help="The path to the configuration file", envvar="ASH_CONFIG"),
    ] = None,
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    offline: Annotated[
        bool,
        typer.Option(
            help="Run scan in offline/airgapped mode (skips NPM/PNPM/Yarn Audit checks). IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage."
        ),
    ] = False,
    no_build: Annotated[
        bool,
        typer.Option(help="Only run the container image, do not rebuild it."),
    ] = False,
    no_run: Annotated[
        bool,
        typer.Option(help="Only build the container image, do not run scans"),
    ] = False,
    build_target: Annotated[
        AshBuildTarget,
        typer.Option(
            help="Specify build target for container image (e.g. 'ci' for elevated access)",
        ),
    ] = AshBuildTarget.default.value,
    oci_runner: Annotated[
        str,
        typer.Option(
            help="Specify OCI runner to use (e.g. 'docker', 'finch')",
            envvar="OCI_RUNNER",
        ),
    ] = os.environ.get("OCI_RUNNER", None),
    strategy: Annotated[
        Strategy,
        typer.Option(help="Whether to run scanners in parallel or sequential"),
    ] = Strategy.parallel.value,
    scanners: Annotated[
        List[str],
        typer.Option(help="Specific scanner names to run. Defaults to all scanners."),
    ] = [],
    no_cleanup: Annotated[
        bool,
        typer.Option(help="Keep working directory after scan completes"),
    ] = False,
    progress: Annotated[
        bool,
        typer.Option(
            help="Show progress of each job interactively in the console. Defaults to True."
        ),
    ] = True,
    output_formats: Annotated[
        List[ExportFormat],
        typer.Option(
            help="The output formats to use",
        ),
    ] = [
        e.value
        for e in [
            ExportFormat.SARIF,
            ExportFormat.CYCLONEDX,
            ExportFormat.JSON,
            ExportFormat.HTML,
            ExportFormat.JUNITXML,
        ]
    ],
):
    """Main entry point."""
    # These are lazy-loaded to prevent slow CLI load-in, which impacts tab-completion
    from automated_security_helper.core.execution_engine import ExecutionStrategy
    from automated_security_helper.models.core import ExportFormat
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.models.asharp_model import ASHARPModel
    from automated_security_helper.utils.log import get_logger

    try:
        logger = get_logger(
            level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
            output_dir=Path(output_dir),
        )
        # Create orchestrator instance
        source_dir = Path(source_dir)
        output_dir = Path(output_dir)
        logger.debug(f"Scanners specified: {scanners}")

        orchestrator = ASHScanOrchestrator(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=output_dir.joinpath("work"),
            scan_output_format=[
                ExportFormat.HTML,
                ExportFormat.JSON,
                ExportFormat.TEXT,
                ExportFormat.YAML,
                ExportFormat.JUNITXML,
            ],
            enabled_scanners=scanners,
            config_path=config,
            verbose=verbose or debug,
            debug=debug,
            strategy=(
                ExecutionStrategy.PARALLEL
                if strategy == Strategy.parallel
                else ExecutionStrategy.SEQUENTIAL
            ),
            no_cleanup=no_cleanup,
            output_formats=output_formats,
            show_progress=progress,
        )

        # Execute scan
        results = orchestrator.execute_scan()
        if isinstance(results, ASHARPModel):
            content = results.model_dump_json(indent=2)
        else:
            content = json.dumps(results, indent=2, default=str)

        # Write results to output file
        output_file = output_dir.joinpath("ash_aggregated_results.json")
        with open(output_file, "w") as f:
            f.write(content)

    except Exception as e:
        logger.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    app()
