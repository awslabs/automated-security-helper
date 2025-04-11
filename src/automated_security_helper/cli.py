# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import Annotated, List
import typer
import json
import sys
from pathlib import Path


from automated_security_helper.core.execution_engine import ExecutionStrategy
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.core import ExportFormat
from automated_security_helper.utils.log import ASH_LOGGER


app = typer.Typer(
    name="ash",
    help="Automated Security Helper Multi-Scanner",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=True,
)


@app.command(
    name="scan",
    no_args_is_help=True,
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
        str, typer.Option(help="The path to the configuration file")
    ] = None,
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    offline: Annotated[
        bool,
        typer.Option(help="Run in offline mode (skips NPM/PNPM/Yarn Audit checks)"),
    ] = False,
    no_run: Annotated[
        bool,
        typer.Option(help="Only build the container image, do not run scans"),
    ] = False,
    build_target: Annotated[
        str,
        typer.Option(
            help="Specify build target for container image (e.g. 'ci' for elevated access)",
        ),
    ] = "default",
    oci_runner: Annotated[
        str,
        typer.Option(help="Specify OCI runner to use (e.g. 'docker', 'finch')"),
    ] = os.environ.get("OCI_RUNNER", None),
    strategy: Annotated[
        ExecutionStrategy,
        typer.Option(help="Whether to run scanners in parallel or sequential"),
    ] = ExecutionStrategy.PARALLEL,
    scanners: Annotated[
        List[str],
        typer.Option(help="Specific scanner names to run. Defaults to all scanners."),
    ] = [],
    no_cleanup: Annotated[
        bool,
        typer.Option(help="Keep working directory after scan completes"),
    ] = False,
    output_formats: Annotated[
        list[ExportFormat],
        typer.Option(
            help="The output formats to use",
        ),
    ] = ["sarif", "cyclonedx", "json", "html", "junitxml"],
):
    """Main entry point."""

    # def parse_args():
    #     """Parse command line arguments."""
    #     parser = argparse.ArgumentParser(description="ASH Multi-Scanner")
    #     parser.add_argument(
    #         "-s", "--source-dir", dest="source", help="Source directory to scan"
    #     )
    #     parser.add_argument(
    #         "-o",
    #         "--output-dir",
    #         dest="output",
    #         required=False,
    #         help="Output file path",
    #     )
    #     parser.add_argument("-c", "--config", help="Path to configuration file")
    #     parser.add_argument(
    #         "-f",
    #         "--format",
    #         dest="formats",
    #         action="append",
    #         default=[],
    #         help="Output format(s) (can be specified multiple times, defaults to json if none specified)",
    #         choices=[
    #             "json",
    #             "text",
    #             "html",
    #             "csv",
    #             "yaml",
    #             "junitxml",
    #             "sarif",
    #             "asff",
    #             "cyclonedx",
    #             "spdx",
    #         ],
    #     )
    #     parser.add_argument(
    #         "-v", "--verbose", action="store_true", help="Enable verbose logging"
    #     )
    #     parser.add_argument(
    #         "--debug", action="store_true", help="Enable debug logging"
    #     )
    #     parser.add_argument(
    #         "--offline",
    #         action="store_true",
    #         help="Run in offline mode (skips NPM/PNPM/Yarn Audit checks)",
    #     )
    #     parser.add_argument(
    #         "--no-run",
    #         action="store_true",
    #         help="Only build the container image, do not run scans",
    #     )
    #     parser.add_argument(
    #         "--build-target",
    #         default="default",
    #         help="Specify build target for container image (e.g. 'ci' for elevated access)",
    #     )
    #     parser.add_argument(
    #         "--oci-runner",
    #         default="docker",
    #         help="Specify OCI runner to use (e.g. 'docker', 'finch')",
    #     )
    #     parser.add_argument(
    #         "--strategy",
    #         default="sequential",
    #         help="Whether to run scanners in parallel or sequential",
    #         choices=[
    #             "sequential",
    #             "parallel",
    #         ],
    #     )
    #     parser.add_argument(
    #         "--scanners",
    #         help="Specific scanner names to run",
    #     )
    #     parser.add_argument(
    #         "--no-cleanup",
    #         action="store_true",
    #         help="Keep working directory after scan completes",
    #     )

    # args = parse_args()

    try:
        # Create orchestrator instance
        source_dir = Path(source_dir)
        output_dir = Path(output_dir)

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
            verbose=verbose,
            strategy=strategy,
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
        ASH_LOGGER.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    app()
