# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from pathlib import Path
from typing import Annotated, List, Optional
import typer
from rich import print, print_json
from rich.markdown import Markdown

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import AshLogLevel, ReportFormat
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.interfaces import IReporter
from automated_security_helper.utils.log import get_logger


def get_report_formats(incomplete: str = None) -> List[str]:
    report_formats = []
    # Get values from ReportFormat str enum
    for report_format in ReportFormat:
        if incomplete != "" and incomplete not in report_format.value:
            continue
        report_formats.append(report_format.value)
    return report_formats


def report_command(
    report_format: Annotated[
        str,
        typer.Option(
            "--format",
            help=f"Report format to generate (reporter plugin name). Defaults to 'markdown'. Examples values: {', '.join(get_report_formats(''))}",
            autocompletion=get_report_formats,
            shell_complete=get_report_formats,
        ),
    ] = ReportFormat.markdown.value,
    output_dir: Annotated[
        str,
        typer.Option(
            help="The directory to output results to",
            envvar="ASH_OUTPUT_DIR",
        ),
    ] = Path.cwd().joinpath(".ash", "ash_output").as_posix(),
    config: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to ASH configuration file.",
        ),
    ] = None,
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
):
    """Generate a report from ASH scan results using the specified reporter plugin."""
    # Set up logging
    final_log_level = (
        AshLogLevel.VERBOSE
        if verbose
        else AshLogLevel.DEBUG
        if debug
        else AshLogLevel.ERROR
        if log_level
        in [
            AshLogLevel.QUIET,
            AshLogLevel.ERROR,
            AshLogLevel.SIMPLE,
        ]
        else log_level
    )
    final_logging_log_level = logging._nameToLevel.get(
        final_log_level.value, logging.INFO
    )
    ASH_LOGGER = get_logger(level=final_logging_log_level)
    results_file = None
    output_dir_path = Path(output_dir)
    results_file_paths = [
        output_dir_path.joinpath(".ash", "ash_output", "ash_aggregated_results.json"),
        output_dir_path.joinpath("ash_output", "ash_aggregated_results.json"),
        output_dir_path.joinpath("ash_aggregated_results.json"),
    ]
    for poss_result_file in results_file_paths:
        if poss_result_file.exists():
            results_file = poss_result_file
            break

    # Ensure results file exists if provided explicitly
    if results_file is not None and not results_file.exists():
        print(f"[red]Error: Results file not found: {results_file}[/red]")
        raise typer.Exit(1)

    # Determine output directory
    if output_dir is None:
        output_dir = results_file.parent
        output_dir_path = Path(output_dir)

    # Ensure output directory exists
    output_dir_path.mkdir(parents=True, exist_ok=True)

    # Load the ASH configuration
    ash_config = resolve_config(config_path=config)

    # Create plugin context
    plugin_context = PluginContext(
        source_dir=Path.cwd(),
        output_dir=output_dir_path,
        work_dir=output_dir_path.joinpath("work"),
        config=ash_config,
    )

    # Set the plugin context for the plugin manager
    ash_plugin_manager.set_context(plugin_context)

    # Load the results file
    try:
        with open(results_file, "r") as f:
            model = AshAggregatedResults.model_validate_json(f.read())
    except Exception as e:
        print(f"[red]Error loading results file: {e}[/red]")
        raise typer.Exit(1)

    # Find the reporter plugin
    reporter_plugins = ash_plugin_manager.plugin_modules(
        plugin_type=IReporter,
    )
    reporter_plugin = None

    for plugin_class in reporter_plugins:
        try:
            plugin_instance = plugin_class(
                context=plugin_context,
            )

            if hasattr(plugin_instance, "config") and hasattr(
                plugin_instance.config, "name"
            ):
                if plugin_instance.config.name.lower() == report_format.lower():
                    ASH_LOGGER.info(f"Found reporter plugin {plugin_class.__name__}")
                    reporter_plugin = plugin_instance
                    break
        except Exception as e:
            ASH_LOGGER.debug(
                f"Error initializing reporter plugin {plugin_class.__name__}: {e}"
            )

    if reporter_plugin is None:
        print(f"[red]Error: Reporter plugin '{report_format}' not found.[/red]")
        print("[yellow]Available reporter formats:[/yellow]")
        for plugin_class in reporter_plugins:
            try:
                plugin_instance = plugin_class(context=plugin_context)
                if hasattr(plugin_instance, "config") and hasattr(
                    plugin_instance.config, "name"
                ):
                    print(f"  - {plugin_instance.config.name}")
            except Exception as e:
                ASH_LOGGER.trace(e)
        raise typer.Exit(1)

    # Generate the report
    try:
        report_content = reporter_plugin.report(model)
        if report_format in [
            "asff",
            # "csv",
            "cyclonedx",
            # "html",
            "flat-json",
            # "junitxml",
            # "markdown",
            "ocsf",
            "sarif",
            "spdx",
            # "text",
            # "yaml",
        ]:
            print_json(report_content)
        elif report_format == "markdown":
            print(Markdown(report_content))
        else:
            print(report_content)
    except Exception as e:
        print(f"[red]Error generating report: {e}[/red]")
        if debug:
            import traceback

            print(traceback.format_exc())
        raise typer.Exit(1)
