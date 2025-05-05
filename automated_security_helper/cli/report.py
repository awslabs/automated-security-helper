# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from pathlib import Path
from typing import Annotated, Optional
import typer
from rich import print, print_json

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.interfaces import IReporter
from automated_security_helper.utils.log import get_logger


def report_command(
    fmt: Annotated[
        str,
        typer.Argument(
            help="Report format to generate (reporter plugin name). Defaults to 'text'.",
        ),
    ] = "text",
    results_file: Annotated[
        Optional[Path],
        typer.Option(
            help="Path to the ash_aggregated_results.json file. Defaults to the latest results.",
            writable=True,
        ),
    ] = None,
    config: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to ASH configuration file.",
        ),
    ] = None,
    output_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--output-dir",
            "-o",
            help="Output directory for generated reports.",
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

    # Ensure results file exists if provided explicitly
    if results_file is not None and not results_file.exists():
        print(f"[red]Error: Results file not found: {results_file}[/red]")
        raise typer.Exit(1)

    # Find the results file if not specified
    if results_file is None:
        # Look in current directory, then .ash/ash_output
        potential_paths = [
            Path.cwd() / "ash_aggregated_results.json",
            Path.cwd() / ".ash" / "ash_output" / "ash_aggregated_results.json",
        ]

        for path in potential_paths:
            if path is None:
                continue
            if Path(path).exists():
                results_file = path
                break

        if results_file is None:
            print("[red]Error: Could not find ash_aggregated_results.json file.[/red]")
            print(
                "[yellow]Please specify the path to the results file or run from a directory containing the results.[/yellow]"
            )
            raise typer.Exit(1)

    # Determine output directory
    if output_dir is None:
        output_dir = results_file.parent

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load the ASH configuration
    ash_config = resolve_config(config_path=config)

    # Create plugin context
    plugin_context = PluginContext(
        source_dir=Path.cwd(),
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=ash_config,
    )

    # Set the plugin context for the plugin manager
    ash_plugin_manager.set_context(plugin_context)

    # Load the results file
    try:
        with open(results_file, "r") as f:
            model = ASHARPModel.model_validate_json(f.read())
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
                if plugin_instance.config.name.lower() == fmt.lower():
                    ASH_LOGGER.info(f"Found reporter plugin {plugin_class.__name__}")
                    reporter_plugin = plugin_instance
                    break
        except Exception as e:
            ASH_LOGGER.debug(
                f"Error initializing reporter plugin {plugin_class.__name__}: {e}"
            )

    if reporter_plugin is None:
        print(f"[red]Error: Reporter plugin '{fmt}' not found.[/red]")
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
        if fmt in [
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
        else:
            print(report_content)
    except Exception as e:
        print(f"[red]Error generating report: {e}[/red]")
        if debug:
            import traceback

            print(traceback.format_exc())
        raise typer.Exit(1)
