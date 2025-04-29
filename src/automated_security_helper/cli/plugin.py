# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH plugins.
"""

import json
import logging
import os
from pathlib import Path
from typing import Annotated
import typer
from rich.console import Console
from rich.table import Table

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.plugins.loader import load_plugins
from automated_security_helper.utils.log import get_logger

plugin_app = typer.Typer(
    name="plugin",
    help="Manage ASH plugins",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
    in ["YES", "1", "TRUE"],
)


@plugin_app.command(
    name="list",
    help="""
The `plugin list` command lists all available plugins.
""",
)
def list_plugins(
    ctx: typer.Context,
    config: Annotated[
        str,
        typer.Option(
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    include_plugin_config: Annotated[
        bool,
        typer.Option(help="Whether to include the plugin config in the response table"),
    ] = False,
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """
    List plugins available within the current Python session.
    """
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "scan"]:
        return

    logger = get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )

    if config is None:
        for config_file in ASH_CONFIG_FILE_NAMES:
            def_paths = [
                Path.cwd().joinpath(config_file),
                Path.cwd().joinpath(".ash", config_file),
            ]
            for def_path in def_paths:
                if def_path.exists():
                    logger.info(f"Using config file found at: {def_path.as_posix()}")
                    config = def_path.as_posix()
                    break
            if config is not None:
                break
    else:
        logger.info(f"Using config file specified at: {config}")

    try:
        console = Console()
        plugin_context = PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
            config=resolve_config(config_path=config),
        )

        # Load all plugins
        loaded_plugins = load_plugins(plugin_context=plugin_context)

        # Create tables for each plugin type
        plugin_types = {
            "scanners": loaded_plugins.get("scanners", []),
            "converters": loaded_plugins.get("converters", []),
            "reporters": loaded_plugins.get("reporters", []),
        }

        for plugin_type, plugin_list in plugin_types.items():
            table = Table(
                "Name",
                "Enabled",
                "Class",
                "Module",
                "Plugin Config",
                title=f"ASH {plugin_type.capitalize()}",
                title_justify="left",
                title_style="bold",
                show_lines=True,
            )

            if plugin_list:
                for plugin_class in plugin_list:
                    # Get plugin name and module
                    plugin_class_name = getattr(plugin_class, "__name__", "Unknown")
                    plugin_module = getattr(plugin_class, "__module__", "Unknown")
                    plugin_name = plugin_class_name

                    # Create an instance to get the config name
                    try:
                        plugin_config = plugin_context.config.get_plugin_config(
                            plugin_type=plugin_type.rstrip("s"),  # Remove 's' from end
                            plugin_name=plugin_class_name,
                        )
                        if hasattr(plugin_config, "model_dump"):
                            plugin_config = plugin_config.model_dump()

                        # Get the actual name from the config
                        if isinstance(plugin_config, dict):
                            plugin_name = plugin_config.get("name", plugin_class_name)
                        else:
                            plugin_instance = plugin_class(
                                context=plugin_context,
                                config=plugin_config,
                            )
                            try:
                                plugin_name = plugin_instance.config.name
                                plugin_config = plugin_instance.config
                                if hasattr(plugin_config, "model_dump"):
                                    plugin_config = plugin_config.model_dump()
                            except AttributeError:
                                plugin_name = plugin_class_name

                        # Add row to table
                        table.add_row(
                            plugin_name,
                            (
                                plugin_config.enabled
                                if hasattr(plugin_config, "enabled")
                                else "True"
                            ),
                            plugin_class_name,
                            plugin_module,
                            (
                                ""
                                if not include_plugin_config
                                else (
                                    plugin_config.model_dump_json(indent=2)
                                    if hasattr(plugin_config, "model_dump_json")
                                    and callable(plugin_config.model_dump_json)
                                    else (
                                        json.dumps(plugin_config, default=str, indent=2)
                                        if plugin_config
                                        else "N/A"
                                    )
                                )
                            ),
                        )
                    except Exception as e:
                        # If we can't instantiate, still show the plugin but note the error
                        table.add_row(
                            f"{plugin_class_name.lower()} (Error: {str(e)})",
                            plugin_class_name,
                            plugin_module,
                        )

            console.print(table)
    except Exception as e:
        typer.secho(
            f"Error: {e}",
            err=True,
        )
        raise typer.Exit(1)


if __name__ == "__main__":
    plugin_app()
