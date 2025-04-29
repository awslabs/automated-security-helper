# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH plugins.
"""

import json
import os
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugins.loader import load_plugins
from automated_security_helper.config.default_config import get_default_config

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
):
    """
    List plugins available within the current Python session.
    """
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "scan"]:
        return

    try:
        console = Console()
        plugin_context = PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
            config=get_default_config(),
        )

        # Load all plugins
        loaded_plugins = load_plugins()

        # Create tables for each plugin type
        plugin_types = {
            "scanners": loaded_plugins.get("scanners", []),
            "converters": loaded_plugins.get("converters", []),
            "reporters": loaded_plugins.get("reporters", []),
        }

        for plugin_type, plugin_list in plugin_types.items():
            table = Table(
                "Name",
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

                    # Create an instance to get the config name
                    try:
                        plugin_config = plugin_context.config.get_plugin_config(
                            plugin_type=plugin_type.rstrip("s"),  # Remove 's' from end
                            plugin_name=plugin_class_name,
                        )
                        if hasattr(plugin_config, "model_dump"):
                            plugin_config = plugin_config.model_dump()

                        # plugin_instance = plugin_class(
                        #     context=plugin_context,
                        #     config=plugin_config,
                        # )

                        # Get the actual name from the config
                        plugin_name = plugin_config.get("name", plugin_class_name)

                        # Add row to table
                        table.add_row(
                            plugin_name,
                            plugin_class_name,
                            plugin_module,
                            (
                                plugin_config.model_dump_json(indent=2)
                                if hasattr(plugin_config, "model_dump_json")
                                and callable(plugin_config.model_dump_json)
                                else (
                                    json.dumps(plugin_config, default=str, indent=2)
                                    if plugin_config
                                    else "N/A"
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
