# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH outputs and reports.
"""

import os
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.plugin_registry import PluginRegistry

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
    # config: Annotated[
    #     str,
    #     typer.Option(
    #         help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
    #         envvar="ASH_CONFIG",
    #     ),
    # ] = None,
):
    """
    List plugins available within the current Python session.
    """
    """Runs an ASH scan against the source-dir, outputting results to the output-dir. This is the default command used when there is no explicit. subcommand specified."""
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "scan"]:
        return

    try:
        # logger = get_logger()
        console = Console()
        plugin_context = PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath("ash_output"),
        )
        plugin_registry = PluginRegistry(plugin_context=plugin_context)
        plugins = {
            "scanners": plugin_registry.get_plugin("scanner"),
            "converters": plugin_registry.get_plugin("converter"),
            "reporters": plugin_registry.get_plugin("reporter"),
        }
        for plugin_type, plugin_list in plugins.items():
            table = Table(
                "Name",
                "Enabled",
                "Default Options",
                title=f"ASH {plugin_type.capitalize()}",
                title_justify="left",
                title_style="bold",
                show_lines=True,
            )
            if isinstance(plugin_list, dict):
                for plugin_name, reg_plugin in plugin_list.items():
                    table.add_row(
                        reg_plugin.plugin_config.name,
                        str(reg_plugin.plugin_config.enabled),
                        reg_plugin.plugin_config.options.model_dump_json(
                            by_alias=True,
                            exclude_none=True,
                            exclude_unset=True,
                            indent=2,
                        ),
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
