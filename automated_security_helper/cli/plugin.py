# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH plugins.
"""

import json
import logging
import os
from pathlib import Path
from typing import Annotated, List
import typer
from rich.console import Console
from rich.table import Table

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import (
    find_config_file,
    resolve_config,
)
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
    include_plugin_config: Annotated[
        bool,
        typer.Option(help="Whether to include the plugin config in the response table"),
    ] = False,
    ash_plugin_modules: Annotated[
        List[str],
        typer.Option(
            help="List of Python modules to import containing ASH plugins and/or event subscribers. These are loaded in addition to the default modules.",
            envvar="ASH_PLUGIN_MODULES",
        ),
    ] = [],
    config: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    config_overrides: Annotated[
        List[str],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2')",
        ),
    ] = [],
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    show_versions: Annotated[
        bool,
        typer.Option(
            "--show-versions",
            help=(
                "For scanners, add Version and Reachable columns reporting each "
                "scanner's detected tool version and whether its dependencies are "
                "satisfied (Yes/No/Unknown). Off by default, so the fast listing is "
                "unchanged; enabling it instantiates each scanner and runs its "
                "dependency check, which takes longer."
            ),
        ),
    ] = False,
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
        found = find_config_file()
        if found is not None:
            logger.info(f"Using config file found at: {found.as_posix()}")
            config = found.as_posix()
    else:
        logger.info(f"Using config file specified at: {config}")

    try:
        console = Console()
        ash_config = resolve_config(
            config_path=config, config_overrides=config_overrides
        )
        ash_config.ash_plugin_modules.extend(ash_plugin_modules)
        plugin_context = PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
            config=ash_config,
        )

        # Load all plugins
        loaded_plugins = load_plugins(plugin_context=plugin_context)

        # Create tables for each plugin type
        plugin_types = {
            "scanners": loaded_plugins.get("scanners", []),
            "converters": loaded_plugins.get("converters", []),
            "reporters": loaded_plugins.get("reporters", []),
        }

        # When --show-versions is requested, describe the loaded scanners through
        # the SAME shared inventory path the MCP list_scanners tool uses, so the
        # two surfaces cannot drift (issues #606/#626). list_scanner_inventory
        # probes in an isolated throwaway context (not the cwd) on purpose:
        # dependency/version checks ask environment questions ("is this binary on
        # PATH", "is this module importable"), so pointing the probe at the working
        # tree would let a stray file change the answer to a deployment question.
        # The CLI therefore delegates to that isolated path rather than re-probing
        # against Path.cwd() -- both surfaces now share one probe context, and the
        # parity test exercises this exact call. Keyed by the scanner's snake_cased
        # config name so each per-class row can look up its own entry.
        scanner_inventory_by_class: dict = {}
        if show_versions:
            from automated_security_helper.core.scanner_inventory import (
                list_scanner_inventory,
                _scanner_name_from_class,
            )

            try:
                inventory = list_scanner_inventory(
                    scanner_classes_provider=lambda: plugin_types["scanners"]
                )
                by_name = {entry.get("name"): entry for entry in inventory}
                for scanner_class in plugin_types["scanners"]:
                    scanner_inventory_by_class[scanner_class] = by_name.get(
                        _scanner_name_from_class(scanner_class)
                    )
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug(f"Could not build scanner inventory: {exc}")
                for scanner_class in plugin_types["scanners"]:
                    scanner_inventory_by_class[scanner_class] = None

        def _reachable_label(entry) -> str:
            """Map tri-state dependencies_satisfied to a Yes/No/Unknown label."""
            if entry is None:
                return "Unknown"
            satisfied = entry.get("dependencies_satisfied")
            if satisfied is True:
                return "Yes"
            if satisfied is False:
                return "No"
            return "Unknown"

        def _version_label(entry) -> str:
            """Render the detected version, or 'Unknown' when none was detected."""
            if entry is None:
                return "Unknown"
            return entry.get("version") or "Unknown"

        for plugin_type, plugin_list in plugin_types.items():
            show_version_cols = show_versions and plugin_type == "scanners"

            columns = ["Name", "Enabled", "Class", "Module"]
            if show_version_cols:
                columns.extend(["Version", "Reachable"])
            columns.append("Plugin Config")

            table = Table(
                *columns,
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

                    inventory_entry = scanner_inventory_by_class.get(plugin_class)

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

                        # Resolve the real enabled state. By this point
                        # plugin_config has been model_dump()'d to a dict in every
                        # reachable branch, so `hasattr(plugin_config, "enabled")`
                        # was always False and the column previously rendered the
                        # literal "True" for every plugin (incl. disabled ones).
                        # Read the dict key (or an object attr, defensively),
                        # falling back to True only when the flag is genuinely
                        # absent.
                        if isinstance(plugin_config, dict):
                            enabled_value = plugin_config.get("enabled", True)
                        else:
                            enabled_value = getattr(plugin_config, "enabled", True)

                        # Assemble the row in column order. Version/Reachable are
                        # inserted only when the scanner version columns are shown.
                        row = [
                            plugin_name,
                            enabled_value,
                            plugin_class_name,
                            plugin_module,
                        ]
                        if show_version_cols:
                            row.append(_version_label(inventory_entry))
                            row.append(_reachable_label(inventory_entry))
                        row.append(
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
                        )
                        # Enabled may be a bool; Rich requires str cells.
                        table.add_row(*[str(cell) for cell in row])
                    except Exception as e:
                        # If we can't instantiate, still show the plugin but note the
                        # error. The row must fill every column of the table, so it is
                        # built from the same column order rather than a fixed 3-arg
                        # call (the pre-existing bug: a 5- or 7-column table given 3
                        # cells raised "Not enough columns" and masked the real error).
                        error_row = [
                            f"{plugin_class_name.lower()} (Error: {str(e)})",
                            "Unknown",
                            plugin_class_name,
                            plugin_module,
                        ]
                        if show_version_cols:
                            error_row.append(_version_label(inventory_entry))
                            error_row.append(_reachable_label(inventory_entry))
                        error_row.append("")
                        table.add_row(*[str(cell) for cell in error_row])

            console.print(table)
    except Exception as e:
        typer.secho(
            f"Error: {e}",
            err=True,
        )
        raise typer.Exit(1)


if __name__ == "__main__":
    plugin_app()
