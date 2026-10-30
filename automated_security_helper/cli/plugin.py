# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH plugins.
"""

import json
import logging
from pathlib import Path
from typing import Annotated, List
import typer
from automated_security_helper.utils.ui_theme import rich_theme
from rich.table import Table

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import off_host_reporter_refused
from automated_security_helper.base.uv_tool_mixin import (
    deferred_tool_version_probes,
    guarded_values,
)
from automated_security_helper.config.named_config import (
    refuse_a_named_config_that_does_not_exist,
)
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.plugin_option_check import (
    refuse_unknown_plugin_options,
)
from automated_security_helper.config.resolve_config import (
    find_config_file,
    resolve_config,
)
from automated_security_helper.core.constants import ASH_CONFIG_SOURCES_DESCRIPTION
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugins.loader import (
    PluginModuleError,
    PluginModuleNamespaceError,
    load_plugins,
    plugin_module_fix,
    scan_plugin_filter,
)
from automated_security_helper.utils.console import ash_console, secho
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import (
    escape_markup,
    get_logger,
    show_debug_locals,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line
from automated_security_helper.utils.uv_tool_runner import checking_only

#: The table titles, by the plugin type the registry and a scan use.
_PLUGIN_TYPES = (
    ("scanner", "scanners"),
    ("converter", "converters"),
    ("reporter", "reporters"),
)

plugin_app = typer.Typer(
    name="plugin",
    help="Manage ASH plugins",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    # Not on a CI runner: locals can hold secrets (utils/log.py).
    pretty_exceptions_show_locals=show_debug_locals(),
)


@plugin_app.command(
    name="list",
    help="""
The `plugin list` command lists what a scan with this configuration loads, on or off.
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
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
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
                "satisfied (Yes/No/Unknown). Off by default; enabling it checks "
                "each scanner's dependencies and probes its version, which takes "
                "longer."
            ),
        ),
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """
    List the plugins a scan with this configuration runs: the built-in plugins
    and those the run's plugin modules bring in, each built from its configured
    section as the scan builds it. A plugin that is installed but not selected
    by this configuration is not listed.
    """
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "scan"]:
        return

    logger = get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )

    try:
        # A named config file that is not there is refused first, exit 3 below:
        # resolve_config would answer it with the default configuration, and the
        # listing would describe a configuration other than the one named.
        refuse_a_named_config_that_does_not_exist(config)
        # Inside the try: discovery refuses a source it cannot read (exit 3).
        if config is None:
            found = find_config_file()
            if found is not None:
                # One line: the path is the caller's text, as in cli/config.py.
                logger.info(
                    shown_on_one_line(f"Using config file found at: {found.as_posix()}")
                )
                config = found.as_posix()
        else:
            logger.info(shown_on_one_line(f"Using config file specified at: {config}"))

        # The theme is ASH's own (rich_theme); the console stays the
        # command-safe one (ash_console), which passes Console's own
        # arguments through. --no-color reaches the tables through it: it
        # used to reach the logger alone.
        console = ash_console(theme=rich_theme(), no_color=not color)
        ash_config = resolve_config(
            config_path=config, config_overrides=config_overrides
        )
        # Split on commas and stripped, from the config and the flag alike, the way
        # a scan reads them: "a_ash_plugins, b_ash_plugins" names two modules.
        from automated_security_helper.config.plugin_module_trust import (
            drop_untrusted_off_host_plugins,
            reindex_plugin_module_references,
            split_plugin_modules,
        )

        entries_as_written = [*ash_config.ash_plugin_modules, *ash_plugin_modules]
        split_modules = split_plugin_modules(entries_as_written)
        # The split renumbers the list (a comma-joined entry becomes several),
        # so the config's references move with their entries: a refusal naming
        # an entry the file read from the environment reads them by index.
        # The move comes first: it changes nothing when it refuses.
        reindex_plugin_module_references(ash_config, entries_as_written, split_modules)
        ash_config.ash_plugin_modules = split_modules
        plugin_context = PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
            config=ash_config,
        )

        # Load all plugins
        loaded_plugins = load_plugins(plugin_context=plugin_context)

        # What is registered that a scan of this configuration selects from. The
        # ASH_SCANNERS, ASH_CONVERTERS and ASH_REPORTERS lists load_plugins
        # returns register nothing, so showing them would miss a decorated plugin
        # a package does not list, and show a listed class that was never
        # registered. The lists give the order, so the built-in tables keep it.
        from automated_security_helper.plugins import ash_plugin_manager

        # Selected as a scan with this configuration selects them, in the engine's
        # three steps (core/execution_engine.py): of the registered classes, the
        # built-in plugins plus those the run's ash_plugin_modules define, bind
        # or list (plugins.loader.scan_plugin_filter); minus what only another
        # run's untrusted import registered; minus the off-host classes the
        # trusted modules do not load. Listing everything registered named
        # plugins, as Enabled, that no scan with the same configuration runs.
        admits = scan_plugin_filter(split_modules)
        selected = {
            kind: list(ash_plugin_manager.plugin_modules(kind, admits))
            for kind in ("scanner", "converter", "reporter")
        }
        selected = ash_plugin_manager.plugins_loaded_by(selected, split_modules)
        # The option's entries as given, not split_modules: the trust filter
        # splits its operator_modules itself (plugin_module_trust.
        # drop_untrusted_off_host_plugins, through split_plugin_modules), and
        # the engine passes it the same unsplit list (core/execution_engine.py),
        # so a comma-joined ASH_PLUGIN_MODULES names each of its modules here
        # as it does there.
        selected = drop_untrusted_off_host_plugins(
            ash_config, selected, ash_plugin_modules
        )

        # Before any plugin is built, as the scan engine and ash report check: a
        # configuration with an unknown or refused option of a plugin the listing
        # builds is refused, exit 3 (below), and the refusal names no value or
        # key read from the environment. Checked for the plugins selected above,
        # which are the ones built: the whole registry would refuse the listing
        # for a section of a plugin no scan of this configuration selects, and
        # would read the registry outside the scan's filter.
        refuse_unknown_plugin_options(ash_config, selected)

        def _registered(plugin_type: str, declared: List) -> List:
            registered = list(selected[plugin_type])
            order = {cls: index for index, cls in enumerate(declared)}
            return sorted(
                registered,
                key=lambda cls: (order.get(cls, len(order)), registered.index(cls)),
            )

        # Create tables for each plugin type
        plugin_types = {
            title: _registered(plugin_type, loaded_plugins.get(title, []))
            for plugin_type, title in _PLUGIN_TYPES
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
        # parity test exercises this exact call. The inventory describes the
        # classes it is given, one entry each in the order given
        # (core/scanner_inventory._describe_scanners keeps the provider's order
        # on both of its paths), so each row's entry is the one at its class's
        # position; the two-scanner test in test_plugin_list_agrees_with_a_scan
        # pins that pairing. A lookup by a name derived from the class name
        # missed every scanner whose config name differs from it (the inventory
        # keys its entries by the config name), and those rows read Version and
        # Reachable Unknown with the probe's answer in hand; keying by the
        # entry's name would miss them again on the inventory's placeholder
        # path, which names a scanner it could not describe after its class.
        # An inventory of another length is not the one asked for: every row
        # then reads Unknown, with the cause said once below.
        scanner_inventory_by_class: dict = {}
        if show_versions:
            from automated_security_helper.core.scanner_inventory import (
                list_scanner_inventory,
            )

            scanner_classes = list(plugin_types["scanners"])
            try:
                inventory = list_scanner_inventory(
                    scanner_classes_provider=lambda: scanner_classes
                )
                if len(inventory) != len(scanner_classes):
                    raise ValueError(
                        f"{len(inventory)} entries for {len(scanner_classes)} scanners"
                    )
                scanner_inventory_by_class = dict(zip(scanner_classes, inventory))
            except Exception as exc:
                # Every scanner row then reads Unknown: said once, where the
                # operator reads, not at debug, so an Unknown column has a
                # cause beside it.
                logger.warning(
                    "Could not build the scanner inventory, so every scanner's "
                    f"Version and Reachable read Unknown: {error_text(exc)}"
                )
                for scanner_class in scanner_classes:
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

        # Every listed plugin is built below from its section, as a scan builds
        # it, so the row shows the config the plugin's own model reads.
        # Built inside checking_only() and deferred_tool_version_probes(), as the
        # scan phase and the inventory build them: outside them a uv-based
        # scanner's construction-time version probe resolves, and can download,
        # its tool, and a listing installs nothing.
        with checking_only(), deferred_tool_version_probes():
            _print_tables(
                console,
                plugin_types,
                plugin_context,
                ash_config,
                show_versions,
                include_plugin_config,
                scanner_inventory_by_class,
                _version_label,
                _reachable_label,
            )
    except PluginModuleNamespaceError as e:
        # The namespace refusal keeps its own advice: "install what the
        # module needs" points an operator who named a standard-library
        # module or a namespace package at dependencies that are not the
        # problem. report, merge and dependencies keep this arm apart too.
        secho(
            shown_on_one_line(
                "Invalid configuration: "
                + e.shown_with(
                    "Nothing was listed. Rename the package or name the "
                    "packages inside it, or remove the entry from the config "
                    "file, --config-overrides or --ash-plugin-modules."
                )
            ),
            err=True,
            fg=typer.colors.RED if color else None,
        )
        raise typer.Exit(3)
    except PluginModuleError as e:
        # In the listing's own closing words: the default closing speaks of a
        # scan this command does not make and of option spellings it does not
        # take. The fix clause follows the loss's stage (plugin_module_fix).
        # On one line: a masked label is fixed text, but a literal entry's
        # name is the config file's own and can hold a newline.
        secho(
            shown_on_one_line(
                "Invalid configuration: "
                + e.shown_with(
                    f"Nothing was listed. {plugin_module_fix(e)}, rename "
                    "the entry, or remove it from the config file, "
                    "--config-overrides or --ash-plugin-modules."
                )
            ),
            err=True,
            fg=typer.colors.RED if color else None,
        )
        raise typer.Exit(3)
    except ASHConfigValidationError as e:
        # Exit 3, the code every ASH command uses for an unusable configuration:
        # listing the plugins of the default config instead would describe a
        # configuration other than the one named or found. The refusal names
        # the file, whose path is the caller's text, so each of its lines is
        # shown on one line; which lines there are is
        # parser_text.refusal_own_lines' one rule, as the scan's refusal uses.
        # error_text, not str(e): the text is described with the error's own
        # redaction pass, as the per-plugin error row describes its error.
        from automated_security_helper.utils.parser_text import refusal_own_lines

        for line in refusal_own_lines(e, f"Invalid configuration: {error_text(e)}"):
            secho(
                shown_on_one_line(line),
                err=True,
                fg=typer.colors.RED if color else None,
            )
        raise typer.Exit(3)
    except Exception as e:
        secho(
            f"Error: {error_text(e)}",
            err=True,
        )
        raise typer.Exit(1)


def _print_tables(
    console,
    plugin_types: dict,
    plugin_context: PluginContext,
    ash_config,
    show_versions: bool,
    include_plugin_config: bool,
    scanner_inventory_by_class: dict,
    _version_label,
    _reachable_label,
) -> None:
    """Print one table per plugin type, a row per plugin, as list_plugins lays them out."""
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

                # Build the plugin from its section, as a scan builds it
                try:
                    kind = plugin_type.rstrip("s")  # Remove 's' from end
                    if kind == "reporter":
                        # The section a scan builds the reporter from: for a
                        # reporter that sends findings off the host, the
                        # operator's when the scanned repository's file wrote
                        # this one (config/operator_only_options.reporter_section),
                        # as the report phase and ash report read it.
                        plugin_config = reporter_section(ash_config, plugin_class)
                    else:
                        plugin_config = plugin_context.config.get_plugin_config(
                            plugin_type=kind,
                            plugin_name=plugin_config_key(plugin_class),
                        )
                    # An off-host reporter runs only when its section says
                    # enabled: true, whatever its own default and whatever
                    # else the section wrote there
                    # (base/reporter_plugin.off_host_reporter_refused); the
                    # report phase builds a refused one turned off, so the
                    # listing shows it turned off.
                    refused = kind == "reporter" and off_host_reporter_refused(
                        plugin_class, plugin_config
                    )
                    if refused and isinstance(plugin_config, dict):
                        plugin_config = {**plugin_config, "enabled": False}

                    # The plugin's own config model reads the section, so a
                    # key the section leaves out takes the model's default:
                    # an opt-in plugin (enabled False by default) whose
                    # section sets options only is listed as a scan runs it,
                    # off. Read as a plain dict, a section without the key
                    # defaulted the column to True, and a section without
                    # "name" named the class, not the plugin.
                    plugin_instance = plugin_class(
                        context=plugin_context,
                        config=plugin_config,
                    )
                    # The values masked in the row: the config's environment
                    # values and the plugin's own redaction values too: an
                    # option default it read straight from the environment
                    # (bedrock-summary's model id) is in its dump and in
                    # none of the config's recorded values.
                    hidden = list(ash_config._environment_values)
                    hidden.extend(guarded_values(plugin_instance) or ())
                    try:
                        plugin_name = plugin_instance.config.name
                        plugin_config = plugin_instance.config
                        if hasattr(plugin_config, "model_dump"):
                            plugin_config = plugin_config.model_dump()
                    except AttributeError:
                        plugin_name = plugin_class_name

                    # Resolve the real enabled state from the dict the model
                    # was dumped to (or an object attr, defensively), falling
                    # back to True only when the flag is genuinely absent.
                    if isinstance(plugin_config, dict):
                        enabled_value = plugin_config.get("enabled", True)
                    else:
                        enabled_value = getattr(plugin_config, "enabled", True)
                    if refused:
                        enabled_value = False

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
                    # Enabled may be a bool; Rich requires str entries. A str
                    # entry is markup, and the config's values, the tool's
                    # version and the names are not ASH's: each is escaped,
                    # with the values the config read from the environment
                    # masked first -- the config column dumps the typed
                    # options, and the error row's error_text already
                    # masks the same values.
                    table.add_row(
                        *[
                            escape_markup(text_without_values(str(entry), hidden))
                            for entry in row
                        ]
                    )
                except Exception as e:
                    # If we can't instantiate, still show the plugin but note the
                    # error. The row must fill every column of the table, so it is
                    # built from the same column order rather than a fixed 3-arg
                    # call (the pre-existing bug: a 5- or 7-column table given 3
                    # entries raised "Not enough columns" and masked the real error).
                    # error_text, with the config's environment values: a
                    # plugin's own model error quotes its input otherwise.
                    described = error_text(e, ash_config._environment_values)
                    error_row = [
                        f"{plugin_class_name.lower()} (Error: {described})",
                        "Unknown",
                        plugin_class_name,
                        plugin_module,
                    ]
                    if show_version_cols:
                        error_row.append(_version_label(inventory_entry))
                        error_row.append(_reachable_label(inventory_entry))
                    error_row.append("")
                    table.add_row(
                        *[
                            escape_markup(
                                text_without_values(
                                    str(entry), ash_config._environment_values
                                )
                            )
                            for entry in error_row
                        ]
                    )

        console.print(table)


if __name__ == "__main__":
    from automated_security_helper.cli.entrypoint import run_module_app

    run_module_app(plugin_app)
