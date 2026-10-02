# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CLI command for installing dependencies for ASH plugins."""

import logging
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, List, Optional

import typer

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form.
from rich import print  # noqa: A004
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import (
    ASH_BIN_PATH,
    ASH_CONFIG_FILE_NAMES,
    ASH_WORK_DIR_NAME,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import load_plugins
from automated_security_helper.utils.log import get_logger
from automated_security_helper.utils.subprocess_utils import (
    clear_find_executable_cache,
    find_executable,
)

dependencies_app = typer.Typer(
    name="dependencies",
    help="Install dependencies for ASH plugins",
    pretty_exceptions_enable=True,
)

console = Console()

# Exit codes. Distinct values so a caller can tell "you asked for a tool that does
# not exist" from "the install ran and something failed".
EXIT_OK = 0
EXIT_INSTALL_FAILED = 1
EXIT_BAD_SELECTION = 2


@dataclass
class PluginInstallOutcome:
    """What actually happened for one plugin, as counts rather than impressions.

    The reason this type exists at all: the previous implementation tracked a
    single `exit_code` and printed "All dependencies installed successfully!"
    whenever it stayed 0 -- which it did when every plugin returned an empty
    command list. Three of ASH's scanners were in exactly that state, so the
    installer's happiest output was also its report for having installed nothing.
    """

    name: str
    plugin_type: str
    command: Optional[str] = None
    commands_attempted: int = 0
    commands_succeeded: int = 0
    commands_failed: int = 0
    commands_skipped_empty: int = 0
    errors: List[str] = field(default_factory=list)
    executable: Optional[str] = None

    @property
    def declared_no_commands(self) -> bool:
        """No usable install command was declared for this platform/arch.

        Excludes plugins that raised while producing their commands. Those have an
        unknown install path rather than no install path, and reporting a crash as
        "no install path on this platform" is the wrong diagnosis in the one
        function whose whole purpose is to report accurately.
        """
        return self.commands_attempted == 0 and not self.errors

    @property
    def needs_external_tool(self) -> bool:
        """Whether this plugin runs an external executable at all.

        Python-only converters and reporters do not, so a sweep that demanded an
        executable for every plugin would report failures for plugins that were
        never going to have one.
        """
        return bool(self.command)

    @property
    def status(self) -> str:
        if self.errors or self.commands_failed:
            return "FAILED"
        if self.commands_succeeded:
            return "INSTALLED" if self.executable else "INSTALLED (not on PATH)"
        if not self.needs_external_tool:
            return "PYTHON-ONLY"
        if self.executable:
            return "ALREADY PRESENT"
        return "NO INSTALL PATH"


def get_platform() -> str:
    """Get the current platform name."""
    system = platform.system().lower()
    if system in ["linux", "darwin", "windows"]:
        return system
    else:
        return "unknown"


def get_architecture() -> str:
    """Get the current architecture."""
    arch = platform.machine().lower()
    if arch in ("x86_64", "amd64"):
        return "amd64"
    elif arch in ("aarch64", "arm64"):
        return "arm64"
    else:
        return "unknown"


def run_command(args: List[str], shell: bool = False):
    """Run a command and return the exit code."""
    from automated_security_helper.utils.subprocess_utils import run_command as run_cmd

    try:
        result = run_cmd(args=args, shell=shell, check=False, log_level=logging.INFO)  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
        print(result.stdout)
        print(result.stderr)
        return result.returncode
    except Exception as e:
        print(f"[bold red]Error running command {' '.join(args)}: {str(e)}[/bold red]")
        return 1


@dependencies_app.command(name="install")
def install_dependencies(
    bin_path: Optional[Path] = typer.Option(
        ASH_BIN_PATH,
        "--bin-path",
        "-b",
        help="Path to install binaries to.",
        envvar="ASH_BIN_PATH",
    ),
    plugin_types: List[str] = typer.Option(
        ["converter", "scanner", "reporter"],
        "--plugin-type",
        "-t",
        help="Plugin types to install dependencies for",
    ),
    tools: Annotated[
        List[str],
        typer.Option(
            "--tool",
            "-T",
            help=(
                "Install dependencies for these tools only, by plugin name "
                "(repeatable, e.g. '--tool grype --tool syft'). An unknown name is "
                "an error rather than a no-op."
            ),
        ),
    ] = [],
    config: Annotated[
        str | None,
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
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
) -> int:
    """Install dependencies for ASH plugins.

    This command installs all required dependencies for the specified plugin types.
    By default, it installs dependencies for all plugin types (converter, scanner, reporter).

    Binary tools will be installed to the specified bin path (defaults to ~/.ash/bin).
    """
    # Set the ASH_BIN_PATH environment variable to override the default
    import os

    # Set up logging
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )

    # Use provided bin path or default if bin_path was null
    target_bin_path = bin_path or ASH_BIN_PATH
    # Create target_bin_path directory if it doesn't exist
    target_bin_path.mkdir(parents=True, exist_ok=True)
    os.environ["ASH_BIN_PATH"] = str(target_bin_path)

    console.print(
        Panel(
            f"[bold green]Installing ASH dependencies[/bold green]\n"
            f"[cyan]Target bin path:[/cyan] {target_bin_path}\n"
            f"[cyan]Plugin types:[/cyan] {', '.join(plugin_types)}",
            title="ASH Dependency Installer",
            expand=False,
        )
    )

    print("Getting platform and architecture")
    platform_name = get_platform()
    arch = get_architecture()

    print(
        f"Installing dependencies for platform: {platform_name}, architecture: {arch}"
    )

    source_dir = Path.cwd()
    output_dir = source_dir.joinpath(".ash", "ash_output")
    work_dir = output_dir.joinpath(ASH_WORK_DIR_NAME)
    # config_path is what makes --config/ASH_CONFIG mean anything here. Omitting it
    # made the option accept a path and then quietly ignore it, so
    # `ash dependencies install --config .ash/.ash_community_plugins.yaml` resolved
    # the default config instead and installed dependencies for the wrong set of
    # plugins.
    resolved_config = resolve_config(
        config_path=config,
        source_dir=source_dir,
        config_overrides=config_overrides,
    )

    # Import the plugin modules the config names before enumerating anything.
    #
    # `--config` previously resolved the config's *values* and stopped there. The
    # scanners a config adds through `ash_plugin_modules` were never imported, so
    # their plugin classes never registered, so
    # `ash dependencies install --config .ash/.ash_community_plugins.yaml` installed
    # dependencies for the built-in set and reported success -- and trivy, snyk and
    # ferret had to be installed by hand in CI before the scan.
    #
    # load_plugins is what the scan path already uses for this. Calling it here means
    # a config that adds scanners also adds their dependencies, and `--tool
    # trivy-repo` resolves instead of being rejected as an unknown name.
    load_plugins(
        PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=work_dir,
            config=resolved_config,
        )
    )

    outcomes: List[PluginInstallOutcome] = []
    construction_failures: List[PluginInstallOutcome] = []
    discovered: List[tuple] = []
    for plugin_type in plugin_types:
        plugin_module_input = (
            "converter"
            if plugin_type == "converter"
            else "reporter"
            if plugin_type == "reporter"
            else "scanner"
        )
        for plugin_class in ash_plugin_manager.plugin_modules(plugin_module_input):
            try:
                plugin_instance: PluginBase = plugin_class(
                    context=PluginContext(
                        source_dir=source_dir,
                        output_dir=output_dir,
                        work_dir=work_dir,
                        config=resolved_config,
                    )
                )
                # `name` exists on every plugin config but is not always populated,
                # and getattr's default only fires when the attribute is absent --
                # so a config carrying name=None used to yield None here and sorting
                # the discovered names raised TypeError.
                plugin_name = (
                    getattr(plugin_instance.config, "name", None)
                    or plugin_class.__name__
                )
                discovered.append((plugin_type, plugin_name, plugin_instance))
            except Exception as e:
                # Reported as a warning here and weighed by the verdict later, because
                # whether it is fatal depends on the run: a --tool run answers only for
                # what it was asked about, so an unrelated plugin that will not
                # construct is information rather than this run's failure.
                print(
                    f"[bold yellow]Plugin {plugin_class.__name__} could not be "
                    f"loaded: {str(e)}[/bold yellow]",
                )
                # Held aside rather than added to `outcomes` directly. `outcomes` is
                # what the verdict is computed from, and a plugin that failed to
                # construct is unrelated to a `--tool` request for a different one --
                # so folding it in unconditionally made
                # `ash dependencies install --tool trivy-repo` exit 1 because some
                # other community plugin would not import, and name that other plugin
                # in the failure panel.
                construction_failures.append(
                    PluginInstallOutcome(
                        name=plugin_class.__name__,
                        plugin_type=plugin_type,
                        errors=[str(e)],
                    )
                )

    # --tool selection. Validated against the names actually discovered rather than
    # a hardcoded list, so it cannot drift from the plugin registry. An unknown name
    # is refused: silently installing nothing for `--tool gryp` would be a typo that
    # reports success, which is the class of bug this whole change is about.
    if tools:
        available = sorted({name for _, name, _ in discovered})
        unknown = [t for t in tools if t not in available]
        if unknown:
            # A plugin that failed to construct has no config, so its declared name is
            # unknowable here -- only its class name is. Rather than claim a match that
            # cannot be established, say that some plugins failed to load, so a
            # requested name missing for that reason is not misreported as a typo.
            broken_note = (
                ""
                if not construction_failures
                else (
                    "\n[yellow]Note:[/yellow] "
                    f"{len(construction_failures)} plugin(s) failed to load and are "
                    "absent from that list: "
                    + ", ".join(sorted(o.name for o in construction_failures))
                )
            )
            console.print(
                Panel(
                    f"[bold red]Unknown tool(s): {', '.join(sorted(unknown))}[/bold red]\n"
                    f"[cyan]Available:[/cyan] {', '.join(available)}{broken_note}",
                    title="Nothing installed",
                    expand=False,
                )
            )
            raise typer.Exit(EXIT_BAD_SELECTION)
        selected = [entry for entry in discovered if entry[1] in tools]
    else:
        # Only a run that was not narrowed to specific tools answers for every
        # plugin, so construction failures count against the verdict only here.
        outcomes.extend(construction_failures)
        selected = discovered

    for plugin_type, plugin_name, plugin_instance in selected:
        outcome = PluginInstallOutcome(
            name=plugin_name,
            plugin_type=plugin_type,
            command=getattr(plugin_instance, "command", None),
        )
        outcomes.append(outcome)

        print(f"Installing dependencies for {plugin_type} plugin: {plugin_name}")
        try:
            commands = plugin_instance.get_installation_commands(platform_name, arch)
        except Exception as e:
            print(
                f"[bold red]Error getting installation commands for plugin "
                f"{plugin_name}: {str(e)}[/bold red]"
            )
            outcome.errors.append(str(e))
            continue

        for cmd in commands:
            # An empty argv is not a command. These reached run_command before this
            # change, failed, and pushed the run's exit code to 1 -- which then went
            # nowhere, because the returned code was discarded. Skipping them and
            # counting them separately keeps a declared-but-empty entry from
            # masquerading as an attempt.
            if not cmd:
                print(
                    f"[yellow]Skipping an empty install command declared by "
                    f"{plugin_name}[/yellow]"
                )
                outcome.commands_skipped_empty += 1
                continue

            # Fix for opengrep download command
            if (
                len(cmd) > 2
                and cmd[0] == sys.executable
                and cmd[1] == "-c"
                and "opengrep" in cmd[2]
            ):
                # Fix the Python command by properly importing Path
                cmd = [sys.executable, "-c", "from pathlib import Path; " + cmd[2]]

            print(f"Running command: {' '.join(cmd)}")
            outcome.commands_attempted += 1
            cmd_exit_code = run_command(cmd)
            if cmd_exit_code != 0:
                print(f"Command failed with exit code: {cmd_exit_code}")
                outcome.commands_failed += 1
            else:
                print(f"Command succeeded with exit code: {cmd_exit_code}")
                outcome.commands_succeeded += 1

    # Post-install sweep. find_executable memoizes negative results, so a lookup
    # made before the install would answer for the world as it was and report a tool
    # ASH just installed as absent.
    clear_find_executable_cache()
    for outcome in outcomes:
        if outcome.needs_external_tool:
            outcome.executable = find_executable(outcome.command)

    return _report_and_exit(outcomes, requested_tools=tools)


def _report_and_exit(
    outcomes: List[PluginInstallOutcome], requested_tools: List[str]
) -> int:
    """Print the tally and derive the verdict from it.

    The verdict is computed from counts, never assumed. Three things fail a run:

    1. Any install command exited non-zero, or a plugin raised.
    2. Nothing was attempted **and** a needed tool is still absent. A run in which
       every command list was empty installed nothing, and reporting that as
       success is what let three scanners stay absent from ASH's own CI while the
       installer said it had finished. The second half of the condition matters:
       attempting nothing because everything is already present is a no-op, and
       failing it would turn `--tool npm-audit` on a machine with node into a false
       alarm.
    3. A tool named explicitly with --tool is not on PATH afterwards. Asking for a
       specific tool and getting a clean exit without it is the same failure in
       miniature. Restricted to plugins that actually run an external binary, since
       a reporter has no executable to find.

    Tools with no install path on this platform are reported by name and do not
    fail the run on their own when they are already present. That is a real
    constraint rather than a malfunction -- npm-audit needs a Node runtime ASH does
    not install, cfn-nag needs RubyGems, and grype and trivy publish no
    windows/arm64 build -- and it is named in the output rather than left for the
    reader to infer from silence.
    """
    table = Table(title="Dependency installation results")
    table.add_column("Plugin")
    table.add_column("Type")
    table.add_column("Tool")
    table.add_column("Cmds", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Status")
    table.add_column("Resolved to")

    for outcome in sorted(outcomes, key=lambda o: (o.plugin_type, o.name)):
        # Python-only plugins are the bulk of the list and say nothing useful here.
        if outcome.status == "PYTHON-ONLY" and not outcome.commands_attempted:
            continue
        table.add_row(
            outcome.name,
            outcome.plugin_type,
            outcome.command or "-",
            str(outcome.commands_attempted),
            str(outcome.commands_failed),
            outcome.status,
            outcome.executable or "-",
        )
    console.print(table)

    commands_attempted = sum(o.commands_attempted for o in outcomes)
    commands_failed = sum(o.commands_failed for o in outcomes)
    plugins_with_errors = [o.name for o in outcomes if o.errors]
    verified = sorted(
        o.name for o in outcomes if o.needs_external_tool and o.executable
    )
    # Named whether or not the tool happens to be present. "npm is on PATH" and
    # "ASH cannot install npm" are different facts, and a reader planning a CI image
    # needs the second one even when the first is currently true.
    unprovisionable = sorted(
        o.name for o in outcomes if o.needs_external_tool and o.declared_no_commands
    )
    missing_after_install = sorted(
        o.name
        for o in outcomes
        if o.needs_external_tool and not o.executable and o.commands_attempted
    )

    # An external tool that is needed, has no install path here, and is not present.
    # This is what makes "nothing was installed" a failure rather than a no-op: the
    # run installed nothing *and* something it needs is still missing.
    still_missing = sorted(
        o.name
        for o in outcomes
        if o.needs_external_tool and not o.executable and o.declared_no_commands
    )

    reasons: List[str] = []
    if commands_failed:
        reasons.append(f"{commands_failed} install command(s) failed")
    if plugins_with_errors:
        reasons.append(f"plugin error(s): {', '.join(sorted(plugins_with_errors))}")
    if commands_attempted == 0 and still_missing:
        # Deliberately conditioned on something actually being absent. A run that
        # attempts nothing because everything it needs is already present is a no-op,
        # not a failure -- `--tool npm-audit` on a machine with node is the case, and
        # failing it would be a false alarm. But a run that attempts nothing while a
        # needed tool is missing is exactly the state grype, syft and cfn-nag were in
        # on every CI runner, and that must not read as success.
        reasons.append(
            "no install commands were run and these are still absent: "
            + ", ".join(still_missing)
        )
    unsatisfied_requests = sorted(
        o.name
        for o in outcomes
        # needs_external_tool is required: `executable` is only ever populated for
        # plugins that have a command, so without it every Python-only plugin named
        # with --tool (any reporter, or the archive converter) failed the run for
        # lacking a binary it was never going to have.
        if requested_tools
        and o.name in requested_tools
        and o.needs_external_tool
        and not o.executable
    )
    if unsatisfied_requests:
        reasons.append(
            f"requested tool(s) still not on PATH: {', '.join(unsatisfied_requests)}"
        )

    verified_names = f" -- {', '.join(verified)}" if verified else ""
    summary = [
        f"[cyan]Commands run:[/cyan] {commands_attempted} ({commands_failed} failed)",
        f"[cyan]Tools verified on PATH:[/cyan] {len(verified)}{verified_names}",
    ]
    if unprovisionable:
        summary.append(
            f"[yellow]No install path on this platform:[/yellow] "
            f"{', '.join(unprovisionable)}"
        )
    if missing_after_install:
        summary.append(
            f"[yellow]Install ran but tool not found on PATH:[/yellow] "
            f"{', '.join(missing_after_install)}"
        )

    if reasons:
        console.print(
            Panel(
                "\n".join(summary)
                + "\n\n[bold red]"
                + "; ".join(reasons)
                + "[/bold red]",
                title="Installation Incomplete",
                expand=False,
            )
        )
        raise typer.Exit(EXIT_INSTALL_FAILED)

    console.print(
        Panel(
            "\n".join(summary),
            title="Installation Complete",
            expand=False,
        )
    )
    return EXIT_OK
