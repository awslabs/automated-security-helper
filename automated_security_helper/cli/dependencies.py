# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CLI command for installing dependencies for ASH plugins."""

import logging
import platform
import sys
from pathlib import Path
from typing import Annotated, List, Optional

import typer
from rich import print
from rich.console import Console
from rich.panel import Panel

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import (
    ASH_BIN_PATH,
    ASH_CONFIG_FILE_NAMES,
    ASH_WORK_DIR_NAME,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.utils.log import get_logger

dependencies_app = typer.Typer(
    name="dependencies",
    help="Install dependencies for ASH plugins",
    pretty_exceptions_enable=True,
)

console = Console()


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

    exit_code = 0
    for plugin_type in plugin_types:
        plugins = ash_plugin_manager.plugin_modules(plugin_type)
        for plugin_class in plugins:
            try:
                # Create an instance to access configuration
                source_dir = Path.cwd()
                output_dir = source_dir.joinpath(".ash", "ash_output")
                work_dir = output_dir.joinpath(ASH_WORK_DIR_NAME)
                plugin_instance: PluginBase = plugin_class(
                    context=PluginContext(
                        source_dir=source_dir,
                        output_dir=output_dir,
                        work_dir=work_dir,
                        config=resolve_config(
                            source_dir=source_dir,
                            config_overrides=config_overrides,
                        ),
                    )
                )
                plugin_name = getattr(
                    plugin_instance.config, "name", plugin_class.__name__
                )

                print(
                    f"Installing dependencies for {plugin_type} plugin: {plugin_name}"
                )

                # Get installation commands
                try:
                    commands = plugin_instance.get_installation_commands(
                        platform_name, arch
                    )

                    # Run each command
                    for cmd in commands:
                        # Fix for opengrep download command
                        if (
                            len(cmd) > 2
                            and cmd[0] == sys.executable
                            and cmd[1] == "-c"
                            and "opengrep" in cmd[2]
                        ):
                            # Fix the Python command by properly importing Path
                            fixed_cmd = [
                                sys.executable,
                                "-c",
                                "from pathlib import Path; " + cmd[2],
                            ]
                            print(f"Running command: {' '.join(fixed_cmd)}")
                            cmd_exit_code = run_command(fixed_cmd)
                        else:
                            print(f"Running command: {' '.join(cmd)}")
                            cmd_exit_code = run_command(cmd)

                        if cmd_exit_code != 0:
                            print(f"Command failed with exit code: {cmd_exit_code}")
                            exit_code = max(exit_code, cmd_exit_code)
                        else:
                            print(f"Command succeeded with exit code: {cmd_exit_code}")

                except Exception as e:
                    print(
                        f"[bold red]Error getting installation commands for plugin {plugin_name}: {str(e)}[/bold red]"
                    )
                    exit_code = 1

            except Exception as e:
                print(
                    f"[bold red]Error installing dependencies for plugin {plugin_class.__name__}: {str(e)}[/bold red]",
                )
                exit_code = 1

    if exit_code == 0:
        console.print(
            Panel(
                "[bold green]All dependencies installed successfully![/bold green]",
                title="Installation Complete",
                expand=False,
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]Some dependencies failed to install (exit code: {exit_code})[/bold red]",
                title="Installation Incomplete",
                expand=False,
            )
        )

    return exit_code
