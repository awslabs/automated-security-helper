#!/usr/bin/env python3
"""Tool installer for ASH plugins."""

import logging
from pathlib import Path
import platform
import sys
from typing import List

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.utils.log import ASH_LOGGER


def get_platform() -> str:
    """Get the current platform name."""
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "darwin"
    elif system == "windows":
        return "windows"
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


def run_command(args: List[str], shell: bool = False) -> int:
    """Run a command and return the exit code."""
    from automated_security_helper.utils.subprocess_utils import run_command as run_cmd

    try:
        result = run_cmd(args=args, shell=shell, check=False, log_level=logging.INFO)
        return result.returncode
    except Exception as e:
        ASH_LOGGER.error(f"Error running command {' '.join(args)}: {str(e)}")
        return 1


def install_dependencies() -> int:
    """Install dependencies for all plugins."""
    platform_name = get_platform()
    arch = get_architecture()

    ASH_LOGGER.info(
        f"Installing dependencies for platform: {platform_name}, architecture: {arch}"
    )

    # Get all plugin types
    plugin_types = ["converter", "scanner", "reporter"]

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
                        ),
                    )
                )
                plugin_name = getattr(
                    plugin_instance.context.config, "name", plugin_class.__name__
                )

                ASH_LOGGER.info(
                    f"Installing dependencies for {plugin_type} plugin: {plugin_name}"
                )

                # Get installation commands
                commands = plugin_instance.get_installation_commands(
                    platform_name, arch
                )

                # Run each command
                for cmd in commands:
                    cmd_exit_code = run_command(cmd)
                    if cmd_exit_code != 0:
                        exit_code = max(exit_code, cmd_exit_code)

            except Exception as e:
                ASH_LOGGER.error(
                    f"Error installing dependencies for plugin {plugin_class.__name__}: {str(e)}"
                )
                exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(install_dependencies())
