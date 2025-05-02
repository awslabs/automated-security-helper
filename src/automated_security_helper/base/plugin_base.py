"""Module containing the PluginBase class."""

from datetime import datetime
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Dict, List

from pydantic import BaseModel, ConfigDict, Field, model_validator

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.log import ASH_LOGGER


class PackageManager(str, Enum):
    APT = "apt"
    PIP = "pip"
    NPM = "npm"
    BREW = "brew"
    YUM = "yum"
    CHOCO = "choco"
    CUSTOM = "custom"
    URL = "url"  # For direct URL downloads


class PluginDependency(BaseModel):
    name: str
    version: str = "latest"
    package_manager: PackageManager = PackageManager.APT


class CustomCommand(BaseModel):
    args: List[str]
    shell: bool = False  # Set to True only when shell expansion is absolutely necessary


class PluginBase(BaseModel):
    """Base plugin class with common functionality for all plugin types."""

    model_config = ConfigDict(
        extra="allow", arbitrary_types_allowed=True, use_enum_values=True
    )
    context: PluginContext | None = None

    output: List[str] = []
    errors: List[str] = []
    results_dir: Path | None = None
    tool_version: str | None = None
    tool_description: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    exit_code: int = 0

    # Installation-related properties
    dependencies: Annotated[
        Dict[str, Dict[str, List[PluginDependency]]],
        Field(
            description="Dependencies by platform and architecture",
        ),
    ] = {}

    custom_install_commands: Annotated[
        Dict[str, Dict[str, List[CustomCommand]]],
        Field(
            description="Custom installation commands by platform and architecture",
        ),
    ] = {}

    def is_python_only(self) -> bool:
        """
        Determine if this plugin only depends on Python and has no external dependencies.

        A plugin is considered Python-only if:
        1. It has no dependencies defined in self.dependencies, or
        2. It only has pip dependencies (Python packages)
        3. It has no custom installation commands

        Returns:
            bool: True if the plugin only depends on Python, False otherwise
        """
        # Check if there are any custom installation commands
        if len(self.custom_install_commands) > 0:
            ASH_LOGGER.debug(
                f"Plugin {self.__class__.__name__} has custom install commands, this is not Python-only"
            )
            return False

        # Check if there are any dependencies
        if len(self.dependencies) == 0:
            ASH_LOGGER.debug(
                f"Plugin {self.__class__.__name__} has no dependencies and no custom install commands, this is Python-only"
            )
            return True

        # Check if all dependencies are Python packages (pip)
        for platform in self.dependencies:
            for arch in self.dependencies[platform]:
                for dep in self.dependencies[platform][arch]:
                    if dep.package_manager != PackageManager.PIP:
                        ASH_LOGGER.debug(
                            f"Plugin {self.__class__.__name__} has non-Python dependencies with {dep.package_manager}, this is not Python-only"
                        )
                        return False

        # If we got here, all dependencies are Python packages
        return True

    @model_validator(mode="after")
    def setup_paths(self) -> "PluginBase":
        """Set up default paths and initialize plugin configuration."""
        # Use context if provided, otherwise fall back to instance attributes
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        ASH_LOGGER.trace(f"Using provided context for {self.__class__.__name__}")
        return self

    def get_installation_commands(self, platform: str, arch: str) -> List[List[str]]:
        """Generate installation commands for the specified platform/architecture as arrays of arguments"""
        commands = []

        # Process standard dependencies
        if platform in self.dependencies and arch in self.dependencies[platform]:
            for dep in self.dependencies[platform][arch]:
                if dep.package_manager == PackageManager.APT:
                    commands.append(
                        [
                            "apt-get",
                            "install",
                            "-y",
                            f"{dep.name}{f'={dep.version}' if dep.version != 'latest' else ''}",
                        ]
                    )
                elif dep.package_manager == PackageManager.PIP:
                    commands.append(
                        [
                            sys.executable,
                            "-m",
                            "pip",
                            "install",
                            f"{dep.name}{f'=={dep.version}' if dep.version != 'latest' else ''}",
                        ]
                    )
                elif dep.package_manager == PackageManager.NPM:
                    commands.append(
                        [
                            "npm",
                            "install",
                            "-g",
                            f"{dep.name}{f'@{dep.version}' if dep.version != 'latest' else ''}",
                        ]
                    )
                elif dep.package_manager == PackageManager.BREW:
                    commands.append(
                        [
                            "brew",
                            "install",
                            f"{dep.name}{f'@{dep.version}' if dep.version != 'latest' else ''}",
                        ]
                    )
                elif dep.package_manager == PackageManager.YUM:
                    commands.append(
                        [
                            "yum",
                            "install",
                            "-y",
                            f"{dep.name}{f'-{dep.version}' if dep.version != 'latest' else ''}",
                        ]
                    )
                elif dep.package_manager == PackageManager.CHOCO:
                    commands.append(
                        [
                            "choco",
                            "install",
                            "-y",
                            f"{dep.name}{f' --version={dep.version}' if dep.version != 'latest' else ''}",
                        ]
                    )
                elif dep.package_manager == PackageManager.URL:
                    # For URL downloads, we need to use the download_utils module
                    # This is handled by custom commands, so we don't need to do anything here
                    pass

        # Add custom installation commands
        if (
            platform in self.custom_install_commands
            and arch in self.custom_install_commands[platform]
        ):
            for cmd in self.custom_install_commands[platform][arch]:
                commands.append(cmd.args)

        return commands
