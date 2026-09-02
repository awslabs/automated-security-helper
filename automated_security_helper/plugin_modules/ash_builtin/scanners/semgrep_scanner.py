"""Module containing the Semgrep security scanner implementation.

The bulk of the logic (arg-building, offline cache, SARIF post-processing)
lives in :mod:`_grep_scanner_base`. This module only customises:

- the binary command (`semgrep`) and uv-tool resolution
- semgrep-specific dependency validation (Windows skip + UV-tool fallback)
- the cache env var and `SEMGREP_RULES` env propagation for subprocess
"""

import logging
import os
import platform
from typing import Annotated, List, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.constants import is_offline_mode
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    GrepScannerBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command


class SemgrepScannerConfigOptions(ScannerOptionsBase):
    config: Annotated[
        str,
        Field(
            description="YAML configuration file, directory of YAML files ending in .yml|.yaml, URL of a configuration file, or Semgrep registry entry name. Defaults to 'p/ci' for consistent results across online and offline modes.",
        ),
    ] = "p/ci"

    exclude: Annotated[
        List[str],
        Field(
            description="Skip any file or directory whose path matches the pattern.",
        ),
    ] = ["*-converted.py", "*_report_result.txt"]

    exclude_rule: Annotated[
        List[str],
        Field(description="Skip any rule with the given id."),
    ] = []

    severity: Annotated[
        List[Literal["INFO", "WARNING", "ERROR"]],
        Field(
            description="Report findings only from rules matching the supplied severity level.",
        ),
    ] = []

    metrics: Annotated[
        Literal["auto", "on", "off"],
        Field(
            description="Configures how usage metrics are sent to the Semgrep server.",
        ),
    ] = "auto"

    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached rules.",
            default_factory=is_offline_mode,
        ),
    ]

    tool_version: Annotated[
        str | None,
        Field(
            description="Specific version constraint for semgrep installation (e.g., '>=1.125.0')"
        ),
    ] = None

    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class SemgrepScannerConfig(ScannerPluginConfigBase):
    name: Literal["semgrep"] = "semgrep"
    # Semgrep does not support Windows at all
    enabled: bool = platform.system().lower() != "windows"
    options: Annotated[
        SemgrepScannerConfigOptions, Field(description="Configure Semgrep scanner")
    ] = SemgrepScannerConfigOptions()


@ash_scanner_plugin
class SemgrepScanner(GrepScannerBase[SemgrepScannerConfig]):
    """SemgrepScanner implements code scanning using Semgrep."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = SemgrepScannerConfig()
        self.command = "semgrep"
        self.use_uv_tool = True  # Enable UV tool execution
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.SAST

        self._setup_uv_tool_install_commands()
        self.tool_version = self._get_uv_tool_version("semgrep")
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    # ---------------------------------------------------------------
    # GrepScannerBase hooks
    # ---------------------------------------------------------------

    def cache_dir_env_var(self) -> str:
        return "SEMGREP_RULES_CACHE_DIR"

    def cache_dir_name(self) -> str:
        return "Semgrep"

    def default_rulesets(self) -> List[str]:
        return ["p/ci"]

    def extra_subprocess_env(self) -> dict | None:
        """Propagate `SEMGREP_RULES` from the cache dir for offline runs."""
        if self.config.options.offline and "SEMGREP_RULES_CACHE_DIR" in os.environ:
            return {"SEMGREP_RULES": f"{os.environ['SEMGREP_RULES_CACHE_DIR']}/*"}
        return None

    # ---------------------------------------------------------------
    # Semgrep-specific UV-tool dependency resolution
    # ---------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        """semgrep 1.125.0+ has improved stability."""
        if self.config and self.config.options.tool_version:
            return self.config.options.tool_version
        return ">=1.125.0,<2.0.0"

    def validate_plugin_dependencies(self) -> bool:
        if platform.system().lower() == "windows":
            self._plugin_log(
                "Semgrep is not supported on Windows and will be skipped",
                level=logging.INFO,
            )
            return False

        if not self._validate_uv_tool_availability():
            # UV missing — defer to consolidated resolver: if the tool is on
            # PATH directly we can still run it.
            if get_uv_tool_command(self.command) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False

        if self.use_uv_tool:
            installation_info = self._get_tool_installation_info()
            if installation_info.get("available"):
                source = installation_info.get("preferred_source", "unknown")
                if source == "uv":
                    self._plugin_log("Semgrep already installed via UV tool")
                elif source == "pre_installed":
                    self._plugin_log(
                        f"Using pre-installed semgrep at {installation_info.get('pre_installed_path')}"
                    )
                self.dependencies_satisfied = True
                return True

            self._plugin_log(
                "Semgrep not found via UV tool, attempting explicit installation..."
            )
            timeout = (
                getattr(self.config.options, "install_timeout", 300)
                if self.config
                else 300
            )
            if self._install_uv_tool(timeout=timeout):
                self._plugin_log("Successfully installed semgrep via UV tool")
                self.dependencies_satisfied = True
                return True
            # Last resort — consolidated resolver handles the
            # "uv missing → direct binary → None" fallback.
            if get_uv_tool_command(self.command) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "Direct executable detection also failed for semgrep",
                level=logging.ERROR,
            )
            return False

        self.dependencies_satisfied = True
        return True
