"""Module containing the Opengrep security scanner implementation.

The bulk of the logic (arg-building, offline cache, SARIF post-processing)
lives in :mod:`_grep_scanner_base`. This module only customises:

- the binary command (`opengrep`) and its custom URL-based install commands
- version-gated `--metrics` (deprecated in opengrep 1.7.0+)
- patterns mode (`--pattern`) which switches the scanner to JSON output
"""

from __future__ import annotations

import platform
import struct
import subprocess  # nosec B404 — required for opengrep --version detection
from pathlib import Path
from typing import Annotated, List, Literal, Optional, Tuple

from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.constants import is_offline_mode
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.core import ToolArgs, ToolExtraArg
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    GrepScannerBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.download_utils import (
    create_url_download_command,
    get_opengrep_url,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable


class OpengrepScannerConfigOptions(ScannerOptionsBase):
    config: Annotated[
        str,
        Field(
            description="YAML configuration file, directory of YAML files ending in .yml|.yaml, URL of a configuration file, or Opengrep registry entry name. Defaults to 'p/ci' for consistent results across online and offline modes.",
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
            description="Configures how usage metrics are sent to the OpenGrep server. Deprecated in Opengrep v1.7.0+. This configuration is ignored if the installed version is >= 1.7.0.",
        ),
    ] = "auto"

    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached rules.",
            default_factory=is_offline_mode,
        ),
    ]

    patterns: Annotated[
        List[str],
        Field(description="Patterns to search for with OpenGrep."),
    ] = []

    version: Annotated[
        str,
        Field(description="Version of OpenGrep to use."),
    ] = "v1.15.1"


class OpengrepScannerConfig(ScannerPluginConfigBase):
    name: Literal["opengrep"] = "opengrep"
    enabled: bool = platform.system().lower() != "windows"
    options: Annotated[
        OpengrepScannerConfigOptions, Field(description="Configure Opengrep scanner")
    ] = OpengrepScannerConfigOptions()


@ash_scanner_plugin
class OpengrepScanner(GrepScannerBase[OpengrepScannerConfig]):
    """OpengrepScanner implements code scanning using Opengrep."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = OpengrepScannerConfig()
        self.command = "opengrep"
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "OpengrepScanner":
        """Set up custom installation commands for opengrep."""
        version = self.config.options.version
        # TODO: detect manylinux vs musllinux
        linux_type = "manylinux"

        if "linux" not in self.custom_install_commands:
            self.custom_install_commands["linux"] = {}
        self.custom_install_commands["linux"]["amd64"] = [
            create_url_download_command(
                url=get_opengrep_url(
                    "linux", "amd64", version=version, linux_type=linux_type
                ),
                rename_to="opengrep",
            )
        ]
        self.custom_install_commands["linux"]["arm64"] = [
            create_url_download_command(
                url=get_opengrep_url(
                    "linux", "arm64", version=version, linux_type=linux_type
                ),
                rename_to="opengrep",
            )
        ]

        if "darwin" not in self.custom_install_commands:
            self.custom_install_commands["darwin"] = {}
        self.custom_install_commands["darwin"]["amd64"] = [
            create_url_download_command(
                url=get_opengrep_url("darwin", "amd64", version=version),
                rename_to="opengrep",
            )
        ]
        self.custom_install_commands["darwin"]["arm64"] = [
            create_url_download_command(
                url=get_opengrep_url("darwin", "arm64", version=version),
                rename_to="opengrep",
            )
        ]

        if "windows" not in self.custom_install_commands:
            self.custom_install_commands["windows"] = {}
        self.custom_install_commands["windows"]["amd64"] = [
            create_url_download_command(
                url=get_opengrep_url("windows", "amd64", version=version),
                rename_to="opengrep.exe",
            )
        ]
        return self

    # ---------------------------------------------------------------
    # GrepScannerBase hooks
    # ---------------------------------------------------------------

    def cache_dir_env_var(self) -> str:
        return "OPENGREP_RULES_CACHE_DIR"

    def cache_dir_name(self) -> str:
        return "Opengrep"

    def default_rulesets(self) -> List[str]:
        return ["p/ci"]

    def emit_metrics_flag(self) -> bool:
        """`--metrics` was removed in opengrep 1.7.0; only emit on older versions."""
        return self._should_use_metrics_flag()

    # ---------------------------------------------------------------
    # Dependency resolution
    # ---------------------------------------------------------------

    def validate_plugin_dependencies(self) -> bool:
        found = find_executable(self.command)
        ASH_LOGGER.verbose(f"Found opengrep executable at: {found}")
        return found is not None

    def _has_install_commands(self) -> bool:
        system = platform.system().lower()
        arch = "amd64" if struct.calcsize("P") * 8 == 64 else "arm64"
        if system in self.custom_install_commands:
            if arch in self.custom_install_commands[system]:
                return len(self.custom_install_commands[system][arch]) > 0
        return False

    # ---------------------------------------------------------------
    # Version detection (used to gate --metrics)
    # ---------------------------------------------------------------

    def _get_opengrep_version(self) -> tuple[int, int, int] | None:
        try:
            result = subprocess.run(  # nosec B603 — list args, executable from find_executable()
                [self.command, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                version_str = result.stdout.strip().split()[-1].lstrip("v")
                parts = version_str.split(".")
                if len(parts) >= 3:
                    return (int(parts[0]), int(parts[1]), int(parts[2]))
        except FileNotFoundError:
            return None
        except Exception as e:
            ASH_LOGGER.verbose(f"Unable to determine Opengrep version: {e}")
        return None

    def _should_use_metrics_flag(self) -> bool:
        version = self._get_opengrep_version()
        if version is None:
            ASH_LOGGER.verbose(
                "Unable to determine Opengrep version, assuming --metrics is NOT supported (default version >= 1.7.0)"
            )
            return False
        if version >= (1, 7, 0):
            ASH_LOGGER.verbose(
                f"Opengrep version {'.'.join(map(str, version))} detected, skipping --metrics flag"
            )
            return False
        ASH_LOGGER.verbose(
            f"Opengrep version {'.'.join(map(str, version))} detected, using --metrics flag"
        )
        return True

    # ---------------------------------------------------------------
    # Patterns mode — opengrep-only override
    # ---------------------------------------------------------------

    def _process_config_options(self):
        result = super()._process_config_options()

        # Patterns mode: switch to JSON output and replace extra_args with
        # only --json + --pattern entries (matches pre-refactor behaviour).
        if self.config.options.patterns:
            self.args.extra_args = [ToolExtraArg(key="--json", value="")]
            for pattern in self.config.options.patterns:
                self.args.extra_args.append(
                    ToolExtraArg(key="--pattern", value=pattern)
                )

        return result

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths,
    ) -> Tuple[List[str], Path, Optional[dict]]:
        final_args, results_file, env = super()._execute_scan(
            target, target_type, global_ignore_paths
        )
        if self.config.options.patterns:
            results_file = results_file.parent / "opengrep_results.json"
            # Re-resolve final_args so output_arg uses the json path.
            final_args = self._resolve_arguments(target=target, results_file=results_file)
        return final_args, results_file, env
