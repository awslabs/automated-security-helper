# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the JupyterConverter implementation."""

import subprocess
from pathlib import Path
from typing import Annotated, List, Literal, Optional

from pydantic import Field

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)

from automated_security_helper.base.options import (
    ConverterOptionsBase,
)
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.sarif_utils import path_matches_pattern


class JupyterConverterConfigOptions(ConverterOptionsBase):
    tool_version: Annotated[
        str | None,
        Field(
            description="Version constraint for nbconvert tool installation (e.g., '>=7.16.0'). If not specified, the latest version will be installed."
        ),
    ] = ">=7.16.0,<8.0.0"
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation (default: 300)"),
    ] = 300


class JupyterConverterConfig(ConverterPluginConfigBase):
    """Jupyter Notebook (.ipynb) to Python converter configuration."""

    name: Literal["jupyter"] = "jupyter"
    enabled: bool = True
    options: Annotated[
        JupyterConverterConfigOptions,
        Field(description="Configure Jupyter Notebook converter"),
    ] = JupyterConverterConfigOptions()


@ash_converter_plugin
class JupyterConverter(ConverterPluginBase[JupyterConverterConfig]):
    """Converter implementation for Jupyter notebooks security scanning."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = JupyterConverterConfig()

        self.command = "nbconvert"
        self.use_uv_tool = True  # Enable UV tool execution

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # Update tool version detection to work with explicit installation
        self.tool_version = self._get_uv_tool_version("nbconvert")

        return super().model_post_init(context)

    def _get_tool_version_constraint(self) -> Optional[str]:
        """Get version constraint for nbconvert installation.

        Returns:
            Version constraint string for nbconvert (e.g., ">=7.16.0") or None for latest
        """
        return self.config.options.tool_version

    def _get_tool_package_extras(self) -> Optional[List[str]]:
        """Get package extras for nbconvert installation.

        Returns:
            List of package extras needed for nbconvert. Should be nothing needed by
            default for script export.
        """
        return []

    def _get_tool_with_dependencies(self) -> Optional[List[str]]:
        """Get additional dependencies to install with nbconvert.

        Returns:
            List of additional dependencies needed for nbconvert (jupyter for CLI access)
        """
        return ["jupyter"]

    def validate_plugin_dependencies(self) -> bool:
        """Enhanced validation with explicit tool installation.

        This method implements the enhanced validation workflow that:
        1. Checks if UV tool is available when required
        2. Attempts explicit tool installation if needed
        3. Falls back to existing validation methods
        4. Provides comprehensive logging for troubleshooting

        Returns:
            True if converter is ready to use, False otherwise
        """
        if self.use_uv_tool:
            # Attempt explicit tool installation
            installation_success = self._install_uv_tool(
                timeout=self.config.options.install_timeout
            )

            if installation_success:
                ASH_LOGGER.debug(f"UV tool installation successful for {self.command}")
                # Update tool version after successful installation
                self.tool_version = self._get_uv_tool_version(self.command)
                return True
            else:
                ASH_LOGGER.warning(
                    f"UV tool installation failed for {self.command}, attempting fallback validation"
                )

        # Fallback to checking if jupyter command is available via direct execution
        try:
            result = subprocess.run(
                ["jupyter", "nbconvert", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                ASH_LOGGER.debug("Found jupyter nbconvert via direct execution")
                return True
        except (
            subprocess.TimeoutExpired,
            FileNotFoundError,
            subprocess.SubprocessError,
        ):
            pass

        ASH_LOGGER.warning(
            f"Converter {self.command} is not available. "
            f"Jupyter notebook conversion will be skipped."
        )
        return False

    def _execute_nbconvert_via_uv(self, cmd: List[str], timeout: int = 60) -> bool:
        """Execute jupyter nbconvert command via UV tool runner.

        Args:
            cmd: Command list to execute (should start with 'jupyter')
            timeout: Timeout in seconds

        Returns:
            True if execution succeeded, False otherwise
        """
        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            uv_runner = get_uv_tool_runner()

            # Check UV availability
            if not uv_runner.is_uv_available():
                ASH_LOGGER.debug("UV is not available for nbconvert execution")
                return False

            # Extract jupyter arguments (skip 'jupyter')
            if len(cmd) < 1 or cmd[0] != "jupyter":
                ASH_LOGGER.error(f"Invalid jupyter command format: {cmd}")
                return False

            jupyter_args = cmd[1:]  # Skip 'jupyter'

            ASH_LOGGER.debug(f"Executing jupyter via UV with args: {jupyter_args}")

            # Use UV tool runner to execute jupyter (nbconvert tool provides jupyter command)
            result = uv_runner.run_tool(
                tool_name="jupyter",
                args=jupyter_args,
                cwd=self.context.source_dir,
                capture_output=True,
                text=True,
                check=False,
                package_extras=self._get_tool_package_extras(),
                version_constraint=self._get_tool_version_constraint(),
                timeout=timeout,
            )

            if result.returncode == 0:
                ASH_LOGGER.debug("jupyter execution via UV succeeded")
                return True
            else:
                ASH_LOGGER.warning(
                    f"jupyter execution via UV failed with exit code {result.returncode}"
                )
                if result.stderr:
                    ASH_LOGGER.debug(f"jupyter stderr: {result.stderr}")
                return False

        except UVToolRunnerError as e:
            ASH_LOGGER.warning(f"UV tool runner error for jupyter: {e}")
            return False
        except ImportError as e:
            ASH_LOGGER.warning(f"UV tool runner module not available: {e}")
            return False
        except Exception as e:
            ASH_LOGGER.warning(f"Unexpected error during UV jupyter execution: {e}")
            return False

    def convert(self) -> List[Path]:
        """Converts Jupyter notebooks (.ipynb files) in the source_dir to Python files using CLI.

        Returns:
            List[Path]: List of converted Python files
        """
        ASH_LOGGER.debug(
            f"Searching for .ipynb files in search_path within the ASH scan set: {self.context.source_dir}"
        )
        # Find all notebook files to scan from the scan set
        ipynb_files = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
        )
        ipynb_files = [f.strip() for f in ipynb_files if f.strip().endswith(".ipynb")]

        ASH_LOGGER.debug(f"Found {len(ipynb_files)} .ipynb files in scan set.")
        results: List[Path] = []

        # Add warning if no Jupyter notebook files found
        if not ipynb_files:
            ASH_LOGGER.info(
                f"No Jupyter notebook (.ipynb) files found in {self.context.source_dir}"
            )
            return results

        self.results_dir.mkdir(parents=True, exist_ok=True)

        for ipynb_file in ipynb_files:
            try:
                skip_item = False
                # Skip directories
                if Path(ipynb_file).is_dir():
                    ASH_LOGGER.debug(f"Skipping directory: {ipynb_file}")
                    skip_item = True
                else:
                    for ignore_path in self.context.config.global_settings.ignore_paths:
                        rel_path = (
                            Path(ipynb_file)
                            .relative_to(self.context.source_dir)
                            .as_posix()
                        )
                        if path_matches_pattern(rel_path, ignore_path.path):
                            ASH_LOGGER.debug(
                                f"Skipping conversion of ignored path: {ipynb_file} due to global ignore_path '{ignore_path.path}' with reason '{ignore_path.reason}'"
                            )
                            skip_item = True
                            break
                if skip_item:
                    continue

                ASH_LOGGER.debug(f"Converting {ipynb_file} to .py")
                short_ipynb_file = get_shortest_name(ipynb_file)
                normalized_ipynb_file = get_normalized_filename(short_ipynb_file)
                # Ensure the target path has a .py extension (remove .ipynb and add -converted.py)
                filename_base = normalized_ipynb_file.replace(".ipynb", "")
                target_path = self.results_dir.joinpath(f"{filename_base}-converted.py")
                target_path.parent.mkdir(parents=True, exist_ok=True)

                ASH_LOGGER.verbose(
                    f"Converting {ipynb_file} to target_path: {Path(target_path).as_posix()}"
                )

                # Use CLI command similar to the original shell script
                cmd = [
                    "jupyter",
                    "nbconvert",
                    "--log-level",
                    "WARN",
                    "--to",
                    "script",
                    str(ipynb_file),
                    "--output",
                    str(
                        target_path.with_suffix("")
                    ),  # nbconvert adds .py automatically
                ]

                # Execute using UV tool runner if available, otherwise direct execution
                if self.use_uv_tool:
                    success = self._execute_nbconvert_via_uv(cmd, timeout=60)
                    if not success:
                        ASH_LOGGER.warning(
                            f"UV tool execution failed for {ipynb_file}, trying direct execution"
                        )
                        result = subprocess.run(
                            cmd, capture_output=True, text=True, timeout=60
                        )
                        if result.returncode != 0:
                            raise subprocess.CalledProcessError(
                                result.returncode, cmd, result.stdout, result.stderr
                            )
                else:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=60
                    )
                    if result.returncode != 0:
                        raise subprocess.CalledProcessError(
                            result.returncode, cmd, result.stdout, result.stderr
                        )

                # Check if the converted file was created
                if target_path.exists():
                    results.append(target_path)
                    ASH_LOGGER.debug(
                        f"Successfully converted {ipynb_file} to {target_path}"
                    )
                else:
                    ASH_LOGGER.warning(
                        f"Conversion completed but output file not found: {target_path}"
                    )

            except subprocess.TimeoutExpired:
                ASH_LOGGER.error(f"Timeout converting {ipynb_file}")
            except subprocess.CalledProcessError as e:
                ASH_LOGGER.error(f"Error converting {ipynb_file}: {e}")
                if e.stderr:
                    ASH_LOGGER.debug(f"nbconvert stderr: {e.stderr}")
            except Exception as e:
                ASH_LOGGER.error(f"Unexpected error converting {ipynb_file}: {e}")
                import traceback

                ASH_LOGGER.debug(
                    f"Jupyter conversion error traceback: {traceback.format_exc()}"
                )

        return results
