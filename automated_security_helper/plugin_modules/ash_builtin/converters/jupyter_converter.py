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
    ] = ">=7.0.0"  # More flexible version constraint
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation (default: 600)"),
    ] = 600  # Increased timeout for better reliability
    fallback_to_system: Annotated[
        bool,
        Field(description="Whether to fallback to system-installed jupyter/nbconvert if UV installation fails"),
    ] = True


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
        # Use a more flexible version constraint to avoid conflicts
        return self.config.options.tool_version or ">=6.0.0,<8.0.0"

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
        # Install jupyter-core and ipython for better compatibility
        return ["jupyter-core", "ipython"]

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
        # First, try to detect system-installed nbconvert (which we installed in Dockerfile)
        if self.config.options.fallback_to_system:
            try:
                # Try multiple possible nbconvert commands
                for cmd in ["python3 -m nbconvert", "nbconvert", "jupyter-nbconvert"]:
                    try:
                        if cmd.startswith("python3"):
                            result = subprocess.run(
                                cmd.split() + ["--version"],
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                        else:
                            result = subprocess.run(
                                [cmd, "--version"],
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                        if result.returncode == 0:
                            ASH_LOGGER.debug(f"Found nbconvert via direct execution: {cmd}")
                            self.use_uv_tool = False  # Use direct execution instead
                            self.command = cmd if not cmd.startswith("python3") else "python3 -m nbconvert"
                            self.tool_version = result.stdout.strip()
                            return True
                    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                        continue
            except Exception as e:
                ASH_LOGGER.debug(f"System nbconvert check failed: {e}")

        # If system nbconvert not found, try UV tool approach
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

        ASH_LOGGER.warning(
            f"Converter {self.command} is not available. "
            f"Jupyter notebook conversion will be skipped. "
            f"To fix this, install nbconvert: pip install nbconvert"
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

            # Extract nbconvert arguments
            if len(cmd) < 1 or cmd[0] != "nbconvert":
                ASH_LOGGER.error(f"Invalid nbconvert command format: {cmd}")
                return False

            nbconvert_args = cmd[1:]  # Skip 'nbconvert'

            ASH_LOGGER.debug(f"Executing nbconvert via UV with args: {nbconvert_args}")

            # Use UV tool runner to execute nbconvert directly
            result = uv_runner.run_tool(
                tool_name="nbconvert",
                args=nbconvert_args,
                cwd=self.context.source_dir,
                capture_output=True,
                text=True,
                check=False,
                package_extras=self._get_tool_package_extras(),
                version_constraint=self._get_tool_version_constraint(),
                timeout=timeout,
            )

            if result.returncode == 0:
                ASH_LOGGER.debug("nbconvert execution via UV succeeded")
                return True
            else:
                ASH_LOGGER.warning(
                    f"nbconvert execution via UV failed with exit code {result.returncode}"
                )
                if result.stderr:
                    ASH_LOGGER.debug(f"nbconvert stderr: {result.stderr}")
                return False

        except UVToolRunnerError as e:
            ASH_LOGGER.warning(f"UV tool runner error for nbconvert: {e}")
            # Try to install the tool if it's not available
            if "not found" in str(e).lower() or "not installed" in str(e).lower():
                ASH_LOGGER.info("Attempting to install nbconvert via UV...")
                try:
                    install_success = uv_runner.install_tool_with_version(
                        tool_name="nbconvert",
                        version_constraint=self._get_tool_version_constraint(),
                        timeout=300,
                        package_extras=self._get_tool_package_extras(),
                        with_dependencies=self._get_tool_with_dependencies(),
                    )
                    if install_success:
                        ASH_LOGGER.info("nbconvert installed successfully, retrying execution...")
                        # Retry the execution after successful installation
                        result = uv_runner.run_tool(
                            tool_name="nbconvert",
                            args=nbconvert_args,
                            cwd=self.context.source_dir,
                            capture_output=True,
                            text=True,
                            check=False,
                            package_extras=self._get_tool_package_extras(),
                            version_constraint=self._get_tool_version_constraint(),
                            timeout=timeout,
                        )
                        if result.returncode == 0:
                            ASH_LOGGER.debug("nbconvert execution via UV succeeded after installation")
                            return True
                except Exception as install_e:
                    ASH_LOGGER.warning(f"Failed to install nbconvert via UV: {install_e}")
            return False
        except ImportError as e:
            ASH_LOGGER.warning(f"UV tool runner module not available: {e}")
            return False
        except Exception as e:
            ASH_LOGGER.warning(f"Unexpected error during UV nbconvert execution: {e}")
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

                # Build command based on available nbconvert method
                if self.use_uv_tool:
                    cmd = [
                        "nbconvert",
                        "--log-level",
                        "WARN",
                        "--to",
                        "script",
                        str(ipynb_file),
                        "--output",
                        str(target_path.with_suffix("")),  # nbconvert adds .py automatically
                    ]
                elif self.command and self.command.startswith("python3"):
                    cmd = [
                        "python3",
                        "-m",
                        "nbconvert",
                        "--log-level",
                        "WARN",
                        "--to",
                        "script",
                        str(ipynb_file),
                        "--output",
                        str(target_path.with_suffix("")),  # nbconvert adds .py automatically
                    ]
                else:
                    cmd = [
                        self.command or "nbconvert",
                        "--log-level",
                        "WARN",
                        "--to",
                        "script",
                        str(ipynb_file),
                        "--output",
                        str(target_path.with_suffix("")),  # nbconvert adds .py automatically
                    ]

                # Execute using UV tool runner if available, otherwise direct execution
                success = False
                if self.use_uv_tool:
                    success = self._execute_nbconvert_via_uv(cmd, timeout=60)
                    if not success:
                        ASH_LOGGER.warning(
                            f"UV tool execution failed for {ipynb_file}, trying direct execution"
                        )
                
                # Try direct execution if UV failed or not available
                if not success:
                    try:
                        result = subprocess.run(
                            cmd, capture_output=True, text=True, timeout=60, cwd=self.context.source_dir
                        )
                        if result.returncode != 0:
                            # Try alternative commands if the first one fails
                            for alt_cmd in [["python3", "-m", "nbconvert"], ["jupyter-nbconvert"]]:
                                try:
                                    alt_full_cmd = alt_cmd + cmd[1:]  # Keep the same arguments
                                    result = subprocess.run(
                                        alt_full_cmd, capture_output=True, text=True, timeout=60, cwd=self.context.source_dir
                                    )
                                    if result.returncode == 0:
                                        break
                                except (FileNotFoundError, subprocess.SubprocessError):
                                    continue
                            
                            if result.returncode != 0:
                                raise subprocess.CalledProcessError(
                                    result.returncode, cmd, result.stdout, result.stderr
                                )
                    except FileNotFoundError as e:
                        ASH_LOGGER.error(f"nbconvert command not found: {e}")
                        ASH_LOGGER.error(f"Please install nbconvert: pip install nbconvert")
                        continue

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
