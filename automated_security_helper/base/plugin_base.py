"""Module containing the PluginBase class."""

from datetime import datetime
import logging
import sys
import os
from pathlib import Path
from typing import Annotated, Dict, List, Literal, Optional, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.enums import PackageManager
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.log import ASH_LOGGER


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
        extra="allow",
        arbitrary_types_allowed=True,
        use_enum_values=True,
    )
    context: PluginContext | None = None
    config: PluginConfigBase | None = None

    output: List[str] = []
    errors: List[str] = []
    results_dir: Path | None = None
    tool_version: str | None = None
    tool_description: str | None = None
    dependencies_satisfied: bool = False
    start_time: datetime | None = None
    end_time: datetime | None = None
    exit_code: int = 0

    # UV tool execution support
    use_uv_tool: bool = False
    command: str | None = None
    uv_tool_install_commands: List[str] = []

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

    def _plugin_log(
        self,
        *msg: str,
        level: int = 15,
        target_type: str | None = "source",
        append_to_stream: Literal["stderr", "stdout", "none"] = "none",
    ):
        """Log a message to the plugin's log file.

        Args:
            *msg: Message to log
            level: Log level
            target_type: Target type (e.g. source, converted)
            append_to_stream: Append to stdout or stderr stream
        """
        tt = None
        if target_type is not None:
            tt = f" @ [magenta]{target_type}[/magenta]"

        ASH_LOGGER._log(
            level,
            f"([yellow]{self.config.name or self.__class__.__name__}[/yellow]{tt})"
            + "\t"
            + "\n".join(msg),
            args=(),
        )
        if level == logging.ERROR or append_to_stream == "stderr":
            self.errors.append(
                f"({self.config.name or self.__class__.__name__}) " + "\n".join(msg)
            )
        elif append_to_stream == "stdout":
            self.output.append(
                f"({self.config.name or self.__class__.__name__}) " + "\n".join(msg)
            )

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

    def _get_uv_tool_version(self, tool_name: str) -> Optional[str]:
        """Get version of a tool managed by UV.

        Args:
            tool_name: Name of the tool to get version for

        Returns:
            Version string if detected, None if version cannot be determined or UV is not available
        """
        if not self.use_uv_tool:
            self._plugin_log(
                f"UV tool execution is disabled for {tool_name}",
                level=logging.DEBUG,
            )
            return None

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            runner = get_uv_tool_runner()

            # Check if UV is available before attempting to get version
            if not runner.is_uv_available():
                self._plugin_log(
                    f"UV is not available for {tool_name} version detection",
                    level=logging.WARNING,
                )
                return None

            version = runner.get_tool_version(tool_name)
            if version:
                self._plugin_log(
                    f"Detected UV tool {tool_name} version: {version}",
                    level=logging.DEBUG,
                )
            else:
                self._plugin_log(
                    f"Could not determine UV tool {tool_name} version",
                    level=logging.WARNING,
                )
            return version

        except UVToolRunnerError as e:
            self._plugin_log(
                f"UV tool runner error getting {tool_name} version: {e}",
                level=logging.WARNING,
            )
            return None
        except ImportError as e:
            self._plugin_log(
                f"UV tool runner module not available for {tool_name}: {e}",
                level=logging.ERROR,
            )
            return None
        except Exception as e:
            self._plugin_log(
                f"Unexpected error getting UV tool {tool_name} version: {e}",
                level=logging.WARNING,
            )
            return None

    def _run_subprocess(
        self,
        command: List[str],
        results_dir: str | Path | None = None,
        stdout_preference: Literal["return", "write", "both", "none"] = "write",
        stderr_preference: Literal["return", "write", "both", "none"] = "write",
        cwd: Path | str | None = None,
    ) -> Dict[str, str]:
        """Run a subprocess with the given command.

        This method supports both direct command execution and UV tool execution
        based on the use_uv_tool flag. When UV tool execution is enabled, it will
        attempt to run the command via 'uv tool run' and fall back to direct
        execution if UV is not available or fails.

        Args:
            command: Command to run
            results_dir: Directory to write output files to
            stdout_preference: How to handle stdout
            stderr_preference: How to handle stderr
            cwd: Working directory for the command (defaults to context.source_dir)

        Returns:
            Dictionary with stdout and stderr if requested
        """
        from automated_security_helper.utils.subprocess_utils import (
            run_command_with_output_handling,
        )

        try:
            # Use provided cwd or fall back to context.source_dir
            working_dir = cwd if cwd is not None else Path(self.context.source_dir)

            # Attempt UV tool execution if enabled
            if self.use_uv_tool and self.command and len(command) > 0:
                # Check if the first element of the command is our tool command
                if command[0] == self.command:
                    uv_result = self._try_uv_tool_execution(command, working_dir)
                    if uv_result is not None:
                        return uv_result
                    # If UV execution failed, continue with direct execution fallback

            # Run the command using the centralized utility (direct execution or fallback)
            response = run_command_with_output_handling(
                command=command,
                results_dir=results_dir,
                stdout_preference=stdout_preference,
                stderr_preference=stderr_preference,
                cwd=working_dir,
                shell=False,
                class_name=self.__class__.__name__,
                encoding="utf-8",
                errors="replace",
            )

            # Process stdout and stderr for the scanner plugin
            if "stdout" in response and response["stdout"]:
                self.output.extend(response["stdout"].splitlines())

            if "stderr" in response and response["stderr"]:
                self.errors.extend(response["stderr"].splitlines())

            # Set exit code (default to 1 if not available)
            self.exit_code = response.get("returncode", 1)

            return response

        except Exception as e:
            error_msg = f"Error running command {command}: {e}"
            self.errors.append(error_msg)
            self._plugin_log(
                error_msg,
                level=logging.ERROR,
            )
            # show full stack trace in debug
            ASH_LOGGER.debug(
                f"({self.config.name}) Full error details: {e}", exc_info=True
            )
            self.exit_code = 1
            return {"error": str(e)}

    def _try_uv_tool_execution(
        self, command: List[str], working_dir: Path
    ) -> Optional[Dict[str, str]]:
        """Attempt to execute command using UV tool run.

        Args:
            command: Command to execute
            working_dir: Working directory for the command

        Returns:
            Dictionary with command results if successful, None if UV execution should fall back
        """
        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            uv_runner = get_uv_tool_runner()

            # Check UV availability
            if not uv_runner.is_uv_available():
                self._plugin_log(
                    f"UV is not available, falling back to direct execution for {self.command}",
                    level=logging.WARNING,
                )
                return None

            # Extract tool arguments (everything after the tool command)
            tool_args = command[1:] if len(command) > 1 else []

            self._plugin_log(
                f"Executing {self.command} via UV tool run with args: {tool_args}",
                level=logging.DEBUG,
            )

            # Get package extras and version constraint for UV tool execution
            package_extras = self._get_tool_package_extras()
            version_constraint = self._get_tool_version_constraint()

            # Use UV tool runner to execute the command
            result = uv_runner.run_tool(
                tool_name=self.command,
                args=tool_args,
                cwd=working_dir,
                capture_output=True,
                text=True,
                check=False,
                package_extras=package_extras,
                version_constraint=version_constraint,
            )

            # Convert subprocess result to expected format
            response = {
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "returncode": result.returncode,
            }

            # Process stdout and stderr for the scanner plugin
            if response["stdout"]:
                self.output.extend(response["stdout"].splitlines())

            if response["stderr"]:
                self.errors.extend(response["stderr"].splitlines())

            # Set exit code
            self.exit_code = response["returncode"]

            self._plugin_log(
                f"UV tool execution completed for {self.command} with exit code {response['returncode']}",
                level=logging.DEBUG,
            )

            return response

        except UVToolRunnerError as e:
            self._plugin_log(
                f"UV tool runner error for {self.command}: {e}. Falling back to direct execution.",
                level=logging.WARNING,
            )
            return None
        except ImportError as e:
            self._plugin_log(
                f"UV tool runner module not available: {e}. Falling back to direct execution.",
                level=logging.WARNING,
            )
            return None
        except Exception as e:
            self._plugin_log(
                f"Unexpected error during UV tool execution for {self.command}: {e}. Falling back to direct execution.",
                level=logging.WARNING,
            )
            ASH_LOGGER.debug(f"UV tool execution error details: {e}", exc_info=True)
            return None

    def _validate_uv_tool_availability(self) -> bool:
        """Validate that UV tool execution is available when required.

        Returns:
            True if UV tool is available or not required, False if required but unavailable
        """
        if not self.use_uv_tool:
            return True  # UV tool not required, validation passes

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            runner = get_uv_tool_runner()
            is_available = runner.is_uv_available()

            if not is_available:
                self._plugin_log(
                    f"UV tool execution is required but UV is not available for {self.command}",
                    level=logging.WARNING,
                )
                return False

            self._plugin_log(
                f"UV tool execution validated for {self.command}",
                level=logging.DEBUG,
            )
            return True

        except UVToolRunnerError as e:
            self._plugin_log(
                f"UV tool runner error during validation: {e}",
                level=logging.WARNING,
            )
            return False
        except ImportError as e:
            self._plugin_log(
                f"UV tool runner module not available during validation: {e}",
                level=logging.ERROR,
            )
            return False
        except Exception as e:
            self._plugin_log(
                f"Unexpected error during UV tool validation: {e}",
                level=logging.WARNING,
            )
            return False

    def _setup_uv_tool_install_commands(self) -> None:
        """Set up UV tool install commands with version constraints and offline mode support.

        This method should be called during scanner initialization to prepare
        the installation commands based on the scanner's configuration.
        """
        if not self.use_uv_tool or not self.command:
            return

        version_constraint = self._get_tool_version_constraint()
        package_extras = self._get_tool_package_extras()

        # Build tool specification with extras if provided
        if package_extras:
            extras_str = ",".join(package_extras)
            base_spec = f"{self.command}[{extras_str}]"
        else:
            base_spec = self.command

        tool_spec = (
            f"{base_spec}{version_constraint}" if version_constraint else base_spec
        )

        # Build install command with offline mode support
        install_cmd_parts = ["uv", "tool", "install"]

        # Add offline flag if in offline mode
        if self._is_offline_mode():
            install_cmd_parts.append("--offline")

        install_cmd_parts.append(tool_spec)

        # Store as both string and list formats for compatibility
        install_cmd_str = " ".join(install_cmd_parts)
        self.uv_tool_install_commands = [install_cmd_str]

        self._plugin_log(
            f"Set up UV tool install command: {install_cmd_str}",
            f"Offline mode: {self._is_offline_mode()}",
            level=logging.DEBUG,
        )

    def _is_offline_mode(self) -> bool:
        """Check if ASH is running in offline mode.

        Returns:
            True if offline mode is enabled, False otherwise
        """
        return str(os.environ.get("ASH_OFFLINE", "NO")).upper() in ["YES", "TRUE", "1"]

    def _install_uv_tool(
        self, timeout: int = 300, retry_config: Optional[Dict] = None
    ) -> bool:
        """Execute UV tool installation commands with comprehensive logging and retry logic.

        Args:
            timeout: Timeout in seconds for installation (default: 300)
            retry_config: Optional retry configuration dict with keys:
                - max_retries: Maximum number of retry attempts (default: 3)
                - base_delay: Base delay for exponential backoff (default: 1.0)
                - max_delay: Maximum delay between retries (default: 60.0)

        Returns:
            True if installation succeeded, False otherwise
        """
        import time
        from datetime import datetime, timezone

        installation_start_time = time.time()
        installation_start_datetime = datetime.now(timezone.utc)

        # Log installation initiation with structured information
        self._plugin_log(
            f"[INSTALLATION_START] Initiating UV tool installation for '{self.command}'",
            f"Installation parameters: timeout={timeout}s, retry_config={retry_config}",
            f"Start time: {installation_start_datetime.isoformat()}",
            level=15,
        )

        if not self.use_uv_tool or not self.command:
            self._plugin_log(
                f"[INSTALLATION_SKIP] UV tool installation not applicable for scanner '{self.__class__.__name__}'",
                f"Reason: use_uv_tool={self.use_uv_tool}, command={self.command}",
                level=logging.DEBUG,
            )
            return False

        # Check for offline mode
        if self._is_offline_mode():
            self._plugin_log(
                "[INSTALLATION_SKIP] Offline mode detected (ASH_OFFLINE=true)",
                f"Skipping UV tool installation for '{self.command}' and relying on pre-installed tools",
                "Fallback strategy: Will attempt to use pre-installed version if available",
                level=15,
            )
            return False

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRetryConfig,
                UVToolRunnerError,
            )

            runner = get_uv_tool_runner()

            # Check UV availability first with detailed logging
            uv_check_start = time.time()
            uv_available = runner.is_uv_available()
            uv_check_time = time.time() - uv_check_start

            if not uv_available:
                self._plugin_log(
                    "[INSTALLATION_FAILED] UV is not available for tool installation",
                    f"UV availability check took {uv_check_time:.3f}s",
                    "Fallback strategy: Scanner will attempt direct tool execution",
                    level=logging.WARNING,
                )
                return False

            self._plugin_log(
                f"[INSTALLATION_PROGRESS] UV availability confirmed in {uv_check_time:.3f}s",
                level=logging.DEBUG,
            )

            # Log cache information for optimization insights
            cache_info = runner.get_cache_info()
            if cache_info.get("cache_available"):
                self._plugin_log(
                    "[INSTALLATION_CACHE] UV cache is available and functional",
                    f"Cache details: {cache_info.get('details', 'No details available')}",
                    level=logging.DEBUG,
                )
            else:
                self._plugin_log(
                    "[INSTALLATION_CACHE] UV cache not available or has issues",
                    f"Cache error: {cache_info.get('error', 'Unknown')}",
                    level=logging.DEBUG,
                )

            # Set up retry configuration with logging
            if retry_config:
                config = UVToolRetryConfig(
                    max_retries=retry_config.get("max_retries", 3),
                    base_delay=retry_config.get("base_delay", 1.0),
                    max_delay=retry_config.get("max_delay", 60.0),
                    exponential_base=retry_config.get("exponential_base", 2.0),
                    jitter=retry_config.get("jitter", True),
                    network_check_timeout=retry_config.get(
                        "network_check_timeout", 5.0
                    ),
                )
                self._plugin_log(
                    "[INSTALLATION_CONFIG] Using custom retry configuration",
                    f"max_retries={config.max_retries}, base_delay={config.base_delay}s, max_delay={config.max_delay}s",
                    level=logging.DEBUG,
                )
            else:
                config = None
                self._plugin_log(
                    "[INSTALLATION_CONFIG] Using default retry configuration",
                    level=logging.DEBUG,
                )

            # Get version constraint, package extras, and additional dependencies for installation
            version_constraint = self._get_tool_version_constraint()
            package_extras = self._get_tool_package_extras()
            with_dependencies = self._get_tool_with_dependencies()

            # Log installation attempt details
            if package_extras:
                extras_str = ",".join(package_extras)
                base_spec = f"{self.command}[{extras_str}]"
            else:
                base_spec = self.command

            tool_spec = (
                f"{base_spec}{version_constraint}" if version_constraint else base_spec
            )
            self._plugin_log(
                "[INSTALLATION_ATTEMPT] Starting installation of UV tool",
                f"Tool specification: {tool_spec}",
                f"Version constraint: {version_constraint or 'latest'}",
                f"Package extras: {package_extras or 'none'}",
                f"Timeout: {timeout}s",
                level=15,
            )

            # Check if tool is already installed before attempting installation
            pre_install_check_start = time.time()
            already_installed = runner.is_tool_installed(self.command)
            pre_install_check_time = time.time() - pre_install_check_start

            if already_installed:
                # Validate cached tool functionality
                validation_result = runner.validate_cached_tool(self.command)

                if validation_result["is_functional"]:
                    self._plugin_log(
                        f"[INSTALLATION_SKIP] Tool '{self.command}' is already installed and functional",
                        f"Installed version: {validation_result['version'] or 'unknown'}",
                        f"Pre-installation check took {pre_install_check_time:.3f}s",
                        "Skipping installation and using cached version",
                        level=15,
                    )
                    return True
                else:
                    self._plugin_log(
                        f"[INSTALLATION_WARNING] Tool '{self.command}' is installed but not functional",
                        f"Validation error: {validation_result.get('error', 'unknown')}",
                        "Proceeding with reinstallation",
                        level=logging.WARNING,
                    )
                    # Continue with installation to fix the broken cached tool

            self._plugin_log(
                "[INSTALLATION_PROGRESS] Tool not currently installed, proceeding with installation",
                f"Pre-installation check took {pre_install_check_time:.3f}s",
                level=logging.DEBUG,
            )

            # Attempt installation with retry logic and progress monitoring
            install_start_time = time.time()

            # Log progress indicator for long installations
            if timeout > 60:  # For installations expected to take more than 1 minute
                self._plugin_log(
                    f"[INSTALLATION_PROGRESS] Starting installation (timeout: {timeout}s)",
                    "This may take several minutes depending on network speed and tool size",
                    level=15,
                )

            success = runner.install_tool_with_version(
                tool_name=self.command,
                version_constraint=version_constraint,
                timeout=timeout,
                retry_config=config,
                package_extras=package_extras,
                with_dependencies=with_dependencies,
            )

            install_duration = time.time() - install_start_time

            # Log progress completion
            if install_duration > 30:  # Log if installation took more than 30 seconds
                self._plugin_log(
                    f"[INSTALLATION_PROGRESS] Installation attempt completed in {install_duration:.1f}s",
                    level=15,
                )

            installation_time = time.time() - installation_start_time

            if success:
                # Get installed version for confirmation
                post_install_version = runner.get_installed_tool_version(self.command)

                self._plugin_log(
                    f"[INSTALLATION_SUCCESS] Successfully installed UV tool '{self.command}'",
                    f"Installed version: {post_install_version or 'unknown'}",
                    f"Total installation time: {installation_time:.3f}s",
                    f"Installation completed at: {datetime.now(timezone.utc).isoformat()}",
                    level=15,
                )
                return True
            else:
                self._plugin_log(
                    f"[INSTALLATION_FAILED] Failed to install UV tool '{self.command}' after all retry attempts",
                    f"Total installation time: {installation_time:.3f}s",
                    "Fallback strategy: Scanner will attempt direct tool execution or validation",
                    level=logging.WARNING,
                )
                return False

        except UVToolRunnerError as e:
            installation_time = time.time() - installation_start_time
            self._plugin_log(
                "[INSTALLATION_ERROR] UV tool runner error during installation",
                f"Tool: {self.command}",
                f"Error: {e}",
                "Error type: UVToolRunnerError",
                f"Installation time before error: {installation_time:.3f}s",
                "Fallback strategy: Scanner will attempt alternative validation methods",
                level=logging.WARNING,
            )
            return False
        except ImportError as e:
            installation_time = time.time() - installation_start_time
            self._plugin_log(
                "[INSTALLATION_ERROR] UV tool runner module not available",
                f"Tool: {self.command}",
                f"Error: {e}",
                "Error type: ImportError",
                f"Installation time before error: {installation_time:.3f}s",
                "Resolution: Ensure UV tool runner dependencies are properly installed",
                level=logging.ERROR,
            )
            return False
        except Exception as e:
            installation_time = time.time() - installation_start_time
            self._plugin_log(
                "[INSTALLATION_ERROR] Unexpected error during UV tool installation",
                f"Tool: {self.command}",
                f"Error: {e}",
                f"Error type: {type(e).__name__}",
                f"Installation time before error: {installation_time:.3f}s",
                "Fallback strategy: Scanner will attempt alternative validation methods",
                level=logging.WARNING,
            )
            ASH_LOGGER.debug(
                f"UV tool installation error details for {self.command}: {e}",
                exc_info=True,
            )
            return False

    def _is_uv_tool_installed(self) -> bool:
        """Check if the UV tool is already installed.

        Returns:
            True if tool is installed, False otherwise
        """
        if not self.use_uv_tool or not self.command:
            return False

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            runner = get_uv_tool_runner()

            if not runner.is_uv_available():
                return False

            # Check if tool is in the list of installed tools
            try:
                installed_tools = runner.list_available_tools()
                is_installed = self.command in installed_tools

                self._plugin_log(
                    f"UV tool {self.command} installation status: {'installed' if is_installed else 'not installed'}",
                    level=logging.DEBUG,
                )

                return is_installed

            except UVToolRunnerError:
                # If we can't list tools, try to get version as fallback
                version = runner.get_tool_version(self.command)
                is_installed = version is not None

                self._plugin_log(
                    f"UV tool {self.command} installation status (via version check): {'installed' if is_installed else 'not installed'}",
                    level=logging.DEBUG,
                )

                return is_installed

        except (UVToolRunnerError, ImportError) as e:
            self._plugin_log(
                f"Error checking UV tool installation status: {e}",
                level=logging.WARNING,
            )
            return False
        except Exception as e:
            self._plugin_log(
                f"Unexpected error checking UV tool installation: {e}",
                level=logging.WARNING,
            )
            return False

    def _get_tool_installation_info(self) -> Dict[str, Any]:
        """Get comprehensive installation information for the scanner's tool.

        Returns:
            Dictionary containing installation information including UV and pre-installed status
        """
        if not self.command:
            return {
                "tool_name": None,
                "is_uv_installed": False,
                "is_pre_installed": False,
                "uv_version": None,
                "pre_installed_version": None,
                "pre_installed_path": None,
                "preferred_source": "none",
                "available": False,
            }

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            runner = get_uv_tool_runner()
            info = runner.get_tool_installation_info(self.command)
            info["tool_name"] = self.command

            self._plugin_log(
                f"Tool installation info for {self.command}: "
                f"UV installed: {info['is_uv_installed']}, "
                f"Pre-installed: {info['is_pre_installed']}, "
                f"Preferred: {info['preferred_source']}, "
                f"Available: {info['available']}",
                level=logging.DEBUG,
            )

            return info

        except Exception as e:
            self._plugin_log(
                f"Error getting tool installation info: {e}",
                level=logging.WARNING,
            )
            return {
                "tool_name": self.command,
                "is_uv_installed": False,
                "is_pre_installed": False,
                "uv_version": None,
                "pre_installed_version": None,
                "pre_installed_path": None,
                "preferred_source": "none",
                "available": False,
                "error": str(e),
            }

    def _should_install_tool(self, prefer_cached: bool = True) -> bool:
        """Determine if the tool should be installed via UV.

        Args:
            prefer_cached: Whether to prefer cached/pre-installed tools over installation

        Returns:
            True if tool should be installed via UV, False if existing installation should be used
        """
        if not self.use_uv_tool or not self.command:
            return False

        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
            )

            runner = get_uv_tool_runner()
            should_install = runner.should_install_tool(self.command, prefer_cached)

            self._plugin_log(
                f"Should install {self.command} via UV: {should_install} (prefer_cached: {prefer_cached})",
                level=logging.DEBUG,
            )

            return should_install

        except Exception as e:
            self._plugin_log(
                f"Error determining if tool should be installed: {e}",
                level=logging.WARNING,
            )
            return False

    def _validate_tool_availability_with_pre_installed(self) -> Dict[str, Any]:
        """Validate tool availability including pre-installed tools.

        Returns:
            Dictionary containing validation results and tool information
        """
        validation_result = {
            "available": False,
            "validation_method": "none",
            "installation_info": {},
            "errors": [],
            "warnings": [],
        }

        if not self.command:
            validation_result["errors"].append("No command specified for scanner")
            return validation_result

        # Get comprehensive tool installation information
        installation_info = self._get_tool_installation_info()
        validation_result["installation_info"] = installation_info

        # If tool is available from any source, validation passes
        if installation_info["available"]:
            validation_result["available"] = True
            validation_result["validation_method"] = installation_info[
                "preferred_source"
            ]

            if installation_info["preferred_source"] == "uv":
                self._plugin_log(
                    f"Tool {self.command} validated via UV tool (version: {installation_info.get('uv_version', 'unknown')})",
                    level=15,
                )
            elif installation_info["preferred_source"] == "pre_installed":
                self._plugin_log(
                    f"Tool {self.command} validated via pre-installed executable "
                    f"(version: {installation_info.get('pre_installed_version', 'unknown')}, "
                    f"path: {installation_info.get('pre_installed_path', 'unknown')})",
                    level=15,
                )
                validation_result["warnings"].append(
                    f"Using pre-installed {self.command} instead of UV-managed version. "
                    f"Consider installing via UV for better dependency isolation."
                )

            return validation_result

        # Tool is not available, check if we should try to install it
        if self.use_uv_tool and self._should_install_tool(prefer_cached=True):
            self._plugin_log(
                f"Tool {self.command} not available, attempting UV installation",
                level=15,
            )

            if self._install_uv_tool():
                # Re-check availability after installation
                updated_info = self._get_tool_installation_info()
                validation_result["installation_info"] = updated_info

                if updated_info["available"]:
                    validation_result["available"] = True
                    validation_result["validation_method"] = "uv_installed"
                    self._plugin_log(
                        f"Tool {self.command} successfully installed and validated via UV",
                        level=15,
                    )
                else:
                    validation_result["errors"].append(
                        f"Tool {self.command} installation appeared to succeed but tool is still not available"
                    )
            else:
                validation_result["errors"].append(
                    f"Failed to install tool {self.command} via UV"
                )
        else:
            validation_result["errors"].append(
                f"Tool {self.command} is not available and cannot be installed"
            )

        return validation_result

    def _get_tool_version_constraint(self) -> Optional[str]:
        """Get version constraint for tool installation.

        This method should be implemented by each scanner to provide
        version constraints specific to that tool.

        Returns:
            Version constraint string (e.g., ">=1.7.0", "==3.2.0") or None for latest
        """
        pass

    def _get_tool_package_extras(self) -> Optional[List[str]]:
        """Get package extras for tool installation.

        This method should be implemented by each scanner to provide
        package extras specific to that tool (e.g., ["sarif", "toml"]).

        Returns:
            List of package extras or None if no extras are needed
        """
        return None

    def _get_tool_with_dependencies(self) -> Optional[List[str]]:
        """Get additional dependencies to install with the tool using --with flag.

        This method should be implemented by each plugin to provide
        additional dependencies that should be installed alongside the main tool.

        Returns:
            List of additional dependencies or None if no additional dependencies are needed
        """
        return None

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
                elif dep.package_manager == PackageManager.UV:
                    commands.append(
                        [
                            "uv",
                            "tool",
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

        # Add UV tool installation commands if available
        if self.use_uv_tool and self.uv_tool_install_commands:
            for install_cmd in self.uv_tool_install_commands:
                # Convert string command to list of arguments
                if isinstance(install_cmd, str):
                    commands.append(install_cmd.split())
                else:
                    commands.append(install_cmd)

        # Add custom installation commands
        if (
            platform in self.custom_install_commands
            and arch in self.custom_install_commands[platform]
        ):
            for cmd in self.custom_install_commands[platform][arch]:
                commands.append(cmd.args)

        return commands
