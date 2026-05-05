"""Mixin providing UV tool management for PluginBase.

All UV-related methods (installation, validation, version detection,
execution) live here.  PluginBase inherits from this mixin so that
every plugin/scanner can call ``self._install_uv_tool()`` etc. without
any change to call sites.

The mixin accesses ``self.command``, ``self.use_uv_tool``,
``self.uv_tool_package_name``, ``self.uv_tool_install_commands``,
``self.context``, ``self.config``, ``self._plugin_log()``,
``self.exit_code``, ``self.output``, and ``self.errors`` -- all of
which are defined on PluginBase.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    pass


class UVToolMixin:
    """UV tool management methods extracted from PluginBase."""

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def _get_uv_tool_version(
        self, tool_name: str, package_name: Optional[str] = None
    ) -> Optional[str]:
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

            if not runner.is_uv_available():
                self._plugin_log(
                    f"UV is not available for {tool_name} version detection",
                    level=logging.WARNING,
                )
                return None

            version = runner.get_tool_version(tool_name, package_name)
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

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _try_uv_tool_execution(
        self,
        command: List[str],
        working_dir: Path,
        results_dir: Optional[Path] = None,
        stdout_preference: str = "write",
        stderr_preference: str = "write",
        env: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, str]]:
        """Attempt to execute command using UV tool run.

        Args:
            command: Command to execute
            working_dir: Working directory for the command
            results_dir: Directory to write output files to
            stdout_preference: How to handle stdout
            stderr_preference: How to handle stderr
            env: Environment variables for the child process. Passed through
                to the underlying tool runner; when ``None`` the child
                inherits the parent env unchanged.

        Returns:
            Dictionary with command results if successful, None if UV execution should fall back
        """
        try:
            from automated_security_helper.utils.uv_tool_runner import (
                get_uv_tool_runner,
                UVToolRunnerError,
            )

            uv_runner = get_uv_tool_runner()

            if not uv_runner.is_uv_available():
                self._plugin_log(
                    f"UV is not available, falling back to direct execution for {self.command}",
                    level=logging.WARNING,
                )
                return None

            tool_args = command[1:] if len(command) > 1 else []

            self._plugin_log(
                f"Executing {self.command} via UV tool run with args: {tool_args}",
                level=logging.DEBUG,
            )

            package_extras = self._get_tool_package_extras()
            version_constraint = self._get_tool_version_constraint()

            result = uv_runner.run_tool(
                tool_name=self.command,
                args=tool_args,
                cwd=working_dir,
                capture_output=True,
                text=True,
                check=False,
                package_extras=package_extras,
                version_constraint=version_constraint,
                results_dir=results_dir,
                stdout_preference=stdout_preference,
                stderr_preference=stderr_preference,
                class_name=self.__class__.__name__,
                env=env,
            )

            response = {
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "returncode": result.returncode,
            }

            self._process_command_response(response)

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

    # ------------------------------------------------------------------
    # Availability / validation
    # ------------------------------------------------------------------

    def _validate_uv_tool_availability(self) -> bool:
        """Validate that UV tool execution is available when required.

        Returns:
            True if UV tool is available or not required, False if required but unavailable
        """
        if not self.use_uv_tool:
            return True

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

        installation_info = self._get_tool_installation_info()
        validation_result["installation_info"] = installation_info

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

        if self.use_uv_tool and self._should_install_tool(prefer_cached=True):
            self._plugin_log(
                f"Tool {self.command} not available, attempting UV installation",
                level=15,
            )

            if self._install_uv_tool():
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

    # ------------------------------------------------------------------
    # Installation setup
    # ------------------------------------------------------------------

    def _setup_uv_tool_install_commands(self) -> None:
        """Set up UV tool install commands with version constraints and offline mode support.

        This method should be called during scanner initialization to prepare
        the installation commands based on the scanner's configuration.
        """
        if not self.use_uv_tool or not self.command:
            return

        version_constraint = self._get_tool_version_constraint()
        package_extras = self._get_tool_package_extras()

        tool_name = (
            self.uv_tool_package_name if self.uv_tool_package_name else self.command
        )

        if package_extras:
            extras_str = ",".join(package_extras)
            base_spec = f"{tool_name}[{extras_str}]"
        else:
            base_spec = tool_name

        tool_spec = (
            f"{base_spec}{version_constraint}" if version_constraint else base_spec
        )

        install_cmd_parts = ["uv", "tool", "install"]
        install_cmd_parts.append(tool_spec)

        install_cmd_str = " ".join(install_cmd_parts)
        self.uv_tool_install_commands = [install_cmd_str]

        self._plugin_log(
            f"Set up UV tool install command: {install_cmd_str}",
            f"Offline mode: {self._is_offline_mode()}",
            level=logging.DEBUG,
        )

    # ------------------------------------------------------------------
    # Offline mode
    # ------------------------------------------------------------------

    def _is_offline_mode(self) -> bool:
        """Check if ASH is running in offline mode.

        Returns:
            True if offline mode is enabled, False otherwise
        """
        from automated_security_helper.core.constants import is_offline_mode

        return is_offline_mode()

    # ------------------------------------------------------------------
    # Installation
    # ------------------------------------------------------------------

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
        installation_start_time = time.time()
        installation_start_datetime = datetime.now(timezone.utc)

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

            version_constraint = self._get_tool_version_constraint()
            package_extras = self._get_tool_package_extras()
            with_dependencies = self._get_tool_with_dependencies()

            tool_name = (
                self.uv_tool_package_name if self.uv_tool_package_name else self.command
            )

            if package_extras:
                extras_str = ",".join(package_extras)
                base_spec = f"{tool_name}[{extras_str}]"
            else:
                base_spec = tool_name

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

            pre_install_check_start = time.time()
            already_installed = runner.is_tool_installed(self.command)
            pre_install_check_time = time.time() - pre_install_check_start

            if already_installed:
                validation_result = runner.validate_cached_tool(
                    self.command, self.uv_tool_package_name
                )

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

            self._plugin_log(
                "[INSTALLATION_PROGRESS] Tool not currently installed, proceeding with installation",
                f"Pre-installation check took {pre_install_check_time:.3f}s",
                level=logging.DEBUG,
            )

            install_start_time = time.time()

            if timeout > 60:
                self._plugin_log(
                    f"[INSTALLATION_PROGRESS] Starting installation (timeout: {timeout}s)",
                    "This may take several minutes depending on network speed and tool size",
                    level=15,
                )

            success = runner.install_tool_with_version(
                tool_name=tool_name,
                version_constraint=version_constraint,
                timeout=timeout,
                retry_config=config,
                package_extras=package_extras,
                with_dependencies=with_dependencies,
            )

            install_duration = time.time() - install_start_time

            if install_duration > 30:
                self._plugin_log(
                    f"[INSTALLATION_PROGRESS] Installation attempt completed in {install_duration:.1f}s",
                    level=15,
                )

            installation_time = time.time() - installation_start_time

            if success:
                from automated_security_helper.utils.subprocess_utils import (
                    clear_find_executable_cache,
                )

                clear_find_executable_cache()

                post_install_version = runner.get_installed_tool_version(
                    self.command, package_extras
                )

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

    # ------------------------------------------------------------------
    # Installation status
    # ------------------------------------------------------------------

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

            try:
                installed_tools = runner.list_available_tools()
                is_installed = self.command in installed_tools

                self._plugin_log(
                    f"UV tool {self.command} installation status: {'installed' if is_installed else 'not installed'}",
                    level=logging.DEBUG,
                )

                return is_installed

            except UVToolRunnerError:
                version = runner.get_tool_version(
                    self.command, self.uv_tool_package_name
                )
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
            info = runner.get_tool_installation_info(
                self.command, self.uv_tool_package_name
            )
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

    # ------------------------------------------------------------------
    # Extension points (meant to be overridden by subclasses)
    # ------------------------------------------------------------------

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
