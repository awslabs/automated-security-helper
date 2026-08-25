"""UV tool runner utility for managing UV-based tool execution and installation."""

import subprocess  # nosec B404 — uv_tool_runner is the subprocess orchestrator for tool execution
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable


class UVToolRunnerError(Exception):
    """Exception raised for UV tool runner errors."""

    pass


@dataclass
class UVToolRetryConfig:
    """Configuration for UV tool operation retry logic."""

    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    network_check_timeout: float = 5.0


class UVToolRunner:
    """UV tool runner for managing UV-based tool execution and installation."""

    def __init__(self, uv_executable: str = "uv"):
        """Initialize UV tool runner."""
        self.uv_executable = uv_executable
        self._uv_available_cache: Optional[bool] = None

    def is_uv_available(self) -> bool:
        """Check if UV is available on the system."""
        if self._uv_available_cache is not None:
            return self._uv_available_cache

        try:
            result = subprocess.run(  # nosec B603 — list args, validated uv executable path
                [self.uv_executable, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                encoding="utf-8",
                errors="replace",
            )
            self._uv_available_cache = result.returncode == 0
        except Exception:
            self._uv_available_cache = False

        return self._uv_available_cache

    def list_available_tools(self) -> List[str]:
        """List all available UV tools."""
        if not self.is_uv_available():
            raise UVToolRunnerError("UV is not available")

        try:
            result = subprocess.run(  # nosec B603 — list args, validated uv executable path
                [self.uv_executable, "tool", "list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
                encoding="utf-8",
                errors="replace",
            )

            tools = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    tool_name = line.strip().split()[0]
                    if tool_name == "-":
                        tool_name = line.strip().split()[1]  # Add sub-commands too
                    tools.append(tool_name)

            return tools

        except subprocess.CalledProcessError as e:
            raise UVToolRunnerError(f"Failed to list UV tools: {e}")

    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a specific tool is installed via UV."""
        try:
            installed_tools = self.list_available_tools()
        except UVToolRunnerError:
            return False
        return tool_name in installed_tools

    def get_tool_version(
        self, tool_name: str, package_name: Optional[str] = None
    ) -> Optional[str]:
        """Get version of a UV tool."""
        if not self.is_uv_available():
            return None

        try:
            command = [self.uv_executable, "tool", "run"]

            # Build command with --from parameter if extras specified
            if package_name:
                # Build the --from specification
                command.extend(
                    [
                        "--from",
                        package_name,
                    ]
                )

            command.extend([tool_name, "--version"])
            result = subprocess.run(  # nosec B603 — list args, validated uv executable path
                command,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                encoding="utf-8",
                errors="replace",
            )

            if result.returncode == 0 and result.stdout.strip():
                version_line = result.stdout.strip().split("\n")[0]
                return version_line.strip()

        except Exception:  # nosec B110 — version check failure is non-critical
            pass

        return None

    def get_installed_tool_version(
        self, tool_name: str, package_name: Optional[str] = None
    ) -> Optional[str]:
        """Get version of an installed UV tool."""
        if not self.is_tool_installed(tool_name):
            return None
        return self.get_tool_version(tool_name, package_name)

    def install_tool_with_version(
        self,
        tool_name: str,
        version_constraint: Optional[str] = None,
        timeout: int = 300,
        retry_config: Optional[UVToolRetryConfig] = None,
        package_extras: Optional[List[str]] = None,
        with_dependencies: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None,
    ) -> bool:
        """Install a UV tool with optional version constraint, extras, and retry logic.

        Args:
            tool_name: Name of the tool to install
            version_constraint: Optional version constraint (e.g., ">=1.7.0,<2.0.0")
            timeout: Timeout in seconds for installation
            retry_config: Optional retry configuration
            package_extras: Optional list of package extras (e.g., ["sarif", "toml"])
            with_dependencies: Optional list of additional dependencies to install with --with flag
            progress_callback: Optional callback function for progress updates

        Returns:
            True if installation succeeded, False otherwise
        """
        import os

        if not self.is_uv_available():
            return False

        # Check if tool is already installed - skip installation if it exists
        if self.is_tool_installed(tool_name):
            # Tool already exists, no need to reinstall
            return True

        # Check if tool executable exists but is broken (e.g., broken symlink)
        # This can happen if UV tool was uninstalled but symlinks remain
        import logging

        from automated_security_helper.utils.subprocess_utils import find_executable

        tool_path = find_executable(tool_name)
        if tool_path and not os.path.exists(tool_path):
            # Broken symlink detected - remove it so UV can recreate
            try:
                os.remove(tool_path)
                logging.debug(f"Removed broken symlink for {tool_name} at {tool_path}")
            except Exception as e:
                logging.warning(f"Failed to remove broken symlink for {tool_name}: {e}")

        # Check for offline mode
        from automated_security_helper.core.constants import is_offline_mode

        if is_offline_mode():
            # In offline mode, skip installation attempts and rely on pre-installed tools
            return False

        # Build tool specification with extras if provided
        if package_extras:
            extras_str = ",".join(package_extras)
            base_spec = f"{tool_name}[{extras_str}]"
        else:
            base_spec = tool_name

        tool_spec = (
            f"{base_spec}{version_constraint}" if version_constraint else base_spec
        )

        # Build command with offline support
        cmd = [self.uv_executable, "tool", "install"]

        # Add offline flag if UV_OFFLINE environment variable is set
        if os.environ.get("UV_OFFLINE") == "1":
            cmd.append("--offline")

        # Add --with dependencies if provided
        if with_dependencies:
            for dep in with_dependencies:
                cmd.extend(["--with", dep])

        cmd.append(tool_spec)

        # Set up progress monitoring for long installations
        progress_thread = None
        if callable(progress_callback) and timeout > 60:

            def progress_monitor():
                start_time = time.time()
                while True:
                    elapsed = time.time() - start_time
                    if elapsed > timeout:
                        break
                    if callable(progress_callback):
                        progress_callback(
                            f"Installation in progress... ({elapsed:.0f}s elapsed)"
                        )
                    time.sleep(10)  # Update every 10 seconds

            progress_thread = threading.Thread(target=progress_monitor, daemon=True)
            progress_thread.start()

        try:
            subprocess.run(  # nosec B603 — list args, validated uv executable path
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
                encoding="utf-8",
                errors="replace",
            )

            # Stop progress monitoring
            if progress_thread:
                progress_thread = None

            return True
        except subprocess.TimeoutExpired as e:
            # Handle timeout specifically
            raise UVToolRunnerError(
                f"Tool installation timed out after {timeout} seconds for {tool_name}. "
                f"Command: {' '.join(cmd)}"
                f"Error: {e}"
            )
        except subprocess.CalledProcessError as e:
            # Handle non-zero exit codes
            error_msg = f"Tool installation failed for {tool_name} with exit code {e.returncode}"
            if e.stderr:
                error_msg += f". Error: {e.stderr.strip()}"
            raise UVToolRunnerError(error_msg)
        except Exception as e:
            # Handle other exceptions
            raise UVToolRunnerError(
                f"Unexpected error during tool installation for {tool_name}: {e}"
            )

    def run_tool(
        self,
        tool_name: str,
        package_name: Optional[str] | None = None,
        args: List[str] | None = None,
        cwd: Optional[Path] = None,
        capture_output: bool = True,
        text: bool = True,
        check: bool = False,
        timeout: Optional[int] = None,
        package_extras: Optional[List[str]] = None,
        version_constraint: Optional[str] = None,
        results_dir: Optional[Path] = None,
        stdout_preference: str = "write",
        stderr_preference: str = "write",
        class_name: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """Run a UV tool with specified arguments and output handling support.

        Args:
            tool_name: Name of the tool to run
            args: Arguments to pass to the tool
            cwd: Working directory for the command
            capture_output: Whether to capture stdout/stderr
            text: Whether to return text output
            check: Whether to raise exception on non-zero exit
            timeout: Timeout in seconds
            package_extras: Optional list of package extras for --from parameter
            version_constraint: Optional version constraint for --from parameter
            results_dir: Directory to write output files to
            stdout_preference: How to handle stdout ("return", "write", "both", "none")
            stderr_preference: How to handle stderr ("return", "write", "both", "none")
            class_name: Optional class name for log file naming
            env: Environment variables for the child process. When supplied,
                offline-mode additions are layered on top; when ``None``,
                the child inherits the parent env.

        Returns:
            CompletedProcess result with enhanced output handling
        """
        from automated_security_helper.utils.subprocess_utils import (
            run_command_with_output_handling,
        )
        import os

        if not self.is_uv_available():
            raise UVToolRunnerError("UV is not available")

        if args is None:
            args = []

        command = [self.uv_executable, "tool", "run"]

        # Set up environment for offline mode if needed. If the caller
        # passed an explicit env, start from it; otherwise start from
        # os.environ when we need to set offline flags.
        from automated_security_helper.core.constants import is_offline_mode

        if is_offline_mode():
            env = dict(env) if env is not None else os.environ.copy()
            env["UV_OFFLINE"] = "1"
            command.append("--offline")

        # Build command with --from parameter if extras or version constraint specified
        if package_extras or version_constraint:
            # Build the --from specification
            if package_extras:
                extras_str = ",".join(package_extras)
                base_spec = f"{tool_name}[{extras_str}]"
            else:
                base_spec = tool_name

            from_spec = (
                f"{base_spec}{version_constraint}" if version_constraint else base_spec
            )

            command.extend(
                [
                    "--from",
                    from_spec,
                ]
            )

        if package_name:
            command.extend(
                [
                    "--from",
                    package_name,
                ]
            )

        command.extend([tool_name, *args])

        # Use the centralized output handling if results_dir is provided
        if results_dir is not None:
            try:
                response = run_command_with_output_handling(
                    command=command,
                    results_dir=results_dir,
                    stdout_preference=stdout_preference,
                    stderr_preference=stderr_preference,
                    cwd=cwd,
                    env=env,
                    shell=False,
                    class_name=class_name or f"UVTool_{tool_name}",
                    encoding="utf-8" if text else None,
                    errors="replace" if text else None,
                )

                # Create a CompletedProcess-like object from the response
                result = subprocess.CompletedProcess(
                    args=command,
                    returncode=response.get("returncode", 0),
                    stdout=response.get("stdout", ""),
                    stderr=response.get("stderr", ""),
                )

                if check and result.returncode != 0:
                    raise subprocess.CalledProcessError(
                        result.returncode, command, result.stdout, result.stderr
                    )

                return result

            except Exception as e:
                if "error" in str(e) and "returncode" in str(e):
                    # This is likely from run_command_with_output_handling
                    raise UVToolRunnerError(f"UV tool run failed for {tool_name}: {e}")
                else:
                    raise UVToolRunnerError(f"UV tool run failed for {tool_name}: {e}")

        # Fallback to original subprocess.run for backward compatibility
        try:
            result = subprocess.run(  # nosec B603 — list args, validated uv executable path
                command,
                cwd=cwd,
                capture_output=capture_output,
                text=text,
                check=check,
                timeout=timeout,
                env=env,
                encoding="utf-8" if text else None,
                errors="replace" if text else None,
            )
            return result
        except subprocess.CalledProcessError as e:
            raise UVToolRunnerError(f"UV tool run failed for {tool_name}: {e}")

    def get_tool_installation_info(
        self, tool_name: str, package_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get comprehensive installation information for a tool."""
        is_uv_installed = (
            self.is_tool_installed(tool_name) if self.is_uv_available() else False
        )
        uv_version = (
            self.get_tool_version(tool_name, package_name) if is_uv_installed else None
        )

        # Simple pre-installed check
        from automated_security_helper.utils.subprocess_utils import (
            find_executable as _find_exec,
        )

        pre_installed_path = _find_exec(tool_name)
        is_pre_installed = pre_installed_path is not None

        if is_uv_installed:
            preferred_source = "uv"
            available = True
        elif is_pre_installed:
            preferred_source = "pre_installed"
            available = True
        else:
            preferred_source = "none"
            available = False

        return {
            "tool_name": tool_name,
            "is_uv_installed": is_uv_installed,
            "is_pre_installed": is_pre_installed,
            "uv_version": uv_version,
            "pre_installed_version": None,
            "pre_installed_path": pre_installed_path,
            "preferred_source": preferred_source,
            "available": available,
        }

    def should_install_tool(self, tool_name: str, prefer_cached: bool = True) -> bool:
        """Determine if a tool should be installed via UV."""
        if not self.is_uv_available():
            return False

        info = self.get_tool_installation_info(tool_name)

        if info["is_uv_installed"]:
            return False

        if prefer_cached and info["is_pre_installed"]:
            return False

        return True

    def get_cache_info(self) -> Dict[str, Any]:
        """Get UV cache information for optimization purposes."""
        try:
            result = subprocess.run(  # nosec B603 — list args, validated uv executable path
                [self.uv_executable, "cache", "dir"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                encoding="utf-8",
                errors="replace",
            )

            if result.returncode == 0:
                # Parse cache info from output
                cache_info = {
                    "cache_available": True,
                    "cache_output": result.stdout.strip(),
                }

                # Try to extract cache size and location if available
                lines = result.stdout.strip().split("\n")
                # The command returns only the cache path
                for line in lines:
                    cache_info["details"] = line.strip()
                    break

                return cache_info
            else:
                return {
                    "cache_available": False,
                    "error": (
                        result.stderr.strip()
                        if result.stderr
                        else "Unknown cache error"
                    ),
                }

        except Exception as e:
            return {"cache_available": False, "error": str(e)}

    def clean_cache(self) -> bool:
        """Clean UV cache to free up space."""
        try:
            subprocess.run(  # nosec B603 — list args, validated uv executable path
                [self.uv_executable, "cache", "clean"],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
                encoding="utf-8",
                errors="replace",
            )
            return True
        except Exception:
            return False

    def validate_cached_tool(
        self, tool_name: str, package_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate that a cached tool is still functional."""
        validation_result = {
            "tool_name": tool_name,
            "is_functional": False,
            "version": None,
            "error": None,
        }

        try:
            # Try to get version to validate functionality
            version = self.get_tool_version(tool_name, package_name)
            if version:
                validation_result["is_functional"] = True
                validation_result["version"] = version
            else:
                validation_result["error"] = "Could not determine tool version"

        except Exception as e:
            validation_result["error"] = str(e)

        return validation_result


# Global instance
_uv_tool_runner: UVToolRunner = UVToolRunner()


def get_uv_tool_runner() -> UVToolRunner:
    """Get the global UV tool runner instance."""
    global _uv_tool_runner
    if _uv_tool_runner is None:
        _uv_tool_runner = UVToolRunner()
    return _uv_tool_runner


def reset_uv_tool_runner() -> None:
    """Reset the global UV tool runner instance (mainly for testing)."""
    global _uv_tool_runner
    _uv_tool_runner = UVToolRunner()


# ---------------------------------------------------------------------------
# Module-level fallback helpers
#
# Small, dependency-free API that scanners can use to resolve how to invoke a
# tool: prefer ``uv tool run <tool>`` when both ``uv`` and the tool are
# reachable, otherwise fall back to the directly installed binary.  Results
# are memoized per process so the version probe runs only once.
# ---------------------------------------------------------------------------


_uv_command_cache: Dict[str, Optional[List[str]]] = {}
_uv_executable_cache: Dict[str, Optional[str]] = {}
_executable_cache: Dict[str, Optional[str]] = {}

# Coarse lock guarding the three module-level cache dicts above. This lock
# is only held across in-memory reads/writes; it is NOT held across the
# subprocess probe. See `_get_or_create_probe_lock` below for the per-key
# lock used to dedupe concurrent probes for the same `(tool, fallback)`
# pair without serializing distinct pairs.
#
# RLock (reentrant) so callers can call `find_uv_or_none` / `find_executable`
# from inside another lock-holding helper without deadlock.
_uv_tool_runner_cache_lock = threading.RLock()

# Per-cache-key probe locks. Lazily created the first time a thread asks
# about a particular `(tool_name, fallback)` key. Stored in a
# `WeakValueDictionary` so the lock is garbage-collected once no thread is
# blocked on it AND no thread holds a strong reference. This means cold-
# cache lookups for two different tools probe in parallel; only threads
# racing on the *same* key serialize. See DA r5 #7.
import weakref as _weakref

_uv_tool_probe_locks: "_weakref.WeakValueDictionary[str, threading.Lock]" = (
    _weakref.WeakValueDictionary()
)

# Timeout (seconds) for the ``uv tool run <tool> --version`` probe. Five
# seconds is plenty for ``--version`` on any reasonable host; the previous
# 30s value could stack to ~150s of phase blockage across five cold-cache
# scanners with no progress reporting (DA r4 #5).
_UV_VERSION_PROBE_TIMEOUT = 5


def _reset_uv_tool_runner_caches() -> None:
    """Reset module-level caches (mainly for testing)."""
    with _uv_tool_runner_cache_lock:
        _uv_command_cache.clear()
        _uv_executable_cache.clear()
        _executable_cache.clear()


def find_uv_or_none() -> Optional[str]:
    """Return the path to the ``uv`` binary, or ``None`` if it is missing."""
    with _uv_tool_runner_cache_lock:
        if "uv" in _uv_executable_cache:
            return _uv_executable_cache["uv"]

        from automated_security_helper.utils.subprocess_utils import (
            find_executable as _find_executable,
        )

        resolved = _find_executable("uv")
        _uv_executable_cache["uv"] = resolved
        return resolved


def find_executable(name: str) -> Optional[str]:
    """Find an executable by direct path, then PATH lookup."""
    with _uv_tool_runner_cache_lock:
        if name in _executable_cache:
            return _executable_cache[name]

        from automated_security_helper.utils.subprocess_utils import (
            find_executable as _find_executable,
        )

        resolved = _find_executable(name)
        _executable_cache[name] = resolved
        return resolved


def get_uv_tool_command(
    tool_name: str,
    *,
    fallback_binary: Optional[str] = None,
) -> Optional[List[str]]:
    """Resolve the command list to invoke ``tool_name``.

    Resolution order:

    1. If ``uv`` exists and ``uv tool run <tool_name> --version`` succeeds,
       return ``["uv", "tool", "run", tool_name]``.
    2. Else if ``fallback_binary`` (default: ``tool_name``) is found on PATH,
       return ``[<fallback_path>]``.
    3. Else return ``None`` (caller marks deps unsatisfied).

    Memoized per process so the version probe runs only once per
    ``(tool_name, fallback_binary)`` pair. Thread-safe: a single shared
    lock guards reads, writes, and the underlying probe so concurrent
    threads racing on the same cache key see exactly one probe and a
    consistent result.
    """
    binary = fallback_binary or tool_name
    cache_key = f"{tool_name}::{binary}"

    # Fast-path: cache hit under the coarse lock.
    with _uv_tool_runner_cache_lock:
        if cache_key in _uv_command_cache:
            return _uv_command_cache[cache_key]
        # Get-or-create the per-key probe lock under the coarse lock so two
        # threads racing here see the same lock object.
        #
        # STRONG-REF CONTRACT (DA r6 #6): the local `probe_lock` variable
        # MUST stay in scope until after the `with probe_lock:` acquire
        # below. The WeakValueDictionary holds the lock by weak reference;
        # without a stack-frame strong reference, GC could collect the
        # lock between the dict-write here and the acquire below, and a
        # concurrent thread on the same cache key would create a NEW
        # lock — defeating the per-key serialization. Do NOT refactor
        # this block to return the lock from a helper without giving the
        # caller a strong ref before the acquire.
        probe_lock = _uv_tool_probe_locks.get(cache_key)
        if probe_lock is None:
            probe_lock = threading.Lock()
            _uv_tool_probe_locks[cache_key] = probe_lock

    # Per-key lock: serialize probes for THIS cache key without blocking
    # probes for other cache keys. The coarse cache lock is NOT held here,
    # so the slow `uv tool run --version` subprocess does not serialize all
    # parallel scanner cold-cache lookups.
    with probe_lock:
        # Re-check under the probe lock — another thread may have populated
        # the cache while we waited.
        with _uv_tool_runner_cache_lock:
            if cache_key in _uv_command_cache:
                return _uv_command_cache[cache_key]

        uv_path = find_uv_or_none()
        command: Optional[List[str]] = None
        if uv_path is not None:
            try:
                probe = subprocess.run(  # nosec B603 — fixed list of trusted strings
                    [uv_path, "tool", "run", tool_name, "--version"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=_UV_VERSION_PROBE_TIMEOUT,
                )
                if probe.returncode == 0:
                    command = ["uv", "tool", "run", tool_name]
            except (subprocess.SubprocessError, OSError):
                pass

        if command is None:
            direct = find_executable(binary)
            if direct is not None:
                command = [direct]

        with _uv_tool_runner_cache_lock:
            _uv_command_cache[cache_key] = command
        return command
