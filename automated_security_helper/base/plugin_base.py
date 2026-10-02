"""Module containing the PluginBase class."""

from datetime import datetime
import logging
import sys
from pathlib import Path
from typing import Annotated, Callable, Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.core.enums import PackageManager
from automated_security_helper.core.exceptions import (
    ScannerError,
    ToolNotProvisionableError,
)
from automated_security_helper.utils.log import ASH_LOGGER


class PluginDependency(BaseModel):
    name: str
    version: str = "latest"
    package_manager: PackageManager = PackageManager.APT


# Version strings starting with one of these are PEP 440 specifiers (a range),
# not a single version.
_VERSION_SPECIFIER_START = ("<", ">", "!", "~", "=")


def pep440_requirement(name: str, version: str) -> str:
    """Render ``name`` and ``version`` as one pip/uv requirement string.

    ``version`` is interpreted three ways:

    - ``"latest"`` -- no constraint, so the resolver takes the newest release.
    - a PEP 440 specifier such as ``">=0.1.0,<2.0.0"`` -- passed through verbatim.
    - a bare version such as ``"1.2.3"`` -- pinned exactly, with ``==``.

    The middle case is why this helper exists. Rendering every non-``latest``
    version as ``f"{name}=={version}"`` turns a range into a requirement pip
    cannot parse (``ferret-scan==>=0.1.0,<2.0.0``), so a plugin that declared a
    supported *range* had no way to get it honoured. The observable failure was
    not an error, which is what made it expensive: the range went undeclared,
    the installer fell back to "latest", and CI installed whichever release
    happened to be newest at the moment the job ran. ferret-scan 2.3.3 was
    published mid-run on 2026-08-20 and turned every open PR red without a
    single source change.

    Only pip and uv use this. apt, npm, brew, yum and choco all spell ranges
    differently, and guessing a translation between them would trade a loud
    failure for a quiet mis-install.
    """
    if version == "latest":
        return name
    if version.startswith(_VERSION_SPECIFIER_START):
        return f"{name}{version}"
    return f"{name}=={version}"


def _versioned(dep: "PluginDependency", separator: str) -> str:
    """Render ``name<separator>version``, or bare ``name`` for ``"latest"``.

    The separator is the package manager's own spelling of a pin: ``=`` for apt
    and conda, ``@`` for npm and brew, ``-`` for yum. Ranges are not translated
    between managers -- see ``pep440_requirement`` for why.
    """
    if dep.version == "latest":
        return dep.name
    return f"{dep.name}{separator}{dep.version}"


#: How each package manager's dependencies are rendered into one argv.
#:
#: A mapping rather than an ``if``/``elif`` chain so the set of handled members is a
#: value this module can compare against ``PackageManager`` -- see
#: ``_UNRENDERED_PACKAGE_MANAGERS``. The chain this replaced covered eight of the ten
#: members and ended without an ``else``, so a plugin declaring ``package_manager:
#: conda`` produced an empty command list, the installer reported success, and the
#: scanner turned up MISSING at scan time with nothing naming the cause.
_INSTALL_COMMAND_BUILDERS: Dict[
    PackageManager, Callable[["PluginDependency"], List[str]]
] = {
    PackageManager.APT: lambda dep: [
        "apt-get",
        "install",
        "-y",
        _versioned(dep, "="),
    ],
    PackageManager.PIP: lambda dep: [
        sys.executable,
        "-m",
        "pip",
        "install",
        pep440_requirement(dep.name, dep.version),
    ],
    PackageManager.UV: lambda dep: [
        "uv",
        "tool",
        "install",
        pep440_requirement(dep.name, dep.version),
    ],
    # conda pins with a single `=`, the same spelling apt uses. A real command rather
    # than a refusal because "conda" is a published, user-facing value: it is in the
    # generated AshConfig schema, so a custom plugin may already declare it, and such a
    # plugin means `conda install` -- rejecting the member would break a documented
    # input while installing it is what the author asked for.
    PackageManager.CONDA: lambda dep: [
        "conda",
        "install",
        "-y",
        _versioned(dep, "="),
    ],
    PackageManager.NPM: lambda dep: [
        "npm",
        "install",
        "-g",
        _versioned(dep, "@"),
    ],
    PackageManager.BREW: lambda dep: [
        "brew",
        "install",
        _versioned(dep, "@"),
    ],
    PackageManager.YUM: lambda dep: [
        "yum",
        "install",
        "-y",
        _versioned(dep, "-"),
    ],
    # choco's version flag lands inside the same argv element as the package name.
    # Preserved verbatim from the chain this replaced: it is wrong (argv elements do
    # not word-split), but correcting it is a behaviour change for chocolatey users
    # and belongs in its own commit, not in a commit about a missing member.
    PackageManager.CHOCO: lambda dep: [
        "choco",
        "install",
        "-y",
        f"{dep.name}{f' --version={dep.version}' if dep.version != 'latest' else ''}",
    ],
}

#: Members that intentionally render no command, each for a stated reason.
#:
#: URL downloads are performed by ``download_utils`` through a plugin's
#: ``custom_install_commands``, and ``CUSTOM`` says only "not one of the managers
#: above" -- it carries no package name a command could be built from, so its
#: commands also live in ``custom_install_commands``. Both are listed here so that
#: "renders nothing" is a recorded decision rather than a missing branch.
_NO_INSTALL_COMMAND_PACKAGE_MANAGERS = frozenset(
    {
        PackageManager.URL,
        PackageManager.CUSTOM,
    }
)

#: Every PackageManager member that is neither rendered nor deliberately skipped.
#:
#: Derived, not listed, so it cannot drift from the enum. It must stay empty: a new
#: member added without either a builder or an entry above lands here, and
#: ``tests/unit/base/test_install_command_dispatch_is_exhaustive.py`` fails on it.
#: That test is the mechanism -- without it a new member would reach
#: ``get_installation_commands`` and raise there, which is loud but only for whoever
#: happens to run that plugin.
_UNRENDERED_PACKAGE_MANAGERS = (
    frozenset(PackageManager)
    - frozenset(_INSTALL_COMMAND_BUILDERS)
    - _NO_INSTALL_COMMAND_PACKAGE_MANAGERS
)


class CustomCommand(BaseModel):
    args: List[str]
    shell: bool = False  # Set to True only when shell expansion is absolutely necessary


class PluginBase(UVToolMixin, BaseModel):
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

    # UV special use cases
    uv_tool_package_name: str | None = None

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
            "\t" + "\n".join(msg),
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

    def _process_command_response(self, response: dict) -> None:
        """Accumulate stdout, stderr, and exit code from a subprocess response.

        Args:
            response: Dictionary with optional stdout, stderr, and returncode keys.
        """
        if response.get("stdout"):
            self.output.extend(response["stdout"].splitlines())

        if response.get("stderr"):
            self.errors.extend(response["stderr"].splitlines())

        # Accumulate worst exit code across multiple subprocess calls.
        # Use abs() so negative codes (e.g. -1 for timeout) aren't
        # silently swallowed by max(0, -1).
        new_code = response.get("returncode", 1)
        self.exit_code = max(
            self.exit_code, abs(new_code) if new_code < 0 else new_code
        )

    def _run_subprocess(
        self,
        command: List[str],
        results_dir: str | Path | None = None,
        stdout_preference: Literal["return", "write", "both", "none"] = "write",
        stderr_preference: Literal["return", "write", "both", "none"] = "write",
        cwd: Path | str | None = None,
        env: Dict[str, str] | None = None,
        timeout: float | None = None,
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
            env: Environment variables for the child process. When None, the
                child inherits the parent env. Pass a local dict (e.g.
                ``{**os.environ, "MY_VAR": "v"}``) to add/override vars
                without mutating the parent process ``os.environ`` — this
                matters because scanners run in parallel threads and share
                the parent env.

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
                    # timeout has to be handed to this path too, not just to the
                    # direct-execution call below. This branch returns, so a
                    # timeout passed only below would apply exclusively to
                    # scanners for which uv is unavailable. bandit, checkov and
                    # semgrep all set use_uv_tool=True unconditionally and only
                    # clear it when uv is missing, and ASH ships via uv -- so on a
                    # normal install the reported bandit hang went through here,
                    # unbounded, no matter what scan_timeout said.
                    uv_result = self._try_uv_tool_execution(
                        command,
                        working_dir,
                        results_dir=Path(results_dir) if results_dir else None,
                        stdout_preference=stdout_preference,
                        stderr_preference=stderr_preference,
                        env=env,
                        timeout=timeout,
                    )
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
                env=env,
                shell=False,
                class_name=self.__class__.__name__,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )

            self._process_command_response(response)

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

    def get_installation_commands(self, platform: str, arch: str) -> List[List[str]]:
        """Generate installation commands for the specified platform/architecture as arrays of arguments"""
        commands = []

        # Process standard dependencies
        if platform in self.dependencies and arch in self.dependencies[platform]:
            for dep in self.dependencies[platform][arch]:
                # Normalised so a plugin that declares the raw string ("conda") and one
                # that declares the member (PackageManager.CONDA) take the same path. A
                # value that is not a member at all raises here, naming the value.
                package_manager = PackageManager(dep.package_manager)

                if package_manager in _NO_INSTALL_COMMAND_PACKAGE_MANAGERS:
                    # Installed through custom_install_commands, not from here.
                    continue

                builder = _INSTALL_COMMAND_BUILDERS.get(package_manager)
                if builder is None:
                    # Reachable only for a PackageManager member added without a
                    # builder. Refused rather than skipped: returning no command for a
                    # declared dependency lets the install report success and defers the
                    # failure to scan time, where it appears as a scanner reported
                    # MISSING and names neither the dependency nor the manager.
                    raise ToolNotProvisionableError(
                        f"{self.__class__.__name__} declares dependency "
                        f"'{dep.name}' with package manager "
                        f"'{package_manager.value}', which ASH has no install "
                        f"command for. Add a renderer to "
                        f"_INSTALL_COMMAND_BUILDERS, or list the member in "
                        f"_NO_INSTALL_COMMAND_PACKAGE_MANAGERS if it is installed "
                        f"through custom_install_commands."
                    )

                commands.append(builder(dep))

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
