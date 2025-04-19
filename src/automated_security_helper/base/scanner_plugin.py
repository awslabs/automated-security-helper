from datetime import datetime, timezone
import logging
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER

from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Any, Dict, Generic, List, Literal, Optional, TypeVar
import shutil
import subprocess  # nosec B404 - We are using `subprocess` explicitly to call CLI security scanning tools.
from abc import abstractmethod
from pathlib import Path


class ScannerPluginConfigBase(PluginConfigBase):
    pass


T = TypeVar("T", bound=ScannerPluginConfigBase)


class ScannerPluginBase(BaseModel, Generic[T]):
    """Base class for all scanner plugins."""

    model_config = ConfigDict(extra="allow")

    config: T | ScannerPluginConfigBase | None = None

    tool_type: str = "UNKNOWN"
    tool_version: str | None = None
    description: str | None = None
    command: Annotated[
        str,
        Field(
            description="The command to invoke the scanner, typically the binary or path to a script"
        ),
    ] = None
    args: Annotated[
        ToolArgs,
        Field(
            description="Specialized arguments to pass to the scanner command. Includes an `extra_args` field which accepts a dictionary of arbitrary arguments to pass to the scanner. These are not configurable at scan time."
        ),
    ] = ToolArgs()
    source_dir: Path | None = None
    output_dir: Path | None = None

    output: List[str] = []
    errors: List[str] = []

    # These will be initialized during `self.model_post_init()`
    # in paths relative to the `output_dir` provided
    work_dir: Path | None = None
    results_dir: Path | None = None
    results_file: Path | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    exit_code: int = 0

    def model_post_init(self, context):
        if self.config is None:
            raise ScannerError(
                f"Unable to initialize {self.__class__.__name__}! Configuration is empty."
            )

        if self.source_dir is None:
            self.source_dir = Path.cwd()
        if self.output_dir is None:
            self.output_dir = self.source_dir.joinpath("ash_output")

        # Ensure paths are Path objects
        self.source_dir = Path(str(self.source_dir))
        self.output_dir = Path(str(self.output_dir))
        self.work_dir = self.output_dir.joinpath("work")
        self.results_dir = self.output_dir.joinpath("scanners").joinpath(
            self.config.name
        )

        return super().model_post_init(context)

    def _scanner_log(
        self,
        *msg: str,
        level: int | str = 15,
        target_type: str = None,
        append_to_stream: Literal["stderr", "stdout", "none"] = "none",
    ):
        """Log a message to the scanner's log file.

        Args:
            level: Log level
            msg: Message to log
        """
        tt = None
        if target_type is not None:
            tt = f" @ [magenta]{target_type}[/magenta]"

        ASH_LOGGER._log(
            level,
            f"([yellow]{self.config.name or self.__class__.__name__}[/yellow]{tt})\t{'\n'.join(msg)}",
            args=(),
        )
        if level == logging.ERROR or append_to_stream == "stderr":
            self.errors.append(
                f"({self.config.name or self.__class__.__name__}) {'\n'.join(msg)}"
            )
        elif append_to_stream == "stdout":
            self.output.append(
                f"({self.config.name or self.__class__.__name__}) {'\n'.join(msg)}"
            )

    def _process_config_options(self) -> None:
        """By default, returns False to indicate that the scanner did not perform any
        configuration option processing.

        Override this method if you need to process custom options before
        arguments are resolved!

        This method is called at the start of `self._resolve_arguments(target)` before
        `self.args.extra_args` is processed. Use this method to populate additional
        argument key/value pairs where needed.
        """
        pass

    def _resolve_arguments(
        self, target: str | Path, results_file: str | Path = None
    ) -> List[str]:
        """Resolve any configured options into command line arguments.

        Args:
            target: Target to scan

        Returns:
            List[str]: Arguments to pass to scanner
        """
        self._process_config_options()

        args = [
            self.command,
            self.args.format_arg,
            self.args.format_arg_value,
        ]

        for tool_extra_arg in self.args.extra_args:
            args.append(tool_extra_arg.key)
            args.append(tool_extra_arg.value)

        args.extend(
            [
                self.args.scan_path_arg,
                Path(target).as_posix(),
                self.args.output_arg,
                (
                    Path(results_file).as_posix()
                    if results_file is not None
                    else (
                        Path(self.results_file).as_posix()
                        if self.results_file is not None
                        else None
                    )
                ),
            ]
        )
        return [item for item in args if item is not None]

    def _pre_scan(
        self,
        target: Path,
        config: Optional[ScannerPluginConfigBase] = None,
        *args,
        **kwargs,
    ) -> None:
        """Perform pre-scan setup.

        Args:
            target: Target to scan
            options: Optional scanner-specific options
        """
        self.start_time = datetime.now(timezone.utc)
        if target.as_posix() == ".":
            target_type = "source"
        else:
            target_type = "temp"

        self._scanner_log(
            "Starting scan",
            target_type=target_type,
            level=logging.INFO,
        )
        self._scanner_log(
            f"self.config: {self.config}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        if config is not None:
            if hasattr(config, "model_dump") and callable(config.model_dump):
                config = config.model_dump(by_alias=True)
            self.config = self.config.__class__.model_validate(config)
        self._scanner_log(
            f"config: {config}",
            target_type=target_type,
            level=logging.DEBUG,
        )

        self.results_dir.mkdir(parents=True, exist_ok=True)
        if not Path(target).exists():
            raise ScannerError(
                f"([yellow]{self.config.name or self.__class__.__name__}[/yellow] @ [magenta]{target_type}[/magenta]) Target {target} does not exist!"
            )

        self.work_dir.mkdir(parents=True, exist_ok=True)
        if self.results_dir:
            self.results_dir.mkdir(parents=True, exist_ok=True)

    def _post_scan(
        self,
        target: Path,
    ) -> None:
        """Perform pre-scan setup.

        Args:
            target: Target to scan
            options: Optional scanner-specific options
        """
        self.end_time = datetime.now(timezone.utc)

        if target.as_posix() == ".":
            target_type = "source"
        else:
            target_type = "temp"

        ec_color = "bold green" if self.exit_code == 0 else "bold red"
        self._scanner_log(
            f"Scan completed in {(self.end_time - self.start_time).total_seconds()} seconds with an exit code of [{ec_color}]{self.exit_code}[/{ec_color}]",
            target_type=target_type,
            level=logging.INFO,
        )

    def _run_subprocess(
        self,
        command: List[str],
        results_dir: str | Path = None,
        stdout_preference: Literal["return", "write", "both", "none"] = "write",
        stderr_preference: Literal["return", "write", "both", "none"] = "write",
    ) -> Dict[str, str]:
        """Run a subprocess with the given command.

        Args:
            command: Command to run

        Raises:
            ScannerError: If process errors
        """
        try:
            binary_full_path = shutil.which(command[0])
            if binary_full_path is not None:
                command = [binary_full_path, *command[1:]]
        except Exception as e:
            ASH_LOGGER.debug(e)

        ASH_LOGGER.debug(f"({self.config.name}) Running: {command}")
        try:
            result = subprocess.run(  # nosec B603 - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
                command,
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                cwd=Path(self.source_dir).as_posix(),
                # env=os.environ.copy(),
            )
            # Default to 1 if it doesn't exist, something went wrong during execution
            self.exit_code = result.returncode or 1

            # Process stdout
            if result.stdout:
                self.output.extend(result.stdout.splitlines())
                if results_dir is not None and stdout_preference in ["write", "both"]:
                    with open(
                        Path(results_dir).joinpath(
                            f"{self.__class__.__name__}.stdout.log"
                        ),
                        "w",
                    ) as stdout_file:
                        stdout_file.write(result.stdout)
            # Process stderr
            if result.stderr:
                self.errors.extend(result.stderr.splitlines())
                if results_dir is not None and stderr_preference in ["write", "both"]:
                    with open(
                        Path(results_dir).joinpath(
                            f"{self.__class__.__name__}.stderr.log"
                        ),
                        "w",
                    ) as stderr_file:
                        stderr_file.write(result.stderr)

            response = {}
            if stdout_preference in ["return", "both"]:
                response["stdout"] = result.stdout
            if stderr_preference in ["return", "both"]:
                response["stderr"] = result.stderr
            return response

        except Exception as e:
            self.errors.append(str(e))
            # show full stack trace in warning
            ASH_LOGGER.debug(f"({self.config.name}) Error running {command}: {e}")
            self.exit_code = 1

    ### Methods that require implementation by plugins.
    @abstractmethod
    def validate(self) -> bool:
        """Validate scanner configuration.

        Returns:
            bool: True if validation passes
        """
        pass

    @abstractmethod
    def scan(
        self,
        target: Path,
        config: T | ScannerPluginConfigBase = None,
        global_ignore_paths: List[IgnorePathWithReason] = [],
        *args,
        **kwargs,
    ) -> Any | SarifReport | CycloneDXReport:
        """Execute scanner against a target.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Any | SarifReport | CycloneDxReport: Full scan results

        Raises:
            ScannerError: if scanning failed for any reason
        """
        pass
